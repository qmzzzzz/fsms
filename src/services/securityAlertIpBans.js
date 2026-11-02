/**
 * 自动封禁阶梯与 IP 封禁判据（自 securityAlert.js 拆出）
 *
 * 拆出的直接原因是后者的 max-lines 棘轮已贴上限，而本次要补的是「IP 封禁的
 * 多账号/共享出口信号」这一整块新判据。按职责拆分也合理：本文件只回答
 * 「这个 IP 该不该封、封多久」，告警检测与通知仍在 securityAlert.js。
 *
 * ============================ 阶梯事件源为什么是审计 ============================
 * 事件源必须是 append-only 的审计日志，而不是 ipblacklist 集合：
 * 该集合上 (ip,type) 唯一（models/IPBlacklist.js:95），blockIP 走 findOneAndUpdate +
 * upsert（管道 $ifNull 保留首封 createdAt，models/IPBlacklist.js:269），且 TTL 索引（models/IPBlacklist.js:92）到期即删档 ⇒ 同一 IP 任何时刻
 * 最多只剩一条 ⇒ 在它上面 countDocuments 恒 ≤1，第三/四档（24 小时、7 天）永不可达，
 * 而日志照打"第 N 次"——运维以为阶梯在工作。
 *
 * 窗口定 30 天依赖一条前提：审计至少得留 30 天，否则"30 天内的封禁次数"没有数据支撑。
 * 该前提由 constants/retention.js 的 MIN_RETENTION_DAYS=90 保证（AUDIT_RETENTION_DAYS
 * 会被钳制到 ≥90，配不出更短的值）。这里不写运行期 Math.min 兜底——在 90 天下它是死分支；
 * 改由用例盯住不变量（tests/services/securityAlertBanLadder.test.js）：
 * 谁把留存下限调到 30 天以下、或把窗口拉到留存之外，那条用例就红。
 *
 * ============================ 为什么 IP 封禁要多账号信号 ============================
 * 5 次失败/5 分钟就封 IP 的旧判据，在 NAT/共享出口下等于「一个人连错 5 次密码，
 * 整个办公室被挡 1 小时」。而单账号的撞库本来就有两道更精准的防线：
 * 账户锁定（authService）与 loginUserLimiter（账号维度 20 次/15 分钟）。
 * IP 封禁因此改成只在**多账号失败**（password spraying 的确定性信号）时执行；
 * 单账号失败只告警、不封 IP。
 *
 * 共享出口再加一层：若该 IP 近 7 天有 ≥3 个不同账号成功登录，说明它是 NAT/办公出口，
 * **首次**触发只告警不封（避免一次误伤整栋楼），第二次起恢复封禁——真攻击者不会
 * 因为一次宽限而消失，而正常的共享出口用户不会天天刷出 5 次跨账号失败。
 *
 * 跳过封禁的告警行必须写 `body.ipBanApplied: false`：它是阶梯的事件源，
 * 若把「只告警没封」也计成一次封禁，下一次真封禁会凭空升档。
 */
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
// 直连封禁原语叶子模块（门面会反向拉回本告警链，形成惰性环）。
// 调用时取属性（薄包装），不解构：测试据此替换封禁结果，解构会在加载期固化绑定。
const ipBlacklistStore = require('../middleware/security/ipBlacklistStore');
const addToBlacklist = (...args) => ipBlacklistStore.addToBlacklist(...args);

// 与 securityAlert.ALERT_TYPES 的同名取值必须一致；单独声明是为了避免
// securityAlertIpBans ← securityAlert ← securityAlertIpBans 的循环依赖。
const BAN_EVENT_ACTIONS = Object.freeze({
  BRUTE_FORCE: 'brute_force_login',
  PERMISSION_ABUSE: 'permission_abuse',
});

const BRUTE_FORCE_ATTEMPTS = 5;
const BAN_ESCALATION_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const ESCALATION_TIERS = [
  1 * 60 * 60 * 1000,
  4 * 60 * 60 * 1000,
  24 * 60 * 60 * 1000,
  7 * 24 * 60 * 60 * 1000,
];

// 多账号信号：少于 2 个不同用户名失败 ⇒ 按单账号撞库处理，交给账户锁定/账号限流。
const IP_BAN_MIN_DISTINCT_ACCOUNTS = 2;
// 共享出口判定：近 7 天该 IP 成功登录过 ≥3 个不同账号。
const SHARED_EGRESS_MIN_ACCOUNTS = 3;
const SHARED_EGRESS_LOOKBACK_MS = 7 * 24 * 60 * 60 * 1000;

const windowStart = () => new Date(Date.now() - BAN_ESCALATION_WINDOW_MS);

const IPBanEvents = {
  windowMs: () => BAN_ESCALATION_WINDOW_MS,
  countPrior: (normalizedIp) =>
    AuditLog.countDocuments({
      action: BAN_EVENT_ACTIONS.BRUTE_FORCE,
      ip: normalizedIp,
      timestamp: { $gte: windowStart() },
      // R-H2 之后"一条 brute_force_login 审计"不再等价于"一次封禁动作"：
      // 账号维度达标（分布式撞单账号）而 IP 维度未达标时也落一条告警行（当前
      // 请求 IP 可能只贡献了 1 次失败）。这类行若计入阶梯，受害者的 IP 攒几行
      // 后会被无辜升档到 4h/24h/7d。body.ipAttempts 是该行落库时即写入的
      // "IP 维度失败次数"，只有 ≥ 阈值的行才配代表"这个 IP 自己刷满过一次"。
      'body.ipAttempts': { $gte: BRUTE_FORCE_ATTEMPTS },
      // 本次起还有第二类"不够格"的行：多账号信号不足 / 共享出口首次触发时，
      // 只告警不封 IP（见文件头）。它们同样不得抬升后续封禁档位。
      // 历史行没有该字段 ⇒ $ne:false 照常匹配。
      'body.ipBanApplied': { $ne: false },
    }),
  /** 同一窗口内的**触发次数**（含只告警未封的行），用于共享出口的首次宽限判定 */
  countPriorOffenses: (normalizedIp) =>
    AuditLog.countDocuments({
      action: BAN_EVENT_ACTIONS.BRUTE_FORCE,
      ip: normalizedIp,
      timestamp: { $gte: windowStart() },
      'body.ipAttempts': { $gte: BRUTE_FORCE_ATTEMPTS },
    }),
  /** 首次触发 = 第 1 档；每多一次历史事件升一档，封顶第 4 档 */
  tierFor: (priorBans) => Math.min(Math.max(priorBans, 0), ESCALATION_TIERS.length - 1),
  /**
   * 权限滥用的阶梯事件源（2026-09-30 补遏制时新增）。
   *
   * 与 countPrior 分账的理由：`body.ipAttempts` 那套过滤只对暴力破解有意义
   * （它要剔掉"账号维度达标、IP 维度未达标"的告警行）。权限滥用没有维度之分——
   * 每写一条 permission_abuse 审计就对应一次封禁动作，直接计数即可。
   *
   * 复用同一组时长档位（ESCALATION_TIERS）与同一个 windowMs：两本账、一套阶梯。
   */
  countPermissionAbusePrior: (normalizedIp) =>
    AuditLog.countDocuments({
      action: BAN_EVENT_ACTIONS.PERMISSION_ABUSE,
      ip: normalizedIp,
      timestamp: { $gte: windowStart() },
    }),
  /**
   * 窗口内该 IP 失败过的不同账号数（大小写不敏感，与 User.findByUsername 同口径）。
   * 用 distinct 的 collation 而不是先取回再 Set：后者把攻击者可控的用户名数组
   * 整个拉进进程，正是本仓反复收口的「无界请求方可控输入」形态。
   */
  countDistinctFailedAccounts: (normalizedIp, since) =>
    AuditLog.distinct('username', {
      ip: normalizedIp,
      action: { $in: ['login_failed', 'auth_failed'] },
      timestamp: { $gte: since },
    })
      .collation(AuditLog.AUDIT_USERNAME_COLLATION)
      .then((names) => names.filter(Boolean).length),
  /**
   * 近 7 天该 IP 有成功登录的不同账号数（封顶计数，只需知道是否 ≥ 阈值）。
   * $limit 放在 $group 之后：MongoDB 仍会为匹配文档建分组，但返回与后续内存
   * 只保留 3 条；对正常办公出口（至多几十个账号）没有可见成本。
   */
  countSharedEgressAccounts: (normalizedIp) =>
    AuditLog.aggregate([
      {
        $match: {
          ip: normalizedIp,
          action: 'login_success',
          timestamp: { $gte: new Date(Date.now() - SHARED_EGRESS_LOOKBACK_MS) },
        },
      },
      { $group: { _id: { $toLower: '$username' } } },
      { $limit: SHARED_EGRESS_MIN_ACCOUNTS },
    ]).then((rows) => rows.length),
};

/**
 * 纯判定：本次是否对目标 IP 执行自动封禁。
 *
 * @param {{signalUnavailable?: boolean, distinctAccounts: number, sharedEgressAccounts: number,
 *          priorOffenses: number}} input
 * @returns {'applied'|'skipped_signal_unavailable'|'skipped_single_account'|'skipped_shared_egress'}
 *   调用方保证 ipFailures 已达标；返回值直接用于审计 body.ipBanOutcome 与 riskFactors。
 */
const resolveIpBanDecision = ({
  signalUnavailable,
  distinctAccounts,
  sharedEgressAccounts,
  priorOffenses,
}) => {
  // 信号查询失败时宁可少封：多账号前置条件无法验证，而 NAT 误伤是不可逆的对外动作。
  // 告警审计仍会落库（riskFactors 里可见 skipped_signal_unavailable）。
  if (signalUnavailable) return 'skipped_signal_unavailable';
  if (distinctAccounts < IP_BAN_MIN_DISTINCT_ACCOUNTS) return 'skipped_single_account';
  if (sharedEgressAccounts >= SHARED_EGRESS_MIN_ACCOUNTS && priorOffenses === 0)
    return 'skipped_shared_egress';
  return 'applied';
};

/**
 * 收集一次暴力破解判定所需的全部计数：失败信号（多账号/共享出口）与阶梯历史。
 *
 * 两侧的计数键**不同**，不能合并：
 *   - 失败信号数的是 `login_failed` / `login_success` 审计行，它们的 ip 列是
 *     **上报 ip**（authService 写入时的原始 req.ip）。PUBLIC_PEER_HEADER 下
 *     归一化 IP（socket 对端）在这批行里根本不存在，拿它去数恒得 0 ⇒ 封禁死代码。
 *   - 阶梯数的是 `brute_force_login` 告警行，本模块落库时写的是**归一化 IP**
 *     （securityAlert.js 的 AuditLog.create）。同时它必须跨 `::ffff:x` / `x`
 *     两种形态共用一条链，否则交替使用即可让计数恒为 0。
 *
 * 任一查询失败都内部降级而不是抛出：调用方的告警审计必须继续落库，
 * 不能因为"用来决定封不封的辅助信号"查不到就连证据一起丢。
 * 信号查询失败 ⇒ 本次不封（signalUnavailable），阶梯查询失败 ⇒ 按第一档。
 */
const collectBruteForceSignals = async ({ reportedIp, normalizedIp, windowStart, fallbackIp }) => {
  let distinctAccounts = 0;
  let sharedEgressAccounts = 0;
  let signalUnavailable = false;
  try {
    [distinctAccounts, sharedEgressAccounts] = await Promise.all([
      IPBanEvents.countDistinctFailedAccounts(reportedIp, windowStart),
      IPBanEvents.countSharedEgressAccounts(reportedIp),
    ]);
  } catch (e) {
    signalUnavailable = true;
    logger.error(
      `IP 封禁信号统计失败（本次不自动封禁，告警流程继续）: ${fallbackIp}, 错误: ${e.message}`
    );
  }

  // 渐进式封禁的"第几次"必须在**本次告警落库之前**统计：
  // 每次真正封禁 = 一条 brute_force_login 审计（ipBanApplied=true），频控只挡通知。
  // 为什么不数 ipblacklist 集合：该集合上 (ip,type) 唯一（models/IPBlacklist.js:95），
  // blockIP 走 upsert（管道 $ifNull 保留首封 createdAt，models/IPBlacklist.js:269），且 TTL 索引（models/IPBlacklist.js:92）
  // 到期即删档 ⇒ 同一 IP 任何时刻最多只剩一条 ⇒ countDocuments 恒 ≤1，
  // 第三/四档（24 小时、7 天）永不可达，而日志照打"第 N 次"——运维以为阶梯在工作。
  // 审计是 append-only 的，是唯一能承载"事件次数"的现存存储。
  // 代价：窗口受审计留存期约束，留存配得比 30 天短时阶梯窗口随之收窄（不假装是 30 天）。
  let priorBans = 0;
  let priorOffenses = 0;
  try {
    [priorBans, priorOffenses] = await Promise.all([
      IPBanEvents.countPrior(normalizedIp),
      IPBanEvents.countPriorOffenses(normalizedIp),
    ]);
  } catch (e) {
    logger.error(`自动封禁阶梯统计失败（按第一档处理）: ${fallbackIp}, 错误: ${e.message}`);
  }

  const ipBanOutcome = resolveIpBanDecision({
    signalUnavailable,
    distinctAccounts,
    sharedEgressAccounts,
    priorOffenses,
  });
  return {
    distinctAccounts,
    sharedEgressAccounts,
    priorBans,
    ipBanOutcome,
    ipBanApplied: ipBanOutcome === 'applied',
  };
};

/**
 * 执行一次渐进式 IP 封禁，并按返回值（不是按异常）记录结果。
 *
 * addToBlacklist 自己 catch 掉所有失败、从不抛错 ⇒ "await 正常返回"绝不等于
 * "封禁生效"：白名单命中、地址解析失败、黑名单写库失败三条路径都返回
 * `{banned:false, reason}`。修复前这里无条件打「渐进式封禁 IP x：第 N 次」，
 * 运维读到"已封 7 天"以为攻击者被挡住，实际上该 IP 还在自由撞库（纸面防线）。
 * 成功行不带时长：addToBlacklist 自己会打「封禁时长：N秒」，两处各写一遍必然漂移。
 */
const applyBruteForceIpBan = async ({ normalizedIp, priorBans, fallbackIp }) => {
  try {
    const tier = IPBanEvents.tierFor(priorBans);
    try {
      require('./forensicTrigger').markForensicTarget(normalizedIp, {
        reason: 'brute_force_auto_ban',
        source: 'securityAlertIpBans',
        evidence: { tier: tier + 1, durationMs: ESCALATION_TIERS[tier] },
      }); // 取证标记（P1 钩子c）：这里是实际执行封禁的起点、先于 addToBlacklist——取证不依赖封禁是否落地（白名单/写库失败/抛错都算已确认攻击源）
    } catch (_) {} // 失败怎么办：mark 内部吞异常并计数（fail-visible）、壳兜 require 期异常——标记失败绝不影响封禁与告警流程
    const result = await addToBlacklist(
      normalizedIp,
      ESCALATION_TIERS[tier],
      `brute_force_auto_ban_tier${tier + 1}`,
      'auto'
    );
    if (result?.banned) logger.warn(`渐进式封禁 ${normalizedIp} 第 ${priorBans + 1} 次`);
    else
      logger.error(
        `自动封禁未生效 ${normalizedIp}（${result?.reason ?? 'no_result'}）请人工封禁或核对白名单`
      );
  } catch (e) {
    logger.error(`自动封禁 IP 失败: ${fallbackIp}, 错误: ${e.message}`);
  }
};

/** 跳过封禁的可见性：单账号是常态噪声（info），共享出口/信号不可用才值得运维注意 */
const logIpBanSkipped = ({
  outcome,
  normalizedIp,
  ipFailures,
  distinctAccounts,
  sharedEgressAccounts,
}) => {
  const log = outcome === 'skipped_single_account' ? logger.info : logger.warn;
  log(
    `IP 自动封禁已跳过（${outcome}）: ${normalizedIp}，` +
      `失败 ${ipFailures} 次 / 账号 ${distinctAccounts} 个 / 共享出口账号 ${sharedEgressAccounts} 个`
  );
};

module.exports = {
  BAN_EVENT_ACTIONS,
  BRUTE_FORCE_ATTEMPTS,
  BAN_ESCALATION_WINDOW_MS,
  ESCALATION_TIERS,
  IP_BAN_MIN_DISTINCT_ACCOUNTS,
  SHARED_EGRESS_MIN_ACCOUNTS,
  SHARED_EGRESS_LOOKBACK_MS,
  IPBanEvents,
  resolveIpBanDecision,
  collectBruteForceSignals,
  applyBruteForceIpBan,
  logIpBanSkipped,
};
