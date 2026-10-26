/**
 * 安全告警服务
 * 监控和响应系统安全事件
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { normalizeIP, ipAttributionRiskFactors, resolvePunishTarget } = require('../utils/ipUtils');
const { businessHour, isOffHours } = require('../constants/timezone');
// 高危档不在此复述：与审计页 level=error、概览高危次数同一派生集合（F-149）
const { AUDIT_ERROR_RISK_LEVELS } = require('../constants/audit');
const { sendNotification } = require('./securityAlertDelivery');
const { applyAuditDataScope } = require('./auditScopeFilter');
const { guardDetection } = require('../utils/auditWriteFailure');
// 级别/类型枚举独立成叶子：permissionAbuse 需要它们，若仍定义在本文件就会
// 形成 securityAlert ↔ permissionAbuse 双向依赖。
const { ALERT_LEVELS, ALERT_TYPES } = require('./alertTypes');
// 频控表与投递入口同样独立成叶子（见 alertDispatch.js 头注释）。
const {
  ALERT_RATE_LIMIT_MS,
  startAlertCleanup,
  stopAlertCleanup,
  shouldSendAlert,
  dispatchNotification,
} = require('./alertDispatch');
// 封禁阶梯与 IP 封禁判据独立成文件：本文件 max-lines 已贴棘轮上限，
// 且「该不该封这个 IP」与「告警怎么发」是两条正交职责（详见该模块头注释）
const {
  BRUTE_FORCE_ATTEMPTS,
  BAN_ESCALATION_WINDOW_MS,
  ESCALATION_TIERS,
  IPBanEvents,
  collectBruteForceSignals,
  applyBruteForceIpBan,
  logIpBanSkipped,
} = require('./securityAlertIpBans');
// 告警阈值配置
const THRESHOLDS = {
  // 暴力破解：5 次失败/5 分钟
  bruteForceAttempts: BRUTE_FORCE_ATTEMPTS,
  bruteForceWindowMs: 5 * 60 * 1000,

  // 批量操作阈值
  bulkExportThreshold: 100,

  // 频繁权限检查失败
  permissionFailures: 20,
  permissionWindowMs: 5 * 60 * 1000,

  // 告警频率限制（防止告警风暴）
  alertRateLimitMs: ALERT_RATE_LIMIT_MS,
};

/**
 * 自动封禁阶梯（渐进式封禁时长）与其事件计数已迁至 securityAlertIpBans.js：
 * 本文件只消费其导出的 ESCALATION_TIERS / IPBanEvents / resolveIpBanDecision。
 * 迁移理由与「为什么事件源必须是审计」见该模块头注释（行预算：本文件贴 max-lines）。
 */

/**
 * 检测并记录暴力破解攻击
 */
const checkBruteForce = async (username, ip, attribution = null) => {
  const windowStart = new Date(Date.now() - THRESHOLDS.bruteForceWindowMs);

  // 双维度计数：账户维度 + IP 维度，任一达到阈值即告警
  // 账户维度必须与 User.findByUsername 同口径（大小写不敏感 collation）：
  // 否则 `Admin` / `admin` / `ADMIN` 各占一个计数桶，攻击者只要轮换大小写，
  // 同一账户的失败次数就永远到不了阈值，而账户锁定仍按同一个账户生效。
  const [userFailures, ipFailures] = await Promise.all([
    AuditLog.countDocuments({
      username,
      action: { $in: ['login_failed', 'auth_failed'] },
      timestamp: { $gte: windowStart },
    }).collation(AuditLog.AUDIT_USERNAME_COLLATION),
    AuditLog.countDocuments({
      ip,
      action: { $in: ['login_failed', 'auth_failed'] },
      timestamp: { $gte: windowStart },
    }),
  ]);

  const maxFailures = Math.max(userFailures, ipFailures);
  if (maxFailures >= THRESHOLDS.bruteForceAttempts) {
    // 口径：告警去重键与封禁对象都必须用**归一化 IP**——
    // `::ffff:1.2.3.4` 与 `1.2.3.4` 混合出现时按原文组键会产生两个去重键，
    // 同一来源重复告警（与封禁/阶梯的两把尺问题同源）
    //
    // 惩罚目标裁定（2026-10-01 审计 finding，utils/ipUtils.resolvePunishableIp）：
    // 有 attribution（调用方持 req 时在调用侧 resolve）则按裁定打——
    // PUBLIC_PEER_HEADER（对端公网却带 XFF）的 reportedIp 完全由对方写，改打
    // socketPeer；TRUSTED_PROXY/DIRECT 打 reportedIp 并留痕。缺省（历史调用方/
    // 测试替身直接传 ip 串）保持既有语义。
    // 计数仍按**上报的 ip**：审计行的 ip 列就是它，换目标计数会让历史行永远
    // 配不上；对"固定伪造值刷满阈值"的攻击者，改打 socketPeer 后照样落网，
    // 对"轮换伪造值"者由账号锁定 + 限流兜底（此处计数本来就攒不起来）。
    const punishTarget = resolvePunishTarget(attribution, ip);
    const normalizedIp = normalizeIP(punishTarget) || punishTarget;

    // R-H2：**封禁判据只看 IP 维度**。maxFailures 取的是双维度的较大值——分布式撞
    // 单账号（多个攻击 IP 各自少量尝试同一账号）会让 userFailures 达标，而"当前请求
    // 的 IP"可能只贡献了 1 次失败：此时封它，NAT 出口后的无辜用户陪绑（受害者本人
    // 换个网络登录一次即被封 1 小时）。账号维度的攻击由账户锁定 + loginUserLimiter
    // 兜底；IP 封禁只对「这个 IP 自己刷满了失败」的确定性信号执行。

    // IP 封禁的前置信号（2026-10-21 #21）：单账号失败交给账户锁定/账号限流，
    // 只有跨账号失败才封 IP；共享出口首次触发只告警。判据见 securityAlertIpBans。
    // 两组计数键不同：失败信号数的是 login_failed 审计行（ip 列 = 上报 ip），
    // 阶梯数的是本模块落库的告警行（ip 列 = 归一化 IP）。混用任一侧都会让
    // 对应判据恒为 0：前者在 PUBLIC_PEER_HEADER 下不存在该值，后者跨
    // `::ffff:x` / `x` 时不共链。
    const { distinctAccounts, sharedEgressAccounts, priorBans, ipBanOutcome, ipBanApplied } =
      await collectBruteForceSignals({
        reportedIp: ip,
        normalizedIp,
        windowStart,
        fallbackIp: ip,
      });

    // 审计写入挂独立 try/catch。此前裸 await 位于 try 块之外，
    // AuditLog.create 抛错（DB 瞬断/校验失败）会把异常上抛给调用方，
    // 下方自动封禁 try 块根本执行不到——告警审计写失败反而放过了封禁。
    // 审计失败不阻断封禁与通知，但按项目风格记录 error（不静默吞错）。
    try {
      await AuditLog.create({
        action: ALERT_TYPES.BRUTE_FORCE,
        category: 'auth',
        username,
        ip: normalizedIp,
        riskLevel: ALERT_LEVELS.CRITICAL,
        riskFactors: [
          `登录失败次数超标 (账户:${userFailures}, IP:${ipFailures})`,
          ...(ipBanApplied ? [] : [`ip_ban_${ipBanOutcome}`]),
          // 封禁留痕（口径见 ipUtils.ipAttributionRiskFactors）
          ...ipAttributionRiskFactors(attribution?.kind),
        ],
        body: {
          userAttempts: userFailures,
          ipAttempts: ipFailures,
          window: '5 分钟',
          distinctAccounts,
          sharedEgressAccounts,
          ipBanApplied,
          ipBanOutcome,
        },
      });
    } catch (e) {
      logger.error(`暴力破解告警审计落库失败（封禁流程继续）: ${e.message}`);
    }

    // B-M1：投递走 fire-and-forget——本函数被登录失败/导出路径 await，
    // 告警已落库（上方 create 在 await 内，即时性保留），这里只走网络投递

    // R-H2：IP 维度未达标（分布式撞单账号）到此为止——告警与审计已落库
    // （body 的 ipAttempts 即判据），封禁只对「这个 IP 自己刷满了失败」执行
    if (ipFailures < THRESHOLDS.bruteForceAttempts) return;

    if (ipBanApplied) {
      await applyBruteForceIpBan({ normalizedIp, priorBans, fallbackIp: ip });
    } else {
      logIpBanSkipped({
        outcome: ipBanOutcome,
        normalizedIp,
        ipFailures,
        distinctAccounts,
        sharedEgressAccounts,
      });
    }

    // ============ 处置与通知解耦（2026-09-30，与 rateLimitEscalationBan 同一修法）============
    // 修复前：两行 `shouldSendAlert` 挡在 priorBans 统计 / 审计 / 封禁**之前**，
    // 任一命中即 `return`，把三件事一起关在门外。后果不是少一条通知：
    //   - 封禁**失败**（命中白名单 / 黑名单写库故障）时，5 分钟内的重试被这行吞掉——
    //     而"封禁没生效"恰恰是最需要重试的场合；
    //   - 审计行是**阶梯的事件源**（IPBanEvents.countPrior 数的就是它，
    //     见上方 :66-86 的注释），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP
    //     每次都只被封 1 小时，而 :279 照打「第 N 次」——运维以为阶梯在工作。
    // 现在：统计 / 审计 / 封禁**无条件执行**，频控只约束 dispatchNotification。
    // 通知是给人看的，处置是对系统做的，两者不该共用一个开关。
    //
    // 键**内联**而非中间变量：键里同时含 username 与归一化 IP，两处各内联一次
    // 才能保证"构造方式"只有一种（抽成变量反而要再抽一个函数，本文件 max-lines 已贴上限）。
    // `||` 的短路是有意的：账户维度 key 放行时不消费 IP 维度 key，两个维度各自计频，
    // 与修复前"任一放行即投递"的语义一致（改 `|` 会多消费一个 key ⇒ 抑制变强 ⇒ 行为回归）。
    if (
      shouldSendAlert(`brute_force_user_${username}`) ||
      shouldSendAlert(`brute_force_ip_${normalizedIp}`)
    ) {
      dispatchNotification(
        ALERT_TYPES.BRUTE_FORCE,
        ALERT_LEVELS.CRITICAL,
        `检测到暴力破解攻击：用户 ${username}，IP ${ip}`,
        { username, ip, attempts: maxFailures, distinctAccounts, ipBanApplied }
      );
    }
  }
};

/**
 * 检测批量数据导出操作
 */
const checkBulkExport = async (userId, username, count, operation) => {
  // 「达到阈值即告警」在三个检测器里必须是同一种比较：另两处用 `>=`
  // （bruteForceAttempts、permissionFailures），这里原先是 `count <= 阈值` 才返回，
  // 等价于"必须严格大于 100"——每次恰好导出 100 条的内部人员完全静默，
  // 且可以无限重复。阈值本身是"含"的语义，改成 `<` 才与同伴一致。
  if (count < THRESHOLDS.bulkExportThreshold) return;

  const alertKey = `bulk_export_${userId}`;

  // 同口径：告警审计落库失败**不得**冒泡到调用方。checkBulkExport 被
  // reportController/auditController 的导出路径 `await`，此前裸 await AuditLog.create
  // 在 DB 瞬断/校验失败时会把一次本已成功的导出顶成 500——告警是旁路增强，
  // 绝不该拖垮主流程。捕获后仍继续投递通知（告警本身重要），仅记 error 不静默。
  //
  // 处置与通知解耦（2026-10-01，与上面 checkBruteForce 里 :302-311 那一条修法同源）：
  // 修复前这里写的是 `if (!shouldSendAlert(alertKey)) return;`，一行把**审计落库**
  // 一起挡在了门外。后果不是少一条通知，而是少一条证据：
  //   - 抑制窗（同一 userId 的 5 分钟）内的第二次、第三次批量导出**完全没有留痕**，
  //     而"短时间内反复大批量导出"恰恰是最需要被审计看见的内部威胁形态；
  //   - 审计行是 riskLevel=HIGH 的正式记录，与管理页的审计查询/导出脱敏/取证都相关，
  //     它的有无不该由"给人看的通知"是否轮到发送来决定。
  // 现在：审计无条件写，频控只约束 dispatchNotification。
  try {
    await AuditLog.create({
      action: ALERT_TYPES.BULK_EXPORT,
      category: 'system',
      userId,
      username,
      riskLevel: ALERT_LEVELS.HIGH,
      riskFactors: ['批量数据操作'],
      body: { operation, count },
    });
  } catch (e) {
    logger.error(`批量导出告警审计落库失败（通知流程继续）: ${e.message}`);
  }

  // B-M1：导出路径不因 webhook 投递阻塞响应
  if (shouldSendAlert(alertKey)) {
    dispatchNotification(
      ALERT_TYPES.BULK_EXPORT,
      ALERT_LEVELS.HIGH,
      `检测到批量数据导出：用户 ${username}，数量 ${count}`,
      { userId, username, count, operation }
    );
  }
};

/**
 * 检测非常规时间访问
 * 阈值与时区均取 constants/timezone 单一声明，
 * 与 AuditLog.detectAnomalies / behaviorBaseline 保证同口径
 */
const checkUnusualTime = (timestamp = new Date()) => {
  const hour = businessHour(timestamp);
  if (isOffHours(timestamp)) {
    return { isUnusual: true, hour };
  }
  return { isUnusual: false };
};

/**
 * 检测权限滥用
 *
 * @param {string} userId 被拒用户
 * @param {{kind:string,punishIp:string,reportedIp?:string,socketPeer?:string}|string} attribution
 *   调用方持 req 时传 utils/ipUtils.resolvePunishableIp(req) 的裁定结果；
 *   兼容直接传 ip 串（按 UNVERIFIABLE 既有口径处理）
 */
const checkPermissionAbuse = async (userId, attribution) => {
  // 惩罚目标裁定：字符串形态 = 旧口径（归一化后即目标）；对象形态按裁定
  const attr =
    typeof attribution === 'string'
      ? { kind: 'unverifiable', punishIp: attribution }
      : attribution || null;
  const ip = attr?.punishIp;
  // B-L6 接线口径：信号取全局审计中间件落库的 403 响应（写路径 403 均有记录，
  // 零新增写入），兼容显式写入的 permission_denied/forbidden 动作
  const recentFailures = await AuditLog.countDocuments({
    userId,
    $or: [{ statusCode: 403 }, { action: { $in: ['permission_denied', 'forbidden'] } }],
    timestamp: { $gte: new Date(Date.now() - THRESHOLDS.permissionWindowMs) },
  });

  if (recentFailures >= THRESHOLDS.permissionFailures) {
    // username 为 AuditLog 必填字段：缺失会让告警写入 ValidationError 静默失败
    //（批次 E 测试暴露的潜伏缺陷——该函数此前无调用方，缺陷从未触发）
    const User = require('../models/User');
    const abuser = await User.findById(userId).select('username').lean();
    if (!abuser) return;

    // 处置侧整块（审计 / 遏制封禁 / 通知）抽到 securityAlertPermissionAbuse.js：
    // 本文件 max-lines 已贴棘轮上限，且"遏制"是本次新增的一整条职责。
    // 该模块的头注释记着为什么这里必须封 IP（此前只告警不封任何东西 ⇒ 有效凭据
    // 持有者把探测压到 <20 次/5 分钟即可永久试探权限边界）。
    await require('./securityAlertPermissionAbuse').recordAndContain({
      userId,
      username: abuser.username || String(userId),
      ip,
      attributionKind: attr?.kind,
      recentFailures,
    });
  }
};

/**
 * 获取安全概览（管理员仪表盘）
 *
 * scopeFilter 由调用方注入（默认空 = 全库）：HTTP 路径必须传入
 * `applyAuditDataScope` 的结果——这四个计数与 /security/alerts、/audit-logs
 * 是同一权限码下的出口，范围口径必须同源。默认空只服务于内部/定时调用方，
 * 与 `AuditLog.detectAnomalies` 的 scopeFilter 约定一致。
 *
 * @param {number} days 统计窗口（天）
 * @param {object} scopeFilter Mongo 查询条件（通常来自 applyAuditDataScope）
 */
const getSecurityOverview = async (days = 7, scopeFilter = {}) => {
  try {
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const withinWindow = { timestamp: { $gte: since } };
    const [criticalAlerts, highAlerts, failedLogins, unusualAccess] = await Promise.all([
      AuditLog.countDocuments({ ...scopeFilter, riskLevel: 'critical', ...withinWindow }),
      AuditLog.countDocuments({ ...scopeFilter, riskLevel: 'high', ...withinWindow }),
      AuditLog.countDocuments({ ...scopeFilter, action: 'login_failed', ...withinWindow }),
      // riskFactors 是数组字段，用 $in 匹配数组中是否包含非常规时间访问标记
      AuditLog.countDocuments({
        ...scopeFilter,
        riskFactors: { $in: ['unusual_time', 'unusual_time_access'] },
        ...withinWindow,
      }),
    ]);

    return {
      period: `${days}天`,
      criticalAlerts,
      highAlerts,
      failedLogins,
      unusualAccess,
      riskScore: Math.min(
        100,
        Math.max(
          0,
          // unusualAccess 每项 +5 纳入评分：非常规时间访问是独立风险信号，
          // 此前查询后未参与计算，导致该维度风险被完全忽略
          criticalAlerts * 10 + highAlerts * 5 + failedLogins * 2 + unusualAccess * 5
        )
      ),
    };
  } catch (error) {
    logger.error(`安全概览获取失败: ${error.message}`);
    // A-2：失败不能伪装成「零风险」。调用方（安全面板）必须能区分
    // 「确实没有告警」与「查询根本没成功」——后者按 503 明确降级。
    return { degraded: true, period: `${days}天` };
  }
};

/**
 * 获取最近的告警列表
 *
 * 数据范围必须与 GET /api/security/audit-logs **同源**：两个端点挂同一个权限码
 * `security:audit`（routes/securityRoutes.js:235 / :276），而 /audit-logs 走
 * `applyAuditDataScope`（auditQueryService.js:217）。此前本函数不带范围条件，
 * 于是 level 8 的 SECURITY_ADMIN（initData 的口径：level ≥7 只有本部门范围）
 * 可以从这里读出全系统的高危审计行（username/ip/path）——
 * 把审计日志按部门收口的努力被同一权限下的另一个出口整体绕过。
 *
 * `operatorId` 缺省 ⇒ 一条不给（fail-closed）：没有操作者上下文就无从谈"可见范围"，
 * 宁可让内部调用方显式表态，也不要默认放开全量。
 */
const getRecentAlerts = async (limit = 50, operatorId = null) => {
  if (!operatorId) return [];
  const { query } = await applyAuditDataScope(
    { riskLevel: { $in: AUDIT_ERROR_RISK_LEVELS } },
    operatorId
  );
  // 投影与 GET /security/audit-logs 同口径：只给元数据，不含 body/params/query/hmac。
  // body 经 sanitizer 仍可能残留业务上下文与其他 PII，而审计列表/导出明确不返回它；
  // 同权限下的告警卡片不应成为更宽的那个出口。
  return await AuditLog.find(query)
    .sort({ timestamp: -1 })
    .limit(limit)
    .select(
      'action category riskLevel username ip timestamp method path statusCode success duration userAgent'
    )
    .lean();
};

module.exports = {
  THRESHOLDS,
  ALERT_LEVELS,
  ALERT_TYPES,
  IPBanEvents,
  ESCALATION_TIERS,
  BAN_ESCALATION_WINDOW_MS,
  // 检测器统一经 guardDetection 在导出边界包一层：它们内部只挡住了"审计落库"和
  // "封禁写入"两处抛点，入口那次"用来观测的计数查询"一直是裸 await，而所有调用方
  // （authService 五处、rbac 一处）都是空 catch ⇒ 观测失败会整块静默掉检测与封禁。
  // checkBulkExport 不包：它的计数来自调用方，写入与投递两处已各自收口，
  // 实测找不出任何可达抛点（写不出用例来证明它需要这层壳），不做无据防御。
  checkBruteForce: guardDetection('暴力破解检测', checkBruteForce),
  checkBulkExport,
  checkUnusualTime,
  checkPermissionAbuse: guardDetection('权限滥用检测', checkPermissionAbuse),
  getSecurityOverview,
  getRecentAlerts,
  // F-214：「fire-and-forget 的统一入口」必须对外可见，否则外部调用方只能绕开它去
  // `void` 裸的 sendNotification —— 裸函数没有 reject 兜底，void 之后就是一条
  // unhandledRejection，而 index.js 的那条分支在**所有环境**都 process.exit(1)。
  // 内部三个检测器一直在用它，外部的黑名单通知却用不到：这就是"入口"没导出的代价。
  // sendNotification 仍导出：auditMonitor 需要 await 投递结果做它自己的记账。
  dispatchNotification,
  sendNotification,
  shouldSendAlert,
  startAlertCleanup,
  stopAlertCleanup,
};
