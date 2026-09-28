/**
 * 安全告警服务
 * 监控和响应系统安全事件
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { normalizeIP } = require('../utils/ipUtils');
const { businessHour, isOffHours } = require('../constants/timezone');
// 高危档不在此复述：与审计页 level=error、概览高危次数同一派生集合（F-149）
const { AUDIT_ERROR_RISK_LEVELS } = require('../constants/audit');
const { sendNotification } = require('./securityAlertDelivery');
const { applyAuditDataScope } = require('./auditScopeFilter');
const { guardDetection } = require('../utils/auditWriteFailure');

// 告警阈值配置
const THRESHOLDS = {
  // 暴力破解：5 次失败/5 分钟
  bruteForceAttempts: 5,
  bruteForceWindowMs: 5 * 60 * 1000,

  // 批量操作阈值
  bulkExportThreshold: 100,

  // 频繁权限检查失败
  permissionFailures: 20,
  permissionWindowMs: 5 * 60 * 1000,

  // 告警频率限制（防止告警风暴）
  alertRateLimitMs: 5 * 60 * 1000,
};

// 告警级别
const ALERT_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

// 告警类型
const ALERT_TYPES = {
  BRUTE_FORCE: 'brute_force_login',
  PRIVILEGE_ESCALATION: 'privilege_escalation',
  BULK_EXPORT: 'bulk_data_export',
  UNUSUAL_TIME: 'unusual_time_access',
  PERMISSION_ABUSE: 'permission_abuse',
  SUSPICIOUS_IP: 'suspicious_ip_activity',
  // 限流持续触顶的升级封禁事件（services/rateLimitEscalation.js 的 CC 防护闭环）
  RATE_LIMIT_ABUSE: 'rate_limit_abuse',
};

/**
 * 自动封禁阶梯（渐进式封禁时长）与其事件计数
 *
 * 事件源必须是 append-only 的审计日志，而不是 ipblacklist 集合：
 * 该集合上 (ip,type) 唯一（models/IPBlacklist.js:92），blockIP 走 findOneAndUpdate +
 * $setOnInsert:createdAt（:266），且 TTL 索引（:89）到期即删档 ⇒ 同一 IP 任何时刻
 * 最多只剩一条 ⇒ 在它上面 countDocuments 恒 ≤1，第三/四档（24 小时、7 天）永不可达，
 * 而日志照打"第 N 次"——运维以为阶梯在工作。
 *
 * 窗口定 30 天依赖一条前提：审计至少得留 30 天，否则"30 天内的封禁次数"没有数据支撑。
 * 该前提由 constants/retention.js 的 MIN_RETENTION_DAYS=90 保证（AUDIT_RETENTION_DAYS
 * 会被钳制到 ≥90，配不出更短的值）。这里不写运行期 Math.min 兜底——在 90 天下它是死分支；
 * 改由用例盯住不变量（tests/services/securityAlertBanLadder.test.js）：
 * 谁把留存下限调到 30 天以下、或把窗口拉到留存之外，那条用例就红。
 */
const BAN_ESCALATION_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const ESCALATION_TIERS = [
  1 * 60 * 60 * 1000,
  4 * 60 * 60 * 1000,
  24 * 60 * 60 * 1000,
  7 * 24 * 60 * 60 * 1000,
];
const IPBanEvents = {
  windowMs: () => BAN_ESCALATION_WINDOW_MS,
  countPrior: (normalizedIp) =>
    AuditLog.countDocuments({
      action: ALERT_TYPES.BRUTE_FORCE,
      ip: normalizedIp,
      timestamp: { $gte: new Date(Date.now() - IPBanEvents.windowMs()) },
    }),
  /** 首次触发 = 第 1 档；每多一次历史事件升一档，封顶第 4 档 */
  tierFor: (priorBans) => Math.min(Math.max(priorBans, 0), ESCALATION_TIERS.length - 1),
};

// 告警频率限制缓存// 结构：{ alertKey: { timestamp, expiresAt } }
const alertRateLimit = new Map();

// P3-24 容量上限：alertKey 含攻击者可控内容（如 `brute_force_user_${username}`，
// username 来自登录请求体且只限长度不限字符集），攻击者轮换用户名即可驱动
// Map 增长。已有 5 分钟过期 + 10 分钟清理定时器兜底，规模有界但界值取决于
// 攻击速率（10 分钟内的唯一 key 数）——万级 QPS 撞库下仍可达数百万条目。
// 此处加硬上限：超限时先清过期项，仍超限则整体清空（宁可短时放开频控，
// 也不能让告警模块本身成为内存耗尽的入口）。
// 原 `Number(env) || 10000` 接受负值，而 -1 会让
// `alertRateLimit.size >= cap` 与 `remaining >= cap` 双双恒真 ⇒ 每来一条告警就
// alertRateLimit.clear() 并打 error，风暴抑制形同不存在（且自身成为日志放大器）。
const { readPositiveNumberEnv } = require('../utils/envNumber');
const ALERT_RATE_LIMIT_MAX_ENTRIES = readPositiveNumberEnv('ALERT_RATE_LIMIT_MAX', 10000, {
  integer: true,
  onInvalid: (name, raw, d) =>
    logger.error(
      `${name}=${JSON.stringify(raw)} 非法（须为正整数），已按默认 ${d} 处理；` +
        '负值会让频控表每次决策都被整体清空'
    ),
});

/** 清理已过期的频控条目，返回剩余条目数 */
const pruneAlertRateLimit = () => {
  const now = Date.now();
  for (const [key, value] of alertRateLimit.entries()) {
    if (value.expiresAt <= now) alertRateLimit.delete(key);
  }
  return alertRateLimit.size;
};

// 清理定时器引用（由 startAlertCleanup 显式启动）
let alertCleanupTimer = null;

/**
 * 启动告警频率限制的定期清理（每 10 分钟一次）
 * 由 index.js 在启动时显式调用，避免模块加载即产生副作用
 */
const startAlertCleanup = () => {
  if (alertCleanupTimer) return;
  alertCleanupTimer = setInterval(pruneAlertRateLimit, 10 * 60 * 1000);
  // 不阻塞 Node 进程退出（测试环境尤其需要）
  alertCleanupTimer.unref?.();
};

/**
 * 停止告警频率限制的定期清理（供优雅关闭调用）
 */
const stopAlertCleanup = () => {
  if (alertCleanupTimer) {
    clearInterval(alertCleanupTimer);
    alertCleanupTimer = null;
  }
};

/**
 * 检查是否应该发送告警（频率限制）
 */
const shouldSendAlert = (alertKey) => {
  const now = Date.now();
  const cached = alertRateLimit.get(alertKey);

  if (cached && now < cached.expiresAt) {
    return false;
  }

  // 写入前做容量保护（P3-24）
  if (alertRateLimit.size >= ALERT_RATE_LIMIT_MAX_ENTRIES) {
    const remaining = pruneAlertRateLimit();
    if (remaining >= ALERT_RATE_LIMIT_MAX_ENTRIES) {
      alertRateLimit.clear();
      logger.error(
        `告警频控表超过硬上限 ${ALERT_RATE_LIMIT_MAX_ENTRIES} 且过期项不足以回收，已整体清空。` +
          '这通常意味着正在遭受大规模轮换用户名的撞库攻击，短时内可能出现重复告警'
      );
    }
  }

  alertRateLimit.set(alertKey, {
    timestamp: now,
    expiresAt: now + THRESHOLDS.alertRateLimitMs,
  });
  return true;
};

/**
 * fire-and-forget 投递的统一入口（B-M1：网络投递不得挂在响应路径上）
 *
 * webhook 不可达时（2 次重试 × 5s 超时 + 退避 ≈ 11s）会把延迟放大到认证/导出
 * 响应上，构成 DoS 放大器，所以三处检测器都只"投递"、不等待。
 * 但 `.catch(() => {})` 这个形状把两件事混成了一件：
 *   - "投递没送达"——sendNotification 内部已经重试并 logger.warn 过，不用管；
 *   - "告警机器本身崩了"——它在自己写下 SECURITY_ALERT 那行日志之前就抛出来
 *     （计数/序列化/日志器不可用），这才是这条 catch 要接住的东西。
 * 静默接住它 = 这条告警从未存在过，而检测器已经按"已告警"继续走下去了。
 * 口径同 utils/auditWriteFailure.js：不改变业务语义，但不再静默。
 */
const dispatchNotification = (alertType, level, message, data) =>
  void sendNotification(alertType, level, message, data).catch((err) =>
    logger.error(`安全告警投递未能执行（${alertType}）：${err.message}`, { alertType })
  );

/**
 * 检测并记录暴力破解攻击
 */
const checkBruteForce = async (username, ip) => {
  const windowStart = new Date(Date.now() - THRESHOLDS.bruteForceWindowMs);

  // 双维度计数：账户维度 + IP 维度，任一达到阈值即告警
  const [userFailures, ipFailures] = await Promise.all([
    AuditLog.countDocuments({
      username,
      action: { $in: ['login_failed', 'auth_failed'] },
      timestamp: { $gte: windowStart },
    }),
    AuditLog.countDocuments({
      ip,
      action: { $in: ['login_failed', 'auth_failed'] },
      timestamp: { $gte: windowStart },
    }),
  ]);

  const maxFailures = Math.max(userFailures, ipFailures);
  if (maxFailures >= THRESHOLDS.bruteForceAttempts) {
    // 按账户维度 + IP 维度分别做频率限制，避免重复告警（键直接内联：
    // 中间变量 userAlertKey/ipAlertKey 各只用一次，本文件行数已在棘轮红线上）
    const shouldAlertUser = shouldSendAlert(`brute_force_user_${username}`);
    const shouldAlertIp = shouldSendAlert(`brute_force_ip_${ip}`);
    if (!shouldAlertUser && !shouldAlertIp) return;

    // E-04 口径：封禁与阶梯统计都以**归一化 IP** 为准。addToBlacklist 入库的是归一化
    // 形态，用原始值（如 ::ffff:1.2.3.4）查询会恒为 0，阶梯永远停在第一档。
    const normalizedIp = normalizeIP(ip) || ip;

    // R-H2：**封禁判据只看 IP 维度**。maxFailures 取的是双维度的较大值——分布式撞
    // 单账号（多个攻击 IP 各自少量尝试同一账号）会让 userFailures 达标，而"当前请求
    // 的 IP"可能只贡献了 1 次失败：此时封它，NAT 出口后的无辜用户陪绑（受害者本人
    // 换个网络登录一次即被封 1 小时）。账号维度的攻击由账户锁定 + loginUserLimiter
    // 兜底；IP 封禁只对「这个 IP 自己刷满了失败」的确定性信号执行。

    // 渐进式封禁的"第几次"必须在**本次告警落库之前**统计：
    // 每穿过一次上面的频控闸 = 一条 brute_force_login 审计 + 一次封禁动作，
    // 所以"历史上这个 IP 触发过几条该审计"就是封禁事件数。
    // 为什么不数 ipblacklist 集合：该集合上 (ip,type) 唯一（models/IPBlacklist.js:92），
    // blockIP 用 findOneAndUpdate + $setOnInsert:createdAt（:266），且 TTL 索引（:89）
    // 到期即删档 ⇒ 同一 IP 任何时刻最多只剩一条 ⇒ countDocuments 恒 ≤1，
    // 第三/四档（24 小时、7 天）永不可达，而日志照打"第 N 次"——运维以为阶梯在工作。
    // 审计是 append-only 的，是唯一能承载"事件次数"的现存存储。
    // 代价：窗口受审计留存期约束，留存配得比 30 天短时阶梯窗口随之收窄（不假装是 30 天）。
    let priorBans = 0;
    try {
      priorBans = await IPBanEvents.countPrior(normalizedIp);
    } catch (e) {
      // 统计失败按第一档处理（宁可少封不可不封），但必须留痕：阶梯退化是可观测的
      logger.error(`自动封禁阶梯统计失败（按第一档处理）: ${ip}, 错误: ${e.message}`);
    }

    // P1-23：审计写入挂独立 try/catch。此前裸 await 位于 try 块之外，
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
        riskFactors: [`登录失败次数超标 (账户:${userFailures}, IP:${ipFailures})`],
        body: { userAttempts: userFailures, ipAttempts: ipFailures, window: '5 分钟' },
      });
    } catch (e) {
      logger.error(`暴力破解告警审计落库失败（封禁流程继续）: ${e.message}`);
    }

    // B-M1：投递走 fire-and-forget——本函数被登录失败/导出路径 await，
    // 告警已落库（上方 create 在 await 内，即时性保留），这里只走网络投递
    dispatchNotification(
      ALERT_TYPES.BRUTE_FORCE,
      ALERT_LEVELS.CRITICAL,
      `检测到暴力破解攻击：用户 ${username}，IP ${ip}`,
      { username, ip, attempts: maxFailures }
    );

    // R-H2：IP 维度未达标（分布式撞单账号）到此为止——告警与审计已落库
    // （body 的 ipAttempts 即判据），封禁只对「这个 IP 自己刷满了失败」执行
    if (ipFailures < THRESHOLDS.bruteForceAttempts) return;

    try {
      // E-04：**必须**保持惰性 require（securityAlert ↔ middleware/security
      // 循环依赖），提到文件顶部会在加载顺序不利时拿到未完成的导出。
      const { addToBlacklist } = require('../middleware/security');
      const tier = IPBanEvents.tierFor(priorBans);
      const tierReason = `brute_force_auto_ban_tier${tier + 1}`;
      // addToBlacklist 自己 catch 掉所有失败、从不抛错 ⇒ "await 正常返回"绝不等于"封禁生效"。
      // 修复前这里无条件打「渐进式封禁 IP x：第 N 次，封禁 X 小时」，而白名单命中、地址解析失败、
      // 黑名单写库失败三条路径下**一条记录都没有**：运维读到"已封 7 天"以为攻击者被挡住，
      // 实际上该 IP 还在自由撞库（纸面防线）。封禁结果只能按返回值分派，不能按异常分派。
      // 成功行不带时长：addToBlacklist 自己会打「封禁时长：N秒」，两处各写一遍必然漂移。
      const result = await addToBlacklist(normalizedIp, ESCALATION_TIERS[tier], tierReason, 'auto');
      if (result?.banned) logger.warn(`渐进式封禁 ${normalizedIp} 第 ${priorBans + 1} 次`);
      else
        logger.error(
          `自动封禁未生效 ${normalizedIp}（${result?.reason ?? 'no_result'}）请人工封禁或核对白名单`
        );
    } catch (e) {
      logger.error(`自动封禁 IP 失败: ${ip}, 错误: ${e.message}`);
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
  if (!shouldSendAlert(alertKey)) return;

  // P1-23 同口径：告警审计落库失败**不得**冒泡到调用方。checkBulkExport 被
  // reportController/auditController 的导出路径 `await`，此前裸 await AuditLog.create
  // 在 DB 瞬断/校验失败时会把一次本已成功的导出顶成 500——告警是旁路增强，
  // 绝不该拖垮主流程。捕获后仍继续投递通知（告警本身重要），仅记 error 不静默。
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
  dispatchNotification(
    ALERT_TYPES.BULK_EXPORT,
    ALERT_LEVELS.HIGH,
    `检测到批量数据导出：用户 ${username}，数量 ${count}`,
    { userId, username, count, operation }
  );
};

/**
 * 检测非常规时间访问
 * P3-7/P3-18：阈值与时区均取 constants/timezone 单一声明，
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
 */
const checkPermissionAbuse = async (userId, ip) => {
  // B-L6 接线口径：信号取全局审计中间件落库的 403 响应（写路径 403 均有记录，
  // 零新增写入），兼容显式写入的 permission_denied/forbidden 动作
  const recentFailures = await AuditLog.countDocuments({
    userId,
    $or: [{ statusCode: 403 }, { action: { $in: ['permission_denied', 'forbidden'] } }],
    timestamp: { $gte: new Date(Date.now() - THRESHOLDS.permissionWindowMs) },
  });

  if (recentFailures >= THRESHOLDS.permissionFailures) {
    const alertKey = `permission_abuse_${userId}`;
    if (!shouldSendAlert(alertKey)) return;

    // username 为 AuditLog 必填字段：缺失会让告警写入 ValidationError 静默失败
    //（批次 E 测试暴露的潜伏缺陷——该函数此前无调用方，缺陷从未触发）
    const User = require('../models/User');
    const abuser = await User.findById(userId).select('username').lean();
    if (!abuser) return;

    // P1-23 同口径（另两个检测器都已挂 try/catch，这里是漏网的第三处）：调用方
    // middleware/rbac.js 是 `void checkPermissionAbuse(...).catch(() => {})`，
    // 裸 await 一旦抛错（DB 瞬断/必填字段校验失败）整条 HIGH 告警会**无声消失**——
    // 既不进审计、也没有一行日志，运维与代码都无从知道权限滥用检测在掉链子。
    // 捕获后仍继续投递通知：告警落库失败不该连带吞掉另一条独立的通知通道。
    try {
      await AuditLog.create({
        action: ALERT_TYPES.PERMISSION_ABUSE,
        category: 'system',
        userId,
        username: abuser.username || String(userId),
        ip,
        riskLevel: ALERT_LEVELS.HIGH,
        riskFactors: ['频繁权限检查失败'],
        body: { failures: recentFailures },
      });
    } catch (e) {
      logger.error(`权限滥用告警审计落库失败（通知流程继续）: ${e.message}`);
    }

    // B-M1：同上，fire-and-forget
    dispatchNotification(
      ALERT_TYPES.PERMISSION_ABUSE,
      ALERT_LEVELS.HIGH,
      `检测到权限滥用：用户 ${userId}，失败 ${recentFailures} 次`,
      { userId, ip, failures: recentFailures }
    );
  }
};

/**
 * 获取安全概览（管理员仪表盘）
 */
const getSecurityOverview = async (days = 7) => {
  try {
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const [criticalAlerts, highAlerts, failedLogins, unusualAccess] = await Promise.all([
      AuditLog.countDocuments({ riskLevel: 'critical', timestamp: { $gte: since } }),
      AuditLog.countDocuments({ riskLevel: 'high', timestamp: { $gte: since } }),
      AuditLog.countDocuments({ action: 'login_failed', timestamp: { $gte: since } }),
      // riskFactors 是数组字段，用 $in 匹配数组中是否包含非常规时间访问标记
      AuditLog.countDocuments({
        riskFactors: { $in: ['unusual_time', 'unusual_time_access'] },
        timestamp: { $gte: since },
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
    return {
      period: `${days}天`,
      criticalAlerts: 0,
      highAlerts: 0,
      failedLogins: 0,
      unusualAccess: 0,
      riskScore: 0,
    };
  }
};

/**
 * 获取最近的告警列表
 *
 * 数据范围必须与 GET /api/security/audit-logs **同源**：两个端点挂同一个权限码
 * `security:audit`（routes/securityRoutes.js:235 / :276），而 /audit-logs 走
 * `applyAuditDataScope`（auditQueryService.js:217）。此前本函数不带范围条件，
 * 于是 level 8 的 SECURITY_ADMIN（initData 的口径：level ≥7 只有本部门范围）
 * 可以从这里读出全系统的高危审计行（username/ip/path/body）——
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
  return await AuditLog.find(query)
    .sort({ timestamp: -1 })
    .limit(limit)
    .select(
      'action category riskLevel username ip timestamp body method path statusCode success duration userAgent'
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
