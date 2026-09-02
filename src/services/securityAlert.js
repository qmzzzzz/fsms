/**
 * 安全告警服务
 * 监控和响应系统安全事件
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { incSecurityAlert } = require('../utils/metrics');
const { normalizeIP } = require('../utils/ipUtils');
const { businessHour, isOffHours } = require('../constants/timezone');

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
};

// 告警频率限制缓存
// 结构：{ alertKey: { timestamp, expiresAt } }
const alertRateLimit = new Map();

// P3-24 容量上限：alertKey 含攻击者可控内容（如 `brute_force_user_${username}`，
// username 来自登录请求体且只限长度不限字符集），攻击者轮换用户名即可驱动
// Map 增长。已有 5 分钟过期 + 10 分钟清理定时器兜底，规模有界但界值取决于
// 攻击速率（10 分钟内的唯一 key 数）——万级 QPS 撞库下仍可达数百万条目。
// 此处加硬上限：超限时先清过期项，仍超限则整体清空（宁可短时放开频控，
// 也不能让告警模块本身成为内存耗尽的入口）。
const ALERT_RATE_LIMIT_MAX_ENTRIES = Number(process.env.ALERT_RATE_LIMIT_MAX) || 10000;

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
 * 发送告警通知
 * 始终写结构化日志；配置了 SECURITY_ALERT_WEBHOOK 时额外投递到 IM/告警平台
 * （钉钉/企业微信/Slack 等通用 JSON Webhook）。
 *
 * 成熟化（可观测性轮）：
 * - 出站前 SSRF 校验：协议仅 http/https、拒绝本机地址、IP 字面量拒绝
 *   私网/保留段；域名的内网指向风险由可选 SECURITY_ALERT_WEBHOOK_ALLOWLIST
 *   （主机名白名单，逗号分隔）承接，生产环境建议必配
 * - 投递通道走 utils/httpPostJson（node:https 显式传参）
 * - 失败自动重试 1 次（1s 退避），仍失败仅告警不阻断主流程
 * - 可选 SECURITY_ALERT_WEBHOOK_SECRET：HMAC-SHA256 签名经 X-Webhook-Signature
 *   下发，接收端验签防伪造告警
 * - 每次告警计入 security_alerts_total 指标
 */
const sendNotification = async (alertType, level, message, data) => {
  const logMethod = level === 'critical' ? 'error' : level === 'high' ? 'warn' : 'info';
  const payload = {
    type: alertType,
    level,
    message,
    timestamp: new Date().toISOString(),
    ...data,
  };

  logger[logMethod]('SECURITY_ALERT', payload);
  incSecurityAlert(alertType, level);

  const webhookUrl = process.env.SECURITY_ALERT_WEBHOOK;
  if (!webhookUrl) return;

  // 仅投递达到最低级别的告警（默认 high 及以上，避免低价值噪声）
  const LEVEL_ORDER = { low: 1, medium: 2, high: 3, critical: 4 };
  const minLevel = process.env.SECURITY_ALERT_MIN_LEVEL || 'high';
  if ((LEVEL_ORDER[level] || 0) < (LEVEL_ORDER[minLevel] || 3)) return;

  // ===== 出站目标校验（SSRF 防护）=====
  let target;
  try {
    target = new URL(webhookUrl);
  } catch (_) {
    logger.warn('安全告警 webhook URL 无法解析，跳过投递');
    return;
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    logger.warn('安全告警 webhook 仅允许 http/https，跳过投递');
    return;
  }
  const targetHost = target.hostname.toLowerCase();
  if (
    targetHost === 'localhost' ||
    targetHost.endsWith('.localhost') ||
    targetHost.endsWith('.local')
  ) {
    logger.warn('安全告警 webhook 禁止指向本机地址，跳过投递');
    return;
  }
  // 主机白名单：配置后仅放行名单内主机（域名的内网指向由该白名单承接）
  const allowlist = (process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (allowlist.length > 0 && !allowlist.includes(targetHost)) {
    logger.warn('安全告警 webhook 主机不在 ALLOWLIST 白名单内，跳过投递');
    return;
  }
  // IP 字面量：拒绝私网/保留段
  if (/^[0-9a-f.:]+$/i.test(targetHost)) {
    const ipaddr = require('ipaddr.js');
    let parsedIp;
    try {
      parsedIp = ipaddr.parse(targetHost);
    } catch (_) {
      parsedIp = null;
    }
    const FORBIDDEN_RANGES = [
      'loopback',
      'private',
      'linkLocal',
      'uniqueLocal',
      'reserved',
      'unspecified',
      'carrierGradeNat',
    ];
    if (parsedIp && FORBIDDEN_RANGES.includes(parsedIp.range())) {
      logger.warn('安全告警 webhook 禁止指向 ' + parsedIp.range() + ' 地址，跳过投递');
      return;
    }
  }
  // ===== 校验完毕（全部通过才进入投递）=====

  const body = JSON.stringify({
    msgtype: 'text',
    text: {
      content:
        '【安全告警·' +
        level +
        '】' +
        message +
        '\n类型：' +
        alertType +
        '\n时间：' +
        payload.timestamp,
    },
    alert: payload,
  });

  // 可选签名：接收端以同密钥 HMAC-SHA256(body) 比对 X-Webhook-Signature
  const headers = {};
  const secret = process.env.SECURITY_ALERT_WEBHOOK_SECRET;
  if (secret) {
    const crypto = require('crypto');
    headers['X-Webhook-Signature'] =
      'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  }

  const { postJson } = require('../utils/httpPostJson');
  const MAX_ATTEMPTS = 2;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const res = await postJson(webhookUrl, headers, body, 5000);
      if (res.ok) return;
      logger.warn(
        '安全告警投递失败：HTTP ' + res.status + '（第 ' + attempt + '/' + MAX_ATTEMPTS + ' 次）'
      );
    } catch (err) {
      logger.warn('安全告警投递异常（第 ' + attempt + '/' + MAX_ATTEMPTS + ' 次）：' + err.message);
    }
    if (attempt < MAX_ATTEMPTS) {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
};

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
    // 按账户维度 + IP 维度分别做频率限制，避免重复告警
    const userAlertKey = `brute_force_user_${username}`;
    const ipAlertKey = `brute_force_ip_${ip}`;
    const shouldAlertUser = shouldSendAlert(userAlertKey);
    const shouldAlertIp = shouldSendAlert(ipAlertKey);
    if (!shouldAlertUser && !shouldAlertIp) return;

    await AuditLog.create({
      action: ALERT_TYPES.BRUTE_FORCE,
      category: 'auth',
      username,
      ip,
      riskLevel: ALERT_LEVELS.CRITICAL,
      riskFactors: [`登录失败次数超标 (账户:${userFailures}, IP:${ipFailures})`],
      body: { userAttempts: userFailures, ipAttempts: ipFailures, window: '5 分钟' },
    });

    await sendNotification(
      ALERT_TYPES.BRUTE_FORCE,
      ALERT_LEVELS.CRITICAL,
      `检测到暴力破解攻击：用户 ${username}，IP ${ip}`,
      { username, ip, attempts: maxFailures }
    );

    try {
      const IPBlacklist = require('../models/IPBlacklist');
      const { addToBlacklist } = require('../middleware/security');
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      // 历史封禁次数必须按归一化 IP 统计：addToBlacklist 入库的是归一化形态，
      // 用原始值（如 ::ffff:1.2.3.4）查询会恒为 0，封禁永远停在第一档
      const normalizedIp = normalizeIP(ip) || ip;
      const priorBans = await IPBlacklist.countDocuments({
        ip: normalizedIp,
        source: 'auto',
        createdAt: { $gte: thirtyDaysAgo },
      });
      const ESCALATION_TIERS = [
        1 * 60 * 60 * 1000,
        4 * 60 * 60 * 1000,
        24 * 60 * 60 * 1000,
        7 * 24 * 60 * 60 * 1000,
      ];
      const tierIndex = Math.min(priorBans, ESCALATION_TIERS.length - 1);
      const banDurationMs = ESCALATION_TIERS[tierIndex];
      await addToBlacklist(
        normalizedIp,
        banDurationMs,
        `brute_force_auto_ban_tier${tierIndex + 1}`,
        'auto'
      );
      logger.warn(
        `渐进式封禁 IP ${normalizedIp}：第 ${priorBans + 1} 次，封禁 ${banDurationMs / 3600000} 小时`
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
  if (count <= THRESHOLDS.bulkExportThreshold) return;

  const alertKey = `bulk_export_${userId}`;
  if (!shouldSendAlert(alertKey)) return;

  await AuditLog.create({
    action: ALERT_TYPES.BULK_EXPORT,
    category: 'system',
    userId,
    username,
    riskLevel: ALERT_LEVELS.HIGH,
    riskFactors: ['批量数据操作'],
    body: { operation, count },
  });

  await sendNotification(
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
  // 使用 $in 替代无锚点正则，可走 action 字段索引
  const recentFailures = await AuditLog.countDocuments({
    userId,
    action: { $in: ['permission_denied', 'forbidden'] },
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

    await sendNotification(
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
 */
const getRecentAlerts = async (limit = 50) => {
  return await AuditLog.find({
    riskLevel: { $in: ['high', 'critical'] },
  })
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
  checkBruteForce,
  checkBulkExport,
  checkUnusualTime,
  checkPermissionAbuse,
  getSecurityOverview,
  getRecentAlerts,
  sendNotification,
  shouldSendAlert,
  startAlertCleanup,
  stopAlertCleanup,
};
