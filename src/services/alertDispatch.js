/**
 * 告警频控与投递入口（自 securityAlert.js 抽出）
 *
 * 抽出的直接原因：`securityAlertPermissionAbuse` 需要 `shouldSendAlert` /
 * `dispatchNotification`，若定义在 `securityAlert` 里会形成
 * `securityAlert ↔ permissionAbuse` 的双向依赖。频控表与投递壳不依赖任何检测逻辑，
 * 独立成叶子模块后两个文件都只单向引用它（新增检测器必须保持这个方向）。
 *
 * 投递仍是 fire-and-forget：webhook 不可达时（2 次重试 × 5s 超时 + 退避 ≈ 11s）
 * 会把延迟放大到认证/导出响应上，构成 DoS 放大器，所以检测器只"投递"、不等待。
 */

const logger = require('../utils/logger');
const { sendNotification } = require('./securityAlertDelivery');
const { readPositiveNumberEnv } = require('../utils/envNumber');

const ALERT_RATE_LIMIT_MS = 5 * 60 * 1000;

// 告警频率限制缓存。结构：{ alertKey: { timestamp, expiresAt } }
const alertRateLimit = new Map();

// 容量上限：alertKey 含攻击者可控内容（如 `brute_force_user_${username}`，
// username 来自登录请求体且只限长度不限字符集），攻击者轮换用户名即可驱动
// Map 增长。已有 5 分钟过期 + 10 分钟清理定时器兜底，规模有界但界值取决于
// 攻击速率（10 分钟内的唯一 key 数）——万级 QPS 撞库下仍可达数百万条目。
// 此处加硬上限：超限时先清过期项，仍超限则整体清空（宁可短时放开频控，
// 也不能让告警模块本身成为内存耗尽的入口）。
// 原 `Number(env) || 10000` 接受负值，而 -1 会让
// `alertRateLimit.size >= cap` 与 `remaining >= cap` 双双恒真 ⇒ 每来一条告警就
// alertRateLimit.clear() 并打 error，风暴抑制形同不存在（且自身成为日志放大器）。
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
  if (!alertCleanupTimer) return;
  clearInterval(alertCleanupTimer);
  alertCleanupTimer = null;
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

  // 写入前做容量保护
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
    expiresAt: now + ALERT_RATE_LIMIT_MS,
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

const __resetAlertRateLimitForTest = () => alertRateLimit.clear(); // 测试钩子：清频控表（生产不得调用；用例侧理由见各 honeypot 套件的前置注释）

module.exports = {
  __resetAlertRateLimitForTest,
  ALERT_RATE_LIMIT_MS,
  startAlertCleanup,
  stopAlertCleanup,
  shouldSendAlert,
  dispatchNotification,
};
