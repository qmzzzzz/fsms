/**
 * 手写审计写入失败的统一处理器（P0-5 回归防护）
 *
 * 背景：P0-5 修复后 `res.locals.skipGlobalAudit` 在响应时刻读取、真正生效，
 * 「控制器手写 AuditLog.create」成为该类操作在审计库中的**唯一留痕**。
 * 修复前该标志恒失效，全局审计中间件总会补记一条，因此控制器侧
 * `.catch(() => {})` 静默吞错时仍有兜底记录；修复后同样的静默吞错会让
 * 整个操作**零留痕**（合规上不可接受，且无任何可观测信号）。
 *
 * 本模块提供统一的失败处理器：
 *   - 不改变业务语义：审计失败仍不阻断主流程（与原 `.catch(() => {})` 一致）；
 *   - 但不再静默：写 error 日志 + 计入 security_alerts_total{type=audit_write_failed}，
 *     使「审计链出现缺口」在日志与监控面同时可见。
 *
 * 与 models/auditLogWriteStatics.js 的 `record()` 是同一纪律的两个落点
 * （那边 level=medium 且 resolve null；这边调用方用的是 `AuditLog.create`，
 * 需自行兜底且 level=high——因为此处记录的是敏感操作/安全配置变更）。
 */

const logger = require('./logger');

/**
 * 生成 `.catch()` 处理器
 * @param {string} auditAction 便于检索的审计动作标识（非 AuditLog 的 action 枚举值）
 * @param {object} [req] 可选：用于取操作者用户名
 * @returns {(err: Error) => void}
 */
const onAuditWriteFailure = (auditAction, req) => (err) => {
  logger.error(`{审计写入失败}：${err.message}`, {
    auditAction,
    operator: req?.user?.username,
  });
  try {
    require('./metrics').incSecurityAlert('audit_write_failed', 'high');
  } catch (_) {
    /* 指标端不可用时仅保留日志 */
  }
};

module.exports = { onAuditWriteFailure };
