/**
 * 安全告警的级别与类型枚举（单一事实来源）
 *
 * 此前 `securityAlertPermissionAbuse` 从 `securityAlert` 反向取用这两个枚举，
 * 而 `securityAlert` 又静态引用前者，构成双向依赖。枚举本身不依赖检测逻辑，
 * 独立成叶子后两侧都单向引用本模块。
 */

const { BAN_EVENT_ACTIONS } = require('./securityAlertIpBans');
const { AUDIT_CHAIN_ALERT_TYPES } = require('./auditChainAlertTypes');
const { CANARY_ALERT_TYPES } = require('./canaryAlertTypes');

// 告警级别
const ALERT_LEVELS = { LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };

// 告警类型
const ALERT_TYPES = {
  BRUTE_FORCE: BAN_EVENT_ACTIONS.BRUTE_FORCE,
  PRIVILEGE_ESCALATION: 'privilege_escalation',
  BULK_EXPORT: 'bulk_data_export',
  UNUSUAL_TIME: 'unusual_time_access',
  PERMISSION_ABUSE: BAN_EVENT_ACTIONS.PERMISSION_ABUSE,
  SUSPICIOUS_IP: 'suspicious_ip_activity',
  RATE_LIMIT_ABUSE: 'rate_limit_abuse', // 限流触顶升级封禁（rateLimitEscalation 闭环）
  // 审计哈希链三类（2026-09-30）：定义见 auditChainAlertTypes.js，判据见 auditChainMonitor.js
  ...AUDIT_CHAIN_ALERT_TYPES,
  // 哨兵用户名探测（2026-10-19）：定义见 canaryAlertTypes.js，判据见 canaryWatch.js
  ...CANARY_ALERT_TYPES,
};

module.exports = { ALERT_LEVELS, ALERT_TYPES };
