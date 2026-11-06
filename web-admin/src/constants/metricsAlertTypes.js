/**
 * 系统运行指标面板的告警类型码表（前端镜像）
 *
 * 面板数据取自 GET /api/metrics 的 alerts[].type，取值就是后端 incSecurityAlert 的字符串。
 * 中文/英文标签在 i18n 的 about.metrics.alertTypes 下，本清单是「必须登记」的名单：
 * tests/i18n/metricsAlertTypesCoverage.test.js 既逐个查词条，也回扫后端源文件——
 * 后端新增告警类型而不登记词条会当场红（页面上则退回裸码，见 AboutView.metricsAlertLabel）。
 *
 * 清单来源：services/alertTypes.js 的 ALERT_TYPES、constants/failOpenSites.js 的
 * FAIL_OPEN_SITES[].type、以及直接调用 incSecurityAlert / sendNotification 的字面量；
 * captcha_${scope}_cap_reached 是模板字面量，scope 只有 ip / global 两个取值。
 */
export const METRICS_ALERT_TYPE_CODES = [
  'admin_initial_password_file_delete_failed',
  'admin_initial_password_permission_not_tightened',
  'admin_initial_password_write_failed',
  'audit_anomaly_detected',
  'audit_chain_break_detected',
  'audit_chain_verify_failed',
  'audit_hash_compute_failed',
  'audit_wal_permission_not_tightened',
  'audit_write_failed',
  'ban_ladder_degraded',
  'brute_force_login',
  'bulk_data_export',
  'canary_username_attempt',
  'captcha_active_bound_lost',
  'captcha_global_cap_reached',
  'captcha_ip_cap_reached',
  'captcha_switch_db_fallback',
  'forensic_capture_trigger_unavailable',
  'forensic_capture_write_failed',
  'honeypot_chain_escalated',
  'honeypot_login',
  'honeypot_probe',
  'idempotency_degraded',
  'idempotency_lease_takeover',
  'ip_blacklist_failopen',
  'legacy_cbc_decrypt_enabled',
  'login_encrypt_strict_disabled',
  'nosql_injection_attempt',
  'password_history_pepper_rotation',
  'permission_abuse',
  'pii_rotation_old_key_lingering',
  'pii_v1_rows_unmigrated',
  'privilege_escalation',
  'proxy_protocol_header_rejected',
  'rate_limit_abuse',
  'rate_limit_auth_abuse',
  'rate_limit_triggered',
  'ratelimit_store_degraded',
  'reauth_grant_store_degraded',
  'scan_probe_detected',
  'scan_probe_storm',
  'security_detection_failed',
  'sql_injection_attempt',
  'suspicious_ip_activity',
  'trusted_proxy_cidrs_unset',
  'unusual_time_access',
  'ws_inbound_throttled',
]
