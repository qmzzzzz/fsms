/**
 * 审计日志枚举常量 —— 单一事实来源
 *
 * 用途：消除 AuditLog schema enum 与审计查询校验白名单两处定义的漂移风险。
 * 新增/调整分类时只改本文件，schema 与控制器校验自动同步。
 *
 * 取值必须与 utils/auditMeta.js 的 ROUTE_CATEGORY_MAP 取值全集保持一致，
 * 否则未覆盖的分类会在 insertMany({ordered:false}) 时被 ValidationError 静默丢弃。
 */

const AUDIT_CATEGORIES = [
  'auth',
  'user',
  'role',
  'permission',
  'device',
  'alarm',
  'inspection',
  'security',
  'report',
  'system',
];

const AUDIT_RISK_LEVELS = ['low', 'medium', 'high', 'critical'];

// 审计日志 action 枚举白名单
// 分两部分：
//  1) 路由派生型——由 utils/auditMeta 的 deriveAction 从「完整路径」推导，
//     命名规律为 {category}_{子路径}，无子路径时按方法映射 create/update/delete；
//     新增写路由时必须同步补充此处，否则审计页无法按该 action 筛选（validateEnum 返回 400）
//  2) 事件型——由控制器/服务显式写入（登录成败、安全告警、配置变更等），无对应 HTTP 路由语义
// D-1：自 securityController 迁入，供审计查询/导出（auditController）与
// 报表导出（reportController）等多处复用同一份枚举
const AUDIT_LOG_ACTIONS = [
  // ===== 路由派生型 =====
  // 认证类
  'auth_register',
  'auth_login',
  'auth_refresh',
  'auth_password',
  'auth_profile',
  'auth_logout',
  // P3-11：认证类其余路由派生 action（GET 类多为敏感读取，POST 为状态变更）
  'auth_captcha',
  'auth_captcha-status',
  'auth_login-public-key',
  'auth_session',
  'auth_me',
  'auth_mfa_status',
  'auth_mfa_enroll',
  'auth_mfa_enable',
  'auth_mfa_disable',
  'auth_mfa_recovery-codes',
  // 用户/角色/权限类
  'user_create',
  'user_update',
  'user_delete',
  'user_roles',
  'user_batch',
  'role_create',
  'role_update',
  'role_delete',
  'role_permissions',
  'permission_create',
  'permission_update',
  'permission_delete',
  'permission_batch',
  // P3-11：角色列表兜底路由
  'role_all',
  // 业务类
  'device_create',
  'device_update',
  'device_status',
  'device_maintenance',
  'device_delete',
  'device_scrap',
  'alarm_report',
  'alarm_dispatch',
  'alarm_arrive',
  'alarm_resolve',
  'alarm_false-alarm',
  'alarm_cancel',
  'inspection_create',
  'inspection_update',
  'inspection_start',
  'inspection_complete',
  'inspection_review',
  'inspection_cancel',
  'inspection_delete',
  // 安全管理类
  'security_change-password',
  'security_view-sensitive',
  'security_report-suspicious',
  'security_users_lock',
  'security_ip-list',
  'security_config_allowPublicRegistration',
  'security_config_loginCaptchaEnabled',
  // 注册验证码开关（PUT/GET /api/security/config/registerCaptchaEnabled）：
  // 路由已存在但白名单遗漏，审计页按该 action 筛选会被 validateEnum 打 400
  // ——记录进了库却查不出来，属于「审计留痕形同虚设」
  'security_config_registerCaptchaEnabled',
  // WB-1：生产启动期密钥强度审计留痕（validate 已拦截弱密钥，此处记录「已通过」事实）
  'security_key_strength_audit',
  // P3-11：以下派生 action 此前缺失于白名单——审计页按它们筛选会被
  // validateEnum 打 400（记录在库里却筛不出来）。与各路由文件逐一核对：
  'security_view', // GET /api/security（无子路径兜底）
  'security_my-info', // GET /api/security/my-info
  'security_bindings', // GET /api/security/bindings
  'security_stats', // GET /api/security/stats
  'security_overview', // GET /api/security/overview（auditGetPaths 未覆盖，防未来接入）
  'security_alerts', // GET /api/security/alerts
  'security_users_view', // GET 类用户子路径兜底
  'security_users_mfa_reset', // PUT /api/security/users/:userId/mfa/reset
  'security_audit-logs_verify', // GET /api/security/audit-logs/verify
  'security_ip-list_query', // GET /api/security/ip-list/query
  'user_stats', // GET /api/users/stats
  'user_view', // GET /api/users/:id（敏感读取审计）
  'role_view', // GET /api/roles/:id
  'role_permissions_tree', // GET /api/roles/permissions/tree
  'permission_view', // GET /api/permissions/:id
  'device_stats', // GET /api/devices/stats
  'device_expiring', // GET /api/devices/expiring
  'device_reminders', // GET /api/devices/reminders
  'device_view', // GET /api/devices/:id
  'alarm_stats', // GET /api/alarms/stats
  'alarm_view', // GET /api/alarms/:id
  'inspection_stats', // GET /api/inspections/stats
  'inspection_view', // GET /api/inspections/:id
  'report_dashboard', // GET /api/reports/dashboard
  'report_devices', // GET /api/reports/devices
  'report_alarms', // GET /api/reports/alarms
  'report_inspections', // GET /api/reports/inspections
  'report_export', // GET /api/reports/export（auditGetPaths 覆盖）
  'security_report', // POST /api/security/report
  'security_my-logs', // GET /api/security/my-logs
  'security_audit-logs', // GET /api/security/audit-logs（auditGetPaths 覆盖）
  'security_audit-logs_export', // GET /api/security/audit-logs/export
  // 设备级会话管理（sid 为 UUID，已由 deriveAction 剔除动态段）
  'auth_sessions', // GET /api/auth/sessions、DELETE /api/auth/sessions/:sid
  'auth_sessions_others', // DELETE /api/auth/sessions/others

  // ===== 事件型 =====
  // 认证事件
  'login_success',
  'login_failed',
  'login_unusual_time',
  'logout',
  'password_changed',
  'change_password',
  // MFA 两步验证事件（登录 MFA 步骤/开关/恢复码/管理员重置全链路）
  'mfa_challenge',
  'mfa_verify_failed',
  'mfa_attempt_locked',
  'mfa_enroll',
  'mfa_enable',
  'mfa_disable',
  'login_recovery_code',
  'recovery_codes_regenerate',
  'admin_reset_mfa',
  // 设备级会话事件（用户从「登录会话」界面踢除设备）
  'session_revoked',
  'session_revoked_others',
  // 用户状态事件
  'user_locked',
  'user_unlocked',
  // 安全告警事件
  'brute_force_login',
  'bulk_data_export',
  'permission_abuse',
  'privilege_escalation',
  'suspicious_ip_activity',
  'suspicious_report',
  'view_sensitive_data',
  'ip_range_denied',
  'audit_log_query',
  'audit_chain_verify',
  // P3-35：早于 auditLog 中间件的 403 拒绝（黑名单命中 / CSRF 来源校验失败）
  // 与协议合规拒绝。此前这三类拒绝只进 logger，审计页无从筛选
  'ip_blacklist_blocked',
  'csrf_origin_denied',
  'malformed_request_blocked',
  // 系统配置事件
  'registration_enabled',
  'registration_disabled',
  'login_captcha_enabled',
  'login_captcha_disabled',
  'register_captcha_enabled',
  'register_captcha_disabled',
  'ip_blacklist_added',
  'ip_blacklist_removed',
  'ip_whitelist_added',
  'ip_whitelist_removed',

  // ===== 历史兼容 =====
  // 修复前（req.path 被剥离导致派生失效）产生的记录，保留以便查询存量数据
  'system_create',
  'system_update',
  'system_delete',
  'batch_delete_users',
  'role_assign_permissions',
  'permission_batch_create',
  'device_status_update',
  'device_maintenance_add',
  'alarm_false_alarm',
];

module.exports = {
  AUDIT_CATEGORIES,
  AUDIT_RISK_LEVELS,
  AUDIT_LOG_ACTIONS,
};
