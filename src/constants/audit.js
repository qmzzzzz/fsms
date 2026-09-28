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

// AUDIT_RISK_LEVELS 是**有序**清单（低→中→高→致命），所以"某档及以上"是这里的一个切片，
// 而不是一句需要人肉复述的话。所有此类判据必须由 riskLevelsAtLeast 派生（F-149）。
// 不这么办的失效模式不是"报错"，是静默漏：给 AUDIT_RISK_LEVELS 新增一档（例如 'urgent'
// 插在 high 与 critical 之间）后，手抄的 `['high','critical']` 会把新档留在"高危"之外，
// 而查询/导出侧的白名单引用的是同一份 AUDIT_RISK_LEVELS、已经放行 ⇒ 新档记录能落库、
// 能在审计页筛出来，却不进任何高危聚合（securityController）、告警取数（securityAlert）、
// 行为基线（behaviorBaseline）与导出等级派生（reportExportService/auditQuery）——
// 安全侧的漏，且没有任何一处会说"这一档没人管"。
// 档位找不到时直接抛：返回半截清单（slice(-1) 之类）等于把上面那个失效模式搬进派生器。
const riskLevelsAtLeast = (level) => {
  const idx = AUDIT_RISK_LEVELS.indexOf(level);
  if (idx < 0) {
    throw new Error(
      `riskLevelsAtLeast('${level}')：'${level}' 不在 AUDIT_RISK_LEVELS 内——` +
        '档位清单改过之后，所有"某档及以上"的判据都要跟着改，不能退回手抄字面量'
    );
  }
  // 冻结的理由同 originCheck.WRITE_METHODS：共享默认值被某个调用方 push 一下就会改掉全部门槛
  return Object.freeze(AUDIT_RISK_LEVELS.slice(idx));
};

// 「高危及以上」＝错误档的判定基础（审计页 level=error、导出里的"错误"标签同一口径）
const AUDIT_ERROR_RISK_LEVELS = riskLevelsAtLeast('high');

// 「警告及以上」。审计页 info 档用的是它的补集（`$nin`）而不是 `$in: ['low']`：
// 这是既有行为，补集形式对 riskLevel 缺失/为 null 的存量文档仍然成立，
// 换成 $in 会让这类文档从 info/warning/error 三个档里同时消失。
const AUDIT_WARNING_OR_HIGHER_RISK_LEVELS = riskLevelsAtLeast('medium');

// 审计记录 method 维的取值全集（单一事实来源：AuditLog schema 的 enum 与所有写入点共用）。
//
// 为什么必须有 HEAD：Express 把 HEAD 路由到 GET 处理器，而全局审计中间件与 authenticate
// 都排在路由之前，所以"带 token 的 HEAD"是常态流量（监控 curl -I、探测脚本、浏览器预取）。
// 原先 enum 只有 5 个动词，这类记录的 method 落在枚举外 ⇒ **整条文档**被 ValidationError 拒掉，
// 且两条落库路径都不说"是 method 越枚举"：
//   - 直写路径 AuditLog.record()：错误进 catch，只剩一行 error 日志 + audit_write_failed 指标，
//     ip_range_denied（riskLevel=high）这类事件在留存里凭空消失；
//   - 缓冲路径 auditBuffer 的 insertMany({ordered:false})：该文档被当成"毒文档"重试数轮后丢弃，
//     与本模块刻意丢弃畸形外部文档的语义混在一起，事后无法区分"客户端畸形"与"我们自己太窄"。
// OPTIONS 由 app.js 的 cors() 在 preflight 分支直接 204 结束（preflightContinue 默认 false），
// 走不到审计层；列进来是防御性收口，避免将来摘掉 cors 或改路由顺序时又回到同一处缺口。
const AUDIT_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

/**
 * method 的落库闸：枚举外的动词一律降级为「不记 method」。
 *
 * 抽成函数不是为了复用而复用——**批量写入路径必须在算哈希之前做同一份降级**。
 * 逐条路径（AuditLog.create）先铸造后算哈希，两侧天然同源；批量路径
 * （auditBuffer → chainBatch → insertMany）先对普通对象算哈希，铸造发生在之后，
 * 于是 schema 的 set 把 method 抹掉时「被哈希的形态」与「落库的形态」分叉，
 * 那条记录从此永远核验不过（永久假篡改），且它自身的完整性保护静默失效——
 * 已经是红的记录再被改也照样红，唯一的"补救"是整库重签（等于销毁取证价值）。
 * 触发它只需一条 `curl -X FOO`：app 级审计中间件在路由匹配之前就跑，收得下任意动词。
 */
const auditMethodOrUndefined = (value) => (AUDIT_HTTP_METHODS.includes(value) ? value : undefined);

// 审计页的「日志等级」三级展示口径（由 success + riskLevel 派生，不是库里存的字段）。
// 与 AUDIT_RISK_LEVELS 同理收成单一事实来源：查询侧（utils/auditQuery）、导出侧
// （reportExportService 的枚举校验与 includes 闸门）原先各写一份字面量，
// 单侧增删就会造成"查询放行、导出 400"的口径漂移（E-05 同一类）。
const AUDIT_DISPLAY_LEVELS = ['info', 'warning', 'error'];

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
  // P1-11：登录失败计数达阈值触发的 10 分钟临时锁定（authService 写入）。
  // 此前缺失于白名单：记录在库却无法按该 action 筛选（validateEnum 打 400）
  'account_temp_locked',
  'user_unlocked',
  // 安全告警事件
  'brute_force_login',
  // 限流持续触顶的升级封禁事件（rateLimitEscalation 写入，CC 防护闭环）
  'rate_limit_abuse',
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
  // queryLimit 的两类拒绝（参数超长 / 收到对象数组形态的取值）。
  // 与上面三类同族：都发生在 auditLog 之前，此前只进 logger。
  // 不复用 malformed_request_blocked：那一条由协议合规层发出（Content-Type/头部/方法畸形），
  // 这一条是 NoSQL 操作符与资源耗尽探测的指纹，混在一起就分不出"谁在探查询参数"。
  'query_param_rejected',
  // 响应头已发出、流被中途截断时补写的更正事件（errorHandler 的 markResponseAbortedByError）。
  // 不登记就是 P1-11 复发：记录确实落库了，但 validateEnum 对不在白名单的 action 直接 400
  // ⇒ 查询与导出都筛不出它，"这次导出被截断了"这条唯一的线索变成查不到的死角。
  'response_aborted_after_headers',
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
  riskLevelsAtLeast,
  AUDIT_ERROR_RISK_LEVELS,
  AUDIT_WARNING_OR_HIGHER_RISK_LEVELS,
  AUDIT_HTTP_METHODS,
  auditMethodOrUndefined,
  AUDIT_DISPLAY_LEVELS,
  AUDIT_LOG_ACTIONS,
};
