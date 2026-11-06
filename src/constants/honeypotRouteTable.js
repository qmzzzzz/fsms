'use strict';

/**
 * 真实路由声明表（P2-2 路由台账）这份表是"app 里到底有哪些路由"的**唯一声明**：一行一条，方法 + 全路径（含挂载前缀、`:参数`）
 * + 权限码（单个 / 数组=OR / null=无 checkPermission）+ 认证中间件名（null=完全公开）
 * + 陷阱会话在这条路由上的回答类别（TRAP_HANDLING 的闭集）。
 * 为什么需要它：改道点（services/honeypotDecoy.js 的 steer）只挂在 `authenticate` 上，因此"未匹配路径回 403"这句话在 HTTP 上根本不可达——那些请求落到 app.js 的兜底 404，与真实会话逐字相同。判定层过去却把"前缀之外的一切"写成 DENY(403)，与真实语义不符。有了这张表，判定层才能把三件事分开：**已声明路由**（按前缀给合成数据面）、**前缀里的聚合子路径**（`/api/users/stats` 这类已声明端点，batch B 起回同形合成体）、**未知路径**（NOT_FOUND ⇒ 与 app.js 兜底的 `接口不存在：METHOD path` 逐字节相同）。
 * 判据的两端都在 CI 里：tests/ci/honeypotRouteTableParity.test.js 从 src/app.js 的挂载× src/routes/*.js 的声明**现算**一遍，与本表双向比对（多一行少一行、权限码/认证/敏感任一处不符都红），并把每一行的 handling 与真实判定链现算结果对拍。新增路由而忘了表态 ⇒ 该用例红；删路由而表里留着 ⇒ 同样红。与最大体积门禁（max-lines 300）的关系同 honeypotDecoyData.js：表是纯数据，判定在 constants/honeypotDecoy.js。本文件是**零 require 叶子**，可被判定层与门禁同时引用而无环。
 */

/** 陷阱对一条真实路由的回答类别（闭合词表） */
const TRAP_HANDLING = Object.freeze({
  PUBLIC: 'public', // 没有认证中间件：陷阱不参与，真实处理器照常应答
  PASSTHROUGH: 'passthrough', // 放行白名单：真实处理器应答（仅 3 条，逐条钉死）
  LIST: 'decoy-list', // 合成集合列表
  DETAIL: 'decoy-detail', // 合成明细；未命中合成表时按真实口径 404（集合专属错误码）
  AGGREGATE: 'decoy-aggregate', // 聚合端点：与真实控制器同字段集的合成体
  SUMMARY: 'decoy-summary', // P1 的合成汇总（batch C 收口为逐端点同形体）
  SELF: 'decoy-self', // 本人自助面：按会话身份回同形合成体
  FILE: 'decoy-file', // 文件/导出类：合成工作簿或按真实口径拒绝
  METRICS: 'decoy-metrics', // 运行时指标快照：与真实 getSnapshot() 同键集的合成体
  REAUTH: 'reauth401', // 缺票闸：回真实链逐字相同的 401 REAUTH_TICKET_REQUIRED。陷阱既不发票据也不持窗口，所以「缺票」是这些路由上唯一可能的真实答案；声明成合成面就是把「少一道闸」写在响应里
  DENY: 'deny403', // 一律拒绝（与真实 403 同一个响应构造器，错误体逐字相同）
});

const AUTHENTICATE = 'authenticate';
const AUTHENTICATE_LOGOUT = 'authenticateForLogout';

/** 一行声明：perm 为 null 表示声明里没有 checkPermission（不等于没有认证） */
const row = (method, path, perm, auth, handling, viewSensitive = false) =>
  Object.freeze({ method, path, perm, auth, handling, viewSensitive });

const pub = (method, path, handling) => row(method, path, null, null, handling);
const only = (method, path, handling) => row(method, path, null, AUTHENTICATE, handling);
const need = (method, path, perm, handling) => row(method, path, perm, AUTHENTICATE, handling);
const logout = (method, path, handling) => row(method, path, null, AUTHENTICATE_LOGOUT, handling);
const vsens = (method, path, handling) => row(method, path, null, AUTHENTICATE, handling, true);

/** 逐条声明（顺序 = 源码里各路由文件的声明顺序） */
const ROUTE_TABLE = Object.freeze([
  pub('POST', '/csp-report', 'public'),
  pub('POST', '/client-errors', 'public'),
  pub('GET', '/.well-known/security.txt', 'public'),
  pub('GET', '/security.txt', 'public'),
  pub('GET', '/api/version', 'passthrough'),
  pub('POST', '/api/auth/register', 'public'),
  pub('GET', '/api/auth/captcha', 'public'),
  pub('GET', '/api/auth/captcha-status', 'public'),
  pub('GET', '/api/auth/login-public-key', 'public'),
  pub('POST', '/api/auth/login', 'public'),
  pub('POST', '/api/auth/refresh', 'passthrough'),
  pub('GET', '/api/auth/session', 'public'),
  only('GET', '/api/auth/me', 'decoy-self'),
  only('PUT', '/api/auth/password', 'deny403'),
  only('PUT', '/api/auth/profile', 'deny403'),
  only('PUT', '/api/auth/avatar', 'deny403'),
  only('DELETE', '/api/auth/avatar', 'deny403'),
  logout('POST', '/api/auth/logout', 'passthrough'),
  only('GET', '/api/auth/mfa/status', 'decoy-self'),
  only('POST', '/api/auth/mfa/enroll', 'deny403'),
  only('POST', '/api/auth/mfa/enable', 'deny403'),
  only('POST', '/api/auth/mfa/disable', 'deny403'),
  only('POST', '/api/auth/mfa/recovery-codes', 'deny403'),
  only('GET', '/api/auth/sessions', 'decoy-self'),
  only('DELETE', '/api/auth/sessions/others', 'deny403'),
  only('DELETE', '/api/auth/sessions/:sid', 'deny403'),
  need('GET', '/api/users/stats', 'user:read', 'decoy-aggregate'),
  need('GET', '/api/users', 'user:read', 'decoy-list'),
  need('GET', '/api/users/:id', 'user:read', 'decoy-detail'),
  need('POST', '/api/users', 'user:create', 'deny403'),
  need('PUT', '/api/users/:id', 'user:update', 'deny403'),
  need('PUT', '/api/users/:id/roles', 'role:assign', 'deny403'),
  need('DELETE', '/api/users/batch', 'user:delete', 'deny403'),
  need('DELETE', '/api/users/:id', 'user:delete', 'deny403'),
  only('GET', '/api/avatars/:userId', 'decoy-file'),
  need('GET', '/api/roles', 'role:read', 'decoy-list'),
  need('GET', '/api/roles/all', 'role:read', 'decoy-aggregate'),
  need(
    'GET',
    '/api/roles/permissions/tree',
    ['permission:read', 'permission:tree'],
    'decoy-aggregate'
  ),
  need('GET', '/api/roles/:id', 'role:read', 'decoy-detail'),
  need('POST', '/api/roles', 'role:create', 'deny403'),
  need('PUT', '/api/roles/:id', 'role:update', 'deny403'),
  need('PUT', '/api/roles/:id/permissions', 'role:assign', 'deny403'),
  need('DELETE', '/api/roles/:id', 'role:delete', 'deny403'),
  need('GET', '/api/permissions', 'permission:read', 'decoy-list'),
  need('GET', '/api/permissions/grants', 'privilege:read', 'decoy-aggregate'),
  need('GET', '/api/permissions/grants/review', 'privilege:read', 'decoy-aggregate'),
  need('POST', '/api/permissions/grants', 'privilege:grant', 'deny403'),
  need('POST', '/api/permissions/grants/:id/approve', 'privilege:approve', 'deny403'),
  need('POST', '/api/permissions/grants/:id/reject', 'privilege:approve', 'deny403'),
  need('POST', '/api/permissions/grants/:id/revoke', 'privilege:grant', 'deny403'),
  need('GET', '/api/permissions/:id', 'permission:read', 'decoy-detail'),
  need('POST', '/api/permissions', 'permission:create', 'deny403'),
  need('POST', '/api/permissions/batch', 'permission:create', 'deny403'),
  need('PUT', '/api/permissions/:id', 'permission:update', 'deny403'),
  need('DELETE', '/api/permissions/:id', 'permission:delete', 'deny403'),
  need('GET', '/api/devices', 'device:read', 'decoy-list'),
  need('GET', '/api/devices/stats', 'device:read', 'decoy-aggregate'),
  need('GET', '/api/devices/expiring', 'device:read', 'decoy-aggregate'),
  need('GET', '/api/devices/reminders', 'device:read', 'decoy-aggregate'),
  need('GET', '/api/devices/:id', 'device:read', 'decoy-detail'),
  need('POST', '/api/devices', 'device:create', 'deny403'),
  need('PUT', '/api/devices/:id', 'device:update', 'deny403'),
  need('PUT', '/api/devices/:id/status', 'device:update', 'deny403'),
  need('POST', '/api/devices/:id/maintenance', 'device:maintain', 'deny403'),
  need('DELETE', '/api/devices/:id', 'device:delete', 'deny403'),
  need('PUT', '/api/devices/:id/scrap', 'device:scrap', 'deny403'),
  need('GET', '/api/alarms', 'alarm:read', 'decoy-list'),
  need('GET', '/api/alarms/stats', 'alarm:read', 'decoy-aggregate'),
  need('GET', '/api/alarms/:id', 'alarm:read', 'decoy-detail'),
  need('POST', '/api/alarms/report', 'alarm:create', 'deny403'),
  need('PUT', '/api/alarms/:id/dispatch', 'alarm:dispatch', 'deny403'),
  need('PUT', '/api/alarms/:id/arrive', 'alarm:handle', 'deny403'),
  need('PUT', '/api/alarms/:id/resolve', 'alarm:handle', 'deny403'),
  need('PUT', '/api/alarms/:id/false-alarm', 'alarm:handle', 'deny403'),
  need('PUT', '/api/alarms/:id/cancel', 'alarm:handle', 'deny403'),
  need('GET', '/api/inspections', 'inspection:read', 'decoy-list'),
  need('GET', '/api/inspections/stats', 'inspection:read', 'decoy-aggregate'),
  need('GET', '/api/inspections/:id', 'inspection:read', 'decoy-detail'),
  need('POST', '/api/inspections', 'inspection:create', 'deny403'),
  need('PUT', '/api/inspections/:id', 'inspection:create', 'deny403'),
  need('PUT', '/api/inspections/:id/start', 'inspection:execute', 'deny403'),
  need('PUT', '/api/inspections/:id/complete', 'inspection:execute', 'deny403'),
  need('PUT', '/api/inspections/:id/review', 'inspection:review', 'deny403'),
  need('PUT', '/api/inspections/:id/cancel', 'inspection:create', 'deny403'),
  need('DELETE', '/api/inspections/:id', 'inspection:delete', 'deny403'),
  need('GET', '/api/reports/dashboard', 'report:read', 'decoy-summary'),
  need('GET', '/api/reports/devices', 'report:read', 'decoy-summary'),
  need('GET', '/api/reports/alarms', 'report:read', 'decoy-summary'),
  need('GET', '/api/reports/inspections', 'report:read', 'decoy-summary'),
  need('GET', '/api/reports/export', 'report:export', 'decoy-file'),
  need('POST', '/api/reports/export/pii', ['report:export', 'pii:export'], 'deny403'),
  only('GET', '/api/security/my-info', 'decoy-self'),
  only('PUT', '/api/security/change-password', 'deny403'),
  only('GET', '/api/security/bindings', 'decoy-self'),
  only('POST', '/api/security/reauth', 'deny403'),
  vsens('POST', '/api/security/view-sensitive', 'deny403'),
  need('GET', '/api/security/stats', 'security:stats', 'decoy-summary'),
  only('GET', '/api/security/report-targets', 'decoy-self'),
  only('POST', '/api/security/report', 'deny403'),
  only('GET', '/api/security/my-logs', 'decoy-self'),
  need('PUT', '/api/security/users/:userId/lock', 'user:lock', 'deny403'),
  need('PUT', '/api/security/users/:userId/mfa/reset', 'user:reset_password', 'deny403'),
  need('PUT', '/api/security/users/:userId/password/reset', 'user:reset_password', 'deny403'),
  need('GET', '/api/security/overview', 'security:audit', 'decoy-summary'),
  need('GET', '/api/security/alerts', 'security:audit', 'reauth401'),
  need('GET', '/api/security/audit-logs/verify', 'security:audit', 'reauth401'),
  need('GET', '/api/security/audit-logs/export', 'security:audit', 'reauth401'),
  need('GET', '/api/security/audit-logs', 'security:audit', 'reauth401'),
  need('GET', '/api/security/audit-logs/:id', 'security:audit', 'reauth401'),
  need('GET', '/api/security/stuffing-profile', 'security:audit', 'reauth401'), // 撞库画像读口（ADR-013 P2 情报）：真实链过权限闸后仍要票，陷阱回同一句 401——旧口径「与真实 403 逐字相同」在呈现身份持有 security:audit 之后不再成立
  need('GET', '/api/security/attack-profile', 'security:audit', 'reauth401'), // 单 IP 攻击行为画像：与撞库画像同权限面/同缺票闸
  need('GET', '/api/security/attack-events', 'security:audit', 'reauth401'),
  need('GET', '/api/security/attack-events/summary', 'security:audit', 'reauth401'),
  need('GET', '/api/security/config/allowPublicRegistration', 'security:config', 'decoy-summary'),
  need('PUT', '/api/security/config/allowPublicRegistration', 'security:config', 'deny403'),
  need('GET', '/api/security/config/loginCaptchaEnabled', 'security:config', 'decoy-summary'),
  need('PUT', '/api/security/config/loginCaptchaEnabled', 'security:config', 'deny403'),
  need('GET', '/api/security/config/registerCaptchaEnabled', 'security:config', 'decoy-summary'),
  need('PUT', '/api/security/config/registerCaptchaEnabled', 'security:config', 'deny403'),
  need('GET', '/api/security/upgrade', 'security:config', 'decoy-summary'),
  need('GET', '/api/security/upgrade/jobs/:jobId', 'security:config', 'decoy-summary'),
  need('POST', '/api/security/upgrade/requests', 'security:config', 'deny403'),
  need('GET', '/api/security/ip-list', 'security:config', 'decoy-summary'),
  need('GET', '/api/security/ip-list/query', 'security:config', 'decoy-summary'),
  need('POST', '/api/security/ip-list', 'security:config', 'deny403'),
  need('DELETE', '/api/security/ip-list/:id', 'security:config', 'deny403'),
  pub('GET', '/health', 'public'),
  pub('GET', '/readyz', 'public'),
  pub('GET', '/metrics', 'public'),
  need('GET', '/api/metrics', 'security:audit', 'decoy-metrics'),
  pub('GET', '/api', 'public'),
  pub('GET', '/api-docs.json', 'public'),
]);

/** 路径切段：与 Express 默认口径对齐——大小写不敏感、容忍**一个**尾斜杠（`//` 仍是空段） */
const segmentsOf = (path) => {
  const bare = String(path || '/')
    .split('?')[0]
    .toLowerCase();
  const trimmed = bare.length > 1 && bare.endsWith('/') ? bare.slice(0, -1) : bare;
  return trimmed.split('/');
};

const sameShape = (declared, actual) =>
  declared.length === actual.length &&
  declared.every((seg, i) => (seg.startsWith(':') ? actual[i].length > 0 : seg === actual[i]));

/**
 * 命中已声明路由则返回该行，否则 null。 HEAD 回退到 GET：Express 的 HEAD 由 GET 处理器应答，路由表里没有独立的 HEAD 声明。
 */
const matchRoute = ({ method, path } = {}) => {
  const upper = String(method || 'GET').toUpperCase();
  const candidates = upper === 'HEAD' ? ['HEAD', 'GET'] : [upper];
  const actual = segmentsOf(path);
  for (const candidate of candidates) {
    const found = ROUTE_TABLE.find(
      (item) => item.method === candidate && sameShape(segmentsOf(item.path), actual)
    );
    if (found) return found;
  }
  return null;
};

module.exports = {
  AUTHENTICATE,
  AUTHENTICATE_LOGOUT,
  ROUTE_TABLE,
  TRAP_HANDLING,
  matchRoute,
  segmentsOf,
};
