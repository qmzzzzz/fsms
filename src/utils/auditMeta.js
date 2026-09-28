/**
 * 审计元数据派生：从 HTTP 方法与请求路径推导语义化的 category / action
 *
 * 背景（关键约束）：Express 在 `app.use('/api/', mw)` 与 `router` 两级挂载下会逐层剥离
 * `req.path` 的前缀——中间件里读到的是 `/users/:id`，`res.json` 时刻更被剥成 `/:id`。
 * 因此派生与路径排除都必须基于 `req.originalUrl`（去掉查询串），
 * 否则所有请求都匹配不到 `/api/xxx` 前缀而退化为 category=system、action=system_xxx。
 */

const { matchesPathPrefix } = require('./helpers');
const { AUDIT_LOG_ACTIONS } = require('../constants/audit');

// 路由前缀 → 语义 category 映射
// 取值全集必须与 models/AuditLog.js 的 category enum 一致，否则记录会被静默丢弃
const ROUTE_CATEGORY_MAP = {
  '/api/devices': 'device',
  '/api/alarms': 'alarm',
  '/api/inspections': 'inspection',
  '/api/users': 'user',
  '/api/roles': 'role',
  '/api/permissions': 'permission',
  '/api/security': 'security',
  '/api/auth': 'auth',
  '/api/reports': 'report',
};

/**
 * 取用于审计的规范请求路径：优先 originalUrl（未被挂载前缀剥离），并去掉查询串
 * @param {object} req Express 请求对象
 * @returns {string} 形如 /api/users/6a58.../roles
 */
const auditPath = (req) => {
  const raw = req.originalUrl || req.url || req.path || '';
  // 截断上限：path 会原样落进被索引的 AuditLog.path，超长可致索引键超限、记录被丢弃。
  return String(raw).split('?')[0].slice(0, 512);
};

/**
 * 路由与审计必须同尺。
 *
 * Express 默认 `case sensitive routing = false`（本仓未开启），因此
 * GET /API/users 与 GET /API/reports/export 会真实命中 /api/users、
 * /api/reports/export 的处理器。而审计侧此前用**大小写敏感**的字符串前缀比较
 * 决定是否记账、归入哪个 category —— 实测同一请求：
 *   路由命中（200/401 照常返回数据），审计白名单不命中（零记录），category 退化为 system。
 * 对一个以"操作留痕"为卖点的合规系统，这等价于给所有敏感读取和批量导出
 * 留了一条免审计的通路：把 URL 里任意一段改成大写即可。
 *
 * 判据本身在 utils/helpers.matchesPathPrefix（协议合规的 skipPaths、静态托管的
 * RESERVED_PREFIXES 用同一份实现，避免四处各写一遍再各自漂移）。
 * 注意：**落库的 path 字段仍存原始值**，归一只用于判定与派生，
 * 客户端实际发送的 URL 本身是证据（大写路径这个动作就值得被看见）。
 */

/**
 * 由完整路径派生 category
 * @param {string} path 完整请求路径（须含 /api 前缀）
 * @returns {string} category，未匹配任何前缀时返回 system
 */
const deriveCategory = (path) => {
  for (const [prefix, cat] of Object.entries(ROUTE_CATEGORY_MAP)) {
    if (matchesPathPrefix(path, prefix)) return cat;
  }
  return 'system';
};

/**
 * 动态标识段的形状集合（这些段不得混入 action）
 *
 * 为什么必须包含 UUID：会话管理接口的路径参数是 sid（randomUUID），
 * 若不剔除，DELETE /api/auth/sessions/<uuid> 会派生出
 * `auth_sessions_550e8400-e29b-...` —— action 取值随请求无限膨胀，
 * 既撑爆 {action:1} 索引的基数，也让审计页的 action 枚举校验永远拦不住。
 * 24 位十六进制（ObjectId）与纯数字同理。
 */
const DYNAMIC_SEGMENT_PATTERNS = [
  /^[0-9a-f]{24}$/i, // ObjectId
  /^\d+$/, // 自增/数字 ID
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID（sid）
];

/** 判断路径段是否为动态标识（应从 action 派生中剔除） */
const isDynamicSegment = (segment) => DYNAMIC_SEGMENT_PATTERNS.some((re) => re.test(segment));

/**
 * 合法动作后缀段的形状：短、可打印标识符（含 - 与 _）。
 * 现有合法后缀（create/update/roles/dispatch/report/status/false-alarm/ip-list/
 * loginCaptchaEnabled 等）全部命中；攻击者可控的超长/畸形段被丢弃。
 */
const ACTION_SEGMENT_RE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * action 的大小写折叠：以白名单为唯一"承认大小写"的地方
 *
 * 变体路径（/API/Reports/EXPORT）若原样派生，会得到 report_EXPORT 与 report_export
 * 两个 action 值——按 action 过滤的审计查询漏检，且 {action:1} 索引基数翻倍。
 * 但一律小写也不对：路由里存在合法的 camelCase 段（如
 * PUT /api/security/config/loginCaptchaEnabled → security_config_loginCaptchaEnabled），
 * 这些形态已在 AUDIT_LOG_ACTIONS 登记，折叠后反而与白名单失配
 * （constants/auditActionReachability 门禁会立刻报警）。
 *
 * 规则因此是：**登记过的形态原样保留，未登记的形态一律折叠为小写**。
 * 客户端改大小写只能得到一个未登记的变体，而被折叠回登记值。
 */
const REGISTERED_ACTIONS = new Set(AUDIT_LOG_ACTIONS);
const foldRegisteredAction = (action) =>
  REGISTERED_ACTIONS.has(action) ? action : action.toLowerCase();

/**
 * 由 method + 完整路径派生语义 action
 * 规则：剔除动态标识段（ObjectId / 数字 / UUID）后，取资源段之后的子路径作为动作后缀；
 * 无子路径时按方法映射为 view / create / update / delete，
 * 未识别的方法兜底为 `${category}_${method 小写}`
 * 例：POST /api/alarms/report → alarm_report；PUT /api/users/:id/roles → user_roles；
 *     GET /api/users → user_view（敏感读取审计，此前被误标为 user_update）；
 *     DELETE /api/auth/sessions/:sid → auth_sessions（sid 为 UUID，已剔除）
 * @param {string} method HTTP 方法
 * @param {string} path 完整请求路径
 * @param {string} category 已派生的 category
 * @returns {string} action
 */
const deriveAction = (method, path, category) => {
  const segments = path.split('/').filter(Boolean);
  // 剔除动态标识段（ObjectId/数字/UUID），并丢弃非「短可打印标识」段——否则
  // GET /api/devices/<5000 个 a> 会把整段拼进 action，撑爆 {action:1} 索引键
  // （>1024B 插入失败 → 审计记录被抑制 + 索引基数膨胀）。
  const cleanSegments = segments.filter((s) => !isDynamicSegment(s) && ACTION_SEGMENT_RE.test(s));
  // cleanSegments[0] = 'api'，[1] = 资源段（users/alarms/...），其后为子动作
  const subAction = cleanSegments.slice(2).join('_').slice(0, 64);

  if (subAction) return foldRegisteredAction(`${category}_${subAction}`.slice(0, 96));
  // HEAD 与 GET 同一语义：Express 把 HEAD 归一成 GET（Route.dispatch），所以 HEAD
  // 跑的就是那条读取逻辑。审计闸门已把 HEAD 纳入敏感读取（middleware/security.js
  // 的 isGetAudit），此处若继续走末尾兜底会得到 `user_head` —— 一个不在
  // AUDIT_LOG_ACTIONS 里的 action，审计页既筛不到也统计不到，等于留了一条"看得见
  // 却查不了"的记录。方法维度不丢：AuditLog.method 原样存 HEAD。
  if (method === 'GET' || method === 'HEAD') return `${category}_view`;
  if (method === 'POST') return `${category}_create`;
  if (method === 'DELETE') return `${category}_delete`;
  if (method === 'PUT' || method === 'PATCH') return `${category}_update`;
  return `${category}_${String(method)
    .toLowerCase()
    .replace(/[^a-z]/g, '')
    .slice(0, 16)}`;
};

/**
 * 一次性派生审计元数据
 * @param {object} req Express 请求对象
 * @returns {{path: string, category: string, action: string}}
 */
const deriveAuditMeta = (req) => {
  const path = auditPath(req);
  const category = deriveCategory(path);
  return { path, category, action: deriveAction(req.method, path, category) };
};

module.exports = {
  ROUTE_CATEGORY_MAP,
  DYNAMIC_SEGMENT_PATTERNS,
  isDynamicSegment,
  auditPath,
  deriveCategory,
  deriveAction,
  deriveAuditMeta,
};
