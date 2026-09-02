/**
 * 审计元数据派生：从 HTTP 方法与请求路径推导语义化的 category / action
 *
 * 背景（关键约束）：Express 在 `app.use('/api/', mw)` 与 `router` 两级挂载下会逐层剥离
 * `req.path` 的前缀——中间件里读到的是 `/users/:id`，`res.json` 时刻更被剥成 `/:id`。
 * 因此派生与路径排除都必须基于 `req.originalUrl`（去掉查询串），
 * 否则所有请求都匹配不到 `/api/xxx` 前缀而退化为 category=system、action=system_xxx。
 */

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
  return String(raw).split('?')[0];
};

/**
 * 由完整路径派生 category
 * @param {string} path 完整请求路径（须含 /api 前缀）
 * @returns {string} category，未匹配任何前缀时返回 system
 */
const deriveCategory = (path) => {
  for (const [prefix, cat] of Object.entries(ROUTE_CATEGORY_MAP)) {
    if (path === prefix || path.startsWith(`${prefix}/`)) return cat;
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
  const cleanSegments = segments.filter((s) => !isDynamicSegment(s));
  // cleanSegments[0] = 'api'，[1] = 资源段（users/alarms/...），其后为子动作
  const subAction = cleanSegments.slice(2).join('_');

  if (subAction) return `${category}_${subAction}`;
  if (method === 'GET') return `${category}_view`;
  if (method === 'POST') return `${category}_create`;
  if (method === 'DELETE') return `${category}_delete`;
  if (method === 'PUT' || method === 'PATCH') return `${category}_update`;
  return `${category}_${String(method).toLowerCase()}`;
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
