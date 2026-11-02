'use strict';

/**
 * 蜜罐影子数据面的**判定逻辑**（P1）
 *
 * 合成数据表本身搬到了 constants/honeypotDecoyData.js（纯数据，体积原因；本仓 max-lines 300 是只降不升的棘轮基线，加两条诱饵记录不该变成「必须改基线」）。本文件只留判定：
 * 给定 (method, path) 决定这个请求在陷阱会话里应该「回合成数据 / 放行 / 拒绝」，以及把合成表按 id / 集合取成响应载荷。
 *
 * 接线台账与前提自证见 src/tests/ci/honeypotDecoyLedger.test.js：
 * app.js 每个挂载前缀必须要么有合成数据面、要么在例外清单里写明理由。
 */

const {
  DECOY_ALARMS,
  DECOY_DEVICES,
  DECOY_INSPECTIONS,
  DECOY_ORG,
  DECOY_PERMISSION_ROWS,
  DECOY_PERMISSIONS,
  DECOY_ROLE_CODES,
  DECOY_ROLES,
  DECOY_SELF,
  DECOY_USERS,
  HONEYPOT_DECOY_ID_PREFIX,
  OFFSET_SUFFIX,
} = require('./honeypotDecoyData');
// 写操作名单从单一事实来源取（不在此再抄一份）：蜜罐的「写请求一律 DENY」必须与 CSRF 来源闸、全局审计、行为基线用的是同一张表——抄一份就可能出现「CSRF 拦了但蜜罐放行」的口径分叉。middleware/httpMethods.js 是零 require 叶子，无环风险。
const { WRITE_METHODS } = require('../middleware/httpMethods');
const { DECOY_SELF_EMAIL_DOMAIN } = require('./honeypotDecoySelf');
const { matchRoute, segmentsOf, TRAP_HANDLING } = require('./honeypotRouteTable'); // 判定层必须知道这条路径是不是 app.js 里真有的路由：零 require 叶子，与体积/判据门禁共用同一份声明
const { isReauthGated, reauthPayload } = require('./honeypotTicketGate'); // 缺票闸的声明与拒绝体单一来源：本文件被 errorCodePlaceholderDefault 的码槽现采点名（parts:['code']），字面量放这里会破闭，改由该叶给出调用（马甲的两个面共用同一份冻结体）
const { ALARM_OPEN_STATUSES } = require('./honeypotDecoyListShape'); // 列表端点形状单一来源：S1 的「未终结档」从这里派生，别处不再抄一份枚举
const { listPageOf, listQueryRejection } = require('./honeypotDecoyListQuery'); // 列表查询面（校验/过滤/分页）：非法查询必须回真实路由同一个 400 体，合法查询必须回真实控制器的分页信封

const countByStatus = (rows, status) => rows.filter((row) => row.status === status).length;

const DECOY_SUMMARY = Object.freeze({
  org: DECOY_ORG,
  users: DECOY_USERS.length,
  activeUsers: countByStatus(DECOY_USERS, 'active'),
  roles: DECOY_ROLES.length,
  devices: DECOY_DEVICES.length,
  faultDevices: countByStatus(DECOY_DEVICES, 'fault'),
  alarms: DECOY_ALARMS.length,
  openAlarms: DECOY_ALARMS.filter((row) => ALARM_OPEN_STATUSES.includes(row.status)).length, // 口径是「状态属于未终结档」（AlarmService.js:381 的 pending/processing 集合），不是「总数 − 某一档」：终态不止一种，减法会把误报/已取消也算成未处理
  inspections: DECOY_INSPECTIONS.length,
});

const HONEYPOT_VERDICT = Object.freeze({
  DECOY: 'decoy',
  PASSTHROUGH: 'passthrough',
  DENY: 'deny',
  NOT_FOUND: 'not-found',
});
const PASSTHROUGH_ROUTES = Object.freeze([
  Object.freeze({ method: 'POST', path: '/api/auth/refresh' }),
  Object.freeze({ method: 'POST', path: '/api/auth/logout' }),
  Object.freeze({ method: 'GET', path: '/api/version' }),
]);
const DECOY_COLLECTIONS = Object.freeze([
  Object.freeze({ prefix: '/api/users', key: 'users' }),
  Object.freeze({ prefix: '/api/roles', key: 'roles' }),
  Object.freeze({ prefix: '/api/permissions', key: 'permissions' }),
  Object.freeze({ prefix: '/api/devices', key: 'devices' }),
  Object.freeze({ prefix: '/api/alarms', key: 'alarms' }),
  Object.freeze({ prefix: '/api/inspections', key: 'inspections' }),
  Object.freeze({ prefix: '/api/reports', key: 'reports' }),
  Object.freeze({ prefix: '/api/security', key: 'security' }),
]);
const DECOY_TABLES = Object.freeze({
  users: DECOY_USERS,
  roles: DECOY_ROLES,
  permissions: DECOY_PERMISSION_ROWS,
  devices: DECOY_DEVICES,
  alarms: DECOY_ALARMS,
  inspections: DECOY_INSPECTIONS,
});

const DECOY_NOT_FOUND = Object.freeze({
  // 明细未命中**逐集合对齐**真实控制器，不再统一回「资源不存在」：统一文案会把「集合里没有这条记录」与「集合不该有明细」抹平，是可指纹差异
  users: Object.freeze({
    kind: 'codeError',
    code: 'USER_NOT_FOUND', // 该码在注册表里默认 401（登录态用），读侧真实路径一律显式覆盖成 404
    options: Object.freeze({ statusCode: 404 }),
  }),
  roles: Object.freeze({ kind: 'codeError', code: 'ROLE_NOT_FOUND' }),
  permissions: Object.freeze({ kind: 'codeError', code: 'PERMISSION_NOT_FOUND' }),
  devices: Object.freeze({ kind: 'codeError', code: 'DEVICE_NOT_FOUND' }),
  alarms: Object.freeze({ kind: 'codeError', code: 'ALARM_NOT_FOUND' }),
  inspections: Object.freeze({ kind: 'codeError', code: 'INSPECTION_NOT_FOUND' }),
});

const collectionFor = (path) =>
  DECOY_COLLECTIONS.find((item) => path === item.prefix || path.startsWith(item.prefix + '/')) ||
  null;
const isPassthrough = (method, path) =>
  PASSTHROUGH_ROUTES.some((route) => route.method === method && route.path === path);

const resolveDecoyVerdict = ({ method, path } = {}) => {
  // 判决三态必须分开：混一起就会写出「口径对、HTTP 不可达」的死代码（判序与「不可达」清单见 ADR-013 P2-2）
  const upperMethod = String(method || 'GET').toUpperCase();
  const target = String(path || '');
  if (isPassthrough(upperMethod, target)) return HONEYPOT_VERDICT.PASSTHROUGH;
  const route = matchRoute({ method: upperMethod, path: target });
  if (!route) return HONEYPOT_VERDICT.NOT_FOUND;
  if (!route.auth || route.handling === TRAP_HANDLING.PASSTHROUGH)
    return HONEYPOT_VERDICT.PASSTHROUGH;
  if (WRITE_METHODS.includes(upperMethod) || route.handling === TRAP_HANDLING.DENY) {
    return HONEYPOT_VERDICT.DENY;
  }
  return HONEYPOT_VERDICT.DECOY;
};

const SECOND_MS = 1000;
const rowClockNow = (at) =>
  new Date(Math.floor((at === undefined ? Date.now() : Number(at)) / SECOND_MS) * SECOND_MS); // 行时钟量化到秒：行时间始终贴近此刻（秒级新鲜），且同一秒内的重复读取逐字相同——不量化会让两次抓取差出毫秒级抖动，那是一次 diff 就能自动化识别的指纹
// 只有有限数字才算「有值」：null/undefined/NaN/空串一律按缺失处理。Number(null)===0 会把「没有值」静默折成「此刻」，Number(undefined) 让 toISOString 抛 RangeError ⇒ 500。
const offsetMinutesOf = (value) =>
  typeof value === 'number' && Number.isFinite(value) ? value : null;
const materializeValue = (value, at) => {
  if (Array.isArray(value)) return value.map((item) => materializeValue(item, at));
  if (value && typeof value === 'object') return materializeRow(value, at);
  return value;
};
const materializeRow = (row, at) => {
  const base = rowClockNow(at).getTime(); // 一份响应一个基准：同一份载荷里的行时间不会跨秒开裂（调用方必须显式传基准——别用 `table.map(materializeRow)`，那会把下标当成基准）
  const out = {};
  for (const [key, value] of Object.entries(row)) {
    if (!key.endsWith(OFFSET_SUFFIX)) {
      out[key] = materializeValue(value, at);
      continue;
    }
    const offset = offsetMinutesOf(value);
    out[key.slice(0, -OFFSET_SUFFIX.length)] =
      offset === null ? null : new Date(base - offset * 60000).toISOString();
  }
  return out;
};

const selfRowOf = (user) =>
  user && user.userId
    ? {
        ...DECOY_SELF,
        _id: String(user.userId),
        username: typeof user.username === 'string' ? user.username : DECOY_SELF.username,
        realName:
          typeof user.realName === 'string' && user.realName ? user.realName : DECOY_SELF.realName,
      }
    : DECOY_SELF; // /api/users/me 是"本人"：有会话身份时按会话呈现（_id 用真实 userId），否则才回合成首行

const listRejectionPayload = (key, query) => {
  const rejection = listQueryRejection(key, query); // 非法查询的判定与真实链同序：路由校验链 → 控制器日期闸（形态先于区间反向）
  if (!rejection) return null;
  if (rejection.code === 'DATE_PARAM_INVALID')
    return { kind: 'codeError', code: 'DATE_PARAM_INVALID' };
  if (rejection.code === 'DATE_RANGE_INVALID')
    return { kind: 'codeError', code: 'DATE_RANGE_INVALID' };
  return {
    kind: 'codeError',
    code: 'VALIDATION_FAILED',
    options: { fieldErrors: [...rejection.fieldErrors] },
  }; // 与路由 consumeValidation 同一个 ApiResponse.codeError：码、文案、四键明细逐字相同
};

const listPayloadOf = (key, table, base, query) => {
  const rejected = listRejectionPayload(key, query);
  if (rejected) return rejected; // 拒绝路径不物化任何一行
  const page = listPageOf(
    key,
    table.map((row) => materializeRow(row, base)),
    query
  ); // 信封按真实控制器逐字给出：total 是**过滤后**条数、totalPages=ceil、越界页回空数组
  return {
    kind: 'list',
    data: page.data,
    message: page.message,
    pagination: page.pagination,
    total: page.total,
  };
};

const resolveDecoyPayload = ({ method = 'GET', path, user, query } = {}) => {
  // 按**路由声明**取，而不是按前缀 + 尾串猜：同一前缀下「聚合子路径」与「明细 id」长得一样（/api/users/stats vs /api/users/hp-u1），只按尾串判会把聚合路径当成查无此 id——真实链那里是 200
  const target = String(path || '');
  const route = matchRoute({ method, path: target }); // 取路径段走 segmentsOf：大小写、一个尾斜杠、查询串的口径与 Express 和路由表完全同源
  if (!route) return null;
  if (isReauthGated(route)) return reauthPayload(); // 缺票闸不是「这条集合没有该资源」，必须在集合面之前返回：判它的是真实链的第二道闸，与合成表无关
  const collection = collectionFor(route.path);
  if (!collection) return null;
  const base = rowClockNow(); // 一次应答只取一个基准：同一份响应里所有行共享它，行时间不会跨秒开裂
  if (route.handling === TRAP_HANDLING.SUMMARY) {
    return { kind: 'summary', data: materializeRow(DECOY_SUMMARY, base) };
  }
  if (route.handling !== TRAP_HANDLING.LIST && route.handling !== TRAP_HANDLING.DETAIL) return null;
  const table = DECOY_TABLES[collection.key];
  if (route.handling === TRAP_HANDLING.LIST) {
    return listPayloadOf(collection.key, table, base, query);
  }
  const wanted = segmentsOf(target).slice(segmentsOf(collection.prefix).length).join('/');
  if (wanted === 'me' && collection.key === 'users') {
    return { kind: 'detail', data: materializeRow(selfRowOf(user), base) };
  }
  const row = table.find((item) => String(item._id).toLowerCase() === wanted);
  return row
    ? { kind: 'detail', data: materializeRow(row, base) }
    : DECOY_NOT_FOUND[collection.key] || null;
};

const syntheticEmailOf = (username) =>
  typeof username === 'string' && username ? username + '@' + DECOY_SELF_EMAIL_DOMAIN : null; // 呈现层邮箱：库里那份 @honeypot.invalid 是给防守方看的，不能出现在任何对外载荷里

const presentedClaims = (user, roles) => {
  if (!user || user.isHoneypot !== true) return { email: user ? user.email : null, roles };
  return { email: syntheticEmailOf(user.username), roles: [...DECOY_ROLE_CODES] };
}; // 签署声明：载荷可被客户端解码，「零角色 + 不可路由域名」等于自报家门

module.exports = {
  DECOY_ALARMS,
  DECOY_COLLECTIONS,
  DECOY_DEVICES,
  DECOY_NOT_FOUND,
  DECOY_ORG,
  DECOY_PERMISSIONS,
  DECOY_ROLE_CODES,
  DECOY_SELF,
  DECOY_SUMMARY,
  DECOY_TABLES,
  DECOY_USERS,
  HONEYPOT_DECOY_ID_PREFIX,
  HONEYPOT_VERDICT,
  PASSTHROUGH_ROUTES,
  WRITE_METHODS,
  materializeRow,
  offsetMinutesOf,
  presentedClaims,
  resolveDecoyPayload,
  rowClockNow,
  resolveDecoyVerdict,
  syntheticEmailOf,
};
