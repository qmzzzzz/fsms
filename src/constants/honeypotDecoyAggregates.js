'use strict'; // 批次 B：AGGREGATE 十条路由的合成聚合应答（纯函数，零 require model/service/mongoose）

const aggData = require('./honeypotDecoyAggregatesData'); // 端点表 + NON_DERIVABLE 登记 + 临时授权合成行
const decoy = require('./honeypotDecoyData');
const alerts = require('./deviceAlerts'); // 设备档位判据（排除集/日历日窗口）唯一来源
const grantRules = require('./privilegeGrant'); // 授权字段表/审批策略/状态枚举唯一来源
const helpers = require('../utils/helpers'); // 分页与日期窗口判据唯一来源
const { normalizeProbePath } = require('./probePaths');
const { businessMonthStart } = require('./timezone');
const { USER_STATUS } = require('../utils/constants');
const { MIN, byKey, epochOf, isoOfOffset, tally } = require('./honeypotDecoyShape'); // 合成行的取值与分桶共用件（体积原因拆出的纯函数叶子）
const { rowClockNow } = require('./honeypotDecoy'); // 行时钟（量化到秒）唯一来源：同一秒内逐字相同、跨秒只按整秒平移（毫秒级抖动才是可自动化识别的指纹）

const HOUR_MS = 60 * MIN;
const DAY_MS = 24 * HOUR_MS;
const OVERDUE_LIST_LIMIT = 100; // 与 services/accessReviewService.listOverdueGrants 默认 limit 同值
const REMINDER_RESULT_LIMIT = 200; // 与 services/deviceReminder.js resultLimit 默认值同值
const GRANT_STATUS = Object.freeze(
  Object.fromEntries(grantRules.PRIVILEGE_GRANT_STATUSES.map((s) => [s.toUpperCase(), s]))
);

const byRoleOf = (activeRows) => {
  const counts = new Map();
  const bump = (code) => counts.set(code, (counts.get(code) || 0) + 1);
  activeRows.forEach((row) => (row.roles || []).forEach((role) => bump(role && role.code))); // roles 元素是 populate 后的 {_id,name,code}（userService.js:56）
  const rows = decoy.DECOY_ROLES.filter((role) => counts.has(role.code)).map((role) => ({
    roleId: role._id,
    roleName: role.name,
    roleCode: role.code,
    count: counts.get(role.code),
  }));
  return rows.sort((a, b) => b.count - a.count); // 真实链 $lookup 带 status:'active'：未命中的角色整行丢弃
};

const userStatsPayload = ({ now }) => {
  const users = decoy.DECOY_USERS; // 键集与键序照抄 controllers/userController/read.js 的 mapUserStatsFacet
  const monthStart = businessMonthStart(new Date(now.getTime())).getTime();
  const active = users.filter((row) => row.status === USER_STATUS.ACTIVE);
  return {
    data: {
      total: users.length,
      active: active.length,
      inactive: users.filter((row) => row.status === USER_STATUS.INACTIVE).length,
      thisMonth: users.filter((row) => epochOf(row.createdAtOffsetMin, now) >= monthStart).length,
      byDepartment: tally(active, 'department'),
      byRole: byRoleOf(active),
    },
  };
};

const roleOptionOf = ({ _id, name, code, description }) => ({ _id, name, code, description });

const roleOptionsPayload = () => ({ data: decoy.DECOY_ROLES.map(roleOptionOf) }); // roleService.listAllRoles 投影

const treeNodeOf = (row) => {
  const node = { _id: row._id, id: row._id, name: row.name, code: row.code }; // 键集与键序取自 roleController.js:354-364
  node.type = row.type;
  node.module = row.module;
  node.path = row.path;
  node.method = row.method || '*';
  node.children = [];
  return node;
};

const moduleNodeOf = (module) => {
  const id = 'module-' + module;
  const name = aggData.MODULE_NAMES[module] || module;
  return { _id: id, id, name, module, children: [] };
};

const permissionTreePayload = () => {
  const nodes = decoy.DECOY_PERMISSION_ROWS.map(treeNodeOf); // 父子按权限码前缀还原（seeding.js:106-121 同判据）
  const byCode = new Map(nodes.map((node) => [node.code, node]));
  const moduleSet = new Set(nodes.map((node) => node.module));
  const modules = new Map([...moduleSet].map((module) => [module, moduleNodeOf(module)]));
  nodes.forEach((node) => {
    const root = node.code.endsWith(':*') ? null : byCode.get(node.code.split(':')[0] + ':*');
    (root || modules.get(node.module)).children.push(node);
  });
  return { data: [...modules.keys()].sort().map((module) => modules.get(module)) }; // $sort{module:1} ⇒ 字母序
};

const grantRowOf = (row, now) => {
  const policy = grantRules.approvalPolicyOf(row.permissionCodes); // 键集与键序取 GRANT_LIST_FIELDS（唯一投影）
  const isoAt = (item) => isoOfOffset(item.atOffsetMin, now);
  const approvalOf = (item) => ({ by: item.by, name: item.name, at: isoAt(item) });
  const source = { ...row, highRisk: policy.highRisk, requiredApprovals: policy.requiredApprovals };
  source.approvals = row.approvals.map(approvalOf);
  const out = {};
  grantRules.GRANT_LIST_FIELDS.forEach((field) => {
    const isDate = field.endsWith('At'); // 四个 *At 是日期列，其余原样透传（缺省字段给 null）
    const value = source[isDate ? field + decoy.OFFSET_SUFFIX : field];
    out[field] = isDate ? isoOfOffset(value, now) : value === undefined ? null : value;
  });
  return out;
};

const grantsPayload = ({ query, now }) => {
  const { page, limit } = helpers.normalizePagination(query.page, query.limit);
  const mine = (row) => !query.status || row.status === query.status;
  const owner = (row) => !query.userId || String(row.userId) === String(query.userId);
  const rows = aggData.DECOY_TEMP_GRANTS.filter((row) => mine(row) && owner(row));
  rows.sort((a, b) => a.createdAtOffsetMin - b.createdAtOffsetMin); // 真实链 sort{createdAt:-1}，此处按时间正序取页
  return {
    data: rows.slice((page - 1) * limit, page * limit).map((row) => grantRowOf(row, now)),
    pagination: {
      page,
      limit,
      total: rows.length,
      totalPages: Math.ceil(rows.length / limit) || 0,
    },
  };
};

const grantReviewPayload = ({ now, requestNow }) => {
  const all = aggData.DECOY_TEMP_GRANTS; // 键集与顺序照抄 accessReviewService.reviewSummary + 控制器 overdueGrants
  const at = now.getTime();
  const isLive = (row) =>
    row.status === GRANT_STATUS.ACTIVE && epochOf(row.expiresAtOffsetMin, now) > at;
  const staleBefore = at - grantRules.REVIEW_OVERDUE_DAYS * DAY_MS; // 90 天 > MAX_GRANT_HOURS=168h ⇒ overdue 恒 0
  const isOverdue = (row) => {
    const grantedAt = epochOf(row.grantedAtOffsetMin, now);
    if (!isLive(row) || grantedAt === null) return false;
    if (row.reviewedAtOffsetMin !== undefined) return false;
    return grantedAt <= staleBefore;
  };
  const live = all.filter(isLive);
  const overdue = all.filter(isOverdue);
  overdue.sort((a, b) => a.grantedAtOffsetMin - b.grantedAtOffsetMin); // 真实链 sort{grantedAt:1}
  const isHighRisk = (row) => grantRules.approvalPolicyOf(row.permissionCodes).highRisk;
  const isSoon = (row) =>
    epochOf(row.expiresAtOffsetMin, now) <= at + grantRules.EXPIRING_SOON_HOURS * HOUR_MS;
  return {
    data: {
      asOf: requestNow.toISOString(), // 请求时刻，不可预置（见 NON_DERIVABLE）
      overdueDays: grantRules.REVIEW_OVERDUE_DAYS,
      active: live.length,
      expiringSoon: live.filter(isSoon).length,
      highRiskActive: live.filter(isHighRisk).length,
      overdue: overdue.length,
      pending: all.filter((row) => row.status === GRANT_STATUS.PENDING).length,
      overdueGrants: overdue.slice(0, OVERDUE_LIST_LIMIT).map((row) => grantRowOf(row, now)),
    },
  };
};

const deviceFactsOf = (row, now) => ({
  ...row, // 合成行的键名已与真实投影同形（deviceCode/deviceName/location），只补物化日期
  installDate: isoOfOffset(row.installDateOffsetMin, now),
  expiryDate: isoOfOffset(row.expiryDateOffsetMin, now),
  nextCheckDate: isoOfOffset(row.nextCheckDateOffsetMin, now),
});

const alertBucketsOf = (now, days) => {
  const at = now.getTime(); // 判据与 constants/deviceAlerts.deviceAlertFilters 逐条对齐
  const windowEnd = alerts.addCalendarDays(now, days).getTime();
  const rows = decoy.DECOY_DEVICES.map((row) => deviceFactsOf(row, now));
  const expiry = (row) => (row.expiryDate === null ? null : helpers.toEpochMs(row.expiryDate));
  const nextCheck = (row) =>
    row.nextCheckDate === null ? null : helpers.toEpochMs(row.nextCheckDate);
  const inExpiry = (row) => !alerts.ALERT_EXCLUDED_STATUS.includes(row.status);
  const inSchedule = (row) => !alerts.MAINTENANCE_EXCLUDED_STATUS.includes(row.status);
  const soon = (row) => inExpiry(row) && expiry(row) >= at && expiry(row) <= windowEnd;
  const overdue = (row) => inSchedule(row) && nextCheck(row) !== null && nextCheck(row) <= at;
  return {
    all: rows,
    expired: rows.filter((row) => inExpiry(row) && expiry(row) !== null && expiry(row) < at),
    expiringSoon: rows.filter(soon),
    needMaintenance: rows.filter(overdue),
    needSchedule: rows.filter((row) => inSchedule(row) && nextCheck(row) === null),
    expiryUnknown: rows.filter((row) => inExpiry(row) && expiry(row) === null),
  };
};

const pick = (row, fields) =>
  fields.reduce((out, field) => ({ ...out, [field]: row[field] }), { _id: row._id });

const expiringMessage = (total, returned) =>
  // 与 controllers/deviceController.getExpiringDevices 逐字一致
  total > returned
    ? `获取即将到期设备成功（共 ${total} 台，仅返回最先到期的 ${alerts.EXPIRING_LIST_LIMIT} 台，请缩小 days 窗口分批查看）`
    : aggData.EXPIRING_MESSAGE;

const deviceStatsPayload = ({ now }) => {
  const buckets = alertBucketsOf(now, alerts.DEFAULT_EXPIRING_DAYS); // 键序 = deviceStatsService 的 stats 字面量顺序
  return {
    data: {
      total: buckets.all.length,
      byType: tally(buckets.all, 'deviceType'),
      byStatus: tally(buckets.all, 'status'),
      needMaintenance: buckets.needMaintenance.length,
      needSchedule: buckets.needSchedule.length,
      expiringSoon: buckets.expiringSoon.length,
      expired: buckets.expired.length,
      expiryUnknown: buckets.expiryUnknown.length,
    },
  };
};

const expiringPayload = ({ now, query }) => {
  const days = alerts.normalizeExpiringDays(query.days);
  const matched = alertBucketsOf(now, days).expiringSoon;
  matched.sort(byKey('expiryDate')); // 真实链 sort{expiryDate:1}
  const fields = aggData.DEVICE_EXPIRY_FIELDS;
  const data = matched.slice(0, alerts.EXPIRING_LIST_LIMIT).map((row) => pick(row, fields));
  const total = matched.length;
  const pagination = { page: null, limit: alerts.EXPIRING_LIST_LIMIT, total, totalPages: null };
  pagination.hasMore = total > data.length;
  return { data, message: expiringMessage(total, data.length), pagination };
};

const remindersPayload = ({ now, requestNow, query }) => {
  const days = alerts.normalizeExpiringDays(query.days);
  const buckets = alertBucketsOf(now, days);
  const lists = {};
  const truncated = {};
  aggData.REMINDER_BUCKETS.forEach((item) => {
    const sorted = buckets[item.key].slice().sort(byKey(item.sort)); // 真实链 sort{[sortKey]:1,_id:1}
    truncated[item.key] = sorted.length > REMINDER_RESULT_LIMIT;
    lists[item.key] = sorted.slice(0, REMINDER_RESULT_LIMIT).map((row) => pick(row, item.fields));
  });
  truncated.total = aggData.REMINDER_BUCKETS.some((item) => truncated[item.key]);
  const counts = aggData.REMINDER_BUCKETS.map((item) => [item.key, buckets[item.key].length]);
  const ids = aggData.REMINDER_BUCKETS.flatMap((item) => buckets[item.key]).map((row) => row._id);
  return {
    data: {
      scannedAt: requestNow.toISOString(), // 请求时刻，不可预置（见 NON_DERIVABLE）
      expiringDays: days,
      summary: { ...Object.fromEntries(counts), total: new Set(ids).size },
      ...lists,
      limits: { resultLimit: REMINDER_RESULT_LIMIT, truncated },
    },
  };
};

const dateWindowOf = (query) => {
  // 拒绝形状与真实控制器逐字同码同序（先格式后区间）：回落 404「资源不存在」时，一次带坏参数的请求就能自证这是合成端点
  if (!helpers.isValidDateParam(query.startDate) || !helpers.isValidDateParam(query.endDate))
    return { kind: 'codeError', code: 'DATE_PARAM_INVALID' };
  if (helpers.isDateRangeReversed(query.startDate, query.endDate))
    return { kind: 'codeError', code: 'DATE_RANGE_INVALID' };
  const edge = (at, side) => (at ? helpers.parseDateBoundary(at, side).getTime() : null);
  return { from: edge(query.startDate, 'start'), to: edge(query.endDate, 'end') };
};

const withinWindow = (epoch, window) =>
  (window.from === null || epoch >= window.from) && (window.to === null || epoch <= window.to);

const windowRowsOf = (rows, offsetKey, now, window) =>
  rows.filter((row) => withinWindow(epochOf(row[offsetKey], now), window)); // 时间列名按真实投影（occurredAtOffsetMin/planStartTimeOffsetMin 经 materializeRow 折成真名）

const alarmStatsPayload = ({ now, query }) => {
  const window = dateWindowOf(query);
  if (window.kind) return window;
  const rows = windowRowsOf(decoy.DECOY_ALARMS, 'occurredAtOffsetMin', now, window);
  return {
    data: {
      total: rows.length,
      byStatus: tally(rows, 'status'),
      byLevel: tally(rows, 'level'),
      byType: tally(rows, 'alarmType'),
    },
  };
};

const inspectionStatsPayload = ({ now, query }) => {
  const window = dateWindowOf(query);
  if (window.kind) return window;
  const rows = windowRowsOf(decoy.DECOY_INSPECTIONS, 'planStartTimeOffsetMin', now, window);
  const done = rows.filter((row) => row.status === 'completed'); // byResult 只对已完成的行分组
  return {
    data: {
      total: rows.length,
      byStatus: tally(rows, 'status'),
      byType: tally(rows, 'inspectionType'),
      byResult: tally(done, 'result'),
    },
  };
};

const AGGREGATE_BUILDERS = Object.freeze([
  userStatsPayload, // 与 aggData.AGGREGATE_ENDPOINTS 同序（下标对应）；用例逐条调用可钉住串位
  roleOptionsPayload,
  permissionTreePayload,
  grantsPayload,
  grantReviewPayload,
  deviceStatsPayload,
  expiringPayload,
  remindersPayload,
  alarmStatsPayload,
  inspectionStatsPayload,
]);

const resolveAggregatePayload = (input) => {
  const source = input || {};
  if (!['GET', 'HEAD'].includes(String(source.method || 'GET').toUpperCase())) return null; // 其余方法是 deny403
  const endpoints = aggData.AGGREGATE_ENDPOINTS;
  const index = endpoints.findIndex((item) => item.path === normalizeProbePath(source.path));
  if (index < 0) return null;
  const query = source.query && typeof source.query === 'object' ? source.query : {};
  const built = AGGREGATE_BUILDERS[index]({ now: rowClockNow(), requestNow: new Date(), query }); // now 是行时钟（量化到秒：一次应答一个基准）；requestNow 才是请求时刻，只喂 asOf/scannedAt（见 NON_DERIVABLE）
  if (!built) return null;
  if (built.kind === 'codeError') return built; // 拒绝路径原样上交：由 honeypotDecoy.sendAggregate 统一走 ApiResponse.codeError
  const endpoint = endpoints[index];
  return {
    endpoint: endpoint.id,
    envelope: endpoint.envelope,
    message: built.message || endpoint.message,
    data: built.data,
    ...(built.pagination ? { pagination: built.pagination } : {}),
  };
};

module.exports = {
  AGGREGATE_ENDPOINTS: aggData.AGGREGATE_ENDPOINTS,
  NON_DERIVABLE: aggData.NON_DERIVABLE,
  expiringMessage,
  resolveAggregatePayload,
};
