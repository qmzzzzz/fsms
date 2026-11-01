'use strict'; // 批次 D：六个列表端点的校验/过滤/分页执行（纯函数；零 model/service/mongoose 依赖）

const helpers = require('../utils/helpers');
const { normalizeSearchTerm } = require('../utils/searchPatterns');
const shape = require('./honeypotDecoyListShape');

/*
 * ── 换名表（唯一）────────────────────────────────────────────────────────────
 * 真实字段名 → 合成行键名。数据面第三刀把键名换成真实投影时（alarms 的 code→alarmCode、
 * timeOffsetMin→occurredAtOffsetMin（物化后 occurredAt）、location 字符串→子文档；inspections 的
 * code→title、area→locations[]、inspector→assignedTo[]；devices 的 code→deviceCode、name→deviceName…，
 * 见 work/hp-list-endpoints.md §4），**只改这张表**：过滤/排序/日期窗/搜索都从这里取键名，
 * 别处（含测试）不再出现第二个键名常量。段末 '[]' 表示"在该键的数组元素上继续取"
 * （如 roles[].code ⇒ 每个角色的 code），location.building ⇒ 子文档取值。
 */
const LIST_FIELD_KEYS = Object.freeze({
  users: Object.freeze({
    createdAt: 'createdAt',
    department: 'department',
    realName: 'realName',
    role: 'roles[].code',
    status: 'status',
    updatedAt: 'updatedAt',
    username: 'username',
  }),
  roles: Object.freeze({
    code: 'code',
    createdAt: 'createdAt',
    level: 'level',
    name: 'name',
    status: 'status',
  }),
  permissions: Object.freeze({
    createdAt: 'createdAt',
    module: 'module',
    sort: 'sort',
    status: 'status',
    type: 'type',
  }),
  devices: Object.freeze({
    building: 'location.building',
    code: 'deviceCode',
    deviceCode: 'deviceCode',
    deviceType: 'deviceType',
    floor: 'location.floor',
    name: 'deviceName',
    status: 'status',
  }),
  alarms: Object.freeze({
    alarmType: 'alarmType',
    code: 'alarmCode',
    description: 'description',
    level: 'level',
    location: 'location.building', // 真实搜索打的是 location.building（AlarmService.js:75-79），不是整串 location
    status: 'status',
  }),
  inspections: Object.freeze({
    assignedTo: 'assignedTo[]._id', // 过滤参数是 ref id；装饰行值已是 populate 形状的子文档数组
    inspectionType: 'inspectionType',
    'locations.building': 'locations[].building', // 真实搜索打的是 locations.building（InspectionService.js:127-128）
    planStartTime: 'planStartTime',
    status: 'status',
    title: 'title',
  }),
});

const LIST_DATE_FIELDS = Object.freeze({ alarms: 'occurredAt', inspections: 'planStartTime' }); // 与 AlarmService.js:75-79 / InspectionService.js:107-111 的窗口字段同名

// validator 语义镜像（node_modules/validator 是这三条判据的唯一来源，同源性由同套件逐条抽取比对）
const INT_RE = /^[-+]?[0-9]+$/; // isInt.js:11 默认形态（allow_leading_zeroes !== false）
const HEX_RE = /^(0x|0h)?[0-9A-F]+$/i; // isHexadecimal（isMongoId = 本正则 && 长度 24）
const ISO_RE =
  /^([+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-3])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24:?00)([.,]\d+(?!:))?)?(\17[0-5]\d([.,]\d+)?)?([zZ]|([+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/; // isISO8601.js:11 非 strict 形态
const PRESENTATION_RE = /[^\uFE0F\uFE0E][\uFE0F\uFE0E]/g; // isLength.js:23
const SURROGATE_RE = /[\uD800-\uDBFF][\uDC00-\uDFFF]/g; // isLength.js:24

const asScalars = (value) => (Array.isArray(value) ? value : [value]);
const isFalsyValue = (value) =>
  value === undefined || value === null || value === '' || value === false || value === 0;
const lengthOf = (text) =>
  text.length -
  (text.match(PRESENTATION_RE) || []).length -
  (text.match(SURROGATE_RE) || []).length;

const passesRule = (rule, raw) => {
  const text = String(raw);
  if (rule.kind === 'in') return rule.values.map(String).indexOf(text) >= 0; // isIn：先 stringify 数组元素再 indexOf
  if (rule.kind === 'int') {
    if (!INT_RE.test(text)) return false;
    const num = Number(text);
    return (
      (rule.min === undefined || num >= rule.min) && (rule.max === undefined || num <= rule.max)
    );
  }
  if (rule.kind === 'length') return lengthOf(rule.trim ? text.trim() : text) <= rule.max; // 链上是 .trim() 之后再 isLength
  if (rule.kind === 'mongoId') return HEX_RE.test(text) && text.length === 24;
  if (rule.kind === 'iso8601') return ISO_RE.test(text); // 非 strict：不跑 isValidDate（'2026-04-31' 照样放行，与真实链一致）
  return true;
};

const fieldErrorsOf = (endpoint, query) => {
  const errors = [];
  for (const rule of endpoint.rules) {
    for (const raw of asScalars(query[rule.field])) {
      if (rule.optional === 'falsy' ? isFalsyValue(raw) : raw === undefined) continue; // 路由链的 optional 两种形态：按值跳过 vs 只跳 undefined
      if (passesRule(rule, raw)) continue;
      errors.push({ type: 'field', location: 'query', path: rule.field, msg: rule.msg }); // 形状同 safeFieldErrors（无 value 键）
    }
  }
  return errors;
};

const dateGateOf = (endpoint, query) => {
  if (!endpoint.dates) return null;
  const { startDate, endDate } = query;
  if (
    (startDate && !helpers.isValidDateParam(startDate)) ||
    (endDate && !helpers.isValidDateParam(endDate))
  )
    return 'DATE_PARAM_INVALID'; // 优先级同真实控制器：参数形态先于区间反向
  return helpers.isDateRangeReversed(startDate, endDate) ? 'DATE_RANGE_INVALID' : null;
};

/** 非法查询的拒绝描述符：{code, fieldErrors?}；合法则 null。判定顺序=真实链：路由校验 → 控制器日期闸。 */
const listQueryRejection = (key, query) => {
  const endpoint = shape.LIST_ENDPOINTS_BY_KEY[key];
  if (!endpoint) return null;
  const asked = query && typeof query === 'object' ? query : {};
  const fieldErrors = fieldErrorsOf(endpoint, asked);
  if (fieldErrors.length) return { code: 'VALIDATION_FAILED', fieldErrors };
  const gate = dateGateOf(endpoint, asked);
  return gate ? { code: gate } : null;
};

const valuesAt = (row, path) =>
  path.split('.').reduce(
    (acc, segment) => {
      const spread = segment.endsWith('[]');
      const name = spread ? segment.slice(0, -2) : segment;
      const picked = acc.flatMap((item) =>
        item === undefined || item === null ? [] : [item[name]]
      );
      return spread ? picked.flatMap((value) => (Array.isArray(value) ? value : [])) : picked;
    },
    [row]
  );

const fieldOf = (key, field) => {
  const table = LIST_FIELD_KEYS[key] || {};
  return table[field] || field; // _id 这类无需换名的字段按原名取
};

const matchesFilter = (key, row, field, raw) =>
  valuesAt(row, fieldOf(key, field)).some((value) => String(value) === String(raw)); // 数据面已是真实枚举/真实键：没有第二套值域要桥

const matchesSearch = (key, row, endpoint, term) => {
  const needle = term.toLowerCase();
  return endpoint.search.some(({ field, kind }) =>
    valuesAt(row, fieldOf(key, field)).some((value) => {
      if (value === undefined || value === null) return false;
      const text = String(value);
      if (kind === 'codePrefix') return text.startsWith(needle.toUpperCase()); // upperCodePrefixPattern：大写化后前缀、大小写敏感
      return kind === 'prefix'
        ? text.toLowerCase().startsWith(needle)
        : text.toLowerCase().includes(needle);
    })
  );
};

const compareValues = (left, right) => {
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  const a = left === undefined || left === null ? '' : String(left);
  const b = right === undefined || right === null ? '' : String(right);
  if (a === b) return 0;
  return a < b ? -1 : 1;
};

const sortRows = (key, endpoint, rows) =>
  [...rows].sort((left, right) => {
    for (const { field, dir } of endpoint.sort) {
      const cmp = compareValues(
        valuesAt(left, fieldOf(key, field))[0],
        valuesAt(right, fieldOf(key, field))[0]
      );
      if (cmp !== 0) return dir * cmp;
    }
    return 0;
  });

const isSkippable = (raw) =>
  raw === undefined ||
  raw === null ||
  raw === false ||
  raw === '' ||
  (typeof raw === 'string' && raw.trim() === ''); // 真实链的 if (x) 口径：空值/纯空白等于没筛（长度类字段链上还有 .trim()）

const withinRange = (value, range) => {
  if (range.$gte === undefined && range.$lte === undefined) return true;
  const at = helpers.toEpochMs(value);
  if (Number.isNaN(at)) return false;
  if (range.$gte !== undefined && at < range.$gte) return false;
  if (range.$lte !== undefined && at > range.$lte) return false;
  return true;
};

const matchesFilters = (key, row, endpoint, asked) =>
  endpoint.filters.every((field) => {
    const raw = asked[field];
    if (isSkippable(raw)) return true;
    return matchesFilter(key, row, field, typeof raw === 'string' ? raw.trim() : raw);
  });

const passesRow = (key, endpoint, row, asked, range, term) => {
  if (!matchesFilters(key, row, endpoint, asked)) return false;
  const dateField = LIST_DATE_FIELDS[key];
  if (dateField && !withinRange(valuesAt(row, fieldOf(key, dateField))[0], range)) return false;
  if (endpoint.search && term && !matchesSearch(key, row, endpoint, term)) return false;
  return true;
};

/** 分页信封：total=**过滤后**条数、totalPages=ceil(total/limit)、越界页回空数组（绝不回第一页）。 */
const listPageOf = (key, rows, query) => {
  const endpoint = shape.LIST_ENDPOINTS_BY_KEY[key];
  if (!endpoint) return null;
  const asked = query && typeof query === 'object' ? query : {};
  const range = {};
  if (asked.startDate) range.$gte = helpers.parseDateBoundary(asked.startDate, 'start'); // 与两个真实 service 同一对边界
  if (asked.endDate) range.$lte = helpers.parseDateBoundary(asked.endDate, 'end');
  const term = typeof asked.search === 'string' ? normalizeSearchTerm(asked.search) : '';
  const matched = rows.filter((row) => passesRow(key, endpoint, row, asked, range, term));
  const ordered = sortRows(key, endpoint, matched);
  const { page, limit } = helpers.normalizePagination(
    asked.page ?? 1,
    asked.limit ?? endpoint.defaultLimit,
    endpoint.maxLimit
  );
  const total = ordered.length;
  const pagination = { page, limit, total, totalPages: Math.ceil(total / limit) };
  if (endpoint.nextCursor) pagination.nextCursor = null; // 合成 id 是 hp-*（非 24 hex）：真铸游标会在第二次请求被 decodeCursor 拒成 400，比 null 更硬
  return {
    data: ordered.slice((page - 1) * limit, (page - 1) * limit + limit),
    message: endpoint.message,
    pagination,
    total,
  };
};

module.exports = {
  LIST_DATE_FIELDS,
  LIST_FIELD_KEYS,
  listPageOf,
  listQueryRejection,
};
