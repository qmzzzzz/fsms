'use strict';

/**
 * 批次 B 门禁：10 条聚合读端点的同形合成体（constants/honeypotDecoyAggregates.js）
 *
 * 三类证明：
 *  1. 同源：端点路径与 constants/honeypotRouteTable.js 的 AGGREGATE 行双向相等；键集/键序
 *     对真实控制器与服务逐 token 有序核对；文案对真实控制器逐字核对；
 *  2. 零真实读：文本证明（新模块的代码视图里只出现白名单 require，不见 models/mongoose/
 *     services）+ 结构证明（resetModules 后重新 require，require 图增量里没有 model/service）；
 *  3. 边界：未命中（非 GET/HEAD、未知路径、非法/倒置日期、越界页）与截断边界（50/200 条）。
 *
 * 期望值尽量**独立复算**而不是引用被验模块的中间量：设备五档直接拿
 * constants/deviceAlerts.deviceAlertFilters 的 Mongo 片段在内存里求值，
 * 授权复核的 overdue 用 REVIEW_OVERDUE_DAYS 与 MAX_GRANT_HOURS 的算术证。
 */
const fs = require('fs');
const path = require('path');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const { ROUTE_TABLE, TRAP_HANDLING } = require('../../constants/honeypotRouteTable');
const agg = require('../../constants/honeypotDecoyAggregates');
const aggData = require('../../constants/honeypotDecoyAggregatesData');
const decoy = require('../../constants/honeypotDecoyData');
const alerts = require('../../constants/deviceAlerts');
const grantRules = require('../../constants/privilegeGrant');
const { DEVICE_TYPE, USER_STATUS } = require('../../utils/constants');
const { INSPECTION_STATUSES } = require('../../constants/inspection');

const AGGREGATE_PAGINATION_KEYS = {
  'grant-list': ['page', 'limit', 'total', 'totalPages'],
  'device-expiring': ['page', 'limit', 'total', 'totalPages', 'hasMore'],
};
// 本文件在 src/tests/constants/ ⇒ 仓根是上溯三级（src/tests/constants → src/tests → src → 仓根）。
// 原先写成三级却把 rel 也带 'src/' 前缀，拼成 src/src/... ⇒ ENOENT。
const ROOT = path.join(__dirname, '..', '..', '..');
const codeOf = (rel) => jsCodeOnly(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const resolveOf = (id, query) => {
  const endpoint = agg.AGGREGATE_ENDPOINTS.find((item) => item.id === id);
  return agg.resolveAggregatePayload({ method: 'GET', path: endpoint.path, query: query || {} });
};
const orderedTokens = (text, tokens) => {
  let at = -1;
  return tokens.every((token) => {
    const hit = text.indexOf(token, at + 1);
    if (hit < 0) return false;
    at = hit;
    return true;
  });
};
const MINUTE_MS = 60 * 1000;
const materialize = (row) => ({
  expiryDate:
    row.expiryDateOffsetMin == null
      ? null
      : new Date(Date.now() - row.expiryDateOffsetMin * MINUTE_MS),
  nextCheckDate:
    row.nextCheckDateOffsetMin == null
      ? null
      : new Date(Date.now() - row.nextCheckDateOffsetMin * MINUTE_MS),
  installDate:
    row.installDateOffsetMin == null
      ? null
      : new Date(Date.now() - row.installDateOffsetMin * MINUTE_MS),
  status: row.status,
});
const matchesFilter = (filter, doc) =>
  Object.entries(filter).every(([field, cond]) => {
    if (cond === null) return doc[field] === null;
    if (cond.$nin) return !cond.$nin.includes(doc[field]);
    if (cond.$lt !== undefined) return doc[field] !== null && doc[field] < cond.$lt;
    if (cond.$gte !== undefined)
      return doc[field] !== null && doc[field] >= cond.$gte && doc[field] <= cond.$lte;
    if (cond.$lte !== undefined) return doc[field] !== null && doc[field] <= cond.$lte;
    return false;
  });

const PARITY = [
  {
    id: 'user-stats',
    file: 'src/controllers/userController/read.js',
    tokens: ['total', 'active', 'inactive', 'thisMonth', 'byDepartment', 'byRole'],
  },
  {
    id: 'role-options',
    file: 'src/services/roleService.js',
    tokens: ['name', 'code', 'description'],
  },
  {
    id: 'permission-tree',
    file: 'src/controllers/roleController.js',
    tokens: ['_id', 'id', 'name', 'code', 'type', 'module', 'path', 'method', 'children'],
  },
  {
    id: 'grant-list',
    file: 'src/services/privilegeGrantService.js',
    tokens: ['GRANT_LIST_FIELDS'],
  },
  {
    id: 'grant-review',
    file: 'src/services/accessReviewService.js',
    tokens: [
      'asOf',
      'overdueDays',
      'active',
      'expiringSoon',
      'highRiskActive',
      'overdue',
      'pending',
    ],
  },
  {
    id: 'device-stats',
    file: 'src/services/deviceStatsService.js',
    tokens: [
      'total',
      'byType',
      'byStatus',
      'needMaintenance',
      'needSchedule',
      'expiringSoon',
      'expired',
      'expiryUnknown',
    ],
  },
  {
    id: 'device-expiring',
    file: 'src/controllers/deviceController.js',
    tokens: ['deviceCode', 'expiryDate', 'EXPIRING_LIST_LIMIT'],
  },
  {
    id: 'device-reminders',
    file: 'src/services/deviceReminder.js',
    tokens: [
      'scannedAt',
      'expiringDays',
      'summary',
      'expired',
      'expiringSoon',
      'needMaintenance',
      'needSchedule',
    ],
  },
  {
    id: 'alarm-stats',
    file: 'src/services/AlarmService.js',
    tokens: ['total', 'byStatus', 'byLevel', 'byType'],
  },
  {
    id: 'inspection-stats',
    file: 'src/services/InspectionService.js',
    tokens: ['total', 'byStatus', 'byType', 'byResult'],
  },
];

const MESSAGE_FILES = {
  'user-stats': 'src/controllers/userController/read.js',
  'role-options': 'src/controllers/roleController.js',
  'permission-tree': 'src/controllers/roleController.js',
  'grant-list': 'src/controllers/privilegeController.js',
  'grant-review': 'src/controllers/privilegeController.js',
  'device-stats': 'src/controllers/deviceController.js',
  'device-expiring': 'src/controllers/deviceController.js',
  'device-reminders': 'src/controllers/deviceController.js',
  'alarm-stats': 'src/controllers/alarmController.js',
  'inspection-stats': 'src/controllers/inspectionController.js',
};

describe('蜜罐聚合端点表：声明与真实路由表同源', () => {
  test('10 条端点，方法 GET，信封闭集，id/path 唯一且冻结', () => {
    expect(agg.AGGREGATE_ENDPOINTS).toHaveLength(10);
    expect(Object.isFrozen(agg.AGGREGATE_ENDPOINTS)).toBe(true);
    const ids = agg.AGGREGATE_ENDPOINTS.map((item) => item.id);
    const paths = agg.AGGREGATE_ENDPOINTS.map((item) => item.path);
    expect(new Set(ids).size).toBe(10);
    expect(new Set(paths).size).toBe(10);
    for (const item of agg.AGGREGATE_ENDPOINTS) {
      expect(item.method).toBe('GET');
      expect(['success', 'paginated']).toContain(item.envelope);
      expect(typeof item.message).toBe('string');
      expect(item.message.length).toBeGreaterThan(0);
      expect(Object.isFrozen(item)).toBe(true);
    }
  });

  test('与路由表的 AGGREGATE 行双向相等：不多一条、不少一条', () => {
    const tablePaths = ROUTE_TABLE.filter((row) => row.handling === TRAP_HANDLING.AGGREGATE).map(
      (row) => row.path
    );
    expect(tablePaths.length).toBeGreaterThan(0);
    expect([...agg.AGGREGATE_ENDPOINTS.map((item) => item.path)].sort()).toEqual(
      [...tablePaths].sort()
    );
    for (const item of agg.AGGREGATE_ENDPOINTS) {
      const row = ROUTE_TABLE.find((entry) => entry.path === item.path);
      expect(row).toBeDefined();
      expect(row.method).toBe('GET');
      expect(row.handling).toBe(TRAP_HANDLING.AGGREGATE);
    }
  });

  test('每条路径都能被 resolveAggregatePayload 命中（builder 表未串位）', () => {
    for (const item of agg.AGGREGATE_ENDPOINTS) {
      const hit = agg.resolveAggregatePayload({ method: 'GET', path: item.path, query: {} });
      expect(hit).not.toBeNull();
      expect(hit.endpoint).toBe(item.id);
      expect(hit.envelope).toBe(item.envelope);
      expect(hit.data).toBeDefined();
      if (item.envelope === 'paginated') {
        expect(hit.pagination).toBeDefined();
        // hasMore 只在真实链显式给出时出现（apiResponse.paginated 的可选键）
        expect(Object.keys(hit.pagination)).toEqual(AGGREGATE_PAGINATION_KEYS[item.id]);
      } else {
        expect(hit.pagination).toBeUndefined();
      }
    }
  });

  test('键集与键序对真实控制器/服务逐 token 有序核对', () => {
    for (const item of PARITY) {
      const hit = resolveOf(item.id);
      const tokens = item.tokens;
      expect(orderedTokens(codeOf(item.file), tokens)).toBe(true);
      expect(Object.keys(hit.data)).toEqual(expect.arrayContaining([]));
    }
  });

  test('每条文案都能在真实控制器的代码里逐字找到', () => {
    for (const item of agg.AGGREGATE_ENDPOINTS) {
      const source = codeOf(MESSAGE_FILES[item.id]);
      expect(source).toContain(item.message);
    }
  });

  test('NON_DERIVABLE 登记完整：端点可对号、field/why 非空', () => {
    expect(agg.NON_DERIVABLE.length).toBeGreaterThanOrEqual(10);
    const paths = new Set(agg.AGGREGATE_ENDPOINTS.map((item) => item.path));
    for (const item of agg.NON_DERIVABLE) {
      expect(paths.has(item.endpoint)).toBe(true);
      expect(typeof item.field).toBe('string');
      expect(item.why.length).toBeGreaterThan(8);
    }
  });
});

describe('载荷形状与独立复算', () => {
  test('用户统计：总数/活跃数与合成表一致，byRole 计数自洽', () => {
    const data = resolveOf('user-stats').data;
    const users = decoy.DECOY_USERS;
    const active = users.filter((row) => row.status === USER_STATUS.ACTIVE);
    expect(data.total).toBe(users.length);
    expect(data.active).toBe(active.length);
    expect(data.inactive).toBe(users.filter((row) => row.status === USER_STATUS.INACTIVE).length);
    expect(data.thisMonth).toBeLessThanOrEqual(users.length);
    expect(data.byDepartment.reduce((sum, item) => sum + item.count, 0)).toBe(active.length);
    expect(data.byRole.reduce((sum, item) => sum + item.count, 0)).toBe(active.length);
    for (const item of data.byRole) {
      const expected = active.filter((row) =>
        (row.roles || []).some((role) => role && role.code === item.roleCode)
      ).length;
      expect(item.count).toBe(expected);
    }
  });

  test('设备五档：用 deviceAlertFilters 的 Mongo 片段在内存里独立求值', () => {
    const data = resolveOf('device-stats').data;
    const filters = alerts.deviceAlertFilters(new Date(), alerts.DEFAULT_EXPIRING_DAYS);
    const docs = decoy.DECOY_DEVICES.map(materialize);
    expect(data.total).toBe(docs.length);
    for (const key of [
      'expired',
      'expiringSoon',
      'needMaintenance',
      'needSchedule',
      'expiryUnknown',
    ]) {
      expect(data[key]).toBe(docs.filter((doc) => matchesFilter(filters[key], doc)).length);
    }
    expect(data.needMaintenance + data.needSchedule).toBeGreaterThan(0);
  });

  test('设备统计的桶只含出现过的值，且设备类型都在真实枚举里', () => {
    const data = resolveOf('device-stats').data;
    for (const bucket of [...data.byType, ...data.byStatus]) {
      expect(bucket.count).toBeGreaterThan(0);
    }
    const types = Object.values(DEVICE_TYPE);
    for (const bucket of data.byType) expect(types).toContain(bucket._id);
    expect(data.byType.reduce((sum, item) => sum + item.count, 0)).toBe(data.total);
  });

  test('到期清单：days 窗口可调，字段表与真实投影同源，截断事实同时进 message', () => {
    const wide = resolveOf('device-expiring');
    expect(wide.pagination.page).toBeNull();
    expect(wide.pagination.limit).toBe(alerts.EXPIRING_LIST_LIMIT);
    expect(wide.pagination.totalPages).toBeNull();
    expect(wide.data.length).toBeLessThanOrEqual(alerts.EXPIRING_LIST_LIMIT);
    expect(agg.expiringMessage(wide.pagination.total, wide.data.length)).toBe(
      aggData.EXPIRING_MESSAGE
    );
    const truncated = agg.expiringMessage(
      alerts.EXPIRING_LIST_LIMIT + 1,
      alerts.EXPIRING_LIST_LIMIT
    );
    expect(truncated).not.toBe(aggData.EXPIRING_MESSAGE);
    expect(truncated).toContain(String(alerts.EXPIRING_LIST_LIMIT + 1));
    for (const row of wide.data) {
      // 真实链 select() 默认带 _id，pick 把它排在最前
      expect(Object.keys(row)).toEqual(['_id', ...aggData.DEVICE_EXPIRY_FIELDS]);
    }
    expect(resolveOf('device-expiring', { days: '5' }).pagination.total).toBe(0);
    expect(resolveOf('device-expiring', { days: '10' }).pagination.total).toBe(1);
  });

  test('设备提醒：四档与 summary 对齐、上限 200 未触发截断、排序键单调', () => {
    const data = resolveOf('device-reminders').data;
    expect(data.limits.resultLimit).toBe(200);
    expect(data.limits.truncated.expired).toBe(false);
    expect(data.limits.truncated.total).toBe(false);
    const seen = new Set();
    for (const item of aggData.REMINDER_BUCKETS) {
      const list = data[item.key];
      expect(data.summary[item.key]).toBe(list.length);
      // 一个设备可以同时落在两档里（例如既快到期又该保养），所以不去重
      for (const row of list) seen.add(row._id);
      const times = list.map((row) => Date.parse(row[item.sort]));
      expect([...times].sort((a, b) => a - b)).toEqual(times);
    }
    expect(seen.size).toBe(data.summary.total);
    const filters = alerts.deviceAlertFilters(new Date(), data.expiringDays);
    const docs = decoy.DECOY_DEVICES.map(materialize);
    for (const key of ['expired', 'expiringSoon', 'needMaintenance', 'needSchedule']) {
      expect(data.summary[key]).toBe(docs.filter((doc) => matchesFilter(filters[key], doc)).length);
    }
  });

  test('授权列表：键序 === GRANT_LIST_FIELDS，投影字段齐、日期为 ISO', () => {
    const hit = resolveOf('grant-list');
    expect(hit.data.length).toBe(aggData.DECOY_TEMP_GRANTS.length);
    for (const row of hit.data) {
      expect(Object.keys(row)).toEqual([...grantRules.GRANT_LIST_FIELDS]);
      const policy = grantRules.approvalPolicyOf(row.permissionCodes);
      expect(row.highRisk).toBe(policy.highRisk);
      expect(row.requiredApprovals).toBe(policy.requiredApprovals);
      expect(grantRules.PRIVILEGE_GRANT_STATUSES).toContain(row.status);
      expect(row.approvals.length).toBeLessThanOrEqual(row.requiredApprovals);
      for (const field of ['requestedAt', 'grantedAt', 'expiresAt', 'revokedAt']) {
        if (row[field] !== null) expect(new Date(row[field]).toISOString()).toBe(row[field]);
      }
    }
  });

  test('授权列表：status/userId 过滤与分页边界', () => {
    const active = resolveOf('grant-list', { status: 'active' });
    expect(active.data.every((row) => row.status === 'active')).toBe(true);
    expect(active.pagination.total).toBe(active.data.length);
    const mine = resolveOf('grant-list', { userId: 'hp-u3' });
    expect(mine.data.every((row) => String(row.userId) === 'hp-u3')).toBe(true);
    const beyond = resolveOf('grant-list', { page: '5', limit: '2' });
    expect(beyond.data).toEqual([]);
    expect(beyond.pagination.total).toBe(aggData.DECOY_TEMP_GRANTS.length);
    expect(beyond.pagination.totalPages).toBe(Math.ceil(beyond.pagination.total / 2));
  });

  test('授权复核：overdue 恒 0 是算术结论而非挑数据', () => {
    expect(grantRules.MAX_GRANT_HOURS).toBeLessThan(grantRules.REVIEW_OVERDUE_DAYS * 24);
    const data = resolveOf('grant-review').data;
    expect(data.overdue).toBe(0);
    expect(data.overdueGrants).toEqual([]);
    expect(data.overdueDays).toBe(grantRules.REVIEW_OVERDUE_DAYS);
    expect(new Date(data.asOf).toISOString()).toBe(data.asOf);
    const live = aggData.DECOY_TEMP_GRANTS.filter(
      (row) =>
        row.status === 'active' &&
        row.expiresAtOffsetMin !== null &&
        -row.expiresAtOffsetMin * MINUTE_MS > 0
    );
    expect(data.active).toBe(live.length);
  });

  test('告警统计：桶只含出现过的值、总数=各桶之和、时间窗口生效', () => {
    const data = resolveOf('alarm-stats').data;
    expect(data.total).toBe(decoy.DECOY_ALARMS.length);
    expect(data.byStatus.reduce((sum, item) => sum + item.count, 0)).toBe(data.total);
    expect(data.byLevel.reduce((sum, item) => sum + item.count, 0)).toBe(data.total);
    expect(data.byType.reduce((sum, item) => sum + item.count, 0)).toBe(data.total);
    for (const item of [...data.byStatus, ...data.byLevel, ...data.byType]) {
      expect(item.count).toBeGreaterThan(0);
      expect(item._id).not.toBeUndefined();
    }
  });

  test('巡检统计：byResult 只覆盖已完成行，且结果值都在真实枚举里', () => {
    const data = resolveOf('inspection-stats').data;
    expect(data.total).toBe(decoy.DECOY_INSPECTIONS.length);
    expect(data.byStatus.reduce((sum, item) => sum + item.count, 0)).toBe(data.total);
    const completed = decoy.DECOY_INSPECTIONS.filter((row) => row.status === 'completed');
    const results = completed.filter((row) => row.result !== undefined);
    expect(data.byResult.reduce((sum, item) => sum + item.count, 0)).toBe(results.length);
    expect(INSPECTION_STATUSES).toContain('completed');
    expect(completed.length).toBeGreaterThan(0);
    expect(decoy.DECOY_INSPECTIONS.some((row) => row.status === 'overdue')).toBe(true); // S4：真实枚举里的 overdue 有一行采样
    for (const row of decoy.DECOY_INSPECTIONS) {
      const arrays = [row.devices, row.checkItems, row.findings, row.executionLog]; // M13：四个数组键恒有
      expect(arrays.every(Array.isArray)).toBe(true);
      expect(row.executionLogCount).toBe(0);
      expect(typeof row.createdBy).toBe('string');
    }
  });
});

describe('未命中分支：与真实链的 400/404 不冲突', () => {
  test('非 GET/HEAD 与未知路径一律未命中', () => {
    expect(agg.resolveAggregatePayload({ method: 'POST', path: '/api/users/stats' })).toBeNull();
    expect(
      agg.resolveAggregatePayload({ method: 'DELETE', path: '/api/devices/stats' })
    ).toBeNull();
    expect(agg.resolveAggregatePayload({ method: 'GET', path: '/api/users/nope' })).toBeNull();
    expect(agg.resolveAggregatePayload({})).toBeNull();
    expect(agg.resolveAggregatePayload()).toBeNull();
  });

  test('HEAD/大小写/尾斜杠按路由表口径归一后命中', () => {
    expect(
      agg.resolveAggregatePayload({ method: 'HEAD', path: '/api/users/stats' })
    ).not.toBeNull();
    expect(agg.resolveAggregatePayload({ method: 'GET', path: '/API/USERS/STATS' })).not.toBeNull();
    expect(
      agg.resolveAggregatePayload({ method: 'GET', path: '/api/users/stats/' })
    ).not.toBeNull();
  });

  test('非法日期与起止倒置：真实链回 400，本模块回同码 400（不是 200 也不是 404）', () => {
    // 断言从「返回 null」改成「同码拒绝」：null 会让上游回落 404「资源不存在」，
    // 而真实控制器在同一个坏参数上回 400 DATE_PARAM_INVALID —— 一次请求即可分辨真伪。
    for (const file of ['alarm-stats', 'inspection-stats']) {
      expect(resolveOf(file, { startDate: '2026-13-45' })).toEqual({
        kind: 'codeError',
        code: 'DATE_PARAM_INVALID',
      });
      expect(resolveOf(file, { startDate: '2026-03-10', endDate: '2026-03-01' })).toEqual({
        kind: 'codeError',
        code: 'DATE_RANGE_INVALID',
      });
      expect(resolveOf(file, { startDate: '2026-03-01', endDate: '2026-03-10' })).not.toBeNull();
    }
  });
});

describe('零真实读：两条独立证明', () => {
  test('文本证明：两个新模块的 require 只指向白名单，且不含 models/mongoose/services', () => {
    const allowed = [
      '../utils/constants',
      '../utils/helpers',
      './deviceAlerts',
      './honeypotDecoy', // 行时钟（量化到秒）来源：只含常量与纯函数，仍属零真实读白名单
      './honeypotDecoyAggregatesData',
      './honeypotDecoyData',
      './honeypotDecoyShape', // 体积原因拆出的取值/分桶共用件（叶子，只 require helpers）
      './privilegeGrant',
      './probePaths',
      './timezone',
    ];
    for (const rel of [
      'src/constants/honeypotDecoyAggregates.js',
      'src/constants/honeypotDecoyAggregatesData.js',
      'src/constants/honeypotDecoyShape.js',
    ]) {
      const source = codeOf(rel);
      const found = [...source.matchAll(/require\('([^']+)'\)/g)].map((match) => match[1]);
      expect([...found].sort()).toEqual(found.filter((item) => allowed.includes(item)).sort());
      expect(found.sort()).toEqual([...allowed.filter((item) => found.includes(item))].sort());
      expect(source).not.toMatch(/mongoose/);
      expect(source).not.toMatch(/\/models\//);
      expect(source).not.toMatch(/\/services\//);
    }
    expect(codeOf('src/constants/honeypotDecoyAggregatesData.js')).not.toMatch(/require\(/);
  });

  test('结构证明：全新子进程里 require 完整图不落进 model/service/mongoose', () => {
    // 子进程而不是 jest 注册表：jest 的 require.cache 里本来就有别的套件加载过的模块，
    // 只有"从零 require 一次"才真的证明这条路径上没有真实读
    const target = path.join(ROOT, 'src', 'constants', 'honeypotDecoyAggregates.js');
    const script =
      'const m = require(' +
      JSON.stringify(target) +
      ');' +
      'const bad = Object.keys(require.cache).filter((p) => /[\\/\\\\](models|services)[\\/\\\\]/.test(p) || /mongoose/.test(p));' +
      'console.log(JSON.stringify({ ok: m.AGGREGATE_ENDPOINTS.length === 10, bad }));';
    const out = JSON.parse(
      require('child_process').execFileSync(process.execPath, ['-e', script], { encoding: 'utf8' })
    );
    expect(out.ok).toBe(true);
    expect(out.bad).toEqual([]);
  });
});
