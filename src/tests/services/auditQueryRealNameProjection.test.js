/**
 * 审计出口的 realName 双面收口（免数据库，静态桩驱动三条读取路径）
 *
 * 缺陷形态：审计列表/详情 populate 用户文档时投影写成 'username realName'，
 * 明文姓名随响应出站；全局审计中间件再采集响应体进 responseBody 时，
 * 姓名就二次固化进 append-only 审计集合（另一面由 SENSITIVE_KEY_SUBSTRINGS 收口）。
 * 本文件钉的是读取面：三条路径（游标分页 / offset 分页 / 详情）投影都必须只取 username，
 * 且响应体里不再出现 realName 键。
 */

jest.mock('../../models/AuditLog', () => ({
  find: (...args) => mockChainFor('find', args, mockDocsFresh()),
  findOne: (...args) => mockChainFor('findOne', args, mockDetailFresh()),
  countDocuments: (...args) => mockChainFor('countDocuments', args, 3),
  aggregate: (...args) => mockChainFor('aggregate', args, []),
  RESPONSE_EXCLUDE: '-hmac -responseBody',
  AUDIT_USERNAME_COLLATION: { locale: 'en', strength: 2 },
}));

jest.mock('../../services/statsCache', () => ({ get: () => ({ hit: false }), set: jest.fn() }));
jest.mock('../../services/auditScopeFilter', () => ({
  applyAuditDataScope: async (q) => ({ query: q }),
}));
jest.mock('../../services/ipLocationService', () => ({ locate: () => null }));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));
jest.mock('../../middleware/errorHandler', () => ({
  asyncHandler: (fn) => fn, // 不桩会把内部结果吞进 next()，断言读不到响应
  markResponseAbortedByError: jest.fn(),
}));
jest.mock('../../services/auditExportService', () => ({
  buildAuditExportManifest: jest.fn(() => ({})),
  sendAuditExportHeaders: jest.fn(),
  streamAuditExport: jest.fn(),
  MANIFEST_LINE_PREFIX: '# manifest: ',
  EXPORT_CSV_HEADER: 'timestamp,action\n',
}));
// 查询组装与 collation 挂载与被测性质无关：给最小实现即可
jest.mock('../../utils/auditQuery', () => ({
  buildAuditQuery: () => ({
    query: {},
    startDate: undefined,
    endDate: undefined,
    usernamePrefix: null,
  }),
  withCollation: (q, c) => (c ? q.collation(c) : q),
}));

const { encodeCursor } = require('../../utils/cursorPagination');
const { queryAuditLogs } = require('../../services/auditQueryService');
const { getAuditLogDetail } = require('../../controllers/auditController');

// 每次链式调用登记一条 { op, args, steps }；populate 实参在断言时逐条核对
const mockOps = [];

// 用户文档原文带 realName：若投影串把它带进来，材料化后响应必含该键 ⇒ 断言转红
const mockUserRaw = Object.freeze({
  _id: '64f000000000000000000001',
  username: 'op-admin',
  realName: 'SHOULD-NOT-LEAK',
});

/** 按 populate 记录的投影串裁剪用户文档——让"投影串"变成可观察的行为而不是文本。
 *  mongoose 投影默认保留 _id（字符串投影未显式排除时），故 _id 恒在。 */
const mockProjectUser = (proj) => {
  const keep = new Set(
    String(proj || '')
      .split(/\s+/)
      .filter(Boolean)
  );
  keep.add('_id');
  const out = {};
  for (const [k, v] of Object.entries(mockUserRaw)) if (keep.has(k)) out[k] = v;
  return out;
};

const mockMaterialize = (entry) => {
  const pop = entry.steps.find(([m]) => m === 'populate');
  if (!pop || entry.resolve == null) return entry.resolve;
  const user = mockProjectUser(pop[2]);
  if (Array.isArray(entry.resolve)) {
    return entry.resolve.map((d) => ({ ...d, userId: { ...user } }));
  }
  return { ...entry.resolve, userId: { ...user } };
};

const mockChainFor = (op, args, resolve) => {
  const entry = { op, args, steps: [], resolve };
  mockOps.push(entry);
  const node = {
    populate(...a) {
      entry.steps.push(['populate', ...a]);
      return node;
    },
    sort(...a) {
      entry.steps.push(['sort', ...a]);
      return node;
    },
    skip(...a) {
      entry.steps.push(['skip', ...a]);
      return node;
    },
    limit(...a) {
      entry.steps.push(['limit', ...a]);
      return node;
    },
    select(...a) {
      entry.steps.push(['select', ...a]);
      return node;
    },
    collation(...a) {
      entry.steps.push(['collation', ...a]);
      return node;
    },
    lean: () => Promise.resolve(mockMaterialize(entry)),
    then: (onRes, onRej) => Promise.resolve(mockMaterialize(entry)).then(onRes, onRej),
    catch: (onRej) => Promise.resolve(mockMaterialize(entry)).catch(onRej),
  };
  return node;
};

const mockDocsFresh = () => [
  {
    _id: '65000000000000000000000a',
    timestamp: new Date('2026-09-01T01:00:00.000Z'),
    action: 'login',
    userId: { ...mockUserRaw },
  },
  {
    _id: '65000000000000000000000b',
    timestamp: new Date('2026-09-01T00:59:00.000Z'),
    action: 'logout',
    userId: { ...mockUserRaw },
  },
];
const mockDetailFresh = () => ({
  _id: '65000000000000000000000a',
  timestamp: new Date('2026-09-01T01:00:00.000Z'),
  action: 'login',
  userId: { ...mockUserRaw },
  body: {},
});

const makeRes = () => ({
  statusCode: null,
  payload: null,
  headers: {},
  locals: {},
  setHeader(k, v) {
    this.headers[k] = v;
    return this;
  },
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(data) {
    this.payload = data;
    return this;
  },
});
const makeReq = (extra = {}) => ({
  method: 'GET',
  originalUrl: '/api/security/audit-logs',
  ip: '203.0.113.9',
  user: { userId: 'op-1', username: 'op-admin' },
  get: () => 'jest-ua',
  query: {},
  params: {},
  ...extra,
});

beforeEach(() => {
  mockOps.length = 0;
});

describe('审计读取路径的 populate 投影只取 username（响应无 realName）', () => {
  test('游标分页：populate 投影为 username，响应体不含 realName', async () => {
    const cursor = encodeCursor({
      v: new Date('2026-09-01T01:00:00.000Z'),
      id: '65000000000000000000000a',
    });
    const res = makeRes();
    await queryAuditLogs(makeReq({ query: { cursor, limit: '10' } }), res);
    expect(res.statusCode).toBe(200);
    const find = mockOps.find((e) => e.op === 'find');
    expect(find).toBeTruthy();
    expect(find.steps).toContainEqual(['populate', 'userId', 'username']);
    // 投影行为化断言：材料化后的 userId 只剩投影声明过的键，realName 无处可挂
    expect(Object.keys(res.payload.data[0].userId).sort()).toEqual(['_id', 'username']);
    expect(JSON.stringify(res.payload)).not.toContain('realName');
    expect(JSON.stringify(res.payload)).not.toContain('SHOULD-NOT-LEAK');
  });

  test('offset 分页：populate 投影为 username，响应体不含 realName', async () => {
    const res = makeRes();
    await queryAuditLogs(makeReq({ query: { page: '1', limit: '10' } }), res);
    expect(res.statusCode).toBe(200);
    const find = mockOps.find((e) => e.op === 'find');
    expect(find).toBeTruthy();
    expect(find.steps).toContainEqual(['populate', 'userId', 'username']);
    expect(find.steps.map(([m]) => m)).toContain('skip'); // 确认走的是 offset 分支
    expect(Object.keys(res.payload.data[0].userId).sort()).toEqual(['_id', 'username']);
    expect(JSON.stringify(res.payload)).not.toContain('realName');
    expect(JSON.stringify(res.payload)).not.toContain('SHOULD-NOT-LEAK');
  });

  test('详情：findOne populate 投影为 username，响应体不含 realName', async () => {
    const res = makeRes();
    await getAuditLogDetail(makeReq({ params: { id: '65000000000000000000000a' } }), res);
    expect(res.statusCode).toBe(200);
    const one = mockOps.find((e) => e.op === 'findOne');
    expect(one).toBeTruthy();
    expect(one.steps).toContainEqual(['populate', 'userId', 'username']);
    expect(Object.keys(res.payload.data.userId).sort()).toEqual(['_id', 'username']);
    expect(JSON.stringify(res.payload)).not.toContain('realName');
    expect(JSON.stringify(res.payload)).not.toContain('SHOULD-NOT-LEAK');
  });

  test('总闸：三条路径的 populate 实参逐字一致，且不得回退成含 realName 的投影', async () => {
    // 自驱三条路径（beforeEach 会清空登记，不能依赖前几条用例的残留）
    const cursor = encodeCursor({
      v: new Date('2026-09-01T01:00:00.000Z'),
      id: '65000000000000000000000a',
    });
    await queryAuditLogs(makeReq({ query: { cursor, limit: '10' } }), makeRes());
    await queryAuditLogs(makeReq({ query: { page: '1', limit: '10' } }), makeRes());
    await getAuditLogDetail(makeReq({ params: { id: '65000000000000000000000a' } }), makeRes());
    expect(mockOps.filter((e) => e.op === 'find' || e.op === 'findOne')).toHaveLength(3);
    const pops = mockOps.flatMap((e) =>
      e.steps.filter(([m]) => m === 'populate').map(([, field, proj]) => `${e.op}:${field}:${proj}`)
    );
    expect(pops).toEqual([
      'find:userId:username',
      'find:userId:username',
      'findOne:userId:username',
    ]);
  });
});
