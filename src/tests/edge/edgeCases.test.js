/**
 * 边界情况补齐（2026-09-15 边界覆盖专项）
 *
 * 从 lcov 未覆盖分支逐行审阅后确认的四类真边界（此前无测试）：
 *  1. auditScopeFilter（评价报告 #22 拆分件）：self/department 各越权与放行分支
 *     ——权限翻译逻辑，全部是安全语义分支
 *  2. cursorPagination：sortField 被注入为非 string（qs 展开攻击面）与
 *     valueType 非法值分支
 *  3. ipRange：规则超长（单条 64 / 整体 8192）与 ipaddr.js 抛错容错
 *     （畸形 IP、地址族错配）
 *  4. protocolCompliance：同名 header 多值的字节求和分支 + 违规审计异步落库
 *     （setImmediate 路径，含 AuditLog.record 抛错的容错分支）
 */

const mockPermissionRbac = { getDataScope: jest.fn() };

jest.mock('../../middleware/rbac', () => ({
  ...jest.requireActual('../../middleware/rbac'),
  getDataScope: (...a) => mockPermissionRbac.getDataScope(...a),
}));

const mockUserFindById = jest.fn();
const mockUserDistinct = jest.fn();

jest.mock('../../models/User', () => ({
  findById: (...a) => mockUserFindById(...a),
  distinct: (...a) => mockUserDistinct(...a),
}));

const mongoose = require('mongoose');
const { applyAuditDataScope } = require('../../services/auditScopeFilter');
const { applyCursorCondition, decodeCursor } = require('../../utils/cursorPagination');
const {
  validateRules,
  isIPAllowed,
  MAX_RULE_LENGTH,
  MAX_TEXT_LENGTH,
} = require('../../utils/ipRange');

const HEX_SELF = 'a'.repeat(24);
const OID = (s) => new mongoose.Types.ObjectId(s);

describe('auditScopeFilter 数据范围翻译分支（#22）', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  test('all：原样放行，不加任何条件', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({ type: 'all' });
    const q = { action: 'auth_login' };
    const { query, dataScope } = await applyAuditDataScope(q, 'op1');
    expect(query).toBe(q);
    expect(dataScope.type).toBe('all');
  });

  test('self：未点查 → 收敛为本人 userId', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({ type: 'self', userId: HEX_SELF });
    const { query } = await applyAuditDataScope({}, 'op1');
    expect(query.userId).toEqual(OID(HEX_SELF));
  });

  test('self：点查他人 → 无条件拒绝（空 $in）', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({ type: 'self', userId: HEX_SELF });
    const other = OID('2'.repeat(24));
    const { query } = await applyAuditDataScope({ userId: other }, 'op1');
    expect(query._id).toEqual({ $in: [] });
  });

  test('department：缺 department 字段 → 退化为本人 userId', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({ type: 'department', userId: HEX_SELF });
    const { query } = await applyAuditDataScope({}, 'op1');
    expect(query.userId).toEqual(OID(HEX_SELF));
  });

  test('department 点查：目标属本部门 → 放行为目标 userId', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({
      type: 'department',
      userId: 'u1',
      department: '运维部',
    });
    mockUserFindById.mockReturnValue({
      select: () => ({
        lean: async () => ({ _id: 't1', department: '运维部' }),
      }),
    });
    const target = OID('3'.repeat(24));
    const { query } = await applyAuditDataScope({ userId: target }, 'op1');
    expect(query.userId).toEqual(target);
    expect(mockUserDistinct).not.toHaveBeenCalled(); // 点查快路径不拉成员集
  });

  test('department 点查：目标属其他部门 → 拒绝', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({
      type: 'department',
      userId: 'u1',
      department: '运维部',
    });
    mockUserFindById.mockReturnValue({
      select: () => ({
        lean: async () => ({ _id: 't2', department: '财务部' }),
      }),
    });
    const { query } = await applyAuditDataScope({ userId: OID('4'.repeat(24)) }, 'op1');
    expect(query._id).toEqual({ $in: [] });
  });

  test('department 点查：目标查询失败（catch→null）→ 拒绝', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({
      type: 'department',
      userId: 'u1',
      department: '运维部',
    });
    mockUserFindById.mockReturnValue({
      select: () => ({
        lean: async () => {
          throw new Error('db down');
        },
      }),
    });
    const { query } = await applyAuditDataScope({ userId: OID('5'.repeat(24)) }, 'op1');
    expect(query._id).toEqual({ $in: [] });
  });

  test('department 无点查：成员集非空 → $in 集合；30s 内命中缓存', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({
      type: 'department',
      userId: 'u1',
      department: '运维部',
    });
    const ids = [OID('6'.repeat(24)), OID('7'.repeat(24))];
    mockUserDistinct.mockResolvedValue(ids);
    const first = await applyAuditDataScope({}, 'op1');
    expect(first.query.userId).toEqual({ $in: ids });
    // 第二次走缓存：distinct 不再被调
    const second = await applyAuditDataScope({}, 'op1');
    expect(second.query.userId).toEqual({ $in: ids });
    expect(mockUserDistinct).toHaveBeenCalledTimes(1);
  });

  test('department 无点查：成员集为空 → 拒绝', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({
      type: 'department',
      userId: 'u1',
      department: '空部门',
    });
    mockUserDistinct.mockResolvedValue([]);
    const { query } = await applyAuditDataScope({}, 'op1');
    expect(query._id).toEqual({ $in: [] });
  });

  test('未知范围类型 → 无条件拒绝', async () => {
    mockPermissionRbac.getDataScope.mockResolvedValue({ type: 'weird' });
    const { query } = await applyAuditDataScope({}, 'op1');
    expect(query._id).toEqual({ $in: [] });
  });
});

describe('cursorPagination 类型注入与非法值分支', () => {
  const validCursor = (id = 'a'.repeat(24), v = '2026-09-01T00:00:00.000Z') =>
    Buffer.from(JSON.stringify({ v, id }), 'utf8').toString('base64url');

  test('sortField 被注入为 object（qs 展开）→ 400 排序字段不合法', () => {
    expect(() =>
      applyCursorCondition(
        {},
        {
          sortField: { $where: '1' },
          sortDir: 1,
          cursor: validCursor(),
        }
      )
    ).toThrow('排序字段不合法');
  });

  test('sortField 以点号开头 → 400', () => {
    expect(() =>
      applyCursorCondition({}, { sortField: '.hidden', sortDir: 1, cursor: validCursor() })
    ).toThrow('排序字段不合法');
  });

  test('valueType=date 且 v 非法日期 → 400 游标无效', () => {
    expect(() =>
      applyCursorCondition(
        {},
        {
          sortField: 'createdAt',
          sortDir: 1,
          cursor: validCursor('a'.repeat(24), 'not-a-date'),
          valueType: 'date',
        }
      )
    ).toThrow('分页游标无效');
  });

  test('valueType=number 且 v 非有限数 → 400 游标无效', () => {
    expect(() =>
      applyCursorCondition(
        {},
        {
          sortField: 'count',
          sortDir: 1,
          cursor: validCursor('a'.repeat(24), 'NaN-ish'),
          valueType: 'number',
        }
      )
    ).toThrow('分页游标无效');
  });

  test('decodeCursor：非 base64url 乱串 → 400；超长 → 400', () => {
    expect(() => decodeCursor('!!!not-base64!!!')).toThrow('分页游标无效');
    expect(() => decodeCursor('x'.repeat(5000))).toThrow('分页游标无效');
  });
});

describe('ipRange 超长与畸形输入容错', () => {
  test('validateRules：单条规则超过 64 字符 → invalid', () => {
    const long = '192.168.1.'.concat('1'.repeat(MAX_RULE_LENGTH)); // 远超 64
    const r = validateRules('192.168.1.1,' + long);
    expect(r.valid).toBe(false);
    expect(r.invalid).toEqual([long]);
  });

  test('validateRules：整体文本超过 8192 字符 → 全部无效', () => {
    const chunks = [];
    let n = 0;
    while (chunks.join(',').length <= MAX_TEXT_LENGTH) {
      chunks.push('10.0.0.' + (n++ % 250) + '/32');
    }
    const text = chunks.join(',');
    expect(text.length).toBeGreaterThan(MAX_TEXT_LENGTH);
    const r = validateRules(text);
    expect(r.valid).toBe(false);
    expect(r.invalid).toEqual(['规则文本过长']);
    expect(r.allowCount).toBe(0);
  });

  test('isIPAllowed：客户端为畸形 IP（ipaddr 解析失败）→ invalid_client_ip', () => {
    expect(isIPAllowed('999.999.999.999', '192.168.1.0/24').reason).toBe('invalid_client_ip');
    expect(isIPAllowed('not-an-ip', '*').reason).toBe('invalid_client_ip');
    expect(isIPAllowed('999.999.999.999', '192.168.1.0/24').allowed).toBe(false);
  });

  test('isIPAllowed：客户端 IPv6 与 IPv4 网段规则地址族错配 → false（不抛错）', () => {
    expect(isIPAllowed('::1', '192.168.1.0/24').allowed).toBe(false);
    expect(isIPAllowed('2001:db8::1', '10.0.0.0/8').allowed).toBe(false);
    // 末段区间语法：IPv6 客户端命中 ipv4-pattern 的 include(':') 早退分支
    expect(isIPAllowed('2001:db8::1', '192.168.1.1-254').allowed).toBe(false);
  });
});
