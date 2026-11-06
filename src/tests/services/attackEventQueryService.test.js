/**
 * 攻击告警查询服务的纯逻辑面：注册表不变量、筛选→谓词矩阵、severity 派生、
 * 处置富化与分类计数归并。
 *
 * 取页与 HTTP 语义（鉴权链/数据范围/分页出口）不在此测——真实 HTTP + 内存 Mongo
 * 的边界测试见 tests/controllers/attackEvents.test.js；本文件把模型边界全部 mock 掉，
 * 让「输入参数 → Mongo 谓词形状」的映射矩阵可以逐格断言，不受夹具数据干扰。
 */

'use strict';

jest.mock('../../models/AuditLog', () => ({
  AUDIT_USERNAME_COLLATION: { locale: 'en', strength: 2 },
  RESPONSE_EXCLUDE: '-body -hmac',
  aggregate: jest.fn(),
  find: jest.fn(),
  countDocuments: jest.fn(),
}));
jest.mock('../../models/IPBlacklist', () => ({ find: jest.fn() }));
jest.mock('../../services/forensicTrigger', () => ({ isForensicTarget: jest.fn() }));
// withIpLocation 的归属地口径已由审计侧测试钉住，这里按原样透传（保住行引用语义）
jest.mock('../../services/auditQueryService', () => ({
  withIpLocation: (docs) => docs,
}));

const AuditLog = require('../../models/AuditLog');
const IPBlacklist = require('../../models/IPBlacklist');
const { isForensicTarget } = require('../../services/forensicTrigger');
const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
const { ipQueryCondition } = require('../../utils/ipUtils');
const attackEvents = require('../../constants/attackEvents');
const {
  buildAttackEventFilters,
  buildSeverityCondition,
  collectDisposal,
  summarizeByAttackType,
  fetchAttackEventPage,
} = require('../../services/attackEventQueryService');

const badParamOf = (fn) => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return null;
};

describe('attackEvents 注册表不变量', () => {
  test('action 全集 ⊆ AUDIT_LOG_ACTIONS（白名单外的 action 记了也筛不出）', () => {
    const missing = attackEvents.ALL_ATTACK_EVENT_ACTIONS.filter(
      (action) => !AUDIT_LOG_ACTIONS.includes(action)
    );
    expect(missing).toEqual([]);
  });

  test('每个分类至少一条映射，分类切片互不重叠且并集等于全集', () => {
    const seen = new Set();
    for (const code of attackEvents.ATTACK_EVENT_TYPE_CODES) {
      const slice = attackEvents.actionsByAttackType(code);
      expect(slice.length).toBeGreaterThan(0);
      for (const action of slice) {
        expect(seen.has(action)).toBe(false); // 映射单值：一对多会让分类计数数重
        seen.add(action);
      }
    }
    expect(seen.size).toBe(attackEvents.ALL_ATTACK_EVENT_ACTIONS.length);
  });

  test('未知分类码在 actionsByAttackType 下返回空数组而不是抛错', () => {
    expect(attackEvents.actionsByAttackType('no_such_type')).toEqual([]);
  });
});

describe('buildAttackEventFilters 筛选→谓词矩阵', () => {
  test('无筛选：基查询钉在注册表全集上', () => {
    const { query, usernamePrefix } = buildAttackEventFilters({});
    expect(query.action.$in).toHaveLength(attackEvents.ALL_ATTACK_EVENT_ACTIONS.length);
    expect(query.action.$in).toEqual(expect.arrayContaining(attackEvents.ALL_ATTACK_EVENT_ACTIONS));
    expect(usernamePrefix).toBe(false);
  });

  test('attackType 切片：action 收窄到该分类的注册表子集', () => {
    const { query } = buildAttackEventFilters({ attackType: 'honeypot' });
    expect(query.action.$in).toEqual([
      'honeypot_login',
      'honeypot_probe',
      'honeypot_chain_escalated',
    ]);
  });

  test('attackType 非法值 400（validateEnum 白名单）', () => {
    const error = badParamOf(() => buildAttackEventFilters({ attackType: 'sql_injection' }));
    expect(error).not.toBeNull();
    expect(error.status).toBe(400);
  });

  test('规则名等值：注册表内放行，注册表外 400', () => {
    const { query } = buildAttackEventFilters({ action: 'login_failed' });
    expect(query.action).toBe('login_failed');
    const error = badParamOf(() => buildAttackEventFilters({ action: 'audit_log_query' }));
    expect(error.status).toBe(400); // 注册表外的审计 action 不是攻击事件
  });

  test('规则名与分类同给：同域放行，跨域恒空 400', () => {
    const ok = buildAttackEventFilters({ attackType: 'credential', action: 'login_failed' });
    expect(ok.query.action).toBe('login_failed');
    const conflict = badParamOf(() =>
      buildAttackEventFilters({ attackType: 'probe', action: 'login_failed' })
    );
    expect(conflict.status).toBe(400);
    expect(conflict.message).toContain('恒空');
  });

  test('时间窗：date-only 展开为业务时区边界，反序与超窗 400', () => {
    const { query } = buildAttackEventFilters({ startDate: '2026-11-01', endDate: '2026-11-03' });
    expect(query.timestamp.$gte).toBeInstanceOf(Date);
    expect(query.timestamp.$lte).toBeInstanceOf(Date);
    expect(query.timestamp.$gte.getTime()).toBeLessThan(query.timestamp.$lte.getTime());

    const reversed = badParamOf(() =>
      buildAttackEventFilters({ startDate: '2026-11-03', endDate: '2026-11-01' })
    );
    expect(reversed.status).toBe(400);

    const tooWide = badParamOf(() =>
      buildAttackEventFilters({ startDate: '2025-01-01', endDate: '2026-11-01' })
    );
    expect(tooWide.status).toBe(400);

    const numeric = badParamOf(() => buildAttackEventFilters({ startDate: '123' }));
    expect(numeric.status).toBe(400); // 数字形态串是"写错的日期"（isValidDateParam 判据）
  });

  test('ip：合法走 ipQueryCondition 单源，非法 400', () => {
    const { query } = buildAttackEventFilters({ ip: '203.0.113.7' });
    expect(query.ip).toEqual(ipQueryCondition('203.0.113.7'));
    const error = badParamOf(() => buildAttackEventFilters({ ip: 'not-an-ip' }));
    expect(error.status).toBe(400);
  });

  test('username：前缀范围条件 + collation 旗标；数组形态 400', () => {
    const { query, usernamePrefix } = buildAttackEventFilters({ username: 'adm' });
    expect(query.username).toEqual({ $gte: 'adm', $lt: 'adm\uFFFF' });
    expect(usernamePrefix).toBe(true);

    const bare = buildAttackEventFilters({});
    expect(bare.usernamePrefix).toBe(false);

    const error = badParamOf(() => buildAttackEventFilters({ username: ['a'] }));
    expect(error.status).toBe(400);
  });

  test('path：部分匹配正则必须转义；数组形态 400', () => {
    const { query } = buildAttackEventFilters({ path: '/api/(devices)?*' });
    expect(query.path).toEqual({ $regex: '/api/\\(devices\\)\\?\\*', $options: 'i' });
    const error = badParamOf(() => buildAttackEventFilters({ path: ['x'] }));
    expect(error.status).toBe(400);
  });

  test('severity 区间与分类切片可叠加（两个维度同时收窄）', () => {
    const { query } = buildAttackEventFilters({ attackType: 'credential', severityMin: 'high' });
    expect(query.action.$in).toEqual([
      'login_failed',
      'brute_force_login',
      'login_captcha_rejected',
      'mfa_verify_failed',
      'mfa_attempt_locked',
      'account_temp_locked',
      'canary_username_attempt',
    ]);
    expect(query.riskLevel).toEqual({ $in: ['high', 'critical'] });
  });
});

describe('buildSeverityCondition 有序清单派生（F-149）', () => {
  test('「某档及以上」切片必须等于 riskLevelsAtLeast 的产物', () => {
    expect(buildSeverityCondition('high', undefined)).toEqual({
      riskLevel: { $in: ['high', 'critical'] },
    });
    expect(buildSeverityCondition('low', undefined)).toEqual({
      riskLevel: { $in: ['low', 'medium', 'high', 'critical'] },
    });
  });

  test('「某档及以下」从同一份有序清单推导', () => {
    expect(buildSeverityCondition(undefined, 'medium')).toEqual({
      riskLevel: { $in: ['low', 'medium'] },
    });
    expect(buildSeverityCondition('medium', 'high')).toEqual({
      riskLevel: { $in: ['medium', 'high'] },
    });
  });

  test('档位非法 400；min 高于 max 恒空 400（不是静默空集）；两端同档合法', () => {
    expect(badParamOf(() => buildSeverityCondition('urgent', undefined)).status).toBe(400);
    const empty = badParamOf(() => buildSeverityCondition('critical', 'low'));
    expect(empty.status).toBe(400);
    expect(empty.message).toContain('恒空');
    expect(buildSeverityCondition('high', 'high')).toEqual({ riskLevel: { $in: ['high'] } });
    expect(buildSeverityCondition(undefined, undefined)).toBeNull();
  });
});

describe('collectDisposal 处置派生', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    isForensicTarget.mockReturnValue(false);
  });

  const mockBlacklistEntries = (entries) => {
    IPBlacklist.find.mockReturnValue({
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue(entries),
    });
  };

  test('当前在黑名单 → banned；过期行 → 回落 observing；取证标记 → forensic', async () => {
    mockBlacklistEntries([
      { ip: '203.0.113.1', expiresAt: null }, // 永久
      { ip: '203.0.113.2', expiresAt: new Date(Date.now() - 60 * 1000) }, // 已过期未清扫
    ]);
    isForensicTarget.mockImplementation((ip) => ip === '203.0.113.3');

    const rows = [{ ip: '203.0.113.1' }, { ip: '203.0.113.2' }, { ip: '203.0.113.3' }, {}];
    await collectDisposal(rows);
    expect(rows.map((row) => row.disposal)).toEqual([
      'banned',
      'observing', // expiresAt 已过：处置列是"此刻"状态，不依赖 TTL 清扫时机
      'forensic',
      'observing',
    ]);
  });

  test('两侧各自 normalizeIP 再对齐：::ffff: 映射形态不算"两个人"', async () => {
    mockBlacklistEntries([{ ip: '::ffff:203.0.113.9', expiresAt: null }]);
    const rows = [{ ip: '203.0.113.9' }];
    await collectDisposal(rows);
    expect(rows[0].disposal).toBe('banned');
  });

  test('黑名单查询只取 type:"black"（白名单是放行语义，不是处置）', async () => {
    mockBlacklistEntries([]);
    await collectDisposal([{ ip: '203.0.113.1' }]);
    expect(IPBlacklist.find).toHaveBeenCalledWith(expect.objectContaining({ type: 'black' }));
  });

  test('fail-soft 外壳：黑名单查询抖动 → 整页降级 unknown，不冒充「观察」也不拖垮主查询', async () => {
    IPBlacklist.find.mockImplementation(() => {
      throw new Error('connection reset');
    });
    const { collectDisposalSafely } = require('../../services/attackEventQueryService');
    const rows = [{ ip: '203.0.113.1' }, { ip: '203.0.113.2' }];
    await expect(collectDisposalSafely(rows)).resolves.toBe(rows); // 不抛，原行返回
    expect(rows.map((row) => row.disposal)).toEqual(['unknown', 'unknown']);
  });
});

describe('summarizeByAttackType 分类计数归并', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const mockAggregate = (rows) => {
    AuditLog.aggregate.mockImplementation(() => {
      const p = Promise.resolve(rows);
      p.collation = jest.fn().mockReturnThis();
      return p;
    });
  };

  test('$group 落在 action 上再经注册表归并回分类；注册表外只进 all', async () => {
    mockAggregate([
      { _id: 'login_failed', count: 3 },
      { _id: 'brute_force_login', count: 1 },
      { _id: 'honeypot_login', count: 2 },
      { _id: 'not_in_registry_action', count: 4 },
    ]);
    const counts = await summarizeByAttackType({ query: {}, usernamePrefix: false });
    expect(counts.all).toBe(10);
    expect(counts.byType).toMatchObject({ credential: 4, honeypot: 2, probe: 0 });
    // 谓词必须原样进 $match（数据范围已由调用方并入）
    expect(AuditLog.aggregate).toHaveBeenCalledWith(
      expect.arrayContaining([{ $match: {} }, { $group: { _id: '$action', count: { $sum: 1 } } }]),
      expect.anything()
    );
  });

  test('username 前缀时 aggregate 必须挂 collation', async () => {
    mockAggregate([]);
    await summarizeByAttackType({ query: { username: { $gte: 'a' } }, usernamePrefix: true });
    const aggQuery = AuditLog.aggregate.mock.results[0].value;
    expect(aggQuery.collation).toHaveBeenCalledWith(AuditLog.AUDIT_USERNAME_COLLATION);
  });
});

describe('fetchAttackEventPage 取页骨架', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const makeQuery = (docs) => {
    const q = {};
    for (const method of ['populate', 'sort', 'limit', 'skip', 'collation']) {
      q[method] = jest.fn().mockReturnThis();
    }
    q.select = jest.fn().mockImplementation(() => Promise.resolve(docs));
    return q;
  };

  test('游标模式：limit+1 拉取，total 为 null，排序/投影形状与审计页同源', async () => {
    const docs = [
      { _id: 'a', timestamp: 3 },
      { _id: 'b', timestamp: 2 },
      { _id: 'c', timestamp: 1 },
    ];
    AuditLog.find.mockReturnValue(makeQuery(docs));

    const result = await fetchAttackEventPage({
      query: { action: { $in: [] } },
      usernamePrefix: false,
      pageNum: 1,
      limitNum: 2,
      cursorQuery: { $and: [] },
    });
    expect(result.cursorPaged).toBe(true);
    expect(result.total).toBeNull();
    expect(AuditLog.find).toHaveBeenCalledWith({ $and: [] });
    expect(result.docs).toHaveLength(3); // limitNum+1 只判 hasMore，裁剪交给 buildCursorResult
    const chain = AuditLog.find.mock.results[0].value;
    expect(chain.sort).toHaveBeenCalledWith({ timestamp: -1, _id: -1 });
    expect(chain.limit).toHaveBeenCalledWith(3);
  });

  test('偏移模式：skip/limit 与 countDocuments 并行，total 返回真实值', async () => {
    AuditLog.find.mockReturnValue(makeQuery([{ _id: 'a' }]));
    AuditLog.countDocuments.mockImplementation(() => {
      const p = Promise.resolve(7);
      p.collation = jest.fn().mockReturnThis();
      return p;
    });

    const result = await fetchAttackEventPage({
      query: {},
      usernamePrefix: false,
      pageNum: 3,
      limitNum: 20,
      cursorQuery: null,
    });
    expect(result.cursorPaged).toBe(false);
    expect(result.total).toBe(7);
    const chain = AuditLog.find.mock.results[0].value;
    expect(chain.skip).toHaveBeenCalledWith(40);
    expect(chain.limit).toHaveBeenCalledWith(20);
  });
});
