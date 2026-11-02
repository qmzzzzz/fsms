/**
 * services/attackProfile.js 取数层：输入边界、投影最小化、名单降级。
 *
 * 聚合与判定的纯函数由 attackProfileSummary.test.js 覆盖；本文件只钉取数层
 * 那些脱离 Mongo/名单服务就看不到的分支：
 *   · 非法 IP 不落库查询（不把请求方输入直接变成查询条件）；
 *   · 名单查询失败只降级 containment，画像主体仍可用；
 *   · 审计查询只 select 判定字段，且把数据范围条件原样合并进查询；
 *   · 库内倒序取回后在内存里翻正，首尾时间不能颠倒。
 */

'use strict';

jest.mock('../../models/AuditLog', () => ({
  find: jest.fn(),
  countDocuments: jest.fn(),
}));
jest.mock('../../services/ipListService', () => ({
  matchEntries: jest.fn(),
}));

const AuditLog = require('../../models/AuditLog');
const ipListService = require('../../services/ipListService');
const {
  buildAttackProfile,
  resolveWindow,
  PROFILE_FIELDS,
} = require('../../services/attackProfile');
const { MAX_PROFILE_ROWS } = require('../../constants/attackProfile');

const BASE = new Date('2026-01-01T00:00:00Z');
const at = (minutes) => new Date(BASE.getTime() + minutes * 60 * 1000);

const row = (overrides = {}) => ({
  timestamp: at(0),
  action: 'login_failed',
  category: 'auth',
  success: false,
  statusCode: 401,
  method: 'POST',
  path: '/api/auth/login',
  username: 'alice',
  userAgent: 'jest-agent',
  ...overrides,
});

const mockQuery = (rows) => {
  const lean = jest.fn().mockResolvedValue(rows);
  const limit = jest.fn(() => ({ lean }));
  const sort = jest.fn(() => ({ limit }));
  const select = jest.fn(() => ({ sort }));
  AuditLog.find.mockReturnValue({ select });
  return { select, sort, limit };
};

const mockContainment = () =>
  ipListService.matchEntries.mockResolvedValue({ blackMatches: [], whiteMatches: [] });

describe('attackProfile 取数层', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    AuditLog.countDocuments.mockResolvedValue(0);
    mockContainment();
  });

  test('非法 IP：ok=false 且不发起任何查询', async () => {
    const result = await buildAttackProfile({ ip: '0177.0.0.1' });
    expect(result).toEqual({ ok: false, reason: 'invalid_ip' });
    expect(AuditLog.find).not.toHaveBeenCalled();
    expect(AuditLog.countDocuments).not.toHaveBeenCalled();
    expect(ipListService.matchEntries).not.toHaveBeenCalled();
  });

  test('名单服务失败：只降级 containment，画像主体照常返回', async () => {
    const { select } = mockQuery([]);
    AuditLog.countDocuments.mockResolvedValue(0);
    ipListService.matchEntries.mockRejectedValue(new Error('名单库不可用'));

    const result = await buildAttackProfile({ ip: '203.0.113.9', now: BASE });
    expect(result.ok).toBe(true);
    expect(result.verdict).toBe('no_data');
    expect(result.containment).toEqual({
      degraded: true,
      blacklisted: false,
      whitelisted: false,
      entries: [],
    });
    expect(select).toHaveBeenCalledTimes(1);
  });

  test('查询条件合并数据范围、投影不含敏感载荷，名单条目只带展示字段', async () => {
    const { select } = mockQuery([
      row({ _id: 'rec-late', timestamp: at(2) }),
      row({ _id: 'rec-early', timestamp: at(1), username: 'bob' }),
    ]);
    AuditLog.countDocuments.mockResolvedValue(2);
    ipListService.matchEntries.mockResolvedValue({
      blackMatches: [
        {
          ip: '203.0.113.9',
          reason: '自动封禁',
          source: 'auto',
          targetUsername: null,
          expiresAt: null,
          createdAt: at(5),
          body: 'MUST_NOT_LEAK',
          extraInternal: 'MUST_NOT_LEAK',
          _id: 'mongo-internal',
        },
      ],
      whiteMatches: [],
    });

    const result = await buildAttackProfile({
      ip: '203.0.113.9',
      hours: 24,
      now: BASE,
      scopeFilter: { userId: 'scope-user' },
      scopeLimited: true,
    });

    expect(result.ok).toBe(true);
    expect(result.window).toEqual({
      hours: 24,
      since: at(-24 * 60).toISOString(),
      until: BASE.toISOString(),
    });
    expect(result.containment).toMatchObject({
      degraded: false,
      blacklisted: true,
      whitelisted: false,
    });
    expect(result.containment.entries).toEqual([
      {
        listType: 'black',
        ip: '203.0.113.9',
        reason: '自动封禁',
        source: 'auto',
        targetUsername: null,
        expiresAt: null,
        createdAt: at(5),
      },
    ]);
    expect(JSON.stringify(result.containment)).not.toContain('MUST_NOT_LEAK');
    expect(JSON.stringify(result.containment)).not.toContain('mongo-internal');

    const condition = AuditLog.find.mock.calls[0][0];
    expect(condition).toMatchObject({
      userId: 'scope-user',
      timestamp: { $gte: at(-24 * 60), $lte: BASE },
    });
    expect(condition.ip.$in).toEqual(['203.0.113.9', '::ffff:203.0.113.9']);

    const projection = select.mock.calls[0][0];
    expect(projection).toBe(PROFILE_FIELDS);
    // 记录定位键随投影取回，但正文/头袋仍不得出现在 select 里
    expect(projection).toContain('_id');
    for (const forbidden of [
      'body',
      'requestHeaders',
      'responseHeaders',
      'responseBody',
      'params',
      'query',
    ]) {
      expect(projection).not.toContain(forbidden);
    }

    // 库内按时间倒序取回；翻正后首尾时间必须恢复正序
    expect(result.firstSeen).toEqual(at(1));
    expect(result.lastSeen).toEqual(at(2));
    expect(result.scopeLimited).toBe(true);
    expect(result.suggestions).toContain('verify_scope');

    // 证据只带定位键与判定字段：两行都归入 brute_force，logId 可回指原始记录
    const evidence = result.categories.flatMap((item) => item.evidence);
    expect(evidence.map((item) => item.logId).sort()).toEqual(['rec-early', 'rec-late']);
    expect(result.uncategorized).toEqual({ count: 0, evidence: [] });
  });

  test('未打满行数上限：取回条数即总数，不再额外 count', async () => {
    mockQuery([row()]);

    const result = await buildAttackProfile({ ip: '203.0.113.9', now: BASE });
    expect(result.total).toBe(1);
    expect(result.truncated).toBe(false);
    expect(AuditLog.countDocuments).not.toHaveBeenCalled();
  });

  test('库内命中数大于分析条数时标记 truncated（不冒充看全了）', async () => {
    const maxedRows = Array.from({ length: MAX_PROFILE_ROWS }, (_, i) =>
      row({ _id: `rec-${i}`, timestamp: at(i) })
    );
    mockQuery(maxedRows);
    AuditLog.countDocuments.mockResolvedValue(MAX_PROFILE_ROWS + 1);

    const result = await buildAttackProfile({ ip: '203.0.113.9', now: BASE });
    expect(result.ok).toBe(true);
    expect(result.total).toBe(MAX_PROFILE_ROWS + 1);
    expect(result.analyzed).toBe(MAX_PROFILE_ROWS);
    expect(result.truncated).toBe(true);
    expect(AuditLog.countDocuments).toHaveBeenCalledTimes(1);
  });
});

describe('attackProfile 时间窗解析', () => {
  test('缺省 7 天；越界夹到 [1h, 720h]；坏值回落默认', () => {
    const now = BASE;
    expect(resolveWindow(undefined, now).hours).toBe(168);
    expect(resolveWindow('', now).hours).toBe(168);
    expect(resolveWindow('abc', now).hours).toBe(168);
    expect(resolveWindow(0, now).hours).toBe(1);
    expect(resolveWindow(-5, now).hours).toBe(1);
    expect(resolveWindow(9999, now).hours).toBe(720);
    expect(resolveWindow(24, now).since).toEqual(at(-24 * 60));
    expect(resolveWindow(24, now).until).toEqual(now);
  });
});
