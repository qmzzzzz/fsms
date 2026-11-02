'use strict';

/**
 * IP 攻击画像派生层的单元测试（2026-11-02 审计补盲）
 *
 * 画像的取数层（services/attackProfile.js）依赖 Mongo，但判定与聚合是纯函数：
 * 同一批审计行必须得到同一分类/评分/建议。这里钉住三件最容易被后续改动悄悄改坏的事：
 * ① 分类优先级与显式排除（黑名单命中是处置结果，不是行为分类）；
 * ② 「失败后成功」的升级门槛与蜜罐会话的排除；
 * ③ 证据窗口与时间线桶的口径（首尾保留、24/48 小时切换小时桶与天桶）。
 */

const { summarizeRows } = require('../../services/attackProfileSummary');
const { categoryOf, severityOf } = require('../../services/attackProfileClassify');
const { ATTACK_CATEGORIES: C, VERDICTS, SUGGESTIONS } = require('../../constants/attackProfile');

const BASE = new Date('2026-01-01T00:00:00Z');
const at = (minutes) => new Date(BASE.getTime() + minutes * 60 * 1000);

const row = (overrides = {}) => ({
  timestamp: at(0),
  action: 'login_failed',
  category: 'auth',
  method: 'POST',
  path: '/api/auth/login',
  statusCode: 401,
  success: false,
  username: 'alice',
  userAgent: 'jest-agent',
  refusalReason: null,
  riskLevel: null,
  ...overrides,
});

const run = (rows, overrides = {}) =>
  summarizeRows({
    ip: '203.0.113.9',
    rows,
    total: rows.length,
    truncated: false,
    window: { hours: 24, since: new Date(BASE.getTime() - 3600e3), until: BASE },
    containment: { degraded: false, blacklisted: false, whitelisted: false, entries: [] },
    scopeLimited: false,
    ...overrides,
  });

const failure = (minutes, username = 'alice') => row({ timestamp: at(minutes), username });

describe('attack profile 判定层：分类优先级', () => {
  test('诱捕动作优先于凭据攻击；黑名单命中显式不分类', () => {
    expect(categoryOf(row({ action: 'honeypot_login' }), C.BRUTE_FORCE)).toBe(C.HONEYPOT);
    expect(
      categoryOf(row({ action: 'ip_blacklist_blocked', statusCode: 403 }), C.BRUTE_FORCE)
    ).toBe(null);
  });

  test('动作未命中时按路径兜底：扫描器指纹 / 注入指纹 / 越权拒绝原因', () => {
    expect(categoryOf(row({ action: null, path: '/.env', statusCode: 404 }), C.BRUTE_FORCE)).toBe(
      C.PATH_SCANNING
    );
    expect(
      categoryOf(
        row({ action: null, path: '/api/a/../../etc/passwd', statusCode: 404 }),
        C.BRUTE_FORCE
      )
    ).toBe(C.INJECTION_PROBE);
    expect(
      categoryOf(
        row({
          action: null,
          path: '/api/users',
          statusCode: 403,
          refusalReason: 'PERMISSION_DENIED',
        }),
        C.BRUTE_FORCE
      )
    ).toBe(C.UNAUTHORIZED_ACCESS);
  });

  test('登录入口的 401 不算越权（密码不对不是提权尝试）', () => {
    expect(
      categoryOf(
        row({
          action: null,
          path: '/api/auth/login',
          statusCode: 401,
          refusalReason: 'UNAUTHORIZED',
        }),
        C.BRUTE_FORCE
      )
    ).toBeNull();
  });

  test('严重度随阈值变化：暴力破解次数 / 扫描条数 / 导出成功', () => {
    expect(severityOf(C.BRUTE_FORCE, { count: 9 }, 9)).toBe('medium');
    expect(severityOf(C.BRUTE_FORCE, { count: 9 }, 10)).toBe('high');
    expect(severityOf(C.PATH_SCANNING, { count: 1 }, 0)).toBe('low');
    expect(severityOf(C.PATH_SCANNING, { count: 3 }, 0)).toBe('medium');
    expect(severityOf(C.DATA_EXFILTRATION, { count: 1, successCount: 1 }, 0)).toBe('high');
    expect(severityOf(C.HONEYPOT, { count: 1, successCount: 0 }, 0)).toBe('critical');
  });
});

describe('attack profile 聚合层：分类与结论', () => {
  test('空输入：no_data、零分、无建议', () => {
    const result = run([]);
    expect(result.verdict).toBe(VERDICTS.NO_DATA);
    expect(result.score).toBe(0);
    expect(result.categories).toEqual([]);
    expect(result.uncategorized).toEqual({ count: 0, evidence: [] });
    expect(result.suggestions).toEqual([]);
    expect(result.stats.peakBucketRequests).toBe(0);
    expect(result.stats.peakBucketStart).toBeNull();
  });

  test('同一账号 5 次失败：暴力破解，不到升级门槛时只给监控建议', () => {
    const result = run(Array.from({ length: 5 }, (_, i) => failure(i)));
    expect(result.categories).toHaveLength(1);
    expect(result.categories[0]).toMatchObject({
      code: C.BRUTE_FORCE,
      count: 5,
      severity: 'medium',
    });
    expect(result.verdict).toBe(VERDICTS.LOW);
    expect(result.suggestions).toEqual([SUGGESTIONS.MONITOR]);
  });

  test('4 个不同账号各失败一次：凭据撞库（high）并给出封禁/复核建议', () => {
    const result = run(['a', 'b', 'c', 'd'].map((name, i) => failure(i, name)));
    expect(result.categories[0]).toMatchObject({
      code: C.CREDENTIAL_STUFFING,
      severity: 'high',
    });
    expect(result.stats.distinctAccountsTried).toBe(4);
    expect(result.verdict).toBe(VERDICTS.ATTACK);
    expect(result.suggestions).toEqual(
      expect.arrayContaining([
        SUGGESTIONS.MONITOR,
        SUGGESTIONS.ENABLE_MFA,
        SUGGESTIONS.REVIEW_ACCOUNTS,
        SUGGESTIONS.BLOCK_IP,
      ])
    );
  });

  test('失败 10 次后再成功：判 compromised，并给出改密/复核建议', () => {
    const rows = Array.from({ length: 11 }, (_, i) => failure(i));
    rows.push(row({ timestamp: at(30), action: 'login_success', success: true, statusCode: 200 }));
    const result = run(rows);
    expect(result.stats.failedLogins).toBe(11);
    expect(result.stats.successAfterFailure).toBe(true);
    expect(result.stats.suspiciousSuccessAt).toEqual(at(30));
    expect(result.verdict).toBe(VERDICTS.COMPROMISED);
    expect(result.riskLevel).toBe('critical');
    expect(result.suggestions).toEqual(
      expect.arrayContaining([
        SUGGESTIONS.RESET_CREDENTIALS,
        SUGGESTIONS.REVIEW_ACCOUNTS,
        SUGGESTIONS.ENABLE_MFA,
      ])
    );
  });

  test('蜜罐会话的 login_success 不算真实突破，不参与升级判据', () => {
    const rows = Array.from({ length: 11 }, (_, i) => failure(i));
    rows.push(
      row({ timestamp: at(30), action: 'login_success', success: true, username: 'sysadmin' })
    );
    const result = run(rows);
    expect(result.stats.successfulLogins).toBe(1);
    expect(result.stats.successAfterFailure).toBe(false);
    expect(result.verdict).not.toBe(VERDICTS.COMPROMISED);
  });

  test('已封禁的攻击源不重复建议封禁；受限数据范围追加 verify_scope', () => {
    const rows = ['a', 'b', 'c'].map((name, i) => failure(i, name));
    const result = run(rows, {
      containment: { degraded: false, blacklisted: true, whitelisted: false, entries: [] },
      scopeLimited: true,
    });
    expect(result.suggestions).not.toContain(SUGGESTIONS.BLOCK_IP);
    expect(result.suggestions).toContain(SUGGESTIONS.VERIFY_SCOPE);
  });

  test('名单查询降级时 containment 明确标注 degraded（不伪装成“未封禁”）', () => {
    const result = run([failure(0)], { containment: undefined });
    expect(result.containment).toEqual({
      degraded: true,
      blacklisted: false,
      whitelisted: false,
      entries: [],
    });
  });
});

describe('attack profile 聚合层：证据与时间线', () => {
  test('证据窗口首尾各留一半，总长不超过上限', () => {
    const rows = Array.from({ length: 20 }, (_, i) => failure(i));
    const result = run(rows);
    const evidence = result.categories[0].evidence;
    expect(evidence).toHaveLength(8);
    expect(evidence[0].timestamp).toEqual(at(0));
    expect(evidence[evidence.length - 1].timestamp).toEqual(at(19));
  });

  test('未分类行进入 uncategorized 证据：黑名单处置不被当成分类，也不从画像里消失', () => {
    const rows = [
      row({ _id: 'u1', timestamp: at(0), action: 'ip_blacklist_blocked', statusCode: 403 }),
      row({
        _id: 'u2',
        timestamp: at(1),
        action: 'user_delete',
        success: true,
        statusCode: 200,
        riskLevel: 'low',
      }),
      row({ _id: 'u3', timestamp: at(2) }),
    ];
    const result = run(rows);
    expect(result.categories).toHaveLength(1);
    expect(result.categories[0].code).toBe(C.BRUTE_FORCE);
    expect(result.uncategorized.count).toBe(2);
    expect(result.uncategorized.evidence.map((item) => item.logId)).toEqual(['u1', 'u2']);
    expect(result.uncategorized.evidence.map((item) => item.action)).toEqual([
      'ip_blacklist_blocked',
      'user_delete',
    ]);
  });

  test('未分类证据首尾各留一半，总长不超过上限', () => {
    const rows = Array.from({ length: 20 }, (_, i) =>
      row({
        _id: `u${i}`,
        timestamp: at(i),
        action: 'ip_blacklist_blocked',
        statusCode: 403,
      })
    );
    const result = run(rows);
    expect(result.uncategorized.count).toBe(20);
    expect(result.uncategorized.evidence).toHaveLength(8);
    expect(result.uncategorized.evidence[0].logId).toBe('u0');
    expect(result.uncategorized.evidence[7].logId).toBe('u19');
  });

  test('证据行带记录定位键 logId，缺 _id 时为 null（不伪造定位）', () => {
    const result = run([row({ _id: 'c1' }), row({ timestamp: at(1), username: 'bob' })]);
    const evidence = result.categories[0].evidence;
    expect(evidence.map((item) => item.logId)).toEqual(['c1', null]);
  });

  test('≤48 小时用小时桶，>48 小时用天桶；桶内只记出现过的分类', () => {
    const rows = [failure(0), failure(1560)]; // 0h 与 26h
    const hourly = run(rows, { window: { hours: 24, since: at(-60), until: at(1560) } });
    expect(hourly.timeline.unit).toBe('hour');
    expect(hourly.timeline.buckets).toHaveLength(2);
    expect(hourly.timeline.buckets[0].categories).toEqual([C.BRUTE_FORCE]);

    const daily = run(rows, { window: { hours: 72, since: at(-60), until: at(1560) } });
    expect(daily.timeline.unit).toBe('day');
    expect(daily.timeline.buckets).toHaveLength(2);
    expect(daily.timeline.buckets[1].total).toBe(1);
  });

  test('峰值请求按当前桶宽统计，空窗口不伪造时间点', () => {
    const rows = [failure(0), failure(1), failure(2), failure(1560)];
    const daily = run(rows, { window: { hours: 72, since: at(-60), until: at(1560) } });
    expect(daily.stats.peakBucketRequests).toBe(3);
    expect(typeof daily.stats.peakBucketStart).toBe('string');
    expect(run([]).stats.peakBucketStart).toBeNull();
  });
});

describe('attack profile 建议层：针对性复核', () => {
  test('越权与限流命中时追加对应复核建议', () => {
    const rows = [
      row({
        timestamp: at(0),
        action: 'permission_abuse',
        path: '/api/users',
        statusCode: 403,
        refusalReason: 'PERMISSION_DENIED',
      }),
      row({ timestamp: at(1), action: 'rate_limit_abuse', statusCode: 429 }),
    ];
    const result = run(rows);
    expect(result.verdict).toBe(VERDICTS.SUSPICIOUS);
    expect(result.suggestions).toEqual(
      expect.arrayContaining([SUGGESTIONS.REVIEW_ACCESS_CONTROL, SUGGESTIONS.REVIEW_RATE_LIMITS])
    );
  });
});
