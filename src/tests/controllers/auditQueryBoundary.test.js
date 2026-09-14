/**
 * Audit query boundary regression tests.
 *
 * These guards are shared by query, export, and integrity verification.
 */

const { buildAuditQuery } = require('../../utils/auditQuery');

const requestWithQuery = (query) => ({ query });

describe('buildAuditQuery boundaries', () => {
  test('rejects invalid start and end dates', () => {
    expect(() => buildAuditQuery(requestWithQuery({ startDate: 'not-a-date' }))).toThrow(
      '开始日期格式错误'
    );
    expect(() => buildAuditQuery(requestWithQuery({ endDate: 'not-a-date' }))).toThrow(
      '结束日期格式错误'
    );
  });

  test('rejects invalid enum values', () => {
    expect(() => buildAuditQuery(requestWithQuery({ action: 'not-an-action' }))).toThrow('action');
    expect(() => buildAuditQuery(requestWithQuery({ category: 'not-a-category' }))).toThrow(
      'category'
    );
    expect(() => buildAuditQuery(requestWithQuery({ riskLevel: 'extreme' }))).toThrow('riskLevel');
    expect(() => buildAuditQuery(requestWithQuery({ level: 'debug' }))).toThrow('level');
  });

  test('rejects invalid user ID and IP', () => {
    expect(() => buildAuditQuery(requestWithQuery({ userId: 'bad-object-id' }))).toThrow('userId');
    expect(() => buildAuditQuery(requestWithQuery({ ip: 'not-an-ip' }))).toThrow('ip');
  });

  test('builds exact filters from valid params', () => {
    const { query } = buildAuditQuery(
      requestWithQuery({
        startDate: '2026-09-01',
        endDate: '2026-09-02',
        userId: '000000000000000000000001',
        username: 'alice(.*',
        action: 'auth_login',
        category: 'auth',
        ip: '192.168.1.1',
        riskLevel: 'high',
        success: 'true',
        level: 'warning',
      })
    );

    // date-only 边界走业务时区口径（评价报告 #12）；期望值内嵌 +08:00，
    // 不随 runner 本地时区漂移（UTC CI 实证：无后缀写法在 UTC 下差 8 小时）
    expect(query.timestamp.$gte.getTime()).toBe(
      new Date('2026-09-01T00:00:00.000+08:00').getTime()
    );
    expect(query.timestamp.$lte.getMilliseconds()).toBe(999);
    expect(query.userId).toBe('000000000000000000000001');
    expect(query.username.$regex).toBe('alice\\(\\.\\*');
    expect(query.username.$options).toBe('i');
    expect(query.action).toBe('auth_login');
    expect(query.category).toBe('auth');
    expect(query.riskLevel).toBe('high');
    expect(query.success).toBe(true);
    expect(query.$and).toEqual([{ success: true, riskLevel: 'medium' }]);
  });
});
