/**
 * Audit query boundary regression tests.
 *
 * These guards are shared by query, export, and integrity verification.
 */

const { buildAuditQuery } = require('../../utils/auditQuery');

const requestWithQuery = (query) => ({ query });

/**
 * E-05 回归：审计查询的筛选条件必须与导出共用同一份实现
 *
 * 背景：services/auditQueryService.js 曾内联维护第二份 buildAuditQuery，
 * 两份已经漂移——本地副本的 date-only 边界走服务器本地时区
 * （`new Date(`${d}T00:00:00`)`），共享实现走业务时区（parseDateBoundary）。
 * 后果：UTC 容器下「查询」与「导出」对同一天的边界相差 8 小时，
 * 东八区当天 0-8 点的记录在查询侧被静默漏掉，且没有任何报错。
 *
 * 本用例做两件事：
 *   1. 源码级断言全仓只有一处 buildAuditQuery 定义（防再次分叉）；
 *   2. 行为级断言 date-only 边界落在业务时区，不随 runner 本地时区漂移。
 */
describe('E-05：审计查询与导出共用同一 buildAuditQuery（防口径分叉）', () => {
  test('全仓仅 utils/auditQuery.js 定义 buildAuditQuery', () => {
    const fs = require('fs');
    const path = require('path');
    const SRC = path.join(__dirname, '../../');
    const collect = (dir, acc = []) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) {
          if (e.name === 'tests' || e.name === 'node_modules') continue;
          collect(path.join(dir, e.name), acc);
        } else if (e.name.endsWith('.js')) acc.push(path.join(dir, e.name));
      }
      return acc;
    };
    const defs = [];
    for (const f of collect(SRC)) {
      const src = fs.readFileSync(f, 'utf8');
      // 只认「函数定义」：const buildAuditQuery = ( 或 function buildAuditQuery(
      if (/const\s+buildAuditQuery\s*=|function\s+buildAuditQuery\s*\(/.test(src)) {
        defs.push(path.relative(SRC, f).replace(/\\/g, '/'));
      }
    }
    expect(defs).toEqual(['utils/auditQuery.js']);
  });

  test('date-only 边界落业务时区，且与 TZ 环境变量无关', () => {
    const original = process.env.TZ;
    process.env.TZ = 'UTC'; // 模拟 UTC 容器
    try {
      // 清缓存以确保 parseDateBoundary 内的时区解析重新求值
      jest.resetModules();
      const { buildAuditQuery: fresh } = require('../../utils/auditQuery');
      const { query } = fresh(requestWithQuery({ startDate: '2026-09-15', endDate: '2026-09-15' }));
      // 东八区 2026-09-15 00:00:00 == UTC 2026-09-14T16:00:00Z
      expect(query.timestamp.$gte.toISOString()).toBe('2026-09-14T16:00:00.000Z');
      // 结束边界为业务时区当天最后一毫秒
      expect(query.timestamp.$lte.toISOString()).toBe('2026-09-15T15:59:59.999Z');
    } finally {
      if (original === undefined) delete process.env.TZ;
      else process.env.TZ = original;
      jest.resetModules();
    }
  });
});

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
