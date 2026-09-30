/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：utils/auditQuery.buildAuditQuery 及其调用方
 * 守护的不变式：查询 / 导出 / 完整性校验必须共用同一份 buildAuditQuery（不得内联第二份）
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `auditQueryBoundary.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * Audit query boundary regression tests.
 *
 * These guards are shared by query, export, and integrity verification.
 */

const mongoose = require('mongoose');
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
    // userId 必须是 ObjectId 实例而不是原样字符串：这份 filter 既走 find/countDocuments
    // （ODM 会补 cast）也走 aggregate（不 cast ⇒ 字符串永远匹配不到 ObjectId 字段，
    // 于是聚合静默返回 0 条而列表照常出数据，管理员视角一切正常）。
    expect(query.userId).toBeInstanceOf(mongoose.Types.ObjectId);
    expect(String(query.userId)).toBe('000000000000000000000001');
    // Top-8 前半（2026-09-28）：username 由「不锚定 + $options:'i' 的 $regex」改为
    // 「前缀 + collation 范围查询」。特殊字符因此不再需要转义——范围比较天然免疫正则注入
    // （附带收益：原实现靠 escapeRegExp 防注入，改后这个注入面直接不存在了）。
    // 上界 = 追加 collation 最高哨兵 U+FFFF（永久未分配码位，隐式权重高于一切已分配字符）。
    // 2026-09-30 修正：本断言此前仍钉着被 d72872c 废掉的「末字符码点 +1」——'alice(.*'
    // 的 `*`(0x2A) → `+`(0x2B)——那是 ICU 排序下的**空区间**形态（标点权重排在字母之前，
    // `alice(.+` < `alice(.*`），与该提交修复的正是同一类缺陷。此处只钉形状（哨兵在末尾），
    // 哨兵在 collation 下确实恒大于任何 `prefix + <已分配字符>` 由
    // auditUsernamePrefixIndex.test.js 的 DB 回归用例负责。
    expect(query.username).toEqual({ $gte: 'alice(.*', $lt: 'alice(.*\uFFFF' });
    expect(query.action).toBe('auth_login');
    expect(query.category).toBe('auth');
    expect(query.riskLevel).toBe('high');
    expect(query.success).toBe(true);
    expect(query.$and).toEqual([{ success: true, riskLevel: 'medium' }]);
  });
});
