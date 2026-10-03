/**
 * 审计 riskLevel 汇总的 TTL 缓存（2026-09-26 审计 Top-8 后半：每页全量聚合）
 *
 * 缺陷原文：「username regex 全表扫 + **每页全量聚合**」（原报告的行号早已失效，这里改引
 * **当前**的聚合站点 `auditQueryService.js:136`），修复面「加索引 / 加 TTL 缓存」。
 *
 * 为什么当初只修后半：汇总 `$group` **与页码无关**（只依赖 query），却被写在两个
 * 取页函数里各一份 ⇒ 翻 N 页就为同一谓词重算 N 次全量聚合。这是纯粹的重复计算，
 * 缓存它不改变任何语义。
 *
 * 2026-09-28 更新：**前半也已修**（Top-8 前半，经拍板）。username 由「不锚定 +
 * `$options:'i'` 的 `$regex`」改为「前缀 + collation 范围查询」，并补齐
 * `username_ci_timestamp` 索引——`$regex` 不感知 collation，保留 `i` 时"只改成前缀"
 * 实测收益为零（实测记录见 `utils/auditQuery.js`）。当初不做的另一条理由
 * （`auditScopeFilter` 会**覆盖** `query.userId`）依然成立且被尊重：本次**没有**把
 * username 翻译成 `userId:{$in:[...]}`，只改了 username 自身的匹配形态。
 *
 * 本文件钉四件事：
 *   ① 命中：同一 query 的多次取页只算一次聚合（缺陷本体）；
 *   ② 隔离：不同 query 绝不共享结果（缓存最危险的失效方向是"张冠李戴"）；
 *   ③ 时效：TTL 到期后必须重算（不能退化成"进程生命周期内只算一次"）；
 *   ④ 降级：键构造失败/过长时不缓存，但结果必须仍然正确。
 */

'use strict';

const path = require('path');
const fs = require('fs');

const AuditLog = require('../../models/AuditLog');
const statsCache = require('../../services/statsCache');
const { summarizeByRiskLevel, summaryCacheKey } = require('../../services/auditQueryService');

const ROOT = path.resolve(__dirname, '../../..');

/** 清掉本模块产生的全部缓存条目（statsCache 是共享底座，不能整表清空） */
const clearAuditCache = () => {
  for (const key of [...statsCache._store.keys()]) {
    if (key.startsWith('audit:risk-summary:')) statsCache._store.delete(key);
  }
};

/** 把某个键的过期时间拨到过去，用于验证 TTL 语义（比 fake timers 稳：不牵扯异步 DB） */
const expireKey = (prefix) => {
  for (const [key, entry] of statsCache._store) {
    if (key.startsWith(prefix)) entry.expireAt = Date.now() - 1;
  }
};

describe('Top-8 汇总缓存：同一 query 的多页只算一次', () => {
  let aggSpy;

  beforeEach(() => {
    clearAuditCache();
    aggSpy = jest.spyOn(AuditLog, 'aggregate').mockResolvedValue([{ _id: 'high', count: 2 }]);
  });

  afterEach(() => {
    jest.restoreAllMocks();
    clearAuditCache();
  });

  test('同一 query 连续取两页 → 聚合只执行一次（缺陷本体）', async () => {
    const q = { riskLevel: 'high', timestamp: { $gte: new Date('2026-09-01') } };
    expect(await summarizeByRiskLevel(q)).toEqual([{ _id: 'high', count: 2 }]);
    expect(await summarizeByRiskLevel({ ...q })).toEqual([{ _id: 'high', count: 2 }]);
    expect(aggSpy).toHaveBeenCalledTimes(1);
  });

  test('键序无关：同一条件换个书写顺序仍命中同一缓存（不许把命中与否交给键序）', async () => {
    await summarizeByRiskLevel({ riskLevel: 'high', action: 'login' });
    await summarizeByRiskLevel({ action: 'login', riskLevel: 'high' });
    expect(aggSpy).toHaveBeenCalledTimes(1);
  });

  test('不同 query 绝不共享结果（缓存最危险的失效方向是张冠李戴）', async () => {
    await summarizeByRiskLevel({ riskLevel: 'high' });
    await summarizeByRiskLevel({ riskLevel: 'low' });
    expect(aggSpy).toHaveBeenCalledTimes(2);
    // 键确实不同（而不是"第二次恰好没命中"这种侥幸）
    expect(summaryCacheKey({ riskLevel: 'high' })).not.toBe(summaryCacheKey({ riskLevel: 'low' }));
  });

  test('TTL 到期后重算（不得退化成进程生命周期内只算一次）', async () => {
    const q = { riskLevel: 'medium' };
    await summarizeByRiskLevel(q);
    await summarizeByRiskLevel(q);
    expect(aggSpy).toHaveBeenCalledTimes(1);

    expireKey('audit:risk-summary:');
    await summarizeByRiskLevel(q);
    expect(aggSpy).toHaveBeenCalledTimes(2);
  });

  test('缓存未命中时结果与不带缓存完全一致（降级方向不能是"返回空"）', async () => {
    aggSpy.mockResolvedValue([]);
    expect(await summarizeByRiskLevel({ riskLevel: 'critical' })).toEqual([]);
  });

  test('前提自证：聚合真的被调用了（否则上面几条的"只调用一次"是空集假绿）', async () => {
    await summarizeByRiskLevel({ riskLevel: 'high' });
    expect(aggSpy).toHaveBeenCalledTimes(1);
    const pipeline = aggSpy.mock.calls[0][0];
    expect(JSON.stringify(pipeline)).toContain('$group');
    expect(JSON.stringify(pipeline)).toContain('$riskLevel');
  });
});

describe('Top-8 汇总缓存：键的边界', () => {
  beforeEach(() => clearAuditCache());
  afterEach(() => {
    jest.restoreAllMocks();
    clearAuditCache();
  });

  test('超长键（department 档展开出的长 $in）不缓存，但结果照常返回', async () => {
    // 用内存换一次查询是亏的；但不缓存**绝不能**影响正确性。
    const spy = jest.spyOn(AuditLog, 'aggregate').mockResolvedValue([{ _id: 'low', count: 1 }]);
    const huge = { userId: { $in: Array.from({ length: 400 }, (_, i) => `u${i}`) } };
    expect(summaryCacheKey(huge)).toBeNull();
    expect(await summarizeByRiskLevel(huge)).toEqual([{ _id: 'low', count: 1 }]);
    expect(await summarizeByRiskLevel(huge)).toEqual([{ _id: 'low', count: 1 }]);
    // 没缓存 ⇒ 两次都真算（而不是"缓存了但键超长被静默丢弃"）
    expect(spy).toHaveBeenCalledTimes(2);
  });

  test('ObjectId / Date 参与键构造时不抛错且可区分', () => {
    const mongoose = require('mongoose');
    const a = summaryCacheKey({ userId: new mongoose.Types.ObjectId('64b7f0c2a1b2c3d4e5f60718') });
    const b = summaryCacheKey({ userId: new mongoose.Types.ObjectId('64b7f0c2a1b2c3d4e5f60719') });
    expect(typeof a).toBe('string');
    expect(a).not.toBe(b);
    expect(summaryCacheKey({ timestamp: { $gte: new Date('2026-09-01') } })).toContain(
      '2026-09-01'
    );
  });
});

describe('Top-8 写法门禁：聚合口径只有一处', () => {
  const src = fs
    .readFileSync(path.join(ROOT, 'src/services/auditQueryService.js'), 'utf8')
    .split('\n')
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');

  test('两个取页函数都走 summarizeByRiskLevel，且全文件只剩一处 riskLevel $group', () => {
    // 判据是"重复计算不许复辟"：把汇总再抄回取页函数里（原实现就是两份），
    // 本用例会红——而只测 summarizeByRiskLevel 的用例对此毫无感知。
    const calls = src.match(/summarizeByRiskLevel\(query, collation\)/g) || [];
    expect(calls.length).toBe(2);
    const inline = src.match(/\$group:\s*\{\s*_id:\s*'\$riskLevel'/g) || [];
    expect(inline.length).toBe(1);
    // 且那唯一一处必须在 summarizeByRiskLevel 之内（不在取页函数里）
    expect(src.indexOf("_id: '$riskLevel'")).toBeGreaterThan(
      src.indexOf('const summarizeByRiskLevel')
    );
    expect(src).toContain('const summarizeByRiskLevel');
  });
});
