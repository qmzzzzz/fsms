/**
 * 审计查询条件必须对 find 与 aggregate 同时成立
 *
 * 缺陷（实测确认）：assembleQuery 把 `?userId=<24hex>` 原样留成字符串。同一个 query 对象
 * 在本仓被喂给两处：
 *   - `AuditLog.find(query)` / `countDocuments(query)` —— Mongoose 按 schema 自动 cast ⇒ 有结果；
 *   - `AuditLog.aggregate([{$match: query}, {$group: {$sum:1} by riskLevel}])` —— **不做 schema cast**
 *     ⇒ 字符串永远比不上 ObjectId 存储类型 ⇒ 分组全空。
 * 症状不是报错而是**自相矛盾的数字**：列表有行、meta.total>0，而 riskLevel 统计（critical/high…）
 * 全为 0；且只有带 ?userId= 的查询会这样（数据范围条件里 rbac 给的本来就是 ObjectId），
 * 不带该参数一切正常 ⇒ 线上极难被发现，用户只会认为统计功能是坏的。
 * 判据来源与本仓既有裁定一致：utils/scopeCast.js 的头注释（同一坑在三个服务里各踩过一遍）。
 *
 * 可证伪性：把 query.userId 改回 `= userId`（不 cast）⇒ 两条用例都红；
 * 把 cast 做过头（例如连 username 的正则字符串也 cast）⇒ 第三条用例红。
 */

'use strict';

const mongoose = require('mongoose');
const AuditLog = require('../../models/AuditLog');
const { buildAuditQuery } = require('../../utils/auditQuery');

const TAG = `aqc${Date.now().toString(36)}`;
const USER_A = new mongoose.Types.ObjectId();
const USER_B = new mongoose.Types.ObjectId();

const mkDoc = (userId, riskLevel, action) => ({
  action,
  category: 'user',
  username: `${TAG}u`,
  userId,
  ip: '10.9.9.9',
  method: 'POST',
  path: '/api/users',
  success: true,
  riskLevel,
});

describe('审计 query 条件在 find 与 aggregate 两条路径上同尺', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // 用 create/insertMany 这条"正常写入"路径造数：bulkWrite 会进 append-only 钩子
    // （models/auditLogHooks.js 在 test 环境下拒绝它），而本文件要测的是查询条件，不是链
    await AuditLog.insertMany([
      mkDoc(USER_A, 'critical', `${TAG}_a`),
      mkDoc(USER_A, 'high', `${TAG}_b`),
      mkDoc(USER_B, 'low', `${TAG}_c`),
    ]);
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ username: `${TAG}u` }, { bypassAppendOnly: true });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('组装出的 userId 条件是 ObjectId 类型（这是 cast 缺失的直接判据）', () => {
    const { query } = buildAuditQuery({ query: { userId: String(USER_A) } });
    expect(query.userId instanceof mongoose.Types.ObjectId).toBe(true);
    expect(String(query.userId)).toBe(String(USER_A));
  });

  test('同一条件喂给 find/countDocuments 与 aggregate 必须给出一致计数（原缺陷：分项全空而 total>0）', async () => {
    const { query } = buildAuditQuery({ query: { userId: String(USER_A) } });

    const total = await AuditLog.countDocuments(query);
    const rows = await AuditLog.find(query).select('_id riskLevel');
    const grouped = await AuditLog.aggregate([
      { $match: query },
      { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
    ]);

    expect(total).toBe(2);
    expect(rows).toHaveLength(2);
    const byLevel = Object.fromEntries(grouped.map((g) => [g._id, g.count]));
    // 关键：分组求和必须等于总数，否则就是"total>0 而统计为空"的那个形态
    expect(Object.values(byLevel).reduce((a, b) => a + b, 0)).toBe(total);
    expect(byLevel).toEqual({ critical: 1, high: 1 });
  });

  test('cast 只落在 userId 上：username 是前缀范围条件而非正则（过度 cast 会把搜索打坏）', () => {
    const { query } = buildAuditQuery({ query: { userId: String(USER_A), username: `${TAG}u` } });
    expect(query.userId instanceof mongoose.Types.ObjectId).toBe(true);
    // Top-8 前半（2026-09-28）：username 由「不锚定 + $options:'i' 的 $regex」改为
    // 「前缀 + collation 范围查询」。两条都锁：不得退回正则（正则既用不上索引——
    // $regex 不感知 collation——不锚定又会把 `adm` 误命中 `damin`），
    // 也不得被 cast 成 ObjectId（这才是本用例原本要防的"过度 cast"）。
    // 上界追加 collation 哨兵 U+FFFF（永久未分配码位），不是「末字符码点 +1」——
    // 后者在 ICU 排序下对 z/Z/9 等末字符构成空区间（d72872c 修的正是它）。
    expect(query.username).toEqual({ $gte: `${TAG}u`, $lt: `${TAG}u\uFFFF` });
  });

  test('非 hex 的 userId 仍按既有契约被拒（cast 不得把校验变成静默兜底）', () => {
    expect(() => buildAuditQuery({ query: { userId: 'not-an-id' } })).toThrow(/userId/);
  });
});
