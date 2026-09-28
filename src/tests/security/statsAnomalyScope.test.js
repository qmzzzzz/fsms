'use strict';

/**
 * GET /api/security/stats 的"异常行为"两路聚合必须按操作者数据范围收口
 *
 * 缺陷本体：`getSecurityStats`（securityController.js:284）里
 * 今日登录数 / 今日失败数 / 高危操作数是**全局聚合**（是否随范围收窄属另一条口径，
 * 本用例不管），但 `AuditLog.detectAnomalies()` 是 `$group:{_id:'$userId'}`
 * ——返回体里就是"哪些用户在一小时内失败了 ≥5 次"，是**行级**信息的聚合出口。
 * 同权限码下的 /security/alerts 已经收口，这个出口没收：
 * 部门档安全管理员（SECURITY_ADMIN 是 level 8 ⇒ department 档）由此拿到全系统
 * 其他人的 userId + 失败次数，等于把审计页的收口绕开。
 *
 * 判据分工（缺一条就留有假绿空间）：
 * 1. 泄漏判据：部门 A 的安全管理员不得在 failedOperationUsers 里看到部门 B 的用户；
 * 2. 反向对照：all 档必须两条都看到，否则"聚合一律返回空"也能让 1 变绿；
 * 3. 同源判据：同一操作者下，接口见到的 userId = 参照实现（applyAuditDataScope + 同一阈值）
 *    见到的 userId，防止"另起一套范围口径"；
 * 4. 部门档却没有部门 ⇒ 必须空（与 auditScopeFilter.js:45-53 的 deny 口径同向）；
 * 5. 静态方法默认不收口：`detectAnomalies()` 不带 scopeFilter 仍看全库——
 *    auditMonitor 定时任务必须对任意部门的用户都报警，不能被这次改动顺带削弱。
 *
 * 只断言 failedOperationUsers：unusualTimeOperations 的判据是"业务时区的非工作时段"，
 * 结果集随用例运行时刻漂移，拿它做断言会变成一条时好时坏的假判据。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const stamp = `zst${Date.now()}`.slice(-12);
const PASSWORD = 'Zz!pTg7mKq9xLd4nBv2Rf8sY';
const DEPT_A = `ZZST-A-${stamp}`;
const DEPT_B = `ZZST-B-${stamp}`;
const ACTION = 'zz_stats_probe';
// 与控制器一致：windowMinutes 60 / threshold 5
const SEED_COUNT = 6;

const mkUser = async (User, name, extra = {}) =>
  User.create({
    username: `${name}${stamp}`,
    email: `${name}${stamp}@example.com`,
    password: PASSWORD,
    ...extra,
  });

const tokenFor = (user) =>
  jwt.sign(
    { userId: String(user._id), username: user.username, tokenVersion: 0 },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

describe('GET /security/stats 的异常行为聚合按数据范围收口', () => {
  let app;
  let User;
  let AuditLog;
  let allToken;
  let deptAToken;
  let noDeptToken;
  let subjA;
  let subjB;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

    const upsertPerm = (code, module) =>
      Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { name: code, code, type: 'api', module } },
        { upsert: true, new: true }
      );
    const wildcard = await upsertPerm('*:*', 'system');
    const statsPerm = await upsertPerm('security:stats', 'security');

    const superRole = await Role.create({
      name: `全档${stamp}`,
      code: `ZZSTSUPER${stamp}`,
      level: 10,
      permissions: [wildcard._id],
    });
    const secRole = await Role.create({
      name: `部门安全档${stamp}`,
      code: `ZZSTSEC${stamp}`,
      level: 8,
      permissions: [statsPerm._id],
    });

    const root = await mkUser(User, 'stroot', { roles: [superRole._id] });
    const secA = await mkUser(User, 'stseca', { roles: [secRole._id], department: DEPT_A });
    const secNone = await mkUser(User, 'stsecn', { roles: [secRole._id] });
    subjA = await mkUser(User, 'stsubj_a', { department: DEPT_A });
    subjB = await mkUser(User, 'stsubj_b', { department: DEPT_B });

    allToken = tokenFor(root);
    deptAToken = tokenFor(secA);
    noDeptToken = tokenFor(secNone);

    // 两个部门的主体各造 6 条失败：阈值 5 ⇒ 不带收口时两条都会出现在返回体里
    const now = new Date();
    const rows = [];
    for (const subj of [subjA, subjB]) {
      for (let i = 0; i < SEED_COUNT; i++) {
        rows.push({
          action: ACTION,
          category: 'auth',
          username: subj.username,
          userId: subj._id,
          ip: `203.0.113.${subj === subjA ? 21 : 22}`,
          success: false,
          timestamp: now,
        });
      }
    }
    await AuditLog.insertMany(rows);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await AuditLog.deleteMany({ action: ACTION }, { bypassAppendOnly: true }).catch(() => {});
      await User.deleteMany({ username: new RegExp(`^st.*${stamp}$`) }).catch(() => {});
      const Role = require('../../models/Role');
      const Permission = require('../../models/Permission');
      await Role.deleteMany({ code: new RegExp(`^ZZST(SUPER|SEC)${stamp}$`) }).catch(() => {});
      await Permission.deleteMany({ code: 'security:stats' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const failedUsers = async (token) => {
    const res = await request(app)
      .get('/api/security/stats')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    // 控制器 ApiResponse.success(res, {overview, anomalies, securityLevel})
    // ⇒ 数据在 body.data 一层（不像 /alerts 那样再套一层 data）；
    // 这里写死形状，不做"多种可能形状都试一遍"的兜底。
    const list = res.body.data.anomalies.failedOperationUsers;
    expect(Array.isArray(list)).toBe(true);
    const probe = [String(subjA._id), String(subjB._id)];
    // 排序后才返回：本用例钉的是"见到哪些 userId"（集合），不是接口的排序。
    // $group 的返回顺序在内存版 mongod 上不保证与插入序一致（实测同一用例
    // 两次全量跑给出相反顺序），把它当断言会变成一条时好时坏的假判据。
    // 接口自身的排序（次数降序）不在本文件的判据范围内。
    return list
      .map((r) => String(r._id))
      .filter((id) => probe.includes(id))
      .sort();
  };

  /** 参照实现：与 /audit-logs 同一个翻译器 + 同一阈值 */
  const referenceUsers = async (operatorId) => {
    const { applyAuditDataScope } = require('../../services/auditScopeFilter');
    const { query } = await applyAuditDataScope({ action: ACTION, success: false }, operatorId);
    const grouped = await AuditLog.aggregate([
      { $match: query },
      { $group: { _id: '$userId', count: { $sum: 1 } } },
      { $match: { count: { $gte: 5 } } },
    ]);
    return grouped.map((r) => String(r._id)).sort();
  };

  test('1 泄漏判据：部门 A 的安全管理员看不到部门 B 用户的失败次数', async () => {
    const seen = await failedUsers(deptAToken);
    expect(seen).toContain(String(subjA._id));
    expect(seen).not.toContain(String(subjB._id));
  });

  test('2 反向对照：all 档两条都看得到（否则"一律返回空"也能让判据 1 变绿）', async () => {
    const rootId = String((await User.findOne({ username: `stroot${stamp}` }))._id);
    expect(await failedUsers(allToken)).toEqual([String(subjA._id), String(subjB._id)].sort());
    // 前提自证：操作者确实是 all 档，且参照实现在这一档也见到两条
    const { getDataScope } = require('../../middleware/rbac');
    expect((await getDataScope(rootId)).type).toBe('all');
    expect(await referenceUsers(rootId)).toEqual([String(subjA._id), String(subjB._id)].sort());
  });

  test('3 同源判据：接口见到的 userId = 参照实现见到的 userId', async () => {
    const secAId = String((await User.findOne({ username: `stseca${stamp}` }))._id);
    // 前提自证：该操作者确实是 department 档，否则"子集"断言是空话
    const { getDataScope } = require('../../middleware/rbac');
    expect((await getDataScope(secAId)).type).toBe('department');
    expect(await failedUsers(deptAToken)).toEqual(await referenceUsers(secAId));
  });

  test('4 部门档拿不到部门 ⇒ 一条都不给（deny 口径，不退化成"看全部"或"看自己"）', async () => {
    const op = await User.findOne({ username: `stsecn${stamp}` });
    const { getDataScope } = require('../../middleware/rbac');
    const scope = await getDataScope(String(op._id));
    expect(scope.type).toBe('department');
    expect(scope.department).toBeFalsy();
    expect(await referenceUsers(String(op._id))).toEqual([]);
    expect(await failedUsers(noDeptToken)).toEqual([]);
  });

  test('5 静态方法默认不收口：auditMonitor 仍必须看到全系统用户', async () => {
    const all = await AuditLog.detectAnomalies({ windowMinutes: 60, threshold: 5 });
    const ids = all.failedOperations.map((r) => String(r._id));
    expect(ids).toContain(String(subjA._id));
    expect(ids).toContain(String(subjB._id));
  });
});
