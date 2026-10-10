'use strict';

/**
 * GET /api/security/alerts 与 GET /api/security/audit-logs 的可见范围必须同源
 *
 * 缺陷本体：两个端点挂的是**同一个权限码** `security:audit`（routes/securityRoutes.js:235
 * 与 :276），但只有 /audit-logs 走了 `applyAuditDataScope`（auditQueryService.js:217）。
 * `/alerts` 直接 `AuditLog.find({riskLevel:{$in:['high','critical']}})`，不带任何范围条件，
 * 并把 username/ip/path/body 原样返回。
 * 而 initData 的口径是"level 决定数据范围：≥9 全部 / ≥7 本部门"，SECURITY_ADMIN 是 **level 8**
 * ⇒ 部门档。于是：把审计日志按部门收口的努力，被同一权限下的另一个出口整体绕过
 * ——与 reportController.js:213「越权出口封堵」当年处理的是同一类问题（report:export 曾可
 * 绕过 security:audit 全量导出审计）。
 *
 * 判据分工（缺一条就留有假绿空间）：
 * 1. 泄漏判据：部门 A 的安全管理员从 /alerts 里**不得**看到部门 B 的高危审计行；
 * 2. 同源判据：同一操作者下，/alerts 见到的 userId 集合必须是 /audit-logs 见到集合的子集
 *    （只断言"B 看不到"会放过"顺手把范围口径改成另一套"的修法）；
 * 3. 反向对照：all 档（SUPER_ADMIN）两条都必须看到，否则"一律返回空"也能让 1、2 全绿；
 * 4. 部门档却没有部门 ⇒ 必须一条看不到（与 auditScopeFilter.js:45-53 的 deny 口径同向），
 *    不能退化成"退而看自己的"或"干脆放行全部"；
 * 5. 服务层单不带操作者 ⇒ 不可见（fail-closed），带 all 档 ⇒ 可见。
 *
 * 副作用（已登记，属产品口径而非本用例能判定）：告警行里 attacker 产生的那些没有 userId，
 * 收口后部门档管理员看不到它们——这与 /audit-logs 今天的表现完全一致，
 * 因为本改动的定义就是"向已存在的那套口径收敛"。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const stamp = `zsa${Date.now()}`.slice(-12);
const PASSWORD = 'Zz!pTg7mKq9xLd4nBv2Rf8sY';
const DEPT_A = `ZZS-A-${stamp}`;
const DEPT_B = `ZZS-B-${stamp}`;

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
    {
      expiresIn: '24h',
    }
  );

describe('/security/alerts 的数据范围必须与 /security/audit-logs 同源', () => {
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
    const auditPerm = await upsertPerm('security:audit', 'security');

    let superRole = await Role.findOne({ code: `ZZSSUPER${stamp}` });
    if (!superRole) {
      superRole = await Role.create({
        name: `全档${stamp}`,
        code: `ZZSSUPER${stamp}`,
        level: 10,
        permissions: [wildcard._id],
      });
    }
    let secRole = await Role.findOne({ code: `ZZSSEC${stamp}` });
    if (!secRole) {
      secRole = await Role.create({
        name: `部门安全档${stamp}`,
        code: `ZZSSEC${stamp}`,
        level: 8,
        permissions: [auditPerm._id],
      });
    }

    const root = await mkUser(User, 'zsaroot', { roles: [superRole._id] });
    const secA = await mkUser(User, 'zsaseca', { roles: [secRole._id], department: DEPT_A });
    // 部门档但 department 取不到（未填/被清空）：必须落到 deny，而不是"看全部"或"看自己"
    const secNone = await mkUser(User, 'zsasecn', { roles: [secRole._id] });
    subjA = await mkUser(User, 'zsubj_a', { department: DEPT_A });
    subjB = await mkUser(User, 'zsubj_b', { department: DEPT_B });

    allToken = tokenFor(root);
    deptAToken = tokenFor(secA);
    noDeptToken = tokenFor(secNone);

    const now = new Date();
    await AuditLog.insertMany([
      {
        action: 'zz_alert_probe',
        category: 'security',
        riskLevel: 'critical',
        username: subjA.username,
        userId: subjA._id,
        ip: '203.0.113.11',
        success: false,
        timestamp: now,
      },
      {
        action: 'zz_alert_probe',
        category: 'security',
        riskLevel: 'critical',
        username: subjB.username,
        userId: subjB._id,
        ip: '203.0.113.12',
        success: false,
        timestamp: now,
      },
    ]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await AuditLog.deleteMany({ action: 'zz_alert_probe' }, { bypassAppendOnly: true }).catch(
        () => {}
      );
      await User.deleteMany({ username: new RegExp(`^zs.*${stamp}$`) }).catch(() => {});
      const Role = require('../../models/Role');
      const Permission = require('../../models/Permission');
      await Role.deleteMany({ code: new RegExp(`^ZZS(SUPER|SEC)${stamp}$`) }).catch(() => {});
      await Permission.deleteMany({ code: 'security:audit' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const get = (token, path) => request(app).get(path).set('Authorization', `Bearer ${token}`);
  /**
   * 观测面用 username：`getRecentAlerts` 的 select 白名单里没有 userId
   * （securityAlert.js:414-421），而范围过滤恰恰是按 userId 做的。
   * 断言 username 既能在 HTTP 侧认出"这是哪个部门的人"，也顺带钉住
   * "收口用的字段与出口可见字段不是一回事"这个事实。
   */
  const rowsOf = (body) => {
    // 控制器：ApiResponse.success(res, { data: [...], meta })（securityController.js:944-956）
    // ⇒ 响应体里是**双层 data**。这里写死这一层形状，不做"多种可能形状都试一遍"的兜底：
    // 兜底会把"接口返回体变了"和"范围没收口"两件事混成一条红。
    const list = body?.data?.data;
    expect(Array.isArray(list)).toBe(true);
    return list.map((r) => String(r.username ?? '')).filter(Boolean);
  };
  /** 参照实现：/audit-logs 走的就是这一个翻译器（auditQueryService.js:217） */
  const scopedProbeNames = async (operatorId) => {
    const { applyAuditDataScope } = require('../../services/auditScopeFilter');
    const { query } = await applyAuditDataScope({ action: 'zz_alert_probe' }, operatorId);
    const rows = await AuditLog.find(query).select('username').lean();
    return rows.map((r) => String(r.username)).sort();
  };
  const probeNames = () => [subjA.username, subjB.username];
  const onlyProbe = (list) => list.filter((n) => probeNames().includes(n));

  test('泄漏判据：部门 A 的安全管理员不得在 /alerts 里看到部门 B 的高危行', async () => {
    const res = await get(deptAToken, '/api/security/alerts');
    expect(res.status).toBe(200);
    const seen = rowsOf(res.body);
    expect(seen).toContain(subjA.username);
    expect(seen).not.toContain(subjB.username);
  });

  test('同源判据：/alerts 见到的探针行 = 参照实现见到的行（同一操作者）', async () => {
    const secAId = (await User.findOne({ username: `zsaseca${stamp}` }))._id.toString();
    const alerts = await get(deptAToken, '/api/security/alerts');
    expect([...new Set(onlyProbe(rowsOf(alerts.body)))].sort()).toEqual(
      await scopedProbeNames(secAId)
    );
  });

  test('反向对照：all 档两条都看得到（否则"一律返回空"也能让上面两条绿）', async () => {
    const res = await get(allToken, '/api/security/alerts');
    expect(res.status).toBe(200);
    const seen = rowsOf(res.body);
    expect(seen).toContain(subjA.username);
    expect(seen).toContain(subjB.username);
  });

  test('部门档拿不到部门 ⇒ 一条都不给（deny 口径，不退化成"看全部"或"看自己"）', async () => {
    // 前提自证：该操作者确实是 department 档、且自己的 department 是空的
    const op = await User.findOne({ username: `zsasecn${stamp}` });
    const { getDataScope } = require('../../middleware/rbac');
    const scope = await getDataScope(String(op._id));
    expect(scope.type).toBe('department');
    expect(scope.department).toBeFalsy();
    expect(await scopedProbeNames(String(op._id))).toEqual([]);

    const res = await get(noDeptToken, '/api/security/alerts');
    // 状态码与"零泄漏"两条都要无条件成立。原写法 `if (200) … else expect(404)`
    // 给了控制器一条逃逸口：把空列表改成 404 就能整条跳过 deny 口径判据还保持绿。
    expect(res.status).toBe(200);
    expect(onlyProbe(rowsOf(res.body))).toEqual([]);
  });

  test('服务层：不带操作者不可见，带 all 档操作者可见（fail-closed 在服务内收口）', async () => {
    const securityAlert = require('../../services/securityAlert');
    expect(await securityAlert.getRecentAlerts(50)).toEqual([]);
    const rootId = (await User.findOne({ username: `zsaroot${stamp}` }))._id.toString();
    const rows = await securityAlert.getRecentAlerts(50, rootId);
    expect(rows.map((r) => String(r.username))).toContain(subjB.username);
  });
});
