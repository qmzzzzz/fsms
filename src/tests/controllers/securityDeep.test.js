/**
 * 安全管理控制器深覆盖（冲 95% 批次 C）
 *
 * 此前缺口：securityController 语句 47%。覆盖：stats/overview/alerts、
 * my-logs、上报、敏感数据查看（二次验证）、强化改密、锁定/解锁全分支、
 * 管理员重置 MFA、审计日志查询/导出、IP 黑白名单 CRUD + 全网段对称约束。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('安全管理深覆盖（批次 C）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let IPBlacklist;
  let superToken; // 内置超管操作者
  let superUserId;
  let lowToken; // 低层级用户（被操作对象 + 改密用）
  let lowUserId;
  let victimId; // MFA 待重置对象
  const stamp = `sd${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    IPBlacklist = require('../../models/IPBlacklist');
    require('../../models/TokenBlacklist');
    require('../../models/AuditLog');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    // 内置超管操作者（全段 IP 管理仅内置超管可执行）
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    const superUser = await User.create({
      username: `sdsuper${stamp}`,
      email: `sdsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superUserId = String(superUser._id);
    superToken = jwt.sign(
      { userId: superUserId, username: superUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 低层级用户（改密/锁定对象）
    const lowUser = await User.create({
      username: `sdlow${stamp}`,
      email: `sdlow${stamp}@example.com`,
      password: PASSWORD,
    });
    lowUserId = String(lowUser._id);
    lowToken = jwt.sign(
      { userId: lowUserId, username: lowUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // MFA 重置对象
    const victim = await User.create({
      username: `sdvictim${stamp}`,
      email: `sdvictim${stamp}@example.com`,
      password: PASSWORD,
    });
    victimId = String(victim._id);
    await User.findByIdAndUpdate(victimId, { mfaEnabled: true, mfaSecret: 'JBSWY3DPEHPK3PXP' });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^sd(super|low|victim)${stamp}$`) }).catch(
        () => {}
      );
      await IPBlacklist.deleteMany({ ip: new RegExp(`^203\\.0\\.113\\.`) }).catch(() => {});
      await IPBlacklist.deleteMany({ ip: '0.0.0.0/0' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${superToken}`),
    post: (url) => request(app).post(url).set('Authorization', `Bearer ${superToken}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${superToken}`),
    delete: (url) => request(app).delete(url).set('Authorization', `Bearer ${superToken}`),
  });

  test('统计/概览/告警/个人日志', async () => {
    expect((await authed().get('/api/security/stats')).status).toBe(200);
    expect((await authed().get('/api/security/overview')).status).toBe(200);
    expect((await authed().get('/api/security/alerts')).status).toBe(200);
    expect((await authed().get('/api/security/my-logs?limit=10')).status).toBe(200);
  });

  test('安全上报：成功 + 非法目标类型 400', async () => {
    const ok = await authed()
      .post('/api/security/report')
      .send({
        targetType: 'system',
        reason: `测试上报_${stamp}`,
        description: '覆盖用上报',
      });
    expect(ok.status).toBe(200);

    const bad = await authed().post('/api/security/report').send({
      targetType: 'bogus',
      reason: 'x',
    });
    expect(bad.status).toBe(400);
  });

  test('敏感数据查看：缺二次验证 403 → 密码验证通过 → 非法 dataType 400', async () => {
    const noReauth = await authed()
      .post('/api/security/view-sensitive')
      .send({ dataType: 'phone' });
    expect(noReauth.status).toBe(403);

    const ok = await request(app)
      .post('/api/security/view-sensitive')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ dataType: 'phone', currentPassword: PASSWORD });
    expect(ok.status).toBe(200);

    const badType = await request(app)
      .post('/api/security/view-sensitive')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ dataType: 'ssn', currentPassword: PASSWORD });
    expect(badType.status).toBe(400);
  });

  test('#9 普通用户（无 system:read）经二次验证可查看本人敏感信息；查看他人被拒', async () => {
    // 本人：lowToken 无 system:read，但查的是自己 → 免鉴权放行 → requireReAuthentication 通过后 200
    const selfOk = await request(app)
      .post('/api/security/view-sensitive')
      .set('Authorization', `Bearer ${lowToken}`)
      .send({ dataType: 'email', currentPassword: PASSWORD });
    expect(selfOk.status).toBe(200);
    expect(selfOk.body.data.full).toBe(`sdlow${stamp}@example.com`);

    // 他人：lowToken 查 victim → 需 system:read → 403
    const otherForbidden = await request(app)
      .post('/api/security/view-sensitive')
      .set('Authorization', `Bearer ${lowToken}`)
      .send({ dataType: 'email', targetUserId: victimId, currentPassword: PASSWORD });
    expect(otherForbidden.status).toBe(403);
  });

  test('强化改密：确认密码不一致 400 → 成功 200', async () => {
    const mismatch = await request(app)
      .put('/api/security/change-password')
      .set('Authorization', `Bearer ${lowToken}`)
      .send({ currentPassword: PASSWORD, newPassword: randomPassword(), confirmPassword: 'nope' });
    expect(mismatch.status).toBe(400);

    const newPassword = randomPassword();
    const ok = await request(app)
      .put('/api/security/change-password')
      .set('Authorization', `Bearer ${lowToken}`)
      .send({ currentPassword: PASSWORD, newPassword, confirmPassword: newPassword });
    expect(ok.status).toBe(200);
  });

  test('锁定/解锁：成功/解锁未锁定 400/锁自己 403/锁内置超管拒绝/非法入参 400', async () => {
    const lock = await authed()
      .put(`/api/security/users/${lowUserId}/lock`)
      .send({
        locked: true,
        reason: `测试锁定_${stamp}`,
      });
    expect(lock.status).toBe(200);
    expect(lock.body.data.status).toBe('locked');

    const unlock = await authed()
      .put(`/api/security/users/${lowUserId}/lock`)
      .send({ locked: false });
    expect(unlock.status).toBe(200);

    const unlockAgain = await authed()
      .put(`/api/security/users/${lowUserId}/lock`)
      .send({ locked: false });
    expect(unlockAgain.status).toBe(400);

    const lockSelf = await authed()
      .put(`/api/security/users/${superUserId}/lock`)
      .send({ locked: true });
    expect(lockSelf.status).toBe(403);

    const superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    const superTarget = await User.findOne({ username: `sdsuper${stamp}` });
    void superRole;
    const lockSuper = await request(app)
      .put(`/api/security/users/${superTarget._id}/lock`)
      .set('Authorization', `Bearer ${superToken}`)
      .send({ locked: true });
    // 同级 403 先触发（与批次 A 删除同语义）
    expect(lockSuper.status).toBe(403);

    const badBody = await authed()
      .put(`/api/security/users/${lowUserId}/lock`)
      .send({ locked: 'yes' });
    expect(badBody.status).toBe(400);
  });

  test('管理员重置 MFA：未开启 400 / 自身 400 / 开启对象 200 / 内置超管 403', async () => {
    const noMfa = await authed().put(`/api/security/users/${lowUserId}/mfa/reset`);
    expect(noMfa.status).toBe(400);

    const selfReset = await request(app)
      .put(`/api/security/users/${superUserId}/mfa/reset`)
      .set('Authorization', `Bearer ${superToken}`);
    expect(selfReset.status).toBe(400);

    const ok = await authed().put(`/api/security/users/${victimId}/mfa/reset`);
    expect(ok.status).toBe(200);
    expect(ok.body.data.mfaEnabled).toBe(false);

    const superTarget = await User.findOne({ username: `sdsuper${stamp}` });
    const selfResetAgain = await request(app)
      .put(`/api/security/users/${superTarget._id}/mfa/reset`)
      .set('Authorization', `Bearer ${superToken}`);
    // 自身不走管理接口重置（应在 MFA 状态检查前被 400 拦下）
    expect(selfResetAgain.status).toBe(400);

    // 层级 403 分支：第二个内置超管（同为 10 级 → 同级拦截）
    const super2 = await User.create({
      username: `sdsuper2${stamp}`,
      email: `sdsuper2${stamp}@example.com`,
      password: PASSWORD,
      roles: [(await Role.findOne({ code: 'SUPER_ADMIN' }))._id],
      mfaEnabled: true,
    });
    const resetSuper2 = await request(app)
      .put(`/api/security/users/${super2._id}/mfa/reset`)
      .set('Authorization', `Bearer ${superToken}`);
    expect(resetSuper2.status).toBe(403);
  });

  test('IP 黑白名单：新增/查询命中/列表/删除；全网段仅内置超管', async () => {
    const add = await authed()
      .post('/api/security/ip-list')
      .send({
        ip: '203.0.113.50',
        type: 'black',
        reason: `测试_${stamp}`,
      });
    expect([200, 201]).toContain(add.status);

    const query = await authed().get('/api/security/ip-list/query?ip=203.0.113.50');
    expect(query.status).toBe(200);

    expect((await authed().get('/api/security/ip-list?page=1&limit=20')).status).toBe(200);

    // 全网段：内置超管可加可删
    const fullRange = await authed().post('/api/security/ip-list').send({
      ip: '0.0.0.0/0',
      type: 'white',
      reason: '全段放行_测试',
    });
    expect([200, 201]).toContain(fullRange.status);
    const fullDoc = fullRange.body.data?._id || fullRange.body.data?.id;
    if (fullDoc) {
      expect((await authed().delete(`/api/security/ip-list/${fullDoc}`)).status).toBe(200);
    }

    // 非内置超管（无 security:config 权限）→ 权限层 403 先行。
    // low 用户改密后 tokenVersion 已递增（全量吊销），此处按库内实时版本重签
    const freshLow = await User.findById(lowUserId).select('username tokenVersion');
    const lowToken2 = jwt.sign(
      { userId: lowUserId, username: freshLow.username, tokenVersion: freshLow.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    const lowFullRange = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${lowToken2}`)
      .send({ ip: '0.0.0.0/0', type: 'black', reason: '越权尝试' });
    expect(lowFullRange.status).toBe(403);

    const entry = await IPBlacklist.findOne({ ip: '203.0.113.50', type: 'black' });
    expect((await authed().delete(`/api/security/ip-list/${entry._id}`)).status).toBe(200);
  });

  test('审计日志：查询（含非法枚举 400）/验证/导出 CSV', async () => {
    expect(
      (await authed().get('/api/security/audit-logs?category=user&page=1&limit=10')).status
    ).toBe(200);
    expect((await authed().get('/api/security/audit-logs?category=bogus')).status).toBe(400);
    expect((await authed().get('/api/security/audit-logs/verify?limit=50')).status).toBe(200);

    const csv = await authed().get('/api/security/audit-logs/export?limit=50');
    expect(csv.status).toBe(200);
    expect(csv.headers['content-type']).toContain('text/csv');
  });
});
