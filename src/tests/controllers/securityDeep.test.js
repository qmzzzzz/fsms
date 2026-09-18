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
  let lowToken; // 低层级用户（被操作对象）
  let lowUserId;
  let chgToken; // 改密专用用户
  let chgUserId;
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

    // 改密专用用户（顺序无关）：改密会写 passwordChangedAt 并递增 tokenVersion
    // （invalidateUserTokens 全量吊销）。若与 lowUser 共用账号，#10「强化改密」先跑时
    // #9「本人敏感信息查看」持有的 lowToken 会被连带吊销 → 401 假红。
    // 凭据状态属账号私有，改密用例自建账号，不向其他用例外溢。
    const chgUser = await User.create({
      username: `sdchg${stamp}`,
      email: `sdchg${stamp}@example.com`,
      password: PASSWORD,
    });
    chgUserId = String(chgUser._id);
    chgToken = jwt.sign(
      { userId: chgUserId, username: chgUser.username, tokenVersion: 0 },
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
      await User.deleteMany({ username: new RegExp(`^sd(super|low|victim|chg)${stamp}$`) }).catch(
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
    // 「非法目标类型」的判据是校验明细落在 targetType 上
    expect(bad.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(bad.body.errors.fieldErrors[0].path).toBe('targetType');
  });

  test('敏感数据查看：缺二次验证 403 → 密码验证通过 → 非法 dataType 400', async () => {
    const noReauth = await authed()
      .post('/api/security/view-sensitive')
      .send({ dataType: 'phone' });
    expect(noReauth.status).toBe(403);
    // 403 的语义是「需要二次验证」：前端据此弹密码/动态码输入框，
    // 换成别的 403（如权限不足）会让引导错向
    expect(noReauth.body.errors.errorCode).toBe('REAUTH_REQUIRED');

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
    expect(badType.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(badType.body.errors.fieldErrors[0].path).toBe('dataType');
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

  test('强化改密：确认密码不一致 400 → 成功 200 → 改密前的令牌被吊销', async () => {
    const mismatch = await request(app)
      .put('/api/security/change-password')
      .set('Authorization', `Bearer ${chgToken}`)
      .send({ currentPassword: PASSWORD, newPassword: randomPassword(), confirmPassword: 'nope' });
    expect(mismatch.status).toBe(400);
    // 不一致在路由层的 confirmPassword 校验就被判掉（不进入业务层）
    expect(mismatch.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(mismatch.body.errors.fieldErrors[0].path).toBe('confirmPassword');

    const newPassword = randomPassword();
    const ok = await request(app)
      .put('/api/security/change-password')
      .set('Authorization', `Bearer ${chgToken}`)
      .send({ currentPassword: PASSWORD, newPassword, confirmPassword: newPassword });
    expect(ok.status).toBe(200);

    // 改密的实质安全语义：旧凭据必须立刻失效（passwordChangedAt / tokenVersion 全量吊销），
    // 否则「改密挤掉攻击者会话」这一用户预期不成立。
    const reuseOldToken = await request(app)
      .get('/api/security/my-logs?limit=1')
      .set('Authorization', `Bearer ${chgToken}`);
    expect(reuseOldToken.status).toBe(401);
    expect(reuseOldToken.body.errors.errorCode).toBe('PASSWORD_CHANGED_RELOGIN');

    // 新口令可登录、旧口令不可登录（改密落库的真实性校验，避免只信响应码）
    const persisted = await User.findById(chgUserId).select('+password');
    expect(await persisted.comparePassword(newPassword)).toBe(true);
    expect(await persisted.comparePassword(PASSWORD)).toBe(false);
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
    // 解锁未锁定账户是独立契约（不是笼统的 400）：提示语与前端按钮态依赖它
    expect(unlockAgain.body.errors.errorCode).toBe('ACCOUNT_NOT_LOCKED');

    const lockSelf = await authed()
      .put(`/api/security/users/${superUserId}/lock`)
      .send({ locked: true });
    expect(lockSelf.status).toBe(403);
    // 「锁自己」命中的是超管保护（用户是内置超管），不是自锁专用码
    expect(lockSelf.body.errors.errorCode).toBe('CANNOT_LOCK_SUPER_ADMIN');

    const superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    const superTarget = await User.findOne({ username: `sdsuper${stamp}` });
    void superRole;
    const lockSuper = await request(app)
      .put(`/api/security/users/${superTarget._id}/lock`)
      .set('Authorization', `Bearer ${superToken}`)
      .send({ locked: true });
    // 同级 403 先触发（与批次 A 删除同语义）
    expect(lockSuper.status).toBe(403);
    expect(lockSuper.body.errors.errorCode).toBe('CANNOT_LOCK_SUPER_ADMIN');

    const badBody = await authed()
      .put(`/api/security/users/${lowUserId}/lock`)
      .send({ locked: 'yes' });
    expect(badBody.status).toBe(400);
    expect(badBody.body.errors.errorCode).toBe('VALIDATION_FAILED');
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
    // 实测 200（新增 IP 名单条目固定 200）
    expect(add.status).toBe(200);

    const query = await authed().get('/api/security/ip-list/query?ip=203.0.113.50');
    expect(query.status).toBe(200);

    expect((await authed().get('/api/security/ip-list?page=1&limit=20')).status).toBe(200);

    // 全网段：内置超管可加可删
    const fullRange = await authed().post('/api/security/ip-list').send({
      ip: '0.0.0.0/0',
      type: 'white',
      reason: '全段放行_测试',
    });
    // 实测 200（同上前置）
    expect(fullRange.status).toBe(200);
    const fullDoc = fullRange.body.data?._id || fullRange.body.data?.id;
    // 【静默跳过修正】原先删除断言包在 if (fullDoc) 里：拿不到 id 就整条不执行。
    // 实测响应体带 _id（=创建返回值），故先钉死 id 存在，再断删除成功。
    expect(fullDoc).toBeTruthy();
    expect((await authed().delete(`/api/security/ip-list/${fullDoc}`)).status).toBe(200);

    // 非内置超管（无 security:config 权限）→ 权限层 403 先行。
    // 按库内实时 tokenVersion 重签：不依赖「改密用例是否已跑过」的顺序前提
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
