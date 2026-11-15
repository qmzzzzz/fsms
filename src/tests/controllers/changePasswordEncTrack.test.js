/**
 * S5 改密密文轨分支补齐（controllers/securityController/account.js 的 changePasswordSecure）
 *
 * 并行开发为 /api/security/change-password 增加了与 /api/auth/password 同口径的
 * ECDH 信封密文轨（encCurrentPassword / encNewPassword），新增分支未测导致
 * securityController branches 跌破棘轮基线（91%）。本套件经真实 HTTP +
 * 真实 WebCrypto 信封（buildLoginEnvelope 镜像前端流程）覆盖：
 *   - 当前口令密文无效 → AUTH_ENCRYPTED_CREDENTIAL_INVALID
 *   - 新口令密文无效 → 同上
 *   - 密文轨下明文 confirmPassword 与解密结果不一致 → 400
 *   - 全密文轨成功改密（confirmPassword 缺省以解密结果为准）
 *
 * 注意 passwordChangeLimiter 为 5 次/15 分钟（userId+IP 组合键），各用户各自计数。
 * P3-23：此前前三条用例共享同一账号的预算（3/5 已用），与第四条存在隐式顺序耦合；
 * 现改为**每条用例独立账号**（makeAccount），预算互不串用，任意顺序都成立。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { buildLoginEnvelope, randomPassword } = require('../helpers/buildLoginEnvelope');

describe('S5 改密密文轨（/api/security/change-password）', () => {
  let app;
  let User;
  const PASSWORD = randomPassword();
  const NEW_PASSWORD = randomPassword();
  const stamp = `ec${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  /** 每条用例自建专属账号并自行签发令牌：凭据状态（口令/tokenVersion）是账号私有的，
   * 改密又是破坏性操作——共享账号会让用例间产生隐式顺序依赖与限流预算串用（P3-23）。 */
  const makeAccount = async (suffix) => {
    const u = await User.create({
      username: `${stamp}${suffix}`,
      email: `${stamp}${suffix}@example.com`,
      password: PASSWORD,
    });
    const tk = jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    return { u, tk };
  };

  const putWith = (tk, body) =>
    request(app)
      .put('/api/security/change-password')
      .set('Authorization', `Bearer ${tk}`)
      .send(body);

  test('encCurrentPassword 密文无效 → 400 AUTH_ENCRYPTED_CREDENTIAL_INVALID', async () => {
    const { tk } = await makeAccount('t1');
    const garbage = await buildLoginEnvelope('', { raw: { v: 999, x: 'a', y: 'b' } });
    const res = await putWith(tk, { encCurrentPassword: garbage, encNewPassword: 'whatever' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('encNewPassword 密文无效 → 400 AUTH_ENCRYPTED_CREDENTIAL_INVALID', async () => {
    const { tk } = await makeAccount('t2');
    const goodCurrent = await buildLoginEnvelope(PASSWORD, { aad: 'password:current' });
    const garbage = await buildLoginEnvelope('', { raw: { v: 1, x: 'not-a-key' } });
    const res = await putWith(tk, { encCurrentPassword: goodCurrent, encNewPassword: garbage });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('密文轨下明文 confirmPassword 与解密结果不一致 → 400', async () => {
    const { tk } = await makeAccount('t3');
    const goodCurrent = await buildLoginEnvelope(PASSWORD, { aad: 'password:current' });
    const goodNew = await buildLoginEnvelope(NEW_PASSWORD, { aad: 'password:new' });
    const res = await putWith(tk, {
      encCurrentPassword: goodCurrent,
      encNewPassword: goodNew,
      confirmPassword: 'TotallyDifferent1!x',
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('不一致');
  });

  test('全密文轨成功改密（confirmPassword 缺省以解密结果为准）', async () => {
    // 改密是**破坏性**操作：口令被永久改掉、tokenVersion 递增，
    // 该账号此前签发的令牌全部作废——本用例同样使用专属账号。
    const { u: chgUser, tk: chgToken } = await makeAccount('chg');

    const goodCurrent = await buildLoginEnvelope(PASSWORD, { aad: 'password:current' });
    const goodNew = await buildLoginEnvelope(NEW_PASSWORD, { aad: 'password:new' });
    const res = await putWith(chgToken, {
      encCurrentPassword: goodCurrent,
      encNewPassword: goodNew,
    });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const after = await User.findById(chgUser._id).select('+password +tokenVersion');
    expect(await after.comparePassword(NEW_PASSWORD)).toBe(true);
    // 改密后全部会话被吊销（与明文轨同口径）
    expect(after.tokenVersion).toBe(1);

    // 吊销的真实性：改密前的令牌必须立刻不可用（只断 tokenVersion 字段等于信任内部实现，
    // 打一次受保护接口才能证明「旧会话确实被踢掉」这个对外承诺成立）
    const reuseOld = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${chgToken}`);
    expect(reuseOld.status).toBe(401);
  });
});
