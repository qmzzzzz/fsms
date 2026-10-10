'use strict';

/**
 * `POST /api/security/view-sensitive`：dataType 白名单必须先于二次验证
 *
 * 路由里那条 `body('dataType').isIn([...])` 挂在 `requireReAuthentication()` **之后**，
 * 而校验结果只由控制器在链尾读 ⇒ 填错 dataType 的请求会先把步进验证走完：
 *  · 口令错 ⇒ `mfaService.recordMfaFailure` 给本人 `mfaFailCount +1`（阈值 5，
 *    计数器与锁定窗口和**登录**共用）；
 *  · 口令对 ⇒ `mfaLastCounter` 被推进，这个时间窗的码随后不能再用（含登录）；
 *  · 走密码分支 ⇒ 白白做一次 bcrypt 比对。
 * 一个"注定 400"的请求不应产生任何凭据侧副作用。修法：把校验链挪到步进验证之前，
 * 并就地 `consumeValidation()` —— 对外的错误码不变（仍是控制器给的 VALIDATION_FAILED）。
 *
 * 四条用例两两配对：两条证明"坏参数不再烧凭据"，两条证明"步进验证本身仍然有效"
 * （否则前两条会因为"所有请求都被挡下"而假绿）。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `vso${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();
// decryptMfaSecret 对存量明文原样透传，故这里可直接放一份 base32 密钥（与 securityDeep 同法）
const MFA_SECRET = 'JBSWY3DPEHPK3PXP';
const WRONG_CODE = '111111';

describe('view-sensitive：坏 dataType 不得产生凭据侧副作用', () => {
  let app;
  let User;
  const tokens = {};

  const view = (who, body) =>
    request(app)
      .post('/api/security/view-sensitive')
      .set('Authorization', `Bearer ${tokens[who]}`)
      .send(body);

  const failCount = async (who) => {
    const u = await User.findOne({ username: who }).select('+mfaFailCount +mfaLastCounter').lean();
    return { mfaFailCount: u?.mfaFailCount ?? 0, mfaLastCounter: u?.mfaLastCounter ?? null };
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    require('../../models/Role');
    require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const mk = async (name) => {
      const u = await User.create({
        username: name,
        email: `${name}@example.com`,
        password: PASSWORD,
      });
      await User.findByIdAndUpdate(u._id, { mfaEnabled: true, mfaSecret: MFA_SECRET });
      tokens[name] = jwt.sign(
        { userId: String(u._id), username: name, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      return name;
    };
    await mk(`${stamp}_a`);
    await mk(`${stamp}_b`);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('dataType 非法 + 动态口令错 ⇒ 400 VALIDATION_FAILED，且失败计数不加', async () => {
    const who = `${stamp}_a`;
    const before = await failCount(who);
    expect(before.mfaFailCount).toBe(0);

    const res = await view(who, { dataType: 'salary', mfaCode: WRONG_CODE });

    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    const after = await failCount(who);
    expect(after.mfaFailCount).toBe(0);
  });

  test('dataType 非法 + 密码错 ⇒ 400 VALIDATION_FAILED（不得先答 REAUTH_PASSWORD_INCORRECT）', async () => {
    // 顺序判据最锋利的一条：步进验证若先跑，密码分支会先返回 REAUTH_PASSWORD_INCORRECT，
    // 客户端就永远看不到"你 dataType 填错了"。
    const who = `${stamp}_a`;
    const res = await view(who, { dataType: 'salary', currentPassword: `${PASSWORD}-wrong` });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
  });

  test('前提：dataType 合法 + 动态口令错 ⇒ 步进验证仍然生效并计入失败', async () => {
    const who = `${stamp}_b`;
    const before = await failCount(who);
    expect(before.mfaFailCount).toBe(0);

    const res = await view(who, { dataType: 'phone', mfaCode: WRONG_CODE });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('REAUTH_MFA_INCORRECT');
    expect((await failCount(who)).mfaFailCount).toBe(1);
  });

  test('前提：dataType 合法 + 不带任何凭据 ⇒ REAUTH_REQUIRED（白名单没把闸拆掉）', async () => {
    const res = await view(`${stamp}_b`, { dataType: 'phone' });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('REAUTH_REQUIRED');
  });
});
