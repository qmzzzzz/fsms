/**
 * 二次验证与改密必须是两个独立的限流桶
 *
 * /api/security/view-sensitive 做凭据校验（当前密码或 TOTP），与其余凭据端点同强度
 * 是对的；但它当时**复用了 passwordChangeLimiter**——同一个
 * `pwd-change:${userId}:${ip}` 键、同一个 5 次/15 分钟窗口。于是：
 *   ① 用户连续查看 5 次本人手机号/邮箱（正常操作）→ PUT /change-password 被 429，
 *      而 429 文案还写着"密码修改操作过于频繁"，用户与运维都看不出根因；
 *   ② 攻击者刷改密接口，同样能把受害者的二次验证配额耗光。
 * 这恰好违反了 rateLimit.js 给改密限流器自己写的注释：
 * "与 loginLimiter 分开计数，避免 X 配额与 Y 配额互相污染"。
 *
 * 本文件钉的是**隔离性**（不是阈值）：两个桶各自耗尽时，另一边必须照常放行。
 * 全部用"错误凭据"驱动：限流判定在凭据校验之前，所以既不改变账户状态，
 * 又能真实消耗配额 → 用例之间互不依赖（随机顺序门禁下也不会互相污染）。
 */
const request = require('supertest');
const mongoose = require('mongoose');
const {
  passwordChangeLimiter,
  reauthLimiter,
  passwordChangeUserLimiter,
  reauthUserLimiter,
} = require('../middleware/rateLimit');

describe('二次验证限流与改密限流互不污染', () => {
  let app;
  let User;
  let user;
  let token;
  const PASSWORD = 'Rb6#Kp21wQz8';
  const WRONG = 'Wrong#Cred00001';
  // supertest 在本机可能落任意一种回环形态，三把键都清才算真的清零
  const IPS = ['::ffff:127.0.0.1', '127.0.0.1', '::1'];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const jwt = require('jsonwebtoken');
    User = require('../models/User');
    user = await User.create({
      username: 'bucket',
      email: 'bucket@example.com',
      password: PASSWORD,
    });
    token = jwt.sign(
      { userId: String(user._id), username: 'bucket', tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    // 每个凭据端点现在是两把桶并列（组合键含可伪造的 req.ip + 纯 userId 兜底），
    // 只清一把 = 本文件要防的"配额互相污染"换了个位置重演。
    for (const ip of IPS) {
      await reauthLimiter.resetKey(`reauth:${String(user._id)}:${ip}`);
      await passwordChangeLimiter.resetKey(`pwd-change:${String(user._id)}:${ip}`);
    }
    await reauthUserLimiter.resetKey(`reauth-user:${String(user._id)}`);
    await passwordChangeUserLimiter.resetKey(`pwd-change-user:${String(user._id)}`);
  });

  const stepUp = () =>
    request(app)
      .post('/api/security/view-sensitive')
      .set('Authorization', `Bearer ${token}`)
      .send({ dataType: 'phone', currentPassword: WRONG });

  const changePassword = () =>
    request(app)
      .put('/api/auth/password')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: WRONG, newPassword: 'Nw4#Yt88mKz2' });

  test('二次验证自身仍然受限：第 6 次命中 429 且文案指向二次验证', async () => {
    const codes = [];
    const bodies = [];
    for (let i = 0; i < 6; i++) {
      const res = await stepUp();
      codes.push(res.status);
      bodies.push(res.body && res.body.message);
    }
    // 前 5 次是"凭据不对"，不是"太频繁"
    expect(codes.slice(0, 5).every((c) => c !== 429)).toBe(true);
    expect(codes[5]).toBe(429);
    expect(bodies[5]).toContain('二次验证');
    // 反向保护：文案不得再指向改密（否则用户按文案去等改密冷却，根因被藏住）
    expect(bodies[5]).not.toContain('密码修改');
  });

  test('耗尽二次验证配额后，改密接口照常处理（不得 429）', async () => {
    for (let i = 0; i < 8; i++) {
      await stepUp();
    }
    const res = await changePassword();
    expect(res.status).not.toBe(429);
    // 必须仍然走到凭据校验：错口令 → 4xx，但不是"太频繁"
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  test('反向：耗尽改密配额后，二次验证接口照常处理（不得 429）', async () => {
    for (let i = 0; i < 8; i++) {
      await changePassword();
    }
    const res = await stepUp();
    expect(res.status).not.toBe(429);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });
});
