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
 * 阈值本身不在此钉死——用例动态探测到首个 429 即认为桶已打穿，耗尽点由被测
 * 实现自己给出，改阈值不会误伤本文件。
 * 全部用"错误凭据"驱动：限流判定在凭据校验之前，所以既不改变账户状态，
 * 又能真实消耗配额 → 用例之间互不依赖（随机顺序门禁下也不会互相污染）。
 */
const request = require('supertest');
const mongoose = require('mongoose');

// 捕获被测实现真实使用的限流 store 实例：beforeEach 直接对桶整体 resetAll，
// 不再手工枚举回环 IP 形态（supertest 落在哪种回环形态、键格式将来怎么变，
// 都以实现自己的 store 为准——这才是与被测实现同源的清零路径）。
const mockStores = [];
jest.mock('../middleware/rateLimitStore', () => {
  const actual = jest.requireActual('../middleware/rateLimitStore');
  return {
    __esModule: true,
    makeSharedStore: (...args) => {
      const store = actual.makeSharedStore(...args);
      mockStores.push({ prefix: args[0], store });
      return store;
    },
  };
});

describe('二次验证限流与改密限流互不污染', () => {
  let app;
  let User;
  let user;
  let token;
  const PASSWORD = 'Rb6#Kp21wQz8';
  const WRONG = 'Wrong#Cred00001';
  // 本文件涉及的四个桶：两个「userId:ip」组合键桶 + 两个纯 userId 账号桶
  const BUCKET_PREFIXES = new Set(['reauth', 'pwd-change', 'reauth-user', 'pwd-change-user']);
  // 阈值探测上限：只起安全网作用（桶失效时避免无限循环），不是阈值断言
  const PROBE_CAP = 50;

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
    // 直接对实现真实使用的 store 实例整体清零，键空间覆盖与实现同源。
    for (const { prefix, store } of mockStores) {
      if (BUCKET_PREFIXES.has(prefix) && store && typeof store.resetAll === 'function') {
        await store.resetAll();
      }
    }
    // 限流桶之外还有一把**跨用例**的凭据失败锁：错误口令会让 recordMfaFailure
    // 写 mfaFailCount，5 次后置 mfaLockUntil。不清它，下一条用例的 429 可能来自
    // 凭据锁定而不是限流桶——本文件要断言的隔离性就失去区分力。
    await User.updateOne(
      { _id: user._id },
      { $set: { mfaFailCount: 0, mfaLockUntil: null, failedLoginCount: 0, lockUntil: null } }
    );
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

  /** 连续打到首个 429 为止（带安全网上限）；返回首个 429 的序号与响应 */
  const hitLimit = async (fn) => {
    for (let i = 0; i < PROBE_CAP; i += 1) {
      const res = await fn();
      if (res.status === 429) return { index: i, res };
    }
    return { index: -1, res: null };
  };

  test('二次验证自身仍然受限：连续命中后 429 且文案指向二次验证', async () => {
    const { index, res } = await hitLimit(stepUp);
    // 桶必须真的存在并生效：探测上限内必须见到 429。
    // 首问不得立即 429（否则凭据校验语义被限流吞掉）；具体第几次打穿不在此钉死。
    expect(index).toBeGreaterThanOrEqual(1);
    expect(res.body.message).toContain('二次验证');
    // 反向保护：文案不得再指向改密（否则用户按文案去等改密冷却，根因被藏住）
    expect(res.body.message).not.toContain('密码修改');
  });

  test('耗尽二次验证配额后，改密接口照常处理（不得 429）', async () => {
    // 前提自证：二次验证桶确实被打穿了，下面的"改密不受影响"才构成隔离性证据
    const { index } = await hitLimit(stepUp);
    expect(index).toBeGreaterThanOrEqual(0);
    const res = await changePassword();
    expect(res.status).not.toBe(429);
    // 必须仍然走到凭据校验：错口令 → 4xx，但不是"太频繁"
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  test('反向：耗尽改密配额后，二次验证接口照常处理（不得 429）', async () => {
    const { index } = await hitLimit(changePassword);
    expect(index).toBeGreaterThanOrEqual(0);
    const res = await stepUp();
    expect(res.status).not.toBe(429);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });
});
