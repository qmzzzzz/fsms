/**
 * 登录口令加密传输集成测试（密文轨端到端 + 双轨兼容）
 *
 * 覆盖：公钥下发、login 密文轨（正确/错误口令/重放/篡改）、
 * 明文兼容轨、register 密文轨、changePassword 双字段密文轨。
 * mfaDisable 的密文轨与 changePassword 走同一解密入口，不在本文件重复覆盖。
 *
 * 注意 loginLimiter 限 10 次/15min：本文件登录请求总数控制在 6 次以内。
 */

const request = require('supertest');
const mongoose = require('mongoose');
const {
  buildLoginEnvelope,
  randomPassword,
  generateEcKeyPem,
} = require('../helpers/buildLoginEnvelope');

describe('登录口令加密传输（密文轨）', () => {
  let app;
  let User;
  let SystemConfig;
  let loginCipher;
  const PASSWORD = randomPassword();
  const NEW_PASSWORD = randomPassword();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    require('../../models/Role');
    SystemConfig = require('../../models/SystemConfig');

    // 注入本文件专属 ECDH 密钥：隔离同 worker 其他测试文件可能的模块级残留状态
    loginCipher = require('../../utils/loginCipher');
    process.env.LOGIN_ECDH_PRIVATE_KEY = generateEcKeyPem().privateKey;
    loginCipher._resetForTests();

    // 打开公开注册开关（register 用例前置；缓存需显式失效）
    await SystemConfig.findOneAndUpdate(
      { key: 'allowPublicRegistration' },
      { $set: { key: 'allowPublicRegistration', value: true } },
      { upsert: true }
    );
    SystemConfig.invalidateRegistrationCache();

    // 注册图形验证码**默认开启**（src/config/index.js:72 顶层 registerCaptchaEnabled，
    // models/SystemConfig.js:207 的 fallback 也读顶层；全仓无任何地方设 REGISTER_CAPTCHA_ENABLED=false）。
    // 本文件的 register 用例测的是「密文轨 + 解密后补做的强度校验」，与验证码前置层无关：
    // 验证码若开着，弱口令与合规口令会**同样**被 400 拦在验证码层 ——
    // 那会让 :150 的 `weakRes.status===400` 退化成"被验证码拦下"的假绿，
    // 而 :158 的 `res.status===201` 直接转红。故此处显式落库关闭，让本文件只测它要测的那一层。
    // 注册验证码前置层本身的覆盖见 src/tests/controllers/authLifecycle.test.js（固定文本 mock，端到端）
    // 与 src/tests/security/systemConfigBooleanContract.test.js（默认值契约）。
    await SystemConfig.findOneAndUpdate(
      { key: 'registerCaptchaEnabled' },
      { $set: { key: 'registerCaptchaEnabled', value: false } },
      { upsert: true }
    );
    SystemConfig.invalidateRegisterCaptchaCache();

    await User.create({
      username: 'enclogin_user',
      email: 'enclogin@example.com',
      password: PASSWORD,
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    // 清理本文件注入的 ECDH 密钥，避免同 worker 后续文件读到残留值
    delete process.env.LOGIN_ECDH_PRIVATE_KEY;
    loginCipher._resetForTests();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('GET /api/auth/login-public-key 下发公钥', async () => {
    const res = await request(app).get('/api/auth/login-public-key');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.publicKey).toMatch(/BEGIN PUBLIC KEY/);
    expect(res.body.data.curve).toBe('P-256');
    expect(res.body.data.keyId).toMatch(/^[0-9a-f]{8}$/);
  });

  test('login 密文轨：正确口令登录成功', async () => {
    const encPassword = await buildLoginEnvelope(PASSWORD);
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'enclogin_user', encPassword });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.user.username).toBe('enclogin_user');
    expect(res.body.data.token).toBeTruthy();

    // 【顺序无关修复】原先把令牌存进模块级 userToken 供改密用例读取，形成隐式
    // 「本用例必须先跑」依赖；改密用例改为自建账号自行登录后本变量已无消费者。
    // 顺带把「令牌非空」升级为「令牌真能用」：签发的令牌若 tokenVersion/会话
    // 注册有误，truthy 断言照样通过，只有真正打一次受保护接口才暴露。
    const me = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${res.body.data.token}`);
    expect(me.status).toBe(200);
    // /auth/me 的用户对象嵌在 data.user（不是 data 本身），字段路径必须照实断
    expect(me.body.data.user.username).toBe('enclogin_user');
  });

  test('login 密文轨：错误口令返回与明文轨一致的 401（解密对后续流程透明）', async () => {
    const encPassword = await buildLoginEnvelope(randomPassword());
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'enclogin_user', encPassword });
    expect(res.status).toBe(401);
    expect(res.body.errors.errorCode).toBe('AUTH_INVALID_CREDENTIALS');
  });

  test('login 密文轨：重放同一信封被拒', async () => {
    const encPassword = await buildLoginEnvelope(PASSWORD);
    const first = await request(app)
      .post('/api/auth/login')
      .send({ username: 'enclogin_user', encPassword });
    expect(first.status).toBe(200);

    const replay = await request(app)
      .post('/api/auth/login')
      .send({ username: 'enclogin_user', encPassword });
    expect(replay.status).toBe(400);
    expect(replay.body.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('login 密文轨：篡改信封被拒', async () => {
    const envelope = await buildLoginEnvelope(PASSWORD);
    const inner = JSON.parse(Buffer.from(envelope, 'base64').toString('utf8'));
    inner.c = inner.c.slice(0, -4) + 'AAAA';
    const tampered = Buffer.from(JSON.stringify(inner), 'utf8').toString('base64');
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'enclogin_user', encPassword: tampered });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('login 明文兼容轨：灰度期继续可用', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'enclogin_user', password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('register 密文轨：注册成功且口令强度校验生效', async () => {
    const username = 'encreg_user';
    const email = 'encreg@example.com';
    // 强度不足的口令装信封 → 控制器解密后补做强度校验，应 400
    const weak = await buildLoginEnvelope('weak');
    const weakRes = await request(app)
      .post('/api/auth/register')
      .send({ username, email, encPassword: weak });
    expect(weakRes.status).toBe(400);

    // 合规口令装信封 → 201
    const regPassword = randomPassword();
    const encPassword = await buildLoginEnvelope(regPassword);
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username, email, encPassword });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);

    // 注册的口令应可登录（密文轨闭环）
    const loginEnc = await buildLoginEnvelope(regPassword);
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username, encPassword: loginEnc });
    expect(loginRes.status).toBe(200);
  });

  test('changePassword 双字段密文轨：改密成功且新口令可登录', async () => {
    // 【顺序无关修复】改密会**永久**改掉账号口令。此前本用例复用 enclogin_user：
    //   ① 令牌取自模块级 userToken（由「正确口令登录成功」用例写入）——随机顺序下
    //      本用例先跑时是 undefined，Bearer undefined → 401 假红；
    //   ② 改密后任何仍以 PASSWORD 登录的用例（重放/明文兼容轨）都会拿到 401。
    // 口令是账号私有状态：本用例自建专用账号并自行登录取令牌，既不依赖、也不污染他例。
    const chgUsername = 'enchg_user';
    await User.create({
      username: chgUsername,
      email: 'enchg@example.com',
      password: PASSWORD,
    });
    const chgLogin = await request(app)
      .post('/api/auth/login')
      .send({ username: chgUsername, password: PASSWORD });
    expect(chgLogin.status).toBe(200);

    const encCurrent = await buildLoginEnvelope(PASSWORD);
    const encNew = await buildLoginEnvelope(NEW_PASSWORD);
    const res = await request(app)
      .put('/api/auth/password')
      .set('Authorization', `Bearer ${chgLogin.body.data.token}`)
      .send({ encCurrentPassword: encCurrent, encNewPassword: encNew });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // 旧口令失效（明文轨验证，避免再消耗密文轨 nonce 语义混淆）
    const oldRes = await request(app)
      .post('/api/auth/login')
      .send({ username: chgUsername, password: PASSWORD });
    expect(oldRes.status).toBe(401);

    // 新口令可登录（密文轨）
    const newEnc = await buildLoginEnvelope(NEW_PASSWORD);
    const newRes = await request(app)
      .post('/api/auth/login')
      .send({ username: chgUsername, encPassword: newEnc });
    expect(newRes.status).toBe(200);
    expect(newRes.body.data.user.username).toBe(chgUsername);
  });
});
