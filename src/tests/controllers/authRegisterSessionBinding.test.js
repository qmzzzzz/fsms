/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：POST /api/auth/register 的令牌签发与会话注册（authService.registerUser）
 * 守护的不变式：**任何新增的登录态都必须绑定一条可吊销的 UserSession**
 *   —— 令牌里没有 sid，就等于这条登录态在「登录会话」界面不存在、踢不掉，
 *      且它的 refresh 轮换会一路自我续期而永不过期。
 * 可证伪性：变异实测 M1~M4 记录在
 *   deliverables/AGENT工作总账与待办-2026-09-21.md 的 F-175 条目
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 【缺陷本体（F-175）】
 * `authController.register` 的注释写着「注册成功即建立会话」，`authService.registerUser`
 * 的注释写着同一句，但代码只做了两件事：`generateToken(...)`（六个实参，没有 jti、没有 sid）
 * 与 `generateRefreshToken(user._id, tokenVersion)`（没有 sid），**既不建 UserSession，
 * 也不传 sid**。
 *
 * 后果不是"少一个字段"而是这条登录态不可治理：
 *   1. `authService.refreshSession` 的设备级校验是 `const rotateSid = decoded.sid || null;
 *      if (rotateSid) { ...validateSession... }` —— 无 sid 时整段跳过；
 *   2. 轮换末尾 `generateRefreshToken(user._id, tokenVersion, rotateSid)` 又把 null 传下去，
 *      于是每次刷新签出**另一对无 sid 的 7 天令牌**，血统无限自续；
 *   3. 「登录会话」界面（GET /api/auth/sessions）里没有它，`DELETE /sessions/:sid`
 *      无从下手 —— 用户能看到并踢掉的设备列表里，天生少一台他正在用的设备。
 *
 * 而 `middleware/auth.js` 对"无 sid 令牌"的承诺是「这些令牌最长在 refresh 有效期后自然消亡」
 * ——那是对的，前提是**只给功能上线前签发的旧令牌兜底**。注册路径每次成功都在制造新的
 * 无 sid 令牌，这个群体因此永不消亡，注释与事实相反。（同类"注释声称的机制并不存在"本仓
 * 已有判例：inspectionRoutes 的 L-05 记的正是这条。）
 *
 * 【修法与它的边界】注册改走与登录同一段 `issueRevocableTokenPair`（sid 与 UserSession
 * 一一对应 + 落库失败退回无 sid 的降级判据），不是再抄一份 mint。降级方向保持"少给一份
 * 可吊销性"而不是"拒绝注册"：拒绝会让会话表抖动时把注册整条链路打死。
 * 刻意**不**在这里治"降级令牌的无上限血统"——那要决定是强制重登还是给一个绝对上限，
 * 属对外口径，已作为待拍板项交接。
 *
 * 【为什么必须打真实 HTTP】不变式的载体是 Set-Cookie 里那两个令牌 + 会话表里的对应记录 +
 * 轮换后的令牌是否还认那条会话；服务层单测看不到控制器下发的是哪一份令牌。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const config = require('../../config');

const stamp = `zqf175${Date.now().toString(36)}`.toLowerCase().replace(/[^a-z0-9]/g, '');

/** 从 Set-Cookie 里取某个 cookie 的值（注册响应体不含令牌字段，只有 cookie 这一条出口） */
const cookieValue = (res, name) => {
  for (const c of res.headers['set-cookie'] || []) {
    const [pair] = c.split(';');
    const idx = pair.indexOf('=');
    if (pair.slice(0, idx).trim() === name) return pair.slice(idx + 1);
  }
  return undefined;
};

describe('注册即登录的令牌必须绑定一条可吊销会话（F-175）', () => {
  let app;
  let User;
  let UserSession;
  let sessionService;
  let tokenService;
  let authService;

  /** 真实 HTTP 注册一次：本次登录态就是被测对象，所有断言只围绕它 */
  let reg;
  /** 第二条真实注册：只用于"能被踢掉"那一臂，避免与上面的用例争同一份状态 */
  let other;
  /** 另一台设备的会话（sid 与 reg 不同），用来发起那次踢除 */
  let peerSid;
  let peerToken;

  const passwords = {};

  const registerViaHttp = async (local) => {
    const username = `${stamp}${local}`;
    const password = randomPassword();
    passwords[local] = password;
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username, email: `${username}@reg.example.com`, password });
    expect(res.status).toBe(201);
    const access = cookieValue(res, 'access_token');
    const refreshToken = cookieValue(res, 'refresh_token');
    return {
      username,
      local,
      access,
      refreshToken,
      userId: res.body.data.userId,
      sid: jwt.verify(refreshToken, config.jwt.refreshSecret, { algorithms: ['HS256'] }).sid,
    };
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    UserSession = require('../../models/UserSession');
    sessionService = require('../../services/sessionService');
    tokenService = require('../../services/tokenService');
    authService = require('../../services/authService');
    require('../../models/TokenBlacklist');

    // 测试库是**每文件全新空库**（setup.js 的 T-1 隔离），故公开注册默认关着，
    // 不开这两把闸就只会拿到 403/400，七条断言全在同一步上空跑：
    // 1) allowPublicRegistration 缺省为 false ⇒ 路由直接 403 PUBLIC_REGISTRATION_DISABLED
    // 2) registerCaptchaEnabled 缺省为 true ⇒ 无验证码字段先 400 CAPTCHA_INVALID
    // 缓存失效必须显式调用：两把闸都有进程内缓存，只落库不失效读到的是旧值。
    const SystemConfig = require('../../models/SystemConfig');
    await SystemConfig.create({ key: 'allowPublicRegistration', value: true });
    SystemConfig.invalidateRegistrationCache();
    await SystemConfig.create({ key: 'registerCaptchaEnabled', value: false });
    SystemConfig.invalidateRegisterCaptchaCache();

    const { createApp } = require('../../app');
    app = createApp();

    reg = await registerViaHttp('a');
    other = await registerViaHttp('b');

    // 踢除自己所在会话会被 CANNOT_REVOKE_CURRENT_SESSION 挡下（语义上那是登出），
    // 所以踢 reg 这条必须借另一条会话的身份——直接建，不绕注册（少占一次限流额度）。
    peerSid = `peersid_${stamp}`;
    await sessionService.createSession({
      userId: other.userId,
      req: { ip: '127.0.0.1', get: () => 'jest-peer-device' },
      sid: peerSid,
    });
    const peerUser = await User.findById(other.userId).select(
      'username email realName tokenVersion'
    );
    peerToken = tokenService.generateToken(
      peerUser._id,
      peerUser.username,
      peerUser.email,
      [],
      peerUser.realName,
      peerUser.tokenVersion ?? 0,
      `jti_${stamp}`,
      peerSid
    );
  });

  afterAll(async () => {
    // beforeAll 失败时 reg/other 仍是 undefined：这里必须容错，
    // 否则 afterAll 的 TypeError 会盖掉真正的失败原因（首次跑就是这样）
    const ids = [reg, other].filter(Boolean).map((r) => r.userId);
    if (ids.length > 0) {
      await UserSession.deleteMany({ $or: [{ userId: { $in: ids } }, { sid: peerSid }] });
      await User.deleteMany({ _id: { $in: ids } });
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // ---------- 前提自证：注册通道本身可用 ----------

  test('前提：注册下发两个 httpOnly 令牌 cookie（否则后面的断言全是空跑）', async () => {
    expect(reg.access).toEqual(expect.any(String));
    expect(reg.refreshToken).toEqual(expect.any(String));
    // 令牌确实能用：走一次 authenticate（不只看它存在）
    const me = await request(app)
      .get('/api/auth/me')
      .set('Cookie', [`access_token=${reg.access}`]);
    expect(me.status).toBe(200);
  });

  // ---------- 缺陷本体：令牌里必须有 sid，会话表里必须有对应记录 ----------

  test('注册的 refresh 令牌带 sid，且 UserSession 里有与之对应的一条 active 记录', async () => {
    expect(typeof reg.sid).toBe('string');
    expect(reg.sid).toBeTruthy();

    const session = await UserSession.findOne({ sid: reg.sid }).lean();
    expect(session).not.toBeNull();
    expect(String(session.userId)).toBe(String(reg.userId));
    expect(session.status).toBe('active');
    // 注册只应建立这一条会话：多出来就是重复建会话（界面上会留下幽灵设备）
    expect(await UserSession.countDocuments({ userId: reg.userId })).toBe(1);
  });

  test('注册的 access 令牌与 refresh 令牌绑同一条会话（否则踢掉会话挡不住另一支令牌）', async () => {
    const accessSid = jwt.verify(reg.access, config.jwt.secret, { algorithms: ['HS256'] }).sid;
    expect(accessSid).toBe(reg.sid);
  });

  test('「登录会话」界面看得见这条注册登录态', async () => {
    const res = await request(app)
      .get('/api/auth/sessions')
      .set('Cookie', [`access_token=${reg.access}`]);
    expect(res.status).toBe(200);
    expect(res.body.data.currentSidPresent).toBe(true);
    const listed = res.body.data.sessions.map((s) => s.sid);
    expect(listed).toContain(reg.sid);
  });

  // ---------- 可吊销性：这条血统踢得掉，且踢掉后刷不动 ----------

  test('刷新继承同一个 sid：轮换不会把登录态洗成不可吊销', async () => {
    const res = await request(app).post('/api/auth/refresh').send({
      refreshToken: reg.refreshToken,
    });
    expect(res.status).toBe(200);
    const nextRefresh = cookieValue(res, 'refresh_token');
    expect(nextRefresh).toEqual(expect.any(String));
    expect(jwt.verify(nextRefresh, config.jwt.refreshSecret, { algorithms: ['HS256'] }).sid).toBe(
      reg.sid
    );
    // 会话表不因为轮换多出一条（多出来＝幽灵设备）
    expect(await UserSession.countDocuments({ userId: reg.userId })).toBe(1);
  });

  test('踢掉注册建立的会话后，它的 refresh 令牌必须被拒（缺陷本体：旧实现这里返回 200）', async () => {
    const revoke = await request(app)
      .delete(`/api/auth/sessions/${other.sid}`)
      .set('Cookie', [`access_token=${peerToken}`]);
    expect(revoke.status).toBe(200);

    const refreshed = await request(app).post('/api/auth/refresh').send({
      refreshToken: other.refreshToken,
    });
    // 关键一臂：无 sid 的令牌走不到 validateSession，这一臂在修复前是 200 + 一对新令牌
    expect(refreshed.status).toBe(401);
    expect(refreshed.body.success).toBe(false);
    expect(cookieValue(refreshed, 'refresh_token')).toBeUndefined();
  });

  // ---------- 降级方向：落库失败退回"少给可吊销性"，而不是拒绝注册 ----------

  test('会话落库失败时注册仍然成功，但令牌不带 sid（降级只少给一层可吊销性）', async () => {
    const spy = jest
      .spyOn(sessionService, 'createSession')
      .mockRejectedValue(new Error('模拟会话表写入失败'));
    try {
      const result = await authService.registerUser(
        {
          username: `${stamp}deg`,
          email: `${stamp}deg@reg.example.com`,
          password: randomPassword(),
        },
        { req: { ip: '127.0.0.1', get: () => 'jest-degraded' } }
      );
      expect(result.outcome).toBe('OK');
      expect(result.token).toEqual(expect.any(String));
      expect(result.sid).toBeNull();
      expect(result.sessionRegistered).toBe(false);
      // 降级签发的令牌必须"看起来就没有会话"，而不是带一个查不到的 sid
      expect(
        jwt.verify(result.refreshToken, config.jwt.refreshSecret, { algorithms: ['HS256'] }).sid
      ).toBeUndefined();
      expect(await UserSession.countDocuments({ userId: result.userId })).toBe(0);
    } finally {
      spy.mockRestore();
      await User.deleteMany({ username: `${stamp}deg` });
    }
  });
});
