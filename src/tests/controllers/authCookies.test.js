/**
 * I-01 httpOnly Cookie 认证迁移测试
 * 覆盖：
 * - cookie 工具函数（解析 / 时长换算 / 设置 / 清除）
 * - 登录/注册成功时下发两个令牌 cookie（响应体保留 tokens 字段）
 * - authenticate 中间件 Bearer 与 cookie 双路径（同一套校验，含黑名单）
 * - 刷新接口：请求体与 refresh_token cookie 双来源，轮换时同步轮换 cookie
 * - 登出按正确 path 清除 cookie，且黑名单逻辑保留（旧令牌立即失效）
 */

const request = require('supertest');
const mongoose = require('mongoose');

const {
  parseCookies,
  durationToMs,
  setAuthCookies,
  clearAuthCookies,
} = require('../../utils/cookie');

/** 解析 supertest 响应的 Set-Cookie 头为 { [name]: { value, attrs } } */
const parseSetCookies = (res) => {
  const list = res.headers['set-cookie'] || [];
  const map = {};
  for (const c of list) {
    const [pair, ...attrs] = c.split(';');
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    map[pair.slice(0, idx).trim()] = {
      value: pair.slice(idx + 1),
      attrs: attrs.map((a) => a.trim().toLowerCase()),
    };
  }
  return map;
};

describe('cookie 工具函数', () => {
  test('parseCookies 正确解析多键值、引号与 URL 编码', () => {
    const parsed = parseCookies('a=1; b="quoted"; c=hello%20world; lone; =x');
    expect(parsed.a).toBe('1');
    expect(parsed.b).toBe('quoted');
    expect(parsed.c).toBe('hello world');
    expect(parsed.lone).toBeUndefined();
  });

  test('parseCookies 对空/非法输入返回空对象', () => {
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies('')).toEqual({});
    expect(parseCookies(123)).toEqual({});
  });

  test('durationToMs 换算 JWT 过期表达式', () => {
    expect(durationToMs('24h', 0)).toBe(24 * 60 * 60 * 1000);
    expect(durationToMs('7d', 0)).toBe(7 * 24 * 60 * 60 * 1000);
    expect(durationToMs('30s', 0)).toBe(30 * 1000);
    expect(durationToMs('bogus', 555)).toBe(555);
  });

  test('setAuthCookies 按契约下发两个 cookie', () => {
    const calls = [];
    const fakeRes = { cookie: (name, value, opts) => calls.push({ name, value, opts }) };
    setAuthCookies(fakeRes, 'AT', 'RT');
    expect(calls).toHaveLength(2);

    const access = calls.find((c) => c.name === 'access_token');
    expect(access.value).toBe('AT');
    expect(access.opts.path).toBe('/api');
    expect(access.opts.httpOnly).toBe(true);
    expect(access.opts.sameSite).toBe('strict');
    expect(access.opts.maxAge).toBe(durationToMs(require('../../config').jwt.expire, 0));

    const refresh = calls.find((c) => c.name === 'refresh_token');
    expect(refresh.value).toBe('RT');
    expect(refresh.opts.path).toBe('/api/auth');
    expect(refresh.opts.maxAge).toBe(durationToMs(require('../../config').jwt.refreshExpire, 0));
  });

  test('clearAuthCookies 按各自 path 清除', () => {
    const calls = [];
    const fakeRes = { clearCookie: (name, opts) => calls.push({ name, opts }) };
    clearAuthCookies(fakeRes);
    expect(calls).toHaveLength(2);
    expect(calls.find((c) => c.name === 'access_token').opts.path).toBe('/api');
    expect(calls.find((c) => c.name === 'refresh_token').opts.path).toBe('/api/auth');
  });
});

describe('httpOnly Cookie 认证集成', () => {
  let app;
  let User;
  let SystemConfig;
  let config;
  // 夹具口令须避开 helpers.BREACHED_PASSWORDS 黑名单（G8）：
  // Test@12345 归一化后为 test@123，属撞库字典条目，注册接口会拒绝
  const PASSWORD = 'Vn6$Rw83pKx5';

  const accessMaxAgeSec = () => Math.round(durationToMs(config.jwt.expire, 0) / 1000);
  const refreshMaxAgeSec = () => Math.round(durationToMs(config.jwt.refreshExpire, 0) / 1000);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    SystemConfig = require('../../models/SystemConfig');
    config = require('../../config');

    await User.create({
      username: 'cookieuser',
      email: 'cookieuser@example.com',
      password: PASSWORD,
    });

    // 打开公开注册开关（含缓存失效），用于注册下发 cookie 用例
    await SystemConfig.create({ key: 'allowPublicRegistration', value: true });
    SystemConfig.invalidateRegistrationCache();

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 登录并返回解析后的响应 */
  const login = () =>
    request(app).post('/api/auth/login').send({ username: 'cookieuser', password: PASSWORD });

  test('登录成功下发两个令牌 cookie 且响应体保留 tokens 字段', async () => {
    const res = await login();
    expect(res.status).toBe(200);

    // 响应体契约：保留 token/refreshToken（兼容现有测试与 API 消费者）
    expect(res.body.data.token).toBeTruthy();
    expect(res.body.data.refreshToken).toBeTruthy();

    const cookies = parseSetCookies(res);
    expect(cookies.access_token).toBeDefined();
    expect(cookies.refresh_token).toBeDefined();
    // cookie 值与响应体令牌一致
    expect(cookies.access_token.value).toBe(res.body.data.token);
    expect(cookies.refresh_token.value).toBe(res.body.data.refreshToken);

    // 属性契约：HttpOnly / SameSite=Lax / path / maxAge；测试环境(NODE_ENV=test)非生产且未设 COOKIE_SECURE，不应带 Secure
    for (const [name, expectedPath, expectedMaxAge] of [
      ['access_token', '/api', accessMaxAgeSec()],
      ['refresh_token', '/api/auth', refreshMaxAgeSec()],
    ]) {
      const { attrs } = cookies[name];
      expect(attrs).toContain('httponly');
      expect(attrs).toContain('samesite=strict');
      expect(attrs).toContain(`path=${expectedPath}`);
      expect(attrs).toContain(`max-age=${expectedMaxAge}`);
      expect(attrs).not.toContain('secure');
    }
  });

  test('Bearer 与 cookie 双路径均可通过 authenticate，且 Bearer 优先', async () => {
    const loginRes = await login();
    const { token } = loginRes.body.data;

    // cookie 路径：不带 Authorization 头，仅携带 access_token cookie
    const byCookie = await request(app)
      .get('/api/auth/me')
      .set('Cookie', [`access_token=${token}`]);
    expect(byCookie.status).toBe(200);
    expect(byCookie.body.data.user.username).toBe('cookieuser');

    // Bearer 路径
    const byBearer = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(byBearer.status).toBe(200);

    // Bearer 优先：无效 cookie + 有效 Bearer 仍通过（证明头优先于 cookie 回退）
    const bearerWins = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`)
      .set('Cookie', ['access_token=invalid-token-value']);
    expect(bearerWins.status).toBe(200);

    // 无任何凭证：401
    const anon = await request(app).get('/api/auth/me');
    expect(anon.status).toBe(401);
  });

  test('cookie 路径与 Bearer 路径走同一套校验（黑名单命中同样拒绝）', async () => {
    const loginRes = await login();
    const { token } = loginRes.body.data;

    // 通过登出使该 token 进入黑名单
    const out = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', [`access_token=${token}`]);
    expect(out.status).toBe(200);

    // 黑名单令牌经 cookie 路径同样 401
    const denied = await request(app)
      .get('/api/auth/me')
      .set('Cookie', [`access_token=${token}`]);
    expect(denied.status).toBe(401);
  });

  test('刷新接口：请求体来源成功且轮换两个 cookie，响应体保留 tokens 字段', async () => {
    const loginRes = await login();
    const { refreshToken } = loginRes.body.data;

    const res = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(res.status).toBe(200);
    expect(res.body.data.token).toBeTruthy();
    expect(res.body.data.refreshToken).toBeTruthy();
    // 新令牌与旧令牌不同（轮换）
    expect(res.body.data.refreshToken).not.toBe(refreshToken);

    const cookies = parseSetCookies(res);
    expect(cookies.access_token.value).toBe(res.body.data.token);
    expect(cookies.refresh_token.value).toBe(res.body.data.refreshToken);
    expect(cookies.access_token.attrs).toContain('path=/api');
    expect(cookies.refresh_token.attrs).toContain('path=/api/auth');
  });

  test('刷新接口：仅携带 refresh_token cookie（无请求体）同样成功', async () => {
    const loginRes = await login();
    const { refreshToken } = loginRes.body.data;

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refresh_token=${refreshToken}`]);
    expect(res.status).toBe(200);
    expect(res.body.data.token).toBeTruthy();

    // 旧 refresh token 已被轮换拉黑，重放应 401
    const replay = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(replay.status).toBe(401);
  });

  test('刷新接口：无任何令牌来源返回 400', async () => {
    const res = await request(app).post('/api/auth/refresh').send({});
    expect(res.status).toBe(400);
  });

  test('登出按正确 path 清除两个 cookie 且旧令牌立即失效', async () => {
    const loginRes = await login();
    const { token, refreshToken } = loginRes.body.data;

    const res = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', [`access_token=${token}`, `refresh_token=${refreshToken}`]);
    expect(res.status).toBe(200);

    const cookies = parseSetCookies(res);
    // 清除 cookie：max-age=0（或过期时间在过去）且 path 与下发时一致
    expect(cookies.access_token).toBeDefined();
    expect(cookies.refresh_token).toBeDefined();
    expect(cookies.access_token.attrs).toContain('path=/api');
    expect(cookies.refresh_token.attrs).toContain('path=/api/auth');
    for (const name of ['access_token', 'refresh_token']) {
      const cleared =
        cookies[name].attrs.includes('max-age=0') ||
        cookies[name].attrs.some(
          (a) => a.startsWith('expires=') && new Date(a.slice(8)).getTime() < Date.now()
        );
      expect(cleared).toBe(true);
    }

    // 黑名单保留：旧 access/refresh 令牌登出后立即失效
    const meDenied = await request(app)
      .get('/api/auth/me')
      .set('Cookie', [`access_token=${token}`]);
    expect(meDenied.status).toBe(401);

    const refreshDenied = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(refreshDenied.status).toBe(401);
  });

  test('注册成功同样下发两个令牌 cookie', async () => {
    const res = await request(app).post('/api/auth/register').send({
      username: 'cookie_reg_user',
      email: 'cookie_reg@example.com',
      password: PASSWORD,
    });
    expect(res.status).toBe(201);

    const cookies = parseSetCookies(res);
    expect(cookies.access_token).toBeDefined();
    expect(cookies.refresh_token).toBeDefined();
    expect(cookies.access_token.attrs).toContain('httponly');
    expect(cookies.access_token.attrs).toContain('path=/api');
    expect(cookies.refresh_token.attrs).toContain('path=/api/auth');

    // 注册后 cookie 即可直接访问受保护接口
    const me = await request(app)
      .get('/api/auth/me')
      .set('Cookie', [`access_token=${cookies.access_token.value}`]);
    expect(me.status).toBe(200);
  });
});
