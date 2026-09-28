/**
 * access 令牌过期后仍必须能登出（吊销入口不得随 access 一起失效）
 *
 * 缺陷形态：`/api/auth/logout` 原本挂在 `authenticate` 之后，而 refresh 令牌与
 * 设备会话的**唯一**吊销代码就在登出处理体里。access 短、refresh 长（7 天）是设计本意，
 * 于是"access 已过期"这一常态直接换来 401，处理体根本不执行 ⇒
 * 手里那个仍然有效的 refresh 令牌再也关不掉，服务端会话记录一直挂在 active。
 * 浏览器端靠拦截器"先刷新再登出"侥幸规避；API 客户端、脚本、以及令牌泄露后的
 * 正确收尾动作都不会这么做。
 *
 * 判据：登出的身份依据可以是 refresh 令牌本身（独立密钥签名 + type=refresh +
 * 未被黑名单吊销）。持有它就有权关掉它自己的会话，也仅仅只有这个权力。
 *
 * 可证伪性：把路由改回 `authenticate` ⇒ 第 1 条用例 401 变红；
 * 让 authenticateForLogout 在无 refresh 时也放行 ⇒ 第 3、4 条负向用例变红；
 * 让它接受 access 当 refresh 用（type 不校验）⇒ 第 5 条变红。
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const request = require('supertest');
const config = require('../../config');
const User = require('../../models/User');
const tokenService = require('../../services/tokenService');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const PASSWORD = randomPassword();
const TAG = `lwx${Date.now().toString(36)}`;

/** 与登录签发同形态、但**已经过期**的 access 令牌 */
const expiredAccessToken = (user) =>
  jwt.sign(
    {
      userId: String(user._id),
      username: user.username,
      roles: [],
      tokenVersion: user.tokenVersion || 0,
      jti: crypto.randomUUID(),
      type: 'access',
    },
    config.jwt.secret,
    { expiresIn: '-10s' }
  );

describe('access 过期后的登出', () => {
  let app;
  const ids = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (ids.length) await User.deleteMany({ _id: { $in: ids } });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const makeUser = async (suffix) => {
    const user = await User.create({
      username: `${TAG}${suffix}`,
      email: `${TAG}${suffix}@example.com`,
      password: PASSWORD,
      roles: [],
    });
    ids.push(user._id);
    return user;
  };

  /**
   * 返回状态码而不是布尔值：/api/auth/refresh 挂着 strictLimiter，
   * 若把 429 也当成"令牌已失效"，负向断言就会因为限流而假绿。
   * 429 一律显式失败。
   */
  const refreshStatus = async (token) => {
    const res = await request(app).post('/api/auth/refresh').send({ refreshToken: token });
    expect(res.status).not.toBe(429);
    return res.status;
  };

  test('★ 过期 access + 有效 refresh：登出成功，且该 refresh 立刻不能再换发', async () => {
    const user = await makeUser('expiredaccess');
    const refreshToken = tokenService.generateRefreshToken(user._id, user.tokenVersion || 0, null);
    // 前提自证用**无副作用**的方式：/api/auth/refresh 是单次消费的（轮换会把旧令牌
    // 拉进黑名单），拿它做"登出前还活着"的检查会直接把本用例的场景毁掉。
    expect(jwt.verify(refreshToken, config.jwt.refreshSecret, { algorithms: ['HS256'] }).type).toBe(
      'refresh'
    );

    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${expiredAccessToken(user)}`)
      .send({ refreshToken });
    expect({ status: res.status, code: res.body?.errors?.errorCode }).toEqual({
      status: 200,
      code: undefined,
    });

    // 真正的安全结论：泄露的 refresh 令牌现在关得掉了
    expect(await refreshStatus(refreshToken)).not.toBe(200);
  });

  test('完全没有 access 令牌时，凭有效 refresh 也能登出（cookie 之外的 API 客户端形态）', async () => {
    const user = await makeUser('noaccess');
    const refreshToken = tokenService.generateRefreshToken(user._id, user.tokenVersion || 0, null);
    const res = await request(app).post('/api/auth/logout').send({ refreshToken });
    expect(res.status).toBe(200);
    expect(await refreshStatus(refreshToken)).not.toBe(200);
  });

  test('过期 access 且不带 refresh ⇒ 401（登出不得成为匿名端点）', async () => {
    const user = await makeUser('nothing');
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${expiredAccessToken(user)}`)
      .send({});
    expect(res.status).toBe(401);
  });

  test('两个令牌都没有 ⇒ 401', async () => {
    const res = await request(app).post('/api/auth/logout').send({});
    expect(res.status).toBe(401);
  });

  test('access 令牌冒充 refresh ⇒ 401（用途校验在登出入口同样成立）', async () => {
    const user = await makeUser('crosstype');
    // 必须在"两把密钥相同"的拓扑下测：密钥不同时 access 签名根本过不了 refresh 验签，
    // 那条 401 与用途校验无关，把它当证据会让"删掉 type 判据"这个变异存活。
    const savedSecret = config.jwt.secret;
    config.jwt.secret = config.jwt.refreshSecret;
    try {
      // 令牌必须在改密钥**之后**签发，否则它仍是另一把密钥签的，前提自证会先炸
      const forged = tokenService.generateToken(
        String(user._id),
        user.username,
        user.email,
        [],
        user.realName,
        user.tokenVersion || 0
      );
      expect(jwt.verify(forged, config.jwt.refreshSecret, { algorithms: ['HS256'] }).type).toBe(
        'access'
      ); // 前提自证：这个令牌确实能被 refresh 侧验出签名
      const res = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${expiredAccessToken(user)}`)
        .send({ refreshToken: forged });
      expect(res.status).toBe(401);
    } finally {
      config.jwt.secret = savedSecret;
    }
  });

  test('已被吊销的 refresh 不能再当登出凭据（不给出"重复登出仍成功"的口子）', async () => {
    const user = await makeUser('alreadyrevoked');
    const refreshToken = tokenService.generateRefreshToken(user._id, user.tokenVersion || 0, null);
    const first = await request(app).post('/api/auth/logout').send({ refreshToken });
    expect(first.status).toBe(200);
    const second = await request(app).post('/api/auth/logout').send({ refreshToken });
    expect(second.status).toBe(401);
  });

  test('正常路径不受影响：有效 access + 有效 refresh 仍按完整认证走（含会话吊销）', async () => {
    const user = await makeUser('healthy');
    const fresh = tokenService.generateToken(
      String(user._id),
      user.username,
      user.email,
      [],
      user.realName,
      user.tokenVersion || 0
    );
    const refreshToken = tokenService.generateRefreshToken(user._id, user.tokenVersion || 0, null);
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${fresh}`)
      .send({ refreshToken });
    expect(res.status).toBe(200);
    expect(await refreshStatus(refreshToken)).not.toBe(200);
  });

  // 黑名单查询是 fail-closed 上抛的（查不到结论 ≠ 没被吊销）。access 链早已把这类
  // 故障映射成 503（authMiddlewareFailClosedGuards 里"黑名单服务故障 → 503"那条），
  // refresh 链却没人接：同一个故障走 access 得 503、走 refresh 得 500
  // "服务器内部错误"并按 UnhandledError 记 error 级日志——把可自愈的降级报成假事故，
  // 也让运维在告警面上看不到"安全服务不可用"这条真实原因。
  test('黑名单服务故障（refresh 路径）→ 503 安全服务不可用，不得降级成笼统 500', async () => {
    const user = await makeUser('blfail');
    const refreshToken = tokenService.generateRefreshToken(user._id, user.tokenVersion || 0, null);
    const TokenBlacklist = require('../../models/TokenBlacklist');
    const spy = jest.spyOn(TokenBlacklist, 'findOne').mockImplementation(() => {
      throw new Error('db down (故障注入)');
    });
    let res;
    try {
      res = await request(app).post('/api/auth/logout').send({ refreshToken });
    } finally {
      spy.mockRestore();
    }
    expect(res.status).toBe(503);
    expect(res.body.message).toBe('安全服务暂不可用，请稍后重试');
    // 故障期间绝不"顺手登出成功"：登出会吊销会话，属于必须拿到确定结论才能做的写操作
    expect(await refreshStatus(refreshToken)).toBe(200);
  });

  test('黑名单服务故障（过期 access 落到 refresh 分支）→ 同为 503，不因入口形态分裂', async () => {
    // authorizeByRefreshToken 有两个调用点（无 access / access 已过期）。
    // 只给其中一个补口径 = 半个修复：故障语义会随客户端带没带那个过期头而不同。
    const user = await makeUser('blfailx');
    const refreshToken = tokenService.generateRefreshToken(user._id, user.tokenVersion || 0, null);
    const TokenBlacklist = require('../../models/TokenBlacklist');
    const spy = jest.spyOn(TokenBlacklist, 'findOne').mockImplementation(() => {
      throw new Error('db down (故障注入)');
    });
    let res;
    try {
      res = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${expiredAccessToken(user)}`)
        .send({ refreshToken });
    } finally {
      spy.mockRestore();
    }
    expect(res.status).toBe(503);
    expect(res.body.message).toBe('安全服务暂不可用，请稍后重试');
    expect(await refreshStatus(refreshToken)).toBe(200);
  });
});
