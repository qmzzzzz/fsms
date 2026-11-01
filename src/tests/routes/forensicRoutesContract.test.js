'use strict';

/**
 * 取证溯源接口契约（T5/T6）：走真 HTTP，钉住「错误要说清是哪一种」而不是只说失败。
 *
 * 为什么不能只留服务层单测：服务层单测绕过路由，看不见三件只有在真实请求上才成立的事——
 * · 401 必须早于参数校验，否则未鉴权的人能靠「参数错」探出端点存在与字段名；
 * · 判据不可用（地址根本解析不出来）必须是 400，不能是 200 + 空数组。空结果读起来就是
 *   「这个 IP 很干净」，而这恰恰是溯源时最危险的假阴性；
 * · 封段被拒时必须带 errors.reason。只回「操作失败」，操作者唯一能做的就是换个网段重试，
 *   于是把 full_range_cidr / operator_inside 这类「再试也没用」的护栏当成偶发失败。
 *
 * 票据一次性只在 HTTP 上验得了：同一张票第二次必须落空，这条是「跳过确认直接封」的唯一拦路。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const stamp = `zfrc${Date.now()}`.slice(-10);
const BASE = '/api/security/forensic';

describe('取证溯源接口契约（T5/T6）', () => {
  let app;
  let token;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    require('../../models/ForensicCapture');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `ZFRC_ALL${stamp}`,
      code: `ZFRC_ALL${stamp}`,
      level: 10,
      permissions: [wildcard._id],
    });
    const user = await User.create({
      username: `zfrc_all${stamp}`.toLowerCase(),
      email: `zfrc_all${stamp}@example.com`,
      password: 'Test@1234567',
      department: `ZFRC-D-${stamp}`,
      roles: [role._id],
    });
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteMany({ username: `zfrc_all${stamp}`.toLowerCase() }).catch(() => {});
      await Role.deleteMany({ code: `ZFRC_ALL${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const get = (p, q) =>
    request(app)
      .get(BASE + p)
      .set('Authorization', `Bearer ${token}`)
      .query(q || {});
  const post = (p, b) =>
    request(app)
      .post(BASE + p)
      .set('Authorization', `Bearer ${token}`)
      .send(b);

  test('1 未鉴权一律 401，且 401 早于参数校验（不泄露端点与字段名）', async () => {
    for (const p of ['/trace', '/clusters']) {
      const res = await request(app).get(BASE + p);
      expect(res.status).toBe(401);
    }
    const bad = await request(app)
      .post(BASE + '/pool-ban/request')
      .send({ cidr: '0.0.0.0/0' });
    expect(bad.status).toBe(401);
    expect(bad.body.errors && bad.body.errors.errorCode).not.toBe('VALIDATION_FAILED');
  });

  test('2 三个维度都不给 → 400，不能靠「查全部」绕过判据', async () => {
    const res = await get('/trace');
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('FORENSIC_NO_CRITERIA');
  });

  test('3 地址不可解析按「判据不可用」拒绝，不返回空结果（假阴性来源）', async () => {
    const res = await get('/trace', { ip: '999.999.999.999' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('FORENSIC_NO_CRITERIA');
  });

  test('4 合法 IP 查不到任何记录也是 200：没记录是正常结论，不是错误', async () => {
    const res = await get('/trace', { ip: '203.0.113.77' });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data.timeline)).toBe(true);
    expect(res.body.data.count).toBe(0);
    // truncated 必须显式给出：空结果与「被 limit 截断后的空」不能长得一样
    expect(res.body.data.truncated).toBe(false);
    expect(typeof res.body.data.triggers).toBe('object');
    expect(res.body.data.timeline.length).toBe(0);
  });

  test('5 聚类：窗口越界在路由层就被拒，合法窗口的时间跨度逐字对上', async () => {
    const tooWide = await get('/clusters', { windowHours: 99999 });
    expect(tooWide.status).toBe(400);
    expect(tooWide.body.errors.errorCode).toBe('VALIDATION_FAILED');

    const res = await get('/clusters', { windowHours: 48 });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data.segments)).toBe(true);
    expect(Array.isArray(res.body.data.recommended)).toBe(true);
    const span = new Date(res.body.data.until).getTime() - new Date(res.body.data.since).getTime();
    expect(span).toBe(48 * 3600 * 1000);
  });

  test('6 request 缺 reason 在路由层就被拒（reason_required 走不到 HTTP 面）', async () => {
    const res = await post('/pool-ban/request', { cidr: '198.51.100.0/24' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
  });

  test('7 0.0.0.0/0 被拒，且 reason 具体到「再试也没用」', async () => {
    const res = await post('/pool-ban/request', { cidr: '0.0.0.0/0', reason: '全封' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('FORENSIC_POOL_BAN_REFUSED');
    expect(res.body.errors.reason).toBe('full_range_cidr');
  });

  test('8 两步确认：票据只能用一次，重放必须落空', async () => {
    const issued = await post('/pool-ban/request', {
      cidr: '198.51.100.0/24',
      reason: `契约测试 ${stamp}`,
    });
    expect(issued.status).toBe(200);
    expect(typeof issued.body.data.token).toBe('string');
    const tokenStr = issued.body.data.token;

    // /24 的主机数正好等于 HIGH_IMPACT_HOSTS(256) ⇒ 票据必带 needTypedConfirm，
    // 不带 typedConfirm 落库会被拒（这是"两侧都必须实现"的后端一侧，见 ADR-018 ③）。
    expect(issued.body.data.needTypedConfirm).toBe(true);

    const first = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.100.0/24',
    });
    expect(first.status).toBe(200);
    expect(typeof first.body.data.bannedCount).toBe('number');

    // 重放：票据已被消耗（一次性），带不带 typedConfirm 都必须是 unknown_token
    const replay = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.100.0/24',
    });
    expect(replay.status).toBe(400);
    expect(replay.body.errors.errorCode).toBe('FORENSIC_POOL_BAN_REFUSED');
    expect(replay.body.errors.reason).toBe('unknown_token');
  });

  test('8b 需要打字确认的段：缺 typedConfirm 或打字不匹配一律拒，且票据不被消耗', async () => {
    const issued = await post('/pool-ban/request', {
      cidr: '198.51.100.0/24',
      reason: `契约测试 ${stamp}`,
    });
    expect(issued.status).toBe(200);
    const tokenStr = issued.body.data.token;

    const missing = await post('/pool-ban/confirm', { token: tokenStr, durationHours: 1 });
    expect(missing.status).toBe(400);
    expect(missing.body.errors.reason).toBe('typed_confirmation_required');

    const wrong = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.101.0/24',
    });
    expect(wrong.status).toBe(400);
    expect(wrong.body.errors.reason).toBe('typed_confirmation_required');

    // 打错字不消耗票据：改对了同一张票仍然能用（ADR-018「让人多走一步」而不是"重来一遍"）
    const right = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.100.0/24',
    });
    expect(right.status).toBe(200);
  });

  test('9 无导出密钥时拒绝，不产出未签名包', async () => {
    const savedExport = process.env.FORENSIC_EXPORT_SECRET;
    const savedHmac = process.env.AUDIT_HMAC_SECRET;
    delete process.env.FORENSIC_EXPORT_SECRET;
    delete process.env.AUDIT_HMAC_SECRET;
    try {
      const res = await post('/export', { ip: '203.0.113.77' });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('FORENSIC_EXPORT_NO_SECRET');
      expect(res.body.data).toBeUndefined();
    } finally {
      if (savedExport !== undefined) process.env.FORENSIC_EXPORT_SECRET = savedExport;
      if (savedHmac !== undefined) process.env.AUDIT_HMAC_SECRET = savedHmac;
    }
  });
});
