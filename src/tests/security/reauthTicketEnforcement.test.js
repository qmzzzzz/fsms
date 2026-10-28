'use strict';

/**
 * 审计读取的二次验证票据（P3-2）
 *
 * 覆盖两个层面：
 *  1. 票据本体：签发/校验往返、绑定 userId + 会话 sid、过期与篡改 fail-closed；
 *  2. HTTP 链路：审计读取（/alerts、/audit-logs、/audit-logs/export）必须带票，
 *     票据由 POST /security/reauth 用当前口令换取；管理员写操作（安全开关、
 *     重置他人 MFA）必须当场通过一次二次验证。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { reauthHeaders } = require('../helpers/reauthTicket');
const {
  issueReauthTicket,
  verifyReauthTicket,
  REAUTH_TICKET_TTL_MS,
} = require('../../utils/reauthTicket');

const stamp = `rkt${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

describe('reauth ticket 本体', () => {
  const userId = `user-${stamp}`;
  const otherUserId = `other-${stamp}`;

  test('签发 / 校验往返：同一 userId 与 sessionId 通过', () => {
    const { ticket, expiresIn } = issueReauthTicket({ userId, sessionId: 'sid-A' });
    expect(expiresIn).toBe(REAUTH_TICKET_TTL_MS / 1000);
    expect(verifyReauthTicket(ticket, { userId, sessionId: 'sid-A' })).toBe(true);
  });

  test('绑定 userId：换账号即失败', () => {
    const { ticket } = issueReauthTicket({ userId, sessionId: 'sid-A' });
    expect(verifyReauthTicket(ticket, { userId: otherUserId, sessionId: 'sid-A' })).toBe(false);
  });

  test('绑定会话：sid 不一致（含 null ↔ 非空）均失败', () => {
    const { ticket } = issueReauthTicket({ userId, sessionId: 'sid-A' });
    expect(verifyReauthTicket(ticket, { userId, sessionId: 'sid-B' })).toBe(false);
    expect(verifyReauthTicket(ticket, { userId, sessionId: null })).toBe(false);

    const noSid = issueReauthTicket({ userId, sessionId: null }).ticket;
    expect(verifyReauthTicket(noSid, { userId, sessionId: null })).toBe(true);
    expect(verifyReauthTicket(noSid, { userId, sessionId: 'sid-A' })).toBe(false);
  });

  test('过期即失败（不提供宽限）', () => {
    const now = Date.now();
    const { ticket } = issueReauthTicket(
      { userId, sessionId: 'sid-A' },
      now - REAUTH_TICKET_TTL_MS
    );
    expect(verifyReauthTicket(ticket, { userId, sessionId: 'sid-A' }, now)).toBe(false);
  });

  test('篡改 / 结构异常一律 fail-closed（不抛异常）', () => {
    const { ticket } = issueReauthTicket({ userId, sessionId: 'sid-A' });
    const [body, signature] = ticket.split('.');

    expect(verifyReauthTicket(`${body}x.${signature}`, { userId, sessionId: 'sid-A' })).toBe(false);
    expect(verifyReauthTicket(`${body}.${signature}x`, { userId, sessionId: 'sid-A' })).toBe(false);
    expect(verifyReauthTicket(`${ticket}.extra`, { userId, sessionId: 'sid-A' })).toBe(false);
    expect(verifyReauthTicket(body, { userId, sessionId: 'sid-A' })).toBe(false);
    expect(verifyReauthTicket('', { userId, sessionId: 'sid-A' })).toBe(false);
    expect(verifyReauthTicket(null, { userId, sessionId: 'sid-A' })).toBe(false);
  });

  /**
   * 域分离（M-1）：签名输入带固定域前缀，与「同一把 HMAC_SECRET 的其它用途」
   * 在字节层面隔开。此前的签名输入是裸 base64url(body)，与审计链检查点等
   * 其余 HMAC 用途同构。用例钉住：**不含域前缀**的签名（即改造前的旧口径）
   * 必须被判无效——否则这次加固就等于只在注释里成立。
   */
  test('签名绑定域前缀：裸 body 的签名（旧口径）一律无效', () => {
    const { hmacSigner } = require('../../utils/encryption');
    const { ticket } = issueReauthTicket({ userId, sessionId: 'sid-A' });
    const [body] = ticket.split('.');

    // 旧口径（直接签 body，不带域前缀）伪造不了本系统认可的票据
    const legacySig = hmacSigner.sign(body);
    expect(verifyReauthTicket(`${body}.${legacySig}`, { userId, sessionId: 'sid-A' })).toBe(false);
    // 反向对照：带域前缀的签名被接受（证明拒绝来自域前缀、而非别的判据）
    expect(hmacSigner.verify(`reauth-ticket:v1:${body}`, ticket.split('.')[1])).toBe(true);
  });
});

describe('reauth ticket HTTP 强制', () => {
  let app;
  let User;
  let Role;
  let readerToken;
  let writerToken;
  let readerPassword;
  let writerPassword;
  let readerUserId;
  let victimId;

  const sign = (user, jti) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0, jti },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `票据测试_${stamp}`,
      code: `RKT_${stamp.toUpperCase()}`,
      level: 10,
      permissions: [wildcard._id],
    });

    readerPassword = randomPassword();
    writerPassword = randomPassword();
    const reader = await User.create({
      username: `rktreader${stamp}`,
      email: `rktreader${stamp}@example.com`,
      password: readerPassword,
      roles: [role._id],
    });
    readerUserId = String(reader._id);
    readerToken = sign(reader, `reader-${stamp}`);

    const writer = await User.create({
      username: `rktwriter${stamp}`,
      email: `rktwriter${stamp}@example.com`,
      password: writerPassword,
      roles: [role._id],
    });
    writerToken = sign(writer, `writer-${stamp}`);

    const victim = await User.create({
      username: `rktvictim${stamp}`,
      email: `rktvictim${stamp}@example.com`,
      password: randomPassword(),
    });
    victimId = String(victim._id);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^rkt.*${stamp}$`) }).catch(() => {});
      await Role.deleteOne({ code: `RKT_${stamp.toUpperCase()}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const getAs = (token, path, headers = {}) =>
    request(app).get(path).set('Authorization', `Bearer ${token}`).set(headers);

  test('三个审计读取端点：无票据 → 401 REAUTH_TICKET_REQUIRED', async () => {
    for (const path of [
      '/api/security/alerts',
      '/api/security/audit-logs?limit=1',
      '/api/security/audit-logs/export?limit=1',
    ]) {
      const res = await getAs(readerToken, path);
      expect({ path, status: res.status, code: res.body.errors?.errorCode }).toEqual({
        path,
        status: 401,
        code: 'REAUTH_TICKET_REQUIRED',
      });
    }
  });

  test('票据绑定：他人票据 / 他会话票据 → 401 REAUTH_TICKET_INVALID', async () => {
    const foreign = issueReauthTicket({ userId: 'not-this-user', sessionId: `reader-${stamp}` });
    const otherSession = issueReauthTicket({ userId: readerUserId, sessionId: 'another-session' });

    for (const ticket of [foreign.ticket, otherSession.ticket, 'forged.ticket']) {
      const res = await getAs(readerToken, '/api/security/alerts', { 'X-Reauth-Ticket': ticket });
      expect(res.status).toBe(401);
      expect(res.body.errors.errorCode).toBe('REAUTH_TICKET_INVALID');
    }
  });

  test('POST /reauth：缺凭据 403 / 口令错误 403 / 口令正确签发可复用 5 分钟的票据', async () => {
    const missing = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${readerToken}`)
      .send({});
    expect(missing.status).toBe(403);
    expect(missing.body.errors.errorCode).toBe('REAUTH_REQUIRED');

    const wrong = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${readerToken}`)
      .send({ currentPassword: `${readerPassword}x` });
    expect(wrong.status).toBe(403);
    expect(wrong.body.errors.errorCode).toBe('REAUTH_PASSWORD_INCORRECT');

    const ok = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${readerToken}`)
      .send({ currentPassword: readerPassword });
    expect(ok.status).toBe(200);
    const { ticket, expiresIn } = ok.body.data;
    expect(typeof ticket).toBe('string');
    expect(expiresIn).toBe(REAUTH_TICKET_TTL_MS / 1000);

    // 票据可在 TTL 内复用，三个受保护读取端点都放行
    for (const path of [
      '/api/security/alerts',
      '/api/security/audit-logs?limit=1',
      '/api/security/audit-logs/export?limit=1',
    ]) {
      const res = await getAs(readerToken, path, { 'X-Reauth-Ticket': ticket });
      expect({ path, status: res.status }).toEqual({ path, status: 200 });
    }
  });

  test('管理员写操作：无凭据不得触达控制器（403 REAUTH_REQUIRED）', async () => {
    const config = await request(app)
      .put('/api/security/config/loginCaptchaEnabled')
      .set('Authorization', `Bearer ${writerToken}`)
      .send({ loginCaptchaEnabled: true });
    expect(config.status).toBe(403);
    expect(config.body.errors.errorCode).toBe('REAUTH_REQUIRED');

    const reset = await request(app)
      .put(`/api/security/users/${victimId}/mfa/reset`)
      .set('Authorization', `Bearer ${writerToken}`)
      .send({});
    expect(reset.status).toBe(403);
    expect(reset.body.errors.errorCode).toBe('REAUTH_REQUIRED');
  });

  test('管理员写操作：当场通过二次验证后放行（配置 200 / MFA 重置进入业务分支）', async () => {
    const config = await request(app)
      .put('/api/security/config/loginCaptchaEnabled')
      .set('Authorization', `Bearer ${writerToken}`)
      .send({ loginCaptchaEnabled: true, currentPassword: writerPassword });
    expect(config.status).toBe(200);

    // 目标未开启 MFA ⇒ 控制器 400；这里只证明 step-up 已通过（不再是 403 REAUTH_*）
    const reset = await request(app)
      .put(`/api/security/users/${victimId}/mfa/reset`)
      .set('Authorization', `Bearer ${writerToken}`)
      .send({ currentPassword: writerPassword });
    expect(reset.status).toBe(400);
    expect(reset.body.errors?.errorCode).not.toMatch(/^REAUTH_/);
  });

  test('测试助手票据与生产签发同口径（防止测试绕过校验）', () => {
    const headers = reauthHeaders(readerToken);
    const ticket = headers['X-Reauth-Ticket'];
    const decoded = jwt.decode(readerToken);
    expect(verifyReauthTicket(ticket, { userId: decoded.userId, sessionId: decoded.jti })).toBe(
      true
    );
  });
});

describe('T-2：签发控制器的会话绑定分支（分支覆盖 50% 的那一格）', () => {
  /**
   * `req.user.sessionId ?? null` 是控制器里唯一的真实分支：
   * 令牌没有 sid（改造前签发的存量令牌 / 未走设备会话的调用方）时，
   * 票据必须按「未绑定会话」签发——即 null 只能匹配 null，不能退化成"任何会话都认"。
   * 该分支此前无任何用例，覆盖率停在 50%（2026-10-25 七维审计 T-2）。
   */
  const fakeRes = () => {
    const captured = {};
    const res = {
      status(code) {
        captured.status = code;
        return res;
      },
      json(body) {
        captured.body = body;
        return res;
      },
    };
    return { res, captured };
  };

  test('令牌无 sessionId：按未绑定会话签发，且不认任何具体会话', async () => {
    const { issueReauthTicket: handler } = require('../../controllers/securityController/reauth');
    const { res, captured } = fakeRes();
    await handler({ user: { userId: `nosid-${stamp}` } }, res);

    expect(captured.status).toBe(200);
    const { ticket } = captured.body.data;
    expect(verifyReauthTicket(ticket, { userId: `nosid-${stamp}`, sessionId: null })).toBe(true);
    // 反向：绑定 null 的票据不得被某个具体会话冒用
    expect(verifyReauthTicket(ticket, { userId: `nosid-${stamp}`, sessionId: 'sid-x' })).toBe(
      false
    );
  });

  test('令牌带 sessionId：票据绑定该会话，换个 sid 即失败', async () => {
    const { issueReauthTicket: handler } = require('../../controllers/securityController/reauth');
    const { res, captured } = fakeRes();
    await handler({ user: { userId: `withsid-${stamp}`, sessionId: 'sid-y' } }, res);

    const { ticket } = captured.body.data;
    expect(verifyReauthTicket(ticket, { userId: `withsid-${stamp}`, sessionId: 'sid-y' })).toBe(
      true
    );
    expect(verifyReauthTicket(ticket, { userId: `withsid-${stamp}`, sessionId: 'sid-z' })).toBe(
      false
    );
  });
});
