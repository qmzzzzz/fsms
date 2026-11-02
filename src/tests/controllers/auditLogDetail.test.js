/**
 * GET /api/security/audit-logs/:id 单条详情
 *
 * 列表投影（RESPONSE_EXCLUDE）刻意不含 body/params/query 与请求/响应头袋、
 * 响应正文；本端点是详情页唯一的完整记录来源。覆盖行为面：
 * 完整字段下发（含新采集的头袋与响应正文）、hmac 不外泄、数据范围（self 档
 * 越权点查与不存在同为 404）、缺票闸与非法 ID。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { TEST_CLIENT_IP } = require('../fixtures');
const { reauthHeaders } = require('../helpers/reauthTicket');

describe('GET /api/security/audit-logs/:id 单条详情', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let admin;
  let adminToken;
  let selfUser;
  let selfToken;
  let ownLogId;
  let foreignLogId;

  const suffix = Date.now().toString(36);
  const tokenFor = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '6h' }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    const AuditLog = require('../../models/AuditLog');

    const auditPerm = await Permission.findOneAndUpdate(
      { code: 'security:audit' },
      {
        $setOnInsert: { name: '审计日志', code: 'security:audit', type: 'api', module: 'security' },
      },
      { upsert: true, new: true }
    );

    const adminRole = await Role.create({
      name: `审计详情超管_${suffix}`,
      code: `AUDIT_DETAIL_ADMIN_${suffix}`,
      level: 10,
      permissions: [auditPerm._id],
    });
    admin = await User.create({
      username: `audit_detail_admin_${suffix}`,
      email: `audit_detail_admin_${suffix}@example.com`,
      password: 'Test@1234567',
      roles: [adminRole._id],
    });
    adminToken = tokenFor(admin);

    // level 4 ⇒ self 数据范围：只能看到 userId 等于自己的审计记录
    const selfRole = await Role.create({
      name: `审计详情自查_${suffix}`,
      code: `AUDIT_DETAIL_SELF_${suffix}`,
      level: 4,
      permissions: [auditPerm._id],
    });
    selfUser = await User.create({
      username: `audit_detail_self_${suffix}`,
      email: `audit_detail_self_${suffix}@example.com`,
      password: 'Test@1234567',
      roles: [selfRole._id],
    });
    selfToken = tokenFor(selfUser);

    ownLogId = new mongoose.Types.ObjectId();
    foreignLogId = new mongoose.Types.ObjectId();
    const base = {
      category: 'user',
      ip: TEST_CLIENT_IP,
      success: true,
      riskLevel: 'high',
      method: 'POST',
      path: '/api/users/x',
      timestamp: new Date(),
      hashVersion: 6,
      prevHash: null,
      hash: 'a'.repeat(64),
      // hmac 是完整性签名的副产物，详情接口不得下发
      hmac: 'hmac-must-not-leak',
    };
    await AuditLog.collection.insertMany([
      {
        ...base,
        _id: ownLogId,
        action: 'user_delete',
        userId: selfUser._id,
        username: selfUser.username,
        body: { password: '***', keep: 'trace-me' },
        params: { id: 'u-1' },
        query: { token: '***', next: '/users' },
        requestHeaders: { authorization: '***', 'content-type': 'application/json' },
        responseHeaders: { 'content-type': 'application/json; charset=utf-8' },
        responseBody: { ok: true, recoveryCodes: '***' },
        responseBodyTruncated: true,
        responseBodySkipped: 'stream',
        clientInfo: { browser: 'Chrome 140', reportedIp: TEST_CLIENT_IP, socketPeer: '127.0.0.1' },
        fingerprint: 'fp-trace',
        sessionId: 'sess-trace',
      },
      {
        ...base,
        _id: foreignLogId,
        action: 'auth_login',
        userId: admin._id,
        username: admin.username,
        body: { password: '***' },
      },
    ]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const getDetail = (id, token = adminToken, withTicket = true) => {
    const req = request(app)
      .get(`/api/security/audit-logs/${id}`)
      .set('Authorization', `Bearer ${token}`);
    if (withTicket) req.set(reauthHeaders(token));
    return req;
  };

  test('返回完整记录：请求体/头袋/响应正文/客户端与链字段，hmac 不外泄', async () => {
    const res = await getDetail(ownLogId);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const doc = res.body.data;

    expect(doc.body).toEqual({ password: '***', keep: 'trace-me' });
    expect(doc.params).toEqual({ id: 'u-1' });
    expect(doc.query).toEqual({ token: '***', next: '/users' });
    expect(doc.requestHeaders).toEqual({
      authorization: '***',
      'content-type': 'application/json',
    });
    expect(doc.responseHeaders).toEqual({
      'content-type': 'application/json; charset=utf-8',
    });
    expect(doc.responseBody).toEqual({ ok: true, recoveryCodes: '***' });
    expect(doc.responseBodyTruncated).toBe(true);
    expect(doc.responseBodySkipped).toBe('stream');
    expect(doc.clientInfo).toEqual({
      browser: 'Chrome 140',
      reportedIp: TEST_CLIENT_IP,
      socketPeer: '127.0.0.1',
    });
    expect(doc.fingerprint).toBe('fp-trace');
    expect(doc.sessionId).toBe('sess-trace');
    expect(doc.hashVersion).toBe(6);
    expect(doc.hash).toBe('a'.repeat(64));
    // userId 被 populate 成对象，详情页不再显示 [object Object]
    expect(doc.userId.username).toBe(selfUser.username);
    // 归属地是可选增强字段：键必须在，值随 IP 段而定
    expect('location' in doc).toBe(true);

    // hmac/__v 是服务端内部副产物，不得经详情接口外泄
    expect(doc.hmac).toBeUndefined();
    expect(doc.__v).toBeUndefined();
  });

  test('数据范围：self 档可读自己的记录，点查他人记录与不存在同为 404（不泄露存在性）', async () => {
    const own = await getDetail(ownLogId, selfToken);
    expect(own.status).toBe(200);
    expect(own.body.data._id).toBe(String(ownLogId));

    const foreign = await getDetail(foreignLogId, selfToken);
    expect(foreign.status).toBe(404);
    expect(foreign.body.errors?.errorCode).toBe('AUDIT_LOG_NOT_FOUND');

    const missing = await getDetail(new mongoose.Types.ObjectId(), selfToken);
    expect(missing.status).toBe(404);
    expect(missing.body.errors?.errorCode).toBe('AUDIT_LOG_NOT_FOUND');
  });

  test('缺二次验证票据：401 REAUTH_TICKET_REQUIRED（权限码与参数校验之后）', async () => {
    const res = await getDetail(ownLogId, adminToken, false);
    expect(res.status).toBe(401);
    expect(res.body.errors?.errorCode).toBe('REAUTH_TICKET_REQUIRED');
  });

  test('非法 _id：400，不当作「记录不存在」', async () => {
    const res = await getDetail('not-an-object-id');
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });
});
