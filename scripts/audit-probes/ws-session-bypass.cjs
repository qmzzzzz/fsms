#!/usr/bin/env node
/**
 * P0-2 复现探针：WebSocket 会话吊销 / IP 白名单双绕过
 *
 * 断言（人工判读，非自动化测试）：同一 JWT 在 HTTP 侧被 403
 * （AUTH_IP_RANGE_DENIED），却在 WebSocket 侧认证成功——
 * authenticateSocket 不校验 sid（设备会话状态）与 allowedIPs。
 *
 * 本文件由根目录 .audit-e2e-ws5.cjs 迁移而来（P1-30）：原探针位于被忽略的
 * .audit-* 文件中，唯一可复现 P0-2 的脚本不能随临时文件一起消失。
 *
 * 2026-09-17 复核：P0-2 修复已落地（websocketService 新增
 * _assertHandshakeSessionUsable / _assertHandshakeIpAllowed，在 authenticateSocket
 * 内于密码修改校验之后调用），本脚本实测结论已变为「✅ 未通过」。
 * 自动化回归已由 src/tests/services/websocketAuthScope.test.js 承接；本脚本
 * 保留作为可脱离 Jest 运行的人工复核工具（端到端 socket.io 握手路径）。
 */
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'x'.repeat(48);
process.env.JWT_REFRESH_SECRET = 'y'.repeat(48);
process.env.AES_SECRET_KEY = 'z'.repeat(48);
process.env.HMAC_SECRET = 'h'.repeat(48);
process.env.LOG_LEVEL = 'error';

const http = require('http');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

/** 建库 + 造数：一个 allowedIPs=10.0.0.0/8 的用户，会话已吊销，令牌 sid 指向该吊销会话 */
async function seed() {
  const mongod = await MongoMemoryServer.create({ instance: { dbName: 'p9' } });
  await mongoose.connect(mongod.getUri('p9'));
  const User = require('../../src/models/User');
  const Role = require('../../src/models/Role');
  const Permission = require('../../src/models/Permission');
  const UserSession = require('../../src/models/UserSession');
  require('../../src/models/TokenBlacklist');
  require('../../src/models/AuditLog');
  require('../../src/models/SystemConfig');
  const app = require('../../src/app').createApp();

  const p = await Permission.create({
    name: '设备读',
    code: 'device:read',
    type: 'api',
    module: 'device',
  });
  const rr = await Role.create({
    name: 'ADMIN',
    code: 'ADMIN',
    level: 9,
    status: 'active',
    permissions: [p._id],
  });
  const u = await User.create({
    username: 'wsuser',
    email: 'ws@t.com',
    password: 'WsPass@123456',
    status: 'active',
    department: '东区',
    roles: [rr._id],
    tokenVersion: 0,
    allowedIPs: '10.0.0.0/8',
  });
  await UserSession.create({
    sid: 'SID-REVOKED',
    userId: u._id,
    status: 'revoked',
    ip: '1.2.3.4',
    userAgent: 'probe',
    expiresAt: new Date(Date.now() + 86400000),
    revokedAt: new Date(),
    revokeReason: 'probe',
  });
  const token = jwt.sign(
    {
      userId: String(u._id),
      username: u.username,
      email: u.email,
      roles: ['ADMIN'],
      tokenVersion: 0,
      jti: 'j',
      sid: 'SID-REVOKED',
    },
    process.env.JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h' }
  );
  return { mongod, app, token };
}

/** 启动带 WS 服务的 HTTP server，返回端口与 WebSocketService 实例 */
async function startServer(app) {
  const server = http.createServer(app);
  const WebSocketService = require('../../src/services/websocketService');
  const wsvc = new WebSocketService(server);
  await new Promise((r) => server.listen(0, r));
  return { port: server.address().port, wsvc };
}

/** 轮询式 HTTP 客户端（socket.io over polling 需要手工构造帧） */
function makeClients(port) {
  const H = { Origin: 'http://localhost:3001' };
  const get = (path) =>
    new Promise((resolve) => {
      http
        .request({ host: '127.0.0.1', port, path, method: 'GET', headers: H }, (res) => {
          let d = '';
          res.on('data', (c) => (d += c));
          res.on('end', () => resolve({ status: res.statusCode, body: d }));
        })
        .on('error', (e) => resolve({ status: 0, body: 'ERR ' + e.message }))
        .end();
    });
  const post = (path, body) =>
    new Promise((resolve) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          path,
          method: 'POST',
          headers: {
            ...H,
            'Content-Type': 'text/plain;charset=UTF-8',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (res) => {
          let d = '';
          res.on('data', (c) => (d += c));
          res.on('end', () => resolve({ status: res.statusCode, body: d }));
        }
      );
      req.on('error', (e) => resolve({ status: 0, body: 'ERR ' + e.message }));
      req.write(body);
      req.end();
    });
  return { get, post };
}

/** 完成一次 socket.io v4 轮询握手，返回 engine.io sid 与轮询响应 */
async function handshake(clients, token) {
  const hs = await clients.get('/socket.io/?EIO=4&transport=polling&t=' + Date.now());
  const eioSid = (hs.body.match(/"sid":"([^"]+)"/) || [])[1];
  console.log('  1. engine.io open ->', hs.status, 'eioSid=' + eioSid);

  // CONNECT 帧的 auth 载荷携带 token（socket.io v4 标准做法）
  const connectFrame = '40' + JSON.stringify({ token });
  const c1 = await clients.post('/socket.io/?EIO=4&transport=polling&sid=' + eioSid, connectFrame);
  console.log(
    '  2. CONNECT 帧(带 auth.token) ->',
    c1.status,
    '| resp:',
    JSON.stringify(c1.body).slice(0, 90)
  );
  const poll1 = await clients.get(
    '/socket.io/?EIO=4&transport=polling&sid=' + eioSid + '&t=' + Date.now()
  );
  console.log(
    '  3. 立即轮询 ->',
    poll1.status,
    '| 下行帧:',
    JSON.stringify(poll1.body).slice(0, 120)
  );
  return eioSid;
}

/** 读服务端连接状态并打印结论行 */
async function report(wsvc, clients, eioSid) {
  await new Promise((r) => setTimeout(r, 800));
  const entry = [...wsvc.clients.values()][0];
  console.log('\n=== 服务端 socket 状态 ===');
  console.log('  clients 条数 =', wsvc.clients.size);
  console.log('  authenticated =', entry && entry.authenticated);
  console.log('  entry.userId  =', entry && entry.userId);
  console.log(
    '  服务端已绑定 socket.userId =',
    entry && entry.userId ? '✅ 已绑定（= 认证通过）' : '未绑定'
  );
  console.log('  绑定到 userConnections 的 userId 数 =', wsvc.userConnections.size);

  const passed = entry && entry.userId;
  const extraPoll = await clients.get(
    '/socket.io/?EIO=4&transport=polling&sid=' + eioSid + '&t=' + Date.now()
  );
  console.log(
    '  连接是否仍存活（轮询返回非 4xx）:',
    extraPoll.status,
    JSON.stringify(extraPoll.body).slice(0, 80)
  );
  console.log(
    '\n  ⮕ 结论: ' +
      (passed
        ? '❌❌ 确认绕过 —— WS 认证未校验 sid（已吊销会话）也未校验 allowedIPs，同一 token 在 HTTP 被 403、在 WS 却认证成功'
        : '✅ 未通过 —— WS 认证已拒绝（P0-2 修复生效；详见上方 auth-error 帧')
  );
}

async function main() {
  const { mongod, app, token } = await seed();
  const { port, wsvc } = await startServer(app);
  const clients = makeClients(port);

  console.log('=== 前置条件（两条独立的失效信号，HTTP 侧均已拒绝）===');
  console.log('  1) allowedIPs = "10.0.0.0/8"，探测源 IP = 127.0.0.1（不在白名单）');
  console.log('  2) 会话 SID-REVOKED.status = "revoked"（设备会话已吊销）');
  const rh = await request(app)
    .get('/api/devices')
    .set('Authorization', 'Bearer ' + token);
  console.log(
    '  HTTP 对照 GET /api/devices ->',
    rh.status,
    '(' + (rh.body?.errors?.errorCode || '') + ')'
  );

  console.log('\n=== WebSocket 完整握手（socket.io v4 over polling）===');
  const eioSid = await handshake(clients, token);
  await report(wsvc, clients, eioSid);

  wsvc.dispose();
  await mongoose.connection.db.dropDatabase();
  await mongoose.disconnect();
  await mongod.stop();
  process.exit(0);
}

main().catch((e) => {
  console.error('ERR', e.stack);
  process.exit(1);
});
