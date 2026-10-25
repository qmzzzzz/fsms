#!/usr/bin/env node
/**
 * P0-2 复现探针：WebSocket 会话吊销 / IP 白名单双绕过
 *
 * 断言（**退出码即结论**，不再依赖人工读输出）：同一 JWT 在 HTTP 侧因某一条规则
 * 被拒，在 WebSocket 侧也必须因**同一条**规则被拒——authenticateSocket 曾经既不校验
 * sid（设备会话状态）也不校验 allowedIPs。
 *
 * 退出码：
 *   0 = 全部场景已拒，且每个场景都拿到**理由匹配**的 `auth-error` 帧
 *   1 = 确认绕过（socket 绑上了该场景用户的 userId）
 *   2 = 不可判定：没绑上 userId 但没看到 auth-error、或 auth-error 的理由对不上、
 *       或 HTTP 侧前置对照没按预期被拒。这些都不构成"修复生效"的证据。
 *
 * ## 为什么必须是两个场景（2026-10-24 修复）
 *
 * 原实现只用一个令牌，**同时**带「已吊销会话」与「非白名单 IP」两条违规，判据是
 * "收到任何 auth-error 就算拒绝"。于是它只证明了**至少一条**控制在生效：
 * 有人把 sid 校验删掉、只留 IP 校验，探针照样 exit 0 报"P0-2 修复在位"。
 * 一个只能证明"至少一条"的探针，对一个有两条独立控制项的漏洞是无效证据。
 *
 * 现在拆成两个**单违规**场景，各自要求"理由匹配"的拒绝帧：
 *   session_revoked  会话已吊销 + IP 不限制   → 必须因「设备会话已失效」被拒
 *   ip_not_allowed   会话正常   + IP 不在白名单 → 必须因「IP 范围」被拒
 * 任一条控制被摘掉，对应场景立刻变红。
 *
 * 归因靠 auth-error 的 message 文本（服务端帧里没有错误码，这是唯一通道）。
 * 文案改动会让探针落到「不可判定」而不是「通过」——这正是要的：探针说不出
 * "是哪条控制拒的"时，它就没有资格宣布那条控制在位。
 *
 * ## 历史
 *
 * 本文件由根目录 .audit-e2e-ws5.cjs 迁移而来（P1-30）：原探针位于被忽略的
 * .audit-* 文件中，唯一可复现 P0-2 的脚本不能随临时文件一起消失。
 * 2026-09-17 复核 P0-2 修复已落地（websocketService 新增
 * _assertHandshakeSessionUsable / _assertHandshakeIpAllowed）；自动化回归由
 * src/tests/services/websocketAuthScope.test.js 承接，本脚本保留作为可脱离 Jest
 * 运行的人工复核工具（端到端 socket.io 握手路径）。
 */
const http = require('http');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

/**
 * 两个**单违规**场景。`http` 是前置对照的期望（状态码 + 错误码），
 * `ws` 是 WS 侧期望的拒绝理由（正则 + 人读标签）。
 *
 * 选码依据（不是猜的）：
 *   - 会话吊销：middleware/auth.js:401 → DEVICE_SESSION_REVOKED（401）
 *   - IP 白名单：middleware/auth.js:376 → AUTH_IP_RANGE_DENIED（403）
 *   - WS 文案：handshake.js:558「该设备会话已失效，请重新登录」
 *             handshake.js:464「当前网络不在允许的 IP 范围内」
 * 顺序上 HTTP 侧 IP 校验（auth.js:236）先于会话校验（auth.js:239），故两个场景各自
 * 只会命中自己那条规则：A 的 allowedIPs 为空（跳过 IP 校验），B 的会话为 active。
 */
const SCENARIOS = [
  {
    key: 'session_revoked',
    title: '会话已吊销（IP 不限制）',
    sid: 'SID-REVOKED',
    sessionStatus: 'revoked',
    allowedIPs: '',
    http: { status: 401, code: 'DEVICE_SESSION_REVOKED' },
    ws: { pattern: /设备会话已失效/, label: '设备会话已失效' },
  },
  {
    key: 'ip_not_allowed',
    title: 'IP 不在白名单（会话正常）',
    sid: 'SID-ACTIVE',
    sessionStatus: 'active',
    allowedIPs: '10.0.0.0/8',
    http: { status: 403, code: 'AUTH_IP_RANGE_DENIED' },
    ws: { pattern: /IP 范围/, label: '当前网络不在允许的 IP 范围内' },
  },
];

/** 建库 + 造数：每个场景一个用户，只带本场景那一条违规 */
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

  const tokens = {};
  const userIds = {};
  for (const s of SCENARIOS) {
    const u = await User.create({
      username: 'wsprobe_' + s.key,
      email: s.key + '@t.com',
      password: 'WsPass@123456',
      status: 'active',
      department: '东区',
      roles: [rr._id],
      tokenVersion: 0,
      allowedIPs: s.allowedIPs,
    });
    await UserSession.create({
      sid: s.sid,
      userId: u._id,
      status: s.sessionStatus,
      ip: '1.2.3.4',
      userAgent: 'probe',
      expiresAt: new Date(Date.now() + 86400000),
      ...(s.sessionStatus === 'revoked' ? { revokedAt: new Date(), revokeReason: 'probe' } : {}),
    });
    tokens[s.key] = jwt.sign(
      {
        userId: String(u._id),
        username: u.username,
        email: u.email,
        roles: ['ADMIN'],
        tokenVersion: 0,
        jti: 'j-' + s.key,
        sid: s.sid,
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );
    userIds[s.key] = String(u._id);
  }
  return { mongod, app, tokens, userIds };
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
  const send = (method, path, body) =>
    new Promise((resolve) => {
      const headers = { ...H };
      if (body !== undefined) {
        headers['Content-Type'] = 'text/plain;charset=UTF-8';
        headers['Content-Length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => resolve({ status: res.statusCode, body: d }));
      });
      req.on('error', (e) => resolve({ status: 0, body: 'ERR ' + e.message }));
      if (body !== undefined) req.write(body);
      req.end();
    });
  return { get: (path) => send('GET', path), post: (path, body) => send('POST', path, body) };
}

/** 完成一次 socket.io v4 轮询握手，返回 engine.io sid 与已收到的下行帧（判据要用） */
async function handshake(clients, token) {
  const frames = [];
  const hs = await clients.get('/socket.io/?EIO=4&transport=polling&t=' + Date.now());
  const eioSid = (hs.body.match(/"sid":"([^"]+)"/) || [])[1];
  frames.push(hs.body);
  console.log('  1. engine.io open ->', hs.status, 'eioSid=' + eioSid);

  // CONNECT 帧的 auth 载荷携带 token（socket.io v4 标准做法）
  const connectFrame = '40' + JSON.stringify({ token });
  const c1 = await clients.post('/socket.io/?EIO=4&transport=polling&sid=' + eioSid, connectFrame);
  frames.push(c1.body);
  console.log(
    '  2. CONNECT 帧(带 auth.token) ->',
    c1.status,
    '| resp:',
    JSON.stringify(c1.body).slice(0, 90)
  );
  const poll1 = await clients.get(
    '/socket.io/?EIO=4&transport=polling&sid=' + eioSid + '&t=' + Date.now()
  );
  frames.push(poll1.body);
  console.log(
    '  3. 立即轮询 ->',
    poll1.status,
    '| 下行帧:',
    JSON.stringify(poll1.body).slice(0, 120)
  );
  return { eioSid, frames: frames.join(' ') };
}

/**
 * 判据（纯函数，便于自证）：把"人工读输出"变成可机判的三态。
 *
 * 三条独立要求，缺一条就落到 inconclusive（**不得**判成通过）：
 *
 *   ① 没绑上 userId —— 这是"没绕过"的必要条件，但不充分：握手根本没走到
 *      authenticateSocket（engine.io 路径变了、CONNECT 帧格式换了、探针自己写错）
 *      时同样没有 userId。
 *   ② 服务端确实回了 `auth-error` 帧 —— 拒绝是"认证逻辑做的"，不是"握手没发生"。
 *   ③ 拒绝理由与本场景期望的那条控制**匹配** —— 否则只证明了"某处拒了"。
 *      ③ 是本轮修复的核心：原判据在②处就收工，于是一个同时带两条违规的令牌
 *      会让"只修好一条"也报成"两条都在位"。
 *
 * @param {{boundUserId?: string|null, downstream: string, expected?: {pattern: RegExp, label: string}}} observed
 * @returns {{state: 'bypass'|'rejected'|'inconclusive', code: number, why: string}}
 */
function decideVerdict(observed) {
  const downstream = String(observed.downstream || '');
  if (observed.boundUserId) {
    return {
      state: 'bypass',
      code: 1,
      why:
        '❌❌ 确认绕过 —— WS 侧认证通过了（socket 已绑定 userId=' +
        observed.boundUserId +
        '），而同一 token 在 HTTP 侧被拒：本场景那条控制没生效',
    };
  }
  if (!/auth-error/.test(downstream)) {
    return {
      state: 'inconclusive',
      code: 2,
      why:
        '⚠ 不可判定 —— 既没绑上 userId，也没看到 auth-error 帧。' +
        '可能是握手层变了（engine.io 路径/CONNECT 帧格式）导致请求没走到 authenticateSocket；' +
        '此时"没绑上"不构成"P0-2 已修复"的证据，请改判据而不是宣布通过',
    };
  }
  const expected = observed.expected;
  if (!expected || !expected.pattern) {
    return {
      state: 'inconclusive',
      code: 2,
      why:
        '⚠ 不可判定 —— 收到了 auth-error，但调用方没有声明本场景期望的拒绝理由，' +
        '无法归因是哪条控制在生效。拒绝必须可归因才算是该控制的证据',
    };
  }
  if (!expected.pattern.test(downstream)) {
    return {
      state: 'inconclusive',
      code: 2,
      why:
        '⚠ 不可判定 —— 收到了 auth-error，但理由不是本场景期望的「' +
        expected.label +
        '」。可能是另一条控制先命中、或文案已改；两种都说明本场景这条控制' +
        '**没有被证明在位**（旧判据在这里会误判为 ✅ 通过）',
    };
  }
  return {
    state: 'rejected',
    code: 0,
    why: '✅ 已拒且理由匹配 —— 服务端回了 auth-error 帧，且正是「' + expected.label + '」',
  };
}

/**
 * 观察服务端状态：本场景用户是否被绑定，以及握手期间的下行帧。
 *
 * 不取 `[...clients.values()][0]`：同一进程里跑多个场景时，第一个条目可能是
 * 上一场景的残留，或是一条未认证的占位条目。按 userId 精确匹配才是要判的事实。
 */
async function observe(wsvc, clients, session, userId) {
  await new Promise((r) => setTimeout(r, 800));
  const bound = [];
  for (const entry of wsvc.clients.values()) {
    if (entry && entry.userId && String(entry.userId) === String(userId)) {
      bound.push(String(entry.userId));
    }
  }
  console.log(
    '  4. 服务端状态 -> clients 条数 =',
    wsvc.clients.size,
    '| 本场景 userId 已绑定的连接数 =',
    bound.length
  );
  const extraPoll = await clients.get(
    '/socket.io/?EIO=4&transport=polling&sid=' + session.eioSid + '&t=' + Date.now()
  );
  console.log(
    '  5. 连接是否仍存活（轮询状态）->',
    extraPoll.status,
    '| 帧:',
    JSON.stringify(extraPoll.body).slice(0, 110)
  );
  return { boundUserId: bound[0] || null, downstream: session.frames + ' ' + extraPoll.body };
}

/** 跑一个场景：HTTP 前置对照 → WS 握手 → 观察 → 判据 */
async function runScenario(ctx, scenario) {
  console.log('\n=== 场景 ' + scenario.key + '：' + scenario.title + ' ===');
  const token = ctx.tokens[scenario.key];
  const userId = ctx.userIds[scenario.key];

  // 前置对照：同一令牌必须在 HTTP 侧因**本场景那一条**规则被拒。
  // 不校验这一条的话，一个 500 或"因别的原因 401"也会被当成有效对照——
  // 那时 WS 侧的"被拒"同样无法归因。
  const rh = await request(ctx.app)
    .get('/api/devices')
    .set('Authorization', 'Bearer ' + token);
  const httpCode = rh.body?.errors?.errorCode || '';
  const httpOk = rh.status === scenario.http.status && httpCode === scenario.http.code;
  console.log(
    '  HTTP 对照 GET /api/devices ->',
    rh.status,
    '(' + (httpCode || '—') + ')',
    httpOk ? '✓' : '⚠ 与期望不符'
  );
  if (!httpOk) {
    return {
      scenario,
      verdict: {
        state: 'inconclusive',
        code: 2,
        why:
          '⚠ 前置对照不成立 —— HTTP 侧期望 ' +
          scenario.http.status +
          '/' +
          scenario.http.code +
          '，实际 ' +
          rh.status +
          '/' +
          (httpCode || '—') +
          '。同一令牌在 HTTP 侧不是因本场景那条规则被拒，WS 侧的"被拒"就无法归因',
      },
    };
  }

  const session = await handshake(ctx.clients, token);
  const observed = await observe(ctx.wsvc, ctx.clients, session, userId);
  const verdict = decideVerdict({ ...observed, expected: scenario.ws });
  console.log('  ⮕ ' + verdict.why);
  return { scenario, verdict };
}

// 环境设置放进 main()：模块级赋值会让"只 require 判据做单测"的调用方被污染
// （jest 同一 worker 里 process.env 是共享的，探针写死 JWT_SECRET 会影响后续套件）。
async function main() {
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'x'.repeat(48);
  process.env.JWT_REFRESH_SECRET = 'y'.repeat(48);
  process.env.AES_SECRET_KEY = 'z'.repeat(48);
  process.env.HMAC_SECRET = 'h'.repeat(48);
  process.env.LOG_LEVEL = 'error';

  const { mongod, app, tokens, userIds } = await seed();
  const { port, wsvc } = await startServer(app);
  const clients = makeClients(port);
  const ctx = { app, tokens, userIds, wsvc, clients };

  console.log('=== 前置条件 ===');
  console.log('  探测源 IP = 127.0.0.1；两个场景各只带一条违规（见文件头）');

  const results = [];
  for (const scenario of SCENARIOS) {
    results.push(await runScenario(ctx, scenario));
  }

  console.log('\n=== 汇总 ===');
  for (const { scenario, verdict } of results) {
    console.log('  ' + scenario.key.padEnd(16) + verdict.state.padEnd(14) + 'exit=' + verdict.code);
  }

  let code = 0;
  if (results.some((r) => r.verdict.state === 'bypass')) code = 1;
  else if (results.some((r) => r.verdict.state === 'inconclusive')) code = 2;

  wsvc.dispose();
  await mongoose.connection.db.dropDatabase();
  await mongoose.disconnect();
  await mongod.stop();
  // 退出码即结论：0 = 两个场景都已拒且理由匹配；1 = 至少一条确认绕过；2 = 有场景不可判定
  console.log('[PROBE] verdict=' + results.map((r) => r.verdict.state).join(',') + ' exit=' + code);
  process.exit(code);
}

// 仅在直接执行时跑探针；被 require（回归测试只核 decideVerdict 的真值表）时不得建库、不得退出。
if (require.main === module) {
  main().catch((e) => {
    // 探针自己跑挂了 ≠ 漏洞存在。必须与「确认绕过」(1) 分开，
    // 否则一次依赖/环境故障会被读成"复现成功"，或反过来把崩溃当成结论。
    console.error('[PROBE] 执行失败（不可判定，非漏洞结论）：' + e.stack);
    process.exit(2);
  });
}

module.exports = { decideVerdict, SCENARIOS };
