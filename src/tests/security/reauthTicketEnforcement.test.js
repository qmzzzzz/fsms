/* ===== 附录（2026-10-31 注释密度治理迁出）：src/services/reauthGrantStore.js 的原委 =====
 * * 会话级二次验证窗口（配合 models/ReauthGrant）
 * *
 * * 语义：POST /security/reauth 成功 ⇒ 为该会话开一个 5 分钟窗口；窗口内受保护读取
 * * 只需有效访问令牌，不再需要票据。票据（一次性）保留给无会话的 API 客户端。
 * *
 * * 方向选择：
 * *   · 记录失败 ⇒ **fail-open 到票据路径**（不抛错）。这里判的是"要不要再要求一次
 * *     step-up"，而读取端点本身仍有权限码 + 数据范围两道门；写库失败时把用户挡在门外
 * *     只会制造"审计页永远打不开"的故障，而不会阻止任何越权（越权者的令牌本来就过不了
 * *     权限码）。与票据消费那条 fail-closed 的区别：那里丢的是**唯一性判据**，这里丢的
 * *     只是**便利**。
 * *   · 查询失败（存储不可用）同理：按"没有窗口"处理，请求会拿到 REAUTH_TICKET_REQUIRED
 * *     并重新 step-up——仍然安全，只是多一次验证。
 *
 * 迁出理由：NEW_FILE_MAX=0.30 的密度上限；正文约束在源码一行内保留，完整权衡留在这里。
 */

/* ===== 附录（2026-10-31 注释密度治理迁出）：src/models/ReauthGrant.js 的原委 =====
 * * 二次验证「已通过」的会话级凭据（sudo 窗口）。
 * *
 * * 为什么需要它（2026-10-31，审计一-3 的第二半）：
 * * 票据被改成一次性消费之后，前端每发一个受保护读取都要重新输一遍口令——审计页一次
 * * 首屏就是三条请求（列表 + 告警 + 导出），等于每点一次筛选弹一次密码框。于是把
 * * 「刚通过 step-up」记在**服务端**、按**会话**绑定，而不是让客户端继续拿一件
 * * 可重放的 bearer 凭据：
 * *   · 浏览器侧不再持有任何可重放的凭据（票据只留给无会话的 API 客户端，且一次性）；
 * *   · 窗口仍然是 5 分钟（与票据同长），到期由 TTL 索引清掉，不续期；
 * *   · 绑定 sid：换设备/换会话即失效（authenticate 先行拒绝，本条无从单独使用）。
 * *
 * * 判据的代价：窗口内任何**持有该会话访问令牌**的人都能读审计——这与「登录后即可读
 * * 自己有权限的数据」同阶，且比"客户端存一张 5 分钟有效的票据"严格：票据一旦泄漏，
 * * 攻击者不需要令牌也能……不，票据本身仍要通过 authenticate（绑定 userId+sid），
 * * 故两者强度相当，但本方案少一件要保管的凭据。
 * *
 * * sid 唯一：同一会话只留一条（重新 step-up 时刷新 expiresAt），不堆积历史。
 *
 * 迁出理由：NEW_FILE_MAX=0.30 的密度上限；正文约束在源码一行内保留，完整权衡留在这里。
 */

'use strict';

/**
 * 审计读取的二次验证票据（P3-2）
 *
 * 覆盖三个层面：
 *  1. 票据本体：签发/校验往返、绑定 userId + 会话 sid、过期与篡改 fail-closed；
 *  2. HTTP 链路：审计读取（/alerts、/audit-logs、/audit-logs/export）必须带票，
 *     票据由 POST /security/reauth 用当前口令换取；管理员写操作（安全开关、
 *     重置他人 MFA）必须当场通过一次二次验证；
 *  3. 会话窗口：一次 step-up 后同会话三条受保护读取免票；窗口按 sid+userId 绑定，他人会话借不到。
 *
 * 设计约束（承接自生产代码头注释，源码侧只留一句指针——注释密度棘轮不统计 src/tests/）：
 *  · 会话窗口（services/reauthGrantStore + models/ReauthGrant）：step-up 成功 ⇒ 服务端给该会话开 5 分钟窗口，
 *    窗口内凭有效访问令牌即可读；客户端不持任何可重放凭据；换设备/被踢即失效（绑定 sid）。
 *    窗口查询失败按「无窗口」处理退回票据（丢的是便利，不是判据）。
 *  · 一次性票据（utils/reauthTicket + services/reauthTicketStore）：票据是 bearer 凭据，不消费就能在 5 分钟内
 *    无限重放——前端内存、代理/访问日志里的 X-REAUTH-TICKET 头都算泄漏面。服务端按 jti 唯一索引消费，
 *    二次使用即拒；无 jti 的旧票一律判无效（不留「没有 jti 就跳过唯一性判据」的旁路）。
 *  · 票据消费存储不可用 ⇒ 500 fail-closed（丢的是唯一性判据）；唯一索引即并发判据，先查后写会留同一竞态窗口。
 *  · 票据消费记录落 Mongo 而非进程内 Set：多实例内存不共享，判据必须与实例数无关。
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
const ReauthGrant = require('../../models/ReauthGrant');
const UserSession = require('../../models/UserSession');
const sessionService = require('../../services/sessionService');
const tokenService = require('../../services/tokenService');
const { accessToken: accessTokenOf } = require('../helpers/authResponse');

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
  let writerUserId;
  let readerPassword;
  let writerPassword;
  let readerUserId;
  let victimId;
  let readerSid;
  let writerSid;
  let sessionUserId;
  let sessionUsername;
  let sessionPassword;

  const sign = (user, jti, sid) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0, jti, sid },
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
    // P1-1：窗口判据按**设备会话 sid**（refresh 不换）而不是 jti（每次签发都换），
    // 所以令牌必须绑一条真实会话——否则窗口无从建立，用例测到的是无 sid 的降级路径。
    readerSid = `rktsid${stamp}reader`;
    await sessionService.createSession({
      userId: reader._id,
      req: { ip: '127.0.0.1', get: () => 'jest-reauth' },
      sid: readerSid,
    });
    readerToken = sign(reader, `reader-${stamp}`, readerSid);

    const writer = await User.create({
      username: `rktwriter${stamp}`,
      email: `rktwriter${stamp}@example.com`,
      password: writerPassword,
      roles: [role._id],
    });
    writerUserId = String(writer._id);
    writerSid = `rktsid${stamp}writer`;
    await sessionService.createSession({
      userId: writer._id,
      req: { ip: '127.0.0.1', get: () => 'jest-reauth' },
      sid: writerSid,
    });
    writerToken = sign(writer, `writer-${stamp}`, writerSid);

    const victim = await User.create({
      username: `rktvictim${stamp}`,
      email: `rktvictim${stamp}@example.com`,
      password: randomPassword(),
    });
    victimId = String(victim._id);

    sessionPassword = randomPassword();
    const sessionUser = await User.create({
      username: `rktsession${stamp}`,
      email: `rktsession${stamp}@example.com`,
      password: sessionPassword,
      roles: [role._id],
    });
    sessionUserId = String(sessionUser._id);
    sessionUsername = sessionUser.username;

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^rkt.*${stamp}$`) }).catch(() => {});
      await ReauthGrant.deleteMany({
        userId: { $in: [readerUserId, writerUserId, sessionUserId] },
      }).catch(() => {});
      await UserSession.deleteMany({ sid: new RegExp(stamp) }).catch(() => {});
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

  test('POST /reauth：缺凭据 403 / 口令错误 403 / 口令正确签发票据并开 5 分钟窗口', async () => {
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

    // 一次性票据**首次使用**放行
    const first = await getAs(readerToken, '/api/security/alerts', { 'X-Reauth-Ticket': ticket });
    expect(first.status).toBe(200);
  });

  test('会话窗口：一次 step-up 之后，同一会话的三条受保护读取都不再要求票据', async () => {
    // 上一条用例刚为该会话开过窗口（POST /reauth 成功即开），这里刻意**不带票据**：
    // 窗口是服务端状态，客户端手里没有任何可重放的凭据。
    for (const path of [
      '/api/security/alerts',
      '/api/security/audit-logs?limit=1',
      '/api/security/audit-logs/export?limit=1',
    ]) {
      const res = await getAs(readerToken, path);
      expect({ path, status: res.status }).toEqual({ path, status: 200 });
    }
  });

  test('窗口绑定会话：他人会话令牌拿不到窗口（仍需票据 → 401 REQUIRED）', async () => {
    // 另一个账号（未 step-up）读审计：窗口按 sid + userId 绑定，不可能被借用
    const res = await getAs(writerToken, '/api/security/alerts');
    expect(res.status).toBe(401);
    expect(res.body.errors.errorCode).toBe('REAUTH_TICKET_REQUIRED');
  });

  test('窗口写入口径（P1-1）：step-up 后窗口行绑设备会话 sid，不是本次令牌的 jti', async () => {
    await ReauthGrant.deleteMany({ userId: sessionUserId }); // 每个用例自带干净起点（窗口行 sid 全局唯一）
    const sid = `rktsess${stamp}write`;
    await sessionService.createSession({
      userId: sessionUserId,
      req: { ip: '127.0.0.1', get: () => 'jest-reauth' },
      sid,
    });
    const access = jwt.sign(
      {
        userId: sessionUserId,
        username: sessionUsername,
        tokenVersion: 0,
        jti: `w1-${stamp}`,
        sid,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const ok = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${access}`)
      .send({ currentPassword: sessionPassword });
    expect(ok.status).toBe(200);
    const row = await ReauthGrant.findOne({ userId: sessionUserId }).lean();
    // 旧口径：这条写的是 jti（每次 refresh 都换）⇒ 窗口行与登出撤销键错位
    expect(row && row.sid).toBe(sid);
  });

  test('refresh 之后窗口仍在：换 jti 不换 sid ⇒ 不带票据也能读审计（R-1 残留的正面判据）', async () => {
    await ReauthGrant.deleteMany({ userId: sessionUserId }); // 每个用例自带干净起点（窗口行 sid 全局唯一）
    const sid = `rktsess${stamp}main`;
    await sessionService.createSession({
      userId: sessionUserId,
      req: { ip: '127.0.0.1', get: () => 'jest-reauth' },
      sid,
    });
    const access1 = jwt.sign(
      {
        userId: sessionUserId,
        username: sessionUsername,
        tokenVersion: 0,
        jti: `m1-${stamp}`,
        sid,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const ok = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${access1}`)
      .send({ currentPassword: sessionPassword });
    expect(ok.status).toBe(200);

    // 前提自证：refresh 真的换了 jti、真的没换 sid（否则下一条判据没有意义）
    const rotated = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: tokenService.generateRefreshToken(sessionUserId, 0, sid) });
    expect(rotated.status).toBe(200);
    const access2 = accessTokenOf(rotated);
    expect(jwt.decode(access2).jti).not.toBe(jwt.decode(access1).jti);
    expect(jwt.decode(access2).sid).toBe(sid);

    // 旧口径：窗口按旧 jti 写、按新 jti 查 ⇒ 401 REQUIRED（刷新后窗口凭空消失）
    const read = await request(app)
      .get('/api/security/alerts')
      .set('Authorization', `Bearer ${access2}`);
    expect({ status: read.status, code: read.body.errors?.errorCode }).toEqual({
      status: 200,
      code: undefined,
    });
  });

  test('窗口到期即失效：expiresAt 已过 ⇒ 401 REAUTH_TICKET_REQUIRED（第 16 轮 P0-1）', async () => {
    // 缺口形状（r16-auth 变异实测）：把 reauthGrantStore.hasLiveReauthGrant 里的
    // `expiresAt: { $gt: new Date() }` 整条删掉，src/tests/{middleware,security,app}
    // 仍 98 suites / 1240 tests 全绿 —— 因为此前所有 ReauthGrant 造数都用**未来**时刻，
    // 没有一条用例造过期窗口行。"窗口会到期"这件事因此没有任何判据。
    // 后果不是理论上的：TTL 监视器 60s 才扫一轮，判据一丢窗口就变永久，
    // /api/security/alerts、/audit-logs 持续可读（无票、无口令）。
    await ReauthGrant.deleteMany({ userId: sessionUserId }); // 每个用例自带干净起点（窗口行 sid 全局唯一）
    const sid = `rktsess${stamp}expired`;
    await sessionService.createSession({
      userId: sessionUserId,
      req: { ip: '127.0.0.1', get: () => 'jest-reauth' },
      sid,
    });
    const access = jwt.sign(
      {
        userId: sessionUserId,
        username: sessionUsername,
        tokenVersion: 0,
        jti: `e1-${stamp}`,
        sid,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    // 造一条**已过期**的窗口行（sid/userId 全对，只有到期时刻在昨天）。
    // 直接写库而不是"等 5 分钟"：可证伪，且不依赖时钟推进。
    await ReauthGrant.create({
      sid,
      userId: sessionUserId,
      grantedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
      expiresAt: new Date(Date.now() - 60 * 1000),
    });

    const read = await request(app)
      .get('/api/security/alerts')
      .set('Authorization', `Bearer ${access}`);
    expect({ status: read.status, code: read.body.errors?.errorCode }).toEqual({
      status: 401,
      code: 'REAUTH_TICKET_REQUIRED',
    });
  });

  test('登出即清窗口：撤销键与写入键同口径 ⇒ 窗口行归零（R-3 的 deleteOne 匹配 0 条）', async () => {
    await ReauthGrant.deleteMany({ userId: sessionUserId }); // 每个用例自带干净起点（窗口行 sid 全局唯一）
    const sid = `rktsess${stamp}logout`;
    await sessionService.createSession({
      userId: sessionUserId,
      req: { ip: '127.0.0.1', get: () => 'jest-reauth' },
      sid,
    });
    const access1 = jwt.sign(
      {
        userId: sessionUserId,
        username: sessionUsername,
        tokenVersion: 0,
        jti: `l1-${stamp}`,
        sid,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const ok = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${access1}`)
      .send({ currentPassword: sessionPassword });
    expect(ok.status).toBe(200);
    expect(await ReauthGrant.countDocuments({ userId: sessionUserId })).toBe(1);

    // 模拟 refresh 后登出：新 access token 同 sid、新 jti
    const access2 = jwt.sign(
      {
        userId: sessionUserId,
        username: sessionUsername,
        tokenVersion: 0,
        jti: `l2-${stamp}`,
        sid,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const out = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${access2}`);
    expect(out.status).toBe(200);
    // 旧口径：写入键是 jti、撤销键是 sid ⇒ 匹配 0 条，行留到 5 分钟 TTL（窗口"看起来仍然有效"）
    expect(await ReauthGrant.countDocuments({ userId: sessionUserId })).toBe(0);
  });

  test('窗口只认设备会话 sid：按 jti 写的行不构成窗口（R-3 的措辞冲突）', async () => {
    await ReauthGrant.deleteMany({ userId: sessionUserId }); // 每个用例自带干净起点（窗口行 sid 全局唯一）
    const sid = `rktsess${stamp}jti`;
    await sessionService.createSession({
      userId: sessionUserId,
      req: { ip: '127.0.0.1', get: () => 'jest-reauth' },
      sid,
    });
    const jti = `jtiwin-${stamp}`;
    const access = jwt.sign(
      { userId: sessionUserId, username: sessionUsername, tokenVersion: 0, jti, sid },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    // 造一条旧口径的窗口行（sid 位置放的是 jti）：旧实现读的也是 jti ⇒ 假绿；新实现只认 sid。
    await ReauthGrant.deleteMany({ userId: sessionUserId });
    await ReauthGrant.create({
      sid: jti,
      userId: sessionUserId,
      grantedAt: new Date(),
      expiresAt: new Date(Date.now() + 60 * 1000),
    });

    const res = await request(app)
      .get('/api/security/alerts')
      .set('Authorization', `Bearer ${access}`);
    expect(res.status).toBe(401);
    expect(res.body.errors.errorCode).toBe('REAUTH_TICKET_REQUIRED');
  });

  test('一次性票据：同一张票第二次使用即被拒（重放），且换端点也一样', async () => {
    // 用**没有会话窗口**的账号（writer 未 step-up）：走的是票据路径本身。
    const ok = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${writerToken}`)
      .send({ currentPassword: writerPassword });
    expect(ok.status).toBe(200);
    const ticket = ok.body.data.ticket;
    // 该账号此刻也开了窗口；先清掉窗口，让后续请求只能靠票据（否则窗口会兜住重放，
    // 判据就测不到）。直接删库比"等 5 分钟"可证伪。
    await ReauthGrant.deleteMany({ userId: writerUserId });

    const used = await getAs(writerToken, '/api/security/audit-logs?limit=1', {
      'X-Reauth-Ticket': ticket,
    });
    expect(used.status).toBe(200);

    // 换一个受保护端点重放同一张票：判据是"这张票用过没有"，与端点无关
    const replay = await getAs(writerToken, '/api/security/audit-logs/export?limit=1', {
      'X-Reauth-Ticket': ticket,
    });
    expect(replay.status).toBe(401);
    expect(replay.body.errors.errorCode).toBe('REAUTH_TICKET_INVALID');
  });

  test('并发双发同一张票：只有一个请求能进控制器（判据落在唯一索引上）', async () => {
    const ok = await request(app)
      .post('/api/security/reauth')
      .set('Authorization', `Bearer ${writerToken}`)
      .send({ currentPassword: writerPassword });
    const ticket = ok.body.data.ticket;
    await ReauthGrant.deleteMany({ userId: writerUserId });

    // 两个请求同时发出：先查后写的实现会双双放行，唯一索引实现只有一个赢
    const [a, b] = await Promise.all([
      getAs(writerToken, '/api/security/alerts', { 'X-Reauth-Ticket': ticket }),
      getAs(writerToken, '/api/security/alerts', { 'X-Reauth-Ticket': ticket }),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 401]);
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
