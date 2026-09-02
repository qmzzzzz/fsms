/**
 * sessionService 单元测试（设备级会话管理）
 *
 * 为什么这些用例值得写：会话服务是「踢除单台设备」这件事的唯一事实来源，
 * 它一旦静默失准，表现不是报错而是**安全结论错误**——用户以为踢掉了可疑
 * 设备，对方其实还在线；或者用户看到的列表里全是早已失效的僵尸记录。
 * 这类缺陷没有异常栈可循，只能靠测试把不变式钉住：
 *
 *  1. parseUserAgent 的分支顺序（写错不报错，只静默给出错误设备名）；
 *  2. revokeSession 必须带 userId 才生效（越权防护的落点）；
 *  3. revokeOtherSessions 必须保留当前会话（否则用户把自己也踢下线）；
 *  4. 校验缓存必须在吊销时失效（否则最长 15 秒仍放行已踢除的设备）；
 *  5. validateSession 数据库故障时 fail-closed（不能因查不到结论而放行）；
 *  6. listSessions 惰性收敛过期状态（TTL 清理有延迟，过期记录仍可能被查到）。
 */

const mongoose = require('mongoose');

describe('sessionService（设备级会话服务）', () => {
  let sessionService;
  let UserSession;
  const userA = new mongoose.Types.ObjectId();
  const userB = new mongoose.Types.ObjectId();

  /** 构造一个最小可用的 req 替身（sessionService 只用到 get / ip） */
  const fakeReq = (
    ua = 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36',
    ip = '10.0.0.1'
  ) => ({
    get: (name) => (String(name).toLowerCase() === 'user-agent' ? ua : ''),
    ip,
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    sessionService = require('../../services/sessionService');
    UserSession = require('../../models/UserSession');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    await UserSession.deleteMany({});
    // 缓存必须逐例清空：上一例吊销后的 usable=false 会被缓存 15 秒，
    // 残留到下一例会让新建会话被判为不可用（测试间的隐性耦合）
    sessionService.clearSessionCache();
  });

  describe('parseUserAgent（设备解析，ua-parser-js）', () => {
    test('bot 检测优先于浏览器判断', () => {
      // 爬虫 UA 常同时包含 Chrome/Safari 标识。若交给解析器，Googlebot 会被
      // 报成 Chrome —— 列表里出现一条「Chrome · Windows」而实际是脚本调用，
      // 用户会误判为「有人用浏览器登录了我的账号」，把可疑访问伪装成正常访问
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (compatible; Googlebot/2.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
      );
      expect(r.deviceType).toBe('bot');
      expect(r.browser).toBe('');
    });

    test('curl / python-requests / okhttp 等非浏览器客户端归为 bot', () => {
      for (const ua of [
        'curl/8.4.0',
        'python-requests/2.31.0',
        'okhttp/4.12.0',
        'Go-http-client/2.0',
      ]) {
        expect(sessionService.parseUserAgent(ua).deviceType).toBe('bot');
      }
    });

    test('Edge 不被误判为 Chrome，且给出主版本号', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91'
      );
      expect(r.browser).toBe('Edge');
      expect(r.browserVersion).toBe('120');
      expect(r.os).toBe('Windows');
      expect(r.deviceType).toBe('desktop');
    });

    test('Chrome 不被误判为 Safari（Chrome UA 同时含 Safari 标识）', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.6099.130 Safari/537.36'
      );
      expect(r.browser).toBe('Chrome');
      expect(r.browserVersion).toBe('120');
      // ua-parser-js 1.x 给的是 'Mac OS'（不是 'macOS'）。断言解析库的实际口径
      // 而非我们期望的写法：若要改成品牌写法，应在展示层映射，
      // 不能让测试假装库返回了别的值
      expect(r.os).toBe('Mac OS');
    });

    test('真 Safari 仍识别为 Safari', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15'
      );
      expect(r.browser).toBe('Safari');
      expect(r.browserVersion).toBe('17');
    });

    test('桌面浏览器落 desktop —— ua-parser-js 对桌面不返回 device.type', () => {
      // 若照抄 undefined，列表里所有电脑都会显示成「未知设备」
      for (const ua of [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
      ]) {
        expect(sessionService.parseUserAgent(ua).deviceType).toBe('desktop');
      }
    });

    test('iPhone 解析出厂商与型号（认出自己设备的关键线索）', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1'
      );
      expect(r.deviceType).toBe('mobile');
      expect(r.os).toBe('iOS');
      expect(r.deviceVendor).toBe('Apple');
      expect(r.deviceModel).toBe('iPhone');
    });

    test('iPad 判为 tablet —— iPadOS 的 UA 会自称 Macintosh', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Safari/604.1'
      );
      expect(r.deviceType).toBe('tablet');
      expect(r.deviceModel).toBe('iPad');
    });

    test('Android 手机解析出具体型号（多台安卓并排时唯一的区分依据）', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36'
      );
      expect(r.os).toBe('Android');
      expect(r.osVersion).toBe('14');
      expect(r.deviceType).toBe('mobile');
      expect(r.browser).toBe('Chrome');
      expect(r.deviceModel).toBe('Pixel 8');
    });

    test('解析出渲染引擎与 CPU 架构（核查伪造 UA 的内部矛盾）', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
      );
      expect(r.engine).toBe('Blink');
      expect(r.cpu).toBe('amd64');
    });

    test('空 UA 全部落空串，deviceType 为 unknown（不臆造设备名）', () => {
      for (const v of ['', undefined, null]) {
        const r = sessionService.parseUserAgent(v);
        expect(r.deviceType).toBe('unknown');
        expect(r.browser).toBe('');
        expect(r.os).toBe('');
        expect(r.deviceModel).toBe('');
      }
    });

    test('无法识别的 UA 不抛错，返回 unknown 结构', () => {
      // createSession 在登录主路径上，解析失败绝不能让登录失败
      const r = sessionService.parseUserAgent('!!!not-a-real-ua!!!');
      expect(r).toHaveProperty('deviceType');
      expect(r).toHaveProperty('browser');
    });

    test('返回结构的字段集合固定（新增字段须同步落库与展示）', () => {
      const r = sessionService.parseUserAgent('curl/8.4.0');
      expect(Object.keys(r).sort()).toEqual([
        'browser',
        'browserVersion',
        'cpu',
        'deviceModel',
        'deviceType',
        'deviceVendor',
        'engine',
        'os',
        'osVersion',
      ]);
    });
  });

  describe('describeDevice（日志用的单行设备名）', () => {
    test('型号 · 浏览器 · 系统三段拼接', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36'
      );
      expect(sessionService.describeDevice(r)).toBe('Google Pixel 8 · Chrome 120 · Android 14');
    });

    test('桌面无型号时只拼浏览器与系统，不留空段', () => {
      const r = sessionService.parseUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
      );
      // 不能出现 ' ·  · ' 这种空段：日志里读起来像解析坏了
      expect(sessionService.describeDevice(r)).toBe('Chrome 120 · Windows 10');
    });

    test('无任何信息返回空串（调用方据此回退 unknown）', () => {
      expect(sessionService.describeDevice(sessionService.parseUserAgent(''))).toBe('');
      expect(sessionService.describeDevice()).toBe('');
    });
  });

  describe('newSid', () => {
    test('产出 UUID 且互不重复（路由 UUID 校验依赖此形状）', () => {
      const a = sessionService.newSid();
      const b = sessionService.newSid();
      expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      expect(a).not.toBe(b);
    });
  });

  describe('createSession', () => {
    test('落库设备信息与时间线，并按 refresh 有效期设置过期时间', async () => {
      const { sid, session } = await sessionService.createSession({
        userId: userA,
        req: fakeReq(),
      });
      expect(sid).toBeTruthy();
      expect(session.status).toBe('active');
      expect(session.browser).toBe('Chrome');
      expect(session.os).toBe('Windows');
      expect(session.ip).toBe('10.0.0.1');
      expect(session.lastIp).toBe('10.0.0.1');
      expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    test('同一设备重新登录产生新会话而非复用旧记录', async () => {
      // 复用旧记录会让列表里的 createdAt 显示为上次登录时间，与用户直觉不符
      await sessionService.createSession({ userId: userA, req: fakeReq() });
      await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await UserSession.countDocuments({ userId: userA })).toBe(2);
    });

    test('超长 UA 被截断到 512 字符（防止单条文档被撑大）', async () => {
      const { session } = await sessionService.createSession({
        userId: userA,
        req: fakeReq('X'.repeat(2000)),
      });
      expect(session.userAgent.length).toBe(512);
    });
  });

  describe('validateSession', () => {
    test('活跃会话可用；伪造 sid 不可用', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect((await sessionService.validateSession(sid)).usable).toBe(true);
      expect((await sessionService.validateSession(sessionService.newSid())).usable).toBe(false);
      expect((await sessionService.validateSession(null)).usable).toBe(false);
    });

    test('已过期（status 仍 active）的会话不可用 —— TTL 清理有延迟', async () => {
      const sid = sessionService.newSid();
      await UserSession.create({
        sid,
        userId: userA,
        status: 'active',
        expiresAt: new Date(Date.now() - 1000),
      });
      expect((await sessionService.validateSession(sid)).usable).toBe(false);
    });

    test('吊销后立即不可用（缓存必须被主动失效）', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      // 先读一次把 usable=true 灌进缓存，模拟真实请求路径
      expect((await sessionService.validateSession(sid)).usable).toBe(true);

      await sessionService.revokeSession({ sid, userId: userA });
      // 若 revokeSession 没有 invalidate 缓存，这里会拿到 15 秒内的旧结论 true
      expect((await sessionService.validateSession(sid)).usable).toBe(false);
    });

    test('数据库故障时 fail-closed 抛 SESSION_SERVICE_UNAVAILABLE', async () => {
      const spy = jest.spyOn(UserSession, 'findOne').mockImplementation(() => {
        throw new Error('connection lost');
      });
      try {
        await expect(sessionService.validateSession(sessionService.newSid())).rejects.toMatchObject(
          { code: 'SESSION_SERVICE_UNAVAILABLE' }
        );
      } finally {
        spy.mockRestore();
      }
    });

    test('命中缓存时不再查库（避免给每个请求附加一次数据库往返）', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      await sessionService.validateSession(sid);

      const spy = jest.spyOn(UserSession, 'findOne');
      await sessionService.validateSession(sid);
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe('touchSession（活跃信息节流写入）', () => {
    test('首次写入生效，节流窗口内第二次跳过', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await sessionService.touchSession(sid, fakeReq(undefined, '10.0.0.2'))).toBe(true);
      // 60 秒窗口内重复调用不应再写库，否则只读认证路径变成写路径
      expect(await sessionService.touchSession(sid, fakeReq(undefined, '10.0.0.3'))).toBe(false);

      const doc = await UserSession.findOne({ sid });
      expect(doc.lastIp).toBe('10.0.0.2');
    });

    test('无 sid 时直接返回 false（不含 sid 的旧令牌走此路径）', async () => {
      expect(await sessionService.touchSession(null, fakeReq())).toBe(false);
    });

    test('写库失败静默返回 false（观测性写入不得影响请求）', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const spy = jest.spyOn(UserSession, 'updateOne').mockRejectedValue(new Error('write failed'));
      await expect(sessionService.touchSession(sid, fakeReq())).resolves.toBe(false);
      spy.mockRestore();
    });
  });

  describe('revokeSession（单设备吊销与越权防护）', () => {
    test('本人吊销成功，状态与原因落库', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(
        await sessionService.revokeSession({ sid, userId: userA, reason: 'user_revoked' })
      ).toBe(true);

      const doc = await UserSession.findOne({ sid });
      expect(doc.status).toBe('revoked');
      expect(doc.revokeReason).toBe('user_revoked');
      expect(doc.revokedAt).toBeInstanceOf(Date);
    });

    test('用他人 userId 吊销无效 —— 越权防护不能依赖「sid 猜不到」', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await sessionService.revokeSession({ sid, userId: userB })).toBe(false);

      // A 的会话必须仍然可用：拿到他人 sid 也不能下线他人设备
      expect((await UserSession.findOne({ sid })).status).toBe('active');
      expect((await sessionService.validateSession(sid)).usable).toBe(true);
    });

    test('缺少 userId 直接拒绝（防止调用方漏传导致按 sid 全局吊销）', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await sessionService.revokeSession({ sid })).toBe(false);
      expect((await UserSession.findOne({ sid })).status).toBe('active');
    });

    test('重复吊销返回 false（幂等，不产生二次审计）', async () => {
      const { sid } = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await sessionService.revokeSession({ sid, userId: userA })).toBe(true);
      expect(await sessionService.revokeSession({ sid, userId: userA })).toBe(false);
    });

    test('只影响目标会话，同一用户其他设备不受影响', async () => {
      const s1 = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const s2 = await sessionService.createSession({ userId: userA, req: fakeReq() });
      await sessionService.revokeSession({ sid: s1.sid, userId: userA });

      expect((await sessionService.validateSession(s1.sid)).usable).toBe(false);
      expect((await sessionService.validateSession(s2.sid)).usable).toBe(true);
    });
  });

  describe('revokeOtherSessions（退出其他设备）', () => {
    test('保留 exceptSid，其余全部吊销', async () => {
      const current = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const other1 = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const other2 = await sessionService.createSession({ userId: userA, req: fakeReq() });

      const count = await sessionService.revokeOtherSessions({
        userId: userA,
        exceptSid: current.sid,
      });
      expect(count).toBe(2);
      expect((await sessionService.validateSession(current.sid)).usable).toBe(true);
      expect((await sessionService.validateSession(other1.sid)).usable).toBe(false);
      expect((await sessionService.validateSession(other2.sid)).usable).toBe(false);
    });

    test('不触及其他用户的会话', async () => {
      const mine = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const theirs = await sessionService.createSession({ userId: userB, req: fakeReq() });
      await sessionService.revokeOtherSessions({ userId: userA, exceptSid: mine.sid });
      expect((await UserSession.findOne({ sid: theirs.sid })).status).toBe('active');
    });

    test('无其他会话时返回 0', async () => {
      const only = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await sessionService.revokeOtherSessions({ userId: userA, exceptSid: only.sid })).toBe(
        0
      );
    });

    test('缺少 userId 返回 0（不做无条件批量吊销）', async () => {
      await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await sessionService.revokeOtherSessions({ userId: null })).toBe(0);
    });

    test('未传 exceptSid 时吊销全部（含当前）', async () => {
      const s1 = await sessionService.createSession({ userId: userA, req: fakeReq() });
      expect(await sessionService.revokeOtherSessions({ userId: userA })).toBe(1);
      expect((await sessionService.validateSession(s1.sid)).usable).toBe(false);
    });
  });

  describe('revokeAllSessions（全局吊销时收敛会话表）', () => {
    test('该用户全部会话吊销并清缓存', async () => {
      const s1 = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const s2 = await sessionService.createSession({ userId: userA, req: fakeReq() });
      await sessionService.validateSession(s1.sid); // 先入缓存

      const count = await sessionService.revokeAllSessions(userA, 'password_changed');
      expect(count).toBe(2);
      expect((await sessionService.validateSession(s1.sid)).usable).toBe(false);
      expect((await sessionService.validateSession(s2.sid)).usable).toBe(false);
      expect((await UserSession.findOne({ sid: s1.sid })).revokeReason).toBe('password_changed');
    });

    test('无活跃会话返回 0；无 userId 返回 0', async () => {
      expect(await sessionService.revokeAllSessions(userA)).toBe(0);
      expect(await sessionService.revokeAllSessions(null)).toBe(0);
    });
  });

  describe('listSessions（会话列表数据源）', () => {
    test('按最近活动倒序，并标记当前设备', async () => {
      const older = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const newer = await sessionService.createSession({ userId: userA, req: fakeReq() });
      await UserSession.updateOne(
        { sid: older.sid },
        { $set: { lastSeenAt: new Date(Date.now() - 60_000) } }
      );

      const list = await sessionService.listSessions({ userId: userA, currentSid: newer.sid });
      expect(list.map((s) => s.sid)).toEqual([newer.sid, older.sid]);
      expect(list[0].current).toBe(true);
      expect(list[1].current).toBe(false);
    });

    test('不返回他人会话', async () => {
      await sessionService.createSession({ userId: userB, req: fakeReq() });
      const mine = await sessionService.createSession({ userId: userA, req: fakeReq() });
      const list = await sessionService.listSessions({ userId: userA });
      expect(list).toHaveLength(1);
      expect(list[0].sid).toBe(mine.sid);
    });

    test('已吊销会话不出现在列表中', async () => {
      const s1 = await sessionService.createSession({ userId: userA, req: fakeReq() });
      await sessionService.createSession({ userId: userA, req: fakeReq() });
      await sessionService.revokeSession({ sid: s1.sid, userId: userA });

      const list = await sessionService.listSessions({ userId: userA });
      expect(list.map((s) => s.sid)).not.toContain(s1.sid);
    });

    test('过期但状态仍 active 的记录被惰性收敛为 expired 且不列出', async () => {
      const stale = sessionService.newSid();
      await UserSession.create({
        sid: stale,
        userId: userA,
        status: 'active',
        expiresAt: new Date(Date.now() - 1000),
      });

      const list = await sessionService.listSessions({ userId: userA });
      expect(list.map((s) => s.sid)).not.toContain(stale);
      // 状态被就地修正：否则用户会在别处看到一台永远踢不掉的「在线」设备
      expect((await UserSession.findOne({ sid: stale })).status).toBe('expired');
    });

    test('输出不含 fingerprint（内部风控字段，不对用户暴露）', async () => {
      await sessionService.createSession({ userId: userA, req: fakeReq() });
      const [item] = await sessionService.listSessions({ userId: userA });
      // fingerprint 是跨账号可关联的标识，对用户没有解释价值，
      // 暴露只会新增一个可被拿去做用户追踪的字段
      expect(item).not.toHaveProperty('fingerprint');
      // userAgent 刻意保留：核查可疑登录时它是最终依据（解析结果可能失准，
      // 原文不会），且本端点只返回请求者自己的会话，不构成他人隐私泄露
      expect(item.userAgent).toBeTruthy();
      expect(Object.keys(item).sort()).toEqual(
        [
          'browser',
          'browserVersion',
          'cpu',
          'createdAt',
          'current',
          'deviceModel',
          'deviceType',
          'deviceVendor',
          'engine',
          'expiresAt',
          'ip',
          'lastIp',
          'lastSeenAt',
          'os',
          'osVersion',
          'sid',
          'userAgent',
        ].sort()
      );
    });

    test('列表刻意返回完整 IP —— 脱敏后无法区分同网段的可疑登录', async () => {
      await sessionService.createSession({
        userId: userA,
        req: fakeReq(undefined, '203.0.113.45'),
      });
      const [item] = await sessionService.listSessions({ userId: userA });
      expect(item.ip).toBe('203.0.113.45');
    });

    test('currentSid 为 null 时无任何条目标记为本设备（不含 sid 的旧令牌）', async () => {
      await sessionService.createSession({ userId: userA, req: fakeReq() });
      const list = await sessionService.listSessions({ userId: userA, currentSid: null });
      expect(list.every((s) => s.current === false)).toBe(true);
    });
  });
});
