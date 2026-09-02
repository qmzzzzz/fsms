/**
 * 设备级会话管理接口回归（登录会话）
 *
 * 这一层要验的不是「功能能跑」，而是几条**安全不变式**在真实中间件栈下成立：
 *
 *  1. 登录会写入会话记录，且令牌里的 sid 与之对应（否则界面根本列不出设备）；
 *  2. 只能看到自己的会话（列表不接受任何指定用户的入参）；
 *  3. 踢除他人 sid 返回 404 —— 与「不存在」同一响应，不给 sid 存在性探测通道；
 *  4. 踢除自己返回 400 —— 那是登出的语义，允许的话用户会停在 401 循环里；
 *  5. 被踢设备的 access token 立刻 401、refresh token 也不能复活（关键一环，
 *     若 refresh 不校验 sid，整个设备级吊销可被一次刷新绕过）；
 *  6. `/sessions/others` 不落到 `:sid` 分支（路由注册顺序），且保留当前设备；
 *  7. 改密走全局吊销，会话表同步收敛，不留「显示在线实际掉线」的僵尸记录。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('设备级会话管理接口（/api/auth/sessions）', () => {
  let app;
  let User;
  let UserSession;
  let sessionService;

  // 夹具口令须避开撞库字典（helpers.BREACHED_PASSWORDS），否则注册/改密被拒
  const PASSWORD = 'Kq4$Wm71zBx3';
  const NEW_PASSWORD = 'Tj8%Rv52nHx7';

  /** 不同 UA 便于在断言里区分是哪台设备 */
  const UA_DESKTOP =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36';
  const UA_MOBILE =
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1';

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    UserSession = require('../../models/UserSession');
    sessionService = require('../../services/sessionService');

    await User.create({ username: 'sessuser', email: 'sessuser@example.com', password: PASSWORD });
    await User.create({
      username: 'sessother',
      email: 'sessother@example.com',
      password: PASSWORD,
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    // 会话校验缓存跨用例残留会让「刚吊销的会话仍可用」之类断言随机失败
    sessionService.clearSessionCache();
  });

  /** 以指定 UA 登录，返回 { token, refreshToken, sid } */
  const loginAs = async (username = 'sessuser', ua = UA_DESKTOP, password = PASSWORD) => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('User-Agent', ua)
      .send({ username, password });
    expect(res.status).toBe(200);
    const { token, refreshToken } = res.body.data;
    // 从令牌里取 sid：这是「令牌与会话记录是否真的绑定」的直接证据
    const sid = jwt.decode(token)?.sid || null;
    return { token, refreshToken, sid };
  };

  const listSessions = (token) =>
    request(app).get('/api/auth/sessions').set('Authorization', `Bearer ${token}`);

  describe('登录建立会话', () => {
    test('令牌携带 sid，且与会话记录一一对应', async () => {
      const { token, sid } = await loginAs();
      expect(sid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

      const doc = await UserSession.findOne({ sid });
      expect(doc).toBeTruthy();
      expect(doc.status).toBe('active');
      expect(doc.browser).toBe('Chrome');

      // refresh token 也必须带同一个 sid，否则轮换后会话关联断裂
      const { refreshToken } = await loginAs();
      expect(jwt.decode(refreshToken).sid).toBeTruthy();

      // sid 与 jti 是两件事：jti 每次签发都不同，sid 跨轮换恒定
      expect(jwt.decode(token).jti).toBe(sid); // 登录路径刻意复用同一 UUID，便于审计追溯
    });

    test('两台设备分别登录，列表能区分设备并标记本设备', async () => {
      const desktop = await loginAs('sessuser', UA_DESKTOP);
      const mobile = await loginAs('sessuser', UA_MOBILE);

      const res = await listSessions(mobile.token);
      expect(res.status).toBe(200);
      expect(res.body.data.currentSidPresent).toBe(true);

      const items = res.body.data.sessions;
      const mine = items.find((s) => s.sid === mobile.sid);
      const other = items.find((s) => s.sid === desktop.sid);
      expect(mine.current).toBe(true);
      expect(mine.deviceType).toBe('mobile');
      expect(other.current).toBe(false);
      expect(other.deviceType).toBe('desktop');
      // total 与数组长度一致，前端「共 N 台设备」文案依赖它
      expect(res.body.data.total).toBe(items.length);
    });
  });

  describe('列表的归属隔离', () => {
    test('只返回本人的会话，看不到他人设备', async () => {
      const me = await loginAs('sessuser', UA_DESKTOP);
      const them = await loginAs('sessother', UA_MOBILE);

      const res = await listSessions(me.token);
      const sids = res.body.data.sessions.map((s) => s.sid);
      expect(sids).toContain(me.sid);
      expect(sids).not.toContain(them.sid);
    });

    test('列表不含 fingerprint，但保留原始 UA 供本人核查', async () => {
      // fingerprint 是跨账号可关联的追踪标识，对用户无解释价值，不得下发。
      // userAgent 相反：解析结果可能失准，原文是核查可疑登录的最终依据，
      // 且本端点只返回请求者自己的会话，不构成他人隐私泄露。
      const me = await loginAs();
      const res = await listSessions(me.token);
      for (const item of res.body.data.sessions) {
        expect(item).not.toHaveProperty('fingerprint');
        expect(item.userAgent).toBeTruthy();
      }
    });

    test('列表返回详细设备信息（型号/版本/引擎），足以分辨具体设备', async () => {
      // 只给「Chrome · Windows」时，多台同环境设备并排无法区分哪台不是自己的
      const mobile = await loginAs('sessuser', UA_MOBILE);
      const res = await listSessions(mobile.token);
      const mine = res.body.data.sessions.find((s) => s.sid === mobile.sid);

      expect(mine.deviceVendor).toBe('Apple');
      expect(mine.deviceModel).toBe('iPhone');
      expect(mine.os).toBe('iOS');
      expect(mine.osVersion).toBeTruthy();
      // ua-parser-js 把移动版 Safari 报为 'Mobile Safari'（与桌面版区分），
      // 断言库的实际口径而非我们习惯的写法
      expect(mine.browser).toBe('Mobile Safari');
      expect(mine.browserVersion).toBe('17');
      expect(mine.engine).toBe('WebKit');
    });

    test('未认证访问返回 401', async () => {
      expect((await request(app).get('/api/auth/sessions')).status).toBe(401);
    });
  });

  describe('踢除单台设备', () => {
    test('踢除成功后该设备令牌立即 401，本设备不受影响', async () => {
      const victim = await loginAs('sessuser', UA_MOBILE);
      const operator = await loginAs('sessuser', UA_DESKTOP);

      const res = await request(app)
        .delete(`/api/auth/sessions/${victim.sid}`)
        .set('Authorization', `Bearer ${operator.token}`);
      expect(res.status).toBe(200);
      expect(res.body.data.sid).toBe(victim.sid);

      // 被踢设备：令牌本身没过期、也没进黑名单，纯靠会话状态被拒
      const denied = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${victim.token}`);
      expect(denied.status).toBe(401);

      // 操作设备仍然可用 —— 这正是与 tokenVersion 全局吊销的关键差别
      const ok = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${operator.token}`);
      expect(ok.status).toBe(200);
    });

    test('被踢设备无法用 refresh token 复活', async () => {
      const victim = await loginAs('sessuser', UA_MOBILE);
      const operator = await loginAs('sessuser', UA_DESKTOP);

      await request(app)
        .delete(`/api/auth/sessions/${victim.sid}`)
        .set('Authorization', `Bearer ${operator.token}`)
        .expect(200);

      // 若 refresh 不校验 sid，这里会 200 并换到一张新令牌，
      // 整个设备级吊销机制就被一次刷新绕过了
      const res = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken: victim.refreshToken });
      expect(res.status).toBe(401);
    });

    test('踢除他人的 sid 返回 404，且对方会话保持可用', async () => {
      const me = await loginAs('sessuser', UA_DESKTOP);
      const them = await loginAs('sessother', UA_MOBILE);

      const res = await request(app)
        .delete(`/api/auth/sessions/${them.sid}`)
        .set('Authorization', `Bearer ${me.token}`);
      expect(res.status).toBe(404);

      // 对方仍可正常访问：越权防护落在查询条件上，不依赖「UUID 猜不到」
      const stillOk = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${them.token}`);
      expect(stillOk.status).toBe(200);
    });

    test('不存在的 sid 与他人的 sid 返回同一个 404（不构成存在性探测通道）', async () => {
      const me = await loginAs();
      const them = await loginAs('sessother', UA_MOBILE);
      const ghost = sessionService.newSid();

      const a = await request(app)
        .delete(`/api/auth/sessions/${ghost}`)
        .set('Authorization', `Bearer ${me.token}`);
      const b = await request(app)
        .delete(`/api/auth/sessions/${them.sid}`)
        .set('Authorization', `Bearer ${me.token}`);

      expect(a.status).toBe(404);
      expect(b.status).toBe(404);
      expect(a.body.message).toBe(b.body.message);
    });

    test('踢除当前设备返回 400（那是登出的语义）', async () => {
      const me = await loginAs();
      const res = await request(app)
        .delete(`/api/auth/sessions/${me.sid}`)
        .set('Authorization', `Bearer ${me.token}`);
      expect(res.status).toBe(400);

      // 关键：拒绝之后当前令牌必须仍然可用，不能出现「报错了但人也掉线了」
      const ok = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${me.token}`);
      expect(ok.status).toBe(200);
    });

    test('畸形 sid 被参数校验拦在控制器之前（400）', async () => {
      const me = await loginAs();
      for (const bad of ['not-a-uuid', '../../etc/passwd', '%24ne', 'x'.repeat(300)]) {
        const res = await request(app)
          .delete(`/api/auth/sessions/${encodeURIComponent(bad)}`)
          .set('Authorization', `Bearer ${me.token}`);
        expect(res.status).toBe(400);
      }
    });

    test('未认证时不得吊销任何会话', async () => {
      const victim = await loginAs('sessuser', UA_MOBILE);
      const res = await request(app).delete(`/api/auth/sessions/${victim.sid}`);
      expect(res.status).toBe(401);
      expect((await UserSession.findOne({ sid: victim.sid })).status).toBe('active');
    });
  });

  describe('退出其他设备', () => {
    test('保留当前设备、吊销其余设备，且不递增 tokenVersion', async () => {
      const u = await User.findOne({ username: 'sessuser' });
      const versionBefore = u.tokenVersion ?? 0;

      const a = await loginAs('sessuser', UA_MOBILE);
      const b = await loginAs('sessuser', UA_MOBILE);
      const current = await loginAs('sessuser', UA_DESKTOP);

      const res = await request(app)
        .delete('/api/auth/sessions/others')
        .set('Authorization', `Bearer ${current.token}`);
      expect(res.status).toBe(200);
      expect(res.body.data.revokedCount).toBeGreaterThanOrEqual(2);

      // 当前设备不受影响：不改密码就能清掉其他设备，这是本功能的核心价值
      expect(
        (await request(app).get('/api/auth/me').set('Authorization', `Bearer ${current.token}`))
          .status
      ).toBe(200);
      for (const gone of [a, b]) {
        expect(
          (await request(app).get('/api/auth/me').set('Authorization', `Bearer ${gone.token}`))
            .status
        ).toBe(401);
      }

      const after = await User.findOne({ username: 'sessuser' });
      expect(after.tokenVersion ?? 0).toBe(versionBefore);
    });

    test('/sessions/others 不落到 :sid 分支（路由注册顺序正确）', async () => {
      const me = await loginAs();
      const res = await request(app)
        .delete('/api/auth/sessions/others')
        .set('Authorization', `Bearer ${me.token}`);
      // 顺序颠倒时 'others' 会被 UUID 校验拒为 400
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty('revokedCount');
    });

    test('不影响其他用户的会话', async () => {
      const them = await loginAs('sessother', UA_MOBILE);
      const me = await loginAs('sessuser', UA_DESKTOP);

      await request(app)
        .delete('/api/auth/sessions/others')
        .set('Authorization', `Bearer ${me.token}`)
        .expect(200);

      expect((await UserSession.findOne({ sid: them.sid })).status).toBe('active');
    });
  });

  describe('全局吊销路径的会话表收敛', () => {
    test('登出后本会话置为 revoked，不留「显示在线」的记录', async () => {
      const me = await loginAs();
      await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${me.token}`)
        .expect(200);

      expect((await UserSession.findOne({ sid: me.sid })).status).toBe('revoked');
    });

    test('改密后该用户全部会话被吊销（与 tokenVersion 同步）', async () => {
      // 独立用户，避免改密影响其他用例的夹具口令
      const username = 'sesspwd';
      await User.create({ username, email: 'sesspwd@example.com', password: PASSWORD });

      const s1 = await loginAs(username, UA_DESKTOP);
      const s2 = await loginAs(username, UA_MOBILE);

      const res = await request(app)
        .put('/api/auth/password')
        .set('Authorization', `Bearer ${s1.token}`)
        .send({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD });
      expect(res.status).toBe(200);

      for (const sid of [s1.sid, s2.sid]) {
        const doc = await UserSession.findOne({ sid });
        expect(doc.status).toBe('revoked');
        expect(doc.revokeReason).toBe('password_changed');
      }

      // 会话列表随之为空：用户不会看到一批实际已掉线的设备
      const relogin = await loginAs(username, UA_DESKTOP, NEW_PASSWORD);
      const list = await listSessions(relogin.token);
      expect(list.body.data.sessions.map((s) => s.sid)).toEqual([relogin.sid]);
    });
  });

  describe('兼容不含 sid 的旧令牌', () => {
    test('旧令牌可正常访问，列表返回 currentSidPresent=false 供前端提示', async () => {
      const u = await User.findOne({ username: 'sessuser' });
      // 手工签发一张不含 sid 的令牌，等价于本功能上线前签发的存量令牌
      const legacy = jwt.sign(
        {
          userId: String(u._id),
          username: u.username,
          email: u.email,
          tokenVersion: u.tokenVersion ?? 0,
          jti: require('crypto').randomUUID(),
        },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      // 必须放行而不是 401：上线瞬间拒绝旧令牌等于把所有在线用户踢下线
      const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${legacy}`);
      expect(me.status).toBe(200);

      const res = await listSessions(legacy);
      expect(res.status).toBe(200);
      expect(res.body.data.currentSidPresent).toBe(false);
      // 没有任何条目会被标为本设备，前端据此提示「重新登录后可完整管理」
      expect(res.body.data.sessions.every((s) => s.current === false)).toBe(true);
    });
  });
});
