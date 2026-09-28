'use strict';

/**
 * 凭据型限流的「账号维度桶」：X-Forwarded-For 轮换不得分裂配额
 *
 * 根因（本文件用真请求实测，不靠读代码相信）：
 *   `passwordChangeLimiter` / `reauthLimiter` 的键都是 `${prefix}:${userId}:${req.ip}`，
 *   而 app.js 在 `TRUST_PROXY_HOPS>0` 时把 req.ip 取自 X-Forwarded-For
 *   （生产 compose 默认 1 跳）。于是"同一账号 + 每请求换一个假 IP"= 每换一个 IP
 *   就多一份 5 次/15 分钟 的配额，凭据爆破的速率上限实际由攻击者决定。
 *   `/auth/login` 一侧早就有纯账号桶（loginUserLimiter），改密/二次验证侧缺失。
 *
 * 修法口径是**并列两个桶**而不是把 IP 从组合键里删掉：
 * 只留账号桶会丢掉「单 IP 横扫多账号」的约束，只留 IP 桶就是本条缺陷本身。
 *
 * 判据（每条都可证伪）：
 *   · 前提：真实 app 的 `trust proxy` 确为 1，且 hops=1 时 XFF 确实移动 req.ip
 *     ——不测这一条，后面的"轮换"可能全是假的（恒绿）；
 *   · 机制：同一个 limiter 挂在 mini 应用上，轮换 XFF 10 次 ⇒ 组合键**零 429**（缺陷本体），
 *     纯账号桶第 6 次起恒 429（修复本体）；换 userId 立刻恢复放行（键真是 userId）；
 *   · 接线：三条真路由（PUT /auth/password、PUT /security/change-password、
 *     POST /security/view-sensitive）各自轮换 10 次 ⇒ 前 5 次非 429、第 6 次起恒 429，
 *     且 429 的文案指向本桶（证明命中的不是别的限流器）；
 *   · 不误伤：合法用户在配额内正常改密成功（并回读数据库确认真改了）。
 *
 * view-sensitive 用「故意缺 dataType」的坏请求体：限流判定在参数校验**之前**，
 * 账号桶照样计数，而不会真去比对凭据（那会烧 mfaFailCount，阈值 5 且与登录共用）。
 */

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

// trust proxy 在 createApp() 内读 env ⇒ 必须在 require('../../app') 之前设好
const ORIG_TRUST_PROXY_HOPS = process.env.TRUST_PROXY_HOPS;
process.env.TRUST_PROXY_HOPS = '1';

const stamp = `plb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();
/** 每次换一个地址（203.0.113.0/24 是 TEST-NET-3，不会与真实对端冲突） */
const xff = (i) => `203.0.113.${i}`;

/** 只带身份的 mini 应用：把两个桶单独拿出来对照，不掺路由与权限 */
const miniApp = (userId, limiter, eolTrusted = true) => {
  const probe = express();
  probe.set('trust proxy', eolTrusted ? 1 : false);
  if (userId) {
    probe.use((req, res, next) => {
      req.user = { userId };
      next();
    });
  }
  probe.post('/x', limiter, (req, res) => res.status(400).end());
  probe.get('/echo', (req, res) => res.json({ ip: req.ip }));
  return probe;
};

const drive = async (probe, count, offset) => {
  const seen = [];
  for (let i = 1; i <= count; i += 1) {
    const res = await request(probe)
      .post('/x')
      .set('X-Forwarded-For', xff(offset + i));
    seen.push({ i, status: res.status, message: res.body?.message });
  }
  return seen;
};

describe('凭据型限流的账号维度桶', () => {
  let app;
  let User;
  let limiters;
  const created = [];

  const tokenFor = (userId, username) =>
    jwt.sign({ userId: String(userId), username, tokenVersion: 0 }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

  /** 每个用例一个独立用户 ⇒ 账号桶互不污染 */
  const makeUser = async (label) => {
    const username = `${stamp}${label}`.slice(0, 20);
    const user = await User.create({
      username,
      email: `${username}@example.com`,
      password: PASSWORD,
    });
    created.push(user._id);
    return { user, token: tokenFor(user._id, username) };
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    require('../../models/TokenBlacklist');
    limiters = require('../../middleware/rateLimit');
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (ORIG_TRUST_PROXY_HOPS === undefined) delete process.env.TRUST_PROXY_HOPS;
    else process.env.TRUST_PROXY_HOPS = ORIG_TRUST_PROXY_HOPS;
    if (created.length) await User.deleteMany({ _id: { $in: created } });
  });

  test('前提：真实 app 信任 1 跳，且 hops=1 时 XFF 决定 req.ip（否则整份用例为假绿）', async () => {
    expect(app.get('trust proxy')).toBe(1);

    const probe = miniApp(null, (req, res, next) => next());
    const a = await request(probe).get('/echo').set('X-Forwarded-For', xff(101));
    const b = await request(probe).get('/echo').set('X-Forwarded-For', xff(102));
    const none = await request(probe).get('/echo');
    expect(a.body.ip).toBe(xff(101));
    expect(b.body.ip).toBe(xff(102));
    // 没带头时不是 XFF 值 ⇒ 上面两次确实是"被 XFF 改写"而不是恒等回显
    expect(none.body.ip).not.toBe(xff(101));
  });

  test('机制：组合键桶被 XFF 轮换打穿（10 次零 429）＝缺陷本体；账号桶第 6 次起 429＝修复本体', async () => {
    const uid = `${stamp}-mini`;

    const composite = await drive(miniApp(uid, limiters.passwordChangeLimiter), 10, 1);
    expect(composite.map((x) => x.status === 429)).toEqual(new Array(10).fill(false));

    const bucket = await drive(miniApp(uid, limiters.passwordChangeUserLimiter), 10, 21);
    expect(bucket.slice(0, 5).map((x) => x.status)).toEqual([400, 400, 400, 400, 400]);
    expect(bucket.slice(5).map((x) => x.status)).toEqual([429, 429, 429, 429, 429]);
    expect(bucket[5].message).toBe('密码修改操作过于频繁，请稍后再试');
  });

  test('键必须真是 userId 而不是 IP：同 IP 换账号立刻放行（退化成纯 IP 桶则本用例红）', async () => {
    const probeA = miniApp(`${stamp}-u1`, limiters.passwordChangeUserLimiter);
    const probeB = miniApp(`${stamp}-u2`, limiters.passwordChangeUserLimiter);
    const exhausted = await drive(probeA, 6, 60);
    expect(exhausted[5].status).toBe(429);
    // 同一个出口 IP、另一个账号：不得被上一个账号的配额连坐
    const other = await request(probeB).post('/x').set('X-Forwarded-For', xff(66));
    expect(other.status).toBe(400);
  });

  test('未认证请求不得塌进同一个 undefined 桶（skip 分支）', async () => {
    // 不挂 req.user、也不换 IP：若 skip 漏掉，8 次请求共用 `pwd-change-user:undefined`，
    // 第 6 次必然 429。skip 生效时全部走到底。
    const probe = miniApp(null, limiters.passwordChangeUserLimiter, false);
    const seen = await drive(probe, 8, 80);
    expect(seen.map((x) => x.status)).toEqual(new Array(8).fill(400));
  });

  const routeCases = [
    {
      name: 'authPassword',
      method: 'put',
      path: '/api/auth/password',
      label: 'ap',
      body: () => ({ currentPassword: `Wrong-${stamp}`, newPassword: randomPassword() }),
      message: '密码修改操作过于频繁，请稍后再试',
    },
    {
      name: 'securityChangePassword',
      method: 'put',
      path: '/api/security/change-password',
      label: 'sc',
      body: () => ({ currentPassword: `Wrong-${stamp}`, newPassword: randomPassword() }),
      message: '密码修改操作过于频繁，请稍后再试',
    },
    {
      name: 'viewSensitive',
      method: 'post',
      path: '/api/security/view-sensitive',
      label: 'vs',
      body: () => ({ currentPassword: `Wrong-${stamp}` }),
      message: '二次验证尝试过于频繁，请稍后再试',
    },
  ];

  for (const c of routeCases) {
    test(`接线：${c.path} 的账号配额不随 IP 分裂（轮换 10 次，第 6 次起 429）`, async () => {
      const { token } = await makeUser(c.label);
      const seen = [];
      for (let i = 1; i <= 10; i += 1) {
        const sent = c.method === 'post' ? request(app).post(c.path) : request(app).put(c.path);
        const res = await sent
          .set('Authorization', `Bearer ${token}`)
          .set('X-Forwarded-For', xff(30 + i))
          .send(c.body());
        seen.push({ i, status: res.status, message: res.body?.message });
      }
      // 前 5 次必须"各就各位地失败"（校验/凭据错），不得提前被挡住
      expect(seen.slice(0, 5).map((x) => x.status === 429)).toEqual([
        false,
        false,
        false,
        false,
        false,
      ]);
      expect(seen.slice(5).map((x) => x.status)).toEqual([429, 429, 429, 429, 429]);
      expect(seen[5].message).toBe(c.message);
    });
  }

  test('反向对照：合法改密在配额内成功，且数据库真的换了口令（不是回 200 的假成功）', async () => {
    const { user } = await makeUser('ok');
    const fresh = randomPassword();
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: user.username, password: PASSWORD });
    expect(login.status).toBe(200);
    const res = await request(app)
      .put('/api/auth/password')
      .set('Authorization', `Bearer ${login.body.data.token}`)
      .set('X-Forwarded-For', xff(81))
      .send({ currentPassword: PASSWORD, newPassword: fresh });
    expect({ status: res.status, message: res.body?.message }).toMatchObject({ status: 200 });
    // 口令字段是 select:false，不显式取会拿到 undefined ⇒ "非空"断言形同虚设
    const db = await User.findById(user._id).select('+password').lean();
    expect(db.password).toEqual(expect.any(String));
    expect(db.password).toMatch(/^\$2[aby]\$\d{2}\$/);
    expect(db.password).not.toBe(fresh);
    // 行为判据（不依赖字段可读）：旧口令再也登不进去，新口令登得进去
    const stale = await request(app)
      .post('/api/auth/login')
      .send({ username: user.username, password: PASSWORD });
    expect(stale.status).toBe(401);
    const again = await request(app)
      .post('/api/auth/login')
      .send({ username: user.username, password: fresh });
    expect(again.status).toBe(200);
  });
});
