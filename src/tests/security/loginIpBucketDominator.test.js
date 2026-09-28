'use strict';

/**
 * 登录入口的 IP 维度限流桶：同键空间不得存在「更宽的第二个桶」
 *
 * 缺陷本体（实测，不靠读代码相信）：`authRoutes.js` 的 `POST /login` 依次挂
 * `loginIpLimiter`（30 次/15 分钟，键 `login-ip:${ip}`）与 `loginLimiter`
 * （10 次/15 分钟，键 `login:${ip}`）。两个桶**键空间完全相同**（只由来源 IP 决定）、
 * 窗口相同、`skipSuccessfulRequests` 相同，只有阈值不同 ⇒ 宽桶永远不可能比严桶
 * 多挡一次，也不可能比严桶多放行一次。它的注释却写着"作为外层兜底，封住单 IP
 * 撞库路径（轮换用户名批量尝试）"—— 那条路径早已被同一键空间上更严的桶覆盖，
 * 兜底是个不存在的能力。
 *
 * 实测读数（mini 应用按真实挂载顺序串联，每次换一个不存在的用户名）：
 *   · 串联：第 11 次起 429，文案＝`loginLimiter` 的；第 31 次起文案换成宽桶的
 *     —— 宽桶"可达"，但可达的位置已经在挡住之中，它只换了一条文案；
 *   · 只挂宽桶：首个 429 落在第 31 次；只挂严桶：落在第 11 次。
 *   ⇒ 严桶单独存在即可给出同一条不变量；宽桶的边际约束为 0，
 *     却额外占一个 store、每请求多一次计数写，并给运维"还有更宽的第二层兜底"的错觉。
 *
 * 真实路由上还有一层更早的停止：`securityAlert` 的暴力破解阈值 5 次/5 分钟 ⇒ 自动封禁，
 * `checkIPBlacklist` 在限流之前就把第 6 次之后的请求挡成 403。本文件不改动那条分层，
 * 只钉两件事：**同键空间只有一个治理者**，以及**被挡住之后不会重新放行**。
 *
 * 判据不读限流器内部配置（`express-rate-limit` 的中间件只暴露 `getKey`/`resetKey`，
 * 阈值/窗口都在闭包里），而是**用行为给桶分类**：轮换用户名仍会触顶 ⇒ 该桶的键空间
 * 就是 IP；永不触顶 ⇒ 它按账号分桶，本来就不该被当作 IP 治理者。
 *
 * 可证伪方向：
 *   · 把宽桶（或任何"同键空间、同窗口、阈值更宽"的 IP 桶）重新挂回 `/login` ⇒ 用例 1 红
 *     （它单独触顶 31 ≠ 串联触顶 11）；
 *   · 删掉 `loginLimiter` 只剩宽桶 ⇒ 用例 1 红（串联触顶跳到 31，与用例 2 的"放行上界"
 *     不再由同一条最严尺子给出，且单 IP 可用配额翻倍以上）；
 *   · 让严桶的键掺进 username ⇒ 用例 1 红（它不再被认作 IP 治理者，纯 IP 治理者集合
 *     只剩宽桶，串联触顶=31）；
 *   · 真路由上出现"挡住之后又放行"（桶被分裂/配额被重置）⇒ 用例 2 红。
 */

const express = require('express');
const mongoose = require('mongoose');
const request = require('supertest');

// app.js 的 trust proxy 在 createApp() 内读 env ⇒ 必须在 require 之前设好。
// 不设这一条，本用例所有请求的 req.ip 都会是 127.0.0.1，自动封禁会把回环地址
// 拉进黑名单并连坐同 worker 的其它用例 —— 那不是被测行为。
const ORIG_TRUST_PROXY_HOPS = process.env.TRUST_PROXY_HOPS;
process.env.TRUST_PROXY_HOPS = '1';

// 判据必须挂在**真实挂载表**上：在测试里重述一遍"哪些限流器装了 /login"，
// 挂载表一旦改动用例仍然绿，等于没有盯住任何东西。
const authRouter = require('../../routes/authRoutes');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const RUN = `${Date.now().toString(36)}${Math.floor(Math.random() * 46656)
  .toString(36)
  .padStart(3, 'a')}`;
/** 每次运行一个独立 IP：桶键含 IP，复用旧 IP 会读到上一份用例的计数。
 *  地址段刻意互斥（1–61 真路由 / 70–84 串联 / 90–174 单桶），
 *  否则"单独触顶"会读到串联跑剩的计数。 */
const BASE = (Number.parseInt(RUN.slice(0, 4), 36) + Number.parseInt(RUN.slice(-4), 36)) % 60;
const ipAt = (n) => `192.0.2.${n}`;
const IP_REAL = ipAt(1 + BASE);
const IP_CHAIN = ipAt(70 + (BASE % 15));
const soloIp = (n) => ipAt(90 + n * 28 + (BASE % 28));

/** 挂在真实路由上的限流中间件（express-rate-limit 的产物带 getKey/resetKey，校验器不带） */
const mountedLimiters = (method, path) => {
  const layer = authRouter.stack.find(
    (l) => l.route && l.route.path === path && l.route.methods[method]
  );
  if (!layer) throw new Error(`真实路由上找不到 ${method.toUpperCase()} ${path}：判据失效，必须红`);
  const found = layer.route.stack
    .map((h) => h.handle)
    .filter((h) => typeof h?.getKey === 'function' && typeof h?.resetKey === 'function');
  if (found.length === 0) throw new Error(`${path} 上没识别出任何限流中间件：识别口径失效，必须红`);
  return found;
};

const limiterApp = (limiters) => {
  const app = express();
  app.set('trust proxy', 1);
  // 必须有 body parser：真路由上限流器挂在 express.json 之后，`req.body.username` 是看得见的。
  // 少了这一行，账号维度桶会走"username 缺失 ⇒ 回退 IP 键"的分支（实测第 21 次触顶），
  // 于是被误判成 IP 治理者 —— 测的就不是被测对象了。
  app.use(express.json());
  app.post('/login', ...limiters, (req, res) =>
    res.status(401).json({ success: false, message: '用户名或密码错误' })
  );
  return app;
};

/** 轮换用户名打到首个 429；返回 null 表示在 cap 次内根本没挡住（⇒ 该桶按账号分桶） */
const firstBlocked = async (limiters, ip, cap = 40) => {
  const app = limiterApp(limiters);
  for (let i = 1; i <= cap; i += 1) {
    const res = await request(app)
      .post('/login')
      .set('X-Forwarded-For', ip)
      .send({ username: `${ip.replace(/\./g, '')}u${i}`.slice(0, 20), password: randomPassword() });
    if (res.status === 429) return { attempt: i, message: res.body?.message ?? null };
  }
  return null;
};

describe('登录入口 IP 维度限流桶的「唯一治理者」不变量', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(() => {
    if (ORIG_TRUST_PROXY_HOPS === undefined) delete process.env.TRUST_PROXY_HOPS;
    else process.env.TRUST_PROXY_HOPS = ORIG_TRUST_PROXY_HOPS;
  });

  test('每个"轮换用户名仍会触顶"的桶，其单独触顶次数必须等于串联触顶次数', async () => {
    const mounted = mountedLimiters('post', '/login');
    const chain = await firstBlocked(mounted, IP_CHAIN);
    expect(chain).not.toBeNull();

    const governors = [];
    for (let n = 0; n < mounted.length; n += 1) {
      const solo = await firstBlocked([mounted[n]], soloIp(n));
      if (solo) governors.push({ n, ...solo });
    }
    // 至少要有 IP 维度的治理者，否则本用例是在空集上为真
    expect(governors.length).toBeGreaterThan(0);
    // 每个 IP 治理者都必须"轮到自己时才挡"：单独触顶＝串联触顶，
    // 且给出同一句文案（挡住请求的确实是同一个桶，而不是碰巧同一次数）
    expect(governors.map((g) => g.attempt)).toEqual(
      new Array(governors.length).fill(chain.attempt)
    );
    expect(governors.map((g) => g.message)).toEqual(
      new Array(governors.length).fill(chain.message)
    );
  }, 120000);

  test('真路由：轮换用户名不得把单 IP 的失败尝试推高过 IP 桶配额，且挡住之后不再放行', async () => {
    const app = require('../../app').createApp();
    // 前提自证：这条不成立时，下面的"被挡住"可能全是回环地址连坐
    expect(app.get('trust proxy')).toBe(1);

    const seen = [];
    for (let i = 1; i <= 14; i += 1) {
      const res = await request(app)
        .post('/api/auth/login')
        .set('X-Forwarded-For', IP_REAL)
        .send({
          username: `${IP_REAL.replace(/\./g, '')}u${i}`.slice(0, 20),
          password: randomPassword(),
        });
      seen.push({ i, status: res.status, message: res.body?.message ?? null });
    }
    const blocked = (row) => row.status === 403 || row.status === 429;

    // ① 前面确实打到了凭据校验（被参数校验 400 挡在门外时限流器照样计数，但用例失真）
    expect(seen[0].status).toBe(401);
    // ② 放行次数不得超过最严 IP 桶的配额（10 次/15 分钟；自动封禁的 5 次/5 分钟更早）
    expect(seen.filter((row) => !blocked(row)).length).toBeLessThanOrEqual(10);
    // ③ 一旦被挡住就永远被挡住：中途"复活"＝桶被分裂或配额被重置
    const first = seen.findIndex(blocked);
    expect(first).toBeGreaterThan(-1);
    expect(seen.slice(first).every(blocked)).toBe(true);
  }, 120000);
});
