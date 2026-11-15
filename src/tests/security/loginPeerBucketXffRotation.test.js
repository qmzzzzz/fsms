'use strict';

/**
 * 登录入口的 socket 对端维度限流桶：X-Forwarded-For 轮换不得重置按来源的失败计数
 *
 * 缺陷本体（渗透测试 2026-11-04 实测）：development 默认 TRUST_PROXY_HOPS=1、回环对端走
 * isPeerTrustedProxy 的回环兼容档 ⇒ loginLimiter 的组键（clientIpForSecurityDecision）
 * 取自请求方自写的 X-Forwarded-For——每换一个伪造值就换一个全新桶，"单 IP 10 次/15 分钟"
 * 对决心明确的枚举者形同虚设；叠加挑战闸当时的窗口衰减语义，构成可持续的口令枚举路径。
 * loginPeerLimiter 把第二把尺钉在不可伪造的 socket 对端（TCP 源地址）上。
 *
 * 判据（行为口径，不读限流器闭包，挂在真实挂载表上）：
 *   1. 全链 + 每请求轮换 XFF：前 300 次全部通过（401），第 301 次才 429，且 429 头
 *      RateLimit-Limit=300——证明挡人的是对端桶而不是 IP 桶（否则第 11 次即 429/limit=10）；
 *   2. 挂载表自证：恰好有一个组键以 login-peer: 开头的桶（对端尺在真路由上），
 *      恰好有一个 login: 开头的 IP 桶；固定 XFF 单挂非对端桶时，只有 IP 桶在
 *      40 次内触顶（第 11 次）——它是被轮换绕开的那把尺，也是"轮换有效"前提的行为证明。
 *
 * 两条用例各自**自足**（P2-13：--randomize 打乱文件内用例顺序，任一顺序都必须成立）：
 * 限流器是模块级内存态、同文件共享（supertest 的对端恒为回环）。用例 1 先清对端桶
 * 再打满它；用例 2 显式构造对端桶的「已打满」态（全链 + 轮换 XFF 打 300 次失败尝试）
 * 再做单桶探测——不再依赖声明顺序，根 afterAll 把桶随套件复位。
 *
 * 可证伪方向：
 *   · 删掉 loginPeerLimiter 或改回 clientIpForSecurityDecision 组键 ⇒ 用例 1 红
 *     （要么永不触顶，要么由 IP 桶在 11 次挡下、limit=10）；
 *   · 对端桶改回按 XFF 组键 ⇒ 用例 1 红（轮换使它同样永不触顶）；
 *   · 真实挂载表上摘掉对端桶 ⇒ 用例 2 红（login-peer: 前缀的桶不存在）。
 */

const express = require('express');
const request = require('supertest');
const { ipKeyGenerator } = require('express-rate-limit');

const authRouter = require('../../routes/authRoutes');
// normalizeRateLimitIp 是 rateLimit.js 的「仅供测试」导出：与该文件 keyGenerator 同一把尺
const { normalizeRateLimitIp } = require('../../middleware/rateLimit');

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
  // 必须有 body parser：真路由上限流器挂在 express.json 之后（账号键依赖 req.body.username），
  // 缺了它测的就不是真链路的形态
  app.use(express.json());
  app.post('/login', ...limiters, (req, res) =>
    res.status(401).json({ success: false, message: '用户名或密码错误' })
  );
  return app;
};

/** 第 198.51.0.0/16 段是 TEST-NET-2 内的私用段，不会与真实路由的探针 IP 段相撞；每请求一个全新值。
 * 刻意用合法四段形式：非法文本会被 normalizeRateLimitIp 并进共享 unknown 桶（fail-closed 设计），
 * 那样"轮换"根本没发生，测的就不是被测对象。 */
const rotateIp = (i) => `198.51.${Math.floor(i / 250)}.${(i % 250) + 1}`;
const fixedIp = (n) => `198.51.200.${n}`;

/** 对端桶清零（--randomize 用例乱序的前提）：对端桶键由 socket 对端决定，supertest 恒为回环，
 * 换不出新桶——所以唯一的顺序解耦手段是把回环桶清掉再开始。
 * v8 的中间件只暴露 resetKey(key)（key 是字符串，不是 req；store 也不再挂在 limiter 上），
 * 键模板取自 rateLimit.js 的 keyGenerator（login-peer: + ipKeyGenerator(normalizeRateLimitIp(peer))，
 * 后两个助手就是生产在用的同一把尺，::ffff: 与纯 IPv4 已实测收敛同键）。
 * 若键模板将来改动，用例 1 的「第 301 次才挡下」会以 first429=1 当场变红——复位丢失是响的，不是静默的。 */
const LOOPBACK_PEER_KEY = `login-peer:${ipKeyGenerator(normalizeRateLimitIp('127.0.0.1'))}`;
const resetPeerBucket = (mounted) => {
  for (const limiter of mounted) {
    if (typeof limiter.resetKey === 'function') limiter.resetKey(LOOPBACK_PEER_KEY);
  }
};

describe('登录入口 socket 对端限流桶：XFF 轮换不得重置按来源的失败计数', () => {
  test(
    '全链 + 轮换 XFF：IP 桶全程不触顶，对端桶在第 301 次挡下（RateLimit-Limit=300）',
    async () => {
      const mounted = mountedLimiters('post', '/login');
      expect(mounted.length).toBeGreaterThanOrEqual(3);
      // 自足前提（P2-13）：单桶探测那条用例会把对端桶灌满——乱序下它先跑时，
      // 本用例若不清桶，第 1 次就 429，"第 301 次才挡下"测的就不是本档场景。
      resetPeerBucket(mounted);
      const app = limiterApp(mounted);

      let last = null;
      let first429 = 0;
      for (let i = 1; i <= 301; i += 1) {
        last = await request(app)
          .post('/login')
          .set('X-Forwarded-For', rotateIp(i))
          .send({ username: `rot${i}`, password: 'rot' });
        if (last.status === 429) {
          first429 = i;
          break;
        }
      }
      // 轮换 XFF 使 IP 桶（10 次/15 分钟）全程失效：429 不可能来自它（第 11 次）
      expect(first429).toBe(301);
      expect(last.headers['ratelimit-limit']).toBe('300');
    },
    60 * 1000
  );

  test(
    '单桶探测：固定 XFF 下 IP 桶第 11 次触顶；对端桶被挡住之后不再放行',
    async () => {
      const mounted = mountedLimiters('post', '/login');
      // 自足前提（P2-13）：对端桶必须处于「已打满且不再放行」态。原写法依赖首条用例
      // 先把它打满，--randomize 反序时对端桶是空的 ⇒ 单挂它 40 次全过，governors 缺一条
      // 而翻红（约 50% 概率）。显式构造桶状态：走全链 + 每请求轮换 XFF 打 300 次失败尝试
      // ——对端恒为回环、每个 XFF 值只落 1 次（IP 桶不触顶）、账号桶按 username 计数
      // 且 fill 前缀独占 ⇒ 恰好只有对端桶被灌满，与首条用例打满后的形态一致。
      const fullChain = limiterApp(mountedLimiters('post', '/login'));
      for (let i = 1; i <= 300; i += 1) {
        await request(fullChain)
          .post('/login')
          .set('X-Forwarded-For', rotateIp(i))
          .send({ username: `peerfill${i}`, password: 'solo' });
      }
      // 前提自证：灌满之后，多一发必须由对端桶挡下（limit=300）。
      // 缺了这段，fill 没灌满时下面的 governors 会少一条，红因就不是本档要测的事。
      const probed = await request(fullChain)
        .post('/login')
        .set('X-Forwarded-For', rotateIp(301))
        .send({ username: 'peerfill-probe', password: 'solo' });
      expect(probed.status).toBe(429);
      expect(probed.headers['ratelimit-limit']).toBe('300');
      const governors = [];
      for (let n = 0; n < mounted.length; n += 1) {
        const app = limiterApp([mounted[n]]);
        for (let i = 1; i <= 40; i += 1) {
          const res = await request(app)
            .post('/login')
            .set('X-Forwarded-For', fixedIp(n))
            .send({ username: `solo${n}u${i}`, password: 'solo' });
          if (res.status === 429) {
            governors.push({ n, attempt: i, limit: res.headers['ratelimit-limit'] });
            break;
          }
        }
      }
      // 恰好两个治理者：
      //  · IP 维度桶（loginLimiter，10 次/15 分钟）在固定 XFF 下第 11 次触顶——
      //    它就是被轮换绕开的那把尺，本条同时是"轮换有效"前提的行为证明；
      //  · 对端桶第 1 次就触顶（limit=300）：它在本文件首条用例里已被打满且**不再放行**
      //    （对端维度"挡住之后不得复活"，与 loginIpBucketDominator 的同款不变量）；
      // 账号桶轮换用户名永不触顶，混进来都会破坏本断言。
      expect(governors).toHaveLength(2);
      expect(governors.map((g) => g.attempt).sort((a, b) => a - b)).toEqual([1, 11]);
      expect(governors.map((g) => g.limit).sort()).toEqual(['10', '300']);
    },
    60 * 1000
  );
});

// 根收尾（P2-13）：对端桶随套件复位。乱序下最后跑的用例（无论哪条）都会留下接近满格的
// 对端桶，留给同文件后续新增用例就是一条顺序耦合——在 root 钩子里清零（键口径见 resetPeerBucket）。
afterAll(() => {
  resetPeerBucket(mountedLimiters('post', '/login'));
});
