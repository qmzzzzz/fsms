/* ===== 附录（2026-10-31 注释密度治理迁出）：src/routes/avatarRoutes.js 的原委 =====
 * * 顺序契约：IP 桶（认证前）→ authenticate → 用户桶（认证后）。
 * *
 * * A2 修复（2026-10-30）：IP 桶必须用 `router.use` 挂在**路由前缀**上，不能只挂在下面那条
 * * `GET /:userId` 上。修复前：全局限流器按前缀豁免本面（rateLimit.js 的 isAvatarReadRequest，
 * * 头像是"一页 N 张"的资源型请求，不该吃通用配额），而桶又只存在于路由链上 ⇒ 本前缀下
 * * **未匹配任何路由**的请求（`/api/avatars`、`/api/avatars/<id>/<extra>` 等 404 空转）
 * * 两处都不计：全局桶被 skip、路由级桶不执行 = 唯一"零配额"请求面（实测 400 发 0 次 429）。
 * * `router.use` 在 router 入口执行，未匹配路由也计数，"换桶"这才成为完整的换桶。
 * *
 * * 挂一次而不是在每条路由上再挂一份：`router.use` 先执行一次、路由链再执行一次会把合法读取
 * * 计两次，等于把本桶阈值悄悄减半。
 * * 副作用（如实记录）：本前缀下**任意方法**都进 IP 桶；非 GET/HEAD 的请求同时仍受全局
 * * general/ip 桶约束（本面只豁免安全方法），方向更严，不构成放宽。
 * 迁出理由：NEW_FILE_MAX=0.30 的密度上限；正文当前约束在源码一行内保留，完整权衡留在这里。
 */

/**
 * A2 守卫：/api/avatars 前缀下的「未匹配路由」请求必须同样进限流桶、同样留审计。
 *
 * 修复前的两半判据各自都"合理"，叠在一起才成洞：
 *   · 限流侧（rateLimit.js 的 isAvatarReadRequest）按前缀把整个 /api/avatars 面从
 *     general/ip 桶里豁免——头像是"一页 N 张"的资源型请求，不该吃通用配额；
 *   · 桶本身（avatarRoutes.js）却只挂在 GET /:userId 这一条路由上。
 *   ⇒ /api/avatars、/api/avatars/<id>/<extra> 这类 404 空转既不进任何桶（被 skip 的全局限流器
 *     不执行、路由级桶没有匹配的路由就永远不跑），也仍在 auditGetExcludePaths 的 /api/avatars
 *     前缀之内（零留痕）。合起来就是全站唯一的"零配额 + 零留痕"请求面。
 *
 * 四组判据，全部打真中间件/真发请求（不断言源码文本）：
 *   ① 修复后：真实 avatarRoutes（router.use 桶），640 次未匹配请求 ⇒ 前 600 次 404、第 601 次起 429；
 *      同一 IP 再打裸前缀 /api/avatars ⇒ 429（裸前缀也计数）。
 *   ② 修复前夹具：桶只挂 GET /:userId 的旧形态 ⇒ 640 次全 404、0 次 429、响应无 RateLimit-* 头；
 *      同一 app 里 /api/users/<不存在> 第 101 次起 429（对照组：证明全局限流器本身是活的，
 *      唯一变量就是 /api/avatars 前缀豁免）。
 *   ③ 审计：真实 auditLog()（生产默认豁免清单）——合法读取形态 GET /api/avatars/<24 位 ObjectId>
 *      仍 0 条（原意"不灌满审计链"成立），未匹配形态逐条 +1。
 *   ④ 判据夹具：修复前的纯前缀判据对同一批形态恒为 true（旧判据在 /api/avatars/x/y 上是红的）。
 */

// —— 必须早于 require('../../middleware/rateLimit') 与 require('../../app')：限流器与 config 都在模块加载期取值 ——
const SAVED_ENV = {};
[
  'TRUST_PROXY_HOPS',
  'RATE_LIMIT_MAX_REQUESTS',
  'RATE_LIMIT_IP_MAX_REQUESTS',
  'RATE_LIMIT_WINDOW_MS',
].forEach((k) => {
  SAVED_ENV[k] = process.env[k];
});
const GENERAL_MAX = 100;
process.env.TRUST_PROXY_HOPS = '1';
process.env.RATE_LIMIT_MAX_REQUESTS = String(GENERAL_MAX);
process.env.RATE_LIMIT_IP_MAX_REQUESTS = '100000';
process.env.RATE_LIMIT_WINDOW_MS = '900000';

const express = require('express');
const request = require('supertest');
const { waitFor, waitForStable } = require('../helpers/waitFor');

const OID = '8f1b2c3d4e5f60718293a4b5';

jest.setTimeout(300000);

describe('A2：头像前缀的未匹配请求必须计数且留痕', () => {
  const {
    isAvatarReadRequest,
    AVATAR_READ_IP_MAX,
    ipLimiter,
    generalLimiter,
  } = require('../../middleware/rateLimit');
  const { auditLog } = require('../../middleware/security/auditLog');
  const auditBuffer = require('../../services/auditBuffer');

  /** 逐发请求并统计状态码；headers 取第一发的 RateLimit-*（被 skip 的请求不会有这些头） */
  const runFlood = async (app, url, times, ip) => {
    const statuses = [];
    let rateHeaders = null;
    for (let i = 0; i < times; i += 1) {
      const res = await request(app).get(url).set('X-Forwarded-For', ip);
      statuses.push(res.status);
      if (i === 0) rateHeaders = Object.keys(res.headers).filter((h) => /^ratelimit/i.test(h));
    }
    return { statuses, rateHeaders };
  };

  /** 修复后形态：真实 avatarRoutes（IP 桶挂在 router.use 上）+ 真全局限流器 + 404 兜底 */
  const buildFixedApp = () => {
    const server = express();
    server.use(ipLimiter);
    server.use(generalLimiter);
    server.use('/api/avatars', require('../../routes/avatarRoutes'));
    server.use((req, res) => res.status(404).json({ success: false, message: 'Not Found' }));
    return server;
  };

  /** 修复前夹具：桶只挂 GET /:userId（与 routes/avatarRoutes.js 修复前的写法同形） */
  const buildLegacyApp = () => {
    const { avatarReadIpLimiter } = require('../../middleware/rateLimit');
    const router = express.Router();
    router.get('/:userId', avatarReadIpLimiter, (req, res) =>
      res.status(404).json({ success: false, message: 'Not Found' })
    );
    const server = express();
    server.use(ipLimiter);
    server.use(generalLimiter);
    server.use('/api/avatars', router);
    server.use((req, res) => res.status(404).json({ success: false, message: 'Not Found' }));
    return server;
  };

  test('① 修复后：未匹配的 /api/avatars/** 进桶（第 601 次起 429，裸前缀也计数）', async () => {
    const app = buildFixedApp();
    const times = AVATAR_READ_IP_MAX + 40;
    const { statuses } = await runFlood(app, `/api/avatars/${OID}/extra`, times, '10.31.1.1');
    expect(statuses.slice(0, AVATAR_READ_IP_MAX).every((s) => s === 404)).toBe(true);
    expect(statuses.slice(AVATAR_READ_IP_MAX).every((s) => s === 429)).toBe(true);

    // 同一 IP 同一桶：裸前缀（无 segment）也已被计数
    const bare = await request(app).get('/api/avatars').set('X-Forwarded-For', '10.31.1.1');
    expect(bare.status).toBe(429);
  });

  test('② 修复前夹具：640 次全 404 / 0 次 429 / 无 RateLimit-* 头（对照组证明限流器是活的）', async () => {
    const app = buildLegacyApp();
    const { statuses, rateHeaders } = await runFlood(
      app,
      `/api/avatars/${OID}/extra`,
      640,
      '10.31.2.1'
    );
    expect(statuses.every((s) => s === 404)).toBe(true);
    expect(statuses.filter((s) => s === 429)).toHaveLength(0);
    // 一条 RateLimit-* 都没有 = 全局限流器确实被前缀判据 skip 了（不是"桶宽"）
    expect(rateHeaders).toEqual([]);

    // 对照组：同一 app、同一 IP，非头像路径的第 101 次就是 429 ⇒ 限流器本身没坏
    const control = await runFlood(
      app,
      '/api/users/nonexistent-probe',
      GENERAL_MAX + 40,
      '10.31.2.2'
    );
    expect(control.statuses.slice(0, GENERAL_MAX).every((s) => s === 404)).toBe(true);
    expect(control.statuses[GENERAL_MAX]).toBe(429);
  });

  describe('③ 审计：合法读取仍豁免，未匹配形态逐条留痕', () => {
    let app;
    let pushSpy;

    /**
     * 取本次请求落进 auditBuffer 的行。
     *
     * 等待的是「条件成立 / 读数不再变化」，不是「时间过去 30ms」：
     * 固定睡眠在慢机上等不够会随机红、在快机上白等。expected=0 的用例必须
     * 证明「行数稳定为 0」——只 flush 一次事件循环就断言 0 是把'还没到'当'不会到'。
     */
    const recordsAfter = async (fn, expected = 1) => {
      pushSpy.mockClear();
      await fn();
      if (expected === 0) {
        await waitForStable(() => pushSpy.mock.calls.length, {
          timeoutMs: 500,
          intervalMs: 20,
          label: '审计行数稳定为 0',
        });
      } else {
        await waitFor(() => pushSpy.mock.calls.length >= expected, {
          timeoutMs: 2000,
          label: `审计行数达到 ${expected}`,
        });
      }
      return pushSpy.mock.calls.map((call) => call[0]);
    };

    beforeAll(() => {
      // 用真实 auditLog（生产默认豁免清单）包一个不涉认证的桩路由：本组只判"路径/方法是否豁免"
      const router = express.Router();
      router.get('/:userId', (req, res) => res.json({ success: true }));
      app = express();
      app.use(express.json());
      app.use(auditLog());
      app.use('/api/avatars', router);
      app.use((req, res) => res.status(404).json({ success: false, message: 'Not Found' }));
      pushSpy = jest.spyOn(auditBuffer, 'push').mockImplementation(() => {});
    });

    afterAll(() => {
      pushSpy.mockRestore();
    });

    test('合法读取形态 GET /api/avatars/<24 位 ObjectId> → 0 条审计（原意：不被 N 张图灌满）', async () => {
      const rows = await recordsAfter(() => request(app).get(`/api/avatars/${OID}`).expect(200), 0);
      expect(rows).toHaveLength(0);
      // HEAD 同判（Express 把 HEAD 归一成 GET，业务照跑）
      const headRows = await recordsAfter(
        () => request(app).head(`/api/avatars/${OID}`).expect(200),
        0
      );
      expect(headRows).toHaveLength(0);
    });

    test.each([
      ['裸前缀', '/api/avatars'],
      ['多一段', `/api/avatars/${OID}/extra`],
      ['非 ObjectId 形态（不命中读取路由的 isMongoId 形态）', '/api/avatars/abc'],
      ['再多一段', `/api/avatars/${OID}/extra/more`],
    ])('未匹配形态「%s」→ 审计 +1（修复前一条都没有）', async (_label, url) => {
      const rows = await recordsAfter(() => request(app).get(url));
      expect(rows).toHaveLength(1);
      expect(String(rows[0].path)).toBe(url);
      expect(rows[0].method).toBe('GET');
    });
  });

  test('④ 判据夹具：修复前的纯前缀判据对同一批形态恒为 true（旧判据在 x/y 上是红的）', () => {
    // 修复前的判据原文（helpers.matchesPathPrefix 的整段前缀语义）
    const legacyPrefixJudge = (fullPath) => {
      const p = String(fullPath).toLowerCase();
      return p === '/api/avatars' || p.startsWith('/api/avatars/');
    };
    const forms = [
      '/api/avatars',
      `/api/avatars/${OID}`,
      `/api/avatars/${OID}/extra`,
      '/api/avatars/abc',
    ];
    // 旧判据：4 种形态全部"命中豁免" ⇒ 组③里那 4 条 +1 的审计行，在修复前一条都不会有
    expect(forms.filter((f) => legacyPrefixJudge(f))).toEqual(forms);
    // 生产判据只对"整段边界"负责（它现在的职责是给全局桶让位，覆盖由 avatarRoutes 的
    // router.use 兜住）——两者叠加后组①/组③ 才有红绿分歧，这条断言钉住"旧判据确实更宽"。
    const req = { method: 'GET', originalUrl: forms[2] };
    expect(isAvatarReadRequest(req)).toBe(true);
  });
});
