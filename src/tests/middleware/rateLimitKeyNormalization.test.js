/**
 * 限流键 IP 归一化与 CC 升级接线门禁
 *
 * 两类判据：
 *  1. 行为判据（normalizeRateLimitIp）：`::ffff:1.2.3.4` 与 `1.2.3.4` 必须落进
 *     同一个限流桶——名单侧（IPBlacklist）入库前归一化，限流侧若按原文组键，
 *     同一来源拿到两份配额，标称阈值名存实亡（总账 §4.4 双桶条目）。
 *  2. 接线判据（源码门禁，仓库既有 pattern）：所有以 IP 组键的限流器必须显式
 *     走 normalizeRateLimitIp + ipKeyGenerator（后者按 /56 聚合 IPv6，防同一
 *     /64 轮换地址绕过），所有 IP 维度限流器的 429 handler 必须上报升级
 *     信号。谁加新限流器忘了归一化/上报，这两条就红——比逐个跑 HTTP 集成
 *     用例便宜，且对"未来新增的限流器"同样有效。
 */

const fs = require('fs');
const path = require('path');

const express = require('express');
const request = require('supertest');
const { ipKeyGenerator } = require('express-rate-limit');
const {
  normalizeRateLimitIp,
  normalizeLoginRateKey,
  loginUserLimitWarnMessage,
  LOGIN_RATE_KEY_MAX_CHARS,
  LOGIN_RATE_KEY_OVERSIZED,
  loginUserLimiter,
} = require('../../middleware/rateLimit');

/** 读源码并剥掉注释：门禁只约束代码形状，不约束注释里的历史示例文字 */
const readCode = (rel) =>
  fs
    .readFileSync(path.join(__dirname, rel), 'utf-8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

const RATE_LIMIT_SRC = () => readCode('../../middleware/rateLimit.js');
const WELLKNOWN_SRC = () => readCode('../../routes/wellKnownRoutes.js');
const SWAGGER_SRC = () => readCode('../../config/swagger.js');

describe('normalizeRateLimitIp（限流键 IP 归一化）', () => {
  test('IPv4 映射形态（::ffff:）收敛为纯 IPv4', () => {
    expect(normalizeRateLimitIp('::ffff:1.2.3.4')).toBe('1.2.3.4');
    expect(normalizeRateLimitIp('::FFFF:1.2.3.4')).toBe('1.2.3.4');
  });

  test('规范 IPv4 原样通过；IPv6 等价写法收敛为 RFC 5952 压缩形式', () => {
    expect(normalizeRateLimitIp('1.2.3.4')).toBe('1.2.3.4');
    expect(normalizeRateLimitIp('2001:0DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
  });

  test('歧义写法并到共享占位键，不回退原文（2026-10-01 修正）', () => {
    // 旧口径"回退原文：该形态自成一桶"在 trust proxy 开着时是反的：req.ip 来自
    // 请求方写的 X-Forwarded-For，换一个垃圾文本就换一个全新桶 ⇒ 配额刷不完、
    // 升级计数永不累积。归一化失败只能并到一个换不掉的共享键。
    expect(normalizeRateLimitIp('0177.0.0.1')).toBe('unknown');
    expect(normalizeRateLimitIp('garbage-not-an-ip')).toBe('unknown');
    expect(normalizeRateLimitIp('999.999.999.999')).toBe('unknown');
    expect(normalizeRateLimitIp('0')).toBe('unknown');
  });

  test('逐请求伪造垃圾 XFF 换不出新桶（P0 复现口径）', () => {
    // 实测（trust proxy=1 + 直连）：proxy-addr 原样透传非 IP 文本，req.ip 即该文本；
    // 修前 100 个不同垃圾串 = 100 个独立配额桶，修后全部收敛为 1 个。
    const keys = Array.from({ length: 100 }, (_, i) => normalizeRateLimitIp(`r-${i}-not-an-ip`));
    expect(new Set(keys).size).toBe(1);
    expect(keys[0]).toBe('unknown');
  });

  test('缺失/空白形态给稳定占位键，不产生 undefined 键', () => {
    expect(normalizeRateLimitIp(null)).toBe('unknown');
    expect(normalizeRateLimitIp(undefined)).toBe('unknown');
    expect(typeof normalizeRateLimitIp('')).toBe('string');
  });

  test('IPv6 同 /56 的不同地址收敛到同一限流键（v8 防地址轮换）', () => {
    const key = (ip) => ipKeyGenerator(normalizeRateLimitIp(ip));
    expect(key('2001:db8:aaaa:bbbb::1')).toBe(key('2001:db8:aaaa:bbbb:ffff::1'));
    expect(key('2001:db8:aaaa:bbbb::1')).not.toBe(key('2001:db8:aaaa:cccc::1'));
  });
});

describe('限流器接线门禁（源码形状）', () => {
  test('rateLimit.js 不允许任何未经归一化/未经可信边界裁定的 req.ip 键拼装', () => {
    const src = RATE_LIMIT_SRC();
    // `:${req.ip}` / `=> req.ip` 两种形态都会造成 ::ffff: 双桶；
    // 归一化调用点写作 normalizeRateLimitIp(clientIpForSecurityDecision(req))：
    // 组键身份必须与准入裁决同一把尺，否则边界外自写 XFF 可逐请求换桶。
    expect(src).not.toMatch(/:\$\{req\.ip\}/);
    expect(src).not.toMatch(/keyGenerator: \(req\) => req\.ip/);
    expect(src).not.toMatch(/normalizeRateLimitIp\(req\.ip\)/);
    // 归一化助手必须存在且被实际使用
    expect(src).toContain('const normalizeRateLimitIp = (ip) =>');
    expect(
      src.match(/normalizeRateLimitIp\(clientIpForSecurityDecision\(req\)\)/g).length
    ).toBeGreaterThanOrEqual(13);
    expect(src.match(/ipKeyGenerator\(/g).length).toBeGreaterThanOrEqual(13);
  });

  /**
   * 门禁清单原本只 grep rateLimit.js 与 wellKnownRoutes.js，于是挂在 config/swagger.js
   * 里的 docsLimiter 成了盲区：它按 `api-docs:${req.ip}` 组键，既没归一化（`::ffff:` 双桶）
   * 也没接共享存储（N 个副本 = N×30 次/15 分钟），而该限流器存在的理由正是"拦文档
   * 口令穷举"。补进清单，让"新增限流器"这一族不再按文件位置漏检。
   */
  test('config/swagger.js 的文档限流器必须同口径组键并接共享存储', () => {
    const src = SWAGGER_SRC();
    expect(src).not.toMatch(/api-docs:\$\{req\.ip\}/);
    expect(src).toContain(
      "ipKeyGenerator(normalizeIP(clientIpForSecurityDecision(req)) || 'unknown')"
    );
    expect(src).toContain("makeSharedStore('docs')");
  });

  test('IP 维度限流器的 429 handler 必须上报升级信号', () => {
    const src = RATE_LIMIT_SRC();
    for (const limiter of ['general', 'strict', 'login-ip', 'ip', 'captcha', 'register']) {
      expect(src).toContain(`noteRateLimitHit(req, '${limiter}')`);
    }
    // userLimiter 只在未认证（按 IP 组键）分支上报，认证用户按 userId 组键不封 IP
    expect(src).toMatch(/if \(!req\.user\?\.userId\) noteRateLimitHit\(req, 'user-ip'\)/);
  });

  test('wellKnownRoutes 三个限流器接入共享存储并归一化键（P-9）', () => {
    const src = WELLKNOWN_SRC();
    // 2026-11-17 起三个限流器由 reportLimiterOf(name, max) 工厂统一产出：store/keyGenerator/
    // handler 只在工厂里写一份，差异只剩共享 store 命名空间与配额。门禁改为两层，意图不变：
    // ① 钉工厂形状——store 必须接 makeSharedStore，键必须走安全裁决地址 + 归一化 +
    //    IPv6 /56 聚合（工厂内单点定义恰好 1 处；计数变多即出现绕过工厂的裸限流器）；
    // ② 三个上报/发现端点的注册点逐一显式走工厂并各自命名空间（独立计数），缺一个即红。
    expect(src).toContain('const reportLimiterOf = (name, max) =>');
    expect(src).toContain('store: makeSharedStore(name)');
    expect(src.match(/normalizeRateLimitIp\(clientIpForSecurityDecision\(req\)\)/g).length).toBe(1);
    expect(src.match(/ipKeyGenerator\(/g).length).toBe(1);
    for (const prefix of ['csp-report', 'client-errors', 'security-txt']) {
      expect(src).toContain(`reportLimiterOf('${prefix}'`);
    }
  });
});

/**
 * 登录账号桶（login-user:<username>）的键必须有界——第三轮 D3
 *
 * 缺陷本体：`normalizeLoginRateKey` 只 trim + toLowerCase，而限流器挂在 `loginValidation` **之前**
 * （authRoutes 的 loginLimiter → loginUserLimiter → loginValidation），body 上限 1mb ⇒ 单个请求就能
 * 让 Redis/MemoryStore 里出现一个接近 1MB 的键，且 15 分钟窗口内不释放。
 *
 * 判据分两层，缺一层就能被绕过：
 *   1. 单元层：超长 username 归一后长度有界；
 *   2. 行为层：**换不出新配额**——今天每个不同的长串都是新桶，于是"轮换长 username"等于"无限配额"。
 *      修法不是截断（前 64 字符相同的任意长串会互相挤占同一个桶）也不是摘要（键空间仍由请求方决定），
 *      而是把超出上限的一律并到一个登记在案的共享桶。
 */
describe('登录账号桶键必须有界（未校验输入不得原样成为存储键）', () => {
  test('超长 username 的键长有界（今天会原样进键，长度 200000）', () => {
    const long = 'a'.repeat(200000);
    expect(normalizeLoginRateKey(long).length).toBeLessThanOrEqual(LOGIN_RATE_KEY_MAX_CHARS);
    expect(normalizeLoginRateKey(long)).toBe(LOGIN_RATE_KEY_OVERSIZED);
  });

  test('超长不截断：互不相同（但前 64 字符相同）的长串必须同桶，换不出新配额', () => {
    const prefix = 'a'.repeat(LOGIN_RATE_KEY_MAX_CHARS);
    const keys = Array.from({ length: 50 }, (_, i) =>
      normalizeLoginRateKey(prefix + 'x'.repeat(2000) + i)
    );
    expect(new Set(keys).size).toBe(1);
    expect(keys[0]).toBe(LOGIN_RATE_KEY_OVERSIZED);
  });

  test('非字符串输入不得压成任意键长（对象/数组/undefined 一并收敛）', () => {
    expect(normalizeLoginRateKey({ toString: () => 'z'.repeat(5000) }).length).toBeLessThanOrEqual(
      LOGIN_RATE_KEY_MAX_CHARS
    );
    expect(typeof normalizeLoginRateKey(undefined)).toBe('string');
    expect(normalizeLoginRateKey(undefined).length).toBeLessThanOrEqual(LOGIN_RATE_KEY_MAX_CHARS);
  });

  test('对照：界内的短 username 仍逐值分桶（有界不等于全并一桶）', () => {
    expect(normalizeLoginRateKey('alice')).not.toBe(normalizeLoginRateKey('bob'));
    expect(normalizeLoginRateKey(' alice ')).toBe(normalizeLoginRateKey('ALICE'));
  });

  test('行为层：21 个互不相同的 200KB username 落在同一个桶里，第 21 发 429', async () => {
    const app = express();
    app.set('trust proxy', 1);
    app.use(express.json({ limit: '1mb' }));
    app.use(loginUserLimiter);
    app.post('/login', (req, res) => res.status(400).json({ success: false }));

    const ip = '198.51.100.77';
    let res;
    for (let i = 0; i < 21; i += 1) {
      const username = 'a'.repeat(200000 - 4) + String(i).padStart(4, '0');
      res = await request(app)
        .post('/login')
        .set('X-Forwarded-For', ip)
        .send({ username, password: 'x' });
    }
    // 修前：21 个长串 = 21 个独立桶 ⇒ 永不触顶（本断言红）；修后：同一个 ~oversized 桶 ⇒ 第 21 发 429
    expect(res.status).toBe(429);
  });
});

describe('登录限流告警的日志注入防线（P2-07，审计 2026-11-15）', () => {
  const makeReq = (username) => ({
    body: { username },
    ip: '198.51.100.88',
    headers: {},
    socket: { remoteAddress: '198.51.100.88' },
    method: 'POST',
    path: '/api/auth/login',
  });

  test('含换行的 username 不得把告警拆成多行（控制字符在插值前清洗）', () => {
    const msg = loginUserLimitWarnMessage(
      makeReq('admin\n2026-11-15 ERROR fake line planted by attacker')
    );
    expect(msg).not.toContain('\n');
    expect(msg).not.toContain('\r');
    // 控制字符被替换为空格而不是删除：行内内容仍可读，但不再换行伪造日志
    expect(msg).toContain('admin 2026-11-15 error fake line planted by attacker');
  });

  test('插值基于归一化键（trim/小写）；界内原样、超长并入共享桶键', () => {
    expect(loginUserLimitWarnMessage(makeReq('  ADMIN  '))).toContain('username=admin,');
    const max64 = 'x'.repeat(LOGIN_RATE_KEY_MAX_CHARS);
    expect(loginUserLimitWarnMessage(makeReq(max64))).toContain(`username=${max64},`);
    // 超长 username：normalizeLoginRateKey 并入登记在案的共享桶键（见该函数注释）
    const longMsg = loginUserLimitWarnMessage(makeReq('x'.repeat(200)));
    expect(longMsg).toContain(`username=${LOGIN_RATE_KEY_OVERSIZED},`);
  });

  test('username 缺失时以 "-" 占位（不产生 undefined 字样）', () => {
    expect(loginUserLimitWarnMessage(makeReq(undefined))).toContain('username=-,');
  });
});
