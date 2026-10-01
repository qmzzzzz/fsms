/**
 * 限流键 IP 归一化与 CC 升级接线门禁
 *
 * 两类判据：
 *  1. 行为判据（normalizeRateLimitIp）：`::ffff:1.2.3.4` 与 `1.2.3.4` 必须落进
 *     同一个限流桶——名单侧（IPBlacklist）入库前归一化，限流侧若按原文组键，
 *     同一来源拿到两份配额，标称阈值名存实亡（总账 §4.4 双桶条目）。
 *  2. 接线判据（源码门禁，仓库既有 pattern）：所有以 IP 组键的限流器必须显式
 *     走 normalizeRateLimitIp，所有 IP 维度限流器的 429 handler 必须上报升级
 *     信号。谁加新限流器忘了归一化/上报，这两条就红——比逐个跑 HTTP 集成
 *     用例便宜，且对"未来新增的限流器"同样有效。
 */

const fs = require('fs');
const path = require('path');

const { normalizeRateLimitIp } = require('../../middleware/rateLimit');

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
});

describe('限流器接线门禁（源码形状）', () => {
  test('rateLimit.js 不允许任何未经归一化的 req.ip 键拼装', () => {
    const src = RATE_LIMIT_SRC();
    // `:${req.ip}` / `=> req.ip` 两种形态都会造成 ::ffff: 双桶；
    // 归一化调用点写作 normalizeRateLimitIp(req.ip)
    expect(src).not.toMatch(/:\$\{req\.ip\}/);
    expect(src).not.toMatch(/keyGenerator: \(req\) => req\.ip/);
    // 归一化助手必须存在且被实际使用
    expect(src).toContain('const normalizeRateLimitIp = (ip) =>');
    expect(src.match(/normalizeRateLimitIp\(req\.ip\)/g).length).toBeGreaterThanOrEqual(9);
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
    expect(src).toContain("normalizeIP(req.ip) || 'unknown'");
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
    for (const prefix of ['csp-report', 'client-errors', 'security-txt']) {
      expect(src).toContain(`makeSharedStore('${prefix}')`);
    }
    // 三个 keyGenerator 全部走归一化（::ffff: 双桶在日志放大类端点上同样成立）
    expect(src.match(/normalizeRateLimitIp\(req\.ip\)/g).length).toBe(3);
  });
});
