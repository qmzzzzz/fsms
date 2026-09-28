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

describe('normalizeRateLimitIp（限流键 IP 归一化）', () => {
  test('IPv4 映射形态（::ffff:）收敛为纯 IPv4', () => {
    expect(normalizeRateLimitIp('::ffff:1.2.3.4')).toBe('1.2.3.4');
    expect(normalizeRateLimitIp('::FFFF:1.2.3.4')).toBe('1.2.3.4');
  });

  test('规范 IPv4 原样通过；IPv6 等价写法收敛为 RFC 5952 压缩形式', () => {
    expect(normalizeRateLimitIp('1.2.3.4')).toBe('1.2.3.4');
    expect(normalizeRateLimitIp('2001:0DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
  });

  test('歧义写法回退原文（自成一桶，不与任何他人共享）', () => {
    // normalizeIP 对八进制/十六进制等歧义形态返回 null：
    // 限流侧不做"帮你猜写法"，回退原文保持与改前相同的 fail-closed 语义
    expect(normalizeRateLimitIp('0177.0.0.1')).toBe('0177.0.0.1');
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
