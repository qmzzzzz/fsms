/**
 * 静态面限流豁免：判据单一来源 + 被裸奔的面真的被覆盖（2026-09-30）
 *
 * 缺陷形态（不是"缺一道闸"，是**两份互相不知情的清单**）：
 * rateLimit.js 的 `isStaticFrontendRequest` 判据是「安全方法 + 非 `/api/` 前缀」，
 * staticFrontend.js 的 `RESERVED_PREFIXES` 判据是「本模块确实托管哪一面」。
 * 两者对 11 条非 /api 路径里有 8 条判定相反——旧判据豁免的 8 条里，
 * staticFrontend 一条都不托管。逐条核对后的归属：
 *
 *   /health /readyz            → constants/probePaths.isProbeRequest 单独兜住（已单一来源）
 *   /api-docs                  → swagger.docsLimiter（30 次/15 分钟）
 *   /csp-report /client-errors
 *   /.well-known/security.txt  → wellKnownRoutes 三个专属限流器
 *   /metrics                   → metricsAuth（内网/回环免令牌）——**这就是 app.js 自陈的
 *                                威胁模型「有人从容器网络直连 app:3000」那一档**
 *   /socket.io/                → 无。MAX_CONNECTIONS=1000 约束的是**已建立连接数**，
 *                                而 authenticateSocket 在连接**建立之后**才跑；
 *                                握手是未认证 GET，此前在应用层零限流
 *
 * 后两条是真正的裸奔，且都不是「忘了写限流器」，是「判据本身划错了界」。
 *
 * 本文件钉三件事：
 *   1. 限流侧**只读** staticFrontend 导出的判据（源码形态：不得出现自带清单）；
 *   2. 旧判据与新判据判定不同的路径，逐条确认现在归属明确（不是"没人管"）；
 *   3. 静态面不再是零预算——staticSurfaceLimiter 存在且挂在 app 上。
 *
 * 第 2 条用「从被测对象反推集合」的方式构造（与 earlyRejectionRateLimitedAllSurfaces
 * 对探针清单的处理同一条纪律）：清单少登记一条就少一条用例，
 * 于是"漏登记"这个改动天然测不出来 —— 所以这里额外钉住集合非空且覆盖关键前缀。
 */

const fs = require('fs');
const path = require('path');

const { isStaticSurfaceRequest, RESERVED_PREFIXES } = require('../../middleware/staticFrontend');

const ROOT = path.resolve(__dirname, '../../..');
const RATE_LIMIT_JS = path.join(ROOT, 'src', 'middleware', 'rateLimit.js');
const APP_JS = path.join(ROOT, 'src', 'app.js');

/** 造一个只有 method/path 的最小 req —— 判据本身只读这两个字段 */
const req = (method, urlPath) => ({ method, path: urlPath });

/** 旧判据的原样复刻：安全方法 + 非 `/api/` 前缀（保留在此是为了证明"判定不同"这件事） */
const legacyIsStaticFrontendRequest = (r) =>
  (r.method === 'GET' || r.method === 'HEAD') && !(r.path === '/api' || r.path.startsWith('/api/'));

describe('静态面判据的单一来源', () => {
  test('限流侧不得自带静态面清单（必须委托 staticFrontend）', () => {
    const src = fs.readFileSync(RATE_LIMIT_JS, 'utf8');
    expect(src).toContain("const { isStaticSurfaceRequest } = require('./staticFrontend')");
    // 旧判据的标记：`const isApiPath =` 与本文件自造的 isStaticFrontendRequest
    expect(src).not.toContain('const isApiPath =');
    expect(src).not.toContain('const isStaticFrontendRequest =');
    // 且必须真的用它，而不是 import 完放着
    expect(src).toMatch(/isStaticSurfaceRequest\(req\)/);
  });

  test('判据与 RESERVED_PREFIXES 同尺（大小写不敏感，与 Express 路由一致）', () => {
    // Express 默认 case sensitive routing=false，`/API/x` 会真的进 API 路由。
    // 判据若大小写敏感，`GET /API/devices` 会被当成静态面豁免 ⇒ 一个 API 面裸奔。
    expect(isStaticSurfaceRequest(req('GET', '/API/devices'))).toBe(false);
    expect(isStaticSurfaceRequest(req('GET', '/Assets/x.js'))).toBe(true);
  });

  test('方法维度：只有 GET/HEAD 属于静态面（放大面走的是非安全方法）', () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'TRACE']) {
      expect(isStaticSurfaceRequest(req(method, '/'))).toBe(false);
      expect(isStaticSurfaceRequest(req(method, '/assets/x.js'))).toBe(false);
    }
    expect(isStaticSurfaceRequest(req('GET', '/'))).toBe(true);
    expect(isStaticSurfaceRequest(req('HEAD', '/assets/x.js'))).toBe(true);
  });
});

describe('此前被裸奔的面，现在归属明确', () => {
  /** 旧判据豁免、而 staticFrontend 并不托管的路径 */
  const diverged = RESERVED_PREFIXES.filter((prefix) =>
    legacyIsStaticFrontendRequest(req('GET', prefix))
  );

  test('集合非空且覆盖全部保留前缀（防"清单被清空导致本文件空转"）', () => {
    expect(RESERVED_PREFIXES.length).toBeGreaterThan(5);
    // 注意 `/api` 不在 diverged 里：旧判据的 `!isApiPath` 本来就把它排除，
    // 两边对它的结论一致。下方那条 `filter` 断言把这件事写死。
    for (const must of ['/health', '/readyz', '/metrics', '/socket.io']) {
      expect(diverged).toContain(must);
    }
    // `/api` 是唯一**不**分歧的保留前缀：旧判据的 `!isApiPath` 本来就把它排除，
    // 两边对它的结论一致（不是静态面）。写成显式断言而不是从总数里减 1，
    // 这样"又少一条分歧"会直接指向是哪条前缀，而不是只报一个差值。
    expect(RESERVED_PREFIXES.filter((p) => !diverged.includes(p))).toEqual(['/api']);
  });

  test('每个保留前缀都不再被判为静态面（这是那条真正要钉的不变式）', () => {
    // 上一条钉"分歧存在"，这条钉"分歧已消除"——前者会因为旧判据被删掉而红，
    // 后者在结论正确时恒绿。两条方向相反，缺一条就有一半场景测不到。
    for (const prefix of RESERVED_PREFIXES) {
      expect(isStaticSurfaceRequest(req('GET', prefix))).toBe(false);
    }
  });

  test.each([
    ['/health', '/health'],
    ['/readyz', '/readyz'],
    ['/metrics', '/metrics'],
    ['/socket.io/', '/socket.io/'],
    ['/api-docs', '/api-docs'],
    ['/csp-report', '/csp-report'],
    ['/.well-known/security.txt', '/.well-known/security.txt'],
  ])('%s：不再被判为静态面（回到通用限流的覆盖范围）', (_label, urlPath) => {
    expect(legacyIsStaticFrontendRequest(req('GET', urlPath))).toBe(true);
    expect(isStaticSurfaceRequest(req('GET', urlPath))).toBe(false);
  });

  test('/socket.io 的子路径同样不被豁免（长轮询握手打在 ?EIO=4 上）', () => {
    // 只钉前缀不带查询串的那一条是不够的：实际握手是
    // GET /socket.io/?EIO=4&transport=polling，path 里就是 /socket.io/。
    expect(isStaticSurfaceRequest(req('GET', '/socket.io/'))).toBe(false);
    expect(legacyIsStaticFrontendRequest(req('GET', '/socket.io/'))).toBe(true);
  });

  test('静态面本身仍然被正确识别（豁免集合没有塌成空）', () => {
    for (const p of ['/', '/login', '/dashboard', '/assets/index-abc123.js', '/sw.js']) {
      expect(isStaticSurfaceRequest(req('GET', p))).toBe(true);
    }
  });
});

describe('静态面不再是零预算（豁免 → 换桶）', () => {
  test('app.js 挂载 staticSurfaceLimiter', () => {
    const src = fs.readFileSync(APP_JS, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(src).toMatch(/app\.use\(staticSurfaceLimiter\)/);
    // 必须与另两个资源型限流器相邻挂载（全站），而不是只挂在 /api/ 上——
    // 静态面在 /api/ 之外，挂在 /api/ 上等于这个桶永不计数
    expect(src).toMatch(
      /app\.use\(ipLimiter\);[\s\S]*app\.use\(generalLimiter\);[\s\S]*app\.use\(staticSurfaceLimiter\);/
    );
  });

  test('该桶只在静态面计数（否则会把 API 请求也计进静态配额）', () => {
    const { staticSurfaceSkip } = require('../../middleware/rateLimit');
    // 静态面：未被白名单豁免、非探针 ⇒ 计入
    expect(staticSurfaceSkip({ ...req('GET', '/assets/x.js'), ip: '1.2.3.4' })).toBe(false);
    // API 面 ⇒ 不计入
    expect(staticSurfaceSkip({ ...req('GET', '/api/devices'), ip: '1.2.3.4' })).toBe(true);
    // 白名单 ⇒ 不计入
    expect(
      staticSurfaceSkip({ ...req('GET', '/assets/x.js'), ip: '1.2.3.4', ipWhitelisted: true })
    ).toBe(true);
    // 探针 ⇒ 不计入（探针不在静态面，但判据链要一致）
    expect(staticSurfaceSkip({ ...req('GET', '/health'), ip: '1.2.3.4' })).toBe(true);
  });

  test('该桶不接入 CC 封禁升级阶梯（NAT 聚合流量误封风险）', () => {
    // 静态面被限流绝大多数是"一个出口后面的人全被限了"，接到封禁阶梯上
    // 会把误封从单个 IP 放大到整个办公室。判据：handler 里不得出现 noteRateLimitHit。
    const src = fs.readFileSync(RATE_LIMIT_JS, 'utf8');
    const start = src.indexOf('const staticSurfaceLimiter =');
    expect(start).toBeGreaterThan(-1);
    const body = src.slice(start, src.indexOf('const strictLimiter ='));
    expect(body).toContain('静态面限流触发');
    expect(body).not.toContain('noteRateLimitHit(');
  });
});
