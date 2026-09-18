const swaggerUi = require('swagger-ui-express');
const rateLimit = require('express-rate-limit');
const openapiSpec = require('../docs/openapi.json');

const swaggerOptions = {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: '消防巡检管理系统 API 文档',
  customfavIcon: '/favicon.ico',
  explorer: true,
  // 【P2-29 CSP 兼容约束】不得启用 customJsStr / customJs（内联脚本）：
  // 全局 CSP 为 `script-src 'self'`（middleware/security.js），内联 <script>
  // 会被浏览器直接拦掉，页面白屏且只在 devtools 里报错，服务端看到的仍是 200。
  //
  // 实测 swagger-ui-express 5.0.1 的默认模板（未传 customJsStr 时）：
  //   内联 <script> 数量 = 0
  //   外链 <script> = ./swagger-ui-bundle.js | ./swagger-ui-standalone-preset.js | ./swagger-ui-init.js
  //   内联 <style> 数量 = 2   ← style-src 已含 'unsafe-inline'，放行
  // 三个脚本都是同源外链，因此当前配置下 CSP 并不会阻断文档页；
  // 报告中「开启文档即白屏」的判断对本版本不成立，无需为此放宽 script-src。
  //
  // 该不变量由 src/tests/middleware/infraHardening.test.js 的
  // 「渲染模板不含内联 script」用例锁定：一旦升级依赖后模板引入内联脚本，
  // 测试立即失败，避免悄然白屏。
};

/**
 * API 文档专用限流器（P2-30）
 *
 * 原问题：限流器只挂在 `/api/`（app.js），而 /api-docs 与 /api-docs.json
 * 挂在根路径，落在所有限流之外。basicAuth 用 timingSafeEqual 防住了时序侧信道，
 * 但拦不住穷举——攻击者可以不限速地爆破 DOCS_USERNAME / DOCS_PASSWORD，
 * 而这两个值通常是人工设置的弱口令。
 *
 * 配额取 30 次/15 分钟：文档页首屏要拉 html + 3 个 js + css（约 5 个请求），
 * 正常浏览远用不完；爆破则在几次尝试内即被截断。
 * 静态资源与 HTML 共用同一个桶是有意的——按 IP 计数才能真正约束爆破者。
 */
const docsLimiter = rateLimit({
  // P2-70：窗口同样外置（原硬编码 15 分钟）。与 max 同一口径：
  // 只在「有限且为正」时采用，否则回落默认，避免 0/负值让窗口失效。
  windowMs: (() => {
    const ms = Number(process.env.DOCS_RATE_LIMIT_WINDOW_MS);
    return Number.isInteger(ms) && ms > 0 ? ms : 15 * 60 * 1000;
  })(),
  // P2-37：原为 `Number(...) || 30`——负值（如 -1）是**真值**，会原样传给
  // express-rate-limit，得到「配额为负」的限流器：每个请求都被计数并立即超限，
  // 文档页 100% 429。现改为只在「有限且为正」时采用，否则回落默认 30。
  // 同时排除小数（限流器按整数比较）与非数字（Number("abc")=NaN）。
  max: (() => {
    const n = Number(process.env.DOCS_RATE_LIMIT_MAX);
    return Number.isInteger(n) && n > 0 ? n : 30;
  })(),
  // IP 白名单豁免（checkIPBlacklist 在更早阶段设置 req.ipWhitelisted）
  skip: (req) => req.ipWhitelisted === true,
  keyGenerator: (req) => `api-docs:${req.ip}`,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    try {
      require('../utils/logger').warn(
        `API 文档限流触发：${req.ip} - ${req.method} ${req.originalUrl}`
      );
    } catch (_) {
      /* logger 不可用时静默 */
    }
    res.status(429).json({
      success: false,
      message: '访问过于频繁，请稍后再试',
    });
  },
});

/**
 * API 文档是否启用（P2-38：判定口径已统一到 config/validate.js）
 *
 * 规则（实现在 validate.js 的 isDocsEnabled，此处仅转出）：
 *   - 显式设置 ENABLE_API_DOCS 时按其取值判定：'true'/'1' 为开，其余为关；
 *   - 未显式设置时跟随 NODE_ENV：生产默认关，非生产默认开。
 *
 * 为何不再在本文件自行判定：启动期校验（validate.js 的 validateDocsCredentials）
 * 必须与运行期一致，否则 `ENABLE_API_DOCS=1` 会让文档真的开放却不触发
 * 「必须配 DOCS_USERNAME/DOCS_PASSWORD」的启动期拦截——两处口径分叉就是
 * 「静默失效」的温床。单一实现放在零依赖的 validate.js，本文件直接复用。
 *
 * 保留本函数作为导出：app.js 与既有测试（src/tests/config/docsAccess.test.js）
 * 按此名消费。
 *
 * @returns {boolean} true=文档端点启用
 */
const { isDocsEnabled } = require('./validate');

// 启动期一次性告警：文档开启但未配置 Basic Auth 凭据。
// 告警必须放在模块加载期而非请求路径内，否则每个未带凭据的文档请求都会刷一条 warn。
//
// 【M-01 修复】此处原为 fail-open（未配凭据则 basicAuth 直接放行），
// 攻击者无需凭据即可枚举全部 API 端点、请求/响应 schema 与内部权限编码。
// 现改为 fail-closed：basicAuth 拒绝访问，生产环境另由 config/validate.js
// 在启动期直接阻断。告警文案同步改为"已按安全策略拒绝访问"，避免误导运维
// 以为只是提示。
if (isDocsEnabled() && !(process.env.DOCS_USERNAME && process.env.DOCS_PASSWORD)) {
  try {
    require('../utils/logger').warn(
      'ENABLE_API_DOCS 已开启但未设置 DOCS_USERNAME/DOCS_PASSWORD：' +
        'API 文档已按安全策略拒绝访问（fail-closed）。如需开放请同时配置两项凭据。'
    );
  } catch (_) {
    /* logger 不可用时静默 */
  }
}

/**
 * Basic Auth 中间件（fail-closed）
 *
 * 行为约定（M-01）：
 *   - 未配置凭据 → 拒绝（503），不再放行。理由是"文档已开启却无凭据"属配置
 *     错误，此时放行等于把全部接口契约匿名公开；失败方向应为拒绝。
 *   - 生产环境还会在启动期由 config/validate.js 直接阻断，双保险。
 *   - 凭据校验用恒定时间比较，避免时序侧信道。
 */
function basicAuth(req, res, next) {
  const username = process.env.DOCS_USERNAME;
  const password = process.env.DOCS_PASSWORD;

  // fail-closed：文档已开启却无凭据，拒绝访问而非放行
  if (!username || !password) {
    return res.status(503).json({
      success: false,
      message: 'API 文档未配置访问凭据，已按安全策略拒绝访问',
    });
  }

  const authHeader = req.headers.authorization || '';
  const [scheme, encoded] = authHeader.split(' ');

  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep !== -1) {
      const user = decoded.slice(0, sep);
      const pass = decoded.slice(sep + 1);
      // 恒定时间比较，避免时序攻击
      const userOk = timingSafeEqual(user, username);
      const passOk = timingSafeEqual(pass, password);
      if (userOk && passOk) return next();
    }
  }

  res.setHeader('WWW-Authenticate', 'Basic realm="API Docs"');
  return res.status(401).json({ success: false, message: '需要认证' });
}

function timingSafeEqual(a, b) {
  const crypto = require('crypto');
  // 先各自做 SHA-256 归一化为定长摘要，再恒定时间比较，
  // 避免直接比较时因长度不等提前返回而泄漏长度信息
  const bufA = crypto.createHash('sha256').update(Buffer.from(a)).digest();
  const bufB = crypto.createHash('sha256').update(Buffer.from(b)).digest();
  return crypto.timingSafeEqual(bufA, bufB);
}

const serve = swaggerUi.serve;
const setup = swaggerUi.setup(openapiSpec, swaggerOptions);

/**
 * 渲染后的文档 HTML（供 CSP 兼容性测试断言用）
 * 不额外发起 HTTP 请求即可校验「模板是否引入了内联脚本」这一不变量。
 */
function renderDocsHtml() {
  let html = '';
  const res = {
    send: (body) => {
      html = body;
    },
    set: () => res,
    setHeader: () => res,
    status: () => res,
    json: () => res,
  };
  setup({ url: '/', originalUrl: '/api-docs/', headers: {}, query: {} }, res, () => {});
  return html;
}

module.exports = {
  serve,
  setup,
  openapiSpec,
  isDocsEnabled,
  basicAuth,
  docsLimiter,
  renderDocsHtml,
};
