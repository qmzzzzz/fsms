/**
 * HTTP 安全头与 CSP（自 `middleware/security.js` 拆出，2026-10-18）
 *
 * 内容：CSP（每请求 nonce / Swagger 豁免 / 上报端点）与 helmet 全量响应头配置、
 * HSTS 明文兜底、Permissions-Policy、Reporting-Endpoints、Trusted Types 灰度。
 * 纯写响应头，不读 body、不碰数据库；挂载顺序见 security/index.js 的 applyResponseHardening。
 *
 * 拆分动机：原文件 ESLint 计 644 代码行（max-lines 300），本段无任何出站调用，
 * 是风险最低的一块；对外导出面由 security/index.js 原样再导出。
 */

const crypto = require('crypto');
const helmet = require('helmet');
const { matchesAnyPathPrefix } = require('../../utils/helpers');

/**
 * CSP 违规上报端点（G9）
 * 由 CSP_REPORT_ENABLED 开启：开启后 CSP 头附加 report-uri，浏览器把违规详情
 * POST 到该路径。默认关闭——未部署上报消费方时下发 report-uri 只会给
 * 每个客户端凭空增加一条失败请求。
 */
const CSP_REPORT_PATH = '/csp-report';
const cspReportEnabled = process.env.CSP_REPORT_ENABLED === 'true';

/**
 * A7（2026-10-16）：Trusted Types 由 report-only 升为**强制**的开关。
 *
 * 默认 false —— 保持灰度（见下方 trustedTypesReportOnly 的头注释）。置 true 时：
 *   ① `require-trusted-types-for 'script'` 挪进**主 CSP**（强制头，浏览器会阻断违规的
 *      DOM 写入：innerHTML / insertAdjacentHTML / document.write / 三方 SDK 的 DOM 写入）；
 *   ② 不再下发 report-only 头（同一个策略下发两遍，浏览器会按两条独立策略各报一次，
 *      违规计数翻倍，而"报告数"正是本开关的决策依据）。
 *
 * ⚠ 前置条件是**数据**而不是代码（deliverables/安全需求加固清单-2026-10-16.md A7）：
 * 必须先让 `CSP_REPORT_ENABLED=true` 跑够一段时间（建议 ≥2 周），确认
 * `require-trusted-types-for` 的违规清零、或每一条都有正当豁免，再打开本开关。
 * 没跑够灰度就升强制会**直接打断前端**（且是"页面局部功能静默失效"这种最难排查的形态）。
 *
 * 为什么用环境变量而不是直接改代码：升级是一次**部署决策**（依赖灰度数据），
 * 而代码里没有任何判据能替运维做这个决定；写成常量会让"回退"变成一次代码提交 +
 * 重新构建镜像。开关 + 一条用例（securityHeaderPolicyHardening.test.js 的 A7 组）
 * 让"升强制"与"回退"都是改一个环境变量重启。
 */
const trustedTypesEnforced = process.env.TRUSTED_TYPES_ENFORCE === 'true';

/**
 * 1. HTTP 安全头配置
 * 使用 Helmet 设置各种安全相关的 HTTP 响应头
 *
 * style-src（L-5）：全站不再允许 'unsafe-inline'，改为每请求随机 nonce；
 * 仅 /api-docs（Swagger UI 会自注入内联 <style>，无法携带 nonce）单独
 * 放行 'unsafe-inline'，把放宽面收敛到文档路径。
 */
const SWAGGER_PATH_PREFIX = '/api-docs';

// 路径前缀判定用全仓同一把尺（按段边界 + 大小写不敏感）：Express 5 默认大小写不敏感路由，
// 手写的 `=== / startsWith` 会让 `/API-docs` 命中 Swagger 路由却判为"非文档路径"，
// 于是那条响应拿不到它必需的 'unsafe-inline'（方向是变严、不是漏洞，但两处口径不一致）。
const isSwaggerDocsPath = (req) => matchesAnyPathPrefix([SWAGGER_PATH_PREFIX], req.path);

const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': ["'self'"],
  'style-src': [
    "'self'",
    (req, res) => (isSwaggerDocsPath(req) ? "'unsafe-inline'" : `'nonce-${res.locals.cspNonce}'`),
  ],
  'img-src': ["'self'", 'data:', 'blob:'],
  'font-src': ["'self'", 'data:'],
  'connect-src': ["'self'"],
  'object-src': ["'none'"],
  'frame-ancestors': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"],
};

if (cspReportEnabled) {
  // report-uri 已被规范标记为废弃，但仍是当前浏览器覆盖面最广的上报通道，
  // 因此与新版 report-to（配合 Reporting-Endpoints 响应头）同时下发
  CSP_DIRECTIVES['report-uri'] = [CSP_REPORT_PATH];
  CSP_DIRECTIVES['report-to'] = ['csp-endpoint'];
}

// A7（2026-10-16）：升强制时把 require-trusted-types-for 挪进**主 CSP**。
// 必须在 securityHeaders 构造**之前**写入——helmet 在构造期就把 directives 快照进
// 中间件，之后再改这个对象对已构造的 securityHeaders 无效（静默无效，不会有任何提示）。
if (trustedTypesEnforced) {
  CSP_DIRECTIVES['require-trusted-types-for'] = ["'script'"];
}

/**
 * 生成每请求 CSP nonce（L-5）
 * 必须在 securityHeaders 之前挂载：helmet 的 style-src 函数指令在写响应头时
 * 读取 res.locals.cspNonce。API 以 JSON 为主，生成开销可忽略。
 */
const attachCspNonce = (req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
};

const securityHeaders = helmet({
  // 内容安全策略：API 以 JSON 为主，仍启用严格 CSP；
  // style 走每请求 nonce（仅 /api-docs 放行 'unsafe-inline'），script 仅限同源
  contentSecurityPolicy: {
    useDefaults: false,
    directives: CSP_DIRECTIVES,
  },
  // 跨域嵌入策略（COEP）——**有意关闭**，勿按"漏配"处理（2026-10-15 补决策记录）
  //
  // 为何关闭：COEP 的唯一用途是开启跨源隔离（`crossOriginIsolated === true`），
  // 从而解锁 SharedArrayBuffer / performance.measureUserAgentSpecificMemory 等高精度
  // 能力。FSMS 是内部单体系统，无任何跨源隔离需求；而开启后浏览器会要求**所有**
  // 子资源携带 CORP 或 CORS 授权，本仓依赖的跨源资源会成片加载失败——/api-docs 的
  // Swagger UI 自注入资源、Google Fonts（style-src/font-src 已显式放行
  // fonts.googleapis.com、fonts.gstatic.com）、报表导出的 blob: 下载。收益为负。
  //
  // 何时应重新评估：① 前端确需 SharedArrayBuffer / 跨源隔离能力；② 跨源资源全部
  // 迁回同源，或逐项补齐 CORP/CORS（含 /api-docs 路径）；③ 上游基线要求
  // `credentialless`——注意 credentialless 是"不带凭据的跨源加载"，仍会拦掉需要
  // Cookie/凭据的跨源请求，不是免费开关，必须按上面的清单逐项实测再决定。
  // 现状记录：本轮之前全仓（含 *.md）无任何 COEP 决策留痕，下一个人照抄外部基线时
  // 没有反面证据可查——这条注释就是那份证据。
  crossOriginEmbedderPolicy: false,
  // 跨域 opener 隔离
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  // 跨域资源策略（CORP）——2026-10-15 由 same-site 收紧到 same-origin
  // 取值与另外四份副本对齐：nginx.conf.example 的 server 级/`location /`/`location /assets/`
  // 三份、web-admin/vite.config.js 的 buildSecurityHeaders，以及 helmet 7 的默认值
  // （node_modules/helmet/index.cjs:168 `{policy = "same-origin"}`）。
  // 影响面：同源反代拓扑下前后端同源，same-origin 对同源 fetch 无影响，只收紧
  // "同站子域跨源读取 API 响应"这一档（本仓无子域前端，nginx 单 server_name）。
  crossOriginResourcePolicy: { policy: 'same-origin' },
  // DNS 预获取控制
  dnsPrefetchControl: { allow: false },
  // 帧选项（防止点击劫持）
  frameguard: { action: 'deny' },
  // 隐藏 X-Powered-By 头
  hidePoweredBy: true,
  // HSTS (HTTP Strict Transport Security)
  // 注意：helmet 仅在 HTTPS 请求上下发该头；HTTP 兜底下发见 applySecurity 中的 ensureHsts
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  // IE 禁止
  ieNoOpen: true,
  // 禁止 MIME 嗅探
  noSniff: true,
  // 来源策略
  originAgentCluster: true,
  // Referrer 策略——2026-10-15 由 strict-origin-when-cross-origin 收紧到 same-origin
  //
  // 这是 FSMS 此前**唯一**比上游基线松的响应头。取值须与另外四份副本一致：
  // nginx.conf.example:108（server 级）、:175（`location /`）、:217（`location /assets/`）、
  // web-admin/vite.config.js:134（buildSecurityHeaders）。注意 nginx 侧安全头有三份
  // 副本且 `add_header` 在嵌套块是整体替换（见该文件 L-09 注释），漏改一份就是一条
  // 静默退化的路径；本仓此前**没有**针对 Referrer-Policy 的跨副本一致性断言，
  // 现由 src/tests/middleware/securityHeaderPolicyHardening.test.js 钉住五份取值相同。
  //
  // 前置确认（已实测，2026-10-15）：
  //  ① 跨源子资源仅 Google Fonts（fonts.googleapis.com / fonts.gstatic.com），
  //     不依赖 Referer ⇒ 无影响；
  //  ② 全仓无外部跳转 / 防盗链 / 外链来源分析：web-admin/src 无
  //     window.open / location.href= / target="_blank" / document.referrer，
  //     nginx.conf.example 无 valid_referers；
  //  ③ 后端唯一消费 Referer 的是 src/middleware/originCheck.js:57（Origin 头缺失时的
  //     回退分支）——同源请求在 same-origin 下照常携带 Referer，且浏览器写请求必带
  //     Origin 走优先分支，回退分支不受影响。
  // 风险提示：跨源请求将完全不带 Referer；若将来引入外链来源分析或防盗链，须回头复评。
  referrerPolicy: { policy: 'same-origin' },
  // XSS Auditor 显式禁用（2026-10-15 回源更正注释）
  //
  // helmet 的该选项**语义反直觉**，勿按字面理解（回源：node_modules/helmet/
  // index.cjs 的 xXssProtection() 恒 setHeader("X-XSS-Protection", "0")，
  // 且 getMiddlewareFunctionsFromOptions 里 `case true: push(...)` /
  // `case false: break`）：
  //   - xssFilter: true（当前值）⇒ 下发 `X-XSS-Protection: 0`，即**主动禁用**
  //     有绕过历史的旧 XSS Auditor（OWASP 建议显式置 0；现代浏览器已忽略该头，
  //     仅为兼容性工具保留）；
  //   - xssFilter: false ⇒ **完全不设该头**（不是"设 0"），且 helmet 不告警。
  // 原注释写作「XSS 保护（旧版浏览器）」，与真实行为方向相反——照字面读会以为
  // 这是"开启保护"，进而可能在排障时把它当成冗余项删掉/关掉。
  // XSS 防护实际由 CSP（每请求 nonce，见上方 CSP_DIRECTIVES）+ 前端框架输出转义承担。
  // 口径一致性：deployment/nginx.conf.example:111 的 `add_header X-XSS-Protection "0"`
  // 与本项同值（该文件注释所称"与后端 helmet xssFilter 口径一致"经复核成立）。
  // 改动风险提示：本头曾长期无测试守护（全仓 grep 无断言），误改为 false 不会有任何
  // 红灯——经 nginx 的流量仍被 nginx 兜住，但直连 app 端口（容器网络/探针）的响应会
  // 静默失去该头。现由 src/tests/middleware/xssProtectionHeader.test.js 钉住
  // 「下发且精确等于 '0'」与「恰好一个头」，上述误改会立即转红。
  xssFilter: true,
});

/**
 * 1.2 Permissions-Policy 显式下发
 * helmet 7.x 已移除该功能（旧配置会被静默忽略），必须手工下发。
 * 覆盖常见敏感特性：禁用定位/麦克风/摄像头/支付/USB/传感器等。
 */
const PERMISSIONS_POLICY_VALUE = [
  'camera=()',
  'microphone=()',
  'geolocation=()',
  'payment=()',
  'usb=()',
  'magnetometer=()',
  'gyroscope=()',
  'accelerometer=()',
  'fullscreen=(self)',
].join(', ');

const permissionsPolicy = (req, res, next) => {
  res.setHeader('Permissions-Policy', PERMISSIONS_POLICY_VALUE);
  next();
};

/**
 * 1.3 Reporting-Endpoints 下发（G9）
 * report-to 指令依赖该响应头解析具名端点；仅在上报开启时下发，
 * 否则浏览器会为一个不存在的端点保留上报队列。
 */
const reportingEndpoints = (req, res, next) => {
  if (cspReportEnabled) {
    res.setHeader('Reporting-Endpoints', `csp-endpoint="${CSP_REPORT_PATH}"`);
  }
  next();
};

/**
 * 1.4 Trusted Types 灰度（report-only，2026-10-15）
 *
 * 目的：在不阻断任何现有行为的前提下，先摸清前端有多少 DOM 写入点会被
 * `require-trusted-types-for 'script'` 命中（innerHTML / insertAdjacentHTML /
 * document.write / 三方 SDK 的 DOM 写入），为将来是否真正启用 Trusted Types 取证。
 * 只上报不阻断 ⇒ 对现有行为零影响；头名与主 CSP 不同
 * （Content-Security-Policy-Report-Only vs Content-Security-Policy），两者互不干扰。
 *
 * ⚠ helmet 7.2.0 的**构造期硬约束**（回源 node_modules/helmet/index.cjs:90-92）：
 *   `Content-Security-Policy needs a default-src but none was provided. If you really
 *    want to disable it, set it to contentSecurityPolicy.dangerouslyDisableDefaultSrc.`
 *   该检查在 normalizeDirectives() 里、对 reportOnly 与强制模式一视同仁——**不因为
 *   report-only 就放宽**。因此只写 `require-trusted-types-for` 会在模块加载期直接抛错
 *   （整个 app 起不来），必须显式声明「不要 default-src」。
 *   本策略只要 Trusted Types 这一条，故用 dangerouslyDisableDefaultSrc 把 default-src
 *   摘掉——下发结果就是 `require-trusted-types-for 'script'` 一条指令，
 *   不会把 helmet 的全套默认指令（default-src 'self' 等）拖进来制造上报噪音。
 *
 * 上报出口：仅当 CSP_REPORT_ENABLED=true 时附带 report-uri / report-to（与主 CSP
 * 同口径，端点复用 CSP_REPORT_PATH 与 Reporting-Endpoints 的 csp-endpoint）；
 * 关闭时报告只落在浏览器控制台，不下发任何多余指令。
 * 前置条件：开启上报前需先排查前端 DOM 写入点，否则噪音会淹没真实违规。
 *
 * A7（2026-10-16）**升强制**：灰度达标（违规清零或全部有正当豁免）后，把
 * `require-trusted-types-for 'script'` 挪进主 CSP。开关是 `TRUSTED_TYPES_ENFORCE`
 * （见文件上方的 trustedTypesEnforced 注释）——置 true 后本中间件退化为 no-op，
 * 同一条指令改由 securityHeaders 的强制头下发。
 */
const TRUSTED_TYPES_REPORT_ONLY_DIRECTIVES = {
  'default-src': helmet.contentSecurityPolicy.dangerouslyDisableDefaultSrc,
  'require-trusted-types-for': ["'script'"],
};

if (cspReportEnabled) {
  TRUSTED_TYPES_REPORT_ONLY_DIRECTIVES['report-uri'] = [CSP_REPORT_PATH];
  TRUSTED_TYPES_REPORT_ONLY_DIRECTIVES['report-to'] = ['csp-endpoint'];
}

/**
 * 强制态下的占位中间件（A7，2026-10-16）。
 *
 * 用 no-op 透传而不是 `if (trustedTypesReportOnly) app.use(...)`：挂载点保持**无条件**
 * 一条语句，applyResponseHardening 的圈复杂度与行数不变（棘轮只许降不许升），
 * 也让"策略到底下发在哪一条头里"这件事只有一处判断（本文件的 trustedTypesEnforced），
 * 而不是"构造处判一次、挂载处再判一次"——两处判据分叉就是一条静默失效的路径
 * （例如强制态下仍下发 report-only，同一个策略下发两遍）。
 */
const noTrustedTypesReportOnly = (req, res, next) => next();

const trustedTypesReportOnly = trustedTypesEnforced
  ? noTrustedTypesReportOnly
  : helmet.contentSecurityPolicy({
      useDefaults: false,
      reportOnly: true,
      directives: TRUSTED_TYPES_REPORT_ONLY_DIRECTIVES,
    });

/**
 * 1.1 HSTS 兜底下发
 * helmet 默认仅在安全连接（HTTPS）下设置 Strict-Transport-Security。
 * 为保证反向代理/扫描器在任意入口都能看到该头，此处对未携带 HSTS 的响应统一下发；
 * 浏览器按 RFC 6797 只会采纳经 HTTPS 送达的 HSTS，明文下的头不构成安全风险。
 */
const ensureHsts = (req, res, next) => {
  if (!res.getHeader('Strict-Transport-Security')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
};
module.exports = {
  securityHeaders,
  attachCspNonce,
  ensureHsts,
  permissionsPolicy,
  reportingEndpoints,
  trustedTypesReportOnly,
  CSP_REPORT_PATH,
  cspReportEnabled,
};
