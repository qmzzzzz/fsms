/**
 * HTTP 安全头与 CSP：CSP（每请求 nonce / Swagger 豁免 / 上报端点）、helmet 全量响应头、
 * HSTS 明文兜底、Permissions-Policy、Reporting-Endpoints、Trusted Types 灰度。
 * 纯写响应头——不读 body、不碰数据库；挂载顺序见 security/index.js 的 applyResponseHardening。
 */

const crypto = require('crypto');
const helmet = require('helmet');
const { matchesAnyPathPrefix } = require('../../utils/helpers');

/**
 * CSP 违规上报端点（G9）：由 CSP_REPORT_ENABLED 开启后下发 report-uri / report-to。
 * 默认关闭——没有上报消费方时下发端点只会给每个客户端凭空增加一条失败请求。
 */
const CSP_REPORT_PATH = '/csp-report';
const cspReportEnabled = process.env.CSP_REPORT_ENABLED === 'true';

/**
 * Trusted Types 强制开关（A7）。默认 false = 保持灰度（见 trustedTypesReportOnly）。
 * 置 true 时：① require-trusted-types-for 挪进主 CSP（浏览器阻断违规的 DOM 写入）；
 * ② 不再下发 report-only 头（同一策略下发两遍会让违规计数翻倍）。
 *
 * ⚠ 前置条件是灰度数据：先跑 CSP_REPORT_ENABLED=true ≥2 周，确认违规清零或每一条
 * 都有正当豁免。没跑够就升强制会直接打断前端（页面局部功能静默失效，最难排查）。
 * 用环境变量而非常量：升级依赖部署决策，代码里没有判据能替运维做；
 * 开关让升强制与回退都只是改一个环境变量重启，不必重新构建镜像。
 */
const trustedTypesEnforced = process.env.TRUSTED_TYPES_ENFORCE === 'true';

/**
 * 1. HTTP 安全头配置（helmet）
 *
 * style-src（L-5）：全站禁用 'unsafe-inline'，改为每请求随机 nonce；
 * 仅 /api-docs（Swagger UI 自注入内联 <style>，无法携带 nonce）放行，把放宽面收敛到文档路径。
 */
const SWAGGER_PATH_PREFIX = '/api-docs';

// 路径判定用全仓同一把尺（按段边界 + 大小写不敏感）：手写 === / startsWith 会让
// /API-docs 命中路由却判为非文档路径，拿不到它必需的 'unsafe-inline'（方向是变严，但口径分叉）。
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
  // 跨域嵌入策略（COEP）——**有意关闭**，勿按"漏配"处理。
  // 唯一用途是开启跨源隔离（SharedArrayBuffer 等）；FSMS 是内部单体，无此需求，
  // 而开启后所有子资源都必须带 CORP/CORS，Swagger UI、Google Fonts、blob: 下载会成片失败。
  // 重新评估条件：前端确需跨源隔离；或跨源资源全部同源化 / 逐项补齐 CORP（含 /api-docs）。
  crossOriginEmbedderPolicy: false,
  // 跨域 opener 隔离
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  // 跨域资源策略（CORP）。取值须与 nginx.conf.example 三份、web-admin/vite.config.js、
  // helmet 默认值一致（securityHeaderPolicyHardening.test.js 钉住五份相同）。
  // 同源反代下对同源 fetch 无影响，只收紧"同站子域跨源读取 API 响应"。
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
  // Referrer 策略。取值须与另外四份副本一致（nginx.conf.example 三份 +
  // web-admin/vite.config.js），由 securityHeaderPolicyHardening.test.js 钉住五份相同；
  // nginx 的 add_header 在嵌套块是整体替换，漏改一份就是一条静默退化路径。
  // 影响面：跨源子资源仅 Google Fonts（不依赖 Referer）；全仓无外链跳转/防盗链/来源分析；
  // 后端唯一消费 Referer 的是 originCheck.js 的 Origin 缺失回退分支，同源请求照常携带。
  // 若将来引入外链来源分析或防盗链，须回头复评。
  referrerPolicy: { policy: 'same-origin' },
  // XSS Auditor 显式禁用。helmet 的语义**反直觉**（回源 index.cjs 的 xXssProtection()）：
  //   - xssFilter: true ⇒ 下发 X-XSS-Protection: 0，主动禁用有绕过历史的旧 Auditor（当前值）；
  //   - xssFilter: false ⇒ 完全不设该头（不是"设 0"），且 helmet 不告警。
  // XSS 防护实际由 CSP（每请求 nonce）+ 前端框架输出转义承担；
  // nginx.conf.example 的 add_header 与本项同值。
  // xssProtectionHeader.test.js 钉住"下发且恰为 '0'"，误改为 false 会立即转红。
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
 * Trusted Types 灰度（report-only）。
 * 不阻断任何现有行为，只上报会被 require-trusted-types-for 命中的 DOM 写入点
 * （为是否升强制取证）。头名与主 CSP 不同（Report-Only vs 强制），两者互不干扰。
 *
 * ⚠ helmet 7.2.0 构造期硬约束（index.cjs:90-92）：CSP 必须声明 default-src，
 * report-only 也不例外；只写 require-trusted-types-for 会在模块加载期直接抛错。
 * 本策略只要这一条，故用 dangerouslyDisableDefaultSrc 摘掉 default-src，
 * 避免把 helmet 全套默认指令拖进来制造上报噪音。
 *
 * 上报出口仅当 CSP_REPORT_ENABLED=true 时附带（端点复用 CSP_REPORT_PATH）。
 * 强制态下本中间件退化为 no-op，同一条指令改由 securityHeaders 下发。
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
 * 强制态下的占位中间件（A7）。
 * 用 no-op 透传而不是条件 app.use：挂载点保持无条件一条语句（max-lines/圈复杂度棘轮），
 * 也让"策略下发在哪条头里"只有 trustedTypesEnforced 一处判断——两处判据分叉
 * 就是静默失效（例如强制态仍下发 report-only，同一策略下发两遍）。
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
