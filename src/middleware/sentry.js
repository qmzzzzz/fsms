const Sentry = require('@sentry/node');

let initialized = false;

/**
 * 出网数据收口（2026-09-26 实测确认的缺陷）
 *
 * `Sentry.Handlers.requestHandler()` 无参调用时走 @sentry/node 7.120.4 的默认采集表
 * （`@sentry/utils/cjs/requestdata.js` 的 `DEFAULT_INCLUDES = {ip:false, request:true,
 * transaction:true, user:true}`，而 `request:true` 又展开成
 * `DEFAULT_REQUEST_INCLUDES = ['cookies','data','headers','method','query_string','url']`）。
 *
 * 端到端实测（同版本、同调用形态、真 beforeSend 里截获事件；探针 DSN 指向 127.0.0.1:1）
 * 打在本仓最敏感的三个点上，修复前**实际出网**的事件内容：
 *   request.data        = '{"username":"admin","password":"***","mfaCode":"123456"}'
 *   request.headers     = {authorization:'Bearer …', cookie:'sid=…', …全量请求头}
 *   request.cookies     = {sid:'…'}
 *   request.query_string= 'next=/home'
 *   request.url         = 'http://<no host>/api/auth/login?next=/home'  ← 查询串在 url 里也有一份
 *   event.user          = {username:'admin', email:'a@b.co'}
 * app.js:189 把 sentryRequestHandler/sentryTracingHandler 挂在所有路由之前、app.js:429 在通用
 * errorHandler（app.js:433）之前用 sentryErrorHandler() 兜异常 ⇒
 * 只要配了 SENTRY_DSN，口令/MFA 码/令牌/会话 cookie 就会随任意一次 5xx 发往 DSN。
 *
 * 关于 event.user 的键：默认表是 `DEFAULT_USER_INCLUDES = ['id','username','email']`
 * 且按 `key in req.user` 逐个取，本仓 req.user（auth.js buildAuthContext）用的是
 * `userId` 而非 `id` ⇒ 实测只抠出 username + email。这不构成"只需删 username"的理由：
 * email 单独就足以定位到人，而收口的判据是"身份不出网"，不是"这几个键恰好是凭据"。
 *
 * 两层收口，缺一不可（实测两层各自承担了什么）：
 *  - include 白名单（下面的 SENTRY_REQUEST_INCLUDE）把采集侧就关掉，不指望运气管线脱敏。
 *    实测生效面：request 只剩 {method,url}、query_string/headers/cookies/data 根本不进事件、
 *    event.user 整块不再出现（`user:false`）。
 *  - beforeSend 是本模块唯一的出网咽喉，两件事只有它能做到：
 *    1) url 里那份查询串（'url' 是白名单要保留的项，而它由 req.originalUrl 拼成，天然带 ?query）
 *       实测只有这一层能削掉；
 *    2) 把 event.request 整个面按**保留白名单**重削一遍（SENTRY_ALLOWED_REQUEST_FIELDS）。
 *       咽喉不读上面的采集白名单、也不看 SDK 版本的字段命名表，所以升级 @sentry/node、
 *       有人改回 `requestHandler()` 无参、甚至有人往采集白名单里加键，都不会重新打开这个洞
 *       （用例 `sentryOutboundScrub.test.js` 的四臂矩阵 + 变异实测钉着这几条）。
 * 保留 method + 去查询串的 path：定位 5xx 需要的就是这两个，凭据一律不出网。
 *
 * 判据口径（用例与探针都按这个来）：不看 beforeSend 的入参，看**真的写进 transport 的字节**。
 * 实测（自定义 transport 截获 envelope）修复后三处泄漏面全清，只剩
 * `request: {method:'POST', url:'http://<no host>/api/auth/login'}` + `transaction:
 * 'POST /api/auth/login'`。两点容易误判的事实，一并钉在这里：
 *  - 事件对象上的 `sdkProcessingMetadata.request` 是**未裁剪的原始 req**（含 body/headers/user），
 *    但它不会进 envelope（SDK 在序列化前剥掉）⇒ 别把它当泄漏面去补，白做功；
 *  - `include.transaction` 我没关（默认表里它是 true），因为它写的是参数化路由名、实测不含查询串，
 *    关掉只会丢掉 Sentry 侧的分组能力。
 */
const SENTRY_REQUEST_INCLUDE = {
  request: ['method', 'url'],
  // 显式关掉默认的 user 提取：本仓从不调 Sentry.setUser，事件里的身份只可能来自 req.user
  user: false,
};

/**
 * 出网咽喉对 `event.request` 只保留这两个键：独立于 SENTRY_REQUEST_INCLUDE，也独立于 SDK 的字段命名。
 *
 * 为什么是"白名单保留"而不是"黑名单逐个删"（变异实测逼出来的第二个洞）：
 * `include.request` 允许是数组，而 `@sentry/utils/cjs/requestdata.js` 的 `extractRequestData`
 * 对认不出的键名走 `default:` 分支——`if ({}.hasOwnProperty.call(req, key)) requestData[key] = req[key]`，
 * 即**原样抄 req 上的同名属性**。所以只要有人往上面的采集白名单里加一个 `'user'`，
 * 事件里就会多出一份 `request.user = req.user`（原始对象：userId/username/email/realName/sessionId 全在），
 * 而它既不经 `include.user`（已置 false）、也不叫 data/headers/cookies 里的任何一个名字
 * ⇒ 黑名单删不到它。黑名单永远只能追"已知的字段名"，白名单一次到位：认不出的键一律不出网。
 * 代价为零：本模块自己只声明要 method + url，Sentry 侧定位 5xx 需要的也是这两个（+ transaction）。
 */
const SENTRY_ALLOWED_REQUEST_FIELDS = ['method', 'url'];

/**
 * 出网前的事件收口（纯函数，便于单测；同时作为 init 的 beforeSend）
 * @param {object|null} event Sentry 事件
 * @returns {object|null} 原样返回（已就地削减敏感字段），null 输入透传
 */
function scrubOutboundEvent(event) {
  if (!event || typeof event !== 'object') return event;
  const request = event.request;
  if (request && typeof request === 'object') {
    for (const field of Object.keys(request)) {
      if (!SENTRY_ALLOWED_REQUEST_FIELDS.includes(field)) delete request[field];
    }
    if (typeof request.url === 'string') request.url = request.url.split('?')[0];
  }
  // transaction 名同样去查询串：本版本实测它已是参数化路由（'POST /api/auth/login'，
  // extractPathForTransaction 自带切分），所以这一行今天不改变任何输出；
  // 留着它是因为 transaction 与 request.url 是两处独立写入、共用同一份 originalUrl，
  // 而出网咽喉的判据是"不依赖 SDK 版本的默认行为"。
  if (typeof event.transaction === 'string') event.transaction = event.transaction.split('?')[0];
  // user 整块删掉，不是只删某个键：实测默认表从 req.user 抠出 {username, email}，
  // 单留 email 就足以定位到人。整块删的代价为零：本仓从不调 Sentry.setUser
  // （grep 全仓无匹配），也没有任何一处依赖事件里的 user 做聚合。
  delete event.user;
  return event;
}

function initSentry() {
  if (process.env.SENTRY_DSN) {
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV || 'development',
      tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
      // v7 起 AutoSessionTracking 不再是 Sentry.Integrations 的成员，改为 init 选项。
      // 旧写法 new Sentry.Integrations.AutoSessionTracking() 拿到的是 undefined，
      // 会在配置 SENTRY_DSN 时直接抛 TypeError，导致初始化失败。
      autoSessionTracking: true,
      integrations: [new Sentry.Integrations.Http({ tracing: true })],
      beforeSend: scrubOutboundEvent,
    });
    initialized = true;
    return true;
  }
  return false;
}

/** 是否已初始化（供调用方在 captureException 前判断，避免未配置时的无效调用噪音） */
function isSentryInitialized() {
  return initialized;
}

function sentryRequestHandler() {
  return Sentry.Handlers.requestHandler({ include: SENTRY_REQUEST_INCLUDE });
}

function sentryTracingHandler() {
  return Sentry.Handlers.tracingHandler();
}

function sentryErrorHandler() {
  return Sentry.Handlers.errorHandler();
}

function captureException(error, context = {}) {
  Sentry.captureException(error, { extra: context });
}

module.exports = {
  initSentry,
  isSentryInitialized,
  sentryRequestHandler,
  sentryTracingHandler,
  sentryErrorHandler,
  captureException,
  scrubOutboundEvent,
  SENTRY_REQUEST_INCLUDE,
  SENTRY_ALLOWED_REQUEST_FIELDS,
};
