const Sentry = require('@sentry/node');

let initialized = false;

/**
 * 出网数据收口（2026-09-26 实测确认的缺陷）
 *
 * `Sentry.Handlers.requestHandler()` 无参调用时走 @sentry/node 7.x 的默认采集表
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
 * `request: {method:'POST', url:'http://<no host>/api/auth/login'}`。
 * v11 迁移后的两点变化，一并钉在这里：
 *  - `transaction` 不再由 RequestData 集成写入（v8 起重构，改由 tracing 的 span 名提供，
 *    本仓 tracesSampleRate>0 时由 httpIntegration 产生）；对它的去查询串剥离由
 *    scrubOutboundEvent 承担，纯函数真值表覆盖。
 *  - 事件对象上的 `sdkProcessingMetadata.normalizedRequest` 是归一化请求（含 data/headers），
 *    同样不会进 envelope（SDK 序列化前剥掉）⇒ 别把它当泄漏面去补，白做功。
 */
/**
 * v11 适配：`requestDataIntegration` 的 include 是**扁平结构**——v7 的两级写法
 * `{request: [...], user: false}` 在 v8 随 RequestData 集成一起重构，v11 只剩这六个键。
 * 六个键全部显式关掉、只留 url：v11 的推导默认值（sendDefaultPii 未设时）是
 * `cookies/headers/query_string` 开着（deny 只过滤已知敏感名，属黑名单）+ `data` 恒真
 * （`dataCollection.httpBodies` 只管写入不管读取）⇒ 不显式关就是洞。
 * `method` 不受 include 控制（extractNormalizedRequestData 无条件写），`url` 恒开。
 *
 * 这是采集侧第一层；第二层（beforeSend 保留白名单）独立于它，见 SENTRY_ALLOWED_REQUEST_FIELDS。
 */
const SENTRY_REQUEST_INCLUDE = {
  cookies: false,
  data: false,
  headers: false,
  ip: false,
  query_string: false,
  url: true,
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
      // v11：PII 采集总闸显式关闭。注意 v11.4.0 起 init 的 sendDefaultPii 已不再映射到
      // dataCollection（实测该版本 resolveDataCollectionOptions 只认 dataCollection 键，
      // 不传时按 DEFAULTS 全开：userInfo/cookies/httpHeaders/httpBodies/urlQueryParams）
      // ⇒ 逐键显式关，sendDefaultPii 那句是自欺欺人，不写。
      dataCollection: {
        userInfo: false,
        cookies: false,
        httpHeaders: false,
        httpBodies: [],
        urlQueryParams: false,
      },
      // v11：默认集成里已有一个无配置的 requestDataIntegration 和一个开 tracing 的
      // httpIntegration；这里传同名带 include 的实例覆盖前者（filterDuplicates 后者胜），
      // tracing 交给后者。v7 的 new Sentry.Integrations.Http({tracing:true}) 与
      // autoSessionTracking init 选项都已随 Sentry.Integrations 在 v8+ 移除。
      integrations: [Sentry.requestDataIntegration({ include: SENTRY_REQUEST_INCLUDE })],
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

/**
 * v11 起请求/追踪数据由集成自动采集（requestDataIntegration + httpIntegration），
 * Handlers.requestHandler / tracingHandler 这两个中间件在 v8 移除、v11 无替代导出。
 * 保留函数与中间件形状（app.js:189-190 的挂载点不用改）：返回直通的中间件而不是
 * null，防止调用点 app.use(undefined) 直接炸——形态由测试钉住。
 */
function sentryRequestHandler() {
  return (req, res, next) => next();
}

function sentryTracingHandler() {
  return (req, res, next) => next();
}

/**
 * v11 的官方替代是 Sentry.setupExpressErrorHandler(app)，但它要 app 实例、且内部直接
 * 启 Sentry 自己的错误响应；本模块的调用点（app.js:429）挂在通用 errorHandler 之前、
 * 只拿得到中间件，所以保持 (err,req,res,next) 四参自实现：捕获后继续向后传，响应
 * 仍由本仓的 errorHandler 出（与 v7 Handlers.errorHandler 的行为一致）。
 */
function sentryErrorHandler() {
  return (err, req, res, next) => {
    Sentry.captureException(err);
    next(err);
  };
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
