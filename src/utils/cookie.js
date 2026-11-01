/**
 * Cookie 工具 —— httpOnly 令牌 Cookie 契约的唯一实现位置
 *
 * 契约（I-01）：
 * - access_token ：值=accessToken ，path=/          ，maxAge 与 JWT_EXPIRE 一致
 * - refresh_token：值=refreshToken，path=/api/auth  ，maxAge 与 JWT_REFRESH_EXPIRE 一致
 * - 属性：httpOnly: true、sameSite: 'strict'（严格化，原 lax）
 * - secure：生产环境（NODE_ENV=production）或 COOKIE_SECURE=true 时开启
 *
 * access cookie 的 path 必须是 `/`，不能收窄到 `/api`：Socket.IO 的握手请求打在 `/socket.io/`（服务端默认 path，见 services/websocketService/index.js；Nginx 也是独立 location），path=/api 的 cookie **不会**随该请求发出。而前端拿不到令牌本体（httpOnly + 响应体不回传），无法改用 handshake.auth 兜底 ⇒ 握手必然匿名，
 * WebSocket 鉴权整体失效（services/websocketService/handshake.js 只认 auth.token 或 access_token cookie）。path 本来就不是 httpOnly cookie 的安全边界（XSS 可以直接发请求，读不到值也不妨碍利用），SameSite=strict 仍负责跨站请求的防护。 refresh cookie 保持在 /api/auth：只有刷新/登出需要它。
 *
 * 项目未引入 cookie-parser 依赖，此处提供轻量的手动解析实现。
 */

const config = require('../config');

const ACCESS_COOKIE_NAME = 'access_token';
const REFRESH_COOKIE_NAME = 'refresh_token';
const ACCESS_COOKIE_PATH = '/';
const REFRESH_COOKIE_PATH = '/api/auth';

/**
 * 生产环境（isSecureCookie() 为真）下 access cookie 的 `__Host-` 前缀形态
 *
 * `__Host-` 是浏览器强制校验的保留前缀：携带它的 cookie 必须同时满足
 * Secure、Path=/、**不带 Domain 属性**，且只会在 HTTPS 连接上被浏览器接受与回传。
 * 三项条件本实现全部满足（baseCookieOptions 的 secure 位 + ACCESS_COOKIE_PATH=/
 * + 本仓从不传 Domain）。收益：兄弟子域（或被攻陷的子域）无法用 Set-Cookie
 * 覆写主域的令牌 cookie——普通名 cookie 默认按「域匹配」被任意同注册域子域投毒。
 *
 * 两个刻意的边界：
 * 1. **refresh cookie 不加前缀**：`__Host-` 强制 Path=/，而 refresh cookie 的
 *    path=/api/auth（缩小暴露面，见 I-01 注释）不满足前缀要求，硬上会被浏览器
 *    直接拒收 ⇒ 刷新整体失效。refresh 的跨站防护由 SameSite=strict 承担。
 * 2. **仅 isSecureCookie() 时启用**：前缀 cookie 在非 HTTPS（含本地 http 开发）
 *    下会被浏览器静默丢弃，门禁复用 Secure 位同一判据，两侧永远同真同假。
 */
const ACCESS_COOKIE_NAME_SECURED = '__Host-access_token';

/**
 * 读取 access cookie 时应尝试的名字序列（按优先级）。
 *
 * 安全模式 = [带前缀名, 旧普通名]：升级部署后，老会话浏览器里还持有旧普通名
 * cookie（直到 maxAge 自然过期），读侧双名兼容让存量会话零感知平滑迁移；
 * 写侧（setAuthCookies）从启用起只写带前缀名，旧名只减不增，双名窗口有限。
 * 非安全模式 = [普通名]：与升级前完全一致。
 */
const activeAccessCookieNames = () =>
  isSecureCookie() ? [ACCESS_COOKIE_NAME_SECURED, ACCESS_COOKIE_NAME] : [ACCESS_COOKIE_NAME];

/** 按「名字优先级」从已解析的 cookie 对象中取第一个非空值；全缺返回 null */
const pickCookieValue = (cookies, names) => {
  if (!cookies || typeof cookies !== 'object') return null;
  for (const name of names) {
    const value = cookies[name];
    if (typeof value === 'string' && value) return value;
  }
  return null;
};

/**
 * 解析 Cookie 请求头为键值对象兼容多值、URL 编码值与空/非法输入（解析失败返回空对象，不抛错）
 */
const parseCookies = (cookieHeader) => {
  const result = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return result;
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const name = pair.slice(0, idx).trim();
    if (!name) continue;
    let value = pair.slice(idx + 1).trim();
    // 去除可选的包裹引号
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      result[name] = decodeURIComponent(value);
    } catch (_) {
      result[name] = value;
    }
  }
  return result;
};

/**
 * 从 req 中读取解析后的 cookies（带缓存，避免重复解析）
 */
const getCookies = (req) => {
  if (!req.cookies) {
    req.cookies = parseCookies(req.headers?.cookie);
  }
  return req.cookies;
};

/**
 * 将 JWT 过期表达式转换为毫秒
 *
 * 单位集合必须与 jsonwebtoken 自己那套（它依赖的 `ms`）同集，一处不能少：同一个配置值有两个解释器——令牌的 `exp` 由 `ms` 解析，而 cookie 的 `maxAge` 与会话行的 `expiresAt` （sessionService.js:278）由本函数解析。少认一个单位不是报错，而是**静默回落到 fallbackMs**：实测 `'2 weeks'` 在令牌侧是 336h、在改造前的本函数是 168h（回退默认值），于是会话行比它绑定的 refresh 令牌早死七天，第 7～14 天每次刷新都吃 DEVICE_SESSION_REVOKED。
 *
 * 不能在这里 `require('ms')`——它是 jsonwebtoken 的传递依赖，不在本仓 package.json 里。语法表因此只能存在两份，漂移由用例把守而不是由注释把守： src/tests/utils/durationToMsParity.test.js 的期望值一律由 `jwt.sign` + `jwt.decode` 现场反推，任何一侧改口径就会红。
 *
 * 纯数字串（如 '5000'）按毫秒解释，与 jsonwebtoken 对纯数字串的处理一致（实测两侧都是 5 秒）；数值入参（typeof number）本函数按毫秒、jsonwebtoken 按秒—— 仓内没有传数值的调用方（env 读出来必是字符串），故不改动。
 *
 */
const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
// 儒略年：与 ms 的 year 取值同口径
const YEAR_MS = 365.25 * DAY_MS;

/** 长式/短式/单复数全部展开到同一基数；键集与下面正则的单位交替项一一对应 */
const DURATION_UNIT_MS = {
  ms: 1,
  msec: 1,
  msecs: 1,
  millisecond: 1,
  milliseconds: 1,
  s: 1000,
  sec: 1000,
  secs: 1000,
  second: 1000,
  seconds: 1000,
  m: MINUTE_MS,
  min: MINUTE_MS,
  mins: MINUTE_MS,
  minute: MINUTE_MS,
  minutes: MINUTE_MS,
  h: HOUR_MS,
  hr: HOUR_MS,
  hrs: HOUR_MS,
  hour: HOUR_MS,
  hours: HOUR_MS,
  d: DAY_MS,
  day: DAY_MS,
  days: DAY_MS,
  w: 7 * DAY_MS,
  week: 7 * DAY_MS,
  weeks: 7 * DAY_MS,
  y: YEAR_MS,
  yr: YEAR_MS,
  yrs: YEAR_MS,
  year: YEAR_MS,
  years: YEAR_MS,
};

const durationToMs = (expr, fallbackMs) => {
  if (typeof expr === 'number' && Number.isFinite(expr)) return expr;
  if (typeof expr !== 'string') return fallbackMs;
  // 单位可省略（省略＝毫秒，对应 ms 把纯数字串当毫秒偏移的分支）；符号位保留——
  // 否则 '-1h' 会落到 fallbackMs，把一个本该立即过期的配置值读成 7 天（放宽方向）
  const match =
    /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
      expr.trim()
    );
  if (!match) return fallbackMs;
  const value = parseFloat(match[1]);
  const unit = (match[2] || 'ms').toLowerCase();
  const unitMs = DURATION_UNIT_MS[unit];
  if (!Number.isFinite(unitMs)) return fallbackMs;
  return Math.round(value * unitMs);
};

/**
 * 是否启用 Secure 属性：按生产硬闸判据强制开启，其余环境由 COOKIE_SECURE=true 显式开启
 *
 */
const isSecureCookie = () => {
  const { requiresProductionHardening } = require('../config/validate');
  return requiresProductionHardening() || process.env.COOKIE_SECURE === 'true';
};

/** 公共 cookie 属性 */
const baseCookieOptions = () => ({
  httpOnly: true,
  sameSite: 'strict',
  secure: isSecureCookie(),
});

/**
 * 登录/注册/刷新成功后下发令牌 cookie
 *
 * refreshToken 为 null 表示本次是降级签发（设备会话注册失败，只发 access）：此时必须**清除**可能残留的旧 refresh cookie，否则浏览器里上一账号/上一次登录的 refresh 会继续被 /api/auth/refresh 接受，降级就变成了"静默复用旧会话"。
 *
 */
const setAuthCookies = (res, accessToken, refreshToken) => {
  if (!res || typeof res.cookie !== 'function') return;
  // 名字由 Secure 位判据决定（__Host- 前缀见其定义处注释）：secure 关闭时写普通名，
  // 否则浏览器会因非 HTTPS 直接丢弃带前缀 cookie。
  const secureMode = isSecureCookie();
  if (accessToken) {
    res.cookie(secureMode ? ACCESS_COOKIE_NAME_SECURED : ACCESS_COOKIE_NAME, accessToken, {
      ...baseCookieOptions(),
      path: ACCESS_COOKIE_PATH,
      maxAge: durationToMs(config.jwt.expire, 24 * 60 * 60 * 1000),
    });
  }
  if (refreshToken) {
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      ...baseCookieOptions(),
      path: REFRESH_COOKIE_PATH,
      maxAge: durationToMs(config.jwt.refreshExpire, 7 * 24 * 60 * 60 * 1000),
    });
    return;
  }
  res.clearCookie(REFRESH_COOKIE_NAME, { ...baseCookieOptions(), path: REFRESH_COOKIE_PATH });
};

/**
 * 登出时按各自 path 清除两个令牌 cookie （maxAge=0 + 相同 path 才能让浏览器真正删除对应 cookie）
 *
 * access 侧**新旧名都清**：迁移窗口内浏览器可能同时持有旧普通名（升级前签发）
 * 与新前缀名两枚 cookie，只清一枚会留下「看起来登出了、旧串仍在浏览器里」的
 * 残留（旧串虽然已被服务端吊销，但残留本身是卫生问题，也可能在换个后端实例
 * 时被回读）。清旧名必须不带前缀判据——无论当前 secure 与否都把两个名字都发一遍
 * Set-Cookie 过期指令，浏览器各删各的。
 */
const clearAuthCookies = (res) => {
  if (!res || typeof res.clearCookie !== 'function') return;
  res.clearCookie(ACCESS_COOKIE_NAME_SECURED, { ...baseCookieOptions(), path: ACCESS_COOKIE_PATH });
  res.clearCookie(ACCESS_COOKIE_NAME, { ...baseCookieOptions(), path: ACCESS_COOKIE_PATH });
  res.clearCookie(REFRESH_COOKIE_NAME, { ...baseCookieOptions(), path: REFRESH_COOKIE_PATH });
};

module.exports = {
  ACCESS_COOKIE_NAME,
  ACCESS_COOKIE_NAME_SECURED,
  REFRESH_COOKIE_NAME,
  ACCESS_COOKIE_PATH,
  REFRESH_COOKIE_PATH,
  activeAccessCookieNames,
  pickCookieValue,
  parseCookies,
  getCookies,
  durationToMs,
  isSecureCookie,
  setAuthCookies,
  clearAuthCookies,
};
