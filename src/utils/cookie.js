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
 * 本注释此前把 access cookie 的时长写死为 24 小时，而 config/index.js 的 JWT_EXPIRE 默认值是 '2h'。注释里的具体时长必然随配置漂移，故只声明「与配置一致」这一不变量，实际取值以 config.jwt.expire / config.jwt.refreshExpire 为唯一事实来源。
 *
 * 项目未引入 cookie-parser 依赖，此处提供轻量的手动解析实现。
 */

const config = require('../config');

const ACCESS_COOKIE_NAME = 'access_token';
const REFRESH_COOKIE_NAME = 'refresh_token';
const ACCESS_COOKIE_PATH = '/';
const REFRESH_COOKIE_PATH = '/api/auth';

/**
 * 解析 Cookie 请求头为键值对象兼容多值、URL 编码值与空/非法输入（解析失败返回空对象，不抛错）
 * @param {string|undefined} cookieHeader - req.headers.cookie
 * @returns {Object<string,string>}
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
 * @param {import('express').Request} req
 * @returns {Object<string,string>}
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
 * `'1y'` 更隐蔽：`ms` 用儒略年（365.25 天），原先写 365 会让两侧每年差 6 小时。
 *
 * 不能在这里 `require('ms')`——它是 jsonwebtoken 的传递依赖，不在本仓 package.json 里。语法表因此只能存在两份，漂移由用例把守而不是由注释把守： src/tests/utils/durationToMsParity.test.js 的期望值一律由 `jwt.sign` + `jwt.decode` 现场反推，任何一侧改口径就会红。
 *
 * 纯数字串（如 '5000'）按毫秒解释，与 jsonwebtoken 对纯数字串的处理一致（实测两侧都是 5 秒）；数值入参（typeof number）本函数按毫秒、jsonwebtoken 按秒—— 仓内没有传数值的调用方（env 读出来必是字符串），故不改动。
 *
 * @param {string|number} expr
 * @param {number} fallbackMs - 无法解析时的回退值
 * @returns {number}
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
 * 原实现 `config.nodeEnv === 'production'` 是字面量比较：NODE_ENV=prod 或 staging 的部署里生产校验与 Secure 位各按一把尺，会话 cookie 的 Secure 会静默关闭——登录会话可在明文 HTTP 上被截取。故统一改用 validate.js 导出的同一判据（惰性 require，避开 utils→config→validate 的加载期环路，与仓内 userPermissionService / auditChain 等处的惰性 require 口径一致）。
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
 * @param {import('express').Response} res
 * @param {string} accessToken
 * @param {string|null} refreshToken
 */
const setAuthCookies = (res, accessToken, refreshToken) => {
  if (!res || typeof res.cookie !== 'function') return;
  if (accessToken) {
    res.cookie(ACCESS_COOKIE_NAME, accessToken, {
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
 * @param {import('express').Response} res
 */
const clearAuthCookies = (res) => {
  if (!res || typeof res.clearCookie !== 'function') return;
  res.clearCookie(ACCESS_COOKIE_NAME, { ...baseCookieOptions(), path: ACCESS_COOKIE_PATH });
  res.clearCookie(REFRESH_COOKIE_NAME, { ...baseCookieOptions(), path: REFRESH_COOKIE_PATH });
};

module.exports = {
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  ACCESS_COOKIE_PATH,
  REFRESH_COOKIE_PATH,
  parseCookies,
  getCookies,
  durationToMs,
  isSecureCookie,
  setAuthCookies,
  clearAuthCookies,
};
