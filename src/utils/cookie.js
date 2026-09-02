/**
 * Cookie 工具 —— httpOnly 令牌 Cookie 契约的唯一实现位置
 *
 * 契约（I-01）：
 * - access_token ：值=accessToken ，path=/api       ，maxAge 与 JWT_EXPIRE 一致
 * - refresh_token：值=refreshToken，path=/api/auth  ，maxAge 与 JWT_REFRESH_EXPIRE 一致
 * - 属性：httpOnly: true、sameSite: 'strict'（P3-36 严格化，原 lax）
 * - secure：生产环境（NODE_ENV=production）或 COOKIE_SECURE=true 时开启
 *
 * P3-36：本注释此前把 access cookie 的时长写死为 24 小时，而 config/index.js
 * 的 JWT_EXPIRE 默认值是 '2h'。注释里的具体时长必然随配置漂移，
 * 故只声明「与配置一致」这一不变量，实际取值以
 * config.jwt.expire / config.jwt.refreshExpire 为唯一事实来源。
 *
 * 项目未引入 cookie-parser 依赖，此处提供轻量的手动解析实现。
 */

const config = require('../config');

const ACCESS_COOKIE_NAME = 'access_token';
const REFRESH_COOKIE_NAME = 'refresh_token';
const ACCESS_COOKIE_PATH = '/api';
const REFRESH_COOKIE_PATH = '/api/auth';

/**
 * 解析 Cookie 请求头为键值对象
 * 兼容多值、URL 编码值与空/非法输入（解析失败返回空对象，不抛错）
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
 * 将 JWT 过期表达式（与 jsonwebtoken/ms 语法兼容的子集）转换为毫秒
 * 支持：'30s' / '15m' / '24h' / '7d' / '2w' / '1y' / 纯数字（毫秒）
 * @param {string|number} expr
 * @param {number} fallbackMs - 无法解析时的回退值
 * @returns {number}
 */
const durationToMs = (expr, fallbackMs) => {
  if (typeof expr === 'number' && Number.isFinite(expr)) return expr;
  if (typeof expr !== 'string') return fallbackMs;
  const match = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w|y)?$/i.exec(expr.trim());
  if (!match) return fallbackMs;
  const value = parseFloat(match[1]);
  const unit = (match[2] || 'ms').toLowerCase();
  const unitMs = {
    ms: 1,
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
    w: 7 * 24 * 60 * 60 * 1000,
    y: 365 * 24 * 60 * 60 * 1000,
  };
  return Math.round(value * unitMs[unit]);
};

/**
 * 是否启用 Secure 属性：生产环境强制开启，其余环境由 COOKIE_SECURE=true 显式开启
 * （读 config 现有模式：config.nodeEnv 即 NODE_ENV || 'development'）
 */
const isSecureCookie = () =>
  config.nodeEnv === 'production' || process.env.COOKIE_SECURE === 'true';

/** 公共 cookie 属性 */
const baseCookieOptions = () => ({
  httpOnly: true,
  sameSite: 'strict',
  secure: isSecureCookie(),
});

/**
 * 登录/注册/刷新成功后下发两个令牌 cookie
 * @param {import('express').Response} res
 * @param {string} accessToken
 * @param {string} refreshToken
 */
const setAuthCookies = (res, accessToken, refreshToken) => {
  if (!res || typeof res.cookie !== 'function') return;
  res.cookie(ACCESS_COOKIE_NAME, accessToken, {
    ...baseCookieOptions(),
    path: ACCESS_COOKIE_PATH,
    maxAge: durationToMs(config.jwt.expire, 24 * 60 * 60 * 1000),
  });
  res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
    ...baseCookieOptions(),
    path: REFRESH_COOKIE_PATH,
    maxAge: durationToMs(config.jwt.refreshExpire, 7 * 24 * 60 * 60 * 1000),
  });
};

/**
 * 登出时按各自 path 清除两个令牌 cookie
 * （maxAge=0 + 相同 path 才能让浏览器真正删除对应 cookie）
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
