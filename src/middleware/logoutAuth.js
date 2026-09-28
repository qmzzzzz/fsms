/**
 * 登出入口的认证：access 令牌过期时仍允许用 refresh 令牌证明会话归属。
 *
 * 为什么单列一个文件：middleware/auth.js 已经越过体积门禁（max-lines 300），
 * 而这段逻辑除 `authenticate`/`extractAccessToken` 外不依赖认证主链的任何内部件，
 * 天然可独立成模块——棘轮因此是靠"搬家"满足的，不是靠放宽阈值。
 *
 * 为什么登出不能直接用 authenticate：登出是 refresh 令牌与设备会话的**唯一**吊销入口，
 * 而 access 短、refresh 长（7 天）是设计本意。挂 authenticate 时，
 * "access 已过期"这一常态直接 401，处理体根本不执行 ⇒
 * 手里那个仍然有效的 refresh 令牌再也关不掉，服务端会话记录一直挂在 active。
 * 浏览器端靠拦截器"先刷新再登出"侥幸规避；API 客户端、脚本、以及
 * 令牌泄露后的正确收尾动作都不会这么做。
 *
 * 身份依据换成 refresh 令牌是充分的：独立密钥签名、带 type/sid、且必须未被吊销
 * （黑名单命中即拒）。持有它代表"有权关掉这个会话"，也仅仅只有这个权力——
 * 这里构造的 req.user 不含 roles/权限，只在登出处理体内被读 sid/userId。
 *
 * 顺序与失败语义：
 *  1. access 存在且验签通过 → 走完整 authenticate（黑名单/账户/会话/IP 一项不少）；
 *  2. access 存在但**非过期类**错误 → 交回 authenticate 做统一错误映射（不在此降级）；
 *  3. access 过期 或 根本没有 access → 尝试 refresh；成功则构造登出身份；
 *  4. 两条路都不成立 → 401，绝不"匿名放行"（否则登出会变成任意人可触发的接口）。
 *
 * 刻意不再套 userLimiter：该限流器按 req.user 的角色定配额，这里构造的是最小登出身份
 * （roles 为空），硬套会让配额判定读到 undefined。全局 generalLimiter 仍在路径上。
 */

const jwt = require('jsonwebtoken');
const config = require('../config');
const ApiResponse = require('../utils/apiResponse');
const { getCookies, REFRESH_COOKIE_NAME } = require('../utils/cookie');
const { isTokenBlacklisted } = require('./tokenBlacklist');
const { authenticate, extractAccessToken, mapAuthFailure } = require('./auth');

/**
 * 登出用的第二条身份通路：一个"活的" refresh 令牌。
 * @param {boolean} accessTokenExpired 是否因 access 过期才落到这条路（决定错误码）
 * @returns {Promise<boolean>} true 表示已构造 req.user，可以放行
 */
const authorizeByRefreshToken = async (req, res, accessTokenExpired) => {
  const fromBody = typeof req.body?.refreshToken === 'string' ? req.body.refreshToken : null;
  const refreshToken = fromBody || getCookies(req)[REFRESH_COOKIE_NAME] || null;
  if (!refreshToken) {
    ApiResponse.codeError(res, accessTokenExpired ? 'AUTH_TOKEN_EXPIRED' : 'AUTH_TOKEN_MISSING');
    return false;
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, config.jwt.refreshSecret, { algorithms: ['HS256'] });
  } catch (_) {
    // 验不过签/已过期都只说明"证明不了会话归属"。不细分错误码：
    // 在这里区分 refresh 与 access 的失效原因会给探测者多一条免费信息
    ApiResponse.codeError(res, 'AUTH_TOKEN_INVALID');
    return false;
  }
  if (decoded.type !== 'refresh') {
    ApiResponse.codeError(res, 'AUTH_TOKEN_INVALID');
    return false;
  }
  let blacklisted;
  try {
    blacklisted = await isTokenBlacklisted(refreshToken);
  } catch (err) {
    // isTokenBlacklisted 对数据库故障刻意 fail-closed 上抛（不返回"没查到"）。
    // 这里必须接住并交回 auth.js 的唯一映射表：同一个"安全服务不可用"走 access
    // 得 503、走 refresh 得 500，等于让登出入口的故障口径取决于客户端挑哪条路。
    mapAuthFailure(err, res);
    return false;
  }
  if (blacklisted) {
    ApiResponse.codeError(res, 'AUTH_TOKEN_REVOKED');
    return false;
  }

  req.user = {
    userId: String(decoded.userId),
    username: decoded.username || null,
    roles: [],
    roleCodes: [],
    sid: decoded.sid || null,
    authViaRefreshToken: true,
  };
  return true;
};

const authenticateForLogout = async (req, res, next) => {
  const accessToken = extractAccessToken(req);
  if (accessToken) {
    try {
      jwt.verify(accessToken, config.jwt.secret, { algorithms: ['HS256'] });
    } catch (err) {
      if (err && err.name === 'TokenExpiredError') {
        if (await authorizeByRefreshToken(req, res, true)) return next();
        return undefined;
      }
      // 非过期类错误一律交回主链，由它按统一口径判 401
    }
    return authenticate(req, res, next);
  }
  if (await authorizeByRefreshToken(req, res, false)) return next();
  return undefined;
};

module.exports = { authenticateForLogout, authorizeByRefreshToken };
