/**
 * 令牌服务（D-1 自 authController 拆出）
 *
 * JWT access/refresh 令牌的签发与轻量有效性探测。
 * 控制器只负责 HTTP 编排，令牌语义集中于此。
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const { isTokenBlacklisted } = require('../middleware/tokenBlacklist');

/**
 * 生成 JWT Token
 * @param {number} tokenVersion - 当前用户 token 版本，用于会话吊销校验
 * @param {string} jti - 令牌唯一标识（每次签发都不同）
 * @param {string} [sid] - 设备会话标识（跨 refresh 轮换保持不变，用于设备级吊销）
 */
const generateToken = (
  userId,
  username,
  email,
  roles,
  realName,
  tokenVersion = 0,
  jti = crypto.randomUUID(),
  sid = null
) => {
  return jwt.sign(
    // sid 与 jti 的分工必须清楚：
    //   jti —— 每次签发都不同，保证 refresh 轮换后旧令牌无法重用；
    //   sid —— 整个登录会话期间恒定，指向 UserSession 一条记录。
    // 设备级吊销只能绑定 sid：若绑 jti，下一次轮换就换了新 jti，
    // 「已踢除的设备」会自动复活。
    { userId, username, email, roles, realName, tokenVersion, jti, ...(sid ? { sid } : {}) },
    config.jwt.secret,
    { expiresIn: config.jwt.expire }
  );
};

/**
 * 生成刷新 Token
 * @param {number} tokenVersion - 当前用户 token 版本，用于会话吊销校验
 * @param {string} [sid] - 设备会话标识（与 access token 同值，轮换时必须原样传递）
 */
const generateRefreshToken = (userId, tokenVersion = 0, sid = null) => {
  return jwt.sign(
    // jti 保证同秒内多次签发也产生不同令牌，使 refresh 轮换真正生效（杜绝令牌重用）；
    // 否则同秒相同 payload+exp 会签出相同 refresh token，"轮换"形同未轮换
    { userId, type: 'refresh', tokenVersion, jti: crypto.randomUUID(), ...(sid ? { sid } : {}) },
    config.jwt.refreshSecret,
    { expiresIn: config.jwt.refreshExpire }
  );
};

/**
 * 判断 access token 是否仍有效（吞错，失败即 false）
 * 与 authenticate 中间件同口径的核心校验：签名 / 黑名单 / 用户状态 / tokenVersion。
 * 不校验 passwordChangedAt 与 IP 范围——探测仅做「是否已登录」的预筛，
 * 真正的安全校验仍由后续 getMe（走 authenticate）兜底。
 */
const isAccessTokenValid = async (token) => {
  try {
    const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });
    if (await isTokenBlacklisted(token)) return false;
    const user = await User.findById(decoded.userId).select('status tokenVersion').lean();
    if (!user || user.status !== 'active') return false;
    return decoded.tokenVersion === (user.tokenVersion ?? 0);
  } catch (_) {
    return false;
  }
};

/**
 * 判断 refresh token 是否仍有效（吞错，失败即 false）
 * 与 refreshToken 控制器同口径：refreshSecret 签名 / type / 黑名单 / 用户状态 / tokenVersion。
 */
const isRefreshTokenValid = async (token) => {
  try {
    const decoded = jwt.verify(token, config.jwt.refreshSecret, { algorithms: ['HS256'] });
    if (decoded.type !== 'refresh') return false;
    if (await isTokenBlacklisted(token)) return false;
    const user = await User.findById(decoded.userId).select('status tokenVersion').lean();
    if (!user || user.status !== 'active') return false;
    return decoded.tokenVersion === (user.tokenVersion ?? 0);
  } catch (_) {
    return false;
  }
};

module.exports = {
  generateToken,
  generateRefreshToken,
  isAccessTokenValid,
  isRefreshTokenValid,
};
