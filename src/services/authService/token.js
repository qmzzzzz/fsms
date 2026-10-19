/**
 * 刷新令牌轮换与登出吊销
 *
 * 自 authService.js 拆出。两者共用「把某个 refresh token 变成已吊销状态」这一
 * 底层能力（revokeOneRefreshToken），放在一起是为了让「轮换失败时的吊销」与
 * 「登出时的吊销」永远走同一段代码，而不是两处各调一次 API 却各自演化。
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../../models/User');
const config = require('../../config');
const logger = require('../../utils/logger');
const { isIPAllowed } = require('../../utils/ipRange');
const {
  blacklistToken,
  consumeToken,
  invalidateUserTokens,
} = require('../../middleware/tokenBlacklist');
const sessionService = require('../sessionService');
const { generateToken, generateRefreshToken } = require('../tokenService');

/**
 * 轮换主体的三项廉价判据：IP 范围 → 改密时间 → tokenVersion（外加取回 roles）。
 *
 * 顺序不是随意的：从"最便宜且最可能命中"排到"要额外一次 populate"。三条都必须与
 * authenticate 中间件同口径，否则会出现「HTTP 拒了、refresh 还认」的第二扇门。
 *
 * @param {object} user 已按 decoded.userId 查回的文档
 * @param {object} decoded 已验证的 refresh 载荷
 * @param {{ip: string}} ctx
 * @returns {Promise<{ok: true, roles: string[]}|{ok: false, outcome: string}>}
 */
async function resolveRefreshSubject(user, decoded, ctx) {
  // 修复：刷新令牌轮换时补齐 IP 访问范围校验（与登录口径一致），
  // 防止 refresh token 被窃取后从任意 IP 完成轮换导致合法用户被踢出（会话 DoS）
  if (user.allowedIPs) {
    const { allowed } = isIPAllowed(ctx.ip, user.allowedIPs);
    if (!allowed) {
      logger.warn('Refresh 拒绝 - IP 不在允许范围', { username: user.username, ip: ctx.ip });
      return { ok: false, outcome: 'IP_DENIED' };
    }
  }

  // 检查密码是否已修改（签发时间早于密码修改时间则拒绝）
  // 秒级比较（与 authenticate 中间件同口径）：iat 为秒、passwordChangedAt 为毫秒，
  // 直接毫秒比较会把「改密后同一秒内签发」的令牌误判为失效
  if (user.passwordChangedAt && decoded.iat) {
    const passwordChangedSec = Math.floor(user.passwordChangedAt.getTime() / 1000);
    if (passwordChangedSec > decoded.iat) {
      return { ok: false, outcome: 'PASSWORD_CHANGED' };
    }
  }

  const populatedUser = await User.findById(user._id).populate({
    path: 'roles',
    select: 'name code',
    match: { status: 'active' },
  });
  // 安全修复：populate 后可能存在 null（指向已删除角色的 ObjectId），需过滤
  const roles = populatedUser.roles.map((r) => r?.code).filter(Boolean);

  // 校验 tokenVersion：缺失（早期签发的旧 token）或不匹配（该用户已被吊销全部会话）
  // 一律拒绝，与 authenticate 中间件口径保持一致（历史文档缺字段时按 0 参与比对）
  const expectedTokenVersion = user.tokenVersion ?? 0;
  if (decoded.tokenVersion === undefined || decoded.tokenVersion !== expectedTokenVersion) {
    return { ok: false, outcome: 'VERSION_MISMATCH' };
  }
  return { ok: true, roles };
}

/**
 * 重放检测命中后的处置：吊销该用户全部会话。
 *
 * fail-closed：吊销失败时不能按 REPLAYED「已处置」返回——攻击者会话仍然在线，
 * 上抛 REVOKE_UNAVAILABLE 由控制器回 503，让客户端重试并触发告警，而不是静默放行。
 *
 * @param {object} decoded 已验证的 refresh 载荷
 * @returns {Promise<{ok: false, outcome: string}>}
 */
async function revokeOnRefreshReplay(decoded) {
  try {
    await invalidateUserTokens(decoded.userId);
  } catch (revokeErr) {
    logger.error(`重放检测触发但会话吊销失败：${revokeErr.message}`, {
      userId: decoded.userId,
    });
    return { ok: false, outcome: 'REVOKE_UNAVAILABLE' };
  }
  // 会话表须与 tokenVersion 保持一致：否则「登录会话」界面会留下一批
  // 显示 active 但实际已不能用的僵尸记录，用户看到的信息与事实不符
  await sessionService.revokeAllSessionsSafe(decoded.userId, 'token_reuse');
  logger.warn('Refresh token 重放检测触发，吊销用户全部会话', { userId: decoded.userId });
  return { ok: false, outcome: 'REPLAYED' };
}

/**
 * 原子消费旧 refresh token（一次性使用）；已被消费 ⇒ 进入重放检测。
 *
 * 把「查黑名单→加黑名单」合并为一次原子抢占：并发的两次 /refresh 只有一次能换取新令牌对，
 * 另一次进入重放检测，消除原「检查与轮换非原子」的 TOCTOU 平行会话窗口。
 *
 * @param {string} refreshTokenRaw
 * @param {object} decoded 已验证的 refresh 载荷
 * @returns {Promise<{ok: true}|{ok: false, outcome: string}>}
 */
async function claimRefreshToken(refreshTokenRaw, decoded) {
  let claimed = false;
  try {
    claimed = await consumeToken(refreshTokenRaw, decoded.exp);
  } catch (consumeErr) {
    logger.error(`Refresh 轮换中止 - 黑名单服务故障：${consumeErr.message}`);
    return { ok: false, outcome: 'BLACKLIST_UNAVAILABLE' };
  }
  if (claimed) return { ok: true };
  return revokeOnRefreshReplay(decoded);
}

/**
 * 设备级会话校验：轮换必须继承原 sid，且该会话仍须可用。
 *
 * 这是「踢除设备后不能复活」的关键一环 —— 若此处不校验，被踢设备手里的
 * refresh token 依然有效，一次刷新就能换到不带 sid（或带新 sid）的令牌，
 * 绕过整个设备级吊销机制。
 *
 * @param {string|null} rotateSid
 * @returns {Promise<string|null>} 拒绝时返回 outcome，放行返回 null
 */
async function resolveRotationSession(rotateSid) {
  if (!rotateSid) return null;
  let sessionState;
  try {
    sessionState = await sessionService.validateSession(rotateSid);
  } catch (sessErr) {
    logger.error(`Refresh 轮换中止 - 会话服务故障：${sessErr.message}`);
    return 'SESSION_UNAVAILABLE';
  }
  if (!sessionState.usable) {
    logger.warn(`Refresh 拒绝 - 会话已被吊销：sid=${String(rotateSid).slice(0, 8)}…`);
    return 'SESSION_REVOKED';
  }
  return null;
}

/**
 * 刷新令牌轮换（业务层）
 * @returns {Promise<{outcome:'MISSING'|'INVALID'|'IP_DENIED'|'PASSWORD_CHANGED'|'VERSION_MISMATCH'|'BLACKLIST_UNAVAILABLE'|'REPLAYED'|'REVOKE_UNAVAILABLE'|'SESSION_UNAVAILABLE'|'SESSION_REVOKED'|'EXPIRED'|'OK'}>}
 *   OK 时附 { token, refreshToken }
 */
async function refreshSession(refreshTokenRaw, ctx) {
  if (!refreshTokenRaw) {
    return { outcome: 'MISSING' };
  }

  // 验签与用途闸留在本函数体内，**不抽成 decodeRefreshToken**：credentialDoorCheckLedger
  // 按「函数体内有没有 jwt.verify(」实测每扇门的形状，抽走之后 refreshSession 在台账里
  // 会变成"不验签的门"，那条双向登记会红（且红得对——它守的正是"这扇门自己验不验"）。
  let decoded;
  try {
    decoded = jwt.verify(refreshTokenRaw, config.jwt.refreshSecret, { algorithms: ['HS256'] });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return { outcome: 'EXPIRED' };
    }
    return { outcome: 'INVALID' };
  }

  if (decoded.type !== 'refresh') {
    return { outcome: 'INVALID' };
  }

  // 先做廉价校验（用户状态/IP 范围/密码修改时间/tokenVersion），
  // 最后一步才做原子消费——顺序反了会在重放检测之前就花掉一次黑名单写入
  const user = await User.findById(decoded.userId);
  if (!user || user.status !== 'active') {
    return { outcome: 'INVALID' };
  }

  const subject = await resolveRefreshSubject(user, decoded, ctx);
  if (!subject.ok) {
    return { outcome: subject.outcome };
  }

  const claim = await claimRefreshToken(refreshTokenRaw, decoded);
  if (!claim.ok) {
    return { outcome: claim.outcome };
  }

  const rotateSid = decoded.sid || null;
  const sessionRejection = await resolveRotationSession(rotateSid);
  if (sessionRejection) {
    return { outcome: sessionRejection };
  }

  // 签发新的 access token + refresh token（携带当前 tokenVersion 与原 sid）
  const token = generateToken(
    user._id,
    user.username,
    user.email,
    subject.roles,
    user.realName,
    user.tokenVersion,
    crypto.randomUUID(),
    rotateSid
  );
  const refreshToken = generateRefreshToken(user._id, user.tokenVersion, rotateSid);

  return { outcome: 'OK', token, refreshToken };
}
/**
 * 吊销单个 refresh 令牌。
 * @returns {Promise<{handled:boolean, failed:boolean}>}
 *   handled=false 表示签名无效/已过期（本就不可用，不算失败，也不写黑名单）
 */
/**
 * 判别一枚 refresh 串是否**不属于**当前操作者。
 *
 * 无法判别时按"不属于"处理（fail-closed）：载荷里没有 userId、或压根拿不到操作者
 * 身份，都不能证明"这串是我的"。反过来，签名无效/已过期的串**不算**外来——
 * 它本就不可用，与 revokeOneRefreshToken 的口径一致（否则一次携带过期串的登出会被拒）。
 *
 * @param {string} token 原始 refresh 串
 * @param {string} ownerUserId 当前操作者 userId（authenticate 保证存在）
 * @returns {boolean} true=这串不属于当前操作者
 */
function isForeignRefreshToken(token, ownerUserId) {
  let payload = null;
  try {
    payload = jwt.verify(token, config.jwt.refreshSecret, { algorithms: ['HS256'] });
  } catch (e) {
    return false;
  }
  if (!payload || !payload.exp) return false;
  if (!ownerUserId) return true;
  return String(payload.userId) !== String(ownerUserId);
}

async function revokeOneRefreshToken(token) {
  let payload = null;
  try {
    payload = jwt.verify(token, config.jwt.refreshSecret, { algorithms: ['HS256'] });
  } catch (e) {
    // refresh token 校验失败说明它本就无效，不影响登出结论
    logger.warn(`登出时 refresh token 校验失败: ${e.message}`);
    return { handled: false, failed: false };
  }
  if (!payload || !payload.exp) return { handled: false, failed: false };
  try {
    await blacklistToken(token, payload.exp);
  } catch (e) {
    logger.error(`登出未能吊销 refresh token（${e.code || e.message}）：令牌在过期前仍然可用`);
    return { handled: true, failed: true };
  }
  return { handled: true, failed: false };
}

/**
 * 登出令牌吊销（业务层）：把 access/refresh 令牌加入黑名单
 * @param {object} input
 * @param {string|null} input.accessToken 认证用的 access 令牌（与 authenticate 同源提取）
 * @param {string|null} [input.refreshToken] 主 refresh 令牌
 * @param {string[]} [input.extraRefreshTokens] 其余**同时被出示**的 refresh 令牌
 *   （控制器把 body 与 cookie 两个来源都交进来：旧签名只能收一个，于是
 *   `body || cookie` 这种"二选一"让一条已轮换掉的旧串把在用的那条挡在身后）
 * @returns {Promise<{revokeFailed:boolean}>} revokeFailed=true 表示有令牌未能确认入库
 *
 * P2-26 fail-closed：令牌吊销未能落库时由控制器返回失败而非「登出成功」。
 * 原实现把 blacklistToken 的异常吞进 logger.warn 照常返回成功，于是
 * DB 瞬断期间「登出」只是清了 cookie —— 被窃取的 access token 在其剩余
 * 有效期（默认 2h）内仍可通过认证，而用户已认为会话已终止、不会再补救。
 * refresh 轮换路径（consumeToken）刻意 fail-closed，契约必须一致。
 */
async function revokeTokensOnLogout({
  accessToken,
  refreshToken,
  extraRefreshTokens = [],
  userId,
} = {}) {
  // 属主预检（F-100 的另一半）：任何一枚被出示的 refresh 串若不是当前操作者的，
  // 整次登出失败，且**不做任何吊销**——见 errorCodes.LOGOUT_REFRESH_FOREIGN 的注释。
  // 旧实现不判属主：拿到他人 refresh 串即可代为吊销（会话 DoS），接口还回 200。
  // 预检必须走在任何 blacklistToken 之前：部分成功会让"登出"处于说不清的状态。
  const refreshCandidates = [...new Set([refreshToken, ...extraRefreshTokens].filter(Boolean))];
  if (refreshCandidates.some((t) => isForeignRefreshToken(t, userId))) {
    return { revokeFailed: false, foreignRefresh: true };
  }

  // 吊销失败标记：任一令牌未能确认入库即视为登出未完成
  let revokeFailed = false;

  if (accessToken) {
    // 使用 verify 校验签名，防止伪造 token 污染黑名单
    let payload = null;
    try {
      payload = jwt.verify(accessToken, config.jwt.secret, { algorithms: ['HS256'] });
    } catch (e) {
      // 签名无效/已过期的令牌本就不可用，无需吊销，不算失败
      logger.warn(`登出时 access token 校验失败: ${e.message}`);
    }
    if (payload && payload.exp) {
      try {
        await blacklistToken(accessToken, payload.exp);
      } catch (e) {
        revokeFailed = true;
        logger.error(`登出未能吊销 access token（${e.code || e.message}）：令牌在过期前仍然可用`);
      }
    }
  }

  // 去重：body 与 cookie 常是同一条令牌（同值重复吊销只是多写一次同键黑名单）
  for (const token of refreshCandidates) {
    const { failed } = await revokeOneRefreshToken(token);
    if (failed) revokeFailed = true;
  }

  return { revokeFailed };
}

module.exports = {
  refreshSession,
  revokeTokensOnLogout,
};
