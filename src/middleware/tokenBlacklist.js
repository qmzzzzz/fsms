/**
 * Token 黑名单中间件
 * 支持令牌注销、登出后失效等功能
 * 使用 MongoDB 持久化存储，进程重启后不丢失
 */

const crypto = require('crypto');
const logger = require('../utils/logger');
const TokenBlacklistModel = require('../models/TokenBlacklist');

// 使用 SHA-256 哈希存储 token，防止数据库泄露后 token 被直接复用
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

/**
 * 将令牌加入黑名单（持久化到 MongoDB，存储哈希而非明文）
 *
 * fail-closed（P2-26）：写入失败必须向上抛错。原实现只记日志便返回，
 * 于是「登出成功」与「令牌已吊销」脱钩——DB 瞬断期间被窃取的 access token
 * 在其剩余有效期（默认 2h）内持续可用，而用户已看到登出成功、不会再采取补救。
 * 同文件的 consumeToken 对同类失败刻意 fail-closed，两者契约必须一致。
 *
 * @param {string} token - JWT Token
 * @param {number} exp - 令牌过期时间（秒级时间戳）
 * @throws {Error} code=BLACKLIST_PERSIST_FAILED 写入未确认
 */
const blacklistToken = async (token, exp) => {
  const expiryMs = exp * 1000;
  // 已过期的令牌无需入库：它本身已不可用，写入只会徒增集合体积
  if (expiryMs <= Date.now()) return;

  try {
    const tokenHash = hashToken(token);
    await TokenBlacklistModel.findOneAndUpdate(
      { tokenHash },
      { tokenHash, expiresAt: new Date(expiryMs), createdAt: new Date() },
      { upsert: true, new: true }
    );
    logger.info(`Token 已加入黑名单`, { tokenHash: tokenHash.slice(0, 16) + '...' });
  } catch (err) {
    if (err.code === 11000) {
      const conflictedKey = Object.keys(err.keyPattern || {})[0];
      if (conflictedKey === 'tokenHash') {
        // 令牌已在黑名单中：吊销目标已达成，属幂等成功
        logger.debug('Token 已在黑名单中（重复写入忽略）');
        return;
      }
      // 非 tokenHash 冲突意味着令牌**没有**被加入黑名单，登出形同虚设
      logger.error(
        `Token 黑名单写入遭遇非预期唯一键冲突（key=${JSON.stringify(err.keyPattern)}）：` +
          '本次登出未能吊销令牌，请执行 scripts/fix-token-blacklist-index.js 清理遗留索引'
      );
      const infraErr = new Error('Token blacklist index misconfigured');
      infraErr.code = 'BLACKLIST_INDEX_CONFLICT';
      throw infraErr;
    }
    logger.error(`Token 黑名单持久化失败：${err.message}`);
    const persistErr = new Error('Token blacklist persist failed');
    persistErr.code = 'BLACKLIST_PERSIST_FAILED';
    persistErr.cause = err;
    throw persistErr;
  }
};

/**
 * 检查令牌是否在黑名单中（比对哈希值）
 * @param {string} token - JWT Token
 * @returns {boolean} 是否在黑名单中
 */
const isTokenBlacklisted = async (token) => {
  try {
    const tokenHash = hashToken(token);
    const entry = await TokenBlacklistModel.findOne({ tokenHash }).lean();
    return !!entry;
  } catch (err) {
    logger.error(`Token 黑名单查询失败：${err.message}`);
    // fail-closed：数据库故障时拒绝而非放行，向上传播错误由 auth 中间件返回 503
    const serviceErr = new Error('Token blacklist service unavailable');
    serviceErr.code = 'BLACKLIST_SERVICE_UNAVAILABLE';
    throw serviceErr;
  }
};

/**
 * 原子消费一次性令牌（refresh 轮换专用）：
 * 以 tokenHash 唯一索引为锁，插入成功即获得所有权（返回 true）；
 * 命中 tokenHash 唯一键冲突说明令牌已被先前/并发请求消费（返回 false，
 * 调用方走重放检测）。
 *
 * 将「查黑名单 → 再加黑名单」两步合并为一步原子抢占，消除轮换 TOCTOU：
 * 并发的两次 /refresh 只有一次能换取新令牌对，另一次必然进入重放处理。
 *
 * fail-closed：持久化失败时向上抛错，调用方拒绝轮换——宁可让用户重新登录，
 * 也不允许旧 refresh token 在黑名单未落库的情况下继续可用。
 *
 * 重要：E11000 必须按 keyPattern 区分来源，不能一律当作重放。
 * 历史遗留的 `token_1` 唯一索引（旧 schema 存明文 token）会让所有新文档
 * 的 token 字段同为 null，第二条起插入即 E11000——若把它误判为重放，
 * 每次 refresh 都会触发 invalidateUserTokens 递增 tokenVersion，
 * 用户会话被永久吊销（实测已发生）。此类冲突属基础设施故障，须抛错而非降级。
 *
 * @param {string} token - JWT refresh token
 * @param {number} exp - 令牌过期时间（秒级时间戳）
 * @returns {boolean} true=本次消费成功；false=令牌已被消费过（真实重放）
 */
const consumeToken = async (token, exp) => {
  const tokenHash = hashToken(token);
  const expiryMs = exp * 1000;
  try {
    await TokenBlacklistModel.create({
      tokenHash,
      expiresAt: new Date(expiryMs),
      reason: 'rotate',
      createdAt: new Date(),
    });
    logger.info(`Refresh token 已原子消费并加入黑名单`, {
      tokenHash: tokenHash.slice(0, 16) + '...',
    });
    return true;
  } catch (err) {
    if (err.code === 11000) {
      const conflictedKey = Object.keys(err.keyPattern || {})[0];
      if (conflictedKey === 'tokenHash') {
        // 真实重放：同一 refresh token 被二次使用
        return false;
      }
      // 非 tokenHash 冲突（如遗留 token_1 索引的 null 键）：基础设施异常，
      // 不能当作重放——否则会误吊销合法用户的全部会话
      logger.error(
        `Refresh token 消费遭遇非预期唯一键冲突（index=${err.index ?? '未知'} ` +
          `key=${JSON.stringify(err.keyPattern)}）。` +
          'tokenblacklists 可能残留旧 schema 索引，请执行 scripts/fix-token-blacklist-index.js'
      );
      const infraErr = new Error('Token blacklist index misconfigured');
      infraErr.code = 'BLACKLIST_INDEX_CONFLICT';
      throw infraErr;
    }
    logger.error(`Refresh token 原子消费失败：${err.message}`);
    throw err;
  }
};

/**
 * 强制失效某个用户的所有令牌
 * (用于管理员禁用用户、修改密码、refresh token 重放检测等场景)
 * 实现方式：
 *   1. 递增 tokenVersion —— 所有已签发 token 的版本号不再匹配，彻底失效
 *      这比仅靠 passwordChangedAt 更强：能杜绝 refresh token 重放后轮换出的新 token
 *   2. 同时更新 passwordChangedAt 作为冗余校验
 *
 * 契约（fail-closed）：DB 写入失败时记录告警并**向上抛错**。
 * 此前吞错会让「全量吊销」静默失败——禁用/改密/重放检测的调用方
 * 误以为既有令牌已作废，攻击者的旧令牌却仍然可用。调用方不得
 * 吞掉本函数的异常，应让请求以失败告终而非带病放行。
 */
const invalidateUserTokens = async (userId) => {
  try {
    const User = require('../models/User');
    await User.findByIdAndUpdate(userId, {
      $inc: { tokenVersion: 1 },
      passwordChangedAt: new Date(),
    });
  } catch (err) {
    logger.error(`失效用户令牌失败（fail-closed 上抛）：${err.message}`, { userId });
    throw err;
  }
  // 缓存清除失败不影响吊销结果（最长 60s 自然过期），不纳入上方事务性失败
  const { invalidateUserCache } = require('./auth');
  invalidateUserCache(userId);
  logger.info('用户所有令牌已失效（tokenVersion 递增）', { userId });
};

module.exports = {
  blacklistToken,
  isTokenBlacklisted,
  consumeToken,
  invalidateUserTokens,
};
