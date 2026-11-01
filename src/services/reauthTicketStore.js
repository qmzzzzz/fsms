/**
 * 二次验证票据的一次性消费：同一 jti 只能成功 create 一次（唯一索引是并发判据）。
 * 方向：判据载体建立/读取失败一律 fail-closed；原委见 tests/security/reauthTicketOneTimeUse.test.js。
 */

const ReauthTicketUse = require('../models/ReauthTicketUse');

/**
 * 判据载体必须先真的存在：mongoose autoIndex 后台建索引，失败只打日志而插入照常成功 ⇒ 判据静默失效（tokenblacklists.token_1 同形教训）。故首次使用前显式 createIndexes()（幂等、结果缓存），失败即抛。
 */
let indexReady = null;
const ensureUniqueJtiIndex = () => {
  if (!indexReady) {
    indexReady = ReauthTicketUse.createIndexes().catch((err) => {
      indexReady = null; // 下次重试：一次失败不应让本进程永久放弃该判据
      throw new Error(`二次验证票据判据不可用（jti 唯一索引建立失败）：${err.message}`);
    });
  }
  return indexReady;
};

/** 消费一张票据的 jti：true = 首次使用；false = 已被消费（重放）。 */
async function consumeReauthTicketJti({ jti, userId, expiresAt }) {
  await ensureUniqueJtiIndex();
  try {
    await ReauthTicketUse.create({ jti, userId, expiresAt });
    return true;
  } catch (err) {
    if (err && err.code === 11000) return false; // 11000 = 已消费（正常拒绝路径，非异常）；日志噪音留给调用方区分重放与故障
    throw err;
  }
}

module.exports = { consumeReauthTicketJti };
