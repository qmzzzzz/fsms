/**
 * 管理员重置口令时生成的一次性临时口令（P1-2）：策略要求 12 位以上且含大写/小写/数字/特殊字符四类
 * （utils/helpers.validatePasswordStrength）。base64 直出常缺一类、会产出"自己都过不了策略"的口令——故四类各抽
 * 一个再补足长度并 Fisher–Yates 洗牌；随机源只用 crypto.randomInt（CSPRNG），不用 Math.random。
 */

const crypto = require('crypto');

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // 去掉 I/O 减少抄写歧义
const LOWER = 'abcdefghijkmnopqrstuvwxyz'; // 去掉 l
const DIGITS = '23456789'; // 去掉 0/1
const SYMBOLS = '!@#$%^&*-_=+';
const ALL = UPPER + LOWER + DIGITS + SYMBOLS;
const DEFAULT_LENGTH = 16;

/** 从字符集随机取一个字符 */
const pick = (chars) => chars[crypto.randomInt(0, chars.length)];

/** 生成满足企业口令策略的临时口令；length 目标长度（非整数或小于 12 按 12 处理）。@returns {string} */
function generateTemporaryPassword(length = DEFAULT_LENGTH) {
  const size = Math.max(12, Number.isInteger(length) ? length : DEFAULT_LENGTH);
  const chars = [pick(UPPER), pick(LOWER), pick(DIGITS), pick(SYMBOLS)];
  while (chars.length < size) chars.push(pick(ALL));

  // Fisher–Yates：保证四个"必选位"不会永远落在前四位
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(0, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

module.exports = { generateTemporaryPassword };
