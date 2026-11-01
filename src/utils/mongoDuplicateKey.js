/**
 * MongoDB 唯一键冲突（E11000）的统一判定谓词。
 *
 * 竞态窗口场景（判重通过后写入仍撞唯一索引）需要把原始 MongoError 归一成业务
 * outcome 而不是放任冒泡成 500（防枚举统一口径，审计 2026-11-02 B-F-3）。
 * 单文档写入冲突表现为顶层 `code === 11000`；批量写入（insertMany/bulkWrite）
 * 的冲突藏在 `writeErrors[].code`——只判顶层会漏掉批量形态。判据形态与
 * errorHandler 的 11000 规则、initData/adminAccount.js 的冲突归一一致。
 *
 * @param {Error} e - 捕获到的错误
 * @returns {boolean}
 */
const isDuplicateKeyError = (e) =>
  Boolean(e && (e.code === 11000 || (e.writeErrors || []).some((w) => w && w.code === 11000)));

module.exports = { isDuplicateKeyError };
