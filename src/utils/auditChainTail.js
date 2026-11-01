/**
 * 审计链尾初始化口径（纯读侧判据；单独成文件只为拆 auditChain.js 的 max-lines）。
 * 判据：链尾 = 没有任何记录把它当父；与 _id 序无关（push 预分配 _id 会让久候批次早于其间直写记录，取最大 _id 会接出平分叉）。先取最近窗口候选，再用带索引的 prevHash 反查已认领者。原委见 tests/services/auditChainVerifyIdOrder.test.js。
 */

const logger = require('./logger');

// 候选窗口：256 条覆盖单实例一分钟量级（越大越不怕真尾被挤出，代价是初始化多扫）。
const TAIL_WINDOW = 256;

/** 旧口径：取最大 _id（前提 _id 序 == 追加序，push 预分配后不再恒真）；仅兜底路径使用。 */
async function latestHashByMaxId(model) {
  const latest = await model
    .findOne({ hash: { $ne: null } }, { hash: 1, _id: 1 })
    .sort({ _id: -1 })
    .lean();
  return latest && latest.hash ? latest.hash : null;
}

/** 取链尾 hash（首次初始化用）；null = 链上还没有任何带哈希的记录。 */
async function getLatestHash(model) {
  // 替身模型没有窗口反查能力：按旧口径回落（生产恒为 mongoose Model，这条分支只为夹具存在）。
  if (typeof model.find !== 'function') {
    logger.warn('审计链尾初始化：模型缺少 find()（替身/瘦包装器），已回落到「最大 _id」口径');
    return latestHashByMaxId(model);
  }
  // _id 降序只用于取候选，不用于判定谁是尾。
  const recent = await model
    .find({ hash: { $ne: null } }, { hash: 1, _id: 1 })
    .sort({ _id: -1 })
    .limit(TAIL_WINDOW)
    .lean();
  const hashes = (recent || []).map((r) => r && r.hash).filter(Boolean);
  if (!hashes.length) return null;
  // 用带索引的 prevHash 反查已认领者（$in 命中索引）。
  const claimed = new Set(
    (await model.find({ prevHash: { $in: hashes } }, { prevHash: 1 }).lean())
      .map((r) => r && r.prevHash)
      .filter(Boolean)
  );
  const unclaimed = hashes.filter((h) => !claimed.has(h));
  if (unclaimed.length === 1) return unclaimed[0];
  if (unclaimed.length === 0) {
    // 候选全有子记录 ⇒ 真尾在窗口外（多实例下窗口可能被挤满）：回落旧口径并告警，不返回 null（null 会被读成「链尚未开始」）。
    logger.warn(
      `审计链尾初始化：最近 ${hashes.length} 条全部已有子记录（真尾在窗口外），已回落到「最大 _id」口径`
    );
    return latestHashByMaxId(model);
  }
  // 无子记录者不止一条（真分叉或窗口混入历史记录）：取 _id 最大者，仍比直接取最大 _id 保守。
  logger.warn(
    `审计链尾初始化：最近 ${hashes.length} 条中无子记录者 ${unclaimed.length} 条（疑似分叉或混入历史记录），已取其中 _id 最大者`
  );
  return unclaimed[0];
}

module.exports = { TAIL_WINDOW, getLatestHash, latestHashByMaxId };
