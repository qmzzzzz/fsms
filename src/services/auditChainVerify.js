/**
 * 审计哈希链完整性校验服务
 *
 * 单一实现，供三方复用：运维脚本（scripts/verify-audit-chain.js）、
 * 管理接口（GET /api/security/audit-chain/verify）、周期性自检任务。
 *
 * 三层校验，强度递减但互补：
 *
 * 1. hash 重算（内容防篡改）—— 逐条 SHA256(prevHash|canonicalPayload) 比对。
 *    payload 口径按记录自带的 hashVersion 选择（null 视为 v1 存量口径）。
 *    任何字段被改写都会在此暴露，与记录顺序无关，是最强的一层。
 *
 * 2. hmac 校验（密钥防篡改）—— hash 是无密钥 SHA-256，拿到 DB 写权限者可
 *    整条链重算；hmac = HMAC-SHA256(HMAC_SECRET, hash) 是唯一真正的防线。
 *    缺失或失配均计入断裂。未配置 HMAC_SECRET 时降级并显式声明。
 *
 * 3. 链接性校验（删除/插入检测）—— 每条记录的 prevHash 必须命中「近期已见
 *    hash 的滑动窗口」。用窗口而非「严格等于上一条的 hash」，是因为 _id 顺序
 *    与实际串链顺序存在小幅错位：AuditLog.create 在构造文档时就分配了 _id，
 *    而 auditBuffer 走 insertMany 的批次要等 2s 定时器才拿到 _id——两者在
 *    链锁上的先后可能与 _id 大小相反。这种错位不是完整性问题（哈希链本身连续），
 *    严格逐对比较会产出大量假阳性断链，反而掩盖真实篡改。
 *    窗口足够小（LINK_WINDOW_SIZE），删除或插入记录仍会立即暴露。
 *
 * 存量数据的已知限制（必须如实告知，不得当作「已修好」）：
 * - hashVersion=null（legacy，本机 1137 条）：写入时无哈希链，完全无保护。
 * - hashVersion=2（本机 4419 条）：批量路径算 hash 时未补 schema 默认值，
 *   校验端用 canonicalPayloadV2LegacyBatch 宽容该已知漂移（计入
 *   legacyV2BatchTolerated 而非 breaks）。代价是这批记录的
 *   riskLevel/riskFactors **从未受哈希保护**，事后无法追认。
 *   宽容后仍有少量 v2 记录失配（本机 19 条），成因未能归因到任何单/双字段
 *   变换——可能是当时并发写入下 payload 与落库文档存在其它差异。
 *   这些条目保留在 breaks 中，不做进一步宽容：宁可留下待查告警，
 *   也不为了「报告干净」而扩大宽容面。
 * - hashVersion=3（修复后写入）：实测 hash/hmac/链接三层全绿。
 * 结论：**新写入的链已可信；存量 v1/v2 记录的完整性不可追认**。
 */

const {
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
  computeHash,
  computeHmac,
  isHmacConfigured,
} = require('../utils/auditChain');

// 链接性校验的滑动窗口大小：容纳 _id 与串链顺序的正常错位，
// 远小于任何有意义的删除批量，不影响篡改检出
const LINK_WINDOW_SIZE = 256;

// 单次校验的记录上限：审计集合可达千万级，全量校验必须由离线脚本分段执行。
// 接口侧默认只校验最近一段，避免长事务与内存膨胀。
const DEFAULT_MAX_RECORDS = 20000;
const HARD_MAX_RECORDS = 200000;

// 断裂样本上限（响应体大小保护）
const MAX_SAMPLES = 20;

/**
 * 校验审计哈希链
 *
 * @param {import('mongoose').Model} AuditLog 审计日志模型
 * @param {Object} [options]
 * @param {number} [options.maxRecords] 最多校验多少条（从最新往前取，再按时序校验）
 * @param {boolean} [options.fromLatest=true] true=校验最近 maxRecords 条；false=从最早开始
 * @returns {Promise<Object>} 校验报告
 */
const verifyAuditChain = async (AuditLog, options = {}) => {
  const maxRecords = Math.max(
    1,
    Math.min(Number(options.maxRecords) || DEFAULT_MAX_RECORDS, HARD_MAX_RECORDS)
  );
  const fromLatest = options.fromLatest !== false;

  const hmacChecked = isHmacConfigured();

  let total = 0;
  let legacy = 0;
  let breaks = 0;
  const byType = {
    hash_mismatch: 0,
    hmac_missing: 0,
    hmac_mismatch: 0,
    chain_break: 0,
  };
  // v2 批量路径的历史默认值漂移：不是篡改，单独计数不计入 breaks
  let legacyV2BatchTolerated = 0;
  const samples = [];

  const pushBreak = (sample) => {
    breaks += 1;
    byType[sample.type] = (byType[sample.type] || 0) + 1;
    if (samples.length < MAX_SAMPLES) samples.push(sample);
  };

  // 取最近 maxRecords 条：先按 _id 降序取窗口，再反转为升序校验
  // （链接性校验依赖时序，必须升序推进）
  const window = await AuditLog.find({})
    .sort({ _id: fromLatest ? -1 : 1 })
    .limit(maxRecords)
    .lean();
  const docs = fromLatest ? window.reverse() : window;

  // 近期已见 hash 的滑动窗口（Set 用于命中判断，数组用于按序淘汰）
  const seen = new Set();
  const seenOrder = [];
  const remember = (hash) => {
    seen.add(hash);
    seenOrder.push(hash);
    if (seenOrder.length > LINK_WINDOW_SIZE) {
      seen.delete(seenOrder.shift());
    }
  };

  // 窗口起点的 prevHash 无从校验（其父记录在窗口之外），跳过第一条的链接检查
  let isFirst = true;

  for (const doc of docs) {
    total += 1;

    // 无 hash 的存量记录：计为 legacy，并清空链接窗口
    // （其后第一条记录的 prevHash 指向 legacy 之前，无法在此校验）
    if (!doc.hash) {
      legacy += 1;
      seen.clear();
      seenOrder.length = 0;
      isFirst = true;
      continue;
    }

    const version = doc.hashVersion || 1;
    const expectedHash = computeHash(doc.prevHash, canonicalPayload(doc, version));
    if (expectedHash !== doc.hash) {
      // v2 记录额外尝试「批量路径历史口径」：v2 时期 chainBatch 未补 schema
      // 默认值，riskLevel/riskFactors 落库后被 Mongoose 填充，重算必然失配。
      // 这是已知的实现缺陷而非篡改，不应计入 breaks 淹没真实告警。
      // v1/v3 不做此宽容：v1 的 payload 不含这两个字段，v3 已保证算前补齐。
      const toleratedByLegacyBatch =
        version === 2 && computeHash(doc.prevHash, canonicalPayloadV2LegacyBatch(doc)) === doc.hash;

      if (toleratedByLegacyBatch) {
        legacyV2BatchTolerated += 1;
      } else {
        pushBreak({
          _id: String(doc._id),
          index: total,
          type: 'hash_mismatch',
          hashVersion: version,
          action: doc.action,
          timestamp: doc.timestamp,
        });
      }
    }

    if (hmacChecked) {
      if (!doc.hmac) {
        pushBreak({ _id: String(doc._id), index: total, type: 'hmac_missing', action: doc.action });
      } else if (doc.hmac !== computeHmac(doc.hash)) {
        pushBreak({
          _id: String(doc._id),
          index: total,
          type: 'hmac_mismatch',
          action: doc.action,
        });
      }
    }

    // 链接性：prevHash=null 是链首，合法
    if (!isFirst && doc.prevHash && !seen.has(doc.prevHash)) {
      pushBreak({
        _id: String(doc._id),
        index: total,
        type: 'chain_break',
        action: doc.action,
        actualPrevHash: doc.prevHash,
        timestamp: doc.timestamp,
      });
    }

    remember(doc.hash);
    isFirst = false;
  }

  return {
    intact: breaks === 0,
    total,
    legacy,
    breaks,
    byType,
    // v2 时期批量写入路径的默认值漂移条数（已知实现缺陷，非篡改）。
    // 这些记录的 riskLevel/riskFactors 从未受哈希保护，事后无法追认；
    // 数值应随存量记录过期（TTL）而归零，若持续增长说明仍有 v2 写入路径存活。
    legacyV2BatchTolerated,
    hmacChecked,
    scanned: { maxRecords, fromLatest },
    chainTailHash: seenOrder.length ? seenOrder[seenOrder.length - 1] : null,
    samples,
    verifiedAt: new Date().toISOString(),
  };
};

module.exports = {
  verifyAuditChain,
  LINK_WINDOW_SIZE,
  DEFAULT_MAX_RECORDS,
  HARD_MAX_RECORDS,
};
