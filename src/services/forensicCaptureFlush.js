/** 取证捕获的落库（2026-10-31 从 forensicCapture.js 拆出，max-lines 300 棘轮）：校验分流 + 幂等写入 + 失败回填。两条纪律属**落库**语义而非编排：① 校验失败要显式计 dropped 且不裁 WAL（否则库与盘同时失去证据）；② 回填与计数必须排在告警/日志之前——告警一抛就整批蒸发且零痕迹（P0-2）。 */

const wal = require('./forensicCaptureWal');
const { validateOne, docsNotYetStored } = require('./forensicCaptureCodec');
const { incSecurityAlert } = require('../utils/metrics');
const forensicManifest = require('./forensicManifest');

// 单次 insertMany 的字节预算（16MB）：远低于 MongoDB 单消息 ~48MB 的硬上限，
// 给 BSON 编码与驱动封装留足余量。预算是防毒批的兜底而非容量承诺。
const FLUSH_CHUNK_BYTES = 16 * 1024 * 1024;
// 单条大小估算失败的兜底值：按"超预算"处理 ⇒ 该条独立成批，失败也不拖累其他记录。
const DOC_SIZE_ESTIMATE_FALLBACK = FLUSH_CHUNK_BYTES;

const serializedBytesOf = (doc) => {
  try {
    return Buffer.byteLength(JSON.stringify(doc), 'utf8');
  } catch {
    return DOC_SIZE_ESTIMATE_FALLBACK;
  }
};

/**
 * 按估算序列化字节把待插文档切成每批 ≤ FLUSH_CHUNK_BYTES。
 * 单条本身超预算时独立成批（恒有进展），不与后续记录合并。
 */
const splitBySerializedBytes = (docs) => {
  const chunks = [];
  let current = [];
  let currentBytes = 0;
  for (const doc of docs) {
    const bytes = serializedBytesOf(doc);
    if (current.length > 0 && currentBytes + bytes > FLUSH_CHUNK_BYTES) {
      chunks.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(doc);
    currentBytes += bytes;
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
};

/** 依赖全部由编排层注入：本模块不持有状态，也不自己决定容量口径 */
const createFlusher = ({ state, noteError, warnRateLimited, errText, bufferHardLimit }) => {
  const anchorStored = async (docs) => {
    if (!Array.isArray(docs) || docs.length === 0) return; // G-6/H-3：进库的必须进清单
    await forensicManifest.appendBatch({
      recordHashes: docs.map((d) => d.recordHash).filter(Boolean),
      firstSeq: docs[0].__walSeq || null,
      lastSeq: docs[docs.length - 1].__walSeq || null,
    });
  };

  const flush = async () => {
    if (state.flushing || state.buffer.length === 0) return;
    state.flushing = true;
    const batch = state.buffer.splice(0, state.buffer.length);
    const ForensicCapture = require('../models/ForensicCapture');
    const valid = []; // 先逐条校验再插入（P0-3）：insertMany 的校验失败是静默的（不 reject 也不报告），原来紧接着裁整批 WAL ⇒ 库与盘同时失去证据且计数全 0。只有真落库的才允许裁 WAL。
    const invalid = [];
    for (const doc of batch) {
      const verdict = validateOne(ForensicCapture, doc);
      if (verdict) invalid.push(verdict);
      else valid.push(doc);
    }
    if (invalid.length > 0) {
      state.dropped += invalid.length;
      noteError(`validation: ${invalid[0].message}`);
      warnRateLimited(
        `取证记录校验失败被拒 ${invalid.length} 条（已计 dropped，WAL 行保留以便复核）：${invalid[0].message}`
      );
      // 被拒记录的 WAL 行**不裁**：它们是"记录存在过"的最后证据，裁掉等于没有发生过。
    }
    try {
      if (valid.length > 0) {
        // 防毒批：单条载荷有封顶，但封顶值可经 env 放大，且 UTF-8 多字节会让字符数
        // 远小于字节数；满批（bufferHardLimit 条）在最坏情况下能逼近/越过 MongoDB
        // 单消息 ~48MB 上限——那会退化成「整批失败 → 整批回填 → 同一批再次超限」
        // 的毒批循环。按估算字节分批 insertMany；分批不改变语义：仍 ordered:false，
        // 全部成功才裁 WAL/锚清单，部分批失败走下方既有的回填与补锚路径。
        for (const chunk of splitBySerializedBytes(valid)) {
          await ForensicCapture.insertMany(chunk, {
            ordered: false,
            throwOnValidationError: true,
          });
        }
        wal.trimBySeqs(valid.map((d) => d.__walSeq).filter(Boolean));
        // 落库成功后才锚进清单（顺序不能反：先记清单后落库，落库失败就会留下"证明一条不存在的记录"的锚点）。写失败只计数告警、不外抛（appendBatch 自己兜），绝不让清单问题回滚已成功的落库。
        await anchorStored(valid);
      }
    } catch (err) {
      let retry = valid; // 顺序是硬要求（P0-2）：回填与计数必须先于任何"可能抛错"的调用（告警/日志），否则整批已 splice 走的记录既不入库也不回填也不计数。回填前做幂等筛选，已入库的行不得再回填（否则重试即写重）。
      try {
        retry = await docsNotYetStored(ForensicCapture, valid);
      } catch {
        /* 筛选失败不改变重试口径：整批回填，宁可重试也不丢 */
      }
      const room = Math.max(0, bufferHardLimit - state.buffer.length);
      state.buffer.unshift(...retry.slice(0, room));
      if (retry.length > room) state.dropped += retry.length - room;
      state.writeFailures += 1;
      noteError(err);
      // 与触发侧同一口径：记账已做完，告警自身抛错不得穿透（字面量留在调用点供门禁枚举）
      try {
        incSecurityAlert('forensic_capture_write_failed', 'medium');
      } catch {
        /* 告警失败不改写落库语义 */
      }
      warnRateLimited(
        `取证批量落库失败（累计 ${state.writeFailures} 次），回填 ${Math.min(retry.length, room)} 条待重试，` +
          `超硬上限丢弃 ${Math.max(0, retry.length - room)} 条：${errText(err)}`
      );
      if (retry.length < valid.length) {
        const retrySet = new Set(retry); // H-3：部分成功时已进库子集必须补锚（回填只管没入库的）
        try {
          await anchorStored(valid.filter((d) => !retrySet.has(d)));
        } catch (_) {}
      }
    } finally {
      state.flushing = false;
    }
  };

  return flush;
};

module.exports = { createFlusher };
