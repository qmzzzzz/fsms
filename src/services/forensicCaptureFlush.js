/** 取证捕获的落库（2026-10-31 从 forensicCapture.js 拆出，max-lines 300 棘轮）：校验分流 + 幂等写入 + 失败回填。两条纪律属**落库**语义而非编排：① 校验失败要显式计 dropped 且不裁 WAL（否则库与盘同时失去证据）；② 回填与计数必须排在告警/日志之前——告警一抛就整批蒸发且零痕迹（P0-2）。 */

const wal = require('./forensicCaptureWal');
const { validateOne, docsNotYetStored } = require('./forensicCaptureCodec');
const { incSecurityAlert } = require('../utils/metrics');
const forensicManifest = require('./forensicManifest');

/** 依赖全部由编排层注入：本模块不持有状态，也不自己决定容量口径 */
const createFlusher = ({ state, noteError, warnRateLimited, errText, bufferHardLimit }) => {
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
        await ForensicCapture.insertMany(valid, { ordered: false, throwOnValidationError: true });
        wal.trimBySeqs(valid.map((d) => d.__walSeq).filter(Boolean));
        // 落库成功后才锚进清单（顺序不能反：先记清单后落库，落库失败就会留下"证明一条不存在的记录"的锚点）。写失败只计数告警、不外抛（appendBatch 自己兜），绝不让清单问题回滚已成功的落库。
        await forensicManifest.appendBatch({
          recordHashes: valid.map((d) => d.recordHash).filter(Boolean),
          firstSeq: valid[0].__walSeq || null,
          lastSeq: valid[valid.length - 1].__walSeq || null,
        });
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
    } finally {
      state.flushing = false;
    }
  };

  return flush;
};

module.exports = { createFlusher };
