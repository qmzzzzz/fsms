/**
 * 审计批量写入路径的「文档级判定层」（从 services/auditBuffer.js 拆出；拆分的直接原因是
 * 体积棘轮：auditBuffer.js 的 max-lines 计数正好顶在 300，任何净增行都会令 lint:ratchet 转红，
 * 而本层三件事全都是**不持有缓冲与计数器**的纯判定，天然属于这里）：
 *
 *   ① precastBatch    串链前的预铸造闸——谁不能进链、谁要丢弃、落库形态回写
 *   ② collectDurableIds / walSeqsOf  落库回执与 WAL 行号的对应关系
 *
 * 状态仍归 auditBuffer：被拒文档的丢弃计数、缓冲撤回、逐文档计次通过 sink 交回去，
 * 本模块只在需要时读 wal 模块（归档路径与主文件都在 wal 层，符合既有分层）。
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const wal = require('./auditBufferWal');
const auditChain = require('../utils/auditChain');

/**
 * 载荷字段清单按当前哈希版本取，与 chainBatch 的口径同源。
 * 回写范围必须严格等于「进入 canonicalPayload 的范围」：少一个字段就留一处分叉
 * （被哈希的形态 ≠ 落库形态 ⇒ 该记录永久 hash_mismatch，一条假篡改且自身保护静默失效），
 * 多回写非载荷字段则是无谓的写放大。
 * 版本号 bump 而清单没导出时回落 V4：宁可少回写几个字段（由
 * tests/services/auditChainBatchCastParity.test.js 那族对拍用例立刻变红），
 * 也不能让本层抛 TypeError——那会被 flush 的外层 catch 读成"落库失败"。
 */
const PRECAST_FIELDS =
  auditChain[`PAYLOAD_FIELDS_V${auditChain.CURRENT_PAYLOAD_VERSION}`] ||
  auditChain.PAYLOAD_FIELDS_V4;

/**
 * 单条预铸造。
 * @returns {?string} null=通过（落库形态已写回 doc 本身）；字符串=拒绝原因
 */
function precastOne(doc) {
  // 这里**没有**铸造抛错的分支，是有意的：mongoose 8 把 CastError 推迟到 validateSync
  // （实测 14 个对抗输入——非 hex 串 / 23 位串 / 对象 / 数组 / 枚举外 / 非法日期——
  // 一个都不在构造时抛，探针与输出见 zztmpctl/probe_b72_castthrow.txt）。
  // 而 push() 在入队时就 JSON.stringify 过整条文档，"读字段即抛"的载荷根本进不到这里。
  // 真出现抛错时不兜底反而更安全：穿过本函数落到 flush 的外层 catch，整批按落库故障
  // 回退重试直至毒批丢弃（有记账、有归档）；若在**已经记完本批拒绝账**之后才抛出，
  // 外层回退会把同一批再送一次 ⇒ droppedCount 双计、被拒文档又被塞进 insertMany。
  const hydrated = new AuditLog(doc);
  const err = hydrated.validateSync();
  if (err) return `validate/${Object.keys(err.errors || {}).join(',') || err.name}`;
  const cast = hydrated.toObject({ getters: false, virtuals: false });
  // 写回原对象而不是换新对象：__walSeq、预分配的 _id、以及 flushStrikes 的 WeakMap 键
  // 都挂在引用上。insertMany 再铸一次是幂等的（输入已是铸后形态）。
  for (const f of PRECAST_FIELDS) doc[f] = cast[f];
  return null;
}

/** 预检拒绝的告警文案（含累计丢失量与 WAL 归档去向） */
function rejectMessage(rejected, seqs, droppedTotal) {
  const listed = rejected
    .slice(0, 5)
    .map((r) => r.reason)
    .join(', ');
  const walPart =
    seqs.size > 0
      ? `其 ${seqs.size} 行 WAL 取证行已归档到 ${wal.getWalPath()}.discarded 并从主文件移除`
      : '本批无 WAL 行可归档（WAL 未启用窗口入队的文档）';
  return (
    `审计批次内 ${rejected.length} 条文档在串链前的 schema 预铸造中被拒` +
    `（${listed}${rejected.length > 5 ? ' 等' : ''}），已丢弃并计入累计丢失 ${droppedTotal} 条。` +
    `这些文档若直接送 insertMany({ordered:false}) 会被**静默丢弃**：不抛错、不计错误，` +
    `而其下一条的 prevHash 指向从未落库的记录 ⇒ 核验端报 chain_break 假篡改。${walPart}。` +
    `请排查审计中间件是否被喂了不合 schema 的字段`
  );
}

/**
 * 整批预铸造：在算哈希**之前**跑，一次性消掉批量写路径的两个**同源**缺口
 * （同源：铸造发生在算哈希之后）。判据与实测数字见交付台账批次 72。
 *
 * ① 静默丢文档 ⇒ 永久链洞。`insertMany({ordered:false})` 对**mongoose 层**校验失败的文档
 *   是「resolve 但不返回」：不抛错、不进 writeErrors、零告警（实测：推 3 条、其中 1 条
 *   category 枚举外 ⇒ 库里 2 条、droppedCount 仍 0、warn/error 0 条）。被丢那条的**下一条**
 *   的 prevHash 指向从未落库的记录 ⇒ 核验端 chain_break 假篡改，且永远修不掉（真被改也照样红，
 *   唯一补救是整库重签＝销毁取证价值）；它的 WAL 行还照样被本批裁剪吃掉 ⇒「崩溃后重放」这层
 *   保险一起没了，`.discarded` 里也查不到它。
 * ② 被哈希的形态 ≠ 落库的形态。chainBatch 对普通对象算哈希、insertMany 之后才铸造，
 *   schema 里任何改写值的 setter/类型转换都让这条记录永久 hash_mismatch。
 *   utils/auditChain.js 的 PAYLOAD_SCHEMA_DEFAULTS 与 method 降级闸是 ② 的两处**镜像补丁**：
 *   每新增一个改写器就得人记得再补一处，漏一次即永久假篡改（实测 22 个对抗形态里 11 个分叉：
 *   statusCode:'200'、success:1、userId 大写十六进制串、riskFactors:'x'、duration:'12.7'、
 *   timestamp 毫秒数 …）。本闸从源头消掉整族，将来新写的 setter 无需再镜像。
 *
 * ① 的判据用 validateSync——它与 ordered:false 的实际丢弃行为逐条一致（同一份 schema 判定；
 * 27 个变体实测零过拒、零漏拒。「过拒」＝把真能落库的记录丢掉，那是**新增**的数据丢失，
 * 比洞更糟，所以两个方向都必须量）。
 *
 * @param {object[]} docs 本批文档（**必须已预分配 _id**：丢弃记账靠 _id 精确撤走缓冲副本）
 * @param {{addDropped:Function, retract:Function, clearStrike:Function}} sink
 *   本模块私有的三样由调用方给：丢弃计数（返回新的累计值）、按 _id 撤回缓冲副本、
 *   逐文档计次清理
 * @returns {object[]} 可进链子集；被拒的那些已在本次调用内完成归档与告警
 */
function precastBatch(docs, sink) {
  const accepted = [];
  const rejected = [];
  for (const d of docs) {
    const reason = precastOne(d);
    if (reason === null) accepted.push(d);
    else rejected.push({ doc: d, reason });
  }
  if (rejected.length === 0) return accepted;

  const rejectedDocs = rejected.map((r) => r.doc);
  // 链锁超时的僵尸回退可能已把本批放回缓冲；被拒文档若不撤走，下一轮会被再拒一次、
  // droppedCount 双计（丢失量说谎）。sink.retract 只取"按 _id 从缓冲精确移除"这一步。
  sink.retract(new Set(rejectedDocs.map((d) => String(d._id))));
  for (const d of rejectedDocs) sink.clearStrike(d);
  const seqs = walSeqsOf(rejectedDocs);
  const droppedTotal = sink.addDropped(rejectedDocs.length);
  // P1-24 的取证顺序在这里同样成立：先归档再改主文件，否则每次重启都重放同一批、
  // 再走一遍预检、再丢一次，而 .discarded 里始终没有它们。
  if (seqs.size > 0) wal.discardBySeqs(seqs);
  logger.error(rejectMessage(rejected, seqs, droppedTotal));
  return accepted;
}

// ==================== 以下两个函数自 auditBuffer.js 逐字节搬入（批次 72，逻辑与注释均未改） ====
// 搬它们的理由：auditBuffer.js 的 max-lines 计数正好顶在 300（体积棘轮基线 0），
// 新增预铸造闸必须有等量的净去处；这两个函数都不读任何模块状态，是这里唯一的无损候选。

/**
 * 从 insertMany 的错误里收集「已经存在于库中」的文档 _id（字符串形式）。
 *
 * 两类来源（Mongoose 8 + driver 6 实测的错误结构，契约钉在
 * tests/auditBufferZombieDuplicate.test.js 的「前提自证」用例）：
 *  - err.insertedDocs：ordered:false 下**本次**确认写入的文档（带 _id）；
 *  - err.writeErrors[i]：因 _id 唯一键冲突被拒的记录。实测其形状是
 *    `{ index, err: { index, code, errmsg, op } }`——服务端错误码嵌在 `.err` 下，
 *    条目自身只有 index（`w.code`/`w.op` 均为 undefined）。首次实跑就是按 `w.code`
 *    判 11000 取到空集、幂等识别静默失效，故这里读 `w.err.code` + `docs[w.index]`。
 *
 * AuditLog 无其它 unique 索引（见 auditWalReplayIdempotency 用例 2 的实测断言），
 * 故 11000 只可能来自 _id 冲突，本判据不会把「别的原因写失败」误判成已落库。
 */
function collectDurableIds(err, docs) {
  const ids = new Set();
  const add = (d) => {
    const id = d && d._id;
    if (id !== undefined && id !== null) ids.add(String(id));
  };
  if (Array.isArray(err.insertedDocs)) err.insertedDocs.forEach(add);
  if (Array.isArray(err.writeErrors)) {
    for (const w of err.writeErrors) {
      if (w && w.err && w.err.code === 11000) add(docs[w.index]);
    }
  }
  return ids;
}

/** 取一批文档的 WAL 序号集合（无序号的文档 = WAL 未启用窗口入队的，本来就没有行） */
function walSeqsOf(docs) {
  return new Set(docs.map((d) => d && d.__walSeq).filter(Boolean));
}

/**
 * 处理「批次算哈希失败」的收尾（2026-09-30 加固）。
 *
 * 从 auditBuffer.flush 里抽出来（该文件 max-lines 已贴棘轮上限——本文件的存在
 * 本身就是同一条纪律的产物，见 auditBuffer.js 顶部注释）。
 *
 * 做三件事，每一件都有必须的理由：
 *  ① 打标：给**尚未拿到 hash** 的文档写 `hashFailure`。核验器对"无 hash 记录"
 *     只有一种解读——出现在带哈希记录之后即判 hash_stripped（人为抹除）。
 *     而"算 hash 抛错仍落库"是良性且会持续产生的成因，不打标就会让真实篡改告警
 *     淹没在常态噪声里（M-09「幻影链尾」的同一条演化路径）。
 *     只标没有 hash 的那些：chainBatch 逐条串链，抛错时前若干条已算出 hash
 *     （构成一段合法链，父链来自真实链尾），它们不该被一起降级。
 *  ② 链尾推进：把已串链**前缀**的链尾取出来返回。原实现在抛错时整批不推进，但
 *     前缀的 hash 已写进文档并会落库 ⇒ 下一批从**旧链尾**重新串链 ⇒ 两条记录
 *     认领同一个父哈希 ⇒ chain_fork（核验器的 F-184a 判据把它列为高危篡改信号）。
 *     即「每次哈希异常都制造一个分叉」——返回前缀链尾是必须的修复，不是优化。
 *  ③ 告警：这条路此前只有 logger.warn。「批次无哈希落库」= 链上出现一段无法追认的
 *     记录，是完整性缺口的**唯一直接信号**，必须进告警面而非只躺在一行日志里。
 *
 * @param {Array} docs 已预铸造、准备落库的文档（本函数就地改写）
 * @param {Error} hashErr chainBatch 抛出的错误
 * @param {Function} [onAlert] 告警回调（默认计 incSecurityAlert），便于测试替换
 * @returns {{pendingTail: string|null, chained: boolean}} 前缀链尾与"是否有可推进的链段"
 */
function handleHashFailure(docs, hashErr, onAlert) {
  // ① 打标（只给无 hash 的）
  const brief = String((hashErr && hashErr.message) || 'unknown').slice(0, 200);
  for (const d of docs) {
    if (!d.hash) {
      d.hash = null;
      d.prevHash = null;
      d.hashVersion = null;
      d.hashFailure = brief;
    }
  }
  // ② 前缀链尾：最后一个带 hash 的文档，它的 hash 就是本批已确认链段的尾
  const lastHashed = [...docs].reverse().find((d) => d.hash);
  // ③ 告警（指标端不可用不影响落库与标记）
  try {
    if (typeof onAlert === 'function') onAlert();
    else require('../utils/metrics').incSecurityAlert('audit_hash_compute_failed', 'high');
  } catch (_) {
    /* 指标端不可用：日志与落库标记仍是留痕 */
  }
  return { pendingTail: lastHashed ? lastHashed.hash : null, chained: Boolean(lastHashed) };
}

module.exports = {
  PRECAST_FIELDS,
  precastBatch,
  collectDurableIds,
  walSeqsOf,
  handleHashFailure,
};
