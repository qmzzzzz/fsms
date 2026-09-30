/**
 * 审计日志缓冲批量写入模块
 * 仅用于 HTTP 全局审计中间件的高频请求型日志：内存缓冲 + 定时/满额批量 insertMany，
 * 降低高频写操作下"每请求一次 DB 写"的入库压力。
 *
 * 注意：事件型审计（AuditLog.record：登录成败、暴力破解告警、锁定/解锁等）不经过本模块，
 * 保持直写——暴力破解检测（checkBruteForce）依赖 login_failed 的即时可查性。
 *
 * 【WAL 兜底（G4 不丢失）】的 WAL 文件层已拆至 services/auditBufferWal.js（O-3 体积棘轮，
 * 2026-09-17）：本模块保留内存缓冲、批量落库（flush）与进程生命周期，WAL 的路径派生、
 * 按行追加、前缀裁剪、大小上限、毒批序号与归档、以及串行化它们的 walChain 由 wal 模块负责。
 * 对外行为与拆分前一致：push 时同步追加 WAL 行，flush 落库成功后按**该批文档的
 * `__walSeq` 精确移除对应行**（F-97：原先按落库条数裁前 N 行，有空洞时会误删未落库行），
 * 崩溃后 start() 重放 WAL 残留（先按毒批归档序号过滤，P1-24）。
 */

const mongoose = require('mongoose');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const wal = require('./auditBufferWal');
const { isContentAttributableFailure } = require('../utils/mongoFailureAttribution');
// 批量写路径的文档级判定层（串链前的预铸造闸 + 落库回执/行号对账）在 services/auditBufferDocs.js。
// 拆出去是因为本文件的 max-lines 计数正好顶在 300（体积棘轮基线 0）：新增判据必须有等量的净去处。
const auditDocs = require('./auditBufferDocs');
// 预检拒掉的文档要动本模块私有的三样状态，由判定层反向调用（判定层不持有缓冲与计数器）：
// 丢弃计数（返回累计值供告警文案）、按 _id 撤走缓冲副本、逐文档内容级计次清理。
const precastSink = {
  addDropped: (n) => noteDropped(n, 'precast'),
  retract: retractDurable,
  clearStrike: (d) => flushStrikes.delete(d),
};

// 缓冲上限：达到即触发一次批量落库
const BUFFER_LIMIT = 100;
// 定时落库间隔（毫秒）
const FLUSH_INTERVAL_MS = 2000;

// ================= 容量与重试保护（P2-21） =================
// 缓冲硬上限：Mongo 中断期间每 2s flush 失败整批回退，高流量下缓冲无界增长会 OOM。
// 达到上限后丢弃最旧记录（WAL 里仍有对应行，崩溃后可重放；比整进程 OOM 可接受）。
// 原先写作 Number(env) || 10000，而**负值是真值**——
// AUDIT_BUFFER_HARD_LIMIT=-1 会原样生效，令 enforce 分支 `length <= -1` 恒不成立、
// `overflow = length + 1`，于是每次 push 都把整个缓冲 splice 掉（实测：push 5 条丢 10 条），
// 审计记录停止落库却只有 WAL 残留。改为统一判据：只采纳有限正整数，否则回落默认并告警。
const { readPositiveNumberEnv } = require('../utils/envNumber');
const BUFFER_HARD_LIMIT = readPositiveNumberEnv('AUDIT_BUFFER_HARD_LIMIT', 10000, {
  integer: true,
  onInvalid: (name, raw, d) =>
    logger.error(
      `${name}=${JSON.stringify(raw)} 非法（须为正整数），已按默认 ${d} 处理；` +
        '负值会让每次 push 都判定"超限"并丢弃整个缓冲'
    ),
});
// 单次回退到缓冲头部的最大条数：`buffer.unshift(...docs)` 在数十万级会触发
// V8 参数展开上限（RangeError: Maximum call stack size exceeded），整批永久丢失。
// 超过此数量改用分块 unshift。
const UNSHIFT_CHUNK_SIZE = 1000;
// 毒文档隔离阈值：同一批次连续失败达到此次数即丢弃并告警，
// 防止一条永久非法的文档让整批无限滞留重试（原实现只防了「重复插入」，没防「无限重试」）。
const MAX_BATCH_RETRY = 5;
// 优雅关闭时「排空缓冲」的总预算（毫秒）。必须有上限：关停等不下去时
// 容器会 SIGKILL，那时 WAL 行就是唯一残留——但**不能无限等**，否则这一步本身
// 就成了部署卡死的原因。判据同 F-74：只采纳有限正数，坏值回落默认并告警。
const FLUSH_DRAIN_BUDGET_MS = readPositiveNumberEnv('AUDIT_FLUSH_DRAIN_BUDGET_MS', 2000, {
  onInvalid: (name, raw, d) =>
    logger.error(
      `${name}=${JSON.stringify(raw)} 非法（须为正的毫秒数），已按默认 ${d} 处理；` +
        '负值会让关停排空循环每次立刻判定"超时"，缓冲里的审计一行都发不出去'
    ),
});

const buffer = [];
let flushTimer = null;
let flushing = false;
// 累计因容量上限被丢弃的条数（供合规仪表盘暴露，不能静默丢数据）
let droppedCount = 0;
/**
 * 丢弃记账的**唯一入口**（2026-09-26 审计 Top-6）。
 *
 * 三条丢弃路径（缓冲超硬上限裁剪 / 毒文档整批丢弃 / 预铸造拒收）此前各自
 * `droppedCount += n`，只进 JSON 快照 ⇒ 「审计记录被丢弃」在 Prometheus 侧
 * 完全不可见，5 条告警规则无一覆盖它——留痕出现空洞而面板照常满格。
 * 收成一个函数后，`reason` 成为必填参数：新增第四条丢弃路径时**不传 reason
 * 就编译不过语义**（review 时一眼可见），不会再出现"新增路径忘了上报"。
 */
const noteDropped = (n, reason) => {
  droppedCount += n;
  try {
    require('../utils/metrics').incAuditDrop(reason, n);
  } catch (_) {
    /* 指标端不可用不影响丢弃主流程（记账已在上一行完成） */
  }
  // 返回累计值：precastSink 的调用方要用它写告警文案
  return droppedCount;
};
// 连续 flush 失败次数（仅用于告警节流与既有指标；**不再**作为丢弃判据，见下）
let consecutiveFailures = 0;
// 当前**在途** flush 已取走的批次数：关停排空要用它把"还没落库、也不在缓冲里"的
// 那一段算进 residual，否则 `buffer.length === 0` 会被误读成"已排空"（F-101）。
let inFlightCount = 0;

/**
 * 丢弃判据从"全局连败"改成"同一文档累计的内容级失败次数"（F-96）
 *
 * 原实现：`consecutiveFailures >= 5` 即丢弃**当批**并按 `__walSeq` 把那些行移出主 WAL。
 * 但 `consecutiveFailures` 与批次内容无关 ⇒ Mongo 主从切换 / 重启 / 网络抖动
 * 只要横跨 5 轮 flush（约 10 秒），第 5 轮那批**完全合法**的审计就会被当成"毒文档"
 * 归档进 `.discarded` 且永不再回灌 —— 一次抖动换一条永久缺失的合规记录，
 * 日志还把归因写成"毒文档"。本仓 `retractDurable` 的注释里已经记过一次同型症状
 * （"被 MAX_BATCH_RETRY 以毒文档名义丢弃…可这些记录其实早已在库里"）。
 *
 * 三个判据分开：
 *   · 内容级失败（服务端逐条拒绝 / 校验失败）⇒ 计次，达阈值只丢**那些文档**；
 *   · 基础设施类失败（选不到节点/网络/拓扑/选举/写关注）⇒ 一律不丢，继续重试；
 *   · 认不出来的失败 ⇒ **保守当作基础设施**：误判成"毒文档"的代价是不可逆删除，
 *     误判成基础设施的代价只是重试不收敛（缓冲有硬上限、WAL 原样保留，重启可重放）。
 */
const flushStrikes = new WeakMap();
let outageFailures = 0;

/**
 * 分块回退到缓冲头部（P2-21）
 *
 * 不用 `buffer.unshift(...docs)`：spread 会把每个元素作为独立实参压栈，
 * 数十万级时超过 V8 的参数数量上限直接抛 RangeError，整批审计永久丢失。
 * 分块处理并保持原有顺序（先插入靠后的块，最终顺序不变）。
 */
function unshiftChunked(docs) {
  for (let i = docs.length; i > 0; i -= UNSHIFT_CHUNK_SIZE) {
    const start = Math.max(0, i - UNSHIFT_CHUNK_SIZE);
    buffer.unshift(...docs.slice(start, i));
  }
}

/**
 * 按硬上限裁剪缓冲，丢弃最旧记录
 * @returns {number} 本次丢弃条数
 */
function enforceBufferLimit() {
  if (buffer.length <= BUFFER_HARD_LIMIT) return 0;
  const overflow = buffer.length - BUFFER_HARD_LIMIT;
  buffer.splice(0, overflow);
  noteDropped(overflow, 'buffer_overflow');
  logger.error(
    `审计缓冲超过硬上限 ${BUFFER_HARD_LIMIT}，已丢弃最旧 ${overflow} 条（累计 ${droppedCount} 条）。` +
      '数据库可能长时间不可用，请立即排查；这些记录的 WAL 行仍在磁盘上'
  );
  return overflow;
}

/**
 * 从缓冲里撤掉「已确认落库」的文档 —— 僵尸 flush 的自愈收尾。
 *
 * 为什么需要这一步（时序，不是效果问题）：
 *   t=0    flush#1 把批次 splice 出缓冲，insertMany 开始
 *   t=150  链锁持有超时：Promise.race 不会取消 fn，只是不等它
 *          → flush#1 的外层 catch 看到的是**锁超时错误**，此时对落库结果一无所知
 *          → 整批放回缓冲
 *   t=600  那个僵尸 fn 里的 insertMany 才真正返回（成功，或 E11000 全批冲突）
 * 只靠"下一轮识别 11000"仍不收敛：只要 insertMany 持续比链锁超时慢，**每一轮**都会
 * 先超时回退、再在 t=600 知道真相，缓冲永远清不掉，最终被 MAX_BATCH_RETRY 以
 * "毒文档"名义丢弃并计入 droppedCount——可这些记录其实早已在库里（合规指标说谎）。
 * 所以在知道真相的那一刻，按 _id 精确撤掉缓冲中已落库的那些条：
 * 同一批对象引用，撤的就是它们；新入队的其它文档 _id 不同，不受影响。
 * 未发生超时回退时（正常错误传播）批次根本不在缓冲里，本函数自然 0 命中。
 *
 * @returns {number} 实际撤掉的条数
 */
function retractDurable(durableIds) {
  let n = 0;
  for (let i = buffer.length - 1; i >= 0; i -= 1) {
    const id = buffer[i] && buffer[i]._id;
    if (id !== undefined && id !== null && durableIds.has(String(id))) {
      buffer.splice(i, 1);
      n += 1;
    }
  }
  return n;
}

/**
 * 内容级失败的逐文档计次（F-96 的核心：计数挂在**文档**上，不挂在全局）
 *
 * 为什么必须逐文档：全局连败计数与批次内容无关 ⇒ Mongo 抖动 5 轮后，
 * 第 5 轮那批完全合法的审计会被当"毒文档"删掉（不可逆，WAL 行同步归档走）。
 * @param {Array<object>} retryDocs 本轮确认未落库的文档
 * @returns {{doomed: Array<object>, kept: Array<object>}} 达到阈值的（可丢弃）与仍应重试的
 */
function settleContentFaultStrikes(retryDocs) {
  // 只给"这一批里每一条文档"各自计次：全局连败不再决定丢弃，
  // 于是第 5 轮恰好被 flush 出去的合法批次不会替前面的错误买单。
  for (const d of retryDocs) flushStrikes.set(d, (flushStrikes.get(d) || 0) + 1);
  const doomed = retryDocs.filter((d) => (flushStrikes.get(d) || 0) >= MAX_BATCH_RETRY);
  const doomedSet = new Set(doomed);
  for (const d of doomed) flushStrikes.delete(d);
  return { doomed, kept: retryDocs.filter((d) => !doomedSet.has(d)) };
}

/** 丢弃告警文案（独立成函数同样是为了不加重 catch 的分支密度） */
function doomedBatchMessage(doomed, kept, discardSeqs, err) {
  const walPart =
    discardSeqs.size > 0
      ? `已归档 ${discardSeqs.size} 行 WAL 取证行到 ${wal.getWalPath()}.discarded 并从主 WAL 移除`
      : `WAL 行仍保留在 ${wal.getWalPath()}，可人工取证`;
  return (
    `审计批次内有 ${doomed.length} 条文档连续 ${MAX_BATCH_RETRY} 次被服务端按内容拒绝，` +
    `已丢弃并归档取证（累计丢弃 ${droppedCount} 条，同批其余 ${kept.length} 条留在缓冲继续重试）。` +
    `最后一次错误：${err.name || 'Error'}/${err.codeName || err.code || '-'} ${err.message}。` +
    walPart
  );
}

/** 不可归因于内容（基础设施或未知）时的告警：明确写出"不丢弃"，便于值班同学判断处置方向 */
function outageMessage(err) {
  return (
    `审计落库连续 ${outageFailures} 轮失败且不可归因于文档内容` +
    `（${err.name || 'Error'}: ${String(err.message).slice(0, 160)}）。` +
    `缓冲与 WAL 全部保留、不做毒批丢弃——数据库恢复后自动重放；` +
    `缓冲若增长到硬上限 ${BUFFER_HARD_LIMIT} 条，会按最旧优先丢弃并另行以 error 级告警。`
  );
}

/**
 * 批量落库：取走当前缓冲并 insertMany；进行中不重入，新日志继续进缓冲
 *
 * 哈希链在锁内完成「读尾→串链→落库→推进尾」全流程：
 * - 仅在 insertMany 确认成功后 advanceChainTail，杜绝 insert 失败重试时
 *   prevHash 指向从未入库记录的「幻影链尾」断链；
 * - 部分成功（ordered:false）时 DB 中已存在真实记录但与内存尾不一致，
 *   标记链尾失效、下次从 DB 重同步自愈；
 * - 哈希计算为 best-effort：失败时文档以无 hash 落库，**不阻塞落库**。
 *   但"不阻塞落库"不等于"无后果"：verify 端按 services/auditChainVerify.js:25-32
 *   分类——无 hash 记录出现在链启用**之前**才算 legacy（不计断裂），本函数运行在
 *   链已启用**之后**，故这类记录会被计入 breaks（type=hash_stripped）。
 *   即代价是**一条完整性断裂告警**。原注释写成"verify 时计为 legacy"，
 *   会把这条告警误读成噪音，进而掩盖真实篡改——方向恰好写反了。
 * 落库失败则文档回到缓冲重试（at-least-once；WAL 行保留至成功后再裁剪）。
 */
async function flush() {
  if (flushing || buffer.length === 0) return;
  flushing = true;
  const batch = buffer.splice(0, buffer.length);
  // 这批文档此刻**既不在缓冲也未落库**：关停排空必须把它们计入 residual，
  // 否则 `buffer.length === 0` 会被误读成"已排空"（F-101）。
  inFlightCount = batch.length;
  // 幂等重放的身份键：预分配 _id（原先由 Mongoose 在 insertMany 内分配，时机一致）。
  // 回退重试的文档是**同一批对象引用**（unshiftChunked(retryDocs)），_id 因此存活，
  // 下一轮再插必撞 11000 → 被 collectDurableIds 识别为已落库，不再重复插入。
  //
  // 为什么不在 push() 里分配：链尾重同步用 `sort({_id:-1})` 近似「最新链尾」
  // （utils/auditChain.js getLatestHash）。缓冲里久候的批次若在入队时拿到 _id，
  // 其 _id 会**早于**其间直写的 AuditLog.create 记录，而链顺序上它更晚——
  // _id 顺序与链顺序反转会让重同步挑错链尾，凭空造出 chain_break 篡改告警。
  for (const d of batch) if (!d._id) d._id = new mongoose.Types.ObjectId();
  // docs = 预铸造后的**可进链子集**（闸在 services/auditBufferDocs.js，被拒的那些已在该调用内
  // 完成丢弃记账）。初值取整批：万一预铸造自身抛错，外层 catch 回退的是整批，一条都不丢。
  let docs = batch;
  try {
    const {
      chainBatch,
      withChainLock,
      getChainTail,
      advanceChainTail,
      resyncChainTail,
    } = require('../utils/auditChain');

    docs = auditDocs.precastBatch(batch, precastSink);

    await withChainLock(async (gen) => {
      // 整批都被预检拒：已就地记账并归档，链尾/WAL/缓冲都不必再碰（insertMany([]) 会抛
      // "Batch cannot be empty"，那会被读成一次莫须有的落库故障）
      if (docs.length === 0) return;
      const startPrevHash = await getChainTail(AuditLog);
      let pendingTail = null;
      let chained = false;
      try {
        pendingTail = chainBatch(docs, startPrevHash);
        chained = true;
      } catch (hashErr) {
        logger.warn(`审计日志哈希链计算失败，批次将无哈希落库：${hashErr.message}`);
      }

      try {
        await AuditLog.insertMany(docs, { ordered: false });
        if (chained) {
          // 落库确认成功后才推进链尾（消除幻影链尾）；Redis 模式下需 await 落共享缓存；
          // B-L4：传 gen 代际——持锁超时后僵尸 flush 的推进被跳过
          await advanceChainTail(pendingTail, gen);
        }
        // F-97：只按 __walSeq 裁掉本批确认落库的那些行。原先是 trimLines(docs.length)
        // ——「文件前 N 行」等价「本批 N 条」的前提在有空洞时不成立（WAL 未启用窗口
        // 入队的文档没有行、append 失败只告警、毒批从文件中间移走行），于是每次裁剪
        // 都会越界吃掉排在后面的**尚未落库**记录的行：那记录只剩内存副本，进程一崩
        // 就永久缺失，droppedCount 还不计。按序号匹配从结构上消灭"错位"。
        //
        // F-143：这里原先写着 `if (wal.isEnabled()) wal.trimBySeqs(...)`——用"能不能追加"
        // 的状态去门控"要不要回收"。关停链的 flushAndStop 在排空预算用尽时会 break 并
        // `stop()`（disable），而那一轮在途 insertMany 可能**随后仍然成功**：记录确认在库里，
        // 行却被永久留下。重放文档的 `_id` 是下一轮 flush 新分配的（WAL 行写于 push，
        // 那时还没有 `_id`），幂等性只覆盖同进程的引用存活，跨重启不成立 ⇒
        // **每重启一次就把这个已落库的批次再插一份**。裁剪本身与 enable 无关：
        // walTrimBySeqs 空集直接 return，removeWalLinesBySeqs 从不读 walEnabled。
        wal.trimBySeqs(auditDocs.walSeqsOf(docs));
        // 本批已确认在库：其内容级失败计次随对象一起作废
        for (const d of docs) flushStrikes.delete(d);
        outageFailures = 0;
        // 本批已确认在库：外层若曾因链锁超时把它们回退进缓冲（僵尸 fn 场景），
        // 此刻按 _id 精确撤回——否则下一轮还会插一遍（重复审计），而"每轮都比超时快不了"
        // 的持续慢盘下永远收敛不了。正常路径批次根本不在缓冲里，这里是 0 命中。
        retractDurable(new Set(docs.map((d) => String(d._id))));
        consecutiveFailures = 0; // 成功即重置毒文档计数
      } catch (insertErr) {
        // 剔除「已在库中」的子集，只回退未落库的部分：
        // 否则重试会对全部文档重新串链再插一份；且若批次里有一条永久非法的"毒文档"，
        // 其余文档将被无限重复插入直至磁盘耗尽，而重算出的双份记录各自成链，
        // 完整性校验脚本无法察觉（hash 是串链时写入的、两份相同的稳定键）。
        // 身份键用 _id 而不是 hash：hash 每轮 chainBatch 重算，只有 _id 跨轮稳定。
        const durable = auditDocs.collectDurableIds(insertErr, docs);
        if (durable.size === 0) throw insertErr;

        // 有子集已在库中 → 内存链尾与 DB 不再一致，标记失效由下一轮从 DB 重同步
        await resyncChainTail();
        // 超时回退可能已把本批重新排入缓冲；知道真相的此刻按 _id 撤回（见 retractDurable）
        const retracted = retractDurable(durable);
        const retryDocs = docs.filter((d) => !durable.has(String(d._id)));

        // F-97：已落库子集的行就地按序号回收。裁剪按序号而非条数之后，这一步不再是
        // "可选的账目美化"——留着它们就是往文件前缀里堆死行，而每一堆死行都是
        // 下一次裁剪的潜在错位来源（旧实现靠"下次按条数裁时顺带吃掉前缀"回收死行，
        // 那正是误删未落库行的机制本身）。
        const storedSeqs = auditDocs.walSeqsOf(docs.filter((d) => durable.has(String(d._id))));
        if (storedSeqs.size > 0) wal.trimBySeqs(storedSeqs);

        if (retryDocs.length === 0) {
          // 整批早已落库——此前链锁超时的「僵尸 insertMany」在本次重试前真正写入了。
          // 按幂等重放收尾：不报错、不回退、重置毒文档计数。
          //
          // 这里不再裁剪 WAL：僵尸那一轮的成功路径已按序号裁掉这批行
          // （序号集合完全相同，再裁是 0 命中的空操作）。F-143 之后这句前提才真的
          // 恒成立——原先若僵尸轮跑在 `stop()` 之后，它那一轮的裁剪被 enable 闸门跳过，
          // 这里"不再裁剪"就等于把已落库的行永久留在文件里。
          consecutiveFailures = 0;
          logger.warn(
            `审计批次 ${docs.length} 条已全部存在于库中（上一轮超时后的延迟落库），` +
              `按幂等重放处理：不重试、不裁剪 WAL${retracted ? `，另从缓冲撤回 ${retracted} 条` : ''}`
          );
          return;
        }

        insertErr.__retryDocs = retryDocs;
        throw insertErr;
      }
    });
  } catch (err) {
    consecutiveFailures += 1;
    // 审计落库失败不影响业务主流程，仅记录告警（与原单条写入策略一致）
    logger.warn(
      `审计日志批量落库失败（${docs.length} 条，连续第 ${consecutiveFailures} 次）：${err.message}`
    );

    const retryDocs = Array.isArray(err.__retryDocs) ? err.__retryDocs : docs;
    // 计次与「该丢哪些」抽成纯函数：本 catch 已经背了幂等重放 / 僵尸回退 /
    // 部分成功三套逻辑，再叠判据就会突破 eslint complexity 棘轮（实测 0→1 warn）。
    if (isContentAttributableFailure(err)) {
      const { doomed, kept } = settleContentFaultStrikes(retryDocs);
      if (doomed.length > 0) {
        noteDropped(doomed.length, 'poison_doc');
        // P1-24：丢弃批次的内存副本后，同步把其 WAL 行归档移出主文件，
        // 否则每次重启都重放同一批毒文档、再走满 5 次失败、再丢一次。
        // 按 __walSeq 精确匹配（不按行序），不误伤同文件中其他待落库的行。
        const discardSeqs = new Set(doomed.map((d) => d && d.__walSeq).filter(Boolean));
        // F-143 同族第三处：这里也曾用 `wal.isEnabled() &&` 门控。下面的 error 日志
        // （doomedBatchMessage）按 `discardSeqs.size > 0` 分支，会照着"已归档…并从主 WAL
        // 移除"说话——闸门为假时那句话是假的，而 `.discarded` 正是"审计永久缺失了多少"的
        // 唯一凭据：内存副本已丢、行却没归档 ⇒ 谎报 + 每次重启重放同一批毒文档。
        if (discardSeqs.size > 0) wal.discardBySeqs(discardSeqs);
        logger.error(doomedBatchMessage(doomed, kept, discardSeqs, err));
        consecutiveFailures = 0;
        // 同批无辜文档回到缓冲，别跟着毒文档一起消失
        if (kept.length > 0) {
          unshiftChunked(kept);
          enforceBufferLimit();
        }
        return;
      }
    } else {
      // 不可归因于内容 ⇒ 基础设施或未知原因：**一律不丢弃**，只告警。
      outageFailures += 1;
      if (outageFailures === 1 || outageFailures % MAX_BATCH_RETRY === 0) {
        logger.error(outageMessage(err));
      }
    }

    // 文档回到缓冲重试（at-least-once；WAL 仍保留这些行，重试成功后再裁剪）。
    // 部分成功场景只回退未落库的子集（__retryDocs），防止毒文档引发无限重复插入；
    // 已入库子集的行在上面按序号就地回收（F-97，旧实现留成永久残留）。
    // 分块回退：数十万级 spread 会触发 V8 参数上限 RangeError
    unshiftChunked(retryDocs);
    enforceBufferLimit();
  } finally {
    flushing = false;
    // 在途状态结束：批次已落库 / 已回退缓冲 / 已归档丢弃。与 `flushing` 同处置位，
    // 二者必须一起归零——否则残留计数会在下一次"仍在途"的判断里说谎。
    inFlightCount = 0;
  }
}

/**
 * 压入一条审计记录；缓冲满额立即触发异步落库
 * @param {object} doc AuditLog 文档
 */
function push(doc) {
  // P1-24：分配 WAL 序号（已有则复用——重放/回退重试的文档必须保留原序号，
  // 否则「毒批丢弃后按序号移除对应 WAL 行」匹配不上）。序号分配逻辑在 wal 模块。
  wal.assignSeq(doc);
  buffer.push(doc);
  // 行必须以 \n 结尾：readWalLines/walTrimLines/enforceWalLimit 均按行解析，
  // 缺行终止符会让多次 push 连成单个巨型"行"，崩溃重放 JSON.parse 失败、
  // 按行裁剪/超限丢弃全部退化（R-6 实施时由测试暴露的既有缺陷，一并修复）
  wal.appendLine(JSON.stringify(doc) + '\n');
  // 容量保护：DB 长时间不可用时缓冲会无界增长（P2-21）
  enforceBufferLimit();
  if (buffer.length >= BUFFER_LIMIT) {
    flush().catch((err) => logger.warn(`审计日志落库触发异常：${err.message}`));
  }
}

/**
 * 启动定时落库；并重放 WAL 残留
 *
 * 修复启动竞态：原先 walEnabled 要等异步重放完成才置 true，窗口期内
 * 健康探测/极早请求会入缓冲但不写 WAL 行——之后 flush 按文档数裁剪时
 * 行数不足，触发「行数(n)少于待裁剪(m)」告警（数据无损失，纯账目漂移）。
 * 现改为 start() 内同步开启 WAL，保证开启后的任何 push 必有对应行。
 *
 * 重放串行化进 walChain：读取时不会有并发追加插队；重放文档对应的旧行
 * 不在此处裁剪，留给其后续 flush 按 `__walSeq` 精确消费，避免双重记账
 * （F-97：重放时顺手给缺序号的旧行补号，否则那些行永远裁不掉、每次重启重复插一份）。
 */
function start() {
  if (flushTimer) return;
  // 路径重读（T-1/auditBufferGap 抖动修复）+ L-28 按库名派生：均落在 wal.startup 内。
  wal.startup(process.env.AUDIT_WAL_PATH);

  wal.serialize(
    async () => {
      const lines = await wal.readLines();
      if (!lines.length) return;
      // P1-24：先按毒批归档过滤——上一次运行判定丢弃、但归档改写未完成的
      // 行（崩溃窗口）在此被跳过，避免重启后重复处理毒批。
      const discarded = await wal.readDiscardedSeqs();
      let skippedDiscarded = 0;
      let replayed = 0;
      // F-97：顺手给缺 `__walSeq` 的旧行补上序号并回写文件。裁剪按序号匹配之后，
      // 认不出序号的行裁不掉；而这些行若一直留在文件里，每次重启都会被重放进缓冲，
      // 且重放文档的 _id 是 flush 时才分配的新值 ⇒ 每重启一次就重复插入一份审计。
      await wal.stampReplaySeqs(lines, (doc) => {
        if (doc.__walSeq && discarded.has(doc.__walSeq)) {
          skippedDiscarded += 1;
          return;
        }
        buffer.push(doc);
        replayed += 1;
      });
      if (skippedDiscarded > 0) {
        logger.warn(
          `审计 WAL 重放跳过 ${skippedDiscarded} 条已判定丢弃的毒批行（归档见 ${wal.getWalPath()}.discarded）`
        );
      }
      logger.info(`审计 WAL 重放 ${replayed} 条遗留记录`);
      // 重放同样受硬上限约束：崩溃前积压的 WAL 可能远超内存承载（P2-21）
      enforceBufferLimit();
    },
    (e) => logger.warn(`审计 WAL 启动重放失败：${e.message}`)
  );

  flushTimer = setInterval(() => {
    flush().catch((err) => logger.warn(`审计日志定时落库异常：${err.message}`));
  }, FLUSH_INTERVAL_MS);
  // 不阻塞 Node 进程退出（测试环境尤其需要）
  if (flushTimer && flushTimer.unref) flushTimer.unref();
}

/**
 * 停止定时器（优雅关闭时先 stop 再 flush，确保缓冲清空）
 */
function stop() {
  wal.disable();
  if (flushTimer) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
}

/**
 * 等待在途的那一轮 flush 结束（有上限）。
 * `flushing` 是模块内标志，没有 promise 可 await —— 僵尸 flush（链锁超时后仍在跑的
 * 那一轮）也不会暴露句柄，所以只能轮询。上限由调用方给（这里=排空预算的剩余时间），
 * 本函数不自拟超时，避免"关停到底能等多久"出现两把尺子。
 * @param {number} budgetMs 最多等待的毫秒数
 */
async function waitForFlushIdle(budgetMs) {
  const until = Date.now() + budgetMs;
  while (flushing && Date.now() < until) {
    await new Promise((resolve) => setTimeout(resolve, 20).unref?.());
  }
}

/**
 * 收尾排空（B-L2 + F-101，优雅关闭专用）：把缓冲真正刷干净 → 等 walChain 落盘 → 停用。
 *
 * B-L2 那一半：此前 gracefulShutdown 是「await flush(); stop()」，不等 walChain 上的
 * 裁剪完成，500ms 强制退出可截断原子替换的 rename ⇒ 已落库批次的 WAL 行残留文件，
 * 重启重放把整批审计跨重启重复插入。所以这里必须 `await wal.drain()` 再 stop。
 *
 * F-101 修的是另一半：`flush()` 的第一行是 `if (flushing || buffer.length === 0) return;`。
 * 关闭时**恰好有一轮定时 flush 在途**（2s 一轮，概率不低）时，`await flush()` 立即 resolve，
 * 什么都没做；接着 drain 与 stop 照常走完，调用方据此报「审计日志缓冲已清空」——
 * 而缓冲里其实还压着记录。谎报的代价不是日志难看：运维以为已安全落库、容器随后强退，
 * 那条"已清空"就成了审计缺失的直接证据（也是这条链上最后一种"指标说谎"）。
 *
 * 现在按**缓冲是否真的空了**循环收敛，并有硬上限（关停不能无限等）；
 * 返回 `drained` / `residual`，由调用方如实记录，不再无条件说"已清空"。
 * @param {number} [hardCeilingMs] 调用方总预算给出的**外部**上限（F-103）。
 *   本模块自己的 `AUDIT_FLUSH_DRAIN_BUDGET_MS` 是"我愿意为排空等多久"，
 *   这个参数是"关停链只剩下这么多时间"——取两者较小值，缺省不限制。
 * @returns {Promise<{drained:boolean, residual:number}>}
 */
async function flushAndStop(hardCeilingMs = Infinity) {
  const deadline = Date.now() + Math.min(FLUSH_DRAIN_BUDGET_MS, hardCeilingMs);
  for (;;) {
    // 先等在途的那一轮结束，**再**看缓冲空不空：在途批次此刻不在缓冲里，
    // 但它一旦失败就会整批 unshift 回来（F-96 之后失败批次不会凭空消失）。
    // 只看 buffer.length 会把"正有一批在外面跑"误判成"已排空"——那还是同一句谎话。
    if (flushing) {
      await waitForFlushIdle(Math.max(10, deadline - Date.now()));
      if (Date.now() >= deadline && flushing) break; // 等到超时仍在途：如实报未排空
      continue;
    }
    if (buffer.length === 0) break;
    if (Date.now() >= deadline) break;
    await flush().catch((e) => logger.warn(`收尾 flush 失败：${e.message}`));
  }
  // 在途批次此刻既不在缓冲也未落库，只能由 `inFlightCount` 记账（用例 ④ 钉这条）：
  // 漏了它，"关停时正有一批跑不出去"就会被算成 residual 0 ⇒ 又变成"已排空"那句谎话。
  const residual = buffer.length + (flushing ? inFlightCount : 0);
  await wal.drain(); // 等追加/裁剪链排空（rename 落盘）
  stop();
  return { drained: residual === 0, residual };
}

/**
 * WAL 是否启用（合规仪表盘指标）
 */
function isWalEnabled() {
  return wal.isEnabled();
}

/** 当前 WAL 文件路径（导出供测试断言与运维核对）；路径状态由 wal 模块持有 */
function getWalPath() {
  return wal.getWalPath();
}

/**
 * 缓冲运行指标（P2-21）
 * droppedCount 必须可观测：静默丢弃审计数据在合规上等同于篡改。
 */
function getStats() {
  return {
    bufferLength: buffer.length,
    hardLimit: BUFFER_HARD_LIMIT,
    droppedCount,
    consecutiveFailures,
    outageFailures,
    ...wal.getStats(),
  };
}

/** 仅供测试重置内部状态（生产不调用） */
function __resetForTest() {
  buffer.length = 0;
  droppedCount = 0;
  consecutiveFailures = 0;
  // 不重置 inFlightCount：它与 `flushing` 同生死（flush 的 finally 一起归零），
  // 而本函数连 flushing 都不重置——单独清零只会让两者口径不一致。
  wal.resetCounters();
}

/**
 * 仅供测试：等待在途的那一轮 flush 结束（轮询 `flushing`，带毫秒上限）。生产不调用。
 *
 * 为什么测试需要它：`flushing` 是**模块级**标志，而 fire-and-forget 的 flush
 * （push 满额触发、定时器触发）会**跨用例**存活。用例里拿固定 `setTimeout` 当同步
 * 原语是在赌时间——CI 的 CPU 争用下，一次上万条批次的 flush 能跑数百毫秒，于是下一条
 * 用例的显式 `flush()` 被 `if (flushing || buffer.length === 0) return` 直接早退，
 * 断言看到的是"还没处理完"的中间态。
 *
 * CI 实测（run #74，seed 777001）就是这一格：
 *   ✓ 缓冲不超过硬上限…            (169 ms)  ← 推 10300 条并触发一轮 fire-and-forget flush
 *   ✓ 失败后文档回到缓冲重试        (1 ms)   ← 1ms 就"通过"，正是早退的证据
 *   ✕ 同一条文档累计内容级失败达阈值 (133 ms)  ← 5 次 flush 少计一次 ⇒ 停在 4 < MAX_BATCH_RETRY(5)
 *
 * 返回后可以保证：那一轮的批次**已经结算完**（已落库 / 已丢弃 / 已回退进缓冲）——
 * `flush()` 的 finally（置 `flushing=false`）排在 catch 的 `unshiftChunked` 之后。
 * 它**不**保证缓冲为空；要清空请照旧调 `__resetForTest`。
 */
const __waitForFlushIdle = (budgetMs = 5000) => waitForFlushIdle(budgetMs);

module.exports = {
  push,
  flush,
  flushAndStop,
  start,
  stop,
  isWalEnabled,
  getStats,
  getWalPath,
  __resetForTest,
  __waitForFlushIdle,
};
