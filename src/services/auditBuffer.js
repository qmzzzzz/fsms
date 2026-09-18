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
 * 对外行为与拆分前一致：push 时同步追加 WAL 行，flush 落库成功后按本次落库条数前缀裁剪，
 * 崩溃后 start() 重放 WAL 残留（先按毒批归档序号过滤，P1-24）。
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const wal = require('./auditBufferWal');

// 缓冲上限：达到即触发一次批量落库
const BUFFER_LIMIT = 100;
// 定时落库间隔（毫秒）
const FLUSH_INTERVAL_MS = 2000;

// ================= 容量与重试保护（P2-21） =================
// 缓冲硬上限：Mongo 中断期间每 2s flush 失败整批回退，高流量下缓冲无界增长会 OOM。
// 达到上限后丢弃最旧记录（WAL 里仍有对应行，崩溃后可重放；比整进程 OOM 可接受）。
const BUFFER_HARD_LIMIT = Number(process.env.AUDIT_BUFFER_HARD_LIMIT) || 10000;
// 单次回退到缓冲头部的最大条数：`buffer.unshift(...docs)` 在数十万级会触发
// V8 参数展开上限（RangeError: Maximum call stack size exceeded），整批永久丢失。
// 超过此数量改用分块 unshift。
const UNSHIFT_CHUNK_SIZE = 1000;
// 毒文档隔离阈值：同一批次连续失败达到此次数即丢弃并告警，
// 防止一条永久非法的文档让整批无限滞留重试（原实现只防了「重复插入」，没防「无限重试」）。
const MAX_BATCH_RETRY = 5;

const buffer = [];
let flushTimer = null;
let flushing = false;
// 累计因容量上限被丢弃的条数（供合规仪表盘暴露，不能静默丢数据）
let droppedCount = 0;
// 连续 flush 失败次数（毒文档隔离计数器）
let consecutiveFailures = 0;

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
  droppedCount += overflow;
  logger.error(
    `审计缓冲超过硬上限 ${BUFFER_HARD_LIMIT}，已丢弃最旧 ${overflow} 条（累计 ${droppedCount} 条）。` +
      '数据库可能长时间不可用，请立即排查；这些记录的 WAL 行仍在磁盘上'
  );
  return overflow;
}

/**
 * 批量落库：取走当前缓冲并 insertMany；进行中不重入，新日志继续进缓冲
 *
 * 哈希链在锁内完成「读尾→串链→落库→推进尾」全流程：
 * - 仅在 insertMany 确认成功后 advanceChainTail，杜绝 insert 失败重试时
 *   prevHash 指向从未入库记录的「幻影链尾」断链；
 * - 部分成功（ordered:false）时 DB 中已存在真实记录但与内存尾不一致，
 *   标记链尾失效、下次从 DB 重同步自愈；
 * - 哈希计算为 best-effort：失败时文档以无 hash 落库（verify 时计为 legacy），不阻塞落库。
 * 落库失败则文档回到缓冲重试（at-least-once；WAL 行保留至成功后再裁剪）。
 */
async function flush() {
  if (flushing || buffer.length === 0) return;
  flushing = true;
  const docs = buffer.splice(0, buffer.length);
  try {
    const {
      chainBatch,
      withChainLock,
      getChainTail,
      advanceChainTail,
      resyncChainTail,
    } = require('../utils/auditChain');

    await withChainLock(async (gen) => {
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
        // 落库确认成功后才推进链尾（消除幻影链尾）；Redis 模式下需 await 落共享缓存；
        // B-L4：传 gen 代际——持锁超时后僵尸 flush 的推进被跳过
        if (chained) await advanceChainTail(pendingTail, gen);
        if (wal.isEnabled()) wal.trimLines(docs.length);
        consecutiveFailures = 0; // 成功即重置毒文档计数
      } catch (insertErr) {
        const insertedDocs = Array.isArray(insertErr.insertedDocs) ? insertErr.insertedDocs : [];
        if (insertedDocs.length > 0) {
          // 部分成功：标记「应重试子集」到错误对象，由外层统一回缓冲。
          // 必须按 hash 剔除已插入子集——否则重试会对全部文档重新串链再插一份；
          // 若批次中存在一条永久非法的"毒文档"，其余文档将被无限重复插入直至磁盘耗尽，
          // 且重算后的双份记录各自成链，完整性校验脚本无法察觉（hash 是串链时写入的稳定键）。
          const insertedHashes = new Set(insertedDocs.map((d) => d.hash).filter(Boolean));
          insertErr.__retryDocs = docs.filter((d) => !insertedHashes.has(d.hash));
          await resyncChainTail();
        }
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

    // 毒文档隔离（P2-21）：原实现只防了「重复插入」，没防「无限滞留重试」——
    // 一条永久非法的文档（如 category 不在枚举内）会让整批每 2s 重试一次，永不收敛。
    // 连续失败达阈值即丢弃本批并告警，让后续正常记录得以落库。
    if (consecutiveFailures >= MAX_BATCH_RETRY) {
      droppedCount += retryDocs.length;
      // P1-24：丢弃批次的内存副本后，同步把其 WAL 行归档移出主文件。
      // 此前 WAL 行原样保留 → 每次重启 start() 重放同一批毒文档，
      // 再走满 5 次失败、再丢一次，且这几行永远消费不掉。
      // 按 __walSeq 精确匹配（不按行序），不会误伤同文件中其他待落库的行。
      const discardSeqs = new Set(retryDocs.map((d) => d && d.__walSeq).filter(Boolean));
      if (wal.isEnabled() && discardSeqs.size > 0) wal.discardBySeqs(discardSeqs);
      logger.error(
        `审计批次连续失败 ${consecutiveFailures} 次，判定为毒文档批并丢弃 ${retryDocs.length} 条` +
          `（累计丢弃 ${droppedCount} 条）。最后一次错误：${err.message}。` +
          (discardSeqs.size > 0
            ? `已归档 ${discardSeqs.size} 行 WAL 取证行到 ${wal.getWalPath()}.discarded 并从主 WAL 移除（重启重放不再重复处理）`
            : `WAL 行仍保留在 ${wal.getWalPath()}，可人工取证`)
      );
      consecutiveFailures = 0;
      return;
    }

    // 文档回到缓冲重试（at-least-once；WAL 仍保留这些行，重试成功后再裁剪）。
    // 部分成功场景只回退未落库的子集（__retryDocs），防止毒文档引发无限重复插入；
    // 已入库子集的 WAL 行成为残留量（罕见路径，at-least-once 容忍范围内）。
    // 分块回退：数十万级 spread 会触发 V8 参数上限 RangeError
    unshiftChunked(retryDocs);
    enforceBufferLimit();
  } finally {
    flushing = false;
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
 * 不在此处裁剪，留给其后续 flush 按条数自然消费，避免双重记账。
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
      for (const line of lines) {
        try {
          const doc = JSON.parse(line);
          if (doc && doc.__walSeq && discarded.has(doc.__walSeq)) {
            skippedDiscarded += 1;
            continue;
          }
          buffer.push(doc);
        } catch {
          // 损坏行跳过，不阻塞启动；该行残留文件中，会被后续裁剪按占位消化
        }
      }
      if (skippedDiscarded > 0) {
        logger.warn(
          `审计 WAL 重放跳过 ${skippedDiscarded} 条已判定丢弃的毒批行（归档见 ${wal.getWalPath()}.discarded）`
        );
      }
      logger.info(`审计 WAL 重放 ${lines.length - skippedDiscarded} 条遗留记录`);
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
 * 收尾排空（B-L2，优雅关闭专用）：flush → 等待 walChain（裁剪/追加）排空 → stop。
 *
 * 此前 gracefulShutdown 的「await flush(); stop()」不等 walChain 上的裁剪完成，
 * 500ms 强制退出可截断原子替换的 rename——已落库批次的 WAL 行残留文件，
 * 重启重放把整批审计跨重启重复插入；in-flight 定时 flush 跳过裁剪同理。
 * 本函数保证：flush 落库 → 裁剪 rename 完成 → 才停用。
 */
async function flushAndStop() {
  await flush().catch((e) => logger.warn(`收尾 flush 失败：${e.message}`));
  await wal.drain(); // 等追加/裁剪链排空（rename 落盘）
  stop();
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
    ...wal.getStats(),
  };
}

/** 仅供测试重置内部状态（生产不调用） */
function __resetForTest() {
  buffer.length = 0;
  droppedCount = 0;
  consecutiveFailures = 0;
  wal.resetCounters();
}

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
};
