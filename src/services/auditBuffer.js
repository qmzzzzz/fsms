/**
 * 审计日志缓冲批量写入模块
 * 仅用于 HTTP 全局审计中间件的高频请求型日志：内存缓冲 + 定时/满额批量 insertMany，
 * 降低高频写操作下"每请求一次 DB 写"的入库压力。
 *
 * 注意：事件型审计（AuditLog.record：登录成败、暴力破解告警、锁定/解锁等）不经过本模块，
 * 保持直写——暴力破解检测（checkBruteForce）依赖 login_failed 的即时可查性。
 *
 * 【WAL 兜底（G4 不丢失）】push 时同步追加一行到本地 WAL 文件，flush 落库成功后
 * 按本次落库条数做「前缀裁剪」（读文件→丢弃前 N 行→临时文件原子替换回原名），
 * 只移除已持久化的行——不得整文件截断，否则 flush 间隙新追加的行会被误删，
 * 崩溃后这些"已写 WAL"的记录彻底丢失。进程崩溃后 start() 重放 WAL 残留。
 * 所有 WAL 文件操作串行化在 walChain 上，避免并发读写竞争。
 * walEnabled 门控：仅 start() 后开启，测试不调 start 故无 WAL 副作用，行为与改造前一致。
 * 属 best-effort：未对每条记录 fsync，崩溃仍可能丢 OS 页缓存中最后几条（远优于丢失整批≤100条/2s）。
 */

const fs = require('fs');
const path = require('path');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

// 缓冲上限：达到即触发一次批量落库
const BUFFER_LIMIT = 100;
// 定时落库间隔（毫秒）
const FLUSH_INTERVAL_MS = 2000;
// WAL 文件路径（可配），存放尚未确认落库的审计文档（每行一条 JSON）
const WAL_PATH = process.env.AUDIT_WAL_PATH || path.join(__dirname, '../../logs/audit-buffer.wal');

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
// WAL 硬上限（字节）：DB 长时间不可用且高流量时 WAL 持续增长（磁盘写放大，报告 R-6）。
// 超限丢弃最旧一半行（与 BUFFER_HARD_LIMIT 丢最旧同向的止损策略）并告警。
// 被丢弃行的文档若仍在缓冲中会照常落库，其后的 walTrimLines 按实际行数收敛（已有告警口径）；
// 对应文档已被 BUFFER_HARD_LIMIT 丢弃的行，本就是纯取证残留。
// 运行期读 env 便于测试注入小阈值；默认 50MB。
const getWalMaxBytes = () => Number(process.env.AUDIT_WAL_MAX_BYTES) || 50 * 1024 * 1024;

const buffer = [];
let flushTimer = null;
let flushing = false;
let walEnabled = false;
// 串行化所有 WAL 文件操作（追加 / 裁剪 / 重放），杜绝并发读写竞争导致丢行
let walChain = Promise.resolve();
// 累计因容量上限被丢弃的条数（供合规仪表盘暴露，不能静默丢数据）
let droppedCount = 0;
// 连续 flush 失败次数（毒文档隔离计数器）
let consecutiveFailures = 0;
// 累计因 WAL 超限被丢弃的行数（可观测，静默丢取证数据在合规上不可接受）
let walDroppedLines = 0;

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

function ensureLogsDir() {
  const dir = path.dirname(WAL_PATH);
  if (!fs.existsSync(dir)) {
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch {
      /* logger 已确保 logs 存在，忽略 */
    }
  }
}

/**
 * 追加一行到 WAL（非阻塞，串行化在 walChain 上）
 */
function walAppendLine(line) {
  walChain = walChain
    .then(() => fs.promises.appendFile(WAL_PATH, line, 'utf8'))
    .then(() => enforceWalLimit())
    .catch((e) => logger.warn(`审计 WAL 追加失败：${e.message}`));
}

/**
 * WAL 大小硬上限保护（R-6）：超过 getWalMaxBytes() 丢弃最旧一半行并告警。
 * 串行化在 walChain 上（与追加/裁剪互斥）；只保留较新一半——
 * 较新行对应的文档大概率仍在缓冲中等待落库，优先保住可落库数据的账目完整。
 */
async function enforceWalLimit() {
  let stat;
  try {
    stat = await fs.promises.stat(WAL_PATH);
  } catch (e) {
    if (e.code !== 'ENOENT') logger.warn(`审计 WAL 大小检查失败：${e.message}`);
    return;
  }
  const maxBytes = getWalMaxBytes();
  if (stat.size <= maxBytes) return;

  const content = await fs.promises.readFile(WAL_PATH, 'utf8');
  const parts = content.split('\n');
  const hasTrailingNewline = parts[parts.length - 1] === '';
  const records = hasTrailingNewline ? parts.slice(0, -1) : parts;
  if (records.length < 2) return; // 单行超限无「一半」可弃，留给外部取证处理

  const keepFrom = Math.floor(records.length / 2);
  const dropped = keepFrom;
  const nextContent = `${records.slice(keepFrom).join('\n')}\n`;

  const tmpPath = `${WAL_PATH}.tmp`;
  await fs.promises.writeFile(tmpPath, nextContent, 'utf8');
  await fs.promises.rename(tmpPath, WAL_PATH);

  walDroppedLines += dropped;
  logger.error(
    `审计 WAL 超过硬上限（${stat.size} > ${maxBytes} 字节），已丢弃最旧 ${dropped} 行（累计 ${walDroppedLines} 行）。` +
      '数据库可能长时间不可用，请立即排查'
  );
}

/**
 * 移除 WAL 前 n 行（已确认落库的文档）。前缀裁剪而非整文件截断：
 * flush 成功与裁剪之间 push() 仍会向文件尾部追加新行，整文件截断会把
 * 这些尚未落库的行一并抹掉，崩溃后造成已写 WAL 记录丢失。串行化在 walChain 上，
 * 且裁剪排在既有 append 之后执行，保证被裁掉的行数内不含未落库数据。
 */
function walTrimLines(n) {
  walChain = walChain
    .then(async () => {
      let content;
      try {
        content = await fs.promises.readFile(WAL_PATH, 'utf8');
      } catch (e) {
        if (e.code !== 'ENOENT') logger.warn(`审计 WAL 读取失败：${e.message}`);
        return;
      }
      if (!content) return;

      const parts = content.split('\n');
      const hasTrailingNewline = parts[parts.length - 1] === '';
      const records = hasTrailingNewline ? parts.slice(0, -1) : parts;
      if (records.length === 0) return;

      if (records.length < n) {
        // 行数少于待裁剪数：按实际行数清理（WAL 可能被外部干预过），不静默
        logger.warn(`审计 WAL 行数(${records.length})少于待裁剪行数(${n})，按实际行数清理`);
      }
      const rest = records.slice(Math.min(n, records.length));
      const nextContent = rest.length ? `${rest.join('\n')}\n` : '';
      if (nextContent === content) return;

      // 临时文件 + 原子替换，避免写一半崩溃留下残缺 WAL
      const tmpPath = `${WAL_PATH}.tmp`;
      await fs.promises.writeFile(tmpPath, nextContent, 'utf8');
      await fs.promises.rename(tmpPath, WAL_PATH);
    })
    .catch((e) => logger.warn(`审计 WAL 裁剪失败：${e.message}`));
}

/**
 * 读取 WAL 全部物理行（供启动重放使用）。文件不存在视为空。
 */
async function readWalLines() {
  try {
    const content = await fs.promises.readFile(WAL_PATH, 'utf8');
    return content.split('\n').filter(Boolean);
  } catch (e) {
    if (e.code !== 'ENOENT') logger.warn(`审计 WAL 读取失败：${e.message}`);
    return [];
  }
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

    await withChainLock(async () => {
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
        // 落库确认成功后才推进链尾（消除幻影链尾）；Redis 模式下需 await 落共享缓存
        if (chained) await advanceChainTail(pendingTail);
        if (walEnabled) walTrimLines(docs.length);
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
      logger.error(
        `审计批次连续失败 ${consecutiveFailures} 次，判定为毒文档批并丢弃 ${retryDocs.length} 条` +
          `（累计丢弃 ${droppedCount} 条）。最后一次错误：${err.message}。` +
          `WAL 行仍保留在 ${WAL_PATH}，可人工取证`
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
  buffer.push(doc);
  // 行必须以 \n 结尾：readWalLines/walTrimLines/enforceWalLimit 均按行解析，
  // 缺行终止符会让多次 push 连成单个巨型"行"，崩溃重放 JSON.parse 失败、
  // 按行裁剪/超限丢弃全部退化（R-6 实施时由测试暴露的既有缺陷，一并修复）
  if (walEnabled) walAppendLine(JSON.stringify(doc) + '\n');
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
  ensureLogsDir();
  walEnabled = true;

  walChain = walChain
    .then(async () => {
      const lines = await readWalLines();
      if (!lines.length) return;
      for (const line of lines) {
        try {
          buffer.push(JSON.parse(line));
        } catch {
          // 损坏行跳过，不阻塞启动；该行残留文件中，会被后续裁剪按占位消化
        }
      }
      logger.info(`审计 WAL 重放 ${lines.length} 条遗留记录`);
      // 重放同样受硬上限约束：崩溃前积压的 WAL 可能远超内存承载（P2-21）
      enforceBufferLimit();
    })
    .catch((e) => logger.warn(`审计 WAL 启动重放失败：${e.message}`));

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
  walEnabled = false;
  if (flushTimer) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
}

/**
 * WAL 是否启用（合规仪表盘指标）
 */
function isWalEnabled() {
  return walEnabled;
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
    walEnabled,
    walDroppedLines,
  };
}

/** 仅供测试重置内部状态（生产不调用） */
function __resetForTest() {
  buffer.length = 0;
  droppedCount = 0;
  consecutiveFailures = 0;
  walDroppedLines = 0;
}

module.exports = {
  push,
  flush,
  start,
  stop,
  isWalEnabled,
  getStats,
  __resetForTest,
};
