/**
 * 审计缓冲的 WAL 文件层（自 services/auditBuffer.js 拆出，O-3 体积棘轮 / P1-24）
 *
 * 职责边界：本模块负责 WAL 文件的一切——路径派生、按行追加、前缀裁剪、大小上限、
 * 毒批序号与归档，以及把上述操作串行化的 walChain；内存缓冲、批量落库（flush）
 * 与进程生命周期仍在 services/auditBuffer.js。拆出原因：auditBuffer.js 在 P1-24
 * 修复后超过 eslint max-lines 上限（300 行，已计 skipBlankLines/skipComments），
 * 而 eslint.ratchet.json 对其无基线（只许 0 条 warn），故按职责拆分而非放宽基线。
 * 对外行为不变：auditBuffer 的公开 API 与拆分前一致。
 *
 * 【WAL 兜底（G4 不丢失）】push 时同步追加一行到本地 WAL 文件，flush 落库成功后
 * 按本次落库条数做「前缀裁剪」（读文件→丢弃前 N 行→临时文件原子替换回原名），
 * 只移除已持久化的行——不得整文件截断，否则 flush 间隙新追加的行会被误删，
 * 崩溃后这些"已写 WAL"的记录彻底丢失。进程崩溃后 auditBuffer.start() 重放 WAL 残留。
 * 所有 WAL 文件操作串行化在 walChain 上，避免并发读写竞争。
 * walEnabled 门控：仅 startup() 后开启，测试不调 start 故无 WAL 副作用，行为与改造前一致。
 * 属 best-effort：未对每条记录 fsync，崩溃仍可能丢 OS 页缓存中最后几条（远优于丢失整批≤100条/2s）。
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

// WAL 文件路径（可配），存放尚未确认落库的审计文档（每行一条 JSON）。
//
// 路径解析时机（T-1/auditBufferGap 抖动修复）：历史上是模块加载期 const——
// Jest 并行 worker 里先 require 本模块的测试文件会锁死路径，后设
// AUDIT_WAL_PATH 的套件被静默忽略，指向已清理目录或共享默认文件，
// 造成跨套件 WAL 串写与断言抖动。现改为 start() 时重读 env（与
// AUDIT_WAL_MAX_BYTES 的运行期读法同语义）：每次启动都可重指向，
// 生产环境一次启动一个路径不受影响；测试套件按 worker 独立 mkdtemp。
/**
 * 默认 WAL 路径：**按目标库名派生**，避免多进程共享同一份 WAL。
 *
 * L-28 修复（2026-09-16）：原默认值为固定的 `logs/audit-buffer.wal`，
 * 只要两个进程 cwd 相同（典型场景：同一台机上跑 dev 实例 + 脚本 + 测试),
 * 就会往同一个文件里追加各自的行。后果不是「互相覆盖」而是更隐蔽的
 * **交叉重放**：A 进程崩溃后重启，会把 B 进程尚未落库的行也读进自己的
 * 缓冲并落库——而 B 进程仍在运行、稍后也会落库同一批 → 审计记录**重复插入**，
 * 哈希链随之出现分叉，verify-audit-chain 报 chain_break。
 *
 * 派生规则（三层，后者覆盖前者）：
 *   1. 显式 AUDIT_WAL_PATH → 完全按运维指定（最高优先级，保持向后兼容）
 *   2. 有 MONGODB_URI → logs/audit-buffer.<dbName>.wal（各库各一份，天然隔离）
 *   3. 都没有 → logs/audit-buffer.wal（历史默认值，单实例场景行为不变）
 *
 * 为什么用库名而不是 pid：WAL 的唯一用途是**跨重启**崩溃恢复，
 * pid 命名的文件在进程死掉后就再也无人认领，等于放弃了 WAL 的全部价值。
 * 库名是「同一份审计数据」的天然标识，重启前后保持不变。
 */
function deriveDefaultWalPath() {
  const uri = process.env.MONGODB_URI;
  let dbName = '';
  if (uri) {
    try {
      // 取 URI path 段的库名：mongodb://host:port/<db>?opts
      // 不用 URL 解析：mongodb:// 不是标准 scheme，URL 会误判 user:pass 部分
      const m = String(uri).match(/^[a-z+]+:\/\/[^/]*\/([^?/]+)/i);
      if (m && m[1]) dbName = dbNameToFileSegment(decodeURIComponent(m[1]));
    } catch {
      /* 解析失败回退到历史默认值，不因路径问题阻断启动 */
    }
  }
  const base = path.join(__dirname, '../../logs/audit-buffer');
  return dbName ? `${base}.${dbName}.wal` : `${base}.wal`;
}
/**
 * 库名 → 文件名安全片段（L-30）。
 *
 * 缺陷（本函数抽出的原因）：库名直接拼进文件名，而 URI 里的库名要经
 * decodeURIComponent 还原（`%2F` 就是 `/`）。于是 `mongodb://h/db%2F..%2Fevil`
 * 会让 WAL 落到 `logs/audit-buffer.db/../../evil.wal`——实测更深一级的
 * `db%2F..%2F..%2Fevil` 直接逃出 `logs/` 到仓库根。**文件名可被 URI 控制 =
 * 任意相对路径写**，攻击面不需要本地权限，只要有人能影响 MONGODB_URI。
 *
 * 编码选择：用 encodeURIComponent 做**单射**转义（`%` 仍保留、大小写敏感），
 * 而不是「非法字符一律替换成下划线」——后者不单射：`db/x` 与 `db_x`、
 * `a b` 与 `a_b` 都会映射到同一文件，等于把 L-28 刚消除的**交叉重放**
 * 又从另一条路引回来（两个不同的库共写一份 WAL）。宁可文件名难看，不可歧义。
 *
 * 对合法库名的行为：MongoDB 库名约束里不含 `/ \ : * ? " < > |` 等字符
 * （本文档不引用具体版本条款，只按「白名单字符恒等」这一可验证性质陈述），
 * 因此本函数对真实库名是**恒等变换**——`fire_safety_db` → `fire_safety_db`。
 * 唯一补一刀的是 `*`：encodeURIComponent 不转义它，而它在 NTFS 上是非法字符。
 *
 * @param {string} raw 已 decodeURIComponent 的库名
 * @returns {string} 可安全拼进文件名的片段；无法安全化时返回空串（回退默认路径）
 */
function dbNameToFileSegment(raw) {
  const name = String(raw);
  if (!name) return '';
  // '*' 是 encodeURIComponent 的保留字符（不转义）但为 Windows 非法文件名字符，
  // 单独补转义；其余非法字符（/ \ : ? " < > | 空格 控制符）它已全部转义
  const encoded = encodeURIComponent(name).replace(/\*/g, '%2A');
  // 兜底断言：转义后仍含路径分隔符或相对路径片段 → 拒绝，回退默认路径
  // （encodeURIComponent 的正确性不该被"信任"，这是 fail-closed 的第二道闸）
  if (encoded.includes('/') || encoded.includes('\\')) return '';
  if (encoded === '.' || encoded === '..') return '';
  return encoded;
}

let walPath = deriveDefaultWalPath();

// WAL 硬上限（字节）：DB 长时间不可用且高流量时 WAL 持续增长（磁盘写放大，报告 R-6）。
// 超限丢弃最旧一半行（与 BUFFER_HARD_LIMIT 丢最旧同向的止损策略）并告警。
// 被丢弃行的文档若仍在缓冲中会照常落库，其后的 walTrimLines 按实际行数收敛（已有告警口径）；
// 对应文档已被 BUFFER_HARD_LIMIT 丢弃的行，本就是纯取证残留。
// 运行期读 env 便于测试注入小阈值；默认 50MB。
const getWalMaxBytes = () => Number(process.env.AUDIT_WAL_MAX_BYTES) || 50 * 1024 * 1024;
// B-I1：每条 append 都 stat 是串行 walChain 的吞吐瓶颈——改为每 N 次追加
// 抽查一次大小（默认 32；N×单行 ≈ 数 KB 的滞后窗口，对 50MB 上限可忽略）。
// 0/负值按 1 处理（恢复逐条检查，供测试注入）。
const getWalStatInterval = () => Math.max(1, Number(process.env.AUDIT_WAL_STAT_INTERVAL) || 32);
let walAppendCount = 0;

let walEnabled = false;
// 串行化所有 WAL 文件操作（追加 / 裁剪 / 重放），杜绝并发读写竞争导致丢行
let walChain = Promise.resolve();
// 累计因 WAL 超限被丢弃的行数（可观测，静默丢取证数据在合规上不可接受）
let walDroppedLines = 0;
// ================= 毒文档批的 WAL 标记（P1-24） =================
// 背景：batch 连续失败达阈值被丢弃后，内存中已无该批文档，但其 WAL 行仍在。
// 重启时 start() 会把这些行重新读回缓冲，再次走满 5 次失败——每重启一次
// 重复处理一次毒批，且 WAL 里那几行永远消费不掉（行数恒多于待裁剪数）。
// 解法：push 时给文档（及其 WAL 行）分配一个**进程内唯一**的 WAL 序号；
// 毒批丢弃时按序号把对应行移出主 WAL，追加归档到 <walPath>.discarded
// （保留人工取证能力），使重启重放不再看到这些行。
//
// 序号为什么用「运行标识-自增」而不是裸自增：重放的行来自上一个进程，
// 其序号若与本次运行的自增撞号，丢弃匹配会误删同号的正常行。加运行标识后
// 跨进程不可能碰撞；同一进程内自增即唯一。已在文档上的序号不重分配
// （重放/重试路径复用原序号，否则会丢掉与 WAL 行的对应关系）。
//
// 文档上多出的 __walSeq 字段不进 DB：AuditLog schema 为 strict:true，
// insertMany 落库时静默剔除；也不进哈希 payload（payload 只取白名单字段）。
const WAL_RUN_ID =
  process.pid.toString(36) + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
let walSeqCounter = 0;
// 累计因毒批丢弃被归档移出主 WAL 的行数（P1-24，可观测）
let walDiscardedLines = 0;

function ensureLogsDir() {
  const dir = path.dirname(walPath);
  if (!fs.existsSync(dir)) {
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch {
      /* logger 已确保 logs 存在，忽略 */
    }
  }
}

/**
 * 当前 WAL 文件路径（导出供测试断言与运维核对）
 * auditBuffer.start() 每次经 startup() 重读 AUDIT_WAL_PATH，此处返回的恒为下一次写入将使用的路径
 */
function getWalPath() {
  return walPath;
}

/**
 * 读取 WAL 并切分为记录行数组（P1-24 抽出：enforceWalLimit / walTrimLines /
 * filterWalLinesBySeqs 三处共用，此前各自重复一遍「split + 尾换行判定」）。
 * 与 readWalLines 的差别：尾部无换行的残缺行**保留**为最后一条记录，
 * 按行重写时才不会把它丢掉。
 * @returns {Promise<{records: string[], content: string}|null>} 文件不存在返回 null
 */
async function readWalRecords() {
  let content;
  try {
    content = await fs.promises.readFile(walPath, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') logger.warn(`审计 WAL 读取失败：${e.message}`);
    return null;
  }
  if (!content) return { records: [], content: '' };
  const parts = content.split('\n');
  const hasTrailingNewline = parts[parts.length - 1] === '';
  return { records: hasTrailingNewline ? parts.slice(0, -1) : parts, content };
}

/** 临时文件 + 原子替换回主 WAL（P1-24 抽出，三处改写共用） */
async function atomicReplaceWal(nextContent) {
  const tmpPath = walPath + '.tmp';
  await fs.promises.writeFile(tmpPath, nextContent, 'utf8');
  await fs.promises.rename(tmpPath, walPath);
}

/** 解析一行的 __walSeq；损坏行或无数值行返回 null（不参与匹配，保持原样） */
function walSeqOf(line) {
  try {
    const d = JSON.parse(line);
    return d && d.__walSeq ? d.__walSeq : null;
  } catch {
    return null;
  }
}

/**
 * 追加一行到 WAL（非阻塞，串行化在 walChain 上）
 */
function walAppendLine(line) {
  walChain = walChain
    .then(() => fs.promises.appendFile(walPath, line, 'utf8'))
    .then(() => {
      // B-I1：stat 节流——每 N 次追加抽查一次大小（详见 getWalStatInterval 注释）
      walAppendCount += 1;
      if (walAppendCount % getWalStatInterval() === 0) return enforceWalLimit();
    })
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
    stat = await fs.promises.stat(walPath);
  } catch (e) {
    if (e.code !== 'ENOENT') logger.warn(`审计 WAL 大小检查失败：${e.message}`);
    return;
  }
  const maxBytes = getWalMaxBytes();
  if (stat.size <= maxBytes) return;

  const wal = await readWalRecords();
  if (!wal || wal.records.length < 2) return; // 单行超限无「一半」可弃，留给外部取证处理

  const keepFrom = Math.floor(wal.records.length / 2);
  const dropped = keepFrom;
  await atomicReplaceWal(`${wal.records.slice(keepFrom).join('\n')}\n`);

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
      const wal = await readWalRecords();
      if (!wal || wal.records.length === 0) return;

      if (wal.records.length < n) {
        // 行数少于待裁剪数：按实际行数清理（WAL 可能被外部干预过），不静默
        logger.warn(`审计 WAL 行数(${wal.records.length})少于待裁剪行数(${n})，按实际行数清理`);
      }
      const rest = wal.records.slice(Math.min(n, wal.records.length));
      const nextContent = rest.length ? `${rest.join('\n')}\n` : '';
      if (nextContent === wal.content) return;

      // 临时文件 + 原子替换，避免写一半崩溃留下残缺 WAL
      await atomicReplaceWal(nextContent);
    })
    .catch((e) => logger.warn(`审计 WAL 裁剪失败：${e.message}`));
}

/**
 * 读取 WAL 全部物理行（供启动重放使用）。文件不存在视为空。
 */
async function readWalLines() {
  const wal = await readWalRecords();
  return wal ? wal.records.filter(Boolean) : [];
}

/**
 * 读取毒批归档文件的全部 WAL 序号（P1-24）。文件不存在视为无归档。
 * 用途有二：① 重启重放前过滤主 WAL 中「已判定丢弃但改写未完成」的行
 * （崩溃窗口）；② 运维核对被丢弃取证的规模。
 */
async function readDiscardedSeqs() {
  const content = await fs.promises.readFile(walPath + '.discarded', 'utf8').catch((e) => {
    if (e.code !== 'ENOENT') logger.warn(`审计 WAL 毒批归档读取失败：${e.message}`);
    return '';
  });
  const seqs = new Set();
  for (const line of content.split('\n')) {
    const seq = walSeqOf(line); // 归档内损坏行返回 null，跳过（原件保留在归档文件中）
    if (seq) seqs.add(seq);
  }
  return seqs;
}

/**
 * 从主 WAL 移除指定序号的行，并**先归档后改写**（P1-24）。
 * 必须在本模块 walChain 的临界区内调用（不得自行再串 walChain，否则死锁）。
 * 顺序保证：先 append 归档 → 再原子替换主文件。若在两步间崩溃，
 * 归档已含证据、主文件仍含这些行——重启重放按归档序号跳过，不会重复处理。
 * @param {Set<string>} seqSet 待移除行的 __walSeq 集合
 * @returns {Promise<number>} 实际移除的行数
 */
async function filterWalLinesBySeqs(seqSet) {
  if (!seqSet || seqSet.size === 0) return 0;
  const wal = await readWalRecords();
  if (!wal || wal.records.length === 0) return 0;

  const removed = [];
  const kept = [];
  for (const line of wal.records) {
    const seq = walSeqOf(line);
    // 损坏行 seq=null：不参与匹配，保持原样留在主 WAL
    (seq && seqSet.has(seq) ? removed : kept).push(line);
  }
  if (removed.length === 0) return 0;

  // 先归档（取证留痕）后原子替换主 WAL；两步之间崩溃也不会重复处理（见函数注释）
  await fs.promises.appendFile(walPath + '.discarded', removed.join('\n') + '\n', 'utf8');
  await atomicReplaceWal(kept.length ? kept.join('\n') + '\n' : '');
  walDiscardedLines += removed.length;
  return removed.length;
}

/** 毒批丢弃入口（P1-24）：串行化在 walChain 上，失败仅告警不阻断 flush 收尾 */
function walDiscardBySeqs(seqs) {
  const seqSet = seqs instanceof Set ? seqs : new Set(seqs);
  walChain = walChain
    .then(() => filterWalLinesBySeqs(seqSet))
    .then((n) => {
      if (n > 0) {
        logger.warn(`审计 WAL 已归档 ${n} 行毒批取证行并从主 WAL 移除（重启重放不再重复处理）`);
      }
    })
    .catch((e) => logger.warn(`审计 WAL 毒批归档失败：${e.message}`));
}

// ================= 供 auditBuffer 使用的生命周期与访问器 =================

/**
 * 启动 WAL 层：重指向路径（未显式配置时按目标库名派生）、确保目录存在、开启写入。
 * @param {string|undefined} envPath 显式配置的 AUDIT_WAL_PATH
 */
function startup(envPath) {
  walPath = envPath || deriveDefaultWalPath();
  ensureLogsDir();
  walEnabled = true;
}

/** 关闭写入（stop() 调用）；已排入 walChain 的操作仍会执行完 */
function disable() {
  walEnabled = false;
}

/** WAL 是否启用（合规仪表盘指标） */
function isEnabled() {
  return walEnabled;
}

/**
 * 给文档分配 WAL 序号（P1-24）；未启用或已有序号时不动。
 * 序号随 WAL 行一起落盘，毒批丢弃时按它精确匹配并移除对应行。
 */
function assignSeq(doc) {
  if (!walEnabled || doc.__walSeq) return;
  walSeqCounter += 1;
  doc.__walSeq = WAL_RUN_ID + '-' + walSeqCounter;
}

/** 追加一行到 WAL；未启用时跳过（等价于拆分前调用点的 `if (walEnabled)` 门控） */
function appendLine(line) {
  if (walEnabled) walAppendLine(line);
}

/**
 * 把一次 WAL 操作排入串行链并返回链尾。onError 必须处理失败，
 * 保证 walChain 上不留 rejection（与既有 walTrimLines/walDiscardBySeqs 的 catch 语义一致）。
 */
function serialize(fn, onError) {
  const handle = onError || ((e) => logger.warn(`审计 WAL 链上操作失败：${e.message}`));
  walChain = walChain.then(fn).catch(handle);
  return walChain;
}

/** 等待串行链排空（追加/裁剪的 rename 落盘），供优雅关闭收尾使用 */
async function drain() {
  await walChain.catch(() => {});
}

/** WAL 侧运行指标（供 auditBuffer.getStats 展开合并） */
function getStats() {
  return { walEnabled, walDroppedLines, walDiscardedLines };
}

/** 重置累计计数（仅供测试） */
function resetCounters() {
  walDroppedLines = 0;
  walDiscardedLines = 0;
}

module.exports = {
  startup,
  disable,
  isEnabled,
  assignSeq,
  appendLine,
  trimLines: walTrimLines,
  discardBySeqs: walDiscardBySeqs,
  readLines: readWalLines,
  readDiscardedSeqs,
  serialize,
  drain,
  getWalPath,
  getStats,
  resetCounters,
};
