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
 * 按**本批文档的 `__walSeq` 精确移除**对应的行（读文件→挑出序号命中的行→临时文件
 * 原子替换回原名）。只移除已持久化的行——不得整文件截断，也不得"按条数裁前 N 行"
 * （F-97：本批文档的行未必是文件最前 N 行，一旦有空洞就会误删尚未落库记录的行），
 * 否则崩溃后这些"已写 WAL"的记录彻底丢失。进程崩溃后 auditBuffer.start() 重放 WAL 残留。
 * 所有 WAL 文件操作串行化在 walChain 上，避免并发读写竞争。
 * walEnabled 门控：仅 startup() 后开启，测试不调 start 故无 WAL 副作用，行为与改造前一致。
 * 属 best-effort：未对每条记录 fsync，崩溃仍可能丢 OS 页缓存中最后几条（远优于丢失整批≤100条/2s）。
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const cap = require('./auditWalCap');

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

let walEnabled = false;
// 串行化所有 WAL 文件操作（追加 / 裁剪 / 重放），杜绝并发读写竞争导致丢行
let walChain = Promise.resolve();
// 累计"WAL 行没落盘"的追加失败次数。这些记录的崩溃保护层已经失效：
// 内存缓冲仍在、正常落库后无损，但**在落库之前进程若退出就永久缺失**。
// 没有这个计数时，面板上的 `walEnabled: true` 在磁盘写不进（满/权限/只读挂载）时
// 是一句谎话——追加失败的证据只剩一行 warn 日志，而运维看的是合规面板。
let walAppendFailures = 0;
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
// 累计"重放时解析不出文档"的行数。这类行既不重放、也没有 __walSeq 可裁，
// 会每次重启被重新读一遍且永不清零——合规口径下"有多少取证永远进不了库"必须可见。
let walCorruptLines = 0;
// 累计"重放补号后整体回写失败"的次数（F-97 机制自身的失效计数）。语义与上面几条
// 不同：不是"已经丢了"，而是"下一次重启会把同一事件再插一份、哈希链跟着分叉"。
// 它必须与 walCorruptLines 分开——后者的行不会重放，前者的行已经进了这次缓冲。
let walRewriteFailures = 0;
// 上一次读取 WAL 时文件尾是否缺行尾换行（撕裂写或外部写手才会造成）。
// 缺了它，下一次 append 会把新记录直接拼在残行之后 ⇒ 两条记录同时不可恢复。
let walTailIncomplete = false;

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
 * 读取 WAL 并切分为记录行数组（P1-24 抽出：enforceWalLimit / removeWalLinesBySeqs /
 * readWalLines 等处共用，此前各自重复一遍「split + 尾换行判定」）。
 * 与 readWalLines 的差别：尾部无换行的残缺行**保留**为最后一条记录，
 * 按行重写时才不会把它丢掉。
 *
 * 「文件不存在」与「读不回文件」必须分派给不同调用方，所以本体只承认前者：
 * ENOENT → null，其余读取错误**抛出**。折成同一个 null 的代价是 removeWalLinesBySeqs
 * 把「一批刚确认落库的行没裁掉」读成「本来就没有行要裁」——前者的后果是这些行留在
 * 原地、重启按 WAL 语义重放（已落库的那批再插一份），后者什么都不是。同一个 null
 * 也让启动重放把「读不回」当成「WAL 是空的」而静默跳过整轮重放。
 *
 * @returns {Promise<{records: string[], content: string}|null>} 文件不存在返回 null
 * @throws 非 ENOENT 的读取错误原样抛出，由调用方按各自后果决定级别与措辞
 */
async function readWalRecordsStrict() {
  let content;
  try {
    content = await fs.promises.readFile(walPath, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    return null;
  }
  if (!content) return { records: [], content: '' };
  const parts = content.split('\n');
  const hasTrailingNewline = parts[parts.length - 1] === '';
  walTailIncomplete = !hasTrailingNewline;
  return { records: hasTrailingNewline ? parts.slice(0, -1) : parts, content };
}

/**
 * auditWalCap 用的兜版本：那一边把「stat 刚成功、内容却读不回」整体算一次
 * `walTrimFailures`，级别（error）与措辞归它（F-217 的一一对应判据也建在那条口径上），
 * 这里只留一行 warn 证据，不再另计一次账。
 */
async function readWalRecords() {
  try {
    return await readWalRecordsStrict();
  } catch (e) {
    logger.warn(`审计 WAL 读取失败：${e.message}`);
    return null;
  }
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
 *
 * 行尾换行由 WAL 层自己补齐。本模块对外的格式契约是"每行一条 JSON"，
 * 少一个换行就会把相邻两条记录拼成同一行 ⇒ `readWalRecords` 把它当成**一条损坏行**
 * （两条取证记录同时不可恢复），而且按行裁剪与按文档 flush 的计数从此永久错位一格，
 * 之后每次裁剪都会报"行数少于待裁剪行数"。目前唯一调用方自己加了 '\n'，
 * 但这个不变行不该靠调用方口头遵守——写路径就是它的归属层。
 */
function walAppendLine(line) {
  const payload = typeof line === 'string' && line.endsWith('\n') ? line : `${line}\n`;
  walChain = walChain
    .then(() => fs.promises.appendFile(walPath, payload, 'utf8'))
    // 只给 appendFile 挂这一层 catch：计数口径必须是"这一行没落盘"。
    // 若与下面的大小抽查共用 catch，enforceWalLimit 的 stat/rename 失败也会记进来，
    // 面板上就分不清"写不进去"和"抽查出错"。级别保持 warn（不升 error）：磁盘满时
    // 每条记录都会失败，error 级会把日志刷爆——持续性由 walAppendFailures 这个计数器体现。
    .catch((e) => {
      walAppendFailures += 1;
      logger.warn(
        `审计 WAL 追加失败（累计 ${walAppendFailures} 次）：${e.message}——` +
          '本条记录只有内存态，落库前进程退出即永久缺失'
      );
    })
    // 上限抽查与裁剪计数已拆到 auditWalCap（B-I1 节流判据在该模块内）。
    // 这里必须是"表达式形式"的箭头：afterAppend 命中抽查时返回的是 enforceWalLimit 的
    // Promise，链要等裁剪做完才走下一步——写成 { ...; } 语句体会把它丢成悬空 Promise。
    .then(() => cap.afterAppend({ walPath, readWalRecords, atomicReplaceWal }))
    .catch((e) => logger.warn(`审计 WAL 追加链后续操作失败：${e.message}`));
}

/**
 * 按 `__walSeq` 从主 WAL 移除指定的行。
 *
 * 为什么按序号而不是按行序（F-97）：「文件前 N 行」等价「本批 N 条」这个前提
 * 在本仓至少四条路径下不成立——WAL 未启用窗口入缓冲的文档没有行、`walAppendLine`
 * 的 appendFile 失败只告警（文档有缓冲副本却没行）、毒批 `discardBySeqs` 从文件
 * **中间**移走行、部分成功时已落库子集的行留在原地。一旦出现空洞，按行裁剪就会
 * 越界删掉排在后面的、**尚未落库**记录的行：那些记录只剩内存副本，进程一崩就永久
 * 缺失，而 `droppedCount` 完全不计。旧告警（"行数少于待裁剪数"）也抓不住——
 * 后面有更新行垫着时 `records.length >= n` 恒成立，实测该分支在缺陷场景里根本不触发。
 * 按序号匹配从结构上消灭"错位"这个概念：只可能删到自己确认落库的那些行。
 *
 * 必须在本模块 walChain 的临界区内调用（不得自行再串 walChain，否则死锁）。
 * archive=true 时**先归档后改写**（P1-24 取证顺序）：若在两步间崩溃，归档已含证据、
 * 主文件仍含这些行——重启重放按归档序号跳过，不会重复处理。
 * @param {Set<string>} seqSet 待移除行的 __walSeq 集合
 * @param {boolean} archive 是否把被移除的行追加到 <walPath>.discarded 取证归档
 * @returns {Promise<number>} 实际移除的行数
 */
async function removeWalLinesBySeqs(seqSet, archive) {
  if (!seqSet || seqSet.size === 0) return 0;
  let wal;
  try {
    wal = await readWalRecordsStrict();
  } catch (e) {
    // 走到这里说明调用方手上有一批**已确认落库**（或已判定丢弃）的序号，而文件读不回来：
    // 这些行留在原地。后果与 auditWalCap 的「已超限但读不回内容」同一格——重启按 WAL
    // 语义重放，已落库的那批再插一份。原先它与「本来就没有行」共用一个 `return 0`，
    // 日志与面板都分不出这两种世界。级别用 error：这不是"每条记录都可能撞上"的
    // 高频路径（每轮 flush 一次），而是"这一轮的回收整轮失效"。
    logger.error(
      `审计 WAL ${archive ? '毒批归档' : '落库回收'}读不回文件（${e.code || 'READ_ERROR'} ${
        e.message
      }）：${seqSet.size} 个序号本轮 0 命中，对应行留在原地——重启会把已落库的记录再重放一遍`
    );
    return 0;
  }
  if (!wal || wal.records.length === 0) return 0;

  const removed = [];
  const kept = [];
  for (const line of wal.records) {
    const seq = walSeqOf(line);
    // 损坏行 seq=null：不参与匹配，保持原样留在主 WAL
    (seq && seqSet.has(seq) ? removed : kept).push(line);
  }
  if (removed.length === 0) return 0;

  if (archive) {
    await fs.promises.appendFile(walPath + '.discarded', removed.join('\n') + '\n', 'utf8');
    walDiscardedLines += removed.length;
  }
  await atomicReplaceWal(kept.length ? kept.join('\n') + '\n' : '');
  return removed.length;
}

/** 毒批丢弃入口（P1-24）：串行化在 walChain 上，失败仅告警不阻断 flush 收尾 */
function walDiscardBySeqs(seqs) {
  const seqSet = seqs instanceof Set ? seqs : new Set(seqs);
  walChain = walChain
    .then(() => removeWalLinesBySeqs(seqSet, true))
    .then((n) => {
      if (n > 0) {
        logger.warn(`审计 WAL 已归档 ${n} 行毒批取证行并从主 WAL 移除（重启重放不再重复处理）`);
      }
    })
    .catch((e) => logger.warn(`审计 WAL 毒批归档失败：${e.message}`));
}

/**
 * 落库成功后的裁剪入口（F-97）：只移除本批**已确认落库**的那些行。
 * 不归档——记录已在库里，塞进 `.discarded` 会污染"被丢弃取证"这一语义
 * （那个文件是"审计永久缺失了多少"的唯一凭据）。
 * 串行化在 walChain 上，故排在既有 append 之后执行；由于是按序号匹配，
 * 排在后面的其它待落库行**不可能**被牵连（这正是按行计数做不到的）。
 */
function walTrimBySeqs(seqs) {
  const seqSet = seqs instanceof Set ? seqs : new Set(seqs);
  if (seqSet.size === 0) return;
  walChain = walChain
    .then(() => removeWalLinesBySeqs(seqSet, false))
    .catch((e) => logger.warn(`审计 WAL 裁剪失败：${e.message}`));
}

/**
 * 读取 WAL 全部物理行（供启动重放使用）。文件不存在视为空。
 *
 * 读失败不能也"视为空"：调用方（auditBuffer.start）拿到 0 行就直接 return，于是上一进程
 * 待落库的记录这一轮一条都不回来，而 `审计 WAL 重放 N 条遗留记录` 那行 info 根本不打——
 * 面板与日志上留下的是"没有待重放的记录"这个假象。文件本身还在，下次启动仍会重放，
 * 所以这里返回 [] 保持原行为，只是把这个"整轮重放没做成"说清楚。
 */
async function readWalLines() {
  let wal;
  try {
    wal = await readWalRecordsStrict();
  } catch (e) {
    logger.error(
      `审计 WAL 启动重放读不回文件（${e.code || 'READ_ERROR'} ${e.message}）：` +
        '本轮不重放，缓冲按空启动——上一进程留下的待落库记录这一轮不会回来（文件留在原地，下次启动再试）'
    );
    return [];
  }
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
 * 在 walChain 的临界区内整体重写 WAL（仅供启动重放"补序号"使用，必须在
 * serialize 回调里 await 调用——不另排一次链，否则新追加的行会被旧快照覆盖掉）。
 * 与 filterWalLinesBySeqs 的区别：这里不删任何行、不归档，只是把同一批行换了写法。
 * @param {string[]} lines 与文件顺序一致的行（不含换行符）
 */
async function rewriteInChain(lines) {
  await atomicReplaceWal(lines.length ? `${lines.join('\n')}\n` : '');
}

/**
 * 给重放读到的、缺 `__walSeq` 的行补序号（F-97 的配套半条）。
 *
 * 为什么必须补：裁剪改成"按序号精确匹配"之后，**认不出序号的行永远不会被裁掉**。
 * 存量里没有序号的行有两类——P1-24 之前写的旧行、以及被外部工具/测试手工写入的行。
 * 不补的后果不是"文件里多几行"：这些行每次重启都会被重放进缓冲，而重放文档的 `_id`
 * 是 flush 时才分配的（每次不同）⇒ **每重启一次就重复插入一份审计记录**，
 * 而且哈希链跟着一起分叉。旧实现靠"按条数裁前 N 行"顺手把它们带走了，
 * 那是同一个缺陷的另一面：能带走死行，也就能带走别人的活行。
 *
 * 补在**边界**而不是补在每个消费方：序号一旦写进行里，之后所有路径（裁剪、
 * 毒批归档、崩溃重放跳过）用的都是同一份身份，不需要各自再兜一次。
 * @param {string[]} lines readLines() 的返回值（顺序即文件顺序）
 * @param {(doc: object) => void} onDoc 每行解析出的文档回调（损坏行不会调用）
 */
async function stampReplaySeqs(lines, onDoc) {
  const out = [];
  let dirty = false;
  let corrupt = 0;
  for (const line of lines) {
    let doc = null;
    try {
      doc = JSON.parse(line);
    } catch {
      doc = null; // 损坏行原样保留：不猜内容，也不因此丢掉后面的行
    }
    if (doc && typeof doc === 'object') {
      if (!doc.__walSeq) {
        assignSeq(doc); // walEnabled 在 startup() 之后恒真，序号在此刻分配并随行回写
        out.push(JSON.stringify(doc));
        dirty = true;
      } else {
        out.push(line);
      }
      onDoc(doc);
    } else {
      // 解析不出文档（JSON 抛错，或解析出数字/字符串/null 这类非对象）：
      // 这一行既不会被重放，也因为带不走 __walSeq 而永远不会被按序号裁掉。
      // 不删（不猜内容），但必须计数并告警——否则"有多少取证永远进不了库"
      // 在合规口径里是 0，而它其实每次重启都在原地重复出现。
      corrupt += 1;
      out.push(line);
    }
  }
  if (corrupt) {
    walCorruptLines += corrupt;
    // 留痕与计数同源：坏行身份、累计数、文件路径都归本模块所有
    logger.error(
      `审计 WAL 有 ${corrupt} 行解析不出取证文档（累计 ${walCorruptLines} 行）：` +
        `文件 ${getWalPath()}。这些行不会重放、也因带不走 __walSeq 而永远不会被裁剪，` +
        '只会被每次重启重新读一遍——等于这部分审计证据在合规口径里静默失踪，请立即取原件核查'
    );
  }
  // 文件尾缺换行时强制走一次整体重写：rewriteInChain 落的是 `join('\n') + '\n'`，
  // 顺带把缺失的行尾补回来。不补的后果是下一次 append 把新记录拼在残行尾巴上，
  // 两条取证记录同时不可恢复（见 walAppendLine 上方那段格式契约）。
  if (!dirty && walTailIncomplete && lines.length) {
    dirty = true;
    logger.warn(
      `审计 WAL 文件尾缺少行尾换行，已在启动重放时补齐：${getWalPath()}` +
        '（成因通常是撕裂写或外部写手；不补则下一条记录会被拼在残行之后）'
    );
  }
  // 补号必须回写才算数：内存里的文档有序号，文件里的行没有 ⇒ 落库后按序号裁剪
  // 认不出这些行，它们留在原地，下次重启被重放成**同一事件的第二个副本**
  // （_id 是 flush 时才分配的，每次不同），哈希链随之分叉。回写失败是这条
  // F-97 机制唯一的失效形态，原先只汇进一句 `启动重放失败` 的 warn——
  // 读日志的人分不清"序号没写回去"和"读文件失败"，也没有任何计数器能事后核对。
  // 不向上抛：这条链的调用方（auditBuffer.start 的 onError）只会再刷一句 warn，
  // 而它一抛就跳过了后面的 `enforceBufferLimit()`——崩溃前积压很多时那正是
  // 唯一挡住缓冲无界增长的闸门，缺陷场景里反而不能丢。
  if (dirty) {
    try {
      await rewriteInChain(out);
    } catch (e) {
      walRewriteFailures += 1;
      logger.error(
        `审计 WAL 重放补号回写失败（累计 ${walRewriteFailures} 次）：${e.message}——文件 ${getWalPath()}` +
          ' 里这批行仍缺 __walSeq：本次它们已进内存缓冲并会正常落库，但落库后按序号裁不掉，' +
          '下次重启会作为同一事件的第二个副本被重放（哈希链同时分叉），请立即取文件原件核查'
      );
    }
  }
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
  return {
    walEnabled,
    ...cap.getStats(),
    walDiscardedLines,
    walCorruptLines,
    walAppendFailures,
    walRewriteFailures,
  };
}

/**
 * 重置累计计数（仅供测试）。
 * `cap.resetCounters()` 连抽查相位 `walAppendCount` 一起归零——不归零时它是跨用例泄漏的
 * 模块级累加值，"默认间隔 32 ⇒ 这批追加里不会抽查"这类前提就取决于此前跑过多少条记录。
 * 完整理由写在 auditWalCap.resetCounters（判据与相位都在那边）。
 */
function resetCounters() {
  cap.resetCounters();
  walDiscardedLines = 0;
  walCorruptLines = 0;
  walAppendFailures = 0;
  walRewriteFailures = 0;
}

module.exports = {
  startup,
  disable,
  isEnabled,
  assignSeq,
  appendLine,
  trimBySeqs: walTrimBySeqs,
  discardBySeqs: walDiscardBySeqs,
  stampReplaySeqs,
  readLines: readWalLines,
  readDiscardedSeqs,
  serialize,
  drain,
  getWalPath,
  getStats,
  resetCounters,
};
