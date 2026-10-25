/**
 * 审计 WAL 的「硬上限」子系统：抽查节流相位 + 超限裁剪 + 裁剪侧计数
 * （报告 R-6 / B-I1 / F-74 / F-217 / F-218）
 *
 * 从 `auditBufferWal.js` 按**既有边界**拆出：宿主管 WAL 文件的 I/O 与串行链，本模块只
 * 回答两个问题——「这次要不要抽查大小」「抽查发现越限之后怎么办」。逐条搬运，行为不变。
 * 拆的直接动因是 `max-lines` 棘轮：宿主文件已到 329 > 300 有效行，而本仓规矩是棘轮只许降
 * 不许升（同族先例：handoff §16.3 把判据搬进 `bundleBudgetPolicy.js`；台账 §8822 的
 * `securityAlert.js [max-lines] 0 -> 1` 也是"不动基线、搬代码"）。
 *
 * 文件 I/O 由宿主注入（`readWalRecords` / `atomicReplaceWal` / 当次的 `walPath`）：
 * `enforceWalLimit` 运行在宿主的串行 `walChain` 上，自己不得再排一次队。
 * `stat` 走 `fs.promises.stat` 的属性查找（不解构成局部变量），这样测试对
 * `fs.promises.stat` 的 spy 仍然拦得住这条路径——它原先就靠这个 spy 驱动。
 */
const fs = require('fs');
const logger = require('../utils/logger');
// 「上限已越过而本轮没腾出空间」是 R-6 唯一的可见形态：这两条臂自己一抛，
// 面板上就既没有裁剪失败也没有超限告警（全总化唯一实现，见 utils/auditWriteFailure）。
const { errText } = require('../utils/auditWriteFailure');
const { readPositiveNumberEnv } = require('../utils/envNumber');

// WAL 硬上限（字节）：DB 长时间不可用且高流量时 WAL 持续增长（磁盘写放大，报告 R-6）。
// 超限丢弃最旧一半行（与 BUFFER_HARD_LIMIT 丢最旧同向的止损策略）并告警。
// 丢弃对象按持久化承诺分级：普通行优先，`__walDurable` 行默认不丢（详见 enforceWalLimit）。
// 被丢弃的普通行，其文档若仍在缓冲中会照常落库，WAL 行由该批成功落库时的按序号裁剪回收；
// 对应文档已被 BUFFER_HARD_LIMIT 丢弃的行，本就是纯取证残留。
// 运行期读 env 便于测试注入小阈值；默认 50MB。
const DEFAULT_WAL_MAX_BYTES = 50 * 1024 * 1024;
// 同一个坏值只告警一次（本函数每次 stat 抽查都会调用，逐次告警会刷日志）
let walMaxBytesWarnedFor = null;

/**
 * 解析 AUDIT_WAL_MAX_BYTES。
 *
 * 原先是 `Number(env) || 50MB`，于是**负数**是个被静默接受的合法真值——
 * `stat.size <= 负数` 恒假 ⇒ 每次抽查都判定"超限"并弃掉一半行，
 * WAL 被持续销毁式裁剪，而这是崩溃后唯一的取证残留。0/NaN 会被 `||` 兜住，
 * 负数不会。判据统一交给 utils/envNumber（与审计链锁超时同一口径）：
 * 非"有限正数"一律按未配置处理并显式告警。
 * 测试注入的小阈值（如 1、200 字节）仍是正数，语义不变。
 */
function getWalMaxBytes() {
  return readPositiveNumberEnv('AUDIT_WAL_MAX_BYTES', DEFAULT_WAL_MAX_BYTES, {
    onInvalid: (name, raw, fallback) => {
      if (walMaxBytesWarnedFor === raw) return; // 每次大小抽查都会走到这里，坏值只报一次
      walMaxBytesWarnedFor = raw;
      logger.error(
        `${name}=${JSON.stringify(raw)} 非法（须为正的字节数），已按默认 ${fallback} 处理；` +
          '负值若被接受会让 WAL 每次检查都"超限"并弃掉一半行（崩溃后唯一的取证残留）'
      );
    },
  });
}

// B-I1：每条 append 都 stat 是串行 walChain 的吞吐瓶颈——改为每 N 次追加
// 抽查一次大小（默认 32；N×单行 ≈ 数 KB 的滞后窗口，对 50MB 上限可忽略）。
// F-217：这一档原先写成 `Math.max(1, Number(env) || 32)`，而它上面那句注释
// "0/负值按 1 处理"只在负值上成立。实测（node -e，本机）：
//   "0"→32  "-5"→1  "abc"→32  "2.5"→2.5  ""→32
// 即 `0 || 32` 被 || 吞成 32 ⇒ 注释承诺的"最保守那一档"恰好给出最松那一档，
// 且零反馈；2.5 原样生效后 `count % 2.5 === 0` 实际等价"每 5 次"，也不是注释说的值。
// 现在走仓内统一判据（utils/envNumber）：只有正整数被采纳，其余（含 0）回落默认
// 并留一条 warn。要"逐条检查"就注入 1 —— 那是既有测试的实际做法，不该为同一个意图
// 保留第二种写法（同时接受 0 和 1 两种拼法，正是刚才那句假注释的来路）。
const WAL_STAT_INTERVAL_DEFAULT = 32;
const getWalStatInterval = () =>
  readPositiveNumberEnv('AUDIT_WAL_STAT_INTERVAL', WAL_STAT_INTERVAL_DEFAULT, {
    integer: true,
    onInvalid: (name, raw) =>
      logger.warn(
        `${name}=${JSON.stringify(raw)} 非法（须为正的抽查间隔次数），已按默认 ${WAL_STAT_INTERVAL_DEFAULT} 处理`
      ),
  });
// 抽查相位：本模块的私有状态，但**参与归零**（见 resetCounters）
let walAppendCount = 0;

// 累计因 WAL 超限被丢弃的行数（可观测，静默丢取证数据在合规上不可接受）
let walDroppedLines = 0;
// F-217：WAL **裁剪侧**的失败计数。追加侧有 walAppendFailures，而"越过上限之后这一轮
// 到底省没省出空间"以前一个计数都没有（`enforceWalLimit` 的三个失败点全部只 warn 或不 warn）。
// 于是存在一条面板完全同形的路径：appendFile 一直成功、裁剪一直失败 ⇒
// walEnabled:true / walAppendFailures:0 / walDroppedLines:0 / walRewriteFailures:0，
// 与"上限从未被触碰"一字不差，而此时 R-6 这个硬上限已经是空操作（WAL 无界增长 + 写放大）。
// "追加成功而裁剪失败"不是想象：appendFile 只要**目标文件**可写，裁剪要 writeFile(.tmp)+rename，
// 需要**目录**可写 —— 目录权限、目录配额、上一次以别的 uid 留下的 .tmp 不属主，三种都够。
// （本机未实测：Windows 上 fs.chmodSync 是空操作，POSIX 权限分裂复现不出来，属不变式论证。）
let walTrimFailures = 0;
// 已按显式开关丢弃的「已 fsync 敏感行」条数。与 walDroppedLines 分开：
// 前者是"取证缺失"，后者里混着"承诺缺失"，合规口径上不是一回事。
let walDurableDropped = 0;
// 因普通行不足而拒绝裁剪 durable 行的次数。非零即表示 WAL 正在无界增长，
// 是比 walTrimFailures 更严重的信号（后者是"想裁没裁成"，这里是"按策略不裁"）。
let walDurableTrimRefusals = 0;

/**
 * 该 WAL 行是否携带「已向调用方承诺持久化」的标记（由 auditOutbox 写出）。
 * 解析失败按**普通行**处理：坏行本来就会被裁，且它不构成任何承诺。
 * @param {string} line
 * @returns {boolean}
 */
function isDurableLine(line) {
  try {
    const doc = JSON.parse(line);
    return Boolean(doc) && doc.__walDurable === true;
  } catch {
    return false;
  }
}

/**
 * 是否允许以磁盘可用性优先、丢弃已 fsync 的敏感行。默认 **false**。
 * 运行期读 env：测试可逐用例注入，且运维改开关不必重启构建。
 */
function allowDurableTrim() {
  return String(process.env.AUDIT_WAL_ALLOW_DURABLE_TRIM || '').toLowerCase() === 'true';
}
/** 推进裁剪计数并返回拼好"累计 N 次"的文案；级别留给调用点（同一族的三条路径严重程度不同） */
const noteTrimFailure = (msg) => {
  walTrimFailures += 1;
  return `${msg}（累计 ${walTrimFailures} 次）`;
};

/**
 * WAL 大小硬上限保护（R-6）：超过 getWalMaxBytes() 丢弃最旧一半行并告警。
 * 串行化在宿主的 walChain 上（与追加/裁剪互斥）。
 *
 * **丢弃对象按持久化承诺分级**（2026-10-21 修正）：
 *  - 普通行（`auditBuffer.push` 写出，尽力而为）优先丢，最旧优先；
 *  - `__walDurable` 行（`auditOutbox` 写出，背后是"敏感操作已回成功"）默认**不丢**。
 *    普通行不足以完成本轮目标时，记 `walDurableTrimRefusals` 并停手，
 *    只有显式 `AUDIT_WAL_ALLOW_DURABLE_TRIM=true` 才允许裁，且计入 `walDurableDropped`。
 *
 * 旧实现按**位置**丢最旧一半，理由是"较新行对应的文档大概率仍在缓冲中"。
 * 那个理由对普通行成立，对 durable 行不成立：它们的承诺是"已 fsync 即已持久化"，
 * 而 `.discarded` 永不回灌 ⇒ 按位置裁剪等于把承诺改成"落盘但永久不入库"。
 * 「大概率」不能作为合规链路的正确性前提，故改为按标记分级。
 */
async function enforceWalLimit({ walPath, readWalRecords, atomicReplaceWal }) {
  let stat;
  try {
    stat = await fs.promises.stat(walPath);
  } catch (e) {
    // ENOENT：WAL 还没建（或刚被排空删掉），不是失败；其余都是"这次上限检查没做成"
    if (e?.code !== 'ENOENT') logger.warn(noteTrimFailure(`审计 WAL 大小检查失败：${errText(e)}`));
    return;
  }
  const maxBytes = getWalMaxBytes();
  if (stat.size <= maxBytes) return;

  // 走到这里说明**已经越过硬上限**，下面每一条提前返回都是"该腾空间而这一轮没腾"
  const wal = await readWalRecords();
  if (!wal) {
    // stat 刚成功而读不回内容：文件被并发删掉，或 EACCES/EIO。两种都让 R-6 当场失效。
    logger.error(noteTrimFailure(`审计 WAL 已超限但读不回内容，本轮未裁剪：${walPath}`));
    return;
  }
  const records = wal.records;
  if (records.length < 2) return; // 单行超限无「一半」可弃，刻意不计（留给外部取证）

  // 丢一半仍是止损口径（R-6 的产品语义不变），但**丢哪一半**现在按持久化承诺分级。
  //
  // 分级动因：`auditOutbox` 写出的行带 `__walDurable`——那一行背后是"敏感操作已回成功"，
  // 即对调用方的持久化承诺。按位置丢最旧一半会把这些行静默移出主 WAL，而
  // `.discarded` 是**永不回灌**的取证归档（见 auditBuffer 的 start() 注释与
  // readDiscardedSeqs 的用法：只读序号用于跳过，不读内容重放）。
  // 于是"已 fsync"退化成"已落盘但永久不入库"——恰好推翻 outbox 的唯一承诺。
  //
  // 因此：普通行（`push` 写入，尽力而为）优先丢，durable 行默认不丢。
  // 全解析一次是必要的：既要挑出候选，也要在拒绝裁剪时给出"durable 行还剩多少"。
  // 成本与上面 readWalRecords 读整个文件同量级，且只在超限路径上发生。
  const dropTarget = Math.floor(records.length / 2);
  const normalIdx = [];
  const durableIdx = [];
  records.forEach((line, i) => {
    (isDurableLine(line) ? durableIdx : normalIdx).push(i);
  });

  const dropIdx = normalIdx.slice(0, dropTarget);
  const shortfall = dropTarget - dropIdx.length;
  let durableDropped = 0;

  if (shortfall > 0) {
    if (!allowDurableTrim()) {
      // 严格模式：普通行不够就停手。文件会继续超限，这是**有意的**取舍——
      // 以磁盘可用性换"不静默推翻已承诺的持久化"，把决定权显式交回运维。
      walDurableTrimRefusals += 1;
      logger.error(
        `审计 WAL 超过硬上限，但可裁的普通行只有 ${dropIdx.length} 条，` +
          `不足以完成本轮 ${dropTarget} 条的目标；默认策略**拒绝裁剪 ${durableIdx.length} 条` +
          `已 fsync 的敏感审计行**（累计拒绝 ${walDurableTrimRefusals} 次）。` +
          '这些行对应已向调用方返回成功的操作，裁掉即「承诺已持久化却永久不入库」。' +
          '请立即恢复数据库连通性或扩容 WAL；确需以磁盘可用性优先，' +
          '显式设置 AUDIT_WAL_ALLOW_DURABLE_TRIM=true（会同时记 walDurableDropped）'
      );
      if (!dropIdx.length) return; // 一条普通行都没有：本轮不动文件，避免空归档
    } else {
      dropIdx.push(...durableIdx.slice(0, shortfall));
      durableDropped = shortfall;
    }
  }

  const dropSet = new Set(dropIdx);
  const droppedLines = records.filter((_, i) => dropSet.has(i));
  const keptLines = records.filter((_, i) => !dropSet.has(i));
  if (!droppedLines.length) return;

  try {
    // 先归档再裁剪：这些行即将从主 WAL 消失，但它们是取证记录，不能只计一个
    // dropped 数字就丢。归档失败 ⇒ 放弃本轮裁剪（宁可文件超限，也不丢证据）。
    await fs.promises.appendFile(walPath + '.discarded', `${droppedLines.join('\n')}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
  } catch (e) {
    logger.error(
      noteTrimFailure(
        `审计 WAL 超限裁剪前归档失败：${errText(e)}——本轮不裁剪，主 WAL 继续超限（取证优先）`
      )
    );
    return;
  }
  try {
    await atomicReplaceWal(`${keptLines.join('\n')}\n`);
  } catch (e) {
    // 就地消化、不再冒泡到"追加链后续操作失败"那条 catch：那条的口径是"追加链上
    // 有后续操作炸了"，把裁剪失败混进去就等于把 walTrimFailures 与追加侧计数重新焊在一起，
    // 而分开的这两个计数正是本函数要表达的东西。
    logger.error(
      noteTrimFailure(
        `审计 WAL 超限裁剪回写失败：${errText(e)}——上限已越过而本轮没有腾出任何空间，` +
          '下一次抽查会再试（R-6 在此期间不生效）'
      )
    );
    return;
  }

  walDroppedLines += droppedLines.length;
  if (durableDropped > 0) {
    // 与上面那条拒绝日志同一件事的两面：拒绝是"没丢"，这里是"按显式开关丢了"。
    // 单独计数，面板上才能把"取证缺失"与"承诺缺失"分开。
    walDurableDropped += durableDropped;
    // 同时打进 Prometheus：这条路径的严重度高于其余三个 drop reason
    // （丢的是已 fsync 且已回成功的敏感审计），必须能触发 AuditRecordsDropped，
    // 而不是只等有人打开合规面板才发现。
    require('../utils/metricsAuditDrops').incAuditDrop('wal_durable_lost', durableDropped);
    logger.error(
      `审计 WAL 超限裁剪已按 AUDIT_WAL_ALLOW_DURABLE_TRIM 丢弃 ${durableDropped} 条` +
        `**已 fsync 的敏感审计行**（累计 ${walDurableDropped} 条）——` +
        '这些操作曾向调用方返回成功，现仅存于 .discarded 取证归档、不会自动回灌。' +
        '请按合规事件上报并核查缺失区间'
    );
  }
  logger.error(
    `审计 WAL 超过硬上限（${stat.size} > ${maxBytes} 字节），已丢弃最旧 ${droppedLines.length} 行` +
      `（归档到 ${walPath}.discarded，累计 ${walDroppedLines} 行）。数据库可能长时间不可用，请立即排查`
  );
}

/**
 * 追加（成功或失败）之后走的一步：推进抽查相位，命中间隔才做上限检查。
 * 从 `auditBufferWal.walAppendLine` 的 `.then` 里整段搬来，判据一字未改。
 */
function afterAppend(deps) {
  walAppendCount += 1;
  if (walAppendCount % getWalStatInterval() !== 0) return undefined;
  return enforceWalLimit(deps);
}

/** 上限侧运行指标（由宿主 auditBufferWal.getStats 展开，面板字段名不变） */
function getStats() {
  return {
    walDroppedLines,
    walTrimFailures,
    walDurableDropped,
    walDurableTrimRefusals,
  };
}

/**
 * 归零。`walAppendCount` 虽不出现在 getStats 里，也必须一起清：它是抽查判据
 * `walAppendCount % interval === 0` 的左操作数，即"下一次抽查落在第几次追加"的相位。
 * 不清时它是模块级累加值、跨用例泄漏，于是"默认间隔 32 ⇒ 这 10 次追加里根本不会抽查"
 * 这类前提成立与否取决于此前跑过多少条审计记录——实测同一文件换 seed 后变红的臂会换位
 * （zzqA_walStatIntervalEnvContract 的 2.5 臂 ⇄ 0 臂），正是本仓三 seed 随机顺序门禁要禁的形。
 * 既有两处"注入 interval=1 来消除顺序依赖"的绕行（auditBufferFlushAndWalGuards 的
 * walcap / stat_err 两条）在本改动后依然成立：任何整数 % 1 === 0，与相位无关。
 */
function resetCounters() {
  walAppendCount = 0;
  walDroppedLines = 0;
  walTrimFailures = 0;
  walDurableDropped = 0;
  walDurableTrimRefusals = 0;
}

// `enforceWalLimit` 一并导出：宿主只在 afterAppend 里调它，但它的分级判据
// （普通行优先 / durable 行默认不裁）无法通过 afterAppend 的节流相位稳定驱动，
// 单测需要直接调用。生产代码不得绕过 afterAppend 自行调用（会破坏抽查节流）。
module.exports = { afterAppend, enforceWalLimit, getStats, resetCounters };
