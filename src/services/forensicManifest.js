/** 取证清单（P2b / T3，§2.4）：把"批次"变成可核算的东西 —— 每批一行 JSONL，行与行用 chainHash 串起来，每日一条审计事件把当天末条哈希钉进审计链。 为什么需要它：recordHash 只保证**单条**不被改。整条/整批被删时库里剩下的每条都自洽，没有任何一处会说"这里曾经有一条"。 count/firstSeq/lastSeq 给出"应有几条、从哪到哪"，chainHash 把顺序与内容绑在一起（改中间任一条 ⇒ 其后全部 chainHash 变）。 能力边界（如实记录，不得读成"完整防篡改"）：manifest 与 Mongo 同主权边界。能同时改库+清单文件+审计链的人仍可重写一切。它的价值是把伪造从"改一处"变成"必须同时改三处"，不是"防得住"。清单落盘失败只计数+告警（fail-visible），不重试、不阻塞落库。 / */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { errText } = require('../utils/auditWriteFailure');
const { toEpochMs } = require('../utils/helpers');
const { businessDateParts } = require('../constants/timezone');
const { withLock } = require('./forensicManifestLock');
const retry = require('./forensicManifestRetry');

const MANIFEST_VERSION = 1;
const MANIFEST_DIR = path.join(path.resolve(__dirname, '..', '..'), 'logs', 'forensic-manifest');
const GENESIS = 'genesis';
const WARN_INTERVAL_MS = 60000;

const state = { writeFailures: 0, written: 0, lastError: null, lastWarnAt: 0 };

// 追加是「读末行 → 算哈希 → append」的读-改-写，必须**两层**串起来：进程内并发由 appendChain 排队（同 WAL 的 walChain；实测不做时三个并发批次的 prev 序列是 [genesis,genesis,genesis]， verifyManifest 会把合法数据报成断链）；跨进程/多副本由 forensicManifestLock 的文件锁互斥。
let appendChain = Promise.resolve();

const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');

/** 文件名用**业务时区**（constants/timezone.js 的单一声明），不是 UTC。 实测缺陷：首版用 `toISOString().slice(0,10)`，于是北京时间 00:00–08:00 产生的批次全落到"昨天"的文件里，与仓内 businessDateParts 的业务日口径分叉——同一份数据在报表里算今天、在清单里算昨天。仓里已经为"今天到底是哪天"立过单一声明，这里不能再造第二个。 / / */
const dateKeyOf = (now = new Date()) => businessDateParts(now).dateStr;

const filePathOf = (dir, now) => path.join(dir, `${dateKeyOf(now)}.jsonl`);

/** 限量 warn：清单落盘失败可能是持续故障，计数在涨而日志不刷屏 */
const warnRateLimited = (msg) => {
  const now = Date.now();
  if (now - state.lastWarnAt < WARN_INTERVAL_MS) return;
  state.lastWarnAt = now;
  logger.warn(msg);
};

/** 一批的清单条目（纯函数：同样输入必须得出同样 chainHash，复核方可独立复算）。 chainHash = sha256(prevChainHash + hashesDigest + count + firstSeq + lastSeq) 三个设计要点： ① **hashesDigest 把逐条 recordHash 的顺序与内容折进哈希**（digest = sha256(join(''))）： 调换两条 ⇒ digest 变 ⇒ chainHash 变；少一条 ⇒ 同理。 ② **行内字段全部参与**：count/firstSeq/lastSeq 任改一个而 chainHash 不变 ⇒ 重算即失配。若只把 hashes 折进去，改 count 这类"改一条"在数学上根本查不出来——那正是验收线要抓的形态。 ③ **prevChainHash 参与**：整批搬到另一条链上 ⇒ 哈希变（否则可把某批挖走再挪到别处）。定长 hex 原样拼接无歧义：recordHash 恒 64 位，各段之间不需要分隔符。 / / / */
const batchEntryOf = ({
  prevChainHash = GENESIS,
  recordHashes = [],
  firstSeq = null,
  lastSeq = null,
  now = new Date(),
}) => {
  const hashesDigest = sha256(recordHashes.join(''));
  const count = recordHashes.length;
  const chainHash = sha256(
    [prevChainHash, hashesDigest, String(count), String(firstSeq), String(lastSeq)].join('|')
  );
  return {
    v: MANIFEST_VERSION,
    ts: now.toISOString(),
    count,
    firstSeq,
    lastSeq,
    hashesDigest,
    prevChainHash,
    chainHash,
  };
};

/** 重算某行的 chainHash（复核用；与写入走同一个 batchEntryOf，不复制第二份算法） */
const recomputeOf = (entry) =>
  sha256(
    [
      entry.prevChainHash,
      entry.hashesDigest,
      String(entry.count),
      String(entry.firstSeq),
      String(entry.lastSeq),
    ].join('|')
  );

/** 读当日清单最后一行拿 prevChainHash（文件不存在 ⇒ genesis；末行坏掉 ⇒ 报错而不是猜） */
const readLastChainHash = (filePath) => {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    if (e?.code === 'ENOENT') return GENESIS;
    throw e;
  }
  const lines = content.split('\n').filter(Boolean);
  if (lines.length === 0) return GENESIS;
  let last;
  try {
    last = JSON.parse(lines[lines.length - 1]);
  } catch {
    throw new Error(`清单末行解析不出（${filePath}），拒绝在其后继续接链`); // 末行损坏时**不猜**：宁可让本批起链失败并留下可复核的痕迹，也不悄悄接上一个读不懂的哈希
  }
  if (!last || typeof last.chainHash !== 'string')
    throw new Error(`清单末行缺少 chainHash（${filePath}）`);
  return last.chainHash;
};

/** 追加一批（落库成功后调用）。失败只计数 + 限频 warn，**绝不抛**：取证是尽力而为的增强证据，清单写不进去不能反过来卡住请求或回滚落库。 / */
async function writeLocked(batch) {
  const filePath = filePathOf(batch.dir, batch.now);
  // 锁内重读末行：抢锁前读到的末行可能已被别的进程推进，必须以锁内为准
  const locked = await withLock(batch.dir, {}, async () => {
    const prevChainHash = readLastChainHash(filePath);
    const entry = batchEntryOf({ prevChainHash, ...batch });
    await fs.promises.appendFile(filePath, JSON.stringify(entry) + '\n', {
      encoding: 'utf8',
      mode: 0o600,
    });
    return entry;
  });
  if (!locked.ok) {
    const err = new Error(`取证清单锁获取（${locked.reason}）失败`); // 用带 code 的错误传锁失败：下游按 code 判，不靠解析中文文本（那太脆）
    err.code = 'FORENSIC_MANIFEST_LOCK_TIMEOUT';
    throw err;
  }
  state.written += 1;
  return locked.value;
}

/** 锁内写一批：成功返回 entry，失败抛错（调用方决定是入队重试还是报错）。 */
async function appendBatch({
  dir = MANIFEST_DIR,
  recordHashes = [],
  firstSeq = null,
  lastSeq = null,
  now = new Date(),
} = {}) {
  if (!Array.isArray(recordHashes) || recordHashes.length === 0) {
    return { written: false, reason: 'empty_batch' }; // 不写"0 条"噪声行，也不推进链
  }
  // 排进串行链：写入动作（建目录 → 读末行 → 算哈希 → append）整体不可与其它批次交错
  const run = appendChain.then(async () => {
    await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
    await retry.drain((b) => writeLocked(b)); // 先把之前写失败的批次补上：必须在本次之前，否则链序错乱（补出假断裂）
    const entry = await writeLocked({ dir, recordHashes, firstSeq, lastSeq, now });
    return { written: true, entry };
  });
  appendChain = run.catch(() => {}); // 单个批次失败不得卡死后续批次
  try {
    return await run;
  } catch (e) {
    state.writeFailures += 1;
    state.lastError = errText(e).slice(0, 200);
    warnRateLimited(
      `取证清单写入失败（累计 ${state.writeFailures} 批）：${state.lastError}——该批已落库但不在清单内，复核会显示为缺失批次`
    );
    retry.enqueue({ dir, recordHashes, firstSeq, lastSeq, now }); // 入队等下次补写，不是丢
    // 锁超时与真·写失败要分开报：前者是"别人占着"，后者是"磁盘/权限"，处置完全不同。归并会让人查错方向。
    return {
      written: false,
      reason: e && e.code === 'FORENSIC_MANIFEST_LOCK_TIMEOUT' ? 'lock_timeout' : 'write_failed',
    };
  }
}

/** 读回当日清单：坏行单独记，绝不与正常条目混在一起 */
function readManifest({ dir = MANIFEST_DIR, date = new Date() } = {}) {
  const filePath = filePathOf(dir, date);
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    if (e?.code === 'ENOENT') return { entries: [], badLines: [], exists: false };
    throw e;
  }
  const entries = [];
  const badLines = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    if (!lines[i]) continue;
    try {
      const parsed = JSON.parse(lines[i]);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
        badLines.push({ line: i + 1 });
      else entries.push({ ...parsed, __line: i + 1 });
    } catch {
      badLines.push({ line: i + 1 }); // 1-based，可直接对照编辑器
    }
  }
  return { entries, badLines, exists: true };
}

/** 单行判据：链首尾相连 + 行内字段自洽（拆出来是为了让每个判据单独可读、复杂度各自可控） */
const CLOCK_SKEW_TOLERANCE_MS = 5000; // NTP 微调会让 ts 小幅回退，容差内不算回拨；超过就是回拨或被重排

/** 逐条判据。prev 为上一行条目（首行为 null）—— 传整个条目而不是只传上一行哈希， 是因为时钟回拨也必须在这里判：ts 倒退会让"落错文件/链错乱"看起来像篡改， 而它其实是运维事故（NTP 跳变）。报出来才能让人去查时钟，而不是去查有没有人动过清单。 / */
const entryProblemsOf = (entry, prev) => {
  const out = [];
  const expectedPrev = prev ? prev.chainHash : GENESIS;
  if (prev) {
    const backMs = toEpochMs(prev.ts) - toEpochMs(entry.ts); // 时间口径走 helpers：裸 Date.parse 是 dateParamGateSingleSource 的禁形
    // 容差内是 NTP 微调，超过才是回拨（或有人重排）
    if (Number.isFinite(backMs) && backMs > CLOCK_SKEW_TOLERANCE_MS) {
      out.push({
        type: 'clock_skew',
        line: entry.__line,
        message: `第 ${entry.__line} 行时间比上一行早 ${backMs}ms：时钟回拨或被重排`,
      });
    }
  }
  if (entry.prevChainHash !== expectedPrev) {
    out.push({
      type: 'chain_broken',
      line: entry.__line,
      message: `prevChainHash 与上一行 chainHash 不一致（期望 ${String(expectedPrev).slice(0, 12)}…）`,
    });
  }
  if (entry.v !== MANIFEST_VERSION)
    out.push({ type: 'hash_mismatch', line: entry.__line, message: `未知版本 ${entry.v}` });
  else if (recomputeOf(entry) !== entry.chainHash)
    out.push({ type: 'hash_mismatch', line: entry.__line, message: '重算的 chainHash 不符' });
  return out;
};

/** 尾部判据：只有拿到外部期望值时才可能发现"整段删尾"——清单内部对此无自证能力 */
const tailProblemsOf = (last, { expectedLastSeq, expectedLastChainHash }) => {
  const out = [];
  if (expectedLastSeq && last.lastSeq !== expectedLastSeq) {
    out.push({
      type: 'tail_truncated',
      line: last.__line,
      message: `末条 lastSeq=${last.lastSeq}，外部锚点记的是 ${expectedLastSeq}`,
    });
  }
  if (expectedLastChainHash && last.chainHash !== expectedLastChainHash) {
    out.push({
      type: 'tail_truncated',
      line: last.__line,
      message: '末条 chainHash 与外部锚点登记的不一致',
    });
  }
  return out;
};

/** 复核当日清单。三类篡改各有专型，不含糊成一句"有问题"： · hash_mismatch —— 行内字段与 chainHash 对不上（改了字段没重算哈希）；· chain_broken —— prevChainHash ≠ 上一行 chainHash（删行/换序/整段搬走）；· tail_truncated —— 末尾比"应该到的"短。纯删尾在链内**天然自洽**，必须靠外部期望值（每日审计事件登记的末条 seq/chainHash）才发现——这条限制写在返回值里，不假装能自证。 / / */
function verifyManifest({
  dir = MANIFEST_DIR,
  date = new Date(),
  expectedLastSeq = null,
  expectedLastChainHash = null,
} = {}) {
  const { entries, badLines, exists } = readManifest({ dir, date });
  const problems = [];
  // 文件存在但一行都没有 ≠ 干净：最彻底的篡改（把当天全部批次抹掉）正是这个形状。首版把它判成 ok:true/count:0，等于"删干净 = 通过"。
  if (exists && entries.length === 0 && badLines.length === 0) {
    problems.push({
      type: 'empty_manifest',
      line: null,
      message: '清单文件存在但没有任何批次：要么当天确实无捕获（应无文件），要么已被清空',
    });
  }
  if (!exists)
    problems.push({
      type: 'file_missing',
      line: null,
      message: `当日清单文件不存在：${filePathOf(dir, date)}`,
    });
  for (const bad of badLines)
    problems.push({ type: 'unparsable_line', line: bad.line, message: '该行解析不出条目' });
  problems.push(
    ...entries.flatMap((entry, idx) => entryProblemsOf(entry, idx === 0 ? null : entries[idx - 1]))
  );

  const last = entries.length ? entries[entries.length - 1] : null;
  if (last) problems.push(...tailProblemsOf(last, { expectedLastSeq, expectedLastChainHash }));

  return {
    ok: problems.length === 0,
    problems,
    count: entries.length,
    lastChainHash: last ? last.chainHash : GENESIS,
    lastSeq: last ? last.lastSeq : null,
  };
}

/** 每日锚点：把某天的末条 chainHash / lastSeq / 批数写进审计链。 为什么必须是**审计链**而不是同一个 manifest 文件：两者同主权边界时， "连清单一起改"只需要改一个地方。钉进审计链后，伪造必须在两个不同结构里同时成立，且审计链自身有 prevHash/hmac 串起来——这才是"删尾可判"的依据（清单内部无自证能力）。 幂等口径：一天一条（以 dateKey 为业务日），由调用方记 lastAnchorDateKey 防重复追加。写失败不抛（调用方是定时任务，抛出去只会让定时器停掉、从此不再留痕）。 / / */
async function writeDailyAnchor({
  dir = MANIFEST_DIR,
  date = new Date(),
  username = 'system',
  model = null,
} = {}) {
  // 模型可注入：调度侧不传则惰性取真模型；用例传桩件即可断言"写了什么"，不必去 mock 模块解析（isolateModules 对已加载模块不生效，实测假绿）。
  const AuditLog = model || require('../models/AuditLog');
  const dateKey = dateKeyOf(date);
  // 当天还没有任何清单文件 ⇒ **不写锚点**，也不让调用方把它记成"已锚定"。实测缺陷：跨日 00:05 的首个 tick 会写一条 batches:0/ok:false 的锚点并置 lastAnchorDateKey，当天 10:00 真正产生的批次从此永远不被锚定——锚点机制整天失效且看起来"跑过了"。
  if (!readManifest({ dir, date }).exists) return { written: false, reason: 'empty_day' };
  const v = verifyManifest({ dir, date });
  const body = {
    dateKey,
    batches: v.count,
    lastSeq: v.lastSeq,
    lastChainHash: v.lastChainHash,
    ok: v.ok,
    problems: v.problems.map((p) => `${p.type}@${p.line ?? '-'}`).slice(0, 20),
  };
  try {
    await AuditLog.create({
      action: 'forensic_capture_manifest',
      category: 'security',
      username,
      body,
      success: true,
      riskLevel: v.ok ? 'low' : 'high', // 清单自查不通过 ⇒ 高危：这条锚点的价值全在"当天可证明"上，记成 low 会让一批"验了但没验成"的绿记录留在留存里。
    });
    return { written: true, body };
  } catch (e) {
    state.anchorFailures = (state.anchorFailures || 0) + 1;
    warnRateLimited(`取证清单每日锚点写入失败（累计 ${state.anchorFailures} 次）：${errText(e)}`);
    return { written: false, reason: 'anchor_write_failed', body };
  }
}

function getManifestStats() {
  return {
    written: state.written,
    writeFailures: state.writeFailures,
    anchorFailures: state.anchorFailures || 0,
    lastError: state.lastError,
  };
}

function resetManifestState() {
  state.writeFailures = 0;
  state.written = 0;
  state.anchorFailures = 0;
  state.lastError = null;
  state.lastWarnAt = 0;
}

module.exports = {
  MANIFEST_VERSION,
  MANIFEST_DIR,
  GENESIS,
  dateKeyOf,
  batchEntryOf,
  appendBatch,
  readManifest,
  verifyManifest,
  writeDailyAnchor,
  getManifestStats,
  resetManifestState,
};
