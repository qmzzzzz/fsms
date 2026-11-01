/**
 * 取证捕获的独立 WAL 文件层（P2，2026-10-31）
 *
 * 为什么不复用 auditBufferWal：审计 WAL 背负"审计记录不可丢"的承诺（durable 行、
 * 毒批归档、按序号精确裁剪），取证捕获是**尽力而为**的增强证据，容量语义相反——
 * 超过 FORENSIC_WAL_CAP_BYTES 时丢最旧一半并计数告警（任务书 §1.3 的容量退让），
 * 不能把两套承诺揉进一个计数器。路径派生复用 auditWalPath 的库名隔离口径。
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { errText } = require('../utils/auditWriteFailure');
const { readPositiveNumberEnv } = require('../utils/envNumber');
const { deriveDefaultWalPathInfo } = require('./auditWalPath');
const walPerm = require('./auditWalPermissions');

const DEFAULT_CAP_BYTES = 50 * 1024 * 1024;
const STAT_INTERVAL_DEFAULT = 32;

/** 默认路径按目标库名派生（与 audit-buffer 同一隔离粒度，避免多库共写一份文件） */
const resolveWalPath = () => {
  const info = deriveDefaultWalPathInfo();
  const base = path.join(__dirname, '../../logs/forensic-capture');
  return info.dbName ? `${base}.${info.dbName}.wal` : `${base}.wal`;
};

let walPath = resolveWalPath();
let walEnabled = false;
let walChain = Promise.resolve();
const RUN_ID =
  process.pid.toString(36) + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
let seqCounter = 0;
let appendCount = 0;
let walDroppedLines = 0;
let walAppendFailures = 0;
let walTrimFailures = 0;
let walCorruptLines = 0;
let walMaxBytesWarnedFor = null;

const getWalMaxBytes = () =>
  readPositiveNumberEnv('FORENSIC_WAL_CAP_BYTES', DEFAULT_CAP_BYTES, {
    onInvalid: (name, raw, fallback) => {
      if (walMaxBytesWarnedFor === raw) return;
      walMaxBytesWarnedFor = raw;
      logger.error(
        `${name}=${JSON.stringify(raw)} 非法（须为正的字节数），已按默认 ${fallback} 处理`
      );
    },
  });

const getStatInterval = () =>
  readPositiveNumberEnv('FORENSIC_WAL_STAT_INTERVAL', STAT_INTERVAL_DEFAULT, {
    integer: true,
    onInvalid: (name, raw) =>
      logger.warn(
        `${name}=${JSON.stringify(raw)} 非法（须为正的抽查间隔），已按默认 ${STAT_INTERVAL_DEFAULT} 处理`
      ),
  });

const getWalPath = () => walPath;

async function readRecordsStrict() {
  let content;
  try {
    content = await fs.promises.readFile(walPath, 'utf8');
  } catch (e) {
    if (e?.code !== 'ENOENT') throw e;
    return null;
  }
  if (!content) return { records: [], content: '' };
  const parts = content.split('\n');
  const hasTrailing = parts[parts.length - 1] === '';
  return { records: hasTrailing ? parts.slice(0, -1) : parts, content };
}

async function atomicReplace(nextContent) {
  const tmpPath = walPath + '.tmp';
  await fs.promises.writeFile(tmpPath, nextContent, { encoding: 'utf8', mode: 0o600 });
  await fs.promises.rename(tmpPath, walPath);
}

const walSeqOf = (line) => {
  try {
    const doc = JSON.parse(line);
    return doc && doc.__walSeq ? doc.__walSeq : null;
  } catch {
    return null;
  }
};

/** 超过硬上限：丢最旧一半并归档到 .discarded（永不回灌），计数 + 限频 warn */
async function enforceWalCap() {
  let stat;
  try {
    stat = await fs.promises.stat(walPath);
  } catch (e) {
    if (e?.code !== 'ENOENT') {
      walTrimFailures += 1;
      logger.warn(`取证 WAL 大小检查失败（累计 ${walTrimFailures} 次）：${errText(e)}`);
    }
    return;
  }
  const maxBytes = getWalMaxBytes();
  if (stat.size <= maxBytes) return;
  let wal;
  try {
    wal = await readRecordsStrict();
  } catch (e) {
    walTrimFailures += 1;
    logger.error(`取证 WAL 已超限但读不回内容，本轮未裁剪：${errText(e)}`);
    return;
  }
  if (!wal || wal.records.length < 2) return;
  const dropCount = Math.floor(wal.records.length / 2);
  const dropped = wal.records.slice(0, dropCount);
  const kept = wal.records.slice(dropCount);
  try {
    await fs.promises.appendFile(walPath + '.discarded', dropped.join('\n') + '\n', {
      encoding: 'utf8',
      mode: 0o600,
    });
  } catch (e) {
    walTrimFailures += 1;
    logger.error(`取证 WAL 超限裁剪前归档失败：${errText(e)}——本轮不裁剪，主文件继续超限`);
    return;
  }
  try {
    await atomicReplace(kept.length ? kept.join('\n') + '\n' : '');
  } catch (e) {
    walTrimFailures += 1;
    logger.error(`取证 WAL 超限裁剪回写失败（累计 ${walTrimFailures} 次）：${errText(e)}`);
    return;
  }
  walDroppedLines += dropped.length;
  logger.error(
    `取证 WAL 超过硬上限（${stat.size} > ${maxBytes} 字节），已丢弃最旧 ${dropped.length} 行` +
      `（归档到 ${walPath}.discarded，累计 ${walDroppedLines} 行）——取证证据出现缺口，请扩容或缩短保留期`
  );
}

/** 追加一行（串行化，失败只计数不抛：取证失败不得影响业务响应） */
function appendLine(line) {
  if (!walEnabled) return;
  const payload = typeof line === 'string' && line.endsWith('\n') ? line : `${line}\n`;
  walChain = walChain
    .then(() => fs.promises.appendFile(walPath, payload, { encoding: 'utf8', mode: 0o600 }))
    .catch((e) => {
      walAppendFailures += 1;
      logger.warn(
        `取证 WAL 追加失败（累计 ${walAppendFailures} 次）：${errText(e)}——本条取证记录只有内存态`
      );
    })
    .then(() => {
      appendCount += 1;
      if (appendCount % getStatInterval() !== 0) return undefined;
      return enforceWalCap();
    })
    .catch((e) => logger.warn(`取证 WAL 追加链后续操作失败：${errText(e)}`));
}

/** 按 __walSeq 精确移除已落库的行（不归档：它们已在库里） */
function trimBySeqs(seqs) {
  const seqSet = seqs instanceof Set ? seqs : new Set(seqs);
  if (seqSet.size === 0) return;
  walChain = walChain
    .then(async () => {
      const wal = await readRecordsStrict();
      if (!wal || wal.records.length === 0) return 0;
      const kept = [];
      let removed = 0;
      for (const line of wal.records) {
        const seq = walSeqOf(line);
        if (seq && seqSet.has(seq)) removed += 1;
        else kept.push(line);
      }
      if (removed === 0) return 0;
      await atomicReplace(kept.length ? kept.join('\n') + '\n' : '');
      return removed;
    })
    .catch((e) => logger.warn(`取证 WAL 裁剪失败：${errText(e)}`));
}

/** 启动重放：读出全部行（损坏行计数并跳过，不猜内容） */
async function readLines() {
  let wal;
  try {
    wal = await readRecordsStrict();
  } catch (e) {
    logger.error(`取证 WAL 启动重放读不回文件：${errText(e)}——本轮不重放`);
    return [];
  }
  if (!wal) return [];
  const out = [];
  for (const line of wal.records) {
    if (!line) continue;
    try {
      const doc = JSON.parse(line);
      if (doc && typeof doc === 'object' && !Array.isArray(doc))
        out.push(doc); // 只认对象：数组/标量是残缺写入，不得重放
      else {
        walCorruptLines += 1;
      }
    } catch {
      walCorruptLines += 1;
    }
  }
  if (walCorruptLines > 0 && out.length + walCorruptLines === wal.records.length) {
    logger.error(
      `取证 WAL 有 ${walCorruptLines} 行解析不出记录（累计 ${walCorruptLines} 行）：${walPath}——这些行不会重放，请取原件核查`
    );
  }
  return out;
}

/** 启动：重指向路径（env 优先）、确保目录可写、开启写入 */
function startup(envPath) {
  walPath = envPath || resolveWalPath();
  const writable = walPerm.ensureWalDirWritable(walPath);
  walPerm.hardenWalArtifacts(walPath);
  walEnabled = writable;
  if (!writable) {
    logger.error(
      `取证 WAL 未启用：${walPath} 不可写。取证记录仍进内存缓冲，崩溃窗口内的记录会丢失`
    );
  }
  return writable;
}

function disable() {
  walEnabled = false;
}

const isEnabled = () => walEnabled;

function assignSeq(doc) {
  if (!walEnabled || doc.__walSeq) return;
  seqCounter += 1;
  doc.__walSeq = `${RUN_ID}-${seqCounter}`;
}

/** 排空串行链（优雅关闭用） */
async function drain() {
  await walChain.catch(() => {});
}

function serialize(fn, onError) {
  walChain = walChain
    .then(fn)
    .catch(onError || ((e) => logger.warn(`取证 WAL 链上操作失败：${errText(e)}`)));
  return walChain;
}

function getStats() {
  return { walEnabled, walDroppedLines, walAppendFailures, walTrimFailures, walCorruptLines };
}

function resetCounters() {
  appendCount = 0;
  walDroppedLines = 0;
  walAppendFailures = 0;
  walTrimFailures = 0;
  walCorruptLines = 0;
}

module.exports = {
  startup,
  disable,
  isEnabled,
  assignSeq,
  appendLine,
  trimBySeqs,
  readLines,
  serialize,
  drain,
  getWalPath,
  getStats,
  resetCounters,
};
