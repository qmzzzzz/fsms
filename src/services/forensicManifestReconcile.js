// 清单↔库对账：三种形态的判据口径、能力边界、只读原则与周期接线见 docs/forensic-manifest-reconcile.md
const manifest = require('./forensicManifest');
const manifestPrune = require('./forensicManifestPrune');
const logger = require('../utils/logger');
const { businessDayBounds } = require('../constants/timezone');
const { resolveBusinessRetention } = require('../constants/businessRetention');

const BATCH = 5000; // 分批发 IN：单日 4 万条量级时不能一次全塞进 $in，也不能退化成逐条查询

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;
const MIN_INTERVAL_MS = 5 * 60 * 1000;
const MAX_INTERVAL_MS = 24 * 60 * 60 * 1000;

const chunk = (arr, size) => {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
};

const manifestKeepDays = () => {
  const v = Number.parseInt(process.env.FORENSIC_MANIFEST_KEEP_DAYS || '', 10);
  return Number.isFinite(v) && v > 0 ? v : manifestPrune.DEFAULT_KEEP_DAYS;
};

function resolveReconcileWindowDays() {
  const retention = resolveBusinessRetention('ForensicCapture');
  const ttlDays = retention.enabled ? retention.effectiveDays : Infinity;
  return Math.min(ttlDays, manifestKeepDays());
}

const isBeyondWindow = (dateKey, windowDays, now) =>
  dateKey < manifest.dateKeyOf(new Date(now.getTime() - windowDays * 86400000));

async function reconcileWithDb({
  dir,
  date = new Date(),
  model = null,
  windowDays,
  now = new Date(),
} = {}) {
  const effectiveWindow =
    Number.isFinite(windowDays) && windowDays > 0 ? windowDays : resolveReconcileWindowDays();
  const dateKey = manifest.dateKeyOf(date);
  if (isBeyondWindow(dateKey, effectiveWindow, now)) {
    logger.info(
      `取证对账跳过 ${dateKey}：超出对账窗口（${effectiveWindow} 天 = min(TTL, manifest 保留期)），` +
        '该日期的库内数据/清单可能已被保留期回收，无从对账'
    );
    return {
      ok: true,
      checked: 0,
      declared: 0,
      shortfall: 0,
      unmanifested: 0,
      skippedBeyondTtl: 1,
      problems: [],
    };
  }

  const ForensicCapture = model || require('../models/ForensicCapture');
  const problems = [];
  const read = manifest.readManifest(dir ? { dir, date } : { date });
  if (!read.exists || read.entries.length === 0) {
    problems.push({
      type: 'no_manifest',
      line: null,
      message: '当日清单不存在或为空：无法与库对账（这不等于一致）',
    });
    return {
      ok: false,
      checked: 0,
      declared: 0,
      shortfall: 0,
      unmanifested: 0,
      skippedBeyondTtl: 0,
      problems,
    };
  }

  const declared = read.entries.reduce((sum, e) => sum + (e.count || 0), 0);
  // 按**业务日**整天取库：seq 是 'RUN-序号' 字符串，字典序在 r-10/r-2 上会错，拿它做 $gte/$lte 区间会漏记录（B-2）。用 createdAt 落在业务日窗口内才可靠。
  const bounds = businessDayBounds(dateKey);
  const docs = await ForensicCapture.find(
    { createdAt: { $gte: bounds.start, $lte: bounds.end } },
    { recordHash: 1, _id: 0 }
  ).lean();
  const present = new Set(docs.map((d) => d.recordHash).filter(Boolean));

  const shortfall = Math.max(0, declared - present.size);
  if (shortfall > 0) {
    problems.push({
      type: 'record_missing',
      line: null,
      message: `清单声明 ${declared} 条，当天库内只有 ${present.size} 条（少 ${shortfall} 条）`,
    });
  }
  const unmanifested = Math.max(0, present.size - declared);

  return {
    ok: problems.length === 0,
    checked: present.size,
    declared,
    shortfall,
    unmanifested,
    skippedBeyondTtl: 0,
    problems,
  };
}

let reconcileTimer = null;
/** 轮转游标：0=昨天、1=前天……在窗口内循环（见文件头「每轮只核一个业务日」） */
let cursorOffset = 0;
const health = {
  runs: 0,
  failures: 0,
  skippedBeyondTtl: 0,
  lastRunAt: null,
  lastCheckedKey: null,
  lastError: null,
};

function readIntervalMs() {
  const v = Number.parseInt(process.env.FORENSIC_RECONCILE_INTERVAL_MS || '', 10);
  if (!Number.isFinite(v) || v <= 0) return DEFAULT_INTERVAL_MS;
  return Math.min(Math.max(v, MIN_INTERVAL_MS), MAX_INTERVAL_MS);
}

async function reconcileOnce() {
  const windowDays = resolveReconcileWindowDays();
  const offset = (cursorOffset % Math.max(windowDays, 1)) + 1; // 1=昨天起步
  cursorOffset += 1;
  const date = new Date(Date.now() - offset * 86400000);
  try {
    const result = await reconcileWithDb({ date, windowDays });
    health.runs += 1;
    health.lastRunAt = new Date().toISOString();
    health.lastCheckedKey = manifest.dateKeyOf(date);
    health.skippedBeyondTtl += result.skippedBeyondTtl || 0;
    if (!result.ok) {
      health.failures += 1;
      logger.warn(
        `取证清单↔库对账未通过（${health.lastCheckedKey}）：${JSON.stringify(result.problems)}`
      );
    }
    return result;
  } catch (e) {
    health.runs += 1;
    health.failures += 1;
    health.lastError = String((e && e.message) || e);
    logger.error(`取证清单↔库对账执行失败：${health.lastError}`);
    return null;
  }
}

function start() {
  if (reconcileTimer) return;
  const intervalMs = readIntervalMs();
  reconcileTimer = setInterval(() => {
    reconcileOnce().catch(() => {}); // reconcileOnce 自身已兜错；这层只兜 logger 侧意外
  }, intervalMs);
  if (reconcileTimer && reconcileTimer.unref) reconcileTimer.unref();
  logger.info(
    `取证清单↔库周期对账已启动：间隔 ${Math.round(intervalMs / 60000)} 分钟，` +
      `窗口 ${resolveReconcileWindowDays()} 天（每轮轮转核一个业务日，当日除外）`
  );
}

function stop() {
  if (reconcileTimer) {
    clearInterval(reconcileTimer);
    reconcileTimer = null;
  }
}

const getReconcileHealth = () => ({ ...health, running: Boolean(reconcileTimer) });

const resetForTest = () => {
  stop();
  cursorOffset = 0;
  health.runs = 0;
  health.failures = 0;
  health.skippedBeyondTtl = 0;
  health.lastRunAt = null;
  health.lastCheckedKey = null;
  health.lastError = null;
};

module.exports = {
  BATCH,
  chunk,
  reconcileWithDb,
  resolveReconcileWindowDays,
  reconcileOnce,
  start,
  stop,
  getReconcileHealth,
  resetForTest,
};
