// 报表导出并发闸：缺陷、策略（上限 2 + 有界排队）、分池与指标口径见 docs/export-concurrency.md

'use strict';

const runtimeMetrics = require('../utils/metricsRuntime');

/** 默认值与硬护栏（护栏是"环境变量写错时不至于把导出打死或放开"） */
const DEFAULTS = { max: 2, queue: 8, timeoutMs: 30000 };
const BOUNDS = {
  max: { min: 1, max: 8 },
  queue: { min: 0, max: 64 },
  timeoutMs: { min: 1000, max: 300000 },
};

/** 拒绝原因的闭合集合：与 metricsRuntime 的 EXPORT_REJECT_REASONS 同源（高基数纪律） */
const REJECT_REASONS = ['queue_full', 'timeout'];

/** 分池登记：闭合集合（fail-loud，拼错池名直接抛而非静默并入默认池） */
const POOLS = ['report-export', 'audit-export', 'forensic-export'];

/**
 * 每池独立状态。active **包含**已被移交给排队者的槽位：移交时 active 不变，
 * 只有真正空出来的槽位才减一（否则排队者在"拿到槽位"的瞬间会短暂超过上限）。
 * @type {Map<string, {active: number, waiters: {resolve: (granted: boolean) => void, timer: NodeJS.Timeout}[], rejected: {queue_full: number, timeout: number}}>}
 */
const pools = new Map();
for (const name of POOLS) {
  pools.set(name, { active: 0, waiters: [], rejected: { queue_full: 0, timeout: 0 } });
}

function poolState(poolName) {
  const state = pools.get(poolName);
  if (!state) {
    throw new Error(`未知导出池：${JSON.stringify(poolName)}（合法池：${POOLS.join('/')}）`);
  }
  return state;
}

/** 各池 gauge 求和（指标标签面不变，见文件头"指标"段） */
function totals() {
  let active = 0;
  let queued = 0;
  let queueFull = 0;
  let timeout = 0;
  for (const s of pools.values()) {
    active += s.active;
    queued += s.waiters.length;
    queueFull += s.rejected.queue_full;
    timeout += s.rejected.timeout;
  }
  return { active, queued, queueFull, timeout };
}

/**
 * 读取一个正整数环境变量并钳制到 [min, max]。
 * 非法值（非数字、NaN、Infinity）退回 fallback 而不是报错：
 * 导出闸的配置错误不该让整个服务起不来，但**必须**在日志里留痕（见 warnOnce）。
 */
function readClamped(name, fallback, { min, max }) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    warnOnce(name, raw);
    return fallback;
  }
  const floored = Math.floor(value);
  if (floored < min || floored > max) {
    warnOnce(name, raw);
    return Math.min(Math.max(floored, min), max);
  }
  return floored;
}

const warned = new Set();
/** 每个变量只喊一次：这是配置错误，不是每请求事件 */
function warnOnce(name, raw) {
  if (warned.has(name)) return;
  warned.add(name);
  try {
    // 惰性 require：logger → config → … 的加载链较长，本模块会被控制器在启动期加载，
    // 顶层引用会把导出闸挂进那条链里（A-1 的惰性环正是这么形成的）。
    require('../utils/logger').warn(
      `${name}=${JSON.stringify(raw)} 非法或越界，导出并发闸改用钳制后的值` +
        `（允许区间见 services/exportConcurrency.js 的 BOUNDS）`
    );
  } catch (_) {
    /* 日志不可用不影响闸本身 */
  }
}

/** 当前生效的三个限制（供测试与日志读取） */
function currentLimits() {
  return {
    max: readClamped('EXPORT_MAX_CONCURRENCY', DEFAULTS.max, BOUNDS.max),
    queue: readClamped('EXPORT_MAX_QUEUE', DEFAULTS.queue, BOUNDS.queue),
    timeoutMs: readClamped('EXPORT_QUEUE_TIMEOUT_MS', DEFAULTS.timeoutMs, BOUNDS.timeoutMs),
  };
}

function syncGauges() {
  const t = totals();
  runtimeMetrics.setExportGauges({ inflight: t.active, queued: t.queued });
}

/**
 * 并发已满时的拒绝信号。
 *
 * 用独立的 Error 子类而不是给普通 Error 挂 code：控制器需要 `instanceof` 判断，
 * 才能把「闸拒绝」与「导出过程本身出错」分开——后者必须继续走全局错误处理器
 * （500 + 脱敏日志），混成同一个分支会把真实故障说成"忙，请重试"。
 */
class ExportBusyError extends Error {
  /**
   * @param {'queue_full'|'timeout'} reason
   * @param {number} retryAfterSeconds
   */
  constructor(reason, retryAfterSeconds) {
    super(reason === 'queue_full' ? '导出任务繁忙：等待队列已满' : '导出任务繁忙：等待槽位超时');
    this.name = 'ExportBusyError';
    this.code = 'EXPORT_BUSY';
    this.reason = reason;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * 生成一次释放函数（幂等）。
 *
 * 幂等不是洁癖：控制器里 release 挂在 `finally`，而 `writeExportWorkbook` 在客户端
 * 中断时会抛错——异常路径与正常路径都会走到 finally，将来若有人再包一层 try/finally
 * 就会重复释放。重复释放会让 active 减两次，等于把上限悄悄放大一倍。
 */
function makeRelease(pool) {
  let released = false;
  return function release() {
    if (released) return;
    released = true;
    const next = pool.waiters.shift();
    if (next) {
      // 槽位**移交**而不是"先减再加"：中间那一瞬会让新请求看到空槽位并插队
      clearTimeout(next.timer);
      next.resolve(true);
    } else {
      pool.active = Math.max(0, pool.active - 1);
    }
    syncGauges();
  };
}

/**
 * 申请一个导出槽位。
 *
 * @param {string} [poolName='report-export'] 池名（闭合集合，见 POOLS）；
 *   省略即报表导出池——存量调用方零改动。
 * @returns {Promise<() => void>} 释放函数（必须调用，通常放 finally）
 * @throws {ExportBusyError} 队列已满（立即）或排队超时
 */
async function acquireExportSlot(poolName = 'report-export') {
  const pool = poolState(poolName);
  const { max, queue, timeoutMs } = currentLimits();

  if (pool.active < max) {
    pool.active += 1;
    syncGauges();
    return makeRelease(pool);
  }

  if (pool.waiters.length >= queue) {
    pool.rejected.queue_full += 1;
    runtimeMetrics.incExportRejected('queue_full');
    syncGauges();
    throw new ExportBusyError('queue_full', Math.ceil(timeoutMs / 1000));
  }

  const granted = await new Promise((resolve) => {
    const waiter = { resolve, timer: null };
    waiter.timer = setTimeout(() => {
      const idx = pool.waiters.indexOf(waiter);
      // 已被 release 移交（定时器与移交在同一 tick 内竞争）时不能重复 resolve：
      // resolve 本身幂等，但这里若继续走超时分支会把"已授予"记成一次拒绝。
      if (idx < 0) return;
      pool.waiters.splice(idx, 1);
      pool.rejected.timeout += 1;
      runtimeMetrics.incExportRejected('timeout');
      syncGauges();
      resolve(false);
    }, timeoutMs);
    // 队列定时器不得钉住进程退出：导出队列不该成为 shutdown 的阻塞源
    if (typeof waiter.timer.unref === 'function') waiter.timer.unref();
    pool.waiters.push(waiter);
    syncGauges();
  });

  if (!granted) throw new ExportBusyError('timeout', Math.ceil(timeoutMs / 1000));
  // 槽位由 release 移交，active 保持不变（见文件头注释）
  return makeRelease(pool);
}

/** 仅供测试：清空队列与计数（生产不调用） */
function __resetForTest() {
  for (const pool of pools.values()) {
    for (const waiter of pool.waiters) {
      clearTimeout(waiter.timer);
      waiter.resolve(false);
    }
    pool.waiters.length = 0;
    pool.active = 0;
    pool.rejected.queue_full = 0;
    pool.rejected.timeout = 0;
  }
  warned.clear();
  syncGauges();
}

/** 当前状态快照（供测试与诊断日志；指标文本由 metricsRuntime 渲染）。分池后为各池之和 */
function snapshot() {
  const t = totals();
  return {
    ...currentLimits(),
    inflight: t.active,
    queued: t.queued,
    rejected: { queue_full: t.queueFull, timeout: t.timeout },
  };
}

module.exports = {
  DEFAULTS,
  BOUNDS,
  POOLS,
  REJECT_REASONS,
  ExportBusyError,
  acquireExportSlot,
  currentLimits,
  snapshot,
  __resetForTest,
};
