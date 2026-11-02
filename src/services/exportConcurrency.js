/**
 * 报表导出并发闸
 *
 * ## 缺陷
 * `/api/reports/export` **必须**有并发上限：`writeExportWorkbook` 对每个请求把命中的行全部
 * `addRow` 进工作表、再整包序列化（同步 CPU）——峰值与「并发人数 × 单次行数」成正比。
 * 自研写入器（utils/xlsxWriter）单次常驻远小于 exceljs 的单元格对象模型（实测 5000 行
 * 整包 0.17 MB），但判据是那个**乘积**：十几个并发仍能把进程推过容器内存限制，而失败形态
 * 是 OOM 杀死整个进程——连不导出的人一起掉线；导出低频、可重试，不该有同等并发权。
 *
 * ## 策略（用户 2026-10-26 拍板：上限 2 + 有界排队）
 * - 上限：`EXPORT_MAX_CONCURRENCY`，默认 **2**。导出是 CPU/内存重活，2 个并发已能
 *   吃满单核的 zip 压缩与行转换，再多只是把内存峰值线性放大。
 * - 排队：超出上限的请求**不立即失败**，进有界队列等槽位（导出常在页面上点一次就走，
 *   直接回 429 的体验是"偶发失败"，而排队 3 秒拿到文件是"慢一点但成功"）。
 * - 队列上限：`EXPORT_MAX_QUEUE`，默认 **8**。没有队列上限的"有界等待"是自欺——
 *   100 个请求同时进来就变成 100 个连接挂着等 30 秒，内存没省、连接还被占满。
 * - 排队超时：`EXPORT_QUEUE_TIMEOUT_MS`，默认 **30000**。超时回 429 + `Retry-After`，
 *   让客户端知道"不是坏了，是忙"。
 *
 * 三个值都读环境变量并在**每次 acquire 时**读取：导出路径不在热循环里，多读三次
 * `process.env` 的成本可以忽略，换来的是测试不必重置模块、运维改配置后新请求即生效。
 * 取值一律**钳制**到安全区间：`EXPORT_MAX_CONCURRENCY=0` 会让所有导出永久 429
 * （比 OOM 更隐蔽的可用性事故），而 `=10000` 等于没设。
 *
 * ## 为什么单独成文件
 * `reportController` 的行数/复杂度贴着棘轮红线；且这段状态机需要**独立证伪**
 * （槽位转移、超时与释放的先后、幂等释放），塞进控制器只能靠 HTTP 间接测。
 *
 * ## 指标
 * 状态变化即推送 `utils/metricsRuntime`（`export_inflight` / `export_queued` /
 * `export_rejected_total{reason}`）。不在这里自己渲染文本：指标口径只有一处，
 * 否则 `/metrics` 与 JSON 快照会各说各话（本仓反复踩过的那类"同一条判据的第二处实现"）。
 */

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

// 正在占用槽位的导出数。**包含**已被移交给排队者的槽位：移交时 active 不变，
// 只有真正空出来的槽位才减一（否则排队者在"拿到槽位"的瞬间会短暂超过上限）。
let active = 0;
/** @type {{resolve: (granted: boolean) => void, timer: NodeJS.Timeout}[]} */
const waiters = [];
const rejected = { queue_full: 0, timeout: 0 };

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
  runtimeMetrics.setExportGauges({ inflight: active, queued: waiters.length });
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
function makeRelease() {
  let released = false;
  return function release() {
    if (released) return;
    released = true;
    const next = waiters.shift();
    if (next) {
      // 槽位**移交**而不是"先减再加"：中间那一瞬会让新请求看到空槽位并插队
      clearTimeout(next.timer);
      next.resolve(true);
    } else {
      active = Math.max(0, active - 1);
    }
    syncGauges();
  };
}

/**
 * 申请一个导出槽位。
 *
 * @returns {Promise<() => void>} 释放函数（必须调用，通常放 finally）
 * @throws {ExportBusyError} 队列已满（立即）或排队超时
 */
async function acquireExportSlot() {
  const { max, queue, timeoutMs } = currentLimits();

  if (active < max) {
    active += 1;
    syncGauges();
    return makeRelease();
  }

  if (waiters.length >= queue) {
    rejected.queue_full += 1;
    runtimeMetrics.incExportRejected('queue_full');
    syncGauges();
    throw new ExportBusyError('queue_full', Math.ceil(timeoutMs / 1000));
  }

  const granted = await new Promise((resolve) => {
    const waiter = { resolve, timer: null };
    waiter.timer = setTimeout(() => {
      const idx = waiters.indexOf(waiter);
      // 已被 release 移交（定时器与移交在同一 tick 内竞争）时不能重复 resolve：
      // resolve 本身幂等，但这里若继续走超时分支会把"已授予"记成一次拒绝。
      if (idx < 0) return;
      waiters.splice(idx, 1);
      rejected.timeout += 1;
      runtimeMetrics.incExportRejected('timeout');
      syncGauges();
      resolve(false);
    }, timeoutMs);
    // 队列定时器不得钉住进程退出：导出队列不该成为 shutdown 的阻塞源
    if (typeof waiter.timer.unref === 'function') waiter.timer.unref();
    waiters.push(waiter);
    syncGauges();
  });

  if (!granted) throw new ExportBusyError('timeout', Math.ceil(timeoutMs / 1000));
  // 槽位由 release 移交，active 保持不变（见文件头注释）
  return makeRelease();
}

/** 仅供测试：清空队列与计数（生产不调用） */
function __resetForTest() {
  for (const waiter of waiters) {
    clearTimeout(waiter.timer);
    waiter.resolve(false);
  }
  waiters.length = 0;
  active = 0;
  rejected.queue_full = 0;
  rejected.timeout = 0;
  warned.clear();
  syncGauges();
}

/** 当前状态快照（供测试与诊断日志；指标文本由 metricsRuntime 渲染） */
function snapshot() {
  return {
    ...currentLimits(),
    inflight: active,
    queued: waiters.length,
    rejected: { ...rejected },
  };
}

module.exports = {
  DEFAULTS,
  BOUNDS,
  REJECT_REASONS,
  ExportBusyError,
  acquireExportSlot,
  currentLimits,
  snapshot,
  __resetForTest,
};
