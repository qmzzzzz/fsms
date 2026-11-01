'use strict';

/**
 * bcrypt worker 线程池：hash / compare / genSalt 的同形异步门面
 *
 * bcryptjs 的异步 API 只是把同步计算切片让出事件循环，CPU 仍在主线程上；本模块把计算
 * 卸载到常驻 worker（数量 = min(CPU, 4)，`BCRYPT_WORKERS` 覆盖），主线程只做消息往返。
 *
 * 回退进程内 bcryptjs 的条件（保持测试与可用性语义）：
 * - 测试环境（NODE_ENV=test / JEST_WORKER_ID / VITEST）与
 *   `BCRYPT_WORKER_THREADS=0`：现有测试用 jest.mock('bcryptjs') 数调用次数
 *   （loginTimingParity 的时序侧信道判据），跨线程后 mock 不生效；
 * - worker 初始化/运行失败：登录可用性优先于性能。
 * 两种实现的 Promise 形态一致，调用方零语义改动。
 *
 * 关停：worker 全部 unref()，不阻止进程退出；关停期间的在途 compare 随线程
 * 销毁，与进程内实现的崩溃语义等价，index.js 的精细关停无需感知本池。
 */
const os = require('os');
const path = require('path');

const WORKER_FILE = path.join(__dirname, 'bcryptWorkerThread.js');

const isTestEnv = () =>
  process.env.NODE_ENV === 'test' ||
  Boolean(process.env.JEST_WORKER_ID) ||
  Boolean(process.env.VITEST);

const offloadEnabled = () => {
  if (process.env.BCRYPT_WORKER_THREADS === '0') return false;
  if (process.env.BCRYPT_WORKER_THREADS === '1') return true;
  return !isTestEnv();
};

const resolvePoolSize = () => {
  const configured = parseInt(process.env.BCRYPT_WORKERS, 10);
  if (Number.isFinite(configured) && configured > 0) return Math.min(configured, 16);
  return Math.max(1, Math.min(os.cpus().length, 4));
};

/** 进程内兜底：懒加载，让测试环境的 jest.mock 仍能拦截到 bcryptjs */
const runInline = (op, args) => {
  const bcrypt = require('bcryptjs');
  return bcrypt[op](...args);
};

let pool = null;
let initFailed = false;

const ensurePool = () => {
  if (!offloadEnabled() || initFailed) return null;
  if (pool) return pool;

  try {
    const { Worker } = require('worker_threads');
    const workers = [];
    const queue = [];

    const pump = () => {
      // 一个 worker 同时只跑一个任务：bcryptjs 的异步实现内部靠切片调度，
      // 同线程并发多个任务只会互相拖长尾延迟，收益为负。
      const idle = workers.find((entry) => entry.inflight.size === 0);
      if (!idle || queue.length === 0) return;
      const task = queue.shift();
      const id = idle.seq++;
      idle.inflight.set(id, task);
      idle.worker.postMessage({ id, op: task.op, args: task.args });
    };

    for (let i = 0; i < resolvePoolSize(); i++) {
      const worker = new Worker(WORKER_FILE);
      const entry = { worker, inflight: new Map(), seq: 0 };

      worker.on('message', (msg) => {
        if (!msg || typeof msg.id !== 'number') return;
        const task = entry.inflight.get(msg.id);
        if (!task) return;
        entry.inflight.delete(msg.id);
        if (msg.ok) task.resolve(msg.result);
        else task.reject(new Error(msg.error));
        pump();
      });

      // 线程崩溃：在途任务按失败结算并摘除该 worker；全灭则置 initFailed 永久回退
      // 进程内实现（比反复重建线程池更可预期，且登录路径绝不能因池问题而 500）。
      const kill = (label) => {
        for (const task of entry.inflight.values()) {
          task.reject(new Error(`bcrypt worker ${label}`));
        }
        entry.inflight.clear();
        const idx = workers.indexOf(entry);
        if (idx !== -1) workers.splice(idx, 1);
        if (workers.length === 0) {
          initFailed = true;
          pool = null;
          // 崩溃时排队的任务直接走进程内兜底，避免悬挂
          while (queue.length > 0) {
            const task = queue.shift();
            Promise.resolve()
              .then(() => runInline(task.op, task.args))
              .then(task.resolve, task.reject);
          }
        }
        pump();
      };

      worker.on('error', (error) => {
        const logger = require('../utils/logger');
        logger.warn(`bcrypt worker 异常（回退进程内实现）：${error?.message ?? error}`);
        kill('error');
      });
      worker.on('exit', (code) => {
        if (code !== 0) kill(`exit(${code})`);
      });

      // 必须排在全部监听之后：给 MessagePort 加 message 监听会把端口重新 ref 住，
      // 先 unref 再挂监听等于没 unref —— 短命进程（脚本 / CLI / CI 种子）将永不退出。
      worker.unref();

      workers.push(entry);
    }

    pool = { workers, queue, pump };
    return pool;
  } catch (error) {
    initFailed = true;
    return null;
  }
};

/** 排队上限（审计 2026-11-02 P3-2）：池吞吐 ≈ workers×(1/250ms)，全站 bcrypt 路径
 * 虽各有独立限流，但容量闸不该依赖"上游都守规矩"的自觉。超限直接走 runInline——
 * 与线程池初始化失败的兜底同一出口（主线程阻塞退化为主线程算，语义一致）。 */
const QUEUE_MAX = 256;

const run = (op, args) => {
  const p = ensurePool();
  if (!p || p.queue.length >= QUEUE_MAX) return runInline(op, args);
  return new Promise((resolve, reject) => {
    p.queue.push({ op, args, resolve, reject });
    p.pump();
  });
};

/**
 * bcryptjs 同形 API（Promise 形态）。注意 hash 第二参既可能是 rounds（数字）
 * 也可能是 salt（$2a$... 字符串），worker 内直接透传给 bcryptjs 处理。
 */
const hash = (password, saltOrRounds) => run('hash', [password, saltOrRounds]);
const compare = (password, hashed) => run('compare', [password, hashed]);
const genSalt = (rounds) => run('genSalt', [rounds]);

/** 测试专用：终止全部 worker 并复位池状态（生产代码勿调用） */
const _shutdownForTests = async () => {
  if (!pool) return;
  const entries = pool.workers.slice();
  pool = null;
  initFailed = false;
  await Promise.all(entries.map((entry) => entry.worker.terminate().catch(() => {})));
};

module.exports = { hash, compare, genSalt, _shutdownForTests };
