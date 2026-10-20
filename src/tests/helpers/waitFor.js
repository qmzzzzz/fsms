/**
 * 测试确定性等待工具（2026-10-20，审计 P2-2 / T-2）
 *
 * 固定 `await new Promise((r) => setTimeout(r, N))` 是 flake 的主要来源：
 * N 在慢 CI、并行 worker、冷缓存下只是「大概率够」，不够时红的是断言而不是
 * 「等得不够」；够的时候又白付 N 毫秒。这里统一成两类等待：
 *
 *   · waitFor(cond)         —— 轮询到**真实完成条件**成立；
 *   · waitForStable(read)   —— 轮询到读数连续两次相同（用于「计数不再变化」）；
 *   · flushEventLoop()      —— 只让出事件循环若干轮（微任务/已就绪 I/O），
 *                             不承诺任何时长，用于「投递是 fire-and-forget」的场景。
 *
 * 本文件自身的轮询间隔是 setTimeout，但它是轮询机制而不是固定睡眠：
 * 失败时抛出带 label 的超时错误，能直接看出等的是哪个条件。
 */

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_INTERVAL_MS = 25;

const normalizeOptions = (options) => {
  if (typeof options === 'number') return { timeoutMs: options };
  return options || {};
};

/**
 * 轮询等待条件成立；条件可为同步或异步（Promise 会被 await，避免恒真值退化）。
 * 条件抛错时重试，超时错误里保留最后一次异常，便于区分「条件没到」与「查询坏了」。
 */
async function waitFor(condition, options = {}) {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    intervalMs = DEFAULT_INTERVAL_MS,
    label = 'condition',
  } = normalizeOptions(options);
  const deadline = Date.now() + timeoutMs;
  let lastError;
  for (;;) {
    try {
      if (await condition()) return true;
      lastError = undefined;
    } catch (err) {
      lastError = err;
    }
    if (Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  const detail = lastError ? `；最后一次错误：${lastError.message}` : '';
  throw new Error(`waitFor 超时（${timeoutMs}ms）：${label}${detail}`);
}

/**
 * 轮询读数直到连续两次相同（例如「审计行数不再增长」）。
 * 返回稳定后的读数；超时抛错而不是返回可能仍在变化的值。
 */
async function waitForStable(read, options = {}) {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    intervalMs = DEFAULT_INTERVAL_MS,
    label = 'stable value',
  } = normalizeOptions(options);
  const deadline = Date.now() + timeoutMs;
  let previous = await read();
  for (;;) {
    if (Date.now() >= deadline) {
      throw new Error(`waitForStable 超时（${timeoutMs}ms）：${label} 仍在变化`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    const current = await read();
    if (current === previous) return current;
    previous = current;
  }
}

/** 让出事件循环（setImmediate），不承诺任何时间；用于 fire-and-forget 的投递。 */
async function flushEventLoop(turns = 1) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

module.exports = {
  waitFor,
  waitForStable,
  flushEventLoop,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_INTERVAL_MS,
};
