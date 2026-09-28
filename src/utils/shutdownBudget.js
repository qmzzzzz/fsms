'use strict';

/**
 * 优雅关闭的总预算（F-103）
 *
 * 缺陷的三个实测输入（本轮独立复测，与台账 §14.21.5 / §16 一致）：
 *  · HTTP 步骤自带 10 s 强制超时（`src/index.js` 的 `forceTimeout`）；
 *  · `stopReminderScheduler` 最长等 30 s（`deviceReminder.js` 的 `waitCount < 30`）；
 *  · `docker-compose.yml` 的 app 服务此前**没有** `stop_grace_period`
 *    ⇒ Docker 按默认 10 s 发 SIGKILL。
 * 链上各步预算之和远超部署窗口，而**有持久化后果**的两步（审计缓冲排空、Mongo 连接关闭）
 * 恰好排在链尾 ⇒ 最坏情形下它们一次都不会执行，且 SIGKILL 不留任何日志线索
 * （比"指标说谎"更糟：连谎话都没有）。
 *
 * 所以"整条链必须落在部署窗口之内"这件事，现在由本模块做单一事实源：
 * 每一步向 `stepAllowMs(该步之后仍需的保留时间)` 要自己的超时；预算用尽时拿到 0，
 * 步骤立刻走自己的兜底路径（审计排空会带着 residual 如实报错，不是静默跳过）。
 *
 * 注意 `TAIL_RESERVE_MS` 的存在理由：排空与关库这两步**不能**被前面的步骤吃光预算，
 * 否则"能等到请求结束"就永远优先于"审计不落盘"——方向反了。
 */

const { readPositiveNumberEnv } = require('./envNumber');
const logger = require('./logger');

// 总预算必须**小于**部署侧声明的 stop_grace_period（compose 里 30s），留出的差值是
// 给"预算判断本身之后的收尾动作"（日志 transport 落盘 + process.exit）的余量。
const SHUTDOWN_TOTAL_BUDGET_MS = readPositiveNumberEnv('SHUTDOWN_TOTAL_BUDGET_MS', 25000, {
  onInvalid: (name, raw, d) =>
    logger.error(
      `${name}=${JSON.stringify(raw)} 非法（须为正的毫秒数），已按默认 ${d} 处理；` +
        '一个负值或超大值会让关停链跑到部署窗口之外，审计排空被 SIGKILL 截断'
    ),
});

// 排空审计缓冲（自身上限 2s）+ 关 Redis + 关 Mongo + 日志 transport flush 的保留时间
const TAIL_RESERVE_MS = readPositiveNumberEnv('SHUTDOWN_TAIL_RESERVE_MS', 6000, {
  onInvalid: (name, raw, d) =>
    logger.error(`${name}=${JSON.stringify(raw)} 非法，已按默认 ${d} 处理（见本文件顶部注释）`),
});

let deadline = 0;

/** 关停开始时调用一次：把总预算折算成绝对截止时间 */
function beginShutdownBudget(totalMs = SHUTDOWN_TOTAL_BUDGET_MS) {
  deadline = Date.now() + totalMs;
  return deadline;
}

/**
 * 本步还能占用多少毫秒（已经为 reserveMs 留出时间）。
 * 从未 begin（生产里不会发生，测试里表示"不限制"）时返回 Infinity，
 * 让调用方退回各自的硬上限，而不是把超时钳成 0。
 * @param {number} reserveMs 本步之后仍需保留的毫秒数
 */
function stepAllowMs(reserveMs = 0) {
  if (deadline === 0) return Infinity;
  return Math.max(0, deadline - Date.now() - reserveMs);
}

/** 仅供测试：重置/注入预算，避免用例真的等 25 s */
function __setDeadlineForTest(value) {
  deadline = value;
}

/**
 * 给"可能永远不 settle 的 await"套上硬闸（F-202）。
 *
 * 为什么需要：关停链上 `await runStep(...)` 的语义是"等这一步做完"，但 Redis socket
 * 卡在半开、Mongo 驱动处在重连队列里时，那个 promise 再也不会落地 —— 于是后面的
 * 审计排空、SIEM 排空、`process.exit` 全部跑不到，进程只在部署侧 stop_grace_period 之后
 * 吃一发 SIGKILL，日志里连"卡在哪一步"都没有。F-103 给的是"每步该等多久"的额度，
 * 但额度只有被**读取**才生效；本函数是那条额度的执行端。
 *
 * 契约（调用方只看返回值，本函数**永不 reject**）：
 *   `{ timedOut: false, error: null }`   正常做完
 *   `{ timedOut: false, error }`         做完但抛错（与原 runStep 的 try/catch 同义）
 *   `{ timedOut: true,  error: null }`   放弃等待——**如实上报**，不静默跳过（F-101 同族）
 *
 * `allowMs` 的两种取值各有含义，不能混为一谈：
 *   `Infinity`（预算从未 begin）⇒ 不设闸，只做异常收口，与 stepAllowMs 的"不限制"口径对齐；
 *   `0` 或正数（预算已用尽＝0）⇒ 走同一条竞速。用 `setTimeout(…, 0)` 而不是"同步判超时"，
 *   是为了让**已经做完**的步骤赢下这一帧：预算用尽只该意味着"不再等还在跑的"，
 *   不该把做完的事报成"放弃等待"（那会让日志谎报，F-101 同一族）。
 *
 * 两条容易写错的细节：
 * 1. **rejection 必须当场接住**。`Promise.race` 只消费第一个 settle 的结果；放弃等待之后
 *    task 才 reject 的话，它没有任何处理器 ⇒ unhandledRejection 会打死正在关停的进程
 *    （比卡死更糟：退出码与日志都变了）。这里用 `Promise.resolve(task).then(_, handler)`
 *    生成一个"永不抛"的派生 promise，task 的 rejection 在被放弃的那一刻起就有主。
 * 2. **闸的定时器要 unref**。否则"放弃等待"只是把挂住换成让事件循环多活 allowMs 毫秒。
 *
 * @param {Promise} task 已经在跑的步骤（本函数不重启、不改写它）
 * @param {number} allowMs 最多等多久（来自 `stepAllowMs(reserve)` 与硬上限的较小值）
 * @returns {Promise<{timedOut: boolean, error: (Error|null), elapsedMs: number}>}
 */
async function guardStep(task, allowMs) {
  const started = Date.now();
  const settled = Promise.resolve(task).then(
    () => ({ timedOut: false, error: null }),
    (error) => ({ timedOut: false, error })
  );
  if (!Number.isFinite(allowMs)) {
    return { ...(await settled), elapsedMs: Date.now() - started };
  }
  let timer = null;
  const guard = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true, error: null }), allowMs);
    if (timer && typeof timer.unref === 'function') timer.unref();
  });
  try {
    return { ...(await Promise.race([settled, guard])), elapsedMs: Date.now() - started };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

module.exports = {
  SHUTDOWN_TOTAL_BUDGET_MS,
  TAIL_RESERVE_MS,
  beginShutdownBudget,
  stepAllowMs,
  guardStep,
  __setDeadlineForTest,
};
