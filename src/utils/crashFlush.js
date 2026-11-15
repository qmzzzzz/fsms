'use strict';

/**
 * 崩溃路径（uncaughtException / unhandledRejection）的收尾链：审计缓冲硬预算 flush + 日志 bestEffortDrain + 限时退出。从 src/index.js 抽出（index.js 已贴着 300 行代码棘轮；且这条链在两条崩溃路径上逐字共享，抽模块同时消除了复制粘贴面）。
 * 语义契约：
 * - flush 带 CRASH_FLUSH_BUDGET_MS 硬闸（guardStep 永不 reject、定时器 unref）：Mongo 卡死时 flush 永不 settle，没有闸的话下面的 exit(1) 永远跑不到——崩溃退化成挂死（比崩溃更难诊断）。超时**如实上报**后照常退出，现场由 WAL 保留、重启后重放（F-101 家族：放弃等待必须留声，不许静默跳过）。
 * - flush/排空失败不阻断退出：进程已处于不可信状态，尽力而为。
 * - 本链永不 reject：崩溃处理器的调用点没有 catch，一次 reject 就是新的 unhandledRejection（utils/loggerFlush.js bestEffortDrain 同款纪律）。
 */

const logger = require('./logger');
const shutdownBudget = require('./shutdownBudget');
const { bestEffortDrain } = require('./loggerFlush');
const auditBuffer = require('../services/auditBuffer');
const forensicCapture = require('../services/forensicCapture');

// flush 与日志排空的预算都远小于 1s 的退出延时：崩溃链的总时长有上界，绝不为"送日志/落审计"把一个已经崩溃的进程再拖长（bestEffortDrain 同口径）。
const CRASH_FLUSH_BUDGET_MS = 2000;
const CRASH_DRAIN_BUDGET_MS = 500;

// 进程即将退出前必须 flush 审计缓冲——内存里可能有上百条已确认响应给客户端、但尚未落库的审计记录，直接 exit 会让它们随进程消失（WAL 能在下次启动重放，但重放依赖进程能正常再启动，不能作为唯一保障）。
const flushAuditOnCrash = (tag) =>
  shutdownBudget
    .guardStep(
      Promise.resolve()
        .then(() => auditBuffer.flush())
        .then(() => forensicCapture.flush()),
      CRASH_FLUSH_BUDGET_MS
    )
    .then(({ timedOut, error }) => {
      if (timedOut)
        logger.error(
          `[${tag}] 退出前审计 flush 超出 ${CRASH_FLUSH_BUDGET_MS}ms 预算，放弃等待（现场由 WAL 保留）`
        );
      else if (error)
        logger.error(
          `[${tag}] 退出前审计缓冲落库失败：${error && error.message ? error.message : error}`
        );
    });

const drainAndExit = (tag) =>
  Promise.resolve()
    .then(() => flushAuditOnCrash(tag))
    .then(() => bestEffortDrain({ allowMs: CRASH_DRAIN_BUDGET_MS, tag }))
    .finally(() => setTimeout(() => process.exit(1), 1000));

module.exports = { drainAndExit, CRASH_FLUSH_BUDGET_MS, CRASH_DRAIN_BUDGET_MS };
