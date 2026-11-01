/** 取证捕获的生命周期（2026-10-31 从 forensicCapture.js 拆出）：定时 flush / WAL 启动重放 / 关停排空。
 * 不参与采样与预算决策。flushAndStop 的 {drained,residual} 必须如实上报：谎报已排空比不排空更糟（WAL 行仍在盘上，重启会重放，而运维会以为没有遗留）。 */

const logger = require('../utils/logger');
const { errText } = require('../utils/auditWriteFailure');
const forensicManifest = require('./forensicManifest');
const forensicManifestPrune = require('./forensicManifestPrune');

/** 每日锚点的检查间隔：锚点是"每天一条"，但定时器按分钟级轮询更稳（跨日由 checkAnchor 自己判） */
const ANCHOR_TICK_MS = 30 * 60 * 1000;

const createLifecycle = ({ state, wal, flush, trimBuffer, intervalMs }) => {
  /**
   * 每日锚点：把当天清单的末条 chainHash 钉进审计链。只在**跨日后的第一次**触发（记录上次写过的 dateKey），避免每 30 分钟追加一条重复锚点污染审计链。写失败不重试也不抛：下一 tick 会再试，而抛出去会让定时器整个停掉——那才是真的不再留痕。
   */
  async function checkAnchor() {
    // 顺带归档超期清单：一天一文件会一直堆，但清理是**销毁证据**的动作，所以只归档不删除、当天文件永不碰、失败不抛（见 forensicManifestPrune 文件头）。
    try {
      const pruned = forensicManifestPrune.pruneManifest();
      if (pruned.archived.length) {
        logger.info(
          `取证清单归档 ${pruned.archived.length} 个超期日文件（保留 ${pruned.kept} 个）`
        );
      }
    } catch (e) {
      logger.warn(`取证清单归档失败（不影响锚点与捕获）：${errText(e)}`);
    }
    const today = forensicManifest.dateKeyOf();
    if (state.lastAnchorDateKey === today) return;
    const r = await forensicManifest.writeDailyAnchor();
    // 只在**真的写进审计链**后才记当天已锚。empty_day（当天还没有清单）与写失败都保持未锚状态，否则跨日首个 tick 会把当天锁死：真实批次随后产生却永远不再锚定（锚点机制整天静默失效）。
    if (r.written) state.lastAnchorDateKey = today;
  }

  function start() {
    if (state.flushTimer) return;
    // 启动期异常（WAL 目录不可写/权限加固失败）只降级：定时 flush 仍要建立，绝不阻断进程启动
    try {
      wal.startup(process.env.FORENSIC_WAL_PATH);
      wal.serialize(
        async () => {
          const docs = await wal.readLines();
          if (!docs.length) return;
          state.buffer.push(...docs);
          trimBuffer();
          logger.info(`取证 WAL 重放 ${docs.length} 条遗留记录`);
        },
        (e) => logger.warn(`取证 WAL 启动重放失败：${errText(e)}`)
      );
    } catch (e) {
      logger.error(`取证 WAL 启动失败（已降级为纯内存缓冲，崩溃窗口内记录会丢失）：${errText(e)}`);
    }
    state.flushTimer = setInterval(() => flush().catch(() => {}), intervalMs);
    if (state.flushTimer.unref) state.flushTimer.unref();
    if (process.env.FORENSIC_MANIFEST_ANCHOR_DISABLED !== 'true') {
      state.anchorTimer = setInterval(() => checkAnchor().catch(() => {}), ANCHOR_TICK_MS);
      if (state.anchorTimer.unref) state.anchorTimer.unref();
    }
  }

  function stop() {
    wal.disable();
    if (state.flushTimer) {
      clearInterval(state.flushTimer);
      state.flushTimer = null;
    }
    if (state.anchorTimer) {
      clearInterval(state.anchorTimer);
      state.anchorTimer = null;
    }
  }

  async function flushAndStop(budgetMs = 2000) {
    const deadline = Date.now() + budgetMs;
    while ((state.buffer.length || state.flushing) && Date.now() < deadline) {
      await flush().catch(() => {});
      if (state.flushing) await new Promise((r) => setTimeout(r, 20));
    }
    const residual = state.buffer.length;
    await wal.drain();
    stop();
    return { drained: residual === 0, residual };
  }

  return { start, stop, flushAndStop };
};

module.exports = { createLifecycle };
