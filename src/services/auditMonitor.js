/**
 * 审计日志异常检测定时监控
 *
 * 定时调用 AuditLog.detectAnomalies() 检测异常行为（高频失败、非常规时间操作），
 * 检测到异常时经 securityAlert 推送告警，形成「检测 → 告警」闭环。
 *
 * 复用现有 detectAnomalies 与 securityAlert，不重写检测/告警逻辑。
 *
 * 生命周期：由 index.js 在启动时调用 start()，优雅关闭时调用 stop()。
 * 定时器 unref，不阻塞 Node 进程退出。
 *
 * 【窗口跟着间隔走】检测能力真正覆盖的时间轴 = 窗口 / 间隔，二者必须同源：
 * 间隔可调（AUDIT_MONITOR_INTERVAL_MS），窗口由 start() 落盘的**生效间隔**推导
 * （见 effectiveIntervalMs），否则"把间隔调大减压"会静默变成"大部分审计没人看"。
 * 【一轮一闸】上一轮未结束则本轮跳过并计数；每轮聚合带 maxTimeMS 上限，
 * 保证闸门不会因为一轮挂死而永久停摆。
 * 【失败留痕】每轮结果写进 health（runs/failures/consecutiveFailures/…），
 * 由 getHealth() 读出——isRunning() 只说定时器在，不说检测在成功跑。
 */

const AuditLog = require('../models/AuditLog');
const securityAlert = require('./securityAlert');
const logger = require('../utils/logger');
const { businessDateParts } = require('../constants/timezone');
const { readPositiveNumberEnv } = require('../utils/envNumber');

// 检测间隔（毫秒），默认 5 分钟，可通过 AUDIT_MONITOR_INTERVAL_MS 配置
const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;
/** 定时检测的最小间隔：低于此值的一律抬到该值（见下方 start() 的钳制说明） */
const MIN_INTERVAL_MS = 30 * 1000;
/**
 * 检测窗口相对生效间隔的重叠余量 = 2×最小间隔。
 * setInterval 的实际触发时刻会因事件循环滞后整体后移，窗口严格等于间隔会在两轮
 * 之间留下一条没人看的缝，故按周期加余量。
 */
const WINDOW_OVERLAP_MS = 2 * MIN_INTERVAL_MS;
/** 单轮聚合预算下限：间隔配得很短时，也要给慢查询留出时间 */
const MIN_ROUND_BUDGET_MS = 60 * 1000;

let monitorTimer = null;
/**
 * start() 实际生效的间隔（env 非法回落、最小值钳制**之后**的值）。
 *
 * runDetection 必须按它推导检测窗口：窗口此前恒为模型默认值 5 分钟，而间隔可由
 * AUDIT_MONITOR_INTERVAL_MS 配成任意值——把间隔调大"减压"，实际是把被检时间占比
 * 降到 窗口/间隔（间隔 1 小时 ⇒ 只看到 8.3% 的时间轴），而合规面板仍报
 * monitorRunning: true。静默漏检与"看起来在、实际断"是同一缺陷类，故让窗口跟着走。
 */
let effectiveIntervalMs = DEFAULT_INTERVAL_MS;
/** 单轮闸门：上一轮未结束时本轮跳过（详见 runDetection） */
let detectionRunning = false;

/**
 * 检测运行状态。isRunning() 只说明"定时器挂着"，不说明"检测在成功跑"——
 * 两者可以同时成立，所以每轮的结果必须自己留痕。
 */
const health = {
  runs: 0, // 实际执行的轮次数（被跳过的不计）
  failures: 0, // 累计以异常结束的轮次
  consecutiveFailures: 0, // 连续失败次数，成功一轮即归零（判健用这个）
  skippedOverlaps: 0, // 因上一轮未结束而跳过的轮次
  lastRunAt: null,
  lastFailureAt: null,
  lastFailureMessage: null,
};

/** 检测窗口（分钟，允许小数——模型侧按 windowMinutes*60000 使用） */
function windowMinutesFor(intervalMs) {
  return (intervalMs + WINDOW_OVERLAP_MS) / 60000;
}

/** 单轮聚合的服务端上限：一轮最多占一个周期，但不低于下限 */
function roundBudgetMs() {
  return Math.max(MIN_ROUND_BUDGET_MS, effectiveIntervalMs);
}

/**
 * 维度 → 最近一次推送所在的业务日期（如 '2026-09-24'）。
 *
 * 存在的理由：shouldSendAlert 的抑制窗口是 THRESHOLDS.alertRateLimitMs
 * （securityAlert.js:27 硬编码 5 分钟），而本模块的检测间隔默认也是 5 分钟、
 * 且可经 AUDIT_MONITOR_INTERVAL_MS 配成 30s~任意值。于是"同一维度当天只推送一次"
 * 这条写在键名里的约定，实际建立在 **TTL(5min) 与 interval 的竞态** 上：
 * interval ≥ TTL 时（默认值恰好相等，实测 6 分钟即跨过）频控表项在下一轮开始前
 * 就已过期 ⇒ 每轮都放行 ⇒ 一个维度一天最多 144 条高危告警，而不是 1 条。
 * 也就是说键名里的日期**从不参与抑制判定**，只有当日 0 点换键那一次是特例。
 * 本表把"当日一次"变成构造即为真，不再依赖两个常量的大小关系。
 * 键数上限 = 维度数（3），换日覆盖，不需要清理任务。
 */
const notifiedDayByDimension = new Map();

/**
 * 执行一次异常检测并推送告警
 *
 * detectAnomalies 返回 { failedOperations, failedOperationsByIp, unusualTimeOperations }，
 * 三者均为 [{ _id, count }] 数组。任一非空即尝试推送。
 *
 * 【第三个维度此前被整段丢弃 ⇒ IP 维度的爆破不会告警】
 * `failedOperationsByIp` 是检测层专门跑的一条聚合（按来源 IP 分组的失败计数），
 * 但原实现只读前两个数组：当一轮里"每个用户的失败都没过阈值、但某些来源 IP 的
 * 失败过了阈值"时（典型形态：跨多账号的口令喷洒 / 撞库，单账号失败次数被摊薄），
 * `failedCount === 0 && unusualCount === 0` ⇒ 连 if 都进不去 ⇒ **既不记日志也不告警**，
 * 而这条聚合每次都在白跑。检测能力存在、告警闭环缺一段。
 * 现在按同一套「维度 + 当日窗口」频控口径把它并入，三个维度各自独立限流。
 *
 * 推送前经 securityAlert.shouldSendAlert 频控闸门：以「检测维度 + 当日窗口」
 * 构造稳定 alertKey，被限流时仅记日志不推送。
 * 但"同一维度当天只推送一次"这条由**本模块自己的 notifiedDayByDimension** 保证，
 * 不能指望 shouldSendAlert——它的窗口只有 5 分钟，详见该表上方的说明。
 *
 * 【单轮闸门】setInterval 不等上一轮结束：一轮跑不完一个周期时第二轮照样进来，
 * 于是每轮三条聚合开始并发——"把间隔调大减压"的配置反被放大成加倍负载。
 * 现在上一轮未结束则本轮直接跳过并计数（skippedOverlaps 持续增长就是"检测跟不上
 * 节奏"的可查询证据）。跳过不会变成永久停摆：聚合带 maxTimeMS 上限（见
 * roundBudgetMs），最坏情况由服务端中断这轮、走 catch 释放闸门。
 */
async function runDetection() {
  if (detectionRunning) {
    health.skippedOverlaps += 1;
    logger.warn(
      `审计异常检测上一轮未结束，本轮跳过（累计跳过 ${health.skippedOverlaps} 轮）；` +
        `跳过持续增长说明单轮耗时已超过间隔 ${effectiveIntervalMs / 1000}s`
    );
    return;
  }
  detectionRunning = true;
  health.runs += 1;
  health.lastRunAt = new Date().toISOString();
  try {
    const result = await AuditLog.detectAnomalies({
      windowMinutes: windowMinutesFor(effectiveIntervalMs),
      maxTimeMS: roundBudgetMs(),
    });
    // 走到这里说明"看数据"这一步成功了；之后的告警侧异常另计（下面 sendNotification
    // 的 reject 同样落进 catch，闭环断在推送侧也要可见）
    health.consecutiveFailures = 0;

    const failedCount = result.failedOperations.length;
    // 兼容旧签名：调用方（含测试替身）可能只给两个维度
    const failedIpCount = (result.failedOperationsByIp || []).length;
    const unusualCount = result.unusualTimeOperations.length;

    if (failedCount > 0 || failedIpCount > 0 || unusualCount > 0) {
      const message =
        `审计异常检测发现 ${failedCount} 个高频失败用户、` +
        `${failedIpCount} 个高频失败来源 IP、` +
        `${unusualCount} 个非常规时间操作用户`;
      logger.warn(message);

      // 按维度分别过频控：命中的维度才参与本次改动推送。
      // 窗口日期统一取业务时区（P3-18 单一声明 businessDateParts）：此前用
      // toISOString().slice(0,10) 是 UTC 日期，UTC+8 下要到北京时间 08:00 才换天，
      // 与 securityController 今日统计的本地零点口径分叉——同一自然日 08:00
      // 前后各能推一次告警，「每日一次」频控实际失效（时区口径分叉修复）。
      const dayWindow = businessDateParts().dateStr;
      const dimensionsToNotify = [];
      // [频控键后缀, 人读维度名, 本轮命中数]——键串与修复前逐字一致
      // （auditMonitorTimezone / zzqA_auditMonitorAlertLoop 按完整字符串断言）
      const candidates = [
        ['high_frequency_failure', '高频失败', failedCount],
        ['high_frequency_failure_by_ip', '高频失败来源 IP', failedIpCount],
        ['unusual_time_operation', '非常规时间操作', unusualCount],
      ];
      for (const [keyPart, label, count] of candidates) {
        if (!count) continue;
        // 顺序有意：先问共享频控、再问当日闸。反过来会在"当日已推过"时根本不调
        // shouldSendAlert，也就拿不到"抑制来自当日闸而不是 5 分钟 TTL"这条可归因证据
        // （zzqoder_auditMonitorDailyAlertCap 正是靠这个顺序做因果判定的）。
        const allowedByThrottle = securityAlert.shouldSendAlert(
          `audit_anomaly_${keyPart}_${dayWindow}`
        );
        if (!allowedByThrottle) continue;
        if (notifiedDayByDimension.get(keyPart) === dayWindow) continue;
        // 在决定推送的那一刻占位，不等 sendNotification 返回：与修复前一致
        // （原实现也是先消费频控表项再推送）。这里刻意不做"推送失败则本轮重试"——
        // 一轮三条聚合撞的是同一个故障 Webhook，重试只会把风暴放大。
        notifiedDayByDimension.set(keyPart, dayWindow);
        dimensionsToNotify.push(label);
      }

      if (dimensionsToNotify.length === 0) {
        logger.info('审计异常告警处于频控/当日已推送窗口内，本轮仅记录不推送');
        return;
      }

      // 复用 securityAlert 的告警推送能力（写结构化日志 + 可选 Webhook）
      await securityAlert.sendNotification('audit_anomaly_detected', 'high', message, {
        dimensions: dimensionsToNotify,
        failedOperations: result.failedOperations,
        failedOperationsByIp: result.failedOperationsByIp || [],
        unusualTimeOperations: result.unusualTimeOperations,
      });
    }
  } catch (err) {
    health.failures += 1;
    health.consecutiveFailures += 1;
    health.lastFailureAt = new Date().toISOString();
    health.lastFailureMessage = err.message;
    logger.error(`审计异常监控执行失败：${err.message}`);
  } finally {
    detectionRunning = false;
  }
}

/**
 * 启动定时异常检测
 * 重复调用安全（幂等）：已有定时器时直接返回
 */
function start() {
  if (monitorTimer) return;

  // 统一判据——只有有限正数被采纳，否则回落默认并告警（本模块另有 30s 下限，
  // 见下方 MIN_INTERVAL_MS 钳制；两者叠加覆盖"负值 ⇒ setInterval 1ms 忙轮询"）。
  let intervalMs = readPositiveNumberEnv('AUDIT_MONITOR_INTERVAL_MS', DEFAULT_INTERVAL_MS, {
    onInvalid: (name, raw, d) =>
      logger.warn(
        `${name}=${JSON.stringify(raw)} 非法（须为正数），已按默认 ${d}ms 处理；` +
          '负值会被 setInterval 抬成 1ms，形成每毫秒三条审计聚合的忙轮询'
      ),
  });
  // 下限钳制：每轮检测会跑三条聚合（失败按用户/按 IP/非常规时间），
  // 而 env 值原先直传 setInterval——负数与 0 会被 Node 抬成 1ms 间隔
  // （`-5 || DEFAULT` 取 -5，非 NaN 即生效），等于用定时任务自己把库打满。
  // 与仓内其余 env 数值口径一致：可配但不设下界不信任输入。
  if (intervalMs < MIN_INTERVAL_MS) {
    logger.warn(
      `AUDIT_MONITOR_INTERVAL_MS=${intervalMs} 低于最小间隔 ${MIN_INTERVAL_MS}ms，` +
        `已抬升到最小值（防止高频自触发把审计库打满）`
    );
    intervalMs = MIN_INTERVAL_MS;
  }

  // 钳制之后的值才是"生效间隔"，检测窗口按它推导（见 effectiveIntervalMs 说明）。
  // 写在钳制之后是必须的：写在前面会让"配 1s 间隔"推导出 1s 窗口，
  // 而实际周期是 30s——占空比又掉回 3%，等于修了个假的。
  effectiveIntervalMs = intervalMs;

  monitorTimer = setInterval(() => {
    runDetection().catch((err) => {
      logger.error(`审计监控定时任务异常：${err.message}`);
    });
  }, intervalMs);

  // 不阻塞 Node 进程退出（测试环境尤其需要）
  if (monitorTimer && monitorTimer.unref) monitorTimer.unref();

  logger.info(
    `审计异常监控已启动（间隔 ${intervalMs / 1000}s，` +
      `每轮检测窗口 ${windowMinutesFor(intervalMs).toFixed(1)} 分钟）`
  );
}

/**
 * 停止定时异常检测（供优雅关闭调用）
 */
function stop() {
  if (monitorTimer) {
    clearInterval(monitorTimer);
    monitorTimer = null;
    logger.info('审计异常监控已停止');
  }
}

/**
 * 监控是否在运行（合规仪表盘指标）
 *
 * 只回答"定时器挂着没有"，不回答"检测有没有在成功跑"——后者见 getHealth()。
 * 两者必须成对读：isRunning()===true 且 consecutiveFailures>0 就是
 * 「面板说活着、实际每轮都失败」的形态。
 */
function isRunning() {
  return !!monitorTimer;
}

/** 运行状态快照（返回副本：调用方不得能改内部计数） */
function getHealth() {
  return { ...health, intervalMs: effectiveIntervalMs, running: !!monitorTimer };
}

/**
 * 测试钩子（与 auditBuffer.__resetForTest 同惯例）：清空当日已推送表与健康计数。
 * notifiedDayByDimension / health 是模块级状态，同一测试文件内多条用例共用一个
 * 日期串时会互相抑制 ⇒ 必须每条用例前重置，否则随机顺序门禁下会出现假红/假绿。
 * detectionRunning 一并复位：某条用例若留下一个永不 settle 的轮次，不复位会把
 * 后续所有用例变成"静默跳过"——那正是本模块要防的缺陷类，不能由测试钩子制造。
 * effectiveIntervalMs 复位到默认值，防止上一条用例配的间隔泄漏到下一条的窗口断言。
 */
function __resetForTest() {
  notifiedDayByDimension.clear();
  detectionRunning = false;
  effectiveIntervalMs = DEFAULT_INTERVAL_MS;
  health.runs = 0;
  health.failures = 0;
  health.consecutiveFailures = 0;
  health.skippedOverlaps = 0;
  health.lastRunAt = null;
  health.lastFailureAt = null;
  health.lastFailureMessage = null;
}

module.exports = {
  start,
  stop,
  runDetection,
  isRunning,
  getHealth,
  __resetForTest,
  // 仅供测试：窗口/预算的推导基准常量，避免用例里重复写死 30s
  __MIN_INTERVAL_MS: MIN_INTERVAL_MS,
};
