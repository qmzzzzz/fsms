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
 */

const AuditLog = require('../models/AuditLog');
const securityAlert = require('./securityAlert');
const logger = require('../utils/logger');
const { businessDateParts } = require('../constants/timezone');

// 检测间隔（毫秒），默认 5 分钟，可通过 AUDIT_MONITOR_INTERVAL_MS 配置
const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;

let monitorTimer = null;

/**
 * 执行一次异常检测并推送告警
 *
 * detectAnomalies 返回 { failedOperations, unusualTimeOperations }，
 * 两者均为 [{ _id: userId, count }] 数组。任一非空即尝试推送。
 *
 * 推送前经 securityAlert.shouldSendAlert 频控闸门：以「检测维度 + 当日窗口」
 * 构造稳定 alertKey，同一维度当天只推送一次；被限流时仅记日志不推送，
 * 避免 5 分钟一轮的定时检测形成告警风暴。
 */
async function runDetection() {
  try {
    const result = await AuditLog.detectAnomalies();

    const failedCount = result.failedOperations.length;
    const unusualCount = result.unusualTimeOperations.length;

    if (failedCount > 0 || unusualCount > 0) {
      const message = `审计异常检测发现 ${failedCount} 个高频失败用户、${unusualCount} 个非常规时间操作用户`;
      logger.warn(message);

      // 按维度分别过频控：命中的维度才参与本轮推送。
      // 窗口日期统一取业务时区（P3-18 单一声明 businessDateParts）：此前用
      // toISOString().slice(0,10) 是 UTC 日期，UTC+8 下要到北京时间 08:00 才换天，
      // 与 securityController 今日统计的本地零点口径分叉——同一自然日 08:00
      // 前后各能推一次告警，「每日一次」频控实际失效（时区口径分叉修复）。
      const dayWindow = businessDateParts().dateStr;
      const dimensionsToNotify = [];
      if (
        failedCount > 0 &&
        securityAlert.shouldSendAlert(`audit_anomaly_high_frequency_failure_${dayWindow}`)
      ) {
        dimensionsToNotify.push('高频失败');
      }
      if (
        unusualCount > 0 &&
        securityAlert.shouldSendAlert(`audit_anomaly_unusual_time_operation_${dayWindow}`)
      ) {
        dimensionsToNotify.push('非常规时间操作');
      }

      if (dimensionsToNotify.length === 0) {
        logger.info('审计异常告警处于频控窗口内，本轮仅记录不推送');
        return;
      }

      // 复用 securityAlert 的告警推送能力（写结构化日志 + 可选 Webhook）
      await securityAlert.sendNotification('audit_anomaly_detected', 'high', message, {
        dimensions: dimensionsToNotify,
        failedOperations: result.failedOperations,
        unusualTimeOperations: result.unusualTimeOperations,
      });
    }
  } catch (err) {
    logger.error(`审计异常监控执行失败：${err.message}`);
  }
}

/**
 * 启动定时异常检测
 * 重复调用安全（幂等）：已有定时器时直接返回
 */
function start() {
  if (monitorTimer) return;

  const intervalMs = parseInt(process.env.AUDIT_MONITOR_INTERVAL_MS, 10) || DEFAULT_INTERVAL_MS;

  monitorTimer = setInterval(() => {
    runDetection().catch((err) => {
      logger.error(`审计监控定时任务异常：${err.message}`);
    });
  }, intervalMs);

  // 不阻塞 Node 进程退出（测试环境尤其需要）
  if (monitorTimer && monitorTimer.unref) monitorTimer.unref();

  logger.info(`审计异常监控已启动（间隔 ${intervalMs / 1000}s）`);
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
 */
function isRunning() {
  return !!monitorTimer;
}

module.exports = { start, stop, runDetection, isRunning };
