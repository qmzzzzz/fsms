/**
 * 设备到期/维护提醒服务
 * 周期性扫描到期设备与待维护设备，生成提醒记录并写入审计日志，
 * 供前端首页与消息中心展示。
 *
 * 提醒维度：
 *   - expiringSoon 即将到期（默认 30 天内）
 *   - expired     已过期仍在册
 *   - needMaintenance 超过检查周期未维护
 */

const FireDevice = require('../models/FireDevice');
const logger = require('../utils/logger');

// 内存级缓存最新一次扫描结果，供接口快速返回
let lastScanResult = null;
let lastScanAt = null;
// 修复：isScanning 声明移至顶部，避免函数定义中引用未声明变量（可读性与 TDZ 安全）
let isScanning = false;

/**
 * 扫描设备并生成到期/维护提醒
 * @param {Object} options
 * @param {number} options.expiringDays 即将到期窗口（默认 30 天）
 * @param {Object|null} options.scopeFilter 数据范围过滤（H-1：接口路径按调用者范围过滤；
 *        后台调度不传 = 全库扫描供审计）。带 scopeFilter 的结果不写入全局缓存，避免跨用户泄漏
 * @param {number} options.resultLimit 每维度返回上限（默认 200，防止无界全库返回）
 */
const scanDeviceReminders = async (options = {}) => {
  // 互斥锁：防止并发重叠
  if (isScanning) {
    // H-1 数据边界：带 scopeFilter 的调用绝不可返回全局缓存——
    // 那是无范围的全库扫描结果，直接返回会把全部设备提醒泄漏给低权限用户
    if (options.scopeFilter) {
      logger.warn('设备到期扫描已在进行中，本次数据范围查询跳过');
      return { scannedAt: new Date().toISOString(), summary: { total: 0 }, skipped: true };
    }
    logger.warn('设备到期扫描已在进行中，返回上次全库结果');
    return (
      lastScanResult || {
        scannedAt: new Date().toISOString(),
        summary: { total: 0 },
        skipped: true,
      }
    );
  }
  isScanning = true;

  try {
    const { expiringDays = 30, scopeFilter = null, resultLimit = 200 } = options;
    const base = scopeFilter || {};

    // 已过期仍在册（未报废）
    const expired = await FireDevice.find({
      ...base,
      expiryDate: { $lt: new Date() },
      status: { $ne: 'scrapped' },
    })
      .select('deviceCode deviceName deviceType location expiryDate status')
      .sort({ expiryDate: 1 })
      .limit(resultLimit);

    // 即将到期窗口内
    const windowEnd = new Date();
    windowEnd.setDate(windowEnd.getDate() + expiringDays);
    const expiringSoon = await FireDevice.find({
      ...base,
      expiryDate: { $gte: new Date(), $lte: windowEnd },
      status: { $ne: 'scrapped' },
    })
      .select('deviceCode deviceName deviceType location expiryDate status')
      .sort({ expiryDate: 1 })
      .limit(resultLimit);

    // 超过检查周期未维护且非维护中
    const needMaintenance = await FireDevice.find({
      ...base,
      nextCheckDate: { $lte: new Date() },
      status: { $nin: ['maintenance', 'scrapped'] },
    })
      .select('deviceCode deviceName deviceType location nextCheckDate status')
      .sort({ nextCheckDate: 1 })
      .limit(resultLimit);

    // total 按设备去重：同一设备可同时命中 expired 与 needMaintenance，
    // 直接相加会把一台设备计成两台，总数虚高
    const uniqueDeviceIds = new Set(
      [...expired, ...expiringSoon, ...needMaintenance].map((d) => String(d._id))
    );

    const result = {
      scannedAt: new Date().toISOString(),
      expiringDays,
      summary: {
        expired: expired.length,
        expiringSoon: expiringSoon.length,
        needMaintenance: needMaintenance.length,
        total: uniqueDeviceIds.size,
      },
      expired,
      expiringSoon,
      needMaintenance,
    };

    // 仅后台全库扫描写入全局缓存；按用户范围的查询结果各不相同，不可缓存共享
    if (!scopeFilter) {
      lastScanResult = result;
      lastScanAt = new Date();
    }

    logger.info(
      `设备到期扫描完成：过期 ${expired.length} / 即将到期 ${expiringSoon.length} / 待维护 ${needMaintenance.length}`
    );

    return result;
  } finally {
    isScanning = false;
  }
};

/**
 * 标记逾期巡检（P2-19）
 *
 * Inspection.status 定义了 'overdue' 枚举，但全仓没有任何调度器或写入路径会置它——
 * 前端按 overdue 筛选永远返回空，dashboard 的逾期数只能靠
 * `status:'pending' AND planEndTime <= now` 的临时聚合推算，
 * 与「状态字段」这一事实来源不一致。
 *
 * 这里在设备提醒扫描的同一节拍里推进巡检状态：
 * pending/in_progress 且计划结束时间已过 → overdue。
 * 已完成/已取消不回退（终态），已是 overdue 的不重复写。
 *
 * @returns {Promise<number>} 本次标记的条数
 */
const markOverdueInspections = async () => {
  try {
    const Inspection = require('../models/Inspection');
    const res = await Inspection.updateMany(
      {
        status: { $in: ['pending', 'in_progress'] },
        planEndTime: { $lt: new Date() },
      },
      { $set: { status: 'overdue' } }
    );
    const n = res.modifiedCount ?? 0;
    if (n > 0) {
      logger.info(`巡检逾期标记完成：${n} 条 pending/in_progress 已超过计划结束时间，置为 overdue`);
    }
    return n;
  } catch (err) {
    // 提醒扫描的附加职责，失败不应影响设备提醒本身
    logger.error(`巡检逾期标记失败：${err.message}`);
    return 0;
  }
};

/**
 * 获取上一次扫描结果（若无则触发一次扫描）
 * 带 scopeFilter 的调用（接口路径）绕过全局缓存：缓存内容是全库结果，直接返回会击穿数据范围
 */
const getDeviceReminders = async (options = {}) => {
  if (options.scopeFilter) {
    return await scanDeviceReminders(options);
  }
  // 缓存 TTL：超过扫描间隔则重新扫描
  const intervalMs = options.intervalMs || 24 * 60 * 60 * 1000;
  if (lastScanResult && lastScanAt && Date.now() - lastScanAt.getTime() < intervalMs) {
    return lastScanResult;
  }
  return await scanDeviceReminders(options);
};

// 模块级持有调度句柄：防止意外二次调用泄漏旧定时器（stop 无法引用旧 timer）
let activeScheduler = null;

/**
 * 启动周期性到期扫描（默认每日一次）
 * @param {number} intervalMs 扫描间隔毫秒
 */
const startReminderScheduler = (intervalMs = 24 * 60 * 60 * 1000) => {
  // 幂等保护：重复启动直接返回既有句柄，避免泄漏旧 timer
  if (activeScheduler) {
    logger.warn('设备到期提醒调度已在运行，忽略重复启动');
    return activeScheduler;
  }

  // 服务启动后延迟 30 秒执行首次扫描，避免与初始化争抢连接
  const firstTimer = setTimeout(() => {
    scanDeviceReminders().catch((err) => logger.error(`首次设备到期扫描失败：${err.message}`));
    markOverdueInspections();
  }, 30 * 1000);

  const timer = setInterval(() => {
    // 巡检逾期标记与设备扫描互不依赖，即使扫描被跳过也要执行
    markOverdueInspections();
    // 防止并发重叠：上次扫描未完成时跳过
    if (isScanning) {
      logger.warn('上一次设备到期扫描尚未完成，跳过本次');
      return;
    }
    scanDeviceReminders().catch((err) => logger.error(`设备到期周期扫描失败：${err.message}`));
  }, intervalMs);
  timer.unref?.();
  firstTimer.unref?.();

  logger.info(`设备到期提醒调度已启动，间隔：${intervalMs / 1000 / 60} 分钟`);
  activeScheduler = { timer, firstTimer };
  return activeScheduler;
};

/**
 * 停止调度器并等待当前扫描完成（供优雅关闭调用）
 */
const stopReminderScheduler = async (scheduler) => {
  const target = scheduler || activeScheduler;
  activeScheduler = null;
  if (target) {
    clearTimeout(target.firstTimer);
    clearInterval(target.timer);
  }
  // 等待当前扫描完成（最多 30 秒）
  let waitCount = 0;
  while (isScanning && waitCount < 30) {
    await new Promise((r) => setTimeout(r, 1000));
    waitCount++;
  }
};

module.exports = {
  scanDeviceReminders,
  getDeviceReminders,
  markOverdueInspections,
  startReminderScheduler,
  stopReminderScheduler,
};
