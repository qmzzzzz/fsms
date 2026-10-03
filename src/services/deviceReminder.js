/**
 * 设备到期/维护提醒服务
 * 周期性扫描到期设备与待维护设备，生成提醒记录并写入审计日志，
 * 供前端首页与消息中心展示。
 *
 * 提醒维度：
 *   - expiringSoon 即将到期（默认 30 天内）
 *   - expired     已过期仍在册
 *   - needMaintenance 超过检查周期未维护
 *   - needSchedule 从未录入过检查日、因而根本没有排期的设备
 *     （范围比较 $lte 不匹配缺失字段，缺这一档就等于把"没排期"当成"不需排期"）
 * 四个维度的判据不在这里写：统一取自 constants/deviceAlerts，
 * 与 stats / 报表 / 仪表盘共用同一份，避免同一台设备在两个出口结论相反。
 */

const FireDevice = require('../models/FireDevice');
const logger = require('../utils/logger');
const { deviceAlertFilters } = require('../constants/deviceAlerts');
// 与 reportDashboardService 的「事实逾期」统计共用同一份派生清单（F-151）：两边各写一遍时，看板会
// 统计出调度器永不改写的超期数（或反过来漏计），而漏计在看板上显示为「没有超期」——静默的负结果。
const { INSPECTION_OVERDUE_MARKABLE_STATUSES } = require('../constants/inspection');

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
 * @param {number} options.resultLimit 每维度返回上限（默认 200，防止无界全库返回）。
 *        上限是「单次返回多少条」，不是「库里有多少条命中」；两者必须一起出口，
 *        载体是响应里的 `limits.truncated`（见 ALERT_BUCKETS 下方的说明）
 */
/**
 * 四档查询的固定形状：`[响应键, 排序键, select 投影]`，键名取自
 * `constants/deviceAlerts` 的 `deviceAlertFilters()` 返回值（判据只有一份）。
 *
 * 表格化不是为了少写几行，而是为了让下面那条「多取一条当探针」的规则只有一份实现：
 * 四段近乎相同的 `find().select().sort().limit()` 手抄正是「改三处漏一处」的温床，
 * 而漏掉的那一处不会报错，只会让某一档的计数继续假装是总数。
 */
const ALERT_BUCKETS = [
  ['expired', 'expiryDate', 'deviceCode deviceName deviceType location expiryDate status'],
  ['expiringSoon', 'expiryDate', 'deviceCode deviceName deviceType location expiryDate status'],
  [
    'needMaintenance',
    'nextCheckDate',
    'deviceCode deviceName deviceType location nextCheckDate status',
  ],
  // 从未做过检查 ⇒ 没有排期 ⇒ $lte 判据永不命中。
  // 这一档存在的理由就是：一台装好多年的设备可以在所有出口里永久隐身。
  [
    'needSchedule',
    'installDate',
    'deviceCode deviceName deviceType location installDate checkCycle status',
  ],
];

/** 与 ALERT_BUCKETS 同序的档位名，供"未扫描"兜底补齐形状 */
const ALERT_BUCKET_KEYS = ALERT_BUCKETS.map(([key]) => key);

/**
 * 形状完整的"本次未扫描"结果。
 *
 * 互斥锁命中时旧实现只回 `{summary:{total:0}, skipped:true}`——三个（现四个）明细数组键
 * 根本不存在，控制器仍按 200 + "获取设备提醒成功"返回。于是首页卡片显示"0 条待办"，
 * 与"确实没有到期设备"在响应形状上无法区分，安全提醒被静默丢弃。
 * 现在补齐全部键并带 `partial:true`，让调用方至少能判别降级。
 */
const unscannedResult = () => ({
  scannedAt: new Date().toISOString(),
  summary: { expired: 0, expiringSoon: 0, needMaintenance: 0, needSchedule: 0, total: 0 },
  expired: [],
  expiringSoon: [],
  needMaintenance: [],
  needSchedule: [],
  limits: {
    // 本次没有扫描 ⇒ 没有上限可言，也没有清单被截断；这些 0 的含义由 `partial` 承担，
    // 键必须与正常路径同构，否则调用方读 `limits.truncated.expired` 又是一次 undefined
    resultLimit: null,
    truncated: {
      ...Object.fromEntries(ALERT_BUCKET_KEYS.map((key) => [key, false])),
      total: false,
    },
  },
  skipped: true,
  partial: true,
});

const scanDeviceReminders = async (options = {}) => {
  // 互斥锁：防止并发重叠
  if (isScanning) {
    // H-1 数据边界：带 scopeFilter 的调用绝不可返回全局缓存——
    // 那是无范围的全库扫描结果，直接返回会把全部设备提醒泄漏给低权限用户
    if (options.scopeFilter) {
      logger.warn('设备到期扫描已在进行中，本次数据范围查询跳过');
      return unscannedResult();
    }
    logger.warn('设备到期扫描已在进行中，返回上次全库结果');
    return lastScanResult || unscannedResult();
  }
  isScanning = true;

  try {
    const { expiringDays = 30, scopeFilter = null, resultLimit = 200 } = options;
    const base = scopeFilter || {};
    // 判定时刻取一次，四档共用（跨秒会让同一响应的两档用两个 now）
    const alert = deviceAlertFilters(new Date(), expiringDays);

    // 每档多取一条当探针：`limit(resultLimit)` 拿到 `resultLimit` 条时，
    // 「够不够回答总数」这个问题根本没有信息量——5000 台超期与 200 台超期
    // 在响应里是同一个形状。多一条只回答「后面还有没有」，而这一条恰好不进清单，
    // 于是计数与清单同源于同一次查询，不可能分叉成两个窗口里的数。
    // 四档串行发出（不是 Promise.all）：同一次响应里的判定时刻已经由上面的 `alert` 唯一确定，
    // 并发只是把「互斥锁命中」时的在途查询数从 1 变成 4，那是另一条线在钉的性质。
    const pages = [];
    for (const [key, sortKey, projection] of ALERT_BUCKETS) {
      const docs = await FireDevice.find({ ...base, ...alert[key] })
        .select(projection)
        .sort({ [sortKey]: 1 })
        .limit(resultLimit + 1);
      pages.push({
        key,
        items: docs.slice(0, resultLimit),
        truncated: docs.length > resultLimit,
      });
    }

    const buckets = Object.fromEntries(pages.map(({ key, items }) => [key, items]));
    // 任一档被截断 ⇒ total 同样是下界（total 由四档页内集合去重而来，
    // 看不见没进页面的设备）
    const anyTruncated = pages.some((page) => page.truncated);

    // total 按设备去重：同一设备可同时命中 expired 与 needMaintenance，
    // 直接相加会把一台设备计成两台，总数虚高
    const uniqueDeviceIds = new Set(pages.flatMap((page) => page.items).map((d) => String(d._id)));

    const summary = {
      expired: buckets.expired.length,
      expiringSoon: buckets.expiringSoon.length,
      needMaintenance: buckets.needMaintenance.length,
      needSchedule: buckets.needSchedule.length,
      total: uniqueDeviceIds.size,
    };

    const result = {
      scannedAt: new Date().toISOString(),
      expiringDays,
      summary,
      ...buckets,
      limits: {
        resultLimit,
        truncated: {
          ...Object.fromEntries(pages.map((page) => [page.key, page.truncated])),
          total: anyTruncated,
        },
      },
    };

    // 仅后台全库扫描写入全局缓存；按用户范围的查询结果各不相同，不可缓存共享
    if (!scopeFilter) {
      lastScanResult = result;
      lastScanAt = new Date();
    }

    logger.info(
      `设备到期扫描完成：过期 ${summary.expired} / 即将到期 ${summary.expiringSoon} / 待维护 ${summary.needMaintenance} / 未排期 ${summary.needSchedule}${
        anyTruncated ? `（至少一档达到单次上限 ${resultLimit}，上面的数是页内值而非库里总数）` : ''
      }`
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
        status: { $in: INSPECTION_OVERDUE_MARKABLE_STATUSES },
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
    // 提醒扫描的附加职责，失败不应影响设备提醒本身。
    // 本函数被调度器裸调用（无 await），所以"永不 reject"是硬契约：catch 体自己也
    // 不能抛——被 reject(undefined/null) 时 `${err.message}` 会变成 TypeError，
    // 那正是本函数要消除的东西（未持有的 rejection ⇒ index.js 的 unhandledRejection ⇒ 进程下线）。
    logger.error(`巡检逾期标记失败：${err?.message ?? err}`);
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

  // 服务启动后延迟 30 秒执行首次扫描，避免与初始化争抢连接。
  // 定时器回调是同步的：里面每个 promise 都必须就地持有（.catch），否则回调返回时
  // 它还在飞——一次拒绝没人接 = 进程下线（见 src/index.js 的 unhandledRejection 处理器）。
  const firstTimer = setTimeout(() => {
    scanDeviceReminders().catch((err) =>
      logger.error(`首次设备到期扫描失败：${err?.message ?? err}`)
    );
    markOverdueInspections().catch((err) =>
      logger.error(`首次巡检逾期标记失败：${err?.message ?? err}`)
    );
  }, 30 * 1000);

  const timer = setInterval(() => {
    // 巡检逾期标记与设备扫描互不依赖，即使扫描被跳过也要执行
    markOverdueInspections().catch((err) =>
      logger.error(`巡检逾期标记调度失败：${err?.message ?? err}`)
    );
    // 防止并发重叠：上次扫描未完成时跳过
    if (isScanning) {
      logger.warn('上一次设备到期扫描尚未完成，跳过本次');
      return;
    }
    scanDeviceReminders().catch((err) =>
      logger.error(`设备到期周期扫描失败：${err?.message ?? err}`)
    );
  }, intervalMs);
  timer.unref?.();
  firstTimer.unref?.();

  logger.info(`设备到期提醒调度已启动，间隔：${intervalMs / 1000 / 60} 分钟`);
  activeScheduler = { timer, firstTimer };
  return activeScheduler;
};

/**
 * 停止调度器并等待当前扫描完成（供优雅关闭调用）
 * @param {object} [scheduler] 调度器句柄，缺省用模块内 activeScheduler
 * @param {{maxWaitMs?: number}} [opts] 最长等待。30 s 是硬上限，但优雅关闭会按
 *   关停总预算把它压得更小（F-103）：一次扫描跑不跑完，不该决定排在前面的审计能不能落盘。
 */
const stopReminderScheduler = async (scheduler, { maxWaitMs = 30000 } = {}) => {
  const target = scheduler || activeScheduler;
  activeScheduler = null;
  if (target) {
    clearTimeout(target.firstTimer);
    clearInterval(target.timer);
  }
  const scanWaitDeadline = Date.now() + Math.max(0, maxWaitMs);
  while (isScanning && Date.now() < scanWaitDeadline) {
    await new Promise((r) => setTimeout(r, 1000));
  }
};

module.exports = {
  scanDeviceReminders,
  getDeviceReminders,
  markOverdueInspections,
  startReminderScheduler,
  stopReminderScheduler,
};
