/**
 * 设备/巡检报表统计服务：将数据范围、日期口径与聚合逻辑留在 service 层，
 * 控制器只保留请求校验和统一响应。
 */

const FireDevice = require('../models/FireDevice');
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');
const { getDataScope } = require('../middleware/rbac');
const { buildDateRangeFilter } = require('../utils/helpers');
const { scopeFilterFor } = require('./reportExportService');
const { deviceAlertFilters } = require('../constants/deviceAlerts');
const { BUSINESS_TIMEZONE } = require('../constants/timezone');

const MS_PER_MINUTE = 1000 * 60;
const TREND_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

// 到期窗口不再自己用定长毫秒算：`30*86400*1000` 与其余实现的 `setDate(+30)`
// 在 31 天月份/夏令时下差最多 1 天，同一台设备在一处算"即将到期"、另一处不算。
// 口径唯一来源：constants/deviceAlerts（含 scrapped 排除）。

/**
 * 报表内嵌"即将到期"清单的单次上限（资源护栏）。
 *
 * 刻意**不**与 `EXPIRING_LIST_LIMIT`(50) 合并：那是提醒出口的上限，这里是报表出口，
 * 两者要各自调参（是否统一属待拍板项，见 AGENT 工作总账 §104.7）。
 * 但「截断必须可数」这条约定（`constants/deviceAlerts.js:38-48`、F-174）对本出口同样成立，
 * 所以响应体如实带 `expiringSoonTotal` / `expiringSoonTruncated`：
 * 修复前 20 行的清单与库里 5000 台的清单**同形**，安全员据此排巡检/备耗材。
 */
const EXPIRING_REPORT_LIMIT = 20;

// 日期边界这里的时区口径不是漏接：service 层拿不到 req，也就没有 resolveQueryTimezone 可解析 ?tz，
// 所以本文件的 buildDateRangeFilter(startDate, endDate) 一律两参 ⇒ date-only 落业务时区。
// 报警报表那条链（controllers/reportController.js）把校验过的 tz 传成了第三参，于是同一个 ?tz
// 在两类出口一个生效一个无效——已登记为欠账 B，判据见 src/tests/utils/dateBoundaryTzWiring.test.js。
const getDeviceReportData = async (query) => {
  const { startDate, endDate } = query;
  const dateFilter = buildDateRangeFilter(startDate, endDate);
  const dataScope = await getDataScope(query.userId);
  const scopeFilter = scopeFilterFor('device', dataScope);

  const baseMatch = { ...scopeFilter };
  if (Object.keys(dateFilter).length > 0) baseMatch.installDate = dateFilter;

  // 清单与计数必须共用同一次过滤器构造：分两份写就会各算各的（口径漂移 →
  // "被数进去却没列出来"或反过来，那比没有总数更糟）。
  const expiringFilter = {
    ...scopeFilter,
    // 原先完全没有状态排除：已报废设备会作为"即将到期"连同位置出现在报表里
    ...deviceAlertFilters(new Date()).expiringSoon,
  };

  const [facetResult, expiringSoon, expiringSoonTotal] = await Promise.all([
    FireDevice.aggregate([
      { $match: baseMatch },
      {
        $facet: {
          byType: [
            { $group: { _id: '$deviceType', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
          ],
          byStatus: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
          byBuilding: [
            { $group: { _id: '$location.building', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
          ],
          maintenanceTotal: [
            { $unwind: '$maintenanceRecord' },
            { $group: { _id: null, count: { $sum: 1 } } },
          ],
        },
      },
    ]),
    FireDevice.find(expiringFilter)
      .select('deviceCode deviceName deviceType expiryDate location')
      .sort({ expiryDate: 1 })
      .limit(EXPIRING_REPORT_LIMIT),
    FireDevice.countDocuments(expiringFilter),
  ]);

  const { byType, byStatus, byBuilding, maintenanceTotal } = facetResult[0];
  return {
    byType,
    byStatus,
    byBuilding,
    expiringSoon,
    // 截断可数：命中上限不等于"全部"，total 与 truncated 由同一次过滤得出
    expiringSoonLimit: EXPIRING_REPORT_LIMIT,
    expiringSoonTotal,
    expiringSoonTruncated: expiringSoonTotal > expiringSoon.length,
    totalMaintenance: maintenanceTotal[0]?.count || 0,
  };
};

/** `value || fallback` 的具名形式：把「聚合结果缺省」从主流程的分支里移出去 */
const orDefault = (value, fallback) => value || fallback;

/** 完成率（整数百分比）：分母为 0 时按 0 计，与旧实现一致 */
const completionRateOf = (completed, total) =>
  total > 0 ? Math.round((completed / total) * 100) : 0;

/** 时间窗条件：无日期过滤时不注入 planStartTime（空对象会让 $match 变成恒真） */
const withDateFilter = (scopeFilter, dateFilter) =>
  Object.keys(dateFilter).length > 0 ? { ...scopeFilter, planStartTime: dateFilter } : scopeFilter;

const getInspectionReportData = async (query) => {
  const { startDate, endDate } = query;
  const dateFilter = buildDateRangeFilter(startDate, endDate);
  const dataScope = await getDataScope(query.userId);
  const scopeFilter = scopeFilterFor('inspection', dataScope);

  const matchFilter = { $match: withDateFilter(scopeFilter, dateFilter) };

  // L-2：原先 7 次串行往返，同一份匹配条件下用 $facet 收敛为 1 次，
  // 仪表盘冷启动时显著降低 p95；返回结构与旧实现对齐，前端无需变更。
  const [facetResult] = await Inspection.aggregate([
    matchFilter,
    {
      $facet: {
        byType: [{ $group: { _id: '$inspectionType', count: { $sum: 1 } } }],
        byStatus: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
        byResult: [
          { $match: { status: 'completed' } },
          { $group: { _id: '$result', count: { $sum: 1 } } },
        ],
        total: [{ $count: 'count' }],
        completed: [{ $match: { status: 'completed' } }, { $count: 'count' }],
        byAssignee: [
          { $unwind: '$assignedTo' },
          { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 10 },
        ],
      },
    },
  ]);

  const byType = orDefault(facetResult?.byType, []);
  const byStatus = orDefault(facetResult?.byStatus, []);
  const byResult = orDefault(facetResult?.byResult, []);
  const byAssignee = orDefault(facetResult?.byAssignee, []);
  const total = orDefault(facetResult?.total?.[0]?.count, 0);
  const completed = orDefault(facetResult?.completed?.[0]?.count, 0);
  const completionRate = completionRateOf(completed, total);

  return { byType, byStatus, byResult, total, completed, completionRate, byAssignee };
};

/**
 * 报警报表：一次 $facet 汇总 6 个维度（A-4 自控制器下沉，聚合口径不变）。
 * @param {{scopeFilter: object, matchStage: object}} args
 */
const getAlarmReportData = async ({ scopeFilter, matchStage }) => {
  const thirtyDaysAgo = new Date(Date.now() - TREND_WINDOW_MS);

  // 使用 $facet 将 6 次聚合合并为 1 次查询；顶层 $match 先应用数据范围，各分支再叠加自身过滤
  const [facetResult] = await FireAlarm.aggregate([
    { $match: scopeFilter },
    {
      $facet: {
        // 按类型统计
        byType: [{ $match: matchStage }, { $group: { _id: '$alarmType', count: { $sum: 1 } } }],
        // 按状态统计
        byStatus: [{ $match: matchStage }, { $group: { _id: '$status', count: { $sum: 1 } } }],
        // 按级别统计
        byLevel: [{ $match: matchStage }, { $group: { _id: '$level', count: { $sum: 1 } } }],
        // 按原因统计（与其他分支一致叠加日期过滤，避免选了日期后口径不一致）
        byCause: [
          { $match: { ...matchStage, cause: { $ne: null } } },
          { $group: { _id: '$cause', count: { $sum: 1 } } },
        ],
        // 按天统计（近30天）：时区取业务时区单一声明，与仪表盘「今日」同口径
        byDay: [
          { $match: { occurredAt: { $gte: thirtyDaysAgo } } },
          {
            $group: {
              _id: {
                $dateToString: {
                  format: '%Y-%m-%d',
                  date: '$occurredAt',
                  timezone: BUSINESS_TIMEZONE,
                },
              },
              count: { $sum: 1 },
            },
          },
          { $sort: { _id: 1 } },
        ],
        // 平均响应时间（分钟）（叠加日期过滤；receivedAt 同样加 $ne:null 守卫，
        // 防止缺失字段的文档参与 $subtract 得到 NaN/报错拉低均值）
        avgResponseTime: [
          { $match: { ...matchStage, dispatchedAt: { $ne: null }, receivedAt: { $ne: null } } },
          {
            $group: {
              _id: null,
              avgMinutes: {
                $avg: { $divide: [{ $subtract: ['$dispatchedAt', '$receivedAt'] }, MS_PER_MINUTE] },
              },
            },
          },
        ],
      },
    },
  ]);

  const { byType, byStatus, byLevel, byCause, byDay, avgResponseTime } = facetResult;
  return {
    byType,
    byStatus,
    byLevel,
    byCause,
    byDay,
    avgResponseTime: Math.round(avgResponseTime[0]?.avgMinutes || 0),
  };
};

module.exports = { getDeviceReportData, getInspectionReportData, getAlarmReportData };
