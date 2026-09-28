/**
 * 设备/巡检报表统计服务：将数据范围、日期口径与聚合逻辑留在 service 层，
 * 控制器只保留请求校验和统一响应。
 */

const FireDevice = require('../models/FireDevice');
const Inspection = require('../models/Inspection');
const { getDataScope } = require('../middleware/rbac');
const { buildDateRangeFilter } = require('../utils/helpers');
const { scopeFilterFor } = require('./reportExportService');
const { deviceAlertFilters } = require('../constants/deviceAlerts');

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

const getInspectionReportData = async (query) => {
  const { startDate, endDate } = query;
  const dateFilter = buildDateRangeFilter(startDate, endDate);
  const dataScope = await getDataScope(query.userId);
  const scopeFilter = scopeFilterFor('inspection', dataScope);

  const matchFilter = {
    $match: {
      ...scopeFilter,
      ...(Object.keys(dateFilter).length > 0 ? { planStartTime: dateFilter } : {}),
    },
  };

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

  const byType = facetResult?.byType || [];
  const byStatus = facetResult?.byStatus || [];
  const byResult = facetResult?.byResult || [];
  const byAssignee = facetResult?.byAssignee || [];
  const total = facetResult?.total?.[0]?.count || 0;
  const completed = facetResult?.completed?.[0]?.count || 0;
  const completionRate = total > 0 ? Math.round((completed / total) * 100) : 0;

  return { byType, byStatus, byResult, total, completed, completionRate, byAssignee };
};

module.exports = { getDeviceReportData, getInspectionReportData };
