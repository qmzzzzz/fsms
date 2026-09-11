/**
 * 设备/巡检报表统计服务：将数据范围、日期口径与聚合逻辑留在 service 层，
 * 控制器只保留请求校验和统一响应。
 */

const FireDevice = require('../models/FireDevice');
const Inspection = require('../models/Inspection');
const { getDataScope } = require('../middleware/rbac');
const { buildDateRangeFilter } = require('../utils/helpers');
const { scopeFilterFor } = require('./reportExportService');

const MS_PER_MINUTE = 1000 * 60;
const EXPIRY_WINDOW_MS = 30 * MS_PER_MINUTE * 60 * 24;

const getDeviceReportData = async (query) => {
  const { startDate, endDate } = query;
  const dateFilter = buildDateRangeFilter(startDate, endDate);
  const dataScope = await getDataScope(query.userId);
  const scopeFilter = scopeFilterFor('device', dataScope);

  const baseMatch = { ...scopeFilter };
  if (Object.keys(dateFilter).length > 0) baseMatch.installDate = dateFilter;

  const [facetResult, expiringSoon] = await Promise.all([
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
    FireDevice.find({
      ...scopeFilter,
      expiryDate: { $lte: new Date(Date.now() + EXPIRY_WINDOW_MS), $gte: new Date() },
    })
      .select('deviceCode deviceName deviceType expiryDate location')
      .sort({ expiryDate: 1 })
      .limit(20),
  ]);

  const { byType, byStatus, byBuilding, maintenanceTotal } = facetResult[0];
  return {
    byType,
    byStatus,
    byBuilding,
    expiringSoon,
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
