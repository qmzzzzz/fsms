/**
 * 报表统计控制器
 * 提供系统各模块的统计报表和数据分析
 *
 * O-1 重构：导出组件区已迁入 services/reportExportService.js，仪表盘聚合
 * 与缓存已迁入 services/reportDashboardService.js。本文件保留三张统计报表
 * 聚合，以及 exportReport 的参数校验、权限闸与响应编排。
 * 行为口径逐项不变（reportExport*.test.js 为安全网）。
 */

const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope } = require('../middleware/rbac');
const { hasPermission } = require('../utils/permissionHelper');
const { isValidDateParam, buildDateRangeFilter } = require('../utils/helpers');
const { BUSINESS_TIMEZONE } = require('../constants/timezone');
const FireAlarm = require('../models/FireAlarm');
const {
  scopeFilterFor,
  buildExportQuery,
  validateAuditExportEnums,
  EXPORT_MODEL_CONFIG,
} = require('../services/reportExportService');
const { streamExportRows, writeExportWorkbook } = require('../services/reportWorkbookService');
const dashboardService = require('../services/reportDashboardService');
const reportStatsService = require('../services/reportStatsService');

// ── 常量 ─────────────────────────────────────────────────────────────────────
const MS_PER_MINUTE = 1000 * 60; // 毫秒 → 分钟
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const TREND_WINDOW_MS = 30 * MS_PER_DAY; // 趋势统计窗口（30 天）

/**
 * 获取综合仪表盘统计
 * GET /api/reports/dashboard
 */
const getDashboardStats = asyncHandler(async (req, res) => {
  const { data, message } = await dashboardService.getDashboardData(req.user.userId);
  return ApiResponse.success(res, data, message);
});

/**
 * 获取设备报表
 * GET /api/reports/devices
 */
const getDeviceReport = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;

  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
  }

  const data = await reportStatsService.getDeviceReportData({
    ...req.query,
    userId: req.user.userId,
  });
  return ApiResponse.success(res, data, '获取设备报表成功');
});

/**
 * 获取报警报表
 * GET /api/reports/alarms
 */
const getAlarmReport = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;

  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
  }

  // 日期边界统一经 buildDateRangeFilter（本地时区边界口径，见 utils/helpers）
  const dateFilter = buildDateRangeFilter(startDate, endDate);

  const matchStage = Object.keys(dateFilter).length > 0 ? { occurredAt: dateFilter } : {};
  const thirtyDaysAgo = new Date(Date.now() - TREND_WINDOW_MS);

  // 数据范围过滤（与 dashboard/export 口径一致，防止报表统计越权）
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = scopeFilterFor('alarm', dataScope);

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
        // 按天统计（近30天）：时区取业务时区单一声明，与仪表盘「今日」同口径（P3-18）
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

  return ApiResponse.success(
    res,
    {
      byType,
      byStatus,
      byLevel,
      byCause,
      byDay,
      avgResponseTime: Math.round(avgResponseTime[0]?.avgMinutes || 0),
    },
    '获取报警报表成功'
  );
});

/**
 * 获取巡检报表
 * GET /api/reports/inspections
 */
const getInspectionReport = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;

  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
  }

  const data = await reportStatsService.getInspectionReportData({
    ...req.query,
    userId: req.user.userId,
  });
  return ApiResponse.success(res, data, '获取巡检报表成功');
});

/**
 * 导出报表数据
 * GET /api/reports/export
 *
 * O-1 重构：配置/查询构建/枚举校验/流式写出/workbook 编排均在
 * services/reportExportService.js，此处只保留参数校验、权限闸与编排。
 */
const exportReport = asyncHandler(async (req, res) => {
  // P3-13：audit 分支补 ip/userId 筛选参数（与 /security/audit-logs 查询接口同参），
  // 此前导出接口不支持这两个维度——列表筛出 20 条、导出却是全量，「导出即所见」破缺
  const {
    type = 'alarms',
    format = 'xlsx',
    startDate,
    endDate,
    username,
    action,
    category,
    riskLevel,
    success,
    level,
    ip,
    userId,
  } = req.query;

  // 目前仅支持 xlsx,其他格式提前拒绝,避免前端误以为导出成功
  if (format !== 'xlsx') {
    return ApiResponse.codeError(res, 'EXPORT_FORMAT_UNSUPPORTED', { message: `不支持的导出格式: ${format}`, params: { format: format } });
  }

  // 日期参数校验：非法值会产生 Invalid Date 导致查询抛错
  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
  }

  // 日期边界统一经 buildDateRangeFilter：date-only 按本地时区解析，
  // 结束日期补全为当天末尾（与审计日志列表接口的「含当天」语义一致）
  const dateFilter = buildDateRangeFilter(startDate, endDate);

  // 数据范围过滤(与仪表盘保持一致,确保导出数据和所见一致)
  const dataScope = await getDataScope(req.user.userId);

  // ===== 越权出口封堵：audit 类型须额外持有 security:audit =====
  // 审计日志是全系统所有用户的 IP/路径/操作记录，与业务报表不同源：
  // - /api/security/audit-logs 要求 security:audit + strictLimiter
  // - 本接口只要求 report:export（通常下发运营岗）
  // 若不叠加校验，持 report:export 而无 security:audit 者可从此处
  // 全量导出审计日志，绕过整个 security:audit 权限模型（横向提权读取）。
  // audit 分支同时不叠加 dataScope（审计无部门/属主字段，语义上只能全局或禁止），
  // 故此处必须以权限码作为唯一闸门。
  if (type === 'audit') {
    const canReadAudit = await hasPermission(req.user.userId, 'security:audit');
    if (!canReadAudit) {
      logger.warn(
        `审计导出越权尝试被拒：user=${req.user.username || req.user.userId} ` +
          '持 report:export 但无 security:audit'
      );
      return ApiResponse.codeError(res, 'AUDIT_EXPORT_REQUIRES_AUDIT_PERM');
    }
  }

  // audit 分支枚举白名单校验：与 /security/audit-logs 查询接口同一份枚举清单，
  // 防止拼错的 action/category/riskLevel/level 被静默忽略而放大导出范围。
  // P3-13：level 此前缺失校验——非法值不命中派生分支被静默忽略，
  // 用户选「仅错误」却导出全量，且无任何提示
  if (type === 'audit') {
    try {
      validateAuditExportEnums({ action, category, riskLevel, level });
    } catch (err) {
      return ApiResponse.error(res, err.message, 400);
    }
  }

  const query = buildExportQuery(type, {
    dataScope,
    dateFilter,
    username,
    action,
    category,
    riskLevel,
    success,
    level,
    ip,
    userId,
  });
  if (query === null) return ApiResponse.codeError(res, 'REPORT_TYPE_UNSUPPORTED');

  // 无数据权限时直接返回空文件(只有表头)
  if (dataScope.type === 'none') {
    query._id = { $in: [] };
  }

  // 批量导出检测：导出前统计命中行数，超过阈值触发高危审计与告警（补齐导出审计盲区）
  const { checkBulkExport } = require('../services/securityAlert');
  const exportTotal = await EXPORT_MODEL_CONFIG[type].model.countDocuments(query);
  await checkBulkExport(req.user.userId, req.user.username, exportTotal, `report_export_${type}`);

  await writeExportWorkbook(res, { type, query });
});

module.exports = {
  getDashboardStats,
  getDeviceReport,
  getAlarmReport,
  getInspectionReport,
  exportReport,
  // 测试钩子（与 auditBuffer.__resetForTest 同惯例）：O-1 容量上限分支
  // 无法经 HTTP 在合理开销内填满 500 键，测试直接驱动缓存与保护函数；
  // streamExportRows 重导出自 service（B-4 两阶段排序的单测入口）
  __test: {
    ...dashboardService.__test,
    streamExportRows,
  },
};
