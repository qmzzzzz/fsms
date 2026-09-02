/**
 * 报表统计控制器
 * 提供系统各模块的统计报表和数据分析
 */

const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope, buildDataScopeFilter } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { hasPermission } = require('../utils/permissionHelper');
const {
  escapeRegExp,
  sanitizeSpreadsheetCell,
  buildDateRangeFilter,
  validateEnum,
} = require('../utils/helpers');
// 审计枚举单一事实来源：constants/audit.js（D-1 起 AUDIT_LOG_ACTIONS 亦收敛于此）
const { AUDIT_CATEGORIES, AUDIT_RISK_LEVELS, AUDIT_LOG_ACTIONS } = require('../constants/audit');
const { BUSINESS_TIMEZONE, businessDayBounds } = require('../constants/timezone');
const crypto = require('crypto');
const mongoose = require('mongoose');
const FireDevice = require('../models/FireDevice');
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');

/**
 * 按资源类型生成数据范围过滤条件（P2-20 单一口径入口）
 *
 * 此前每个统计/导出分支各自硬编码属主字段，设备资源在列表用
 * maintenanceRecord.operator、在报表用 createdBy，两套口径导致
 * 「可见清单」与「统计数字」永久对不上，且导出比列表宽（越权面）。
 * @param {'device'|'alarm'|'inspection'|'user'} resource
 */
const scopeFilterFor = (resource, dataScope) => {
  const { ownerField, departmentField } = DATA_SCOPE_FIELDS[resource];
  return buildDataScopeFilter(dataScope, ownerField, departmentField);
};

// ── 仪表盘结果缓存（P-04）：高频只读聚合，30s TTL 显著降低数据库压力 ──
// 与 statsCache 同理，进程内 TTL 缓存；数据范围过滤条件纳入缓存键，天然按用户+数据范围隔离。
// 仅 TTL 失效（无主动失效钩子）：仪表盘为概览统计，最多 30 秒偏差对决策无实质影响。
// 容量上限（R-2 报告 O-1）：键含 userId+过滤指纹，高基数组合下无上限增长；
// 与 userCache/statsCache 口径对齐，超限先清过期、仍超清最旧（Map 插入序即时间序）
const dashboardCache = new Map(); // key -> { data, expireAt }
const DASHBOARD_CACHE_TTL_MS = 30 * 1000;
const DASHBOARD_CACHE_MAX_ENTRIES = 500;

const dashboardCacheTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of dashboardCache.entries()) {
    if (entry.expireAt <= now) dashboardCache.delete(key);
  }
}, 30 * 1000);
dashboardCacheTimer.unref?.();

/** 写入前容量保护：先清过期项，仍超限则淘汰最旧条目（30s TTL 下正常规模远达不到上限） */
const enforceDashboardCacheLimit = () => {
  if (dashboardCache.size < DASHBOARD_CACHE_MAX_ENTRIES) return;
  const now = Date.now();
  for (const [key, entry] of dashboardCache.entries()) {
    if (entry.expireAt <= now) dashboardCache.delete(key);
  }
  while (dashboardCache.size >= DASHBOARD_CACHE_MAX_ENTRIES) {
    dashboardCache.delete(dashboardCache.keys().next().value);
  }
};

const getDashboardCacheKey = (userId, filters) => {
  const fp = crypto.createHash('sha1').update(JSON.stringify(filters)).digest('hex').slice(0, 16);
  return `dash:${userId}:${fp}`;
};

// $facet 子管道输出 { n: count } 的提取辅助：$count 返回数组，取首项
const facetCount = (arr) => (arr && arr[0] && typeof arr[0].n === 'number' ? arr[0].n : 0);

// ── 常量 ─────────────────────────────────────────────────────────────────────
const EXPORT_LIMIT = 5000; // 导出最大行数
const MS_PER_MINUTE = 1000 * 60; // 毫秒 → 分钟
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const EXPIRY_WINDOW_MS = 30 * MS_PER_DAY; // 设备即将过期窗口（30 天）
const TREND_WINDOW_MS = 30 * MS_PER_DAY; // 趋势统计窗口（30 天）

/**
 * 校验查询参数中的日期格式（非法日期会产生 Invalid Date 导致查询抛错 500）
 * @returns {boolean} 是否合法
 */
const isValidDateParam = (value) =>
  value === undefined || value === '' || !isNaN(new Date(value).getTime());

/**
 * 获取综合仪表盘统计
 * GET /api/reports/dashboard
 */
const getDashboardStats = asyncHandler(async (req, res) => {
  const dataScope = await getDataScope(req.user.userId);

  // P3-18：今日边界改由业务时区单一声明给出。
  // 原实现用 `new Date(y, m-1, d)`（服务器本地时区）算「今天」，
  // 而下方 byDay 聚合硬编码 '+08:00'——容器跑 UTC 时两个「天」错位，
  // 「今日报警数」与趋势图末点在 UTC 16:00 后必然对不上。
  const now = new Date();
  const { start: startOfDay, end: endOfDay } = businessDayBounds();

  // 根据数据范围生成过滤条件，确保用户只能看到权限范围内的统计数据
  const deviceFilter = scopeFilterFor('device', dataScope);
  const alarmFilter = scopeFilterFor('alarm', dataScope);
  const inspectionFilter = scopeFilterFor('inspection', dataScope);

  // 无数据权限时直接返回空统计
  if (dataScope.type === 'none') {
    return ApiResponse.success(
      res,
      {
        devices: { total: 0, online: 0, fault: 0, needMaintenance: 0, byType: [] },
        alarms: { total: 0, pending: 0, today: 0, byLevel: [], avgResponse: 0 },
        inspections: { total: 0, pending: 0, overdue: 0, today: 0, completionRate: 0 },
      },
      '获取仪表盘统计成功'
    );
  }

  // P-04：结果缓存（30s TTL）。键含 userId + 数据范围过滤指纹，按用户+范围隔离。
  const cacheKey = getDashboardCacheKey(req.user.userId, {
    d: deviceFilter,
    a: alarmFilter,
    i: inspectionFilter,
  });
  const cached = dashboardCache.get(cacheKey);
  if (cached && cached.expireAt > Date.now()) {
    return ApiResponse.success(res, cached.data, '获取仪表盘统计成功（缓存命中）');
  }

  // P-03：将原先 15+ 次独立查询合并为 3 条 $facet 聚合管道，单次往返计算全部指标，
  // 大幅降低数据库连接与往返开销（原先每个 countDocuments/aggregate 均为独立往返）。

  const [deviceFacet] = await FireDevice.aggregate([
    { $match: deviceFilter },
    {
      $facet: {
        total: [{ $count: 'n' }],
        online: [{ $match: { status: 'normal' } }, { $count: 'n' }],
        fault: [{ $match: { status: { $in: ['fault', 'warning'] } } }, { $count: 'n' }],
        needMaintenance: [
          { $match: { nextCheckDate: { $lte: now }, status: { $ne: 'maintenance' } } },
          { $count: 'n' },
        ],
        byType: [{ $group: { _id: '$deviceType', count: { $sum: 1 } } }, { $sort: { count: -1 } }],
      },
    },
  ]);

  const [alarmFacet] = await FireAlarm.aggregate([
    { $match: alarmFilter },
    {
      $facet: {
        total: [{ $count: 'n' }],
        pending: [{ $match: { status: 'pending' } }, { $count: 'n' }],
        today: [{ $match: { occurredAt: { $gte: startOfDay } } }, { $count: 'n' }],
        byLevel: [{ $group: { _id: '$level', count: { $sum: 1 } } }],
        avgResponse: [
          { $match: { dispatchedAt: { $ne: null }, receivedAt: { $ne: null } } },
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

  const [inspectionFacet] = await Inspection.aggregate([
    { $match: inspectionFilter },
    {
      $facet: {
        total: [{ $count: 'n' }],
        pending: [{ $match: { status: 'pending' } }, { $count: 'n' }],
        // P2-19：overdue 已成为真实状态（由 deviceReminder.markOverdueInspections 推进）。
        // 仍保留 `pending 且已过计划结束时间` 的兜底口径：调度器两次执行之间
        // 新到期的计划尚未被标记，只按 status 统计会短时漏计。
        overdue: [
          {
            $match: {
              $or: [
                { status: 'overdue' },
                { status: { $in: ['pending', 'in_progress'] }, planEndTime: { $lte: now } },
              ],
            },
          },
          { $count: 'n' },
        ],
        today: [
          {
            $match: {
              $or: [
                { actualStartTime: { $gte: startOfDay } },
                // 计划窗口覆盖整个当日（00:00 ~ 23:59:59.999），晚间计划同样计入当日
                { planStartTime: { $gte: startOfDay, $lte: endOfDay } },
              ],
            },
          },
          { $count: 'n' },
        ],
        completed: [{ $match: { status: 'completed' } }, { $count: 'n' }],
      },
    },
  ]);

  const data = {
    devices: {
      total: facetCount(deviceFacet.total),
      online: facetCount(deviceFacet.online),
      fault: facetCount(deviceFacet.fault),
      needMaintenance: facetCount(deviceFacet.needMaintenance),
      byType: deviceFacet.byType || [],
    },
    alarms: {
      total: facetCount(alarmFacet.total),
      pending: facetCount(alarmFacet.pending),
      today: facetCount(alarmFacet.today),
      byLevel: alarmFacet.byLevel || [],
      avgResponse: Math.round(alarmFacet.avgResponse[0]?.avgMinutes || 0),
    },
    inspections: {
      total: facetCount(inspectionFacet.total),
      pending: facetCount(inspectionFacet.pending),
      overdue: facetCount(inspectionFacet.overdue),
      today: facetCount(inspectionFacet.today),
      completionRate:
        facetCount(inspectionFacet.total) > 0
          ? Math.round(
              (facetCount(inspectionFacet.completed) / facetCount(inspectionFacet.total)) * 100
            )
          : 0,
    },
  };

  enforceDashboardCacheLimit();
  dashboardCache.set(cacheKey, { data, expireAt: Date.now() + DASHBOARD_CACHE_TTL_MS });

  return ApiResponse.success(res, data, '获取仪表盘统计成功');
});

/**
 * 获取设备报表
 * GET /api/reports/devices
 */
const getDeviceReport = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;

  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.error(res, '日期参数格式错误', 400);
  }

  // 日期边界统一经 buildDateRangeFilter（本地时区边界口径，见 utils/helpers）
  const dateFilter = buildDateRangeFilter(startDate, endDate);

  // 数据范围过滤（与 dashboard/export 口径一致，防止报表统计越权）
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = scopeFilterFor('device', dataScope);

  // 修复：dateFilter 此前计算后未用于查询，现并入 $match（按安装日期统计报表）
  const baseMatch = { ...scopeFilter };
  if (Object.keys(dateFilter).length > 0) baseMatch.installDate = dateFilter;

  // 使用 $facet 将 3 次独立聚合合并为一次查询
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
    // 即将过期设备（同样纳入数据范围过滤，避免越权可见）
    FireDevice.find({
      ...scopeFilter,
      expiryDate: { $lte: new Date(Date.now() + EXPIRY_WINDOW_MS), $gte: new Date() },
    })
      .select('deviceCode deviceName deviceType expiryDate location')
      .sort({ expiryDate: 1 })
      .limit(20),
  ]);

  const { byType, byStatus, byBuilding, maintenanceTotal } = facetResult[0];

  return ApiResponse.success(
    res,
    {
      byType,
      byStatus,
      byBuilding,
      expiringSoon,
      totalMaintenance: maintenanceTotal[0]?.count || 0,
    },
    '获取设备报表成功'
  );
});

/**
 * 获取报警报表
 * GET /api/reports/alarms
 */
const getAlarmReport = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;

  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.error(res, '日期参数格式错误', 400);
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
    return ApiResponse.error(res, '日期参数格式错误', 400);
  }

  // 日期边界统一经 buildDateRangeFilter（本地时区边界口径，见 utils/helpers）
  const dateFilter = buildDateRangeFilter(startDate, endDate);

  // 数据范围过滤（与 dashboard/export 口径一致，防止报表统计越权）
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = scopeFilterFor('inspection', dataScope);

  const matchStage = {
    $match: {
      ...scopeFilter,
      ...(Object.keys(dateFilter).length > 0 ? { planStartTime: dateFilter } : {}),
    },
  };

  // 按类型统计
  const byType = await Inspection.aggregate([
    matchStage,
    { $group: { _id: '$inspectionType', count: { $sum: 1 } } },
  ]);

  // 按状态统计
  const byStatus = await Inspection.aggregate([
    matchStage,
    { $group: { _id: '$status', count: { $sum: 1 } } },
  ]);

  // 按结果统计（修复：叠加日期过滤，与其他统计口径一致）
  const byResult = await Inspection.aggregate([
    { $match: { ...(matchStage.$match || {}), status: 'completed' } },
    { $group: { _id: '$result', count: { $sum: 1 } } },
  ]);

  // 完成率统计（叠加数据范围过滤，与聚合口径一致）
  const totalQuery = {
    ...scopeFilter,
    ...(Object.keys(dateFilter).length > 0 ? { planStartTime: dateFilter } : {}),
  };
  const completedQuery = { ...totalQuery, status: 'completed' };
  const total = await Inspection.countDocuments(totalQuery);
  const completed = await Inspection.countDocuments(completedQuery);
  const completionRate = total > 0 ? Math.round((completed / total) * 100) : 0;

  // 按人员统计（修复：叠加日期过滤）
  const byAssignee = await Inspection.aggregate([
    matchStage,
    { $unwind: '$assignedTo' },
    { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 10 },
  ]);

  return ApiResponse.success(
    res,
    {
      byType,
      byStatus,
      byResult,
      total,
      completed,
      completionRate,
      byAssignee,
    },
    '获取巡检报表成功'
  );
});

/**
 * 导出报表数据
 * GET /api/reports/export
 */
const ExcelJS = require('exceljs');

// 状态映射
const statusMap = {
  pending: '待处理',
  processing: '处理中',
  resolved: '已处理',
  false_alarm: '误报',
  cancelled: '已取消',
};

const alarmTypeMap = {
  smoke: '烟雾报警',
  temp_abnormal: '温度异常',
  manual_button: '手动报警',
  phone_report: '电话报告',
  patrol_find: '巡检发现',
  other: '其他',
};

const deviceStatusMap = {
  normal: '正常',
  offline: '离线',
  fault: '故障',
  maintenance: '维护中',
};

const AuditLog = require('../models/AuditLog');
const { normalizeIP } = require('../utils/ipUtils');

// ══════════════════════════════════════════════════════════════
// 导出（exportReport）拆分组件（七维终评：380+ 行多职责函数收敛）
// 原则：纯配置与纯函数提到模块级，handler 只做参数校验与编排；
// 行为口径与原实现逐项一致，仅结构调整。
// ══════════════════════════════════════════════════════════════

const EXPORT_SHEET_NAMES = {
  alarms: '报警记录',
  devices: '设备列表',
  inspections: '巡检记录',
  audit: '审计日志',
};

// 模型 + 排序 + populate + 字段裁剪配置（选择投影在查询阶段生效）
const EXPORT_MODEL_CONFIG = {
  alarms: {
    model: FireAlarm,
    sort: { occurredAt: -1 },
    populate: [
      { path: 'handler', select: 'username realName' },
      { path: 'deviceId', select: 'deviceCode deviceName' },
    ],
  },
  devices: { model: FireDevice, sort: { deviceCode: 1 }, populate: [] },
  audit: {
    model: AuditLog,
    sort: { timestamp: -1 },
    populate: [],
    select: '-body -params -query',
  },
  inspections: {
    model: Inspection,
    sort: { planStartTime: -1 },
    populate: [{ path: 'assignedTo', select: 'username realName' }],
  },
};

const EXPORT_COLUMN_DEFS = {
  alarms: [
    { header: '报警编号', key: 'alarmCode', width: 15 },
    { header: '报警时间', key: 'occurredAt', width: 18 },
    { header: '报警类型', key: 'alarmType', width: 12 },
    { header: '报警位置', key: 'location', width: 20 },
    { header: '描述', key: 'description', width: 30 },
    { header: '状态', key: 'status', width: 10 },
    { header: '上报人', key: 'reporter', width: 12 },
    { header: '处理人', key: 'handler', width: 12 },
    { header: '处理结果', key: 'handleResult', width: 25 },
  ],
  devices: [
    { header: '设备编码', key: 'deviceCode', width: 15 },
    { header: '设备名称', key: 'deviceName', width: 20 },
    { header: '设备类型', key: 'deviceType', width: 15 },
    { header: '状态', key: 'status', width: 10 },
    { header: '安装位置', key: 'location', width: 25 },
    { header: '下次检查', key: 'nextCheckDate', width: 12 },
    { header: '过期时间', key: 'expiryDate', width: 12 },
  ],
  audit: [
    { header: '操作时间', key: 'timestamp', width: 20 },
    { header: '日志等级', key: 'level', width: 10 },
    { header: '操作用户', key: 'username', width: 15 },
    { header: '操作类型', key: 'action', width: 20 },
    { header: '分类', key: 'category', width: 12 },
    { header: '请求方式', key: 'method', width: 10 },
    { header: '请求路径', key: 'path', width: 30 },
    { header: 'IP 地址', key: 'ip', width: 16 },
    { header: '风险等级', key: 'riskLevel', width: 12 },
    { header: '操作结果', key: 'success', width: 12 },
    { header: '执行时长', key: 'duration', width: 12 },
  ],
  inspections: [
    { header: '巡检标题', key: 'title', width: 25 },
    { header: '巡检类型', key: 'inspectionType', width: 12 },
    { header: '状态', key: 'status', width: 10 },
    { header: '结果', key: 'result', width: 10 },
    { header: '计划开始', key: 'planStartTime', width: 18 },
    { header: '计划结束', key: 'planEndTime', width: 18 },
    { header: '实际开始', key: 'actualStartTime', width: 18 },
    { header: '实际结束', key: 'actualEndTime', width: 18 },
    { header: '执行人', key: 'assignedTo', width: 15 },
    { header: '备注', key: 'remark', width: 30 },
  ],
};

// 审计 action 展示名（导出用；与审计页 labelMaps 相互独立，口径同义）
const EXPORT_ACTION_LABELS = {
  login_success: '登录成功',
  login_failed: '登录失败',
  logout: '退出登录',
  user_create: '创建用户',
  user_update: '更新用户',
  user_delete: '删除用户',
  role_create: '创建角色',
  role_update: '更新角色',
  role_delete: '删除角色',
  device_create: '创建设备',
  device_update: '更新设备',
  alarm_dispatch: '指派报警',
  alarm_resolve: '处理报警',
  password_changed: '修改密码',
  suspicious_report: '安全举报',
};
const EXPORT_RISK_LEVEL_LABELS = { critical: '严重', high: '高', medium: '中', low: '低' };

const formatExportLocation = (loc) => {
  if (!loc) return '-';
  const { building, floor, room } = loc;
  return building || floor || room ? `${building || ''}${floor || ''}${room || ''}` : '-';
};

const EXPORT_ROW_TRANSFORMS = {
  alarms: (item) => ({
    alarmCode: item.alarmCode,
    occurredAt: item.occurredAt ? new Date(item.occurredAt).toLocaleString('zh-CN') : '-',
    alarmType: alarmTypeMap[item.alarmType] || item.alarmType || '-',
    location: formatExportLocation(item.location),
    description: item.description || '-',
    status: statusMap[item.status] || item.status || '-',
    reporter: (item.reporter && (item.reporter.name || item.reporter.username)) || '-',
    handler: (item.handler && (item.handler.realName || item.handler.username)) || '-',
    handleResult: item.handleResult || '-',
  }),
  devices: (item) => ({
    deviceCode: item.deviceCode || '-',
    deviceName: item.deviceName || '-',
    deviceType: item.deviceType || '-',
    status: deviceStatusMap[item.status] || item.status || '-',
    location: formatExportLocation(item.location),
    nextCheckDate: item.nextCheckDate
      ? new Date(item.nextCheckDate).toLocaleDateString('zh-CN')
      : '-',
    expiryDate: item.expiryDate ? new Date(item.expiryDate).toLocaleDateString('zh-CN') : '-',
  }),
  audit: (item) => ({
    timestamp: item.timestamp
      ? new Date(item.timestamp).toLocaleString('zh-CN', { hour12: false })
      : '-',
    // 日志等级派生口径与 /security/audit-logs 一致
    level:
      !item.success || ['high', 'critical'].includes(item.riskLevel)
        ? '错误'
        : item.riskLevel === 'medium'
          ? '警告'
          : '信息',
    username: item.username || '-',
    action: EXPORT_ACTION_LABELS[item.action] || item.action || '-',
    category: item.category || '-',
    method: item.method || '-',
    path: item.path || '-',
    ip: item.ip || '-',
    riskLevel: EXPORT_RISK_LEVEL_LABELS[item.riskLevel] || item.riskLevel || '-',
    success: item.success ? '成功' : '失败',
    duration: item.duration ? `${item.duration}ms` : '-',
  }),
  inspections: (item) => ({
    title: item.title || '-',
    inspectionType: item.inspectionType || '-',
    status: item.status || '-',
    result: item.result || '-',
    planStartTime: item.planStartTime ? new Date(item.planStartTime).toLocaleString('zh-CN') : '-',
    planEndTime: item.planEndTime ? new Date(item.planEndTime).toLocaleString('zh-CN') : '-',
    actualStartTime: item.actualStartTime
      ? new Date(item.actualStartTime).toLocaleString('zh-CN')
      : '-',
    actualEndTime: item.actualEndTime ? new Date(item.actualEndTime).toLocaleString('zh-CN') : '-',
    assignedTo:
      item.assignedTo && item.assignedTo.length > 0
        ? item.assignedTo
            .map((u) => (u && (u.realName || u.username)) || '')
            .filter(Boolean)
            .join(', ')
        : '-',
    remark: item.remark || '-',
  }),
};

/** 电子表格公式注入防护包装：对所有单元格文本做危险前缀加固（= + - @ Tab CR） */
const createSafeTransform = (transform) => (item) => {
  const row = transform(item);
  for (const key of Object.keys(row)) {
    row[key] = sanitizeSpreadsheetCell(row[key]);
  }
  return row;
};

/**
 * 按导出类型构建查询条件（原 exportReport 内联 buildQuery 的模块级提取）
 * @returns {Object|null} 查询条件；不支持的 type 返回 null
 */
const buildExportQuery = (type, ctx) => {
  const {
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
  } = ctx;
  const withDate = (scopeFilter, field) =>
    Object.keys(dateFilter).length > 0 ? { ...scopeFilter, [field]: dateFilter } : scopeFilter;

  switch (type) {
    case 'alarms':
      return withDate(scopeFilterFor('alarm', dataScope), 'occurredAt');
    case 'devices':
      // 修复：devices 导出分支此前忽略了 dateFilter，导致用户传入 startDate/endDate 后
      // 导出结果不受日期过滤（与 alarms/inspections 分支口径不一致）
      return withDate(scopeFilterFor('device', dataScope), 'installDate');
    case 'inspections':
      // 修复：补全巡检导出查询，应用数据范围和日期过滤
      return withDate(scopeFilterFor('inspection', dataScope), 'planStartTime');
    case 'audit': {
      const auditQuery = {};
      if (Object.keys(dateFilter).length > 0) auditQuery.timestamp = dateFilter;
      // 使用 escapeRegExp 防止 ReDoS 正则拒绝服务攻击
      if (username) auditQuery.username = { $regex: escapeRegExp(username), $options: 'i' };
      // action/category 为枚举值,精确匹配,与审计日志查询接口语义一致
      if (action) auditQuery.action = action;
      if (category) auditQuery.category = category;
      if (riskLevel) auditQuery.riskLevel = riskLevel;
      if (success !== undefined && success !== '') {
        auditQuery.success = success === 'true' || success === true;
      }
      // P3-13：补齐 ip/userId 维度，与 /security/audit-logs 查询口径一致。
      // ip 归一化 + 原始值双匹配（存量记录可能以 ::ffff:1.2.3.4 形式落库）
      if (ip) {
        const normalizedIP = normalizeIP(ip);
        if (!normalizedIP) throw new Error('参数 ip 必须是合法的 IPv4/IPv6 地址');
        const ipVariants = [...new Set([normalizedIP, String(ip).trim()])];
        auditQuery.ip = ipVariants.length > 1 ? { $in: ipVariants } : ipVariants[0];
      }
      if (userId) {
        if (!mongoose.Types.ObjectId.isValid(userId)) {
          throw new Error('参数 userId 必须是合法的用户 ID');
        }
        auditQuery.userId = userId;
      }
      // 日志等级派生筛选,与 /security/audit-logs 接口口径保持一致(导出即所见)
      // 用 $and 叠加而非直接覆盖字段,避免丢弃用户已选的 success/riskLevel 筛选
      if (level && ['info', 'warning', 'error'].includes(level)) {
        let levelCond;
        if (level === 'error') {
          levelCond = { $or: [{ success: false }, { riskLevel: { $in: ['high', 'critical'] } }] };
        } else if (level === 'warning') {
          levelCond = { success: true, riskLevel: 'medium' };
        } else {
          levelCond = { success: true, riskLevel: { $nin: ['medium', 'high', 'critical'] } };
        }
        auditQuery.$and = [...(auditQuery.$and || []), levelCond];
      }
      return auditQuery;
    }
    default:
      return null;
  }
};

/**
 * audit 分支枚举白名单校验：与 /security/audit-logs 查询接口同一份枚举清单，
 * 防止拼错的 action/category/riskLevel/level 被静默忽略而放大导出范围。
 * P3-13：level 此前缺失校验——非法值不命中派生分支被静默忽略，
 * 用户选「仅错误」却导出全量，且无任何提示
 * @throws {Error} 非法枚举值（消息可直接回给调用方）
 */
const validateAuditExportEnums = ({ action, category, riskLevel, level }) => {
  validateEnum(action, AUDIT_LOG_ACTIONS, 'action');
  validateEnum(category, AUDIT_CATEGORIES, 'category');
  validateEnum(riskLevel, AUDIT_RISK_LEVELS, 'riskLevel');
  validateEnum(level, ['info', 'warning', 'error'], 'level');
};

/**
 * 流式写出导出行：
 * - 有 populate：populate 不支持 cursor，用基于 _id 的范围分批替代 skip（避免 O(n²)），
 *   且累计达到 EXPORT_LIMIT 即截断（修复：此前 populate 分批不带上限）
 * - 无 populate：mongoose cursor 顺序流式读取
 */
const streamExportRows = async (worksheet, config, query, safeTransform) => {
  if (config.populate && config.populate.length > 0) {
    const BATCH_SIZE = 200;
    let lastId = null;
    let exportedCount = 0;
    let batch;
    do {
      const batchQuery = { ...query };
      if (lastId) batchQuery._id = { $gt: lastId };
      batch = await config.model
        .find(batchQuery)
        .sort({ _id: 1 })
        .limit(BATCH_SIZE)
        .populate(config.populate)
        .lean();
      for (const item of batch) {
        worksheet.addRow(safeTransform(item));
        lastId = item._id;
        exportedCount++;
        if (exportedCount >= EXPORT_LIMIT) break;
      }
    } while (batch.length === BATCH_SIZE && exportedCount < EXPORT_LIMIT);
  } else {
    const cursor = config.model
      .find(query)
      .sort(config.sort)
      .limit(EXPORT_LIMIT)
      .select(config.select)
      .cursor();
    for await (const doc of cursor) {
      worksheet.addRow(safeTransform(doc));
    }
  }
};

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
    return ApiResponse.error(res, `不支持的导出格式: ${format}`, 400);
  }

  // 日期参数校验：非法值会产生 Invalid Date 导致查询抛错
  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.error(res, '日期参数格式错误', 400);
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

  // 查询条件构建已提取为模块级 buildExportQuery（见上方拆分组件区）

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
  if (query === null) return ApiResponse.error(res, '不支持的报表类型', 400);

  // 无数据权限时直接返回空文件(只有表头)
  if (dataScope.type === 'none') {
    query._id = { $in: [] };
  }

  const config = EXPORT_MODEL_CONFIG[type];

  // 批量导出检测：导出前统计命中行数，超过阈值触发高危审计与告警（补齐导出审计盲区）
  const { checkBulkExport } = require('../services/securityAlert');
  const exportTotal = await config.model.countDocuments(query);
  await checkBulkExport(req.user.userId, req.user.username, exportTotal, `report_export_${type}`);

  // 设置响应头
  const sheetName = EXPORT_SHEET_NAMES[type] || '数据导出';

  const filename = `${sheetName}_${new Date().toISOString().slice(0, 10)}.xlsx`;
  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);

  // 创建 Excel 工作簿
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet(sheetName);

  // 设置工作表属性
  worksheet.properties.defaultColWidth = 15;

  worksheet.columns = EXPORT_COLUMN_DEFS[type];

  // 行转换 + 公式注入防护 + 流式写出（均见上方拆分组件区）
  const safeTransform = createSafeTransform(EXPORT_ROW_TRANSFORMS[type]);
  await streamExportRows(worksheet, config, query, safeTransform);

  // 设置表头样式
  worksheet.getRow(1).eachCell((cell) => {
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4472C4' } };
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.alignment = { vertical: 'middle', horizontal: 'center' };
    cell.border = { thin: true };
  });

  // 生成并发送 Excel 文件（流式写入响应，workbook.xlsx.write 会自动结束流）
  await workbook.xlsx.write(res);
});

module.exports = {
  getDashboardStats,
  getDeviceReport,
  getAlarmReport,
  getInspectionReport,
  exportReport,
  // 测试钩子（与 auditBuffer.__resetForTest 同惯例）：O-1 容量上限分支
  // 无法经 HTTP 在合理开销内填满 500 键，测试直接驱动缓存与保护函数
  __test: { dashboardCache, enforceDashboardCacheLimit, DASHBOARD_CACHE_MAX_ENTRIES },
};
