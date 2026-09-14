/**
 * 仪表盘统计服务：负责结果缓存与三条 $facet 聚合。
 * 控制器只保留参数闸与响应编排，统计逻辑与缓存口径集中在这一层。
 */

const crypto = require('crypto');
const FireDevice = require('../models/FireDevice');
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');
const { getDataScope } = require('../middleware/rbac');
const { businessDayBounds } = require('../constants/timezone');
const { scopeFilterFor } = require('./reportExportService');

const dashboardCache = new Map();
const DASHBOARD_CACHE_TTL_MS = 30 * 1000;
const DASHBOARD_CACHE_MAX_ENTRIES = 500;

// 评价报告低危项（与 P3-23 结论对齐）：模块加载即 setInterval——
// 纯 import 该模块（脚本/单测/Tree-shaking 场景）也会常驻一个定时器。
// 改为首次真正使用缓存时惰性启动，一次性句柄保证只启一个。
let dashboardCacheTimer = null;
const ensureDashboardCacheSweeper = () => {
  if (dashboardCacheTimer) return;
  dashboardCacheTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of dashboardCache.entries()) {
      if (entry.expireAt <= now) dashboardCache.delete(key);
    }
  }, 30 * 1000);
  dashboardCacheTimer.unref?.();
};

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

const facetCount = (arr) => (arr && arr[0] && typeof arr[0].n === 'number' ? arr[0].n : 0);

const MS_PER_MINUTE = 1000 * 60;

const EMPTY_DASHBOARD = {
  devices: { total: 0, online: 0, fault: 0, needMaintenance: 0, byType: [] },
  alarms: { total: 0, pending: 0, today: 0, byLevel: [], avgResponse: 0 },
  inspections: { total: 0, pending: 0, overdue: 0, today: 0, completionRate: 0 },
};

const collectDashboardFacets = async (filters, now, startOfDay, endOfDay) => {
  const [deviceFacet] = await FireDevice.aggregate([
    { $match: filters.device },
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
    { $match: filters.alarm },
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
    { $match: filters.inspection },
    {
      $facet: {
        total: [{ $count: 'n' }],
        pending: [{ $match: { status: 'pending' } }, { $count: 'n' }],
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

  return { deviceFacet, alarmFacet, inspectionFacet };
};

const buildDashboardData = (deviceFacet, alarmFacet, inspectionFacet) => ({
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
});

const getDashboardData = async (userId) => {
  const dataScope = await getDataScope(userId);
  const now = new Date();
  const businessBounds = businessDayBounds();
  const filters = {
    device: scopeFilterFor('device', dataScope),
    alarm: scopeFilterFor('alarm', dataScope),
    inspection: scopeFilterFor('inspection', dataScope),
  };

  if (dataScope.type === 'none') {
    return { data: EMPTY_DASHBOARD, message: '获取仪表盘统计成功' };
  }

  const cacheKey = getDashboardCacheKey(userId, filters);
  const cached = dashboardCache.get(cacheKey);
  if (cached && cached.expireAt > Date.now()) {
    return { data: cached.data, message: '获取仪表盘统计成功（缓存命中）' };
  }

  const { deviceFacet, alarmFacet, inspectionFacet } = await collectDashboardFacets(
    filters,
    now,
    businessBounds.start,
    businessBounds.end
  );
  const data = buildDashboardData(deviceFacet, alarmFacet, inspectionFacet);

  enforceDashboardCacheLimit();
  ensureDashboardCacheSweeper();
  dashboardCache.set(cacheKey, { data, expireAt: Date.now() + DASHBOARD_CACHE_TTL_MS });
  return { data, message: '获取仪表盘统计成功' };
};

module.exports = {
  getDashboardData,
  __test: {
    dashboardCache,
    enforceDashboardCacheLimit,
    ensureDashboardCacheSweeper,
    DASHBOARD_CACHE_MAX_ENTRIES,
  },
};
