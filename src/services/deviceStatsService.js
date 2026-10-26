/**
 * 设备统计聚合。写路径经 statsCache.invalidateDeviceStats 主动失效；15s TTL 只兜
 * 跨重启/广播断链的陈旧窗口，键含库名（测试按文件分配新库，进程内 Map 跨文件存活）。
 */

const FireDevice = require('../models/FireDevice');
const { deviceAlertFilters } = require('../constants/deviceAlerts');
const { listAggregateOptions } = require('../utils/queryBudget');
const { castScopeObjectIds } = require('../utils/scopeCast');
const statsCache = require('./statsCache');

const TTL_SEC = 15;
const MAX_KEY_LEN = 2048;

const cacheKeyOf = (scopeFilter) => {
  try {
    const key = `devstats:${FireDevice.db.name}:${JSON.stringify(scopeFilter)}:g${statsCache.deviceGeneration()}`;
    return key.length > MAX_KEY_LEN ? null : key;
  } catch (_) {
    return null; // 键构造失败就不缓存，绝不因缓存影响查询
  }
};

/**
 * 应用数据范围过滤（口径与列表/详情一致）：漏传即零结果，不回落全组织统计。
 * 聚合前必须归一化 ObjectId：aggregate 不做 cast，否则 total>0 而分组全空。
 */
const getDeviceStats = async (scopeFilter) => {
  if (!scopeFilter) {
    return {
      total: 0,
      byType: [],
      byStatus: [],
      needMaintenance: 0,
      needSchedule: 0,
      expiringSoon: 0,
      expired: 0,
      expiryUnknown: 0,
    };
  }
  const cacheKey = cacheKeyOf(scopeFilter);
  if (cacheKey) {
    const cached = statsCache.get(cacheKey);
    if (cached.hit) return cached.data;
  }
  const scoped = castScopeObjectIds(scopeFilter);
  // 判定时刻只取一次：跨秒抖动会让"同一响应里的两个档"用两个now
  const now = new Date();
  const alert = deviceAlertFilters(now);
  // 一次 $facet 共享同一次顶层 $match 与同一份快照：total 与各分组之和不会对不上
  const [facet] = await FireDevice.aggregate(
    [
      { $match: scoped },
      {
        $facet: {
          byType: [
            { $group: { _id: '$deviceType', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
          ],
          byStatus: [{ $group: { _id: '$status', count: { $sum: 1 } } }, { $sort: { count: -1 } }],
          needMaintenance: [{ $match: alert.needMaintenance }, { $count: 'n' }],
          // 从未录入检查日的设备没有排期，$lte 永不命中；单列一档以保持既有指标含义
          needSchedule: [{ $match: alert.needSchedule }, { $count: 'n' }],
          expiringSoon: [{ $match: alert.expiringSoon }, { $count: 'n' }],
          expired: [{ $match: alert.expired }, { $count: 'n' }],
          expiryUnknown: [{ $match: alert.expiryUnknown }, { $count: 'n' }],
          total: [{ $count: 'n' }],
        },
      },
    ],
    listAggregateOptions()
  );

  const countOf = (arm) => facet?.[arm]?.[0]?.n || 0;
  const stats = {
    total: countOf('total'),
    byType: facet?.byType || [],
    byStatus: facet?.byStatus || [],
    needMaintenance: countOf('needMaintenance'),
    needSchedule: countOf('needSchedule'),
    expiringSoon: countOf('expiringSoon'),
    expired: countOf('expired'),
    expiryUnknown: countOf('expiryUnknown'),
  };
  if (cacheKey) statsCache.set(cacheKey, stats, TTL_SEC);
  return stats;
};

module.exports = { getDeviceStats };
