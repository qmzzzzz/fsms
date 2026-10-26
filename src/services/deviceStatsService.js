/**
 * 设备统计（自 DeviceService 拆出：体积棘轮 + 统计缓存归属）
 *
 * 缓存语义：仪表盘/设备页会反复轮询同一数据范围，聚合本身是 8 臂 $facet。
 * 写路径统一经 statsCache.invalidateDeviceStats 主动失效，15s TTL 只兜
 * 跨重启/广播断链的陈旧窗口；键含库名是因为测试按文件分配全新空库，
 * 而进程内 Map 跨文件存活。
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
 * 获取设备统计（应用数据范围过滤，口径与列表/详情一致）
 *
 * 两处收口：
 *  1. 漏传即 deny：原缺省 `scopeFilter = {}` 与 type:'all' 返回的 `{}` 无法区分，
 *     于是任何漏传都静默变成"全组织设备统计"。改为无默认值：undefined → 零结果；
 *     真正的 all 由调用方显式传 `{}`（buildDataScopeFilter 对 all 就是返回 `{}`）。
 *  2. 聚合前归一化 ObjectId：device 的 ownerField 是数组
 *     ['createdBy','maintenanceRecord.operator'] ⇒ self 范围产出
 *     `{$or:[{createdBy:'<hex 字符串>'},...]}`。countDocuments 会 cast、
 *     aggregate 不会 ⇒ total>0 而 byType/byStatus 全空。
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
  // 一次 $facet 收敛全部计数：原先 2 条聚合 + 6 条 countDocuments 并发发出，
  // 各自读取不同时刻的快照——同一响应里 total 与 byStatus 之和可能对不上。
  // $facet 内共享同一次顶层 $match 与同一份快照，口径天然一致，连接池占用也减半。
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
          // 从未录入过检查日的设备没有排期，$lte 判据永远不命中它——
          // 单列一档而不是并入 needMaintenance，是为了不改变既有指标的含义
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
