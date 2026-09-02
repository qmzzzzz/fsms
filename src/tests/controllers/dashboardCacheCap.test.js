/**
 * 仪表盘缓存容量上限测试（报告 O-1）
 *
 * dashboardCache 原为 Map + 30s TTL 无条目上限，键含 userId+过滤指纹，
 * 高基数组合下无界增长。现与 userCache/statsCache 口径对齐：
 * 写入前先清过期项、仍超限淘汰最旧条目（Map 插入序即时间序）。
 */

const reportController = require('../../controllers/reportController');

describe('dashboardCache 容量上限（O-1）', () => {
  const { dashboardCache, enforceDashboardCacheLimit, DASHBOARD_CACHE_MAX_ENTRIES } =
    reportController.__test;

  afterEach(() => {
    dashboardCache.clear();
  });

  test('导出测试钩子可用且上限为正数', () => {
    expect(dashboardCache).toBeInstanceOf(Map);
    expect(typeof enforceDashboardCacheLimit).toBe('function');
    expect(DASHBOARD_CACHE_MAX_ENTRIES).toBeGreaterThan(0);
  });

  test('未超限时清理不误删有效条目', () => {
    dashboardCache.set('k1', { data: { a: 1 }, expireAt: Date.now() + 10_000 });
    enforceDashboardCacheLimit();
    expect(dashboardCache.has('k1')).toBe(true);
  });

  test('超限时先清过期项：过期条目被回收，有效条目保留', () => {
    const max = DASHBOARD_CACHE_MAX_ENTRIES;
    for (let i = 0; i < max; i++) {
      dashboardCache.set(`fresh-${i}`, { data: {}, expireAt: Date.now() + 10_000 });
    }
    // 插入一条已过期条目占位
    dashboardCache.set('expired', { data: {}, expireAt: Date.now() - 1 });
    // 现有写入路径：先执行容量保护再 set 新键
    enforceDashboardCacheLimit();
    dashboardCache.set('incoming', { data: {}, expireAt: Date.now() + 10_000 });

    expect(dashboardCache.has('expired')).toBe(false);
    expect(dashboardCache.has('incoming')).toBe(true);
    expect(dashboardCache.size).toBeLessThanOrEqual(max);
  });

  test('全部未过期仍超限时淘汰最旧条目，总量收敛到上限内', () => {
    const max = DASHBOARD_CACHE_MAX_ENTRIES;
    for (let i = 0; i < max; i++) {
      dashboardCache.set(`all-fresh-${i}`, { data: {}, expireAt: Date.now() + 10_000 });
    }
    enforceDashboardCacheLimit();
    dashboardCache.set('newest', { data: {}, expireAt: Date.now() + 10_000 });

    expect(dashboardCache.size).toBeLessThanOrEqual(max);
    // 最旧的键（Map 插入序头部）被淘汰，最新键保留
    expect(dashboardCache.has('all-fresh-0')).toBe(false);
    expect(dashboardCache.has('newest')).toBe(true);
  });
});
