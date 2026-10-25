/**
 * P-3：权限撤销的跨实例窗口 —— 降级期 TTL 策略
 *
 * 背景（audit-2026-10-25 §5.7）：显式失效依赖 Redis 广播。配了 REDIS_URL
 * 但连接不可用时，其它实例收不到失效消息，只能等自然过期——原 30 秒 TTL
 * 就是「收回的权限仍被放行」的最长窗口。
 *
 * 策略：
 *  - 正常（Redis 就绪）与「完全没配 Redis」（静态单实例）：30 秒；
 *  - 「配了 REDIS_URL 但不可用」：写回 TTL 压到 2 秒；
 *  - 降级前写下的 30 秒条目按 `cachedAt + 2 秒` 复核，降级立即生效。
 *
 * 时间推进：不用 jest.useFakeTimers（与 mongodb 驱动冲突，见
 * permCacheLifecycle.test.js 的实测结论），只对 Date.now 做区间性 spy。
 */

const mongoose = require('mongoose');

describe('userPermissionService 降级期权限缓存 TTL（P-3）', () => {
  let service;
  let User;
  let sharedCache;
  let user;
  let configuredSpy;
  let enabledSpy;
  let findByIdSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    service = require('../../services/userPermissionService');
    sharedCache = require('../../services/sharedCache');
    User = require('../../models/User');
    require('../../models/Role');
    require('../../models/Permission');

    user = await User.create({
      username: 'permcache_p3',
      email: 'permcache_p3@example.com',
      password: 'Qz7#Lm42vTx9',
    });
  });

  beforeEach(() => {
    service.stopCleanup();
    service.invalidatePermissionCacheLocal();
    configuredSpy = jest.spyOn(sharedCache, 'isRedisConfigured');
    enabledSpy = jest.spyOn(sharedCache, 'isRedisEnabled');
    findByIdSpy = jest.spyOn(User, 'findById');
  });

  afterEach(() => {
    findByIdSpy.mockRestore();
    enabledSpy.mockRestore();
    configuredSpy.mockRestore();
  });

  afterAll(async () => {
    service.stopCleanup();
    await User.deleteMany({ username: 'permcache_p3' });
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 以「首次查库那一刻」为基准推进时钟，返回受控的 now 函数 */
  function advanceFrom(t0, offsetMs) {
    return jest.spyOn(Date, 'now').mockReturnValue(t0 + offsetMs);
  }

  test('Redis 就绪：仍用 30 秒 TTL，10 秒内命中、31 秒后回表', async () => {
    configuredSpy.mockReturnValue(true);
    enabledSpy.mockReturnValue(true);

    const t0 = Date.now();
    await service.getPermissions(user._id);
    expect(findByIdSpy).toHaveBeenCalledTimes(1);

    let nowSpy = advanceFrom(t0, 10 * 1000);
    try {
      await service.getPermissions(user._id);
    } finally {
      nowSpy.mockRestore();
    }
    expect(findByIdSpy).toHaveBeenCalledTimes(1); // 仍命中

    nowSpy = advanceFrom(t0, 31 * 1000);
    try {
      await service.getPermissions(user._id);
    } finally {
      nowSpy.mockRestore();
    }
    expect(findByIdSpy).toHaveBeenCalledTimes(2); // 已过期
  });

  test('配了 Redis 但不可用：TTL 收敛到 2 秒', async () => {
    configuredSpy.mockReturnValue(true);
    enabledSpy.mockReturnValue(false);

    const t0 = Date.now();
    await service.getPermissions(user._id);
    expect(findByIdSpy).toHaveBeenCalledTimes(1);

    let nowSpy = advanceFrom(t0, service.PERM_CACHE_DEGRADED_TTL_MS - 500);
    try {
      await service.getPermissions(user._id);
    } finally {
      nowSpy.mockRestore();
    }
    expect(findByIdSpy).toHaveBeenCalledTimes(1); // 2 秒内仍命中

    nowSpy = advanceFrom(t0, service.PERM_CACHE_DEGRADED_TTL_MS + 100);
    try {
      await service.getPermissions(user._id);
    } finally {
      nowSpy.mockRestore();
    }
    expect(findByIdSpy).toHaveBeenCalledTimes(2); // 超过 2 秒即回表
  });

  test('健康期写入的 30 秒条目，Redis 一断开就按 2 秒口径失效', async () => {
    configuredSpy.mockReturnValue(true);
    enabledSpy.mockReturnValue(true);

    const t0 = Date.now();
    await service.getPermissions(user._id);
    expect(findByIdSpy).toHaveBeenCalledTimes(1);

    // 同一份缓存：写入时 Redis 健康（ttlMs=30s），随后连接断开
    enabledSpy.mockReturnValue(false);
    const nowSpy = advanceFrom(t0, 3 * 1000);
    try {
      await service.getPermissions(user._id);
    } finally {
      nowSpy.mockRestore();
    }
    expect(findByIdSpy).toHaveBeenCalledTimes(2); // 不因旧 expireAt 继续放行
  });

  test('完全没配 Redis（静态单实例）：维持 30 秒，不牺牲命中率', async () => {
    configuredSpy.mockReturnValue(false);
    enabledSpy.mockReturnValue(false);

    const t0 = Date.now();
    await service.getPermissions(user._id);
    expect(findByIdSpy).toHaveBeenCalledTimes(1);

    const nowSpy = advanceFrom(t0, 10 * 1000);
    try {
      await service.getPermissions(user._id);
    } finally {
      nowSpy.mockRestore();
    }
    expect(findByIdSpy).toHaveBeenCalledTimes(1);
  });

  test('批量路径同样按降级 TTL 收敛', async () => {
    configuredSpy.mockReturnValue(true);
    enabledSpy.mockReturnValue(false);

    const findSpy = jest.spyOn(User, 'find');
    const t0 = Date.now();
    try {
      await service.getPermissionsForUsers([user._id]);
      expect(findSpy).toHaveBeenCalledTimes(1);

      const nowSpy = advanceFrom(t0, service.PERM_CACHE_DEGRADED_TTL_MS + 100);
      try {
        await service.getPermissionsForUsers([user._id]);
      } finally {
        nowSpy.mockRestore();
      }
      expect(findSpy).toHaveBeenCalledTimes(2);
    } finally {
      findSpy.mockRestore();
    }
  });
});
