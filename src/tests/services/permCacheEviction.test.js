/**
 * P3：userPermissionService 的两条容量/成本治理。
 *
 * 1. 容量超限从"整体 clear()"改为"淘汰最旧的一半"：≥2000 人的角色做一次权限热同步
 *    （A-5 批量路径）不再把全量缓存拍空引发集中查库；未淘汰条目继续命中，正确性仍由 DB 兜底。
 * 2. basePermPrime 一次性预取：审批人资格判定（privilegeGrantService）先 prime 再逐码判定，
 *    最多 MAX_GRANT_CODES 次串行查库收敛为 1 次；条目读即删、每次 prime 整表替换，不留陈旧态。
 */
const mongoose = require('mongoose');

describe('userPermissionService 容量淘汰与一次性预取（P3）', () => {
  let service;
  let User;
  let permCache;
  let PERM_CACHE_MAX_SIZE;
  let evictOldestHalf;
  const created = { users: [] };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    service = require('../../services/userPermissionService');
    User = require('../../models/User');
    require('../../models/Role');
    require('../../models/Permission');
    require('../../models/PrivilegeGrant');
    ({ permCache, PERM_CACHE_MAX_SIZE, evictOldestHalf } = service.__test);
  });

  beforeEach(() => {
    service.stopCleanup();
    service.invalidatePermissionCacheLocal();
  });

  afterAll(async () => {
    service.stopCleanup();
    await User.deleteMany({ _id: { $in: created.users } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const fill = (n, prefix) => {
    const now = Date.now();
    for (let i = 0; i < n; i += 1) {
      permCache.set(`${prefix}${i}`, {
        perms: [],
        cachedAt: now,
        ttlMs: 30000,
        expireAt: now + 30000,
      });
    }
  };

  const mkUser = async (tag) => {
    const u = await User.create({
      username: `p3evict_${tag}`,
      email: `p3evict_${tag}@example.com`,
      password: 'Qz7#Lm42vTx9',
    });
    created.users.push(u._id);
    return u;
  };

  test('evictOldestHalf：按插入序淘汰最旧的一半（奇数向下取整）', () => {
    fill(5, 'unit-');
    evictOldestHalf();
    expect(permCache.size).toBe(3);
    expect(permCache.has('unit-0')).toBe(false);
    expect(permCache.has('unit-1')).toBe(false);
    expect(permCache.has('unit-2')).toBe(true);
    expect(permCache.has('unit-4')).toBe(true);
  });

  test('getPermissions 容量超限：淘汰一半而非整体清空，未淘汰条目继续命中', async () => {
    fill(PERM_CACHE_MAX_SIZE, 'full-');
    const user = await mkUser('main');
    const perms = await service.getPermissions(String(user._id));
    expect(perms).toEqual([]);
    expect(permCache.size).toBeLessThanOrEqual(PERM_CACHE_MAX_SIZE);
    expect(permCache.has('full-0')).toBe(false); // 最旧的被淘汰
    expect(permCache.has(`full-${PERM_CACHE_MAX_SIZE - 1}`)).toBe(true); // 较新的保留
    expect(permCache.has(String(user._id))).toBe(true); // 本次结果已写入

    // 未被淘汰的旧条目继续命中：不再触发查库
    const findByIdSpy = jest.spyOn(User, 'findById');
    const again = await service.getPermissions(`full-${PERM_CACHE_MAX_SIZE - 1}`);
    expect(findByIdSpy).not.toHaveBeenCalled();
    expect(again).toEqual([]);
    findByIdSpy.mockRestore();
  });

  test('user 不存在的穿透路径同样走部分回收（不再整体 clear）', async () => {
    fill(PERM_CACHE_MAX_SIZE, 'miss-');
    const missing = new mongoose.Types.ObjectId().toString();
    await expect(service.getPermissions(missing)).resolves.toEqual([]);
    expect(permCache.size).toBeLessThan(PERM_CACHE_MAX_SIZE);
    expect(permCache.has('miss-0')).toBe(false);
    expect(permCache.has(missing)).toBe(true); // 短 TTL 空结果条目已写入
  });

  test('批量写回（getPermissionsForUsers）超限只淘汰一半，整批结果照常返回', async () => {
    fill(PERM_CACHE_MAX_SIZE - 2, 'batch-');
    const ids = [await mkUser('b1'), await mkUser('b2'), await mkUser('b3')].map((u) =>
      String(u._id)
    );
    const result = await service.getPermissionsForUsers(ids);
    expect([...result.keys()].sort()).toEqual(ids.sort());
    expect([...result.values()].every((perms) => Array.isArray(perms))).toBe(true);
    expect(permCache.has('batch-0')).toBe(false); // 淘汰了最旧的一半
    expect(permCache.has('batch-1997')).toBe(true);
  });

  test('primeBasePermissions：空入参直接重置预取表（不查库）', async () => {
    const findSpy = jest.spyOn(User, 'find');
    try {
      await service.primeBasePermissions([]);
      expect(findSpy).not.toHaveBeenCalled();
      await service.primeBasePermissions(undefined);
      expect(findSpy).not.toHaveBeenCalled();
    } finally {
      findSpy.mockRestore();
    }
  });

  test('primeBasePermissions：一次取回后逐条消费一次，未命中 prime 才回落查库', async () => {
    const user = await mkUser('prime');
    const key = String(user._id);
    await service.primeBasePermissions([key, new mongoose.Types.ObjectId().toString()]);
    const findSpy = jest.spyOn(User, 'findById');
    try {
      // prime 已含该用户：逐码判定（hasPermission includeGrants:false）不再触发 findById
      await expect(
        service.hasPermission(key, 'device:read', { includeGrants: false })
      ).resolves.toBe(false);
      expect(findSpy).not.toHaveBeenCalled();
      // prime 条目读即删：第二次判定回落到查库
      await expect(
        service.hasPermission(key, 'device:read', { includeGrants: false })
      ).resolves.toBe(false);
      expect(findSpy).toHaveBeenCalledTimes(1);
    } finally {
      findSpy.mockRestore();
    }
  });
});
