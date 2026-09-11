/**
 * userPermissionService 生命周期测试（补覆盖率门槛：函数 77% / 分支 57%）
 *
 * 既有测试覆盖了读路径（getPermissions/失效），但显式生命周期三件套
 * （startCleanup / stopCleanup / handleRemoteInvalidation）零覆盖——
 * 定时器泄漏治理（O-4）把它们从「模块加载即 setInterval」改成了
 * 显式 start/stop，改动的正确性一直没有测试守护。
 *
 * 清理回调的驱动方式：不用 jest.useFakeTimers——伪造的定时器族与
 * mongodb 驱动内部计时冲突会导致 DB 操作永久挂起（实测）。改为
 * mock setInterval 捕获真实回调，再按需手动触发，时间语义完全真实。
 */

const mongoose = require('mongoose');

describe('userPermissionService 缓存生命周期', () => {
  let service;
  let User;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    service = require('../../services/userPermissionService');
    User = require('../../models/User');
    // getPermissions 的 populate('roles') → populate('permissions') 要求
    // 关联模型已注册，否则抛 MissingSchemaError
    require('../../models/Role');
    require('../../models/Permission');
  });

  beforeEach(() => {
    service.stopCleanup();
    service.invalidatePermissionCacheLocal(); // 清空模块级缓存，用例互不串扰
  });

  afterAll(async () => {
    service.stopCleanup();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('startCleanup / stopCleanup', () => {
    test('重复启动只注册一个定时器（幂等）', () => {
      const siSpy = jest.spyOn(global, 'setInterval');
      try {
        service.startCleanup();
        service.startCleanup();
        expect(siSpy).toHaveBeenCalledTimes(1);
      } finally {
        siSpy.mockRestore();
        service.stopCleanup();
      }
    });

    test('stopCleanup 清除定时器且对未启动状态幂等', () => {
      const ciSpy = jest.spyOn(global, 'clearInterval');
      try {
        service.startCleanup();
        service.stopCleanup();
        service.stopCleanup(); // 第二次无定时器可清，不应再调 clearInterval
        expect(ciSpy).toHaveBeenCalledTimes(1);
      } finally {
        ciSpy.mockRestore();
      }
    });

    test('清理回调只回收过期条目，未过期条目保留', async () => {
      // 捕获真实清理回调：mock setInterval 拦截注册，回调本体不执行，
      // 由测试在选定时机手动触发——时间流逝仍为真实语义
      let cleanupTick = null;
      const fakeHandle = { unref: jest.fn() };
      const siSpy = jest.spyOn(global, 'setInterval').mockImplementation((cb) => {
        cleanupTick = cb;
        return fakeHandle;
      });

      const missingId = new mongoose.Types.ObjectId().toString();
      let realUser;
      const findByIdSpy = jest.spyOn(User, 'findById');
      try {
        service.startCleanup();
        expect(cleanupTick).not.toBeNull();
        expect(fakeHandle.unref).toHaveBeenCalled(); // 不阻塞进程退出

        // 造数：不存在的用户 → 5 秒短 TTL 空结果条目（将过期方）；
        // 真实用户 → 30 秒 TTL 条目（保持新鲜方）
        await service.getPermissions(missingId);
        realUser = await User.create({
          username: 'permcache_survivor',
          email: 'permcache_survivor@example.com',
          password: 'Qz7#Lm42vTx9',
        });
        await service.getPermissions(realUser._id);
        expect(findByIdSpy).toHaveBeenCalledTimes(2);

        // 立即触发一次清理：两条目都未过期，均应保留（if 假分支）
        cleanupTick();
        await service.getPermissions(realUser._id);
        expect(findByIdSpy).toHaveBeenCalledTimes(2); // 仍命中缓存

        // 等短 TTL（5s）过期后再触发：过期条目被回收（if 真分支），新鲜条目保留
        await new Promise((r) => setTimeout(r, 5200));
        cleanupTick();

        await service.getPermissions(realUser._id);
        expect(findByIdSpy).toHaveBeenCalledTimes(2); // 未过期条目未被误删

        await service.getPermissions(missingId);
        expect(findByIdSpy).toHaveBeenCalledTimes(3); // 过期条目已回收，重新查库
      } finally {
        findByIdSpy.mockRestore();
        siSpy.mockRestore();
        service.stopCleanup();
        if (realUser) await User.deleteMany({ username: 'permcache_survivor' });
      }
    }, 15000);
  });

  describe('handleRemoteInvalidation（跨实例广播接收端）', () => {
    let realUser;
    let findByIdSpy;

    beforeAll(async () => {
      realUser = await User.create({
        username: 'permcache_remote',
        email: 'permcache_remote@example.com',
        password: 'Qz7#Lm42vTx9',
      });
    });

    beforeEach(() => {
      findByIdSpy = jest.spyOn(User, 'findById');
    });

    afterEach(() => {
      findByIdSpy.mockRestore();
    });

    afterAll(async () => {
      await User.deleteMany({ username: 'permcache_remote' });
    });

    test('本前缀用户级失效：仅重查该用户', async () => {
      await service.getPermissions(realUser._id);
      expect(findByIdSpy).toHaveBeenCalledTimes(1);

      service.handleRemoteInvalidation(`permcache:${realUser._id}`);

      await service.getPermissions(realUser._id);
      expect(findByIdSpy).toHaveBeenCalledTimes(2); // 缓存被失效，重新查库
    });

    test('全局失效键（*）清空整个缓存', async () => {
      await service.getPermissions(realUser._id);
      expect(findByIdSpy).toHaveBeenCalledTimes(1);

      service.handleRemoteInvalidation('permcache:*');

      await service.getPermissions(realUser._id);
      expect(findByIdSpy).toHaveBeenCalledTimes(2);
    });

    test('非字符串与外前缀键一律忽略（共享通道上其它业务的消息不处理）', async () => {
      await service.getPermissions(realUser._id);
      expect(findByIdSpy).toHaveBeenCalledTimes(1);

      service.handleRemoteInvalidation(12345);
      service.handleRemoteInvalidation(null);
      service.handleRemoteInvalidation('statscache:something');

      await service.getPermissions(realUser._id);
      expect(findByIdSpy).toHaveBeenCalledTimes(1); // 仍命中缓存，未被误失效
    });
  });
});
