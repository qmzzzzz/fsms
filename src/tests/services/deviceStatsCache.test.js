/**
 * 设备统计 TTL 缓存的命中与失效（P2-6）
 *
 * 判据不是「缓存模块自己说命中」，而是**聚合实际少打了一次库**：
 * 用 FireDevice.aggregate 的调用次数作为可证伪信号。写路径失效同样按这个口径
 * 断言——只要设备写操作后仍能读到旧聚合，下一次统计就会少打一次库而变红。
 */

const mongoose = require('mongoose');

const FireDevice = require('../../models/FireDevice');
const DeviceService = require('../../services/DeviceService');
const statsCache = require('../../services/statsCache');

const stamp = `zzdsc${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 12);

const seedDevice = (suffix) => ({
  deviceCode: `${stamp}-${suffix}`,
  deviceName: `${stamp}-${suffix}`,
  deviceType: 'extinguisher',
  installDate: new Date('2026-01-01'),
});

describe('DeviceService.getDeviceStats 缓存', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp}`) });
    await FireDevice.create([seedDevice('A'), seedDevice('B')]);
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp}`) }).catch(() => {});
    statsCache.invalidateDeviceStats('test-teardown');
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  beforeEach(() => {
    // 用例顺序随机：每个用例都从"无缓存"起步，避免上一条的命中被算进本条的次数
    statsCache.invalidateDeviceStats('test-setup');
  });

  test('同一数据范围重复查询只打一次聚合，且返回值一致', async () => {
    const spy = jest.spyOn(FireDevice, 'aggregate');
    try {
      const first = await DeviceService.getDeviceStats({});
      const aggregateCalls = spy.mock.calls.length;
      expect(aggregateCalls).toBe(1);

      const second = await DeviceService.getDeviceStats({});
      expect(spy.mock.calls.length).toBe(aggregateCalls); // 命中缓存，不再打库
      expect(second).toEqual(first);
    } finally {
      spy.mockRestore();
    }
  });

  test('不同数据范围各自成键，不互相串味', async () => {
    const spy = jest.spyOn(FireDevice, 'aggregate');
    try {
      const all = await DeviceService.getDeviceStats({});
      const building = await DeviceService.getDeviceStats({ 'location.building': '不存在的楼栋' });
      expect(spy.mock.calls.length).toBe(2);
      expect(building.total).toBe(0);
      expect(all.total).toBeGreaterThanOrEqual(2);
    } finally {
      spy.mockRestore();
    }
  });

  test('invalidateDeviceStats 后必须重查（失效有牙齿）', async () => {
    await DeviceService.getDeviceStats({});
    const spy = jest.spyOn(FireDevice, 'aggregate');
    try {
      statsCache.invalidateDeviceStats('test-manual');
      await DeviceService.getDeviceStats({});
      expect(spy.mock.calls.length).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });

  test('设备创建走写路径失效：新建后统计立刻包含新设备', async () => {
    const before = await DeviceService.getDeviceStats({});
    const spy = jest.spyOn(FireDevice, 'aggregate');
    try {
      await DeviceService.createDevice(seedDevice('NEW'), new mongoose.Types.ObjectId());
      const after = await DeviceService.getDeviceStats({});
      expect(spy.mock.calls.length).toBe(1); // 失效后重查
      expect(after.total).toBe(before.total + 1);
    } finally {
      spy.mockRestore();
    }
  });

  test('设备删除走写路径失效：删除后统计立刻减少', async () => {
    // 自建自删：不依赖上一条用例留下的夹具，随机顺序下也可单独成立
    const extra = await DeviceService.createDevice(
      seedDevice('DEL'),
      new mongoose.Types.ObjectId()
    );
    const before = await DeviceService.getDeviceStats({});
    const spy = jest.spyOn(FireDevice, 'aggregate');
    try {
      await DeviceService.deleteDevice(extra);
      const after = await DeviceService.getDeviceStats({});
      expect(spy.mock.calls.length).toBe(1);
      expect(after.total).toBe(before.total - 1);
    } finally {
      spy.mockRestore();
    }
  });

  test('漏传范围仍是零结果且不走缓存（deny 路径优先于缓存）', async () => {
    const spy = jest.spyOn(FireDevice, 'aggregate');
    try {
      expect(await DeviceService.getDeviceStats()).toEqual({
        total: 0,
        byType: [],
        byStatus: [],
        needMaintenance: 0,
        needSchedule: 0,
        expiringSoon: 0,
        expired: 0,
        expiryUnknown: 0,
      });
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});
