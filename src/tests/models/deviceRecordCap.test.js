/**
 * 设备维护/检查记录数组的尾部封顶（src/models/FireDevice.js 的 pushCapped）
 *
 * 缺陷形态：addMaintenanceRecord / addInspectionRecord 只 push + save，数组长度无上限。
 * 单条内容虽被路由限到 500 字符（deviceRoutes.js:169-180），但**条数**没人管，于是：
 *   1) 单文档迟早越过 Mongo 的 16MB 上限 ⇒ 此后该设备任何 save() 都失败
 *      —— 包括改状态、报废，设备被"历史记录"锁死；
 *   2) DeviceService.findScopeFieldsByIds 用 select('maintenanceRecord.operator')
 *      把整支数组读进**报警/巡检写路径的对象级范围闸** ⇒ 一个设备的数组长度
 *      会拖慢别人发起的请求（放大面跨用户，这是它比"详情接口太长"要紧的原因）；
 *   3) reportStatsService 的报表聚合里有 $unwind: '$maintenanceRecord'（无 $limit），
 *      代价随总条数线性增长。
 * 口径照搬本仓既有实现 Inspection.executionLog（InspectionService.js:22-40）：
 * **截断必须可数**，count > length 就是"有留痕被截断"这一事实的载体，
 * 不许拿数组长度假装"这就是全部历史"。
 *
 * 为什么断言用精确等号而不是 `<= 200`：`<=` 在"根本没封顶"的实现下会红，
 * 但在"封顶逻辑写错方向（留最旧、丢最新）"时同样会红——看起来更严；
 * 真正的区别是 `<=` 挡不住"把上限调成 5000"这类放宽。这里同时钉
 * 长度、计数、**留存的是哪一段**三格，缺一格就留有假绿空间。
 */

const mongoose = require('mongoose');

const CAP = 200; // 与 FireDevice.js 的 RECORD_TAIL_CAP 同值；对不上时下面用例会红

describe('FireDevice 追加型子文档数组：必须尾部封顶，且截断可数', () => {
  let FireDevice;
  let stamp;
  let created = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../../models/FireDevice');
    stamp = Date.now();
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceName: new RegExp(`^zzcap${stamp}`) });
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const makeDevice = async (over = {}) => {
    const doc = await FireDevice.create({
      deviceName: `zzcap${stamp}`,
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
      ...over,
    });
    created.push(doc._id);
    return doc;
  };

  test('越过上限后：长度恰好等于上限、计数记的是总次数、留下的必须是最新那一段', async () => {
    const device = await makeDevice();
    const TOTAL = CAP + 50;
    for (let i = 1; i <= TOTAL; i++) {
      await device.addMaintenanceRecord({ content: `rec-${i}`, type: 'repair' });
    }

    expect(device.maintenanceRecord).toHaveLength(CAP);
    // 计数与数组长度不是一回事：被截掉的 50 条要能在 count 里找到去处
    expect(device.maintenanceRecordCount).toBe(TOTAL);
    // 方向性：丢的是最旧的，不是最新的（维护记录丢最新 = 丢当期合规证据）
    expect(device.maintenanceRecord[0].content).toBe(`rec-${TOTAL - CAP + 1}`);
    expect(device.maintenanceRecord[CAP - 1].content).toBe(`rec-${TOTAL}`);
  });

  test('封顶是真的落库了，不是只在内存里裁了一刀', async () => {
    const device = await makeDevice();
    for (let i = 1; i <= CAP + 5; i++) {
      await device.addMaintenanceRecord({ content: `p-${i}`, type: 'repair' });
    }
    const back = await FireDevice.findById(device._id).lean();
    expect(back.maintenanceRecord).toHaveLength(CAP);
    expect(back.maintenanceRecordCount).toBe(CAP + 5);
    expect(back.maintenanceRecord[back.maintenanceRecord.length - 1].content).toBe(`p-${CAP + 5}`);
  });

  test('同一文档继续追加时计数单调累加（跨多次 save 不重置）', async () => {
    const device = await makeDevice();
    for (let i = 1; i <= 3; i++) {
      await device.addMaintenanceRecord({ content: `c-${i}`, type: 'routine' });
    }
    expect(device.maintenanceRecordCount).toBe(3);
    // routine 会顺延检查周期，这条只确认封顶改动没有连带改坏周期推进规则
    expect(device.lastCheckDate).toBeInstanceOf(Date);
    expect(device.nextCheckDate.getTime()).toBeGreaterThan(device.lastCheckDate.getTime());
    await device.addMaintenanceRecord({ content: 'c-4', type: 'repair' });
    expect(device.maintenanceRecordCount).toBe(4);
    expect(device.nextCheckDate.getTime()).toBeGreaterThan(device.lastCheckDate.getTime());
  });

  test('inspectionRecord 同一条规则（写入方法目前零调用方，封顶是为了接上时不必回来补）', async () => {
    const device = await makeDevice();
    for (let i = 1; i <= CAP + 7; i++) {
      await device.addInspectionRecord({ result: 'pass' });
    }
    expect(device.inspectionRecord).toHaveLength(CAP);
    // 这支数组没有计数：它的"被截断"事实目前无处可查，见 26.x 开放项
    expect(device.maintenanceRecordCount).toBe(0);
  });

  test('报废守卫没被这次改动挪走（封顶代码必须跑在守卫之后）', async () => {
    const device = await makeDevice({ status: 'scrapped', lifecycleStage: 'scrapped' });
    await expect(device.addMaintenanceRecord({ content: 'x', type: 'repair' })).rejects.toThrow(
      /设备已报废/
    );
    expect(device.maintenanceRecord).toHaveLength(0);
    expect(device.maintenanceRecordCount).toBe(0);
  });
});
