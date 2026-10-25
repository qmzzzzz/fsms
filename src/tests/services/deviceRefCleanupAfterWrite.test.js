/**
 * 设备删除与引用写入的并发窗口：写入方落库后自查并摘除悬空引用
 *
 * DeviceService.deleteDevice 在自己的事务里清理引用，但清理跑完后、本次引用
 * 落库前设备才被删除时，清理覆盖不到新写入的引用。写入方（报警上报、
 * 巡检创建/更新/完成）落库后调用这些原语摘下已不存在的设备。
 */

const mongoose = require('mongoose');

describe('写后复验：摘除已不存在设备的引用', () => {
  let FireDevice;
  let FireAlarm;
  let Inspection;
  let DeviceService;
  let AlarmService;
  let inspectionService;
  const stamp = `dr${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]).slice(0, 10);
  let device;
  let missingId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    DeviceService = require('../../services/DeviceService');
    AlarmService = require('../../services/AlarmService');
    inspectionService = require('../../services/InspectionService');
    device = await FireDevice.create({
      deviceCode: `${stamp}-01`,
      deviceName: `${stamp} 烟感`,
      deviceType: 'smoke_detector',
      installDate: new Date('2026-01-01'),
    });
    missingId = new mongoose.Types.ObjectId();
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('findMissingIds：只回报库中确实不存在的 id', async () => {
    const missing = await DeviceService.findMissingIds([device._id, missingId, device._id]);
    expect(missing).toEqual([String(missingId)]);
  });

  test('detachDevice：只摘掉匹配的那条关联，不覆盖期间改过的其它设备', async () => {
    const alarm = await FireAlarm.create({
      description: `${stamp} 报警`,
      alarmType: 'smoke',
      level: 'warning',
      deviceId: device._id,
    });

    await AlarmService.detachDevice(alarm._id, missingId);
    expect(String((await FireAlarm.findById(alarm._id)).deviceId)).toBe(String(device._id));

    await AlarmService.detachDevice(alarm._id, device._id);
    expect((await FireAlarm.findById(alarm._id)).deviceId).toBeUndefined();
  });

  test('removeMissingDeviceRefs：同时摘掉 devices 与 findings.deviceId', async () => {
    const inspection = await Inspection.create({
      title: `${stamp} 巡检`,
      inspectionType: 'daily',
      devices: [device._id, missingId],
      findings: [
        { deviceId: device._id, issue: '正常' },
        { deviceId: missingId, issue: '需要复核' },
      ],
    });

    await inspectionService.removeMissingDeviceRefs(inspection._id, [missingId]);

    const after = await Inspection.findById(inspection._id).lean();
    expect(after.devices.map(String)).toEqual([String(device._id)]);
    expect(String(after.findings[0].deviceId)).toBe(String(device._id));
    expect(after.findings[1].deviceId).toBeUndefined();
  });
});
