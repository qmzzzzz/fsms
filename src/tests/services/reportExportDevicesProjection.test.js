/**
 * P2-06：设备导出查询必须带列投影（EXPORT_MODEL_CONFIG.devices.select）。
 *
 * 设备文档每台最多挂 200 条维保子文档，而导出行只消费 7 列——无投影会把整文档
 * （含全部维保记录）拖进进程。判据用行变换的**入参**做对拍：投影在查询期生效，
 * 到达行变换的文档不该再携带 maintenanceRecord；再用"同一查询不带投影时该字段在"
 * 做对照组，证明字段消失来自投影而非数据缺失。导出行的 7 列内容逐项钉住（不回归）。
 */
const mongoose = require('mongoose');

describe('设备导出的列投影（P2-06）', () => {
  let FireDevice;
  let fetchExportRows;
  let EXPORT_MODEL_CONFIG;
  let EXPORT_ROW_TRANSFORMS;
  let createSafeTransform;
  const stamp = `p06${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../../models/FireDevice');
    ({ fetchExportRows } = require('../../services/reportWorkbookService'));
    const svc = require('../../services/reportExportService');
    EXPORT_MODEL_CONFIG = svc.EXPORT_MODEL_CONFIG;
    EXPORT_ROW_TRANSFORMS = svc.EXPORT_ROW_TRANSFORMS;
    createSafeTransform = svc.createSafeTransform;
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('导出查询带投影：维保子文档不进行程，行内容 7 列不回归', async () => {
    const entries = Array.from({ length: 200 }, (_, i) => ({
      date: new Date(Date.now() - i * 86400000),
      type: 'routine',
      result: '正常',
      remark: `维保第 ${i} 条`,
    }));
    await FireDevice.create({
      deviceCode: `${stamp}-01`,
      deviceName: '投影验证设备',
      deviceType: 'hydrant',
      status: 'normal',
      installDate: new Date('2026-01-02T03:04:05.000Z'),
      nextCheckDate: new Date('2026-07-08T00:00:00.000Z'),
      expiryDate: new Date('2027-01-01T00:00:00.000Z'),
      location: { building: 'B1', floor: '3', room: '301' },
      maintenanceRecord: entries,
    });

    const seenDocs = [];
    const worksheet = {
      rows: [],
      addRow(row) {
        this.rows.push(row);
      },
    };
    const safeTransform = (doc) => {
      seenDocs.push(doc);
      return createSafeTransform(EXPORT_ROW_TRANSFORMS.devices)(doc);
    };
    await fetchExportRows(
      worksheet,
      EXPORT_MODEL_CONFIG.devices,
      { deviceCode: `${stamp}-01` },
      safeTransform
    );

    // 投影在查询期生效：到达行变换的文档不再携带 200 条维保子文档
    expect(seenDocs).toHaveLength(1);
    expect(seenDocs[0].maintenanceRecord).toBeUndefined();
    // 对照组：不带投影的同一文档该字段存在 ⇒ 上面的 undefined 确实来自投影
    const unprojected = await FireDevice.findOne({ deviceCode: `${stamp}-01` }).lean();
    expect(unprojected.maintenanceRecord).toHaveLength(200);

    // 行内容不回归：7 列逐项（类型/状态按 zh 展示名映射，日期按业务时区渲染；deviceCode 按模型口径大写）
    expect(worksheet.rows).toEqual([
      {
        deviceCode: `${stamp}-01`.toUpperCase(),
        deviceName: '投影验证设备',
        deviceType: '消火栓',
        status: '正常',
        location: 'B13301',
        nextCheckDate: '2026/7/8',
        expiryDate: '2027/1/1',
      },
    ]);
  });
});
