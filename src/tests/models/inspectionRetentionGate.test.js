/**
 * 巡检保留期计龄闸（models/Inspection.js 的 pre('validate')）
 *
 * 缺陷形态（审计 2026-11-14 P3）：TTL 索引 ttl_planStartTime 挂在 planStartTime 上，而该字段
 * 在 schema 里无 required 无 default ⇒ 缺键/null 的文档**永远不会被 TTL 回收**（MongoDB 的 TTL
 * 不匹配缺键），保留期声明（BUSINESS_RETENTION_DAYS_INSPECTION，compose 默认 :-180）对它们失效。
 *
 * 修法口径（为什么不是三个更"直接"的方案，写下来防止后人再走一遍）：
 *  · schema `required: true`——会把"planStartTime 可为缺键/null"这一**已被测试钉住的契约**打碎
 *    （tests/services/inspectionCursorNullableSortKey.test.js 用缺键/null 夹具钉住列表游标的空值块
 *    行为），存量无键行也会从此不可编辑；
 *  · TTL 改挂 createdAt——违背 constants/businessRetention.js 的业务口径（巡检按事件时间计龄），
 *    且该口径经 businessRetentionVerdict.test.js 的 ttl_planStartTime 行钉住；
 *  · 派生 expiryAt 落库——保留天数是 env 可调的，存进行的截止时刻在改档后全部失真。
 *  所以闸收在"开关在场 ⇒ 不许制造无键行"：新文档缺键、既有值被改空都拒绝；
 *  存量无键行不被误伤（save 其它字段照常）；开关未配置时不设闸（无 TTL 就没有"过期不了"）。
 */

const mongoose = require('mongoose');

const ENV_KEY = 'BUSINESS_RETENTION_DAYS_INSPECTION';

describe('Inspection 保留期计龄闸：开关在场 ⇒ 巡检必须带事件时间', () => {
  let Inspection;
  let stamp;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Inspection = require('../../models/Inspection');
    stamp = Date.now();
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(`^zzretg${stamp}`) });
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  afterEach(() => {
    delete process.env[ENV_KEY];
  });

  const base = (over = {}) => ({
    inspectionType: 'daily',
    title: `zzretg${stamp}`,
    ...over,
  });

  test('开关在场：新文档缺 planStartTime 被拒，带值放行', async () => {
    process.env[ENV_KEY] = '180';
    await expect(Inspection.create(base())).rejects.toThrow(/计划开始时间/);
    const ok = await Inspection.create(base({ planStartTime: new Date('2026-01-01T00:00:00Z') }));
    expect(ok.planStartTime).toBeTruthy();
    await Inspection.deleteOne({ _id: ok._id });
  });

  test('开关未配置：缺键仍可写（无 TTL 即无"过期不了"问题；游标空值块契约不受影响）', async () => {
    const doc = await Inspection.create(base());
    expect(doc.planStartTime).toBeUndefined();
    await Inspection.deleteOne({ _id: doc._id });
  });

  test('存量无键行不被误伤：改其它字段照常保存；把既有值改成空才被拒', async () => {
    const legacy = await Inspection.create(base());
    process.env[ENV_KEY] = '180';
    legacy.remark = `zzretg${stamp}-touched`;
    await expect(legacy.save()).resolves.toBeTruthy(); // planStartTime 未动 ⇒ isModified false ⇒ 放行
    legacy.planStartTime = null;
    await expect(legacy.save()).rejects.toThrow(/计划开始时间/);
    await Inspection.deleteOne({ _id: legacy._id });
  });
});
