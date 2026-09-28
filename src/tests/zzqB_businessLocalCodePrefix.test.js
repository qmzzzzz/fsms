/**
 * 自动编号里嵌的日期/年份必须按**业务时区**取，不能用服务器本地 getter
 *
 * 现场形态（两处）：
 *   models/FireAlarm.js  generatePrefix → `ALM${getFullYear()}${月}${日}`
 *   models/FireDevice.js generatePrefix → `${类型前缀}-${getFullYear()}`
 * 两者都读 `new Date()` 的**服务器本地**分量，而全站"今天/本月"口径的唯一来源是
 * `constants/timezone.businessDateParts`（默认 Asia/Shanghai，可由 TZ_BUSINESS 覆盖）。
 *
 * 为什么这不是"少一个小时"的展示瑕疵：`deviceCode` 是设备台账列表的一等列
 * （web-admin/src/views/DeviceView.vue 直接渲染），运维拿编号报修、拿日期段核对台账。
 * UTC 容器 + 东八区业务口径下，业务时区每天 00:00–08:00（即一天三分之一）产生的
 * 记录，编号里刻的是**昨天**；跨年时（业务 1 月 1 日凌晨）刻的是**去年**。
 * 同一条记录的 occurredAt 在界面上显示 25 日、编号写 24 日，两处互相"证明"对方没问题。
 *
 * 判据设计（四条各自挡一类错）：
 *   1) 分歧时刻必须换成分量 —— 挡"仍读服务器本地"；
 *   2) 同一时刻在不同服务器时区下结果必须相同 —— 挡"改成本机时区兜一圈"，
 *      也挡任何把业务时区理解成"服务器所在时区"的实现；
 *   3) 换 TZ_BUSINESS（配置项，validate.js 明确允许任意 IANA 名）后必须跟着换 ——
 *      挡"写死 +8 秒偏移"这种看着对其实把配置项变成装饰的实现；
 *   4) 插件必须把取号时刻作为第二个实参交给回调 —— 挡"回调里自己再 new Date()"：
 *      前三条都能拿显式 `at` 打绿，唯独这一条只能从插件那一侧证。
 * 另配同日控制臂：口径一致的时刻两侧本来就该相等，防止"永远挪一天"的实现蒙混过关。
 *
 * 两个时区轴必须分别注入，否则判据 1/2 是空转（本用例的第一版就踩了这一点）：
 *   - 业务时区是**模块加载期**读进常量的（`BUSINESS_TIMEZONE`），只能靠重载模块切换；
 *   - 服务器本地时区是**调用期**读的（`getFullYear()` 当场查 `process.env.TZ`），
 *     只在 require 时设过再还原等于什么都没设——断言必须整段包在调用期的 TZ 窗口里。
 *   实测：`2026-09-24T17:30Z` 的 `getFullYear()/getMonth()/getDate()` 在
 *   TZ=UTC 下是 2026-9-24，在 TZ=Asia/Shanghai 下是 2026-9-25。
 */

const mongoose = require('mongoose');
const autoIncrement = require('../plugins/autoIncrement');

const SERVER_UTC = 'UTC';
// 业务 09-25 01:30（东八区），UTC 容器本地还是 09-24
const DIVERGE_INSTANT = new Date('2026-09-24T17:30:00Z');
// 业务 09-25 15:30，两边同为 09-25
const AGREE_INSTANT = new Date('2026-09-25T07:30:00Z');
// 业务 2026-01-01 00:30（东八区）/ 2025-12-31 08:30（LA），年份各错一格
const YEAR_DIVERGE_INSTANT = new Date('2025-12-31T16:30:00Z');

/** 业务时区是模块级常量：换配置要重载模块 */
const loadModels = (businessTz) => {
  const savedBusiness = process.env.TZ_BUSINESS;
  jest.resetModules();
  if (businessTz === undefined) delete process.env.TZ_BUSINESS;
  else process.env.TZ_BUSINESS = businessTz;
  let loaded;
  jest.isolateModules(() => {
    loaded = {
      FireAlarm: require('../models/FireAlarm'),
      FireDevice: require('../models/FireDevice'),
      businessDateParts: require('../constants/timezone').businessDateParts,
    };
  });
  if (savedBusiness === undefined) delete process.env.TZ_BUSINESS;
  else process.env.TZ_BUSINESS = savedBusiness;
  return loaded;
};

/** 服务器本地时区在调用期生效：断言整段包进来，否则等于没换 */
const withServerTz = (tz, runAssertions) => {
  const saved = process.env.TZ;
  process.env.TZ = tz;
  try {
    return runAssertions();
  } finally {
    if (saved === undefined) delete process.env.TZ;
    else process.env.TZ = saved;
  }
};

describe('编号日期段跟随业务时区，不跟随服务器本地时区', () => {
  it('分歧时刻：业务已是次日，编号刻业务那天（不是服务器本地的昨天）', () => {
    const { FireAlarm } = loadModels('Asia/Shanghai');
    withServerTz(SERVER_UTC, () => {
      expect(FireAlarm.buildCodePrefix(DIVERGE_INSTANT)).toBe('ALM20260925');
    });
  });

  it('控制臂：口径一致的时刻两侧本来就该相等（防"永远挪一天"）', () => {
    const { FireAlarm } = loadModels('Asia/Shanghai');
    withServerTz(SERVER_UTC, () => {
      expect(FireAlarm.buildCodePrefix(AGREE_INSTANT)).toBe('ALM20260925');
    });
  });

  it('与全站"今天"同源：编号日期段 == businessDateParts().dateStr 去连字符', () => {
    const { FireAlarm, businessDateParts } = loadModels('Asia/Shanghai');
    withServerTz(SERVER_UTC, () => {
      for (const at of [DIVERGE_INSTANT, AGREE_INSTANT, YEAR_DIVERGE_INSTANT]) {
        expect(FireAlarm.buildCodePrefix(at)).toBe(
          `ALM${businessDateParts(at).dateStr.replace(/-/g, '')}`
        );
      }
    });
  });

  it('跨年格：业务已进入新年，年份取业务年（设备编号与报警编号同一条判据）', () => {
    const { FireAlarm, FireDevice } = loadModels('Asia/Shanghai');
    withServerTz(SERVER_UTC, () => {
      expect(FireAlarm.buildCodePrefix(YEAR_DIVERGE_INSTANT)).toBe('ALM20260101');
      // 未知类型落到 OT 前缀：断言的是年份那一格，不依赖类型映射表
      expect(FireDevice.buildCodePrefix({ deviceType: 'not-a-type' }, YEAR_DIVERGE_INSTANT)).toBe(
        'OT-2026'
      );
    });
  });

  it('服务器时区无关：同一时刻在 UTC+14 / UTC-11 / UTC / 本机下都是同一个号', () => {
    const { FireAlarm, FireDevice } = loadModels('Asia/Shanghai');
    for (const serverTz of [
      'Pacific/Kiritimati',
      'Pacific/Midway',
      SERVER_UTC,
      'America/Los_Angeles',
    ]) {
      withServerTz(serverTz, () => {
        expect(FireAlarm.buildCodePrefix(DIVERGE_INSTANT)).toBe('ALM20260925');
        expect(FireDevice.buildCodePrefix({ deviceType: 'not-a-type' }, YEAR_DIVERGE_INSTANT)).toBe(
          'OT-2026'
        );
      });
    }
  });

  it('业务时区是配置项不是装饰：换成 LA 后两个编号都跟着按 LA 的日历日走', () => {
    // LA(UTC-7, 夏令时)：DIVERGE 是 09-24 10:30，YEAR_DIVERGE 还是 2025-12-31
    // ——写死 +8 偏移的实现在这两格分别给出 ALM20260925 / ALM20260101 / OT-2026，全部判红
    const { FireAlarm, FireDevice } = loadModels('America/Los_Angeles');
    withServerTz(SERVER_UTC, () => {
      expect(FireAlarm.buildCodePrefix(DIVERGE_INSTANT)).toBe('ALM20260924');
      expect(FireAlarm.buildCodePrefix(YEAR_DIVERGE_INSTANT)).toBe('ALM20251231');
      expect(FireDevice.buildCodePrefix({ deviceType: 'not-a-type' }, YEAR_DIVERGE_INSTANT)).toBe(
        'OT-2025'
      );
    });
  });

  it('形状不变式：报警编号恒为 ALM+8 位数字，设备编号恒为 前缀-4 位年份', () => {
    const { FireAlarm, FireDevice } = loadModels('Asia/Shanghai');
    withServerTz(SERVER_UTC, () => {
      expect(FireAlarm.buildCodePrefix(AGREE_INSTANT)).toMatch(/^ALM\d{8}$/);
      expect(FireDevice.buildCodePrefix({ deviceType: 'not-a-type' }, AGREE_INSTANT)).toMatch(
        /^[A-Z]{2,4}-\d{4}$/
      );
    });
  });
});

describe('插件把取号时刻交给回调，而不是让回调自己读钟', () => {
  it('generatePrefix 收到的第二个实参是一个真实时刻（Date 实例）', async () => {
    let seen;
    const originalDb = mongoose.connection.db;
    mongoose.connection.db = {
      collection: () => ({ findOneAndUpdate: async () => ({ seq: 7 }) }),
    };
    try {
      const schema = new mongoose.Schema({ probeCode: String });
      let counterSlot = 0;
      schema.plugin(autoIncrement, {
        field: 'probeCode',
        counterPrefix: 'zzbprobe',
        generatePrefix: (doc, at) => {
          seen = at;
          counterSlot += 1;
          return `PFX${counterSlot}`;
        },
      });
      const Model = mongoose.model('ZzbProbeArgShape', schema);
      const doc = new Model({});
      await doc.validate();
      // 编号确有生成 ⇒ 钩子确实跑过，排除"seen 为 undefined 只是因为没进插件"
      expect(doc.probeCode).toMatch(/^PFX\d+-0007$/);
      expect(seen).toBeInstanceOf(Date);
      expect(Number.isNaN(seen.getTime())).toBe(false);
    } finally {
      mongoose.connection.db = originalDb;
    }
  });
});
