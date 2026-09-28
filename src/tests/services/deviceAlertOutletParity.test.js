/**
 * 设备提醒档：五个出口必须给同一台设备同一个结论
 *
 * 修前的事实（逐条在本文件里被断言钉住）：
 *  - `DeviceService.getDeviceStats` 与 `reportDashboardService` 的"待维护"只排除 maintenance，
 *    而 `deviceReminder` 排除 [maintenance, scrapped] ⇒ 同一台报废设备在仪表盘计数、
 *    在提醒清单里不出现，两个出口互相矛盾；
 *  - `reportStatsService.getDeviceReportData` 的"即将到期"**完全没有状态排除** ⇒
 *    已报废设备连同位置出现在设备报表里；且它的窗口是定长毫秒 `30*86400*1000`，
 *    与其余实现的 `setDate(+30)` 是两套算法；
 *  - 四处（现为五处）都用 `$lte/$gte` 范围比较判"待维护"，而一台从未录入过检查日的设备
 *    `nextCheckDate` 恒为 null（模型排期钩子只在 lastCheckDate 存在时计算，
 *    且 lastCheckDate 不在新建白名单里）⇒ Mongo 的范围比较不匹配缺失字段 ⇒
 *    "没有排期"被读成"不需要排期"，这台设备在所有出口永久隐身。
 *
 * 因此本文件的判据是**跨出口一致性**，不是"某处非空"：
 * 每台设备给出期望归属档的显式表，再由三个可达出口各测一遍，任何一处漂移都会红。
 *
 * 另一处零覆盖（本轮补上）：`deviceAlertFilters` 返回**五**档，而本文件此前只对四档
 * 立了判据——`expiryUnknown`（有效期未登记）在四个消费方里只被 `DeviceService.getDeviceStats`
 * 计数消费（`deviceReminder` 的返回体根本没有这一档），
 * 没有任何一条用例断言过它的成员。把它改成 `$exists: false`（漏掉显式 null 的那种形态）、
 * 或删掉它的 status 排除（把已报废设备报成"合规上必须可见"）、或整个清空，全套用例照绿。
 */

const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

const FireDevice = require('../../models/FireDevice');
const DeviceService = require('../../services/DeviceService');
const deviceReminder = require('../../services/deviceReminder');
const { deviceAlertFilters, addCalendarDays } = require('../../constants/deviceAlerts');

const DAY = 24 * 60 * 60 * 1000;
const TAG = 'ZZALERT'; // 模型会把 deviceCode 归一成大写，期望表按归一后形态写

/** 每台设备的期望归属：null 表示"任何一档都不该出现" */
const CASES = [
  {
    code: `${TAG}-OVERDUE-CHECK`,
    setup: { status: 'normal', nextCheckDate: new Date(Date.now() - DAY) },
    expect: { needMaintenance: true },
  },
  {
    code: `${TAG}-SCRAPPED-OVERDUE`,
    setup: {
      status: 'scrapped',
      lifecycleStage: 'scrapped',
      nextCheckDate: new Date(Date.now() - DAY),
      expiryDate: new Date(Date.now() + 5 * DAY),
    },
    // 报废即生命周期终点：四档全不该出现（这正是修前仪表盘会多算的那台）
    expect: {},
  },
  {
    code: `${TAG}-IN-MAINTENANCE`,
    setup: { status: 'maintenance', nextCheckDate: new Date(Date.now() - DAY) },
    expect: {},
  },
  {
    code: `${TAG}-UNSCHEDULED`,
    setup: { status: 'normal', installDate: new Date(Date.now() - 400 * DAY), checkCycle: 30 },
    expect: { needSchedule: true },
  },
  {
    code: `${TAG}-EXPIRING-5D`,
    setup: {
      status: 'normal',
      nextCheckDate: new Date(Date.now() + 100 * DAY),
      expiryDate: new Date(Date.now() + 5 * DAY),
    },
    expect: { expiringSoon: true },
  },
  {
    code: `${TAG}-EDGE-DAY30`,
    setup: {
      status: 'normal',
      nextCheckDate: new Date(Date.now() + 100 * DAY),
      // 窗口右界那一刻：三档判据必须给出同一个"在窗口内"
      expiryDate: addCalendarDays(new Date(), 30),
    },
    expect: { expiringSoon: true },
  },
  {
    code: `${TAG}-EXPIRED`,
    setup: {
      status: 'normal',
      nextCheckDate: new Date(Date.now() + 100 * DAY),
      expiryDate: new Date(Date.now() - 5 * DAY),
    },
    expect: { expired: true },
  },
  // ↓ 三条只为 expiryUnknown 档而存在（F-168）。前两条是同一件事的两种库内形态，
  //   必须**都**算"有效期未登记"——只写其中一条，另一条就是测不到的死角。
  {
    code: `${TAG}-NO-EXPIRY`,
    setup: { status: 'normal', nextCheckDate: new Date(Date.now() + 100 * DAY) },
    expect: {}, // 字段整个不存在
  },
  {
    code: `${TAG}-NULL-EXPIRY`,
    setup: {
      status: 'normal',
      nextCheckDate: new Date(Date.now() + 100 * DAY),
      expiryDate: null,
    },
    expect: {}, // 字段存在但值为 null（`$exists: false` 会漏掉这一台）
  },
  {
    code: `${TAG}-SCRAPPED-NO-EXPIRY`,
    setup: {
      status: 'scrapped',
      lifecycleStage: 'scrapped',
      nextCheckDate: new Date(Date.now() + 100 * DAY),
    },
    expect: {}, // 报废且无有效期：四档不含，expiryUnknown 也不含
  },
];

const bucketsOf = (expectation) => Object.keys(expectation).filter((k) => expectation[k]);

/**
 * expiryUnknown 的成员表**单独一张**，不塞进上面的 `expect`。
 *
 * 因为这一档与四档不互斥：一台"没登记有效期且已过检查期"的设备同时在
 * expiryUnknown 与 needMaintenance 里，`constants/deviceAlerts.js:23-24` 的
 * "档与档互斥 ⇒ 各档之和可与 total 对齐"只对到期/排期那几档成立。
 * 若把它并进 expect，"每台至多属一档"的前提自证会被我自己的数据打红，
 * 而正确的做法（承认重叠）反而看不见。
 */
const EXPIRY_UNKNOWN_MEMBERS = [
  `${TAG}-OVERDUE-CHECK`,
  `${TAG}-IN-MAINTENANCE`,
  `${TAG}-UNSCHEDULED`,
  `${TAG}-NO-EXPIRY`,
  `${TAG}-NULL-EXPIRY`,
];

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  await FireDevice.deleteMany({ deviceCode: new RegExp(`^${TAG}`) });
  for (const c of CASES) {
    await FireDevice.create({
      deviceCode: c.code,
      deviceName: c.code,
      deviceType: 'extinguisher',
      // installDate 是模型必填项；只有 -UNSCHEDULED 那条刻意给 400 天前
      installDate: new Date(Date.now() - 100 * DAY),
      ...c.setup,
    });
  }
});

afterAll(async () => {
  await FireDevice.deleteMany({ deviceCode: new RegExp(`^${TAG}`) });
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});

/** 出口二：提醒扫描（返回每档的设备编码数组） */
async function fromReminders() {
  const r = await deviceReminder.scanDeviceReminders({ scopeFilter: {} });
  const pick = (key) =>
    (r[key] || []).map((d) => d.deviceCode).filter((code) => code.startsWith(TAG));
  return {
    expired: pick('expired'),
    expiringSoon: pick('expiringSoon'),
    needMaintenance: pick('needMaintenance'),
    needSchedule: pick('needSchedule'),
  };
}

/** 出口三：到期设备清单 */
async function fromExpiringList() {
  const rows = await DeviceService.getExpiringDevices(30, {});
  return rows.map((d) => d.deviceCode).filter((code) => code.startsWith(TAG));
}

/**
 * 出口四（"有效期未登记"唯一的可达出口）：直接拿判据去库里取成员。
 * 这一档只被 `getDeviceStats` 计数消费，清单侧没有出口，所以成员级判据只能落在生产过滤器上——
 * 而不是测试自己重写一份条件（那会让变异永远打不红）。
 */
async function fromUnknownExpiry() {
  const rows = await FireDevice.find(deviceAlertFilters(new Date()).expiryUnknown)
    .select('deviceCode')
    .lean();
  return rows.map((d) => d.deviceCode).filter((code) => code.startsWith(TAG));
}

describe('同一台设备在五档判据下的归属', () => {
  test('每台设备的期望归属本身自洽（前提自证：档位互斥）', () => {
    for (const c of CASES) {
      expect(bucketsOf(c.expect).length).toBeLessThanOrEqual(1);
    }
    const filters = deviceAlertFilters(new Date());
    expect(Object.keys(filters)).toEqual([
      'expired',
      'expiringSoon',
      'needMaintenance',
      'needSchedule',
      'expiryUnknown',
    ]);
  });

  test('提醒扫描的每一档成员必须与期望表逐字一致', async () => {
    const got = await fromReminders();
    for (const bucket of Object.keys(got)) {
      const want = CASES.filter((c) => c.expect[bucket]).map((c) => c.code);
      expect({ bucket, members: got[bucket].sort() }).toEqual({
        bucket,
        members: want.sort(),
      });
    }
  });

  test(' scrapped 设备在任何一档都不出现（修前仪表盘会多算它）', async () => {
    const got = await fromReminders();
    const all = [...got.expired, ...got.expiringSoon, ...got.needMaintenance, ...got.needSchedule];
    expect(all).not.toContain(`${TAG}-SCRAPPED-OVERDUE`);
    const stats = await DeviceService.getDeviceStats({});
    // 计数侧同样不含：三档之和不得超过"在册且非报废"的设备数
    const aliveTotal = await FireDevice.countDocuments({ status: { $ne: 'scrapped' } });
    expect(stats.total).toBeGreaterThan(0);
    expect(aliveTotal).toBeLessThan(stats.total);
  });

  test('三个出口对"即将到期"给出同一批设备', async () => {
    const stats = await DeviceService.getDeviceStats({});
    const reminders = await fromReminders();
    const list = await fromExpiringList();
    const expected = CASES.filter((c) => c.expect.expiringSoon).map((c) => c.code);

    expect(reminders.expiringSoon.sort()).toEqual(expected.sort());
    expect(list.sort()).toEqual(expect.arrayContaining(expected));
    // 计数与成员集合同口径：stats 这一档的数量必须 >= 期望表里的条数，
    // 且不得把报废/窗口外的设备算进来（差值只能来自本文件之外的存量数据）
    // 必须用 $and：直接 `{...expiringSoonFilter, status:'scrapped'}` 会把我正要验证的
    // `status: {$nin:['scrapped']}` 覆盖掉，判据恒等于"没排除任何东西"（假 0/假 1 都可能）
    const scrappedInWindow = await FireDevice.countDocuments({
      $and: [deviceAlertFilters(new Date()).expiringSoon, { status: 'scrapped' }],
    });
    expect(scrappedInWindow).toBe(0);
    expect(stats.expiringSoon).toBeGreaterThanOrEqual(expected.length);
  });

  test('未排期设备必须单独可见，且不得混进"待维护"', async () => {
    const stats = await DeviceService.getDeviceStats({});
    const got = await fromReminders();
    expect(got.needSchedule).toContain(`${TAG}-UNSCHEDULED`);
    expect(got.needMaintenance).not.toContain(`${TAG}-UNSCHEDULED`);
    expect(stats.needSchedule).toBeGreaterThanOrEqual(1);

    // 两档互斥：同一台设备不能同时被计入 needMaintenance 与 needSchedule
    const both = await FireDevice.countDocuments({
      deviceCode: `${TAG}-UNSCHEDULED`,
      ...deviceAlertFilters(new Date()).needMaintenance,
    });
    expect(both).toBe(0);
  });

  /**
   * 前提自证：`expiryDate` 的"没登记"在库里有**两种**形态，而 Mongo 的 `{field: null}`
   * 恰好同时匹配两者（`$exists: false` 只匹配前者）。不先把这个差异钉住，
   * 下面那条成员级断言就可能只剩一种形态在被测——而看起来像在测两件事。
   */
  test('expiryUnknown 的前提：同一件事在库里有"缺键"和"显式 null"两种形态', async () => {
    const rows = await FireDevice.find({
      deviceCode: { $in: [`${TAG}-NO-EXPIRY`, `${TAG}-NULL-EXPIRY`] },
    }).lean();
    expect(rows.length).toBe(2);
    const byCode = Object.fromEntries(rows.map((r) => [r.deviceCode, r]));
    expect(Object.prototype.hasOwnProperty.call(byCode[`${TAG}-NO-EXPIRY`], 'expiryDate')).toBe(
      false
    );
    expect(Object.prototype.hasOwnProperty.call(byCode[`${TAG}-NULL-EXPIRY`], 'expiryDate')).toBe(
      true
    );
    expect(byCode[`${TAG}-NULL-EXPIRY`].expiryDate).toBeNull();
  });

  test('expiryUnknown 的成员逐字一致，且计数出口与判据同口径', async () => {
    const got = await fromUnknownExpiry();
    expect(got.sort()).toEqual([...EXPIRY_UNKNOWN_MEMBERS].sort());

    const stats = await DeviceService.getDeviceStats({});
    // 这一档不含任何时刻比较 ⇒ 两次取判据必然同值，等式可以收紧到 toBe。
    // 它测的是"接线"（计数出口用的确实是这一档），上面那条测的是"口径"：
    // 只留一条的话，把 expiryUnknown 整档清空会让两条都假绿（0 === 0），
    // 而只留等式则防不住出口侧换成 expired/expiringSoon。
    expect(stats.expiryUnknown).toBe(
      await FireDevice.countDocuments(deviceAlertFilters(new Date()).expiryUnknown)
    );
    expect(stats.expiryUnknown).toBeGreaterThanOrEqual(EXPIRY_UNKNOWN_MEMBERS.length);
  });

  test('反向前提：expiryUnknown 与到期/排期档不互斥，"各档之和可与 total 对齐"不成立', async () => {
    const alert = deviceAlertFilters(new Date());
    // 同一台设备既"有效期未登记"又"已过检查期待维护" ⇒ 两档之和会重计它。
    // 必须用 $and：展开两个 filter 会让后写的 status 覆盖前一个，判据静默变成"没排除任何东西"。
    expect(
      await FireDevice.countDocuments({
        deviceCode: `${TAG}-OVERDUE-CHECK`,
        $and: [alert.needMaintenance, alert.expiryUnknown],
      })
    ).toBe(1);
    expect(
      await FireDevice.countDocuments({
        deviceCode: `${TAG}-UNSCHEDULED`,
        $and: [alert.needSchedule, alert.expiryUnknown],
      })
    ).toBe(1);
    // 排除集**不对称**（到期侧 [scrapped]，排期侧 [maintenance, scrapped]）：
    // 同一台"维护中且没登记有效期"的设备在 needMaintenance 里隐身、
    // 在 expiryUnknown 里必须可见。把 ALERT_EXCLUDED_STATUS 换成 MAINTENANCE_EXCLUDED_STATUS
    // 就会让这一条红（而不是只靠上面的成员表撞红）。
    expect({
      needMaintenance: await FireDevice.countDocuments({
        deviceCode: `${TAG}-IN-MAINTENANCE`,
        ...alert.needMaintenance,
      }),
      expiryUnknown: await FireDevice.countDocuments({
        deviceCode: `${TAG}-IN-MAINTENANCE`,
        ...alert.expiryUnknown,
      }),
    }).toEqual({ needMaintenance: 0, expiryUnknown: 1 });
    // 报废侧：两档都不含它（status 排除集在到期/信息不全侧同样生效）
    expect(await fromUnknownExpiry()).not.toContain(`${TAG}-SCRAPPED-NO-EXPIRY`);
  });
});

/**
 * 单一来源守卫：任何消费方再各自写一份窗口/排除集，这条会红。
 * 文本判据只能防"又抄一份"，防不住"删掉调用"，所以它与上面的跨出口一致性断言是互补关系。
 */
describe('提醒档判据只有一处定义', () => {
  const CONSUMERS = [
    'src/services/DeviceService.js',
    'src/services/deviceReminder.js',
    'src/services/reportStatsService.js',
    'src/services/reportDashboardService.js',
  ];
  const codeOnly = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  // 只禁"再写一份条件"的形状，不禁函数引用：任何消费方出现 `expiryDate: {` 或
  // `nextCheckDate: {` 这类内联范围条件，就说明它绕开了统一口径。
  const BANNED = [
    /setDate\(/,
    /ne:\s*'scrapped'/,
    /ne:\s*'maintenance'/,
    /\d+\s*\*\s*MS_PER_MINUTE\s*\*\s*60\s*\*\s*24/,
    /expiryDate:\s*\{/,
    /nextCheckDate:\s*\{/,
  ];

  test('四个消费方都引用 constants/deviceAlerts', () => {
    for (const rel of CONSUMERS) {
      const code = codeOnly(fs.readFileSync(path.join(__dirname, '..', '..', '..', rel), 'utf8'));
      expect({ rel, refs: /constants\/deviceAlerts/.test(code) }).toEqual({
        rel,
        refs: true,
      });
    }
  });

  test('消费方不得再自写窗口或排除集（内联 expiryDate/nextCheckDate 即算另起一份）', () => {
    for (const rel of CONSUMERS) {
      const code = codeOnly(fs.readFileSync(path.join(__dirname, '..', '..', '..', rel), 'utf8'));
      for (const rx of BANNED) {
        expect({ rel, pattern: String(rx), hit: rx.test(code) }).toEqual({
          rel,
          pattern: String(rx),
          hit: false,
        });
      }
    }
  });

  test('反向前提：每个禁用判据都真能抓到被抄回的写法（防空集恒绿）', () => {
    const dirty = codeOnly(
      [
        'const w = new Date(); w.setDate(w.getDate() + 30);',
        "const a = { status: { $ne: 'scrapped' } };",
        "const b = { status: { $ne: 'maintenance' } };",
        'const c = 30 * MS_PER_MINUTE * 60 * 24;',
        'const d = { expiryDate: { $gte: now } };',
        'const e = { nextCheckDate: { $lte: now } };',
      ].join('\n')
    );
    const missed = BANNED.filter((rx) => !rx.test(dirty)).map(String);
    expect(missed).toEqual([]);

    // 干净形状不得误伤：只引用函数、不带内联条件
    const clean = codeOnly(
      'const f = deviceAlertFilters(now).expiringSoon;\nawait FireDevice.find({ ...base, ...f });\n'
    );
    const falsePositives = BANNED.filter((rx) => rx.test(clean)).map(String);
    expect(falsePositives).toEqual([]);

    // 注释里的同名写法必须被剥掉，否则本守卫会在正常代码上假红
    const commentOnly = codeOnly(
      "// setDate(x) 已经不再使用\n/* status: { $ne: 'scrapped' } */\nconst a = 1;\n"
    );
    for (const rx of BANNED) expect(rx.test(commentOnly)).toBe(false);
  });
});
