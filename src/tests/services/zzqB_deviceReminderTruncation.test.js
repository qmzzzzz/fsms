/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：deviceReminder.scanDeviceReminders 的单次上限（resultLimit）与 summary
 * 守护的不变式：**截断必须可数**——响应必须能区分「库里就这么多」与
 *   「库里更多、我只看见前 N 条」；且降级路径的载体键与正常路径同构
 * 可证伪性：每条判据都有对照臂（撞上限 / 恰好等于上限 / 未撞上限三态都出现），
 *   变异实测记录在 deliverables/复核台账-B会话-2026-09-24.md 的批次 74 小节
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 【缺陷本体】
 * 四档清单各跑 `.limit(resultLimit)`（默认 200），随后 `summary.expired = expired.length`。
 * 于是命中 5000 台时报 200、确实只有 200 台时也报 200——**上限值被当成库里总数出口**；
 * `summary.total` 只是四页去重后的并集，同样看不见页外设备。
 * 与 `GET /api/devices/expiring` 的 F-174 同族（那侧已收口成 `pagination`），
 * 本文件把提醒扫描这一侧补齐。
 *
 * 【为什么判据落在「探针」而不是 countDocuments】
 * `limit+1` 的探针与清单同源于同一次查询：不多一次往返，也不给「计数与清单来自两个
 * 窗口」留余地（计数与清单分窗比没有计数更糟——边界上的设备会被数进去却没列出来）。
 * 同一条约定已写进 `auditExportService.js:61`（多取一条当探针）、
 * `reportWorkbookService.js:13`（恰好等于上限不得误报截断）、`models/FireDevice.js:235`。
 *
 * 【夹具口径】
 * 种子设备全部落在同一个 `location.building`，每次扫描都带该范围：不带范围就是全库扫描，
 * 会看见**同一 worker 库里其他测试文件**留下的设备（`setup.js` 按 JEST_WORKER_ID 分库，
 * 同库内文件串行而非隔离），任何精确计数断言都会变成随机数。
 */

const mongoose = require('mongoose');
const { deviceAlertFilters } = require('../../constants/deviceAlerts');

const DEVICE_TYPE = Object.values(require('../../utils/constants').DEVICE_TYPE)[0];

const TAG = `ZZB74${Date.now().toString(36)}`.toUpperCase().replace(/[^A-Z0-9]/g, '');
const BUILDING = `Z74栋${TAG}`;
const SCOPE = { 'location.building': BUILDING };
const code = (suffix) => `${TAG}_${suffix}`;

const DAY = 86400000;

/**
 * 种子集合（相对判定时刻的天数偏移）：
 *   A1~A3 只命中 expired（有效期已过、排期在未来）
 *   B1   同时命中 expired 与 needMaintenance（去重臂）
 *   C1   只命中 needSchedule（从未录入检查日 ⇒ 没有排期）
 *   D1   只命中 expiringSoon
 * ⇒ expired 4 / expiringSoon 1 / needMaintenance 1 / needSchedule 1：
 *   四档相加 7 台而设备只有 6 台（B1 重复），两个数必须分别钉住。
 * 偏移都取整数量级天，测试进程内的毫秒漂移不改变归档。
 */
const SEEDS = [
  { suffix: 'A1', expiryOffset: -3, checkOffset: +100 },
  { suffix: 'A2', expiryOffset: -2, checkOffset: +100 },
  { suffix: 'A3', expiryOffset: -1, checkOffset: +100 },
  { suffix: 'B1', expiryOffset: -10, checkOffset: -5 },
  { suffix: 'C1', expiryOffset: +200, checkOffset: null },
  { suffix: 'D1', expiryOffset: +5, checkOffset: +100 },
];

const BUCKET_KEYS = ['expired', 'expiringSoon', 'needMaintenance', 'needSchedule'];

/**
 * 把过滤器压成可比较的字符串。Date 先经 `toJSON` 变 ISO 串（JSON.stringify 的 replacer
 * 拿到的是已转换的值），所以按 ISO 形状归一——否则本用例与服务的判定时刻差几毫秒就红，
 * 而那既不是被测性质也不是任何人该关心的东西。
 */
const fingerprint = (filter) =>
  JSON.stringify(filter, (key, value) =>
    typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value) ? 'DATE' : value
  );

describe('设备提醒扫描的截断必须可数', () => {
  let FireDevice;
  let service;
  const now = Date.now();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../../models/FireDevice');
    service = require('../../services/deviceReminder');

    await FireDevice.deleteMany({ deviceCode: { $regex: `^${TAG}_` } });
    await FireDevice.insertMany(
      SEEDS.map(({ suffix, expiryOffset, checkOffset }) => ({
        deviceCode: code(suffix),
        deviceName: `提醒截断-${suffix}`,
        deviceType: DEVICE_TYPE,
        status: 'normal',
        installDate: new Date(now - 30 * DAY),
        expiryDate: new Date(now + expiryOffset * DAY),
        // C1 用「不写这个字段」表达无排期：$lte 永不匹配缺失字段，正是 needSchedule 档存在的原因
        ...(checkOffset === null ? {} : { nextCheckDate: new Date(now + checkOffset * DAY) }),
        location: { building: BUILDING },
      }))
    );
  });

  // 本仓 jest 未开 restoreMocks：装了 spy 不还原，下一个用例会在假 find 上静默绿灯
  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceCode: { $regex: `^${TAG}_` } });
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const scan = (resultLimit) => service.scanDeviceReminders({ scopeFilter: SCOPE, resultLimit });

  test('撞上限：清单只有上限条数，且响应必须自己声明「后面还有」', async () => {
    const r = await scan(2);

    // expired 档库里 4 台，只出口 2 台
    expect(r.summary.expired).toBe(2);
    expect(r.expired).toHaveLength(2);
    expect(r.limits.resultLimit).toBe(2);

    // 保留的是「最先到期」的那批，不是任意两条：排序与截断方向一起钉住
    expect(r.expired.map((d) => d.deviceCode)).toEqual([code('B1'), code('A1')]);

    // 未撞上限的三档不得被连坐标记（total 随任一档为真）
    expect(r.limits.truncated).toEqual({
      expired: true,
      expiringSoon: false,
      needMaintenance: false,
      needSchedule: false,
      total: true,
    });
  });

  test('恰好等于上限不得误报截断（探针只能多一条，不能少一条）', async () => {
    // 上限 1 时 needMaintenance / needSchedule 各只有 1 台：数组长度 == 上限而探针未命中。
    // 这一臂专杀把判据写成 `docs.length >= resultLimit` 的实现。
    const tight = await scan(1);
    expect(tight.summary.needMaintenance).toBe(1);
    expect(tight.limits.truncated.needMaintenance).toBe(false);
    expect(tight.limits.truncated.needSchedule).toBe(false);
    // expired 4 台仍算截断
    expect(tight.limits.truncated.expired).toBe(true);

    // 上限 4 == expired 档全量：探针取到 4 条、不多于上限 ⇒ 一律未截断
    const exact = await scan(4);
    expect(exact.summary.expired).toBe(4);
    expect(exact.expired).toHaveLength(4);
    expect(exact.limits.truncated).toEqual({
      expired: false,
      expiringSoon: false,
      needMaintenance: false,
      needSchedule: false,
      total: false,
    });
  });

  test('计数随上限移动：证明 summary 跟着真实集合走，不是被钉住的常量', async () => {
    const capped = await scan(2);
    const full = await scan(10);

    expect(capped.summary.expired).toBe(2);
    expect(full.summary.expired).toBe(4);
    expect(full.limits.truncated.expired).toBe(false);
    // 计数与清单同值同源（旧实现里两者也恒等，但恒等的是被截断后的那个数）
    expect(full.summary.expired).toBe(full.expired.length);
  });

  test('total 按设备去重：跨档命中的同一台设备不得计两次', async () => {
    const r = await scan(10);
    const sum = BUCKET_KEYS.reduce((acc, key) => acc + r.summary[key], 0);

    // B1 同时落进 expired 与 needMaintenance：相加 7、去重 6
    expect(sum).toBe(7);
    expect(r.summary.total).toBe(6);
  });

  test('四档都要有独立的计数与截断位，缺一档即红', async () => {
    const r = await scan(10);
    for (const key of BUCKET_KEYS) {
      expect(Array.isArray(r[key])).toBe(true);
      expect(typeof r.summary[key]).toBe('number');
    }
    // 截断位与 summary 键一一对应：多一档少一档都会让消费方读到 undefined
    expect(Object.keys(r.summary).sort()).toEqual([...BUCKET_KEYS, 'total'].sort());
    expect(Object.keys(r.limits.truncated).sort()).toEqual([...BUCKET_KEYS, 'total'].sort());
  });

  test('探针不改判据：四档各自一次查询、判据不串档、且都带上调用者数据范围（H-1）', async () => {
    const original = FireDevice.find;
    const captured = [];
    jest.spyOn(FireDevice, 'find').mockImplementation(function spy(filter) {
      captured.push(filter);
      return original.call(this, filter);
    });

    await scan(1);

    expect(captured).toHaveLength(BUCKET_KEYS.length);
    // 每档都必须带着范围：探针改的是 limit，不是过滤器
    for (const filter of captured) {
      expect(filter['location.building']).toBe(BUILDING);
    }
    // 与生产判据逐档对账（不比时间戳，只比形状与键）：
    // 把某一档的判据错发给另一档、或把四档并成一个 $or，都在这里红
    const alert = deviceAlertFilters(new Date());
    expect(captured.map(fingerprint).sort()).toEqual(
      BUCKET_KEYS.map((key) => fingerprint({ ...SCOPE, ...alert[key] })).sort()
    );
  });

  test('降级路径与正常路径同构：limits 键不能只在成功时存在', async () => {
    let release;
    const gate = new Promise((res) => {
      release = res;
    });
    const chain = {
      select: () => chain,
      sort: () => chain,
      limit: () => chain,
      then: (resolve) => gate.then(() => resolve([])),
    };
    jest.spyOn(FireDevice, 'find').mockReturnValue(chain);

    // 第一次扫描挂起 ⇒ isScanning 为真；第二次带范围只能走降级出口
    const pendingScan = service.scanDeviceReminders({ scopeFilter: SCOPE });
    const skipped = await service.scanDeviceReminders({ scopeFilter: SCOPE, resultLimit: 2 });

    expect(skipped.skipped).toBe(true);
    expect(skipped.partial).toBe(true);
    expect(skipped.limits.truncated.expired).toBe(false);

    release();
    const scanned = await pendingScan;

    // 载体键必须成对存在：读 data.limits.truncated.expired 的一方在降级时也不能拿到 undefined
    expect(Object.keys(skipped.limits).sort()).toEqual(Object.keys(scanned.limits).sort());
    expect(Object.keys(skipped.limits.truncated).sort()).toEqual(
      Object.keys(scanned.limits.truncated).sort()
    );
    expect(Object.keys(skipped.summary).sort()).toEqual(Object.keys(scanned.summary).sort());
  });
});
