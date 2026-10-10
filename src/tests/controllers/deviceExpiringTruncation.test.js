/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：GET /api/devices/expiring 与 DeviceService 的到期清单/计数
 * 守护的不变式：**截断必须可数**——响应体必须能区分"库里就 50 台"与
 *   "库里 512 台、我只看见最先到期的 50 台"
 * 可证伪性：见各用例的对照臂；已做变异实测（M1~M7，变异窗口与结果记录在
 *   deliverables/AGENT工作总账与待办-2026-09-21.md 的 F-174 条目）
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 【缺陷本体（F-174）】
 * `DeviceService.getExpiringDevices` 是 `.sort({expiryDate:1}).limit(50)`，控制器又用
 * `ApiResponse.success(res, devices)` 把它作为**裸数组**放进 `data`。于是"被截断"这一事实
 * 在响应里没有任何载体：`data.length` 恒等于 50，读到的"50 台即将到期"与真的只有 50 台
 * 完全同形。对消防台账这不是显示问题而是合规判断问题——安全员按屏幕上这份清单排巡检、
 * 备耗材，而清单外还有一大半设备，没有任何一处告诉他人。
 *
 * 同一份代码里就有反证：本服务的**兄弟接口** `GET /api/devices`（deviceController.js:102）
 * 走 `ApiResponse.paginated`，如实带 `total`/`totalPages`；`getDeviceStats` 为同一档判据
 * 专门跑 `countDocuments`（DeviceService.js:420）——"到期设备到底有多少台"一直是系统要
 * 回答的问题，只有清单这条路把它丢了。本仓另有多处已把同一约定写进注释：
 * `auditExportService.js:69`（多取一条当探针，"truncated 判定精确"）、
 * `reportWorkbookService.js:20`（恰好等于上限不得误报截断）、
 * `models/FireDevice.js:235`（"截断必须可数，不能拿数组长度假装这就是全部历史"）。
 *
 * 【修法】`paginated` 只新增 `pagination` 兄弟键，`data` **仍是数组**——三条既有消费路径
 * （zzqB 窗口链、deviceAlertOutletParity 出口三、 scopeCast 的 `toEqual([])`）
 * 都不受影响，因此这是纯增补而不是契约破坏。
 * 计数与清单必须共用同一次过滤器构造与同一个判定时刻，否则两个数来自两个窗口，
 * 边界上的设备会"被数进去却没列出来"（或反过来）——那比没有总数更糟。
 * 判据因此收进 `getExpiringDevices(days, scope, {withTotal:true})` 这一条路径：
 * 拆成两个方法就是给未来的第二份判据开门（本仓 F-1xx 系列反复在治这个）。
 *
 * 【为什么必须打真实 HTTP】
 * 不变式的载体是**响应体形状**，服务层单测看不到控制器怎么包装响应。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const { EXPIRING_LIST_LIMIT } = require('../../constants/deviceAlerts');

const stamp = `ZQF174${Date.now().toString(36)}`.toUpperCase().replace(/[^A-Z0-9]/g, '');

/** 种子数量：必须严格大于生产上限，否则"撞上限"一臂是空跑的假绿 */
const SEED_COUNT = 51;
/** 撞上限的一组全部落在同一日历日偏移，请求窗口取 20 天即可整体命中 */
const SEED_OFFSET_DAYS = 3;
const REQUEST_DAYS = 20;

const codeFor = (i) => `${stamp}_E${String(i).padStart(3, '0')}`;
const ALL_CODES = Array.from({ length: SEED_COUNT }, (_, i) => codeFor(i));
/** 单台子集：窗口收窄与"未撞上限不得谎报截断"两臂用它，闭集判定不受并发套件污染 */
const SINGLE_CODE = `${stamp}_SINGLE`;
const SINGLE_SCOPE = { deviceCode: { $in: [SINGLE_CODE] } };
/** 到期日互不相同的三台：只用于钉住"截断保留的是最近到期的一批" */
const ORDER_CODES = [`${stamp}_O1`, `${stamp}_O2`, `${stamp}_O3`];
const ORDER_SCOPE = { deviceCode: { $in: ORDER_CODES } };

describe('到期设备清单的截断必须可数（F-174）', () => {
  let app;
  let FireDevice;
  let deviceService;
  let adminToken;

  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`),
  });

  const atOffset = (days) => {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d;
  };

  const seed = (deviceCode, deviceName, deviceType, days) => ({
    deviceCode,
    deviceName,
    deviceType,
    installDate: new Date('2026-01-01'),
    expiryDate: atOffset(days),
    location: { building: '截断栋', floor: '1F', detail: deviceCode },
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../../models/FireDevice');
    deviceService = require('../../services/DeviceService');
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: `超管_截断_${stamp}`,
      code: `SUPER_ADMIN_TRC_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `trcadmin${stamp}`.toLowerCase(),
      email: `trcadmin${stamp.toLowerCase()}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();

    // 直接建文档（不绕 HTTP）：51 次 POST 会一并推动 counters 取号，
    // 而这里只关心同一集合内清单与计数的关系，编号显式给定即可。
    await FireDevice.insertMany([
      ...ALL_CODES.map((deviceCode, i) =>
        seed(deviceCode, `${stamp} 到期${i}`, 'extinguisher', SEED_OFFSET_DAYS)
      ),
      seed(SINGLE_CODE, `${stamp} 单台`, 'hydrant', 5),
      seed(ORDER_CODES[0], `${stamp} 最近`, 'hydrant', 1),
      seed(ORDER_CODES[1], `${stamp} 居中`, 'hydrant', 2),
      seed(ORDER_CODES[2], `${stamp} 最远`, 'hydrant', 3),
    ]);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({
        deviceCode: { $in: [...ALL_CODES, SINGLE_CODE, ...ORDER_CODES] },
      }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `trcadmin${stamp}`.toLowerCase() }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_TRC_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  // ---------- 前提自证：撞得上上限 ----------

  test('前提：种子确有 SEED_COUNT 台落在窗口内，且 SEED_COUNT 真的大于上限', async () => {
    expect(EXPIRING_LIST_LIMIT).toBeGreaterThan(0);
    expect(SEED_COUNT).toBeGreaterThan(EXPIRING_LIST_LIMIT);
    const mine = await deviceService.getExpiringDevices(
      REQUEST_DAYS,
      {
        deviceCode: { $in: ALL_CODES },
      },
      { withTotal: true }
    );
    expect(mine.total).toBe(SEED_COUNT);
  });

  // ---------- 缺陷本体：HTTP 响应必须说清"只给了一部分" ----------

  test('HTTP 撞上限：pagination 如实带 total/hasMore，data 仍是数组', async () => {
    const res = await authed().get(`/api/devices/expiring?days=${REQUEST_DAYS}`);
    expect(res.status).toBe(200);

    // data 保持数组：新增的是 pagination 兄弟键，不是把清单包进对象
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data).toHaveLength(EXPIRING_LIST_LIMIT);

    expect(res.body.pagination).toEqual({
      // page/totalPages 必须是 null：本接口没有翻页入参，填成 1/N 就是许诺"还能取第 2 页"，
      // 而客户端真去取会原样拿回第 1 页——那是换个方向的谎。
      page: null,
      limit: EXPIRING_LIST_LIMIT,
      total: expect.any(Number),
      totalPages: null,
      hasMore: true,
    });
    // 这条就是缺陷本体："被截断"必须能从响应里读出来，而不是靠 data.length 猜
    expect(res.body.pagination.total).toBeGreaterThanOrEqual(SEED_COUNT);
    expect(res.body.pagination.total).toBeGreaterThan(res.body.data.length);
    // 人读的那一路也要说：前端 toast 用的就是 message，只有 pagination 可读＝只有机器能发现
    expect(res.body.message).toContain('仅返回');
  });

  test('HTTP 反向保护：窗口内不足上限时不得谎报截断', async () => {
    // days=0 的窗口在日历日语义下塌缩为单一时刻 ⇒ 必然空集（zzqB 已钉同一判据）。
    // 这一臂挡的是"为了显得诚实而无条件报截断"。
    const res = await authed().get('/api/devices/expiring?days=0');
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual([]);
    expect(res.body.pagination.hasMore).toBe(false);
    expect(res.body.pagination.total).toBe(0);
    expect(res.body.pagination.totalPages).toBeNull();
    expect(res.body.message).not.toContain('仅返回');
  });

  // ---------- 同源：计数与清单必须是同一个窗口 ----------

  test('闭集：total 与清单成员出自同一判据（多算/少算都会在这里露出来）', async () => {
    const { devices, total } = await deviceService.getExpiringDevices(
      REQUEST_DAYS,
      { deviceCode: { $in: ALL_CODES } },
      { withTotal: true }
    );
    expect(total).toBe(SEED_COUNT);
    expect(devices).toHaveLength(EXPIRING_LIST_LIMIT);
    // 同一台设备不得既被计入两次又被清单漏掉：清单里必须全是本组种子
    expect(new Set(devices.map((d) => d.deviceCode)).size).toBe(EXPIRING_LIST_LIMIT);
    expect(devices.every((d) => ALL_CODES.includes(d.deviceCode))).toBe(true);
  });

  test('截断保留的是"最近到期"的一批，且 total 仍是全集规模', async () => {
    // 三台到期日互不相同，上限压到 2 ⇒ 被丢掉的必须是最远那台。
    // 这一臂挡：排序方向被改成 -1（把最远的留在屏上、把最紧急的丢掉而响应照样"看起来正常"），
    // 以及 total 被写成 devices.length（截断后自我循环，等于没报）。
    const { devices, total } = await deviceService.getExpiringDevices(REQUEST_DAYS, ORDER_SCOPE, {
      withTotal: true,
      limit: 2,
    });
    expect(devices.map((d) => d.deviceCode)).toEqual([ORDER_CODES[0], ORDER_CODES[1]]);
    expect(total).toBe(3);
  });

  test('窗口归一必须同时作用于计数：?days 的语义不能在计数这一路失效', async () => {
    // 单台种子在 +5 天。计数若漏了 normalizeExpiringDays，'abc' 会带着 NaN 进查询
    // （窗口塌成空集 ⇒ total=0 而清单非空），0 档也会被放宽成默认 30 天。
    const total = async (days) =>
      (await deviceService.getExpiringDevices(days, SINGLE_SCOPE, { withTotal: true })).total;

    expect(await total(0)).toBe(0);
    expect(await total(5)).toBe(1);
    expect(await total('abc')).toBe(1); // 不可解析 → 回退默认 30 天
    expect(await total(9999)).toBe(1); // 上界钳制方向是收窄
  });

  test('漏传数据范围：计数与清单同为空，而不是回退成全表', async () => {
    const denied = await deviceService.getExpiringDevices(REQUEST_DAYS, undefined, {
      withTotal: true,
    });
    expect(denied).toEqual({ devices: [], total: 0 });
  });

  test('反向保护：不带 withTotal 的旧调用仍返回数组（三条既有消费路径的合同不许被顺手改掉）', async () => {
    const legacy = await deviceService.getExpiringDevices(REQUEST_DAYS, {
      deviceCode: { $in: ALL_CODES },
    });
    expect(Array.isArray(legacy)).toBe(true);
    expect(legacy).toHaveLength(EXPIRING_LIST_LIMIT);
    expect(await deviceService.getExpiringDevices(REQUEST_DAYS)).toEqual([]);
  });
});
