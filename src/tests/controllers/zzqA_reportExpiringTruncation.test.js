/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：GET /api/reports/devices 的 `expiringSoon` 段（reportStatsService）
 * 守护的不变式：**截断必须可数** —— 响应体必须能区分"库里就 20 台"与
 *   "库里 21 台、我只看见最先到期的 20 台"（F-210，与 F-174 同一条约定的第二个出口）
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 【缺陷本体】
 * `reportStatsService.getDeviceReportData` 用 `.limit(20)` 截清单，却把**裸数组**放进响应，
 * 控制器（reportController.js:60）再以 `'获取设备报表成功'` 作答。于是"被截断"这个事实在
 * 响应里没有任何载体：`data.expiringSoon.length` 恒等于 20，库里 20 台与 2000 台同形。
 * 同一份代码里就有反证：兄弟出口 `GET /api/devices/expiring` 已经带 `pagination.total`
 * （F-174 的落点），`constants/deviceAlerts.js:38-48` 更把约定写成了文字——
 * 「上限本身不是问题，**静默**才是」。报表这一路是漏网的那个出口。
 *
 * 【为什么打真实 HTTP 而不是只测 service】
 * 不变式的载体是**响应体形状**。服务层单测看不到控制器怎么包装响应，也看不到
 * `scopeFilterFor('device', dataScope)` 在 self 档把 JWT 里的**字符串** userId
 * 铸成 ObjectId 这一步（F-A5 修的就是它）——那一步坏了，这里 total/list 会同时归零，
 * 而"两个 0 相等"在服务层看起来仍然像"没截断"。
 *
 * 【为什么用 self 档用户而不是超管】
 * `all` 档的过滤条件是空集，`expiringSoonTotal` 会把**其他套件并发写入**的设备一起数进来，
 * 精确断言就成了测不确定的数。self 档把可见集锁在"本测试自己创建的文档"上：
 * 数字可精确、且不依赖套件运行顺序（顺带把 F-A5 的 cast 路径也纳入覆盖）。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `ZQF210${Date.now().toString(36)}`.toUpperCase().replace(/[^A-Z0-9]/g, '');

/** 撞上限组：数量必须**严格大于**报表上限，否则"撞上限"一臂是空跑的假绿 */
const TRUNC_CODES = Array.from({ length: 21 }, (_, i) => `${stamp}_T${String(i).padStart(2, '0')}`);
/** 未撞上限组（反向对照）：证明 truncated 不是恒真 */
const SMALL_CODES = Array.from({ length: 3 }, (_, i) => `${stamp}_S${i}`);
const MY_CODES = [...TRUNC_CODES, ...SMALL_CODES];

const atOffset = (days) => {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d;
};

const seed = (deviceCode, userId, i) => ({
  deviceCode,
  deviceName: `${stamp} 报表到期 ${i}`,
  deviceType: 'extinguisher',
  installDate: new Date('2026-01-01'),
  // 全部落在 30 天窗口内且到期日互不相同，排序稳定，截断保留的是最先到期的一批
  expiryDate: atOffset(2 + (i % 15)),
  location: { building: `${stamp}栋`, floor: '1F', detail: deviceCode },
  createdBy: userId,
});

describe('报表设备段的到期截断必须可数（F-210）', () => {
  let app;
  let FireDevice;
  let truncToken;
  let smallToken;
  let truncUserId;

  const asTrunc = () =>
    request(app).get('/api/reports/devices').set('Authorization', `Bearer ${truncToken}`);
  const asSmall = () =>
    request(app).get('/api/reports/devices').set('Authorization', `Bearer ${smallToken}`);

  /** self 档用户：level 4 ⇒ getDataScope 返回 {type:'self'}（rbac.js LEVEL_SELF=4） */
  const makeSelfUser = async (label) => {
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    const perm = await Permission.findOneAndUpdate(
      { code: 'report:read' },
      { $setOnInsert: { name: '报表读取', code: 'report:read', type: 'api', module: 'report' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `报表self_${label}_${stamp}`,
      code: `REPORT_SELF_${label}_${stamp}`,
      level: 4,
      isBuiltIn: false,
      permissions: [perm._id],
    });
    const user = await User.create({
      username: `repself${label}${stamp}`.toLowerCase(),
      email: `repself${label}${stamp.toLowerCase()}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    const token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    return { user, token, role };
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    require('../../models/TokenBlacklist');
    FireDevice = require('../../models/FireDevice');

    const a = await makeSelfUser('A');
    const b = await makeSelfUser('B');
    truncUserId = a.user._id;
    truncToken = a.token;
    smallToken = b.token;
    global.__F210_ROLES = [a.role, b.role];
    global.__F210_USERS = [a.user, b.user];

    await FireDevice.insertMany([
      ...TRUNC_CODES.map((deviceCode, i) => seed(deviceCode, truncUserId, i)),
      ...SMALL_CODES.map((deviceCode, i) => seed(deviceCode, b.user._id, i)),
    ]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({ deviceCode: { $in: MY_CODES } }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteMany({ _id: { $in: global.__F210_USERS.map((u) => u._id) } }).catch(
        () => {}
      );
      await Role.deleteMany({ _id: { $in: global.__F210_ROLES.map((r) => r._id) } }).catch(
        () => {}
      );
      await mongoose.connection.close();
    }
  });

  // ---------- 前提自证：种子确实撞得上限 ----------

  test('前提：报表上限真实存在，且撞上限组的种子严格大于它（否则下面第一条是空跑）', async () => {
    const res = await asTrunc().expect(200);
    const limit = res.body.data.expiringSoonLimit;
    expect(typeof limit).toBe('number');
    expect(limit).toBeGreaterThan(0);
    expect(TRUNC_CODES.length).toBeGreaterThan(limit);
    // 种子全部落库且归 self 用户所有（scope 没漏进别人的数据）
    const mine = await FireDevice.countDocuments({
      deviceCode: { $in: MY_CODES },
      createdBy: truncUserId,
    });
    expect(mine).toBe(TRUNC_CODES.length);
  });

  test('撞上限：清单封顶、total 如实、truncated=true（修复前这三者只会给出"20"）', async () => {
    const res = await asTrunc().expect(200);
    const d = res.body.data;
    expect(d.expiringSoon).toHaveLength(d.expiringSoonLimit);
    expect(d.expiringSoonTotal).toBe(TRUNC_CODES.length);
    expect(d.expiringSoonTruncated).toBe(true);
  });

  // ---------- 反向对照臂：未撞上限不得谎报截断 ----------

  test('未撞上限（对照）：total=list.length 且 truncated=false（证明上一条不是恒真）', async () => {
    const res = await asSmall().expect(200);
    const d = res.body.data;
    expect(d.expiringSoonTotal).toBe(SMALL_CODES.length);
    expect(d.expiringSoon).toHaveLength(SMALL_CODES.length);
    expect(d.expiringSoonTruncated).toBe(false);
  });

  // ---------- 同源性：计数与清单必须吃同一个过滤器 ----------

  test('计数与清单共用同一判据：把一台置为 scrapped，total 与清单同步减少、不得虚报截断', async () => {
    // 若 countDocuments 用的是另一份过滤器（例如漏了 deviceAlertFilters 的 status 排除），
    // 这里就会得到 total=21 / list=20 ⇒ truncated=true —— 一个不存在的截断被报出来。
    await FireDevice.updateOne({ deviceCode: TRUNC_CODES[0] }, { $set: { status: 'scrapped' } });
    try {
      const res = await asTrunc().expect(200);
      const d = res.body.data;
      expect(d.expiringSoonTotal).toBe(TRUNC_CODES.length - 1);
      expect(d.expiringSoon).toHaveLength(Math.min(d.expiringSoonLimit, TRUNC_CODES.length - 1));
      expect(d.expiringSoonTruncated).toBe(d.expiringSoonTotal > d.expiringSoon.length);
      // scrapped 的那台既不在清单里、也不在计数里：两侧口径一致
      expect(d.expiringSoon.map((x) => x.deviceCode)).not.toContain(TRUNC_CODES[0]);
    } finally {
      await FireDevice.updateOne({ deviceCode: TRUNC_CODES[0] }, { $set: { status: 'normal' } });
    }
  });

  test('段名与消息不谎报：数据范围只覆盖本用户，响应 message 仍是成功（不因增补字段而变契约）', async () => {
    const res = await asTrunc().expect(200);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toContain('成功');
    // 其余段不受增补字段影响（byStatus 来自同一 scopeFilter 的聚合，键集稳定）
    expect(Array.isArray(res.body.data.byStatus)).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(res.body.data, 'expiringSoonTotal')).toBe(true);
  });
});
