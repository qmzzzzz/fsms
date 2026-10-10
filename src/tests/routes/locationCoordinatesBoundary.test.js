'use strict';

/**
 * 设备/报警写入路径上「路由校验面」与「模型约束面」不一致的三格
 *
 * 共同后果不是 500 而是**点不出字段名的 400**：Mongoose 的 cast/required 失败会被
 * 收进 ValidationError，`errorHandler.js:63-71` 在非 development 下把 `fieldErrors`
 * 整个抹掉（"避免泄露 schema 信息"），于是提交者只看到一句「校验失败」。
 * 本仓既有判据一律要求 400 由路由给出且点名路径，
 * 因为 DB 层那句 400 既不点名、也不该成为唯一的拒绝来源。
 *
 * 三格（均已实测）：
 *   1. `location.coordinates.{lat,lng}`：模型有该字段（FireDevice.js:55、FireAlarm.js:47，
 *      类型 Number 无边界），三条路由的 location 链却一个字没写 ⇒
 *      `lat: 91` 这种物理上不存在的坐标原样落库并被详情接口回吐；
 *      `lat: 'abc'` 由 cast 拒掉，但点不出字段名。
 *   2. `installDate`：模型 required（FireDevice.js:74-77），路由声明 optional
 *      ⇒ 省略必填字段的请求拿到一句无名 400（前端表单必填，纯 API 调用方无提示）。
 *   3. `images`：模型是 `[String]` 无任何约束，路由只判"数组最多 10 个"
 *      ⇒ 单元素长度此前只剩 1MB body 总闸兜着。
 *
 * 每个拒绝用例都回读数据库确认「什么都没写」，并有反向对照确认合法值仍能写入且
 * 原样读回——防止把字段判成永远写不进去的死字段。
 *
 * 「什么都没写」这一格有两个假绿构造方式，本文件的回读口一律避开（均实测）：
 *   · **按非法值计数**：`countDocuments({'location.coordinates.lat': 'abc'})` 看着
 *     在查脏数据，实际查不到任何东西——真写进去了也是 Number cast 之后的形态，
 *     存不出 `'abc'`；用模型查还会先抛 CastError（查询条件同样要过 cast）。
 *   · **按被 setter 改写过的字段查原始驱动**：`deviceCode` 配了 `uppercase`，
 *     落库是大写而查询条件不会被改写（Mongoose 6+ 不再对 query 跑 setter），
 *     于是 `collection.findOne({deviceCode: 小写})` 恒为 null ⇒ "没落库"永真。
 * 正解是拿**本用例自己的唯一编码**做存在性判断：脏写一旦发生的编码还是它，
 * 这条断言才有可能转红。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `lct${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();
/** 与 deviceRoutes.js 的 images.* 上限同值 */
const IMAGE_MAX = 2048;

describe('设备/报警写入：路由与模型的约束一致性', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let FireDevice;
  let FireAlarm;
  let superToken;

  const auth = (token) => ({ Authorization: `Bearer ${token}` });
  const paths = (res) => (res.body?.errors?.fieldErrors || []).map((e) => e.path);
  const tokenFor = (userId, username) =>
    jwt.sign({ userId: String(userId), username, tokenVersion: 0 }, process.env.JWT_SECRET, {
      expiresIn: '24h',
    });

  const newDevice = (over) => ({
    deviceCode: `${stamp}d${Math.random().toString(36).slice(2, 7)}`,
    deviceName: `${stamp}设备`,
    deviceType: 'extinguisher',
    installDate: '2025-01-01',
    ...over,
  });
  const newAlarm = (description, location) => ({
    alarmType: 'smoke',
    description,
    location,
  });

  /** 存在性只按编码查（大写形态，见文件头），不按被校验的字段查 */
  const deviceExists = async (code) => {
    const n = await FireDevice.collection.countDocuments({ deviceCode: code.toUpperCase() });
    return n > 0;
  };
  const rawDevice = (code) => FireDevice.collection.findOne({ deviceCode: code.toUpperCase() });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    require('../../models/TokenBlacklist');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const operator = await User.create({
      username: `${stamp}op`,
      email: `${stamp}op@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superToken = tokenFor(operator._id, operator.username);

    const { createApp } = require('../../app');
    app = createApp();
  });

  const postDevice = (payload) =>
    request(app).post('/api/devices').set(auth(superToken)).send(payload);
  const postAlarm = (payload) =>
    request(app).post('/api/alarms/report').set(auth(superToken)).send(payload);

  // ==================== 1. location.coordinates ====================
  describe('location.coordinates 的类型与取值域', () => {
    // 非法类型必须是 4xx **且点名**：只断言状态码会放过"DB cast 顺手拒掉"这条假绿路径
    test('设备创建：lat 传字符串必须 4xx 且点名该字段', async () => {
      const payload = newDevice({ location: { coordinates: { lat: 'abc' } } });
      const res = await postDevice(payload);
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
      expect(paths(res)).toContain('location.coordinates.lat');
      expect(await deviceExists(payload.deviceCode)).toBe(false);
    });

    test('报警上报：lat 传字符串必须 4xx 且点名该字段', async () => {
      const description = `${stamp}alarmstr`;
      const res = await postAlarm(newAlarm(description, { coordinates: { lat: 'abc' } }));
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
      // 这里整对象比对而不是 paths(res).toContain(...)：后者失败时只回显字段名数组，
      // 分不清"闸门没跑"和"跑错了字段"；把整个响应体打进失败文本才是可归因的红
      expect(res.body).toMatchObject({
        errors: {
          fieldErrors: expect.arrayContaining([
            expect.objectContaining({ path: 'location.coordinates.lat' }),
          ]),
        },
      });
      const n = await FireAlarm.collection.countDocuments({ description });
      expect(n).toBe(0);
    });

    test('coordinates 整个传成字符串（模型里是子文档）必须 4xx 且点名 coordinates', async () => {
      const payload = newDevice({ location: { coordinates: 'abc' } });
      const res = await postDevice(payload);
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
      expect(paths(res)).toContain('location.coordinates');
      expect(await deviceExists(payload.deviceCode)).toBe(false);
    });

    test.each([
      ['lat', 91],
      ['lat', -91],
      ['lng', 181],
      ['lng', -181],
      ['lat', {}],
      ['lat', true],
    ])('%s=%p 必须 4xx 且点名该字段，不得落库', async (field, value) => {
      const payload = newDevice({ location: { coordinates: { [field]: value } } });
      const res = await postDevice(payload);
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
      expect(paths(res)).toContain(`location.coordinates.${field}`);
      expect(await deviceExists(payload.deviceCode)).toBe(false);
    });

    test('边界值与极小坐标必须原样落库（判据不能误伤合法输入）', async () => {
      // 1e-7 是 JSON 里 `0.0000001` 的序列化形态：若闸门走 String(value) 再 isFloat，
      // 带符号指数会被拒（validator 的 isFloat 不接受 `1e-7`）——那才是真缺陷。
      const cases = [
        { lat: 90, lng: -180 },
        { lat: -90, lng: 180 },
        { lat: 0.0000001, lng: 1e-9 },
        { lat: '30.5', lng: '120.5' }, // 数字字符串：模型 cast 今天接受，闸门不得收紧
      ];
      for (const [i, coordinates] of cases.entries()) {
        const payload = newDevice({ deviceCode: `${stamp}ok${i}`, location: { coordinates } });
        const res = await postDevice(payload);
        expect(res.status).toBeLessThan(400);
        const raw = await rawDevice(payload.deviceCode);
        expect(raw.location.coordinates).toMatchObject({
          lat: Number(coordinates.lat),
          lng: Number(coordinates.lng),
        });
      }
    });

    test('设备更新路径同样收口（PUT /devices/:id）', async () => {
      const created = await FireDevice.create(newDevice({ deviceCode: `${stamp}u1` }));
      const res = await request(app)
        .put(`/api/devices/${created._id}`)
        .set(auth(superToken))
        .send({ location: { coordinates: { lat: 91 } } });
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
      expect(paths(res)).toContain('location.coordinates.lat');
      const after = await FireDevice.collection.findOne({ _id: created._id });
      expect(after.location?.coordinates?.lat ?? null).not.toBe(91);
    });

    test('存量文档 lat 为 null 时原样存回不得被闸门打回（编辑回填路径）', async () => {
      const created = await FireDevice.create(
        newDevice({
          deviceCode: `${stamp}u2`,
          location: { coordinates: { lat: null, lng: null } },
        })
      );
      const res = await request(app)
        .put(`/api/devices/${created._id}`)
        .set(auth(superToken))
        .send({ location: { building: `${stamp}栋`, coordinates: { lat: null, lng: null } } });
      expect(res.status).toBeLessThan(400);
    });
  });

  // ==================== 2. installDate：模型必填、路由必填 ====================
  describe('installDate 的必填性必须在路由层点名', () => {
    test('省略 installDate ⇒ 400 且点名该字段（此前是 DB 层无名 400）', async () => {
      const full = newDevice();
      const { installDate, ...rest } = full;
      // 反空转：必须证明"省略"真的发生过。若 newDevice() 日后不再提供 installDate，
      // rest 就与完整 payload 逐键等价，本用例会退化成"验证一个本来就缺字段的请求"
      // ——仍然全绿，却已不再测"省略必填字段"这一格。
      expect(installDate).toBe('2025-01-01');
      expect(rest).not.toHaveProperty('installDate');
      const res = await postDevice(rest);
      expect(res.status).toBe(400);
      expect(paths(res)).toContain('installDate');
      expect(await deviceExists(rest.deviceCode)).toBe(false);
    });

    test('非法日期格式仍点名同一字段（原链口径不变）', async () => {
      const payload = newDevice({ installDate: 'not-a-date' });
      const res = await postDevice(payload);
      expect(res.status).toBe(400);
      expect(paths(res)).toContain('installDate');
      expect(await deviceExists(payload.deviceCode)).toBe(false);
    });

    test('显式 null 与空串不得被当成"没给"以外的含义：一律 400 点名', async () => {
      for (const value of [null, '']) {
        const payload = newDevice({ installDate: value });
        const res = await postDevice(payload);
        expect(res.status).toBe(400);
        expect(paths(res)).toContain('installDate');
        expect(await deviceExists(payload.deviceCode)).toBe(false);
      }
    });

    test('反向对照：合法 ISO8601 正常创建', async () => {
      const payload = newDevice({ deviceCode: `${stamp}date1` });
      const res = await postDevice(payload);
      expect(res.status).toBeLessThan(400);
      const raw = await rawDevice(payload.deviceCode);
      expect(raw.installDate.getTime()).toBe(new Date('2025-01-01').getTime());
    });
  });

  // ==================== 3. images 逐元素长度 ====================
  describe('images 的逐元素边界', () => {
    test('单张超长 ⇒ 400 点名 images[0]，且不得落库', async () => {
      const payload = newDevice({
        deviceCode: `${stamp}img1`,
        images: ['x'.repeat(IMAGE_MAX + 1)],
      });
      const res = await postDevice(payload);
      expect(res.status).toBe(400);
      expect(paths(res)).toContain('images[0]');
      expect(await deviceExists(payload.deviceCode)).toBe(false);
    });

    // 保护来自"闸门存在"，不来自顺序：本链的校验器只有 isLength（不写回 req.body），
    // 把闸门挪到长度链之后同样报 images[0]（已变异实测）。顺序真正要紧的是带 .trim()
    // 的链——见 validationRules.js 里 mustBeString 的说明。
    test('元素非字符串 ⇒ 400 点名 images[0]，且不得落库', async () => {
      const payload = newDevice({ deviceCode: `${stamp}img2`, images: [{}] });
      const res = await postDevice(payload);
      expect(res.status).toBe(400);
      expect(paths(res)).toContain('images[0]');
      expect(await deviceExists(payload.deviceCode)).toBe(false);
    });

    test('反向对照：恰好到上限的地址原样落库', async () => {
      const url = `https://example.com/${'y'.repeat(IMAGE_MAX - 20)}`;
      expect(url.length).toBeLessThanOrEqual(IMAGE_MAX);
      const payload = newDevice({ deviceCode: `${stamp}img3`, images: [url] });
      const res = await postDevice(payload);
      expect(res.status).toBeLessThan(400);
      const raw = await rawDevice(payload.deviceCode);
      expect(raw.images).toEqual([url]);
    });

    test('update 链不带 images 规则 ⇒ 本批改动不得让更新路径改变行为', async () => {
      const created = await FireDevice.create(newDevice({ deviceCode: `${stamp}img4` }));
      const res = await request(app)
        .put(`/api/devices/${created._id}`)
        .set(auth(superToken))
        .send({ remark: 'ok' });
      expect(res.status).toBeLessThan(400);
    });
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
