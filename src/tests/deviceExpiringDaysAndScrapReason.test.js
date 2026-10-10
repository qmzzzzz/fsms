/**
 * 两处「客户端显式提交的值被 `||` 当成没提交」的可证伪固化
 *
 * 一、`?days=` 到期窗口天数。两个 HTTP 入口此前各写一份
 * `Math.min(365, Math.max(1, parseInt(days,10) || 30))`，其中 `|| 30` 把 `?days=0`
 * 翻译成默认窗口：调用方要的是**最窄**窗口（"此刻已过期的那一刻"，用于对账/巡检收尾），
 * 拿回的却是 30 倍宽的集合，而且与完全不传参**返回同一份数据**，无从察觉。
 * 同类缺陷本仓已有判例并选择了另一侧：`alarmController` 的 `isTrueParam` 区分
 * "显式假值"与"未提交"。这里把判定收进 `normalizeExpiringDays`（见该函数注释），
 * 规则是"永不把请求放宽"：可解析整数原样采用（负数收到 0），不可解析回退默认，
 * 上界 365 仍钳制（收窄方向的资源护栏）。
 * 注意 `days=0` 的窗口在日历日语义下塌缩为单一时刻 ⇒ 结果必然为空集；
 * 断言因此写成"请求越窄，集合真越窄"（严格子集链）而不是"0 天能查到一台"。
 *
 * 二、`PUT /api/devices/:id/scrap` 的 `scrapReason`。路由校验是
 * `mustBeString` + `optional().trim().isLength({max:200})`，**没有 `notEmpty`**，
 * 所以 `{"scrapReason": ""}` 是一次合法的 200 写入；原 `reason || '正常报废'`
 * 把它和"根本没填这个字段"折叠成同一句肯定性结论"正常报废"（= 到寿正常处置），
 * 于是台账里凭空多出一条操作者从未声明过的合规判定——报废原因是消防合规的
 * 追溯字段，"没写"必须和"写了正常报废"可区分。`??` 只兜 undefined/null。
 * 模型层的实例方法 `FireDevice.methods.scrapped` 是同一条规则的第二个出口
 * （目前只被测试调用，但两处必须同口径，否则日后接线时会静默分叉）。
 *
 * 三态矩阵的对照臂：`days=1` / `days=5` / `days=30` 的命中集必须是严格递增的
 * 子集链（挡住"窗口恒空"这一侧的假绿），`days` 缺省必须等于 `days=30`
 * （挡住"把回退改成不传=0"这一侧的过度收窄）。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

const { normalizeExpiringDays, DEFAULT_EXPIRING_DAYS } = require('../constants/deviceAlerts');

const stamp = `ZZB${Date.now().toString(36)}`.toUpperCase().replace(/[^A-Z0-9]/g, '');

/** 到期日相对"现在"的日历日偏移：每个偏移一台，用 deviceCode 反查归属 */
const OFFSETS = [1, 5, 29, 31, 300, 400];
const codeFor = (days) => `${stamp}_D${String(days).padStart(3, '0')}`;
const ALL_CODES = OFFSETS.map(codeFor);

describe('到期窗口天数归一：客户端的 0 不得被翻译成默认值', () => {
  test('可解析整数原样采用，0 与"未传"绝不落进同一格', () => {
    expect(DEFAULT_EXPIRING_DAYS).toBe(30);
    expect(normalizeExpiringDays('0')).toBe(0);
    expect(normalizeExpiringDays(0)).toBe(0);
    expect(normalizeExpiringDays('12')).toBe(12);
    // 这条就是缺陷本体：折叠时两侧同形，修好后必须可区分
    expect(normalizeExpiringDays('0')).not.toBe(normalizeExpiringDays(undefined));
  });

  test('收窄方向有下界 0、放宽方向有上界 365', () => {
    expect(normalizeExpiringDays(-5)).toBe(0);
    expect(normalizeExpiringDays('-10')).toBe(0);
    expect(normalizeExpiringDays(9999)).toBe(365);
    expect(normalizeExpiringDays('9999')).toBe(365);
  });

  test('不可解析回退默认窗口（与 securityController 的 days/limit 钳制同口径）', () => {
    expect(normalizeExpiringDays(undefined)).toBe(30);
    expect(normalizeExpiringDays(null)).toBe(30);
    expect(normalizeExpiringDays('')).toBe(30);
    expect(normalizeExpiringDays('abc')).toBe(30);
    expect(normalizeExpiringDays({})).toBe(30);
    // 回退值可由调用方指定，说明它是"默认"而不是硬编码 30
    expect(normalizeExpiringDays('abc', 7)).toBe(7);
  });
});

describe('到期窗口按请求收窄（服务层 + 两个 HTTP 入口）与报废原因空串', () => {
  let app;
  let FireDevice;
  let deviceService;
  let adminToken;

  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`),
    post: (url) => request(app).post(url).set('Authorization', `Bearer ${adminToken}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${adminToken}`),
  });

  const now = () => new Date();
  const inDays = (days) => {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString();
  };

  /** 只在自己的子集里判定：本库按 worker 共享，全库计数必然被别的套件污染 */
  const expiringCodes = (days) =>
    deviceService.getExpiringDevices(days, { deviceCode: { $in: ALL_CODES } });
  const kept = (docs) => docs.map((d) => d.deviceCode).sort();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../models/User');
    const Role = require('../models/Role');
    const Permission = require('../models/Permission');
    FireDevice = require('../models/FireDevice');
    deviceService = require('../services/DeviceService');
    require('../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: `超管_窗口_${stamp}`,
      code: `SUPER_ADMIN_WIN_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `winadmin${stamp}`.toLowerCase(),
      email: `winadmin${stamp.toLowerCase()}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../app');
    app = createApp();

    for (const days of OFFSETS) {
      const createRes = await authed()
        .post('/api/devices')
        .send({
          deviceCode: codeFor(days),
          deviceName: `灭火器_窗口_${days}`,
          deviceType: 'extinguisher',
          installDate: now().toISOString(),
          expiryDate: inDays(days),
          location: { building: 'B栋', floor: '1F', detail: `窗口${days}` },
        });
      expect(createRes.status).toBe(201);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({ deviceCode: { $in: ALL_CODES } }).catch(() => {});
      const User = require('../models/User');
      const Role = require('../models/Role');
      await User.deleteOne({ username: `winadmin${stamp}`.toLowerCase() }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_WIN_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('子集链：窗口越窄命中严格越少，缺省仍等于 30 天', async () => {
    const d0 = kept(await expiringCodes(0));
    const d1 = kept(await expiringCodes(1));
    const d5 = kept(await expiringCodes(5));
    const d30 = kept(await expiringCodes(30));

    // 每一档都必须"只少了该少的"：既挡住放宽（0 档拿回 30 档的集合），
    // 也挡住反向的过度收窄/窗口塌成空集（否则整条链全空照样通过）
    expect(d30).toEqual([codeFor(1), codeFor(5), codeFor(29)]);
    expect(d5).toEqual([codeFor(1), codeFor(5)]);
    expect(d1).toEqual([codeFor(1)]);
    expect(d0).toEqual([]);

    // 不可解析 → 回退默认，必须与显式 30 同形（缺省语义没被顺手改掉）
    expect(kept(await expiringCodes('abc'))).toEqual(d30);
    expect(kept(await expiringCodes(undefined))).toEqual(d30);
    expect(kept(await expiringCodes(-10))).toEqual(d0);
  });

  test('上界 365 是收窄方向的护栏：+300 在钳制窗口内，+400 不在', async () => {
    expect(kept(await expiringCodes(9999))).toEqual([
      codeFor(1),
      codeFor(5),
      codeFor(29),
      codeFor(31),
      codeFor(300),
    ]);
  });

  test('HTTP /devices/expiring：?days=0 不得把 +5 天的设备端回来，且不传参仍能查到', async () => {
    const narrow = await authed().get('/api/devices/expiring?days=0');
    expect(narrow.status).toBe(200);
    const narrowCodes = narrow.body.data
      .map((d) => d.deviceCode)
      .filter((c) => ALL_CODES.includes(c));
    expect(narrowCodes).toEqual([]);

    // 对照臂：同一条请求路径、同一个筛选，缺省窗口必须能看见 +5 那台。
    // 少了这一臂，上面那句"查不到"可能只是因为整条链路根本查不出东西。
    const wide = await authed().get('/api/devices/expiring');
    expect(wide.status).toBe(200);
    const wideCodes = wide.body.data.map((d) => d.deviceCode).filter((c) => ALL_CODES.includes(c));
    expect(wideCodes).toContain(codeFor(5));
  });

  test('HTTP /devices/reminders：同一份天数归一在第二个入口同样生效', async () => {
    const narrow = await authed().get('/api/devices/reminders?days=0');
    expect(narrow.status).toBe(200);
    expect(narrow.body.data.partial).toBeUndefined();
    const narrowCodes = narrow.body.data.expiringSoon
      .map((d) => d.deviceCode)
      .filter((c) => ALL_CODES.includes(c));
    expect(narrowCodes).toEqual([]);

    const wide = await authed().get('/api/devices/reminders');
    expect(wide.status).toBe(200);
    const wideCodes = wide.body.data.expiringSoon
      .map((d) => d.deviceCode)
      .filter((c) => ALL_CODES.includes(c));
    expect(wideCodes).toContain(codeFor(5));
    expect(wide.body.data.summary.expiringSoon).toBeGreaterThanOrEqual(1);
    // 截断可数的载体必须出得了 HTTP：服务层的 `limits` 若在这条链上丢掉，
    // 关于 truncated 的一切判据都只是进程内的自我安慰。
    // 这里只钉形状不钉真假值：本用例走缺省上限 200，而库里有多少台在跑的其它套件留下的
    // 设备取决于 worker 分库的串行顺序，真值断言会变成随执行顺序漂移的随机数。
    expect(Object.keys(wide.body.data.limits).sort()).toEqual(['resultLimit', 'truncated']);
    expect(wide.body.data.limits.resultLimit).toBe(200);
    expect(Object.keys(wide.body.data.limits.truncated).sort()).toEqual([
      'expired',
      'expiringSoon',
      'needMaintenance',
      'needSchedule',
      'total',
    ]);
  });
});

describe('报废原因：空串是"提交了但没填"，不是"正常报废"', () => {
  let app;
  let FireDevice;
  let adminToken;

  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`),
    post: (url) => request(app).post(url).set('Authorization', `Bearer ${adminToken}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${adminToken}`),
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../models/User');
    const Role = require('../models/Role');
    const Permission = require('../models/Permission');
    FireDevice = require('../models/FireDevice');
    require('../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: `超管_报废_${stamp}`,
      code: `SUPER_ADMIN_SCRAP_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `scrapadmin${stamp}`.toLowerCase(),
      email: `scrapadmin${stamp.toLowerCase()}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../models/User');
      const Role = require('../models/Role');
      await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp}_`) }).catch(() => {});
      await User.deleteOne({ username: `scrapadmin${stamp}`.toLowerCase() }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_SCRAP_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  /** 每次报废都要一台独立设备：scrapped → scrapped 是非法迁移（P2-16） */
  const createDevice = async (tag) => {
    const createRes = await authed()
      .post('/api/devices')
      .send({
        deviceCode: `${stamp}_S${tag}`,
        deviceName: `烟感_报废_${tag}`,
        deviceType: 'smoke_detector',
        installDate: new Date().toISOString(),
        location: { building: 'C栋', floor: '2F', detail: `报废${tag}` },
      });
    expect(createRes.status).toBe(201);
    return String(createRes.body.data._id || createRes.body.data.id);
  };

  const readBack = async (id) => FireDevice.findById(id).lean();

  test('显式空串原样落库，响应与台账都不出现"正常报废"', async () => {
    const id = await createDevice('EMPTY');
    const res = await authed().put(`/api/devices/${id}/scrap`).send({ scrapReason: '' });
    expect(res.status).toBe(200);

    const doc = await readBack(id);
    expect(doc.status).toBe('scrapped');
    expect(doc.scrapReason).toBe('');
    expect(doc.scrapReason).not.toBe('正常报废');
  });

  test('字段缺省仍得到"正常报废"——收紧不能把既有默认一起改掉', async () => {
    const id = await createDevice('OMIT');
    const res = await authed().put(`/api/devices/${id}/scrap`).send({});
    expect(res.status).toBe(200);

    const doc = await readBack(id);
    expect(doc.scrapReason).toBe('正常报废');
  });

  test('写了原因照常原样入库（两分支之外的主干不能被碰坏）', async () => {
    const id = await createDevice('TEXT');
    const res = await authed()
      .put(`/api/devices/${id}/scrap`)
      .send({ scrapReason: '到期送检不合格' });
    expect(res.status).toBe(200);
    expect((await readBack(id)).scrapReason).toBe('到期送检不合格');
  });

  test('模型实例方法是同一条规则的第二出口，三态与 HTTP 路径同口径', async () => {
    const draft = (tag) =>
      new FireDevice({
        deviceCode: `${stamp}_M${tag}`,
        deviceName: `烟感_实例方法_${tag}`,
        deviceType: 'smoke_detector',
        installDate: new Date(),
        location: { building: 'C栋', floor: '2F', detail: `实例方法${tag}` },
      });

    const blank = draft('EMPTY');
    await blank.scrapped('');
    const omitted = draft('OMIT');
    await omitted.scrapped();
    const written = draft('TEXT');
    await written.scrapped('破损');

    expect([blank.scrapReason, omitted.scrapReason, written.scrapReason]).toEqual([
      '',
      '正常报废',
      '破损',
    ]);

    // 落库侧再确认一遍：内存里赋对了、却被 schema default/中间件改写是同一类缺陷
    const stored = await FireDevice.find({
      deviceCode: { $in: [blank.deviceCode, omitted.deviceCode, written.deviceCode] },
    }).lean();
    const byTag = Object.fromEntries(
      stored.map((d) => [d.deviceCode.replace(`${stamp}_M`, ''), d.scrapReason])
    );
    expect(byTag).toEqual({ EMPTY: '', OMIT: '正常报废', TEXT: '破损' });
  });
});
