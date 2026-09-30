'use strict';

/**
 * body 字段的「非字符串」闸门（写路径全谱）
 *
 * 根因（express-validator 7.3.2，已用独立探针逐值实测）：链上校验器拿到的是
 * `String(value)` 之后的值，且 `.trim()` 这类 sanitizer 会把强转结果写回 `req.body`。
 * 于是本仓最常见的可选文本字段写法
 *     body('department').optional().trim().isLength({ max: 100 })
 * 对 `{"department": {}}` 全程零报错——`'[object Object]'`（16 字符）满足 max:100，
 * 接口回 200，脏字符串原样落库。数字/布尔同理（`123` ⇒ `'123'`）。
 * 只有 `.isString()` 能挡住，且必须排在受保护的链之前：一旦前序链的 sanitizer 先跑，
 * 后面的 `.isString()` 看到的就是字符串，闸门形同装饰。
 *
 * 判据（每条都可证伪，不靠状态码猜）：
 *   · 非字符串 ⇒ 400，且 `errors.fieldErrors` 点名该字段、文案是闸门自己的那句
 *     （不是 DB 层泄漏过来的 `CastError` 通用文案，那条路径下 fieldErrors 为空）；
 *   · 拒绝之后回读数据库 ⇒ 什么都没写、原值没变；
 *   · 反向对照 ⇒ 合法字符串照旧放行；显式 `null`/缺字段/空串**不得**被闸门误伤
 *     （存量文档里这些字段可能就是 null，前端回填后 PUT 会被打回）。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { decryptPii } = require('../../utils/piiCrypto');

const stamp = `btg${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();
/** 各链都会把该值 stringify 成 16 字符，足以通过 max:50~1000 的长度约束 */
const POLLUTED = '[object Object]';

describe('写路径的 body 类型闸门', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let FireDevice;
  let Inspection;
  let superToken;
  let superId;

  const auth = (token) => ({ Authorization: `Bearer ${token}` });
  const msgs = (res) => (res.body?.errors?.fieldErrors || []).map((e) => `${e.path}=${e.msg}`);

  const tokenFor = (userId, username) =>
    jwt.sign({ userId: String(userId), username, tokenVersion: 0 }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

  /**
   * 闸门给出的那句错（不是长度文案、不是 DB 泄漏）。
   * 通配符字段的错误 path 按实际下标回显（`findings.*.issue` ⇒ `findings[0].issue`），
   * 比对前先把下标归一回 `.*`。
   */
  const gateFired = (res, field, label) =>
    msgs(res).some((s) => {
      const at = s.indexOf('=');
      const path = s.slice(0, at).replace(/\[\d+\]/g, '.*');
      return path === field && s.slice(at + 1) === `${label}必须为字符串`;
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    Inspection = require('../../models/Inspection');
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
    superId = String(operator._id);
    superToken = tokenFor(operator._id, operator.username);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`^${stamp}`) }).catch(() => {});
      await Permission.deleteMany({ code: new RegExp(`^${stamp}`) }).catch(() => {});
      await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp}`) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const makeDevice = async (label) =>
    FireDevice.create({
      deviceCode: `${stamp}dc${label}`,
      deviceName: `${stamp}设备${label}`,
      deviceType: 'extinguisher',
      building: 'A栋',
      // installDate 在模型里是 required（FireDevice 的 schema），缺了它连夹具都建不起来
      installDate: new Date(),
    });

  const makeInspection = async (label) =>
    Inspection.create({
      title: `${stamp}insp${label}`,
      inspectionType: 'daily',
      planStartTime: new Date(Date.now() - 3600_000),
      planEndTime: new Date(Date.now() + 3600_000),
      createdBy: superId,
    });

  describe('POST /users 的 department（可选文本，脏值今天会直接落库）', () => {
    // 每条用例自己的用户名：否则"脏值今天居然建成功了"会让后面的用例撞上唯一索引，
    // 失败原因从"闸门缺失"变成"409 重名"，红就红得不成立
    const post = (body, tag = 'x') =>
      request(app)
        .post('/api/users')
        .set(auth(superToken))
        .send({
          username: `${stamp}u${tag}`,
          email: `${stamp}u${tag}@example.com`,
          password: PASSWORD,
          ...body,
        });

    test('1 对象值必须被闸门点名拒绝', async () => {
      const res = await post({ department: {} }, 'a');
      expect(gateFired(res, 'department', '部门')).toBe(true);
      expect(res.status).toBe(400);
    });

    test('2 闸门未放行 ⇒ 库里没有这个用户，也没有 [object Object]', async () => {
      const res = await post({ department: {} }, 'b');
      // 今天这里拿到的是 201 + department === '[object Object]'：
      // 长度约束被 stringify 绕过，脏值原样落库
      expect(res.status).toBe(400);
      expect(await User.countDocuments({ username: `${stamp}ub` })).toBe(0);
      expect(await User.findOne({ department: POLLUTED }).lean()).toBeNull();
    });

    test('3 反向对照：合法字符串仍然建得成，部门逐字入库', async () => {
      const res = await post({ department: '安全部' }, 'c');
      expect(msgs(res)).toEqual([]);
      expect(res.status).toBe(201);
      const doc = await User.findOne({ username: `${stamp}uc` }).lean();
      expect(doc.department).toBe('安全部');
    });

    test('4 显式 null / 缺字段 / 空串不得被闸门误伤（前端回填 null 的回归护栏）', async () => {
      for (const [tag, value] of [
        ['d', null],
        ['e', ''],
        ['f', undefined],
      ]) {
        const res = await post({ department: value }, tag);
        expect(gateFired(res, 'department', '部门')).toBe(false);
        expect(res.status).toBe(201);
      }
    });
  });

  describe('PUT /users/:id 的 realName', () => {
    test('5 数组/数字/布尔值同样点名拒绝，且原值不变', async () => {
      const target = await User.create({
        username: `${stamp}t`,
        email: `${stamp}t@example.com`,
        password: PASSWORD,
        realName: '原名',
      });
      for (const bad of [['a', 'b'], 12345, true]) {
        const res = await request(app)
          .put(`/api/users/${target._id}`)
          .set(auth(superToken))
          .send({ realName: bad });
        expect(gateFired(res, 'realName', '姓名')).toBe(true);
        expect(res.status).toBe(400);
      }
      // P1-②：库内是密文（lean 不走 getter）——"原值不变"按解密后的口径断言
      const doc = await User.findById(target._id).lean();
      expect(decryptPii(doc.realName)).toBe('原名');
    });
  });

  describe('设备写路径（create + update）', () => {
    test('6 POST /devices 的 remark 对象值 ⇒ 400 点名，且设备未创建', async () => {
      const res = await request(app)
        .post('/api/devices')
        .set(auth(superToken))
        .send({
          deviceCode: `${stamp}new`,
          deviceName: `${stamp}新设备`,
          deviceType: 'extinguisher',
          remark: {},
        });
      expect(gateFired(res, 'remark', '备注')).toBe(true);
      expect(res.status).toBe(400);
      expect(await FireDevice.countDocuments({ deviceCode: `${stamp}new` })).toBe(0);
    });

    test('7 PUT /devices/:id 的 floor 数字值 ⇒ 400 点名（不得静默存成 "3"）', async () => {
      const dev = await makeDevice('floor');
      const res = await request(app)
        .put(`/api/devices/${dev._id}`)
        .set(auth(superToken))
        .send({ floor: 3 });
      expect(gateFired(res, 'floor', '楼层')).toBe(true);
      const doc = await FireDevice.findById(dev._id).lean();
      expect(String(doc.floor ?? '')).not.toBe('3');
    });
  });

  describe('报警上报与处理', () => {
    test('8 POST /alarms/report 的 description 对象值 ⇒ 400 点名，报警未落库', async () => {
      const before = await FireDevice.countDocuments({});
      const res = await request(app)
        .post('/api/alarms/report')
        .set(auth(superToken))
        .send({ alarmType: 'smoke', description: {} });
      expect(gateFired(res, 'description', '报警描述')).toBe(true);
      expect(res.status).toBe(400);
      expect(await FireDevice.countDocuments({})).toBe(before);
    });

    test('9 PUT /alarms/:id/resolve 的 handleResult 数组值 ⇒ 400 点名', async () => {
      const dev = await makeDevice('alarm');
      const created = await request(app)
        .post('/api/alarms/report')
        .set(auth(superToken))
        .send({ alarmType: 'smoke', description: '真实描述', deviceId: String(dev._id) });
      const id = created.body?.data?._id || created.body?.data?.alarm?._id;
      if (!id) {
        // 上报本身失败时不做断言的前提：把真实响应摊开，避免"跳过即通过"的假绿
        throw new Error(`报警上报未成功，无法测 resolve：${JSON.stringify(created.body)}`);
      }
      const res = await request(app)
        .put(`/api/alarms/${id}/resolve`)
        .set(auth(superToken))
        .send({ handleResult: ['已处理'] });
      expect(gateFired(res, 'handleResult', '处理结果描述')).toBe(true);
    });
  });

  describe('巡检写路径（含 findings 通配符字段）', () => {
    test('10 POST /inspections 的 title 对象值 ⇒ 400 点名，巡检未创建', async () => {
      const res = await request(app)
        .post('/api/inspections')
        .set(auth(superToken))
        .send({ title: {}, inspectionType: 'daily' });
      expect(gateFired(res, 'title', '巡检标题')).toBe(true);
      expect(await Inspection.countDocuments({ title: POLLUTED })).toBe(0);
    });

    test('11 PUT /inspections/:id/complete 的 findings.*.issue 对象值 ⇒ 400 点名通配字段', async () => {
      const insp = await makeInspection('find');
      const res = await request(app)
        .put(`/api/inspections/${insp._id}/complete`)
        .set(auth(superToken))
        .send({ findings: [{ issue: { nested: 1 } }] });
      expect(gateFired(res, 'findings.*.issue', '问题描述')).toBe(true);
      const doc = await Inspection.findById(insp._id).lean();
      expect(doc.findings || []).toHaveLength(0);
    });
  });

  describe('权限模型写路径', () => {
    test('12 POST /roles 的 name 对象值 ⇒ 400 点名，角色未创建', async () => {
      const code = `${stamp}role`.toUpperCase();
      const res = await request(app)
        .post('/api/roles')
        .set(auth(superToken))
        .send({ name: {}, code, description: 'd' });
      expect(gateFired(res, 'name', '角色名称')).toBe(true);
      expect(await Role.countDocuments({ code })).toBe(0);
    });

    test('13 POST /permissions 的 module 数字值 ⇒ 400 点名，权限未创建', async () => {
      const res = await request(app)
        .post('/api/permissions')
        .set(auth(superToken))
        .send({
          name: `${stamp}权限`,
          code: `dev:${stamp.replace(/\D/g, '')}x`,
          type: 'api',
          module: 1,
        });
      expect(gateFired(res, 'module', '模块名')).toBe(true);
    });
  });

  describe('安全审计写路径', () => {
    test('14 POST /security/report 的 reason 对象值 ⇒ 400 点名', async () => {
      const res = await request(app)
        .post('/api/security/report')
        .set(auth(superToken))
        .send({ targetType: 'user', reason: {}, description: 'd' });
      expect(gateFired(res, 'reason', '原因')).toBe(true);
    });
  });

  describe('认证入口（登录用户名 / 口令形状）', () => {
    test('15 POST /auth/login 的数字口令 ⇒ 400 点名，不得冒到 bcrypt 变 500', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: `${stamp}op`, password: 12345678 });
      expect(gateFired(res, 'password', '密码')).toBe(true);
      expect(res.status).toBe(400);
    });

    // 反向对照必须"成功"，不能只"没被闸门打回"：原来写的是 [200,201,401]，
    // 而 401 恰恰是本用例要排除的误伤形态（口令被 sanitizer 改写、或闸门把字符串判成非法）
    // ⇒ 那条断言在任何口令都登不上的环境里也恒绿。钉成 200 + 拿到 token 才可证伪。
    test('16 反向对照：字符串口令不被闸门误伤，真实认证成功', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: `${stamp}op`, password: PASSWORD });
      expect(gateFired(res, 'password', '密码')).toBe(false);
      expect(res.status).toBe(200);
      expect(res.body.data.token).toBeTruthy();
    });

    test('17 PUT /auth/profile 的 avatar 对象值 ⇒ 400 点名', async () => {
      const res = await request(app)
        .put('/api/auth/profile')
        .set(auth(superToken))
        .send({ avatar: {} });
      expect(gateFired(res, 'avatar', '头像地址')).toBe(true);
    });
  });
});
