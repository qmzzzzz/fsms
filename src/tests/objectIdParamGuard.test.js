'use strict';

/**
 * P2-25 回归门禁：每个挂载了 :id / :userId 路由的子 Router 都必须真的被
 * `applyObjectIdParams` 注册过参数校验
 *
 * 背景（`middleware/validateObjectId.js` 文件头）：原实现用 `app.param('id', ...)`，
 * 而 Express 的参数回调**不向子 Router 传播** ⇒ 该校验一次都没执行过，
 * 非法 :id 一路走到 Mongoose 才抛 CastError。P2-25 改成逐个 router 注册。
 *
 * 为什么需要本用例：注册名单是 `app.js` 里手写的一个参数列表。
 * 新增一个资源路由（或给已有 router 加 :id 参数）时，**忘记把它加进名单不会有任何报错**——
 * 表现正是 P2-25 已经付过学费的那个形态：校验静默消失、错误形态从 400 退化成 500/CastError，
 * 而路由里那句 `param('id').isMongoId()` 看着还在（它没被 consume，形同装饰——
 * 这一点是我本次改动实测出来的：先前我以为"没消费校验链"就是缺陷，加了 consumeValidation()
 * 才发现真正生效的是这里的 param 处理器，它在路由链之前就把请求拒掉了）。
 *
 * 因此本用例**不写死路由清单**：从 Express 路由器自身枚举出所有带 :id/:userId 的路由，
 * 逐条真发请求，要求返回 `PARAM_MUST_BE_VALID_OBJECT_ID`。
 * 新加一条 :id 路由却忘了注册 ⇒ 这里立刻红。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

const BAD_ID = 'not-an-objectid';
const MOUNTED = {
  '/api/users': () => require('../routes/userRoutes'),
  '/api/roles': () => require('../routes/roleRoutes'),
  '/api/permissions': () => require('../routes/permissionRoutes'),
  '/api/devices': () => require('../routes/deviceRoutes'),
  '/api/alarms': () => require('../routes/alarmRoutes'),
  '/api/inspections': () => require('../routes/inspectionRoutes'),
  '/api/reports': () => require('../routes/reportRoutes'),
  '/api/security': () => require('../routes/securityRoutes'),
};

/** 递归收集一个 router 里所有含 :id / :userId 的 (method, path) */
const collectIdRoutes = (router, out) => {
  for (const layer of router.stack || []) {
    if (layer.route) {
      const path = layer.route.path;
      if (/:(id|userId)\b/.test(path)) {
        for (const method of Object.keys(layer.route.methods)) out.push({ method, path });
      }
      continue;
    }
    // 嵌套 router（layer.handle 自带 stack）继续下钻，避免漏登记
    if (layer.handle && Array.isArray(layer.handle.stack)) collectIdRoutes(layer.handle, out);
  }
  return out;
};

describe('zzqoder P2-25 参数校验注册门禁', () => {
  let app;
  let token;
  const stamp = `p225${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../models/User');
    const Role = require('../models/Role');
    const Permission = require('../models/Permission');

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
    const u = await User.create({
      username: `p225super${stamp}`,
      email: `p225super${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    token = jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // createApp() 里才会执行 applyObjectIdParams(...)，先建 app 再检查各 router 的注册状态
    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    const User = require('../models/User');
    await User.deleteMany({ username: new RegExp(`^p225super${stamp}`) });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const cases = [];
  for (const [mount, load] of Object.entries(MOUNTED)) {
    const router = load();
    for (const r of collectIdRoutes(router, [])) {
      cases.push({ mount, router, ...r });
    }
  }

  test('枚举本身有效：至少覆盖到 20 条带 :id 的路由（防枚举失效导致空集恒绿）', () => {
    expect(cases.length).toBeGreaterThanOrEqual(20);
  });

  test('名单一致：所有含 :id 路由的 router 都注册了 id 参数处理器', () => {
    for (const load of Object.values(MOUNTED)) {
      const router = load();
      const hasIdRoute = collectIdRoutes(router, []).length > 0;
      const registered = Object.keys(router.params || {});
      if (hasIdRoute) expect(registered).toContain('id');
    }
  });

  test.each(cases.map((c) => ({ ...c, title: `${c.method.toUpperCase()} ${c.mount}${c.path}` })))(
    '$title ⇒ 非法 id 必须被参数校验挡下',
    async (c) => {
      const url = `${c.mount}${c.path.replace(':id', BAD_ID).replace(':userId', BAD_ID)}`;
      const res = await request(app)[c.method](url).set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(400);
      expect(res.body?.errors?.errorCode).toBe('PARAM_MUST_BE_VALID_OBJECT_ID');
    }
  );

  test('反向前提：合法格式的 id 不会被这道门误伤（否则上面全红也"通过"）', async () => {
    const ghost = new mongoose.Types.ObjectId();
    const url = `/api/roles/${ghost}`;
    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);
    expect(res.body?.errors?.errorCode).not.toBe('PARAM_MUST_BE_VALID_OBJECT_ID');
    // 走到业务层才给出的"不存在"：证明上面那批 400 不是"所有请求都 400"造成的假绿
    expect(res.body?.errors?.errorCode).toBe('ROLE_NOT_FOUND');
  });
});
