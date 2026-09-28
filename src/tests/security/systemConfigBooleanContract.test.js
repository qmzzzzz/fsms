'use strict';

/**
 * 三个全局安全开关的写入契约与读回一致性
 * （allowPublicRegistration / loginCaptchaEnabled / registerCaptchaEnabled）
 *
 * 这三道闸决定"公开注册是否开着""登录/注册是否要图形验证码"，都是**鉴权面**的开关，
 * 但仓库里此前一条用例都没有：把控制器里的 `typeof x !== 'boolean'` 守卫整段删掉，
 * 全套测试仍然绿。
 *
 * 为什么字符串必须被拒（而不是被转换）：`SystemConfig.value` 是 Mixed，
 * 写入侧一旦放过 `'false'`，读侧 `toConfigBoolean` 虽有兜底，但 `valueType` 会被记成
 * 'string'，配置页与运维脚本对"这是不是一个布尔开关"的判断就此失真。
 * 写入边界按 `typeof` 收死、并给出**字段专属**错误码，是这三条路由的真实契约。
 *
 * 第二条断言打的是缓存失效：先 GET 把 30s 缓存预热成旧值，再 PUT 相反值，再 GET。
 * 少调一次 `invalidate*Cache` ⇒ 第二次 GET 仍回旧值 ⇒ 这里红。
 *
 * 契约的**唯一**执行点在控制器（`typeof x !== 'boolean'` + 字段专属码，前端 api.js
 * 为这三个码各有一条 i18n）。这三条路由此前还各挂着一个从不消费的
 * `body(...).isBoolean()`——纯装饰，且一旦有人补上 consumeValidation() 就会把
 * 专属码压成通用 VALIDATION_FAILED，故随本用例一并移除。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `scb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

const SWITCHES = [
  {
    field: 'allowPublicRegistration',
    path: '/api/security/config/allowPublicRegistration',
    code: 'CONFIG_ALLOW_REGISTRATION_MUST_BE_BOOLEAN',
  },
  {
    field: 'loginCaptchaEnabled',
    path: '/api/security/config/loginCaptchaEnabled',
    code: 'CONFIG_LOGIN_CAPTCHA_MUST_BE_BOOLEAN',
  },
  {
    field: 'registerCaptchaEnabled',
    path: '/api/security/config/registerCaptchaEnabled',
    code: 'CONFIG_REGISTER_CAPTCHA_MUST_BE_BOOLEAN',
  },
];

/** 这些形态都不是布尔：必须被写入边界挡下，且库里/读回都不得留下痕迹 */
const NON_BOOLEANS = ['false', '0', 'true', 0, 1, null, undefined, {}, []];

describe('安全开关写入契约（非布尔一律拒）+ 读回一致', () => {
  let app;
  let token;
  let SystemConfig;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    SystemConfig = require('../../models/SystemConfig');

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
    const op = await User.create({
      username: `scbop${stamp}`,
      email: `scbop${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    token = jwt.sign(
      { userId: String(op._id), username: op.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      await User.deleteMany({ username: `scbop${stamp}` }).catch(() => {});
      await SystemConfig.deleteMany({ key: { $in: SWITCHES.map((s) => s.field) } }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const put = (path, body) =>
    request(app).put(path).set('Authorization', `Bearer ${token}`).send(body);
  const get = (path) => request(app).get(path).set('Authorization', `Bearer ${token}`);

  test.each(SWITCHES.map((s) => ({ ...s, title: s.field })))(
    '$field：写入非布尔一律 400，且不落库',
    async ({ field, path, code }) => {
      // 先写一个已知的真值，才能验证"被拒的写入确实什么都没改"
      const ok = await put(path, { [field]: true });
      expect(ok.status).toBe(200);

      for (const bad of NON_BOOLEANS) {
        const res = await put(path, { [field]: bad });
        expect(res.status).toBe(400);
        // 字段专属错误码（不是笼统的 VALIDATION_FAILED）：前端提示语依赖它
        expect(res.body.errors.errorCode).toBe(code);
      }

      const doc = await SystemConfig.findOne({ key: field }).lean();
      expect(doc.value).toBe(true);
      expect(doc.valueType).toBe('boolean');
      const readBack = await get(path);
      expect(readBack.status).toBe(200);
      expect(readBack.body.data[field]).toBe(true);
    }
  );

  test.each(SWITCHES.map((s) => ({ ...s, title: s.field })))(
    '$field：翻转后 GET 必须读到新值（缓存失效真的发生了）',
    async ({ field, path }) => {
      await put(path, { [field]: true });
      const warm = await get(path);
      expect(warm.body.data[field]).toBe(true); // 预热：把 30s 缓存填成 true

      const flip = await put(path, { [field]: false });
      expect(flip.status).toBe(200);

      const after = await get(path);
      expect(after.body.data[field]).toBe(false);

      // 再翻回来，两个方向都要立刻可见
      await put(path, { [field]: true });
      expect((await get(path)).body.data[field]).toBe(true);
    }
  );

  test('反向前提：三条用例不是"所有写入都 400"造成的假绿', async () => {
    // 上面第一条里 400 断言密集，若路由本身鉴权/路径配错，8 个非布尔全 400 也会"通过"。
    // 这里要求同一路径的**合法**写入返回 200，且落库值与请求一致。
    for (const s of SWITCHES) {
      const res = await put(s.path, { [s.field]: false });
      expect(res.status).toBe(200);
      expect(res.body.data[s.field]).toBe(false);
      const doc = await SystemConfig.findOne({ key: s.field }).lean();
      expect(doc.value).toBe(false);
    }
  });

  test('默认值契约：库中无该键时，注册验证码必须回落到【开启】', async () => {
    // 本文件原有两条用例**抓不到**这一格：它们先 `PUT {field:true}` 建了 doc，
    // 因此永远走不到 fallback 分支。而真实缺陷恰在 fallback ——
    // `registerCaptchaEnabled` 曾被写在 `config.rateLimit` 子对象里，三处读取方
    // （authService.js:118 / authController.js:128 / SystemConfig.js:207）
    // 读的都是**顶层** ⇒ 恒为 undefined ⇒ toConfigBoolean(undefined,false) === false
    // ⇒ 注册接口的图形验证码被静默关闭；而 initData 从不播种该键，
    // 所以全新部署必然走这条 fallback，与四处"默认开启/默认强校验"的声明全部相反。
    //
    // 断言写成 env 无关形式：期望值由 env 规则本身推出，因此无论 CI 是否设置
    // REGISTER_CAPTCHA_ENABLED，位置写错（拿到 undefined）都会红。
    const expected = process.env.REGISTER_CAPTCHA_ENABLED !== 'false';

    // ① 位置契约：该键必须能被**顶层**读到，且不许再出现在限流子对象里
    const cfg = require('../../config');
    expect(cfg.registerCaptchaEnabled).toBe(expected);
    expect(cfg.rateLimit.registerCaptchaEnabled).toBeUndefined();

    // ② 行为契约：库中无 doc 时必须回落到同一结论（这才是调用方真正消费的语义）
    await SystemConfig.deleteMany({ key: 'registerCaptchaEnabled' });
    SystemConfig.invalidateRegisterCaptchaCache();
    await expect(SystemConfig.isRegisterCaptchaEnabled()).resolves.toBe(expected);
  });
});
