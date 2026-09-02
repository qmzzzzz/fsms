/**
 * P1-2 回归：改密接口对非字符串 currentPassword 必须返回 400 而非 500
 *
 * 背景（实测事故）：express-validator 的 notEmpty/isLength/matches 在校验前会把
 * 入参强制转成字符串，`{}` → `[object Object]` 能通过全部校验，但 req.body 中的
 * 原值仍是对象。该对象直达 bcrypt.compare 时抛 TypeError（异步拒绝），
 * 冒泡到全局错误兜底 → 500。虽然生产环境不外泄堆栈，但：
 * - 500 与 400 的区分本身就是可探测的信号（攻击者据此确认参数进入了加密层）
 * - 未处理异常会污染错误监控、掩盖真实故障
 *
 * 两道防线各自独立断言：
 * 1. 路由校验层：body('currentPassword').isString() 前置 → 400 数据验证失败
 * 2. 模型层纵深防御：User.comparePassword 类型守卫 → 返回 false 而非抛错
 *    （改密/登录/MFA 多个调用点共用该方法，不能只靠单条路由的校验器）
 */

const request = require('supertest');
const mongoose = require('mongoose');
const { passwordChangeLimiter } = require('../../middleware/rateLimit');

describe('P1-2 改密接口非字符串入参防护', () => {
  let app;
  let User;
  let user;
  let token;
  // 夹具口令须避开 BREACHED_PASSWORDS 黑名单（G8）
  const PASSWORD = 'Qz7#Lm42vTx9';

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const jwt = require('jsonwebtoken');
    User = require('../../models/User');

    user = await User.create({
      username: 'pwdtype_user',
      email: 'pwdtype_user@example.com',
      password: PASSWORD,
    });

    token = jwt.sign(
      { userId: String(user._id), username: 'pwdtype_user', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // S4：两个改密端点均挂凭据型 passwordChangeLimiter（5 次/15 分钟，
  // userId+IP 组合键、成功请求同样计数）。本文件的类型守卫用例会对同一
  // 用户连发请求，每例前先清零计数，否则第 6 次起命中 429 而非被测的 400
  beforeEach(async () => {
    for (const ip of ['::ffff:127.0.0.1', '127.0.0.1', '::1']) {
      await passwordChangeLimiter.resetKey(`pwd-change:${String(user._id)}:${ip}`);
    }
  });

  // 非字符串入参谱系：对象是最危险的一类（能通过隐式转字符串的全部校验）
  const NON_STRING_CASES = [
    ['空对象', {}],
    ['带键对象', { $ne: null }],
    ['数组', ['a']],
    ['数字', 12345678],
    ['布尔', true],
  ];

  describe('PUT /api/auth/password（passwordChangeLimiter，用例前已重置计数）', () => {
    const changePassword = (currentPassword) =>
      request(app)
        .put('/api/auth/password')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword, newPassword: 'Nw9$Kd71bRx2' });

    test.each(NON_STRING_CASES)('currentPassword 为%s → 400 而非 500', async (_label, value) => {
      const res = await changePassword(value);
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      // 500 意味着异常穿透到了 bcrypt 层
      expect(res.status).not.toBe(500);
    });

    test('newPassword 为对象同样 400（不进入强度校验的正则分支）', async () => {
      const res = await request(app)
        .put('/api/auth/password')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: PASSWORD, newPassword: {} });
      expect(res.status).toBe(400);
    });

    test('合法字符串但密码错误 → 400（与类型错误同码，不产生可区分信号）', async () => {
      const res = await changePassword('WrongPass@123');
      expect(res.status).toBe(400);
    });
  });

  describe('PUT /api/security/change-password（passwordChangeLimiter，5 次/窗口）', () => {
    test('currentPassword 为对象 → 400 而非 500', async () => {
      const res = await request(app)
        .put('/api/security/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: {}, newPassword: 'Nw9$Kd71bRx2', confirmPassword: 'Nw9$Kd71bRx2' });
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('User.comparePassword 类型守卫（纵深防御）', () => {
    test('非字符串候选口令返回 false，绝不抛 TypeError', async () => {
      const doc = await User.findById(user._id).select('+password');
      for (const value of [{}, [], 123, true, null, undefined, Buffer.from('x')]) {
        await expect(doc.comparePassword(value)).resolves.toBe(false);
      }
    });

    test('正确字符串口令仍正常匹配（守卫未破坏原有能力）', async () => {
      const doc = await User.findById(user._id).select('+password');
      await expect(doc.comparePassword(PASSWORD)).resolves.toBe(true);
      await expect(doc.comparePassword('wrong-password')).resolves.toBe(false);
    });

    test('文档未 select(+password) 时返回 false 而非抛错', async () => {
      // this.password 为 undefined，bcrypt.compare 同样会抛 TypeError
      const doc = await User.findById(user._id);
      expect(doc.password).toBeUndefined();
      await expect(doc.comparePassword(PASSWORD)).resolves.toBe(false);
    });
  });
});
