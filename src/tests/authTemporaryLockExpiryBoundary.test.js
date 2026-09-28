'use strict';

/**
 * 临时锁定的**双向**边界（成对用例）
 *
 * 被测判据：`auth.js` 的 `assertAccountUsable` 里
 *   if (freshUser.lockUntil && freshUser.lockUntil > new Date()) → ACCOUNT_TEMP_LOCKED
 *
 * 既有套件 `authMiddlewareFailClosedGuards.test.js` 只钉了"未到期 ⇒ 401"这一侧。
 * 变异实测（v2 全量跑尺，src/middleware/auth.js）证明这半边无人设防：
 *   把 `&&` 改成 `||`（即"只要 lockUntil 字段存在就锁"）⇒ 全套用例仍绿。
 * 也就是**过期锁定永不自解**：用户被临时锁定一次之后，只要那条 `lockUntil` 还留在文档上，
 * 就只能等管理员手工解锁——而"到点自动解锁"正是这个字段的唯一存在理由。
 *
 * 所以本文件补第二侧：过期时间戳必须放行。两条用例互为对照，
 * 单留任何一条都会退化成"只证明代码在跑，不证明判据在判"。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('临时锁定到期必须自动放行（与"未到期拦截"成对）', () => {
  let User;
  let app;
  let auth;
  const PASSWORD = randomPassword();
  const stamp = `lx${Date.now()}`.replace(/\D/g, '');
  const users = {};

  const makeUser = async (name, update = {}) => {
    const user = await User.create({
      username: `${stamp}${name}`,
      email: `${stamp}${name}@example.com`,
      password: PASSWORD,
    });
    if (Object.keys(update).length > 0) await User.findByIdAndUpdate(user._id, update);
    users[name] = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../models/User');
    auth = require('../middleware/auth');
    await makeUser('expired', { lockUntil: new Date(Date.now() - 60 * 1000) });
    await makeUser('active', { lockUntil: new Date(Date.now() + 3600 * 1000) });
    const { createApp } = require('../app');
    app = createApp();
    auth.invalidateUserCache();
  });

  afterAll(async () => {
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    auth.invalidateUserCache();
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const getMe = (token) => request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);

  test('对照：lockUntil 未到期 ⇒ 401 临时锁定（保证下面那条不是因为判据没生效而绿）', async () => {
    const res = await getMe(users.active);
    expect(res.status).toBe(401);
    expect(res.body.message).toContain('临时锁定');
  });

  test('lockUntil 已过期 ⇒ 必须放行（`&&`→`||` 变异会把这条打红：过期锁永不自解）', async () => {
    auth.invalidateUserCache();
    const res = await getMe(users.expired);
    expect(res.status).toBe(200);
    expect(res.body.message).not.toContain('临时锁定');
  });
});
