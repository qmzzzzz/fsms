'use strict';

/**
 * 锁定/解锁接口的布尔边界（PUT /api/security/users/:userId/lock）
 *
 * 缺陷形态：`isBoolean()` 放行字符串 `'false'`/`'0'`（validator 先 String() 再判），
 * 而 `authService.setUserLockStatus` 按 truthy 分派两态（`locked ? 'locked' : 'active'`），
 * 于是一条 `{"locked":"false"}` 的**解锁**请求会把账户锁上——而且 `!locked` 那两组
 * 状态保护（INACTIVE_UNLOCK / NOT_LOCKED）被一并跳过，连拒绝都不会给。
 * 修法是在链尾收一次 `.toBoolean()`。
 *
 * 为什么断言"落库 status + 审计 action"而不是响应码：那条字符串真正的危害是被解释
 * 成了相反的意思，200 与 400 都看不出来。审计 action 同样由 locked 三元派生，
 * 两者一起断言才能让"把 isBoolean 删掉""把 toBoolean 删掉"两类变异各自变红。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `ulb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

/** 'false'/'0' 必须解锁，'true'/'1' 必须锁定，真布尔是同一条规则的两个特例 */
const BOOL_TABLE = [
  { key: 'sfalse', in: 'false', want: 'active', action: 'user_unlocked' },
  { key: 'szero', in: '0', want: 'active', action: 'user_unlocked' },
  { key: 'bfalse', in: false, want: 'active', action: 'user_unlocked' },
  { key: 'strue', in: 'true', want: 'locked', action: 'user_locked' },
  { key: 'sone', in: '1', want: 'locked', action: 'user_locked' },
  { key: 'btrue', in: true, want: 'locked', action: 'user_locked' },
];

/** 这些值不在布尔契约内：必须 400，且账户状态与审计都不得发生任何变化 */
const REJECTED = [
  { key: 'r0', body: { locked: 'yes' } },
  { key: 'r1', body: { locked: '' } },
  { key: 'r2', body: { locked: 'active' } },
  { key: 'r3', body: {} },
];

describe('锁定/解锁的布尔边界（字符串 false 不得变成锁定）', () => {
  let app;
  let User;
  let AuditLog;
  let superToken;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

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
      username: `ulbop${stamp}`,
      email: `ulbop${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^ulb\\w+${stamp}$`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  /** 建一个处于 want 反面的账户：解锁用例从 locked 起，锁定用例从 active 起 */
  const makeTarget = async (label, want) => {
    const status = want === 'active' ? 'locked' : 'active';
    const doc = await User.create({
      username: `ulbt${label}${stamp}`,
      email: `ulbt${label}${stamp}@example.com`,
      password: PASSWORD,
      status,
    });
    return doc;
  };

  test.each(BOOL_TABLE.map((c) => ({ ...c, title: `${JSON.stringify(c.in)} ⇒ ${c.want}` })))(
    '$title',
    async (c) => {
      const target = await makeTarget(c.key, c.want);
      const before = await AuditLog.countDocuments({ targetUserId: String(target._id) });

      const res = await request(app)
        .put(`/api/security/users/${target._id}/lock`)
        .set('Authorization', `Bearer ${superToken}`)
        .send({ locked: c.in });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe(c.want);
      expect((await User.findById(target._id)).status).toBe(c.want);

      // 留痕方向必须与真实意图一致：解锁写成 user_unlocked，锁定写成 user_locked
      expect(
        await AuditLog.countDocuments({
          targetUserId: String(target._id),
          action: c.action,
          success: true,
        })
      ).toBe(1);
      // 反向留痕不得出现（否则"两态各写一条"也能蒙过上面那条）
      expect(
        await AuditLog.countDocuments({
          targetUserId: String(target._id),
          action: c.action === 'user_locked' ? 'user_unlocked' : 'user_locked',
        })
      ).toBe(0);
      expect(await AuditLog.countDocuments({ targetUserId: String(target._id) })).toBe(before + 1);
    }
  );

  test.each(REJECTED.map((c) => ({ ...c, title: `${c.key} ${JSON.stringify(c.body)}` })))(
    '非法 locked $title ⇒ 400 且账户与审计纹丝不动',
    async ({ key, body }) => {
      const target = await makeTarget(key, 'active');
      // 从 locked 起更严格：解锁方向也要被拦住，才能证明 400 不是"状态恰好如此"
      await User.findByIdAndUpdate(target._id, { status: 'locked' });

      const res = await request(app)
        .put(`/api/security/users/${target._id}/lock`)
        .set('Authorization', `Bearer ${superToken}`)
        .send(body);

      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect((await User.findById(target._id)).status).toBe('locked');
      expect(await AuditLog.countDocuments({ targetUserId: String(target._id) })).toBe(0);
    }
  );

  test('反向前提：本用例的 400 不是"所有请求都 400"造成的假绿', async () => {
    // 与上一条同一路径、同一鉴权，只把 locked 换成契约内的真布尔 ⇒ 必须 200。
    // 若上面那批 400 来自权限/路由/鉴权配置错误，这里会一起红。
    const target = await makeTarget('sanity', 'active');
    await User.findByIdAndUpdate(target._id, { status: 'locked' });
    const res = await request(app)
      .put(`/api/security/users/${target._id}/lock`)
      .set('Authorization', `Bearer ${superToken}`)
      .send({ locked: false });
    expect(res.status).toBe(200);
    expect((await User.findById(target._id)).status).toBe('active');
  });

  // ==== 两套锁定是分开的：管理员锁定改 status，暴力破解只写 lockUntil ====
  // loginUser（入口 src/services/authService.js:221，lockUntil 判据在
  // src/services/authService.js:356）与 authenticate（入口 src/middleware/auth.js:208，
  // lockUntil 判据在 src/middleware/auth.js:297）只看 lockUntil 就拒绝，
  // 所以"解锁只改回 status"会给出 200「用户已解锁」+ 审计 success:true，
  // 而用户依旧登不进来、活令牌全部 403。修法是解锁时连临时锁定一起清掉。
  const makeTempLocked = async (label, status) =>
    User.create({
      username: `ulbt${label}${stamp}`,
      email: `ulbt${label}${stamp}@example.com`,
      password: PASSWORD,
      status,
      lockUntil: new Date(Date.now() + 10 * 60 * 1000),
      failedLoginCount: 9,
    });
  const loginAs = (username) =>
    request(app).post('/api/auth/login').send({ username, password: PASSWORD });

  test('前提自证：status 已是 active 但 lockUntil 在未来 ⇒ 正确口令也登不进来', async () => {
    // 这条不测修复，它测的是"为什么只改 status 不够"。若哪天有人把 loginUser
    // 的 lockUntil 闸删掉，这条会红——那时上面那组断言就失去意义了。
    const target = await makeTempLocked('tmpgate', 'active');
    const res = await loginAs(target.username);
    expect(res.status).toBe(401);
    expect(res.body.errors.errorCode).toBe('AUTH_INVALID_CREDENTIALS');
  });

  test('解锁 ⇒ status/lockUntil/failedLoginCount 三者一起复原，且真的能登录', async () => {
    const target = await makeTempLocked('unlock', 'locked');
    const res = await request(app)
      .put(`/api/security/users/${target._id}/lock`)
      .set('Authorization', `Bearer ${superToken}`)
      .send({ locked: false });
    expect(res.status).toBe(200);

    const after = await User.findById(target._id).select('status lockUntil failedLoginCount');
    expect(after.status).toBe('active');
    expect(after.lockUntil).toBeFalsy();
    expect(after.failedLoginCount).toBe(0);
    // 端到端判据：运维要看到的是"这个人能登进来"，不是三个字段各自归零
    expect((await loginAs(target.username)).status).toBe(200);
  });

  test('方向性：锁定不得顺手清掉 lockUntil（否则解锁成了唯一的复原路径）', async () => {
    const target = await makeTempLocked('lockdir', 'active');
    const before = await User.findById(target._id).select('lockUntil');
    const res = await request(app)
      .put(`/api/security/users/${target._id}/lock`)
      .set('Authorization', `Bearer ${superToken}`)
      .send({ locked: true });
    expect(res.status).toBe(200);
    const after = await User.findById(target._id).select('status lockUntil failedLoginCount');
    expect(after.status).toBe('locked');
    expect(String(after.lockUntil)).toBe(String(before.lockUntil));
  });
});
