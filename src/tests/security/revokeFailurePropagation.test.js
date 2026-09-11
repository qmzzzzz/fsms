/**
 * S1：invalidateUserTokens 吊销失败时的错误传播（fail-closed 落地）
 *
 * 四个调用方共享同一风险形态：「敏感状态已经变更，吊销动作本身却可能失败」。
 * 修复前要么异常冒泡到 asyncHandler 退化成笼统 500（客户端无法区分
 * 「什么都没发生」与「完成了一半」），要么——以管理员重置 MFA 最严重——
 * 先拆掉两步验证再吊销，吊销失败即「防护已拆除而旧会话仍在线」。
 *
 * 本套件用 jest.spyOn(User, 'findByIdAndUpdate') 注入故障——
 * invalidateUserTokens 内部正是通过该方法写 tokenVersion——在真实
 * HTTP 请求路径上断言每条链都返回如实的状态码与文案：
 *   - PUT /api/auth/password                  → 503「已改但未吊销」，密码确实已落库
 *   - PUT /api/security/change-password       → 503，同上
 *   - PUT /api/security/users/:id/mfa/reset   → 吊销失败 503 且 MFA 原样保留；
 *                                               部分失败（已下线但清除失败）如实 503；
 *                                               正常路径 200 回归不受影响
 *   - POST /api/auth/refresh（重放 + 吊销失败）→ 503（不得用 401 假装已处置）；
 *                                               健康重放 → 401 且 tokenVersion 递增
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('S1 invalidateUserTokens 吊销失败的错误传播', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let generateRefreshToken;
  let superToken;
  const PASSWORD = randomPassword();
  const stamp = `rv${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const users = {};

  const makeUser = async (name, extra = {}) => {
    const user = await User.create({
      username: `${stamp}${name}`,
      email: `${stamp}${name}@example.com`,
      password: PASSWORD,
      ...extra,
    });
    users[name] = {
      _id: user._id,
      token: jwt.sign(
        { userId: String(user._id), username: user.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      ),
    };
    return user;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    require('../../models/AuditLog');
    ({ generateRefreshToken } = require('../../services/tokenService'));

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    const superUser = await User.create({
      username: `${stamp}super`,
      email: `${stamp}super@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superToken = jwt.sign(
      { userId: String(superUser._id), username: superUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    users.super = { _id: superUser._id };

    await makeUser('authpwd');
    await makeUser('secpwd');
    // 三个独立的 MFA 重置对象，分别覆盖：吊销失败 / 部分失败 / 正常成功
    for (const name of ['victimA', 'victimB', 'victimC']) {
      await makeUser(name, { mfaEnabled: true, mfaSecret: 'JBSWY3DPEHPK3PXP' });
    }
    await makeUser('replayA');
    await makeUser('replayB');

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  describe('改密路径：密码已落库但吊销失败 → 503 如实告知', () => {
    test('PUT /api/auth/password：503 + 密码确实已改 + tokenVersion 未递增', async () => {
      const u = users.authpwd;
      const newPassword = randomPassword();
      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        .mockRejectedValue(new Error('db down (S1 故障注入)'));
      let res;
      try {
        res = await request(app)
          .put('/api/auth/password')
          .set('Authorization', `Bearer ${u.token}`)
          .send({ currentPassword: PASSWORD, newPassword });
      } finally {
        spy.mockRestore();
      }

      expect(res.status).toBe(503);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('密码已修改');
      expect(res.body.message).toContain('请重新登录');

      const after = await User.findById(u._id).select('+password');
      expect(await after.comparePassword(newPassword)).toBe(true);
      expect(after.tokenVersion).toBe(0);
    });

    test('PUT /api/security/change-password：503 + 密码确实已改 + tokenVersion 未递增', async () => {
      const u = users.secpwd;
      const newPassword = randomPassword();
      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        .mockRejectedValue(new Error('db down (S1 故障注入)'));
      let res;
      try {
        res = await request(app)
          .put('/api/security/change-password')
          .set('Authorization', `Bearer ${u.token}`)
          .send({ currentPassword: PASSWORD, newPassword, confirmPassword: newPassword });
      } finally {
        spy.mockRestore();
      }

      expect(res.status).toBe(503);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('密码已修改');

      const after = await User.findById(u._id).select('+password');
      expect(await after.comparePassword(newPassword)).toBe(true);
      expect(after.tokenVersion).toBe(0);
    });
  });

  describe('管理员重置 MFA：fail-closed 顺序（先吊销，后清 MFA）', () => {
    test('吊销失败 → 503，两步验证原样保留（绝不出现「已拆除但会话在线」）', async () => {
      const v = users.victimA;
      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        .mockRejectedValue(new Error('db down (S1 故障注入)'));
      let res;
      try {
        res = await request(app)
          .put(`/api/security/users/${v._id}/mfa/reset`)
          .set('Authorization', `Bearer ${superToken}`);
      } finally {
        spy.mockRestore();
      }

      expect(res.status).toBe(503);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('未执行重置');

      const after = await User.findById(v._id).select('+mfaSecret');
      expect(after.mfaEnabled).toBe(true);
      expect(after.mfaSecret).toBe('JBSWY3DPEHPK3PXP');
      expect(after.tokenVersion).toBe(0);
    });

    test('吊销成功但清除 MFA 失败 → 503 如实告知「已强制下线但未清除」', async () => {
      const v = users.victimB;
      const originalFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation((id, update) => {
        if (update && update.$inc) return originalFindByIdAndUpdate(id, update); // 吊销真实落库
        return Promise.reject(new Error('db down (S1 故障注入：MFA 清除)'));
      });
      let res;
      try {
        res = await request(app)
          .put(`/api/security/users/${v._id}/mfa/reset`)
          .set('Authorization', `Bearer ${superToken}`);
      } finally {
        spy.mockRestore();
      }

      expect(res.status).toBe(503);
      expect(res.body.message).toContain('已被强制下线');

      const after = await User.findById(v._id);
      expect(after.tokenVersion).toBe(1); // 吊销确实生效
      expect(after.mfaEnabled).toBe(true); // 两步验证仍开启（安全方向）
    });

    test('正常路径回归：200 + MFA 已清 + 强制下线生效', async () => {
      const v = users.victimC;
      const res = await request(app)
        .put(`/api/security/users/${v._id}/mfa/reset`)
        .set('Authorization', `Bearer ${superToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.mfaEnabled).toBe(false);

      const after = await User.findById(v._id);
      expect(after.mfaEnabled).toBe(false);
      expect(after.tokenVersion).toBe(1);
    });
  });

  describe('刷新轮换重放检测：吊销失败不得被 401 掩盖', () => {
    test('重放触发但吊销失败 → 503「安全服务暂不可用」', async () => {
      const u = users.replayA;
      const token = generateRefreshToken(u._id, 0, null);

      // 首次刷新正常消费该令牌；同一令牌再次使用即触发重放检测
      const first = await request(app).post('/api/auth/refresh').send({ refreshToken: token });
      expect(first.status).toBe(200);

      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        .mockRejectedValue(new Error('db down (S1 故障注入)'));
      let replay;
      try {
        replay = await request(app).post('/api/auth/refresh').send({ refreshToken: token });
      } finally {
        spy.mockRestore();
      }

      expect(replay.status).toBe(503);
      expect(replay.body.message).toBe('安全服务暂不可用，请稍后重试');

      const after = await User.findById(u._id);
      expect(after.tokenVersion).toBe(0); // 吊销未生效——不得谎报已处置
    });

    test('健康重放 → 401 且 tokenVersion 递增（对照组）', async () => {
      const u = users.replayB;
      const token = generateRefreshToken(u._id, 0, null);

      const first = await request(app).post('/api/auth/refresh').send({ refreshToken: token });
      expect(first.status).toBe(200);

      const replay = await request(app).post('/api/auth/refresh').send({ refreshToken: token });
      expect(replay.status).toBe(401);
      expect(replay.body.message).toContain('请重新登录');

      const after = await User.findById(u._id);
      expect(after.tokenVersion).toBe(1);
    });
  });
});
