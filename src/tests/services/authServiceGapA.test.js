/**
 * authService 覆盖率补全 A：updateUserProfile 全函数 + changeUserPassword 分支 +
 * revokeTokensOnLogout 分支
 *
 * 目标行（2026-09-01 实测未覆盖）：
 *   updateUserProfile: 860-901（整函数）
 *   changeUserPassword: 786-787, 798-799, 806, 812, 817, 827
 *   revokeTokensOnLogout: 936, 942-943, 956, 962-963
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('authService gap A', () => {
  let User;
  let authService;
  const stamp = `ga${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const createdUsers = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    // 确保 Role/GUEST 存在（registerUser 内部会查）
    const Role = require('../../models/Role');
    const exists = await Role.findOne({ code: 'GUEST' });
    if (!exists) {
      await Role.create({ name: '访客', code: 'GUEST', level: 1 });
    }
    authService = require('../../services/authService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const makeUser = async (suffix, extra = {}) => {
    const user = await User.create({
      username: `${stamp}${suffix}`,
      email: `${stamp}${suffix}@example.com`,
      password: PASSWORD,
      ...extra,
    });
    createdUsers.push(user._id);
    return user;
  };

  // ==================== updateUserProfile ====================
  describe('updateUserProfile', () => {
    test('NOT_FOUND - 不存在的 userId', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const result = await authService.updateUserProfile(fakeId, { realName: 'X' });
      expect(result.outcome).toBe('NOT_FOUND');
    });

    test('INVALID_PHONE - 非法手机号格式', async () => {
      const user = await makeUser('prof1');
      const result = await authService.updateUserProfile(user._id, { phone: '12345' });
      expect(result.outcome).toBe('INVALID_PHONE');
    });

    test('INVALID_EMAIL - 非法邮箱格式', async () => {
      const user = await makeUser('prof2');
      const result = await authService.updateUserProfile(user._id, { email: 'not-an-email' });
      expect(result.outcome).toBe('INVALID_EMAIL');
    });

    test('EMAIL_TAKEN - 邮箱已被其他用户占用', async () => {
      const userA = await makeUser('prof3a');
      const userB = await makeUser('prof3b');
      const result = await authService.updateUserProfile(userA._id, { email: userB.email });
      expect(result.outcome).toBe('EMAIL_TAKEN');
    });

    test('INVALID_AVATAR - 非法头像 URL', async () => {
      const user = await makeUser('prof4');
      const result = await authService.updateUserProfile(user._id, {
        avatar: 'javascript:alert(1)',
      });
      expect(result.outcome).toBe('INVALID_AVATAR');
    });

    test('OK - 正常更新全部可自助字段并返回 profile', async () => {
      const user = await makeUser('prof5');
      const result = await authService.updateUserProfile(user._id, {
        realName: '张三',
        phone: '13800138000',
        avatar: 'https://example.com/avatar.png',
      });
      expect(result.outcome).toBe('OK');
      expect(result.profile.realName).toBe('张三');
      expect(result.profile.phone).toBe('13800138000');
      expect(result.profile.avatar).toBe('https://example.com/avatar.png');
    });

    // ==================== H-01 回归：department 不可自助修改 ====================
    // department 是数据范围的唯一来源（rbac.js:195 构造 department 型 dataScope，
    // 再经 constants/dataScopeFields.js 映射为各业务资源的过滤字段）。
    // 若可自助修改，持有 level>=7 角色的账户只需一次 PUT /api/auth/profile
    // 即可把 dataScope 指向任意部门，绕过部门隔离读取并导出该部门数据。
    // 反向证据：管理员改他人部门（PUT /api/users/:id）有层级校验，自助入口原先无。
    test('H-01 - 携带 department 时被忽略，不改变原值', async () => {
      const user = await makeUser('prof5dept', { department: 'B栋' });
      expect((await User.findById(user._id)).department).toBe('B栋');

      const result = await authService.updateUserProfile(user._id, {
        realName: '李四',
        department: 'A栋', // 尝试越权改写数据范围来源
      });
      expect(result.outcome).toBe('OK');

      // 数据库中的 department 必须保持原值
      expect((await User.findById(user._id)).department).toBe('B栋');
      // 返回的 profile 也不得回显请求体中的值
      expect(result.profile.department).toBe('B栋');
      // 其余字段正常更新（确认是"忽略该字段"而非"整体拒绝请求"）
      expect((await User.findById(user._id)).realName).toBe('李四');
    });

    test('H-01 - 原本无 department 时不会被写入', async () => {
      const user = await makeUser('prof5nodept');
      const result = await authService.updateUserProfile(user._id, { department: 'A栋' });
      expect(result.outcome).toBe('OK');
      expect((await User.findById(user._id)).department).toBeUndefined();
    });

    test('OK - 更新邮箱为自己当前邮箱不触发 EMAIL_TAKEN', async () => {
      const user = await makeUser('prof6');
      const result = await authService.updateUserProfile(user._id, { email: user.email });
      expect(result.outcome).toBe('OK');
    });

    test('OK - 合法相对路径头像与 data URI', async () => {
      const user = await makeUser('prof7');
      const r1 = await authService.updateUserProfile(user._id, {
        avatar: '/uploads/photo.jpg',
      });
      expect(r1.outcome).toBe('OK');
    });

    test('OK - 空字符串头像通过校验', async () => {
      const user = await makeUser('prof8');
      const r = await authService.updateUserProfile(user._id, { avatar: '' });
      expect(r.outcome).toBe('OK');
    });
  });

  // ==================== changeUserPassword ====================
  describe('changeUserPassword', () => {
    test('MISSING - currentPassword 或 newPassword 缺失', async () => {
      const user = await makeUser('cp1');
      const result = await authService.changeUserPassword(
        user._id,
        { currentPassword: PASSWORD },
        { username: user.username }
      );
      expect(result.outcome).toBe('MISSING');
    });

    test('MISSING - 两者都缺失', async () => {
      const user = await makeUser('cp1b');
      const result = await authService.changeUserPassword(
        user._id,
        {},
        { username: user.username }
      );
      expect(result.outcome).toBe('MISSING');
    });

    test('WEAK - 新密码强度不足', async () => {
      const user = await makeUser('cp2');
      const result = await authService.changeUserPassword(
        user._id,
        { currentPassword: PASSWORD, newPassword: 'weak' },
        { username: user.username }
      );
      expect(result.outcome).toBe('WEAK');
      expect(result.message).toBeTruthy();
    });

    test('USER_NOT_FOUND - 不存在的 userId', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const result = await authService.changeUserPassword(
        fakeId,
        { currentPassword: PASSWORD, newPassword: randomPassword() },
        { username: 'ghost' }
      );
      expect(result.outcome).toBe('USER_NOT_FOUND');
    });

    test('CURRENT_WRONG - 当前密码错误', async () => {
      const user = await makeUser('cp3');
      const result = await authService.changeUserPassword(
        user._id,
        { currentPassword: 'WrongPass!99xx', newPassword: randomPassword() },
        { username: user.username }
      );
      expect(result.outcome).toBe('CURRENT_WRONG');
    });

    test('SAME_PASSWORD - 新密码与旧密码相同', async () => {
      const user = await makeUser('cp4');
      const result = await authService.changeUserPassword(
        user._id,
        { currentPassword: PASSWORD, newPassword: PASSWORD },
        { username: user.username }
      );
      expect(result.outcome).toBe('SAME_PASSWORD');
    });

    test('OK - 成功修改密码', async () => {
      const user = await makeUser('cp5');
      const newPwd = randomPassword();
      const result = await authService.changeUserPassword(
        user._id,
        { currentPassword: PASSWORD, newPassword: newPwd },
        { username: user.username }
      );
      expect(result.outcome).toBe('OK');
      expect(result.username).toBe(user.username);
    });

    test('ENC_INVALID - encCurrentPassword 解密失败', async () => {
      const user = await makeUser('cp6');
      // 构造一个无法解密的密文
      const badEnc = Buffer.from(JSON.stringify({ v: 1, x: 'bad', y: 'bad', c: 'bad' })).toString(
        'base64'
      );
      const result = await authService.changeUserPassword(
        user._id,
        { encCurrentPassword: badEnc, newPassword: randomPassword() },
        { username: user.username }
      );
      expect(result.outcome).toBe('ENC_INVALID');
    });

    test('ENC_INVALID - encNewPassword 解密失败', async () => {
      const user = await makeUser('cp7');
      const badEnc = Buffer.from(JSON.stringify({ v: 1, x: 'bad', y: 'bad', c: 'bad' })).toString(
        'base64'
      );
      const result = await authService.changeUserPassword(
        user._id,
        { currentPassword: PASSWORD, encNewPassword: badEnc },
        { username: user.username }
      );
      expect(result.outcome).toBe('ENC_INVALID');
    });
  });

  // ==================== revokeTokensOnLogout ====================
  describe('revokeTokensOnLogout', () => {
    test('无令牌时返回 revokeFailed=false', async () => {
      const result = await authService.revokeTokensOnLogout({});
      expect(result.revokeFailed).toBe(false);
    });

    test('access token 签名无效 → 不算失败（本就不可用）', async () => {
      const badToken = jwt.sign({ userId: 'x' }, 'wrong-secret', { expiresIn: '1h' });
      const result = await authService.revokeTokensOnLogout({ accessToken: badToken });
      expect(result.revokeFailed).toBe(false);
    });

    test('refresh token 签名无效 → 不算失败', async () => {
      const badRefresh = jwt.sign({ userId: 'x', type: 'refresh' }, 'wrong-secret', {
        expiresIn: '1h',
      });
      const result = await authService.revokeTokensOnLogout({ refreshToken: badRefresh });
      expect(result.revokeFailed).toBe(false);
    });

    test('有效 access token 正常吊销', async () => {
      const token = jwt.sign(
        { userId: 'test-user', username: 'u', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      const result = await authService.revokeTokensOnLogout({ accessToken: token });
      expect(result.revokeFailed).toBe(false);
    });

    test('有效 refresh token 正常吊销', async () => {
      const refreshSecret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
      const token = jwt.sign(
        { userId: 'test-user', type: 'refresh', tokenVersion: 0 },
        refreshSecret,
        { expiresIn: '1h' }
      );
      const result = await authService.revokeTokensOnLogout({ refreshToken: token });
      expect(result.revokeFailed).toBe(false);
    });

    test('blacklistToken 抛错 → revokeFailed=true（access）', async () => {
      // authService 在模块加载时解构了 blacklistToken，无法事后 spyOn；
      // 改为让底层 TokenBlacklist.findOneAndUpdate 抛错触发 fail-closed 路径
      const TokenBlacklist = require('../../models/TokenBlacklist');
      const spy = jest
        .spyOn(TokenBlacklist, 'findOneAndUpdate')
        .mockRejectedValueOnce(new Error('db down'));

      const token = jwt.sign(
        { userId: 'test-user', username: 'u', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      const result = await authService.revokeTokensOnLogout({ accessToken: token });
      expect(result.revokeFailed).toBe(true);
      spy.mockRestore();
    });

    test('blacklistToken 抛错 → revokeFailed=true（refresh）', async () => {
      const TokenBlacklist = require('../../models/TokenBlacklist');
      const spy = jest
        .spyOn(TokenBlacklist, 'findOneAndUpdate')
        .mockRejectedValueOnce(new Error('db down'));

      const refreshSecret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
      const token = jwt.sign(
        { userId: 'test-user', type: 'refresh', tokenVersion: 0 },
        refreshSecret,
        { expiresIn: '1h' }
      );
      const result = await authService.revokeTokensOnLogout({ refreshToken: token });
      expect(result.revokeFailed).toBe(true);
      spy.mockRestore();
    });

    test('已过期的 access token 校验失败但不算 revokeFailed', async () => {
      // 签发一个已经过期的 token
      const token = jwt.sign(
        { userId: 'test-user', username: 'u', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '-1s' }
      );
      const result = await authService.revokeTokensOnLogout({ accessToken: token });
      // 过期 token verify 抛 TokenExpiredError → payload=null → 不调 blacklist → false
      expect(result.revokeFailed).toBe(false);
    });
  });
});
