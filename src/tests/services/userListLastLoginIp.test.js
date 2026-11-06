/**
 * 用户管理「最后登录 IP」：默认不给，显式 includeLastLoginIp 才给。
 *
 * 为什么要这条边界：lastLoginIp 在 dataClassification 里是 L3（行为痕迹，可定位自然人），
 * 默认投影长期排除它；把它无条件放回列表，等于让任何持 user:read 的部门管理员看到
 * 全部门员工的登录 IP。这里钉死两件事：
 *   A. 默认投影不含 lastLoginIp（接口层回归到“不传就不给”）；
 *   B. 显式传入时真能拿到值（否则前端列永远是占位符，能力等于没接）。
 * 权限判定在 userController/read.js（system:read），不在本层。
 */
const mongoose = require('mongoose');

const User = require('../../models/User');
require('../../models/Role');
const userService = require('../../services/userService');

const TAG = `llip${Date.now().toString(36)}`;
const IP = '203.0.113.9';

describe('用户管理「最后登录 IP」投影', () => {
  let userId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const doc = await User.create({
      username: `${TAG}u`,
      password: 'Test#12345Aa!',
      realName: 'T',
      email: `${TAG}u@example.com`,
      status: 'active',
      lastLoginAt: new Date(),
      lastLoginIp: IP,
    });
    userId = doc._id;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(TAG) });
      await mongoose.connection.close();
    }
  });

  test('A 默认不给：列表不带 lastLoginIp，但仍带最后登录时间', async () => {
    const { users } = await userService.listUsers(
      { username: new RegExp(TAG) },
      { createdAt: -1 },
      1,
      5
    );
    expect(users).toHaveLength(1);
    expect(users[0].lastLoginIp).toBeUndefined();
    expect(users[0].lastLoginAt).toBeTruthy();
  });

  test('B 显式 includeLastLoginIp：列表拿到真实值', async () => {
    const { users } = await userService.listUsers(
      { username: new RegExp(TAG) },
      { createdAt: -1 },
      1,
      5,
      { includeLastLoginIp: true }
    );
    expect(users[0].lastLoginIp).toBe(IP);
  });

  test('C 详情接口同样两档', async () => {
    const plain = await userService.getUserDetail(userId);
    expect(plain.lastLoginIp).toBeUndefined();
    const withIp = await userService.getUserDetail(userId, { includeLastLoginIp: true });
    expect(withIp.lastLoginIp).toBe(IP);
  });
});
