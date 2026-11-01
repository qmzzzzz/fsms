/**
 * updateUser 的头像清空事务路径与数据范围字段变更闸。
 *
 * 既有套件没有"把 avatar 置空串"的用例：saveUserWithAvatarCleanup 的 withTransaction
 * 回调（含 session 有无两臂）从未被计数（functions 90% < 97%）；rejectOutOfScopeFieldChange
 * 的 self 档拒绝臂与 department 档放行臂同样从未被计数。这里直接驱动控制器。
 */
jest.mock('express-validator', () => ({
  validationResult: () => ({ isEmpty: () => true, array: () => [] }),
}));

// 恢复账户（status→active）要吊销旧会话；只替这一支，其余导出保留真实实现——
// 同进程里 auth 等模块也从 tokenBlacklist 取函数，整体替身会把它们一起换成 undefined。
jest.mock('../../middleware/tokenBlacklist', () => ({
  ...jest.requireActual('../../middleware/tokenBlacklist'),
  invalidateUserTokens: jest.fn(),
}));

const mongoose = require('mongoose');
const { updateUser } = require('../../controllers/userController/update');
const User = require('../../models/User');
const Role = require('../../models/Role');
const Permission = require('../../models/Permission');
const UserAvatar = require('../../models/UserAvatar');
const { invalidateUserTokens } = require('../../middleware/tokenBlacklist');

const stamp = 'up' + Date.now().toString(36);
const PASSWORD = 'Zq7!Wn4#Rt9$Yp2@Ks6&Lm8*Vc3^Bh5%Jf1Nx0Kd';

const mockRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn((body) => {
    res.body = body;
    return res;
  });
  return res;
};

const reqOf = (id, user, body) => ({
  params: { id },
  body,
  user,
  ip: '127.0.0.1',
  headers: {},
  socket: { remoteAddress: '127.0.0.1' },
});

const opOf = (doc) => ({ userId: String(doc._id), username: doc.username });

describe('updateUser：头像清空与范围字段闸', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
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
    let selfRole = await Role.findOne({ code: 'UP_SELF' + stamp });
    if (!selfRole) {
      selfRole = await Role.create({ name: '普通', code: 'UP_SELF' + stamp, level: 4 });
    }
    let deptRole = await Role.findOne({ code: 'UP_DEPT' + stamp });
    if (!deptRole) {
      deptRole = await Role.create({ name: '部门', code: 'UP_DEPT' + stamp, level: 7 });
    }
    global.__upSuper = await User.create({
      username: 'upsuper' + stamp,
      email: 'upsuper' + stamp + '@example.com',
      password: PASSWORD,
      roles: [superRole._id],
    });
    global.__upSelfOp = await User.create({
      username: 'upself' + stamp,
      email: 'upself' + stamp + '@example.com',
      password: PASSWORD,
      roles: [selfRole._id],
    });
    global.__upDeptOp = await User.create({
      username: 'updept' + stamp,
      email: 'updept' + stamp + '@example.com',
      password: PASSWORD,
      roles: [deptRole._id],
      department: '东区',
    });
    global.__upTargetA = await User.create({
      username: 'upta' + stamp,
      email: 'upta' + stamp + '@example.com',
      password: PASSWORD,
      roles: [selfRole._id],
      createdBy: global.__upSuper._id,
      department: '东区',
      avatar: '/api/avatars/legacy.png',
    });
    global.__upTargetB = await User.create({
      username: 'uptb' + stamp,
      email: 'uptb' + stamp + '@example.com',
      password: PASSWORD,
      roles: [],
      createdBy: global.__upSelfOp._id,
    });
    global.__upTargetC = await User.create({
      username: 'uptc' + stamp,
      email: 'uptc' + stamp + '@example.com',
      password: PASSWORD,
      roles: [],
      createdBy: global.__upDeptOp._id,
      department: '东区',
    });
    // 前态为 disabled：恢复账户（status→active）时先吊销旧会话，失败必须中止且不改库
    global.__upTargetD = await User.create({
      username: 'uptd' + stamp,
      email: 'uptd' + stamp + '@example.com',
      password: PASSWORD,
      roles: [],
      createdBy: global.__upSuper._id,
      status: 'locked', // 恢复账户 = 从非 active 回到 active（枚举只有 active/inactive/locked）
    });
    await UserAvatar.create({
      _id: global.__upTargetA._id,
      mime: 'image/png',
      data: 'AAAA',
      hash: 'hash-a',
      size: 10,
      width: 1,
      height: 1,
    });
  });

  afterAll(() => {
    for (const k of [
      '__upSuper',
      '__upSelfOp',
      '__upDeptOp',
      '__upTargetA',
      '__upTargetB',
      '__upTargetC',
      '__upTargetD',
    ]) {
      delete global[k];
    }
  });

  test('avatar 置空串：同一事务里删 UserAvatar 并清指针', async () => {
    const res = mockRes();
    await updateUser(
      reqOf(String(global.__upTargetA._id), opOf(global.__upSuper), { avatar: '' }),
      res
    );
    expect(res.body.success).toBe(true);
    const after = await User.findById(global.__upTargetA._id).select('avatar').lean();
    expect(after.avatar).toBe('');
    const pic = await UserAvatar.findById(global.__upTargetA._id);
    expect(pic).toBeNull();
  });

  test('self 档操作者改 department：USER_SCOPE_FIELD_FORBIDDEN', async () => {
    const res = mockRes();
    await updateUser(
      reqOf(String(global.__upTargetB._id), opOf(global.__upSelfOp), { department: '西区' }),
      res
    );
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FIELD_FORBIDDEN');
    const after = await User.findById(global.__upTargetB._id).select('department').lean();
    expect(after.department).toBeFalsy();
  });

  test('department 档操作者把目标留在本部门内：放行', async () => {
    const res = mockRes();
    await updateUser(
      reqOf(String(global.__upTargetC._id), opOf(global.__upDeptOp), { department: '东区' }),
      res
    );
    expect(res.body.success).toBe(true);
  });
  test('恢复账户时旧会话吊销失败：中止并报 SESSION_REVOKE_SERVICE_UNAVAILABLE，库内状态不动', async () => {
    invalidateUserTokens.mockRejectedValueOnce(new Error('redis down'));
    const res = mockRes();
    await updateUser(
      reqOf(String(global.__upTargetD._id), opOf(global.__upSuper), { status: 'active' }),
      res
    );
    expect(res.body.errors.errorCode).toBe('SESSION_REVOKE_SERVICE_UNAVAILABLE');
    expect(invalidateUserTokens).toHaveBeenCalledTimes(1);
    const after = await User.findById(global.__upTargetD._id).select('status').lean();
    expect(after.status).toBe('locked'); // 半恢复（已激活但旧令牌仍可用）比不恢复更危险
  });

  test('恢复账户且吊销成功：正常放行为 active（对照臂，防"一律拒绝"也能过）', async () => {
    invalidateUserTokens.mockResolvedValueOnce(undefined);
    const res = mockRes();
    await updateUser(
      reqOf(String(global.__upTargetD._id), opOf(global.__upSuper), { status: 'active' }),
      res
    );
    expect(res.body.success).toBe(true);
    const after = await User.findById(global.__upTargetD._id).select('status').lean();
    expect(after.status).toBe('active');
  });
});

// 套件级收尾：本文件连了 mongoose，必须在最后一条 root 级 afterAll 里关掉
// （判据见 src/tests/ci/mongooseTeardownLedger.test.js；关在非最后一段里会被判违规）。
afterAll(async () => {
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
