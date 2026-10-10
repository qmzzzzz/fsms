/**
 * 角色权限分配接口的「同级/上级」闸回归测试
 *
 * 锁定的高危不变式（peer-bypass HIGH）：
 *   非内置同级角色 + 请求体里塞一个诱饵 targetUserId，**不得**绕过同级保护去
 *   全局改写该角色的权限。assignPermissions 的克隆分支条件是
 *   `targetUserId && role.isBuiltIn`；对**非内置**角色传 targetUserId 会被静默丢弃、
 *   落到 `role.permissions = [...]` 的全局改写。旧判据 `role.level >= operatorMax && !targetUserId`
 *   因此被一个多余参数旁路——同级操作员可越界重排另一同级角色的生效权限（全组织面）。
 *
 * 本用例是**可证伪**的：若闸回退成 `!targetUserId`，第一个用例即 200 且角色权限被改写 → 红。
 * 合法克隆路径（内置角色 + targetUserId）由第三个用例守住，证明闸没有误伤到过宽。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('rolePermissionController 同级/上级角色改写闸', () => {
  let app;
  let User;
  let Role;
  let Permission;

  const stamp = `pg${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  let midToken; // 5 级操作员，持 role:assign + 可分配的 child 权限
  let peerRoleId; // 与操作员同级（5）、非内置的角色 —— 攻击目标
  let childPermId; // 操作员自身持有、可放进子集的权限
  let decoyUserId; // 诱饵 targetUserId（任意合法用户 id）

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const mkPerm = async (name, code, module) =>
      (await Permission.create({ name, code, type: 'api', module }))._id;

    const roleAssignPerm = await mkPerm('分配权限', 'role:assign', 'role');
    childPermId = String(await mkPerm(`同级闸读_${stamp}`, `pg${stamp}:read`, 'pg'));
    const peerInitialPerm = String(await mkPerm(`同级闸初值_${stamp}`, `pg${stamp}:init`, 'pg'));

    // 操作员：5 级，非内置，持 role:assign + 待分配子权限
    const midRole = await Role.create({
      name: `同级闸操作员_${stamp}`,
      code: `PGMID_${stamp.toUpperCase()}`,
      level: 5,
      isBuiltIn: false,
      permissions: [roleAssignPerm, childPermId],
    });
    const midUser = await User.create({
      username: `pgmid${stamp}`,
      email: `pgmid${stamp}@example.com`,
      password: PASSWORD,
      roles: [midRole._id],
    });
    midToken = jwt.sign(
      { userId: String(midUser._id), username: midUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 攻击目标：同级(5)、非内置、初始持有一个哨兵权限（用于断言未被改写）
    const peerRole = await Role.create({
      name: `同级闸目标_${stamp}`,
      code: `PGPEER_${stamp.toUpperCase()}`,
      level: 5,
      isBuiltIn: false,
      permissions: [peerInitialPerm],
    });
    peerRoleId = String(peerRole._id);

    // 诱饵 targetUserId：随便一个合法用户
    const decoy = await User.create({
      username: `pgdecoy${stamp}`,
      email: `pgdecoy${stamp}@example.com`,
      password: PASSWORD,
      roles: [midRole._id],
    });
    decoyUserId = String(decoy._id);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const authed = (token) => ({
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${token}`),
  });

  test('非内置同级角色 + 诱饵 targetUserId：不得旁路同级闸做全局改写', async () => {
    const res = await authed(midToken)
      .put(`/api/roles/${peerRoleId}/permissions`)
      .send({ permissions: [childPermId], targetUserId: decoyUserId });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN');

    // 关键：拒绝必须"没写库"——若闸被绕过，permissions 会变成 [childPermId]
    const after = await Role.findById(peerRoleId).select('permissions').lean();
    expect(after.permissions.map(String)).not.toContain(String(childPermId));
  });

  test('非内置同级角色、不传 targetUserId：同级闸照常拦截（既有行为不回归）', async () => {
    const res = await authed(midToken)
      .put(`/api/roles/${peerRoleId}/permissions`)
      .send({ permissions: [childPermId] });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN');
  });

  test('低于自身层级的非内置角色 + 诱饵 targetUserId：合法全局改写不受该闸影响', async () => {
    const lowRole = await Role.create({
      name: `同级闸低级_${stamp}`,
      code: `PGLOW_${stamp.toUpperCase()}`,
      level: 2,
      isBuiltIn: false,
      permissions: [],
    });

    const res = await authed(midToken)
      .put(`/api/roles/${String(lowRole._id)}/permissions`)
      .send({ permissions: [childPermId], targetUserId: decoyUserId });

    // 低层级角色：level >= operatorMax 为假 → 同级闸不介入；非内置 → 走全局改写并成功
    expect(res.status).toBe(200);
    const after = await Role.findById(lowRole._id).select('permissions').lean();
    expect(after.permissions.map(String)).toContain(String(childPermId));
  });
});
