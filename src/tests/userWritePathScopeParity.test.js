/**
 * 被测对象：src/controllers/userController.js 的 updateUser / deleteUser / batchDeleteUsers /
 *   assignRoles，以及 src/controllers/securityController.js 的 toggleUserLock / resetUserMfa
 *   （用户对象六个写入口）。
 * 守护的不变式：写路径与读路径（getUserById）数据范围判定同口径——目标用户若在操作者
 *   可见域之外，六个写入口一律 403 USER_SCOPE_FORBIDDEN；可见域内的写操作不受影响
 *   （正对照排除"全局误拒"）。层级闸（peer/higher）与范围闸是两个正交轴，都要有。
 * 可证伪性：修复前由子审计员 Zeno 实测（D:/tmp/verify_scope.js、verify_scope2.js，
 *   2026-09-20 22:05，内存 Mongo + 真实路由）：GET /api/users/:id → 403 USER_VIEW_FORBIDDEN，
 *   同一 ID 的 PUT / DELETE / 派角色 / 锁定 → 200（写操作真实生效）。即无守卫时每条
 *   负向用例都会走到成功分支而转红。审计员 B 已在交付前对 updateUser/toggleUserLock
 *   两处做过"注掉守卫 → 复跑转红 → 还原字节一致"的变异复核。
 * 既往审计边界：只覆盖六个对象级写入口的范围闸。层级保护、内置超管锁、字段级范围闸
 *   （department/allowedIPs）、批量上限与 ID 格式校验由各自既有用例覆盖，本文件不重复；
 *   securityController 的 toggleUserLock 服务层逻辑（authService.setUserLockStatus）
 *   未逐行覆盖，仅验证其控制器前置闸。
 * 命名沿革：无（首版，2026-09-21 审计员 B 新增）。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('用户对象写路径的数据范围闸（与读路径同口径）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let operator;
  let operatorToken;
  let outTarget;
  let inTarget;
  let targetRole;
  const stamp = `wsp${Date.now().toString(36)}`;
  const DEPT_IN = '东区';
  const DEPT_OUT = '总部';

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');

    const codes = [
      'user:read',
      'user:update',
      'user:delete',
      'role:assign',
      'user:lock',
      'user:reset_password',
    ];
    const permIds = [];
    for (const code of codes) {
      const perm = await Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { name: code, code, type: 'api', module: 'user' } },
        { upsert: true, new: true }
      );
      permIds.push(perm._id);
    }

    // 操作者：level 8 ≥ LEVEL_DEPARTMENT(7) ⇒ 数据范围 = 本部门
    const operatorRole = await Role.create({
      name: `写路径范围操作者${stamp}`,
      code: `WSP_OP_${stamp}`,
      level: 8,
      permissions: permIds,
    });
    // 目标角色：level 4，低于操作者（排除层级闸干扰，孤立验证范围闸）
    targetRole = await Role.create({
      name: `写路径范围目标${stamp}`,
      code: `WSP_TGT_${stamp}`,
      level: 4,
      permissions: [],
    });

    operator = await User.create({
      username: `wspop${stamp}`,
      email: `wspop${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      department: DEPT_IN,
      roles: [operatorRole._id],
    });
    outTarget = await User.create({
      username: `wspout${stamp}`,
      email: `wspout${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      department: DEPT_OUT,
      roles: [targetRole._id],
      createdBy: new mongoose.Types.ObjectId(),
    });
    inTarget = await User.create({
      username: `wspin${stamp}`,
      email: `wspin${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      department: DEPT_IN,
      roles: [targetRole._id],
      createdBy: new mongoose.Types.ObjectId(),
    });

    operatorToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    app = require('../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const names = [`wspop${stamp}`, `wspout${stamp}`, `wspin${stamp}`];
      await User.deleteMany({ username: { $in: names } }).catch(() => {});
      await Role.deleteMany({ code: { $in: [`WSP_OP_${stamp}`, `WSP_TGT_${stamp}`] } }).catch(
        () => {}
      );
      await Permission.deleteMany({
        code: {
          $in: [
            'user:read',
            'user:update',
            'user:delete',
            'role:assign',
            'user:lock',
            'user:reset_password',
          ],
        },
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = (method, url) =>
    request(app)[method](url).set('Authorization', `Bearer ${operatorToken}`);

  test('前提自证：域外目标在读路径即被拒（GET 403），不是"看不到但能写"', async () => {
    const res = await authed('get', `/api/users/${outTarget._id}`);
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_VIEW_FORBIDDEN');
  });

  test('updateUser：域外目标 403 USER_SCOPE_FORBIDDEN，且资料不被改写', async () => {
    const res = await authed('put', `/api/users/${outTarget._id}`).send({ realName: '越权改写' });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
    const fresh = await User.findById(outTarget._id);
    expect(fresh.realName).not.toBe('越权改写');
  });

  test('deleteUser：域外目标 403，用户真实存在（未被删）', async () => {
    const res = await authed('delete', `/api/users/${outTarget._id}`);
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
    expect(await User.findById(outTarget._id)).not.toBeNull();
  });

  test('assignRoles：域外目标 403，角色不被改写', async () => {
    const res = await authed('put', `/api/users/${outTarget._id}/roles`).send({
      roles: [String(targetRole._id)],
    });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
  });

  test('batchDeleteUsers：批量入口不得成为单对象闸的绕过路径', async () => {
    const res = await authed('delete', '/api/users/batch').send({ ids: [String(outTarget._id)] });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
    expect(await User.findById(outTarget._id)).not.toBeNull();
  });

  test('toggleUserLock：域外目标 403，status 不被改写', async () => {
    const res = await authed('put', `/api/security/users/${outTarget._id}/lock`).send({
      locked: true,
      reason: '越权锁定',
    });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
    const fresh = await User.findById(outTarget._id);
    expect(fresh.status).not.toBe('locked');
  });

  test('resetUserMfa：域外目标 403', async () => {
    const res = await authed('put', `/api/security/users/${outTarget._id}/mfa/reset`).send({});
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
  });

  test('正对照：域内目标的正常更新不受影响（排除全局误拒）', async () => {
    const res = await authed('put', `/api/users/${inTarget._id}`).send({ realName: '正常更新' });
    expect(res.status).toBe(200);
    const fresh = await User.findById(inTarget._id);
    expect(fresh.realName).toBe('正常更新');
  });
});
