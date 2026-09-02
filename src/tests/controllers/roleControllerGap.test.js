/**
 * roleController 覆盖率补齐（gap）
 *
 * 目标：将分支覆盖率从 ~41% 提到 >=70%，函数覆盖率从 ~63% 尽量 >=85%。
 * 覆盖此前未命中分支：
 *  - emitWebSocketEvent / syncPermissionsToUsers 有 wsService 的分支
 *  - getRoles search 参数
 *  - createRole 非超管层级拦截 + 权限子集校验
 *  - updateRole 验证失败/404/内置状态保护/空名称/非超管层级双向拦截
 *  - assignPermissions 各种错误分支 + 克隆模式全路径 + 超管角色锁定
 *  - deleteRole 404 + 使用中拦截
 *  - getPermissionTree 父子节点挂载
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('roleController 覆盖率补齐', () => {
  let app;
  let User;
  let Role;
  let Permission;
  const stamp = `rcg${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  // Tokens for different privilege levels
  let superToken; // built-in SUPER_ADMIN holder (*:*)
  let superUserId;
  let midToken; // level-5 operator with role:create, role:update, role:assign, role:delete, role:read
  let midUserId;
  let _lowToken; // level-2 operator with role:read only
  let lowUserId;

  // Reusable entity IDs
  let customRoleId; // a custom role created by superadmin for tests
  let builtinSuperId;
  let permReadId;
  let _permWriteId;
  let _wildcardPermId;
  let midOperatorRoleId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    // Ensure wildcard permission exists
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    _wildcardPermId = String(wildcardPerm._id);

    // Ensure built-in SUPER_ADMIN role exists
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    builtinSuperId = String(builtInSuper._id);

    // Create test permissions (module segment must be alpha-only, no digits)
    permReadId = String(
      (
        await Permission.create({
          name: 'RCG读',
          code: `rcg${stamp}:read`,
          type: 'api',
          module: 'rcg',
        })
      )._id
    );
    _permWriteId = String(
      (
        await Permission.create({
          name: 'RCG写',
          code: `rcg${stamp}:write`,
          type: 'api',
          module: 'rcg',
        })
      )._id
    );

    // --- Super admin user (holds built-in SUPER_ADMIN) ---
    const superUser = await User.create({
      username: `rcgsuper${stamp}`,
      email: `rcgsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superUserId = String(superUser._id);
    superToken = jwt.sign(
      { userId: superUserId, username: superUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // --- Mid-level operator (level 5, holds role CRUD perms but NOT *:*) ---
    const roleCreatePerm = await Permission.findOneAndUpdate(
      { code: 'role:create' },
      { $setOnInsert: { name: '创建角色', code: 'role:create', type: 'api', module: 'role' } },
      { upsert: true, new: true }
    );
    const roleUpdatePerm = await Permission.findOneAndUpdate(
      { code: 'role:update' },
      { $setOnInsert: { name: '更新角色', code: 'role:update', type: 'api', module: 'role' } },
      { upsert: true, new: true }
    );
    const roleAssignPerm = await Permission.findOneAndUpdate(
      { code: 'role:assign' },
      { $setOnInsert: { name: '分配权限', code: 'role:assign', type: 'api', module: 'role' } },
      { upsert: true, new: true }
    );
    const roleDeletePerm = await Permission.findOneAndUpdate(
      { code: 'role:delete' },
      { $setOnInsert: { name: '删除角色', code: 'role:delete', type: 'api', module: 'role' } },
      { upsert: true, new: true }
    );
    const roleReadPerm = await Permission.findOneAndUpdate(
      { code: 'role:read' },
      { $setOnInsert: { name: '读取角色', code: 'role:read', type: 'api', module: 'role' } },
      { upsert: true, new: true }
    );

    const midRole = await Role.create({
      name: '中级_RCG',
      code: `MID_RCG_${stamp.toUpperCase()}`,
      level: 5,
      isBuiltIn: false,
      permissions: [
        roleCreatePerm._id,
        roleUpdatePerm._id,
        roleAssignPerm._id,
        roleDeletePerm._id,
        roleReadPerm._id,
      ],
    });
    midOperatorRoleId = String(midRole._id);
    const midOperator = await User.create({
      username: `rcgmid${stamp}`,
      email: `rcgmid${stamp}@example.com`,
      password: PASSWORD,
      roles: [midRole._id],
    });
    midUserId = String(midOperator._id);
    midToken = jwt.sign(
      { userId: midUserId, username: midOperator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // --- Low-level user (level 2, role:read only) ---
    const lowRole = await Role.create({
      name: '低级_RCG',
      code: `LOW_RCG_${stamp.toUpperCase()}`,
      level: 2,
      isBuiltIn: false,
      permissions: [roleReadPerm._id],
    });
    const lowUser = await User.create({
      username: `rcglow${stamp}`,
      email: `rcglow${stamp}@example.com`,
      password: PASSWORD,
      roles: [lowRole._id],
    });
    lowUserId = String(lowUser._id);
    _lowToken = jwt.sign(
      { userId: lowUserId, username: lowUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Create a custom role for manipulation
    const customRole = await Role.create({
      name: '自定义_RCG',
      code: `CUSTOM_RCG_${stamp.toUpperCase()}`,
      level: 3,
      isBuiltIn: false,
      permissions: [],
    });
    customRoleId = String(customRole._id);

    const { createApp } = require('../../app');
    app = createApp();

    // Inject mock wsService to cover WebSocket emit branches (lines 33-37, 59-62)
    const mockWsService = {
      emitRoleUpdate: jest.fn(),
      emitPermissionUpdate: jest.fn(),
      emitPermissionSync: jest.fn().mockResolvedValue(undefined),
    };
    app.set('wsService', mockWsService);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await Role.deleteMany({ code: new RegExp(`_RCG_${stamp.toUpperCase()}$`) }).catch(() => {});
      await Permission.deleteMany({ code: new RegExp(`rcg${stamp}`) }).catch(() => {});
      await User.deleteMany({
        username: new RegExp(`^rcg(super|mid|low|clone|target|victim)${stamp}$`),
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = (token) => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${token}`),
    post: (url) => request(app).post(url).set('Authorization', `Bearer ${token}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${token}`),
    delete: (url) => request(app).delete(url).set('Authorization', `Bearer ${token}`),
  });

  // ===================== getRoles: search branch (lines 78-79) =====================

  test('getRoles: search parameter triggers $or regex branch', async () => {
    const res = await authed(superToken).get('/api/roles?search=RCG');
    expect(res.status).toBe(200);
    expect(res.body.data).toBeDefined();
  });

  // ===================== createRole non-superadmin branches =====================

  test('createRole: non-superadmin level > operatorMaxLevel → 403 (line 203)', async () => {
    // Mid operator (level 5) tries to create role at level 8
    const res = await authed(midToken)
      .post('/api/roles')
      .send({
        name: '高层级尝试',
        code: `HILEV_${stamp.toUpperCase()}`,
        level: 8,
      });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('无权创建高于自身层级的角色');
  });

  test('createRole: non-superadmin lacking permission subset → 403 (lines 213-218)', async () => {
    // Mid operator has role:* perms but not rcg*:* — try assigning rcg perm
    const res = await authed(midToken)
      .post('/api/roles')
      .send({
        name: '越权授予',
        code: `NOPERM_${stamp.toUpperCase()}`,
        level: 3,
        permissions: [permReadId],
      });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('无权授予以下权限');
  });

  // ===================== updateRole error branches =====================

  test('updateRole: validation errors → 400 (line 256)', async () => {
    // Send invalid name (too long, > 50 chars)
    const res = await authed(superToken)
      .put(`/api/roles/${customRoleId}`)
      .send({ name: 'A'.repeat(51) });
    expect(res.status).toBe(400);
  });

  test('updateRole: role not found → 404 (line 263)', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await authed(superToken).put(`/api/roles/${fakeId}`).send({ name: '不存在' });
    expect(res.status).toBe(404);
  });

  test('updateRole: built-in role status change → 403 (lines 278-279)', async () => {
    const res = await authed(superToken)
      .put(`/api/roles/${builtinSuperId}`)
      .send({ status: 'inactive' });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('内置角色不能修改状态');
  });

  test('updateRole: name trimming works (line 318 path)', async () => {
    const res = await authed(superToken)
      .put(`/api/roles/${customRoleId}`)
      .send({ name: '  已更名_RCG  ' });
    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe('已更名_RCG');
  });

  test('updateRole: non-superadmin level > operatorMaxLevel → 403 (lines 295-301)', async () => {
    // Mid operator (level 5) tries to set custom role to level 8
    const res = await authed(midToken).put(`/api/roles/${customRoleId}`).send({ level: 8 });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('无权将角色层级设置为高于自身层级');
  });

  test('updateRole: non-superadmin touching higher-level role → 403 (lines 303-308)', async () => {
    // Create a level-7 role via superadmin, then mid (level 5) tries to change its level
    const highRole = await Role.create({
      name: '高级_RCG',
      code: `HIGH_RCG_${stamp.toUpperCase()}`,
      level: 7,
      isBuiltIn: false,
    });
    const res = await authed(midToken).put(`/api/roles/${highRole._id}`).send({ level: 4 });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('无权变更高于自身层级的角色');
    await Role.findByIdAndDelete(highRole._id).catch(() => {});
  });

  // ===================== assignPermissions error branches =====================

  test('assignPermissions: validation errors → 400 (line 351)', async () => {
    // Send non-array permissions (triggers express-validator isArray check)
    const res = await authed(superToken)
      .put(`/api/roles/${customRoleId}/permissions`)
      .send({ permissions: 'not-an-array' });
    expect(res.status).toBe(400);
  });

  test('assignPermissions: missing permissions array → 400 (line 357)', async () => {
    // Body without permissions field at all
    const res = await authed(superToken).put(`/api/roles/${customRoleId}/permissions`).send({});
    expect(res.status).toBe(400);
  });

  test('assignPermissions: role not found → 404 (line 362)', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await authed(superToken)
      .put(`/api/roles/${fakeId}/permissions`)
      .send({ permissions: [permReadId] });
    expect(res.status).toBe(404);
  });

  test('assignPermissions: empty permissions array after filter → 400 (line 374)', async () => {
    // Empty array passes isArray() validation but yields uniquePermIds.length === 0
    const res = await authed(superToken)
      .put(`/api/roles/${customRoleId}/permissions`)
      .send({ permissions: [] });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('请提供至少一个有效的权限 ID');
  });

  test('assignPermissions: invalid permission IDs in DB → 400 (line 380)', async () => {
    // Valid ObjectId format but doesn't exist in DB
    const fakePermId = new mongoose.Types.ObjectId().toString();
    const res = await authed(superToken)
      .put(`/api/roles/${customRoleId}/permissions`)
      .send({ permissions: [fakePermId] });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('存在无效的权限 ID');
  });

  test('assignPermissions: non-superadmin level check global mode → 403 (lines 392-394)', async () => {
    // Mid operator (level 5) tries to assign permissions on mid-level role (level 5, >= operatorMaxLevel)
    const res = await authed(midToken)
      .put(`/api/roles/${midOperatorRoleId}/permissions`)
      .send({ permissions: [permReadId] });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('无权修改等于或高于自身层级的角色权限');
  });

  test('assignPermissions: non-superadmin lacking perm subset → 403 (lines 399-404)', async () => {
    // Mid operator tries to assign rcg perm to a lower-level custom role
    // First create a level-3 role owned by nobody
    const lowCustomRole = await Role.create({
      name: '低自_RCG',
      code: `LOWCUST_${stamp.toUpperCase()}`,
      level: 3,
      isBuiltIn: false,
    });
    const res = await authed(midToken)
      .put(`/api/roles/${lowCustomRole._id}/permissions`)
      .send({ permissions: [permReadId] });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('无权分配以下权限');
    await Role.findByIdAndDelete(lowCustomRole._id).catch(() => {});
  });

  // ===================== assignPermissions: clone mode (lines 412-502) =====================

  test('assignPermissions: clone mode — non-built-in role + targetUserId → global mode (not clone)', async () => {
    // Clone mode only activates for built-in roles. For custom roles with targetUserId,
    // it falls through to global mode (line 512+). Verify this doesn't crash.
    const res = await authed(superToken)
      .put(`/api/roles/${customRoleId}/permissions`)
      .send({ permissions: [permReadId], targetUserId: superUserId });
    expect(res.status).toBe(200);
  });

  test('assignPermissions: clone mode — target user not found → 404 (line 419)', async () => {
    let guestRole = await Role.findOne({ code: 'GUEST' });
    if (!guestRole) {
      guestRole = await Role.create({
        name: '访客',
        code: 'GUEST',
        level: 1,
        isBuiltIn: true,
        permissions: [],
      });
    }
    const fakeUserId = new mongoose.Types.ObjectId();
    const res = await authed(superToken)
      .put(`/api/roles/${guestRole._id}/permissions`)
      .send({ permissions: [permReadId], targetUserId: String(fakeUserId) });
    expect(res.status).toBe(404);
    expect(res.body.message).toContain('目标用户不存在');
  });

  test('assignPermissions: clone mode — target user lacks the role → 400 (line 424)', async () => {
    let guestRole = await Role.findOne({ code: 'GUEST' });
    if (!guestRole) {
      guestRole = await Role.create({
        name: '访客',
        code: 'GUEST',
        level: 1,
        isBuiltIn: true,
        permissions: [],
      });
    }
    // Create a user that does NOT hold the guest role
    const noRoleUser = await User.create({
      username: `rcgvictim${stamp}`,
      email: `rcgvictim${stamp}@example.com`,
      password: PASSWORD,
      roles: [],
    });
    const res = await authed(superToken)
      .put(`/api/roles/${guestRole._id}/permissions`)
      .send({ permissions: [permReadId], targetUserId: String(noRoleUser._id) });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('目标用户未持有该角色');
    await User.findByIdAndDelete(noRoleUser._id).catch(() => {});
  });

  test('assignPermissions: clone mode — target same/higher level user → 403 (line 438)', async () => {
    let guestRole = await Role.findOne({ code: 'GUEST' });
    if (!guestRole) {
      guestRole = await Role.create({
        name: '访客',
        code: 'GUEST',
        level: 1,
        isBuiltIn: true,
        permissions: [],
      });
    }
    // Mid operator needs rcg perms to pass subset check (lines 399-404)
    // before reaching target level check (line 438). Grant them temporarily.
    const midRoleDoc = await Role.findById(midOperatorRoleId);
    const origMidPerms = [...midRoleDoc.permissions];
    midRoleDoc.permissions.push(permReadId);
    await midRoleDoc.save();

    // Invalidate permission cache so getPermissions sees the new perm
    const { invalidatePermissionCache } = require('../../services/userPermissionService');
    invalidatePermissionCache(midUserId);

    try {
      // Target user holds guest role AND mid-level role → maxLevel >= operatorMaxLevel
      const highTarget = await User.create({
        username: `rcgtarget${stamp}`,
        email: `rcgtarget${stamp}@example.com`,
        password: PASSWORD,
        roles: [guestRole._id, mongoose.Types.ObjectId.createFromHexString(midOperatorRoleId)],
      });
      const res = await authed(midToken)
        .put(`/api/roles/${guestRole._id}/permissions`)
        .send({ permissions: [permReadId], targetUserId: String(highTarget._id) });
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('无权变更同级或更高级别用户的角色权限');
      await User.findByIdAndDelete(highTarget._id).catch(() => {});
    } finally {
      // Restore mid operator permissions
      midRoleDoc.permissions = origMidPerms;
      await midRoleDoc.save();
      invalidatePermissionCache(midUserId);
    }
  });

  test('assignPermissions: clone mode — SUPER_ADMIN role not clonable → 403 (line 449)', async () => {
    // To reach line 449 (isSuperAdminRole check), we need isSelf=true so line 437 passes.
    // The superadmin targets themselves with the SUPER_ADMIN role in clone mode.
    const res = await authed(superToken)
      .put(`/api/roles/${builtinSuperId}/permissions`)
      .send({ permissions: [permReadId], targetUserId: superUserId });
    expect(res.status).toBe(403);
    expect(res.body.errors?.errorCode).toBe('SUPER_ADMIN_ROLE_NOT_CLONABLE');
  });

  test('assignPermissions: clone mode — successful clone (lines 453-509)', async () => {
    let guestRole = await Role.findOne({ code: 'GUEST' });
    if (!guestRole) {
      guestRole = await Role.create({
        name: '访客',
        code: 'GUEST',
        level: 1,
        isBuiltIn: true,
        permissions: [],
      });
    }
    // Create a low-level target user holding the guest role
    const cloneTarget = await User.create({
      username: `rcgclonetgt${stamp}`,
      email: `rcgclonetgt${stamp}@example.com`,
      password: PASSWORD,
      roles: [guestRole._id],
    });

    const res = await authed(superToken)
      .put(`/api/roles/${guestRole._id}/permissions`)
      .send({ permissions: [permReadId], targetUserId: String(cloneTarget._id) });
    expect(res.status).toBe(200);
    expect(res.body.data.clonedRole).toBeDefined();
    expect(res.body.data.message).toContain('已为');

    // Verify original guest role unchanged
    const refreshedGuest = await Role.findById(guestRole._id);
    expect(refreshedGuest.permissions.map(String)).not.toContain(permReadId);

    await User.findByIdAndDelete(cloneTarget._id).catch(() => {});
    // Clean up cloned role
    const clonedCode = res.body.data.clonedRole.code;
    if (clonedCode) {
      await Role.deleteOne({ code: clonedCode }).catch(() => {});
    }
  });

  // ===================== assignPermissions: super admin role locked (lines 518-519) =====================

  test('assignPermissions: SUPER_ADMIN global mode → 403 (lines 518-519)', async () => {
    const res = await authed(superToken)
      .put(`/api/roles/${builtinSuperId}/permissions`)
      .send({ permissions: [permReadId] });
    expect(res.status).toBe(403);
    expect(res.body.errors?.errorCode).toBe('SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED');
  });

  // ===================== assignPermissions: global mode success + syncPermissionsToUsers (line 553) =====================

  test('assignPermissions: global mode success triggers syncPermissionsToUsers (line 553)', async () => {
    // Create a dedicated custom role and assign a user to it
    const syncRole = await Role.create({
      name: '同步测试_RCG',
      code: `SYNC_RCG_${stamp.toUpperCase()}`,
      level: 3,
      isBuiltIn: false,
    });
    const syncUser = await User.create({
      username: `rcgsyncuser${stamp}`,
      email: `rcgsyncuser${stamp}@example.com`,
      password: PASSWORD,
      roles: [syncRole._id],
    });

    const res = await authed(superToken)
      .put(`/api/roles/${syncRole._id}/permissions`)
      .send({ permissions: [permReadId] });
    expect(res.status).toBe(200);

    // Verify wsService was called
    const wsService = app.get('wsService');
    expect(wsService.emitPermissionUpdate).toHaveBeenCalled();
    expect(wsService.emitPermissionSync).toHaveBeenCalled();

    await User.findByIdAndDelete(syncUser._id).catch(() => {});
    await Role.findByIdAndDelete(syncRole._id).catch(() => {});
  });

  // ===================== deleteRole error branches =====================

  test('deleteRole: role not found → 404 (line 571)', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await authed(superToken).delete(`/api/roles/${fakeId}`);
    expect(res.status).toBe(404);
  });

  test('deleteRole: role in use → 400 (line 581)', async () => {
    // customRoleId is held by nobody yet; create a user holding it
    const holderUser = await User.create({
      username: `rcgholder${stamp}`,
      email: `rcgholder${stamp}@example.com`,
      password: PASSWORD,
      roles: [mongoose.Types.ObjectId.createFromHexString(customRoleId)],
    });
    const res = await authed(superToken).delete(`/api/roles/${customRoleId}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('个用户正在使用该角色');
    await User.findByIdAndDelete(holderUser._id).catch(() => {});
  });

  // ===================== getPermissionTree: parent-child node mounting (lines 651-653) =====================

  test('getPermissionTree: parent-child relationship covered (lines 651-653)', async () => {
    // Create parent permission
    const parentPerm = await Permission.create({
      name: 'RCG父权限',
      code: `rcg${stamp}:parent`,
      type: 'menu',
      module: 'rcg',
    });
    // Create child permission with parent reference
    await Permission.create({
      name: 'RCG子权限',
      code: `rcg${stamp}:child`,
      type: 'button',
      module: 'rcg',
      parent: parentPerm._id,
    });

    const res = await authed(superToken).get('/api/roles/permissions/tree');
    expect(res.status).toBe(200);
    // Find the rcg module in tree
    const rcgModule = res.body.data.find((m) => m.module === 'rcg');
    expect(rcgModule).toBeDefined();

    // Clean up
    await Permission.deleteMany({ code: new RegExp(`rcg${stamp}:(parent|child)`) }).catch(() => {});
  });

  // ===================== emitWebSocketEvent with permissions-updated type (line 35) =====================

  test('emitWebSocketEvent: permissions-updated type uses emitPermissionUpdate (line 35)', async () => {
    const wsService = app.get('wsService');
    wsService.emitPermissionUpdate.mockClear();

    // Trigger permissions-updated event via assignPermissions
    const evtRole = await Role.create({
      name: '事件测试_RCG',
      code: `EVT_RCG_${stamp.toUpperCase()}`,
      level: 3,
      isBuiltIn: false,
    });
    await authed(superToken)
      .put(`/api/roles/${evtRole._id}/permissions`)
      .send({ permissions: [permReadId] });

    expect(wsService.emitPermissionUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'permissions-updated' })
    );

    await Role.findByIdAndDelete(evtRole._id).catch(() => {});
  });

  // ===================== syncPermissionsToUsers failure path (lines 61-62) =====================

  test('syncPermissionsToUsers: emitPermissionSync failure logged but not blocking (lines 61-62)', async () => {
    const wsService = app.get('wsService');
    const origMock = wsService.emitPermissionSync.getMockImplementation();
    wsService.emitPermissionSync.mockRejectedValueOnce(new Error('WS push failed'));

    const failRole = await Role.create({
      name: '故障测试_RCG',
      code: `FAIL_RCG_${stamp.toUpperCase()}`,
      level: 3,
      isBuiltIn: false,
    });
    const failUser = await User.create({
      username: `rcgfailusr${stamp}`,
      email: `rcgfailusr${stamp}@example.com`,
      password: PASSWORD,
      roles: [failRole._id],
    });

    // Should still succeed despite WS push failure
    const res = await authed(superToken)
      .put(`/api/roles/${failRole._id}/permissions`)
      .send({ permissions: [permReadId] });
    expect(res.status).toBe(200);

    // Restore mock
    if (origMock) {
      wsService.emitPermissionSync.mockImplementation(origMock);
    } else {
      wsService.emitPermissionSync.mockResolvedValue(undefined);
    }

    await User.findByIdAndDelete(failUser._id).catch(() => {});
    await Role.findByIdAndDelete(failRole._id).catch(() => {});
  });

  // ===================== assignPermissions: clone mode — non-superadmin level check (line 396-398) =====================

  test('assignPermissions: clone mode non-superadmin role.level > operatorMaxLevel → 403 (lines 396-398)', async () => {
    // Create a built-in role at level 8 (higher than mid operator level 5)
    let highBuiltin = await Role.findOne({ code: 'SECURITY_ADMIN' });
    if (!highBuiltin) {
      highBuiltin = await Role.create({
        name: '安全管理员',
        code: 'SECURITY_ADMIN',
        level: 8,
        isBuiltIn: true,
        permissions: [],
      });
    }
    // Create target user holding this high built-in role
    const highTarget = await User.create({
      username: `rcghightgt${stamp}`,
      email: `rcghightgt${stamp}@example.com`,
      password: PASSWORD,
      roles: [highBuiltin._id],
    });

    const res = await authed(midToken)
      .put(`/api/roles/${highBuiltin._id}/permissions`)
      .send({ permissions: [permReadId], targetUserId: String(highTarget._id) });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('无权基于高于自身层级的角色调整权限');

    await User.findByIdAndDelete(highTarget._id).catch(() => {});
  });

  // ===================== Successful create + delete for completeness =====================

  test('deleteRole: successful deletion of unused custom role', async () => {
    const delRole = await Role.create({
      name: '待删_RCG',
      code: `DEL_RCG_${stamp.toUpperCase()}`,
      level: 2,
      isBuiltIn: false,
    });
    const res = await authed(superToken).delete(`/api/roles/${delRole._id}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toContain('角色删除成功');

    // Verify wsService.emitRoleUpdate was called for deletion
    const wsService = app.get('wsService');
    expect(wsService.emitRoleUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'role-deleted' })
    );
  });
});
