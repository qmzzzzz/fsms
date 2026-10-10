/**
 * `PUT /api/roles/:id/permissions` 的 targetUserId 克隆分支必须有数据范围闸
 *
 * 缺陷原貌：`findTargetUserInScope()` 函数名里有 `InScope`，实现的却只有
 * ①ID 合法 ②用户存在 ③确实持有被操作角色 ④**层级**比较，
 * 从头到尾没有调用过 `assertRecordInScope`。而它的返回值直接进了
 * `cloneBuiltInRoleForUser` → `updateUserRoles(targetUser._id, ...)`，
 * 也就是一次**跨用户 roles 数组的写操作**。
 *
 * 同一能力从另一个入口进来是有闸的：`userController.assignRoles`
 * （`src/controllers/userController.js:683`）在动 `roles` 之前先跑
 * `assertRecordInScope(req, user, 'createdBy', 'department')`，不在范围即
 * `USER_SCOPE_FORBIDDEN`。两条路由挂的权限码完全相同（都只有 `role:assign`），
 * 差别仅在这道范围闸——于是部门域操作者可以改**别的部门**用户的角色，
 * 而同一份改动走"编辑用户角色"接口会被 403。本仓对该闸的定性见
 * `userController.js:599` 附近注释："层级校验管能不能碰这个人，
 * 范围校验管这个人是否在你的可见域内——两者正交"。
 *
 * 夹具刻意让层级差与范围差不重合（操作者 L7 / 目标 L3 ⇒ 层级闸放行），
 * 这样"红/绿"只可能由数据范围闸解释。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('克隆内置角色给他人：targetUser 必须落在操作者的数据范围内', () => {
  let app;
  let User;
  let Role;
  let Permission;

  const stamp = `sc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  let deptToken; // L7 部门主管，数据范围 department='东区'
  let operatorId;
  let builtinRoleEastId; // 东区目标用户持有的内置角色
  let builtinRoleHqId; // 总部目标用户持有的内置角色
  let eastTargetId;
  let hqTargetId;
  let grantablePermId;
  let roleAssignPermId; // 'role:assign' 的 permission id，mkUser 组操作者角色时引用

  const mkUser = async (username, level, department, roleIds, opts = {}) => {
    const role = await Role.create({
      name: `范围闸角色_${username}`,
      code: `SC${level}_${username}`.toUpperCase(),
      level,
      isBuiltIn: false,
      permissions: opts.grantAssign ? [roleAssignPermId, grantablePermId] : [],
    });
    return User.create({
      username,
      email: `${username}@example.com`,
      password: PASSWORD,
      department,
      ...(opts.createdBy ? { createdBy: opts.createdBy } : {}),
      roles: [...roleIds, role._id],
    });
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const mkPerm = async (name, code) =>
      (await Permission.create({ name, code, type: 'api', module: code.split(':')[0] }))._id;

    roleAssignPermId = String(await mkPerm('分配权限', 'role:assign'));
    grantablePermId = String(await mkPerm(`范围闸可授_${stamp}`, `sc${stamp}:read`));

    const mkBuiltin = async (suffix) => {
      const role = await Role.create({
        name: `范围闸内置_${suffix}`,
        code: `SCBI_${suffix}_${stamp}`.toUpperCase(),
        level: 3,
        isBuiltIn: true,
        permissions: [grantablePermId],
      });
      return String(role._id);
    };
    builtinRoleEastId = await mkBuiltin('east');
    builtinRoleHqId = await mkBuiltin('hq');

    const operator = await mkUser(`scline${stamp}`, 7, '东区', [], { grantAssign: true });
    operatorId = String(operator._id);
    deptToken = jwt.sign(
      { userId: operatorId, username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 两个目标用户只差一个部门：层级同为 3（低于操作者的 7），都持同名内置角色
    eastTargetId = String((await mkUser(`sceast${stamp}`, 3, '东区', [builtinRoleEastId]))._id);
    hqTargetId = String((await mkUser(`schq${stamp}`, 3, '总部', [builtinRoleHqId]))._id);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const signFor = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  /** self 档用例专用：内置 L3 角色（克隆分支的入口条件是 role.isBuiltIn） */
  const mkSelfBuiltin = async (suffix) => {
    const role = await Role.create({
      name: `范围闸内置_${suffix}`,
      code: `SCBIS_${suffix}_${stamp}`.toUpperCase(),
      level: 3,
      isBuiltIn: true,
      permissions: [grantablePermId],
    });
    return String(role._id);
  };

  const put = (token, roleId, body) =>
    request(app)
      .put(`/api/roles/${roleId}/permissions`)
      .set('Authorization', `Bearer ${token}`)
      .send(body);

  const rolesOf = async (userId) =>
    (await User.findById(userId).select('roles').lean()).roles.map(String);

  /**
   * "拒绝必须没写库"的取证方式。客户端拿到 403 不代表服务端停了手：
   * 漏掉 `return null` 的实现会先发 403、再把克隆流程走完（目标 roles 被改写 +
   * 库里多出一个克隆角色），而**只读一次**读到的很可能是写完之前那一瞬 —— 变异自检
   * 里正是这样让"发 403 但不拦"的实现漏网的。故在 600ms 内反复采样，任一样本偏离即红。
   */
  const stayUnchanged = async (userId, beforeRoles, beforeRoleCount) => {
    const deadline = Date.now() + 600;
    for (;;) {
      expect(await rolesOf(userId)).toEqual(beforeRoles);
      expect(await Role.countDocuments({})).toBe(beforeRoleCount);
      if (Date.now() >= deadline) return;
      await new Promise((resolve) => setTimeout(resolve, 60));
    }
  };

  test('跨部门目标用户：403 且其 roles 一字未改（缺陷现场：此前 200 + 已被换成克隆角色）', async () => {
    const before = await rolesOf(hqTargetId);
    expect(before).toContain(builtinRoleHqId);
    const roleCount = await Role.countDocuments({});

    const res = await put(deptToken, builtinRoleHqId, {
      permissions: [grantablePermId],
      targetUserId: hqTargetId,
    });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
    await stayUnchanged(hqTargetId, before, roleCount);
  });

  test('同部门目标用户：合法克隆照常成功（闸不能顺手把正路也关掉）', async () => {
    const before = await rolesOf(eastTargetId);

    const res = await put(deptToken, builtinRoleEastId, {
      permissions: [grantablePermId],
      targetUserId: eastTargetId,
    });

    expect(res.status).toBe(200);
    const after = await rolesOf(eastTargetId);
    expect(after).not.toContain(builtinRoleEastId);
    expect(after.length).toBe(before.length);
    // 克隆出来的新角色必须真的归该用户所有，且不是内置角色
    const cloned = await Role.findById(after.find((id) => !before.includes(id)));
    expect(cloned).toBeTruthy();
    expect(cloned.isBuiltIn).toBe(false);
  });

  test('判据只可能来自范围：同一 token 对总部用户走"编辑用户角色"入口本来就是 403', async () => {
    // 这条是**对照**而不是重复：它证明两个入口对同一动作的结论在修复后一致，
    // 而不是本线新加了一道比原口径更严的闸。
    const res = await request(app)
      .put(`/api/users/${hqTargetId}/roles`)
      .set('Authorization', `Bearer ${deptToken}`)
      .send({ roles: [builtinRoleHqId] });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
  });

  test('操作者本人：自克隆不因新闸被误伤（isSelf 一路的既有豁免口径保持）', async () => {
    const selfBuiltin = await Role.create({
      name: `范围闸内置_self`,
      code: `SCBI_SELF_${stamp}`.toUpperCase(),
      level: 3,
      isBuiltIn: true,
      permissions: [grantablePermId],
    });
    await User.findByIdAndUpdate(operatorId, { $push: { roles: selfBuiltin._id } });

    const before = await rolesOf(operatorId);
    expect(before).toContain(String(selfBuiltin._id));

    const res = await put(deptToken, String(selfBuiltin._id), {
      permissions: [grantablePermId],
      targetUserId: operatorId,
    });

    expect(res.status).toBe(200);
    // 自己的 roles 被换成克隆角色 = 走通了克隆分支（isSelf 豁免由
    // rbac.isRecordInScope 的"自己的记录永远在自己范围内"提供，不在本线新写一份）
    const after = await rolesOf(operatorId);
    expect(after).not.toContain(String(selfBuiltin._id));
    expect(after.length).toBe(before.length);
  });

  // 上面四条全在 department 档（L7）取证，而 assertRecordInScope 的 ownerField
  // 只在 self 档才被读到 —— 只测 department 档时把 ownerField/departmentField 传反
  // 也是全绿。下面两条把 self 档的两个臂钉住：ownerField 写错方向即红。
  test('self 档操作者对自己创建的用户：照常可克隆（ownerField 必须真的被用上）', async () => {
    const flat = await mkUser(`scflat${stamp}`, 4, '东区', [], { grantAssign: true });
    const flatToken = signFor(flat);
    const builtin = await mkSelfBuiltin('sub');
    const sub = await mkUser(`scsub${stamp}`, 3, '东区', [builtin], { createdBy: flat._id });

    const res = await put(flatToken, builtin, {
      permissions: [grantablePermId],
      targetUserId: String(sub._id),
    });

    expect(res.status).toBe(200);
    const after = await rolesOf(String(sub._id));
    expect(after).not.toContain(builtin);
  });

  test('self 档操作者对别人创建的用户：403（同部门、低层级都救不了，缺陷原貌为 200）', async () => {
    const flat2 = await mkUser(`scflat2${stamp}`, 4, '东区', [], { grantAssign: true });
    const builtin = await mkSelfBuiltin('stranger');
    // createdBy 指向另一个真实用户：证明拦下它的是"不是属主"，而不是字段缺失/CastError
    const stranger = await mkUser(`scar${stamp}`, 3, '东区', [builtin], {
      createdBy: operatorId,
    });

    const before = await rolesOf(String(stranger._id));
    expect(before).toContain(builtin);
    const roleCount = await Role.countDocuments({});

    const res = await put(signFor(flat2), builtin, {
      permissions: [grantablePermId],
      targetUserId: String(stranger._id),
    });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
    await stayUnchanged(String(stranger._id), before, roleCount);
  });

  // 变异自检的反查产物：把克隆分支里那道「目标用户同级/上级」层级闸整块摘除，
  // 本仓**原有**四套角色相关用例全绿——该判定此前零覆盖。范围闸与层级闸正交，
  // 补在同一个夹具里成本最低（同一入口、同一分支），故登记于此。
  test('范围内但同层级的目标用户：仍须被层级闸拦住（403 且没写库）', async () => {
    const builtin = await mkSelfBuiltin('peer');
    // 同部门（范围闸放行）+ 自身最高层级 7（与操作者持平 → 层级闸该拦）
    const peer = await mkUser(`scpeer${stamp}`, 7, '东区', [builtin]);
    const before = await rolesOf(String(peer._id));
    expect(before).toContain(builtin);
    const roleCount = await Role.countDocuments({});

    const res = await put(deptToken, builtin, {
      permissions: [grantablePermId],
      targetUserId: String(peer._id),
    });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN');
    await stayUnchanged(String(peer._id), before, roleCount);
  });
});
