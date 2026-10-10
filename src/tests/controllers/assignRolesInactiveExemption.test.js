/**
 * P2-8 权限子集校验：「排除集」只能认生效角色与生效权限
 *
 * 子集校验的形状是：本次要授予的权限码集合 − 目标已持有的码集合 ⊆ 操作者持有的码集合。
 * 减数（排除集）存在的理由是"收权时目标的权限可以多于操作者"。
 * 但排除集若把**停用**角色/停用权限也算作"目标已持有"，就出现一条静默绕过：
 * 操作者并不持有码 X，目标身上只有一条**停用**的角色带着 X ⇒ X 被减掉 ⇒ 校验通过 ⇒
 * 授予成功。此后管理员把那条角色/权限重新启用，X 就落地成了
 * "操作者从不持有、却由他授出"的权限——正是 P2-8 要消灭的横向扩权路径。
 *
 * 判据与操作者侧同口径：`userPermissionService.getPermissions` 只算 `status:'active'`。
 *
 * 两个实测踩过的坑（写给改这个文件的人）：
 *  · `Permission.code` 有 `lowercase` 归一化，夹具里写 `zzq:auditA` 存进去是 `zzq:audita`，
 *    用原串去 `toContain` 永远不命中——权限码一律小写。
 *  · `ApiResponse.codeError` 把 `params` 摊平进 `errors`（不是 `errors.details.params`）。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const SCOPE_DEPT = 'ZZQINACT';
const CODE_A = 'zzq:audita';
const CODE_B = 'zzq:auditb';

describe('assignRoles 排除集只认生效角色/生效权限', () => {
  let app;
  let User;
  let Role;
  let operatorToken;
  let grantRoleA; // 生效角色，只带 CODE_A
  let grantRoleB; // 生效角色，只带 CODE_B（该权限自身是停用的）
  let targetViaInactiveRole;
  let targetViaActiveRole;
  let targetViaInactivePerm;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const assignPerm = await Permission.create({
      name: '分配角色',
      code: 'role:assign',
      type: 'api',
      module: 'system',
    });
    // 争议权限：A 挂在停用角色上；B 自身停用、挂在生效角色上
    const [permA, permB] = await Permission.create([
      { name: 'A', code: CODE_A, type: 'api', module: 'zzq' },
      { name: 'B', code: CODE_B, type: 'api', module: 'zzq', status: 'inactive' },
    ]);

    const opRole = await Role.create({
      name: 'ZZQ 操作者',
      code: 'ZZQ_INACT_OP',
      level: 8,
      permissions: [assignPerm._id],
    });
    const inactiveRole = await Role.create({
      name: 'ZZQ 停用角色',
      code: 'ZZQ_INACT_ROLE',
      level: 5,
      status: 'inactive',
      permissions: [permA._id],
    });
    const activeRole = await Role.create({
      name: 'ZZQ 生效角色',
      code: 'ZZQ_INACT_ACTIVEROLE',
      level: 5,
      permissions: [permA._id],
    });
    const permInactiveRole = await Role.create({
      name: 'ZZQ 含停用权限角色',
      code: 'ZZQ_INACT_PERMROLE',
      level: 5,
      permissions: [permB._id],
    });
    grantRoleA = await Role.create({
      name: 'ZZQ 被授予角色A',
      code: 'ZZQ_INACT_GRANTA',
      level: 5,
      permissions: [permA._id],
    });
    grantRoleB = await Role.create({
      name: 'ZZQ 被授予角色B',
      code: 'ZZQ_INACT_GRANTB',
      level: 5,
      permissions: [permB._id],
    });

    const mk = async (username, roles) =>
      User.create({
        username,
        email: `${username}@example.com`,
        password: 'Test@1234567',
        department: SCOPE_DEPT,
        roles,
      });
    const operator = await mk('zzq_inact_op', [opRole._id]);
    targetViaInactiveRole = await mk('zzq_inact_t1', [inactiveRole._id]);
    targetViaActiveRole = await mk('zzq_inact_t2', [activeRole._id]);
    targetViaInactivePerm = await mk('zzq_inact_t3', [permInactiveRole._id]);

    operatorToken = jwt.sign(
      { userId: String(operator._id), username: 'zzq_inact_op', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const assign = (target, grantRole) =>
    request(app)
      .put(`/api/users/${target._id}/roles`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send({ roles: [String(grantRole._id)] });

  test('目标只以「停用角色」持有的权限码不算已持有：必须 403 且角色未变', async () => {
    const res = await assign(targetViaInactiveRole, grantRoleA);
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('PERMISSION_GRANT_FORBIDDEN');
    expect(res.body.errors.permissions).toContain(CODE_A);
    const after = await User.findById(targetViaInactiveRole._id).select('roles');
    expect(after.roles.map(String)).not.toContain(String(grantRoleA._id));
  });

  test('目标只以「停用权限」持有的权限码同样不算：必须 403', async () => {
    const res = await assign(targetViaInactivePerm, grantRoleB);
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('PERMISSION_GRANT_FORBIDDEN');
    expect(res.body.errors.permissions).toContain(CODE_B);
  });

  test('反向对照：目标以「生效角色」实际持有该码时排除集仍然生效（不得收紧成一律拒绝）', async () => {
    const res = await assign(targetViaActiveRole, grantRoleA);
    expect(res.status).toBe(200);
    const after = await User.findById(targetViaActiveRole._id).select('roles');
    expect(after.roles.map(String)).toContain(String(grantRoleA._id));
  });

  test('前提取证：停用侧确实不进 getPermissions，而旧的不滤版本会把它算进排除集', async () => {
    const userService = require('../../services/userService');
    const target = targetViaInactiveRole;

    // 操作者侧口径：只有 active 参与授权
    const operatorHeld = await userService.getPermissions(target._id);
    expect(operatorHeld).not.toContain(CODE_A);

    // 修复后的排除集：不含停用角色的权限码
    const exempt = await userService.findActiveRolePermissionDocs(target.roles);
    expect(JSON.stringify(exempt)).not.toContain(CODE_A);
    // 修复前用的版本：确实含该码 ⇒ 证明它当初会被减掉（不是"原来也没洞"）
    const unfiltered = await userService.findRolePermissionDocs(target.roles);
    expect(JSON.stringify(unfiltered)).toContain(CODE_A);
  });
});
