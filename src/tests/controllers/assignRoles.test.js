/**
 * assignRoles 越权防护 + 超管唯一性不变量集成测试
 *
 * 背景一（M-01）：此前 assignRoles 仅校验"被分配角色的层级"，未校验"目标用户的层级"，
 * SECURITY_ADMIN(level 8) 可将内置超级管理员(level 10) 的角色替换为 GUEST，
 * 实现管理员权限剥离。
 *
 * 背景二（超管唯一性）：原超管保护带 `!isSelf` 例外，超管可剥离自己的超管角色，
 * 而剥离后无任何接口能修回（层级校验拦下所有针对 level=10 的操作），构成自锁死。
 * 实测生产数据确实出现了「SUPER_ADMIN 角色存在但 0 个持有者」的状态。
 *
 * 两组用例合并在同一文件：SUPER_ADMIN 的 code 有 unique 索引，
 * 拆分到不同测试文件会在并行执行时撞 E11000。
 *
 * P3-51 补记：上述 E11000 的根因已修复（src/tests/setup.js 现按
 * JEST_WORKER_ID 分配独立数据库，并行套件不再共享同一个库）。
 * 此处保持合并只是因为两组用例共用同一套 fixture，拆分收益不大——
 * 但「必须合并否则撞索引」这一约束已经不成立。
 */

const request = require('supertest');

// 所有夹具同部门：让范围闸放行，从而把断言打在层级/权限闸上
const SCOPE_DEPT = 'SECDEPT';
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('assignRoles 越权防护（M-01）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let operator; // SECURITY_ADMIN 操作者
  let superAdmin; // 内置超级管理员（目标）
  let lowUser; // 无角色的低层级用户（合法操作对照）
  let guestRole;
  let superRoleRef; // 超管角色引用（超管唯一性用例复用）
  let operatorToken;
  let superToken; // 超管本人令牌（自锁死路径用例）

  beforeAll(async () => {
    // worker 进程必须先连接内存数据库（authenticate 会查黑名单/用户）
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    // ---- 构造 RBAC 固件 ----
    const assignPerm = await Permission.create({
      name: '分配角色',
      code: 'role:assign',
      type: 'api',
      module: 'system',
    });
    // 超管的 *:* 通配权限：超管唯一性用例需要超管本人能过 checkPermission。
    // 用 upsert 而非 create：`*:*` 的 code 有 unique 索引，userStats.test.js 也会
    // 播种同一条记录，并行执行时 create 会撞 E11000
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );

    const superRole = await Role.create({
      name: '超级管理员',
      code: 'SUPER_ADMIN',
      level: 10,
      isBuiltIn: true,
      permissions: [wildcardPerm._id],
    });
    superRoleRef = superRole;
    const secRole = await Role.create({
      name: '安全管理员',
      code: 'SECURITY_ADMIN',
      level: 8,
      isBuiltIn: true,
      permissions: [assignPerm._id],
    });
    guestRole = await Role.create({
      name: '访客',
      code: 'GUEST',
      level: 1,
      isBuiltIn: true,
    });

    superAdmin = await User.create({
      username: 'sa_target',
      email: 'sa@example.com',
      password: 'Test@1234567',
      // 夹具必须落在操作者的数据范围内（同部门或其创建），否则范围闸先拒，测不到本该测的闸
      department: SCOPE_DEPT,
      roles: [superRole._id],
    });
    operator = await User.create({
      username: 'sec_operator',
      email: 'sec@example.com',
      password: 'Test@1234567',
      // 夹具必须落在操作者的数据范围内（同部门或其创建），否则范围闸先拒，测不到本该测的闸
      department: SCOPE_DEPT,
      roles: [secRole._id],
    });
    lowUser = await User.create({
      username: 'low_user',
      email: 'low@example.com',
      password: 'Test@1234567',
      // 夹具必须落在操作者的数据范围内（同部门或其创建），否则范围闸先拒，测不到本该测的闸
      department: SCOPE_DEPT,
      roles: [],
    });

    operatorToken = jwt.sign(
      { userId: String(operator._id), username: 'sec_operator', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    superToken = jwt.sign(
      { userId: String(superAdmin._id), username: 'sa_target', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('SECURITY_ADMIN 不得剥离内置超级管理员的角色（目标层级保护）', async () => {
    const res = await request(app)
      .put(`/api/users/${superAdmin._id}/roles`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send({ roles: [String(guestRole._id)] });
    // 实测确定行为（P1-29 修复：原为 expect([403,400]).toContain —— 400 属校验类拒绝，与本用例
    // 「层级保护」语义无关，双可能断言会掩盖拦截原因的漂移且断言过宽）；实测 403 层级拒绝
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_ROLE_ASSIGN_PEER_OR_HIGHER_FORBIDDEN');
    const after = await User.findById(superAdmin._id).select('roles');
    expect(after.roles.map(String)).not.toContain(String(guestRole._id));
  });

  test('SECURITY_ADMIN 不得变更同级（level 8）用户的角色', async () => {
    const peer = await User.create({
      username: 'sec_peer',
      email: 'peer@example.com',
      password: 'Test@1234567',
      // 夹具必须落在操作者的数据范围内（同部门或其创建），否则范围闸先拒，测不到本该测的闸
      department: SCOPE_DEPT,
      roles: [(await Role.findOne({ code: 'SECURITY_ADMIN' }))._id],
    });
    const res = await request(app)
      .put(`/api/users/${peer._id}/roles`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send({ roles: [String(guestRole._id)] });
    expect(res.status).toBe(403);
    // 403 必须点名角色分配闸：同级保护/数据范围/权限子集都会 403，
    // 不点名就分不清是哪道闸挡下的（更无法发现「闸门被换掉」）
    expect(res.body.errors.errorCode).toBe('USER_ROLE_ASSIGN_PEER_OR_HIGHER_FORBIDDEN');
    // 且角色集合必须原样（403 不等于「先写后报错」）：与请求前的取值逐项比对，
    // 而不是断言某个具体角色——同级闸若被绕过，roles 会变成 [guestRole]
    const peerAfter = await User.findById(peer._id).select('roles').lean();
    expect(peerAfter.roles.map(String)).toEqual(peer.roles.map(String));
    expect(peerAfter.roles.map(String)).not.toContain(String(guestRole._id));
  });

  test('SECURITY_ADMIN 仍可给低层级用户分配不高于自身层级的角色（合法路径不受影响）', async () => {
    const res = await request(app)
      .put(`/api/users/${lowUser._id}/roles`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send({ roles: [String(guestRole._id)] });
    expect(res.status).toBe(200);
    const after = await User.findById(lowUser._id).select('roles');
    expect(after.roles.map(String)).toContain(String(guestRole._id));
  });

  test('SECURITY_ADMIN 不得分配高于自身层级的角色（既有防护不回归）', async () => {
    const superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    const res = await request(app)
      .put(`/api/users/${lowUser._id}/roles`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send({ roles: [String(superRole._id)] });
    expect(res.status).toBe(403);
    // 「不得超过自身层级」这条闸有独立错误码，与上面的目标侧层级闸区分
    expect(res.body.errors.errorCode).toBe('ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN');
    // 越权分配必须没写库
    const lowAfter = await User.findById(lowUser._id).select('roles').lean();
    expect(lowAfter.roles.map(String)).not.toContain(String(superRole._id));
  });

  // ===== 后端复审 B-2：同级角色归属（纵深防御）=====
  //
  // 这组用例区分「必须拒」与「必须放行」两侧。B-2 最初实现要求
  // 「分配的角色必须全部属于操作者自身」，把上面那条合法路径
  // （SECURITY_ADMIN 授予 GUEST）一并封死了 —— 一道会拦正常业务的闸门
  // 最终只会被绕过或删掉，不如从一开始就把边界划准。
  describe('B-2 同级角色归属包含校验', () => {
    let peerAdminToken;
    let peerRoleA;
    let peerRoleB;
    let peerRoleWide; // 同级 + 携带操作者没有的权限（用于闸门顺序对照）
    let victim;

    beforeAll(async () => {
      const devicePerm = await Permission.findOneAndUpdate(
        { code: 'device:delete' },
        {
          $setOnInsert: { name: '删除设备', code: 'device:delete', type: 'api', module: 'device' },
        },
        { upsert: true, new: true }
      );
      const assignPerm = await Permission.findOne({ code: 'role:assign' });

      // 两个同级（level 6）但分管不同模块的角色
      peerRoleA = await Role.create({
        name: '同级管理员A',
        code: 'PEER_ADMIN_A',
        level: 6,
        permissions: [assignPerm._id],
      });
      peerRoleB = await Role.create({
        name: '同级管理员B',
        code: 'PEER_ADMIN_B',
        level: 6,
        // 权限集与 A **完全相同**（只有 code/name 不同）。原先这里多挂了 devicePerm，
        // 于是请求先被上一层的 P2-8 权限子集校验以 PERMISSION_GRANT_FORBIDDEN 拦掉，
        // B-2 这条「同级角色归属」闸门根本没执行过——用例只断 403，看不出是谁拦的。
        // 实测：把 userController 里 B-2 整段（含 ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN）
        // 删掉，本文件当时全绿，且该错误码在全仓测试里出现 0 次。
        permissions: [assignPerm._id],
      });

      // 对照角色：同级**且**权限比自己宽 —— 两道闸门都该拦，但只有先撞上的那道
      // 会被执行。单独测它，才能证明上一条用例改的是对的闸门。
      peerRoleWide = await Role.create({
        name: '同级管理员B-宽权限',
        code: 'PEER_ADMIN_B_WIDE',
        level: 6,
        permissions: [assignPerm._id, devicePerm._id],
      });

      const peerAdmin = await User.create({
        username: 'peer_admin_a',
        email: 'peer_a@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [peerRoleA._id],
      });
      peerAdminToken = jwt.sign(
        { userId: String(peerAdmin._id), username: 'peer_admin_a', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      victim = await User.create({
        username: 'peer_victim',
        email: 'peer_victim@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        // B-2 的操作者是 level 6 ⇒ 数据范围是 self，只能管自己创建的账户
        createdBy: peerAdmin._id,
        roles: [],
      });
    });

    // 本组三条用例共用一个 victim，而「放行」那条会把 level 6 的角色真的写进去；
    // 此后 victim 自身的最高层级就等于操作者（6），**目标侧**层级闸
    // （USER_ROLE_ASSIGN_PEER_OR_HIGHER_FORBIDDEN）会先于 B-2 与 P2-8 拦下请求。
    // 原用例只断 403，看不出被哪道闸拦的，于是这条耦合在固定顺序下一直隐身；
    // 换成点名错误码的断言后，--randomize 换个 seed 就红。逐条重置起点才是正解。
    beforeEach(async () => {
      await User.findByIdAndUpdate(victim._id, { $set: { roles: [] } });
    });

    test('不得分配自身未持有的同级角色（同级横向扩权被切断）', async () => {
      // A 把 B 的角色挂到别人身上，是「互挂对方角色集齐双方权限」的第一步。
      // 层级校验放行（6 不大于 6），权限子集校验也放行（B 的权限集与 A 相同），
      // 因此**必须**由 B-2 拦下——错误码点名，才能证明拦它的是 B-2 而不是上一层闸门。
      const res = await request(app)
        .put(`/api/users/${victim._id}/roles`)
        .set('Authorization', `Bearer ${peerAdminToken}`)
        .send({ roles: [String(peerRoleB._id)] });

      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN');
      const after = await User.findById(victim._id).select('roles');
      expect(after.roles.map(String)).not.toContain(String(peerRoleB._id));
    });

    test('同级且权限更宽时由 P2-8 先拦（闸门执行顺序的显式记录）', async () => {
      // 与上一条只差"角色多带一个自己没有的权限"：这一条走 PERMISSION_GRANT_FORBIDDEN。
      // 两条并排放，是为了让"谁先拦"变成被钉住的事实——将来有人调整闸门顺序或删掉
      // 其中一道，必有一条用例红，而不是像原先那样两道闸门共用一个 403 谁也分不清。
      const res = await request(app)
        .put(`/api/users/${victim._id}/roles`)
        .set('Authorization', `Bearer ${peerAdminToken}`)
        .send({ roles: [String(peerRoleWide._id)] });

      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('PERMISSION_GRANT_FORBIDDEN');
      const after = await User.findById(victim._id).select('roles');
      expect(after.roles.map(String)).not.toContain(String(peerRoleWide._id));
    });

    test('可分配自身持有的同级角色（归属成立即放行）', async () => {
      const res = await request(app)
        .put(`/api/users/${victim._id}/roles`)
        .set('Authorization', `Bearer ${peerAdminToken}`)
        .send({ roles: [String(peerRoleA._id)] });

      expect(res.status).toBe(200);
      const after = await User.findById(victim._id).select('roles');
      expect(after.roles.map(String)).toContain(String(peerRoleA._id));
    });

    test('可分配低于自身层级且自己未持有的角色（不逼管理员囤积角色）', async () => {
      // 这正是最初实现误拦的路径：GUEST(level 1) 操作者并不持有，
      // 但授予它不会给目标带来操作者没有的权限，由 P2-8 子集校验兜住。
      //
      // 用独立的目标账户：上一条用例已把 victim 提到 level 6（同级），
      // 复用它会先被「不得变更同级或更高级用户」的目标层级保护拦下，
      // 得到一个与本用例意图无关的 403 —— 用例之间的状态耦合会让
      // 断言在通过与失败之间取决于执行顺序。
      const fresh = await User.create({
        username: 'peer_fresh',
        email: 'peer_fresh@example.com',
        password: 'Test@1234567',
        // 操作者是 level 6 ⇒ self 档；victim 的属主就是本组操作者，直接继承
        createdBy: victim.createdBy,
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [],
      });
      const res = await request(app)
        .put(`/api/users/${fresh._id}/roles`)
        .set('Authorization', `Bearer ${peerAdminToken}`)
        .send({ roles: [String(guestRole._id)] });

      expect(res.status).toBe(200);
      const after = await User.findById(fresh._id).select('roles');
      expect(after.roles.map(String)).toContain(String(guestRole._id));
    });
  });

  // ===== 超管唯一且不可更改 =====
  describe('超管唯一且不可更改', () => {
    test('超管不得剥离自己的超管角色（原 !isSelf 例外造成的自锁死路径）', async () => {
      const res = await request(app)
        .put(`/api/users/${superAdmin._id}/roles`)
        .set('Authorization', `Bearer ${superToken}`)
        .send({ roles: [String(guestRole._id)] });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('不可被剥离');

      const after = await User.findById(superAdmin._id).select('roles');
      expect(after.roles.map(String)).toContain(String(superRoleRef._id));
    });

    test('超管不得把超管角色授予他人（保唯一性）', async () => {
      const target = await User.create({
        username: 'sa_grantee',
        email: 'grantee@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [guestRole._id],
      });
      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set('Authorization', `Bearer ${superToken}`)
        .send({ roles: [String(guestRole._id), String(superRoleRef._id)] });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('不可被授予');

      const after = await User.findById(target._id).select('roles');
      expect(after.roles.map(String)).not.toContain(String(superRoleRef._id));
    });

    test('超管仍可正常调整他人的非超管角色（合法路径不受影响）', async () => {
      const target = await User.create({
        username: 'sa_normal',
        email: 'normal@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [],
      });
      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set('Authorization', `Bearer ${superToken}`)
        .send({ roles: [String(guestRole._id)] });

      expect(res.status).toBe(200);
      const after = await User.findById(target._id).select('roles');
      expect(after.roles.map(String)).toContain(String(guestRole._id));
    });

    test('创建用户时携带超管角色被拒（层级校验对超管本人不生效，需专项拦截）', async () => {
      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${superToken}`)
        .send({
          username: 'sa_second',
          email: 'sa_second@example.com',
          password: 'Vn6$Rw83pKx5',
          roles: [String(superRoleRef._id)],
        });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('只允许存在一位超级管理员');
      expect(await User.findOne({ username: 'sa_second' })).toBeNull();
    });

    test('超管账户不可被置为 inactive（含自己，禁用后无人能恢复）', async () => {
      const res = await request(app)
        .put(`/api/users/${superAdmin._id}`)
        .set('Authorization', `Bearer ${superToken}`)
        .send({ status: 'inactive' });

      expect(res.status).toBe(403);
      // 三个超管守卫码各不相同，点名「禁用」这一条；
      // 下面已有 status 仍为 active 的行为断言，两者合起来才说明「拒了且没改」
      expect(res.body.errors.errorCode).toBe('CANNOT_DISABLE_SUPER_ADMIN');
      const after = await User.findById(superAdmin._id).select('status');
      expect(after.status).toBe('active');
    });

    test('超管账户不可被删除（另一超管发起同样拒绝）', async () => {
      const other = await User.create({
        username: 'sa_deleter',
        email: 'deleter@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [superRoleRef._id],
      });
      const token = jwt.sign(
        { userId: String(other._id), username: 'sa_deleter', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      const res = await request(app)
        .delete(`/api/users/${superAdmin._id}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(403);
      expect(await User.findById(superAdmin._id)).not.toBeNull();
      await User.deleteOne({ _id: other._id });
    });

    test('批量删除含超管账户时整批拒绝（不成为单个删除保护的绕过路径）', async () => {
      const other = await User.create({
        username: 'sa_batch',
        email: 'batch@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [superRoleRef._id],
      });
      const token = jwt.sign(
        { userId: String(other._id), username: 'sa_batch', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      const victim = await User.create({
        username: 'sa_victim',
        email: 'victim@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [guestRole._id],
      });

      const res = await request(app)
        .delete('/api/users/batch')
        .set('Authorization', `Bearer ${token}`)
        .send({ ids: [String(victim._id), String(superAdmin._id)] });

      expect(res.status).toBe(403);
      // 整批拒绝：同批次的普通用户也不应被删除
      expect(await User.findById(victim._id)).not.toBeNull();
      expect(await User.findById(superAdmin._id)).not.toBeNull();

      await User.deleteMany({ _id: { $in: [other._id, victim._id] } });
    });
  });

  // ===== 启动期归属对账（唯一的归属写入口）=====
  describe('角色层级双向拦截（P1-1 先降级再自挂提权链）', () => {
    let richRole; // 超管预建的 level 9 富权限角色（攻击目标）
    let midToken; // 持 role:update + role:assign 的中层管理员

    beforeAll(async () => {
      const updatePerm = await Permission.findOneAndUpdate(
        { code: 'role:update' },
        { $setOnInsert: { name: '更新角色', code: 'role:update', type: 'api', module: 'system' } },
        { upsert: true, new: true }
      );
      const assignPerm = await Permission.findOne({ code: 'role:assign' });

      // 攻击者：level 5，同时持有 role:update 与 role:assign
      const midRole = await Role.create({
        name: '中层管理员',
        code: 'MID_ADMIN_ESC',
        level: 5,
        permissions: [updatePerm._id, assignPerm._id],
      });
      const midUser = await User.create({
        username: 'mid_escalate',
        email: 'mid_esc@example.com',
        password: 'Test@1234567',
        // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
        // 让范围闸先拒，本该被测的层级/权限闸根本走不到
        department: SCOPE_DEPT,
        roles: [midRole._id],
      });
      midToken = jwt.sign(
        { userId: String(midUser._id), username: 'mid_escalate', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      // 目标：非内置的 level 9 富权限角色（内置角色的 level 已被单独锁死）
      richRole = await Role.create({
        name: '富权限角色',
        code: 'RICH_ROLE_ESC',
        level: 9,
        permissions: [updatePerm._id, assignPerm._id],
      });
    });

    test('不得把高于自身层级的角色降级（提权链第一步即被切断）', async () => {
      const res = await request(app)
        .put(`/api/roles/${richRole._id}`)
        .set('Authorization', `Bearer ${midToken}`)
        .send({ level: 5 });

      expect(res.status).toBe(403);
      // 层级未被改动，后续「自挂」步骤失去前提
      const after = await Role.findById(richRole._id).select('level');
      expect(after.level).toBe(9);
    });

    test('升方向防护不回归：不得把角色提到高于自身层级', async () => {
      const ownRole = await Role.create({
        name: '自有低级角色',
        code: 'OWN_LOW_ESC',
        level: 3,
      });
      const res = await request(app)
        .put(`/api/roles/${ownRole._id}`)
        .set('Authorization', `Bearer ${midToken}`)
        .send({ level: 9 });

      expect(res.status).toBe(403);
      expect((await Role.findById(ownRole._id).select('level')).level).toBe(3);
    });

    test('管辖范围内的层级调整仍然放行（合法路径不受影响）', async () => {
      const ownRole = await Role.create({
        name: '可管角色',
        code: 'MANAGEABLE_ESC',
        level: 4,
      });
      const res = await request(app)
        .put(`/api/roles/${ownRole._id}`)
        .set('Authorization', `Bearer ${midToken}`)
        .send({ level: 2 });

      expect(res.status).toBe(200);
      expect((await Role.findById(ownRole._id).select('level')).level).toBe(2);
    });

    test('不改 level 时不触发层级校验（仅改描述应放行）', async () => {
      const ownRole = await Role.create({
        name: '仅改描述',
        code: 'DESC_ONLY_ESC',
        level: 4,
      });
      const res = await request(app)
        .put(`/api/roles/${ownRole._id}`)
        .set('Authorization', `Bearer ${midToken}`)
        .send({ description: '仅更新描述' });

      expect(res.status).toBe(200);
      // 「放行」的判据是描述真的改了、且 level 没被动过：
      // 若实现误把 level 也重置，只断 200 不会红
      expect(res.body.data.description).toBe('仅更新描述');
      expect(res.body.data.level).toBe(4);
    });
  });

  describe('reconcileSuperAdmin 启动自愈', () => {
    const withTargetUsername = async (username, fn) => {
      const original = process.env.SUPER_ADMIN_USERNAME;
      process.env.SUPER_ADMIN_USERNAME = username;
      try {
        await fn();
      } finally {
        if (original === undefined) delete process.env.SUPER_ADMIN_USERNAME;
        else process.env.SUPER_ADMIN_USERNAME = original;
      }
    };

    test('归属丢失（0 持有者）时补回超管角色', async () => {
      await withTargetUsername('sa_target', async () => {
        await User.updateOne({ _id: superAdmin._id }, { $pull: { roles: superRoleRef._id } });
        const before = await User.findById(superAdmin._id).select('roles');
        expect(before.roles.map(String)).not.toContain(String(superRoleRef._id));

        const { reconcileSuperAdmin } = require('../../services/initData');
        await reconcileSuperAdmin();

        const after = await User.findById(superAdmin._id).select('roles');
        expect(after.roles.map(String)).toContain(String(superRoleRef._id));
      });
    });

    test('归属扩散（多持有者）时剥离非授权账户', async () => {
      await withTargetUsername('sa_target', async () => {
        const extra = await User.create({
          username: 'sa_extra',
          email: 'extra@example.com',
          password: 'Test@1234567',
          // 部门档管理员只能管同部门用户（rbac.isRecordInScope）：不给部门就等于
          // 让范围闸先拒，本该被测的层级/权限闸根本走不到
          department: SCOPE_DEPT,
          roles: [superRoleRef._id],
        });

        const { reconcileSuperAdmin } = require('../../services/initData');
        await reconcileSuperAdmin();

        const extraAfter = await User.findById(extra._id).select('roles');
        expect(extraAfter.roles.map(String)).not.toContain(String(superRoleRef._id));
        const saAfter = await User.findById(superAdmin._id).select('roles');
        expect(saAfter.roles.map(String)).toContain(String(superRoleRef._id));

        await User.deleteOne({ _id: extra._id });
      });
    });

    test('目标账户不存在时不创建账户、不抛异常', async () => {
      await withTargetUsername('no_such_admin_zz', async () => {
        // P3-51：worker 库隔离生效后，全集合计数断言不再被并行套件干扰，
        // 因此恢复更强的断言——「总数不变」能覆盖「创建了别的名字的账户」，
        // 而只查目标用户名覆盖不到这种情况。
        // （此前该断言随机失败：多 worker 共享单一内存库，期望 16 实得 17）
        const { reconcileSuperAdmin } = require('../../services/initData');
        const before = await User.countDocuments({});
        await expect(reconcileSuperAdmin()).resolves.toBeUndefined();
        expect(await User.countDocuments({})).toBe(before);
        expect(await User.findOne({ username: 'no_such_admin_zz' })).toBeNull();
      });
    });

    test('isBuiltIn 被篡改为 false 时强制修正（否则全部超管保护静默失效）', async () => {
      await withTargetUsername('sa_target', async () => {
        await Role.updateOne({ _id: superRoleRef._id }, { $set: { isBuiltIn: false } });

        const { reconcileSuperAdmin } = require('../../services/initData');
        await reconcileSuperAdmin();

        const after = await Role.findById(superRoleRef._id).select('isBuiltIn');
        expect(after.isBuiltIn).toBe(true);
      });
    });
  });

  describe('createUser 权限子集闸门（建号侧 P2-8：与 assignRoles 共用同一实现）', () => {
    // 实测依据（2026-09-24 变异 MN）：把 `userController.js` 建号侧的
    // `if (!operatorPermCodes.includes('*:*'))` 整段短路 ⇒ **全套 335 套件 / 3821 例
    // 全绿**。也就是说这道"不得授予自身不持有的权限"的闸门，此前在全仓没有任何用例
    // 经过它——assignRoles 侧有 4 条（本文件的 P2-8 与 B-2 两组），建号侧一条都没有。
    // 而建号与分配角色是**同一件事的两个入口**：都能把带新权限的角色挂到账号上。
    const ensurePermission = (code, name) =>
      Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { name, code, type: 'api', module: 'system' } },
        { upsert: true, new: true }
      );

    const makeOperator = async () => {
      const createPerm = await ensurePermission('user:create', '建号');
      const acctRole = await Role.create({
        name: 'ZZQ 账号管理员',
        code: 'ACCT_ADMIN',
        level: 7,
        permissions: [createPerm._id],
      });
      const op = await User.create({
        username: 'acct_op',
        email: 'acct_op@example.com',
        password: 'Test@1234567',
        department: SCOPE_DEPT,
        roles: [acctRole._id],
      });
      const token = jwt.sign(
        { userId: String(op._id), username: 'acct_op', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      return { token, createPerm };
    };

    afterEach(async () => {
      await User.deleteMany({ username: /^(acct_op|escalated|normal)$/ });
      await Role.deleteMany({ code: /^(ACCT_ADMIN|FAT_ROLE|NARROW_ROLE)$/ });
    });

    test('挂一个"自身不持有其权限"的低层级角色：建号被拒且账号不落库', async () => {
      const { token } = await makeOperator();
      // 层级 3 < 操作者 7 ⇒ 层级闸放行；不是超管 ⇒ 超管闸放行；
      // 唯一能拦住它的就是权限子集闸。
      const configPerm = await ensurePermission('security:config', '安全配置');
      const fatRole = await Role.create({
        name: 'ZZQ 富权限角色',
        code: 'FAT_ROLE',
        level: 3,
        permissions: [configPerm._id],
      });

      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${token}`)
        .send({
          username: 'escalated',
          email: 'escalated@example.com',
          password: 'Vn6$Rw83pKx5',
          department: SCOPE_DEPT,
          roles: [String(fatRole._id)],
        });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('security:config');
      expect(await User.findOne({ username: 'escalated' })).toBeNull();
    });

    // 对照组：闸门只拦"自身没有的权限"。删掉上一段代码它照样绿，
    // 但它保证没人把建号闸改成"逢角色必拒"来糊弄那条 403。
    test('挂一个权限全在自身集合内的角色仍放行（闸不误伤正常建号）', async () => {
      const { token, createPerm } = await makeOperator();
      const narrowRole = await Role.create({
        name: 'ZZQ 窄权限角色',
        code: 'NARROW_ROLE',
        level: 3,
        permissions: [createPerm._id],
      });

      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${token}`)
        .send({
          username: 'normal',
          // 邮箱不能复用 normal@example.com：本文件前部 sa_normal 用例占用了它，
          // 去前缀改名时撞上邮箱唯一索引会让本用例 400（邮箱已被使用）
          email: 'normal-narrow@example.com',
          password: 'Vn6$Rw83pKx5',
          department: SCOPE_DEPT,
          roles: [String(narrowRole._id)],
        });

      expect(res.status).toBe(201);
      const created = await User.findOne({ username: 'normal' });
      expect(created).not.toBeNull();
      expect(created.roles.map(String)).toContain(String(narrowRole._id));
    });
  });
});
