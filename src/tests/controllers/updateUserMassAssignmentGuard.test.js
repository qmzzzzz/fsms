/**
 * updateUser / createUser 特权字段批量赋值（mass assignment）防护回归
 *
 * 攻击链来源（nu11cyber 实证打法 → 本系统映射）：
 *   靶机上 PATCH /members/{id} 不校验归属即可改任意用户（含创始人账号）的
 *   password / level / role，一次请求接管最高权限。本系统对应的两个写入口是
 *   PUT /api/users/:id（updateUser）与 POST /api/users（createUser），二者均以
 *   「显式解构 + 逐字段赋值」收口：updateUser 只取 realName/email/phone/
 *   department/avatar/status/allowedIPs，createUser 另列明 createdBy 由服务端
 *   注入。请求体里的 password / roles / tokenVersion / createdBy / mfaEnabled /
 *   lockUntil / failedLoginCount 不在解构清单内，被静默忽略。
 *
 * 本文件把这条链固化为三组断言：
 *   ① 字段白名单：特权字段一律不落库（口令哈希、角色引用、会话吊销版本号、
 *      审计属主、MFA 开关、爆破锁定状态逐项不变），白名单字段照常生效——
 *      闸门不能退化成「整个接口不可用」；
 *   ② IDOR/提权链：低层级操作者改高层级用户（含内置超管）连白名单字段都摸不到，
 *      403 点名 USER_UPDATE_PEER_OR_HIGHER_FORBIDDEN，且目标的数据逐项不变；
 *   ③ 建号轨同口径：POST /api/users 携带的特权字段不进入新文档。
 *
 * 与 assignRoles.test.js 的分工：那份钉「派角色」授权轨的层级/同级/权限子集闸，
 * 本文件钉「改资料」轨的字段白名单与 IDOR 链。两份合起来覆盖 nu11cyber 上
 * 打通的 members 篡改链在本系统的全部入口。
 */

const request = require('supertest');
const fs = require('fs');
const path = require('path');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

// 所有夹具同部门：让数据范围闸放行，从而把断言打在层级/字段闸上
const SCOPE_DEPT = 'MASSDEPT';
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('updateUser/createUser 特权字段批量赋值防护', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let operator; // SECURITY_ADMIN 操作者（持 user:update + user:create）
  let superAdmin; // 内置超级管理员（IDOR 目标）
  let lowUser; // 低层级用户（字段白名单目标）
  let guestRole;
  let superRole;
  let operatorToken;

  beforeAll(async () => {
    // worker 进程必须先连接内存数据库（authenticate 会查黑名单/用户）
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const updatePerm = await Permission.create({
      name: '更新用户',
      code: 'user:update',
      type: 'api',
      module: 'system',
    });
    const createPerm = await Permission.create({
      name: '创建用户',
      code: 'user:create',
      type: 'api',
      module: 'system',
    });
    // 超管的 *:* 通配权限：IDOR 对照组需要超管本人能过 checkPermission。
    // upsert 而非 create：`*:*` 的 code 有 unique 索引，与并行套件共存
    // （同 assignRoles.test.js 口径）
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );

    superRole = await Role.create({
      name: '超级管理员',
      code: 'SUPER_ADMIN',
      level: 10,
      isBuiltIn: true,
      permissions: [wildcardPerm._id],
    });
    const secRole = await Role.create({
      name: '安全管理员',
      code: 'SECURITY_ADMIN',
      level: 8,
      isBuiltIn: true,
      permissions: [updatePerm._id, createPerm._id],
    });
    guestRole = await Role.create({
      name: '访客',
      code: 'GUEST',
      level: 1,
      isBuiltIn: true,
    });

    superAdmin = await User.create({
      username: 'sa_mass_target',
      email: 'sa_mass@example.com',
      password: 'Test@1234567',
      department: SCOPE_DEPT,
      roles: [superRole._id],
    });
    operator = await User.create({
      username: 'sec_mass_operator',
      email: 'sec_mass@example.com',
      password: 'Test@1234567',
      department: SCOPE_DEPT,
      roles: [secRole._id],
    });
    lowUser = await User.create({
      username: 'low_mass_target',
      email: 'low_mass@example.com',
      password: 'Test@1234567',
      department: SCOPE_DEPT,
      roles: [guestRole._id],
      createdBy: operator._id,
    });

    operatorToken = jwt.sign(
      { userId: String(operator._id), username: 'sec_mass_operator', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /**
   * nu11cyber 上实证打通的载荷：一次 PUT 同时摸 password / roles / level /
   * tokenVersion / createdBy / mfaEnabled / lockUntil / failedLoginCount。
   * 本系统应有的表现：只有 realName 落地，其余原样。
   */
  const privilegedPayload = () => ({
    realName: '合法改名',
    password: 'Hacked@123456',
    roles: [String(superRole._id)],
    level: 99,
    tokenVersion: 999,
    createdBy: String(superAdmin._id),
    mfaEnabled: true,
    lockUntil: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    failedLoginCount: 0,
  });

  test('① 字段白名单：特权字段不落库，白名单字段照常生效', async () => {
    const before = await User.findById(lowUser._id).select('+password').lean();

    const res = await request(app)
      .put(`/api/users/${lowUser._id}`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send(privilegedPayload());

    expect(res.status).toBe(200);
    // 白名单内的字段必须真的写进去——否则这道闸只是把接口整个打死，
    // 运营会立刻想办法绕开它（与 deviceUpdateFieldParity 同一判据）
    expect(res.body.data.realName).toBe('合法改名');

    const after = await User.findById(lowUser._id).select('+password').lean();
    // 口令：哈希逐字节不变 ⇒ 载荷里的 password 从未进入赋值链
    // （靶机正是靠这一格完成创始人账号接管）
    expect(after.password).toBe(before.password);
    // 角色引用不变 ⇒ 无法借通用更新接口把超管角色挂到任何账户
    expect(after.roles.map(String)).toEqual(before.roles.map(String));
    // 会话吊销版本号不变 ⇒ 无法作废他人全部令牌，也无法反向"解锁"
    expect(after.tokenVersion).toBe(0);
    // 审计属主不变 ⇒ 无法把账户"送人"（数据范围随 createdBy 走）
    expect(String(after.createdBy)).toBe(String(operator._id));
    // MFA 开关与爆破锁定状态不变 ⇒ 无法伪造/绕过二次验证、无法解锁被爆破账户
    expect(after.mfaEnabled).toBe(false);
    expect(after.lockUntil).toBeNull();
    expect(after.failedLoginCount).toBe(0);
    // level 不是 User 文档字段（层级在 Role 上），静默忽略即无此键
    expect(after.level).toBeUndefined();

    // 端到端确认口令未被触碰：旧口令仍可用、载荷口令不可用
    const withHash = await User.findById(lowUser._id).select('+password');
    expect(await withHash.comparePassword('Test@1234567')).toBe(true);
    expect(await withHash.comparePassword('Hacked@123456')).toBe(false);
  });

  test('② IDOR 链：低层级操作者改内置超管 → 403 且超管数据逐项不变', async () => {
    const before = await User.findById(superAdmin._id).select('+password').lean();

    const res = await request(app)
      .put(`/api/users/${superAdmin._id}`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send(privilegedPayload());

    // 403 必须点名层级闸：范围闸/权限子集也会 403，不点名就分不清
    // 是哪道闸挡下的（更无法发现「闸门被换掉」）
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_UPDATE_PEER_OR_HIGHER_FORBIDDEN');

    const after = await User.findById(superAdmin._id).select('+password').lean();
    expect(after.password).toBe(before.password);
    expect(after.roles.map(String)).toEqual(before.roles.map(String));
    expect(after.status).toBe(before.status);
    expect(after.realName).toBe(before.realName);
    expect(after.tokenVersion).toBe(before.tokenVersion);
  });

  test('②b 同层目标同样拒：level 8 操作者改 level 8 用户 → 403', async () => {
    const peer = await User.create({
      username: 'sec_mass_peer',
      email: 'peer_mass@example.com',
      password: 'Test@1234567',
      department: SCOPE_DEPT,
      roles: [(await Role.findOne({ code: 'SECURITY_ADMIN' }))._id],
    });

    const res = await request(app)
      .put(`/api/users/${peer._id}`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send({ realName: '同级也不给改' });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_UPDATE_PEER_OR_HIGHER_FORBIDDEN');
    const after = await User.findById(peer._id).select('realName').lean();
    expect(after.realName).not.toBe('同级也不给改');
  });

  test('③ 建号轨同口径：POST /api/users 携带的特权字段不进入新文档', async () => {
    const stamp = `${Date.now()}${Math.floor(Math.random() * 1e6)}`;
    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${operatorToken}`)
      .send({
        username: `mass_probe_${stamp}`,
        email: `mass_probe_${stamp}@example.com`,
        password: randomPassword(),
        realName: '批量赋值探针',
        department: SCOPE_DEPT,
        roles: [String(guestRole._id)],
        // 以下全部应被忽略
        status: 'inactive',
        tokenVersion: 999,
        createdBy: String(superAdmin._id),
        mfaEnabled: true,
        failedLoginCount: 42,
      });

    expect(res.status).toBe(201);
    const created = await User.findOne({ username: `mass_probe_${stamp}` })
      .select('+password')
      .lean();
    expect(created).not.toBeNull();
    expect(created.status).toBe('active');
    expect(created.tokenVersion).toBe(0);
    expect(created.mfaEnabled).toBe(false);
    expect(created.failedLoginCount).toBe(0);
    // 建号属主必须是操作者本人（服务端注入），不是载荷里"送"出去的超管
    expect(String(created.createdBy)).toBe(String(operator._id));
    // 口令走明文轨 → bcrypt 落库，载荷无法预置哈希
    expect(created.password).toMatch(/^\$2[aby]\$/);
  });
  // ===== 字段口径对账：路由校验 ↔ 控制器解构 =====
  //
  // 与 deviceUpdateFieldParity.test.js 同一判据，换到 user 更新轨：
  // 「路由校验了某字段」暗示该字段可更新，控制器若不解构它，就是静默丢弃
  // （前端假成功）；反向，控制器解构了路由没校验的字段，就是一条未校验的写入面。
  // 第三组断言把特权字段钉在白名单外——批量赋值防护不能只靠今天恰好没人写错。
  describe('updateUser 字段口径对账（防静默丢弃 / 防未校验写入）', () => {
    const routeSrc = fs
      .readFileSync(path.resolve(__dirname, '../../routes/userRoutes.js'), 'utf8')
      .replace(/\r\n/g, '\n');
    const controllerSrc = fs
      .readFileSync(path.resolve(__dirname, '../../controllers/userController/update.js'), 'utf8')
      .replace(/\r\n/g, '\n');

    /** updateUserValidation 这一段里校验过的字段名（含 mustBeString 与引用的校验器常量） */
    const routeValidatedFields = () => {
      const start = routeSrc.indexOf('const updateUserValidation');
      expect(start).toBeGreaterThan(-1);
      const rest = routeSrc.slice(start);
      const endRel = rest.slice(1).search(/\n(?:const|module\.exports)\b/);
      const block = endRel === -1 ? rest : rest.slice(0, endRel + 1);
      const fields = new Set();
      for (const m of block.matchAll(/body\('([^']+)'\)/g)) fields.add(m[1]);
      for (const m of block.matchAll(/mustBeString\('([^']+)'/g)) fields.add(m[1]);
      // 块内以标识符引用的校验器（如 allowedIPsCheck）：取其定义处的 body('X')
      for (const m of block.matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*),?\s*$/gm)) {
        const def = routeSrc.match(new RegExp(`const ${m[1]} = ([\\s\\S]*?);\\n`));
        if (def) {
          for (const b of def[1].matchAll(/body\('([^']+)'\)/g)) fields.add(b[1]);
        }
      }
      return [...fields];
    };

    /** updateUser 函数体内 `const { ... } = req.body` 解构出的字段 */
    const controllerDestructuredFields = () => {
      const fnStart = controllerSrc.indexOf('const updateUser = asyncHandler');
      expect(fnStart).toBeGreaterThan(-1);
      const fnSrc = controllerSrc.slice(fnStart);
      const endRel = fnSrc.slice(1).search(/\nconst [a-zA-Z]/);
      const fnBody = endRel === -1 ? fnSrc : fnSrc.slice(0, endRel + 1);
      const destructure = fnBody.match(/const \{([^}]+)\} = req\.body;/);
      expect(destructure).not.toBeNull();
      return destructure[1]
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    };

    const EXPECTED_FIELDS = [
      'allowedIPs',
      'avatar',
      'department',
      'email',
      'phone',
      'realName',
      'status',
    ];

    test('前提自证：两侧都解析到预期的 7 个字段（否则差集为空是解析失效的假绿）', () => {
      expect(routeValidatedFields().sort()).toEqual([...EXPECTED_FIELDS].sort());
      expect(controllerDestructuredFields().sort()).toEqual([...EXPECTED_FIELDS].sort());
    });

    test('路由校验过的字段，控制器必须解构（校验存在暗示可更新，不得静默丢弃）', () => {
      const destructured = new Set(controllerDestructuredFields());
      const silentlyDropped = routeValidatedFields().filter((f) => !destructured.has(f));
      expect(silentlyDropped).toEqual([]);
    });

    test('控制器解构的字段，路由必须校验（不得存在未校验的写入面）', () => {
      const validated = new Set(routeValidatedFields());
      const unvalidated = controllerDestructuredFields().filter((f) => !validated.has(f));
      expect(unvalidated).toEqual([]);
    });

    test('特权字段永不出现在解构清单里（批量赋值防护的静态钉）', () => {
      const PRIVILEGED_FIELDS = [
        'password',
        'passwordHistory',
        'roles',
        'level',
        'tokenVersion',
        'createdBy',
        'mfaEnabled',
        'mfaSecret',
        'mfaRecoveryCodes',
        'lockUntil',
        'failedLoginCount',
      ];
      const leaked = controllerDestructuredFields().filter((f) => PRIVILEGED_FIELDS.includes(f));
      expect(leaked).toEqual([]);
    });
  });
});
