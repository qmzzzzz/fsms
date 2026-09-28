/**
 * 超管不得经"新建角色"接口铸出第二个 `*:*` 角色
 *
 * 缺陷形态（读码即确认）：roleController.createRole 里
 *   const isSuperAdmin = operatorPermCodes.includes('*:*');
 *   if (!isSuperAdmin) {
 *     ...
 *     if (validPerms.some((perm) => perm.code === '*:*')) return codeError('CANNOT_GRANT_WILDCARD_PERMISSION');
 *   }
 * 通配检查被关在 `if (!isSuperAdmin)` 里 ⇒ **超管**走的是"整块跳过"的路径，
 * 于是 POST /api/roles 带 `permissions:[<*:* 的 id>]` 会成功建出一个挂通配的新角色。
 * `utils/superAdmin.js:9-21` 把「内置超管角色唯一」定为系统不变量（归属扩散 ⇒
 * 审计上无法界定最终责任人；归属丢失 ⇒ 无接口可恢复），这条路径上它完全失效。
 *
 * 同型缺陷已在 rolePermissionController.js:63-77（**分配**路径）修复并有套件
 * reservedWildcardAssignment.test.js 覆盖；本文件补的是**铸造**路径。
 *
 * 用例覆盖四面：
 *  1) 攻击面：超管建挂 `*:*` 的角色 ⇒ 403，且**落库态**里没有该角色
 *  2) 混合请求：同批既有普通权限又有 `*:*` ⇒ 整批拒绝（不得部分放行）
 *  3) 反向保护：超管建带普通权限的角色仍成功（防线不得扩大成"超管什么都不能建"）
 *  4) 反向保护：`permissions` 省略/为空时仍成功（新逻辑不得误伤"不带权限建角色"）
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { RESERVED_WILDCARD_PERMISSION } = require('../utils/superAdmin');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

const stamp = `zzd3${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);
const PASSWORD = randomPassword();
/**
 * 角色 code 的字符集是 `^[A-Z_]+$`（roleRoutes.js:37）——**不允许数字**。
 * 所以 stamp 里的数字必须先映射成字母，否则每条用例都会先被 400 拦掉，
 * 得到"看起来在测防线、其实什么都没测到"的假绿。
 * （既有的 reservedWildcardAssignment.test.js 用 `Role.create` 直连建角色、
 *  绕过路由校验，因此没暴露这一点；本文件走真实 HTTP，必须守这个约束。）
 */
const codeStamp = stamp.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]).toUpperCase();
const codeFor = (suffix) => `${codeStamp}${suffix}`.toUpperCase().replace(/[^A-Z_]/g, '_');

describe('保留通配的铸造防线（POST /api/roles）', () => {
  let app;
  let Permission;
  let Role;
  let User;
  let wildcardId;
  let normalPermId;
  let superRoleId;
  let superToken;
  let createdSuper = false;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Permission = require('../models/Permission');
    Role = require('../models/Role');
    User = require('../models/User');
    require('../models/TokenBlacklist');
    require('../models/AuditLog');

    const mkPerm = (code) =>
      Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { name: `权限_${code}`, code, type: 'api', module: code.split(':')[0] } },
        { upsert: true, new: true }
      );
    const wildcard = await mkPerm(RESERVED_WILDCARD_PERMISSION);
    const normal = await mkPerm(`${stamp.slice(2)}:read`);
    wildcardId = String(wildcard._id);
    normalPermId = String(normal._id);

    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    createdSuper = !superRole;
    if (createdSuper) {
      superRole = await Role.create({
        name: `超管_${stamp}`,
        code: 'SUPER_ADMIN',
        level: 10,
        isBuiltIn: true,
        permissions: [wildcard._id],
      });
    } else if (!(superRole.permissions || []).map(String).includes(wildcardId)) {
      // 复用系统里既有的内置超管角色时，必须确保它确实持有通配——否则本文件要测的
      // "超管早返回通道"根本不成立（权限不足会以 403 的另一种原因通过，形成假绿）
      await Role.updateOne({ _id: superRole._id }, { $push: { permissions: wildcard._id } });
    }
    superRoleId = String(superRole._id);

    const boss = await User.create({
      username: `${stamp}boss`,
      email: `${stamp}boss@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superToken = jwt.sign(
      { userId: String(boss._id), username: boss.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    // 只清自己造的东西：`*:*` 权限与内置 SUPER_ADMIN 可能是 initData 播种的共享状态，
    // 同一 jest run 里其它套件（globalSetup 共享库）会依赖它们。
    await Role.deleteMany({ code: new RegExp(`^${stamp}`, 'i') }).catch(() => {});
    if (createdSuper) {
      await Role.deleteMany({ _id: superRoleId, code: 'SUPER_ADMIN' }).catch(() => {});
    }
    await Permission.deleteMany({ _id: normalPermId }).catch(() => {});
    await User.deleteMany({ username: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const createRole = (payload, token = superToken) =>
    request(app).post('/api/roles').set('Authorization', `Bearer ${token}`).send(payload);

  const roleByCode = (code) => Role.findOne({ code }).lean();

  test('夹具：超管确实持有通配（否则本文件的攻击面根本不成立）', async () => {
    const superRole = await Role.findById(superRoleId).select('permissions').lean();
    expect((superRole.permissions || []).map(String)).toContain(wildcardId);
  });

  test('★ 超管建挂 *:* 的角色必须 403，且不得落库', async () => {
    const code = codeFor('wild');
    const res = await createRole({
      name: `偷渡通配_${stamp}`,
      code,
      level: 3,
      permissions: [wildcardId],
    });
    expect(res.status).toBe(403);
    expect(await roleByCode(code)).toBeNull();
  });

  test('混合请求也拦：同批既有普通权限又有 *:* 时整批拒绝（不得部分放行）', async () => {
    const code = codeFor('mix');
    const res = await createRole({
      name: `混合_${stamp}`,
      code,
      level: 3,
      permissions: [normalPermId, wildcardId],
    });
    expect(res.status).toBe(403);
    expect(await roleByCode(code)).toBeNull();
  });

  test('反向保护：超管建带普通权限的角色仍成功（防线不得扩大成"什么都不能建"）', async () => {
    const code = codeFor('ok');
    const res = await createRole({
      name: `正常_${stamp}`,
      code,
      level: 3,
      permissions: [normalPermId],
    });
    expect(res.status).toBe(201);
    const persisted = await roleByCode(code);
    expect(persisted).not.toBeNull();
    expect((persisted.permissions || []).map(String)).toEqual([normalPermId]);
  });

  test('反向保护：不带 permissions 的角色仍可建（新逻辑不得误伤该分支）', async () => {
    const code = codeFor('bare');
    const res = await createRole({ name: `空权限_${stamp}`, code, level: 2 });
    expect(res.status).toBe(201);
    const persisted = await roleByCode(code);
    expect(persisted).not.toBeNull();
    expect(persisted.permissions || []).toEqual([]);
  });
});
