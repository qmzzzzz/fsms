/**
 * 超管不得经"分配权限"接口铸出第二个 `*:*` 角色
 *
 * 缺陷形态（读码即确认）：rolePermissionController.validatePermissionTargets 里
 *   const isSuperAdmin = operatorPermCodes.includes('*:*');
 *   if (isSuperAdmin) return {...};          // ← 早返回，跳过下面全部提权校验
 * 于是内置超管把 `*:*` 这个 permission id 直接 PUT 给任意自定义角色就能成功：
 * createRole 里精心守住的"内置超管角色唯一"不变式（防归属扩散、防自锁）
 * 在 assign 这条路径上完全没设防——等于凭空多出一个全权限角色。
 *
 * 用例覆盖三面：
 *  1) 攻击面：超管把 `*:*` 给非内置角色 ⇒ 403 且**落库态**里没有 `*:*`
 *  2) 反向保护：超管分配普通权限仍可成功（防线不得变成"超管什么都不能分配"）
 *  3) 自锁保护：内置超管角色自身重新断言 `*:*` 仍允许（否则修法会锁死唯一超管）
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { RESERVED_WILDCARD_PERMISSION } = require('../utils/superAdmin');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

const stamp = `zzd2${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);
const PASSWORD = randomPassword();

describe('保留通配的分配防线', () => {
  let app;
  let Permission;
  let Role;
  let User;
  let wildcardId;
  let normalPermId;
  let superRoleId;
  let targetRoleId;
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
      // 复用系统里既有的内置超管角色时，确保它确实持有通配（否则本文件要测的
      // "超管早返回通道"根本不成立，用例会以另一种方式红）
      await Role.updateOne({ _id: superRole._id }, { $push: { permissions: wildcard._id } });
    }
    const targetRole = await Role.create({
      name: `自定义_${stamp}`,
      code: `CUSTOM_${stamp}`.replace(/[^A-Z0-9_]/g, '_').toUpperCase(),
      level: 3,
      isBuiltIn: false,
      permissions: [],
    });
    superRoleId = String(superRole._id);
    targetRoleId = String(targetRole._id);

    const boss = await User.create({
      username: `${stamp}boss`,
      email: `${stamp}boss@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superToken = jwt.sign(
      { userId: String(boss._id), username: boss.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    // 只清自己造的东西：`*:*` 权限与内置 SUPER_ADMIN 可能是 initData 播种的共享状态，
    // 同一 jest run 里其它套件（内存库是 globalSetup 共享的）会依赖它们。
    await Role.deleteMany({ _id: targetRoleId }).catch(() => {});
    if (createdSuper) {
      await Role.deleteMany({ _id: superRoleId, code: 'SUPER_ADMIN' }).catch(() => {});
    }
    await Permission.deleteMany({ _id: normalPermId }).catch(() => {});
    await User.deleteMany({ username: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const assign = (roleId, permissions, token = superToken) =>
    request(app)
      .put(`/api/roles/${roleId}/permissions`)
      .set('Authorization', `Bearer ${token}`)
      .send({ permissions });

  const permsOfTarget = async () => {
    const r = await Role.findById(targetRoleId).select('permissions').lean();
    return (r.permissions || []).map(String);
  };

  /**
   * 每条用例前把目标角色的权限重置为空。
   *
   * 原写法把「目标角色当前没有任何权限」当成用例序列里的**第一条**，
   * 但 `jest --randomize` 连文件内顺序一起打散：一旦本文件的 assign 用例
   * （例如"反向保护：超管分配普通权限仍可成功"）先跑，它就会真的把
   * normalPermId 写进 targetRoleId，那条前置断言必红（实测单文件 + 同一 seed
   * 即可复现，与跨套件污染无关）。前置状态必须由 beforeEach 建立，
   * 不能靠"排在前面"来保证。
   */
  beforeEach(async () => {
    await Role.updateOne({ _id: targetRoleId }, { $set: { permissions: [] } });
    expect(await permsOfTarget()).toEqual([]);
  });

  test('夹具：目标角色当前没有任何权限（否则"未含通配"是假绿）', async () => {
    expect(await permsOfTarget()).toEqual([]);
  });

  test('★ 超管把 *:* 分配给非内置角色必须 403，且不得落库', async () => {
    const res = await assign(targetRoleId, [wildcardId]);
    expect(res.status).toBe(403);
    expect(await permsOfTarget()).not.toContain(wildcardId);
  });

  test('混合请求也拦：同批里既有普通权限又有 *:* 时整批拒绝（不得部分放行）', async () => {
    const res = await assign(targetRoleId, [normalPermId, wildcardId]);
    expect(res.status).toBe(403);
    expect(await permsOfTarget()).toEqual([]);
  });

  test('反向保护：超管分配普通权限仍成功（防线不得扩大成"什么都不能分配"）', async () => {
    const res = await assign(targetRoleId, [normalPermId]);
    expect(res.status).toBe(200);
    expect(await permsOfTarget()).toContain(normalPermId);
  });

  test('不给"内置超管角色自己"开口子：对超管角色分配 *:* 同样 403', async () => {
    // 本接口后面还有既有的 SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED——超管角色的权限
    // 本来就不许经此改写。所以"给超管角色留一条通配分配通道"是个永不成立的例外，
    // 这道防线刻意不做角色例外。断言"权限集合未被改动"而不是只断 403，
    // 免得将来有人把两个 403 的先后顺序调换而没人发现。
    const before = (await Role.findById(superRoleId).select('permissions').lean()).permissions.map(
      String
    );
    const res = await assign(superRoleId, [wildcardId]);
    expect(res.status).toBe(403);
    const after = (await Role.findById(superRoleId).select('permissions').lean()).permissions.map(
      String
    );
    expect(after).toEqual(before);
    expect(after).toContain(wildcardId);
  });
});
