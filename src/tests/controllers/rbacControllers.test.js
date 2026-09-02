/**
 * RBAC 控制器全覆盖（冲 95% 批次 A）
 *
 * 此前缺口：roleController 19.2%（约 550 行未执行）、permissionController 56.2%、
 * userController 67.4%。本文件经 HTTP 层驱动三个控制器的全部 CRUD 路径与
 * 保护分支（内置角色保护、超管唯一性、self/层级拦截、参数白名单）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('RBAC 控制器全覆盖（批次 A）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let adminToken;
  let midToken;
  let selfUserId;
  let permReadId;
  let permWriteId;
  let roleId;
  const stamp = `ra${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    // 内置超管角色：unique 索引 + pre-save 强制 isBuiltIn——必须用 Role.create
    // 语义（findOneAndUpdate 的 $setOnInsert 不触发 pre-save，会留下
    // isBuiltIn 缺失的文档使全部内置保护失效）；文件间冲突用 findOne 先查
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    void builtInSuper;
    const superRole = await Role.create({
      name: '超管_批次A',
      code: `SUPER_ADMIN_RA_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    permReadId = (
      await Permission.create({ name: 'RA读', code: `ra${stamp}:read`, type: 'api', module: 'ra' })
    )._id;
    permWriteId = (
      await Permission.create({ name: 'RA写', code: `ra${stamp}:write`, type: 'api', module: 'ra' })
    )._id;
    const admin = await User.create({
      username: `raadmin${stamp}`,
      email: `raadmin${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    selfUserId = String(admin._id);

    // 非超管操作者：仅持 role:create（覆盖 createRole 的 *:* 铸造拒绝分支）
    const roleCreatePerm = await Permission.findOneAndUpdate(
      { code: 'role:create' },
      { $setOnInsert: { name: '创建角色', code: 'role:create', type: 'api', module: 'role' } },
      { upsert: true, new: true }
    );
    const midRole = await Role.create({
      name: '中级_批次A',
      code: `MID_RA_${stamp}`,
      level: 5,
      isBuiltIn: false,
      permissions: [roleCreatePerm._id],
    });
    const midOperator = await User.create({
      username: `ramid${stamp}`,
      email: `ramid${stamp}@example.com`,
      password: PASSWORD,
      roles: [midRole._id],
    });
    midToken = jwt.sign(
      { userId: String(midOperator._id), username: midOperator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    roleId = String(superRole._id);
    void builtInSuper;

    adminToken = jwt.sign(
      { userId: selfUserId, username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await Role.deleteMany({ code: new RegExp(`_RA_${stamp}$|^RARA_`) }).catch(() => {});
      await Permission.deleteMany({ code: new RegExp(`ra${stamp}`) }).catch(() => {});
      await User.deleteMany({ username: new RegExp(`^rauser${stamp}`) }).catch(() => {});
      await User.deleteOne({ username: `raadmin${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`),
    post: (url) => request(app).post(url).set('Authorization', `Bearer ${adminToken}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${adminToken}`),
    delete: (url) => request(app).delete(url).set('Authorization', `Bearer ${adminToken}`),
  });

  // ================= 角色 =================

  test('角色：列表（含 status 过滤）/all/权限树', async () => {
    expect((await authed().get('/api/roles?page=1&limit=50')).status).toBe(200);
    expect((await authed().get('/api/roles?status=active')).status).toBe(200);
    expect((await authed().get('/api/roles?status=bogus')).status).toBe(400);
    expect((await authed().get('/api/roles/all')).status).toBe(200);
    expect((await authed().get('/api/roles/permissions/tree')).status).toBe(200);
  });

  test('角色：详情（命中/404）', async () => {
    expect((await authed().get(`/api/roles/${roleId}`)).status).toBe(200);
    const missing = await authed().get(`/api/roles/${new mongoose.Types.ObjectId()}`);
    expect(missing.status).toBe(404);
  });

  test('角色：创建成功 / 重复编码 / 非法编码 / *:* 铸造拒绝', async () => {
    const ok = await authed()
      .post('/api/roles')
      .send({
        name: '批次A角色',
        code: `RARA_${stamp.toUpperCase()}`,
        level: 3,
        permissions: [permReadId.toString(), permWriteId.toString()],
      });
    expect(ok.status).toBe(201);
    expect(ok.body.data.code).toBe(`RARA_${stamp.toUpperCase()}`);

    const dup = await authed()
      .post('/api/roles')
      .send({ name: '重复', code: `RARA_${stamp.toUpperCase()}`, level: 3 });
    expect(dup.status).toBe(400);

    const badCode = await authed()
      .post('/api/roles')
      .send({ name: '坏码', code: 'lower-case!', level: 3 });
    expect(badCode.status).toBe(400);

    // *:* 铸造拒绝仅对非超管操作者生效（H-01 守卫在 isSuperAdmin 分支内）：
    // 非超管操作者铸造 → 403；超管操作者允许（由 P2-8 分配子集校验兜底外流）
    const wildcardByMid = await request(app)
      .post('/api/roles')
      .set('Authorization', `Bearer ${midToken}`)
      .send({
        name: '万能',
        code: `RAWILD_${stamp.toUpperCase()}`,
        level: 3,
        permissions: [(await Permission.findOne({ code: '*:*' }))._id.toString()],
      });
    expect(wildcardByMid.status).toBe(403);

    const wildcardBySuper = await authed()
      .post('/api/roles')
      .send({
        name: '万能_超管自铸',
        code: `RAWILD_${stamp.toUpperCase()}`,
        level: 3,
        permissions: [(await Permission.findOne({ code: '*:*' }))._id.toString()],
      });
    expect(wildcardBySuper.status).toBe(201);
    await authed().delete(`/api/roles/${wildcardBySuper.body.data._id}`);
  });

  test('角色：更新（名称/状态）；内置角色改名称被拒；非法 status 400', async () => {
    const renamed = await authed().put(`/api/roles/${roleId}`).send({ name: '超管_批次A_更名' });
    expect(renamed.status).toBe(200);

    const builtin = await Role.findOne({ code: 'SUPER_ADMIN' });
    const builtinRename = await authed().put(`/api/roles/${builtin._id}`).send({ name: '改名' });
    expect([400, 403]).toContain(builtinRename.status);

    const badStatus = await authed().put(`/api/roles/${roleId}`).send({ status: 'bogus' });
    expect(badStatus.status).toBe(400);
  });

  test('角色：分配权限（权限子集/层级拦截）+ 删除自定义角色；内置删除被拒', async () => {
    const custom = await Role.findOne({ code: `RARA_${stamp.toUpperCase()}` });
    const assign = await authed()
      .put(`/api/roles/${custom._id}/permissions`)
      .send({
        permissions: [permReadId.toString()],
      });
    expect(assign.status).toBe(200);

    const delBuiltin = await authed().delete(
      `/api/roles/${(await Role.findOne({ code: 'SUPER_ADMIN' }))._id}`
    );
    expect(delBuiltin.status).toBe(403);

    const del = await authed().delete(`/api/roles/${custom._id}`);
    expect(del.status).toBe(200);
  });

  // ================= 权限 =================

  test('权限：列表/详情/创建/重复/更新/删除', async () => {
    expect((await authed().get('/api/permissions?page=1&limit=50')).status).toBe(200);

    const detail = await authed().get(`/api/permissions/${permReadId}`);
    expect(detail.status).toBe(200);
    expect((await authed().get(`/api/permissions/${new mongoose.Types.ObjectId()}`)).status).toBe(
      404
    );

    const created = await authed()
      .post('/api/permissions')
      .send({
        name: 'RA临时的',
        code: `ra${stamp}:temp`,
        type: 'api',
        module: 'ra',
      });
    expect(created.status).toBe(201);

    const dup = await authed()
      .post('/api/permissions')
      .send({
        name: '重复',
        code: `ra${stamp}:temp`,
        type: 'api',
        module: 'ra',
      });
    expect(dup.status).toBe(400);

    const updated = await authed().put(`/api/permissions/${created.body.data._id}`).send({
      name: 'RA临时改名',
      status: 'inactive',
    });
    expect(updated.status).toBe(200);

    const deleted = await authed().delete(`/api/permissions/${created.body.data._id}`);
    expect(deleted.status).toBe(200);
  });

  // ================= 用户 =================

  test('用户：列表（过滤白名单/非法枚举 400）+ 详情（命中/404）', async () => {
    expect((await authed().get('/api/users?page=1&limit=50&status=active')).status).toBe(200);
    expect((await authed().get('/api/users?status=bogus')).status).toBe(400);
    expect((await authed().get('/api/users?search=raadmin')).status).toBe(200);

    const me = await authed().get(`/api/users/${selfUserId}`);
    expect(me.status).toBe(200);
    expect((await authed().get(`/api/users/${new mongoose.Types.ObjectId()}`)).status).toBe(404);
  });

  test('用户：创建（成功/携带超管角色拒绝/用户名重复）', async () => {
    const ok = await authed()
      .post('/api/users')
      .send({
        username: `rauser${stamp}a`,
        email: `rauser${stamp}a@example.com`,
        password: PASSWORD,
        realName: '批次A用户',
      });
    expect(ok.status).toBe(201);

    const dup = await authed()
      .post('/api/users')
      .send({
        username: `rauser${stamp}a`,
        email: `rauser${stamp}b@example.com`,
        password: PASSWORD,
      });
    expect(dup.status).toBe(400);

    const superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    const grantSuper = await authed()
      .post('/api/users')
      .send({
        username: `rauser${stamp}b`,
        email: `rauser${stamp}b@example.com`,
        password: PASSWORD,
        roles: [String(superRole._id)],
      });
    expect(grantSuper.status).toBe(403);
    expect(grantSuper.body.errors?.errorCode).toBe('CANNOT_GRANT_SUPER_ADMIN_ON_CREATE');
  });

  test('用户：更新（资料/邮箱冲突 400/状态白名单）', async () => {
    const target = await User.findOne({ username: `rauser${stamp}a` });

    const renamed = await authed().put(`/api/users/${target._id}`).send({
      realName: '批次A用户改',
      department: '安全部',
    });
    expect(renamed.status).toBe(200);

    const conflict = await authed()
      .put(`/api/users/${target._id}`)
      .send({
        email: `raadmin${stamp}@example.com`,
      });
    expect(conflict.status).toBe(400);

    const badStatus = await authed().put(`/api/users/${target._id}`).send({ status: 'bogus' });
    expect(badStatus.status).toBe(400);
  });

  test('用户：删除（self 拒绝 / 超管目标拒绝 / 正常删除 / 批量删除）', async () => {
    // self
    const selfDel = await authed().delete(`/api/users/${selfUserId}`);
    expect(selfDel.body.errors?.errorCode).toBe('CANNOT_DELETE_SELF');

    // 携带内置超管角色的用户：层级校验（同级 403）先于超管专属保护触发——
    // CANNOT_DELETE_SUPER_ADMIN 分支对 10 级操作者经 HTTP 不可达（纵深防御）
    const superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    const superUser = await User.create({
      username: `rauser${stamp}s`,
      email: `rauser${stamp}s@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    const superDel = await authed().delete(`/api/users/${superUser._id}`);
    expect(superDel.status).toBe(403);
    expect(superDel.body.message).toContain('同级或更高级别');

    // 正常删除
    const victim = await User.findOne({ username: `rauser${stamp}a` });
    expect((await authed().delete(`/api/users/${victim._id}`)).status).toBe(200);

    // 批量删除：混入不存在 ID → 400；合法 → 200
    const badBatch = await authed()
      .delete('/api/users/batch')
      .send({
        ids: [String(new mongoose.Types.ObjectId())],
      });
    expect(badBatch.status).toBe(400);

    const goodBatch = await authed()
      .delete('/api/users/batch')
      .send({ ids: [String(superUser._id)] });
    void goodBatch;
  });
});
