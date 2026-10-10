/**
 * 权限缓存失效链回归（P1-14）
 *
 * 背景：userPermissionService 的进程内 TTL 缓存（30s）缓存的是「用户 -> 权限编码
 * 数组」的**解析结果**，而解析过程带两个 match 条件：
 *   - 角色 match { status: 'active' }
 *   - 权限 match { status: 'active' }
 * 因此只要「角色/权限的 status」或「权限被删除」发生变化，任何已缓存用户的解析
 * 结果都会失真。此时若不显式失效，被降权的用户最长仍持有旧权限 30 秒——这是一
 * 个真实的安全窗口，而不是单纯的数据陈旧。
 *
 * 本文件用**真实 HTTP 请求**驱动写接口，再用真实的 getPermissions 读缓存，
 * 断言「写入后解析结果立即变化」。不 mock 缓存层——mock 掉就测不到这条链。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('权限缓存失效链（P1-14）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let userPermissionService;
  let adminToken;
  let target; // 被观察缓存的普通用户
  let role;
  let emptyRole;
  let perm;

  const seedPerm = (code) =>
    Permission.findOneAndUpdate(
      { code },
      { $setOnInsert: { code, name: code, type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    userPermissionService = require('../../services/userPermissionService');
    require('../../models/TokenBlacklist');
    const { createApp } = require('../../app');
    app = createApp();

    const [permUpdate, roleUpdate, wildcard] = await Promise.all([
      seedPerm('permission:update'),
      seedPerm('role:update'),
      seedPerm('*:*'),
    ]);

    const adminRole = await Role.findOneAndUpdate(
      { code: 'CACHE_ADMIN_ROLE' },
      {
        $setOnInsert: {
          code: 'CACHE_ADMIN_ROLE',
          name: '缓存回归管理员',
          level: 9,
          permissions: [permUpdate._id, roleUpdate._id, wildcard._id],
        },
      },
      { upsert: true, new: true }
    );
    const admin = await User.create({
      username: 'cache_admin',
      email: 'cache_admin@example.com',
      password: 'Qz7#Lm42vTx9',
      roles: [adminRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    perm = await seedPerm('cacheprobe:read');
    emptyRole = await Role.create({
      code: 'CACHE_EMPTY_ROLE',
      name: '空权限角色',
      level: 2,
      permissions: [],
    });
    role = await Role.create({
      code: 'CACHE_PROBE_ROLE',
      name: '缓存探针角色',
      level: 3,
      permissions: [perm._id],
    });
    target = await User.create({
      username: 'cache_target',
      email: 'cache_target@example.com',
      password: 'Qz7#Lm42vTx9',
      roles: [role._id],
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    // 清空模块级缓存，用例互不串扰；不清空则上一个用例的失效会掩盖本用例的缺口
    userPermissionService.invalidatePermissionCacheLocal();
  });

  test('前置：目标用户当前解析出探针权限（确认 fixture 有效，防假绿）', async () => {
    const perms = await userPermissionService.getPermissions(target._id);
    expect(perms).toContain('cacheprobe:read');
  });

  test('PUT /api/permissions/:id 停用权限后，已缓存用户立即失去该权限', async () => {
    // 1) 先填充缓存（真实读路径）
    expect(await userPermissionService.getPermissions(target._id)).toContain('cacheprobe:read');

    // 2) 通过真实接口把权限置为 inactive
    const res = await request(app)
      .put(`/api/permissions/${perm._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'inactive' });
    expect(res.status).toBe(200);

    // 3) 解析结果必须立即变化——未失效则这里仍返回旧的 ['cacheprobe:read']
    const after = await userPermissionService.getPermissions(target._id);
    expect(after).not.toContain('cacheprobe:read');

    // 还原，避免影响后续用例
    await Permission.findByIdAndUpdate(perm._id, { $set: { status: 'active' } });
    userPermissionService.invalidatePermissionCacheLocal();
  });

  test('PUT /api/roles/:id 停用角色后，已缓存用户立即失去该角色的权限', async () => {
    expect(await userPermissionService.getPermissions(target._id)).toContain('cacheprobe:read');

    const res = await request(app)
      .put(`/api/roles/${role._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'inactive' });
    expect(res.status).toBe(200);

    const after = await userPermissionService.getPermissions(target._id);
    expect(after).not.toContain('cacheprobe:read');

    await Role.findByIdAndUpdate(role._id, { $set: { status: 'active' } });
    userPermissionService.invalidatePermissionCacheLocal();
  });

  test('权限停用后重新启用，解析结果立即恢复（双向失效）', async () => {
    expect(await userPermissionService.getPermissions(target._id)).toContain('cacheprobe:read');

    await request(app)
      .put(`/api/permissions/${perm._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'inactive' })
      .expect(200);
    expect(await userPermissionService.getPermissions(target._id)).not.toContain('cacheprobe:read');

    await request(app)
      .put(`/api/permissions/${perm._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'active' })
      .expect(200);
    // 恢复方向同样必须立即生效：若只在「变为 inactive」时失效，
    // 这里会命中停用期间写入的空结果缓存，管理员看到的是「已启用但没人有权限」
    expect(await userPermissionService.getPermissions(target._id)).toContain('cacheprobe:read');
  });

  test('PUT /api/roles/:id/permissions 改角色权限后，持有该角色的用户立即生效', async () => {
    expect(await userPermissionService.getPermissions(target._id)).toContain('cacheprobe:read');

    const other = await seedPerm('cacheprobe:write');
    const res = await request(app)
      .put(`/api/roles/${role._id}/permissions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ permissions: [String(other._id)] });
    expect(res.status).toBe(200);

    const after = await userPermissionService.getPermissions(target._id);
    expect(after).toContain('cacheprobe:write');
    expect(after).not.toContain('cacheprobe:read');

    await Role.findByIdAndUpdate(role._id, { $set: { permissions: [perm._id] } });
    userPermissionService.invalidatePermissionCacheLocal();
  });

  test('PUT /api/users/:id/roles 改用户角色后，该用户权限立即生效', async () => {
    expect(await userPermissionService.getPermissions(target._id)).toContain('cacheprobe:read');

    const res = await request(app)
      .put(`/api/users/${target._id}/roles`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ roles: [String(emptyRole._id)] });
    expect(res.status).toBe(200);

    const after = await userPermissionService.getPermissions(target._id);
    expect(after).not.toContain('cacheprobe:read');

    await User.findByIdAndUpdate(target._id, { $set: { roles: [role._id] } });
    userPermissionService.invalidatePermissionCacheLocal();
  });
});
