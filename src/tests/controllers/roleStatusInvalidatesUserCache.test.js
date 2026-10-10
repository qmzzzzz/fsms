/**
 * 「停用角色」必须同时失效两份缓存（回归 F-117）
 *
 * 角色 status 变更会改变两类授权输入的解析结果：
 *  1. userPermissionService 的「用户 -> 权限码」解析缓存（TTL 30s）
 *     —— 由 P1-14 失效，permissionCacheInvalidation.test.js 已覆盖。
 *  2. middleware/auth 的用户缓存（TTL 60s），它填充了 req.user.roles /
 *     req.user.roleCodes —— rbac.js 的 checkRole 优先读 roleCodes，
 *     rateLimit.js 的角色配额（SUPER_ADMIN 500 / SECURITY_ADMIN 400）也读它，
 *     userController.js 的「同级角色归属」闸门以它为事实来源。
 *
 * 修复前 updateRole 只做第 1 件事，于是与 auth.js 自己的注释直接矛盾：
 *   「停用角色后，该角色码不得继续进入 req.user.roleCodes，
 *     否则 checkRole 与 userLimiter 会按已作废的角色放行/限流」
 * 经本接口停用的角色，其 code 最长仍留存 60 秒。
 *
 * 口径对齐 rolePermissionController.js 的权限变更路径（同样按持有者逐个失效）。
 *
 * 只用一个 spy 钉住「失效调用」这条接线，其余全走真实链路：
 * auth.js 缓存自身的读写字段由它自己的用例负责，这里重复断言只会让两处同时脆。
 */

jest.mock('../../middleware/auth', () => {
  const actual = jest.requireActual('../../middleware/auth');
  return { ...actual, invalidateUserCache: jest.fn() };
});

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { invalidateUserCache } = require('../../middleware/auth');

describe('停用角色 -> auth 用户缓存失效链', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let adminToken;
  let probeRole;
  let holder;

  const seedPerm = (code) =>
    Permission.findOneAndUpdate(
      { code },
      { $setOnInsert: { code, name: code, type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );

  const invalidatedIds = () => invalidateUserCache.mock.calls.map(([id]) => String(id));

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    const { createApp } = require('../../app');
    app = createApp();

    const [roleUpdate, wildcard] = await Promise.all([seedPerm('role:update'), seedPerm('*:*')]);
    const adminRole = await Role.create({
      code: `RSI_ADMIN_${Date.now()}`,
      name: '失效链管理员',
      level: 9,
      permissions: [roleUpdate._id, wildcard._id],
    });
    const admin = await User.create({
      username: `rsi_admin_${Date.now()}`,
      email: `rsi_admin_${Date.now()}@example.com`,
      password: 'Qz7#Lm42vTx9',
      roles: [adminRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    probeRole = await Role.create({
      code: `RSI_PROBE_${Date.now()}`,
      name: '被停用角色',
      level: 3,
      permissions: [],
    });
    holder = await User.create({
      username: `rsi_holder_${Date.now()}`,
      email: `rsi_holder_${Date.now()}@example.com`,
      password: 'Qz7#Lm42vTx9',
      roles: [probeRole._id],
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // 每条用例的判据都是「本次请求相对角色当前 status 是否构成变更」，
  // 因此起始 status 必须被固定，否则用例之间通过 DB 互相传递状态，
  // --randomize 打乱文件内顺序后（重新启用 / 同值对照）就会互换前提。
  beforeEach(async () => {
    invalidateUserCache.mockClear();
    await Role.updateOne({ _id: probeRole._id }, { $set: { status: 'active' } });
  });

  const setStatusDirectly = (status) =>
    Role.updateOne({ _id: probeRole._id }, { $set: { status } });

  const statusInDb = async () => {
    const doc = await Role.findById(probeRole._id).select('status').lean();
    return doc.status;
  };

  test('前置：探针角色确实有持有者（否则下面的 toContain 是空话）', async () => {
    const roleService = require('../../services/roleService');
    const holders = await roleService.listUsersWithRole(probeRole._id);
    expect(holders.map((u) => String(u._id))).toContain(String(holder._id));
  });

  test('停用角色后，该角色的每个持有者都被失效 auth 缓存', async () => {
    const res = await request(app)
      .put(`/api/roles/${probeRole._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'inactive' });

    expect(res.status).toBe(200);
    expect(invalidatedIds()).toContain(String(holder._id));
  });

  test('重新启用同样失效（只在变 inactive 时失效＝恢复方向看不到权限）', async () => {
    // 前提自行铺设：直接从 inactive 起，不依赖上一条用例留下的状态
    await setStatusDirectly('inactive');
    await request(app)
      .put(`/api/roles/${probeRole._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'active' })
      .expect(200);

    expect(invalidatedIds()).toContain(String(holder._id));
  });

  test('反向对照：只改名称不改 status 时不得失效任何用户缓存', async () => {
    const res = await request(app)
      .put(`/api/roles/${probeRole._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: '仅改名' });

    expect(res.status).toBe(200);
    // 无谓的全量失效会把每个请求都变成查库，这条断言钉住「按 status 变更触发」
    expect(invalidateUserCache).not.toHaveBeenCalled();
  });

  test('反向对照：status 传成当前相同值也不算变更', async () => {
    // 读库而非读内存副本：beforeAll 创建的 probeRole.status 永远停在创建时的值，
    // 拿它当前提等于自证一个没有发生的状态
    expect(await statusInDb()).toBe('active');
    const res = await request(app)
      .put(`/api/roles/${probeRole._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'active' });

    expect(res.status).toBe(200);
    expect(invalidateUserCache).not.toHaveBeenCalled();
  });
});
