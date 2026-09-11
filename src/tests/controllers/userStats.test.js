/**
 * /api/users/stats 统计缓存集成测试
 * 覆盖：首次查询写缓存、二次命中、缓存键隔离、数据变更主动失效、缓存降级
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('/api/users/stats 统计缓存', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let statsCache;
  let admin;
  let adminToken;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    statsCache = require('../../services/statsCache');

    // `*:*` 的 code 有 unique 索引，assignRoles.test.js 也会播种同一条记录；
    // 并行执行时 create 会撞 E11000，故统一用 upsert 复用已有记录
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超级管理员_统计测试',
      code: 'SUPER_ADMIN_STATS',
      level: 10,
      isBuiltIn: true,
      permissions: [wildcardPerm._id],
    });

    admin = await User.create({
      username: 'stats_admin',
      email: 'stats_admin@example.com',
      password: 'Test@1234567',
      roles: [superRole._id],
    });

    adminToken = jwt.sign(
      { userId: String(admin._id), username: 'stats_admin', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    statsCache.stopCleanup();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const getStats = () =>
    request(app).get('/api/users/stats').set('Authorization', `Bearer ${adminToken}`);

  const cacheKeysOfAdmin = () => {
    const prefix = `stats:${admin._id}:`;
    return [...statsCache._store.keys()].filter((k) => k.startsWith(prefix));
  };

  test('首次请求执行查询并写入缓存，二次请求命中缓存', async () => {
    const countSpy = jest.spyOn(User, 'countDocuments');
    const aggSpy = jest.spyOn(User, 'aggregate');

    const first = await getStats();
    expect(first.status).toBe(200);
    expect(first.body.success).toBe(true);
    expect(typeof first.body.data.total).toBe('number');
    expect(Array.isArray(first.body.data.byDepartment)).toBe(true);
    expect(Array.isArray(first.body.data.byRole)).toBe(true);

    // 首次查询应为单次 $facet 聚合（不再触发 countDocuments 串行往返）
    expect(aggSpy.mock.calls.length).toBe(1);
    expect(countSpy.mock.calls.length).toBe(0);

    // 缓存键携带 userId 前缀
    expect(cacheKeysOfAdmin().length).toBe(1);

    // 二次请求命中缓存，不再执行聚合
    const second = await getStats();
    expect(second.status).toBe(200);
    expect(second.body.data).toEqual(first.body.data);
    expect(aggSpy.mock.calls.length).toBe(1);

    countSpy.mockRestore();
    aggSpy.mockRestore();
  });

  test('缓存按用户隔离，不读取其他用户的缓存', async () => {
    const otherUser = await User.create({
      username: 'stats_other',
      email: 'stats_other@example.com',
      password: 'Test@1234567',
      roles: [admin.roles[0]],
    });
    const otherToken = jwt.sign(
      { userId: String(otherUser._id), username: 'stats_other', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    await request(app).get('/api/users/stats').set('Authorization', `Bearer ${otherToken}`);

    // 每个用户独立缓存键
    expect(cacheKeysOfAdmin().length).toBe(1);
    expect([...statsCache._store.keys()].some((k) => k.startsWith(`stats:${otherUser._id}:`))).toBe(
      true
    );
  });

  test('创建用户后缓存失效，下次请求返回最新数据', async () => {
    const before = await getStats();
    expect(before.body.data.total).toBeGreaterThanOrEqual(1);
    expect(cacheKeysOfAdmin().length).toBe(1);

    await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        username: 'stats_newuser',
        email: 'stats_newuser@example.com',
        // 走 POST /api/users 校验链，须避开泄露口令黑名单（G8）
        password: 'Vn6$Rw83pKx5',
      })
      .expect(201);

    // 缓存已被 createUser 末尾的失效调用清除
    expect(cacheKeysOfAdmin().length).toBe(0);

    const after = await getStats();
    expect(after.status).toBe(200);
    expect(cacheKeysOfAdmin().length).toBe(1);
  });

  test('删除用户后缓存失效', async () => {
    const target = await User.create({
      username: 'stats_del',
      email: 'stats_del@example.com',
      password: 'Test@1234567',
      roles: [],
    });
    await getStats();
    expect(cacheKeysOfAdmin().length).toBe(1);

    await request(app)
      .delete(`/api/users/${target._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(cacheKeysOfAdmin().length).toBe(0);
  });

  test('更新用户状态后缓存失效', async () => {
    const target = await User.create({
      username: 'stats_status',
      email: 'stats_status@example.com',
      password: 'Test@1234567',
      roles: [],
    });
    await getStats();
    expect(cacheKeysOfAdmin().length).toBe(1);

    await request(app)
      .put(`/api/users/${target._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'inactive' })
      .expect(200);

    expect(cacheKeysOfAdmin().length).toBe(0);
  });

  test('分配角色后缓存失效', async () => {
    const target = await User.create({
      username: 'stats_role',
      email: 'stats_role@example.com',
      password: 'Test@1234567',
      roles: [],
    });
    await getStats();
    expect(cacheKeysOfAdmin().length).toBe(1);

    await request(app)
      .put(`/api/users/${target._id}/roles`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ roles: [String(admin.roles[0])] })
      .expect(200);

    expect(cacheKeysOfAdmin().length).toBe(0);
  });

  test('锁定用户后缓存失效', async () => {
    const target = await User.create({
      username: 'stats_lock',
      email: 'stats_lock@example.com',
      password: 'Test@1234567',
      roles: [],
    });
    await getStats();
    expect(cacheKeysOfAdmin().length).toBe(1);

    await request(app)
      .put(`/api/security/users/${target._id}/lock`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ locked: true })
      .expect(200);

    expect(cacheKeysOfAdmin().length).toBe(0);
  });

  test('缓存模块异常时接口降级为直查数据库', async () => {
    const originalGet = statsCache._store.get;
    statsCache._store.get = () => {
      throw new Error('mock stats cache failure');
    };
    try {
      const res = await getStats();
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(typeof res.body.data.total).toBe('number');
    } finally {
      statsCache._store.get = originalGet;
    }
  });
});
