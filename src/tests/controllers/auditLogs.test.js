/**
 * /api/security/audit-logs 查询优化集成测试
 * 覆盖：非法枚举 400、组合筛选、时间降序、分页上限 1000、username 正则转义、超大时间范围告警
 * 注意：接口响应结构为 data = { data: [...logs], meta: {...} }
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { TEST_CLIENT_IP } = require('../fixtures');

describe('/api/security/audit-logs 查询优化', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let admin;
  let adminToken;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

    // 幂等播种：'security:audit' 的 code 有 unique 索引，其它并行套件
    // （reportExportAuditPerm / auditReportFixes）也会播种同一条记录，
    // 用 create 会在并行执行时撞 E11000
    const auditPerm = await Permission.findOneAndUpdate(
      { code: 'security:audit' },
      {
        $setOnInsert: { name: '审计日志', code: 'security:audit', type: 'api', module: 'security' },
      },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超级管理员_审计测试',
      code: 'SUPER_ADMIN_AUDIT',
      level: 10,
      isBuiltIn: true,
      permissions: [auditPerm._id],
    });

    admin = await User.create({
      username: 'audit_admin',
      email: 'audit_admin@example.com',
      password: 'Test@1234567',
      roles: [superRole._id],
    });

    adminToken = jwt.sign(
      { userId: String(admin._id), username: 'audit_admin', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 插入审计日志固件
    await AuditLog.insertMany([
      {
        action: 'login_success',
        category: 'auth',
        username: 'user.a+',
        userId: admin._id,
        ip: TEST_CLIENT_IP,
        success: true,
        riskLevel: 'low',
        method: 'POST',
        path: '/api/auth/login',
        timestamp: new Date('2026-08-01T10:00:00Z'),
      },
      {
        action: 'user_delete',
        category: 'user',
        username: 'admin2',
        userId: admin._id,
        ip: '10.0.0.1',
        success: false,
        riskLevel: 'high',
        method: 'DELETE',
        path: '/api/users/x',
        timestamp: new Date('2026-08-02T10:00:00Z'),
      },
      {
        action: 'password_changed',
        category: 'auth',
        username: 'user.a',
        userId: admin._id,
        ip: TEST_CLIENT_IP,
        success: true,
        riskLevel: 'medium',
        method: 'PUT',
        path: '/api/security/change-password',
        timestamp: new Date('2026-08-03T10:00:00Z'),
      },
      {
        action: 'login_failed',
        category: 'auth',
        username: 'userXa',
        userId: admin._id,
        ip: '192.168.0.1',
        success: false,
        riskLevel: 'medium',
        method: 'POST',
        path: '/api/auth/login',
        timestamp: new Date('2026-08-04T10:00:00Z'),
      },
    ]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const queryLogs = (qs = '') =>
    request(app).get(`/api/security/audit-logs?${qs}`).set('Authorization', `Bearer ${adminToken}`);

  const daysAgo = (days) => new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  test('非法 action 返回 400 与明确错误信息', async () => {
    const res = await queryLogs('action=hack');
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('action');
  });

  test('非法 riskLevel 返回 400', async () => {
    const res = await queryLogs('riskLevel=severe');
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('riskLevel');
  });

  test('非法 level 返回 400', async () => {
    const res = await queryLogs('level=debug');
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('level');
  });

  test('非法 category 返回 400（避免静默返回全量数据）', async () => {
    const res = await queryLogs('category=bogus');
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('category');
  });

  test('合法 category 正确过滤', async () => {
    const res = await queryLogs('category=user');
    expect(res.status).toBe(200);
    expect(res.body.data.data.every((l) => l.category === 'user')).toBe(true);
  });

  test('新增的 security / report 分类为合法取值', async () => {
    for (const cat of ['security', 'report']) {
      const res = await queryLogs(`category=${cat}`);
      expect(res.status).toBe(200);
    }
  });

  test('合法枚举值与空值透传不产生行为变化', async () => {
    const res = await queryLogs('action=login_success&riskLevel=low&level=info');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.data.length).toBeGreaterThanOrEqual(1);
    // 未传筛选参数返回全量数据
    const all = await queryLogs();
    expect(all.status).toBe(200);
    expect(all.body.data.data.length).toBeGreaterThanOrEqual(3);
  });

  test('组合筛选正确不遗漏不混淆', async () => {
    const res = await queryLogs('riskLevel=high&action=user_delete');
    expect(res.status).toBe(200);
    expect(res.body.data.data.length).toBe(1);
    expect(res.body.data.data[0].action).toBe('user_delete');
    expect(res.body.data.data[0].riskLevel).toBe('high');
  });

  test('无排序参数时结果按 timestamp 降序', async () => {
    const res = await queryLogs();
    expect(res.status).toBe(200);
    const timestamps = res.body.data.data.map((d) => new Date(d.timestamp).getTime());
    const sorted = [...timestamps].sort((a, b) => b - a);
    expect(timestamps).toEqual(sorted);
  });

  test('limit 超过上限被截断至 1000', async () => {
    const res = await queryLogs('limit=50000');
    expect(res.status).toBe(200);
    expect(res.body.data.meta.limit).toBe(1000);
  });

  test('username 正则特殊字符被转义匹配', async () => {
    const res = await queryLogs('username=user.a');
    expect(res.status).toBe(200);
    // 查询条件中的 . 应被 escapeRegExp 转义为字面字符：部分匹配 user.a / user.a+，
    // 但绝不能把 userXa 当作 user.a 匹配到（未转义时 . 通配会命中）
    expect(res.body.data.data.length).toBeGreaterThanOrEqual(1);
    expect(res.body.data.data.some((d) => d.username === 'userXa')).toBe(false);
  });

  test('超大时间范围触发 X-Performance-Warning 响应头且查询正常', async () => {
    const start = daysAgo(400);
    const end = daysAgo(10);
    const res = await queryLogs(`startDate=${start}&endDate=${end}`);
    expect(res.status).toBe(200);
    expect(res.headers['x-performance-warning']).toBe('query_range_too_large');
  });

  test('正常时间范围不设置告警头', async () => {
    const start = daysAgo(3);
    const end = daysAgo(1);
    const res = await queryLogs(`startDate=${start}&endDate=${end}`);
    expect(res.status).toBe(200);
    expect(res.headers['x-performance-warning']).toBeUndefined();
  });

  test('非法 userId 返回 400 而非 500（CastError 前置拦截）', async () => {
    const res = await queryLogs('userId=not-an-objectid');
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('userId');
  });

  test('合法 userId 正常过滤', async () => {
    const res = await queryLogs(`userId=${admin._id}`);
    expect(res.status).toBe(200);
    expect(res.body.data.data.length).toBeGreaterThanOrEqual(1);
  });

  test('非法 ip 返回 400', async () => {
    const res = await queryLogs('ip=999.999.999.999');
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('ip');
  });

  test('ip 查询兼容 IPv4 与其映射形态', async () => {
    // 固件中以 TEST_CLIENT_IP 落库，用映射形态查询也应命中
    const direct = await queryLogs(`ip=${TEST_CLIENT_IP}`);
    expect(direct.status).toBe(200);
    expect(direct.body.data.data.length).toBeGreaterThanOrEqual(1);

    const mapped = await queryLogs(`ip=::ffff:${TEST_CLIENT_IP}`);
    expect(mapped.status).toBe(200);
    expect(mapped.body.data.data.length).toBeGreaterThanOrEqual(1);
  });

  test('响应不外泄 hmac（阻断 HMAC 离线爆破通道），但保留 hash/prevHash', async () => {
    // 必须走 create（触发 pre-save 钩子算 hmac），insertMany 固件不带 hmac 会造成假绿
    const created = await AuditLog.create({
      action: 'password_changed',
      category: 'auth',
      username: 'hmac_probe_user',
      userId: admin._id,
      ip: TEST_CLIENT_IP,
      success: true,
      riskLevel: 'medium',
      method: 'PUT',
      path: '/api/security/change-password',
    });
    const raw = await AuditLog.findById(created._id).lean();
    expect(typeof raw.hmac).toBe('string');

    const res = await queryLogs('username=hmac_probe_user&limit=10');
    expect(res.status).toBe(200);
    const hit = res.body.data.data.find((l) => l._id === String(created._id));
    expect(hit).toBeDefined();

    // hmac = HMAC-SHA256(HMAC_SECRET, hash)。与同响应中的 hash 组成明文—标签对，
    // 一旦同时下发即可离线穷举密钥，因此必须缺席；hash/prevHash 无密钥参与，可保留
    expect(hit.hmac).toBeUndefined();
    expect(hit.hash).toBe(raw.hash);
    expect(Object.prototype.hasOwnProperty.call(hit, 'prevHash')).toBe(true);
    // 敏感入参投影同样排除
    expect(hit.body).toBeUndefined();
    expect(hit.params).toBeUndefined();
    expect(hit.query).toBeUndefined();
  });
});
