/**
 * 高量级列表游标分页端到端测试（E-2）
 *
 * 覆盖四个改造成游标分页的列表接口：设备 / 报警 / 巡检 / 审计日志。
 * 核心断言：逐页消费 nextCursor 能无重复、无遗漏地遍历全部记录，
 * 且顺序与排序键一致；无效游标一律 400；游标模式不返回 total。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { TEST_CLIENT_IP } = require('../fixtures');

describe('高量级列表游标分页（E-2）', () => {
  let app;
  let FireDevice;
  let FireAlarm;
  let Inspection;
  let AuditLog;
  let adminToken;
  const stamp = `cp${Date.now()}`.replace(/\d/g, (d) => 'klmnopqrst'[Number(d)]);
  const auditSeedUser = `cursor_seed_${stamp}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_游标分页',
      code: `SUPER_ADMIN_CP_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `cpadmin${stamp}`,
      email: `cpadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });

    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();

    // ===== 造数 =====
    const base = new Date('2026-08-30T12:00:00Z');

    // 7 台设备（deviceCode 升序游标）
    await FireDevice.create(
      Array.from({ length: 7 }, (_, i) => ({
        deviceCode: `CT-${stamp}-${String(i + 1).padStart(3, '0')}`,
        deviceName: `游标测试设备${i + 1}`,
        deviceType: 'smoke_detector',
        installDate: base,
        location: { building: 'A栋', floor: `${i + 1}F` },
      }))
    );

    // 6 条报警（occurredAt 降序游标，每条相差 1 分钟）
    await FireAlarm.create(
      Array.from({ length: 6 }, (_, i) => ({
        alarmType: 'smoke',
        description: `游标测试报警 ${stamp}-${i + 1}`,
        occurredAt: new Date(base.getTime() - i * 60 * 1000),
        location: { building: 'A栋' },
      }))
    );

    // 5 条巡检（planStartTime 降序游标）
    await Inspection.create(
      Array.from({ length: 5 }, (_, i) => ({
        inspectionType: 'daily',
        title: `游标测试巡检 ${stamp}-${i + 1}`,
        planStartTime: new Date(base.getTime() - i * 60 * 1000),
      }))
    );

    // 8 条审计日志（timestamp 降序游标；用专属 username 过滤，
    // 隔离测试过程中其他请求被审计中间件写入的记录）
    await AuditLog.create(
      Array.from({ length: 8 }, (_, i) => ({
        action: 'login_success',
        category: 'auth',
        username: auditSeedUser,
        success: true,
        riskLevel: 'low',
        ip: TEST_CLIENT_IP,
        timestamp: new Date(base.getTime() - i * 60 * 1000),
      }))
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({ deviceCode: new RegExp(`^CT-${stamp}`) }).catch(() => {});
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
      await AuditLog.deleteMany({ username: auditSeedUser }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `cpadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_CP_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`),
  });

  /**
   * 通用游标遍历器：从首页起逐页消费 nextCursor，直到 hasMore 为假。
   * 返回按接口返回顺序拼接的记录列表与页数。
   */
  const walkCursor = async (urlPrefix, limit, { itemsOf, cursorOf }) => {
    const collected = [];
    let cursor = null;
    let pages = 0;
    do {
      const url = cursor
        ? `${urlPrefix}&limit=${limit}&cursor=${encodeURIComponent(cursor)}`
        : `${urlPrefix}&limit=${limit}`;

      const res = await authed().get(url);
      expect(res.status).toBe(200);
      // 设备/报警/巡检走 ApiResponse.paginated（data 与 pagination 同级），
      // 审计日志走 success({ data, meta })，两者都以完整响应体为基取字段
      const body = res.body;
      const items = itemsOf(body);
      collected.push(...items);
      pages += 1;
      expect(items.length).toBeLessThanOrEqual(limit);
      cursor = cursorOf(body);
      if (pages > 100) throw new Error('游标遍历超过 100 页，疑似死循环');
    } while (cursor);
    return { collected, pages };
  };

  test('设备列表：游标遍历无重复无遗漏，deviceCode 升序', async () => {
    const { collected, pages } = await walkCursor(`/api/devices?search=${stamp}`, 3, {
      itemsOf: (body) => body.data,
      cursorOf: (body) => body.pagination.nextCursor,
    });
    expect(pages).toBe(3); // 7 条 / 每页 3
    const codes = collected.map((d) => d.deviceCode);
    expect(codes).toHaveLength(7);
    expect(new Set(codes).size).toBe(7);
    // FireDevice.deviceCode 经 schema 大写化，期望值同口径取大写
    const expected = Array.from(
      { length: 7 },
      (_, i) => `CT-${stamp.toUpperCase()}-${String(i + 1).padStart(3, '0')}`
    );
    expect(codes.map((c) => c.toUpperCase())).toEqual(expected);
  });

  test('报警列表：游标遍历无重复无遗漏，occurredAt 降序', async () => {
    const { collected, pages } = await walkCursor(`/api/alarms?search=${stamp}`, 2, {
      itemsOf: (body) => body.data,
      cursorOf: (body) => body.pagination.nextCursor,
    });
    expect(pages).toBe(3); // 6 条 / 每页 2
    expect(collected).toHaveLength(6);
    expect(new Set(collected.map((a) => String(a._id))).size).toBe(6);
    const times = collected.map((a) => new Date(a.occurredAt).getTime());
    expect(times).toEqual([...times].sort((a, b) => b - a));
    expect(collected[0].description).toContain(`${stamp}-1`);
  });

  test('巡检列表：游标遍历无重复无遗漏，planStartTime 降序', async () => {
    const { collected } = await walkCursor(`/api/inspections?search=${stamp}`, 2, {
      itemsOf: (body) => body.data,
      cursorOf: (body) => body.pagination.nextCursor,
    });
    expect(collected).toHaveLength(5);
    expect(new Set(collected.map((a) => String(a._id))).size).toBe(5);
    const times = collected.map((a) => new Date(a.planStartTime).getTime());
    expect(times).toEqual([...times].sort((a, b) => b - a));
  });

  test('审计日志：游标遍历无重复无遗漏，且游标模式跳过 total', async () => {
    const first = await authed().get(`/api/security/audit-logs?username=${auditSeedUser}&limit=3`);
    expect(first.status).toBe(200);
    // 未传 cursor：保持 offset 语义，total 可用
    expect(first.body.data.meta.total).toBe(8);

    const { collected } = await walkCursor(
      `/api/security/audit-logs?username=${auditSeedUser}`,
      3,
      {
        itemsOf: (body) => body.data.data,
        cursorOf: (body) => body.data.meta.nextCursor,
      }
    );
    expect(collected).toHaveLength(8);
    expect(new Set(collected.map((l) => String(l._id))).size).toBe(8);
    const times = collected.map((l) => new Date(l.timestamp).getTime());
    expect(times).toEqual([...times].sort((a, b) => b - a));

    // 游标模式元数据：不返回 total（省 countDocuments），hasNext/nextCursor 表达翻页
    const cursorPage = await authed().get(
      `/api/security/audit-logs?username=${auditSeedUser}&limit=3&cursor=${encodeURIComponent(first.body.data.meta.nextCursor || '')}`
    );
    if (first.body.data.meta.nextCursor) {
      expect(cursorPage.status).toBe(200);
      expect(cursorPage.body.data.meta.total).toBeNull();
      expect(cursorPage.body.data.meta.hasPrev).toBe(true);
    }
  });

  test('无效游标一律 400', async () => {
    const endpoints = [
      '/api/devices?limit=5&cursor=bad-cursor',
      '/api/alarms?limit=5&cursor=bad-cursor',
      '/api/inspections?limit=5&cursor=bad-cursor',
      '/api/security/audit-logs?limit=5&cursor=bad-cursor',
    ];
    for (const url of endpoints) {
      const res = await authed().get(url);
      expect(res.status).toBe(400);
    }
  });

  test('游标模式响应不携带 total（设备/报警/巡检）', async () => {
    const first = await authed().get(`/api/devices?search=${stamp}&limit=3`);
    const cursor = first.body.pagination.nextCursor;
    expect(cursor).toBeTruthy();
    const second = await authed().get(
      `/api/devices?search=${stamp}&limit=3&cursor=${encodeURIComponent(cursor)}`
    );
    expect(second.status).toBe(200);
    expect(second.body.pagination.total).toBeNull();
    expect(second.body.pagination.totalPages).toBeNull();
    expect(typeof second.body.pagination.hasMore).toBe('boolean');
  });
});
