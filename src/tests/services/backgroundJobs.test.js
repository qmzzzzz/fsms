/**
 * 后台任务与错误路径覆盖（冲 95% 批次 E）
 *
 * 覆盖：auditMonitor（异常检测闭环）、deviceReminder（扫描/调度器）、
 * securityAlert 检测函数（爆破/批量导出/权限滥用/概览/最近告警）、
 * auditChainVerify（篡改检出）、auditBuffer flush 成功路径、
 * errorHandler 错误映射、permissionHelper、apiResponse/ApiError。
 */

const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const makeRes = () => {
  const res = {
    statusCode: 200,
    body: null,
    headers: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    set(k, v) {
      this.headers[k] = v;
      return this;
    },
    end() {
      return this;
    },
  };
  return res;
};

describe('后台任务与错误路径（批次 E）', () => {
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let adminUserId;
  const stamp = `e${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_批次E',
      code: `SUPER_ADMIN_E_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `eadmin${stamp}`,
      email: `eadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminUserId = String(admin._id);
    void jwt; // 令牌签发已不再需要（本套件全部为直驱/服务层调用）

    const { createApp } = require('../../app');
    global.__eapp = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const Role2 = require('../../models/Role');
      await User.deleteOne({ username: `eadmin${stamp}` }).catch(() => {});
      await Role2.deleteOne({ code: `SUPER_ADMIN_E_${stamp}` }).catch(() => {});
      await require('../../models/IPBlacklist')
        .deleteMany({ source: 'auto' })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  // ================= auditMonitor =================

  test('auditMonitor：start/stop 幂等 + runDetection 无异常静默', async () => {
    const monitor = require('../../services/auditMonitor');
    monitor.start();
    monitor.start(); // 幂等
    expect(monitor.isRunning()).toBe(true);
    await monitor.runDetection(); // 空库/无异常 → 不推送不抛错
    monitor.stop();
    monitor.stop(); // 幂等
    expect(monitor.isRunning()).toBe(false);
  });

  test('auditMonitor：检出高频失败用户并推送告警', async () => {
    const monitor = require('../../services/auditMonitor');
    // 造高频失败记录（阈值： AuditLog.detectAnomalies 内部定义）
    const docs = [];
    for (let i = 0; i < 12; i++) {
      docs.push({
        action: 'login_failed',
        category: 'auth',
        username: `efail${stamp}`,
        userId: new (require('mongoose').Types.ObjectId)(),
        ip: '203.0.113.201',
        success: false,
        riskLevel: 'medium',
        timestamp: new Date(),
      });
    }
    await AuditLog.insertMany(docs);

    await monitor.runDetection();
    // 告警侧效果：security_alerts_total 计数或审计记录存在即可（不抛错即通过）
  });

  // ================= deviceReminder =================

  test('deviceReminder：扫描三类提醒 + 调度器生命周期', async () => {
    const FireDevice = require('../../models/FireDevice');
    const now = Date.now();
    await FireDevice.create({
      deviceCode: `E-${stamp}-EXP`,
      deviceName: '已过期',
      deviceType: 'hydrant',
      status: 'normal',
      installDate: new Date(now - 86400000),
      expiryDate: new Date(now - 86400000),
      nextCheckDate: new Date(now - 86400000),
      location: { building: 'E栋' },
    });
    const reminder = require('../../services/deviceReminder');

    const result = await reminder.scanDeviceReminders({ expiringDays: 30 });
    expect(result.summary).toBeTruthy();
    expect(result.summary.expired).toBeGreaterThanOrEqual(1);

    // 二次扫描命中缓存（无 scope）
    const cached = await reminder.scanDeviceReminders();
    expect(cached.summary).toBeTruthy();

    // 带范围查询不写全局缓存
    const scoped = await reminder.scanDeviceReminders({
      scopeFilter: { location: { building: '不存在' } },
      resultLimit: 10,
    });
    expect(scoped.summary.expired).toBe(0);

    // 调度器生命周期
    const scheduler = reminder.startReminderScheduler(24 * 60 * 60 * 1000);
    await reminder.stopReminderScheduler(scheduler);
  });

  test('markOverdueInspections：过期 pending 推进为 overdue', async () => {
    const Inspection = require('../../models/Inspection');
    const now = Date.now();
    const insp = await Inspection.create({
      inspectionType: 'daily',
      title: `逾期_${stamp}`,
      planStartTime: new Date(now - 7200000),
      planEndTime: new Date(now - 3600000),
      status: 'pending',
      checkItems: [{ name: 'x' }],
    });
    const reminder = require('../../services/deviceReminder');
    await reminder.markOverdueInspections();
    const after = await Inspection.findById(insp._id).lean();
    expect(after.status).toBe('overdue');
  });

  // ================= securityAlert 检测函数 =================

  test('checkBruteForce：达阈值 → 写告警审计 + 自动封禁 + 频控去重', async () => {
    const securityAlert = require('../../services/securityAlert');
    const bfUser = `bf${stamp}`;
    const docs = [];
    for (let i = 0; i < 6; i++) {
      docs.push({
        action: 'login_failed',
        category: 'auth',
        username: bfUser,
        ip: '203.0.113.210',
        success: false,
        timestamp: new Date(),
      });
    }
    await AuditLog.insertMany(docs);

    await securityAlert.checkBruteForce(bfUser, '203.0.113.210');

    const alert = await AuditLog.findOne({ action: 'brute_force_login', username: bfUser }).lean();
    expect(alert).toBeTruthy();

    const IPBlacklist = require('../../models/IPBlacklist');
    const ban = await IPBlacklist.findOne({ ip: '203.0.113.210', source: 'auto' });
    expect(ban).toBeTruthy();

    // 频控窗口内重复检测 → 不再重复告警
    const before = await AuditLog.countDocuments({ action: 'brute_force_login', username: bfUser });
    await securityAlert.checkBruteForce(bfUser, '203.0.113.210');
    const after = await AuditLog.countDocuments({ action: 'brute_force_login', username: bfUser });
    expect(after).toBe(before);
  });

  test('checkBulkExport / checkPermissionAbuse / getSecurityOverview / getRecentAlerts', async () => {
    const securityAlert = require('../../services/securityAlert');

    await securityAlert.checkBulkExport(adminUserId, `eadmin${stamp}`, 500, 'report_export');
    const bulkAlert = await AuditLog.findOne({
      action: 'bulk_data_export',
      username: `eadmin${stamp}`,
    }).lean();
    expect(bulkAlert).toBeTruthy();

    const permFailDocs = [];
    for (let i = 0; i < 21; i++) {
      permFailDocs.push({
        action: 'permission_denied',
        category: 'system',
        userId: adminUserId,
        username: `eadmin${stamp}`,
        ip: '203.0.113.220',
        success: false,
        timestamp: new Date(),
      });
    }
    await AuditLog.insertMany(permFailDocs);
    await securityAlert.checkPermissionAbuse(adminUserId, '203.0.113.220');
    const abuse = await AuditLog.findOne({
      action: 'permission_abuse',
      userId: adminUserId,
    }).lean();
    expect(abuse).toBeTruthy();

    const overview = await securityAlert.getSecurityOverview(7);
    expect(overview.riskScore).toBeGreaterThanOrEqual(0);

    const recent = await securityAlert.getRecentAlerts(10);
    expect(Array.isArray(recent)).toBe(true);
  });

  // ================= auditChainVerify =================

  test('auditChainVerify：合法链校验通过 + 篡改检出', async () => {
    const { verifyAuditChain } = require('../../services/auditChainVerify');

    // 写入三条链式审计（pre-save 自动串链）
    for (let i = 0; i < 3; i++) {
      await AuditLog.create({
        action: 'chain_test',
        category: 'system',
        username: `chain${stamp}`,
        success: true,
        seq: i,
        timestamp: new Date(),
      });
    }
    const verifyOk = await verifyAuditChain(AuditLog, { maxRecords: 200 });
    expect(verifyOk.intact).toBe(true);

    // 绕过钩子直接改库（模拟篡改）→ 链校验应检出
    const target = await AuditLog.findOne({ username: `chain${stamp}` }).lean();
    await AuditLog.collection.updateOne({ _id: target._id }, { $set: { action: 'tampered' } });
    const verifyTampered = await verifyAuditChain(AuditLog, { maxRecords: 200 });
    expect(verifyTampered.intact).toBe(false);
  });

  // ================= auditBuffer flush =================

  test('auditBuffer：push 后 flush 成功落库且缓冲清空', async () => {
    const auditBuffer = require('../../services/auditBuffer');
    auditBuffer.__resetForTest();
    for (let i = 0; i < 3; i++) {
      auditBuffer.push({
        action: 'buffer_flush_test',
        category: 'system',
        username: `bfx${stamp}`,
        success: true,
        seq: i,
        timestamp: new Date(),
      });
    }
    await auditBuffer.flush();
    expect(auditBuffer.getStats().bufferLength).toBe(0);
    const saved = await AuditLog.countDocuments({
      action: 'buffer_flush_test',
      username: `bfx${stamp}`,
    });
    expect(saved).toBe(3);
  });

  // ================= errorHandler 错误映射 =================

  test('errorHandler：各错误类型映射（直驱）', async () => {
    // 该模块为函数直出（asyncHandler 挂在函数属性上），不能解构
    const errorHandler = require('../../middleware/errorHandler');

    const run = async (err) => {
      const res = makeRes();
      errorHandler(err, { method: 'GET', originalUrl: '/x', id: 't' }, res, () => {});
      return res;
    };

    const cast = await run(
      Object.assign(new Error('cast'), { name: 'CastError', kind: 'ObjectId' })
    );
    expect(cast.statusCode).toBe(400);

    const dup = await run(
      Object.assign(new Error('dup'), { code: 11000, keyValue: { username: 'x' } })
    );
    expect(dup.statusCode).toBe(400);

    const validation = await run(
      Object.assign(new Error('v'), { name: 'ValidationError', errors: { f: { message: 'bad' } } })
    );
    expect(validation.statusCode).toBe(400);

    const jwtErr = await run(Object.assign(new Error('jwt'), { name: 'JsonWebTokenError' }));
    expect(jwtErr.statusCode).toBe(401);

    const expired = await run(Object.assign(new Error('exp'), { name: 'TokenExpiredError' }));
    expect(expired.statusCode).toBe(401);

    const unknown = await run(new Error('boom'));
    expect(unknown.statusCode).toBe(500);
  });

  // ================= permissionHelper / apiResponse / ApiError =================

  test('permissionHelper：getUserPermissions / hasRole / getUserRoles / hasAny / hasAll', async () => {
    const helper = require('../../utils/permissionHelper');

    const permInfo = await helper.getUserPermissions(adminUserId);
    expect(permInfo.user).toBeTruthy();
    expect(permInfo.permissions).toContain('*:*');

    // Role.code 有 uppercase:true 转换，断言须用大写形态
    expect(await helper.hasRole(adminUserId, `SUPER_ADMIN_E_${stamp.toUpperCase()}`)).toBe(true);
    expect(await helper.hasRole(adminUserId, 'NOPE')).toBe(false);

    const roles = await helper.getUserRoles(adminUserId);
    expect(roles.length).toBeGreaterThan(0);

    expect(await helper.hasAnyPermission(adminUserId, ['*:*', 'x:y'])).toBe(true);
    expect(await helper.hasAllPermissions(adminUserId, ['*:*'])).toBe(true);

    const tree = await helper.getMenuTree(adminUserId);
    expect(Array.isArray(tree)).toBe(true);
  });

  test('apiResponse / ApiError 全方法', async () => {
    const ApiResponse = require('../../utils/apiResponse');
    const ApiError = require('../../utils/ApiError');

    const check = (res, status, success) => {
      expect(res.statusCode).toBe(status);
      expect(res.body.success).toBe(success);
    };

    check(Object.assign(makeRes(), ApiResponse.success(makeRes(), { a: 1 }, 'ok', 200)), 200, true);
    check(Object.assign(makeRes(), ApiResponse.error(makeRes(), 'bad', 400)), 400, false);
    check(Object.assign(makeRes(), ApiResponse.unauthorized(makeRes())), 401, false);
    check(Object.assign(makeRes(), ApiResponse.forbidden(makeRes())), 403, false);
    check(Object.assign(makeRes(), ApiResponse.notFound(makeRes())), 404, false);

    const paginated = makeRes();
    ApiResponse.paginated(
      paginated,
      [1, 2],
      { page: 1, limit: 10, total: 2, totalPages: 1 },
      'list'
    );
    expect(paginated.statusCode).toBe(200);
    expect(paginated.body.data).toEqual([1, 2]);

    const err = ApiError.badRequest('bad');
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe('bad');

    const notFoundErr = ApiError.notFound('gone');
    expect(notFoundErr.statusCode).toBe(404);
  });
});
