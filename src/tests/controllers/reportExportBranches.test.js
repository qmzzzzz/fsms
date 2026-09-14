/**
 * reportController.exportReport 分支补齐
 *
 * 依据全量覆盖率的未覆盖分支行号（exportReport handler）：
 *  - L851-853：format !== 'xlsx' 提前拒绝（此前仅测过 type 非法）
 *  - L856-858：日期参数非法 400（Invalid Date 会让查询在 DB 层抛错）
 *  - L892-898：audit 分支导出枚举白名单校验失败 400（P3-13 补的 level 维度）
 *  - L914-917：dataScope.type === 'none' → 强制空集，导出仅含表头的文件
 *  - 路由层：持认证但缺 report:export 的业务类型导出 → 403
 *  - getDashboardStats L111：dataScope=none → 全零空统计
 *  - getDeviceReport/getAlarmReport/getInspectionReport 的日期分支：
 *    非法日期 400（L255/L324/L411）与日期窗口并入聚合（L268/L330/L425/L450）
 *  - EXPORT_ROW_TRANSFORMS 行级 fallback（L620-690）：需真实导出行驱动，
 *    见 beforeAll 种子注释
 *  - buildExportQuery audit 分支参数（L733-768）：username/action/category/
 *    riskLevel/success/ip（$in 双形态）/userId/level 三档派生
 *  - streamExportRows populate 分批路径（L798-818）：205 行报警跨两个批次
 *  - dashboardCache TTL 定时清理（L49-54）：isolateModules + 假定时器
 *
 * 集成风格：supertest + createApp + JWT 直签（对齐 securityDeep.test.js）。
 * none 分支经 partial mock rbac.getDataScope 注入（路由层的 checkPermission
 * 保留 requireActual 原实现，权限闸不受影响）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

// getDataScope 可注入：none 分支无法用真实角色组合稳定构造
// （能过 report:export 路由闸的用户其 dataScope 必然非 none）
jest.mock('../../middleware/rbac', () => ({
  ...jest.requireActual('../../middleware/rbac'),
  getDataScope: jest.fn(),
}));

const rbac = require('../../middleware/rbac');

describe('reportController.exportReport 分支补齐', () => {
  let app;
  let superToken;
  let noExportToken;
  let superUserId;
  const stamp = `rexp${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '1h' });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');

    // 默认走真实 dataScope 语义（超管 = all），仅 none 用例临时覆盖
    rbac.getDataScope.mockImplementation(async () => ({ type: 'all' }));

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    const superUser = await User.create({
      username: `rexpsuper${stamp}`,
      email: `rexpsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superToken = signToken(String(superUser._id), superUser.username);
    superUserId = String(superUser._id);

    // 仅持登录可见的基础权限，不含 report:export → 业务类型导出应被路由闸拒绝
    const basicPerm = await Permission.findOneAndUpdate(
      { code: 'profile:read' },
      {
        $setOnInsert: { name: '个人资料读取', code: 'profile:read', type: 'api', module: 'system' },
      },
      { upsert: true, new: true }
    );
    const noExportRole = await Role.create({
      name: `无导出角色_${stamp}`,
      code: `NO_EXPORT_${stamp}`,
      level: 1,
      permissions: [basicPerm._id],
    });
    const noExportUser = await User.create({
      username: `rexpnone${stamp}`,
      email: `rexpnone${stamp}@example.com`,
      password: PASSWORD,
      roles: [noExportRole._id],
    });
    noExportToken = signToken(String(noExportUser._id), noExportUser.username);

    const { createApp } = require('../../app');
    app = createApp();

    // ===== 导出数据行种子 =====
    // EXPORT_ROW_TRANSFORMS 的行级 fallback 分支（L620-690）只在真实行流过
    // streamExportRows 时执行——此前用例全部导出空数据，transform 一次都没跑。
    // 每张表刻意造「全字段 + 缺省字段」两行，让映射命中与 '-' 兜底两侧都走到。
    const FireAlarm = require('../../models/FireAlarm');
    const FireDevice = require('../../models/FireDevice');
    const Inspection = require('../../models/Inspection');
    const AuditLog = require('../../models/AuditLog');
    const now = new Date();

    // 报警三行：驱动 formatExportLocation 三分支与 alarms 行 fallback
    await FireAlarm.create([
      {
        alarmCode: `REXPA${stamp}FULL`,
        alarmType: 'smoke', // 命中 alarmTypeMap
        description: `分支补齐全字段报警_${stamp}`,
        status: 'pending', // 命中 statusMap
        occurredAt: now,
        location: { building: 'A栋', floor: '3F', room: '301' }, // 三段拼接
        reporter: { name: '张三' },
        handleResult: '已现场处理',
        handler: superUser._id, // populate 命中 username 兜底 realName
      },
      {
        alarmCode: `REXPA${stamp}BARE`,
        alarmType: 'other',
        description: `分支补齐缺省报警_${stamp}`,
        // occurredAt/location/reporter/handler/handleResult 全缺 → 各列 '-'
      },
      {
        alarmCode: `REXPA${stamp}COORD`,
        alarmType: 'other',
        description: `分支补齐坐标位置报警_${stamp}`,
        // building/floor/room 全空仅坐标 → location 兜底 '-'（L623 假侧）
        location: { coordinates: { lat: 30.1, lng: 120.2 } },
      },
    ]);

    // 设备两行：map 命中/未命中（scrapped 不在 deviceStatusMap → 透传原值）
    await FireDevice.create([
      {
        deviceCode: `REXPD${stamp}FULL`,
        deviceName: `分支补齐全字段设备_${stamp}`,
        deviceType: 'smoke_detector',
        status: 'normal',
        installDate: now,
        location: { building: 'B栋', floor: '2F', room: '202' },
        nextCheckDate: now,
        expiryDate: now,
      },
      {
        deviceCode: `REXPD${stamp}BARE`,
        deviceName: `分支补齐缺省设备_${stamp}`,
        deviceType: 'extinguisher',
        status: 'scrapped',
        installDate: now,
        // nextCheckDate/expiryDate/location 缺省 → '-' 兜底
      },
    ]);

    // 巡检两行：人员/时间字段齐备 vs 全缺
    await Inspection.create([
      {
        title: `分支补齐全字段巡检_${stamp}`,
        inspectionType: 'daily',
        status: 'completed',
        result: 'normal',
        planStartTime: now,
        planEndTime: now,
        actualStartTime: now,
        actualEndTime: now,
        assignedTo: [superUser._id], // populate 命中 username（realName 缺省走 || 兜底）
        remark: '无异常',
      },
      {
        title: `分支补齐缺省巡检_${stamp}`,
        inspectionType: 'special',
        // 状态/结果/四个时间/人员/备注全缺 → '-' 兜底
      },
    ]);

    // 审计三行：覆盖日志等级三档派生（错误/警告/信息）与各列 fallback
    await AuditLog.create([
      {
        action: 'login_success', // 命中 EXPORT_ACTION_LABELS
        category: 'auth',
        username: `rexpaudit${stamp}`,
        success: false, // → 等级「错误」
        riskLevel: 'high', // 命中 EXPORT_RISK_LEVEL_LABELS
        method: 'GET',
        path: '/api/example',
        ip: '203.0.113.10',
        duration: 120,
        reason: `分支补齐审计行_${stamp}`,
      },
      {
        action: 'custom_branch_action', // 不在映射表 → 透传原值
        category: 'user',
        username: `rexpaudit${stamp}`,
        success: true,
        riskLevel: 'medium', // 成功+medium → 等级「警告」
        reason: `分支补齐审计行_${stamp}`,
        // method/path/ip/duration 缺省 → '-'
      },
      {
        action: 'logout',
        category: 'auth',
        username: `rexpaudit${stamp}`,
        success: true,
        // riskLevel 缺省 → 等级「信息」+ riskLevel 列 '-'
        reason: `分支补齐审计行_${stamp}`,
      },
    ]);

    // 205 行报警：populate 分批导出（BATCH_SIZE=200）跨两个批次，
    // 覆盖 streamExportRows 的 lastId 续批与 do-while 终止（L805-818）
    await FireAlarm.insertMany(
      Array.from({ length: 205 }, (_, i) => ({
        alarmCode: `REXPB${stamp}${String(i).padStart(3, '0')}`,
        alarmType: 'temp_abnormal',
        description: `分支补齐批量报警_${stamp}_${i}`,
      }))
    );
  });

  afterAll(async () => {
    rbac.getDataScope.mockRestore?.();
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteMany({ username: new RegExp(`^rexp(super|none|audit)${stamp}$`) }).catch(
        () => {}
      );
      await Role.deleteMany({ code: new RegExp(`^NO_EXPORT_${stamp}$`) }).catch(() => {});
      // 种子数据按前缀清理（报警两批 / 设备 / 巡检 / 审计）
      const FireAlarm = require('../../models/FireAlarm');
      const FireDevice = require('../../models/FireDevice');
      const Inspection = require('../../models/Inspection');
      const AuditLog = require('../../models/AuditLog');
      await FireAlarm.deleteMany({ alarmCode: new RegExp(`^REXP[AB]${stamp}`) }).catch(() => {});
      await FireDevice.deleteMany({ deviceCode: new RegExp(`^REXPD${stamp}`) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(`^分支补齐.*巡检_${stamp}$`) }).catch(
        () => {}
      );
      await AuditLog.deleteMany({ reason: new RegExp(`^分支补齐审计行_${stamp}$`) }).catch(
        () => {}
      );
      await mongoose.connection.close();
    }
  });

  test('format != xlsx → 400 提前拒绝，避免前端误以为导出成功（L851-853）', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=alarms&format=csv')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('不支持的导出格式');
  });

  test('日期参数非法 → 400（Invalid Date 会在查询层抛错，必须前置拦截）（L856-858）', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=alarms&startDate=not-a-date')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('日期参数格式错误');
  });

  test('audit 导出枚举白名单校验失败 → 400（非法 level 不允许静默放大导出范围）（L892-898）', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=audit&level=bogus-level')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(400);
  });

  test('日期窗口内无数据 → 200 空表头文件（响应头齐备）', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=devices&startDate=2099-01-01&endDate=2099-01-02')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('spreadsheetml');
    expect(res.headers['content-disposition']).toContain('attachment');
  });

  test('dataScope.type=none → 强制空集，仅导出表头（越权数据零泄漏）（L914-917）', async () => {
    rbac.getDataScope.mockResolvedValueOnce({ type: 'none' });
    const res = await request(app)
      .get('/api/reports/export?type=devices')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('spreadsheetml');
    rbac.getDataScope.mockResolvedValue({ type: 'all' });
  });

  test('已认证但缺 report:export → 业务类型导出被路由闸 403', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=devices')
      .set('Authorization', `Bearer ${noExportToken}`);
    expect(res.status).toBe(403);
  });

  // ===== getDashboardStats / 三张报表接口的日期与范围分支 =====

  test('dashboard：dataScope=none → 全零空统计（越权数据零泄漏）（L111）', async () => {
    rbac.getDataScope.mockResolvedValueOnce({ type: 'none' });
    const res = await request(app)
      .get('/api/reports/dashboard')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.devices).toMatchObject({
      total: 0,
      online: 0,
      fault: 0,
      needMaintenance: 0,
    });
    expect(res.body.data.alarms.total).toBe(0);
    expect(res.body.data.inspections.total).toBe(0);
  });

  test('三张报表接口：非法日期 → 400 前置拦截（L255/L324/L411）', async () => {
    for (const path of [
      '/api/reports/devices',
      '/api/reports/alarms',
      '/api/reports/inspections',
    ]) {
      const res = await request(app)
        .get(`${path}?startDate=not-a-date`)
        .set('Authorization', `Bearer ${superToken}`);
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('日期参数格式错误');
    }
  });

  test('三张报表接口：日期窗口并入聚合 → 200（L268/L330/L425/L450）', async () => {
    for (const path of [
      '/api/reports/devices',
      '/api/reports/alarms',
      '/api/reports/inspections',
    ]) {
      const res = await request(app)
        .get(`${path}?startDate=2020-01-01&endDate=2099-01-01`)
        .set('Authorization', `Bearer ${superToken}`);
      expect(res.status).toBe(200);
    }
  });

  // ===== 真实行数据的四类导出（EXPORT_ROW_TRANSFORMS 行级 fallback）=====

  test('带数据行导出：四类全 200（行级 fallback 与映射命中两侧均执行）', async () => {
    for (const type of ['alarms', 'devices', 'audit', 'inspections']) {
      const res = await request(app)
        .get(`/api/reports/export?type=${type}&format=xlsx`)
        .set('Authorization', `Bearer ${superToken}`);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('spreadsheetml');
    }
  });

  // ===== buildExportQuery 的 audit 参数分支（L733-768）=====

  test('audit 导出带全部筛选参数 → 200（username/action/category/riskLevel/success/ip $in/userId）', async () => {
    const res = await request(app)
      .get(
        '/api/reports/export?type=audit&format=xlsx' +
          `&username=rexp&action=login_success&category=auth&riskLevel=high&success=true` +
          `&ip=2001:DB8::1&userId=${superUserId}`
      )
      .set('Authorization', `Bearer ${superToken}`);
    // 2001:DB8::1 归一化小写后与原始串不同 → ipVariants 双元素 → $in 匹配
    expect(res.status).toBe(200);
  });

  test('audit 导出 level 三档派生（error/warning/info 各一次 $and 条件构建）→ 200', async () => {
    for (const level of ['error', 'warning', 'info']) {
      const res = await request(app)
        .get(`/api/reports/export?type=audit&format=xlsx&level=${level}`)
        .set('Authorization', `Bearer ${superToken}`);
      expect(res.status).toBe(200);
    }
  });

  test('audit 导出：非法 ip / 非法 userId → 构建期抛错 500（当前行为口径）', async () => {
    const badIp = await request(app)
      .get('/api/reports/export?type=audit&format=xlsx&ip=999.999.999.999')
      .set('Authorization', `Bearer ${superToken}`);
    expect(badIp.status).toBe(500);

    const badUserId = await request(app)
      .get('/api/reports/export?type=audit&format=xlsx&userId=not-an-object-id')
      .set('Authorization', `Bearer ${superToken}`);
    expect(badUserId.status).toBe(500);
  });

  // ===== streamExportRows populate 两阶段分批（B-4 修复后）=====

  test('populate 分批导出：205 行报警跨两个 $in 回填批次 → 200', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=alarms&format=xlsx')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('spreadsheetml');
  });

  test('B-4 回归：导出行序与列表接口一致（config.sort=occurredAt 倒序，而非 _id 序）', async () => {
    const FireAlarm = require('../../models/FireAlarm');
    const day = 24 * 60 * 60 * 1000;
    const now = Date.now();
    const tag = `ORD${stamp}`;
    // 插入序与业务序刻意相反：_id 最小的 A 时间最旧，_id 最大的 B 时间最新。
    // 旧实现按 _id 升序写出（A,B,C）；修复后必须按 occurredAt 倒序（B,C,A）
    await FireAlarm.create([
      {
        alarmCode: `${tag}A`,
        alarmType: 'other',
        description: `B-4 排序种子A_${stamp}`,
        occurredAt: new Date(now - 3 * day),
      },
      {
        alarmCode: `${tag}B`,
        alarmType: 'other',
        description: `B-4 排序种子B_${stamp}`,
        occurredAt: new Date(now - 1 * day),
      },
      {
        alarmCode: `${tag}C`,
        alarmType: 'other',
        description: `B-4 排序种子C_${stamp}`,
        occurredAt: new Date(now - 2 * day),
      },
    ]);

    const res = await request(app)
      .get('/api/reports/export?type=alarms&format=xlsx')
      .set('Authorization', `Bearer ${superToken}`)
      .buffer(true)
      .parse((r, cb) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);

    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(res.body);
    const sheet = wb.worksheets[0];
    const markerOrder = [];
    sheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return; // 表头
      const code = String(row.getCell(1).value || '');
      if (code.startsWith(tag)) markerOrder.push(code.slice(tag.length));
    });
    expect(markerOrder).toEqual(['B', 'C', 'A']);
  });

  test('populate callback retains the first-stage query during batch hydration', async () => {
    const { streamExportRows } = require('../../controllers/reportController').__test;
    const calls = [];
    let phase = 0;
    const model = {
      find: jest.fn((query) => {
        calls.push(query);
        const chain = {
          sort: () => chain,
          limit: () => chain,
          select: () => chain,
          populate: () => chain,
          lean: async () => {
            phase += 1;
            return phase === 1 ? [{ _id: 'ordered-id' }] : [{ _id: 'ordered-id', scope: 'ok' }];
          },
        };
        return chain;
      }),
    };
    const rows = [];

    await streamExportRows(
      { addRow: (row) => rows.push(row) },
      { model, sort: { occurredAt: -1 }, populate: [{ path: 'handler' }] },
      { scope: 'allowed' },
      (doc) => doc
    );

    expect(calls).toHaveLength(2);
    expect(calls[1]).toEqual({
      $and: [{ scope: 'allowed' }, { _id: { $in: ['ordered-id'] } }],
    });
    expect(rows).toEqual([{ _id: 'ordered-id', scope: 'ok' }]);
  });

  // ===== dashboardCache TTL 定时清理（L49-54）=====

  test('dashboardCache 定时清理：过期条目回收、有效条目保留（L49-54）', () => {
    // 惰性定时器（评价报告低危项）：sweeper 不再于模块加载期启动，
    // 需显式调用 ensureDashboardCacheSweeper（模拟首次业务写入）后，
    // setInterval 落在假定时器上，advance 才能确定性触发
    jest.useFakeTimers();
    let dashboardCache = null;
    let ensureSweeper = null;
    try {
      let isolatedController;
      jest.isolateModules(() => {
        isolatedController = require('../../controllers/reportController');
      });
      ({ dashboardCache, ensureDashboardCacheSweeper: ensureSweeper } = isolatedController.__test);
      ensureSweeper();

      dashboardCache.set('expired-key', { data: {}, expireAt: Date.now() - 1000 });
      dashboardCache.set('live-key', { data: {}, expireAt: Date.now() + 60 * 1000 });

      jest.advanceTimersByTime(30 * 1000 + 1); // 触发 30s 清理节拍

      expect(dashboardCache.has('expired-key')).toBe(false);
      expect(dashboardCache.has('live-key')).toBe(true);
    } finally {
      // 假定时器必须还原：泄漏会冻结后续用例的 mongoose/supertest 定时器
      if (dashboardCache) dashboardCache.clear();
      jest.useRealTimers();
    }
  });
});
