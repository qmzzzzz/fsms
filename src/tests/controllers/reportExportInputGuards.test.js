/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：reportController.exportReport 的输入与范围分支
 * 守护的不变式：非 xlsx 提前拒绝；非法日期 400；导出枚举白名单校验；dataScope.type==="none" → 强制空集
 * 可证伪性：变异实测（筛查 N=2）：杀 2/3
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [部分有效] `:32-35` 全局 mock `getDataScope → {type:"all"}` 导致导出越权面被**抹平**（原出处 2026-09-16 全面代码审计报告；**该报告已删除**，问题编号保留原样）
 *     复核（2026-09-20 **变异实测**）：本文件内确实被抹平（观察为真），但**数据范围解析本身被大量用例守着**——
 *     把真实 `getDataScope` 改成永远 `{type:"all"}`，`rbac.js` 的 99 套全量 related（1162 例）中
 *     **杀掉 27 例 / 12 套**（含"部门主管只见本部门设备""self 范围看他人 403""报警派单后 self 读范围"等）。
 *     证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法。
 *
 * 命名沿革：2026-09-20 由 `reportExportBranches.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * reportController.exportReport / 报表统计接口 分支补齐
 *
 * 【行号说明】本文件早期版本用 `L<行号>` 标注被测分支。2026-09-16 第二轮审计把
 * 报表导出组件从 reportController 抽到 services/reportExportService.js 与
 * services/reportWorkbookService.js（控制器由 884 行降到 253 行），所有行号整体漂移，
 * 标注全部失实。按「注释必须与实现同步」的要求，现改为语义描述、不再写行号——
 * 行号是易漂移的脆弱耦合，函数名与行为描述才是稳定锚点。
 *
 * 覆盖分支：
 *  - exportReport：format !== 'xlsx' 提前拒绝（此前仅测过 type 非法）
 *  - exportReport：日期参数非法 400（Invalid Date 会让查询在 DB 层抛错）
 *  - exportReport：audit 分支导出枚举白名单校验失败 400（P3-13 补的 level 维度）
 *  - exportReport：dataScope.type === 'none' → 强制空集，导出仅含表头的文件
 *  - 路由层：持认证但缺 report:export 的业务类型导出 → 403
 *  - getDashboardStats：dataScope=none → 全零空统计
 *  - getDeviceReport/getAlarmReport/getInspectionReport 的日期分支：
 *    非法日期 400 与「日期窗口并入聚合」（两条互为对照，见下）
 *  - EXPORT_ROW_TRANSFORMS 行级 fallback：需真实导出行驱动，见 beforeAll 种子注释
 *  - buildExportQuery 的 audit 分支参数：username/action/category/riskLevel/
 *    success/ip（$in 双形态）/userId/level 三档派生
 *  - streamExportRows 的 populate 分批回填（BATCH_SIZE=200）：205 行跨两个批次
 *  - dashboardCache TTL 定时清理：isolateModules + 假定时器
 *
 * 【断言口径】「窗口/筛选/分批」这类用例必须做内容级断言：
 * 一个把筛选器整个删掉的实现，返回的仍是合法的 200 + spreadsheetml 文件。
 * 只断状态码的用例无法证伪，等于没测（详见各用例内的变异验证记录）。
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

  /**
   * 把导出的 xlsx 响应体解析成二维文本表（含表头行）。
   * 多个用例需要「内容级」断言——只断 200 无法证伪筛选器被删，
   * 因为返回一个未经过滤的完整表格同样是 200。
   * @param {Buffer} body xlsx 二进制
   * @returns {Promise<string[][]>}
   */
  const parseWorkbookRows = async (body) => {
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(body);
    const ws = wb.worksheets[0];
    const rows = [];
    ws.eachRow((row) => {
      const cells = [];
      row.eachCell({ includeEmpty: true }, (cell) => cells.push(String(cell.value ?? '')));
      rows.push(cells);
    });
    return rows;
  };

  /** 把 Buffer 响应体收全（supertest 默认不缓冲二进制） */
  const bufferBody = (r, cb) => {
    const chunks = [];
    r.on('data', (c) => chunks.push(c));
    r.on('end', () => cb(null, Buffer.concat(chunks)));
  };

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
    // EXPORT_ROW_TRANSFORMS 的行级 fallback 分支只在真实行流过
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
        // building/floor/room 全空仅坐标 → location 兜底 '-'（formatExportLocation 的假侧）
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
        userId: superUser._id, // userId 维度筛选的内容级对照锚点
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
        userId: superUser._id, // 同上：让 userId 筛选命中 2 行而非 3 行，构成可证伪对照
        success: true,
        // riskLevel 缺省 → 等级「信息」+ riskLevel 列 '-'
        reason: `分支补齐审计行_${stamp}`,
      },
    ]);

    // 205 行报警：populate 分批导出（BATCH_SIZE=200）跨两个批次，
    // 覆盖 streamExportRows 的批次循环：orderedIds 按 BATCH_SIZE 分批回填，
    // 循环必须走到尾批（截断为单批会丢 200..204 这 5 行，见用例内断言）
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

  test('format != xlsx → 400 提前拒绝，避免前端误以为导出成功', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=alarms&format=csv')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('不支持的导出格式');
  });

  test('日期参数非法 → 400（Invalid Date 会在查询层抛错，必须前置拦截）', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=alarms&startDate=not-a-date')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('日期参数格式错误');
  });

  test('audit 导出枚举白名单校验失败 → 400（非法 level 不允许静默放大导出范围）', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=audit&level=bogus-level')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(400);
    // 「不允许静默放大导出范围」的判据是错误信息点名了 level 与合法取值，
    // 而非泛泛的 400 —— 静默忽略同样会返回 200，这才是本用例要防的
    expect(res.body.message).toContain('level');
    expect(res.body.message).toContain('info/warning/error');
  });

  test('日期窗口内无数据 → 200 空表头文件（响应头齐备）', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=devices&startDate=2099-01-01&endDate=2099-01-02')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('spreadsheetml');
    expect(res.headers['content-disposition']).toContain('attachment');
  });

  test('dataScope.type=none → 强制空集，导出的 xlsx 除表头外零数据行（越权面内容级验证）', async () => {
    // 本次改动复审强化：原用例只断言 200 + content-type，等于「只要返回了一个 xlsx 就算过」——
    // 而 dataScope=none 的**安全语义**是「不得导出任何他人数据」。响应头无法证伪这一语义
    // （返回一个装满数据的文件同样是 200 + spreadsheetml）。
    // 现用 exceljs 解析真实响应体，断言：① 工作表存在；② 除表头行外无数据行；
    // ③ 种子数据里的可识别标记（如报警编码前缀）一个都不出现。
    rbac.getDataScope.mockResolvedValueOnce({ type: 'none' });
    const res = await request(app)
      .get('/api/reports/export?type=devices')
      .set('Authorization', `Bearer ${superToken}`)
      .buffer(true)
      .parse((r, cb) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('spreadsheetml');

    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(res.body);
    const ws = wb.worksheets[0];
    expect(ws).toBeTruthy();

    // 表头行之后不得有任何数据行（rowCount 含表头，故允许 1 行）
    expect(ws.actualRowCount).toBeLessThanOrEqual(1);

    // 全表文本化后搜种子标记：任何一条泄漏都会被抓住
    let dump = '';
    ws.eachRow((row) => {
      row.eachCell((cell) => {
        dump += String(cell.value ?? '') + '\u0001';
      });
    });
    expect(dump).not.toContain(stamp); // 本套件所有种子数据的公共标记
    expect(dump).not.toContain('REXPD'); // 设备种子编码前缀

    rbac.getDataScope.mockResolvedValue({ type: 'all' });
  });

  test('已认证但缺 report:export → 业务类型导出被路由闸 403', async () => {
    const res = await request(app)
      .get('/api/reports/export?type=devices')
      .set('Authorization', `Bearer ${noExportToken}`);
    expect(res.status).toBe(403);
    // 路由闸的码是 PERMISSION_DENIED（checkPermission 统一出口），
    // 与「audit 导出需 security:audit」的业务码区分
    expect(res.body.errors.errorCode).toBe('PERMISSION_DENIED');
  });

  // ===== getDashboardStats / 三张报表接口的日期与范围分支 =====

  test('dashboard：dataScope=none → 全零空统计（越权数据零泄漏）', async () => {
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

  test('三张报表接口：非法日期 → 400 前置拦截', async () => {
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

  test('三张报表接口：日期窗口并入聚合（窗口内无数据 / 全窗口有数据 双向对照）', async () => {
    // 本次改动复审强化：原用例只断 200 —— 而「日期窗口被丢弃」同样返回 200
    // （已用变异验证：删掉 matchStage 的日期合并，原断言全绿）。
    // 现改为内容级：查询窗口取 2099 年（种子数据全在今天），断言导出行归零；
    // 再取全窗口断言种子行回来。两次对照才能证伪「筛选器被忽略」。
    const windowed = await request(app)
      .get(`${'/api/reports/alarms'}?startDate=2099-01-01&endDate=2099-12-31`)
      .set('Authorization', `Bearer ${superToken}`);
    expect(windowed.status).toBe(200);
    expect(windowed.body.data.byType).toEqual([]);
    expect(windowed.body.data.byStatus).toEqual([]);

    // 对照：不传日期（空窗口 = 不过滤）必须能看到今天种子的报警
    const all = await request(app)
      .get('/api/reports/alarms')
      .set('Authorization', `Bearer ${superToken}`);
    expect(all.status).toBe(200);
    const totalByType = all.body.data.byType.reduce((a, r) => a + r.count, 0);
    expect(totalByType).toBeGreaterThan(0);
  });

  // ===== 真实行数据的四类导出（EXPORT_ROW_TRANSFORMS 行级 fallback）=====

  test('带数据行导出：四类全 200 且内容含种子行（行级 fallback 与映射命中两侧均执行）', async () => {
    // 本次改动复审强化：原用例只断 200 + content-type，等于「返回了 xlsx 就算过」。
    // 变异验证：把 EXPORT_ROW_TRANSFORMS 置空，原断言仍全绿——因为行转换被绕过
    // 时导出的仍是合法 xlsx。现解析响应体，逐类断言种子标记确实出现在单元格中。
    const seeds = {
      alarms: `REXPA${stamp}FULL`,
      devices: `REXPD${stamp}FULL`.toUpperCase(), // deviceCode 模型层 uppercase: true
      audit: `rexpaudit${stamp}`, // audit 列定义无 reason 字段，用 username 作标记
      inspections: `分支补齐全字段巡检_${stamp}`,
    };
    for (const [type, marker] of Object.entries(seeds)) {
      const res = await request(app)
        .get(`/api/reports/export?type=${type}&format=xlsx`)
        .set('Authorization', `Bearer ${superToken}`)
        .buffer(true)
        .parse(bufferBody);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('spreadsheetml');

      const rows = await parseWorkbookRows(res.body);
      expect(rows.length).toBeGreaterThan(1); // 至少表头 + 一行数据
      const dump = rows.map((r) => r.join('\u0001')).join('\u0002');
      expect(dump).toContain(marker);
      // reason/description 字段也经行转换写出：确认转换器没有整体塌成 '-'
      expect(dump).not.toBe('');
    }
  });

  // ===== buildExportQuery 的 audit 参数分支 =====

  test('audit 导出带全部筛选参数 → 200 且筛选真正生效（username/action/category/riskLevel/success/ip $in/userId）', async () => {
    // 本次改动复审强化：原用例只断 200。变异验证：把 username 正则过滤整个删掉，
    // 原断言仍全绿（导出的是全量表，同样是 200）。现按「命中/不命中」双向对照：
    // ① 用种子值筛选 → 必须出现 seed 行；② 用一个不可能存在的值 → 必须为空。
    const params = (over = {}) =>
      new URLSearchParams({ type: 'audit', format: 'xlsx', ...over }).toString();

    const hit = await request(app)
      .get('/api/reports/export?' + params({ username: `rexpaudit${stamp}` }))
      .set('Authorization', `Bearer ${superToken}`)
      .buffer(true)
      .parse(bufferBody);
    expect(hit.status).toBe(200);
    const hitRows = await parseWorkbookRows(hit.body);
    expect(hitRows.length).toBe(4); // 表头 + 3 行同用户名种子

    // 对照：不存在的 username → 只剩表头（证伪「筛选被静默忽略」）
    const miss = await request(app)
      .get('/api/reports/export?' + params({ username: `no_such_user_${stamp}` }))
      .set('Authorization', `Bearer ${superToken}`)
      .buffer(true)
      .parse(bufferBody);
    expect(miss.status).toBe(200);
    const missRows = await parseWorkbookRows(miss.body);
    expect(missRows.length).toBe(1);

    // action / category / success 组合筛选同样按内容核对（命中 1 行）
    const combo = await request(app)
      .get(
        '/api/reports/export?' +
          params({ action: 'login_success', category: 'auth', success: 'false' })
      )
      .set('Authorization', `Bearer ${superToken}`)
      .buffer(true)
      .parse(bufferBody);
    expect(combo.status).toBe(200);
    const comboRows = await parseWorkbookRows(combo.body);
    expect(comboRows.length).toBe(2); // 表头 + login_success/false 那一行

    // userId 维度：3 行种子中 2 行挂在 superUser 名下。必须**叠加 username 种子
    // 约束**再断言——全局审计中间件会给本文件的每一发 HTTP 请求写 1 行
    // userId=superUser 的审计行，运行时行数随用例顺序膨胀（--randomize
    // seed 31337/777001 实测：无 username 约束时 4 变 6）；username 是
    // 唯一 stamp，天然隔离运行时行。可证伪性不变：userId 过滤若失效会捞到
    // 第 3 行种子（另一个用户的 rexpaudit 行），username 失效会捞到运行时行。
    const byUser = await request(app)
      .get('/api/reports/export?' + params({ userId: superUserId, username: `rexpaudit${stamp}` }))
      .set('Authorization', `Bearer ${superToken}`)
      .buffer(true)
      .parse(bufferBody);
    expect(byUser.status).toBe(200);
    const byUserRows = await parseWorkbookRows(byUser.body);
    expect(byUserRows.length).toBe(3); // 表头 + 2 行 superUser 名下的种子
  });

  test('audit 导出 level 三档派生：每档内容互不相同且各自可证伪（error/warning/info $and 条件）', async () => {
    // 本次改动复审强化：原用例 for 循环只断 200，三档都拿到全量表也照样通过。
    // 变异验证：把 level==="error" 的判断改成 false（该档筛选器整个失效），
    // 原断言全绿。现按内容断言：三档的行数/首列等级文字必须各不相同。
    const levels = ['error', 'warning', 'info'];
    const seen = new Map();
    for (const level of levels) {
      const res = await request(app)
        // 叠加 username 隔离：全局审计中间件会为本次测试的 HTTP 请求写入额外行，
        // 仅按 level 过滤会把它们一并捞进来（其等级多为 info），使三档断言失准
        .get(
          `/api/reports/export?type=audit&format=xlsx&level=${level}` +
            `&username=rexpaudit${stamp}`
        )
        .set('Authorization', `Bearer ${superToken}`)
        .buffer(true)
        .parse(bufferBody);
      expect(res.status).toBe(200);
      const rows = await parseWorkbookRows(res.body);
      // 每档恰好命中一行种子（三行种子分别为 error/warning/info）
      expect(rows.length).toBe(2); // 表头 + 1 行
      const levelCell = rows[1][1]; // 第 2 列 = 日志等级
      expect(levelCell).toBeTruthy();
      seen.set(level, levelCell);
    }
    // 三档派生结果必须互不相同：若某一档的派生条件被删，会退化成同一集合
    expect(new Set(seen.values()).size).toBe(3);
  });

  test('audit 导出：非法 ip / 非法 userId → 400 参数错误（与 CSV 导出同口径）', async () => {
    // 本用例原先把 500 + INTERNAL_ERROR 钉成"当前行为口径"。那是 characterization：
    // 一个写坏的 URL 参数得到"服务器内部错误，请稍后重试"，运维按服务端故障去查，
    // 用户看不出是自己填错了。`buildExportQuery` 的两处抛错全是参数校验（与
    // utils/auditQuery.js 同一份判据），CSV 导出侧一直兜成 400 + 原文案，
    // 现 xlsx 侧对齐。防外泄的原意保留：不得出现 mongoose/CastError 字样。
    const badIp = await request(app)
      .get('/api/reports/export?type=audit&format=xlsx&ip=999.999.999.999')
      .set('Authorization', `Bearer ${superToken}`);
    expect(badIp.status).toBe(400);
    expect(badIp.body.message).toBe('参数 ip 必须是合法的 IPv4/IPv6 地址');
    expect(badIp.body.message).not.toMatch(/CastError|mongoose|ValidatorError/i);

    const badUserId = await request(app)
      .get('/api/reports/export?type=audit&format=xlsx&userId=not-an-object-id')
      .set('Authorization', `Bearer ${superToken}`);
    expect(badUserId.status).toBe(400);
    expect(badUserId.body.message).toBe('参数 userId 必须是合法的用户 ID');
    expect(badUserId.body.message).not.toMatch(/CastError|mongoose|ValidatorError/i);
  });

  // ===== streamExportRows populate 两阶段分批（B-4 修复后）=====

  test('populate 分批导出：205 行报警跨两个 $in 回填批次 → 全部 205 行都在文件里', async () => {
    // 本次改动复审强化：原用例只断 200。分批回填若丢批（只回填第一批），同样是 200。
    // 现按内容断言：205 条种子编码必须一条不落地出现在导出文件中。
    const res = await request(app)
      .get('/api/reports/export?type=alarms&format=xlsx')
      .set('Authorization', `Bearer ${superToken}`)
      .buffer(true)
      .parse(bufferBody);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('spreadsheetml');

    const rows = await parseWorkbookRows(res.body);
    const dump = rows.map((r) => r.join('\u0001')).join('\u0002');
    // BATCH_SIZE=200 → 必须跨两个回填批次；漏批会让尾批（200..204）整体消失
    for (const i of [0, 199, 200, 204]) {
      expect(dump).toContain(`REXPB${stamp}${String(i).padStart(3, '0')}`);
    }
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

  // ===== dashboardCache TTL 定时清理 =====

  test('dashboardCache 定时清理：过期条目回收、有效条目保留', () => {
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
