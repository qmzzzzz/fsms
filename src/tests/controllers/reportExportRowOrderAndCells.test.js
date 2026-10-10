/**
 * xlsx 导出的行序与单元格文本（并行 agent 导出链报告的第 2、3 条，独立复现后修）
 *
 * 【缺陷形状一：并列段的行序与列表反号】
 * `EXPORT_MODEL_CONFIG` 的 sort 原先只写主排序键（`{occurredAt:-1}` / `{timestamp:-1}`
 * / `{planStartTime:-1}`），而 populate 分支"取 id"那条腿又补了一个**反向**的 `_id: 1`。
 * 仓库既有不变式不是新约定：「排序键取值可重复 ⇒ 必须有同向 `_id` 次级键」
 * （models/FireAlarm.js:160、models/Inspection.js:179、models/AuditLog.js:309 三处写明，
 * 复合索引也按 `{key:-1,_id:-1}` 建），列表服务层用的正是它
 * （AlarmService.js:112、InspectionService.js:146、auditQueryService.js:153），
 * 并由 tests/explainSpotcheckContract.test.js:66-71 逐字段钉住那四份排序。
 * 导出这一侧不满足 ⇒ 同一毫秒内的并列行，列表按 `_id` 降序、导出按 `_id` 升序，
 * 两份材料的第 N 行不是同一条记录（"导出即所见"破在并列段与 5000 行截断边界上）；
 * 顺带把 `{occurredAt:-1,_id:1}` 这种混合方向排序做成用不上复合索引的阻塞内存排序。
 *
 * 【缺陷形状二：空值占位符被加固成 `'-`】
 * `createSafeTransform` 把每一个单元格文本都过 `sanitizeSpreadsheetCell`，而后者给一切
 * 以 `-` 开头的文本加前导单引号 ⇒ 转换层自己写的占位符 `-` 也中了招，文件里显示 `'-`。
 * 实测（本仓库的 exceljs）：`cell.value = '=1+1'` 得到 type=3(String)、formula=undefined，
 * 即 xlsx 的单元格是**带类型的文本**，Excel 打开时不求值，那个单引号只是被显示出来。
 * 所以加固对 xlsx 不是为了"别让 Excel 执行"，而是为了断掉
 * "xlsx 另存为 CSV 再导入"那一跳（CSV 无类型，`-2+3` 会被求值）——真实数据照旧加固，
 * 只有我们自己写的占位符放行。同一条记录的 CSV 侧本就显示空，两份材料从此不再互相打脸。
 *
 * 【三条链怎么配对】
 * ① 夹具前提自证：并列段的 `occurredAt` 确实完全相同（否则行序由主键决定，本文件恒真）；
 * ② 正向对照：真实数据 `=1+1` 必须仍被加固、`duration=0` 必须仍显示 `0ms`
 *    （否则"放行占位符"会被写成"把危险前缀一起放行"或"把 0 吃成占位符"）；
 * ③ 可证伪对：导出行序 == 列表那份全序，而不是"看起来有序"。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const EXPORT_MODEL_CONFIG = require('../../services/reportExportService').EXPORT_MODEL_CONFIG;
const AuditLog = require('../../models/AuditLog');

/** tests/explainSpotcheckContract.test.js:66-71 钉住的那张表（列表侧的同一个全序） */
const LIST_SORTS = {
  alarms: { occurredAt: -1, _id: -1 },
  devices: { deviceCode: 1 },
  audit: { timestamp: -1, _id: -1 },
  inspections: { planStartTime: -1, _id: -1 },
};

describe('xlsx 导出的行序与单元格文本', () => {
  const stamp = `kq7o${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const MARKER_IP = '203.0.113.78';
  const PASSWORD = randomPassword();
  // 三条报警共用**同一个** occurredAt ⇒ 先后只能由次级键决定
  const TIE_TIME = new Date(Date.now() + 7 * 24 * 3600 * 1000);

  let app;
  let superToken;

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '24h' });

  /** xlsx 响应体 → 「表头 → 该列全部单元格文本（按文件里的行序）」 */
  const columnsFromWorkbook = async (body) => {
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(body);
    const ws = wb.worksheets[0];
    const header = [];
    ws.getRow(1).eachCell({ includeEmpty: true }, (cell, idx) => {
      header[idx - 1] = String(cell.value ?? '');
    });
    const out = {};
    header.forEach((name, idx) => {
      out[name] = [];
      ws.eachRow((row, rowNumber) => {
        if (rowNumber === 1) return;
        out[name].push(String(row.getCell(idx + 1).value ?? ''));
      });
    });
    return out;
  };

  const exportXlsx = async (query) => {
    const res = await request(app)
      .get(`/api/reports/export?format=xlsx&${query}`)
      .set('Authorization', `Bearer ${superToken}`)
      .buffer()
      .parse((r, cb) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    return columnsFromWorkbook(res.body);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    const FireAlarm = require('../../models/FireAlarm');

    const perms = [];
    for (const code of ['*:*', 'report:export', 'security:audit']) {
      perms.push(
        await Permission.findOneAndUpdate(
          { code },
          { $setOnInsert: { name: `ord_${code}`, code, type: 'api', module: 'system' } },
          { upsert: true, new: true }
        )
      );
    }
    const role = await Role.create({
      name: `行序对拍超管_${stamp}`,
      code: `ORDER_SUPER_${stamp}`,
      level: 10,
      permissions: perms.map((p) => p._id),
    });
    const superUser = await User.create({
      username: `kq7order${stamp}`,
      email: `kq7order${stamp}@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    superToken = signToken(String(superUser._id), superUser.username);

    // 描述里塞一条公式注入载荷：它必须仍被加固（正向对照），而占位符不得被加固
    await FireAlarm.create([
      {
        alarmType: 'smoke',
        description: `TIE-${stamp}-1`,
        occurredAt: TIE_TIME,
        status: 'pending',
      },
      {
        alarmType: 'smoke',
        description: `TIE-${stamp}-2`,
        occurredAt: TIE_TIME,
        status: 'pending',
      },
      {
        alarmType: 'smoke',
        description: `=1+1 ${stamp}`,
        occurredAt: TIE_TIME,
        status: 'pending',
        handleResult: '',
      },
    ]);

    // 审计侧：一条"没有 success / 没有 duration"的记录（suspicious_report 等直写点的常态）
    await AuditLog.create({
      action: 'suspicious_report',
      category: 'security',
      username: `kq7order${stamp}`,
      method: 'POST',
      path: `/order/${stamp}`,
      ip: MARKER_IP,
      timestamp: new Date(),
      reason: `行序与单元格夹具_${stamp}`,
      // 另附一条 duration=0 的，防止"放行占位符"被写成"把 0 也吃掉"
    });
    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      username: `kq7order${stamp}`,
      success: true,
      duration: 0,
      riskLevel: 'low',
      method: 'POST',
      path: `/order0/${stamp}`,
      ip: MARKER_IP,
      timestamp: new Date(),
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    const FireAlarm = require('../../models/FireAlarm');
    await FireAlarm.deleteMany({ description: new RegExp(`^TIE-${stamp}`) }).catch(() => {});
    await FireAlarm.deleteMany({ description: new RegExp(`^=1\\+1 ${stamp}$`) }).catch(() => {});
    await AuditLog.deleteMany({ ip: MARKER_IP }, { bypassAppendOnly: true }).catch(() => {});
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    await User.deleteMany({ username: new RegExp(`^kq7order${stamp}$`) }).catch(() => {});
    await Role.deleteMany({ code: new RegExp(`^ORDER_SUPER_${stamp}$`) }).catch(() => {});
  });

  test('① 前提自证：三条报警共用同一个 occurredAt ⇒ 先后只能由次级键决定', async () => {
    const FireAlarm = require('../../models/FireAlarm');
    const docs = await FireAlarm.find({
      description: new RegExp(`^TIE-${stamp}|^=1\\+1 ${stamp}$`),
    }).lean();
    expect(docs).toHaveLength(3);
    expect(new Set(docs.map((d) => +d.occurredAt))).toEqual(new Set([+TIE_TIME]));
    // 三条 _id 互不相同 ⇒ "并列段"确实存在：主排序键给不出唯一答案，
    // ② 那条对拍才有内容（否则文件顺序与次级键方向无关，本文件恒真）
    expect(new Set(docs.map((d) => String(d._id))).size).toBe(3);
  });

  test('② 导出行序 = 列表那份全序（并列段按 _id 降序，不是升序）', async () => {
    const FireAlarm = require('../../models/FireAlarm');
    const cols = await exportXlsx('type=alarms');
    const mine = (
      await FireAlarm.find({
        description: new RegExp(`^TIE-${stamp}|^=1\\+1 ${stamp}$`),
      })
        .sort({ occurredAt: -1, _id: -1 })
        .select('alarmCode')
        .lean()
    ).map((d) => d.alarmCode);
    expect(mine).toHaveLength(3);
    // 取本用例那几条在文件里的**相对顺序**（其他测试文件的报警也在这张表里）
    const codes = cols['报警编号'];
    expect(codes.filter((c) => mine.includes(c))).toEqual(mine);
  });

  test('③ 四份导出排序与列表同一张表（并列段的同向次级键）', () => {
    for (const [type, sort] of Object.entries(LIST_SORTS)) {
      expect({ type, sort: EXPORT_MODEL_CONFIG[type].sort }).toEqual({ type, sort });
    }
  });

  test('④ 空值占位符显示为 `-`，而真实数据的公式前缀照旧加固', async () => {
    const cols = await exportXlsx('type=alarms');
    const rows = cols['描述'].map((description, i) => ({
      description,
      location: cols['报警位置'][i],
      handler: cols['处理人'][i],
      handleResult: cols['处理结果'][i],
    }));

    // 我方占位符：不得带前导单引号
    for (const r of rows) {
      for (const value of Object.values(r)) {
        expect(value.startsWith("'-")).toBe(false);
      }
    }
    // 缺 location / handler 的行必须是 `-`，不能是空串——空串会把"未填"与
    // "导出丢了字段"两种状态混成同一种，读文件的人无从分辨
    const tied = rows.find((r) => r.description.startsWith('TIE-'));
    expect(tied).toBeDefined();
    expect(tied.location).toBe('-');
    expect(tied.handler).toBe('-');

    // 正向对照：外部输入以 `=` 开头仍必须加固成 `'=…`（放行的只有占位符）
    const payload = rows.find((r) => r.description.includes('=1+1'));
    expect(payload.description).toBe(`'=1+1 ${stamp}`);
  });

  test('⑤ 审计表：缺字段是 `-`，duration=0 是 `0ms`（两态不得塌成一个）', async () => {
    const cols = await exportXlsx(`type=audit&ip=${MARKER_IP}`);
    const paths = cols['请求路径'];
    const idxReport = paths.findIndex((p) => p.includes(`/order/${stamp}`));
    const idxZero = paths.findIndex((p) => p.includes(`/order0/${stamp}`));
    expect(idxReport).toBeGreaterThanOrEqual(0);
    expect(idxZero).toBeGreaterThanOrEqual(0);
    // suspicious_report：success / duration 从未写入
    expect(cols['操作结果'][idxReport]).toBe('-');
    expect(cols['执行时长'][idxReport]).toBe('-');
    // login_success 且 duration=0：必须是 0ms，不能退化成占位符
    expect(cols['操作结果'][idxZero]).toBe('成功');
    expect(cols['执行时长'][idxZero]).toBe('0ms');
  });
});
