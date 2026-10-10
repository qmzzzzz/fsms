/**
 * ──────────────────────────────────────────────────────────────────────────
 * 报表 xlsx 导出「不完整必须说出来」必须通到 HTTP 响应头（待办 #13 选项③）
 *
 * 被测对象：GET /api/reports/export?type=audit&format=xlsx
 *   （reportController.exportReport → reportWorkbookService.writeExportWorkbook）
 * 守护的不变式：EXPORT_LIMIT 硬截断可以保留，但**必须显式声明**——
 *   响应头 X-Export-Truncated: true + 表内末行脚注，双通道各答一个问题
 *   （头答"这个文件完整吗"，脚注答"缺的是哪一种"）。反形状是
 *   「HTTP 200 + 一份看起来完整的合规材料，其实少了后面全部记录」——
 *   与"筛选参数被静默翻译"同一族：结果集窄了，零提示。
 *
 * 为什么服务层用例不够：reportWorkbookService.test.js 与
 *   reportWorkbookExportIntegrity.test.js 断言的是 **mock 出来的 res 对象**
 *   （res.setHeader 被 toHaveBeenCalledWith）。那证明"服务会置头"，
 *   不证明"控制器真的把 res 交给了他、客户端收得到"。
 *   控制器侧此前只有负向一条（auditExportUsernamePrefixParity.test.js:235：
 *   完整导出不得带头）。缺的正是正向那条：**计数腿多报 ⇒ 真实响应上必须见到头**。
 *
 * 取证方式：
 *   - 真实 HTTP（supertest）+ 真实 mongod（mongodb-memory-server），取数腿不 mock。
 *   - 夹具用唯一 username 前缀自我隔离；计数腿 spy 取「原值 +1」自适配，
 *     不写死行数 ⇒ 别的套件往共享库加行也不会让本文件假红或假绿。
 *   - 脚注行号从表内实读，行数与实况对账，不与预期背。
 *   - 撞的是 countDrift 一格（计数之后被删除/不再匹配），不是 truncated 一格：
 *     后者要真造 5001 行，前者走同一条置头分支、成本一行 spy。
 *
 * 变异验证记录（2026-10-10，逐条改实现 → 跑本套件 → finally 还原，4/4 KILLED）：
 *   M1 控制器丢掉 total: exportTotal ⇒ countDrift 退 0 ⇒ ②③ 红（2 failed / 1 passed）：
 *      负用例仍绿，指纹正是"只有对账那一格哑火"。
 *   M2 服务层删掉 res.setHeader(TRUNCATION_HEADER, 'true') ⇒ 仅 ② 红（1 failed / 2 passed）：
 *      脚注仍在，所以③的位置断言不红——两条通道各有一条用例守着。
 *   M3 置头条件改成 if (true) ⇒ 仅 ① 红（1 failed / 2 passed）：负前提是唯一能分辨
 *      "该不说的时候别说"的用例。
 *   M4 脚注 addRow 换成 insertRow(2, …)（插到表头下一行）⇒ ②③ 红（2 failed / 1 passed）。
 * ──────────────────────────────────────────────────────────────────────────
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const AuditLog = require('../../models/AuditLog');

// 唯一前缀：夹具行与请求痕迹都带它，别的套件的行进不了本次查询结果集
const PREFIX = 'kq9trunc';
const stamp = `kq9s${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const MARKER_IP = '203.0.113.78';
const PASSWORD = randomPassword();
const FIXTURE_USERNAMES = [`${PREFIX}Alpha`, `${PREFIX}Beta`, `${PREFIX}Gamma`];
const USERNAME_COLUMN = '操作用户';

describe('报表 xlsx 导出的截断声明必须通到 HTTP 响应头（#13 选项③）', () => {
  let app;
  let superToken;

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '24h' });

  /** 真实走一遍导出；xlsx 是二进制体，必须 buffer + 自采集 */
  const exportAudit = () =>
    request(app)
      .get(`/api/reports/export?type=audit&format=xlsx&username=${PREFIX}`)
      .set('Authorization', `Bearer ${superToken}`)
      .buffer()
      .parse((r, cb) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });

  const sheetOf = async (body) => {
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(body);
    return wb.worksheets[0];
  };

  /** 脚注行行号；没有脚注返回 0。从末行往上找：脚注只允许出现在最后一行 */
  const footerRowNumberOf = (ws) => {
    for (let n = ws.rowCount; n >= 2; n--) {
      const first = String(ws.getRow(n).getCell(1).value ?? '');
      if (first.includes('数据不完整')) return n;
    }
    return 0;
  };

  /** 表头 → 该列全部单元格文本（与 auditExportUsernamePrefixParity 同一把尺） */
  const columnsOf = (ws) => {
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

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');

    // 两个权限都显式给：report:export 是入口，security:audit 是 audit 分支的叠加闸
    //（少后者会在控制器里被 403 拦下，根本走不到置头那一行）。
    // level 10 ⇒ 真实 getDataScope 返回 {type:'all'}，不 mock 数据范围轴。
    const perms = [];
    for (const code of ['report:export', 'security:audit']) {
      perms.push(
        await Permission.findOneAndUpdate(
          { code },
          { $setOnInsert: { name: `trunc_${code}`, code, type: 'api', module: 'system' } },
          { upsert: true, new: true }
        )
      );
    }
    const role = await Role.create({
      name: `口径截断超管_${stamp}`,
      code: `TRUNC_SUPER_${stamp}`,
      level: 10,
      permissions: perms.map((p) => p._id),
    });
    const superUser = await User.create({
      username: `kq9operator${stamp}`,
      email: `kq9operator${stamp}@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    superToken = signToken(String(superUser._id), superUser.username);

    await AuditLog.create(
      FIXTURE_USERNAMES.map((username, i) => ({
        action: 'login_failed',
        category: 'auth',
        username,
        success: false,
        riskLevel: 'low',
        method: 'GET',
        path: `/api/trunc/${i}`,
        ip: MARKER_IP,
        timestamp: new Date(Date.now() + i * 1000),
        reason: `截断声明夹具_${stamp}`,
      }))
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ ip: MARKER_IP }, { bypassAppendOnly: true }).catch(() => {});
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    await User.deleteMany({ username: new RegExp(`^kq9operator${stamp}$`) }).catch(() => {});
    await Role.deleteMany({ code: new RegExp(`^TRUNC_SUPER_${stamp}$`) }).catch(() => {});
  });

  // ===== ① 负前提：行数对得上时，头与脚注都不该出现 =====
  test('完整导出：无 X-Export-Truncated，表内无脚注行，数据行数等于夹具行数', async () => {
    const res = await exportAudit();
    expect(res.status).toBe(200);
    expect(res.headers['x-export-truncated']).toBeUndefined();
    const ws = await sheetOf(res.body);
    expect(footerRowNumberOf(ws)).toBe(0);
    // 表头 1 行之外全是数据行：脚注若被无条件追加，这里立刻多出一行
    expect(ws.rowCount - 1).toBe(FIXTURE_USERNAMES.length);
    const cols = columnsOf(ws);
    expect(cols[USERNAME_COLUMN].sort()).toEqual([...FIXTURE_USERNAMES].sort());
  });

  // ===== ② 正向：计数腿多报一条 ⇒ 真实响应必须带头，且脚报名点差额 =====
  test('计数腿多报 ⇒ X-Export-Truncated: true + 末行脚注写明少了几行', async () => {
    const original = AuditLog.countDocuments.bind(AuditLog);
    const spy = jest
      .spyOn(AuditLog, 'countDocuments')
      .mockImplementation((q, o) => original(q, o).then((n) => n + 1));
    try {
      const res = await exportAudit();
      expect(res.status).toBe(200);
      // 头是给程序化读取的：值必须是字符串 'true'，且只在真的不完整时出现
      expect(res.headers['x-export-truncated']).toBe('true');
      const ws = await sheetOf(res.body);
      const written = ws.rowCount - 2; // 表头 + 脚注
      expect(written).toBe(FIXTURE_USERNAMES.length);
      // 脚注是给"拿到文件的人"的：必须钉在最后一行，且逐字对账
      expect(footerRowNumberOf(ws)).toBe(ws.rowCount);
      const footer = String(ws.getRow(ws.rowCount).getCell(1).value ?? '');
      expect(footer).toContain('数据不完整');
      expect(footer).toContain(`实际写入 ${written} 行`);
      expect(footer).toContain(`计数时 ${written + 1} 行`);
      expect(footer).toContain('请缩小时间范围或增加筛选条件后重新导出');
      // 脚注不得被算成数据行：用户名列里出现脚注即说明行定位错了
      const cols = columnsOf(ws);
      expect(cols[USERNAME_COLUMN]).toHaveLength(written + 1); // 数据行 + 脚注行
      for (const name of cols[USERNAME_COLUMN].slice(0, written)) {
        expect(name.startsWith(PREFIX)).toBe(true);
      }
    } finally {
      spy.mockRestore();
    }
  });

  // ===== ③ 脚注位置：只能追加在末行，不能挤进数据中间 =====
  test('脚注是最后一行，且不落在任何数据行之间（Excel 打开不错位）', async () => {
    const original = AuditLog.countDocuments.bind(AuditLog);
    const spy = jest
      .spyOn(AuditLog, 'countDocuments')
      .mockImplementation((q, o) => original(q, o).then((n) => n + 1));
    try {
      const res = await exportAudit();
      const ws = await sheetOf(res.body);
      expect(footerRowNumberOf(ws)).toBe(ws.rowCount);
      // 2..末行-1 必须全是数据行：任何一行带脚注字样都说明追加位置被挪动过
      for (let n = 2; n < ws.rowCount; n++) {
        expect(String(ws.getRow(n).getCell(1).value ?? '')).not.toContain('数据不完整');
      }
    } finally {
      spy.mockRestore();
    }
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，不关的套件会让
// jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀（"A worker process has failed to
// exit gracefully"），强杀会吞掉该套件的输出。readyState 守卫是为了不关别人建立的连接；
// 本条挂在根作用域，故在本套件所有 describe 自己的 afterAll 之后才跑。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
