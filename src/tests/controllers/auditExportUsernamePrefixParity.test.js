/**
 * ──────────────────────────────────────────────────────────────────────────
 * 审计 xlsx 导出的 username 语义必须与「列表 / CSV 导出」同一条口径
 *
 * 被测对象：GET /api/reports/export?type=audit&username=…（xlsx 链）
 * 守护的不变式：本仓写成硬约束的「导出即所见」（reportExportService 文件头、
 *   utils/auditQuery.js:199-200）——同一个 URL 参数在三条链上必须是同一个结果集。
 *
 * 缺陷形状（修复前）：xlsx 侧留着列表改造前的旧写法
 *   `{ $regex: escapeRegExp(username), $options: 'i' }`，且全程不挂 collation。
 * 于是同一个 `?username=` 有两种语义：列表＝大小写不敏感的**前缀**，导出＝子串。
 * 后果不是"搜索结果略有差别"，而是两头都错、且错向相反：
 *   1) 子串 ⇒ **证据材料比可见集宽**：筛 `adm` 的 xlsx 里出现 `damin`、`superadmin`
 *      的 IP/路径/操作，而操作员以为文件只有那一个人的记录；
 *   2) 不挂 collation ⇒ **比可见集窄**：默认（二进制）collation 下 `ADMIN` 不落在
 *      `[adm, adn)` 内，列表能搜到的记录导出里没有（合规材料缺行且零提示）。
 * 另有一条纯性能代价：`i` 正则无法用索引（本机实测 keysExamined 2000 = 全索引扫）。
 *
 * 本文件的取证方式：
 *   - 夹具前提自证（用例 ①）：旧形态命中 5 条、前缀无 collation 命中 1 条、
 *     前缀带 collation 命中 3 条 ⇒ 三个数互不相等，才证明"换判据"与"挂 collation"
 *     是两个各自独立的开关，任何一处漏改都会在下面的用例里变成可观察的差集。
 *   - 三条链各走真实 HTTP + 真实 mongod（mongodb-memory-server 支持 collation）。
 *   - 计数腿（countDocuments）单独验：它只影响 checkBulkExport 的高危告警阈值，
 *     少算时**文件本身完全正常**（countDrift 是 `max(total-written,0)`，total 偏小
 *     不触发脚注）⇒ 行为断言看不见它，必须直接看传给它的 options。
 *
 * 变异验证记录（2026-10-01，逐条 exact-anchor 改实现 → 跑本套件 → finally 还原；5/5 KILLED）：
 *   M1 workbook 不再把 collation 转交 streamExportRows ⇒ 3 红：③（X-Export-Truncated 被置真——
 *      取数腿按二进制 collation 只写 1 行而对账用的计数是 3 ⇒ countDrift=2，正是脚注该说话的
 *      时刻，实测 Received: "true"）、④、⑦。
 *   M2 计数腿丢掉 collationOptions ⇒ 2 红：⑥、⑦。这条**不反映到文件内容**：total 偏小时
 *      countDrift 恒为 0，所以只能由 ⑥ 那种"看传给它的 options"的断言守住。
 *   M3 username 条件退回 `{$regex…, $options:'i'}` ⇒ 4 红：②、③、④、⑥。
 *   M4 hasUsernamePrefixCondition 恒为真（"统一挂"）⇒ 1 红：② 的等值形态用例。
 *   M5 控制器把 collationOptions 送进 workbook 时丢掉 ⇒ 3 红：③、④、⑦。
 * ──────────────────────────────────────────────────────────────────────────
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const AuditLog = require('../../models/AuditLog');
const { buildExportQuery } = require('../../services/reportExportService');
const { EXPORT_CSV_COLUMNS } = require('../../services/auditExportService');
const {
  usernamePrefixCondition,
  hasUsernamePrefixCondition,
  withCollation,
} = require('../../utils/auditQuery');

const CI = AuditLog.AUDIT_USERNAME_COLLATION;

describe('审计 xlsx 导出的 username 前缀 + collation 口径', () => {
  // 过滤串刻意带唯一前缀，避免命中其它测试文件留下的审计行；操作员用户名刻意
  // 不以它开头（登录/导出本身也会写审计行，否则参照集被请求痕迹污染）。
  const FILTER = 'kq7tadm';
  const stamp = `kq7p${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const MARKER_IP = '203.0.113.77';
  const PASSWORD = randomPassword();

  /** 真前缀 3 条（大小写各一）+ 子串命中 2 条（旧写法会多带进文件）+ 无关 1 条 */
  const usernames = {
    ciMatches: ['kq7tadmin', 'kq7tAdmin', 'kq7tADMIN'],
    // 两条都**包含** FILTER 但不以它开头 ⇒ 只有"子串语义"才会命中
    substringOnly: ['dkq7tadm', 'zzkq7tadmx'],
    unrelated: ['kq7troot'],
  };
  let app;
  let superToken;

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '1h' });

  /** 把 xlsx 响应体解析成「表头 → 该列全部单元格文本」 */
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

  const usernamesFromCsv = (text) => {
    const lines = text.trim().split('\n');
    const idx = EXPORT_CSV_COLUMNS.indexOf('username');
    return lines
      .slice(1)
      .filter((line) => !line.startsWith('#'))
      .map((line) => line.split(',')[idx]);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');

    // level 10 ⇒ 真实 getDataScope 返回 {type:'all'}（不 mock，避免把数据范围轴抹平）
    const perms = [];
    for (const code of ['*:*', 'report:export', 'security:audit']) {
      perms.push(
        await Permission.findOneAndUpdate(
          { code },
          { $setOnInsert: { name: `parith_${code}`, code, type: 'api', module: 'system' } },
          { upsert: true, new: true }
        )
      );
    }
    const role = await Role.create({
      name: `口径对齐超管_${stamp}`,
      code: `PARITY_SUPER_${stamp}`,
      level: 10,
      permissions: perms.map((p) => p._id),
    });
    const superUser = await User.create({
      username: `kq7operator${stamp}`,
      email: `kq7operator${stamp}@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    superToken = signToken(String(superUser._id), superUser.username);

    const now = new Date();
    const all = [...usernames.ciMatches, ...usernames.substringOnly, ...usernames.unrelated];
    await AuditLog.create(
      all.map((username, i) => ({
        action: 'login_failed',
        category: 'auth',
        username,
        success: false,
        riskLevel: 'low',
        method: 'GET',
        path: `/api/parity/${i}`,
        ip: MARKER_IP,
        timestamp: new Date(now.getTime() + i * 1000),
        reason: `username 口径对齐夹具_${stamp}`,
      }))
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ ip: MARKER_IP }, { bypassAppendOnly: true }).catch(() => {});
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    await User.deleteMany({ username: new RegExp(`^kq7operator${stamp}$`) }).catch(() => {});
    await Role.deleteMany({ code: new RegExp(`^PARITY_SUPER_${stamp}$`) }).catch(() => {});
  });

  // ===== ① 夹具前提自证：三个数互不相等，才说明两处开关各自独立 =====
  describe('① 夹具前提自证', () => {
    test('旧形态（子串 + i）命中 5 条、前缀无 collation 命中 1 条、前缀带 collation 命中 3 条', async () => {
      const legacy = await AuditLog.countDocuments({
        username: { $regex: FILTER, $options: 'i' },
      });
      const prefixNoCollation = await AuditLog.countDocuments({
        username: usernamePrefixCondition(FILTER),
      });
      const prefixWithCollation = await AuditLog.countDocuments(
        { username: usernamePrefixCondition(FILTER) },
        { collation: CI }
      );
      // 5 = 3 条真前缀 + 2 条"包含但不是前缀"（旧写法把它们当命中）
      expect(legacy).toBe(usernames.ciMatches.length + usernames.substringOnly.length);
      // 1 = 只有小写那条：二进制 collation 下 'A'(0x41) < 'a'(0x61)，
      // `kq7tAdmin` 整串排在下界 `kq7tadm` 之前 ⇒ 前缀条件不挂 collation 会**漏**记录
      expect(prefixNoCollation).toBe(1);
      expect(prefixWithCollation).toBe(usernames.ciMatches.length);
      // 挂上 collation 后取到的正是那 3 条大小写变体（与上面的 1 对照：差的 2 条
      // 就是"列表能搜到、不挂 collation 的导出搜不到"的具体记录）
      const collatedSet = await AuditLog.find({ username: usernamePrefixCondition(FILTER) })
        .collation(CI)
        .select('username')
        .lean();
      expect(collatedSet.map((d) => d.username).sort()).toEqual([...usernames.ciMatches].sort());
    });
  });

  // ===== ② 判据本身 =====
  describe('② hasUsernamePrefixCondition 取自 query 而非请求参数', () => {
    test('带 username 的导出条件 ⇒ true；不带 ⇒ false', () => {
      const withUser = buildExportQuery('audit', { dateFilter: {}, username: FILTER });
      const withoutUser = buildExportQuery('audit', { dateFilter: {} });
      expect(hasUsernamePrefixCondition(withUser)).toBe(true);
      expect(hasUsernamePrefixCondition(withoutUser)).toBe(false);
    });

    test('等值形态不触发（它没有正确性问题，不该付"屏蔽全部时间序索引"的代价）', () => {
      expect(hasUsernamePrefixCondition({ username: 'admin' })).toBe(false);
      expect(hasUsernamePrefixCondition({ username: { $in: ['admin'] } })).toBe(false);
      expect(hasUsernamePrefixCondition({})).toBe(false);
      expect(hasUsernamePrefixCondition(null)).toBe(false);
      expect(hasUsernamePrefixCondition(undefined)).toBe(false);
      expect(hasUsernamePrefixCondition('x')).toBe(false);
    });
  });

  // ===== ③ xlsx 链：内容级断言 =====
  describe('③ GET /api/reports/export?type=audit&username=', () => {
    test('文件里恰好是大小写不敏感的**前缀**集：不含子串行，也不漏大小写不同的行', async () => {
      const res = await request(app)
        .get(`/api/reports/export?type=audit&format=xlsx&username=${FILTER}`)
        .set('Authorization', `Bearer ${superToken}`)
        .buffer()
        .parse((r, cb) => {
          const chunks = [];
          r.on('data', (c) => chunks.push(c));
          r.on('end', () => cb(null, Buffer.concat(chunks)));
        });
      expect(res.status).toBe(200);
      // 对账脚注必须不出现：计数腿与取数腿挂的是同一份 collation，任何一侧漏挂都会让
      // "命中数"与"写出行数"对不上（变异 M1：删掉转交给 streamExportRows 的第 5 个实参
      // ⇒ 取数腿按二进制 collation 只写 1 行而计数仍是 3 ⇒ countDrift=2 ⇒ 头被置真）。
      expect(res.headers['x-export-truncated']).toBeUndefined();
      const cols = await columnsFromWorkbook(res.body);
      const got = cols['操作用户'].sort();
      expect(got).toEqual([...usernames.ciMatches].sort());
      for (const leaking of usernames.substringOnly) {
        expect(got).not.toContain(leaking);
      }
    });
  });

  // ===== ④ CSV 链与 xlsx 链同口径 =====
  describe('④ 三条链同一个结果集', () => {
    test('xlsx 与 CSV 导出的 username 集合相同', async () => {
      const xlsxRes = await request(app)
        .get(`/api/reports/export?type=audit&format=xlsx&username=${FILTER}`)
        .set('Authorization', `Bearer ${superToken}`)
        .buffer()
        .parse((r, cb) => {
          const chunks = [];
          r.on('data', (c) => chunks.push(c));
          r.on('end', () => cb(null, Buffer.concat(chunks)));
        });
      const csvRes = await request(app)
        .get(`/api/security/audit-logs/export?username=${FILTER}`)
        .set('Authorization', `Bearer ${superToken}`);
      expect(csvRes.status).toBe(200);
      expect(usernamesFromCsv(csvRes.text).sort()).toEqual([...usernames.ciMatches].sort());
      const cols = await columnsFromWorkbook(xlsxRes.body);
      expect(cols['操作用户'].sort()).toEqual(usernamesFromCsv(csvRes.text).sort());
    });

    test('列表接口在同一参数下命中数一致（导出即所见，含总数）', async () => {
      const res = await request(app)
        .get(`/api/security/audit-logs?username=${FILTER}&page=1&limit=50`)
        .set('Authorization', `Bearer ${superToken}`);
      expect(res.status).toBe(200);
      // 响应信封：body.data = { data: [行…], meta: { total, count, … } }
      const payload = res.body.data || {};
      const rows = payload.data || [];
      expect(rows.map((d) => d.username).sort()).toEqual([...usernames.ciMatches].sort());
      expect(payload.meta.total).toBe(usernames.ciMatches.length);
    });
  });

  // ===== ⑤ 不挂 collation 的两种情形（反向对照：统一挂会把时间序索引全部屏蔽） =====
  describe('⑤ 反向对照：不该挂的不能挂', () => {
    test('不带 username 时 countDocuments 收不到 collation', async () => {
      const original = AuditLog.countDocuments.bind(AuditLog);
      const spy = jest
        .spyOn(AuditLog, 'countDocuments')
        .mockImplementation((q, o) => original(q, o));
      try {
        await request(app)
          .get('/api/reports/export?type=audit&format=xlsx')
          .set('Authorization', `Bearer ${superToken}`)
          .expect(200);
        expect(spy).toHaveBeenCalled();
        for (const [, options] of spy.mock.calls) {
          expect(options && options.collation).toBeUndefined();
        }
      } finally {
        spy.mockRestore();
      }
    });

    test('withCollation 在 collation 为 null 时原样返回（挂与不挂的分界只有一处）', () => {
      const fake = { collation: jest.fn(() => fake) };
      expect(withCollation(fake, null)).toBe(fake);
      expect(fake.collation).not.toHaveBeenCalled();
      expect(withCollation(fake, CI)).toBe(fake);
      expect(fake.collation).toHaveBeenCalledWith(CI);
    });
  });

  // ===== ⑥ 计数腿（只影响高危批量导出告警，文件本身看不出来） =====
  describe('⑥ 计数腿必须与取数腿同 collation', () => {
    test('带 username 时 countDocuments 收到 AUDIT_USERNAME_COLLATION', async () => {
      const original = AuditLog.countDocuments.bind(AuditLog);
      const spy = jest
        .spyOn(AuditLog, 'countDocuments')
        .mockImplementation((q, o) => original(q, o));
      try {
        await request(app)
          .get(`/api/reports/export?type=audit&format=xlsx&username=${FILTER}`)
          .set('Authorization', `Bearer ${superToken}`)
          .expect(200);
        const hit = spy.mock.calls.find(([, o]) => o && o.collation);
        expect(hit).toBeDefined();
        expect(hit[1].collation).toEqual(CI);
      } finally {
        spy.mockRestore();
      }
    });
  });

  // ===== ⑦ 接线闸门：collation 必须真的从控制器流到取数腿 =====
  describe('⑦ 接线（只登记不接线 = 缺陷）', () => {
    // 必须先摘注释再压空白：反过来的话注释正文会与代码粘成一坨，
    // 闸门可能被"注释里写好的正确形态"骗绿。
    const squash = (p) =>
      fs
        .readFileSync(path.resolve(__dirname, p), 'utf8')
        .replace(/\/\/[^\n]*/g, '')
        .replace(/\s+/g, '');

    test('collation 口径在 service 层定义并被控制器消费，最终流到两条腿', () => {
      const svc = squash('../../services/reportExportService.js');
      // 判据只有一处三元表达式。它必须在 service 层：分层棘轮 D-1a 禁止 controller
      // 直连 models，而这份口径要读 model 上的 AUDIT_USERNAME_COLLATION。
      expect(svc).toContain(
        'collationOptionsForExport=(query)=>hasUsernamePrefixCondition(query)?{collation:AuditLog.AUDIT_USERNAME_COLLATION}:{}'
      );
      // 定义了却没导出 = 只登记不接线
      expect(svc).toContain('buildExportQuery,collationOptionsForExport');

      const ctrl = squash('../../controllers/reportController.js');
      expect(ctrl).toContain('collationOptionsForExport(query)');
      // 反向：控制器不得再自己摸 model 上的 collation 常量（口径只许一处）
      expect(ctrl).not.toContain('AUDIT_USERNAME_COLLATION');
      // 同一个 options 对象同时喂给两条腿（分开构造就是两处口径可各自漂）
      expect(ctrl).toContain('countDocuments(query,collationOptions)');
      expect(ctrl).toContain(
        'writeExportWorkbook(res,{type,query,total:exportTotal,...collationOptions})'
      );
      const wb = squash('../../services/reportWorkbookService.js');
      expect(wb).toContain('streamExportRows(worksheet,config,query,safeTransform,collation)');
      expect(wb).toContain('{type,query,total=null,collation=null}');
    });
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
