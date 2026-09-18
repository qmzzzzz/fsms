/**
 * P0-6 / P1-10 修复锁定：审计响应包装的流式路径与脱敏深度窗口
 *
 * P0-6（审计报告 §3.4）：全局审计中间件原先只包装 res.json/res.send，而导出接口
 * 走 res.write/res.end（auditExportService）或 workbook.xlsx.write(res)
 * （reportWorkbookService）——实测两个导出接口真实下载成功但 auditBuffer 计数为 0。
 * 修复后包装 write/end，本文件锁定：
 *   - 纯流式响应（write*N + end）产生且仅产生 1 条审计；
 *   - res.json / res.send 不因内部 res.end 二次记录；
 *   - write(chunk, encoding, callback) 三参形态与返回值原样透传；
 *   - 端到端：GET /api/reports/export 与 GET /api/security/audit-logs/export
 *     真实下载并各留 1 条审计。
 *
 * P1-10（审计报告 §3.7）：审计体脱敏的 depth > 6 分支原先原样返回子树，
 * 7/8/9 层嵌套的明文口令因此进入 auditBuffer。修复后锁定：
 *   - 7/8/9 层（乃至任意更深层）的明文口令不得出现在 push 入参中；
 *   - 中间件脱敏结果与 models/auditLogSanitizer.sanitizeAuditBody 逐字节一致
 *     （0–10 层全比对），保证两处口径不再漂移。
 */

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const auditBuffer = require('../../services/auditBuffer');
const { auditLog } = require('../../middleware/security');
const { sanitizeAuditBody } = require('../../models/auditLogSanitizer');
const { stripControlCharsDeep } = require('../../utils/helpers');

const spyPush = jest.spyOn(auditBuffer, 'push');

const tick = () => new Promise((resolve) => setImmediate(resolve));
const pushedDocs = () => spyPush.mock.calls.map(([doc]) => doc).filter(Boolean);
const pushedForPath = (fullPath) => pushedDocs().filter((doc) => doc.path === fullPath);

// ============================================================
// P0-6：流式响应包装
// ============================================================
describe('P0-6 响应包装覆盖 res.write/res.end', () => {
  beforeEach(() => {
    spyPush.mockClear();
  });

  const buildApp = (handler) => {
    const app = express();
    app.use(express.json());
    app.use('/api/', auditLog());
    app.post('/api/probe', handler);
    return app;
  };

  test('write*2 + end 的纯流式响应 → 恰好 1 条审计（导出类路径不再零审计）', async () => {
    const app = buildApp((req, res) => {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.write('col\n');
      res.write('row\n');
      res.end();
    });

    const res = await request(app).post('/api/probe').send({});
    expect(res.status).toBe(200);
    expect(res.text).toBe('col\nrow\n');
    await tick();

    const pushed = pushedForPath('/api/probe');
    expect(pushed).toHaveLength(1);
    expect(pushed[0].statusCode).toBe(200);
    expect(pushed[0].success).toBe(true);
  });

  test('仅 res.end() 无消息体 → 仍记录 1 条', async () => {
    const app = buildApp((req, res) => {
      res.end();
    });

    const res = await request(app).post('/api/probe').send({});
    expect(res.status).toBe(200);
    await tick();

    expect(pushedForPath('/api/probe')).toHaveLength(1);
  });

  test('res.json → 1 条（res.send 内部再调 res.end 被 logged 守卫吃掉）', async () => {
    const app = buildApp((req, res) => res.json({ ok: true }));

    const res = await request(app).post('/api/probe').send({});
    expect(res.status).toBe(200);
    await tick();

    expect(pushedForPath('/api/probe')).toHaveLength(1);
  });

  test('res.send → 1 条', async () => {
    const app = buildApp((req, res) => res.send('plain'));

    const res = await request(app).post('/api/probe').send({});
    expect(res.status).toBe(200);
    await tick();

    expect(pushedForPath('/api/probe')).toHaveLength(1);
  });

  test('三参形态 write(chunk, encoding, callback) 原样透传：回调被调用、返回值不变', async () => {
    const seen = { callbackCalled: false, writeReturn: null };
    const app = buildApp((req, res) => {
      // Express/Node 的 write 支持 (chunk, encoding, callback)；固定两参签名会丢回调
      seen.writeReturn = res.write('hello', 'utf8', () => {
        seen.callbackCalled = true;
      });
      res.end();
    });

    const res = await request(app).post('/api/probe').send({});
    expect(res.status).toBe(200);
    expect(res.text).toBe('hello');
    expect(seen.callbackCalled).toBe(true);
    // 背压语义：write 返回 boolean（未超缓冲时为 true）
    expect(typeof seen.writeReturn).toBe('boolean');
    await tick();

    expect(pushedForPath('/api/probe')).toHaveLength(1);
  });
});

// ============================================================
// P0-6 端到端：两个导出接口
// ============================================================
describe('P0-6 端到端：导出接口真实下载并留痕', () => {
  let app;
  let User;
  let Role;
  let Permission;
  const actors = {};

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/AuditLog');

    const seedPerm = async (code, name) =>
      Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { code, name, type: 'api', module: 'security' } },
        { upsert: true, new: true }
      );

    const exportPerm = await seedPerm('report:export', '导出报表');
    const auditPerm = await seedPerm('security:audit', '审计日志');

    const makeActor = async (key, roleCode, permIds) => {
      const role = await Role.findOneAndUpdate(
        { code: roleCode },
        { $setOnInsert: { code: roleCode, name: roleCode, level: 8, permissions: permIds } },
        { upsert: true, new: true }
      );
      const user = await User.create({
        username: `stream_${key}`,
        email: `stream_${key}@example.com`,
        password: randomPassword(),
        roles: [role._id],
      });
      actors[key] = {
        user,
        token: jwt.sign(
          { userId: String(user._id), username: user.username, tokenVersion: 0 },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        ),
      };
    };

    await makeActor('exporter', 'STREAM_EXPORT_TEST', [exportPerm._id]);
    await makeActor('auditor', 'STREAM_AUDIT_TEST', [auditPerm._id]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: /^stream_/ });
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    spyPush.mockClear();
  });

  const get = (key, url) =>
    request(app).get(url).set('Authorization', `Bearer ${actors[key].token}`);

  test('GET /api/reports/export（xlsx 流式写出）→ 真实下载且 push 收到 report_export', async () => {
    // 二进制响应不能用 supertest 默认解析器（会把 xlsx 当对象吞掉），
    // 显式收原始字节：断言 zip 魔数 PK\x03\x04 证明拿到的是真实 xlsx 字节流
    const res = await request(app)
      .get('/api/reports/export?type=devices&format=xlsx')
      .set('Authorization', `Bearer ${actors.exporter.token}`)
      .buffer(true)
      .parse((r, cb) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('spreadsheetml.sheet');
    expect(Buffer.isBuffer(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body.subarray(0, 4).toString('hex')).toBe('504b0304'); // zip 魔数
    await tick();

    const pushed = pushedForPath('/api/reports/export');
    expect(pushed).toHaveLength(1);
    expect(pushed[0].action).toBe('report_export');
    expect(pushed[0].username).toBe('stream_exporter');
    expect(pushed[0].body).toBeNull(); // GET 审计不记请求体
  });

  test('GET /api/security/audit-logs/export（CSV 流式）→ 真实下载且 push 收到 security_audit-logs_export', async () => {
    const res = await get('auditor', '/api/security/audit-logs/export?limit=10');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.text.length).toBeGreaterThan(0); // 真实下载，非空壳 200
    await tick();

    const pushed = pushedForPath('/api/security/audit-logs/export');
    expect(pushed).toHaveLength(1);
    expect(pushed[0].action).toBe('security_audit-logs_export');
    expect(pushed[0].statusCode).toBe(200);
  });
});

// ============================================================
// P1-10：脱敏深度窗口
// ============================================================
describe('P1-10 审计体脱敏：超深嵌套不泄漏明文', () => {
  const SECRET = 'P@ssw0rd-Deep-Nested-Must-Not-Leak';

  /** layers 层包裹，password 叶子位于 depth = layers */
  const nest = (layers) => {
    let node = { password: SECRET };
    for (let i = 0; i < layers; i += 1) node = { [`lv${i}`]: node };
    return node;
  };

  const buildApp = () => {
    const app = express();
    app.use(express.json());
    app.use('/api/', auditLog());
    app.post('/api/probe', (req, res) => res.json({ ok: true }));
    return app;
  };

  beforeEach(() => {
    spyPush.mockClear();
  });

  test.each([7, 8, 9])('%i 层嵌套：push 的 body 不含明文口令', async (layers) => {
    const app = buildApp();
    const res = await request(app).post('/api/probe').send(nest(layers));
    expect(res.status).toBe(200);
    await tick();

    const pushed = pushedForPath('/api/probe');
    expect(pushed).toHaveLength(1);
    const serialized = JSON.stringify(pushed[0].body);
    expect(serialized).not.toContain(SECRET);
    // 触发的是"深度超限"占位分支，而不是静默丢弃字段
    expect(serialized).toContain('[深度超限]');
  });

  test('0–10 层：中间件脱敏结果与 sanitizeAuditBody 逐字节一致（口径不漂移）', async () => {
    const app = buildApp();
    for (let layers = 0; layers <= 10; layers += 1) {
      spyPush.mockClear();
      const body = nest(layers);
      const res = await request(app).post('/api/probe').send(body);
      expect(res.status).toBe(200);
      await tick();

      const pushed = pushedForPath('/api/probe');
      expect(pushed).toHaveLength(1);
      expect(JSON.stringify(pushed[0].body)).toBe(
        JSON.stringify(stripControlCharsDeep(sanitizeAuditBody(body)))
      );
      expect(JSON.stringify(pushed[0].body)).not.toContain(SECRET);
    }
  });

  test('真实 app 全链路（sanitizeMongo → auditLog）：深层明文同样不入 buffer', async () => {
    // 本 describe 的中间件级用例不依赖数据库；这一条走真实 app（认证/权限/
    // 审计全链路）需要连接，故自管连接生命周期，不污染其它 describe
    const ownsConnection = mongoose.connection.readyState === 0;
    if (ownsConnection) await mongoose.connect(process.env.MONGODB_URI);
    try {
      const User = require('../../models/User');
      const user = await User.findOneAndUpdate(
        { username: 'stream_depth' },
        {
          $setOnInsert: {
            username: 'stream_depth',
            email: 'stream_depth@example.com',
            password: randomPassword(),
          },
        },
        { upsert: true, new: true }
      );
      const token = jwt.sign(
        { userId: String(user._id), username: user.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      const { createApp } = require('../../app');
      const realApp = createApp();
      spyPush.mockClear();

      // 攻击面：写方法 + 超深嵌套 body；POST /api/roles 未持权限（403）也会被审计，
      // 关键断言是审计体里不得出现明文
      const deepBody = nest(8);
      const res = await request(realApp)
        .post('/api/roles')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'x', code: 'x', ...deepBody });
      // 实测 403：该账号未持 role:create 权限，请求在权限闸被拒。
      // 原写法 toBeGreaterThanOrEqual(200) 近乎恒真（连 500 都放行）。
      // 本用例的主张不是「请求成功」，而是「403 这条早期拒绝路径同样被审计」——
      // 下面 hits.length > 0 与不含明文才是核心判据，这里先把状态钉死。
      expect(res.status).toBe(403);
      await tick();
      await tick();

      const hits = pushedForPath('/api/roles');
      expect(hits.length).toBeGreaterThan(0);
      for (const doc of hits) {
        expect(JSON.stringify(doc.body)).not.toContain(SECRET);
      }
    } finally {
      await require('../../models/User')
        .deleteMany({ username: 'stream_depth' })
        .catch(() => {});
      if (ownsConnection) await mongoose.connection.close();
    }
  });
});
