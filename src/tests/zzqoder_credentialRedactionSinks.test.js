/**
 * 凭据不得以明文进入「可长期留存、且会被导出」的两类载体
 *
 * ① 不可篡改的审计集合 AuditLog：request-audit 路径对 body 做了 SENSITIVE_KEYS 脱敏，
 *    却对 params/query **完全不脱敏**。经 query 传令牌（本应用 /api/auth/refresh
 *    就支持 body 或 query 两种来源）会把可用凭证永久入库，并随每次审计导出 CSV
 *    再复制一份 —— 审计库因此变成凭据库。
 * ② 日志文件 logs/combined-*.log（按 RETENTION_DAYS 长期留存）：app.js 早就给 morgan
 *    的 :url 套了 redactUrlQuery，理由正是「query 里的令牌/口令会明文长期留存」。
 *    但 errorHandler 与 originCheck 这两条**攻击者可稳定触发**的写日志入口把
 *    originalUrl 原文塞进消息；originCheck 还直接内插攻击者可控的 Origin 头。
 *
 * 每个断言都先证明「探针确实触发了那条路径」，避免空集假绿。
 *
 * 后续（本次改动 ①′）：把 query/params 改走 helpers.SENSITIVE_QUERY_KEYS
 * （访问日志 URL 打码用的那份）。核实结论是**取并集而不是替换**：
 * 查询名单按整键/下划线边界匹配 ⇒ 会漏掉 refreshToken/accessToken/mfaCode 这类
 * camelCase（正是 body 名单靠子串抓住的形态），单向替换等于把 ① 修好的洞再打开；
 * 而 body 名单又漏 code/otp/authorization/session 这类裸键。两份盲区方向相反，
 * 所以 auditLogSanitizer.isQuerySensitiveKey = 子串名单 ∪ 边界名单。
 */

const express = require('express');
const request = require('supertest');
const fs = require('fs');
const path = require('path');

const SECRET = 'eyJhbGciOiJIUzI1Ni5yZWFsLWxvb2tpbmcuand0LXZhbHVl';

const listen = (app) =>
  new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });

describe('审计与日志两类长期载体不得存明文凭据', () => {
  describe('① 审计 params/query 复用 body 的同一份脱敏名单', () => {
    /**
     * 本层测修复的核心命题：SENSITIVE_KEYS 走 key.toLowerCase().includes(...)，
     * 所以 query 里 camelCase 的 refreshToken/accessToken 也会被同一名单命中——
     * 这正是「复用 body 名单」而非另抄一份的理由（另抄时常写成整键相等，camelCase 即漏；
     * 本仓 helpers.js 的 matchesSensitiveQueryKey 此刻正是这个毛病，已交复核 处理）。
     * 调用点有没有真的接上这条流水线，由下面的接线守卫负责；两条合起来才是完整证明。
     */
    const { sanitizeAuditBody, SENSITIVE_KEYS } = require('../models/auditLogSanitizer');

    test('名单对 query 形态的令牌键确实生效（含 camelCase），非敏感键保持可读', () => {
      const q = sanitizeAuditBody({
        refreshToken: SECRET,
        accessToken: SECRET,
        token: SECRET,
        encPassword: 'P@ssw0rd!',
        page: '2',
        keep: 'yes',
      });
      expect(q.refreshToken).toBe('***');
      expect(q.accessToken).toBe('***');
      expect(q.token).toBe('***');
      expect(q.encPassword).toBe('***');
      expect(q.page).toBe('2'); // 非敏感参数必须保持可读，否则审计失去取证价值
      expect(JSON.stringify(q)).not.toContain(SECRET);
      expect(SENSITIVE_KEYS.length).toBeGreaterThan(0);
    });

    test('嵌套对象/数组里的敏感键同样脱敏（extended query parser 会产出该形态）', () => {
      const q = sanitizeAuditBody({
        filter: { secret: SECRET },
        tags: [{ apikey: SECRET }],
      });
      expect(JSON.stringify(q)).not.toContain(SECRET);
    });

    test('接线守卫：两条审计写入路径都不得把未清洗的 req.query/req.params 直接入库', () => {
      const RE_UNSANITIZED = /^\s*(query|params):\s*req\.(query|params)\s*,/;
      // 先自证这条正则抓得到「原样写入」的写法，否则空数组只是正则失效的假绿
      expect(RE_UNSANITIZED.test('      query: req.query,')).toBe(true);

      const files = ['../middleware/security.js', '../models/auditLogWriteStatics.js'].map((rel) =>
        path.join(__dirname, rel)
      );
      const offenders = [];
      for (const file of files) {
        const src = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
        src.split('\n').forEach((line, i) => {
          if (RE_UNSANITIZED.test(line)) {
            offenders.push(`${path.basename(file)}:${i + 1}: ${line.trim()}`);
          }
        });
      }
      expect(offenders).toEqual([]);
    });
  });

  describe('①′ 审计 query/params 的并集名单', () => {
    const { sanitizeAuditBody, sanitizeAuditQuery } = require('../models/auditLogSanitizer');
    const { matchesSensitiveQueryKey } = require('../utils/helpers');

    test('body 名单漏掉的裸键，query 口径必须抓到（并集的右半）', () => {
      const q = {
        code: SECRET,
        otp: '987654',
        authorization: SECRET,
        session: 'sess-abc',
        captcha: '9x2k',
        signature: 'deadbeef',
        code_verifier: 'pkce-verifier',
      };
      // 前提自证：这些键**确实**不在 body 名单的命中范围内
      // （否则"并集带来新覆盖"这条命题根本没被验证，只是装饰）
      for (const k of Object.keys(q)) {
        expect(sanitizeAuditBody({ [k]: SECRET })[k]).toBe(SECRET);
      }
      const out = sanitizeAuditQuery(q);
      for (const k of Object.keys(q)) expect(out[k]).toBe('***');
    });

    test('查询名单漏掉的 camelCase，并集必须保住（并集的左半）', () => {
      const q = { refreshToken: SECRET, accessToken: SECRET, mfaCode: '987654' };
      // 前提自证：`SENSITIVE_QUERY_KEYS` 单独用会漏这几个键 ⇒
      // "把 query 换成查询名单"这种单向收敛会**退回**凭据明文入库，必须拒绝
      for (const k of Object.keys(q)) {
        expect(matchesSensitiveQueryKey(k.toLowerCase())).toBe(false);
      }
      const out = sanitizeAuditQuery(q);
      for (const k of Object.keys(q)) expect(out[k]).toBe('***');
    });

    test('业务键不误伤：postcode/zipcode 含 code 子串，靠边界匹配放行', () => {
      const out = sanitizeAuditQuery({
        postcode: '200120',
        zipcode: '94105',
        page: '2',
        status: 'pending',
      });
      expect(out).toEqual({
        postcode: '200120',
        zipcode: '94105',
        page: '2',
        status: 'pending',
      });
    });

    test('接线守卫：两条写入路径都不得再用 body 口径清洗 params/query', () => {
      const RE_BODY_ON_QUERY =
        /safe(?:Params|Query)\s*=\s*sanitizeAuditBody\(|(?:params|query):\s*sanitizeAuditBody\(/;
      // 自证正则抓得到被禁止的写法，空数组才不是假绿
      expect(
        RE_BODY_ON_QUERY.test('const safeQuery = sanitizeAuditBody(stripControlCharsDeep(x));')
      ).toBe(true);
      expect(RE_BODY_ON_QUERY.test('      query: sanitizeAuditBody(req.query),')).toBe(true);

      const offenders = [];
      for (const rel of ['../middleware/security.js', '../models/auditLogWriteStatics.js']) {
        const file = path.join(__dirname, rel);
        fs.readFileSync(file, 'utf8')
          .replace(/\r\n/g, '\n')
          .split('\n')
          .forEach((line, i) => {
            if (RE_BODY_ON_QUERY.test(line)) {
              offenders.push(`${path.basename(file)}:${i + 1}: ${line.trim()}`);
            }
          });
      }
      expect(offenders).toEqual([]);
    });

    test('端到端：真实中间件下 ?otp= / ?refreshToken= 落到审计缓冲时必须是 ***', async () => {
      const { auditLog } = require('../middleware/security');
      const auditBuffer = require('../services/auditBuffer');
      const spyPush = jest.spyOn(auditBuffer, 'push').mockImplementation(() => {});
      const app = express();
      app.use(express.json());
      app.use('/api/', auditLog());
      // 用 POST：GET 只有命中 auditGetPaths 白名单才审计（本探针不在名单内，
      // 用 GET 会得到"没有审计记录"的假信号，而不是"清洗没生效"）
      app.post('/api/zzqoder-otp', (_req, res) => res.json({ ok: true }));

      // 必须先取 calls 再 mockRestore：恢复 spyOn 会把 mock.calls 清空，
      // 表现是"中间件没写审计"的假信号（首版就红在这里）。
      let seen = [];
      try {
        await request(app).post(
          `/api/zzqoder-otp?otp=987654&refreshToken=${SECRET}&postcode=200120&code=PKCE123456`
        );
        await new Promise((r) => setImmediate(r));
        await new Promise((r) => setImmediate(r));
        seen = spyPush.mock.calls.map(([d]) => d);
      } finally {
        spyPush.mockRestore();
      }

      const doc = seen.find((d) => d && d.path === '/api/zzqoder-otp');
      expect(doc).toBeDefined(); // 自证确实走了真实落库通道
      expect(doc.query.otp).toBe('***');
      expect(doc.query.code).toBe('***');
      expect(doc.query.refreshToken).toBe('***');
      expect(doc.query.postcode).toBe('200120'); // 不误伤业务参数
      expect(JSON.stringify(doc.query)).not.toContain('987654');
      expect(JSON.stringify(doc.query)).not.toContain(SECRET);
      expect(JSON.stringify(doc.query)).not.toContain('PKCE123456');
    });

    test('第二条写入路径（recordSensitiveAction）也必须并集脱敏——不是只修中间件那条', async () => {
      // 变异实测：把 models/auditLogWriteStatics.js 的 sanitizeAuditQuery 调用整段删掉，
      // 上面那条中间件端到端用例**照样全绿**（两条路径各写各的 query），
      // 首版"5/5 被杀"是残留变异造成的假象。本用例补的正是这条无人看守的路径。
      const AuditLog = require('../models/AuditLog');
      const createSpy = jest.spyOn(AuditLog, 'create').mockImplementation(async (d) => d);
      const req = {
        method: 'GET',
        originalUrl: '/api/users/zz1?otp=987654&refreshToken=rt-value&postcode=200120',
        params: { id: '507f1f77bcf86cd799439011' },
        query: { otp: '987654', refreshToken: 'rt-value', postcode: '200120' },
        body: {},
        ip: '10.0.0.1',
        get: (h) => (h === 'user-agent' ? 'jest-agent' : ''),
      };
      let created;
      try {
        created = await AuditLog.recordSensitiveAction(
          'u-zz',
          'zzqoder',
          'user_delete',
          'system',
          req,
          { statusCode: 200 },
          12
        );
      } finally {
        createSpy.mockRestore();
      }

      expect(created).toBeDefined();
      expect(created.query.otp).toBe('***');
      expect(created.query.refreshToken).toBe('***');
      expect(created.query.postcode).toBe('200120'); // 不误伤业务参数
      expect(created.params.id).toBe('507f1f77bcf86cd799439011'); // 路由参数非凭据，保持可读
      expect(JSON.stringify(created.query)).not.toContain('987654');
      expect(JSON.stringify(created.query)).not.toContain('rt-value');
    });
  });

  describe('② 日志文件：错误与 CSRF 拒绝路径必须脱敏 URL 并清洗攻击者输入', () => {
    let logger;
    let lines;

    beforeEach(() => {
      logger = require('../utils/logger');
      lines = [];
      jest.spyOn(logger, 'warn').mockImplementation((msg) => lines.push(String(msg)));
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('JSON 解析失败的日志行不含 query 里的口令', async () => {
      const errorHandler = require('../middleware/errorHandler');
      const app = express();
      app.use(express.json());
      app.post('/api/zzqoder-parse', (_req, res) => res.json({}));
      app.use(errorHandler);
      const server = await listen(app);
      try {
        const res = await request(server)
          .post('/api/zzqoder-parse?password=hunter2-secret-value')
          .set('Content-Type', 'application/json')
          .send('{not-json');
        expect(res.status).toBe(400);
      } finally {
        await new Promise((r) => server.close(r));
      }
      const text = lines.join('\n');
      expect(text).toContain('JSON 解析失败'); // 证明确实走到了那条日志
      expect(text).not.toContain('hunter2-secret-value');
      expect(text).toContain('password=***');
    });

    test('CSRF 拒绝日志不含换行注入，且一次拒绝只产生一行', async () => {
      const { createOriginCheck } = require('../middleware/originCheck');
      const app = express();
      app.use(express.json());
      app.use('/api/zzqoder-csrf', createOriginCheck(['https://good.example']), (_req, res) =>
        res.json({ ok: true })
      );
      const server = await listen(app);
      try {
        const res = await request(server)
          .post('/api/zzqoder-csrf?page=2')
          .set('Origin', 'https://evil.example')
          .set('Content-Type', 'application/json')
          .send({});
        expect(res.status).toBe(403);
      } finally {
        await new Promise((r) => server.close(r));
      }
      const hits = lines.filter((l) => l.includes('来源校验失败'));
      expect(hits).toHaveLength(1); // 探针确实触发了这条日志
      expect(hits[0].includes('\n')).toBe(false); // 换行注入会在这里暴露成"多一行"
    });

    /**
     * URL 打码与审计脱敏对同一个键必须给同一个结论。
     * 曾经的缺口：redactUrlQuery 只用「整键/下划线边界」那一半名单，
     * 于是 ?accessToken=<口令> 原样进 combined 日志，而同一条请求的审计副本里
     * 已是 ***；现在两条链路共用 utils/helpers.isCredentialQueryKey（并集）。
     */
    test('camelCase 的 accessToken 与 password 在访问日志里同样被打码', async () => {
      const { createOriginCheck } = require('../middleware/originCheck');
      const app = express();
      app.use(express.json());
      app.use('/api/zzqoder-csrf2', createOriginCheck(['https://good.example']), (_req, res) =>
        res.json({ ok: true })
      );
      const server = await listen(app);
      try {
        await request(server)
          .post(`/api/zzqoder-csrf2?accessToken=${SECRET}`)
          .set('Origin', 'https://evil.example')
          .set('Content-Type', 'application/json')
          .send({});
      } finally {
        await new Promise((r) => server.close(r));
      }
      const text = lines.filter((l) => l.includes('来源校验失败')).join('\n');
      expect(text).toContain('accessToken=***');
      expect(text).not.toContain(SECRET);
    });

    test('反向保护：白名单内的 Origin 仍正常放行（脱敏不得变成一律拒绝）', async () => {
      const { createOriginCheck } = require('../middleware/originCheck');
      const app = express();
      app.use(express.json());
      app.use('/api/zzqoder-ok', createOriginCheck(['https://good.example']), (_req, res) =>
        res.json({ ok: true })
      );
      const server = await listen(app);
      try {
        const res = await request(server)
          .post('/api/zzqoder-ok?page=2')
          .set('Origin', 'https://good.example')
          .set('Content-Type', 'application/json')
          .send({});
        expect(res.status).toBe(200);
        expect(lines.filter((l) => l.includes('来源校验失败'))).toHaveLength(0);
      } finally {
        await new Promise((r) => server.close(r));
      }
    });
  });
});
