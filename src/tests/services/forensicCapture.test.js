/**
 * 取证捕获服务（P2）：脱敏完整性、容量闸可见性、记录哈希稳定性
 *
 * 被测对象：services/forensicCapture.js（buildRecord / captureRequestBody /
 * buildResponsePart / sanitizeBodyForForensic / record / getForensicCaptureStats）。
 *
 * 每条用例都写成「注入一个真实的泄漏形态，断言产物里**逐字节**找不到它」，
 * 而不是「断言函数被调用过」——后者在实现改坏时仍然是绿的。
 *
 * 三个变异常量（环境变量在本文件 require 前设定，模块级常量随加载固化）：
 *   · FORENSIC_PER_IP_PER_MIN=2 / FORENSIC_SAMPLE_EVERY_N=3 —— 让采样在 10 次调用内可观测；
 *   · 各 CAP=200 —— 让截断在小载荷上就能触发，不必造 16KB 体；
 *   · FORENSIC_CAPTURE_ENABLED=true —— 默认态。
 */

process.env.FORENSIC_CAPTURE_ENABLED = 'true';
process.env.FORENSIC_PER_IP_PER_MIN = '2';
process.env.FORENSIC_SAMPLE_EVERY_N = '3';
// CAP 保持默认（16384 / 65536）：截断用例喂**超过默认上限**的载荷，
// 这样"未超限时结构完整、超限时留标记"两件事都能断言（压小 CAP 会让常规体也被截成字符串）

// 触发判据由中间件注入，但 shouldCapture 也会自己读一次（对拍要用）。
// jest.mock 的工厂只能引用 mock 前缀变量，故状态对象按此命名。
const mockTrigger = { on: false, throws: false };
jest.mock('../../services/forensicTrigger', () => ({
  isForensicTarget: () => {
    if (mockTrigger.throws) throw new Error('trigger boom');
    return mockTrigger.on;
  },
  getForensicTarget: () =>
    mockTrigger.on ? { reason: 'honeypot_login', markedAt: new Date(0) } : null,
  markForensicTarget: () => true,
  clearForensicTarget: () => true,
  getForensicTriggerStats: () => ({ enabled: true }),
}));

// 落库用替身：本文件只验「产物长什么样」，不碰数据库（模型层另有用例）
jest.mock('../../models/ForensicCapture', () => ({
  insertMany: jest.fn(async () => ({ insertedCount: 1 })),
}));

const svc = require('../../services/forensicCapture');
const { sanitizeAuditBody } = require('../../models/auditLogSanitizer');
const { digestOf } = require('../../utils/passwordHistory');
const { maskPiiText } = require('../../utils/logPiiMask');

/** 哨兵密文集合：任何一条出现在产物里就是泄漏 */
const SENTINELS = {
  password: 'S3NTINEL-PW-7f3a9c',
  passwordAlias: 'S3NTINEL-PWD-1b2c',
  token: 'S3NTINEL-TOKEN-4d5e',
  cookie: 'S3NTINEL-COOKIE-6f7a',
  setCookieValue: 'S3NTINEL-SETCOOKIE-8b9c',
  authorization: 'S3NTINEL-BEARER-0d1e',
  email: 'sentinel.pii@example.com',
  phone: '13900139001',
  idCard: '110101199003071234',
};

const buildReq = (over = {}) => ({
  method: 'POST',
  originalUrl: '/api/probe?q=1',
  query: { q: '1' },
  params: {},
  headers: {
    'content-type': 'application/json',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    authorization: `Bearer ${SENTINELS.authorization}`,
    cookie: `sid=${SENTINELS.cookie}`,
    'x-forwarded-for': '203.0.113.7, 10.0.0.1',
  },
  body: {},
  httpVersion: '1.1',
  socket: { remoteAddress: '203.0.113.7' },
  ip: '203.0.113.7',
  get(key) {
    return this.headers[key] || '';
  },
  ...over,
});

const jsonResponse = (body, contentType = 'application/json; charset=utf-8') => ({
  status: 200,
  headers: {
    'content-type': contentType,
    'set-cookie': [`sid=${SENTINELS.setCookieValue}; Path=/; HttpOnly`],
  },
  contentType,
  body,
  bytes: Buffer.byteLength(body, 'utf8'),
});

/** 记录构造走**中间件的同一段流水线**：响应侧必须先过 buildResponsePart（掩码/摘要/截断都在那里） */
const recordOf = (reqOver = {}, responseOver = {}) =>
  svc.buildRecord({
    req: buildReq(reqOver),
    res: {},
    ip: '203.0.113.7',
    trigger: { reason: 'honeypot_login', markedAt: new Date('2026-10-31T00:00:00Z') },
    response: svc.buildResponsePart({ ...jsonResponse('{"ok":true}'), ...responseOver }),
  });

describe('脱敏完整性：哨兵密文一个都不许出现在取证产物里', () => {
  test('请求头：Authorization / Cookie 整体掩码，XFF 保留原链（§2.2 明示）', () => {
    const doc = recordOf();
    const headers = JSON.stringify(doc.request.headers);
    expect(headers).not.toContain(SENTINELS.authorization);
    expect(headers).not.toContain(SENTINELS.cookie);
    expect(doc.request.headers.authorization).toBe('[REDACTED]');
    expect(doc.request.headers.cookie).toBe('[REDACTED]');
    // 反向对照：XFF 必须原样保留（否则归属地/攻击链取证失效）
    expect(doc.request.headers['x-forwarded-for']).toBe('203.0.113.7, 10.0.0.1');
  });

  test('响应头：Set-Cookie 只留属性摘要，值一律不进产物', () => {
    const doc = recordOf();
    const summary = doc.response.headers['set-cookie'];
    expect(Array.isArray(summary)).toBe(true);
    expect(summary[0]).toEqual({ name: 'sid', httpOnly: true });
    expect(JSON.stringify(doc.response.headers)).not.toContain(SENTINELS.setCookieValue);
  });

  test('请求体：口令/token/邮箱/手机/身份证全部脱敏（PII 走 logPiiMask 同源正则）', () => {
    const body = {
      username: 'bob',
      password: SENTINELS.password,
      passwd: SENTINELS.passwordAlias,
      token: SENTINELS.token,
      // 非敏感键名里的 PII：只有 logPiiMask 同源正则能救（键名不在敏感名单里）
      note: `联系方式 ${SENTINELS.email} / ${SENTINELS.phone} / ${SENTINELS.idCard}`,
    };
    const doc = recordOf({ body });
    const dumped = JSON.stringify(doc.request);
    for (const [name, value] of Object.entries(SENTINELS)) {
      if (name === 'setCookieValue' || name === 'authorization' || name === 'cookie') continue;
      expect({ name, leaked: dumped.includes(value) }).toEqual({ name, leaked: false });
    }
    // 口令落 {len,hmac}：长度可用、明文不可用
    expect(doc.request.body.password).toEqual({
      len: SENTINELS.password.length,
      hmac: digestOf(SENTINELS.password),
    });
    expect(doc.request.body.passwd).toEqual({
      len: SENTINELS.passwordAlias.length,
      hmac: digestOf(SENTINELS.passwordAlias),
    });
    // PII 保留可读轮廓（掩码而非删除）：取证要看得出"这里是个手机号"
    expect(doc.request.body.note).toBe(
      `联系方式 ${maskPiiText(SENTINELS.email)} / ${maskPiiText(SENTINELS.phone)} / ${maskPiiText(SENTINELS.idCard)}`
    );
  });

  test('query/params：走单源 sanitizeAuditQuery（裸键 code/otp 也砍）', () => {
    const doc = recordOf({ query: { code: '123456', refreshToken: SENTINELS.token, q: '1' } });
    expect(doc.request.query.code).toBe('***');
    expect(doc.request.query.refreshToken).toBe('***');
    expect(doc.request.query.q).toBe('1');
  });
});

describe('口令升级与单源脱敏的一致性（不复制第三份实现）', () => {
  test('无口令体：取证脱敏结果与 sanitizeAuditBody 逐字节一致（0–8 层）', () => {
    const nest = (depth) => {
      let node = { leaf: 'v', token: 'T' };
      for (let i = 0; i < depth; i += 1) node = { ['l' + i]: node };
      return node;
    };
    for (let depth = 0; depth <= 8; depth += 1) {
      const body = nest(depth);
      expect(JSON.stringify(svc.sanitizeBodyForForensic(body))).toBe(
        JSON.stringify(sanitizeAuditBody(body))
      );
    }
  });

  test('深度超限：第 7 层起返回可见标记（不是原样返回子树）', () => {
    const deep = { a: { b: { c: { d: { e: { f: { g: { password: SENTINELS.password } } } } } } } };
    const out = JSON.stringify(svc.sanitizeBodyForForensic(deep));
    expect(out).not.toContain(SENTINELS.password);
    expect(out).toContain('[深度超限]');
  });

  test('__proto__ 键必须保真落盘（否则攻击载荷从取证副本里消失）', () => {
    const body = JSON.parse('{"__proto__":{"password":"S3NTINEL-PW-7f3a9c"},"ok":1}');
    const out = svc.sanitizeBodyForForensic(body);
    expect(Object.prototype.hasOwnProperty.call(out, '__proto__')).toBe(true);
    expect(JSON.stringify(out)).not.toContain(SENTINELS.password);
  });
});

describe('上限与截断：超限必须留可见标记 + 全文摘要', () => {
  test('请求体超限：bodyTruncated=true、带标记、bodySha256 覆盖**全文**、bodyBytes 为原文字节数', () => {
    const longText = 'x'.repeat(20000); // 超过默认 FORENSIC_REQ_BODY_CAP=16384
    const doc = recordOf({ body: { note: longText } });
    expect(doc.request.bodyTruncated).toBe(true);
    expect(doc.request.body).toContain('[FORENSIC_TRUNCATED]');
    expect(doc.request.bodyBytes).toBe(
      Buffer.byteLength(JSON.stringify({ note: longText }), 'utf8')
    );
    // 摘要取全文 ⇒ 截断不影响后续比对原始载荷
    expect(doc.request.bodySha256).toMatch(/^[0-9a-f]{64}$/);
    // 反向对照：未超限时不带标记
    const small = recordOf({ body: { note: 'short' } });
    expect(small.request.bodyTruncated).toBe(false);
    expect(JSON.stringify(small.request.body)).not.toContain('FORENSIC_TRUNCATED');
  });

  test('头袋超限：逐键收下并在末尾留 __truncated 计数（不静默丢）', () => {
    const headers = {};
    for (let i = 0; i < 60; i += 1) headers['x-probe-' + i] = 'v'.repeat(300);
    const masked = svc.maskHeaders(headers, 8192);
    expect(masked.__truncated.capBytes).toBe(8192);
    expect(masked.__truncated.dropped).toBeGreaterThan(0);
    // 反向对照：未超限时不带 __truncated（否则"截断"这件事永远为真）
    expect(svc.maskHeaders({ 'x-a': 'v' }, 8192).__truncated).toBeUndefined();
  });

  test('响应体超限：同样带标记与全文摘要（响应侧口径与请求侧一致）', () => {
    const big = JSON.stringify({ payload: 'y'.repeat(70000) }); // 超过默认 FORENSIC_RES_BODY_CAP=65536
    const part = svc.buildResponsePart(jsonResponse(big));
    expect(part.bodyTruncated).toBe(true);
    expect(part.body).toContain('[FORENSIC_TRUNCATED]');
    expect(part.bodyBytes).toBe(Buffer.byteLength(big, 'utf8'));
  });

  test('二进制/流式响应：只留 {contentType,bytes,complete}，不存半截内容', () => {
    const part = svc.buildResponsePart({
      status: 200,
      headers: { 'content-type': 'application/pdf' },
      contentType: 'application/pdf',
      body: '%PDF-1.4 secret',
      bytes: 4096,
      complete: true,
      streamed: true,
    });
    expect(part.body).toEqual({ contentType: 'application/pdf', bytes: 4096, complete: true });
    expect(JSON.stringify(part)).not.toContain('PDF-1.4 secret');
  });
});

describe('容量闸：采样与丢弃必须可见（计数 + 信号，不静默）', () => {
  beforeEach(() => {
    svc.resetForTests();
  });

  test('单 IP 超配额后按 1/N 采样：sampled 累加，captured 只在放行时增长', () => {
    const made = [];
    for (let i = 0; i < 9; i += 1) {
      made.push(
        svc.record({
          req: buildReq(),
          res: {},
          ip: '203.0.113.7',
          trigger: { reason: 'honeypot_login' },
          response: jsonResponse('{"ok":true}'),
        })
      );
    }
    const stats = svc.getForensicCaptureStats();
    // 前 2 条放行（配额 2），其后 7 条进入采样态，每第 3 条再放行一次
    expect(stats.captured).toBe(2 + Math.floor(7 / 3));
    expect(stats.sampled).toBe(7 - Math.floor(7 / 3));
    expect(stats.dropped).toBe(0);
    // 采样不是"静默跳过"：计数必须能读出
    expect(made.filter(Boolean)).toHaveLength(stats.captured);
  });

  test('全局日预算耗尽：停止捕获并计 dropped（配置为极小预算的实例）', () => {
    jest.isolateModules(() => {
      process.env.FORENSIC_GLOBAL_DAILY_BYTES = '2000'; // 单条实测约 1284 字节 ⇒ 只放行 1 条
      const isolated = require('../../services/forensicCapture');
      const results = [];
      for (let i = 0; i < 4; i += 1) {
        results.push(
          isolated.record({
            req: buildReq(),
            res: {},
            ip: '198.51.100.4',
            trigger: { reason: 'brute_force_auto_ban' },
            response: jsonResponse('{"ok":true}'),
          })
        );
      }
      const stats = isolated.getForensicCaptureStats();
      expect(stats.captured).toBeGreaterThan(0);
      expect(stats.captured).toBeLessThan(4); // 预算用尽后确实停捕
      expect(stats.dropped).toBeGreaterThan(0); // 且不是静默停止
      expect(results.filter(Boolean).length).toBe(stats.captured);
      delete process.env.FORENSIC_GLOBAL_DAILY_BYTES;
    });
  });

  test('采样跳过不占日预算：连续采样后第 10 次放行不因"假耗尽"被丢（预算口径可证伪）', () => {
    mockTrigger.on = true;
    jest.isolateModules(() => {
      process.env.FORENSIC_PER_IP_PER_MIN = '1';
      process.env.FORENSIC_SAMPLE_EVERY_N = '10';
      process.env.FORENSIC_GLOBAL_DAILY_BYTES = '4000';
      const isolated = require('../../services/forensicCapture');
      for (let i = 0; i < 11; i += 1) {
        isolated.record({
          req: buildReq(),
          res: {},
          ip: '198.51.100.9',
          trigger: { reason: 'honeypot_login' },
          response: jsonResponse('{"ok":true}'),
        });
      }
      const stats = isolated.getForensicCaptureStats();
      // 第 1 条配额内放行；第 2–10 条采样跳过；第 11 条第 10 次采样被放行。
      // 若采样也扣日预算，第 11 条会撞上"预算耗尽"被 drop ⇒ 这条断言红。
      expect(stats.sampled).toBe(9);
      expect(stats.captured).toBe(2);
      expect(stats.dropped).toBe(0);
      expect(stats.bytes).toBeLessThanOrEqual(Number(process.env.FORENSIC_GLOBAL_DAILY_BYTES));
      delete process.env.FORENSIC_PER_IP_PER_MIN;
      delete process.env.FORENSIC_SAMPLE_EVERY_N;
      delete process.env.FORENSIC_GLOBAL_DAILY_BYTES;
    });
    mockTrigger.on = false;
  });

  test('统计形状冻结：恰好七个字段（契约 §2.2 逐字）', () => {
    const stats = svc.getForensicCaptureStats();
    expect(Object.keys(stats).sort()).toEqual([
      'bytes',
      'captured',
      'dropped',
      'lastError',
      'rejected',
      'sampled',
      'walDropped',
    ]);
    expect(typeof stats.bytes).toBe('number');
    expect(stats.lastError).toBeNull();
  });
});

describe('入口判据三态：关 / 开 / 抛错', () => {
  beforeEach(() => {
    svc.resetForTests();
    mockTrigger.on = false;
    mockTrigger.throws = false;
  });

  test('开关关闭 ⇒ 不捕获（不查触发、不计数）', () => {
    const prev = process.env.FORENSIC_CAPTURE_ENABLED;
    process.env.FORENSIC_CAPTURE_ENABLED = 'false';
    expect(svc.shouldCapture('203.0.113.7')).toBe(false);
    process.env.FORENSIC_CAPTURE_ENABLED = prev;
    expect(svc.getForensicCaptureStats().rejected).toBe(0);
  });

  test('未标记 ⇒ 不捕获；已标记 ⇒ 捕获', () => {
    expect(svc.shouldCapture('203.0.113.7')).toBe(false);
    mockTrigger.on = true;
    expect(svc.shouldCapture('203.0.113.7')).toBe(true);
  });

  test('触发判据抛错 ⇒ 跳过并计 rejected，绝不外抛（取证不得成为请求链单点）', () => {
    mockTrigger.throws = true;
    expect(() => svc.shouldCapture('203.0.113.7')).not.toThrow();
    expect(svc.shouldCapture('203.0.113.7')).toBe(false);
    expect(svc.getForensicCaptureStats().rejected).toBe(2);
    expect(svc.getForensicCaptureStats().lastError).toContain('trigger_unavailable');
  });
});

describe('recordHash：canonicalJSON 稳定、篡改必变', () => {
  test('键序无关：同一内容两种键序算出同一哈希', () => {
    expect(svc.canonicalJson({ b: 1, a: 2 })).toBe(svc.canonicalJson({ a: 2, b: 1 }));
    const h1 = svc.recordHashOf({ a: 2, b: 1 });
    const h2 = svc.recordHashOf({ b: 1, a: 2 });
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  test('改任一字段 ⇒ 哈希变化；recordHash 自身不参与计算', () => {
    const doc = { ip: '203.0.113.7', path: '/api/probe', response: { status: 200 } };
    const h = svc.recordHashOf(doc);
    expect(svc.recordHashOf({ ...doc, response: { status: 201 } })).not.toBe(h);
    expect(svc.recordHashOf({ ...doc, recordHash: 'deadbeef' })).toBe(h);
  });

  test('seq 由 WAL 行号镜像而来，且参与哈希（P2b 清单要按它锚定）', async () => {
    svc.resetForTests();
    const model = require('../../models/ForensicCapture');
    model.insertMany.mockClear();
    svc.record({
      req: buildReq(),
      res: {},
      ip: '203.0.113.7',
      trigger: { reason: 'honeypot_login' },
      response: jsonResponse('{"ok":true}'),
    });
    await svc.flush();
    // 未启用 WAL ⇒ 没有行号：seq 落 null 而不是 undefined（strict schema 会静默丢掉 undefined 键）
    expect(model.insertMany.mock.calls[0][0][0].seq).toBeNull();
    // 篡改 seq 必须能被哈希抓住：清单链按 firstSeq/lastSeq 覆盖记录，seq 若在哈希外就能被悄悄改
    const doc = { ip: '203.0.113.7', seq: 'run-1' };
    expect(svc.recordHashOf({ ...doc, seq: 'run-2' })).not.toBe(svc.recordHashOf(doc));
  });

  test('undefined 键与 Date 都被规范化（否则哈希在落库后必然对不上）', () => {
    expect(svc.canonicalJson({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(svc.canonicalJson({ t: new Date('2026-10-31T00:00:00Z') })).toBe(
      '{"t":"2026-10-31T00:00:00.000Z"}'
    );
  });
});
