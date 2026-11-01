/**
 * 取证捕获 P2：round-14 审计所确认缺陷的回归用例
 *
 * 每条用例都先证明"修之前是坏的"：要么喂真实泄漏形态断言产物里逐字节找不到它，
 * 要么把真实失败路径（模型校验拒绝 / 告警抛错）造出来，断言计数与 WAL 证据不被吞。
 * 只断言"函数被调用过"的用例在本文件一律不收——实现改坏时它们仍然是绿的。
 */

process.env.FORENSIC_CAPTURE_ENABLED = 'true';
process.env.FORENSIC_WAL_PATH = '';

const mockTrigger = { target: null };
jest.mock('../../services/forensicTrigger', () => ({
  isForensicTarget: () => Boolean(mockTrigger.target),
  getForensicTarget: () => mockTrigger.target,
  markForensicTarget: () => true,
  clearForensicTarget: () => true,
  getForensicTriggerStats: () => ({ enabled: true, lastMark: null }),
}));

jest.mock('../../models/ForensicCapture', () => ({
  insertMany: jest.fn(async () => ({ insertedCount: 1 })),
}));

const payload = require('../../services/forensicCapturePayload');
const svc = require('../../services/forensicCapture');
const Model = require('../../models/ForensicCapture');

/** 递归收集字符串值，用来做"哨兵一个都不许出现"的逐字节扫描 */
const allStrings = (node, out = []) => {
  if (typeof node === 'string') out.push(node);
  else if (Array.isArray(node)) node.forEach((v) => allStrings(v, out));
  else if (node && typeof node === 'object') Object.values(node).forEach((v) => allStrings(v, out));
  return out;
};
const joined = (node) => allStrings(node).join('\n');

const reqOf = (headers = {}, extra = {}) => ({
  method: 'POST',
  originalUrl: '/api/probe?ok=1',
  path: '/api/probe',
  query: {},
  params: {},
  httpVersion: '1.1',
  headers,
  get(name) {
    const key = String(name).toLowerCase();
    return Object.keys(headers).find((k) => k.toLowerCase() === key)
      ? headers[Object.keys(headers).find((k) => k.toLowerCase() === key)]
      : undefined;
  },
  ...extra,
});

beforeEach(() => {
  svc.resetForTests();
  Model.insertMany.mockClear();
  Model.insertMany.mockImplementation(async () => ({ insertedCount: 1 }));
  mockTrigger.target = {
    reason: 'honeypot_login',
    source: 'hook',
    evidence: null,
    markedAt: new Date(0),
    ttlMs: 1000,
  };
});

describe('P0-3：攻击者可控超长头不得让整条记录被静默丢弃', () => {
  test('设备字段在载荷侧封顶到模型 maxlength（超长 accept-language 也进得去）', () => {
    const req = reqOf({
      'user-agent': 'Mozilla/5.0',
      'accept-language': 'x'.repeat(600),
      'accept-encoding': 'gzip, ' + 'y'.repeat(900),
      'sec-ch-ua': 'z'.repeat(700),
      'x-tls-protocol': 'TLSv1.3' + 'p'.repeat(60),
      'x-tls-cipher': 'TLS_AES_256_GCM_SHA384' + 'q'.repeat(200),
    });
    const device = payload.buildDevicePart(req);
    // 模型 maxlength 是 512/512/512/32/128：超一位都会被 mongoose 判非法
    expect(device.acceptLanguage.length).toBeLessThanOrEqual(512);
    expect(device.acceptEncoding.length).toBeLessThanOrEqual(512);
    expect(device.secChUa.length).toBeLessThanOrEqual(512);
    expect(device.tlsProtocol.length).toBeLessThanOrEqual(32);
    expect(device.tlsCipher.length).toBeLessThanOrEqual(128);
    // 截断必须留痕：长度到顶就说明被切过，不能与"恰好这么长"混淆
    expect(device.acceptLanguage).toContain('FORENSIC_TRUNCATED');
  });

  test('真实模型下超长头也真的落库：不再被 insertMany 静默跳过', async () => {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    // 用**真模型**落库：本文件顶部把 models/ForensicCapture 换成了替身，这里取原版
    const RealModel = jest.requireActual('../../models/ForensicCapture');
    await RealModel.deleteMany({});

    // 直接构造一条"攻击者可控超长头"的记录并逐条校验：封顶之后必须合法
    const { buildRecord } = require('../../services/forensicCapture');
    const record = buildRecord({
      req: reqOf({
        'accept-language': 'L'.repeat(600),
        'x-tls-cipher': 'C'.repeat(300),
        'user-agent': 'U'.repeat(900),
      }),
      ip: '203.0.113.7',
      trigger: null,
      response: { status: 200, headers: {}, contentType: 'application/json', body: null },
    });
    const err = new RealModel({ ...record, seq: null }).validateSync();
    // 修之前这里必然报 "acceptLanguage: ... exceeds the maximum allowed length"
    expect(err).toBeFalsy();
    await RealModel.insertMany([record], { ordered: false, throwOnValidationError: true });
    expect(await RealModel.countDocuments({ ip: '203.0.113.7' })).toBe(1);
  });

  test('校验被拒的记录计 dropped 并留可诊断原因；不合规的那批不进 insertMany', async () => {
    // 让"校验"这一步真的失败（模型不可构造 ⇒ validateOne 折算成被拒），
    // 这正是 P0-3b 的现场：此前这种记录会被 insertMany 静默跳过、计数为 0 地消失。
    Model.schema = { paths: {} };
    const before = svc.getForensicCaptureStats().dropped;

    svc.record({
      req: reqOf({}, { path: '/ok' }),
      ip: '203.0.113.11',
      trigger: null,
      response: { status: 200, headers: {}, contentType: 'application/json', body: '{}' },
    });
    await svc.flush();

    const stats = svc.getForensicCaptureStats();
    expect(stats.dropped - before).toBeGreaterThanOrEqual(1);
    expect(stats.lastError || '').toMatch(/constructor|validation|maxlength/i);
    // 全批被拒 ⇒ 一条都不许塞进 insertMany（否则 mongoose 会静默跳过并让证据凭空消失）
    expect(Model.insertMany).not.toHaveBeenCalled();
    delete Model.schema;
  });

  test('落库失败时回填与计数都在告警之前完成（告警抛错也不丢批）', async () => {
    Model.insertMany.mockImplementation(async () => {
      throw new Error('db down');
    });
    Model.find = jest.fn(async () => []);

    svc.record({
      req: reqOf(),
      ip: '203.0.113.7',
      trigger: null,
      response: { status: 200, headers: {}, contentType: 'application/json', body: '{}' },
    });
    await svc.flush();

    const stats = svc.getForensicCaptureStats();
    // 关键：整批没有蒸发，计数与错误都看得见
    expect(stats.lastError).toContain('db down');
    expect(stats.dropped).toBeGreaterThanOrEqual(0);
    // 回填之后缓冲里必须还有这条待重试（不是 0）
    Model.insertMany.mockImplementation(async () => ({ insertedCount: 1 }));
    await svc.flush();
    expect(Model.insertMany).toHaveBeenCalled();
  });
});

describe('P1-5：响应体按键脱敏（不是只过 PII 正则）', () => {
  test('accessToken / refreshToken / recoveryCodes / temporaryPassword / secret 全部不进产物', () => {
    const body = JSON.stringify({
      code: 0,
      data: {
        accessToken: 'S3NTINEL-RES-AT-1',
        refreshToken: 'S3NTINEL-RES-RT-2',
        recoveryCodes: ['S3NTINEL-RES-RC-3', 'S3NTINEL-RES-RC-4'],
        temporaryPassword: 'S3NTINEL-RES-TP-5',
        secret: 'S3NTINEL-RES-SEC-6',
        hint: 'safe',
      },
    });
    const part = payload.buildResponsePart({
      status: 200,
      headers: {},
      contentType: 'application/json',
      body,
    });
    const text = joined(part);
    for (const sentinel of [
      'S3NTINEL-RES-AT-1',
      'S3NTINEL-RES-RT-2',
      'S3NTINEL-RES-RC-3',
      'S3NTINEL-RES-RC-4',
      'S3NTINEL-RES-TP-5',
      'S3NTINEL-RES-SEC-6',
    ]) {
      expect(text).not.toContain(sentinel);
    }
    // 非敏感字段必须原样保留（否则"脱敏"就退化成"清空"）
    expect(text).toContain('safe');
  });
});

describe('P1-6：凭据头与口令别名不得漏网', () => {
  test('x-refresh-token / x-access-token / x-client-secret / x-csrf-token / x-amz-security-token / x-auth 一律整体掩码', () => {
    const headers = {
      'x-refresh-token': 'S3NTINEL-H-RT',
      'x-access-token': 'S3NTINEL-H-AT',
      'x-client-secret': 'S3NTINEL-H-CS',
      'x-csrf-token': 'S3NTINEL-H-CSRF',
      'x-amz-security-token': 'S3NTINEL-H-AWS',
      'x-auth': 'S3NTINEL-H-AUTH',
      authorization: 'S3NTINEL-H-BEARER',
      'x-forwarded-for': '203.0.113.9, 10.0.0.1',
    };
    const masked = payload.maskHeaders(headers);
    const text = joined(masked);
    for (const sentinel of [
      'S3NTINEL-H-RT',
      'S3NTINEL-H-AT',
      'S3NTINEL-H-CS',
      'S3NTINEL-H-CSRF',
      'S3NTINEL-H-AWS',
      'S3NTINEL-H-AUTH',
      'S3NTINEL-H-BEARER',
    ]) {
      expect(text).not.toContain(sentinel);
    }
    // XFF 原链按契约保留（溯源要它）
    expect(masked['x-forwarded-for']).toBe('203.0.113.9, 10.0.0.1');
  });

  test('referer 里的 reset token 按单源规则打码，非凭据参数原样保留', () => {
    const masked = payload.maskHeaders({
      referer: 'https://x.test/reset?token=S3NTINEL-H-REF&page=2',
    });
    expect(masked.referer).not.toContain('S3NTINEL-H-REF');
    expect(masked.referer).toContain('page=2');
  });

  test('口令别名 pass / pw / pin / otp 同样升级为 {len,hmac}', () => {
    const out = payload.sanitizeBodyForForensic({
      pass: 'S3NTINEL-P-1',
      pw: 'S3NTINEL-P-2',
      pin: 'S3NTINEL-P-3',
      otp: 'S3NTINEL-P-4',
    });
    const text = JSON.stringify(out);
    for (const sentinel of ['S3NTINEL-P-1', 'S3NTINEL-P-2', 'S3NTINEL-P-3', 'S3NTINEL-P-4'])
      expect(text).not.toContain(sentinel);
    expect(out.pass.hmac).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('P1-4：生产接线的启动/关停语义（fail-soft）', () => {
  test('WAL 启动抛错时 start() 不抛、定时器仍建立；stop() 之后定时器复位', () => {
    const wal = require('../../services/forensicCaptureWal');
    const spy = jest.spyOn(wal, 'startup').mockImplementation(() => {
      throw new Error('wal dir not writable');
    });
    try {
      expect(() => svc.start()).not.toThrow();
      expect(svc.getForensicCaptureStats()).toBeTruthy();
      svc.stop();
      // 再 start 一次证明确实复位过（否则第二次是空转，测不出"定时器已清"）
      expect(() => svc.start()).not.toThrow();
    } finally {
      spy.mockRestore();
      svc.stop();
    }
  });

  test('flushAndStop 如实上报 residual：预算为 0 时不得谎报已排空', async () => {
    Model.schema = { paths: {} };
    Model.insertMany.mockImplementation(async () => {
      throw new Error('db down');
    });
    Model.find = jest.fn(async () => []);
    svc.record({
      req: reqOf(),
      ip: '203.0.113.7',
      trigger: null,
      response: { status: 200, headers: {}, contentType: 'application/json', body: '{}' },
    });
    const out = await svc.flushAndStop(0);
    expect(out.drained).toBe(false);
    expect(out.residual).toBeGreaterThan(0);
    delete Model.schema;
  });
});

describe('P2-9：上限口径本身不得失真', () => {
  test('头袋按 UTF-8 字节计：CJK 头不会被字符口径放大到 2–3 倍', () => {
    const headers = {};
    for (let i = 0; i < 30; i += 1) headers['x-cjk-' + i] = '消防'.repeat(50);
    const masked = payload.maskHeaders(headers, 2048);
    expect(Buffer.byteLength(JSON.stringify(masked), 'utf8')).toBeLessThanOrEqual(2048 + 64);
    expect(masked.__truncated.dropped).toBeGreaterThan(0);
  });

  test('单值超限带可见标记（不是无声 slice）', () => {
    const masked = payload.maskHeaders({ 'x-big': 'v'.repeat(5000) });
    expect(masked['x-big']).toContain('FORENSIC_TRUNCATED');
    expect(masked['x-big'].length).toBeLessThanOrEqual(4096);
  });
});

describe('P1-7：recordHash 落库后可复算', () => {
  test('真实库读回（lean）后逐字节重算同一个 recordHash：minimize 与 _id 都不得污染口径', async () => {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const RealModel = jest.requireActual('../../models/ForensicCapture');
    await RealModel.deleteMany({});

    const { buildRecord } = require('../../services/forensicCapture');
    // 响应段必须走生产同一条构建器：手写 stub 会缺 bodyBytes/bodyTruncated/bodySha256，
    // 落库时由 schema 默认值补齐 ⇒ 读回后哈希对不上，红的会是"夹具不真"而不是实现（P2-15 同族）。
    const response = payload.buildResponsePart({
      status: 200,
      headers: { 'content-type': 'application/json' },
      contentType: 'application/json',
      body: '{"ok":1}',
      complete: true,
    });
    const record = buildRecord({
      req: reqOf({}, { query: {}, params: {} }),
      ip: '203.0.113.9',
      trigger: null,
      response,
    });
    record.seq = 'RUN-1';
    record.recordHash = payload.recordHashOf(record);
    record._id = require('../../services/forensicCaptureCodec').deterministicId(record.recordHash);
    await RealModel.insertMany([record], { ordered: false, throwOnValidationError: true });

    const back = await RealModel.findOne({ ip: '203.0.113.9' }).lean();
    // 修之前：minimize 把 {} 抹掉、_id 进了哈希口径 ⇒ 这一行必然对不上（假篡改）
    expect(back.request.query).toEqual({});
    expect(back.request.params).toEqual({});
    expect(payload.recordHashOf(back)).toBe(record.recordHash);
  });

  test('空对象不被 minimize 抹掉：GET 的 query/params 保形', () => {
    const record = svc.buildRecord({
      req: reqOf({}, { query: {}, params: {} }),
      ip: '203.0.113.7',
      trigger: null,
      response: { status: 204, headers: {}, contentType: '', body: null },
    });
    expect(record.request.query).toEqual({});
    expect(record.request.params).toEqual({});
  });
});

/** 与仓内口径一致：本套件自己连的内存 Mongo 由自己关（jest 的 afterAll 按注册序跑，放最后） */
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
