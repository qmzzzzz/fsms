/**
 * 登录审计留痕的保真度（三条各自独立、都曾静默失真）
 *
 * 1) `sanitizeAuditDeep`（模型侧 params/query 清洗）此前是"先按键脱敏、再剥控制字符"，
 *    注释还断言"顺序无关紧要"。对 body 确实无关（子串匹配），对 query 相关：
 *    查询键名单 `matchesSensitiveQueryKey` 按整键/下划线边界判、不容空白，
 *    而 `stripControlCharsDeep` 会重写键名并 trim。于是 `?+sign=<凭据>`
 *    （qs 把 `+` 解成空格）先判定时 `" sign"` 不命中 ⇒ 值原样保留，
 *    随后键被归一成 `"sign"` ⇒ 明文凭据落进 append-only、定期导 CSV 的审计集合。
 *    中间件侧一直是"先清洗后脱敏"，同一条请求两处结论相反。
 *
 * 2) `recordLogin` 从不取用调用方传的 `extra.reason`，而 M-5 把差异化响应收成统一 401
 *    防枚举时，注释写的是"真实原因仅记入服务端日志与审计"——审计这一环是空的。
 *
 * 3) 五处登录失败审计写失败仍用 `.catch(() => {})` 完全静默（同仓 17 处已接
 *    `onAuditWriteFailure`）。`login_failed` 是暴力破解检测与锁定的唯一数据源，
 *    写失败即检测漏数且无任何指标。
 *
 * 每条都配反向对照，防止"永远通过"的断言。
 */

const mongoose = require('mongoose');
const AuditLog = require('../../models/AuditLog');
const User = require('../../models/User');
const metrics = require('../../utils/metrics');
const authService = require('../../services/authService');
const { normalizeLoginRateKey } = require('../../middleware/rateLimit');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const TAG = `laf${Date.now().toString(36)}`;
const PASSWORD = randomPassword();
const SECRET = 'eyJhbGciOi.SECRETVALUE.not-a-real-token';

const ctx = {
  ip: '127.0.0.1',
  userAgent: 'test-agent',
  fingerprint: 'fp-test',
  method: 'POST',
  path: '/api/auth/login',
  req: { headers: { 'user-agent': 'test-agent' }, ip: '127.0.0.1', connection: {} },
};

/** 中间件同款请求桩：只用到审计会读的字段 */
const auditReq = (query) => ({
  method: 'POST',
  originalUrl: '/api/probe?x=1',
  path: '/api/probe',
  ip: '203.0.113.9',
  headers: { 'user-agent': 'probe-agent' },
  get: (h) => (String(h).toLowerCase() === 'user-agent' ? 'probe-agent' : undefined),
  body: {},
  params: {},
  query,
  user: {},
});

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(process.env.MONGODB_URI);
  }
});

afterAll(async () => {
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});

const res_ok = () => ({ statusCode: 200 });

describe('查询键归一先于脱敏（凭据不得以明文入审计）', () => {
  const readBack = (username) => AuditLog.collection.findOne({ username });

  test('核心：带前导空格的敏感键，其值必须被脱敏', async () => {
    const req = auditReq({ ' sign': SECRET, otp: SECRET });
    const res = { statusCode: 200 };
    await AuditLog.recordSensitiveAction(null, `${TAG}redact`, 'auth_login', 'auth', req, res, 1);
    const written = await readBack(`${TAG}redact`);
    expect(written).not.toBeNull();
    // 清洗后键名归一为 sign/otp，两个值都必须是占位符
    expect(written.query.sign).toBe('***');
    expect(written.query.otp).toBe('***');
    expect(JSON.stringify(written.query)).not.toContain('SECRETVALUE');
  });

  test('对照：非敏感键的值必须原样保留（否则"全部打码"也能骗绿）', async () => {
    const req = auditReq({ keyword: 'plainvalue' });
    await AuditLog.recordSensitiveAction(
      null,
      `${TAG}keep`,
      'auth_login',
      'auth',
      req,
      res_ok(),
      1
    );
    const written = await readBack(`${TAG}keep`);
    expect(written.query.keyword).toBe('plainvalue');
  });

  test('前提自证：两种顺序确实给出不同结果（判据不是空转）', () => {
    const { sanitizeAuditQuery } = require('../../models/auditLogSanitizer');
    const { stripControlCharsDeep } = require('../../utils/helpers');
    const leaky = stripControlCharsDeep(sanitizeAuditQuery({ ' sign': SECRET }));
    const safe = sanitizeAuditQuery(stripControlCharsDeep({ ' sign': SECRET }));
    expect(leaky.sign).toBe(SECRET);
    expect(safe.sign).toBe('***');
  });
});

describe('recordLogin 必须兑现它声称要记的东西', () => {
  test('extra.reason 落库且外控 UA 被清洗', async () => {
    await AuditLog.recordLogin(null, `${TAG}reason`, '203.0.113.10', false, 'zz\nagent', {
      fingerprint: 'fp',
      reason: 'account_status_inactive',
    });
    const written = await AuditLog.collection.findOne({ username: `${TAG}reason` });
    expect(written.reason).toBe('account_status_inactive');
    expect(written.userAgent).toBe('zz agent');
    expect(written.userAgent).not.toContain('\n');
  });

  test('端到端：禁用账号的登录尝试在审计里可与"密码错误"区分', async () => {
    const user = await User.create({
      username: `${TAG}inactive`,
      email: `${TAG}inactive@example.com`,
      password: PASSWORD,
      status: 'inactive',
    });
    try {
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        ctx
      );
      // 对外仍是统一 401（M-5 防枚举不许动），差别只在留存里
      expect(result.outcome).toBeTruthy();
      const written = await AuditLog.collection.findOne({ username: `${TAG}inactive` });
      expect(written).not.toBeNull();
      expect(written.reason).toBe('account_status_inactive');
    } finally {
      await User.collection.deleteOne({ _id: user._id });
    }
  });

  test('对照：不带 reason 的调用不得凭空写出该字段', async () => {
    await AuditLog.recordLogin(null, `${TAG}noreason`, '203.0.113.11', false, 'zz-agent', {
      fingerprint: 'fp',
    });
    const written = await AuditLog.collection.findOne({ username: `${TAG}noreason` });
    expect(written.reason ?? null).toBeNull();
  });
});

describe('登录审计写失败必须有信号', () => {
  test('落库抛错时计入 audit_write_failed，且登录结论不变', async () => {
    const spy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
    const original = AuditLog.recordLogin;
    AuditLog.recordLogin = () => Promise.reject(new Error('zz inject'));
    try {
      const result = await authService.loginUser(
        { username: `${TAG}nosuchuser`, password: `${PASSWORD}wrong` },
        ctx
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      expect(spy).toHaveBeenCalledWith('audit_write_failed', 'high');
    } finally {
      AuditLog.recordLogin = original;
      spy.mockRestore();
    }
  });
});

describe('登录账号维度限流键的归一化', () => {
  test('核心：首尾空白与大小写不得分裂计数桶', () => {
    expect(normalizeLoginRateKey(' admin ')).toBe(normalizeLoginRateKey('ADMIN'));
    expect(normalizeLoginRateKey('admin   ')).toBe(normalizeLoginRateKey('admin'));
  });

  test('对照：不同账号仍必须分桶（否则"全部同键"也能骗绿）', () => {
    expect(normalizeLoginRateKey('alice')).not.toBe(normalizeLoginRateKey('bob'));
    expect(normalizeLoginRateKey('ali ce')).not.toBe(normalizeLoginRateKey('alice'));
  });
});

/**
 * 中间件 `auditLog` 里的 body 脱敏是 `models/auditLogSanitizer.sanitizeAuditBody` 的
 * 第二份实现（两处深度窗口需各自独立控制，见该文件注释）。它此前仍在用 `cleaned[k] = ...`
 * 落键：express.json 走 JSON.parse，`{"__proto__":{...}}` 的 __proto__ 是**自身可枚举键**，
 * 这句赋值触发 Object.prototype setter ⇒ 该键整个消失，攻击探针在审计副本里蒸发。
 * 既有的"0–10 层逐字节一致"用例没带这个键，所以两处漂移长期无人察觉。
 */
describe('中间件 body 脱敏与模型侧同形（含 __proto__ 自身键）', () => {
  const express = require('express');
  const request = require('supertest');
  const { auditLog } = require('../../middleware/security');
  const auditBuffer = require('../../services/auditBuffer');
  const { sanitizeAuditBody } = require('../../models/auditLogSanitizer');
  const { stripControlCharsDeep } = require('../../utils/helpers');

  // 必须经 JSON.parse 才有"自身 __proto__ 键"；对象字面量里的 __proto__ 是原型设置
  const RAW = '{"password":"plainsecret","__proto__":{"polluted":1}}';

  const buildApp = () => {
    const app = express();
    app.use(express.json());
    // auditLog 是工厂：必须调用后再挂载（直接把工厂当中间件会让请求永远不 settle）
    app.use('/api/', auditLog());
    app.post('/api/probe', (_req, res) => res.json({ ok: true }));
    return app;
  };

  const tick = () => new Promise((resolve) => setImmediate(resolve));

  test('核心：__proto__ 作为自身键必须保留，且不得污染原型', async () => {
    const spy = jest.spyOn(auditBuffer, 'push').mockImplementation(() => {});
    try {
      const res = await request(buildApp()).post('/api/probe').type('json').send(RAW);
      expect(res.status).toBe(200);
      await tick();
      expect(spy).toHaveBeenCalled();
      const pushed = spy.mock.calls.map((c) => c[0]).find((e) => e && e.path === '/api/probe');
      expect(pushed).toBeDefined();

      const descriptor = Object.getOwnPropertyDescriptor(pushed.body, '__proto__');
      expect(descriptor).toBeDefined();
      expect(descriptor.value).toEqual({ polluted: 1 });
      expect(pushed.body.password).toBe('***');
      // 副证：这条请求若把原型写脏，之后任何新对象都会带 polluted
      expect({}.polluted).toBeUndefined();
      // 与模型侧逐字节一致（两处实现不许漂移）
      expect(JSON.stringify(pushed.body)).toBe(
        JSON.stringify(stripControlCharsDeep(sanitizeAuditBody(JSON.parse(RAW))))
      );
    } finally {
      spy.mockRestore();
    }
  });
});
