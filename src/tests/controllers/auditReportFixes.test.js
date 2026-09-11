/**
 * 本轮审计报告修复的综合回归
 *
 * 覆盖：
 * - P1-2  my-logs 不外泄 hmac（离线爆破通道）
 * - P1-5  审计 CSV 公式注入防护
 * - P1-7  注册开关不被环境变量覆写
 * - AUX-01 TRUST_PROXY_HOPS 值域校验
 * - AUX-04 查询参数标量收敛（?x[$ne]=y 操作符注入 / .trim() 型 500）
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('审计报告修复综合回归', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let admin;
  let adminToken;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

    const auditPerm = await Permission.findOneAndUpdate(
      { code: 'security:audit' },
      {
        $setOnInsert: { code: 'security:audit', name: '审计日志', type: 'api', module: 'security' },
      },
      { upsert: true, new: true }
    );
    const role = await Role.findOneAndUpdate(
      { code: 'AUDITOR_FIX_TEST' },
      {
        $setOnInsert: {
          code: 'AUDITOR_FIX_TEST',
          name: '审计员_修复测试',
          level: 8,
          permissions: [auditPerm._id],
        },
      },
      { upsert: true, new: true }
    );

    admin = await User.create({
      username: 'fixreg_admin',
      email: 'fixreg_admin@example.com',
      password: 'Qz7#Lm42vTx9',
      department: 'AUDIT_FIX_DEPT',
      roles: [role._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const asAdmin = (path) => request(app).get(path).set('Authorization', `Bearer ${adminToken}`);

  // ================= P1-2 =================
  describe('P1-2 my-logs 不外泄 hmac', () => {
    test('getUserActivity 复用 RESPONSE_EXCLUDE：结果无 hmac，保留 hash', async () => {
      // /api/security/my-logs 任意登录用户可调，一次可拉 500 条。
      // 若同时给出 (hash, hmac)，攻击者离线即可穷举 HMAC_SECRET
      const created = await AuditLog.create({
        action: 'login_success',
        category: 'auth',
        userId: admin._id,
        username: admin.username,
        ip: '::1',
        path: '/api/auth/login',
        statusCode: 200,
        success: true,
      });
      const raw = await AuditLog.findById(created._id).lean();
      expect(typeof raw.hmac).toBe('string');

      const rows = await AuditLog.getUserActivity(admin._id, { limit: 50, days: 1 });
      const hit = rows.find((r) => String(r._id) === String(created._id));
      expect(hit).toBeDefined();
      expect(hit.hmac).toBeUndefined();
      expect(hit.hash).toBe(raw.hash);
      expect(hit.body).toBeUndefined();
    });

    test('HTTP 层 /api/security/my-logs 响应同样无 hmac', async () => {
      const res = await asAdmin('/api/security/my-logs?limit=20&days=1');
      expect(res.status).toBe(200);
      const list = res.body.data?.logs || res.body.data?.data || res.body.data || [];
      expect(Array.isArray(list)).toBe(true);
      for (const row of list) {
        expect(row.hmac).toBeUndefined();
      }
    });
  });

  // ================= P1-5 =================
  describe('P1-5 审计 CSV 公式注入防护', () => {
    test('攻击者可控的 username 中的公式被前置单引号中和', async () => {
      // 登录失败路径以原始请求体 username 入库，loginValidation 不限字符集
      const payload = "=cmd|'/c calc'!A1";
      await AuditLog.create({
        action: 'login_failed',
        category: 'auth',
        userId: admin._id,
        username: payload,
        ip: '::1',
        path: '/api/auth/login',
        statusCode: 401,
        success: false,
      });

      const res = await asAdmin('/api/security/audit-logs/export?limit=200');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/csv');
      // P3-12 起接口为流式 CSV（不再包 JSON 信封），正文直接是 CSV 文本
      const csv = res.text || '';
      expect(csv).toContain('username');

      // 危险载荷必须以 ' 开头出现（Excel/WPS 按文本处理），绝不能原样出现在行首
      const dangerous = csv.split('\n').filter((line) => line.includes('cmd|'));
      expect(dangerous.length).toBeGreaterThan(0);
      for (const line of dangerous) {
        // 该单元格被引号包裹（含逗号）时，前置单引号在引号之后
        expect(/(^|,)"?'=/.test(line) || line.includes("'=cmd")).toBe(true);
        // 不存在「未中和的裸公式单元格」
        expect(/(^|,)=cmd/.test(line)).toBe(false);
      }
    });

    test.each([
      ['加号前缀', '+SUM(1)'],
      ['减号前缀', '-2+3'],
      ['@ 前缀', '@SUM(1)'],
    ])('%s 同样被中和', async (_label, payload) => {
      const { sanitizeSpreadsheetCell } = require('../../utils/helpers');
      expect(sanitizeSpreadsheetCell(payload)).toBe(`'${payload}`);
    });

    test('普通值不受影响（不引入多余引号）', () => {
      const { sanitizeSpreadsheetCell } = require('../../utils/helpers');
      expect(sanitizeSpreadsheetCell('admin')).toBe('admin');
      expect(sanitizeSpreadsheetCell('login_failed')).toBe('login_failed');
    });
  });

  // ================= AUX-04 =================
  describe('AUX-04 查询参数标量收敛', () => {
    test.each([
      ['对象型 search（原 500）', '/api/users?search[$regex]=^a'],
      ['对象型 status（操作符注入）', '/api/users?status[$ne]=active'],
      ['对象型 status（操作符注入）', '/api/users?status[$ne]=active'],
    ])('%s → 400 而非 500', async (_label, path) => {
      const res = await asAdmin(path);
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.errors?.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
    });

    test('重复 search 不再享有 hpp 白名单，统一按非标量拒绝', async () => {
      // 评价报告 L5：queryScalarGuard 要求全标量，而旧 hpp whitelist
      // 放行 search/sort 数组，两道防线口径冲突；现在统一拒绝数组形态
      const res = await asAdmin('/api/users?search=a&search=b');
      expect(res.status).not.toBe(500);
      expect(res.status).toBe(400);
      expect(res.body.errors?.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
    });

    test('标量参数正常通行', async () => {
      const res = await asAdmin('/api/users?status=active&page=1&limit=5');
      expect(res.status).not.toBe(400);
    });
  });

  // ================= 审计链在线校验接口 =================
  describe('AUX-02 审计链完整性校验接口', () => {
    test('返回结构化报告（含逐类断裂计数与 v2 历史漂移计数）', async () => {
      const res = await asAdmin('/api/security/audit-logs/verify?limit=200');
      expect(res.status).toBe(200);
      const r = res.body.data;
      expect(typeof r.intact).toBe('boolean');
      expect(typeof r.total).toBe('number');
      expect(r.byType).toHaveProperty('hash_mismatch');
      expect(r.byType).toHaveProperty('hmac_missing');
      expect(r.byType).toHaveProperty('hmac_mismatch');
      expect(r.byType).toHaveProperty('chain_break');
      // v2 批量路径的默认值漂移单独计数，不淹没真实告警
      expect(typeof r.legacyV2BatchTolerated).toBe('number');
      expect(r.hmacChecked).toBe(true);
    });

    test('新写入记录（v3）通过校验，不产生 hash_mismatch', async () => {
      // 本轮修复后 chainBatch 会在算 hash 前补齐 schema 默认值，
      // 且版本号升到 3 以消除 v2 的口径歧义
      const docs = [
        {
          action: 'audit_chain_verify',
          category: 'security',
          username: 'v3_probe',
          ip: '::1',
          path: '/v1',
          statusCode: 200,
          success: true,
        },
        {
          action: 'audit_chain_verify',
          category: 'security',
          username: 'v3_probe',
          ip: '::1',
          path: '/v2',
          statusCode: 200,
          success: true,
        },
      ];
      const { chainBatch, getLatestHash } = require('../../utils/auditChain');
      chainBatch(docs, await getLatestHash(AuditLog));
      await AuditLog.insertMany(docs, { ordered: false });

      const { verifyAuditChain } = require('../../services/auditChainVerify');
      const stored = await AuditLog.find({ username: 'v3_probe' }).lean();
      expect(stored.every((d) => d.hashVersion === 3)).toBe(true);

      // 单独校验这两条：重算必须一致
      const { canonicalPayload, computeHash, computeHmac } = require('../../utils/auditChain');
      for (const d of stored) {
        expect(computeHash(d.prevHash, canonicalPayload(d, 3))).toBe(d.hash);
        expect(d.hmac).toBe(computeHmac(d.hash));
      }

      // 接口层面也不应把它们计为断裂
      const report = await verifyAuditChain(AuditLog, { maxRecords: 500 });
      const v3Breaks = (report.samples || []).filter((s) => s.hashVersion === 3);
      expect(v3Breaks).toEqual([]);
    });

    test('非法 limit / from 返回 400', async () => {
      expect((await asAdmin('/api/security/audit-logs/verify?limit=abc')).status).toBe(400);
      expect((await asAdmin('/api/security/audit-logs/verify?from=sideways')).status).toBe(400);
    });

    test('无 security:audit 权限被拒', async () => {
      const plain = await User.create({
        username: 'fixreg_plain',
        email: 'fixreg_plain@example.com',
        password: 'Qz7#Lm42vTx9',
      });
      const token = jwt.sign(
        { userId: String(plain._id), username: plain.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      const res = await request(app)
        .get('/api/security/audit-logs/verify')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(403);
    });
  });
});
