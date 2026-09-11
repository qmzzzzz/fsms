/**
 * AuditLog 模型静态方法测试：脱敏递归性与风险评估准确性
 */

const mongoose = require('mongoose');

describe('AuditLog 模型静态方法', () => {
  let AuditLog;

  beforeAll(async () => {
    AuditLog = require('../../models/AuditLog');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterEach(async () => {
    // append-only 钩子会拒绝 deleteMany，测试清理需通过 bypassAppendOnly 绕过
    await AuditLog.deleteMany({ username: /^sanitize_|^risk_/ }, { bypassAppendOnly: true });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const makeReq = (overrides = {}) => ({
    ip: '::1',
    method: 'PUT',
    originalUrl: '/api/auth/password',
    params: {},
    query: {},
    body: {},
    get: (h) => (h === 'user-agent' ? 'jest' : undefined),
    ...overrides,
  });

  describe('recordSensitiveAction — body 递归脱敏', () => {
    test('嵌套对象与数组中的敏感字段一并脱敏', async () => {
      const req = makeReq({
        body: {
          currentPassword: 'a',
          profile: { token: 'secret-token', nested: { password: 'p' } },
          list: [{ refreshToken: 'rt' }, { safe: 'keep' }],
        },
      });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'sanitize_user',
        'change_password',
        'auth',
        req,
        { statusCode: 200 },
        5
      );

      expect(doc.body.currentPassword).toBe('***');
      // 关键回归点：此前仅遍历第一层，嵌套层级明文落库
      expect(doc.body.profile.token).toBe('***');
      expect(doc.body.profile.nested.password).toBe('***');
      expect(doc.body.list[0].refreshToken).toBe('***');
      expect(doc.body.list[1].safe).toBe('keep');
    });

    test('非敏感字段与原始类型保持不变', async () => {
      const req = makeReq({ body: { realName: '张三', age: 30, active: true, tags: ['a', 'b'] } });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'sanitize_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.body.realName).toBe('张三');
      expect(doc.body.age).toBe(30);
      expect(doc.body.active).toBe(true);
      expect(doc.body.tags).toEqual(['a', 'b']);
    });

    test('超深嵌套被截断而非抛栈溢出', async () => {
      let deep = { password: 'x' };
      for (let i = 0; i < 12; i++) deep = { level: deep };
      const req = makeReq({ body: deep });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'sanitize_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc).toBeTruthy();
    });
  });

  describe('recordSensitiveAction — 风险评估', () => {
    test('无代理的普通成功操作为 low（修复 proxy_detected 永假命中）', async () => {
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_update',
        'user',
        makeReq(),
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toEqual([]);
      expect(doc.riskLevel).toBe('low');
    });

    test('单级代理（X-Forwarded-For 仅一个地址）不计入风险', async () => {
      const req = makeReq({
        get: (h) =>
          h === 'x-forwarded-for' ? '203.0.113.9' : h === 'user-agent' ? 'jest' : undefined,
      });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toEqual([]);
      expect(doc.riskLevel).toBe('low');
    });

    test('多级代理链被标记 multi_hop_proxy', async () => {
      const req = makeReq({
        get: (h) =>
          h === 'x-forwarded-for'
            ? '203.0.113.9, 198.51.100.7'
            : h === 'user-agent'
              ? 'jest'
              : undefined,
      });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toContain('multi_hop_proxy');
      expect(doc.riskLevel).toBe('medium');
    });

    test('删除操作计入 delete_operation', async () => {
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_delete',
        'user',
        makeReq(),
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toContain('delete_operation');
      expect(doc.riskLevel).toBe('medium');
    });

    test('失败的批量删除累积为 high', async () => {
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_batch_delete',
        'user',
        makeReq(),
        { statusCode: 500 },
        5
      );
      expect(doc.riskFactors).toEqual(
        expect.arrayContaining(['delete_operation', 'batch_operation', 'error_response'])
      );
      expect(doc.riskLevel).toBe('high');
    });

    test('path 使用完整 originalUrl 而非被剥离的 req.path', async () => {
      const req = makeReq({ originalUrl: '/api/auth/password?x=1', path: '/password' });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'change_password',
        'auth',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.path).toBe('/api/auth/password');
    });
  });

  describe('索引声明', () => {
    test('不存在被复合索引前缀覆盖的冗余单字段索引', () => {
      const signatures = AuditLog.schema.indexes().map(([key]) => Object.keys(key).join('|'));
      // 这些单字段索引应已被 {字段, timestamp:-1} 复合索引取代
      for (const redundant of [
        'action',
        'category',
        'userId',
        'statusCode',
        'success',
        'ip',
        'riskLevel',
      ]) {
        expect(signatures).not.toContain(redundant);
      }
    });

    test('关键查询维度均有 timestamp 降序复合索引', () => {
      const signatures = AuditLog.schema.indexes().map(([key]) =>
        Object.entries(key)
          .map(([k, v]) => `${k}:${v}`)
          .join('|')
      );
      for (const expected of [
        'userId:1|timestamp:-1',
        'category:1|timestamp:-1',
        'action:1|timestamp:-1',
        'riskLevel:1|timestamp:-1',
        'success:1|timestamp:-1',
        'ip:1|timestamp:-1',
        'category:1|action:1|timestamp:-1',
      ]) {
        expect(signatures).toContain(expected);
      }
    });

    test('TTL 索引保留可配留存期（与 constants/retention 单一声明一致）', () => {
      const ttl = AuditLog.schema
        .indexes()
        .find(([, opts]) => opts && opts.expireAfterSeconds !== undefined);
      expect(ttl).toBeTruthy();
      // P3-46：不再在测试里复刻解析逻辑（原为 `parseInt(...) || 180`，
      // 与模型侧的钳制口径不同，配置为 1 时测试期望 1 天而模型实为 90 天）。
      // 改为直接比对单一声明，口径只有一处
      const { RETENTION_SECONDS, MIN_RETENTION_DAYS } = require('../../constants/retention');
      expect(ttl[1].expireAfterSeconds).toBe(RETENTION_SECONDS);
      // 无论环境变量如何取值，TTL 都不得低于合规下限
      expect(ttl[1].expireAfterSeconds).toBeGreaterThanOrEqual(MIN_RETENTION_DAYS * 24 * 60 * 60);
      expect(ttl[0]).toEqual({ timestamp: -1 });
    });
  });
});
