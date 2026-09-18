const mongoose = require('mongoose');

describe('AuditLog behavior guards', () => {
  let AuditLog;
  const stamp = `alb${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      AuditLog._setAppendOnlyEnforced(false);
      await AuditLog.deleteMany({ username: stamp }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('getUserActivity filters by category and omits protected fields', async () => {
    const userId = new mongoose.Types.ObjectId();
    await AuditLog.create({
      action: 'auth_login',
      category: 'auth',
      userId,
      username: stamp,
      body: { password: 'secret' },
      hmac: 'must-not-leak',
    });
    await AuditLog.create({
      action: 'device_update',
      category: 'device',
      userId,
      username: stamp,
    });

    const logs = await AuditLog.getUserActivity(userId, { category: 'auth', limit: 10 });
    expect(logs).toHaveLength(1);
    expect(logs[0].category).toBe('auth');
    expect(logs[0].body).toBeUndefined();
    expect(logs[0].hmac).toBeUndefined();
  });

  test('preserves a caller-provided hash and derives its HMAC and version', async () => {
    const doc = await AuditLog.create({
      action: 'audit_imported',
      category: 'system',
      username: stamp,
      hash: 'imported-chain-hash',
    });
    // 【断言收紧】原断言只有 toBeTruthy()×2，标题承诺的「保留调用方提供的 hash」从未被断言：
    // 变异验证——把 auditLogHooks 的 `if (this.hash)` 短路分支改成 `if (false)`
    // （调用方 hash 会被重算覆盖），旧写法 SURVIVED（同目录 45 个相关用例全绿）。
    // 实测：hash 原样保留、prevHash 保持 null 不被改写、hashVersion 落为 CURRENT_PAYLOAD_VERSION(3)、
    // hmac 为 64 位十六进制（= SHA-256 输出长度）。
    expect(doc.hash).toBe('imported-chain-hash');
    expect(doc.prevHash).toBeNull();
    expect(doc.hashVersion).toBe(3);
    expect(String(doc.hmac)).toMatch(/^[0-9a-f]{64}$/);
  });

  test('blocks save-side modification of an append-only audit record', async () => {
    const doc = await AuditLog.create({
      action: 'append_only_original',
      category: 'system',
      username: stamp,
    });
    doc.action = 'append_only_tampered';
    await expect(doc.save()).rejects.toThrow('append-only');
  });
});
