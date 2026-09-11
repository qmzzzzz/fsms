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
    expect(doc.hmac).toBeTruthy();
    expect(doc.hashVersion).toBeTruthy();
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
