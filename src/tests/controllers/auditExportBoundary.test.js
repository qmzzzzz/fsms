/**
 * Audit export hard-limit and CSV escaping regression tests.
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('audit export boundaries', () => {
  let app;
  let AuditLog;
  let Role;
  let Permission;
  let operator;
  let operatorToken;
  const stamp = `aeb${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    const wildcardPermission = await Permission.create({
      name: 'Audit export wildcard',
      code: '*:*',
      type: 'api',
      module: 'system',
    });
    const superRole = await Role.create({
      name: 'Audit export super role',
      code: `AEB_ROLE_${stamp}`,
      level: 10,
      isBuiltIn: true,
      permissions: [wildcardPermission._id],
    });
    operator = await require('../../models/User').create({
      username: `aeboperator${stamp}`,
      email: `aeboperator${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      roles: [superRole._id],
    });

    operatorToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await AuditLog.deleteMany({ username: `aebexport${stamp}` }).catch(() => {});
      await require('../../models/User')
        .deleteMany({
          username: `aeboperator${stamp}`,
        })
        .catch(() => {});
      await Role.deleteMany({ code: `AEB_ROLE_${stamp}` }).catch(() => {});
      await Permission.deleteOne({ code: '*:*' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('streams the CSV export with a safe manifest', async () => {
    const documents = Array.from({ length: 5 }, (_, index) => ({
      timestamp: new Date(Date.UTC(2026, 8, 8, 0, 0, index)),
      action: 'auth_login',
      username: index === 0 ? `=cmd|'/c calc'!A1` : `aebuser${stamp}`,
      ip: '192.168.1.10',
      path: '/audit-logs',
      statusCode: 200,
      success: true,
      riskLevel: 'low',
      category: 'auth',
    }));
    await AuditLog.insertMany(documents);

    const response = await request(app)
      .get('/api/security/audit-logs/export')
      .query({ action: 'auth_login' })
      .set('Authorization', `Bearer ${operatorToken}`);

    expect(response.status).toBe(200);
    expect(response.headers['x-audit-truncated']).toBeUndefined();
    expect(Number(response.headers['x-audit-manifest-records'])).toBeGreaterThanOrEqual(5);
    expect(response.text).toContain(`'=cmd|'/c calc'!A1`);
    expect(response.text).toContain('__MANIFEST__');
  });
});
