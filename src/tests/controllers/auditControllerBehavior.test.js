const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('auditController endpoint behavior', () => {
  let app;
  let Role;
  let Permission;
  let operator;
  let operatorToken;
  const stamp = `acb${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    const wildcard = await Permission.create({
      name: 'Audit controller wildcard',
      code: '*:*',
      type: 'api',
      module: 'system',
    });
    const role = await Role.create({
      name: 'Audit controller operator',
      code: `ACB_ROLE_${stamp}`,
      level: 10,
      isBuiltIn: true,
      permissions: [wildcard._id],
    });
    operator = await require('../../models/User').create({
      username: `acboperator${stamp}`,
      email: `acboperator${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      roles: [role._id],
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
      await require('../../models/User')
        .deleteMany({ username: `acboperator${stamp}` })
        .catch(() => {});
      await Role.deleteOne({ code: `ACB_ROLE_${stamp}` }).catch(() => {});
      await Permission.deleteOne({ code: '*:*' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = (url) => request(app).get(url).set('Authorization', `Bearer ${operatorToken}`);

  test('returns an explicit empty offset page for an unmatched filter', async () => {
    const res = await authed(`/api/security/audit-logs?username=does-not-exist-${stamp}&limit=10`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.data).toEqual([]);
    expect(res.body.data.meta).toMatchObject({ total: 0, totalPages: 0 });
  });

  test('rejects invalid integrity-verification parameters before querying', async () => {
    const badLimit = await authed('/api/security/audit-logs/verify?limit=latest');
    expect(badLimit.status).toBe(400);
    expect(badLimit.body.message).toContain('limit');

    const badFrom = await authed('/api/security/audit-logs/verify?from=newest');
    expect(badFrom.status).toBe(400);
    expect(badFrom.body.message).toContain('from');
  });

  test('returns the integrity report from the runtime endpoint', async () => {
    const res = await authed('/api/security/audit-logs/verify?limit=20&from=earliest');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toMatchObject({ intact: expect.any(Boolean) });
    expect(res.body.data.byType).toEqual(
      expect.objectContaining({
        hash_mismatch: expect.any(Number),
        hmac_missing: expect.any(Number),
        hmac_mismatch: expect.any(Number),
        chain_break: expect.any(Number),
      })
    );
  });
});
