const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('audit log data scope', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  const stamp = `ads${Date.now().toString(36)}`;

  const makeUser = async ({ username, department, roleIds }) =>
    User.create({
      username,
      email: `${username}@example.com`,
      password: `Aa1!${stamp}Test`,
      department,
      roles: roleIds,
    });

  const makeToken = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

    const wildcard = await Permission.create({
      name: 'Audit data scope wildcard',
      code: '*:*',
      type: 'api',
      module: 'system',
    });
    const departmentRole = await Role.create({
      name: 'Audit department',
      code: `ADS_DEPT_${stamp.toUpperCase()}`,
      level: 7,
      permissions: [wildcard._id],
    });
    const selfRole = await Role.create({
      name: 'Audit self',
      code: `ADS_SELF_${stamp.toUpperCase()}`,
      level: 4,
      permissions: [wildcard._id],
    });
    const guestRole = await Role.create({
      name: 'Audit guest',
      code: `ADS_GUEST_${stamp.toUpperCase()}`,
      level: 1,
      permissions: [wildcard._id],
    });

    const departmentOperator = await makeUser({
      username: `adsdept${stamp}`,
      department: 'A栋',
      roleIds: [departmentRole._id],
    });
    const selfOperator = await makeUser({
      username: `adsself${stamp}`,
      department: 'A栋',
      roleIds: [selfRole._id],
    });
    const guestOperator = await makeUser({
      username: `adsguest${stamp}`,
      department: 'A栋',
      roleIds: [guestRole._id],
    });
    const actorA = await makeUser({
      username: `adsactora${stamp}`,
      department: 'A栋',
      roleIds: [selfRole._id],
    });
    const actorB = await makeUser({
      username: `adsactorb${stamp}`,
      department: 'B栋',
      roleIds: [selfRole._id],
    });

    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      userId: actorA._id,
      username: actorA.username,
      ip: '127.0.0.1',
      success: true,
    });
    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      userId: actorB._id,
      username: actorB.username,
      ip: '127.0.0.1',
      success: true,
    });
    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      userId: selfOperator._id,
      username: selfOperator.username,
      ip: '127.0.0.1',
      success: true,
    });

    app = require('../../app').createApp();
    app.set('auditScopeUsers', {
      departmentOperator,
      selfOperator,
      guestOperator,
      actorA,
      actorB,
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const usernames = Object.values(app.get('auditScopeUsers') || {}).map(
        (user) => user.username
      );
      await AuditLog.deleteMany({ username: { $in: usernames } }).catch(() => {});
      await User.deleteMany({ username: { $regex: `^ads.*${stamp}$` } }).catch(() => {});
      await Role.deleteMany({ code: { $regex: `^ADS_.*_${stamp.toUpperCase()}$` } }).catch(
        () => {}
      );
      await Permission.deleteOne({ code: '*:*' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('department operators see only logs from their own department', async () => {
    const users = app.get('auditScopeUsers');
    const token = makeToken(users.departmentOperator);
    const res = await request(app)
      .get('/api/security/audit-logs?action=login_success&limit=20')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    const usernames = res.body.data.data.map((item) => item.username);
    expect(usernames).toContain(users.actorA.username);
    expect(usernames).toContain(users.selfOperator.username);
    expect(usernames).not.toContain(users.actorB.username);
  });

  test('self operators see only their own logs', async () => {
    const users = app.get('auditScopeUsers');
    const token = makeToken(users.selfOperator);
    const res = await request(app)
      .get('/api/security/audit-logs?action=login_success&limit=20')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data.data.map((item) => item.username)).toEqual([users.selfOperator.username]);
  });

  test('guests get an explicitly empty audit page', async () => {
    const users = app.get('auditScopeUsers');
    const token = makeToken(users.guestOperator);
    const res = await request(app)
      .get('/api/security/audit-logs?action=login_success&limit=20')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data.data).toEqual([]);
  });

  test('export applies the same department boundary', async () => {
    const users = app.get('auditScopeUsers');
    const token = makeToken(users.departmentOperator);
    const res = await request(app)
      .get('/api/security/audit-logs/export?action=login_success')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.text).toContain(users.actorA.username);
    expect(res.text).toContain(users.selfOperator.username);
    expect(res.text).not.toContain(users.actorB.username);
  });
});
