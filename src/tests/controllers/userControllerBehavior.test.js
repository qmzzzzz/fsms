const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { buildLoginEnvelope } = require('../helpers/buildLoginEnvelope');
const userController = require('../../controllers/userController');

describe('userController data scope and encrypted credentials', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let operator;
  let operatorToken;
  const stamp = `ucb${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    const readPermission = await Permission.findOneAndUpdate(
      { code: 'user:read' },
      { $setOnInsert: { name: 'User read', code: 'user:read', type: 'api', module: 'user' } },
      { upsert: true, new: true }
    );
    const createPermission = await Permission.findOneAndUpdate(
      { code: 'user:create' },
      { $setOnInsert: { name: 'User create', code: 'user:create', type: 'api', module: 'user' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: 'User behavior operator',
      code: `UCB_ROLE_${stamp}`,
      level: 3,
      permissions: [readPermission._id, createPermission._id],
    });
    operator = await User.create({
      username: `ucboperator${stamp}`,
      email: `ucboperator${stamp}@example.com`,
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
      await User.deleteMany({
        username: { $in: [`ucboperator${stamp}`, `ucbtarget${stamp}`] },
      }).catch(() => {});
      await Role.deleteOne({ code: `UCB_ROLE_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = (method, url) =>
    request(app)[method](url).set('Authorization', `Bearer ${operatorToken}`);

  test('denies user-list data scope with an explicit empty page', async () => {
    const res = await authed('get', '/api/users?page=1&limit=10');
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual([]);
    expect(res.body.pagination.total).toBe(0);
  });

  test('validates password strength after decrypting the credential', async () => {
    const encPassword = await buildLoginEnvelope('weak');
    const res = await authed('post', '/api/users').send({
      username: `ucbtarget${stamp}`,
      email: `ucbtarget${stamp}@example.com`,
      encPassword,
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('translates an unreadable encrypted credential into a coded response', async () => {
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    await userController.createUser(
      {
        body: { username: `ucbtarget${stamp}`, encPassword: 'invalid-envelope' },
        user: { userId: String(operator._id), username: operator.username },
        ip: '127.0.0.1',
        get: () => 'jest',
      },
      res,
      () => {}
    );
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        errors: expect.objectContaining({ errorCode: 'AUTH_ENCRYPTED_CREDENTIAL_INVALID' }),
      })
    );
  });
});
