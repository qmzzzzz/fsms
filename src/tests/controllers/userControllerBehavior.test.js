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
  let adminToken;
  let guestRole;
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
      { expiresIn: '24h' }
    );

    // 高权限操作者：数据范围 all + 权限子集足够，用于覆盖密文建号成功路径与写后回滚
    const adminRole = await Role.create({
      name: 'User behavior admin',
      code: `UCB_ADMIN_${stamp}`,
      level: 9,
      permissions: [readPermission._id, createPermission._id],
    });
    guestRole = await Role.create({
      name: 'User behavior guest',
      code: `UCB_GUEST_${stamp}`,
      level: 1,
      permissions: [readPermission._id],
    });
    const admin = await User.create({
      username: `ucbadmin${stamp}`,
      email: `ucbadmin${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      department: 'UCB-DEPT',
      roles: [adminRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({
        username: {
          $in: [
            `ucboperator${stamp}`,
            `ucbadmin${stamp}`,
            `ucbtarget${stamp}`,
            `ucbenctarget${stamp}`,
            `ucbrollback${stamp}`,
            `ucbpermrollback${stamp}`,
          ],
        },
      }).catch(() => {});
      await Role.deleteMany({
        code: { $in: [`UCB_ROLE_${stamp}`, `UCB_ADMIN_${stamp}`, `UCB_GUEST_${stamp}`] },
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = (method, url) =>
    request(app)[method](url).set('Authorization', `Bearer ${operatorToken}`);

  test('denies user-list data scope with 403 DATA_SCOPE_DENIED', async () => {
    // 夹具角色 level 3 < LEVEL_SELF(4) ⇒ 数据范围 {type:'none'}。
    // #12 之前这里是 200 + 空页；之后一律 403 + errorCode：空页让调用方分不清
    // 「没有用户」与「这个账号没有可见范围」，而这两件事的后续动作相反。
    const res = await authed('get', '/api/users?page=1&limit=10');
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.errors.errorCode).toBe('DATA_SCOPE_DENIED');
  });

  test('validates password strength after decrypting the credential', async () => {
    const encPassword = await buildLoginEnvelope('weak', { aad: 'user:create' });
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

  describe('密文建号成功路径与写后回滚', () => {
    const userService = require('../../services/userService');
    const adminCall = (method, url) =>
      request(app)[method](url).set('Authorization', `Bearer ${adminToken}`);
    const PASSWORD_VALUE = 'N3w-Strong-Pass!';

    afterEach(() => jest.restoreAllMocks());

    test('合法密文口令解密并完成建号（201，落库口令即解密结果）', async () => {
      const username = `ucbenctarget${stamp}`;
      const encPassword = await buildLoginEnvelope(PASSWORD_VALUE, { aad: 'user:create' });

      const res = await adminCall('post', '/api/users').send({
        username,
        email: `${username}@example.com`,
        encPassword,
      });

      expect(res.status).toBe(201);
      const created = await User.findByUsername(username).select('+password');
      expect(await created.comparePassword(PASSWORD_VALUE)).toBe(true);
    });

    test('建号后角色被抬高 ⇒ 撤销新账户（TOCTOU 回滚）', async () => {
      const username = `ucbrollback${stamp}`;
      const encPassword = await buildLoginEnvelope(PASSWORD_VALUE, { aad: 'user:create' });
      const original = userService.findRolesByIds.bind(userService);
      jest.spyOn(userService, 'findRolesByIds').mockImplementation((...args) => {
        // 建号路径只有写后复验会按 'level code permissions' 读取
        if (args[1] === 'level code permissions') {
          return Promise.resolve([{ ...guestRole.toObject(), level: 11 }]);
        }
        return original(...args);
      });

      const res = await adminCall('post', '/api/users').send({
        username,
        email: `${username}@example.com`,
        encPassword,
        roles: [String(guestRole._id)],
      });

      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN');
      expect(await User.findByUsername(username)).toBeNull();
    });

    test('建号后角色权限被扩张 ⇒ 撤销新账户并回传缺失权限', async () => {
      const username = `ucbpermrollback${stamp}`;
      const encPassword = await buildLoginEnvelope(PASSWORD_VALUE, { aad: 'user:create' });
      const original = userService.findRolesByIds.bind(userService);
      jest.spyOn(userService, 'findRolesByIds').mockImplementation((...args) => {
        if (args[1] === 'level code permissions') {
          return Promise.resolve([
            {
              ...guestRole.toObject(),
              permissions: [{ _id: 'perm-x', code: 'security:config' }],
            },
          ]);
        }
        return original(...args);
      });

      const res = await adminCall('post', '/api/users').send({
        username,
        email: `${username}@example.com`,
        encPassword,
        roles: [String(guestRole._id)],
      });

      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('PERMISSION_GRANT_FORBIDDEN');
      expect(res.body.errors.permissions).toContain('security:config');
      expect(await User.findByUsername(username)).toBeNull();
    });
  });
});
