const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

/**
 * 回归：createUser 必须与 updateUser 同口径执行 P0-1 数据范围校验。
 *
 * department 是「数据范围决定字段」：新建账户落入该部门后按自身部门可见数据。
 * 旧实现只有 updateUser 有闸（userController.js:590），createUser 直接把
 * req.body.department 交给 userService.createUser，零范围推理 →
 * department 域管理员可在域外安插一个自己持口令、可读该域数据的账号（绕道）。
 *
 * 本测钉死：
 *  - 东区(level8/department)管理员建 总部 用户 → 403 USER_SCOPE_FIELD_FORBIDDEN 且未落库；
 *  - 建本部门(东区)用户 → 201（不误伤合法维护）；
 *  - 不传 department → 201（新账号无部门，不产生跨域可见性）。
 * pre-fix（无闸）：三条都会 201 → 用例①红；post-fix：①绿。
 */

describe('createUser 数据范围闸（P0-1 建号补齐）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let token;
  const stamp = `cug${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    app = require('../../app').createApp();

    const pCreate = await Permission.findOneAndUpdate(
      { code: 'user:create' },
      { $setOnInsert: { name: '建用户', code: 'user:create', type: 'api', module: 'user' } },
      { upsert: true, new: true }
    );
    const mgrRole = await Role.create({
      name: `建号主管_${stamp}`,
      code: `CUG_MGR_${stamp}`,
      level: 8,
      status: 'active',
      permissions: [pCreate._id],
    });
    const mgr = await User.create({
      username: `cmgr${stamp}`,
      email: `cmgr${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '东区',
      roles: [mgrRole._id],
      tokenVersion: 0,
    });
    token = jwt.sign(
      {
        userId: String(mgr._id),
        username: mgr.username,
        email: mgr.email,
        roles: [`CUG_MGR_${stamp}`],
        tokenVersion: 0,
        jti: 'j',
        sid: null,
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    const rx = new RegExp(stamp);
    await User.deleteMany({ username: rx }).catch(() => {});
    await Role.deleteMany({ code: rx }).catch(() => {});
    if (mongoose.connection.readyState === 1) await mongoose.connection.close();
  });

  test('在操作者数据范围外(总部)建号被拒，且账号未落库', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${token}`)
      .send({
        username: `cvictim${stamp}`,
        email: `cvictim${stamp}@example.com`,
        password: randomPassword(),
        department: '总部',
      });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FIELD_FORBIDDEN');
    expect(await User.countDocuments({ username: `cvictim${stamp}` })).toBe(0);
  });

  test('在本部门(东区)建号仍放行（闸只拦域外，不误伤合法维护）', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${token}`)
      .send({
        username: `cos${stamp}`,
        email: `cos${stamp}@example.com`,
        password: randomPassword(),
        department: '东区',
      });
    expect(res.status).toBe(201);
    expect(res.body.data.department).toBe('东区');
  });

  test('不带 department 建号放行（无部门即不产生跨域可见性）', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${token}`)
      .send({
        username: `cnodept${stamp}`,
        email: `cnodept${stamp}@example.com`,
        password: randomPassword(),
      });
    expect(res.status).toBe(201);
  });
});
