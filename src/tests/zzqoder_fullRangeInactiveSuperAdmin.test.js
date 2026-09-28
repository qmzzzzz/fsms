/**
 * 全网段名单守卫只认「生效的内置超管」（回归 F-118）
 *
 * guardFullRangeCIDR（添加侧）与 removeIPEntry 的 P2-13 对称约束（删除侧）
 * 共用 operatorIsSuperAdmin()。该查询此前写作
 *   .populate('roles', 'code isBuiltIn')
 * 字符串形式的 populate **无法携带 match**，因此被停用（inactive）的
 * SUPER_ADMIN 仍会让判定为真——与本仓「只认生效角色」的口径不一致
 * （对照 auth.js buildAuthContext、rbac.js 回退查询、permissionHelper）。
 *
 * 接口侧改内置角色 status 被 roleGuards.js 的 BUILTIN_ROLE_STATUS_LOCKED 挡住，
 * 所以这里的危害前提是直连数据库改状态（SystemConfig 注释也承认运维有此习惯）。
 * 属纵深防御，但危害是全站级的：一旦误判为超管，即可加白 0.0.0.0/0
 * 让黑名单与限流整体失效，或拆掉超管配置的全网段白名单再塞恶意黑名单。
 *
 * 每条用例自己设定 SUPER_ADMIN 的 status 并自建自清名单条目：
 * CI 用 `jest --randomize` 打乱**文件内**用例顺序（ci.yml:106-114），
 * 依赖上一条用例的残留状态就是下一个偶发红。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('全网段名单守卫：停用超管不再等于超管', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let IPBlacklist;
  let superRole;
  let secRole;
  let operatorId;
  let token;

  const FULL_RANGE = '0.0.0.0/0';
  const stamp = Date.now();

  const setSuperStatus = (status) =>
    Role.findByIdAndUpdate(superRole._id, { $set: { status } }, { new: true });

  const seedPerm = async (code) =>
    Permission.findOneAndUpdate(
      { code },
      { $setOnInsert: { code, name: code, type: 'api', module: 'security' } },
      { upsert: true, new: true }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    IPBlacklist = require('../models/IPBlacklist');
    require('../models/TokenBlacklist');
    const { createApp } = require('../app');
    app = createApp();

    const [secConfig] = await Promise.all([seedPerm('security:config')]);

    // 内置超管角色：code 与 isBuiltIn 必须同时命中（utils/superAdmin.js）
    superRole = await Role.create({
      code: 'SUPER_ADMIN',
      name: '内置超级管理员',
      level: 10,
      isBuiltIn: true,
      permissions: [],
    });
    secRole = await Role.create({
      code: `FR_SEC_${stamp}`,
      name: '安全配置管理员',
      level: 6,
      permissions: [secConfig._id],
    });

    const operator = await User.create({
      username: `fr_op_${stamp}`,
      email: `fr_op_${stamp}@example.com`,
      password: 'Qz7#Lm42vTx9',
      // 同时持有（可能已停用的）超管与一个生效的 security:config 角色：
      // 后者保证请求能过 checkPermission，从而真正走到本守卫
      roles: [superRole._id, secRole._id],
    });
    operatorId = String(operator._id);
    token = jwt.sign(
      { userId: operatorId, username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await IPBlacklist.deleteMany({ ip: FULL_RANGE }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  afterEach(async () => {
    await IPBlacklist.deleteMany({ ip: FULL_RANGE });
  });

  // 落库的条目一律用 white：全网段 black 一旦写入，security 中间件会立刻把
  // 发起请求的自己（127.0.0.1）判为封禁，后续用例拿到的是 IP_BLOCKED 而不是
  // 本守卫的 FULL_RANGE_FORBIDDEN——实测过。这正是 ipListController 注释里
  // 「加黑导致全站拒服且管理员自己也无法登录解除」那句话的可执行版本。
  // 被拒侧仍用 black（不会落库，因此无副作用）。
  const addFullRange = (type = 'white') =>
    request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${token}`)
      .send({ ip: FULL_RANGE, type, reason: 'guard-probe' });

  test('前置自证：操作者确实持有内置超管，且请求确实能过权限层（防假绿）', async () => {
    expect(superRole.isBuiltIn).toBe(true);
    expect(superRole.code).toBe('SUPER_ADMIN');

    await setSuperStatus('active');
    const res = await addFullRange();
    // 生效超管必须放行：否则后面所有「被拒」断言都可能只是"守卫无条件拒绝"
    expect(res.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE, type: 'white' })).toBe(1);
  });

  test('添加侧：SUPER_ADMIN 停用后不得再添加全网段（403 且不留条目）', async () => {
    await setSuperStatus('inactive');

    const res = await addFullRange();

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);
  });

  test('删除侧：全网段条目存在时，停用超管不得将其移除（P2-13 对称约束）', async () => {
    await setSuperStatus('active');
    expect((await addFullRange()).status).toBe(200);
    const entry = await IPBlacklist.findOne({ ip: FULL_RANGE, type: 'white' });
    expect(entry).toBeTruthy();

    await setSuperStatus('inactive');
    const res = await request(app)
      .delete(`/api/security/ip-list/${entry._id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
    // 被拒必须是"仍在"，而不是"被删了但返回 403"
    expect(await IPBlacklist.countDocuments({ _id: entry._id })).toBe(1);
  });

  test('反向对照：同一个操作者在超管生效时可删除该条目', async () => {
    await setSuperStatus('active');
    expect((await addFullRange()).status).toBe(200);
    const entry = await IPBlacklist.findOne({ ip: FULL_RANGE, type: 'white' });

    const res = await request(app)
      .delete(`/api/security/ip-list/${entry._id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ _id: entry._id })).toBe(0);
  });

  test('非超管（无 SUPER_ADMIN 角色）添加全网段仍被拒：本修复未放宽原有收口', async () => {
    const plain = await User.create({
      username: `fr_plain_${stamp}`,
      email: `fr_plain_${stamp}@example.com`,
      password: 'Qz7#Lm42vTx9',
      roles: [secRole._id],
    });
    await setSuperStatus('active');

    const res = await request(app)
      .post('/api/security/ip-list')
      .set(
        'Authorization',
        `Bearer ${jwt.sign(
          { userId: String(plain._id), username: plain.username, tokenVersion: 0 },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        )}`
      )
      .send({ ip: FULL_RANGE, type: 'black', reason: 'guard-probe' });

    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
  });

  test('对照：普通网段不受该守卫约束（停用超管也仍能加黑单个 IP）', async () => {
    await setSuperStatus('inactive');

    const res = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${token}`)
      .send({ ip: '203.0.113.77', type: 'black', reason: 'guard-probe' });

    expect(res.status).toBe(200);
    await IPBlacklist.deleteMany({ ip: '203.0.113.77' });
  });

  test('前提自证：本文件的操作者 operatorId 与守卫查询的是同一个用户', async () => {
    const me = await User.findById(operatorId).select('roles').lean();
    expect(me.roles.map(String)).toContain(String(superRole._id));
  });
});
