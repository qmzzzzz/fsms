/**
 * getUserStats 的 self 数据范围必须真正命中（aggregate-cast 回归）
 *
 * 缺陷形态：`Model.aggregate([{$match: ...}])` 不做 schema cast。self 范围下
 * buildDataScopeFilter 产出 `{createdBy: '<JWT 字符串 id>'}`，而 User.createdBy 是 ObjectId，
 * 于是聚合零匹配 → self 域用户的统计面板恒为 0；列表走 find() 会 cast，出现
 * "列表看得到自己建的账号、看板却是 0" 的自相矛盾（数据可见性/正确性缺陷）。
 *
 * 本用例是**可证伪**的：
 *   - 未 cast → total=0 → 红；
 *   - cast 方向错（例如误放行全部）→ total>1 → 红（夹具里塞了一条他人建的账号）。
 * 只有"精确命中本人创建的那一条"才绿。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('getUserStats self 范围 aggregate cast', () => {
  let app;
  let User;
  let Role;
  let Permission;

  const stamp = `usc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  let operatorToken;
  let operatorId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const userReadPerm = await Permission.findOneAndUpdate(
      { code: 'user:read' },
      { $setOnInsert: { name: '读取用户', code: 'user:read', type: 'api', module: 'user' } },
      { upsert: true, new: true }
    );

    const selfRole = await Role.create({
      name: `自查统计_${stamp}`,
      code: `USC_SELF_${stamp.toUpperCase()}`,
      // getDataScope 按角色 level 推导数据范围：>=4 且 <7 → self 档。
      // （role.dataScope 字段不参与 getDataScope 的判定，这里靠 level 落到 self。）
      level: 4,
      isBuiltIn: false,
      permissions: [userReadPerm._id],
    });

    const operator = await User.create({
      username: `uscop${stamp}`,
      email: `uscop${stamp}@example.com`,
      password: PASSWORD,
      roles: [selfRole._id],
    });
    operatorId = String(operator._id);
    operatorToken = jwt.sign(
      { userId: operatorId, username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 本人创建的账号（self 范围应命中这一条）
    await User.create({
      username: `uscmine${stamp}`,
      email: `uscmine${stamp}@example.com`,
      password: PASSWORD,
      roles: [selfRole._id],
      createdBy: operator._id,
    });
    // 他人创建的账号（不得计入本人 self 统计，用于证伪"误放行全部"）
    await User.create({
      username: `uscother${stamp}`,
      email: `uscother${stamp}@example.com`,
      password: PASSWORD,
      roles: [selfRole._id],
      createdBy: new mongoose.Types.ObjectId(),
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('self 域操作员统计精确命中自己创建的那一条（既非 0、也非全量）', async () => {
    const res = await request(app)
      .get('/api/users/stats')
      .set('Authorization', `Bearer ${operatorToken}`);

    expect(res.status).toBe(200);
    // 未 cast → 0（红）；cast 错误地放行全部 → >1（红）。正确：恰为 1。
    expect(res.body.data.total).toBe(1);
    // 分组维度同样不得为空集假绿
    expect(res.body.data.byRole.length).toBeGreaterThan(0);
  });
});
