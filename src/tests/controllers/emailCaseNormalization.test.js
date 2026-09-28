'use strict';

/**
 * 邮箱大小写：比对、查重、落库必须是同一个形态
 *
 * 两条更新链（`PUT /api/auth/profile`、`PUT /api/users/:id`）都没有 `.normalizeEmail()`
 * （只有注册链有）。实测出的真实缺陷不是"撞唯一索引变 500/通用 400"——
 * Mongoose 会把 schema 的 `lowercase` setter 同时作用于查询条件，所以大写形态的
 * **查重照样命中**（第 1、2 条用例在变异体下也是绿的，这一点是我用变异实测纠正的）。
 *
 * 真实缺陷在**比对**那一格：`email !== user.email` 是普通 JS 比较，吃内存里的原样串。
 * 于是用户提交"自己邮箱的大写形态"时 —— 比对判定"换了个邮箱" → 查重（经 setter 规范化后）
 * 命中的正是自己 → 回 `EMAIL_TAKEN`：**改自己的资料被告知邮箱已被他人占用**。
 * 第 3 条用例钉的就是这一格，也是 `normalizeEmailKey` 唯一的行为差异点。
 *
 * 第 4 条是管理员路径的对应格子（那里 `_id:{$ne}` 把自撞挡掉了，故它在变异体下也应为绿
 * —— 记在这里是为了说明"这条不区分修复前后"，别把它当成修复证据）。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `ecz${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

describe('邮箱大小写规范化：比对、查重、落库同形态', () => {
  let app;
  let User;
  let opToken;
  let dupId; // 已拥有 dup 邮箱的用户
  let otherId; // 未占用该邮箱的用户（全文件只读，见下方 freeId 的注释）
  let freeId; // 专供"改成未被占用的邮箱"那条用例使用
  const tokens = new Map();

  const sign = (u) =>
    jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: u.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let role = await Role.findOne({ code: `${stamp}_ALL` });
    if (!role) {
      role = await Role.create({
        name: `${stamp} 全量`,
        code: `${stamp}_ALL`,
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const op = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}_op@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    opToken = sign(op);
    const dup = await User.create({
      username: `${stamp}_dup`,
      email: `dup${stamp}@example.com`,
      password: PASSWORD,
    });
    const other = await User.create({
      username: `${stamp}_oth`,
      email: `other${stamp}@example.com`,
      password: PASSWORD,
    });
    dupId = String(dup._id);
    otherId = String(other._id);
    tokens.set(dupId, sign(dup));
    tokens.set(otherId, sign(other));

    // "改成未被占用的邮箱"这条会**真的改写**被操作账号的邮箱，所以它必须有专用样本：
    // 原先它复用 otherId（前两条用例都断言"other 的邮箱未被改写"），于是这两条与它
    // 之间构成隐式顺序前提 —— --randomize 把它排到前面时，前两条就红在
    // emailOf(otherId) 读到了 free 形态（F-112 同一类：用例之间通过库传递状态）。
    const free = await User.create({
      username: `${stamp}_free`,
      email: `occupied${stamp}@example.com`,
      password: PASSWORD,
    });
    freeId = String(free._id);
    tokens.set(freeId, sign(free));

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const emailOf = async (id) => (await User.findById(id).lean()).email;

  test('本人资料：撞他人邮箱的大写形态 ⇒ 专属码 EMAIL_TAKEN', async () => {
    const taken = await emailOf(dupId);
    const res = await request(app)
      .put('/api/auth/profile')
      .set('Authorization', `Bearer ${tokens.get(otherId)}`)
      .send({ email: taken.toUpperCase() });

    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('EMAIL_TAKEN');
    expect(await emailOf(otherId)).toBe(`other${stamp}@example.com`);
  });

  test('管理员改他人：撞他人邮箱 ⇒ 专属码 EMAIL_TAKEN_SHORT，目标邮箱未被改写', async () => {
    const taken = await emailOf(dupId);
    const res = await request(app)
      .put(`/api/users/${otherId}`)
      .set('Authorization', `Bearer ${opToken}`)
      .send({ email: taken.toUpperCase() });

    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('EMAIL_TAKEN_SHORT');
    expect(await emailOf(otherId)).toBe(`other${stamp}@example.com`);
  });

  test('修复点：本人提交"自己邮箱的大写形态" ⇒ 200，不得被判成已被他人占用', async () => {
    const own = await emailOf(dupId);
    const res = await request(app)
      .put('/api/auth/profile')
      .set('Authorization', `Bearer ${tokens.get(dupId)}`)
      .send({ email: own.toUpperCase() });

    expect(res.status).toBe(200);
    expect(await emailOf(dupId)).toBe(own);
  });

  test('管理员路径：把目标邮箱改回它自己的大写形态 ⇒ 200（`$ne` 早已挡住自撞）', async () => {
    const own = await emailOf(dupId);
    const res = await request(app)
      .put(`/api/users/${dupId}`)
      .set('Authorization', `Bearer ${opToken}`)
      .send({ email: own.toUpperCase() });

    expect(res.status).toBe(200);
    expect(await emailOf(dupId)).toBe(own);
  });

  test('反向前提：未被占用的大写邮箱 ⇒ 200 且落库为小写', async () => {
    const free = `FREE${stamp}@EXAMPLE.com`;
    expect(await emailOf(freeId)).toBe(`occupied${stamp}@example.com`); // 起点自证
    const res = await request(app)
      .put('/api/auth/profile')
      .set('Authorization', `Bearer ${tokens.get(freeId)}`)
      .send({ email: free });

    expect(res.status).toBe(200);
    expect(await emailOf(freeId)).toBe(`free${stamp}@example.com`);
  });
});
