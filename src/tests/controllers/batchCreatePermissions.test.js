/**
 * 批量创建权限写入路径测试（报告 O-2：逐条 create → insertMany(ordered:false)）
 *
 * 覆盖批量接口的功能语义保持：新增条目一次落库、已存在条目进 skipped、
 * 悬空父引用进 skipped、响应结构（created/skipped/details）不变。
 * 采用 upsert 播种 `*:*` 权限（unique 索引，与其他套件并行兼容）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('batchCreatePermissions 批量写入（O-2）', () => {
  let app;
  let Permission;
  let adminToken;
  // Permission.code 正则约束 module/action 段仅小写字母（[a-z]+）：
  // 唯一性 stamp 必须纯字母，掺入数字会被路由校验器 400
  const stamp = `o${Math.random().toString(36).slice(2, 10).replace(/\d/g, 'x')}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const User = require('../../models/User');
    const Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_批量权限',
      code: `SUPER_ADMIN_O2_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `o2_admin_${stamp}`,
      email: `o2_admin_${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });

    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      // 清理本套件播种的数据（按 stamp 前缀定向删除，不影响其他套件）
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `o2_admin_${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_O2_${stamp}` }).catch(() => {});
      await Permission.deleteMany({ code: { $in: [`${stamp}:alpha`, `${stamp}:beta`] } }).catch(
        () => {}
      );
      await mongoose.connection.close();
    }
  });

  test('混合批次：新增 1 条落库，已存在与悬空父引用各进 skipped，响应结构不变', async () => {
    // 预置一条已存在权限，用于「已存在」skip 分支
    await Permission.create({
      name: '已存在',
      code: `${stamp}:alpha`,
      type: 'api',
      module: 'test',
    });

    const res = await request(app)
      .post('/api/permissions/batch')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        permissions: [
          { name: '批量新增', code: `${stamp}:beta`, type: 'api', module: 'test' },
          { name: '重复', code: `${stamp}:alpha`, type: 'api', module: 'test' },
          {
            name: '悬空父级',
            code: `${stamp}:gamma`,
            type: 'api',
            module: 'test',
            parent: String(new mongoose.Types.ObjectId()),
          },
        ],
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.created).toBe(1);
    const skippedCodes = Object.fromEntries(res.body.data.skipped.map((s) => [s.code, s.reason]));
    expect(skippedCodes[`${stamp}:alpha`]).toBe('已存在');
    expect(skippedCodes[`${stamp}:gamma`]).toBe('父级权限不存在');
    // details 为落库文档（批量写入语义与原逐条 create 一致）
    expect(res.body.data.details).toHaveLength(1);
    expect(res.body.data.details[0].code).toBe(`${stamp}:beta`);
    // 落库确认
    const saved = await Permission.findOne({ code: `${stamp}:beta` }).lean();
    expect(saved).toBeTruthy();
  });

  test('重复提交：已落库的 code 走预检 skip，不产生重复文档', async () => {
    const res = await request(app)
      .post('/api/permissions/batch')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        permissions: [{ name: '批量新增', code: `${stamp}:beta`, type: 'api', module: 'test' }],
      });

    expect(res.status).toBe(200);
    expect(res.body.data.created).toBe(0);
    expect(res.body.data.skipped).toHaveLength(1);

    const docs = await Permission.countDocuments({ code: `${stamp}:beta` });
    expect(docs).toBe(1);
  });

  test('空数组 / 非数组载荷被路由校验拒绝（400）', async () => {
    const empty = await request(app)
      .post('/api/permissions/batch')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ permissions: [] });
    expect(empty.status).toBe(400);

    const notArray = await request(app)
      .post('/api/permissions/batch')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ permissions: 'nope' });
    expect(notArray.status).toBe(400);
  });
});
