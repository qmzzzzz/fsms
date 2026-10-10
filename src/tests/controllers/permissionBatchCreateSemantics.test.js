/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：权限批量创建接口（O-2：逐条 create → insertMany(ordered:false)）
 * 守护的不变式：一次落库、已存在条目进 skipped、悬空父引用进 skipped、响应结构（created/skipped/details）不变
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `batchCreatePermissions.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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
      { expiresIn: '24h' }
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
    // 自包含前置：清掉本批次两个 code 的可能残留，再显式预置「已存在」
    // （仅预置 alpha 时，随机顺序下本用例可能先于「重复提交」运行并写入
    //  beta，使「重复提交」用例的预检 skip 分支落空、created 由 0 变 1）
    await Permission.deleteMany({ code: { $in: [`${stamp}:alpha`, `${stamp}:beta`] } });
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
    // 自包含前置：原实现依赖「混合批次」用例先把 beta 写库，
    // 随机顺序下本用例可能先执行，预检查不到 beta 于是真的创建（created 期望 0 实得 1）
    await Permission.deleteMany({ code: `${stamp}:beta` });
    await Permission.create({
      name: '批量新增',
      code: `${stamp}:beta`,
      type: 'api',
      module: 'test',
    });

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
    // 断言被拒的是 permissions 字段本身（校验明细透传），而非别的 400
    expect(empty.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(empty.body.errors.fieldErrors[0].path).toBe('permissions');

    const notArray = await request(app)
      .post('/api/permissions/batch')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ permissions: 'nope' });
    expect(notArray.status).toBe(400);
    expect(notArray.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(notArray.body.errors.fieldErrors[0].path).toBe('permissions');
  });
});
