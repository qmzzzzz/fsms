'use strict';

/**
 * 「引用数组元素」与「备注类自由文本」的路由边界（三条写路径）
 *   · PUT  /api/inspections/:id/cancel      —— reason
 *   · POST /api/roles                       —— permissions / permissions.*
 *   · PUT  /api/roles/:id/permissions        —— permissions 条数
 *   · POST /api/users  + PUT /api/users/:id/roles —— roles / roles.*
 *
 * 两条根因，与 view-sensitive / users-lock 那一对完全同族：
 *
 * (1) 数组只判「是不是数组」，元素格式与条数都不设防。
 *     `roles:['zz']` / `permissions:['zz']` 直达服务层的
 *     `Role.find({_id:{$in:['zz']}})` / `Permission.find({_id:{$in:['zz']}})`，
 *     抛 CastError 后由 errorHandler 回「资源 ID 格式无效」且 errors 为 null——
 *     提交者写的字段名叫 roles，回显里一个 "roles" 都找不到。超管轨还跳过那次
 *     存在性查询，非法元素直达 `Role.create`/`User.create` 的 [ObjectId] 数组。
 *
 * (2) 上限声明写在 schema 里，更新路径却不跑校验器。
 *     Inspection.executionLog[].remark 有 maxlength: 500（models/Inspection.js:149-152），
 *     取消走 findOneAndUpdate ⇒ 默认不校验，超长值原样入库；该数组另有 `$slice`
 *     尾部封顶，只裁条数不裁长度，于是"一次写入"变成"这条巡检永久卡死"
 *     （文档顶到 16MB 后连保存都做不了）。路由层是这条路上唯一的收口点。
 *
 * 判据共用同一把尺：400 必须由路由给出且 errors.fieldErrors 点名该字段
 * （validationResult 的结果一定带 path；DB 层泄漏过来的 VALIDATION_FAILED 在非
 * development 下 fieldErrors 被抹掉，CastError 更是只剩一句话），
 * 并且每个拒绝用例都回读数据库确认「什么都没写」。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `rab${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();
// 与 models/Inspection.js executionLog[].remark 的 maxlength 同值
const REMARK_MAX = 500;
// Role.code 的形状是 ^[A-Z_]+$（routes/roleRoutes.js:35），stamp 含数字映射出的
// 小写字母，必须整体大写；否则创建请求会先被"角色编码"那条规则拒掉，
// 让 5/7 两个负向用例因为别的原因变绿（假绿）。
const roleCode = (suffix) => `${stamp}${suffix}`.toUpperCase();

describe('写路径的引用数组与自由文本边界', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let Inspection;
  let superToken;
  let superId;

  const paths = (res) => (res.body?.errors?.fieldErrors || []).map((e) => e.path);

  const auth = (token) => ({ Authorization: `Bearer ${token}` });

  const tokenFor = (userId, username) =>
    jwt.sign({ userId: String(userId), username, tokenVersion: 0 }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    Inspection = require('../../models/Inspection');
    require('../../models/TokenBlacklist');
    require('../../models/FireDevice');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const operator = await User.create({
      username: `${stamp}op`,
      email: `${stamp}op@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superId = String(operator._id);
    superToken = tokenFor(operator._id, operator.username);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`^${stamp}`) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  /** 建一条 pending 巡检（直接走模型，绕开创建接口的表单形状） */
  const makeInspection = async (label) =>
    Inspection.create({
      title: `${stamp}insp${label}`,
      inspectionType: 'daily',
      planStartTime: new Date(Date.now() - 3600_000),
      planEndTime: new Date(Date.now() + 3600_000),
      createdBy: superId,
    });

  const remarks = async (id) => {
    const doc = await Inspection.findById(id).lean();
    return (doc?.executionLog || []).map((e) => String(e.remark ?? ''));
  };

  const cancel = (id, body) =>
    request(app).put(`/api/inspections/${id}/cancel`).set(auth(superToken)).send(body);

  describe('PUT /inspections/:id/cancel 的 reason', () => {
    test('1 超长 reason 必须在路由层被点名，且不得留下任何留痕', async () => {
      const insp = await makeInspection('long');
      const res = await cancel(insp._id, { reason: 'x'.repeat(REMARK_MAX + 1) });

      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(paths(res)).toContain('reason');

      const doc = await Inspection.findById(insp._id).lean();
      expect(doc.status).toBe('pending');
      expect(await remarks(insp._id)).toEqual([]);
    });

    test('2 反向对照：恰好 500 字必须放行并逐字进入 executionLog', async () => {
      const insp = await makeInspection('edge');
      const reason = 'y'.repeat(REMARK_MAX);
      const res = await cancel(insp._id, { reason });

      expect(res.status).toBe(200);
      const log = await remarks(insp._id);
      expect(log).toHaveLength(1);
      expect(log[0]).toBe(reason);
    });

    test('3 非字符串 reason 不得被 stringify 成 [object Object] 入库', async () => {
      const insp = await makeInspection('obj');
      const res = await cancel(insp._id, { reason: { nested: 'x' } });

      expect(res.status).toBe(400);
      expect(paths(res)).toContain('reason');
      expect(await remarks(insp._id)).toEqual([]);
    });

    test('4 不传 reason 的取消仍然正常，默认文案不变（新闸只管类型与长度）', async () => {
      const insp = await makeInspection('none');
      const res = await cancel(insp._id, {});

      expect(res.status).toBe(200);
      const log = await remarks(insp._id);
      expect(log).toEqual(['取消巡检']);
    });
  });

  describe('POST /roles 与 PUT /roles/:id/permissions 的 permissions', () => {
    test('5 非法权限 ID：400 点名 permissions[0]，且角色行不得存在', async () => {
      const res = await request(app)
        .post('/api/roles')
        .set(auth(superToken))
        .send({ name: `${stamp}坏权限`, code: roleCode('BADP'), permissions: ['zz'] });

      expect(res.status).toBe(400);
      expect(paths(res)).toContain('permissions[0]');
      // 排除假绿：这次 400 必须只因为 permissions，而不是 name/code 形状不对
      expect(paths(res)).toEqual(['permissions[0]']);
      expect(await Role.countDocuments({ code: roleCode('BADP') })).toBe(0);
    });

    test('6 反向对照：合法权限 ID 数组逐条落库（新闸不得多吃）', async () => {
      // Permission.code 的形状是 /^(\*|[a-z]+):(\*|[a-z_]+)$/（models/Permission.js:23），
      // stamp 里的数字已整体映射成字母，可直接作 module 段
      const p1 = await Permission.create({
        name: `${stamp}权限一`,
        code: `${stamp}:read`,
        type: 'api',
        module: 'test',
      });
      const p2 = await Permission.create({
        name: `${stamp}权限二`,
        code: `${stamp}:write`,
        type: 'api',
        module: 'test',
      });
      const res = await request(app)
        .post('/api/roles')
        .set(auth(superToken))
        .send({
          name: `${stamp}合法权限`,
          code: roleCode('GOOD'),
          permissions: [String(p1._id), String(p2._id)],
        });

      expect(res.status).toBe(201);
      const created = await Role.findOne({ code: roleCode('GOOD') }).lean();
      expect(created.permissions.map(String).sort()).toEqual(
        [String(p1._id), String(p2._id)].sort()
      );
    });

    test('7 条数上界：501 项在路由层拒绝，不打进 $in 查询', async () => {
      const fake = Array.from({ length: 501 }, () => String(new mongoose.Types.ObjectId()));
      const res = await request(app)
        .post('/api/roles')
        .set(auth(superToken))
        .send({ name: `${stamp}超大`, code: roleCode('BIG'), permissions: fake });

      expect(res.status).toBe(400);
      expect(paths(res)).toEqual(['permissions']);
      expect(await Role.countDocuments({ code: roleCode('BIG') })).toBe(0);
    });

    test('8 整表替换端点同口径：非法元素 400 且原有权限表保持不变', async () => {
      const role = await Role.create({
        name: `${stamp}待替换`,
        code: roleCode('ASG'),
        level: 5,
        permissions: [],
      });
      const res = await request(app)
        .put(`/api/roles/${role._id}/permissions`)
        .set(auth(superToken))
        .send({ permissions: ['zz'] });

      expect(res.status).toBe(400);
      expect(paths(res)).toContain('permissions[0]');
      const after = await Role.findById(role._id).lean();
      expect(after.permissions).toEqual([]);
    });
  });

  describe('POST /users 与 PUT /users/:id/roles 的 roles', () => {
    test('9 建用户时非法角色 ID：400 点名 roles[0]，用户不得被创建', async () => {
      const res = await request(app)
        .post('/api/users')
        .set(auth(superToken))
        .send({
          username: `${stamp}badrole`,
          email: `${stamp}badrole@example.com`,
          password: PASSWORD,
          roles: ['zz'],
        });

      expect(res.status).toBe(400);
      expect(paths(res)).toContain('roles[0]');
      expect(await User.countDocuments({ username: `${stamp}badrole` })).toBe(0);
    });

    test('10 分配角色时非法元素：400 点名 roles[0]，账户原有角色不变', async () => {
      const keep = await Role.create({
        name: `${stamp}保留角色`,
        code: roleCode('KEEP'),
        level: 3,
        permissions: [],
      });
      const target = await User.create({
        username: `${stamp}target`,
        email: `${stamp}target@example.com`,
        password: PASSWORD,
        roles: [keep._id],
      });

      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set(auth(superToken))
        .send({ roles: ['zz'] });

      expect(res.status).toBe(400);
      expect(paths(res)).toContain('roles[0]');
      const after = await User.findById(target._id).lean();
      expect(after.roles.map(String)).toEqual([String(keep._id)]);
    });

    test('11 反向对照：合法角色 ID 正常分配（新闸只管格式与条数）', async () => {
      const role = await Role.create({
        name: `${stamp}可分配`,
        code: roleCode('ASSIGN'),
        level: 2,
        permissions: [],
      });
      const target = await User.create({
        username: `${stamp}okrole`,
        email: `${stamp}okrole@example.com`,
        password: PASSWORD,
        roles: [],
      });

      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set(auth(superToken))
        .send({ roles: [String(role._id)] });

      expect(res.status).toBe(200);
      const after = await User.findById(target._id).lean();
      expect(after.roles.map(String)).toEqual([String(role._id)]);
    });
  });
});
