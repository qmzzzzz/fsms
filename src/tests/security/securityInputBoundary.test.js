'use strict';

/**
 * 两条 security 路由的 body 入参边界
 *   · POST /api/security/view-sensitive   —— targetUserId
 *   · PUT  /api/security/users/:userId/lock —— reason
 *
 * 共同根因：这两条路由各自只校验了「看起来像 ID / 看起来像开关」的那个字段
 * （dataType、locked），另一个直接进 DB 层。危害有两类，本文件按类给判据：
 *
 * (1) 注定失败的请求先走完了步进二次验证。view-sensitive 的链序是
 *     dataType 白名单 → consumeValidation() → requireReAuthentication()，
 *     坏 targetUserId 一路通过，直到控制器 `User.findById(targetUserId)` 才炸；
 *     于是动态口令已被消费（mfaLastCounter 推进，与登录共用同一个码）、
 *     或密码分支白做一次 bcrypt 比对。该口径在仓内已有共识（G3 修 dataType 时
 *     写下的"注定 400 的请求不得产生凭据侧副作用"），判据用最锋利的形状：
 *     坏参数 + 错口令必须答 400 VALIDATION_FAILED，而不是先答 REAUTH_PASSWORD_INCORRECT。
 *
 * (2) 非法值漏到 DB 层，400 里丢掉字段明细。reason 会写进 `user.remark`
 *     （models/User.js:197-201，maxlength 500）与 `AuditLog.reason`（schema 无上限）。
 *     update 走 user.save()，校验器真的会跑 ⇒ 超长得到的是 Mongoose ValidationError，
 *     经 errorHandler 在非 development 下把 fieldErrors 抹成 undefined，客户端只看到
 *     一个和自己提交的字段同不上名的 VALIDATION_FAILED；非字符串得到的是 CastError，
 *     被映射成「资源 ID 格式无效」——用户没有提交过任何 ID。
 *     路由层的规则同时修掉这两点：错误点名 reason，且给出可核对的上限。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `sib${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();
// 与 models/User.js remark 的 maxlength 同值；上限判据必须钉住真实约束，
// 路由比 schema 更紧会误伤合法输入，更松则又漏回 DB 层
const REMARK_MAX = 500;

describe('view-sensitive：targetUserId 必须先于步进验证被校验', () => {
  let app;
  let User;
  let AuditLog;
  const users = {};

  const view = (key, body) =>
    request(app)
      .post('/api/security/view-sensitive')
      .set('Authorization', `Bearer ${users[key].token}`)
      .send(body);

  const sensitiveRows = (key) =>
    AuditLog.countDocuments({ action: 'view_sensitive_data', userId: users[key].id });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    // 坏 targetUserId 想暴露的是"校验顺序"，就必须先过 checkViewSensitivePermission
    // 那道 `system:read` 闸（非本人一律要求该权限），否则请求在 403 上就停了，
    // 后面的步进验证根本没跑，判据会被假绿掩盖。
    const readPerm = await Permission.findOneAndUpdate(
      { code: 'system:read' },
      { $setOnInsert: { name: '系统查看', code: 'system:read', type: 'api', module: 'security' } },
      { upsert: true, new: true }
    );
    let readerRole = await Role.findOne({ code: `${stamp}_reader` });
    if (!readerRole) {
      readerRole = await Role.create({
        name: '序列用例查看者',
        code: `${stamp}_reader`,
        level: 9,
        permissions: [readPerm._id],
      });
    }

    const mk = async (key, phone, privileged = false) => {
      const u = await User.create({
        username: `${stamp}_${key}`,
        email: `${stamp}_${key}@example.com`,
        password: PASSWORD,
        phone,
        roles: privileged ? [readerRole._id] : [],
      });
      users[key] = {
        id: String(u._id),
        username: u.username,
        phone,
        token: jwt.sign(
          { userId: String(u._id), username: u.username, tokenVersion: 0 },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        ),
      };
    };
    await mk('badpwd', '13900000001', true);
    await mk('self', '13900000002');
    await mk('selfid', '13900000003');
    await mk('oper', '13900000004', true);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
      // 序列用例的角色随用例走，不留存到别的测试文件里
      await require('../../models/Role')
        .deleteMany({ code: `${stamp}_reader` })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('1 坏 targetUserId + 错口令 ⇒ 400 点名 targetUserId，不得先答口令错误', async () => {
    const res = await view('badpwd', {
      dataType: 'phone',
      targetUserId: 'not-an-object-id',
      currentPassword: `${PASSWORD}-wrong`,
    });
    // 修复前实测：403 REAUTH_PASSWORD_INCORRECT —— 坏参数先走完了步进验证的密码分支
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.status).toBe(400);
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetUserId');
    expect(await sensitiveRows('badpwd')).toBe(0);
  });

  test('2 反向对照：本人查看（不带 targetUserId）+ 正确口令 ⇒ 200 且手机号逐字返回', async () => {
    const res = await view('self', { dataType: 'phone', currentPassword: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.data.full).toBe(users.self.phone);
    // 掩码位仍在：收紧入参校验不得顺手拆掉脱敏
    expect(res.body.data.masked).toMatch(/\*/);
    expect(await sensitiveRows('self')).toBe(1);
  });

  test('3 反向对照：targetUserId 写自己的合法 ID 必须放行（新规则只许管格式）', async () => {
    const res = await view('selfid', {
      dataType: 'phone',
      targetUserId: users.selfid.id,
      currentPassword: PASSWORD,
    });
    expect(res.status).toBe(200);
    expect(res.body.data.full).toBe(users.selfid.phone);
  });

  test('4 操作符形状不得被当成查询条件：既不返回号码也不留审计', async () => {
    // deepSanitizeKeys 会删掉 $ 开头的键，于是 findById 收到的是 {}；
    // 清洗器之外还须有格式闸——两者任缺其一时这条都会返回数据或漏出 DB 层错误
    const res = await view('oper', {
      dataType: 'phone',
      targetUserId: { $ne: null },
      currentPassword: PASSWORD,
    });
    // 修复前实测：状态已经是 400，但那是 CastError 分支给的"资源 ID 格式无效"，
    // res.body.errors 为 null ⇒ 没有任何字段明细，客户端无从知道是哪个入参坏了
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.status).toBe(400);
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetUserId');
    expect(res.body.data).toBeUndefined();
    expect(await sensitiveRows('oper')).toBe(0);
  });
});

describe('锁定/解锁：reason 的类型与长度在路由层收口', () => {
  let app;
  let User;
  let AuditLog;
  let opId;
  let opToken;

  const putLock = (targetId, body) =>
    request(app)
      .put(`/api/security/users/${targetId}/lock`)
      .set('Authorization', `Bearer ${opToken}`)
      .send(body);

  const reload = async (id) => User.findById(id).select('status remark').lean();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');

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
    const op = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}_op@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    opId = String(op._id);
    opToken = jwt.sign(
      { userId: String(op._id), username: op.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const newTarget = async (key, extra = {}) =>
    User.create({
      username: `${stamp}_t${key}`,
      email: `${stamp}_t${key}@example.com`,
      password: PASSWORD,
      ...extra,
    });

  test('5 锁定：超长 reason 在路由层被点名，账户状态与 remark 纹丝不动', async () => {
    const target = await newTarget('over');
    // 失败请求不留审计行：路由级校验必须发生在服务层写库之前。
    // 判据用**增量**而不是绝对 0：兄弟用例（6/7/8）会为同一个操作者成功落库，
    // 按 opId 数绝对值就把断言变成了用例顺序的函数（--randomize 下多数 seed 红）。
    const before = await AuditLog.countDocuments({ userId: opId });
    const res = await putLock(target._id, { locked: true, reason: 'w'.repeat(REMARK_MAX + 1) });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
    const after = await reload(target._id);
    expect(after.status).toBe('active');
    expect(after.remark ?? '').toBe('');
    expect(await AuditLog.countDocuments({ userId: opId })).toBe(before);
  });

  test('6 反向对照：恰好 500 字必须放行且逐字落进 remark', async () => {
    const target = await newTarget('edge');
    const reason = 'x'.repeat(REMARK_MAX);
    const res = await putLock(target._id, { locked: true, reason });
    expect(res.status).toBe(200);
    expect((await reload(target._id)).remark).toBe(reason);
  });

  test('7 解锁方向同样受闸：否则只闸锁定也能全绿', async () => {
    const target = await newTarget('unlock', { status: 'locked' });
    const res = await putLock(target._id, { locked: false, reason: 'y'.repeat(REMARK_MAX + 1) });
    expect(res.status).toBe(400);
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
    expect((await reload(target._id)).status).toBe('locked');
  });

  test('8 非字符串 reason 明确拒绝，不得被 Cast 成 [object Object] 或数字串', async () => {
    for (const [i, reason] of [{ nested: 'x' }, 12345, ['a', 'b']].entries()) {
      const target = await newTarget(`type${i}`);
      const res = await putLock(target._id, { locked: true, reason });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
      const after = await reload(target._id);
      expect(after.status).toBe('active');
      expect(after.remark ?? '').not.toMatch(/\[object /);
      expect(after.remark ?? '').not.toBe('12345');
    }
  });

  test('9 缺省 reason 的锁定仍然正常：新闸只许管类型与长度', async () => {
    const target = await newTarget('plain', { remark: '既有备注' });
    const res = await putLock(target._id, { locked: true });
    expect(res.status).toBe(200);
    const after = await reload(target._id);
    expect(after.status).toBe('locked');
    expect(after.remark).toBe('既有备注');
  });
});
