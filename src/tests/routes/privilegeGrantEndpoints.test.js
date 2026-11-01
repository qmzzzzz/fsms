/**
 * 临时权限授予端点（C-08 / C-09）HTTP 层契约
 *
 * 服务层用例（services/privilegeGrantFlow.test.js）证明规则本身；
 * 这里证明规则**接在真实链路上**：鉴权码生效、审批需要权限、审计按派生 action 落库。
 * 只测服务层的话，"路由少挂一个 checkPermission" 这一类缺陷不会被任何用例看见。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// 低敏业务模块（目录已登记）：A2 起「未登记的模块前缀」一律按高敏，普通码须落在已登记模块里
const CODE_GRANTABLE = 'report:zzgrant_probe';
const CODE_HIGH_RISK = 'user:update';
const CODE_GRANT = 'privilege:grant';
const CODE_APPROVE = 'privilege:approve';
const CODE_READ = 'privilege:read';
const PASSWORD = 'Gr4nt-Passw0rd!';
const stamp = Date.now();

// 写响应 key 白名单：四个写端点各自钉死应有键集。多一个内部字段就是契约泄漏，
// 少一个就是前端拿不到数据——两边都红；要改先在这里改，再改控制器。
const WRITE_RESPONSE_KEYS = {
  create: ['approvals', 'highRisk', 'id', 'requiredApprovals', 'status'],
  approve: ['approvals', 'expiresAt', 'id', 'requiredApprovals', 'status'],
  reject: ['id', 'status'],
  revoke: ['id', 'status'],
};

// 前端渲染用到的键（PrivilegeGrantView.vue 的 grep 证据见 work/fix-round10-privilege-egress-trace.md）
const FRONTEND_RENDERED_KEYS = [
  '_id',
  'approvals',
  'decisionReason',
  'durationHours',
  'expiresAt',
  'grantedAt',
  'highRisk',
  'permissionCodes',
  'reason',
  'requestedAt',
  'requestedBy',
  'requestedByName',
  'requiredApprovals',
  'status',
  'userId',
  'username',
];

// 列表/复核清单下发的全部字段 = 前端渲染键 + 撤销留痕（revokeReason 前端要显示，revokedAt/revokedByName 是同一组留痕）
const GRANT_LIST_KEYS = [...FRONTEND_RENDERED_KEYS, 'revokeReason', 'revokedAt', 'revokedByName'];

const expectExactKeys = (payload, keys) =>
  expect(Object.keys(payload).sort()).toEqual([...keys].sort());

describe('临时权限授予端点', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let PrivilegeGrant;
  const created = { users: [], roles: [], permissions: [] };
  let target;

  const tokenOf = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      {
        expiresIn: '7d',
      }
    );

  const makeUser = async (name, roleId) => {
    const user = await User.create({
      username: `${name}${stamp}`,
      email: `${name}${stamp}@zzgrant.test`,
      password: PASSWORD,
      department: 'ZZGRANT',
      roles: [roleId],
    });
    created.users.push(user._id);
    return { user, token: tokenOf(user) };
  };

  let requester;
  let approverA;
  let approverB;
  let viewer;
  let plain;
  let selfApprover;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/AuditLog'); // 注册模型即可，本文件不直接断言审计（有专门用例）
    PrivilegeGrant = require('../../models/PrivilegeGrant');
    require('../../models/TokenBlacklist');
    require('../../models/UserSession');

    const perms = await Permission.create([
      { name: '临时只读', code: CODE_GRANTABLE, type: 'api', module: 'report' },
      { name: '改用户', code: CODE_HIGH_RISK, type: 'api', module: 'user' },
      { name: '申请临时授权', code: CODE_GRANT, type: 'api', module: 'privilege' },
      { name: '审批临时授权', code: CODE_APPROVE, type: 'api', module: 'privilege' },
      { name: '查看临时授权', code: CODE_READ, type: 'api', module: 'privilege' },
    ]);
    created.permissions.push(...perms.map((p) => p._id));
    const byCode = new Map(perms.map((p) => [p.code, p._id]));

    const makeRole = async (name, codes) => {
      const role = await Role.create({
        name: `${name}${stamp}`,
        code: `${name.toUpperCase()}${stamp}`,
        permissions: codes.map((c) => byCode.get(c) || c),
      });
      created.roles.push(role._id);
      return role;
    };

    const requesterRole = await makeRole('zzgrant_requester', [CODE_GRANT]);
    const approverRole = await makeRole('zzgrant_approver', [
      CODE_APPROVE,
      CODE_READ,
      CODE_GRANTABLE,
      CODE_HIGH_RISK,
    ]);
    const viewerRole = await makeRole('zzgrant_viewer', [CODE_READ]);
    const plainRole = await makeRole('zzgrant_plain', []);
    const selfRole = await makeRole('zzgrant_self', [CODE_GRANT, CODE_APPROVE, CODE_GRANTABLE]);

    requester = await makeUser('zzgrant_req', requesterRole._id);
    approverA = await makeUser('zzgrant_appr_a', approverRole._id);
    approverB = await makeUser('zzgrant_appr_b', approverRole._id);
    viewer = await makeUser('zzgrant_view', viewerRole._id);
    plain = await makeUser('zzgrant_plain', plainRole._id);
    selfApprover = await makeUser('zzgrant_self', selfRole._id);
    const targetUser = await makeUser('zzgrant_target', plainRole._id);
    target = targetUser.user;

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await PrivilegeGrant.deleteMany({ username: { $regex: /^zzgrant_/ } }).catch(() => {});
      await User.deleteMany({ _id: { $in: created.users } }).catch(() => {});
      await Role.deleteMany({ _id: { $in: created.roles } }).catch(() => {});
      await Permission.deleteMany({ _id: { $in: created.permissions } }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('读接口鉴权：匿名 401、无权限 403、有 privilege:read 可读', async () => {
    expect((await request(app).get('/api/permissions/grants')).status).toBe(401);
    expect(
      (
        await request(app)
          .get('/api/permissions/grants')
          .set('Authorization', `Bearer ${plain.token}`)
      ).status
    ).toBe(403);
    expect(
      (
        await request(app)
          .get('/api/permissions/grants')
          .set('Authorization', `Bearer ${viewer.token}`)
      ).status
    ).toBe(200);
  });

  test('入参越界：有效期超上限被校验链拦下并点名字段', async () => {
    const res = await request(app)
      .post('/api/permissions/grants')
      .set('Authorization', `Bearer ${requester.token}`)
      .send({
        targetUserId: String(target._id),
        permissionCodes: [CODE_GRANTABLE],
        reason: '越界有效期',
        durationHours: 999,
      });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(JSON.stringify(res.body.errors)).toContain('durationHours');
  });

  test('全链路：申请 → 审批生效 → 复核汇总 → 撤销回收', async () => {
    const created1 = await request(app)
      .post('/api/permissions/grants')
      .set('Authorization', `Bearer ${requester.token}`)
      .send({
        targetUserId: String(target._id),
        permissionCodes: [CODE_GRANTABLE],
        reason: '季度报表支持',
        durationHours: 2,
      });
    expect(created1.status).toBe(201);
    expect(created1.body.data.status).toBe('pending');
    expect(created1.body.data.requiredApprovals).toBe(1);
    expectExactKeys(created1.body.data, WRITE_RESPONSE_KEYS.create);
    const grantId = created1.body.data.id;

    const approved = await request(app)
      .post(`/api/permissions/grants/${grantId}/approve`)
      .set('Authorization', `Bearer ${approverA.token}`);
    expect(approved.status).toBe(200);
    expect(approved.body.data.status).toBe('active');
    expect(approved.body.data.expiresAt).toBeTruthy();
    expectExactKeys(approved.body.data, WRITE_RESPONSE_KEYS.approve);

    const summary = await request(app)
      .get('/api/permissions/grants/review')
      .set('Authorization', `Bearer ${viewer.token}`);
    expect(summary.status).toBe(200);
    expect(summary.body.data.active).toBeGreaterThanOrEqual(1);

    const list = await request(app)
      .get(`/api/permissions/grants?status=active&userId=${target._id}`)
      .set('Authorization', `Bearer ${viewer.token}`);
    expect(list.status).toBe(200);
    expect(list.body.data.some((row) => String(row._id) === grantId)).toBe(true);

    const revoked = await request(app)
      .post(`/api/permissions/grants/${grantId}/revoke`)
      .set('Authorization', `Bearer ${requester.token}`)
      .send({ reason: '任务提前结束' });
    expect(revoked.status).toBe(200);
    expect(revoked.body.data.status).toBe('revoked');
    // F1：撤销响应体只回 id/status，不得泄露内部留痕字段名（revokedBy/revokedAt/revokeReason…）
    expectExactKeys(revoked.body.data, WRITE_RESPONSE_KEYS.revoke);
  });

  test('撤销非 pending/active 的记录：409 带 errorCode 与库内当前状态（errors.currentStatus）', async () => {
    const created = await request(app)
      .post('/api/permissions/grants')
      .set('Authorization', `Bearer ${requester.token}`)
      .send({
        targetUserId: String(target._id),
        permissionCodes: [CODE_GRANTABLE],
        reason: '状态参数契约',
        durationHours: 2,
      });
    expect(created.status).toBe(201);
    const grantId = created.body.data.id;

    const rejected = await request(app)
      .post(`/api/permissions/grants/${grantId}/reject`)
      .set('Authorization', `Bearer ${approverA.token}`)
      .send({ reason: '材料不全' });
    expect(rejected.status).toBe(200);
    expect(rejected.body.data.status).toBe('rejected');
    expectExactKeys(rejected.body.data, WRITE_RESPONSE_KEYS.reject);

    const res = await request(app)
      .post(`/api/permissions/grants/${grantId}/revoke`)
      .set('Authorization', `Bearer ${requester.token}`)
      .send({ reason: '任务结束' });
    expect(res.status).toBe(409);
    expect(res.body.errors.errorCode).toBe('PRIVILEGE_GRANT_NOT_ACTIVE');
    // 前端按 code 走静态 i18n 文案，动态状态只能靠 errors 里的结构化字段带出（A2）
    expect(res.body.errors.currentStatus).toBe('rejected');
  });
  test('高敏授予需两名审批人：一人签批后仍是 pending', async () => {
    const res1 = await request(app)
      .post('/api/permissions/grants')
      .set('Authorization', `Bearer ${requester.token}`)
      .send({
        targetUserId: String(target._id),
        permissionCodes: [CODE_HIGH_RISK],
        reason: '账号信息纠错',
        durationHours: 4,
      });
    expect(res1.status).toBe(201);
    expect(res1.body.data.highRisk).toBe(true);
    expect(res1.body.data.requiredApprovals).toBe(2);

    const first = await request(app)
      .post(`/api/permissions/grants/${res1.body.data.id}/approve`)
      .set('Authorization', `Bearer ${approverA.token}`);
    expect(first.status).toBe(200);
    expect(first.body.data.status).toBe('pending');

    const second = await request(app)
      .post(`/api/permissions/grants/${res1.body.data.id}/approve`)
      .set('Authorization', `Bearer ${approverB.token}`);
    expect(second.status).toBe(200);
    expect(second.body.data.status).toBe('active');
  });

  test('职责分离：申请人不得自审（403 且带业务码）', async () => {
    const req1 = await request(app)
      .post('/api/permissions/grants')
      .set('Authorization', `Bearer ${selfApprover.token}`)
      .send({
        targetUserId: String(target._id),
        permissionCodes: [CODE_GRANTABLE],
        reason: '自审阻断验证',
        durationHours: 1,
      });
    expect(req1.status).toBe(201);

    const self = await request(app)
      .post(`/api/permissions/grants/${req1.body.data.id}/approve`)
      .set('Authorization', `Bearer ${selfApprover.token}`);
    expect(self.status).toBe(403);
    expect(self.body.errors.errorCode).toBe('PRIVILEGE_SELF_APPROVAL_FORBIDDEN');
  });

  test('审计按派生 action 入缓冲：申请 permission_grants、审批 permission_grants_approve', async () => {
    const auditBuffer = require('../../services/auditBuffer');
    const { waitFor } = require('../helpers/waitFor');
    const spy = jest.spyOn(auditBuffer, 'push');
    const grantRecords = () =>
      spy.mock.calls
        .map((call) => call[0])
        .filter((doc) => String(doc.path || '').includes('/api/permissions/grants'));
    try {
      const res1 = await request(app)
        .post('/api/permissions/grants')
        .set('Authorization', `Bearer ${requester.token}`)
        .send({
          targetUserId: String(target._id),
          permissionCodes: [CODE_GRANTABLE],
          reason: '审计留痕验证',
          durationHours: 1,
        });
      expect(res1.status).toBe(201);

      const approve = await request(app)
        .post(`/api/permissions/grants/${res1.body.data.id}/approve`)
        .set('Authorization', `Bearer ${approverA.token}`);
      expect(approve.status).toBe(200);

      await waitFor(() => grantRecords().some((doc) => doc.action === 'permission_grants'), {
        label: 'permission_grants 审计入缓冲',
      });
      await waitFor(
        () => grantRecords().some((doc) => doc.action === 'permission_grants_approve'),
        {
          label: 'permission_grants_approve 审计入缓冲',
        }
      );

      const created1 = grantRecords().find((doc) => doc.action === 'permission_grants');
      expect(created1.category).toBe('permission');
      expect(created1.username).toBe(requester.user.username);
      const approved1 = grantRecords().find((doc) => doc.action === 'permission_grants_approve');
      expect(approved1.category).toBe('permission');
      expect(approved1.username).toBe(approverA.user.username);
      expect(String(approved1.path)).toContain('/approve');
    } finally {
      spy.mockRestore();
    }
  });

  test('驳回端点：有审批权即驳回并留痕；驳回后重复审批被 409 与业务码挡下', async () => {
    const req1 = await request(app)
      .post('/api/permissions/grants')
      .set('Authorization', `Bearer ${requester.token}`)
      .send({
        targetUserId: String(target._id),
        permissionCodes: [CODE_GRANTABLE],
        reason: '驳回链路 HTTP 层',
        durationHours: 1,
      });
    expect(req1.status).toBe(201);

    const rejected = await request(app)
      .post(`/api/permissions/grants/${req1.body.data.id}/reject`)
      .set('Authorization', `Bearer ${approverA.token}`)
      .send({ reason: '重复申请，业务上不必要' });
    expect(rejected.status).toBe(200);
    expect(rejected.body.data.status).toBe('rejected');
    expectExactKeys(rejected.body.data, WRITE_RESPONSE_KEYS.reject);

    const again = await request(app)
      .post(`/api/permissions/grants/${req1.body.data.id}/approve`)
      .set('Authorization', `Bearer ${approverB.token}`);
    expect(again.status).toBe(409);
    expect(again.body.errors.errorCode).toBe('PRIVILEGE_GRANT_NOT_PENDING');
  });

  test('R10-3 列表与复核清单只下发白名单字段：条目键集 == GRANT_LIST_KEYS（原始文档全字段会红）', async () => {
    const created1 = await request(app)
      .post('/api/permissions/grants')
      .set('Authorization', `Bearer ${requester.token}`)
      .send({
        targetUserId: String(target._id),
        permissionCodes: [CODE_GRANTABLE],
        reason: '字段白名单验证',
        durationHours: 2,
      });
    expect(created1.status).toBe(201);
    const grantId = created1.body.data.id;
    const approved = await request(app)
      .post(`/api/permissions/grants/${grantId}/approve`)
      .set('Authorization', `Bearer ${approverA.token}`);
    expect(approved.status).toBe(200);
    // 推进到「超期未复核」窗口：90 天前生效、尚未到期；这条同时进入 /grants/review 的 overdueGrants[]
    await PrivilegeGrant.updateOne(
      { _id: grantId },
      { $set: { grantedAt: new Date(Date.now() - 100 * 24 * 3600 * 1000) } }
    );

    const list = await request(app)
      .get(`/api/permissions/grants?userId=${target._id}`)
      .set('Authorization', `Bearer ${viewer.token}`);
    expect(list.status).toBe(200);
    // 分页 total 来自独立的 countDocuments：投影白名单不得影响它
    expect(list.body.pagination.total).toBeGreaterThanOrEqual(1);
    const row = list.body.data.find((item) => String(item._id) === grantId);
    expect(row).toBeTruthy();
    expectExactKeys(row, GRANT_LIST_KEYS);
    // 前端渲染的每个键都必须在响应里（少一个就是功能回归）
    for (const key of FRONTEND_RENDERED_KEYS) expect(Object.keys(row)).toContain(key);

    const review = await request(app)
      .get('/api/permissions/grants/review')
      .set('Authorization', `Bearer ${viewer.token}`);
    expect(review.status).toBe(200);
    const overdue = review.body.data.overdueGrants.find((item) => String(item._id) === grantId);
    expect(overdue).toBeTruthy();
    expectExactKeys(overdue, GRANT_LIST_KEYS);
  });
});
