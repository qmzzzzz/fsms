/**
 * 报表导出的 audit 分支越权出口回归（P1-4）
 *
 * 背景（实测越权）：GET /api/reports/export?type=audit 只要求 report:export
 * （通常下发运营岗），而同一份数据在 /api/security/audit-logs 要求
 * security:audit + strictLimiter。audit 分支还不叠加 dataScope（审计无部门/
 * 属主字段），于是持 report:export 者可从此处全量导出所有用户的
 * IP/路径/操作记录，整个 security:audit 权限模型被绕过。
 *
 * 修复口径：audit 类型额外校验 security:audit；业务类型不受影响。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('P1-4 /api/reports/export?type=audit 权限闸门', () => {
  let app;
  let User;
  let Role;
  let Permission;
  /** { token } by 角色语义 */
  const actors = {};

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    /** 幂等播种权限（多套件并行共享同一内存库，create 会撞 unique） */
    const seedPerm = async (code, name) =>
      Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { code, name, type: 'api', module: 'report' } },
        { upsert: true, new: true }
      );

    const exportPerm = await seedPerm('report:export', '导出报表');
    const auditPerm = await seedPerm('security:audit', '审计日志');

    /** 建角色 + 用户 + 签发令牌 */
    const makeActor = async (key, roleCode, permIds) => {
      const role = await Role.findOneAndUpdate(
        { code: roleCode },
        { $setOnInsert: { code: roleCode, name: roleCode, level: 6, permissions: permIds } },
        { upsert: true, new: true }
      );
      const user = await User.create({
        username: `exp_${key}`,
        email: `exp_${key}@example.com`,
        password: 'Qz7#Lm42vTx9',
        roles: [role._id],
      });
      actors[key] = {
        user,
        token: jwt.sign(
          { userId: String(user._id), username: user.username, tokenVersion: 0 },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        ),
      };
    };

    // 只有导出权限（漏洞利用者画像：运营岗）
    await makeActor('exportOnly', 'EXPORT_ONLY_TEST', [exportPerm._id]);
    // 导出 + 审计权限（合法的安全管理员）
    await makeActor('exportAndAudit', 'EXPORT_AUDIT_TEST', [exportPerm._id, auditPerm._id]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const exportAs = (key, qs) =>
    request(app)
      .get(`/api/reports/export?${qs}`)
      .set('Authorization', `Bearer ${actors[key].token}`);

  test('仅持 report:export → audit 导出被 403 拒绝并带错误码', async () => {
    const res = await exportAs('exportOnly', 'type=audit&format=xlsx');
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.errors?.errorCode).toBe('AUDIT_EXPORT_REQUIRES_AUDIT_PERM');
  });

  test('同时持 security:audit → audit 导出放行', async () => {
    const res = await exportAs('exportAndAudit', 'type=audit&format=xlsx');
    // 200（有数据）或 404（无数据）都算通过闸门；关键是不再 403
    expect(res.status).not.toBe(403);
  });

  test('业务类型导出不受本次加固影响（仍只需 report:export）', async () => {
    for (const type of ['alarms', 'devices', 'inspections']) {
      const res = await exportAs('exportOnly', `type=${type}&format=xlsx`);
      expect(res.status).not.toBe(403);
    }
  });

  test('未认证请求一律 401（闸门不在认证之前生效）', async () => {
    const res = await request(app).get('/api/reports/export?type=audit&format=xlsx');
    expect(res.status).toBe(401);
  });
});
