/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：userController 列表筛选（department/role）与批量删除
 * 守护的不变式：筛选走真实 HTTP 与 Mongo；批量删除对空列表 / 非法 ID / 超上限必须拒绝
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `userBoundary.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 用户列表筛选与批量删除边界回归
 *
 * department/role 筛选走真实 HTTP 与 Mongo 查询；
 * 批量删除覆盖空列表、非法 ID、超上限与成功删除路径。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const seedUserBoundaryFixtures = async ({ stamp, password }) => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(process.env.MONGODB_URI);
  }
  const User = require('../../models/User');
  const Role = require('../../models/Role');
  const Permission = require('../../models/Permission');

  const wildcardPermission = await Permission.create({
    name: '全部权限',
    code: '*:*',
    type: 'api',
    module: 'system',
  });
  const superRole = await Role.create({
    name: '超级管理员',
    code: 'SUPER_ADMIN',
    level: 10,
    isBuiltIn: true,
    permissions: [wildcardPermission._id],
  });
  const boundaryRole = await Role.create({
    name: '边界普通用户',
    code: `UB_ROLE_${stamp}`,
    level: 1,
    permissions: [],
  });
  const operator = await User.create({
    username: `uboperator${stamp}`,
    email: `uboperator${stamp}@example.com`,
    password,
    roles: [superRole._id],
  });
  await User.insertMany([
    {
      username: `ubdept${stamp}a`,
      email: `ubdept${stamp}a@example.com`,
      password,
      department: `DEPT_${stamp}`,
      roles: [boundaryRole._id],
    },
    {
      username: `ubdept${stamp}b`,
      email: `ubdept${stamp}b@example.com`,
      password,
      department: `DEPT_${stamp}`,
      roles: [boundaryRole._id],
    },
  ]);

  return { User, Role, Permission, operator, boundaryRole };
};

const cleanupUserBoundaryFixtures = async ({ stamp }) => {
  if (mongoose.connection.readyState === 0) return;
  await require('../../models/User')
    .deleteMany({
      username: {
        $in: [
          `uboperator${stamp}`,
          `ubdept${stamp}a`,
          `ubdept${stamp}b`,
          `ubdel${stamp}a`,
          `ubdel${stamp}b`,
        ],
      },
    })
    .catch(() => {});
  await require('../../models/Role')
    .deleteMany({ code: { $in: ['SUPER_ADMIN', `UB_ROLE_${stamp}`] } })
    .catch(() => {});
  await require('../../models/Permission')
    .deleteOne({ code: '*:*' })
    .catch(() => {});
  await mongoose.connection.close();
};

describe('userController 列表与批量删除边界', () => {
  let app;
  let User;
  let operator;
  let operatorToken;
  const stamp = `ub${Date.now().toString(36)}`;
  const password = `Aa1!${stamp}Test`;

  beforeAll(async () => {
    ({ User, operator } = await seedUserBoundaryFixtures({ stamp, password }));
    operatorToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    app = require('../../app').createApp();
  });

  afterAll(() => cleanupUserBoundaryFixtures({ stamp }));

  const authed = (method, url) =>
    request(app)[method](url).set('Authorization', `Bearer ${operatorToken}`);

  test('department 和 role 均按精确值过滤', async () => {
    const byDept = await authed(
      'get',
      `/api/users?department=${encodeURIComponent(`DEPT_${stamp}`)}`
    );
    expect(byDept.status).toBe(200);
    expect(byDept.body.data.map((user) => user.username).sort()).toEqual(
      [`ubdept${stamp}a`, `ubdept${stamp}b`].sort()
    );

    const byRole = await authed('get', `/api/users?role=${encodeURIComponent(`UB_ROLE_${stamp}`)}`);
    expect(byRole.status).toBe(200);
    expect(byRole.body.data).toHaveLength(2);
  });

  test('批量删除逐层校验并成功删除目标', async () => {
    const missing = await authed('delete', '/api/users/batch');
    expect(missing.status).toBe(400);

    const invalidIds = await authed('delete', '/api/users/batch').send({
      ids: ['bad-object-id'],
    });
    expect(invalidIds.status).toBe(400);

    const oversized = await authed('delete', '/api/users/batch').send({
      ids: Array.from({ length: 101 }, () => '000000000000000000000000'),
    });
    expect(oversized.status).toBe(400);

    await User.insertMany([
      {
        username: `ubdel${stamp}a`,
        email: `ubdel${stamp}a@example.com`,
        password,
      },
      {
        username: `ubdel${stamp}b`,
        email: `ubdel${stamp}b@example.com`,
        password,
      },
    ]);
    const targets = await User.find({
      username: { $in: [`ubdel${stamp}a`, `ubdel${stamp}b`] },
    }).lean();
    const targetIds = targets.map((user) => String(user._id));
    expect(targetIds).toHaveLength(2);

    const deleted = await authed('delete', '/api/users/batch').send({ ids: targetIds });
    expect(deleted.status).toBe(200);
    expect(deleted.body.data.deleted).toBe(2);
    const remaining = await User.countDocuments({ _id: { $in: targetIds } });
    expect(remaining).toBe(0);
  });
});
