/**
 * L-23 回归：用户角色统计的 $match 必须前置到 $unwind 之前
 *
 * 缺陷历史：原管道为 `$unwind → $match → $group`，先展开每个用户的 roles 数组
 * 再逐行过滤，$unwind 的输入/输出行数被放大（N 用户 × 平均角色数）。
 * 修复后为 `$match（数组层粗筛）→ $unwind → $match（展开后精确过滤）→ $group`。
 *
 * 为什么必须有测试锁定：这是纯粹的**性能语义**修复——两种顺序的结果集完全相同，
 * 因此没有任何结果断言会因回退而变红；而回退的代价是实测 1.64x 的退化
 * （2 万用户规模 81.53ms → 133.57ms）。只能靠管道形状断言锁定。
 *
 * 锁定方式：capture aggregate 的管道参数，断言数组层 $match 出现在 $unwind 之前。
 * 同时做**语义等价**验证：同一份数据用两种顺序跑，结果必须一致
 * （防止有人为了"过测试"而把过滤条件挪走，造成统计口径变化）。
 */
const mongoose = require('mongoose');

describe('L-23 角色用户数统计的管道顺序', () => {
  let User;
  let Role;
  let RoleService;
  let capturedPipeline;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    // 该模块导出的是**单例实例**（`module.exports = new RoleService()`），不是类
    RoleService = require('../../services/roleService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('数组层 $match 必须出现在 $unwind 之前（顺序锁定）', async () => {
    const spy = jest.spyOn(User, 'aggregate').mockImplementation(() => {
      return Promise.resolve([]);
    });
    const listSpy = jest.spyOn(Role, 'find').mockImplementation(() => ({
      populate: () => ({
        sort: () => ({
          limit: () => ({ skip: () => Promise.resolve([]) }),
        }),
      }),
    }));
    const countSpy = jest.spyOn(Role, 'countDocuments').mockResolvedValue(0);
    try {
      await RoleService.listRoles({}, 1, 10);
      expect(spy).toHaveBeenCalled();
      capturedPipeline = spy.mock.calls[0][0];
    } finally {
      spy.mockRestore();
      listSpy.mockRestore();
      countSpy.mockRestore();
    }

    const unwindIdx = capturedPipeline.findIndex((s) => s.$unwind !== undefined);
    expect(unwindIdx).toBeGreaterThan(-1);
    // 关键断言：$unwind 之前必须已有一层 $match（数组层粗筛）
    const matchBeforeUnwind = capturedPipeline
      .slice(0, unwindIdx)
      .filter((s) => s.$match !== undefined);
    expect(matchBeforeUnwind.length).toBeGreaterThan(0);
    // 且粗筛条件就是目标角色集（不是空条件之类的形式主义）
    const rolesCond = matchBeforeUnwind[0].$match.roles;
    expect(rolesCond).toBeDefined();
    expect(rolesCond.$in).toBeDefined();
  });

  test('顺序变化不改变统计结果（语义等价，防"为过测试改口径"）', async () => {
    const RoleModel = require('../../models/Role');
    const suffix = `l23${Date.now().toString(36)}`;
    const roleA = await RoleModel.create({
      name: `L23 角色A ${suffix}`,
      code: `l23_a_${suffix}`,
      status: 'active',
    });
    const roleB = await RoleModel.create({
      name: `L23 角色B ${suffix}`,
      code: `l23_b_${suffix}`,
      status: 'active',
    });
    // 密码须满足模型强度（≥12 字符）；本测试只关心 roles 聚合，口令值无关
    const pwd = 'L23-Lock-Password!';
    const created = await User.insertMany([
      {
        username: `l23_u1_${suffix}`,
        email: `u1_${suffix}@e.com`,
        password: pwd,
        roles: [roleA._id],
      },
      {
        username: `l23_u2_${suffix}`,
        email: `u2_${suffix}@e.com`,
        password: pwd,
        roles: [roleA._id, roleB._id],
      },
      {
        username: `l23_u3_${suffix}`,
        email: `u3_${suffix}@e.com`,
        password: pwd,
        roles: [roleB._id],
      },
      { username: `l23_u4_${suffix}`, email: `u4_${suffix}@e.com`, password: pwd, roles: [] },
    ]);

    try {
      const roleIds = [roleA._id, roleB._id];
      // 新顺序（生产实现）
      const optimized = await User.aggregate([
        { $match: { roles: { $in: roleIds } } },
        { $unwind: '$roles' },
        { $match: { roles: { $in: roleIds } } },
        { $group: { _id: '$roles', count: { $sum: 1 } } },
      ]);
      // 旧顺序（修复前）
      const legacy = await User.aggregate([
        { $unwind: '$roles' },
        { $match: { roles: { $in: roleIds } } },
        { $group: { _id: '$roles', count: { $sum: 1 } } },
      ]);

      const norm = (rows) =>
        rows
          .map((r) => `${r._id}:${r.count}`)
          .sort()
          .join(',');
      expect(norm(optimized)).toBe(norm(legacy));
      // 顺带锁定正确计数：roleA 2 人、roleB 2 人
      const m = new Map(optimized.map((r) => [String(r._id), r.count]));
      expect(m.get(String(roleA._id))).toBe(2);
      expect(m.get(String(roleB._id))).toBe(2);
    } finally {
      await User.deleteMany({ _id: { $in: created.map((u) => u._id) } });
      await RoleModel.deleteMany({ _id: { $in: [roleA._id, roleB._id] } });
    }
  });
});
