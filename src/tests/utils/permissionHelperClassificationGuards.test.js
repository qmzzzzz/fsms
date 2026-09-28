/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：permissionHelper：用户不存在分支、菜单/按钮权限分类、各函数错误分支、菜单树挂载
 * 守护的不变式：菜单与按钮权限必须分类正确；用户不存在必须短路；数据范围委托必须生效
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `permissionHelperGap.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * permissionHelper 分支补齐（覆盖率棘轮：45.45% → 目标 ≥75%）
 *
 * 缺口：用户不存在分支（33）、菜单/按钮权限分类（49-62）、
 * 各函数错误分支（100-101/180-181/214-215/230-231/246-247/273-274/300-301）、
 * 菜单树模块节点与挂载（137/150-151/160-162/173-174）、
 * getDataScope 委托（311-312）。
 */

const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('permissionHelper 分支补齐', () => {
  let User;
  let Role;
  let Permission;
  let helper;
  const PASSWORD = randomPassword();
  const stamp = `ph${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const users = {};
  let ROLE_OFF_CODE;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    helper = require('../../utils/permissionHelper');

    const permMenu = await Permission.create({
      code: 'phgap:view',
      name: 'PHGap 查看页',
      type: 'menu',
      path: '/phgap/view',
      module: 'phgap',
      status: 'active',
    });
    const permButton = await Permission.create({
      code: 'phgap:export',
      name: 'PHGap 导出按钮',
      type: 'button',
      module: 'phgap',
      status: 'active',
    });
    const permApi = await Permission.create({
      code: 'phgap:list',
      name: 'PHGap 列表接口',
      type: 'api',
      path: '/api/phgap',
      method: 'GET',
      module: 'phgap',
      status: 'active',
    });
    // 模块通配菜单：code 为 `<module>:*` 形式，验证菜单树模块节点取名路径
    const permModuleWildcard = await Permission.create({
      code: 'phgaptwo:*',
      name: 'PHGap2 模块',
      type: 'menu',
      path: '/phgaptwo',
      module: 'phgaptwo',
      status: 'active',
    });
    // 无关模块菜单：不应出现在任何测试用户的菜单树中
    await Permission.create({
      code: 'phother:view',
      name: '无关模块菜单',
      type: 'menu',
      path: '/phother',
      module: 'phother',
      status: 'active',
    });
    // 只挂在「已停用角色」上的权限：用于 P3-8 口径的一致性断言。
    // 故意单独占一个模块 phoff——getMenuTree 的菜单可见性是**模块级**的
    // （:159 moduleHasPerm），若放在 phgap 会把这条权限泄漏进上面
    // 「按模块聚合」用例的 children 断言里（实测过，红在该用例身上，
    // 与本文件要守的不变式无关）。这条泄漏本身已单独登记待拍板。
    const permOff = await Permission.create({
      code: 'phoff:view',
      name: 'PHOff 停用角色权限',
      type: 'menu',
      path: '/phoff/view',
      module: 'phoff',
      status: 'active',
    });

    const roleFull = await Role.create({
      name: 'PHGap 全类型角色',
      code: `PHGAP_ROLE_${stamp.toUpperCase()}`,
      level: 1,
      status: 'active',
      permissions: [permMenu._id, permButton._id, permApi._id],
    });
    const roleWildcard = await Role.create({
      name: 'PHGap2 通配角色',
      code: `PHGAP_ROLE2_${stamp}`,
      level: 1,
      status: 'active',
      permissions: [permModuleWildcard._id],
    });
    // 管理员停用后的角色：三处判定（getUserRoles / hasRole / getUserPermissions）
    // 必须把它当作「不存在」。P3-8 修了后两处，getUserRoles 是当时漏掉的第三处。
    const roleOff = await Role.create({
      name: 'PHGap 已停用角色',
      code: `PHGAP_ROLE_OFF_${stamp}`,
      level: 1,
      status: 'inactive',
      permissions: [permOff._id],
    });
    ROLE_OFF_CODE = roleOff.code;

    const makeUser = async (name, roles) => {
      const user = await User.create({
        username: `${stamp}${name}`,
        email: `${stamp}${name}@example.com`,
        password: PASSWORD,
        roles,
      });
      users[name] = user;
    };
    await makeUser('full', [roleFull._id]);
    await makeUser('wild', [roleWildcard._id]);
    await makeUser('norole', []);
    await makeUser('mixed', [roleFull._id, roleOff._id]);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`_${stamp}$`, 'i') }).catch(() => {});
      await Permission.deleteMany({
        module: { $in: ['phgap', 'phgaptwo', 'phother', 'phoff'] },
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  describe('getUserPermissions', () => {
    test('activeRoles（L-15 导出）：剔除可能的 null 洞 + 入参缺失/非数组兜底', () => {
      // 防御性冗余：实测 mongoose 8.24.1 对 populate+match 未命中的引用是丢弃元素（不留 null），
      // 见 zzqoder_populateMatchShape.test.js。下面注入字面 null，是验证「数组里一旦出现 null 洞，
      // 取 r.name/r.code 也不会抛 TypeError → 500」这层兜底在将来版本改行为时仍然成立。
      expect(helper.activeRoles({ roles: [{ code: 'a' }, null, { code: 'b' }] })).toEqual([
        { code: 'a' },
        { code: 'b' },
      ]);
      // 三个兜底分支：user 缺失 / roles 缺失 / roles 不是数组
      expect(helper.activeRoles(undefined)).toEqual([]);
      expect(helper.activeRoles({})).toEqual([]);
      expect(helper.activeRoles({ roles: 'not-an-array' })).toEqual([]);
    });

    test('不存在的用户 → null', async () => {
      await expect(helper.getUserPermissions(new mongoose.Types.ObjectId())).resolves.toBeNull();
    });

    test('菜单/按钮/接口三类权限正确分桶', async () => {
      const info = await helper.getUserPermissions(users.full._id);
      expect(info).toBeTruthy();
      expect(info.permissions).toEqual(
        expect.arrayContaining(['phgap:view', 'phgap:export', 'phgap:list'])
      );
      expect(info.menuPermissions).toEqual([
        expect.objectContaining({ code: 'phgap:view', path: '/phgap/view', module: 'phgap' }),
      ]);
      expect(info.buttonPermissions).toEqual([expect.objectContaining({ code: 'phgap:export' })]);
      expect(info.apiPermissions).toEqual([
        expect.objectContaining({ code: 'phgap:list', method: 'GET' }),
      ]);
      expect(info.user.email).toBe(`${stamp}full@example.com`);
    });

    test('DB 故障：记录日志并向上抛错（不得静默降级）', async () => {
      const spy = jest.spyOn(User, 'findById').mockImplementation(() => {
        throw new Error('db down (故障注入)');
      });
      try {
        await expect(helper.getUserPermissions(users.full._id)).rejects.toThrow('db down');
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('getMenuTree', () => {
    test('不存在的用户 → 空树', async () => {
      await expect(helper.getMenuTree(new mongoose.Types.ObjectId())).resolves.toEqual([]);
    });

    test('按模块聚合：有权模块出现、无关模块被过滤', async () => {
      const tree = await helper.getMenuTree(users.full._id);
      const modules = tree.map((n) => n.id);
      expect(modules).toContain('phgap');
      expect(modules).not.toContain('phother');
      const phgap = tree.find((n) => n.id === 'phgap');
      expect(phgap.children).toEqual([
        expect.objectContaining({ code: 'phgap:view', path: '/phgap/view' }),
      ]);
    });

    test('模块通配权限：模块节点名取自 `<module>:*` 菜单', async () => {
      const tree = await helper.getMenuTree(users.wild._id);
      const node = tree.find((n) => n.id === 'phgaptwo');
      expect(node).toBeTruthy();
      expect(node.name).toBe('PHGap2 模块');
      expect(node.children).toEqual([expect.objectContaining({ code: 'phgaptwo:*' })]);
    });

    test('权限查询故障 → 返回空树而非抛错', async () => {
      const spy = jest.spyOn(Permission, 'find').mockImplementation(() => {
        throw new Error('db down (故障注入)');
      });
      try {
        await expect(helper.getMenuTree(users.full._id)).resolves.toEqual([]);
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('权限判定函数的错误分支（一律 fail-closed 返回 false）', () => {
    const withBrokenDb = async (fn) => {
      const spy = jest.spyOn(User, 'findById').mockImplementation(() => {
        throw new Error('db down (故障注入)');
      });
      try {
        return await fn();
      } finally {
        spy.mockRestore();
      }
    };

    test('hasPermission：正常判定 + 故障 → false', async () => {
      await expect(helper.hasPermission(users.full._id, 'phgap:list')).resolves.toBe(true);
      await expect(helper.hasPermission(users.full._id, 'nope:none')).resolves.toBe(false);
      await withBrokenDb(async () => {
        await expect(helper.hasPermission(users.full._id, 'phgap:list')).resolves.toBe(false);
      });
    });

    test('hasAnyPermission：任一命中 + 空入参 + 故障 → false', async () => {
      await expect(
        helper.hasAnyPermission(users.full._id, ['nope:none', 'phgap:export'])
      ).resolves.toBe(true);
      await expect(helper.hasAnyPermission(users.full._id, ['nope:none'])).resolves.toBe(false);
      await expect(helper.hasAnyPermission(users.full._id, undefined)).resolves.toBe(false);
      await withBrokenDb(async () => {
        await expect(helper.hasAnyPermission(users.full._id, ['phgap:list'])).resolves.toBe(false);
      });
    });

    test('hasAllPermissions：全部命中 / 缺一即否 / 故障 → false', async () => {
      await expect(
        helper.hasAllPermissions(users.full._id, ['phgap:view', 'phgap:list'])
      ).resolves.toBe(true);
      await expect(
        helper.hasAllPermissions(users.full._id, ['phgap:view', 'nope:none'])
      ).resolves.toBe(false);
      await withBrokenDb(async () => {
        await expect(helper.hasAllPermissions(users.full._id, ['phgap:view'])).resolves.toBe(false);
      });
    });

    test('hasRole：字符串/数组入参 + 故障 → false', async () => {
      await expect(
        helper.hasRole(users.full._id, `PHGAP_ROLE_${stamp.toUpperCase()}`)
      ).resolves.toBe(true);
      await expect(
        helper.hasRole(users.full._id, ['NOPE_ROLE', `PHGAP_ROLE_${stamp.toUpperCase()}`])
      ).resolves.toBe(true);
      await expect(helper.hasRole(users.full._id, 'NOPE_ROLE')).resolves.toBe(false);
      await withBrokenDb(async () => {
        await expect(
          helper.hasRole(users.full._id, `PHGAP_ROLE_${stamp.toUpperCase()}`)
        ).resolves.toBe(false);
      });
    });
  });

  describe('getUserRoles / getDataScope', () => {
    test('getUserRoles：返回角色要素；用户不存在 → 空数组；故障 → 空数组', async () => {
      const roles = await helper.getUserRoles(users.full._id);
      expect(roles).toEqual([
        expect.objectContaining({ code: `PHGAP_ROLE_${stamp.toUpperCase()}`, level: 1 }),
      ]);
      await expect(helper.getUserRoles(new mongoose.Types.ObjectId())).resolves.toEqual([]);

      const spy = jest.spyOn(User, 'findById').mockImplementation(() => {
        throw new Error('db down (故障注入)');
      });
      try {
        await expect(helper.getUserRoles(users.full._id)).resolves.toEqual([]);
      } finally {
        spy.mockRestore();
      }
    });

    test('getUserRoles：停用角色不返回，与 hasRole/getUserPermissions 同口径（P3-8 第三处）', async () => {
      // 前提先钉住：库里这个用户确实挂着 2 个角色、其中 1 个是 inactive。
      // 没有这条，"match 写错导致全被过滤"也会让下面的断言变绿（假绿）。
      const raw = await User.findById(users.mixed._id).select('roles').lean();
      expect(raw.roles).toHaveLength(2);
      await expect(
        Role.countDocuments({ _id: { $in: raw.roles }, status: 'inactive' })
      ).resolves.toBe(1);

      const activeCode = `PHGAP_ROLE_${stamp.toUpperCase()}`;
      const codes = (await helper.getUserRoles(users.mixed._id)).map((r) => r.code);
      // 精确等值（不是 not.toContain）：全空数组也算红
      expect(codes).toEqual([activeCode]);

      // 一致性：同一用户对三处判定的结论必须相同，否则"调了哪个函数"决定权限
      await expect(helper.hasRole(users.mixed._id, ROLE_OFF_CODE)).resolves.toBe(false);
      await expect(helper.hasRole(users.mixed._id, activeCode)).resolves.toBe(true);
      const info = await helper.getUserPermissions(users.mixed._id);
      expect(info.user.roles.map((r) => r.code)).toEqual([activeCode]);
      expect(info.permissions).not.toContain('phoff:view');
    });

    test('getDataScope：委托 rbac 层返回数据范围对象', async () => {
      const scope = await helper.getDataScope(users.full._id);
      expect(scope).toBeTruthy();
      expect(typeof scope).toBe('object');
    });
  });
});
