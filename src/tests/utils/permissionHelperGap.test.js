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
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`_${stamp}$`, 'i') }).catch(() => {});
      await Permission.deleteMany({ module: { $in: ['phgap', 'phgaptwo', 'phother'] } }).catch(
        () => {}
      );
      await mongoose.connection.close();
    }
  });

  describe('getUserPermissions', () => {
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

    test('getDataScope：委托 rbac 层返回数据范围对象', async () => {
      const scope = await helper.getDataScope(users.full._id);
      expect(scope).toBeTruthy();
      expect(typeof scope).toBe('object');
    });
  });
});
