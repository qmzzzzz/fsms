/**
 * 登录/刷新返回的权限快照语义
 *
 * 被测改动：issueLoginSession 的 populate 新增 `match:{status:'active'}`
 * （roles 与嵌套 permissions 两层）——登录响应即客户端权限快照，含停用项会让
 * 前端渲染出服务端必然 403 的控件。这条行为此前**没有任何用例覆盖**。
 *
 * 为什么标题盯着 null：派发评审的子 agent 断言"嵌套 match 会在数组里留下 null 占位，
 * 少一层 filter 就必 500"。我按提示做了修复并写用例，结果**变异存活**——回退修复后
 * 四条用例全绿。于是实测三种形态（探针脚本，跑完即删）：
 *   A 权限项被停用（match 过滤掉）→ populate 结果是 [生效项]，无 null
 *   B 权限文档被直连删除（悬空引用）→ 同上，元素被丢弃而非置 null
 *   C Role.permissions 数组里存了字面 null → 读出来照样没有 null
 * 结论：Mongoose 对**数组路径**的 populate 从不留 null 洞（未命中即丢元素），
 * 所以该 500 结论不成立，我的修复也已回退。真正需要钉住的是快照语义本身，
 * 也就是下面四条。（会把值变成 null 的是**单文档路径**：非数组 ref 未命中时
 * populate 结果就是 null——那才是 r?.code 这类守卫该出现的地方。）
 *
 * 断言取的都是外部可观察面（loginUser 返回值），不是源码文本。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('登录权限快照：只含生效角色/权限项', () => {
  const PASSWORD = randomPassword();
  const stamp = `zzqp${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 12);
  const createdUsers = [];

  let User;
  let Role;
  let Permission;
  let authService;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    require('../models/TokenBlacklist');
    require('../models/AuditLog');
    authService = require('../services/authService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const makePerm = (action, status = 'active') =>
    Permission.create({
      name: `${stamp} 权限 ${action}`,
      code: `device:${action}`,
      module: 'device',
      status,
    });

  const login = async (user) =>
    authService.loginUser(
      { username: user.username, password: PASSWORD },
      {
        ip: '127.0.0.1',
        userAgent: 'probe-agent',
        fingerprint: 'probe-fp',
        method: 'POST',
        path: '/api/auth/login',
        req: { headers: { 'user-agent': 'probe-agent' }, ip: '127.0.0.1', connection: {} },
      }
    );

  const makeUserWithRole = async (suffix, permissionIds, roleExtra = {}) => {
    const role = await Role.create({
      name: `${stamp}角色${suffix}`,
      code: `ZZQO_${suffix.toUpperCase()}`,
      level: 3,
      permissions: permissionIds,
      ...roleExtra,
    });
    const user = await User.create({
      username: `${stamp}${suffix}`,
      email: `${stamp}${suffix}@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    createdUsers.push(user._id);
    return user;
  };

  test('核心：角色上挂着"停用权限项"时登录仍成功，且快照只含生效项', async () => {
    const on = await makePerm('read');
    const off = await makePerm('purge', 'inactive');
    const user = await makeUserWithRole('mix', [on._id, off._id]);

    // 修复前：这里不是断言失败而是抛 TypeError（populate 留下的 null 上取 .code）
    const result = await login(user);

    expect(result.outcome).toBe('OK');
    expect(result.user.permissions).toContain(on.code);
    expect(result.user.permissions).not.toContain(off.code);
  });

  test('快照数组里不得出现 null/undefined 元素（外部可见的形态契约）', async () => {
    const on = await makePerm('export');
    const off = await makePerm('destroy', 'inactive');
    const user = await makeUserWithRole('shape', [on._id, off._id]);

    const result = await login(user);

    expect(result.user.permissions.length).toBeGreaterThan(0);
    expect(result.user.permissions.every((c) => typeof c === 'string' && c.length > 0)).toBe(true);
  });

  test('反向保护：权限项全部生效时快照一个不少（filter 不得变成一刀切）', async () => {
    const a = await makePerm('list');
    const b = await makePerm('create');
    const user = await makeUserWithRole('allon', [a._id, b._id]);

    const result = await login(user);

    expect(result.user.permissions).toEqual(expect.arrayContaining([a.code, b.code]));
    expect(result.user.permissions).toHaveLength(2);
  });

  test('悬空引用（权限文档已被删）同样不得打穿登录', async () => {
    const alive = await makePerm('query');
    const doomed = await makePerm('wiped');
    const user = await makeUserWithRole('dangling', [alive._id, doomed._id]);
    // 直连集合删掉：绕过任何"软删/停用"的业务入口，模拟数据修复脚本留下的悬空 ref
    await Permission.collection.deleteOne({ _id: doomed._id });

    const result = await login(user);

    expect(result.outcome).toBe('OK');
    expect(result.user.permissions).toEqual([alive.code]);
  });

  test('另一半改动面：角色被停用时，该角色的权限也不得出现在快照里', async () => {
    const perm = await makePerm('audit');
    const user = await makeUserWithRole('offrole', [perm._id]);
    // 停用整个角色（正常运维入口的落库效果）
    await Role.collection.updateOne({ _id: user.roles[0] }, { $set: { status: 'inactive' } });

    const result = await login(user);

    expect(result.outcome).toBe('OK');
    expect(result.user.roles).toEqual([]);
    expect(result.user.permissions).toEqual([]);
  });
});
