/**
 * 保留通配权限 `*:*` 不得被停用（停用＝全体超管瞬间自锁，只能直连数据库救）
 * （复核 提的 HIGH；A 自己在控制器加守卫时撞了 lint:ratchet 复杂度基线而回退，
 *  正解是把校验放到服务层唯一落库出口 —— 见 A 的原话与本技术文档 6-Z）
 *
 * 现状核对（实测，不是照抄 A 的结论）：
 *  - 铸造路径已封：permissionRoutes 的 create / batch-create 都带 `.not().equals('*:*')`
 *  - 删除路径已封：deletePermission 先查 `Role.countDocuments({permissions:id})`，
 *    而 SUPER_ADMIN 恒引用 `*:*`（initData:432）⇒ 走不到删除
 *  - **停用路径没封**：控制器 `if (status !== undefined) permission.status = status;`
 *    之后直接 savePermission ⇒ PUT 一个 `{status:'inactive'}` 就把超管的唯一权限源关掉
 *
 * 为什么放在 savePermission：它是 update 路径唯一的落库出口
 * （grep 全仓：savePermission 只有 permissionController.js:146 一个调用方），
 * 在这里拦既避开控制器复杂度棘轮，也不给未来新增调用方留绕过面。
 */
const mongoose = require('mongoose');

const RESERVED = '*:*';

describe('保留通配权限的停用防线', () => {
  let Permission;
  let Role;
  let service;
  const stamp = `zzrw${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);
  // 这条 `*:*` 是不是本套件建的——决定 afterAll 有没有资格删它（见下方注释）
  let createdByUs = false;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Permission = require('../models/Permission');
    Role = require('../models/Role');
    service = require('../services/permissionService');
    // 一次 jest 调用只有**一个** mongod，所有套件共用同一个库，而 Permission.code 是
    // unique。全仓有十几套用例各自 upsert 一条 `*:*`（如 statsAnomalyScope、
    // auditDataScope、assignRoles），所以原来的 Permission.create 只要撞上别人的
    // 生命周期就是 E11000、整组用例红——红不红取决于落到哪个 worker、时序怎么交错。
    // 改成"有就复用、没有才建"，并记住归属，删除侧才谈得上只清自己那条。
    const existing = await Permission.findOne({ code: RESERVED }).lean();
    if (existing) {
      createdByUs = false;
    } else {
      await Permission.create({
        name: `${stamp} 保留通配`,
        code: RESERVED,
        type: 'api',
        module: 'system',
        status: 'active',
      });
      createdByUs = true;
    }
  });

  afterAll(async () => {
    // 只删自己建的那条：按 code 删会把别人正在引用的 `*:*` 一起删掉，
    // 留下角色侧的悬空 permissions 引用——那正是本套件想避免的那类跨套件污染。
    if (createdByUs) {
      await Permission.deleteMany({ code: RESERVED }).catch(() => {});
    }
    // `zzrw:read` 是上一条用例建的普通权限，原来漏了清理：它会留在共享库里
    // 被任何按 module/code 统计权限的用例读到。
    await Permission.deleteMany({ code: 'zzrw:read' }).catch(() => {});
    await Role.deleteMany({ name: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const reload = () => Permission.findOne({ code: RESERVED }).select('status name').lean();

  test('停用保留通配必须被拒，且库里仍然是 active', async () => {
    const perm = await Permission.findOne({ code: RESERVED });
    perm.status = 'inactive';
    await expect(service.savePermission(perm)).rejects.toThrow();
    expect((await reload()).status).toBe('active');
  });

  test('拒绝要落到 4xx 语义（ApiError.badRequest），不能是 500', async () => {
    const perm = await Permission.findOne({ code: RESERVED });
    perm.status = 'inactive';
    await expect(service.savePermission(perm)).rejects.toMatchObject({ statusCode: 400 });
  });

  test('反向保护：保留通配的普通字段仍可维护（防线不得变成不可编辑）', async () => {
    const perm = await Permission.findOne({ code: RESERVED });
    perm.name = `${stamp} 改名后的保留通配`;
    const saved = await service.savePermission(perm);
    // 只断言"合法维护能通过"。这里刻意不再断言 status：
    // 缺陷未修时前两用例会真的把该行写成 inactive，那条状态断言会变成
    // 依赖用例顺序的附带耦合，而不是本例要证的命题。
    expect(saved.name).toBe(`${stamp} 改名后的保留通配`);
  });

  test('普通权限仍可正常停用（窄化只针对保留通配，不得顺手扩大）', async () => {
    const normal = await Permission.create({
      name: `${stamp} 普通权限`,
      code: 'zzrw:read',
      type: 'api',
      module: 'zzrw',
      status: 'active',
    });
    normal.status = 'inactive';
    const saved = await service.savePermission(normal);
    expect(saved.status).toBe('inactive');
  });

  test('删除路径的既有防线：被角色引用即拒（记录为"已封"，不需要再加一道）', async () => {
    const role = await Role.create({
      name: `${stamp} 引用者`,
      code: `ZZRW_${stamp}`.replace(/[^A-Z0-9_]/g, '_'),
      level: 5,
      permissions: [await Permission.findOne({ code: RESERVED }).then((p) => p._id)],
    });
    const target = await Permission.findOne({ code: RESERVED });
    await expect(service.deletePermission(target._id)).rejects.toThrow(/引用/);
    await Role.deleteOne({ _id: role._id }).catch(() => {});
  });
});
