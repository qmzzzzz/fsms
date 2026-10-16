/**
 * 审计查看权与用户删除权的职责分离（A6，2026-10-16）
 *
 * 背景：`SECURITY_ADMIN` 同时持有 `user:delete` 与 `security:audit` —— 一个角色既能
 * 执行敏感操作、又能查看这些操作的审计记录。主篡改向量（改/删审计记录）已由审计链
 * （append-only + hash chain）覆盖，剩下的是合规口味问题：执行者与监督者不应是同一人。
 *
 * 本文件钉三件事，缺一条这个角色就白拆：
 *   ① 角色真的被播种（只登记不接线 = 缺陷）；
 *   ② 权限集**恰好两条只读**——多一条写权限，职责分离就名存实亡；
 *   ③ level 9（全量数据范围）是**刻意的**：与 SECURITY_ADMIN 同档（8 ⇒ 本部门）会让
 *      这个角色看不到本部门之外的审计记录，从而失去拆分意义。这条同时反向钉住
 *      "level 只影响数据范围、不授予权限"（否则 9 就成了提权）。
 */

const mongoose = require('mongoose');

const READ_ONLY_CODES = ['security:stats', 'security:audit'];
// 任何写语义的权限码后缀：AUDIT_VIEWER 一个都不许有
const WRITE_SUFFIXES = [
  ':create',
  ':update',
  ':delete',
  ':lock',
  ':reset_password',
  ':assign',
  ':assign_role',
  ':config',
  ':handle',
  ':dispatch',
  ':maintain',
  ':scrap',
  ':review',
  ':execute',
];

describe('AUDIT_VIEWER 只读审计角色（A6 职责分离）', () => {
  let Role;
  let Permission;
  let defaultRoles;
  let initPermissions;
  let initRoles;

  const rolePermCodes = async (code) => {
    const role = await Role.findOne({ code }).populate('permissions', 'code');
    return (role.permissions || []).map((p) => p.code).sort();
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ({ Role, Permission } = require('../../models'));
    // initPermissions / initRoles 都是**幂等且只增不删**的（缺什么补什么 +
    // 内置角色权限对账），因此这里可以安全地直接跑，不会清掉并发套件的数据。
    ({ defaultRoles, initPermissions, initRoles } = require('../../services/initData'));
    await initPermissions();
    await initRoles();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('角色已登记且被播种：AUDIT_VIEWER 存在、内置、level 9', async () => {
    const declared = defaultRoles.find((r) => r.code === 'AUDIT_VIEWER');
    expect(declared).toBeDefined();
    expect(declared.isBuiltIn).toBe(true);
    // level 9 = 全量数据范围（middleware/rbac.js:169）；与 SECURITY_ADMIN 同档会让
    // 这个角色看不到本部门之外的审计记录，拆分就失去意义
    expect(declared.level).toBe(9);

    const seeded = await Role.findOne({ code: 'AUDIT_VIEWER' });
    expect(seeded).not.toBeNull();
    expect(seeded.isBuiltIn).toBe(true);
  });

  test('权限集恰好两条只读，且一条写权限都没有（职责分离的核心）', async () => {
    const codes = await rolePermCodes('AUDIT_VIEWER');
    expect(codes).toEqual([...READ_ONLY_CODES].sort());

    const offenders = codes.filter((c) => WRITE_SUFFIXES.some((s) => c.endsWith(s)));
    expect({ offenders }).toEqual({ offenders: [] });
  });

  test('前提自证：两条只读权限确实存在于权限目录（否则 populate 为空会让上一条恒真）', async () => {
    const found = await Permission.find({ code: { $in: READ_ONLY_CODES } })
      .select('code')
      .lean();
    expect(found.map((p) => p.code).sort()).toEqual([...READ_ONLY_CODES].sort());
  });

  test('职责分离成立：SECURITY_ADMIN 有 user:delete，AUDIT_VIEWER 没有；且后者权限是前者的子集', async () => {
    const admin = await rolePermCodes('SECURITY_ADMIN');
    const viewer = await rolePermCodes('AUDIT_VIEWER');

    // 执行者：能删用户
    expect(admin).toContain('user:delete');
    // 监督者：不能删用户 —— 这正是拆分的意义
    expect(viewer).not.toContain('user:delete');
    // 监督者的权限不得超出被监督者（否则它反而拿到额外能力）
    expect(viewer.every((c) => admin.includes(c))).toBe(true);
    // 反向：两者权限集不相等，证明真的拆出了两个角色而不是复制一份
    expect(viewer).not.toEqual(admin);
  });
});
