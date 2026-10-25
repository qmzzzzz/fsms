/**
 * 权限删除改为软删除（#7）
 *
 * 原实现 `findByIdAndDelete` → 复核引用 → 冲突时 `Permission.create(removed)` 恢复。
 * 这条链的缺口在"恢复"本身：恢复失败（进程崩溃、写超时、并发重建同 code）时权限
 * 真的消失，而 Role.permissions 里还留着指向不存在文档的悬空 id——且失败时没有把
 * 被删文档写进日志，人工连重建的依据都没有。
 *
 * 现在删除 = 打 `deletedAt`，文档永不离开集合。本文件钉四层：
 *   ① 删除语义：默认查询不可见，原始集合里文档仍在且带标记；
 *   ② 编码不释放：同 code 不能重建（unique 索引仍被占用），错误要说清原因；
 *   ③ 冲突补偿：有子权限/被角色引用时拒绝，且父文档必须恢复为可见（standalone 无事务）；
 *   ④ 最后兜底：补偿写失败也不得丢数据，完整文档必须落日志；
 *   ⑤ 启动自愈：目录内的内置权限被软删除后，initPermissions 会恢复它。
 */

const mongoose = require('mongoose');

describe('权限软删除（#7 先删后复核窗口根治）', () => {
  let Permission;
  let Role;
  let service;
  let logger;
  let initPermissions;
  // Permission.code 的模块段只允许小写字母（^[a-z]+:[a-z_]+$），时间戳必须转成字母
  const stamp = String(Date.now())
    .replace(/\d/g, (d) => 'abcdefghij'[Number(d)])
    .slice(-8);
  const code = (suffix) => `zzsd${stamp}${suffix}:read`;
  const createdCodes = [];
  const createdRoleIds = [];

  const makePerm = async (suffix, extra = {}) => {
    const permission = await Permission.create({
      name: `软删夹具_${suffix}_${stamp}`,
      code: code(suffix),
      type: 'api',
      module: `zzsd${stamp}${suffix}`,
      ...extra,
    });
    createdCodes.push(permission.code);
    return permission;
  };

  /** 绕过模型的软删过滤器读原始文档（断言"物理上还在"） */
  const rawDoc = (id) => Permission.collection.findOne({ _id: new mongoose.Types.ObjectId(id) });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Permission = require('../../models/Permission');
    Role = require('../../models/Role');
    service = require('../../services/permissionService');
    logger = require('../../utils/logger');
    ({ initPermissions } = require('../../services/initData/seeding'));
  });

  afterAll(async () => {
    await Permission.deleteMany({ code: { $in: createdCodes } }).catch(() => {});
    await Role.deleteMany({ _id: { $in: createdRoleIds } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('删除成功 = 打标记：默认查询不可见，原始文档仍在且 deletedAt 非空', async () => {
    const perm = await makePerm('del');

    await expect(service.deletePermission(perm._id)).resolves.toBe(true);

    expect(await Permission.findById(perm._id)).toBeNull();
    expect(await Permission.countDocuments({ code: perm.code })).toBe(0);
    expect(await Permission.find({ module: perm.module })).toHaveLength(0);

    const raw = await rawDoc(perm._id);
    expect(raw).not.toBeNull();
    expect(raw.deletedAt).toBeInstanceOf(Date);

    // 显式 includeDeleted 才看得见 —— 这是播种/编码占用检查依赖的唯一后门
    const included = await Permission.findById(perm._id).setOptions({ includeDeleted: true });
    expect(included).not.toBeNull();
  });

  test('编码不被释放：已被软删除的 code 不能重建，400 要指明占用来源', async () => {
    const perm = await makePerm('reuse');
    await service.deletePermission(perm._id);

    await expect(
      service.createPermission({
        name: '重复编码',
        code: perm.code,
        type: 'api',
        module: perm.module,
      })
    ).rejects.toMatchObject({ statusCode: 400, message: expect.stringContaining('已删除') });
  });

  test('有子权限时拒绝删除，且父权限在 standalone 补偿后立刻恢复可见', async () => {
    const parent = await makePerm('parent');
    const child = await makePerm('child', { parent: parent._id });

    await expect(service.deletePermission(parent._id)).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('子权限'),
    });

    // 补偿必须发生：否则父权限在默认查询里"消失"，而接口返回的却是 400
    const reloaded = await Permission.findById(parent._id);
    expect(reloaded).not.toBeNull();
    expect((await rawDoc(parent._id)).deletedAt).toBeNull();
    // 子权限未被波及
    expect(await Permission.findById(child._id)).not.toBeNull();
  });

  test('被角色引用时拒绝删除，且权限恢复可见（引用不悬空）', async () => {
    const perm = await makePerm('ref');
    const role = await Role.create({
      name: `软删引用角色_${stamp}`,
      code: `ZZSD_REF_${stamp}`,
      level: 1,
      permissions: [perm._id],
    });
    createdRoleIds.push(role._id);

    await expect(service.deletePermission(perm._id)).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('引用'),
    });

    expect((await rawDoc(perm._id)).deletedAt).toBeNull();
    const stillThere = await Permission.findById(perm._id).lean();
    expect(stillThere).not.toBeNull();
    expect((await Role.findById(role._id)).permissions.map(String)).toContain(String(perm._id));
  });

  test('删除不存在的 ID 返回 false（不抛错，控制器按 404 处理）', async () => {
    await expect(service.deletePermission(new mongoose.Types.ObjectId())).resolves.toBe(false);
  });

  test('补偿写失败也不丢数据：文档仍在库中，完整文档写入错误日志', async () => {
    const parent = await makePerm('restorefail');
    await makePerm('restorefailchild', { parent: parent._id });

    const updateSpy = jest
      .spyOn(Permission, 'updateOne')
      .mockRejectedValueOnce(new Error('模拟恢复写入失败'));
    const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      await expect(service.deletePermission(parent._id)).rejects.toMatchObject({ statusCode: 500 });

      // 关键差异：原实现此时文档已被物理删除，只能靠 create 恢复；现在文档一定还在
      const raw = await rawDoc(parent._id);
      expect(raw).not.toBeNull();
      expect(raw.deletedAt).toBeInstanceOf(Date);

      const restoreLog = errorSpy.mock.calls.find(
        ([message]) => typeof message === 'string' && message.includes('恢复失败')
      );
      expect(restoreLog).toBeTruthy();
      // 人工重建所需的关键字段必须在日志里，而不只是 "失败了"
      expect(restoreLog[1]).toMatchObject({
        permissionId: String(parent._id),
        permission: expect.objectContaining({ code: parent.code, name: parent.name }),
      });
    } finally {
      updateSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  test('启动自愈：目录内的内置权限被软删除后，initPermissions 会把它恢复为可见', async () => {
    // 取叶子权限：模块根（如 system:*）有子权限，按设计删不掉，验不到恢复路径
    const builtInCode = 'user:read';
    const builtIn = await Permission.findOne({ code: builtInCode }).setOptions({
      includeDeleted: true,
    });
    // 该库此前未播种：先让 initPermissions 建出目录，再删其中一条
    if (!builtIn) {
      await initPermissions();
    }
    const target = await Permission.findOne({ code: builtInCode });
    expect(target).not.toBeNull();

    await expect(service.deletePermission(target._id)).resolves.toBe(true);
    expect(await Permission.findOne({ code: builtInCode })).toBeNull();

    await initPermissions();

    const restored = await Permission.findOne({ code: builtInCode });
    expect(restored).not.toBeNull();
    const raw = await Permission.collection.findOne({ _id: target._id });
    expect(raw.deletedAt).toBeNull();
  }, 60000);
});
