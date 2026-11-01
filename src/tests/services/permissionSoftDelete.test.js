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
 *   ⑥ 写路径覆盖（F4/F8，第十一轮）：过滤判据只有 softDeleteExempt 一处，读路径与写钩子共用——
 *      `pre(/^find/)` 在 mongoose 8.24.1 下**也覆盖 findOneAndUpdate/findOneAndReplace**（实测），
 *      原先它只认 filter 不认 update 文档，于是用 findOneAndUpdate 做恢复恒返回 null、DB 里
 *      deletedAt 不变，且不报错；故那两个 op 不再单独注册钩子（重复注册只会让读者以为它们没走）。
 *      `estimatedDocumentCount` 则恰好相反：该命令**没有 filter 形参**，钩子改不到它，注册只会让读
 *      代码的人以为墓碑已被排除（实测 est=2 而 countDocuments=1）——要排除墓碑只能用 countDocuments。
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

  /*
   * D5（2026-10-30 审计）：软删除过滤原先只覆盖 /^find/ 与 countDocuments，
   * updateOne/updateMany/aggregate 等路径会**就地改掉已删除的行**——而本文件开头那条
   * 「文档永不离开集合、保留期后可复核」的承诺，靠的正是「已删除 = 只读墓碑」。
   * 下面三条把「写路径看不见 / 显式状态变更放行 / 读路径不泄露」钉成行为判据。
   */
  test('写路径同样看不见软删除文档：updateOne / updateMany 不得命中', async () => {
    const perm = await makePerm('wexcl');
    await service.deletePermission(perm._id);

    // 反例对照：同一条 update 打在**活跃**行上必须命中 —— 否则下面的 0 可能只是「判据没接线」
    const active = await makePerm('wact');
    const hit = await Permission.updateOne({ _id: active._id }, { $set: { sort: 9 } });
    expect(hit.modifiedCount).toBe(1);

    const one = await Permission.updateOne({ _id: perm._id }, { $set: { name: '被改掉的名字' } });
    expect(one.modifiedCount).toBe(0);

    const many = await Permission.updateMany(
      { module: perm.module },
      { $set: { description: '批量改' } }
    );
    expect(many.modifiedCount).toBe(0);

    // 物理上确实没被改动（不是「看着没改」）
    expect((await rawDoc(perm._id)).name).toBe(perm.name);
  });

  test('显式状态变更必须放行：$set.deletedAt 与 includeDeleted 两条口子不被追加条件吃掉', async () => {
    const perm = await makePerm('rest');
    await service.deletePermission(perm._id);
    expect(await Permission.findById(perm._id)).toBeNull();

    // 与 permissionService 的补偿路径同形：过滤条件只给 _id，靠「更新文档在动 deletedAt」放行
    const r = await Permission.updateOne({ _id: perm._id }, { $set: { deletedAt: null } });
    expect(r.matchedCount).toBe(1);
    expect(await Permission.findById(perm._id)).not.toBeNull();

    // includeDeleted: true 是显式后门：能改已删除的行（播种/运维修复用）
    await service.deletePermission(perm._id);
    const viaOption = await Permission.updateOne(
      { _id: perm._id },
      { $set: { sort: 7 } },
      { includeDeleted: true }
    );
    expect(viaOption.modifiedCount).toBe(1);
  });

  test('读路径不泄露软删除的 code：distinct / aggregate 与 find 同口径', async () => {
    const perm = await makePerm('readpath');
    await service.deletePermission(perm._id);

    expect(await Permission.distinct('code', { module: perm.module })).toEqual([]);
    expect(await Permission.aggregate([{ $match: { module: perm.module } }])).toEqual([]);

    // 反例对照：活跃行的同两条查询必须命中，否则「上面是空」可能只是查询写错了
    const live = await makePerm('readlive');
    expect(await Permission.distinct('code', { module: live.module })).toEqual([live.code]);
    const aggLive = await Permission.aggregate([{ $match: { module: live.module } }]);
    expect(aggLive.map((d) => d.code)).toEqual([live.code]);
  });
  /*
   * F4（第十一轮审计）：pre(/^find/) 对 findOneAndUpdate 同样生效并追加 deletedAt:null，
   * 而「更新文档在动 deletedAt」这条放行口子原先只挂在 updateOne/updateMany/replaceOne 上
   * ⇒ 用 findOneAndUpdate 做恢复恒返回 null、DB 里 deletedAt 不变，且不报错。
   * 下面三条把「恢复真的生效」与「普通更新仍看不见墓碑」同时钉住。
   */
  test('findOneAndUpdate 恢复必须真的生效（不得静默返回 null）', async () => {
    const perm = await makePerm('fau');
    await service.deletePermission(perm._id);

    const restored = await Permission.findOneAndUpdate(
      { _id: perm._id },
      { $set: { deletedAt: null } },
      { new: true }
    );
    expect(restored).not.toBeNull();
    expect((await rawDoc(perm._id)).deletedAt).toBeNull();
  });

  test('findOneAndUpdate 普通更新仍看不见墓碑（放行口子只认 deletedAt 本身）', async () => {
    const perm = await makePerm('fag');
    await service.deletePermission(perm._id);

    const hit = await Permission.findOneAndUpdate(
      { _id: perm._id },
      { $set: { sort: 3 } },
      { new: true }
    );
    expect(hit).toBeNull();
    expect((await rawDoc(perm._id)).sort).not.toBe(3);
  });

  test('findOneAndReplace 恢复同样生效（replace 形态没有 $set）', async () => {
    const perm = await makePerm('far');
    await service.deletePermission(perm._id);
    const raw = await rawDoc(perm._id);

    const restored = await Permission.findOneAndReplace(
      { _id: perm._id },
      { ...raw, deletedAt: null },
      { new: true }
    );
    expect(restored).not.toBeNull();
    expect((await rawDoc(perm._id)).deletedAt).toBeNull();
  });

  /*
   * F8：estimatedDocumentCount 的命令**不吃 filter**（第十一轮实测 est=2 而 countDocuments=1），
   * 原先注册的 pre('estimatedDocumentCount') 只会让读代码的人以为墓碑已被排除。判据改成
   * 「按实测钉住命令语义 + 模型不得再注册这个钩子」。
   */
  test('estimatedDocumentCount 不吃 filter：墓碑计入估算，排除墓碑只能用 countDocuments', async () => {
    const perm = await makePerm('fest');
    const before = await Permission.estimatedDocumentCount();
    await service.deletePermission(perm._id);
    expect(await Permission.estimatedDocumentCount()).toBe(before);
    expect(await Permission.countDocuments({ code: perm.code })).toBe(0);
  });

  test('模型不得再注册 estimatedDocumentCount 过滤器（该命令没有 filter 形参）', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '../../models/Permission.js'), 'utf8');
    expect(src).not.toMatch(/pre\('estimatedDocumentCount'/);
  });
});
