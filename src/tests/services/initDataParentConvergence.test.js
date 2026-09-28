/**
 * 权限播种必须能自愈历史 parent 漂移
 *
 * 背景（initData.js 注释自证的事故）：2026-09-18 之前，模块通配符权限（user:* 等 10 条）
 * 被挂到**自己**身上形成自环，其下 37 个子权限从 /api/roles/permissions/tree 整体消失，
 * 角色权限编辑页拿不到任何可勾选项。代码侧已修（显式跳过通配符自身），
 * 但**数据侧的残留没有任何修复路径**：
 *   initPermissions 的 parent 关联只遍历 toInsert（本次新插的行），
 *   而自环/悬空的那些行"本来就存在" ⇒ 永远不在 toInsert 里 ⇒ 永远不再被关联。
 *   全库已播种时更早退（toInsert 为空直接 return），连对账都不走。
 * 于是"改完代码树就正常了"只在空库成立；已有部署里那个坏掉的权限树不会因为升级而恢复，
 * 而运维看到的是"重启多次、接口 200、树依旧空"。
 *
 * 判据分工：
 *   1. 自愈判据：库里预置自环 + 悬空行 ⇒ 播种后必须被纠正
 *   2. 反向对照：已收敛的库重复播种不重写（对账 ≠ 每次全量 $set）
 *   3. 爆炸半径：目录外的自定义权限不得被关联、不得被删
 *   4. 口径：目录内的权限以目录为准（运维手工挂错的父级会被收回，
 *      与内置角色每次启动对账 rolePermissionMap 同一条口径）
 */

'use strict';

const mongoose = require('mongoose');
const Permission = require('../../models/Permission');
const { initPermissions, defaultPermissions } = require('../../services/initData');

const findPerm = async (code) => Permission.findOne({ code }).select('parent').lean();

describe('initPermissions 的 parent 对账与自愈', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('历史残留（通配符自环 + 子权限悬空）在下次播种时被纠正', async () => {
    await Permission.deleteMany({});
    const wildcard = await Permission.create({
      name: '用户管理菜单',
      code: 'user:*',
      type: 'menu',
      module: 'system',
      path: '/system/users',
    });
    // 事故原貌：parent 指向自己
    await Permission.updateOne({ _id: wildcard._id }, { $set: { parent: wildcard._id } });
    await Permission.create({
      name: '查看用户列表',
      code: 'user:read',
      type: 'api',
      module: 'system',
      path: '/api/users',
      method: 'GET',
    });

    // 前提自证：两行确实处于坏状态（它们"本来就存在"，不在本次新插集合里）
    expect(String((await findPerm('user:*')).parent)).toBe(String(wildcard._id));
    expect((await findPerm('user:read')).parent).toBeNull();

    await initPermissions();

    const wildcardAfter = await findPerm('user:*');
    expect(wildcardAfter.parent).toBeNull();
    const readAfter = await findPerm('user:read');
    expect(String(readAfter.parent)).toBe(String(wildcard._id));
    // 目录内其余非通配符权限同样必须已挂上（不是只修了我手动预置的那两条）
    const idByCode = new Map(
      (await Permission.find({}).select('code parent').lean()).map((d) => [
        d.code,
        d.parent ? String(d.parent) : null,
      ])
    );
    const codeToId = new Map(
      (await Permission.find({}).select('code').lean()).map((d) => [d.code, String(d._id)])
    );
    const orphans = defaultPermissions
      .map((p) => p.code)
      .filter((code) => !code.endsWith(':*'))
      .filter((code) => idByCode.get(code) !== codeToId.get(`${code.split(':')[0]}:*`));
    expect(orphans).toEqual([]);
  });

  test('反向对照：已收敛的库重复播种不发起写入（对账不等于每次重写）', async () => {
    await Permission.deleteMany({});
    await initPermissions();
    const snapshot = async () =>
      (await Permission.find({}).select('code parent').lean())
        .map((d) => `${d.code}=${d.parent ? String(d.parent) : 'null'}`)
        .sort();
    const before = await snapshot();

    const bulkSpy = jest.spyOn(Permission, 'bulkWrite');
    const insertSpy = jest.spyOn(Permission, 'insertMany');
    try {
      await initPermissions();
    } finally {
      expect(bulkSpy.mock.calls.length).toBe(0);
      expect(insertSpy.mock.calls.length).toBe(0);
      bulkSpy.mockRestore();
      insertSpy.mockRestore();
    }
    expect(await snapshot()).toEqual(before);
  });

  test('爆炸半径：目录外的自定义权限既不挂父也不被删', async () => {
    await Permission.deleteMany({});
    await initPermissions();
    const custom = await Permission.create({
      name: '自定义报表导出',
      code: 'custom:export',
      type: 'api',
      module: 'custom',
      path: '/api/custom/export',
      method: 'POST',
    });
    await initPermissions();
    const after = await Permission.findOne({ code: 'custom:export' }).select('parent').lean();
    expect(after).not.toBeNull();
    expect(after.parent).toBeNull();
    expect(String(after._id)).toBe(String(custom._id));
    // 目录内的行仍须全部存在（自愈遍历的是目录，不得顺手清理别人）
    expect(await Permission.countDocuments({})).toBe(defaultPermissions.length + 1);
  });

  test('口径：目录内的权限以目录为准（手工挂错的父级被收回）', async () => {
    await Permission.deleteMany({});
    await initPermissions();
    const deviceWildcard = await Permission.findOne({ code: 'device:*' });
    // 运维把 user:read 手工挪到设备模块下：按目录它属于 user:*
    await Permission.updateOne({ code: 'user:read' }, { $set: { parent: deviceWildcard._id } });
    expect(String((await findPerm('user:read')).parent)).toBe(String(deviceWildcard._id));

    await initPermissions();
    const userWildcard = await Permission.findOne({ code: 'user:*' });
    expect(String((await findPerm('user:read')).parent)).toBe(String(userWildcard._id));
  });
});
