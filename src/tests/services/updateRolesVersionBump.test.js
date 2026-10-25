/**
 * updateRoles 必须推进 __v，否则 User.save() 的乐观并发过滤形同虚设
 *
 * 用户更新/锁定路径的做法是「载入文档 → 校验 → save()」，save 的过滤条件
 * 含载入时的 __v。若并发的角色分配只 `$set roles` 而不动 __v，save 仍会命中，
 * 把基于**旧角色快照**做的层级/权限判定结果写回去（越权授予的分支被带进库）。
 * 同时保留 expectedRoles 条件写的语义：角色已变 ⇒ 不写。
 */

const mongoose = require('mongoose');

describe('updateRoles 与 __v 乐观并发', () => {
  let User;
  let userService;
  const stamp = `rv${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]).slice(0, 10);
  const ids = [
    new mongoose.Types.ObjectId(),
    new mongoose.Types.ObjectId(),
    new mongoose.Types.ObjectId(),
  ];
  let user;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    userService = require('../../services/userService');
    user = await User.create({
      username: `${stamp}u`,
      email: `${stamp}u@example.com`,
      password: 'Test@1234567',
      roles: [ids[0]],
    });
  });

  afterAll(async () => {
    await User.deleteMany({ _id: user._id }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('并发的角色变更会让随后基于旧快照的 save 抛 VersionError', async () => {
    const staleDoc = await User.findById(user._id);

    await userService.updateRoles(user._id, [ids[1]]);

    staleDoc.roles = [ids[0], ids[2]];
    await expect(staleDoc.save()).rejects.toMatchObject({ name: 'VersionError' });

    const after = await User.findById(user._id).select('roles');
    expect(after.roles.map(String)).toEqual([String(ids[1])]);
  });

  test('expectedRoles 条件写：快照不符时返回 null，不覆盖当前角色', async () => {
    const missed = await userService.updateRoles(user._id, [ids[2]], [ids[0]]);
    expect(missed).toBeNull();

    const after = await User.findById(user._id).select('roles');
    expect(after.roles.map(String)).toEqual([String(ids[1])]);
  });
});
