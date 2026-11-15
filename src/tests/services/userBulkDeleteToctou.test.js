/**
 * P3：批量删除无快照路径的 TOCTOU 收口。
 *
 * 旧实现在"预取 id"之后仍以**原过滤器** deleteMany：预取与删除的窗口内新命中过滤器的
 * 用户会被顺带删掉，却不在级联（头像/进行中指派）的 id 清单里——删了人、漏了清理。
 * 现实现以预取 id（$in）删除：删除面与级联严格同源，窗口内新命中者不属本批、不被删除。
 *
 * 窗口模拟：spy User.deleteMany，在真正执行删除前插入一名"恰好命中过滤器"的用户，
 * 等价于两次库操作之间发生了并发写入。
 */
const mongoose = require('mongoose');

describe('userService.deleteMany 无快照路径的 TOCTOU（P3）', () => {
  let User;
  let UserAvatar;
  let FireAlarm;
  let userService;
  const createdUserIds = [];
  const DEPT = `P3TOCTOU${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const mkUser = async (tag) => {
    const u = await User.create({
      username: `${DEPT.toLowerCase()}_${tag}`,
      email: `${DEPT.toLowerCase()}_${tag}@example.com`,
      password: 'Qz7#Lm42vTx9',
      department: DEPT,
    });
    createdUserIds.push(u._id);
    return u;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    UserAvatar = require('../../models/UserAvatar');
    FireAlarm = require('../../models/FireAlarm');
    require('../../models/Role');
    userService = require('../../services/userService');
  });

  afterAll(async () => {
    await Promise.all([
      User.deleteMany({ _id: { $in: createdUserIds } }).catch(() => {}),
      UserAvatar.deleteMany({ _id: { $in: createdUserIds } }).catch(() => {}),
      FireAlarm.deleteMany({ description: new RegExp(`^${DEPT}`) }).catch(() => {}),
    ]);
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('窗口内新命中过滤器的用户不被删除，删除面与级联严格同源', async () => {
    const u1 = await mkUser('a');
    const u2 = await mkUser('b');
    const keeper = await mkUser('keep');
    // u1 有进行中的指派：级联必须释放（证明删除面内的级联照常生效）
    const alarm = await FireAlarm.create({
      description: `${DEPT} 报警`,
      alarmType: 'smoke',
      status: 'processing',
      handler: u1._id,
    });

    const realDeleteMany = User.deleteMany.bind(User);
    let phantom = null;
    const deleteSpy = jest.spyOn(User, 'deleteMany').mockImplementation(async (filter, opts) => {
      // 模拟"预取之后、删除之前"的并发写入：新用户命中同一过滤器
      phantom = await mkUser('phantom');
      return realDeleteMany(filter, opts);
    });

    try {
      const result = await userService.deleteMany({
        department: DEPT,
        username: { $ne: keeper.username },
      });
      // 只有预取到的 u1/u2 被删；窗口内出现的 phantom 不属本批，不被顺带删除
      expect(result.deletedCount).toBe(2);
      expect(await User.findById(u1._id)).toBeNull();
      expect(await User.findById(u2._id)).toBeNull();
      expect(phantom).not.toBeNull();
      expect(await User.findById(phantom._id)).not.toBeNull();
      expect(await User.findById(keeper._id)).not.toBeNull();
      // 删除面内的级联照常：u1 的进行中指派被释放
      const after = await FireAlarm.findById(alarm._id);
      expect(after.handler).toBeNull();
      expect(after.status).toBe('pending');
    } finally {
      deleteSpy.mockRestore();
    }
  });
});
