/**
 * 用户名字符集约束必须在模型层生效
 *
 * `username` 原先只有长度约束，字符集规则只存在于两条路由正则里。
 * 这正是本仓反复出现的那一类缺陷：**同一语义在多处各抄一遍，漏一处即失效**——
 * 漏掉的这一处是"非路由写入"（initData 走 raw collection、数据修复脚本、
 * 将来的批量导入），而用户名是审计日志/告警通知/审批记录里操作者的呈现标识。
 *
 * 更要紧的是：本仓为仿冒面加的 USERNAME_COLLATION（strength:2）只折大小写与重音，
 * **不折西里尔 'а' 与拉丁 'a'**。所以唯一索引挡不住 `аdmin` 与 `admin` 并存。
 * 下面第 ③ 组就是把这件事作为事实测出来（走 raw collection，绕开刚加的校验），
 * 它证明这条约束不是假想的整洁性问题，而是既有防仿冒措施的真实缺口。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('用户名合法字符集：模型层收口', () => {
  let User;
  const PASSWORD = randomPassword();
  const stamp = `zzus${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
  });

  afterAll(async () => {
    await User.collection.deleteMany({
      username: { $in: ['admin', `${stamp}adm1n`, 'admin-x', 'admin.x', 'admin x'] },
    });
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const errorFor = (username) => {
    const err = new User({
      username,
      email: `${stamp}@example.com`,
      password: PASSWORD,
    }).validateSync();
    return err && err.errors && err.errors.username ? err.errors.username.message : null;
  };

  describe('① 模型层拒绝非白名单字符', () => {
    test.each([
      // 西里尔 'а' + 'dmin'：视觉上与 admin 等同
      ['同形异码仿冒（西里尔 а）', 'аdmin'],
      ['连字符', 'admin-x'],
      ['点号', 'admin.x'],
      ['空格', 'admin x'],
      ['中文', '管理员账户'],
      ['全角数字', 'admin１２'],
    ])('%s → 校验失败', (_label, username) => {
      expect(errorFor(username)).toBeTruthy();
    });
  });

  describe('② 反向保护：既有合法写法一律不受影响', () => {
    test.each([
      ['下划线', 'sys_admin'],
      ['大小写混合', 'Zhang_San'],
      ['字母数字', 'admin01'],
      ['最长 30 字符', 'a'.repeat(30)],
    ])('%s → 通过', (_label, username) => {
      expect(errorFor(username)).toBeNull();
    });
  });

  test('③ 事实核对：唯一索引的 collation 挡不住同形异码，只有字符集约束挡得住', async () => {
    // 走 raw collection：绕开刚加的模型校验，专测"数据库层的既有防线够不够"
    await User.collection.deleteMany({ username: { $in: ['admin', 'admin-x'] } });
    const base = {
      email: `zz${stamp}@example.com`,
      password: '$2$10$notahash',
      status: 'active',
    };
    await User.collection.insertOne({ ...base, username: 'admin' });
    let collision = null;
    try {
      // 拉丁 a 换成西里尔 а：collation(strength:2) 视作两个不同的值
      await User.collection.insertOne({
        ...base,
        email: `zz2${stamp}@example.com`,
        username: 'аdmin',
      });
    } catch (err) {
      collision = err;
    }
    expect(collision).toBeNull(); // 并存成功 → collation 确实不折同形异码
    expect(await User.countDocuments({ username: { $in: ['admin', 'аdmin'] } })).toBe(2);

    // 而同一形态经模型写入必须被拒（这才是修复后的真实防线）
    await expect(
      User.create({ username: 'аdmin', email: `zz3${stamp}@example.com`, password: PASSWORD })
    ).rejects.toThrow(/用户名/);

    await User.collection.deleteMany({ username: { $in: ['admin', 'аdmin'] } });
  });

  test('④ 真实创建路径照常可用（收口不得把注册/初始化打死）', async () => {
    const created = await User.create({
      username: `${stamp}adm1n`,
      email: `${stamp}2@example.com`,
      password: PASSWORD,
    });
    expect(String(created._id)).toMatch(/^[0-9a-f]{24}$/);
    await User.collection.deleteOne({ _id: created._id });
  });
});
