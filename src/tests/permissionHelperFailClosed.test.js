/**
 * hasAllPermissions 的空列表是 fail-open
 *
 * 数学上的空集全称命题在这里变成授权结论：
 *   [].every(...) === true   ⇒ 「要求的全部权限都持有」对空要求返回「是」
 * 放到鉴权语义里就是——**调用方只要没写权限要求，这个函数就放行**。
 * 典型触发形态是 `hasAllPermissions(uid, req.body.requiredPerms || [])`
 * 或上游配置读空：请求方什么都没被要求，却拿到 true。
 *
 * 同文件里就有对照组，这也是判定它是缺陷而不是设计的关键证据：
 *   hasAnyPermission 用 `.some` ⇒ 空列表 **false**（已经是 fail-closed）
 *   hasPermission   单码，无空集问题
 * 一个模块里「任一」与「全部」对同一个空输入给出相反结论，只能是漏写。
 *
 * 现有测试 permissionHelperGap.test.js 也确实暴露了这个不对称：
 * 它专门断言了 `hasAnyPermission(..., undefined) === false`，
 * 却对 hasAllPermissions 只测了「全命中 / 缺一即否 / 故障」三条，没有空入参分支。
 *
 * 现状：hasAllPermissions 在生产代码里 0 调用方（只有定义、导出与 3 处测试引用），
 * 所以这是**潜在**缺陷而非现网漏洞——但它是被导出的公共鉴权原语，
 * 第一个调用方出现的那天就会静默授权。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('hasAllPermissions：空要求不得等于放行', () => {
  let User;
  let Role;
  let Permission;
  let helper;
  let uid;
  let permA;
  let permB;
  const PASSWORD = randomPassword();
  const stamp = `phfc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    helper = require('../utils/permissionHelper');

    permA = await Permission.create({
      code: `${stamp}:a`,
      name: '权限A',
      type: 'api',
      module: stamp,
      status: 'active',
    });
    permB = await Permission.create({
      code: `${stamp}:b`,
      name: '权限B',
      type: 'api',
      module: stamp,
      status: 'active',
    });
    const role = await Role.create({
      name: `全量角色_${stamp}`,
      code: `PHFC_${stamp}`.replace(/[^A-Z0-9_]/g, '_').toUpperCase(),
      level: 5,
      permissions: [permA._id, permB._id],
    });
    const user = await User.create({
      username: `${stamp}u1`,
      email: `${stamp}u1@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    uid = user._id;
  });

  afterAll(async () => {
    await Permission.deleteMany({ module: stamp }).catch(() => {});
    await Role.deleteMany({ name: new RegExp(stamp) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('夹具可信：该用户确实持有两个权限（否则下面的 true 是假绿）', async () => {
    await expect(helper.hasAllPermissions(uid, [`${stamp}:a`, `${stamp}:b`])).resolves.toBe(true);
  });

  test('★ 空数组必须判否（当前 .every 的空集语义会放行）', async () => {
    await expect(helper.hasAllPermissions(uid, [])).resolves.toBe(false);
  });

  test('★ undefined / null 同样判否（缺参不等于无要求）', async () => {
    await expect(helper.hasAllPermissions(uid, undefined)).resolves.toBe(false);
    await expect(helper.hasAllPermissions(uid, null)).resolves.toBe(false);
  });

  test('与 hasAnyPermission 对称：同一个空输入两边结论必须一致', async () => {
    const all = await helper.hasAllPermissions(uid, []);
    const any = await helper.hasAnyPermission(uid, []);
    expect(all).toBe(any);
    expect(all).toBe(false);
  });

  test('反向保护：非空要求全部命中仍是 true（修 fail-open 不得改成恒 false）', async () => {
    await expect(helper.hasAllPermissions(uid, [`${stamp}:a`])).resolves.toBe(true);
    await expect(helper.hasAllPermissions(uid, [`${stamp}:a`, `${stamp}:b`])).resolves.toBe(true);
  });

  test('反向保护：缺一即否（原语义不得被放宽成"任一"）', async () => {
    await expect(helper.hasAllPermissions(uid, [`${stamp}:a`, `${stamp}:missing`])).resolves.toBe(
      false
    );
  });

  test('非数组入参判否且不抛（原来靠 catch 兜住，会顺带打一条 error 日志）', async () => {
    await expect(helper.hasAllPermissions(uid, `${stamp}:a`)).resolves.toBe(false);
  });

  test('空要求时不应再查库（守卫在取权限集之前，省下无谓往返）', async () => {
    const spy = jest.spyOn(User, 'findById');
    try {
      await helper.hasAllPermissions(uid, []);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});
