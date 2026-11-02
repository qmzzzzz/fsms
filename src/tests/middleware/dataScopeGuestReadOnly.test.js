/**
 * 内置访客 GUEST 的数据范围：全量业务只读，而不是「无数据」
 *
 * 缺陷形态（修前）：getDataScope 只按角色 level 分档，level 1 一律 none。
 * GUEST 确实持有 device/alarm/inspection/report 的 read，但列表/统计/导出/详情
 * 全部走数据范围 → 403 DATA_SCOPE_DENIED。公开注册的默认角色正是 GUEST，
 * 于是「注册成功 → 登录 → 四个业务模块全不可用」，与 README 的角色表矛盾。
 *
 * 本套件同时钉住反向边界：例外只认内置 code=GUEST，其余 level<4 的自定义角色
 * 仍是 none——若把判据写成「level<4 一律全量」，任何低级别自定义角色都会静默
 * 获得全组织数据可见性。
 */

const mongoose = require('mongoose');

describe('内置访客的数据范围', () => {
  let User;
  let Role;
  let getDataScope;
  let applyDataScopeToQuery;
  let isRecordInScope;

  const stamp = `gsr${Date.now()}`;
  const createdUsers = [];
  const createdRoles = [];
  let createdGuest = false;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    ({ getDataScope, applyDataScopeToQuery, isRecordInScope } = require('../../middleware/rbac'));

    let guest = await Role.findOne({ code: 'GUEST' });
    if (!guest) {
      guest = await Role.create({ name: '访客', code: 'GUEST', level: 1 });
      createdGuest = true;
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await Role.deleteMany({ _id: { $in: createdRoles } }).catch(() => {});
      if (createdGuest) await Role.deleteOne({ code: 'GUEST' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const makeUser = async (suffix, role) => {
    const user = await User.create({
      username: `${stamp}${suffix}`,
      email: `${stamp}${suffix}@example.com`,
      password: 'Guest-Scope-Pass!1',
      roles: [role._id],
    });
    createdUsers.push(user._id);
    return user;
  };

  test('GUEST（level 1）返回 all：列表/导出不再以「范围不可用」拒绝', async () => {
    const guest = await Role.findOne({ code: 'GUEST' });
    const user = await makeUser('guest', guest);
    const scope = await getDataScope(String(user._id));

    expect(scope).toEqual({ type: 'all' });
    // 消费面：范围条件为空对象（不额外过滤），且不抛 403
    const query = {};
    expect(
      applyDataScopeToQuery(query, scope, {
        ownerField: 'createdBy',
        departmentField: 'location.building',
      })
    ).toBe(true);
    expect(query).toEqual({});
    expect(
      isRecordInScope(
        scope,
        { _id: new mongoose.Types.ObjectId(), createdBy: new mongoose.Types.ObjectId() },
        { ownerField: 'createdBy', departmentField: 'location.building', userId: String(user._id) }
      )
    ).toBe(true);
  });

  test('反向边界：level<4 的自定义角色仍然是 none（例外只认内置 GUEST code）', async () => {
    const lowRole = await Role.create({
      name: `低级别自定义角色${stamp}`,
      code: `GSL_${stamp.toUpperCase()}`,
      level: 1,
    });
    createdRoles.push(lowRole._id);
    const user = await makeUser('low', lowRole);

    const scope = await getDataScope(String(user._id));
    expect(scope).toEqual({ type: 'none' });
    expect(() =>
      applyDataScopeToQuery({}, scope, {
        ownerField: 'createdBy',
        departmentField: 'location.building',
      })
    ).toThrow(/没有可用的数据范围/);
  });
});
