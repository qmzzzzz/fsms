/**
 * 角色写路径的授权解析与守卫短路语义
 *
 * 被测对象：src/controllers/roleGuards.js（roleController 的 updateRole / deleteRole 共用）
 * 守护的不变式：
 *   1) 同一请求内「操作者最高层级」只解析一次（一次 populate 查询，不是三次）；
 *      且 ALL 范围连这一次都不做——范围条件本来就是空。
 *   2) 守卫的拒绝信号是布尔值，不依赖 ApiResponse.codeError 的返回值形状。
 *      真实 res 上 codeError 会返回链式对象，测试桩常只实现 status/json 不返回自身；
 *      若控制器写成 `const err = guard(); if (err) return err;`，桩就会让守卫"放行"，
 *      空名称请求一路走到 save()（本仓实测踩过：TypeError: role.save is not a function）。
 *   3) 错误码优先级（status 非法 vs 内置角色锁定、层级越权 vs 名称为空）稳定可预期。
 *
 * 可证伪性：把 createAuthorityResolver 的记忆化去掉 → 用例 1 红；
 * 把任一守卫改成返回 codeError 结果 → 用例 2 红；交换 status 两条臂的顺序 → 用例 3 红。
 */

jest.mock('../../middleware/rbac', () => ({
  getDataScope: jest.fn(),
}));

const { getDataScope } = require('../../middleware/rbac');
const permissionHelper = require('../../utils/permissionHelper');
const roleService = require('../../services/roleService');
const {
  createAuthorityResolver,
  applyRoleScopeToQuery,
  guardRoleWithinOperatorLevel,
  guardRoleStatusValue,
  applyRoleEditableFields,
} = require('../../controllers/roleGuards');
const roleController = require('../../controllers/roleController');

/**
 * res 桩：status() 链式返回自身，终点 json() 返回 undefined。
 * 这正是 jest 自动 mock / 多数手写桩的形态（终点不 return this）。
 * 守卫因此必须以布尔值为唯一拒绝信号——若控制器改写 `if (guard()) return guard()`
 * 之类依赖 codeError 返回值的形态，本文件的空名称用例会立刻变红。
 */
const makeRes = () => ({
  statusCode: null,
  payload: null,
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(body) {
    this.payload = body;
    return undefined;
  },
});

const errorCodeOf = (res) => res.payload?.errors?.errorCode;

describe('createAuthorityResolver / applyRoleScopeToQuery', () => {
  let levelSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    levelSpy = jest.spyOn(permissionHelper, 'getOperatorMaxLevel').mockResolvedValue(6);
  });

  test('同一解析器多次取层级只打一次库', async () => {
    const authority = createAuthorityResolver('u1');
    expect(await authority.maxLevel()).toBe(6);
    expect(await authority.maxLevel()).toBe(6);
    expect(await authority.maxLevel()).toBe(6);
    expect(levelSpy).toHaveBeenCalledTimes(1);
    expect(levelSpy).toHaveBeenCalledWith('u1');
  });

  test('ALL 范围不解析层级（无范围条件可拼）', async () => {
    getDataScope.mockResolvedValue({ type: 'all' });
    const { query } = await applyRoleScopeToQuery({}, 'u1');
    expect(query).toEqual({});
    expect(levelSpy).not.toHaveBeenCalled();
  });

  test('none 范围同样不解析层级，且条件恒空集', async () => {
    getDataScope.mockResolvedValue({ type: 'none' });
    const { query } = await applyRoleScopeToQuery({ status: 'active' }, 'u1');
    expect(query).toEqual({ status: 'active', _id: { $in: [] } });
    expect(levelSpy).not.toHaveBeenCalled();
  });

  test('department 范围只解析一次层级', async () => {
    getDataScope.mockResolvedValue({ type: 'department', department: 'A栋' });
    const authority = createAuthorityResolver('u1');
    await applyRoleScopeToQuery({}, 'u1', authority);
    await applyRoleScopeToQuery({ x: 1 }, 'u1', authority);
    expect(levelSpy).toHaveBeenCalledTimes(1);
  });
});

describe('guardRoleWithinOperatorLevel', () => {
  // jest.spyOn 对同一属性返回同一个 spy：不清零就会把上一个 describe 的调用数带进来
  beforeEach(() => jest.clearAllMocks());

  test('ALL 范围直接放行且不触发层级查询', async () => {
    const levelSpy = jest.spyOn(permissionHelper, 'getOperatorMaxLevel').mockResolvedValue(3);
    const res = makeRes();
    const denied = await guardRoleWithinOperatorLevel({
      res,
      role: { level: 9 },
      dataScope: { type: 'all' },
      authority: createAuthorityResolver('u1'),
      forbiddenCode: 'ROLE_UPDATE_FORBIDDEN',
      higherLevelCode: 'ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN',
    });
    expect(denied).toBe(false);
    expect(levelSpy).not.toHaveBeenCalled();
    levelSpy.mockRestore();
  });

  test('none 范围用 forbiddenCode 拒绝，返回布尔而非 codeError 的返回值', async () => {
    const res = makeRes();
    const denied = await guardRoleWithinOperatorLevel({
      res,
      role: { level: 1 },
      dataScope: { type: 'none' },
      authority: createAuthorityResolver('u1'),
      forbiddenCode: 'ROLE_DELETE_FORBIDDEN',
      higherLevelCode: 'ROLE_DELETE_HIGHER_LEVEL_FORBIDDEN',
    });
    expect(denied).toBe(true);
    expect({ status: res.statusCode, errorCode: errorCodeOf(res) }).toEqual({
      status: 403,
      errorCode: 'ROLE_DELETE_FORBIDDEN',
    });
  });
});

describe('status 与名称守卫的优先级/短路', () => {
  test('非法 status 优先于"内置角色不可停用"（先判值域再判归属）', () => {
    const res = makeRes();
    expect(guardRoleStatusValue({ res, role: { isBuiltIn: true }, status: 'disabled' })).toBe(true);
    expect(errorCodeOf(res)).toBe('ROLE_STATUS_INVALID');
  });

  test('合法 status 落在内置角色上 → BUILTIN_ROLE_STATUS_LOCKED', () => {
    const res = makeRes();
    expect(guardRoleStatusValue({ res, role: { isBuiltIn: true }, status: 'inactive' })).toBe(true);
    expect(errorCodeOf(res)).toBe('BUILTIN_ROLE_STATUS_LOCKED');
  });

  test('未提交 status 时两条臂都不触发', () => {
    expect(guardRoleStatusValue({ res: makeRes(), role: { isBuiltIn: true } })).toBe(false);
  });

  test('空名称必须在赋值前拒掉：其余字段同样不得被写入（PATCH 半途生效=静默改数据）', () => {
    const role = { name: '原名', description: '原描述', level: 5, status: 'active' };
    const res = makeRes();
    const denied = applyRoleEditableFields({
      res,
      role,
      name: '   ',
      description: '新描述',
      level: 1,
      status: 'inactive',
    });
    expect(denied).toBe(true);
    expect(errorCodeOf(res)).toBe('ROLE_NAME_REQUIRED');
    expect(role).toEqual({ name: '原名', description: '原描述', level: 5, status: 'active' });
  });

  test('名称带首尾空白时写入 trim 后的值，undefined 字段保持原值', () => {
    const role = { name: '原名', level: 5 };
    expect(
      applyRoleEditableFields({ res: makeRes(), role, name: '  新名  ', level: undefined })
    ).toBe(false);
    expect(role).toEqual({ name: '新名', level: 5 });
  });
});

describe('updateRole 只用一次层级解析', () => {
  let levelSpy;
  let permSpy;
  let findSpy;
  let saveSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    levelSpy = jest.spyOn(permissionHelper, 'getOperatorMaxLevel').mockResolvedValue(6);
    permSpy = jest.spyOn(roleService, 'getOperatorPermissions').mockResolvedValue(['role:edit']);
    findSpy = jest.spyOn(roleService, 'findRoleForUpdate').mockResolvedValue({
      _id: 'r1',
      code: 'OPS',
      name: '运维',
      level: 4,
      isBuiltIn: false,
      save() {},
    });
    saveSpy = jest.spyOn(roleService, 'saveRole').mockResolvedValue(undefined);
    jest.spyOn(roleService, 'findPopulatedRole').mockResolvedValue({ _id: 'r1' });
    getDataScope.mockResolvedValue({ type: 'department', department: 'A栋' });
  });

  const call = (body) => {
    const res = makeRes();
    const next = jest.fn();
    const req = {
      params: { id: 'r1' },
      body,
      user: { userId: 'u1', username: 'op' },
      app: { get: () => undefined },
    };
    return { res, next, promise: roleController.updateRole(req, res, next) };
  };

  test('改层级请求：范围条件 + 跨层级守卫 + 目标层级守卫共用一次解析', async () => {
    const { res, next, promise } = call({ level: 5 });
    await promise;
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    // 拆解前这里是 3（applyRoleScopeToQuery + 跨层级守卫 + 目标层级守卫各一次）
    expect(levelSpy).toHaveBeenCalledTimes(1);
    expect(permSpy).toHaveBeenCalledTimes(1);
    expect(findSpy).toHaveBeenCalledTimes(1);
    expect(saveSpy).toHaveBeenCalledTimes(1);
  });

  test('只改描述：不解析层级以外的目标层级校验', async () => {
    const { promise } = call({ description: '仅描述' });
    await promise;
    expect(levelSpy).toHaveBeenCalledTimes(1); // 范围条件那一次
    expect(permSpy).not.toHaveBeenCalled(); // level 未提交 ⇒ 提权守卫整块跳过
    expect(saveSpy).toHaveBeenCalledTimes(1);
  });
});
