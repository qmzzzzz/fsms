/**
 * 角色授予的写后复验判据
 *
 * updateRole（改 level）与 assignPermissions（扩权限）是独立请求，可以在
 * 「判定通过 → 角色落库」之间把角色抬高/扩权。写后复验用**重新读取的**角色
 * 文档再判一次；本文件钉住判据本身（层级、子集、角色在窗口内被删除）。
 */

const { findGrantViolationAfterWrite } = require('../../controllers/userController/shared');

const role = (level, codes) => ({
  level,
  permissions: (codes || []).map((code) => ({ code })),
});

describe('findGrantViolationAfterWrite', () => {
  const base = {
    operatorPermCodes: ['user:update'],
    operatorMaxLevel: 8,
    currentRoleDocs: [],
    expectedCount: 1,
  };

  test('复验通过返回 null', () => {
    expect(
      findGrantViolationAfterWrite({ ...base, grantRoleDocs: [role(3, ['user:update'])] })
    ).toBeNull();
  });

  test('角色在窗口内被删除：文档数对不上按 ROLE_ID_INVALID 处理，不得按低层级放行', () => {
    expect(findGrantViolationAfterWrite({ ...base, grantRoleDocs: [] })).toEqual({
      code: 'ROLE_ID_INVALID',
    });
    expect(findGrantViolationAfterWrite({ ...base, grantRoleDocs: null })).toEqual({
      code: 'ROLE_ID_INVALID',
    });
  });

  test('角色在窗口内被抬高：层级超过操作者即拒', () => {
    expect(
      findGrantViolationAfterWrite({ ...base, grantRoleDocs: [role(9, ['user:update'])] })
    ).toEqual({ code: 'ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN' });
  });

  test('角色在窗口内被扩权：回报操作者无权授予的权限码', () => {
    expect(
      findGrantViolationAfterWrite({
        ...base,
        grantRoleDocs: [role(3, ['user:update', 'user:delete'])],
      })
    ).toEqual({ code: 'PERMISSION_GRANT_FORBIDDEN', lacking: ['user:delete'] });
  });

  test('目标已持有的权限不计入本次授予（收权不受影响）', () => {
    expect(
      findGrantViolationAfterWrite({
        ...base,
        grantRoleDocs: [role(3, ['user:update', 'user:delete'])],
        currentRoleDocs: [role(1, ['user:delete'])],
      })
    ).toBeNull();
  });

  test('通配权限 *:* 直接放行', () => {
    expect(
      findGrantViolationAfterWrite({
        ...base,
        operatorPermCodes: ['*:*'],
        grantRoleDocs: [role(3, ['user:delete'])],
      })
    ).toBeNull();
  });
});
