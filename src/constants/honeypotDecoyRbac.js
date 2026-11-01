'use strict';

const { DECOY_PERMISSION_CATALOG } = require('./honeypotDecoySelf');
const { DECOY_ROLE_ENTRIES, DECOY_USERS } = require('./honeypotDecoyUsers');
const { frozenRows, HONEYPOT_DECOY_ID_PREFIX } = require('./honeypotDecoyIds');

const DECOY_ROLE_CODES = Object.freeze(DECOY_ROLE_ENTRIES.map((entry) => entry.code)); // Role.code 在模型侧是 uppercase:true ⇒ 真实码只会是大写
const DECOY_PERMISSIONS = Object.freeze(DECOY_PERMISSION_CATALOG.map((row) => row.code)); // 与装扮身份同源：真实链的 permissions 是「菜单码 ∪ 按钮码 ∪ 接口码」的并集
const DECOY_PERMISSION_REFS = frozenRows(
  DECOY_PERMISSION_CATALOG.map((row, index) => ({
    _id: HONEYPOT_DECOY_ID_PREFIX + 'p' + (index + 1),
    name: row.name,
    code: row.code,
    type: row.type,
    module: row.module,
  }))
);
const PERMISSION_REFS_BY_CODE = new Map(DECOY_PERMISSION_REFS.map((ref) => [ref.code, ref]));

const permissionScopeOf = (modules) =>
  DECOY_PERMISSION_REFS.filter((ref) => modules.includes(ref.module));

const permissionParentOf = (code) => {
  const root = code.split(':')[0] + ':*';
  const ref = root === code ? null : PERMISSION_REFS_BY_CODE.get(root);
  return ref ? { _id: ref._id, name: ref.name, code: ref.code } : null;
};

const ROLE_PERMISSION_MODULES = Object.freeze({
  SYSTEM_ADMIN: Object.freeze(['system', 'device', 'alarm', 'inspection', 'report']),
  OPS_MANAGER: Object.freeze(['device', 'alarm', 'inspection']),
  DUTY_OFFICER: Object.freeze(['alarm', 'inspection']),
  MAINTAINER: Object.freeze(['device', 'inspection']),
});
const ROLE_LEDGER = Object.freeze({
  SYSTEM_ADMIN: Object.freeze({
    description: '系统全部配置与账号管理',
    level: 10,
    createdAtOffsetMin: 60 * 24 * 640,
    updatedAtOffsetMin: 60 * 24 * 32,
  }),
  OPS_MANAGER: Object.freeze({
    description: '设备与工单的运维管理',
    level: 7,
    createdAtOffsetMin: 60 * 24 * 600,
    updatedAtOffsetMin: 60 * 24 * 26,
  }),
  DUTY_OFFICER: Object.freeze({
    description: '报警处置与巡检记录',
    level: 5,
    createdAtOffsetMin: 60 * 24 * 560,
    updatedAtOffsetMin: 60 * 24 * 18,
  }),
  MAINTAINER: Object.freeze({
    description: '设备维护与现场确认',
    level: 3,
    createdAtOffsetMin: 60 * 24 * 480,
    updatedAtOffsetMin: 60 * 24 * 9,
  }),
});

const DECOY_ROLES = frozenRows(
  DECOY_ROLE_ENTRIES.map((entry) => ({
    _id: entry._id,
    code: entry.code,
    name: entry.name,
    description: ROLE_LEDGER[entry.code].description,
    status: 'active',
    permissions: permissionScopeOf(ROLE_PERMISSION_MODULES[entry.code]), // 键集 = roleService.js:15 的列表投影 {name code type module}
    level: ROLE_LEDGER[entry.code].level,
    isBuiltIn: false,
    createdAtOffsetMin: ROLE_LEDGER[entry.code].createdAtOffsetMin,
    updatedAtOffsetMin: ROLE_LEDGER[entry.code].updatedAtOffsetMin,
    userCount: DECOY_USERS.filter((user) =>
      (user.roles || []).some((role) => role.code === entry.code)
    ).length,
  }))
);
const DECOY_PERMISSION_ROWS = frozenRows(
  DECOY_PERMISSION_CATALOG.map((row, index) => ({
    _id: HONEYPOT_DECOY_ID_PREFIX + 'p' + (index + 1),
    code: row.code,
    name: row.name,
    type: row.type,
    module: row.module,
    path: row.path,
    method: row.method || '*', // 模型默认值 '*'（src/models/Permission.js:61-65）：真实文档恒有该键，目录里只有接口行显式给了方法
    status: 'active',
    parent: permissionParentOf(row.code), // populate 形状 {_id,name,code}（permissionService.js:160）；父子按权限码前缀还原，与权限树同判据
    sort: 0,
    deletedAt: null,
    createdAtOffsetMin: 60 * 24 * 600,
    updatedAtOffsetMin: 60 * 24 * 45,
  }))
);

module.exports = { DECOY_PERMISSION_ROWS, DECOY_PERMISSIONS, DECOY_ROLE_CODES, DECOY_ROLES };
