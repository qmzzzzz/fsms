/**
 * userController 写路径共享件：数据范围字段名 + 跨 create/update/roles/delete 复用的写守卫。
 */
const ApiResponse = require('../../utils/apiResponse');
const { matchesPermissionCodes } = require('../../utils/permissionHelper');
const logger = require('../../utils/logger');
const { validateRules } = require('../../utils/ipRange');
// 数据范围字段名只有一份（constants/dataScopeFields.js）。此前 getUserStats 里私抄了
// 'createdBy'/'department'：改常量会让列表按新字段过滤、统计仍按旧字段聚合，
// 同一用户在"我的列表"与"我的统计"上看到互相矛盾的口径——正是这个常量当初要消灭的。
const { DATA_SCOPE_FIELDS } = require('../../constants/dataScopeFields');

/**
 * user 资源的属主/部门字段只有一份（constants/dataScopeFields.js）。
 * 此前本文件 5 处数据范围闸手写 'createdBy'/'department'，而同文件的统计接口引用常量——
 * 常量一改就会出现"列表/详情/写路径按新字段、统计按旧字段"的口径分叉（原始教训）。
 */
const { ownerField: USER_OWNER_FIELD, departmentField: USER_DEPT_FIELD } = DATA_SCOPE_FIELDS.user;

/** 角色文档集合 → 其携带的权限码集合（纯投影，不含任何授权判定语义） */
const permissionCodesOfRoles = (roleDocs) => {
  const codes = new Set();
  for (const r of roleDocs) {
    for (const p of r.permissions || []) {
      if (p?.code) codes.add(p.code);
    }
  }
  return codes;
};

/**
 * 权限子集校验的唯一实现：本次要授予的权限里、操作者自身不具备的那些即越权。
 *
 * 建号与角色分配此前各写一份同样的"双重循环取码 + 过滤"，注释里互相声明
 * "与对方完全同口径"——口径靠注释维持就是漂移的开始（层级闸与子集闸的先后、
 * 排除集是否参与，两处都必须一致）。
 *
 * currentRoleDocs 传目标已持有的角色：收权时目标的权限可能多于操作者，
 * 那些权限不是本次授予行为，必须排除，否则操作者连"给下级收权"都做不到。
 * @returns {string[]} 操作者无权授予的权限码；空数组即放行
 */
const findUnoperableGrantCodes = (operatorPermCodes, grantRoleDocs, currentRoleDocs) => {
  const granting = permissionCodesOfRoles(grantRoleDocs);
  if (currentRoleDocs) {
    for (const code of permissionCodesOfRoles(currentRoleDocs)) granting.delete(code);
  }
  return [...granting].filter((code) => !matchesPermissionCodes(operatorPermCodes, code));
};

/**
 * IP 访问范围规则的语法闸（建号与更新共用）：非法片段逐条回报，
 * 否则入库后规则静默失效——比报错更糟的是"以为限了"。
 * @returns {boolean} true 表示已写出拒绝响应，调用方应立即 return
 */
const rejectInvalidIpRules = (res, allowedIPs) => {
  if (allowedIPs === undefined || allowedIPs === '') return false;
  const check = validateRules(allowedIPs);
  if (check.valid) return false;
  ApiResponse.codeError(res, 'IP_RULES_FORMAT_INVALID', {
    message: `IP 范围规则格式有误：${check.invalid.join('、')}`,
    params: { rules: check.invalid.join('、') },
  });
  return true;
};

/** 日志与告警里指代操作者的统一写法（用户名缺失时退回 id，不出现 undefined） */
const operatorTag = (req) => req.user.username || req.user.userId;

/**
 * 同级角色的归属校验（纵深防御）：与操作者同 level 的角色，必须是操作者自己持有的那些。
 *
 * 只对**与操作者同级**的角色生效：高于操作者的已被层级校验拒绝，低于的由权限子集
 * 校验兜住，只有"恰好同级"这一档需要额外要求归属——两名同级、分管不同模块的
 * 管理员互挂对方角色，即可各自集齐双方全部权限且不触发任何层级告警。
 *
 * 不能写成"想授予某角色就必须自己持有它"：那会封死"把 GUEST 授予新人"这类
 * 最常见的合法操作（操作者本人当然不持有 GUEST），反而逼管理员囤积角色，
 * 本身就是权限膨胀的反模式。
 * @returns {string[]} 同级且非操作者自身持有的角色编码
 */
const findForeignPeerRoles = (operatorRoleCodes, validRoles, operatorMaxLevel) =>
  validRoles
    .filter((r) => (r.level || 0) === operatorMaxLevel)
    .map((r) => r.code)
    .filter((code) => !operatorRoleCodes.has(code));

/**
 * 同级角色归属闸的执行体（B-2）：两条授权轨共用同一实现——改角色（assignRoles）
 * 与建号（createUser）。
 *
 * 建号轨原本漏了这一道，而漏掉它不是"当场提权"（上一层的权限子集闸已保证新账户
 * 权限 ⊆ 操作者自身权限），真实后果是**角色继承型扩权**：新账户成了那个同级角色的
 * 合法持有者，日后该角色被补上任何权限，新账户——以及掌握其口令的操作者——自动获得，
 * 而这条增量从未触过任何授权判定。附带同样重要的归因面：动作记在别人名下。
 * 与 assignRoles 保持同一尺子是必要的：两条轨口径不一致时，运营者会自然流向松的那条。
 *
 * `req.user.roleCodes` 由 auth 中间件在请求期实时刷新（freshRoleCodes），
 * 非签发时快照，作为角色归属比对的事实来源。
 * @param {string} subjectTag 日志里指代被授权主体的写法（`target=xxx` / `newUser=xxx`）
 * @returns {boolean} true 表示已写出 403 拒绝响应，调用方应立即返回
 */
const rejectForeignPeerRoles = (res, req, grantRoles, operatorMaxLevel, subjectTag) => {
  const foreignRoles = findForeignPeerRoles(
    new Set(req.user.roleCodes || []),
    grantRoles,
    operatorMaxLevel
  );
  if (foreignRoles.length === 0) return false;
  logger.warn(
    `角色分配越权被拒（同级角色归属）：operator=${operatorTag(req)} ${subjectTag} ` +
      `非自身持有的同级角色=${foreignRoles.join(',')}`
  );
  ApiResponse.codeError(res, 'ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN', {
    message: `无权分配自身未持有的同级角色：${foreignRoles.join('、')}`,
    params: { foreignRoles: foreignRoles.join('、') },
  });
  return true;
};

module.exports = {
  USER_OWNER_FIELD,
  USER_DEPT_FIELD,
  findUnoperableGrantCodes,
  rejectInvalidIpRules,
  operatorTag,
  rejectForeignPeerRoles,
};
