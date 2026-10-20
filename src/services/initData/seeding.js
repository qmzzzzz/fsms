/**
 * 系统初始化数据服务 · 权限与角色播种（并发冲突容错与幂等对账）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const Permission = require('../../models/Permission');
const Role = require('../../models/Role');
const logger = require('../../utils/logger');
const { defaultPermissions } = require('./permissions');
const { defaultRoles, rolePermissionMap } = require('./roles');

/**
 * 只插入目录里缺失的权限，返回**真实**创建数
 *
 * created 不能取 toInsert.length：多实例并发部署时 insertMany 可能抛 11000 且
 * ordered:false 下只有一部分落库、返回值还拿不到，此时按预查差集上报会把
 * 没插成功的文档也算成"已创建"（初始化日志一直是运维判断播种是否成功的唯一凭据）。
 */
const insertMissingPermissions = async (toInsert) => {
  if (toInsert.length === 0) {
    // 不在这里早退整个播种：「所有 code 都已存在」不等于「树是对的」。
    // 2026-09-18 的 parent 自环事故只修了代码，坏数据留在库里；那些行因为
    // "本来就存在"永远进不了 toInsert ⇒ 不走到下面的对账就永远不恢复，
    // 而运维看到的是"重启多次、接口 200、角色权限树依旧空"。
    logger.info('权限数据已全部存在，仅做 parent 关联对账');
    return 0;
  }
  let inserted = [];
  let hadConflict = false;
  try {
    // 先全部插入（不带 parent），确保所有文档已落库
    inserted = await Permission.insertMany(toInsert, { ordered: false });
  } catch (err) {
    if (err.code !== 11000) throw err;
    hadConflict = true;
    logger.warn('权限初始化遇到并发冲突，继续关联 parent');
  }
  return hadConflict
    ? await Permission.countDocuments({ code: { $in: toInsert.map((p) => p.code) } })
    : inserted.length;
};

/**
 * 初始化权限数据
 */
const initPermissions = async () => {
  logger.info('开始初始化权限数据...');

  try {
    // 查询已存在的权限 code
    const existingCodes = (await Permission.find({}).select('code').lean()).map((p) => p.code);
    const toInsert = defaultPermissions
      .filter((p) => !existingCodes.includes(p.code))
      .map((p) => ({ ...p, parent: null })); // 先全部置为 null，后续统一关联

    const created = await insertMissingPermissions(toInsert);

    // 修复：构建 code -> _id 映射时查询全部 defaultPermissions 的 code（含已存在的父权限），
    // 否则已存在的模块通配符（如 user:*）不在映射中，新插入子权限的 parent 永远无法关联
    const allPermCodes = defaultPermissions.map((p) => p.code);
    const allPermissions = await Permission.find({
      code: { $in: allPermCodes },
    })
      .select('code parent')
      .lean();
    const codeToId = new Map(allPermissions.map((p) => [p.code, p._id]));
    const parentByCode = new Map(
      allPermissions.map((p) => [p.code, p.parent ? String(p.parent) : null])
    );

    // 批量更新 parent 关联
    // 注意：模块通配符（如 user:*）是模块的根，其 parent 必须是 null。
    // 若对它也走下面的 `${module}:*` 关联，通配符会被挂到**自己**身上形成自环
    // （实测 2026-09-18：10 个通配符全部自环），于是 roleController 的
    // buildPermissionTree 把它们挂进「parent 在结果集内」分支、永不进入任何模块的
    // children——连同其下 37 个子权限一起从 /api/roles/permissions/tree 消失，
    // 角色权限编辑页拿不到任何可勾选权限。故显式跳过通配符自身（并按 null 纠正历史自环）。
    //
    // 遍历对象是 defaultPermissions 而不是 toInsert：目录就是权威形状，已存在的行
    // 也要对账，否则历史漂移无人回收。口径与内置角色每次启动对账 rolePermissionMap
    // 一致——运维手工把目录内权限挪到别处会被收回，目录外的自定义权限完全不受影响。
    // 写入前与库中现值比对：已收敛的库这趟一条 updateOne 都不生成
    // （"重复播种不下发写入"的幂等契约见 tests/services/initDataLifecycle.test.js A2）。
    const bulkOps = [];
    for (const permData of defaultPermissions) {
      if (!permData.code.includes(':')) continue;
      const isModuleRoot = permData.code.endsWith(':*');
      const desiredId = isModuleRoot
        ? null
        : codeToId.get(`${permData.code.split(':')[0]}:*`) || null;
      const permId = codeToId.get(permData.code);
      if (!permId) continue; // 唯一键冲突下这行可能确实没落库
      if (String(parentByCode.get(permData.code) ?? '') === String(desiredId ?? '')) continue;
      bulkOps.push({
        updateOne: {
          filter: { _id: permId },
          update: { $set: { parent: desiredId } },
        },
      });
    }

    if (bulkOps.length > 0) {
      await Permission.bulkWrite(bulkOps);
    }

    const skipped = defaultPermissions.length - created;
    logger.info(
      `权限初始化完成：创建 ${created} 个，校准 ${bulkOps.length} 个 parent 关联，跳过 ${skipped} 个`
    );
    return { created, skipped };
  } catch (error) {
    logger.error(`权限初始化失败：${error.message}`);
    throw error;
  }
};

/** 内置角色与预定义权限集对账；返回是否产生了一条收敛操作。 */
function reconcileBuiltInRole(roleData, existing, permIdsFor, reconcileOps) {
  if (!roleData.isBuiltIn) return false;
  const expectedIds = permIdsFor(roleData.code).map((id) => id.toString());
  const currentIds = (existing.permissions || []).map((p) => p.toString());
  const needsUpdate =
    expectedIds.length !== currentIds.length || !expectedIds.every((id) => currentIds.includes(id));
  if (!needsUpdate) return false;
  reconcileOps.push({
    updateOne: {
      filter: { _id: existing._id },
      update: { $set: { permissions: expectedIds } },
    },
  });
  logger.warn(`内置角色 ${roleData.code} 权限已对账收敛`);
  return true;
}

/** 批量创建角色并绑定权限；多实例首启的唯一键冲突按 A-3 回查后继续。 */
async function createRolesWithPermissions(rolesToCreate, rolePermissionsMap) {
  let createdRoles = [];
  try {
    createdRoles = await Role.insertMany(rolesToCreate, { ordered: false });
  } catch (err) {
    // A-3：多实例同时首启时，另一实例可能已抢先写入同 code 的角色。
    // 权限播种早已按同一口径处理 11000（见 insertMissingPermissions）；
    // 这里若不接住，冲突实例会在初始化阶段直接退出。
    // ordered:false 下非冲突文档已经落库，按 code 回查即可拿到「本次可见」的全集，
    // 后续权限关联照常执行（对另一实例写过的行也是幂等收敛）。
    if (err.code !== 11000) throw err;
    logger.warn('角色初始化遇到并发冲突（11000），回查已落库角色后继续');
    createdRoles = await Role.find({ code: { $in: rolesToCreate.map((r) => r.code) } })
      .select('_id code')
      .lean();
  }

  const bulkOps = createdRoles
    .map((role) => {
      const permIds = rolePermissionsMap.get(role.code);
      if (!permIds || permIds.length === 0) return null;
      return {
        updateOne: {
          filter: { _id: role._id },
          update: { $set: { permissions: permIds } },
        },
      };
    })
    .filter(Boolean);
  if (bulkOps.length > 0) await Role.bulkWrite(bulkOps);
  return createdRoles.length;
}

/**
 * 初始化角色数据
 * 注意：内置角色（isBuiltIn）每次启动都会与 rolePermissionMap 对账，
 * 防止数据库残留过宽权限（如 GUEST 曾拥有 device:* 通配符）无法被收回。
 *
 * 消除 N+1：原实现对每个角色各发一次 findOne + 一次 Permission.find
 * （6 个角色 ≥ 12 次串行往返），且 SECURITY_ADMIN/FIRE_SUPERVISOR 的权限集
 * 高度重叠却各自重复拉取。现在改为「两次批量查询 + 内存内映射」：
 * 一次取回全部角色，一次取回全部涉及的权限，之后纯内存比对。
 */
const initRoles = async () => {
  logger.info('开始初始化角色数据...');

  let created = 0;
  let skipped = 0;
  let reconciled = 0;

  // ===== 批量预取（替代逐角色查询） =====
  const allRoleCodes = defaultRoles.map((r) => r.code);
  const existingRoles = await Role.find({ code: { $in: allRoleCodes } });
  const existingByCode = new Map(existingRoles.map((r) => [r.code, r]));

  // 所有角色涉及的权限码取并集后一次查完（重叠权限只查一次）
  const allPermCodes = [...new Set(defaultRoles.flatMap((r) => rolePermissionMap[r.code] || []))];
  const permDocs =
    allPermCodes.length > 0
      ? await Permission.find({ code: { $in: allPermCodes } })
          .select('_id code')
          .lean()
      : [];
  const permIdByCode = new Map(permDocs.map((p) => [p.code, p._id]));

  /** 取某角色预定义权限对应的 ObjectId 列表（缺失的权限码自动跳过） */
  const permIdsFor = (roleCode) =>
    (rolePermissionMap[roleCode] || []).map((code) => permIdByCode.get(code)).filter(Boolean);

  // 先收集所有需要创建的 role + 权限，再批量操作，减少中间失败导致的脏数据
  const rolesToCreate = [];
  const rolePermissionsMap = new Map(); // roleCode -> [permIds]
  // 内置角色权限对账的批量更新操作
  const reconcileOps = [];

  for (const roleData of defaultRoles) {
    const existing = existingByCode.get(roleData.code);
    if (existing) {
      skipped++;
      if (reconcileBuiltInRole(roleData, existing, permIdsFor, reconcileOps)) reconciled++;
      continue;
    }
    rolesToCreate.push(roleData);

    const permIds = permIdsFor(roleData.code);
    if (permIds.length > 0) {
      rolePermissionsMap.set(roleData.code, permIds);
    }
  }

  // 对账更新一次性提交（原实现逐个 existing.save()）
  if (reconcileOps.length > 0) {
    await Role.bulkWrite(reconcileOps);
  }

  // 批量创建角色并绑定权限
  if (rolesToCreate.length > 0) {
    created = await createRolesWithPermissions(rolesToCreate, rolePermissionsMap);
  }

  logger.info(`角色初始化完成：创建 ${created} 个，对账 ${reconciled} 个，跳过 ${skipped} 个`);
  return { created, reconciled, skipped };
};

module.exports = { initPermissions, initRoles };
