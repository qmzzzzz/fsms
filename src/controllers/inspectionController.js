/**
 * 巡检管理控制器
 * 职责：请求解析、参数校验、数据范围校验、响应格式化
 * 业务逻辑委托给 InspectionService
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope, assertRecordInScope } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { rejectOutOfScopeReferences, normalizeInspectionRefLists } = require('./inspectionGuards');
const { normalizePagination, isValidDateParam } = require('../utils/helpers');
const inspectionService = require('../services/InspectionService');

/**
 * 校验巡检记录是否在当前用户数据范围内
 *
 * 字段名取自 DATA_SCOPE_FIELDS.inspection，不在这里写字面量：
 * 列表/统计/报表与单条判定必须共用同一份声明（P2-20 的原始教训）。
 */
const isInspectionInScope = async (req, inspection) => {
  const { allowed } = await assertRecordInScope(
    req,
    inspection,
    DATA_SCOPE_FIELDS.inspection.ownerField,
    DATA_SCOPE_FIELDS.inspection.departmentField
  );
  return allowed;
};

/**
 * 获取巡检列表
 * GET /api/inspections
 *
 * E-2：支持游标分页。传 cursor 时走 keyset seek（不带 total，
 * 响应携带 hasMore/nextCursor）；不传保持原 page/limit 语义。
 */
const getInspections = asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 10,
    cursor,
    status,
    inspectionType,
    assignedTo,
    startDate,
    endDate,
    search,
  } = req.query;

  // 判据单源 helpers.isValidDateParam：裸 isNaN(new Date(x)) 会把 '123' 静默翻成公元 0122 年
  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
  }

  const dataScope = await getDataScope(req.user.userId);
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 100);

  const { inspections, count, hasMore, nextCursor } = await inspectionService.getInspections({
    page: pageNum,
    limit: limitNum,
    cursor,
    status,
    inspectionType,
    assignedTo,
    startDate,
    endDate,
    search,
    dataScope,
  });

  if (cursor) {
    return ApiResponse.paginated(
      res,
      inspections,
      {
        page: null,
        limit: limitNum,
        total: null,
        totalPages: null,
        hasMore,
        nextCursor,
      },
      '获取巡检列表成功'
    );
  }

  return ApiResponse.paginated(
    res,
    inspections,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
      nextCursor,
    },
    '获取巡检列表成功'
  );
});

/**
 * 获取巡检详情
 * GET /api/inspections/:id
 */
const getInspectionById = asyncHandler(async (req, res) => {
  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.codeError(res, 'INSPECTION_NOT_FOUND');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.codeError(res, 'INSPECTION_VIEW_FORBIDDEN');
  return ApiResponse.success(res, inspection, '获取成功');
});

/**
 * 创建巡检计划
 * POST /api/inspections
 */
const createInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const allowedFields = (({
    title,
    inspectionType,
    planStartTime,
    planEndTime,
    assignedTo,
    devices,
    locations,
    priority,
    description,
    remark,
    checkItems,
  }) => ({
    title,
    inspectionType,
    planStartTime,
    planEndTime,
    assignedTo,
    devices,
    locations,
    priority,
    description,
    remark,
    checkItems,
  }))(req.body);

  // 归一必须在守卫之前、且就用这份归一结果落库：守卫内部比长度用的是去重后的列表，
  // 而落库走 allowedFields ⇒ 两边不是同一份就会把重复项真的存进 assignedTo/devices
  // （判据与后果见 inspectionGuards.js 的 normalizeInspectionRefLists）。
  normalizeInspectionRefLists(allowedFields);

  if (await rejectUnusableAssignees(res, allowedFields.assignedTo)) return undefined;
  if (await rejectOutOfScopeReferences(req, res, allowedFields)) return undefined;

  const inspection = await inspectionService.createInspection(allowedFields);
  return ApiResponse.success(res, inspection, '巡检计划创建成功', 201);
});

/**
 * 执行人必须存在且处于启用状态（与报警指派同口径，见 AlarmService.dispatchAlarm）
 *
 * 路由只校验了 `assignedTo.*.isMongoId()`——**格式对、人不存在的数组会一路落库**。
 * 后果不是显示问题，而是这条计划永远无法开工：startInspection 的条件是
 * 「assignedTo 含操作者」或「assignedTo.0 不存在」，单元素幽灵数组两者都不满足；
 * 同时它继续计入 pending 统计并把 completionRate 一起拖住。
 * 删除用户时的级联清理（userService.releaseOpenAssignments）堵住"先分配后删人"，
 * 这一处堵反方向"先删人/填错 ID 后分配"，两处合起来 assignedTo 才不再产生死计划。
 *
 * @returns {Promise<string[]>} 不可用的执行人 ID（空数组表示全部可用）
 */
const findUnusableAssignees = async (assignedTo) => {
  if (!Array.isArray(assignedTo) || assignedTo.length === 0) return [];
  const usable = new Set(await inspectionService.findActiveUserIds(assignedTo));
  return assignedTo.filter((id) => !usable.has(String(id)));
};

const rejectUnusableAssignees = async (res, assignedTo) => {
  const bad = await findUnusableAssignees(assignedTo);
  if (bad.length === 0) return false;
  // 只回数量不回 ID 列表：被删用户的 id 不该成为可枚举的确认信号
  ApiResponse.codeError(res, 'VALIDATION_FAILED', {
    message: `指定的执行人不存在或已被停用（${bad.length} 个）`,
  });
  return true;
};

/**
 * 更新巡检计划
 * PUT /api/inspections/:id
 */
const updateInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.codeError(res, 'INSPECTION_NOT_FOUND');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN');

  // 同 create：先归一再判再落库，且归一的这一份就是被写进去的那份
  // （服务层按 `updates[field] !== undefined` 逐列 $set）。
  //
  // 为什么必须归一**副本**而不是 `req.body` 本身：审计中间件在 setImmediate 回调时刻才读
  // `req.body`（middleware/security.js 的 persistAuditRecord，其文档明确"勿提前快照"），
  // 并把它哈希进只追加的审计链。原地改写会把"客户端提交的三个指派"记成"一个"——
  // 取证记录与被审计的行为不再是同一件事，且与 POST 侧（归一 allowedFields 副本、
  // 审计原始体）形成按 HTTP 方法分叉的两种取证形态。副本用展开浅拷即可：数组属性被
  // 整体替换，`req.body` 里的原数组不受影响。
  const updates = normalizeInspectionRefLists({ ...req.body });

  if (await rejectUnusableAssignees(res, updates.assignedTo)) return undefined;
  // 更新路径此前只判"改前这条记录在不在范围内"：范围闸上线后写进来的**新值**
  // （换楼栋、换执行人、换设备）一律不判，等于用一次合法的 PUT 把计划搬出范围。
  if (await rejectOutOfScopeReferences(req, res, updates)) return undefined;

  // 不写本地 try/catch：错误到 HTTP 的映射只有 errorHandler 一处实现。
  // 本地 `catch { ApiResponse.error(res, '操作失败', err.statusCode || 400) }` 的代价
  // （F-173，与 deviceController.updateDeviceStatus 同一缺陷类）：
  //   ① 服务层专门写给用户的可执行文案被压成通用的"操作失败"——updateInspection 抛的
  //      '已开始的巡检计划不能修改'、startInspection 抛的 '巡检当前状态不允许执行或
  //      您不是被指派人' 到了客户端全都变成同一句废话；
  //   ② 没有 statusCode 的驱动级故障（并发写冲突、网络中断）被伪装成 400，
  //      且 errorHandler 的 logger.error 根本没机会跑 ⇒ 服务端故障零日志；
  //   ③ VersionError 的"刷新即可重试"这类可自愈指引丢失。
  // asyncHandler 的 JSDoc 就是这个意思："避免在 async 函数中使用 try-catch"。
  // 钉住：src/tests/controllers/deviceStatusErrorMapping.test.js（同一映射面）
  const updated = await inspectionService.updateInspection(inspection, updates);
  return ApiResponse.success(res, updated, '巡检计划更新成功');
});

/**
 * 开始执行巡检
 * PUT /api/inspections/:id/start
 */
const startInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.codeError(res, 'INSPECTION_NOT_FOUND');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN');

  // 不本地吞错，理由见 updateInspection 的注释（F-173）：
  // 这里被压掉的正是 ApiError.conflict('巡检当前状态不允许执行或您不是被指派人')。
  const updated = await inspectionService.startInspection(inspection, req.user.userId);
  return ApiResponse.success(res, updated, '巡检开始执行');
});

/**
 * 提交巡检结果
 * PUT /api/inspections/:id/complete
 */
const completeInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { result, findings, location, remark } = req.body;
  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.codeError(res, 'INSPECTION_NOT_FOUND');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN');

  // findings[].deviceId 会被 INSPECTION_POPULATE populate 出 deviceCode/deviceName
  // （services/InspectionService.js:49），与 create/update 的 devices[] 同源威胁。
  // 此前 complete 这条路完全没调守卫——"已修的同类漏了一处"：
  // 持 inspection:execute（通常 self 档）者可借本人范围内的巡检，把范围外设备台账读回来。
  if (await rejectOutOfScopeReferences(req, res, { findings })) return undefined;

  // 不本地吞错，理由见 updateInspection 的注释（F-173）
  const updated = await inspectionService.completeInspection(
    inspection,
    { result, findings, location, remark },
    req.user.userId
  );
  return ApiResponse.success(res, updated, '巡检结果提交成功');
});

/**
 * 审核巡检结果
 * PUT /api/inspections/:id/review
 */
const reviewInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { reviewComment, reviewResult } = req.body;
  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.codeError(res, 'INSPECTION_NOT_FOUND');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN');

  // 不本地吞错，理由见 updateInspection 的注释（F-173）
  const updated = await inspectionService.reviewInspection(
    inspection,
    { reviewResult, reviewComment },
    req.user.userId
  );
  return ApiResponse.success(res, updated, '巡检审核完成');
});

/**
 * 取消巡检
 * PUT /api/inspections/:id/cancel
 */
const cancelInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { reason } = req.body;
  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.codeError(res, 'INSPECTION_NOT_FOUND');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN');

  // 不本地吞错，理由见 updateInspection 的注释（F-173）：
  // 服务层用 ApiError.conflict 表达"已完成/已取消不能再操作"（409），文案本就是给用户的。
  const updated = await inspectionService.cancelInspection(inspection, reason, req.user.userId);
  return ApiResponse.success(res, updated, '巡检已取消');
});

/**
 * 删除巡检
 * DELETE /api/inspections/:id
 */
const deleteInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.codeError(res, 'INSPECTION_NOT_FOUND');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN');

  // 不本地吞错，理由见 updateInspection 的注释（F-173）。
  // 这里是这套 catch 伤害最明显的一处：服务层**专门区分**了两种删除失败
  // （'正在执行的巡检不能删除' 400 / '巡检不存在或已被删除' 404，见
  // InspectionService.deleteInspection 的 TOCTOU 注释），旧的 catch 把它们压成
  // '操作失败' / '记录不存在'——区分工作的价值全部丢在最后一米。
  await inspectionService.deleteInspection(inspection);
  return ApiResponse.success(res, null, '巡检删除成功');
});

/**
 * 获取巡检统计信息
 * GET /api/inspections/stats
 */
const getInspectionStats = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;
  // 判据单源 helpers.isValidDateParam：裸 isNaN(new Date(x)) 会把 '123' 静默翻成公元 0122 年
  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
  }
  // L2：与列表同口径的数据范围，防止越权统计全组织巡检
  const dataScope = await getDataScope(req.user.userId);
  const stats = await inspectionService.getInspectionStats(startDate, endDate, dataScope);
  return ApiResponse.success(res, stats, '获取统计信息成功');
});

module.exports = {
  getInspections,
  getInspectionById,
  createInspection,
  updateInspection,
  startInspection,
  completeInspection,
  reviewInspection,
  cancelInspection,
  deleteInspection,
  getInspectionStats,
};
