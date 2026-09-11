/**
 * 巡检管理控制器
 * 职责：请求解析、参数校验、数据范围校验、响应格式化
 * 业务逻辑委托给 InspectionService
 */

const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope, assertRecordInScope } = require('../middleware/rbac');
const { normalizePagination } = require('../utils/helpers');
const inspectionService = require('../services/InspectionService');

/**
 * 校验巡检记录是否在当前用户数据范围内
 */
const isInspectionInScope = async (req, inspection) => {
  const { allowed } = await assertRecordInScope(
    req,
    inspection,
    'assignedTo',
    'locations.building'
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

  if (
    (startDate && isNaN(new Date(startDate).getTime())) ||
    (endDate && isNaN(new Date(endDate).getTime()))
  ) {
    return ApiResponse.error(res, '日期参数格式错误', 400);
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
  if (!inspection) return ApiResponse.notFound(res, '巡检记录不存在');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.forbidden(res, '无权查看该巡检记录');
  return ApiResponse.success(res, inspection, '获取成功');
});

/**
 * 创建巡检计划
 * POST /api/inspections
 */
const createInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

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

  const inspection = await inspectionService.createInspection(allowedFields);
  return ApiResponse.success(res, inspection, '巡检计划创建成功', 201);
});

/**
 * 更新巡检计划
 * PUT /api/inspections/:id
 */
const updateInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.notFound(res, '巡检记录不存在');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.forbidden(res, '无权操作该巡检记录');

  try {
    const updated = await inspectionService.updateInspection(inspection, req.body);
    return ApiResponse.success(res, updated, '巡检计划更新成功');
  } catch (err) {
    return ApiResponse.error(res, err.statusCode === 404 ? '记录不存在' : '操作失败', err.statusCode || 400);
  }
});

/**
 * 开始执行巡检
 * PUT /api/inspections/:id/start
 */
const startInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.notFound(res, '巡检记录不存在');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.forbidden(res, '无权操作该巡检记录');

  try {
    const updated = await inspectionService.startInspection(inspection, req.user.userId);
    return ApiResponse.success(res, updated, '巡检开始执行');
  } catch (err) {
    return ApiResponse.error(res, err.statusCode === 404 ? '记录不存在' : '操作失败', err.statusCode || 400);
  }
});

/**
 * 提交巡检结果
 * PUT /api/inspections/:id/complete
 */
const completeInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { result, findings, location, remark } = req.body;
  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.notFound(res, '巡检记录不存在');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.forbidden(res, '无权操作该巡检记录');

  try {
    const updated = await inspectionService.completeInspection(
      inspection,
      { result, findings, location, remark },
      req.user.userId
    );
    return ApiResponse.success(res, updated, '巡检结果提交成功');
  } catch (err) {
    return ApiResponse.error(res, err.statusCode === 404 ? '记录不存在' : '操作失败', err.statusCode || 400);
  }
});

/**
 * 审核巡检结果
 * PUT /api/inspections/:id/review
 */
const reviewInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { reviewComment, reviewResult } = req.body;
  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.notFound(res, '巡检记录不存在');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.forbidden(res, '无权操作该巡检记录');

  try {
    const updated = await inspectionService.reviewInspection(
      inspection,
      { reviewResult, reviewComment },
      req.user.userId
    );
    return ApiResponse.success(res, updated, '巡检审核完成');
  } catch (err) {
    return ApiResponse.error(res, err.statusCode === 404 ? '记录不存在' : '操作失败', err.statusCode || 400);
  }
});

/**
 * 取消巡检
 * PUT /api/inspections/:id/cancel
 */
const cancelInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { reason } = req.body;
  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.notFound(res, '巡检记录不存在');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.forbidden(res, '无权操作该巡检记录');

  try {
    const updated = await inspectionService.cancelInspection(inspection, reason, req.user.userId);
    return ApiResponse.success(res, updated, '巡检已取消');
  } catch (err) {
    return ApiResponse.error(res, err.statusCode === 404 ? '记录不存在' : '操作失败', err.statusCode || 400);
  }
});

/**
 * 删除巡检
 * DELETE /api/inspections/:id
 */
const deleteInspection = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const inspection = await inspectionService.getInspectionById(req.params.id);
  if (!inspection) return ApiResponse.notFound(res, '巡检记录不存在');
  if (!(await isInspectionInScope(req, inspection)))
    return ApiResponse.forbidden(res, '无权操作该巡检记录');

  try {
    await inspectionService.deleteInspection(inspection);
    return ApiResponse.success(res, null, '巡检删除成功');
  } catch (err) {
    return ApiResponse.error(res, err.statusCode === 404 ? '记录不存在' : '操作失败', err.statusCode || 400);
  }
});

/**
 * 获取巡检统计信息
 * GET /api/inspections/stats
 */
const getInspectionStats = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;
  if (
    (startDate && isNaN(new Date(startDate).getTime())) ||
    (endDate && isNaN(new Date(endDate).getTime()))
  ) {
    return ApiResponse.error(res, '日期参数格式错误', 400);
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
