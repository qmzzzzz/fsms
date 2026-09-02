/**
 * 火警报警管理控制器
 * 职责：请求解析、参数校验、数据范围校验、响应格式化
 * 业务逻辑委托给 AlarmService
 */

const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope, assertRecordInScope } = require('../middleware/rbac');
const { normalizePagination } = require('../utils/helpers');
const alarmService = require('../services/AlarmService');

/**
 * 校验报警记录是否在当前用户数据范围内
 */
const isAlarmInScope = async (req, alarm) => {
  const { allowed } = await assertRecordInScope(req, alarm, 'reporter.userId', 'location.building');
  return allowed;
};

/**
 * 获取报警列表
 * GET /api/alarms
 *
 * E-2：支持游标分页。传 cursor 时走 keyset seek（不带 total，
 * 响应携带 hasMore/nextCursor）；不传保持原 page/limit 语义。
 */
const getAlarms = asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 10,
    cursor,
    status,
    level,
    alarmType,
    startDate,
    endDate,
    search,
  } = req.query;

  // 日期格式校验
  if (
    (startDate && isNaN(new Date(startDate).getTime())) ||
    (endDate && isNaN(new Date(endDate).getTime()))
  ) {
    return ApiResponse.error(res, '日期参数格式错误', 400);
  }

  const dataScope = await getDataScope(req.user.userId);
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 100);

  const { alarms, count, hasMore, nextCursor } = await alarmService.getAlarms({
    page: pageNum,
    limit: limitNum,
    cursor,
    status,
    level,
    alarmType,
    startDate,
    endDate,
    search,
    dataScope,
  });

  if (cursor) {
    return ApiResponse.paginated(
      res,
      alarms,
      {
        page: null,
        limit: limitNum,
        total: null,
        totalPages: null,
        hasMore,
        nextCursor,
      },
      '获取报警列表成功'
    );
  }

  return ApiResponse.paginated(
    res,
    alarms,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
      nextCursor,
    },
    '获取报警列表成功'
  );
});

/**
 * 获取报警详情
 * GET /api/alarms/:id
 */
const getAlarmById = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const alarm = await alarmService.getAlarmById(req.params.id);
  if (!alarm) return ApiResponse.notFound(res, '报警记录不存在');
  if (!(await isAlarmInScope(req, alarm))) return ApiResponse.forbidden(res, '无权查看该报警记录');
  return ApiResponse.success(res, alarm, '获取成功');
});

/**
 * 接收报警（手动上报）
 * POST /api/alarms/report
 */
const reportAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { alarmType, level, location, description, deviceId, reporter } = req.body;
  const alarm = await alarmService.reportAlarm({
    alarmType,
    level,
    location,
    description,
    deviceId,
    reporterName: reporter?.name,
    reporterPhone: reporter?.phone,
    userId: req.user.userId,
    username: req.user.realName || req.user.username,
  });

  return ApiResponse.success(res, alarm, '报警接收成功', 201);
});

/**
 * 受理报警（分配处理人）
 * PUT /api/alarms/:id/dispatch
 */
const dispatchAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { handlerId } = req.body;
  // 单次查询合并：此前先 getAlarmStatus 再 getAlarmById 双查同一 ID，
  // getAlarmById 返回完整文档（含 status），存在性判断直接读其状态字段即可
  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.notFound(res, '报警记录不存在');
  if (!(await isAlarmInScope(req, fullAlarm)))
    return ApiResponse.forbidden(res, '无权操作该报警记录');

  // 传入数据范围：Service 层据此校验被指派人是否在操作者可管辖范围内（P2-17）
  const dataScope = await getDataScope(req.user.userId);
  const updated = await alarmService.dispatchAlarm(req.params.id, handlerId, req.user.userId, {
    dataScope,
  });
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.notFound(res, '报警记录不存在');
    return ApiResponse.error(res, '该报警已被处理', 409);
  }
  return ApiResponse.success(res, updated, '报警已指派');
});

/**
 * 到达现场登记
 * PUT /api/alarms/:id/arrive
 */
const arriveAtScene = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.notFound(res, '报警记录不存在');
  if (!(await isAlarmInScope(req, fullAlarm)))
    return ApiResponse.forbidden(res, '无权操作该报警记录');

  const updated = await alarmService.arriveAtScene(req.params.id, req.user.userId);
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.notFound(res, '报警记录不存在');
    return ApiResponse.error(res, '报警状态不允许此操作', 409);
  }
  return ApiResponse.success(res, updated, '已登记到达现场');
});

/**
 * 处理完成
 * PUT /api/alarms/:id/resolve
 */
const resolveAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { handleResult, cause } = req.body;
  if (!handleResult) return ApiResponse.error(res, '请提供处理结果描述', 400);

  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.notFound(res, '报警记录不存在');
  if (!(await isAlarmInScope(req, fullAlarm)))
    return ApiResponse.forbidden(res, '无权操作该报警记录');

  const updated = await alarmService.resolveAlarm(
    req.params.id,
    { handleResult, cause },
    req.user.userId
  );
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.notFound(res, '报警记录不存在');
    return ApiResponse.error(res, '该报警当前状态不允许此操作', 409);
  }
  return ApiResponse.success(res, updated, '报警处理完成');
});

/**
 * 标记为误报
 * PUT /api/alarms/:id/false-alarm
 */
const markAsFalseAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { reason } = req.body;
  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.notFound(res, '报警记录不存在');
  if (!(await isAlarmInScope(req, fullAlarm)))
    return ApiResponse.forbidden(res, '无权操作该报警记录');

  const updated = await alarmService.markAsFalseAlarm(req.params.id, reason, req.user.userId);
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.notFound(res, '报警记录不存在');
    return ApiResponse.error(res, '该报警当前状态不允许此操作', 409);
  }
  return ApiResponse.success(res, updated, '已标记为误报');
});

/**
 * 取消报警
 * PUT /api/alarms/:id/cancel
 */
const cancelAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { reason } = req.body;
  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.notFound(res, '报警记录不存在');
  if (!(await isAlarmInScope(req, fullAlarm)))
    return ApiResponse.forbidden(res, '无权操作该报警记录');

  const updated = await alarmService.cancelAlarm(req.params.id, reason, req.user.userId);
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.notFound(res, '报警记录不存在');
    return ApiResponse.error(res, '该报警当前状态不允许此操作', 409);
  }
  return ApiResponse.success(res, updated, '报警已取消');
});

/**
 * 获取报警统计信息
 * GET /api/alarms/stats
 */
const getAlarmStats = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;
  if (
    (startDate && isNaN(new Date(startDate).getTime())) ||
    (endDate && isNaN(new Date(endDate).getTime()))
  ) {
    return ApiResponse.error(res, '日期参数格式错误', 400);
  }
  const dataScope = await getDataScope(req.user.userId);
  const stats = await alarmService.getAlarmStats(startDate, endDate, dataScope);
  return ApiResponse.success(res, stats, '获取统计信息成功');
});

module.exports = {
  getAlarms,
  getAlarmById,
  getAlarmStats,
  reportAlarm,
  dispatchAlarm,
  arriveAtScene,
  resolveAlarm,
  markAsFalseAlarm,
  cancelAlarm,
};
