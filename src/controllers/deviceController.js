/**
 * 消防设备管理控制器
 * 职责：请求解析、参数校验、数据范围校验、响应格式化
 * 业务逻辑委托给 DeviceService
 */

const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope, buildDataScopeFilter, assertRecordInScope } = require('../middleware/rbac');
const { normalizePagination } = require('../utils/helpers');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const deviceService = require('../services/DeviceService');

/**
 * 校验设备是否在当前用户数据范围内
 *
 * P2-20：属主字段取自 DATA_SCOPE_FIELDS 单一声明。
 * 此前详情用 maintenanceRecord.operator、报表/导出/统计用 createdBy，
 * 同一台设备在不同接口的可见性互相矛盾（导出口径比列表宽，构成越权面）。
 */
const isDeviceInScope = async (req, device) => {
  const { ownerField, departmentField } = DATA_SCOPE_FIELDS.device;
  const { allowed } = await assertRecordInScope(req, device, ownerField, departmentField);
  return allowed;
};

/**
 * 生成设备资源的数据范围过滤条件（统计/导出/提醒共用同一口径）
 */
const buildDeviceScopeFilter = (dataScope) => {
  const { ownerField, departmentField } = DATA_SCOPE_FIELDS.device;
  return buildDataScopeFilter(dataScope, ownerField, departmentField);
};

/**
 * 获取设备列表
 * GET /api/devices
 *
 * E-2：支持游标分页。传 cursor 时走 keyset seek（不带 total，
 * 响应携带 hasMore/nextCursor）；不传保持原 page/limit 语义。
 */
const getDevices = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, cursor, deviceType, status, building, floor, search } = req.query;
  const dataScope = await getDataScope(req.user.userId);
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 100);

  const { devices, count, hasMore, nextCursor } = await deviceService.getDevices({
    page: pageNum,
    limit: limitNum,
    cursor,
    deviceType,
    status,
    building,
    floor,
    search,
    dataScope,
  });

  if (cursor) {
    return ApiResponse.paginated(
      res,
      devices,
      {
        page: null,
        limit: limitNum,
        total: null,
        totalPages: null,
        hasMore,
        nextCursor,
      },
      '获取设备列表成功'
    );
  }

  return ApiResponse.paginated(
    res,
    devices,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
      nextCursor,
    },
    '获取设备列表成功'
  );
});

/**
 * 获取设备详情
 * GET /api/devices/:id
 */
const getDeviceById = asyncHandler(async (req, res) => {
  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.notFound(res, '设备不存在');
  if (!(await isDeviceInScope(req, device))) return ApiResponse.forbidden(res, '无权查看该设备');
  return ApiResponse.success(res, device, '获取成功');
});

/**
 * 创建设备
 * POST /api/devices
 */
const createDevice = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const allowedFields = (({
    deviceCode,
    deviceName,
    deviceType,
    model,
    manufacturer,
    location,
    building,
    floor,
    room,
    installDate,
    commissionDate,
    expiryDate,
    checkCycle,
    remark,
    images,
  }) => ({
    deviceCode,
    deviceName,
    deviceType,
    model,
    manufacturer,
    // 路由校验过的顶层 building/floor/room 并入 location（嵌套值优先），
    // 避免已校验字段被白名单静默丢弃（不丢数据原则）
    location: {
      ...(building !== undefined ? { building } : {}),
      ...(floor !== undefined ? { floor } : {}),
      ...(room !== undefined ? { room } : {}),
      ...(location || {}),
    },
    installDate,
    commissionDate,
    expiryDate,
    checkCycle,
    remark,
    images,
  }))(req.body);

  const device = await deviceService.createDevice(allowedFields, req.user.userId);
  return ApiResponse.success(res, device, '设备创建成功', 201);
});

/**
 * 更新设备信息
 * PUT /api/devices/:id
 */
const updateDevice = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.notFound(res, '设备不存在');
  if (!(await isDeviceInScope(req, device))) return ApiResponse.forbidden(res, '无权操作该设备');

  const updated = await deviceService.updateDevice(device, req.body);
  return ApiResponse.success(res, updated, '设备更新成功');
});

/**
 * 更新设备状态
 * PUT /api/devices/:id/status
 */
const updateDeviceStatus = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { status } = req.body;
  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.notFound(res, '设备不存在');
  if (!(await isDeviceInScope(req, device))) return ApiResponse.forbidden(res, '无权操作该设备');

  try {
    const updated = await deviceService.updateDeviceStatus(device, status);
    return ApiResponse.success(res, updated, '状态更新成功');
  } catch (err) {
    return ApiResponse.error(res, err.message, err.statusCode || 400);
  }
});

/**
 * 添加维护记录
 * POST /api/devices/:id/maintenance
 */
const addMaintenanceRecord = asyncHandler(async (req, res) => {
  const { content, type } = req.body;
  if (!content) return ApiResponse.error(res, '请提供维护内容', 400);

  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.notFound(res, '设备不存在');
  if (!(await isDeviceInScope(req, device))) return ApiResponse.forbidden(res, '无权操作该设备');

  // type 透传：repair/replacement 属维修行为，不应顺延检查周期
  // （模型层 addMaintenanceRecord 按此区分，见 FireDevice.js 注释）
  const updated = await deviceService.addMaintenanceRecord(device, content, req.user.userId, type);
  return ApiResponse.success(res, updated, '维护记录添加成功');
});

/**
 * 删除设备
 * DELETE /api/devices/:id
 */
const deleteDevice = asyncHandler(async (req, res) => {
  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.notFound(res, '设备不存在');
  if (!(await isDeviceInScope(req, device))) return ApiResponse.forbidden(res, '无权操作该设备');

  await deviceService.deleteDevice(device);
  return ApiResponse.success(res, null, '设备删除成功');
});

/**
 * 获取设备统计信息
 * GET /api/devices/stats
 */
const getDeviceStats = asyncHandler(async (req, res) => {
  // 数据范围控制（与 getUserStats 口径一致，防止越权看到全组织统计）
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = buildDeviceScopeFilter(dataScope);

  const stats = await deviceService.getDeviceStats(scopeFilter);
  return ApiResponse.success(res, stats, '获取统计信息成功');
});

/**
 * 获取即将到期设备列表
 * GET /api/devices/expiring
 */
const getExpiringDevices = asyncHandler(async (req, res) => {
  const { days = 30 } = req.query;
  // H-1：与列表/统计同口径注入数据范围，防止越权枚举全组织设备位置
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = buildDeviceScopeFilter(dataScope);
  const devices = await deviceService.getExpiringDevices(days, scopeFilter);
  return ApiResponse.success(res, devices, '获取即将到期设备成功');
});

/**
 * 设备报废
 * PUT /api/devices/:id/scrap
 */
const scrapDevice = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return ApiResponse.error(res, '数据验证失败', 400, errors.array());

  const { scrapReason, scrapDate } = req.body;
  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.notFound(res, '设备不存在');
  if (!(await isDeviceInScope(req, device))) return ApiResponse.forbidden(res, '无权操作该设备');

  const updated = await deviceService.scrapDevice(device, scrapReason, scrapDate);
  return ApiResponse.success(res, updated, '设备报废成功');
});

/**
 * 获取设备到期/维护提醒
 * GET /api/devices/reminders
 */
const getDeviceReminders = asyncHandler(async (req, res) => {
  const { getDeviceReminders: getReminders } = require('../services/deviceReminder');
  const daysNum = Math.min(365, Math.max(1, parseInt(req.query.days, 10) || 30));
  // H-1：按调用者数据范围过滤；带 scopeFilter 的查询绕过全局缓存且每维度限 200 条
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = buildDeviceScopeFilter(dataScope);
  const reminders = await getReminders({ expiringDays: daysNum, scopeFilter });
  return ApiResponse.success(res, reminders, '获取设备提醒成功');
});

module.exports = {
  getDevices,
  getDeviceById,
  createDevice,
  updateDevice,
  updateDeviceStatus,
  addMaintenanceRecord,
  deleteDevice,
  getDeviceStats,
  getExpiringDevices,
  scrapDevice,
  getDeviceReminders,
};
