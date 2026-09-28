/**
 * 消防设备管理控制器
 * 职责：请求解析、参数校验、数据范围校验、响应格式化
 * 业务逻辑委托给 DeviceService
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const { normalizeExpiringDays, EXPIRING_LIST_LIMIT } = require('../constants/deviceAlerts');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const {
  getDataScope,
  buildDataScopeFilter,
  assertRecordInScope,
  isDepartmentValueAllowed,
} = require('../middleware/rbac');
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
 * 楼栋（设备的 departmentField）必须落在操作者自己的部门内
 *
 * 创建与更新都判，且更新判的是**新值**：`location.building` 在更新白名单里，
 * 而范围闸此前只看"改前这条在不在范围内" ⇒ 一次合法的 PUT 就能把设备搬到
 * 别的部门名下（搬出后即脱离自己可见范围，也从别人的清单里凭空出现）。
 * 判据与巡检共用 rbac.isDepartmentValueAllowed，不在此重复档位语义。
 * @param {string|undefined} building 本次要写入的楼栋；未填则不判（留空不构成搬迁）
 * @returns {Promise<boolean>} true 表示已写出拒绝响应，调用方应立即 return
 */
const rejectOutOfScopeBuilding = async (req, res, building) => {
  if (building === undefined || building === null || building === '') return false;
  const dataScope = await getDataScope(req.user.userId);
  if (isDepartmentValueAllowed(dataScope, building)) return false;
  return ApiResponse.codeError(res, 'DEVICE_OPERATE_FORBIDDEN', {
    message: `无权在其他楼栋登记设备：${building}`,
  });
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
  if (!device) return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  if (!(await isDeviceInScope(req, device)))
    return ApiResponse.codeError(res, 'DEVICE_VIEW_FORBIDDEN');
  return ApiResponse.success(res, device, '获取成功');
});

/**
 * 创建设备
 * POST /api/devices
 */
const createDevice = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

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

  if (await rejectOutOfScopeBuilding(req, res, allowedFields.location.building)) return undefined;

  const device = await deviceService.createDevice(allowedFields, req.user.userId);
  return ApiResponse.success(res, device, '设备创建成功', 201);
});

/**
 * 更新设备信息
 * PUT /api/devices/:id
 */
const updateDevice = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  if (!(await isDeviceInScope(req, device)))
    return ApiResponse.codeError(res, 'DEVICE_OPERATE_FORBIDDEN');

  // 判**新值**：改前在范围内不代表改后仍在。楼栋与改前一致时不判
  // （客户端常把整个 location 原样回传，那不是"搬迁"）。
  const incomingBuilding =
    req.body.location && req.body.location.building !== undefined
      ? req.body.location.building
      : req.body.building;
  if (
    incomingBuilding !== undefined &&
    incomingBuilding !== (device.location && device.location.building) &&
    (await rejectOutOfScopeBuilding(req, res, incomingBuilding))
  )
    return undefined;

  const updated = await deviceService.updateDevice(device, req.body);
  return ApiResponse.success(res, updated, '设备更新成功');
});

/**
 * 更新设备状态
 * PUT /api/devices/:id/status
 */
const updateDeviceStatus = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { status } = req.body;
  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  if (!(await isDeviceInScope(req, device)))
    return ApiResponse.codeError(res, 'DEVICE_OPERATE_FORBIDDEN');

  // 不写本地 try/catch：错误到 HTTP 的映射只有 errorHandler 一处实现，本地吞错会同时
  // 破坏三件事——① device.save()/transitionTo() 抛出的驱动级故障没有 statusCode，
  // `err.statusCode || 400` 把它伪装成客户端错误（监控看不到 5xx，用户以为重试无用）；
  // ② 那条路径上一行日志都不留（errorHandler 的 logger.error 根本没机会跑）；
  // ③ 服务层专门写给用户的文案（'设备已报废，不能再变更状态'）和乐观并发冲突的
  // 可自愈文案（VersionError → '请刷新后重试'）被压成通用的"操作失败"。
  // asyncHandler 的 JSDoc 就是这个意思："避免在 async 函数中使用 try-catch"。
  // 钉住：src/tests/controllers/deviceStatusErrorMapping.test.js
  const updated = await deviceService.updateDeviceStatus(device, status);
  return ApiResponse.success(res, updated, '状态更新成功');
});

/**
 * 添加维护记录
 * POST /api/devices/:id/maintenance
 */
const addMaintenanceRecord = asyncHandler(async (req, res) => {
  // 路由链已挂 maintenanceValidation（deviceRoutes.js:169-180：content 1-500、type 枚举），
  // 但本控制器此前从不消费 validationResult → 校验器是死代码：非法 type 直冲模型 enum
  // 抛 ValidationError→500（应 400），content 无 schema 上限→存储无界。补齐与其它写入口一致的守卫。
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { content, type } = req.body;
  if (!content) return ApiResponse.codeError(res, 'MAINTENANCE_CONTENT_REQUIRED');

  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  if (!(await isDeviceInScope(req, device)))
    return ApiResponse.codeError(res, 'DEVICE_OPERATE_FORBIDDEN');

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
  if (!device) return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  if (!(await isDeviceInScope(req, device)))
    return ApiResponse.codeError(res, 'DEVICE_OPERATE_FORBIDDEN');

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
 *
 * F-174：清单被 `EXPIRING_LIST_LIMIT` 截断，而原先的 `ApiResponse.success` 把裸数组
 * 放进 `data`——"库里就 50 台"与"库里 512 台、只给最先到期的 50 台"在响应上完全同形。
 * 这不是显示问题：安全员照着屏幕上这份清单排巡检、备耗材，而系统知道还有一大半没显示。
 * 改走 `paginated`（`data` **仍是数组**，新增的是 `pagination` 兄弟键 ⇒ 对既有调用方是
 * 纯增补），把真实 `total` 与 `hasMore` 交出去。
 *
 * `page`/`totalPages` 取 null 而不是 1/N：本接口没有翻页入参，填上 `totalPages: 11`
 * 等于许诺"还能取第 2 页"，而客户端真去取时会原样拿回第 1 页——那是换一个方向的谎。
 * 同一套写法见上面游标分支（getDevices 的 `page:null/total:null/hasMore`）。
 * 补真正的分页要新增对外查询参数（含路由校验与 OpenAPI 契约变更），不在这个改动里顺手做。
 */
const getExpiringDevices = asyncHandler(async (req, res) => {
  const { days = 30 } = req.query;
  // H-1：与列表/统计同口径注入数据范围，防止越权枚举全组织设备位置
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = buildDeviceScopeFilter(dataScope);
  const { devices, total } = await deviceService.getExpiringDevices(days, scopeFilter, {
    withTotal: true,
  });
  const truncated = total > devices.length;
  return ApiResponse.paginated(
    res,
    devices,
    {
      page: null,
      limit: EXPIRING_LIST_LIMIT,
      total,
      totalPages: null,
      hasMore: truncated,
    },
    // 截断事实同时进 message：前端 toast 读的就是它，只有 pagination 可读
    // 等于只有机器能发现被截断——而对着屏幕做判断的是人。
    truncated
      ? `获取即将到期设备成功（共 ${total} 台，仅返回最先到期的 ${EXPIRING_LIST_LIMIT} 台，请缩小 days 窗口分批查看）`
      : '获取即将到期设备成功'
  );
});

/**
 * 设备报废
 * PUT /api/devices/:id/scrap
 */
const scrapDevice = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { scrapReason, scrapDate } = req.body;
  const device = await deviceService.getDeviceById(req.params.id);
  if (!device) return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  if (!(await isDeviceInScope(req, device)))
    return ApiResponse.codeError(res, 'DEVICE_OPERATE_FORBIDDEN');

  const updated = await deviceService.scrapDevice(device, scrapReason, scrapDate);
  return ApiResponse.success(res, updated, '设备报废成功');
});

/**
 * 获取设备到期/维护提醒
 * GET /api/devices/reminders
 */
const getDeviceReminders = asyncHandler(async (req, res) => {
  const { getDeviceReminders: getReminders } = require('../services/deviceReminder');
  const daysNum = normalizeExpiringDays(req.query.days);
  // H-1：按调用者数据范围过滤；带 scopeFilter 的查询绕过全局缓存且每维度限 200 条
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = buildDeviceScopeFilter(dataScope);
  const reminders = await getReminders({ expiringDays: daysNum, scopeFilter });
  // 降级信号走响应体的 partial/skipped（服务层已保证形状完整，见 deviceReminder.unscannedResult）；
  // 话术按 HTTP 语义仍为成功——非 2xx 会让前端把"扫描进行中"当成请求失败去重试整页
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
