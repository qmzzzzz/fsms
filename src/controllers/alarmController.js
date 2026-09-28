/**
 * 火警报警管理控制器
 * 职责：请求解析、参数校验、数据范围校验、响应格式化
 * 业务逻辑委托给 AlarmService
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const {
  getDataScope,
  assertRecordInScope,
  isDepartmentValueAllowed,
} = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { normalizePagination, isValidDateParam } = require('../utils/helpers');
const alarmService = require('../services/AlarmService');

/**
 * 校验报警记录是否在当前用户数据范围内
 *
 * 属主字段一律取自 DATA_SCOPE_FIELDS.alarm，不在此重复字面量：
 * 详情/操作与列表/统计/导出必须共用同一份声明，否则两条路径又会各走各的（P2-20 的原始教训）。
 */
const isAlarmInScope = async (req, alarm) => {
  const { ownerField, departmentField } = DATA_SCOPE_FIELDS.alarm;
  const { allowed } = await assertRecordInScope(req, alarm, ownerField, departmentField);
  return allowed;
};

/**
 * 「本条的处理人」本身就构成对**这一条**的查看/操作权
 *
 * 背景：rbac 的 self 档语义写着"仅自己创建/**负责**的数据"，而早期
 * DATA_SCOPE_FIELDS.alarm.ownerField 只有 reporter.userId —— 实现比自己的文档少了一半。
 * 于是"报岗人上报 → 主管派给消防员"之后：消防员 arrive/resolve 被数据范围挡在 403，
 * 而报岗人这边四个收口条件又都要求 handler 是自己/为空/待处理，
 * 结果这条 processing 的报警**任何人都关不掉**，只能永久悬在处置中。
 *
 * 边界（务必看清）：这里给的是**单条记录**的访问权，来源是"系统把这条派给了你"这个事实；
 * 状态机也依然在服务层把关（已终结的报警不会因为你是 handler 就能再改）。
 * 列表/统计/导出的可见集由 DATA_SCOPE_FIELDS.alarm 决定，该声明已与本处对齐
 * （ownerField 增加 handler 一臂）——**不变量是"凡单条可操作者必在列表可见"**。
 * 若只对齐详情不对齐列表，结果就是"有权限却点不到"：详情返回 403 变成列表里没有这一行，
 * 这里打通的操作权在真实界面上永远用不上。
 *
 * 对齐的连带后果（不要当成免费）：派单 dispatchAlarm 判的仍是 isAlarmInScope，
 * 因此被派单者现在也落在该报警的数据范围内，
 * 即"handler 可以把这条再转派给别人"。这是同一条属主声明的自然推论，
 * 不是额外开的口子——若要禁止，正确做法是给 dispatch 单独指定 reporter-only 的字段集，
 * 而不是回退列表口径（那会把本条修复的动机整个抹掉）。
 */
// alarm.handler 有两种形态并存：控制器读的是 alarmService.getAlarmById()，
// 那里对 handler 做了 populate → 是**用户文档**（String() 会得到 [object Object]，
// 直接比对必然永不相等——本文件首版就是这么错的）；而别的调用点可能拿到裸 ObjectId。
// 因此两种形态都要归一成 id 字符串。
const handlerIdOf = (alarm) => {
  const h = alarm && alarm.handler;
  if (!h) return '';
  if (typeof h === 'object' && h._id) return String(h._id);
  return String(h);
};

const isAssignedHandler = (req, alarm) => {
  const me = String((req.user && req.user.userId) || '');
  return Boolean(me) && handlerIdOf(alarm) === me;
};

const canOperateAlarm = async (req, alarm) =>
  isAssignedHandler(req, alarm) || (await isAlarmInScope(req, alarm));

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

  // 日期格式校验：判据单源 helpers.isValidDateParam（裸 isNaN(new Date(x)) 会把 '123' 翻成公元 0122 年）
  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
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
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const alarm = await alarmService.getAlarmById(req.params.id);
  if (!alarm) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
  if (!(await canOperateAlarm(req, alarm)))
    return ApiResponse.codeError(res, 'ALARM_VIEW_FORBIDDEN');
  return ApiResponse.success(res, alarm, '获取成功');
});

/**
 * 接收报警（手动上报）
 * POST /api/alarms/report
 */
const reportAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { alarmType, level, location, description, deviceId, reporter } = req.body;

  // deviceId 只过了 isMongoId（格式），这里补「存在 + 在本账号数据范围内」：
  // FireAlarm.deviceId 是 ref→FireDevice，且 getAlarmById 会 populate 出
  // deviceCode/deviceName/deviceType。于是
  //   · 指向不存在的设备 ⇒ 引用静默悬空，工单上没有可核对的点位，
  //     详情接口还会把那个 _id 原样回给每一个能看到这条报警的人；
  //   · 指向他人设备 ⇒ 报警一旦落到对方部门清单里，对方按正常读路径就能看到；
  //     更直接的是**上报方自己** GET 这条报警即可读到他人设备的编码/名称/类型
  //     （读路径本身判定正确，洞在写入侧没收口）。
  // 判据不另起一份：复用 assertRecordInScope + DATA_SCOPE_FIELDS.device，
  // 与 deviceController 的 isDeviceInScope 同一来源。
  if (deviceId) {
    const deviceService = require('../services/DeviceService');
    const [device] = await deviceService.findScopeFieldsByIds([deviceId]);
    if (!device) return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
    const { ownerField, departmentField } = DATA_SCOPE_FIELDS.device;
    const { allowed } = await assertRecordInScope(req, device, ownerField, departmentField);
    if (!allowed) return ApiResponse.codeError(res, 'DEVICE_VIEW_FORBIDDEN');
  }

  // location.building 就是 DATA_SCOPE_FIELDS.alarm 的 departmentField——报警落到哪个部门的
  // 清单/统计/导出里，完全由这个字段决定。上面已经拦了"别把工单挂到别人设备上"，
  // 但同一批请求里直接写一个陌生楼栋，效果一样：department 档账号往他人部门的
  // 报警列表里投毒（读路径判得对，洞在写入侧不收口）。
  // 判据复用 rbac.isDepartmentValueAllowed，与 deviceController.rejectOutOfScopeBuilding
  // 同一档位语义（self 档放行，不因填了位置就把自己锁死）。
  const reportedBuilding = location && location.building;
  if (reportedBuilding) {
    const dataScope = await getDataScope(req.user.userId);
    if (!isDepartmentValueAllowed(dataScope, reportedBuilding))
      return ApiResponse.codeError(res, 'ALARM_OPERATE_FORBIDDEN', {
        message: `无权在其他楼栋上报报警：${reportedBuilding}`,
      });
  }

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
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { handlerId } = req.body;
  // 单次查询合并：此前先 getAlarmStatus 再 getAlarmById 双查同一 ID，
  // getAlarmById 返回完整文档（含 status），存在性判断直接读其状态字段即可
  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
  if (!(await isAlarmInScope(req, fullAlarm)))
    return ApiResponse.codeError(res, 'ALARM_OPERATE_FORBIDDEN');

  // 传入数据范围：Service 层据此校验被指派人是否在操作者可管辖范围内（P2-17）
  const dataScope = await getDataScope(req.user.userId);
  const updated = await alarmService.dispatchAlarm(req.params.id, handlerId, req.user.userId, {
    dataScope,
  });
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
    return ApiResponse.codeError(res, 'ALARM_ALREADY_HANDLED');
  }
  return ApiResponse.success(res, updated, '报警已指派');
});

/**
 * 到达现场登记
 * PUT /api/alarms/:id/arrive
 */
const arriveAtScene = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
  if (!(await canOperateAlarm(req, fullAlarm)))
    return ApiResponse.codeError(res, 'ALARM_OPERATE_FORBIDDEN');

  const updated = await alarmService.arriveAtScene(req.params.id, req.user.userId);
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
    return ApiResponse.codeError(res, 'ALARM_STATUS_NOT_ALLOWED_SHORT');
  }
  return ApiResponse.success(res, updated, '已登记到达现场');
});

/**
 * 处理完成
 * PUT /api/alarms/:id/resolve
 */
const resolveAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { handleResult, cause } = req.body;
  if (!handleResult) return ApiResponse.codeError(res, 'ALARM_HANDLE_RESULT_REQUIRED');

  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
  if (!(await canOperateAlarm(req, fullAlarm)))
    return ApiResponse.codeError(res, 'ALARM_OPERATE_FORBIDDEN');

  const updated = await alarmService.resolveAlarm(
    req.params.id,
    { handleResult, cause },
    req.user.userId
  );
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
    return ApiResponse.codeError(res, 'ALARM_STATUS_NOT_ALLOWED');
  }
  return ApiResponse.success(res, updated, '报警处理完成');
});

/**
 * 标记为误报
 * PUT /api/alarms/:id/false-alarm
 */
const markAsFalseAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { reason } = req.body;
  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
  if (!(await canOperateAlarm(req, fullAlarm)))
    return ApiResponse.codeError(res, 'ALARM_OPERATE_FORBIDDEN');

  const updated = await alarmService.markAsFalseAlarm(req.params.id, reason, req.user.userId);
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
    return ApiResponse.codeError(res, 'ALARM_STATUS_NOT_ALLOWED');
  }
  return ApiResponse.success(res, updated, '已标记为误报');
});

/**
 * 取消报警
 * PUT /api/alarms/:id/cancel
 */
const cancelAlarm = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });

  const { reason } = req.body;
  const fullAlarm = await alarmService.getAlarmById(req.params.id);
  if (!fullAlarm) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
  if (!(await canOperateAlarm(req, fullAlarm)))
    return ApiResponse.codeError(res, 'ALARM_OPERATE_FORBIDDEN');

  const updated = await alarmService.cancelAlarm(req.params.id, reason, req.user.userId);
  if (!updated) {
    const exists = await alarmService.getAlarmStatus(req.params.id);
    if (!exists) return ApiResponse.codeError(res, 'ALARM_NOT_FOUND');
    return ApiResponse.codeError(res, 'ALARM_STATUS_NOT_ALLOWED');
  }
  return ApiResponse.success(res, updated, '报警已取消');
});

/**
 * 获取报警统计信息
 * GET /api/alarms/stats
 */
const getAlarmStats = asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;
  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
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
