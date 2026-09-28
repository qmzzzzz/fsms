/**
 * 巡检写路径的对象级范围闸（从 inspectionController.js 拆出）
 *
 * 拆分理由与本仓 `roleGuards.js` 同一先例：控制器超过 eslint `max-lines` 上限时
 * 收的是体积债，唯一出路是按职责拆文件（`lint:ratchet` 只许降不许升，不允许放宽基线）。
 * 三条臂各自成函数，也是为了不让一个函数的圈复杂度顶到上限。
 */
const mongoose = require('mongoose');
const ApiResponse = require('../utils/apiResponse');
const { getDataScope, isRecordInScope, isDepartmentValueAllowed } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');

const inScope = (dataScope, userId, doc, fields) =>
  isRecordInScope(dataScope, doc, {
    ownerField: fields.ownerField,
    departmentField: fields.departmentField,
    userId,
  });

const stringifyIds = (list) => [...new Set(list.map((id) => String(id)))];

/**
 * `assignedTo` 必须落在操作者的数据范围内。
 *
 * 路由只判 `isMongoId` 格式，于是可以把计划指派给任意部门的任意用户；
 * 而 `startInspection` 的开工条件恰恰是"assignedTo 含操作者"——
 * 等于把别人的账号变成开工身份。
 * 属主/部门字段一律取自 DATA_SCOPE_FIELDS.user；"指派给自己"由 isRecordInScope 的
 * 自记录短路放行（self 档因此仍能把活派给自己）。
 */
const rejectOutOfScopeAssignees = async (res, dataScope, userId, assignedTo) => {
  if (!Array.isArray(assignedTo) || assignedTo.length === 0) return false;
  const userService = require('../services/userService');
  const ids = stringifyIds(assignedTo);
  const docs = await userService.findScopeFieldsByIds(ids);
  if (docs.length !== ids.length) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', { message: '指定的执行人不存在' });
  }
  for (const d of docs) {
    if (!inScope(dataScope, userId, d, DATA_SCOPE_FIELDS.user)) {
      return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN', {
        message: '无权将巡检指派给数据范围外的人员',
      });
    }
  }
  return false;
};

/**
 * `devices` 必须真实存在且在范围内。
 *
 * 悬空引用会让计划无法开工并长期挂在 pending 统计里；而 `getInspectionById` 会
 * populate 出 `deviceCode/deviceName/deviceType/location` ⇒ 引用他人设备等于把
 * 别人的设备台账随计划一起带出。设备删除侧（DeviceService.deleteDevice）已按
 * `devices` 数组 $pull 做级联，这一处堵的是"写入时就不该能引用范围外/不存在的设备"。
 */
const rejectOutOfScopeDevices = async (res, dataScope, userId, devices) => {
  if (!Array.isArray(devices) || devices.length === 0) return false;
  const deviceService = require('../services/DeviceService');
  const ids = stringifyIds(devices);
  // 非法 ID 不进 $in（会抛 CastError 变 500），与"不存在"走同一拒绝口径
  if (ids.some((id) => !mongoose.isValidObjectId(id))) {
    return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  }
  const docs = await deviceService.findScopeFieldsByIds(ids);
  if (docs.length !== ids.length) {
    return ApiResponse.codeError(res, 'DEVICE_NOT_FOUND');
  }
  for (const d of docs) {
    if (!inScope(dataScope, userId, d, DATA_SCOPE_FIELDS.device)) {
      return ApiResponse.codeError(res, 'DEVICE_VIEW_FORBIDDEN', {
        message: '无权引用数据范围外的设备',
      });
    }
  }
  return false;
};

/**
 * `locations[].building` 就是 inspection 的 departmentField ⇒ 只能填自己的部门。
 *
 * 只判"确实填了楼栋"的项：留空的记录本就落在任何部门清单之外，不构成越权写入，
 * 把它一并拒掉会误伤只填楼层/区域的合法入参。
 * 档位语义（all 不限 / self 该维度不参与 / none 一律拒）取自 rbac 的
 * `isDepartmentValueAllowed`——设备侧写同一个字段，必须共用这一份判据。
 */
const rejectOutOfScopeBuildings = (res, dataScope, locations) => {
  if (!Array.isArray(locations) || locations.length === 0) return false;
  const buildings = locations.map((l) => l && l.building).filter(Boolean);
  // 先判"有没有越界的"，再取第一个用于文案。
  // 不能用 `const bad = find(...); if (!bad) return false;`：find 命中时返回的就是那个
  // 越界值本身，若它恰好是假值（如 ''），拒绝会被读成"没有越界"而静默放行。
  const isBad = (b) => !isDepartmentValueAllowed(dataScope, b);
  if (!buildings.some(isBad)) return false;
  const bad = buildings.find(isBad);
  return ApiResponse.codeError(res, 'INSPECTION_OPERATE_FORBIDDEN', {
    message:
      dataScope.type === 'none'
        ? '当前账户无数据范围，不能指定巡检楼栋'
        : `无权在其他楼栋创建巡检计划：${bad}`,
  });
};

/**
 * 从 `findings` 里取出"确实填了设备"的 deviceId。
 *
 * 只判填了设备的发现项：留空的发现项是纯文字问题描述（如"通道畅通"），不构成设备引用，
 * 一并拒掉会误伤合法入参——与 `rejectOutOfScopeBuildings` 只判 `buildings.filter(Boolean)`
 * 的口径一致。
 */
const collectFindingDeviceIds = (findings) => {
  if (!Array.isArray(findings)) return [];
  return findings.map((f) => f && f.deviceId).filter(Boolean);
};

/**
 * 巡检**写入**路径的统一入口（create / update / complete）：任一臂被拒即已写出响应，
 * 调用方应立刻 return。
 * @returns {Promise<boolean>}
 */
const rejectOutOfScopeReferences = async (
  req,
  res,
  { assignedTo, devices, locations, findings } = {}
) => {
  // getDataScope 只查一次，四条臂共用（各自查就是每次一遍带 populate 的查询）
  const dataScope = await getDataScope(req.user.userId);
  const userId = req.user.userId;
  if (await rejectOutOfScopeAssignees(res, dataScope, userId, assignedTo)) return true;
  if (await rejectOutOfScopeDevices(res, dataScope, userId, devices)) return true;
  // `findings[].deviceId` 与 `devices[]` 是**同一种**威胁：INSPECTION_POPULATE
  // （services/InspectionService.js:49）会把二者的 deviceCode/deviceName 一起 populate 出来
  // ⇒ 引用范围外设备 = 把别人的设备台账随记录带出。原先只堵了 `devices[]`，
  // 而**提交结果（complete）这条路连守卫都没调**，findings 是漏掉的那一处。
  // 复用同一份存在性+范围判据，不另写一遍（否则又是一处会漂移的副本）。
  if (await rejectOutOfScopeDevices(res, dataScope, userId, collectFindingDeviceIds(findings)))
    return true;
  return Boolean(rejectOutOfScopeBuildings(res, dataScope, locations));
};

module.exports = {
  rejectOutOfScopeReferences,
  rejectOutOfScopeAssignees,
  rejectOutOfScopeDevices,
  rejectOutOfScopeBuildings,
};
