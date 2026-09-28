/**
 * 报表导出服务（第二轮审计 O-1：自 reportController 抽取的导出组件区）
 *
 * 迁出内容：导出配置（sheet 名/模型/列定义/行转换/展示名映射）、
 * 查询构建（buildExportQuery）、枚举校验（validateAuditExportEnums）。
 * 控制器只保留参数校验、权限闸与响应编排。
 *
 * L-18 修正：原文件头还声称本模块迁出了「流式写出（streamExportRows）与
 * workbook 编排（writeExportWorkbook）」，但这两个函数实际位于
 * services/reportWorkbookService.js，本模块的 module.exports 中并无它们。
 * 已删去该失实描述——按原描述去本文件找函数会扑空。
 *
 * 行为口径与迁移前逐项一致，仅结构调整；行级日期格式化同步收敛到
 * utils/dateFormat（O-6：原 7 处分散的 toLocaleString('zh-CN')，其中
 * audit 列显式 hour12:false、其余依赖隐式默认——已验证两者输出一致，
 * 统一为显式实现）。
 */

const mongoose = require('mongoose');
const FireDevice = require('../models/FireDevice');
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');
const AuditLog = require('../models/AuditLog');
const { escapeRegExp, sanitizeSpreadsheetCell, validateEnum } = require('../utils/helpers');
const { buildDataScopeFilter } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
// 审计枚举单一事实来源：constants/audit.js（D-1 起 AUDIT_LOG_ACTIONS 亦收敛于此）。
// level 三级展示口径原先本文件写两份字面量（下面的 includes 闸门 + 枚举校验）、
// utils/auditQuery.js 再写一份 ⇒ 单侧增删即"查询放行、导出 400"，现统一取常量版。
const {
  AUDIT_CATEGORIES,
  AUDIT_RISK_LEVELS,
  AUDIT_DISPLAY_LEVELS,
  AUDIT_LOG_ACTIONS,
  AUDIT_ERROR_RISK_LEVELS,
} = require('../constants/audit');
const { normalizeIP, ipQueryCondition } = require('../utils/ipUtils');
// success 解析与三级展示口径（level → Mongo 条件）都与审计查询侧共用同一实现
// （两份曾各写一遍、靠注释约定同口径）
const { parseSuccessFilter, buildLevelCondition } = require('../utils/auditQuery');
const { formatDateTime, formatDate } = require('../utils/dateFormat');
const { castScopeObjectIds } = require('../utils/scopeCast');

const EXPORT_LIMIT = 5000;

/**
 * 按资源类型生成数据范围过滤条件（P2-20 单一口径入口）
 *
 * 此前每个统计/导出分支各自硬编码属主字段，设备资源在列表用
 * maintenanceRecord.operator、在报表用 createdBy，两套口径导致
 * 「可见清单」与「统计数字」永久对不上，且导出比列表宽（越权面）。
 *
 * cast 走 utils/scopeCast 的唯一实现（聚合前必须把 hex 字符串转 ObjectId，
 * `aggregate([{$match}])` 不做 schema cast）。本文件原先有一份同逻辑私有实现，
 * 但它只在对象分支里判 hex，`{x:{$in:['<hex>']}}` 的数组元素会原样漏掉——
 * 与 shared 版并存就是第二次漂移，故删除并统一引用。
 * @param {'device'|'alarm'|'inspection'|'user'} resource
 */
const scopeFilterFor = (resource, dataScope) => {
  const { ownerField, departmentField } = DATA_SCOPE_FIELDS[resource];
  return castScopeObjectIds(buildDataScopeFilter(dataScope, ownerField, departmentField));
};

// ── 导出配置 ─────────────────────────────────────────────────────────────────

const EXPORT_SHEET_NAMES = {
  alarms: '报警记录',
  devices: '设备列表',
  inspections: '巡检记录',
  audit: '审计日志',
};

// 模型 + 排序 + populate + 字段裁剪配置（选择投影在查询阶段生效）
const EXPORT_MODEL_CONFIG = {
  alarms: {
    model: FireAlarm,
    sort: { occurredAt: -1 },
    populate: [
      { path: 'handler', select: 'username realName' },
      { path: 'deviceId', select: 'deviceCode deviceName' },
    ],
  },
  devices: { model: FireDevice, sort: { deviceCode: 1 }, populate: [] },
  audit: {
    model: AuditLog,
    sort: { timestamp: -1 },
    populate: [],
    // 直接取模型上的那份排除清单：xlsx 导出此前自带一份 '-body -params -query'，
    // 少了 -hmac ⇒ 全仓唯一一条把审计 HMAC 读进进程的路径（RESPONSE_EXCLUDE 存在的
    // 目的就是阻断 (记录, hmac) 明文—标签对，见 tests/compliance/auditChain.test.js）。
    // 输出侧本来就不打印 hmac，所以这不是"已经泄露"，而是"排除清单各写一份、
    // 控制点随时会漂"——写坏一次就变成真外泄。
    select: AuditLog.RESPONSE_EXCLUDE,
  },
  inspections: {
    model: Inspection,
    sort: { planStartTime: -1 },
    populate: [{ path: 'assignedTo', select: 'username realName' }],
  },
};

// 状态映射
const statusMap = {
  pending: '待处理',
  processing: '处理中',
  resolved: '已处理',
  false_alarm: '误报',
  cancelled: '已取消',
};

const alarmTypeMap = {
  smoke: '烟雾报警',
  temp_abnormal: '温度异常',
  manual_button: '手动报警',
  phone_report: '电话报告',
  patrol_find: '巡检发现',
  other: '其他',
};

const deviceStatusMap = {
  normal: '正常',
  offline: '离线',
  fault: '故障',
  maintenance: '维护中',
};

const EXPORT_COLUMN_DEFS = {
  alarms: [
    { header: '报警编号', key: 'alarmCode', width: 15 },
    { header: '报警时间', key: 'occurredAt', width: 18 },
    { header: '报警类型', key: 'alarmType', width: 12 },
    { header: '报警位置', key: 'location', width: 20 },
    { header: '描述', key: 'description', width: 30 },
    { header: '状态', key: 'status', width: 10 },
    { header: '上报人', key: 'reporter', width: 12 },
    { header: '处理人', key: 'handler', width: 12 },
    { header: '处理结果', key: 'handleResult', width: 25 },
  ],
  devices: [
    { header: '设备编码', key: 'deviceCode', width: 15 },
    { header: '设备名称', key: 'deviceName', width: 20 },
    { header: '设备类型', key: 'deviceType', width: 15 },
    { header: '状态', key: 'status', width: 10 },
    { header: '安装位置', key: 'location', width: 25 },
    { header: '下次检查', key: 'nextCheckDate', width: 12 },
    { header: '过期时间', key: 'expiryDate', width: 12 },
  ],
  audit: [
    { header: '操作时间', key: 'timestamp', width: 20 },
    { header: '日志等级', key: 'level', width: 10 },
    { header: '操作用户', key: 'username', width: 15 },
    { header: '操作类型', key: 'action', width: 20 },
    { header: '分类', key: 'category', width: 12 },
    { header: '请求方式', key: 'method', width: 10 },
    { header: '请求路径', key: 'path', width: 30 },
    { header: 'IP 地址', key: 'ip', width: 16 },
    { header: '风险等级', key: 'riskLevel', width: 12 },
    { header: '操作结果', key: 'success', width: 12 },
    { header: '执行时长', key: 'duration', width: 12 },
  ],
  inspections: [
    { header: '巡检标题', key: 'title', width: 25 },
    { header: '巡检类型', key: 'inspectionType', width: 12 },
    { header: '状态', key: 'status', width: 10 },
    { header: '结果', key: 'result', width: 10 },
    { header: '计划开始', key: 'planStartTime', width: 18 },
    { header: '计划结束', key: 'planEndTime', width: 18 },
    { header: '实际开始', key: 'actualStartTime', width: 18 },
    { header: '实际结束', key: 'actualEndTime', width: 18 },
    { header: '执行人', key: 'assignedTo', width: 15 },
    { header: '备注', key: 'remark', width: 30 },
  ],
};

// 审计 action 展示名（导出用；与审计页 labelMaps 相互独立，口径同义）
const EXPORT_ACTION_LABELS = {
  login_success: '登录成功',
  login_failed: '登录失败',
  logout: '退出登录',
  user_create: '创建用户',
  user_update: '更新用户',
  user_delete: '删除用户',
  role_create: '创建角色',
  role_update: '更新角色',
  role_delete: '删除角色',
  device_create: '创建设备',
  device_update: '更新设备',
  alarm_dispatch: '指派报警',
  alarm_resolve: '处理报警',
  password_changed: '修改密码',
  suspicious_report: '安全举报',
};

const EXPORT_RISK_LEVEL_LABELS = { critical: '严重', high: '高', medium: '中', low: '低' };

const formatExportLocation = (loc) => {
  if (!loc) return '-';
  const { building, floor, room } = loc;
  return building || floor || room ? `${building || ''}${floor || ''}${room || ''}` : '-';
};

/**
 * 审计文档 → 展示档位，是 `utils/auditQuery.buildLevelCondition` 的反向镜像。
 *
 * 必须与查询侧同一集合互斥划分，而查询侧写的是 Mongo **等值** `{success: true|false}`：
 * 等值匹配筛不出"字段缺位"的文档（`AuditLog.success` 无 default，多处直写点不带该字段）。
 * 所以这里也不能替缺位派生一个档位——旧写法 `!item.success ? '错误' : ...` 让
 * 一次成功的非常规时间登录在导出里成了"错误"，而列表侧 `?level=error` 根本筛不出它。
 * 高危档是独立触发的一支（对应 `$or` 的第二条件），与 success 是否缺位无关，保持无条件命中。
 */
const auditExportLevel = (item) => {
  if (item.success === false || AUDIT_ERROR_RISK_LEVELS.includes(item.riskLevel)) return '错误';
  if (item.success !== true) return '-';
  return item.riskLevel === 'medium' ? '警告' : '信息';
};

const EXPORT_ROW_TRANSFORMS = {
  alarms: (item) => ({
    alarmCode: item.alarmCode || '-',
    occurredAt: formatDateTime(item.occurredAt),
    alarmType: alarmTypeMap[item.alarmType] || item.alarmType || '-',
    location: formatExportLocation(item.location),
    description: item.description || '-',
    status: statusMap[item.status] || item.status || '-',
    reporter: (item.reporter && (item.reporter.name || item.reporter.username)) || '-',
    handler: (item.handler && (item.handler.realName || item.handler.username)) || '-',
    handleResult: item.handleResult || '-',
  }),
  devices: (item) => ({
    deviceCode: item.deviceCode || '-',
    deviceName: item.deviceName || '-',
    deviceType: item.deviceType || '-',
    status: deviceStatusMap[item.status] || item.status || '-',
    location: formatExportLocation(item.location),
    nextCheckDate: formatDate(item.nextCheckDate),
    expiryDate: formatDate(item.expiryDate),
  }),
  audit: (item) => ({
    // 日志等级派生口径与 /security/audit-logs 一致。这一处是 buildLevelCondition 的
    // **反向**（那边 level → 查询条件，这边 文档 → 展示档），高危档必须用同一个派生集合
    // （F-149）：给有序等级表加一档时，三档划分由 riskLevelSingleSource 的
    // 划分完整性断言兜住，而这里的 doc→label 镜像它看不见，改等级表时要一并核。
    // 镜像的**另一头**（success 缺位时不得派生档位）由 zzqB_exportAuditLabelsTriState
    // 的逐档对拍兜住，两边都要动时才闭合。
    timestamp: formatDateTime(item.timestamp),
    level: auditExportLevel(item),
    username: item.username || '-',
    action: EXPORT_ACTION_LABELS[item.action] || item.action || '-',
    category: item.category || '-',
    method: item.method || '-',
    path: item.path || '-',
    ip: item.ip || '-',
    riskLevel: EXPORT_RISK_LEVEL_LABELS[item.riskLevel] || item.riskLevel || '-',
    // 三态而不是二态：`AuditLog.success` 无 default、非 required，多处直写点根本不带
    // 该字段（login_unusual_time / suspicious_report / securityAlert 的三处告警审计）。
    // `? '成功' : '失败'` 把"未记录"渲染成"这次操作失败了"——一条肯定性结论。
    success: item.success === true ? '成功' : item.success === false ? '失败' : '-',
    // `duration` 用 `== null` 而不是真值判断：0 是合法值（同一毫秒内返回，缓存命中时是常态），
    // 写成 `item.duration ? ...` 会把"亚毫秒完成"与"从未记录"塌成同一个 `-`，
    // 而同一条记录的 CSV 导出走原样 csvEscape 给 `0` —— 两份合规材料自相矛盾。
    duration: item.duration == null ? '-' : `${item.duration}ms`,
  }),
  inspections: (item) => ({
    title: item.title || '-',
    inspectionType: item.inspectionType || '-',
    status: item.status || '-',
    result: item.result || '-',
    planStartTime: formatDateTime(item.planStartTime),
    planEndTime: formatDateTime(item.planEndTime),
    actualStartTime: formatDateTime(item.actualStartTime),
    actualEndTime: formatDateTime(item.actualEndTime),
    assignedTo:
      item.assignedTo && item.assignedTo.length > 0
        ? item.assignedTo
            .map((u) => (u && (u.realName || u.username)) || '')
            .filter(Boolean)
            .join(', ')
        : '-',
    remark: item.remark || '-',
  }),
};

/** 电子表格公式注入防护包装：对所有单元格文本做危险前缀加固（= + - @ Tab CR） */
const createSafeTransform = (transform) => (item) => {
  const row = transform(item);
  for (const key of Object.keys(row)) {
    row[key] = sanitizeSpreadsheetCell(row[key]);
  }
  return row;
};

/**
 * 审计导出的查询条件：与 /security/audit-logs 查询侧**逐字段同口径**（导出即所见）。
 * 非法值一律抛错（调用方 catch 后转 400），不静默降级成"另一个更窄的结果集"——
 * 导出报表是要拿给别人看的，200 + 无提示比报错危险得多。
 */
const buildAuditExportQuery = ({
  dateFilter,
  username,
  action,
  category,
  riskLevel,
  success,
  ip,
  userId,
  level,
}) => {
  const auditQuery = {};
  if (Object.keys(dateFilter).length > 0) auditQuery.timestamp = dateFilter;
  // 使用 escapeRegExp 防止 ReDoS 正则拒绝服务攻击
  if (username) auditQuery.username = { $regex: escapeRegExp(username), $options: 'i' };
  // action/category 为枚举值,精确匹配,与审计日志查询接口语义一致
  if (action) auditQuery.action = action;
  if (category) auditQuery.category = category;
  if (riskLevel) auditQuery.riskLevel = riskLevel;
  if (success !== undefined && success !== '') {
    // 与查询侧 utils/auditQuery.js 共用同一个解析函数。原实现两处各写一遍
    // `success === 'true' || success === true`，把 '1'/'0'/'yes'/'TRUE'/对象/数组
    // 一律静默折成 false；此前两份是刻意选择（该文件当时在并行会话手里），
    // 现在由单一实现负责一致，`src/tests/auditFilterParity.test.js`
    // 的真值表继续作为第二道保险。
    auditQuery.success = parseSuccessFilter(success);
  }
  // P3-13：补齐 ip/userId 维度，与 /security/audit-logs 查询口径一致。
  // 变体集合改由 ipUtils.ipQueryCondition 统一推导（规范 + 原始 + IPv4 的
  // ::ffff: 映射形态），两侧共用一份实现——各写一份正是查询/导出漂移的来源。
  if (ip) {
    const normalizedIPValue = normalizeIP(ip);
    if (!normalizedIPValue) throw new Error('参数 ip 必须是合法的 IPv4/IPv6 地址');
    auditQuery.ip = ipQueryCondition(ip);
  }
  if (userId) {
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new Error('参数 userId 必须是合法的用户 ID');
    }
    auditQuery.userId = userId;
  }
  // 日志等级派生筛选,与 /security/audit-logs 接口口径保持一致(导出即所见)
  // 用 $and 叠加而非直接覆盖字段,避免丢弃用户已选的 success/riskLevel 筛选
  if (level && AUDIT_DISPLAY_LEVELS.includes(level)) {
    auditQuery.$and = [...(auditQuery.$and || []), buildLevelCondition(level)];
  }
  return auditQuery;
};

/**
 * 按导出类型构建查询条件（原 exportReport 内联 buildQuery 的模块级提取）
 * @returns {Object|null} 查询条件；不支持的 type 返回 null
 */
const buildExportQuery = (type, ctx) => {
  const { dataScope, dateFilter } = ctx;
  const withDate = (scopeFilter, field) =>
    Object.keys(dateFilter).length > 0 ? { ...scopeFilter, [field]: dateFilter } : scopeFilter;

  switch (type) {
    case 'alarms':
      return withDate(scopeFilterFor('alarm', dataScope), 'occurredAt');
    case 'devices':
      // 修复：devices 导出分支此前忽略了 dateFilter，导致用户传入 startDate/endDate 后
      // 导出结果不受日期过滤（与 alarms/inspections 分支口径不一致）
      return withDate(scopeFilterFor('device', dataScope), 'installDate');
    case 'inspections':
      // 修复：补全巡检导出查询，应用数据范围和日期过滤
      return withDate(scopeFilterFor('inspection', dataScope), 'planStartTime');
    case 'audit':
      return buildAuditExportQuery(ctx);
    default:
      return null;
  }
};

/**
 * audit 分支枚举白名单校验：与 /security/audit-logs 查询接口同一份枚举清单，
 * 防止拼错的 action/category/riskLevel/level 被静默忽略而放大导出范围。
 * P3-13：level 此前缺失校验——非法值不命中派生分支被静默忽略，
 * 用户选「仅错误」却导出全量，且无任何提示
 * @throws {Error} 非法枚举值（消息可直接回给调用方）
 */
const validateAuditExportEnums = ({ action, category, riskLevel, level }) => {
  validateEnum(action, AUDIT_LOG_ACTIONS, 'action');
  validateEnum(category, AUDIT_CATEGORIES, 'category');
  validateEnum(riskLevel, AUDIT_RISK_LEVELS, 'riskLevel');
  validateEnum(level, AUDIT_DISPLAY_LEVELS, 'level');
};

module.exports = {
  EXPORT_LIMIT,
  EXPORT_SHEET_NAMES,
  EXPORT_MODEL_CONFIG,
  EXPORT_COLUMN_DEFS,
  EXPORT_ROW_TRANSFORMS,
  createSafeTransform,
  scopeFilterFor,
  buildExportQuery,
  validateAuditExportEnums,
};
