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
const { sanitizeSpreadsheetCell, validateEnum } = require('../utils/helpers');
const { buildDataScopeFilter, isDataScopeDenied, deniedDataScope } = require('../middleware/rbac');
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
const {
  parseSuccessFilter,
  buildLevelCondition,
  usernamePrefixCondition,
  hasUsernamePrefixCondition,
} = require('../utils/auditQuery');
const { formatDateTime, formatDate } = require('../utils/dateFormat');
const { castScopeObjectIds } = require('../utils/scopeCast');
// A4（2026-10-16）：导出侧真实姓名脱敏。掩码实现复用 utils/encryption 的 DataMasking
// （userService / securityController 已在用它的 maskPhone/maskEmail），不另造一份。
const { DataMasking } = require('../utils/encryption');
const logger = require('../utils/logger');

const EXPORT_LIMIT = 5000;

/**
 * 审计导出的 collation 口径：返回一份可直接摊给「计数腿 + 取数腿」的 options 对象。
 *
 * 为什么判据取自组装好的 query 而不是请求参数：见 utils/auditQuery 的
 * hasUsernamePrefixCondition。为什么不挂到控制器里：分层棘轮（D-1a）禁止 controller
 * 直连 models，而这份口径需要 `AuditLog.AUDIT_USERNAME_COLLATION`——数据访问口径
 * 归 service 层。为什么返回对象而不是布尔/枚举值：调用点一个分支都不新增
 * （棘轮只许降不许升），且两条腿拿到的是**同一个**对象，不可能一侧挂一侧不挂。
 */
const collationOptionsForExport = (query) =>
  hasUsernamePrefixCondition(query) ? { collation: AuditLog.AUDIT_USERNAME_COLLATION } : {};

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
  // #12：导出与列表同一把尺——范围不可用即 403，不回一份"看起来完整"的空文件
  if (isDataScopeDenied(dataScope)) throw deniedDataScope();
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
//
// 排序必须是**全序**，且与对应列表接口同序——这是仓库既有不变式，不是新约定：
// FireAlarm.js:242 / Inspection.js:179 / AuditLog.js:309 三处都写明"排序键取值可重复
// ⇒ 必须有同向 `_id` 次级键"，并为此建了 `{key:-1,_id:-1}` 索引；列表侧
// AlarmService.js:118、InspectionService.js:146、auditQueryService.js:154 用的就是它。
// 导出原先只写 `{occurredAt:-1}` / `{planStartTime:-1}` / `{timestamp:-1}`，于是：
//   1. 同一毫秒内的并列行由查询计划决定先后 ⇒ 撞上限时"前 5000 行"取到哪一批
//      不确定，同一条筛选重跑两次可以给出两份不同的合规材料；
//   2. 与列表的次级键**方向相反**（列表 `_id:-1`，取 id 探针腿补的是 `_id:1`）
//      ⇒ 并列段里列表第 5000 行与导出第 5000 行不是同一条，"导出即所见"破在边界上；
//   3. `{occurredAt:-1,_id:1}` 这种混合方向排序用不上那条复合索引，退化成
//      5001 条的阻塞式内存排序。
// deviceCode 例外：模型上 `unique:true`（FireDevice.js:22），取值不可能重复，
// 故不需要次级键——同一判断见 DeviceService.js:84、cursorPagination.js:45。
const EXPORT_MODEL_CONFIG = {
  alarms: {
    model: FireAlarm,
    sort: { occurredAt: -1, _id: -1 },
    populate: [
      { path: 'handler', select: 'username realName' },
      { path: 'deviceId', select: 'deviceCode deviceName' },
    ],
  },
  devices: { model: FireDevice, sort: { deviceCode: 1 }, populate: [] },
  audit: {
    model: AuditLog,
    sort: { timestamp: -1, _id: -1 },
    populate: [],
    // 直接取模型上的那份排除清单：排除清单只能有一份。xlsx 原先自己写
    // '-body -params -query'（少了 -hmac ⇒ 把审计 HMAC 读进进程），而 CSV 导出腿
    // 连清单都没有（全字段取回，hmac/body/params/query 一起进内存）——
    // 两条腿各写一遍就是"控制点随时会漂"。现在两条腿都引用 RESPONSE_EXCLUDE，
    // 写坏一次会同时让两边的用例变红。RESPONSE_EXCLUDE 不含 -hash/-prevHash，
    // 所以 CSV 的链摘要（auditExportService.js:148-151 读 doc.hash）不受影响。
    select: AuditLog.RESPONSE_EXCLUDE,
  },
  inspections: {
    model: Inspection,
    sort: { planStartTime: -1, _id: -1 },
    populate: [{ path: 'assignedTo', select: 'username realName' }],
  },
};

/**
 * 导出侧**携带真实姓名**的报表类型（A4，2026-10-16）。
 *
 * alarms 的 handler.realName、inspections 的 assignedTo[].realName 是 populate
 * 出来的真实姓名；devices 无人员字段，audit 只有 username（账号标识，非姓名）。
 * 判据落在这里而不是控制器：控制器与 workbook 两条腿都要用同一个集合，
 * 两处各写一份 `type === 'alarms' || type === 'inspections'` 就是本仓反复出现的
 * "同一条判据的第二处实现漏抄"。
 */
const PII_NAME_EXPORT_TYPES = Object.freeze(['alarms', 'inspections']);

/**
 * 人员列在导出文件里的取值口径（A4，2026-10-16）。
 *
 * 需求对应：数据保护 → 全生命周期（**共享段**）+ 数据脱敏。报表导出是典型的
 * 「数据离开受控边界」场景（文件会被转发、落到个人电脑），而脱敏与否必须由
 * **角色**决定：默认掩码，持 `system:read` 者才拿全文（与 User PII 的
 * `system:read` 口径一致，见 initData.js 的角色注释）。
 *
 * 只掩 `realName`，**不动 username**：username 是账号标识不是姓名，掩掉它会让
 * 导出件失去可追溯性（合规材料要能对到人）。realName 为空时退回 username 的原行为
 * 保持不变。
 *
 * ⚠ 已知残留（**有意不掩**，见交付报告的待确认项）：alarms 的 `reporter.name` 是
 * 一个**混合字段**——AlarmService.reportAlarm 写的是 `reporterName || username || '匿名用户'`，
 * 即"上报人自填姓名 / 提交者用户名 / 占位符"三者在同一列里无法区分。掩它会连
 * 用户名与"匿名用户"一起掩掉，反而降低导出件的可用性；要掩它必须先让业务确认
 * 该字段的取值口径（是否强制自填姓名）。故本轮**不掩**，并如实登记。
 *
 * @param {{realName?: string, username?: string}|null} user populate 出来的人员对象
 * @param {boolean} maskPii true = 掩码
 * @returns {string} 展示值；无人员对象时为 EXPORT_NO_VALUE
 */
const exportPersonLabel = (user, maskPii) => {
  if (!user) return EXPORT_NO_VALUE;
  const realName = user.realName;
  if (!realName) return user.username || EXPORT_NO_VALUE;
  return maskPii ? DataMasking.maskName(realName) : realName;
};

// 状态 / 类型 / 风险等级 / action 的展示名映射已搬到 constants/reportExportLabels.js
// （纯声明与逻辑分离 + 本文件的 max-lines 体积棘轮预算，理由见该文件头）。
const {
  statusMap,
  alarmTypeMap,
  deviceStatusMap,
  EXPORT_ACTION_LABELS,
  EXPORT_RISK_LEVEL_LABELS,
} = require('../constants/reportExportLabels');

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

/**
 * 空值占位符。`utils/dateFormat` 的 formatDateTime/formatDate 用同一个字面量（无值时
 * 返回 '-'），所以这一格的口径横跨两个文件；createSafeTransform 的放行判据与这里
 * 必须是同一个常量，否则占位符会被公式注入加固写成 `'-`。
 */
const EXPORT_NO_VALUE = '-';

const formatExportLocation = (loc) => {
  if (!loc) return EXPORT_NO_VALUE;
  const { building, floor, room } = loc;
  return building || floor || room
    ? `${building || ''}${floor || ''}${room || ''}`
    : EXPORT_NO_VALUE;
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
  if (item.success !== true) return EXPORT_NO_VALUE;
  return item.riskLevel === 'medium' ? '警告' : '信息';
};

const EXPORT_ROW_TRANSFORMS = {
  alarms: (item, { maskPii = false } = {}) => ({
    alarmCode: item.alarmCode || EXPORT_NO_VALUE,
    occurredAt: formatDateTime(item.occurredAt),
    alarmType: alarmTypeMap[item.alarmType] || item.alarmType || EXPORT_NO_VALUE,
    location: formatExportLocation(item.location),
    description: item.description || EXPORT_NO_VALUE,
    status: statusMap[item.status] || item.status || EXPORT_NO_VALUE,
    reporter: (item.reporter && (item.reporter.name || item.reporter.username)) || EXPORT_NO_VALUE,
    handler: exportPersonLabel(item.handler, maskPii),
    handleResult: item.handleResult || EXPORT_NO_VALUE,
  }),
  devices: (item) => ({
    deviceCode: item.deviceCode || EXPORT_NO_VALUE,
    deviceName: item.deviceName || EXPORT_NO_VALUE,
    deviceType: item.deviceType || EXPORT_NO_VALUE,
    status: deviceStatusMap[item.status] || item.status || EXPORT_NO_VALUE,
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
    username: item.username || EXPORT_NO_VALUE,
    action: EXPORT_ACTION_LABELS[item.action] || item.action || EXPORT_NO_VALUE,
    category: item.category || EXPORT_NO_VALUE,
    method: item.method || EXPORT_NO_VALUE,
    path: item.path || EXPORT_NO_VALUE,
    ip: item.ip || EXPORT_NO_VALUE,
    riskLevel: EXPORT_RISK_LEVEL_LABELS[item.riskLevel] || item.riskLevel || EXPORT_NO_VALUE,
    // 三态而不是二态：`AuditLog.success` 无 default、非 required，多处直写点根本不带
    // 该字段（login_unusual_time / suspicious_report / securityAlert 的三处告警审计）。
    // `? '成功' : '失败'` 把"未记录"渲染成"这次操作失败了"——一条肯定性结论。
    success: item.success === true ? '成功' : item.success === false ? '失败' : EXPORT_NO_VALUE,
    // `duration` 用 `== null` 而不是真值判断：0 是合法值（同一毫秒内返回，缓存命中时是常态），
    // 写成 `item.duration ? ...` 会把"亚毫秒完成"与"从未记录"塌成同一个 `-`，
    // 而同一条记录的 CSV 导出走原样 csvEscape 给 `0` —— 两份合规材料自相矛盾。
    duration: item.duration == null ? EXPORT_NO_VALUE : `${item.duration}ms`,
  }),
  inspections: (item, { maskPii = false } = {}) => ({
    title: item.title || EXPORT_NO_VALUE,
    inspectionType: item.inspectionType || EXPORT_NO_VALUE,
    status: item.status || EXPORT_NO_VALUE,
    result: item.result || EXPORT_NO_VALUE,
    planStartTime: formatDateTime(item.planStartTime),
    planEndTime: formatDateTime(item.planEndTime),
    actualStartTime: formatDateTime(item.actualStartTime),
    actualEndTime: formatDateTime(item.actualEndTime),
    assignedTo:
      item.assignedTo && item.assignedTo.length > 0
        ? item.assignedTo
            .map((u) => exportPersonLabel(u, maskPii))
            .filter((v) => v && v !== EXPORT_NO_VALUE)
            .join(', ')
        : EXPORT_NO_VALUE,
    remark: item.remark || EXPORT_NO_VALUE,
  }),
};

/** 电子表格公式注入防护包装：对所有单元格文本做危险前缀加固（= + - @ Tab CR）
 *
 * A4（2026-10-16）：第二参 options 原样透传给行变换（当前只有 `{ maskPii }`）。
 * 透传而不是在变换里读全局：脱敏是**每请求**的判据（取决于导出者的角色），
 * 放在模块级状态会让同一进程里的两次导出互相污染。
 * 不传时是空对象 ⇒ 行变换的默认值（maskPii=false）生效，旧调用方行为不变。
 */
const createSafeTransform =
  (transform, options = {}) =>
  (item) => {
    const row = transform(item, options);
    for (const key of Object.keys(row)) {
      // 空值占位符是唯一被放行的 `-` 开头文本：它不是外部输入，没有注入面。
      // 放行的理由实测过——exceljs 把 `'=1+1'` 这类字符串存成 type=3（String）、
      // formula=undefined，即 xlsx 的单元格是**带类型的文本**，Excel 打开时不会求值，
      // 那个前导单引号只会原样显示出来。于是一条没有 success/duration 字段的审计记录
      // （suspicious_report、非常规时间登录等直写点）在合规文件里显示成 `'-`，
      // 而 CSV 侧同一条记录显示成空 —— 两份材料不一致，占位符还被污染成看起来像 bug 的串。
      // 真实数据一律照旧加固：单引号断的是"xlsx 另存为 CSV 再导入"那一跳
      // （CSV 无类型，`-2+3` 会被 Excel 当公式求值）。
      if (row[key] !== EXPORT_NO_VALUE) row[key] = sanitizeSpreadsheetCell(row[key]);
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
  // username 用与列表**同一条**前缀条件（utils/auditQuery.usernamePrefixCondition）。
  // 此前这里留着列表侧改造前的旧写法 `{$regex: escapeRegExp(username), $options:'i'}`，
  // 于是同一个 URL 参数在两条链上有两种语义：列表＝大小写不敏感的前缀，导出＝子串。
  // 后果不是"搜索结果略有差别"而是**证据材料比可见集宽**——筛 `adm` 的 xlsx 里会出现
  // `damin`、`superadmin` 的 IP/路径/操作，而操作员以为文件只有那一个人的记录；
  // 本文件的 docstring 与 utils/auditQuery.js:199-200 都把"导出即所见"写成硬约束。
  // 注：`i` 正则还有一层已实测的代价——keysExamined 2000（全索引扫），见 auditQuery.js:176-178。
  if (username) auditQuery.username = usernamePrefixCondition(username);
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

/**
 * 导出含**未脱敏**真实姓名时的行为留痕（A4，2026-10-16）。
 *
 * 与全局审计中间件的关系（**不是**重复留痕）：GET /api/reports/export 已被
 * `app.use('/api/', auditLog())` 记一条 `report_export`（谁、何时、什么筛选条件）。
 * 本函数补的是**另一件事**：这次导出拿到了**未掩码**的姓名全文（即绕过了默认脱敏档）。
 * 两条记录回答不同问题，故并存；这与 securityController 的 view_sensitive_data
 * 不同——那里设了 skipGlobalAudit，同一动作只留一条。
 *
 * 只在"全文导出"这条**提权路径**上写：掩码导出是默认档、已有 report_export 覆盖，
 * 再写一条只会淹没真正的提权事件。
 *
 * 动作复用既有的 `view_sensitive_data`（constants/audit.js 白名单内，语义即
 * "查看了敏感数据"），不新增 action：新增一条要同步维护审计页枚举与
 * auditActionReachability 的可达性技术文档，而这里没有任何新语义。
 *
 * 失败处理：**吞错不重抛**（与 checkBulkExport 同档，见 utils/auditWriteFailure.js 的
 * 档位表）。理由与那里一致——本函数在响应流已经写出之后被调用，重抛只会把一个
 * 已成功的下载顶成 500；且该导出动作的**主留痕**（report_export）由全局中间件负责，
 * 本条是增强记录。失败仍记 error 日志，不静默。
 *
 * @param {{userId: string, username: string, type: string, total: number,
 *          ip?: string, userAgent?: string}} ctx
 * @returns {Promise<void>}
 */
const auditUnmaskedPiiExport = async ({ userId, username, type, total, ip, userAgent }) => {
  try {
    await AuditLog.create({
      action: 'view_sensitive_data',
      category: 'report',
      userId,
      username,
      dataType: 'export_realname', // ≤20 字符（AuditLog.dataType 有 maxlength:20）
      ip,
      userAgent,
      success: true,
      riskLevel: 'medium',
      body: { type, total, masked: false },
    });
  } catch (e) {
    logger.error(`未脱敏 PII 导出的审计落库失败（导出本身已成功，不阻断）：${e.message}`);
  }
};

module.exports = {
  EXPORT_LIMIT,
  EXPORT_NO_VALUE,
  EXPORT_SHEET_NAMES,
  EXPORT_MODEL_CONFIG,
  EXPORT_COLUMN_DEFS,
  EXPORT_ROW_TRANSFORMS,
  PII_NAME_EXPORT_TYPES,
  createSafeTransform,
  scopeFilterFor,
  buildExportQuery,
  collationOptionsForExport,
  validateAuditExportEnums,
  auditUnmaskedPiiExport,
};
