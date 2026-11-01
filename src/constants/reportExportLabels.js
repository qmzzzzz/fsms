/**
 * 报表导出的**展示名映射**（纯声明，无逻辑）
 *
 * 为什么单独成文件：`src/services/reportExportService.js` 触到 `max-lines` 体积棘轮预算（300 行代码，eslint.config.js 的 skipBlankLines + skipComments 都开着，只有代码行算数）。这几个映射是纯数据、无任何依赖、也不被本模块之外引用，属于"声明"而非"逻辑"——按本仓既有分工（constants/ 放声明、services/ 放逻辑）搬出来，同时把预算还给真正承载业务判断的那份文件。
 *
 * ⚠ `EXPORT_ACTION_LABELS` 与审计页的 labelMaps **是两份**，口径同义但相互独立（原注释即如此）。搬动没有改变这一点：要做单一事实来源得先让两侧的取值集合对齐（审计页覆盖的 action 集合与导出页并不相同），那是一次独立的口径评审，不在本次改动内。
 */

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

// 审计 action 展示名（导出用；与审计页 labelMaps 相互独立，口径同义）
const EXPORT_ACTION_LABELS = {
  login_success: '登录成功',
  login_failed: '登录失败',
  login_captcha_rejected: '登录人机校验未通过',
  logout: '退出登录',
  user_create: '创建用户',
  user_update: '更新用户',
  user_delete: '删除用户',
  user_anonymized: '注销并匿名化用户',
  admin_reset_password: '管理员重置口令',
  role_create: '创建角色',
  role_update: '更新角色',
  role_delete: '删除角色',
  device_create: '创建设备',
  device_update: '更新设备',
  alarm_dispatch: '指派报警',
  alarm_resolve: '处理报警',
  password_changed: '修改密码',
  password_force_changed: '首次登录强制改密',
  suspicious_report: '安全举报',
};

const EXPORT_RISK_LEVEL_LABELS = { critical: '严重', high: '高', medium: '中', low: '低' };

// ── 英文导出词表（2026-10-30）──────────────────────────────────────────────── xlsx 是交付给外部审计/管理层的文件，语言必须跟随操作界面（?lang=en）。中文侧仍以 PRODUCTION 的既有映射为准；这里只补英文，避免改变默认导出。
const LABELS_EN = {
  statusMap: {
    pending: 'Pending',
    processing: 'Processing',
    resolved: 'Resolved',
    false_alarm: 'False alarm',
    cancelled: 'Cancelled',
  },
  alarmTypeMap: {
    smoke: 'Smoke alarm',
    temp_abnormal: 'Temperature abnormal',
    manual_button: 'Manual alarm',
    phone_report: 'Phone report',
    patrol_find: 'Patrol finding',
    other: 'Other',
  },
  deviceStatusMap: {
    normal: 'Normal',
    offline: 'Offline',
    fault: 'Fault',
    maintenance: 'Maintenance',
  },
  EXPORT_ACTION_LABELS: {
    login_success: 'Login succeeded',
    login_failed: 'Login failed',
    login_captcha_rejected: 'Login human verification failed',
    logout: 'Logout',
    user_create: 'Create user',
    user_update: 'Update user',
    user_delete: 'Delete user',
    user_anonymized: 'Deactivate and anonymize user',
    admin_reset_password: 'Admin reset password',
    role_create: 'Create role',
    role_update: 'Update role',
    role_delete: 'Delete role',
    device_create: 'Create device',
    device_update: 'Update device',
    alarm_dispatch: 'Dispatch alarm',
    alarm_resolve: 'Resolve alarm',
    password_changed: 'Change password',
    password_force_changed: 'Forced password change at first login',
    suspicious_report: 'Security report',
  },
  EXPORT_RISK_LEVEL_LABELS: {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
  },
  deviceTypeMap: {
    fire_alarm: 'Fire alarm',
    sprinkler: 'Sprinkler system',
    hydrant: 'Fire hydrant',
    extinguisher: 'Extinguisher',
    smoke_detector: 'Smoke detector',
    heat_detector: 'Heat detector',
    emergency_light: 'Emergency light',
    evacuation_sign: 'Evacuation sign',
    fire_door: 'Fire door',
    other: 'Other',
  },
  inspectionTypeMap: {
    daily: 'Daily',
    weekly: 'Weekly',
    monthly: 'Monthly',
    quarterly: 'Quarterly',
    annual: 'Annual',
    special: 'Special',
  },
  inspectionStatusMap: {
    pending: 'Pending',
    in_progress: 'In progress',
    completed: 'Completed',
    overdue: 'Overdue',
    cancelled: 'Cancelled',
  },
  inspectionResultMap: {
    normal: 'Normal',
    abnormal: 'Abnormal',
    partial: 'Partially abnormal',
  },
  auditLevelMap: { error: 'Error', warning: 'Warning', info: 'Info' },
};

const EXPORT_SHEET_NAMES_EN = {
  alarms: 'Alarm Records',
  devices: 'Device List',
  inspections: 'Inspection Records',
  audit: 'Audit Logs',
};

// 英文表头与 EXPORT_COLUMN_DEFS 逐列同序；只替换 header，key/width 不动。
const EXPORT_COLUMN_HEADERS_EN = {
  alarms: [
    'Alarm Code',
    'Alarm Time',
    'Alarm Type',
    'Alarm Location',
    'Description',
    'Status',
    'Reporter',
    'Handler',
    'Handling Result',
  ],
  devices: [
    'Device Code',
    'Device Name',
    'Device Type',
    'Status',
    'Installation Location',
    'Next Inspection',
    'Expiry Date',
  ],
  audit: [
    'Time',
    'Log Level',
    'User',
    'Action',
    'Category',
    'Method',
    'Path',
    'IP Address',
    'Risk Level',
    'Result',
    'Duration',
  ],
  inspections: [
    'Inspection Title',
    'Inspection Type',
    'Status',
    'Result',
    'Planned Start',
    'Planned End',
    'Actual Start',
    'Actual End',
    'Assignee',
    'Remark',
  ],
};

const LABELS_ZH = {
  statusMap,
  alarmTypeMap,
  deviceStatusMap,
  EXPORT_ACTION_LABELS,
  EXPORT_RISK_LEVEL_LABELS,
  deviceTypeMap: {
    fire_alarm: '火灾报警器',
    sprinkler: '喷淋系统',
    hydrant: '消火栓',
    extinguisher: '灭火器',
    smoke_detector: '烟雾探测器',
    heat_detector: '温度探测器',
    emergency_light: '应急灯',
    evacuation_sign: '疏散指示牌',
    fire_door: '防火门',
    other: '其他',
  },
  inspectionTypeMap: {
    daily: '每日',
    weekly: '每周',
    monthly: '每月',
    quarterly: '每季度',
    annual: '每年',
    special: '专项',
  },
  inspectionStatusMap: {
    pending: '待执行',
    in_progress: '执行中',
    completed: '已完成',
    overdue: '已超期',
    cancelled: '已取消',
  },
  inspectionResultMap: { normal: '正常', abnormal: '异常', partial: '部分异常' },
  auditLevelMap: { error: '错误', warning: '警告', info: '信息' },
};

/** 按语言取全套导出标签；默认中文，未知语言同样回中文（行为与改造前一致）。 */
const getExportLabelMaps = (lang) =>
  String(lang || '')
    .toLowerCase()
    .startsWith('en')
    ? LABELS_EN
    : LABELS_ZH;

module.exports = {
  statusMap,
  alarmTypeMap,
  deviceStatusMap,
  EXPORT_ACTION_LABELS,
  EXPORT_RISK_LEVEL_LABELS,
  EXPORT_SHEET_NAMES_EN,
  EXPORT_COLUMN_HEADERS_EN,
  getExportLabelMaps,
};
