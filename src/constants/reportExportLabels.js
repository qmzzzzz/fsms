/**
 * 报表导出的**展示名映射**（纯声明，无逻辑）
 *
 * 为什么单独成文件：`src/services/reportExportService.js` 触到 `max-lines` 体积棘轮
 * 预算（300 行代码，eslint.config.js 的 skipBlankLines + skipComments 都开着，
 * 只有代码行算数）。这几个映射是纯数据、无任何依赖、也不被本模块之外引用，
 * 属于"声明"而非"逻辑"——按本仓既有分工（constants/ 放声明、services/ 放逻辑）搬出来，
 * 同时把预算还给真正承载业务判断的那份文件。
 *
 * ⚠ `EXPORT_ACTION_LABELS` 与审计页的 labelMaps **是两份**，口径同义但相互独立
 * （原注释即如此）。搬动没有改变这一点：要做单一事实来源得先让两侧的取值集合对齐
 * （审计页覆盖的 action 集合与导出页并不相同），那是一次独立的口径评审，不在本次改动内。
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

module.exports = {
  statusMap,
  alarmTypeMap,
  deviceStatusMap,
  EXPORT_ACTION_LABELS,
  EXPORT_RISK_LEVEL_LABELS,
};
