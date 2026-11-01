/**
 * 文件/导出类端点的注册表与合成导出行（P1c）
 *
 * 与判定文件分家的理由只有一条：体积（导出行是纯数据，塞在一起会顶过 max-lines 300 的棘轮）。
 * 这里只放声明；判定与发送在 services/honeypotDecoyFiles.js。
 * 合成行的时间一律写相对量 `xxxOffsetMin`（正数 = 若干分钟之前），运行期由 materializeRow 物化——
 * 静态日期会随部署变旧，一眼可辨是假数据。形状 = EXPORT_ROW_TRANSFORMS 的输入。
 * **行序 = 真实导出的排序键**：alarms 按 occurredAt 降序、devices 按 deviceCode 升序、
 * inspections 按 planStartTime 降序（reportExportService 的 EXPORT_MODEL_CONFIG）。
 * 日期过滤字段（真实链 buildExportQuery 的 withDate 一侧）单列在下方 DECOY_EXPORT_DATE_FIELDS。
 */

const { frozenRows } = require('./honeypotDecoyData');

/** 文件类端点：prefix 为真时按前缀匹配（头像路径里带目标用户 id），否则全等 */
const FILE_ENDPOINTS = Object.freeze([
  Object.freeze({
    id: 'reports-export',
    path: '/api/reports/export',
    methods: Object.freeze(['GET', 'HEAD']),
  }),
  Object.freeze({
    id: 'reports-export-pii',
    path: '/api/reports/export/pii',
    methods: Object.freeze(['POST']),
  }),
  Object.freeze({
    id: 'audit-logs-export',
    path: '/api/security/audit-logs/export',
    methods: Object.freeze(['GET', 'HEAD']),
  }),
  Object.freeze({
    id: 'avatars',
    path: '/api/avatars',
    prefix: true, // 前缀语义 = 全等或后跟一个 '/'：覆盖 '/api/avatars/<id>' 的两种尾斜杠拼写
    methods: Object.freeze(['GET', 'HEAD']),
  }),
]);

const DECOY_EXPORT_ITEMS = Object.freeze({
  alarms: frozenRows([
    {
      alarmCode: 'AL-2026-0731',
      occurredAtOffsetMin: 118,
      alarmType: 'smoke',
      location: { building: 'A1 厂房', floor: '2 层', room: '东侧' },
      description: '感烟探测器触发报警',
      status: 'resolved',
      reporter: { name: '张伟' }, // 上报人列不掩码：EXPORT_ROW_TRANSFORMS 的既有口径（残留，见 ADR-013）
      handler: { realName: '李强' },
      handleResult: '现场确认误报，已复位',
    },
    {
      alarmCode: 'AL-2026-0730',
      occurredAtOffsetMin: 262,
      alarmType: 'smoke',
      location: { building: 'A1 厂房', floor: '3 层', room: '西侧' },
      description: '感烟探测器持续报警',
      status: 'processing',
      reporter: { name: '李强' },
      handler: { realName: '王芳' },
      handleResult: '已派单，待现场复核',
    },
    {
      alarmCode: 'AL-2026-0729',
      occurredAtOffsetMin: 545,
      alarmType: 'temp_abnormal',
      location: { building: 'B2 罐区', floor: '1 层', room: '南侧' },
      description: '感温探测器温度超限',
      status: 'resolved',
      reporter: { name: '王芳' },
      handler: { realName: '陈磊' },
      handleResult: '温度回落，已复位',
    },
    {
      alarmCode: 'AL-2026-0728',
      occurredAtOffsetMin: 1490,
      alarmType: 'manual_button',
      location: { building: 'B2 罐区', floor: '1 层', room: '东侧' },
      description: '手动报警按钮被按下',
      status: 'false_alarm',
      reporter: { name: '赵敏' },
      handler: { realName: '孙浩' },
      handleResult: '确认为清洁作业误触',
    },
  ]),
  devices: frozenRows([
    {
      deviceCode: 'HD-B2-006',
      deviceName: '点型感温探测器',
      deviceType: 'heat_detector',
      status: 'normal',
      location: { building: 'B2 罐区', floor: '1 层', room: '南侧' },
      installDateOffsetMin: 60 * 24 * 520,
      nextCheckDateOffsetMin: -60 * 24 * 30,
      expiryDateOffsetMin: -60 * 24 * 240,
    },
    {
      deviceCode: 'HY-A2-031',
      deviceName: '室内消火栓',
      deviceType: 'hydrant',
      status: 'normal',
      location: { building: 'A2 仓库', floor: '1 层', room: '北侧' },
      installDateOffsetMin: 60 * 24 * 450,
      nextCheckDateOffsetMin: -60 * 24 * 20,
      expiryDateOffsetMin: -60 * 24 * 365,
    },
    {
      deviceCode: 'MB-B2-011',
      deviceName: '手动报警按钮',
      deviceType: 'other', // 报警按钮不在 deviceTypeMap 里：用 other 走「其他」，绝不落裸英文键
      status: 'normal',
      location: { building: 'B2 罐区', floor: '1 层', room: '东侧' },
      installDateOffsetMin: 60 * 24 * 240,
      nextCheckDateOffsetMin: -60 * 24 * 12,
      expiryDateOffsetMin: -60 * 24 * 150,
    },
    {
      deviceCode: 'SD-A1-014',
      deviceName: '点型感烟探测器',
      deviceType: 'smoke_detector',
      status: 'normal',
      location: { building: 'A1 厂房', floor: '2 层', room: '东侧' },
      installDateOffsetMin: 60 * 24 * 380,
      nextCheckDateOffsetMin: -60 * 24 * 26, // 负偏移 = 未来：下次检查/到期是"还没到"的日期
      expiryDateOffsetMin: -60 * 24 * 180,
    },
    {
      deviceCode: 'SD-A1-027',
      deviceName: '点型感烟探测器',
      deviceType: 'smoke_detector',
      status: 'fault',
      location: { building: 'A1 厂房', floor: '3 层', room: '西侧' },
      installDateOffsetMin: 60 * 24 * 300,
      nextCheckDateOffsetMin: -60 * 24 * 1,
      expiryDateOffsetMin: -60 * 24 * 75,
    },
    {
      deviceCode: 'SP-B1-002',
      deviceName: '消防喷淋泵',
      deviceType: 'sprinkler',
      status: 'normal',
      location: { building: 'B1 泵房', floor: '1 层', room: '设备间' },
      installDateOffsetMin: 60 * 24 * 610,
      nextCheckDateOffsetMin: -60 * 24 * 45,
      expiryDateOffsetMin: -60 * 24 * 300,
    },
  ]),
  inspections: frozenRows([
    {
      title: 'B2 罐区每日巡检',
      inspectionType: 'daily',
      status: 'in_progress',
      planStartTimeOffsetMin: 60 * 3,
      planEndTimeOffsetMin: -60 * 3,
      actualStartTimeOffsetMin: 60 * 2,
      assignedTo: [{ realName: '赵敏' }],
      remark: '进行中',
    },
    {
      title: 'A1 厂房月度消防巡检',
      inspectionType: 'monthly',
      status: 'completed',
      result: 'normal',
      planStartTimeOffsetMin: 60 * 21,
      planEndTimeOffsetMin: 60 * 19,
      actualStartTimeOffsetMin: 60 * 20.5,
      actualEndTimeOffsetMin: 60 * 19.2,
      assignedTo: [{ realName: '陈磊' }],
      remark: '全部检查项合格',
    },
    {
      title: 'B1 泵房周巡检',
      inspectionType: 'weekly',
      status: 'completed',
      result: 'normal',
      planStartTimeOffsetMin: 60 * 44,
      planEndTimeOffsetMin: 60 * 42,
      actualStartTimeOffsetMin: 60 * 43.5,
      actualEndTimeOffsetMin: 60 * 42.2,
      assignedTo: [{ realName: '孙浩' }],
      remark: '喷淋泵压力正常',
    },
  ]),
});

/** 真实链的日期过滤字段（buildExportQuery 的 withDate 一侧）：日期参数作用在合成行的哪个字段上 */
const DECOY_EXPORT_DATE_FIELDS = Object.freeze({
  alarms: 'occurredAt',
  devices: 'installDate', // 设备按安装日期过滤：该字段不在导出的列里，只作过滤键
  inspections: 'planStartTime',
});

module.exports = { DECOY_EXPORT_DATE_FIELDS, DECOY_EXPORT_ITEMS, FILE_ENDPOINTS };
