/**
 * 文件/导出类端点的注册表与导出面（P1c；A6 起导出行从数据面派生）
 *
 * 这里只放声明；判定与发送在 services/honeypotDecoyFiles.js。
 * **导出面不存第二份行**：DECOY_EXPORT_ITEMS 引用数据面同一批冻结行对象，只按真实导出的
 * 排序键重排（alarms/inspections 时间新→旧、devices 按 deviceCode 升序）。此前手抄第二份行，
 * 导出设备行与列表面同码不同日期——并行维护必然分叉，如今结构上不可能（单向判据见
 * honeypotDecoyLedger 的「导出面与数据面同一世界」）。相对量 `xxxOffsetMin`（正数 = 若干分钟
 * 之前）运行期由 materializeRow 物化；超出导出列的键由 createSafeTransform 忽略（列驱动）。
 */

const {
  DECOY_ALARMS,
  DECOY_DEVICES,
  DECOY_INSPECTIONS,
  frozenRows,
} = require('./honeypotDecoyData');

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

// 行对象与数据面**同一引用**（不是拷贝）：OffsetMin 越小越新 ⇒ 时间降序 = 偏移升序
const newerFirst = (field) => (a, b) => a[field] - b[field];
const byDeviceCode = (a, b) =>
  a.deviceCode < b.deviceCode ? -1 : a.deviceCode > b.deviceCode ? 1 : 0;
const DECOY_EXPORT_ITEMS = Object.freeze({
  alarms: frozenRows([...DECOY_ALARMS].sort(newerFirst('occurredAtOffsetMin'))),
  devices: frozenRows([...DECOY_DEVICES].sort(byDeviceCode)),
  inspections: frozenRows([...DECOY_INSPECTIONS].sort(newerFirst('planStartTimeOffsetMin'))),
});

/** 真实链的日期过滤字段（buildExportQuery 的 withDate 一侧）：日期参数作用在合成行的哪个字段上 */
const DECOY_EXPORT_DATE_FIELDS = Object.freeze({
  alarms: 'occurredAt',
  devices: 'installDate', // 设备按安装日期过滤：该字段不在导出的列里，只作过滤键
  inspections: 'planStartTime',
});

module.exports = { DECOY_EXPORT_DATE_FIELDS, DECOY_EXPORT_ITEMS, FILE_ENDPOINTS };
