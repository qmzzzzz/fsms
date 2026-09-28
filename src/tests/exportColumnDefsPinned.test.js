/**
 * 四类导出的列定义与行转换必须一一对得上（reportExportService.js）
 *
 * `writeExportWorkbook` 里两件事各写一半：
 *   `worksheet.columns = EXPORT_COLUMN_DEFS[type]`   —— 决定表头文案与**取值的 key**
 *   `worksheet.addRow(safeTransform(doc))`           —— 决定行对象实际有哪些 key
 * exceljs 按 key 查值：列定义里出现一个行对象没有的 key，那一列就整列空白地发货，
 * 而 200 + `spreadsheetml` + 合法 xlsx 全都照旧。这是一份**看起来完整的合规材料缺列**，
 * 且缺的是哪一列只有打开文件的人才发现得了。
 *
 * 既有覆盖把这件事漏在三处：
 *   ① 本文件落地前，`src/tests` 全仓 grep `EXPORT_COLUMN_DEFS` 命中数为 0（列定义无人引用）；
 *   ② `reportWorkbookService.test.js` 用的是
 *      `expect(worksheet.columns).toEqual(expect.arrayContaining([objectContaining({key:'deviceCode'})]))`
 *      ——子集匹配，删列、换序、改表头全都看不出来；
 *   ③ `reportExportInputGuards.test.js` 会解析真实 xlsx，但每类只埋**一个**种子标记，
 *      三十七列里其余各列的非空性不在断言范围内。
 *
 * 本文件钉四格，全部纯内存（不连库、不碰 exceljs）：
 *   Ⅰ 四类导出类型在列定义/模型配置/表名/行转换四张表里键集一致——
 *      少一张表就会出现 `columns = undefined`（无表头文件）或行转换缺失；
 *   Ⅱ 每类的 (表头, key) 有序清单逐项锁定——改文案/调顺序必须是**有意识**的编辑；
 *   Ⅲ 列 key 集与行转换产出的 key 集**双向**相等（多出一列 ⇒ 整列空白；少一列 ⇒ 算了不外发）；
 *   Ⅳ 空文档过一遍行转换，每一列都必须是非空字符串（`'-'` 兜底不得塌成 undefined）。
 *
 * Ⅳ 落地时当场抓到一处：`alarms.alarmCode` 是全部列里唯一不带 `|| '-'` 的直取字段
 * （同类主键 `devices.deviceCode` 有），已补齐。缺兜底时该列在文档没有编号的那一格
 * 渲染成空白单元格，而报警编号正是合规材料里最不该空白的一列——
 * 读表的人无法区分"这条没有编号"与"导出漏了"。
 */
const {
  EXPORT_MODEL_CONFIG,
  EXPORT_SHEET_NAMES,
  EXPORT_COLUMN_DEFS,
  EXPORT_ROW_TRANSFORMS,
  createSafeTransform,
} = require('../services/reportExportService');

const TYPES = ['alarms', 'devices', 'audit', 'inspections'];

/** Ⅱ 的有序清单：(表头, key) 成对写出，宽度另判 */
const COLUMN_CONTRACT = {
  alarms: [
    ['报警编号', 'alarmCode'],
    ['报警时间', 'occurredAt'],
    ['报警类型', 'alarmType'],
    ['报警位置', 'location'],
    ['描述', 'description'],
    ['状态', 'status'],
    ['上报人', 'reporter'],
    ['处理人', 'handler'],
    ['处理结果', 'handleResult'],
  ],
  devices: [
    ['设备编码', 'deviceCode'],
    ['设备名称', 'deviceName'],
    ['设备类型', 'deviceType'],
    ['状态', 'status'],
    ['安装位置', 'location'],
    ['下次检查', 'nextCheckDate'],
    ['过期时间', 'expiryDate'],
  ],
  audit: [
    ['操作时间', 'timestamp'],
    ['日志等级', 'level'],
    ['操作用户', 'username'],
    ['操作类型', 'action'],
    ['分类', 'category'],
    ['请求方式', 'method'],
    ['请求路径', 'path'],
    ['IP 地址', 'ip'],
    ['风险等级', 'riskLevel'],
    ['操作结果', 'success'],
    ['执行时长', 'duration'],
  ],
  inspections: [
    ['巡检标题', 'title'],
    ['巡检类型', 'inspectionType'],
    ['状态', 'status'],
    ['结果', 'result'],
    ['计划开始', 'planStartTime'],
    ['计划结束', 'planEndTime'],
    ['实际开始', 'actualStartTime'],
    ['实际结束', 'actualEndTime'],
    ['执行人', 'assignedTo'],
    ['备注', 'remark'],
  ],
};

describe('四类导出的列定义与行转换对齐', () => {
  test('四张表的键集完全一致（新增一类导出必须四张表一起补）', () => {
    expect(Object.keys(EXPORT_COLUMN_DEFS).sort()).toEqual([...TYPES].sort());
    const maps = { EXPORT_MODEL_CONFIG, EXPORT_SHEET_NAMES, EXPORT_ROW_TRANSFORMS };
    for (const [name, map] of Object.entries(maps)) {
      expect({ map: name, keys: Object.keys(map).sort() }).toEqual({
        map: name,
        keys: [...TYPES].sort(),
      });
    }
  });

  test.each(TYPES)('列定义有序清单逐项锁定：%s', (type) => {
    const pairs = EXPORT_COLUMN_DEFS[type].map((c) => [c.header, c.key]);
    expect({ type, pairs }).toEqual({ type, pairs: COLUMN_CONTRACT[type] });
  });

  test.each(TYPES)('每列宽度是正数：%s', (type) => {
    const bad = EXPORT_COLUMN_DEFS[type]
      .filter((c) => typeof c.width !== 'number' || !(c.width > 0))
      .map((c) => c.key);
    expect({ type, bad }).toEqual({ type, bad: [] });
  });

  test.each(TYPES)('列 key 集与行转换产出 key 集双向相等：%s', (type) => {
    const columns = EXPORT_COLUMN_DEFS[type].map((c) => c.key);
    const produced = Object.keys(createSafeTransform(EXPORT_ROW_TRANSFORMS[type])({}));
    // 只在列定义里出现 ⇒ exceljs 查不到值，整列空白发货
    const columnsWithoutValue = columns.filter((k) => !produced.includes(k));
    // 只在行转换里出现 ⇒ 算了却没有表头，将来加列时容易被误删
    const valuesWithoutColumn = produced.filter((k) => !columns.includes(k));
    expect({ type, columnsWithoutValue, valuesWithoutColumn }).toEqual({
      type,
      columnsWithoutValue: [],
      valuesWithoutColumn: [],
    });
    expect({ type, duplicateKeys: columns.length - new Set(columns).size }).toEqual({
      type,
      duplicateKeys: 0,
    });
  });

  test.each(TYPES)('空文档过行转换后每一列仍是非空字符串：%s', (type) => {
    const row = createSafeTransform(EXPORT_ROW_TRANSFORMS[type])({});
    const broken = EXPORT_COLUMN_DEFS[type]
      .map((c) => c.key)
      .filter((k) => typeof row[k] !== 'string' || row[k].length === 0);
    expect({ type, broken }).toEqual({ type, broken: [] });
  });
});
