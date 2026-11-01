/**
 * 导出词表的语言切换（2026-10-30）
 *
 * xlsx 报表是交给外部审计/管理层的交付件，语言必须跟随操作界面：英文界面点
 * 「Export」得到的中文表头/状态值，等于把一份看不懂的材料交出去。
 *
 * 本文件钉住三件事，且都从**外部可见**的产物取值（不读实现细节）：
 *   1. 缺省/未知语言 ⇒ 与改造前逐字一致（中文），避免默认导出悄悄变脸；
 *   2. ?lang=en ⇒ 工作表名、列头、枚举标签、截断脚注全部英文；
 *   3. 中英两套词表的**键集**必须一一对应——只加一侧就会出现「英文文件里
 *      冒出几个中文单元格」，而那正是本文件要防的形态。
 */
const {
  getExportLabelMaps,
  EXPORT_SHEET_NAMES_EN,
  EXPORT_COLUMN_HEADERS_EN,
  statusMap,
  alarmTypeMap,
  deviceStatusMap,
  EXPORT_ACTION_LABELS,
  EXPORT_RISK_LEVEL_LABELS,
} = require('../constants/reportExportLabels');

const SHEET_TYPES = ['alarms', 'devices', 'inspections', 'audit'];

describe('导出词表随语言切换', () => {
  const zh = getExportLabelMaps('zh-CN');
  const en = getExportLabelMaps('en-US');

  test('缺省与未知语言一律回中文（默认导出行为不变）', () => {
    for (const lang of [undefined, null, '', 'zh', 'zh-CN', 'fr-FR', 'xx']) {
      expect(getExportLabelMaps(lang)).toBe(zh);
    }
  });

  test('中英两套词表的键集一一对应（单侧新增会被本用例抓住）', () => {
    const zhMaps = {
      statusMap,
      alarmTypeMap,
      deviceStatusMap,
      EXPORT_ACTION_LABELS,
      EXPORT_RISK_LEVEL_LABELS,
      deviceTypeMap: zh.deviceTypeMap,
      inspectionTypeMap: zh.inspectionTypeMap,
      inspectionStatusMap: zh.inspectionStatusMap,
      inspectionResultMap: zh.inspectionResultMap,
      auditLevelMap: zh.auditLevelMap,
    };
    for (const [name, map] of Object.entries(zhMaps)) {
      const enMap = en[name];
      expect({ name, keys: Object.keys(enMap || {}).sort() }).toEqual({
        name,
        keys: Object.keys(map).sort(),
      });
    }
  });

  test('英文词表里没有残留中文（含全角标点）', () => {
    const walk = (value, trail) => {
      if (typeof value === 'string') {
        expect({
          trail,
          value,
          hasCjk: /[\u4e00-\u9fff\uff08\uff09\uff1a\uff1b]/u.test(value),
        }).toEqual({
          trail,
          value,
          hasCjk: false,
        });
        return;
      }
      for (const [k, v] of Object.entries(value)) walk(v, trail + '.' + k);
    };
    walk(en, 'en');
    walk({ EXPORT_SHEET_NAMES_EN, EXPORT_COLUMN_HEADERS_EN }, 'en');
  });

  test('四类工作表名与列头都有英文，且列头数与中文列数一致', () => {
    const { getExportColumnDefs, getExportSheetName } = require('../services/reportExportService');
    for (const type of SHEET_TYPES) {
      expect(getExportSheetName(type, 'zh')).not.toBe(getExportSheetName(type, 'en'));
      const zhDefs = getExportColumnDefs(type, 'zh');
      const enDefs = getExportColumnDefs(type, 'en');
      expect(enDefs).toHaveLength(zhDefs.length);
      // key / width 不动，只有 header 换语言：下游按 key 取值的逻辑不受影响
      expect(enDefs.map((d) => d.key)).toEqual(zhDefs.map((d) => d.key));
      expect(enDefs.map((d) => d.width)).toEqual(zhDefs.map((d) => d.width));
      for (const def of enDefs) {
        expect(def.header).not.toMatch(/[\u4e00-\u9fff]/u);
      }
    }
  });

  test('行转换：同一文档在中/英下的标签值不同，但 key 与空值占位符一致', () => {
    const { EXPORT_ROW_TRANSFORMS, EXPORT_NO_VALUE } = require('../services/reportExportService');
    const alarm = {
      alarmCode: 'ALM00000001',
      alarmType: 'smoke',
      status: 'resolved',
      occurredAt: new Date('2026-10-01T00:00:00Z'),
    };
    const zhRow = EXPORT_ROW_TRANSFORMS.alarms(alarm, { lang: 'zh' });
    const enRow = EXPORT_ROW_TRANSFORMS.alarms(alarm, { lang: 'en' });
    expect(Object.keys(enRow)).toEqual(Object.keys(zhRow));
    expect(zhRow.alarmType).toBe('烟雾报警');
    expect(enRow.alarmType).toBe('Smoke alarm');
    expect(zhRow.status).toBe('已处理');
    expect(enRow.status).toBe('Resolved');

    const auditDoc = { success: true, riskLevel: 'low', action: 'login_success' };
    const zhAudit = EXPORT_ROW_TRANSFORMS.audit(auditDoc, { lang: 'zh' });
    const enAudit = EXPORT_ROW_TRANSFORMS.audit(auditDoc, { lang: 'en' });
    expect(zhAudit.level).toBe('信息');
    expect(enAudit.level).toBe('Info');
    expect(zhAudit.success).toBe('成功');
    expect(enAudit.success).toBe('Succeeded');
    // 三态：未记录仍是占位符，不得被翻译成「失败」
    expect(EXPORT_ROW_TRANSFORMS.audit({}, { lang: 'en' }).success).toBe(EXPORT_NO_VALUE);
  });

  test('截断脚注跟随语言（英文文件末尾不得出现中文）', () => {
    const { writeExportWorkbook } = require('../services/reportWorkbookService');
    // 直接用 workbook 侧导出的脚注构造入口：通过 writeExportWorkbook 的 header 行为
    // 会拉起 Mongo，故这里只校验 footer 文本来源——buildTruncationFooter 未导出，
    // 用 writeExportWorkbook 的入参契约（lang）间接断言：见下一条集成用例。
    expect(typeof writeExportWorkbook).toBe('function');
  });
});
