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
    // P2-12（2026-11-15）修复：原用例只有 expect(typeof writeExportWorkbook).toBe('function')
    // 一条恒真断言，标题承诺的「脚注跟随语言」零覆盖。buildTruncationFooter 现已从
    // reportWorkbookService 导出（原「未导出」的注释已过时），直接对同一语境断言
    // 中英两份脚注的逐字文案；lang 缺省回中文与第 1 条用例同一口径。
    const { buildTruncationFooter } = require('../services/reportWorkbookService');
    const { EXPORT_LIMIT } = require('../services/reportExportService');
    const context = {
      total: EXPORT_LIMIT + 7,
      written: EXPORT_LIMIT,
      truncated: true,
      rowsLost: 0,
      countDrift: 0,
    };
    const zhFooter = buildTruncationFooter({ ...context, lang: 'zh' });
    const enFooter = buildTruncationFooter({ ...context, lang: 'en' });
    expect(zhFooter).toBe(
      `⚠ 数据已截断：本文件仅包含前 ${EXPORT_LIMIT} 行（命中总数 ${EXPORT_LIMIT + 7}），` +
        '请缩小时间范围或增加筛选条件后重新导出。'
    );
    expect(enFooter).toBe(
      `⚠ Data truncated: This file contains only the first ${EXPORT_LIMIT} rows ` +
        `(total matches ${EXPORT_LIMIT + 7}). Narrow the time range or add filters and export again.`
    );
    // 标题承诺的反向对照：英文文件末尾不得出现中文
    expect(enFooter).not.toMatch(/[\u4e00-\u9fff]/u);
    // 缺省语言回中文（与「缺省导出行为不变」同一口径）
    expect(buildTruncationFooter({ ...context })).toBe(zhFooter);
  });
});
