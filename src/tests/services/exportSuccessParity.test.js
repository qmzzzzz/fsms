'use strict';

/**
 * 的漂移锁：审计筛选在「查询」与「导出」两侧必须逐值同口径
 *
 * 背景：`buildAuditQuery`（utils/auditQuery.js）与 `buildExportQuery('audit')`
 * （services/reportExportService.js）是同一批筛选条件的两份实现。用户看到的
 * 承诺是"导出即所见"，所以任何一侧单方面改判据都会造成
 * **查询 400、导出静默给另一个结果集**（或反之）—— 已经为 riskLevel 清单
 * 钉过同一类漂移，本文件补 success 这一维。
 *
 * 为什么用"两份实现 + 真值表"而不是抽公共函数：判据的家（helpers.js /
 * auditQuery.js）此刻在并行会话手里，提前抽一个只有一处调用的公共 API
 * 就是本仓记过一次的"死分支"。等两处都稳定后再合并，届时本文件仍会绿
 * （它比的是行为，不是实现位置）。
 *
 * 断言形状刻意取"两侧结果整体相等"（含抛错时的 message 文本）：
 * 只断言"都抛错"会放过文案漂移，只断言成功值会放过"一侧抛一侧不抛"。
 */

const { buildAuditQuery } = require('../../utils/auditQuery');
const { buildExportQuery } = require('../../services/reportExportService');

// 覆盖：合法布尔文本 / 布尔 / 数字串 / 大小写 / 带空格 / 空值 / 非字符串
const VALUES = [
  'true',
  'false',
  true,
  false,
  '1',
  '0',
  1,
  0,
  'yes',
  'TRUE',
  'True',
  ' true',
  'true ',
  '',
  null,
  {},
  [],
  ['true'],
  { $ne: 'x' },
  undefined,
];

const queryOutcome = (success) => {
  try {
    return { accepted: true, value: buildAuditQuery({ query: { success } }).query.success };
  } catch (error) {
    return { accepted: false, message: error.message };
  }
};

const exportOutcome = (success) => {
  try {
    return {
      accepted: true,
      value: buildExportQuery('audit', { success, dateFilter: {} }).success,
    };
  } catch (error) {
    return { accepted: false, message: error.message };
  }
};

describe('zzqA success 筛选两侧同口径', () => {
  // 标签必须自带类型信息：`['true']` 与 `'true'` 的 String() 相同，
  // 用 String(value) 当键会让后者顶掉前者（真值表悄悄少一行 = 假绿）
  const CASES = VALUES.map((v, i) => [`#${i} ${JSON.stringify(v)}`, v]);

  test.each(CASES)('逐值相等：%s', (_label, value) => {
    expect(exportOutcome(value)).toEqual(queryOutcome(value));
  });

  test('合法值两侧都解析成同一个布尔', () => {
    expect(queryOutcome('true')).toEqual({ accepted: true, value: true });
    expect(exportOutcome('true')).toEqual({ accepted: true, value: true });
    expect(queryOutcome(false)).toEqual({ accepted: true, value: false });
    expect(exportOutcome(false)).toEqual({ accepted: true, value: false });
  });

  test('核心：非法值两侧都拒，且错误文案指向 success（不得静默按 false 筛）', () => {
    for (const bad of ['1', '0', 'yes', 'TRUE', ' true', null, {}, ['true']]) {
      const q = queryOutcome(bad);
      const e = exportOutcome(bad);
      expect(q.accepted).toBe(false);
      expect(e.accepted).toBe(false);
      expect(e.message).toMatch(/success/);
      // 静默折成 false 的样子：accepted 为 true 且 value === false
      expect(e.value).toBeUndefined();
    }
  });

  test('反向保护：空串/未传 两侧都是"不加这个筛选条件"，不得变成 400', () => {
    // 前端"清空筛选"会把参数变成空串；判成 400 等于用户点一下清除按钮就报错
    for (const empty of ['', undefined]) {
      expect(queryOutcome(empty)).toEqual({ accepted: true, value: undefined });
      expect(exportOutcome(empty)).toEqual({ accepted: true, value: undefined });
    }
  });

  test('可证伪性：一侧改宽（把 1 当成 true）时本文件必须红', () => {
    // 这里不是断言产品行为，而是断言"两侧判据集合相等"这件事本身可测：
    // 直接比较两侧对 '1' 的判定，任何一侧被单独放宽都会让上面两条用例失败。
    expect(exportOutcome('1')).toEqual(queryOutcome('1'));
    expect(queryOutcome('1').accepted).toBe(false);
  });
});
