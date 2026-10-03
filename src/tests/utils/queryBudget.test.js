/**
 * 列表链查询预算（utils/queryBudget.js）——纯判据 + 接线门禁
 *
 * finding（2026-10-01）：业务列表链（报警/设备/巡检/用户/角色/权限的
 * find+countDocuments 成对扫描与统计聚合）没有任何时间预算，而审计侧早已有
 * 同一判断的参考实现。本文件钉两层：
 *   A. 预算解析真值表（默认 / env 覆盖 / 越界夹取 / 非法回退——绝不产出 NaN）；
 *   B. 接线门禁：全部列表链服务都必须引用预算工具（漏接一个文件就红），
 *      防止"工具造好了却没接"的 finding 原样复发——那正是 classifyIpAttribution
 *      的教训。
 */
'use strict';

const mongoose = require('mongoose');

const {
  DEFAULT_LIST_QUERY_MAX_TIME_MS,
  LIST_QUERY_BUDGET_MS,
  parseListQueryBudgetMs,
  withListBudget,
  listCountOptions,
  listAggregateOptions,
} = require('../../utils/queryBudget');

const LIST_SERVICES = [
  'src/services/AlarmService.js',
  'src/services/DeviceService.js',
  'src/services/InspectionService.js',
  'src/services/userService.js',
  'src/services/roleService.js',
  'src/services/permissionService.js',
  'src/services/auditQueryService.js',
  'src/services/auditExportService.js',
];

describe('queryBudget 纯判据', () => {
  test('预算值已实例化且在合法区间内', () => {
    expect(LIST_QUERY_BUDGET_MS).toBeGreaterThanOrEqual(500);
    expect(LIST_QUERY_BUDGET_MS).toBeLessThanOrEqual(300000);
  });

  test.each([
    ['未设置 → 默认', undefined, DEFAULT_LIST_QUERY_MAX_TIME_MS],
    ['空串 → 默认', '', DEFAULT_LIST_QUERY_MAX_TIME_MS],
    ['非数字 → 默认（绝不 NaN）', 'abc', DEFAULT_LIST_QUERY_MAX_TIME_MS],
    ['负数形态 → 默认', '-5', DEFAULT_LIST_QUERY_MAX_TIME_MS],
    ['小数形态 → 默认', '1.5', DEFAULT_LIST_QUERY_MAX_TIME_MS],
    ['合法值 → 原样', '3000', 3000],
    ['低于下限 → 夹到 500', '10', 500],
    ['高于上限 → 夹到 300000', '999999', 300000],
  ])('%s', (_label, raw, expected) => {
    expect(parseListQueryBudgetMs(raw)).toBe(expected);
  });

  test('三种形态都真实携带 maxTimeMS（find 链 / count options / aggregate options）', () => {
    const S = new mongoose.Schema({ a: String });
    const M = mongoose.model('QueryBudgetProbe', S);
    expect(withListBudget(M.find({})).options.maxTimeMS).toBe(LIST_QUERY_BUDGET_MS);
    expect(listCountOptions()).toEqual({ maxTimeMS: LIST_QUERY_BUDGET_MS });
    expect(listAggregateOptions()).toEqual({ maxTimeMS: LIST_QUERY_BUDGET_MS });
    // aggregate 第二参形态也被 mongoose 接受（与 auditLogQueryStatics.aggregateWithBudget 同口径）
    expect(() => M.aggregate([{ $match: {} }], listAggregateOptions())).not.toThrow();
  });
});

describe('列表链预算接线门禁（漏接即红）', () => {
  const fs = require('fs');
  const path = require('path');

  test('前提自证：清单里的文件都真实存在（清单漂移先在这里响）', () => {
    for (const rel of LIST_SERVICES) {
      expect(fs.existsSync(path.join(__dirname, '../../..', rel))).toBe(true);
    }
  });

  test.each(LIST_SERVICES)('%s 引用了预算工具', (rel) => {
    const src = fs.readFileSync(path.join(__dirname, '../../..', rel), 'utf8');
    // 至少引用其一：find 链包装 / count options / aggregate options
    const wired =
      src.includes('withListBudget') ||
      src.includes('listCountOptions') ||
      src.includes('listAggregateOptions');
    expect({ rel, wired }).toMatchObject({ rel, wired: true });
  });
});
