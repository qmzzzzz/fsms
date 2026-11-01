/**
 * U4 回归：formatDateTime/formatDate 对非有限时间值走占位符，且 0 不得被当空值
 *
 * 原实现 value ? new Date(value)... : '-'：
 *   · 'abc' 是真值 ⇒ new Date('abc') 为 Invalid Date ⇒ toLocaleString 直出英文串 'Invalid Date' 进界面；
 *   · 0 是**合法**纪元毫秒却因 falsy 被判成空值输出 '-'。
 * 判据钉「占位符」与「0 正常格式化」两端，并把 undefined/null/''/NaN 一起钉住。
 */

'use strict';

const { formatDateTime, formatDate } = require('../../utils/dateFormat');

describe('U4 非有限时间值统一占位符', () => {
  test('非日期串不再直出 Invalid Date', () => {
    expect(formatDateTime('abc')).toBe('-');
    expect(formatDate('abc')).toBe('-');
    expect(formatDateTime('2026-13-45')).toBe('-');
  });

  test('空值与 NaN/Infinity 都是占位符', () => {
    for (const bad of [null, undefined, '', NaN, Infinity, -Infinity]) {
      expect(formatDateTime(bad)).toBe('-');
      expect(formatDate(bad)).toBe('-');
    }
  });

  test('0 必须正常格式化（纪元毫秒是合法时刻，不是空值）', () => {
    const out = formatDateTime(0);
    expect(out).not.toBe('-');
    expect(out).toContain('1970');
    expect(formatDate(0)).not.toBe('-');
  });

  test('正向对照：合法时间仍按业务时区渲染', () => {
    const instant = '2026-08-20T16:00:00Z';
    const zone = require('../../constants/timezone').BUSINESS_TIMEZONE;
    expect(formatDateTime(instant)).toBe(
      new Date(instant).toLocaleString('zh-CN', { hour12: false, timeZone: zone })
    );
    expect(formatDate(instant)).toBe(
      new Date(instant).toLocaleDateString('zh-CN', { timeZone: zone })
    );
  });
});
