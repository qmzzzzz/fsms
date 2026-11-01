/**
 * 日期展示格式化统一口径（第二轮审计 O-6）
 *
 * 此前 reportController 的导出行转换分散着 7 处 toLocaleString/toLocaleDateString 调用：
 * audit 列显式带 { hour12: false }，其余 6 处依赖运行环境隐式默认；两者在当前 Node 下输出
 * 一致但不受保证，ICU 升级即可能分叉。收敛后为唯一显式实现。
 *
 * 约定：
 *  - formatDateTime：日期 + 时间（24 小时制显式化），空值与非有限时间值统一返回 '-'
 *  - formatDate：仅日期，口径同上
 *  - 两者都按 BUSINESS_TIMEZONE 渲染：过滤/聚合窗口（businessDayBounds、$dateToString）
 *    均以东八区为准，展示若不显式带 timeZone，在 UTC 容器里会落后 8 小时，
 *    导致导出行的日期落到自己的筛选窗口之外（第二轮审计 O-6 的展示半段）。
 */

const { BUSINESS_TIMEZONE } = require('../constants/timezone');

/** 收敛成可展示的 Date：空值与非有限时间值一律 null，由调用方补占位符。
 *  null/undefined/'' 必须先挡：new Date(null) 是合法的 1970-01-01，会把"没填"画成纪元 */
const toDisplayDate = (value) => {
  if (value === null || value === undefined || value === '') return null;
  const ts = value instanceof Date ? value.getTime() : new Date(value).getTime();
  return Number.isFinite(ts) ? new Date(ts) : null;
};

const formatDateTime = (value) => {
  const date = toDisplayDate(value);
  return date ? date.toLocaleString('zh-CN', { hour12: false, timeZone: BUSINESS_TIMEZONE }) : '-';
};

const formatDate = (value) => {
  const date = toDisplayDate(value);
  return date ? date.toLocaleDateString('zh-CN', { timeZone: BUSINESS_TIMEZONE }) : '-';
};

module.exports = { formatDateTime, formatDate };
