/**
 * 日期展示格式化统一口径（第二轮审计 O-6）
 *
 * 此前 reportController 的导出行转换分散着 7 处 toLocaleString('zh-CN') /
 * toLocaleDateString('zh-CN') 调用——其中 audit 列显式带 { hour12: false }，
 * 其余 6 处依赖运行环境的隐式默认。两种写法在当前 Node/full-icu 下输出一致
 * （已验证：'2026/9/3 14:30:00'），但隐式默认不受保证：ICU 版本或运行环境
 * 变化时 7 个列的格式可能悄悄分叉。收敛后为唯一显式实现。
 *
 * 约定：
 *  - formatDateTime：日期 + 时间（24 小时制显式化），空值统一返回 '-'
 *  - formatDate：仅日期，空值统一返回 '-'
 *  - 两者都按 BUSINESS_TIMEZONE 渲染：过滤/聚合窗口（businessDayBounds、$dateToString）
 *    均以东八区为准，展示若不显式带 timeZone，在 UTC 容器里会落后 8 小时，
 *    导致导出行的日期落到自己的筛选窗口之外（第二轮审计 O-6 的展示半段）。
 */

const { BUSINESS_TIMEZONE } = require('../constants/timezone');

const formatDateTime = (value) =>
  value
    ? new Date(value).toLocaleString('zh-CN', { hour12: false, timeZone: BUSINESS_TIMEZONE })
    : '-';

const formatDate = (value) =>
  value ? new Date(value).toLocaleDateString('zh-CN', { timeZone: BUSINESS_TIMEZONE }) : '-';

module.exports = { formatDateTime, formatDate };
