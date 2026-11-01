'use strict'; // 合成行的取值与分桶共用件（纯函数叶子）：聚合面与列表面共用同一口径，体积上把行数让给 builders

const helpers = require('../utils/helpers'); // 时间口径唯一来源

const MIN = 60 * 1000;

const epochOf = (at, now) => (at == null ? null : now.getTime() - Number(at) * MIN); // 缺失/未登记 ≠ 此刻，绝不折成 0
const isoOf = (epoch) => (epoch === null ? null : new Date(epoch).toISOString());
const epochOfValue = (value) =>
  value === null || value === undefined ? null : helpers.toEpochMs(value); // 排序口径走 helpers.toEpochMs：裸 Date.parse 是 dateParamGateSingleSource 的禁形（F-157），它会把 '123' 这类纯数字串当成合法日期
const isoOfOffset = (offsetMin, now) => isoOf(epochOf(offsetMin, now));
const byKey = (key) => (a, b) => epochOfValue(a[key]) - epochOfValue(b[key]);

const tally = (rows, field) => {
  const counts = new Map();
  rows.forEach((row) => counts.set(row[field] ?? null, (counts.get(row[field] ?? null) || 0) + 1)); // 字段缺失也成桶：Mongo $group 给 _id:null，而 undefined 会被 JSON 整个丢掉——桶凭空消失还是小事，字段改名漏改一处就这样静默产坏桶
  return [...counts].map(([key, count]) => ({ _id: key, count })).sort((a, b) => b.count - a.count); // $group 合成：同数并列保持出现序
};

module.exports = {
  MIN,
  byKey,
  epochOf,
  epochOfValue,
  isoOf,
  isoOfOffset,
  tally,
};
