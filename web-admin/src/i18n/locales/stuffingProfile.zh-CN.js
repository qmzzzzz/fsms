/**
 * 撞库画像页词表（随页面 chunk 懒加载，见 AttackProfileView 同款口径）。
 * 枚举值来自后端：lengthBucket ∈ constants/credentialShape.js 的 LENGTH_BUCKETS，
 * charsetClass 由 l/u/d/s 标记拼接。未识别的值一律回落后端原值，不编造文案。
 */
export default {
  pageTitle: '撞库画像',
  pageSubtitle:
    '按来源网段聚合蜜罐阶段的口令尝试，识别字典命中与账号覆盖面。画像按业务日现算，不落库。',
  dayLabel: '业务日',
  query: '生成画像',
  querying: '分析中…',
  reset: '重置',
  resultCard: '画像结果',
  recordCount: '{count} 个来源段',
  windowRange: '窗口 {since} ~ {until}',
  sourceKey: '来源段',
  attempts: '尝试次数',
  successes: '成功次数',
  accounts: '涉及账号',
  stemHits: '字典命中',
  lengthBucket: '口令长度档',
  charsetClass: '字符集',
  scopeLabel: '数据范围',
  scopeAll: '全部',
  scopeSelf: '本人',
  scopeDepartment: '本部门',
  sourceHint:
    '来源按 /24（IPv4）或 /64（IPv6）聚合；尝试次数只计蜜罐阶段行，成功次数只计真实账号登录。',
  thresholdHint: '样本门槛：同一来源段至少 {min} 次尝试才出口。',
  emptyTitle: '该业务日没有达到门槛的来源段',
  emptyGeneric:
    '窗口内没有满足样本门槛的撞库迹象；这不等于「没有攻击」，样本不足的来源段已被排除。',
  emptyExpired: '该业务日已超出审计保留期，窗口内已无审计证据——空表不代表没有攻击。',
  emptyScope:
    '当前数据范围为「{scope}」，蜜罐审计行不带用户归属，该范围下的画像恒为空。请使用全局数据范围的账号查看。',
  droppedBelowMin: '{n} 个来源段因样本不足被丢弃（门槛 {min} 次）。',
  droppedUnparsable: '{n} 条记录的来源地址无法解析，未参与聚合。',
  loadError: '画像加载失败，请稍后重试',
  staleData: '画像刷新失败，以下为上次结果',
  retry: '重试',
  lengthBucketValue: {
    lt8: '小于 8 位',
    '8-11': '8-11 位',
    '12-15': '12-15 位',
    '16-19': '16-19 位',
    '20plus': '20 位及以上',
  },
  charsetFlag: {
    l: '小写',
    u: '大写',
    d: '数字',
    s: '符号',
  },
}
