/**
 * 举报对象候选的取数服务（`GET /api/security/report-targets` 的唯一查询点）
 *
 * 为什么单独成文件而不是给 userService / DeviceService / AlarmService 各加一个方法：
 *   · 三处逻辑完全相同（拼关键词条件 → find → select → sort → limit），分写三份
 *     迟早有一份先漂移（本仓已有 `findScopeFieldsByIds` 三份副本的先例）；
 *   · 那三个文件都已贴着 `max-lines` 棘轮上限（300 行代码），再塞方法会直接撞线。
 *
 * 调用方只传**已构造好的范围过滤器**（controllers 用 `buildRecordScopeFilter` 生成，
 * 与提交时的 `isRecordInScope` 逐臂同值）。本文件**不自己拼范围条件**：
 * 一旦这里另起一份口径，就会出现「候选里选得到、提交却被判越权」，或反向的假 deny
 * ——两种都只在特定数据范围档位下复现。
 *
 * 关键词条件用 `$and` 追加，绝不覆盖 `filter` 里可能存在的 `$or`（范围臂）。
 * 直接写 `query.$or = ...` 会把整条数据范围条件替换掉，等于「带搜索的候选查询
 * 不做范围过滤」——本仓在 utils/scopeCast.js 里为同一个坑写过专门注释。
 */

const User = require('../models/User');
const FireDevice = require('../models/FireDevice');
const FireAlarm = require('../models/FireAlarm');
const {
  normalizeSearchTerm,
  prefixPattern,
  substringPattern,
  upperCodePrefixPattern,
} = require('../utils/searchPatterns');

/**
 * 每类候选的查询口径。
 *
 * `select` 是「能认出是哪一条」的最小集，刻意不含 PII 与业务正文：
 *   · 用户：只给 username/realName/department，phone/email 的明文通道只有
 *     `POST /security/view-sensitive`（reauth + 层级闸 + view_sensitive_data 审计）；
 *   · 报警：不给 description（现场细节）与 reporter.*（第三方姓名/电话）。
 *
 * `arms` 的匹配策略沿用各资源列表页的既有口径：标识符（username、alarmCode）
 * 走锚定前缀以命中索引，自由文本（realName、deviceName、楼栋）走子串。
 * `deviceCode` 入库经 `uppercase` 归一化，故用大小写敏感前缀。
 *
 * 报警按 occurredAt 倒序：用户要报的通常是刚发生/刚处理的那条，正序会把它
 * 挤出 limit 之外。
 */
const KINDS = {
  user: {
    model: User,
    select: 'username realName department',
    sort: { username: 1 },
    arms: (term) => [{ username: prefixPattern(term) }, { realName: substringPattern(term) }],
  },
  device: {
    model: FireDevice,
    select: 'deviceCode deviceName location',
    sort: { deviceCode: 1 },
    arms: (term) => [
      { deviceCode: upperCodePrefixPattern(term) },
      { deviceName: substringPattern(term) },
    ],
  },
  alarm: {
    model: FireAlarm,
    select: 'alarmCode alarmType level status location occurredAt',
    sort: { occurredAt: -1 },
    arms: (term) => [
      { alarmCode: prefixPattern(term) },
      { 'location.building': substringPattern(term) },
    ],
  },
};

/**
 * @param {Object} params
 * @param {string} params.type user / device / alarm（未知类型返回空集，不抛错）
 * @param {Object} params.filter 已构造好的数据范围过滤器
 * @param {string} [params.keyword] 用户输入的关键词（内部 trim + 截断到 100 字符）
 * @param {number} params.limit 上限（调用方负责封顶）
 * @returns {Promise<Array>} lean 投影文档
 */
const search = ({ type, filter, keyword, limit }) => {
  const kind = KINDS[type];
  if (!kind) return Promise.resolve([]);

  const query = { ...filter };
  const term = normalizeSearchTerm(keyword);
  if (term) {
    query.$and = [...(query.$and || []), { $or: kind.arms(term) }];
  }
  return kind.model.find(query).select(kind.select).sort(kind.sort).limit(limit).lean();
};

module.exports = { KINDS, search };
