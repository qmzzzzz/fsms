/**
 * 列表搜索的匹配策略（P2-6）
 *
 * 两类字段，两种匹配：
 *   - 编码/用户名等**标识符**：锚定前缀 `^term`。不锚定的 `i` 正则无法用 B-tree
 *     索引，每个请求都是一次全扫描；前缀形态允许索引范围扫描，且"输入开头即前缀"
 *     符合编码检索的实际用法。
 *   - 名称/描述/楼栋等**自由文本**：保持子串匹配。这些字段没有可用的前缀语义，
 *     用户也确实会按中间一段文字找，牺牲索引换可用性是有意选择。
 *
 * 统一长度上限：正则的匹配成本随模式长度上升，且超长"搜索词"不可能是真实标识符。
 * 截断而不是抛 400——既有行为对任意输入都返回结果，拒绝会改变列表接口契约；
 * 截断把病态输入的工作量封顶，正常输入（远短于 100）完全不受影响。
 */

const { escapeRegExp } = require('./helpers');

const MAX_SEARCH_TERM_LENGTH = 100;

/** trim + 长度封顶；非字符串（查询参数被清洗成数组等）视为空搜索 */
const normalizeSearchTerm = (raw) => {
  if (typeof raw !== 'string') return '';
  return raw.trim().slice(0, MAX_SEARCH_TERM_LENGTH);
};

/** 自由文本：大小写不敏感子串 */
const substringPattern = (term) => new RegExp(escapeRegExp(term), 'i');

/** 标识符：大小写不敏感锚定前缀（如用户名、未统一大写的编码） */
const prefixPattern = (term) => new RegExp(`^${escapeRegExp(term)}`, 'i');

/**
 * 入库时经 `uppercase: true` 归一化的编码（如 FireDevice.deviceCode）：
 * 搜索词也转大写并使用**大小写敏感**锚定前缀，才能命中大小写敏感的唯一索引。
 */
const upperCodePrefixPattern = (term) => new RegExp(`^${escapeRegExp(term.toUpperCase())}`);

module.exports = {
  MAX_SEARCH_TERM_LENGTH,
  normalizeSearchTerm,
  substringPattern,
  prefixPattern,
  upperCodePrefixPattern,
};
