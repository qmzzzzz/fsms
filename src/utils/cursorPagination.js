/**
 * 游标（Keyset/Seek）分页工具
 *
 * 背景（E-2）：审计日志/报警/巡检/设备等高量级列表原用 offset 分页，
 * 深分页时 MongoDB skip(N) 需扫描并丢弃前 N 条，页码越深越慢（O(skip+limit)）。
 * 游标分页以「上一页最后一条的排序键 + _id」为起点做范围查询，
 * 每页代价恒定为 O(limit)，且不受并发写入导致的页间漂移影响。
 *
 * 语义约定：
 * - 游标是不透明的（客户端不应解析），当前编码为 base64url(JSON{v,id})；
 * - 排序键取值可能重复（如同一秒多条记录），因此游标必须携带 _id 作平局裁决，
 *   条件形如 (field < v) OR (field == v AND _id < id)（降序；升序换 $gt）；
 * - 游标模式不返回 total/totalPages（省掉 countDocuments 全量统计，
 *   这正是深分页场景的另一大开销），改以 hasMore/nextCursor 表达翻页能力；
 * - 客户端混传 cursor 与 page 时 cursor 优先（page 被忽略）。
 */

const mongoose = require('mongoose');
const ApiError = require('./ApiError');

const MAX_CURSOR_LENGTH = 512;

/**
 * 编码游标
 * @param {{ v: any, id: any }} payload 排序键值与文档 _id
 * @returns {string} base64url 字符串
 */
const encodeCursor = (payload) =>
  Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

/**
 * 解码并校验游标，非法时抛 400
 * @param {string} cursor 客户端传入的游标字符串
 * @returns {{ v: any, id: string }}
 */
const decodeCursor = (cursor) => {
  const invalid = () => ApiError.badRequest('分页游标无效，请从第一页重新查询');
  if (typeof cursor !== 'string' || !cursor || cursor.length > MAX_CURSOR_LENGTH) throw invalid();
  let payload;
  try {
    payload = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch (_) {
    throw invalid();
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw invalid();
  if (!('v' in payload) || typeof payload.id !== 'string') throw invalid();
  if (!/^[0-9a-fA-F]{24}$/.test(payload.id)) throw invalid();
  return payload;
};

/**
 * 把游标条件叠加到基础查询上
 *
 * 用 $and 包裹而不是直接展开到 baseQuery：列表查询可能自带 $or（搜索）
 * 或 $and（审计日志多条件组合），直接混入会互相覆盖。
 *
 * @param {Object} baseQuery 基础过滤条件（数据范围/筛选已应用）
 * @param {Object} options
 * @param {string} options.sortField 排序字段（列表当前使用的单一排序键）
 * @param {1|-1} options.sortDir 排序方向
 * @param {{ v: any, id: string }|null} options.cursor decodeCursor 的结果；为空时原样返回
 * @param {'date'|'string'|'number'} [options.valueType='date'] 排序键类型，决定反序列化方式
 * @returns {Object} 叠加游标条件后的查询
 */
const applyCursorCondition = (baseQuery, { sortField, sortDir, cursor, valueType = 'date' }) => {
  if (!cursor) return baseQuery;

  let v = cursor.v;
  if (valueType === 'date') {
    v = new Date(v);
    if (Number.isNaN(v.getTime())) throw ApiError.badRequest('分页游标无效，请从第一页重新查询');
  } else if (valueType === 'number') {
    v = Number(v);
    if (!Number.isFinite(v)) throw ApiError.badRequest('分页游标无效，请从第一页重新查询');
  }

  const op = sortDir === 1 ? '$gt' : '$lt';
  let id;
  try {
    id = new mongoose.Types.ObjectId(cursor.id);
  } catch (_) {
    throw ApiError.badRequest('分页游标无效，请从第一页重新查询');
  }

  return {
    $and: [
      baseQuery,
      {
        $or: [{ [sortField]: { [op]: v } }, { [sortField]: v, _id: { [op]: id } }],
      },
    ],
  };
};

/**
 * 从 limit+1 拉取结果裁剪出当页数据与下一页游标
 * @param {Array} docs 实际拉取到的文档（调用方须按 limit+1 拉取）
 * @param {number} limit 每页条数
 * @param {string} sortField 排序字段（用于读取最后一条的排序键值）
 * @returns {{ items: Array, hasMore: boolean, nextCursor: string|null }}
 */
const buildCursorResult = (docs, limit, sortField) => {
  const hasMore = docs.length > limit;
  const items = hasMore ? docs.slice(0, limit) : docs;
  const last = items[items.length - 1];
  const nextCursor =
    hasMore && last ? encodeCursor({ v: last[sortField], id: String(last._id) }) : null;
  return { items, hasMore, nextCursor };
};

module.exports = {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
};
