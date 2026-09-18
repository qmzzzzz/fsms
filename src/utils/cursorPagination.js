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

// L-14：排序键值的长度上限。游标是客户端可自由构造的入参，
// `string` 分支此前对 v 不做任何校验，等值/范围查询会直接带上超长串；
// 32 字符足以容纳真实主键（如 deviceCode），同时封住「用超长 v 撑爆查询」的路径。
const MAX_CURSOR_VALUE_LENGTH = 32;

// 评价报告 #13：sortField 防注入白名单格式。当前 4 个调用点均为服务层硬编码，
// 但工具层不能假设未来调用者——排序键直接拼进查询键位（[sortField]），
// 一旦被用户输入污染即可构造任意字段条件（含 $ 开头操作符）。
// 规则：字母/数字/下划线/点号组成、不以点号开头结尾、禁止 $ 与空键段。
const SORT_FIELD_REGEX = /^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$/;

const validateSortField = (sortField) => {
  if (typeof sortField !== 'string' || !SORT_FIELD_REGEX.test(sortField)) {
    throw ApiError.badRequest('排序字段不合法');
  }
  return sortField;
};

/**
 * 点路径取值（评价报告 #13）：buildCursorResult 原用 last[sortField]，
 * 排序键为嵌套路径（如 'meta.ip'）或 lean 文档时取到 undefined，
 * 生成的游标条件 { field: undefined } 会让翻页错查。逐段下钻取值。
 */
const getPath = (obj, path) => {
  let cur = obj;
  for (const seg of path.split('.')) {
    if (cur === null || cur === undefined) return undefined;
    cur = cur[seg];
  }
  return cur;
};

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
  assertCursorValueShape(payload.v, invalid);
  return payload;
};

/**
 * L-14：校验游标排序键值 v 的类型与体积，非法时调用 invalid() 抛出 400。
 *
 * 此前只看「键存在」（`'v' in payload`），于是 {v:{}}, {v:[]},
 * {v:{$gt:''}}, {v:'x'.repeat(1e5)} 都能通过 decodeCursor。危害大小取决于
 * 调用点的 valueType（见 applyCursorCondition）——date/number 分支会各自
 * 兜住非法值，**只有 string 分支把它原样透传**进查询条件，代价是静默错页
 * （详见该分支注释）。
 *
 * 此处按「标量或 null」收口：对象（含数组、含 $ 操作符对象）一律拒绝，
 * 因为它们没有任何合法的排序键语义，只可能是构造出来的查询注入面。
 * null 予以保留——字段显式为 null 的文档会产生这种游标（见 encodeCursor
 * 调用点），拒绝它会让这些文档翻页中断，属另一方向的回归。
 * 独立成函数也是复杂度棘轮（E-02）的要求：decodeCursor 因此回到 15 以内。
 *
 * @param {any} v 游标中的排序键值
 * @param {() => never} invalid 抛错回调（复用调用方的 400 文案）
 */
const assertCursorValueShape = (v, invalid) => {
  if (v !== null && typeof v !== 'string' && typeof v !== 'number') throw invalid();
  if (typeof v === 'string' && v.length > MAX_CURSOR_VALUE_LENGTH) throw invalid();
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
  validateSortField(sortField);

  let v = cursor.v;
  if (valueType === 'date') {
    v = new Date(v);
    if (Number.isNaN(v.getTime())) throw ApiError.badRequest('分页游标无效，请从第一页重新查询');
  } else if (valueType === 'number') {
    v = Number(v);
    if (!Number.isFinite(v)) throw ApiError.badRequest('分页游标无效，请从第一页重新查询');
  } else if (valueType === 'string') {
    // L-14 修复：string 分支此前径直落入「原样透传」，没有任何类型校验。
    // 后果不是抛错而是**静默错页**——v 若为对象/数组，Mongoose 会把它当
    // 操作符对象或数组条件处理，查询语义与调用方预期不符：设备列表翻页
    // 可能返回空页或全部数据，且没有任何可观测信号。
    // 这里显式收敛为「非空字符串 + 长度上限」，非法即 400（与另两分支同口径）。
    if (typeof v !== 'string' || v.length === 0 || v.length > MAX_CURSOR_VALUE_LENGTH) {
      throw ApiError.badRequest('分页游标无效，请从第一页重新查询');
    }
  }
  // 未识别的 valueType（含调用方漏传与拼写错误）按 fail-fast 处理：
  // 静默透传会让游标条件退化为「无范围约束」，是最危险的一种失败形态。
  else {
    throw ApiError.badRequest('分页游标无效，请从第一页重新查询');
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
  validateSortField(sortField);
  const hasMore = docs.length > limit;
  const items = hasMore ? docs.slice(0, limit) : docs;
  const last = items[items.length - 1];
  const nextCursor =
    hasMore && last ? encodeCursor({ v: getPath(last, sortField), id: String(last._id) }) : null;
  return { items, hasMore, nextCursor };
};

module.exports = {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
  MAX_CURSOR_VALUE_LENGTH,
};
