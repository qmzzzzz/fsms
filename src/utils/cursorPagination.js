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
 *
 * 【排序键可为空/可缺失时的口径】（本机 mongod 6.0.14 实测，不是推断）
 * - `undefined` 是**编码层就存在的洞**：`JSON.stringify` 整键丢掉 undefined，
 *   于是 `encodeCursor({v: undefined, id})` 产出的游标连 `decodeCursor` 的
 *   「必须有 v」都过不了 ⇒ 服务下发自己吃不回去的游标（400 死循环）。
 *   所以 `encodeCursor` 把 undefined 归一成 `null`，让"没有排序键"有一种忠实表示。
 * - 范围比较**不跨类型**：`{f:{$lt:<date>}}` 对 null 与缺失键都是空集；
 *   `{f:{$lte:null}}` 与 `{f:null}` 命中整块（含"根本没这个键"的文档），
 *   `{$ne:null}` 精确命中"有值"，而 `{$lt:null}` / `{$gt:null}` 恒空。
 *   ⇒ 空值块必须靠专用子句续翻（`nullBlockClauses`），倒序的有值页也要额外并一条
 *   `{f:{$lte:null}}`（`valueClauses`），否则整块记录在游标模式下永久不可达。
 * - 空值块的位置随排序方向翻转：升序在头部、倒序在尾部（缺失与 null 都按最小值排）。
 *
 * 【等值键的平局裁决：排序必须与游标子句同向，且要有同向复合索引】
 * 范围条件用 `_id` 做平局裁决（见 applyCursorCondition），所以**排序也必须带 `_id`
 * 次级键**，方向与子句的比较符一致（降序 ⇒ `_id:-1` + `$lt`；升序 ⇒ `_id:1` + `$gt`）。
 * 只排主键时隐式平局序是 (key, RecordId **升序**)，与降序子句的 `_id < id` **方向相反** ⇒
 * 等值块（同一毫秒多条）跨页漂移。实测 5000 条 / 100 个取值 × 50 / 每页 20：
 *   .sort({ts:-1})         ⇒ 重复 950、漏 3950（79% 永久不可达）、第 101 页就 hasMore:false
 *   .sort({ts:-1,_id:-1})  ⇒ 重复 0、漏 0、251 页遍历完
 * 准确说法是"**不可依赖**"而不是"**必然漂**"：块内序取自索引的隐式序，所以它随
 * 插入次序变——同一批夹具改成组内反序插入，四格矩阵全绿（正序插入 + 单字段索引
 * + 只排主键这一格才是漂：重复 380、漏 1580）。而 RecordId 会不会与 `_id` 同向，
 * 取决于并发写入、回填/导入、就地 update 造成的文档搬迁——这些都不是能承诺的东西，
 * 所以排序键必须写全为全序。
 * 这条限制对**空值块**同样成立：只排主键时同一份 5 条夹具
 * `find({}).sort({f:1})` 与 `find({}).sort({f:1}).limit(2)` 给出的块内顺序都不一样
 * （计划相关）；带上 `_id` 之后排序是全序，块内先后才可依赖。
 * 三个倒序调用点（报警/巡检/审计）已按此口径带上 `_id:-1`；设备列表按 `deviceCode`
 * 升序排，该键 `unique:true` 不可能重复 ⇒ 不需要次级键。
 * 反过来，**没有同向复合索引时不要单独加次级排序键**（本机实测 5000 条 + {ts:-1} 索引）：
 *   .sort({ts:-1})            → LIMIT/FETCH/IXSCAN，扫 limit 量级
 *   .sort({ts:-1,_id:±1})     → PROJECTION/SORT/**COLLSCAN**，totalDocsExamined=5000
 * 即加次级排序键会把索引有序扫描打成全表扫描 + 阻塞排序（大集合还会撞 32MB 内存排序
 * 上限，表现为列表接口 500）。索引声明见三个模型，存量库对齐走
 * `migrations/20260926000000-cursor-tiebreak-compound-indexes.js`；
 * 取舍与实测口径见 `docs/adr/ADR-006-高量级列表游标分页选型.md`，
 * 代价复核见 `scripts/perf/explain-spotcheck.js`。
 */

const mongoose = require('mongoose');
const ApiError = require('./ApiError');

const MAX_CURSOR_LENGTH = 512;

// L-14：排序键值的长度上限。游标是客户端可自由构造的入参，
// `string` 分支此前对 v 不做任何校验，等值/范围查询会直接带上超长串；
// 上限封住「用超长 v 撑爆查询」的路径。
//
// 但这一上限**同时**是"服务自己下发的游标能不能被自己吃回去"的下限：
// 设备列表（唯一 `valueType:'string'` 的调用点，DeviceService.getDevices）用 `deviceCode`
// 作排序键，而 deviceCode 的合法宽度由 `models/FireDevice` 的 `maxlength:50` 决定
// （路由 `deviceRoutes.js` 的 `isLength({max:50})` 与它对齐）。上限窄于它时的后果
// **不是报错而是翻页自断**：某一页最后一条的编码超过上限时，`buildCursorResult`
// 照样下发 nextCursor，客户端照原样回传却被 `decodeCursor` 拒成 400，
// 用户从这一页起再也翻不动，服务端一条日志都没有——
// 而 50 字符的编码是台账里的合法值（`src/tests/deviceCodeCap.test.js` 就在存它）。
// 取 64：覆盖 50 且留余量，相对整条游标的 `MAX_CURSOR_LENGTH`（512）仍是窄闸。
// 不变式由 `src/tests/utils/cursorPagination.test.js` 从**模型**推导并钉住
// （上限 < 最宽合法排序键 ⇒ 红），因为抄一份数字到测试等于没钉。
const MAX_CURSOR_VALUE_LENGTH = 64;

// 调用点可用的排序键类型。单独列一份是为了让「未识别 valueType 必须 fail-fast」这条
// 在两条路径上都成立：有值路径由 castCursorValue 的末尾兜住，空值路径绕过了它，
// 就靠 applyCursorCondition 里这次 includes 兜住。
const VALUE_TYPES = ['date', 'number', 'string'];

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
 * 游标相关的 400 统一出口（同一文案只留一处，避免改一处漏一处）
 */
const invalidCursor = () => ApiError.badRequest('分页游标无效，请从第一页重新查询');

/**
 * 编码游标
 *
 * `v` 为 undefined 时归一成 `null`。这一条不是洁癖而是修一条死路：
 * `JSON.stringify` 会**整键丢掉** undefined 值（`{v:undefined,id}` → `{"id":"…"}`），
 * 而 `decodeCursor` 要求 `'v' in payload`。所以"排序键可为空/可缺失"的列表
 * （`Inspection.planStartTime` 在模型里无 required 无 default）只要某一页的最后一条
 * 没有这个键，服务就会下发一个**自己解不回去**的游标：客户端照原样回传 ⇒ 400
 * 「分页游标无效，请从第一页重新查询」⇒ 回到第一页再翻到这里又是 400，
 * 永久死循环且服务端零日志。
 * 选 `null` 作"没有排序键"的线上表示是忠实的：MongoDB 把缺失与 null 排在同一个块里
 * （实测 `{f:null}` 同时命中缺键文档与显式 null 文档），空值块的条件由
 * `nullBlockClauses` 专门处理。四个直接调 `encodeCursor` 的 offset 模式落点一并被收口。
 *
 * @param {{ v: any, id: any }} payload 排序键值与文档 _id
 * @returns {string} base64url 字符串
 */
const encodeCursor = (payload) => {
  const v = payload.v === undefined ? null : payload.v;
  return Buffer.from(JSON.stringify({ ...payload, v }), 'utf8').toString('base64url');
};

/**
 * 解码并校验游标，非法时抛 400
 * @param {string} cursor 客户端传入的游标字符串
 * @returns {{ v: any, id: string }}
 */
const decodeCursor = (cursor) => {
  if (typeof cursor !== 'string' || !cursor || cursor.length > MAX_CURSOR_LENGTH) {
    throw invalidCursor();
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch (_) {
    throw invalidCursor();
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw invalidCursor();
  if (!('v' in payload) || typeof payload.id !== 'string') throw invalidCursor();
  if (!/^[0-9a-fA-F]{24}$/.test(payload.id)) throw invalidCursor();
  assertCursorValueShape(payload.v);
  return payload;
};

/**
 * L-14：校验游标排序键值 v 的类型与体积，非法时抛 400（文案走 invalidCursor 统一出口）。
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
 */
const assertCursorValueShape = (v) => {
  if (v !== null && typeof v !== 'string' && typeof v !== 'number') throw invalidCursor();
  if (typeof v === 'string' && v.length > MAX_CURSOR_VALUE_LENGTH) throw invalidCursor();
};

/**
 * 把游标里的排序键值还原成可比较的 BSON 值，并按类型收口非法输入。
 *
 * L-14 修复口径（原样保留在 string 分支）：非空字符串 + 长度上限，非法即 400。
 * 未识别的 valueType（含调用方漏传与拼写错误）按 fail-fast 处理：
 * 静默透传会让游标条件退化为「无范围约束」，是最危险的一种失败形态。
 */
const castCursorValue = (v, valueType) => {
  if (valueType === 'date') {
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) throw invalidCursor();
    return d;
  }
  if (valueType === 'number') {
    const n = Number(v);
    if (!Number.isFinite(n)) throw invalidCursor();
    return n;
  }
  if (valueType === 'string') {
    // v 若为对象/数组，Mongoose 会把它当操作符对象或数组条件处理，查询语义与调用方
    // 预期不符：设备列表翻页可能返回空页或全部数据，且没有任何可观测信号。
    if (typeof v !== 'string' || v.length === 0 || v.length > MAX_CURSOR_VALUE_LENGTH) {
      throw invalidCursor();
    }
    return v;
  }
  throw invalidCursor();
};

/**
 * 排序键有值时的续翻条件：`(f op v) OR (f == v AND _id op id)`，op 由方向决定。
 *
 * 倒序时额外并一条 `{f: {$lte: null}}`：MongoDB 的范围比较**不跨类型**——
 * 实测（mongod 6.0.14）`{f:{$lt:<date>}}` 对 null 与缺失键都返回空集，
 * 而倒序排列下空值块就在**尾部**，少了这一条，"没有排序键"的那批记录
 * 在游标模式下永远翻不到，且列表在这里**假到底**（`hasMore:false`，零日志）。
 * 升序不加：那时空值块在头部，走到有值区间时块已整体在过去，加上就会重复下发。
 */
const valueClauses = (sortField, sortDir, v, id) => {
  const op = sortDir === 1 ? '$gt' : '$lt';
  const clauses = [{ [sortField]: { [op]: v } }, { [sortField]: v, _id: { [op]: id } }];
  if (sortDir === -1) clauses.push({ [sortField]: { $lte: null } });
  return clauses;
};

/**
 * 排序键为空值（显式 null 或该键根本不存在——实测 `{f:null}` 两者都命中）时的续翻条件。
 *
 * 这条分支存在的理由是：**空值不能进类型转换**。走 `castCursorValue` 的话
 * `new Date(null)` 得到 1970-01-01、`Number(null)` 得到 0，条件退化成
 * "找 1970 年之前 / 小于 0 的记录"——实测两者都是恒空集，
 * 于是翻页在这里以"到底了"收尾，而真实数据还在后面（不是报错，是静默截断）。
 *
 * - 倒序：空值块在尾部，块内后续文档靠 `_id` 平局子句续翻，块外已无更低的值域；
 * - 升序：空值块在头部，块之后还有全部有值文档，所以再并一条 `{$ne: null}`
 *   （实测它精确匹配"有值"，把 null 与缺失都排除在外）。
 */
const nullBlockClauses = (sortField, sortDir, id) => {
  const op = sortDir === 1 ? '$gt' : '$lt';
  const clauses = [{ [sortField]: null, _id: { [op]: id } }];
  if (sortDir === 1) clauses.push({ [sortField]: { $ne: null } });
  return clauses;
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
  // 空值分支绕过了 castCursorValue，所以类型白名单在这里也要收一次口：
  // 调用方拼错 valueType 时，两条路径都必须 fail-fast，不能一条严一条松。
  if (!VALUE_TYPES.includes(valueType)) throw invalidCursor();
  let id;
  try {
    id = new mongoose.Types.ObjectId(cursor.id);
  } catch (_) {
    throw invalidCursor();
  }
  const clauses =
    cursor.v === null
      ? nullBlockClauses(sortField, sortDir, id)
      : valueClauses(sortField, sortDir, castCursorValue(cursor.v, valueType), id);

  return { $and: [baseQuery, { $or: clauses }] };
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
