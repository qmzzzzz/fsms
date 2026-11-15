/**
 * 迁移幂等判据的单一事实来源（P2-35，2026-11-15）
 *
 * specSig / collationSig / isEquivalentTwin / dropIndexIfExists 等判据此前在 6 个迁移文件里
 * 各抄一份且已漂移（dropIndexIfExists 分叉为「先查后删」与「drop 后 catch IndexNotFound」两套）。
 * 本模块收口后判据只此一份；dropIndexIfExists 统一为 **drop 后捕获 IndexNotFound /
 * NamespaceNotFound** 的原子口径——「先查后删」在两实例并发 up() 时存在 TOCTOU（migrate-mongo
 * 的锁是 opt-in，本仓未启用），输方会撞 code 27 使整次 migrate 中断。
 * 判据口径与原实现逐字段一致：collation 补默认值后全字段比对（不比 version）、
 * background 不进签名、key 顺序是签名的一部分、声明里没有的选项按「不存在」处理。
 */

/** 递归按键排序后序列化：partialFilterExpression 里的键序是写法差异，不该算漂移 */
const stableJson = (value) => {
  if (value === undefined) return 'null';
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']';
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const body = keys.map((k) => JSON.stringify(k) + ':' + stableJson(value[k])).join(',');
    return '{' + body + '}';
  }
  return JSON.stringify(value);
};

/**
 * 读取集合的全部索引；集合尚不存在（全新库首次 migrate）按"没有索引"处理。
 * 放过 NamespaceNotFound（codeName 或 code 26）与 code 48：宽口径 catch 会把鉴权失败/选主超时
 * 读成"没有索引" → 静默不补齐却打印成功，故只放行这两种可预期的"不存在"。
 */
const listIndexes = async (db, coll) => {
  try {
    return await db.collection(coll).indexes();
  } catch (err) {
    if (err?.codeName === 'NamespaceNotFound' || err?.code === 26 || err?.code === 48) return [];
    throw err;
  }
};

const getIndex = async (db, coll, name) =>
  (await listIndexes(db, coll)).find((i) => i.name === name) || null;

/** key 的签名：**顺序**是 key 的一部分（反序/漏 _id 与声明形态不是同一条索引） */
const keySig = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

const sameKey = (actual, expected) => !!actual && keySig(actual) === keySig(expected);

/**
 * collation 的**缺省值**。mongod 8.0.34 实测：声明过的 collation 在 indexes() 里被展开成全字段，
 * 未声明 collation 的索引则**没有** collation 字段。所以要拿声明的半截 collation 去比，
 * 必须先补默认值，否则 caseLevel 之类的漂移比不出来。
 */
const COLLATION_DEFAULTS = {
  locale: 'simple',
  caseLevel: false,
  caseFirst: 'off',
  strength: 3,
  numericOrdering: false,
  alternate: 'non-ignorable',
  maxVariable: 'punct',
  normalization: false,
  backwards: false,
};

/**
 * collation 归一化：补默认值，只留用户可设字段。
 * · `null` 表示**没有** collation —— 与「有 collation 但全用默认值」是两回事，不能混同。
 * · **不比 `version`**：它是服务端按 ICU 版本回填的（实测 '57.1'），用户设不了，
 *   换 mongod 版本就会变；拿它做判据等于把一次升级当成全线漂移。
 */
const collationSig = (collation) => {
  if (!collation) return null;
  const norm = {};
  for (const [field, fallback] of Object.entries(COLLATION_DEFAULTS)) {
    norm[field] = field in collation ? collation[field] : fallback;
  }
  return norm;
};

/** TTL 归一化：`null` 表示不是 TTL 索引 */
const ttlSig = (spec) =>
  typeof spec.expireAfterSeconds === 'number' ? spec.expireAfterSeconds : null;

/**
 * 索引 spec 的**完整签名** —— 幂等判据的唯一依据。
 * 组成：key 有序签名 + collation 全字段 + unique/sparse/hidden/expireAfterSeconds/
 * partialFilterExpression；声明里没有的选项一律按「不存在」(`false` / `null`) 处理。
 * 因此「实测多了 unique:true」「多了 sparse」「多了 partial」「多了 hidden」「多了任一
 * collation 字段」都算漂移。`background` 不进签名：8.0 起它只是建索引期的 no-op，不回读。
 */
const specSig = (spec) =>
  stableJson({
    key: keySig(spec.key),
    collation: collationSig(spec.collation),
    unique: !!spec.unique,
    sparse: !!spec.sparse,
    hidden: !!spec.hidden,
    expireAfterSeconds: ttlSig(spec),
    partialFilterExpression: spec.partialFilterExpression || null,
  });

/**
 * 异名索引是否与声明**冲突**（即 mongod 的 85 判据成立，必须删掉才能建出目标）。
 * 判据：mongod 的 85 只比 {key, unique, sparse, partialFilterExpression, collation}，
 * **hidden 与 name 都不进判据**。这四维全同则无论名字如何都抛 85（IndexOptionsConflict）⇒
 * 与声明冲突，删它是唯一出路。因此本函数**刻意不比 hidden**：hidden 的差异不构成并存理由，
 * 比较它反而会放过冲突。expireAfterSeconds 由调用处单独判定（删了会丢留存语义）。
 */
const isEquivalentTwin = (actual, declared) =>
  !!actual &&
  keySig(actual.key) === keySig(declared.key) &&
  stableJson(collationSig(actual.collation)) === stableJson(collationSig(declared.collation)) &&
  !!actual.unique === !!declared.unique &&
  !!actual.sparse === !!declared.sparse &&
  stableJson(actual.partialFilterExpression || null) ===
    stableJson(declared.partialFilterExpression || null);

/**
 * 按名删索引；不存在（含集合不存在）即静默跳过并返回 false，不让 down()/清理路径
 * 因"本来就没有"而中断。原子口径：直接 drop、靠捕获 IndexNotFound(27)/NamespaceNotFound(26)
 * 收敛，杜绝「先查后删」在并发 up() 下的 TOCTOU。
 */
const dropIndexIfExists = async (db, coll, name) => {
  try {
    await db.collection(coll).dropIndex(name);
    console.log(`${coll}.${name} 已删除`);
    return true;
  } catch (err) {
    if (err && (err.codeName === 'IndexNotFound' || err.code === 27 || err.code === 26)) {
      return false;
    }
    throw err;
  }
};

module.exports = {
  listIndexes,
  getIndex,
  keySig,
  sameKey,
  COLLATION_DEFAULTS,
  collationSig,
  stableJson,
  ttlSig,
  specSig,
  isEquivalentTwin,
  dropIndexIfExists,
};
