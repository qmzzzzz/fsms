/**
 * 审计 username 前缀过滤的 collation 索引
 *
 * 背景：审计页「用户名」搜索此前是「不锚定 + `$options:'i'` 的 `$regex`」，任何索引都用不上
 * （MongoDB 的 `$regex` 实现不感知 collation，也无法利用大小写不敏感索引）。
 * 本机实测（6939 条真实数据）：子串 / 前缀锚定 / 带 `i` / 不带 `i` 四种形态
 * **连等值查询都是 COLLSCAN**——因为集合上根本没有 username 索引。
 * 代码侧已改为「前缀 + collation 范围查询」（见 `src/utils/auditQuery.js`），
 * 本迁移补上它依赖的那条索引。
 *
 * 为什么索引必须带 collation：带 collation 的索引**只能**被带同一 collation 的查询命中，
 * 反之亦然。而 collation 在这里同时是**正确性**开关——前缀范围 `[$gte, $lt)` 在默认
 * （二进制）collation 下 `ADMIN` 不落在 `[adm, adn)` 内 ⇒ 会漏掉大小写不同的记录
 * （本机实测存量确有 1 条 `ADMIN`，与 `admin` 并存）。
 *
 * 为何不替换任何既有索引：集合上本就没有 username 索引，这是**纯新增**，
 * 不涉及"替换旧单字段索引"那类取舍。
 *
 * 幂等：先读现有索引，按**完整 spec 签名**比对（见 specSig）。签名一致 ⇒ 跳过；否则删除重建。
 *   · 签名 = key（有序）+ collation（**全字段**）+ unique/sparse/hidden/expireAfterSeconds/
 *     partialFilterExpression；声明里没有的选项按「不存在」处理。
 *   · 只比 key 不比选项、或 collation 只比 locale/strength 都是错的（2026-10-31 审计实测，
 *     mongod 8.0.34）：同名同 key 下 unique:true / sparse / partialFilterExpression / hidden /
 *     collation.caseLevel / numericOrdering / alternate / backwards 这 8 种可构造漂移都会被
 *     「key 与 collation 一致，跳过」原样放过，后果从「查询退化为 COLLSCAN」到
 *     「凭空多出 E11000 唯一约束」。
 *   · 目标 key 已被**别的名字**的索引占用时，只删「85 判据成立」的那条再按声明名重建 ——
 *     mongod 的冲突判据只看 key + {unique, sparse,
 *     partialFilterExpression, collation}，不看名字（实测 85 IndexOptionsConflict 原文
 *     "Index already exists with a different name: username_1_timestamp_-1"）；语义有差异的
 *     异名索引与目标**合法并存**，不删（见 up() 里的说明）。
 *
 * 索引重建在写密集的 auditlogs 上耗时可观 ⇒ 低峰执行（与 20260831000000 同一处置）。
 *
 * 回滚（down）：删除该索引。注意回滚后若代码仍走「前缀 + collation 范围查询」，
 * 查询会退化为 COLLSCAN，且**不带 collation 时结果还会漏大小写变体**——必须与代码一并回滚。
 */

const COLLATION = { locale: 'en', strength: 2 };
const INDEX_NAME = 'username_ci_timestamp';
const KEY = { username: 1, timestamp: -1 };
const COLLECTION = 'auditlogs';

/**
 * 读取集合的全部索引；集合尚不存在（全新库首次 migrate）按"没有索引"处理。
 * 放过 NamespaceNotFound（codeName 或 code 26）与 code 48（NamespaceExists）：宽口径 catch 会把鉴权失败/选主超时读成"没有索引"
 * → 静默不补齐却打印成功（同 20260831000000 的处置）。
 */
const listIndexes = async (db) => {
  try {
    return await db.collection(COLLECTION).indexes();
  } catch (err) {
    if (err?.codeName === 'NamespaceNotFound' || err?.code === 26 || err?.code === 48) return [];
    throw err;
  }
};

const getIndex = async (db, name) => (await listIndexes(db)).find((i) => i.name === name) || null;

/** key 的签名：**顺序**是 key 的一部分（反序对「username 等值 + timestamp 排序」不可用） */
const keySig = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

const sameKey = (actual) => !!actual && keySig(actual) === keySig(KEY);

/**
 * collation 的**缺省值**。mongod 8.0.34 实测：声明过的 collation 在 indexes() 里被展开成全字段
 * （locale/caseLevel/caseFirst/strength/numericOrdering/alternate/maxVariable/normalization/
 * backwards/version），未声明 collation 的索引则**没有** collation 字段。所以拿声明的半截
 * collation（如 {locale,strength}）去比，必须先补默认值，否则 caseLevel 之类的漂移比不出来。
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
 * · `null` 表示**没有** collation —— 与「有 collation 但全用默认值」是两回事，不能混同
 *   （否则「声明要 collation、实际没建」这种最要命的漂移会被判成一致）。
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

/** TTL 归一化：`null` 表示不是 TTL 索引 */
const ttlSig = (spec) =>
  typeof spec.expireAfterSeconds === 'number' ? spec.expireAfterSeconds : null;

/**
 * 索引 spec 的**完整签名** —— 幂等判据的唯一依据。
 * 组成：key 有序签名 + collation 全字段 + unique/sparse/hidden/expireAfterSeconds/
 * partialFilterExpression；声明里没有的选项一律按「不存在」(`false` / `null`) 处理。
 * 因此「实测多了 unique:true」「多了 sparse」「多了 partial」「多了 hidden」「collation 多/少了
 * 某个字段」都会算漂移。`background` 不进签名：8.0 起它只是建索引期的 no-op，不会被回读。
 *
 * 判据覆盖但**不可构造**（写成注释而非用例，避免造出 mongod 直接拒的形态）：
 *   · 复合 key + expireAfterSeconds ⇒ 8.0.34 实测 code 67 CannotCreateIndex
 *     （"TTL indexes are single-field indexes, compound indexes do not support TTL"）；
 *     本迁移 KEY 是复合 key，故该漂移不可达（单字段目标才会遇到，见 20260926000000 的处置）；
 *   · collation.caseFirst:'upper' 在**本迁移声明的 collation 下**建不出来：8.0.34 实测
 *     `{locale:'en',strength:2,caseFirst:'upper'}` 抛 code 2 BadValue（"'caseFirst' is invalid
 *     unless 'caseLevel' is on or 'strength' is greater than 2"）⇒ 不可构造；判据仍覆盖它——
 *     把 strength 提到 3 就能构造，实测 `{locale:'en',strength:3,caseFirst:'upper'}` 建成后
 *     会被 specSig 判为漂移并重建（work 里 probe12c 的 S7 一格）。
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

/** 本迁移声明的形态：up() 只建这一条，不带任何其它选项 */
const DECLARED = { key: KEY, collation: COLLATION };

/**
 * 异名索引是否与声明**冲突**（即 mongod 的 85 判据成立，必须删掉才能建出目标）。
 * 判据：mongod 的 85 只比 {key, unique, sparse, partialFilterExpression, collation}，
 * **hidden 与 name 都不进判据**。实测（8.0.34）：两条同 key 索引并存合法，当且仅当它们在
 * 上述四维里**至少有一维不同**；这四维全同则无论名字如何都抛 85——`hidden:true` 的异名索引
 * 同样抛（原文 "An equivalent index already exists with a different name and options"）⇒
 * 与声明冲突，删它是唯一出路（不删则 createIndex 抛 85，整次 migrate 中断）。
 * 因此本函数**刻意不比 hidden**：hidden 的差异不构成并存理由，比较它反而会放过冲突。
 * expireAfterSeconds 由调用处单独判定（它同样会抛 85，但删了会丢留存语义，见 up() 的登记）。
 */
const isEquivalentTwin = (actual) =>
  !!actual &&
  keySig(actual.key) === keySig(DECLARED.key) &&
  stableJson(collationSig(actual.collation)) === stableJson(collationSig(DECLARED.collation)) &&
  !!actual.unique === !!DECLARED.unique &&
  !!actual.sparse === !!DECLARED.sparse &&
  stableJson(actual.partialFilterExpression || null) ===
    stableJson(DECLARED.partialFilterExpression || null);

module.exports = {
  COLLATION,
  INDEX_NAME,
  COLLECTION,
  KEY,

  async up(db) {
    const all = await listIndexes(db);
    const named = all.find((i) => i.name === INDEX_NAME) || null;
    if (named && specSig(named) === specSig(DECLARED)) {
      // 整 spec 一致 ⇒ 本迁移要的形态已在位，无需重建。
      // **此处刻意不清洗异名 twin**：同 key 的第二条索引只要在 {unique, sparse,
      // partialFilterExpression, collation} 任一维上有差异，就与目标**合法并存**（8.0.34 实测
      // 不抛 85），删它反而静默改掉语义（唯一约束/留存/覆盖集/大小写敏感性）。是否收敛是业务
      // 决定，迁移不替使用者决定；冗余靠日志可见即可。
      console.log(`${INDEX_NAME} 已存在且完整 spec 与声明一致，跳过`);
      return;
    }
    if (named) {
      await db.collection(COLLECTION).dropIndex(INDEX_NAME);
      console.log(`${INDEX_NAME} 形态漂移（完整 spec 与声明不一致），已删除待重建`);
    }
    // 异名 twin：**只删**「85 判据成立（key + unique/sparse/partialFilterExpression/collation
    // 四维全同，hidden 与 name 不进判据）」的那条——不删则 createIndex 必抛 85
    // IndexOptionsConflict，而它与目标本就是同一条索引，删掉没有副作用。
    // **删 hidden 等价 twin 会丢掉「它曾是隐藏索引」这个事实**（hidden 不进 85 判据，故它照样
    // 冲突、照样必须删），down() 只按名删、恢复不了它 ⇒ 下面那条删除日志里的 specSig 是唯一
    // 证据，必须打全（含 hidden 位）。
    // 语义有差异的 twin（unique/sparse/partialFilterExpression/另一种 collation）**保留**并
    // 打印完整 spec：删除会静默改掉唯一性/覆盖集/大小写敏感性，该由人判（fail-open 记录）。
    // 登记：expireAfterSeconds 差异实测也会抛 85，但「删了丢留存」与「不删则 migrate 中断」
    // 不可兼得，故走保守侧（不删）；本迁移目标是复合 key，TTL 建不上
    // （实测 code 67 CannotCreateIndex），该分支不可达。
    for (const twin of all.filter((i) => i.name !== INDEX_NAME && sameKey(i.key))) {
      if (isEquivalentTwin(twin) && ttlSig(twin) === ttlSig(DECLARED)) {
        await db.collection(COLLECTION).dropIndex(twin.name);
        // 删除不可逆（down() 只按名删、恢复不了 twin）⇒ 日志是唯一证据，必须打全 spec
        console.log(
          `${twin.name} 与声明在 85 判据上等价（key/unique/sparse/partial/collation 全同，hidden 不参与），` +
            `已删除待按 ${INDEX_NAME} 重建：` +
            specSig(twin)
        );
      } else {
        console.log(
          `${twin.name} 与目标同 key 但 spec 有差异，未删除，需人工确认：${specSig(twin)}`
        );
      }
    }
    await db
      .collection(COLLECTION)
      .createIndex(KEY, { collation: COLLATION, background: true, name: INDEX_NAME });
    console.log(`${INDEX_NAME} 已创建（collation en/strength=2）`);
  },

  async down(db) {
    if (await getIndex(db, INDEX_NAME)) {
      await db.collection(COLLECTION).dropIndex(INDEX_NAME);
      console.log(`${INDEX_NAME} 已删除`);
    } else {
      console.log(`${INDEX_NAME} 不存在，跳过`);
    }
  },
};
