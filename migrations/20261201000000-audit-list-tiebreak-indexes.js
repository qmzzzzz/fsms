/**
 * 审计列表「等值筛选 + 时间倒序」复合索引补平局键 `_id:-1`（第十一轮 F2）
 *
 * 迁移动机（每条都对应一个真实查询形状）：
 *   auditlogs.{userId,category,action,riskLevel,success,ip}_1_timestamp_-1__id_-1
 *     utils/auditQuery.js assembleQuery 的六个筛选维度（userId/action/category/ip/riskLevel/success）；
 *     调用点是 services/auditQueryService.js 的 fetchAuditCursorPage / fetchAuditOffsetPage，
 *     两者都按 `{timestamp:-1,_id:-1}` 排序（游标续页的平局裁决，见 ADR-006）。
 *   auditlogs.category_1_action_1_timestamp_-1__id_-1
 *     审计页「分类 + 操作类型」联合筛选（同文件 assembleQuery 的 category+action 组合）。
 *
 * 为什么必须补：旧二键形态的键序（filter,timestamp）与排序键序（timestamp,_id）**不同向**，
 * 索引只能供 filter 这一段，时间与 _id 两段仍要阻塞排序 ⇒ 优化器干脆不用它。
 * N=2000 实测（work/_harness/_r12-probe-f2final.js，同一集合同一数据，只换索引族）：
 *   无 limit（等值块整块读，最能看清代价） category 筛选：
 *     二键: FETCH filter > IXSCAN(timestamp_-1__id_-1)             keys=2000 n=667
 *     三键: FETCH        > IXSCAN(category_1_timestamp_-1__id_-1)  keys=667  n=667
 *   有 limit 20（生产列表形态）：二键下 category/riskLevel/success 走 timestamp_-1__id_-1（按时间
 *     扫、边扫边过滤，命中密度低时白扫），category+action/action/ip/userId 走各自二键索引但带
 *     阻塞 SORT 阶段；三键下七条全部命中各自的 __id_-1 索引，SORT 全部消失。
 *   反证：把排序里的 _id 去掉 ⇒ 二键索引立刻被选中（同一数据、同一 filter），说明症结是
 *     排序键序而不是「索引不存在」。
 *
 * 写侧成本（同批 20000 条 × 3 轮，四轮重复，work/_harness/_r12-probe-f2e.js）：索引总体积
 * 二键 2844~3144KB → 三键 5684~5880KB（+2640~2892KB / +87%~+102%，摊到每条文档 +45~49B）；
 * 插入耗时抖动大（中位数 +2%~+31%，同机同数据重复四轮），不作为结论，只把体积当确定成本。
 * 取舍：筛选查询的代价随留存期线性增长，写放大是每条文档的常数。
 *
 * 为什么必须**替换**旧形态：模型侧改成三键后，旧二键索引（`category_1_timestamp_-1` 等）
 * 就不再被 schema 声明，而 autoIndex 只创建、从不删除 ⇒ 它会永久留在库里变成纯写放大。
 * `scripts/sync-audit-indexes.js` 能报/删 auditlogs 的冗余索引，但它是一次性运维脚本、不在
 * 部署序列里 ⇒ **迁移是旧二键的确定性回收路径**。新旧 key 形态不同、名字也不同，
 * 故按 create-new-then-drop-old 顺序做：任何时刻至少有一条可用。
 *
 * 幂等：先读新索引，按**完整 spec 签名**比对（见 specSig）。签名一致 ⇒ 跳过；
 *   名字对、spec 漂移 ⇒ 删重建；目标 key 已被别的名字占用 ⇒ 只删「85 判据成立」的那条
 *   （key + unique/sparse/partialFilterExpression/collation 全同，hidden 与 name 不进判据）
 *   再按声明名重建（mongod 对同 key 第二条索引抛 85 IndexOptionsConflict，不收敛会中断整次
 *   migrate）；语义有差异的异名索引与目标合法并存，不删（见 up() 里的说明）。
 *   旧索引只在新索引确认在场后才删。可重复执行。
 *   签名 = key（有序）+ collation（全字段）+ unique/sparse/hidden/expireAfterSeconds/
 *   partialFilterExpression，声明里没有的选项按「不存在」处理：本迁移七条目标都只声明了 key，
 *   所以实测多出 unique:true / sparse / partialFilterExpression / hidden / 任一 collation 都算漂移。
 * 低峰执行：auditlogs 是最大集合，索引重建有可观 IO。
 *
 * 回滚（down）：先把被替换的二键索引按旧形态建回，再删三键索引（实现顺序如此，见 down()）。
 * 代码侧必须同批回滚，否则列表筛选退回「扫满时间窗 + 阻塞排序」。
 */

// 集合名/索引名在迁移里是硬编码字符串（migrate-mongo 上下文不 require 模型）；
// 导出给对账用例，与 Model.collection.name 和 schema 的 key 摆在一起比，改名字才会报警。
const REPLACE = [
  { field: 'userId' },
  { field: 'category' },
  { field: 'action' },
  { field: 'riskLevel' },
  { field: 'success' },
  { field: 'ip' },
  { field: 'category+action' },
].map((entry) => {
  const coll = 'auditlogs';
  const keys =
    entry.field === 'category+action' ? { category: 1, action: 1 } : { [entry.field]: 1 };
  const tail = { timestamp: -1, _id: -1 };
  const oldTail = { timestamp: -1 };
  const key = { ...keys, ...tail };
  const oldKey = { ...keys, ...oldTail };
  const name = mongodName(key);
  const oldName = mongodName(oldKey);
  return { coll, field: entry.field, key, oldKey, name, oldName };
});

/** mongod 的自动命名规则：逐字段 `名_方向` 再用 `_` 连接（_id 因此写成 `__id_-1`） */
function mongodName(key) {
  return Object.keys(key)
    .map((k) => k + '_' + key[k])
    .join('_');
}

/**
 * 读取集合的全部索引；集合尚不存在（全新库首次 migrate）按"没有索引"处理。
 * 放过 NamespaceNotFound（codeName 或 code 26）与 code 48（NamespaceExists）：宽口径 catch 会把
 * 鉴权失败/选主超时读成"没有索引" → 静默不补齐却打印成功（同 20260831000000 / 20261101000000 的处置）。
 */
const listIndexes = async (db, coll) => {
  try {
    return await db.collection(coll).indexes();
  } catch (err) {
    if (err && (err.codeName === 'NamespaceNotFound' || err.code === 26 || err.code === 48))
      return [];
    throw err;
  }
};

const getIndex = async (db, coll, name) =>
  (await listIndexes(db, coll)).find((i) => i.name === name) || null;

/** key 的签名：**顺序**是 key 的一部分（反序/漏 _id 与声明的三键形态不是同一条索引） */
const keySig = (key) =>
  Object.keys(key)
    .map((k) => k + ':' + key[k])
    .join('|');

const sameKey = (actualKey, expectedKey) =>
  !!actualKey && keySig(actualKey) === keySig(expectedKey);

/**
 * collation 的**缺省值**。mongod 8.0.34 实测：声明过的 collation 在 indexes() 里被展开成全字段，
 * 未声明 collation 的索引则**没有** collation 字段。所以要拿声明的半截 collation 去比，必须先补默认值。
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
 * · null 表示**没有** collation —— 与「有 collation 但全用默认值」是两回事，不能混同。
 * · **不比 version**：它是服务端按 ICU 版本回填的，换 mongod 版本就会变。
 */
const collationSig = (collation) => {
  if (!collation) return null;
  const norm = {};
  for (const field of Object.keys(COLLATION_DEFAULTS)) {
    norm[field] = field in collation ? collation[field] : COLLATION_DEFAULTS[field];
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

/** TTL 归一化：null 表示不是 TTL 索引 */
const ttlSig = (spec) =>
  typeof spec.expireAfterSeconds === 'number' ? spec.expireAfterSeconds : null;

/**
 * 索引 spec 的**完整签名** —— 幂等判据的唯一依据。
 * 组成：key 有序签名 + collation 全字段 + unique/sparse/hidden/expireAfterSeconds/
 * partialFilterExpression；声明里没有的选项一律按「不存在」(false / null) 处理。
 * 因此「实测多了 unique:true」「多了 sparse」「多了 partial」「多了 hidden」「多了任一
 * collation 字段」都算漂移。background 不进签名：8.0 起它只是建索引期的 no-op，不回读。
 *
 * 判据覆盖但**不可构造**（写成注释而非用例，避免造出 mongod 直接拒的形态）：
 *   · 复合 key + expireAfterSeconds ⇒ 8.0.34 实测 code 67 CannotCreateIndex
 *     （"TTL indexes are single-field indexes"）；本迁移七条目标全是复合 key，该漂移不可达；
 *   · collation.caseFirst:'upper' 在 strength<=2 下建不出来（code 2 BadValue，实测），
 *     strength:3 才可构造，构造后会被 specSig 判为漂移并重建。
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
 * **hidden 与 name 都不进判据**；这四维全同则无论名字如何都抛 85。
 * 因此本函数**刻意不比 hidden**：hidden 的差异不构成并存理由，比较它反而会放过冲突。
 * expireAfterSeconds 由调用处单独判定（它同样会抛 85，但删了会丢留存语义）。
 */
const isEquivalentTwin = (actual, declared) =>
  !!actual &&
  keySig(actual.key) === keySig(declared.key) &&
  stableJson(collationSig(actual.collation)) === stableJson(collationSig(declared.collation)) &&
  !!actual.unique === !!declared.unique &&
  !!actual.sparse === !!declared.sparse &&
  stableJson(actual.partialFilterExpression || null) ===
    stableJson(declared.partialFilterExpression || null);

module.exports = {
  REPLACE,

  async up(db) {
    for (const { coll, name, key, oldName } of REPLACE) {
      const collection = db.collection(coll);
      const all = await listIndexes(db, coll);
      const named = all.find((i) => i.name === name) || null;
      // 本迁移只声明 key，不声明任何其它选项 ⇒ 其它选项出现即漂移
      const DECLARED = { key };

      if (named && specSig(named) === specSig(DECLARED)) {
        console.log(coll + '.' + name + ' 已存在且完整 spec 与声明一致，跳过');
      } else {
        if (named) {
          await collection.dropIndex(name);
          console.log(coll + '.' + name + ' 形态漂移（完整 spec 与声明不一致），已删除待重建');
        }
        // 异名 twin：**只删**「85 判据成立」的那条——不删则 createIndex 必抛 85 IndexOptionsConflict。
        // 语义有差异的 twin（unique/sparse/partialFilterExpression/另一种 collation）**保留**并打印
        // 完整 spec：删除会静默改掉唯一性/覆盖集/大小写敏感性，该由人判（fail-open 记录）。
        for (const twin of all.filter((i) => i.name !== name && sameKey(i.key, key))) {
          if (isEquivalentTwin(twin, DECLARED) && ttlSig(twin) === ttlSig(DECLARED)) {
            await collection.dropIndex(twin.name);
            console.log(
              coll +
                '.' +
                twin.name +
                ' 与声明在 85 判据上等价（key/unique/sparse/partial/collation 全同，' +
                'hidden 不参与），已删除待按声明名重建：' +
                specSig(twin)
            );
          } else {
            console.log(
              coll +
                '.' +
                twin.name +
                ' 与目标同 key 但 spec 有差异，未删除，需人工确认：' +
                specSig(twin)
            );
          }
        }
        await collection.createIndex(key, { name, background: true });
        console.log(coll + '.' + name + ' 已创建（替换 ' + oldName + '）');
      }
      // 旧索引只有在新索引确认在场后才删：删早了等值块内就又只剩阻塞排序
      await dropIndexIfExists(db, coll, oldName);
    }
  },

  async down(db) {
    for (const { coll, name, oldName, oldKey } of REPLACE) {
      if (!(await getIndex(db, coll, oldName))) {
        await db.collection(coll).createIndex(oldKey, { name: oldName, background: true });
        console.log(coll + '.' + oldName + ' 已按旧形态建回');
      }
      await dropIndexIfExists(db, coll, name);
    }
  },
};

/** 按名删；不存在（含集合不存在）即跳过，不让 down()/清理路径因"本来就没有"而中断 */
async function dropIndexIfExists(db, coll, name) {
  try {
    await db.collection(coll).dropIndex(name);
    console.log(coll + '.' + name + ' 已删除');
  } catch (err) {
    if (err && (err.codeName === 'IndexNotFound' || err.code === 27 || err.code === 26)) return;
    throw err;
  }
}
