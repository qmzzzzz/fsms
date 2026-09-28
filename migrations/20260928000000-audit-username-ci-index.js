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
 * 幂等：先读现有索引。已存在且 collation 一致 ⇒ 跳过；存在但 collation 不一致 ⇒ 删除重建
 * （否则查询侧带 collation 会命中不了它，表现为"索引明明在、却仍走 COLLSCAN"）。
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
 * 读取指定索引；集合尚不存在（全新库首次 migrate）按"不存在"处理。
 * 只放过 NamespaceNotFound：宽口径 catch 会把鉴权失败/选主超时读成"没有索引"
 * → 静默不补齐却打印成功（同 20260831000000 的处置）。
 */
const getIndex = async (db, name) => {
  let list;
  try {
    list = await db.collection(COLLECTION).indexes();
  } catch (err) {
    if (err?.codeName === 'NamespaceNotFound' || err?.code === 26 || err?.code === 48) return null;
    throw err;
  }
  return list.find((i) => i.name === name) || null;
};

const sameCollation = (actual) =>
  !!actual && actual.locale === COLLATION.locale && actual.strength === COLLATION.strength;

module.exports = {
  COLLATION,
  INDEX_NAME,
  COLLECTION,
  KEY,

  async up(db) {
    const existing = await getIndex(db, INDEX_NAME);
    if (existing) {
      if (sameCollation(existing.collation)) {
        console.log(`${INDEX_NAME} 已存在且 collation 一致，跳过`);
        return;
      }
      await db.collection(COLLECTION).dropIndex(INDEX_NAME);
      console.log(`${INDEX_NAME} collation 不一致，已删除待重建`);
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
