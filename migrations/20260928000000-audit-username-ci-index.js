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

// 幂等判据收口到 _lib/indexSpec（P2-35）：specSig/collationSig/isEquivalentTwin 等曾在本文件与
// 其余 5 个迁移各抄一份且已漂移，现统一 require 共享模块，判据口径逐字段不变。
const {
  listIndexes,
  sameKey,
  ttlSig,
  specSig,
  isEquivalentTwin,
  dropIndexIfExists,
} = require('./_lib/indexSpec');

/** 本迁移声明的形态：up() 只建这一条，不带任何其它选项 */
const DECLARED = { key: KEY, collation: COLLATION };

module.exports = {
  COLLATION,
  INDEX_NAME,
  COLLECTION,
  KEY,

  async up(db) {
    const all = await listIndexes(db, COLLECTION);
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
    for (const twin of all.filter((i) => i.name !== INDEX_NAME && sameKey(i.key, KEY))) {
      if (isEquivalentTwin(twin, DECLARED) && ttlSig(twin) === ttlSig(DECLARED)) {
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
    await db.collection(COLLECTION).createIndex(KEY, { collation: COLLATION, name: INDEX_NAME });
    console.log(`${INDEX_NAME} 已创建（collation en/strength=2）`);
  },

  async down(db) {
    const dropped = await dropIndexIfExists(db, COLLECTION, INDEX_NAME);
    if (!dropped) console.log(`${INDEX_NAME} 不存在，跳过`);
  },
};
