/**
 * 游标分页等值键的平局裁决：为三个按时间倒序的列表补同向复合索引
 *
 * 背景（缺陷不在索引，而在排序；本迁移是它的部署前置）：
 * 列表游标续翻的条件是 `(f < v) OR (f == v AND _id < id)`，即排序必须整体等价于
 * `{f:-1, _id:-1}`。而调用点此前只排主键 `{f:-1}`——单字段索引下的隐式平局序是
 * (key, RecordId **升序**)，与 `_id < id` 方向相反 ⇒ 同一取值（同一毫秒多条）跨页漂移：
 * 本机实测 5000 条 / 100 个取值 × 50 / 每页 20 ⇒ 重复 950、漏 3950（79% 永久不可达），
 * 且列表在这里假到底（hasMore:false，零日志）。
 *
 * 为什么必须先建索引再改排序：没有同向复合索引时，`.sort({f:-1,_id:-1})` 会把
 * "索引有序扫描 + limit 早停"打成 COLLSCAN + 阻塞排序（实测 examined 20 → 5000；
 * 大集合还会撞 100 MiB 内存排序上限，表现为列表接口 500）。
 *
 * 三条索引的取舍各不相同，逐条说明：
 *   firealarms.occurredAt_-1      → {occurredAt:-1,_id:-1}：**替换**（最左前缀覆盖旧键，
 *                                    旧单字段索引建完即删，不留写放大）
 *   inspections.planStartTime_-1  → {planStartTime:-1,_id:-1}：同上，替换
 *   auditlogs.timestamp_-1        → 额外新增 {timestamp:-1,_id:-1}：单字段那条**不能删**，
 *                                    它挂着 TTL，而 mongod 6.0.14 实测拒绝在复合索引上
 *                                    挂 expireAfterSeconds（`CannotCreateIndex: TTL indexes
 *                                    are single-field indexes`）⇒ 留存期与排序只能各占一条
 *
 * 设备列表（deviceCode 升序）不在本迁移内：其排序键 `unique:true`，等值不可能重复。
 *
 * 幂等：逐项先读现有索引，按**完整 spec 签名**比对（见 specSig）。签名一致 ⇒ 跳过；
 *   名字对、spec 漂移 ⇒ 删重建；目标 key 已被别的名字占用 ⇒ 只删「85 判据成立」的那条
 *   （key + unique/sparse/partialFilterExpression/collation 全同，hidden 与 name 不进判据）
 *   再按自动命名重建（mongod 对同 key 第二条索引抛 85
 *   IndexOptionsConflict，不收敛会中断整次 migrate）；语义有差异的异名索引与目标合法并存，
 *   不删（见 up() 里的说明）。旧单字段索引只在复合索引确认存在后才删。
 *   签名 = key（有序）+ collation（全字段）+ unique/sparse/hidden/expireAfterSeconds/
 *   partialFilterExpression，声明里没有的选项按「不存在」处理：本迁移三条目标都只声明了 key，
 *   所以实测多出 unique:true / sparse / partialFilterExpression / hidden / 任一 collation
 *   都算漂移（2026-10-31 审计在 8.0.34 上把这 8 种可构造漂移逐条实测过，旧判据全部放过）。
 * 索引重建在写密集的 auditlogs 上耗时可观 ⇒ 低峰执行（与 20260831000000 同一处置）。
 *
 * 回滚（down）：删除复合索引，并把被替换掉的两条单字段索引按旧形态建回。
 * 注意：回滚后调用点若仍带 `_id` 次级排序键，列表会退化成 COLLSCAN + 阻塞排序，
 * 必须与代码一并回滚。
 */

// 导出给对账用例：集合名在本文件里是硬编码字符串（migrate-mongo 上下文不 require 模型），
// 只有把它跟 Model.collection.name 摆在一起比，改集合名才会报警
const TARGETS = [
  { coll: 'firealarms', field: 'occurredAt', replaceSingle: true },
  { coll: 'inspections', field: 'planStartTime', replaceSingle: true },
  { coll: 'auditlogs', field: 'timestamp', replaceSingle: false },
];

const compoundName = (field) => `${field}_-1__id_-1`;
const singleName = (field) => `${field}_-1`;

// 幂等判据收口到 _lib/indexSpec（P2-35）：specSig/collationSig/isEquivalentTwin 等曾在本文件与
// 其余 5 个迁移各抄一份且已漂移，现统一 require 共享模块，判据口径逐字段不变。
const {
  listIndexes,
  getIndex,
  sameKey,
  ttlSig,
  specSig,
  isEquivalentTwin,
  dropIndexIfExists,
} = require('./_lib/indexSpec');

module.exports = {
  TARGETS,

  async up(db) {
    for (const { coll, field, replaceSingle } of TARGETS) {
      const collection = db.collection(coll);
      const KEY = { [field]: -1, _id: -1 };
      const all = await listIndexes(db, coll);
      const named = all.find((i) => i.name === compoundName(field)) || null;
      // 本迁移只声明 key，不声明任何其它选项 ⇒ 其它选项出现即漂移
      const DECLARED = { key: KEY };

      // 幂等的判据是「名字 + **整 spec** 都对」，不是「名字在」、也不是「key 对」：
      // 名字与 key 都对、只多了 unique:true 时，旧判据会放过它 ⇒ 之后插重复键抛 E11000，
      // 把声明为非唯一的索引变成过度约束；collation/partial/hidden 漂移则让查询命不中 ⇒ COLLSCAN。
      if (named && specSig(named) === specSig(DECLARED)) {
        // **此处刻意不清洗异名 twin**：同 key 的第二条索引只要在 {unique, sparse,
        // partialFilterExpression, collation} 任一维上有差异，就与目标**合法并存**（8.0.34 实测
        // 不抛 85），删它反而静默改掉语义（唯一约束/留存/覆盖集/大小写敏感性）。是否收敛是业务
        // 决定，迁移不替使用者决定；冗余靠日志可见即可。
        console.log(`${coll}.${compoundName(field)} 已存在且完整 spec 与声明一致，跳过`);
      } else {
        if (named) {
          await collection.dropIndex(compoundName(field));
          console.log(
            `${coll}.${compoundName(field)} 形态漂移（完整 spec 与声明不一致），已删除待重建`
          );
        }
        // 异名 twin：**只删**「85 判据成立（key + unique/sparse/partialFilterExpression/
        // collation 四维全同，hidden 与 name 不进判据）」的那条——不删则 createIndex 必抛 85
        // IndexOptionsConflict，而它与目标本就是同一条索引，删掉无副作用。
        // **删 hidden 等价 twin 会丢掉「它曾是隐藏索引」这个事实**（hidden 不进 85 判据，故它
        // 照样冲突、照样必须删），down() 只按名删、恢复不了它 ⇒ 下面那条删除日志里的
        // specSig 是唯一证据，必须打全（含 hidden 位）。
        // 语义有差异的 twin（unique/sparse/partialFilterExpression/另一种 collation）**保留**并
        // 打印完整 spec：删除会静默改掉唯一性/覆盖集/大小写敏感性，该由人判（fail-open 记录）。
        // 登记：expireAfterSeconds 差异实测也会抛 85，但「删了丢留存」与「不删则 migrate 中断」
        // 不可兼得，故走保守侧（不删）；本迁移目标全是复合 key，TTL 建不上
        // （实测 code 67 CannotCreateIndex），该分支不可达。
        for (const twin of all.filter(
          (i) => i.name !== compoundName(field) && sameKey(i.key, KEY)
        )) {
          if (isEquivalentTwin(twin, DECLARED) && ttlSig(twin) === ttlSig(DECLARED)) {
            await collection.dropIndex(twin.name);
            // 删除不可逆（down() 只按名删、恢复不了 twin）⇒ 日志是唯一证据，必须打全 spec
            console.log(
              `${coll}.${twin.name} 与声明在 85 判据上等价（key/unique/sparse/partial/collation 全同，` +
                `hidden 不参与），已删除待按自动名重建：` +
                specSig(twin)
            );
          } else {
            console.log(
              `${coll}.${twin.name} 与目标同 key 但 spec 有差异，未删除，需人工确认：` +
                specSig(twin)
            );
          }
        }
        await collection.createIndex(KEY, { background: true });
        console.log(`${coll}.${compoundName(field)} 已创建`);
      }

      // 旧单字段索引只有在复合索引确认在场后才删：删早了会出现"无时间序索引"的空窗
      if (replaceSingle && (await getIndex(db, coll, singleName(field)))) {
        await collection.dropIndex(singleName(field));
        console.log(`${coll}.${singleName(field)} 已被复合索引的最左前缀取代，删除`);
      }
    }
  },

  async down(db) {
    for (const { coll, field, replaceSingle } of TARGETS) {
      const collection = db.collection(coll);

      await dropIndexIfExists(db, coll, compoundName(field));
      if (replaceSingle && !(await getIndex(db, coll, singleName(field)))) {
        await collection.createIndex({ [field]: -1 }, { background: true });
        console.log(`${coll}.${singleName(field)} 已按旧形态建回`);
      }
    }
  },
};
