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
 * 大集合还会撞 32MB 内存排序上限，表现为列表接口 500）。
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
 * 幂等：逐项先读现有索引，已一致则跳过；旧索引只在复合索引确认存在后才删。
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

/**
 * 读取指定索引；集合尚不存在（全新库首次 migrate）按"不存在"处理。
 * 只放过 NamespaceNotFound：宽口径 catch 会把鉴权失败/选主超时读成"没有索引"
 * → 静默不补齐却打印成功（同 20260831000000 的处置）。
 */
const getIndex = async (db, coll, name) => {
  let list;
  try {
    list = await db.collection(coll).indexes();
  } catch (err) {
    if (err?.codeName === 'NamespaceNotFound' || err?.code === 26 || err?.code === 48) return null;
    throw err;
  }
  return list.find((i) => i.name === name) || null;
};

module.exports = {
  TARGETS,

  async up(db) {
    for (const { coll, field, replaceSingle } of TARGETS) {
      const collection = db.collection(coll);

      if (!(await getIndex(db, coll, compoundName(field)))) {
        await collection.createIndex({ [field]: -1, _id: -1 }, { background: true });
        console.log(`${coll}.${compoundName(field)} 已创建`);
      } else {
        console.log(`${coll}.${compoundName(field)} 已存在，跳过`);
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

      if (await getIndex(db, coll, compoundName(field))) {
        await collection.dropIndex(compoundName(field));
        console.log(`${coll}.${compoundName(field)} 已删除`);
      }
      if (replaceSingle && !(await getIndex(db, coll, singleName(field)))) {
        await collection.createIndex({ [field]: -1 }, { background: true });
        console.log(`${coll}.${singleName(field)} 已按旧形态建回`);
      }
    }
  },
};
