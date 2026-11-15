/**
 * 提醒扫描「到期日升序」复合索引补平局键 `_id:1`（E5）
 *
 * 迁移动机（真实查询形状）：deviceReminder 的 expired / expiringSoon 两档按
 * `{expiryDate:1,_id:1}` 升序取页（services/deviceReminder.js 的 ALERT_BUCKETS）。
 * 到期日是**大量同值**的日期——批量采购的设备同批到期，单键索引 `{expiryDate:1}`
 * 只能定位日期块，块内仍是阻塞排序；且没有平局键时，同值页"同一次查询两次给出
 * 不同成员"（同 firealarms/inspections 的 D6 缺陷，20261101000000 是本条的原范式）。
 *
 * 为什么必须**替换**旧形态：模型侧改成两键后，旧单键索引（`expiryDate_1`）不再被
 * schema 声明，而 autoIndex 只创建、从不删除 ⇒ 永久留在库里变成纯写放大；
 * `scripts/sync-audit-indexes.js` 只对账 auditlogs，firedevices 没有对账器会报/删它
 * ⇒ 本迁移是旧单键的唯一回收路径。新旧 key 形态不同、名字也就不同，按
 * create-new-then-drop-old 顺序做：任何时刻至少有一条可用。
 *
 * 幂等/漂移/twin 判据与 20261101000000 同构（specSig = key 有序签名 + collation 全字段 +
 * unique/sparse/hidden/expireAfterSeconds/partialFilterExpression；本迁移只声明 key）。
 * needMaintenance 档的 {nextCheckDate:1,installDate:1,_id:1} 已由 2026-10 建的模型级
 * 复合索引覆盖，不在本迁移范围。低峰执行：firedevices 上的索引重建有可观 IO。
 *
 * 回滚（down）：先按旧形态建回 `expiryDate_1`，再删两键索引。代码侧必须同批回滚，
 * 否则提醒扫描排序退化成阻塞排序（功能不坏，但大集合上变慢）。
 */

// 集合名/索引名在迁移里是硬编码字符串（migrate-mongo 上下文不 require 模型）；
// 导出给对账用例，与 Model.collection.name 和 schema 的 key 摆在一起比，改名字才会报警。
const REPLACE = [
  {
    coll: 'firedevices',
    name: 'expiryDate_1__id_1',
    key: { expiryDate: 1, _id: 1 },
    oldName: 'expiryDate_1',
    oldKey: { expiryDate: 1 },
  },
];

// 幂等判据收口到 _lib/indexSpec（P2-35）：specSig/collationSig/isEquivalentTwin/dropIndexIfExists
// 等曾在本文件与其余 5 个迁移各抄一份且已漂移，现统一 require 共享模块，判据口径逐字段不变。
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
  REPLACE,

  async up(db) {
    for (const { coll, name, key, oldName } of REPLACE) {
      const all = await listIndexes(db, coll);
      const named = all.find((i) => i.name === name) || null;
      const DECLARED = { key }; // 本迁移只声明 key，其它选项出现即漂移

      if (named && specSig(named) === specSig(DECLARED)) {
        console.log(`${coll}.${name} 已存在且完整 spec 与声明一致，跳过`);
      } else {
        if (named) {
          await db.collection(coll).dropIndex(name);
          console.log(`${coll}.${name} 形态漂移（完整 spec 与声明不一致），已删除待重建`);
        }
        for (const twin of all.filter((i) => i.name !== name && sameKey(i.key, key))) {
          if (isEquivalentTwin(twin, DECLARED) && ttlSig(twin) === ttlSig(DECLARED)) {
            await db.collection(coll).dropIndex(twin.name);
            console.log(
              `${coll}.${twin.name} 与声明在 85 判据上等价（key/unique/sparse/partial/collation 全同），已删除待按 ${name} 重建：` +
                specSig(twin)
            );
          } else {
            console.log(
              `${coll}.${twin.name} 与目标同 key 但 spec 有差异，未删除，需人工确认：` +
                specSig(twin)
            );
          }
        }
        await db.collection(coll).createIndex(key, { name, background: true });
        console.log(`${coll}.${name} 已创建（替换 ${oldName}）`);
      }
      // 旧索引只有在新索引确认在场后才删：删早了日期块内就又只剩阻塞排序
      await dropIndexIfExists(db, coll, oldName);
    }
  },

  async down(db) {
    for (const { coll, name, oldName, oldKey } of REPLACE) {
      if (!(await getIndex(db, coll, oldName))) {
        await db.collection(coll).createIndex(oldKey, { name: oldName, background: true });
        console.log(`${coll}.${oldName} 已按旧形态建回`);
      }
      await dropIndexIfExists(db, coll, name);
    }
  },
};
