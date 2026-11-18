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
        await collection.createIndex(key, { name });
        console.log(coll + '.' + name + ' 已创建（替换 ' + oldName + '）');
      }
      // 旧索引只有在新索引确认在场后才删：删早了等值块内就又只剩阻塞排序
      await dropIndexIfExists(db, coll, oldName);
    }
  },

  async down(db) {
    for (const { coll, name, oldName, oldKey } of REPLACE) {
      if (!(await getIndex(db, coll, oldName))) {
        await db.collection(coll).createIndex(oldKey, { name: oldName });
        console.log(coll + '.' + oldName + ' 已按旧形态建回');
      }
      await dropIndexIfExists(db, coll, name);
    }
  },
};
