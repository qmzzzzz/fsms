/**
 * 列表「等值筛选 + 时间倒序」复合索引补平局键 `_id:-1`（D6）
 *
 * 迁移动机（每条都对应一个真实查询形状）：
 *   firealarms.status_1_occurredAt_-1__id_-1 / alarmType_1_occurredAt_-1__id_-1
 *     AlarmService.getAlarms 的 status、alarmType 筛选（AlarmService.js:71,73）
 *   firealarms.handler_1_occurredAt_-1__id_-1 / reporter.userId_1_occurredAt_-1__id_-1
 *     数据范围的属主两臂（constants/dataScopeFields.js:33 ownerField 数组 ⇒ self 档是
 *     `$or:[{reporter.userId},{handler}]`），$or 的每个臂都要能自己供序，SORT_MERGE 才成立
 *   firealarms.location.building_1_occurredAt_-1__id_-1
 *     同文件的部门臂 departmentField（dataScopeFields.js:34）⇒ department 档就是 `location.building` 等值
 *   inspections.status_1_planStartTime_-1__id_-1
 *     InspectionService.getInspections 的 status 筛选（InspectionService.js:100）
 * 六个形状都按 `{occurredAt|planStartTime:-1,_id:-1}` 排序（AlarmService.js:120,133 /
 * InspectionService.js:147,159）。旧形态只有两键：等值块内仍要阻塞排序，而块内隐式序是
 * `_id` **升序**，与续翻子句 `{occurredAt:v,_id:{$lt:id}}` 反向 ⇒ 大集合撞 32MB 排序上限。
 * level 那条（20261021000000 建的 `level_1_occurredAt_-1__id_-1`）是原范式，本次把其余五条
 * 与 inspections 的 status 一条补齐到同一形状。
 *
 * 为什么必须**替换**旧形态：模型侧改成三键后，旧二键索引（`status_1_occurredAt_-1` 等）就不再
 * 被 schema 声明，而 autoIndex 只创建、从不删除 ⇒ 它会永久留在库里变成纯写放大
 * （`scripts/sync-audit-indexes.js` 也会把它当「模型未声明的冗余索引」报出来）。
 * 新旧 key 形态不同、名字也就不同，故按 create-new-then-drop-old 顺序做：任何时刻至少有一条可用。
 *
 * 幂等：先读新索引，已在则跳过创建；旧索引只在新索引确认在场后才删。可重复执行。
 * 低峰执行：firealarms 上的索引重建有可观 IO。
 *
 * 回滚（down）：删除本次建的三键索引，并按旧形态（二键、同名）建回被替换的那条。
 * 代码侧必须同批回滚，否则列表排序退化成阻塞排序。
 */

// 集合名/索引名在迁移里是硬编码字符串（migrate-mongo 上下文不 require 模型）；
// 导出给对账用例，与 Model.collection.name 和 schema 的 key 摆在一起比，改名字才会报警。
const REPLACE = [
  {
    coll: 'firealarms',
    name: 'status_1_occurredAt_-1__id_-1',
    key: { status: 1, occurredAt: -1, _id: -1 },
    oldName: 'status_1_occurredAt_-1',
    oldKey: { status: 1, occurredAt: -1 },
  },
  {
    coll: 'firealarms',
    name: 'handler_1_occurredAt_-1__id_-1',
    key: { handler: 1, occurredAt: -1, _id: -1 },
    oldName: 'handler_1_occurredAt_-1',
    oldKey: { handler: 1, occurredAt: -1 },
  },
  {
    coll: 'firealarms',
    name: 'reporter.userId_1_occurredAt_-1__id_-1',
    key: { 'reporter.userId': 1, occurredAt: -1, _id: -1 },
    oldName: 'reporter.userId_1_occurredAt_-1',
    oldKey: { 'reporter.userId': 1, occurredAt: -1 },
  },
  {
    coll: 'firealarms',
    name: 'location.building_1_occurredAt_-1__id_-1',
    key: { 'location.building': 1, occurredAt: -1, _id: -1 },
    oldName: 'location.building_1_occurredAt_-1',
    oldKey: { 'location.building': 1, occurredAt: -1 },
  },
  {
    coll: 'firealarms',
    name: 'alarmType_1_occurredAt_-1__id_-1',
    key: { alarmType: 1, occurredAt: -1, _id: -1 },
    oldName: 'alarmType_1_occurredAt_-1',
    oldKey: { alarmType: 1, occurredAt: -1 },
  },
  {
    coll: 'inspections',
    name: 'status_1_planStartTime_-1__id_-1',
    key: { status: 1, planStartTime: -1, _id: -1 },
    oldName: 'status_1_planStartTime_-1',
    oldKey: { status: 1, planStartTime: -1 },
  },
];

/**
 * 读取指定索引；集合尚不存在（全新库首次 migrate）按"不存在"处理。
 * 只放过 NamespaceNotFound：宽口径 catch 会把鉴权失败/选主超时读成"没有索引"
 * → 静默不补齐却打印成功（同 20260831000000 / 20261021000000 的处置）。
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

const dropIndexIfExists = async (db, coll, name) => {
  if (!(await getIndex(db, coll, name))) return;
  await db.collection(coll).dropIndex(name);
  console.log(`${coll}.${name} 已删除`);
};

module.exports = {
  REPLACE,

  async up(db) {
    for (const { coll, name, key, oldName } of REPLACE) {
      const existing = await getIndex(db, coll, name);
      if (existing) {
        console.log(`${coll}.${name} 已存在，跳过`);
      } else {
        await db.collection(coll).createIndex(key, { name, background: true });
        console.log(`${coll}.${name} 已创建（替换 ${oldName}）`);
      }
      // 旧索引只有在新索引确认在场后才删：删早了等值块内就又只剩阻塞排序
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
