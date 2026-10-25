/**
 * 列表/统计查询的复合索引补齐与冗余单字段索引回收
 *
 * 迁移动机（每条都对应一个真实查询形状）：
 *   firedevices.status_1_deviceCode_1
 *     设备列表「状态等值 + deviceCode 升序」；单字段 deviceCode 索引在带 status 时
 *     仍要回表过滤大量非命中项。
 *   firedevices.nextCheckDate_1_installDate_1__id_1
 *     提醒扫描「未排期」档：nextCheckDate:null + installDate,_id 升序。原单字段
 *     nextCheckDate_1 只能定位 null 块，块内整档同值 ⇒ 阻塞排序。**替换**，旧索引删。
 *   inspections.assignedTo_1_planStartTime_-1__id_-1
 *     巡检列表数据范围/筛选按 assignedTo 等值 + planStartTime,_id 倒序。**替换**旧
 *     assignedTo_1（新索引最左前缀完全覆盖它）。
 *   inspections.createdBy_1_planStartTime_-1__id_-1
 *     self 数据范围是 assignedTo/createdBy 两臂 $or（constants/dataScopeFields），
 *     另一臂原先无索引；新增。
 *   firealarms.level_1_occurredAt_-1__id_-1
 *     报警列表等级筛选 + 时间倒序。**替换**旧 level_1。
 *   usersessions.status_1（仅删除）
 *     全仓 status 查询都同时带 userId 或 sid，单字段索引永远不是最优路径；
 *     模型已移除 index:true，存量索引在此回收（autoIndex 不会自动删除）。
 *
 * 为什么不能只改模型声明：autoIndex 只在索引缺失时创建，**从不删除**存量索引；
 * 而生产通常关闭 autoIndex，新增复合索引也不会自动出现。两侧必须同批次（见 README 规范）。
 *
 * 幂等：逐项先读现有索引，已一致则跳过；旧索引只在新索引确认存在后才删。
 * 低峰执行：inspections/firealarms 上的复合索引重建有可观 IO。
 *
 * 回滚（down）：删除本次新建的复合索引，并按旧形态建回被替换的单字段索引
 * （status_1 / nextCheckDate_1 / assignedTo_1 / level_1）。代码侧需一并向旧版本回滚，
 * 否则列表排序会退化成阻塞排序。
 */

// 集合名在本文件里是硬编码字符串（migrate-mongo 上下文不 require 模型）；
// 导出给对账用例，与 Model.collection.name 摆在一起比，改集合名才会报警。
const CREATE_ONLY = [
  { coll: 'firedevices', name: 'status_1_deviceCode_1', key: { status: 1, deviceCode: 1 } },
  {
    coll: 'inspections',
    name: 'createdBy_1_planStartTime_-1__id_-1',
    key: { createdBy: 1, planStartTime: -1, _id: -1 },
  },
];

const REPLACE_SINGLE = [
  {
    coll: 'firedevices',
    name: 'nextCheckDate_1_installDate_1__id_1',
    key: { nextCheckDate: 1, installDate: 1, _id: 1 },
    oldName: 'nextCheckDate_1',
    oldKey: { nextCheckDate: 1 },
  },
  {
    coll: 'inspections',
    name: 'assignedTo_1_planStartTime_-1__id_-1',
    key: { assignedTo: 1, planStartTime: -1, _id: -1 },
    oldName: 'assignedTo_1',
    oldKey: { assignedTo: 1 },
  },
  {
    coll: 'firealarms',
    name: 'level_1_occurredAt_-1__id_-1',
    key: { level: 1, occurredAt: -1, _id: -1 },
    oldName: 'level_1',
    oldKey: { level: 1 },
  },
];

// 仅回收：没有对应的新索引
const DROP_ONLY = [{ coll: 'usersessions', name: 'status_1', oldKey: { status: 1 } }];

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

const ensureIndex = async (db, { coll, name, key }, label) => {
  if (await getIndex(db, coll, name)) {
    console.log(`${coll}.${name} 已存在，跳过`);
    return;
  }
  await db.collection(coll).createIndex(key, { name, background: true });
  console.log(`${coll}.${name} 已创建${label ? `（${label}）` : ''}`);
};

const dropIndexIfExists = async (db, coll, name) => {
  if (!(await getIndex(db, coll, name))) return;
  await db.collection(coll).dropIndex(name);
  console.log(`${coll}.${name} 已删除`);
};

module.exports = {
  CREATE_ONLY,
  REPLACE_SINGLE,
  DROP_ONLY,

  async up(db) {
    for (const target of CREATE_ONLY) {
      await ensureIndex(db, target);
    }
    for (const { coll, name, key, oldName } of REPLACE_SINGLE) {
      await ensureIndex(db, { coll, name, key }, '替换旧单字段索引');
      // 旧索引只有在新索引确认在场后才删：删早了会出现"无可用索引"的空窗
      await dropIndexIfExists(db, coll, oldName);
    }
    for (const { coll, name } of DROP_ONLY) {
      await dropIndexIfExists(db, coll, name);
    }
  },

  async down(db) {
    for (const { coll, name, oldKey } of DROP_ONLY) {
      if (!(await getIndex(db, coll, name))) {
        await db.collection(coll).createIndex(oldKey, { name, background: true });
        console.log(`${coll}.${name} 已按旧形态建回`);
      }
    }
    for (const { coll, name, oldName, oldKey } of REPLACE_SINGLE) {
      if (!(await getIndex(db, coll, oldName))) {
        await db.collection(coll).createIndex(oldKey, { name: oldName, background: true });
        console.log(`${coll}.${oldName} 已按旧形态建回`);
      }
      await dropIndexIfExists(db, coll, name);
    }
    for (const { coll, name } of CREATE_ONLY) {
      await dropIndexIfExists(db, coll, name);
    }
  },
};
