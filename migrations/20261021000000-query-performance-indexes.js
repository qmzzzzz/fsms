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
 * 幂等：逐项先读现有索引，按**完整 spec 签名**比对（见 specSig）。签名一致 ⇒ 跳过；
 *   名字对、spec 漂移 ⇒ 删重建（不能只按名字或 key 判：REPLACE_SINGLE 紧接着会删旧索引，
 *   放过漂移的新索引就等于既没可用索引、又丢了旧索引）；目标 key 已被别的名字占用 ⇒ 只删
 *   「85 判据成立」的那条（key + unique/sparse/partialFilterExpression/collation 全同，hidden 与
 *   name 不进判据）再按声明名重建（mongod 对同 key 第二条
 *   索引抛 85 IndexOptionsConflict）；语义有差异的异名索引与目标合法并存，不删。
 *   旧索引只在新索引确认存在后才删。
 *   签名 = key（有序）+ collation（全字段）+ unique/sparse/hidden/expireAfterSeconds/
 *   partialFilterExpression，声明里没有的选项按「不存在」处理：本迁移所有目标都只声明了
 *   key，所以实测多出 unique:true / sparse / partialFilterExpression / hidden / 任一 collation
 *   都算漂移（2026-10-31 审计在 8.0.34 上把这 8 种可构造漂移逐条实测过，旧判据全部放过）。
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

const ensureIndex = async (db, { coll, name, key }, label) => {
  const all = await listIndexes(db, coll);
  const named = all.find((i) => i.name === name) || null;
  // 本迁移只声明 key，不声明任何其它选项 ⇒ 其它选项出现即漂移
  const DECLARED = { key };

  // 幂等的判据是「名字 + **整 spec** 都对」，不是「名字在」、也不是「key 对」：名字与 key
  // 都对、只多了 unique:true 时，旧判据会放过它 ⇒ 之后插重复键抛 E11000（凭空多出约束）；
  // collation/partial/hidden 漂移则让查询命不中它 ⇒ COLLSCAN。而 REPLACE_SINGLE 紧接着会
  // 删掉旧单字段索引 ⇒ 放过漂移就是既没可用索引、又丢了旧索引。
  if (named && specSig(named) === specSig(DECLARED)) {
    // **此处刻意不清洗异名 twin**：同 key 的第二条索引只要在 {unique, sparse,
    // partialFilterExpression, collation} 任一维上有差异，就与目标**合法并存**（8.0.34 实测
    // 不抛 85），删它反而静默改掉语义（唯一约束/留存/覆盖集/大小写敏感性）。是否收敛是业务
    // 决定，迁移不替使用者决定；冗余靠日志可见即可。
    console.log(`${coll}.${name} 已存在且完整 spec 与声明一致，跳过`);
    return;
  }
  if (named) {
    await db.collection(coll).dropIndex(name);
    console.log(`${coll}.${name} 形态漂移（完整 spec 与声明不一致），已删除待重建`);
  }
  // 异名 twin：**只删**「85 判据成立（key + unique/sparse/partialFilterExpression/collation
  // 四维全同，hidden 与 name 不进判据）」的那条——不删则 createIndex 必抛 85
  // IndexOptionsConflict，而它与目标本就是同一条索引，删掉无副作用。
  // **删 hidden 等价 twin 会丢掉「它曾是隐藏索引」这个事实**（hidden 不进 85 判据，故它照样
  // 冲突、照样必须删），down() 只按名删、恢复不了它 ⇒ 下面那条删除日志里的 specSig 是唯一
  // 证据，必须打全（含 hidden 位）。
  // 语义有差异的 twin（unique/sparse/partialFilterExpression/另一种 collation）**保留**并
  // 打印完整 spec：删除会静默改掉唯一性/覆盖集/大小写敏感性，该由人判（fail-open 记录）。
  // 登记：expireAfterSeconds 差异实测也会抛 85，但「删了丢留存」与「不删则 migrate 中断」
  // 不可兼得，故走保守侧（不删）；本迁移目标是复合 key，TTL 建不上
  // （实测 code 67 CannotCreateIndex），该分支不可达。
  for (const twin of all.filter((i) => i.name !== name && sameKey(i.key, key))) {
    if (isEquivalentTwin(twin, DECLARED) && ttlSig(twin) === ttlSig(DECLARED)) {
      await db.collection(coll).dropIndex(twin.name);
      // 删除不可逆（down() 只按名删、恢复不了 twin）⇒ 日志是唯一证据，必须打全 spec
      console.log(
        `${coll}.${twin.name} 与声明在 85 判据上等价（key/unique/sparse/partial/collation 全同，` +
          `hidden 不参与），已删除待按 ${name} 重建：` +
          specSig(twin)
      );
    } else {
      console.log(
        `${coll}.${twin.name} 与目标同 key 但 spec 有差异，未删除，需人工确认：` + specSig(twin)
      );
    }
  }
  await db.collection(coll).createIndex(key, { name, background: true });
  console.log(`${coll}.${name} 已创建${label ? `（${label}）` : ''}`);
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
