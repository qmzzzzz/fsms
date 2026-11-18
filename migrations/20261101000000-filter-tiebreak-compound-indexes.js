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
 * InspectionService.js:147,159）。旧形态只有两键：等值块内仍要阻塞排序（explain 实测 SORT
 * 整块拉进内存，docsExamined=等值块大小），大集合会撞内存排序上限——mongod 8.0.34 实测
 * `internalQueryMaxBlockingSortMemoryUsageBytes=104857600`（**100 MiB**）。隐式平局序是
 * (key, RecordId) 升序，**不是** `_id`；「跨页漏/重」只在排序**不带** `_id` 时成立，
 * 现行调用点都带 `_id:-1`，阻塞排序会把平局排正，不会漂移。
 * level 那条（20261021000000 建的 `level_1_occurredAt_-1__id_-1`）是原范式，本次把其余五条
 * 与 inspections 的 status 一条补齐到同一形状。
 *
 * 为什么必须**替换**旧形态：模型侧改成三键后，旧二键索引（`status_1_occurredAt_-1` 等）就不再
 * 被 schema 声明，而 autoIndex 只创建、从不删除 ⇒ 它会永久留在库里变成纯写放大。
 * `scripts/sync-audit-indexes.js` **只对账 auditlogs**（`scripts/sync-audit-indexes.js:4,249-252`），
 * firealarms/inspections 没有任何对账器会报/删这类冗余——**迁移是旧二键的唯一回收路径**。
 * 新旧 key 形态不同、名字也就不同，故按 create-new-then-drop-old 顺序做：任何时刻至少有一条可用。
 *
 * 幂等：先读新索引，按**完整 spec 签名**比对（见 specSig）。签名一致 ⇒ 跳过；
 *   名字对、spec 漂移 ⇒ 删重建；目标 key 已被别的名字占用 ⇒ 只删「85 判据成立」的那条
 *   （key + unique/sparse/partialFilterExpression/collation 全同，hidden 与 name 不进判据）
 *   再按声明名重建（mongod 对同 key 第二条索引抛 85
 *   IndexOptionsConflict，不收敛会中断整次 migrate）；语义有差异的异名索引与目标合法并存，
 *   不删（见 up() 里的说明）。旧索引只在新索引确认在场后才删。可重复执行。
 *   签名 = key（有序）+ collation（全字段）+ unique/sparse/hidden/expireAfterSeconds/
 *   partialFilterExpression，声明里没有的选项按「不存在」处理：本迁移六条目标都只声明了
 *   key，所以实测多出 unique:true / sparse / partialFilterExpression / hidden / 任一 collation
 *   都算漂移（2026-10-31 审计在 8.0.34 上把这 8 种可构造漂移逐条实测过，旧判据全部放过）。
 * 低峰执行：firealarms 上的索引重建有可观 IO。
 *
 * 回滚（down）：先把被替换的二键索引按旧形态建回，再删三键索引（实现顺序如此，见 down()）。
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

// 幂等判据收口到 _lib/indexSpec（P2-35）：specSig/collationSig/isEquivalentTwin/dropIndexIfExists
// 等曾在本文件与其余 5 个迁移各抄一份且已漂移（dropIndexIfExists 的「先查后删」有 TOCTOU），
// 现统一 require 共享模块（drop 后捕获 IndexNotFound 的原子口径），判据口径逐字段不变。
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
      // 本迁移只声明 key，不声明任何其它选项 ⇒ 其它选项出现即漂移
      const DECLARED = { key };

      // 幂等的判据是「名字 + **整 spec** 都对」，不是「名字在」、也不是「key 对」：名字与 key
      // 都对、只多了 unique:true 时旧判据会放过它 ⇒ 之后插重复键抛 E11000（凭空多出约束）；
      // collation/partial/hidden 漂移则让查询命不中它 ⇒ 等值块内仍阻塞排序，等于白迁。
      if (named && specSig(named) === specSig(DECLARED)) {
        // **此处刻意不清洗异名 twin**：同 key 的第二条索引只要在 {unique, sparse,
        // partialFilterExpression, collation} 任一维上有差异，就与目标**合法并存**（8.0.34 实测
        // 不抛 85），删它反而静默改掉语义（唯一约束/留存/覆盖集/大小写敏感性）。是否收敛是业务
        // 决定，迁移不替使用者决定；冗余靠日志可见即可。
        console.log(`${coll}.${name} 已存在且完整 spec 与声明一致，跳过`);
      } else {
        if (named) {
          await db.collection(coll).dropIndex(name);
          console.log(`${coll}.${name} 形态漂移（完整 spec 与声明不一致），已删除待重建`);
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
              `${coll}.${twin.name} 与目标同 key 但 spec 有差异，未删除，需人工确认：` +
                specSig(twin)
            );
          }
        }
        await db.collection(coll).createIndex(key, { name });
        console.log(`${coll}.${name} 已创建（替换 ${oldName}）`);
      }
      // 旧索引只有在新索引确认在场后才删：删早了等值块内就又只剩阻塞排序
      await dropIndexIfExists(db, coll, oldName);
    }
  },

  async down(db) {
    for (const { coll, name, oldName, oldKey } of REPLACE) {
      if (!(await getIndex(db, coll, oldName))) {
        await db.collection(coll).createIndex(oldKey, { name: oldName });
        console.log(`${coll}.${oldName} 已按旧形态建回`);
      }
      await dropIndexIfExists(db, coll, name);
    }
  },
};
