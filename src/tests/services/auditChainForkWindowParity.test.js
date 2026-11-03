/**
 * F-216 审计链分叉检出的**年龄无关性**门禁（免数据库，真跑出厂校验器）。
 *
 * 起因（实测，修复前口径）：`forgetOldest()` 只删 `firstChildOf`、不删 `seen`，
 * 于是两个"窗口"实际深度不同——`seen` 一路涨到整窗（maxRecords 条），
 * `firstChildOf` 只有 256 条。同父两子的分叉在父哈希落后 **≥ LINK_WINDOW_SIZE 条**时
 * 落在两者的年龄差里：成员测试仍然命中（无 chain_break）、同胞登记已被淘汰
 * （无 chain_fork），报告对一条**已经是 DAG** 的链写 `intact: true`。
 * 实测起点 depth=256 起全部沉默（255 及以内正常）。
 *
 * 分叉不是假想威胁：本仓自己的写入侧测试就在造它
 * （auditBufferZombieDuplicate.test.js:387「部分成功后下一批必须从 DB 重取链尾，
 * 不重同步就会与已落库那条同前驱分叉」），而链尾是 2 秒一批地往前推——
 * 一次僵尸推进留下的分叉，等到核验扫到它时早就过了 256 条。
 *
 * 本文件的取舍：① 只喂数据、只读报告，判据是出厂的 `verifyAuditChain`，不是任何正则；
 * ② 边界从出厂常量 `LINK_WINDOW_SIZE` 推导，不写死 256——将来调窗口大小不必改这里；
 * ③ 窗口**外**那条腿钉的是"回落成 chain_break"，不是"报成 chain_fork"：
 *   若有人为了让分叉永远报得出而把 `seen` 改成不淘汰（两侧一起涨到整窗），
 *   这条腿会红——那是用链接性检出的召回率去换 window 语义，属于口径变更，必须显式讨论。
 */
const mongoose = require('mongoose');
const {
  makeAuditLog,
  buildValidDoc,
  reParent,
  buildChain,
  toNewestFirst,
} = require('../helpers/auditChainFixtures');
const { verifyAuditChain, LINK_WINDOW_SIZE } = require('../../services/auditChainVerify');

/**
 * 在链尾追加一条"认领 depth 代之前的那个父哈希"的记录 ⇒ 同父两子。
 * @returns {{docs: Array, parent: Object, realChild: Object, fork: Object}}
 */
function forkShape(depth, count = 1) {
  const chain = buildChain(depth + 4);
  const parent = chain[chain.length - 1 - depth];
  const realChild = chain[chain.length - depth];
  const forks = [];
  for (let k = 0; k < count; k += 1) {
    const seeded = buildValidDoc(null, {
      action: `fork-${depth}-${k}`,
      _id: mongoose.Types.ObjectId.createFromTime(1800000000 + k),
    });
    forks.push(reParent(seeded, parent.hash));
  }
  return { docs: toNewestFirst([...chain, ...forks]), parent, realChild, forks };
}

describe('F-216 分叉检出与年龄差无关（seen 与 firstChildOf 同生同灭）', () => {
  test('① 任何年龄差的分叉都不得被报告成"链完整"', async () => {
    const depths = [
      1,
      LINK_WINDOW_SIZE - 1,
      LINK_WINDOW_SIZE,
      LINK_WINDOW_SIZE + 1,
      LINK_WINDOW_SIZE * 2,
    ];
    const silent = [];
    for (const depth of depths) {
      const { docs } = forkShape(depth);
      const report = await verifyAuditChain(makeAuditLog(docs), { maxRecords: docs.length });
      const signalled = report.byType.chain_fork + report.byType.chain_break;
      if (report.intact === true || signalled === 0) silent.push(depth);
    }
    // 诊断信息不能用 expect 的第二个参数承载：本仓跑的是 Jest，`expect(value, message)`
    // 是 Vitest 的形状，在 Jest 下直接抛 "Expect takes at most one argument." ——
    // 判据一次都没被执行过，红的理由与"分叉漏报"无关。改成断言前显式抛：
    // 红了照样给出年龄差与窗口值，绿了仍是一次真断言（空数组）。
    if (silent.length > 0) {
      throw new Error(
        `这些年龄差分叉两头都不报（intact=true）：${silent.join('/')}；窗口=${LINK_WINDOW_SIZE}`
      );
    }
    expect(silent).toEqual([]);
  });

  test('② 窗口内：报成 chain_fork，且同胞指认必须是链上那条真子', async () => {
    const { docs, realChild, forks } = forkShape(LINK_WINDOW_SIZE - 1);
    const report = await verifyAuditChain(makeAuditLog(docs), { maxRecords: docs.length });
    expect(report.byType.chain_fork).toBe(1);
    expect(report.byType.chain_break).toBe(0);
    expect(report.samples[0]).toMatchObject({ type: 'chain_fork', parentHash: forks[0].prevHash });
    expect(report.samples[0].forkedWithId).toBe(String(realChild._id));
  });

  test('③ 窗口外：必须回落成 chain_break（不得沉默，也不得改用无限窗口换检出）', async () => {
    const { docs } = forkShape(LINK_WINDOW_SIZE + 2);
    const report = await verifyAuditChain(makeAuditLog(docs), { maxRecords: docs.length });
    expect(report.byType.chain_fork).toBe(0);
    expect(report.byType.chain_break).toBeGreaterThanOrEqual(1);
    expect(report.intact).toBe(false);
  });

  test('④ 同一父哈希挂两条伪造：两条都要留下痕迹', async () => {
    const { docs } = forkShape(LINK_WINDOW_SIZE + 4, 2);
    const report = await verifyAuditChain(makeAuditLog(docs), { maxRecords: docs.length });
    expect(report.byType.chain_break).toBeGreaterThanOrEqual(2);
    expect(report.intact).toBe(false);
  });

  test('⑤ 精度地面：三种诚实形状仍判完整（淘汰不得把正常链挡在窗口外）', async () => {
    const linear = buildChain(LINK_WINDOW_SIZE * 2 + 10);
    const r1 = await verifyAuditChain(makeAuditLog(toNewestFirst(linear)), {
      maxRecords: linear.length,
    });
    expect([r1.intact, r1.breaks, r1.legacy]).toEqual([true, 0, 0]);

    const legacyPrefix = [
      ...[0, 1, 2].map((i) => ({
        _id: mongoose.Types.ObjectId.createFromTime(1600000000 + i),
        timestamp: new Date('2020-01-01T00:00:00.000Z'),
        action: `legacy-${i}`,
      })),
    ];
    const r2 = await verifyAuditChain(makeAuditLog([...toNewestFirst(linear), ...legacyPrefix]), {
      maxRecords: linear.length + 3,
    });
    expect([r2.intact, r2.breaks, r2.legacy]).toEqual([true, 0, 3]);

    const r3 = await verifyAuditChain(makeAuditLog(toNewestFirst(linear)), { maxRecords: 100 });
    expect([r3.intact, r3.breaks, r3.total]).toEqual([true, 0, 100]);
  });

  test('⑥ 夹具自证：读回集合里少一条就必须响（本文件的绿不是数据永远绿）', async () => {
    const linear = buildChain(LINK_WINDOW_SIZE * 2);
    const hole = [...linear];
    hole.splice(5, 1);
    const report = await verifyAuditChain(makeAuditLog(toNewestFirst(hole)), {
      maxRecords: hole.length,
    });
    expect(report.byType.chain_break).toBe(1);
    expect(report.intact).toBe(false);
  });
});

/**
 * 链尾同父分叉的免检盲区（免检分支改为「登记后返回」）。
 *
 * 免检的本义是「窗口头的双亲在窗外、无从对断」，但它原先连**同胞登记**一并跳过。
 * 由此的静默形态：窗口头恰是同父分叉的一腿，另一腿在窗内经 parentAhead 找到父后，
 * 会把自己登记成"唯一孩子"——两腿双双沉默，报告 intact:true。父若真在窗外，
 * 窗内任何记录都不可能在已扫侧/前瞻侧找到它，分叉判定根本不可达 ⇒ 能修的盲区
 * 正是"父在窗内、但其中一腿占了免检位"的形态，⑦ 钉的就是它。⑧ 钉零假阳：
 * 诚实链的窗口头（父被 maxRecords 截在窗外）登记认领后不得产出任何断裂。
 */
describe('免检分支不豁免同胞登记（窗口头是分叉腿的形态）', () => {
  test('⑦ 窗口头是分叉腿：较旧真子经 parentAhead 撞出 chain_fork，不得双静默', async () => {
    // 扫描序（_id 升序）：C2(T0) → C1(T1) → P(T2)。P 是链首（prevHash=null）；
    // C1 是真子；C2 是改挂到 P.hash 的分叉腿、却持有最小 _id ⇒ 占住窗口头免检位。
    // C1 找父：P 不在已扫侧（尚未扫到）、在前瞻侧（parentAhead）⇒ 通过断裂判定；
    // 修复前免检分支不登记 C2 的认领 ⇒ C1 自己登记成唯一孩子 ⇒ chain_fork=0 且 intact:true。
    const oid = (t) => mongoose.Types.ObjectId.createFromTime(t);
    const older = buildChain(2, 1699990000); // 更老的存量，被 maxRecords 截在窗外（窗口真切断）
    const parent = buildValidDoc(null, { action: 'exempt-p', _id: oid(1700000002) });
    const realChild = buildValidDoc(parent, { action: 'exempt-real', _id: oid(1700000001) });
    const forkLeg = reParent(
      buildValidDoc(null, { action: 'exempt-fork', _id: oid(1700000000) }),
      parent.hash
    );
    const docs = [...older, forkLeg, realChild, parent];
    const report = await verifyAuditChain(makeAuditLog(toNewestFirst(docs)), { maxRecords: 3 });
    // 前提自证：窗口确实从 C2 切起（老存量不在窗内）
    expect(report.total).toBe(3);
    expect(report.byType.chain_fork).toBeGreaterThanOrEqual(1);
    expect(report.intact).toBe(false);
    // 认领先登记者为准：先到窗口的免检腿 C2 被指认为被分叉方
    expect(report.samples[0]).toMatchObject({
      type: 'chain_fork',
      parentHash: parent.hash,
      forkedWithId: String(forkLeg._id),
    });
  });

  test('⑧ 零假阳：诚实链的窗口头（父被截在窗外）登记认领后仍判完整', async () => {
    // 真库常态：maxRecords 截断让窗口头的父落在窗外——免检豁免断裂判定，
    // 新增的登记只是把它的认领挂进 firstChildOf；诚实链上同一父哈希不会有第二个孩子，
    // 登记必须完全不可见（intact:true、chain_fork=0、chain_break=0）。
    const chain = buildChain(LINK_WINDOW_SIZE + 2);
    const report = await verifyAuditChain(makeAuditLog(toNewestFirst(chain)), {
      maxRecords: chain.length - 2,
    });
    expect(report.total).toBe(chain.length - 2); // 窗口确实截掉了头两条
    expect(report.intact).toBe(true);
    expect(report.byType.chain_fork).toBe(0);
    expect(report.byType.chain_break).toBe(0);
  });
});
