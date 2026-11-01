/* ===== 附录（2026-10-31 注释密度治理迁出）：src/utils/auditChainTail.js 的原委 =====
 * * 审计链尾的初始化口径（从 utils/auditChain.js 抽出）
 * *
 * * 为什么单独一个文件：auditChain.js 已顶 `max-lines` 棘轮阈值（300 逻辑行），
 * * 而「谁是链尾」这一段是**纯读侧判据**，不碰链尾指针、不碰分布式锁、不碰冻结状态机——
 * * 抽出来既不改变调用时序，也让这段判据能被单独钉住（见 compliance/auditChainTail*.test.js）。
 * *
 * * 判据与 _id 序**无关**：链尾的定义是「没有任何记录把它当作父」。
 * * 原实现取 sort({_id:-1}) 的第一条，其前提是「_id 序 == 追加序」——
 * * 而 auditBuffer 在 push 时就分配 _id（F-143 的跨重启幂等修复）之后，久候批次的 _id
 * * 会**早于**其间直写入库的记录，最大 _id 的那条可能落在链的中间；据此续链会把新记录
 * * 接到一个已有子记录的父哈希上 ⇒ 平分叉（与 D2 同根）。现在先在最近窗口里取候选，
 * * 再用带索引的 prevHash 反查「哪些候选已被认领」——这一步不受子记录 _id 先后的影响
 * * （$in 命中索引，与子记录排在第几无关）。
 * *
 * * 多实例场景下本函数**只**在共享链尾未初始化时被调用一次（且在分布式锁内），
 * * 链尾推进由 A-1 分布式锁保证串行，故不为此引入额外写放大。
 * 迁出理由：NEW_FILE_MAX=0.30 的密度上限；正文当前约束在源码一行内保留，完整权衡留在这里。
 */

/**
 * D2 的现场：链接性判据必须与 `_id` 顺序无关 —— 「子记录先于父被扫到」是**诚实**形态
 *
 * 背景（R11 探针 6 实测，见 work/_harness/r11/p6-chainorder.js）：F-143 之后
 * `auditBuffer.push` 在 push 时就分配 `_id`，而批次要等链锁才落库；这期间直写入库的
 * 记录 `_id` 更大、却先拿到链锁 ⇒ 批次首条的 prevHash 指向一个 `_id` **更大**的记录。
 * 旧判据只记住「扫描顺序里已经出现过的 hash」，于是把这种诚实形态判成 chain_break
 * ——红在诚实库上（假阳性），而假阳性会让人开始忽略 chain_break，真篡改反而被淹没。
 *
 * 被测点（src/services/auditChainVerify.js 的 checkLinkage）：父在不在 =
 * 「已扫侧最近 LINK_WINDOW_SIZE 条哈希」**或**「未扫侧位次 ≤ LINK_WINDOW_SIZE 的前瞻」，
 * 两侧都不以「谁先被扫到」为准；而**删除**（两侧都找不到父哈希）仍然 chain_break。
 * 所以本文件的腿必须成对，任何一侧失真都会红：
 *   · 诚实乱序（真库）⇒ breaks=0 —— 修之前这里红，这条就是先红证据；
 *   · 父真的不在（真删中间一条）⇒ 必须 chain_break —— 修法不是「让红消失」；
 *   · 同父两子 ⇒ chain_fork 保留，且**不因乱序而丢掉**这处分叉。
 *
 * 真库那两条要连 mongod：判据读的是 `.sort({_id:1}).limit().lean()` 的真实顺序，
 * 假夹具里 `_id` 顺序由构造者说了算，证明不了「这种乱序形状真的能落库」。
 * 免数据库那几条用 src/tests/helpers/auditChainFixtures（别在这里抄第 5 份夹具）。
 */

const mongoose = require('mongoose');
const AuditLog = require('../../models/AuditLog');
const { verifyAuditChain, LINK_WINDOW_SIZE } = require('../../services/auditChainVerify');
const F = require('../helpers/auditChainFixtures');

const TAG = 'r12d2';
const T = 1700000000;
const OID = (t) =>
  new mongoose.Types.ObjectId(mongoose.Types.ObjectId.createFromTime(t).toString());

/** 免数据库腿：把升序数组转成 "最新在前"（校验器内部会 reverse 回升序逐条推进） */
const verifyAsc = (asc) => verifyAuditChain(F.makeAuditLog(F.toNewestFirst(asc)));

describe('审计链链接性 × _id 乱序（D2）', () => {
  describe('真库：诚实乱序不得误报断裂，而删除仍必须被抓住', () => {
    beforeAll(async () => {
      mongoose.set('strictQuery', false);
      if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    });

    afterEach(async () => {
      await AuditLog.collection.deleteMany({ action: new RegExp(`^${TAG}-`) });
    });

    afterAll(async () => {
      await AuditLog.collection.deleteMany({ action: new RegExp(`^${TAG}-`) });
      if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
    });

    const report = () =>
      verifyAuditChain(AuditLog, {
        maxRecords: 100,
        fromLatest: true,
        filter: { action: new RegExp(`^${TAG}-`) },
      });

    test('诚实乱序（d0 → d1 → d2，d1 的 _id 最大）⇒ breaks=0，且不得报 chain_break', async () => {
      // 串链：d0 → d1 → d2。_id 升序：d0(T+300) → d2(T+310) → d1(T+320)
      // ⇒ 扫描序里 d2（子）先于 d1（父）被扫到，这正是批次等链锁造成的诚实形态。
      const d0 = F.buildValidDoc(null, { action: `${TAG}-d0`, _id: OID(T + 300) });
      const d1 = F.buildValidDoc(d0, { action: `${TAG}-d1`, _id: OID(T + 320) });
      const d2 = F.buildValidDoc(d1, { action: `${TAG}-d2`, _id: OID(T + 310) });
      await AuditLog.collection.insertMany([d0, d2, d1]);

      const r = await report();
      // 前提自证：这次落库确实是 _id 乱序（否则这条用例什么也没测）——
      // 扫描序（_id 升序）是 d0 → d2 → d1，而串链是 d0 → d1 → d2。
      const scanned = [d0, d2, d1].map((d) => String(d._id));
      expect(scanned).toEqual([...scanned].sort());
      expect(String(d1._id) > String(d2._id)).toBe(true);
      expect(d2.prevHash).toBe(d1.hash);
      expect(r.total).toBe(3);
      expect(r.byType.chain_break).toBe(0);
      expect(r).toMatchObject({ breaks: 0, legacy: 0, intact: true });
      expect(r.samples).toEqual([]);
      // chainTailHash 只是「扫描顺序里最后一条带哈希记录」的哈希，本层**不承诺**它是真链尾
      // （真链尾由 src/utils/auditChainTail.js 的 getLatestHash 取，见 D1）；这里钉住这个口径，
      // 免得有人拿它当链尾用。库里的真链尾在这里是 d2（_id 中间那条）。
      expect(r.chainTailHash).toBe(d1.hash);
    });

    test('反向：删掉中间那条 ⇒ 子记录的 prevHash 两侧都找不到 ⇒ chain_break', async () => {
      const e0 = F.buildValidDoc(null, { action: `${TAG}-e0`, _id: OID(T + 700) });
      const e1 = F.buildValidDoc(e0, { action: `${TAG}-e1`, _id: OID(T + 710) });
      const e2 = F.buildValidDoc(e1, { action: `${TAG}-e2`, _id: OID(T + 720) });
      await AuditLog.collection.insertMany([e0, e1, e2]);

      await AuditLog.collection.deleteMany({ _id: e1._id });

      const r = await report();
      expect(r.total).toBe(2);
      expect(r.byType.chain_break).toBe(1);
      expect(r).toMatchObject({ breaks: 1, intact: false });
      expect(r.samples[0]).toMatchObject({ type: 'chain_break', actualPrevHash: e1.hash });
    });
  });

  describe('免数据库：窗口两侧、分隔段与分叉', () => {
    test('正常顺序的同父两子 ⇒ 仍报 chain_fork（分叉检测不得被这轮改动削掉）', async () => {
      const parent = F.buildValidDoc(null, { action: `${TAG}-fp`, _id: OID(T + 500) });
      const real = F.buildValidDoc(parent, { action: `${TAG}-fre`, _id: OID(T + 510) });
      const twin = F.reParent(real, parent.hash, OID(T + 520));

      const r = await verifyAsc([parent, real, twin]);
      expect(r.byType.chain_fork).toBe(1);
      expect(r.byType.chain_break).toBe(0);
      expect(r.samples[0]).toMatchObject({
        type: 'chain_fork',
        parentHash: parent.hash,
        forkedWithId: String(real._id),
      });
      expect(r).toMatchObject({ breaks: 1, intact: false });
    });

    test('同父两子且孩子先于父被扫到 ⇒ 分叉不得因 _id 乱序而丢掉', async () => {
      // 扫描序（按 _id 升序）：G(590) → forged(600) → parent(620) → real(640)
      // forged 是被插入的伪造批次记录，perturbed 的正是"子先于父"；real 才是先落库的真孩子。
      const g = F.buildValidDoc(null, { action: `${TAG}-ifg`, _id: OID(T + 590) });
      const parent = F.buildValidDoc(g, { action: `${TAG}-ifp`, _id: OID(T + 620) });
      const real = F.buildValidDoc(parent, { action: `${TAG}-ifr`, _id: OID(T + 640) });
      const forged = F.reParent(real, parent.hash, OID(T + 600));

      const r = await verifyAsc([g, forged, parent, real]);
      expect(r.byType.chain_break).toBe(0);
      expect(r.byType.chain_fork).toBe(1);
      // 先被扫到的那个孩子登记为"已认领者"（认领先登记者为准，不按 _id 大小猜谁是真的）
      expect(r.samples[0]).toMatchObject({
        type: 'chain_fork',
        parentHash: parent.hash,
        forkedWithId: String(forged._id),
      });
      expect(r).toMatchObject({ breaks: 1, intact: false });
    });

    test('位次差超过 LINK_WINDOW_SIZE ⇒ 回落 chain_break（窗口上界不静默、也不假红）', async () => {
      const chain = F.buildChain(300);
      const far = F.buildValidDoc(chain[42], { action: `${TAG}-far`, _id: OID(T + 900) });
      // 前提自证：父在扫描序第 43 位、far 在第 301 位，位次差确实超出窗口
      expect(301 - 43).toBeGreaterThan(LINK_WINDOW_SIZE);

      const r = await verifyAsc([...chain, far]);
      expect(r.byType.chain_break).toBe(1);
      expect(r.byType.chain_fork).toBe(0);
      expect(r).toMatchObject({ breaks: 1, intact: false });
    });

    test('前瞻窗口中间隔着无哈希记录（分隔段边界）⇒ 那段链接一律不认', async () => {
      // 扫描序：x(400) → c(410) → h(420) → p(430)；串链 x → p、c 指向 p。
      // c 的父 p 在前瞻窗口里，但中间隔着被抹掉哈希的 h ⇒ 不得认这条链接（否则等于
      // 替 "$unset 灭迹" 收尾）；p 自身的父 x 也在 h 的重置之后 ⇒ 两处都 chain_break。
      const x = F.buildValidDoc(null, { action: `${TAG}-segx`, _id: OID(T + 400) });
      const p = F.buildValidDoc(x, { action: `${TAG}-segp`, _id: OID(T + 430) });
      const c = F.buildValidDoc(p, { action: `${TAG}-segc`, _id: OID(T + 410) });
      const h = F.buildValidDoc(null, { action: `${TAG}-segh`, _id: OID(T + 420) });
      delete h.hash;
      delete h.prevHash;
      delete h.hmac;

      const r = await verifyAsc([x, c, h, p]);
      expect(r.byType.chain_break).toBe(2);
      expect(r.byType.hash_stripped).toBe(1);
      expect(r.byType.chain_fork).toBe(0);
      expect(r).toMatchObject({ breaks: 3, legacy: 0, intact: false });
    });
  });
});
