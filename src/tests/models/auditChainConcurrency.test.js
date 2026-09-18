/**
 * 审计哈希链并发测试（第三批审计 #14 / M-3 修复验证）
 * 并发创建 40 条审计记录，验证：
 * - 无分叉：链上每个 hash 最多被一条记录作为 prevHash 引用
 * - 首条 prevHash 接续库中既有链尾（或为 null）
 * - 链从任一端可完整回溯（每个 prevHash 都能在集合 {记录hash} ∪ {既有链尾} 中找到）
 */

const mongoose = require('mongoose');
const { TEST_CLIENT_IP } = require('../fixtures');

describe('审计哈希链并发不分叉（M-3）', () => {
  let AuditLog;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
  });

  afterAll(async () => {
    // append-only 下无法删除；测试数据留库无副作用（审计日志本就只增）
    // T-1：关闭连接，避免遗留连接拖住 jest worker 优雅退出
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('40 条并发 create 形成单链无分叉', async () => {
    const N = 40;
    const prefix = 'chain_conc_' + Date.now();
    const docs = Array.from({ length: N }, (_, i) => ({
      action: `${prefix}_${i}`,
      category: 'auth',
      username: 'chain-test',
      ip: TEST_CLIENT_IP,
      path: '/test/chain',
      statusCode: 200,
      success: true,
    }));

    // 并发触发 pre-save 哈希计算（锁内串行，但 save 本身并发交错）
    await Promise.all(docs.map((d) => AuditLog.create(d)));

    // 取回本批记录并按链关系验证
    const created = await AuditLog.find({ action: { $regex: `^${prefix}_` } }).lean();
    expect(created.length).toBe(N);

    const hashSet = new Set(created.map((d) => d.hash).filter(Boolean));
    // 前置不变量：串链未整体失效。
    // 原用例把「无分叉」「完整性」都写成 `if (hashSet.has(...))` 式的条件断言：
    // 若 40 条记录的 hash 全为 null/缺失（pre-save 串链完全失效——正是本用例
    // 标题「并发不分叉」要防的最严重退化），两个循环一次都不执行、用例恒绿。
    // 这里先钉死「每条记录都有 hash」，让该退化必然转红。
    expect(hashSet.size).toBe(N);

    // 无分叉：每个 prevHash 至多被一条记录引用
    const prevCounts = new Map();
    for (const d of created) {
      if (!d.prevHash) continue;
      prevCounts.set(d.prevHash, (prevCounts.get(d.prevHash) || 0) + 1);
    }
    // 计数化前置：批内被引用的 prevHash 数量必须恰为 N-1（首条的 prevHash
    // 接续批前链尾或为 null，不在本批 hash 集内）。没有这条，「引用数不足」
    // （如全部 prevHash 为 null 的断链）不会触发任何断言。
    const internalRefs = created.filter((d) => d.prevHash && hashSet.has(d.prevHash)).length;
    expect(internalRefs).toBe(N - 1);
    expect(prevCounts.size).toBeGreaterThan(0);
    // 每个被引用的 prevHash 必须「恰好一次」——同一 prevHash 被两条记录引用即分叉。
    // 去条件化说明：原写法用 `if (hashSet.has(prev))` 守卫，理论上会跳过「批外值被
    // 重复引用」的形态；在 internalRefs===N-1 的前置下该形态不可达（仅一条记录指向
    // 批外），故本层与上方断言等价，保留为第二层防护——任何 prevHash 被引用两次，
    // 无论批内批外，均直接转红。
    for (const count of prevCounts.values()) {
      expect(count).toBe(1);
    }

    // 完整性（顺序无关）：除链首一条外，其余 prevHash 必须指向批内某条 hash。
    // 原先此循环被 `if (d.prevHash && d.prevHash !== earliest.prevHash)` 包裹——
    // 批内全为 null prevHash 时零执行、用例恒绿。现改为计数断言，不依赖 _id 顺序
    // （并发 create 下 _id 顺序不保证等于链推进顺序，原写法即使能红也是偶发）：
    //   - 指向批内的 prevHash 数必须恰为 N-1（internalRefs，上方已断言）；
    //   - 指向批外的 prevHash 只允许存在「一个」取值（批前链尾或 null）——
    //     出现两个以上不同批外值，说明链在批内断开成多条（分叉起点）。
    const externalPrevs = new Set(created.map((d) => d.prevHash).filter((p) => !hashSet.has(p)));
    expect(externalPrevs.size).toBe(1);

    // 哈希可复算：抽 3 条重算校验
    const { canonicalPayload, computeHash } = require('../../utils/auditChain');
    for (const d of created.slice(0, 3)) {
      expect(computeHash(d.prevHash || null, canonicalPayload(d))).toBe(d.hash);
    }
  });
});
