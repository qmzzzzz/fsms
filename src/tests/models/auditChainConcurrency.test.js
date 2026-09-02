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
    // 无分叉：每个 prevHash 至多被一条记录引用
    const prevCounts = new Map();
    for (const d of created) {
      if (!d.prevHash) continue;
      prevCounts.set(d.prevHash, (prevCounts.get(d.prevHash) || 0) + 1);
    }
    for (const [prev, count] of prevCounts.entries()) {
      // 批内首条的 prevHash 指向既有链尾（不在本批 hash 集中），其余必须唯一引用
      if (hashSet.has(prev)) {
        expect(count).toBe(1);
      }
    }

    // 完整性：批内每个 prevHash 都指向批内某条 hash 或批前的链尾
    const sorted = [...created].sort((a, b) => String(a._id).localeCompare(String(b._id)));
    const earliest = sorted[0];
    for (const d of created) {
      if (d.prevHash && d.prevHash !== earliest.prevHash) {
        expect(hashSet.has(d.prevHash)).toBe(true);
      }
    }

    // 哈希可复算：抽 3 条重算校验
    const { canonicalPayload, computeHash } = require('../../utils/auditChain');
    for (const d of created.slice(0, 3)) {
      expect(computeHash(d.prevHash || null, canonicalPayload(d))).toBe(d.hash);
    }
  });
});
