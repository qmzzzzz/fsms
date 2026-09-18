const AuditLog = require('../../models/AuditLog');
const mongoose = require('mongoose');
const { verifyAuditChain } = require('../../services/auditChainVerify');
const { CURRENT_PAYLOAD_VERSION } = require('../../utils/auditChain');

describe('审计链重签后的当前版本不变量', () => {
  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('新写入记录按当前 payload 版本串链并可零断裂校验', async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // P1-29 修复：原实现直接对**空库**跑 verifyAuditChain，并断言
    // expect.any(Boolean) / expect.any(Number) —— 恒真断言，未验证任何行为。
    // 现改为：先用真实模型写入一批记录（pre-save 走真实链锁 + 当前 payload 口径），
    // 再断言校验结论为「零断裂」，且落库记录确实带当前版本（CURRENT_PAYLOAD_VERSION）
    // 的 hash/hmac。版本值一律取常量而非字面量，payload 升版时不会假红。
    const stamp = `resign${Date.now()}`;
    for (let i = 0; i < 3; i++) {
      await AuditLog.create({
        action: 'chain_resign_test',
        category: 'system',
        username: stamp,
        success: true,
        seq: i,
        timestamp: new Date(),
      });
    }

    // 作用域收窄到本用例自己的三条：原写法 total===3 依赖「本文件独占一个空库」这条
    // 隐含前提（setup.js 的每文件独立库），任何人在本文件前面加一条审计写入就会假红。
    const report = await verifyAuditChain(AuditLog, {
      fromLatest: false,
      maxRecords: 100,
      filter: { username: stamp },
    });

    expect(report.total).toBe(3);
    expect(report.legacy).toBe(0);
    expect(report.breaks).toBe(0);
    expect(report.intact).toBe(true);
    expect(report.byType.hash_mismatch).toBe(0);
    const stored = await AuditLog.find({ username: stamp }).select('hashVersion hash hmac').lean();
    expect(stored).toHaveLength(3);
    for (const doc of stored) {
      expect(doc.hashVersion).toBe(CURRENT_PAYLOAD_VERSION);
      expect(doc.hash).toMatch(/^[0-9a-f]{64}$/);
      // HMAC_SECRET 已由 setup.js 注入 → hmac 必须存在（防「静默降级为无密钥哈希」）
      expect(doc.hmac).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
