/**
 * 审计 WAL 大小硬上限测试（报告 R-6）
 *
 * 背景：WAL 行仅在 flush 落库成功后前缀裁剪，DB 长时间不可用且高流量时
 * WAL 持续增长（磁盘写放大）。现增加 AUDIT_WAL_MAX_BYTES 硬上限：
 * 超限丢弃最旧一半行并告警（walDroppedLines 计数可观测）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { TEST_CLIENT_IP } = require('../fixtures');

describe('审计 WAL 大小硬上限（R-6）', () => {
  let tmpDir;
  let auditBuffer;

  beforeAll(() => {
    // AUDIT_WAL_PATH 在模块加载时求值，必须先于 require 设置；
    // getWalMaxBytes / getWalStatInterval 运行期读 env，注入小阈值
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-cap-'));
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'test-audit.wal');
    process.env.AUDIT_WAL_MAX_BYTES = '200';
    // B-I1：stat 节流默认每 32 次追加抽查一次——本套件只 push 10 条，
    // 注入 1 恢复逐条检查，使上限裁剪在套件内可见
    process.env.AUDIT_WAL_STAT_INTERVAL = '1';
    auditBuffer = require('../../services/auditBuffer');
  });

  afterAll(() => {
    auditBuffer.stop();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 忽略 */
    }
  });

  test('WAL 超限后丢弃最旧行且文件不再无界增长', async () => {
    auditBuffer.__resetForTest();
    auditBuffer.start(); // 开启 walEnabled

    // 每行约 60~70 字节；10 行远超 200 字节上限，追加路径的 enforceWalLimit 会多次触发
    for (let i = 0; i < 10; i++) {
      auditBuffer.push({
        action: 'wal_cap_test',
        category: 'auth',
        ip: TEST_CLIENT_IP,
        success: true,
        seq: i,
      });
    }

    // enforcement 在 walChain 上异步执行：轮询等待丢弃计数器推进
    const deadline = Date.now() + 5000;
    while (auditBuffer.getStats().walDroppedLines === 0 && Date.now() < deadline) {
      // walChain 链式任务在微任务/IO 后推进，让出事件循环
      await new Promise((r) => setTimeout(r, 50));
    }

    const stats = auditBuffer.getStats();
    expect(stats.walDroppedLines).toBeGreaterThan(0);

    // 文件存在且受控（保留一半语义下允许上限 + 单行容差）
    const size = fs.statSync(process.env.AUDIT_WAL_PATH).size;
    expect(size).toBeLessThanOrEqual(200 + 120);

    // 残留行均为合法 JSON（丢弃按整行进行，不产生残缺行）
    const lines = fs.readFileSync(process.env.AUDIT_WAL_PATH, 'utf8').split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  test('getStats 暴露 walDroppedLines（合规可观测）', () => {
    const stats = auditBuffer.getStats();
    expect(stats).toHaveProperty('walDroppedLines');
    expect(stats.walEnabled).toBe(true);
  });
});
