/**
 * P1-24 回归：毒文档批丢弃后必须留下标记，重启重放不得重复处理同一批
 *
 * 缺陷：`auditBuffer.flush()` 在连续失败达 MAX_BATCH_RETRY 后丢弃本批（内存副本
 * 清空、droppedCount 计数），但**WAL 里的对应行原样保留**。重启时 `start()`
 * 会把这几行重新读回缓冲，再次走满 5 次失败、再次丢弃——每重启一次重复处理一次，
 * 且这些行永远消费不掉（行数恒多于待裁剪数，把裁剪账目也带偏）。
 *
 * 修复：push() 给每条文档（及其 WAL 行）分配一个**跨进程不碰撞**的 `__walSeq`
 * （运行标识 + 自增）；毒批丢弃时按序号把对应行移出主 WAL 并追加归档到
 * `<walPath>.discarded`（保留人工取证能力）。重启重放时先读归档序号集合，
 * 跳过已判定丢弃的行——即使「归档已写、主 WAL 尚未改写」时崩溃（两步之间的窗口），
 * 重启也不会重复处理。
 *
 * 本测试覆盖三条时序：
 *   A. 正常时序：毒批丢弃 → 归档文件含该行、主 WAL 不再含该行 → 重启重放为空；
 *   B. 崩溃窗口：手工把归档行塞回主 WAL（模拟先归档后改写之间崩溃）→
 *      重启重放必须跳过该行（否则重复处理毒批）；
 *   C. 不误伤：毒批之后的正常批次照常落库，其 WAL 行被常规裁剪而非进归档。
 *
 * 约束：不用 jest.useFakeTimers（与 mongodb-memory-server 冲突），
 * 用 spyOn(setInterval) 捕获回调手动触发（与既有 observability/auditBufferFlushAndWalGuards.test.js 同法）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');
const { TEST_CLIENT_IP } = require('../fixtures');

// 独立临时目录 + 独立 WAL 路径：必须在 require 之前设置
// （auditBuffer 的 start() 每次重读 AUDIT_WAL_PATH，但 require 期会先解析默认路径）
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-poison-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'poison-test.wal');
process.env.AUDIT_BUFFER_HARD_LIMIT = '200';
process.env.AUDIT_WAL_MAX_BYTES = '100000'; // 足够大，本套件不触发 WAL 上限裁剪
process.env.AUDIT_WAL_STAT_INTERVAL = '1000'; // 不因 append 次数触发上限检查

const auditBuffer = require('../../services/auditBuffer');
const wal = require('../../services/auditBufferWal');
const AuditLog = require('../../models/AuditLog');
const { contentLevelWriteError } = require('../helpers/contentLevelWriteError');

/** 轮询等待真实完成条件（替代固定 sleep） */
async function waitFor(cond, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await cond()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return false;
}

function makeDoc(seq) {
  return {
    action: 'poison_probe',
    category: 'auth',
    username: 'poison_' + seq,
    ip: TEST_CLIENT_IP,
    success: true,
    timestamp: new Date(),
  };
}

describe('P1-24 毒批丢弃的 WAL 标记与重启重放', () => {
  let tickFn = null;
  let siSpy = null;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    // 先排空 WAL 串行链再删文件：上一用例遗留的在途 append/裁剪会在 unlink
    // 之后把文件重新创建出来，导致本用例读到上一用例的行（随机序下必现）
    await wal.drain();
    auditBuffer.__resetForTest();
    auditBuffer.stop();
    for (const f of [auditBuffer.getWalPath(), auditBuffer.getWalPath() + '.discarded']) {
      try {
        fs.unlinkSync(f);
      } catch (_) {
        /* 首次运行无文件，忽略 */
      }
    }
  });

  afterEach(() => {
    auditBuffer.stop();
    if (siSpy) {
      siSpy.mockRestore();
      siSpy = null;
    }
    tickFn = null;
  });

  afterAll(async () => {
    // 先排空 walChain（含裁剪 rename），再删临时目录：否则 afterAll 的 rmSync
    // 会与在途的原子替换竞态，产生一条 ENOENT 噪声告警
    await auditBuffer.flushAndStop();
    auditBuffer.stop();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* ignore */
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  function mockTimer() {
    const fakeHandle = { unref: jest.fn() };
    siSpy = jest.spyOn(global, 'setInterval').mockImplementation((cb) => {
      tickFn = cb;
      return fakeHandle;
    });
    return fakeHandle;
  }

  function readWal() {
    try {
      return fs.readFileSync(auditBuffer.getWalPath(), 'utf8');
    } catch (_) {
      return '';
    }
  }

  function readDiscarded() {
    try {
      return fs.readFileSync(auditBuffer.getWalPath() + '.discarded', 'utf8');
    } catch (_) {
      return '';
    }
  }

  /** 触发 MAX_BATCH_RETRY 次失败 flush，使当前批次被判定为毒批并丢弃 */
  async function poisonDrop() {
    for (let i = 0; i < 5; i += 1) {
      tickFn();
      if (i < 4) {
        await waitFor(() => auditBuffer.getStats().consecutiveFailures >= i + 1);
      } else {
        await waitFor(() => auditBuffer.getStats().droppedCount > 0);
      }
    }
    // 毒批处理是两步：① 追加归档 ② 原子改写主 WAL 移除该行。
    // 「看到归档」不等于「主 WAL 已改写」（②排在同一条 walChain 上），
    // 因此这里必须等链排空，后续对主 WAL 的断言才是确定性的。
    const archived = await waitFor(() => readDiscarded().includes('poison_poisoned'));
    expect(archived).toBe(true);
    await wal.drain();
  }

  test('毒批丢弃 → 归档留痕 + 主 WAL 移除 + 重启重放不再处理该批', async () => {
    mockTimer();
    auditBuffer.start();
    auditBuffer.push(makeDoc('poisoned'));

    const insertSpy = jest
      .spyOn(AuditLog, 'insertMany')
      .mockRejectedValue(contentLevelWriteError(1));

    await poisonDrop();
    insertSpy.mockRestore();

    const stats = auditBuffer.getStats();
    expect(stats.droppedCount).toBeGreaterThan(0);
    expect(stats.bufferLength).toBe(0);
    // 主 WAL 已不含毒批行；归档文件含之（取证能力保留）
    expect(readWal()).not.toContain('poison_poisoned');
    expect(readDiscarded()).toContain('poison_poisoned');
    expect(stats.walDiscardedLines).toBeGreaterThan(0);

    // ---- 模拟重启：停 → 清缓冲 → 再 start（重放 WAL）----
    auditBuffer.stop();
    auditBuffer.__resetForTest();
    mockTimer();
    auditBuffer.start();
    // 给重放链一点时间结算（重放为空时不会推入任何文档）
    await new Promise((r) => setTimeout(r, 200));

    // 关键断言：重启后缓冲仍为空——毒批没有被重新读回来
    expect(auditBuffer.getStats().bufferLength).toBe(0);
  });

  test('崩溃窗口：归档已写、主 WAL 未改写 → 重启重放按序号跳过', async () => {
    mockTimer();
    auditBuffer.start();
    auditBuffer.push(makeDoc('poisoned'));

    const insertSpy = jest
      .spyOn(AuditLog, 'insertMany')
      .mockRejectedValue(contentLevelWriteError(1));
    await poisonDrop();
    insertSpy.mockRestore();

    // 从归档里取出那一行，手工塞回主 WAL——精确模拟「先归档、后原子替换」
    // 两步之间进程崩溃留下的状态（归档已含序号、主 WAL 仍含该行）
    const archivedLine = readDiscarded().split('\n').filter(Boolean)[0];
    expect(archivedLine).toBeTruthy();
    fs.appendFileSync(auditBuffer.getWalPath(), archivedLine + '\n', 'utf8');
    expect(readWal()).toContain('poison_poisoned');

    // ---- 模拟重启 ----
    auditBuffer.stop();
    auditBuffer.__resetForTest();
    mockTimer();
    auditBuffer.start();
    await new Promise((r) => setTimeout(r, 200));

    // 重放必须跳过该行：缓冲保持为空（若跳过逻辑失效，这里会是 1）
    expect(auditBuffer.getStats().bufferLength).toBe(0);
  });

  test('正常行不受毒批归档影响（按序号精确匹配，不误伤其他行）', async () => {
    mockTimer();
    auditBuffer.start();

    // 先只推毒行，让它在独立批次里被判毒并归档
    auditBuffer.push(makeDoc('poisoned'));
    const insertSpy = jest
      .spyOn(AuditLog, 'insertMany')
      .mockRejectedValue(contentLevelWriteError(1));
    await poisonDrop();
    insertSpy.mockRestore();
    expect(readDiscarded()).toContain('poison_poisoned');

    // 再推正常行：走真实 insertMany，应正常落库，且其 WAL 行按常规裁剪而非进归档
    auditBuffer.push(makeDoc('healthy'));
    tickFn();
    const landed = await waitFor(async () => {
      const n = await AuditLog.countDocuments({ username: 'poison_healthy' });
      return n === 1;
    });
    expect(landed).toBe(true);
    expect(readDiscarded()).not.toContain('poison_healthy');
    expect(await AuditLog.countDocuments({ username: 'poison_poisoned' })).toBe(0);
  });
});
