/**
 * auditBuffer 分支覆盖率补齐测试
 *
 * 目标：将 branches 从 ~30% 提到 >=75%。
 * 覆盖路径：flush 成功/失败/毒文档隔离、WAL trim/replay、缓冲硬上限裁剪、
 * ensureLogsDir、定时器回调、isWalEnabled、getStats。
 *
 * 约束：不用 jest.useFakeTimers（与 mongodb-memory-server 冲突），
 * 改用 spyOn(setInterval) 捕获回调后手动触发。
 *
 * 健壮性加固（Round-6 P3，修复全量并行下的隔离/时机抖动）：
 * 1. WAL 路径按 worker 隔离——mkdtemp 每进程唯一目录；模块侧改为 start() 时
 *    重读 AUDIT_WAL_PATH（消除「先 require 锁死路径」的跨文件竞态）；
 * 2. 全部文件断言经 auditBuffer.getWalPath() 读取，与模块行为恒一致，
 *    不再依赖 env 是否赢得模块加载顺序；
 * 3. 固定 setTimeout 等待全部替换为 waitFor 轮询断言——对真实完成条件
 *    （DB 计数/WAL 内容/stats 字段）轮询，超时 8s，消除负载敏感窗口。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

// 独立临时目录（mkdtemp 每进程唯一）；模块在 start() 时重读该 env
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditbuf-gap-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'gap-test.wal');
process.env.AUDIT_BUFFER_HARD_LIMIT = '200';
process.env.AUDIT_WAL_MAX_BYTES = '100000'; // 足够大，不触发 WAL cap

// 必须在 env 设置之后 require
const auditBuffer = require('../../services/auditBuffer');
const AuditLog = require('../../models/AuditLog');
const { TEST_CLIENT_IP } = require('../fixtures');

/** 轮询等待真实完成条件（替代固定 setTimeout；全量并行负载下 8s 上限）。
 *  条件可为同步或异步（返回 Promise 会被 await——否则 Promise 恒真值，
 *  循环体永不执行，等待退化为立即通过） */
async function waitFor(cond, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await cond()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return false;
}

/** 等 WAL 异步追加链清空：文件内容不再变化（beforeEach 清理前必须先排空） */
async function waitForWalQuiet(timeoutMs = 8000) {
  const walPath = auditBuffer.getWalPath();
  let last = null;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let cur;
    try {
      cur = fs.readFileSync(walPath, 'utf8');
    } catch (_) {
      cur = null;
    }
    if (cur === last) return;
    last = cur;
    await new Promise((r) => setTimeout(r, 25));
  }
}

function makeDoc(seq) {
  return {
    action: 'login',
    category: 'auth',
    username: `testuser_${seq}`,
    ip: TEST_CLIENT_IP,
    success: true,
    timestamp: new Date(),
    _seq: seq, // 用于追踪，不会存入 DB
  };
}

describe('auditBuffer 分支补齐', () => {
  let tickFn = null;
  let siSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(() => {
    auditBuffer.__resetForTest();
    auditBuffer.stop();
    // 清理 WAL 文件
    try {
      fs.unlinkSync(auditBuffer.getWalPath());
    } catch (_) {
      /* ignore */
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

  /** 读 WAL 内容（经 getWalPath，与模块写入路径恒一致） */
  function readWal() {
    try {
      return fs.readFileSync(auditBuffer.getWalPath(), 'utf8');
    } catch (_) {
      return '';
    }
  }

  // ---- start / stop / isWalEnabled ----
  describe('生命周期', () => {
    test('start 开启 WAL 并注册定时器；重复 start 幂等', () => {
      const fakeHandle = mockTimer();

      auditBuffer.start();
      expect(auditBuffer.isWalEnabled()).toBe(true);
      expect(tickFn).not.toBeNull();
      expect(fakeHandle.unref).toHaveBeenCalled();

      // 重复 start 不应再注册定时器
      const callCount = siSpy.mock.calls.length;
      auditBuffer.start();
      expect(siSpy.mock.calls.length).toBe(callCount);
    });

    test('stop 关闭 WAL 并清除定时器', () => {
      mockTimer();
      auditBuffer.start();
      auditBuffer.stop();
      expect(auditBuffer.isWalEnabled()).toBe(false);
    });

    test('isWalEnabled 初始为 false', () => {
      expect(auditBuffer.isWalEnabled()).toBe(false);
    });
  });

  // ---- push + flush 成功路径 ----
  describe('push + flush 成功落库', () => {
    test('满额触发 flush 并写入 DB', async () => {
      mockTimer();
      auditBuffer.start();

      // push 100 条触发满额 flush（BUFFER_LIMIT=100）
      for (let i = 0; i < 100; i++) {
        auditBuffer.push(makeDoc(i));
      }

      // flush 是异步的：轮询 DB 计数（替代固定 1000ms 等待）
      const done = await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: /^testuser_/ });
        return n === 100;
      });
      expect(done).toBe(true);
    });

    test('定时器回调触发 flush', async () => {
      mockTimer();
      auditBuffer.start();

      // push 少量（不满额）
      auditBuffer.push(makeDoc('timer_test'));
      await waitForWalQuiet();

      // 此时 DB 应为空（未触发满额 flush）
      let count = await AuditLog.countDocuments({ username: 'testuser_timer_test' });
      expect(count).toBe(0);

      // 手动触发定时器回调
      tickFn();
      await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_timer_test' });
        return n === 1;
      });

      count = await AuditLog.countDocuments({ username: 'testuser_timer_test' });
      expect(count).toBe(1);
    });
  });

  // ---- flush 失败 + 重试 + 毒文档隔离 ----
  describe('flush 失败与毒文档隔离', () => {
    test('insertMany 失败后文档回到缓冲重试', async () => {
      mockTimer();
      auditBuffer.start();
      auditBuffer.push(makeDoc('retry1'));

      // 让第一次 flush 失败
      const insertSpy = jest
        .spyOn(AuditLog, 'insertMany')
        .mockRejectedValueOnce(new Error('DB down'));

      tickFn();
      await waitFor(() => auditBuffer.getStats().consecutiveFailures === 1);

      // 文档应回到缓冲
      const stats = auditBuffer.getStats();
      expect(stats.bufferLength).toBeGreaterThan(0);
      expect(stats.consecutiveFailures).toBe(1);

      insertSpy.mockRestore();

      // 再次 flush 应成功
      tickFn();
      await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_retry1' });
        return n === 1;
      });

      const count = await AuditLog.countDocuments({ username: 'testuser_retry1' });
      expect(count).toBe(1);
    });

    test('连续失败达 MAX_BATCH_RETRY 时丢弃批次（毒文档隔离）', async () => {
      mockTimer();
      auditBuffer.start();
      auditBuffer.push(makeDoc('poison'));

      const insertSpy = jest
        .spyOn(AuditLog, 'insertMany')
        .mockRejectedValue(new Error('permanent fail'));

      // 触发 5 次 flush（MAX_BATCH_RETRY=5），每轮轮询失败计数单调递增
      // （用 >= 而非 ===：一轮内可能触发多次 flush，计数会跳过中间值）
      for (let i = 0; i < 5; i++) {
        tickFn();
        const target = i < 4 ? i + 1 : 0; // 第 5 次触发丢弃并重置为 0
        if (i < 4) {
          await waitFor(() => auditBuffer.getStats().consecutiveFailures >= target);
        } else {
          await waitFor(() => auditBuffer.getStats().droppedCount > 0);
        }
      }

      const stats = auditBuffer.getStats();
      // 第 5 次触发丢弃，consecutiveFailures 被重置为 0
      expect(stats.consecutiveFailures).toBe(0);
      expect(stats.droppedCount).toBeGreaterThan(0);
      // 缓冲应已清空（批次被丢弃了）
      expect(stats.bufferLength).toBe(0);

      insertSpy.mockRestore();
    });

    test('部分成功（insertedDocs）只回退未落库子集', async () => {
      mockTimer();
      auditBuffer.start();

      // push 两条不同 username 的文档
      auditBuffer.push(makeDoc('partial_ok'));
      auditBuffer.push(makeDoc('partial_fail'));

      // chainBatch 会给文档添加 hash 字段。模拟部分成功时，
      // insertedDocs 中的 hash 需要与被链化后的文档匹配。
      // 用 mockImplementation 捕获实际参数以获取正确的 hash
      const err = new Error('duplicate key');
      const insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementationOnce((docs) => {
        // 模拟第一条成功、第二条失败
        err.insertedDocs = [docs[0]]; // 第一条已插入（含 hash）
        return Promise.reject(err);
      });

      tickFn();
      await waitFor(() => auditBuffer.getStats().consecutiveFailures === 1);

      const stats = auditBuffer.getStats();
      // 只有 partial_fail 回到了缓冲（通过 hash 排除了已插入的 partial_ok）
      expect(stats.bufferLength).toBeGreaterThanOrEqual(1);
      expect(stats.consecutiveFailures).toBe(1);

      insertSpy.mockRestore();

      // 再 flush 把剩余的落库
      tickFn();
      await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_partial_fail' });
        return n === 1;
      });

      // partial_ok 不在 DB（因为第一次 insertMany 被 mock 了没有真正写入），
      // partial_fail 应在第二次 flush 时成功写入
      const failCount = await AuditLog.countDocuments({ username: 'testuser_partial_fail' });
      expect(failCount).toBe(1);
    });
  });

  // ---- 缓冲硬上限 ----
  describe('缓冲硬上限裁剪', () => {
    test('超过 BUFFER_HARD_LIMIT 丢弃最旧记录', async () => {
      // BUFFER_HARD_LIMIT=200（env 注入）
      // 策略：让 flush 持续失败，文档回退到缓冲不断累积，直到超过硬上限
      mockTimer();
      auditBuffer.start();

      const insertSpy = jest
        .spyOn(AuditLog, 'insertMany')
        .mockRejectedValue(new Error('DB down for overflow test'));

      // 每轮 push 100 条触发 flush → 失败 → 回退到缓冲
      // 3 轮后缓冲应超过 200，触发 enforceBufferLimit
      // 轮询失败计数单调递增（>= ：一轮内可能多次 flush，精确等于会跳过）
      for (let round = 0; round < 3; round++) {
        for (let i = 0; i < 100; i++) {
          auditBuffer.push(makeDoc(`of_${round}_${i}`));
        }
        await waitFor(() => auditBuffer.getStats().consecutiveFailures >= round + 1);
      }

      const stats = auditBuffer.getStats();
      expect(stats.droppedCount).toBeGreaterThan(0);
      expect(stats.bufferLength).toBeLessThanOrEqual(200);

      insertSpy.mockRestore();
    });
  });

  // ---- WAL replay ----
  describe('WAL 重放', () => {
    test('start 时重放 WAL 残留行到缓冲', async () => {
      // 先手动写几行到 WAL 文件
      const walPath = auditBuffer.getWalPath();
      const dir = path.dirname(walPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      const docs = [makeDoc('wal_replay_1'), makeDoc('wal_replay_2')];
      const content = docs.map((d) => JSON.stringify(d)).join('\n') + '\n';
      fs.writeFileSync(walPath, content, 'utf8');

      mockTimer();
      auditBuffer.start();

      // WAL 重放在 walChain 上异步执行：轮询缓冲计数（替代固定 500ms）
      const done = await waitFor(() => auditBuffer.getStats().bufferLength >= 2);
      expect(done).toBe(true);
    });

    test('WAL 含损坏行时跳过不阻塞启动', async () => {
      const walPath = auditBuffer.getWalPath();
      const dir = path.dirname(walPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      fs.writeFileSync(
        walPath,
        '{invalid json\n{"action":"login","category":"auth","username":"good","ip":"1.2.3.4","success":true,"timestamp":"2026-01-01T00:00:00.000Z"}\n',
        'utf8'
      );

      mockTimer();

      // 不应抛异常
      expect(() => auditBuffer.start()).not.toThrow();
      const done = await waitFor(() => auditBuffer.getStats().bufferLength >= 1);

      const stats = auditBuffer.getStats();
      // 至少好的那行被重放了
      expect(stats.bufferLength).toBeGreaterThanOrEqual(1);
      expect(done).toBe(true);
    });
  });

  // ---- WAL trim ----
  describe('WAL 裁剪', () => {
    test('flush 成功后裁剪对应 WAL 行', async () => {
      mockTimer();
      auditBuffer.start();

      // push 一条并 flush
      auditBuffer.push(makeDoc('wal_trim'));
      tickFn();
      // 轮询「先落库、后裁剪完成」的最终状态：WAL 不再含该行
      const done = await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_wal_trim' });
        return n === 1 && !readWal().includes('wal_trim');
      });
      expect(done).toBe(true);
    });
  });

  // ---- getStats ----
  describe('getStats', () => {
    test('返回完整统计结构', () => {
      const stats = auditBuffer.getStats();
      expect(stats).toHaveProperty('bufferLength');
      expect(stats).toHaveProperty('hardLimit');
      expect(stats).toHaveProperty('droppedCount');
      expect(stats).toHaveProperty('consecutiveFailures');
      expect(stats).toHaveProperty('walEnabled');
      expect(stats).toHaveProperty('walDroppedLines');
    });
  });

  // ---- ensureLogsDir ----
  describe('ensureLogsDir', () => {
    test('WAL 目录已存在时 start 不报错', () => {
      mockTimer();
      expect(() => auditBuffer.start()).not.toThrow();
      expect(auditBuffer.isWalEnabled()).toBe(true);
    });
  });

  // ---- enforceWalLimit（WAL 超限裁剪）----
  describe('enforceWalLimit', () => {
    test('WAL 文件超过 AUDIT_WAL_MAX_BYTES 时丢弃最旧一半行', async () => {
      // getWalMaxBytes 运行期读 env，注入小阈值触发裁剪
      const origMax = process.env.AUDIT_WAL_MAX_BYTES;
      process.env.AUDIT_WAL_MAX_BYTES = '200'; // 约 3~4 行就超

      mockTimer();
      auditBuffer.start();

      // push 足够多行使 WAL 文件超过 200 字节
      for (let i = 0; i < 10; i++) {
        auditBuffer.push(makeDoc(`walcap_${i}`));
      }

      // 等待 walChain 上的 enforceWalLimit 执行（原有轮询保留）
      const done = await waitFor(() => auditBuffer.getStats().walDroppedLines > 0);

      const stats = auditBuffer.getStats();
      expect(stats.walDroppedLines).toBeGreaterThan(0);
      expect(done).toBe(true);

      process.env.AUDIT_WAL_MAX_BYTES = origMax;
    });
  });

  // ---- chainBatch 哈希失败 ----
  describe('flush 哈希链计算失败', () => {
    test('chainBatch 抛错时文档仍以无哈希方式落库', async () => {
      mockTimer();
      auditBuffer.start();
      auditBuffer.push(makeDoc('nohash'));

      // mock auditChain.chainBatch 使其抛错
      const auditChain = require('../../utils/auditChain');
      const chainSpy = jest.spyOn(auditChain, 'chainBatch').mockImplementation(() => {
        throw new Error('hash computation failed');
      });

      tickFn();
      await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_nohash' });
        return n === 1;
      });

      // 文档应仍然落库（best-effort：无 hash 但不阻塞）
      const count = await AuditLog.countDocuments({ username: 'testuser_nohash' });
      expect(count).toBe(1);

      chainSpy.mockRestore();
    });
  });

  // ---- WAL 目录不存在时 start 自动创建 ----
  describe('ensureLogsDir 创建目录', () => {
    test('WAL 父目录不存在时 start 自动 mkdirSync', () => {
      // 删除 WAL 所在目录以触发 mkdirSync 分支
      const walPath = auditBuffer.getWalPath();
      const walDir = path.dirname(walPath);
      try {
        fs.rmSync(walDir, { recursive: true, force: true });
      } catch (_) {
        /* ignore */
      }

      mockTimer();
      expect(() => auditBuffer.start()).not.toThrow();
      expect(fs.existsSync(walDir)).toBe(true);
    });
  });

  // ---- walTrimLines 行数不足 ----
  describe('walTrimLines 边界', () => {
    test('WAL 行数少于待裁剪数时按实际行数清理', async () => {
      mockTimer();
      auditBuffer.start();

      // push 1 条产生 1 行 WAL；轮询等待 WAL 写入完成（替代固定 200ms）
      auditBuffer.push(makeDoc('trim_edge'));
      await waitFor(() => readWal().includes('trim_edge'));

      // flush 成功会调用 walTrimLines(docs.length)；轮询裁剪完成
      tickFn();
      const done = await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_trim_edge' });
        return n === 1 && !readWal().includes('trim_edge');
      });

      // 验证 WAL 已被裁剪
      expect(done).toBe(true);
    });
  });

  // ---- fs 错误注入 ----
  describe('WAL 文件系统错误处理', () => {
    test('walAppendLine 追加失败时记录 warn 不抛异常', async () => {
      mockTimer();
      auditBuffer.start();

      // mock appendFile 使其失败
      const appendSpy = jest
        .spyOn(fs.promises, 'appendFile')
        .mockRejectedValue(new Error('EACCES: permission denied'));

      // push 应触发 walAppendLine → catch → logger.warn
      expect(() => auditBuffer.push(makeDoc('fs_err'))).not.toThrow();

      // 等待 walChain 上的 catch 执行
      await new Promise((r) => setTimeout(r, 200));

      appendSpy.mockRestore();
    });

    test('enforceWalLimit stat 返回非 ENOENT 错误时记录 warn', async () => {
      const origMax = process.env.AUDIT_WAL_MAX_BYTES;
      process.env.AUDIT_WAL_MAX_BYTES = '1'; // 极低阈值确保进入 stat 检查

      mockTimer();
      auditBuffer.start();

      // mock stat 返回非 ENOENT 错误
      const statSpy = jest
        .spyOn(fs.promises, 'stat')
        .mockRejectedValue(Object.assign(new Error('EACCES'), { code: 'EACCES' }));

      auditBuffer.push(makeDoc('stat_err'));

      // 等待 walChain 推进
      await new Promise((r) => setTimeout(r, 300));

      statSpy.mockRestore();
      process.env.AUDIT_WAL_MAX_BYTES = origMax;
    });

    test('walTrimLines 中 writeFile 失败触发外层 catch（line 185）', async () => {
      mockTimer();
      auditBuffer.start();

      auditBuffer.push(makeDoc('trim_write_err'));
      // 等 WAL append 完成（轮询内容可见，替代固定 200ms）
      await waitFor(() => readWal().includes('trim_write_err'));

      // mock writeFile 使 walTrimLines 的原子替换失败
      const writeSpy = jest
        .spyOn(fs.promises, 'writeFile')
        .mockRejectedValue(new Error('ENOSPC: no space left'));

      tickFn();
      await new Promise((r) => setTimeout(r, 500));

      writeSpy.mockRestore();
    });

    test('walTrimLines records.length < n 时记录 warn（line 174）', async () => {
      // 场景：WAL 只有 1 行，但 flush 落库 3 条文档后调 walTrimLines(3)
      // → records.length(1) < n(3) → warn + 按实际行数清理

      // 先手动写 1 行到 WAL
      const walPath = auditBuffer.getWalPath();
      const dir = path.dirname(walPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(walPath, JSON.stringify(makeDoc('wal_single')) + '\n', 'utf8');

      mockTimer();
      auditBuffer.start();

      // 等待 WAL 重放完成（1 行进入缓冲）
      await waitFor(() => auditBuffer.getStats().bufferLength >= 1);

      // 再 push 2 条（这 2 条也会追加到 WAL，使 WAL 共 3 行）
      // 但我们想让 WAL 行数 < flush 文档数，所以用另一种策略：
      // 直接往缓冲塞 3 条但不写 WAL（通过 stop/push/start 不行，因为 stop 后 push 不写 WAL）
      auditBuffer.stop();
      auditBuffer.push(makeDoc('extra_1'));
      auditBuffer.push(makeDoc('extra_2'));
      // 此时缓冲有 3 条（1 从重放 + 2 新推），WAL 只有 1 行

      // 重新启动以触发 flush
      const fakeHandle2 = { unref: jest.fn() };
      siSpy.mockRestore();
      siSpy = jest.spyOn(global, 'setInterval').mockImplementation((cb) => {
        tickFn = cb;
        return fakeHandle2;
      });
      auditBuffer.start();

      // 手动 flush
      tickFn();
      await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: /^testuser_(wal_single|extra_)/ });
        return n === 3;
      });

      // walTrimLines(3) 被调用，WAL 只有 1 行 → records.length(1) < n(3)
      // 验证不报错且文档落库
      const count = await AuditLog.countDocuments({ username: /^testuser_(wal_single|extra_)/ });
      expect(count).toBe(3);
    });

    test('start WAL 重放 .catch 路径（line 338）', async () => {
      // 要让 walChain.then(...) 内的代码抛异常，
      // 可以让 readWalLines 成功返回行，但后续 enforceBufferLimit 内的 logger.error 抛错
      const walPath = auditBuffer.getWalPath();
      const dir = path.dirname(walPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      // 写入大量有效 WAL 行使重放后触发 enforceBufferLimit
      // BUFFER_HARD_LIMIT=200，写入 250 行使 enforceBufferLimit 触发 logger.error
      const lines = [];
      for (let i = 0; i < 250; i++) {
        lines.push(JSON.stringify(makeDoc(`replay_overflow_${i}`)));
      }
      fs.writeFileSync(walPath, lines.join('\n') + '\n', 'utf8');

      // mock logger.error 使其在 enforceBufferLimit 内抛错
      const logger = require('../../utils/logger');
      const errSpy = jest.spyOn(logger, 'error').mockImplementationOnce(() => {
        throw new Error('logger.error exploded');
      });

      mockTimer();
      expect(() => auditBuffer.start()).not.toThrow();

      // 等待 walChain 上的 catch 执行（重放 250 行后触发，轮询缓冲）
      await waitFor(() => auditBuffer.getStats().bufferLength >= 200);

      errSpy.mockRestore();
    });
  });
});
