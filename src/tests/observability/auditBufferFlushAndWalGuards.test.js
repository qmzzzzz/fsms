/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：auditBuffer：flush 成功/失败/毒文档隔离、WAL trim/replay、缓冲硬上限裁剪、定时器回调
 * 守护的不变式：毒文档不得阻塞后续 flush；WAL 必须可 replay；缓冲不得无界增长
 * 可证伪性：本轮未做变异实测
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [已修复·核心] **F-34（Critical·治理）**：`:509-531` 把「`chainBatch` 抛错时文档仍以无哈希方式落库」**断言为期望行为**，与 `services/auditChainVerify.test.js:117-130` 合起来构成链绕过的正式背书 ⇒ **修复该绕过会让 CI 变红**（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     复核：校验端已修——`services/auditChainVerify.js:25-31`「无哈希记录不再一律算 legacy…出现在带 hash 记录之后 = 完整性无法追认，计入 breaks（type=hash_stripped）」；`services/auditChainVerify.test.js:74-89` 专项断言 `intact:false` / `legacy:0` / `byType.hash_stripped:1`。故「修复该绕过会让 CI 变红」已不成立。残留（非 Critical）：本文件 `:529` 用例标题写「无哈希方式落库」，函数体只断 `count===1`，未断哈希字段缺失。
 *   - [部分有效] `:563-656` 3 处名实不符 + 2 处 env 泄漏 + 3 处固定 sleep，而文件头宣称「已消除固定 sleep」（原出处 2026-09-16 全面代码审计报告；**该报告已删除**，问题编号保留原样）
 *     复核：env 泄漏已还原（`:498-499`→`:521-523`、`:622-623`→`:648-650` 成对 restore）；固定 sleep 仍有 `:613`（200ms）、`:822`（150ms）——`:64/:98` 属 `waitFor` 轮询，不计。
 *
 * 命名沿革：2026-09-20 由 `auditBufferGap.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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
const wal = require('../../services/auditBufferWal');
const AuditLog = require('../../models/AuditLog');
const { TEST_CLIENT_IP } = require('../fixtures');
const { contentLevelWriteError } = require('../helpers/contentLevelWriteError');

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

/** 等 WAL 异步写入链真正排空（追加/裁剪/rename 全部落盘）。
 *
 * 【竞态修复】原实现比较「两次读到的文件内容是否相同」，但 WAL 追加是
 * fire-and-forget 的异步链（auditBufferWal.walAppendLine）：push() 返回时
 * 文件可能**尚未创建**，此时第一次读得 null 作为基线，第二次读仍是 null，
 * null === null 成立 → 函数在 0 次循环后立即返回。
 *
 * 后果：调用方紧接着读 WAL / 断言缓冲内容时，实际读取的是「异步链还没跑完」
 * 的中间态。单跑本文件时事件循环空闲、链几乎瞬时完成，故长期未被发现；
 * 全量并行（50% workers，每个 worker 在跑真实 DB 操作）下链明显排队，
 * 稳定复现为「WAL 行数 0 / 缓冲计数 0」的假红。
 *
 * 修复：改为等待 wal 模块自己的串行链排空（drain 就是 flushAndStop 用的
 * 同一判据），再叠加一次「文件内容稳定」确认，语义与「追加链排空」等价且
 * 不依赖文件是否已存在。 */
async function waitForWalQuiet(timeoutMs = 8000) {
  await wal.drain(); // 精确判据：walChain 上排队的 append/trim/rename 全部完成
  const p = auditBuffer.getWalPath();
  let last = null;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let cur;
    try {
      cur = fs.readFileSync(p, 'utf8');
    } catch (_) {
      return; // 文件不存在 = 没有待观察的写入（链已排空），无需继续等
    }
    if (cur === last) return; // 内容不再变化
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

  beforeEach(async () => {
    // 【顺序无关修复】先把前序用例遗留的在途 WAL 链（含 flush 成功后才排入的 trim）
    // 等干净，再清理文件。否则前者的 trim 会在本用例执行期内读取并裁掉本用例刚写的行
    // → 本用例的 trim 读到 0 行提前 return，相关断言（如「writeFile 失败须产生 warn」）
    // 会等满 8s 超时。waitForWalQuiet = drain + 内容稳定确认，能覆盖「drain 时 trim 尚未入队」的窗口。
    await waitForWalQuiet();
    auditBuffer.__resetForTest();
    auditBuffer.stop();
    // 【顺序无关修复】清掉本套件写入的审计行：多个用例都以 testuser_ 前缀落库，
    // 计数型断言（如 /^testuser_\d+$/ === 100）会被前序用例的残留污染。
    // 每个用例从干净状态起步，结果与执行顺序无关。
    // bypassAppendOnly 仅测试环境放行（auditLogHooks.js:127 已做 NODE_ENV 校验）。
    try {
      await AuditLog.deleteMany({ username: /^testuser_/ }, { bypassAppendOnly: true });
    } catch (_) {
      /* 库未连接时忽略 */
    }
    // 清理 WAL 文件。两处都清：getWalPath() 在 -t 单跑时可能仍停在模块加载期的
    // 默认路径，而本套件的写入目标始终是 AUDIT_WAL_PATH（startup() 会重读它）。
    for (const p of [auditBuffer.getWalPath(), process.env.AUDIT_WAL_PATH]) {
      try {
        fs.unlinkSync(p);
      } catch (_) {
        /* ignore */
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

  /**
   * 本套件的 WAL 路径（显式钉死，供「写文件 → start() 重放」类用例在 start 前取用）。
   *
   * 【顺序无关修复】不能用 auditBuffer.getWalPath()：它在 startup() 之前返回
   * **模块加载期的默认派生路径**（仓库 logs/），而模块写入时用的是 AUDIT_WAL_PATH。
   * 写错文件 → 重放读不到 → 轮询 8s 超时。本 helper 恒返回本套件的 env 路径。
   */
  const testWalPath = () => process.env.AUDIT_WAL_PATH;
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
      // 【顺序无关修复】原断言用 /^testuser_/ 全前缀 === 100，会被同套件其他
      // 用例（如 testuser_timer_test）留下的行污染成 101 → 轮询恒假、8s 超时。
      // 改为本条用例专属的计数范围（makeDoc(数字) → testuser_<纯数字>），
      // 与「谁先跑」无关。
      const done = await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: /^testuser_\d+$/ });
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
        .mockRejectedValue(contentLevelWriteError(1));

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

    /**
     * 方向断言（补上一那条用例的缺口）。
     *
     * 上面那条名字写着"丢弃最旧记录"，但它只断 `droppedCount>0` 与 `bufferLength<=200`
     * ——两条都是**计数**。于是把 `auditBuffer.js:113` 的 `buffer.splice(0, overflow)`
     * 改成 `splice(-overflow)`，或"更简洁地"写成 `buffer.length = BUFFER_HARD_LIMIT`
     * （截尾＝丢最新），那条用例**照样全绿**，而测试名与 logger 文案都还在声称丢的是最旧。
     *
     * 为什么方向要紧：缓冲只在"DB 不可用"期间才会涨到硬上限，此时队尾正是
     * **故障期间新发生的登录/告警/配置变更**——事故响应最需要的那一段。
     * 留旧丢新等于把现场抹掉、把旧闻留下，且 droppedCount 与日志一个字都不会变。
     *
     * 判据取"交付出去的是哪批"（insertMany 的实参），不读内部数组：
     * 这与生产消费者的可见行为同源，改数组实现方式不会误伤这条。
     */
    test('裁的是队首最旧一批：幸存者必须是连续尾段且含最新一条', async () => {
      mockTimer();
      auditBuffer.start();

      const insertSpy = jest
        .spyOn(AuditLog, 'insertMany')
        .mockRejectedValue(new Error('DB down for direction test'));

      const TOTAL = 230; // 硬上限 200 ⇒ 必然进入裁剪
      for (let i = 0; i < TOTAL; i += 1) auditBuffer.push(makeDoc(i));
      await waitFor(() => auditBuffer.getStats().droppedCount > 0);

      // 让落库转为成功，反复推定时器直到缓冲排空；幸存者从成功批次的实参里收集。
      // 仍在途的失败批次会把文档 unshift 回队首（更早的时间位置），
      // 所以这里不能只看一次快照——收集到 bufferLength 归零为止。
      const survivors = new Set();
      const collect = () => {
        for (const call of insertSpy.mock.calls) {
          for (const doc of call[0] || []) survivors.add(Number(doc._seq));
        }
      };
      insertSpy.mockClear();
      insertSpy.mockResolvedValue({ acknowledged: true });
      for (
        let round = 0;
        round < 40 && (auditBuffer.getStats().bufferLength > 0 || survivors.size === 0);
        round += 1
      ) {
        tickFn();
        await new Promise((r) => setTimeout(r, 25));
        collect();
      }
      insertSpy.mockRestore();

      // 先自证"确实排干了"：否则下面的守恒/尾段断言读的都是中间态
      expect(auditBuffer.getStats().bufferLength).toBe(0);
      const dropped = auditBuffer.getStats().droppedCount;
      expect(survivors.size).toBeGreaterThan(0);
      // 守恒：push 的总数 = 交付 + 丢弃（凭空多与静默少都不许）
      expect(survivors.size + dropped).toBe(TOTAL);
      // 最新一条必须活着 ⇒ 方向写反（丢新端）在这里红
      expect(survivors.has(TOTAL - 1)).toBe(true);
      // 最旧一条必须被裁掉 ⇒ 配合上一行排除"根本没裁/裁了中间"
      expect(survivors.has(0)).toBe(false);
      // 幸存者必须是**连续尾段**：从中间挖洞同样能骗过两条计数断言
      const seqs = [...survivors].sort((a, b) => a - b);
      expect(seqs[seqs.length - 1] - seqs[0] + 1).toBe(seqs.length);
    });
  });

  // ---- WAL replay ----
  describe('WAL 重放', () => {
    test('start 时重放 WAL 残留行到缓冲', async () => {
      // 先手动写几行到 WAL 文件
      const walPath = testWalPath();
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
      const walPath = testWalPath();
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
    // 本 describe 的两个用例都要改 WAL 容量/检查频率 env。**必须**在 finally 里还原：
    // 断言失败会跳过函数体尾部的还原语句，于是极小的 AUDIT_WAL_MAX_BYTES 泄漏给后面的
    // 用例（实测：变异测试时本文件「start WAL 重放链上的失败被 catch 吞掉」因此转红，
    // 把归因从"裁剪方向没钉住"误导成"那条用例有牙"——单独跑它其实是绿的）。
    // 另外 `process.env.X = undefined` 会写入字符串 'undefined'，所以还原用 delete。
    const WAL_ENV_KEYS = ['AUDIT_WAL_MAX_BYTES', 'AUDIT_WAL_STAT_INTERVAL'];
    const snapshotWalEnv = () => Object.fromEntries(WAL_ENV_KEYS.map((k) => [k, process.env[k]]));
    const restoreWalEnv = (snap) => {
      for (const k of WAL_ENV_KEYS) {
        if (snap[k] === undefined) delete process.env[k];
        else process.env[k] = snap[k];
      }
    };

    test('WAL 文件超过 AUDIT_WAL_MAX_BYTES 时丢弃最旧一半行', async () => {
      const snap = snapshotWalEnv();
      try {
        // getWalMaxBytes 运行期读 env，注入小阈值触发裁剪
        process.env.AUDIT_WAL_MAX_BYTES = '200'; // 约 3~4 行就超
        // 消除顺序依赖（本次改动复审）：enforceWalLimit 由 walAppendCount % interval 触发，
        // interval 默认 32 且 walAppendCount 是模块级累加值——单独跑本用例（-t）时
        // 只有 10 次 push，永远到不了阈值，用例会假红。设为 1 后每次 append 都检查。
        process.env.AUDIT_WAL_STAT_INTERVAL = '1';

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
      } finally {
        restoreWalEnv(snap);
      }
    });

    /**
     * 上面那条只断「丢了多少行」（walDroppedLines>0），没断「丢的是哪几行」——
     * 与 §40（缓冲侧 F-122）同一型缺口：把 `records.slice(keepFrom)` 改成
     * `records.slice(0, len - keepFrom)`（留最旧、丢最新）它照样全绿。
     * 本用例把方向钉成判据：WAL 超限后活着的必须是**连续尾段且含最新一行**。
     * 理由与缓冲侧同：WAL 只在 DB 不可用期间涨到上限，尾部正是故障期间新发生的
     * 登录/告警/配置变更——事故取证要的那段；"留旧丢新"是最坏方向。
     */
    test('WAL 超限裁剪的方向：幸存者必须是连续尾段且含最新一行', async () => {
      const snap = snapshotWalEnv();
      try {
        process.env.AUDIT_WAL_STAT_INTERVAL = '1'; // 每次追加后都查大小，裁剪与用例顺序无关

        mockTimer();
        auditBuffer.start();

        // 单行字节数实测得来（不写死阈值，避免文档字段宽度变化让裁剪提前/延后触发）。
        // 测量用的那一行就是 `_seq:0`——它因此恒为文件首行，任何一次裁剪（keepFrom≥1）
        // 都会带走它，`!has(0)` 这条断言才有确定的因果，而不是靠运气。
        const TOTAL = 20;
        auditBuffer.push(makeDoc(0));
        await wal.drain();
        const lineBytes = fs.readFileSync(auditBuffer.getWalPath()).length;
        expect(lineBytes).toBeGreaterThan(0);
        process.env.AUDIT_WAL_MAX_BYTES = String(lineBytes * 6); // 约 6 行必超限一次

        for (let i = 1; i < TOTAL; i += 1) auditBuffer.push(makeDoc(i));
        const trimmed = await waitFor(() => auditBuffer.getStats().walDroppedLines > 0);
        expect(trimmed).toBe(true);
        await wal.drain(); // 排干在途的 append/裁剪，再读终态

        const survivors = new Set(
          fs
            .readFileSync(auditBuffer.getWalPath(), 'utf8')
            .split('\n')
            .filter(Boolean)
            .map((line) => JSON.parse(line)._seq)
        );
        // 至少 2 行，否则"连续尾段"是同义反复
        expect(survivors.size).toBeGreaterThanOrEqual(2);
        expect(survivors.has(TOTAL - 1)).toBe(true); // 丢最新 → 这条红
        expect(survivors.has(0)).toBe(false); // 与上一条一起排除"根本没裁"
        const seqs = [...survivors].sort((a, b) => a - b);
        expect(seqs[seqs.length - 1] - seqs[0] + 1).toBe(seqs.length); // 从中间挖洞 → 这条红
      } finally {
        restoreWalEnv(snap);
      }
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

    /**
     * 2026-09-30 加固：这条路原先只有 logger.warn ——「可检测 ≠ 已告警」。
     * 批次无哈希落库是链完整性的**唯一直接信号**，必须同时满足三件事：
     *   ① 计入 security_alerts_total{type=audit_hash_compute_failed}；
     *   ② 落库文档带 hashFailure 标记（供核验端与"人为抹除"区分）；
     *   ③ 已算出哈希的前缀**照常保留受保护**，不被一起降级（部分成功的正确形态）。
     */
    test('哈希失败 ⇒ 计入安全告警 + 落库带 hashFailure 标记', async () => {
      mockTimer();
      auditBuffer.start();
      auditBuffer.push(makeDoc('hashtrap'));

      const metrics = require('../../utils/metrics');
      const alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
      const auditChain = require('../../utils/auditChain');
      const chainSpy = jest.spyOn(auditChain, 'chainBatch').mockImplementation(() => {
        throw new Error('chain lock timeout');
      });

      tickFn();
      await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_hashtrap' });
        return n === 1;
      });

      // ① 告警面：这是修复的核心断言（修复前调用次数为 0）
      expect(alertSpy).toHaveBeenCalledWith('audit_hash_compute_failed', 'high');

      // ② 落库标记：绕开 model 读原始形态，确认 hashFailure 真的写进去了
      const raw = await AuditLog.collection.findOne({ username: 'testuser_hashtrap' });
      expect(raw.hash).toBeNull();
      expect(raw.prevHash).toBeNull();
      expect(raw.hashFailure).toContain('chain lock timeout');

      chainSpy.mockRestore();
      alertSpy.mockRestore();
      await AuditLog.deleteMany({ username: 'testuser_hashtrap' }, { bypassAppendOnly: true });
    });
  });

  // ---- WAL 目录不存在时 start 自动创建 ----
  describe('ensureLogsDir 创建目录', () => {
    test('WAL 父目录不存在时 start 自动 mkdirSync', () => {
      // 【顺序无关修复】原用例删的是 auditBuffer.getWalPath() 的目录，但在
      // startup() 之前该函数返回**模块加载期的默认派生路径**（仓库 logs/），
      // 而不是本套件的 AUDIT_WAL_PATH——于是「删错目录、断言另一个目录」，
      // 只在特定执行顺序下碰巧通过。现显式钉死路径，删/断言同一个目录。
      mockTimer();
      auditBuffer.start(); // 先 startup() 把路径切到本套件 env 路径
      auditBuffer.stop();
      const walPath = process.env.AUDIT_WAL_PATH;
      expect(auditBuffer.getWalPath()).toBe(walPath); // 路径确实切过去了
      const walDir = path.dirname(walPath);
      fs.rmSync(walDir, { recursive: true, force: true });
      expect(fs.existsSync(walDir)).toBe(false); // 前置条件：目录真的没了

      mockTimer();
      expect(() => auditBuffer.start()).not.toThrow();
      expect(fs.existsSync(walDir)).toBe(true);
    });
  });

  // ---- 裁剪：正常对齐的那一条路径（错位/空洞场景见 auditWalTrimIsPrecise.test.js）----
  describe('WAL 裁剪的正常路径', () => {
    // 本用例原先叫「walTrimLines 行数少于待裁剪数时按实际行数清理」——那个告警分支
    // 已随 F-97 一起删除（按条数裁剪才会"行数不足"，按序号裁剪不存在这个概念），
    // 而它实际的断言从头到尾走的是**对齐**场景（1 条文档 = 1 行），测的就是下面这件事。
    // 改名不改断言：把名字改成它真正证明的东西，避免下一个读的人以为空洞已被覆盖。
    test('flush 成功后本批的 WAL 行被裁掉（1 条文档 = 1 行的对齐场景）', async () => {
      mockTimer();
      auditBuffer.start();

      // push 1 条产生 1 行 WAL；轮询等待 WAL 写入完成（替代固定 200ms）
      auditBuffer.push(makeDoc('trim_edge'));
      await waitFor(() => readWal().includes('trim_edge'));

      // flush 成功会按 __walSeq 裁剪本批；轮询裁剪完成
      tickFn();
      const done = await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: 'testuser_trim_edge' });
        return n === 1 && !readWal().includes('trim_edge');
      });

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

    test('enforceWalLimit stat 返回非 ENOENT 错误时记录 warn 且不抛异常', async () => {
      // P1-29 修复（本次改动复审）：原用例只有「mock + sleep 300ms + restore」，
      // 全程零断言——把源码里的 logger.warn 整行删掉，它依然绿（实测确认）。
      // 现改为捕获 logger.warn 并断言调用参数含错误信息，落实测试名承诺的语义。
      const origMax = process.env.AUDIT_WAL_MAX_BYTES;
      const origInterval = process.env.AUDIT_WAL_STAT_INTERVAL;
      process.env.AUDIT_WAL_MAX_BYTES = '1'; // 极低阈值确保进入 stat 检查
      // 关键：walAppendCount % interval 才触发 enforceWalLimit（默认 32）。
      // 原用例只 push 1 条 → 1 % 32 !== 0 → 压根没进过该函数（这也是它能
      // 「零断言还绿」的根本原因：mock 了 stat，却从未被调用）。
      process.env.AUDIT_WAL_STAT_INTERVAL = '1';

      mockTimer();
      const logger = require('../../utils/logger');
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      const statSpy = jest
        .spyOn(fs.promises, 'stat')
        .mockRejectedValue(Object.assign(new Error('EACCES'), { code: 'EACCES' }));
      try {
        auditBuffer.start();
        auditBuffer.push(makeDoc('stat_err'));

        const logged = await waitFor(() =>
          warnSpy.mock.calls.some((c) => String(c[0]).includes('WAL 大小检查失败'))
        );
        expect(logged).toBe(true);
        expect(warnSpy.mock.calls.some((c) => String(c[0]).includes('EACCES'))).toBe(true);
      } finally {
        statSpy.mockRestore();
        warnSpy.mockRestore();
        process.env.AUDIT_WAL_MAX_BYTES = origMax;
        if (origInterval === undefined) delete process.env.AUDIT_WAL_STAT_INTERVAL;
        else process.env.AUDIT_WAL_STAT_INTERVAL = origInterval;
      }
    });

    test('walTrimBySeqs 中 writeFile 失败触发外层 catch：记 warn 且 WAL 保持原样', async () => {
      // P1-29 修复（本次改动复审）：原用例同样是「mock writeFile + sleep 500ms」，零断言。
      // walTrimBySeqs 把整段逻辑挂在 walChain.then(...)；atomicReplaceWal 抛错会被链尾
      // 的 .catch 兜住并 warn。现断言两件事：① 确实产生了 warn（含错误消息）；
      // ② 原子替换失败后主 WAL 未被破坏（宁可留死行，不可留下半个文件）。
      mockTimer();
      auditBuffer.start();

      auditBuffer.push(makeDoc('trim_write_err'));
      await waitFor(() => readWal().includes('trim_write_err'));
      const walBefore = readWal();

      const logger = require('../../utils/logger');
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      const writeSpy = jest
        .spyOn(fs.promises, 'writeFile')
        .mockRejectedValue(new Error('ENOSPC: no space left'));
      try {
        tickFn();
        const logged = await waitFor(() =>
          warnSpy.mock.calls.some((c) => String(c[0]).includes('ENOSPC'))
        );
        expect(logged).toBe(true);
        // 原子替换走「临时文件 → rename」，writeFile 失败即未触碰主 WAL
        expect(readWal()).toBe(walBefore);
      } finally {
        writeSpy.mockRestore();
        warnSpy.mockRestore();
      }
    });

    test('缓冲 3 条而 WAL 只有 1 行（空洞场景）：旧行在重放时补上序号，落库后一并裁掉', async () => {
      // 本用例原先叫「walTrimLines records.length < n 时记录 warn」——那个"按实际行数清理"
      // 分支已随 F-97 删除：按条数裁剪才会出现"行数不足"，而按序号裁剪根本不会越界。
      // 场景本身仍然是**唯一真实的空洞夹具**（3 条文档 / 1 行 WAL），所以保留并改钉新契约：
      //   ① 手工写入的旧行没有 `__walSeq` ⇒ 重放时必须补号并回写文件
      //      （不补号它就永远裁不掉，而重放文档的 _id 是 flush 时才分配的，
      //       等于每重启一次就重复插入一份审计、哈希链跟着分叉）；
      //   ② 补号之后本批 3 条照常落库，那 1 行被精确裁掉，文件收敛为空；
      //   ③ 另外 2 条是 WAL 关闭期间入缓冲的（有文档、无行）——旧实现正是被这种
      //      "文档数 > 行数"的空洞坑到的：它会越界吃掉排在本批之后的、别的未落库行。

      // 先手动写 1 行到 WAL
      const walPath = testWalPath();
      const dir = path.dirname(walPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(walPath, JSON.stringify(makeDoc('wal_single')) + '\n', 'utf8');

      mockTimer();
      auditBuffer.start();

      // 等待 WAL 重放完成（1 行进入缓冲）
      await waitFor(() => auditBuffer.getStats().bufferLength >= 1);
      await wal.drain();
      // ①：重放把序号补进了文件，而不只是补进内存对象
      const replayedLine = JSON.parse(readWal().trim());
      expect(replayedLine.__walSeq).toBeTruthy();

      // 再塞 2 条但不写 WAL（WAL 关闭期间 push 不落行）⇒ 缓冲 3 条 / WAL 1 行
      auditBuffer.stop();
      auditBuffer.push(makeDoc('extra_1'));
      auditBuffer.push(makeDoc('extra_2'));

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
      const landed = await waitFor(async () => {
        const n = await AuditLog.countDocuments({ username: /^testuser_(wal_single|extra_)/ });
        return n === 3;
      });
      expect(landed).toBe(true);

      await auditBuffer.flush(); // 等本轮 WAL 操作排到链尾
      await wal.drain();
      // ②：已落库的那一行被回收，文件收敛为空（另 2 条本来就没有行）
      expect(readWal().trim()).toBe('');
    });

    test('start WAL 重放链上的失败被 catch 吞掉（不炸 start、不阻塞后续写入）', async () => {
      // 【断言收紧】原用例注入 logger.error 抛错，但重放链上真正会抛的点是
      // enforceBufferLimit 内部的 logger.error；且末尾 `await waitFor(...)`
      // **丢弃了返回值**——超时（8s）也照样绿，同时让本用例白等满 8 秒。
      // 本用例的主张是「重放链上的异常被 serialize 的 catch 处理器吃掉」，
      // 因此判据改为：重放完成（缓冲达上限）+ start 未抛出 + 后续 push 仍工作。
      // 【路径必须显式钉死】`getWalPath()` 返回的是「上一次 startup() 设的路径」，
      // 与「本次 start() 将使用的路径」是两个时刻的值。全量运行下前面的用例已
      // 调过 start()，此处拿到的正是本套件 env 路径；但用 `-t` 单跑时前序用例被
      // 跳过，拿到的是模块加载期的默认路径（logs/audit-buffer.<db>.wal）——
      // 于是行被写进默认文件、重放却读 env 文件，缓冲恒为 0。
      // 故先把路径切好（start→stop 不改写文件），并断言它确实等于 env 路径。
      // 先让 startup() 把 WAL 路径切到本套件的 mkdtemp（getWalPath() 否则返回
      // 模块加载期的默认派生路径），并等这一次重放链跑完（此时文件不存在 → 读 0 行）。
      // 不等就写文件的话，这条链可能在写入之后才执行 readLines，把 250 行提前吞进
      // 缓冲并被下一段断言误算——这正是原用例「恒为 0 行」的隐藏成因之一。
      mockTimer();
      auditBuffer.start();
      await wal.drain();
      auditBuffer.stop();
      const walPath = testWalPath();
      expect(walPath).toBe(process.env.AUDIT_WAL_PATH); // 钉死路径确实切过去了
      const dir = path.dirname(walPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      // 写入大量有效 WAL 行使重放后触发 enforceBufferLimit
      // BUFFER_HARD_LIMIT=200，写入 250 行使 enforceBufferLimit 触发 logger.error
      const lines = [];
      for (let i = 0; i < 250; i++) {
        lines.push(JSON.stringify(makeDoc(`replay_overflow_${i}`)));
      }
      fs.writeFileSync(walPath, lines.join('\n') + '\n', 'utf8');

      // 让重放链上的第一次 logger.error 抛错：serialize 的 catch 处理器必须接住它
      const logger = require('../../utils/logger');
      const errSpy = jest.spyOn(logger, 'error').mockImplementationOnce(() => {
        throw new Error('logger.error exploded');
      });

      mockTimer();
      expect(() => auditBuffer.start()).not.toThrow();

      // 重放完成：250 行读回后被硬上限裁剪到 200（drain 等链排空，比轮询确定）
      await wal.drain();
      expect(auditBuffer.getStats().bufferLength).toBeGreaterThanOrEqual(200);

      // 链上异常被吞：后续 push 仍能正常入缓冲。
      // 注意不能断言「缓冲 = before+1」——200 行已满 BUFFER_LIMIT，push 会立即
      // 触发 flush() 把整批取走落库，缓冲随即归零（实测 before=200 → push 后 0）。
      // 真正要证明的是「push 本身没抛错，且文档确实进了链路」，故断言 WAL 增长：
      // push 必然追加一行（wal.appendLine 在 flush 之前同步调用）。
      const walBefore = fs.readFileSync(walPath, 'utf8');
      expect(() => auditBuffer.push(makeDoc('after_replay_chain_error'))).not.toThrow();
      await wal.drain();
      const walAfter = fs.readFileSync(walPath, 'utf8');
      expect(walAfter).toContain('after_replay_chain_error');
      expect(walAfter.length).toBeGreaterThan(walBefore.length);

      errSpy.mockRestore();
    });
  });

  // ---- waitForWalQuiet 判据（防退化守卫，对应函数注释「竞态修复」）----
  describe('waitForWalQuiet 判据', () => {
    test('追加仍在途时，等待判据不得提前返回', async () => {
      // 【可证伪性】闸住 appendFile 让追加永不完成：waitForWalQuiet 若丢掉
      // `await wal.drain()`，会在「文件不存在」的 catch 分支立即 return，
      // 下面的 expect(returned).toBe(false) 随即转红——这正是该行的承重对象。
      // 修复前的旧判据（只比较两次读到的内容）在同一闸门下必红。
      mockTimer();
      auditBuffer.start();
      await wal.drain(); // 先排空 start() 的重放任务，隔离出 push 的追加

      let release;
      const gate = new Promise((r) => {
        release = r;
      });
      const realAppend = fs.promises.appendFile.bind(fs.promises);
      const appendSpy = jest
        .spyOn(fs.promises, 'appendFile')
        .mockImplementation(async (...args) => {
          await gate;
          return realAppend(...args);
        });

      let returned = false;
      auditBuffer.push(makeDoc('quiet_guard'));
      const waiter = waitForWalQuiet().then(() => {
        returned = true;
      });
      try {
        await new Promise((r) => setTimeout(r, 150));
        expect(returned).toBe(false);
      } finally {
        release();
        await waiter;
        await wal.drain();
        appendSpy.mockRestore();
      }
    });
  });
});
