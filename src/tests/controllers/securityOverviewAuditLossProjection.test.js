/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：GET /api/security/overview 的 compliance.auditLoss 投影
 * 守护的不变式：
 *   1) WAL 里"解析不出取证文档"的行数（walCorruptLines）必须原样出现在合规面板上，
 *      值取自 auditBuffer.getStats()，不得写死、不得因 0 而缺省；
 *   2) 控制器在投影里读取的**每一个键**都必须在真实 getStats() 的形状里存在；
 *   3) 反过来，真实 getStats() 里每一个"取证计数"键都必须被投影读到（F-146）。
 *
 * 为什么要有第 2 条（本文件存在的核心理由）：
 *   既有的控制器用例把 auditBuffer 整体桩掉，而 jest 的 toEqual 会**忽略值为
 *   undefined 的键** ⇒ 桩里少一个字段、或真 getStats() 少一个字段，用例照样绿。
 *   这条失踪路径的代价是合规口径上的静默低估：那些行不会重放、也因带不走
 *   __walSeq 而永远不会被裁剪，每次重启原地重复出现，面板却报 0。
 *   第 2 条用 Proxy 记录控制器读了哪些键，再去**未 mock** 的真实 getStats() 里
 *   逐个核对，把"夹具不忠于生产形状"这一类缺陷从根上堵住。
 *
 * 为什么还要第 3 条：第 2 条是单向子集，投影**漏读**一个键时 reads 只是变小，
 * 子集照样成立 ⇒ 面板少一项而用例全绿，这正是本仓反复出现的"有指标、无出口"。
 * 判据按命名约定（`wal*Lines` / `wal*Failures`，缓冲侧两个历史键点名）从真实形状里
 * 生成，不在测试里抄一份键名清单；第 4 条用例再证明这个约定本身有牙。
 *
 * 可证伪性：必须红的变异方向——删掉投影那一行 / 投影改读一个不存在的源字段 /
 *   从真实 getStats() 里撤掉 walCorruptLines / 给 getStats() 加一个 wal*Failures
 *   计数但不投影（F-146 实测：只有第 3 条红）。
 * ──────────────────────────────────────────────────────────────────────────
 */

// ===== mock 声明区（必须在 require 控制器之前）=====

const mockGetSecurityOverview = jest.fn();
jest.mock('../../services/securityAlert', () => ({
  getSecurityOverview: (...args) => mockGetSecurityOverview(...args),
}));

const mockGetStats = jest.fn();
jest.mock('../../services/auditBuffer', () => ({
  isWalEnabled: () => true,
  getStats: (...args) => mockGetStats(...args),
}));

jest.mock('../../services/auditMonitor', () => ({
  isRunning: () => true,
  getHealth: () => ({ runs: 1, failures: 0, consecutiveFailures: 0, skippedOverlaps: 0 }),
}));

jest.mock('../../utils/auditChain', () => ({
  getLatestHash: () => Promise.resolve('tail-hash'),
}));

// asyncHandler 直接返回原函数，便于裸调用
jest.mock('../../middleware/errorHandler', () => ({
  asyncHandler: (fn) => fn,
}));

const { getSecurityOverview } = require('../../controllers/securityController');

// ===== 夹具 =====

/**
 * 缓冲侧（非 WAL 层）的"取证计数"键名。它们不符合 `wal*Lines` / `wal*Failures`
 * 的命名约定，只能逐个点名——点名处越少越好，所以 WAL 层的键一律走命名判据。
 * 新增一个 WAL 计数键时**不需要**动这里：命名判据会自动要求它被投影。
 */
const LEGACY_LOSS_KEYS = ['droppedCount', 'outageFailures'];

/** 一个键是不是"合规面板必须报出来的取证计数"——判据只写这一处，用例全部复用它 */
const isLossCounterKey = (k) => /^wal.*(Lines|Failures)$/.test(k) || LEGACY_LOSS_KEYS.includes(k);
const lossCounterKeys = (keys) => keys.filter(isLossCounterKey);
const realStatsKeys = () =>
  Object.keys(jest.requireActual('../../services/auditBuffer').getStats());

const overviewShape = () => ({
  criticalAlerts: 0,
  highAlerts: 0,
  failedLogins: 0,
  unusualAccess: 0,
  riskScore: 0,
});

const makeCtx = () => {
  const res = {
    statusCode: null,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.payload = data;
      return this;
    },
  };
  return { req: {}, res, next: jest.fn() };
};

/** 用 Proxy 记下控制器投影读了 stats 的哪些键 */
const readTracker = () => {
  const reads = new Set();
  const stats = new Proxy(
    {},
    {
      get(_target, key) {
        if (typeof key === 'string') reads.add(key);
        return 0;
      },
    }
  );
  return { stats, reads };
};

describe('合规面板 auditLoss 投影（WAL 损坏行必须可见）', () => {
  beforeEach(() => {
    mockGetSecurityOverview.mockResolvedValue(overviewShape());
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test('walCorruptLines 取的是 getStats 的值，整块形状逐项对齐', async () => {
    // 夹具必须**忠于生产形状**：键取自真实 getStats()，每个键给一个可区分的值。
    // 少给一个键 ⇒ jest 的 toEqual 会忽略 undefined 键，用例照样绿而面板少一项
    // （本文件头记着的那次教训），所以这里不手写键名，从真模块的形状生成。
    const realKeys = realStatsKeys();
    const fixture = {};
    realKeys.forEach((k, i) => {
      fixture[k] = k === 'walEnabled' ? true : i + 1;
    });
    mockGetStats.mockReturnValue(fixture);
    const { req, res, next } = makeCtx();
    await getSecurityOverview(req, res, next);

    expect(res.statusCode).toBe(200);
    // 没走 compliance 的 catch 降级（否则断言的是 {error} 形状，等于什么都没测）
    expect(res.payload.data.compliance.error).toBeUndefined();
    // 逐项对齐：值必须来自 fixture 的同一处，集合必须恰好是"取证计数"那一组
    const expected = {};
    realKeys.forEach((k) => {
      if (isLossCounterKey(k)) expected[k] = fixture[k];
    });
    expect(res.payload.data.compliance.auditLoss).toEqual(expected);
    // （expected 完全由判据生成 ⇒ 面板混进 bufferLength/walEnabled 一类运行噪声时这里就红）
  });

  test('计数为 0 时键仍在（0 ≠ 没有这条失踪路径）', async () => {
    const zeros = {};
    realStatsKeys().forEach((k) => {
      zeros[k] = k === 'walEnabled' ? true : 0;
    });
    mockGetStats.mockReturnValue(zeros);
    const { req, res, next } = makeCtx();
    await getSecurityOverview(req, res, next);

    const loss = res.payload.data.compliance.auditLoss;
    expect(loss).toHaveProperty('walCorruptLines', 0);
    expect(loss).toHaveProperty('walAppendFailures', 0);
    expect(Object.keys(loss).sort()).toEqual(lossCounterKeys(Object.keys(zeros)).sort());
  });

  test('投影读到的每个键都在真实 getStats() 形状里，且每个"取证计数"都被读', async () => {
    const { stats, reads } = readTracker();
    mockGetStats.mockReturnValue(stats);
    const { req, res, next } = makeCtx();
    await getSecurityOverview(req, res, next);

    expect(res.payload.data.compliance.error).toBeUndefined();
    expect(reads.has('walCorruptLines')).toBe(true);

    // 真模块（绕过上面的 jest.mock）——投影若读了 getStats 并不具有的键，
    // 面板会显示 undefined/0 而用例全绿，这里把它钉成断言。
    const realKeys = realStatsKeys();
    for (const key of reads) {
      expect(realKeys).toContain(key);
    }

    // 反方向（F-146）：只查"读了的都存在"等于没查——**投影少读一个键**时 reads 只会变小，
    // 子集依然成立 ⇒ 面板少一项、用例全绿，而这正是"有指标、无出口"那条缺陷类本身
    // （控制器 auditLoss 上方注释写明了这一点）。实测：给 getStats() 加 walAppendFailures
    // 而不投影时，只有这条会红。
    const lossCounters = lossCounterKeys(realKeys);
    expect(lossCounters.length).toBeGreaterThanOrEqual(4);
    for (const key of lossCounters) {
      expect(reads.has(key)).toBe(true);
    }
  });

  test('命名判据本身可证伪：新计数键必须被挑出来，非计数键不得被挑出来', () => {
    // 判据是"约定"，约定也要有牙：拿一组合成键名喂给同一个谓词，
    // 断言它恰好选中所有 WAL 取证计数、且不选中缓冲长度/上限这类运行噪声。
    const synthetic = [
      'walDroppedLines',
      'walDiscardedLines',
      'walCorruptLines',
      'walAppendFailures',
      'droppedCount',
      'outageFailures',
      'bufferLength',
      'hardLimit',
      'consecutiveFailures',
      'walEnabled',
      'intervalMs',
    ];
    expect(lossCounterKeys(synthetic)).toEqual([
      'walDroppedLines',
      'walDiscardedLines',
      'walCorruptLines',
      'walAppendFailures',
      'droppedCount',
      'outageFailures',
    ]);
  });
});
