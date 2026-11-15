/**
 * cluster primary 的崩溃退避判据与 CLUSTER_WORKERS 配置告警（审计 2026-11-15）
 *
 * 钉两类回归：
 *   ① 退避判据与日志自相矛盾——worker 活过稳定窗（偶发崩溃）时，原先带着清零后的
 *      crashStreak=0 落进退避公式，算出 500ms 伪退避并打出「短命连发 ×0（存活
 *      …ms < 稳定窗 …ms）」。修复后：活过稳定窗 ⇒ 立即补 fork、不打短命日志。
 *   ② CLUSTER_WORKERS 非法值/超上限原先静默收敛（回落 1 / 夹取 16），运维无从
 *      得知配置没按写的生效。修复后：primary 出声告警（单进程入口同样出声）。
 *
 * cluster 模块用工厂 mock + 文件级共享状态（同 bcryptWorkerPoolCrashFallback 的
 * mockPoolState 形态）：cluster.js 在每个用例里经 resetModules 重新加载，
 * mock 工厂闭包引用同一份状态，断言不依赖 mock 实例身份。
 */

const mockClusterState = { listeners: {}, forkCalls: 0 };

jest.mock('cluster', () => ({
  isPrimary: true,
  setupPrimary: () => {},
  fork: () => {
    mockClusterState.forkCalls += 1;
    return { id: mockClusterState.forkCalls, process: { pid: 2000 + mockClusterState.forkCalls } };
  },
  on: (ev, cb) => {
    (mockClusterState.listeners[ev] = mockClusterState.listeners[ev] || []).push(cb);
  },
  workers: {},
}));

jest.mock('../index', () => {});
jest.mock('../config/secrets', () => ({ hydrateSecretsFromFiles: jest.fn() }));

describe('cluster 崩溃退避与 CLUSTER_WORKERS 配置（审计 2026-11-15）', () => {
  const load = () => {
    jest.resetModules();
    return require('../cluster');
  };

  beforeEach(() => {
    mockClusterState.listeners = {};
    mockClusterState.forkCalls = 0;
    delete process.env.CLUSTER_WORKERS;
  });

  afterEach(() => {
    jest.useRealTimers();
    delete process.env.CLUSTER_WORKERS;
  });

  test('CLUSTER_WORKERS 非法值：回落单进程并出声告警（不再静默）', () => {
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.CLUSTER_WORKERS = 'abc';
    load();
    const logged = errSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(logged).toContain('CLUSTER_WORKERS');
    expect(logged).toContain('abc');
    expect(logged).toContain('单进程');
    errSpy.mockRestore();
  });

  test('CLUSTER_WORKERS 超上限：夹取到 16 并告警', () => {
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.CLUSTER_WORKERS = '99';
    load();
    expect(mockClusterState.forkCalls).toBe(16);
    const logged = errSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(logged).toContain('超过上限 16');
    errSpy.mockRestore();
  });

  test('存活超过稳定窗的退出：立即补 fork，不再打自相矛盾的「短命连发 ×0」', () => {
    jest.useFakeTimers();
    const logSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.CLUSTER_WORKERS = '2';
    load();
    const forkListener = mockClusterState.listeners.fork[0];
    const exitListener = mockClusterState.listeners.exit[0];
    const worker = { id: 42, process: { pid: 4242 } };
    forkListener(worker);
    jest.advanceTimersByTime(15000); // 存活 15s ≥ 稳定窗 10s：偶发崩溃
    const forksBefore = mockClusterState.forkCalls;
    exitListener(worker, 1, null);
    // 修复前：crashStreak 清零后仍落退避公式 ⇒ 500ms 伪退避 + 「短命连发 ×0」日志
    expect(mockClusterState.forkCalls).toBe(forksBefore + 1);
    const logged = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(logged).not.toContain('短命连发 ×0');
    logSpy.mockRestore();
  });

  test('稳定窗内的短命退出：仍按指数退避补 fork（退避语义不变）', () => {
    jest.useFakeTimers();
    const logSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.CLUSTER_WORKERS = '2';
    load();
    const forkListener = mockClusterState.listeners.fork[0];
    const exitListener = mockClusterState.listeners.exit[0];
    const worker = { id: 43, process: { pid: 4343 } };
    forkListener(worker);
    exitListener(worker, 1, null); // 存活 ~0ms
    const logged = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(logged).toContain('短命连发 ×1');
    expect(mockClusterState.forkCalls).toBe(2); // 2 个初始 worker，退避尚未到期
    jest.advanceTimersByTime(1000);
    expect(mockClusterState.forkCalls).toBe(3); // 退避到期后补 fork
    logSpy.mockRestore();
  });
});
