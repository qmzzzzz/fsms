/**
 * 导出并发闸（P-2）——状态机行为化测试
 *
 * 为什么要单独测这个状态机：它的失败形态都是**静默**的。
 *   · 槽位泄漏（release 少调/重复调）⇒ 上限悄悄变成 1 或 3，日志里什么都没有；
 *   · 排队者拿到槽位时 active 多加一 ⇒ 实际并发超过上限，OOM 风险回来；
 *   · 超时者被记成"已授予" ⇒ 指标显示 0 拒绝，而用户在报 429；
 *   · 环境变量写成 0 ⇒ 所有导出永久 429，比 OOM 更隐蔽。
 * 这些都不会让任何 HTTP 断言变红，只有直接驱动状态机才能钉住。
 *
 * 时间用假定时器：真实等待 30s 的用例在 CI 上不可接受，而"缩短超时到 1ms"
 * 又会被 BOUNDS 的下限钳掉（那个下限是有意的，不该为测试放宽）。
 */

'use strict';

const gate = require('../../services/exportConcurrency');
const runtimeMetrics = require('../../utils/metricsRuntime');

const ENV_KEYS = ['EXPORT_MAX_CONCURRENCY', 'EXPORT_MAX_QUEUE', 'EXPORT_QUEUE_TIMEOUT_MS'];

describe('导出并发闸（P-2）', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
    for (const key of ENV_KEYS) delete process.env[key];
    gate.__resetForTest();
    runtimeMetrics.__resetForTest();
  });

  afterEach(() => {
    gate.__resetForTest();
    runtimeMetrics.__resetForTest();
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedEnv[key];
    }
    jest.useRealTimers();
  });

  test('上限内直接授予：inflight 随申请/释放增减', async () => {
    const release1 = await gate.acquireExportSlot();
    expect(gate.snapshot().inflight).toBe(1);
    const release2 = await gate.acquireExportSlot();
    expect(gate.snapshot().inflight).toBe(2);

    release1();
    expect(gate.snapshot().inflight).toBe(1);
    release2();
    expect(gate.snapshot().inflight).toBe(0);
  });

  test('超限排队：释放一个槽位后排队者被授予，且 active 不越过上限', async () => {
    const r1 = await gate.acquireExportSlot();
    const r2 = await gate.acquireExportSlot();
    expect(gate.snapshot().inflight).toBe(2);

    const third = gate.acquireExportSlot();
    expect(gate.snapshot()).toMatchObject({ inflight: 2, queued: 1 });

    r1();
    const r3 = await third;
    // 槽位是**移交**：active 应保持 2，而不是 3
    expect(gate.snapshot()).toMatchObject({ inflight: 2, queued: 0 });

    r2();
    r3();
    expect(gate.snapshot().inflight).toBe(0);
  });

  test('队列已满：立即拒绝（queue_full），不占用连接等待', async () => {
    process.env.EXPORT_MAX_CONCURRENCY = '1';
    process.env.EXPORT_MAX_QUEUE = '1';
    const r1 = await gate.acquireExportSlot();
    const queued = gate.acquireExportSlot(); // 占满队列
    expect(gate.snapshot().queued).toBe(1);

    await expect(gate.acquireExportSlot()).rejects.toMatchObject({
      name: 'ExportBusyError',
      code: 'EXPORT_BUSY',
      reason: 'queue_full',
    });
    expect(gate.snapshot().rejected.queue_full).toBe(1);
    // 指标侧同一事实：拒绝必须可观测（否则运维只看到用户报错）
    expect(runtimeMetrics.getExportSnapshot().rejected.queue_full).toBe(1);

    r1();
    (await queued)();
  });

  test('排队超时：拒绝（timeout）并把自己从队列里摘掉', async () => {
    jest.useFakeTimers();
    process.env.EXPORT_MAX_CONCURRENCY = '1';
    process.env.EXPORT_MAX_QUEUE = '2';
    const r1 = await gate.acquireExportSlot();
    const waiting = gate.acquireExportSlot();
    expect(gate.snapshot().queued).toBe(1);

    jest.advanceTimersByTime(30000);
    await expect(waiting).rejects.toMatchObject({ reason: 'timeout' });
    expect(gate.snapshot()).toMatchObject({ queued: 0, inflight: 1 });
    expect(gate.snapshot().rejected.timeout).toBe(1);
    // 超时者不得占用指标上的 inflight（否则"在途"会长期虚高）
    expect(runtimeMetrics.getExportSnapshot().inflight).toBe(1);

    r1();
    jest.useRealTimers();
  });

  test('释放幂等：重复调用不会把上限悄悄放大', async () => {
    const release = await gate.acquireExportSlot();
    const second = await gate.acquireExportSlot();
    release();
    release(); // 模拟 finally 被包了两层
    expect(gate.snapshot().inflight).toBe(1); // 只该减一次（减两次会变 0）

    // 反向对照：上限仍是 2。再申请一个**刚好占满**（2），再申请才排队。
    // 若重复释放真的减了两次，第一个申请会从 0 直接到 1、第二个到 2 也不排队，
    // 这里两条断言会同时红。
    const third = await gate.acquireExportSlot();
    expect(gate.snapshot().inflight).toBe(2);
    const fourth = gate.acquireExportSlot();
    expect(gate.snapshot().queued).toBe(1);

    second();
    (await fourth)();
    third();
    expect(gate.snapshot().inflight).toBe(0);
  });

  test('环境变量钳制：0 抬到 1、超大压到 8、非法值退回默认', async () => {
    process.env.EXPORT_MAX_CONCURRENCY = '0';
    expect(gate.currentLimits().max).toBe(1); // 0 会让导出永久 429，必须抬到可用下界
    process.env.EXPORT_MAX_CONCURRENCY = '100';
    expect(gate.currentLimits().max).toBe(8);
    process.env.EXPORT_MAX_CONCURRENCY = 'abc';
    expect(gate.currentLimits().max).toBe(gate.DEFAULTS.max);
    process.env.EXPORT_MAX_CONCURRENCY = '3';
    expect(gate.currentLimits().max).toBe(3);
  });

  test('指标文本恒定输出三项（含 0）：从没拒绝过 ≠ 没上报这个指标', () => {
    const text = runtimeMetrics.formatRuntime().join('\n');
    expect(text).toContain('export_inflight 0');
    expect(text).toContain('export_queued 0');
    for (const reason of gate.REJECT_REASONS) {
      expect(text).toContain(`export_rejected_total{reason="${reason}"} 0`);
    }
  });

  test('JSON 快照与文本同源：同一时刻两处读数一致', async () => {
    process.env.EXPORT_MAX_CONCURRENCY = '1';
    const release = await gate.acquireExportSlot();
    const queued = gate.acquireExportSlot();

    const snap = runtimeMetrics.getExportSnapshot();
    expect(snap).toMatchObject({ inflight: 1, queued: 1 });
    const text = runtimeMetrics.formatRuntime().join('\n');
    expect(text).toContain('export_inflight 1');
    expect(text).toContain('export_queued 1');

    release();
    (await queued)();
  });
});
