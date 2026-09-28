'use strict';

/**
 * F-98：`logShipper.close()` 必须把缓冲**排空**，而不是只冲一批
 *
 * 缺陷（台账 §4.2 [报]，本轮实测成立）：`_flush()` 每次只 `splice(0, batchSize)`
 * 发一批（默认 100），而 `close()` 只调用它**一次**就返回。SIEM 后端慢到让串行闩
 * （P3-31 的 `_flushing`）挡住定时器冲刷时，关停那一刻缓冲里可以堆着
 * 远超一批的量（上限 `BUFFER_CAP = 5000`）——进程随即退出，
 * 剩下的行**无声消失**。失败路径至少有节流告警，这条什么都没有，
 * 而关停瞬间丢的往往正是"为什么关停"的那条线索。
 *
 * 修法：`close()` 按批排空，仍受同一个 deadline 约束（后端挂掉不得把退出流程卡死），
 * 排不空时**如实报剩余行数**（不是缓冲上限）。
 *
 * 三条用例的分工：
 *   ① 能送达时必须全部送达（旧实现：5 行只发 2 行 ⇒ 本条红）；
 *   ② 送不出去时要在预算内返回，且报的是**剩余 5 行**这个数字；
 *   ③ 排空过程不得把行序打乱（SIEM 侧靠行序重建事件，失败批次 unshift 回头部）。
 */

// 定时器换成捕获不执行：构造期起的 interval 不该在本套件里真的触发冲刷，
// 否则"close 排空"与"定时器排空"两条路径混在一起，测不到想测的那条。
let tickFn = null;
const intervalSpy = jest.spyOn(global, 'setInterval').mockImplementation((cb) => {
  tickFn = cb;
  return { unref: jest.fn() };
});

const { HttpShipperTransport } = require('../../utils/logShipper');

afterAll(() => intervalSpy.mockRestore());

function makeTransport(overrides = {}) {
  return new HttpShipperTransport({
    url: 'http://127.0.0.1:59999/logs',
    batchSize: 2,
    intervalMs: 600000, // 大到定时器等不到，只能由 close() 触发（轮数确定）
    timeoutMs: 300, // deadline = 1300ms，测试不会挂住
    ...overrides,
  });
}

describe('logShipper.close() 排空缓冲（F-98）', () => {
  let errSpy;
  beforeEach(() => {
    tickFn = null;
    errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => errSpy.mockRestore());

  test('① 后端可用：5 行分 3 批全部送达，缓冲清空（旧实现只冲第一批就返回）', async () => {
    const t = makeTransport();
    const sent = [];
    t._post = async (batch) => {
      sent.push([...batch]);
    };
    for (let i = 0; i < 5; i += 1) t.buffer.push(`line-${i}`);

    // 前提自证：一次定时 tick 只发**一批**（这就是缺陷的机制），
    // 所以"close() 也只冲一批"必然是会丢的——不是我把断言写严了。
    expect(typeof tickFn).toBe('function');
    tickFn();
    await new Promise((resolve) => setImmediate(resolve));
    expect(sent).toEqual([['line-0', 'line-1']]);
    expect(t.buffer).toHaveLength(3);

    await t.close();

    expect(sent.flat()).toEqual(['line-0', 'line-1', 'line-2', 'line-3', 'line-4']);
    expect(sent).toHaveLength(3); // 2 + 2 + 1：证明是**排空**而不是恰好一批装得下
    expect(t.buffer).toHaveLength(0);
    expect(errSpy).not.toHaveBeenCalled();
  });

  test('② 后端不可达：在预算内返回，并如实报"还剩几行"（不是缓冲上限）', async () => {
    const t = makeTransport();
    t._post = async () => {
      throw new Error('ECONNREFUSED');
    };
    for (let i = 0; i < 5; i += 1) t.buffer.push(`line-${i}`);

    const started = Date.now();
    await t.close();
    const elapsed = Date.now() - started;

    // 有界退出：timeoutMs + 1000 = 1300ms 的预算，留一点调度余量
    expect(elapsed).toBeLessThan(3000);
    expect(t.buffer).toHaveLength(5); // 一行都没送出去，也一行都没被静默吞掉
    const logged = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toContain('仍有 5 行未送达');
    expect(logged).not.toContain('5000'); // 不得把"缓冲容量"说成"丢失数量"
  });

  test('③ 中途恢复：失败批次回到头部，行序不得错乱', async () => {
    const t = makeTransport();
    let attempts = 0;
    const sent = [];
    t._post = async (batch) => {
      attempts += 1;
      if (attempts === 1) throw new Error('transient'); // 第一批失败
      sent.push(...batch);
    };
    for (let i = 0; i < 4; i += 1) t.buffer.push(`l${i}`);

    await t.close();

    expect(sent).toEqual(['l0', 'l1', 'l2', 'l3']);
    expect(t.buffer).toHaveLength(0);
  });
});
