/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：src/utils/metrics.js 的 `methodLabelOf`（method 标签闭集化）
 * 守护的不变式：请求行里的 method 是**客户端完全可控**的 token，它绝不能
 *   决定 series 数量——闭集外的动词一律归 `OTHER`，只保留"存在非标准方法"
 *   这一个信号。
 *
 * 缺陷形状（修复前实测）：`method: (req.method || 'GET').toUpperCase()`。
 *   Node 的 HTTP 解析器接受任意扩展方法，于是 `FOO1`、`FOO2`… 每个新动词
 *   都是一条新 series；MAX_SERIES（5000/每 store）被打满后，**真实流量**的
 *   route/status 新 series 被静默丢弃（`canAddSeries` 只保留已存在的 series），
 *   监控因此对事故失明。攻击成本仅几千个请求。
 *
 * 可证伪性：本文件的断言全部落在**外部可观测物**（`_counters` / `_histograms`
 *   的 labelsKey）上，不读被测模块内部实现细节：
 *   - 把 `methodLabelOf` 改回 `String(method).toUpperCase()` → 「200 个不同动词
 *     只产生 1 条 OTHER series」转红（会看到 200 条）；
 *   - 把闭集里删掉 `PATCH`（改成归 OTHER）→ 「标准方法保留原样」转红；
 *   - 把归一放在渲染期而不是采集期（文本 OTHER、快照原值）→ 本文件读的是
 *     采集期的 key，同样转红（两视图口径必须同源）。
 * 顺序无关：每个用例进 beforeEach 全量清空 requests/duration 两个 store。
 * ──────────────────────────────────────────────────────────────────────────
 */

const metrics = require('../../utils/metrics');

/** 造一个最小 req：无 route ⇒ route 标签走 'unmatched'（与真实 404 同口径） */
const makeReq = (method) => ({ method, baseUrl: '', url: '/probe', route: undefined });

/** 造一个只提供 on('finish') 的 res：metricsMiddleware 只依赖这一个事件 */
const makeRes = (statusCode = 200) => {
  const handlers = {};
  return {
    statusCode,
    on(event, fn) {
      handlers[event] = fn;
    },
    fireFinish() {
      if (handlers.finish) handlers.finish();
    },
  };
};

/** 走一次完整的采集中间件（含 finish 回调），返回本次产生的 labelsKey */
const hit = (method, statusCode = 200) => {
  const req = makeReq(method);
  const res = makeRes(statusCode);
  metrics.metricsMiddleware(req, res, () => {});
  res.fireFinish();
};

/** 当前 requests store 的所有 labelsKey */
const requestKeys = () => [...metrics._counters.keys()];

describe('method 标签闭集化（高基数标签防泄漏）', () => {
  beforeEach(() => {
    metrics._counters.clear();
    metrics._histograms.clear();
  });

  test('标准方法原样保留：GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS', () => {
    for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
      hit(m);
    }
    const keys = requestKeys();
    for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
      expect(keys.some((k) => k.includes(`method="${m}"`))).toBe(true);
    }
    // 七个标准方法各一条，且没有一条被归到 OTHER
    expect(keys).toHaveLength(7);
    expect(keys.some((k) => k.includes('method="OTHER"'))).toBe(false);
  });

  test('小写/混合大小写归一到同一标准方法（不会因大小写另开 series）', () => {
    hit('get');
    hit('GeT');
    const keys = requestKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain('method="GET"');
  });

  test('闭集外的动词一律归 OTHER：200 个不同动词只产生 1 条 series', () => {
    const weird = Array.from({ length: 200 }, (_, i) => `FOO${i}`);
    for (const m of weird) hit(m);

    const keys = requestKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain('method="OTHER"');
    // 计数器累计了 200 次，但 series 只有 1 条——这才是"闭集"的含义
    expect(metrics._counters.get(keys[0])).toBe(200);
  });

  test('延迟直方图与计数器同口径：OTHER 在 duration store 里也只有一条', () => {
    for (const m of ['BAR1', 'BAR2', 'BAR3']) hit(m);
    const histKeys = [...metrics._histograms.keys()];
    expect(histKeys).toHaveLength(1);
    expect(histKeys[0]).toContain('method="OTHER"');
  });

  test('防御性：method 缺失/空串时按 GET 处理，不产生 method="" 的畸形 series', () => {
    hit(undefined);
    hit('');
    const keys = requestKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain('method="GET"');
    expect(keys.some((k) => k.includes('method=""'))).toBe(false);
  });

  test('高基数动词打不满 MAX_SERIES：store 规模与动词种类数无关', () => {
    const cap = metrics._MAX_SERIES;
    // 用远超上限的动词种类数（但只发 300 次，避免用例变慢）
    for (let i = 0; i < 300; i += 1) hit(`X-METHOD-${i}`);
    expect(metrics._counters.size).toBe(1);
    // 且没有触发"丢弃新 series"这条兜底（触发说明闭集失效）
    expect(metrics._droppedSeries.get('requests') || 0).toBe(0);
    expect(metrics._counters.size).toBeLessThan(cap);
  });
});
