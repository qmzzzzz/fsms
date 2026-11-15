/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：src/utils/metrics.js 的「兜底机制自身不可观测」与「缺省标签两视图异名」
 *
 * 两处缺陷的共同点：都发生在**异常路径**上，所以正常运行时永远看不见，
 * 真出问题时又恰好是运维最需要数据的那一刻：
 *
 *  1) series 上限（MAX_SERIES）丢弃新 series 时只有一条 warn-once 日志。
 *     文本与快照都只反映"活下来的 series"——被砍掉的那批看起来跟"本来就不存在"
 *     一模一样：route 列表少了、错误率的分子分母少了，面板照常画满格。
 *     沉默的兜底比没有兜底更危险：它会让人以为兜底没在起作用。
 *  2) 调用方漏传的标签在两个视图里口径不同：文本走 String(undefined)
 *     → level="undefined"，快照的 collectSeries 走 `|| 'unknown'` → level="unknown"。
 *     而告警规则吃 /metrics 文本、管理面板吃 JSON 快照 ⇒ 同一条 series 两套名字，
 *     照着一边写的规则在另一边永远匹配不上。
 *
 * 可证伪性：每行只钉一个单点变异（变异归因表见
 *   deliverables/AGENT工作总账与待办-2026-09-21.md §50.3）。
 * 顺序无关：所有用例进 beforeEach 全量重置，不依赖文件内先后。
 * ──────────────────────────────────────────────────────────────────────────
 */

const metrics = require('../utils/metrics');
const logger = require('../utils/logger');

const CAP = metrics._MAX_SERIES;

/** 五个 store 的对外名字：文本与快照共用，也是本文件的断言基准 */
const STORES = metrics._SERIES_STORES; // ['requests','duration','alerts','login','mfa']

/** 抓出某 metric 家族的全部样本行（'# HELP/# TYPE' 不以该名开头，天然排除） */
const samples = (prefix) =>
  metrics
    .formatPrometheus()
    .split('\n')
    .filter((line) => line.startsWith(prefix));

const droppedText = () => samples('metrics_series_dropped_total');

/** 打满一个 store：CAP+extra 个互不相同的标签值 */
const fill = (store, extra, labelPrefix) => {
  for (let i = 0; i < CAP + extra; i++) {
    if (store === 'alerts') metrics.incSecurityAlert(`${labelPrefix}_${i}`, 'high');
    else metrics.incLoginAttempt(`${labelPrefix}_${i}`);
  }
};

describe('metrics：截断可见性与缺省标签口径', () => {
  // "打满 store" 是这些用例的正常手段，逐 store 的 warn 会刷屏：每条用例装一层
  // 静默 spy、用完卸下。
  //
  // 为什么装在 beforeEach 而不是 beforeAll：jest.spyOn 命中"属性已经是 mock"时
  // 复用同一个 mock 对象，call 记录跨用例累积——实测在 beforeAll 版里，断言
  // "逐 store 各喊一次"的那条用例会数到全文件的前 5 次（不是它自己的 2 次）。
  let warnSpy;
  beforeEach(() => {
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    // 内部结构存在才清理（实现换型后这些字段可能不再是这些 Map）：隔离不能依赖
    // 内部形状，断言侧已全部锚在外部可见面（formatPrometheus 文本 / getSnapshot 快照）
    for (const coll of [
      metrics._counters,
      metrics._histograms,
      metrics._alertCounters,
      metrics._alertLabels,
      metrics._loginCounters,
      metrics._mfaCounters,
      metrics._droppedSeries,
      metrics._seriesLimitWarned,
    ]) {
      if (coll && typeof coll.clear === 'function') coll.clear();
    }
  });
  afterEach(() => warnSpy.mockRestore());

  describe('缺省标签必须在两个视图同口径（unknown）', () => {
    test('level=undefined：文本与快照都是 unknown，不再一个 undefined 一个 unknown', () => {
      metrics.incSecurityAlert('probe', undefined);

      expect(samples('security_alerts_total')).toEqual([
        'security_alerts_total{type="probe",level="unknown"} 1',
      ]);
      expect(metrics.getSnapshot().alerts).toEqual(
        expect.arrayContaining([{ type: 'probe', level: 'unknown', count: 1 }])
      );
      // 反向：文本里不得再出现 "undefined" 这个标签值
      expect(metrics.formatPrometheus()).not.toMatch(/level="undefined"/);
    });

    test('level=null 归一为 unknown（而非 String(null)="null"）', () => {
      metrics.incSecurityAlert('null', null);
      expect(samples('security_alerts_total')).toEqual([
        'security_alerts_total{type="null",level="unknown"} 1',
      ]);
    });

    test('level=空串归一，且与 undefined 合并成同一条 series', () => {
      metrics.incSecurityAlert('empty', '');
      metrics.incSecurityAlert('empty', undefined);

      // 经快照（公开面）断言合并结果：一条 series、计数 2
      expect(metrics.getSnapshot().alerts).toEqual([{ type: 'empty', level: 'unknown', count: 2 }]);
    });

    test('incLoginAttempt 入口同样归一（不依赖调用方传全枚举）', () => {
      metrics.incLoginAttempt(undefined);
      expect(samples('auth_login_total')).toEqual(['auth_login_total{result="unknown"} 1']);
    });

    test('incMfaAction 入口同样归一', () => {
      metrics.incMfaAction(null);
      expect(samples('auth_mfa_total')).toEqual(['auth_mfa_total{action="unknown"} 1']);
    });

    test('反向保护：正常字面量标签原样透传（归一不得变成改写在范围内）', () => {
      metrics.incSecurityAlert('audit_write_failed', 'critical');
      metrics.incLoginAttempt('failure');
      expect(samples('security_alerts_total')).toEqual([
        'security_alerts_total{type="audit_write_failed",level="critical"} 1',
      ]);
      expect(samples('auth_login_total')).toEqual(['auth_login_total{result="failure"} 1']);
    });
  });

  describe('series 上限截断必须可观测', () => {
    test('未打满：五个 store 各一行且为 0——"缺席"与"为 0"在 PromQL 里是两种状态', () => {
      metrics.incSecurityAlert('low', 'high');

      expect(droppedText()).toEqual(
        STORES.map((s) => `metrics_series_dropped_total{store="${s}"} 0`)
      );
      const series = metrics.getSnapshot().series;
      expect(Object.keys(series.dropped).sort()).toEqual([...STORES].sort());
      expect(series.droppedTotal).toBe(0);
    });

    test('文本与快照的 store 集合、数值逐一对齐（两视图不得各说各话）', () => {
      fill('alerts', 7, 'x');
      fill('login', 3, 'y');

      const fromText = {};
      for (const line of droppedText()) {
        const [, store, value] = line.match(/store="(\w+)"\} (\d+)$/) || [];
        fromText[store] = Number(value);
      }
      expect(fromText).toEqual(metrics.getSnapshot().series.dropped);
      expect(Object.keys(fromText).sort()).toEqual([...STORES].sort());
    });

    test('打满后新增被丢弃 ⇒ 逐 store 计数（不是全局一个数）', () => {
      fill('alerts', 7, 'a');
      fill('login', 3, 'l');

      // 活下来的 series 数经 /metrics 文本观察：alerts/login 各保留 CAP 条
      expect(samples('security_alerts_total')).toHaveLength(CAP);
      expect(samples('auth_login_total')).toHaveLength(CAP);
      // 丢弃计数经快照（与文本同源）观察
      const dropped = metrics.getSnapshot().series.dropped;
      expect(dropped.alerts).toBe(7);
      expect(dropped.login).toBe(3);
      expect(droppedText()).toEqual([
        'metrics_series_dropped_total{store="requests"} 0',
        'metrics_series_dropped_total{store="duration"} 0',
        'metrics_series_dropped_total{store="alerts"} 7',
        'metrics_series_dropped_total{store="login"} 3',
        'metrics_series_dropped_total{store="mfa"} 0',
      ]);
      expect(metrics.getSnapshot().series.droppedTotal).toBe(10);
    });

    test('快照上报的 limit 就是实际生效的上限（同一常量，不得各写一遍）', () => {
      fill('alerts', 2, 'c');
      const series = metrics.getSnapshot().series;
      expect(series.limit).toBe(CAP);
      // 活下来的 series 数=上限：经快照观察，不点内部 Map 的 size
      expect(metrics.getSnapshot().alerts).toHaveLength(series.limit);
    });

    test('上限只挡新 series：既有标签继续累计（反向保护，上限≠不计数）', () => {
      fill('alerts', 5, 'b');

      metrics.incSecurityAlert('b_0', 'high');
      metrics.incSecurityAlert('b_0', 'high');

      // 既有 series 的累计经快照观察：b_0 计到 3，而不是被上限挡成 1
      const b0 = metrics.getSnapshot().alerts.find((row) => row.type === 'b_0');
      expect(b0).toEqual(expect.objectContaining({ type: 'b_0', level: 'high', count: 3 }));
      expect(metrics.getSnapshot().series.dropped.alerts).toBe(5);
    });

    test('HTTP 两个 store 各自独立计数（直方图打满不与请求计数共用丢弃额度）', () => {
      for (let i = 0; i < CAP + 4; i++) {
        const req = { method: 'GET', route: { path: `/probe/r${i}` }, baseUrl: '' };
        const res = {
          statusCode: 200,
          on(_ev, cb) {
            this._cb = cb;
          },
        };
        metrics.metricsMiddleware(req, res, () => {});
        res._cb();
      }
      // 活下来的 series 数经文本观察：http_requests_total 每条 series 一行；
      // 直方图每条 series 恰有一行 *_count（bucket/sum 是多行，不能直接数行数）
      expect(samples('http_requests_total')).toHaveLength(CAP);
      expect(samples('http_request_duration_seconds_count')).toHaveLength(CAP);
      const dropped = metrics.getSnapshot().series.dropped;
      expect(dropped.requests).toBe(4);
      expect(dropped.duration).toBe(4);
    });

    test('HTTP 计数与直方图成对登记：一侧满 ⇒ 整对不登记（不得出现「有量无延迟」半登记态）', () => {
      // 不对称满载态只能从内部 map 造：middleware 写两侧永远成对，单侧打满无法经公开入口到达。
      // 这正是旧缺陷的形状——requests 有位、duration 满 ⇒ 计数登记、延迟缺席，面板无从区分
      // 「没人访问」与「延迟数据被砍」。内部结构不在（实现换型）时放弃这层布防直接返回：
      // 成对登记的外部面由上一条与 droppedText 的判据共同盯着。
      if (!metrics._histograms || typeof metrics._histograms.set !== 'function') return;
      for (let i = 0; i < CAP; i++) {
        metrics._histograms.set(`route="pre${i}"`, { buckets: [], sum: 0, count: 0 });
      }
      const req = { method: 'GET', route: { path: '/probe/new' }, baseUrl: '' };
      const res = {
        statusCode: 200,
        on(_ev, cb) {
          this._cb = cb;
        },
      };
      metrics.metricsMiddleware(req, res, () => {});
      res._cb();
      // 整对拒绝（外部面）：requests 一行都没有；直方图仍是打满时的 CAP 条
      expect(samples('http_requests_total')).toEqual([]);
      expect(samples('http_request_duration_seconds_count')).toHaveLength(CAP);
      // 两侧丢弃计数仍按各自额度独立记：只有真正拒收新 series 的 duration +1
      expect(droppedText()).toEqual([
        'metrics_series_dropped_total{store="requests"} 0',
        'metrics_series_dropped_total{store="duration"} 1',
        'metrics_series_dropped_total{store="alerts"} 0',
        'metrics_series_dropped_total{store="login"} 0',
        'metrics_series_dropped_total{store="mfa"} 0',
      ]);
    });

    test('逐 store 各告警一次：第二个打满的 store 必须喊得出，且不刷屏', () => {
      const capMessages = () =>
        warnSpy.mock.calls
          .map((args) => String(args[0]))
          .filter((m) => m.includes('series 数已达上限'));

      fill('alerts', 3, 'w');
      fill('login', 3, 'v');

      expect(capMessages().filter((m) => m.includes('store=alerts'))).toHaveLength(1);
      expect(capMessages().filter((m) => m.includes('store=login'))).toHaveLength(1);
      expect(capMessages()).toHaveLength(2);

      metrics.incSecurityAlert('w_again', 'high');
      // 第四次丢弃不再重复喊：日志收敛……
      expect(capMessages().filter((m) => m.includes('store=alerts'))).toHaveLength(1);
      // ……但丢弃计数仍累加：可查询的信号不能跟着收敛（经快照观察）
      expect(metrics.getSnapshot().series.dropped.alerts).toBe(4);
    });
  });
});
