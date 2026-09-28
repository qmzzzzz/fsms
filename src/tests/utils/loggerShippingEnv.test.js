/**
 * LOG_SHIPPING_* 数值环境变量的判据契约（收口时我留下的唯一未覆盖面）
 *
 * 复核 在 logger.js 里把三个 `parseInt(env,10) || undefined` 换成统一判据时，
 * 因为"加载期不能用 logger"而把 onInvalid 接成了 console.warn。
 * 这条路径只在 LOG_SHIPPING_URL 存在时才走到，且 transport 真正启动会拉起定时器，
 * 所以本用例把 HttpShipperTransport 换成替身：**只断言构造参数与告警**，
 * 不启动任何网络/定时器副作用。
 *
 * 关键不变量：非法值必须变成 `undefined`，交给传输层自己的默认值
 * （`opts.batchSize || DEFAULT_BATCH`）——绝不能变成 -5 / 0，
 * 否则负批量会让"每批都超限"、0 会让批量语义取决于实现。
 */

const TransportStream = require('winston-transport');

const mockTransportCtor = jest.fn(function FakeTransport(opts) {
  TransportStream.call(this, opts);
  Object.assign(this, opts);
});
// F-215 期间实测发现：原先的替身是个普通对象，`logger.add()` 会以
// "Invalid transport, must be an object with a log method" 拒收，异常被挂载路径的
// catch 接成一条 warn ⇒ 本用例一直在"构造参数对、但从未真的挂上"的状态下变绿，
// 每次加载还往 stdout 喷一条 warn。让它继承 winston-transport 之后，
// 构造参数断言才真的跑在 logger.add 的下游。
mockTransportCtor.prototype = Object.create(TransportStream.prototype);
mockTransportCtor.prototype.log = function log(info, callback) {
  callback();
};

jest.mock('../../utils/logShipper', () => ({
  HttpShipperTransport: mockTransportCtor,
  // F-215 前提：logger.js 现在在挂载期调用 resolveShippingTarget 先校验 URL。
  // 替身必须给**真判据**：给空壳的话 BASE 里的 URL 就"永远合法"，挂载期闸在这几条
  // 用例上变成不可见；用真判据同时正面证明了 BASE 确实过得了那道闸。
  resolveShippingTarget: jest.requireActual('../../utils/logShipper').resolveShippingTarget,
}));

const loadLogger = (env) => {
  jest.resetModules();
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = String(v);
  }
  const warns = [];
  const realWarn = console.warn;
  console.warn = (...a) => warns.push(a.join(' '));
  // 替身能真的挂上之后，挂载成功那条 INFO 会走 winston 的 console transport
  // （它持有 process.stdout 对象、在调用点才取 .write，所以替换方法即可静音）。
  // 不采进 warns：那里面只该有 envNumber 的 onInvalid 告警，:84 断言它为空。
  const realWrite = process.stdout.write;
  process.stdout.write = () => true;
  let mod;
  try {
    mod = require('../../utils/logger');
  } finally {
    process.stdout.write = realWrite;
    console.warn = realWarn;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  return { mod, warns };
};

const shippingOpts = () => mockTransportCtor.mock.calls[mockTransportCtor.mock.calls.length - 1][0];

describe('logger：LOG_SHIPPING_* 只有正整数被采纳', () => {
  const BASE = { LOG_SHIPPING_URL: 'https://siem.example.test/ingest', LOG_SHIPPING_TOKEN: 't' };

  beforeEach(() => mockTransportCtor.mockClear());

  test('非法值（-5 / 0 / abc / 1.5）⇒ 该项退回 undefined 并 console.warn', () => {
    for (const bad of ['-5', '0', 'abc', '1.5']) {
      const { warns } = loadLogger({ ...BASE, LOG_SHIPPING_BATCH: bad });
      expect(shippingOpts().batchSize).toBeUndefined();
      expect(warns.join('\n')).toContain('LOG_SHIPPING_BATCH');
    }
  });

  test('三个变量各自独立判定：只有非法的那一项被忽略', () => {
    loadLogger({
      ...BASE,
      LOG_SHIPPING_BATCH: '50',
      LOG_SHIPPING_INTERVAL_MS: '-1',
      LOG_SHIPPING_TIMEOUT_MS: '4000',
    });
    const opts = shippingOpts();
    expect(opts.batchSize).toBe(50);
    expect(opts.intervalMs).toBeUndefined();
    expect(opts.timeoutMs).toBe(4000);
  });

  test('合法边界 1 仍被采纳（防"下限钳制"混进来——envNumber 刻意不做最小值钳制）', () => {
    loadLogger({ ...BASE, LOG_SHIPPING_BATCH: '1' });
    expect(shippingOpts().batchSize).toBe(1);
  });

  test('未设置这些变量 ⇒ 全部 undefined，且一条告警都不产生', () => {
    const { warns } = loadLogger({ ...BASE });
    const opts = shippingOpts();
    expect(opts.batchSize).toBeUndefined();
    expect(opts.intervalMs).toBeUndefined();
    expect(opts.timeoutMs).toBeUndefined();
    expect(warns).toEqual([]);
  });

  test('反向闸：URL 未配置时不得构造 transport（也别因这几个数字而告警）', () => {
    const { warns } = loadLogger({ LOG_SHIPPING_BATCH: '-5' });
    expect(mockTransportCtor).not.toHaveBeenCalled();
    expect(warns.join('\n')).not.toContain('LOG_SHIPPING_BATCH');
  });
});
