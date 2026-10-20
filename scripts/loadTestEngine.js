/**
 * 压测引擎（基线，零依赖）
 *
 * 从 scripts/load-test.js 原样搬出的「与场景无关」那一半：keepAlive 计时客户端、
 * 并发 hammer 引擎、门禁断言。此前它们与 B/C/E/D 四个相的步骤平铺在同一文件里，
 * 既把 main 顶过 `max-lines-per-function`（100 行），也把文件顶到 `max-lines`
 * 阈值的最后几行（296/300）——再抽任何一段场景代码都会把文件顶爆。
 *
 * 这里**只做搬家**：状态码白名单口径、延迟分位字段名、基线写入位置全部未改。
 * 口径的由来（为什么 /health 与 /metrics 也必须有正确性判据）见 assertPhaseHealthy 的注释，
 * 它随代码一起搬过来了，不是引用别处。
 *
 * 分三段（客户端 / 计分板 / 引擎）而不是一个大工厂，是为了任何一段单独都不越
 * `max-lines-per-function`；三段之间只靠入参传值，引擎不隐式依赖模块级状态。
 * 场景侧通过 createLoadEngine 取用；counters 与 baseline 由场景侧创建并传入——
 * 引擎只往里写，不定义「什么算通过」「基线长什么样」。
 */

const http = require('http');

/**
 * keepAlive 客户端 + 计时请求
 *
 * @param {string} base 目标基址（如 http://127.0.0.1:3777）
 * @returns {{req: Function, sleep: Function}}
 */
function createHttpClient(base) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 256 });

  function req(method, urlPath, { token, body } = {}) {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : null;
      const started = process.hrtime.bigint();
      const r = http.request(
        base + urlPath,
        {
          method,
          agent,
          headers: Object.assign(
            {},
            payload
              ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
              : {},
            token ? { Authorization: 'Bearer ' + token } : {}
          ),
          timeout: 10000,
        },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const ms = Number(process.hrtime.bigint() - started) / 1e6;
            const text = Buffer.concat(chunks).toString('utf8');
            let bodyParsed = text;
            try {
              bodyParsed = JSON.parse(text);
            } catch (_) {
              /* 保留原文 */
            }
            resolve({ status: res.statusCode, body: bodyParsed, ms, headers: res.headers });
          });
        }
      );
      r.on('error', reject);
      r.on('timeout', () => r.destroy(new Error('请求超时 ' + urlPath)));
      if (payload) r.write(payload);
      r.end();
    });
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  return { req, sleep };
}

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

/**
 * 步骤计分板：执行一步、记分、打印，并把「该不该算绿」的判据固化在这里
 *
 * @param {{passed: number, failed: number, failures: string[]}} counters 就地累加的计分板
 * @returns {{step: Function, assertPhaseHealthy: Function}}
 */
function createStepRunner(counters) {
  function step(name, fn) {
    return fn()
      .then((extra) => {
        counters.passed++;
        console.log('  ok ' + name + (extra || ''));
      })
      .catch((err) => {
        counters.failed++;
        counters.failures.push(name);
        console.error('  FAIL ' + name + ': ' + err.message);
      });
  }

  /**
   * 把一个压测相变成**带正确性判据**的门禁，而不是只报数。
   *
   * 为什么必须有：`hammer()` 只统计状态码，自己从不失败。所以此前 B（/health）与
   * C（/metrics）两相在任何退化下都是"绿"的——/health 全 500、/metrics 被
   * metricsAuth 挡成 401、甚至一个请求都没发出去（total=0 ⇒ QPS=0、P95=0），
   * 都照样打印数字并写进基线文件。**一份把错误响应当吞吐量的基线比没有基线更糟**：
   * 它看起来是"压测过了"。口径是"测得这台机器的下界"，前提是这些请求真的成功。
   *
   * @param {string} label 步骤名前缀
   * @param {Object} r hammer() 的返回
   * @param {number[]} allowed 允许出现的状态码集合
   */
  function assertPhaseHealthy(label, r, allowed) {
    return step(label, async () => {
      if (!(r.total > 0)) {
        throw new Error(
          '该相没有发出任何成功计数的请求（status=' + JSON.stringify(r.byStatus) + '）'
        );
      }
      const notAllowed = Object.entries(r.byStatus).filter(
        ([s]) => !allowed.includes(Number(s)) // 'error' 之类经 Number 变 NaN，必然不在白名单内
      );
      if (notAllowed.length > 0) {
        throw new Error(
          '出现非预期状态码 ' +
            JSON.stringify(Object.fromEntries(notAllowed)) +
            '（允许 ' +
            allowed.join('/') +
            '；全量=' +
            JSON.stringify(r.byStatus) +
            '）'
        );
      }
    });
  }

  return { step, assertPhaseHealthy };
}

/**
 * 引擎装配
 *
 * @param {object} cfg
 * @param {string} cfg.base 目标基址
 * @param {{passed: number, failed: number, failures: string[]}} cfg.counters 步骤计分板
 * @param {{phases: Record<string, object>}} cfg.baseline 基线产物（hammer 把每相结果写进 baseline.phases）
 * @returns {{req: Function, sleep: Function, step: Function, hammer: Function, fmt: Function, assertPhaseHealthy: Function}}
 */
function createLoadEngine({ base, counters, baseline }) {
  const { req, sleep } = createHttpClient(base);
  const { step, assertPhaseHealthy } = createStepRunner(counters);

  /** 并发压测引擎：N worker 各自串行循环，直到 deadline / maxRequests / 命中 stopStatus */
  async function hammer({
    name,
    path: urlPath,
    method = 'GET',
    token,
    body,
    concurrency,
    durationMs,
    maxRequests = Infinity,
    stopOnStatus = null,
  }) {
    const latencies = [];
    const byStatus = {};
    let total = 0;
    let stopped = false;
    const deadline = Date.now() + durationMs;

    const worker = async () => {
      while (!stopped && Date.now() < deadline && total < maxRequests) {
        try {
          const r = await req(method, urlPath, { token, body });
          total += 1;
          latencies.push(r.ms);
          byStatus[r.status] = (byStatus[r.status] || 0) + 1;
          if (stopOnStatus && r.status === stopOnStatus) {
            stopped = true;
            break;
          }
        } catch (_) {
          byStatus.error = (byStatus.error || 0) + 1;
        }
      }
    };

    const started = Date.now();
    await Promise.all(Array.from({ length: concurrency }, worker));
    const elapsedSec = (Date.now() - started) / 1000;

    latencies.sort((a, b) => a - b);
    const result = {
      total,
      elapsedSec: Number(elapsedSec.toFixed(2)),
      qps: Number((total / elapsedSec).toFixed(1)),
      p50: Number(percentile(latencies, 50).toFixed(2)),
      p90: Number(percentile(latencies, 90).toFixed(2)),
      p95: Number(percentile(latencies, 95).toFixed(2)),
      p99: Number(percentile(latencies, 99).toFixed(2)),
      max: latencies.length ? Number(latencies[latencies.length - 1].toFixed(2)) : 0,
      byStatus,
    };
    baseline.phases[name] = result;
    return result;
  }

  /** 一行打印一个相的结果（模板字面量：等价的 16 行 `+` 拼接只是为了绕行宽，不携带信息） */
  const fmt = (r) =>
    `  ${r.total} req / ${r.elapsedSec}s  QPS=${r.qps}  P50=${r.p50}ms  P95=${r.p95}ms` +
    `  P99=${r.p99}ms  status=${JSON.stringify(r.byStatus)}`;

  return { req, sleep, step, hammer, fmt, assertPhaseHealthy };
}

module.exports = { createLoadEngine };
