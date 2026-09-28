/**
 * 应用指标（报告 O-8）：零依赖自实现的 Prometheus 文本格式 /metrics
 *
 * 背景：本项目管理面板为 Vue3+ECharts 手搓（吃自家 JSON 接口），
 * 不引入 prom-client 等新依赖；/metrics 供运维侧（Prometheus/兼容抓取器）
 * 拉取，错误率/分位数由消费方按原始计数计算。
 *
 * 暴露内容：
 * - http_requests_total{method,route,status_code}：请求计数
 * - http_request_duration_seconds{...}：延迟直方图（bucket/sum/count）
 * - security_alerts_total{type,level}：安全告警事件计数（securityAlert 上报）
 * - auth_login_total{result} / auth_mfa_total{action}：业务级计数
 * - metrics_series_dropped_total{store}：被 series 上限丢弃的新 series 条数
 * - audit_records_dropped_total{reason}：落库前被丢弃的审计记录条数（合规空洞）
 * - audit_buffer_backlog_records：进程内缓冲当前积压条数（gauge，拉取时取值）
 * - readyz_verdict / readyz_verdict_age_seconds / readyz_checks_total{result}：就绪判定
 * - disk_free_bytes{path} / disk_total_bytes{path} / disk_probe_failures_total：日志卷余量
 * - log_shipper_flush_failures_total / log_shipper_dropped_lines_total：日志投递失败与丢行
 *
 * route 标签取「路由模板」而非原始 URL：匹配到具体路由时用 baseUrl+path
 * （如 /api/devices/:id），未匹配（404）统一记 unmatched——防止把用户可控
 * 的路径参数做成高基数标签撑爆时序库。
 *
 * 开关：METRICS_ENABLED=false 关闭 /metrics 端点（采集照常，只是不暴露）。
 */

const METRICS_ENABLED = process.env.METRICS_ENABLED !== 'false';

// 审计丢失/积压信号单独成文件（本文件的 max-lines 贴着 300 棘轮红线）
const auditDropMetrics = require('./metricsAuditDrops');
// 运行时健康信号（Mongo 就绪 / 磁盘 / 日志投递）同样单独成文件，理由同上
const runtimeMetrics = require('./metricsRuntime');

// 延迟直方图桶（秒）：覆盖 5ms ~ 10s 的 API 时延分布
const DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.3, 0.5, 1, 2, 5, 10];

// 底层存储：labelsKey -> value（labelsKey 形如 method="GET",route="/x",status_code="200"）
const counters = new Map(); // http_requests_total
const histograms = new Map(); // http_request_duration_seconds -> { buckets, sum, count }
const alertCounters = new Map(); // security_alerts_total
// 业务级指标（2026-09-02 综合评估 P3）：登录成功率与 MFA 管理动作。
// 只计结果枚举，不含用户/IP 维度——业务指标同样受高基数纪律约束
const loginCounters = new Map(); // auth_login_total{result}
const mfaCounters = new Map(); // auth_mfa_total{action}
// 平行保存结构化标签对象（getSnapshot 直读，免去字符串反解析）
const counterLabels = new Map(); // labelsKey -> labels object
const histogramLabels = new Map(); // labelsKey -> labels object
const alertLabels = new Map(); // labelsKey -> labels object
const loginLabels = new Map(); // labelsKey -> labels object
const mfaLabels = new Map(); // labelsKey -> labels object

/** 标签值转义（Prometheus label value：\ " \n） */
function escapeLabelValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

// 评价报告低危项：指标 Map 无淘汰上限——正常路径 route 标签是路由模板
// （有界），但防御纵深不能依赖单一标签的自觉：未来任何人引入一个用户可控
// 标签（如 path、userId），长跑进程内存就会缓慢增长。加 series 上限：
// 超限后只累计已存在的 series、丢弃新 series。
//
// 上限是**逐 store** 各 MAX_SERIES 条（不是全局共享一个 5000 的额度）：
// 各 store 的标签维度独立，一个 store 被打满不该让另一个 store 失去登记能力。
const MAX_SERIES = 5000;

// store 名 = 对外标签 store="..." 的闭合取值集，与五个 metric 家族一一对应。
// 必须是闭合集合：「报告被丢弃了多少 series」这件事自身若按丢弃的标签值建
// series，就等于用一个高基数计数器去监控高基数——上限被绕过的经典写法。
const SERIES_STORES = ['requests', 'duration', 'alerts', 'login', 'mfa'];
const droppedSeries = new Map(); // store -> 因上限被丢弃的新 series 次数
const seriesLimitWarned = new Set(); // 逐 store 各告警一次（全局一次会漏报第二个打满的 store）

/** 丢弃计数 +1：只按闭合的 store 名累加，自身不可能膨胀 */
function noteSeriesDrop(store) {
  droppedSeries.set(store, (droppedSeries.get(store) || 0) + 1);
}

/** 日志只负责"当场喊一声"，可查询的截断信号在 metrics_series_dropped_total */
function warnSeriesLimitOnce(store) {
  if (seriesLimitWarned.has(store)) return;
  seriesLimitWarned.add(store);
  // 惰性 require 避免 logger ↔ metrics 潜在加载环
  try {
    require('./logger').warn(
      `指标 store=${store} 的 series 数已达上限 ${MAX_SERIES}，新 series 被丢弃` +
        `（疑似高基数标签泄漏），累计丢弃数见 metrics_series_dropped_total{store="${store}"}`
    );
  } catch (_) {
    /* logger 不可用时静默，指标采集绝不影响业务 */
  }
}

/**
 * 还能不能登记一条新 series。返回 false 时调用方丢弃新 series（既有 series 照常累计）。
 *
 * 截断必须是**消费方可见**的：此前只有一条 warn-once 日志，抓取的 Prometheus/面板
 * 看不出"这个 store 其实被砍掉了一批 series"——route 列表少了几条、错误率少了分母，
 * 看起来都像"本来就没有"。沉默的兜底机制比没有兜底更危险。
 */
function canAddSeries(store, currentSize) {
  if (currentSize < MAX_SERIES) return true;
  noteSeriesDrop(store);
  warnSeriesLimitOnce(store);
  return false;
}

/**
 * 标签值归一：调用方漏传（undefined / null / 空串）时统一成 'unknown'。
 *
 * 必须在**入口**做，不能等渲染时各修各的：labelsKey 与快照共用同一个 labels 对象，
 * 文本渲染用 String(value)（undefined → "undefined"）、快照的 collectSeries 用
 * `labels[k] || 'unknown'`（→ "unknown"），于是同一条 series 在两个视图里
 * 顶着两个不同的标签值——而这两个视图恰是告警规则（吃 /metrics 文本）与
 * 管理面板（吃 JSON 快照）各自的取数口径，改一处口径就对不上另一处。
 * 实测旧行为：文本 `security_alerts_total{...,level="undefined"}`，
 * 快照 `{...,level:"unknown"}`。
 */
function normLabel(value) {
  if (value === undefined || value === null) return 'unknown';
  const str = String(value);
  return str === '' ? 'unknown' : str;
}

function labelsKey(labels) {
  const parts = [];
  for (const key of Object.keys(labels)) {
    parts.push(key + '="' + escapeLabelValue(labels[key]) + '"');
  }
  return parts.join(',');
}

/** 计数器 +1（不存在则建 0，并登记标签对象供 snapshot 使用；受 MAX_SERIES 约束） */
function incCounter(store, map, labels, labelStore) {
  const key = labelsKey(labels);
  if (!map.has(key)) {
    if (!canAddSeries(store, map.size)) return;
    labelStore.set(key, labels);
  }
  map.set(key, (map.get(key) || 0) + 1);
}

/** 路由标签：优先路由模板（低基数），未匹配记 unmatched，末尾斜杠归一 */
function routeLabelOf(req) {
  if (req.route && req.route.path) {
    const full = String(req.baseUrl || '') + String(req.route.path);
    return full.length > 1 ? full.replace(/\/+$/, '') : full;
  }
  return 'unmatched';
}

/**
 * HTTP 指标采集中间件：请求结束时记录计数与延迟。
 * 挂载点在所有业务中间件之前（IP 黑名单/限流器产生的 403/429 同样计数）。
 */
function metricsMiddleware(req, res, next) {
  const startNs = process.hrtime.bigint();
  res.on('finish', () => {
    try {
      const labels = {
        method: (req.method || 'GET').toUpperCase(),
        route: routeLabelOf(req),
        status_code: String(res.statusCode),
      };
      incCounter('requests', counters, labels, counterLabels);
      const durationSec = Number(process.hrtime.bigint() - startNs) / 1e9;
      const key = labelsKey(labels);
      let h = histograms.get(key);
      if (!h) {
        if (!canAddSeries('duration', histograms.size)) return;
        h = { buckets: DURATION_BUCKETS.map(() => 0), sum: 0, count: 0 };
        histograms.set(key, h);
        histogramLabels.set(key, labels);
      }
      h.sum += durationSec;
      h.count += 1;
      for (let i = 0; i < DURATION_BUCKETS.length; i++) {
        if (durationSec <= DURATION_BUCKETS[i]) h.buckets[i] += 1;
      }
      // 超出最大桶的请求只计入 count（渲染时 le="+Inf" 按 count 输出）
    } catch (_) {
      // 指标采集失败绝不影响业务响应
    }
  });
  next();
}

/** 安全告警计数（securityAlert.sendNotification 调用） */
function incSecurityAlert(type, level) {
  try {
    // 走与其他计数器同一个 incCounter，从而共享 MAX_SERIES 上限与逐 store 告警。
    // 原实现是手写的 set/get，唯独这个计数器绕过了 canAddSeries——
    // 而它偏偏是喂 alert 类型字符串的那个：今天所有调用点都传字面量所以没爆，
    // 但只要有人传一个动态 type（IP、用户名），它就是唯一会无界增长、
    // 并把每次 /metrics 抓取体撑大的映射。防御性上限不该靠调用方自觉。
    //
    // type/level 是外部可控面（sendNotification 的第一个实参），故过 normLabel：
    // 缺省时两视图口径必须一致，且不能靠调用方自觉传全。
    incCounter(
      'alerts',
      alertCounters,
      { type: normLabel(type), level: normLabel(level) },
      alertLabels
    );
  } catch (_) {
    /* 采集失败不影响主流程 */
  }
}

/**
 * 登录尝试计数（authController.login 调用）
 * @param {'success'|'failure'|'mfa_challenge'} result 结果枚举：
 *   success=签发令牌；mfa_challenge=进入 MFA 二段（中间态，不计成败）；
 *   failure=凭据/验证码/MFA 码错误等一切拒绝
 */
function incLoginAttempt(result) {
  try {
    incCounter('login', loginCounters, { result: normLabel(result) }, loginLabels);
  } catch (_) {
    /* 采集失败不影响主流程 */
  }
}

/**
 * MFA 管理动作计数（mfaController 调用）
 * @param {'enable'|'disable'|'recovery_regenerate'} action
 */
function incMfaAction(action) {
  try {
    incCounter('mfa', mfaCounters, { action: normLabel(action) }, mfaLabels);
  } catch (_) {
    /* 采集失败不影响主流程 */
  }
}

const droppedOf = (store) => droppedSeries.get(store) || 0;

/**
 * 截断信号自身：五个 store 恒定各一行（包括 0）。
 *
 * 打 0 而不是"没有丢弃就不输出"：PromQL 里「series 不存在」与「series 为 0」
 * 是两种状态（前者让 increase()/== 0 无从绑定），运维在面板上不该去分辨
 * "从没截断过" 和 "这一版代码没上报这个指标"。
 */
function formatSeriesDropped() {
  const out = [];
  out.push(
    '# HELP metrics_series_dropped_total New metric series discarded by the per-store MAX_SERIES cap'
  );
  out.push('# TYPE metrics_series_dropped_total counter');
  for (const store of SERIES_STORES) {
    out.push('metrics_series_dropped_total{store="' + store + '"} ' + droppedOf(store));
  }
  return out;
}

/** 快照侧同一事实（面板/接口读这份，口径必须与文本一致） */
function seriesStats() {
  const dropped = {};
  let droppedTotal = 0;
  for (const store of SERIES_STORES) {
    dropped[store] = droppedOf(store);
    droppedTotal += dropped[store];
  }
  return { limit: MAX_SERIES, dropped, droppedTotal };
}

/**
 * 渲染 Prometheus 文本格式（/metrics 端点用）
 */
function formatPrometheus() {
  const lines = [];

  lines.push('# HELP http_requests_total Total number of HTTP requests');
  lines.push('# TYPE http_requests_total counter');
  for (const [key, value] of counters) {
    lines.push('http_requests_total{' + key + '} ' + value);
  }

  lines.push('# HELP http_request_duration_seconds HTTP request duration in seconds');
  lines.push('# TYPE http_request_duration_seconds histogram');
  for (const [key, h] of histograms) {
    for (let i = 0; i < DURATION_BUCKETS.length; i++) {
      lines.push(
        'http_request_duration_seconds_bucket{' +
          key +
          ',le="' +
          DURATION_BUCKETS[i] +
          '"} ' +
          h.buckets[i]
      );
    }
    lines.push('http_request_duration_seconds_bucket{' + key + ',le="+Inf"} ' + h.count);
    lines.push('http_request_duration_seconds_sum{' + key + '} ' + h.sum.toFixed(6));
    lines.push('http_request_duration_seconds_count{' + key + '} ' + h.count);
  }

  lines.push('# HELP security_alerts_total Total number of security alerts raised');
  lines.push('# TYPE security_alerts_total counter');
  for (const [key, value] of alertCounters) {
    lines.push('security_alerts_total{' + key + '} ' + value);
  }

  lines.push('# HELP auth_login_total Total login attempts by result');
  lines.push('# TYPE auth_login_total counter');
  for (const [key, value] of loginCounters) {
    lines.push('auth_login_total{' + key + '} ' + value);
  }

  lines.push('# HELP auth_mfa_total Total MFA management actions by type');
  lines.push('# TYPE auth_mfa_total counter');
  for (const [key, value] of mfaCounters) {
    lines.push('auth_mfa_total{' + key + '} ' + value);
  }

  lines.push(...formatSeriesDropped());
  lines.push(...auditDropMetrics.formatAuditDrops());
  lines.push(...runtimeMetrics.formatRuntime());

  return lines.join('\n') + '\n';
}

/**
 * GET /metrics 端点处理器（Prometheus 拉取）
 */
function metricsEndpoint(req, res) {
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.end(formatPrometheus());
}

/**
 * JSON snapshot（报告 O-8 面板半：现有 Vue3+ECharts 面板直读）
 * GET /api/metrics（authenticate + security:audit 权限）返回本对象。
 *
 * - summary：全站请求/错误/错误率
 * - latency：全站与逐路由平均延迟（来自直方图 sum/count）
 * - routes：按请求量降序的逐路由计数与错误数
 * - alerts：安全告警计数（按类型/级别）
 * - series：series 上限与逐 store 丢弃数（截断是否发生过的机读答案）
 * - process：RSS/heap/uptime（面板健康卡）
 */
/** 逐路由计数汇总：跨 method 合并到 route 模板上，5xx 记为错误 */
function aggregateRoutes(valueMap, labelMap) {
  const routes = new Map();
  let totalRequests = 0;
  let totalErrors = 0;
  for (const [key, value] of valueMap) {
    const labels = labelMap.get(key) || {};
    const route = labels.route || 'unknown';
    const isServerError = String(labels.status_code || '').startsWith('5');
    const entry = routes.get(route) || { route, requests: 0, errors: 0 };
    entry.requests += value;
    totalRequests += value;
    if (isServerError) {
      entry.errors += value;
      totalErrors += value;
    }
    routes.set(route, entry);
  }
  return { routes, totalRequests, totalErrors };
}

/** 平均延迟：直方图 sum/count，count=0 时记 0 而非 NaN/Infinity */
function aggregateLatency(valueMap, labelMap) {
  const accByRoute = new Map();
  for (const [key, h] of valueMap) {
    const route = (labelMap.get(key) || {}).route || 'unknown';
    const acc = accByRoute.get(route) || { sum: 0, count: 0 };
    acc.sum += h.sum;
    acc.count += h.count;
    accByRoute.set(route, acc);
  }
  const avg = (sum, count) => (count > 0 ? Number((sum / count).toFixed(6)) : 0);
  const latency = { avgSeconds: 0, byRoute: {} };
  let totalSum = 0;
  let totalCount = 0;
  for (const [route, acc] of accByRoute) {
    latency.byRoute[route] = { avgSeconds: avg(acc.sum, acc.count), count: acc.count };
    totalSum += acc.sum;
    totalCount += acc.count;
  }
  latency.avgSeconds = avg(totalSum, totalCount);
  return latency;
}

/**
 * 标签型计数 → 行数组（缺失标签记 'unknown'）。
 * 字段顺序固定为「标签在前、count 在后」，与 JSON 快照的既有形状一致。
 */
function collectSeries(valueMap, labelMap, labelKeys) {
  const rows = [];
  for (const [key, value] of valueMap) {
    const labels = labelMap.get(key) || {};
    const row = {};
    for (const labelKey of labelKeys) row[labelKey] = labels[labelKey] || 'unknown';
    row.count = value;
    rows.push(row);
  }
  return rows;
}

const sumCounts = (rows) => rows.reduce((acc, row) => acc + row.count, 0);

function getSnapshot() {
  const { routes, totalRequests, totalErrors } = aggregateRoutes(counters, counterLabels);
  const latency = aggregateLatency(histograms, histogramLabels);
  const alerts = collectSeries(alertCounters, alertLabels, ['type', 'level']);

  // 业务级：登录结果分布（附成功率）与 MFA 管理动作
  const login = collectSeries(loginCounters, loginLabels, ['result']);
  const loginTotal = sumCounts(login);
  const loginSuccess = login
    .filter((row) => row.result === 'success')
    .reduce((acc, row) => acc + row.count, 0);
  const mfa = collectSeries(mfaCounters, mfaLabels, ['action']);

  const mem = process.memoryUsage();
  return {
    timestamp: Date.now(),
    summary: {
      totalRequests,
      totalErrors,
      errorRate: totalRequests > 0 ? Number((totalErrors / totalRequests).toFixed(4)) : 0,
    },
    latency,
    routes: [...routes.values()].sort((a, b) => b.requests - a.requests),
    alerts,
    business: {
      login,
      loginSuccessRate: loginTotal > 0 ? Number((loginSuccess / loginTotal).toFixed(4)) : 0,
      mfa,
    },
    series: seriesStats(),
    process: {
      uptimeSeconds: Math.floor(process.uptime()),
      rssMB: Number((mem.rss / 1024 / 1024).toFixed(1)),
      heapUsedMB: Number((mem.heapUsed / 1024 / 1024).toFixed(1)),
    },
  };
}

module.exports = {
  METRICS_ENABLED,
  metricsMiddleware,
  metricsEndpoint,
  incSecurityAlert,
  incLoginAttempt,
  incMfaAction,
  incAuditDrop: auditDropMetrics.incAuditDrop,
  recordReadyz: runtimeMetrics.recordReadyz,
  routeLabelOf,
  formatPrometheus,
  getSnapshot,
  // 仅供测试/调试
  _counters: counters,
  _histograms: histograms,
  _alertCounters: alertCounters,
  _loginCounters: loginCounters,
  _mfaCounters: mfaCounters,
  // alertLabels 此前**没有**导出，而 writeSurface 测试的 afterEach 里写着
  // `metrics._alertLabels?.clear?.()` ——可选链把"清不掉的标签表"伪装成"清好了"。
  // 导出后那行才真正生效（漏导出一次，标签表就在同一文件的用例间悄悄累积）。
  _alertLabels: alertLabels,
  _droppedSeries: droppedSeries,
  _auditDrops: auditDropMetrics._auditDrops,
  _seriesLimitWarned: seriesLimitWarned,
  _MAX_SERIES: MAX_SERIES,
  _SERIES_STORES: SERIES_STORES,
};
