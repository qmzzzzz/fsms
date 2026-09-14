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
 *
 * route 标签取「路由模板」而非原始 URL：匹配到具体路由时用 baseUrl+path
 * （如 /api/devices/:id），未匹配（404）统一记 unmatched——防止把用户可控
 * 的路径参数做成高基数标签撑爆时序库。
 *
 * 开关：METRICS_ENABLED=false 关闭 /metrics 端点（采集照常，只是不暴露）。
 */

const METRICS_ENABLED = process.env.METRICS_ENABLED !== 'false';

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
// 标签（如 path、userId），长跑进程内存就会缓慢增长。加全局 series 上限：
// 超限后只累计已存在的 series、丢弃新 series，并告警一次。
const MAX_SERIES = 5000;
let seriesLimitWarned = false;
function canAddSeries(currentSize) {
  if (currentSize < MAX_SERIES) return true;
  if (!seriesLimitWarned) {
    seriesLimitWarned = true;
    // 惰性 require 避免 logger ↔ metrics 潜在加载环
    try {
      require('./logger').warn(
        `指标 series 数已达上限 ${MAX_SERIES}，新 series 被丢弃（疑似高基数标签泄漏）`
      );
    } catch (_) {
      /* logger 不可用时静默，指标采集绝不影响业务 */
    }
  }
  return false;
}

function labelsKey(labels) {
  const parts = [];
  for (const key of Object.keys(labels)) {
    parts.push(key + '="' + escapeLabelValue(labels[key]) + '"');
  }
  return parts.join(',');
}

/** 计数器 +1（不存在则建 0，并登记标签对象供 snapshot 使用；受 MAX_SERIES 约束） */
function incCounter(map, labels, labelStore) {
  const key = labelsKey(labels);
  if (!map.has(key)) {
    if (!canAddSeries(map.size)) return;
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
      incCounter(counters, labels, counterLabels);
      const durationSec = Number(process.hrtime.bigint() - startNs) / 1e9;
      const key = labelsKey(labels);
      let h = histograms.get(key);
      if (!h) {
        if (!canAddSeries(histograms.size)) return;
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
    const labels = { type, level };
    const key = labelsKey(labels);
    if (!alertLabels.has(key)) alertLabels.set(key, labels);
    alertCounters.set(key, (alertCounters.get(key) || 0) + 1);
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
    incCounter(loginCounters, { result }, loginLabels);
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
    incCounter(mfaCounters, { action }, mfaLabels);
  } catch (_) {
    /* 采集失败不影响主流程 */
  }
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
 * - process：RSS/heap/uptime（面板健康卡）
 */
function getSnapshot() {
  const routes = new Map();
  let totalRequests = 0;
  let totalErrors = 0;
  const latencyByRoute = new Map(); // route -> { sum, count }

  for (const [key, value] of counters) {
    const labels = counterLabels.get(key) || {};
    const route = labels.route || 'unknown';
    const statusCode = String(labels.status_code || '');
    const entry = routes.get(route) || { route, requests: 0, errors: 0 };
    entry.requests += value;
    if (statusCode.startsWith('5')) entry.errors += value;
    totalRequests += value;
    if (statusCode.startsWith('5')) totalErrors += value;
    routes.set(route, entry);
  }

  for (const [key, h] of histograms) {
    const route = (histogramLabels.get(key) || {}).route || 'unknown';
    const acc = latencyByRoute.get(route) || { sum: 0, count: 0 };
    acc.sum += h.sum;
    acc.count += h.count;
    latencyByRoute.set(route, acc);
  }

  const latency = { avgSeconds: 0, byRoute: {} };
  let totalSum = 0;
  let totalCount = 0;
  for (const [route, acc] of latencyByRoute) {
    latency.byRoute[route] = {
      avgSeconds: acc.count > 0 ? Number((acc.sum / acc.count).toFixed(6)) : 0,
      count: acc.count,
    };
    totalSum += acc.sum;
    totalCount += acc.count;
  }
  latency.avgSeconds = totalCount > 0 ? Number((totalSum / totalCount).toFixed(6)) : 0;

  const alerts = [];
  for (const [key, value] of alertCounters) {
    const labels = alertLabels.get(key) || {};
    alerts.push({ type: labels.type || 'unknown', level: labels.level || 'unknown', count: value });
  }

  // 业务级：登录结果分布（附成功率）与 MFA 管理动作
  const login = [];
  let loginTotal = 0;
  let loginSuccess = 0;
  for (const [key, value] of loginCounters) {
    const result = (loginLabels.get(key) || {}).result || 'unknown';
    login.push({ result, count: value });
    loginTotal += value;
    if (result === 'success') loginSuccess += value;
  }
  const mfa = [];
  for (const [key, value] of mfaCounters) {
    mfa.push({ action: (mfaLabels.get(key) || {}).action || 'unknown', count: value });
  }

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
  routeLabelOf,
  formatPrometheus,
  getSnapshot,
  // 仅供测试/调试
  _counters: counters,
  _histograms: histograms,
  _alertCounters: alertCounters,
  _loginCounters: loginCounters,
  _mfaCounters: mfaCounters,
};
