'use strict';

const { DETECTION_DIMENSIONS, UNKNOWN_DETECTION_DIMENSION } = require('./detectionObjectives');
const { EXPORT_REJECT_REASONS } = require('../utils/metricsRuntime');
const { ROUTE_TABLE, TRAP_HANDLING, matchRoute } = require('./honeypotRouteTable');

const HOUR_SECONDS = 3600;
const SNAPSHOT_MESSAGE = '获取成功';
const OBJECTIVE_SECONDS = 300;
const SERIES_LIMIT = 5000;
const SERIES_STORES = ['requests', 'duration', 'alerts', 'login', 'mfa'];

const seedOf = (text) => {
  let hash = 0;
  for (let i = 0; i < text.length; i += 1) hash = (hash * 31 + text.charCodeAt(i)) % 100003;
  return hash;
};

const grownBy = (base, perHour, elapsedSec) =>
  base + Math.floor((perHour * elapsedSec) / HOUR_SECONDS);

const gaugedBy = (base, span, periodSec, elapsedSec) => {
  const phase = elapsedSec % periodSec;
  return base + Math.floor((phase * span) / periodSec);
};

const ROUTE_SEEDS = (() => {
  const labels = new Set();
  for (const row of ROUTE_TABLE) labels.add(row.path);
  return [...labels].sort().map((route) => ({ route, seed: seedOf(route) }));
})();

const requestRowOf = (entry, elapsedSec) => {
  const requests = grownBy(60 + (entry.seed % 1400), 20 + (entry.seed % 220), elapsedSec);
  return { route: entry.route, requests, errors: Math.floor((requests * (entry.seed % 9)) / 1000) };
};

const routeSectionOf = (elapsedSec) => {
  const rows = ROUTE_SEEDS.map((entry) => ({ entry, ...requestRowOf(entry, elapsedSec) })).sort(
    (a, b) => b.requests - a.requests || (a.route < b.route ? -1 : 1)
  );
  const byRoute = {};
  let totalRequests = 0;
  let totalErrors = 0;
  for (const row of rows) {
    const avgSeconds = Number((4 + (row.entry.seed % 46)) / 1000);
    byRoute[row.route] = { avgSeconds, count: row.requests };
    totalRequests += row.requests;
    totalErrors += row.errors;
  }
  const weighted = rows.reduce((acc, row) => acc + byRoute[row.route].avgSeconds * row.requests, 0);
  return {
    routes: rows.map(({ route, requests, errors }) => ({ route, requests, errors })),
    totalRequests,
    totalErrors,
    latency: {
      avgSeconds: totalRequests > 0 ? Number((weighted / totalRequests).toFixed(6)) : 0,
      byRoute,
    },
  };
};

const ALERT_SERIES = [
  { type: 'brute_force_login', level: 'high', base: 6, perHour: 3 },
  { type: 'permission_abuse', level: 'high', base: 2, perHour: 1 },
  { type: 'suspicious_ip_activity', level: 'medium', base: 9, perHour: 5 },
  { type: 'rate_limit_abuse', level: 'medium', base: 14, perHour: 8 },
  { type: 'unusual_time_access', level: 'low', base: 3, perHour: 1 },
  { type: 'bulk_data_export', level: 'high', base: 1, perHour: 1 },
];

const LOGIN_SERIES = [
  { result: 'success', base: 320, perHour: 24 },
  { result: 'failure', base: 96, perHour: 9 },
  { result: 'mfa_challenge', base: 41, perHour: 4 },
];

const MFA_SERIES = [
  { action: 'enable', base: 4, perHour: 1 },
  { action: 'disable', base: 2, perHour: 1 },
  { action: 'recovery_regenerate', base: 1, perHour: 1 },
];

const DETECTION_LAG_SERIES = [...DETECTION_DIMENSIONS, UNKNOWN_DETECTION_DIMENSION].map(
  (dimension, index) => ({
    dimension,
    within: { base: 12 + index * 4, perHour: 3 + index },
    outside: { base: 1 + index, perHour: 1 },
    avgWithinMs: 180 + index * 20,
    avgOutsideMs: 420 + index * 30,
    objectiveSeconds: dimension === UNKNOWN_DETECTION_DIMENSION ? null : OBJECTIVE_SECONDS,
  })
);

const SKIP_SERIES = ['missing_first_event_at', 'negative_lag', 'invalid_interval', 'other'].map(
  (reason, index) => ({ reason, base: index === 3 ? 0 : index + 1, perHour: 1 })
);

const businessOf = (elapsedSec) => {
  const login = LOGIN_SERIES.map((row) => ({
    result: row.result,
    count: grownBy(row.base, row.perHour, elapsedSec),
  }));
  const mfa = MFA_SERIES.map((row) => ({
    action: row.action,
    count: grownBy(row.base, row.perHour, elapsedSec),
  }));
  const loginTotal = login.reduce((acc, row) => acc + row.count, 0);
  const loginSuccess = login
    .filter((row) => row.result === 'success')
    .reduce((acc, row) => acc + row.count, 0);
  const dimensions = DETECTION_LAG_SERIES.map((row) => {
    const withinObjective = grownBy(row.within.base, row.within.perHour, elapsedSec);
    const outsideObjective = grownBy(row.outside.base, row.outside.perHour, elapsedSec);
    const lagMs = withinObjective * row.avgWithinMs + outsideObjective * row.avgOutsideMs;
    return {
      dimension: row.dimension,
      lagSecondsSum: Number((lagMs / 1000).toFixed(6)),
      lagSampleCount: withinObjective + outsideObjective,
      withinObjective,
      outsideObjective,
      objectiveSeconds: row.objectiveSeconds,
    };
  });
  const skipped = SKIP_SERIES.map((row) => ({
    reason: row.reason,
    count: grownBy(row.base, row.perHour, elapsedSec),
  }));
  return {
    login,
    loginSuccessRate: loginTotal > 0 ? Number((loginSuccess / loginTotal).toFixed(4)) : 0,
    mfa,
    detection: { dimensions, skipped },
  };
};

const seriesOf = () => {
  const dropped = {};
  for (const store of SERIES_STORES) dropped[store] = 0;
  return {
    limit: SERIES_LIMIT,
    dropped,
    droppedTotal: SERIES_STORES.reduce((acc, store) => acc + dropped[store], 0),
  };
};

const exportOf = (elapsedSec) => {
  const rejected = {};
  for (const reason of EXPORT_REJECT_REASONS) {
    rejected[reason] = grownBy(reason === 'queue_full' ? 2 : 0, 1, elapsedSec);
  }
  return { inflight: 0, queued: gaugedBy(0, 3, 900, elapsedSec), rejected };
};

const processOf = () => {
  const mem = process.memoryUsage();
  return {
    uptimeSeconds: Math.floor(process.uptime()),
    rssMB: Number((mem.rss / 1024 / 1024).toFixed(1)),
    heapUsedMB: Number((mem.heapUsed / 1024 / 1024).toFixed(1)),
  };
};

const elapsedOf = (uptimeSeconds) => {
  const value = Number.isFinite(uptimeSeconds) ? uptimeSeconds : process.uptime();
  return Math.max(0, Math.floor(value));
};

const buildMetricsSnapshot = ({ now = Date.now(), uptimeSeconds } = {}) => {
  const elapsedSec = elapsedOf(uptimeSeconds);
  const routeSection = routeSectionOf(elapsedSec);
  const processRows = processOf();
  return {
    timestamp: now,
    summary: {
      totalRequests: routeSection.totalRequests,
      totalErrors: routeSection.totalErrors,
      errorRate:
        routeSection.totalRequests > 0
          ? Number((routeSection.totalErrors / routeSection.totalRequests).toFixed(4))
          : 0,
    },
    latency: routeSection.latency,
    routes: routeSection.routes,
    alerts: ALERT_SERIES.map((row) => ({
      type: row.type,
      level: row.level,
      count: grownBy(row.base, row.perHour, elapsedSec),
    })),
    business: businessOf(elapsedSec),
    series: seriesOf(),
    export: exportOf(elapsedSec),
    ws: {
      connections: gaugedBy(2, 18, 1800, elapsedSec),
      inboundThrottled: grownBy(0, 30, elapsedSec),
      inboundDisconnects: grownBy(0, 3, elapsedSec),
    },
    process: { ...processRows, uptimeSeconds: elapsedSec },
  };
};

const resolveMetricsPayload = ({ method = 'GET', path } = {}) => {
  const route = matchRoute({ method, path: String(path || '') });
  if (!route || route.handling !== TRAP_HANDLING.METRICS) return null;
  return {
    kind: 'metrics',
    data: buildMetricsSnapshot({ now: Date.now() }),
    message: SNAPSHOT_MESSAGE,
  };
};

module.exports = { SNAPSHOT_MESSAGE, buildMetricsSnapshot, resolveMetricsPayload };
