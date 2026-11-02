'use strict';

/**
 * GET /api/metrics 合成快照面的判据。
 *
 * 为什么有这个面：授权轴判据发现「呈现身份持有 security:audit（经 security:*），而陷阱对
 * /api/metrics 回 403」是唯一一条**纯自相矛盾**——不需要知道票据闸的存在，只比对
 * /api/auth/me 与本次响应即可发现。收口方式是把该行声明成 decoy-metrics 并回同键集的合成体。
 *
 * 判据分四层：
 *  1) **形态**：把真实采集器喂饱后取 getSnapshot()，与合成体做「键路径 + 叶子类型」逐条对拍
 *     （动态键的映射节点按 * 归一，另有三条独立的键域断言兜住）。
 *  2) **标签域**：合成取值只能落在真实域里——路由模板取自路由表、告警类型/级别取自真实枚举、
 *     登录结果与 MFA 动作取自真实模块的 JSDoc 字面量联合、检测维度/series store/导出拒绝原因
 *     取自真实常量。任一处造一个新词，攻击者一眼可辨。
 *  3) **自洽**：总量 / 错误率 / 延迟加权 / 成功率 / 样本数 / 合计，以及计数器跨次抓取只增不减。
 *     「两次抓取对得起来」正是反复抓取面板的攻击者最廉价的检测手段。
 *  4) **不泄漏**：蜜罐 / 哨兵 / 审计链家族与任何口令类字段一律不出现（出现非零计数等于告诉
 *     对方本系统有蜜罐且在被打）。
 *
 * 反向自证：把合成体的一个键删掉、把一个标签改成域外的词，必须分别被形态与域判据点名。
 */

const fs = require('fs');
const path = require('path');

const metrics = require('../../utils/metrics');
const detectionMetrics = require('../../utils/metricsDetection');
const { EXPORT_REJECT_REASONS } = require('../../utils/metricsRuntime');
const { ALERT_LEVELS, ALERT_TYPES } = require('../../services/alertTypes');
const { CANARY_ALERT_TYPES } = require('../../services/canaryAlertTypes');
const { HONEYPOT_ALERT_TYPES } = require('../../services/honeypotAlertTypes');
const { AUDIT_CHAIN_ALERT_TYPES } = require('../../services/auditChainAlertTypes');
const { DEFAULT_CANARY_USERNAMES } = require('../../constants/canaryAccounts');
const {
  DETECTION_DIMENSIONS,
  UNKNOWN_DETECTION_DIMENSION,
  resolveDetectionTargetMs,
} = require('../../constants/detectionObjectives');
const { ROUTE_TABLE } = require('../../constants/honeypotRouteTable');
const {
  SNAPSHOT_MESSAGE,
  buildMetricsSnapshot,
  resolveMetricsPayload,
} = require('../../constants/honeypotDecoyMetrics');

const ROOT = path.resolve(__dirname, '../../..');
const METRICS_PATH = '/api/metrics';
const INTERVAL_MS = 300000;
const OBJECTIVE_SECONDS = resolveDetectionTargetMs(INTERVAL_MS) / 1000;

const METRICS_SRC = fs.readFileSync(path.join(ROOT, 'src/utils/metrics.js'), 'utf8');
const APP_SRC = fs.readFileSync(path.join(ROOT, 'src/app.js'), 'utf8');
const FACE_SRC = fs.readFileSync(path.join(ROOT, 'src/constants/honeypotDecoyMetrics.js'), 'utf8');

/** 映射节点（键是数据值）：形态对拍按 * 归一，键域另有独立断言 */
const MAP_NODES = new Set(['latency.byRoute', 'series.dropped', 'export.rejected']);

const typeOf = (value) => (value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value);

const skeletonOf = (value) => {
  const out = new Set();
  const walk = (node, at) => {
    if (MAP_NODES.has(at)) {
      out.add(at + '.*');
      for (const child of Object.values(node)) walk(child, at + '.*');
      return;
    }
    if (Array.isArray(node)) {
      out.add(at + '[]');
      for (const item of node) walk(item, at + '[]');
      return;
    }
    if (node && typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) walk(child, at ? at + '.' + key : key);
      return;
    }
    out.add(at + ':' + typeOf(node));
  };
  walk(value, '');
  return [...out].sort();
};

/** 把真实采集器喂饱：不喂的话数组都是空的，形态对拍等于空转 */
const realSnapshot = () => {
  const res = {
    statusCode: 200,
    on: (event, handler) => {
      if (event === 'finish') handler();
    },
  };
  metrics.metricsMiddleware(
    { baseUrl: '/api/users', route: { path: '/:id' }, method: 'GET' },
    res,
    () => {}
  );
  metrics.incSecurityAlert(ALERT_TYPES.BRUTE_FORCE, ALERT_LEVELS.HIGH);
  metrics.incLoginAttempt('success');
  metrics.incMfaAction('enable');
  for (const dimension of DETECTION_DIMENSIONS) {
    detectionMetrics.recordDetection({ dimension, lagMs: 1000, intervalMs: INTERVAL_MS });
  }
  return metrics.getSnapshot();
};

const bodyOf = (uptimeSeconds) => buildMetricsSnapshot({ now: 1762000000000, uptimeSeconds });

const realRouteLabels = () => [...new Set(ROUTE_TABLE.map((row) => row.path))].sort();

const jsdocDomainOf = (fnName, paramName) => {
  const re = new RegExp(
    '@param\\s*\\{([^}]*)\\}\\s*' + paramName + '[\\s\\S]*?function ' + fnName + '\\('
  );
  const match = re.exec(METRICS_SRC);
  if (!match) return [];
  return match[1]
    .split('|')
    .map((item) => item.trim().replace(/^'|'$/g, ''))
    .filter(Boolean)
    .sort();
};

const countersOf = (body) => ({
  totalRequests: body.summary.totalRequests,
  totalErrors: body.summary.totalErrors,
  // 逐路由按**键**比，不按数组下标：请求量排序会随速率差改变，下标对位等于在比「第几名」,
  // 那不是单调性判据要的东西
  routes: Object.fromEntries(
    body.routes.map((row) => [row.route, row.requests + '/' + row.errors])
  ),
  alerts: body.alerts.map((row) => row.count),
  login: body.business.login.map((row) => row.count),
  mfa: body.business.mfa.map((row) => row.count),
  detectionLag: body.business.detection.dimensions.map((row) => row.lagSampleCount),
  skipped: body.business.detection.skipped.map((row) => row.count),
  wsThrottled: body.ws.inboundThrottled,
  wsDisconnects: body.ws.inboundDisconnects,
  exportRejected: Object.values(body.export.rejected),
});

const alertTypeDomain = () => Object.values(ALERT_TYPES);
const alertLevelDomain = () => Object.values(ALERT_LEVELS);
const familyValues = (family) => Object.values(family);

describe('GET /api/metrics 合成快照面：形态 / 标签域 / 自洽 / 不泄漏', () => {
  test('前提：真实快照每一类都非空（否则形态对拍是空转）', () => {
    const real = realSnapshot();
    expect(real.routes.length).toBeGreaterThan(0);
    expect(real.alerts.length).toBeGreaterThan(0);
    expect(real.business.login.length).toBeGreaterThan(0);
    expect(real.business.mfa.length).toBeGreaterThan(0);
    expect(real.business.detection.dimensions).toHaveLength(DETECTION_DIMENSIONS.length + 1);
    expect(real.business.detection.skipped.length).toBeGreaterThan(0);
    expect(Object.keys(real.series.dropped).length).toBeGreaterThan(0);
    expect(Object.keys(real.export.rejected).length).toBeGreaterThan(0);
    // 登录结果 / MFA 动作的真实域取自模块 JSDoc 的字面量联合（不是抄合成体）
    expect(jsdocDomainOf('incLoginAttempt', 'result')).toEqual([
      'failure',
      'mfa_challenge',
      'success',
    ]);
    expect(jsdocDomainOf('incMfaAction', 'action')).toEqual([
      'disable',
      'enable',
      'recovery_regenerate',
    ]);
  });

  test('形态对拍：合成体与真实 getSnapshot() 的键路径 + 叶子类型逐条相等', () => {
    expect(skeletonOf(bodyOf(3600))).toEqual(skeletonOf(realSnapshot()));
  });

  test('标签域对拍：合成取值全部落在真实域里（路由模板 / 告警 / 登录 / MFA / 维度 / store / 拒绝原因）', () => {
    const body = bodyOf(3600);
    expect([...new Set(body.routes.map((row) => row.route))].sort()).toEqual(realRouteLabels());
    expect(Object.keys(body.latency.byRoute).sort()).toEqual(realRouteLabels());
    for (const row of body.alerts) {
      expect(alertTypeDomain()).toContain(row.type);
      expect(alertLevelDomain()).toContain(row.level);
    }
    expect(body.business.login.map((row) => row.result).sort()).toEqual(
      jsdocDomainOf('incLoginAttempt', 'result')
    );
    expect(body.business.mfa.map((row) => row.action).sort()).toEqual(
      jsdocDomainOf('incMfaAction', 'action')
    );
    expect(body.business.detection.dimensions.map((row) => row.dimension)).toEqual([
      ...DETECTION_DIMENSIONS,
      UNKNOWN_DETECTION_DIMENSION,
    ]);
    expect(Object.keys(body.series.dropped).sort()).toEqual([...metrics._SERIES_STORES].sort());
    expect(Object.keys(body.export.rejected).sort()).toEqual([...EXPORT_REJECT_REASONS].sort());
  });

  test('口径同源：series 上限 / 目标秒数 / 成功文案都从真实声明现算', () => {
    const body = bodyOf(3600);
    expect(body.series.limit).toBe(metrics._MAX_SERIES);
    const objectives = body.business.detection.dimensions.map((row) => row.objectiveSeconds);
    expect(objectives.slice(0, DETECTION_DIMENSIONS.length)).toEqual(
      DETECTION_DIMENSIONS.map(() => OBJECTIVE_SECONDS)
    );
    expect(objectives[objectives.length - 1]).toBeNull();
    const handler =
      /app\.get\('\/api\/metrics'[\s\S]*?ApiResponse\.success\(res,\s*getSnapshot\(\),\s*'([^']+)'\)/.exec(
        APP_SRC
      );
    expect(handler).not.toBeNull();
    expect(SNAPSHOT_MESSAGE).toBe(handler[1]);
  });

  test('自洽一：总量 / 错误率 / 延迟加权 / 逐路由计数对得起来', () => {
    const body = bodyOf(7200);
    const sum = (list, pick) => list.reduce((acc, row) => acc + pick(row), 0);
    expect(body.summary.totalRequests).toBe(sum(body.routes, (row) => row.requests));
    expect(body.summary.totalErrors).toBe(sum(body.routes, (row) => row.errors));
    expect(body.summary.errorRate).toBe(
      Number((body.summary.totalErrors / body.summary.totalRequests).toFixed(4))
    );
    for (const row of body.routes) {
      expect(body.latency.byRoute[row.route].count).toBe(row.requests);
      expect(row.errors).toBeLessThanOrEqual(row.requests);
    }
    const weighted = body.routes.reduce(
      (acc, row) => acc + body.latency.byRoute[row.route].avgSeconds * row.requests,
      0
    );
    expect(body.latency.avgSeconds).toBe(
      Number((weighted / body.summary.totalRequests).toFixed(6))
    );
    expect(body.routes.map((row) => row.requests)).toEqual(
      [...body.routes.map((row) => row.requests)].sort((a, b) => b - a)
    );
  });

  test('自洽二：成功率 / 检测样本数 / series 合计 / 导出与 ws 形状', () => {
    const body = bodyOf(7200);
    const login = body.business.login;
    const total = login.reduce((acc, row) => acc + row.count, 0);
    const success = login.find((row) => row.result === 'success').count;
    expect(body.business.loginSuccessRate).toBe(Number((success / total).toFixed(4)));
    for (const row of body.business.detection.dimensions) {
      expect(row.lagSampleCount).toBe(row.withinObjective + row.outsideObjective);
      expect(row.lagSecondsSum).toBe(Number(row.lagSecondsSum.toFixed(6)));
      expect(row.lagSecondsSum).toBeGreaterThan(0);
      const impliedLagMs = (row.lagSecondsSum * 1000) / row.lagSampleCount;
      // objectiveSeconds 为 null = 真实链「尚未测得目标」（other 维度从不记录），不参与比较
      if (row.objectiveSeconds !== null && row.withinObjective > row.outsideObjective) {
        expect(impliedLagMs).toBeLessThanOrEqual(row.objectiveSeconds * 1000);
      }
    }
    expect(body.series.droppedTotal).toBe(
      Object.values(body.series.dropped).reduce((acc, value) => acc + value, 0)
    );
    expect(body.export.inflight).toBeGreaterThanOrEqual(0);
    expect(body.export.queued).toBeGreaterThanOrEqual(0);
    expect(body.ws.connections).toBeGreaterThanOrEqual(0);
    expect(body.ws.inboundThrottled).toBeGreaterThanOrEqual(0);
    expect(body.ws.inboundDisconnects).toBeGreaterThanOrEqual(0);
    expect(body.process.uptimeSeconds).toBe(7200);
    expect(body.process.rssMB).toBeGreaterThan(0);
    expect(body.process.heapUsedMB).toBeGreaterThan(0);
  });

  test('单调性与仪表：计数器跨次抓取只增不减，仪表落在区间内，时间戳前进', () => {
    const early = buildMetricsSnapshot({ now: 1762000000000, uptimeSeconds: 100 });
    const later = buildMetricsSnapshot({ now: 1762000001000, uptimeSeconds: 100000 });
    const before = countersOf(early);
    const after = countersOf(later);
    expect(JSON.stringify(after)).not.toBe(JSON.stringify(before));
    for (const key of Object.keys(before)) {
      const a = before[key];
      const b = after[key];
      const pairs = Array.isArray(a)
        ? a.map((value, index) => [value, b[index]])
        : a && typeof a === 'object'
          ? Object.keys(a).map((label) => [a[label], b[label]])
          : [[a, b]];
      for (const [left, right] of pairs) {
        const leftParts = String(left).split('/').map(Number);
        const rightParts = String(right).split('/').map(Number);
        expect(rightParts[0]).toBeGreaterThanOrEqual(leftParts[0]);
        if (leftParts.length > 1) expect(rightParts[1]).toBeGreaterThanOrEqual(leftParts[1]);
      }
    }
    expect(later.timestamp).toBeGreaterThan(early.timestamp);
    expect(later.process.uptimeSeconds).toBeGreaterThan(early.process.uptimeSeconds);
    expect(later.ws.connections).toBeGreaterThanOrEqual(2);
    expect(later.ws.connections).toBeLessThan(20);
    expect(later.export.queued).toBeLessThan(3);
  });

  test('不泄漏：蜜罐 / 哨兵 / 审计链家族与口令类字段一律不出现', () => {
    const body = bodyOf(3600);
    const serialized = JSON.stringify(body);
    const bannedFamilies = [
      ...familyValues(HONEYPOT_ALERT_TYPES),
      ...familyValues(CANARY_ALERT_TYPES),
      ...familyValues(AUDIT_CHAIN_ALERT_TYPES),
    ];
    expect(bannedFamilies.length).toBeGreaterThan(0);
    for (const banned of bannedFamilies) expect(serialized).not.toContain(banned);
    // 家族词：路由模板里一个都不含（下面先自证这一点，否则这条判据可能因为「词太泛」而误伤）
    const labels = [
      ...body.routes.map((row) => row.route),
      ...body.alerts.flatMap((row) => [row.type, row.level]),
      ...body.business.login.map((row) => row.result),
      ...body.business.mfa.map((row) => row.action),
      ...body.business.detection.dimensions.map((row) => row.dimension),
      ...body.business.detection.skipped.map((row) => row.reason),
      ...Object.keys(body.series.dropped),
      ...Object.keys(body.export.rejected),
    ];
    for (const word of ['honeypot', 'decoy', 'canary', 'sentinel', 'credential']) {
      expect(labels.filter((label) => label.toLowerCase().includes(word))).toEqual([]);
      expect(serialized.toLowerCase()).not.toContain(word);
    }
    // 哨兵名按**标签等值**判（canary 名单里有 user/root/test 这类泛词：子串判会误伤
    // /api/users/:id 这种真实路由，等值判才是「身份泄漏」的正确口径）
    for (const name of DEFAULT_CANARY_USERNAMES) expect(labels).not.toContain(name);
    // 口令类**字段名**一处都不许有（值层面本来就没有口令）。映射节点的键是**路由模板**
    // （/api/auth/password 是真实路径，不是字段名），按「以 / 开头」排除——否则这条判据会把
    // 真实路由表判成泄漏，那正是「判据口径错当行为」的老毛病。
    const keys = [];
    const collectKeys = (node) => {
      if (Array.isArray(node)) node.forEach(collectKeys);
      else if (node && typeof node === 'object')
        for (const [key, child] of Object.entries(node)) {
          if (!key.startsWith('/')) keys.push(key);
          collectKeys(child);
        }
    };
    collectKeys(body);
    expect(keys.filter((key) => /password|credential|secret|token/i.test(key))).toEqual([]);
    expect(serialized).not.toContain('security:config');
    expect(serialized).not.toContain('@honeypot.invalid');
    expect(body.alerts.map((row) => row.type)).toEqual(
      body.alerts.map((row) => row.type).filter((type) => !bannedFamilies.includes(type))
    );
  });

  test('接线：只认 /api/metrics（GET/HEAD + 一个尾斜杠），其它路径与写方法都不接', () => {
    const payload = resolveMetricsPayload({ method: 'GET', path: METRICS_PATH });
    expect(payload.kind).toBe('metrics');
    expect(payload.message).toBe(SNAPSHOT_MESSAGE);
    expect(resolveMetricsPayload({ method: 'HEAD', path: METRICS_PATH }).kind).toBe('metrics');
    expect(resolveMetricsPayload({ method: 'GET', path: METRICS_PATH + '/' }).kind).toBe('metrics');
    expect(resolveMetricsPayload({ method: 'GET', path: '/API/Metrics' }).kind).toBe('metrics');
    for (const sample of [
      { method: 'GET', path: '/api' },
      { method: 'GET', path: '/api/metrics/extra' },
      { method: 'POST', path: METRICS_PATH },
      { method: 'GET', path: '/api/security/overview' },
      { method: 'GET', path: '/api/metrics//' },
    ]) {
      expect(resolveMetricsPayload(sample)).toBeNull();
    }
    expect(FACE_SRC).not.toMatch(/\/models\//);
    expect(FACE_SRC).not.toMatch(/\/services\//);
    expect(FACE_SRC).not.toMatch(/mongoose/);
  });

  test('结构证明：全新子进程里 require 完整图不落进 model/service/mongoose', () => {
    const target = path.join(ROOT, 'src', 'constants', 'honeypotDecoyMetrics.js');
    const script =
      'const m = require(' +
      JSON.stringify(target) +
      ');' +
      'const body = m.buildMetricsSnapshot({ now: 1, uptimeSeconds: 60 });' +
      'const bad = Object.keys(require.cache).filter((p) => /[\\/\\\\](models|services|controllers)[\\/\\\\]/.test(p) || /mongoose/.test(p));' +
      'console.log(JSON.stringify({ ok: body && body.summary.totalRequests > 0, bad }));';
    const out = JSON.parse(
      require('child_process').execFileSync(process.execPath, ['-e', script], { encoding: 'utf8' })
    );
    expect(out.ok).toBe(true);
    expect(out.bad).toEqual([]);
  });

  test('反向自证（判据有牙）：删一个键、把一个标签换成域外的词都必须被点名', () => {
    const real = skeletonOf(realSnapshot());
    const body = bodyOf(3600);
    const missing = JSON.parse(JSON.stringify(body));
    delete missing.summary.errorRate;
    expect(skeletonOf(missing)).not.toEqual(real);
    const cloned = JSON.parse(JSON.stringify(body));
    cloned.alerts[0].type = 'not_a_real_alert_type';
    expect(alertTypeDomain()).not.toContain(cloned.alerts[0].type);
    const drifted = JSON.parse(JSON.stringify(body));
    drifted.latency.avgSeconds = 9;
    const weighted = drifted.routes.reduce(
      (acc, row) => acc + drifted.latency.byRoute[row.route].avgSeconds * row.requests,
      0
    );
    expect(drifted.latency.avgSeconds).not.toBe(
      Number((weighted / drifted.summary.totalRequests).toFixed(6))
    );
  });
});
