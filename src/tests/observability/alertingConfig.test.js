/**
 * 告警触达链路配置一致性测试（G-2 回归守护）
 *
 * 四个配置文件分散在 deployment/observability/ 与根目录，任何一侧单独
 * 修改都可能让链路「看起来在、实际断」：规则引用的指标不存在、severity
 * 没有匹配路由、prometheus 没指向 alertmanager、compose 没挂载配置。
 * 本测试用文本断言锁定四者之间的契约（不引入 yaml 解析依赖）。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const prometheusYml = read('deployment/observability/prometheus.yml');
const alertRulesYml = read('deployment/observability/alert-rules.yml');
const alertmanagerYml = read('deployment/observability/alertmanager.yml');
const composeYml = read('docker-compose.yml');
const metricsJs = read('src/utils/metrics.js');

describe('告警链路配置一致性（G-2）', () => {
  describe('prometheus → alertmanager 接线', () => {
    test('alerting 段指向 alertmanager:9093', () => {
      expect(prometheusYml).toMatch(/alerting:\s*\n\s+alertmanagers:/);
      expect(prometheusYml).toContain("targets: ['alertmanager:9093']");
    });

    test('rule_files 装载 alert-rules.yml（容器内路径）', () => {
      expect(prometheusYml).toContain('/etc/prometheus/alert-rules.yml');
    });

    test('抓取 job 名与规则表达式中的 job 标签一致', () => {
      const jobMatch = prometheusYml.match(/job_name:\s*([\w-]+)/);
      expect(jobMatch).not.toBeNull();
      const jobName = jobMatch[1];
      // 规则里所有 up{job="..."} 必须指向同一 job，否则 BackendDown 恒不触发
      const ruleJobs = [...alertRulesYml.matchAll(/up\{job="([\w-]+)"\}/g)].map((m) => m[1]);
      expect(ruleJobs.length).toBeGreaterThan(0);
      expect([...new Set(ruleJobs)]).toEqual([jobName]);
    });
  });

  describe('规则 → 路由的 severity 覆盖', () => {
    test('每条告警规则都声明了 severity 标签', () => {
      const ruleCount = (alertRulesYml.match(/^\s*- alert:/gm) || []).length;
      const severityCount = (alertRulesYml.match(/severity:\s*(critical|warning)/g) || []).length;
      expect(ruleCount).toBeGreaterThanOrEqual(4); // 宕机/错误率/延迟/安全突发
      expect(severityCount).toBe(ruleCount);
    });

    test('规则使用的每个 severity 在 alertmanager 都有匹配路由', () => {
      const ruleSeverities = new Set(
        [...alertRulesYml.matchAll(/severity:\s*(critical|warning)/g)].map((m) => m[1])
      );
      for (const sev of ruleSeverities) {
        expect(alertmanagerYml).toContain(`severity="${sev}"`);
      }
    });

    test('顶级路由存在兜底 receiver，且该 receiver 已定义（告警不允许静默丢失）', () => {
      const routeMatch = alertmanagerYml.match(
        /route:\s*\n(?:\s*#[^\n]*\n)*\s*receiver:\s*([\w-]+)/
      );
      expect(routeMatch).not.toBeNull();
      const rootReceiver = routeMatch[1];
      expect(alertmanagerYml).toMatch(new RegExp(`name:\\s*${rootReceiver}\\b`));
    });

    test('critical/warning 接收器都启用了恢复通知', () => {
      const sendResolved = (alertmanagerYml.match(/send_resolved:\s*true/g) || []).length;
      expect(sendResolved).toBeGreaterThanOrEqual(2);
    });
  });

  describe('规则引用的指标与后端导出一致', () => {
    // 规则表达式引用了不存在的指标名时不会报错，只会「永远不触发」——
    // 这类静默失效只能用契约测试拦截
    const ruleMetrics = [
      'http_requests_total',
      'http_request_duration_seconds',
      'security_alerts_total',
    ];

    test.each(ruleMetrics)('指标 %s 在 src/utils/metrics.js 有定义', (metric) => {
      expect(metricsJs).toContain(metric);
    });
  });

  describe('docker-compose 编排', () => {
    test('alertmanager 服务使用钉版镜像且配置只读挂载', () => {
      const serviceBlock = composeYml.slice(composeYml.indexOf('alertmanager:'));
      expect(serviceBlock).toMatch(/image:\s*prom\/alertmanager:v[\d.]+/); // 钉版，禁 latest
      expect(composeYml).toContain(
        './deployment/observability/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro'
      );
    });

    test('prometheus 服务同时挂载 prometheus.yml 与 alert-rules.yml', () => {
      expect(composeYml).toContain(
        './deployment/observability/prometheus.yml:/etc/prometheus/prometheus.yml:ro'
      );
      expect(composeYml).toContain(
        './deployment/observability/alert-rules.yml:/etc/prometheus/alert-rules.yml:ro'
      );
    });

    test('通知状态持久化卷已声明（重启不丢静默记录）', () => {
      expect(composeYml).toContain('alertmanager-data:/alertmanager');
      expect(composeYml).toMatch(/^\s{2}alertmanager-data:/m);
    });
  });
});
