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
// 指标定义分布在四个文件：metrics.js 主体 + 三组单独成文件的信号
// （metricsAuditDrops 审计丢失、metricsRuntime 运行时健康、metricsDetection 检测延迟）。
//
// 只读 metrics.js 会漏掉后两组；而更早的写法之所以能过，靠的是 metrics.js 的
// **头部注释**里把 audit_records_dropped_total 列了进去——注释不是定义，
// 那是"文档替实现背书"。改成三源并集后，至少要求名字出现在真正产出它的文件里。
//
// 能力边界（如实说明）：这仍是**文本**判据，不是"这个名字真的被渲染出来"。
// 后者的可执行判据在 src/tests/observability/runtimeMetricsCoverage.test.js
// （它调 formatPrometheus() 并断言输出里真的有这些 series）。
const metricsJs = [
  'src/utils/metrics.js',
  'src/utils/metricsAuditDrops.js',
  'src/utils/metricsRuntime.js',
  'src/utils/metricsDetection.js',
]
  .map(read)
  .join('\n');

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
    // 这类静默失效只能用契约测试拦截。
    //
    // 指标名从 alert-rules.yml **推导**，不写死清单：手写清单是第二事实源，
    // 新增规则而忘了同步这里，门禁就变成"全绿但没在守护"（本条此前的 3 项
    // 手写名单就是这种情况——metrics_series_dropped_total 不会被它管到）。
    // 语法依据：PromQL 里函数名后跟 `(`，指标名后跟 `{`（标签选择器）或
    // `[`（区间向量），据此把 rate/sum/increase/histogram_quantile 分出去；
    // 再把 annotations 里的 `{{ $labels.x }}` 模板整体摘掉，否则模板里的
    // `store` 会被当成指标名（实测踩过）。`up` 由抓取器自身产出，白名单放行。
    const PROM_OWN = ['up'];
    const referencedMetrics = () => {
      const promql = alertRulesYml.replace(/\{\{[\s\S]*?\}\}/g, '');
      const names = new Set();
      for (const m of promql.matchAll(/([a-zA-Z_:][a-zA-Z0-9_:]*)\s*[[{]/g)) {
        if (!PROM_OWN.includes(m[1])) names.add(m[1]);
      }
      return [...names];
    };

    test('推导结果覆盖主力指标（防正则退化让门禁空转）', () => {
      const names = referencedMetrics();
      expect(names.length).toBeGreaterThanOrEqual(4);
      for (const expected of [
        'http_requests_total',
        'http_request_duration_seconds_bucket',
        'security_alerts_total',
        'metrics_series_dropped_total',
      ]) {
        expect(names).toContain(expected);
      }
      // 白名单确实生效：up 出现在 expr 里但不该混进"必须由本服务导出"的名单
      expect(alertRulesYml).toContain('up{job=');
      expect(names).not.toContain('up');
    });

    test.each(referencedMetrics())('指标 %s 在本服务的指标源文件里有定义', (metric) => {
      expect(metricsJs).toContain(metric);
    });
  });

  describe('docker-compose 编排', () => {
    test('alertmanager 服务使用钉版镜像且配置只读挂载', () => {
      const serviceBlock = composeYml.slice(composeYml.indexOf('\n  alertmanager:'));
      expect(serviceBlock).toMatch(/image:\s*prom\/alertmanager:v[\d.]+/); // 钉版，禁 latest
      // F-15：运行侧改为只读消费命名卷 alertmanager-config（宿主配置先由
      // alertmanager-config-init 复制进卷并 chown 65534，避免 0600 私有文件
      // 让容器内 nobody 读不到而启动失败）。挂载源与启动闸仍共用
      // ALERTMANAGER_CONFIG_PATH，避免「校验 A、运行 B」——那一半在下一条用例里钉。
      expect(serviceBlock).toContain('alertmanager-config:/etc/alertmanager:ro');
      expect(serviceBlock).toMatch(
        /alertmanager-config-init:\s*\n\s*condition:\s*service_completed_successfully/
      );
    });

    test('配置字节的唯一来源：校验容器与初始化容器共用 ALERTMANAGER_CONFIG_PATH', () => {
      // 校验源（check）与运行源（init 复制进卷的那份）必须是同一个宿主文件，
      // 否则闸校验的是 A、实际跑的是 B。
      const checkStart = composeYml.indexOf('\n  alertmanager-config-check:');
      const initStart = composeYml.indexOf('\n  alertmanager-config-init:');
      const runtimeStart = composeYml.indexOf('\n  alertmanager:');
      expect(checkStart).toBeGreaterThan(-1);
      expect(initStart).toBeGreaterThan(checkStart);
      expect(runtimeStart).toBeGreaterThan(initStart);
      const source = '${ALERTMANAGER_CONFIG_PATH:-./deployment/observability/alertmanager.yml}';
      expect(composeYml.slice(checkStart, initStart)).toContain(
        `${source}:/etc/alertmanager/alertmanager.yml:ro`
      );
      expect(composeYml.slice(initStart, runtimeStart)).toContain(
        `${source}:/source/alertmanager.yml:ro`
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

// ============================================================================
// 告警标签可归因（2026-10-24）
//
// 本轮修的两个真实缺陷：HighErrorRate / SecurityAlertBurst 用 bare `sum(...)`
// 聚合，Prometheus 的聚合运算符在不写 `by` 时**丢弃全部标签**（含 instance），
// 于是多实例部署下只剩一条无主的时间序列——告警说不清是哪台机器出错，
// annotations 里的 {{ $labels.instance }} 渲染成空串，面板也无法按实例下钻。
// 单实例环境里这个缺陷"看起来完全正常"，所以只能靠契约测试钉住。
//
// 另一件事是抑制规则。此前 alertmanager.yml 写的是「任何 critical 抑制同实例的
// 任何 warning，equal: ['instance']」，理由为「BackendDown 时 HighP95Latency 必然
// 伴随」。复核结论是**整条规则不成立**，已在 alertmanager.yml 里连同三条理由一起
// 写明并清空（见该文件 inhibit_rules 上方注释）。这里把"清空"这个决定钉住，
// 避免后来者当成漏配又随手加回一条 severity 一刀切的规则。
// ============================================================================
describe('告警标签可归因与抑制规则口径', () => {
  /** 规则块：`- alert:` 到下一个 `- alert:` 之前，剔除注释行（注释里的示例不得参与判定） */
  const ruleBlocks = alertRulesYml
    .split(/^\s*- alert:\s*/m)
    .slice(1)
    .map((raw) => ({
      name: raw.split('\n')[0].trim(),
      code: raw
        .split('\n')
        .filter((line) => !/^\s*#/.test(line))
        .join('\n'),
    }));
  const ruleNames = ruleBlocks.map((r) => r.name);

  test('前提自证：规则块切分成功（防空集假绿）', () => {
    const declared = (alertRulesYml.match(/^\s*- alert:/gm) || []).length;
    expect(ruleBlocks.length).toBe(declared);
    expect(ruleBlocks.length).toBeGreaterThanOrEqual(4);
    expect(ruleNames).toContain('HighErrorRate');
    expect(ruleNames).toContain('SecurityAlertBurst');
    expect(ruleNames).toContain('HighP95Latency');
  });

  test('不出现 bare sum(...)：聚合必须写 by (...)，否则 instance 被整体丢弃', () => {
    // `sum by (x) (...)` 中 sum 后面跟的是 by，所以 /\bsum\s*\(/ 只命中 bare sum。
    // BackendDown 是唯一例外：判据刻意是"两色都抓不到"（sum(up)==0），
    // 按 instance 聚合会在蓝绿未同时运行时永久红着——一条永远在响的告警等于没有告警。
    const LABEL_DROP_OK = new Set(['BackendDown']);
    const offenders = ruleBlocks
      .filter((r) => /\bsum\s*\(/.test(r.code) && !LABEL_DROP_OK.has(r.name))
      .map((r) => r.name);
    expect(offenders).toEqual([]);
  });

  test('引用 $labels.instance 的规则必须保留 instance 标签', () => {
    const offenders = [];
    for (const { name, code } of ruleBlocks) {
      if (!/\$labels\.instance/.test(code)) continue;
      if (/\bsum\s*\(/.test(code)) {
        offenders.push(`${name}: bare sum 丢掉了全部标签`);
        continue;
      }
      for (const m of code.matchAll(/sum by \(([^)]*)\)/g)) {
        if (!/\binstance\b/.test(m[1])) offenders.push(`${name}: sum by(${m[1]}) 未保留 instance`);
      }
    }
    expect(offenders).toEqual([]);
  });

  test('两条曾用 bare sum 的规则现按 instance 聚合（回归锚点）', () => {
    const block = (n) => ruleBlocks.find((r) => r.name === n).code;
    expect(block('HighErrorRate')).toMatch(
      /sum by \(instance\) \(rate\(http_requests_total\{status_code=~"5\.\."\}\[5m\]\)\)/
    );
    expect(block('HighErrorRate')).toMatch(
      /sum by \(instance\) \(rate\(http_requests_total\[5m\]\)\)/
    );
    expect(block('SecurityAlertBurst')).toMatch(
      /sum by \(instance\) \(increase\(security_alerts_total\[10m\]\)\)/
    );
  });

  test('抑制规则：当前为空（已复核），非空时两侧必须用 alertname 精确指定', () => {
    const section = (alertmanagerYml.split(/^inhibit_rules:/m)[1] || '').trim();
    expect(section).not.toBe(''); // 段存在（缺整个键也是错）
    if (section === '[]') {
      // 当前结论：规则集里没有一对"目标告警是源告警的纯后果、且标签可对齐"的组合。
      // 三条理由见 alertmanager.yml 内注释（原始理由事实错误 / equal 标签在
      // absent() 分支不存在 / 一刀切会压掉根因信号）。
      return;
    }
    const entries = section.split(/^\s*-\s+source_matchers:/m).slice(1);
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      const [sourcePart, targetPart = ''] = entry.split(/target_matchers:/);
      // severity 一刀切会压掉同实例的独立信号（AuditRecordsDropped 压 DiskSpaceLow），
      // 因此两侧都必须点名 alertname。
      expect(sourcePart).toMatch(/alertname\s*=/);
      expect(targetPart).toMatch(/alertname\s*=/);
    }
  });

  test('absent() 分支的存在是 inhibit 不能用 instance 作 equal 的前提（钉住事实）', () => {
    // Alertmanager 的 equal 要求该标签在源与目标**两侧都存在**才比较；absent()
    // 只回填选择器里的标签，所以 absent(readyz_verdict{job="xf-app"}) 产出的告警
    // 只有 job、没有 instance。ReadinessProbeMissing 同时有 absent() 与带 instance
    // 的两条分支——"后端真挂了"时命中的恰恰是无 instance 的那条。
    expect(alertRulesYml).toMatch(/absent\(readyz_verdict\{job="xf-app"\}\)/);
    expect(alertRulesYml).toMatch(/readyz_verdict_age_seconds\{job="xf-app"\}/);
  });
});
