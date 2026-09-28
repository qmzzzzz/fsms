/**
 * 审计丢失/积压的 Prometheus 信号（2026-09-26 审计 Top-6）
 *
 * 缺陷原文：「`src/utils/metrics.js` vs `auditBuffer.js` —— 审计数据丢失/积压
 * 没有任何 Prometheus 指标 → 现有 5 条告警规则无一覆盖"审计丢弃"这一合规核心故障；
 * `droppedCount` 只能靠需 `security:audit` 权限的 JSON API 查看」，
 * 修复面「导出 2 个指标」。
 *
 * 为什么这条值得单独一套用例：
 *   auditBuffer 自己的注释写着「静默丢弃审计数据在合规上等同于篡改」——
 *   而"能经 API 查到"与"能被监控告警到"是两件事：前者要求有人主动去查、
 *   且有 security:audit 权限；后者才是"丢数据时系统自己喊出来"。
 *   在补齐之前，三条丢弃路径（缓冲超硬上限裁剪 / 毒文档整批丢弃 / 预铸造拒收）
 *   全部只累加模块内的 `droppedCount`，Prometheus 侧**一个字都没有**。
 *
 * 本文件钉四件事：
 *   ① 计数器口径：闭合 reason 集合、每次上报、非法 reason 不新建 series；
 *   ② 渲染口径：恒定输出各 reason 行（含 0）+ 积压 gauge（含 0）；
 *   ③ 上报接线：真实走一遍缓冲溢出路径，指标必须动；且源码里不得存在
 *      绕过记账函数的 `droppedCount +=`（新增第四条丢弃路径时忘上报 = 红）；
 *   ④ 告警规则：规则真的存在、且引用的指标名在本服务有定义（否则规则永不触发）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');

describe('Top-6 ① 计数器口径：闭合 reason、非法值不新建 series', () => {
  let metrics;

  beforeAll(() => {
    metrics = require('../../utils/metrics');
  });

  beforeEach(() => {
    metrics._auditDrops.clear();
  });

  test('按 reason 累加条数（n 默认 1，支持批量）', () => {
    metrics.incAuditDrop('buffer_overflow');
    metrics.incAuditDrop('buffer_overflow', 4);
    metrics.incAuditDrop('poison_doc', 2);
    expect(metrics._auditDrops.get('buffer_overflow')).toBe(5);
    expect(metrics._auditDrops.get('poison_doc')).toBe(2);
  });

  test('闭合集合之外的 reason 并入 other（不允许自由文本建 series）', () => {
    // 高基数纪律：reason 一旦接受调用方传的自由文本，就等于用计数器监控高基数——
    // 与 metrics_series_dropped_total 的 store 闭合集合同一条规矩。
    metrics.incAuditDrop('someone_typoed_this');
    metrics.incAuditDrop('buffer_overflow');
    expect(metrics._auditDrops.get('other')).toBe(1);
    expect([...metrics._auditDrops.keys()].sort()).toEqual(['buffer_overflow', 'other']);
  });

  test('非正数 / 非数值不记账（"丢了 0 条"出现即调用方算错，静默接受会变成漂移）', () => {
    metrics.incAuditDrop('poison_doc', 0);
    metrics.incAuditDrop('poison_doc', -3);
    metrics.incAuditDrop('poison_doc', NaN);
    metrics.incAuditDrop('poison_doc', Infinity);
    expect(metrics._auditDrops.get('poison_doc')).toBeUndefined();
  });

  test('省略 n 表示「这一条」（默认值 1），而不是 0', () => {
    metrics.incAuditDrop('precast');
    expect(metrics._auditDrops.get('precast')).toBe(1);
  });
});

describe('Top-6 ② 渲染口径：恒定行（含 0），面板不必区分"没丢过"与"没上报"', () => {
  let metrics;

  beforeAll(() => {
    metrics = require('../../utils/metrics');
  });

  beforeEach(() => {
    metrics._auditDrops.clear();
  });

  test('四个 reason 各一行（即使全为 0）+ 积压 gauge 一行', () => {
    const out = metrics.formatPrometheus();
    for (const reason of ['buffer_overflow', 'poison_doc', 'precast', 'other']) {
      expect(out).toContain(`audit_records_dropped_total{reason="${reason}"} 0`);
    }
    expect(out).toMatch(/^audit_buffer_backlog_records \d+$/m);
    expect(out).toContain('# TYPE audit_records_dropped_total counter');
    expect(out).toContain('# TYPE audit_buffer_backlog_records gauge');
  });

  test('上报后的数值出现在文本里（文本与内部计数同源）', () => {
    metrics.incAuditDrop('poison_doc', 7);
    expect(metrics.formatPrometheus()).toContain(
      'audit_records_dropped_total{reason="poison_doc"} 7'
    );
  });

  test('积压 gauge 取的是审计缓冲的真实长度（拉取时取值，不是缓存的快照）', () => {
    const auditBuffer = require('../../services/auditBuffer');
    auditBuffer.__resetForTest();
    const empty = metrics.formatPrometheus().match(/^audit_buffer_backlog_records (\d+)$/m);
    expect(empty[1]).toBe('0');

    auditBuffer.push({ action: 'probe', method: 'GET', path: '/x' });
    const one = metrics.formatPrometheus().match(/^audit_buffer_backlog_records (\d+)$/m);
    expect(one[1]).toBe('1');

    auditBuffer.__resetForTest();
    const back = metrics.formatPrometheus().match(/^audit_buffer_backlog_records (\d+)$/m);
    expect(back[1]).toBe('0');
  });
});

describe('Top-6 ③ 上报接线：真实丢弃路径必须动指标', () => {
  const ORIG_HARD_LIMIT = process.env.AUDIT_BUFFER_HARD_LIMIT;

  afterEach(() => {
    if (ORIG_HARD_LIMIT === undefined) delete process.env.AUDIT_BUFFER_HARD_LIMIT;
    else process.env.AUDIT_BUFFER_HARD_LIMIT = ORIG_HARD_LIMIT;
    jest.resetModules();
  });

  test('缓冲超硬上限裁剪 → audit_records_dropped_total{reason="buffer_overflow"}', () => {
    // 用 isolateModules 把硬上限压到 3：这条路径在生产里要等 DB 长时间不可用
    // 才会走到，不压上限就只能靠读代码"相信"它会上报。
    process.env.AUDIT_BUFFER_HARD_LIMIT = '3';
    jest.resetModules();
    const auditBuffer = require('../../services/auditBuffer');
    const metrics = require('../../utils/metrics');
    metrics._auditDrops.clear();

    for (let i = 0; i < 5; i += 1) {
      auditBuffer.push({ action: 'probe', method: 'GET', path: `/x/${i}` });
    }

    expect(auditBuffer.getStats().droppedCount).toBe(2);
    expect(metrics._auditDrops.get('buffer_overflow')).toBe(2);
  });

  test('写法门禁：`droppedCount +=` 只能出现在记账函数里（新增丢弃路径忘上报 = 红）', () => {
    // 判据是"记账只有一个入口"。三条路径各自 `droppedCount += n` 的写法
    // 本身没错，错在**新增第四条时没人会想起来同步上报**——
    // 本仓同类事故（"已修的同类漏了一处"）已发生多次，故用结构断言堵住。
    const src = fs
      .readFileSync(path.join(ROOT, 'src/services/auditBuffer.js'), 'utf8')
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
      .join('\n');
    const bumps = src.match(/droppedCount\s*\+=/g) || [];
    expect(bumps.length).toBe(1);
    // 且那唯一一处必须紧邻指标上报（同一个函数体内）
    expect(src).toMatch(/droppedCount \+= n;[\s\S]{0,400}?incAuditDrop\(reason, n\)/);
    // 三条路径都必须经记账函数（reason 是必填实参，漏传即静态可见）
    expect(src).toContain("noteDropped(overflow, 'buffer_overflow')");
    expect(src).toContain("noteDropped(doomed.length, 'poison_doc')");
    expect(src).toContain("noteDropped(n, 'precast')");
  });

  test('前提自证：审计缓冲的 WAL 在测试里未启用（本组不会向仓库写 WAL 文件）', () => {
    // 不 start() ⇒ walEnabled 为 false ⇒ appendLine 空转。若哪天有人让 push 隐式启动 WAL，
    // 这条会红，提醒本组用例需要改到临时目录去跑。
    const auditBuffer = require('../../services/auditBuffer');
    expect(auditBuffer.isWalEnabled()).toBe(false);
  });
});

describe('Top-6 ④ 告警规则：丢了审计必须有人被叫醒', () => {
  const rules = fs.readFileSync(
    path.join(ROOT, 'deployment/observability/alert-rules.yml'),
    'utf8'
  );
  const metricsJs = fs.readFileSync(path.join(ROOT, 'src/utils/metrics.js'), 'utf8');

  test('存在引用 audit_records_dropped_total 的规则，且严重度为 critical', () => {
    // 审计留痕出现空洞 = 合规核心故障，不是"性能劣化"级别的提示。
    expect(rules).toContain('audit_records_dropped_total');
    const block = rules.slice(rules.indexOf('audit_records_dropped_total'));
    expect(block).toMatch(/severity:\s*critical/);
    expect(rules).toContain('alert: AuditRecordsDropped');
  });

  test('规则描述里给出可执行的处置方向（不只说"出事了"）', () => {
    const block = rules.slice(rules.indexOf('alert: AuditRecordsDropped'));
    expect(block).toContain('audit_buffer_backlog_records');
    expect(block).toMatch(/wal|discarded/i);
  });

  test('规则引用的指标名在本服务有定义（否则规则永不触发，CI 却全绿）', () => {
    for (const name of ['audit_records_dropped_total', 'audit_buffer_backlog_records']) {
      expect(metricsJs).toContain(name);
    }
  });
});
