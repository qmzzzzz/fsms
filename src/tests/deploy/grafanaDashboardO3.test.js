/**
 * O-3：Grafana 看板必须覆盖告警规则依赖的运行时/审计指标
 *
 * 告警触发后值班人员若在看板上找不到对应曲线，只能手工查 Prometheus —— 这正是
 * 审计报告里 O-3 的缺口。本套件把「告警规则用到的指标」与「看板查询」对账：
 * 每条 O-3 点名的新增指标都至少被一个面板查询；看板结构（id/坐标/datasource）
 * 同时做最低限度自证，防止新增面板时把 JSON 写成 Grafana 拒绝加载的形态。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const DASHBOARD = path.join(ROOT, 'deployment/observability/grafana/dashboards/xf-backend.json');

const dashboard = JSON.parse(fs.readFileSync(DASHBOARD, 'utf8'));

/** 面板里所有查询表达式（含变量展开前的原始 PromQL） */
const queries = dashboard.panels.flatMap((p) => (p.targets || []).map((t) => t.expr || ''));

describe('O-3 Grafana 看板契约', () => {
  test('JSON 结构自证：面板 id 唯一、宽度不越界、查询都指向 prometheus 数据源', () => {
    expect(dashboard.uid).toBe('xf-backend');
    expect(Array.isArray(dashboard.panels)).toBe(true);
    expect(dashboard.panels.length).toBeGreaterThan(6);

    const ids = dashboard.panels.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const p of dashboard.panels) {
      expect(typeof p.id).toBe('number');
      expect(typeof p.type).toBe('string');
      expect(p.gridPos.w).toBeLessThanOrEqual(24);
      expect(p.gridPos.x + p.gridPos.w).toBeLessThanOrEqual(24);
      for (const t of p.targets || []) {
        expect(t.datasource).toEqual({ type: 'prometheus', uid: 'prometheus' });
      }
    }
    // 每个查询的 refId 在面板内唯一（重复会让 Grafana 丢一条曲线）
    for (const p of dashboard.panels) {
      const refs = (p.targets || []).map((t) => t.refId);
      expect(new Set(refs).size).toBe(refs.length);
    }
  });

  test.each([
    ['审计丢弃', 'audit_records_dropped_total'],
    ['审计缓冲积压', 'audit_buffer_backlog_records'],
    ['readyz 判定', 'readyz_verdict'],
    ['readyz 陈旧度', 'readyz_verdict_age_seconds'],
    ['磁盘可用', 'disk_free_bytes'],
    ['磁盘总量', 'disk_total_bytes'],
    ['磁盘探测失败', 'disk_probe_failures_total'],
    ['日志转发失败', 'log_shipper_flush_failures_total'],
    ['日志丢行', 'log_shipper_dropped_lines_total'],
    ['MTTD 延迟', 'detection_lag_seconds'],
    ['MTTD 达标计数', 'detections_within_objective_total'],
    ['MTTD 目标', 'detection_objective_seconds'],
    ['MTTD 跳过', 'detection_lag_skipped_total'],
  ])('O-3：%s 指标有对应面板查询（%s）', (_label, metric) => {
    expect(queries.some((q) => q.includes(metric))).toBe(true);
  });

  test('O-3：fail-open 面板与告警规则使用同一组 type 标签', () => {
    const failOpen = queries.find((q) => q.includes('security_alerts_total{type=~'));
    expect(failOpen).toBeTruthy();
    for (const type of [
      'ip_blacklist_failopen',
      'ratelimit_store_degraded',
      'captcha_active_bound_lost',
      'captcha_switch_db_fallback',
    ]) {
      expect(failOpen).toContain(type);
    }
  });

  test('O-3：告警规则引用的每条 expr 核心指标都能在看板里看到', () => {
    const rules = fs.readFileSync(
      path.join(ROOT, 'deployment/observability/alert-rules.yml'),
      'utf8'
    );
    // 从规则文件里抽指标名（排除 annotation 里的散文），逐条确认看板有查询。
    // 只核对 O-3 新增的这组；告警文件里 up/http/security_alerts 等旧指标早已有面板。
    //
    // detection_lag_seconds / detection_objective_seconds 不在此列：告警规则不直接
    // 引用它们（判据是 detections_within_objective_total），看板上的「平均延迟 vs 目标」
    // 由 summary 的 _sum/_count 与目标 gauge 自行推导。把它们也塞进规则对账会逼着
    // 规则文件写一条没人用的 expr，那是为了让测试变绿而改生产配置。
    const RULE_METRICS = [
      'audit_records_dropped_total',
      'audit_buffer_backlog_records',
      'readyz_verdict',
      'readyz_verdict_age_seconds',
      'disk_free_bytes',
      'disk_total_bytes',
      'disk_probe_failures_total',
      'log_shipper_flush_failures_total',
      'log_shipper_dropped_lines_total',
      'detections_within_objective_total',
      'detection_lag_skipped_total',
    ];
    for (const metric of RULE_METRICS) {
      expect(rules).toContain(metric);
      expect(queries.some((q) => q.includes(metric))).toBe(true);
    }
  });
});
