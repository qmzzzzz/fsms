/**
 * P3：诱饵 metrics 告警序列不得包含真实系统从不投递的类型。
 *
 * 真实 /api/metrics 的 alerts 序列来自 securityAlertDelivery.sendNotification 的实投计数；
 * `unusual_time_access` 在投递链路上没有任何调用点（审计 riskFactors 里出现 ≠ 告警类型投递），
 * 诱饵序列收录它即构成"真实面永远不会出现的指纹差异"。
 */
const { buildMetricsSnapshot } = require('../../constants/honeypotDecoyMetrics');
const { ALERT_TYPES } = require('../../services/alertTypes');

describe('诱饵 metrics 告警序列的标签域（P3）', () => {
  test('不含真实系统从不投递的 unusual_time_access', () => {
    const body = buildMetricsSnapshot({ now: 1762000000000, uptimeSeconds: 3600 });
    const types = body.alerts.map((row) => row.type);
    expect(types).not.toContain('unusual_time_access');
  });

  test('其余告警类型/级别仍全部落在真实枚举域内（形态对拍不回归）', () => {
    const body = buildMetricsSnapshot({ now: 1762000000000, uptimeSeconds: 3600 });
    for (const row of body.alerts) {
      expect(Object.values(ALERT_TYPES)).toContain(row.type);
      expect(['low', 'medium', 'high', 'critical']).toContain(row.level);
    }
    expect(body.alerts.length).toBeGreaterThan(0);
  });
});
