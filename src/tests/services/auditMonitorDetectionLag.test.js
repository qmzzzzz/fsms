'use strict';

/**
 * auditMonitor 的 MTTD 记账与载荷透出（Plan B）
 *
 * 判据：
 *   ① 每个命中维度都按 min(firstEventAt) 计算延迟，与是否推送无关；
 *   ② 缺少 firstEventAt（旧模型/替身）不猜测、不记样本，载荷里为 null；
 *   ③ detectedAt 在 await 之后取，时钟倒挂不算 0 延迟；
 *   ④ 载荷 `detection` 经 securityAlert.sendNotification 原样透出，
 *      投递层 {...data} 透传到 webhook `alert`。
 */

jest.mock('../../models/AuditLog', () => ({ detectAnomalies: jest.fn() }));
jest.mock('../../services/securityAlert', () => ({
  shouldSendAlert: jest.fn(() => true),
  sendNotification: jest.fn(async () => {}),
}));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));
jest.mock('../../utils/httpPostJson', () => ({ postJson: jest.fn() }));

const AuditLog = require('../../models/AuditLog');
const securityAlert = require('../../services/securityAlert');
const auditMonitor = require('../../services/auditMonitor');
const detectionMetrics = require('../../utils/metricsDetection');
const { postJson } = require('../../utils/httpPostJson');
const securityAlertDelivery = require('../../services/securityAlertDelivery');

const NOW = new Date('2026-10-19T10:00:00.000Z').getTime();
const FIRST = '2026-10-19T09:57:00.000Z'; // 3 分钟前

const resultWithFirst = (firstEventAt = FIRST) => ({
  failedOperations: [{ _id: 'u1', count: 12, firstEventAt }],
  failedOperationsByIp: [{ _id: '1.2.3.4', count: 20, firstEventAt: '2026-10-19T09:59:00.000Z' }],
  unusualTimeOperations: [{ _id: 'u2', count: 8, firstEventAt: '2026-10-19T09:58:00.000Z' }],
});

describe('auditMonitor MTTD 记账', () => {
  let nowSpy;

  beforeEach(() => {
    auditMonitor.stop();
    auditMonitor.__resetForTest();
    detectionMetrics.__resetForTest();
    AuditLog.detectAnomalies.mockReset();
    securityAlert.sendNotification.mockClear();
    securityAlert.shouldSendAlert.mockClear().mockReturnValue(true);
    nowSpy = jest.spyOn(Date, 'now').mockReturnValue(NOW);
  });

  afterEach(() => {
    nowSpy.mockRestore();
    auditMonitor.stop();
  });

  test('所有命中维度都记账（含未推送维度），并按 min(firstEventAt) 计算延迟', async () => {
    AuditLog.detectAnomalies.mockResolvedValue(resultWithFirst());

    await auditMonitor.runDetection();

    const snap = detectionMetrics.getDetectionSnapshot();
    const byDim = Object.fromEntries(snap.dimensions.map((d) => [d.dimension, d]));

    // 三个维度都命中 ⇒ 三个都有样本（与推送频控无关）
    expect(byDim.high_frequency_failure.lagSampleCount).toBe(1);
    expect(byDim.high_frequency_failure.lagSecondsSum).toBe(180);
    expect(byDim.high_frequency_failure_by_ip.lagSecondsSum).toBe(60);
    expect(byDim.unusual_time_operation.lagSecondsSum).toBe(120);

    // 默认间隔 5 分钟 ⇒ 1× 目标 300s；三个都达标
    expect(byDim.high_frequency_failure.objectiveSeconds).toBe(300);
    expect(byDim.high_frequency_failure.withinObjective).toBe(1);
    expect(byDim.high_frequency_failure.outsideObjective).toBe(0);
  });

  test('超目标：lag > 1× interval 记未达标（边界按毫秒比较）', async () => {
    AuditLog.detectAnomalies.mockResolvedValue(
      resultWithFirst('2026-10-19T09:54:59.999Z') // 300001ms
    );

    await auditMonitor.runDetection();

    const row = detectionMetrics
      .getDetectionSnapshot()
      .dimensions.find((d) => d.dimension === 'high_frequency_failure');
    expect(row.outsideObjective).toBe(1);
    expect(row.withinObjective).toBe(0);
  });

  test('缺少 firstEventAt：不记样本、记跳过，载荷里 lag/target 为 null', async () => {
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [{ _id: 'u1', count: 12 }],
      failedOperationsByIp: [],
      unusualTimeOperations: [],
    });

    await auditMonitor.runDetection();

    const snap = detectionMetrics.getDetectionSnapshot();
    const row = snap.dimensions.find((d) => d.dimension === 'high_frequency_failure');
    expect(row.lagSampleCount).toBe(0);
    expect(snap.skipped.find((s) => s.reason === 'missing_first_event_at').count).toBe(1);

    const meta = securityAlert.sendNotification.mock.calls[0][3];
    expect(meta.detection).toEqual([
      {
        dimension: 'high_frequency_failure',
        lagSeconds: null,
        targetSeconds: 300,
        withinObjective: null,
        firstEventAt: null,
      },
    ]);
  });

  test('时钟倒挂：负延迟不算 0，记 negative_lag 并透出 null', async () => {
    const future = '2026-10-19T10:01:00.000Z';
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [{ _id: 'u1', count: 12, firstEventAt: future }],
      failedOperationsByIp: [],
      unusualTimeOperations: [],
    });

    await auditMonitor.runDetection();

    const snap = detectionMetrics.getDetectionSnapshot();
    expect(snap.skipped.find((s) => s.reason === 'negative_lag').count).toBe(1);
    const meta = securityAlert.sendNotification.mock.calls[0][3];
    for (const entry of meta.detection) {
      expect(entry.lagSeconds).toBeNull();
      expect(entry.withinObjective).toBeNull();
    }
  });

  test('未命中维度不产生样本，也不出现在载荷明细里', async () => {
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [],
      failedOperationsByIp: [],
      unusualTimeOperations: [{ _id: 'u2', count: 8, firstEventAt: FIRST }],
    });

    await auditMonitor.runDetection();

    const meta = securityAlert.sendNotification.mock.calls[0][3];
    expect(meta.detection.map((d) => d.dimension)).toEqual(['unusual_time_operation']);
  });

  test('全部被频控挡住时仍然记账（检测发生了，只是不通知）', async () => {
    AuditLog.detectAnomalies.mockResolvedValue(resultWithFirst());
    securityAlert.shouldSendAlert.mockReturnValue(false);

    await auditMonitor.runDetection();

    expect(securityAlert.sendNotification).not.toHaveBeenCalled();
    const snap = detectionMetrics.getDetectionSnapshot();
    const total = snap.dimensions.reduce((acc, d) => acc + d.lagSampleCount, 0);
    expect(total).toBe(3);
  });

  test('间隔调大时目标随之变化（1× 生效间隔，不是写死 5 分钟）', async () => {
    process.env.AUDIT_MONITOR_INTERVAL_MS = String(60 * 60 * 1000);
    try {
      auditMonitor.start();
      auditMonitor.stop();
      AuditLog.detectAnomalies.mockResolvedValue(resultWithFirst());

      await auditMonitor.runDetection();

      const row = detectionMetrics
        .getDetectionSnapshot()
        .dimensions.find((d) => d.dimension === 'high_frequency_failure');
      expect(row.objectiveSeconds).toBe(3600);
      expect(row.withinObjective).toBe(1);
    } finally {
      delete process.env.AUDIT_MONITOR_INTERVAL_MS;
    }
  });

  test('投递层透传：webhook 的 alert.detection 与载荷一致（不丢字段）', async () => {
    // 用真实投递模块验证 {...data} 透传，而不是只看 sendNotification 的实参。
    // 频控/最小级别/白名单都在投递层之前，故这里直接给全放行条件。
    const saved = {
      webhook: process.env.SECURITY_ALERT_WEBHOOK,
      min: process.env.SECURITY_ALERT_MIN_LEVEL,
      allow: process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST,
    };
    process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.invalid/hook';
    process.env.SECURITY_ALERT_MIN_LEVEL = 'low';
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'hooks.example.invalid';
    postJson.mockResolvedValue({ ok: true, status: 200 });

    const detection = [
      {
        dimension: 'high_frequency_failure',
        lagSeconds: 120,
        targetSeconds: 300,
        withinObjective: true,
        firstEventAt: FIRST,
      },
    ];
    try {
      await securityAlertDelivery.sendNotification('audit_anomaly_detected', 'high', '探针', {
        detection,
      });

      expect(postJson).toHaveBeenCalledTimes(1);
      const body = JSON.parse(postJson.mock.calls[0][2]);
      expect(body.alert.detection).toEqual(detection);
    } finally {
      for (const [key, value] of Object.entries({
        SECURITY_ALERT_WEBHOOK: saved.webhook,
        SECURITY_ALERT_MIN_LEVEL: saved.min,
        SECURITY_ALERT_WEBHOOK_ALLOWLIST: saved.allow,
      })) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      postJson.mockReset();
    }
  });
});
