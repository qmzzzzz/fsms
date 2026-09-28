/**
 * 审计异常监控的告警闭环契约（+ 间隔下限）
 *
 * 缺陷一（实测于修复前）：detectAnomalies 返回三个维度，
 * 但 runDetection 只读 failedOperations / unusualTimeOperations 两个，
 * `failedOperationsByIp` 被整段丢弃 ⇒ **只有 IP 维度命中时既不记日志也不告警**，
 * 而那条聚合每轮都在白跑。典型漏报形态：跨多账号口令喷洒——
 * 单账号失败次数被摊薄不过阈值，但某些来源 IP 早已过阈。
 *
 * 缺陷二：AUDIT_MONITOR_INTERVAL_MS 直传 setInterval，
 * parseInt('-5') 非 NaN ⇒ `-5 || DEFAULT` 取 -5 ⇒ Node 把间隔抬成 1ms，
 * 每 1ms 跑三条审计聚合（自我 DoS）。
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

const AuditLog = require('../../models/AuditLog');
const securityAlert = require('../../services/securityAlert');
const auditMonitor = require('../../services/auditMonitor');

const DAY = 'day-window';
jest.mock('../../constants/timezone', () => ({
  businessDateParts: () => ({ dateStr: DAY }),
  BUSINESS_TIMEZONE: 'Asia/Shanghai',
  OFF_HOURS_START: 22,
  OFF_HOURS_END: 6,
}));

describe('auditMonitor 告警闭环', () => {
  beforeEach(() => {
    auditMonitor.stop();
    // 本文件把 shouldSendAlert mock 成恒 true，所以"当日已推送"这条真实抑制
    // 必须由被测模块自己的模块级表承担——多条用例共用同一个固定业务日，
    // 不重置就会从第二条用例起全部静默（假红），且随机顺序下红的位置还会变。
    auditMonitor.__resetForTest();
    jest.clearAllMocks();
    securityAlert.shouldSendAlert.mockReturnValue(true);
    securityAlert.sendNotification.mockResolvedValue(undefined);
  });

  test('缺陷用例：只有 IP 维度命中也必须告警（修复前完全不告警）', async () => {
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [],
      failedOperationsByIp: [{ _id: '1.2.3.4', count: 42 }],
      unusualTimeOperations: [],
    });

    await auditMonitor.runDetection();

    expect(securityAlert.sendNotification).toHaveBeenCalledTimes(1);
    const [type, level, message, meta] = securityAlert.sendNotification.mock.calls[0];
    expect(type).toBe('audit_anomaly_detected');
    expect(level).toBe('high');
    expect(meta.dimensions).toEqual(['高频失败来源 IP']);
    expect(meta.failedOperationsByIp).toHaveLength(1);
    // 文案必须区分"用户"与"来源 IP"，不能把 IP 数当用户数报
    expect(message).toContain('0 个高频失败用户');
    expect(message).toContain('1 个高频失败来源 IP');
    // IP 维度用独立的频控键，不得复用用户维度的键
    expect(securityAlert.shouldSendAlert).toHaveBeenCalledWith(
      expect.stringContaining('_by_ip_' + DAY)
    );
  });

  test('三个维度各自独立过闸：只有 IP 过闸时只推 IP 维度', async () => {
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [{ _id: 'u1', count: 9 }],
      failedOperationsByIp: [{ _id: '1.2.3.4', count: 42 }],
      unusualTimeOperations: [{ _id: 'u2', count: 7 }],
    });
    securityAlert.shouldSendAlert.mockImplementation((key) => key.includes('_by_ip_'));

    await auditMonitor.runDetection();

    const [, , , meta] = securityAlert.sendNotification.mock.calls[0];
    expect(meta.dimensions).toEqual(['高频失败来源 IP']);
  });

  test('兼容旧签名：结果里没有 failedOperationsByIp 字段不得抛错', async () => {
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [{ _id: 'u1', count: 9 }],
      unusualTimeOperations: [],
    });

    await expect(auditMonitor.runDetection()).resolves.toBeUndefined();
    const [, , , meta] = securityAlert.sendNotification.mock.calls[0];
    expect(meta.dimensions).toEqual(['高频失败']);
    expect(meta.failedOperationsByIp).toEqual([]);
  });

  test('频控全挡：只记日志不推送', async () => {
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [{ _id: 'u1', count: 9 }],
      failedOperationsByIp: [{ _id: '1.2.3.4', count: 42 }],
      unusualTimeOperations: [{ _id: 'u2', count: 7 }],
    });
    securityAlert.shouldSendAlert.mockReturnValue(false);

    await auditMonitor.runDetection();
    expect(securityAlert.sendNotification).not.toHaveBeenCalled();
  });

  test('反向闸：三维度全为空不得告警（防"改成恒推"混过上面的用例）', async () => {
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [],
      failedOperationsByIp: [],
      unusualTimeOperations: [],
    });

    await auditMonitor.runDetection();
    expect(securityAlert.sendNotification).not.toHaveBeenCalled();
    expect(securityAlert.shouldSendAlert).not.toHaveBeenCalled();
  });

  test('聚合抛错必须被吞并，不让定时任务打崩进程', async () => {
    AuditLog.detectAnomalies.mockRejectedValue(new Error('mongo down'));
    await expect(auditMonitor.runDetection()).resolves.toBeUndefined();
    expect(securityAlert.sendNotification).not.toHaveBeenCalled();
  });
});

describe('auditMonitor.start 的间隔下限', () => {
  let spy;

  beforeEach(() => {
    auditMonitor.stop();
    spy = jest
      .spyOn(global, 'setInterval')
      .mockImplementation(() => ({ unref: jest.fn(), refresh: jest.fn() }));
  });
  afterEach(() => {
    auditMonitor.stop();
    spy.mockRestore();
    delete process.env.AUDIT_MONITOR_INTERVAL_MS;
  });

  const startedInterval = () => spy.mock.calls[spy.mock.calls.length - 1][1];

  // 注：'-1' 走 统一判据（非法 ⇒ 回落**默认** 300000 + 告警），
  // 而不是落到 30s 下限——下限只约束"合法但过小"的正数。两者语义不同，都要保住。
  test.each([
    ['-1', 300000],
    ['0', 300000],
    ['1', 30000],
    ['29999', 30000],
    ['garbage', 300000],
    ['', 300000],
    ['300000', 300000],
  ])('AUDIT_MONITOR_INTERVAL_MS=%s ⇒ 实际间隔 %i', (raw, expected) => {
    if (raw === '') delete process.env.AUDIT_MONITOR_INTERVAL_MS;
    else process.env.AUDIT_MONITOR_INTERVAL_MS = raw;
    auditMonitor.start();
    expect(startedInterval()).toBe(expected);
  });

  test('低于下限要留下 warn 痕迹（不能静默改运维配置）', () => {
    process.env.AUDIT_MONITOR_INTERVAL_MS = '5';
    const logger = require('../../utils/logger');
    logger.warn.mockClear();
    auditMonitor.start();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('最小间隔'));
  });
});
