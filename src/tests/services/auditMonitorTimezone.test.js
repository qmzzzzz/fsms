/**
 * auditMonitor 告警频控时区口径回归测试（时区分叉修复）
 *
 * 修复背景：runDetection 的频控 key 此前用 `new Date().toISOString().slice(0,10)`
 * （UTC 日期）拼装，UTC+8 下要到北京时间 08:00 才换天，与 securityController
 * 今日统计的零点口径分叉——同一自然日 08:00 前后各能推一次告警，
 * 「每日一次」频控实际失效。现统一为 P3-18 业务时区声明 businessDateParts().dateStr。
 *
 * 本文件把全局时钟固定在「UTC 日期与业务时区日期分叉」的敏感时刻
 * （UTC 2026-09-01 18:00 = 北京 2026-09-02 02:00），验证频控 key 锚定
 * 业务时区日期（09-02）而非 UTC 日期（09-01），防止回归。
 * 附带覆盖推送/频控拒绝/检测异常三条分支，收紧 auditMonitor 覆盖率棘轮。
 *
 * 边界说明：本文件不触库（AuditLog/securityAlert 均 mock），固定时钟
 * 仅影响本文件进程内执行期，测试后恢复，不影响 mongodb-memory-server。
 */

const RealDate = Date;
// 分叉敏感时刻：UTC 2026-09-01 18:00 == 北京 2026-09-02 02:00
// —— 此刻 UTC 日期是 09-01，业务时区日期是 09-02，恰好差一天
const FIXED_NOW = new RealDate('2026-09-01T18:00:00Z').getTime();

jest.mock('../../services/securityAlert', () => ({
  shouldSendAlert: jest.fn(() => true),
  sendNotification: jest.fn(async () => ({ delivered: false })),
}));

jest.mock('../../models/AuditLog', () => ({
  detectAnomalies: jest.fn(async () => ({
    failedOperations: [{ _id: 'user_a', count: 6 }],
    unusualTimeOperations: [{ _id: 'user_b', count: 3 }],
  })),
}));

const securityAlert = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');
const monitor = require('../../services/auditMonitor');

/** 把全局 Date 固定到分叉敏感时刻（返回 spy 供恢复；静态方法一并桥接） */
/**
 * 把全局 Date 固定到分叉敏感时刻，返回恢复函数。
 * 注意：不能用 jest.spyOn(global,'Date')——spy 替换后的函数不会继承
 * 原构造器的静态方法（Date.now 变 undefined），winston 的
 * FileStreamRotator 写日志时即崩溃；直接整体替换并在 finally 恢复。
 */
function freezeAtFixedInstant() {
  const originalDate = global.Date;
  const MockDate = function Date(...args) {
    if (args.length === 0) return new RealDate(FIXED_NOW);
    return new RealDate(...args);
  };
  // 桥接原型与静态方法：instanceof Date 成立、Date.now/parse/UTC 可用
  MockDate.prototype = RealDate.prototype;
  Object.setPrototypeOf(MockDate, RealDate);
  MockDate.now = () => FIXED_NOW;
  MockDate.parse = RealDate.parse;
  MockDate.UTC = RealDate.UTC;
  global.Date = MockDate;
  return () => {
    global.Date = originalDate;
  };
}

beforeEach(() => {
  securityAlert.shouldSendAlert.mockClear().mockReturnValue(true);
  securityAlert.sendNotification.mockClear();
  AuditLog.detectAnomalies.mockClear();
});

describe('auditMonitor 告警频控时区口径（时区分叉修复回归）', () => {
  test('UTC 与业务时区分叉时刻：频控 key 锚定业务时区日期（09-02），而非 UTC 日期（09-01）', async () => {
    const restore = freezeAtFixedInstant();
    try {
      await monitor.runDetection();

      // 旧实现（toISOString）在此刻会拼出 ..._2026-09-01：08:00 换天后
      // 同一自然日可再推一次。精确断言 key 锚定业务时区的「今天」。
      expect(securityAlert.shouldSendAlert).toHaveBeenCalledWith(
        'audit_anomaly_high_frequency_failure_2026-09-02'
      );
      expect(securityAlert.shouldSendAlert).toHaveBeenCalledWith(
        'audit_anomaly_unusual_time_operation_2026-09-02'
      );

      // 两个维度都通过频控 → 合并为一次推送，维度清单完整
      expect(securityAlert.sendNotification).toHaveBeenCalledTimes(1);
      const [, , , meta] = securityAlert.sendNotification.mock.calls[0];
      expect(meta.dimensions).toEqual(['高频失败', '非常规时间操作']);
    } finally {
      restore();
    }
  });

  test('全部维度被频控拦截时不推送（每日一次闸门生效）', async () => {
    securityAlert.shouldSendAlert.mockReturnValue(false);
    await monitor.runDetection();
    expect(securityAlert.sendNotification).not.toHaveBeenCalled();
  });

  test('单维度被频控、另一维度放行时仅推送放行维度', async () => {
    securityAlert.shouldSendAlert.mockImplementation((key) =>
      key.startsWith('audit_anomaly_unusual_time_operation_')
    );
    await monitor.runDetection();
    expect(securityAlert.sendNotification).toHaveBeenCalledTimes(1);
    const [, , , meta] = securityAlert.sendNotification.mock.calls[0];
    expect(meta.dimensions).toEqual(['非常规时间操作']);
  });

  test('detectAnomalies 抛错不向上传播（定时任务不被单轮失败打断）', async () => {
    AuditLog.detectAnomalies.mockRejectedValueOnce(new Error('db down'));
    await expect(monitor.runDetection()).resolves.toBeUndefined();
  });
});
