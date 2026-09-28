/**
 * 「同一维度当天只推送一条高危告警」这条不变量的**真实**判定路径。
 *
 * 为什么另开一个文件：本模块原有的两套用例（auditMonitorTimezone /
 * zzqA_auditMonitorAlertLoop）把 `shouldSendAlert` 整个 mock 成 `() => true`，
 * 于是"每日一次"这条被写进注释、写进用例名（auditMonitorTimezone:94「每日一次闸门生效」）
 * 的不变量，**从来没有被任何断言触碰过**——被 mock 掉的那一步恰恰是唯一的抑制来源。
 * 本文件不 mock 它：用 jest.spyOn 透传真实现，再从 mock.results 读出返回值，
 * 这样才能把"这一轮到底是谁拦下来的"归因清楚。
 *
 * 修复前的真实缺陷（本文件主证用例在修复前必红）：
 * 频控键里带了日期（`..._failure_2026-09-24`），但 shouldSendAlert 的窗口只有
 * THRESHOLDS.alertRateLimitMs = 5 分钟（securityAlert.js:27，无 env 可调），
 * 而检测间隔默认同为 5 分钟、且可配到任意大 ⇒ 键名里的日期从不参与抑制判定。
 * 只要 interval ≥ TTL，每轮都会放行 ⇒ 一个维度一天最多 ~144 条高危告警。
 * 现在由 auditMonitor 自己的 notifiedDayByDimension 兜住，与两个常量的大小关系解耦。
 */

jest.mock('../../models/AuditLog', () => ({ detectAnomalies: jest.fn() }));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const mockClock = { day: '2026-09-24', now: 0 };

jest.mock('../../constants/timezone', () => ({
  businessDateParts: () => ({ dateStr: mockClock.day }),
  BUSINESS_TIMEZONE: 'Asia/Shanghai',
  OFF_HOURS_START: 22,
  OFF_HOURS_END: 6,
}));

const AuditLog = require('../../models/AuditLog');
const securityAlert = require('../../services/securityAlert');
const auditMonitor = require('../../services/auditMonitor');

const MINUTE = 60 * 1000;
// 跨过 TTL 用的步进：必须严格大于 alertRateLimitMs，否则本文件测的是"5 分钟窗口还在"，
// 与修复前无异 ⇒ 用真实常量把这个前提钉住（见下条用例），不让它随常量改动悄悄失效。
const JUMP_MS = securityAlert.THRESHOLDS.alertRateLimitMs + MINUTE;

const ANOMALY = {
  failedOperations: [{ _id: 'u1', count: 12 }],
  failedOperationsByIp: [],
  unusualTimeOperations: [],
};

describe('auditMonitor 每日一条告警上限（真频控，不 mock shouldSendAlert）', () => {
  let throttleSpy;
  let sendSpy;
  let realNow;
  // 真频控表是 securityAlert 的模块级状态，本文件多条用例共用同一个业务日 ⇒
  // 若时间不推进，上一条用例消费的表项会把下一条的第一轮直接拦掉（假红）。
  // 业务日来自被 mock 的 businessDateParts、与 now 无关，所以可以只推进 now：
  // 每条用例起点各差一天，旧表项（TTL 5 分钟）必然已过期。
  let caseSeq = 0;

  beforeAll(() => {
    realNow = Date.now();
    jest.spyOn(Date, 'now').mockImplementation(() => mockClock.now);
  });
  afterAll(() => {
    Date.now.mockRestore();
  });

  beforeEach(() => {
    auditMonitor.stop();
    auditMonitor.__resetForTest();
    caseSeq += 1;
    mockClock.now = realNow + caseSeq * 24 * 60 * MINUTE;
    mockClock.day = '2026-09-24';
    AuditLog.detectAnomalies.mockResolvedValue(ANOMALY);
    // 透传真实现：既能观察每轮的返回值，也让 5 分钟窗口按真实代码走
    throttleSpy = jest.spyOn(securityAlert, 'shouldSendAlert');
    sendSpy = jest.spyOn(securityAlert, 'sendNotification').mockImplementation(async () => {});
  });

  afterEach(() => {
    throttleSpy.mockRestore();
    sendSpy.mockRestore();
  });

  test('前提钉住：JUMP_MS 确实跨过了频控窗口（否则下面的主证用例是假绿）', () => {
    expect(JUMP_MS).toBeGreaterThan(securityAlert.THRESHOLDS.alertRateLimitMs);
  });

  test('主证：同一自然日内跨 TTL 的两轮检测，只推一条', async () => {
    await auditMonitor.runDetection();
    expect(sendSpy).toHaveBeenCalledTimes(1);

    mockClock.now += JUMP_MS;
    await auditMonitor.runDetection();

    expect(sendSpy).toHaveBeenCalledTimes(1);
  });

  test('归因：第二轮是被"当日闸"拦下的，不是被 5 分钟频控拦下的', async () => {
    await auditMonitor.runDetection();
    mockClock.now += JUMP_MS;
    await auditMonitor.runDetection();

    // 单维度命中 ⇒ 每轮各调用一次真频控
    expect(throttleSpy).toHaveBeenCalledTimes(2);
    // 第二轮频控**放行**了（跨过了 TTL），却没有推送 ⇒ 唯一的抑制来源是当日闸。
    // 这一条就是修复前的真实形态：value 为 true 且当时会推送。
    expect(throttleSpy.mock.results[1].value).toBe(true);
    expect(sendSpy).toHaveBeenCalledTimes(1);
  });

  test('反向：换到下一个业务日必须重新推送（防止把上限写成"永远只推一次"）', async () => {
    await auditMonitor.runDetection();
    expect(sendSpy).toHaveBeenCalledTimes(1);

    mockClock.now += JUMP_MS;
    mockClock.day = '2026-09-25';
    await auditMonitor.runDetection();

    expect(sendSpy).toHaveBeenCalledTimes(2);
    const [, , secondMessage] = sendSpy.mock.calls[1];
    expect(secondMessage).toContain('1 个高频失败用户');
  });

  test('上限是按维度的：同一天新出现的维度不受其他维度的当日记录影响', async () => {
    await auditMonitor.runDetection(); // 只有"高频失败"命中
    expect(sendSpy.mock.calls[0][3].dimensions).toEqual(['高频失败']);

    mockClock.now += JUMP_MS;
    AuditLog.detectAnomalies.mockResolvedValue({
      failedOperations: [{ _id: 'u1', count: 12 }],
      failedOperationsByIp: [{ _id: '1.2.3.4', count: 42 }],
      unusualTimeOperations: [],
    });
    await auditMonitor.runDetection();

    expect(sendSpy).toHaveBeenCalledTimes(2);
    expect(sendSpy.mock.calls[1][3].dimensions).toEqual(['高频失败来源 IP']);
  });
});
