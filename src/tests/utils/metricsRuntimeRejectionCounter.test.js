/**
 * P3：unhandledRejection 的 Prometheus 计数器（metricsRuntime 家族）。
 *
 * 守的是什么：进程因未处理拒绝退出前，/metrics 侧要有一个可聚合的信号——
 * target down 只知道实例没了，不知道是怎么没的。计数按 reason_kind 闭集分类
 * （Error 实例 / 非 Error），err.name 是开放集、绝不进标签（闭集标签纪律）。
 */
const rt = require('../../utils/metricsRuntime');

const rejectionLines = () =>
  rt.formatRuntime().filter((l) => l.startsWith('unhandled_rejections_total'));

describe('P3 unhandledRejection 计数器', () => {
  beforeEach(() => rt.__resetForTest());

  test('Error 实例归 error，其余归 non_error（闭集两值，不按 err.name 开集建 series）', () => {
    rt.incUnhandledRejection(new TypeError('x'));
    rt.incUnhandledRejection('boom');
    rt.incUnhandledRejection(undefined);
    const text = rejectionLines().join('\n');
    expect(text).toContain('unhandled_rejections_total{reason_kind="error"} 1');
    expect(text).toContain('unhandled_rejections_total{reason_kind="non_error"} 2');
  });

  test('未发生时恒定输出 0（「从没发生过」与「这一版没上报」可区分）', () => {
    const text = rejectionLines().join('\n');
    expect(text).toContain('unhandled_rejections_total{reason_kind="error"} 0');
    expect(text).toContain('unhandled_rejections_total{reason_kind="non_error"} 0');
  });

  test('累计语义：同类多次计数累加', () => {
    rt.incUnhandledRejection(new Error('a'));
    rt.incUnhandledRejection(new Error('b'));
    const text = rejectionLines().join('\n');
    expect(text).toContain('unhandled_rejections_total{reason_kind="error"} 2');
  });
});
