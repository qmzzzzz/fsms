'use strict';

/**
 * 脱敏的"同址同形"契约（IPv6 内嵌 IPv4 的八位组边界）
 *
 * 被测判据：`DataMasking._expandIPv6` 里
 *   if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
 * 解析失败时 `maskIP` 退化成整体打码 `****`（方向是更保守，不是泄露），
 * 所以这条判据错了**不会泄密**，但会**破坏脱敏一致性**：同一个地址换一种写法就得到不同宽度，
 * 审计导出里的 IP 列会出现"有的能看出 /48、有的整列全黑"，跨行统计与去重都会失真。
 *
 * 变异实测来源（v2 全量跑尺，src/utils/encryption.js）：把 `o > 255` 挪成 `o >= 255`
 * （即合法的 255 被当成非法）⇒ 既有全套用例仍绿。本文件补上这一格：
 * 用**等价写法必须同结果**做断言，而不是钉一个具体字符串——这样既不锁死实现细节，
 * 又能在边界值被误判时立刻红（255 会被降级成 `****`，与纯十六进制写法不再相等）。
 */

const { DataMasking } = require('../../utils/encryption');

describe('maskIP：同一地址的不同合法写法必须脱敏成同一结果', () => {
  test('IPv6 尾段内嵌 IPv4：八位组取到边界值 255 时仍按 /48 脱敏（与纯十六进制写法等价）', () => {
    expect(DataMasking.maskIP('2001:db8::192.168.0.255')).toBe(
      DataMasking.maskIP('2001:db8::c0a8:ff')
    );
    expect(DataMasking.maskIP('2001:db8::192.168.0.255')).toBe('2001:db8:0:****');
  });

  test('负对照：真非法的八位组（256）必须落到整体打码，不许与合法值同结果', () => {
    expect(DataMasking.maskIP('2001:db8::192.168.0.256')).toBe('****');
  });

  test('IPv4 映射形态与其纯 IPv4 写法同结果（既有契约，防止上面两条靠巧合绿）', () => {
    expect(DataMasking.maskIP('::ffff:1.2.3.4')).toBe(DataMasking.maskIP('1.2.3.4'));
    expect(DataMasking.maskIP('::ffff:1.2.3.4')).toBe('1.2.*.*');
  });

  test('八位组下边界 0 合法（与上边界对称，只钉一侧等于没钉边界）', () => {
    expect(DataMasking.maskIP('2001:db8::0.0.0.0')).toBe(DataMasking.maskIP('2001:db8::0:0'));
  });
});
