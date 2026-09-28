'use strict';

/**
 * （2026-09-20）：webhook SSRF 白名单漏了 IPv4 兼容形态 `::a.b.c.d`（`::/96`）
 *
 * `securityAlertDelivery.isForbiddenIpLiteral` 只对 `isIPv4MappedAddress()`
 * （`::ffff:x`）做 `toIPv4Address()` 展开，展开后按 `range()` 判定。问题是
 * **`::/96` 这一类 ipaddr 给的是 `range() === 'unicast'`**，于是判据放行。
 *
 * 更关键的一点：带点分的写法根本走不到判据——WHATWG URL 会把它改写成十六进制：
 *   new URL('http://[::10.0.0.1]/').hostname === '[::a00:1]'
 * 而 ipaddr 对两种文本的答案不同（实测）：
 *   parse('::10.0.0.1') → ::ffff:a00:1 / range=ipv4Mapped  ⇒ 会被 DENY
 *   parse('::a00:1')    → ::a00:1      / range=unicast     ⇒ 放行
 * ⇒ "点分写法被拒"只是纸面效果，判据实际看到的永远是十六进制那条。
 *
 * 定级为**加固**而非漏洞：现代 Linux/Node 协议栈不做 `::/96`→IPv4 转换（该语义早已废弃），
 * 真要把低 32 位打到内网得依赖 NAT64，而 `64:ff9b::/96`（rfc6052）已被现有判据拒绝。
 * 之所以仍要记账：这条判据的注释读起来像"嵌入 IPv4 的两类形态都处理了"，
 * 而它只处理了一类——这种错觉会让后来人以为可以在此基础上放宽别的分支。
 * 另注：ipaddr.js 2.5.0 **没有** `isIPv4CompatibleAddress()`（实测 undefined），
 * 修法别用那个名字；外层 `catch` 会把 TypeError 吞成"解析失败→放行"。
 *
 * 下面两条原先按 `test.failing` 登记（当时的 CI 因此为绿）。2026-09-20 由
 * `securityAlertDelivery` 补上"IPv6 高 96 位全零即拒"的判据后修好，标记已摘除；
 * **断言原文一字未动**（勿"顺手放宽"）。非 failing 的对照组保证用例不是靠"输入不像 IP"蒙绿。
 */

const { isWebhookTargetAllowed } = require('../../services/securityAlertDelivery');

describe('zzqA webhook 判据对嵌入 IPv4 的 IPv6 形态', () => {
  describe('对照组（当前已成立，用于保证探针本身有效）', () => {
    test('公网目标照常放行（判据不许靠"什么都不放"通过）', () => {
      expect(isWebhookTargetAllowed('http://8.8.8.8/hook')).toBe(true);
      expect(isWebhookTargetAllowed('https://oapi.dingtalk.com/robot')).toBe(true);
      // ::ffff: 映射形态：展开后是 unicast ⇒ 放行（这条就是源码注释里说的"承重"行为）
      expect(isWebhookTargetAllowed('http://[::ffff:8.8.8.8]/hook')).toBe(true);
    });

    test('映射形态的内网/元数据地址被拒（展开→判 range 的链路是通的）', () => {
      expect(isWebhookTargetAllowed('http://[::ffff:127.0.0.1]/hook')).toBe(false);
      expect(isWebhookTargetAllowed('http://[::ffff:169.254.169.254]/hook')).toBe(false);
      expect(isWebhookTargetAllowed('http://[64:ff9b::a9fe:a9fe]/hook')).toBe(false);
    });

    test('URL 解析器把点分 IPv6 改写成十六进制（本缺陷成立的前提）', () => {
      expect(new URL('http://[::10.0.0.1]/').hostname).toBe('[::a00:1]');
      // 两种文本在 ipaddr 眼里不是同一个东西：一个 ipv4Mapped、一个 unicast
      const ipaddr = require('ipaddr.js');
      expect(ipaddr.parse('::10.0.0.1').range()).toBe('ipv4Mapped');
      expect(ipaddr.parse('::a00:1').range()).toBe('unicast');
      expect(ipaddr.parse('::a00:1').isIPv4MappedAddress()).toBe(false);
    });
  });

  describe('嵌入 IPv4 的 ::/96 形态（曾登记为缺陷，2026-09-20 已修）', () => {
    test('::/96 里的私有地址必须被拒（等价 10.0.0.1）', () => {
      expect(isWebhookTargetAllowed('http://[::a00:1]/hook')).toBe(false);
    });

    test('::/96 整段不可能是合法 webhook 目标，公网嵌入形态也一并拒绝', () => {
      // 1.1.1.1 嵌在 ::/96 里：拒它的理由不是"内网"，而是"这个前缀本身不该被投递"
      expect(isWebhookTargetAllowed('http://[::0101:0101]/hook')).toBe(false);
    });
  });
});
