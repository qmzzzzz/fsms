/**
 * 安全告警 webhook 的出站地址判定：必须是"只放行全局单播"的白名单
 *
 * 审计对象：src/services/securityAlertDelivery.js 的 isWebhookTargetAllowed
 * 原实现是一份**禁止网段黑名单**（loopback/private/linkLocal/uniqueLocal/
 * reserved/unspecified/carrierGradeNat）。黑名单的失败方向是错的：
 * ipaddr.js 的 range() 返回的是一个**开放命名空间**，没列到的名字一律当公网。
 *
 * 实测漏掉的（ipaddr.js 2.5.0）：
 *   rfc6052  64:ff9b::/96  NAT64 Well-Known Prefix —— 目的 IPv4 直接嵌在地址里，
 *                          [64:ff9b::a9fe:a9fe] 就是 169.254.169.254（云元数据）
 *   teredo   2001::/32     同样嵌 IPv4
 *   broadcast 255.255.255.255、multicast 224/4、as112、TEST-NET/基准段（reserved）
 *
 * 修法是把判定翻成白名单（只允许 range()==='unicast'），本用例钉住翻修后的契约，
 * 并同时钉住**不得过度拦截**：公网 IPv4 / 公网 IPv6 / 域名 /
 * 以及 ::ffff:8.8.8.8（IPv4 映射的公网地址——它的 range() 是 'ipv4Mapped'，
 * 不做 toIPv4Address() 展开就会被白名单误杀，这条正是那个展开的设防用例）。
 *
 * 另有反向对照：同一目标的不同写法（裸 IPv4 vs 嵌在特殊前缀里）结论必须一致。
 */

const { isWebhookTargetAllowed } = require('../services/securityAlertDelivery');

const BLOCKED = [
  // 黑名单原本覆盖的：作为锚点（回归时先在这里变红）
  ['loopback IPv4', 'http://127.0.0.1/hook'],
  ['私网 10/8', 'http://10.1.2.3/hook'],
  ['云元数据 linkLocal', 'http://169.254.169.254/hook'],
  ['ULA', 'http://[fd00::1234]/hook'],
  ['CGNAT 100.64/10', 'http://100.100.100.100/hook'],
  // 黑名单漏掉、白名单收口的（本次缺陷本体）
  ['NAT64 rfc6052 → 环回', 'http://[64:ff9b::7f00:1]/hook'],
  ['NAT64 rfc6052 → 元数据', 'http://[64:ff9b::a9fe:a9fe]/hook'],
  ['NAT64 rfc6052 → 私网', 'http://[64:ff9b::0a00:0001]/hook'],
  ['Teredo 嵌 IPv4 → 元数据', 'http://[2001:0::a9fe:a9fe]/hook'],
  ['limited broadcast', 'http://255.255.255.255/hook'],
  ['multicast 224/4', 'http://224.0.0.1/hook'],
  ['TEST-NET-1（reserved）', 'http://192.0.2.1/hook'],
  ['基准测试段（reserved）', 'http://198.18.0.1/hook'],
  ['AS112', 'http://192.31.196.5/hook'],
  ['240/4 保留', 'http://240.0.0.1/hook'],
  ['未指定 0.0.0.0', 'http://0.0.0.0/hook'],
  ['IPv6 环回带方括号', 'http://[::1]/hook'],
  ['IPv4 映射 → 环回', 'http://[::ffff:127.0.0.1]/hook'],
  // ::/96 IPv4 兼容前缀：ipaddr 的 range() 给 'unicast'，白名单单独看不够（实测）
  ['::/96 嵌私网 10.0.0.1', 'http://[::a00:1]/hook'],
  ['::/96 嵌云元数据 169.254.169.254', 'http://[::a9fe:a9fe]/hook'],
  ['::/96 点分写法（URL 归一成十六进制后同上）', 'http://[::169.254.169.254]/hook'],
  ['全零 :: （unspecified，也落在 ::/96）', 'http://[::]/hook'],
];

const ALLOWED = [
  ['公网 IPv4 字面量', 'http://8.8.8.8/hook'],
  ['公网 IPv6 字面量', 'http://[2606:4700:4700::1111]/hook'],
  ['高 96 位非零的公网 IPv6（::/96 判据不得误杀）', 'http://[2001:4860:4860::8888]/hook'],
  ['IPv4 映射的公网地址（须先展开）', 'http://[::ffff:8.8.8.8]/hook'],
  ['域名（内网指向由 ALLOWLIST/网络层约束）', 'https://hooks.slack.com/services/T/B/X'],
];

describe('webhook 出站地址判定：白名单只放行全局单播', () => {
  const prevAllowlist = process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
  beforeEach(() => {
    delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
  });
  afterAll(() => {
    if (prevAllowlist === undefined) delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
    else process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = prevAllowlist;
  });

  test('取数有效：矩阵里 true 与 false 都出现过（防"恒 false"式全绿）', () => {
    expect(BLOCKED.length).toBeGreaterThanOrEqual(15);
    expect(ALLOWED.length).toBeGreaterThanOrEqual(4);
    const gotBlocked = BLOCKED.filter(([, u]) => isWebhookTargetAllowed(u) === false).length;
    const gotAllowed = ALLOWED.filter(([, u]) => isWebhookTargetAllowed(u) === true).length;
    expect(gotBlocked).toBe(BLOCKED.length);
    expect(gotAllowed).toBe(ALLOWED.length);
  });

  test.each(BLOCKED)('拒绝 %s（%s）', (_label, url) => {
    expect(isWebhookTargetAllowed(url)).toBe(false);
  });

  test.each(ALLOWED)('放行 %s（%s）', (_label, url) => {
    expect(isWebhookTargetAllowed(url)).toBe(true);
  });

  test('同一目标的不同写法结论必须一致（特殊前缀不是新出口）', () => {
    // 嵌在 NAT64/Teredo 里的地址 ≡ 裸写的内嵌 IPv4
    expect(isWebhookTargetAllowed('http://[64:ff9b::a9fe:a9fe]/hook')).toBe(
      isWebhookTargetAllowed('http://169.254.169.254/hook')
    );
    expect(isWebhookTargetAllowed('http://[2001:0::a9fe:a9fe]/hook')).toBe(
      isWebhookTargetAllowed('http://169.254.169.254/hook')
    );
    expect(isWebhookTargetAllowed('http://[::ffff:127.0.0.1]/hook')).toBe(
      isWebhookTargetAllowed('http://127.0.0.1/hook')
    );
    // 公网侧同样一致
    expect(isWebhookTargetAllowed('http://[::ffff:8.8.8.8]/hook')).toBe(
      isWebhookTargetAllowed('http://8.8.8.8/hook')
    );
  });

  test('WHATWG URL 已归一化各种 IPv4 写法（核对源码注释里的断言，非猜测）', () => {
    // 这些写法若未被归一化，网域判定就会看到"不是 IP 字面量"而放行
    const forms = [
      'http://2130706433/',
      'http://0x7f000001/',
      'http://017700000001/',
      'http://127.1/',
    ];
    for (const url of forms) {
      expect(new URL(url).hostname).toBe('127.0.0.1');
      expect(isWebhookTargetAllowed(`${url}hook`)).toBe(false);
    }
  });

  test('非 http/https 协议与坏 URL 一律拒（白名单翻转不得削弱既有前置闸）', () => {
    expect(isWebhookTargetAllowed('file:///etc/passwd')).toBe(false);
    expect(isWebhookTargetAllowed('gopher://127.0.0.1:11211/')).toBe(false);
    expect(isWebhookTargetAllowed('not a url')).toBe(false);
  });

  test('::/96 判据的两个前提（实测，别再按名字猜 API）', () => {
    // ① URL 解析器总把点分 IPv6 改写成十六进制 ⇒ 判据看到的永远是 ::a00:1 这种形态
    expect(new URL('http://[::10.0.0.1]/').hostname).toBe('[::a00:1]');
    expect(new URL('http://[::169.254.169.254]/').hostname).toBe('[::a9fe:a9fe]');
    // ② ipaddr.js 2.5.0 **没有** isIPv4CompatibleAddress()：按那个名字写会 TypeError，
    //    并被外层 catch 吞成"解析失败 ⇒ 放行"。所以判据只能走 toByteArray() 高 96 位。
    const ipaddr = require('ipaddr.js');
    expect(typeof ipaddr.parse('::1').isIPv4CompatibleAddress).toBe('undefined');
    expect(ipaddr.parse('::a00:1').range()).toBe('unicast');
  });

  test('ALLOWLIST 仍然只做收紧，不做放行（白名单不得改变它的语义）', () => {
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'hooks.slack.com';
    expect(isWebhookTargetAllowed('https://hooks.slack.com/services/T/B/X')).toBe(true);
    expect(isWebhookTargetAllowed('https://evil.example/services')).toBe(false);
    // 在白名单里但不是全局单播 → 依旧拒（收紧只能更小，不能更大）
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = '8.8.8.8,127.0.0.1';
    expect(isWebhookTargetAllowed('http://8.8.8.8/hook')).toBe(true);
    expect(isWebhookTargetAllowed('http://127.0.0.1/hook')).toBe(false);
  });
});
