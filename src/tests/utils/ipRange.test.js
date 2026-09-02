/**
 * ipRange 工具测试：用户 IP 访问范围规则的解析、校验与匹配
 */

const { splitRules, parseRules, validateRules, isIPAllowed } = require('../../utils/ipRange');

describe('ipRange（用户 IP 访问范围规则）', () => {
  describe('splitRules 分隔符', () => {
    test('支持逗号、分号、空格、回车混合分隔', () => {
      const text = '192.168.1.1,192.168.1.2;192.168.1.3 192.168.1.4\n192.168.1.5';
      expect(splitRules(text)).toEqual([
        '192.168.1.1',
        '192.168.1.2',
        '192.168.1.3',
        '192.168.1.4',
        '192.168.1.5',
      ]);
    });

    test('去除重复与空白片段', () => {
      expect(splitRules(' 1.1.1.1 ,, 1.1.1.1 ; ')).toEqual(['1.1.1.1']);
    });

    test('空值返回空数组', () => {
      expect(splitRules('')).toEqual([]);
      expect(splitRules('   ')).toEqual([]);
      expect(splitRules(null)).toEqual([]);
    });
  });

  describe('规则格式校验', () => {
    test('文档中列出的 9 种格式全部合法', () => {
      const text = [
        '192.168.1.1',
        '192.168.1.1-254',
        '192.168.1.1/24',
        '192.168.1.*',
        '192.168.1-10.*',
        '!192.168.1.1',
        '2001::db8:2003',
        '2001::db8:2003/96',
        '!2001::db8:2003',
      ].join('\n');
      const result = validateRules(text);
      expect(result.valid).toBe(true);
      expect(result.invalid).toEqual([]);
      expect(result.denyCount).toBe(2);
    });

    test('空规则视为合法（不限制）', () => {
      expect(validateRules('').valid).toBe(true);
      expect(validateRules('   ').valid).toBe(true);
      expect(validateRules(undefined).valid).toBe(true);
    });

    test('非法片段被识别并回报', () => {
      const result = validateRules('192.168.1.1, not-an-ip, 999.1.1.1, 10.0.0.0/33');
      expect(result.valid).toBe(false);
      expect(result.invalid).toContain('not-an-ip');
      expect(result.invalid).toContain('999.1.1.1');
      expect(result.invalid).toContain('10.0.0.0/33');
    });

    test('段区间上下限颠倒或越界为非法', () => {
      expect(validateRules('192.168.1.254-1').valid).toBe(false);
      expect(validateRules('192.168.1.1-300').valid).toBe(false);
      expect(validateRules('192.168.300.1').valid).toBe(false);
    });

    test('仅有 ! 前缀而无内容为非法', () => {
      expect(validateRules('!').valid).toBe(false);
    });

    test('IPv6 不支持段区间/通配语法（应使用 CIDR）', () => {
      expect(validateRules('2001:db8::*').valid).toBe(false);
      expect(validateRules('2001:db8::1-10').valid).toBe(false);
    });

    test('规则条数超过上限为非法', () => {
      const many = Array.from({ length: 201 }, (_, i) => `10.0.0.${i % 256}`).join(',');
      expect(validateRules(many).valid).toBe(false);
    });
  });

  describe('parseRules 分类', () => {
    test('允许项与排除项分别归类', () => {
      const { allows, denies, invalid } = parseRules('192.168.1.0/24, !192.168.1.100');
      expect(allows).toHaveLength(1);
      expect(denies).toHaveLength(1);
      expect(denies[0].raw).toBe('!192.168.1.100');
      expect(invalid).toEqual([]);
    });
  });

  describe('匹配：单地址', () => {
    test('精确命中与不命中', () => {
      expect(isIPAllowed('192.168.1.1', '192.168.1.1').allowed).toBe(true);
      expect(isIPAllowed('192.168.1.2', '192.168.1.1').allowed).toBe(false);
    });

    test('IPv4 映射 IPv6 客户端等价于纯 IPv4', () => {
      expect(isIPAllowed('::ffff:192.168.1.1', '192.168.1.1').allowed).toBe(true);
    });

    test('IPv6 等价写法命中', () => {
      expect(isIPAllowed('2001:db8:0:0:0:0:0:1', '2001:db8::1').allowed).toBe(true);
    });
  });

  describe('匹配：末段区间 192.168.1.1-254', () => {
    test('区间内放行、区间外拒绝', () => {
      const rule = '192.168.1.1-254';
      expect(isIPAllowed('192.168.1.1', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.1.128', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.1.254', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.1.0', rule).allowed).toBe(false);
      expect(isIPAllowed('192.168.1.255', rule).allowed).toBe(false);
      expect(isIPAllowed('192.168.2.100', rule).allowed).toBe(false);
    });
  });

  describe('匹配：CIDR 网段', () => {
    test('IPv4 /24 含主机位写法（192.168.1.1/24）按网段解释', () => {
      const rule = '192.168.1.1/24';
      expect(isIPAllowed('192.168.1.77', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.2.77', rule).allowed).toBe(false);
    });

    test('IPv6 /96 网段匹配', () => {
      const rule = '2001::db8:2003/96';
      expect(isIPAllowed('2001::db8:2003', rule).allowed).toBe(true);
      expect(isIPAllowed('2001::db8:9999', rule).allowed).toBe(true);
      expect(isIPAllowed('2002::db8:2003', rule).allowed).toBe(false);
    });

    test('IPv4 客户端不会命中 IPv6 网段，反之亦然', () => {
      expect(isIPAllowed('192.168.1.1', '2001:db8::/32').allowed).toBe(false);
      expect(isIPAllowed('2001:db8::1', '192.168.0.0/16').allowed).toBe(false);
    });
  });

  describe('匹配：通配符与段区间', () => {
    test('192.168.1.* 匹配整个 C 段', () => {
      const rule = '192.168.1.*';
      expect(isIPAllowed('192.168.1.0', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.1.255', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.2.1', rule).allowed).toBe(false);
    });

    test('192.168.1-10.* 匹配第三段 1~10 的全部地址', () => {
      const rule = '192.168.1-10.*';
      expect(isIPAllowed('192.168.1.5', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.10.200', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.11.1', rule).allowed).toBe(false);
      expect(isIPAllowed('192.169.5.1', rule).allowed).toBe(false);
    });

    test('通配模式不匹配 IPv6 客户端', () => {
      expect(isIPAllowed('2001:db8::1', '192.168.1.*').allowed).toBe(false);
    });

    test('单独 * 等价于放行全部', () => {
      expect(isIPAllowed('8.8.8.8', '*').allowed).toBe(true);
      expect(isIPAllowed('2001:db8::1', '*').allowed).toBe(true);
    });
  });

  describe('匹配：排除项优先级', () => {
    test('排除项覆盖允许项', () => {
      const rule = '192.168.1.*, !192.168.1.100';
      expect(isIPAllowed('192.168.1.99', rule).allowed).toBe(true);
      const denied = isIPAllowed('192.168.1.100', rule);
      expect(denied.allowed).toBe(false);
      expect(denied.reason).toBe('denied');
      expect(denied.matchedRule).toBe('!192.168.1.100');
    });

    test('排除网段同样生效', () => {
      const rule = '10.0.0.0/8, !10.1.0.0/16';
      expect(isIPAllowed('10.2.3.4', rule).allowed).toBe(true);
      expect(isIPAllowed('10.1.3.4', rule).allowed).toBe(false);
    });

    test('仅配置排除项时，未被排除的 IP 放行', () => {
      const rule = '!192.168.1.100';
      expect(isIPAllowed('8.8.8.8', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.1.100', rule).allowed).toBe(false);
    });

    test('IPv6 排除项生效', () => {
      const rule = '2001::db8:2003/96, !2001::db8:2003';
      expect(isIPAllowed('2001::db8:2004', rule).allowed).toBe(true);
      expect(isIPAllowed('2001::db8:2003', rule).allowed).toBe(false);
    });
  });

  describe('边界与容错', () => {
    test('规则为空时不限制', () => {
      expect(isIPAllowed('8.8.8.8', '').allowed).toBe(true);
      expect(isIPAllowed('8.8.8.8', '   ').allowed).toBe(true);
      expect(isIPAllowed('8.8.8.8', null).allowed).toBe(true);
      expect(isIPAllowed('8.8.8.8', undefined).reason).toBe('no_rules');
    });

    test('已配置规则但客户端 IP 无法解析时拒绝（fail-closed）', () => {
      const r = isIPAllowed('not-an-ip', '192.168.1.1');
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe('invalid_client_ip');
    });

    test('非法规则片段被忽略，不影响其余规则判定', () => {
      const rule = 'bad-rule, 192.168.1.1';
      expect(isIPAllowed('192.168.1.1', rule).allowed).toBe(true);
      expect(isIPAllowed('192.168.1.2', rule).allowed).toBe(false);
    });

    test('全部规则非法时等价于无允许项，按放行处理', () => {
      // 允许项解析后为空且无排除项 → 不构成限制，避免因误填导致账户完全无法登录
      expect(isIPAllowed('8.8.8.8', 'bad, worse').allowed).toBe(true);
    });

    test('多条规则命中时返回首个命中的规则文本', () => {
      const r = isIPAllowed('192.168.1.5', '10.0.0.0/8, 192.168.1.*');
      expect(r.allowed).toBe(true);
      expect(r.matchedRule).toBe('192.168.1.*');
    });
  });
});
