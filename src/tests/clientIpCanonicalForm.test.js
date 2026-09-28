'use strict';

/**
 * （2026-09-19）：客户端 IP 必须是规范形态，否则"把自己写成受信任地址"可行
 *
 * 实测（本仓 normalizeIP 走 ipaddr.js）：
 *   0177.0.0.1 → 127.0.0.1（八进制）   0x7f.0.0.1 → 127.0.0.1（十六进制）
 *   017700000001 → 127.0.0.1（单数字）  ::ffff:0177.0.0.1 → 177.0.0.1（映射前缀被吞）
 * 客户端 IP 文本一旦可被外部影响（开 trust proxy 后的 XFF、WS 握手头），
 * 命中白名单 = 同时豁免黑名单与限流；账户级 allowedIPs 同理是访问控制。
 * 故在两个"这个客户端是谁"的判定点（utils/ipRange、models/IPBlacklist）上严格化。
 */

const mongoose = require('mongoose');
// 此后判据住在 utils/ipUtils（四个解析漏斗共用同一把尺子），
// 过渡模块 utils/ipCanonical 已并入并删除；strictNormalizeClientIp ≡ 现在的 normalizeIP。
const {
  isAmbiguousIpText,
  normalizeIP: strictNormalizeClientIp,
  lenientAddressHint,
} = require('../utils/ipUtils');
const { isIPAllowed } = require('../utils/ipRange');

describe('客户端 IP 严格形态', () => {
  describe('判据本身', () => {
    test.each([
      ['127.0.0.1', false],
      ['10.0.0.1', false],
      ['255.255.255.255', false],
      ['::1', false],
      ['2001:db8::1', false],
      ['::ffff:127.0.0.1', false],
      ['64:ff9b::192.0.2.1', false],
      ['::::', false], // 完全解析不出的一律不算歧义：仍走原有 null→拒绝 路径
      ['not-an-ip', false], // 无点、非纯数字 ⇒ 不存在"被解释成另一个地址"的问题
      ['017700000001', true], // 纯数字形态：ipaddr 按 32 位整数解析成某个地址
      ['2130706433', true], // 同上（十进制整数形态）
      ['127.1', true],
      ['127.0.0.01', true],
      ['::ffff:0177.0.0.1', true],
    ])('isAmbiguousIpText(%s) === %s', (input, expected) => {
      expect(isAmbiguousIpText(input)).toBe(expected);
    });

    test.each([
      ['0177.0.0.1', '127.0.0.1'],
      ['0x7f.0.0.1', '127.0.0.1'],
      ['017700000001', '127.0.0.1'],
      ['127.1', '127.0.0.1'],
    ])(
      '歧义形态 %s 在宽松解析下确实会变成 %s（这条是危害本身，不是判据）',
      (input, collapsesTo) => {
        // 此后本仓的 normalizeIP 已不再宽松，危害证据只能直接问 ipaddr
        // （lenientAddressHint 就是它的显示用出口，绝不参与任何判定）
        expect(lenientAddressHint(input)).toBe(collapsesTo);
        expect(require('../utils/ipUtils').normalizeIP(input)).toBeNull();
        expect(isAmbiguousIpText(input)).toBe(true);
        expect(strictNormalizeClientIp(input)).toBeNull();
      }
    );

    test('严格归一化：规范形态结果与旧口径一致，歧义形态变 null', () => {
      expect(strictNormalizeClientIp('::ffff:127.0.0.1')).toBe('127.0.0.1');
      expect(strictNormalizeClientIp('2001:0DB8::1')).toBe('2001:db8::1');
      expect(strictNormalizeClientIp(' 10.0.0.1 ')).toBe('10.0.0.1');
      expect(strictNormalizeClientIp('0x7f.0.0.1')).toBeNull();
      expect(strictNormalizeClientIp('0177.0.0.1')).toBeNull();
      expect(strictNormalizeClientIp(undefined)).toBeNull();
      // 负向自证：ipaddr 本身仍然会把八进制变成 127.0.0.1，
      // 所以上面的 null 不是"输入本来就不像 IP"造成的巧合，而是本仓主动拒绝
      expect(lenientAddressHint('0177.0.0.1')).toBe('127.0.0.1');
    });
  });

  describe('账户 allowedIPs（访问控制）', () => {
    test('伪装成被允许的环回地址必须被拒（修复前：allowed=true）', () => {
      for (const fake of ['0x7f.0.0.1', '0177.0.0.1', '017700000001']) {
        const r = isIPAllowed(fake, '127.0.0.1');
        expect({ fake, ...r }).toEqual({
          fake,
          allowed: false,
          reason: 'invalid_client_ip',
          matchedRule: null,
        });
      }
    });

    test('正对照：规范写法与 ::ffff: 映射写法照旧放行（严格化不许误伤真实客户端）', () => {
      expect(isIPAllowed('127.0.0.1', '127.0.0.1').allowed).toBe(true);
      expect(isIPAllowed('::ffff:127.0.0.1', '127.0.0.1').allowed).toBe(true);
      expect(isIPAllowed('10.0.0.7', '10.0.0.0/24').allowed).toBe(true);
      expect(isIPAllowed('10.9.0.7', '10.0.0.0/24').allowed).toBe(false);
      // 排除项仍然优先
      expect(isIPAllowed('10.0.0.7', '10.0.0.0/24, !10.0.0.7').allowed).toBe(false);
    });
  });

  describe('IP 黑白名单（豁免面）', () => {
    let IPBlacklist;
    beforeAll(async () => {
      IPBlacklist = require('../models/IPBlacklist');
      if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    });
    beforeEach(async () => {
      await IPBlacklist.deleteMany({});
      IPBlacklist.invalidateSnapshot();
    });
    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
    });

    test('白名单条目不能被八进制/十六进制形态命中', async () => {
      await IPBlacklist.blockIP('127.0.0.1', { type: 'white', durationMs: 0 });
      expect(await IPBlacklist.isWhitelisted('127.0.0.1')).toBe(true); // 正对照
      expect(await IPBlacklist.isWhitelisted('::ffff:127.0.0.1')).toBe(true); // 映射形态仍等价
      for (const fake of ['0x7f.0.0.1', '0177.0.0.1', '017700000001']) {
        expect(await IPBlacklist.isWhitelisted(fake)).toBe(false);
      }
    });

    test('黑名单同样不接受歧义形态；网段白名单也不接受', async () => {
      await IPBlacklist.blockIP('10.0.0.0/8', { type: 'white', durationMs: 0 });
      expect(await IPBlacklist.isWhitelisted('10.1.2.3')).toBe(true);
      expect(await IPBlacklist.isWhitelisted('012.1.2.3')).toBe(false); // 八进制 012 → 会被读成 10.x
      await IPBlacklist.blockIP('203.0.113.9', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('203.0.113.9')).toBe(true);
      expect(await IPBlacklist.isBlocked('0217.0.0.011')).toBe(false); // 不"命中别的封禁"也不伪装
    });

    test('matchIP / findCoveringEntries 的管理面口径不受影响（条目文本仍可宽松）', async () => {
      await IPBlacklist.blockIP('192.168.0.0/16', { durationMs: 0 });
      const hits = await IPBlacklist.matchIP('192.168.7.5', 'black');
      expect(hits.map((h) => h.ip)).toEqual(['192.168.0.0/16']);
      const covering = await IPBlacklist.findCoveringEntries('192.168.7.5', 'black');
      expect(covering).toHaveLength(1);
    });
  });

  /**
   * 严格形态判据曾只挡"全是数字"的写法：十进制 2130706433 与八进制 017700000001 被抓，
   * 而十六进制 `0x7f000001` 含 'x' 漏网——实测 isAmbiguousIpText=false 而
   * normalizeIP 给出 127.0.0.1，等于把"客户端可控文本写成任意规范地址"这条线
   * 留了一个形态缺口（命中白名单即同时豁免黑名单+限流，并绕过账户 allowedIPs）。
   * 消费侧的端到端拦截由本文件上面的白名单/封禁用例覆盖，这里只钉判据本身的形态集合。
   */
  describe('歧义形态集合必须覆盖十六进制单数字', () => {
    const { isAmbiguousIpText } = require('../utils/ipUtils');

    test.each(['0x7f000001', '0X7F000001', '0x7f000001/32', '2130706433', '017700000001'])(
      '%s 判为歧义',
      (text) => {
        expect(isAmbiguousIpText(text)).toBe(true);
      }
    );

    test.each(['127.0.0.1', '0.0.0.0', '::ffff:127.0.0.1', '192.168.0.0/16', '::1'])(
      '规范形态 %s 不得被误判（否则查询侧直接失效）',
      (text) => {
        expect(isAmbiguousIpText(text)).toBe(false);
      }
    );
  });
});
