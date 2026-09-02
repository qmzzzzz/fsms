/**
 * IPBlacklist 模型测试
 * 覆盖：单地址精确匹配（存量行为回归）、等价地址归一化、CIDR 网段包含、过期惰性清理、脏数据容错
 */

const mongoose = require('mongoose');

describe('IPBlacklist Model', () => {
  let IPBlacklist;

  beforeAll(async () => {
    IPBlacklist = require('../../models/IPBlacklist');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await IPBlacklist.deleteMany({});
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('单地址精确匹配（存量行为回归）', () => {
    test('IPv4 精确命中，同网段其他地址不误拦', async () => {
      await IPBlacklist.blockIP('192.168.1.100', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('192.168.1.100')).toBe(true);
      expect(await IPBlacklist.isBlocked('192.168.1.101')).toBe(false);
    });

    test('无效/空客户端 IP 直接放行', async () => {
      await IPBlacklist.blockIP('1.2.3.4', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked(undefined)).toBe(false);
      expect(await IPBlacklist.isBlocked('')).toBe(false);
    });
  });

  describe('等价地址归一化匹配', () => {
    test('IPv6 等价文本写法视为同一地址', async () => {
      await IPBlacklist.blockIP('2001:db8::1', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('2001:db8:0:0:0:0:0:1')).toBe(true);
    });

    test('IPv4 映射 IPv6（::ffff:）与纯 IPv4 等价', async () => {
      await IPBlacklist.blockIP('192.168.1.5', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('::ffff:192.168.1.5')).toBe(true);
    });
  });

  describe('CIDR 网段匹配', () => {
    test('IPv4 /16 网段拦截网段内地址、放行网段外地址', async () => {
      await IPBlacklist.blockIP('192.168.0.0/16', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('192.168.1.77')).toBe(true);
      expect(await IPBlacklist.isBlocked('192.169.1.77')).toBe(false);
    });

    test('IPv6 /64 网段拦截（防地址轮换绕过封禁）', async () => {
      await IPBlacklist.blockIP('2001:db8:aaaa:bbbb::/64', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('2001:db8:aaaa:bbbb:0:0:0:1234')).toBe(true);
      expect(await IPBlacklist.isBlocked('2001:db8:aaaa:cccc::1')).toBe(false);
    });

    test('白名单支持 CIDR 网段', async () => {
      await IPBlacklist.blockIP('10.0.0.0/8', { type: 'white', durationMs: 0 });
      expect(await IPBlacklist.isWhitelisted('10.1.2.3')).toBe(true);
      expect(await IPBlacklist.isWhitelisted('11.1.2.3')).toBe(false);
    });

    test('多条网段并存时均生效（如 /16 与 /24 叠加）', async () => {
      await IPBlacklist.blockIP('192.168.0.0/16', { durationMs: 0 });
      await IPBlacklist.blockIP('192.168.100.0/24', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('192.168.100.55')).toBe(true);
      expect(await IPBlacklist.isBlocked('192.168.7.7')).toBe(true);
    });
  });

  describe('matchIP 查询（多条命中取最宽泛）', () => {
    test('/16 与 /24 同时命中时，最宽泛的 /16 排首位', async () => {
      await IPBlacklist.blockIP('192.168.100.0/24', { durationMs: 0 });
      await IPBlacklist.blockIP('192.168.0.0/16', { durationMs: 0 });
      const matches = await IPBlacklist.matchIP('192.168.100.55', 'black');
      expect(matches).toHaveLength(2);
      expect(matches[0].ip).toBe('192.168.0.0/16');
      expect(matches[1].ip).toBe('192.168.100.0/24');
    });

    test('IPv6 多条命中按前缀宽度排序（/32 优先于 /64）', async () => {
      await IPBlacklist.blockIP('2001:db8:aaaa:bbbb::/64', { durationMs: 0 });
      await IPBlacklist.blockIP('2001:db8::/32', { durationMs: 0 });
      const matches = await IPBlacklist.matchIP('2001:db8:aaaa:bbbb::1', 'black');
      expect(matches[0].ip).toBe('2001:db8::/32');
      expect(matches[1].ip).toBe('2001:db8:aaaa:bbbb::/64');
    });

    test('单地址与 CIDR 并存时 CIDR 优先（单地址视为最窄 /32）', async () => {
      await IPBlacklist.blockIP('10.1.2.3', { durationMs: 0 });
      await IPBlacklist.blockIP('10.0.0.0/8', { durationMs: 0 });
      const matches = await IPBlacklist.matchIP('10.1.2.3', 'black');
      expect(matches[0].ip).toBe('10.0.0.0/8');
      expect(matches[1].ip).toBe('10.1.2.3');
    });

    test('等价文本形式与白名单类型查询', async () => {
      await IPBlacklist.blockIP('2001:db8::1', { type: 'white', durationMs: 0 });
      const matches = await IPBlacklist.matchIP('2001:db8:0:0:0:0:0:1', 'white');
      expect(matches).toHaveLength(1);
      expect(matches[0].ip).toBe('2001:db8::1');
    });

    test('未命中返回空数组', async () => {
      await IPBlacklist.blockIP('192.168.1.1', { durationMs: 0 });
      expect(await IPBlacklist.matchIP('8.8.8.8', 'black')).toEqual([]);
    });
  });

  describe('过期记录惰性清理', () => {
    test('过期后放行（含 CIDR 记录）', async () => {
      await IPBlacklist.blockIP('1.2.3.4', { durationMs: 1 });
      await IPBlacklist.blockIP('5.6.7.0/24', { durationMs: 1 });
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(await IPBlacklist.isBlocked('1.2.3.4')).toBe(false);
      expect(await IPBlacklist.isBlocked('5.6.7.8')).toBe(false);
    });

    test('未过期记录仍生效', async () => {
      await IPBlacklist.blockIP('1.2.3.4', { durationMs: 60 * 60 * 1000 });
      expect(await IPBlacklist.isBlocked('1.2.3.4')).toBe(true);
    });
  });

  describe('异常数据容错', () => {
    test('历史脏数据（非法 IP 文本）不影响正常判断', async () => {
      await IPBlacklist.create({ ip: '::::', type: 'black', expiresAt: null });
      expect(await IPBlacklist.isBlocked('1.2.3.4')).toBe(false);
      // 脏数据字符串级精确相等仍命中自身（与旧行为一致）
      expect(await IPBlacklist.isBlocked('::::')).toBe(true);
    });
  });
});
