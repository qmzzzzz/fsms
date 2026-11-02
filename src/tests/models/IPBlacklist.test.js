/**
 * IPBlacklist 模型测试
 * 覆盖：单地址精确匹配（存量行为回归）、等价地址归一化、CIDR 网段包含、过期惰性清理、脏数据容错
 *
 * 快照失效清单（F5，第十一轮）：post 钩子必须与 auditLogHooks 的 APPEND_ONLY_HOOKS 同宽（9 项写入口）。
 * 漏 replaceOne / findOneAndReplace / bulkWrite 时，改过的 ip 在 TTL 内表现为「旧地址仍拦、新地址不拦」，
 * 且没有任何信号——不是延迟生效，是判据反了。清单宽度的判据在下方「快照失效覆盖全部写入口」用例。
 */

const mongoose = require('mongoose');
const { waitFor } = require('../helpers/waitFor');

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
      // durationMs:1 的到期由 waitFor 轮询实际判定，不靠一段固定睡眠覆盖
      await waitFor(
        async () =>
          (await IPBlacklist.isBlocked('1.2.3.4')) === false &&
          (await IPBlacklist.isBlocked('5.6.7.8')) === false,
        { label: '两条 1ms 封禁均已到期并放行' }
      );
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
  /*
   * F5（第十一轮审计）：名单快照的失效钩子只列了 8 个写操作，漏掉
   * findOneAndReplace / replaceOne / bulkWrite —— 与 APPEND_ONLY_HOOKS 的 9 项清单不一致。
   * 漏一个的后果不是"晚 10 秒生效"这么轻：改过 ip 之后**旧地址继续被拦、新地址不被拦**，
   * 而快照 TTL 内没有任何信号提示这件事（TTL 到期后才自愈，且期间判据是反的）。
   * 下面三条按"改完立刻读"钉住：每个写入口都必须让快照失效。
   */
  /*
   * F-25-7（第 25 轮审计实测）：重复封禁同一 IP 时，upsert 的 $set 把**既有条目的字段整体覆写**，
   * 于是「第三方写下的永久封禁」被一次 24h 的重复封禁降级成临时封禁，且对方的 reason 也被换掉。
   * 后果不是「少拦一会儿」：到期后 TTL 直接删档，而重复封禁这条路是运维最常走的
   * （自动阶梯、池封禁、手工补封都会打到同一条 upsert 上）⇒ 永久封禁会自己消失，没有任何信号。
   * 修法取「更严的一侧」：永久优先、时长取大、原 reason/source 保留。下面断言全部读**库侧**行。
   */
  describe('重复封禁取更严的一侧（F-25-7）', () => {
    const rowOf = (ip) => IPBlacklist.findOne({ ip }).lean();

    test('永久封禁不得被后续临时封禁降级（到期时间仍是 null）', async () => {
      await IPBlacklist.blockIP('203.0.113.40', {
        reason: '第三方-长期封禁',
        durationMs: 0,
        source: 'auto',
      });
      await IPBlacklist.blockIP('203.0.113.40', { reason: '我方-24h', durationMs: 24 * 3600000 });
      const row = await rowOf('203.0.113.40');
      expect({ durationMs: row.durationMs, expiresAt: row.expiresAt }).toEqual({
        durationMs: 0,
        expiresAt: null,
      });
      // 判据反了的样子：expiresAt 变成某个时刻，TTL 到期就把这条永久封禁删掉
      expect(row.reason).toBe('第三方-长期封禁');
      expect(row.source).toBe('auto');
    });

    test('时长只增不减：7 天封禁不被 1 小时的重复封禁缩短', async () => {
      await IPBlacklist.blockIP('203.0.113.41', { reason: '七天', durationMs: 7 * 24 * 3600000 });
      const before = await rowOf('203.0.113.41');
      await IPBlacklist.blockIP('203.0.113.41', { reason: '缩短到1h', durationMs: 3600000 });
      const after = await rowOf('203.0.113.41');
      expect(after.durationMs).toBe(7 * 24 * 3600000);
      expect(+after.expiresAt).toBe(+before.expiresAt); // 缩短请求也不得推迟既有到期
    });

    test('重复封禁保留首封时间 createdAt', async () => {
      await IPBlacklist.blockIP('203.0.113.42', { reason: '首封', durationMs: 3600000 });
      const first = await rowOf('203.0.113.42');
      await IPBlacklist.blockIP('203.0.113.42', { reason: '再封', durationMs: 3600000 });
      const second = await rowOf('203.0.113.42');
      expect(+second.createdAt).toBe(+first.createdAt);
    });

    test('省略 targetUsername 不得把既有值清空', async () => {
      await IPBlacklist.blockIP('203.0.113.43', {
        reason: '带用户',
        durationMs: 3600000,
        targetUsername: 'alice',
      });
      await IPBlacklist.blockIP('203.0.113.43', { reason: '不带用户', durationMs: 3600000 });
      expect((await rowOf('203.0.113.43')).targetUsername).toBe('alice');
    });
  });

  describe('快照失效覆盖全部写入口（F5）', () => {
    /** 预热快照：先 blockIP（会失效快照）再 isBlocked（把当前名单读进缓存） */
    const warm = async (ip) => {
      await IPBlacklist.blockIP(ip, { durationMs: 0 });
      expect(await IPBlacklist.isBlocked(ip)).toBe(true);
    };

    test('findOneAndReplace 改 ip 后快照必须失效', async () => {
      await warm('203.0.113.10');
      await IPBlacklist.findOneAndReplace(
        { ip: '203.0.113.10' },
        { ip: '203.0.113.11', type: 'black', durationMs: 0, expiresAt: null }
      );
      expect(await IPBlacklist.isBlocked('203.0.113.11')).toBe(true);
      expect(await IPBlacklist.isBlocked('203.0.113.10')).toBe(false);
    });

    test('replaceOne 改 ip 后快照必须失效', async () => {
      await warm('203.0.113.20');
      await IPBlacklist.replaceOne(
        { ip: '203.0.113.20' },
        { ip: '203.0.113.21', type: 'black', durationMs: 0, expiresAt: null }
      );
      expect(await IPBlacklist.isBlocked('203.0.113.21')).toBe(true);
      expect(await IPBlacklist.isBlocked('203.0.113.20')).toBe(false);
    });

    test('bulkWrite 改 ip 后快照必须失效', async () => {
      await warm('203.0.113.30');
      await IPBlacklist.bulkWrite([
        {
          updateOne: {
            filter: { ip: '203.0.113.30' },
            update: { $set: { ip: '203.0.113.31' } },
          },
        },
      ]);
      expect(await IPBlacklist.isBlocked('203.0.113.31')).toBe(true);
      expect(await IPBlacklist.isBlocked('203.0.113.30')).toBe(false);
    });
  });
});
