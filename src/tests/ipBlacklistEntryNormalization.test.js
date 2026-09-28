'use strict';

/**
 * （2026-09-19）：IP 名单条目的**存储侧**归一化
 *
 * 既有套件覆盖的是"匹配时把等价写法当同一地址"（ipMatchesEntry 归一化两侧）。
 * 缺的是另一半：`ip` 上的唯一索引是**文本唯一**，而匹配是**语义唯一**。
 * 于是同一个地址可以躺两条记录（`1.2.3.4` 与 `::ffff:1.2.3.4`），
 * 后果不是脏数据，而是 **解封失效**——管理面按精确文本删其中一条，
 * 另一条继续命中，表现为"封得住、解不开"。
 * 今天两个写入方各自先归一化所以没踩到；不变行属于存储边界，不该靠调用方记住。
 */

const mongoose = require('mongoose');

describe('IPBlacklist 条目归一化', () => {
  let IPBlacklist;

  beforeAll(async () => {
    IPBlacklist = require('../models/IPBlacklist');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await IPBlacklist.deleteMany({});
    IPBlacklist.invalidateSnapshot();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  describe('normalizeEntryIp 判据', () => {
    test.each([
      ['::ffff:1.2.3.4', '1.2.3.4'],
      ['::ffff:127.0.0.1', '127.0.0.1'],
      ['2001:0DB8::1', '2001:db8::1'],
      [' 10.0.0.1 ', '10.0.0.1'],
      ['10.0.0.0/8', '10.0.0.0/8'],
      // 收口后本行改判"原样返回"（技术文档 17:55Z 已预告）：ipUtils 不再接受
      // ipaddr 的宽松 v4 数值形态（这里 010 = 八进制 8），歧义文本一律解析失败，
      // 归一化对解析失败的值只做"不动"，拒绝与否由入站校验负责。
      // 旧口径 010.000.000.000/8 → 8.0.0.0/8 正是宽松解析仍在的活证据。
      ['010.000.000.000/8', '010.000.000.000/8'],
      // 幂等：已经归一化的必须原样返回，否则每次写库都在改数据
      ['192.168.1.100', '192.168.1.100'],
      ['2001:db8:aaaa:bbbb::/64', '2001:db8:aaaa:bbbb::/64'],
    ])('%s ⇒ %s', (raw, expected) => {
      expect(IPBlacklist.normalizeEntryIp(raw)).toBe(expected);
    });

    test('认不出的值原样保留：归一化只做收敛，不新增拒绝路径（格式校验属于入站边界）', () => {
      expect(IPBlacklist.normalizeEntryIp('::::')).toBe('::::');
      expect(IPBlacklist.normalizeEntryIp('not-an-ip')).toBe('not-an-ip');
      expect(IPBlacklist.normalizeEntryIp('')).toBe('');
      expect(IPBlacklist.normalizeEntryIp(undefined)).toBe('');
      expect(IPBlacklist.normalizeEntryIp(null)).toBe('');
      // 负向自证：判据不是"一律返回原文"（那样上面全绿也没意义）
      expect(IPBlacklist.normalizeEntryIp('::ffff:9.9.9.9')).not.toBe('::ffff:9.9.9.9');
    });
  });

  describe('写路径都吃到这把尺子', () => {
    test('blockIP 收到映射形式时按规范文本落库，且不产生第二条等价记录', async () => {
      const entry = await IPBlacklist.blockIP('::ffff:203.0.113.7', { durationMs: 0 });
      expect(entry.ip).toBe('203.0.113.7');
      expect(await IPBlacklist.countDocuments({ ip: '203.0.113.7' })).toBe(1);
      // 旧行为：这一条会存在（因为 filter 用的是调用方给的原文）
      expect(await IPBlacklist.countDocuments({ ip: '::ffff:203.0.113.7' })).toBe(0);
    });

    test('create 路径（跑校验）同样归一化', async () => {
      const doc = await IPBlacklist.create({ ip: '::ffff:203.0.113.20', type: 'black' });
      expect(doc.ip).toBe('203.0.113.20');
      const raw = await IPBlacklist.collection.findOne({ ip: '::ffff:203.0.113.20' });
      expect(raw).toBeNull();
    });

    test('核心可用性保证：用映射形式解封，能删掉按规范文本存的封禁', async () => {
      await IPBlacklist.blockIP('198.51.100.9', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('198.51.100.9')).toBe(true);

      await IPBlacklist.unblockIP('::ffff:198.51.100.9', 'black');

      expect(await IPBlacklist.isBlocked('198.51.100.9')).toBe(false);
      expect(await IPBlacklist.countDocuments({})).toBe(0);
    });

    test('反向：先以映射形式封、再以规范形式解，同样解得开（同一把尺子的两个方向）', async () => {
      await IPBlacklist.blockIP('::ffff:198.51.100.10', { durationMs: 0 });
      await IPBlacklist.unblockIP('198.51.100.10', 'black');
      expect(await IPBlacklist.isBlocked('198.51.100.10')).toBe(false);
    });

    test('同一地址的两种写法不再各存一条黑白记录（唯一索引不再被文本差异绕过）', async () => {
      await IPBlacklist.blockIP('203.0.113.30', { type: 'white', durationMs: 0 });
      await IPBlacklist.blockIP('::ffff:203.0.113.30', { type: 'white', durationMs: 0 });
      expect(await IPBlacklist.countDocuments({ type: 'white' })).toBe(1);
    });
  });

  describe('不改变既有语义', () => {
    test('脏数据仍然只是"不命中"，不因归一化而报错或变成通配', async () => {
      await IPBlacklist.create({ ip: '::::', type: 'black', expiresAt: null });
      expect(await IPBlacklist.isBlocked('8.8.8.8')).toBe(false);
      expect(await IPBlacklist.isBlocked('::::')).toBe(true); // 精确文本匹配仍然成立
      const rows = await IPBlacklist.find({});
      expect(rows.map((r) => r.ip)).toEqual(['::::']);
    });

    test('CIDR 条目仍按网段命中，且规范写法不会被改写', async () => {
      await IPBlacklist.blockIP('192.168.0.0/16', { durationMs: 0 });
      expect(await IPBlacklist.isBlocked('192.168.7.5')).toBe(true);
      expect((await IPBlacklist.findOne({ type: 'black' })).ip).toBe('192.168.0.0/16');
    });
  });
});
