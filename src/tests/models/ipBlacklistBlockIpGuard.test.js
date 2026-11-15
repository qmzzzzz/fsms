/**
 * P2-09：blockIP 的 durationMs 入口显式收口。
 *
 * 旧写法 `durationMs > 0 ? durationMs : 0` 把 NaN 静默判成永久封禁，字符串入参会让
 * 合并管道里的 $add/$max 产出非法到期时间。现口径：Number() 显式收口，非有限数值或
 * 负数抛 TypeError（fail-loud）；undefined 走缺省 1 小时；0 保持"业务永久"语义。
 */
const mongoose = require('mongoose');

describe('IPBlacklist.blockIP 的 durationMs 收口（P2-09）', () => {
  let IPBlacklist;
  const stamp = Date.now();
  const ips = {
    nan: `192.0.2.${(stamp % 250) + 1}`,
    str: `192.0.2.${((stamp >> 2) % 250) + 1}`,
    inf: `192.0.2.${((stamp >> 4) % 250) + 1}`,
    neg: `192.0.2.${((stamp >> 6) % 250) + 1}`,
    undef: `192.0.2.${((stamp >> 8) % 250) + 1}`,
    zero: `192.0.2.${((stamp >> 10) % 250) + 1}`,
    pos: `192.0.2.${((stamp >> 12) % 250) + 1}`,
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    IPBlacklist = require('../../models/IPBlacklist');
  });

  afterAll(async () => {
    await IPBlacklist.deleteMany({ ip: { $in: Object.values(ips) } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('NaN / 非数值串 / Infinity / 负数一律 TypeError（fail-loud，不再静默判永久）', async () => {
    for (const [ip, bad] of [
      [ips.nan, NaN],
      [ips.str, 'abc'],
      [ips.inf, Infinity],
      [ips.neg, -1],
    ]) {
      await expect(IPBlacklist.blockIP(ip, { durationMs: bad })).rejects.toThrow(TypeError);
      await expect(IPBlacklist.blockIP(ip, { durationMs: bad })).rejects.toThrow(/durationMs/);
    }
    // 脏值路径不落库
    expect(
      await IPBlacklist.findOne({ ip: { $in: [ips.nan, ips.str, ips.inf, ips.neg] } })
    ).toBeNull();
  });

  test('undefined 走缺省 1 小时；0 保持业务永久；正数按毫秒到期', async () => {
    const before = Date.now();
    const byDefault = await IPBlacklist.blockIP(ips.undef, {});
    expect(byDefault.durationMs).toBe(3600000);
    expect(byDefault.expiresAt).not.toBeNull();

    const permanent = await IPBlacklist.blockIP(ips.zero, { durationMs: 0 });
    expect(permanent.durationMs).toBe(0);
    expect(permanent.expiresAt).toBeNull(); // 0=业务永久语义保持

    const timed = await IPBlacklist.blockIP(ips.pos, { durationMs: 5000 });
    expect(timed.durationMs).toBe(5000);
    expect(timed.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 5000);
    expect(timed.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 5000);
  });
});
