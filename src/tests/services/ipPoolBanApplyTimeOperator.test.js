'use strict';

/**
 * 落库时刻的判据（判据位接错时刻 + 先判后写）
 *
 * 缺陷一（audit-r2-fixes 实测、本文件钉住）：取票与落库是**两个时刻**。取票时操作者在段外（判据放行），
 * 确认时来源 IP 已变到段内 ⇒ 整段连操作者一起封掉，若又无覆盖其来源的永久白名单，谁都解不开。
 * ip-list 侧不存在：它在**写入时刻**现取 operatorIp（ipListSegmentGuards.js:219）。
 *
 * 缺陷二：并集判据原先只在**写完**之后跑，于是两份事各自成立——名单被别人补齐成整族时，
 * 回滚会按 _id 删掉**别人**那条（实测：他人预置的 128.0.0.0/1 被一次确认删掉）。
 * 故并集必须在写入**之前**也判一次；写完之后的复检保留，它挡的是并发写者。
 *
 * 判据类拒绝不消耗票据：与打字确认同理，环境变回来自救。
 */

describe('pool-ban 落库时刻的判据', () => {
  let ban;
  let IPBlacklist;
  let mongoose;
  const V4 = '203.0.113.0/28';
  const INSIDE = '203.0.113.5';
  const OUTSIDE = '198.51.100.9';
  const V6 = ['::/1', '8000::/1'];
  // 必须与「别人已存在的那条」**同值**，否则 upsert 不命中，回滚根本碰不到别人的行（见下方用例）
  const A = ['0.0.0.0/1', '128.0.0.0/1'];

  const clean = async () => {
    if (IPBlacklist) await IPBlacklist.deleteMany({ ip: { $in: [V4, ...V6, ...A] } });
  };

  const request = (cidr) =>
    ban.requestBan({ cidr, reason: '落到时刻判据', operator: 'probe-op', operatorIp: OUTSIDE });

  beforeAll(async () => {
    mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    IPBlacklist = require('../../models/IPBlacklist');
    ban = require('../../services/ipPoolBan');
  });

  beforeEach(async () => {
    ban.resetPoolBanState();
    await clean();
  });

  afterAll(async () => {
    await clean().catch(() => {});
    if (mongoose && mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('确认时操作者已进入该段：必须拒，且一条都不落库', async () => {
    const t = await request(V4);
    expect(t.ok).toBe(true);
    const applied = await ban.applyBan({ token: t.token, operatorIp: INSIDE });
    expect(applied.ok).toBe(false);
    expect(applied.reason).toBe('operator_inside');
    expect(await IPBlacklist.countDocuments({ ip: V4 })).toBe(0);
  });

  test('反向对照：操作者不在段内时照常落库（判据不是恒拒）', async () => {
    const t = await request(V4);
    const applied = await ban.applyBan({ token: t.token, operatorIp: OUTSIDE });
    expect(applied.ok).toBe(true);
    expect(applied.bannedCount).toBe(1);
  });

  test('判据类拒绝不消耗票据：来源变回去仍可确认', async () => {
    const t = await request(V4);
    const refused = await ban.applyBan({ token: t.token, operatorIp: INSIDE });
    expect(refused.reason).toBe('operator_inside');
    const retried = await ban.applyBan({ token: t.token, operatorIp: OUTSIDE });
    expect(retried.ok).toBe(true);
    expect(retried.bannedCount).toBe(1);
  });

  test('未传 operatorIp 时行为不变（控制器接线前不得改变既有语义）', async () => {
    const t = await request(V4);
    const applied = await ban.applyBan({ token: t.token });
    expect(applied.ok).toBe(true);
    expect(applied.bannedCount).toBe(1);
  });

  test('取齐两张 /1 票：第二条在**写入之前**就被拒，rolledBack=0（没写就没得回滚）', async () => {
    const first = await request(V6[0]);
    const second = await request(V6[1]);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect((await ban.applyBan({ token: first.token, typedConfirm: V6[0] })).ok).toBe(true);
    const applied2 = await ban.applyBan({ token: second.token, typedConfirm: V6[1] });
    expect(applied2.ok).toBe(false);
    expect(applied2.reason).toBe('union_covers_family');
    expect(applied2.rolledBack).toBe(0);
    expect(applied2.rolledBackIds).toEqual([]);
    expect(await IPBlacklist.countDocuments({ ip: { $in: V6 } })).toBe(1);
  });

  test('他人已有的条目不得被回滚删掉：并集在取票之后由他人补齐', async () => {
    const t = await request(A[0]);
    expect(t.ok).toBe(true);
    await IPBlacklist.blockIP(A[0], { reason: '他人预置', durationMs: 0, source: 'manual' });
    await IPBlacklist.blockIP(A[1], { reason: '他人预置', durationMs: 0, source: 'manual' });
    const others = await IPBlacklist.findOne({ ip: A[0] }).lean();
    expect(others).toBeTruthy();
    const applied = await ban.applyBan({ token: t.token, typedConfirm: A[0] });
    expect(applied.ok).toBe(false);
    expect(applied.reason).toBe('union_covers_family');
    const after = await IPBlacklist.findOne({ ip: A[0] }).lean();
    expect(after).toBeTruthy();
    expect(String(after._id)).toBe(String(others._id));
    expect(after.reason).toBe('他人预置');
  });
});
