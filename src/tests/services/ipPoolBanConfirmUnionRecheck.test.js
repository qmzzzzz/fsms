'use strict';

/**
 * 确认时的并集复检：申请时判过、确认时必须再判一次
 *
 * 缺陷形态（audit-ops 第 22 轮实测，第 23 轮由本文件钉住）：
 *   依次申请 ::/1 与 8000::/1 两张票据（各申请时并集都还没铺满），再各自确认 ⇒ 两条都落库，
 *   并集等价 ::/0（全 IPv6 拒服 + 管理员自锁），而顺序重申请会被 union_covers_family 拒。
 *   不需要并发，取齐票即可。
 *
 * 判据要害：requestBan 与 applyBan 之间是**两个时刻**，黑名单在两者之间会变（可能正是另一张票
 * 落库造成的）。只在申请时判一次 = 用"申请那一刻的名单"决定"落库那一刻"的安全性。
 */

const { cidrUnionCoversAll } = require('../../utils/cidrCoverage');
const ipListService = require('../../services/ipListService');

describe('pool-ban 确认时的并集复检（取齐票不得拼满整族）', () => {
  let ban;
  let IPBlacklist;
  let mongoose;
  const V6 = ['::/1', '8000::/1'];

  const clean = async () => {
    if (IPBlacklist) await IPBlacklist.deleteMany({ ip: { $in: V6 } });
  };

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

  const unionOfV6 = async () => {
    const rows = await IPBlacklist.find({ ip: { $in: V6 } }).lean();
    return cidrUnionCoversAll(
      rows.map((r) => r.ip),
      'ipv6'
    );
  };

  test('取齐两张 /1 票再各自确认：第二条必须被拦，并集不得铺满 IPv6', async () => {
    const first = await ban.requestBan({
      cidr: '::/1',
      reason: '取齐票-甲',
      operator: 'probe-op',
      operatorIp: '198.51.100.9',
    });
    const second = await ban.requestBan({
      cidr: '8000::/1',
      reason: '取齐票-乙',
      operator: 'probe-op',
      operatorIp: '198.51.100.9',
    });
    // 申请阶段两条都该拿到票（各自单独看不铺满）
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);

    const applied1 = await ban.applyBan({ token: first.token, typedConfirm: '::/1' });
    expect(applied1.ok).toBe(true);

    const applied2 = await ban.applyBan({ token: second.token, typedConfirm: '8000::/1' });
    expect(applied2.ok).toBe(false);
    expect(applied2.reason).toBe('union_covers_family');

    const union = await unionOfV6();
    expect(union.ipv6).toBe(false);
    expect(await IPBlacklist.countDocuments({ ip: { $in: V6 } })).toBe(1);
  });

  test('反向对照：单条 /1 确认照常落库（判据不是恒拒）', async () => {
    const t = await ban.requestBan({
      cidr: '::/1',
      reason: '单条对照',
      operator: 'probe-op',
      operatorIp: '198.51.100.9',
    });
    expect(t.ok).toBe(true);
    const applied = await ban.applyBan({ token: t.token, typedConfirm: '::/1' });
    expect(applied.ok).toBe(true);
    expect(applied.bannedCount).toBe(1);
  });

  test('申请时已铺满则直接拒（既有判据未放宽）', async () => {
    await IPBlacklist.blockIP('::/1', { reason: '预置', durationMs: 0, source: 'manual' });
    const t = await ban.requestBan({
      cidr: '8000::/1',
      reason: '铺满后申请',
      operator: 'probe-op',
      operatorIp: '198.51.100.9',
    });
    expect(t.ok).toBe(false);
    expect(t.reason).toBe('union_covers_family');
  });

  /**
   * 确认时的并集复核对「已经写进去的行」有没有兜底 —— rollbackIfUnionCoversFamily（services/ipPoolBan.js）
   *
   * 该分支只在「写入前并集不覆盖、写入后覆盖」时进得去，而两个判据之间只隔一次 await：
   * 正常单线程路径上不可能出现，只有名单在窗口内被他人改动才成立。因此 jest.spyOn 造出
   * 「第二次调用结果不同」的最小窗口——这是唯一可达路径，不是为了让测试好写。
   *
   * 断言全部是**库侧事实**：写进去的 _id 真的没了；他人写前已有的同值条目不受影响；
   * 拒绝原因为 union_covers_family 且 rolledBack 计数与实际删除条数一致（假记数会被抓到）。
   */
  test('确认时并集被他人铺满 ⇒ 回滚本次写入（库侧事实：_id 真的不在库）', async () => {
    const ticket = await ban.requestBan({
      cidr: '8000::/1',
      reason: '回滚-本次写入',
      operator: 'probe-op',
      operatorIp: '198.51.100.9',
    });
    expect(ticket.ok).toBe(true);

    // 他人在窗口内落的那一条：它与本次写入合成 ::/0，正是回滚要防的形态
    const realList = ipListService.listActiveEntryIps.bind(ipListService);
    let calls = 0;
    const spy = jest.spyOn(ipListService, 'listActiveEntryIps').mockImplementation(async (type) => {
      calls += 1;
      const base = await realList(type);
      // 第 1 次是写入前判据（只有库里真实存在的），第 2 次起追加他人的 ::/1
      return calls === 1 ? base : [...base, '::/1'];
    });

    let applied;
    try {
      applied = await ban.applyBan({ token: ticket.token, typedConfirm: '8000::/1' });
    } finally {
      spy.mockRestore();
    }

    expect(applied.ok).toBe(false);
    expect(applied.reason).toBe('union_covers_family');
    expect(applied.rolledBack).toBe(1);

    // 库侧事实①：这次写入的 _id 真的不在库里了（不是只看返回的 rolledBack 计数）
    const ids = applied.rolledBackIds.map(String);
    expect(ids).toHaveLength(1);
    expect(await IPBlacklist.findById(ids[0]).lean()).toBeNull();
    // 库侧事实②：库里那条 8000::/1 真的没了（并集没有被本次写入铺满）
    expect(await IPBlacklist.countDocuments({ ip: '8000::/1' })).toBe(0);
    expect((await unionOfV6()).ipv6).toBe(false);
  });

  /**
   * F-25-8（第 25 轮审计实测，19/20 可复现）：并集在窗口内被铺满时要回滚，而回滚删的是
   * 「本次写入返回的 _id」——upsert 命中他人写前已有的同值条目时，那个 _id 是**别人的**。
   * 于是被拒的这次操作静默删掉一个既有封禁：拒绝理由说「为了保护名单」，实际把名单删薄了。
   *
   * 判据：blockIP 的驱动元数据（updatedExisting=false ⇒ 本次新建）是唯一能看见并发插入窗口的
   * 依据；先读后比看不见。未知/缺省一律按「非本次新建」⇒ 保守不删。
   */
  test('命中他人既有条目时回滚不得删它（库侧事实：条目与 _id 原样还在）', async () => {
    const existing = await IPBlacklist.blockIP('8000::/1', {
      reason: '他人预置-同值',
      durationMs: 0,
      source: 'manual',
    });
    const before = await IPBlacklist.findOne({ ip: '8000::/1' }).lean();
    expect(String(before._id)).toBe(String(existing._id));

    const ticket = await ban.requestBan({
      cidr: '8000::/1',
      reason: '回滚-命中既有',
      operator: 'probe-op',
      operatorIp: '198.51.100.9',
    });
    expect(ticket.ok).toBe(true);

    const realList = ipListService.listActiveEntryIps.bind(ipListService);
    let calls = 0;
    const spy = jest.spyOn(ipListService, 'listActiveEntryIps').mockImplementation(async (type) => {
      calls += 1;
      const base = await realList(type);
      return calls === 1 ? base : [...base, '::/1'];
    });

    let applied;
    try {
      applied = await ban.applyBan({ token: ticket.token, typedConfirm: '8000::/1' });
    } finally {
      spy.mockRestore();
    }

    expect(applied.ok).toBe(false);
    expect(applied.reason).toBe('union_covers_family');
    // 一条都没删（本次没新建任何条目），且如实报出「跳过了几条既有条目」
    expect(applied.rolledBack).toBe(0);
    expect(applied.rolledBackIds).toEqual([]);
    expect(applied.skippedExisting).toBe(1);

    // 库侧事实：他人那条既在库里、_id 与内容都没变
    const after = await IPBlacklist.findOne({ ip: '8000::/1' }).lean();
    expect(after).not.toBeNull();
    expect(String(after._id)).toBe(String(before._id));
    expect(after.reason).toBe('他人预置-同值');
    expect(after.durationMs).toBe(0);
  });

  test('回滚只删本次写入返回的 _id，不连带删同族其它条目（按 ip 删就会误删）', async () => {
    // 同族其它条目：他人写前已存在，与本次写入不同值 ⇒ 回滚若按 ip/网段删就会误伤
    const other = await IPBlacklist.blockIP('fd00::/8', {
      reason: '他人预置-同族',
      durationMs: 0,
      source: 'manual',
    });
    expect(String(other._id)).toBeTruthy();

    const ticket = await ban.requestBan({
      cidr: '8000::/1',
      reason: '回滚-不误删同族',
      operator: 'probe-op',
      operatorIp: '198.51.100.9',
    });
    expect(ticket.ok).toBe(true);

    const realList = ipListService.listActiveEntryIps.bind(ipListService);
    let calls = 0;
    const spy = jest.spyOn(ipListService, 'listActiveEntryIps').mockImplementation(async (type) => {
      calls += 1;
      const base = await realList(type);
      return calls === 1 ? base : [...base, '::/1'];
    });

    let applied;
    try {
      applied = await ban.applyBan({ token: ticket.token, typedConfirm: '8000::/1' });
    } finally {
      spy.mockRestore();
    }
    expect(applied.ok).toBe(false);
    expect(applied.reason).toBe('union_covers_family');
    expect(applied.rolledBack).toBe(1);

    // 库侧事实：本次写入的那条没了，同族他人条目仍在（回滚按 _id 而不是按 ip/网段）
    expect(await IPBlacklist.countDocuments({ ip: '8000::/1' })).toBe(0);
    expect(await IPBlacklist.findById(other._id).lean()).not.toBeNull();
    expect(await IPBlacklist.countDocuments({ ip: 'fd00::/8' })).toBe(1);
  });
});
