/** T6-2 CIDR 封禁：默认人工确认；自动模式必须显式开启且只认轮换池。护栏宁可拒，不可误伤。
 *
 * B1/B2/B3（2026-11-03）改写说明：
 *  - 票据外置 sharedCache（键 ip_pool_ban:ticket:*）：出票 setIfAbsent / 消费 getDel，
 *    并发同 token 只一方生效；Redis 配置但故障时 fail-closed 拒绝。进程内 pending 计数
 *    不再存在（getPoolBanStats().pending 恒 null），旧"内存边界"用例随之改写为存储语义。
 *  - 审计走 auditOutbox.recordDurably：本套件按仓内先例（mfaControllerErrorPaths 等）
 *    mock 该边界——recordDurably 自身的三态（DB 成功/WAL 兜底/重抛）由
 *    tests/services/auditOutbox.test.js 专责，这里钉的是 applyBan 的接线语义。 */
jest.mock('../../services/auditOutbox', () => ({
  recordDurably: jest.fn(),
}));

const ban = require('../../services/ipPoolBan');
const ipListService = require('../../services/ipListService');
const liveTraffic = require('../../services/ipPoolLiveTraffic');
const sharedCache = require('../../services/sharedCache');
const mongoose = require('mongoose');
const { recordDurably } = require('../../services/auditOutbox');

const operatorIp = '10.0.0.5';
// 生产真实返回形状：IPBlacklist.blockIP ⇒ findOneAndUpdate 的落库文档，**没有** banned 字段
const BLOCKED_DOC = { _id: 'e1', ip: '203.0.113.0/24', type: 'black', reason: 't' };

beforeEach(() => {
  ban.resetPoolBanState();
  jest.restoreAllMocks();
  recordDurably.mockReset();
  recordDurably.mockResolvedValue({}); // 缺省成功：成功落库的形态由归因用例断言实参
  // 并集判据要读当前黑名单快照、活跃度护栏要查审计库：不 mock 都会真的去打库
  jest.spyOn(ipListService, 'listActiveEntryIps').mockResolvedValue([]);
  jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
  jest.spyOn(liveTraffic, 'segmentHasLiveTraffic').mockResolvedValue({ live: false, scanned: 0 });
  delete process.env.IP_POOL_BAN_ALLOW_AUTO;
});

describe('护栏：这些情况一律拒绝封禁', () => {
  test('全网段 /0 ⇒ 拒绝（封了会把管理员自己挡在外面，无法再登录解除）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const r = await ban.requestBan({
      cidr: '0.0.0.0/0',
      reason: 'test',
      operator: 'admin',
      operatorIp,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('full_range_cidr');
    expect(ban.getPoolBanStats().refused).toBe(1);
  });

  test('白名单覆盖该段 ⇒ 拒绝（白名单优先，封了也不生效反而误导）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([{ ip: '203.0.113.0/24' }]);
    const r = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'admin',
      operatorIp,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('whitelist_covers');
  });

  test('操作者自己在该段内 ⇒ 拒绝（一键封禁最容易犯的自伤）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const r = await ban.requestBan({
      cidr: '10.0.0.0/24',
      reason: 't',
      operator: 'admin',
      operatorIp: '10.0.0.5',
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('operator_inside');
  });

  test('没写理由 ⇒ 拒绝（封段必须留下可追溯的理由）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const r = await ban.requestBan({ cidr: '203.0.113.0/24', operator: 'admin', operatorIp });
    expect(r.reason).toBe('reason_required');
  });

  test('段解析不出 ⇒ 拒绝（绝不拿一个解析不动的值去封）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const r = await ban.requestBan({
      cidr: 'not-a-cidr',
      reason: 't',
      operator: 'admin',
      operatorIp,
    });
    expect(r.reason).toBe('unparsable_cidr');
  });

  test('操作者在段外 ⇒ 放行（否则上面几条只是恒拒）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const r = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'admin',
      operatorIp,
    });
    expect(r.ok).toBe(true);
    expect(r.cidr).toBe('203.0.113.0/24');
  });
});

describe('拒绝计数：每个拒绝原因恰好记一次（同一事件两处自增 = 看板翻倍；漏记 = 看板少计）', () => {
  // 判据是**增量**：新增判据时不必回头改其它用例，也就少一次忘改的机会
  const cases = [
    [
      'unparsable_cidr',
      () => {},
      () => ban.requestBan({ cidr: 'not-a-cidr', reason: 't', operatorIp }),
    ],
    [
      'full_range_cidr',
      () => {},
      () => ban.requestBan({ cidr: '0.0.0.0/0', reason: 't', operatorIp }),
    ],
    ['reason_required', () => {}, () => ban.requestBan({ cidr: '203.0.113.0/24', operatorIp })],
    [
      'whitelist_covers',
      () => ipListService.findCoveringEntries.mockResolvedValue([{ ip: '203.0.113.0/24' }]),
      () => ban.requestBan({ cidr: '203.0.113.0/24', reason: 't', operatorIp }),
    ],
    [
      'union_covers_family',
      () => ipListService.listActiveEntryIps.mockResolvedValue(['128.0.0.0/1']),
      () => ban.requestBan({ cidr: '0.0.0.0/1', reason: 't', operatorIp }),
    ],
    [
      'operator_inside',
      () => {},
      () => ban.requestBan({ cidr: '10.0.0.0/24', reason: 't', operatorIp }),
    ],
    [
      'live_traffic_inside',
      () => liveTraffic.segmentHasLiveTraffic.mockResolvedValue({ live: true, scanned: 3 }),
      () => ban.requestBan({ cidr: '203.0.113.0/24', reason: 't', operatorIp }),
    ],
  ];

  test('申请侧七条判据逐条：拒绝即 +1', async () => {
    for (const [name, setup, call] of cases) {
      ban.resetPoolBanState();
      jest.restoreAllMocks();
      // restoreAllMocks 会撤掉 beforeEach 的三条 spy，这里按需重装（每条用例自己声明依赖，不靠外部顺序）
      jest.spyOn(ipListService, 'listActiveEntryIps').mockResolvedValue([]);
      jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
      jest
        .spyOn(liveTraffic, 'segmentHasLiveTraffic')
        .mockResolvedValue({ live: false, scanned: 0 });
      setup();
      const before = ban.getPoolBanStats().refused;
      const r = await call();
      expect({
        name,
        reason: r.reason,
        delta: ban.getPoolBanStats().refused - before,
      }).toEqual({ name, reason: name, delta: 1 });
    }
  });

  test('确认侧三条判据逐条：拒绝即 +1（unknown_token 曾经整条漏记）', async () => {
    const ticketFor = async (cidr) =>
      (await ban.requestBan({ cidr, reason: 't', operator: 'a', operatorIp })).token;
    const calls = [
      ['unknown_token', async () => ban.applyBan({ token: 'deadbeef' })],
      [
        'token_expired',
        async () =>
          ban.applyBan({
            token: await ticketFor('203.0.113.0/24'),
            now: new Date(Date.now() + 11 * 60 * 1000),
          }),
      ],
      [
        'typed_confirmation_required',
        async () => ban.applyBan({ token: await ticketFor('203.0.113.0/24') }),
      ],
    ];
    for (const [name, call] of calls) {
      ban.resetPoolBanState();
      const before = ban.getPoolBanStats().refused;
      const r = await call();
      expect({
        name,
        reason: r.reason,
        delta: ban.getPoolBanStats().refused - before,
      }).toEqual({ name, reason: name, delta: 1 });
    }
  });
});

describe('票据外置 sharedCache（B2）：一次性消费、敲错不消耗、fail-closed', () => {
  test('出票即落共享存储（键形状钉死），确认成功后被原子取删', async () => {
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const key = `${ban.TICKET_KEY_PREFIX}${req.token}`;
    // 键形状是对账面：ADR-005 的切换点清单按这个前缀登记，改前缀必须同步 ADR
    expect(await sharedCache.get(key)).toMatchObject({ cidr: '203.0.113.0/24' });
    await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' });
    expect(await sharedCache.get(key)).toBeNull();
  });

  test('并发同 token 双请求只一次 blockIP（getDel 原子取删，旧 Map 两步形态有双花窗口）', async () => {
    const blockSpy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const [r1, r2] = await Promise.all([
      ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' }),
      ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' }),
    ]);
    expect([r1, r2].filter((r) => r.ok)).toHaveLength(1);
    expect([r1, r2].find((r) => !r.ok).reason).toBe('unknown_token');
    expect(blockSpy).toHaveBeenCalledTimes(1);
  });

  test('敲错字后票据原样写回且剩余 TTL 随票走：重试仍可落库，过期后存储侧自然失效', async () => {
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const key = `${ban.TICKET_KEY_PREFIX}${req.token}`;
    const wrong = await ban.applyBan({ token: req.token, typedConfirm: '203.0.114.0/24' });
    expect(wrong).toMatchObject({ ok: false, reason: 'typed_confirmation_required' });
    // 写回的票带着剩余 TTL（随票存的 ttlMs 与票的 expiresAt 自洽），且重试仍能落库
    const writtenBack = await sharedCache.get(key);
    expect(writtenBack).toBeTruthy();
    expect(writtenBack.ttlMs).toBeGreaterThan(0);
    expect(writtenBack.ttlMs).toBeLessThanOrEqual(ban.CONFIRM_TTL_MS);
    const right = await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' });
    expect(right.ok).toBe(true);
    // TTL 由存储侧记账：推过 expiresAt 后写回的票自然消失（不依赖进程内清扫）
    const clock = jest.spyOn(Date, 'now').mockReturnValue(req.expiresAt.getTime() + 1000);
    try {
      await expect(sharedCache.get(key)).resolves.toBeNull();
    } finally {
      clock.mockRestore();
    }
  });

  test('Redis 配置但故障 ⇒ 出票被拒（fail-closed），绝不落进程内存假票', async () => {
    const savedUrl = process.env.REDIS_URL;
    process.env.REDIS_URL = 'redis://127.0.0.1:1'; // 必然连不上，且不 init（同 sharedCacheNonceFailClosed 的替身形态）
    sharedCache._resetForTests();
    try {
      expect(sharedCache.isRedisConfigured()).toBe(true);
      expect(sharedCache.isRedisEnabled()).toBe(false);
      const r = await ban.requestBan({
        cidr: '203.0.113.0/24',
        reason: 't',
        operator: 'a',
        operatorIp,
      });
      // 拒绝原因借用票据族语义（unknown_token：重新发起即可）——枚举是三向对账的闭合集合
      expect(r).toMatchObject({ ok: false, reason: 'unknown_token' });
      // 且没有任何内存假票：Redis 恢复前确认侧也取不到
      await expect(
        ban.applyBan({ token: 'whatever', typedConfirm: '203.0.113.0/24' })
      ).resolves.toMatchObject({ ok: false, reason: 'unknown_token' });
    } finally {
      if (savedUrl === undefined) delete process.env.REDIS_URL;
      else process.env.REDIS_URL = savedUrl;
      sharedCache._resetForTests();
    }
  });
});

describe('并集铺满判据（与 ipListController 同一把尺子）', () => {
  test('单条 /1 本身不是全网段，但两条互补 /1 的并集是 ⇒ 第二条必须拒（并集等价 /0）', async () => {
    // 0.0.0.0/1 不含操作者 IP（10.0.0.5 在 128.0.0.0/1 里），故第一条本身能过护栏
    ipListService.listActiveEntryIps.mockResolvedValue([]);
    // 先封"不含操作者"的那半（10.0.0.5 落在 0.0.0.0/1，放在第二步才不会被 operator_inside 抢先）
    const first = await ban.requestBan({
      cidr: '128.0.0.0/1',
      reason: 't',
      operator: 'admin',
      operatorIp,
    });
    expect(first.ok).toBe(true);
    expect(first.reason).toBeUndefined();
    // 模拟第一条已落库后再次申请互补的那半
    ipListService.listActiveEntryIps.mockResolvedValue(['128.0.0.0/1']);
    const second = await ban.requestBan({
      cidr: '0.0.0.0/1',
      reason: 't',
      operator: 'admin',
      operatorIp,
    });
    expect(second.ok).toBe(false);
    expect(second.reason).toBe('union_covers_family');
  });

  test('对照：同样已封 0.0.0.0/1，但只封一个小段 ⇒ 照常放行（判据不是恒拒）', async () => {
    ipListService.listActiveEntryIps.mockResolvedValue(['0.0.0.0/1']);
    const r = await ban.requestBan({
      cidr: '198.51.100.0/24', // 与已封段不重叠、也不含操作者
      reason: 't',
      operator: 'admin',
      operatorIp,
    });
    expect(r.ok).toBe(true);
  });
});

describe('封禁时长：缺省不等于永久', () => {
  // 203.0.113.0/24 主机数 ≥256 ⇒ 落库要打字确认，这里一并带上（用例关注的是时长，不是护栏）
  const issue = async () =>
    ban.requestBan({ cidr: '203.0.113.0/24', reason: 't', operator: 'a', operatorIp });
  const typed = '203.0.113.0/24';

  test('未声明 duration ⇒ 落库用 DEFAULT_BAN_MS（24h），不是 expiresAt=null 的永久', async () => {
    const spy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await issue();
    await ban.applyBan({ token: req.token, typedConfirm: typed });
    expect(spy.mock.calls[0][1].durationMs).toBe(24 * 60 * 60 * 1000);
  });

  test('显式 permanent ⇒ durationMs=0（IPBlacklist 里 0 才表示永久）', async () => {
    const spy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await issue();
    await ban.applyBan({
      token: req.token,
      typedConfirm: typed,
      permanent: true,
    });
    expect(spy.mock.calls[0][1].durationMs).toBe(0);
  });

  test('传了明确时长 ⇒ 原样使用', async () => {
    const spy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await issue();
    await ban.applyBan({
      token: req.token,
      typedConfirm: typed,
      durationMs: 7 * 3600 * 1000,
    });
    expect(spy.mock.calls[0][1].durationMs).toBe(7 * 3600 * 1000);
  });
});

describe('确认票据：不确认就不封', () => {
  test('只有持票才能落库；无票/过期票一律拒绝', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    expect((await ban.applyBan({ token: 'bogus' })).reason).toBe('unknown_token');
    const expired = await ban.applyBan({
      token: req.token,
      now: new Date(req.expiresAt.getTime() + 1000),
    });
    expect(expired.reason).toBe('token_expired');
  });

  test('票据只能用一次（重放同一张票不得二次生效）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    expect((await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' })).ok).toBe(
      true
    );
    expect((await ban.applyBan({ token: req.token })).reason).toBe('unknown_token');
  });
});

describe('打字确认不消耗票据（ADR-018 ③）', () => {
  test('敲错一次仍是同一张票：改对了还能落库，不是"重来一遍"', async () => {
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({ cidr: '203.0.113.0/24', reason: 't', operatorIp });
    const wrong = await ban.applyBan({ token: req.token, typedConfirm: '203.0.114.0/24' });
    expect(wrong).toMatchObject({ ok: false, reason: 'typed_confirmation_required' });
    const right = await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' });
    expect(right.ok).toBe(true);
  });

  test('对照：落库成功后同一张票立刻作废（一次性语义不能被"不消耗"放宽）', async () => {
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({ cidr: '203.0.113.0/24', reason: 't', operatorIp });
    const done = await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' });
    expect(done.ok).toBe(true);
    const replay = await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' });
    expect(replay).toMatchObject({ ok: false, reason: 'unknown_token' });
  });
});

describe('落库结果必须如实上报（addToBlacklist 从不抛错）', () => {
  test('落库失败不得被记成成功（否则运维以为封了）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(undefined); // 生产里 upsert 抛错由上层捕获，返回空
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const r = await ban.applyBan({
      token: req.token,
      typedConfirm: '203.0.113.0/24',
    });
    expect(r.bannedCount).toBe(0);
    expect(r.results[0]).toMatchObject({ banned: false, reason: null });
    expect(ban.getPoolBanStats().applied).toBe(0);
    expect(ban.getPoolBanStats().failedEntries).toBe(1);
  });

  test('成功落库才计 applied 并写审计（recordDurably 带 ip_list_change 检索标识）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const r = await ban.applyBan({
      token: req.token,
      typedConfirm: '203.0.113.0/24',
    });
    expect(r.bannedCount).toBe(1);
    expect(ban.getPoolBanStats().applied).toBe(1);
    expect(recordDurably).toHaveBeenCalledTimes(1);
    expect(recordDurably.mock.calls[0][0]).toMatchObject({
      action: 'ip_blacklist_added',
      category: 'security',
      success: true,
    });
    expect(recordDurably.mock.calls[0][1]).toMatchObject({ auditAction: 'ip_list_change' });
  });

  test('审计 DB 失败但 WAL 可用（recordDurably 契约 resolve null）⇒ 响应仍 ok 且不回滚', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const blockSpy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    recordDurably.mockResolvedValueOnce(null); // auditOutbox 契约：DB 失败、已转 WAL ⇒ resolve null
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const r = await ban.applyBan({
      token: req.token,
      typedConfirm: '203.0.113.0/24',
    });
    expect(r.ok).toBe(true);
    expect(r.bannedCount).toBe(1);
    expect(blockSpy).toHaveBeenCalledTimes(1); // 封禁不回滚
    // 本地诊断面如实记"未直写 DB"：这是补偿已发生的唯一进程内留痕
    expect(ban.getPoolBanStats().lastErrors).toHaveLength(1);
    expect(ban.getPoolBanStats().lastErrors[0]).toMatchObject({ action: 'ip_blacklist_added' });
  });

  test('审计 WAL 不可用 ⇒ recordDurably 的 rejection 原样重抛（不假装记账成功）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    recordDurably.mockRejectedValueOnce(new Error('mongo down'));
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    await expect(
      ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' })
    ).rejects.toThrow('mongo down');
    expect(ban.getPoolBanStats().lastErrors).toHaveLength(1);
    expect(ban.getPoolBanStats().lastErrors[0].error).toContain('mongo down');
  });

  test('lastErrors 是上限 5 的数组：连环失败每条都留（action/timestamp），不再被后写覆盖', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    recordDurably.mockRejectedValue(new Error(`boom-${Date.now()}`));
    for (let i = 0; i < 7; i += 1) {
      const cidr = `198.51.100.${i * 4}/26`; // 每次独占网段（/26 恒不需打字确认），互不借夹具
      const req = await ban.requestBan({
        cidr,
        reason: 't',
        operator: 'a',
        operatorIp,
      });
      expect(req.ok).toBe(true);
      await expect(ban.applyBan({ token: req.token, typedConfirm: cidr })).rejects.toThrow();
    }
    const errors = ban.getPoolBanStats().lastErrors;
    expect(errors).toHaveLength(5);
    for (const e of errors) {
      expect(e.action).toBe('ip_blacklist_added');
      expect(e.timestamp).toBeTruthy();
      expect(e.error).toContain('boom-');
    }
  });
});

describe('审计归因（B1/B3）：操作者身份与请求上下文必须落到审计行', () => {
  const realId = new mongoose.Types.ObjectId();
  const fixtureReq = (id) => ({
    method: 'POST',
    originalUrl: '/api/forensic/pool-ban/confirm',
    url: '/api/forensic/pool-ban/confirm',
    headers: { 'user-agent': 'jest-agent' },
    get: (k) => ({ 'user-agent': 'jest-agent' })[k.toLowerCase()],
    socket: { remoteAddress: '198.51.100.9' },
    ip: '198.51.100.9',
    user: { userId: id, username: '段管-张三', sessionId: 'sess-1' },
  });

  test('userId=真实 ObjectId、username=票据里的用户名（不再是 24 位 ObjectId 串）、ip/clientInfo 在场', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: realId,
      operatorUsername: '段管-张三',
      operatorIp,
    });
    await ban.applyBan({
      token: req.token,
      typedConfirm: '203.0.113.0/24',
      req: fixtureReq(realId),
    });
    const entry = recordDurably.mock.calls[0][0];
    expect(entry.userId).toEqual(realId);
    expect(entry.username).toBe('段管-张三');
    expect(entry.username).not.toMatch(/^[0-9a-f]{24}$/i);
    expect(entry).toMatchObject({
      method: 'POST',
      path: '/api/forensic/pool-ban/confirm',
      sessionId: 'sess-1',
    });
    expect(entry.ip).toBeTruthy();
    expect(entry.clientInfo).toBeTruthy();
    expect(typeof entry.fingerprint).toBe('string');
    expect(entry.userAgent).toBe('jest-agent');
  });

  test('旧口径回归：operator 传可读名（非 ObjectId）时不得让审计行 cast 崩溃（userId 缺席、名字落 username）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'probe-op', // 服务层直调的历史形态
      operatorIp,
    });
    await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24' });
    const entry = recordDurably.mock.calls[0][0];
    expect(entry.userId).toBeUndefined();
    expect(entry.username).toBe('probe-op');
  });
});

describe('自动封禁：不存在自动分支，只出票不自批', () => {
  test('任何调用方都无法通过参数绕过人工确认：banRecommended 只返回票据，绝不落库', async () => {
    const spy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const r = await ban.banRecommended({
      clusters: [
        {
          segment: '203.0.113',
          cidr: '203.0.113.0/24',
          verdict: 'rotate_pool',
          recommendBan: true,
        },
      ],
      operator: 'system',
      operatorIp,
    });
    expect(r.ok).toBe(true);
    // 关键不变量：出票 ≠ 生效。自动路径一旦能直接 apply，误封半径就是整栋楼。
    expect(spy).not.toHaveBeenCalled();
    expect(r.requested.every((x) => typeof x.token === 'string' && x.token.length > 0)).toBe(true);
  });

  test('旧形态（传 auto:true）不再有任何特权：与不传等价，仍然只出票', async () => {
    const spy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const r = await ban.banRecommended({
      clusters: [
        {
          segment: '203.0.113',
          cidr: '203.0.113.0/24',
          verdict: 'rotate_pool',
          recommendBan: true,
        },
      ],
      operator: 'system',
      operatorIp,
      auto: true, // 已移除的开关：传了也不得生效（没有开关可误开）
    });
    expect(r.ok).toBe(true);
    expect(spy).not.toHaveBeenCalled();
  });

  test('显式开启后，共享出口仍不得自动封（自动只认 rotate_pool）', async () => {
    process.env.IP_POOL_BAN_ALLOW_AUTO = 'true';
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    const r = await ban.banRecommended({
      clusters: [
        {
          segment: '203.0.113',
          cidr: '203.0.113.0/24',
          verdict: 'rotate_pool',
          recommendBan: true,
        },
        // 故意让共享出口自称 recommendBan=true：只靠 recommendBan 过滤是挡不住的，
        // 必须由 verdict 这一层拦住，否则这条用例根本测不到 verdict 判据（变异实测会存活）
        {
          segment: '198.51.100',
          cidr: '198.51.100.0/24',
          verdict: 'shared_egress',
          recommendBan: true,
        },
      ],
      operator: 'system',
      reason: 'auto',
      auto: true,
    });
    expect(r.requested.map((x) => x.cidr)).toEqual(['203.0.113.0/24']);
    expect(ban.getPoolBanStats().requests).toBe(1); // 共享出口连"待确认"都不该生成
  });

  test('没有候选 ⇒ 报「无候选」而不是空成功，且不借用拒绝原因码', async () => {
    const r = await ban.banRecommended({ clusters: [], operator: 'system', reason: 'x' });
    expect(r.ok).toBe(false);
    expect(r.empty).toBe(true);
    // reason 是**拒绝原因**字段，只认常量表里的码；「没有候选」不是拒绝，不许自造表外码
    expect(r.reason).toBeNull();
  });
});
