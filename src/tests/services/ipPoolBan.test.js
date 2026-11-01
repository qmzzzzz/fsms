/** T6-2 CIDR 封禁：默认人工确认；自动模式必须显式开启且只认轮换池。护栏宁可拒，不可误伤。 */
const ban = require('../../services/ipPoolBan');
const ipListService = require('../../services/ipListService');
const liveTraffic = require('../../services/ipPoolLiveTraffic');

const operatorIp = '10.0.0.5';
// 生产真实返回形状：IPBlacklist.blockIP ⇒ findOneAndUpdate 的落库文档，**没有** banned 字段
const BLOCKED_DOC = { _id: 'e1', ip: '203.0.113.0/24', type: 'black', reason: 't' };
// 注入审计模型：不注入会真的去打库，每个用例白等 10 秒缓冲超时
const auditStub = () => ({ create: jest.fn(async (doc) => doc) });

beforeEach(() => {
  ban.resetPoolBanState();
  jest.restoreAllMocks();
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
    ['unparsable_cidr', () => {}, () => ban.requestBan({ cidr: 'not-a-cidr', reason: 't', operatorIp })],
    ['full_range_cidr', () => {}, () => ban.requestBan({ cidr: '0.0.0.0/0', reason: 't', operatorIp })],
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
    ['operator_inside', () => {}, () => ban.requestBan({ cidr: '10.0.0.0/24', reason: 't', operatorIp })],
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
      jest.spyOn(liveTraffic, 'segmentHasLiveTraffic').mockResolvedValue({ live: false, scanned: 0 });
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
          ban.applyBan({ token: await ticketFor('203.0.113.0/24'), now: new Date(Date.now() + 11 * 60 * 1000) }),
      ],
      ['typed_confirmation_required', async () => ban.applyBan({ token: await ticketFor('203.0.113.0/24') })],
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

describe('票据表的内存边界（TTL 只约束可用性，不约束占用）', () => {
  test('过期票据在下次出票时被清掉：pending 不随"申请了不确认"无限增长', async () => {
    const t0 = new Date('2026-01-01T00:00:00Z');
    for (let i = 0; i < 5; i += 1) {
      await ban.requestBan({
        cidr: '198.51.100.0/24',
        reason: 't',
        operator: 'a',
        operatorIp,
        now: t0,
      });
    }
    expect(ban.getPoolBanStats().pending).toBe(5);
    // 11 分钟后（> CONFIRM_TTL_MS）再出票：前 5 张已过期，必须被清掉，只剩新的 1 张
    const later = new Date(t0.getTime() + 11 * 60 * 1000);
    await ban.requestBan({
      cidr: '198.51.100.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
      now: later,
    });
    expect(ban.getPoolBanStats().pending).toBe(1);
  });

  test('总量封顶：超过 PENDING_MAX 时丢最早出票的，内存有界', async () => {
    const t0 = new Date('2026-01-01T00:00:00Z');
    const total = ban.PENDING_MAX + 3;
    for (let i = 0; i < total; i += 1) {
      await ban.requestBan({
        cidr: '198.51.100.0/24',
        reason: 't',
        operator: 'a',
        operatorIp,
        now: t0,
      });
    }
    expect(ban.getPoolBanStats().pending).toBe(ban.PENDING_MAX);
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
    await ban.applyBan({ token: req.token, typedConfirm: typed, model: auditStub() });
    expect(spy.mock.calls[0][1].durationMs).toBe(24 * 60 * 60 * 1000);
  });

  test('显式 permanent ⇒ durationMs=0（IPBlacklist 里 0 才表示永久）', async () => {
    const spy = jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const req = await issue();
    await ban.applyBan({
      token: req.token,
      typedConfirm: typed,
      permanent: true,
      model: auditStub(),
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
      model: auditStub(),
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
    expect((await ban.applyBan({ token: 'bogus', model: auditStub() })).reason).toBe(
      'unknown_token'
    );
    const expired = await ban.applyBan({
      token: req.token,
      now: new Date(req.expiresAt.getTime() + 1000),
      model: auditStub(),
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
    expect(
      (await ban.applyBan({ token: req.token, typedConfirm: '203.0.113.0/24', model: auditStub() }))
        .ok
    ).toBe(true);
    expect((await ban.applyBan({ token: req.token, model: auditStub() })).reason).toBe(
      'unknown_token'
    );
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
      model: auditStub(),
    });
    expect(r.bannedCount).toBe(0);
    expect(r.results[0]).toMatchObject({ banned: false, reason: null });
    expect(ban.getPoolBanStats().applied).toBe(0);
    expect(ban.getPoolBanStats().failedEntries).toBe(1);
  });

  test('成功落库才计 applied 并写审计', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const auditModel = auditStub();
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const r = await ban.applyBan({
      token: req.token,
      typedConfirm: '203.0.113.0/24',
      model: auditModel,
    });
    expect(r.bannedCount).toBe(1);
    expect(ban.getPoolBanStats().applied).toBe(1);
    expect(auditModel.create).toHaveBeenCalledTimes(1);
    expect(auditModel.create.mock.calls[0][0]).toMatchObject({
      action: 'ip_blacklist_added',
      category: 'security',
      success: true,
    });
  });

  test('审计写失败不得让封禁回滚或抛（封禁已生效，追溯性受损但要留痕）', async () => {
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
    jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
    const auditModel = {
      create: jest.fn(async () => {
        throw new Error('mongo down');
      }),
    };
    const req = await ban.requestBan({
      cidr: '203.0.113.0/24',
      reason: 't',
      operator: 'a',
      operatorIp,
    });
    const r = await ban.applyBan({
      token: req.token,
      typedConfirm: '203.0.113.0/24',
      model: auditModel,
    });
    expect(r.ok).toBe(true);
    expect(r.bannedCount).toBe(1);
    expect(ban.getPoolBanStats().lastError).toContain('mongo down');
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
