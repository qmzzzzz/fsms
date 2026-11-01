/**
 * 取证触发标记表（P1）行为用例：滑动续期 / TTL 到期 / 容量 LRU 淘汰 / 异常 fail-visible /
 * 归一化口径 / 三处 v1 钩子（ipBlacklist 主分支与降级分支、recordHoneypotLogin、
 * applyBruteForceIpBan 执行处）与「未标记面行为对拍」。
 *
 * 隔离策略：
 *  - 主实例用 env 默认值（TTL 30min / MAX 4096）；容量与开关用例在 jest.isolateModules
 *    里以独立 env 取一份新实例，断言精确到条数，不影响主实例。
 *  - 时间一律用 Date.now 的 spy 推进，不引入任何真实睡眠（noFixedSleepRatchet）。
 *  - 与标记无关的既有行为（白名单放行 / 降级 fail-open / 蜜罐记录与告警）逐条钉住：
 *    新增的钩子不得改变它们。
 */

jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(() => Promise.resolve(null)),
  create: jest.fn(() => Promise.resolve({ _id: 'audit-stub' })),
}));

const logger = require('../../utils/logger');
const forensicTrigger = require('../../services/forensicTrigger');
const IPBlacklist = require('../../models/IPBlacklist');
const ipBlacklistStore = require('../../middleware/security/ipBlacklistStore');
const {
  checkIPBlacklist,
  invalidateIPBlockCache,
} = require('../../middleware/security/ipBlacklist');
const securityAlert = require('../../services/securityAlert');
const honeypotWatch = require('../../services/honeypotWatch');
const { applyBruteForceIpBan, ESCALATION_TIERS } = require('../../services/securityAlertIpBans');
const AuditLog = require('../../models/AuditLog');

const stats = () => forensicTrigger.getForensicTriggerStats();
const lastMark = () => stats().lastMark;

// ---- 既有的请求/响应替身（形态与 securitySanitizeAndBlacklistDegrade 套件一致）----
const makeRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  res.send = jest.fn(() => res);
  res.headersSent = false;
  res.statusCode = undefined;
  res.status.mockImplementation((code) => {
    res.statusCode = code;
    return res;
  });
  res.setHeader = jest.fn(() => res);
  res.getHeader = jest.fn(() => undefined);
  return res;
};

const makeReq = (overrides = {}) => ({
  ip: '203.0.113.77', // TEST-NET-3 文档段：语义上表示外部请求，非内网
  connection: { remoteAddress: '203.0.113.77' },
  method: 'GET',
  path: '/api/devices',
  originalUrl: '/api/devices',
  params: {},
  query: {},
  body: {},
  headers: {},
  get: jest.fn(() => undefined),
  ...overrides,
});

const originalAddToBlacklist = ipBlacklistStore.addToBlacklist;

afterEach(() => {
  jest.restoreAllMocks();
  ipBlacklistStore.addToBlacklist = originalAddToBlacklist;
});

describe('P1 取证触发标记表：基本口径', () => {
  test('env 默认值生效：enabled=true、TTL 30 分钟、容量 4096', () => {
    const s = stats();
    expect(s.enabled).toBe(true);
    expect(s.ttlMs).toBe(30 * 60 * 1000);
    expect(s.maxIps).toBe(4096);
  });

  test('归一化口径：::ffff:x 与 x 同键；命中续期计入 renewals', () => {
    const s0 = stats();
    expect(
      forensicTrigger.markForensicTarget('::ffff:203.0.113.211', {
        reason: 'unit_test',
        source: 'forensicTrigger.test',
      })
    ).toBe(true);
    expect(forensicTrigger.isForensicTarget('203.0.113.211')).toBe(true);
    const s1 = stats();
    expect(s1.marks - s0.marks).toBe(1);
    expect(s1.renewals - s0.renewals).toBe(0);

    expect(
      forensicTrigger.markForensicTarget('203.0.113.211', {
        reason: 'unit_test',
        source: 'forensicTrigger.test',
      })
    ).toBe(true);
    const s2 = stats();
    expect(s2.renewals - s1.renewals).toBe(1);
    forensicTrigger.clearForensicTarget('203.0.113.211');
  });

  test('未识别/空 IP 一律 false，且拒绝计数可见', () => {
    const s0 = stats();
    for (const bad of ['', 'not-an-ip', undefined, null, 12345]) {
      expect(forensicTrigger.isForensicTarget(bad)).toBe(false);
    }
    expect(forensicTrigger.markForensicTarget(NaN, { reason: 'x', source: 'y' })).toBe(false);
    expect(forensicTrigger.clearForensicTarget({})).toBe(false);
    const s1 = stats();
    expect(s1.rejected - s0.rejected).toBe(7);
  });

  test('滑动续期：TTL 内再次命中，窗口随之后移（原到期点之后仍存活）', () => {
    const t0 = 1700000000000;
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(t0);
    forensicTrigger.markForensicTarget('203.0.113.212', {
      reason: 'unit',
      source: 'unit',
      ttlMs: 120000,
    });
    nowSpy.mockReturnValue(t0 + 90000);
    forensicTrigger.markForensicTarget('203.0.113.212', {
      reason: 'unit',
      source: 'unit',
      ttlMs: 120000,
    });
    nowSpy.mockReturnValue(t0 + 150000); // 原到期点(t0+120s)已过、续期后到期点(t0+210s)未到
    expect(forensicTrigger.isForensicTarget('203.0.113.212')).toBe(true);
    nowSpy.mockReturnValue(t0 + 210001);
    expect(forensicTrigger.isForensicTarget('203.0.113.212')).toBe(false);
    forensicTrigger.clearForensicTarget('203.0.113.212');
  });

  test('TTL 到期：过期即 false；过期后重标记按新标记计（不算续期）', () => {
    const t0 = 1700000100000;
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(t0);
    forensicTrigger.markForensicTarget('203.0.113.213', {
      reason: 'unit',
      source: 'unit',
      ttlMs: 60000,
    });
    nowSpy.mockReturnValue(t0 + 60001);
    expect(forensicTrigger.isForensicTarget('203.0.113.213')).toBe(false);
    const s0 = stats();
    expect(
      forensicTrigger.markForensicTarget('203.0.113.213', {
        reason: 'unit',
        source: 'unit',
        ttlMs: 60000,
      })
    ).toBe(true);
    const s1 = stats();
    expect(s1.marks - s0.marks).toBe(1);
    expect(s1.renewals - s0.renewals).toBe(0);
    forensicTrigger.clearForensicTarget('203.0.113.213');
  });

  test('clearForensicTarget：清除即失效；再次清除返回 false', () => {
    forensicTrigger.markForensicTarget('203.0.113.214', { reason: 'unit', source: 'unit' });
    expect(forensicTrigger.isForensicTarget('203.0.113.214')).toBe(true);
    expect(forensicTrigger.clearForensicTarget('203.0.113.214')).toBe(true);
    expect(forensicTrigger.isForensicTarget('203.0.113.214')).toBe(false);
    expect(forensicTrigger.clearForensicTarget('203.0.113.214')).toBe(false);
  });

  test('开关：仅精确 false 关闭（大小写/其他值不关）', () => {
    const prev = process.env.FORENSIC_TRIGGER_ENABLED;
    const fresh = (value) => {
      process.env.FORENSIC_TRIGGER_ENABLED = value;
      let ft;
      jest.isolateModules(() => {
        ft = require('../../services/forensicTrigger');
      });
      return ft;
    };
    const off = fresh('false');
    expect(off.getForensicTriggerStats().enabled).toBe(false);
    expect(off.markForensicTarget('203.0.113.215', { reason: 'x', source: 'y' })).toBe(false);
    expect(off.isForensicTarget('203.0.113.215')).toBe(false);
    const upper = fresh('FALSE');
    expect(upper.getForensicTriggerStats().enabled).toBe(true);
    if (prev === undefined) delete process.env.FORENSIC_TRIGGER_ENABLED;
    else process.env.FORENSIC_TRIGGER_ENABLED = prev;
  });

  test('容量 LRU 淘汰（独立实例 MAX=6）：逐条淘汰最久未标记者、续期可保护、绝不整体清空', () => {
    const prev = process.env.FORENSIC_TRIGGER_MAX_IPS;
    process.env.FORENSIC_TRIGGER_MAX_IPS = '6';
    let ft;
    jest.isolateModules(() => {
      ft = require('../../services/forensicTrigger');
    });
    if (prev === undefined) delete process.env.FORENSIC_TRIGGER_MAX_IPS;
    else process.env.FORENSIC_TRIGGER_MAX_IPS = prev;

    const t0 = 1700000200000;
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(t0);
    const mark = (n, opts = {}) =>
      ft.markForensicTarget('203.0.113.' + n, { reason: 'cap', source: 'unit', ...opts });
    for (let i = 220; i <= 225; i += 1) mark(i);

    nowSpy.mockReturnValue(t0 + 1000);
    mark(220); // 续期：最旧序号但最近被标记 —— LRU 不得先动它
    mark(226); // 第一次溢出：只淘汰最久未标记的一条（221）

    expect(ft.isForensicTarget('203.0.113.221')).toBe(false);
    expect(ft.isForensicTarget('203.0.113.222')).toBe(true);
    expect(ft.isForensicTarget('203.0.113.220')).toBe(true);
    expect(ft.getForensicTriggerStats().evictions).toBe(1);

    mark(227);
    mark(228); // 再淘汰两条：222、223
    expect(ft.isForensicTarget('203.0.113.222')).toBe(false);
    expect(ft.isForensicTarget('203.0.113.223')).toBe(false);
    // 不整体清空：多个原始条目仍在（220/224/225），而非全灭
    expect(ft.isForensicTarget('203.0.113.224')).toBe(true);
    expect(ft.isForensicTarget('203.0.113.225')).toBe(true);
    const s = ft.getForensicTriggerStats();
    expect(s.markedIps).toBe(6);
    expect(s.evictions).toBe(3);
    expect(s.lastEvictionAt).toBe(t0 + 1000);
  });

  test('异常 fail-visible：内部异常被吞掉、计数与 lastError 可见、绝不外抛', () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error('fault-injection: 读取 options 抛错');
        },
      }
    );
    const logSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    const s0 = stats();
    let threw = false;
    let result = null;
    try {
      result = forensicTrigger.markForensicTarget('203.0.113.240', hostile);
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(false);
    expect(result).toBe(false);
    const s1 = stats();
    expect(s1.failures - s0.failures).toBe(1);
    expect(s1.lastError).toContain('fault-injection');
    expect(s1.lastErrorAt).toBeGreaterThan(0);
    expect(forensicTrigger.isForensicTarget('203.0.113.240')).toBe(false);
    expect(logSpy.mock.calls.some((call) => String(call[0]).includes('取证标记表异常'))).toBe(true);
  });
});

describe('v1 钩子 a：ipBlacklist 命中分支', () => {
  test('主分支：黑名单命中 → 403 行为不变 + blacklist_hit 标记', async () => {
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
    jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
    jest.spyOn(securityAlert, 'shouldSendAlert').mockReturnValue(false);
    const req = makeReq({ ip: '198.51.100.41' });
    const res = makeRes();
    const next = jest.fn();

    await checkIPBlacklist(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(forensicTrigger.isForensicTarget('198.51.100.41')).toBe(true);
    expect(lastMark()).toMatchObject({
      ip: '198.51.100.41',
      reason: 'blacklist_hit',
      source: 'ipBlacklist',
    });
    invalidateIPBlockCache('198.51.100.41');
    forensicTrigger.clearForensicTarget('198.51.100.41');
  });

  test('降级缓存分支：DB 故障期命中缓存 → 403 + 同点标记（清掉后再标记可证）', async () => {
    const ip = '198.51.100.42';
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
    jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
    jest.spyOn(securityAlert, 'shouldSendAlert').mockReturnValue(false);
    await checkIPBlacklist(makeReq({ ip }), makeRes(), jest.fn());

    jest.restoreAllMocks();
    forensicTrigger.clearForensicTarget(ip); // 先清掉第一次的标记：第二次若再标记，只可能出自降级分支
    expect(forensicTrigger.isForensicTarget(ip)).toBe(false);

    jest.spyOn(IPBlacklist, 'isWhitelisted').mockRejectedValue(new Error('db down'));
    jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
    const res = makeRes();
    const next = jest.fn();
    await checkIPBlacklist(makeReq({ ip }), res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(forensicTrigger.isForensicTarget(ip)).toBe(true);
    expect(lastMark()).toMatchObject({ ip, reason: 'blacklist_hit', source: 'ipBlacklist' });
    invalidateIPBlockCache(ip);
    forensicTrigger.clearForensicTarget(ip);
  });

  test('未标记面行为对拍：白名单放行 / 降级未命中 fail-open —— 既有语义逐条不变', async () => {
    // ① 白名单放行：置豁免标记、放行、绝不标记
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(true);
    jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(false);
    const req1 = makeReq({ ip: '198.51.100.43' });
    const res1 = makeRes();
    const next1 = jest.fn();
    await checkIPBlacklist(req1, res1, next1);
    expect(next1).toHaveBeenCalledTimes(1);
    expect(req1.ipWhitelisted).toBe(true);
    expect(res1.statusCode).toBeUndefined();
    expect(forensicTrigger.isForensicTarget('198.51.100.43')).toBe(false);

    // ② DB 故障 + 缓存未命中：fail-open 放行（避免数据库抖动造成全站不可用），同样不标记
    jest.restoreAllMocks();
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockRejectedValue(new Error('db down'));
    jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
    const req2 = makeReq({ ip: '198.51.100.44' });
    const res2 = makeRes();
    const next2 = jest.fn();
    await checkIPBlacklist(req2, res2, next2);
    expect(next2).toHaveBeenCalledTimes(1);
    expect(res2.statusCode).toBeUndefined();
    expect(forensicTrigger.isForensicTarget('198.51.100.44')).toBe(false);
  });
});

describe('v1 钩子 b：honeypotWatch.recordHoneypotLogin', () => {
  const honeypotCtx = (ip) => ({
    username: 'zzforensic_trap',
    ip,
    userAgent: 'test-agent',
    fingerprint: 'fp-forensic',
    method: 'POST',
    path: '/api/auth/login',
  });

  test('记录后标记：审计照写 + honeypot_login 标记 + 通知受既有频控约束（未放行则不推）', async () => {
    jest.spyOn(securityAlert, 'shouldSendAlert').mockReturnValue(false);
    jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
    AuditLog.create.mockClear();

    await honeypotWatch.recordHoneypotLogin(honeypotCtx('198.51.100.45'));

    expect(AuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'honeypot_login', ip: '198.51.100.45' })
    );
    expect(forensicTrigger.isForensicTarget('198.51.100.45')).toBe(true);
    expect(lastMark()).toMatchObject({
      ip: '198.51.100.45',
      reason: 'honeypot_login',
      source: 'honeypotWatch',
    });
    expect(securityAlert.dispatchNotification).not.toHaveBeenCalled();
    forensicTrigger.clearForensicTarget('198.51.100.45');
  });

  test('标记失败（非法 IP）不改变记录行为：审计照写、不抛、拒绝计数可见', async () => {
    jest.spyOn(securityAlert, 'shouldSendAlert').mockReturnValue(false);
    jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
    AuditLog.create.mockClear();
    const s0 = stats();

    await expect(
      honeypotWatch.recordHoneypotLogin(honeypotCtx('not-an-ip'))
    ).resolves.toBeUndefined();

    expect(AuditLog.create).toHaveBeenCalledTimes(1);
    expect(forensicTrigger.isForensicTarget('not-an-ip')).toBe(false);
    expect(stats().rejected - s0.rejected).toBeGreaterThanOrEqual(1);
  });
});

describe('v1 钩子 c：securityAlertIpBans 实际封禁执行处', () => {
  test('banned=true：既有成功日志行为不变 + brute_force_auto_ban 标记', async () => {
    const ip = '198.51.100.46';
    ipBlacklistStore.addToBlacklist = jest.fn(async () => ({ banned: true }));
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});

    await applyBruteForceIpBan({ normalizedIp: ip, priorBans: 0, fallbackIp: ip });

    expect(ipBlacklistStore.addToBlacklist).toHaveBeenCalledWith(
      ip,
      ESCALATION_TIERS[0],
      'brute_force_auto_ban_tier1',
      'auto'
    );
    expect(warnSpy.mock.calls.some((call) => String(call[0]).includes('渐进式封禁'))).toBe(true);
    expect(forensicTrigger.isForensicTarget(ip)).toBe(true);
    expect(lastMark()).toMatchObject({
      ip,
      reason: 'brute_force_auto_ban',
      source: 'securityAlertIpBans',
    });
    forensicTrigger.clearForensicTarget(ip);
  });

  test('banned=false（白名单/写库失败）：标记仍建立（取证不随封禁成败丢失），错误行照打', async () => {
    const ip = '198.51.100.47';
    ipBlacklistStore.addToBlacklist = jest.fn(async () => ({
      banned: false,
      reason: 'whitelisted',
    }));
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});

    await applyBruteForceIpBan({ normalizedIp: ip, priorBans: 1, fallbackIp: ip });

    expect(errSpy.mock.calls.some((call) => String(call[0]).includes('whitelisted'))).toBe(true);
    expect(forensicTrigger.isForensicTarget(ip)).toBe(true);
    forensicTrigger.clearForensicTarget(ip);
  });

  test('封禁执行抛出时：标记已建立、异常仍被既有 catch 吞掉（绝不影响后续流程）', async () => {
    const ip = '198.51.100.48';
    ipBlacklistStore.addToBlacklist = jest.fn(async () => {
      throw new Error('fault-injection: addToBlacklist 抛错');
    });
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});

    await expect(
      applyBruteForceIpBan({ normalizedIp: ip, priorBans: 2, fallbackIp: ip })
    ).resolves.toBeUndefined();

    expect(errSpy.mock.calls.some((call) => String(call[0]).includes('自动封禁 IP 失败'))).toBe(
      true
    );
    expect(forensicTrigger.isForensicTarget(ip)).toBe(true);
    forensicTrigger.clearForensicTarget(ip);
  });
});
