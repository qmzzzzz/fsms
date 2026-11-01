/**
 * honeypotChainWatch：蜜罐事件链（L1）的聚合判据、每业务日一次升级、审计与告警契约。
 *
 * 钉住的核心契约：
 *  - 阶段表与标签表键集相等，且四个阶段在 src/ 里都确有写入方（不是凭空造的查询令牌）；
 *  - 单阶段重复 N 次**不算**链（那是各检测器自己的频控口径）；跨 ≥2 个阶段才升级；
 *  - 同一条链（同一 IP、同一业务日）只升级一次：去重凭据是审计行本身，跨轮/跨重启成立；
 *  - 归一化在合并之前：::ffff:1.2.3.4 与 1.2.3.4 必须并成同一条链；
 *  - 缺 IP 的行不参与（否则所有「来源不明」的攻击者会被并成一条链 = 制造假告警）；
 *  - 归一化不通过的**文本**也不成键（同 forensicTrigger 口径），丢弃量从 unparsableSources 可见；
 *  - 单轮上限只限「升级」名额：当日已升级的来源先被剔出，尾部候选不会因前 50 名每轮重复占位而被饿死；
 *  - 业务日之外的行不算（窗口取 businessDayBounds，不是"最近 24 小时"）；
 *  - 审计写失败 ⇒ 本轮不投递（下一轮重试），错误经 errText 进 logger.error；
 *  - 成功读数与「最后一轮」读数：lastSuccessAt 只在**整轮跑完**时落，与 lastRunAt 配对即可判「上一轮到底跑没跑完」；
 *  - 连败判据按整轮：断在聚合之后的失败轮不抵消前面的连败（consecutiveFailures 的归零点在整轮末尾）；
 *  - 测试钩子 __resetForTest 逐键复位计数、在飞标志与间隔读数（不是 stop：定时器仍归 stop() 管）；
 *  - 生命周期：start/stop 幂等、间隔低于下限被抬升、getHealth 反映运行态与计数。
 */
const mongoose = require('mongoose');

const { scanWriteSites } = require('../helpers/auditWriteSites');

describe('honeypotChainWatch 蜜罐事件链聚合', () => {
  let AuditLog;
  let securityAlert;
  let chain;
  let logger;
  let dispatchSpy;
  let errorSpy;
  let infoSpy;
  let warnSpy;
  const base = 10 + (Date.now() % 200);
  let seq = 0;
  const nextIp = () => '198.18.' + base + '.' + ++seq; // 基准网段（RFC 2544）：与其它套件的夹具 IP 不重叠
  const auditIp = (ip) => ip;
  const dayWindow = () => require('../../constants/timezone').businessDateParts().dateStr;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
    securityAlert = require('../../services/securityAlert');
    logger = require('../../utils/logger');
    chain = require('../../services/honeypotChainWatch');
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ ip: /^198\.18\./ }).catch(() => {});
    await AuditLog.deleteMany({ username: { $in: ['chain_probe', 'noip_a', 'noip_b'] } }).catch(
      () => {}
    );
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    chain.__resetForTest(); // 计数是模块级累加器：不逐条复位，绝对值断言会被前序用例污染（随机顺序门禁下必现）
    dispatchSpy = jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    chain.stop();
    dispatchSpy.mockRestore();
    errorSpy.mockRestore();
    infoSpy.mockRestore();
    warnSpy.mockRestore();
    delete process.env.HONEYPOT_CHAIN_INTERVAL_MS;
  });

  const stage = (action, ip, extra) =>
    AuditLog.create({
      action,
      category: action === 'login_failed' ? 'auth' : 'security',
      username: 'chain_probe',
      ip: auditIp(ip),
      success: false,
      riskLevel: 'high',
      ...extra,
    });

  const escalations = (ip) => AuditLog.find({ action: 'honeypot_chain_escalated', ip }).lean();
  const chainDispatches = () =>
    dispatchSpy.mock.calls.filter(
      (c) => c[0] === securityAlert.ALERT_TYPES.HONEYPOT_CHAIN_ESCALATED
    );

  test('前提：阶段表与标签表键集相等，且四个阶段都确有写入方', () => {
    expect([...chain.STAGE_ACTIONS].sort()).toEqual(Object.keys(chain.STAGE_LABELS).sort());
    expect(chain.STAGE_ACTIONS).toHaveLength(4);
    expect(chain.CHAIN_MIN_STAGES).toBe(2);
    const written = new Set(scanWriteSites().written.keys());
    for (const action of chain.STAGE_ACTIONS) {
      expect({ action, hasWriter: written.has(action) }).toEqual({ action, hasWriter: true });
    }
  });

  test('单阶段重复不算链：同 IP 两条 login_failed 不升级、不投递', async () => {
    const ip = nextIp();
    await stage('login_failed', ip);
    await stage('login_failed', ip);
    await chain.runScan();
    expect(await escalations(ip)).toHaveLength(0);
    expect(chainDispatches()).toHaveLength(0);
  });

  test('跨两阶段：写一条升级审计并投递一次（字段与载荷契约）', async () => {
    const ip = nextIp();
    await stage('login_failed', ip);
    await stage('honeypot_login', ip);
    await chain.runScan();

    const rows = await escalations(ip);
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row.action).toBe('honeypot_chain_escalated');
    expect(row.category).toBe('security');
    expect(row.riskLevel).toBe('critical');
    expect(row.username).toBe('anonymous');
    expect(row.reason).toBe('honeypot_chain_escalated');
    expect(row.riskFactors).toEqual(
      expect.arrayContaining([
        'honeypot_chain_escalated',
        'deceptive_account_interaction',
        'chain_stage_login_failed',
        'chain_stage_honeypot_login',
      ])
    );
    expect(row.body.stages).toEqual(['honeypot_login', 'login_failed']);
    expect(row.body.events).toBe(2);
    expect(row.body.dayWindow).toBe(dayWindow());

    const calls = chainDispatches();
    expect(calls).toHaveLength(1);
    expect(calls[0][1]).toBe('critical');
    expect(calls[0][2]).toContain(ip);
    expect(calls[0][2]).toContain('诱饵口令命中');
    expect(calls[0][3]).toMatchObject({ ip, stages: ['honeypot_login', 'login_failed'] });
  });

  test('同一 IP 同一业务日只升级一次：第二轮不再写审计、不再投递', async () => {
    const ip = nextIp();
    await stage('login_failed', ip);
    await stage('honeypot_probe', ip);
    await chain.runScan();
    await chain.runScan();
    expect(await escalations(ip)).toHaveLength(1);
    expect(chainDispatches()).toHaveLength(1);
  });

  test('归一化在合并之前：::ffff: 与裸 IPv4 的两条阶段并成同一条链', async () => {
    const ip = nextIp();
    await stage('login_failed', '::ffff:' + ip);
    await stage('honeypot_probe', ip);
    await chain.runScan();
    expect(await escalations(ip)).toHaveLength(1); // 存的也是归一化后的形态
    expect(chainDispatches()).toHaveLength(1);
  });

  test('缺 IP 的行不参与：两条无 IP 的阶段不构成链', async () => {
    await AuditLog.create({
      action: 'login_failed',
      category: 'auth',
      username: 'noip_a',
      success: false,
    });
    await AuditLog.create({
      action: 'honeypot_probe',
      category: 'security',
      username: 'noip_b',
      ip: null,
      success: false,
    });
    await chain.runScan();
    expect(chainDispatches()).toHaveLength(0);
  });

  test('归一化不通过的文本不成链：不升级、不投递，丢弃量从 unparsableSources 可见', async () => {
    const before = chain.getHealth().unparsableSources;
    const junk = 'not-an-ip-' + Date.now();
    await stage('login_failed', junk);
    await stage('honeypot_login', junk);
    await chain.runScan();
    expect(await escalations(junk)).toHaveLength(0);
    expect(chainDispatches()).toHaveLength(0);
    expect(chain.getHealth().unparsableSources - before).toBeGreaterThanOrEqual(1);
  });

  test('单轮上限只限升级名额：当日已升级的不再占位，尾部候选在后续轮次被升（不再饿死）', async () => {
    const ips = [];
    for (let i = 0; i < 52; i += 1) ips.push(nextIp());
    for (let i = 0; i < ips.length; i += 1) {
      const ts = new Date(Date.now() - (ips.length - i) * 1000); // lastSeenAt 严格递增，尾部 = 最旧的两个
      await stage('login_failed', ips[i], { timestamp: ts });
      await stage('honeypot_login', ips[i], { timestamp: ts });
    }
    const before = chain.getHealth();
    await chain.runScan();
    const afterFirst = chain.getHealth();
    expect(afterFirst.droppedCandidates - before.droppedCandidates).toBeGreaterThanOrEqual(2);
    expect(afterFirst.lastPendingCandidates).toBeGreaterThanOrEqual(2);
    await chain.runScan();
    for (const ip of ips) expect(await escalations(ip)).toHaveLength(1);
    const afterSecond = chain.getHealth();
    expect(afterSecond.lastPendingCandidates).toBeLessThan(afterFirst.lastPendingCandidates); // pending 是"本轮开始时待升级数"：第二轮只剩被推迟的那两个
    expect(afterSecond.lastPendingCandidates).toBeLessThanOrEqual(2);
  });

  test('间隔上界：超过上限被压到 24h，面板读数等于定时器实际时长', () => {
    process.env.HONEYPOT_CHAIN_INTERVAL_MS = '3000000000';
    chain.start();
    expect(chain.getHealth().intervalMs).toBe(24 * 60 * 60 * 1000);
    expect(warnSpy.mock.calls.some((c) => String(c[0]).includes('高于最大间隔'))).toBe(true);
    chain.stop();
  });

  test('业务日窗口：昨天及更早的两条阶段今天不升级', async () => {
    const ip = nextIp();
    const old = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    await stage('login_failed', ip, { timestamp: old });
    await stage('honeypot_login', ip, { timestamp: old });
    await chain.runScan();
    expect(await escalations(ip)).toHaveLength(0);
    expect(chainDispatches()).toHaveLength(0);
  });

  test('审计写失败：本轮不投递（不制造按轮次的告警风暴），下一轮落库后才投递', async () => {
    const ip = nextIp();
    await stage('login_failed', ip);
    await stage('honeypot_login', ip);
    const before = chain.getHealth();
    const createSpy = jest.spyOn(AuditLog, 'create').mockRejectedValueOnce(new Error('disk full'));
    await expect(chain.runScan()).resolves.toBeUndefined();
    createSpy.mockRestore();
    expect(
      errorSpy.mock.calls.some((c) => String(c[0]).includes('蜜罐事件链升级审计写入失败'))
    ).toBe(true);
    expect(chain.getHealth().escalationFailures - before.escalationFailures).toBe(1);
    expect(chainDispatches()).toHaveLength(0);
    await chain.runScan();
    expect(await escalations(ip)).toHaveLength(1);
    expect(chainDispatches()).toHaveLength(1);
  });

  test('重叠守卫：上一轮未结束时本轮只记跳过、不并发压入', async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const aggSpy = jest.spyOn(AuditLog, 'aggregate').mockImplementation(() => gate);
    const before = chain.getHealth();
    const first = chain.runScan();
    await chain.runScan(); // 命中守卫：立即返回
    release([]);
    await first;
    aggSpy.mockRestore();
    const after = chain.getHealth();
    expect(after.skippedOverlaps - before.skippedOverlaps).toBe(1);
    expect(after.runs - before.runs).toBe(1);
  });

  test('成功/失败读数配对：lastSuccessAt 只在整轮跑完时落，失败轮只推失败侧', async () => {
    const failSpy = jest
      .spyOn(AuditLog, 'aggregate')
      .mockRejectedValueOnce(new Error('mongo down'));
    await chain.runScan();
    failSpy.mockRestore();
    const failed = chain.getHealth();
    expect(failed.failures).toBe(1);
    expect(failed.consecutiveFailures).toBe(1);
    expect(failed.lastRunAt).not.toBeNull();
    expect(failed.lastFailureAt).not.toBeNull();
    expect(failed.lastSuccessAt).toBeNull(); // 只跑了一半的轮次不得冒充成功读数

    await chain.runScan();
    const ok = chain.getHealth();
    expect(ok.consecutiveFailures).toBe(0);
    expect(ok.lastSuccessAt).not.toBeNull();
    expect(Date.parse(ok.lastSuccessAt)).toBeGreaterThanOrEqual(Date.parse(ok.lastRunAt)); // 两个读数配对：比较即可判「上一轮跑完了还是一半就断了」
  });

  test('连败判据按整轮：断在聚合之后的失败轮不抵消前面的连败（归零点在整轮末尾）', async () => {
    const aggSpy = jest
      .spyOn(AuditLog, 'aggregate')
      .mockRejectedValueOnce(new Error('aggregate down'));
    await chain.runScan();
    aggSpy.mockRestore();
    expect(chain.getHealth().consecutiveFailures).toBe(1);

    const distinctSpy = jest
      .spyOn(AuditLog, 'distinct')
      .mockRejectedValueOnce(new Error('distinct down'));
    await chain.runScan(); // 聚合成功、断在候选处理：旧实现（聚合后即归零）会把它记成 1，真相是连续第 2 轮失败
    distinctSpy.mockRestore();
    const after = chain.getHealth();
    expect(after.consecutiveFailures).toBe(2);
    expect(after.lastSuccessAt).toBeNull();
  });

  test('测试钩子：__resetForTest 把计数与「最后一轮」读数一并复位；定时器仍归 stop()', async () => {
    await chain.runScan();
    process.env.HONEYPOT_CHAIN_INTERVAL_MS = '1000';
    chain.start();
    const dirty = chain.getHealth();
    expect(dirty.runs).toBeGreaterThan(0);
    expect(dirty.lastRunAt).not.toBeNull();
    expect(dirty.intervalMs).toBe(60000);

    chain.__resetForTest();
    const clean = chain.getHealth();
    expect(clean.runs).toBe(0);
    expect(clean.failures).toBe(0);
    expect(clean.consecutiveFailures).toBe(0);
    expect(clean.skippedOverlaps).toBe(0);
    expect(clean.escalated).toBe(0);
    expect(clean.escalationFailures).toBe(0);
    expect(clean.unparsableSources).toBe(0);
    expect(clean.droppedCandidates).toBe(0);
    expect(clean.lastCandidates).toBe(0);
    expect(clean.lastPendingCandidates).toBe(0);
    expect(clean.lastRunAt).toBeNull();
    expect(clean.lastSuccessAt).toBeNull();
    expect(clean.lastEscalatedIp).toBeNull();
    expect(clean.lastFailureAt).toBeNull();
    expect(clean.lastFailureMessage).toBeNull();
    expect(clean.intervalMs).toBe(300000); // 上一条用例配的间隔不得泄漏到下一条的读数断言
    expect(clean.running).toBe(true); // 复位不关定时器：关停只有一个入口 stop()，否则钩子会制造「以为停了其实还在跑」
  });
  test('生命周期：start/stop 幂等；间隔低于下限被抬升；getHealth 反映运行态', () => {
    expect(chain.isRunning()).toBe(false);
    process.env.HONEYPOT_CHAIN_INTERVAL_MS = '1000';
    chain.start();
    chain.start();
    expect(chain.isRunning()).toBe(true);
    expect(chain.getHealth().intervalMs).toBe(60000); // 最小间隔（源码 MIN_INTERVAL_MS）
    expect(warnSpy.mock.calls.some((c) => String(c[0]).includes('低于最小间隔'))).toBe(true);
    expect(infoSpy.mock.calls.some((c) => String(c[0]).includes('蜜罐事件链巡检已启动'))).toBe(
      true
    );
    chain.stop();
    chain.stop();
    expect(chain.isRunning()).toBe(false);
    expect(chain.getHealth().running).toBe(false);
  });
});
