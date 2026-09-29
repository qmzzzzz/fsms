/**
 * 自动封禁阶梯与批量导出阈值的两处边界（services/securityAlert.js）
 *
 * 缺陷一（阶梯只有第一档能用）：渐进式封禁用
 *   IPBlacklist.countDocuments({ ip, source:'auto', createdAt >= 30 天前 })
 * 来数"这是第几次封禁"。但 ipblacklist 上 (ip,type) 是唯一索引（models/IPBlacklist.js:92），
 * blockIP 走 findOneAndUpdate + $setOnInsert:createdAt（:266），TTL 索引（:89）到期即删档
 * ⇒ 同一 IP 任何时刻最多只剩一条 ⇒ 计数恒 ≤1，且封禁到期后归零：
 * 第三/四档（24 小时、7 天）永不可达，而 logger.warn 照打"第 N 次"——
 * 运维从日志上看到的是一个根本不存在的防线。
 * 修法：事件源换成 append-only 的审计（每条"触发暴力破解"的检测都会写一条该审计，
 * 而**封禁本身可能不落地**——见 F-160：白名单命中/地址解析失败/写库失败三种情况下
 * 一条黑名单记录都没有，阶梯仍按"检测次数"升档，这是 by design，日志必须说清没封成）。
 *
 * 缺陷二（阈值差一）：checkBulkExport 用 `count <= 100` 提前返回，即"必须 >100 才告警"，
 * 而同文件的另两个检测器都是 `>=`。恰好每次导出 100 行的内部人员永久静默。
 *
 * 判据分工：
 * 1. 端到端驱动 checkBruteForce 四次 ⇒ 时长必须是 1h/4h/24h/7d（旧实现四次全是 1h）；
 *    用不同 username 绕开 5 分钟 IP 频控（闸是"任一 key 放行即继续"的 OR 语义）；
 * 2. 反向对照：全新 IP 必须仍是第一档，否则"一律拉到最高档"也能让第 1 条绿；
 * 3. 归一化共用：::ffff:x 与 x 必须落在同一条阶梯上（否则计数恒 0，等于没有阶梯）；
 * 4. 统计抛错时封禁照做、按第一档（不能"统计失败就干脆不封"）；
 * 5. 窗口/留存下限的常量不变量：30 天窗口押在"审计至少留 30 天"上，没有运行期兜底，
 *    所以由用例盯住 MIN_RETENTION_DAYS ≥ 窗口（谁改坏这前提谁红）；
 * 6. 导出阈值 100 与 99 各一条，配"没告警"的负向断言；
 * 7. F-160：封禁成功与否只能由 addToBlacklist 的返回值决定（它从不抛错），
 *    四类返回形态（成功/白名单/写库失败/契约漂移）各自钉住"成功行不许出现"。
 */

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const {
  checkBruteForce,
  checkBulkExport,
  IPBanEvents,
  ESCALATION_TIERS,
  BAN_ESCALATION_WINDOW_MS,
  ALERT_TYPES,
  THRESHOLDS,
} = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');
const security = require('../../middleware/security');

const HOUR = 60 * 60 * 1000;
const stamp = Date.now().toString().slice(-7);
const targetIp = `203.0.113.${(Number(stamp) % 200) + 10}`;
const FRESH_IP = '198.51.100.77';
const ERR_IP = '192.0.2.44';
const MAP_IP = '192.0.2.88';

const originalAdd = security.addToBlacklist;
let captured;
// F-160：addToBlacklist 的返回值就是"到底封成没有"的唯一事实源，逐条用例改写它
let banResult;
const BAN_OK_IPS = ['192.0.2.211', '192.0.2.212', '192.0.2.213', '192.0.2.214'];
// AuditLog 有 append-only 护栏（models/auditLogHooks.js:135），清理只能走测试专用旁路
const purge = (filter) => AuditLog.deleteMany(filter, { bypassAppendOnly: true });

/**
 * 把一条阶梯的起点钉死为 0，并**自证**清空成功。
 *
 * 阶梯计数来自「30 天窗口内 action=暴力破解告警、ip=归一化 IP 的审计行条数」，
 * 于是"第 N 档"这个期望值押的是"这条链上恰好有 N-1 条前序事件"。原文件把这条前提
 * 写成了一条**有序用例**：端到端那条先跑满 5 次，归一化那条的注释里直接写着
 * "前面已触发过 5 次"。`--randomize --seed=20260917` 下两条同时红，且红法互相印证
 * ——归一化那条拿到第一档 1h，端到端那条因为被它先塞了一发而从第 2 档起跳。
 * 起点搬进用例自己之后，既顺序无关，也不再受上一轮崩溃残留影响。
 */
const startChainAtZero = async (ip) => {
  await purge({ action: ALERT_TYPES.BRUTE_FORCE, ip: { $in: [ip, `::ffff:${ip}`] } });
  expect(await IPBanEvents.countPrior(ip)).toBe(0);
};

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  security.addToBlacklist = jest.fn(async (ip, durationMs, reason, source) => {
    captured.push({ ip, durationMs, reason, source });
    return banResult;
  });
});
afterAll(async () => {
  security.addToBlacklist = originalAdd;
  await purge({ username: /^zz(bf|be)/ });
  await purge({
    ip: {
      $in: [
        targetIp,
        FRESH_IP,
        ERR_IP,
        MAP_IP,
        ...BAN_OK_IPS,
        `::ffff:${targetIp}`,
        `::ffff:${MAP_IP}`,
      ],
    },
  });
  if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
});
beforeEach(() => {
  captured = [];
  banResult = { banned: true, normalizedIp: '192.0.2.211' };
});

/** 让 username 维度达到阈值：同一用户名在 5 分钟窗口内塞 bruteForceAttempts 条失败 */
const seedFailures = async (username, ip) => {
  const rows = [];
  for (let i = 0; i < THRESHOLDS.bruteForceAttempts; i += 1) {
    rows.push({
      action: 'login_failed',
      category: 'auth',
      username,
      ip,
      success: false,
      riskLevel: 'low',
      timestamp: new Date(),
    });
  }
  await AuditLog.insertMany(rows);
};

describe('自动封禁阶梯：四档都必须可达', () => {
  test('端到端：同一 IP 连续四次触发 ⇒ 1h/4h/24h/7d，第五次仍封顶 7d', async () => {
    await startChainAtZero(targetIp);
    for (let round = 1; round <= 5; round += 1) {
      await seedFailures(`zzbf${round}_${stamp}`, targetIp);
      await checkBruteForce(`zzbf${round}_${stamp}`, targetIp);
    }
    expect(captured).toHaveLength(5);
    expect(captured.map((c) => c.durationMs)).toEqual([
      1 * HOUR,
      4 * HOUR,
      24 * HOUR,
      7 * 24 * HOUR,
      7 * 24 * HOUR,
    ]);
    expect(captured.map((c) => c.reason)).toEqual([
      'brute_force_auto_ban_tier1',
      'brute_force_auto_ban_tier2',
      'brute_force_auto_ban_tier3',
      'brute_force_auto_ban_tier4',
      'brute_force_auto_ban_tier4',
    ]);
    // 入库形态必须是归一化 IP + source=auto（否则下一次统计对不上）
    expect(captured.every((c) => c.ip === targetIp && c.source === 'auto')).toBe(true);
  }, 30000);

  test('反向对照：全新的 IP 仍是第一档（判据不是"一律拉到最高"）', async () => {
    await startChainAtZero(FRESH_IP);
    await seedFailures(`zzbffresh_${stamp}`, FRESH_IP);
    await checkBruteForce(`zzbffresh_${stamp}`, FRESH_IP);
    expect(captured).toHaveLength(1);
    expect(captured[0].durationMs).toBe(1 * HOUR);
  }, 20000);

  test('归一化共用阶梯：::ffff:x 与 x 记在同一条链上', async () => {
    // 只测**查询侧**：链上的历史事件按归一化 IP 存着，触发请求是 ::ffff: 形态。
    // 起点自建自证（原先靠"端到端那条先跑满 5 次"，等于把前置状态写成一条有序用例）；
    // 写入侧的归一化由下一条用例端到端覆盖，两条各管一侧，互不借对方的中间态。
    // 4 条夹具行带 body.ipAttempts=5（与真实落库行同构）：countPrior 过滤
    // 「IP 维度未达标的告警行」后这些行必须仍在链上（R-H2 阶梯质量闸的回归面）。
    await startChainAtZero(targetIp);
    await AuditLog.insertMany(
      [0, 1, 2, 3].map(() => ({
        action: ALERT_TYPES.BRUTE_FORCE,
        category: 'auth',
        username: `zzbfv6seed_${stamp}`,
        ip: targetIp,
        success: false,
        riskLevel: 'low',
        body: {
          userAttempts: THRESHOLDS.bruteForceAttempts,
          ipAttempts: THRESHOLDS.bruteForceAttempts,
          window: '5 分钟',
        },
        timestamp: new Date(),
      }))
    );
    expect(await IPBanEvents.countPrior(targetIp)).toBe(4);

    await seedFailures(`zzbfv6_${stamp}`, `::ffff:${targetIp}`);
    await checkBruteForce(`zzbfv6_${stamp}`, `::ffff:${targetIp}`);
    expect(captured).toHaveLength(1);
    // 4 条前序 ⇒ 第 5 次落到封顶档；::ffff: 若另起一条链，这里会是第一档 1h
    expect(captured[0].durationMs).toBe(7 * 24 * HOUR);
    expect(captured[0].ip).toBe(targetIp);
  }, 20000);

  test('阶梯必须双向串起来：先 ::ffff:x 触发、后 x 触发要升档（审计写入侧也得是归一化 IP）', async () => {
    // 上一条测的是"查询侧归一化"；这一条测"写入侧归一化"。只修一侧的话，
    // 攻击者交替使用两种形态即可让计数恒为 0，阶梯照样只剩第一档。
    await startChainAtZero(MAP_IP);
    const v6form = `::ffff:${MAP_IP}`;
    await seedFailures(`zzbfmap1_${stamp}`, v6form);
    await checkBruteForce(`zzbfmap1_${stamp}`, v6form);
    expect(captured.map((c) => c.durationMs)).toEqual([1 * HOUR]);

    captured.length = 0;
    await seedFailures(`zzbfmap2_${stamp}`, MAP_IP);
    await checkBruteForce(`zzbfmap2_${stamp}`, MAP_IP);
    expect(captured.map((c) => c.durationMs)).toEqual([4 * HOUR]);
    expect(captured[0].reason).toBe('brute_force_auto_ban_tier2');
  }, 20000);

  test('统计失败 ⇒ 按第一档照封，而不是跳过封禁', async () => {
    // 只坏阶梯的计数：checkBruteForce 开头的失败次数统计必须照常工作，
    // 否则这条测的是"整个函数抛异常"而不是"阶梯降级"
    await seedFailures(`zzbferr_${stamp}`, ERR_IP);
    const spy = jest.spyOn(IPBanEvents, 'countPrior').mockRejectedValue(new Error('db down'));
    try {
      await checkBruteForce(`zzbferr_${stamp}`, ERR_IP);
    } finally {
      spy.mockRestore();
    }
    const ban = captured.find((c) => c.ip === ERR_IP);
    expect(ban).toBeTruthy();
    expect(ban.durationMs).toBe(1 * HOUR);
  }, 20000);

  test('窗口与留存下限的不变量：窗口 30 天，审计至少得留到 30 天', () => {
    // 阶梯窗口的可靠性完全押在"countPrior 查得到的审计，至少活 30 天"上。
    // securityAlert.js 里没有运行期 Math.min 兜底（MIN_RETENTION_DAYS=90 时它是死分支），
    // 所以这条用例就是唯一的那道闸：谁拉长窗口、或把留存下限调到窗口以下，这里红。
    const { MIN_RETENTION_DAYS } = require('../../constants/retention');
    expect(BAN_ESCALATION_WINDOW_MS).toBe(30 * 24 * HOUR);
    expect(IPBanEvents.windowMs()).toBe(BAN_ESCALATION_WINDOW_MS);
    expect(MIN_RETENTION_DAYS * 24 * HOUR).toBeGreaterThanOrEqual(BAN_ESCALATION_WINDOW_MS);
    expect(ESCALATION_TIERS).toHaveLength(4);
    expect(IPBanEvents.tierFor(-5)).toBe(0);
    expect(IPBanEvents.tierFor(99)).toBe(ESCALATION_TIERS.length - 1);
  });
});

describe('F-160 封禁结果按返回值分派：日志不能说"已封禁"而黑名单里什么都没有', () => {
  // 缺陷：middleware/security.js 的 addToBlacklist 把三类失败全在自己内部 catch/return
  // （地址解析失败、白名单命中、blockIP 抛错），**从不向调用方抛异常**。
  // 于是 securityAlert 原先"await 正常返回 = 封禁成功"，无条件打
  // 「渐进式封禁 IP x：第 N 次，封禁 X 小时」——三种情况下黑名单里一条记录都没有，
  // 运维读到"已封 7 天"以为攻击者被挡住，实际该 IP 还在自由撞库（纸面防线）。
  // 而外层那个 `catch (e) { 自动封禁 IP 失败 }` 对封禁失败本身是不可达的死分支。
  const logger = require('../../utils/logger');
  const OK_LINE = '渐进式封禁';
  const BAD_LINE = '自动封禁未生效';
  let warnSpy;
  let errSpy;
  beforeEach(() => {
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    warnSpy.mockRestore();
    errSpy.mockRestore();
  });
  const texts = (spy) => spy.mock.calls.map((c) => String(c[0]));
  const hit = (spy, needle) => texts(spy).some((t) => t.includes(needle));

  /** 一次独立的触发：用户名与 IP 都必须唯一，否则被 5 分钟告警频控吃掉 */
  const trigger = async (n, ip) => {
    const username = `zzbf_f160_${n}_${stamp}`;
    await seedFailures(username, ip);
    await checkBruteForce(username, ip);
  };

  test('封禁成功 ⇒ 只打成功行，不打失败行', async () => {
    banResult = { banned: true, normalizedIp: BAN_OK_IPS[0] };
    await trigger('ok', BAN_OK_IPS[0]);
    expect(hit(warnSpy, OK_LINE)).toBe(true);
    expect(hit(errSpy, BAD_LINE)).toBe(false);
  }, 20000);

  test('白名单命中（零记录落库）⇒ 不得打成功行，且必须点名 whitelisted', async () => {
    banResult = { banned: false, reason: 'whitelisted' };
    await trigger('wl', BAN_OK_IPS[1]);
    expect(hit(warnSpy, OK_LINE)).toBe(false);
    expect(hit(errSpy, BAD_LINE)).toBe(true);
    // 理由必须原样传出来：运维据此区分"设计如此（白名单）"与"防线坏了（写库失败）"
    expect(texts(errSpy).join('\n')).toContain('whitelisted');
    expect(texts(errSpy).join('\n')).toContain(BAN_OK_IPS[1]);
  }, 20000);

  test('黑名单写库失败 ⇒ 同样不得打成功行，且给出可执行的前置动作', async () => {
    banResult = { banned: false, reason: 'persist_failed' };
    await trigger('pf', BAN_OK_IPS[2]);
    expect(hit(warnSpy, OK_LINE)).toBe(false);
    expect(hit(errSpy, BAD_LINE)).toBe(true);
    expect(texts(errSpy).join('\n')).toContain('persist_failed');
    expect(texts(errSpy).join('\n')).toContain('人工封禁');
  }, 20000);

  test('契约漂移（addToBlacklist 返回 undefined）⇒ fail-closed，按"未生效"记', async () => {
    // 这一条钉的是方向：调用方**不得**把"没有答案"读成"成功"。
    // 若哪天有人把分派写成 `if (!result || result.banned !== false)`，前四条照绿、这条红。
    banResult = undefined;
    await trigger('drift', BAN_OK_IPS[3]);
    expect(hit(warnSpy, OK_LINE)).toBe(false);
    expect(hit(errSpy, BAD_LINE)).toBe(true);
    expect(texts(errSpy).join('\n')).toContain('no_result');
  }, 20000);

  test('生产端契约：真实 addToBlacklist 对不可解析地址返回 {banned:false, reason:unparsable_ip}', async () => {
    // 前面四条测的是消费端；这一条测生产端真的每个出口都带状态（跑真实实现，不跑 mock）。
    // 不可解析地址在 require 模型之后就早退，不写库、不需要真数据。
    const r = await originalAdd('这不是一个 IP', 1000, 'zz_f160', 'auto');
    expect(r).toMatchObject({ banned: false, reason: 'unparsable_ip' });
  });

  test('写法门禁：成功日志必须在 banned 判定之后，不许无条件打', () => {
    // 行为四条 + 这条文本闸：文本闸不是替代，它钉的是"别再退回 await 即成功"这个写法。
    const src = fs.readFileSync(
      path.join(__dirname, '..', '..', 'services', 'securityAlert.js'),
      'utf8'
    );
    const from = src.indexOf('await addToBlacklist(');
    expect(from).toBeGreaterThan(-1);
    const window = src.slice(from, src.indexOf('} catch', from));
    // 抽取自证：窗口里必须真的同时有判定与成功日志（缺一个则 indexOf=-1，比较必红）
    const gate = window.indexOf('.banned');
    const okLog = window.indexOf('渐进式封禁');
    expect(gate).toBeGreaterThan(-1);
    expect(okLog).toBeGreaterThan(-1);
    expect(gate).toBeLessThan(okLog);
  });
});

describe('批量导出阈值：含边界的 >= 语义', () => {
  test('恰好等于阈值必须告警，比阈值小一条不许告警', async () => {
    // userId 走 schema 的 ObjectId 关联（传字符串会被 cast 成 ValidationError，
    // 而 P1-23 之后这个错是被 catch 掉的 ⇒ 用例假绿），所以两个样本各给一个真 ObjectId；
    // 频控 key 含 userId，必须不同，否则第二条被"5 分钟内不重复告警"吃掉
    const atUser = new mongoose.Types.ObjectId();
    const belowUser = new mongoose.Types.ObjectId();
    const at = `zzbe_at_${stamp}`;
    const below = `zzbe_below_${stamp}`;
    await checkBulkExport(String(atUser), at, THRESHOLDS.bulkExportThreshold, 'export_devices');
    await checkBulkExport(
      String(belowUser),
      below,
      THRESHOLDS.bulkExportThreshold - 1,
      'export_devices'
    );

    expect(await AuditLog.countDocuments({ action: ALERT_TYPES.BULK_EXPORT, username: at })).toBe(
      1
    );
    expect(
      await AuditLog.countDocuments({ action: ALERT_TYPES.BULK_EXPORT, username: below })
    ).toBe(0);
  }, 20000);
});
