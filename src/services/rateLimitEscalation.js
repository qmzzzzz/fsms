/**
 * 限流触发升级服务 · 信号分类与计数（CC 防护闭环）
 *
 * 解决的问题：此前限流「只挡不罚」——CC 攻击者把每个 IP 恰好压在阈值下，
 * 或轮换 IP 长期贴着 429 刷，除了一行 warn 日志不产生任何安全信号，更不会
 * 升级成封禁。本服务把 429 变成一等安全事件：达阈值 → 走与暴力破解同一条
 * 封禁阶梯（1h→4h→24h→7d）→ checkIPBlacklist 在限流之前 403 短路该 IP。
 *
 * ============================ 为什么要按信号分类 ============================
 * 2026-09-30 重构。此前全仓只有**一个**阀值（30 次/5 分钟），而喂进这个计数器的
 * 是 7 个限流器，它们的**合法拒绝率**相差两个数量级：
 *
 *   限流器        自身配额            一次"拒绝"证明该 IP 已经发了多少请求
 *   captcha       60 次/5 分钟        ≥ 60 次单端点请求
 *   register      10 次/5 分钟        ≥ 10 次注册尝试
 *   login-ip      10 次/15 分钟       ≥ 10 次登录尝试
 *   strict        30 次/15 分钟       ≥ 30 次**已认证**敏感操作
 *   general       300 次/15 分钟      ≥ 300 次任意请求
 *   ip            1000 次/1 小时      ≥ 1000 次任意请求
 *
 * 把它们加进同一个桶，等于宣称"30 次 captcha 拒绝"与"30 次任意请求拒绝"是同一种
 * 证据。实际后果不是抽象问题，是两条具体的误封：
 *
 *   ① `strict` 是**已认证**端点（refresh / MFA / 报表导出 / 审计导出 / 重置他人密码）。
 *      一个管理员给 20 名新员工批量开户 = 20 次建号 + 20 次改密 + 20 次派角色，
 *      落在 strict 上就是 60 次操作——**一个共享出口 IP 的整间办公室被封 1 小时**。
 *      而且这个越界者是**账号**，不是 IP：该封账号（userLimiter / 账户锁定已经在做），
 *      不该封 IP。
 *   ② `general` / `ip` 是**体量**信号。它们的配额（300/15 分钟、1000/小时）在
 *      NAT 共享出口下本来就被多人分摊，"30 次拒绝"意味着该出口在一小时内发了
 *      1000+ 请求——在局域网消防场景里这是正常办公，在公网托管 + 企业 NAT 下同样正常。
 *
 * 所以本模块把信号分三类，各用各的阀值，**判据是"一次拒绝能证明多少恶意"**：
 *
 *   ANON_ABUSE 端点滥用：单端点紧预算被反复打穿。人类不做这件事（一次登录页
 *              加载只取 1 张验证码，10 次拒绝 ⇒ 70 次验证码请求）。
 *              默认阀值 10，**封 IP**。
 *   VOLUME     体量：单 IP 总请求数被超过。合法共享出口能到这个量级。
 *              默认阀值 100（原单一阀值取 30 时，这一档被误伤；100 才是它的量纲）。
 *              **封 IP**。
 *   AUTH       已认证：越界的是账号不是 IP。默认阀值 30，但**只告警不封 IP**——
 *              处置对象是账号，而账号维度的处置（userLimiter 配额、账户锁定、
 *              MFA 失败锁定）已经各自就位。此处再封一次 IP 只会误伤共享出口。
 *
 * 混检保护：三类计数互相独立。伪造体量（10 次 captcha + 90 次 general）不会
 * 让 ANON_ABUSE 提前到点，各按各的量纲判——这与 securityAlert.checkBruteForce
 * 的 E-04「封禁判据只看 IP 维度」是同一条纪律（宁可少封，不可把无辜者绑上去）。
 *
 * ============================ 为什么用令牌桶而不是固定窗口 ============================
 * 原实现是固定窗口（`windowStart` + 归零重开）。固定窗口有两个固有缺陷：
 *   - **边界突发**：在窗口最后 1 秒打满 N 次、下一秒窗口重开再打 N 次，
 *     实际取到 2N 的速率而阀值只写了 N；
 *   - **升级即清零**：达阈值后 `entry.count = 0; entry.windowStart = now`，
 *     攻击者立刻获得一整个新窗口的免费额度。若那次封禁恰好失败
 *     （写库故障 / 白名单），下一轮再来一轮，**压力从未被记住**。
 *
 * 令牌桶把这两个都消掉：令牌按 `阀值/窗口` 匀速回填，达阈值靠**净消耗**而不是
 * 靠"某个窗口内的瞬时计数"。持续速率恰好等于阀值的攻击者永远不触发升级
 * （每发一次补回一枚，桶水位在 0/1 之间摆动）——这是正确的：等于预算的速率
 * 本就不该被封。边界突发也不再有任何收益。
 *
 * 代价要说清：纯突发打满 N 次**不封**，要第 N+1 次。这不是弱化，是去掉了一个
 * 可被时序利用的口子；净效果是"少了 1 次的余量，换掉了 2N 的时序后门"。
 *
 * ============================ 计数表容量 ============================
 * 键是攻击者可控的来源 IP，轮换 IP 即可驱动 Map 增长。原实现在超限时
 * `hits.clear()` ——**攻击者轮换 10000 个 IP 就能把所有人的计数清零**，
 * 变成一条可主动触发的绕过。改为**按压力升序有界淘汰**：先清已回填的，
 * 仍满则牺牲"最接近升级"程度最低的条目（详见 evictForCapacity 的注释——
 * 那里还解释了为什么"按最旧优先"同样是个坑）。
 *
 * ============================ 仍保留的既定取舍 ============================
 * 计数在进程内（不引入 Redis 新依赖面），多实例部署时每实例只看到自己分到的 429
 * ⇒ 实际封禁阀值 = 配置阀值 × 实例数。这个方向是"少封不误封"，是刻意接受的：
 * 多实例一致性由 `constants/runtime.assertSingleProcessAssumptions` 在启动日志里
 * 列出确切失效清单，限流拦截本身仍由各限流器自己的共享存储跨实例保证。
 */
const logger = require('../utils/logger');
const { normalizeIP } = require('../utils/ipUtils');
const { readPositiveNumberEnv } = require('../utils/envNumber');
const { incSecurityAlert } = require('../utils/metrics');

const CLASS_ANON_ABUSE = 'ANON_ABUSE';
const CLASS_VOLUME = 'VOLUME';
const CLASS_AUTH = 'AUTH';

/** 窗口内触发多少次"拒绝"即升级。整桶回填，故持续速率等于此值不触发（见文件头） */
const ESCALATION_WINDOW_MS = readPositiveNumberEnv('CC_ESCALATION_WINDOW_MS', 5 * 60 * 1000, {
  integer: true,
  onInvalid: (name, raw, d) =>
    logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正整数毫秒），已按默认 ${d} 处理`),
});

/** 三类信号的阀值与处置。ban=false 表示只告警——处置对象是账号而非 IP */
const SIGNAL_CLASSES = {
  [CLASS_ANON_ABUSE]: {
    limiters: ['captcha', 'login-ip', 'register'],
    thresholdEnv: 'CC_ESCALATION_THRESHOLD_ANON',
    threshold: 10,
    ban: true,
    summary: '端点滥用（未认证）',
  },
  [CLASS_VOLUME]: {
    limiters: ['general', 'ip'],
    thresholdEnv: 'CC_ESCALATION_THRESHOLD_VOLUME',
    threshold: 100,
    ban: true,
    summary: '体量超限（未认证）',
  },
  [CLASS_AUTH]: {
    limiters: ['strict', 'user-ip'],
    thresholdEnv: 'CC_ESCALATION_THRESHOLD_AUTH',
    threshold: 30,
    ban: false,
    summary: '已认证敏感操作超限（处置对象为账号）',
  },
};

/** 限流器名 → 类别。未登记的限流器一律计入 VOLUME（最保守：不豁免、不轻判） */
const LIMITER_CLASS = new Map(
  Object.entries(SIGNAL_CLASSES).flatMap(([className, spec]) =>
    spec.limiters.map((limiter) => [limiter, className])
  )
);

/** 阀值可用 env 覆盖，但被夹到 [1, 100000]：0 会让该类永不触发（死配置） */
function resolveThresholds() {
  const out = {};
  for (const [className, spec] of Object.entries(SIGNAL_CLASSES)) {
    const raw = readPositiveNumberEnv(spec.thresholdEnv, spec.threshold, {
      integer: true,
      onInvalid: (name, bad, d) =>
        logger.error(`${name}=${JSON.stringify(bad)} 非法（须为正整数），已按默认 ${d} 处理`),
    });
    const clamped = Math.min(Math.max(raw, 1), 100000);
    if (clamped !== raw) {
      logger.error(`${spec.thresholdEnv}=${raw} 超出 [1,100000]，已夹取到 ${clamped}`);
    }
    out[className] = { ...spec, threshold: clamped };
  }
  return out;
}

const CLASSES = resolveThresholds();

const MAX_TRACKED_IPS = readPositiveNumberEnv('CC_ESCALATION_MAX_TRACKED', 10000, {
  integer: true,
  onInvalid: (name, raw, d) =>
    logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正整数），已按默认 ${d} 处理`),
});
/** 超限时每轮淘汰的比例（1..50）。取小值是为了不给轮换 IP 攻击者一次性清空的机会 */
const EVICT_RATIO = Math.min(
  Math.max(
    readPositiveNumberEnv('CC_ESCALATION_EVICT_RATIO', 10, {
      integer: true,
      onInvalid: (name, raw, d) =>
        logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正整数），已按默认 ${d} 处理`),
    }),
    1
  ),
  50
);

/** 归一化 IP → 计数记录。**唯一需要多进程共享的地方**，故不做惰性单例 */
const records = new Map();

const newRecord = (now) => {
  const classes = {};
  for (const [className, spec] of Object.entries(CLASSES)) {
    classes[className] = { tokens: spec.threshold, byLimiter: {} };
  }
  return { firstSeenMs: now, lastRefillMs: now, classes, escalatedAtMs: {} };
};

/** 清掉窗口已完全回填的记录，返回剩余条数 */
const pruneSettled = (now) => {
  for (const [key, rec] of records) {
    if (now - rec.lastRefillMs >= ESCALATION_WINDOW_MS) records.delete(key);
  }
  return records.size;
};

/**
 * 淘汰打分：已消耗的令牌总量。**越大表示越接近升级、越值得保留**。
 *
 * 三类都要算：只看未认证两类的话，一个"已认证操作越界"的 IP 会被当成无害流量
 * 优先牺牲掉——而那恰恰是最需要留证（要按 userId 核查）的一条。
 */
const pressureOf = (rec) => {
  let pressure = 0;
  for (const [className, spec] of Object.entries(CLASSES)) {
    pressure += spec.threshold - rec.classes[className].tokens;
  }
  return pressure;
};

/**
 * 容量淘汰：先清已回填的，仍超限则**按压力升序**淘汰——压力最小的先走，
 * 同压力时再按 firstSeenMs 升序（更早的先走）。
 *
 * 刻意**不整体清空**：那等于给"轮换 MAX_TRACKED_IPS 个 IP"一条一键重置所有计数的
 * 旁路，攻击者每轮花 N 次请求就能把所有人的压力归零。
 *
 * 也刻意**不按最旧优先**：那样被牺牲的会是"积累了很久、正要升级"的那条，
 * 而攻击者新轮换进来的垃圾 IP（压力 1）反倒留在表里——等于给攻击者一个
 * "用新 IP 把旧目标挤出表"的手段。淘汰顺序必须由**安全价值**决定，不由时间决定。
 *
 * 代价要说清：攻击者若想让某个垃圾 IP 看起来"有压力"，得在该 IP 上真的打满
 * threshold+1 次（默认 11 次）——这是一笔真实成本，不是零成本旁路。
 */
const evictForCapacity = (now) => {
  pruneSettled(now);
  if (records.size < MAX_TRACKED_IPS) return;
  const budget = Math.max(1, Math.floor(MAX_TRACKED_IPS * (EVICT_RATIO / 100)));
  const ordered = [...records.entries()].sort((a, b) => {
    const byPressure = pressureOf(a[1]) - pressureOf(b[1]);
    return byPressure !== 0 ? byPressure : a[1].firstSeenMs - b[1].firstSeenMs;
  });
  for (let i = 0; i < budget && i < ordered.length; i += 1) records.delete(ordered[i][0]);
  logger.error(
    `限流升级计数表超过硬上限 ${MAX_TRACKED_IPS}，已按压力升序淘汰 ${budget} 条` +
      '（不整体清空：那会让轮换 IP 的攻击者一键重置所有人的计数；' +
      '也不按最旧优先：那会让"正要升级"的条目被新轮换进来的垃圾挤掉）'
  );
};

const recordFor = (ipKey, now) => {
  let rec = records.get(ipKey);
  if (!rec) {
    if (records.size >= MAX_TRACKED_IPS) evictForCapacity(now);
    rec = newRecord(now);
    records.set(ipKey, rec);
  }
  return rec;
};

/** 按经过时间匀速回填令牌（每窗口回填满桶） */
const refill = (rec, now) => {
  const elapsed = now - rec.lastRefillMs;
  if (elapsed <= 0) return;
  rec.lastRefillMs = now;
  if (elapsed >= ESCALATION_WINDOW_MS) {
    for (const [className, spec] of Object.entries(CLASSES)) {
      rec.classes[className].tokens = spec.threshold;
      rec.classes[className].byLimiter = {};
    }
    return;
  }
  const ratio = elapsed / ESCALATION_WINDOW_MS;
  for (const [className, spec] of Object.entries(CLASSES)) {
    const state = rec.classes[className];
    if (state.tokens >= spec.threshold) continue;
    state.tokens = Math.min(spec.threshold, state.tokens + ratio * spec.threshold);
  }
};

/** 快照：把构成写进审计，避免"10 次 captcha + 20 次 general"被记成"general 触发" */
const snapshotOf = (state) => ({
  byLimiter: { ...state.byLimiter },
  total: Object.values(state.byLimiter).reduce((a, b) => a + b, 0),
});

/**
 * 记一次限流触发；达所属类别的阀值时以 fire-and-forget 方式升级。
 *
 * 必须永不抛错、永不 await（挂在 429 响应路径上）：升级是增强动作，
 * 任何异常都只能降级为"本次不升级"，不能拖垮限流响应本身。
 *
 * @param {import('express').Request} req 限流器拒绝的请求（只用 req.ip）
 * @param {string} limiterName 触发的限流器名（写入审计与通知，便于溯源）
 */
const noteRateLimitHit = (req, limiterName) => {
  incSecurityAlert('rate_limit_triggered', 'medium');

  // 与名单/封禁同一把尺：::ffff:1.2.3.4 与 1.2.3.4 必须是同一个攻击源
  const ipKey = normalizeIP(req?.ip) || String(req?.ip ?? 'unknown');
  const now = Date.now();

  let rec;
  try {
    rec = recordFor(ipKey, now);
    refill(rec, now);
  } catch (err) {
    logger.error(`限流升级计数失败（本拍不升级）: ${ipKey}, 错误: ${err.message}`);
    return;
  }

  const className = LIMITER_CLASS.get(limiterName) || CLASS_VOLUME;
  const spec = CLASSES[className];
  const state = rec.classes[className];

  state.tokens -= 1;
  state.byLimiter[limiterName] = (state.byLimiter[limiterName] || 0) + 1;

  // 每窗口只升级一次；不重置计数——压力必须被记住（见文件头「为什么用令牌桶」）
  const escalatedAt = rec.escalatedAtMs[className] || 0;
  if (now - escalatedAt < ESCALATION_WINDOW_MS) return;

  const snapshot = snapshotOf(state);
  const escalated = state.tokens < 0;
  rec.escalatedAtMs[className] = escalated ? now : rec.escalatedAtMs[className];

  if (escalated && spec.ban) {
    // 惰性 require 断本模块 → ban 模块 → middleware/security 的循环依赖
    void require('./rateLimitEscalationBan')
      .escalateIp(ipKey, {
        className,
        limiterName,
        snapshot,
        threshold: spec.threshold,
        windowMs: ESCALATION_WINDOW_MS,
      })
      .catch((err) => logger.error(`限流升级处理失败: ${ipKey}, 错误: ${err.message}`));
    return;
  }

  if (escalated && !spec.ban) {
    incSecurityAlert('rate_limit_auth_abuse', 'high');
    logger.error(
      `已认证操作越界（不封 IP）：${ipKey} 在窗口内触发 ${spec.summary} ${snapshot.total} 次` +
        `（构成 ${JSON.stringify(snapshot.byLimiter)}，阀值 ${spec.threshold}）。` +
        '越界的是账号不是 IP：请按 userId 核查，处置走账号侧（账户锁定 / MFA 失败锁定）'
    );
  }
};

/** 读取某 IP 各类别的当前水位（仅测试/诊断用） */
const peekIp = (ip) => {
  const rec = records.get(normalizeIP(ip) || String(ip ?? 'unknown'));
  if (!rec) return null;
  const out = {};
  for (const [className, spec] of Object.entries(CLASSES)) {
    out[className] = { threshold: spec.threshold, ...snapshotOf(rec.classes[className]) };
  }
  return out;
};

/** 清空计数表（仅测试用） */
const resetForTest = () => {
  records.clear();
};

module.exports = {
  CLASS_ANON_ABUSE,
  CLASS_VOLUME,
  CLASS_AUTH,
  SIGNAL_CLASSES: CLASSES,
  LIMITER_CLASS,
  ESCALATION_WINDOW_MS,
  MAX_TRACKED_IPS,
  EVICT_RATIO,
  noteRateLimitHit,
  peekIp,
  resetForTest,
};
