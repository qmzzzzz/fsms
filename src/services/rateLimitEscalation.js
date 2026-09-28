/**
 * 限流触发升级服务（CC 防护闭环）
 *
 * 解决的问题：此前限流「只挡不罚」——CC 攻击者把每个 IP 恰好压在阈值下，
 * 或轮换 IP 长期贴着 429 刷，除了一行 warn 日志不产生任何安全信号，更不会
 * 升级成封禁；运维只能事后翻 http_requests_total 的 429 维度。本服务把 429
 * 变成一等安全事件：
 *   1. 每次限流触发上报 security_alerts_total{type=rate_limit_triggered}（可观测）；
 *   2. 同一 IP 在窗口内持续触顶达阈值 → 走与暴力破解同一条封禁阶梯
 *      （ESCALATION_TIERS：1h→4h→24h→7d，按 30 天窗口内的审计事件数升档）
 *      → 自动封禁 → checkIPBlacklist 在限流之前以 403 短路该 IP 的后续请求。
 *
 * 误封防线（CC 升级最大的风险是把正常用户/NAT 出口错杀）：
 *   - 阈值默认 100 次/5 分钟：generalLimiter 本身 300 次/15 分钟，触顶后窗口内
 *     **每一条后续请求都是 429**，真攻击 5 分钟可刷出数千次；正常聚合流量触顶后
 *     用户看到错误即停，5 分钟内再堆满 100 次 429 意味着"已被告知限速仍持续高频重试"。
 *   - 白名单 IP 的资源型限流在 rateLimit.js 直接 skip，handler 不执行 ⇒ 天然不会
 *     被本服务封禁（凭据型限流不豁免白名单，攻击信号同样不该豁免）。
 *   - 凭据型限流的账号维度桶（login-user / pwd-change-user / reauth-user）不接入：
 *     按 username 组键没有 IP 可封，且分布式撞单账号的升级由 checkBruteForce 负责。
 *   - 封禁动作复用 addToBlacklist：白名单命中/解析失败/写库失败全部 fail-soft，
 *     并按返回值记账（F-160 口径），成功与否在日志里不撒谎。
 *
 * 实例边界：触发计数在进程内（不引入 Redis 新依赖面），多实例部署时每实例只看到
 * 自己分到的 429 ⇒ 实际封禁阈值 = 配置阈值 × 实例数，语义是"少封不误封"；
 * 429 拦截本身仍由限流器自己的共享存储跨实例保证，不受此影响。
 */
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { normalizeIP } = require('../utils/ipUtils');
const { readPositiveNumberEnv } = require('../utils/envNumber');
const { incSecurityAlert } = require('../utils/metrics');
const {
  ALERT_LEVELS,
  ALERT_TYPES,
  ESCALATION_TIERS,
  BAN_ESCALATION_WINDOW_MS,
  dispatchNotification,
} = require('./securityAlert');

/** 窗口内触发多少次限流升级为封禁（429 计数） */
const ESCALATION_THRESHOLD = readPositiveNumberEnv('CC_ESCALATION_THRESHOLD', 100, {
  integer: true,
  onInvalid: (name, raw, d) =>
    logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正整数），已按默认 ${d} 处理`),
});
/** 触发计数的窗口长度：固定窗口，达阈值后计数归零重开 */
const ESCALATION_WINDOW_MS = readPositiveNumberEnv('CC_ESCALATION_WINDOW_MS', 5 * 60 * 1000, {
  integer: true,
  onInvalid: (name, raw, d) =>
    logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正整数毫秒），已按默认 ${d} 处理`),
});
/**
 * 计数表容量上限：键是攻击者可控的来源 IP，轮换 IP 即可驱动 Map 增长。
 * 超限时先清过期窗口，仍超限则整体清空（宁可短时漏计，也不能让防护模块
 * 自己成为内存耗尽入口）——与 securityAlert.alertRateLimit 同一条纪律。
 */
const MAX_TRACKED_IPS = readPositiveNumberEnv('CC_ESCALATION_MAX_TRACKED', 10000, {
  integer: true,
  onInvalid: (name, raw, d) =>
    logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正整数），已按默认 ${d} 处理`),
});

/** 归一化 IP -> { windowStart, count }（固定窗口计数） */
const hits = new Map();

/** 清掉窗口已过期的计数项，返回剩余条数 */
const pruneExpired = () => {
  const now = Date.now();
  for (const [key, entry] of hits.entries()) {
    if (now - entry.windowStart >= ESCALATION_WINDOW_MS) hits.delete(key);
  }
  return hits.size;
};

/**
 * 记一次限流触发；达阈值时以 fire-and-forget 方式升级封禁。
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
  let entry = hits.get(ipKey);
  if (!entry || now - entry.windowStart >= ESCALATION_WINDOW_MS) {
    if (hits.size >= MAX_TRACKED_IPS) {
      const remaining = pruneExpired();
      if (remaining >= MAX_TRACKED_IPS) {
        hits.clear();
        logger.error(`限流升级计数表超过硬上限 ${MAX_TRACKED_IPS} 且无可回收过期项，已整体清空`);
      }
    }
    entry = { windowStart: now, count: 0 };
    hits.set(ipKey, entry);
  }
  entry.count += 1;
  if (entry.count < ESCALATION_THRESHOLD) return;

  // 达阈值：立即重开窗口（同一窗口内只升级一次；封禁生效后 403 短路，
  // 计数自然不再增长），升级动作异步执行
  entry.count = 0;
  entry.windowStart = now;
  void escalate(ipKey, limiterName);
};

/**
 * 升级封禁：写审计（append-only，兼作封禁阶梯的事件源）→ 通知 → 封禁。
 *
 * 阶梯统计必须在本次审计落库**之前**读（同 checkBruteForce 的口径）：
 * 每次升级都写一条 rate_limit_abuse 审计，"30 天窗口内该 IP 的历史条数"
 * 就是本次落在第几档。
 */
const escalate = async (normalizedIp, limiterName) => {
  try {
    let priorBans = 0;
    try {
      priorBans = await AuditLog.countDocuments({
        action: ALERT_TYPES.RATE_LIMIT_ABUSE,
        ip: normalizedIp,
        timestamp: { $gte: new Date(Date.now() - BAN_ESCALATION_WINDOW_MS) },
      });
    } catch (e) {
      // 统计失败按第一档处理（宁可少封不可不封），但必须留痕：阶梯退化是可观测的
      logger.error(`限流升级阶梯统计失败（按第一档处理）: ${normalizedIp}, 错误: ${e.message}`);
    }

    try {
      await AuditLog.create({
        action: ALERT_TYPES.RATE_LIMIT_ABUSE,
        category: 'security',
        // CC 触发源通常未认证；username 是审计必填字段（缺失会 ValidationError 静默丢档）
        username: 'anonymous',
        ip: normalizedIp,
        riskLevel: ALERT_LEVELS.HIGH,
        riskFactors: ['限流持续触顶'],
        body: {
          limiter: limiterName,
          threshold: ESCALATION_THRESHOLD,
          windowMs: ESCALATION_WINDOW_MS,
        },
      });
    } catch (e) {
      logger.error(`限流升级审计落库失败（封禁流程继续）: ${e.message}`);
    }

    dispatchNotification(
      ALERT_TYPES.RATE_LIMIT_ABUSE,
      ALERT_LEVELS.HIGH,
      `IP ${normalizedIp} 持续触发限流被自动封禁（限流器 ${limiterName}）`,
      { ip: normalizedIp, limiter: limiterName, tier: priorBans + 1 }
    );

    try {
      // 惰性 require 断 securityAlert ↔ middleware/security 的循环依赖（同 checkBruteForce）
      const { addToBlacklist } = require('../middleware/security');
      const tier = Math.min(Math.max(priorBans, 0), ESCALATION_TIERS.length - 1);
      const result = await addToBlacklist(
        normalizedIp,
        ESCALATION_TIERS[tier],
        `rate_limit_auto_ban_tier${tier + 1}`,
        'auto'
      );
      const banFailReason = result?.reason ?? 'no_result';
      if (result?.banned)
        logger.warn(
          `限流升级封禁 ${normalizedIp}（第 ${priorBans + 1} 档，限流器 ${limiterName}）`
        );
      else logger.error(`限流升级封禁未生效 ${normalizedIp}（${banFailReason}）请人工核对白名单`);
    } catch (e) {
      logger.error(`限流升级封禁执行失败: ${normalizedIp}, 错误: ${e.message}`);
    }
  } catch (e) {
    logger.error(`限流升级处理失败: ${normalizedIp}, 错误: ${e.message}`);
  }
};

/** 读取某 IP 的当前窗口计数（仅测试/诊断用） */
const peekHits = (ip) => {
  const entry = hits.get(normalizeIP(ip) || String(ip ?? 'unknown'));
  return entry ? entry.count : 0;
};

/** 清空计数表（仅测试用） */
const resetForTest = () => {
  hits.clear();
};

module.exports = {
  ESCALATION_THRESHOLD,
  ESCALATION_WINDOW_MS,
  MAX_TRACKED_IPS,
  noteRateLimitHit,
  peekHits,
  resetForTest,
};
