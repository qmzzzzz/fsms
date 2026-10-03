/**
 * 限流升级 · 处置侧（写审计 / 通知 / 封禁）
 *
 * 与计数侧（rateLimitEscalation.js）拆开是体积债的收口，不是架构偏好：
 * 前者已经触及 eslint max-lines 上限，本仓的既定出路是按职责拆文件
 * （lint:ratchet 只许降不许升，不允许放宽基线——同 roleGuards.js /
 * inspectionGuards.js 的先例）。计数侧不 require 本模块，只在升级那一刻
 * 惰性 require，所以这里可以反向依赖 middleware/security 而不构成环。
 *
 * ============================ 最重要的一条：处置与通知解耦 ============================
 * 原实现是：
 *
 *     if (!shouldSendAlert(`rate_limit_abuse_${ip}`)) return;   // ← 通知频控
 *     await AuditLog.create({...});                              // 审计
 *     await addToBlacklist(...);                                 // 封禁
 *
 * 一行通知频控把**审计与封禁一起挡在门外**。后果不是少一条告警：
 *   - 封禁**失败**（写库故障 / 命中白名单）时，5 分钟内的重试也被这行吞掉——
 *     而"封禁没生效"恰恰是最需要重试的场合；
 *   - 审计行是**阶梯的事件源**（IPBanEvents.countPrior 数的就是它），
 *     跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，
 *     而日志与通知仍在照打"第 N 档"。
 *
 * 现在：**审计与封禁无条件执行**，只有 `dispatchNotification` 受频控约束。
 * 通知是给人看的，处置是对系统做的，两者不该共用一个开关。
 *
 * ============================ 阶梯统计必须在本次落库之前读 ============================
 * 同 checkBruteForce 的口径：每次升级写一条 rate_limit_abuse 审计，
 * "30 天窗口内该 IP 的历史条数"就是本次落在第几档。先读后写。
 */
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const {
  ALERT_LEVELS,
  ALERT_TYPES,
  ESCALATION_TIERS,
  BAN_ESCALATION_WINDOW_MS,
  dispatchNotification,
  shouldSendAlert,
  IPBanEvents,
} = require('./securityAlert');

/**
 * 写审计。append-only 兼作阶梯事件源，因此**不设频控**——
 * 漏写一行会让阶梯停滞，而阶梯停滞的后果是"反复触发的 IP 永远只封 1 小时"。
 */
const recordEscalation = async (normalizedIp, detail) => {
  try {
    await AuditLog.create({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      category: 'security',
      // CC 触发源通常未认证；username 是审计必填字段（缺失会 ValidationError 静默丢档）
      username: 'anonymous',
      ip: normalizedIp,
      riskLevel: ALERT_LEVELS.HIGH,
      riskFactors: [
        '限流持续触顶',
        `信号类别:${detail.className}`,
        // 封禁留痕（utils/ipUtils.resolvePunishableIp 的裁定口径）：DIRECT 是
        // "无代理、对端即身份"的默认事实，不必刷存在；其余类别（TRUSTED_PROXY
        // 可用但不可区分 / PUBLIC_PEER_HEADER 已改打 socket 对端）必须可事后追查
        ...(detail.attributionKind && detail.attributionKind !== 'direct'
          ? [`ip_attribution_${detail.attributionKind}`]
          : []),
      ],
      body: {
        limiter: detail.limiterName,
        className: detail.className,
        threshold: detail.threshold,
        windowMs: detail.windowMs,
        // 全量构成而不是只记触发阀值的那一个限流器：
        // 混检时（10 captcha + 20 general）只记 general 会让事后复盘归因错误
        mix: detail.snapshot.byLimiter,
        total: detail.snapshot.total,
      },
    });
    return true;
  } catch (e) {
    logger.error(`限流升级审计落库失败（阶梯事件源缺失，封禁流程继续）: ${e.message}`);
    return false;
  }
};

/**
 * 升级封禁。永不 reject——调用方是 fire-and-forget。
 *
 * @param {string} normalizedIp 已归一化的来源 IP
 * @param {{className:string, limiterName:string, snapshot:{byLimiter:Object,total:number},
 *          threshold:number, windowMs:number, attributionKind?:string}} detail 计数侧的快照
 *          （attributionKind 来自 resolvePunishableIp 的裁定，写进审计留痕）
 */
const escalateIp = async (normalizedIp, detail) => {
  const { className, snapshot } = detail;

  // 阶梯统计必须在本次审计落库**之前**读
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

  await recordEscalation(normalizedIp, detail);

  try {
    // 惰性 require 断 securityAlert ↔ middleware/security 的循环依赖（同 checkBruteForce）
    const { addToBlacklist } = require('../middleware/security');
    // 阶梯钳制复用 securityAlert 的 IPBanEvents.tierFor（两本账各自计数——
    // brute_force 行与 rate_limit_abuse 行分账，只是共用同一组时长档位）
    const tier = IPBanEvents.tierFor(priorBans);
    const result = await addToBlacklist(
      normalizedIp,
      ESCALATION_TIERS[tier],
      `rate_limit_auto_ban_tier${tier + 1}`,
      'auto'
    );
    // 通知在封禁结果**之后**按返回值分派（F-160 同一条教训：addToBlacklist
    // 从不抛错，白名单/写库失败时"已自动封禁"的通知就是纸面防线撒谎）。
    // 档位保持静态成员（outboundAlertContract D1 门禁要求调用点档位可静态
    // 解析 ∈ ALERT_LEVELS）；封禁是否生效在 data.banned 供机器消费。
    const banned = !!result?.banned;
    const reason = result?.reason ?? 'no_result';
    if (banned) {
      logger.warn(
        `限流升级封禁 ${normalizedIp}（第 ${priorBans + 1} 档，${className}，` +
          `构成 ${JSON.stringify(snapshot.byLimiter)}）`
      );
    } else {
      // 封禁没生效是必须有人看的事：error 级，且如实写出原因
      logger.error(
        `限流升级封禁未生效 ${normalizedIp}（${reason}）——审计已留痕、阶梯已推进，` +
          '但该 IP 在本次封禁到期前仍可继续请求，请人工核对白名单与 IPBlacklist 写入链路'
      );
    }
    // 通知频控只在这里生效：审计与封禁都已执行，它挡的只是"又一条相同的告警"
    if (!shouldSendAlert(`rate_limit_abuse_${normalizedIp}`)) return;
    const notice = banned
      ? `IP ${normalizedIp} 持续触发限流被自动封禁（${className} / 限流器 ${detail.limiterName}）`
      : `限流升级封禁未生效：IP ${normalizedIp}（${reason}）请人工核对白名单`;
    dispatchNotification(ALERT_TYPES.RATE_LIMIT_ABUSE, ALERT_LEVELS.HIGH, notice, {
      ip: normalizedIp,
      limiter: detail.limiterName,
      className,
      tier: priorBans + 1,
      banned,
    });
  } catch (e) {
    logger.error(`限流升级封禁执行失败: ${normalizedIp}, 错误: ${e.message}`);
  }
};

module.exports = { escalateIp, recordEscalation };
