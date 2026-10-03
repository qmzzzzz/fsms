/**
 * 权限滥用检测 · 处置侧（写审计 / 遏制封禁 / 通知）
 *
 * 与 securityAlert.js 拆开是体积债的收口，不是架构偏好：后者已经触及
 * eslint max-lines 上限（本仓既定出路是按职责拆文件，lint:ratchet 只许降不许升——
 * 同 rateLimitEscalationBan.js / roleGuards.js / inspectionGuards.js 的先例）。
 *
 * ============================ 它此前缺的是"遏制" ============================
 * 本检测器是唯一一处"跨层探测已认证权限边界"的哨兵，但长期**只告警、不封任何东西**
 * （另两个检测器 —— checkBruteForce / rateLimitEscalation —— 都有封禁动作）。
 * 缺口是：攻击者只要拿到一份**有效凭据**，把权限探测压到每 5 分钟 < 20 次，
 * 就能永久试探权限边界——每次都不达阈值 ⇒ 无告警、无审计、无遏制。
 * 20 次/5 分钟这条阈值只挡"不会隐藏自己的人"，防不住稍微克制一点的。
 *
 * 处置维度取 **IP**：调用点 rbac.js 只传 userId 与 req.ip
 * （`void checkPermissionAbuse(userId, req.ip)`）。账户维度已由 authService 的
 * 账户锁定 / loginUserLimiter 覆盖；这里补的是 IP 侧——一个 IP 连续越权时把它摁住，
 * 而"换账号继续探"也照样被摁。
 *
 * ============================ 与 checkBruteForce 同一条纪律 ============================
 * 1) **先读阶梯、后写审计**：审计行就是阶梯的事件源（每写一条 permission_abuse
 *    审计 = 一次封禁动作），先读后写才能算出"这次是第几档"。
 * 2) **处置与通知解耦**：频控只约束 dispatchNotification，绝不挡审计与封禁。
 *    否则封禁失败时的重试被吞、审计漏写 ⇒ 阶梯事件源恒 0 ⇒ 阶梯永远停在第一档，
 *    而日志照打"第 N 档"。
 * 3) **封禁结果按返回值分派**（F-160）：addToBlacklist 从不抛错，白名单命中 /
 *    地址解析失败 / 黑名单写库失败三条路径都返回 {banned:false, reason}，
 *    "await 正常返回"绝不等于"封禁生效"。
 *
 * 独立事件源（action=permission_abuse）与暴力破解分账（brute_force_login），
 * 各数各的；只共用同一组时长档位 ESCALATION_TIERS 与同一个 30 天窗口。
 */
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { normalizeIP, ipAttributionRiskFactors } = require('../utils/ipUtils');
const {
  ALERT_LEVELS,
  ALERT_TYPES,
  ESCALATION_TIERS,
  dispatchNotification,
  shouldSendAlert,
  IPBanEvents,
} = require('./securityAlert');

/**
 * 记录一次已确认的权限滥用，并对来源 IP 执行渐进式封禁。
 *
 * 调用方（securityAlert.checkPermissionAbuse）已在**本函数之前**完成：
 *   ① 403 计数（recentFailures）并判过阈值；② 读出 username（AuditLog 必填字段）。
 * 因此这里不做任何前置判断——进了这个函数就一定会留下审计行（除非 DB 写失败，
 * 那也是 error 留痕 + 封禁继续），这正是"阶梯事件源不许被频控吞掉"的要求。
 *
 * @param {{userId:*, username:string, ip:string, attributionKind?:string, recentFailures:number}} ctx
 *   ip 是调用方（securityAlert.checkPermissionAbuse）按 resolvePunishableIp 裁定后的
 *   惩罚目标——PUBLIC_PEER_HEADER 时已是 socket 对端而非请求方可写的 XFF；
 *   attributionKind 为裁定类别，写进审计留痕（ip_attribution_*）
 */
const recordAndContain = async ({ userId, username, ip, attributionKind, recentFailures }) => {
  const normalizedIp = normalizeIP(ip) || ip;
  const hasIp = Boolean(ip);

  // 阶梯统计必须在本次审计落库**之前**读（同 checkBruteForce 口径）。
  // 计数失败按第一档处理（宁可少封不可不封），但必须留痕：阶梯退化是可观测的。
  let priorBans = 0;
  if (hasIp) {
    try {
      priorBans = await IPBanEvents.countPermissionAbusePrior(normalizedIp);
    } catch (e) {
      logger.error(`权限滥用阶梯统计失败（按第一档处理）: ${normalizedIp}, 错误: ${e.message}`);
    }
  }

  // P1-23 同口径（另两个检测器都已挂 try/catch，这里是漏网的第三处）：调用方
  // middleware/rbac.js 是 `void checkPermissionAbuse(...).catch(() => {})`，
  // 裸 await 一旦抛错（DB 瞬断/必填字段校验失败）整条 HIGH 告警会**无声消失**——
  // 既不进审计、也没有一行日志，运维与代码都无从知道权限滥用检测在掉链子。
  // 捕获后仍继续投递通知：告警落库失败不该连带吞掉另一条独立的通知通道。
  try {
    await AuditLog.create({
      action: ALERT_TYPES.PERMISSION_ABUSE,
      category: 'system',
      userId,
      username,
      ip: normalizedIp,
      riskLevel: ALERT_LEVELS.HIGH,
      riskFactors: [
        '频繁权限检查失败',
        // 封禁留痕（口径见 ipUtils.ipAttributionRiskFactors）
        ...ipAttributionRiskFactors(attributionKind),
      ],
      body: { failures: recentFailures },
    });
  } catch (e) {
    logger.error(`权限滥用告警审计落库失败（通知流程继续）: ${e.message}`);
  }

  // 遏制：频控只约束通知，不挡封禁（否则封禁失败时的重试被吞、阶梯事件源缺行）
  if (hasIp) {
    try {
      // 惰性 require：循环依赖同 checkBruteForce（securityAlert ↔ middleware/security）
      const { addToBlacklist } = require('../middleware/security');
      const tier = IPBanEvents.tierFor(priorBans);
      const result = await addToBlacklist(
        normalizedIp,
        ESCALATION_TIERS[tier],
        `permission_abuse_auto_ban_tier${tier + 1}`,
        'auto'
      );
      // F-160 同口径：addToBlacklist 从不抛错，封禁是否生效只能按返回值分派
      if (result?.banned) logger.warn(`权限滥用封禁 ${normalizedIp} 第 ${priorBans + 1} 档`);
      else
        logger.error(
          `权限滥用自动封禁未生效 ${normalizedIp}（${result?.reason ?? 'no_result'}）请人工封禁或核对白名单`
        );
    } catch (e) {
      logger.error(`权限滥用自动封禁 IP 失败: ${ip}, 错误: ${e.message}`);
    }
  }

  // 通知频控只挡"又一条相同告警"：审计与封禁都已执行
  if (shouldSendAlert(`permission_abuse_${userId}`)) {
    // B-M1：fire-and-forget，不挂在 rbac 的拒绝路径上
    dispatchNotification(
      ALERT_TYPES.PERMISSION_ABUSE,
      ALERT_LEVELS.HIGH,
      `检测到权限滥用：用户 ${userId}，失败 ${recentFailures} 次`,
      { userId, ip, failures: recentFailures }
    );
  }
};

module.exports = { recordAndContain };
