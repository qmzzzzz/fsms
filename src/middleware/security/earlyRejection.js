/**
 * 「早于 auditLog 中间件的拒绝」审计写入（自 ipBlacklist.js 抽出）
 *
 * 抽出的直接原因：originCheck 只为了这一个函数就经 security/index 门面取用，
 * 而门面把 IP 黑名单、审计中间件、协议合规整条链拉进来，形成
 * `originCheck → security/index → … → originCheck` 的惰性环。本模块只依赖
 * AuditLog 与若干纯工具函数，是叶子节点。
 */

const logger = require('../../utils/logger');
const AuditLog = require('../../models/AuditLog');
const { computeFingerprint } = require('../../utils/fingerprint');
const { stripControlChars } = require('../../utils/helpers');
const { auditPath } = require('../../utils/auditMeta');
const { auditClientAddress } = require('../../utils/ipUtils');

/**
 * 记录「早于 auditLog 中间件的 403 拒绝」审计
 *
 * checkIPBlacklist 与 originCheck 都挂在 auditLog 之前（必须如此：黑名单要在
 * 一切业务处理前拦下，来源校验要在写操作触达控制器前拦下）。副作用是它们的
 * 403 完全不进审计——攻击探测最密集的这段流量在合规留存里是一片空白，
 * 事后既无法统计封禁命中，也无法证明拦截曾生效。
 *
 * 直写 AuditLog.record 而不走 auditBuffer：这类事件量小且属安全信号，
 * 需要即时可查（暴力探测检测也依赖实时性），与 ip_range_denied 同口径。
 * @param {import('express').Request} req
 * @param {{action: string, reason: string, riskFactors: string[], riskLevel?: string, statusCode?: number}} meta
 *        statusCode 缺省 403（黑名单/来源这两类都是拒绝式 403）；
 *        查询形态守卫那类是 400，必须传真实值——审计里记错状态码，
 *        等于让事后统计把"畸形请求被拒"算成"越权被拒"。
 * @returns {void}
 */
const recordEarlyRejection = (req, meta) => {
  setImmediate(() => {
    try {
      AuditLog.record({
        action: meta.action,
        category: 'security',
        userId: req.user?.userId,
        username: req.user?.username || 'anonymous',
        sessionId: req.user?.sessionId || null,
        fingerprint: computeFingerprint(req),
        // method 原样交下去：取值全集与"越枚举怎么办"由 AuditLog schema
        // （constants/audit.js 的 AUDIT_HTTP_METHODS + setter）单点决定。
        // 原先这里私抄一份 5 动词白名单，把 HEAD/OPTIONS 探测**静默降级成无 method 的记录**，
        // 而这类探测恰恰是安全信号——事后看不出它是 HEAD。
        method: req.method,
        path: auditPath(req),
        ...auditClientAddress(req),
        userAgent: stripControlChars(req.get('user-agent'), 512),
        statusCode: meta.statusCode || 403,
        success: false,
        riskLevel: meta.riskLevel || 'medium',
        riskFactors: meta.riskFactors,
        reason: stripControlChars(meta.reason, 512),
      });
    } catch (e) {
      logger.debug(`早期拒绝审计写入跳过：${e.message}`);
    }
  });
};

module.exports = { recordEarlyRejection };
