/**
 * AuditLog 写入类静态方法：登录日志、业务审计与敏感操作审计。
 */

const logger = require('../utils/logger');
const { auditPath } = require('../utils/auditMeta');
const { computeFingerprint } = require('../utils/fingerprint');
const { sanitizeAuditBody, sanitizeAuditQuery } = require('./auditLogSanitizer');
const { stripControlChars, stripControlCharsDeep } = require('../utils/helpers');

/**
 * 审计写入前的统一清洗（req.params / req.query 专用）：先剥控制字符归一键名，再按键脱敏。
 * 键名单用 sanitizeAuditQuery 的并集口径（body 名单 ∪ 查询专用名单）：
 * query 里的 code / otp / authorization / session 与 body 里的 refreshToken 同为凭据，
 * 只用 body 名单会漏前者、只用查询名单会漏后者（盲区方向相反，详见 auditLogSanitizer 头注释）。
 *
 * 顺序必须是「先清洗后脱敏」，不能反：stripControlCharsDeep 会重写键名并 trim，
 * 而 matchesSensitiveQueryKey 按整键/下划线边界判、不容空白。`GET /x?+sign=SECRET`
 * 经 qs 解出的键就是 `" sign"`（`+` 在查询串里是空格）——先脱敏时 `" sign"` 不命中名单、
 * 值被原样保留，随后清洗把键归一成 `"sign"`，于是凭据以明文躺在 append-only、
 * 且定期导出 CSV 的审计集合里。实测两序对比：
 *   清洗→脱敏 = {"sign":"***"} ／ 脱敏→清洗 = {"sign":"SECRET123"}。
 * @param {object} obj req.params 或 req.query
 * @returns {object} 可直接入库的对象
 */
const sanitizeAuditDeep = (obj) =>
  sanitizeAuditQuery(stripControlCharsDeep(obj && typeof obj === 'object' ? obj : {}));

const applyWriteStatics = (schema) => {
  schema.statics.recordLogin = async function (
    userId,
    username,
    ip,
    success,
    userAgent,
    extra = {}
  ) {
    return this.create({
      action: success ? 'login_success' : 'login_failed',
      category: 'auth',
      userId,
      username,
      ip,
      // UA 完全外控：不清洗就把换行/Bidi 写进哈希保护的审计集合，
      // 任何把它推给 SIEM 的动作都会产出可伪造行（与 recordSensitiveAction 同口径）
      userAgent: stripControlChars(userAgent, 512),
      sessionId: extra.sessionId || null,
      // 调用方一直在传 reason（credential_decrypt_failed / account_status_inactive /
      // 登录 IP 不在允许范围内 …），而这里从未取用——M-5 把差异化响应文案收成了统一的 401
      // 防枚举，注释又说"真实原因仅记入服务端日志与审计"，于是取证链的审计这一环是空的：
      // 被禁/被锁账号的登录尝试在留存里与"密码错误"完全同形。
      reason: stripControlChars(extra.reason, 200),
      fingerprint: extra.fingerprint || null,
      success,
      riskLevel: success ? 'low' : 'medium',
    });
  };

  // 评价报告 #8：审计写入不得静默吞错——落库失败时除日志外，计入
  // security_alerts_total{type=audit_write_failed,level=medium}，
  // 让「审计链出现缺口」在监控面可见（审计完整性是合规硬要求）。
  // 返回值契约不变（resolve null），调用方无需感知失败形态。
  schema.statics.record = function (entry) {
    return this.create(entry).catch((error) => {
      logger.error('业务审计落库失败', {
        action: entry.action || 'unknown',
        error: error?.message ?? error,
      });
      try {
        require('../utils/metrics').incSecurityAlert('audit_write_failed', 'medium');
      } catch (_) {
        /* 指标端不可用时仅保留日志 */
      }
      return null;
    });
  };

  schema.statics.recordSensitiveAction = async function (
    userId,
    username,
    action,
    category,
    req,
    res,
    duration
  ) {
    const riskFactors = [];
    if (action.includes('delete')) riskFactors.push('delete_operation');
    if (action.includes('batch')) riskFactors.push('batch_operation');
    if (res.statusCode >= 400) riskFactors.push('error_response');

    const forwardedFor = req.get('x-forwarded-for');
    if (forwardedFor && forwardedFor.split(',').length > 1) {
      riskFactors.push('multi_hop_proxy');
    }

    const riskLevel =
      riskFactors.length >= 2 ? 'high' : riskFactors.length === 1 ? 'medium' : 'low';

    return this.create({
      action,
      category,
      userId,
      username,
      method: req.method,
      path: auditPath(req),
      // 与 middleware/security.js 的 request-audit 路径同口径：
      // 原实现把 req.params / req.query **原样**写入，既不做键脱敏也不剥控制字符，
      // 于是经 query 传的令牌会以明文永久留在不可篡改、且定期导出 CSV 的审计集合里，
      // 攻击者可控的换行/Bidi 字符也会伪造 SIEM 解析出的日志行。
      params: sanitizeAuditDeep(req.params),
      query: sanitizeAuditDeep(req.query),
      body: sanitizeAuditBody(req.body),
      statusCode: res.statusCode,
      success: res.statusCode < 400,
      ip: req.ip,
      userAgent: stripControlChars(req.get('user-agent'), 512),
      sessionId: req.user?.sessionId || null,
      fingerprint: computeFingerprint(req),
      duration,
      riskLevel,
      riskFactors,
    });
  };
};

module.exports = { applyWriteStatics };
