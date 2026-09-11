/**
 * AuditLog 写入类静态方法：登录日志、业务审计与敏感操作审计。
 */

const logger = require('../utils/logger');
const { auditPath } = require('../utils/auditMeta');
const { computeFingerprint } = require('../utils/fingerprint');
const { sanitizeAuditBody } = require('./auditLogSanitizer');

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
      userAgent,
      sessionId: extra.sessionId || null,
      fingerprint: extra.fingerprint || null,
      success,
      riskLevel: success ? 'low' : 'medium',
    });
  };

  schema.statics.record = function (entry) {
    return this.create(entry).catch((error) => {
      logger.warn('业务审计落库失败', {
        action: entry.action || 'unknown',
        error: error.message,
      });
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
      params: req.params,
      query: req.query,
      body: sanitizeAuditBody(req.body),
      statusCode: res.statusCode,
      success: res.statusCode < 400,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      sessionId: req.user?.sessionId || null,
      fingerprint: computeFingerprint(req),
      duration,
      riskLevel,
      riskFactors,
    });
  };
};

module.exports = { applyWriteStatics };
