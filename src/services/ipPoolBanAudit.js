/**
 * IP 池封禁的审计条目构造（2026-11-03 自 ipPoolBan.js 拆出：该文件体积/复杂度双棘轮
 * 已贴上限；本模块是**纯构造**——不落库、不持状态，写入仍由 ipPoolBan 经
 * auditOutbox.recordDurably 完成，B3 的两态语义（WAL 兜底/重抛）留在调用侧）。
 */

const mongoose = require('mongoose');
const { auditClientAddress } = require('../utils/ipUtils');
const { auditPath } = require('../utils/auditMeta');
const { computeFingerprint } = require('../utils/fingerprint');

/**
 * userId 必须能被 AuditLog 的 ObjectId 字段安全 cast：服务层直调传的 operator 可能是
 * 可读名——cast 失败会让 create 抛 CastError，而封禁已生效，重抛等于「封了却回 500」。
 * cast 不过就返回 null（userId 可省字段），名字走 username。
 * @param {*} operator 票据里的操作者（控制器传 req.user.userId；测试/脚本可能传可读名）
 * @returns {mongoose.Types.ObjectId|null}
 */
const castOperatorId = (operator) => {
  if (operator === null || operator === undefined) return null;
  try {
    return new mongoose.Types.ObjectId(String(operator));
  } catch (_) {
    return null;
  }
};

/**
 * 确认落库的审计条目（B1/B3）。按 ipListController 同族口径补操作者与请求上下文
 * （userId/username/method/path/auditClientAddress/userAgent/sessionId/fingerprint）。
 * username 必须取 operatorUsername——旧实现拿 ticket.operator（ObjectId 串）冒充
 * username，审计页里「谁封的段」是一串 24 位十六进制。req 缺省时如实省略请求侧字段。
 * @returns {object} 可直接交给 AuditLog.create / recordDurably 的文档
 */
const buildAuditEntry = ({ ticket, req, results, bannedCount, success }) => {
  const operatorId = castOperatorId(ticket.operator);
  const body = {
    cidr: ticket.cidr,
    reason: ticket.reason,
    operator: ticket.operator,
    operatorUsername: ticket.operatorUsername || null,
    results,
    bannedCount,
  };
  return {
    action: 'ip_blacklist_added',
    category: 'security',
    userId: operatorId || undefined,
    username:
      ticket.operatorUsername ||
      (operatorId ? 'system' : String(ticket.operator ?? '')) ||
      'system',
    ...(req
      ? {
          method: req.method,
          path: auditPath(req),
          ...auditClientAddress(req),
          userAgent: req.get('user-agent'),
          sessionId: (req.user && req.user.sessionId) || null,
          fingerprint: computeFingerprint(req),
        }
      : {}),
    body,
    success,
    riskLevel: 'high',
  };
};

module.exports = { castOperatorId, buildAuditEntry };
