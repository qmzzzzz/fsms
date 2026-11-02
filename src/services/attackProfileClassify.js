'use strict';

/**
 * IP 行为画像的行级判定：把单条审计行翻译成分类与严重度。只做纯函数派生，不碰数据库：
 * 同一行在同一词典下永远得到同一分类，分类优先级可脱离 Mongo 单测。聚合在
 * attackProfileSummary.js，结论（评分/判定/建议）在 attackProfileVerdict.js。
 */

const {
  ATTACK_CATEGORIES: C,
  CREDENTIAL_SET,
  HONEYPOT_SET,
  ENUMERATION_SET,
  UNAUTHORIZED_SET,
  EXFIL_SET,
  INJECTION_SET,
  SCAN_SET,
  RATE_LIMIT_SET,
  BLOCKLIST_SET,
  SUSPICIOUS_SET,
  SCANNER_PATH_RE,
  INJECTION_PATH_RE,
  UNAUTHORIZED_REASON_RE,
  LOGIN_PATH_RE,
} = require('../constants/attackProfile');

const accountOf = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');

const isBlockedRow = (row) => row.success !== true || Number(row.statusCode) >= 400;

const timeOf = (row) => {
  const date = row.timestamp instanceof Date ? row.timestamp : new Date(row.timestamp);
  return Number.isNaN(date.getTime()) ? null : date;
};

/**
 * 证据投影：只带判定需要的字段，正文/头袋不进入画像响应。`logId` 是审计记录定位键：
 * 取证时据此读取单条详情（含完整请求/响应与哈希链），它本身不携带任何审计内容。
 */
const projectionOf = (row) => ({
  logId: row._id ? String(row._id) : null,
  timestamp: row.timestamp,
  action: row.action || null,
  category: row.category || null,
  method: row.method || null,
  path: row.path || null,
  statusCode: row.statusCode ?? null,
  success: row.success === true,
  username: row.username || null,
  refusalReason: row.refusalReason || null,
  reason: row.reason || null,
  riskLevel: row.riskLevel || null,
  riskFactors: Array.isArray(row.riskFactors)
    ? row.riskFactors.slice(0, 5).map((item) => String(item).slice(0, 200))
    : undefined,
});

/**
 * 动作族 → 分类：undefined 表示「动作层面没有结论」，调用方继续看路径/状态；null 表示显式排除（黑名单命中是处置结果，不是新增行为分类）。
 */
const categoryFromAction = (action, credentialCategory) => {
  if (HONEYPOT_SET.has(action)) return C.HONEYPOT;
  if (ENUMERATION_SET.has(action)) return C.ACCOUNT_ENUMERATION;
  if (CREDENTIAL_SET.has(action)) return credentialCategory;
  if (UNAUTHORIZED_SET.has(action)) return C.UNAUTHORIZED_ACCESS;
  if (EXFIL_SET.has(action)) return C.DATA_EXFILTRATION;
  if (INJECTION_SET.has(action)) return C.INJECTION_PROBE;
  if (SCAN_SET.has(action)) return C.PATH_SCANNING;
  if (RATE_LIMIT_SET.has(action)) return C.RATE_LIMIT_ABUSE;
  if (BLOCKLIST_SET.has(action)) return null;
  return undefined;
};

/** 路径 / 响应码层面的兜底分类（动作族未命中时才看）。 */
const categoryFromPath = (row) => {
  const path = String(row.path || '');
  if (Number(row.statusCode) === 404 && row.category === 'system') return C.PATH_SCANNING;
  if (INJECTION_PATH_RE.test(path)) return C.INJECTION_PROBE;
  if (SCANNER_PATH_RE.test(path)) return C.PATH_SCANNING;

  const status = Number(row.statusCode);
  const reason = String(row.refusalReason || '');
  if (
    (status === 401 || status === 403) &&
    !LOGIN_PATH_RE.test(path) &&
    UNAUTHORIZED_REASON_RE.test(reason)
  ) {
    return C.UNAUTHORIZED_ACCESS;
  }
  return undefined;
};

/** 分类优先级：诱捕 > 账号枚举 > 凭据攻击 > 越权 > 数据导出 > 注入 > 扫描 > 限流 > 可疑。一行只进一个分类。 */
const categoryOf = (row, credentialCategory) => {
  const action = String(row.action || '');
  const fromAction = categoryFromAction(action, credentialCategory);
  if (fromAction !== undefined) return fromAction;
  const fromPath = categoryFromPath(row);
  if (fromPath !== undefined) return fromPath;
  if (SUSPICIOUS_SET.has(action)) return C.SUSPICIOUS_ACTIVITY;
  if (row.riskLevel === 'high') return C.SUSPICIOUS_ACTIVITY;
  if (row.riskLevel === 'critical') return C.SUSPICIOUS_ACTIVITY;
  return null;
};

const FIXED_SEVERITY = Object.freeze({
  [C.HONEYPOT]: 'critical',
  [C.CREDENTIAL_STUFFING]: 'high',
  [C.ACCOUNT_ENUMERATION]: 'high',
  [C.RATE_LIMIT_ABUSE]: 'high',
});

const severityOf = (code, stats, failedLogins) => {
  if (FIXED_SEVERITY[code]) return FIXED_SEVERITY[code];
  switch (code) {
    case C.BRUTE_FORCE:
      return failedLogins >= 10 ? 'high' : 'medium';
    case C.UNAUTHORIZED_ACCESS:
      return stats.count >= 5 ? 'high' : 'medium';
    case C.DATA_EXFILTRATION:
      return stats.successCount > 0 || stats.count >= 3 ? 'high' : 'medium';
    case C.INJECTION_PROBE:
      return stats.count >= 3 ? 'high' : 'medium';
    case C.PATH_SCANNING:
      return stats.count >= 3 ? 'medium' : 'low';
    default:
      return 'medium';
  }
};

module.exports = {
  accountOf,
  isBlockedRow,
  timeOf,
  projectionOf,
  categoryOf,
  severityOf,
};
