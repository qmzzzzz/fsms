'use strict';

const crypto = require('crypto');
const ApiResponse = require('../utils/apiResponse');
const { DataMasking } = require('../utils/encryption');
const { normalizeProbePath } = require('../constants/probePaths');
const { AUDIT_CATEGORIES } = require('../constants/audit');
const { SECURITY_SUGGESTION_CODES } = require('../constants/securitySuggestions');
const {
  prefixPattern,
  substringPattern,
  upperCodePrefixPattern,
  normalizeSearchTerm,
} = require('../utils/searchPatterns');
const {
  DECOY_SELF_LOGS,
  DECOY_SELF_TRAIL_IP,
  DECOY_SELF_TRAIL_SID,
  DECOY_SELF_TRAIL_UA,
} = require('../constants/honeypotDecoySelf');
const { DECOY_ALARMS, DECOY_DEVICES, DECOY_USERS } = require('../constants/honeypotDecoyData');
const { HONEYPOT_VERDICT } = require('../constants/honeypotDecoy');
const {
  atOf,
  bindingsPayload,
  contextOf,
  DAY_MS,
  isoOf,
  mePayload,
  mfaStatusPayload,
  sessionContextOf,
  sessionsPayload,
} = require('./honeypotDecoySelfProfile');

const LOG_LIMIT_DEFAULT = 50;
const LOG_LIMIT_MAX = 500;
const LOG_DAYS_DEFAULT = 7;
const LOG_DAYS_MAX = 365;
const CANDIDATE_LIMIT = 20; // 与 controllers/securityController/sensitive.js 的候选上限同值

const decoyTrailId = (seed, atMs) => {
  // 合成审计行的 _id：真实行的时间戳前缀 + 稳定哈希尾，形态同 ObjectId 且永不进查询
  const digest = crypto
    .createHash('sha256')
    .update('honeypot-self-trail:' + seed)
    .digest('hex');
  return (
    Math.floor(atMs / 1000)
      .toString(16)
      .padStart(8, '0')
      .slice(-8) + digest.slice(0, 16)
  );
};

const trailOf = (ctx) =>
  DECOY_SELF_LOGS.map((row) => ({ row, at: atOf(ctx, row.offsetMin) })).sort((a, b) => b.at - a.at);

const logRowOf = (row, ctx, at) => {
  const current = row.session === 'current';
  return {
    _id: decoyTrailId(row.action + '@' + row.offsetMin, at),
    action: row.action,
    category: row.category,
    userId: ctx.userId,
    username: ctx.username,
    targetUserId: null,
    targetUsername: null,
    targetType: null,
    targetId: null,
    dataType: null,
    description: row.description || null,
    reason: null,
    method: row.method,
    path: row.path,
    ip: current ? ctx.ip : DECOY_SELF_TRAIL_IP,
    userAgent: current && ctx.ua ? ctx.ua : DECOY_SELF_TRAIL_UA,
    success: row.success,
    errorMessage: row.errorMessage || null,
    riskLevel: row.riskLevel,
    riskFactors: [],
    sessionId: current ? ctx.sid : DECOY_SELF_TRAIL_SID,
    timestamp: isoOf(at),
    createdAt: isoOf(at),
    updatedAt: isoOf(at),
    __v: 0,
  };
};

const securityScoreOf = (ctx, recentLogins) => {
  const idleDays = Math.floor((ctx.now - ctx.lastLoginMs) / DAY_MS);
  const failedCount = recentLogins.filter((item) => !item.success).length;
  const suggestions = [];
  let score = 100;
  if (idleDays > 30) {
    score -= 10;
    suggestions.push(SECURITY_SUGGESTION_CODES.ACCOUNT_INACTIVE_LONG);
  }
  if (failedCount > 3) {
    score -= 15;
    suggestions.push(SECURITY_SUGGESTION_CODES.REPEATED_LOGIN_FAILURES);
  }
  return { securityScore: Math.max(0, score), suggestions };
};

const myInfoPayload = (ctx) => {
  const recentLogins = trailOf(ctx)
    .filter((item) => item.row.action === 'login_success' || item.row.action === 'login_failed')
    .slice(0, 10)
    .map((item) => ({
      action: item.row.action,
      ip: DataMasking.maskIP(item.row.session === 'current' ? ctx.ip : DECOY_SELF_TRAIL_IP),
      time: isoOf(item.at),
      success: item.row.success,
    }));
  return {
    user: {
      _id: ctx.userId,
      username: ctx.username,
      email: DataMasking.maskEmail(ctx.email),
      phone: DataMasking.maskPhone(ctx.phone),
      lastLoginAt: ctx.lastLoginAt,
      createdAt: ctx.createdAt,
      status: 'active',
      __v: 0,
    },
    ...securityScoreOf(ctx, recentLogins),
    recentLogins,
  };
};

const clampInt = (raw, fallback, max) => {
  const parsed = parseInt(raw, 10);
  return !Number.isInteger(parsed) || parsed < 1 ? fallback : Math.min(parsed, max);
};

const myLogsPayload = (ctx, query) => {
  const category = query.category;
  if (category && !AUDIT_CATEGORIES.includes(category)) {
    return {
      errorCode: 'VALIDATION_FAILED',
      options: { fieldErrors: [{ path: 'category', msg: '不支持的操作类别' }] },
    };
  }
  const limit = clampInt(query.limit, LOG_LIMIT_DEFAULT, LOG_LIMIT_MAX);
  const days = clampInt(query.days, LOG_DAYS_DEFAULT, LOG_DAYS_MAX);
  const since = ctx.now - days * DAY_MS;
  const data = trailOf(ctx)
    .filter((item) => item.at >= since && (!category || item.row.category === category))
    .slice(0, limit)
    .map((item) => logRowOf(item.row, ctx, item.at));
  return { data, message: '获取成功' };
};

const candidateIdOf = (row) => {
  // 候选条目的 id 必须是真记录形态（24 位十六进制）：提交举报时前端原样回传，hp- 前缀一出现即自报家门
  const raw = String((row && row._id) || '');
  if (/^[0-9a-f]{24}$/.test(raw)) return raw;
  return crypto
    .createHash('sha256')
    .update('honeypot-self-candidate:' + raw)
    .digest('hex')
    .slice(0, 24);
};

const locationLabelOf = (location) => {
  if (!location || typeof location !== 'object') return '';
  return [location.building, location.floor, location.room] // 设备/报警候选的 detail 都是这条标签串（sensitive.js:272,283）
    .filter((value) => typeof value === 'string' && value.trim() !== '') // 与真实 helper 同式：空段跳过（sensitive.js:236-241）
    .join(' · ');
};

const selfRowOf = (ctx) => ({
  _id: ctx.userId,
  username: ctx.username,
  realName: ctx.realName,
  department: ctx.department,
});

const CANDIDATE_KINDS = Object.freeze({
  user: {
    rows: (ctx) => [selfRowOf(ctx), ...DECOY_USERS],
    match: (row, term) =>
      prefixPattern(term).test(row.username || '') ||
      substringPattern(term).test(row.realName || ''),
    toItem: (row) => ({
      id: candidateIdOf(row),
      kind: 'user',
      code: row.username || '',
      name: row.realName || '',
      detail: row.department || '',
    }),
  },
  device: {
    rows: () => DECOY_DEVICES,
    match: (row, term) =>
      upperCodePrefixPattern(term).test(row.deviceCode || '') ||
      substringPattern(term).test(row.deviceName || ''),
    toItem: (row) => ({
      id: candidateIdOf(row),
      kind: 'device',
      code: row.deviceCode || '',
      name: row.deviceName || '',
      detail: locationLabelOf(row.location), // 真实链同式：设备候选的 detail 是位置标签串（sensitive.js:272）
    }),
  },
  alarm: {
    rows: () => DECOY_ALARMS,
    match: (row, term) =>
      prefixPattern(term).test(row.alarmCode || '') ||
      substringPattern(term).test(locationLabelOf(row.location)),
    toItem: (row, ctx) => ({
      id: candidateIdOf(row),
      kind: 'alarm',
      code: row.alarmCode || '',
      name: row.alarmType || '',
      detail: locationLabelOf(row.location), // 与设备候选同形（sensitive.js:236-241,272,283）
      occurredAt: isoOf(atOf(ctx, row.occurredAtOffsetMin)),
    }),
  },
});

const reportTargetsPayload = (ctx, query) => {
  const kind =
    typeof query.type === 'string' && Object.hasOwn(CANDIDATE_KINDS, query.type)
      ? CANDIDATE_KINDS[query.type]
      : null;
  if (!kind) {
    return {
      errorCode: 'VALIDATION_FAILED',
      options: { fieldErrors: [{ field: 'type', message: '无效的目标类型' }] },
    };
  }
  const term = normalizeSearchTerm(query.keyword);
  return {
    data: {
      items: kind
        .rows(ctx)
        .filter((row) => !term || kind.match(row, term))
        .slice(0, CANDIDATE_LIMIT)
        .map((row) => kind.toItem(row, ctx)),
    },
    message: '操作成功',
  };
};

const SELF_HANDLERS = Object.freeze({
  me: (ctx) => ({ data: mePayload(ctx), message: '获取成功' }),
  'mfa-status': () => ({ data: mfaStatusPayload(), message: '操作成功' }),
  sessions: (ctx) => ({ data: sessionsPayload(ctx), message: '获取成功' }),
  'my-info': (ctx) => ({ data: myInfoPayload(ctx), message: '获取成功' }),
  bindings: (ctx) => ({ data: bindingsPayload(ctx), message: '获取成功' }),
  'my-logs': myLogsPayload,
  'report-targets': reportTargetsPayload,
});

const SELF_ENDPOINTS = Object.freeze([
  Object.freeze({ id: 'me', path: '/api/auth/me' }),
  Object.freeze({ id: 'mfa-status', path: '/api/auth/mfa/status' }),
  Object.freeze({ id: 'sessions', path: '/api/auth/sessions' }),
  Object.freeze({ id: 'my-info', path: '/api/security/my-info' }),
  Object.freeze({ id: 'bindings', path: '/api/security/bindings' }),
  Object.freeze({ id: 'my-logs', path: '/api/security/my-logs' }),
  Object.freeze({ id: 'report-targets', path: '/api/security/report-targets' }),
]);

const resolveSelfResponse = (input) => {
  // 命中本人自助面则返回合成响应描述；GET/HEAD 之外的写法一律交回上层（⇒ 403）
  const source = input || {};
  const upper = String(source.method || 'GET').toUpperCase();
  if (upper !== 'GET' && upper !== 'HEAD') return null;
  const endpoint = SELF_ENDPOINTS.find((item) => item.path === normalizeProbePath(source.path));
  if (!endpoint) return null;
  const result = SELF_HANDLERS[endpoint.id](contextOf(source.session), source.query || {});
  return {
    ...result,
    endpoint: endpoint.id,
    verdict: result.errorCode ? HONEYPOT_VERDICT.DENY : HONEYPOT_VERDICT.DECOY,
    write: false,
    head: upper === 'HEAD',
  };
};

const sendSelfResponse = (res, response) => {
  if (response.errorCode) {
    return ApiResponse.codeError(res, response.errorCode, response.options || {});
  }
  return ApiResponse.success(res, response.data, response.message);
};

module.exports = { resolveSelfResponse, SELF_ENDPOINTS, sendSelfResponse, sessionContextOf };
