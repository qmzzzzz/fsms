const mongoose = require('mongoose');
const { validateEnum, escapeRegExp, parseDateBoundary } = require('./helpers');
const { normalizeIP } = require('./ipUtils');
const { AUDIT_CATEGORIES, AUDIT_LOG_ACTIONS } = require('../constants/audit');

const AUDIT_LOG_CATEGORIES = AUDIT_CATEGORIES;
const AUDIT_LOG_RISK_LEVELS = ['low', 'medium', 'high', 'critical'];
const AUDIT_LOG_LEVELS = ['info', 'warning', 'error'];

const buildAuditQuery = (req) => {
  const { startDate, endDate, userId, username, action, category, ip, riskLevel, success, level } =
    req.query;

  if (startDate && isNaN(new Date(startDate).getTime())) {
    throw new Error('开始日期格式错误');
  }
  if (endDate && isNaN(new Date(endDate).getTime())) {
    throw new Error('结束日期格式错误');
  }

  validateEnum(action, AUDIT_LOG_ACTIONS, 'action');
  validateEnum(category, AUDIT_LOG_CATEGORIES, 'category');
  validateEnum(riskLevel, AUDIT_LOG_RISK_LEVELS, 'riskLevel');
  validateEnum(level, AUDIT_LOG_LEVELS, 'level');

  if (userId && !mongoose.Types.ObjectId.isValid(userId)) {
    throw new Error('参数 userId 必须是合法的用户 ID');
  }

  let normalizedQueryIP = null;
  if (ip) {
    normalizedQueryIP = normalizeIP(ip);
    if (!normalizedQueryIP) {
      throw new Error('参数 ip 必须是合法的 IPv4/IPv6 地址');
    }
  }

  const query = {};
  if (startDate || endDate) {
    query.timestamp = {};
    // 评价报告 #12：date-only 边界统一走 parseDateBoundary（业务时区口径）。
    // 原实现 `new Date('YYYY-MM-DDT00:00:00')` 无时区后缀按服务器本地时区解析，
    // UTC 容器下比东八区业务口径早 8 小时，跨日漏数。
    if (startDate) {
      query.timestamp.$gte = parseDateBoundary(startDate, 'start');
    }
    if (endDate) {
      query.timestamp.$lte = parseDateBoundary(endDate, 'end');
    }
  }
  if (userId) query.userId = userId;
  if (username) query.username = { $regex: escapeRegExp(username), $options: 'i' };
  if (action) query.action = action;
  if (category) query.category = category;
  if (normalizedQueryIP) {
    const ipVariants = [...new Set([normalizedQueryIP, String(ip).trim()])];
    query.ip = ipVariants.length > 1 ? { $in: ipVariants } : ipVariants[0];
  }
  if (riskLevel) query.riskLevel = riskLevel;
  if (success !== undefined && success !== '') {
    query.success = success === 'true' || success === true;
  }

  if (level && ['info', 'warning', 'error'].includes(level)) {
    let levelCond;
    if (level === 'error') {
      levelCond = { $or: [{ success: false }, { riskLevel: { $in: ['high', 'critical'] } }] };
    } else if (level === 'warning') {
      levelCond = { success: true, riskLevel: 'medium' };
    } else {
      levelCond = { success: true, riskLevel: { $nin: ['medium', 'high', 'critical'] } };
    }
    query.$and = [...(query.$and || []), levelCond];
  }

  return { query, startDate, endDate };
};

module.exports = { buildAuditQuery };
