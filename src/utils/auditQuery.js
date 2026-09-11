const mongoose = require('mongoose');
const { validateEnum, escapeRegExp } = require('./helpers');
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
    if (startDate) {
      query.timestamp.$gte = /^\d{4}-\d{2}-\d{2}$/.test(startDate)
        ? new Date(`${startDate}T00:00:00`)
        : new Date(startDate);
    }
    if (endDate) {
      query.timestamp.$lte = /^\d{4}-\d{2}-\d{2}$/.test(endDate)
        ? new Date(`${endDate}T23:59:59.999`)
        : new Date(endDate);
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
