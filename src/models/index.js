/**
 * 模型统一导出
 */

const User = require('./User');
const Role = require('./Role');
const Permission = require('./Permission');
const FireDevice = require('./FireDevice');
const FireAlarm = require('./FireAlarm');
const Inspection = require('./Inspection');
const SystemConfig = require('./SystemConfig');
const AuditLog = require('./AuditLog');
const TokenBlacklist = require('./TokenBlacklist');
const IPBlacklist = require('./IPBlacklist');
const UserSession = require('./UserSession');

module.exports = {
  User,
  Role,
  Permission,
  FireDevice,
  FireAlarm,
  Inspection,
  SystemConfig,
  AuditLog,
  TokenBlacklist,
  IPBlacklist,
  UserSession,
};
