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
const UserAvatar = require('./UserAvatar');
const PrivilegeGrant = require('./PrivilegeGrant');
const ReauthTicketUse = require('./ReauthTicketUse');
const ReauthGrant = require('./ReauthGrant');
const IdempotencyRecord = require('./IdempotencyRecord');
const ForensicCapture = require('./ForensicCapture');
const ConsentRecord = require('./ConsentRecord');

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
  UserAvatar,
  PrivilegeGrant,
  ReauthTicketUse,
  ReauthGrant,
  IdempotencyRecord,
  ForensicCapture,
  ConsentRecord,
};
