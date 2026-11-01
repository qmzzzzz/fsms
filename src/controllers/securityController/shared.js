/**
 * 安全管理控制器共享 model 句柄：供 account / sensitive / overview / admin / config 各段复用；
 * 函数体内的惰性加载（Role / AuditLogModel）留在各自函数体。
 */

const User = require('../../models/User');
const AuditLog = require('../../models/AuditLog');
const SystemConfig = require('../../models/SystemConfig');

module.exports = { User, AuditLog, SystemConfig };
