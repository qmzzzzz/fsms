/**
 * 安全管理控制器共享 model 句柄
 * （2026-10-19 批 3c-3 自 controllers/securityController.js 原样迁出：
 *  原单文件顶层的 model 句柄集中于此，供 account / sensitive / overview / admin / config
 *  各段复用；函数体内的惰性加载（Role / AuditLogModel）留在各自函数体不迁。）
 */

const User = require('../../models/User');
const AuditLog = require('../../models/AuditLog');
const SystemConfig = require('../../models/SystemConfig');

module.exports = { User, AuditLog, SystemConfig };
