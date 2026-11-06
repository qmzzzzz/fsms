/**
 * 安全管理控制器（门面）
 * 2026-10-19 批 3c-3：自 controllers/securityController.js 拆为目录，本文件保持
 * 原 17 个导出与旧文件逐字同序，require("../controllers/securityController") 的调用方无需改动。
 */

const account = require('./account');
const sensitive = require('./sensitive');
const overview = require('./overview');
const admin = require('./admin');
const config = require('./config');
const reauth = require('./reauth');
const upgrade = require('./upgrade');
const profile = require('./profile');
const attackEvents = require('./attackEvents');

module.exports = {
  getMySecurityInfo: account.getMySecurityInfo,
  changePasswordSecure: account.changePasswordSecure,
  getAccountBindings: account.getAccountBindings,
  viewSensitiveData: sensitive.viewSensitiveData,
  getSecurityStats: overview.getSecurityStats,
  reportSuspiciousActivity: sensitive.reportSuspiciousActivity,
  listReportTargets: sensitive.listReportTargets,
  getMyLogs: account.getMyLogs,
  toggleUserLock: admin.toggleUserLock,
  resetUserMfa: admin.resetUserMfa,
  resetUserPassword: admin.resetUserPassword,
  getSecurityOverview: overview.getSecurityOverview,
  getRecentAlerts: overview.getRecentAlerts,
  getRegistrationConfig: config.getRegistrationConfig,
  setRegistrationConfig: config.setRegistrationConfig,
  getLoginCaptchaConfig: config.getLoginCaptchaConfig,
  setLoginCaptchaConfig: config.setLoginCaptchaConfig,
  getRegisterCaptchaConfig: config.getRegisterCaptchaConfig,
  setRegisterCaptchaConfig: config.setRegisterCaptchaConfig,
  // 审计读取的短时票据：步进验证通过后签发，供 GET 类审计端点在 TTL 内复用
  issueReauthTicket: reauth.issueReauthTicket,
  getUpgradeOverview: upgrade.getUpgradeOverview,
  getUpgradeJob: upgrade.getUpgradeJob,
  triggerUpgrade: upgrade.triggerUpgrade,
  getStuffingProfile: profile.getStuffingProfile,
  getAttackProfile: profile.getAttackProfile,
  getAttackEvents: attackEvents.getAttackEvents,
  getAttackEventSummary: attackEvents.getAttackEventSummary,
};
