/**
 * 认证业务服务门面（对外导出面自 authService.js 保持逐字不变）
 *
 * 实现已按主题拆到同目录的子模块：
 *   failureAndMfa.js 登录/MFA 失败计数口径与二段校验
 *   login.js          登录主流程与口令校验
 *   session.js        注册与登录会话/令牌签发
 *   token.js          刷新令牌轮换与登出吊销
 *   password.js       口令变更
 *   profile.js        资料更新与账号锁定/解锁
 *
 * 本文件只做再导出：调用方（含 16 个测试文件）仍从 '../services/authService'
 * 取用，不需要跟着改 require 路径。
 *
 * 原边界说明（拆分前写在 authService.js 头部，仍然成立）：
 * - MFA 防爆破与恢复码原语在 services/mfaService.js；
 * - 设备级会话落库/吊销在 services/sessionService.js；
 * - 令牌签发与探测在 services/tokenService.js；
 * - 口令密文解密在 utils/loginCipher.js。
 * 本层只做流程编排与判定，不重复实现上述能力。
 */

const { registerUser } = require('./session');
const { loginUser } = require('./login');
const { refreshSession, revokeTokensOnLogout } = require('./token');
const { changeUserPassword } = require('./password');
const { updateUserProfile, setUserLockStatus } = require('./profile');

module.exports = {
  registerUser,
  loginUser,
  refreshSession,
  changeUserPassword,
  updateUserProfile,
  setUserLockStatus,
  revokeTokensOnLogout,
};
