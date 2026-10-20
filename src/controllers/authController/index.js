/**
 * 认证控制器门面
 *
 * 对外导出面固定为 14 个名字（见文件底部 module.exports），
 * 路由与测试仍从 '../controllers/authController' 取用，不需要跟着改 require 路径。
 *
 * 实现按主题拆到同目录的子模块：
 *   · credentials.js —— 注册 / 登录 / 图形验证码 / 登录公钥 / 刷新令牌
 *   · session.js     —— 当前用户信息 / 登出 / 会话探测与设备级会话吊销
 *   · profile.js     —— 改密 / 资料更新
 *   · shared.js      —— 未知 outcome 的 fail-closed 兜底（credentials/profile 共用）
 *
 * 原文件头边界说明（拆分后仍然成立）：
 * D-1：业务规则已下沉到 services 层，本目录只做
 * 入参校验（express-validator）→ service 调用 → HTTP 响应编排：
 * - services/authService.js   注册/登录（含 MFA 二期）/刷新/改密/资料/登出
 * - services/tokenService.js  令牌签发与轻量会话探测
 * - services/sessionService.js 设备级会话
 * - services/mfaService.js    MFA 防爆破与恢复码原语
 *
 * 拆分动机：原文件 ESLint 计 440 代码行（max-lines 300），按「凭证 / 会话 / 资料」
 * 切段，每段有独立测试面（authLifecycle / authControllerOutcomes / logout* 等），
 * 便于后续单点演进（棘轮只许降不许升）。
 */

const {
  register,
  login,
  getCaptcha,
  getCaptchaStatus,
  getLoginPublicKey,
  refreshToken,
} = require('./credentials');
const {
  getMe,
  logout,
  getSessionStatus,
  listSessions,
  revokeSession,
  revokeOtherSessions,
} = require('./session');
const { changePassword, updateProfile } = require('./profile');

module.exports = {
  register,
  login,
  getCaptcha,
  getCaptchaStatus,
  getLoginPublicKey,
  refreshToken,
  getMe,
  changePassword,
  updateProfile,
  logout,
  getSessionStatus,
  listSessions,
  revokeSession,
  revokeOtherSessions,
};
