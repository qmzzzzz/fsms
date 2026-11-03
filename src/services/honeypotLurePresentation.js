/**
 * 诱饵会话的呈现层（2026-11-03 自 honeypotWatch.js 拆出：该文件体积棘轮已贴上限）。
 * 纯呈现工厂——不持状态、不做判定，把「零角色」换成合成角色/权限只为不让攻击者看穿，
 * 授权判定不看它（真实请求全被 honeypotDecoy 接管）。经 honeypotWatch 同名再导出，
 * authService/login.js 与测试的引用面不变。
 */
const {
  DECOY_PERMISSIONS,
  DECOY_ROLE_CODES,
  syntheticEmailOf,
} = require('../constants/honeypotDecoy');

function decorateLureSession(result) {
  if (!result || !result.user) return result;
  return {
    ...result,
    user: {
      ...result.user,
      email: syntheticEmailOf(result.user.username), // 呈现层邮箱：库里那份 @honeypot.invalid 只给防守方看（导出/备份里一眼可辨）
      roles: [...DECOY_ROLE_CODES],
      permissions: [...DECOY_PERMISSIONS],
    },
  };
}

module.exports = { decorateLureSession };
