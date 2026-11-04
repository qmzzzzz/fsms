/** 登录防护共用阈值（挑战闸 / 账户锁定 / 判据窗口）：独立模块，避免服务层为四个数把 dotenv 与启动校验拉进来。 */
const { readClampedIntEnv } = require('../utils/envNumber');

const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;

module.exports = {
  challengeAfter: readClampedIntEnv('LOGIN_CHALLENGE_AFTER', 3, [1, 50]),
  challengeWindowMs: readClampedIntEnv('LOGIN_CHALLENGE_WINDOW_MS', 15 * MINUTE, [MINUTE, DAY]),
  // 粘滞窗（2026-11-04 渗透测试发现后新增）：闸门拦下的尝试（login_captcha_rejected 审计行）
  // 在这个更长的窗口内持续要求人机验证——否则失败计数窗（上面 15 分钟）一滑走，
  // 口令校验就恢复，攻击者按「3 次猜测 + 等窗口」的节奏可持续枚举。
  // 下限 1 分钟保证配置错误时粘滞至少有一点存在感；上限 7 天防止把可用性 DoS 判据配成永久。
  challengeStickyMs: readClampedIntEnv('LOGIN_CHALLENGE_STICKY_MS', 6 * 60 * MINUTE, [
    MINUTE,
    7 * DAY,
  ]),
  lockAfter: readClampedIntEnv('LOGIN_LOCK_AFTER', 10, [1, 100]),
  lockMs: readClampedIntEnv('LOGIN_LOCK_MS', 10 * MINUTE, [MINUTE, DAY]),
};
