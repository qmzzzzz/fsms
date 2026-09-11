/**
 * 权限热生效推送（O-3：自 roleController / userController 抽取的共享实现）
 *
 * 此前两个控制器各自维护一份逐字相同的 syncPermissionsToUsers，
 * 属口径漂移隐患（一处改了失败语义另一处不知道）。抽取后为唯一实现。
 *
 * 与 emitWebSocketEvent 的分工：
 *  - emitWebSocketEvent 面向 role-management 房间（仅管理员），用于刷新管理界面；
 *  - 本函数面向「权限实际发生变化的那些用户」，让他们无需重登即刻生效。
 *
 * 失败不阻断响应：权限已成功落库，推送只是加速生效；
 * 推送失败时用户退化到原有行为（下次登录或缓存过期后生效）。
 */

const logger = require('./logger');

/**
 * @param {import('express').Request} req
 * @param {Array<string|object>} userIds 受影响用户
 * @param {object} meta 推送负载（如变更来源/角色）
 */
const syncPermissionsToUsers = async (req, userIds, meta) => {
  const wsService = req.app.get('wsService');
  if (!wsService || typeof wsService.emitPermissionSync !== 'function') return;
  try {
    await wsService.emitPermissionSync(userIds, meta);
  } catch (err) {
    logger.warn(`权限同步推送失败（不影响本次变更结果）：${err.message}`);
  }
};

module.exports = { syncPermissionsToUsers };
