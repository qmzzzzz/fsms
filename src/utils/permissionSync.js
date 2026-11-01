/**
 * 权限热生效推送：只此一份实现，roleController 与 userController 都必须调用本函数——
 * 各维护一份逐字相同的 syncPermissionsToUsers 是口径漂移隐患（一处改了失败语义
 * 另一处不知道）。
 *
 * 与 emitWebSocketEvent 的分工：
 *  - emitWebSocketEvent 面向 role-management 房间（仅管理员），用于刷新管理界面；
 *  - 本函数面向「权限实际发生变化的那些用户」，让他们无需重登即刻生效。
 *
 * 失败不阻断响应：权限已成功落库，推送只是加速生效；
 * 推送失败时用户退化到原有行为（下次登录或缓存过期后生效）。
 */

const logger = require('./logger');
const { errText } = require('./auditWriteFailure');

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
    // 头部注释承诺「失败不阻断响应」，那么这一行自己就不能抛：
    // 裸读 err.message 在被拒值为非 Error 时抛 TypeError，而这个函数是被控制器
    // await 的 ⇒ 已经落库成功的权限变更会反过来变成一个 500（契约被观测代码打破）。
    logger.warn(`权限同步推送失败（不影响本次变更结果）：${errText(err)}`);
  }
};

module.exports = { syncPermissionsToUsers };
