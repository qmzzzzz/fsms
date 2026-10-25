/**
 * 会话吊销通知（进程内总线）
 *
 * sessionService 在**实际写库成功后**同步通知订阅方（当前是 WebSocketService，
 * 用于按 sid 主动断开对应长连接）。监听器执行失败只告警：吊销已经落库，通知
 * 只是收敛在线连接，不能反过来让一次已成功的吊销操作报错。
 *
 * 进程内语义：本总线不跨实例。跨实例场景由 WebSocket 周期清扫按库复查兜底
 * （校验 UserSession，最长 30s 内收敛）；业务缓存广播只承载失效语义，不能
 * 据它推断「吊销成立」（清一条不存在的缓存与吊销成功在订阅端无法区分）。
 *
 * 独立成模块而非内联在 sessionService：让「通知订阅」与「会话存储」各有
 * 边界，避免 sessionService 继续膨胀（体积棘轮只许降不许升）。
 */
const logger = require('../utils/logger');

const listeners = new Set();

/**
 * @param {(event: {sids: string[], userId: string, all: boolean, reason: string}) => void} handler
 * @returns {() => void} 注销函数
 */
const onSessionRevoked = (handler) => {
  listeners.add(handler);
  return () => listeners.delete(handler);
};

const notifySessionRevoked = (event) => {
  for (const handler of listeners) {
    try {
      handler(event);
    } catch (err) {
      logger.warn(`会话吊销通知处理失败（不影响吊销结论）：${err.message}`);
    }
  }
};

module.exports = { onSessionRevoked, notifySessionRevoked };
