/**
 * 就绪探针检查（报告：可观测性缺口——只有 /health 存活检查，无就绪探针）
 *
 * /health（存活）：进程活着即 200，供 Docker HEALTHCHECK 使用——
 * Mongo 短暂抖动时不该重启容器，二者语义必须分开。
 * /readyz（就绪）：含 Mongo ping，供编排器/LB 判断「能不能干活」——
 * 不 ready 时摘流量但保持进程运行。
 */

const MONGO_PING_TIMEOUT_MS = 1500;

/**
 * 检查 MongoDB 是否可服务（readyState + admin ping 双确认）
 * ping 带 1.5s 超时：探针响应必须快，DB 悬挂时宁可快速报 unready
 *
 * M-1：返回 { ok, reason, detail } 双轨——reason 是固定枚举
 * （'ok'|'disconnected'|'timeout'|'unreachable'），供 /readyz 对外暴露；
 * detail 含驱动原始错误消息（可能泄露主机/端口/副本集/认证细节），
 * **只允许进服务端日志，不得出现在响应体中**。该端点通常不鉴权且被
 * 公网 LB 探测，直出 err.message 等于向外部提供内部拓扑情报。
 * @returns {Promise<{ok: boolean, reason: 'ok'|'disconnected'|'timeout'|'unreachable', detail: string}>}
 */
async function checkMongoReady(timeoutMs = MONGO_PING_TIMEOUT_MS) {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 1) {
    return {
      ok: false,
      reason: 'disconnected',
      detail: 'mongodb readyState=' + mongoose.connection.readyState,
    };
  }

  let timer;
  let timedOut = false;
  try {
    await Promise.race([
      mongoose.connection.db.admin().ping(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          reject(new Error('ping timeout ' + timeoutMs + 'ms'));
        }, timeoutMs);
      }),
    ]);
    return { ok: true, reason: 'ok', detail: 'ok' };
  } catch (err) {
    return { ok: false, reason: timedOut ? 'timeout' : 'unreachable', detail: err.message };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

module.exports = { checkMongoReady };
