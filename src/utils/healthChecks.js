/**
 * 就绪探针检查（报告：可观测性缺口——只有 /health 存活检查，无就绪探针）
 *
 * /health（存活）：进程活着即 200，供 Docker HEALTHCHECK 使用——
 * Mongo 短暂抖动时不该重启容器，二者语义必须分开。
 * /readyz（就绪）：含 Mongo ping，供编排器/LB 判断「能不能干活」——
 * 不 ready 时摘流量但保持进程运行。
 *
 * S-M1（改后审计 2026-09-05）：结果进程内缓存——/readyz 无鉴权且被公网
 * LB/探针高频打，每请求一次 ping 构成对 Mongo 的间接 DoS 放大；探针语义下
 * 1 秒陈旧度完全可接受（B-M1 同款思路：把放大量级压到常数）。
 * TTL 经 READYZ_CACHE_MS 运行期读取（0=关闭缓存），默认 1s。
 */

const MONGO_PING_TIMEOUT_MS = 1500;
const getReadyCacheTtlMs = () => {
  const v = Number(process.env.READYZ_CACHE_MS);
  return Number.isFinite(v) && v >= 0 ? v : 1000;
};
let readyCache = null; // { at: number, result: {ok, reason, detail} }

/**
 * 检查 MongoDB 是否可服务（readyState + admin ping 双确认）
 * ping 带 1.5s 超时：探针响应必须快，DB 悬挂时宁可快速报 unready
 *
 * M-1：返回 { ok, reason, detail } 双轨——reason 是固定枚举
 * （'ok'|'disconnected'|'timeout'|'unreachable'），供 /readyz 对外暴露；
 * detail 含驱动原始错误消息（可能泄露主机/端口/副本集/认证细节），
 * **只允许进服务端日志，不得出现在响应体中**。该端点通常不鉴权且被
 * 公网 LB 探测，直出 err.message 等于向外部提供内部拓扑情报。
 * @param {number} [timeoutMs]
 * @returns {Promise<{ok: boolean, reason: 'ok'|'disconnected'|'timeout'|'unreachable', detail: string}>}
 */
async function checkMongoReady(timeoutMs = MONGO_PING_TIMEOUT_MS) {
  const ttl = getReadyCacheTtlMs();
  if (ttl > 0 && readyCache && Date.now() - readyCache.at < ttl) {
    return readyCache.result;
  }

  const result = await computeMongoReady(timeoutMs);
  if (ttl > 0) {
    readyCache = { at: Date.now(), result };
  }
  return result;
}

async function computeMongoReady(timeoutMs) {
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
    const ping = mongoose.connection.db.admin().ping();
    // S-L5：race 败者的晚到 rejection（serverSelectionTimeoutMS 约 30s 后）
    // 无人处理会落入 unhandledRejection 兜底产生异常日志噪声，先挂空 catch
    ping.catch(() => {});
    await Promise.race([
      ping,
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

/** 仅供测试重置缓存（生产不调用） */
function __resetReadyCacheForTest() {
  readyCache = null;
}

module.exports = { checkMongoReady, __resetReadyCacheForTest };
