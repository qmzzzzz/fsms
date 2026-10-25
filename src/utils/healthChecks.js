/**
 * 报告（可观测性缺口——只有 /health 存活检查，无就绪探针）
 *
 * /health（存活）：进程活着即 200，供 Docker HEALTHCHECK 使用——
 * Mongo 短暂抖动时不该重启容器，二者语义必须分开。
 * /readyz（就绪）：含 Mongo ping **与 Redis ping**，供编排器/LB 判断「能不能干活」——
 * 不 ready 时摘流量但保持进程运行。
 *
 * 为什么 Redis 必须进就绪判据：生产环境 config/validate 强制 REDIS_URL——
 * 限流计数、验证码、权限缓存失效广播与审计链分布式锁都依赖它。只探 Mongo
 * 时 Redis 挂掉的实例照样报 ready：多实例下限流回退为进程内计数（每实例各算
 * 一份，实际阈值被放大 N 倍）、审计链锁退化为进程内（跨实例互斥失效）——
 * 都是安全语义降级，不该被 LB 当成健康实例继续送流量。
 * 未配置 REDIS_URL 的部署（本地/单机测试）不要求 Redis：reason=not_configured，
 * 整体仍 ready，避免把「本部署没启用」误报成故障。
 *
 * S-M1（改后审计 2026-09-05）：结果进程内缓存——/readyz 无鉴权且被公网
 * LB/探针高频打，每请求一次 ping 构成对 Mongo/Redis 的间接 DoS 放大；探针语义下
 * 1 秒陈旧度完全可接受（B-M1 同款思路：把放大量级压到常数）。
 * TTL 经 READYZ_CACHE_MS 运行期读取（显式 0=关闭缓存；未配置或空值=默认 1s）。
 */

const MONGO_PING_TIMEOUT_MS = 1500;
const REDIS_PING_TIMEOUT_MS = 1000;
const READY_CACHE_TTL_DEFAULT_MS = 1000;
const getReadyCacheTtlMs = () => {
  const raw = process.env.READYZ_CACHE_MS;
  // 空串/纯空白必须回落默认值：k8s 的 `value:` 留空与 .env 的 `READYZ_CACHE_MS=` 都会把
  // 变量定义成空串，而 Number('') === 0 ⇒ "忘了填"被读成"故意关缓存"，S-M1 的放大防护
  // 静默消失。这里与 utils/envNumber.js 的差别只有一个：0 在本模块是合法语义，不能并入。
  if (raw === undefined || String(raw).trim() === '') return READY_CACHE_TTL_DEFAULT_MS;
  const v = Number(raw);
  return Number.isFinite(v) && v >= 0 ? v : READY_CACHE_TTL_DEFAULT_MS;
};
let readyCache = null; // { at: number, result: {ok, reason, detail} }
let redisReadyCache = null; // 与 readyCache 分开：TTL 相同，但两者探测节奏不必互相覆盖

/**
 * 检查 MongoDB 是否可服务（readyState + admin ping 双确认）
 * ping 带 1.5s 超时：探针响应必须快，DB 悬挂时宁可快速报 unready
 *
 * 返回 { ok, reason, detail } 双轨——reason 是固定枚举
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

/**
 * 检查 Redis 是否可服务（仅在本部署要求共享状态时）
 *
 * reason 与 Mongo 同口径：'ok'|'disconnected'|'timeout'|'unreachable'，
 * 外加 'not_configured'（未设置 REDIS_URL：本部署不要求，整体仍 ready）。
 * detail 含 ioredis 原始错误（可能带主机/端口），只允许进服务端日志。
 *
 * @param {number} [timeoutMs]
 * @returns {Promise<{ok: boolean, reason: string, detail: string}>}
 */
async function checkRedisReady(timeoutMs = REDIS_PING_TIMEOUT_MS) {
  const ttl = getReadyCacheTtlMs();
  if (ttl > 0 && redisReadyCache && Date.now() - redisReadyCache.at < ttl) {
    return redisReadyCache.result;
  }

  const result = await computeRedisReady(timeoutMs);
  if (ttl > 0) {
    redisReadyCache = { at: Date.now(), result };
  }
  return result;
}

async function computeRedisReady(timeoutMs) {
  // 延迟 require：sharedCache 会拉 ioredis，且其初始化晚于本模块加载
  const sharedCache = require('../services/sharedCache');
  if (!sharedCache.isRedisConfigured()) {
    return {
      ok: true,
      reason: 'not_configured',
      detail: 'REDIS_URL 未配置（本部署未要求 Redis）',
    };
  }

  const client = sharedCache.getRedisClient();
  if (!client || !sharedCache.isRedisEnabled()) {
    return {
      ok: false,
      reason: 'disconnected',
      detail: client ? 'Redis 连接未就绪' : '共享缓存未初始化',
    };
  }

  let timer;
  let timedOut = false;
  try {
    const ping = client.ping();
    // 与 Mongo ping 同理：race 败者的晚到 rejection 必须有人接住
    ping.catch(() => {});
    await Promise.race([
      ping,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          reject(new Error('redis ping timeout ' + timeoutMs + 'ms'));
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
  redisReadyCache = null;
}

module.exports = { checkMongoReady, checkRedisReady, __resetReadyCacheForTest };
