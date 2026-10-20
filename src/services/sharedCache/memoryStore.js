/**
 * 共享缓存 · 内存回退存储与容量收口/降级留痕（2026-10-19 批 3c 自 services/sharedCache.js 拆出）
 *
 * Redis 未配置（或暂时不可用）时的进程内回退：memStore 存储、饱和拒收（enforceMemCap）、
 * 过期清扫与两条 60 秒节流告警（内存表饱和 / incr 降级）。拆出的动机除 max-lines 外，
 * 还有职责边界：本文件不感知 Redis 连接「怎么连」，只承载回退语义与留痕上限。
 * 本模块不是公开 API；对外导出面仍由 index.js 承担。
 */

const logger = require('../../utils/logger');

// 内存回退存储：key -> { value, expireAt }
const memStore = new Map();
let memCleanupTimer = null;

// S-L2（改后审计）：内存回退存储硬上限——Redis 未配置时 nonce 防重放表等
// 可能被分布式来源推高（对照 alertRateLimit 的同类防护）。env 可调，默认 2 万条。
const getMemStoreMax = () => Math.max(1000, Number(process.env.SHARED_CACHE_MEM_MAX) || 20000);

let memCapRejects = 0;
let lastMemCapWarnAt = 0;

/** 饱和拒收留痕：60 秒最多一条 warn，免得拒绝本身变成日志放大器 */
function warnMemCapSaturated() {
  memCapRejects += 1;
  const now = Date.now();
  if (now - lastMemCapWarnAt < 60000) return;
  lastMemCapWarnAt = now;
  logger.warn(
    `共享缓存内存表饱和（上限 ${getMemStoreMax()}，剩余全是防重放关键键）：` +
      `累计拒绝新写入 ${memCapRejects} 次——被拒的登录按"重放"失败，普通缓存改为每次重算。` +
      `持续出现说明有分布式来源在灌 nonce（上限可用 SHARED_CACHE_MEM_MAX 调高）`
  );
}

/**
 * F-211：计数降级留痕。与 warnMemCapSaturated 同策略（60 秒最多一条），
 * 因为触发者是**未认证**的验证码生成——不限流的话"如实报告降级"本身就成了日志放大器。
 */
let incrDegrades = 0;
let lastIncrDegradeWarnAt = 0;

function warnIncrDegraded(key) {
  incrDegrades += 1;
  const now = Date.now();
  if (now - lastIncrDegradeWarnAt < 60000) return;
  lastIncrDegradeWarnAt = now;
  logger.warn(
    `共享缓存 incr：已配置 REDIS_URL 但当前不可用，本次计数如实返回 null` +
      `（累计 ${incrDegrades} 次，键示例 ${key}）——本进程的数字不能当全局计数用；` +
      `持续出现说明 Redis 链路故障，此刻活跃数上限类护栏不生效`
  );
}

/**
 * 容量收口：先清过期，再单遍淘汰普通缓存键。返回 false = 挤无可挤，
 * 调用方必须**放弃本次写入**。
 *
 * 关键键（`critical: true`，目前只有登录 nonce）在任何情况下都不参与淘汰——
 * 这是实测逼出来的口径：原实现按 Map 插入序淘汰最旧，而防重放表里的"最旧"
 * 恰恰是**仍需保护**的那一批。攻击者用服务端公钥就能造出合法信封
 * （ECDH 公钥加密不需要任何秘密），灌满内存表即可把受害者的 nonce 挤出去，
 * 随后重放 10 分钟前抓到的登录信封并拿到**明文口令**
 * （探针：上限调到下限 1000 时灌 1002 条即复现）。
 * 饱和期"新 nonce 被拒收"拒的是攻击者自己的请求，与 Redis 抖动期
 * setIfAbsent 的 fail-closed 同口径（宁可拒绝也不放行重放）；
 * 代价是这场洪水同时会把登录打成拒绝——运维可按 warn 里的提示调高 SHARED_CACHE_MEM_MAX。
 */
function enforceMemCap() {
  const max = getMemStoreMax();
  if (memStore.size <= max) return true;
  memSweep();
  let over = memStore.size - max;
  for (const [k, entry] of memStore) {
    if (over <= 0) break;
    if (!entry.critical) {
      memStore.delete(k);
      over -= 1;
    }
  }
  const admitted = memStore.size <= max;
  if (!admitted) warnMemCapSaturated();
  return admitted;
}

function memSweep() {
  const now = Date.now();
  for (const [key, entry] of memStore) {
    if (entry.expireAt <= now) memStore.delete(key);
  }
}

function ensureMemCleanup() {
  if (memCleanupTimer) return;
  memCleanupTimer = setInterval(memSweep, 60 * 1000);
  memCleanupTimer.unref?.();
}

/** 测试/关闭钩子：复位内存回退存储与节流计数（供 index 的 shutdown/_resetForTests 调用） */
function resetMemoryFallback() {
  memStore.clear();
  memCapRejects = 0;
  lastMemCapWarnAt = 0;
  incrDegrades = 0;
  lastIncrDegradeWarnAt = 0;
  if (memCleanupTimer) {
    clearInterval(memCleanupTimer);
    memCleanupTimer = null;
  }
}

module.exports = {
  memStore,
  enforceMemCap,
  ensureMemCleanup,
  warnIncrDegraded,
  resetMemoryFallback,
};
