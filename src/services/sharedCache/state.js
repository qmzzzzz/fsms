/**
 * 共享缓存 · Redis 连接态与环境判据（2026-10-19 批 3c 自 services/sharedCache.js 拆出）
 *
 * 「现在能用吗」（isRedisEnabled）、「部署上要不要用」（isRedisConfigured）与
 * 连接口令读取集中在这里单点定义：门面 index.js 与失效广播 invalidation.js
 * 都要读这两把判据，若留在 index 就形成 index ↔ invalidation 循环依赖。
 * 本模块不是公开 API；对外导出面仍由 index.js 承担。
 */

// Redis 连接状态：（拆出自原 sharedCache.js 顶层 let，行为不变）
const state = {
  redisClient: null, // ioredis 实例（未启用为 null）
  redisReady: false, // 连接就绪标记（未就绪期间自动走内存回退）
  initAttempted: false,
};

function isRedisEnabled() {
  return state.redisClient !== null && state.redisReady;
}

/**
 * 部署侧是否**要求**跨实例共享状态（配了 REDIS_URL 就是要求）。
 * 与 isRedisEnabled 的区别：后者是"现在能用吗"，前者是"语义上该用哪个存储"。
 * 占位类判据（setIfAbsent）必须按前者决定能不能退回内存——见 setIfAbsent 的回退语义。
 */
function isRedisConfigured() {
  return (process.env.REDIS_URL || '').trim() !== '';
}

/**
 * Redis 认证口令（REDIS_PASSWORD，与 REDIS_URL 同源同时机读取；支持 *_FILE 注入，
 * 见 config/secrets.js）。取值经 ioredis 的 password 选项携带——不走 URL userinfo，
 * 口令字符集就不受 percent-encoding 约束（compose 侧 secrets 文件用 base64 即可）。
 * 空值返回 undefined：不给无认证部署（本地开发/单机内存 Redis）强加 password 选项；
 * 生产侧由 config/validate.js 的认证闸保证「URL 凭据 / REDIS_PASSWORD / 显式豁免」
 * 三者必居其一，服务器端开了 requirepass 而客户端没带时 ioredis 以 NOAUTH 显式失败，
 * 不会静默降级。
 */
function redisConnectionPassword() {
  const password = process.env.REDIS_PASSWORD;
  return password ? password : undefined;
}

module.exports = {
  state,
  isRedisEnabled,
  isRedisConfigured,
  redisConnectionPassword,
};
