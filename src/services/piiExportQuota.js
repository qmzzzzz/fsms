// 未脱敏 PII 导出每日配额（A-8，E2 双计数源）：Redis 主源/审计回退、消费即扣减、fail-closed 与 TOCTOU 口径见 docs/pii-export-quota.md
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { readPositiveNumberEnv } = require('../utils/envNumber');
const sharedCache = require('./sharedCache');

const WINDOW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_QUOTA = 5;
const MAX_QUOTA = 100; // 上限只防误配（写成 100000 等于没有配额），非策略推荐值
const REDIS_KEY_PREFIX = 'pii_export_quota:';

const DAILY_QUOTA = Math.min(
  Math.max(
    readPositiveNumberEnv('PII_EXPORT_DAILY_QUOTA', DEFAULT_QUOTA, {
      integer: true,
      onInvalid: (name, raw, d) =>
        logger.error(name + '=' + JSON.stringify(raw) + ' 非法（须为正整数），已按默认 ' + d),
    }),
    1
  ),
  MAX_QUOTA
);

const recentExportFilter = (userId, since) => ({
  userId,
  action: 'view_sensitive_data',
  dataType: 'export_realname',
  timestamp: { $gte: since },
});

const windowStart = (now) => new Date(now.getTime() - WINDOW_MS);

/** UTC+8 挂钟下的当日键：配额按自然日，不随实例/容器时区漂移 */
const quotaDayKey = (userId, now) => {
  const local = new Date(now.getTime() + 8 * 60 * 60 * 1000);
  const ymd = `${local.getUTCFullYear()}${String(local.getUTCMonth() + 1).padStart(2, '0')}${String(
    local.getUTCDate()
  ).padStart(2, '0')}`;
  return `${REDIS_KEY_PREFIX}${userId}:${ymd}`;
};

const retryAfterOfDay = (now) => {
  const local = new Date(now.getTime() + 8 * 60 * 60 * 1000);
  const nextMidnight = Date.UTC(
    local.getUTCFullYear(),
    local.getUTCMonth(),
    local.getUTCDate() + 1
  );
  const waitMs = nextMidnight - local.getTime();
  return Math.min(Math.max(Math.ceil(waitMs / 1000), 60), WINDOW_MS / 1000);
};

const quotaUnavailable = (cause) => {
  const err = new Error(
    `未脱敏导出配额计数不可用（fail-closed）：${(cause && cause.message) || cause}`
  );
  err.code = 'PII_EXPORT_QUOTA_UNAVAILABLE';
  return err;
};

const readPiiExportQuotaCount = async ({ userId, now = new Date() } = {}) => {
  if (!sharedCache.isRedisConfigured()) return null;
  if (!sharedCache.isRedisEnabled()) throw quotaUnavailable(new Error('Redis 未就绪'));
  try {
    const raw = await sharedCache.getRedisClient().get(quotaDayKey(userId, now));
    const used = raw === null ? 0 : Number(raw);
    const allowed = used < DAILY_QUOTA;
    return {
      used,
      limit: DAILY_QUOTA,
      allowed,
      retryAfterSeconds: allowed ? 0 : retryAfterOfDay(now),
    };
  } catch (err) {
    if (err.code === 'PII_EXPORT_QUOTA_UNAVAILABLE') throw err;
    throw quotaUnavailable(err);
  }
};

const consumePiiExportQuota = async ({ userId, now = new Date() } = {}) => {
  if (!sharedCache.isRedisConfigured()) return null;
  if (!sharedCache.isRedisEnabled()) throw quotaUnavailable(new Error('Redis 未就绪'));
  let used;
  try {
    used = await sharedCache.incrWithTtl(quotaDayKey(userId, now), WINDOW_MS);
  } catch (err) {
    throw quotaUnavailable(err);
  }
  // incrWithTtl 契约：Redis 已启用但命令失败（或已配置未就绪）返回 null ⇒ 计数不可信
  if (used === null) throw quotaUnavailable(new Error('INCR 未生效'));
  const numeric = Number(used);
  const allowed = numeric <= DAILY_QUOTA;
  return {
    used: numeric,
    limit: DAILY_QUOTA,
    allowed,
    retryAfterSeconds: allowed ? 0 : retryAfterOfDay(now),
  };
};

// 配额判定（检查侧，requirePiiExportQuota 中间件用）；读失败上抛：调用方按 fail-closed 处理（5xx），不得折算成放行。
const checkPiiExportQuota = async ({ userId, now = new Date() } = {}) => {
  const counted = await readPiiExportQuotaCount({ userId, now });
  if (counted !== null) return counted;
  const since = windowStart(now);
  const used = await AuditLog.countDocuments(recentExportFilter(userId, since));
  if (used < DAILY_QUOTA) {
    return { allowed: true, used, limit: DAILY_QUOTA, retryAfterSeconds: 0 };
  }
  // 只在拒绝时多查一条（最早那次）：Retry-After 说的是"最早一次滑出窗口还需多久"，钳在 [60s, 窗口]——给 0 会让客户端立刻重试，给超过窗口的值是撒谎。
  const oldest = await AuditLog.findOne(recentExportFilter(userId, since))
    .sort({ timestamp: 1, _id: 1 })
    .select('timestamp')
    .lean();
  const freeAt = oldest && oldest.timestamp ? oldest.timestamp.getTime() + WINDOW_MS : 0;
  const waitMs = freeAt ? freeAt - now.getTime() : WINDOW_MS;
  const retryAfterSeconds = Math.min(Math.max(Math.ceil(waitMs / 1000), 60), WINDOW_MS / 1000);
  return { allowed: false, used, limit: DAILY_QUOTA, retryAfterSeconds };
};

module.exports = {
  WINDOW_MS,
  DAILY_QUOTA,
  REDIS_KEY_PREFIX,
  quotaDayKey,
  checkPiiExportQuota,
  consumePiiExportQuota,
  readPiiExportQuotaCount,
};
