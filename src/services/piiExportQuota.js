/**
 * 未脱敏 PII 导出的滚动 24 小时配额（审计 A-8）：计数直接数留痕本身（view_sensitive_data /dataType=export_realname），过滤条件与写入侧同形、由测试钉住；读失败一律上抛（fail-closed），绝不在"不知道今天已经导了几次"的时候放行。
 */
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { readPositiveNumberEnv } = require('../utils/envNumber');

const WINDOW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_QUOTA = 5;
const MAX_QUOTA = 100; // 上限只防误配（写成 100000 等于没有配额），非策略推荐值

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

// 配额判定；读失败上抛：调用方按 fail-closed 处理（5xx），不得折算成放行。
const checkPiiExportQuota = async ({ userId, now = new Date() }) => {
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

module.exports = { WINDOW_MS, DAILY_QUOTA, checkPiiExportQuota };
