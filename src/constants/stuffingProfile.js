'use strict';

const { ipSegment } = require('../utils/fingerprint'); // /24、/64 的唯一归一化实现（含 ::ffff: 映射），此处不重写一份
const { LENGTH_BUCKETS } = require('./credentialShape');

const MIN_SAMPLES = 30; // 样本不足不出口：宁可没有，也不给运维一份「抽签抽出来的攻击者排名」

const PROFILE_FIELDS = Object.freeze([
  'sourceKey',
  'credentialStemHits',
  'lengthBucket',
  'charsetClass',
  'attempts',
  'successes',
  'accountCardinality',
  'businessDay',
  'windowStart',
  'windowEnd',
]);

const SAMPLED_ACTIONS = Object.freeze(['canary_username_attempt', 'honeypot_login', 'honeypot_probe']); // 只有蜜罐阶段的行才计 attempts
const SUCCESS_ACTION = 'login_success'; // successes 只由真实登录成功贡献：诱饵放行的成功单独计，否则成功率被诱饵自身抬到 100%

const sortedKeys = (counts, order) =>
  [...counts.keys()].sort((a, b) =>
    counts.get(b) - counts.get(a) || (order.indexOf(a) - order.indexOf(b) || String(a).localeCompare(String(b)))
  ); // 平票按档位表序再按字典序——绝不按 Map 插入序：同一份行集必须每次得到同一份画像

const dominantOf = (counts, order) => sortedKeys(counts, order)[0] || null;

const bump = (counts, key) => counts.set(key, (counts.get(key) || 0) + 1);

const emptyGroup = (sourceKey) => ({
  sourceKey,
  attempts: 0,
  successes: 0,
  credentialStemHits: 0,
  lengthBucketCounts: new Map(),
  charsetClassCounts: new Map(),
  accounts: new Set(),
});

const accountOf = (username) =>
  typeof username === 'string' ? username.trim().toLowerCase() : ''; // 大小写不敏感口径与 username_ci 唯一索引同源

const accumulateShape = (group, shape) => {
  if (!shape || typeof shape !== 'object') return;
  if (shape.credentialStemHits === 1) group.credentialStemHits += 1;
  if (shape.lengthBucket) bump(group.lengthBucketCounts, shape.lengthBucket);
  if (shape.charsetClass !== undefined) bump(group.charsetClassCounts, shape.charsetClass);
};

const toEntry = (group, ctx) =>
  Object.freeze({
    sourceKey: group.sourceKey,
    credentialStemHits: group.credentialStemHits,
    lengthBucket: dominantOf(group.lengthBucketCounts, LENGTH_BUCKETS),
    charsetClass: dominantOf(group.charsetClassCounts, []),
    attempts: group.attempts,
    successes: group.successes,
    accountCardinality: group.accounts.size,
    businessDay: ctx.businessDay,
    windowStart: ctx.windowStart,
    windowEnd: ctx.windowEnd,
  });

const byStrength = (a, b) =>
  b.credentialStemHits - a.credentialStemHits ||
  b.attempts - a.attempts ||
  b.accountCardinality - a.accountCardinality ||
  a.sourceKey.localeCompare(b.sourceKey);

/**
 * 黑名单候选判据（共享出口是主误报面）：一个办公室反复输错同一个账号，「/24 试同一账号 30 次、一次词干表都没命中」
 * 与「/24 试 3000 个账号、条条命中字典」必须能分开。成功率只用于排序，不参与本条判定（自助重置后本人重登也会成功）。
 */
const isBlacklistCandidate = (entry) =>
  Boolean(entry) &&
  entry.attempts >= MIN_SAMPLES &&
  !(entry.accountCardinality === 1 && entry.credentialStemHits === 0);

module.exports = {
  MIN_SAMPLES,
  PROFILE_FIELDS,
  SAMPLED_ACTIONS,
  SUCCESS_ACTION,
  accountOf,
  accumulateShape,
  byStrength,
  dominantOf,
  emptyGroup,
  ipSegment,
  isBlacklistCandidate,
  toEntry,
};