/**
 * 登录限流命中记账：让 429 变成可见、可计入的失败尝试。
 *
 * 为什么单独成模块：中间件 handler 里拿不到登录服务的请求上下文，而审计写入必须
 * 非阻塞、不可抛。这里只做「有界去重 + 转交 loginChallenge」两件事。
 *
 * 去重是必需的：被限流时每个请求都写一行，等于用攻击流量把审计库打爆，反而
 * 制造一条新的资源耗尽路径。同键 60 秒内只记一次；键数上限 512，按插入顺序丢最旧。
 * 代价如实声明：窗口内只留一条，证明的是“发生过”而不是“发生了几次”。
 */
const logger = require('../utils/logger');
const { clientIpForSecurityDecision } = require('../utils/ipUtils');

const DEDUPE_TTL_MS = 60 * 1000;
const DEDUPE_MAX_KEYS = 512;
const recent = new Map();
let challengeModule = null;

const prune = (now) => {
  for (const [key, at] of recent) {
    if (now - at >= DEDUPE_TTL_MS) recent.delete(key);
  }
  while (recent.size > DEDUPE_MAX_KEYS) {
    const oldest = recent.keys().next();
    if (oldest.done) break;
    recent.delete(oldest.value);
  }
};

const keyOf = (limiter, username, ip) => {
  const who = username ? String(username).trim().toLowerCase().slice(0, 64) : '';
  return `${limiter}:${who || ip || '-'}`;
};

/** 限流器 handler 里调用；永不抛（内部已 catch），@returns {boolean} 本次是否真的记账 */
const recordLimitedAttempt = (req, limiter) => {
  try {
    const username = req.body?.username;
    const ip = clientIpForSecurityDecision(req);
    const now = Date.now();
    const key = keyOf(limiter, username, ip);
    const last = recent.get(key);
    if (last !== undefined && now - last < DEDUPE_TTL_MS) return false;
    recent.set(key, now);
    prune(now);
    Promise.resolve()
      .then(() => {
        if (!challengeModule) challengeModule = require('./loginChallenge');
        return challengeModule.recordRateLimited({
          username,
          ip,
          userAgent: req.get ? req.get('user-agent') : undefined,
          limiter,
        });
      })
      .catch((err) => {
        logger.warn('登录限流记账失败（不影响 429 响应）：' + String((err && err.message) || err));
      });
    return true;
  } catch (err) {
    logger.warn('登录限流记账入口异常（忽略）：' + String((err && err.message) || err));
    return false;
  }
};

const resetForTest = () => {
  recent.clear();
  challengeModule = null;
};

module.exports = { recordLimitedAttempt, resetForTest, DEDUPE_TTL_MS, DEDUPE_MAX_KEYS };
