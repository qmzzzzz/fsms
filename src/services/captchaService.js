/**
 * 图形验证码服务
 * 生成 SVG 验证码并提供一次性校验（登录前置人机校验）
 *
 * 存储说明：
 * - 经 sharedCache 门面存储（captchaId → { text }）：
 *   配置 REDIS_URL 时为跨实例共享（验证码请求被负载均衡到任一实例均可校验）；
 *   未配置时回退进程内内存（单机部署/开发/测试行为不变）。
 * - 条目自带过期时间（门面按 TTL 存储），容量上限由独立计数器保护。
 *
 * 安全语义：
 * - 一次性消费：verify 无论成功与否都删除记录，杜绝同一验证码重放/爆破
 * - 大小写不敏感比对，5 分钟有效
 * - 上限保护 + 过期清理，防止恶意刷取撑爆存储
 * - 全局上限之外再加**单 IP 活跃配额**，并把计数还给「成功生成 / 消费」：
 *   只靠全局上限时，分布式刷取可以把计数顶满，让所有用户的登录/注册验证码
 *   一起不可用（#8）；拒绝路径也不得计数，否则洪水本身会把上限维持住。
 *
 * 注意：generate/verify 自 R-3 起为异步 API（共享存储读取必须异步），
 * 调用方需 await。
 */

const crypto = require('crypto');
const svgCaptcha = require('svg-captcha');
const logger = require('../utils/logger');
const sharedCache = require('./sharedCache');

// 验证码配置
const CAPTCHA_CONFIG = {
  size: 4, // 4 位字符
  ignoreChars: '0o1iIlLIO', // 排除易混淆字符
  noise: 3, // 干扰线数量
  color: true, // 彩色字符
  background: '#f0f2f5', // 与登录页配色接近的浅底
  width: 120,
  height: 44,
  fontSize: 44,
};

const CAPTCHA_TTL_MS = 5 * 60 * 1000; // 有效期 5 分钟
const MAX_ACTIVE_ENTRIES = 10000; // 全局活跃上限（存储保护）
// 单 IP 活跃配额：把「打满全局」的成本从 ~167 个源地址（60 次/5 分钟/IP）
// 抬到 **500 个**（MAX_ACTIVE_ENTRIES / MAX_ACTIVE_ENTRIES_PER_IP = 10000 / 20）。
// 【2026-10-24 更正：原文写"上千个"，与这两个常量对不上】按 10000/20 算是 500；
// 且 20 小于 captchaLimiter 的 60 次/5 分钟，所以 20 才是先触发的那条 —— 两者
// 一起决定了"打满需要 500 个源、每个源 20 枚"。这个数字直接决定要不要继续加固，
// 写成两倍会让人低估风险。
// 正常用户同一时刻只需 1-2 枚，重试也有余量。
const MAX_ACTIVE_ENTRIES_PER_IP = 20;
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 过期清理周期

// 内存回退存储：仅未启用 Redis 时使用（captchaId → { text, ipKey, expiresAt }）
const localStore = new Map();
// 内存模式下的单 IP 活跃数（与 localStore 同生命周期，校验/过期时同步归还）
const localIpCounts = new Map();

// 清理定时器引用（由 startCaptchaCleanup 显式启动，模式同 securityAlert）
let cleanupTimer = null;
// 上限告警日志的节流时刻：指标每次都记，日志每分钟一条，避免洪水期自造日志风暴
let lastCapWarnAt = 0;

const entryKey = (captchaId) => `captcha:${captchaId}`;
const COUNT_KEY = 'captcha:active-count';
// 保留键判定：所有以 active-count 开头的 captchaId 都会撞进计数器键命名空间
// （全局键 captcha:active-count 与按 IP 键 captcha:active-count:ip:*）。
// 客户端可自由提交 captchaId，若不拦，verify 的 getDel 会删掉计数键（见 verify）。
// 合法 captchaId 恒为 crypto.randomUUID()，永不会取此值。
const collidesWithCountKey = (captchaId) => String(captchaId).startsWith('active-count');
// IP 只以摘要进入键名：避免把地址原文写进共享存储与日志，同时保持定长。
const ipScopeOf = (ip) => {
  const text = typeof ip === 'string' ? ip.trim() : '';
  return text ? crypto.createHash('sha256').update(text).digest('hex').slice(0, 16) : 'unknown';
};
const ipCountKey = (scope) => `captcha:active-count:ip:${scope}`;

/**
 * 启动过期验证码的定期清理（每 5 分钟一次）
 * 由 index.js 在启动时显式调用，避免模块加载即产生副作用。
 * Redis 模式下条目由存储自身过期，本定时器仅服务内存回退路径。
 */
const startCaptchaCleanup = () => {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(pruneLocal, CLEANUP_INTERVAL_MS);
  // 不阻塞 Node 进程退出（与 auditMonitor/securityAlert 同策略）
  cleanupTimer.unref?.();
};

/**
 * 停止定期清理（供优雅关闭调用）
 */
const stopCaptchaCleanup = () => {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
};

/**
 * 归还一条内存模式验证码占用的单 IP 配额。
 * 条目离开 localStore 的每条路径都要调用（校验消费 / 过期清理），否则配额只增不减。
 */
function releaseLocalIp(ipKey) {
  if (!ipKey) return;
  const remaining = (localIpCounts.get(ipKey) || 1) - 1;
  if (remaining > 0) localIpCounts.set(ipKey, remaining);
  else localIpCounts.delete(ipKey);
}

function pruneLocal() {
  const now = Date.now();
  for (const [key, value] of localStore.entries()) {
    if (value.expiresAt <= now) {
      localStore.delete(key);
      releaseLocalIp(value.ipKey);
    }
  }
}

/**
 * 活跃数上限判定被跳过时的统一信号出口（log + 安全告警计数）。
 *
 * 【为什么必须补这个信号，2026-10-09 实测】这条路径此前**一个信号都没有**：
 *   · 本函数 catch 里的 `logger.warn` 不可达（见下方注释，F-205 后门面返回 null 而不抛）；
 *   · 门面在「Redis 已就绪但命令抛错」时只打 `logger.debug`（sharedCache/index.js:330），
 *     而生产默认 `LOG_LEVEL=info`（utils/logger.js:85）⇒ **debug 根本不落盘**。
 * ⇒ 即「Redis 就绪但命令报错」期间，洪水护栏消失这件事在默认配置下**完全不可见**：
 *   没有日志、没有指标、没有告警。这正是本仓纪律所反对的形态
 *   （middleware/rateLimitStore.js:53-56：「降级态只写日志等于没有可告警信号——
 *   `grep 日志` 不是运维动作」；middleware/security/ipBlacklist.js:205 同口径）。
 *
 * 走 `incSecurityAlert` 与 `checkIPBlacklist` 的 ip_blacklist_failopen、
 * `makeSharedStore` 的 ratelimit_store_degraded **同一计数器**，因此被
 * deployment/observability/alert-rules.yml 的规则一并覆盖，不新造指标。
 *
 * 方向说明：这里补的是**信号**，不是把 fail-open 改成 fail-closed。
 * 「刻意不 fail-closed」是成文决策（见下方 catch 注释），本次不动它。
 */
const noteActiveBoundLost = () => {
  try {
    require('../utils/metrics').incSecurityAlert('captcha_active_bound_lost', 'high');
  } catch (_) {
    /* 指标端不可用不影响生成主流程 */
  }
  // 日志与指标都要：指标给告警，日志给现场（含键名与 TTL 口径）。
  // 不设「只告警一次」的标志位——本仓已吃过「一次性信号被当成持续信号」的亏
  // （middleware/rateLimitStore.js:66-79），而这里的调用频率受 captchaLimiter 约束。
  logger.warn(
    `验证码活跃数上限判定不可用（Redis 已启用但计数读取失败），本次不设上限：${COUNT_KEY}`
  );
};

/**
 * 活跃数达到上限时的统一信号出口（log + 安全告警计数）。
 * 指标每次都记（洪水期靠它看量级）；日志按分钟节流——被拒绝的请求本身
 * 可能每秒数百条，逐条 warn 会在告警之外再造一次日志风暴。
 */
const noteCapReached = (scope) => {
  try {
    require('../utils/metrics').incSecurityAlert(`captcha_${scope}_cap_reached`, 'high');
  } catch (_) {
    /* 指标端不可用不影响拒绝方向 */
  }
  const now = Date.now();
  if (now - lastCapWarnAt < 60 * 1000) return;
  lastCapWarnAt = now;
  const limit = scope === 'ip' ? MAX_ACTIVE_ENTRIES_PER_IP : MAX_ACTIVE_ENTRIES;
  logger.warn(
    `验证码活跃数已达${scope === 'ip' ? '单 IP' : '全局'}上限（${limit}），拒绝生成，疑似异常刷取`
  );
};

/**
 * Redis 模式下的双配额预占。
 *
 * 超限时必须把本次刚加上的那一格减回去：被拒绝的请求如果继续计数，
 * 计数器会被洪水本身越推越高（#8 的放大器），攻击停止后还要等满一个窗口。
 * 计数读取失败时与全局上限同一降级方向（放行）——验证码是登录前置，
 * Redis 抖动不该把合法用户挡在门外。
 *
 * @returns {Promise<{ok: boolean, reject?: 'ip'|'global'}>}
 */
const reserveRedisCapacity = async (ipKey) => {
  const perIp = await sharedCache.incrWithTtl(ipKey, CAPTCHA_TTL_MS);
  if (perIp === null) {
    noteActiveBoundLost();
    return { ok: true };
  }
  if (perIp > MAX_ACTIVE_ENTRIES_PER_IP) {
    await sharedCache.decrWithFloorZero(ipKey);
    return { ok: false, reject: 'ip' };
  }

  const active = await sharedCache.incrWithTtl(COUNT_KEY, CAPTCHA_TTL_MS);
  if (active === null) {
    await sharedCache.decrWithFloorZero(ipKey);
    noteActiveBoundLost();
    return { ok: true };
  }
  if (active > MAX_ACTIVE_ENTRIES) {
    await sharedCache.decrWithFloorZero(ipKey);
    await sharedCache.decrWithFloorZero(COUNT_KEY);
    return { ok: false, reject: 'global' };
  }
  return { ok: true };
};

/**
 * 生成验证码
 * @param {{ ip?: string }} [options] 客户端来源 IP（用于单 IP 活跃配额；缺省归入 unknown 桶）
 * @returns {Promise<{ captchaId: string, svg: string } | null>} 超出上限时返回 null
 */
const generate = async ({ ip } = {}) => {
  const ipKey = ipCountKey(ipScopeOf(ip));
  const redis = sharedCache.isRedisEnabled();

  if (redis) {
    const reserved = await reserveRedisCapacity(ipKey);
    if (!reserved.ok) {
      noteCapReached(reserved.reject);
      return null;
    }
  } else {
    // 先清过期再判：否则「过期条目占着配额」会把合法用户挡在上限外
    pruneLocal();
    if ((localIpCounts.get(ipKey) || 0) >= MAX_ACTIVE_ENTRIES_PER_IP) {
      noteCapReached('ip');
      return null;
    }
    if (localStore.size >= MAX_ACTIVE_ENTRIES) {
      noteCapReached('global');
      return null;
    }
  }

  const captcha = svgCaptcha.create(CAPTCHA_CONFIG);
  const captchaId = crypto.randomUUID();
  const entry = { text: captcha.text, ipKey };

  if (redis) {
    // TTL 带抖动：避免大批验证码同一时刻过期（O-15）；一次性语义不受影响
    await sharedCache.set(entryKey(captchaId), entry, sharedCache.jitterTtl(CAPTCHA_TTL_MS));
  } else {
    localStore.set(captchaId, { ...entry, expiresAt: Date.now() + CAPTCHA_TTL_MS });
    localIpCounts.set(ipKey, (localIpCounts.get(ipKey) || 0) + 1);
  }

  return { captchaId, svg: captcha.data };
};

/**
 * 校验验证码（一次性消费：无论成败都删除，防止重放）
 * @param {string} captchaId 验证码 ID
 * @param {string} inputText 用户输入
 * @returns {Promise<boolean>}
 */
const verify = async (captchaId, inputText) => {
  if (!captchaId || !inputText) return false;

  // 保留键闸门（须在触存储之前）：captchaId 以 'active-count' 开头会让
  // entryKey 撞上全局或按 IP 的活跃计数键，getDel 把它删掉 → generate 的
  // 洪水面护栏被反复重置归零。合法 captchaId 恒为 UUID，
  // 故此闸门不误伤真实流程，仅把该越界值按「校验失败」fail-closed 处理。
  if (collidesWithCountKey(captchaId)) return false;

  if (sharedCache.isRedisEnabled()) {
    // 评价报告低危项：原 get→del 两步在并发下同一验证码可被消费两次（双花）。
    // 改用原子取删 GETDEL（sharedCache.getDel）：取值与删除在同一命令内完成。
    const entry = await sharedCache.getDel(entryKey(captchaId)).catch(() => null);
    if (!entry) return false;
    // 条目已离开存储 ⇒ 无论比对结果如何，都要归还它占用的双配额
    await sharedCache.decrWithFloorZero(COUNT_KEY);
    if (entry.ipKey) await sharedCache.decrWithFloorZero(entry.ipKey);
    if (typeof entry.text !== 'string') return false;
    return String(inputText).trim().toLowerCase() === entry.text.toLowerCase();
  }

  const entry = localStore.get(captchaId);
  localStore.delete(captchaId);

  if (!entry) return false; // 不存在（已用过/不存在）
  releaseLocalIp(entry.ipKey);
  if (Date.now() > entry.expiresAt) return false; // 已过期

  return String(inputText).trim().toLowerCase() === entry.text.toLowerCase();
};

/** 测试钩子：清空本地回退存储 */
const _resetForTests = () => {
  localStore.clear();
  localIpCounts.clear();
  lastCapWarnAt = 0;
};

module.exports = {
  generate,
  verify,
  startCaptchaCleanup,
  stopCaptchaCleanup,
  _resetForTests,
};
