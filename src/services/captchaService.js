/**
 * 图形验证码服务
 * 生成 SVG 验证码并提供一次性校验（登录前置人机校验）
 *
 * 存储说明（R-3/M-1）：
 * - 经 sharedCache 门面存储（captchaId → { text }）：
 *   配置 REDIS_URL 时为跨实例共享（验证码请求被负载均衡到任一实例均可校验）；
 *   未配置时回退进程内内存（单机部署/开发/测试行为不变）。
 * - 条目自带过期时间（门面按 TTL 存储），容量上限由独立计数器保护。
 *
 * 安全语义：
 * - 一次性消费：verify 无论成功与否都删除记录，杜绝同一验证码重放/爆破
 * - 大小写不敏感比对，5 分钟有效
 * - 上限保护 + 过期清理，防止恶意刷取撑爆存储
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
const MAX_ACTIVE_ENTRIES = 10000; // 活跃上限保护
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 过期清理周期

// 内存回退存储：仅未启用 Redis 时使用（captchaId → { text, expiresAt }）
const localStore = new Map();

// 清理定时器引用（由 startCaptchaCleanup 显式启动，模式同 securityAlert）
let cleanupTimer = null;

const entryKey = (captchaId) => `captcha:${captchaId}`;
const COUNT_KEY = 'captcha:active-count';
// 保留键判定：entryKey(x) === COUNT_KEY 当且仅当 x === 'active-count'。
// 客户端可自由提交 captchaId，若不拦此值，verify 的 getDel 会删掉活跃计数键
// （见 verify）。合法 captchaId 恒为 crypto.randomUUID()，永不会取此值。
const collidesWithCountKey = (captchaId) => entryKey(String(captchaId)) === COUNT_KEY;

/**
 * 启动过期验证码的定期清理（每 5 分钟一次）
 * 由 index.js 在启动时显式调用，避免模块加载即产生副作用。
 * Redis 模式下条目由存储自身过期，本定时器仅服务内存回退路径。
 */
const startCaptchaCleanup = () => {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, value] of localStore.entries()) {
      if (value.expiresAt <= now) {
        localStore.delete(key);
      }
    }
  }, CLEANUP_INTERVAL_MS);
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

function pruneLocal() {
  const now = Date.now();
  for (const [key, value] of localStore.entries()) {
    if (value.expiresAt <= now) localStore.delete(key);
  }
}

/**
 * 生成验证码
 * @returns {Promise<{ captchaId: string, svg: string } | null>} 超出上限时返回 null
 */
const generate = async () => {
  // 上限保护：活跃计数（窗口=验证码 TTL）超限即拒绝，防恶意刷取撑爆存储
  let active;
  try {
    active = await sharedCache.incrWithTtl(COUNT_KEY, CAPTCHA_TTL_MS);
  } catch (err) {
    // 计数器不可用时的真实行为，按模式分两种，别写成一种口径：
    //  - 内存模式：上限判据本来就是 localStore.size，与计数器无关 ⇒ 等价于"照常按内存判"；
    //  - Redis 模式：拿不到计数就**没有**上限判定可用（active===null 时下面那个分支放行），
    //    此时洪水保护只剩 captchaLimiter（60 次/5 分钟/IP）与条目 TTL 两层。
    // 刻意不 fail-closed：验证码是登录前置，Redis 抖动不该把合法用户挡在门外。
    // F-205 之后这条 catch 实际上到不了：门面在「Redis 启用但命令抛错」时不再回退
    // 进程内计数，而是**如实返回 null**（走上面的 active===null 分支）。留着是因为
    // 成本为零、方向明确（门面内部若改成抛错，这里的行为仍然是上面写的那两种）。
    logger.warn(`验证码计数器异常，本次不启用活跃数上限判定：${err.message}`);
    active = null;
  }

  if (sharedCache.isRedisEnabled()) {
    if (active !== null && active > MAX_ACTIVE_ENTRIES) {
      logger.warn(`验证码存储已达上限（${MAX_ACTIVE_ENTRIES}），拒绝生成，疑似异常刷取`);
      return null;
    }
  } else {
    if (localStore.size >= MAX_ACTIVE_ENTRIES) {
      pruneLocal();
      if (localStore.size >= MAX_ACTIVE_ENTRIES) {
        logger.warn(`验证码存储已达上限（${MAX_ACTIVE_ENTRIES}），拒绝生成，疑似异常刷取`);
        return null;
      }
    }
  }

  const captcha = svgCaptcha.create(CAPTCHA_CONFIG);
  const captchaId = crypto.randomUUID();
  const entry = { text: captcha.text };

  if (sharedCache.isRedisEnabled()) {
    // TTL 带抖动：避免大批验证码同一时刻过期（O-15）；一次性语义不受影响
    await sharedCache.set(entryKey(captchaId), entry, sharedCache.jitterTtl(CAPTCHA_TTL_MS));
  } else {
    localStore.set(captchaId, { ...entry, expiresAt: Date.now() + CAPTCHA_TTL_MS });
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

  // 保留键闸门（须在触存储之前）：Redis 模式下 captchaId='active-count' 会让
  // entryKey 正好撞上活跃计数键 COUNT_KEY，getDel 把它删掉 → generate 的
  // MAX_ACTIVE_ENTRIES 洪水面护栏被反复重置归零。合法 captchaId 恒为 UUID，
  // 故此闸门不误伤真实流程，仅把该越界值按「校验失败」fail-closed 处理。
  if (collidesWithCountKey(captchaId)) return false;

  if (sharedCache.isRedisEnabled()) {
    // 评价报告低危项：原 get→del 两步在并发下同一验证码可被消费两次（双花）。
    // 改用原子取删 GETDEL（sharedCache.getDel）：取值与删除在同一命令内完成。
    const entry = await sharedCache.getDel(entryKey(captchaId)).catch(() => null);
    if (!entry || typeof entry.text !== 'string') return false;
    return String(inputText).trim().toLowerCase() === entry.text.toLowerCase();
  }

  const entry = localStore.get(captchaId);
  localStore.delete(captchaId);

  if (!entry) return false; // 不存在（已用过/不存在）
  if (Date.now() > entry.expiresAt) return false; // 已过期

  return String(inputText).trim().toLowerCase() === entry.text.toLowerCase();
};

/** 测试钩子：清空本地回退存储 */
const _resetForTests = () => {
  localStore.clear();
};

module.exports = {
  generate,
  verify,
  startCaptchaCleanup,
  stopCaptchaCleanup,
  _resetForTests,
};
