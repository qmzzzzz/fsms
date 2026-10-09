/**
 * 系统配置模型
 * 持久化系统级开关设置（如注册开关），支持运行时动态修改
 */

const mongoose = require('mongoose');

const systemConfigSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      // unique 已隐式创建唯一索引，不再重复声明 index:true（避免冗余索引）
      unique: true,
    },
    value: {
      type: mongoose.Schema.Types.Mixed,
      required: true,
    },
    // 值的类型标签。由 set() 按传入值的 JS 类型派生写入，
    // **读取侧不依赖它做反序列化**（Mixed 本身就带 BSON 类型）；
    // 布尔开关的可读性由 toConfigBoolean 负责，不要指望这里。
    valueType: {
      type: String,
      enum: ['boolean', 'string', 'number', 'json'],
      default: 'string',
    },
    // 配置描述
    description: {
      type: String,
      default: '',
    },
    // 预留位：当前**没有任何执行点读取它**（全仓 grep 无消费方），
    // set() 也不会因此拒绝写入。要真正变成一道闸，需要连同
    // securityController 的写回路径一起设计，别把它当成已生效的保护。
    modifiable: {
      type: Boolean,
      default: true,
    },
    // 最后修改者
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true,
  }
);

// get() 的进程内缓存：TTL 30 秒，同一 key 在窗口内只查一次库；
// set() 写入后会失效对应 key，缓存窗口内最多读到 30 秒前的旧值（配置类数据可接受）
const GET_CACHE_TTL_MS = 30 * 1000;
const GET_CACHE_MAX_ENTRIES = 500;
const getCache = new Map(); // key -> { value, expireAt, missing }

// 用于区分「缓存了 undefined 值」与「缓存了不存在」的哨兵
const MISSING = Symbol('config-missing');

// 布尔型配置的解释口径（三个开关共用一份，避免各写一遍各漏一处）
//
// 为什么不能直接 `!!doc.value`：value 是 Mixed，落库形态不止 boolean。
// 运维修配置最常见的是直连库改值（`$set: {value: 'false'}`），
// 而 `'false'` 的非空字符串真值是 **true** —— 于是
// `allowPublicRegistration='false'` 会得到"公开注册已开启"，
// 一个想关闸的动作反而把闸打开，且没有任何报错。方向恰好是最危险的那种：
// 越权写入面（公开注册 + GUEST 角色）静默打开。
// 这里显式认常见写法，认不出来的按 fallback（开关类默认关）。
const CONFIG_TRUTHY = new Set(['true', '1', 'yes', 'on']);
const CONFIG_FALSY = new Set(['false', '0', 'no', 'off', '']);

const toConfigBoolean = (value, fallback = false) => {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) && value !== 0;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (CONFIG_FALSY.has(normalized)) return false;
    if (CONFIG_TRUTHY.has(normalized)) return true;
    return fallback;
  }
  // null / undefined / 数组 / 对象：不是布尔配置该有的形态，按 fallback
  return fallback;
};

// 静态方法：获取配置值（带 30 秒进程内缓存）
//
// P3-22 负缓存：key 不存在时同样进缓存。原实现只在 `doc` 存在时写缓存，
// 于是「查询一个未初始化的配置项」每次都打库——而这恰好是最高频的路径：
// isRegistrationAllowed / isLoginCaptchaEnabled 在配置未落库时（全新部署、
// 或配置被手工删除）会在每个登录请求上产生一次 findOne。
// 负缓存同样受 TTL 约束，配置补齐后最多 30 秒生效。
systemConfigSchema.statics.get = async function (key, defaultValue = null) {
  const now = Date.now();
  const cached = getCache.get(key);
  if (cached && cached.expireAt > now) {
    return cached.value === MISSING ? defaultValue : cached.value;
  }

  const doc = await this.findOne({ key }).lean();

  // 容量上限保护：超限整体清空，避免极端情况下缓存无界增长
  if (getCache.size >= GET_CACHE_MAX_ENTRIES) getCache.clear();

  if (!doc) {
    // 负缓存：记录「该 key 不存在」，避免每次调用都打库。
    // 注意存 MISSING 哨兵而非 defaultValue——不同调用方可能传不同默认值，
    // 缓存 defaultValue 会让第二个调用方拿到第一个调用方的默认值
    getCache.set(key, { value: MISSING, expireAt: now + GET_CACHE_TTL_MS });
    return defaultValue;
  }

  getCache.set(key, { value: doc.value, expireAt: now + GET_CACHE_TTL_MS });
  return doc.value;
};

// 静态方法：设置配置值
systemConfigSchema.statics.set = async function (key, value, userId = null) {
  const valueType =
    typeof value === 'boolean'
      ? 'boolean'
      : typeof value === 'number'
        ? 'number'
        : typeof value === 'object' && value !== null
          ? 'json'
          : 'string';

  const update = { value, valueType };
  // 未传 userId 时从 $set 中剔除 updatedBy 键：
  // 显式传 undefined 会把已有的 updatedBy 覆写成 null，导致修改人信息丢失
  if (userId) update.updatedBy = userId;

  const result = await this.findOneAndUpdate(
    { key },
    { $set: update },
    { upsert: true, new: true }
  );

  // 写入成功后失效对应缓存；注册开关/登录验证码开关有各自的派生布尔缓存，一并失效
  getCache.delete(key);
  if (key === 'allowPublicRegistration') this.invalidateRegistrationCache();
  if (key === 'loginCaptchaEnabled') this.invalidateLoginCaptchaCache();
  if (key === 'registerCaptchaEnabled') this.invalidateRegisterCaptchaCache();

  return result;
};

// 静态方法：获取注册开关状态（带内存缓存）
let _allowRegistrationCache = null;
let _cacheExpiresAt = 0;
const CACHE_TTL = 30 * 1000; // 30 秒缓存

systemConfigSchema.statics.isRegistrationAllowed = async function () {
  const now = Date.now();
  if (_allowRegistrationCache !== null && _cacheExpiresAt > now) {
    return _allowRegistrationCache;
  }

  const doc = await this.findOne({ key: 'allowPublicRegistration' }).lean();
  // 未落库=关；落库值按统一布尔口径解释（'false' 不得被 !! 读成开）
  _allowRegistrationCache = doc ? toConfigBoolean(doc.value, false) : false;
  _cacheExpiresAt = now + CACHE_TTL;
  return _allowRegistrationCache;
};

// 清除缓存（修改后调用）
systemConfigSchema.statics.invalidateRegistrationCache = function () {
  _allowRegistrationCache = null;
  _cacheExpiresAt = 0;
};

// 静态方法：获取登录验证码开关状态（带内存缓存，默认关闭）
let _loginCaptchaCache = null;
let _loginCaptchaCacheExpiresAt = 0;

systemConfigSchema.statics.isLoginCaptchaEnabled = async function () {
  const now = Date.now();
  if (_loginCaptchaCache !== null && _loginCaptchaCacheExpiresAt > now) {
    return _loginCaptchaCache;
  }

  const doc = await this.findOne({ key: 'loginCaptchaEnabled' }).lean();
  _loginCaptchaCache = doc ? toConfigBoolean(doc.value, false) : false;
  _loginCaptchaCacheExpiresAt = now + CACHE_TTL;
  return _loginCaptchaCache;
};

// 清除登录验证码开关缓存（修改后调用）
systemConfigSchema.statics.invalidateLoginCaptchaCache = function () {
  _loginCaptchaCache = null;
  _loginCaptchaCacheExpiresAt = 0;
};

// 静态方法：获取注册验证码开关状态（带内存缓存）
// 默认值取静态配置 config.registerCaptchaEnabled（env REGISTER_CAPTCHA_ENABLED，默认 true），
// 管理员在后台设置后以数据库值为准；**配置未落库**（doc 为 null）时用静态默认。
//
// 【2026-10-09 就地更正】本行原写作「DB 故障时降级到静态配置（fail-open 以静态默认）」——
// **与实现不符**：`isRegisterCaptchaEnabled` / `isLoginCaptchaEnabled` 都没有 try/catch，
// `findOne` 在 DB 故障时直接 reject，降级不在本文件发生，而在各调用点。
// 该表述之所以危险：它让人以为「DB 故障 → 一定有静态默认」，于是没人去问
// 「降级动作的信号在哪」——实测答案是 3 个调用点各复刻一份 try/catch、全都没有信号。
// 现已收口到 `captchaSwitch(kind)`（见下），信号为
// security_alerts_total{type=captcha_switch_db_fallback}。
let _registerCaptchaCache = null;
let _registerCaptchaCacheExpiresAt = 0;

systemConfigSchema.statics.isRegisterCaptchaEnabled = async function () {
  const now = Date.now();
  if (_registerCaptchaCache !== null && _registerCaptchaCacheExpiresAt > now) {
    return _registerCaptchaCache;
  }

  const doc = await this.findOne({ key: 'registerCaptchaEnabled' }).lean();
  // 未落库时回退到 env 静态默认（与登录验证码默认 false 不同——注册接口默认强校验）
  const fallback = toConfigBoolean(require('../config').registerCaptchaEnabled, false);
  _registerCaptchaCache = doc ? toConfigBoolean(doc.value, fallback) : fallback;
  _registerCaptchaCacheExpiresAt = now + CACHE_TTL;
  return _registerCaptchaCache;
};

// 清除注册验证码开关缓存（修改后调用）
systemConfigSchema.statics.invalidateRegisterCaptchaCache = function () {
  _registerCaptchaCache = null;
  _registerCaptchaCacheExpiresAt = 0;
};

/**
 * 验证码开关降级（DB 故障 → 静态配置）的**统一信号出口**。
 *
 * 【为什么要有它，2026-10-09 实测】「DB 故障时降级到静态配置」这句注释原先写在
 * `isRegisterCaptchaEnabled` 上方（见下），但**降级根本不发生在那两个函数里**——
 * 它们没有 try/catch，`findOne` 在 DB 故障时直接 reject。真正做降级的是**调用点**，
 * 而同一个 try/catch 曾被复刻了 **3 份**：
 *   · `authService.registerUser`
 *   · `authService.resolveLoginPassword`（loginUser 链）
 *   · `authController.getCaptchaStatus`
 * ⇒ 「降级到静态默认」这个安全相关的 fail-open 动作**没有任何统一信号**，
 *   只有 3 个各自的空 catch。本仓纪律见 middleware/rateLimitStore.js:53-56：
 *   「降级态只写日志等于没有可告警信号——`grep 日志` 不是运维动作」。
 * 现已收口：3 处一律改调本文件下方的 `SystemConfig.captchaSwitch(kind)`，
 * 降级判定与信号都只在那一个函数里发生，调用点不再自带 try/catch。
 * （这里刻意只写函数名、不写被删代码的行号——那几行已不存在，行号锚点会变成误导。）
 *
 * 严重度定 medium 而非 high：验证码只是登录链的**前置层**，降级后
 * loginLimiter（凭据型限流）与暴力破解检测仍在，不是「全站裸奔」；
 * 与 ip_blacklist_failopen 的 high 不同级（那个降级后黑名单整层失效）。
 *
 * @param {'login'|'register'} kind 哪个开关
 */
const signalCaptchaSwitchFallback = (kind) => {
  try {
    require('../utils/metrics').incSecurityAlert('captcha_switch_db_fallback', 'medium');
  } catch (_) {
    /* 指标端不可用不影响开关读取 */
  }
  try {
    require('../utils/logger').warn(
      `验证码开关读取失败，降级为静态配置（fail-open）：${kind}CaptchaEnabled`
    );
  } catch (_) {
    /* 日志端不可用不影响开关读取 */
  }
};

/**
 * 验证码开关的统一读取口径：**带静态默认兜底 + 降级信号**。
 *
 * 语义与原先 3 处复刻的 try/catch **逐字等价**（同样的静态默认值、同样吞掉异常、
 * 同样不抛），只是把降级动作收敛到一处并补上信号。保留 `isLoginCaptchaEnabled` /
 * `isRegisterCaptchaEnabled` 的 30 秒缓存不变（本函数只是它们的兜底包装）。
 *
 * 调用方应改用本函数；直接调用 `isLoginCaptchaEnabled` / `isRegisterCaptchaEnabled`
 * 会让 DB 故障直接冒泡（那两个函数不吞异常），是否要 fail-open 就成了每个调用点
 * 各自的决定——那正是本次要收口的东西。
 *
 * @param {'login'|'register'} kind
 * @returns {Promise<boolean>} 开关值；DB 故障时返回静态默认
 */
systemConfigSchema.statics.captchaSwitch = async function (kind) {
  const cfg = require('../config');
  const fallback =
    kind === 'login'
      ? toConfigBoolean(cfg.loginCaptchaEnabled, false)
      : toConfigBoolean(cfg.registerCaptchaEnabled, false);
  try {
    return kind === 'login'
      ? await this.isLoginCaptchaEnabled()
      : await this.isRegisterCaptchaEnabled();
  } catch (_) {
    signalCaptchaSwitchFallback(kind);
    return fallback;
  }
};

const SystemConfig = mongoose.model('SystemConfig', systemConfigSchema);

// 供测试直接驱动布尔解释口径（与 utils/logger 的 __test 同一约定）：
// 走 DB 的用例要覆盖"存进去的形态"，而纯函数这层能确定性覆盖全部取值形态
SystemConfig.__test = { toConfigBoolean };

module.exports = SystemConfig;
