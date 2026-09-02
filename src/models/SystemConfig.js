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
    // 值的类型，用于反序列化
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
    // 是否允许通过 API 修改
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
  _allowRegistrationCache = doc ? !!doc.value : false;
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
  _loginCaptchaCache = doc ? !!doc.value : false;
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
// 管理员在后台设置后以数据库值为准；DB 故障时降级到静态配置（fail-open 以静态默认）
let _registerCaptchaCache = null;
let _registerCaptchaCacheExpiresAt = 0;

systemConfigSchema.statics.isRegisterCaptchaEnabled = async function () {
  const now = Date.now();
  if (_registerCaptchaCache !== null && _registerCaptchaCacheExpiresAt > now) {
    return _registerCaptchaCache;
  }

  const doc = await this.findOne({ key: 'registerCaptchaEnabled' }).lean();
  // 未落库时回退到 env 静态默认（与登录验证码默认 false 不同——注册接口默认强校验）
  const fallback = require('../config').registerCaptchaEnabled;
  _registerCaptchaCache = doc ? !!doc.value : !!fallback;
  _registerCaptchaCacheExpiresAt = now + CACHE_TTL;
  return _registerCaptchaCache;
};

// 清除注册验证码开关缓存（修改后调用）
systemConfigSchema.statics.invalidateRegisterCaptchaCache = function () {
  _registerCaptchaCache = null;
  _registerCaptchaCacheExpiresAt = 0;
};

const SystemConfig = mongoose.model('SystemConfig', systemConfigSchema);

module.exports = SystemConfig;
