/**
 * 用户登录会话模型（设备级会话管理）
 *
 * 解决的问题：此前系统只有 tokenVersion 一种吊销手段，而它是**全局**的 ——
 * 递增即让该用户所有设备一起掉线。于是：
 *   1. 用户看不到「我的账号正在哪些设备上登录」，被盗号也无从察觉；
 *   2. 想踢掉一台可疑设备，只能改密码把自己所有设备一起踢下线；
 *   3. 审计日志里的 sessionId 无处可查（没有会话注册表与之对应）。
 *
 * 本模型为每次登录建立一条会话记录，令牌里携带稳定的 sid 指向它。
 * 吊销粒度从此有两级：
 *   - 单会话：把该条置为 revoked，只有那台设备掉线（本模型提供）
 *   - 全局  ：tokenVersion 递增，所有设备掉线（改密/重放检测保留）
 *
 * 为什么不用 TokenBlacklist 承担这件事：
 *   黑名单按 tokenHash 记录**单个令牌**。access token 每 2 小时经 refresh
 *   轮换一次，同一台设备在会话存续期内会产生几十个不同的 token —— 拉黑
 *   其中一个毫无意义（下一次轮换就换新的）。设备级吊销必须绑定一个
 *   跨轮换保持不变的标识，这正是 sid 的作用。
 *
 * 单进程假设说明（见 constants/runtime.js）：本模型状态在 MongoDB，
 * 不依赖进程内存；仅 sessionService 的校验缓存是进程内的（TTL 15s），
 * 多进程部署时单设备吊销最长延迟 15 秒生效，不会失效。
 */

const mongoose = require('mongoose');

const userSessionSchema = new mongoose.Schema({
  /**
   * 会话标识（令牌 sid claim 的值）
   *
   * 与 jti 的区别：jti 每次签发都不同（refresh 轮换靠它保证令牌唯一），
   * sid 在整个会话生命周期内**恒定**。混用两者会让「吊销这台设备」
   * 在下一次令牌轮换后自动失效。
   */
  sid: {
    type: String,
    required: true,
    unique: true,
  },

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },

  /** 会话状态：active=可用；revoked=已吊销（单设备下线）；expired=自然过期 */
  status: {
    type: String,
    enum: ['active', 'revoked', 'expired'],
    default: 'active',
    index: true,
  },

  // ===== 设备识别信息（供用户辨认「这是哪台设备」）=====
  /**
   * 原始 User-Agent（截断存储）
   *
   * 同时保留原始 UA 与解析后的 device/browser/os：解析规则会随浏览器
   * 版本演进而失准，保留原文才能在事后重新解析或人工判断。
   */
  userAgent: {
    type: String,
    maxlength: 512,
  },
  /** 解析出的设备类型：desktop / mobile / tablet / bot / unknown（含 ua-parser-js 的 console/smarttv/wearable/embedded） */
  deviceType: {
    type: String,
    default: 'unknown',
  },
  /** 浏览器名称（如 Chrome / Safari / Edge / WeChat） */
  browser: {
    type: String,
    default: '',
  },
  /**
   * 浏览器主版本号（如 '120'）
   *
   * 只存主版本而非完整版本串：会话列表要的是「Chrome 120」这种可读粒度，
   * 完整的 120.0.6099.130 既占位又无助于用户认出设备。
   * 同时它还有安全用途：用户看到「Chrome 87」这种远低于自己在用版本的条目，
   * 就有理由怀疑那是伪造 UA 的脚本而非自己的浏览器。
   */
  browserVersion: {
    type: String,
    default: '',
  },
  /** 操作系统（如 Windows / macOS / Android / iOS / HarmonyOS） */
  os: {
    type: String,
    default: '',
  },
  /** 操作系统版本（如 '10'、'17.0'）——同一台机器升级系统后可据此察觉变化 */
  osVersion: {
    type: String,
    default: '',
  },
  /**
   * 设备厂商与型号（如 Apple / iPhone、Xiaomi / 13）
   *
   * 这两个字段是「认出自己设备」最有效的线索：账号在多台 Android 上登录时，
   * 「Chrome · Android」三条并排毫无区分度，而「Xiaomi 13 / Samsung SM-G991B」
   * 用户一眼就知道哪台不是自己的。桌面浏览器通常解析不出，留空即可。
   */
  deviceVendor: {
    type: String,
    default: '',
  },
  deviceModel: {
    type: String,
    default: '',
  },
  /**
   * 渲染引擎与 CPU 架构（Blink/WebKit/Gecko，amd64/arm64）
   *
   * 对普通用户价值有限，但在核查可疑登录时有用：伪造的 UA 常出现
   * 「引擎与浏览器不匹配」这类内部矛盾（如自称 Chrome 却是 Gecko 引擎）。
   * 列表默认折叠，仅展开详情时呈现。
   */
  engine: {
    type: String,
    default: '',
  },
  cpu: {
    type: String,
    default: '',
  },

  // ===== 网络信息 =====
  /**
   * 登录时的 IP（完整值）
   *
   * 刻意存完整 IP 而非脱敏值：会话列表的核心用途是让用户判断
   * 「这次登录是不是我」，脱敏成 192.168.*.* 后同一网段的可疑登录
   * 与本人登录无法区分，功能等于失效。该字段仅本人与安全管理员可读。
   */
  ip: {
    type: String,
    maxlength: 64,
  },
  /** 最近一次活动的 IP（会话期间换网络会变化，突变是可疑信号） */
  lastIp: {
    type: String,
    maxlength: 64,
  },
  /**
   * 会话指纹（utils/fingerprint.computeFingerprint 的输出）
   * 同一 sid 下指纹突变 → 令牌可能被窃用（换设备/换网络重放）
   */
  fingerprint: {
    type: String,
    index: true,
    sparse: true,
  },

  // ===== 时间线 =====
  createdAt: {
    type: Date,
    default: Date.now,
  },
  /**
   * 最近活动时间
   *
   * 由 authenticate 中间件节流更新（默认 60s 内最多写一次）：
   * 每请求都写会把一个只读中间件变成写路径，高频接口下等于给每个
   * 请求附加一次数据库写入。
   */
  lastSeenAt: {
    type: Date,
    default: Date.now,
  },
  /** 会话自然过期时间（按 refresh token 有效期计算），TTL 索引据此自动清理 */
  expiresAt: {
    type: Date,
    required: true,
  },
  /** 吊销时间（status=revoked 时有值） */
  revokedAt: {
    type: Date,
    default: null,
  },
  /**
   * 吊销原因，用于事后追溯「这台设备为什么掉线」
   * logout=本设备主动登出；user_revoked=用户从会话列表踢除；
   * admin_revoked=管理员强制下线；password_changed=改密全局吊销；
   * token_reuse=refresh 重放检测；superseded=同设备重新登录顶掉旧会话
   */
  revokeReason: {
    type: String,
    default: null,
  },
});

/**
 * TTL 索引：会话自然过期后由 MongoDB 自动删除
 *
 * 与 status='expired' 的分工：TTL 负责物理清理（避免集合无限增长），
 * status 用于「已过期但还没被清理」这段窗口内的语义判断。
 * 不能只依赖 TTL —— MongoDB 的 TTL 线程每 60 秒扫一次，
 * 过期后仍可能存在最长 1 分钟的可见窗口。
 */
userSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

/** 会话列表查询：按用户 + 状态过滤，按最近活动倒序 */
userSessionSchema.index({ userId: 1, status: 1, lastSeenAt: -1 });

/**
 * 判断会话当前是否仍可用于认证
 *
 * 三个条件都必须满足；expiresAt 的判断不能省略，理由见 TTL 索引的注释
 * （TTL 清理有延迟，过期文档仍可能被查到）。
 * @returns {boolean}
 */
userSessionSchema.methods.isUsable = function () {
  if (this.status !== 'active') return false;
  if (!this.expiresAt) return false;
  return this.expiresAt.getTime() > Date.now();
};

/** 对外脱敏输出：不暴露 fingerprint（内部风控字段，对用户无意义且是可关联标识） */
userSessionSchema.methods.toClientJSON = function (currentSid = null) {
  return {
    sid: this.sid,
    current: this.sid === currentSid,
    deviceType: this.deviceType,
    browser: this.browser,
    browserVersion: this.browserVersion,
    os: this.os,
    osVersion: this.osVersion,
    deviceVendor: this.deviceVendor,
    deviceModel: this.deviceModel,
    engine: this.engine,
    cpu: this.cpu,
    // 原始 UA 对本人可见：核查可疑登录时它是最终依据（解析结果可能失准，
    // 原文不会）。它不是他人隐私——就是这条会话自己的请求头，
    // 且本端点只返回请求者自己的会话。
    userAgent: this.userAgent,
    ip: this.ip,
    lastIp: this.lastIp,
    createdAt: this.createdAt,
    lastSeenAt: this.lastSeenAt,
    expiresAt: this.expiresAt,
  };
};

module.exports = mongoose.model('UserSession', userSessionSchema);
