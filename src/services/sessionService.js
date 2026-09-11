/**
 * 用户会话服务（设备级会话管理）
 *
 * 职责边界：
 *  - 本模块是「会话生命周期」的唯一事实来源（创建/校验/触碰/吊销/列举）；
 *  - 控制器与中间件只调用本模块，不直接操作 UserSession 集合，
 *    避免吊销语义散落到多处后各自漂移（tokenVersion 的教训就在这里：
 *    它被 3 个文件分别递增，语义靠注释维持）。
 *
 * 设备解析改用 ua-parser-js（原为手写正则）：
 *   会话列表的核心用途是让用户判断「这次登录是不是我」。手写正则只能给出
 *   Chrome/Windows 这种粒度，而两条「Chrome · Windows」并排时用户无法区分
 *   哪台是自己的办公机、哪台是陌生设备——功能等于打了对折。ua-parser-js
 *   能给出版本号与设备厂商/型号（如 Chrome 120 · Windows 10 / Apple iPhone），
 *   这才够用户下判断。
 *
 *   固定版本 1.0.41（MIT）而非 2.x：2.x 起主包改为 AGPL-3.0-or-later，
 *   对闭源部署有传染性许可风险；且 2.x 引入 3 个运行时依赖，
 *   而 1.x 是零依赖单文件。安全上也更可控（供应链面更小）。
 *   写死精确版本而非 ^ 范围：该包历史上出过被投毒的补丁版本（2021 年
 *   0.7.29/0.8.0/1.0.0 三个版本被植入挖矿与窃密代码），锁死版本可避免
 *   自动升级到未经审查的补丁号。
 *
 *   原始 UA 仍完整保留：解析规则会随浏览器版本演进而失准，保留原文才能
 *   在事后重新解析或人工判断。
 */

const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const logger = require('../utils/logger');
const UserSession = require('../models/UserSession');
const { computeFingerprint } = require('../utils/fingerprint');
const { durationToMs } = require('../utils/cookie');
const config = require('../config');

/**
 * 会话校验缓存（进程内，短 TTL）
 *
 * 为什么需要：authenticate 是**每个**请求都会经过的路径，若每次都查
 * UserSession，等于给所有接口加一次数据库往返。既有的用户缓存
 * （middleware/auth.js userCache，TTL 60s）已经是同样的思路。
 *
 * 为什么 TTL 取 15 秒而非 60 秒：这是「单设备吊销的生效延迟」上限。
 * 用户点了「踢除该设备」却发现对方还能操作一分钟，会认为功能没生效；
 * 15 秒足够短到符合预期，又能挡掉绝大部分重复查询。
 * 且吊销路径会主动 invalidate（见 revokeSession），正常情况下即时生效——
 * TTL 只是多进程部署时的兜底上限。
 */
const sessionCache = new Map();
const SESSION_CACHE_TTL = 15 * 1000;
const SESSION_CACHE_MAX = 5000;

/** lastSeenAt 写入节流窗口：同一会话 60 秒内最多更新一次 */
const TOUCH_THROTTLE_MS = 60 * 1000;
/** 最近一次 touch 的时刻（sid -> ms），仅用于节流，丢失只会多写一次 */
const lastTouchAt = new Map();

/**
 * 生成新的会话标识
 *
 * 用 randomUUID 而非自增/时间戳：sid 会出现在令牌里并被前端读取展示，
 * 可预测的 sid 会让攻击者能够猜测他人的会话标识（配合其他缺陷即可越权吊销）。
 * @returns {string}
 */
const newSid = () => crypto.randomUUID();

/** 只取主版本号：会话列表要的是「Chrome 120」而非「Chrome 120.0.6099.130」 */
const majorVersion = (version) => {
  if (!version) return '';
  return String(version).split('.')[0] || '';
};

/** 非浏览器客户端（脚本/爬虫/工具）的 UA 特征 */
const BOT_UA_PATTERN =
  /bot|crawler|spider|curl|wget|python-requests|postman|axios|okhttp|java\/|go-http-client/i;

/**
 * 从 User-Agent 解析设备信息（ua-parser-js）
 *
 * bot 判断仍由本模块自己先做，不交给 ua-parser-js：
 *   爬虫与脚本客户端的 UA 里常同时携带 Chrome/Safari 标识，解析器会把
 *   Googlebot 报成 Chrome。会话列表里出现一条「Chrome · Windows」而实际是
 *   脚本调用，用户会误判为「有人用浏览器登录了我的账号」——把可疑访问
 *   伪装成正常访问，比不显示更糟。
 *
 * 各字段的缺失都用空串而非 'unknown' 字面量：
 *   展示层需要区分「解析不出」与「解析出的名字恰好叫 unknown」，
 *   且空串在拼接设备名时可以直接被 filter 掉，不必逐处特判字符串。
 *
 * @param {string} ua 原始 User-Agent
 * @returns {{deviceType: string, browser: string, browserVersion: string,
 *            os: string, osVersion: string, deviceVendor: string,
 *            deviceModel: string, engine: string, cpu: string}}
 */
const parseUserAgent = (ua) => {
  const s = String(ua || '');
  const empty = {
    deviceType: 'unknown',
    browser: '',
    browserVersion: '',
    os: '',
    osVersion: '',
    deviceVendor: '',
    deviceModel: '',
    engine: '',
    cpu: '',
  };
  if (!s) return empty;
  if (BOT_UA_PATTERN.test(s)) return { ...empty, deviceType: 'bot' };

  let parsed;
  try {
    parsed = new UAParser(s).getResult();
  } catch (err) {
    // 解析失败不能让登录失败：createSession 在登录主路径上
    logger.warn(`User-Agent 解析失败，按未知设备记录：${err.message}`);
    return empty;
  }

  // ua-parser-js 对桌面浏览器不返回 device.type（只有 mobile/tablet/console/
  // smarttv/wearable/embedded 才有值）。缺失即桌面 —— 若照抄 undefined，
  // 列表里所有电脑都会显示成「未知设备」。
  const rawType = parsed.device?.type || '';
  const deviceType = rawType || (parsed.browser?.name ? 'desktop' : 'unknown');

  return {
    deviceType,
    browser: parsed.browser?.name || '',
    browserVersion: majorVersion(parsed.browser?.version),
    os: parsed.os?.name || '',
    osVersion: parsed.os?.version || '',
    // 厂商/型号是「认出自己设备」最有效的线索（Apple iPhone / Xiaomi 13）
    deviceVendor: parsed.device?.vendor || '',
    deviceModel: parsed.device?.model || '',
    engine: parsed.engine?.name || '',
    cpu: parsed.cpu?.architecture || '',
  };
};

/**
 * 把解析结果拼成一行可读的设备名（供日志与审计使用）
 *
 * 前端不复用本函数：界面需要分字段渲染（图标、标签、折叠详情），
 * 拿一个拼好的字符串反而要再切开。此处的用途是让服务端日志一眼可读 ——
 * 排查「谁在什么设备上登录」时不必自己拼 UA。
 *
 * @param {object} device parseUserAgent 的返回值
 * @returns {string} 形如 'Xiaomi 13 · Chrome 120 · Android 14'，无信息时空串
 */
const describeDevice = (device = {}) => {
  const model = [device.deviceVendor, device.deviceModel].filter(Boolean).join(' ');
  const browser = [device.browser, device.browserVersion].filter(Boolean).join(' ');
  const os = [device.os, device.osVersion].filter(Boolean).join(' ');
  return [model, browser, os].filter(Boolean).join(' · ');
};

/** 缓存容量保护：超限时整体清空（重建成本远低于逐条淘汰的记账开销） */
const guardCacheSize = () => {
  if (sessionCache.size > SESSION_CACHE_MAX) sessionCache.clear();
  if (lastTouchAt.size > SESSION_CACHE_MAX) lastTouchAt.clear();
};

/** 从缓存与节流表中移除指定 sid（吊销后必须立即调用，否则最长 15 秒仍放行） */
const invalidateSessionCache = (sid) => {
  if (!sid) return;
  sessionCache.delete(String(sid));
  lastTouchAt.delete(String(sid));
};

/** 清空全部会话缓存（用于全局吊销与测试隔离） */
const clearSessionCache = () => {
  sessionCache.clear();
  lastTouchAt.clear();
};

/**
 * 创建登录会话
 *
 * 幂等性说明：不做「同设备复用已有会话」的合并。同一台设备重新登录应当
 * 产生新会话（旧的由调用方按需 supersede），否则用户在会话列表里看到的
 * createdAt 会是上次登录时间，与「本次登录」的直觉不符。
 *
 * @param {object} params
 * @param {string} params.userId 用户 id
 * @param {import('express').Request} params.req 请求对象（提取 UA/IP/指纹）
 * @param {string} [params.sid] 指定 sid（默认自动生成）
 * @returns {Promise<{sid: string, session: object}>}
 */
const createSession = async ({ userId, req, sid = newSid() }) => {
  const ua = String(req?.get?.('user-agent') || '').slice(0, 512);
  const device = parseUserAgent(ua);
  const ip = req?.ip || null;
  // 会话有效期对齐 refresh token：access token 会在此期间反复轮换，
  // 会话的真实存续上限由 refresh 决定
  const ttlMs = durationToMs(config.jwt.refreshExpire, 7 * 24 * 60 * 60 * 1000);

  const session = await UserSession.create({
    sid,
    userId,
    status: 'active',
    userAgent: ua,
    // 整体展开解析结果：逐字段列举时新增一个解析字段就要改两处
    // （parseUserAgent 与此处），漏改的表现是字段静默丢失而非报错
    ...device,
    ip,
    lastIp: ip,
    fingerprint: computeFingerprint(req),
    createdAt: new Date(),
    lastSeenAt: new Date(),
    expiresAt: new Date(Date.now() + ttlMs),
  });

  logger.info('登录会话已创建', {
    userId,
    sid: sid.slice(0, 8),
    device: describeDevice(device) || 'unknown',
  });
  return { sid, session };
};

/**
 * 校验会话是否可用（认证路径调用，带进程内缓存）
 *
 * 返回 null 的三种情况都必须拒绝认证：会话不存在（伪造 sid 或已被清理）、
 * 已吊销、已过期。
 *
 * fail-closed：数据库故障时抛错而非放行，与 isTokenBlacklisted 的契约一致 ——
 * 会话校验是授权决策的一部分，查不到结论时放行等于取消该防线。
 *
 * @param {string} sid
 * @returns {Promise<{usable: boolean, session: object|null}>}
 * @throws {Error} code=SESSION_SERVICE_UNAVAILABLE 数据库不可用
 */
const validateSession = async (sid) => {
  if (!sid) return { usable: false, session: null };
  const key = String(sid);
  const now = Date.now();

  const cached = sessionCache.get(key);
  if (cached && cached.expireAt > now) {
    return { usable: cached.usable, session: cached.session };
  }

  let doc;
  try {
    doc = await UserSession.findOne({ sid: key });
  } catch (err) {
    logger.error(`会话校验查询失败：${err.message}`);
    const serviceErr = new Error('Session service unavailable');
    serviceErr.code = 'SESSION_SERVICE_UNAVAILABLE';
    throw serviceErr;
  }

  const usable = !!doc && doc.isUsable();
  guardCacheSize();
  // 不可用的结论同样缓存：被吊销的会话往往会持续重试（前端定时轮询、
  // 未感知掉线的客户端），不缓存等于让失效会话反复打库
  sessionCache.set(key, {
    usable,
    session: doc || null,
    expireAt: now + SESSION_CACHE_TTL,
  });
  return { usable, session: doc || null };
};

/**
 * 更新会话活跃信息（节流写入）
 *
 * 除 lastSeenAt 外还更新 lastIp：会话期间 IP 变化是判断「令牌是否被
 * 挪到别处使用」的关键线索，只记登录时的 IP 会漏掉这类情况。
 *
 * 失败静默：这是纯观测性写入，不能因为它失败而拒绝用户请求。
 *
 * @param {string} sid
 * @param {import('express').Request} req
 * @returns {Promise<boolean>} 是否实际执行了写入
 */
const touchSession = async (sid, req) => {
  // 整个函数体都在 try 内：本函数的对外契约是**永不 reject**，
  // 调用方（authenticate）因此可以不 await、不挂 .catch 就发起调用。
  // 若把 key 计算、节流表写入留在 try 外，一旦它们抛错就变成
  // unhandled rejection —— 一个纯观测性写入不该有能力搞崩进程。
  try {
    if (!sid) return false;
    const key = String(sid);
    const now = Date.now();
    const last = lastTouchAt.get(key) || 0;
    if (now - last < TOUCH_THROTTLE_MS) return false;

    // 先占位再写库：并发请求下避免同时穿透节流
    lastTouchAt.set(key, now);
    guardCacheSize();
    await UserSession.updateOne(
      { sid: key, status: 'active' },
      { $set: { lastSeenAt: new Date(), lastIp: req?.ip || null } }
    );
    return true;
  } catch (err) {
    logger.warn(`会话活跃时间更新失败（不影响请求）：${err.message}`);
    return false;
  }
};

/**
 * 吊销单个会话（设备级下线）
 *
 * 与 tokenVersion 递增的关键差别：只影响这一台设备，用户其余设备不受影响。
 * 这正是本功能的核心价值 —— 此前「踢掉可疑设备」只能靠改密码全局下线。
 *
 * 越权防护：必须传 userId 并作为查询条件之一。若只按 sid 吊销，
 * 拿到（或猜到）他人 sid 即可下线他人会话。
 *
 * @param {object} params
 * @param {string} params.sid 目标会话
 * @param {string} params.userId 归属用户（越权防护，必填）
 * @param {string} [params.reason] 吊销原因
 * @returns {Promise<boolean>} 是否有会话被实际吊销
 */
const revokeSession = async ({ sid, userId, reason = 'user_revoked' }) => {
  if (!sid || !userId) return false;
  const result = await UserSession.updateOne(
    { sid: String(sid), userId, status: 'active' },
    { $set: { status: 'revoked', revokedAt: new Date(), revokeReason: reason } }
  );
  const revoked = (result.modifiedCount || 0) > 0;
  // 无论是否命中都清缓存：命中时使吊销即时生效；未命中时该 sid 可能
  // 本就不属于此用户，清掉只是丢弃一条缓存，无副作用
  invalidateSessionCache(sid);
  if (revoked) {
    logger.info('会话已吊销', { userId, sid: String(sid).slice(0, 8), reason });
  }
  return revoked;
};

/**
 * 吊销该用户除指定会话外的全部会话（「退出其他所有设备」）
 *
 * 典型场景：用户在会话列表看到可疑设备但不确定是哪一条，一键清空其余设备。
 * 保留当前会话，避免用户把自己也踢下线后需要重新登录。
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} [params.exceptSid] 保留的会话（通常是当前会话）
 * @param {string} [params.reason]
 * @returns {Promise<number>} 被吊销的会话数
 */
const revokeOtherSessions = async ({ userId, exceptSid = null, reason = 'user_revoked' }) => {
  if (!userId) return 0;
  const filter = { userId, status: 'active' };
  if (exceptSid) filter.sid = { $ne: String(exceptSid) };

  // 先取出待吊销的 sid：updateMany 不返回被改文档，而缓存必须按 sid 精确清除
  const targets = await UserSession.find(filter).select('sid').lean();
  if (targets.length === 0) return 0;

  const result = await UserSession.updateMany(filter, {
    $set: { status: 'revoked', revokedAt: new Date(), revokeReason: reason },
  });
  for (const t of targets) invalidateSessionCache(t.sid);

  const count = result.modifiedCount || 0;
  logger.info('批量吊销会话', { userId, count, reason });
  return count;
};

/**
 * 吊销该用户全部会话（含当前会话）
 *
 * 供改密、管理员强制下线、refresh 重放检测调用 —— 这些场景本就要
 * 全局失效，会话表须与 tokenVersion 保持一致，否则会话列表里会留下
 * 一批「显示 active 但实际已不能用」的僵尸记录，用户看到的信息与事实不符。
 *
 * @param {string} userId
 * @param {string} [reason]
 * @returns {Promise<number>}
 */
const revokeAllSessions = async (userId, reason = 'password_changed') => {
  if (!userId) return 0;
  const targets = await UserSession.find({ userId, status: 'active' }).select('sid').lean();
  if (targets.length === 0) return 0;

  const result = await UserSession.updateMany(
    { userId, status: 'active' },
    { $set: { status: 'revoked', revokedAt: new Date(), revokeReason: reason } }
  );
  for (const t of targets) invalidateSessionCache(t.sid);
  const count = result.modifiedCount || 0;
  logger.info('全部会话已吊销', { userId, count, reason });
  return count;
};

/**
 * 吊销单个会话，失败只告警不抛错（fail-soft 包装）
 *
 * 为什么需要这个包装：调用点（登出）的安全结论并不依赖它成功 ——
 * cookie 已清、令牌已入黑名单，会话记录只是「登录会话」界面的数据源。
 * 但每个调用点各写一遍 `.catch((e) => logger.warn(...))` 有两个坏处：
 *  1. 「失败可忽略」这个判断被复制到多处，日后有人改成 fail-closed 会漏改；
 *  2. 那些内联箭头是永不执行的失败路径，却计入覆盖率分母，
 *     把棘轮基线拖成假红灯（而红灯一多，真实退化就会被当噪音）。
 * 语义在此处说一次、测一次即可。
 *
 * @param {object} params 同 revokeSession
 * @returns {Promise<boolean>} 是否吊销成功；异常时返回 false
 */
const revokeSessionSafe = async (params) => {
  try {
    return await revokeSession(params);
  } catch (err) {
    logger.warn(`会话吊销失败（不影响主流程结论）：${err.message}`);
    return false;
  }
};

/**
 * 吊销用户全部会话，失败只告警不抛错（fail-soft 包装）
 *
 * 供改密、管理员重置 MFA、refresh 重放检测调用：这些路径的吊销结论由
 * tokenVersion 递增保证（令牌已全部失效），会话表收敛的作用是让界面
 * 不再列出实际已掉线的设备。收敛失败是「显示不准」，不是「防线失效」，
 * 因此不能因为它而让改密请求整体失败。
 *
 * @param {string} userId
 * @param {string} reason
 * @returns {Promise<number>} 被吊销的会话数；异常时返回 0
 */
const revokeAllSessionsSafe = async (userId, reason) => {
  try {
    return await revokeAllSessions(userId, reason);
  } catch (err) {
    logger.warn(`会话表收敛失败（令牌已由 tokenVersion 全局失效）：${err.message}`);
    return 0;
  }
};

/**
 * 列出用户的活跃会话（会话管理界面数据源）
 *
 * 顺带把「已过期但状态仍是 active」的记录标记为 expired：TTL 清理有延迟，
 * 若不处理，用户会在列表里看到早已失效的设备并疑惑为什么踢不掉。
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} [params.currentSid] 当前请求所属会话（用于标记「本设备」）
 * @returns {Promise<Array<object>>} 脱敏后的会话列表，最近活动在前
 */
const listSessions = async ({ userId, currentSid = null }) => {
  const now = new Date();

  // 惰性收敛过期状态：放在读路径而非定时任务，避免再引入一个后台计时器
  // （多进程下定时任务会重复执行）。写失败不影响列表返回。
  try {
    await UserSession.updateMany(
      { userId, status: 'active', expiresAt: { $lte: now } },
      { $set: { status: 'expired' } }
    );
  } catch (err) {
    logger.warn(`过期会话状态收敛失败：${err.message}`);
  }

  const docs = await UserSession.find({
    userId,
    status: 'active',
    expiresAt: { $gt: now },
  }).sort({ lastSeenAt: -1 });

  return docs.map((d) => d.toClientJSON(currentSid));
};

module.exports = {
  newSid,
  parseUserAgent,
  describeDevice,
  createSession,
  validateSession,
  touchSession,
  revokeSession,
  revokeSessionSafe,
  revokeOtherSessions,
  revokeAllSessions,
  revokeAllSessionsSafe,
  listSessions,
  invalidateSessionCache,
  clearSessionCache,
  // 常量导出供测试断言，避免测试里重复写魔法数字
  SESSION_CACHE_TTL,
  TOUCH_THROTTLE_MS,
};
