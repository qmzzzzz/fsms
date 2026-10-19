/**
 * 登录主流程与口令校验
 *
 * 自 authService.js 拆出：取令牌/口令 → 账号可用性判定 → 口令比对与失败计数
 * → MFA 二段（verifyMfaChallenge，见 failureAndMfa.js）→ 签发会话（session.js）。
 * 哑口令摘要（consumeDummyPasswordTime）也随本文件走：它服务的是「用户不存在」
 * 这条登录路径的耗时侧信道，注册路径用不到。
 */

const crypto = require('crypto');
const User = require('../../models/User');
const config = require('../../config');
const logger = require('../../utils/logger');
const { isIPAllowed } = require('../../utils/ipRange');
const { resolvePunishableIp } = require('../../utils/ipUtils');
const { checkBruteForce } = require('../securityAlert');
const canaryWatch = require('../canaryWatch');
const AuditLog = require('../../models/AuditLog');
// P0-5 后手写审计写入是这些操作的唯一留痕，静默吞错＝审计库零痕迹（且无可观测信号）
const { onAuditWriteFailure } = require('../../utils/auditWriteFailure');
const captchaService = require('../captchaService');
const { decryptLoginCredential } = require('../../utils/loginCipher');
const { USER_STATUS } = require('../../utils/constants');
const {
  verifyMfaChallenge,
  MAX_FAILED_LOGINS,
  LOCK_DURATION_MS,
  resolveFailedLoginCount,
} = require('./failureAndMfa');
const { issueLoginSession } = require('./session');

/**
 * 哑口令摘要：用于抹平「用户不存在」与「用户存在但密码错误」的响应耗时差
 *
 * bcryptjs 是纯 JS 实现，12 轮 compare 需数十至上百毫秒。若「用户不存在」
 * 路径直接返回、不做任何 compare，攻击者只需比较响应时间即可枚举有效用户名——
 * M-5 统一了文案和错误码，但耗时这条侧信道仍然敞开。
 *
 * 摘要在模块加载时一次性生成（随机口令，永不匹配任何真实输入），
 * 之后每次「用户不存在」都对它做一次真实 compare，使两条路径的 CPU 开销等价。
 * 惰性生成 + 缓存：避免在模块加载阶段阻塞（bcrypt.hash 同样是重 CPU 操作）。
 */
let _dummyPasswordHash = null;
const consumeDummyPasswordTime = async (candidate) => {
  try {
    const bcrypt = require('bcryptjs');
    if (!_dummyPasswordHash) {
      _dummyPasswordHash = await bcrypt.hash(
        crypto.randomBytes(24).toString('hex'),
        config.bcryptRounds
      );
    }
    // 入参可能是非字符串（校验器已挡住大部分，此处纵深防御）；
    // 统一转成字符串保证 compare 一定执行到底，不提前抛错缩短耗时
    await bcrypt.compare(
      typeof candidate === 'string' ? candidate : String(candidate ?? ''),
      _dummyPasswordHash
    );
  } catch (_) {
    // 抹平失败不应影响拒绝逻辑本身（宁可保留侧信道也不能 500）
  }
};
/**
 * 用户登录（业务层，含 MFA 二期验证）
 * @param {object} params { username, password, encPassword, mfaCode }
 * @param {object} ctx { ip, userAgent, method, path, fingerprint }
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'|'INVALID_CREDENTIALS'|'MFA_REQUIRED'|'MFA_ATTEMPTS_EXCEEDED'|'MFA_CODE_INVALID'|'OK'}>}
 */
/**
 * 用户登录（业务层，含 MFA 二期验证）
 *
 * E-01 整改：本函数原圈复杂度 46（全仓最高，见 deliverables/_complexity-actual.json）。
 * 按「前置校验 → 账户校验 → 凭据校验 → MFA → 签发」五段拆出模块级 helper，
 * 骨架只保留编排与提前返回。所有切分线都在**无状态交接**处：helper 入参全部
 * 显式传递、不引入类或闭包捕获，函数体逐行搬运，行为与拆分前等价。
 *
 * @param {object} params { username, password, encPassword, mfaCode }
 * @param {object} ctx { ip, userAgent, method, path, fingerprint, req }
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'|'INVALID_CREDENTIALS'|'MFA_REQUIRED'|'MFA_ATTEMPTS_EXCEEDED'|'MFA_CODE_INVALID'|'OK'}>}
 */
async function loginUser(params, ctx) {
  const { username } = params;
  const { ip, userAgent, fingerprint } = ctx;

  // ① 人机校验 + 口令解析（验证码开关 / 密文轨 / 明文兼容轨）
  const pre = await resolveLoginPassword(params, ctx, username);
  if (pre.outcome) return pre;
  const { password } = pre;

  // ② 查用户（含 password 字段）
  // 查找用户（包括密码字段）
  // P3-30：走 findByUsername 以匹配大小写不敏感的 username_ci 唯一索引，
  // 否则用 `Admin` 登录会查不到 `admin` 账户（与判重口径不一致）
  const user = await User.findByUsername(username).select('+password');
  if (!user) {
    // P2-11 修复：时序侧信道。「用户不存在」原先 0 次 bcrypt 直接返回，
    // 而「用户存在」要跑 12 轮 bcrypt（纯 JS 实现，百毫秒级），
    // 响应时间差可直接区分有效用户名——文案统一了但耗时没统一。
    // 此处对固定的哑摘要做一次等价 compare，把两条路径的 CPU 开销拉平。
    await consumeDummyPasswordTime(password);
    // 用户不存在同样计入失败统计，防止借不存在的用户名绕开暴力破解检测
    await AuditLog.recordLogin(null, username, ip, false, userAgent, { fingerprint }).catch(
      onAuditWriteFailure('login_failed_audit', { user: { username } })
    );
    await checkBruteForce(username, ip, resolvePunishableIp(ctx.req)).catch(() => {});
    // 哨兵用户名（canary）：本条分支是名单名唯一可能触发的位置（幽灵语义在
    // canaryWatch 内构造性成立）。审计必写、告警按每哨兵每日一次频控；
    // 函数经 guardDetection 包裹永不 reject，这里仍按防御性口径 catch。
    await canaryWatch
      .recordGhostAttempt({
        username,
        ip,
        userAgent,
        fingerprint,
        method: ctx.method,
        path: ctx.path,
        attribution: resolvePunishableIp(ctx.req),
      })
      .catch(() => {});
    return { outcome: 'INVALID_CREDENTIALS' };
  }

  // ③ 账户可用性：状态 / 临时锁定 / IP 范围（三处拒绝共用 M-5 的 401 口径）
  const denied = await assertAccountUsable(user, { password, ctx, username });
  if (denied) return denied;

  // ④ 口令校验 + 失败计数（P3-1：过期 lockUntil 视为新一轮）
  const rejected = await verifyPasswordOrTrackFailure(user, { password, username, ctx });
  if (rejected) return rejected;

  // ⑤ MFA 二期（I-06）：已开启 TOTP 的账户，密码正确后还需动态口令才签发令牌。
  // 第一步响应携带 mfaRequired 标记，前端据此切换到验证码输入；不泄露其他信息
  if (user.mfaEnabled) {
    const mfa = await verifyMfaChallenge(user, {
      mfaCodeRaw: params.mfaCode,
      username,
      ctx,
    });
    if (mfa.outcome !== 'OK') return mfa;
  }

  // ⑥ 签发：非常规时间审计 → 登录信息更新 → 角色权限 → 令牌 → 会话注册 → 成功审计
  return issueLoginSession(user, ctx, username);
}

/**
 * 登录前置校验与口令解析（E-01 自 loginUser 拆出）
 *
 * 覆盖：验证码人机校验 → 口令密文轨/明文轨解析。这一段自带验证码开关、
 * DB 故障降级、密文解密、明文兼容四个分支，与后续「查用户 → 校验凭据 →
 * 签令牌」无数据耦合；且放在验证码之后，不动「验证码失败」路径的既有耗时特征。
 *
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'}|{password:string}>}
 *   失败时返回 { outcome }（调用方直接透传），成功时返回 { password }
 */
async function resolveLoginPassword(params, ctx, username) {
  const { ip, userAgent } = ctx;

  // 前置人机校验：仅在系统开启验证码开关时执行（默认关闭）
  // 验证码错误/过期时直接拒绝，不进入凭证校验，
  // 也不计入登录失败统计（暴力破解检测针对凭证爆破，验证码层已挡住自动化）
  const { SystemConfig } = require('../../models');
  // 统一口径：DB 故障时降级为静态默认（fail-open）+ 可告警信号，见 SystemConfig.captchaSwitch
  const captchaEnabled = await SystemConfig.captchaSwitch('login');

  if (captchaEnabled && !(await captchaService.verify(params.captchaId, params.captchaText))) {
    return { outcome: 'CAPTCHA_INVALID' };
  }

  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  // 放在验证码之后：验证码是更廉价的拦截层，应先于 ECDH 解密执行，
  // 且不动「验证码失败」路径的既有耗时特征
  let password;
  if (typeof params.encPassword === 'string' && params.encPassword) {
    try {
      password = await decryptLoginCredential(params.encPassword, 'LOGIN');
    } catch (err) {
      // 时序口径：解密失败必须与「密码错误」等耗时（P2-10/P2-11 同类侧信道——
      // 解密是毫秒级，不补哑 compare 会让该路径显著快于正常失败路径）
      await consumeDummyPasswordTime(params.encPassword);
      // 公钥是公开的，攻击者可自行构造合法密文——解密失败同样计入防爆破与审计
      await AuditLog.recordLogin(null, username, ip, false, userAgent, {
        reason: `credential_decrypt_failed:${err.code}`,
      }).catch(onAuditWriteFailure('login_failed_audit', { user: { username } }));
      await checkBruteForce(username, ip, resolvePunishableIp(ctx.req)).catch(() => {});
      logger.warn('登录拒绝 - 口令密文无效', { username, code: err.code });
      return { outcome: 'ENC_INVALID' };
    }
  } else {
    // 明文兼容轨（灰度期；strict 模式下请求到不了这里——校验层已 400）
    password = params.password;
  }
  return { password };
}

/**
 * 账户可用性校验（E-01 自 loginUser 拆出）：账户状态、临时锁定、IP 访问范围。
 *
 * 三处拒绝共用同一外部口径——一律返回与「用户名或密码错误」完全一致的 401
 * （M-5 / P2-10），真实原因只进服务端日志与审计，避免用户名枚举预言机。
 *
 * @returns {Promise<{outcome:'INVALID_CREDENTIALS'}|null>} 拒绝时返回 outcome，可用时返回 null
 */
async function assertAccountUsable(user, { password, ctx, username }) {
  const { ip, userAgent, fingerprint } = ctx;

  // 检查账户状态
  // M-5：禁用/锁定账户与"用户不存在/密码错误"返回完全一致的 401 文案，
  // 防止借差异化响应枚举有效用户名；真实原因仅记入服务端日志与审计
  // 允许清单（F-162）：只有 active 可用。此前是「=== inactive || === locked」的按枚举拒绝，
  // 与同文件 refresh 的 `status !== 'active'` 是同一个概念的两个答案——
  // USER_STATUS 加一档、或备份还原/裸写进一个清单外的值时，登录会**完整放行**、refresh 才拒绝。
  if (user.status !== USER_STATUS.ACTIVE) {
    logger.warn('登录拒绝 - 账户状态异常', { username, status: user.status });
    await AuditLog.recordLogin(user._id, username, ip, false, userAgent, {
      fingerprint,
      reason: `account_status_${user.status}`,
    }).catch(onAuditWriteFailure('login_failed_audit', { user: { username } }));
    // P2-11/M-5 的同族收口：这两条分支此前直接 return，
    // 一次 bcrypt 都不跑 ⇒ 「存在但被禁的账号」比「用户名不存在」快约一次
    // compare 的时间（纯 JS cost-12 ≈ 百毫秒），构成账号存在性 + 锁定态预言机，
    // 且**不需要正确口令**——等于把 ② 里花力气做的时序拉平从这个方向漏掉。
    await consumeDummyPasswordTime(password);
    // 同一条拒绝也必须进暴力破解检测：loginUser 的「用户不存在」分支会计数，
    // 被禁账号若不计数就成了免检探测面（recordLogin 已写失败审计，
    // 但 checkBruteForce 才是把它读出来并告警的那一步）。
    await checkBruteForce(username, ip, resolvePunishableIp(ctx.req)).catch(() => {});
    return { outcome: 'INVALID_CREDENTIALS' };
  }
  if (user.lockUntil && user.lockUntil > new Date()) {
    // M-5 口径：临时锁定同样返回与"用户名或密码错误"一致的 401，
    // 精确剩余时间只进服务端日志——423+精确分钟数可被用于确认有效用户名
    const remainMs = user.lockUntil.getTime() - Date.now();
    logger.warn('登录拒绝 - 账户临时锁定中', {
      username,
      remainMinutes: Math.ceil(remainMs / 60000),
    });
    await AuditLog.recordLogin(user._id, username, ip, false, userAgent, { fingerprint }).catch(
      onAuditWriteFailure('login_failed_audit', { user: { username } })
    );
    // 与上面 status 分支同判据：抹平耗时 + 计入暴力破解检测
    await consumeDummyPasswordTime(password);
    await checkBruteForce(username, ip, resolvePunishableIp(ctx.req)).catch(() => {});
    return { outcome: 'INVALID_CREDENTIALS' };
  }

  // IP 访问范围校验：在凭证校验之前执行，
  // 未授权 IP 即使持有正确口令也无法登录，且不泄露口令是否正确
  if (user.allowedIPs) {
    const { allowed, reason } = isIPAllowed(ip, user.allowedIPs);
    if (!allowed) {
      logger.warn('登录被拒 - IP 不在允许范围', { username, ip, reason });
      // 评价报告 #8：fire-and-forget 审计写入显式挂 catch——record 内部虽已
      // 兜底，这里再挂一层防契约漂移，且表明「不留悬挂 Promise」的意图
      AuditLog.record({
        action: 'ip_range_denied',
        category: 'auth',
        userId: user._id,
        username,
        method: ctx.method,
        path: ctx.path,
        ip,
        success: false,
        riskLevel: 'high',
        riskFactors: ['ip_range_violation'],
        reason: `登录 IP 不在允许范围内（${reason}）`,
      }).catch(() => {});
      // P2-10 修复：此前返回 403/AUTH_IP_RANGE_DENIED，构成用户名枚举预言机——
      // 从受限 IP 之外探测即可区分「该账号存在且配了 allowedIPs」。
      // 这与 M-5 口径（对外一律与「用户名或密码错误」完全一致）自相矛盾：
      // 文案统一了，错误码没统一。
      // 现改为同一 401/AUTH_INVALID_CREDENTIALS，真实原因只进日志与审计；
      // 并补一次哑 compare 抹平耗时差（否则「IP 被拒」路径明显更快，侧信道依旧）。
      await consumeDummyPasswordTime(password);
      return { outcome: 'INVALID_CREDENTIALS' };
    }
  }
  return null;
}

/**
 * 口令校验 + 失败计数累计（E-01 自 loginUser 拆出）
 *
 * P3-1：已过期的 lockUntil 视为新一轮——重置计数从 1 起算并清空过期时间戳；
 * 否则解锁后仅剩 1 次试错即再次锁定，把 10 分钟窗口的配额从 10 次压到 1 次。
 *
 * @returns {Promise<{outcome:'INVALID_CREDENTIALS'}|null>} 口令错误返回 outcome，正确返回 null
 */
async function verifyPasswordOrTrackFailure(user, { password, username, ctx }) {
  const { ip, userAgent, fingerprint } = ctx;

  // 验证密码
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    logger.warn('登录失败 - 密码错误', { username });
    await AuditLog.recordLogin(user._id, username, ip, false, userAgent, { fingerprint }).catch(
      onAuditWriteFailure('login_failed_audit', { user: { username } })
    );
    // B-L1：与上方 227/243 行同口径——checkBruteForce 内的 DB 查询/告警落库
    // 若因 DB 瞬断 reject，异常上抛会把统一 401 变成 500（破坏 M-5 防枚举口径）
    await checkBruteForce(username, ip, resolvePunishableIp(ctx.req)).catch(() => {});
    // 原子递增失败计数（$inc）：读-算-写竞态会让并发请求基于陈旧计数互相覆盖，
    // 丢失更新导致锁定阈值被推迟，利于爆破；$inc 由 DB 保证无丢失更新。
    // 返回更新后文档，据此判断是否跨过锁定阈值（阈值判定可能并发重复触发，
    // 但 lockUntil 覆写幂等，审计重复仅产生冗余日志，可接受）
    //
    // P3-1：走到这里说明账户未处于锁定中（lockUntil 为空或已过期）。
    // 若 lockUntil 已过期却只做 $inc，此前的 9 次失败会继续累计——
    // 解锁后仅剩 1 次试错即再次锁定，等效「每 10 分钟允许 1 次尝试」，
    // 把 10 分钟窗口内的爆破配额从 10 次压到 1 次（对攻击者反而是限制），
    // 对正常用户则是输错一次就锁。已过期的 lockUntil 视为新一轮：
    // 重置计数从 1 起算并清除过期时间戳（与 MFA 计数路径同款修复）。
    const lockExpired = user.lockUntil && user.lockUntil <= new Date();
    const updated = await User.findByIdAndUpdate(
      user._id,
      lockExpired
        ? { $set: { failedLoginCount: 1, lockUntil: null } }
        : { $inc: { failedLoginCount: 1 } },
      { new: true }
    ).catch(() => null);
    // 计数不可观测时的取舍见 resolveFailedLoginCount 的定义处（fail-closed）
    const newCount = resolveFailedLoginCount(updated);
    if (newCount >= MAX_FAILED_LOGINS) {
      // 锁定这条更新本身也可能写不进库。修法与 mfaService.js:142-164 同源：
      // 修复前是 `.catch(() => {})` 吞掉后照常写下「账户临时锁定」，并追加一条
      // action=account_temp_locked 的审计——日志与审计双双宣称一道**并不存在**的防线，
      // 而故障窗口内该账户的口令仍可被无限次在线尝试。观测不到时要如实记录，
      // 不能"记不上就算成功了"。
      let lockApplied = true;
      await User.findByIdAndUpdate(user._id, {
        lockUntil: new Date(Date.now() + LOCK_DURATION_MS),
      }).catch((err) => {
        lockApplied = false;
        logger.error(`账户临时锁定写入失败（防爆破防线未生效）：${err.message}`, { username });
      });
      logger.warn('账户临时锁定', {
        username,
        failedCount: newCount,
        lockMinutes: 10,
        // 锁到底有没有落库：读日志的人据此判断防线是否还在，而不是信一句断言
        lockApplied,
      });
      // 评价报告 #8：暴力破解信号审计写入显式挂 catch（同上口径）
      AuditLog.record({
        action: 'account_temp_locked',
        category: 'auth',
        userId: user._id,
        username,
        ip,
        userAgent,
        fingerprint,
        success: false,
        riskLevel: 'high',
        riskFactors: ['excessive_failed_logins'],
        reason: lockApplied
          ? `连续登录失败 ${newCount} 次，账户临时锁定 10 分钟`
          : `连续登录失败 ${newCount} 次，但锁定未能写入数据库，防爆破防线当前未生效`,
      }).catch(() => {});
    }
    return { outcome: 'INVALID_CREDENTIALS' };
  }
  return null;
}

module.exports = {
  loginUser,
};
