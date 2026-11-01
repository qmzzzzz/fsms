/**
 * 登录主流程与口令校验
 *
 * 自 authService.js 拆出：取令牌/口令 → 账号可用性判定 → 口令比对与失败计数
 * → MFA 二段（verifyMfaChallenge，见 failureAndMfa.js）→ 签发会话（session.js）。
 * 哑口令摘要（consumeDummyPasswordTime）也随本文件走：它服务的是「用户不存在」这条登录路径的耗时侧信道，注册路径用不到。
 */

const crypto = require('crypto');
const User = require('../../models/User');
const config = require('../../config');
const logger = require('../../utils/logger');
const { isIPAllowed } = require('../../utils/ipRange');
const { resolvePunishableIp } = require('../../utils/ipUtils');
const { checkBruteForce } = require('../securityAlert');
const canaryWatch = require('../canaryWatch');
const honeypotWatch = require('../honeypotWatch'); // 蜜罐账户（诱饵）登录判据与留痕；物化/对账/状态见该模块
const AuditLog = require('../../models/AuditLog');
// 手写审计写入是这些操作的唯一留痕，静默吞错＝审计库零痕迹（且无可观测信号）
const { onAuditWriteFailure, awaitAuditWrite } = require('../../utils/auditWriteFailure');
const captchaService = require('../captchaService');
const loginChallenge = require('../loginChallenge');
const bcryptWorker = require('../../utils/bcryptWorkerPool');
const { decryptLoginCredential } = require('../../utils/loginCipher');
const { USER_STATUS } = require('../../utils/constants');
const {
  verifyMfaChallenge,
  MAX_FAILED_LOGINS,
  LOCK_DURATION_MS,
  resolveFailedLoginCount,
} = require('./failureAndMfa');
const { issueLoginSession } = require('./session');
const { credentialShapeOf } = require('../../constants/credentialShape');

/**
 * 哑口令摘要：用于抹平「用户不存在」与「用户存在但密码错误」的响应耗时差
 *
 * bcryptjs 是纯 JS 实现，12 轮 compare 需数十至上百毫秒。若「用户不存在」路径直接返回、不做任何 compare，攻击者只需比较响应时间即可枚举有效用户名——
 * 统一了文案和错误码，但耗时这条侧信道仍然敞开。
 *
 * 摘要在模块加载时一次性生成（随机口令，永不匹配任何真实输入），之后每次「用户不存在」都对它做一次真实 compare，使两条路径的 CPU 开销等价。
 * 惰性生成 + 缓存：避免在模块加载阶段阻塞（bcrypt.hash 同样是重 CPU 操作）。
 */
let _dummyPasswordHash = null;
const consumeDummyPasswordTime = async (candidate) => {
  try {
    if (!_dummyPasswordHash) {
      _dummyPasswordHash = await bcryptWorker.hash(
        crypto.randomBytes(24).toString('hex'),
        config.bcryptRounds
      );
    }
    // 入参可能是非字符串（校验器已挡住大部分，此处纵深防御）；
    // 统一转成字符串保证 compare 一定执行到底，不提前抛错缩短耗时
    await bcryptWorker.compare(
      typeof candidate === 'string' ? candidate : String(candidate ?? ''),
      _dummyPasswordHash
    );
  } catch (_) {
    // 抹平失败不应影响拒绝逻辑本身（宁可保留侧信道也不能 500）
  }
};
/**
 * 用户登录（业务层，含 MFA 二期验证）。
 *
 * 按「前置校验 → 账户校验 → 凭据校验 → MFA → 签发」五段编排；各段 helper 只通过入参取数，不共享闭包状态。
 *
 * @param {object} params { username, password, encPassword, mfaCode, captchaId, captchaText }
 * @param {object} ctx { ip, userAgent, method, path, fingerprint, req }
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'|'INVALID_CREDENTIALS'|'MFA_REQUIRED'|'MFA_ATTEMPTS_EXCEEDED'|'MFA_CODE_INVALID'|'OK'}>}
 */
async function loginUser(params, ctx) {
  const { username } = params;
  const { ip, userAgent, fingerprint } = ctx;

  // ① 人机校验 + 口令解析（静态开关或失败触发的挑战 / 密文轨 / 明文兼容轨）
  const pre = await resolveLoginPassword(params, ctx, username);
  if (pre.outcome) return pre;
  const { password, captchaVerified } = pre;

  // ② 查用户（含 password 字段）
  // 查找用户（包括密码字段）
  // 走 findByUsername 以匹配大小写不敏感的 username_ci 唯一索引，
  // 否则用 `Admin` 登录会查不到 `admin` 账户（与判重口径不一致）
  const user = await User.findByUsername(username).select('+password');
  if (!user) {
    // 修复：时序侧信道。「用户不存在」原先 0 次 bcrypt 直接返回，
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
        credentialShape: credentialShapeOf(password), // 撞库画像三字段的唯一派生点：口令只进不出，落库的只有布尔与档位
      })
      .catch(() => {});
    return { outcome: 'INVALID_CREDENTIALS' };
  }

  // ③ 账户可用性：状态 / 临时锁定 / IP 范围（三处拒绝共用 401 口径）
  const denied = await assertAccountUsable(user, { password, ctx, username, captchaVerified });
  if (denied) return denied;
  if (honeypotWatch.isLureLogin(user, password)) {
    // 蜜罐账户 + 诱饵口令：按成功路径放行（攻击者拿到零权限会话）
    await consumeDummyPasswordTime(password); // 成功路径也跑真 bcrypt，耗时与真实账户等价
    await honeypotWatch
      .recordHoneypotLogin({
        username,
        ip,
        userAgent,
        fingerprint,
        method: ctx.method,
        path: ctx.path,
        attribution: resolvePunishableIp(ctx.req),
        credentialShape: credentialShapeOf(password), // 同源派生：诱饵口令由词干表判定，故本行的 credentialStemHits 结构性恒为 1
      })
      .catch(() => {});
    return honeypotWatch.decorateLureSession(await issueLoginSession(user, ctx, username)); // 呈现层：把零角色换成合成角色/权限，只有外观变化，授权判定不受影响
  }

  // ④ 口令校验 + 失败计数（过期 lockUntil 视为新一轮）
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
 * 登录前置校验与口令解析（自 loginUser 拆出）
 *
 * 覆盖：验证码人机校验 → 口令密文轨/明文轨解析。这一段自带验证码开关、失败触发的挑战、
 * DB 故障降级、密文解密、明文兼容诸分支，与后续「查用户 → 校验凭据 → 签令牌」无数据耦合；且放在验证码之后，不动「验证码失败」路径的既有耗时特征。
 *
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'}|{password:string,captchaVerified:boolean}>}
 *   失败时返回 { outcome }（调用方直接透传）；成功时返回口令与「本次是否已通过人机验证」
 */
async function resolveLoginPassword(params, ctx, username) {
  const { ip, userAgent, fingerprint } = ctx;

  // 前置人机校验 = 静态开关（env LOGIN_CAPTCHA_ENABLED / 系统配置表，默认关闭）∪ 失败触发的挑战（services/loginChallenge：不读开关、默认生效）。
  // 挑战闸门拦在口令比对之前 ⇒ 同一用户名的失败计数停在阈值、到不了 MAX_FAILED_LOGINS：无验证码的批量爆破与「知道用户名就能把账户传入 10 分钟锁定」的可用性 DoS 同时被挡住。
  // 验证码不通过直接拒绝：不进凭证校验、不计入失败统计（爆破检测针对凭证爆破，验证码层已挡住自动化），但要落一条独立审计 login_captcha_rejected（审计二-3 落库留痕：拦下≠没发生；该动作刻意不进任何失败计数，否则「被拦下」自己就会把闸门焊死）。留痕先于返回且有界等待：审计库卡住时不把登录接口挂死，写失败按 high 单独记账。
  const { SystemConfig } = require('../../models');
  // ① 的统一口径：DB 故障时降级为静态默认（fail-open）+ 可告警信号，见 SystemConfig.captchaSwitch
  const captchaBySwitch = await SystemConfig.captchaSwitch('login');
  const challengeRequired = captchaBySwitch
    ? false
    : await loginChallenge.isChallengeRequired(username); // 开关已要求校验时不再查挑战判据（等价于原先的 || 短路，且开关常开的部署不该每请求多读一次审计集合）

  let captchaVerified = false;
  if (captchaBySwitch || challengeRequired) {
    captchaVerified = await captchaService.verify(params.captchaId, params.captchaText);
    if (!captchaVerified) {
      await awaitAuditWrite(
        loginChallenge.recordCaptchaRejected({
          username,
          ip,
          userAgent,
          fingerprint,
          trigger: captchaBySwitch
            ? loginChallenge.CAPTCHA_TRIGGERS.SWITCH
            : loginChallenge.CAPTCHA_TRIGGERS.CHALLENGE,
          captchaSubmitted: Boolean(params.captchaId && params.captchaText),
        }),
        'login_captcha_rejected_audit',
        { user: { username } }
      );
      return { outcome: 'CAPTCHA_INVALID' };
    }
  }

  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  // 放在验证码之后：验证码是更廉价的拦截层，应先于 ECDH 解密执行，
  // 且不动「验证码失败」路径的既有耗时特征
  let password;
  if (typeof params.encPassword === 'string' && params.encPassword) {
    try {
      password = await decryptLoginCredential(params.encPassword, 'LOGIN');
    } catch (err) {
      // 时序口径：解密失败必须与「密码错误」等耗时（同类侧信道——
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
  return { password, captchaVerified };
}

/**
 * 账户可用性校验（自 loginUser 拆出）：账户状态、临时锁定、IP 访问范围。
 *
 * 拒绝共用同一外部口径——一律返回与「用户名或密码错误」完全一致的 401 真实原因只进服务端日志与审计，避免用户名枚举预言机。临时锁定分支在本次已通过
 * 人机验证时放行到口令比对（见该分支），对外口径不变——放行后口令错仍是同一条 401。
 *
 * @param {object} options { password, ctx, username, captchaVerified }
 *   captchaVerified 为调用方在①段（前置人机校验）的结论
 * @returns {Promise<{outcome:'INVALID_CREDENTIALS'}|null>} 拒绝时返回 outcome，可用时返回 null
 */
async function assertAccountUsable(user, { password, ctx, username, captchaVerified }) {
  const { ip, userAgent, fingerprint } = ctx;

  // 检查账户状态
  // 禁用/锁定账户与"用户不存在/密码错误"返回完全一致的 401 文案，
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
    // 同族收口：这两条分支此前直接 return，
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
    // 口径：临时锁定同样返回与"用户名或密码错误"一致的 401，
    // 精确剩余时间只进服务端日志——423+精确分钟数可被用于确认有效用户名
    const remainMs = user.lockUntil.getTime() - Date.now();
    const remainMinutes = Math.ceil(remainMs / 60000);
    if (!captchaVerified) {
      logger.warn('登录拒绝 - 账户临时锁定中', { username, remainMinutes });
      await AuditLog.recordLogin(user._id, username, ip, false, userAgent, { fingerprint }).catch(
        onAuditWriteFailure('login_failed_audit', { user: { username } })
      );
      // 与上面 status 分支同判据：抹平耗时 + 计入暴力破解检测
      await consumeDummyPasswordTime(password);
      await checkBruteForce(username, ip, resolvePunishableIp(ctx.req)).catch(() => {});
      return { outcome: 'INVALID_CREDENTIALS' };
    }
    // 已通过人机验证 ⇒ 继续走口令比对：锁定照旧成立（其余门禁仍按 lockUntil 拒绝，见 middleware/auth.js
    // 与令牌/WS 门），但"任何人凭连续失败就能让账户主人 10 分钟登不进来"这条可用性 DoS 被收口。
    // 对外口径不变：不写新错误码，口令错仍落到统一 401。
    logger.warn('登录放行 - 账户临时锁定中且已通过人机验证', { username, remainMinutes });
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
      // 修复：此前返回 403/AUTH_IP_RANGE_DENIED，构成用户名枚举预言机——
      // 从受限 IP 之外探测即可区分「该账号存在且配了 allowedIPs」。
      // 这与口径（对外一律与「用户名或密码错误」完全一致）自相矛盾：
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
 * 口令校验 + 失败计数累计（自 loginUser 拆出）
 *
 * 已过期的 lockUntil 视为新一轮——重置计数从 1 起算并清空过期时间戳；否则解锁后仅剩 1 次试错即再次锁定，把 10 分钟窗口的配额从 10 次压到 1 次。
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
    // B-L1：与上方 214/258 行同口径——checkBruteForce 内的 DB 查询/告警落库若因 DB 瞬断 reject，异常上抛会把统一 401 变成 500（破坏防枚举口径）
    await checkBruteForce(username, ip, resolvePunishableIp(ctx.req)).catch(() => {});
    // 原子递增失败计数（$inc）：读-算-写竞态会让并发请求基于陈旧计数互相覆盖，
    // 丢失更新导致锁定阈值被推迟，利于爆破；$inc 由 DB 保证无丢失更新。
    // 返回更新后文档，据此判断是否跨过锁定阈值（阈值判定可能并发重复触发，
    // 但 lockUntil 覆写幂等，审计重复仅产生冗余日志，可接受）
    // 走到这里说明账户未处于锁定中（lockUntil 为空或已过期）。
    // 若 lockUntil 已过期却只做 $inc，此前的 9 次失败会继续累计——
    // 解锁后仅剩 1 次试错即再次锁定，等效「每 10 分钟允许 1 次尝试」，
    // 把 10 分钟窗口内的爆破配额从 10 次压到 1 次（对攻击者反而是限制），
    // 对正常用户则是输错一次就锁。已过期的 lockUntil 视为新一轮：
    // 重置计数从 1 起算并清除过期时间戳（与 MFA 计数路径同款修复）。
    //
    // 重置必须是条件写：此前按陈旧快照直接 `$set failedLoginCount:1`，
    // 并发失败（例如攻击者同时发 10 个请求）在锁定刚过期时会全部写 1，
    // 计数永远到不了 MAX_FAILED_LOGINS。条件写只让**第一个**请求重置，
    // 其余请求在 miss 后走 $inc，计数仍然逐次累加。
    const now = new Date();
    const lockExpired = user.lockUntil && user.lockUntil <= now;
    let updated = null;
    if (lockExpired) {
      updated = await User.findOneAndUpdate(
        { _id: user._id, lockUntil: { $lte: now } },
        { $set: { failedLoginCount: 1, lockUntil: null } },
        { new: true }
      ).catch(() => null);
    }
    if (!updated) {
      updated = await User.findByIdAndUpdate(
        user._id,
        { $inc: { failedLoginCount: 1 } },
        { new: true }
      ).catch(() => null);
    }
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
      if (lockApplied) {
        // 锁定生效后必须失效认证缓存：authenticate 读的是缓存快照（TTL 60s），
        // 不失效则已签发的 access token 在窗口内仍能带着旧 lockUntil 通过校验。
        const { invalidateUserCache } = require('../../middleware/auth');
        invalidateUserCache(user._id);
      }
      // 阈值如今只能被"能连续通过人机验证"的一方触达（见 loginChallenge），不再是被动可触发的 DoS 面。
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
