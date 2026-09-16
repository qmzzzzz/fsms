/**
 * 认证业务服务（D-1 自 authController 拆出）
 *
 * 注册/登录（含 MFA 二期验证）/刷新轮换/改密/资料更新/登出吊销的
 * 业务规则层。控制器只做入参校验与 HTTP 响应编排：本服务的每个函数
 * 返回判别式结果对象（{ outcome, ... }），由控制器映射到与拆分前
 * 完全一致的响应码与文案——纯重构，行为不变。
 *
 * 拆分边界：
 * - MFA 防爆破与恢复码原语在 services/mfaService.js；
 * - 设备级会话落库/吊销在 services/sessionService.js；
 * - 令牌签发与探测在 services/tokenService.js；
 * - 口令密文解密在 utils/loginCipher.js。
 * 本层只做流程编排与判定，不重复实现上述能力。
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Role = require('../models/Role');
const config = require('../config');
const logger = require('../utils/logger');
const { validatePasswordStrength, isValidAvatar } = require('../utils/helpers');
const { isIPAllowed } = require('../utils/ipRange');
const { checkBruteForce, checkUnusualTime } = require('./securityAlert');
const {
  blacklistToken,
  consumeToken,
  invalidateUserTokens,
} = require('../middleware/tokenBlacklist');
const AuditLog = require('../models/AuditLog');
const captchaService = require('./captchaService');
const { verifyTotpDetailed } = require('../utils/totp');
const { decryptMfaSecret } = require('../utils/mfaSecret');
const { decryptLoginCredential } = require('../utils/loginCipher');
const sessionService = require('./sessionService');
const { generateToken, generateRefreshToken } = require('./tokenService');
const {
  isMfaLocked,
  recordMfaFailure,
  resetMfaFailures,
  hashRecoveryCode,
} = require('./mfaService');
// O-2 下沉引入：管理员锁定/解锁的层级与内置超管校验（纯工具模块，无循环依赖）
const { getOperatorMaxLevel } = require('../utils/permissionHelper');
const { isSuperAdminRole } = require('../utils/superAdmin');

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
 * 用户注册（业务层）
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'|'WEAK'|'DUPLICATE'|'OK'}>}
 *   OK 时附 { userId, username, email, token, refreshToken }
 */
async function registerUser(body) {
  // 前置人机校验：注册接口强制图形验证码（后台可动态开关，默认开启）
  // 验证码错误/过期时直接拒绝，不进入用户名/邮箱查重与用户创建，
  // 也不计入后续统计——验证码层已挡住自动化批量注册
  const { captchaId, captchaText } = body;
  let registerCaptchaEnabled;
  try {
    const { SystemConfig: SysConfig } = require('../models');
    registerCaptchaEnabled = await SysConfig.isRegisterCaptchaEnabled();
  } catch (_) {
    registerCaptchaEnabled = config.registerCaptchaEnabled;
  }
  if (registerCaptchaEnabled && !(await captchaService.verify(captchaId, captchaText))) {
    return { outcome: 'CAPTCHA_INVALID' };
  }

  const { username, email, realName, phone, department } = body;

  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  let password;
  if (typeof body.encPassword === 'string' && body.encPassword) {
    try {
      password = await decryptLoginCredential(body.encPassword);
    } catch (err) {
      logger.warn('注册拒绝 - 口令密文无效', { username, code: err.code });
      return { outcome: 'ENC_INVALID' };
    }
    // 密文轨的强度校验在解密后补做（校验层只见密文，无法评估强度）
    const encStrengthError = validatePasswordStrength(password);
    if (encStrengthError) {
      return { outcome: 'WEAK', message: encStrengthError };
    }
  } else {
    password = body.password; // 明文兼容轨（强度已由校验层把关）
  }

  // 检查用户名是否已存在（统一返回模糊提示，防止枚举探测有效用户名/邮箱）
  // P3-30：拆成两次查询而非 $or 单查——username 判重必须带 collation（大小写不敏感），
  // 而带 collation 的查询无法命中默认 collation 的 email_1 索引，
  // 合并写会让邮箱分支退化为全集合扫描
  const [existingByName, existingByEmail] = await Promise.all([
    User.findByUsername(username).select('_id').lean(),
    User.findOne({ email }).select('_id').lean(),
  ]);
  if (existingByName || existingByEmail) {
    return { outcome: 'DUPLICATE' };
  }

  // 安全修复：先查默认角色，在 create 时一次性写入 roles，避免两步写入产生孤儿用户
  const defaultRole = await Role.findOne({ code: 'GUEST' }).select('_id code').lean();
  const roleIds = defaultRole ? [defaultRole._id] : [];

  // 创建用户（一次性写入角色，避免 create 后 save 失败导致无角色用户）
  const user = await User.create({
    username,
    email,
    password,
    realName,
    phone,
    department,
    roles: roleIds,
  });

  // 注册成功即建立会话：注册后立即登录无需再次输密码
  const regRoles = defaultRole ? [defaultRole.code] : [];
  const token = generateToken(
    user._id,
    user.username,
    user.email,
    regRoles,
    user.realName,
    user.tokenVersion ?? 0
  );
  const refreshToken = generateRefreshToken(user._id, user.tokenVersion ?? 0);

  logger.info('新用户注册', { username });

  return {
    outcome: 'OK',
    userId: user._id,
    username: user.username,
    email: user.email,
    token,
    refreshToken,
  };
}

/**
 * 用户登录（业务层，含 MFA 二期验证）
 * @param {object} params { username, password, encPassword, mfaCode }
 * @param {object} ctx { ip, userAgent, method, path, fingerprint }
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'|'INVALID_CREDENTIALS'|'MFA_REQUIRED'|'MFA_ATTEMPTS_EXCEEDED'|'MFA_CODE_INVALID'|'OK'}>}
 */
async function loginUser(params, ctx) {
  const { username } = params;
  const { ip, userAgent, fingerprint } = ctx;

  // 前置人机校验：仅在系统开启验证码开关时执行（默认关闭）
  // 验证码错误/过期时直接拒绝，不进入凭证校验，
  // 也不计入登录失败统计（暴力破解检测针对凭证爆破，验证码层已挡住自动化）
  const { SystemConfig } = require('../models');
  let captchaEnabled;
  try {
    captchaEnabled = await SystemConfig.isLoginCaptchaEnabled();
  } catch (_) {
    // 数据库故障时降级到静态配置
    captchaEnabled = config.loginCaptchaEnabled;
  }

  if (captchaEnabled && !(await captchaService.verify(params.captchaId, params.captchaText))) {
    return { outcome: 'CAPTCHA_INVALID' };
  }

  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  // 放在验证码之后：验证码是更廉价的拦截层，应先于 ECDH 解密执行，
  // 且不动「验证码失败」路径的既有耗时特征
  let password;
  if (typeof params.encPassword === 'string' && params.encPassword) {
    try {
      password = await decryptLoginCredential(params.encPassword);
    } catch (err) {
      // 时序口径：解密失败必须与「密码错误」等耗时（P2-10/P2-11 同类侧信道——
      // 解密是毫秒级，不补哑 compare 会让该路径显著快于正常失败路径）
      await consumeDummyPasswordTime(params.encPassword);
      // 公钥是公开的，攻击者可自行构造合法密文——解密失败同样计入防爆破与审计
      await AuditLog.recordLogin(null, username, ip, false, userAgent, {
        reason: `credential_decrypt_failed:${err.code}`,
      }).catch(() => {});
      await checkBruteForce(username, ip).catch(() => {});
      logger.warn('登录拒绝 - 口令密文无效', { username, code: err.code });
      return { outcome: 'ENC_INVALID' };
    }
  } else {
    // 明文兼容轨（灰度期；strict 模式下请求到不了这里——校验层已 400）
    password = params.password;
  }

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
      () => {}
    );
    await checkBruteForce(username, ip).catch(() => {});
    return { outcome: 'INVALID_CREDENTIALS' };
  }

  // 检查账户状态
  // M-5：禁用/锁定账户与"用户不存在/密码错误"返回完全一致的 401 文案，
  // 防止借差异化响应枚举有效用户名；真实原因仅记入服务端日志与审计
  if (user.status === 'inactive' || user.status === 'locked') {
    logger.warn('登录拒绝 - 账户状态异常', { username, status: user.status });
    await AuditLog.recordLogin(user._id, username, ip, false, userAgent, {
      fingerprint,
      reason: `account_status_${user.status}`,
    }).catch(() => {});
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
      () => {}
    );
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

  // 验证密码
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    logger.warn('登录失败 - 密码错误', { username });
    await AuditLog.recordLogin(user._id, username, ip, false, userAgent, { fingerprint }).catch(
      () => {}
    );
    // B-L1：与上方 210/233 行同口径——checkBruteForce 内的 DB 查询/告警落库
    // 若因 DB 瞬断 reject，异常上抛会把统一 401 变成 500（破坏 M-5 防枚举口径）
    await checkBruteForce(username, ip).catch(() => {});
    // 原子递增失败计数（$inc）：读-算-写竞态会让并发请求基于陈旧计数互相覆盖，
    // 丢失更新导致锁定阈值被推迟，利于爆破；$inc 由 DB 保证无丢失更新。
    // 返回更新后文档，据此判断是否跨过锁定阈值（阈值判定可能并发重复触发，
    // 但 lockUntil 覆写幂等，审计重复仅产生冗余日志，可接受）
    //
    // P3-1：走到这里说明账户未处于锁定中（lockUntil 为空或已过期）。
    // 若 lockUntil 已过期却只做 $inc，上一轮的 9 次失败会继续累计——
    // 解锁后仅剩 1 次试错即再次锁定，等效「每 10 分钟允许 1 次尝试」，
    // 把 10 分钟窗口内的爆破配额从 10 次压到 1 次（对攻击者反而是限制），
    // 对正常用户则是输错一次就锁。已过期的 lockUntil 视为新一轮：
    // 重置计数从 1 起算并清除过期时间戳（与 MFA 计数路径同款修复）。
    const MAX_FAILED_LOGINS = 10;
    const LOCK_DURATION_MS = 10 * 60 * 1000;
    const lockExpired = user.lockUntil && user.lockUntil <= new Date();
    const updated = await User.findByIdAndUpdate(
      user._id,
      lockExpired
        ? { $set: { failedLoginCount: 1, lockUntil: null } }
        : { $inc: { failedLoginCount: 1 } },
      { new: true }
    ).catch(() => null);
    const newCount = updated?.failedLoginCount ?? 1;
    if (newCount >= MAX_FAILED_LOGINS) {
      await User.findByIdAndUpdate(user._id, {
        lockUntil: new Date(Date.now() + LOCK_DURATION_MS),
      }).catch(() => {});
      logger.warn('账户临时锁定', { username, failedCount: newCount, lockMinutes: 10 });
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
        reason: `连续登录失败 ${newCount} 次，账户临时锁定 10 分钟`,
      }).catch(() => {});
    }
    return { outcome: 'INVALID_CREDENTIALS' };
  }

  // MFA 二期验证（I-06）：已开启 TOTP 的账户，密码正确后还需动态口令才签发令牌。
  // 第一步响应携带 mfaRequired 标记，前端据此切换到验证码输入；不泄露其他信息
  if (user.mfaEnabled) {
    const mfaCode = typeof params.mfaCode === 'string' ? params.mfaCode.trim() : '';
    if (!mfaCode) {
      await AuditLog.record({
        action: 'mfa_challenge',
        category: 'auth',
        userId: user._id,
        username,
        ip,
        userAgent,
        fingerprint,
        success: true,
        reason: '密码已验证，等待两步验证码',
      }).catch(() => {});
      return { outcome: 'MFA_REQUIRED' };
    }
    // MFA 验证码独立防爆破：锁定期内直接拒绝（与 failedLoginCount 双轨，
    // 攻击者持正确密码时也无法对 6 位码无限尝试）
    if (await isMfaLocked(user._id)) {
      logger.warn('登录拒绝 - MFA 验证通道锁定中', { username });
      await AuditLog.record({
        action: 'mfa_verify_failed',
        category: 'auth',
        userId: user._id,
        username,
        ip,
        userAgent,
        fingerprint,
        success: false,
        riskLevel: 'high',
        riskFactors: ['mfa_bruteforce'],
        reason: 'MFA 验证通道锁定期间尝试登录',
      }).catch(() => {});
      return { outcome: 'MFA_ATTEMPTS_EXCEEDED' };
    }

    // L5：重放防护——验证码命中的时间窗必须晚于最近一次成功使用的窗口；
    // 失败与密码错误同口径计入 failedLoginCount，连续失败触发账户锁定。
    // 支持 6 位 TOTP 或备用恢复码（XXXX-XXXX）二选一：手机丢失/换机时的恢复途径
    const mfaUser = await User.findById(user._id).select(
      '+mfaSecret +mfaLastCounter +mfaRecoveryCodes'
    );
    let totpResult = null;

    if (/^\d{6}$/.test(mfaCode)) {
      totpResult = verifyTotpDetailed(decryptMfaSecret(mfaUser?.mfaSecret), mfaCode);
      // P2-12 修复：重放防护必须原子。原实现「读 mfaLastCounter → 比较 → 事后无条件覆写」
      // 三步分离，两个携带同一有效验证码的并发请求都会读到旧 counter、都判定通过，
      // 造成 TOTP 双花（同一 6 位码换取两个会话）。
      // 现改为条件更新：以 `mfaLastCounter < counter` 为过滤条件推进，
      // 只有第一个请求能命中（DB 保证），其余落入重放分支。
      // 与恢复码的原子消费（下方 $pull 条件过滤）口径一致。
      let claimedCounter = false;
      if (totpResult.valid) {
        const advanced = await User.findOneAndUpdate(
          {
            _id: user._id,
            $or: [
              { mfaLastCounter: { $lt: totpResult.counter } },
              { mfaLastCounter: { $exists: false } },
              { mfaLastCounter: null },
            ],
          },
          { $set: { mfaLastCounter: totpResult.counter } },
          { new: true }
        ).catch(() => null);
        claimedCounter = !!advanced;
      }

      const replayed = totpResult.valid && !claimedCounter;
      if (!totpResult.valid || replayed) {
        logger.warn(`登录失败 - 两步验证码${replayed ? '重放' : '错误'}`, { username });
        // 原子递增（与密码失败路径同口径，见下）
        const updated = await User.findByIdAndUpdate(
          user._id,
          { $inc: { failedLoginCount: 1 } },
          { new: true }
        ).catch(() => null);
        const newCount = updated?.failedLoginCount ?? (user.failedLoginCount || 0) + 1;
        if (newCount >= 10) {
          await User.findByIdAndUpdate(user._id, {
            lockUntil: new Date(Date.now() + 10 * 60 * 1000),
          }).catch(() => {});
          logger.warn('账户临时锁定（MFA 失败累计）', { username, failedCount: newCount });
        }
        // 独立防爆破计数（6 位码空间小，必须有独立阈值）
        await recordMfaFailure(user);
        await AuditLog.record({
          action: 'mfa_verify_failed',
          category: 'auth',
          userId: user._id,
          username,
          ip,
          userAgent,
          fingerprint,
          success: false,
          riskLevel: replayed ? 'high' : 'medium',
          riskFactors: [replayed ? 'mfa_code_replay' : 'mfa_code_invalid'],
          reason: replayed ? '两步验证码重放' : '两步验证码错误',
        }).catch(() => {});
        return { outcome: 'MFA_CODE_INVALID' };
      }
    } else {
      // 备用恢复码路径：格式 XXXX-XXXX，命中即消费（一次性）
      const normalized = mfaCode.toUpperCase().replace(/\s/g, '');
      // 辅助函数：恢复码失败时统一记录（增量 failedLoginCount + MFA 独立计数），
      // 与上方 6 位 TOTP 错误路径保持口径一致，消除"恢复码爆破不触发账户锁定"的逻辑漏洞
      const handleRecoveryFailure = async (riskFactors, reason) => {
        const incUpdated = await User.findByIdAndUpdate(
          user._id,
          { $inc: { failedLoginCount: 1 } },
          { new: true }
        ).catch(() => null);
        const newCount = incUpdated?.failedLoginCount ?? (user.failedLoginCount || 0) + 1;
        if (newCount >= 10) {
          await User.findByIdAndUpdate(user._id, {
            lockUntil: new Date(Date.now() + 10 * 60 * 1000),
          }).catch(() => {});
          logger.warn('账户临时锁定（恢复码验证失败累计）', { username, failedCount: newCount });
        }
        await recordMfaFailure(user);
        await AuditLog.record({
          action: 'mfa_verify_failed',
          category: 'auth',
          userId: user._id,
          username,
          ip,
          userAgent,
          fingerprint,
          success: false,
          riskLevel: 'high',
          riskFactors,
          reason,
        }).catch(() => {});
      };
      if (!/^[A-HJ-KM-NP-Z2-9]{4}-[A-HJ-KM-NP-Z2-9]{4}$/.test(normalized)) {
        await handleRecoveryFailure(['recovery_code_invalid'], '恢复码格式无效');
        return { outcome: 'MFA_CODE_INVALID' };
      }
      const codeHash = hashRecoveryCode(normalized);
      // 原子消费：以「数组中仍含该摘要」为过滤条件执行 $pull 并要求命中——
      // 消除 check 与 pull 分离导致的并发双花窗口；未命中即视为无效。
      //
      // 必须用 findOneAndUpdate 而非 findByIdAndUpdate（Critical 修复）：
      // findByIdAndUpdate 只从第一参取 _id，其余键被**静默丢弃**——
      // 实测传 { _id, mfaRecoveryCodes: '不存在的摘要' } 依然返回文档，
      // 于是任意「格式合法」的恢复码都能通过校验并签发会话，
      // 等同于对所有已开启 MFA 的账户完全绕过两步验证。
      const consumed = await User.findOneAndUpdate(
        { _id: user._id, mfaRecoveryCodes: codeHash },
        { $pull: { mfaRecoveryCodes: codeHash } },
        { new: true, select: '+mfaRecoveryCodes' }
      ).catch(() => null);
      if (!consumed) {
        logger.warn('登录失败 - 备用恢复码无效', { username });
        await handleRecoveryFailure(['recovery_code_invalid'], '备用恢复码不匹配');
        return { outcome: 'MFA_CODE_INVALID' };
      }

      const remaining = Array.isArray(consumed.mfaRecoveryCodes)
        ? consumed.mfaRecoveryCodes.length
        : 0;
      if (remaining <= 3) {
        logger.warn('备用恢复码余量不足', { username, remaining });
      }
      await AuditLog.record({
        action: 'login_recovery_code',
        category: 'auth',
        userId: user._id,
        username,
        ip,
        userAgent,
        fingerprint,
        success: true,
        riskLevel: 'medium',
        riskFactors: ['recovery_code_used'],
        reason: `使用备用恢复码登录（剩余 ${remaining} 个）`,
      }).catch(() => {});
    }

    await resetMfaFailures(user._id);

    // mfaLastCounter 已在上方的原子条件更新中推进，此处无需再写
    // （原实现在此无条件覆写，正是 TOTP 双花的成因之一）
  }

  // 检查非常规时间登录
  const { isUnusual, hour } = checkUnusualTime();
  if (isUnusual) {
    logger.info('非常规时间登录', { username, hour });
    // 记录非常规时间访问日志
    await AuditLog.create({
      action: 'login_unusual_time',
      category: 'auth',
      userId: user._id,
      username,
      ip,
      userAgent,
      riskLevel: 'medium',
      riskFactors: ['unusual_time_access'],
      body: { loginHour: hour },
    }).catch(() => {});
  }

  // 更新登录信息（使用 findByIdAndUpdate 避免触发完整 pre-save 钩子）
  await User.findByIdAndUpdate(user._id, {
    lastLoginAt: new Date(),
    lastLoginIp: ip,
    failedLoginCount: 0,
    lockUntil: null,
  });

  // 获取用户角色和权限
  const populatedUser = await User.findById(user._id).populate({
    path: 'roles',
    select: 'name code',
    populate: { path: 'permissions', select: 'code' },
  });
  // 安全修复：populate 后可能存在 null（指向已删除角色的 ObjectId），需过滤
  const roles = populatedUser.roles.map((r) => r?.code).filter(Boolean);
  const permissions = [
    ...new Set(populatedUser.roles.flatMap((r) => r?.permissions?.map((p) => p.code) || [])),
  ];

  // 生成 Token（携带 tokenVersion，用于后续会话吊销校验）
  // sessionId（jti）在此显式生成，使登录审计与后续该会话的所有请求审计可关联为同一会话链。
  //
  // 设备级会话：sid 与本次登录的 UserSession 记录一一对应，且**跨 refresh 轮换保持不变**，
  // 这样用户在「登录会话」界面踢除某台设备后，那台设备即使刷新令牌也无法复活。
  // 登录路径复用同一个 UUID 作为 sessionId 与 sid：两者语义一致（都标识本次登录），
  // 分开生成只会让审计日志的 sessionId 与会话表的 sid 无法对应，事后追溯断链。
  const sessionId = crypto.randomUUID();
  const sid = sessionId;
  const token = generateToken(
    user._id,
    user.username,
    user.email,
    roles,
    user.realName,
    user.tokenVersion,
    sessionId,
    sid
  );
  const refreshToken = generateRefreshToken(user._id, user.tokenVersion, sid);

  // 会话注册表落库：失败不阻断登录，但要降级为「令牌不含可吊销会话」。
  // 若此处失败仍下发带 sid 的令牌，authenticate 会因查不到会话而拒绝该令牌，
  // 用户登录成功却立刻无法访问任何接口——比「本次登录不支持设备级吊销」严重得多。
  let sessionRegistered = false;
  try {
    await sessionService.createSession({ userId: user._id, req: ctx.req, sid });
    sessionRegistered = true;
  } catch (e) {
    logger.error(`登录会话注册失败（本次登录降级为无设备级吊销能力）：${e.message}`);
  }
  const issuedToken = sessionRegistered
    ? token
    : generateToken(
        user._id,
        user.username,
        user.email,
        roles,
        user.realName,
        user.tokenVersion,
        sessionId
      );
  const issuedRefreshToken = sessionRegistered
    ? refreshToken
    : generateRefreshToken(user._id, user.tokenVersion);

  logger.info('用户登录成功', { username });

  // 操作溯源：记录登录成功
  AuditLog.recordLogin(user._id, username, ip, true, userAgent, { sessionId, fingerprint }).catch(
    (e) => {
      logger.warn(`登录审计落库失败：${e.message}`);
    }
  );

  return {
    outcome: 'OK',
    token: issuedToken,
    refreshToken: issuedRefreshToken,
    user: {
      userId: user._id,
      username: user.username,
      email: user.email,
      realName: user.realName,
      roles,
      permissions,
    },
  };
}

/**
 * 刷新令牌轮换（业务层）
 * @returns {Promise<{outcome:'MISSING'|'INVALID'|'IP_DENIED'|'PASSWORD_CHANGED'|'VERSION_MISMATCH'|'BLACKLIST_UNAVAILABLE'|'REPLAYED'|'REVOKE_UNAVAILABLE'|'SESSION_UNAVAILABLE'|'SESSION_REVOKED'|'EXPIRED'|'OK'}>}
 *   OK 时附 { token, refreshToken }
 */
async function refreshSession(refreshTokenRaw, ctx) {
  if (!refreshTokenRaw) {
    return { outcome: 'MISSING' };
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshTokenRaw, config.jwt.refreshSecret, { algorithms: ['HS256'] });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return { outcome: 'EXPIRED' };
    }
    return { outcome: 'INVALID' };
  }

  if (decoded.type !== 'refresh') {
    return { outcome: 'INVALID' };
  }

  // 先做廉价校验（用户状态/IP 范围/密码修改时间/tokenVersion），
  // 最后一步才做原子消费——把「查黑名单→加黑名单」合并为一次原子抢占：
  // 并发的两次 /refresh 只有一次能换取新令牌对，另一次进入重放检测，
  // 消除原「检查与轮换非原子」的 TOCTOU 平行会话窗口
  const user = await User.findById(decoded.userId);
  if (!user || user.status !== 'active') {
    return { outcome: 'INVALID' };
  }

  // 修复：刷新令牌轮换时补齐 IP 访问范围校验（与登录口径一致），
  // 防止 refresh token 被窃取后从任意 IP 完成轮换导致合法用户被踢出（会话 DoS）
  if (user.allowedIPs) {
    const { allowed } = isIPAllowed(ctx.ip, user.allowedIPs);
    if (!allowed) {
      logger.warn('Refresh 拒绝 - IP 不在允许范围', { username: user.username, ip: ctx.ip });
      return { outcome: 'IP_DENIED' };
    }
  }

  // 检查密码是否已修改（签发时间早于密码修改时间则拒绝）
  // 秒级比较（与 authenticate 中间件同口径）：iat 为秒、passwordChangedAt 为毫秒，
  // 直接毫秒比较会把「改密后同一秒内签发」的令牌误判为失效
  if (user.passwordChangedAt && decoded.iat) {
    const passwordChangedSec = Math.floor(user.passwordChangedAt.getTime() / 1000);
    if (passwordChangedSec > decoded.iat) {
      return { outcome: 'PASSWORD_CHANGED' };
    }
  }

  const populatedUser = await User.findById(user._id).populate({
    path: 'roles',
    select: 'name code',
  });
  // 安全修复：populate 后可能存在 null（指向已删除角色的 ObjectId），需过滤
  const roles = populatedUser.roles.map((r) => r?.code).filter(Boolean);

  // 校验 tokenVersion：缺失（早期签发的旧 token）或不匹配（该用户已被吊销全部会话）
  // 一律拒绝，与 authenticate 中间件口径保持一致（历史文档缺字段时按 0 参与比对）
  const expectedTokenVersion = user.tokenVersion ?? 0;
  if (decoded.tokenVersion === undefined || decoded.tokenVersion !== expectedTokenVersion) {
    return { outcome: 'VERSION_MISMATCH' };
  }

  // 原子消费旧 refresh token（一次性使用）；已被消费 → 重放检测
  let claimed = false;
  try {
    claimed = await consumeToken(refreshTokenRaw, decoded.exp);
  } catch (consumeErr) {
    logger.error(`Refresh 轮换中止 - 黑名单服务故障：${consumeErr.message}`);
    return { outcome: 'BLACKLIST_UNAVAILABLE' };
  }
  if (!claimed) {
    // 重放检测：已失效的 refresh token 被再次使用，可能遭到窃取 → 吊销该用户全部会话。
    // fail-closed：吊销失败时不能按 REPLAYED「已处置」返回——攻击者会话仍然在线，
    // 上抛 REVOKE_UNAVAILABLE 由控制器回 503，让客户端重试并触发告警，而不是静默放行
    try {
      await invalidateUserTokens(decoded.userId);
    } catch (revokeErr) {
      logger.error(`重放检测触发但会话吊销失败：${revokeErr.message}`, {
        userId: decoded.userId,
      });
      return { outcome: 'REVOKE_UNAVAILABLE' };
    }
    // 会话表须与 tokenVersion 保持一致：否则「登录会话」界面会留下一批
    // 显示 active 但实际已不能用的僵尸记录，用户看到的信息与事实不符
    await sessionService.revokeAllSessionsSafe(decoded.userId, 'token_reuse');
    logger.warn('Refresh token 重放检测触发，吊销用户全部会话', { userId: decoded.userId });
    return { outcome: 'REPLAYED' };
  }

  // 设备级会话校验：轮换必须继承原 sid，且该会话仍须可用。
  //
  // 这是「踢除设备后不能复活」的关键一环 —— 若此处不校验，被踢设备手里的
  // refresh token 依然有效，一次刷新就能换到不带 sid（或带新 sid）的令牌，
  // 绕过整个设备级吊销机制。
  const rotateSid = decoded.sid || null;
  if (rotateSid) {
    let sessionState;
    try {
      sessionState = await sessionService.validateSession(rotateSid);
    } catch (sessErr) {
      logger.error(`Refresh 轮换中止 - 会话服务故障：${sessErr.message}`);
      return { outcome: 'SESSION_UNAVAILABLE' };
    }
    if (!sessionState.usable) {
      logger.warn(`Refresh 拒绝 - 会话已被吊销：sid=${String(rotateSid).slice(0, 8)}…`);
      return { outcome: 'SESSION_REVOKED' };
    }
  }

  // 签发新的 access token + refresh token（携带当前 tokenVersion 与原 sid）
  const token = generateToken(
    user._id,
    user.username,
    user.email,
    roles,
    user.realName,
    user.tokenVersion,
    crypto.randomUUID(),
    rotateSid
  );
  const refreshToken = generateRefreshToken(user._id, user.tokenVersion, rotateSid);

  return { outcome: 'OK', token, refreshToken };
}

/**
 * 修改密码（业务层）
 * @param {string} userId
 * @param {object} body 原始请求体（含明文轨与密文轨字段）
 * @param {object} ctx { username } 供审计/日志使用
 * @returns {Promise<{outcome:'ENC_INVALID'|'MISSING'|'WEAK'|'USER_NOT_FOUND'|'CURRENT_WRONG'|'SAME_PASSWORD'|'REVOKE_FAILED'|'OK'}>}
 *   OK / REVOKE_FAILED 时附 { username }（REVOKE_FAILED 表示密码已改但会话吊销失败）
 */
async function changeUserPassword(userId, body, ctx) {
  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  // 密文轨解密后走原有校验流程（非空/强度检查对双轨同样生效）
  let currentPassword;
  if (typeof body.encCurrentPassword === 'string' && body.encCurrentPassword) {
    try {
      currentPassword = await decryptLoginCredential(body.encCurrentPassword);
    } catch (err) {
      logger.warn('改密拒绝 - 当前口令密文无效', { username: ctx.username, code: err.code });
      return { outcome: 'ENC_INVALID' };
    }
  } else {
    currentPassword = body.currentPassword;
  }

  let newPassword;
  if (typeof body.encNewPassword === 'string' && body.encNewPassword) {
    try {
      newPassword = await decryptLoginCredential(body.encNewPassword);
    } catch (err) {
      logger.warn('改密拒绝 - 新口令密文无效', { username: ctx.username, code: err.code });
      return { outcome: 'ENC_INVALID' };
    }
  } else {
    newPassword = body.newPassword;
  }

  if (!currentPassword || !newPassword) {
    return { outcome: 'MISSING' };
  }

  // 确认密码一致性（评价报告 #15 收敛点：原 securityController 内联比对，
  // 密文轨下明文只有解密后才知道，因此统一在解密完成后于业务层校验。
  // 客户端未携带 confirmPassword 时不强制——/api/auth/password 一直如此）
  if (typeof body.confirmPassword === 'string' && body.confirmPassword) {
    if (body.confirmPassword !== newPassword) {
      return { outcome: 'CONFIRM_MISMATCH' };
    }
  }

  // 统一企业级密码强度策略
  const strengthError = validatePasswordStrength(newPassword);
  if (strengthError) {
    return { outcome: 'WEAK', message: strengthError };
  }

  const user = await User.findById(userId).select('+password');
  if (!user) {
    return { outcome: 'USER_NOT_FOUND' };
  }

  const isMatch = await user.comparePassword(currentPassword);
  if (!isMatch) {
    return { outcome: 'CURRENT_WRONG' };
  }

  // 检查新密码是否与旧密码相同
  if (await user.comparePassword(newPassword)) {
    return { outcome: 'SAME_PASSWORD' };
  }

  user.password = newPassword;
  user.passwordChangedAt = new Date();
  await user.save();

  // 改密后立即吊销该用户全部会话（tokenVersion 递增 + 缓存失效），并审计。
  // fail-closed：密码已落库，吊销失败绝不能静默吞掉——旧会话是否仍有效处于未知态，
  // 返回 REVOKE_FAILED 让控制器如实告知「已改但未吊销」，而不是用 500 掩盖部分成功
  try {
    await invalidateUserTokens(user._id);
  } catch (revokeErr) {
    logger.error(`改密成功但会话吊销失败：${revokeErr.message}`, { username: user.username });
    return { outcome: 'REVOKE_FAILED', username: user.username };
  }
  // 会话表须与 tokenVersion 同步收敛：tokenVersion 递增已让所有令牌失效，
  // 但会话记录若仍是 active，「登录会话」界面会列出一批实际已掉线的设备，
  // 用户按列表判断「账号是否被别人登录着」就会得到错误结论。
  // 用 Safe 版本：收敛失败只是「显示不准」，不能让改密请求整体失败
  await sessionService.revokeAllSessionsSafe(user._id, 'password_changed');

  logger.info('用户修改密码', { username: user.username });

  return { outcome: 'OK', username: user.username };
}

/**
 * 更新个人资料（业务层）
 *
 * 【H-01 修复】department 刻意不在自助可改字段内：
 * 它是数据范围的唯一来源（middleware/rbac.js:195 以 user.department 构造
 * department 型 dataScope，再经 constants/dataScopeFields.js 映射为各业务
 * 资源的过滤字段）。若允许用户自助修改，持有 level>=7 角色的账户只需一次
 * PUT /api/auth/profile 即可把 dataScope 指向任意部门，绕过部门隔离读取并
 * 导出该部门的设备/报警/巡检/用户数据。
 *
 * 反向证据：管理员改他人部门（PUT /api/users/:id）是有层级校验的，
 * 而自助入口原先无任何关卡——这一不对称说明原实现是疏漏而非设计。
 *
 * 部门变更应经管理员接口（userController），不自助。
 *
 * @returns {Promise<{outcome:'NOT_FOUND'|'INVALID_PHONE'|'INVALID_EMAIL'|'EMAIL_TAKEN'|'INVALID_AVATAR'|'OK'}>}
 *   OK 时附 { profile }
 */
async function updateUserProfile(userId, body) {
  // 注意：不解构 department——即使请求体携带该字段也会被静默忽略（不报错，
  // 避免向调用方暴露"该字段不可改"的实现细节）
  const { realName, email, phone, avatar } = body;

  const user = await User.findById(userId);
  if (!user) {
    return { outcome: 'NOT_FOUND' };
  }

  // 验证手机号格式（如果提供）
  if (phone && !/^1[3-9]\d{9}$/.test(phone)) {
    return { outcome: 'INVALID_PHONE' };
  }

  // 验证邮箱格式（如果提供）
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { outcome: 'INVALID_EMAIL' };
  }

  // 检查邮箱是否已被其他用户使用
  if (email && email !== user.email) {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return { outcome: 'EMAIL_TAKEN' };
    }
  }

  // 头像白名单校验：仅允许 http(s) URL、相对图片路径或 data:image 数据 URI（不含 svg，防存储型脚本注入）
  if (avatar !== undefined && avatar !== '' && !isValidAvatar(avatar)) {
    return { outcome: 'INVALID_AVATAR' };
  }

  // 更新允许的字段（白名单，非黑名单）
  // department 不在其列——见函数头 H-01 说明；它是授权范围来源，只能由管理员改
  if (realName !== undefined) user.realName = realName;
  if (email !== undefined) user.email = email;
  if (phone !== undefined) user.phone = phone;
  if (avatar !== undefined) user.avatar = avatar;

  await user.save();

  logger.info('用户更新了个人资料', { username: user.username });

  return {
    outcome: 'OK',
    profile: {
      userId: user._id,
      username: user.username,
      realName: user.realName,
      email: user.email,
      phone: user.phone,
      department: user.department,
      avatar: user.avatar,
    },
  };
}

/**
 * 管理员锁定/解锁用户账户（O-2 自 securityController.toggleUserLock 下沉）
 *
 * 业务规则原样迁移：层级校验（同级及以上拦截，含 isSelf 豁免）、内置超管
 * 锁定拒绝、inactive 双向状态机保护（禁用账户不可借解锁复活、亦不可重复
 * 锁定）、成功后缓存失效与专用审计落库。控制器只保留参数校验与
 * outcome → HTTP 响应映射，行为口径与迁移前逐项一致
 * （securityCoverageGap.test.js 的 toggleUserLock 分支为安全网）。
 *
 * @param {string} userId 目标用户 ID
 * @param {object} params { locked: boolean, reason?: string }
 * @param {object} ctx { operatorId, operatorUsername, ip, userAgent }
 * @returns {Promise<{outcome:'NOT_FOUND'|'FORBIDDEN_SAME_LEVEL'|'CANNOT_LOCK_SUPER_ADMIN'|'INACTIVE_UNLOCK'|'INACTIVE_LOCK'|'NOT_LOCKED'|'OK', ...}>}
 */
async function setUserLockStatus(userId, { locked, reason }, ctx) {
  const { operatorId, operatorUsername, ip, userAgent } = ctx;

  const user = await User.findById(userId);
  if (!user) {
    return { outcome: 'NOT_FOUND' };
  }

  // 层级校验：禁止锁定/解锁等于或高于自身层级的用户
  // select 必须包含 isBuiltIn，否则下方内置超管保护判断恒为 false（死代码）
  const targetUserRoles = await Role.find({ _id: { $in: user.roles } }).select(
    'level code isBuiltIn'
  );
  const targetMaxLevel =
    targetUserRoles.length > 0 ? Math.max(...targetUserRoles.map((r) => r.level || 0)) : 0;

  // 按操作者 ID 重新查询角色层级（req.user.roles 存的是角色编码字符串，
  // 直接用于 _id: {$in: ...} 会触发 CastError，导致整个接口 500）
  const operatorMaxLevel = await getOperatorMaxLevel(operatorId);

  // 禁止操作同级或更高级别的用户
  if (targetMaxLevel >= operatorMaxLevel && String(user._id) !== String(operatorId)) {
    return { outcome: 'FORBIDDEN_SAME_LEVEL' };
  }

  // 禁止锁定超级管理员（无 isSelf 例外：锁定后层级校验会拦下所有解锁尝试）
  const isBuiltInSuperAdmin = targetUserRoles.some(isSuperAdminRole);
  if (locked && isBuiltInSuperAdmin) {
    return { outcome: 'CANNOT_LOCK_SUPER_ADMIN' };
  }

  // ===== 解锁/锁定状态保护 =====
  // 仅当账户当前确实处于锁定态时才允许解锁并恢复为 active；
  // 管理员禁用（inactive）的账户不允许借“解锁”复活，需先由管理员通过用户更新接口恢复启用
  if (!locked && user.status === 'inactive') {
    return { outcome: 'INACTIVE_UNLOCK' };
  }
  if (!locked && user.status !== 'locked') {
    return { outcome: 'NOT_LOCKED' };
  }
  // 锁定方向同样拒绝已禁用账户：若允许 inactive → locked，
  // 后续“锁定→解锁”链路会把禁用账户洗回 active，变相复活被禁用账户
  if (locked && user.status === 'inactive') {
    return { outcome: 'INACTIVE_LOCK' };
  }

  user.status = locked ? 'locked' : 'active';

  if (locked && reason) {
    user.remark = reason;
  }

  await user.save();

  // 失效用户缓存（与原实现一致：惰性 require，规避 middleware ↔ service 潜在循环）
  const { invalidateUserCache } = require('../middleware/auth');
  invalidateUserCache(user._id);
  // 锁定/解锁影响用户统计，目标用户与操作者（统计视角）的统计缓存均需失效
  const statsCache = require('./statsCache');
  statsCache.invalidateByUserId(user._id);
  statsCache.invalidateByUserId(operatorId);

  // 注意：不将用户级锁定关联到 IP 黑名单，避免误封 NAT 出口（原样保留）

  // 记录审计日志
  await AuditLog.create({
    action: locked ? 'user_locked' : 'user_unlocked',
    category: 'user',
    userId: operatorId,
    username: operatorUsername,
    targetUserId: user._id,
    targetUsername: user.username,
    reason,
    ip,
    userAgent,
    success: true,
    riskLevel: 'high',
  });

  logger.info('用户锁定状态变更', { username: user.username, locked, operator: operatorUsername });

  return {
    outcome: 'OK',
    userId: user._id,
    username: user.username,
    status: user.status,
    locked,
  };
}

/**
 * 登出令牌吊销（业务层）：把 access/refresh 令牌加入黑名单
 * @returns {Promise<{revokeFailed:boolean}>} revokeFailed=true 表示有令牌未能确认入库
 *
 * P2-26 fail-closed：令牌吊销未能落库时由控制器返回失败而非「登出成功」。
 * 原实现把 blacklistToken 的异常吞进 logger.warn 照常返回成功，于是
 * DB 瞬断期间「登出」只是清了 cookie —— 被窃取的 access token 在其剩余
 * 有效期（默认 2h）内仍可通过认证，而用户已认为会话已终止、不会再补救。
 * refresh 轮换路径（consumeToken）刻意 fail-closed，契约必须一致。
 */
async function revokeTokensOnLogout({ accessToken, refreshToken }) {
  // 吊销失败标记：任一令牌未能确认入库即视为登出未完成
  let revokeFailed = false;

  if (accessToken) {
    // 使用 verify 校验签名，防止伪造 token 污染黑名单
    let payload = null;
    try {
      payload = jwt.verify(accessToken, config.jwt.secret, { algorithms: ['HS256'] });
    } catch (e) {
      // 签名无效/已过期的令牌本就不可用，无需吊销，不算失败
      logger.warn(`登出时 access token 校验失败: ${e.message}`);
    }
    if (payload && payload.exp) {
      try {
        await blacklistToken(accessToken, payload.exp);
      } catch (e) {
        revokeFailed = true;
        logger.error(`登出未能吊销 access token（${e.code || e.message}）：令牌在过期前仍然可用`);
      }
    }
  }

  if (refreshToken) {
    let refreshPayload = null;
    try {
      refreshPayload = jwt.verify(refreshToken, config.jwt.refreshSecret, {
        algorithms: ['HS256'],
      });
    } catch (e) {
      // refresh token 校验失败说明它本就无效，不影响登出结论
      logger.warn(`登出时 refresh token 校验失败: ${e.message}`);
    }
    if (refreshPayload && refreshPayload.exp) {
      try {
        await blacklistToken(refreshToken, refreshPayload.exp);
      } catch (e) {
        revokeFailed = true;
        logger.error(`登出未能吊销 refresh token（${e.code || e.message}）：令牌在过期前仍然可用`);
      }
    }
  }

  return { revokeFailed };
}

module.exports = {
  registerUser,
  loginUser,
  refreshSession,
  changeUserPassword,
  updateUserProfile,
  setUserLockStatus,
  revokeTokensOnLogout,
};
