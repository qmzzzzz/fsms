/**
 * MFA 两步验证基础服务（D-1 自 authController 拆出）
 *
 * 恢复码生成/摘要与 MFA 独立防爆破的原语层，供登录 MFA 步骤、
 * MFA 管理端点（controllers/mfaController.js）与管理员重置
 * （securityController.resetUserMfa）共用，避免多处各自实现。
 */

const crypto = require('crypto');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

// MFA 验证码连续失败阈值与锁定时长（独立于 failedLoginCount：
// 覆盖登录 MFA 步骤、关闭 MFA、重新生成恢复码等所有验证码校验路径）
const MFA_MAX_FAILS = 5;
const MFA_LOCK_MS = 10 * 60 * 1000;

/** 恢复码摘要：HMAC-SHA256（以服务端 HMAC 密钥为 pepper）。
 * 恢复码是低熵认证因子（~38.6 bit），无盐快哈希在库泄露后可被 GPU 快速穷举；
 * 加 pepper 后离线枚举需先拿到密钥。未配置密钥时退化为普通 sha256（开发/测试）。 */
const getRecoveryPepper = () => {
  try {
    return require('../config').hmacSecret || '';
  } catch {
    return process.env.HMAC_SECRET || '';
  }
};

const hashRecoveryCode = (code) => {
  const pepper = getRecoveryPepper();
  if (pepper) {
    return crypto.createHmac('sha256', pepper).update(code, 'utf8').digest('hex');
  }
  return crypto.createHash('sha256').update(code, 'utf8').digest('hex');
};

/**
 * 生成备用恢复码（默认 10 个，格式 XXXX-XXXX）
 * 字母表去除 0/O/1/I/L 等易混字符
 */
const generateRecoveryCodes = (count = 10) => {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const codes = [];
  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(8);
    let raw = '';
    for (let j = 0; j < 8; j++) raw += alphabet[bytes[j] % alphabet.length];
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return codes;
};

/** MFA 验证是否处于锁定窗口（连续失败达阈值后触发）。
 * 锁定自然到期时惰性清零失败计数：否则计数停留在阈值上，
 * 合法用户到期后手滑一次即立即再锁，等效"每 10 分钟仅一次试错"。 */
const isMfaLocked = async (userId) => {
  const u = await User.findById(userId).select('mfaLockUntil');
  if (!u || !u.mfaLockUntil) return false;
  if (u.mfaLockUntil > new Date()) return true;
  // 已过期：惰性重置，解除放大效应
  await User.findByIdAndUpdate(userId, { mfaFailCount: 0, mfaLockUntil: null }).catch(() => {});
  return false;
};

/** 记录一次 MFA 验证失败：原子递增，达阈值即锁定并审计 */
const recordMfaFailure = async (user) => {
  const updated = await User.findByIdAndUpdate(
    user._id,
    { $inc: { mfaFailCount: 1 } },
    { new: true }
  )
    .select('mfaFailCount')
    .catch(() => null);
  const count = updated?.mfaFailCount ?? 1;
  if (count >= MFA_MAX_FAILS) {
    await User.findByIdAndUpdate(user._id, {
      mfaLockUntil: new Date(Date.now() + MFA_LOCK_MS),
    }).catch(() => {});
    logger.warn('MFA 验证连续失败触发临时锁定', {
      username: user.username,
      failedCount: count,
      lockMinutes: 10,
    });
    AuditLog.record({
      action: 'mfa_attempt_locked',
      category: 'auth',
      userId: user._id,
      username: user.username,
      success: false,
      riskLevel: 'high',
      riskFactors: ['mfa_bruteforce'],
      reason: `MFA 验证连续失败 ${count} 次，验证通道临时锁定 10 分钟`,
    }).catch(() => {});
  }
};

/** MFA 验证成功后清零失败计数并解除锁定 */
const resetMfaFailures = (userId) => {
  return User.findByIdAndUpdate(userId, { mfaFailCount: 0, mfaLockUntil: null }).catch(() => {});
};

module.exports = {
  MFA_MAX_FAILS,
  MFA_LOCK_MS,
  getRecoveryPepper,
  hashRecoveryCode,
  generateRecoveryCodes,
  isMfaLocked,
  recordMfaFailure,
  resetMfaFailures,
};
