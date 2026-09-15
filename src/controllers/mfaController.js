/**
 * MFA 两步验证控制器（D-1 自 authController 拆出）
 *
 * MFA 生命周期管理端点：状态查询、登记、确认开启、关闭、恢复码重生成。
 * 登录流程内的 MFA 二期验证仍留在 authController.login（与登录时序/审计强耦合），
 * 共用的防爆破与恢复码原语统一收敛在 services/mfaService.js。
 */

const { validationResult } = require('express-validator');
const User = require('../models/User');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const AuditLog = require('../models/AuditLog');
const { generateSecret, verifyTotpDetailed, otpauthUri } = require('../utils/totp');
const { encryptMfaSecret, decryptMfaSecret } = require('../utils/mfaSecret');
const { decryptLoginCredential } = require('../utils/loginCipher');
const { invalidateUserCache } = require('../middleware/auth');
const {
  hashRecoveryCode,
  generateRecoveryCodes,
  isMfaLocked,
  recordMfaFailure,
  resetMfaFailures,
} = require('../services/mfaService');
const metrics = require('../utils/metrics');

const getMfaStatus = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('mfaEnabled +mfaRecoveryCodes');
  return ApiResponse.success(res, {
    enabled: !!(user && user.mfaEnabled),
    // 剩余恢复码数量：供前端低余量提醒（不暴露码本身）
    recoveryCodesRemaining: Array.isArray(user?.mfaRecoveryCodes)
      ? user.mfaRecoveryCodes.length
      : 0,
  });
});

/**
 * 重新生成备用恢复码（旧码全部作废）
 * POST /api/auth/mfa/recovery-codes  body: { mfaCode }
 * 敏感操作：需当前动态口令验证；受独立防爆破约束；明文仅本次响应返回
 */
const regenerateRecoveryCodes = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: errors.array() });
  }

  const code = typeof req.body.mfaCode === 'string' ? req.body.mfaCode.trim() : '';
  const user = await User.findById(req.user.userId).select('+mfaSecret +mfaRecoveryCodes');
  if (!user) return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
  if (!user.mfaEnabled || !user.mfaSecret) {
    return ApiResponse.codeError(res, 'MFA_NOT_ENABLED_NO_CODES');
  }

  if (await isMfaLocked(user._id)) {
    return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
  }

  const totpResult = verifyTotpDetailed(decryptMfaSecret(user.mfaSecret), code);
  if (!totpResult.valid) {
    await recordMfaFailure(user);
    AuditLog.record({
      action: 'recovery_codes_regenerate',
      category: 'auth',
      userId: user._id,
      username: user.username,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      success: false,
      riskLevel: 'medium',
      reason: '重新生成恢复码失败：动态口令错误',
    }).catch(() => {});
    return ApiResponse.codeError(res, 'MFA_REGEN_CODE_INVALID');
  }

  const recoveryCodes = generateRecoveryCodes(10);
  await User.findByIdAndUpdate(user._id, {
    mfaRecoveryCodes: recoveryCodes.map(hashRecoveryCode),
    // L5：记录已消费的时间窗——本端点用过的码在同窗口内不得再用于登录
    // （与 mfaEnable 同口径；此前缺失使该码可被双花）
    mfaLastCounter: totpResult.counter,
  });
  await resetMfaFailures(user._id);

  logger.info('用户重新生成备用恢复码', { username: user.username });
  metrics.incMfaAction('recovery_regenerate');
  AuditLog.record({
    action: 'recovery_codes_regenerate',
    category: 'auth',
    userId: user._id,
    username: user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
    reason: '重新生成 10 个备用恢复码（旧码作废）',
  }).catch(() => {});

  return ApiResponse.success(res, { recoveryCodes }, '已生成新的备用恢复码，请立即保存');
});

/**
 * 生成 MFA 密钥（开启第一步）
 * POST /api/auth/mfa/enroll
 * 返回 Base32 密钥与 otpauth:// URI，secret 暂存用户记录（未启用前不生效）
 */
const mfaEnroll = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('+mfaSecret');
  if (!user) return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
  if (user.mfaEnabled) return ApiResponse.codeError(res, 'MFA_ALREADY_ENABLED_NO_REPEAT');

  // 修复 B1：用户已 enroll 但未 enable 时返回已有密钥，避免重复生成覆盖已扫码的密钥
  // P2-15：库内为密文，回显给认证器前必须解密（存量明文由 decryptMfaSecret 原样透传）
  if (user.mfaSecret && !user.mfaEnabled) {
    const existing = decryptMfaSecret(user.mfaSecret);
    if (existing) {
      return ApiResponse.success(
        res,
        {
          secret: existing,
          otpauthUri: otpauthUri(existing, user.email || user.username, '消防管理系统'),
        },
        '密钥已存在，请在认证器中添加后输入验证码确认'
      );
    }
    // 解密失败（密钥轮换/数据损坏）：不能返回空密钥让用户扫一个废二维码，
    // 落到下方重新生成分支覆盖掉这条不可用的记录
    logger.warn('MFA 待确认密钥无法解密，将重新生成', { userId: user._id });
  }

  const secret = generateSecret();
  // 静态加密后落库：明文种子等同于「可无限生成有效验证码的凭证」，
  // 不应与业务数据同等级明文存放（详见 utils/mfaSecret.js）
  await User.findByIdAndUpdate(user._id, {
    mfaSecret: encryptMfaSecret(secret),
    mfaEnabled: false,
  });

  AuditLog.record({
    action: 'mfa_enroll',
    category: 'auth',
    userId: user._id,
    username: user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    reason: '生成两步验证密钥（待确认）',
  }).catch(() => {});

  return ApiResponse.success(
    res,
    {
      secret,
      otpauthUri: otpauthUri(secret, user.email || user.username, '消防管理系统'),
    },
    '密钥已生成，请在认证器中添加后输入验证码确认'
  );
});

/**
 * 确认开启 MFA（开启第二步：校验一次动态口令）
 * POST /api/auth/mfa/enable  body: { mfaCode }
 */
const mfaEnable = asyncHandler(async (req, res) => {
  const code = typeof req.body.mfaCode === 'string' ? req.body.mfaCode.trim() : '';
  if (!/^\d{6}$/.test(code)) {
    return ApiResponse.codeError(res, 'MFA_CODE_FORMAT');
  }

  const user = await User.findById(req.user.userId).select('+mfaSecret +mfaLastCounter');
  if (!user) return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
  if (user.mfaEnabled) return ApiResponse.codeError(res, 'MFA_ALREADY_ENABLED');
  if (!user.mfaSecret) return ApiResponse.codeError(res, 'MFA_SECRET_MISSING');

  // 独立防爆破：确认码同样受锁定与失败计数约束
  if (await isMfaLocked(user._id)) {
    return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
  }

  const totpResult = verifyTotpDetailed(decryptMfaSecret(user.mfaSecret), code);
  if (!totpResult.valid) {
    await recordMfaFailure(user);
    return ApiResponse.codeError(res, 'MFA_CODE_INVALID_SYNC');
  }

  // 生成备用恢复码：仅此刻返回明文，服务端只存摘要；旧恢复码全部作废
  const recoveryCodes = generateRecoveryCodes(10);

  // L5：记录已消费的时间窗（开启确认用过的码不能再用于登录）
  // 同步失效 authenticate 的 60s 用户缓存，防 MFA 保护延迟生效窗口
  await User.findByIdAndUpdate(user._id, {
    mfaEnabled: true,
    mfaLastCounter: totpResult.counter,
    mfaRecoveryCodes: recoveryCodes.map(hashRecoveryCode),
  });
  await resetMfaFailures(user._id);
  invalidateUserCache(String(user._id));

  logger.info('用户开启 MFA 并生成备用恢复码', { username: user.username });
  metrics.incMfaAction('enable');
  AuditLog.record({
    action: 'mfa_enable',
    category: 'auth',
    userId: user._id,
    username: user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
    reason: '开启两步验证并生成 10 个备用恢复码',
  }).catch(() => {});

  return ApiResponse.success(
    res,
    { enabled: true, recoveryCodes },
    '两步验证已开启，请立即保存备用恢复码'
  );
});

/**
 * 关闭 MFA
 * POST /api/auth/mfa/disable  body: { mfaCode } 或 { currentPassword }
 */
const mfaDisable = asyncHandler(async (req, res) => {
  // G3：mfaCode / currentPassword 的类型与长度校验结果
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: errors.array() });
  }

  const user = await User.findById(req.user.userId).select('+password +mfaSecret');
  if (!user) return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
  if (!user.mfaEnabled) return ApiResponse.codeError(res, 'MFA_NOT_ENABLED');

  const { mfaCode } = req.body;

  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  let currentPassword;
  if (typeof req.body.encCurrentPassword === 'string' && req.body.encCurrentPassword) {
    try {
      currentPassword = await decryptLoginCredential(req.body.encCurrentPassword);
    } catch (err) {
      logger.warn('关闭 MFA 拒绝 - 口令密文无效', { username: req.user?.username, code: err.code });
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    }
  } else {
    currentPassword = req.body.currentPassword;
  }
  // 关闭属敏感操作：要求动态口令或登录密码二选一，防会话劫持后被冒关。
  // 动态口令与密码两条路径统一受 MFA 防爆破锁定约束，防止攻击者绕行动态口令限速、
  // 通过 currentPassword 路径无限尝试用户登录密码
  const codePath = typeof mfaCode === 'string' && /^\d{6}$/.test(mfaCode.trim());
  const passwordPath = !codePath && typeof currentPassword === 'string' && currentPassword;
  if ((codePath || passwordPath) && (await isMfaLocked(user._id))) {
    return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
  }

  let verified = false;
  let verifyMethod = null;
  let consumedTotpCounter = null;
  if (codePath) {
    const totpResult = verifyTotpDetailed(decryptMfaSecret(user.mfaSecret), mfaCode.trim());
    verified = totpResult.valid;
    if (verified) consumedTotpCounter = totpResult.counter;
    verifyMethod = 'mfa_code';
    if (!verified) await recordMfaFailure(user);
  } else if (typeof currentPassword === 'string' && currentPassword) {
    verified = await user.comparePassword(currentPassword);
    verifyMethod = 'password';
    if (!verified) await recordMfaFailure(user);
  }
  if (!verified) {
    // 失败审计：密码路径此前零痕迹——会话被劫持者可借此无限在线爆破登录密码
    AuditLog.record({
      action: 'mfa_verify_failed',
      category: 'auth',
      userId: user._id,
      username: user.username,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      success: false,
      riskLevel: codePath ? 'medium' : 'high',
      riskFactors: [verifyMethod === 'password' ? 'disable_password_mismatch' : 'mfa_code_invalid'],
      reason: `关闭两步验证身份验证失败（方式：${verifyMethod || '未知'}）`,
    }).catch(() => {});
    return ApiResponse.codeError(res, 'MFA_VERIFY_FAILED');
  }

  // 全量清理：关闭的同时作废恢复码并重置防爆破计数
  await User.findByIdAndUpdate(user._id, {
    mfaEnabled: false,
    mfaSecret: '',
    mfaRecoveryCodes: [],
    mfaFailCount: 0,
    mfaLockUntil: null,
    // L5：动态口令路径消费的时间窗一并记录——关闭写库生效前，
    // 同一码仍可能被并发的登录请求双花（与 mfaEnable/regenerate 同口径）
    ...(consumedTotpCounter !== null ? { mfaLastCounter: consumedTotpCounter } : {}),
  });

  // 同步失效 60s 用户缓存，保证关闭立即生效（登录不再要求 MFA）
  invalidateUserCache(String(user._id));

  logger.warn('用户关闭 MFA', { username: user.username });
  metrics.incMfaAction('disable');
  AuditLog.record({
    action: 'mfa_disable',
    category: 'auth',
    userId: user._id,
    username: user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'high',
    riskFactors: ['mfa_disabled'],
    reason: '关闭两步验证',
  }).catch(() => {});

  return ApiResponse.success(res, { enabled: false }, '两步验证已关闭');
});

module.exports = {
  getMfaStatus,
  mfaEnroll,
  mfaEnable,
  mfaDisable,
  regenerateRecoveryCodes,
};
