/**
 * MFA 两步验证控制器（D-1 自 authController 拆出）
 *
 * MFA 生命周期管理端点：状态查询、登记、确认开启、关闭、恢复码重生成。
 * 登录流程内的 MFA 二期验证仍留在 authController.login（与登录时序/审计强耦合），
 * 共用的防爆破与恢复码原语统一收敛在 services/mfaService.js。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const User = require('../models/User');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { generateSecret, verifyTotpDetailed, otpauthUri } = require('../utils/totp');
const { encryptMfaSecret, decryptMfaSecret } = require('../utils/mfaSecret');
const { invalidateUserCache } = require('../middleware/auth');
const { auditClientAddress } = require('../utils/ipUtils');
const {
  hashRecoveryCode,
  generateRecoveryCodes,
  isMfaLocked,
  recordMfaFailure,
  resetMfaFailures,
  claimTotpWindow,
  recordMfaFailureAudit,
  recordMfaDisableFailure,
  normalizeDisableFactor,
  recordMfaDisableSuccess,
  revokeOtherSessionsAfterMfaChange,
} = require('../services/mfaService');
const { disableWithSecondFactor } = require('../services/mfaDisable');
const metrics = require('../utils/metrics');
// F-03（2026-10-17）：MFA 状态变更（登记/开启/关闭/恢复码重生成）是**业务状态已改变**
// 的安全操作，审计必须先持久化（DB 或审计 WAL）才允许回成功。写成
// `AuditLog.record(...).catch(() => {})` 不算数：record 自身已吞错返回 null，外层 catch
// 永不触发 ⇒ 落库失败只剩一条 error 日志，客户端照收"已开启"。
// 失败/拒绝路径（success:false 的 mfa_verify_failed 等）仍用 record：业务状态未改变，
// best-effort 是正确语义。
const { recordDurably } = require('../services/auditOutbox');

const getMfaStatus = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('mfaEnabled +mfaRecoveryCodes');
  return ApiResponse.success(res, {
    enabled: !!(user && user.mfaEnabled),
    // 剩余恢复码数量：供前端低余量提醒（不暴露码本身）
    recoveryCodesRemaining: user?.mfaRecoveryCodes?.length ?? 0,
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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
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
    recordMfaFailureAudit(req, user, {
      action: 'recovery_codes_regenerate',
      riskLevel: 'medium',
      reason: '重新生成恢复码失败：动态口令错误',
    });
    return ApiResponse.codeError(res, 'MFA_REGEN_CODE_INVALID');
  }

  // 口令有效 ≠ 口令可用。必须认领该时间窗，否则登录刚消费掉的码在 ±1 窗口
  // 残余有效期内还能在这里铸出 10 张新恢复码。
  if (!(await claimTotpWindow(user._id, totpResult.counter))) {
    await recordMfaFailure(user);
    recordMfaFailureAudit(req, user, {
      action: 'recovery_codes_regenerate',
      riskLevel: 'high',
      riskFactors: ['mfa_code_replayed'],
      reason: '重新生成恢复码被拒：动态口令所属时间窗已被消费（重放）',
    });
    return ApiResponse.codeError(res, 'MFA_REGEN_CODE_INVALID', {
      message: '该动态口令已被使用（同一时间窗内只能消费一次），请输入新的口令',
    });
  }

  const recoveryCodes = generateRecoveryCodes(10);
  // 条件更新（mfaEnabled + 旧码组全等），不是无条件覆盖：
  // 两次并发重生成携带**相邻窗口**的不同码时，两次 claimTotpWindow 都会成功
  // （窗口不同不算重放），后到者会把先到者刚下发的 10 张整组顶掉——调用方已经
  // 抄走并存进密码管理器的那一组全部作废，而两个响应都宣称"已生成"。
  // 与 mfaEnable:273 同一条判据：**下发即生效**，不得被并发请求静默回收。
  const prevCodes = user.mfaRecoveryCodes || [];
  // 空数组分支必须把「字段缺失」一起算上：Mongoose 读时给缺失路径补 default:[]，
  // 库里却没有这个字段，直接写 `mfaRecoveryCodes: []` 对历史文档永不命中，
  // 会把"一次都还没生成过码"的用户永久卡在 USER_STATE_CONFLICT。
  const prevFilter = { mfaRecoveryCodes: prevCodes.length ? prevCodes : { $in: [[], null] } };
  const reissued = await User.findOneAndUpdate(
    { _id: user._id, mfaEnabled: true, ...prevFilter },
    { $set: { mfaRecoveryCodes: recoveryCodes.map(hashRecoveryCode) } }
  );
  if (!reissued) {
    // 重读区分三种输法：用户没了 / MFA 已被并发关闭 / 码组被并发换过。
    // 后两种都不得返回本次的码——它们从未生效。前两种对调用方是同一件事
    // （没有可用的恢复码），合并成同一个码，省掉一条"用户刚被删"的假精确。
    const current = await User.findById(user._id).select('mfaEnabled');
    if (current && current.mfaEnabled) {
      return ApiResponse.codeError(res, 'USER_STATE_CONFLICT', {
        message: '恢复码刚被其他请求重新生成，本次未改动任何恢复码，请用新的动态口令重试',
      });
    }
    return ApiResponse.codeError(res, 'MFA_NOT_ENABLED_NO_CODES');
  }
  await resetMfaFailures(user._id);

  logger.info('用户重新生成备用恢复码', { username: user.username });
  metrics.incMfaAction('recovery_regenerate');
  // F-03：旧恢复码已作废、新码已落库 ⇒ 审计先持久化再回成功
  await recordDurably(
    {
      action: 'recovery_codes_regenerate',
      category: 'auth',
      userId: user._id,
      username: user.username,
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'medium',
      reason: '重新生成 10 个备用恢复码（旧码作废）',
    },
    { auditAction: 'recovery_codes_regenerate', req }
  );

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
  // 库内为密文，回显给认证器前必须解密（存量明文由 decryptMfaSecret 原样透传）
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
  const pendingFilter = user.mfaSecret
    ? { _id: user._id, mfaEnabled: { $ne: true }, mfaSecret: user.mfaSecret }
    : {
        _id: user._id,
        mfaEnabled: { $ne: true },
        $or: [{ mfaSecret: '' }, { mfaSecret: null }, { mfaSecret: { $exists: false } }],
      };
  // 条件写入而非无条件覆盖：两个并发 enroll 都读到「尚无密钥」时，后写者
  // 会把先写者刚返回给客户端的密钥换成另一把——先扫到的那张二维码从此永远校验失败。
  // 输家不重写，改读赢家已落库的密钥返回同一把（密钥退化为「本次配置的唯一事实」）。
  const written = await User.findOneAndUpdate(
    pendingFilter,
    { $set: { mfaSecret: encryptMfaSecret(secret) } },
    { new: true }
  );

  if (!written) {
    const current = await User.findById(user._id).select('mfaEnabled +mfaSecret');
    if (!current) return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
    if (current.mfaEnabled) return ApiResponse.codeError(res, 'MFA_ALREADY_ENABLED_NO_REPEAT');
    const currentSecret = current.mfaSecret && decryptMfaSecret(current.mfaSecret);
    if (!currentSecret) {
      // 并发期间被管理员重置/密钥损坏：绝不盲覆盖，交客户端重试以重新走一遍流程
      return ApiResponse.codeError(res, 'USER_STATE_CONFLICT');
    }
    return ApiResponse.success(
      res,
      {
        secret: currentSecret,
        otpauthUri: otpauthUri(currentSecret, user.email || user.username, '消防管理系统'),
      },
      '密钥已存在，请在认证器中添加后输入验证码确认'
    );
  }

  // F-03：待确认密钥已落库 ⇒ 审计先持久化再回成功
  await recordDurably(
    {
      action: 'mfa_enroll',
      category: 'auth',
      userId: user._id,
      username: user.username,
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      reason: '生成两步验证密钥（待确认）',
    },
    { auditAction: 'mfa_enroll', req }
  );

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

  // 口令有效 ≠ 口令可用：必须原子认领该时间窗，与 disable / regenerate / 登录同口径。
  // 只比水位的 `$max` 从不拒绝请求 ⇒ 并发两次 enable 携带同一个码会都通过，账号关闭 MFA
  // 后重开时水位仍保留上一次生命周期的消费记录、`$max` 同样不拒绝。认领让"同一时间窗只能
  // 用一次"成为 DB 层不变量。
  const claimed = await claimTotpWindow(user._id, totpResult.counter);
  if (!claimed) {
    await recordMfaFailure(user);
    logger.warn('MFA 开启被拒：动态口令所属时间窗已被消费（重放）', {
      username: user.username,
    });
    return ApiResponse.codeError(res, 'MFA_CODE_INVALID_SYNC', {
      message: '该动态口令已被使用（同一时间窗内只能消费一次），请输入新的口令',
    });
  }

  // 生成备用恢复码：仅此刻返回明文，服务端只存摘要；旧恢复码全部作废
  const recoveryCodes = generateRecoveryCodes(10);

  // 时间窗已由 claimTotpWindow 原子推进，此处**不得**再写 mfaLastCounter：再写一次只会
  // 制造"验证与写库之间"的第二段窗口。条件更新（mfaEnabled:false + 同一密钥）同样不可省：
  // 并发 enable 携带相邻窗口的不同码时两次认领都能成功，无此闸则后到者会把先到者刚下发的
  // 10 张恢复码整组顶掉——用户手里那组全部作废，而响应里又各自宣称"已开启"。
  const enabled = await User.findOneAndUpdate(
    { _id: user._id, mfaEnabled: false, mfaSecret: user.mfaSecret },
    {
      $set: { mfaEnabled: true, mfaRecoveryCodes: recoveryCodes.map(hashRecoveryCode) },
    },
    { new: true }
  );
  if (!enabled) {
    // 重读区分「并发已开启」与「用户已不存在」；两种都不得返回恢复码
    const current = await User.findById(user._id).select('mfaEnabled');
    if (!current) return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
    return ApiResponse.codeError(res, 'MFA_ALREADY_ENABLED');
  }
  // 同步失效 authenticate 的 60s 用户缓存，防 MFA 保护延迟生效窗口
  await resetMfaFailures(user._id);
  invalidateUserCache(String(user._id));
  // 开启 MFA 后，其他设备不能用旧会话继续绕过第二因子，必须重新登录
  await revokeOtherSessionsAfterMfaChange({
    userId: req.user.userId,
    exceptSid: req.user.sid,
    username: req.user.username,
    reason: 'mfa_enabled',
  });

  logger.info('用户开启 MFA 并生成备用恢复码', { username: user.username });
  metrics.incMfaAction('enable');
  // F-03：MFA 已开启 ⇒ 审计先持久化再回成功
  await recordDurably(
    {
      action: 'mfa_enable',
      category: 'auth',
      userId: user._id,
      username: user.username,
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'medium',
      reason: '开启两步验证并生成 10 个备用恢复码',
    },
    { auditAction: 'mfa_enable', req }
  );

  return ApiResponse.success(
    res,
    { enabled: true, recoveryCodes },
    '两步验证已开启，请立即保存备用恢复码'
  );
});

/**
 * 关闭 MFA
 * POST /api/auth/mfa/disable  body: { mfaCode } 或 { recoveryCode }
 *
 * 第二因子只认「持有认证器（TOTP）」或「持有恢复码」；登录密码不再是可单独
 * 通过的路径。密码是单因子——会话劫持者只要拿到会话，往往也能通过钓鱼/复用
 * 拿到密码，而关闭 MFA 的门槛恰应高于普通敏感操作：它移除的是后续所有登录的
 * 第二道防线。密码仍可作为附加校验字段传入，但不参与放行判定。
 */
const mfaDisable = asyncHandler(async (req, res) => {
  // G3：mfaCode / recoveryCode 的类型与长度校验结果
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const user = await User.findById(req.user.userId).select('+mfaSecret +mfaRecoveryCodes');
  if (!user) return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
  if (!user.mfaEnabled) return ApiResponse.codeError(res, 'MFA_NOT_ENABLED');

  const { mfaCode, normalizedCode, codePath, recoveryPath } = normalizeDisableFactor(req.body);

  if (!codePath && !recoveryPath) {
    // 旧客户端只送 currentPassword：明确告知第二因子要求，而不是伪装成"码错误"
    recordMfaDisableFailure(req, user, 'second_factor_missing');
    return ApiResponse.codeError(res, 'MFA_SECOND_FACTOR_REQUIRED');
  }

  // 两条第二因子路径统一受 MFA 防爆破锁定约束：不能借恢复码路径绕过 TOTP 的尝试限额
  if (await isMfaLocked(user._id)) {
    return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
  }

  // 关 MFA 的写全部收敛在 service：恢复码路径要求"消费码 + 清状态"同一条文档写
  // （拆两步会在第二步失败时留下码已消费、MFA 仍开启的死局）；TOTP 路径的
  // 条件写也锁定验证时的密钥，避免并发重新登记被误清。
  const result = await disableWithSecondFactor(user, {
    mfaCode,
    normalizedCode,
    codePath,
    recoveryPath,
  });
  if (result.outcome === 'VERIFY_FAILED') {
    recordMfaDisableFailure(req, user, result.verifyMethod);
    return ApiResponse.codeError(res, 'MFA_VERIFY_FAILED');
  }
  if (result.outcome === 'NOT_ENABLED') return ApiResponse.codeError(res, 'MFA_NOT_ENABLED');
  if (result.outcome === 'STATE_CONFLICT') {
    return ApiResponse.codeError(res, 'USER_STATE_CONFLICT', {
      message: '两步验证密钥刚被重新登记，本次关闭未生效，请用新密钥的动态口令重试',
    });
  }

  // 同步失效 60s 用户缓存，保证关闭立即生效（登录不再要求 MFA）
  invalidateUserCache(String(user._id));
  // 关闭 MFA 同样改变安全姿态：其他设备必须重新登录，避免旧会话绕过本次变更
  await revokeOtherSessionsAfterMfaChange({
    userId: req.user.userId,
    exceptSid: req.user.sid,
    username: req.user.username,
    reason: 'mfa_disabled',
  });

  logger.warn('用户关闭 MFA', { username: user.username });
  metrics.incMfaAction('disable');
  await recordMfaDisableSuccess(req, user, result.verifyMethod);

  return ApiResponse.success(res, { enabled: false }, '两步验证已关闭');
});

module.exports = {
  getMfaStatus,
  mfaEnroll,
  mfaEnable,
  mfaDisable,
  regenerateRecoveryCodes,
};
