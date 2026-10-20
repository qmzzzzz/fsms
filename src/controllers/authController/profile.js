/**
 * 认证控制器 · 资料域（2026-10-19 自 `controllers/authController.js` 拆分）
 *
 * 覆盖：改密（含 PASSWORD_REUSED 历史复用、REVOKE_FAILED 诊断性审计）与个人资料更新。
 * 函数体与注释自原文件原样迁出，相对 require 路径加深一级。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { asyncHandler } = require('../../middleware/errorHandler');
// 审计写入失败的兜底档位（error 日志 + audit_write_failed 指标）——见 utils/auditWriteFailure.js。
// `AuditLog.record` 自带兜底，但 `recordSensitiveAction` 直接 `return this.create(...)`（无 catch），
// 所以它的调用方必须自己接住 rejection，并且接到同一档。
//
// F-03（2026-10-17）：**业务状态已改变**的成功路径改走 services/auditOutbox.js 的
// `recordSensitiveActionDurably`——落库失败时把同一条文档转进审计 WAL，Mongo 恢复后重放，
// 因此"返回成功"的前提从"DB 已写"变成"已持久化到可重放的介质"。仍用
// `onAuditWriteFailure` 的地方是**诊断性**审计（失败/拒绝路径，业务状态未改变），
// best-effort 是正确语义，见该模块头注释的分档说明。
const { onAuditWriteFailure } = require('../../utils/auditWriteFailure');
const { recordSensitiveActionDurably } = require('../../services/auditOutbox');
const authService = require('../../services/authService');
const AuditLog = require('../../models/AuditLog');
const { rejectUnknownOutcome } = require('./shared');

/**
 * 修改密码
 * PUT /api/auth/password
 */
const changePassword = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const result = await authService.changeUserPassword(req.user.userId, req.body, {
    username: req.user?.username,
  });

  switch (result.outcome) {
    case 'ENC_INVALID':
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    case 'MISSING':
      return ApiResponse.codeError(res, 'PASSWORD_CURRENT_AND_NEW_REQUIRED');
    case 'CONFIRM_MISMATCH':
      // 服务端在解密后才比对确认口令（密文轨下明文只有解出来才知道），
      // 因此该分支可经 HTTP 到达。缺此 case 会落到 default 并回「密码修改成功」，
      // 而口令其实并未修改——用户以为已改，旧口令仍然有效。
      return ApiResponse.codeError(res, 'PASSWORD_CONFIRM_MISMATCH');
    case 'WEAK':
      return ApiResponse.error(res, result.message, 400);
    case 'USER_NOT_FOUND':
      return ApiResponse.codeError(res, 'USER_NOT_FOUND_OR_DELETED');
    case 'CURRENT_WRONG':
      return ApiResponse.codeError(res, 'PASSWORD_CURRENT_INCORRECT');
    case 'SAME_PASSWORD':
      return ApiResponse.codeError(res, 'PASSWORD_SAME_AS_OLD');
    // 复用历史与"与当前相同"分开成码：两条路径判的是不同的事，合并会让用户
    // 以为自己只是没改够（提示他"再改一次换一个"），而真实情况是他正在回滚到旧口令
    case 'PASSWORD_REUSED':
      return ApiResponse.codeError(res, 'PASSWORD_REUSED_IN_HISTORY', {
        params: { historyDepth: result.historyDepth },
      });
    case 'REVOKE_FAILED': {
      // 密码已经改成功——审计必须落库，且先把状态码置为 503，
      // 让 recordSensitiveAction 按 res.statusCode 如实记录失败与风险因子
      res.status(503);
      AuditLog.recordSensitiveAction(
        req.user.userId,
        result.username,
        'change_password',
        'auth',
        req,
        res
      ).catch(onAuditWriteFailure('password_changed_revoke_failed', req));
      return ApiResponse.codeError(res, 'PASSWORD_CHANGED_REVOKE_FAILED');
    }
    case 'OK':
      break;
    default:
      // 未知 outcome 一律 fail-closed（全仓 outcome switch 普查口径），绝不落到成功分支
      return rejectUnknownOutcome(res, 'changePassword', result.outcome);
  }

  // F-03：密码已改成功 ⇒ 审计必须先持久化（DB 或 WAL）才允许回成功。
  // 转 WAL 成功时 recordDurably 返回 null；WAL 不可用会重抛 ⇒ 500，不假装记账成功。
  await recordSensitiveActionDurably({
    userId: req.user.userId,
    username: result.username,
    action: 'change_password',
    category: 'auth',
    req,
    res,
    auditAction: 'password_changed',
  });

  return ApiResponse.success(res, null, '密码修改成功');
});

/**
 * 更新个人资料
 * PUT /api/auth/profile
 */
const updateProfile = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const result = await authService.updateUserProfile(req.user.userId, req.body);

  switch (result.outcome) {
    case 'NOT_FOUND':
      return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
    case 'INVALID_PHONE':
      return ApiResponse.codeError(res, 'PHONE_INVALID');
    case 'INVALID_EMAIL':
      return ApiResponse.codeError(res, 'EMAIL_INVALID');
    case 'EMAIL_TAKEN':
      return ApiResponse.codeError(res, 'EMAIL_TAKEN');
    case 'INVALID_AVATAR':
      return ApiResponse.codeError(res, 'AVATAR_INVALID');
    case 'OK':
      break;
    default:
      // 未知 outcome 一律 fail-closed（全仓 outcome switch 普查口径），绝不落到成功分支
      return rejectUnknownOutcome(res, 'updateProfile', result.outcome);
  }

  return ApiResponse.success(res, result.profile, '资料更新成功');
});

module.exports = {
  changePassword,
  updateProfile,
};
