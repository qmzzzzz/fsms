/**
 * 安全管理控制器 · 自助面（my-info / 改密 / 账户绑定 / 我的操作日志）
 * （2026-10-19 批 3c-3 自 controllers/securityController.js 原样迁出，纯搬家不改语义）
 */

const { User, AuditLog } = require('./shared');
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { DataMasking } = require('../../utils/encryption');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const authService = require('../../services/authService');
// 安全建议码表（i18n）：后端只出稳定码，文案归前端词表——原先这里直接拼中文句子，
// 英文界面下无从翻译。见 constants/securitySuggestions.js 文件头。
const { SECURITY_SUGGESTION_CODES } = require('../../constants/securitySuggestions');
// F-03（2026-10-17）：业务状态已改变的成功路径改走可靠 outbox（落库失败 ⇒ 转审计 WAL
// 待重放），因此"返回成功"不再等于"审计可能没写上"。仍用 onAuditWriteFailure 的两处
// （PII 查看、安全举报）是刻意的 fail-closed：它们必须"记账后重抛"，不许把结果交出去。
const { recordDurably } = require('../../services/auditOutbox');

/**
 * 获取当前用户的安全信息
 * GET /api/security/my-info
 */
const getMySecurityInfo = asyncHandler(async (req, res) => {
  const userId = req.user.userId;

  const user = await User.findById(userId).select(
    'username email phone lastLoginAt createdAt status'
  );

  // 获取最近登录记录
  const recentLogins = await AuditLog.find({
    userId,
    action: { $in: ['login_success', 'login_failed'] },
  })
    .sort({ timestamp: -1 })
    .limit(10)
    .select('action ip timestamp success');

  // 计算安全评分
  let securityScore = 100;
  const suggestions = [];

  // 检查最后登录时间
  const daysSinceLastLogin = user.lastLoginAt
    ? Math.floor((Date.now() - new Date(user.lastLoginAt)) / (1000 * 60 * 60 * 24))
    : 999;

  if (daysSinceLastLogin > 30) {
    securityScore -= 10;
    suggestions.push(SECURITY_SUGGESTION_CODES.ACCOUNT_INACTIVE_LONG);
  }

  // 检查失败登录尝试
  const failedLogins = recentLogins.filter((l) => !l.success).length;
  if (failedLogins > 3) {
    securityScore -= 15;
    suggestions.push(SECURITY_SUGGESTION_CODES.REPEATED_LOGIN_FAILURES);
  }

  return ApiResponse.success(
    res,
    {
      user: {
        ...user.toObject(),
        phone: DataMasking.maskPhone(user.phone),
        email: DataMasking.maskEmail(user.email),
      },
      securityScore: Math.max(0, securityScore),
      suggestions,
      recentLogins: recentLogins.map((login) => ({
        action: login.action,
        ip: DataMasking.maskIP(login.ip),
        time: login.timestamp,
        success: login.success,
      })),
    },
    '获取成功'
  );
});

/**
 * 修改密码（需要当前密码验证）
 * PUT /api/security/change-password
 */
const changePasswordSecure = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  // 评价报告 #15（改密逻辑双实现收敛）：本端点与 /api/auth/password 的
  // 「解密→确认→强度→比对→落库→吊销→会话收敛」此前各写一遍，极易漂移。
  // 现在控制器只做 HTTP 语义映射，业务规则全部收敛到
  // authService.changeUserPassword 单一实现（确认密码比对在解密后于业务层完成）。
  const result = await authService.changeUserPassword(req.user.userId, req.body, {
    username: req.user?.username,
  });

  switch (result.outcome) {
    case 'ENC_INVALID':
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    case 'MISSING':
      return ApiResponse.codeError(res, 'PASSWORD_CURRENT_AND_NEW_REQUIRED');
    case 'CONFIRM_MISMATCH':
      return ApiResponse.codeError(res, 'PASSWORD_CONFIRM_MISMATCH');
    case 'WEAK':
      return ApiResponse.error(res, result.message, 400);
    case 'USER_NOT_FOUND':
      return ApiResponse.codeError(res, 'USER_NOT_FOUND_OR_DELETED');
    case 'CURRENT_WRONG':
      logger.warn('密码修改失败 - 当前密码错误', { username: req.user?.username });
      return ApiResponse.codeError(res, 'PASSWORD_CURRENT_INCORRECT');
    case 'SAME_PASSWORD':
      return ApiResponse.codeError(res, 'PASSWORD_SAME_AS_CURRENT');
    // 与 authController 同码同语义：两个端点改的是同一份口令、同一套历史，
    // 文案差异只应来自各自对"当前密码"的称呼（profile 页 vs 安全中心），复用历史没有这种差异
    case 'PASSWORD_REUSED':
      return ApiResponse.codeError(res, 'PASSWORD_REUSED_IN_HISTORY', {
        params: { historyDepth: result.historyDepth },
      });
    case 'REVOKE_FAILED':
      // fail-closed：密码已落库但吊销失败，如实告知「已改但未吊销」（与 auth 端点同文案）
      return ApiResponse.codeError(res, 'PASSWORD_CHANGED_REVOKE_FAILED');
    case 'OK':
      break;
    default:
      // fail-closed：未知 outcome 绝不落到成功分支。
      // 原为 `default: break;` —— 业务层一旦新增 outcome 而此处忘了映射，会**静默按成功处理**
      // 并写入 password_changed 审计，把「映射表漏项」变成一条假的成功留痕。
      // 实证：zzqA_changePasswordOutcomeMap 的「未知 outcome」用例此前只是被一次
      // 无关的 ValidationError 顶成绿，源码里并没有守这条不变量。
      logger.error('改密返回未知 outcome，已按失败处理', { outcome: result.outcome });
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
  }

  logger.info('用户成功修改密码', { username: result.username });

  // 记录审计日志
  res.locals.skipGlobalAudit = true;
  // F-03：密码已改成功 ⇒ 审计先持久化（DB 或 WAL）才允许回成功
  await recordDurably(
    {
      action: 'password_changed',
      category: 'auth',
      userId: req.user.userId,
      username: result.username,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      success: true,
    },
    { auditAction: 'password_changed', req }
  );

  return ApiResponse.success(res, null, '密码修改成功，请重新登录');
});

/**
 * 获取账户绑定信息
 * GET /api/security/bindings
 */
const getAccountBindings = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('email phone department status');

  return ApiResponse.success(
    res,
    {
      bindings: [
        {
          type: 'email',
          value: DataMasking.maskEmail(user.email),
          verified: !!user.email,
          required: true,
        },
        {
          type: 'phone',
          value: DataMasking.maskPhone(user.phone),
          verified: !!user.phone,
          required: false,
        },
        {
          type: 'department',
          // 原实现 `user.department || '未设置'`：把一句中文占位塞进了**数据字段**，
          // 英文界面下无法翻译（同 suggestions 那族缺陷）。改为原样下发（未设置即空串），
          // 占位符交前端词表渲染——AccountBindingsCard 对空值显示 '—'。
          value: user.department || '',
          // 与上面 email/phone 两项同口径：verified = 「该项有值」。
          // 原先这里写死 true，于是没有部门的用户会显示成「已绑定 + 未设置」这一自相矛盾的状态。
          verified: !!user.department,
          required: false,
        },
      ],
    },
    '获取成功'
  );
});

/**
 * 获取个人操作日志
 * GET /api/security/my-logs
 */
const getMyLogs = asyncHandler(async (req, res) => {
  const { days = 7, limit = 50, category } = req.query;

  // limit 解析为整数并限界：非法输入（非数字/小于 1）回退本接口默认值 50，
  // 上限 500，避免客户端传入任意大值或 NaN 直传 Mongo limit()
  let parsedLimit = parseInt(limit, 10);
  if (!Number.isInteger(parsedLimit) || parsedLimit < 1) parsedLimit = 50;
  parsedLimit = Math.min(parsedLimit, 500);

  // days 同样解析并钳制到 [1,365]：非法输入回退默认 7 天，
  // 防止 NaN 或超大窗口直传 getUserActivity 造成无界时间范围全表扫描
  let parsedDays = parseInt(days, 10);
  if (!Number.isInteger(parsedDays) || parsedDays < 1) parsedDays = 7;
  parsedDays = Math.min(parsedDays, 365);

  const logs = await AuditLog.getUserActivity(req.user.userId, {
    days: parsedDays,
    limit: parsedLimit,
    category,
  });

  return ApiResponse.success(res, logs, '获取成功');
});

module.exports = {
  getMySecurityInfo,
  changePasswordSecure,
  getAccountBindings,
  getMyLogs,
};
