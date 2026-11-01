/**
 * API 客户端配置 - 跨浏览器兼容
 * 负责与后端 API 通信
 *
 * 认证方案（I-01 httpOnly cookie）：
 * - 令牌由后端 Set-Cookie 下发：access_token(path=/, 与 JWT_EXPIRE 一致) 与
 *   refresh_token(path=/api/auth, 与 JWT_REFRESH_EXPIRE 一致)，均 httpOnly + SameSite=Strict，
 *   JS 不可读，XSS 无法窃取；请求经同源代理（dev Vite / 生产 Nginx）自动携带。
 *   access_token 的 path 必须是 `/`：Socket.IO 握手打在 /socket.io/，/api 作用域的
 *   cookie 不会随该请求发出，WebSocket 鉴权会整体失效。
 * - withCredentials=true：确保未来前端与 API 分域部署时 cookie 仍随请求发送。
 *
 * CSRF 说明：
 * - SameSite=Strict 下跨站请求不携带 cookie，经典 CSRF 已被阻断；
 * - 全部写请求均为 JSON Content-Type，无法由表单跨站伪造。
 */

import axios from 'axios'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import router from '@/router'
import i18n from '@/i18n'
// FE-M1：密文被拒时统一失效公钥缓存（loginCipher 仅依赖 axios，无循环）
import { invalidatePublicKeyCache } from '@/utils/loginCipher'
import { clearReauthTicket } from '@/utils/reauthTicket'
import {
  ApiEnvelopeSchema,
  AuthMeResponseSchema,
  LoginResponseSchema,
  SessionListResponseSchema,
  SessionStatusResponseSchema,
  formatIssues,
} from '@/schemas'

// 后端错误码 → i18n key 映射（唯一翻译通道）
// 后端注册表：src/utils/errorCodes.js（码的定义、状态码、中文文案的唯一事实来源）
// 前端职责：码 → key 映射 + 双语文案（locales/*/errors 节）
// 取代原「中文字符串精确匹配」方案——后端文案调整不再破坏前端翻译
const ERROR_CODE_I18N_MAP = {
  // 安全名单
  FULL_RANGE_FORBIDDEN: 'security.fullRangeWarning',
  // 认证
  AUTH_INVALID_CREDENTIALS: 'errors.authInvalidCredentials',
  AUTH_IP_RANGE_DENIED: 'errors.authIpRangeDenied',
  AUTH_USER_NOT_FOUND: 'errors.authUserNotFound',
  // 登录/改密口令密文轨解密失败（服务端换钥后重试一次即可自愈）
  AUTH_ENCRYPTED_CREDENTIAL_INVALID: 'errors.authEncryptedCredentialInvalid',
  // 图形验证码
  CAPTCHA_INVALID: 'errors.captchaInvalid',
  CAPTCHA_SERVICE_UNAVAILABLE: 'errors.captchaServiceUnavailable',
  // 会话吊销（后端 P2-26 fail-closed）
  LOGOUT_REVOKE_FAILED: 'errors.logoutRevokeFailed',
  // 出示了非本人的 refresh 令牌：整次登出被拒（后端 403，见 LOGOUT_REFRESH_FOREIGN）
  LOGOUT_REFRESH_FOREIGN: 'errors.logoutRefreshForeign',
  DATA_SCOPE_DENIED: 'errors.dataScopeDenied',
  // MFA 两步验证
  MFA_CODE_INVALID: 'errors.mfaCodeInvalid',
  MFA_NOT_ENABLED: 'errors.mfaNotEnabled',
  MFA_NOT_ENABLED_NO_CODES: 'errors.mfaNotEnabledNoCodes',
  MFA_ALREADY_ENABLED: 'errors.mfaAlreadyEnabled',
  MFA_ALREADY_ENABLED_NO_REPEAT: 'errors.mfaAlreadyEnabledNoRepeat',
  MFA_SECRET_MISSING: 'errors.mfaSecretMissing',
  MFA_CODE_FORMAT: 'errors.mfaCodeFormat',
  MFA_CODE_INVALID_SYNC: 'errors.mfaCodeInvalidSync',
  MFA_VERIFY_FAILED: 'errors.mfaVerifyFailed',
  MFA_ATTEMPTS_EXCEEDED: 'errors.mfaAttemptsExceeded',
  MFA_REGEN_CODE_INVALID: 'errors.mfaRegenCodeInvalid',
  // IP 名单校验
  IP_REQUIRED: 'errors.ipRequired',
  IP_SINGLE_REQUIRED: 'errors.ipSingleRequired',
  IP_FORMAT_INVALID: 'errors.ipFormatInvalid',
  // 用户管理 / 超管不可变约束
  CANNOT_DELETE_SELF: 'errors.cannotDeleteSelf',
  CANNOT_DELETE_SUPER_ADMIN: 'errors.cannotDeleteSuperAdmin',
  CANNOT_DISABLE_SUPER_ADMIN: 'errors.cannotDisableSuperAdmin',
  CANNOT_LOCK_SUPER_ADMIN: 'errors.cannotLockSuperAdmin',
  CANNOT_RESET_MFA_SUPER_ADMIN: 'errors.cannotResetMfaSuperAdmin',
  CANNOT_GRANT_SUPER_ADMIN_ON_CREATE: 'errors.cannotGrantSuperAdminOnCreate',
  SUPER_ADMIN_ROLE_NOT_DETACHABLE: 'errors.superAdminRoleNotDetachable',
  SUPER_ADMIN_ROLE_NOT_GRANTABLE: 'errors.superAdminRoleNotGrantable',
  SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED: 'errors.superAdminRolePermissionsLocked',
  SUPER_ADMIN_ROLE_NOT_CLONABLE: 'errors.superAdminRoleNotClonable',
  // 报表导出 / 查询参数
  AUDIT_EXPORT_REQUIRES_AUDIT_PERM: 'errors.auditExportRequiresAuditPerm',
  QUERY_PARAM_MUST_BE_SCALAR: 'errors.queryParamMustBeScalar',
  // ================= i18n 全量改造 =================
  DATE_PARAM_INVALID: 'errors.dateParamInvalid',
  DATE_RANGE_INVALID: 'errors.dateRangeInvalid',
  VALIDATION_FAILED: 'errors.validationFailed',
  ALARM_NOT_FOUND: 'errors.alarmNotFound',
  ALARM_VIEW_FORBIDDEN: 'errors.alarmViewForbidden',
  ALARM_OPERATE_FORBIDDEN: 'errors.alarmOperateForbidden',
  ALARM_ALREADY_HANDLED: 'errors.alarmAlreadyHandled',
  ALARM_STATUS_NOT_ALLOWED_SHORT: 'errors.alarmStatusNotAllowedShort',
  ALARM_HANDLE_RESULT_REQUIRED: 'errors.alarmHandleResultRequired',
  ALARM_STATUS_NOT_ALLOWED: 'errors.alarmStatusNotAllowed',
  ALARM_BUILDING_REQUIRED: 'errors.alarmBuildingRequired',
  UNAUTHORIZED_ACCESS: 'errors.unauthorizedAccess',
  AUDIT_EXPORT_FAILED: 'errors.auditExportFailed',
  LIMIT_MUST_BE_POSITIVE_INT: 'errors.limitMustBePositiveInt',
  FROM_MUST_BE_LATEST_OR_EARLIEST: 'errors.fromMustBeLatestOrEarliest',
  REGISTER_INFO_INVALID: 'errors.registerInfoInvalid',
  REFRESH_TOKEN_INVALID: 'errors.refreshTokenInvalid',
  REFRESH_TOKEN_MISSING: 'errors.refreshTokenMissing',
  REFRESH_TOKEN_REVOKED: 'errors.refreshTokenRevoked',
  PASSWORD_CHANGED_RELOGIN: 'errors.passwordChangedRelogin',
  SESSION_EXPIRED: 'errors.sessionExpired',
  SECURITY_SERVICE_UNAVAILABLE: 'errors.securityServiceUnavailable',
  DEVICE_SESSION_REVOKED: 'errors.deviceSessionRevoked',
  REFRESH_TOKEN_EXPIRED: 'errors.refreshTokenExpired',
  PASSWORD_CURRENT_AND_NEW_REQUIRED: 'errors.passwordCurrentAndNewRequired',
  USER_NOT_FOUND_OR_DELETED: 'errors.userNotFoundOrDeleted',
  USER_STATE_CONFLICT: 'errors.userStateConflict',
  PASSWORD_CURRENT_INCORRECT: 'errors.passwordCurrentIncorrect',
  PASSWORD_SAME_AS_OLD: 'errors.passwordSameAsOld',
  PASSWORD_CHANGED_REVOKE_FAILED: 'errors.passwordChangedRevokeFailed',
  USER_NOT_FOUND: 'errors.userNotFound',
  PHONE_INVALID: 'errors.phoneInvalid',
  EMAIL_INVALID: 'errors.emailInvalid',
  EMAIL_TAKEN: 'errors.emailTaken',
  AVATAR_INVALID: 'errors.avatarInvalid',
  AVATAR_NOT_FOUND: 'errors.avatarNotFound',
  CANNOT_REVOKE_CURRENT_SESSION: 'errors.cannotRevokeCurrentSession',
  SESSION_NOT_FOUND: 'errors.sessionNotFound',
  DEVICE_NOT_FOUND: 'errors.deviceNotFound',
  DEVICE_VIEW_FORBIDDEN: 'errors.deviceViewForbidden',
  DEVICE_OPERATE_FORBIDDEN: 'errors.deviceOperateForbidden',
  MAINTENANCE_CONTENT_REQUIRED: 'errors.maintenanceContentRequired',
  INSPECTION_NOT_FOUND: 'errors.inspectionNotFound',
  INSPECTION_VIEW_FORBIDDEN: 'errors.inspectionViewForbidden',
  INSPECTION_OPERATE_FORBIDDEN: 'errors.inspectionOperateForbidden',
  IP_LIST_TYPE_INVALID: 'errors.ipListTypeInvalid',
  IP_LIST_DURATION_OUT_OF_RANGE: 'errors.ipListDurationOutOfRange',
  IP_FULL_RANGE_SUPER_ADMIN_ONLY: 'errors.ipFullRangeSuperAdminOnly',
  IP_COVERED_BY_WHITELIST: 'errors.ipCoveredByWhitelist',
  IP_SEGMENT_WRITE_REFUSED: 'errors.ipSegmentWriteRefused',
  IP_LIST_ENTRY_NOT_FOUND: 'errors.ipListEntryNotFound',
  IP_FULL_RANGE_REMOVE_SUPER_ADMIN_ONLY: 'errors.ipFullRangeRemoveSuperAdminOnly',
  PERMISSION_NOT_FOUND: 'errors.permissionNotFound',
  PARENT_PERMISSION_SELF: 'errors.parentPermissionSelf',
  PARENT_PERMISSION_NOT_FOUND: 'errors.parentPermissionNotFound',
  PARENT_PERMISSION_CYCLE: 'errors.parentPermissionCycle',
  PERMISSION_TREE_DEPTH_ANOMALY: 'errors.permissionTreeDepthAnomaly',
  PERMISSION_LIST_INVALID: 'errors.permissionListInvalid',
  EXPORT_FORMAT_UNSUPPORTED: 'errors.exportFormatUnsupported',
  EXPORT_BUSY: 'errors.exportBusy',
  PII_EXPORT_QUOTA_EXCEEDED: 'errors.piiExportQuotaExceeded',
  PRIVACY_CONSENT_REQUIRED: 'errors.privacyConsentRequired',
  REPORT_TYPE_UNSUPPORTED: 'errors.reportTypeUnsupported',
  ROLE_NOT_FOUND: 'errors.roleNotFound',
  ROLE_VIEW_FORBIDDEN: 'errors.roleViewForbidden',
  ROLE_CODE_TAKEN: 'errors.roleCodeTaken',
  ROLE_CODE_RESERVED: 'errors.roleCodeReserved',
  ROLE_CREATE_HIGHER_LEVEL_FORBIDDEN: 'errors.roleCreateHigherLevelForbidden',
  CANNOT_GRANT_WILDCARD_PERMISSION: 'errors.cannotGrantWildcardPermission',
  PERMISSION_GRANT_FORBIDDEN: 'errors.permissionGrantForbidden',
  ROLE_UPDATE_FORBIDDEN: 'errors.roleUpdateForbidden',
  ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN: 'errors.roleUpdateHigherLevelForbidden',
  BUILTIN_ROLE_NAME_LEVEL_LOCKED: 'errors.builtinRoleNameLevelLocked',
  ROLE_STATUS_INVALID: 'errors.roleStatusInvalid',
  BUILTIN_ROLE_STATUS_LOCKED: 'errors.builtinRoleStatusLocked',
  ROLE_LEVEL_ABOVE_SELF_FORBIDDEN: 'errors.roleLevelAboveSelfForbidden',
  ROLE_NAME_REQUIRED: 'errors.roleNameRequired',
  ROLE_DELETE_FORBIDDEN: 'errors.roleDeleteForbidden',
  ROLE_DELETE_HIGHER_LEVEL_FORBIDDEN: 'errors.roleDeleteHigherLevelForbidden',
  BUILTIN_ROLE_NOT_DELETABLE: 'errors.builtinRoleNotDeletable',
  ROLE_IN_USE: 'errors.roleInUse',
  ROLE_STATE_CONFLICT: 'errors.roleStateConflict',
  PERMISSION_ID_REQUIRED: 'errors.permissionIdRequired',
  PERMISSION_ID_INVALID: 'errors.permissionIdInvalid',
  ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN: 'errors.rolePermPeerOrHigherForbidden',
  ROLE_PERM_BASE_HIGHER_LEVEL_FORBIDDEN: 'errors.rolePermBaseHigherLevelForbidden',
  PERMISSION_ASSIGN_FORBIDDEN: 'errors.permissionAssignForbidden',
  TARGET_USER_ID_INVALID: 'errors.targetUserIdInvalid',
  TARGET_USER_NOT_FOUND: 'errors.targetUserNotFound',
  TARGET_USER_LACKS_ROLE: 'errors.targetUserLacksRole',
  USER_ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN: 'errors.userRolePermPeerOrHigherForbidden',
  PASSWORD_CONFIRM_MISMATCH: 'errors.passwordConfirmMismatch',
  PASSWORD_SAME_AS_CURRENT: 'errors.passwordSameAsCurrent',
  PASSWORD_REUSED_IN_HISTORY: 'errors.passwordReusedInHistory',
  SENSITIVE_VIEW_HIGHER_LEVEL_FORBIDDEN: 'errors.sensitiveViewHigherLevelForbidden',
  SENSITIVE_VIEW_OUT_OF_SCOPE: 'errors.sensitiveViewOutOfScope',
  UNSUPPORTED_DATA_TYPE: 'errors.unsupportedDataType',
  REPORT_TARGET_AND_REASON_REQUIRED: 'errors.reportTargetAndReasonRequired',
  USER_OPERATE_PEER_OR_HIGHER_FORBIDDEN: 'errors.userOperatePeerOrHigherForbidden',
  UNLOCK_INACTIVE_ACCOUNT: 'errors.unlockInactiveAccount',
  LOCK_INACTIVE_ACCOUNT: 'errors.lockInactiveAccount',
  ACCOUNT_NOT_LOCKED: 'errors.accountNotLocked',
  CANNOT_RESET_OWN_MFA_VIA_ADMIN: 'errors.cannotResetOwnMfaViaAdmin',
  PASSWORD_CHANGE_REQUIRED: 'errors.passwordChangeRequired',
  CANNOT_RESET_OWN_PASSWORD_VIA_ADMIN: 'errors.cannotResetOwnPasswordViaAdmin',
  CANNOT_RESET_PASSWORD_SUPER_ADMIN: 'errors.cannotResetPasswordSuperAdmin',
  PASSWORD_RESET_PEER_OR_HIGHER_FORBIDDEN: 'errors.passwordResetPeerOrHigherForbidden',
  PASSWORD_RESET_FAILED: 'errors.passwordResetFailed',
  TARGET_MFA_NOT_ENABLED: 'errors.targetMfaNotEnabled',
  MFA_RESET_PEER_OR_HIGHER_FORBIDDEN: 'errors.mfaResetPeerOrHigherForbidden',
  PRIVILEGE_DURATION_INVALID: 'errors.privilegeDurationInvalid',
  PRIVILEGE_GRANT_INVALID: 'errors.privilegeGrantInvalid',
  PRIVILEGE_CODE_INVALID: 'errors.privilegeCodeInvalid',
  PRIVILEGE_GRANT_NOT_FOUND: 'errors.privilegeGrantNotFound',
  PRIVILEGE_GRANT_NOT_PENDING: 'errors.privilegeGrantNotPending',
  PRIVILEGE_GRANT_NOT_ACTIVE: 'errors.privilegeGrantNotActive',
  PRIVILEGE_SELF_APPROVAL_FORBIDDEN: 'errors.privilegeSelfApprovalForbidden',
  PRIVILEGE_APPROVAL_FORBIDDEN: 'errors.privilegeApprovalForbidden',
  SESSION_REVOKE_SERVICE_UNAVAILABLE: 'errors.sessionRevokeServiceUnavailable',
  FORCE_LOGOUT_MFA_CLEAR_FAILED: 'errors.forceLogoutMfaClearFailed',
  SECURITY_OVERVIEW_FORMAT_INVALID: 'errors.securityOverviewFormatInvalid',
  SECURITY_OVERVIEW_STRUCTURE_INVALID: 'errors.securityOverviewStructureInvalid',
  SECURITY_OVERVIEW_QUERY_FAILED: 'errors.securityOverviewQueryFailed',
  SECURITY_OVERVIEW_DEGRADED: 'errors.securityOverviewDegraded',
  RECENT_ALERTS_EMPTY: 'errors.recentAlertsEmpty',
  RECENT_ALERTS_QUERY_FAILED: 'errors.recentAlertsQueryFailed',
  CONFIG_ALLOW_REGISTRATION_MUST_BE_BOOLEAN: 'errors.configAllowRegistrationMustBeBoolean',
  CONFIG_LOGIN_CAPTCHA_MUST_BE_BOOLEAN: 'errors.configLoginCaptchaMustBeBoolean',
  CONFIG_REGISTER_CAPTCHA_MUST_BE_BOOLEAN: 'errors.configRegisterCaptchaMustBeBoolean',
  USER_VIEW_FORBIDDEN: 'errors.userViewForbidden',
  USER_SCOPE_FORBIDDEN: 'errors.userScopeForbidden',
  IP_RULES_FORMAT_INVALID: 'errors.ipRulesFormatInvalid',
  ROLE_NOT_FOUND_IN_LIST: 'errors.roleNotFoundInList',
  ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN: 'errors.roleAssignHigherLevelForbidden',
  USER_UPDATE_PEER_OR_HIGHER_FORBIDDEN: 'errors.userUpdatePeerOrHigherForbidden',
  USER_SCOPE_FIELD_FORBIDDEN: 'errors.userScopeFieldForbidden',
  CANNOT_CHANGE_OWN_STATUS: 'errors.cannotChangeOwnStatus',
  USER_STATUS_CHANGE_FORBIDDEN: 'errors.userStatusChangeForbidden',
  EMAIL_TAKEN_SHORT: 'errors.emailTakenShort',
  ROLE_LIST_INVALID: 'errors.roleListInvalid',
  ROLE_ID_INVALID: 'errors.roleIdInvalid',
  USER_ROLE_ASSIGN_PEER_OR_HIGHER_FORBIDDEN: 'errors.userRoleAssignPeerOrHigherForbidden',
  ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN: 'errors.roleAssignForeignPeerForbidden',
  USER_DELETE_PEER_OR_HIGHER_FORBIDDEN: 'errors.userDeletePeerOrHigherForbidden',
  USER_ID_LIST_INVALID: 'errors.userIdListInvalid',
  BATCH_DELETE_LIMIT_EXCEEDED: 'errors.batchDeleteLimitExceeded',
  USER_ID_FORMAT_INVALID_IN_LIST: 'errors.userIdFormatInvalidInList',
  USER_ID_NOT_FOUND_IN_LIST: 'errors.userIdNotFoundInList',
  BATCH_DELETE_PEER_OR_HIGHER_FORBIDDEN: 'errors.batchDeletePeerOrHigherForbidden',
  AUTH_TOKEN_MISSING: 'errors.authTokenMissing',
  AUTH_TOKEN_REVOKED: 'errors.authTokenRevoked',
  ACCOUNT_DISABLED: 'errors.accountDisabled',
  ACCOUNT_LOCKED: 'errors.accountLocked',
  ACCOUNT_TEMP_LOCKED: 'errors.accountTempLocked',
  AUTH_TOKEN_INVALID: 'errors.authTokenInvalid',
  AUTH_TOKEN_EXPIRED: 'errors.authTokenExpired',
  AUTH_PROCESS_FAILED: 'errors.authProcessFailed',
  JSON_PARSE_FAILED: 'errors.jsonParseFailed',
  PAYLOAD_EXCEEDS_LIMIT: 'errors.payloadExceedsLimit',
  INTERNAL_ERROR: 'errors.internalError',
  METRICS_INTERNAL_ONLY: 'errors.metricsInternalOnly',
  HTTP_METHOD_UNSUPPORTED: 'errors.httpMethodUnsupported',
  HEADER_COUNT_EXCESSIVE: 'errors.headerCountExcessive',
  HEADER_NAME_INVALID: 'errors.headerNameInvalid',
  HEADER_VALUE_TOO_LONG: 'errors.headerValueTooLong',
  HOST_HEADER_INVALID: 'errors.hostHeaderInvalid',
  CONTENT_LENGTH_INVALID: 'errors.contentLengthInvalid',
  PAYLOAD_TOO_LARGE: 'errors.payloadTooLarge',
  CONTENT_TYPE_MISSING: 'errors.contentTypeMissing',
  CONTENT_TYPE_UNSUPPORTED: 'errors.contentTypeUnsupported',
  PERMISSION_DENIED: 'errors.permissionDenied',
  PERMISSION_CHECK_FAILED: 'errors.permissionCheckFailed',
  ROLE_NOT_ALLOWED: 'errors.roleNotAllowed',
  ROLE_CHECK_FAILED: 'errors.roleCheckFailed',
  REAUTH_REQUIRED: 'errors.reauthRequired',
  REAUTH_PASSWORD_INCORRECT: 'errors.reauthPasswordIncorrect',
  REAUTH_MFA_NOT_ENABLED: 'errors.reauthMfaNotEnabled',
  REAUTH_MFA_INCORRECT: 'errors.reauthMfaIncorrect',
  REAUTH_MFA_REQUIRED: 'errors.reauthMfaRequired',
  REAUTH_PROCESS_FAILED: 'errors.reauthProcessFailed',
  REAUTH_TICKET_REQUIRED: 'errors.reauthTicketRequired',
  REAUTH_TICKET_INVALID: 'errors.reauthTicketInvalid',
  // 请求级幂等（审计一-1）：同键重放不报错（原样回放上一次结果），这三个码是"用错了"
  IDEMPOTENCY_KEY_REQUIRED: 'errors.idempotencyKeyRequired',
  IDEMPOTENCY_KEY_INVALID: 'errors.idempotencyKeyInvalid',
  IDEMPOTENCY_IN_PROGRESS: 'errors.idempotencyInProgress',
  IDEMPOTENCY_KEY_REUSED: 'errors.idempotencyKeyReused',
  MFA_SECOND_FACTOR_REQUIRED: 'errors.mfaSecondFactorRequired',
  IP_BLOCKED: 'errors.ipBlocked',
  UPLOAD_FILE_TOO_LARGE: 'errors.uploadFileTooLarge',
  UPLOAD_TYPE_NOT_ALLOWED: 'errors.uploadTypeNotAllowed',
  UPLOAD_EXT_NOT_ALLOWED: 'errors.uploadExtNotAllowed',
  PARAM_MUST_BE_VALID_OBJECT_ID: 'errors.paramMustBeValidObjectId',
  PUBLIC_REGISTRATION_DISABLED: 'errors.publicRegistrationDisabled',
  REGISTER_SERVICE_UNAVAILABLE: 'errors.registerServiceUnavailable',
  AUDIT_QUERY_FAILED: 'errors.auditQueryFailed',
  // 取证溯源（T5/T6）。FORENSIC_POOL_BAN_REFUSED 的**具体原因**在 errors.reason
  // （full_range_cidr / whitelist_covers / operator_inside / reason_required /
  // unparsable_cidr / unknown_token / token_expired），视图按 reason 选专属文案；
  // 这里的码级文案只是「兜底」——reason 未知时才会看到它。
  FORENSIC_NO_CRITERIA: 'errors.forensicNoCriteria',
  FORENSIC_POOL_BAN_REFUSED: 'errors.forensicPoolBanRefused',
  FORENSIC_EXPORT_NO_SECRET: 'errors.forensicExportNoSecret',
  FORENSIC_QUERY_FAILED: 'errors.forensicQueryFailed',
  // 升级：触发入口仅超管，但错误文案仍由码化通道翻译（英文界面不得回显后端中文）
  SUPER_ADMIN_REQUIRED: 'errors.superAdminRequired',
  UPGRADE_DISABLED: 'errors.upgradeDisabled',
  UPGRADE_IMAGE_INVALID: 'errors.upgradeImageInvalid',
  UPGRADE_IMAGE_NOT_ALLOWED: 'errors.upgradeImageNotAllowed',
  UPGRADE_ALREADY_RUNNING: 'errors.upgradeAlreadyRunning',
  UPGRADE_QUEUE_UNAVAILABLE: 'errors.upgradeQueueUnavailable',
  UPGRADE_JOB_NOT_FOUND: 'errors.upgradeJobNotFound',
}

/**
 * 按 errors.errorCode 解析本地化错误消息
 * 未命中（后端未码化的接口）返回 null，调用方回退到后端 message
 */
function resolveErrorMessage(data) {
  const errorCode = data?.errors?.errorCode
  // errorCode 来自响应体（外部输入），必须限定为自有属性：裸查表会让 'toString'/
  // 'constructor' 等原型链键取到 Object.prototype 上的函数（truthy），返回函数而非
  // 约定的 null，调用方 `resolveErrorMessage(...) || data?.message || t(...)` 兜底链
  // 被短路，界面渲染出「function toString() { [native code] }」
  if (errorCode && Object.prototype.hasOwnProperty.call(ERROR_CODE_I18N_MAP, errorCode)) {
    const i18nKey = ERROR_CODE_I18N_MAP[errorCode]
    const params = data?.errors || {}
    return i18n.global.t(i18nKey, params)
  }
  return null
}

// 供单测校验映射与 locale 文案的 key 对齐（防拼写错误静默漏网）
export { ERROR_CODE_I18N_MAP, resolveErrorMessage }

// 拦截器 fallback 走 i18n（按当前 locale 解析，替代硬编码中文兜底）
const t = (key) => i18n.global.t(key)

/**
 * API base（单一事实来源）。
 *
 * 导出是为了让不走 axios 的调用方复用同一口径：versionWatcher 的 /api/version
 * 探测原先自己用 BASE_URL 拼路径、忽略 VITE_API_BASE_URL ⇒ 分域或
 * VITE_API_BASE_URL='/sub/api' 的部署下静默 404（探测失败按纪律静默，无人发现）。
 */
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'

// 创建 axios 实例
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 审计读取的二次验证（2026-10-31，审计一-3）：**不再有票据请求头**。
// step-up 结果由服务端按会话记 5 分钟窗口（models/ReauthGrant），窗口内读取端点
// 直接放行；客户端手里没有任何可重放的凭据，也就没有头可带。
// 无窗口时请求按契约拿 401 REAUTH_TICKET_REQUIRED，由页面弹二次验证框
// （而不是在拦截器里静默重放写请求）。

// 「需要二次验证」的两个 401 与「登录态失效」是不同语义：前者绝不能触发
// 令牌刷新链或强制登出，否则一次票据过期就会把用户踢回登录页。
const REAUTH_TICKET_ERROR_CODES = ['REAUTH_TICKET_REQUIRED', 'REAUTH_TICKET_INVALID']

/**
 * 从错误响应体读 errorCode；导出类请求 responseType 为 blob，
 * 错误 JSON 也被包成 Blob —— 不先解包就既认不出票据 401，
 * 也看不清后端真正返回的错误码。
 */
const readErrorCode = async (data) => {
  if (data?.errors?.errorCode) return data.errors.errorCode
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    try {
      return JSON.parse(await data.text())?.errors?.errorCode || ''
    } catch (_) {
      return ''
    }
  }
  return ''
}

// ========== Token 自动刷新机制 ==========
// 防止并发刷新：多个 401 请求同时触发时，只执行一次刷新，其余等待结果
let isRefreshing = false
let refreshPromise = null

/**
 * 认证入口路径：这些接口的 401 表示「凭据错误」而非「令牌过期」（P3-41）
 *
 * 它们不能参与刷新重试，理由有三：
 *   1. 语义不符：输错密码/验证码/MFA 码与令牌是否过期无关；
 *   2. 体验：残留 refresh cookie 时要等满 10s 刷新超时才提示，用户以为卡死；
 *   3. 无意义：即使刷新成功，重发一次「密码错误」的请求结果仍然是错。
 *
 * 用 includes 而非全等：baseURL 前缀在不同部署下可能不同（/api、/api/v1）。
 */
const AUTH_NO_REFRESH_PATHS = ['/auth/login', '/auth/register', '/auth/refresh']

/**
 * 并发刷新败者的静默恢复等待窗口（毫秒）
 *
 * 后端对「同一枚 refresh 令牌在宽限期内被二次使用」返回 503
 * SECURITY_SERVICE_UNAVAILABLE（services/authService/token.js 的 CONCURRENT 结局）。
 * 兄弟标签页的 Set-Cookie 需要一次网络往返才会写进浏览器，因此这里等一小段再重试
 * 刷新：过早重试会再撞一次宽限窗口，过晚则用户白等。400ms 覆盖同城 RTT。
 */
export const REFRESH_RACE_RECOVERY_DELAY_MS = 400

/**
 * 刷新令牌：把结局归一化成对象，不再用异常表达失败
 *
 * 调用方必须能区分两种「刷新失败」：
 *  - 服务端**明确拒绝**（401/403/400 REFRESH_TOKEN_MISSING）：会话确实不可用，可以登出；
 *  - **打不通**（网络错误/超时/其它 5xx）：无法证明会话失效，登出就是把有效会话误杀。
 * 旧实现用 try/catch 一律吞成「失败」，两种结局在调用点无法区分——这正是
 * 「一次网络抖动 / 一次多标签页竞态就把用户登出」的根因。
 *
 * @param {{ raceRecovery?: boolean }} [options] raceRecovery=true 时先等
 *   REFRESH_RACE_RECOVERY_DELAY_MS 再发请求（只在并发竞态恢复路径使用）
 * @returns {Promise<{ ok: boolean, status?: number, errorCode?: string }>}
 */
const doRefreshToken = async ({ raceRecovery = false } = {}) => {
  if (isRefreshing) return refreshPromise
  isRefreshing = true
  refreshPromise = (async () => {
    try {
      if (raceRecovery) {
        await new Promise((resolve) => {
          setTimeout(resolve, REFRESH_RACE_RECOVERY_DELAY_MS)
        })
      }
      // 刷新令牌在 httpOnly cookie(path=/api/auth)中，浏览器按路径自动携带，无需 body；
      // 直接用 axios 调用，避免经过拦截器导致循环；补超时防止刷新请求悬挂阻塞重试链
      const resp = await axios.post(
        API_BASE_URL + '/auth/refresh',
        {},
        { timeout: 10000, withCredentials: true }
      )
      // 新令牌由响应 Set-Cookie 写回浏览器，前端无需（也无法）读取
      if (resp.data?.success === true) return { ok: true }
      // 200 但响应体不符合契约（success 不是字面量 true）：既不能当成功重放，
      // 也不能据此断言会话失效——归入「无法判定」，由调用方放弃本次请求。
      return { ok: false, status: resp.status }
    } catch (err) {
      return {
        ok: false,
        status: err?.response?.status,
        errorCode: err?.response?.data?.errors?.errorCode,
      }
    } finally {
      isRefreshing = false
      refreshPromise = null
    }
  })()
  return refreshPromise
}

/**
 * 刷新失败能否断言「会话确实不可用」
 *
 * 唯一证据是服务端**明确拒绝**这次刷新：
 *  - 401/403：刷新令牌无效/过期/被撤销、设备会话被踢、账户被锁、口令已变更等
 *    （controllers/authController/credentials.js 的 REFRESH_OUTCOME_RESPONSES
 *    把这些结局全部映射到这两个状态码）；
 *  - 400 REFRESH_TOKEN_MISSING：浏览器里根本没有刷新令牌，无法续期，等同未登录。
 * 其余结局都不能证明会话失效：网络错误/超时/429/其它 5xx/畸形 200。
 * 尤其是 503 SECURITY_SERVICE_UNAVAILABLE —— 它包含多标签页并发刷新的 CONCURRENT
 * 结局，此刻浏览器 cookie 已被胜者换成新令牌，会话是**有效**的。
 */
const isRefreshSessionDead = (outcome) =>
  outcome?.status === 401 ||
  outcome?.status === 403 ||
  outcome?.errorCode === 'REFRESH_TOKEN_MISSING'

// ========== 请求取消机制 ==========
// 每个请求关联一个 AbortController，路由切换时可批量取消在途请求
const pendingControllers = new Map()

/**
 * 不可被路由切换取消的方法（P3-42）
 *
 * 原实现无条件取消**全部**在途请求。写请求（POST/PUT/PATCH/DELETE）一旦被
 * 取消，前端 catch 到 ERR_CANCELED 后什么也不做，但请求可能已到达服务端
 * 并落库成功 —— 用户看到的是「表单还在、没有成功提示」，实际数据已改。
 * 这种「看似没保存其实保存了」的状态错位，比直接报错危险得多：
 * 用户会再提交一次，产生重复数据；或者以为没生效而放弃，后续按错误的
 * 认知继续操作。
 *
 * 取消 GET 是安全的（幂等、无副作用），这也正是该机制的本意——
 * 避免离开页面后旧列表数据回填。
 */
const UNCANCELABLE_METHODS = new Set(['post', 'put', 'patch', 'delete'])

/**
 * 取消所有可安全取消的在途请求（路由切换时调用）
 *
 * 写请求被保留：它们会自行完成，其 controller 也会在响应/失败时清理。
 * @param {string} [message] 取消原因（仅用于调试）
 * @returns {{cancelled: number, kept: number}} 取消与保留的请求数
 */

// FE-L1：取消错误判定助手——路由切换 abort 在途请求后，视图 catch 应据此
// 跳过「加载失败」提示（用户已到达新页面，弹假错误会训练用户忽略红框）
export const isCanceledError = (e) => e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError'

/**
 * 该错误是否已由响应拦截器向用户提示过（用于避免同一次失败弹两条）
 *
 * 响应拦截器对所有非取消的 HTTP/网络错误都会弹一次具体文案（400/403/404/5xx/网络等）；
 * 组件若在 catch 里再弹一条「操作失败」，用户看到的是「具体原因 + 泛化文案」两条，
 * 且泛化文案往往后到、盖住真正有用的那条。
 *
 * 仅以 axios 错误标记判断，而不是「有 response 就算」：非 axios 的异常（组件自身逻辑、
 * 加解密工具）没有走过拦截器，仍应由调用方提示。silent401 是调用方显式要求静默的
 * 预期结果（会话探测），同样不应由组件补提示。
 */
export const isHandledApiError = (e) => e?.isAxiosError === true && !e?.config?.silent401

export const cancelAllPendingRequests = (message = t('common.routeChangeCancel')) => {
  let cancelled = 0
  let kept = 0
  for (const [key, entry] of pendingControllers) {
    // 兼容早期形态（直接存 controller）与当前形态（存 { controller, method }）
    const controller = entry?.controller || entry
    const method = String(entry?.method || 'get').toLowerCase()
    if (UNCANCELABLE_METHODS.has(method)) {
      kept++
      continue
    }
    try {
      controller.abort(message)
    } catch (_) {}
    pendingControllers.delete(key)
    cancelled++
  }
  return { cancelled, kept }
}

// 请求拦截器
apiClient.interceptors.request.use(
  (config) => {
    // 关联 AbortController，支持请求取消（路由切换时批量取消）
    const controller = new AbortController()
    // 调用方自带的 signal 必须**转发**而不是覆盖：升级进度轮询会带自己的
    // AbortController（弹窗关闭 / 切换任务即中断在途请求）。原实现无条件覆盖
    // config.signal：调用方 abort 之后请求仍在飞、响应照样回填——旧任务的
    // 进度会盖住新任务。
    const callerSignal = config.signal
    if (callerSignal && typeof callerSignal.addEventListener === 'function') {
      if (callerSignal.aborted) {
        controller.abort(callerSignal.reason)
      } else {
        callerSignal.addEventListener('abort', () => controller.abort(callerSignal.reason), {
          once: true,
        })
      }
    }
    config.signal = controller.signal
    const method = String(config.method || 'get').toLowerCase()
    const reqKey = `${method}::${config.url}::${Date.now()}::${Math.random().toString(36).slice(2, 8)}`
    config.__reqKey = reqKey
    // P3-42：连同 method 一起登记，供 cancelAllPendingRequests 区分读写
    pendingControllers.set(reqKey, { controller, method })
    // 认证走 httpOnly cookie（I-01），不再注入 Authorization 头
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

/**
 * 路径 → 专用 schema 映射
 *
 * 只为「前端会据其做判断」的接口写专用 schema：
 *  - /auth/me   权限热刷新与会话恢复的事实来源
 *  - /auth/login 身份写入 store 的入口
 *  - /auth/session 路由守卫的短路依据
 * 其余接口走通用包络校验（success/message/data/pagination 结构），
 * 逐个接口写 schema 会变成维护负担而收益递减 —— 列表类接口的字段
 * 由各视图自行读取，形状不对时视图上肉眼可见，不属于「静默失效」类缺陷。
 *
 * method 为可选约束：/auth/sessions 上 GET 返回列表、DELETE 返回 { sid }，
 * 同一路径两种形状。不区分方法会让每次踢除设备都误报一次漂移 ——
 * 告警一旦开始出现假阳性，真正的漂移就会被当成噪音忽略。
 */
const SCHEMA_ROUTE_MAP = [
  { match: '/auth/me', schema: AuthMeResponseSchema },
  { match: '/auth/login', schema: LoginResponseSchema },
  // 顺序有讲究：'/auth/session' 是 '/auth/sessions' 的前缀，若排在前面，
  // 会话列表响应会被按「只含 authenticated 布尔」的 schema 校验并全部报漂移。
  // includes 匹配没有边界概念，靠声明顺序消歧。
  { match: '/auth/sessions', method: 'get', schema: SessionListResponseSchema },
  { match: '/auth/session', method: 'get', schema: SessionStatusResponseSchema },
]

/**
 * 同一漂移只报一次：形状漂移的成因是后端契约变更，同一路径会持续命中。
 * 每次请求都弹一条 ElMessage 会淹没界面，也无助于定位。
 *
 * P3-66：加 LRU 上限。裸 Set 会随漂移种类无限增长（键是 `url::detail`，
 * detail 含字段级错误信息，长时间运行可持续新增）。Set 的迭代顺序即插入顺序：
 * 队首是「最久没有再次出现」的键，超限时淘汰它；命中的键会先删后插移到队尾，
 * 因此**仍在持续发生**的漂移不会被淘汰（真 LRU，不是插入序 FIFO 截断）。
 * 被淘汰的键若再次出现会再报一次告警——这恰是需要的信息：它还在发生。
 */
const DRIFT_LRU_MAX = 200
const reportedDrifts = new Set()

/** 记录并刷新漂移键：移到队尾；超限时从队首（最久未再出现）淘汰 */
const rememberDrift = (key) => {
  reportedDrifts.delete(key)
  reportedDrifts.add(key)
  while (reportedDrifts.size > DRIFT_LRU_MAX) {
    reportedDrifts.delete(reportedDrifts.values().next().value)
  }
}

/** 供测试断言当前去重集合规模（LRU 上限回归用） */
export const __getDriftCount = () => reportedDrifts.size

/**
 * 校验响应形状，失败时告警但不阻断
 * @param {import('axios').AxiosResponse} response
 */
const verifyResponseShape = (response) => {
  const url = String(response.config?.url || '')
  const data = response.data

  // 二进制响应（/reports/export 的 xlsx）无 JSON 形状可言。
  // 注意 typeof Blob === 'object'，单靠 typeof 判断拦不住，须显式识别
  if (data == null || typeof data !== 'object') return
  if (response.config?.responseType && response.config.responseType !== 'json') return
  if (typeof Blob !== 'undefined' && data instanceof Blob) return
  if (
    typeof ArrayBuffer !== 'undefined' &&
    (data instanceof ArrayBuffer || ArrayBuffer.isView(data))
  )
    return

  const matched = SCHEMA_ROUTE_MAP.find((r) => {
    if (!url.includes(r.match)) return false
    if (!r.method) return true
    return String(response.config?.method || 'get').toLowerCase() === r.method
  })
  const schema = matched ? matched.schema : ApiEnvelopeSchema
  const result = schema.safeParse(data)
  if (result.success) return

  const detail = formatIssues(result.error)
  const driftKey = `${url}::${detail}`
  if (reportedDrifts.has(driftKey)) {
    // 命中即刷新 LRU 位置：持续发生的漂移不会被后出现的新键挤掉，
    // 只有真正「很久没再出现」的旧键才被淘汰（见上方注释）。
    rememberDrift(driftKey)
    return
  }
  rememberDrift(driftKey)

  // console.error 而非 warn：这是需要开发介入的契约破坏，不是可忽略的噪音
  console.error(`[schema-drift] ${url} -> ${detail}`)
  // 只有关键路径（有专用 schema 的）才打扰用户：其形状不对会直接影响
  // 登录/权限判断；通用包络的偏差多数只影响单个视图，静默记录即可
  if (matched) {
    ElMessage.warning(t('messages.schemaDrift'))
  }
}

/** 供测试与调试重置去重集合 */
export const __resetDriftReports = () => reportedDrifts.clear()

apiClient.interceptors.response.use(
  (response) => {
    // 请求完成，清理对应的 AbortController
    if (response.config?.__reqKey) {
      pendingControllers.delete(response.config.__reqKey)
    }
    // 形状校验放在返回前，且自身异常绝不能影响业务响应
    try {
      verifyResponseShape(response)
    } catch (_) {}
    return response
  },
  async (error) => {
    // 清理已取消/完成请求的控制器
    const reqKey = error.config?.__reqKey
    if (reqKey) pendingControllers.delete(reqKey)

    // 请求被主动取消时不弹错误提示
    if (error.code === 'ERR_CANCELED' || error.name === 'CanceledError') {
      return Promise.reject(error)
    }

    /**
     * 调用方声明「本次失败不打扰用户」（config.silentErrors）。
     *
     * 升级进度轮询是 3s 一次的自动请求：切流瞬间的 502 / 网络抖动极常见，
     * 逐次弹红框会在用户面前刷屏，还会把真正需要人介入的失败淹没在噪音里。
     * 只吞掉**提示**：schema 校验、401 刷新与登出链一律照旧。
     * 因此 401/403 两个分支必须照常进入（见下方 notifyStatus）：401 分支里除了
     * 提示还住着「刷新成功后重发仍 401」的 forceSessionReset（登出链），403 分支
     * 承载鉴权结论；分支**内部的提示**才由 silentErrors 决定要不要弹。
     */
    const silentErrors = error.config?.silentErrors === true

    if (error.response) {
      const { status, data, config } = error.response

      // 票据缺失/过期 → 交由页面弹二次验证框并重放请求：
      // 不刷新令牌、不弹「登录已过期」、不跳登录页。
      // 票据被服务端拒绝（如重启换 HMAC 密钥后本地票据仍"未过期"）时清掉本地副本，
      // 否则页面以为还有票据而不会重新弹框。
      const incomingErrorCode = await readErrorCode(data)
      if (status === 401 && REAUTH_TICKET_ERROR_CODES.includes(incomingErrorCode)) {
        if (incomingErrorCode === 'REAUTH_TICKET_INVALID') clearReauthTicket()
        return Promise.reject(error)
      }

      // FE-M1：密文被拒（服务端重启换钥/密钥轮换）——统一在此清公钥缓存，
      // 登录/注册/改密三个口令入口全部自愈（原先只接在 LoginView）。
      // import 无循环：loginCipher 仅依赖 axios
      //
      // 2026-10-10：登录路径的 ENC_INVALID 已与 INVALID_CREDENTIALS 合并为
      // 同一 401（消除 nonce 消费预言机，见 src/controllers/authController.js
      // login 分支），密文轨的登录失败不再有独立错误码可挂。因此登录端点的
      // 「凭据无效」也清一次公钥缓存：服务端轮换密钥后，用户第一次提交失败、
      // 第二次提交即取到新公钥而恢复——自愈不依赖错误码的区分度。
      // 代价是一次失败登录多一个公钥 GET（captchaLimiter 60 次/5 分钟额度内），
      // 且仅限登录端点：其余路径沿用独立错误码的精确触发，不做无差别失效。
      if (data?.errors?.errorCode === 'AUTH_ENCRYPTED_CREDENTIAL_INVALID') {
        invalidatePublicKeyCache()
      } else if (
        data?.errors?.errorCode === 'AUTH_INVALID_CREDENTIALS' &&
        typeof config?.url === 'string' &&
        config.url.includes('/auth/login')
      ) {
        invalidatePublicKeyCache()
      }

      // 401：尝试用 refresh cookie 自动刷新并重试（仅重试一次，避免无限循环）
      //
      // P3-41：认证入口的 401 不参与刷新重试。这些接口的 401 语义是
      // 「凭据错误」而非「令牌过期」——输错密码本来就该立刻得到提示。
      // 原实现无差别刷新：浏览器里残留旧 refresh cookie 时，一次输错密码
      // 要先等 doRefreshToken（超时 10s）跑完才弹「用户名或密码错误」，
      // 用户会以为系统卡死并反复点击（进而更快撞上登录限流）。
      // 即使刷新侥幸成功，重发一次「密码错误」的登录请求也毫无意义。
      const isAuthEntryPoint = AUTH_NO_REFRESH_PATHS.some((p) =>
        String(config?.url || '').includes(p)
      )
      // 会话确认不可用：提示 + 清本地态 + 跳登录。两条路径共用（Qoder 轮7）：
      //   ① 刷新被服务端**明确拒绝**（401/403/REFRESH_TOKEN_MISSING；网络错误与 5xx
      //      不算——见下方 isRefreshSessionDead 的口径）；
      //   ② 刷新**成功**但重发的那一发仍然 401 —— 典型形态是设备被踢或强制下线：
      //      cookie 有效、新令牌照发，但令牌里的 sid 已失效，于是每次请求都落在
      //      "刷新成功 → 重发 → 又 401"。此前 ② 因 `_retried` 短路了整段登出逻辑，
      //      而 switch 里的 401 分支只服务认证入口 → 普通接口得到的是
      //      **没有提示、没有跳转、界面仍是已登录态**，运维只看到满屏空面板。
      // 循环约束不变：②不刷新、不重发，只是把已经确定的失败说出来。
      const forceSessionReset = (payload) => {
        if (apiClient._isHandling401) return
        apiClient._isHandling401 = true
        // 登录页 MFA 二次验证失败也走 401：先查映射（errorCode/后端消息英文化），再透传后端 message
        ElMessage.error(
          resolveErrorMessage(payload) || payload?.message || t('messages.sessionExpired')
        )
        ;(async () => {
          try {
            const { useAuthStore } = await import('@/store')
            try {
              useAuthStore().clearAuth()
            } catch (_) {}
          } catch (_) {}
          // 必须 catch：router.push 在"导航被守卫取消/目标就是当前路由"时是 **reject 的 Promise**，
          // 而这里是即发不待（fire-and-forget）的登出链——不接住就是一条 unhandledrejection，
          // 被 errorReporter 记成前端异常，且真实登出结论被噪音掩盖。
          router.push('/login').catch(() => {})
        })().finally(() => {
          apiClient._isHandling401 = false
        })
      }

      /**
       * 强制改密：写本地标记 + 引导到 /profile。
       *
       * 为什么不只弹提示：该闸生效期间**所有**业务请求都会失败，一次提示等于把用户留在原地
       * 反复点。这里先把 mustChangePassword 写进 store（路由守卫据此收敛），再跳 /profile；
       * 已在 /profile 时只更新标记——那一页的几个卡片会同时收到 403，逐个弹提示就是刷屏。
       * 去重锁与 forceSessionReset 同一思路：并发请求只处理第一次。
       */
      const handlePasswordChangeRequired = (payload, { silent } = {}) => {
        if (apiClient._isHandlingPasswordChange) return
        apiClient._isHandlingPasswordChange = true
        ;(async () => {
          let onProfile = false
          try {
            const { useAuthStore } = await import('@/store')
            const store = useAuthStore()
            const current = store.currentUser
            if (current && current.mustChangePassword !== true) {
              store.setCurrentUser({ ...current, mustChangePassword: true })
            }
          } catch (_) {}
          try {
            onProfile = router.currentRoute?.value?.path === '/profile'
          } catch (_) {}
          if (!onProfile) {
            if (!silent) {
              ElMessage.warning(
                resolveErrorMessage(payload) || payload?.message || t('messages.accessDenied')
              )
            }
            router.replace('/profile').catch(() => {})
          }
        })().finally(() => {
          apiClient._isHandlingPasswordChange = false
        })
      }

      // 强制改密闸（P1-2）：服务端对所有非放行路径一律回 PASSWORD_CHANGE_REQUIRED。
      // 不在这里统一处理的话，页面只会得到一条「权限不足」，然后继续发下一条同样失败的
      // 请求——用户被留在看起来坏掉的界面上，而「去改密」这个唯一的下一步没有任何入口。
      if (incomingErrorCode === 'PASSWORD_CHANGE_REQUIRED') {
        handlePasswordChangeRequired(data, { silent: silentErrors })
        return Promise.reject(error)
      }

      if (status === 401 && !config?._retried && !isAuthEntryPoint) {
        const outcome = await doRefreshToken()
        if (outcome?.ok && config) {
          config._retried = true
          // 新 access_token 已由刷新响应 Set-Cookie 写入浏览器，直接重发即可
          delete config.headers.Authorization
          return apiClient.request(config)
        }

        // silent401：调用方声明「401 属预期结果」（会话恢复探测 /auth/me）。
        // 刷新仍要尝试——access 过期而 refresh 有效时会话应当被救回；
        // 但刷新也失败时不提示、不跳转，把结果交还调用方判定。
        // 否则未登录用户首次访问任意页面都会先弹一次「登录已过期」。
        const rejectAsSessionDead = () => {
          if (config?.silent401) return Promise.reject(error)
          forceSessionReset(data)
          return Promise.reject(error)
        }

        // 503（含 CONCURRENT）：静默恢复一次。
        // 后端对「同一浏览器的两个标签页几乎同时刷新」有宽限：败者拿到 503
        // SECURITY_SERVICE_UNAVAILABLE，但胜者的 Set-Cookie 已经把浏览器里的
        // access/refresh 都换成了新令牌——本次 401 只是**抢跑**，不是会话失效。
        // 等一小段让 Set-Cookie 落地后重试刷新一次：成功即重放原请求（写请求也安全，
        // 原请求在鉴权层就被拒、处理器从未执行）；仍失败则放弃本次请求，不打扰用户。
        if (outcome?.status === 503 && config && !config._raceRecovered) {
          config._raceRecovered = true
          const recovered = await doRefreshToken({ raceRecovery: true })
          if (recovered?.ok && config) {
            config._retried = true
            delete config.headers.Authorization
            return apiClient.request(config)
          }
          // 恢复这一发若被明确拒绝，才轮到登出；否则只放弃本次请求
          if (isRefreshSessionDead(recovered)) return rejectAsSessionDead()
          return Promise.reject(error)
        }

        // 网络错误/超时/429/其它 5xx：无法证明会话失效。
        // 不弹「会话已失效」、不清本地身份、不跳登录页——只把 401 交还调用方；
        // 网络/后端故障的真实原因会由界面上后续请求各自的失败提示承担。
        if (!isRefreshSessionDead(outcome)) return Promise.reject(error)

        return rejectAsSessionDead()
      }

      // 静音只覆盖「提示」本身；401/403 属控制流/安全语义，分支必须照常进入：
      // 401 分支里除了提示还住着「刷新成功后重发仍 401」的 forceSessionReset（登出链），
      // 403 分支承载鉴权结论。二者若整段被跳过，会话已死的页面会静默僵住——
      // 升级轮询正是唯一的 silentErrors 调用方（3s 一次），这条路径真实可达。
      // 分支**内部**的提示仍按 silentErrors 决定是否弹（403 静音不丢任何语义，
      // 因为该分支只有一条提示；429 等仍整体静音，避免轮询把红框刷屏）。
      const notifyStatus = !silentErrors || status === 401 || status === 403
      if (notifyStatus)
        switch (status) {
          case 400:
            ElMessage.warning(
              resolveErrorMessage(data) || data?.message || t('messages.requestParamError')
            )
            break
          case 401:
            // 令牌过期路径已在上方处理（重试或登出），不重复提示。
            // P3-41：认证入口的 401（凭据错误）跳过了上方分支，必须在此提示，
            // 否则输错密码将完全没有反馈——比原来的「等 10s 才提示」更糟。
            if (isAuthEntryPoint) {
              // 认证入口的凭据错误提示：静音态下由调用方自行处理文案
              if (!silentErrors)
                ElMessage.error(resolveErrorMessage(data) || data?.message || t('login.failed'))
            } else if (!config?.silent401) {
              // 落到这里的只剩一种形态：**刷新成功后重发仍然 401**（`_retried` 已置真，
              // 上方分支不再进入）。此前它两头都不管——上方因 `_retried` 短路、
              // 这里只服务认证入口——于是用户既没提示也没登出。
              forceSessionReset(data)
            }
            break
          case 403:
            // 静音态（轮询）下不弹：权限不足的结论已由 reject 交还调用方，
            // 3s 一次重复弹「权限不足」只会把真正需要人介入的失败淹没
            if (!silentErrors)
              ElMessage.error(
                resolveErrorMessage(data) || data?.message || t('messages.accessDenied')
              )
            break
          case 404:
            ElMessage.error(
              resolveErrorMessage(data) || data?.message || t('messages.resourceNotFound')
            )
            break
          case 405:
            // HTTP_METHOD_UNSUPPORTED：协议层拒绝（如 TRACE/TRACK），非用户可纠正的操作错误
            ElMessage.error(
              resolveErrorMessage(data) || data?.message || t('messages.methodNotAllowed')
            )
            break
          case 409:
            // 状态冲突类（ALARM_ALREADY_HANDLED / ALARM_STATUS_NOT_ALLOWED*）：
            // 多为「记录已被他人处理」这类可解释的并发结果，用 warning 而非 error
            ElMessage.warning(resolveErrorMessage(data) || data?.message || t('messages.conflict'))
            break
          case 413:
            // PAYLOAD_EXCEEDS_LIMIT / PAYLOAD_TOO_LARGE：请求体超过服务端上限
            ElMessage.error(
              resolveErrorMessage(data) || data?.message || t('messages.payloadTooLarge')
            )
            break
          case 415:
            // CONTENT_TYPE_UNSUPPORTED：媒体类型不在白名单内
            ElMessage.error(
              resolveErrorMessage(data) || data?.message || t('messages.unsupportedMediaType')
            )
            break
          case 429:
            // 优先透传后端消息（如 MFA 防爆破锁定的"10 分钟后再试"），映射缺失时按 locale 兜底
            ElMessage.warning(
              resolveErrorMessage(data) || data?.message || t('messages.tooManyRequests')
            )
            break
          case 431:
            // HEADER_COUNT_EXCESSIVE / HEADER_VALUE_TOO_LONG：请求头数量或长度超限
            ElMessage.error(
              resolveErrorMessage(data) || data?.message || t('messages.requestHeaderTooLarge')
            )
            break
          case 500:
            // 500 与 503 同口径：先走码化翻译（如 INTERNAL_ERROR / AUDIT_EXPORT_FAILED），
            // 否则英文界面下会直接回显后端中文文案
            ElMessage.error(resolveErrorMessage(data) || data?.message || t('messages.serverError'))
            break
          case 503:
            // 服务不可用类（如 LOGOUT_REVOKE_FAILED / CAPTCHA_SERVICE_UNAVAILABLE）：
            // 走码化翻译通道，否则会退到 default 分支直接回显后端中文，英文界面下不一致
            ElMessage.error(resolveErrorMessage(data) || data?.message || t('messages.serverError'))
            break
          default:
            ElMessage.error(data?.message || t('messages.requestFailed'))
        }
    } else if (error.request) {
      if (!silentErrors) ElMessage.error(t('messages.networkError'))
    } else {
      if (!silentErrors) ElMessage.error(error.message || t('messages.requestConfigError'))
    }

    return Promise.reject(error)
  }
)

// 路径参数统一编码：ID 直接拼进 URL 时，'/'、'?'、'#' 等字符会改变路由语义
//（如 id='a/b' 命中另一条路由）。即使当前取值来自服务端 UUID，也不应依赖这一点。
const encodePathSegment = (value) => encodeURIComponent(String(value))

// API 方法封装
export const api = {
  // 认证相关
  auth: {
    login: (data) => apiClient.post('/auth/login', data),
    getCaptcha: () => apiClient.get('/auth/captcha'),
    getCaptchaStatus: () => apiClient.get('/auth/captcha-status'),
    register: (data) => apiClient.post('/auth/register', data),
    logout: () => apiClient.post('/auth/logout'),
    // config 透传：会话恢复探测传 { silent401: true }，
    // 让「未登录」这一预期结果不弹「登录已过期」也不触发跳转
    getMe: (config) => apiClient.get('/auth/me', config),
    // 轻量会话探测：始终 200，返回 { authenticated }，不触发 token 刷新链
    getSessionStatus: (config) => apiClient.get('/auth/session', config),
    changePassword: (data) => apiClient.put('/auth/password', data),
    updateProfile: (data) => apiClient.put('/auth/profile', data),
    uploadAvatar: (data) => apiClient.put('/auth/avatar', data),
    deleteAvatar: () => apiClient.delete('/auth/avatar'),
    refreshToken: (data) => apiClient.post('/auth/refresh', data),
    // MFA 两步验证（I-06）
    getMfaStatus: () => apiClient.get('/auth/mfa/status'),
    mfaEnroll: (data) => apiClient.post('/auth/mfa/enroll', data),
    mfaEnable: (data) => apiClient.post('/auth/mfa/enable', data),
    mfaDisable: (data) => apiClient.post('/auth/mfa/disable', data),
    regenerateRecoveryCodes: (data) => apiClient.post('/auth/mfa/recovery-codes', data),
    // 设备级会话管理（登录会话）
    listSessions: () => apiClient.get('/auth/sessions'),
    // sid 由服务端下发（UUID），此处仍做一次编码：
    // 路径参数直接拼接是注入面，即使当前取值可信也不应依赖「上游一定干净」
    revokeSession: (sid) => apiClient.delete(`/auth/sessions/${encodePathSegment(sid)}`),
    // 必须是固定字面量而非 revokeSession('others')：后端按注册顺序区分两条路由，
    // 走 :sid 分支会被 UUID 校验拒为 400
    revokeOtherSessions: () => apiClient.delete('/auth/sessions/others'),
  },

  // 用户管理
  users: {
    getList: (params, config) => apiClient.get('/users', { params, ...config }),
    getById: (id) => apiClient.get(`/users/${encodePathSegment(id)}`),
    getStats: () => apiClient.get('/users/stats'),
    // config 透传：建号是「点一次多一条」的端点，视图会带 Idempotency-Key 提交标识
    create: (data, config) => apiClient.post('/users', data, config),
    update: (id, data) => apiClient.put(`/users/${encodePathSegment(id)}`, data),
    delete: (id) => apiClient.delete(`/users/${encodePathSegment(id)}`),
    // 批量删除：固定字面量 /users/batch（后端把该路由注册在 /:id 之前），ids 为 1-100 个 ID。
    // delete 带请求体走 config.data；写方法不参与路由切换取消（UNCANCELABLE_METHODS）
    batchDelete: (ids) => apiClient.delete('/users/batch', { data: { ids } }),
    assignRoles: (id, data) => apiClient.put(`/users/${encodePathSegment(id)}/roles`, data),
  },

  // 角色管理
  roles: {
    getList: (params) => apiClient.get('/roles', { params }),
    getAll: () => apiClient.get('/roles/all'),
    getById: (id) => apiClient.get(`/roles/${encodePathSegment(id)}`),
    create: (data, config) => apiClient.post('/roles', data, config),
    update: (id, data) => apiClient.put(`/roles/${encodePathSegment(id)}`, data),
    delete: (id) => apiClient.delete(`/roles/${encodePathSegment(id)}`),
    assignPermissions: (id, data) =>
      apiClient.put(`/roles/${encodePathSegment(id)}/permissions`, data),
    getPermissionTree: (config) => apiClient.get('/roles/permissions/tree', config),
  },

  // 权限管理
  permissions: {
    getList: (params) => apiClient.get('/permissions', { params }),
    getById: (id) => apiClient.get(`/permissions/${encodePathSegment(id)}`),
    create: (data, config) => apiClient.post('/permissions', data, config),
    update: (id, data) => apiClient.put(`/permissions/${encodePathSegment(id)}`, data),
    delete: (id) => apiClient.delete(`/permissions/${encodePathSegment(id)}`),
    batchCreate: (data, config) => apiClient.post('/permissions/batch', data, config),
    // 临时权限授予（C-08）：路由挂在 /api/permissions/grants 下，与权限目录同一命名空间
    getGrants: (params) => apiClient.get('/permissions/grants', { params }),
    getGrantReview: () => apiClient.get('/permissions/grants/review'),
    createGrant: (data, config) => apiClient.post('/permissions/grants', data, config),
    approveGrant: (id) => apiClient.post(`/permissions/grants/${encodePathSegment(id)}/approve`),
    rejectGrant: (id, data) =>
      apiClient.post(`/permissions/grants/${encodePathSegment(id)}/reject`, data),
    revokeGrant: (id, data) =>
      apiClient.post(`/permissions/grants/${encodePathSegment(id)}/revoke`, data),
  },

  // 设备管理
  devices: {
    getList: (params) => apiClient.get('/devices', { params }),
    getById: (id) => apiClient.get(`/devices/${encodePathSegment(id)}`),
    create: (data, config) => apiClient.post('/devices', data, config),
    update: (id, data) => apiClient.put(`/devices/${encodePathSegment(id)}`, data),
    delete: (id) => apiClient.delete(`/devices/${encodePathSegment(id)}`),
    updateStatus: (id, data) => apiClient.put(`/devices/${encodePathSegment(id)}/status`, data),
    addMaintenance: (id, data) =>
      apiClient.post(`/devices/${encodePathSegment(id)}/maintenance`, data),
    getStats: () => apiClient.get('/devices/stats'),
    getExpiring: (params) => apiClient.get('/devices/expiring', { params }),
    getReminders: () => apiClient.get('/devices/reminders'),
  },

  // 报警管理
  alarms: {
    getList: (params) => apiClient.get('/alarms', { params }),
    getById: (id) => apiClient.get(`/alarms/${encodePathSegment(id)}`),
    report: (data, config) => apiClient.post('/alarms/report', data, config),
    dispatch: (id, data) => apiClient.put(`/alarms/${encodePathSegment(id)}/dispatch`, data),
    arrive: (id) => apiClient.put(`/alarms/${encodePathSegment(id)}/arrive`),
    resolve: (id, data) => apiClient.put(`/alarms/${encodePathSegment(id)}/resolve`, data),
    markAsFalse: (id, data) => apiClient.put(`/alarms/${encodePathSegment(id)}/false-alarm`, data),
    getStats: (params) => apiClient.get('/alarms/stats', { params }),
  },

  // 巡检管理
  inspections: {
    getList: (params) => apiClient.get('/inspections', { params }),
    getById: (id) => apiClient.get(`/inspections/${encodePathSegment(id)}`),
    create: (data, config) => apiClient.post('/inspections', data, config),
    update: (id, data) => apiClient.put(`/inspections/${encodePathSegment(id)}`, data),
    start: (id) => apiClient.put(`/inspections/${encodePathSegment(id)}/start`),
    complete: (id, data) => apiClient.put(`/inspections/${encodePathSegment(id)}/complete`, data),
    review: (id, data) => apiClient.put(`/inspections/${encodePathSegment(id)}/review`, data),
    cancel: (id, data) => apiClient.put(`/inspections/${encodePathSegment(id)}/cancel`, data),
    delete: (id) => apiClient.delete(`/inspections/${encodePathSegment(id)}`),
    getStats: () => apiClient.get('/inspections/stats'),
  },

  // 报表统计
  reports: {
    getDashboard: () => apiClient.get('/reports/dashboard'),
    // O-8 面板 JSON：运行时指标 snapshot（security:audit 权限门控）
    getMetrics: () => apiClient.get('/metrics'),
    getDevices: (params) => apiClient.get('/reports/devices', { params }),
    getAlarms: (params) => apiClient.get('/reports/alarms', { params }),
    getInspections: (params) => apiClient.get('/reports/inspections', { params }),
    export: (params) =>
      apiClient.get('/reports/export', {
        params,
        responseType: 'blob',
      }),
    // L-17：未脱敏导出必须走 POST（凭据不进 URL）并携带当前口令/MFA 码
    exportPii: (params, credential) =>
      apiClient.post('/reports/export/pii', credential, {
        params,
        responseType: 'blob',
      }),
  },

  // 安全管理
  security: {
    getOverview: () => apiClient.get('/security/overview'),
    // 版本概况（security:config）：服务端构建、当前承接色、升级代理心跳与任务历史。
    // 快照数据，页面按需刷新；升级弹窗打开期间另按任务 ID 轮询 /upgrade/jobs/:jobId。
    // config 透传：{ signal } 让调用方可在弹窗关闭 / 切换任务时中断在途请求
    getUpgradeOverview: (config) => apiClient.get('/security/upgrade', config),
    // config 透传 { signal, silentErrors }：轮询是 3s 一次的自动请求，失败不弹提示
    // （由调用方按退避策略重试），关闭弹窗 / 切换任务时中断在途请求。
    getUpgradeJob: (jobId, config) =>
      apiClient.get(`/security/upgrade/jobs/${encodePathSegment(jobId)}`, config),
    // 一键升级（仅超管 + 二次验证）：body { image, currentPassword | encCurrentPassword | mfaCode }。
    // image 必须是 name@sha256:<64hex>；服务端只把请求写入队列，由宿主代理执行并重新校验。
    triggerUpgrade: (data) => apiClient.post('/security/upgrade/requests', data),
    getAlerts: () => apiClient.get('/security/alerts'),
    queryAuditLogs: (params) => apiClient.get('/security/audit-logs', { params }),
    // 二次验证（5 分钟会话窗口 + 一次性票据）。body 同写操作：{ currentPassword |
    // encCurrentPassword | mfaCode }。窗口存在服务端，客户端不保管任何凭据。
    createReauthTicket: (credential) => apiClient.post('/security/reauth', credential),
    getRegistrationConfig: () => apiClient.get('/security/config/allowPublicRegistration'),
    setRegistrationConfig: (data) =>
      apiClient.put('/security/config/allowPublicRegistration', data),
    getLoginCaptchaConfig: () => apiClient.get('/security/config/loginCaptchaEnabled'),
    setLoginCaptchaConfig: (data) => apiClient.put('/security/config/loginCaptchaEnabled', data),
    getRegisterCaptchaConfig: () => apiClient.get('/security/config/registerCaptchaEnabled'),
    setRegisterCaptchaConfig: (data) =>
      apiClient.put('/security/config/registerCaptchaEnabled', data),
    // IP 黑白名单管理
    getIPList: (params) => apiClient.get('/security/ip-list', { params }),
    // 管理员重置用户两步验证（账户救济：清除 TOTP/恢复码并强制下线）。
    // 需操作者本人二次验证：data 为 { currentPassword | encCurrentPassword | mfaCode }。
    resetUserMfa: (userId, data) =>
      apiClient.put(`/security/users/${encodePathSegment(userId)}/mfa/reset`, data),
    // P1-2 管理员重置口令（账户救济）：返回的一次性临时口令只用于本次展示，
    // 服务端不落明文、审计不含口令；用户首次登录必须改密。
    resetUserPassword: (userId, data) =>
      apiClient.put(`/security/users/${encodePathSegment(userId)}/password/reset`, data),
    // 锁定/解锁用户（user:lock）：locked 必须是真布尔——路由 toBoolean 收口前，
    // 字符串 'false' 会被服务层按 truthy 判成锁定。reason 可选 ≤500，锁定方向
    // 写入 user.remark 与 user_locked 审计（服务层连带清 lockUntil 并失效权限缓存）
    lockUser: (userId, data) =>
      apiClient.put(`/security/users/${encodePathSegment(userId)}/lock`, data),
    // 敏感字段按需揭示（step-up）：body { dataType, targetUserId?, currentPassword? | mfaCode? }
    // → data { type, masked, full }。用户列表/详情只下发脱敏值，明文只能走这一条通道
    // （服务端在此写 view_sensitive_data 审计，审计写失败即不返回明文）。
    viewSensitive: (data) => apiClient.post('/security/view-sensitive', data),
    addIPEntry: (data) => apiClient.post('/security/ip-list', data),
    removeIPEntry: (id) => apiClient.delete(`/security/ip-list/${encodePathSegment(id)}`),
    // 举报对象候选（GET /security/report-targets?type=&keyword=）→ data { items }
    // 免权限码（举报对全员开放），但候选集已被服务端按**举报人数据范围**过滤，
    // 判据与提交时的目标核验同源；items 只含 id/kind/code/name/detail（报警另有
    // occurredAt），不含 phone/email、报警描述、上报人姓名。
    // type ∈ user/device/alarm（system 不指向具体对象，没有候选）。
    searchReportTargets: (params) => apiClient.get('/security/report-targets', { params }),
    // 举报异常（人人可用，无权限码）：targetType ∈ user/device/alarm/system。
    // 记录型必须带真实且数据范围内的 targetId（后端核验存在性+范围），system 型
    // 禁止携带 targetId；reason 必填 1-200，description 可选 ≤500。成功后写入
    // riskLevel:high 审计，响应 data.reportId 为审计记录 ID
    report: (data) => apiClient.post('/security/report', data),
    // 审计链完整性核验：GET /audit-logs/verify?limit=&from=latest|earliest
    // → data { intact, breaks, byType, total, scanned, canAttestIntact, verdictCode,
    //          verdictReasons, collectionTotal }
    // 判绿必须看 canAttestIntact（扫全+无断+各层真跑过），不能只看 intact（仅"扫过的没断"）。
    verifyAuditChain: (params) => apiClient.get('/security/audit-logs/verify', { params }),
    // 取证级导出：CSV + 签名 manifest（尾部注释行 + X-Audit-Manifest-* 响应头），
    // 截断时带 X-Audit-Truncated: true。与 /reports/export?type=audit 的 xlsx 报表定位不同。
    exportAuditLogs: (params) =>
      apiClient.get('/security/audit-logs/export', { params, responseType: 'blob' }),
    // 系统安全统计（管理员，需 security:stats）
    getSecurityStats: () => apiClient.get('/security/stats'),
    // 个人安全信息 / 账号绑定 / 个人操作日志（本人数据，无权限码门控）
    getMySecurityInfo: () => apiClient.get('/security/my-info'),
    getAccountBindings: () => apiClient.get('/security/bindings'),
    getMyLogs: (params) => apiClient.get('/security/my-logs', { params }),

    // ================= 取证溯源（T5/T6）=================
    // 后端挂载前缀 /api/security/forensic（src/routes/securityRoutes.js 的
    // router.use('/forensic', forensicRoutes)），故这里写 /security/forensic/*。
    //
    // 信封口径（utils/apiResponse）：成功 { success, message, data }，失败
    // { success: false, message, errors: { errorCode, ...params } }。axios 的
    // res.data 就是这层信封，**业务负载在 res.data.data** —— 视图一律读内层 data，
    // 不要读 res.data（那拿到的是信封本身）。
    //
    // 溯源查询：ip / fingerprint / ipSegment 至少给一个，否则后端 400
    // FORENSIC_NO_CRITERIA（地址解析不出也走同一个码，不是空结果）。
    // 传 fingerprint 时响应才带 pools —— 那就是「他的 ip 池」。
    getForensicTrace: (params, config) =>
      apiClient.get('/security/forensic/trace', { params, ...config }),
    // IP 池聚类：windowHours(1..720，默认 24) minHits(默认 20) minIps(默认 4) limit(默认 50)。
    // 返回 segments 与 recommended（后者是 recommendBan=true 的子集）。
    getForensicClusters: (params, config) =>
      apiClient.get('/security/forensic/clusters', { params, ...config }),
    // 封段两步走：先申请确认票据（不落库），再持票落库。
    // 被护栏拒绝时 HTTP 400 + FORENSIC_POOL_BAN_REFUSED，**具体原因在 errors.reason**，
    // 视图必须按 reason 给专属文案，不能笼统报「操作失败」。
    // config 透传 { silentErrors }：本视图要把拒绝原因渲染在页面上，不希望同一次失败
    // 再弹一条笼统的拦截器提示（重复且更模糊）。
    requestPoolBan: (data, config) =>
      apiClient.post('/security/forensic/pool-ban/request', data, config),
    // 持票落库。token 一次性、10 分钟失效，原样提交。响应 bannedCount 只数**真的**
    // 写进去的条数（addToBlacklist 从不抛错，「没报错」≠「封上了」），
    // 故成功提示必须用 bannedCount 报实数。
    confirmPoolBan: (data, config) =>
      apiClient.post('/security/forensic/pool-ban/confirm', data, config),
    // 签名导出：参数与 trace 同形，响应 data.pkg 是签名包（v/alg/keyId/exportedAt/
    // count/digest/signature/records/manifestRef）。未配密钥 ⇒ 400
    // FORENSIC_EXPORT_NO_SECRET，绝不能当成功。
    exportForensic: (data, config) => apiClient.post('/security/forensic/export', data, config),
  },
}

export { apiClient }

export default apiClient
