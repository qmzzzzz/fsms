/**
 * API 客户端配置 - 跨浏览器兼容
 * 负责与后端 API 通信
 *
 * 认证方案（I-01 httpOnly cookie）：
 * - 令牌由后端 Set-Cookie 下发：access_token(path=/api, 24h) 与
 *   refresh_token(path=/api/auth, 7d)，均 httpOnly + SameSite=Lax，JS 不可读，
 *   XSS 无法窃取；请求经同源代理（dev Vite / 生产 Nginx）自动携带。
 * - withCredentials=true：确保未来前端与 API 分域部署时 cookie 仍随请求发送。
 *
 * CSRF 说明：
 * - SameSite=Lax 下跨站 POST/PUT/DELETE 不携带 cookie，经典 CSRF 已被阻断；
 * - 全部写请求均为 JSON Content-Type，无法由表单跨站伪造。
 */

import axios from 'axios'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import router from '@/router'
import i18n from '@/i18n'
// FE-M1：密文被拒时统一失效公钥缓存（loginCipher 仅依赖 axios，无循环）
import { invalidatePublicKeyCache } from '@/utils/loginCipher'
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
  AUTH_ENCRYPTED_CREDENTIAL_INVALID: 'errors.encryptedCredentialInvalid',
  // 图形验证码
  CAPTCHA_INVALID: 'errors.captchaInvalid',
  CAPTCHA_SERVICE_UNAVAILABLE: 'errors.captchaServiceUnavailable',
  // 会话吊销（后端 P2-26 fail-closed）
  LOGOUT_REVOKE_FAILED: 'errors.logoutRevokeFailed',
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
  VALIDATION_FAILED: 'errors.validationFailed',
  ALARM_NOT_FOUND: 'errors.alarmNotFound',
  ALARM_VIEW_FORBIDDEN: 'errors.alarmViewForbidden',
  ALARM_OPERATE_FORBIDDEN: 'errors.alarmOperateForbidden',
  ALARM_ALREADY_HANDLED: 'errors.alarmAlreadyHandled',
  ALARM_STATUS_NOT_ALLOWED_SHORT: 'errors.alarmStatusNotAllowedShort',
  ALARM_HANDLE_RESULT_REQUIRED: 'errors.alarmHandleResultRequired',
  ALARM_STATUS_NOT_ALLOWED: 'errors.alarmStatusNotAllowed',
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
  PASSWORD_CURRENT_INCORRECT: 'errors.passwordCurrentIncorrect',
  PASSWORD_SAME_AS_OLD: 'errors.passwordSameAsOld',
  PASSWORD_CHANGED_REVOKE_FAILED: 'errors.passwordChangedRevokeFailed',
  USER_NOT_FOUND: 'errors.userNotFound',
  PHONE_INVALID: 'errors.phoneInvalid',
  EMAIL_INVALID: 'errors.emailInvalid',
  EMAIL_TAKEN: 'errors.emailTaken',
  AVATAR_INVALID: 'errors.avatarInvalid',
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
  IP_LIST_ENTRY_NOT_FOUND: 'errors.ipListEntryNotFound',
  IP_FULL_RANGE_REMOVE_SUPER_ADMIN_ONLY: 'errors.ipFullRangeRemoveSuperAdminOnly',
  PERMISSION_NOT_FOUND: 'errors.permissionNotFound',
  PARENT_PERMISSION_SELF: 'errors.parentPermissionSelf',
  PARENT_PERMISSION_NOT_FOUND: 'errors.parentPermissionNotFound',
  PARENT_PERMISSION_CYCLE: 'errors.parentPermissionCycle',
  PERMISSION_TREE_DEPTH_ANOMALY: 'errors.permissionTreeDepthAnomaly',
  PERMISSION_LIST_INVALID: 'errors.permissionListInvalid',
  EXPORT_FORMAT_UNSUPPORTED: 'errors.exportFormatUnsupported',
  REPORT_TYPE_UNSUPPORTED: 'errors.reportTypeUnsupported',
  ROLE_NOT_FOUND: 'errors.roleNotFound',
  ROLE_VIEW_FORBIDDEN: 'errors.roleViewForbidden',
  ROLE_CODE_TAKEN: 'errors.roleCodeTaken',
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
  SENSITIVE_VIEW_HIGHER_LEVEL_FORBIDDEN: 'errors.sensitiveViewHigherLevelForbidden',
  UNSUPPORTED_DATA_TYPE: 'errors.unsupportedDataType',
  REPORT_TARGET_AND_REASON_REQUIRED: 'errors.reportTargetAndReasonRequired',
  USER_OPERATE_PEER_OR_HIGHER_FORBIDDEN: 'errors.userOperatePeerOrHigherForbidden',
  UNLOCK_INACTIVE_ACCOUNT: 'errors.unlockInactiveAccount',
  LOCK_INACTIVE_ACCOUNT: 'errors.lockInactiveAccount',
  ACCOUNT_NOT_LOCKED: 'errors.accountNotLocked',
  CANNOT_RESET_OWN_MFA_VIA_ADMIN: 'errors.cannotResetOwnMfaViaAdmin',
  TARGET_MFA_NOT_ENABLED: 'errors.targetMfaNotEnabled',
  MFA_RESET_PEER_OR_HIGHER_FORBIDDEN: 'errors.mfaResetPeerOrHigherForbidden',
  SESSION_REVOKE_SERVICE_UNAVAILABLE: 'errors.sessionRevokeServiceUnavailable',
  FORCE_LOGOUT_MFA_CLEAR_FAILED: 'errors.forceLogoutMfaClearFailed',
  SECURITY_OVERVIEW_FORMAT_INVALID: 'errors.securityOverviewFormatInvalid',
  SECURITY_OVERVIEW_STRUCTURE_INVALID: 'errors.securityOverviewStructureInvalid',
  SECURITY_OVERVIEW_QUERY_FAILED: 'errors.securityOverviewQueryFailed',
  RECENT_ALERTS_EMPTY: 'errors.recentAlertsEmpty',
  RECENT_ALERTS_QUERY_FAILED: 'errors.recentAlertsQueryFailed',
  CONFIG_ALLOW_REGISTRATION_MUST_BE_BOOLEAN: 'errors.configAllowRegistrationMustBeBoolean',
  CONFIG_LOGIN_CAPTCHA_MUST_BE_BOOLEAN: 'errors.configLoginCaptchaMustBeBoolean',
  CONFIG_REGISTER_CAPTCHA_MUST_BE_BOOLEAN: 'errors.configRegisterCaptchaMustBeBoolean',
  USER_VIEW_FORBIDDEN: 'errors.userViewForbidden',
  IP_RULES_FORMAT_INVALID: 'errors.ipRulesFormatInvalid',
  ROLE_NOT_FOUND_IN_LIST: 'errors.roleNotFoundInList',
  ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN: 'errors.roleAssignHigherLevelForbidden',
  USER_UPDATE_PEER_OR_HIGHER_FORBIDDEN: 'errors.userUpdatePeerOrHigherForbidden',
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
  REAUTH_PROCESS_FAILED: 'errors.reauthProcessFailed',
  IP_BLOCKED: 'errors.ipBlocked',
  UPLOAD_FILE_TOO_LARGE: 'errors.uploadFileTooLarge',
  UPLOAD_TYPE_NOT_ALLOWED: 'errors.uploadTypeNotAllowed',
  UPLOAD_EXT_NOT_ALLOWED: 'errors.uploadExtNotAllowed',
  PARAM_MUST_BE_VALID_OBJECT_ID: 'errors.paramMustBeValidObjectId',
  PUBLIC_REGISTRATION_DISABLED: 'errors.publicRegistrationDisabled',
  REGISTER_SERVICE_UNAVAILABLE: 'errors.registerServiceUnavailable',
  AUDIT_QUERY_FAILED: 'errors.auditQueryFailed',
}

/**
 * 按 errors.errorCode 解析本地化错误消息
 * 未命中（后端未码化的接口）返回 null，调用方回退到后端 message
 */
function resolveErrorMessage(data) {
  const errorCode = data?.errors?.errorCode
  if (errorCode && ERROR_CODE_I18N_MAP[errorCode]) {
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

// 创建 axios 实例
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 15000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

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

const doRefreshToken = async () => {
  if (isRefreshing) return refreshPromise
  isRefreshing = true
  refreshPromise = (async () => {
    try {
      // 刷新令牌在 httpOnly cookie(path=/api/auth)中，浏览器按路径自动携带，无需 body；
      // 直接用 axios 调用，避免经过拦截器导致循环；补超时防止刷新请求悬挂阻塞重试链
      const resp = await axios.post(
        (import.meta.env.VITE_API_BASE_URL || '/api') + '/auth/refresh',
        {},
        { timeout: 10000, withCredentials: true }
      )
      // 新令牌由响应 Set-Cookie 写回浏览器，前端无需（也无法）读取
      return resp.data?.success === true
    } finally {
      isRefreshing = false
      refreshPromise = null
    }
  })()
  return refreshPromise
}

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

export const cancelAllPendingRequests = (message = '路由切换，取消在途请求') => {
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
 */
const reportedDrifts = new Set()

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
  if (reportedDrifts.has(driftKey)) return
  reportedDrifts.add(driftKey)

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

    if (error.response) {
      const { status, data, config } = error.response

      // FE-M1：密文被拒（服务端重启换钥/密钥轮换）——统一在此清公钥缓存，
      // 登录/注册/改密三个口令入口全部自愈（原先只接在 LoginView）。
      // import 无循环：loginCipher 仅依赖 axios
      if (data?.errors?.errorCode === 'AUTH_ENCRYPTED_CREDENTIAL_INVALID') {
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
      if (status === 401 && !config?._retried && !isAuthEntryPoint) {
        try {
          const refreshed = await doRefreshToken()
          if (refreshed && config) {
            config._retried = true
            // 新 access_token 已由刷新响应 Set-Cookie 写入浏览器，直接重发即可
            delete config.headers.Authorization
            return apiClient.request(config)
          }
        } catch (_) {
          // 刷新失败，走正常登出流程
        }

        // silent401：调用方声明「401 属预期结果」（会话恢复探测 /auth/me）。
        // 刷新仍要尝试——access 过期而 refresh 有效时会话应当被救回；
        // 但刷新也失败时不提示、不跳转，把结果交还调用方判定。
        // 否则未登录用户首次访问任意页面都会先弹一次「登录已过期」。
        if (config?.silent401) {
          return Promise.reject(error)
        }

        // 刷新失败：清除认证并跳转登录
        if (!apiClient._isHandling401) {
          apiClient._isHandling401 = true
          // 登录页 MFA 二次验证失败也走 401：先查映射（errorCode/后端消息英文化），再透传后端 message
          ElMessage.error(
            resolveErrorMessage(data) || data?.message || t('messages.sessionExpired')
          )
          ;(async () => {
            try {
              const { useAuthStore } = await import('@/store')
              try {
                useAuthStore().clearAuth()
              } catch (_) {}
            } catch (_) {}
            router.push('/login')
          })().finally(() => {
            apiClient._isHandling401 = false
          })
        }
        return Promise.reject(error)
      }

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
            ElMessage.error(resolveErrorMessage(data) || data?.message || t('login.failed'))
          }
          break
        case 403:
          ElMessage.error(resolveErrorMessage(data) || data?.message || t('messages.accessDenied'))
          break
        case 404:
          ElMessage.error(
            resolveErrorMessage(data) || data?.message || t('messages.resourceNotFound')
          )
          break
        case 429:
          // 优先透传后端消息（如 MFA 防爆破锁定的"10 分钟后再试"），映射缺失时按 locale 兜底
          ElMessage.warning(
            resolveErrorMessage(data) || data?.message || t('messages.tooManyRequests')
          )
          break
        case 500:
          ElMessage.error(data?.message || t('messages.serverError'))
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
      ElMessage.error(t('messages.networkError'))
    } else {
      ElMessage.error(error.message || t('messages.requestConfigError'))
    }

    return Promise.reject(error)
  }
)

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
    refreshToken: (data) => apiClient.post('/auth/refresh', data),
    // MFA 两步验证（I-06）
    getMfaStatus: () => apiClient.get('/auth/mfa/status'),
    mfaEnroll: () => apiClient.post('/auth/mfa/enroll'),
    mfaEnable: (data) => apiClient.post('/auth/mfa/enable', data),
    mfaDisable: (data) => apiClient.post('/auth/mfa/disable', data),
    regenerateRecoveryCodes: (data) => apiClient.post('/auth/mfa/recovery-codes', data),
    // 设备级会话管理（登录会话）
    listSessions: () => apiClient.get('/auth/sessions'),
    // sid 由服务端下发（UUID），此处仍做一次 encodeURIComponent：
    // 路径参数直接拼接是注入面，即使当前取值可信也不应依赖「上游一定干净」
    revokeSession: (sid) => apiClient.delete(`/auth/sessions/${encodeURIComponent(sid)}`),
    // 必须是固定字面量而非 revokeSession('others')：后端按注册顺序区分两条路由，
    // 走 :sid 分支会被 UUID 校验拒为 400
    revokeOtherSessions: () => apiClient.delete('/auth/sessions/others'),
  },

  // 用户管理
  users: {
    getList: (params) => apiClient.get('/users', { params }),
    getById: (id) => apiClient.get(`/users/${id}`),
    getStats: () => apiClient.get('/users/stats'),
    create: (data) => apiClient.post('/users', data),
    update: (id, data) => apiClient.put(`/users/${id}`, data),
    delete: (id) => apiClient.delete(`/users/${id}`),
    assignRoles: (id, data) => apiClient.put(`/users/${id}/roles`, data),
  },

  // 角色管理
  roles: {
    getList: (params) => apiClient.get('/roles', { params }),
    getAll: () => apiClient.get('/roles/all'),
    getById: (id) => apiClient.get(`/roles/${id}`),
    create: (data) => apiClient.post('/roles', data),
    update: (id, data) => apiClient.put(`/roles/${id}`, data),
    delete: (id) => apiClient.delete(`/roles/${id}`),
    assignPermissions: (id, data) => apiClient.put(`/roles/${id}/permissions`, data),
    getPermissionTree: () => apiClient.get('/roles/permissions/tree'),
  },

  // 权限管理
  permissions: {
    getList: (params) => apiClient.get('/permissions', { params }),
    getById: (id) => apiClient.get(`/permissions/${id}`),
    create: (data) => apiClient.post('/permissions', data),
    update: (id, data) => apiClient.put(`/permissions/${id}`, data),
    delete: (id) => apiClient.delete(`/permissions/${id}`),
    batchCreate: (data) => apiClient.post('/permissions/batch', data),
  },

  // 设备管理
  devices: {
    getList: (params) => apiClient.get('/devices', { params }),
    getById: (id) => apiClient.get(`/devices/${id}`),
    create: (data) => apiClient.post('/devices', data),
    update: (id, data) => apiClient.put(`/devices/${id}`, data),
    delete: (id) => apiClient.delete(`/devices/${id}`),
    updateStatus: (id, data) => apiClient.put(`/devices/${id}/status`, data),
    addMaintenance: (id, data) => apiClient.post(`/devices/${id}/maintenance`, data),
    getStats: () => apiClient.get('/devices/stats'),
    getExpiring: (params) => apiClient.get('/devices/expiring', { params }),
  },

  // 报警管理
  alarms: {
    getList: (params) => apiClient.get('/alarms', { params }),
    getById: (id) => apiClient.get(`/alarms/${id}`),
    report: (data) => apiClient.post('/alarms/report', data),
    dispatch: (id, data) => apiClient.put(`/alarms/${id}/dispatch`, data),
    arrive: (id) => apiClient.put(`/alarms/${id}/arrive`),
    resolve: (id, data) => apiClient.put(`/alarms/${id}/resolve`, data),
    markAsFalse: (id, data) => apiClient.put(`/alarms/${id}/false-alarm`, data),
    getStats: (params) => apiClient.get('/alarms/stats', { params }),
  },

  // 巡检管理
  inspections: {
    getList: (params) => apiClient.get('/inspections', { params }),
    getById: (id) => apiClient.get(`/inspections/${id}`),
    create: (data) => apiClient.post('/inspections', data),
    update: (id, data) => apiClient.put(`/inspections/${id}`, data),
    start: (id) => apiClient.put(`/inspections/${id}/start`),
    complete: (id, data) => apiClient.put(`/inspections/${id}/complete`, data),
    review: (id, data) => apiClient.put(`/inspections/${id}/review`, data),
    cancel: (id, data) => apiClient.put(`/inspections/${id}/cancel`, data),
    delete: (id) => apiClient.delete(`/inspections/${id}`),
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
  },

  // 安全管理
  security: {
    getOverview: () => apiClient.get('/security/overview'),
    getAlerts: () => apiClient.get('/security/alerts'),
    queryAuditLogs: (params) => apiClient.get('/security/audit-logs', { params }),
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
    // 管理员重置用户两步验证（账户救济：清除 TOTP/恢复码并强制下线）
    resetUserMfa: (userId) => apiClient.put(`/security/users/${userId}/mfa/reset`),
    addIPEntry: (data) => apiClient.post('/security/ip-list', data),
    removeIPEntry: (id) => apiClient.delete(`/security/ip-list/${id}`),
  },
}

export { apiClient }

export default apiClient
