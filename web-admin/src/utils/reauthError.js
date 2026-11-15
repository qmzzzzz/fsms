import { resolveErrorMessage } from '@/utils/api'

/**
 * 二次验证（step-up）与 blob 错误体解包的共享工具（P3-15 收敛）
 *
 * 此前 REAUTH_TICKET_ERROR_CODES / readReauthErrorCode / blob 错误文案提取
 * 在 AttackAlertsView / AttackProfileView / AuditLogView / StuffingProfileView /
 * ReportView 各有一份拷贝；导出类请求 responseType 为 blob，错误 JSON 也被
 * 包成 Blob，不解包就认不出票据 401、也拿不到真正的错误码。
 */

export const REAUTH_TICKET_ERROR_CODES = ['REAUTH_TICKET_REQUIRED', 'REAUTH_TICKET_INVALID']

/** Blob → 解析后的 JSON 对象；非 Blob 或解析失败返回 null */
export const readBlobJson = async (data) => {
  if (typeof Blob === 'undefined' || !(data instanceof Blob)) return null
  try {
    return JSON.parse(await data.text())
  } catch (_) {
    return null
  }
}

/** 从错误响应体（含 blob 包裹的 JSON）里读 errorCode；读不到返回 '' */
export const readReauthErrorCode = async (e) => {
  const data = e?.response?.data
  if (data?.errors?.errorCode) return data.errors.errorCode
  const parsed = await readBlobJson(data)
  return parsed?.errors?.errorCode || ''
}

/**
 * blob 响应中的后端错误文案：优先码化翻译（api.js resolveErrorMessage），
 * 其次 message 字段，最后兜底文案。
 * @param {Blob|object|undefined} data 错误响应体
 * @param {string} fallback 兜底文案
 * @param {object} [opts]
 * @param {boolean} [opts.requireJsonMime] true 时仅当 Blob MIME 含 json 才解析
 *   （ReportView 口径）；false 时任何 Blob 都尝试解析（AuditLogView 口径）
 */
export const extractBlobErrorMessage = async (data, fallback, { requireJsonMime = false } = {}) => {
  const isBlob = typeof Blob !== 'undefined' && data instanceof Blob
  if (isBlob && (!requireJsonMime || data.type?.includes('json'))) {
    const parsed = await readBlobJson(data)
    if (parsed) return resolveErrorMessage(parsed) || parsed?.message || fallback
  }
  return data?.message || fallback
}
