/**
 * 二次验证（step-up）错误码与错误码读取的**叶子模块**（零依赖）
 *
 * 为什么单独成模块：REAUTH_TICKET_ERROR_CODES 与「从错误响应体读 errorCode
 * （含 blob 解包）」此前在 utils/api.js 与 utils/reauthError.js 各有一份拷贝；
 * 而这两个模块之间存在既有的单向依赖（reauthError → api 的 resolveErrorMessage），
 * api.js 不能反向 import reauthError，两份拷贝无法就地收敛。
 * 下沉到无依赖叶子后两侧共用同一事实，票据错误码增删只改这一处。
 */

/** 「需要二次验证」的两个 401 错误码（与「登录态失效」是不同语义，绝不能混入刷新/登出链） */
export const REAUTH_TICKET_ERROR_CODES = ['REAUTH_TICKET_REQUIRED', 'REAUTH_TICKET_INVALID']

/**
 * 从错误响应体读 errorCode；导出类请求 responseType 为 blob，
 * 错误 JSON 也被包成 Blob —— 不先解包就既认不出票据 401，
 * 也看不清后端真正返回的错误码。读不到返回 ''。
 */
export const readErrorCodeFromData = async (data) => {
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
