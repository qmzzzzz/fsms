/**
 * 审计详情溯源区块的「空值语义」层：把「本来就没有」与「没采集到」分开。
 *
 * 为什么需要这一层：requestHeaders/responseHeaders/responseBody 等溯源字段是
 * 2026-11-03（哈希载荷 v6）才加入模型的，留存期（180 天）内的老记录里这些字段
 * 物理上不存在；而事件型记录（登录成败/MFA/蜜罐/封禁）由业务逻辑在响应发送前
 * 直接登记，本就没有响应侧追溯。两者在旧渲染里统统是一个裸 "-"，客户无法
 * 区分「这条请求确实没有查询参数」和「这条记录存的时候就没这个字段」。
 *
 * 三种「无值」必须说人话，且不能用回填来掩盖：审计记录 append-only、受哈希链
 * 保护，老记录无法补写（补写等于篡改证据），所以只能在展示层如实解释。
 *
 * 状态判据（优先级从高到低）：
 *   1. 空对象 / 空串      —— 采集到了，但请求本来就没有这一项；
 *   2. body === null      —— GET 审计约定不记请求体（采集侧显式落 null）；
 *   3. undefined 且 v6+   —— 事件型记录，响应尚未发送即已登记，响应溯源不可得；
 *   4. undefined 且 <v6   —— 老记录：字段在采集上线前不存在，且不可回填。
 *
 * 本模块只管「怎么说」，不碰落库内容与接口返回面（OpenAPI 零漂移）。
 */

/** 逐字段的「本来就没有」文案 key（采集到空值时的解释各不相同）。 */
export const EMPTY_KEYS = {
  query: 'auditLog.traceEmptyQuery',
  params: 'auditLog.traceEmptyParams',
  body: 'auditLog.traceEmptyBody',
  requestHeaders: 'auditLog.traceEmptyRequestHeaders',
  responseHeaders: 'auditLog.traceEmptyResponseHeaders',
  responseBody: 'auditLog.traceEmptyResponseBody',
}

/** 溯源字段名（供调用方与测试共用，避免各处手写字符串漂移）。 */
export const TRACE_FIELDS = Object.keys(EMPTY_KEYS)

/** 是否为「空值」：undefined / null / 空串 / 空对象（数组不算空——空数组本身就是结论）。 */
export const isEmptyTrace = (value) => {
  if (value === undefined || value === null || value === '') return true
  if (typeof value === 'object' && !Array.isArray(value)) return Object.keys(value).length === 0
  return false
}

/** 值渲染：保留旧 formatTraceValue 的兼容口径（字符串原样、对象 JSON、其余 stringify）。 */
export const formatTraceValue = (value) => {
  if (isEmptyTrace(value)) return '-'
  if (typeof value === 'string') return value
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value, null, 2)
    } catch (_) {
      return String(value)
    }
  }
  return String(value)
}

/** 有值才返回文本，空值返回空串——由模板决定是否配提示行。 */
export const traceValueText = (value) => (isEmptyTrace(value) ? '' : formatTraceValue(value))

/** 记录的哈希版本：老记录可能没有该字段（等于没版本），一律当作老记录。 */
export const hashVersionOf = (record) => {
  const raw = record && record.hashVersion
  const n = Number(raw)
  return Number.isFinite(n) ? n : null
}

/**
 * 四态提示：返回 i18n key，由模板 $t 渲染。
 * @param {object} record 详情记录（需要 hashVersion 与 method）
 * @param {string} field 溯源字段名
 * @returns {string} i18n key
 */
export const traceEmptyHint = (record, field) => {
  const value = record ? record[field] : undefined
  if (value === null && field === 'body') return 'auditLog.traceGetNoBody'
  if (value !== undefined) return EMPTY_KEYS[field] || 'auditLog.traceEmptyGeneric'
  const version = hashVersionOf(record)
  if (version !== null && version >= 6) return 'auditLog.traceEventNoTrace'
  return 'auditLog.traceLegacyNotCollected'
}

/**
 * 状态码的「人话」：映射表在 locales 的 auditLog.httpStatus 下，未登记就只显示数字。
 * @param {number|string|null|undefined} statusCode
 * @returns {string} 如 "httpStatus.304" 或空串
 */
export const httpStatusKey = (statusCode) => {
  if (statusCode === null || statusCode === undefined || statusCode === '') return ''
  return 'auditLog.httpStatus.' + String(statusCode)
}
