/**
 * 响应拦截器状态码覆盖回归（P1-15）
 *
 * 缺陷回顾：switch 只处理 400/401/403/404/429/500/503，后端注册表实际会发出的
 * 405/409/413/415/431 全部落到 default 分支——default 直接回显后端中文 message，
 * 英文界面下文案串语言，且 409 这类「记录已被他人处理」的并发结果被当错误报红。
 * 另：500 分支当时是 `data?.message || t(...)`，绕过了 resolveErrorMessage 码化通道，
 * 与 503 口径不一致。
 *
 * 本套件用真实 apiClient + 自定义 adapter 驱动拦截器，断言：
 *  1. 五个新状态码各自走码化翻译（英文 locale 下不出现中文）；
 *  2. 映射缺失时退回 messages.* 兜底键，而非后端原文；
 *  3. 500 与 503 同口径；
 *  4. 状态码集合与后端注册表一致（新增码若引入新状态码，这里会红）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { ERROR_CODES } = require('../../../../src/utils/errorCodes.js')

import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { apiClient } from '@/utils/api'
import i18n from '@/i18n'

vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { error: vi.fn(), warning: vi.fn(), success: vi.fn(), info: vi.fn() },
}))

/** 让下一次 apiClient 请求以指定状态码与响应体失败，返回被拒绝的 Promise */
const respondWith = (status, data) => {
  apiClient.defaults.adapter = () => Promise.reject({ response: { status, data, config: {} } })
  return apiClient.get('/__probe__').catch((e) => e)
}

const lastCall = (fn) => fn.mock.calls.at(-1)?.[0]

describe('拦截器状态码覆盖（P1-15）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    i18n.global.locale.value = 'en-US'
  })

  afterEach(() => {
    delete apiClient.defaults.adapter
  })

  test('409：并发冲突走 warning，文案来自码化通道', async () => {
    await respondWith(409, { errors: { errorCode: 'ALARM_ALREADY_HANDLED' } })
    expect(ElMessage.warning).toHaveBeenCalledTimes(1)
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(lastCall(ElMessage.warning)).toBe(i18n.global.t('errors.alarmAlreadyHandled'))
  })

  test('405/413/415/431：各自命中映射文案，不回显后端原文', async () => {
    const cases = [
      [405, 'HTTP_METHOD_UNSUPPORTED', 'errors.httpMethodUnsupported'],
      [413, 'PAYLOAD_TOO_LARGE', 'errors.payloadTooLarge'],
      [415, 'CONTENT_TYPE_UNSUPPORTED', 'errors.contentTypeUnsupported'],
      [431, 'HEADER_VALUE_TOO_LONG', 'errors.headerValueTooLong'],
    ]
    for (const [status, code, key] of cases) {
      vi.clearAllMocks()
      await respondWith(status, { errors: { errorCode: code }, message: 'BACKEND-RAW' })
      expect(ElMessage.error, `status ${status}`).toHaveBeenCalledTimes(1)
      expect(lastCall(ElMessage.error), `status ${status}`).toBe(i18n.global.t(key))
    }
  })

  test('映射缺失时退回 messages.* 兜底键，而非后端原文', async () => {
    const cases = [
      [405, 'messages.methodNotAllowed', 'error'],
      [409, 'messages.conflict', 'warning'],
      [413, 'messages.payloadTooLarge', 'error'],
      [415, 'messages.unsupportedMediaType', 'error'],
      [431, 'messages.requestHeaderTooLarge', 'error'],
    ]
    for (const [status, key, level] of cases) {
      vi.clearAllMocks()
      await respondWith(status, { errors: { errorCode: 'FUTURE_CODE_NOT_MAPPED' } })
      const fn = level === 'warning' ? ElMessage.warning : ElMessage.error
      const msg = lastCall(fn)
      expect(msg, `status ${status}`).toBe(i18n.global.t(key))
      expect(msg, `status ${status}`).not.toContain('messages.')
    }
  })

  test('500 与 503 同口径：先走 resolveErrorMessage 码化翻译', async () => {
    await respondWith(500, { errors: { errorCode: 'INTERNAL_ERROR' }, message: 'BACKEND-RAW' })
    expect(lastCall(ElMessage.error)).toBe(i18n.global.t('errors.internalError'))

    vi.clearAllMocks()
    await respondWith(503, {
      errors: { errorCode: 'CAPTCHA_SERVICE_UNAVAILABLE' },
      message: 'BACKEND-RAW',
    })
    expect(lastCall(ElMessage.error)).toBe(i18n.global.t('errors.captchaServiceUnavailable'))
  })

  test('状态码集合与后端注册表一致（新增码引入新状态码时本测试会红）', () => {
    const statuses = [...new Set(Object.values(ERROR_CODES).map((d) => d.status))].sort(
      (a, b) => a - b
    )
    expect(statuses).toEqual([400, 401, 403, 404, 405, 409, 413, 415, 429, 431, 500, 503])
  })
})
