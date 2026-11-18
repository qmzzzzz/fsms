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
 *  4. 状态码集合与后端注册表一致（新增码若引入新状态码，这里会红）；
 *  5. 认证入口按路径段精确匹配（/auth/login-public-key 不被 /auth/login 前缀误伤）。
 *
 * 隔离口径对齐 api 系列其他文件（apiRequestPipeline 等）：每个用例 vi.resetModules()
 * 后动态 import 取干净模块实例——api.js 有多处模块级单例（isRefreshing /
 * refreshPromise / _isHandling401 / reportedDrifts），不隔离会跨用例串味；
 * 走完 401 登出链的用例必须在断言前排干异步链（动态 import store + router.push），
 * 否则链路尾部会漏进下一个用例。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { ERROR_CODES } = require('../../../../src/utils/errorCodes.js')

// vi.hoisted：让 mock 工厂每次被调用都返回**同一组** spy——resetModules 后重新
// import 的 api.js 与本文件引用的 ElMessage 才是同一个对象，断言不会落空
const msg = vi.hoisted(() => ({
  error: vi.fn(),
  warning: vi.fn(),
  success: vi.fn(),
  info: vi.fn(),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({ ElMessage: msg }))

/** 取干净模块图（api.js 的模块级单例必须逐用例隔离） */
const loadAll = async () => {
  vi.resetModules()
  const apiMod = await import('@/utils/api')
  const i18n = (await import('@/i18n')).default
  const router = (await import('@/router')).default
  const axios = (await import('axios')).default
  // 固定英文：断言用 i18n.global.t(key) 动态比对，兜底文案若被写死中文此处即红
  i18n.global.locale.value = 'en-US'
  return { ...apiMod, i18n, router, axios }
}

/** 排干微任务/宏任务：401 登出链（动态 import store + router.push）要落到终态 */
const flush = async (rounds = 8) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((r) => setTimeout(r, 0))
}

/** 让下一次 apiClient 请求以指定状态码与响应体失败；排干异步链后返回被拒的错误 */
const respondWith = async (apiClient, status, data, url = '/__probe__') => {
  // config 必须带真实 url：认证入口判定（isAuthEntryPointPath）读的是 config.url，
  // 缺了它 401 豁免分支永远不命中，与真实 AxiosError 的行为不符
  apiClient.defaults.adapter = () => Promise.reject({ response: { status, data, config: { url } } })
  const err = await apiClient.get(url).catch((e) => e)
  await flush()
  return err
}

const lastCall = (fn) => fn.mock.calls.at(-1)?.[0]

describe('拦截器状态码覆盖（P1-15）', () => {
  let apiClient
  let i18n
  let axios
  let router

  beforeEach(async () => {
    vi.clearAllMocks()
    ;({ apiClient, i18n, axios, router } = await loadAll())
  })

  afterEach(() => {
    delete apiClient.defaults.adapter
    vi.restoreAllMocks()
  })

  test('409：并发冲突走 warning，文案来自码化通道', async () => {
    await respondWith(apiClient, 409, { errors: { errorCode: 'ALARM_ALREADY_HANDLED' } })
    expect(msg.warning).toHaveBeenCalledTimes(1)
    expect(msg.error).not.toHaveBeenCalled()
    expect(lastCall(msg.warning)).toBe(i18n.global.t('errors.alarmAlreadyHandled'))
  })

  test('409 携带 currentStatus：动态状态并入码化文案（中英都带），不回显后端原文', async () => {
    for (const locale of ['zh-CN', 'en-US']) {
      vi.clearAllMocks()
      i18n.global.locale.value = locale
      await respondWith(apiClient, 409, {
        errors: { errorCode: 'PRIVILEGE_GRANT_NOT_ACTIVE', currentStatus: 'expired' },
        message: '该授权当前状态不可撤销（当前：expired）',
      })
      const text = lastCall(msg.warning)
      expect(text, locale).toContain('expired')
      expect(text, locale).not.toContain('该授权当前状态不可撤销')
      expect(text, locale).toBe(
        i18n.global.t('errors.privilegeGrantNotActive', { currentStatus: 'expired' })
      )
    }
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
      await respondWith(apiClient, status, { errors: { errorCode: code }, message: 'BACKEND-RAW' })
      expect(msg.error, `status ${status}`).toHaveBeenCalledTimes(1)
      expect(lastCall(msg.error), `status ${status}`).toBe(i18n.global.t(key))
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
      await respondWith(apiClient, status, { errors: { errorCode: 'FUTURE_CODE_NOT_MAPPED' } })
      const fn = level === 'warning' ? msg.warning : msg.error
      const text = lastCall(fn)
      expect(text, `status ${status}`).toBe(i18n.global.t(key))
      expect(text, `status ${status}`).not.toContain('messages.')
    }
  })

  test('500 与 503 同口径：先走 resolveErrorMessage 码化翻译', async () => {
    await respondWith(apiClient, 500, {
      errors: { errorCode: 'INTERNAL_ERROR' },
      message: 'BACKEND-RAW',
    })
    expect(lastCall(msg.error)).toBe(i18n.global.t('errors.internalError'))

    vi.clearAllMocks()
    await respondWith(apiClient, 503, {
      errors: { errorCode: 'CAPTCHA_SERVICE_UNAVAILABLE' },
      message: 'BACKEND-RAW',
    })
    expect(lastCall(msg.error)).toBe(i18n.global.t('errors.captchaServiceUnavailable'))
  })

  test('票据 401（REAUTH_TICKET_REQUIRED）：不得触发刷新链或强制登出', async () => {
    // P2-28：刷新链走裸 axios.post（api.js doRefreshToken 刻意绕开 apiClient
    // 拦截器），spy 打在 apiClient.post 上盯错对象——豁免分支被删也恒绿。
    // 这里直接盯 axios.post：豁免分支一旦失效，doRefreshToken 会立刻命中本 spy。
    const refreshSpy = vi.spyOn(axios, 'post')
    await respondWith(apiClient, 401, { errors: { errorCode: 'REAUTH_TICKET_REQUIRED' } })
    // 票据缺失只是「需要二次验证」：不提示、不刷新、不跳登录；由页面弹框取票
    expect(msg.error).not.toHaveBeenCalled()
    expect(msg.warning).not.toHaveBeenCalled()
    expect(refreshSpy).not.toHaveBeenCalled()
  })

  test('票据 401（blob 错误体）也能识别，不因 responseType=blob 误判成会话失效', async () => {
    const blob = new Blob([JSON.stringify({ errors: { errorCode: 'REAUTH_TICKET_INVALID' } })], {
      type: 'application/json',
    })
    const refreshSpy = vi.spyOn(axios, 'post')
    await respondWith(apiClient, 401, blob)
    expect(msg.error).not.toHaveBeenCalled()
    expect(refreshSpy).not.toHaveBeenCalled()
  })

  test('认证入口按路径段精确匹配：/auth/login-public-key 不被 /auth/login 前缀误伤', async () => {
    // 防退化：裸 includes 会把 /auth/login-public-key 误判成认证入口（前缀命中）。
    // 该接口是免鉴权的公钥下发，其 401（如网关误配/部署漂移）应走「令牌过期」语义
    // 的刷新链，而不是被当成「凭据错误」直接弹登录失败。
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    const refreshSpy = vi
      .spyOn(axios, 'post')
      .mockRejectedValue({ response: { status: 401, data: {} } })
    await respondWith(
      apiClient,
      401,
      { errors: { errorCode: 'AUTH_INVALID_CREDENTIALS' } },
      '/auth/login-public-key'
    )
    // 未被豁免 → 走了刷新链；刷新被明确拒绝 → 登出链收尾
    expect(refreshSpy).toHaveBeenCalledTimes(1)
    expect(String(refreshSpy.mock.calls[0][0])).toContain('/auth/refresh')
    expect(pushSpy).toHaveBeenCalledTimes(1)

    // 对照：真正的认证入口 /auth/login 仍被豁免（401 不触发刷新，直接提示凭据错误）
    vi.clearAllMocks()
    const loginPushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    const loginRefreshSpy = vi.spyOn(axios, 'post')
    await respondWith(
      apiClient,
      401,
      { errors: { errorCode: 'AUTH_INVALID_CREDENTIALS' } },
      '/auth/login'
    )
    expect(loginRefreshSpy).not.toHaveBeenCalled()
    expect(loginPushSpy).not.toHaveBeenCalled()
    expect(msg.error).toHaveBeenCalledTimes(1)
  })

  test('有牙对照：普通 401 确实会经裸 axios.post 走刷新链（证明上述 not.called 盯对了对象）', async () => {
    // 非票据 401 → doRefreshToken → 裸 axios.post('/auth/refresh')；刷新被明确
    // 拒绝（401）→ forceSessionReset。本用例证明 spy 能看到真实刷新链——
    // 于是上面「票据 401 不触发刷新」的断言才不是恒真。
    vi.spyOn(router, 'push').mockResolvedValue()
    const refreshSpy = vi
      .spyOn(axios, 'post')
      .mockRejectedValue({ response: { status: 401, data: {} } })
    await respondWith(apiClient, 401, { errors: { errorCode: 'SESSION_EXPIRED' } })
    expect(refreshSpy).toHaveBeenCalledTimes(1)
    expect(String(refreshSpy.mock.calls[0][0])).toContain('/auth/refresh')
    // 刷新被明确拒绝 → 会话判死 → 强制登出提示
    expect(msg.error).toHaveBeenCalledTimes(1)
  })

  test('状态码集合与后端注册表一致（新增码引入新状态码时本测试会红）', () => {
    const statuses = [...new Set(Object.values(ERROR_CODES).map((d) => d.status))].sort(
      (a, b) => a - b
    )
    expect(statuses).toEqual([400, 401, 403, 404, 405, 409, 413, 415, 429, 431, 500, 503])
  })
})
