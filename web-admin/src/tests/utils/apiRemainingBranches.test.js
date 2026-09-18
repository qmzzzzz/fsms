/**
 * api.js 剩余分支补测：原型链键污染防护 + 响应缺失 config 字段时的守卫分支
 *
 * 与既有测试的分工（不重复已覆盖内容）：
 *  - apiRequestPipeline.test.js → 401 刷新链、状态码归一、取消机制、形状校验主路径
 *  - apiStatusCodes.test.js     → 405/409/413/415/431/500/503 码化与兜底
 *  - apiDriftLru.test.js        → 漂移去重 / LRU 淘汰
 *  - errorCodeI18n.test.js      → 映射与 locale 文案对齐
 *
 * 本文件只补上述未覆盖的：
 *  1. resolveErrorMessage 的原型链键防护（真实缺陷回归，见下方缺陷说明）；
 *  2. 响应拦截器在「响应 config 字段缺失」时的守卫分支
 *     （api.js:440 的空串回退、api.js:457 的默认 method、api.js:488 的清理守卫）。
 *
 * 驱动方式与 apiRequestPipeline 一致：真实 apiClient + 自定义 adapter 走真实拦截器；
 * 逐用例 vi.resetModules() 取干净模块实例（api.js 有模块级单例：pendingControllers /
 * reportedDrifts / isRefreshing）。
 *
 * 缺陷说明（本文件前 3 条用例的回归目标）：
 *  errorCode 来自后端响应体，属外部输入。原实现裸查表 `ERROR_CODE_I18N_MAP[errorCode]`，
 *  当 errorCode 取 'toString'/'constructor'/'valueOf' 等原型链键时，会沿原型链取到
 *  Object.prototype 上的函数（truthy），resolveErrorMessage 因此返回函数而非约定的 null；
 *  调用方的 `resolveErrorMessage(data) || data?.message || t(...)` 兜底链被短路，
 *  ElMessage 收到并渲染出「function toString() { [native code] }」。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { AxiosError } from 'axios'

const msg = vi.hoisted(() => ({
  error: vi.fn(),
  warning: vi.fn(),
  success: vi.fn(),
  info: vi.fn(),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({ ElMessage: msg }))
vi.mock('@/utils/loginCipher', () => ({ invalidatePublicKeyCache: vi.fn() }))

let consoleErrorSpy

beforeEach(() => {
  vi.clearAllMocks()
  // 漂移告警走 console.error；静音输出，断言用 consoleErrorSpy.mock.calls
  consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
})

/** 取干净模块图（api.js 的模块级单例必须逐用例隔离） */
const loadAll = async () => {
  vi.resetModules()
  const apiMod = await import('@/utils/api')
  const i18n = (await import('@/i18n')).default
  // 固定英文：兜底文案若被硬编码中文，断言会红
  i18n.global.locale.value = 'en-US'
  return { ...apiMod, i18n }
}

/** 构造带 response 的 axios 错误（走 error.response 分支） */
const httpError = (config, status, data) =>
  new AxiosError(
    `Request failed with status code ${status}`,
    AxiosError.ERR_BAD_REQUEST,
    config,
    null,
    { status, data, statusText: String(status), headers: {}, config }
  )

/** 形状漂移日志（verifyResponseShape 的 console.error 输出） */
const driftLogs = () =>
  consoleErrorSpy.mock.calls.filter((a) => String(a[0]).includes('[schema-drift]'))

/** adapter 自造响应：config 用给定对象（模拟适配器未回填请求 config 的响应形态） */
const respondWithConfig = (apiClient, config, data) => {
  apiClient.defaults.adapter = () =>
    Promise.resolve({ data, status: 200, statusText: 'OK', headers: {}, config })
}

describe('resolveErrorMessage：原型链键污染防护', () => {
  test("原型链键（'toString'/'constructor'/'valueOf'）返回 null，不得取到 Object.prototype 的函数", async () => {
    // 防退化：改回裸查表 ERROR_CODE_I18N_MAP[errorCode] → 命中 Object.prototype 上的函数
    // （truthy），返回函数而非 null → 调用方兜底链被短路
    const { resolveErrorMessage } = await loadAll()
    for (const code of ['toString', 'constructor', 'valueOf', 'hasOwnProperty']) {
      expect(resolveErrorMessage({ errors: { errorCode: code } }), `errorCode=${code}`).toBeNull()
    }
  })

  test('对照：自有属性键仍正常命中（防修复过度收紧成恒 null）', async () => {
    // 防退化：把守卫「修」成一律返回 null / 恒假 → 已收录错误码全部漏翻
    const { resolveErrorMessage, i18n } = await loadAll()
    const out = resolveErrorMessage({ errors: { errorCode: 'AUTH_INVALID_CREDENTIALS' } })
    expect(out).not.toBeNull()
    expect(out).toBe(i18n.global.t('errors.authInvalidCredentials'))
  })

  test('400 响应携带原型链键 errorCode：走后端 message 回退，而非渲染函数源码', async () => {
    // 修复前本用例失败：ElMessage.warning 收到的是函数对象（渲染成
    // 「function toString() { [native code] }」）而非 BACKEND-RAW
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(
        httpError(config, 400, { errors: { errorCode: 'toString' }, message: 'BACKEND-RAW' })
      )
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning).toHaveBeenCalledTimes(1)
    expect(msg.warning.mock.calls[0][0]).toBe('BACKEND-RAW')
  })

  test('400 响应携带原型链键且无 message：回退到本地化 requestParamError', async () => {
    // 修复前本用例失败：兜底链被 truthy 函数短路，永远到不了 t('messages.requestParamError')
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 400, { errors: { errorCode: 'valueOf' } }))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning).toHaveBeenCalledTimes(1)
    expect(msg.warning.mock.calls[0][0]).toBe(i18n.global.t('messages.requestParamError'))
  })
})

describe('响应拦截器：响应缺失 config 字段时的守卫分支', () => {
  test('api.js:440 —— 响应 config 无 url：漂移键的 URL 段为空串，不渲染成 undefined', async () => {
    // 防退化：去掉 `|| ''` → url 变 'undefined'，日志与漂移去重键被污染
    const { apiClient } = await loadAll()
    respondWithConfig(apiClient, { method: 'get' }, { success: 'not-a-boolean' })
    await apiClient.get('/whatever')
    expect(driftLogs()).toHaveLength(1)
    const log = String(driftLogs()[0][0])
    expect(log).toContain('[schema-drift]  -> ')
    expect(log).toContain('success')
  })

  test('api.js:457 —— 响应 config 无 method：/auth/session 仍按 GET 命中专用 schema', async () => {
    // 防退化：去掉 `|| 'get'` → method 变 'undefined' ≠ 'get' → 专用 schema 不命中，
    // 会话探测响应（authenticated 非布尔）不再告警
    const { apiClient, i18n } = await loadAll()
    respondWithConfig(
      apiClient,
      { url: '/auth/session' },
      { success: true, data: { authenticated: 'not-a-boolean' } }
    )
    await apiClient.get('/auth/session')
    expect(driftLogs()).toHaveLength(1)
    const log = String(driftLogs()[0][0])
    expect(log).toContain('/auth/session')
    expect(log).toContain('authenticated')
    // 命中专用 schema → 关键路径，须打扰用户
    expect(msg.warning).toHaveBeenCalledTimes(1)
    expect(msg.warning.mock.calls[0][0]).toBe(i18n.global.t('messages.schemaDrift'))
  })

  test('api.js:488 —— 响应对象没有 config 字段：清理守卫不得抛错，请求原样返回', async () => {
    // 防退化：去掉可选链 `response.config?.__reqKey` → TypeError 打断响应拦截器，
    // 所有「适配器未回填 config」的响应全部 reject（而非原样返回）
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = () =>
      Promise.resolve({ data: { success: true }, status: 200, statusText: 'OK', headers: {} })
    const r = await apiClient.get('/devices')
    expect(r.status).toBe(200)
    expect(r.data).toEqual({ success: true })
  })
})

/*
 * ================== 恒未覆盖分支的判据（不为覆盖率造断言） ==================
 *
 * 以下 4 个分支槽在 v8 覆盖率里恒为未覆盖，经探针实测定性为「不可达防御分支」，
 * 故不为其编写断言（判据均可独立复现）：
 *
 *  api.js:254 `const params = data?.errors || {}` 的 `{}` 分支：
 *    进入该行的前提是 api.js:252 命中自有键，而命中即意味着 data.errors.errorCode 存在
 *    （api.js:247 自 data.errors 取值），故 data.errors 必为 truthy → `|| {}` 右支不可达。
 *
 *  api.js:351 `entry?.controller || entry` 的 `entry` 分支、
 *  api.js:352 `entry?.method || 'get'` 的 `'get'` 分支：
 *    pendingControllers 的唯一写入点是 api.js:376 `set(reqKey, { controller, method })`
 *    （全仓 grep 该 Map 仅 api.js 自身读写），entry 恒为含 controller/method 的对象字面量，
 *    且 method 经 api.js:372 `String(config.method || 'get').toLowerCase()` 归一化后恒为非空
 *    字符串 → 「早期形态 entry」兼容分支在本仓库没有写入者，不可达。
 *
 *  api.js:372 `String(config.method || 'get')` 的 `'get'` 分支：
 *    axios 在进入请求拦截器之前就完成 method 归一化——
 *    node_modules/axios/lib/core/Axios.js:147
 *    `config.method = (config.method || this.defaults.method || 'get').toLowerCase();`
 *    早于 api.js:367 注册的请求拦截器（拦截器链在 Axios.js:160-178 才组装），
 *    实测拦截器内 config.method 恒为小写字符串（'get'/'post'/…），故右支不可达。
 */
