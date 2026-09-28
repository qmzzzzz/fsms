/**
 * 全局错误兜底（G-1）测试
 *
 * 锁定三件事：
 * 1. 三路错误源（Vue 组件 / window 运行时与资源 / 未处理 Promise）都能被收集
 * 2. 错误持久化到 localStorage 环形缓冲，容量有上限
 * 3. 同一错误短窗重复触发只累计计数，不刷爆缓冲
 */
import { describe, test, expect, beforeEach, afterEach, beforeAll, vi } from 'vitest'
import {
  initErrorHandling,
  getLoggedErrors,
  clearLoggedErrors,
  redactUrl,
} from '@/utils/errorReporter'

const app = { config: {} }

describe('errorReporter 全局错误兜底', () => {
  beforeAll(() => {
    initErrorHandling(app)
  })

  beforeEach(() => {
    clearLoggedErrors()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('app.config.errorHandler 被挂载：组件错误入库并持久化', () => {
    expect(typeof app.config.errorHandler).toBe('function')

    app.config.errorHandler(new Error('render boom'), null, 'render')

    const entries = getLoggedErrors()
    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({ kind: 'vue', message: 'render boom', info: 'render' })

    const persisted = JSON.parse(localStorage.getItem('fsrbac.errorLog'))
    expect(persisted).toHaveLength(1)
    expect(persisted[0].message).toBe('render boom')
  })

  test('window error 事件：运行时错误带位置信息收集', () => {
    window.dispatchEvent(
      new ErrorEvent('error', {
        message: 'script exploded',
        filename: 'a.js',
        lineno: 10,
        colno: 2,
      })
    )

    const entry = getLoggedErrors().find((e) => e.kind === 'window')
    expect(entry).toBeDefined()
    expect(entry.message).toBe('script exploded')
    expect(entry.file).toBe('a.js')
    expect(entry.line).toBe(10)
  })

  test('元素资源加载失败归类为 resource', () => {
    const img = document.createElement('img')
    img.src = 'https://example.com/missing.png'
    // 必须挂载到文档：捕获阶段监听在 window 上，未入 DOM 的元素事件不会经过 window
    document.body.appendChild(img)
    img.dispatchEvent(new Event('error'))
    img.remove()

    const entry = getLoggedErrors().find((e) => e.kind === 'resource')
    expect(entry).toBeDefined()
    expect(entry.tag).toBe('IMG')
    expect(entry.message).toContain('missing.png')
  })

  test('unhandledrejection：Promise 拒绝原因被收集', () => {
    const event = new Event('unhandledrejection')
    event.reason = new Error('promise rejected')
    window.dispatchEvent(event)

    const entry = getLoggedErrors().find((e) => e.kind === 'promise')
    expect(entry).toBeDefined()
    expect(entry.message).toBe('promise rejected')
  })

  test('同一错误短窗内重复触发只累计 count', () => {
    for (let i = 0; i < 3; i += 1) {
      window.dispatchEvent(new ErrorEvent('error', { message: 'same crash again' }))
    }

    const entries = getLoggedErrors()
    expect(entries).toHaveLength(1)
    expect(entries[0].count).toBe(3)
  })

  test('环形缓冲上限 50 条，超出后保留最新', () => {
    for (let i = 0; i < 60; i += 1) {
      window.dispatchEvent(new ErrorEvent('error', { message: `crash number ${i}` }))
    }

    const entries = getLoggedErrors()
    expect(entries).toHaveLength(50)
    expect(entries[entries.length - 1].message).toBe('crash number 59')
    expect(entries.some((e) => e.message === 'crash number 0')).toBe(false)
  })

  test('clearLoggedErrors 清空内存与本地留档', () => {
    app.config.errorHandler(new Error('to be cleared'), null, 'render')
    expect(getLoggedErrors()).toHaveLength(1)

    clearLoggedErrors()

    expect(getLoggedErrors()).toHaveLength(0)
    expect(JSON.parse(localStorage.getItem('fsrbac.errorLog'))).toHaveLength(0)
  })

  // L-11：上报 URL 不得携带明文凭据。
  // 该函数与后端 utils/helpers.js 的 redactUrlQuery 同口径（键名保留、值打码）。
  describe('redactUrl（L-11 URL 脱敏）', () => {
    test('敏感键的值被打码，非敏感键原样保留', () => {
      expect(redactUrl('/x?token=abc123&page=2')).toBe('/x?token=***&page=2')
      expect(redactUrl('/x?access_token=a&refresh_token=b')).toBe(
        '/x?access_token=***&refresh_token=***'
      )
    })

    test('下划线边界感知：不误伤 postcode / zipcode', () => {
      // 与后端同口径——短键 code 若按子串匹配会把 postcode 一并打码，
      // 损失排障信息（这是本仓库明确踩过的坑）
      expect(redactUrl('/x?postcode=100080&zipcode=200000')).toBe(
        '/x?postcode=100080&zipcode=200000'
      )
      // 但边界组合词要命中
      expect(redactUrl('/x?access_code=z')).toBe('/x?access_code=***')
    })

    test('驼峰形态同样命中（漏码修复）：accessToken/refreshToken/idToken/mfaCode', () => {
      // 旧实现先 toLowerCase 再按下划线边界匹配，'accessToken'→'accesstoken' 既非
      // 'access_token' 也不以 '_token' 结尾 → 明文令牌漏码，写进 localStorage + 扇出 Sentry。
      expect(redactUrl('/x?accessToken=A&refreshToken=B')).toBe(
        '/x?accessToken=***&refreshToken=***'
      )
      expect(redactUrl('/x?idToken=Z&mfaCode=1')).toBe('/x?idToken=***&mfaCode=***')
      // 归一化不得扩大打码面：普通业务参数保持原样
      expect(redactUrl('/x?deviceType=smoke&page=3')).toBe('/x?deviceType=smoke&page=3')
    })

    test('hash 中的敏感参数同样被打码（无 query 时也不例外）', () => {
      expect(redactUrl('/app#/cb?token=leak')).toBe('/app#/cb?token=***')
      expect(redactUrl('/app#access_token=leak')).toBe('/app#access_token=***')
    })

    test('无 query 无 hash、或入参非法时原样返回', () => {
      expect(redactUrl('/plain/path')).toBe('/plain/path')
      expect(redactUrl('')).toBe('')
      expect(redactUrl(null)).toBe(null)
      expect(redactUrl(undefined)).toBe(undefined)
    })

    test('含 = 的值里有 & 之外的字符不受影响；无值参数不抛错', () => {
      expect(redactUrl('/x?flag&token=t&url=http%3A%2F%2Fa.b')).toBe(
        '/x?flag&token=***&url=http%3A%2F%2Fa.b'
      )
    })
  })
})
