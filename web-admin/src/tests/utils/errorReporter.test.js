/**
 * 全局错误兜底（G-1）测试
 *
 * 锁定三件事：
 * 1. 三路错误源（Vue 组件 / window 运行时与资源 / 未处理 Promise）都能被收集
 * 2. 错误持久化到 localStorage 环形缓冲，容量有上限
 * 3. 同一错误短窗重复触发只累计计数，不刷爆缓冲
 */
import { describe, test, expect, beforeEach, afterEach, beforeAll, vi } from 'vitest'
import { initErrorHandling, getLoggedErrors, clearLoggedErrors } from '@/utils/errorReporter'

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
})
