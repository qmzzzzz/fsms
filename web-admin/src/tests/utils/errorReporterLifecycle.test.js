/**
 * F-03 生命周期与体积上限：本地错误缓冲不能只按条数滚动
 *
 * 由来：errorReporter 原实现只在 push 时按 MAX_STORED=50 裁剪，
 *   · 没有任何时间维度的过期 —— 一条上周带 `?token=` 的 URL 会一直躺在
 *     localStorage 里，直到被 50 条新错误挤掉，泄露窗口与排障价值完全脱钩；
 *   · 没有整份缓冲的体积上限 —— message(500) + stack(2000) 各自截断，
 *     50 条叠加仍可能吃满配额，而配额满时 persist 是静默失败的
 *     （表现是"一条都留不下"，不是"少留几条"）。
 * 源码注释里"不会被清理（缓冲按条数滚动，不按时间过期）"是自陈的缺口，
 * 本文件把 MAX_ENTRY_AGE_MS / MAX_STORED_BYTES 两道闸钉住。
 *
 * 手法同 errorReporterBufferEdges：每个用例 vi.resetModules() + 动态 import
 * （模块级缓冲是单例状态），并拦下 window.addEventListener 只保留本实例的
 * pagehide 处理器。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('@sentry/vue', () => ({
  init: vi.fn(),
  captureException: vi.fn(),
  captureMessage: vi.fn(),
}))

const STORAGE_KEY = 'fsrbac.errorLog'
/** 与源码 MAX_STORED_BYTES 同值；写成字面量是为了"改小预算不自动放宽断言" */
const MAX_STORED_BYTES = 128 * 1024
const DAY_MS = 24 * 60 * 60 * 1000

const setup = async () => {
  vi.stubEnv('VITE_ERROR_REPORT_URL', '')
  vi.stubEnv('VITE_SENTRY_DSN', '')
  vi.resetModules()
  const originalAdd = window.addEventListener.bind(window)
  vi.spyOn(window, 'addEventListener').mockImplementation((type, handler, options) => {
    // 只丢弃 pagehide：本文件不测 flush，留着会与其它用例的计数互相干扰
    if (type === 'pagehide') return
    originalAdd(type, handler, options)
  })
  const mod = await import('@/utils/errorReporter')
  const app = { config: {} }
  mod.initErrorHandling(app)
  return { mod, app }
}

const entry = (overrides = {}) => ({
  t: new Date().toISOString(),
  kind: 'window',
  message: 'seeded',
  stack: '',
  url: 'http://localhost/',
  count: 1,
  ...overrides,
})

describe('F-03：错误缓冲的生命周期与体积上限', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  test('超过 7 天的历史条目在加载时被淘汰，未过期的保留', async () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify([
        entry({ t: new Date(Date.now() - 8 * DAY_MS).toISOString(), message: 'expired' }),
        entry({ t: new Date(Date.now() - 6 * DAY_MS).toISOString(), message: 'kept' }),
      ])
    )

    const { mod } = await setup()

    expect(mod.getLoggedErrors().map((e) => e.message)).toEqual(['kept'])
  })

  test('时间戳不可解析的历史条目不被时间淘汰（读不懂时间 ≠ 证据该删）', async () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify([
        entry({ t: 'not-a-date', message: 'legacy' }),
        entry({ t: new Date(Date.now() - 30 * DAY_MS).toISOString(), message: 'expired' }),
      ])
    )

    const { mod } = await setup()

    expect(mod.getLoggedErrors().map((e) => e.message)).toEqual(['legacy'])
  })

  test('落盘再读回时 stack 仍按 2000 字符上限保留（不被消息上限二次截断）', async () => {
    // 回归：加载路径的 sanitizeValue 曾对**所有**字符串套 MAX_MESSAGE_LEN(500)，
    // 于是 record 阶段按 2000 截断并落盘的 stack，刷新后只剩 500 ——
    // 同一份留档在刷新前后内容不同，排障时对不上号。
    const longStack = 'S'.repeat(2000)
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify([entry({ message: 'boom', stack: longStack })])
    )

    const { mod } = await setup()

    expect(mod.getLoggedErrors()[0].stack).toBe(longStack)
  })

  test('整份缓冲超过体积预算时从最旧开始丢，落盘体积回到预算内且最新一条保留', async () => {
    // 每条都顶到各字段上限（message 500 / stack 2000 / 12 个 500 字符的 extra）：
    // 清洗后单条约 7KB，50 条 ≈ 350KB，稳定超过 128KB 预算。
    // 注意不能只靠 stack 撑体积——加载时每个字符串都按各自上限截断，
    // 单条 stack 2000 的旧写法清洗后只剩 500，量级会掉到预算以内（本轮实测踩过）。
    const bigExtra = Object.fromEntries(
      Array.from({ length: 12 }, (_, i) => [`k${i}`, String(i).padEnd(500, 'x')])
    )
    const seeded = Array.from({ length: 50 }, (_, i) =>
      entry({
        t: new Date(Date.now() - (50 - i) * 60 * 1000).toISOString(),
        message: `seed-${i}`.padEnd(500, 'm'),
        stack: 's'.repeat(2000),
        ...bigExtra,
      })
    )
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seeded))
    expect(JSON.stringify(seeded).length).toBeGreaterThan(MAX_STORED_BYTES)

    const { mod, app } = await setup()
    app.config.errorHandler(new Error('after-prune'), null, 'render')

    const persisted = localStorage.getItem(STORAGE_KEY)
    expect(persisted.length).toBeLessThanOrEqual(MAX_STORED_BYTES)

    const entries = JSON.parse(persisted)
    expect(entries.length).toBeLessThan(50)
    // 最新现场必须留下：把"刚出错"和"上周旧账"一起裁掉等于毁掉排障能力
    expect(entries[entries.length - 1].message).toContain('after-prune')
    // 被丢的是最旧的一批
    expect(entries.some((e) => e.message.startsWith('seed-0'))).toBe(false)
    expect(mod.getLoggedErrors().length).toBe(entries.length)
  })
})
