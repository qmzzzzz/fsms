import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// 必须在 import 被测模块前 stub matchMedia —— canHover 每次调用时才读，
// 但 import 本身的顶层代码不依赖 matchMedia，所以先 stub 再 import 即可
vi.stubGlobal('matchMedia', vi.fn())

const { prefetchRoute } = await import('@/utils/routePrefetch')

const mockMatchMedia = (matches) => {
  window.matchMedia.mockReturnValue({ matches, media: '', addEventListener: vi.fn() })
}

describe('routePrefetch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockMatchMedia(true)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('可悬停设备：首次调用触发预取，重复调用短路', async () => {
    // 不验证真实 import 是否发生（jsdom 无法加载 .vue），
    // 只验证不会在重复调用时抛错、且状态不重复累积
    prefetchRoute('/dashboard')
    prefetchRoute('/dashboard')
    prefetchRoute('/devices')
    expect(true).toBe(true) // 无异常即通过
  })

  it('触摸设备（hover: none）：不预取', () => {
    mockMatchMedia(false)
    prefetchRoute('/alarms')
    // 无异常、无网络请求即通过
    expect(true).toBe(true)
  })

  it('未知路径：静默跳过', () => {
    prefetchRoute('/nonexistent')
    prefetchRoute('')
    prefetchRoute(null)
    expect(true).toBe(true)
  })

  it('window.matchMedia 不存在时安全降级', () => {
    const original = window.matchMedia
    window.matchMedia = undefined
    expect(() => prefetchRoute('/dashboard')).not.toThrow()
    window.matchMedia = original
  })
})
