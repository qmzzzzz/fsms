/**
 * routePrefetch 行为与契约测试
 *
 * 本文件取代 2026-10-09 复核（第 34 轮 §1.1）点名的"三条 expect(true).toBe(true)
 * 空断言"状态。那三条断言不验证任何行为：把 prefetchers 的键 '/dashboard'
 * 改成 '/dashboard-TYPO'，本套件与 routeTable.test.js 共 11 例全绿（实测），
 * 即守护为零。
 *
 * 现在钉住的三类真实退化：
 *  1. 行为：首次悬停触发预取、重复悬停短路、触摸设备不预取、未知路径静默跳过、
 *     matchMedia 缺失时安全降级、预取失败后允许重试（catch 分支，此前零覆盖）；
 *  2. 键对账：prefetchers 的每个键都对应真实路由（侧边栏路由），且无多余键
 *     （键写歪 = 悬停永远不预取，用户感知不到任何异常）；
 *  3. import 字面量对账：每个 prefetcher 的动态 import 必须与该路由在
 *     router/index.js 里的懒加载工厂解析到同一模块——Vite 按 import 目标分
 *     chunk，字面量漂移会产出两份重复模块（正是源码注释警告的那件事）。
 *
 * 实现要点：不真实加载 .vue（jsdom 下无意义且慢），用 vi.spyOn 替身记录调用；
 * 字面量对账走工厂函数源码（两侧经同一套 SSR 变换，字面量形态一致）。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// 必须在 import 被测模块前 stub matchMedia —— canHover 每次调用时才读，
// 但 import 本身的顶层代码不依赖 matchMedia，所以先 stub 再 import 即可
vi.stubGlobal('matchMedia', vi.fn())

const { prefetchRoute, __prefetchers } = await import('@/utils/routePrefetch')
const router = (await import('@/router')).default

const mockMatchMedia = (matches) => {
  window.matchMedia.mockReturnValue({ matches, media: '', addEventListener: vi.fn() })
}

/** 取动态 import 的字面量（vitest SSR 变换后是 __vite_ssr_dynamic_import__("...")，浏览器构建里是 import("...")） */
const importLiteral = (fn) => {
  const src = String(fn)
  const m = src.match(/(?:__vite_ssr_dynamic_import__|\bimport)\(\s*(['"])([^'"]+)\1\s*\)/)
  return m ? m[2] : null
}

describe('routePrefetch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockMatchMedia(true)
  })

  afterEach(() => {
    // 必须 restore 而非 clear：spyOn 的替身若留在 __prefetchers 上，
    // 后面的字面量对账读到的会是 spy 包装函数的源码
    vi.restoreAllMocks()
  })

  it('可悬停设备：首次调用触发预取，重复调用短路', async () => {
    const spy = vi.spyOn(__prefetchers, '/dashboard').mockResolvedValue({})

    prefetchRoute('/dashboard')
    prefetchRoute('/dashboard')
    prefetchRoute('/dashboard')
    await Promise.resolve()

    // 键命中且真的被调用过一次；后两次被 prefetched 集合短路
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('触摸设备（hover: none）：不预取', () => {
    mockMatchMedia(false)
    const spy = vi.spyOn(__prefetchers, '/alarms').mockResolvedValue({})

    prefetchRoute('/alarms')

    // 移动端无悬停概念：预取会在 tap 瞬间抢带宽，反而拖慢点击导航
    expect(spy).not.toHaveBeenCalled()
  })

  it('未知路径：静默跳过，且不污染后续预取状态', async () => {
    const spy = vi.spyOn(__prefetchers, '/inspections').mockResolvedValue({})

    expect(() => {
      prefetchRoute('/nonexistent')
      prefetchRoute('')
      prefetchRoute(null)
      prefetchRoute(undefined)
    }).not.toThrow()

    // 未知路径在登记前就 return，未写入 prefetched 集合；
    // 紧接着的合法路径必须照常预取（证明状态没被弄坏）
    prefetchRoute('/inspections')
    await Promise.resolve()
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('window.matchMedia 不存在时安全降级', () => {
    const spy = vi.spyOn(__prefetchers, '/users').mockResolvedValue({})
    const original = window.matchMedia
    window.matchMedia = undefined

    expect(() => prefetchRoute('/users')).not.toThrow()
    // 探测不到 hover 能力时整体禁用，而不是抛错把导航链路带下去
    expect(spy).not.toHaveBeenCalled()

    window.matchMedia = original
  })

  it('预取失败后从集合移除：下次悬停允许重试', async () => {
    // 网络抖动时 load() reject：catch 分支把键移出 prefetched，
    // 否则一次失败之后该路由永远不再预取（用户感知不到，只会觉得"悬停没反应"）
    const spy = vi
      .spyOn(__prefetchers, '/roles')
      .mockRejectedValueOnce(new Error('chunk 加载失败'))
      .mockResolvedValueOnce({})

    prefetchRoute('/roles')
    await Promise.resolve()
    await Promise.resolve()
    expect(spy).toHaveBeenCalledTimes(1)

    prefetchRoute('/roles')
    await Promise.resolve()
    expect(spy).toHaveBeenCalledTimes(2)
  })
})

describe('routePrefetch 与路由表的对账（第 34 轮 §1.1 建议的守护）', () => {
  const routes = router.getRoutes()
  // 侧边栏路由 = 布局子路由，判据取 meta.titleKey（login/register 无此字段）
  const sidebarRoutes = routes.filter((record) => record.meta && record.meta.titleKey)
  const keys = Object.keys(__prefetchers)

  it('每个侧边栏路由都有预取键，且没有指向不存在路由的多余键', () => {
    expect(sidebarRoutes.length).toBeGreaterThan(0)

    for (const record of sidebarRoutes) {
      expect(keys, `路由 ${record.path} 缺少预取键（悬停不会预热 chunk）`).toContain(record.path)
    }
    for (const key of keys) {
      const matched = sidebarRoutes.find((record) => record.path === key)
      expect(matched, `预取键 ${key} 不对应任何侧边栏路由（键已过期）`).toBeTruthy()
    }
  })

  it('每个 prefetcher 的 import 与对应路由的懒加载工厂解析到同一模块', () => {
    // Vite 按 import 目标分 chunk：prefetchers 与 router/index.js 只要不是
    // 同一个模块，就会产出两份重复模块——这正是源码注释警告的退化。
    for (const record of sidebarRoutes) {
      const prefetcher = __prefetchers[record.path]
      expect(typeof prefetcher, `${record.path} 的预取项不是函数`).toBe('function')
      const prefetchLiteral = importLiteral(prefetcher)
      const routeLiteral = importLiteral(record.components.default)
      expect(prefetchLiteral, `${record.path} 的 prefetcher 不是动态 import`).toBeTruthy()
      expect(
        prefetchLiteral,
        `${record.path} 的预取 import 与路由表不一致（会产生重复 chunk）`
      ).toBe(routeLiteral)
    }
  })
})
