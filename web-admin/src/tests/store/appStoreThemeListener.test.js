/**
 * P2-59 / 审计报告 §13 V-4：initTheme 的系统主题监听器重入保护
 *
 * 缺陷回顾（修复前）：initTheme 每次调用都新建一个 matchMedia change 监听器，
 * 且从不摘除旧监听器。监听器闭包持有 store 实例，热重载或未来新增的重复初始化
 * 入口会让系统主题每切换一次就叠加一次 _applyTheme 回调（回调数量随调用次数线性增长）。
 *
 * 断言方式是统计「假 MediaQueryList」上的 add/remove 调用：
 *  - 修复后：第二次 initTheme 先摘除上一轮监听、再注册新的 → 净存活监听器恒为 1；
 *  - 若删掉 store/app.js:66-75 的摘除块，removed 计数为 0 → 本套件变红。
 *
 * 另覆盖：Safari < 14 的 addListener / removeListener 降级分支、
 * matchMedia 缺失（老浏览器/非浏览器环境）时不抛错、旧版 darkMode 的一次性迁移。
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAppStore } from '@/store'

/**
 * 假 MediaQueryList：只记录 add/remove 的调用参数，不做真实事件派发。
 * legacy=true 时模拟 Safari < 14（只有 addListener / removeListener）。
 */
const makeMq = ({ legacy = false, matches = false } = {}) => {
  const calls = { added: [], removed: [] }
  const mq = { matches, calls }
  if (legacy) {
    mq.addListener = (fn) => calls.added.push({ type: 'change', fn })
    mq.removeListener = (fn) => calls.removed.push({ type: 'change', fn })
  } else {
    mq.addEventListener = (type, fn) => calls.added.push({ type, fn })
    mq.removeEventListener = (type, fn) => calls.removed.push({ type, fn })
  }
  return mq
}

describe('useAppStore.initTheme 监听器重入保护（§13 V-4）', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    sessionStorage.clear()
    localStorage.clear()
    document.documentElement.classList.remove('dark')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  test('调用两次：第二次先摘除第一轮监听再注册，净存活恒为 1', () => {
    const mq = makeMq()
    vi.stubGlobal('matchMedia', () => mq)
    const store = useAppStore()

    store.initTheme()
    store.initTheme()

    // 两轮各注册一次
    expect(mq.calls.added).toHaveLength(2)
    // 关键断言：第二轮注册前摘除了第一轮的监听（修复前该计数为 0）
    expect(mq.calls.removed).toHaveLength(1)
    expect(mq.calls.removed[0].type).toBe('change')
    // 摘除的正是第一轮注册的那个函数引用——只有引用相同才算真正摘除
    expect(mq.calls.removed[0].fn).toBe(mq.calls.added[0].fn)
    // 每轮注册新闭包（绑定当前 store），不是复用同一个函数
    expect(mq.calls.added[1].fn).not.toBe(mq.calls.added[0].fn)
    expect(mq.calls.added.length - mq.calls.removed.length).toBe(1)
  })

  test('调用三次：每次都摘除上一轮，净存活仍为 1（线性叠加已消除）', () => {
    const mq = makeMq()
    vi.stubGlobal('matchMedia', () => mq)
    const store = useAppStore()

    store.initTheme()
    store.initTheme()
    store.initTheme()

    expect(mq.calls.added).toHaveLength(3)
    expect(mq.calls.removed).toHaveLength(2)
    expect(mq.calls.removed[0].fn).toBe(mq.calls.added[0].fn)
    expect(mq.calls.removed[1].fn).toBe(mq.calls.added[1].fn)
    expect(mq.calls.added.length - mq.calls.removed.length).toBe(1)
  })

  test('Safari < 14 降级：只有 addListener/removeListener 时同样摘除旧监听', () => {
    const mq = makeMq({ legacy: true })
    vi.stubGlobal('matchMedia', () => mq)
    const store = useAppStore()

    store.initTheme()
    store.initTheme()

    expect(mq.calls.added).toHaveLength(2)
    expect(mq.calls.removed).toHaveLength(1)
    expect(mq.calls.removed[0].fn).toBe(mq.calls.added[0].fn)
    expect(mq.calls.added.length - mq.calls.removed.length).toBe(1)
  })

  test('监听器回调真实生效：change 事件驱动 systemPrefersDark 与 html.dark', () => {
    const mq = makeMq({ matches: false })
    vi.stubGlobal('matchMedia', () => mq)
    const store = useAppStore()
    store.setThemeMode('system')
    store.initTheme()

    const onChange = mq.calls.added[mq.calls.added.length - 1].fn
    expect(typeof onChange).toBe('function')

    onChange({ matches: true })
    expect(store.systemPrefersDark).toBe(true)
    expect(document.documentElement.classList.contains('dark')).toBe(true)

    onChange({ matches: false })
    expect(store.systemPrefersDark).toBe(false)
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })

  test('matchMedia 缺失：不抛错、不注册新监听（老浏览器/无 DOM 环境）', () => {
    const mq = makeMq()
    vi.stubGlobal('matchMedia', () => mq)
    const store = useAppStore()
    store.initTheme()

    vi.stubGlobal('matchMedia', undefined)
    expect(() => store.initTheme()).not.toThrow()
    // 只剩第一轮那一次注册，没有新增（也没有可摘除的对象）
    expect(mq.calls.added).toHaveLength(1)
    expect(store.systemPrefersDark).toBe(false)
  })

  test('旧版 darkMode 一次性迁移：sessionStorage true → localStorage themeMode=dark', () => {
    sessionStorage.setItem('darkMode', 'true')
    const mq = makeMq()
    vi.stubGlobal('matchMedia', () => mq)
    const store = useAppStore()

    store.initTheme()

    expect(store.themeMode).toBe('dark')
    expect(localStorage.getItem('themeMode')).toBe('dark')
    expect(store.isDarkMode).toBe(true)
  })
})
