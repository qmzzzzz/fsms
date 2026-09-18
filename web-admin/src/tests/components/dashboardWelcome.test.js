/**
 * DashboardWelcome 行为测试（问候语 + 秒级时钟 + 头像）
 *
 * 组件定位：仪表盘欢迎卡。三类真实退化：
 *  1. 问候语时段分支写错 → 用户看到「晚上好」却是早上（此前无测试，属静默退化）；
 *  2. 用户显示名回退链断裂 → 卡片显示 undefined；
 *  3. 秒级定时器未清理 → 组件卸载后仍在后台每秒触发（内存/CPU 泄漏，且 Vue 会告警）。
 *
 * 时钟用 vi.useFakeTimers + setSystemTime 精确控制「当前时刻」与「时间推进」，
 * 断言的是 toLocaleDateString/toLocaleTimeString 的真实输出，而不是源码里的格式选项字符串。
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { mountComponent, flush } from '../helpers/componentHarness'
import DashboardWelcome from '@/components/DashboardWelcome.vue'
import i18n from '@/i18n'

let active = null
const mount = (props, options = {}) => {
  active = mountComponent(DashboardWelcome, { props, ...options })
  return active
}

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  active?.handle.unmount()
  active = null
  vi.unstubAllGlobals()
  vi.useRealTimers()
  i18n.global.locale.value = 'zh-CN'
  // 个别用例把 visibilityState 覆写为 hidden；删除自有属性即恢复 jsdom 原型 getter（实测）
  delete document.visibilityState
})

describe('DashboardWelcome 问候语时段分支', () => {
  // 5 个分支（源码判据：h<6 / h<12 / h<14 / h<18 / else）
  const cases = [
    [2, '凌晨好', 'dashboard.greetingLateNight'],
    [9, '早上好', 'dashboard.greetingMorning'],
    [13, '中午好', 'dashboard.greetingNoon'],
    [15, '下午好', 'dashboard.greetingAfternoon'],
    [20, '晚上好', 'dashboard.greetingEvening'],
  ]

  for (const [hour, expected, key] of cases) {
    test(`${hour} 点 → 「${expected}」（${key}）`, async () => {
      vi.setSystemTime(new Date(2026, 0, 1, hour, 30, 0))
      const c = mount({ currentUser: { username: 'tester' } })
      await flush(2)
      expect(c.find('h2').textContent).toBe(`${expected}, tester`)
      // 与词表取值一致：文案若被改动，此断言与 i18n 实例同时暴露
      expect(i18n.global.t(key)).toBe(expected)
      expect(c.errors).toEqual([])
    })
  }

  test('边界小时归属正确：5 点凌晨，6 点早上，11 点仍早上，12 点中午，14 点下午，18 点晚上', async () => {
    const boundaries = [
      [5, '凌晨好'],
      [6, '早上好'],
      [11, '早上好'],
      [12, '中午好'],
      [13, '中午好'],
      [14, '下午好'],
      [17, '下午好'],
      [18, '晚上好'],
      [23, '晚上好'],
    ]
    for (const [hour, expected] of boundaries) {
      vi.setSystemTime(new Date(2026, 0, 1, hour, 0, 0))
      const c = mount({ currentUser: { username: 'tester' } })
      await flush(2)
      expect(c.find('h2').textContent).toBe(`${expected}, tester`)
      c.handle.unmount()
      active = null
    }
  })

  test('跨时段后问候语随时钟刷新（不得固守 setup 时刻的小时）', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 11, 59, 0))
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    expect(c.find('h2').textContent).toBe('早上好, tester')
    // 时钟走到下午时段：问候语必须跟随（真实退化：greeting 只读 new Date() 而不依赖 now ref）
    vi.setSystemTime(new Date(2026, 0, 1, 12, 30, 0))
    vi.advanceTimersByTime(1000)
    await flush(2)
    expect(c.find('h2').textContent).toBe('中午好, tester')
    expect(c.find('.clock-time').textContent.trim()).toBe('12:30:01')
  })
  test('英文界面下问候语与欢迎语走英文词表', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 9, 30, 0))
    const c = mount({ currentUser: { username: 'tester' } }, { locale: 'en-US' })
    await flush(2)
    expect(c.find('h2').textContent).toBe('Good morning, tester')
    expect(c.find('p').textContent).toBe('Welcome back to Fire Safety Management System!')
  })

  test('切换语言后问候语与欢迎语实时跟随（computed 依赖 locale）', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 15, 30, 0))
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    expect(c.find('h2').textContent).toBe('下午好, tester')
    i18n.global.locale.value = 'en-US'
    await flush(2)
    expect(c.find('h2').textContent).toBe('Good afternoon, tester')
    expect(c.find('p').textContent).toBe('Welcome back to Fire Safety Management System!')
  })
})

describe('DashboardWelcome 用户名回退与头像', () => {
  test('显示名回退链：realName → username → Admin', async () => {
    const realName = mount({ currentUser: { realName: '张三', username: 'zhangsan' } })
    await flush(2)
    expect(realName.find('h2').textContent).toContain('张三')
    expect(realName.find('h2').textContent).not.toContain('zhangsan')
    realName.handle.unmount()
    active = null

    const onlyUsername = mount({ currentUser: { username: 'lisi' } })
    await flush(2)
    expect(onlyUsername.find('h2').textContent).toContain('lisi')
    onlyUsername.handle.unmount()
    active = null

    const emptyRealName = mount({ currentUser: { realName: '', username: 'wangwu' } })
    await flush(2)
    // 空串是 falsy，必须继续回退到 username
    expect(emptyRealName.find('h2').textContent).toContain('wangwu')
    emptyRealName.handle.unmount()
    active = null

    const none = mount({})
    await flush(2)
    expect(none.find('h2').textContent).toContain('Admin')
  })

  test('头像取用户名首字母并大写（小写字母必须转为大写）', async () => {
    const lower = mount({ currentUser: { username: 'zhangsan' } })
    await flush(2)
    expect(lower.find('.el-avatar').textContent.trim()).toBe('Z')
    lower.handle.unmount()
    active = null

    const upper = mount({ currentUser: { username: 'Wang' } })
    await flush(2)
    expect(upper.find('.el-avatar').textContent.trim()).toBe('W')
  })

  test('无 currentUser 时头像回退为 A；仅有 realName 时同样回退 A', async () => {
    const none = mount({})
    await flush(2)
    expect(none.find('.el-avatar').textContent.trim()).toBe('A')
    none.handle.unmount()
    active = null
    const onlyReal = mount({ currentUser: { realName: '张三' } })
    await flush(2)
    expect(onlyReal.find('.el-avatar').textContent.trim()).toBe('A')
  })

  test('头像尺寸固定 64px（el-avatar 的 --el-avatar-size 变量）', async () => {
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    expect(c.find('.el-avatar').style.getPropertyValue('--el-avatar-size')).toBe('64px')
    expect(c.find('.welcome-card')).not.toBe(null)
  })
})

describe('DashboardWelcome 秒级时钟', () => {
  test('挂载即显示当前日期与时间，格式取自真实 locale 格式化结果', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 9, 5, 3))
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    const at = new Date(2026, 0, 1, 9, 5, 3)
    const expectedTime = at.toLocaleTimeString('zh-CN', { hour12: false })
    const expectedDate = at.toLocaleDateString('zh-CN', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      weekday: 'long',
    })
    expect(c.find('.clock-time').textContent.trim()).toBe(expectedTime)
    expect(c.find('.clock-date').textContent.trim()).toBe(expectedDate)
    // 字面量兜底：确认上面的期望不是空串/占位（否则断言会退化）
    expect(expectedTime).toBe('09:05:03')
    expect(expectedDate).toBe('2026年1月1日星期四')
  })

  test('每推进 1000ms 时间文本更新一次（秒级刷新真实生效）', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 9, 0, 0))
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    expect(c.find('.clock-time').textContent.trim()).toBe('09:00:00')
    vi.advanceTimersByTime(1000)
    await flush(2)
    expect(c.find('.clock-time').textContent.trim()).toBe('09:00:01')
    vi.advanceTimersByTime(1000)
    await flush(2)
    expect(c.find('.clock-time').textContent.trim()).toBe('09:00:02')
  })

  test('挂载时立即按当前时刻同步，而不是沿用 setup 阶段捕获的旧快照', async () => {
    // startClock() 先 updateClock()：挂载瞬间就取一次当前时间。
    // 若删掉这次同步，卡片会一直显示 setup 阶段（ref(new Date())）的旧值。
    const RealDate = Date
    const setupSnapshot = new RealDate(2026, 0, 1, 10, 0, 0)
    const mountTime = new RealDate(2026, 0, 1, 10, 0, 7)
    let noArgCalls = 0
    class StubDate extends RealDate {
      constructor(...args) {
        if (args.length === 0) {
          noArgCalls += 1
          // 首次无参调用在 setup（const now = ref(new Date())）→ 返回旧快照；
          // 其后（含 onMounted 的 updateClock）→ 返回挂载时刻
          super(noArgCalls === 1 ? setupSnapshot.getTime() : mountTime.getTime())
        } else {
          super(...args)
        }
      }
    }
    vi.stubGlobal('Date', StubDate)
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    // 时钟必须已是挂载时刻（10:00:07），不是 setup 快照（10:00:00）
    expect(c.find('.clock-time').textContent.trim()).toBe('10:00:07')
    expect(c.find('.clock-time').textContent.trim()).not.toBe('10:00:00')
    expect(c.errors).toEqual([])
  })
  test('页面隐藏（visibilityState=hidden）时不刷新，恢复可见后立即同步', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 9, 0, 0))
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    expect(c.find('.clock-time').textContent.trim()).toBe('09:00:00')
    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true })
    vi.advanceTimersByTime(5000)
    await flush(2)
    // 隐藏期间时间文本必须冻结在最后一次可见值
    expect(c.find('.clock-time').textContent.trim()).toBe('09:00:00')
    Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true })
    vi.advanceTimersByTime(1000)
    await flush(2)
    expect(c.find('.clock-time').textContent.trim()).toBe('09:00:06')
  })

  test('卸载后清除定时器：无挂起 interval，DOM 清空且不报错', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 9, 0, 0))
    const c = mount({ currentUser: { username: 'tester' } })
    await flush(2)
    expect(vi.getTimerCount()).toBe(1)
    c.handle.unmount()
    active = null
    // onUnmounted → stopClock 已 clearInterval
    expect(vi.getTimerCount()).toBe(0)
    vi.advanceTimersByTime(10000)
    await flush(2)
    expect(c.root.children).toHaveLength(0)
    expect(c.errors).toEqual([])
    expect(c.warnings).toEqual([])
  })

  test('英文界面下日期/时间也走英文 locale 格式化', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 14, 30, 5))
    const c = mount({ currentUser: { username: 'tester' } }, { locale: 'en-US' })
    await flush(2)
    expect(c.find('.clock-date').textContent.trim()).toBe('Thursday, January 1, 2026')
    expect(c.find('.clock-time').textContent.trim()).toBe('14:30:05')
  })
})

describe('DashboardWelcome 整体渲染健康度', () => {
  test('渲染期无 Vue 运行时错误与告警，关键结构齐备', async () => {
    vi.setSystemTime(new Date(2026, 0, 1, 9, 0, 0))
    const c = mount({ currentUser: { realName: '张三', username: 'zhangsan' } })
    await flush(2)
    expect(c.errors).toEqual([])
    expect(c.warnings).toEqual([])
    expect(c.findAll('h2')).toHaveLength(1)
    expect(c.findAll('p')).toHaveLength(1)
    expect(c.findAll('.welcome-clock')).toHaveLength(1)
    expect(c.findAll('.el-avatar')).toHaveLength(1)
  })
})
