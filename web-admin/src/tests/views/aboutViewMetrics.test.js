/**
 * AboutView「系统运行指标」卡片行为测试（O-8 面板半，2026-09-18）
 *
 * 背景：该卡片的 script 曾整体缺失（模板引用了不存在的绑定），修复后既有的
 * 回归只做「源码文本里含某字符串」的静态检查——实现被重写、条件写反、
 * 分支被删除时那种检查照样通过。本套件改为**真实挂载组件**、驱动真实轮询与
 * 真实 DOM，逐条钉住行为契约：
 *
 *  - 权限门控（security:audit）：无权限不发请求、不渲染卡片；
 *  - 快照归一化：后端字段缺失/类型漂移时渲染 0 值，而不是 NaN/undefined；
 *  - 失败语义：首次失败保持空态；轮询失败保留上一次快照（不清空面板）；
 *  - 轮询节律：30s 一次、页面隐藏时暂停、卸载后停止；
 *  - 展示逻辑：Top 路由上限、条形宽度按本批最大值归一化、uptime 分级进位、
 *    告警标签文案。
 *
 * 时间相关用例统一用 fake timers，且**必须在挂载前**启用：组件的 setInterval
 * 在 onMounted 注册，挂载后再切 fake timers 会漏掉已注册的真实定时器
 * （实测：切完推 30s，请求数不变）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const h = vi.hoisted(() => ({ getMetrics: vi.fn() }))

vi.mock('@/utils/api', () => ({
  api: { reports: { getMetrics: (...a) => h.getMetrics(...a) } },
  isCanceledError: () => false,
}))

import AboutView from '@/views/AboutView.vue'

const PERMS = ['security:audit']
const mounted = []
let visibilityState = null

/** 覆盖 document.visibilityState（jsdom 默认恒为 visible，隐藏态无法自然构造） */
const setVisibility = (state) => {
  visibilityState = state
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    get: () => visibilityState,
  })
}

const snapshot = (data) => ({ data: { success: true, data } })

const FULL = {
  summary: { totalRequests: 1234, totalErrors: 7, errorRate: 0.0123456 },
  latency: { avgSeconds: 0.42, byRoute: {} },
  routes: [
    { route: '/a', requests: 9 },
    { route: '/b', requests: 3 },
    { route: '/c', requests: 0 },
  ],
  alerts: [{ type: 'errorRate', level: 'high', count: 3 }],
  process: { uptimeSeconds: 3661, rssMB: 12, heapUsedMB: 8 },
}

const open = async (perms = PERMS) => {
  const c = mountComponent(AboutView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
  mounted.push(c)
  await flush(8)
  return c
}

const statValues = (c) => c.findAll('.metrics-stat-value').map((e) => e.textContent.trim())
const uptimeText = (c) => statValues(c)[4]
const barWidths = (c) => c.findAll('.route-bar-fill').map((e) => e.style.width)
const routeNames = (c) => c.findAll('.route-name').map((e) => e.textContent.trim())
const alertTexts = (c) => c.findAll('.metrics-alert-tag').map((e) => e.textContent.trim())

afterEach(() => {
  while (mounted.length) mounted.pop().handle.unmount()
  vi.useRealTimers()
  delete document.visibilityState
  visibilityState = null
  h.getMetrics.mockReset()
})

describe('AboutView 指标卡权限门控', () => {
  test('无 security:audit：不渲染卡片，也不发请求（避免每进页吃一次 403）', async () => {
    const c = await open([])
    expect(c.find('.metrics-card')).toBeFalsy()
    expect(h.getMetrics).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('有 security:audit：渲染卡片并拉取一次快照', async () => {
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    const c = await open()
    expect(c.find('.metrics-card')).toBeTruthy()
    expect(h.getMetrics).toHaveBeenCalledTimes(1)
    // 反证：卡片确实带内容渲染（否则上面的 find 可能是误命中别的节点）
    expect(c.find('.metrics-body')).toBeTruthy()
    expect(c.errors).toEqual([])
  })
})

describe('AboutView 指标快照渲染', () => {
  test('五项统计按快照渲染：请求数/错误数/错误率百分比/平均延迟/uptime', async () => {
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    const c = await open()
    expect(statValues(c)).toEqual(['1234', '7', '1.23%', '0.42s', '1h 1m'])
  })

  test('Top 路由：名称/计数渲染，条形宽度按本批最大值归一化并四舍五入', async () => {
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    const c = await open()
    expect(routeNames(c)).toEqual(['/a', '/b', '/c'])
    expect(c.findAll('.route-count').map((e) => e.textContent.trim())).toEqual(['9', '3', '0'])
    // 9 为基准：3/9 = 33.33% → 33%（取整而非进一）；0 条宽度为 0%
    expect(barWidths(c)).toEqual(['100%', '33%', '0%'])
  })

  test('Top 路由只取前 8 条（后端超长列表不得撑爆面板）', async () => {
    const routes = Array.from({ length: 12 }, (_, i) => ({ route: '/r' + i, requests: 100 - i }))
    h.getMetrics.mockResolvedValue(snapshot({ ...FULL, routes }))
    const c = await open()
    expect(routeNames(c)).toEqual(['/r0', '/r1', '/r2', '/r3', '/r4', '/r5', '/r6', '/r7'])
    expect(routeNames(c)).not.toContain('/r8')
    expect(barWidths(c)[7]).toBe('93%')
  })

  // 等价变异说明（变异验证实测，非缺口）：`routeBarWidth` 里的
  // `Math.max(...topRoutes.value.map((x) => x.requests), 0)` 把下限 0 改成 1，
  // 在**后端契约内的非负请求数**上无可观测差异——穷举 0..12345 的三元组合，
  // 归一化宽度 0 处不同（仅请求数为负时才有别，而请求数不可能为负）。
  // 故此处不补用例，避免制造恒真断言。
  test('全部请求数为 0：条形宽度全为 0%，不出现 NaN（除零防护）', async () => {
    h.getMetrics.mockResolvedValue(
      snapshot({
        ...FULL,
        routes: [
          { route: '/a', requests: 0 },
          { route: '/b', requests: 0 },
        ],
      })
    )
    const c = await open()
    expect(barWidths(c)).toEqual(['0%', '0%'])
    expect(c.text()).not.toContain('NaN')
  })

  test('告警标签渲染 type(级别) × 次数，级别走 i18n 词条', async () => {
    h.getMetrics.mockResolvedValue(
      snapshot({
        ...FULL,
        alerts: [
          { type: 'errorRate', level: 'high', count: 3 },
          { type: 'latency', level: 'critical', count: 12 },
        ],
      })
    )
    const c = await open()
    expect(alertTexts(c)).toEqual(['errorRate(高) × 3', 'latency(严重) × 12'])
  })

  test('快照字段缺失/类型漂移：渲染 0 值兜底，不出现 NaN/undefined，也不抛错', async () => {
    // 后端形状漂移的真实形态：整段缺失、null、以及本该是数组却给了对象
    h.getMetrics.mockResolvedValue(
      snapshot({
        summary: null,
        latency: null,
        routes: { '/a': 1 },
        alerts: 'nope',
        process: null,
      })
    )
    const c = await open()
    expect(statValues(c)).toEqual(['0', '0', '0.00%', '0s', '0s'])
    expect(c.findAll('.metrics-route')).toEqual([])
    expect(c.findAll('.metrics-alert-tag')).toEqual([])
    expect(c.text()).not.toContain('NaN')
    expect(c.text()).not.toContain('undefined')
    expect(c.errors).toEqual([])
  })

  test('成功但无数据（data 缺失）：空态文案说「暂无数据」，不渲染 0 值假数据', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    const c = await open()
    expect(c.find('.metrics-body')).toBeFalsy()
    expect(c.find('.el-empty')).toBeTruthy()
    // 与「首次加载失败」那条必须能区分：旧口径下两条用例断言完全同形
    // （都只查 .el-empty 存在），结构上禁止把两种空态读出差别。
    expect(c.find('.el-empty__description').textContent).toBe('暂无数据')
    expect(c.find('.el-empty').textContent).not.toContain('刷新')
    expect(c.errors).toEqual([])
  })
})

describe('AboutView 指标卡失败语义', () => {
  test('首次加载失败：空态文案说「加载失败」并给出刷新，不渲染 0 值假数据', async () => {
    h.getMetrics.mockRejectedValue(new Error('network down'))
    const c = await open()
    expect(c.find('.metrics-body')).toBeFalsy()
    expect(c.find('.el-empty')).toBeTruthy()
    expect(statValues(c)).toEqual([])
    // 「加载失败」与「暂无数据」是两件事：附属数据不可用不该整页报错，
    // 但空态文案不能替后端宣布「没有数据」。
    expect(c.find('.el-empty__description').textContent.trim()).toBe('加载失败')
    expect(c.find('.el-empty').textContent).toContain('刷新')
    expect(c.errors).toEqual([])
  })

  test('失败后点刷新：真的重发指标请求，成功后空态换回数据卡', async () => {
    h.getMetrics.mockRejectedValue(new Error('network down'))
    const c = await open()
    expect(c.find('.el-empty__description').textContent.trim()).toBe('加载失败')
    const callsBefore = h.getMetrics.mock.calls.length

    h.getMetrics.mockResolvedValue(snapshot(FULL))
    click(c.find('.el-empty button'))
    await flush(8)
    expect(h.getMetrics.mock.calls.length).toBe(callsBefore + 1)

    expect(c.find('.el-empty')).toBeFalsy()
    expect(c.find('.metrics-body')).toBeTruthy()
  })

  test('轮询失败保留上一次快照（面板不清空），且确实发生了第二次请求', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    const c = await open()
    expect(statValues(c)).toEqual(['1234', '7', '1.23%', '0.42s', '1h 1m'])

    h.getMetrics.mockRejectedValue(new Error('boom'))
    await vi.advanceTimersByTimeAsync(30000)
    await flush(4)
    // 先证明轮询真的触发了，否则「数据没变」是恒真的
    expect(h.getMetrics).toHaveBeenCalledTimes(2)
    expect(statValues(c)).toEqual(['1234', '7', '1.23%', '0.42s', '1h 1m'])
    expect(c.find('.metrics-body')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('轮询返回 success:false：同样保留上一次快照，不把失败响应当数据渲染', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    const c = await open()

    h.getMetrics.mockResolvedValue({ data: { success: false, data: {} } })
    await vi.advanceTimersByTimeAsync(30000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(2)
    expect(statValues(c)).toEqual(['1234', '7', '1.23%', '0.42s', '1h 1m'])
  })
})

describe('AboutView 指标轮询节律与生命周期', () => {
  test('周期为 30s：29s 不刷新，到 30s 刷新一次', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    await open()
    expect(h.getMetrics).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(29000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(1000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(2)
  })

  test('页面隐藏时暂停轮询，恢复可见后继续（不对后台标签页空转）', async () => {
    vi.useFakeTimers()
    setVisibility('visible')
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    await open()
    expect(h.getMetrics).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(30000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(2)

    setVisibility('hidden')
    await vi.advanceTimersByTimeAsync(60000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(2)

    setVisibility('visible')
    await vi.advanceTimersByTimeAsync(30000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(3)
  })

  test('卸载后停止轮询（不给后端留隐形常驻客户端）', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    const c = await open()
    expect(h.getMetrics).toHaveBeenCalledTimes(1)

    c.handle.unmount()
    mounted.pop()
    await vi.advanceTimersByTimeAsync(120000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(1)
  })

  test('首次失败后仍会按周期重试（不把上次成败当轮询条件）', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockRejectedValue(new Error('first fail'))
    await open()
    expect(h.getMetrics).toHaveBeenCalledTimes(1)

    h.getMetrics.mockResolvedValue(snapshot(FULL))
    await vi.advanceTimersByTimeAsync(30000)
    await flush(4)
    expect(h.getMetrics).toHaveBeenCalledTimes(2)
    expect(statValues(mounted[0])).toEqual(['1234', '7', '1.23%', '0.42s', '1h 1m'])
  })
})

describe('AboutView uptime 分级进位边界', () => {
  test('秒/分/时/天四档进位与非法输入兜底', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue(snapshot(FULL))
    const c = await open()
    expect(uptimeText(c)).toBe('1h 1m')

    const cases = [
      [59, '59s'],
      [60, '1m'],
      [3599, '59m'],
      [3600, '1h 0m'],
      [86399, '23h 59m'],
      [86400, '1d 0h'],
      [90061, '1d 1h'],
      // 关键样本（变异验证发现）：必须让「小时数 % 24」与「分钟数 % 60」取不同值，
      // 否则把天档写成 `${m % 60}h` 的实现也能蒙混过关——
      // 176400s = 49h = 2940min：h%24 = 1 而 m%60 = 0，两者可分。
      [176400, '2d 1h'],
      [172800, '2d 0h'],
      ['90', '1m'],
      [-5, '0s'],
      [null, '0s'],
      ['abc', '0s'],
    ]
    for (const [seconds, expected] of cases) {
      h.getMetrics.mockResolvedValueOnce(
        snapshot({ process: { uptimeSeconds: seconds, rssMB: 0, heapUsedMB: 0 } })
      )
      await vi.advanceTimersByTimeAsync(30000)
      await flush(4)
      expect(uptimeText(c), 'uptimeSeconds=' + String(seconds)).toBe(expected)
    }
  })
})
