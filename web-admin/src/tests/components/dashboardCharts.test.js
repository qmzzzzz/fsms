/**
 * DashboardCharts 行为测试（首页图表区）
 *
 * 组件此前零测试覆盖（0%），但它的两个职责都属于「坏了不会第一时间被发现」：
 *
 *  A. tooltip 的 HTML 转义（L7）：ECharts tooltip 走 HTML 渲染，而类目名来自
 *     数据库（设备类型码可直接出现在图例/扇区名里）。escapeHtml 一旦被删或漏
 *     掉某个字符，注入内容就会进入 tooltip 的 DOM。本文件让注入串**真的走进
 *     组件**（当作 deviceType 的 _id 传入），再取组件注册进 ECharts 的 formatter
 *     原样调用——这是唯一能验证该防护生效的位置。
 *
 *  B. 数据接线与生命周期：日期轴与后端 byDay 的本地日期口径对齐、7 天序列按日
 *     递增无空洞、空数据走「暂无数据」空态而非伪造样例、并发 load 复用同一份
 *     请求、语言切换重建标签、卸载销毁实例并停掉 resize 节流。
 *
 * 技术手段与理由：
 *  - echarts/core 用替身。jsdom 无 canvas，真实 init 会抛
 *    "Renderer 'undefined' is not imported"；替身把每次 setOption 的入参原样
 *    留存，用例直接检查这份配置——比检查 DOM 更能反映组件究竟画了什么。
 *  - 组件经一层 wrapper 挂载以取得 defineExpose 的 load()（真实调用方式与
 *    父视图的模板 ref 一致），不使用 app._instance.exposed（已实测为 null）。
 *  - 期望值在本文件内独立计算（例如日期槽位由 Date 算术推出），不 import 被测的
 *    utils/datetime，避免两边一起错。日期标签按「数字对」解析而非按固定分隔符，
 *    这样实现改用 M/D 或 M-D 也不会产生假红。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { mountComponent, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

const optionCalls = []
const chartInstances = []

vi.mock('echarts/core', () => {
  function LinearGradient() {
    this.kind = 'linear'
  }
  return {
    graphic: { LinearGradient },
    use: vi.fn(),
    init: vi.fn((el) => {
      const instance = {
        el,
        setOption: vi.fn((option) => optionCalls.push(option)),
        resize: vi.fn(),
        dispose: vi.fn(),
      }
      chartInstances.push(instance)
      return instance
    }),
  }
})
vi.mock('echarts/charts', () => ({ LineChart: {}, PieChart: {} }))
vi.mock('echarts/components', () => ({
  TitleComponent: {},
  TooltipComponent: {},
  LegendComponent: {},
  GridComponent: {},
  GraphicComponent: {},
}))
vi.mock('echarts/renderers', () => ({ CanvasRenderer: {} }))
vi.mock('echarts/features', () => ({ LegacyGridContainLabel: {} }))

const getAlarms = vi.fn()
const getDevices = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    reports: {
      getAlarms: (...args) => getAlarms(...args),
      getDevices: (...args) => getDevices(...args),
    },
  },
  isCanceledError: () => false,
}))

const ALL_PERMS = ['report:read']
const DAY = 24 * 60 * 60 * 1000

let active = null
/** 指向被测组件实例（wrapper 的模板 ref），用于调用 expose 的 load() */
let chartsRef = null

const DashboardCharts = (await import('@/components/DashboardCharts.vue')).default

/** 与父视图 DashboardView 相同的用法：模板 ref + defineExpose 的 load() */
const ChartsWrapper = defineComponent({
  setup() {
    chartsRef = ref(null)
    return () => h(DashboardCharts, { ref: chartsRef })
  },
})

/** 独立复刻本仓的本地日期串口径（YYYY-MM-DD，非 UTC） */
const localDate = (date) => {
  const pad = (n) => String(n).padStart(2, '0')
  return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate())
}

/** 最近 7 天的本地日期串，最早 → 最新（与组件生成顺序一致） */
const lastSevenDays = () => {
  const out = []
  for (let i = 6; i >= 0; i -= 1) out.push(localDate(new Date(Date.now() - i * DAY)))
  return out
}

/** 把 'MM/DD'、'M-D' 之类的标签统一解析成 [月, 日] 数字对 */
const parseLabel = (label) => String(label).split(/\D+/).filter(Boolean).map(Number)

const mountCharts = async (options = {}) => {
  const {
    perms = ALL_PERMS,
    byDay = [],
    byType = [],
    alarmsReject = null,
    devicesReject = null,
    locale = 'zh-CN',
  } = options

  getAlarms.mockReset()
  getDevices.mockReset()
  optionCalls.length = 0
  chartInstances.length = 0

  if (alarmsReject) getAlarms.mockRejectedValue(alarmsReject)
  else getAlarms.mockResolvedValue({ data: { data: { byDay } } })
  if (devicesReject) getDevices.mockRejectedValue(devicesReject)
  else getDevices.mockResolvedValue({ data: { data: { byType } } })

  active = mountComponent(ChartsWrapper, {
    locale,
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
  await flush(4)
  return active
}

/** 首个 setOption = 趋势图；第二个 = 饼图（组件固定按此顺序初始化） */
const trendOption = () => optionCalls[0]
const pieOption = () => optionCalls[1]

beforeEach(() => {
  i18n.global.locale.value = 'zh-CN'
})

afterEach(() => {
  if (active) {
    active.unmount()
    active = null
  }
})

describe('A. tooltip 的 HTML 转义（L7：类目名用户可控）', () => {
  test('注入串作为设备类型码进入组件后，tooltip formatter 输出已转义（端到端）', async () => {
    const payload = '<img src=x onerror=alert(1)>'
    await mountCharts({ byType: [{ _id: payload, count: 3 }] })

    const series = pieOption().series[0]
    // 未知类型码回落为原始 _id —— 注入串确实到达了图表数据层
    expect(series.data[0].name).toBe(payload)

    const html = pieOption().tooltip.formatter({
      seriesName: series.name,
      name: series.data[0].name,
      value: 3,
      percent: 100,
    })
    expect(html).not.toContain('<img')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })

  test('趋势图 tooltip 的类目名同样转义（两条 formatter 各自独立防护）', async () => {
    await mountCharts({ byDay: [{ _id: localDate(new Date()), count: 3 }] })
    const formatter = trendOption().tooltip.formatter
    const html = formatter([{ name: '<script>alert(1)</script>', value: 3 }])
    expect(html).not.toContain('<script>')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  test('五个字符各自独立转义（& < > " \'）：少任何一个都留下注入面', async () => {
    await mountCharts({})
    const formatter = pieOption().tooltip.formatter
    const html = formatter({ seriesName: '', name: '&<>"\'', value: 0, percent: 0 })
    expect(html).toContain('&amp;&lt;&gt;&quot;&#39;')
    // 反证：类目名段落里不得残留任何原始特殊字符（否则说明某个 replace 被删）。
    // 剥掉 formatter 自带的 '<br/>' 结构标签后再判定——该标签是模板的一部分，
    // 不属于转义对象。
    const nameSegment = html.replace(/^<br\/>/, '').split(':')[0]
    expect(nameSegment).not.toMatch(/[<>"']/)
    expect(nameSegment).toBe('&amp;&lt;&gt;&quot;&#39;')
  })

  test('& 先于 < 转义：已转义的 &amp; 不会被二次转义成 &amp;amp;', async () => {
    await mountCharts({})
    const formatter = pieOption().tooltip.formatter
    const html = formatter({ seriesName: '', name: 'a & b', value: 1, percent: 1 })
    expect(html).toContain('a &amp; b')
    expect(html).not.toContain('&amp;amp;')
  })

  test('null / undefined 类目名渲染为空串且不抛错（不得出现字面量 null/undefined）', async () => {
    await mountCharts({})
    const formatter = pieOption().tooltip.formatter
    const out = formatter({ seriesName: null, name: undefined, value: 1, percent: 1 })
    expect(out).not.toContain('null')
    expect(out).not.toContain('undefined')
    expect(out).toContain('1 (1%)')
  })
})

describe('B. 趋势图数据接线', () => {
  test('X 轴恒为最近 7 天，逐日递增、无重复、无空洞', async () => {
    await mountCharts({ byDay: [] })
    const labels = trendOption().xAxis.data
    expect(labels).toHaveLength(7)

    const pairs = labels.map(parseLabel)
    expect(pairs.every((p) => p.length === 2 && p.every(Number.isFinite))).toBe(true)

    // 由第一格的「月/日」构造日期，其后每格必须正好 +1 天（跨月/跨年也成立）
    const start = new Date(2000, pairs[0][0] - 1, pairs[0][1])
    pairs.forEach(([month, day], index) => {
      const expected = new Date(start.getTime() + index * DAY)
      expect(
        [month, day],
        '第 ' + index + ' 格应为 ' + expected.toISOString().slice(0, 10)
      ).toEqual([expected.getMonth() + 1, expected.getDate()])
    })
  })

  test('末格为今天（近 7 天窗口的右端锚点）', async () => {
    await mountCharts({ byDay: [] })
    const [month, day] = parseLabel(trendOption().xAxis.data[6])
    const today = new Date()
    expect([month, day]).toEqual([today.getMonth() + 1, today.getDate()])
  })

  test('按 byDay 的 _id 精确匹配当日计数（错位一天即红）', async () => {
    const days = lastSevenDays()
    await mountCharts({ byDay: [{ _id: days[3], count: 42 }] })
    const counts = trendOption().series[0].data
    expect(counts[3]).toBe(42)
    expect(counts.filter((c) => c === 42)).toHaveLength(1)
    expect(counts.reduce((a, b) => a + b, 0)).toBe(42)
  })

  test('byDay 缺失的日期补 0，已有 0 值保留（不得把 0 当缺失丢掉）', async () => {
    const days = lastSevenDays()
    await mountCharts({
      byDay: [
        { _id: days[0], count: 0 },
        { _id: days[1], count: 5 },
      ],
    })
    expect(trendOption().series[0].data).toEqual([0, 5, 0, 0, 0, 0, 0])
  })

  test('请求参数 startDate = 7 天前的本地日期（UTC 串在东八区会错位一天）', async () => {
    await mountCharts({})
    expect(getAlarms).toHaveBeenCalledTimes(1)
    const params = getAlarms.mock.calls[0][0]
    expect(params.startDate).toBe(localDate(new Date(Date.now() - 7 * DAY)))
    expect(params.startDate).not.toContain('T')
    expect(params.startDate).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })

  test('设备分布请求不带日期参数（全量口径）', async () => {
    await mountCharts({})
    expect(getDevices).toHaveBeenCalledTimes(1)
    expect(getDevices.mock.calls[0][0]).toEqual({})
  })

  test('全部为 0 时显示「暂无数据」空态文字，且不显示数据点标签', async () => {
    await mountCharts({ byDay: [] })
    const option = trendOption()
    expect(option.series[0].label.show).toBe(false)
    expect(option.graphic).toHaveLength(1)
    expect(option.graphic[0].style.text).toBe(i18n.global.t('common.noData'))
  })

  test('有任意一天非 0 即退出空态（不得因为首日为 0 就误判为空）', async () => {
    const days = lastSevenDays()
    await mountCharts({ byDay: [{ _id: days[6], count: 1 }] })
    const option = trendOption()
    expect(option.series[0].label.show).toBe(true)
    expect(option.graphic).toEqual([])
  })

  test('y 轴与系列名走 i18n（切语言后重建即英文）', async () => {
    await mountCharts({ byDay: [{ _id: lastSevenDays()[0], count: 1 }], locale: 'en-US' })
    expect(trendOption().series[0].name).toBe('Alarm Count')
    expect(trendOption().xAxis.type).toBe('category')
    expect(trendOption().yAxis.type).toBe('value')
  })
})

describe('C. 饼图数据接线', () => {
  test('空数据不伪造样例：series.data 为空、标题接管空态、图例隐藏', async () => {
    await mountCharts({ byType: [] })
    const option = pieOption()
    expect(option.series[0].data).toEqual([])
    expect(option.title.show).toBe(true)
    expect(option.title.text).toBe(i18n.global.t('common.noData'))
    expect(option.legend.show).toBe(false)
    expect(option.legend.data).toEqual([])
  })

  test('有数据时隐藏空态标题、显示图例（图例项与数据一一对应）', async () => {
    await mountCharts({
      byType: [
        { _id: 'sprinkler', count: 3 },
        { _id: 'hydrant', count: 1 },
      ],
    })
    const option = pieOption()
    expect(option.title.show).toBe(false)
    expect(option.legend.show).toBe(true)
    expect(option.legend.data).toEqual([
      i18n.global.t('dashboard.sprinkler'),
      i18n.global.t('dashboard.hydrant'),
    ])
    expect(option.series[0].data.map((d) => d.value)).toEqual([3, 1])
  })

  test('已知类型码翻译为标签，_id 不再直接出现', async () => {
    await mountCharts({ byType: [{ _id: 'smoke_detector', count: 1 }] })
    expect(pieOption().series[0].data[0].name).toBe(i18n.global.t('dashboard.smokeDetector'))
  })

  test('未知类型码回落为原始 _id（不得渲染成空白或 undefined）', async () => {
    await mountCharts({ byType: [{ _id: 'brand_new_type', count: 2 }] })
    const option = pieOption()
    expect(option.series[0].data[0].name).toBe('brand_new_type')
    expect(option.legend.data).toEqual(['brand_new_type'])
  })

  test('_id 缺失时回落为「全部」标签，不渲染 undefined', async () => {
    await mountCharts({ byType: [{ count: 2 }] })
    const option = pieOption()
    expect(option.series[0].data[0].name).toBe(i18n.global.t('common.all'))
    expect(option.series[0].data[0].name).not.toContain('undefined')
  })

  test('每个扇区都有真实色值，且颜色由名字决定（同名两次结果一致）', async () => {
    await mountCharts({
      byType: [
        { _id: 'sprinkler', count: 1 },
        { _id: 'sprinkler', count: 2 },
      ],
    })
    const data = pieOption().series[0].data
    expect(data[0].itemStyle.color).toMatch(/^#[0-9a-f]{6}$/)
    expect(data[0].itemStyle.color).toBe(data[1].itemStyle.color)
  })

  test('计数值原样透传（count 为聚合结果，不得被改写）', async () => {
    await mountCharts({
      byType: [
        { _id: 'sprinkler', count: 7 },
        { _id: 'hydrant', count: 1 },
      ],
    })
    expect(pieOption().series[0].data.map((d) => d.value)).toEqual([7, 1])
  })
})

describe('D. 加载、并发与生命周期', () => {
  test('挂载即自动加载一次（异步组件挂载前父级的调用会落空）', async () => {
    await mountCharts({})
    expect(getAlarms).toHaveBeenCalledTimes(1)
    expect(getDevices).toHaveBeenCalledTimes(1)
  })

  test('并发 load() 复用同一份请求（in-flight 去重），结算后再调才发新请求', async () => {
    let release = null
    getAlarms.mockReset()
    getDevices.mockReset()
    optionCalls.length = 0
    chartInstances.length = 0
    getAlarms.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ data: { data: { byDay: [] } } })
        })
    )
    getDevices.mockResolvedValue({ data: { data: { byType: [] } } })

    active = mountComponent(ChartsWrapper, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(2)
    expect(getAlarms).toHaveBeenCalledTimes(1)

    // 与父视图完全相同的调用方式：defineExpose 出来的 load()
    chartsRef.value.load()
    chartsRef.value.load()
    await flush(2)
    expect(getAlarms, 'in-flight 期间不得重复发请求').toHaveBeenCalledTimes(1)

    release()
    await flush(4)
    expect(getAlarms).toHaveBeenCalledTimes(1)
    expect(optionCalls.length).toBe(2)

    chartsRef.value.load()
    await flush(4)
    expect(getAlarms, '结算后应允许再次加载').toHaveBeenCalledTimes(2)
  })

  test('请求失败后仍初始化空图表（不留白屏），且无未捕获异常', async () => {
    await mountCharts({ alarmsReject: new Error('boom'), devicesReject: new Error('boom') })
    expect(optionCalls.length).toBe(2)
    expect(trendOption().series[0].data).toEqual([0, 0, 0, 0, 0, 0, 0])
    expect(pieOption().series[0].data).toEqual([])
    expect(active.errors).toEqual([])
  })

  test('一个接口失败不影响另一个（各自 catch 为 null，容错语义独立）', async () => {
    await mountCharts({
      alarmsReject: new Error('alarm down'),
      byType: [{ _id: 'sprinkler', count: 2 }],
    })
    expect(trendOption().series[0].data).toEqual([0, 0, 0, 0, 0, 0, 0])
    expect(pieOption().series[0].data).toHaveLength(1)
  })

  test('两个报表请求并行发出（无依赖关系，不串行等待）', async () => {
    const order = []
    let releaseAlarms = null
    getAlarms.mockReset()
    getDevices.mockReset()
    optionCalls.length = 0
    chartInstances.length = 0
    getAlarms.mockImplementation(
      () =>
        new Promise((resolve) => {
          order.push('alarms-issued')
          releaseAlarms = () => resolve({ data: { data: { byDay: [] } } })
        })
    )
    getDevices.mockImplementation(() => {
      order.push('devices-issued')
      return Promise.resolve({ data: { data: { byType: [] } } })
    })

    active = mountComponent(ChartsWrapper, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(2)
    // 第二个请求在第一个仍挂起时就已发出 → 证明是并行而非串行
    expect(order).toEqual(['alarms-issued', 'devices-issued'])
    releaseAlarms()
    await flush(4)
  })

  test('首个请求结算后不再重复触发（Promise.all 只解析一次）', async () => {
    let releaseAlarms = null
    getAlarms.mockReset()
    getDevices.mockReset()
    optionCalls.length = 0
    chartInstances.length = 0
    getAlarms.mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseAlarms = () => resolve({ data: { data: { byDay: [] } } })
        })
    )
    getDevices.mockResolvedValue({ data: { data: { byType: [] } } })

    active = mountComponent(ChartsWrapper, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(2)
    releaseAlarms()
    await flush(6)
    expect(getAlarms).toHaveBeenCalledTimes(1)
    expect(optionCalls.length).toBe(2)
  })

  test('无 report:read 权限时一次请求都不发、不初始化图表（P3-39 门控）', async () => {
    await mountCharts({ perms: ['alarm:read'] })
    expect(getAlarms).not.toHaveBeenCalled()
    expect(getDevices).not.toHaveBeenCalled()
    expect(optionCalls).toEqual([])
    expect(chartInstances).toEqual([])
  })

  test('权限门控对通配符同样成立（report:* 放行）', async () => {
    await mountCharts({ perms: ['report:*'] })
    expect(getAlarms).toHaveBeenCalledTimes(1)
  })

  test('语言切换后用新语言重建图表标签', async () => {
    await mountCharts({ byType: [{ _id: 'sprinkler', count: 1 }] })
    const before = optionCalls.length

    i18n.global.locale.value = 'en-US'
    await flush(4)
    await waitFor(() => optionCalls.length > before, { message: '语言切换后重建图表' })

    const rebuiltPie = optionCalls[optionCalls.length - 1]
    expect(rebuiltPie.series[0].name).toBe('Device Count')
    expect(rebuiltPie.legend.data).toEqual(['Sprinkler'])
    expect(rebuiltPie.title.text).toBe('No Data')
  })

  test('卸载时销毁两个图表实例', async () => {
    const c = await mountCharts({ byType: [{ _id: 'sprinkler', count: 1 }] })
    expect(chartInstances).toHaveLength(2)
    c.unmount()
    active = null
    expect(chartInstances[0].dispose).toHaveBeenCalledTimes(1)
    expect(chartInstances[1].dispose).toHaveBeenCalledTimes(1)
  })

  test('窗口 resize 经节流后调用 resize：未到 100ms 不调用，到点后各调一次', async () => {
    await mountCharts({})
    chartInstances.forEach((inst) => inst.resize.mockClear())

    window.dispatchEvent(new window.Event('resize'))
    expect(chartInstances[0].resize).not.toHaveBeenCalled()

    await new Promise((resolve) => setTimeout(resolve, 160))
    expect(chartInstances[0].resize).toHaveBeenCalledTimes(1)
    expect(chartInstances[1].resize).toHaveBeenCalledTimes(1)
  })

  test('节流窗口内的连续 resize 合并为一次调用', async () => {
    await mountCharts({})
    chartInstances.forEach((inst) => inst.resize.mockClear())

    window.dispatchEvent(new window.Event('resize'))
    window.dispatchEvent(new window.Event('resize'))
    window.dispatchEvent(new window.Event('resize'))
    await new Promise((resolve) => setTimeout(resolve, 160))
    expect(chartInstances[0].resize).toHaveBeenCalledTimes(1)
  })

  test('卸载时清掉挂起的节流定时器（挂起窗口内卸载不得再触碰图表）', async () => {
    const c = await mountCharts({})
    chartInstances.forEach((inst) => inst.resize.mockClear())

    // 挂起一个尚未到点的节流定时器，随即卸载
    window.dispatchEvent(new window.Event('resize'))
    c.unmount()
    active = null

    await new Promise((resolve) => setTimeout(resolve, 160))
    expect(chartInstances[0].resize).not.toHaveBeenCalled()
  })

  test('卸载后移除 window resize 监听（否则闭包与图表实例被永久持有）', async () => {
    const c = await mountCharts({})
    chartInstances.forEach((inst) => inst.resize.mockClear())

    // 先在挂载态让一次节流完整走完（resizeTimer 归零），避免「上一个定时器未清」
    // 把后续调度误挡掉 —— 那会让本用例对「监听未移除」失去分辨力（实测踩过）。
    window.dispatchEvent(new window.Event('resize'))
    await new Promise((resolve) => setTimeout(resolve, 160))
    expect(chartInstances[0].resize).toHaveBeenCalledTimes(1)
    chartInstances.forEach((inst) => inst.resize.mockClear())

    c.unmount()
    active = null

    // 卸载后再触发 resize：监听已移除时不会再有任何调用；
    // 若监听残留，组件闭包仍持有已 dispose 的实例，这里会计到一次 resize。
    window.dispatchEvent(new window.Event('resize'))
    await new Promise((resolve) => setTimeout(resolve, 160))
    expect(chartInstances[0].resize).not.toHaveBeenCalled()
    expect(chartInstances[1].resize).not.toHaveBeenCalled()
  })
})
