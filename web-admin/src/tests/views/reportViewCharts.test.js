/**
 * ReportView 图表 / 概览 / 生命周期行为测试（2026-09-18）
 *
 * 与 reportView.test.js（导出链路）分工：本文件覆盖「首屏概览 → 骨架替换 →
 * 图表初始化 → 图表数据渲染 → 主题重绘 → resize 节流 → 卸载清理」这条主链路。
 * 这些行为此前只有 0 覆盖：任何一处退化（骨架不消失、图表不初始化、
 * 数据映射写错、主题切换不重绘、监听不摘除）都不会有任何断言变红。
 *
 * echarts 在 jsdom 无 canvas，故替身 init 并记录 setOption/resize/dispose 调用；
 * 断言落在「喂给 echarts 的 option 内容」上——那正是真实退化会改变的地方
 * （例如把 normal/offline 的映射写反、把 noData 占位丢掉、主题色不跟随）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore, useAppStore } from '@/store'

const h = vi.hoisted(() => ({
  getDashboard: vi.fn(),
  getAlarms: vi.fn(),
  getDevices: vi.fn(),
  exportReport: vi.fn(),
  setOptionA: vi.fn(),
  setOptionD: vi.fn(),
  resizeA: vi.fn(),
  resizeD: vi.fn(),
  disposeA: vi.fn(),
  disposeD: vi.fn(),
  initCount: 0,
  canceled: false,
}))

vi.mock('@/utils/api', () => ({
  api: {
    reports: {
      getDashboard: (...a) => h.getDashboard(...a),
      getAlarms: (...a) => h.getAlarms(...a),
      getDevices: (...a) => h.getDevices(...a),
      export: (...a) => h.exportReport(...a),
    },
  },
  isCanceledError: (e) => h.canceled || String(e?.message || '') === 'canceled',
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
// echarts 无 canvas：替身只记录调用与参数，本文件不测绘制
vi.mock('echarts/core', () => ({
  use: vi.fn(),
  init: () => {
    h.initCount += 1
    // 首次 init = 报警类型饼图（模板中先声明），第二次 = 设备状态柱状图
    return h.initCount === 1
      ? {
          setOption: (...a) => h.setOptionA(...a),
          resize: (...a) => h.resizeA(...a),
          dispose: (...a) => h.disposeA(...a),
        }
      : {
          setOption: (...a) => h.setOptionD(...a),
          resize: (...a) => h.resizeD(...a),
          dispose: (...a) => h.disposeD(...a),
        }
  },
}))
vi.mock('echarts/charts', () => ({ PieChart: {}, BarChart: {} }))
vi.mock('echarts/components', () => ({
  TooltipComponent: {},
  LegendComponent: {},
  GridComponent: {},
}))
vi.mock('echarts/renderers', () => ({ CanvasRenderer: {} }))

import ReportView from '@/views/ReportView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

const routes = ['/devices', '/alarms', '/inspections'].map((p) => ({
  path: p,
  name: p.slice(1),
  component: { render: () => null },
}))

const DASHBOARD = {
  data: {
    success: true,
    data: {
      devices: { total: 10, online: 4, needMaintenance: 2 },
      alarms: { total: 5, pending: 1, avgResponse: 3 },
      inspections: { total: 8, completionRate: 75, overdue: 1 },
    },
  },
}
const ALARMS = {
  data: {
    data: {
      byType: [
        { _id: 'smoke', count: 3 },
        { _id: 'weird_type', count: 1 },
        { _id: null, count: 2 },
      ],
    },
  },
}
const DEVICES = {
  data: {
    data: {
      byStatus: [
        { _id: 'normal', count: 7 },
        { _id: 'fault', count: 2 },
      ],
    },
  },
}

const mounted = []
let appStore = null

const open = async (opts = {}) => {
  // 注意：mockRejectedValue/mockResolvedValue 会覆盖彼此，失败场景必须走本函数的
  // *Reject 参数——若在调用 open() 之前自行设置 mockRejectedValue，会被这里的
  // mockResolvedValue 覆盖，用例退化成「请求成功」的假通过（本文件初版踩过）。
  if (opts.dashboardReject) h.getDashboard.mockRejectedValue(opts.dashboardReject)
  else h.getDashboard.mockResolvedValue(opts.dashboard ?? DASHBOARD)
  if (opts.alarmsReject) h.getAlarms.mockRejectedValue(opts.alarmsReject)
  else h.getAlarms.mockResolvedValue(opts.alarms ?? ALARMS)
  if (opts.devicesReject) h.getDevices.mockRejectedValue(opts.devicesReject)
  else h.getDevices.mockResolvedValue(opts.devices ?? DEVICES)
  const c = mountComponent(ReportView, {
    routes,
    initialRoute: '/',
    setupStore: (pinia) => {
      useAuthStore(pinia).setPermissions(opts.perms ?? ['report:read', 'report:export'])
      appStore = useAppStore(pinia)
    },
  })
  mounted.push(c)
  await flush(14)
  return c
}

const lastPie = () => h.setOptionA.mock.calls[h.setOptionA.mock.calls.length - 1]?.[0]
const lastBar = () => h.setOptionD.mock.calls[h.setOptionD.mock.calls.length - 1]?.[0]
const waitNav = (c, path) =>
  waitFor(() => c.router.currentRoute.value.path === path, { message: '导航到 ' + path })

afterEach(() => {
  while (mounted.length) mounted.pop().handle.unmount()
  appStore = null
  // setDarkMode 会把 themeMode 写进 localStorage（store 的持久化设计），
  // 用例间必须清掉：否则后一个用例初始就是暗色，「切换主题」用例退化成空转
  // （实测：不清时，加载期切主题用例里 isDarkMode 已是 true，setDarkMode(true) 无变化）。
  localStorage.removeItem('themeMode')
  h.getDashboard.mockReset()
  h.getAlarms.mockReset()
  h.getDevices.mockReset()
  h.exportReport.mockReset()
  h.setOptionA.mockReset()
  h.setOptionD.mockReset()
  h.resizeA.mockReset()
  h.resizeD.mockReset()
  h.disposeA.mockReset()
  h.disposeD.mockReset()
  h.initCount = 0
  h.canceled = false
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  document.body.innerHTML = ''
})

describe('ReportView 首屏加载与骨架替换', () => {
  test('加载中渲染骨架、不渲染图表容器；数据到达后骨架消失、图表容器就位', async () => {
    let resolveDash
    h.getDashboard.mockImplementation(
      () =>
        new Promise((r) => {
          resolveDash = r
        })
    )
    h.getAlarms.mockResolvedValue(ALARMS)
    h.getDevices.mockResolvedValue(DEVICES)
    const c = mountComponent(ReportView, {
      routes,
      initialRoute: '/',
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(['report:read']),
    })
    mounted.push(c)
    await flush(6)

    expect(c.findAll('.glass-skeleton').length).toBeGreaterThan(0)
    expect(c.findAll('.chart-box')).toHaveLength(0)
    expect(c.find('.overview-card').textContent).not.toContain('设备总数')

    resolveDash(DASHBOARD)
    await flush(14)
    expect(c.findAll('.glass-skeleton')).toHaveLength(0)
    expect(c.findAll('.chart-box')).toHaveLength(2)
    expect(c.find('.overview-card').textContent).toContain('设备总数')
    expect(c.errors).toEqual([])
  })

  test('概览九项按后端字段渲染，在线率与完成率按百分比口径换算', async () => {
    const c = await open()
    const text = c.find('.overview-card').textContent.replace(/\s+/g, ' ')
    // 在线率 = round(4/10*100) = 40%，不是原始计数
    expect(text).toContain('10')
    expect(text).toContain('40%')
    expect(text).toContain('75%')
    expect(text).toContain('3min')
    // 反证：完成率不是把 total 当百分比（8 != 75）
    expect(text).not.toContain('8%')
    expect(c.errors).toEqual([])
  })

  test('设备总数为 0：在线率按 0 处理，不出现 NaN（除零防护）', async () => {
    const c = await open({
      dashboard: {
        data: {
          success: true,
          data: { devices: { total: 0, online: 5 }, alarms: {}, inspections: {} },
        },
      },
    })
    const text = c.find('.overview-card').textContent.replace(/\s+/g, ' ')
    expect(text).toContain('0%')
    expect(text).not.toContain('NaN')
    expect(text).not.toContain('Infinity')
    expect(c.errors).toEqual([])
  })

  test('后端响应 success:false：概览保持 0 值兜底且退出骨架（不永久卡加载态）', async () => {
    // 关键：data 里塞非零值——若实现只看「字段是否存在」而不看 success 标志，
    // 这些值就会被渲染出来，本用例转红（用 data:null 则测不出这一点）
    const c = await open({
      dashboard: {
        data: {
          success: false,
          data: {
            devices: { total: 999, online: 999 },
            alarms: { total: 999 },
            inspections: { total: 999 },
          },
        },
      },
    })
    expect(c.findAll('.glass-skeleton')).toHaveLength(0)
    const text = c.find('.overview-card').textContent.replace(/\s+/g, ' ')
    expect(text).toContain('设备总数')
    expect(text).not.toContain('999')
    expect(text).not.toContain('NaN')
    expect(text).not.toContain('undefined')
    expect(c.errors).toEqual([])
  })

  test('概览段字段整体缺失：每个值位渲染数字 0 兜底，不留空格', async () => {
    const c = await open({ dashboard: { data: { success: true, data: {} } } })
    const text = c.find('.overview-card').textContent.replace(/\s+/g, ' ')
    expect(text).not.toContain('NaN')
    expect(text).not.toContain('undefined')
    // 关键（变异验证发现）：Vue 把 undefined 渲染成空串，只有 not.toContain('undefined')
    // 抓不住「兜底被删」——`devices.total || 0` 改成 `devices.total` 后该断言仍绿。
    // 必须逐个 value 位断言确切文本：空值位会变成 ''（或 'min' 这种只剩单位）。
    const cells = c.findAll('.el-descriptions__content').map((e) => e.textContent.trim())
    expect(cells).toEqual(['0', '0%', '0', '0', '0', '0min', '0', '0%', '0'])
    expect(c.errors).toEqual([])
  })

  test('概览请求失败：静默退出加载态（页面仍可用，不弹错误提示）', async () => {
    h.getDashboard.mockRejectedValue(new Error('net down'))
    h.getAlarms.mockResolvedValue(ALARMS)
    h.getDevices.mockResolvedValue(DEVICES)
    const c = mountComponent(ReportView, {
      routes,
      initialRoute: '/',
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(['report:read']),
    })
    mounted.push(c)
    await flush(14)
    expect(c.findAll('.glass-skeleton')).toHaveLength(0)
    expect(c.errors).toEqual([])
  })
})

describe('ReportView 图表数据渲染', () => {
  test('报警类型饼图：已知类型走 i18n 标签+配色，未知类型回退原始 id，空 id 回退「暂无数据」', async () => {
    await open()
    expect(h.initCount).toBe(2)
    const data = lastPie().series[0].data
    expect(data).toEqual([
      { value: 3, name: '烟雾报警', itemStyle: { color: '#e63946' } },
      { value: 1, name: 'weird_type', itemStyle: { color: '#64748b' } },
      { value: 2, name: '暂无数据', itemStyle: { color: '#64748b' } },
    ])
  })

  test('报警类型无数据：饼图渲染「暂无数据」占位，而不是空 series（图表不白屏）', async () => {
    await open({ alarms: { data: { data: { byType: [] } } } })
    const data = lastPie().series[0].data
    expect(data).toHaveLength(1)
    expect(data[0].name).toBe('暂无数据')
    expect(data[0].value).toBe(1)
    // 占位色必须是主题里的 noDataColor（亮色 #cbd5e1），不是随便一个颜色
    expect(data[0].itemStyle.color).toBe('#cbd5e1')
  })

  test('报警类型缺 count 字段：按 0 计而不是 undefined', async () => {
    await open({ alarms: { data: { data: { byType: [{ _id: 'smoke' }] } } } })
    expect(lastPie().series[0].data[0].value).toBe(0)
  })

  test('响应体缺 data 层：按空数据兜底走占位，不抛错', async () => {
    const c = await open({
      alarms: { data: { success: true } },
      devices: { data: { success: true } },
    })
    expect(lastPie().series[0].data[0].name).toBe('暂无数据')
    expect(lastBar().series[0].data.map((x) => x.value)).toEqual([0, 0, 0, 0])
    expect(c.errors).toEqual([])
  })

  test('设备状态柱状图：四状态固定顺序与配色，缺的状态补 0（不与相邻状态错位）', async () => {
    await open()
    const data = lastBar().series[0].data
    expect(data.map((x) => x.name)).toEqual(['正常', '离线', '故障', '维护中'])
    expect(data.map((x) => x.value)).toEqual([7, 0, 2, 0])
    expect(data.map((x) => x.itemStyle.color)).toEqual(['#16a34a', '#64748b', '#e63946', '#d97706'])
    // 轴标签与 series 必须同序同长，否则柱与标签错位
    expect(lastBar().xAxis.data).toEqual(['正常', '离线', '故障', '维护中'])
    // 柱状图 tooltip 带单位「台」；饼图 tooltip 带占比，两者语义不同不可互换
    expect(lastBar().tooltip).toEqual({ trigger: 'axis', formatter: '{b}: {c}台' })
    expect(lastPie().tooltip).toEqual({ trigger: 'item', formatter: '{b}: {c} ({d}%)' })
  })

  // 等价变异说明（变异验证实测，非缺口）：把 `statusMap[item._id] = item.count || 0`
  // 的兜底去掉，在**读取处** `value: statusMap['normal'] || 0` 会被二次归一，
  // 无可观测差异（实测：去掉后四个状态的 value 仍为 [7,0,2,0]）。故不补用例。

  test('设备状态缺 count：按 0 计而不是 undefined', async () => {
    await open({ devices: { data: { data: { byStatus: [{ _id: 'normal' }] } } } })
    expect(lastBar().series[0].data[0].value).toBe(0)
  })

  test('未知状态值不进图（只渲染后端契约内的四状态）', async () => {
    await open({
      devices: {
        data: {
          data: {
            byStatus: [
              { _id: 'normal', count: 1 },
              { _id: 'ghost', count: 99 },
            ],
          },
        },
      },
    })
    expect(lastBar().series[0].data.map((x) => x.value)).toEqual([1, 0, 0, 0])
    expect(lastBar().series[0].data.map((x) => x.name)).not.toContain('ghost')
  })

  test('图表数据加载失败（非取消）：提示加载失败，且不留下半截图表', async () => {
    const c = await open({
      alarmsReject: new Error('alarms down'),
      devicesReject: new Error('devices down'),
    })
    expect(ElMessage.error).toHaveBeenCalledWith('加载失败')
    expect(h.setOptionA).not.toHaveBeenCalled()
    expect(h.setOptionD).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('路由切换导致的取消错误：静默处理，不弹「加载失败」', async () => {
    await open({ alarmsReject: new Error('canceled') })
    expect(ElMessage.error).not.toHaveBeenCalled()
  })
})

describe('ReportView 主题重绘', () => {
  test('暗色切换：图表按新主题重绘（边框色与分隔线色跟随，不是固定浅色）', async () => {
    await open()
    expect(appStore.isDarkMode, '初始应为亮色').toBe(false)
    expect(lastPie().series[0].itemStyle.borderColor).toBe('#ffffff')
    expect(lastBar().yAxis.splitLine.lineStyle.color).toBe('#e2e8f0')

    appStore.setDarkMode(true)
    await flush(8)

    expect(h.setOptionA.mock.calls.length).toBeGreaterThan(1)
    expect(lastPie().series[0].itemStyle.borderColor).toBe('#0f172a')
    expect(lastBar().yAxis.splitLine.lineStyle.color).toBe('rgba(148, 163, 184, 0.25)')
  })

  test('加载期间切换主题：不因图表尚未创建而报错，且首绘即用当前主题', async () => {
    let resolveDash
    h.getDashboard.mockImplementation(
      () =>
        new Promise((r) => {
          resolveDash = r
        })
    )
    h.getAlarms.mockResolvedValue(ALARMS)
    h.getDevices.mockResolvedValue(DEVICES)
    const c = mountComponent(ReportView, {
      routes,
      initialRoute: '/',
      setupStore: (pinia) => {
        useAuthStore(pinia).setPermissions(['report:read'])
        appStore = useAppStore(pinia)
      },
    })
    mounted.push(c)
    await flush(6)

    // 前置条件自检：必须真的是「从亮切到暗」，否则本用例恒真
    expect(appStore.isDarkMode, '初始应为亮色（上一用例的主题残留未清理）').toBe(false)
    appStore.setDarkMode(true)
    expect(appStore.isDarkMode).toBe(true)
    await flush(6)
    // 此时图表实例尚未创建（loading 未结束），watch 回调不应崩
    expect(h.initCount).toBe(0)
    expect(c.errors).toEqual([])

    resolveDash(DASHBOARD)
    await flush(14)

    expect(h.initCount).toBe(2)
    expect(c.errors).toEqual([])
    // 首绘即用当前（暗色）主题，而不是缓存了切换前的亮色值
    expect(lastPie().series[0].itemStyle.borderColor).toBe('#0f172a')
  })
})

describe('ReportView resize 节流与卸载清理', () => {
  test('连续 resize 只触发一次重排（节流生效），且两个图表都重排', async () => {
    await open()
    window.dispatchEvent(new window.Event('resize'))
    window.dispatchEvent(new window.Event('resize'))
    window.dispatchEvent(new window.Event('resize'))
    await flush(4)
    // 定时器未到点：一次都不应发生（证明不是「每次都重排」）
    expect(h.resizeA).not.toHaveBeenCalled()

    await new Promise((r) => setTimeout(r, 200))
    expect(h.resizeA).toHaveBeenCalledTimes(1)
    expect(h.resizeD).toHaveBeenCalledTimes(1)

    // 第二轮：节流标记必须在定时器回调里复位，否则此后每次 resize 都被
    // `if (resizeTimer) return` 永久挡住（首轮之后窗口再也无法自适应）
    window.dispatchEvent(new window.Event('resize'))
    await new Promise((r) => setTimeout(r, 200))
    expect(h.resizeA).toHaveBeenCalledTimes(2)
    expect(h.resizeD).toHaveBeenCalledTimes(2)
  })

  test('卸载：摘除 resize 监听（卸载后再 resize 不再重排）', async () => {
    const c = await open()
    window.dispatchEvent(new window.Event('resize'))
    await new Promise((r) => setTimeout(r, 200))
    expect(h.resizeA).toHaveBeenCalledTimes(1)

    c.handle.unmount()
    mounted.pop()
    window.dispatchEvent(new window.Event('resize'))
    await new Promise((r) => setTimeout(r, 200))
    expect(h.resizeA).toHaveBeenCalledTimes(1)
  })

  test('卸载：清掉挂起的节流定时器（不让已销毁的图表在 100ms 后被 resize）', async () => {
    const c = await open()
    window.dispatchEvent(new window.Event('resize'))
    c.handle.unmount()
    mounted.pop()
    await new Promise((r) => setTimeout(r, 200))
    expect(h.resizeA).not.toHaveBeenCalled()
  })

  test('卸载：销毁两个 echarts 实例（释放 canvas 与事件监听）', async () => {
    const c = await open()
    c.handle.unmount()
    mounted.pop()
    expect(h.disposeA).toHaveBeenCalledTimes(1)
    expect(h.disposeD).toHaveBeenCalledTimes(1)
  })

  test('加载未完成即卸载：不创建图表实例、不抛错（避免在已销毁的 DOM 上初始化）', async () => {
    let resolveDash
    h.getDashboard.mockImplementation(
      () =>
        new Promise((r) => {
          resolveDash = r
        })
    )
    h.getAlarms.mockResolvedValue(ALARMS)
    h.getDevices.mockResolvedValue(DEVICES)
    const c = mountComponent(ReportView, {
      routes,
      initialRoute: '/',
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(['report:read']),
    })
    mounted.push(c)
    await flush(4)
    c.handle.unmount()
    mounted.pop()
    resolveDash(DASHBOARD)
    await flush(16)
    expect(h.initCount).toBe(0)
    expect(h.setOptionA).not.toHaveBeenCalled()
    expect(h.setOptionD).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})

describe('ReportView 快速入口卡片', () => {
  test('四张卡片：前三张跳对应路由，第四张打开导出对话框', async () => {
    const c = await open()
    const cards = c.findAll('.report-card')
    expect(cards).toHaveLength(4)

    click(cards[0])
    await waitNav(c, '/devices')
    click(cards[1])
    await waitNav(c, '/alarms')
    click(cards[2])
    await waitNav(c, '/inspections')

    click(cards[3])
    await waitFor(() => document.body.querySelectorAll('.el-dialog').length > 0, {
      message: '第四张卡片打开导出对话框',
    })
    expect(c.router.currentRoute.value.path).toBe('/inspections')
    expect(c.errors).toEqual([])
  })

  /**
   * 等待 Element Plus 对话框真正关闭。
   *
   * 坑：`v-model` 置 false 后对话框不是立刻消失，而是走 el-overlay 的过渡——
   * jsdom 不会自动推进 CSS 过渡，overlay 的 display:none 要等过渡时长走完
   * （实测约 400ms）。若只断言「元素还在」，关闭逻辑整体失效也测不出来
   * （本文件初版的「取消」用例就栽在这里：无论取消按钮是否生效，重新查询
   * document.body 都能拿到同一个残留节点，断言恒真）。
   */
  const waitClosed = async () => {
    for (let i = 0; i < 60; i += 1) {
      const ov = document.body.querySelector('.el-overlay')
      if (ov && ov.style.display === 'none') return
      await new Promise((r) => setTimeout(r, 25))
    }
    throw new Error('waitClosed 超时：对话框未关闭（overlay 未进入 display:none）')
  }

  const openDialogByButton = async (c) => {
    click(c.findAll('button').find((b) => b.textContent.includes('导出')))
    await waitFor(() => document.body.querySelectorAll('.el-overlay').length > 0, {
      message: '对话框打开',
    })
    return document.body.querySelector('.el-dialog')
  }

  test('右上角 X 关闭对话框：v-model 双向绑定生效（overlay 进入 display:none）', async () => {
    const c = await open()
    await openDialogByButton(c)
    expect(document.body.querySelector('.el-overlay').style.display).not.toBe('none')

    const closeBtn = document.body.querySelector('.el-dialog__headerbtn')
    expect(closeBtn, '未找到对话框关闭按钮').toBeTruthy()
    click(closeBtn)
    await waitClosed()
    expect(c.errors).toEqual([])
  })

  test('取消按钮关闭对话框（不是只关了样式），且重开后类型回到默认 alarms', async () => {
    const c = await open()
    const dlg = await openDialogByButton(c)
    const deviceRadio = Array.from(dlg.querySelectorAll('.el-radio')).find((r) =>
      r.textContent.includes('设备')
    )
    deviceRadio
      .querySelector('input[type="radio"]')
      .dispatchEvent(new window.Event('change', { bubbles: true }))
    await flush(6)
    expect(deviceRadio.querySelector('input').checked).toBe(true)

    const cancelBtn = Array.from(dlg.querySelectorAll('button')).find(
      (b) => b.textContent.trim() === '取消'
    )
    expect(cancelBtn, '未找到取消按钮').toBeTruthy()
    click(cancelBtn)
    await waitClosed()

    await openDialogByButton(c)
    const alarmsRadio = Array.from(document.body.querySelectorAll('.el-dialog .el-radio')).find(
      (r) => r.textContent.includes('报警')
    )
    expect(alarmsRadio.querySelector('input').checked).toBe(true)
    expect(c.errors).toEqual([])
  })
})

describe('ReportView 导出取消语义', () => {
  test('导出被取消（路由切换 abort）：不提示错误，且按钮复位可重试', async () => {
    const c = await open()
    click(c.findAll('button').find((b) => b.textContent.includes('导出')))
    await waitFor(() => document.body.querySelectorAll('.el-dialog').length > 0, {
      message: '对话框打开',
    })
    const dlg = document.body.querySelector('.el-dialog')
    const confirm = Array.from(dlg.querySelectorAll('button')).find((b) =>
      b.textContent.includes('Excel')
    )
    h.exportReport.mockRejectedValue(new Error('canceled'))
    click(confirm)
    await waitFor(() => h.exportReport.mock.calls.length === 1, { message: '导出请求发出' })
    await flush(10)

    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(confirm.disabled).toBe(false)
    expect(document.body.querySelector('.el-dialog')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('导出失败且错误对象无 message：回退到「导出失败」文案，不显示 undefined', async () => {
    const c = await open()
    click(c.findAll('button').find((b) => b.textContent.includes('导出')))
    await waitFor(() => document.body.querySelectorAll('.el-dialog').length > 0, {
      message: '对话框打开',
    })
    const dlg = document.body.querySelector('.el-dialog')
    const confirm = Array.from(dlg.querySelectorAll('button')).find((b) =>
      b.textContent.includes('Excel')
    )
    h.exportReport.mockRejectedValue({})
    click(confirm)
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '错误提示' })
    expect(ElMessage.error.mock.calls[0][0]).toBe('导出失败')
    expect(ElMessage.error.mock.calls[0][0]).not.toContain('undefined')
    expect(c.errors).toEqual([])
  })

  test('设备报表导出：文件名前缀跟随所选类型（不是写死「报警」）', async () => {
    const c = await open()
    click(c.findAll('button').find((b) => b.textContent.includes('导出')))
    await waitFor(() => document.body.querySelectorAll('.el-dialog').length > 0, {
      message: '对话框打开',
    })
    const dlg = document.body.querySelector('.el-dialog')
    const deviceRadio = Array.from(dlg.querySelectorAll('.el-radio')).find((r) =>
      r.textContent.includes('设备')
    )
    deviceRadio
      .querySelector('input[type="radio"]')
      .dispatchEvent(new window.Event('change', { bubbles: true }))
    await flush(6)

    h.exportReport.mockResolvedValue({
      data: new Blob(['x'], { type: 'application/vnd.ms-excel' }),
    })
    const createUrl = vi.spyOn(window.URL, 'createObjectURL').mockReturnValue('blob:x')
    vi.spyOn(window.URL, 'revokeObjectURL').mockImplementation(() => {})
    const clicked = []
    const origCreate = document.createElement.bind(document)
    const createSpy = vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      const el = origCreate(tag)
      if (tag === 'a') el.click = () => clicked.push(el.download)
      return el
    })
    const confirm = Array.from(dlg.querySelectorAll('button')).find((b) =>
      b.textContent.includes('Excel')
    )
    click(confirm)
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '导出成功' })
    expect(clicked).toHaveLength(1)
    expect(clicked[0]).toContain('设备')
    expect(clicked[0]).not.toContain('报警')
    createUrl.mockRestore()
    createSpy.mockRestore()
    expect(c.errors).toEqual([])
  })
})
