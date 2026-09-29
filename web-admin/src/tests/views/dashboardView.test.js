/**
 * DashboardView 行为测试（首屏骨架 / 权限门控 / 数据接线 / 自动刷新 / 失败取消）
 *
 * 组件定位：登录后首页。数据面（统计卡 + 最近报警）在本视图，图表区拆到
 * DashboardCharts 子组件（异步加载，本套件用 stub 替身，专注父视图的接线与门控）。
 *
 * 锁定的真实退化：
 *  1. 骨架屏不退出（loading 永真）→ 首页永远停在占位块；
 *  2. 权限门控（P3-39）：无 report:read / alarm:read / user:read 时既不该请求接口，
 *     也不该渲染该数据块——原实现无差别请求，用户一进首页连吃 403 红框；
 *  3. 统计卡字段映射：devices.total/online、alarms.pending、users.active（缺字段才退 total），
 *     错一个字段 = 首页数字骗人；0 与"字段缺失"必须可区分（见「active 为 0」用例）；
 *  4. 最近报警映射 + 截断到 5 条 + limit=5 请求参数 + 空值兜底；
 *  5. 失败与取消：真实失败提示一次、abort 静默、取消不污染占位值；
 *  6. 自动刷新与可见性：5 分钟定时、页面隐藏不发、卸载后彻底停止。
 *
 * 期望值在本文件内独立计算（本地时区格式化、字面量取数），不 import 被测工具。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h } from 'vue'
import { mountComponent, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

const getDashboard = vi.fn()
const getUserStats = vi.fn()
const getAlarms = vi.fn()
const isCanceledError = vi.fn(() => false)
/** DashboardCharts 的 load() 探针（父级应在定时/可见性恢复/语言切换时各触发一次） */
const chartsLoad = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    reports: { getDashboard: (...a) => getDashboard(...a) },
    users: { getStats: (...a) => getUserStats(...a) },
    alarms: { getList: (...a) => getAlarms(...a) },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))

/**
 * DashboardCharts 替身：真实组件是异步组件且内部会加载 echarts（jsdom 无 canvas，
 * 初始化必然失败），故只保留父视图需要的那部分契约——一个可被 ref 调用的 load()。
 * 以 __esModule 标记 + default 导出，模拟真实 ESM 模块形状（否则 Vue 的
 * defineAsyncComponent 会把命名空间对象当成组件本身）。
 */
vi.mock('@/components/DashboardCharts.vue', () => ({
  __esModule: true,
  default: defineComponent({
    name: 'DashboardChartsStub',
    setup(_, { expose }) {
      expose({ load: (...a) => chartsLoad(...a) })
      return () => h('div', { class: 'dashboard-charts-stub' })
    },
  }),
}))

vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import DashboardView from '@/views/DashboardView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

const ALL = ['report:read', 'user:read', 'alarm:read']

/**
 * 独立计算 ISO → 本地时区「YYYY-MM-DD HH:mm:ss」定长串（与实现无关的口径）。
 *
 * 不使用 toLocaleString：其输出会随 locale 改变月/日顺序与分隔符，把当前格式
 * 写成期望值会掩盖「时间格式随界面语言漂移」这类退化。
 */
const localStamp = (iso) => {
  const d = new Date(iso)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const okDashboard = (data = {}) => ({
  data: {
    success: true,
    data: { devices: { total: 10, online: 7 }, alarms: { pending: 3 }, ...data },
  },
})

const okUsers = (data = { active: 4, total: 9 }) => ({ data: { data } })

const alarmRow = (over = {}) => ({
  occurredAt: '2026-10-01T01:00:00.000Z',
  location: { building: 'A栋', floor: '3层', room: '配电室' },
  alarmType: 'smoke',
  level: 'critical',
  status: 'pending',
  ...over,
})

const stubDefaults = () => {
  getDashboard.mockResolvedValue(okDashboard())
  getUserStats.mockResolvedValue(okUsers())
  getAlarms.mockResolvedValue({ data: { data: [] } })
  chartsLoad.mockReset()
}

/** 挂载并等首屏数据落地（is-loaded）与异步图表组件挂载完成（越过 loadingComponent 占位） */
const open = async (perms, opts = {}) => {
  stubDefaults()
  if (opts.dashboard) getDashboard.mockResolvedValue(opts.dashboard)
  if (opts.users) getUserStats.mockResolvedValue(opts.users)
  if (opts.alarms) getAlarms.mockResolvedValue(opts.alarms)
  if (opts.dashboardReject) getDashboard.mockRejectedValue(opts.dashboardReject)
  if (opts.usersReject) getUserStats.mockRejectedValue(opts.usersReject)
  if (opts.alarmsReject) getAlarms.mockRejectedValue(opts.alarmsReject)
  active = mountComponent(DashboardView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
    locale: opts.locale || 'zh-CN',
  })
  await waitFor(() => active.find('.dashboard').classList.contains('is-loaded'), {
    message: '首屏加载完成',
  })
  if (perms.includes('report:read')) {
    await waitFor(() => active.findAll('.dashboard-charts-stub').length === 1, {
      message: '异步图表组件挂载',
    })
  }
  await flush(25)
  return active
}

const statValues = (c) => c.findAll('.stat-value').map((x) => x.textContent.trim())
const statTitles = (c) => c.findAll('.stat-title').map((x) => x.textContent.trim())
const alarmRows = (c) => c.findAll('.alarm-card .el-table__body-wrapper .el-table__row')
const alarmCells = (c) =>
  alarmRows(c).map((tr) =>
    Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.replace(/\s+/g, ' ').trim())
  )
const alarmTags = (c) =>
  c
    .findAll('.alarm-card .el-tag')
    .map(
      (t) =>
        t.className.match(/el-tag--(danger|warning|info|success)/)[1] + ':' + t.textContent.trim()
    )

/** jsdom 的 visibilityState 是原型 getter，必须用 defineProperty 覆写（delete 可还原） */
const vis = (v) =>
  Object.defineProperty(document, 'visibilityState', { value: v, configurable: true })

afterEach(() => {
  active?.handle.unmount()
  active = null
  getDashboard.mockReset()
  getUserStats.mockReset()
  getAlarms.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  chartsLoad.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  i18n.global.locale.value = 'zh-CN'
  delete document.visibilityState
  vi.useRealTimers()
})

describe('DashboardView 骨架屏 → 内容直换', () => {
  test('首屏渲染同构骨架（欢迎/4 统计/2 图表/表格），数据到达后骨架退场、真实内容直换', async () => {
    let release
    getDashboard.mockImplementation(() => new Promise((r) => (release = r)))
    getUserStats.mockResolvedValue(okUsers())
    getAlarms.mockResolvedValue({ data: { data: [] } })
    active = mountComponent(DashboardView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL),
    })
    await flush(6)
    // 骨架阶段：四类占位齐全，真实内容标记一个都不在（骨架与真实内容同名卡片壳不参与判定）
    expect(active.find('.dashboard').classList.contains('is-loading')).toBe(true)
    expect(active.findAll('.glass-skeleton').map((x) => x.className)).toEqual([
      'glass-skeleton glass-skeleton--welcome',
      'glass-skeleton glass-skeleton--stat',
      'glass-skeleton glass-skeleton--stat',
      'glass-skeleton glass-skeleton--stat',
      'glass-skeleton glass-skeleton--stat',
      'glass-skeleton glass-skeleton--chart',
      'glass-skeleton glass-skeleton--chart',
      'glass-skeleton glass-skeleton--table',
    ])
    // 骨架表格与真实列表同构：表头 1 行 + 5 行数据占位
    expect(active.findAll('.gs-table__row')).toHaveLength(6)
    expect(statValues(active)).toEqual([])
    expect(active.findAll('.welcome-content')).toEqual([])
    expect(active.findAll('.alarm-card .el-table')).toEqual([])
    expect(active.findAll('.dashboard-charts-stub')).toEqual([])
    release(okDashboard())
    await waitFor(() => active.find('.dashboard').classList.contains('is-loaded'), {
      message: '内容直换',
    })
    await waitFor(() => active.findAll('.dashboard-charts-stub').length === 1, {
      message: '图表组件挂载',
    })
    await flush(10)
    // 内容到达：骨架全部退场，真实结构就位（含统计数值与报警表格）
    expect(active.findAll('.glass-skeleton')).toEqual([])
    expect(active.findAll('.welcome-content')).toHaveLength(1)
    expect(statValues(active)).toEqual(['10', '7', '3', '4'])
    expect(active.findAll('.alarm-card .el-table')).toHaveLength(1)
    expect(active.errors).toEqual([])
  })

  test('加载失败也必须退出骨架（否则首页永远停在占位）；提示归拦截器，组件不弹（P2-3）', async () => {
    getDashboard.mockRejectedValue(new Error('boom'))
    getUserStats.mockResolvedValue(okUsers())
    getAlarms.mockResolvedValue({ data: { data: [] } })
    active = mountComponent(DashboardView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL),
    })
    // 失败路径的稳定终态是「骨架退场」：loading 初值为 true，只有 try/catch 走完才会
    // 被置 false，单调不可逆。不能改等「统计卡回落到 -」——那是初始态，会立刻成立。
    await waitFor(() => !active.find('.dashboard').classList.contains('is-loading'), {
      message: '骨架退场',
    })
    await waitFor(() => active.findAll('.dashboard-charts-stub').length === 1, {
      message: '图表组件挂载',
    })
    await flush(10)
    // 契约对齐 alarmView：加载失败只清态，提示由 api.js 响应拦截器统一负责。
    // 本套件把 @/utils/api 整体替身掉，拦截器不参与 ⇒ 这里必须恰好 0 次。
    expect(ElMessage.error).not.toHaveBeenCalled()
    // 骨架占位（含异步图表区的 loadingComponent）必须全部让位
    expect(active.findAll('.glass-skeleton')).toEqual([])
    // 失败后统计卡保留占位值 -（而不是伪造 0）
    expect(statValues(active)).toEqual(['-', '-', '-', '-'])
    expect(active.errors).toEqual([])
  })

  test('success=false 的响应不覆盖占位值（不把 - 变成 0）', async () => {
    const c = await open(ALL, { dashboard: { data: { success: false, data: {} } } })
    expect(statValues(c)).toEqual(['-', '-', '-', '-'])
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('切换语言后统计卡标题实时跟随（zh → en 字面量）', async () => {
    const c = await open(ALL)
    expect(statTitles(c)).toEqual(['设备总数', '在线设备', '待处理报警', '系统用户'])
    i18n.global.locale.value = 'en-US'
    await flush(30)
    expect(statTitles(c)).toEqual([
      'Total Devices',
      'Online Devices',
      'Pending Alarms',
      'System Users',
    ])
  })
})

describe('DashboardView 统计卡数据接线', () => {
  test('字段映射：设备总数/在线设备/待处理报警/系统用户（active 优先于 total）', async () => {
    const c = await open(ALL, {
      dashboard: okDashboard({ devices: { total: 12, online: 8 }, alarms: { pending: 5 } }),
      users: okUsers({ active: 6, total: 20 }),
    })
    expect(statValues(c)).toEqual(['12', '8', '5', '6'])
    expect(c.errors).toEqual([])
  })

  test('active 为 0（全部账号停用/锁定）必须显示 0，不得退回 total 报喜', async () => {
    // 反向用例：`active || total` 下这一格会显示 20 —— "0 个可用账号"被读成"20 个"。
    // 只有把 0 与字段缺失区分开（?? 而非 ||）才可能绿。
    const c = await open(ALL, { users: okUsers({ active: 0, total: 20 }) })
    expect(statValues(c)).toEqual(['10', '7', '3', '0'])
    expect(c.errors).toEqual([])
  })

  test('用户统计缺 active 时退回 total（且不影响其余三张卡）', async () => {
    const c = await open(ALL, { users: okUsers({ total: 20 }) })
    expect(statValues(c)).toEqual(['10', '7', '3', '20'])
  })

  test('后端字段缺失按 0 兜底（不是 undefined / NaN / 空白）', async () => {
    const c = await open(ALL, {
      dashboard: { data: { success: true, data: {} } },
      users: { data: { data: {} } },
    })
    expect(statValues(c)).toEqual(['0', '0', '0', '0'])
    expect(c.errors).toEqual([])
  })

  test('无趋势文案时不渲染趋势图标（孤立箭头会被误读为指标下跌；不得出现 undefined 字样）', async () => {
    const c = await open(ALL)
    expect(c.findAll('.stat-trend .el-icon')).toEqual([])
    expect(c.findAll('.stat-trend').map((x) => x.textContent.trim())).toEqual(['', '', '', ''])
    expect(c.text()).not.toContain('undefined')
  })
})

describe('DashboardView 请求新鲜度守卫（定时/可见性恢复交叠）', () => {
  test('在途期间触发第二次刷新：旧响应后返回时不得覆盖新值（统计卡）', async () => {
    let call = 0
    getDashboard.mockImplementation(() => {
      call += 1
      // 第一次慢（900ms），第二次快 —— 旧响应必定后到
      if (call === 1)
        return new Promise((r) =>
          setTimeout(
            () =>
              r(okDashboard({ devices: { total: 111, online: 111 }, alarms: { pending: 111 } })),
            900
          )
        )
      return Promise.resolve(
        okDashboard({ devices: { total: 222, online: 222 }, alarms: { pending: 222 } })
      )
    })
    getUserStats.mockResolvedValue(okUsers())
    getAlarms.mockResolvedValue({ data: { data: [] } })
    active = mountComponent(DashboardView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL),
    })
    await flush(10)
    // 首次请求仍在途时，模拟「页面恢复可见」再次触发刷新（第二次立即返回 222）
    document.dispatchEvent(new window.Event('visibilitychange'))
    // 等旧响应（111）到达且首屏 finally 落地：若无新鲜度守卫，111 会覆盖 222
    await new Promise((r) => setTimeout(r, 1000))
    await waitFor(() => active.find('.dashboard').classList.contains('is-loaded'), {
      message: '首屏加载完成',
    })
    await flush(15)
    expect(statValues(active).slice(0, 3)).toEqual(['222', '222', '222'])
    expect(call).toBe(2)
    expect(active.errors).toEqual([])
  })

  test('在途期间触发第二次刷新：旧响应后返回时不得覆盖新值（最近报警表）', async () => {
    let call = 0
    getAlarms.mockImplementation(() => {
      call += 1
      const row = alarmRow({ location: { building: call === 1 ? '旧楼' : '新楼' } })
      if (call === 1) return new Promise((r) => setTimeout(() => r({ data: { data: [row] } }), 900))
      return Promise.resolve({ data: { data: [row] } })
    })
    getDashboard.mockResolvedValue(okDashboard())
    getUserStats.mockResolvedValue(okUsers())
    active = mountComponent(DashboardView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL),
    })
    await flush(10)
    document.dispatchEvent(new window.Event('visibilitychange'))
    await new Promise((r) => setTimeout(r, 1000))
    await waitFor(() => active.find('.dashboard').classList.contains('is-loaded'), {
      message: '首屏加载完成',
    })
    await flush(15)
    expect(alarmCells(active)[0][1]).toBe('新楼')
    expect(call).toBe(2)
    expect(active.errors).toEqual([])
  })

  test('两次刷新互不串扰：统计与报警各自持守卫，后发者胜出且只在各自数据面生效', async () => {
    getDashboard.mockImplementation(() => {
      return new Promise((r) =>
        setTimeout(
          () => r(okDashboard({ devices: { total: 333, online: 333 }, alarms: { pending: 333 } })),
          200
        )
      )
    })
    getAlarms.mockResolvedValue({ data: { data: [alarmRow()] } })
    getUserStats.mockResolvedValue(okUsers())
    active = mountComponent(DashboardView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL),
    })
    await new Promise((r) => setTimeout(r, 400))
    await flush(15)
    expect(statValues(active).slice(0, 3)).toEqual(['333', '333', '333'])
    expect(alarmRows(active)).toHaveLength(1)
    expect(active.errors).toEqual([])
  })
})
describe('DashboardView 权限门控（P3-39：无权限不请求、不渲染）', () => {
  test('无任何权限：三个接口都不请求，数据块全部不渲染，欢迎卡仍在且无错误提示', async () => {
    const c = await open([])
    expect(getDashboard).not.toHaveBeenCalled()
    expect(getUserStats).not.toHaveBeenCalled()
    expect(getAlarms).not.toHaveBeenCalled()
    expect(statValues(c)).toEqual([])
    expect(c.findAll('.dashboard-charts-stub')).toEqual([])
    expect(c.findAll('.charts-async-skeleton')).toEqual([])
    expect(c.findAll('.alarm-card')).toEqual([])
    expect(c.findAll('.welcome-content')).toHaveLength(1)
    expect(c.findAll('.glass-skeleton')).toEqual([])
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('仅 report:read：只请求 dashboard，统计卡与图表渲染，报警卡片不渲染（第四卡未知占位 - 不请求 users）', async () => {
    const c = await open(['report:read'])
    expect(getDashboard).toHaveBeenCalledTimes(1)
    expect(getUserStats).not.toHaveBeenCalled()
    expect(getAlarms).not.toHaveBeenCalled()
    // 第四卡必须是"未知"而不是 0：没有 user:read 时这一格压根没取数，
    // 显示 0 等于向值班人员宣称"系统里没有用户"。
    expect(statValues(c)).toEqual(['10', '7', '3', '-'])
    expect(statValues(c)[3]).not.toBe('0')
    expect(c.findAll('.dashboard-charts-stub')).toHaveLength(1)
    expect(c.findAll('.alarm-card')).toEqual([])
  })

  test('report:read + user:read：users 统计并入第四卡，仍不请求 alarms', async () => {
    const c = await open(['report:read', 'user:read'])
    expect(getDashboard).toHaveBeenCalledTimes(1)
    expect(getUserStats).toHaveBeenCalledTimes(1)
    expect(getAlarms).not.toHaveBeenCalled()
    expect(statValues(c)).toEqual(['10', '7', '3', '4'])
    expect(c.findAll('.alarm-card')).toEqual([])
  })

  test('仅 alarm:read：只请求 alarms（limit=5），报警卡片渲染且无统计卡/图表', async () => {
    const c = await open(['alarm:read'], { alarms: { data: { data: [alarmRow()] } } })
    expect(getDashboard).not.toHaveBeenCalled()
    expect(getUserStats).not.toHaveBeenCalled()
    expect(getAlarms).toHaveBeenCalledTimes(1)
    expect(getAlarms).toHaveBeenCalledWith({ limit: 5 })
    expect(statValues(c)).toEqual([])
    expect(c.findAll('.dashboard-charts-stub')).toEqual([])
    await waitFor(() => alarmCells(c).length === 1 && alarmCells(c)[0].length === 4, {
      message: '报警行渲染',
    })
    expect(alarmCells(c)[0]).toEqual([
      localStamp('2026-10-01T01:00:00.000Z'),
      'A栋 3层 配电室',
      '烟雾报警',
      '待处理',
    ])
  })
})

describe('DashboardView 最近报警映射与截断', () => {
  test('四列逐格映射：本地化时间/位置空格拼装/类型与状态词表、标签色逐行落地', async () => {
    const iso1 = '2026-10-01T01:00:00.000Z'
    const iso2 = '2026-10-02T02:30:00.000Z'
    const c = await open(['alarm:read'], {
      alarms: {
        data: {
          data: [
            alarmRow({
              occurredAt: iso1,
              alarmType: 'smoke',
              level: 'critical',
              status: 'pending',
            }),
            alarmRow({
              occurredAt: iso2,
              location: { building: 'B栋' },
              alarmType: 'temp_abnormal',
              level: 'warning',
              status: 'processing',
            }),
          ],
        },
      },
    })
    await waitFor(() => alarmCells(c).length === 2 && alarmCells(c)[1].length === 4, {
      message: '两行报警渲染',
    })
    expect(c.findAll('.alarm-card .el-table__header th').map((x) => x.textContent.trim())).toEqual([
      '创建时间',
      '报警位置',
      '报警类型',
      '状态',
    ])
    expect(alarmCells(c)).toEqual([
      [localStamp(iso1), 'A栋 3层 配电室', '烟雾报警', '待处理'],
      [localStamp(iso2), 'B栋', '温度异常', '处理中'],
    ])
    // 本地化自检：不得是 ISO 原串直渲染
    expect(alarmCells(c)[0][0]).not.toContain('T')
    // 每行两个标签：类型在前、状态在后
    expect(alarmTags(c)).toEqual([
      'danger:烟雾报警',
      'danger:待处理',
      'warning:温度异常',
      'warning:处理中',
    ])
    expect(c.errors).toEqual([])
  })

  test('请求 limit=5 且后端多返回（7 条）时只保留前 5 条并按序渲染', async () => {
    const rows = Array.from({ length: 7 }, (_, i) =>
      alarmRow({
        location: { building: '楼' + (i + 1) },
        alarmType: 'other',
        level: 'info',
        status: 'pending',
      })
    )
    const c = await open(['alarm:read'], { alarms: { data: { data: rows } } })
    await waitFor(() => alarmCells(c).length === 5 && alarmCells(c)[4].length === 4, {
      message: '截断后 5 行渲染',
    })
    expect(getAlarms).toHaveBeenCalledTimes(1)
    expect(getAlarms).toHaveBeenCalledWith({ limit: 5 })
    expect(alarmCells(c).map((r) => r[1])).toEqual(['楼1', '楼2', '楼3', '楼4', '楼5'])
    expect(alarmCells(c).map((r) => r[2])).toEqual(['其他', '其他', '其他', '其他', '其他'])
  })

  test('最近报警时间格式不随界面语言漂移（O-3 定长口径）', async () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const c = await open(ALL, { alarms: { data: { data: [alarmRow({ occurredAt: iso })] } } })
    const before = alarmCells(c)[0][0]
    expect(before).toBe(localStamp(iso))
    i18n.global.locale.value = 'en-US'
    await flush(30)
    expect(alarmCells(c)[0][0]).toBe(before)
    // 反证：同一次切换里表头确实变成英文（否则上面的恒定断言可能是恒真）
    const headers = () =>
      c.findAll('.alarm-card .el-table__header th').map((th) => th.textContent.trim())
    expect(headers()).toContain('Location')
    expect(headers()).not.toContain('报警位置')
    i18n.global.locale.value = 'zh-CN'
    await flush(30)
  })
  test('边界兜底：时间/location 缺失为空串（不是 Invalid Date/undefined），未知枚举原样回退', async () => {
    const c = await open(['alarm:read'], {
      alarms: {
        data: {
          data: [
            alarmRow({
              occurredAt: null,
              location: { building: 'B栋' },
              alarmType: 'weird',
              level: 'low',
              status: 'mystery',
            }),
            alarmRow({ location: null }),
            alarmRow({
              location: {},
              alarmType: 'temp_abnormal',
              level: 'warning',
              status: 'processing',
            }),
            alarmRow({
              location: { floor: '2层' },
              alarmType: 'notexist',
              level: 'emergency',
              status: 'resolved',
            }),
          ],
        },
      },
    })
    await waitFor(() => alarmCells(c).length === 4 && alarmCells(c)[3].length === 4, {
      message: '边界行渲染',
    })
    const rows = alarmCells(c)
    // 时间缺失 → 空串（不渲染 Invalid Date / undefined）
    expect(rows[0][0]).toBe('')
    expect(c.text()).not.toContain('Invalid Date')
    expect(c.text()).not.toContain('undefined')
    // location 为 null / {} → 空串（单条脏数据不得让整表抛错清空）
    expect(rows[1][1]).toBe('')
    expect(rows[2][1]).toBe('')
    expect(rows[3][1]).toBe('2层')
    // 未知类型/状态原样回退，未知 level 标签为 info
    expect(rows[0][2]).toBe('weird')
    expect(rows[0][3]).toBe('mystery')
    expect(rows[2][2]).toBe('温度异常')
    expect(rows[3][3]).toBe('已处理')
    expect(rows[3][2]).toBe('notexist')
    expect(alarmTags(c)).toEqual([
      'info:weird',
      'info:mystery',
      'danger:烟雾报警',
      'danger:待处理',
      'warning:温度异常',
      'warning:处理中',
      'danger:notexist',
      'success:已处理',
    ])
  })
})

describe('DashboardView 自动刷新与可见性', () => {
  test('每 5 分钟自动刷新统计与最近报警并重载图表（精确到 5 分钟边界）', async () => {
    vi.useFakeTimers()
    const c = await open(ALL)
    const base = {
      d: getDashboard.mock.calls.length,
      u: getUserStats.mock.calls.length,
      a: getAlarms.mock.calls.length,
      ch: chartsLoad.mock.calls.length,
    }
    expect(base.d).toBe(1)
    expect(base.u).toBe(1)
    expect(base.a).toBe(1)
    // 差 1ms 不足 5 分钟：一次都不该刷（防定时周期被改短）
    vi.advanceTimersByTime(5 * 60 * 1000 - 1)
    await flush(10)
    expect(getDashboard.mock.calls.length).toBe(base.d)
    expect(getAlarms.mock.calls.length).toBe(base.a)
    // 跨过 5 分钟：三个数据面各刷新一次
    vi.advanceTimersByTime(1)
    await waitFor(() => getDashboard.mock.calls.length === base.d + 1, { message: '定时刷新' })
    await flush(20)
    expect(getUserStats.mock.calls.length).toBe(base.u + 1)
    expect(getAlarms.mock.calls.length).toBe(base.a + 1)
    expect(chartsLoad.mock.calls.length).toBe(base.ch + 1)
    expect(c.errors).toEqual([])
    // 页面隐藏后到点：定时回调必须跳过（防浏览器后台无谓轮询）
    const hiddenBase = {
      d: getDashboard.mock.calls.length,
      u: getUserStats.mock.calls.length,
      a: getAlarms.mock.calls.length,
      ch: chartsLoad.mock.calls.length,
    }
    vis('hidden')
    vi.advanceTimersByTime(5 * 60 * 1000)
    await flush(20)
    expect(getDashboard.mock.calls.length).toBe(hiddenBase.d)
    expect(getUserStats.mock.calls.length).toBe(hiddenBase.u)
    expect(getAlarms.mock.calls.length).toBe(hiddenBase.a)
    expect(chartsLoad.mock.calls.length).toBe(hiddenBase.ch)
    // 恢复可见后再到点：恢复正常刷新（证明跳过只针对隐藏态，不是定时器被拆）
    vis('visible')
    vi.advanceTimersByTime(5 * 60 * 1000)
    await waitFor(() => getDashboard.mock.calls.length === hiddenBase.d + 1, {
      message: '恢复可见后定时刷新',
    })
    await flush(20)
    expect(getAlarms.mock.calls.length).toBe(hiddenBase.a + 1)
    expect(chartsLoad.mock.calls.length).toBe(hiddenBase.ch + 1)
  })

  test('页面隐藏时不刷新；恢复可见立即刷新统计/报警并重载图表', async () => {
    const c = await open(ALL)
    const base = {
      d: getDashboard.mock.calls.length,
      a: getAlarms.mock.calls.length,
      ch: chartsLoad.mock.calls.length,
    }
    vis('hidden')
    document.dispatchEvent(new Event('visibilitychange'))
    await flush(20)
    expect(getDashboard.mock.calls.length).toBe(base.d)
    expect(getAlarms.mock.calls.length).toBe(base.a)
    expect(chartsLoad.mock.calls.length).toBe(base.ch)
    vis('visible')
    document.dispatchEvent(new Event('visibilitychange'))
    await waitFor(() => getDashboard.mock.calls.length === base.d + 1, { message: '可见后刷新' })
    await flush(20)
    expect(getAlarms.mock.calls.length).toBe(base.a + 1)
    expect(chartsLoad.mock.calls.length).toBe(base.ch + 1)
    expect(c.errors).toEqual([])
  })

  test('卸载后定时器与可见性监听都停止（不再发任何请求）', async () => {
    vi.useFakeTimers()
    const c = await open(ALL)
    const base = {
      d: getDashboard.mock.calls.length,
      a: getAlarms.mock.calls.length,
      ch: chartsLoad.mock.calls.length,
    }
    c.handle.unmount()
    active = null
    // 显式置 visible：若 clearInterval 被移除，未清理的定时器会在这里立刻发请求
    vis('visible')
    vi.advanceTimersByTime(10 * 60 * 1000)
    document.dispatchEvent(new Event('visibilitychange'))
    await flush(20)
    expect(getDashboard.mock.calls.length).toBe(base.d)
    expect(getAlarms.mock.calls.length).toBe(base.a)
    expect(chartsLoad.mock.calls.length).toBe(base.ch)
  })
})

describe('DashboardView 失败与取消路径', () => {
  test('路由取消（abort）：不弹假错误提示，统计卡保持占位，页面无 Vue 错误', async () => {
    isCanceledError.mockReturnValue(true)
    const canceled = Object.assign(new Error('canceled'), { code: 'ERR_CANCELED' })
    const c = await open(ALL, { dashboardReject: canceled, alarmsReject: canceled })
    await flush(20)
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.warning).not.toHaveBeenCalled()
    expect(statValues(c)).toEqual(['-', '-', '-', '-'])
    expect(alarmRows(c)).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('最近报警加载失败：卡片保留空表、统计卡不受牵连；提示归拦截器，组件不弹（P2-3）', async () => {
    const c = await open(ALL, { alarmsReject: new Error('alarms down') })
    // 可等待的终态是主加载成功（统计卡由 - 占位变成真实读数，单调不可逆）。
    // 报警那一路失败后**不再改任何状态**（提示归拦截器），因此没有状态变化可等，
    // 只能等主加载落地后额外 flush，再断言它的副作用边界。
    await waitFor(() => statValues(c)[0] === '10', { message: '统计卡已填充' })
    await flush(10)
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(statValues(c)).toEqual(['10', '7', '3', '4'])
    expect(alarmRows(c)).toEqual([])
    expect(c.findAll('.alarm-card .el-table')).toHaveLength(1)
    expect(c.errors).toEqual([])
  })

  test('用户统计失败：不弹错（其余数据源已成功），第四卡回落到未知占位 -', async () => {
    const c = await open(ALL, { usersReject: new Error('users down') })
    await flush(20)
    expect(ElMessage.error).not.toHaveBeenCalled()
    // 前三个卡来自 dashboard 接口，这一路是成功的：一个数据源失败不得把它们的
    // 真实读数一起冲掉（否则局部故障在界面上表现成"全站没数据"）。
    expect(statValues(c)).toEqual(['10', '7', '3', '-'])
    expect(statValues(c)[3]).not.toBe('0')
    expect(c.errors).toEqual([])
  })

  test('语言切换触发三个数据源各重取一次并重载图表（无重复请求）', async () => {
    const c = await open(ALL)
    const base = {
      d: getDashboard.mock.calls.length,
      u: getUserStats.mock.calls.length,
      a: getAlarms.mock.calls.length,
      ch: chartsLoad.mock.calls.length,
    }
    expect(base.d).toBe(1)
    expect(base.u).toBe(1)
    expect(base.a).toBe(1)
    i18n.global.locale.value = 'en-US'
    await waitFor(() => getDashboard.mock.calls.length === base.d + 1, { message: '语言切换重取' })
    await flush(25)
    expect(getUserStats.mock.calls.length).toBe(base.u + 1)
    expect(getAlarms.mock.calls.length).toBe(base.a + 1)
    expect(chartsLoad.mock.calls.length).toBe(base.ch + 1)
    expect(c.errors).toEqual([])
  })
})
