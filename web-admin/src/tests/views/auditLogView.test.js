/**
 * AuditLogView 组件级行为测试（2026-09-18）
 *
 * 覆盖行为面：列表加载与渲染（时间列本地时区口径、风险/日志等级派生、行着色、
 * 双行单元格、请求列占位）、筛选参数构建（含「清空 success 不得变成空串」边界）、
 * 分页、加载失败与竞态守卫、统计卡、导出（权限门控 / 参数即所见 / 截断提示 /
 * 进行中禁用）、详情对话框条件字段。
 *
 * 已存在 auditLogExportJsonError.test.js 覆盖「导出响应体是 JSON 错误」的解析分支，
 * 本文件不重复该行为面（那边用源码抽取 + 注入依赖，这边走真实挂载链路）。
 *
 * 期望值一律在本文件内独立计算（Date 本地 getter / DOM 文本数字段），
 * 不 import 被测源码的工具函数，避免实现写错时两边一起错、断言恒真。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const get = vi.fn()
const isCanceledError = vi.fn(() => false)
vi.mock('@/utils/api', () => ({
  apiClient: { get: (...a) => get(...a), post: vi.fn(), delete: vi.fn() },
  isCanceledError: (...a) => isCanceledError(...a),
  resolveErrorMessage: () => '码化文案',
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: vi.fn() },
}))

import AuditLogView from '@/views/AuditLogView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

const XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
const PERMS = ['report:export', 'security:audit']
let active = null

const logRow = (over = {}) => ({
  _id: 'r1',
  timestamp: '2026-10-01T01:00:00.000Z',
  username: 'alice',
  ip: '10.0.0.9',
  action: 'auth_login',
  category: 'auth',
  riskLevel: 'low',
  success: true,
  ...over,
})

const mountView = (perms = PERMS) => {
  active = mountComponent(AuditLogView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
  return active
}

const logCalls = () => get.mock.calls.filter((c) => c[0] === '/security/audit-logs')
const lastParams = () => logCalls()[logCalls().length - 1][1].params
const trs = (c) => c.findAll('.el-table__body-wrapper .el-table__row')
const td = (c, r, col) => Array.from(trs(c)[r].querySelectorAll('td'))[col]
const totalDigits = (c) => c.find('.el-pagination__total').textContent.replace(/[^0-9]/g, '')

/**
 * 期望值独立计算（不调用被测实现）：本地时区的「YYYY-MM-DD HH:mm:ss」定长串。
 *
 * 口径由 utils/datetime.formatTime 统一（O-3 单一事实来源）：本地时区、各段补零、
 * **不随界面语言变化**。此前该视图走 toLocaleString(locale)，切语言会改变分隔符与
 * 月日顺序（实测 zh="2026/10/1 09:00:00" vs en="10/1/2026, 09:00:00"），现已修复，
 * 故这里收紧为精确串断言——格式漂移必须红。
 */
const localStamp = (iso) => {
  const d = new Date(iso)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/**
 * 断言单元格渲染的是本地定长时间串。
 *
 * 前提自检（时区无关）：原样 ISO 串必然与本地定长串不同（含 T/Z 且 14:00Z 类 vs
 * 带空格本地串），若实现改成直渲染原始串，下面的 not.toBe 会先失败。
 * 注：当运行环境 TZ=UTC 时，「本地 == UTC」不可观测，此时本函数只钉格式契约
 * （补零 / 空格分隔 / 定长），不宣称验证了时区换算——不编造恒真断言。
 */
const expectLocalTime = (cell, iso) => {
  const expected = localStamp(iso)
  expect(expected).not.toBe(iso)
  expect(cell).toBe(expected)
}

/** 挂载并等待列表与统计请求落地 */
const openList = async (list, meta, perms = PERMS) => {
  get.mockImplementation((url) => {
    if (url === '/security/audit-logs') {
      return Promise.resolve({
        data: { data: { data: list, meta: meta || { total: list.length } } },
      })
    }
    if (url === '/security/overview') {
      return Promise.resolve({
        data: { data: { criticalAlerts: 2, highAlerts: 3, failedLogins: 4 } },
      })
    }
    return Promise.reject(new Error('unexpected url: ' + url))
  })
  const c = mountView(perms)
  await waitFor(() => logCalls().length >= 1, { message: '审计日志列表请求已发出' })
  await waitFor(() => trs(c).length === list.length, { message: '日志行渲染完成' })
  await flush(3)
  return c
}

/**
 * 打开 el-select 并点选指定文案的选项。
 * 用 aria-controls 精确关联该 select 自己的 listbox：页面同时存在多个 select
 * （且 popper 惰性创建），全局查找会点到别的下拉项，测试变成碰运气。
 */
const pickOption = async (wrapper, label) => {
  click(wrapper)
  await flush(6)
  const combo = wrapper.querySelector('input[role=combobox]')
  expect(combo).toBeTruthy()
  const listbox = Array.from(document.body.querySelectorAll('[role=listbox]')).find(
    (lb) => lb.id === combo.getAttribute('aria-controls')
  )
  expect(listbox).toBeTruthy()
  const option = Array.from(listbox.querySelectorAll('.el-select-dropdown__item')).find(
    (o) => o.textContent.trim() === label
  )
  expect(option).toBeTruthy()
  click(option)
  await flush(8)
}

const pickSelect = (c, index, label) => pickOption(c.findAll('.el-select__wrapper')[index], label)

/** 点某个 el-select 的清除图标（需先让输入框处于 hover/聚焦态才会渲染出来） */
const clearSelect = async (wrapper) => {
  wrapper.dispatchEvent(new window.MouseEvent('mouseenter', { bubbles: true }))
  await flush(2)
  const clearEl = wrapper.querySelector('.el-select__clear')
  expect(clearEl).toBeTruthy()
  click(clearEl)
  await flush(8)
}

/** 打开某一行的详情对话框（操作列是 fixed 列，渲染时机晚于普通列） */
const openDetail = async (list) => {
  const c = await openList(list)
  await waitFor(() => c.findAll('.el-table__body-wrapper .glass-btn--link').length === 1, {
    message: '行操作按钮渲染完成',
  })
  click(c.findAll('.el-table__body-wrapper .glass-btn--link')[0])
  await waitFor(() => document.body.querySelectorAll('.el-dialog').length === 1, {
    message: '详情对话框打开',
  })
  await flush(8)
  return c
}

/** 详情对话框的「标签::值」序列（对话框 append-to-body，须查 document.body） */
const descPairs = () => {
  const labels = Array.from(document.body.querySelectorAll('.el-descriptions__label')).map((e) =>
    e.textContent.trim()
  )
  const values = Array.from(document.body.querySelectorAll('.el-descriptions__content')).map((e) =>
    e.textContent.trim()
  )
  return labels.map((l, i) => l + '::' + values[i])
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  get.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  window.localStorage.clear()
})

describe('AuditLogView 列表加载与渲染', () => {
  test('挂载即并行请求列表与统计：分页 total 与四张统计卡取值正确', async () => {
    const c = await openList([logRow()], { total: 33 })
    expect(logCalls()).toHaveLength(1)
    expect(logCalls()[0][1].params).toEqual({ page: 1, limit: 20 })
    expect(get.mock.calls.filter((x) => x[0] === '/security/overview')).toHaveLength(1)
    expect(c.findAll('.stat-value').map((e) => e.textContent.trim())).toEqual(['2', '3', '4', '33'])
    expect(totalDigits(c)).toBe('33')
    expect(c.errors).toEqual([])
  })

  test('时间列按本地时区渲染「YYYY-MM-DD HH:mm:ss」定长串（不是 ISO 原串）', async () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const c = await openList([logRow({ timestamp: iso })])
    const cell = td(c, 0, 0).textContent.trim()
    expect(cell).not.toBe(iso)
    expect(cell).not.toContain('T')
    expect(cell).not.toContain('Z')
    expectLocalTime(cell, iso)
  })

  test('非法时间戳渲染 -：不得出现 Invalid Date 或 NaN', async () => {
    const c = await openList([logRow({ timestamp: 'not-a-date' })])
    const cell = td(c, 0, 0).textContent.trim()
    expect(cell).toBe('-')
    expect(cell).not.toContain('Invalid')
    expect(cell).not.toContain('NaN')
  })

  test('切换界面语言后时间列格式不变（格式不得随 locale 漂移）', async () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const c = await openList([logRow({ timestamp: iso })])
    const before = td(c, 0, 0).textContent.trim()
    expectLocalTime(before, iso)
    i18n.global.locale.value = 'en-US'
    await flush(6)
    expect(td(c, 0, 0).textContent.trim()).toBe(before)
    i18n.global.locale.value = 'zh-CN'
  })

  test('时间缺失时渲染 -（不是空串/undefined/1970）', async () => {
    const c = await openList([logRow({ timestamp: null })])
    const cell = td(c, 0, 0).textContent.trim()
    expect(cell).toBe('-')
    expect(cell).not.toContain('undefined')
    expect(cell).not.toContain('1970')
  })

  test('用户/IP 双行单元格：两字段各自独立渲染，缺失时占位为 -', async () => {
    const c = await openList([logRow(), logRow({ _id: 'r2', username: '', ip: '' })])
    expect(td(c, 0, 1).querySelector('.cell-main').textContent.trim()).toBe('alice')
    expect(td(c, 0, 1).querySelector('.cell-sub').textContent.trim()).toBe('10.0.0.9')
    expect(td(c, 1, 1).querySelector('.cell-main').textContent.trim()).toBe('-')
    expect(td(c, 1, 1).querySelector('.cell-sub').textContent.trim()).toBe('-')
  })

  test('风险等级与日志等级派生：critical/high/medium/失败/未知各自映射且行着色', async () => {
    const c = await openList([
      logRow({ _id: 'r1', riskLevel: 'critical', success: true }),
      logRow({ _id: 'r2', riskLevel: 'high', success: true }),
      logRow({ _id: 'r3', riskLevel: 'medium', success: true }),
      logRow({ _id: 'r4', riskLevel: 'low', success: false }),
      logRow({ _id: 'r5', riskLevel: 'weird', success: true }),
    ])
    expect(trs(c)[0].className).toContain('row-risk-critical')
    expect(trs(c)[1].className).toContain('row-risk-high')
    for (const i of [2, 3, 4]) {
      expect(trs(c)[i].className).not.toContain('row-risk-critical')
      expect(trs(c)[i].className).not.toContain('row-risk-high')
    }
    const tagType = (t) =>
      ['danger', 'warning', 'success', 'info', 'primary'].find((k) =>
        t.classList.contains('el-tag--' + k)
      )
    const levels = (i) =>
      Array.from(td(c, i, 4).querySelectorAll('.el-tag')).map(
        (t) => tagType(t) + ':' + t.textContent.trim()
      )
    expect(levels(0)).toEqual(['danger:严重', 'danger:错误'])
    expect(levels(1)).toEqual(['danger:高', 'danger:错误'])
    expect(levels(2)).toEqual(['warning:中', 'warning:警告'])
    expect(levels(3)).toEqual(['success:低', 'danger:错误'])
    expect(levels(4)).toEqual(['info:weird', 'info:信息'])
  })

  test('操作/分类列：已知值走词表，未知值回退原文（便于识别新增枚举）', async () => {
    const c = await openList([
      logRow({ action: 'zzz_unknown', category: 'nope' }),
      logRow({ _id: 'r2', action: 'auth_login', category: 'device' }),
    ])
    expect(td(c, 0, 2).querySelector('.cell-main').textContent.trim()).toBe('zzz_unknown')
    expect(td(c, 0, 2).querySelector('.cell-sub').textContent.trim()).toBe('nope')
    expect(td(c, 1, 2).querySelector('.cell-main').textContent.trim()).toBe('用户登录')
    expect(td(c, 1, 2).querySelector('.cell-sub').textContent.trim()).toBe('设备')
  })

  test('请求列：method/path 渲染，事件型日志（无请求信息）显示占位符', async () => {
    const c = await openList([
      logRow({ method: 'POST', path: '/api/auth/login' }),
      logRow({ _id: 'r2', method: '', path: '' }),
    ])
    expect(td(c, 0, 3).textContent).toContain('POST')
    expect(td(c, 0, 3).textContent).toContain('/api/auth/login')
    expect(td(c, 1, 3).textContent.trim()).toBe('—')
  })

  test('状态列：成功渲染「是」、失败渲染「否」', async () => {
    const c = await openList([logRow({ success: true }), logRow({ _id: 'r2', success: false })])
    expect(td(c, 0, 5).textContent.trim()).toBe('是')
    expect(td(c, 1, 5).textContent.trim()).toBe('否')
  })
})

describe('AuditLogView 筛选与分页', () => {
  test('分类筛选：回到第 1 页并携带 category 参数', async () => {
    const c = await openList([logRow()], { total: 33 })
    click(c.find('.btn-next'))
    await waitFor(() => lastParams().page === 2, { message: '翻到第 2 页' })
    await pickSelect(c, 0, '设备管理')
    await waitFor(() => lastParams().category === 'device', { message: '分类筛选请求' })
    expect(lastParams()).toEqual({ page: 1, limit: 20, category: 'device' })
  })

  test('操作结果筛选：选「失败」传布尔 false；清空后请求不得再带 success（防空串被当 false）', async () => {
    const c = await openList([logRow()])
    await pickSelect(c, 3, '失败')
    await waitFor(() => 'success' in lastParams(), { message: 'success 参数出现' })
    expect(lastParams()).toEqual({ page: 1, limit: 20, success: false })
    await clearSelect(c.findAll('.el-select__wrapper')[3])
    await waitFor(() => !('success' in lastParams()), { message: '清空后不再携带 success' })
    expect(lastParams()).toEqual({ page: 1, limit: 20 })
  })

  test('日期范围筛选：startDate/endDate 与选择器值一致，并回到第 1 页', async () => {
    const c = await openList([logRow()], { total: 33 })
    click(c.find('.btn-next'))
    await waitFor(() => lastParams().page === 2, { message: '翻到第 2 页' })
    const inputs = c.findAll('.filter-card .el-date-editor input')
    expect(inputs).toHaveLength(2)
    inputs[0].dispatchEvent(new window.MouseEvent('mousedown', { bubbles: true, cancelable: true }))
    inputs[0].focus()
    await flush(8)
    const openPanel = () =>
      Array.from(document.body.querySelectorAll('.el-picker-panel')).find((p) => {
        const w = p.closest('.el-popper')
        return w && w.getAttribute('aria-hidden') !== 'true'
      })
    const panel = openPanel()
    expect(panel).toBeTruthy()
    const days = Array.from(
      panel.querySelectorAll('.el-date-table')[0].querySelectorAll('td.available')
    )
    expect(days.length).toBeGreaterThanOrEqual(15)
    click(days[8])
    await flush(4)
    const panel2 = openPanel()
    expect(panel2).toBeTruthy()
    const days2 = Array.from(
      panel2.querySelectorAll('.el-date-table')[0].querySelectorAll('td.available')
    )
    expect(days2.length).toBeGreaterThanOrEqual(15)
    click(days2[11])
    await waitFor(() => 'startDate' in lastParams(), { message: '日期筛选请求' })
    const [start, end] = c.findAll('.filter-card .el-date-editor input').map((i) => i.value)
    expect(start).not.toBe(end)
    for (const v of [start, end]) {
      expect(v.split('-')).toHaveLength(3)
      expect(v).not.toContain('T')
    }
    expect(lastParams()).toEqual({ page: 1, limit: 20, startDate: start, endDate: end })
  })

  test('用户名筛选：回车触发查询并携带 username', async () => {
    const c = await openList([logRow()])
    const input = c.findAll('.filter-card .el-input input')[0]
    input.value = 'bob'
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    input.dispatchEvent(
      new window.KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true })
    )
    await waitFor(() => lastParams().username === 'bob', { message: '用户名筛选请求' })
    expect(lastParams()).toEqual({ page: 1, limit: 20, username: 'bob' })
  })

  test('重置：清空全部筛选输入并回到第 1 页，请求不再携带任何筛选键', async () => {
    const c = await openList([logRow()])
    await pickSelect(c, 0, '设备管理')
    await pickSelect(c, 3, '失败')
    const input = c.findAll('.filter-card .el-input input')[0]
    input.value = 'bob'
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    input.dispatchEvent(
      new window.KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true })
    )
    await waitFor(() => lastParams().username === 'bob', { message: '用户名筛选请求' })
    expect(lastParams().category).toBe('device')
    expect(lastParams().success).toBe(false)
    click(c.findAll('.glass-btn-group button')[1])
    await waitFor(() => Object.keys(lastParams()).length === 2, { message: '重置后的请求参数' })
    expect(lastParams()).toEqual({ page: 1, limit: 20 })
    expect(c.findAll('.filter-card .el-input input')[0].value).toBe('')
    expect(c.findAll('.filter-card .el-select__wrapper').map((w) => w.textContent.trim())).toEqual([
      '请选择',
      '请选择',
      '请选择',
      '请选择',
    ])
  })

  test('翻页：page 递增且保留当前筛选条件', async () => {
    const c = await openList([logRow()], { total: 45 })
    await pickSelect(c, 2, '高')
    await waitFor(() => lastParams().riskLevel === 'high', { message: '风险等级筛选' })
    click(c.find('.btn-next'))
    await waitFor(() => lastParams().page === 2, { message: '第 2 页请求' })
    expect(lastParams()).toEqual({ page: 2, limit: 20, riskLevel: 'high' })
  })

  test('每页条数改 50：limit 更新且回到第 1 页', async () => {
    const c = await openList([logRow()], { total: 120 })
    click(c.find('.btn-next'))
    await waitFor(() => lastParams().page === 2, { message: '第 2 页请求' })
    await pickOption(c.findAll('.el-pagination .el-select__wrapper')[0], '50/page')
    await waitFor(() => lastParams().limit === 50, { message: '每页 50 请求' })
    expect(lastParams()).toEqual({ page: 1, limit: 50 })
  })
})

describe('AuditLogView 失败路径与竞态', () => {
  test('列表加载失败：提示「加载失败」且不抛 Vue 错误', async () => {
    get.mockImplementation((url) =>
      url === '/security/audit-logs'
        ? Promise.reject(new Error('boom'))
        : Promise.resolve({ data: { data: {} } })
    )
    const c = mountView()
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '加载失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith('加载失败')
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('路由 abort 的在途请求：静默失败不弹错误（FE-L1）', async () => {
    const err = Object.assign(new Error('canceled'), { code: 'ERR_CANCELED' })
    isCanceledError.mockReturnValue(true)
    get.mockImplementation((url) =>
      url === '/security/audit-logs' ? Promise.reject(err) : Promise.resolve({ data: { data: {} } })
    )
    const c = mountView()
    await waitFor(() => isCanceledError.mock.calls.length >= 1, { message: 'abort 分支被走到' })
    expect(isCanceledError).toHaveBeenCalledWith(err)
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('竞态守卫：慢的旧响应不得覆盖新结果', async () => {
    const pending = []
    get.mockImplementation((url) => {
      if (url === '/security/audit-logs') return new Promise((resolve) => pending.push(resolve))
      return Promise.resolve({ data: { data: {} } })
    })
    const c = mountView()
    await waitFor(() => pending.length === 1, { message: '首个列表请求在途' })
    click(c.findAll('.glass-btn-group button')[0])
    await waitFor(() => pending.length === 2, { message: '第二个列表请求在途' })
    pending[1]({ data: { data: { data: [logRow({ username: 'NEW' })], meta: { total: 1 } } } })
    await waitFor(() => trs(c).length === 1, { message: '新结果落地' })
    pending[0]({ data: { data: { data: [logRow({ username: 'OLD' })], meta: { total: 9 } } } })
    await flush(20)
    expect(td(c, 0, 1).querySelector('.cell-main').textContent.trim()).toBe('NEW')
    expect(totalDigits(c)).toBe('1')
  })

  test('统计接口失败：不渲染统计卡，列表照常可用且不弹错误', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/audit-logs') {
        return Promise.resolve({ data: { data: { data: [logRow()], meta: { total: 1 } } } })
      }
      return Promise.reject(new Error('overview down'))
    })
    const c = mountView()
    await waitFor(() => trs(c).length === 1, { message: '列表渲染' })
    await flush(10)
    expect(c.findAll('.stat-value')).toEqual([])
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})

describe('AuditLogView 导出', () => {
  test('导出按钮双权限门控：缺任一权限都不渲染，双权限齐备才显示', async () => {
    const buttonCount = async (perms) => {
      const c = await openList([logRow()], { total: 1 }, perms)
      const n = c.findAll('.card-header .glass-btn').length
      c.handle.unmount()
      active = null
      return n
    }
    expect(await buttonCount(['report:export'])).toBe(0)
    expect(await buttonCount(['security:audit'])).toBe(0)
    expect(await buttonCount(PERMS)).toBe(1)
  })

  test('导出：携带 type=audit 与当前筛选，成功后触发下载并提示', async () => {
    const instant = '2026-09-18T04:30:00+08:00'
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date(instant))
    const created = []
    const realCreate = document.createElement.bind(document)
    const createSpy = vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      const el = realCreate(tag)
      if (tag === 'a') created.push(el)
      return el
    })
    const clickSpy = vi.fn()
    const realAnchorClick = window.HTMLAnchorElement.prototype.click
    window.HTMLAnchorElement.prototype.click = clickSpy
    const createObjectURL = vi.fn(() => 'blob:audit')
    const revokeObjectURL = vi.fn()
    const realCreateURL = window.URL.createObjectURL
    const realRevokeURL = window.URL.revokeObjectURL
    window.URL.createObjectURL = createObjectURL
    window.URL.revokeObjectURL = revokeObjectURL
    try {
      get.mockImplementation((url) => {
        if (url === '/security/audit-logs') {
          return Promise.resolve({ data: { data: { data: [], meta: { total: 0 } } } })
        }
        if (url === '/security/overview') return Promise.resolve({ data: { data: {} } })
        if (url === '/reports/export') {
          return Promise.resolve({
            data: new Blob(['PK'], { type: XLSX }),
            headers: { 'content-type': XLSX },
          })
        }
        return Promise.reject(new Error('unexpected url: ' + url))
      })
      const c = mountView()
      await waitFor(() => logCalls().length >= 1, { message: '列表请求' })
      await pickSelect(c, 0, '设备管理')
      await waitFor(() => lastParams().category === 'device', { message: '分类筛选' })
      click(c.find('.card-header .glass-btn'))
      await waitFor(() => get.mock.calls.some((x) => x[0] === '/reports/export'), {
        message: '导出请求',
      })
      const call = get.mock.calls.find((x) => x[0] === '/reports/export')
      expect(call[1]).toEqual({
        params: { type: 'audit', category: 'device' },
        responseType: 'blob',
      })
      await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '导出成功提示' })
      expect(ElMessage.error).not.toHaveBeenCalled()
      expect(createObjectURL).toHaveBeenCalledTimes(1)
      expect(createObjectURL.mock.calls[0][0]).toBeInstanceOf(Blob)
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:audit')
      expect(clickSpy).toHaveBeenCalledTimes(1)
      expect(created).toHaveLength(1)
      expect(created[0].href).toBe('blob:audit')
      const d = new Date(instant)
      const p = (n) => String(n).padStart(2, '0')
      const expectedName =
        'audit_logs_' + d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + '.xlsx'
      expect(created[0].download).toBe(expectedName)
      expect(c.errors).toEqual([])
    } finally {
      createSpy.mockRestore()
      window.HTMLAnchorElement.prototype.click = realAnchorClick
      window.URL.createObjectURL = realCreateURL
      window.URL.revokeObjectURL = realRevokeURL
      vi.useRealTimers()
    }
  })

  test('导出截断提示：响应头 X-Export-Truncated 存在时向用户提示', async () => {
    const realCreateURL = window.URL.createObjectURL
    const realRevokeURL = window.URL.revokeObjectURL
    const realAnchorClick = window.HTMLAnchorElement.prototype.click
    window.URL.createObjectURL = vi.fn(() => 'blob:x')
    window.URL.revokeObjectURL = vi.fn()
    window.HTMLAnchorElement.prototype.click = vi.fn()
    try {
      get.mockImplementation((url) => {
        if (url === '/security/audit-logs') {
          return Promise.resolve({ data: { data: { data: [], meta: { total: 0 } } } })
        }
        if (url === '/security/overview') return Promise.resolve({ data: { data: {} } })
        if (url === '/reports/export') {
          return Promise.resolve({
            data: new Blob(['PK'], { type: XLSX }),
            headers: { 'content-type': XLSX, 'x-export-truncated': '已达上限，结果被截断' },
          })
        }
        return Promise.reject(new Error('unexpected url: ' + url))
      })
      const c = mountView()
      await waitFor(() => logCalls().length >= 1, { message: '列表请求' })
      click(c.find('.card-header .glass-btn'))
      await waitFor(() => ElMessage.warning.mock.calls.length === 1, { message: '截断提示' })
      expect(ElMessage.warning).toHaveBeenCalledWith('已达上限，结果被截断')
      expect(ElMessage.success).toHaveBeenCalledTimes(1)
      expect(ElMessage.error).not.toHaveBeenCalled()
    } finally {
      window.URL.createObjectURL = realCreateURL
      window.URL.revokeObjectURL = realRevokeURL
      window.HTMLAnchorElement.prototype.click = realAnchorClick
    }
  })

  test('导出进行中：按钮禁用，重复点击不重复发请求', async () => {
    let resolveExport
    get.mockImplementation((url) => {
      if (url === '/security/audit-logs') {
        return Promise.resolve({ data: { data: { data: [], meta: { total: 0 } } } })
      }
      if (url === '/security/overview') return Promise.resolve({ data: { data: {} } })
      if (url === '/reports/export') return new Promise((r) => (resolveExport = r))
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = mountView()
    await waitFor(() => logCalls().length >= 1, { message: '列表请求' })
    const btn = c.find('.card-header .glass-btn')
    click(btn)
    await flush(6)
    expect(btn.disabled).toBe(true)
    click(btn)
    await flush(6)
    expect(get.mock.calls.filter((x) => x[0] === '/reports/export')).toHaveLength(1)
    resolveExport({ data: { message: '导出被拒绝' }, headers: {} })
    await waitFor(() => btn.disabled === false, { message: '导出结束后按钮恢复' })
    expect(ElMessage.error).toHaveBeenCalledWith('导出被拒绝')
  })
})

describe('AuditLogView 详情对话框', () => {
  test('条件字段缺失时不渲染；请求方式/路径/请求参数/User-Agent 渲染占位符', async () => {
    const c = await openDetail([logRow({ userId: 'u-1' })])
    const pairs = descPairs()
    const labels = pairs.map((p) => p.split('::')[0])
    expect(labels).toContain('操作时间')
    expect(labels).not.toContain('风险因素')
    expect(labels).not.toContain('错误信息')
    expect(labels).not.toContain('目标用户')
    expect(labels).not.toContain('操作原因')
    expect(labels).not.toContain('执行时长')
    expect(pairs).toContain('操作用户::alice')
    expect(pairs).toContain('用户 ID::u-1')
    expect(pairs).toContain('操作类型::用户登录')
    expect(pairs).toContain('分类::认证')
    expect(pairs).toContain('请求方式::-')
    expect(pairs).toContain('请求路径::-')
    expect(pairs).toContain('IP 地址::10.0.0.9')
    expect(pairs).toContain('风险等级::低')
    expect(pairs).toContain('操作结果::成功')
    expect(pairs).toContain('请求参数::-')
    expect(pairs).toContain('User-Agent::-')
    const time = pairs.find((p) => p.startsWith('操作时间::')).split('::')[1]
    expect(time).not.toContain('T')
    expectLocalTime(time, logRow().timestamp)
    expect(c.errors).toEqual([])
  })

  test('条件字段齐全时渲染：风险因素多标签、错误信息、目标用户、原因、执行时长 0ms', async () => {
    await openDetail([
      logRow({
        riskFactors: ['geo_anomaly', 'tor_exit'],
        errorMessage: 'E500',
        targetUsername: 'bob',
        reason: 'admin_action',
        duration: 0,
        params: { page: 2 },
      }),
    ])
    const pairs = descPairs()
    expect(pairs).toContain('目标用户::bob')
    expect(pairs).toContain('操作原因::admin_action')
    expect(pairs).toContain('错误信息::E500')
    expect(pairs).toContain('执行时长::0ms')
    expect(pairs).toContain('操作结果::成功')
    expect(
      Array.from(document.body.querySelectorAll('.risk-factor-tag')).map((t) =>
        t.textContent.trim()
      )
    ).toEqual(['geo_anomaly', 'tor_exit'])
    expect(document.body.querySelector('.json-preview').textContent).toBe(
      JSON.stringify({ page: 2 }, null, 2)
    )
  })

  test('详情对话框：点「关闭」后遮罩隐藏且无 Vue 错误', async () => {
    const c = await openDetail([logRow()])
    const overlay = document.body.querySelector('.el-overlay')
    expect(overlay.style.display).toBe('')
    const closeBtn = Array.from(
      document.body.querySelectorAll('.el-dialog__footer .glass-btn')
    ).find((b) => b.textContent.trim() === '关闭')
    expect(closeBtn).toBeTruthy()
    click(closeBtn)
    for (let i = 0; i < 60 && overlay.style.display !== 'none'; i += 1) {
      await new Promise((r) => setTimeout(r, 10))
    }
    expect(overlay.style.display).toBe('none')
    expect(c.errors).toEqual([])
  })
})
