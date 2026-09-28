/**
 * ReportView 导出路径行为测试（2026-09-18）
 *
 * 导出是审计重点操作，且是**最容易静默失效**的一条链路：
 *  - 参数名写错（startDate/endDate）→ 后端忽略筛选，导出的文件「看着正常」但范围不对；
 *  - 日期不经 localDateStr 而走 toISOString → 东八区 0-8 点导出的日期早一天；
 *  - 后端以 JSON 报错却被当 Excel 下载 → 用户得到一个坏文件且无任何提示；
 *  - 权限门控丢失 → 无 report:export 的用户也能触发大文件导出。
 * 本套件逐条钉住。echarts 在 jsdom 下无 canvas，故用 vi.mock 替身（本文件不测图表绘制）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const exportReport = vi.fn()
const getDashboard = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    reports: {
      export: (...a) => exportReport(...a),
      getDashboard: (...a) => getDashboard(...a),
      getAlarms: vi.fn(() => Promise.resolve({ data: { data: [] } })),
      getDevices: vi.fn(() => Promise.resolve({ data: { data: [] } })),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
// echarts 在 jsdom 无 canvas：替身掉 init 与 use，本文件只测导出链路
vi.mock('echarts/core', () => ({
  use: vi.fn(),
  init: () => ({ setOption: vi.fn(), resize: vi.fn(), dispose: vi.fn() }),
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
import i18n from '@/i18n'

let active = null
const EXPORT_PERMS = ['report:read', 'report:export']

const open = async (perms = EXPORT_PERMS) => {
  getDashboard.mockResolvedValue({
    data: { success: true, data: { devices: 1, alarms: 2, inspections: 3 } },
  })
  active = mountComponent(ReportView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
  await flush(12)
  return active
}

/** 打开导出对话框：点「导出」按钮 */
const openDialog = async (c) => {
  const btn = c.findAll('button').find((b) => b.textContent.includes('导出'))
  expect(btn).toBeTruthy()
  click(btn)
  await waitFor(() => document.body.querySelectorAll('.el-dialog').length > 0, {
    message: '导出对话框打开',
  })
  return document.body.querySelector('.el-dialog')
}

/** 对话框内的「导出Excel」确认按钮（渲染在 body 上的 teleport 里） */
const confirmBtn = () => {
  const dlg = document.body.querySelector('.el-dialog')
  const btns = Array.from(dlg.querySelectorAll('button'))
  return btns.find((b) => b.textContent.includes('导出Excel') || b.textContent.includes('Excel'))
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  exportReport.mockReset()
  getDashboard.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  // 清掉 teleport 残留的对话框
  document.body.innerHTML = ''
})

describe('ReportView 导出权限门控', () => {
  test('无 report:export：不渲染导出按钮（入口消失，而非点了才 403）', async () => {
    const c = await open(['report:read'])
    const labels = c.findAll('button').map((b) => b.textContent.trim())
    expect(labels.some((x) => x.includes('导出'))).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('有 report:export：导出按钮出现且可打开对话框', async () => {
    const c = await open()
    const btn = c.findAll('button').find((b) => b.textContent.includes('导出'))
    expect(btn).toBeTruthy()
    await openDialog(c)
    expect(document.body.querySelector('.el-dialog')).toBeTruthy()
  })

  // ---- 快捷入口卡片：按钮之外的第二个导出入口 ----
  // 上面第一条查的是 findAll('button')，而卡片由 el-card 渲染成 div，
  // 于是「按钮没了」被当成了「入口没了」——这是本文件里最像"已设防"的一处假绿：
  // 无 report:export 的用户当时仍然可以点第四张卡片打开导出对话框。
  // 这里两条成对：缺权限时卡片必须**少一张**，有权限时第四张必须真的能开对话框
  // （后者保证前者不是因为卡片整体没渲染而白过）。
  test('无 report:export：第四张导出卡片不渲染（少一张，而不是点了才 403）', async () => {
    const c = await open(['report:read'])
    const cards = c.findAll('.report-card')
    expect(cards.length).toBe(3)
    expect(cards.some((card) => card.textContent.includes('导出'))).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('反向对照：有 report:export 时第四张卡片在，且点它会打开导出对话框', async () => {
    const c = await open()
    const cards = c.findAll('.report-card')
    expect(cards.length).toBe(4)
    click(cards[3])
    await waitFor(() => document.body.querySelectorAll('.el-dialog').length > 0, {
      message: '点击导出卡片应打开对话框',
    })
    expect(document.body.querySelector('.el-dialog')).toBeTruthy()
  })
})

describe('ReportView 导出参数', () => {
  test('默认导出报警报表：type=alarms，未选日期时不带日期参数', async () => {
    exportReport.mockResolvedValue({ data: new Blob(['x'], { type: 'application/vnd.ms-excel' }) })
    const c = await open()
    await openDialog(c)
    click(confirmBtn())
    await waitFor(() => exportReport.mock.calls.length === 1, { message: '导出请求发出' })
    const params = exportReport.mock.calls[0][0]
    expect(params.type).toBe('alarms')
    expect(params).not.toHaveProperty('startDate')
    expect(params).not.toHaveProperty('endDate')
  })

  test('切换报表类型：参数随选择变化（不是写死 alarms）', async () => {
    exportReport.mockResolvedValue({
      data: new Blob(['x'], { type: 'application/vnd.ms-excel' }),
    })
    const c = await open()
    const dlg = await openDialog(c)
    // 对话框内两个单选项：报警报表(=alarms) / 设备报表(=devices)
    const radios = Array.from(dlg.querySelectorAll('.el-radio'))
    expect(radios).toHaveLength(2)
    const deviceRadio = radios.find((r) => r.textContent.includes('设备'))
    expect(deviceRadio).toBeTruthy()
    // 点击真实 radio input（Element Plus 的 label 包着原生 input）
    const input = deviceRadio.querySelector('input[type="radio"]')
    expect(input.value).toBe('devices')
    input.dispatchEvent(new window.Event('change', { bubbles: true }))
    await flush(6)
    click(confirmBtn())
    await waitFor(() => exportReport.mock.calls.length === 1, { message: '导出请求发出' })
    expect(exportReport.mock.calls[0][0].type).toBe('devices')
  })

  test('日期区间按**本地**日期串提交（不得用 UTC 串，否则东八区早一天）', async () => {
    exportReport.mockResolvedValue({
      data: new Blob(['x'], { type: 'application/vnd.ms-excel' }),
    })
    const c = await open()
    const dlg = await openDialog(c)
    // 打开日历面板并点选两个日期（真实交互，而非直接改内部状态）
    click(dlg.querySelector('.el-date-editor'))
    await waitFor(() => document.body.querySelectorAll('.el-picker-panel').length > 0, {
      message: '日历面板打开',
    })
    const cells = Array.from(document.body.querySelectorAll('.el-picker-panel td.available'))
    expect(cells.length).toBeGreaterThan(2)
    // 取面板中间的两个可用日期（避免落在上一月/下一月的灰格上）
    const pick = cells.slice(10, 12)
    expect(pick).toHaveLength(2)
    click(pick[0])
    await flush(6)
    click(pick[1])
    await flush(10)
    click(confirmBtn())
    await waitFor(() => exportReport.mock.calls.length === 1, { message: '导出请求发出' })
    const params = exportReport.mock.calls[0][0]
    // 契约：格式为本地日期串 YYYY-MM-DD，且两个日期都有值、start <= end
    expect(params.startDate).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(params.endDate).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(params.startDate).not.toContain('T')
    expect(params.endDate).not.toContain('Z')
    expect(params.startDate <= params.endDate).toBe(true)
    // 本地口径自检：东八区下 toISOString 会把当天 00:00 退到前一天
    const d = new Date(2026, 0, 5, 1, 30, 0)
    const p2 = (n) => String(n).padStart(2, '0')
    const localOf = (x) => x.getFullYear() + '-' + p2(x.getMonth() + 1) + '-' + p2(x.getDate())
    expect(localOf(d)).toBe('2026-01-05')
    expect(d.toISOString().slice(0, 10)).not.toBe(localOf(d))
    // 面板点选的是「本月」的日期；cells[10]/cells[11] 对应本月 11 / 12 日，
    // 故可以精确钉住「本地日期」口径（实测：改用 toISOString().slice(0,10)
    // 后东八区 11 日 00:00 会退成 10 日 → 本断言转红）
    const now = new Date()
    const p3 = (n) => String(n).padStart(2, '0')
    const ym = now.getFullYear() + '-' + p3(now.getMonth() + 1)
    expect(params.startDate).toBe(ym + '-11')
    expect(params.endDate).toBe(ym + '-12')
  })
})
describe('ReportView 导出错误处理', () => {
  test('后端以 JSON Blob 报错：提示其中的 message，且**不**下载文件', async () => {
    const jsonBlob = new Blob([JSON.stringify({ message: '导出范围过大' })], {
      type: 'application/json',
    })
    exportReport.mockResolvedValue({ data: jsonBlob })
    const c = await open()
    await openDialog(c)
    const createUrl = vi.spyOn(window.URL, 'createObjectURL')
    click(confirmBtn())
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '错误提示' })
    expect(ElMessage.error.mock.calls[0][0]).toBe('导出范围过大')
    expect(createUrl).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    // 对话框保持打开（用户可改条件重试）
    expect(document.body.querySelector('.el-dialog')).toBeTruthy()
    createUrl.mockRestore()
  })

  test('非 Blob 响应（拦截器已解包）：走 message 兜底提示，不下载', async () => {
    exportReport.mockResolvedValue({ data: { message: '无权限导出该范围' } })
    const c = await open()
    await openDialog(c)
    const createUrl = vi.spyOn(window.URL, 'createObjectURL')
    click(confirmBtn())
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '错误提示' })
    expect(ElMessage.error.mock.calls[0][0]).toBe('无权限导出该范围')
    expect(createUrl).not.toHaveBeenCalled()
    createUrl.mockRestore()
  })

  test('成功下载：文件名带报表类型前缀与本地日期，且释放 objectURL（不泄漏）', async () => {
    exportReport.mockResolvedValue({
      data: new Blob(['xlsx-bytes'], { type: 'application/vnd.ms-excel' }),
    })
    const c = await open()
    await openDialog(c)
    const createUrl = vi.spyOn(window.URL, 'createObjectURL').mockReturnValue('blob:fake')
    const revokeUrl = vi.spyOn(window.URL, 'revokeObjectURL').mockImplementation(() => {})
    const clicked = []
    const origCreate = document.createElement.bind(document)
    const createSpy = vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      const el = origCreate(tag)
      if (tag === 'a') {
        el.click = () => clicked.push({ href: el.href, download: el.download })
      }
      return el
    })
    click(confirmBtn())
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '导出成功' })
    expect(clicked).toHaveLength(1)
    const p = (n) => String(n).padStart(2, '0')
    const today = new Date()
    const expectedDate = `${today.getFullYear()}-${p(today.getMonth() + 1)}-${p(today.getDate())}`
    expect(clicked[0].download).toContain(expectedDate)
    expect(clicked[0].download).toContain('报警')
    expect(clicked[0].download.endsWith('.xlsx')).toBe(true)
    expect(clicked[0].href).toBe('blob:fake')
    expect(revokeUrl).toHaveBeenCalledWith('blob:fake')
    expect(createUrl).toHaveBeenCalledTimes(1)
    createUrl.mockRestore()
    revokeUrl.mockRestore()
    createSpy.mockRestore()
    expect(c.errors).toEqual([])
  })

  test('导出进行中：确认按钮被禁用（再点无效），失败后复位可重试', async () => {
    let release
    exportReport.mockImplementationOnce(
      () =>
        new Promise((_res, rej) => {
          release = () => rej(new Error('boom'))
        })
    )
    exportReport.mockResolvedValueOnce({ data: new Blob(['x'], { type: 'application/json' }) })
    const c = await open()
    await openDialog(c)
    click(confirmBtn())
    await waitFor(() => exportReport.mock.calls.length === 1, { message: '首次导出进行中' })
    // 请求在飞：按钮必须 disabled（否则用户可连点触发多次大文件导出）
    expect(confirmBtn().disabled).toBe(true)
    click(confirmBtn())
    await flush(4)
    expect(exportReport.mock.calls.length).toBe(1)
    release()
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '首次失败提示' })
    // 失败后 exporting 复位：按钮恢复可点，且能真正再次发起
    await waitFor(() => confirmBtn().disabled === false, { message: '失败后按钮复位' })
    click(confirmBtn())
    await waitFor(() => exportReport.mock.calls.length === 2, { message: '重试导出' })
    expect(exportReport.mock.calls.length).toBe(2)
  })
})

/**
 * 报表页的「这份文件不完整」提示（与审计页同一条后端契约）。
 *
 * 后端只在结果不保证完整时发 X-Export-Truncated，值是字面 'true'
 * （截断/丢行/计数漂移三种原因写在 xlsx 表内脚注里，头只表态"不完整"）。
 * 此前本视图完全不读这个头：同一份被封顶的文件，从审计页下载会提示、
 * 从报表页下载只报"导出成功"——用户按后者的口径信了文件。
 */
describe('ReportView 导出完整性提示', () => {
  const xlsxResponse = (headers) => ({
    data: new Blob(['xlsx-bytes'], { type: 'application/vnd.ms-excel' }),
    headers,
  })

  const runExport = async (headers) => {
    exportReport.mockResolvedValue(xlsxResponse(headers))
    const c = await open()
    await openDialog(c)
    click(confirmBtn())
    await waitFor(() => exportReport.mock.calls.length === 1, { message: '导出请求发出' })
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '导出完成' })
    return c
  }

  test('带截断标记：除成功提示外还要警告，且弹的是词表文案而非响应头原值', async () => {
    await runExport({ 'x-export-truncated': 'true' })
    expect(ElMessage.warning).toHaveBeenCalledTimes(1)
    const shown = ElMessage.warning.mock.calls[0][0]
    expect(shown).not.toBe('true')
    // 前提自证：键必须真在词表里。缺键时 vue-i18n 把 t() 回落成键名，
    // 下一条"两边都取键名"的断言会恒真。
    expect(i18n.global.te('messages.exportTruncated')).toBe(true)
    expect(shown).toBe(i18n.global.t('messages.exportTruncated'))
    expect(shown.length).toBeGreaterThan(10)
  })

  test('反向对照：没有截断头时不得警告（否则上面那条是恒真的氛围断言）', async () => {
    await runExport({ 'content-type': 'application/vnd.ms-excel' })
    expect(ElMessage.warning).not.toHaveBeenCalled()
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
  })
})
