/**
 * DeviceView 行为测试（设备台账：列表/筛选/分页 + 增删改权限门控 + 日期口径）
 *
 * 设备台账是消防系统的资产主数据，五类退化都不抛错、只静默出错：
 *  1. 权限门控丢失 -> 无 device:create/update/delete 的用户看到并能点开增删改入口；
 *  2. 筛选参数名传错（search vs status）-> 后端忽略条件，用户以为筛过了；
 *  3. 条件变更不重置页码 -> 停在第 N 页看到空列表（典型「查不到数据」投诉）；
 *  4. 加载失败保留旧数据 -> 用户对着过期台账做资产判断；
 *  5. 编辑回填日期口径与保存口径不一致 -> 每打开一次保存就平移一天。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const getList = vi.fn()
const create = vi.fn()
const update = vi.fn()
const remove = vi.fn()
const isCanceledError = vi.fn(() => false)
vi.mock('@/utils/api', () => ({
  api: {
    devices: {
      getList: (...a) => getList(...a),
      create: (...a) => create(...a),
      update: (...a) => update(...a),
      delete: (...a) => remove(...a),
    },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
const confirm = vi.fn()
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: (...a) => confirm(...a) },
}))

import DeviceView from '@/views/DeviceView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null
const FULL = ['device:read', 'device:create', 'device:update', 'device:delete']

const ROW = {
  _id: 'd1',
  deviceCode: 'SMK-001',
  deviceName: '一层烟感',
  deviceType: 'smoke_detector',
  status: 'normal',
  location: { building: 'A栋', floor: '1', room: '101' },
  installDate: '2026-01-05T00:00:00.000Z',
}
const ROWS = [ROW]

const open = async (perms = FULL, rows = ROWS, total = rows.length) => {
  getList.mockResolvedValue({ data: { data: rows, pagination: { total } } })
  active = mountComponent(DeviceView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
  await waitFor(() => getList.mock.calls.length >= 1, { message: '列表请求已发出' })
  await waitFor(
    () => active.findAll('.el-table__body-wrapper .el-table__row').length === rows.length,
    {
      message: '表格行数与返回数据一致',
    }
  )
  await flush(3)
  return active
}

/** 按可见文案找按钮；找不到返回 undefined（调用方先断言存在性再 click） */
const btn = (scope, text) => scope.findAll('button').find((b) => b.textContent.includes(text))

/** 表格正文按行拆成单元格文本数组 */
const cells = (c) =>
  c
    .findAll('.el-table__body-wrapper .el-table__row')
    .map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.trim()))

/** 对话框内容（Element Plus dialog 走 teleport 渲染到 document.body） */
const dlg = () => document.body.querySelector('.el-dialog')
const dlgFootBtn = (text) =>
  Array.from(dlg().querySelectorAll('.el-dialog__footer button')).find(
    (b) => b.textContent.trim() === text
  )

/** 当前可见的 Element Plus 浮层
 *
 * 页面上同时存在 3 个 select 浮层（筛选状态 / 分页 size / 对话框类型）+ 1 个日期浮层，
 * 默认全部渲染在 body 里且 aria-hidden="true"；只有展开的那个是 aria-hidden="false"。
 * 必须取「可见浮层」而不是「第一个浮层」，否则会点到筛选栏里隐藏的下拉项。
 */
const visiblePopper = () =>
  Array.from(document.body.querySelectorAll('.el-popper')).find(
    (el) => el.getAttribute('aria-hidden') === 'false'
  )

/** 打开新增/编辑对话框并等它真正挂上 DOM */
const openDialog = async (c, triggerText) => {
  const trigger = btn(c, triggerText)
  expect(trigger).toBeTruthy()
  click(trigger)
  await waitFor(() => dlg(), { message: '对话框打开' })
  await flush(4)
  return dlg()
}

/** 触发 Element Plus 输入的 v-model 更新（真实浏览器里由用户键入触发） */
const typeInto = (input, value) => {
  input.value = value
  input.dispatchEvent(new window.Event('input', { bubbles: true }))
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  getList.mockReset()
  create.mockReset()
  update.mockReset()
  remove.mockReset()
  confirm.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  document.body.innerHTML = ''
})

describe('DeviceView 写入口权限门控', () => {
  test('只读权限：新增/编辑/删除三个入口都不渲染，但列表照常可读', async () => {
    const c = await open(['device:read'])
    expect(btn(c, '新增设备')).toBeUndefined()
    expect(btn(c, '编辑')).toBeUndefined()
    expect(btn(c, '删除')).toBeUndefined()
    expect(cells(c)).toHaveLength(1)
    expect(cells(c)[0].join(' ')).toContain('SMK-001')
    expect(c.errors).toEqual([])
  })

  test('三个写权限各自独立生效（只给 update 时不得放出新增/删除）', async () => {
    const c = await open(['device:read', 'device:update'])
    expect(btn(c, '编辑')).toBeTruthy()
    expect(btn(c, '新增设备')).toBeUndefined()
    expect(btn(c, '删除')).toBeUndefined()
  })
})

describe('DeviceView 列表加载与筛选', () => {
  test('首屏参数：page/limit/search/status 四元组与筛选状态一致', async () => {
    const c = await open()
    expect(getList.mock.calls).toHaveLength(1)
    expect(getList.mock.calls[0][0]).toEqual({ page: 1, limit: 10, search: '', status: '' })
    expect(cells(c)[0].join(' ')).toContain('SMK-001')
    expect(cells(c)[0].join(' ')).toContain('一层烟感')
    expect(c.errors).toEqual([])
  })

  test('翻到第 2 页后再改条件查询：页码回到 1 且条件真正进入请求参数', async () => {
    const c = await open(FULL, ROWS, 25)
    const next = c.find('.el-pagination .btn-next')
    expect(next).toBeTruthy()
    expect(next.disabled).toBe(false)
    click(next)
    await waitFor(() => getList.mock.calls.length === 2, { message: '第二页请求发出' })
    expect(getList.mock.calls[1][0].page).toBe(2)

    const searchInput = c.findAll('.filter-card input.el-input__inner')[0]
    typeInto(searchInput, '烟感')
    await flush(4)
    const searchBtn = btn(c, '搜索')
    expect(searchBtn).toBeTruthy()
    click(searchBtn)
    await waitFor(() => getList.mock.calls.length === 3, { message: '条件查询请求发出' })
    const params = getList.mock.calls[2][0]
    expect(params.page).toBe(1)
    expect(params.search).toBe('烟感')
    expect(params.status).toBe('')
  })

  test('重置：清空筛选并回到第 1 页', async () => {
    const c = await open(FULL, ROWS, 25)
    const searchInput = c.findAll('.filter-card input.el-input__inner')[0]
    typeInto(searchInput, '烟感')
    await flush(4)
    click(c.find('.el-pagination .btn-next'))
    await waitFor(() => getList.mock.calls.length === 2, { message: '第二页请求发出' })
    const resetBtn = btn(c, '重置')
    click(resetBtn)
    await waitFor(() => getList.mock.calls.length === 3, { message: '重置查询发出' })
    const params = getList.mock.calls[2][0]
    expect(params.search).toBe('')
    expect(params.page).toBe(1)
  })

  test('加载失败：清空列表并提示，不留旧数据', async () => {
    const c = await open()
    expect(cells(c)).toHaveLength(1)
    getList.mockRejectedValue(new Error('boom'))
    click(btn(c, '搜索'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示弹出' })
    expect(cells(c)).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('路由切换 abort 的在途请求：静默失败不弹错误（FE-L1）', async () => {
    const c = await open()
    isCanceledError.mockReturnValue(true)
    getList.mockRejectedValue(new Error('canceled'))
    click(btn(c, '搜索'))
    await waitFor(() => isCanceledError.mock.calls.length >= 1, { message: 'abort 分支被走到' })
    await flush(6)
    expect(ElMessage.error).not.toHaveBeenCalled()
    // 旧数据保留：abort 表示用户已离开，不是数据作废
    expect(cells(c)).toHaveLength(1)
  })
})

describe('DeviceView 新增保存载荷', () => {
  test('安装日期预填为本地今天（该日期由本机日历决定，UTC 快照口径会退一天）', async () => {
    const c = await open()
    const d = await openDialog(c, '新增设备')
    const dateInput = d.querySelector('.el-date-editor input')
    expect(dateInput).toBeTruthy()
    const now = new Date()
    const p = (n) => String(n).padStart(2, '0')
    const expectedLocal = `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`
    expect(dateInput.value).toBe(expectedLocal)
  })

  test('新增：deviceCode 留空提交 undefined（由后端生成，不得发空串）', async () => {
    create.mockResolvedValue({ data: { success: true } })
    const c = await open()
    const d = await openDialog(c, '新增设备')
    typeInto(d.querySelector('input[placeholder="设备名称"]'), '二层烟感')
    await flush(4)
    click(d.querySelector('.el-select__wrapper'))
    await flush(8)
    const opts = Array.from(visiblePopper().querySelectorAll('.el-select-dropdown__item'))
    expect(opts.length).toBeGreaterThan(0)
    const pickedLabel = opts[0].textContent.trim()
    click(opts[0])
    await flush(10)
    expect(d.querySelector('.el-select__placeholder').textContent.trim()).toBe(pickedLabel)
    const submit = dlgFootBtn('新增')
    expect(submit).toBeTruthy()
    click(submit)
    await waitFor(() => create.mock.calls.length === 1, { message: '新增请求发出' })
    const payload = create.mock.calls[0][0]
    expect(payload.deviceCode).toBeUndefined()
    expect(payload.deviceName).toBe('二层烟感')
    expect(payload.deviceType).toBeTruthy()
    expect(payload.installDate).toMatch(/^\d{4}-\d{2}-\d{2}/)
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('校验不通过：不发请求（设备名必填）', async () => {
    create.mockResolvedValue({ data: { success: true } })
    const c = await open()
    const d = await openDialog(c, '新增设备')
    const submit = dlgFootBtn('新增')
    expect(submit).toBeTruthy()
    click(submit)
    await waitFor(
      () =>
        Array.from(d.querySelectorAll('.el-form-item')).filter((it) =>
          it.classList.contains('is-error')
        ).length >= 2,
      { message: '设备名称与设备类型两项被标记为校验失败' }
    )
    await flush(10)
    expect(create).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})

describe('DeviceView 编辑', () => {
  test('编辑回填：本地日期口径（同一时刻若按 UTC 取日期会退一天）', async () => {
    // 构造本地 2026-01-05 00:30 的 ISO 串：东八区下其 UTC 日期是 01-04。
    // 台账的「安装日期」是本地日历概念，回填必须是 01-05。
    const row = { ...ROW, installDate: new Date(2026, 0, 5, 0, 30, 0).toISOString() }
    const c = await open(FULL, [row])
    const d = await openDialog(c, '编辑')
    const dateInput = d.querySelector('.el-date-editor input')
    expect(dateInput).toBeTruthy()
    expect(dateInput.value).toBe('2026-01-05')
    expect(c.errors).toEqual([])
  })

  test('编辑保存走 update（带 _id），且日期打开-保存回环不漂移', async () => {
    update.mockResolvedValue({ data: { success: true } })
    const c = await open()
    const d = await openDialog(c, '编辑')
    const dateInput = d.querySelector('.el-date-editor input')
    expect(dateInput.value).toBe('2026-01-05')
    const submit = dlgFootBtn('保存')
    expect(submit).toBeTruthy()
    click(submit)
    await waitFor(() => update.mock.calls.length === 1, { message: '更新请求发出' })
    expect(create).not.toHaveBeenCalled()
    expect(update.mock.calls[0][0]).toBe('d1')
    const payload = update.mock.calls[0][1]
    expect(payload.installDate).toBe('2026-01-05')
    expect(c.errors).toEqual([])
  })
})

describe('DeviceView 删除', () => {
  test('确认后调用删除接口并刷新列表', async () => {
    const c = await open()
    confirm.mockResolvedValueOnce('confirm')
    remove.mockResolvedValue({ data: { success: true } })
    const del = btn(c, '删除')
    expect(del).toBeTruthy()
    click(del)
    await waitFor(() => remove.mock.calls.length === 1, { message: '删除请求发出' })
    expect(remove.mock.calls[0][0]).toBe('d1')
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    await waitFor(() => getList.mock.calls.length === 2, { message: '删除后刷新列表' })
    expect(c.errors).toEqual([])
  })

  test('取消确认框：不得发删除请求、不得弹失败提示', async () => {
    const c = await open()
    confirm.mockRejectedValueOnce('cancel')
    const del = btn(c, '删除')
    click(del)
    await waitFor(() => confirm.mock.calls.length === 1, { message: '确认框已弹出' })
    await flush(20)
    expect(remove).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('删除失败：提示失败，不静默吞掉', async () => {
    const c = await open()
    confirm.mockResolvedValue('confirm')
    remove.mockRejectedValue(new Error('boom'))
    click(btn(c, '删除'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})
