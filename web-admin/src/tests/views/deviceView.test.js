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
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const getList = vi.fn()
const create = vi.fn()
const update = vi.fn()
const remove = vi.fn()
const getStats = vi.fn()
const getReminders = vi.fn()
const getExpiring = vi.fn()
const updateStatus = vi.fn()
const addMaintenance = vi.fn()
const isCanceledError = vi.fn(() => false)
vi.mock('@/utils/api', () => ({
  api: {
    devices: {
      getList: (...a) => getList(...a),
      create: (...a) => create(...a),
      update: (...a) => update(...a),
      delete: (...a) => remove(...a),
      getStats: (...a) => getStats(...a),
      getReminders: (...a) => getReminders(...a),
      getExpiring: (...a) => getExpiring(...a),
      updateStatus: (...a) => updateStatus(...a),
      addMaintenance: (...a) => addMaintenance(...a),
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

// 概览统计默认值：五个数字互不相同，任何错位（如 expired 用了 expiringSoon 的值）都可见
const STATS = { total: 8, expired: 1, expiringSoon: 2, needMaintenance: 3, needSchedule: 4 }
const REMINDERS = {
  scannedAt: '2026-10-19T08:00:00.000Z',
  summary: { expired: 1, expiringSoon: 1, needMaintenance: 1, needSchedule: 0, total: 3 },
  expired: [
    {
      _id: 'd9',
      deviceCode: 'EXT-009',
      deviceName: '过期灭火器',
      expiryDate: '2026-09-01T00:00:00.000Z',
      status: 'warning',
    },
  ],
  expiringSoon: [
    {
      _id: 'd8',
      deviceCode: 'SMK-008',
      deviceName: '临期烟感',
      expiryDate: '2026-10-25T00:00:00.000Z',
    },
  ],
  needMaintenance: [
    {
      _id: 'd7',
      deviceCode: 'PMP-007',
      deviceName: '待检水泵',
      nextCheckDate: '2026-10-01T00:00:00.000Z',
    },
  ],
  needSchedule: [],
  limits: {
    resultLimit: 20,
    truncated: { expired: false, expiringSoon: false, needMaintenance: false, needSchedule: false },
  },
  partial: false,
  skipped: false,
}

// 概览/提醒/清单三块都参与首屏加载：默认给成功值，失败分支由用例自行覆盖
beforeEach(() => {
  getStats.mockResolvedValue({ data: { data: STATS } })
  getReminders.mockResolvedValue({ data: { data: REMINDERS } })
  getExpiring.mockResolvedValue({
    data: { data: [], pagination: { total: 0, hasMore: false, limit: 20 } },
  })
})

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
  getStats.mockReset()
  getReminders.mockReset()
  getExpiring.mockReset()
  updateStatus.mockReset()
  addMaintenance.mockReset()
  confirm.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  document.body.innerHTML = ''
})

/** 表格第 i 行的全部按钮 */
const rowBtns = (c, i = 0) =>
  Array.from(c.findAll('.el-table__body-wrapper .el-table__row')[i].querySelectorAll('button'))
/** 表格第 i 行按文案找按钮 */
const rowBtn = (c, i, text) => rowBtns(c, i).find((b) => b.textContent.includes(text))

describe('DeviceView 写入口权限门控', () => {
  test('只读权限：新增/编辑/删除三个入口都不渲染，但列表照常可读', async () => {
    const c = await open(['device:read'])
    expect(btn(c, '新增设备')).toBeUndefined()
    expect(btn(c, '编辑')).toBeUndefined()
    expect(btn(c, '删除')).toBeUndefined()
    expect(btn(c, '变更状态')).toBeUndefined()
    expect(btn(c, '维护')).toBeUndefined()
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

  test('加载失败：清空列表、不留旧数据，且组件不弹 toast（提示归拦截器，P2-3）', async () => {
    const c = await open()
    expect(cells(c)).toHaveLength(1)
    getList.mockRejectedValue(new Error('boom'))
    click(btn(c, '搜索'))
    // 契约对齐 alarmView：列表加载失败由 api.js 响应拦截器统一提示，组件只清态。
    // 组件这里再弹一条的话，生产上同一次失败会弹两条（拦截器具体文案 + 组件泛化文案）。
    // 前提自证：本套件把 @/utils/api 整体替身掉，拦截器不参与 ⇒ 这里必须恰好 0 次；
    // 「用户仍能看到错误」的那一半由 apiRequestPipeline.test.js 走真实拦截器兜住。
    await waitFor(() => cells(c).length === 0, { message: '失败后列表清空' })
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.warning).not.toHaveBeenCalled()
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

  test('编辑保存保留 location.detail 且不把它误并入 room（P3 数据完整性回归）', async () => {
    // 后端 FireDevice.location.detail 是真实字段。旧 handleEdit 做了
    // `room = location.room || location.detail`，且 submitForm 重建 location 时丢掉 detail
    // → 编辑一台只有 detail（room 空）的设备，保存后 detail 被搬到 room 且原值消失。
    update.mockResolvedValue({ data: { success: true } })
    const row = {
      ...ROW,
      location: { building: 'A栋', floor: '1', room: '', detail: '靠东侧消防箱内' },
    }
    const c = await open(FULL, [row])
    await openDialog(c, '编辑')
    const submit = dlgFootBtn('保存')
    click(submit)
    await waitFor(() => update.mock.calls.length === 1, { message: '更新请求发出' })
    const { location } = update.mock.calls[0][1]
    expect(location.detail).toBe('靠东侧消防箱内') // 原样保留
    expect(location.room).toBe('') // 未被 detail 污染
    expect(c.errors).toEqual([])
  })

  test('编辑保存只发表单维护的 4 个 location 键（表单不碰的键交给服务端）', async () => {
    // DeviceService.updateDevice 对 location 按子字段合并，"没发的键保持原值"，
    // 所以前端不再需要回传整块 location 来保护 API/导入写入的 coordinates.{lat,lng}
    // ——该存活语义由 src/tests/services/deviceLocationMerge.test.js 钉住。
    // 这里钉的是另一半：载荷不得越界携带表单不维护的键。回传底一旦回来，它就变成
    // "以打开对话框那一刻的快照覆盖别人在此期间改过的子字段"（后写覆盖先写）。
    update.mockResolvedValue({ data: { success: true } })
    const row = {
      ...ROW,
      location: {
        building: 'A栋',
        floor: '1',
        room: '101',
        coordinates: { lat: 31.2, lng: 121.4 },
      },
    }
    const c = await open(FULL, [row])
    await openDialog(c, '编辑')
    click(dlgFootBtn('保存'))
    await waitFor(() => update.mock.calls.length === 1, { message: '更新请求发出' })
    const { location } = update.mock.calls[0][1]
    expect(Object.keys(location).sort()).toEqual(['building', 'detail', 'floor', 'room'])
    expect(location.building).toBe('A栋') // 可编辑字段取自表单回填值
    expect(c.errors).toEqual([])
  })

  test('location 的 4 个键必须都是字符串：清空靠空串上线，靠 undefined 会被传输层吃掉', async () => {
    // 合并语义下"缺键＝不改动"，而 `JSON.stringify` 恰好会丢掉值为 undefined 的键 ⇒
    // 把清空写成 `|| undefined`，服务端读到的是"没提这个字段"，旧值原样躺着。
    // 本仓在 PUT /api/auth/profile 上踩过同一个坑（见
    // src/tests/routes/profileFieldClearability.test.js：空串才是合法清空指令）。
    // room 是有输入框的那一格：删空提交即本用例的载荷形态。detail 目前没有输入框，
    // 表单值恒为回填值（库里没有就是 ''），它必须与另外三格同形，否则一旦补上输入框，
    // "清空详细位置"又是一个表达不出来的动作。
    update.mockResolvedValue({ data: { success: true } })
    const row = { ...ROW, location: { building: 'A栋', floor: '1', room: '101' } }
    const c = await open(FULL, [row])
    const d = await openDialog(c, '编辑')
    typeInto(d.querySelector('input[placeholder="房间"]'), '') // 用户删空房间
    await flush(3)
    click(dlgFootBtn('保存'))
    await waitFor(() => update.mock.calls.length === 1, { message: '更新请求发出' })
    const { location } = update.mock.calls[0][1]
    // 逐键过一遍真实序列化：任何一键是 undefined 都会在这里消失，清空就表达不出来
    const onTheWire = JSON.parse(JSON.stringify({ location })).location
    expect(Object.keys(onTheWire).sort()).toEqual(['building', 'detail', 'floor', 'room'])
    expect(onTheWire.room).toBe('') // 删空的格子以空串上线，而不是蒸发成"没提这个字段"
    expect(onTheWire.detail).toBe('')
    expect(c.errors).toEqual([])
  })

  test('编辑保存：清空检查周期后载荷为 undefined（null 会触发后端 .optional().isInt 400）', async () => {
    update.mockResolvedValue({ data: { success: true } })
    const c = await open(FULL, [{ ...ROW, checkCycle: 45 }])
    const d = await openDialog(c, '编辑')
    const numInput = d.querySelector('.el-input-number input')
    expect(numInput).toBeTruthy()
    expect(numInput.value).toBe('45')
    // 清空 el-input-number：valueOnClear 默认 null → 触发 change 后 v-model 变 null
    numInput.value = ''
    numInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    numInput.dispatchEvent(new window.Event('change', { bubbles: true }))
    await flush(6)
    click(dlgFootBtn('保存'))
    await waitFor(() => update.mock.calls.length === 1, { message: '更新请求发出' })
    const payload = update.mock.calls[0][1]
    // 后端 deviceRoutes 的 checkCycle 是 .optional().isInt({min:1,max:365})：.optional() 只对
    // undefined 放行，null 仍进 isInt → 400「检查周期应为 1-365 天」。客户端把 null 归一为 undefined。
    expect(payload.checkCycle).toBeUndefined()
    expect(payload.checkCycle).not.toBeNull()
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

  test('删除失败：请求已发出且被处理，不双提示（错误 toast 由拦截器负责）、不误报成功', async () => {
    const c = await open()
    confirm.mockResolvedValue('confirm')
    remove.mockRejectedValue(new Error('boom'))
    click(btn(c, '删除'))
    await waitFor(() => remove.mock.calls.length === 1, { message: '删除请求发出' })
    await flush(8)
    // 2026-09-26 审计：操作失败的 toast 由 api 拦截器统一弹出（携带具体错误语义），
    // 组件再补泛化文案会双提示并覆盖具体语义。用户可见的失败反馈在
    // src/tests/utils/apiRequestPipeline.test.js 覆盖；这里钉的是组件侧契约：
    // 拒绝被 catch 处理（无未捕获异常进 errorHandler）、不误报成功、不双提示。
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})

describe('DeviceView 概览条', () => {
  test('统计成功：渲染 5 张卡，数字与标签一一对应', async () => {
    const c = await open()
    await waitFor(() => c.find('.device-overview'), { message: '概览条渲染' })
    const cards = c.findAll('.device-overview .mini-stat')
    expect(cards).toHaveLength(5)
    const text = (i) => cards[i].textContent
    expect(text(0)).toContain('设备总数')
    expect(text(0)).toContain('8')
    expect(text(1)).toContain('已过期')
    expect(text(1)).toContain('1')
    expect(text(2)).toContain('即将到期')
    expect(text(2)).toContain('2')
    expect(text(3)).toContain('待维护')
    expect(text(3)).toContain('3')
    expect(text(4)).toContain('未排期')
    expect(text(4)).toContain('4')
    expect(getStats).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('首屏统计失败：概览条整条不渲染（5 张 0 卡会被读成「设备全好」），且不弹 toast', async () => {
    getStats.mockRejectedValue(new Error('boom'))
    const c = await open()
    await flush(6)
    expect(c.find('.device-overview')).toBeNull()
    // 列表照常可读，失败只是概览缺席
    expect(cells(c)).toHaveLength(1)
    // 失败静默：错误提示归 api 拦截器（组件再弹会双提示）
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('已有读数后刷新失败：保留上一次已知数字（不清成 0）', async () => {
    const c = await open()
    await waitFor(() => c.find('.device-overview'), { message: '概览条渲染' })
    getStats.mockRejectedValue(new Error('boom'))
    click(btn(c, '刷新'))
    await waitFor(() => getStats.mock.calls.length === 2, { message: '刷新触发第二次统计请求' })
    await flush(6)
    expect(c.find('.device-overview').textContent).toContain('8')
    expect(ElMessage.error).not.toHaveBeenCalled()
  })
})

describe('DeviceView 即将到期清单', () => {
  test('点击「即将到期」卡：打开清单并请求 days=30；切到 90 天按新窗口重新请求', async () => {
    const c = await open()
    await waitFor(() => c.find('.device-overview'), { message: '概览条渲染' })
    click(c.findAll('.device-overview .mini-stat')[2])
    await waitFor(() => getExpiring.mock.calls.length === 1, { message: '到期清单请求发出' })
    expect(getExpiring.mock.calls[0][0]).toEqual({ days: 30 })
    await waitFor(() => dlg(), { message: '清单弹窗打开' })
    const radios = Array.from(dlg().querySelectorAll('.el-radio-button'))
    expect(radios.map((el) => el.textContent.trim())).toEqual(['7 天内', '30 天内', '90 天内'])
    click(radios[2].querySelector('input') || radios[2])
    await waitFor(() => getExpiring.mock.calls.length === 2, { message: '切窗口请求发出' })
    expect(getExpiring.mock.calls[1][0]).toEqual({ days: 90 })
    expect(c.errors).toEqual([])
  })

  test('窗口内无设备：显示空态文案', async () => {
    const c = await open()
    await waitFor(() => c.find('.device-overview'), { message: '概览条渲染' })
    click(c.findAll('.device-overview .mini-stat')[2])
    await waitFor(() => dlg()?.querySelector('.expiring-empty'), { message: '空态渲染' })
    expect(dlg().querySelector('.expiring-empty').textContent).toContain('没有即将到期')
  })

  test('截断（hasMore）：回显真实命中 total 与限制 limit，不得只给页内条数', async () => {
    getExpiring.mockResolvedValue({
      data: {
        data: [
          {
            _id: 'd1',
            deviceCode: 'SMK-001',
            deviceName: '一层烟感',
            status: 'normal',
            expiryDate: '2026-10-25T00:00:00.000Z',
          },
        ],
        pagination: { total: 57, hasMore: true, limit: 20 },
      },
    })
    const c = await open()
    await waitFor(() => c.find('.device-overview'), { message: '概览条渲染' })
    click(c.findAll('.device-overview .mini-stat')[2])
    await waitFor(() => dlg()?.querySelector('.expiring-more'), { message: '截断提示渲染' })
    const hint = dlg().querySelector('.expiring-more').textContent
    expect(hint).toContain('57')
    expect(hint).toContain('20')
    expect(c.errors).toEqual([])
  })

  test('清单加载失败：失败块展示重试入口，点击重试重新请求', async () => {
    getExpiring.mockRejectedValue(new Error('boom'))
    const c = await open()
    await waitFor(() => c.find('.device-overview'), { message: '概览条渲染' })
    click(c.findAll('.device-overview .mini-stat')[2])
    await waitFor(() => dlg()?.querySelector('.expiring-failed'), { message: '失败块渲染' })
    const retry = Array.from(dlg().querySelectorAll('button')).find((b) =>
      b.textContent.includes('刷新')
    )
    expect(retry).toBeTruthy()
    getExpiring.mockResolvedValue({
      data: { data: [], pagination: { total: 0, hasMore: false, limit: 20 } },
    })
    click(retry)
    await waitFor(() => getExpiring.mock.calls.length === 2, { message: '重试请求发出' })
    await waitFor(() => dlg()?.querySelector('.expiring-empty'), { message: '重试成功回到空态' })
    expect(c.errors).toEqual([])
  })
})

describe('DeviceView 到期提醒入口', () => {
  const badgeValue = (c) => {
    const sup = c.find('.reminder-badge-wrap .el-badge__content')
    if (!sup) return null
    return sup.style.display === 'none' ? null : sup.textContent.trim()
  }

  test('有到期项：徽标显示 summary.total；打开弹窗触发一次刷新请求', async () => {
    const c = await open()
    await waitFor(() => badgeValue(c) === '3', { message: '徽标渲染总数 3' })
    expect(getReminders).toHaveBeenCalledTimes(1) // 首屏静默拉取（徽标数据源）
    click(btn(c, '到期提醒'))
    await waitFor(() => getReminders.mock.calls.length === 2, { message: '打开弹窗时刷新' })
    await waitFor(() => dlg(), { message: '提醒弹窗渲染' })
    expect(dlg().textContent).toContain('到期提醒清单')
    expect(c.errors).toEqual([])
  })

  test('无到期项：不显示徽标（0 不打扰）', async () => {
    getReminders.mockResolvedValue({
      data: {
        data: {
          ...REMINDERS,
          summary: { expired: 0, expiringSoon: 0, needMaintenance: 0, needSchedule: 0, total: 0 },
        },
      },
    })
    const c = await open()
    await waitFor(() => getReminders.mock.calls.length >= 1, { message: '提醒请求发出' })
    await flush(6)
    expect(badgeValue(c)).toBeNull()
  })

  test('提醒加载失败：徽标不显示；弹窗内提供失败态与重试', async () => {
    getReminders.mockRejectedValue(new Error('boom'))
    const c = await open()
    await flush(6)
    expect(badgeValue(c)).toBeNull()
    click(btn(c, '到期提醒'))
    await waitFor(() => dlg()?.querySelector('.reminder-failed'), { message: '弹窗失败态渲染' })
    const retry = Array.from(dlg().querySelectorAll('button')).find((b) =>
      b.textContent.includes('刷新')
    )
    getReminders.mockResolvedValue({ data: { data: REMINDERS } })
    click(retry)
    await waitFor(() => getReminders.mock.calls.length === 3, { message: '重试发出' })
    await waitFor(() => dlg()?.textContent.includes('过期灭火器'), { message: '重试后清单渲染' })
    expect(c.errors).toEqual([])
  })
})

describe('DeviceView 变更状态', () => {
  const WRITABLE = ['normal', 'warning', 'fault', 'offline', 'maintenance']

  test('确认框带单选组（5 个可写状态，默认选中当前值）；确认后按选中值提交并回表刷新', async () => {
    const c = await open()
    updateStatus.mockResolvedValue({ data: { success: true } })
    const seen = {}
    confirm.mockImplementation((msg, title, opts) => {
      expect(typeof msg).toBe('function')
      const vnode = msg()
      const group = vnode.children[1]
      const radios = group.children.default()
      seen.values = radios.map((r) => r.props.value)
      seen.initial = group.props.modelValue
      seen.title = title
      seen.type = opts?.type
      group.props['onUpdate:modelValue']('maintenance')
      return Promise.resolve('confirm')
    })
    click(rowBtn(c, 0, '变更状态'))
    await waitFor(() => updateStatus.mock.calls.length === 1, { message: '状态更新请求发出' })
    expect(seen.values).toEqual(WRITABLE)
    expect(seen.initial).toBe('normal')
    expect(seen.title).toBe('变更状态')
    expect(seen.type).toBe('warning')
    expect(updateStatus.mock.calls[0][0]).toBe('d1')
    expect(updateStatus.mock.calls[0][1]).toEqual({ status: 'maintenance' })
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    // 成功后列表/概览一起刷新（三块同页展示，必须同源）
    await waitFor(() => getList.mock.calls.length === 2, { message: '列表刷新' })
    await waitFor(() => getStats.mock.calls.length === 2, { message: '概览刷新' })
    expect(c.errors).toEqual([])
  })

  test('报废行：变更状态与维护入口不渲染（后端必拒的入口不出现）', async () => {
    const c = await open(FULL, [{ ...ROW, status: 'scrapped' }])
    expect(rowBtn(c, 0, '变更状态')).toBeUndefined()
    expect(rowBtn(c, 0, '维护')).toBeUndefined()
    // 编辑/删除不受影响（报废行仍可改资料/删除）
    expect(rowBtn(c, 0, '编辑')).toBeTruthy()
    expect(rowBtn(c, 0, '删除')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('取消确认：不发 updateStatus、不弹成功；行锁释放', async () => {
    const c = await open()
    confirm.mockRejectedValue('cancel')
    click(rowBtn(c, 0, '变更状态'))
    await waitFor(() => confirm.mock.calls.length === 1, { message: '确认框弹出' })
    await flush(10)
    expect(updateStatus).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(rowBtn(c, 0, '变更状态').disabled).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('updateStatus 失败：不弹成功、行锁释放（可重试）', async () => {
    const c = await open()
    confirm.mockResolvedValue('confirm')
    updateStatus.mockRejectedValue(new Error('boom'))
    click(rowBtn(c, 0, '变更状态'))
    await waitFor(() => updateStatus.mock.calls.length === 1, { message: '请求发出' })
    await flush(10)
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(rowBtn(c, 0, '变更状态').disabled).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('重入：同一 tick 双击只弹一次确认框（按钮 disabled 尚未生效时的守卫）', async () => {
    const c = await open()
    confirm.mockImplementation(() => new Promise(() => {}))
    const b = rowBtn(c, 0, '变更状态')
    click(b)
    click(b)
    await flush(4)
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })
})

describe('DeviceView 维护登记', () => {
  const MAINTAIN_PERMS = [...FULL, 'device:maintain']

  test('无 device:maintain：维护入口不渲染', async () => {
    const c = await open()
    expect(rowBtn(c, 0, '维护')).toBeUndefined()
  })

  test('有权限：打开维护弹窗（类型默认例行检查），提交后提示并刷新列表/概览', async () => {
    const c = await open(MAINTAIN_PERMS)
    addMaintenance.mockResolvedValue({ data: { success: true } })
    const entry = rowBtn(c, 0, '维护')
    expect(entry).toBeTruthy()
    click(entry)
    await waitFor(() => dlg(), { message: '维护弹窗打开' })
    await flush(4)
    expect(dlg().textContent).toContain('添加维护')
    // 设备上下文带入弹窗，用户不必凭记忆核对是哪台设备
    expect(dlg().textContent).toContain('SMK-001')
    const textarea = dlg().querySelector('textarea')
    expect(textarea).toBeTruthy()
    textarea.value = '  更换压力表  '
    textarea.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    const submit = dlgFootBtn('确定')
    expect(submit).toBeTruthy()
    click(submit)
    await waitFor(() => addMaintenance.mock.calls.length === 1, { message: '维护请求发出' })
    expect(addMaintenance.mock.calls[0][0]).toBe('d1')
    expect(addMaintenance.mock.calls[0][1]).toEqual({ content: '更换压力表', type: 'routine' })
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    await waitFor(() => getList.mock.calls.length === 2, { message: '列表刷新' })
    await waitFor(() => getStats.mock.calls.length === 2, { message: '概览刷新' })
    expect(c.errors).toEqual([])
  })

  test('纯空格内容：本地校验拦截，不发请求（后端 trim 后必拒）', async () => {
    const c = await open(MAINTAIN_PERMS)
    addMaintenance.mockResolvedValue({ data: { success: true } })
    click(rowBtn(c, 0, '维护'))
    await waitFor(() => dlg(), { message: '维护弹窗打开' })
    await flush(4)
    const textarea = dlg().querySelector('textarea')
    textarea.value = '   '
    textarea.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    click(dlgFootBtn('确定'))
    await flush(12)
    expect(addMaintenance).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(dlg().querySelector('.el-form-item.is-error')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('提交失败：不弹成功、弹窗保持打开、可重试（submitting 复位）', async () => {
    const c = await open(MAINTAIN_PERMS)
    addMaintenance.mockRejectedValue(new Error('boom'))
    click(rowBtn(c, 0, '维护'))
    await waitFor(() => dlg(), { message: '维护弹窗打开' })
    await flush(4)
    const textarea = dlg().querySelector('textarea')
    textarea.value = '更换压力表'
    textarea.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    click(dlgFootBtn('确定'))
    await waitFor(() => addMaintenance.mock.calls.length === 1, { message: '请求发出' })
    await flush(8)
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled() // 错误 toast 归拦截器
    expect(dlg()).toBeTruthy() // 弹窗保持打开，内容不丢，可直接重试
    const submit = dlgFootBtn('确定')
    expect(submit.disabled).toBe(false)
    expect(c.errors).toEqual([])
  })
})
