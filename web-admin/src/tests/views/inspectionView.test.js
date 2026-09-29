/**
 * InspectionView 渲染与交互行为（2026-09-18）
 *
 * 缺陷 #2 回归（修复前实测复现）：计划时间列原本是 el-table-column prop="planStartTime"，
 * 把后端返回的 ISO UTC 串原样渲染——东八区用户看到的时间比真实时间早 8 小时
 * （实测 probe：planStartTime = "2026-10-01T01:00:00.000Z" 直接进 DOM）。
 * 现改走 utils/datetime 的 formatTime（全仓统一本地时区口径）。
 *
 * 期望值在本文件内**独立计算**（Date 的本地 getter + 补零），不 import formatTime，
 * 否则 formatTime 自身写错时两边一起错、断言恒真。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const getList = vi.fn()
const getStats = vi.fn()
const start = vi.fn()
const remove = vi.fn()
const getById = vi.fn()
const isCanceledError = vi.fn(() => false)
vi.mock('@/utils/api', () => ({
  api: {
    inspections: {
      getList: (...a) => getList(...a),
      getStats: (...a) => getStats(...a),
      start: (...a) => start(...a),
      delete: (...a) => remove(...a),
      getById: (...a) => getById(...a),
      review: vi.fn(),
    },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: vi.fn() },
}))

import i18n from '@/i18n'
import InspectionView from '@/views/InspectionView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'

let active = null
const PERMS = ['inspection:read', 'inspection:review', 'inspection:execute', 'inspection:delete']

/** 独立计算本地时区渲染结果（与实现无关的口径） */
const expectLocal = (iso) => {
  const d = new Date(iso)
  const p = (n) => String(n).padStart(2, '0')
  return (
    d.getFullYear() +
    '-' +
    p(d.getMonth() + 1) +
    '-' +
    p(d.getDate()) +
    ' ' +
    p(d.getHours()) +
    ':' +
    p(d.getMinutes()) +
    ':' +
    p(d.getSeconds())
  )
}

/** mount 成功后等待列表数据落地 */
const open = async (rows, opts = {}) => {
  getList.mockResolvedValue({
    data: { data: rows, pagination: opts.pagination || { total: rows.length } },
  })
  // opts.statsReject：让统计请求本身失败（首屏失败块的入口条件）；
  // 不给时保持原默认——成功但 data 为空，四张卡 0。
  if (opts.statsReject) getStats.mockRejectedValue(new Error('stats down'))
  else getStats.mockResolvedValue(opts.stats || { data: { success: true, data: {} } })
  getById.mockResolvedValue({ data: { data: { title: 'r', findings: [] } } })
  active = mountComponent(InspectionView, {
    setupStore: (pinia) => {
      useAuthStore(pinia).setPermissions(opts.perms || PERMS)
    },
  })
  await waitFor(
    () => active.findAll('.el-table__body-wrapper .el-table__row').length === rows.length,
    {
      message: '列表行渲染完成',
    }
  )
  await flush(2)
  return active
}

/** 数据行单元格文本矩阵 */
const cells = (c) =>
  c
    .findAll('.el-table__body-wrapper .el-table__row')
    .map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.trim()))

afterEach(() => {
  active?.handle.unmount()
  active = null
  getList.mockReset()
  getStats.mockReset()
  start.mockReset()
  remove.mockReset()
  getById.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  // 确认框的调用计数同样是**跨用例共享**的模块级状态：漏了这一行，
  // `expect(ElMessageBox.confirm).toHaveBeenCalledTimes(1)` 就把前面用例留下的
  // 调用一起数（默认顺序恰好把它排在第一个确认框用例之后所以一直侥幸绿，
  // `--sequence.shuffle` 一打散就变成 "expected 1 times, but got 3 times"）。
  ElMessageBox.confirm.mockReset()
})

describe('InspectionView 计划时间列（本地时区口径）', () => {
  test('ISO UTC 串按本地时区渲染，且不是 ISO 原串（防退回 prop 直渲染）', async () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const c = await open([{ _id: 'i1', title: '季度巡检', status: 'pending', planStartTime: iso }])
    const expected = expectLocal(iso)
    // 期望值自检：证明它不是空串/原串，否则下面的断言会退化
    expect(expected).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
    expect(expected).not.toBe(iso)
    // 第 5 列（1-based：序号/标题/类型/负责人/计划开始时间）
    const row = cells(c)[0]
    expect(row[4]).toBe(expected)
    expect(row[4]).not.toContain('T')
    expect(row[4]).not.toContain('Z')
    expect(c.errors).toEqual([])
  })

  test('多行各自渲染自己的时间（不是复用首行/写死格式）', async () => {
    const a = '2026-10-01T01:00:00.000Z'
    const b = '2026-11-05T23:30:15.000Z'
    const c = await open([
      { _id: 'i1', title: 'A', status: 'pending', planStartTime: a },
      { _id: 'i2', title: 'B', status: 'completed', planStartTime: b },
    ])
    const rows = cells(c)
    expect(rows[0][4]).toBe(expectLocal(a))
    expect(rows[1][4]).toBe(expectLocal(b))
    expect(expectLocal(a)).not.toBe(expectLocal(b))
  })

  test('时间缺失时渲染为 -（不是 undefined / Invalid Date）', async () => {
    const c = await open([{ _id: 'i1', title: 'A', status: 'pending' }])
    const cell = cells(c)[0][4]
    expect(cell).toBe('-')
    expect(cell).not.toContain('Invalid')
  })
})

describe('InspectionView 加载路径', () => {
  test('加载失败：清空列表（不留旧数据）并提示，不抛 Vue 错误', async () => {
    const rows = [{ _id: 'i1', title: 'A', status: 'pending', planStartTime: null }]
    const c = await open(rows)
    expect(cells(c)).toHaveLength(1)
    getList.mockRejectedValue(new Error('boom'))
    click(c.find('.glass-btn--default'))
    await waitFor(() => ElMessage.warning.mock.calls.length === 1, { message: '加载失败提示' })
    expect(cells(c)).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('路由切换 abort 的在途请求：静默失败不弹「加载失败」（FE-L1）', async () => {
    const c = await open([{ _id: 'i1', title: 'A', status: 'pending', planStartTime: null }])
    isCanceledError.mockReturnValue(true)
    getList.mockRejectedValue(new Error('canceled'))
    click(c.find('.glass-btn--default'))
    await waitFor(() => isCanceledError.mock.calls.length === 1, { message: 'abort 分支被走到' })
    expect(ElMessage.warning).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('请求参数透传当前页码/每页条数与筛选状态', async () => {
    const c = await open([{ _id: 'i1', title: 'A', status: 'pending', planStartTime: null }])
    expect(getList).toHaveBeenCalledWith({ page: 1, limit: 10, status: '' })
    expect(c.errors).toEqual([])
  })
})

describe('InspectionView 启动/删除（操作分支）', () => {
  /** 按可见文本找按钮（Element Plus 会把文案渲染在 button 内） */
  const buttonByText = (c, text) =>
    c.findAll('button').find((b) => b.textContent.replace(/\s+/g, ' ').trim() === text)

  const rowWith = (over = {}) => ({
    _id: 'p1',
    title: '月度巡检',
    status: 'pending',
    planStartTime: null,
    ...over,
  })

  test('启动：确认框带上单据名，确认后 start(_id) + 成功提示 + 重新拉列表', async () => {
    const c = await open([rowWith()])
    const before = getList.mock.calls.length
    ElMessageBox.confirm.mockResolvedValue('confirm')
    start.mockResolvedValue({ data: { success: true } })

    click(buttonByText(c, i18n.global.t('inspection.start')))
    await flush(8)

    expect(ElMessageBox.confirm).toHaveBeenCalledTimes(1)
    const [message, title] = ElMessageBox.confirm.mock.calls[0]
    expect(message).toContain('月度巡检')
    expect(title).toBe(i18n.global.t('messages.confirmTitle'))
    expect(start).toHaveBeenCalledTimes(1)
    expect(start).toHaveBeenCalledWith('p1')
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('messages.updateSuccess'))
    expect(getList.mock.calls.length).toBeGreaterThan(before)
    expect(c.errors).toEqual([])
  })

  test('启动确认框被取消/关闭：不发请求、不弹失败提示（用户主动放弃不是错误）', async () => {
    for (const reason of ['cancel', 'close']) {
      start.mockClear()
      getList.mockClear()
      ElMessage.error.mockClear()
      ElMessageBox.confirm.mockReset()
      ElMessageBox.confirm.mockRejectedValueOnce(reason)
      const c = await open([rowWith()])
      start.mockClear()
      ElMessage.error.mockClear()

      click(buttonByText(c, i18n.global.t('inspection.start')))
      await flush(8)

      expect(start, reason + ' 时不得发起启动请求').not.toHaveBeenCalled()
      expect(ElMessage.error, reason + ' 时不得提示失败').not.toHaveBeenCalled()
      expect(c.errors).toEqual([])
    }
  })

  test('启动请求失败：提示失败、不提示成功、不刷新列表', async () => {
    const c = await open([rowWith()])
    const before = getList.mock.calls.length
    ElMessageBox.confirm.mockResolvedValue('confirm')
    start.mockRejectedValue(new Error('server down'))

    click(buttonByText(c, i18n.global.t('inspection.start')))
    await flush(8)

    // 2026-09-26 审计后，操作失败的 toast 由 api 拦截器统一弹出（携带具体错误语义）；
    // 组件再补泛化「更新失败」会双提示并覆盖具体文案。组件侧的新契约是：
    // 不双提示、不误报成功、不刷新列表（拦截器自身的提示行为在
    // src/tests/utils/apiRequestPipeline.test.js 覆盖）。
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(getList.mock.calls.length).toBe(before)
    expect(c.errors).toEqual([])
  })

  test('删除：确认后 delete(_id) + 成功提示 + 重新拉列表；取消则不发请求', async () => {
    const c = await open([rowWith({ _id: 'd1', title: '待删单据' })])
    const before = getList.mock.calls.length
    ElMessageBox.confirm.mockResolvedValue('confirm')
    remove.mockResolvedValue({ data: { success: true } })

    click(buttonByText(c, i18n.global.t('common.delete')))
    await flush(8)

    expect(remove).toHaveBeenCalledTimes(1)
    expect(remove).toHaveBeenCalledWith('d1')
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('messages.deleteSuccess'))
    expect(getList.mock.calls.length).toBeGreaterThan(before)

    remove.mockClear()
    ElMessageBox.confirm.mockReset()
    ElMessageBox.confirm.mockRejectedValueOnce('cancel')
    click(buttonByText(c, i18n.global.t('common.delete')))
    await flush(8)
    expect(remove).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('删除失败：不双提示（错误 toast 由拦截器负责）、不误报成功、不刷新列表', async () => {
    const c = await open([rowWith({ _id: 'd1' })])
    const before = getList.mock.calls.length
    ElMessageBox.confirm.mockResolvedValue('confirm')
    remove.mockRejectedValue(new Error('forbidden'))

    click(buttonByText(c, i18n.global.t('common.delete')))
    await flush(8)

    // 2026-09-26 审计：组件不再自弹泛化「删除失败」（会与拦截器的具体文案双提示）；
    // 用户可见的失败反馈由拦截器保证，在 apiRequestPipeline.test.js 覆盖。
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(getList.mock.calls.length).toBe(before)
  })

  test('执行中的单据不渲染删除入口（避免删掉正在巡检的单据）', async () => {
    const c = await open([rowWith({ status: 'in_progress' })])
    expect(buttonByText(c, i18n.global.t('common.delete'))).toBeUndefined()
    // 反证：同一行确实渲染了其它操作按钮，说明按钮区不是整体缺失
    expect(buttonByText(c, i18n.global.t('inspection.complete'))).toBeTruthy()
  })

  test('每一行只渲染与其状态匹配的操作按钮（状态与入口不得错配）', async () => {
    const c = await open([
      rowWith({ _id: 'a', title: 'A', status: 'pending' }),
      rowWith({ _id: 'b', title: 'B', status: 'in_progress' }),
      rowWith({ _id: 'c', title: 'C', status: 'completed' }),
      rowWith({ _id: 'd', title: 'D', status: 'overdue' }),
    ])
    const rowOf = (title) =>
      cells(c)
        .find((r) => r[1] === title)
        .join(' ')
    expect(rowOf('A')).toContain(i18n.global.t('inspection.start'))
    expect(rowOf('A')).not.toContain(i18n.global.t('inspection.complete'))
    expect(rowOf('B')).toContain(i18n.global.t('inspection.complete'))
    expect(rowOf('B')).not.toContain(i18n.global.t('inspection.start'))
    expect(rowOf('C')).toContain(i18n.global.t('inspection.review'))
    // 逾期行两个入口都必须在：后端把 overdue 同时留在「可开工」与「可提交」集合里
    // （constants/inspection.js 的 INSPECTION_STARTABLE / SUBMITTABLE_STATUSES），
    // 少任何一个都是「真实做过的工作没有入库入口」。
    expect(rowOf('D')).toContain(i18n.global.t('inspection.start'))
    expect(rowOf('D')).toContain(i18n.global.t('inspection.complete'))
    expect(rowOf('C')).not.toContain(i18n.global.t('inspection.start'))
  })

  test('状态筛选切换后按新状态重新请求', async () => {
    const c = await open([rowWith()])
    getList.mockClear()

    const pendingLabel = c
      .findAll('.el-radio-button')
      .find((el) => el.textContent.includes(i18n.global.t('inspection.pending')))
    expect(pendingLabel, '未找到「待巡检」筛选项').toBeTruthy()
    click(pendingLabel.querySelector('input') || pendingLabel)
    await flush(8)

    expect(getList).toHaveBeenCalled()
    const last = getList.mock.calls[getList.mock.calls.length - 1][0]
    expect(last.status).toBe('pending')
    expect(last.page).toBe(1)
  })

  // 上面那条钉不住这个缺陷：它从第 1 点筛选，page 本来就是 1，
  // 断言恒真。真正的不变量是「换筛选条件 ⇒ 页码归位」，必须先离开第 1 页。
  // 少了这一步，用户在第 N 页切到「待巡检」时发出的是 page=N + 新筛选，
  // 结果集不足 N 页 ⇒ 表格先空一片，而 total 显示还有数据。
  // 同工程的 AlarmView / DeviceView / AuditLogView 都有这一步，此前只有本视图漏掉。
  test('状态筛选切换必须回到第 1 页（停在第 N 页会看到空表）', async () => {
    const c = await open([rowWith()], { pagination: { total: 50 } })
    click(c.find('.btn-next'))
    await waitFor(() => getList.mock.calls.length === 2, { message: '翻页请求发出' })
    expect(getList.mock.calls[1][0].page).toBe(2)

    const pendingLabel = c
      .findAll('.el-radio-button')
      .find((el) => el.textContent.includes(i18n.global.t('inspection.pending')))
    expect(pendingLabel, '未找到「待巡检」筛选项').toBeTruthy()
    click(pendingLabel.querySelector('input') || pendingLabel)
    await waitFor(() => getList.mock.calls.length === 3, { message: '筛选请求发出' })
    expect(getList.mock.calls[2][0]).toEqual({ page: 1, limit: 10, status: 'pending' })
  })
})
describe('InspectionView 复核对话框接线', () => {
  test('点击已完成行的「审核」：对话框收到该行 _id 并按它拉详情', async () => {
    const c = await open([
      { _id: 'insp-77', title: '待审巡检', status: 'completed', planStartTime: null },
    ])
    const reviewBtn = c
      .findAll('.glass-btn--link')
      .find((b) => b.textContent.includes('审核') || b.textContent.includes('复核'))
    expect(reviewBtn).toBeTruthy()
    click(reviewBtn)
    await waitFor(() => getById.mock.calls.length === 1, { message: '复核详情按行 _id 加载' })
    expect(getById).toHaveBeenCalledWith('insp-77')
    expect(c.errors).toEqual([])
  })

  test('未完成的行不渲染「审核」入口（避免对不可审的单据发起复核）', async () => {
    const c = await open([
      { _id: 'i1', title: '进行中', status: 'in_progress', planStartTime: null },
    ])
    const labels = c.findAll('.glass-btn--link').map((b) => b.textContent.trim())
    expect(labels.some((x) => x.includes('审核') || x.includes('复核'))).toBe(false)
  })
})

describe('InspectionView 竞态守卫与结果列', () => {
  /**
   * 真实退化（每条都只会「看起来正常」）：
   *  - 去掉 isCurrent 守卫：快速筛选时旧响应后到，把新结果覆盖成上一条件的旧数据；
   *  - 旧响应还顺手把 loading 置回 false，用户看到「已加载完」的假象；
   *  - 结果列退回 prop 直渲染：枚举码直接进 DOM（或恒空）；
   *  - 详情入口不置只读：查看详情时出现「保存」，误点就改数据。
   */
  const r = (title, over = {}) => ({ _id: 'id-' + title, title, status: 'pending', ...over })

  /** 点击筛选按钮（按文案找） */
  const pickFilter = (c, text) => {
    const btn = Array.from(c.find('.el-radio-group').querySelectorAll('.el-radio-button')).find(
      (b) => b.textContent.includes(text)
    )
    expect(btn, `筛选按钮 ${text} 未找到`).toBeTruthy()
    return btn
  }

  test('过期响应不得覆盖新结果：先发的慢请求后到时被丢弃', async () => {
    let releaseSlow
    getList.mockImplementationOnce(
      () =>
        new Promise((res) => {
          releaseSlow = () => res({ data: { data: [r('旧数据')], pagination: { total: 1 } } })
        })
    )
    getList.mockImplementationOnce(() =>
      Promise.resolve({ data: { data: [r('新数据')], pagination: { total: 1 } } })
    )
    getStats.mockResolvedValue({ data: { success: true, data: {} } })
    active = mountComponent(InspectionView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(PERMS),
    })
    await waitFor(() => getList.mock.calls.length === 1, { message: '首请求发出' })

    // 触发第二次加载（筛选切换）——它拿到新结果
    click(pickFilter(active, '已完成'))
    await waitFor(() => getList.mock.calls.length === 2, { message: '第二请求发出' })
    await waitFor(
      () =>
        active.findAll('.el-table__body-wrapper .el-table__row')[0]?.textContent.includes('新数据'),
      { message: '新结果渲染' }
    )

    // 放行被挂起的旧请求：它必须被丢弃，不得覆盖新结果
    releaseSlow()
    await flush(10)
    const text = active.findAll('.el-table__body-wrapper .el-table__row')[0].textContent
    expect(text).toContain('新数据')
    expect(text).not.toContain('旧数据')
    expect(active.errors).toEqual([])
  })

  test('过期响应不得复位 loading：被丢弃的请求不能关掉新请求的加载态', async () => {
    // 可观测口径：模板里 loading && tableData.length === 0 才渲染首屏骨架屏
    // （.glass-skeleton）。所以「loading 是否被过期响应错误复位」可以这样分辨：
    //   1) 首个请求挂起 → 骨架屏在
    //   2) 触发第二个请求（也挂起，列表仍为空）→ 骨架屏仍在
    //   3) 放行首个（过期）请求 → 若 finally 缺 isCurrent 守卫，loading 被置 false
    //      → 骨架屏消失（而新请求其实还在途）
    let releaseSlow
    getList.mockImplementationOnce(
      () =>
        new Promise((res) => {
          releaseSlow = () => res({ data: { data: [], pagination: { total: 0 } } })
        })
    )
    getList.mockImplementationOnce(() => new Promise(() => {}))
    getStats.mockResolvedValue({ data: { success: true, data: {} } })
    active = mountComponent(InspectionView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(PERMS),
    })
    await waitFor(() => getList.mock.calls.length === 1, { message: '首请求发出' })
    await waitFor(() => active.find('.glass-skeleton') !== null, { message: '首屏骨架屏渲染' })

    click(pickFilter(active, '已完成'))
    await waitFor(() => getList.mock.calls.length === 2, { message: '第二请求发出' })
    await flush(4)
    expect(active.find('.glass-skeleton'), '第二请求在途时骨架屏必须仍在').not.toBeNull()

    // 放行过期请求：它不得关掉新请求仍在进行中的 loading
    releaseSlow()
    await flush(10)
    expect(
      active.find('.glass-skeleton'),
      '过期响应复位了 loading（骨架屏被错误移除）'
    ).not.toBeNull()
    expect(active.errors).toEqual([])
  })

  test('结果列：normal/abnormal/partial 渲染对应文案与语义色，未完成渲染 —', async () => {
    await open([
      r('A', { result: 'normal' }),
      r('B', { result: 'abnormal' }),
      r('C', { result: 'partial' }),
      r('D', { result: null }),
    ])
    const resultTexts = cells(active).map((x) => x[5])
    expect(resultTexts[0]).toBe('正常')
    expect(resultTexts[1]).toBe('异常')
    expect(resultTexts[2]).toBe('部分异常')
    expect(resultTexts[3]).toBe('—')

    // 语义色必须与结果一致（写反会让「异常」显示成绿色）
    const tags = active.findAll('.el-table__body-wrapper .el-table__row td:nth-child(6) .el-tag')
    expect(tags.length).toBe(3)
    expect(tags[0].classList.contains('el-tag--success')).toBe(true)
    expect(tags[1].classList.contains('el-tag--danger')).toBe(true)
    expect(tags[2].classList.contains('el-tag--warning')).toBe(true)
  })

  test('未分配负责人的行显示「暂无数据」而非空单元格', async () => {
    await open([r('无负责人', { assignedTo: [] })])
    expect(cells(active)[0][3]).toBe('暂无数据')
  })

  test('负责人取 realName 优先，缺失时退回 username', async () => {
    await open([
      r('多负责人', {
        assignedTo: [{ realName: '张三', username: 'zhangsan' }, { username: 'lisi' }],
      }),
    ])
    expect(cells(active)[0][3]).toBe('张三, lisi')
  })

  test('详情入口：打开只读表单（不得出现保存按钮），且不拉列表刷新', async () => {
    await open([r('详情行')])
    const before = getList.mock.calls.length
    const detailBtn = Array.from(
      active.findAll('.el-table__body-wrapper .el-table__row button')
    ).find((b) => b.textContent.trim() === '详情')
    expect(detailBtn).toBeTruthy()
    click(detailBtn)
    await flush(10)

    const dialog = document.body.querySelector('.el-dialog')
    expect(dialog).toBeTruthy()
    // 只读模式：保存按钮必须不存在（存在即误点改数据的风险）
    const saveBtn = Array.from(dialog.querySelectorAll('button')).find((b) =>
      /保存|Save/.test(b.textContent)
    )
    expect(saveBtn).toBeUndefined()
    expect(getList.mock.calls.length).toBe(before)
    expect(active.errors).toEqual([])
  })

  test('完成入口：点击打开完成表单（进行中的单据才渲染该入口）', async () => {
    await open([r('进行中甲', { status: 'in_progress' })])
    const completeBtn = Array.from(
      active.findAll('.el-table__body-wrapper .el-table__row button')
    ).find((b) => b.textContent.trim() === '提交结果')
    expect(completeBtn).toBeTruthy()
    click(completeBtn)
    await flush(10)
    expect(document.body.querySelector('.el-dialog')).toBeTruthy()
    expect(active.errors).toEqual([])
  })
})

describe('InspectionView 统计卡（后端 byStatus 分组计数，非平铺字段）', () => {
  test('四张卡按 byStatus._id 取数：pending/in_progress/completed/overdue 各自落地', async () => {
    // 与后端 /api/inspections/stats 真实返回同形：状态计数是 $group 后的 [{_id,count}] 数组，
    // 没有 pending / inProgress 平铺字段。旧实现读 s.pending → 恒 undefined → 四卡永远 0，
    // 值班员以为「无巡检」。修复后按 _id 匹配模型枚举原值。
    await open([{ _id: 'i1', title: 'A', status: 'pending', planStartTime: null }], {
      stats: {
        data: {
          success: true,
          data: {
            total: 16,
            byStatus: [
              { _id: 'pending', count: 4 },
              { _id: 'in_progress', count: 2 },
              { _id: 'completed', count: 9 },
              { _id: 'overdue', count: 1 },
            ],
            byType: [],
            byResult: [],
          },
        },
      },
    })
    await waitFor(() => active.findAll('.mini-stat .num')[0].textContent.trim() === '4', {
      message: '统计卡按分组计数落地',
    })
    expect(active.findAll('.mini-stat .num').map((x) => x.textContent.trim())).toEqual([
      '4',
      '2',
      '9',
      '1',
    ])
    // 反证：证明取值真来自分组而非"恰好非零"——读回平铺字段会让四卡全 0
    expect(active.findAll('.mini-stat .num').map((x) => x.textContent.trim())).not.toEqual([
      '0',
      '0',
      '0',
      '0',
    ])
    expect(active.errors).toEqual([])
  })

  test('byStatus 缺某维度时该卡按 0 兜底，其余照常（不是 undefined / NaN）', async () => {
    await open([{ _id: 'i1', title: 'A', status: 'pending', planStartTime: null }], {
      stats: {
        data: {
          success: true,
          data: { total: 5, byStatus: [{ _id: 'pending', count: 5 }], byType: [], byResult: [] },
        },
      },
    })
    await waitFor(() => active.findAll('.mini-stat .num')[0].textContent.trim() === '5', {
      message: 'pending 卡落地',
    })
    expect(active.findAll('.mini-stat .num').map((x) => x.textContent.trim())).toEqual([
      '5',
      '0',
      '0',
      '0',
    ])
  })
})

describe('InspectionView 统计「未知 ≠ 0」与统计竞态', () => {
  /**
   * 这一组钉的是同一条不变量：四个数字位只允许是**真实计数**，
   * 任何「没拿到统计」的路径（请求失败 / success:false / 畸形响应 / 列表先失败导致统计压根没发）
   * 都必须换成失败块，而不是把四张卡写成 0/0/0/0——后者值班员读作「无巡检」，
   * 与「不知道」无法区分（旧实现是 catch (_) { /* 忽略统计失败 *\/ }）。
   */
  const row1 = { _id: 's1', title: '统计行', status: 'pending', planStartTime: null }
  const nums = (c) => c.findAll('.mini-stat .num').map((x) => x.textContent.trim())
  const statsWith = (counts) => ({
    data: {
      success: true,
      data: {
        byStatus: Object.entries(counts).map(([k, count]) => ({ _id: k, count })),
      },
    },
  })
  const filterButton = (c, text) => {
    const btn = Array.from(c.find('.el-radio-group').querySelectorAll('.el-radio-button')).find(
      (b) => b.textContent.includes(text)
    )
    expect(btn, `筛选按钮 ${text} 未找到`).toBeTruthy()
    return btn
  }

  test('统计请求失败：首屏换成失败块，四个数字位不以 0 面孔出现', async () => {
    const c = await open([row1], { statsReject: true })
    await waitFor(() => c.find('.stats-failed') !== null, { message: '统计失败块渲染' })
    expect(nums(c)).toEqual([])
    expect(c.find('.mini-stat')).toBeNull()
    const box = c.find('.stats-failed')
    expect(box.textContent).toContain('加载失败')
    expect(box.querySelector('button').textContent.trim()).toBe(i18n.global.t('common.refresh'))
    expect(c.errors).toEqual([])
  })

  test('失败块里的「刷新」重新拉统计：换回四张真实计数卡', async () => {
    const c = await open([row1], { statsReject: true })
    await waitFor(() => c.find('.stats-failed') !== null, { message: '统计失败块渲染' })
    getStats.mockResolvedValue(statsWith({ pending: 3, in_progress: 1, completed: 2, overdue: 5 }))
    click(c.find('.stats-failed button'))
    await waitFor(() => nums(c).length === 4, { message: '统计卡恢复' })
    expect(nums(c)).toEqual(['3', '1', '2', '5'])
    expect(c.find('.stats-failed')).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('后端 success:false：按失败处理，不拿空 data 冒充「无巡检」', async () => {
    const c = await open([row1], { stats: { data: { success: false, message: '内部错误' } } })
    await waitFor(() => c.find('.stats-failed') !== null, { message: 'success:false 失败块' })
    expect(nums(c)).toEqual([])
  })

  test('畸形统计响应（整个 data 层缺失）：不得抛进 catch 后静默成 0 面孔', async () => {
    // 旧写法 statsRes.data.success 在这种响应下直接 TypeError，被内层 catch 吞掉 ⇒ 四张卡 0
    const c = await open([row1], { stats: {} })
    await waitFor(() => c.find('.stats-failed') !== null, { message: '畸形响应失败块' })
    expect(nums(c)).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('首屏列表就失败：统计压根没发出，四个数字位同样不以 0 面孔出现', async () => {
    getList.mockRejectedValue(new Error('down'))
    getStats.mockResolvedValue({ data: { success: true, data: {} } })
    active = mountComponent(InspectionView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(PERMS),
    })
    await waitFor(() => active.find('.stats-failed') !== null, { message: '列表失败 ⇒ 失败块' })
    // 前提自证：统计请求确实没发出去，所以这里的失败块只能来自「未知」而非「拿到了 0」
    expect(getStats).not.toHaveBeenCalled()
    expect(active.findAll('.mini-stat')).toHaveLength(0)
    expect(active.errors).toEqual([])
  })

  test('已经显示过真实计数后刷新失败：保留上一次已知数字（不把刷新失败伪装成数据归零）', async () => {
    const c = await open([row1], { stats: statsWith({ pending: 7 }) })
    await waitFor(() => nums(c)[0] === '7', { message: '首屏真实计数落地' })
    getStats.mockRejectedValue(new Error('stats down'))
    click(c.find('.table-toolbar .glass-btn--default'))
    await waitFor(() => getStats.mock.calls.length === 2, { message: '刷新请求发出' })
    // 这里必须再给一段静止窗口：getStats 的 reject 与 ref 变更都在微任务里，
    // 而 waitFor 只看到「调用次数变成 2」就返回，此刻 DOM 还没重渲染。
    // 少了这一行，下面的断言读的是**失败分支跑之前**的 DOM —— 用例恒绿、没有牙
    // （实测：删掉 statsLoadedOnce 置位的变异臂在加这行之前存活）。
    // flush(10) 与上面竞态用例用的是同一个已被变异臂证明足够长的窗口。
    await flush(10)
    expect(nums(c)).toEqual(['7', '0', '0', '0'])
    expect(c.find('.stats-failed')).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('被新筛选条件取代的旧统计后到：不得覆盖新条件下的计数', async () => {
    let releaseOldStats
    getList.mockResolvedValue({ data: { data: [row1], pagination: { total: 1 } } })
    getStats.mockImplementationOnce(
      () =>
        new Promise((res) => {
          releaseOldStats = () => res(statsWith({ pending: 99 }))
        })
    )
    active = mountComponent(InspectionView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(PERMS),
    })
    await waitFor(() => getStats.mock.calls.length === 1, { message: '首屏统计发出' })

    // 第二次加载（切换筛选）：它的统计先回来，写入新计数
    getStats.mockResolvedValueOnce(statsWith({ pending: 1 }))
    click(filterButton(active, '已完成'))
    await waitFor(() => nums(active)[0] === '1', { message: '新统计落地' })
    expect(getStats.mock.calls.length).toBe(2)

    // 放行被取代的旧统计：99 不得覆盖 1
    releaseOldStats()
    await flush(10)
    expect(nums(active)).toEqual(['1', '0', '0', '0'])
    expect(active.errors).toEqual([])
  })
})

describe('InspectionView 逾期（overdue）行的操作入口', () => {
  /**
   * 后端 src/constants/inspection.js 把 overdue 同时留在可开工与可提交两个档位集合里
   * （overdue 是调度器打的时间标记，不是工作流阶段），此前前端按
   * row.status === 'pending' / 'in_progress' 亮按钮 ⇒ 逾期巡检在界面上没有任何入口
   * 开工或补录结果，而结果与发现项只能挂在 completed 上：真实做过的工作永久无法入库。
   */
  const overdue = { _id: 'o1', title: '逾期巡检', status: 'overdue', planStartTime: null }
  const rowButtons = (c) =>
    c
      .findAll('.el-table__body-wrapper .el-table__row button')
      .map((b) => b.textContent.replace(/\s+/g, ' ').trim())

  test('逾期行同时给出「开始」与「提交结果」两个入口（后端两条路径都放行）', async () => {
    const c = await open([overdue])
    const labels = rowButtons(c)
    expect(labels).toContain(i18n.global.t('inspection.start'))
    expect(labels).toContain(i18n.global.t('inspection.complete'))
    // 状态列确实渲染成逾期（而不是被误标成别的档位）
    expect(cells(c)[0][6]).toBe(i18n.global.t('common.warning'))
  })

  test('逾期行点「提交结果」：打开完成表单并能对该行 _id 提交（补录做过的工作）', async () => {
    const c = await open([overdue])
    const btn = c
      .findAll('.el-table__body-wrapper .el-table__row button')
      .find((b) => b.textContent.trim() === i18n.global.t('inspection.complete'))
    expect(btn).toBeTruthy()
    click(btn)
    await flush(10)
    expect(document.body.querySelector('.el-dialog')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('逾期行点「开始」：确认后按该行 _id 发出 start 请求', async () => {
    const c = await open([overdue])
    ElMessageBox.confirm.mockResolvedValue('confirm')
    start.mockResolvedValue({ data: { success: true } })
    const btn = c
      .findAll('.el-table__body-wrapper .el-table__row button')
      .find((b) => b.textContent.trim() === i18n.global.t('inspection.start'))
    expect(btn).toBeTruthy()
    click(btn)
    await flush(8)
    expect(start).toHaveBeenCalledTimes(1)
    expect(start).toHaveBeenCalledWith('o1')
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('messages.updateSuccess'))
    expect(c.errors).toEqual([])
  })

  test('取消/关闭确认框：逾期行也不发 start 请求（与 pending 行同口径）', async () => {
    ElMessageBox.confirm.mockRejectedValue('cancel')
    const c = await open([overdue])
    const btn = c
      .findAll('.el-table__body-wrapper .el-table__row button')
      .find((b) => b.textContent.trim() === i18n.global.t('inspection.start'))
    click(btn)
    await flush(8)
    expect(start).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
  })
})
