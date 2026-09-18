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
    data: { data: rows, pagination: { total: rows.length } },
  })
  getStats.mockResolvedValue({ data: { success: true, data: {} } })
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

    expect(ElMessage.error).toHaveBeenCalledWith(i18n.global.t('messages.updateFailed'))
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

  test('删除失败：提示失败且不刷新列表', async () => {
    const c = await open([rowWith({ _id: 'd1' })])
    const before = getList.mock.calls.length
    ElMessageBox.confirm.mockResolvedValue('confirm')
    remove.mockRejectedValue(new Error('forbidden'))

    click(buttonByText(c, i18n.global.t('common.delete')))
    await flush(8)

    expect(ElMessage.error).toHaveBeenCalledWith(i18n.global.t('messages.deleteFailed'))
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
    ).find((b) => b.textContent.trim() === '操作')
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
