/**
 * AlarmView 行为测试（报警列表：分页 / 筛选 / 行级动作 / 上报对话框）
 *
 * 组件定位：报警管理页。数据面 + 交互面都在本视图，子组件只有 GlassSegmented（分段筛选）
 * 与 GlassSkeleton（首屏骨架）。本套件锁定四类真实退化：
 *
 *  1. 列表渲染口径：行字段映射（时间/位置/类型/处理人/状态）与标签色，映射错 = 值班员看错警情；
 *  2. 请求口径：page/limit/status 透传错 = 翻页丢筛选、筛选丢页码；
 *  3. 写操作接线：派单/到达/完成/上报的参数与前置校验，接错 = 工单流转向错误对象；
 *  4. 竞态与失败：过期响应覆盖新结果、失败后残留旧数据、abort 误报红框。
 *
 * 期望值一律在本文件内独立计算（Date 的本地 getter、字面量状态表），不 import 被测工具，
 * 否则实现写错时两边一起错、断言恒真。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

const getList = vi.fn()
const getStats = vi.fn()
const report = vi.fn()
const dispatch = vi.fn()
const arrive = vi.fn()
const resolveAlarm = vi.fn()
const isCanceledError = vi.fn(() => false)
const confirm = vi.fn()
const prompt = vi.fn()
const alert = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    alarms: {
      getList: (...a) => getList(...a),
      getStats: (...a) => getStats(...a),
      report: (...a) => report(...a),
      dispatch: (...a) => dispatch(...a),
      arrive: (...a) => arrive(...a),
      resolve: (...a) => resolveAlarm(...a),
    },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: {
    confirm: (...a) => confirm(...a),
    prompt: (...a) => prompt(...a),
    alert: (...a) => alert(...a),
  },
}))

import AlarmView from '@/views/AlarmView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

const ALL_PERMS = ['alarm:read', 'alarm:create', 'alarm:dispatch', 'alarm:handle']

/** 独立计算 ISO → 本地墙钟串（与实现无关的口径） */
const localStamp = (iso) => {
  const d = new Date(iso)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const mkRow = (id, over = {}) => ({
  _id: id,
  status: 'pending',
  alarmType: 'smoke',
  occurredAt: '2026-10-01T01:00:00.000Z',
  location: { building: 'A栋' },
  handler: { realName: '张三' },
  ...over,
})

/** 数据行单元格文本矩阵（el-table 在 jsdom 下真实渲染行） */
const cells = (c) =>
  c
    .findAll('.el-table__body-wrapper .el-table__row')
    .map((tr) =>
      Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.replace(/\s+/g, ' ').trim())
    )

const rowOf = (c, i) => c.findAll('.el-table__body-wrapper .el-table__row')[i]
const rowBtn = (c, i, label) =>
  Array.from(rowOf(c, i).querySelectorAll('button')).find((b) => b.textContent.trim() === label)

/** 挂载并等首屏列表落地 */
const open = async (rows, opts = {}) => {
  getList.mockResolvedValue({
    data: {
      data: rows,
      pagination: opts.pagination === undefined ? { total: rows.length } : opts.pagination,
    },
  })
  getStats.mockResolvedValue({ data: { data: { byStatus: [], total: 0 } } })
  active = mountComponent(AlarmView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(opts.perms || ALL_PERMS),
    locale: opts.locale || 'zh-CN',
  })
  await waitFor(() => cells(active).length === rows.length, { message: '列表行渲染完成' })
  await flush(4)
  return active
}

const dialogSubmit = () =>
  Array.from(document.querySelectorAll('.el-dialog button')).find(
    (b) => b.textContent.trim() === i18n.global.t('alarm.reportAlarm')
  )

/** 打开上报对话框并填满必填项（alarmType 走真实下拉选择） */
const fillReportForm = async (c, { location = 'A栋3楼配电室', description = '浓烟' } = {}) => {
  click(
    c
      .findAll('.glass-btn--danger')
      .find((b) => b.textContent.includes(i18n.global.t('alarm.reportAlarm')))
  )
  await flush(14)
  const loc = c
    .findAll('.el-dialog input')
    .find((i) => i.getAttribute('placeholder') === i18n.global.t('alarm.location'))
  loc.value = location
  loc.dispatchEvent(new window.Event('input', { bubbles: true }))
  const ta = c.find('.el-dialog textarea')
  ta.value = description
  ta.dispatchEvent(new window.Event('input', { bubbles: true }))
  click(c.find('.el-dialog .el-select'))
  await flush(12)
  const option = Array.from(document.querySelectorAll('.el-select-dropdown__item')).find((o) =>
    o.textContent.includes(i18n.global.t('dashboard.smokeAlarm'))
  )
  click(option)
  await flush(12)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  getList.mockReset()
  getStats.mockReset()
  report.mockReset()
  dispatch.mockReset()
  arrive.mockReset()
  resolveAlarm.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  confirm.mockReset()
  prompt.mockReset()
  alert.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  i18n.global.locale.value = 'zh-CN'
})
describe('AlarmView 列表渲染口径', () => {
  test('行字段逐列映射：时间本地化 / 位置 / 类型 / 处理人 / 状态', async () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const c = await open([
      mkRow('a1', {
        occurredAt: iso,
        location: { building: 'A栋', floor: '3层', room: '配电室' },
        handler: { realName: '张三' },
        status: 'pending',
        alarmType: 'smoke',
      }),
    ])
    const expected = localStamp(iso)
    // 期望值自检：定长口径（各段补零、空格分隔），且不等于 ISO 原串
    expect(expected).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
    expect(expected).not.toBe(iso)
    expect(cells(c)[0]).toEqual([
      '1',
      expected,
      'A栋3层 配电室',
      '烟雾报警',
      '张三',
      '待处理',
      '指派处理处理完成详情',
    ])
    // 时间不得是 ISO 原串（防退回 prop 直渲染 UTC）
    expect(cells(c)[0][1]).not.toContain('T')
    expect(cells(c)[0][1]).not.toContain('Z')
    expect(c.errors).toEqual([])
  })

  test('切换界面语言后时间列格式不变（格式不得随 locale 漂移）', async () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const c = await open([mkRow('lang1', { occurredAt: iso })])
    const before = cells(c)[0][1]
    expect(before).toBe(localStamp(iso))
    i18n.global.locale.value = 'en-US'
    await flush(30)
    expect(cells(c)[0][1]).toBe(before)
    // 反证：同一次切换里确实有别的文案变了（否则上面的恒定断言可能是恒真）。
    // 用表头做反证：它走 $t 模板插值、随 locale 响应式更新；行内状态文案是
    // loadData 时物化的（本视图不 watch locale 重取），不适用于本次反证。
    const headers = () => c.findAll('.el-table__header th').map((th) => th.textContent.trim())
    expect(headers()).toContain('Occurred At')
    expect(headers()).toContain('Handler')
    expect(headers()).not.toContain('发生时间')
    i18n.global.locale.value = 'zh-CN'
    await flush(30)
  })
  test('时间缺失渲染为 -（不是 Invalid Date / undefined）', async () => {
    const c = await open([mkRow('a1', { occurredAt: null })])
    const stamp = cells(c)[0][1]
    expect(stamp).toBe('-')
    expect(stamp).not.toContain('Invalid')
    expect(stamp).not.toContain('undefined')
  })

  test('处理人回退链 realName → name → username → 暂无数据；字符串原样', async () => {
    const c = await open([
      mkRow('h1', { handler: { realName: '真名', name: '别名', username: 'u1' } }),
      mkRow('h2', { handler: { name: '别名', username: 'u2' } }),
      mkRow('h3', { handler: { username: 'u3' } }),
      mkRow('h4', { handler: {} }),
      mkRow('h5', { handler: null }),
      mkRow('h6', { handler: '李四' }),
    ])
    expect(cells(c).map((r) => r[4])).toEqual([
      '真名',
      '别名',
      'u3',
      '暂无数据',
      '暂无数据',
      '李四',
    ])
    expect(c.errors).toEqual([])
  })

  test('状态与类型 → 标签色映射表逐项落地', async () => {
    const c = await open([
      mkRow('t1', { status: 'pending', alarmType: 'smoke' }),
      mkRow('t2', { status: 'processing', alarmType: 'temp_abnormal' }),
      mkRow('t3', { status: 'resolved', alarmType: 'manual_button' }),
      mkRow('t4', { status: 'false_alarm', alarmType: 'phone_report' }),
      mkRow('t5', { status: 'cancelled', alarmType: 'patrol_find' }),
      mkRow('t6', { status: 'pending', alarmType: 'other' }),
    ])
    const tags = c
      .findAll('.el-table__body-wrapper .el-tag')
      .map((t) => t.className.match(/el-tag--(danger|warning|info|success)/)[1])
    // 每行两个标签：类型标签在前、状态标签在后
    expect(tags).toEqual([
      'danger',
      'danger',
      'warning',
      'warning',
      'danger',
      'success',
      'warning',
      'info',
      'warning',
      'warning',
      'info',
      'danger',
    ])
    expect(c.errors).toEqual([])
  })

  test('未知状态与未知类型兜底：状态原样文本、类型退回 row.type 或 -', async () => {
    const c = await open([
      mkRow('u1', { status: 'weird', alarmType: 'nope' }),
      mkRow('u2', { status: undefined, alarmType: undefined, type: '原始类型' }),
    ])
    const rows = cells(c)
    expect(rows[0][5]).toBe('weird')
    expect(rows[0][3]).toBe('-')
    expect(rows[1][3]).toBe('原始类型')
    // 兜底色必须是 info（不是空 class 或 danger）
    const tags = c
      .findAll('.el-table__body-wrapper .el-tag')
      .map((t) => t.className.match(/el-tag--(danger|warning|info|success)/)[1])
    expect(tags).toEqual(['info', 'info', 'info', 'info'])
  })
})
describe('AlarmView 位置与类型显示口径', () => {
  test('结构化位置按「楼栋+楼层 房间」拼装，缺字段不产生多余空格', async () => {
    const c = await open([
      mkRow('p1', { location: { building: 'A栋', floor: '3层', room: '配电室' } }),
      mkRow('p2', { location: { building: 'B栋', room: '库房' } }),
      mkRow('p3', { location: { building: 'C栋', floor: '2层' } }),
      mkRow('p4', { location: 'D栋门口' }),
    ])
    expect(cells(c).map((r) => r[2])).toEqual(['A栋3层 配电室', 'B栋 库房', 'C栋2层', 'D栋门口'])
    // 首行断言自检：确认不是把对象 JSON 直接塞进单元格
    expect(cells(c)[0][2]).not.toContain('{')
    expect(c.errors).toEqual([])
  })

  test('location 为 null 时不抛错、不整表清空：该行回落「暂无数据」，其余行照常渲染', async () => {
    // 退化保护：原实现 typeof null === "object" 后读 location.building 抛 TypeError，
    // 异常被 loadData 的 catch 吞掉 → 整张表被清空（实测 0 行、Total 0、无任何提示），
    // 值班员会以为「没有警情」。
    const c = await open([
      mkRow('n1', { location: null }),
      mkRow('n2', { location: { building: 'B栋', floor: '1层' } }),
    ])
    expect(cells(c).map((r) => r[2])).toEqual([i18n.global.t('common.noData'), 'B栋1层'])
    expect(cells(c)).toHaveLength(2)
    expect(c.errors).toEqual([])
  })

  test('location 是对象但无 building（{} / {building:null}）时回落「暂无数据」，不直出对象文本', async () => {
    // 退化保护：直出对象会渲染成 "{}" 或 "{ \"building\": null }"，对值班员是噪音
    const c = await open([
      mkRow('e1', { location: {} }),
      mkRow('e2', { location: { building: null } }),
    ])
    const locs = cells(c).map((r) => r[2])
    expect(locs).toEqual([i18n.global.t('common.noData'), i18n.global.t('common.noData')])
    for (const t of locs) {
      expect(t).not.toContain('{')
      expect(t).not.toContain('building')
    }
    expect(c.errors).toEqual([])
  })
  test('类型映射表：6 种 alarmType 各自走词表，未命中退回 row.type', async () => {
    const c = await open([
      mkRow('y1', { alarmType: 'smoke' }),
      mkRow('y2', { alarmType: 'temp_abnormal' }),
      mkRow('y3', { alarmType: 'manual_button' }),
      mkRow('y4', { alarmType: 'phone_report' }),
      mkRow('y5', { alarmType: 'patrol_find' }),
      mkRow('y6', { alarmType: 'other' }),
      mkRow('y7', { alarmType: 'x', type: '回退名' }),
    ])
    expect(cells(c).map((r) => r[3])).toEqual([
      '烟雾报警',
      '温度异常',
      '手动报警',
      '电话报告',
      '巡检发现',
      // other 曾渲染成「全部」：本视图并不存在「全部」这个类型，
      // 该断言当时把缺陷钉成了期望值
      '其他',
      '回退名',
    ])
    // 与词表取值一致：文案被改动时此断言与 i18n 同时暴露
    expect(i18n.global.t('dashboard.smokeAlarm')).toBe('烟雾报警')
    expect(i18n.global.t('dashboard.patrolFind')).toBe('巡检发现')
  })

  test('上报下拉框与列表词表同源：六项真实类型，无「全部」，选「其他」提交 other', async () => {
    const c = await open([mkRow('tp1')])
    report.mockResolvedValue({ data: { success: true } })
    click(
      c
        .findAll('.glass-btn--danger')
        .find((b) => b.textContent.includes(i18n.global.t('alarm.reportAlarm')))
    )
    await flush(14)
    const loc = c
      .findAll('.el-dialog input')
      .find((i) => i.getAttribute('placeholder') === i18n.global.t('alarm.location'))
    loc.value = 'A栋'
    loc.dispatchEvent(new window.Event('input', { bubbles: true }))
    const ta = c.find('.el-dialog textarea')
    ta.value = '下拉框自检'
    ta.dispatchEvent(new window.Event('input', { bubbles: true }))
    click(c.find('.el-dialog .el-select'))
    await flush(12)
    // 页面上的分页第 N 页选择器同样把 el-select-dropdown 传送到 body，
    // 因此先按内容锁定「含类型标签的那一个下拉」，再把判据打在它的选项上
    const typeDropdown = Array.from(document.querySelectorAll('.el-select-dropdown')).find((d) =>
      d.textContent.includes('烟雾报警')
    )
    expect(typeDropdown).toBeTruthy()
    const items = Array.from(typeDropdown.querySelectorAll('.el-select-dropdown__item'))
    const texts = items.map((o) => o.textContent.replace(/\s+/g, ' ').trim())
    expect(texts).toEqual(['烟雾报警', '温度异常', '手动报警', '电话报告', '巡检发现', '其他'])
    // 单项判据：'全部' 是本视图一个不存在的类型（列表列若渲染它即错），
    // 而 common.all 在同页的筛选分段上确实存在且合法 —— 只禁下拉不禁页面
    expect(texts).not.toContain('全部')
    const otherOption = items.find((o) => o.textContent.replace(/\s+/g, ' ').trim() === '其他')
    click(otherOption)
    await flush(12)
    click(dialogSubmit())
    await waitFor(() => report.mock.calls.length === 1, { message: '上报请求' })
    // 标签与取值必须成对：「其他」→ other（曾错标成「全部」，用户按字面选即误分类）
    expect(report.mock.calls[0][0].alarmType).toBe('other')
    expect(c.errors).toEqual([])
  })

  test('英文界面下列头、类型、状态、按钮全部走英文词表（无中文残留）', async () => {
    const c = await open([mkRow('e1', { status: 'processing', alarmType: 'smoke' })], {
      locale: 'en-US',
    })
    expect(c.findAll('.el-table__header th').map((th) => th.textContent.trim())).toEqual([
      '#',
      'Occurred At',
      'Location',
      'Alarm Type',
      'Handler',
      'Status',
      'Action',
    ])
    const row = cells(c)[0]
    expect(row[3]).toBe('Smoke Alarm')
    expect(row[5]).toBe('Processing')
    expect(row[6]).toBe('DispatchResolveDetails')
    // 中文不得出现在英文界面（含列头与单元格）
    // 中文不得出现在列头/按钮（数据本身可以是中文姓名，不作断言）
    expect(
      c
        .findAll('.el-table__header')
        .map((h) => h.textContent)
        .join('')
    ).not.toMatch(/[\u4e00-\u9fa5]/)
    expect(
      c
        .findAll('.glass-btn')
        .map((b) => b.textContent)
        .join('')
    ).not.toMatch(/[\u4e00-\u9fa5]/)
  })
})
describe('AlarmView 请求参数口径（分页 / 筛选）', () => {
  test('首屏请求带 page=1 / limit=10 / status 空串（P3-45：原实现不传 → 后端静默截断到 10 条）', async () => {
    const c = await open([mkRow('a1')])
    expect(getList).toHaveBeenCalledTimes(1)
    expect(getList).toHaveBeenCalledWith({ page: 1, limit: 10, status: '' })
    expect(c.findAll('.el-pagination').length).toBe(1)
  })

  test('分页信息缺失时 total 回退为当前页行数（防「表里有行但分页显示 Total 0」）', async () => {
    getList.mockResolvedValue({ data: { data: [mkRow('a1'), mkRow('a2')] } })
    getStats.mockResolvedValue({ data: { data: { byStatus: [], total: 0 } } })
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => cells(active).length === 2, { message: '列表行渲染完成' })
    expect(active.find('.el-pagination__total').textContent).toBe('Total 2')
    expect(cells(active)).toHaveLength(2)
  })

  test('翻页按钮透传目标页码（点第 2 页 → page=2，limit/status 不变）', async () => {
    const c = await open([mkRow('a1')], { pagination: { total: 50 } })
    expect(c.findAll('.el-pager li').map((li) => li.textContent.trim())).toEqual([
      '1',
      '2',
      '3',
      '4',
      '5',
    ])
    click(c.find('.btn-next'))
    await waitFor(() => getList.mock.calls.length === 2, { message: '翻页请求发出' })
    expect(getList.mock.calls[1][0]).toEqual({ page: 2, limit: 10, status: '' })
    expect(c.errors).toEqual([])
  })

  test('切换每页条数回到第 1 页并透传新 limit（停在旧页码会看到空表）', async () => {
    const c = await open([mkRow('a1')], { pagination: { total: 50 } })
    click(c.find('.btn-next'))
    await waitFor(() => getList.mock.calls.length === 2, { message: '翻页' })
    expect(getList.mock.calls[1][0]).toEqual({ page: 2, limit: 10, status: '' })
    // 通过组件实例派发 size-change（jsdom 无布局，下拉面板的项不可点）
    const paginationVm = c.find('.pagination .el-pagination').__vueParentComponent
    paginationVm.emit('update:page-size', 20)
    paginationVm.emit('size-change', 20)
    await waitFor(() => getList.mock.calls.length === 3, { message: '改条数请求' })
    expect(getList.mock.calls[2][0]).toEqual({ page: 1, limit: 20, status: '' })
  })

  test('状态筛选：点分段项 → status 透传且回到第 1 页', async () => {
    const c = await open([mkRow('a1')], { pagination: { total: 50 } })
    click(c.find('.btn-next'))
    await waitFor(() => getList.mock.calls.length === 2, { message: '翻页' })
    const seg = c
      .findAll('.glass-segmented__item')
      .find((b) => b.textContent.includes(i18n.global.t('alarm.pending')))
    click(seg)
    await waitFor(() => getList.mock.calls.length === 3, { message: '筛选请求' })
    expect(getList.mock.calls[2][0]).toEqual({ page: 1, limit: 10, status: 'pending' })
    // 激活态必须移到被点项（否则用户以为筛选没生效）
    const actives = c
      .findAll('.glass-segmented__item.is-active')
      .map((b) => b.textContent.replace(/\s+/g, ' ').trim())
    expect(actives).toHaveLength(1)
    expect(actives[0]).toContain(i18n.global.t('alarm.pending'))
  })

  test('重复点击已激活的分段项不发请求（GlassSegmented 只在值变化时 emit）', async () => {
    const c = await open([mkRow('a1')])
    const all = c
      .findAll('.glass-segmented__item')
      .find((b) => b.textContent.trim().startsWith(i18n.global.t('common.all')))
    click(all)
    await flush(10)
    expect(getList).toHaveBeenCalledTimes(1)
  })
})

describe('AlarmView 统计卡与分段计数（loadStats 口径）', () => {
  test('byStatus 分组计数映射到卡片与分段徽标，总数取 total', async () => {
    getList.mockResolvedValue({ data: { data: [mkRow('s1')], pagination: { total: 1 } } })
    getStats.mockResolvedValue({
      data: {
        data: {
          byStatus: [
            { _id: 'pending', count: 3 },
            { _id: 'processing', count: 2 },
            { _id: 'resolved', count: 5 },
          ],
          total: 42,
        },
      },
    })
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => cells(active).length === 1, { message: '列表' })
    await waitFor(() => active.findAll('.mini-stat .num')[0].textContent.trim() === '3', {
      message: '统计落地',
    })
    expect(active.findAll('.mini-stat .num').map((x) => x.textContent.trim())).toEqual([
      '3',
      '2',
      '5',
      '42',
    ])
    expect(active.findAll('.mini-stat .label').map((x) => x.textContent.trim())).toEqual([
      '待处理',
      '处理中',
      '已处理',
      '报警统计',
    ])
    // 徽标只挂在有统计维度的三项上（误报/取消无维度 → 不渲染）
    expect(active.findAll('.glass-segmented__count').map((x) => x.textContent.trim())).toEqual([
      '3',
      '2',
      '5',
    ])
    expect(active.errors).toEqual([])
  })

  test('统计缺失的维度按 0 兜底（不是 undefined / NaN）', async () => {
    getList.mockResolvedValue({ data: { data: [mkRow('s1')], pagination: { total: 1 } } })
    getStats.mockResolvedValue({
      data: { data: { byStatus: [{ _id: 'pending', count: 7 }], total: 11 } },
    })
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => active.findAll('.mini-stat .num')[0].textContent.trim() === '7', {
      message: '统计落地',
    })
    expect(active.findAll('.mini-stat .num').map((x) => x.textContent.trim())).toEqual([
      '7',
      '0',
      '0',
      '11',
    ])
  })

  test('统计刷新失败：保留上一次已知计数（清零会谎报「当前无警情」）', async () => {
    getList.mockResolvedValue({ data: { data: [mkRow('s1')], pagination: { total: 1 } } })
    getStats.mockResolvedValueOnce({
      data: { data: { byStatus: [{ _id: 'pending', count: 9 }], total: 30 } },
    })
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => active.findAll('.mini-stat .num')[0].textContent.trim() === '9', {
      message: '首次统计落地',
    })
    // 第二次刷新失败：不得把已知的 9/0/0/30 抹成 0/0/0/0
    getStats.mockRejectedValue(new Error('stats down'))
    click(active.findAll('.glass-btn--default').find((b) => b.textContent.includes('刷新')))
    await waitFor(() => getStats.mock.calls.length === 2, { message: '第二次统计请求发出' })
    await flush(20)
    expect(active.findAll('.mini-stat .num').map((x) => x.textContent.trim())).toEqual([
      '9',
      '0',
      '0',
      '30',
    ])
    expect(active.errors).toEqual([])
  })

  test('统计接口首屏失败：给出「加载失败 + 刷新」而不是四张 0 卡，不吞列表、不弹错', async () => {
    getList.mockResolvedValue({ data: { data: [mkRow('s1')], pagination: { total: 1 } } })
    getStats.mockRejectedValue(new Error('stats down'))
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => cells(active).length === 1, { message: '列表不受统计失败影响' })
    await flush(10)
    // 旧断言把 ['0','0','0','0'] 当成契约：首屏拿不到统计时，四张 0 卡读作
    // 「今日无警情」，与「服务挂了」不可区分。失败态必须换掉整个数值区。
    expect(active.findAll('.mini-stat .num')).toEqual([])
    const failed = active.find('.stats-failed')
    expect(failed.textContent).toContain('加载失败')
    expect(failed.querySelector('button').textContent).toContain('刷新')
    expect(cells(active)).toHaveLength(1)
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.warning).not.toHaveBeenCalled()
    expect(active.errors).toEqual([])
  })

  test('统计失败块里的刷新：真的重发统计请求，成功后四张卡回来', async () => {
    getList.mockResolvedValue({ data: { data: [mkRow('s1')], pagination: { total: 1 } } })
    getStats.mockRejectedValue(new Error('stats down'))
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(10)
    expect(active.find('.stats-failed').textContent).toContain('加载失败')
    const callsBefore = getStats.mock.calls.length

    getStats.mockResolvedValue({
      data: { data: { byStatus: [{ _id: 'pending', count: 4 }], total: 12 } },
    })
    click(active.find('.stats-failed button'))
    await waitFor(() => getStats.mock.calls.length === callsBefore + 1, {
      message: '刷新按钮重发统计请求',
    })
    await flush(10)

    expect(active.find('.stats-failed')).toBeFalsy()
    expect(active.findAll('.mini-stat .num').map((x) => x.textContent.trim())).toEqual([
      '4',
      '0',
      '0',
      '12',
    ])
  })
})
describe('AlarmView 加载失败与竞态', () => {
  test('首屏加载失败：骨架退场，空表 + total 归零（不留半截状态）', async () => {
    getList.mockRejectedValue(new Error('boom'))
    getStats.mockResolvedValue({ data: { data: { byStatus: [], total: 0 } } })
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(24)
    expect(active.findAll('.glass-skeleton')).toEqual([])
    expect(active.findAll('.el-table')).toHaveLength(1)
    expect(cells(active)).toEqual([])
    expect(active.find('.el-pagination__total').textContent).toBe('Total 0')
    expect(active.errors).toEqual([])
  })

  test('刷新失败：清空旧数据并把 total 归零（残留旧行会让用户误以为已是最新）', async () => {
    const c = await open([mkRow('a1')])
    expect(cells(c)).toHaveLength(1)
    getList.mockRejectedValue(new Error('boom'))
    click(c.findAll('.glass-btn--default').find((b) => b.textContent.includes('刷新')))
    await waitFor(() => c.find('.el-pagination__total').textContent === 'Total 0', {
      message: '失败后 total 归零',
    })
    expect(cells(c)).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('过期响应不得覆盖新结果（先发的慢请求后返回 → 丢弃）', async () => {
    const defers = []
    getList.mockImplementation(() => new Promise((res) => defers.push(res)))
    getStats.mockResolvedValue({ data: { data: { byStatus: [], total: 0 } } })
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(6)
    expect(defers).toHaveLength(1)
    click(active.findAll('.glass-btn--default').find((b) => b.textContent.includes('刷新')))
    await flush(6)
    expect(defers).toHaveLength(2)
    // 第二次（新）先返回
    defers[1]({ data: { data: [mkRow('NEW')], pagination: { total: 3 } } })
    await waitFor(() => cells(active).length === 1 && cells(active)[0].length === 7, {
      message: '新结果单元格渲染完成',
    })
    expect(cells(active)[0][1]).toBe(localStamp('2026-10-01T01:00:00.000Z'))
    expect(active.find('.el-pagination__total').textContent).toBe('Total 3')
    // 第一次（旧）后返回：行与 total 都不得被改写
    defers[0]({ data: { data: [mkRow('STALE'), mkRow('STALE2')], pagination: { total: 7 } } })
    await flush(12)
    expect(cells(active)).toHaveLength(1)
    expect(active.find('.el-pagination__total').textContent).toBe('Total 3')
    expect(active.errors).toEqual([])
  })

  test('过期请求失败不得清空新数据（catch 分支同样受竞态守卫约束）', async () => {
    const defers = []
    getList.mockImplementation(
      () => new Promise((res, rej) => defers.push({ res: (v) => res(v), rej: (e) => rej(e) }))
    )
    getStats.mockResolvedValue({ data: { data: { byStatus: [], total: 0 } } })
    active = mountComponent(AlarmView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(6)
    click(active.findAll('.glass-btn--default').find((b) => b.textContent.includes('刷新')))
    await flush(6)
    defers[1].res({ data: { data: [mkRow('FRESH')], pagination: { total: 2 } } })
    await waitFor(() => cells(active).length === 1, { message: '新结果落地' })
    defers[0].rej(new Error('stale-fail'))
    await flush(12)
    expect(cells(active)).toHaveLength(1)
    expect(active.find('.el-pagination__total').textContent).toBe('Total 2')
    expect(active.errors).toEqual([])
  })

  test('路由切换 abort 的在途请求：不得弹出假错误提示，且下一次加载仍正常（FE-L1）', async () => {
    const c = await open([mkRow('a1')])
    isCanceledError.mockReturnValue(true)
    getList.mockRejectedValue(Object.assign(new Error('canceled'), { code: 'ERR_CANCELED' }))
    click(c.findAll('.glass-btn--default').find((b) => b.textContent.includes('刷新')))
    await flush(20)
    // 取消不是业务失败：不得出现任何提示（真实退化 = catch 里加 ElMessage 而不判 abort）
    expect(ElMessage.warning).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
    // 取消不得污染状态：恢复后再次加载应正常渲染
    getList.mockResolvedValue({ data: { data: [mkRow('a2')], pagination: { total: 1 } } })
    click(c.findAll('.glass-btn--default').find((b) => b.textContent.includes('刷新')))
    await waitFor(() => cells(c).length === 1 && cells(c)[0].length === 7, {
      message: '取消后恢复加载',
    })
    expect(cells(c)[0][2]).toBe('A栋')
    expect(c.errors).toEqual([])
  })
})

describe('AlarmView 权限门控（与后端 checkPermission 码逐一对应）', () => {
  test('只读用户：无上报入口、行内只剩「详情」；派单/完成按钮不渲染', async () => {
    const c = await open([mkRow('p1', { status: 'processing' })], { perms: ['alarm:read'] })
    expect(c.findAll('.table-toolbar .glass-btn--danger')).toEqual([])
    // 只读用户行内只应有「详情」一个按钮（无权限的动作入口不得存在）
    expect(
      Array.from(rowOf(c, 0).querySelectorAll('button')).map((b) => b.textContent.trim())
    ).toEqual(['详情'])
    expect(c.errors).toEqual([])
  })

  test('alarm:dispatch 单权限：派单可见、完成不可见（对应 PUT /dispatch）', async () => {
    const c = await open([mkRow('p2')], { perms: ['alarm:read', 'alarm:dispatch'] })
    const labels = Array.from(rowOf(c, 0).querySelectorAll('button')).map((b) =>
      b.textContent.trim()
    )
    expect(labels).toEqual(['指派处理', '详情'])
  })

  test('alarm:handle 单权限 + processing 行：派单（走 arrive）与完成都可见（processing→alarm:handle）', async () => {
    const c = await open([mkRow('p3', { status: 'processing' })], {
      perms: ['alarm:read', 'alarm:handle'],
    })
    const labels = Array.from(rowOf(c, 0).querySelectorAll('button')).map((b) =>
      b.textContent.trim()
    )
    expect(labels).toEqual(['指派处理', '处理完成', '详情'])
  })

  test('回归：pending 行 + 仅 alarm:handle（无 dispatch）→ 不渲染派单入口（点击会发 /dispatch→403）', async () => {
    // hasAnyPerm(['alarm:dispatch','alarm:handle']) 的 OR 语义会在这里放行：消防员只有
    // alarm:handle，却对 pending 行看到「指派处理」，点击 → handle() 走 dispatch 分支 → 403。
    const c = await open([mkRow('g1', { status: 'pending' })], {
      perms: ['alarm:read', 'alarm:handle'],
    })
    expect(rowBtn(c, 0, '指派处理')).toBeUndefined()
    expect(c.errors).toEqual([])
  })

  test('回归：processing 行 + 仅 alarm:dispatch（无 handle）→ 不渲染派单入口（点击会发 /arrive→403）', async () => {
    // 反方向：只有 alarm:dispatch 的调度员对 processing 行点「指派处理」，handle() 走 arrive
    // 分支（需 alarm:handle）→ 403。新门控按状态与所需权限一一对应，此处入口应缺席。
    const c = await open([mkRow('g2', { status: 'processing' })], {
      perms: ['alarm:read', 'alarm:dispatch'],
    })
    expect(rowBtn(c, 0, '指派处理')).toBeUndefined()
    expect(c.errors).toEqual([])
  })

  test('alarm:create 门控上报按钮（对应 POST /alarms/report）', async () => {
    const withCreate = await open([mkRow('p4')], { perms: ['alarm:read', 'alarm:create'] })
    expect(
      withCreate.findAll('.table-toolbar .glass-btn--danger').map((b) => b.textContent.trim())
    ).toEqual(['上报火警'])
    withCreate.handle.unmount()
    active = null
    const withoutCreate = await open([mkRow('p5')], { perms: ['alarm:read', 'alarm:handle'] })
    expect(withoutCreate.findAll('.table-toolbar .glass-btn--danger')).toEqual([])
  })
})
describe('AlarmView 行级动作：派单 / 到达现场', () => {
  test('pending 行点「指派处理」：确认后调 dispatch(_id, {})，成功后提示并刷新列表', async () => {
    const c = await open([mkRow('d1', { status: 'pending' })])
    confirm.mockResolvedValue('confirm')
    dispatch.mockResolvedValue({ data: { success: true } })
    const before = getList.mock.calls.length
    click(rowBtn(c, 0, '指派处理'))
    await waitFor(() => dispatch.mock.calls.length === 1, { message: '派单请求发出' })
    expect(dispatch).toHaveBeenCalledWith('d1', {})
    // 确认框文案与标题必须存在（否则用户不知道点了会发生什么）
    expect(confirm.mock.calls[0][0]).toBe(i18n.global.t('alarm.dispatchSelfConfirm'))
    expect(confirm.mock.calls[0][1]).toBe(i18n.global.t('messages.confirmTitle'))
    await waitFor(() => getList.mock.calls.length > before, { message: '成功后刷新列表' })
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('alarm.dispatch'))
    expect(c.errors).toEqual([])
  })

  test('processing 行点同一按钮：走 arrive（不发确认框、不调 dispatch）', async () => {
    const c = await open([mkRow('d2', { status: 'processing' })])
    arrive.mockResolvedValue({ data: { success: true } })
    click(rowBtn(c, 0, '指派处理'))
    await waitFor(() => arrive.mock.calls.length === 1, { message: '到达登记请求' })
    expect(arrive).toHaveBeenCalledWith('d2')
    expect(dispatch).not.toHaveBeenCalled()
    expect(confirm).not.toHaveBeenCalled()
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('alarm.arrive'))
  })

  test('请求进行中禁用该行按钮（防重复提交），完成后解锁', async () => {
    const c = await open([mkRow('d3', { status: 'pending' })])
    confirm.mockResolvedValue('confirm')
    let release
    dispatch.mockImplementation(() => new Promise((r) => (release = r)))
    click(rowBtn(c, 0, '指派处理'))
    await waitFor(() => dispatch.mock.calls.length === 1, { message: '请求发出' })
    await flush(6)
    expect(rowBtn(c, 0, '指派处理').disabled).toBe(true)
    // 详情按钮不受行锁约束（只读操作不该被禁用）
    expect(rowBtn(c, 0, '详情').disabled).toBe(false)
    release({ data: { success: true } })
    await waitFor(() => rowBtn(c, 0, '指派处理').disabled === false, { message: '完成后解锁' })
  })

  test('用户取消确认框：不发请求、不提示成功、不残留忙碌态', async () => {
    const c = await open([mkRow('d4', { status: 'pending' })])
    confirm.mockRejectedValue('cancel')
    click(rowBtn(c, 0, '指派处理'))
    await waitFor(() => confirm.mock.calls.length === 1, { message: '确认框弹出' })
    await flush(16)
    expect(dispatch).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(rowBtn(c, 0, '指派处理').disabled).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('请求失败：不提示成功，但必须释放行锁（否则该行永久点不动）', async () => {
    const c = await open([mkRow('d5', { status: 'pending' })])
    confirm.mockResolvedValue('confirm')
    dispatch.mockRejectedValue(new Error('boom'))
    click(rowBtn(c, 0, '指派处理'))
    await waitFor(() => dispatch.mock.calls.length === 1, { message: '请求发出' })
    await waitFor(() => rowBtn(c, 0, '指派处理').disabled === false, { message: '失败后解锁' })
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('已完成的行：不渲染「指派处理」入口（状态收敛门控），点「处理完成」只提示不发请求', async () => {
    const c = await open([mkRow('d6', { status: 'resolved' })])
    // 新门控按状态与所需权限一一对应：resolved 既非 pending 也非 processing →
    // 「指派处理」入口直接缺席（旧实现会渲染出来，点击后 handle() 早退、给不了任何反馈）。
    expect(rowBtn(c, 0, '指派处理')).toBeUndefined()
    // 「处理完成」仍按 alarm:handle 显示；resolve() 对非 processing 行只给前置条件说明、不发请求
    click(rowBtn(c, 0, '处理完成'))
    await flush(10)
    expect(resolveAlarm).not.toHaveBeenCalled()
    expect(dispatch).not.toHaveBeenCalled()
    expect(arrive).not.toHaveBeenCalled()
    expect(confirm).not.toHaveBeenCalled()
    // 只有状态说明提示，且文案指向真实前置条件
    expect(ElMessage.warning).toHaveBeenCalledWith(i18n.global.t('alarm.resolveRequiresProcessing'))
    expect(c.errors).toEqual([])
  })
})

test('同一 tick 双击「指派处理」：只弹一次确认、只发一个 dispatch 请求', async () => {
  const c = await open([mkRow('db1', { status: 'pending' })])
  let confirmCalls = 0
  confirm.mockImplementation(() => {
    confirmCalls += 1
    return new Promise(() => {})
  })
  const btn = rowBtn(c, 0, '指派处理')
  click(btn)
  click(btn)
  await flush(12)
  // 重入守卫必须在首行同步判定：rowBusy 只是渲染态，第二次点击到达时按钮尚未 disabled
  expect(confirmCalls).toBe(1)
  expect(dispatch).not.toHaveBeenCalled()
  expect(c.errors).toEqual([])
})

test('确认框处理中「指派处理」按钮已禁用（真实浏览器语义下不会二次触发）', async () => {
  const c = await open([mkRow('db2', { status: 'pending' })])
  let releaseConfirm
  confirm.mockImplementation(
    () =>
      new Promise((r) => {
        releaseConfirm = () => r('confirm')
      })
  )
  dispatch.mockResolvedValue({ data: { success: true } })
  click(rowBtn(c, 0, '指派处理'))
  await flush(8)
  expect(rowBtn(c, 0, '指派处理').disabled).toBe(true)
  releaseConfirm()
  await waitFor(() => dispatch.mock.calls.length === 1, { message: '派单请求发出' })
  expect(confirm).toHaveBeenCalledTimes(1)
  expect(c.errors).toEqual([])
})
describe('AlarmView 行级动作：处理完成（双确认 + 原因单选）', () => {
  test('同一 tick 双击「处理完成」：只弹一次结单确认（resolve 侧重入守卫）', async () => {
    const c = await open([mkRow('rr1', { status: 'processing' })])
    let confirmCalls = 0
    confirm.mockImplementation(() => {
      confirmCalls += 1
      return new Promise(() => {})
    })
    const btn = rowBtn(c, 0, '处理完成')
    click(btn)
    click(btn)
    await flush(12)
    expect(confirmCalls).toBe(1)
    expect(prompt).not.toHaveBeenCalled()
    expect(resolveAlarm).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('处理中行点「处理完成」：确认 → 填结果 → 选原因 → resolve 载荷齐全', async () => {
    const c = await open([mkRow('r1', { status: 'processing' })])
    confirm.mockResolvedValue('confirm')
    prompt.mockResolvedValue({ value: '已扑灭' })
    resolveAlarm.mockResolvedValue({ data: { success: true } })
    const before = getList.mock.calls.length
    click(rowBtn(c, 0, '处理完成'))
    await waitFor(() => resolveAlarm.mock.calls.length === 1, { message: '完成请求发出' })
    expect(resolveAlarm).toHaveBeenCalledWith('r1', { handleResult: '已扑灭', cause: 'unknown' })
    // 两次确认：结单确认 + 原因选择（默认 unknown，用户未改时如实提交）
    expect(confirm).toHaveBeenCalledTimes(2)
    expect(confirm.mock.calls[0][0]).toBe(i18n.global.t('alarm.resolveConfirm'))
    expect(prompt.mock.calls[0][0]).toBe(i18n.global.t('alarm.handleResult'))
    // 结果输入框必须自带校验：空白/超长不得放行（否则可以提交空处理结果）
    const promptOpts = prompt.mock.calls[0][2]
    expect(promptOpts.inputType).toBe('textarea')
    expect(typeof promptOpts.inputValidator).toBe('function')
    expect(promptOpts.inputValidator('已扑灭')).toBe(true)
    expect(promptOpts.inputValidator('   ')).toBe(i18n.global.t('alarm.handleResultRequired'))
    expect(promptOpts.inputValidator('x'.repeat(1001))).toBe(
      i18n.global.t('alarm.handleResultRequired')
    )
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('alarm.resolved'))
    // 完成后必须回表刷新：否则行仍显示「处理中」，用户以为没生效
    await waitFor(() => getList.mock.calls.length > before, { message: '完成后刷新列表' })
    expect(c.errors).toEqual([])
  })

  test('原因单选：5 个选项的 value 与文案来自词表，选中项随载荷提交', async () => {
    const c = await open([mkRow('r2', { status: 'processing' })])
    prompt.mockResolvedValue({ value: '已修复' })
    resolveAlarm.mockResolvedValue({ data: { success: true } })
    // 两次确认框：第一次是结单确认（字符串），第二次是原因选择（返回 vnode 函数）。
    // 这里同时记录两种形态，若第二次不再是 vnode 函数，seen.causeDialogs 为 0 → 断言红。
    const seen = { causeDialogs: 0, shapes: [] }
    confirm.mockImplementation((msg, title) => {
      seen.shapes.push(typeof msg)
      if (typeof msg === 'function') {
        seen.causeDialogs += 1
        const vnode = msg()
        const group = vnode.children[1]
        const radios = group.children.default()
        seen.values = radios.map((r) => r.props.value)
        seen.labels = radios.map((r) => r.children.default())
        seen.initial = group.props.modelValue
        seen.title = title
        group.props['onUpdate:modelValue']('equipment_fault')
      }
      return Promise.resolve('confirm')
    })
    click(rowBtn(c, 0, '处理完成'))
    await waitFor(() => resolveAlarm.mock.calls.length === 1, { message: '完成请求发出' })
    expect(seen.values).toEqual(['fire', 'false_alarm', 'equipment_fault', 'test', 'unknown'])
    expect(seen.labels).toEqual(['真实火情', '误报', '设备故障', '测试演练', '原因待查'])
    expect(seen.initial).toBe('unknown')
    expect(seen.title).toBe(i18n.global.t('alarm.causeTitle'))
    // 第二次确认必须是原因选择弹窗（vnode 函数）且恰好一次；链路被改坏时此断言红
    expect(seen.causeDialogs).toBe(1)
    expect(seen.shapes).toEqual(['string', 'function'])
    expect(resolveAlarm.mock.calls[0][1]).toEqual({
      handleResult: '已修复',
      cause: 'equipment_fault',
    })
    expect(c.errors).toEqual([])
  })

  test('确认框取消：不发 resolve、不弹成功；行锁释放', async () => {
    const c = await open([mkRow('r3', { status: 'processing' })])
    confirm.mockRejectedValue('cancel')
    click(rowBtn(c, 0, '处理完成'))
    await waitFor(() => confirm.mock.calls.length === 1, { message: '确认框弹出' })
    await flush(16)
    expect(resolveAlarm).not.toHaveBeenCalled()
    expect(prompt).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(rowBtn(c, 0, '处理完成').disabled).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('结果弹窗取消（第二次确认被拒）：不发 resolve、不弹成功', async () => {
    const c = await open([mkRow('r4', { status: 'processing' })])
    confirm.mockResolvedValue('confirm')
    prompt.mockRejectedValue('cancel')
    click(rowBtn(c, 0, '处理完成'))
    await waitFor(() => prompt.mock.calls.length === 1, { message: '结果弹窗弹出' })
    await flush(16)
    expect(resolveAlarm).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(rowBtn(c, 0, '处理完成').disabled).toBe(false)
  })

  test('resolve 失败：不提示成功、行锁释放（可重试）', async () => {
    const c = await open([mkRow('r5', { status: 'processing' })])
    confirm.mockResolvedValue('confirm')
    prompt.mockResolvedValue({ value: '已处理' })
    resolveAlarm.mockRejectedValue(new Error('boom'))
    click(rowBtn(c, 0, '处理完成'))
    await waitFor(() => resolveAlarm.mock.calls.length === 1, { message: '请求发出' })
    await waitFor(() => rowBtn(c, 0, '处理完成').disabled === false, { message: '失败后解锁' })
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})
describe('AlarmView 详情弹窗', () => {
  test('「详情」按钮展示五要素文本（类型/位置/处理人/状态/发生时间），位置为拼装后的文本', async () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const c = await open([
      mkRow('v1', {
        status: 'resolved',
        alarmType: 'smoke',
        occurredAt: iso,
        location: { building: 'A栋', floor: '3层', room: '配电室' },
        handler: { realName: '张三' },
      }),
    ])
    alert.mockResolvedValue('confirm')
    click(rowBtn(c, 0, '详情'))
    await waitFor(() => alert.mock.calls.length === 1, { message: '详情弹窗弹出' })
    expect(alert.mock.calls[0][0]).toBe(
      [
        '报警类型: 烟雾报警',
        '报警位置: A栋3层 配电室',
        '处理人: 张三',
        '状态: 已处理',
        '发生时间: ' + localStamp(iso),
      ].join('\n')
    )
    expect(alert.mock.calls[0][1]).toBe(i18n.global.t('alarm.title'))
    expect(alert.mock.calls[0][2]).toMatchObject({ customClass: 'alarm-detail-dialog' })
    expect(c.errors).toEqual([])
  })

  test('缺失字段用 - 占位而非 undefined/Invalid Date', async () => {
    const c = await open([
      mkRow('v2', { occurredAt: null, alarmType: undefined, type: undefined, handler: null }),
    ])
    alert.mockResolvedValue('confirm')
    click(rowBtn(c, 0, '详情'))
    await waitFor(() => alert.mock.calls.length === 1, { message: '详情弹窗弹出' })
    const text = alert.mock.calls[0][0]
    expect(text).not.toContain('undefined')
    expect(text).not.toContain('Invalid')
    expect(text).toContain('发生时间: -')
    expect(text).toContain('报警类型: -')
  })
})

describe('AlarmView 上报对话框（表单校验 + 位置解析 + 提交）', () => {
  test('空表单提交：三项必填全部拦截，不发请求、对话框不关', async () => {
    const c = await open([mkRow('f1')])
    click(c.findAll('.glass-btn--danger').find((b) => b.textContent.includes('上报火警')))
    await flush(14)
    click(dialogSubmit())
    await waitFor(() => c.findAll('.el-form-item.is-error').length === 3, {
      message: '三项必填全部报错',
    })
    expect(
      c.findAll('.el-form-item.is-error').map((x) => x.textContent.replace(/\s+/g, ' ').trim())
    ).toEqual(['报警类型请选择', '报警位置', '报警描述0 / 500'])
    expect(report).not.toHaveBeenCalled()
    expect(c.findAll('.el-dialog').length).toBe(1)
    expect(c.errors).toEqual([])
  })

  test('合法提交：位置解析为结构体（房号带空格保留）、occurredAt 为 Date、level 固定 warning', async () => {
    const c = await open([mkRow('f2')])
    report.mockResolvedValue({ data: { success: true } })
    await fillReportForm(c, { location: 'A栋3楼 配电室', description: '闻到焦糊味' })
    click(dialogSubmit())
    await waitFor(() => report.mock.calls.length === 1, { message: '上报请求发出' })
    const payload = report.mock.calls[0][0]
    expect(payload.alarmType).toBe('smoke')
    expect(payload.level).toBe('warning')
    expect(payload.description).toBe('闻到焦糊味')
    expect(payload.location).toEqual({ building: 'A栋', floor: '3层', room: '配电室' })
    // occurredAt 必须是 Date 实例（传字符串后端 isISO8601 可能拒绝）
    expect(payload.occurredAt instanceof Date).toBe(true)
    expect(Number.isNaN(payload.occurredAt.getTime())).toBe(false)
    // 未填 deviceId 时不得把空串塞进载荷
    expect('deviceId' in payload).toBe(false)
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('messages.createSuccess'))
    expect(c.errors).toEqual([])
  })

  test('位置解析边界：无数字整串作建筑名，带「楼/层/F」后缀归一为「N层」，其余归房间', async () => {
    const cases = [
      ['A栋配电室', { building: 'A栋配电室', floor: '', room: '' }],
      ['A栋 3楼 配电室', { building: 'A栋', floor: '3层', room: '配电室' }],
      ['C栋7F东侧', { building: 'C栋', floor: '7层', room: '东侧' }],
      ['A栋3楼', { building: 'A栋', floor: '3层', room: '' }],
    ]
    for (const [input, expected] of cases) {
      getList.mockReset()
      getStats.mockReset()
      report.mockReset()
      const c = await open([mkRow('f3')])
      report.mockResolvedValue({ data: { success: true } })
      await fillReportForm(c, { location: input })
      click(dialogSubmit())
      await waitFor(() => report.mock.calls.length === 1, { message: '上报 ' + input })
      expect({ input, location: report.mock.calls[0][0].location }).toEqual({
        input,
        location: expected,
      })
      c.handle.unmount()
      active = null
    }
  })

  test('设备 ID 可选：填了就随载荷提交', async () => {
    const c = await open([mkRow('f4')])
    report.mockResolvedValue({ data: { success: true } })
    await fillReportForm(c)
    const dev = c
      .findAll('.el-dialog input')
      .find((i) => i.getAttribute('placeholder') === i18n.global.t('alarm.deviceIdPlaceholder'))
    dev.value = '507f1f77bcf86cd799439011'
    dev.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(6)
    click(dialogSubmit())
    await waitFor(() => report.mock.calls.length === 1, { message: '上报请求' })
    expect(report.mock.calls[0][0].deviceId).toBe('507f1f77bcf86cd799439011')
  })

  test('提交失败：提示创建失败、对话框保持打开（用户不必重填）、按钮解锁可重试', async () => {
    const c = await open([mkRow('f5')])
    report.mockRejectedValueOnce(new Error('boom'))
    await fillReportForm(c)
    click(dialogSubmit())
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith(i18n.global.t('messages.createFailed'))
    await waitFor(() => dialogSubmit().disabled === false, { message: '按钮解锁' })
    expect(c.findAll('.el-dialog').length).toBe(1)
    expect(c.errors).toEqual([])
    // 重试成功：同一次填表内容无需重填
    report.mockResolvedValue({ data: { success: true } })
    click(dialogSubmit())
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '重试成功' })
    expect(report.mock.calls).toHaveLength(2)
    expect(report.mock.calls[1][0].location).toEqual({
      building: 'A栋',
      floor: '3层',
      room: '配电室',
    })
  })

  test('关闭对话框后重开：表单字段全部清空（不残留上一次输入）', async () => {
    const c = await open([mkRow('f6')])
    await fillReportForm(c, { location: 'A栋3楼', description: '上次的描述' })
    click(
      Array.from(document.querySelectorAll('.el-dialog button')).find(
        (b) => b.textContent.trim() === i18n.global.t('common.cancel')
      )
    )
    await flush(30)
    click(c.findAll('.glass-btn--danger').find((b) => b.textContent.includes('上报火警')))
    await flush(20)
    const loc = c
      .findAll('.el-dialog input')
      .find((i) => i.getAttribute('placeholder') === i18n.global.t('alarm.location'))
    expect(loc.value).toBe('')
    expect(c.find('.el-dialog textarea').value).toBe('')
    expect(c.errors).toEqual([])
  })

  test('提交成功后关闭对话框且列表刷新（新报警立刻可见）', async () => {
    const c = await open([mkRow('f7')])
    report.mockResolvedValue({ data: { success: true } })
    const before = getList.mock.calls.length
    const beforeStats = getStats.mock.calls.length
    await fillReportForm(c)
    click(dialogSubmit())
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '提交成功' })
    await waitFor(() => getList.mock.calls.length > before, { message: '列表刷新' })
    await waitFor(() => getStats.mock.calls.length > beforeStats, { message: '统计刷新' })
    expect(c.findAll('.el-dialog')).toHaveLength(1)
    expect(c.errors).toEqual([])
  })
})
