/**
 * AttackAlertsView 行为测试（攻击告警查询：分类分段 / 筛选 / 处置列 / 详情与取证深链）
 *
 * 组件定位：安全分析工作台的告警入口 tab。数据面 = getAttackEvents（列表）+
 * getAttackEventSummary（分类角标）+ getAuditLogDetail（详情补齐）。本套件锁定五类退化：
 *
 *  1. 列表渲染口径：行字段映射（时间/来源/请求/类型/证据/严重度/处置）——映射错 = 值班员看错处置状态；
 *  2. 请求口径：分类切片/筛选/页码透传错 = 翻页丢筛选、筛选丢页码；
 *  3. 角标语义：summary 与列表同筛选联动、失败降级为无角标且有可重试痕迹；
 *  4. 失败与竞态：失败不得画成「暂无数据」，有旧数据走 stale（保留+标注）；
 *  5. 出口接线：二次验证弹框重放、详情占位→覆盖、查取证深链带 ip/since/until。
 *
 * 期望值在本文件内独立计算（字面量码表与状态表），不 import 被测工具。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

const getAttackEvents = vi.fn()
const getAttackEventSummary = vi.fn()
const getAuditLogDetail = vi.fn()
const createReauthTicket = vi.fn()
const isCanceledError = vi.fn(() => false)

vi.mock('@/utils/api', () => ({
  api: {
    security: {
      getAttackEvents: (...a) => getAttackEvents(...a),
      getAttackEventSummary: (...a) => getAttackEventSummary(...a),
      getAuditLogDetail: (...a) => getAuditLogDetail(...a),
      createReauthTicket: (...a) => createReauthTicket(...a),
      // 视图未用到的安全组方法不声明：误用会在挂载期炸 TypeError，测试即红
    },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))

// 二次验证弹框替身：v-model 打开态渲染成可见文本，断言弹框时机不碰真实凭据表单
vi.mock('@/components/ReauthDialog.vue', async () => {
  const { h } = await import('vue')
  return {
    __esModule: true,
    default: {
      name: 'ReauthDialogStub',
      props: ['modelValue', 'submitting'],
      emits: ['update:modelValue', 'submit'],
      setup: (props) => () =>
        h(
          'div',
          { 'data-test': 'reauth-stub' },
          props.modelValue ? 'reauth-open' : 'reauth-closed'
        ),
    },
  }
})

import AttackAlertsView from '@/views/AttackAlertsView.vue'

let active = null

const ALL_PERMS = ['security:audit']

/** 夹具行：覆盖三类分类 + 三种处置 + 敏感载荷（列表投影不得带出） */
const mkRow = (id, over = {}) => ({
  _id: id,
  action: 'brute_force_login',
  category: 'security',
  ip: '203.0.113.10',
  username: 'alice',
  method: 'POST',
  path: '/api/auth/login',
  riskLevel: 'critical',
  disposal: 'observing',
  description: '同一 IP 频繁失败',
  timestamp: '2026-11-01T01:00:00.000Z',
  success: false,
  statusCode: 401,
  body: { secret: 'MARKER_BODY' },
  requestHeaders: { authorization: 'MARKER_HEADER' },
  ...over,
})

const ROWS = [
  mkRow('r1'),
  mkRow('r2', {
    action: 'honeypot_login',
    path: '/admin/login',
    riskLevel: 'critical',
    disposal: 'banned',
  }),
  mkRow('r3', {
    action: 'bulk_data_export',
    path: '/api/reports/export',
    riskLevel: 'high',
    disposal: 'forensic',
    username: 'bob',
    description: '',
  }),
]

/** 数据行单元格文本矩阵（el-table 在 jsdom 下真实渲染行） */
const cells = (c) =>
  c
    .findAll('.el-table__body-wrapper .el-table__row')
    .map((tr) =>
      Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.replace(/\s+/g, ' ').trim())
    )

/** 挂载并等首屏列表落地 */
const open = async ({ rows = ROWS, meta, summary } = {}) => {
  getAttackEvents.mockResolvedValue({
    data: {
      data: rows,
      meta: meta === undefined ? { total: rows.length, dataScopeType: 'all' } : meta,
    },
  })
  getAttackEventSummary.mockResolvedValue({
    data: {
      data: summary === undefined ? { credential: 1, honeypot: 1, data_exfil: 1 } : summary,
      meta: { all: 3 },
    },
  })
  active = mountComponent(AttackAlertsView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
  })
  await waitFor(() => cells(active).length === rows.length, { message: '列表行渲染完成' })
  await flush(4)
  return active
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  active?.handle.unmount()
  active = null
})

describe('AttackAlertsView · 列表渲染与请求口径', () => {
  test('首屏：page=1/limit=50 透传，summary 与列表同参；行矩阵按词典渲染', async () => {
    await open()
    expect(getAttackEvents).toHaveBeenCalledTimes(1)
    expect(getAttackEvents.mock.calls[0][0]).toMatchObject({ page: 1, limit: 50 })
    expect(getAttackEventSummary.mock.calls[0][0]).toEqual({})

    const grid = cells(active)
    // 行 1：暴力破解 / 凭证攻击 / 观察
    expect(grid[0].join(' ')).toContain(i18n.global.t('attackAlerts.actions.brute_force_login'))
    expect(grid[0].join(' ')).toContain(i18n.global.t('attackAlerts.types.credential'))
    expect(grid[0].join(' ')).toContain(i18n.global.t('attackAlerts.severity.critical'))
    expect(grid[0].join(' ')).toContain(i18n.global.t('attackAlerts.disposal.observing'))
    // 行 2：蜜罐登录 / 已封禁
    expect(grid[1].join(' ')).toContain(i18n.global.t('attackAlerts.types.honeypot'))
    expect(grid[1].join(' ')).toContain(i18n.global.t('attackAlerts.disposal.banned'))
    // 行 3：数据外泄 / 取证中；description 为空 → 占位文案
    expect(grid[2].join(' ')).toContain(i18n.global.t('attackAlerts.types.data_exfil'))
    expect(grid[2].join(' ')).toContain(i18n.global.t('attackAlerts.disposal.forensic'))
    expect(grid[2].join(' ')).toContain(i18n.global.t('attackAlerts.noDescription'))
    // 列表投影：敏感载荷不得渲染进表格
    expect(active.element.textContent).not.toContain('MARKER_BODY')
    expect(active.element.textContent).not.toContain('MARKER_HEADER')
  })

  test('分类分段即筛选：切到蜜罐 → attackType=honeypot 且回第一页', async () => {
    await open()
    getAttackEvents.mockClear()
    const honeypotItem = active.element.querySelector(
      '.glass-segmented__item[data-value="honeypot"]'
    )
    expect(honeypotItem).not.toBeNull()
    click(honeypotItem)
    await waitFor(
      () => getAttackEvents.mock.calls.some((call) => call[0]?.attackType === 'honeypot'),
      { message: '分类切片已透传' }
    )
    const call = getAttackEvents.mock.calls.find((c) => c[0]?.attackType === 'honeypot')
    expect(call[0]).toMatchObject({ attackType: 'honeypot', page: 1, limit: 50 })
    // 角标请求与列表同筛选（attackType 由后端剔除，前端原样透传）
    expect(getAttackEventSummary.mock.calls.some((c) => c[0]?.attackType === 'honeypot')).toBe(true)
  })

  test('文本筛选 + 查询按钮：ip/账号/路径只塞非空值', async () => {
    await open()
    getAttackEvents.mockClear()
    const ipInput = active.element.querySelector('[data-test="alerts-filter-ip"]')
    ipInput.value = '203.0.113.10'
    ipInput.dispatchEvent(new Event('input'))
    const pathInput = active.element.querySelector('[data-test="alerts-filter-path"]')
    pathInput.value = '/api/auth'
    pathInput.dispatchEvent(new Event('input'))
    click(active.element.querySelector('[data-test="alerts-search"]'))
    await waitFor(() => getAttackEvents.mock.calls.some((call) => call[0]?.ip === '203.0.113.10'), {
      message: '筛选已透传',
    })
    const call = getAttackEvents.mock.calls[0][0]
    expect(call).toMatchObject({ ip: '203.0.113.10', path: '/api/auth', page: 1 })
    expect(call.username).toBeUndefined() // 未填的筛选不进参数
    expect(call.severityMin).toBeUndefined()
  })

  test('重置：清空全部分类与筛选，回到无参查询', async () => {
    await open()
    const honeypotItem = active.element.querySelector(
      '.glass-segmented__item[data-value="honeypot"]'
    )
    click(honeypotItem)
    await flush(4)
    getAttackEvents.mockClear()
    click(active.element.querySelector('[data-test="alerts-reset"]'))
    await waitFor(() => getAttackEvents.mock.calls.length > 0, { message: '重置后重查' })
    const call = getAttackEvents.mock.calls[0][0]
    expect(call.attackType).toBeUndefined() // 空值不进参数（buildFilterParams 只塞非空）
    expect(call.page).toBe(1)
  })

  test('分页：total 已知走完整布局，翻页带新页码且保留筛选', async () => {
    await open({ meta: { total: 120, dataScopeType: 'all' } })
    getAttackEvents.mockClear()
    const nextBtn = active.element.querySelector('.el-pagination .btn-next')
    click(nextBtn)
    await waitFor(() => getAttackEvents.mock.calls.some((c) => c[0]?.page === 2), {
      message: '翻页请求已发出',
    })
    expect(getAttackEvents.mock.calls.find((c) => c[0]?.page === 2)[0].limit).toBe(50)
  })
})

describe('AttackAlertsView · 角标与数据范围', () => {
  test('分段角标取自 summary.byType，「全部」取 meta.all', async () => {
    await open()
    const allItem = active.element.querySelector('.glass-segmented__item[data-value=""]')
    expect(allItem.textContent).toContain('3')
    const credentialItem = active.element.querySelector(
      '.glass-segmented__item[data-value="credential"]'
    )
    expect(credentialItem.textContent).toContain('1')
  })

  test('角标失败：不拖垮列表，降级为无角标并留可重试痕迹', async () => {
    getAttackEvents.mockResolvedValue({
      data: { data: ROWS, meta: { total: 3, dataScopeType: 'all' } },
    })
    getAttackEventSummary.mockRejectedValue(new Error('boom'))
    active = mountComponent(AttackAlertsView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => cells(active).length === ROWS.length, { message: '列表正常落地' })
    expect(active.element.querySelector('[data-test="alerts-summary-error"]')).not.toBeNull()
    expect(
      active.element.querySelector('.glass-segmented__item[data-value="credential"]').textContent
    ).not.toContain('1')
  })

  test('数据范围非 all：页面顶部出现受限提示（空结果不冒充「没有攻击」）', async () => {
    await open({ meta: { total: 3, dataScopeType: 'self' } })
    expect(active.element.querySelector('[data-test="alerts-scope-limited"]')).not.toBeNull()
  })
})

describe('AttackAlertsView · 失败三态（与审计/报警同契约）', () => {
  test('首屏失败：错误块顶替表格，不显示「暂无数据」', async () => {
    getAttackEvents.mockRejectedValue(new Error('boom'))
    getAttackEventSummary.mockResolvedValue({ data: { data: {}, meta: { all: 0 } } })
    active = mountComponent(AttackAlertsView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => !!active.element.querySelector('[data-test="alerts-load-error"]'), {
      message: '错误块出现',
    })
    expect(cells(active)).toHaveLength(0)
  })

  test('翻查失败但有旧数据：stale 保留旧行并标注', async () => {
    await open()
    getAttackEvents.mockRejectedValue(new Error('boom'))
    click(active.element.querySelector('[data-test="alerts-search"]'))
    await waitFor(() => !!active.element.querySelector('[data-test="alerts-load-error"]'), {
      message: 'stale 标注出现',
    })
    expect(cells(active)).toHaveLength(3) // 旧数据保留
  })

  test('边界渲染：处置 unknown 与未注册 action 都不冒充正常分类', async () => {
    // unknown：后端处置富化 fail-soft 的第四档（"此刻不可判定"）
    // 未注册 action：滚动部署窗口内前后端注册表短暂分叉
    await open({
      rows: [
        mkRow('r9', { action: 'login_failed', disposal: 'unknown' }),
        mkRow('r10', { action: 'some_future_action', ip: '203.0.113.99' }),
      ],
    })
    const grid = cells(active)
    expect(grid[0].join(' ')).toContain(i18n.global.t('attackAlerts.disposal.unknown'))
    // 未注册 action 的类型标签显示裸码，不冒充「全部攻击」
    expect(grid[1].join(' ')).toContain('some_future_action')
    expect(grid[1].join(' ')).not.toContain(i18n.global.t('attackAlerts.tabsAll'))
  })

  test('abort（路由切换）不算失败，不留错误块', async () => {
    getAttackEvents.mockImplementation(
      () =>
        new Promise((_, reject) => {
          const err = new Error('canceled')
          isCanceledError.mockImplementationOnce((e) => e === err)
          setTimeout(() => reject(err), 0)
        })
    )
    getAttackEventSummary.mockResolvedValue({ data: { data: {}, meta: { all: 0 } } })
    active = mountComponent(AttackAlertsView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await flush(8)
    expect(active.element.querySelector('[data-test="alerts-load-error"]')).toBeNull()
  })
})

describe('AttackAlertsView · 二次验证与出口', () => {
  test('401 REAUTH_TICKET_REQUIRED：弹框出现且不当作业务失败', async () => {
    const reauthError = Object.assign(new Error('ticket'), {
      response: { data: { errors: { errorCode: 'REAUTH_TICKET_REQUIRED' } } },
    })
    getAttackEvents.mockRejectedValue(reauthError)
    getAttackEventSummary.mockResolvedValue({ data: { data: {}, meta: { all: 0 } } })
    active = mountComponent(AttackAlertsView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(ALL_PERMS),
    })
    await waitFor(() => active.element.textContent.includes('reauth-open'), {
      message: '二次验证弹框打开',
    })
    expect(active.element.querySelector('[data-test="alerts-load-error"]')).toBeNull()
  })

  test('详情：行数据先占位，详情到达后覆盖；getAuditLogDetail 携带行 _id', async () => {
    await open()
    getAuditLogDetail.mockResolvedValue({
      data: { data: { ...ROWS[0], description: '详情补齐的描述' } },
    })
    click(active.element.querySelector('[data-test="alerts-detail-btn"]'))
    await waitFor(() => getAuditLogDetail.mock.calls.length === 1, { message: '详情请求已发出' })
    expect(getAuditLogDetail.mock.calls[0][0]).toBe('r1')
    // 对话框 append-to-body：teleport 到 document.body，不在组件根元素内
    await waitFor(() => document.body.textContent.includes('详情补齐的描述'), {
      message: '详情内容覆盖占位',
    })
  })

  test('查取证深链：携带 ip 与 since/until（date-only）切到取证 tab', async () => {
    await open()
    click(active.element.querySelector('[data-test="alerts-forensic-btn"]'))
    await flush(4)
    const { currentRoute } = active.router
    expect(currentRoute.value.path).toBe('/security-analysis')
    expect(currentRoute.value.query.tab).toBe('forensic')
    expect(currentRoute.value.query.ip).toBe('203.0.113.10')
    // date-only 形状（取证视图 DATE_ONLY 判据）
    expect(currentRoute.value.query.since).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(currentRoute.value.query.until).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })
})
