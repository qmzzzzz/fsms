/**
 * AttackProfileView 组件级行为测试
 *
 * 覆盖「客户只输入 IP 就能用」的主路径：空 IP 不发请求、输入后点按钮出结论、
 * 从审计页带 ?ip= 直接进入即自动分析、失败可见且不抹掉上次结果、
 * 审计读取 401 时弹二次验证并重放、一键报告可查看/复制。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const getProfile = vi.fn()
const createTicket = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    security: {
      getAttackProfile: (...args) => getProfile(...args),
      createReauthTicket: (...args) => createTicket(...args),
    },
  },
  isCanceledError: (e) => Boolean(e && e.code === 'ERR_CANCELED'),
}))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (value) => Promise.resolve('ENC:' + value),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import AttackProfileView from '@/views/AttackProfileView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  if (active) {
    active.handle.unmount()
    active = null
  }
})

const profileData = (over = {}) => ({
  ok: true,
  ip: '203.0.113.10',
  window: {
    hours: 168,
    since: '2026-10-01T00:00:00.000Z',
    until: '2026-10-08T00:00:00.000Z',
  },
  total: 42,
  analyzed: 42,
  truncated: false,
  firstSeen: '2026-10-02T00:00:00.000Z',
  lastSeen: '2026-10-07T00:00:00.000Z',
  score: 65,
  verdict: 'attack',
  riskLevel: 'high',
  scopeLimited: false,
  isPrivate: false,
  stats: {
    failedRequests: 38,
    failedLogins: 30,
    successfulLogins: 0,
    distinctAccountsTried: 12,
    distinctUserAgents: 2,
    criticalRows: 1,
    peakBucketRequests: 30,
    peakBucketStart: '2026-10-03T00:00:00.000Z',
    firstSeen: '2026-10-02T00:00:00.000Z',
    lastSeen: '2026-10-07T00:00:00.000Z',
  },
  categories: [
    {
      code: 'credential_stuffing',
      count: 30,
      blockedCount: 28,
      successCount: 2,
      severity: 'high',
      evidence: [
        {
          timestamp: '2026-10-03T00:00:00.000Z',
          action: 'login_failed',
          method: 'POST',
          path: '/api/auth/login',
          statusCode: 401,
          username: 'alice',
          refusalReason: '密码错误',
          logId: '507f1f77bcf86cd799439011',
        },
      ],
    },
  ],
  topPaths: [{ value: '/api/auth/login', count: 30 }],
  topActions: [{ value: 'login_failed', count: 30 }],
  topTargetAccounts: [{ value: 'alice', count: 20 }],
  topUserAgents: [{ value: 'curl/8', count: 12 }],
  timeline: {
    unit: 'day',
    buckets: [
      {
        bucketStart: '2026-10-03T00:00:00.000Z',
        total: 30,
        blocked: 28,
        categories: ['credential_stuffing'],
      },
    ],
  },
  containment: {
    degraded: false,
    blacklisted: true,
    whitelisted: false,
    entries: [
      {
        listType: 'black',
        ip: '203.0.113.10',
        reason: '撞库',
        expiresAt: null,
        createdAt: '2026-10-04T00:00:00.000Z',
      },
    ],
  },
  suggestions: ['block_ip', 'reset_credentials'],
  ...over,
})

const okBody = (over) => ({ data: { success: true, message: 'ok', data: profileData(over) } })

const mountView = (initialRoute = '/attack-profile', routes) => {
  active = mountComponent(AttackProfileView, {
    initialRoute,
    routes: routes || [
      {
        path: '/attack-profile',
        name: 'attack-profile',
        component: { render: () => null },
      },
      {
        path: '/audit-logs',
        name: 'audit-logs',
        component: { render: () => null },
      },
    ],
  })
  return active
}

const buttonByText = (root, text) =>
  Array.from(root.querySelectorAll('button')).find((el) => el.textContent.trim() === text)

const fillIp = async (c, value) => {
  const input = c.find('.query-form input')
  input.value = value
  input.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(2)
}

describe('AttackProfileView 查询主路径', () => {
  test('空 IP：只提示、不发请求', async () => {
    const c = mountView()
    click(buttonByText(c.root, '开始分析'))
    await flush(3)
    expect(getProfile).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith('请先输入一个 IP 地址')
  })

  test('输入 IP 点分析：按默认 7 天查询，并渲染结论/统计/分类/建议/证据', async () => {
    getProfile.mockResolvedValue(okBody())
    const c = mountView()
    await fillIp(c, '203.0.113.10')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('.verdict-title'), { message: '结论横幅渲染' })

    expect(getProfile).toHaveBeenCalledWith({ ip: '203.0.113.10', hours: 168 })
    expect(c.find('.verdict-title').textContent.trim()).toBe('发现攻击行为')
    expect(c.find('.score-value').textContent).toContain('65')
    expect(c.text()).toContain('登录失败')
    expect(c.text()).toContain('被尝试最多的账号')
    expect(c.text()).toContain('立即封禁该 IP')
    expect(c.text()).toContain('峰值请求数')
    expect(c.text()).toContain('30 次/天')

    const card = c.find('[data-category="credential_stuffing"]')
    expect(card).toBeTruthy()
    expect(card.textContent).toContain('撞库攻击')
    expect(card.textContent).toContain('共 30 次')
    expect(card.textContent).toContain('/api/auth/login')
    expect(card.textContent).toContain('登录失败')
    expect(c.errors).toEqual([])
  })

  test('结果区提供分区导航，长页面可跳转到各分区', async () => {
    getProfile.mockResolvedValue(okBody())
    const c = mountView()
    await fillIp(c, '203.0.113.10')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('[data-test="section-nav"]'), { message: '分区导航渲染' })

    const labels = Array.from(c.root.querySelectorAll('.section-nav__item')).map((el) =>
      el.textContent.trim()
    )
    expect(labels).toEqual(
      expect.arrayContaining(['关键数据', '行为分类', '活动时间线', '当前处置状态'])
    )

    click(buttonByText(c.find('[data-test="section-nav"]'), '行为分类'))
    await flush(2)
    expect(c.find('#profile-categories')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('无数据：只保留结论与处置状态，不渲染空的统计/分类/时间线', async () => {
    getProfile.mockResolvedValue(
      okBody({
        total: 0,
        analyzed: 0,
        score: 0,
        verdict: 'no_data',
        riskLevel: 'none',
        categories: [],
        suggestions: [],
        uncategorized: { count: 0, evidence: [] },
        topPaths: [],
        topActions: [],
        topTargetAccounts: [],
        topUserAgents: [],
        timeline: { unit: 'day', buckets: [] },
        stats: {
          failedRequests: 0,
          failedLogins: 0,
          successfulLogins: 0,
          distinctAccountsTried: 0,
          distinctUserAgents: 0,
          criticalRows: 0,
          peakBucketRequests: 0,
          peakBucketStart: null,
        },
        containment: { degraded: false, blacklisted: false, whitelisted: false, entries: [] },
      })
    )
    const c = mountView()
    await fillIp(c, '203.0.113.99')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('.verdict-title'), { message: '无数据结论渲染' })

    expect(c.find('.verdict-title').textContent.trim()).toBe('没有记录')
    expect(c.find('.stat-grid')).toBeNull()
    expect(c.find('[data-test="section-nav"]')).toBeNull()
    expect(c.text()).toContain('当前处置状态')
    expect(c.text()).toContain('该 IP 当前不在任何名单中')
  })

  test('从审计页带 ?ip= 进入：无需点击即自动分析', async () => {
    getProfile.mockResolvedValue(okBody())
    const c = mountView('/attack-profile?ip=203.0.113.10')
    await waitFor(() => getProfile.mock.calls.length === 1, { message: '自动查询发出' })
    expect(getProfile).toHaveBeenCalledWith({ ip: '203.0.113.10', hours: 168 })
    await waitFor(() => c.find('.verdict-title'), { message: '自动查询结果渲染' })
    expect(c.find('.query-form input').value).toBe('203.0.113.10')
  })

  test('查询失败且没有旧结果：显示失败提示，不伪装成「没有记录」', async () => {
    getProfile.mockRejectedValue({
      response: { data: { errors: { errorCode: 'AUDIT_QUERY_FAILED' } } },
    })
    const c = mountView()
    await fillIp(c, '203.0.113.10')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('.load-alert'), { message: '失败提示出现' })
    expect(c.find('.load-alert').textContent).toContain('分析失败，请稍后重试')
    expect(c.find('.verdict-title')).toBeNull()
  })

  test('刷新失败但已有结果：保留上次结果并标注为旧数据', async () => {
    getProfile.mockResolvedValueOnce(okBody()).mockRejectedValueOnce({
      response: { data: { errors: { errorCode: 'AUDIT_QUERY_FAILED' } } },
    })
    const c = mountView()
    await fillIp(c, '203.0.113.10')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('.verdict-title'), { message: '首次结果渲染' })
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('.load-alert')?.textContent.includes('刷新失败'), {
      message: '旧数据提示出现',
    })
    expect(c.find('.verdict-title').textContent.trim()).toBe('发现攻击行为')
  })
})

describe('AttackProfileView 取证钻取', () => {
  const analyze = async (over) => {
    getProfile.mockResolvedValue(okBody(over))
    const c = mountView()
    await fillIp(c, '203.0.113.10')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('.verdict-title'), { message: '分析结果渲染' })
    return c
  }

  // 期望值独立计算：本地日期（画像页用 localDateStr 生成深链日期）
  const ymd = (iso) => {
    const d = new Date(iso)
    const p = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
  }

  test('证据行点「查看完整取证」：带 logId 跳到审计页详情深链', async () => {
    const c = await analyze()
    await waitFor(
      () => c.find('[data-category="credential_stuffing"] .evidence-table .glass-btn--link'),
      { message: '证据行的取证按钮渲染' }
    )
    click(c.find('[data-category="credential_stuffing"] .evidence-table .glass-btn--link'))
    await waitFor(() => c.router.currentRoute.value.query.logId, { message: '深链跳转落定' })
    expect(c.router.currentRoute.value.name).toBe('audit-logs')
    expect(c.router.currentRoute.value.query.logId).toBe('507f1f77bcf86cd799439011')
  })

  test('点「查看该 IP 全部审计记录」：把 IP 与统计日期带到审计页', async () => {
    const c = await analyze()
    click(buttonByText(c.root, '查看该 IP 全部审计记录'))
    await waitFor(() => c.router.currentRoute.value.query.ip === '203.0.113.10', {
      message: '审计页深链落定',
    })
    const q = c.router.currentRoute.value.query
    expect(c.router.currentRoute.value.name).toBe('audit-logs')
    expect(q.startDate).toBe(ymd('2026-10-01T00:00:00.000Z'))
    expect(q.endDate).toBe(ymd('2026-10-08T00:00:00.000Z'))
  })

  test('未归类记录：单独一节展示数量与证据，同样可逐条打开完整取证', async () => {
    const c = await analyze({
      uncategorized: {
        count: 2,
        evidence: [
          {
            timestamp: '2026-10-04T00:00:00.000Z',
            action: 'ip_blacklist_blocked',
            method: 'POST',
            path: '/api/auth/login',
            statusCode: 403,
            username: null,
            reason: '黑名单拦截',
            logId: '507f1f77bcf86cd799439012',
          },
        ],
      },
    })
    expect(c.text()).toContain('未归类的记录（2 条）')

    await waitFor(
      () => {
        const table = c.findAll('.evidence-table').find((el) => !el.closest('.category-card'))
        return table && table.querySelector('.glass-btn--link')
      },
      { message: '未归类证据表渲染' }
    )
    const table = c.findAll('.evidence-table').find((el) => !el.closest('.category-card'))
    expect(table.textContent).toContain('黑名单拦截')

    click(table.querySelector('.glass-btn--link'))
    await waitFor(() => c.router.currentRoute.value.query.logId, { message: '未归类证据深链落定' })
    expect(c.router.currentRoute.value.query.logId).toBe('507f1f77bcf86cd799439012')
  })
})

describe('AttackProfileView 二次验证', () => {
  const stepUpDlg = () =>
    Array.from(document.body.querySelectorAll('.el-dialog')).find(
      (d) => d.querySelector('.el-dialog__title')?.textContent.trim() === '验证身份'
    )

  const fillAndConfirm = async (password = 'secret') => {
    await waitFor(() => stepUpDlg(), { message: '二次验证弹层打开' })
    const dlg = stepUpDlg()
    const input = dlg.querySelector('input')
    input.value = password
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(2)
    click(buttonByText(dlg, '确定'))
  }

  test('401 REAUTH_TICKET_REQUIRED：验过后重放同一 IP 查询', async () => {
    createTicket.mockResolvedValue({ data: { data: { ticket: 't1', expiresIn: 300 } } })
    let attempts = 0
    getProfile.mockImplementation(() => {
      attempts += 1
      if (attempts === 1) {
        return Promise.reject({
          response: { data: { errors: { errorCode: 'REAUTH_TICKET_REQUIRED' } } },
        })
      }
      return Promise.resolve(okBody())
    })
    const c = mountView()
    await fillIp(c, '203.0.113.10')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => getProfile.mock.calls.length === 1, { message: '首次查询被拒' })
    await fillAndConfirm()
    await waitFor(() => getProfile.mock.calls.length === 2, { message: '验证后重放查询' })
    expect(createTicket).toHaveBeenCalledWith({ encCurrentPassword: 'ENC:secret' })
    await waitFor(() => c.find('.verdict-title'), { message: '重放结果渲染' })
    expect(ElMessage.error).not.toHaveBeenCalled()
  })
})

describe('AttackProfileView 一键报告', () => {
  test('点「生成溯源报告」：预览包含结论、统计、分类与建议；复制写入剪贴板', async () => {
    getProfile.mockResolvedValue(okBody())
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    const c = mountView()
    await fillIp(c, '203.0.113.10')
    click(buttonByText(c.root, '开始分析'))
    await waitFor(() => c.find('.verdict-title'), { message: '结果渲染' })
    click(buttonByText(c.root, '生成溯源报告'))
    await waitFor(() => document.body.querySelector('[data-test="report-preview"]'), {
      message: '报告弹层打开',
    })
    const preview = document.body.querySelector('[data-test="report-preview"]')
    expect(preview.textContent).toContain('IP 行为溯源报告')
    expect(preview.textContent).toContain('发现攻击行为')
    expect(preview.textContent).toContain('撞库攻击')
    expect(preview.textContent).toContain('立即封禁该 IP')

    const dialog = preview.closest('.el-dialog')
    click(buttonByText(dialog, '复制报告'))
    await waitFor(() => writeText.mock.calls.length === 1, { message: '复制报告' })
    expect(writeText.mock.calls[0][0]).toContain('IP 行为溯源报告')
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '复制成功提示' })
  })
})
