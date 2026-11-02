/**
 * ForensicTraceView 组件级行为测试
 *
 * 覆盖行为面：无判据不发请求、空结果不报错、溯源渲染（时间线本地时区口径 /
 * 触发原因分布 / 网段分布 / 「他的 ip 池」仅在传指纹时展示）、溯源失败可见、
 * 聚类渲染与判定文案、封段两步走（先 request 拿票再 confirm 落库）、
 * request 被拒时按 errors.reason 给**具体**文案（五种原因逐个覆盖）、
 * confirm 后按 bannedCount 如实报结果（含 0 条与部分生效）、签名导出。
 *
 * 契约口径（work/forensic-api-contract.md，冻结）：
 *  - 成功信封 { success, message, data }，业务负载在 res.data.data；
 *  - 封禁被拒：HTTP 400 + errors.errorCode=FORENSIC_POOL_BAN_REFUSED，
 *    **具体原因在 errors.reason**（不是 data.reason，也不是顶层 reason）；
 *  - confirm 的成功依据只有 bannedCount（addToBlacklist 从不抛错，
 *    「没报错」≠「封上了」）。
 *
 * 期望值一律在本文件内独立计算（Date 本地 getter 补零 / 直接读词表），
 * 不 import 被测源码的格式化工具，避免实现写错时两边一起错、断言恒真。
 */
import fs from 'node:fs'
import path from 'node:path'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const get = vi.fn()
const post = vi.fn()
const trace = vi.fn()
const clusters = vi.fn()
const requestBan = vi.fn()
const confirmBan = vi.fn()
const exportForensic = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    security: {
      getForensicTrace: (...a) => trace(...a),
      getForensicClusters: (...a) => clusters(...a),
      requestPoolBan: (...a) => requestBan(...a),
      confirmPoolBan: (...a) => confirmBan(...a),
      exportForensic: (...a) => exportForensic(...a),
    },
  },
  apiClient: { get: (...a) => get(...a), post: (...a) => post(...a), delete: vi.fn() },
  isCanceledError: (e) => Boolean(e && e.code === 'ERR_CANCELED'),
  isHandledApiError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import ForensicTraceView from '@/views/ForensicTraceView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

// 权限码写死在用例里（不从源码 import）：门控判据被改错时这里必须失败
const AUDIT = 'security:audit'
const CONFIG = 'security:config'
const PERMS = [AUDIT, CONFIG]

let active = null

beforeEach(() => {
  // 本仓 vitest 配置未开 clearMocks：不显式清理的话，上一个用例的调用记录会
  // 串到下一个（断言 not.toHaveBeenCalled 会因别人的调用而红）。
  vi.clearAllMocks()
})

afterEach(() => {
  if (active) {
    active.handle.unmount()
    active = null
  }
})

const mountView = (perms = PERMS, initialRoute = '/') => {
  active = mountComponent(ForensicTraceView, {
    initialRoute,
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
  return active
}

/** 本地日期串（与视图 value-format=YYYY-MM-DD 同口径） */
const wallDate = (d) => {
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

/** 「最近 N 小时」对应的日期范围（本地日期，独立按 Date 计算，不 import 被测源码） */
const rangeOfHours = (hours) => {
  const until = new Date()
  const since = new Date(until.getTime() - hours * 60 * 60 * 1000)
  return [wallDate(since), wallDate(until)]
}

/** 本地时区「YYYY-MM-DD HH:mm:ss」定长串（口径由 utils/datetime.formatTime 统一） */
const localStamp = (iso) => {
  const d = new Date(iso)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const tlRow = (over = {}) => ({
  createdAt: '2026-10-01T01:00:00.000Z',
  ip: '1.2.3.4',
  ipSegment: '1.2.3',
  method: 'POST',
  path: '/api/auth/login',
  action: 'login_failed',
  category: 'security',
  username: 'alice',
  fingerprint: 'ab12cd34',
  trigger: 'brute_force',
  reason: '5 次失败',
  status: 401,
  recordHash: 'hash-1',
  seq: 'RUN-12',
  ...over,
})

const traceBody = (over = {}) => ({
  data: {
    success: true,
    message: 'ok',
    data: {
      ok: true,
      since: '2026-09-25T00:00:00.000Z',
      until: '2026-10-02T00:00:00.000Z',
      count: 1,
      truncated: false,
      timeline: [tlRow()],
      triggers: { brute_force: 1 },
      segments: { '1.2.3': 1 },
      pools: [],
      ...over,
    },
  },
})

const clusterRow = (over = {}) => ({
  segment: '1.2.3',
  cidr: '1.2.3.0/24',
  hits: 40,
  distinctIps: 12,
  distinctFingerprints: 2,
  firstSeen: '2026-10-01T00:00:00.000Z',
  lastSeen: '2026-10-01T02:00:00.000Z',
  verdict: 'rotate_pool',
  recommendBan: true,
  ...over,
})

const clustersBody = (segments) => ({
  data: {
    success: true,
    message: 'ok',
    data: {
      since: '2026-10-01T00:00:00.000Z',
      until: '2026-10-02T00:00:00.000Z',
      segments,
      recommended: segments.filter((s) => s.recommendBan),
    },
  },
})

/** 填写判据并点击「开始溯源」，等待请求落地 */
const doTrace = async (c, { ip = '1.2.3.4', fingerprint = '' } = {}) => {
  const inputs = c.findAll('.criteria-form .el-input__inner')
  // 表单顺序：IP / 指纹 / 网段 / 日期 / 条数
  setInput(inputs[0], ip)
  setInput(inputs[1], fingerprint)
  await flush(4)
  const btn = c
    .findAll('.glass-btn')
    .find((b) => b.textContent.trim() === i18n.global.t('forensic.search'))
  click(btn)
  await flush(10)
}

const setInput = (el, value) => {
  el.value = value
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
}

/**
 * 按 class 取表格行。
 * 不能用「第几张表」这种位置下标：面板是条件渲染的（hasQueried 之前结果区的
 * 四张表根本不在 DOM 里），位置会随状态漂移，断言就会指到别的表上。
 */
const rowsOf = (c, cls) => {
  const table = c.find(`.${cls}`)
  if (!table) return []
  return Array.from(table.querySelectorAll('.el-table__body-wrapper .el-table__row'))
}

const td = (row, col) => Array.from(row.querySelectorAll('td'))[col]

/** 打开封段确认框：点「封禁此网段」，等对话框渲染出 cidr / 影响面 */
const openBan = async (c) => {
  const banBtn = c
    .findAll('.glass-btn')
    .find((b) => b.textContent.trim() === i18n.global.t('forensic.banAction'))
  click(banBtn)
  await flush(10)
  await waitFor(() => c.find('.ban-summary') !== null, { message: '确认框打开' })
}

/** 填写封段理由：前置校验要求非空，否则前端直接拦住不发 request */
const fillBanReason = async (c, text) => {
  const ta = c.find('.ban-summary textarea')
  ta.value = text
  ta.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(4)
}

/** 点确认框底部的按钮（文案由调用方给：取消 / 确认） */
const clickText = async (c, text) => {
  const btn = c.findAll('.glass-btn').find((b) => b.textContent.trim() === text)
  click(btn)
  await flush(12)
}

describe('ForensicTraceView · 判据守卫（无判据不发请求）', () => {
  test('三个判据都为空：点查询只提示，不发任何溯源请求', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.search'))
    click(btn)
    await flush(10)
    expect(trace).not.toHaveBeenCalled()
    // 提示必须说清「为什么没查」，不能静默无反应
    expect(ElMessage.warning).toHaveBeenCalledTimes(1)
    expect(ElMessage.warning.mock.calls[0][0]).toBe(i18n.global.t('forensic.noCriteria'))
    expect(c.errors).toEqual([])
  })

  test('只填指纹也算有判据：照常发请求，参数里只有 fingerprint', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '', fingerprint: 'ab12cd' })
    expect(trace).toHaveBeenCalledTimes(1)
    const params = trace.mock.calls[0][0]
    expect(params.fingerprint).toBe('ab12cd')
    // 空判据不得下发空串（空串会先撞后端 length 校验）
    expect(params.ip).toBeUndefined()
    expect(params.ipSegment).toBeUndefined()
    expect(params.limit).toBe(200)
  })
})

describe('ForensicTraceView · 空结果不报错', () => {
  test('count=0 / timeline 为空：渲染空态文案，不弹错误提示', async () => {
    trace.mockImplementation(() =>
      Promise.resolve(traceBody({ count: 0, timeline: [], triggers: {}, segments: {}, pools: [] }))
    )
    const c = mountView()
    await flush(8)
    await doTrace(c)
    await waitFor(() => c.text().includes(i18n.global.t('forensic.emptyResult')), {
      message: '空态文案渲染',
    })
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})

describe('ForensicTraceView · 溯源结果渲染', () => {
  test('时间线列走本地时区定长口径（不是原始 ISO，也不是 toLocaleString）', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    await doTrace(c)
    await waitFor(() => rowsOf(c, 'forensic-timeline').length === 1, { message: '时间线渲染一行' })
    const iso = tlRow().createdAt
    const expected = localStamp(iso)
    // 前提自证：原样 ISO 与本地定长串必然不同（否则断言不可证伪）
    expect(expected).not.toBe(iso)
    expect(td(rowsOf(c, 'forensic-timeline')[0], 0).textContent.trim()).toBe(expected)
  })

  test('触发原因分布与网段分布：按次数倒序渲染成行', async () => {
    trace.mockImplementation(() =>
      Promise.resolve(
        traceBody({
          triggers: { brute_force: 3, ip_pool: 7 },
          segments: { '1.2.3': 5, '9.9.9': 2 },
        })
      )
    )
    const c = mountView()
    await flush(8)
    await doTrace(c)
    await flush(12)
    const triggerTable = c.find('.forensic-trigger')
    const segmentTable = c.find('.forensic-segment')
    const tRows = Array.from(
      triggerTable.querySelectorAll('.el-table__body-wrapper .el-table__row')
    )
    const sRows = Array.from(
      segmentTable.querySelectorAll('.el-table__body-wrapper .el-table__row')
    )
    // 次数多的排前面
    expect(td(tRows[0], 0).textContent.trim()).toBe('ip_pool')
    expect(td(tRows[0], 1).textContent.trim()).toBe('7')
    expect(td(sRows[0], 0).textContent.trim()).toBe('1.2.3')
    expect(td(sRows[0], 1).textContent.trim()).toBe('5')
  })

  test('「他的 ip 池」：传了指纹才展示 pools 行，未传时给出「先填指纹」的说明', async () => {
    trace.mockImplementation(() =>
      Promise.resolve(
        traceBody({
          pools: [
            {
              segment: '1.2.3',
              hits: 12,
              distinctIps: 5,
              firstSeen: '2026-10-01T00:00:00.000Z',
              lastSeen: '2026-10-01T01:00:00.000Z',
            },
          ],
        })
      )
    )
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '', fingerprint: 'ab12cd' })
    await flush(12)
    const poolTable = c.find('.forensic-pool')
    const pRows = Array.from(poolTable.querySelectorAll('.el-table__body-wrapper .el-table__row'))
    expect(pRows).toHaveLength(1)
    expect(td(pRows[0], 0).textContent.trim()).toBe('1.2.3')
    expect(td(pRows[0], 1).textContent.trim()).toBe('12')
    expect(td(pRows[0], 2).textContent.trim()).toBe('5')
  })

  test('未填指纹：IP 池面板显示「填写设备指纹后才会展示」，而不是空表', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody({ pools: [] })))
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '1.2.3.4', fingerprint: '' })
    await waitFor(() => c.text().includes(i18n.global.t('forensic.poolOnlyWithFingerprint')), {
      message: 'IP 池未填指纹说明',
    })
  })

  test('truncated=true：给出截断警示（不能把「已达上限」当完整结果）', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody({ truncated: true, count: 200 })))
    const c = mountView()
    await flush(8)
    await doTrace(c)
    await waitFor(() => c.text().includes(i18n.global.t('forensic.truncated', { count: 200 })), {
      message: '截断提示',
    })
  })
})

describe('ForensicTraceView · 溯源失败可见', () => {
  test('查询失败：保留上次结果并标注为上次数据，绝不画成「没有记录」', async () => {
    trace.mockImplementationOnce(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    await doTrace(c)
    await waitFor(() => rowsOf(c, 'forensic-timeline').length === 1, { message: '首次结果' })

    trace.mockImplementationOnce(() => Promise.reject(new Error('boom')))
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.search'))
    click(btn)
    await flush(12)
    // 旧数据仍在（失败 ≠ 空）
    expect(rowsOf(c, 'forensic-timeline').length).toBeGreaterThanOrEqual(1)
    await waitFor(() => c.text().includes(i18n.global.t('forensic.staleData')), {
      message: '上次数据标注',
    })
    expect(c.text()).not.toContain(i18n.global.t('forensic.emptyResult'))
  })
})

describe('ForensicTraceView · 聚类与封段入口', () => {
  test('聚类列表渲染 cidr / 命中 / 判定文案；无 recommendBan 时标「不建议」', async () => {
    clusters.mockImplementation(() =>
      Promise.resolve(
        clustersBody([
          clusterRow(),
          clusterRow({
            segment: '8.8.8',
            cidr: '8.8.8.0/24',
            verdict: 'shared_egress',
            recommendBan: false,
          }),
        ])
      )
    )
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 2, { message: '聚类两行' })
    const r0 = rowsOf(c, 'forensic-clusters')[0]
    expect(td(r0, 0).textContent.trim()).toBe('1.2.3.0/24')
    expect(td(r0, 1).textContent.trim()).toBe('40')
    expect(r0.textContent).toContain(i18n.global.t('forensic.verdictRotatePool'))
    const r1 = rowsOf(c, 'forensic-clusters')[1]
    expect(r1.textContent).toContain(i18n.global.t('forensic.verdictSharedEgress'))
    expect(r1.textContent).toContain(i18n.global.t('forensic.noRecommendBan'))
  })

  test('只有 security:audit ⇒ 不发聚类请求，空态明示"无权限"而不是"查询失败"或"没有网段"', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    const c = mountView([AUDIT])
    await flush(8)
    // 聚类端点后端要 security:config：没这道判据就会先发一个注定 403 的请求，
    // 把"权限不足"渲染成"聚类查询失败"（= 把权限差距伪装成后端故障）。
    expect(clusters).not.toHaveBeenCalled()
    expect(c.text()).toContain(i18n.global.t('forensic.clustersForbidden'))
    expect(c.text()).not.toContain(i18n.global.t('forensic.clustersError'))
    expect(c.text()).not.toContain(i18n.global.t('forensic.clustersEmpty'))
    const banBtn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banAction'))
    expect(banBtn).toBeUndefined()
  })

  test('对照：带上 security:config ⇒ 照常发起聚类并渲染（上面的"不发请求"不是恒真）', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    const c = mountView([AUDIT, CONFIG])
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    expect(clusters).toHaveBeenCalledTimes(1)
    expect(c.text()).not.toContain(i18n.global.t('forensic.clustersForbidden'))
  })
})

describe('ForensicTraceView · 200 但不是成功信封', () => {
  test('查询路径：200 且内层 data 为空 ⇒ 报「溯源查询失败」，不渲染只有标题的空卡片', async () => {
    // 契约漂移形态：HTTP 200 + success 信封 + data:null。导出路径对同一形态会明确报
    // exportFailed，查询路径此前静默渲染空卡片，"查询失败"与"没有记录"就分不开。
    trace.mockImplementation(() =>
      Promise.resolve({ data: { success: true, message: 'ok', data: null } })
    )
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '1.2.3.4' })
    await waitFor(() => c.text().includes(i18n.global.t('forensic.loadError')), {
      message: '契约漂移必须显式报错',
    })
  })

  test('对照：data 是空数组（真空结果）⇒ 走空态文案，不报错', async () => {
    trace.mockImplementation(() =>
      Promise.resolve({
        data: {
          success: true,
          message: 'ok',
          data: { count: 0, records: [], triggers: {}, segments: {}, since: '', until: '' },
        },
      })
    )
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '1.2.3.4' })
    expect(c.text()).toContain(i18n.global.t('forensic.emptyResult'))
    expect(c.text()).not.toContain(i18n.global.t('forensic.loadError'))
  })

  test('聚类路径：200 且内层 data 为空 ⇒ 报「聚类查询失败」，不渲染成「没有网段」', async () => {
    clusters.mockImplementation(() =>
      Promise.resolve({ data: { success: true, message: 'ok', data: null } })
    )
    const c = mountView()
    await waitFor(() => c.text().includes(i18n.global.t('forensic.clustersError')), {
      message: '聚类契约漂移必须显式报错',
    })
    expect(c.text()).not.toContain(i18n.global.t('forensic.clustersEmpty'))
  })
})

describe('ForensicTraceView · 打字确认（B9 回归：/24 必带 typedConfirm）', () => {
  test('后端要求打字 ⇒ 界面出现输入框，且提交时把 typedConfirm 原样带上', async () => {
    requestBan.mockImplementation(() =>
      Promise.resolve({
        data: {
          data: { token: 'tk-1', cidr: '203.0.113.0/24', needTypedConfirm: true, hostCount: 256 },
        },
      })
    )
    confirmBan.mockImplementation(() =>
      Promise.resolve({ data: { data: { cidr: '203.0.113.0/24', bannedCount: 1, results: [{}] } } })
    )
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    await openBan(c)
    await fillBanReason(c, '手工封段')
    await clickText(c, i18n.global.t('forensic.banConfirm'))
    // vitest 的 find 在无匹配时返回 null（不是带 exists() 的 wrapper）
    await waitFor(() => c.find('.ban-typed-confirm') !== null, { message: '打字输入框渲染' })
    // 打字确认必须是**真的两次交互**：第一次点击只申请票据并露出输入框，
    // 用户敲完再点第二次才落库。否则 needTypedConfirm 为真时 typedConfirm 只能是空串，
    // 后端一律 400，界面等于不可用（第 18 轮两条 lane 各自实测）。
    expect(confirmBan).not.toHaveBeenCalled()
    setInput(c.find('.ban-typed-confirm input'), '203.0.113.0/24')
    await flush(4)
    await clickText(c, i18n.global.t('forensic.banConfirm'))
    await flush(10)
    expect(confirmBan).toHaveBeenCalledTimes(1)
    const body = confirmBan.mock.calls.at(-1)[0]
    expect(body.typedConfirm).toBe('203.0.113.0/24')
  })

  test('对照：后端不要求打字 ⇒ 不渲染输入框，请求体里也不出现 typedConfirm', async () => {
    requestBan.mockImplementation(() =>
      Promise.resolve({
        data: { data: { token: 'tk-2', cidr: '198.51.100.0/24', needTypedConfirm: false } },
      })
    )
    confirmBan.mockImplementation(() =>
      Promise.resolve({
        data: { data: { cidr: '198.51.100.0/24', bannedCount: 1, results: [{}] } },
      })
    )
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    await openBan(c)
    await fillBanReason(c, '手工封段')
    await clickText(c, i18n.global.t('forensic.banConfirm'))
    await flush(10)
    expect(c.find('.ban-typed-confirm')).toBeNull()
    expect(confirmBan.mock.calls[0][0]).not.toHaveProperty('typedConfirm')
  })
})

describe('ForensicTraceView · 封段两步走（request → confirm）', () => {
  const fillReason = async (c, text) => {
    const ta = c.find('.ban-summary textarea')
    ta.value = text
    ta.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
  }

  const clickConfirm = async (c) => {
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banConfirm'))
    click(btn)
    await flush(12)
  }

  test('确认框必须先展示 cidr / 命中数 / 影响面，且未填理由不发请求', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    await openBan(c)

    const summary = c.find('.ban-summary').textContent
    expect(summary).toContain('1.2.3.0/24')
    expect(summary).toContain('40')
    // 影响面必须写清「整段都会被拒」，不只命中过的那几个
    expect(summary).toContain(i18n.global.t('forensic.banImpact'))
    expect(summary).toContain(
      i18n.global.t('forensic.banImpactText', { cidr: '1.2.3.0/24', ips: 12 })
    )

    // 理由为空：前端拦住，不发 request
    await clickConfirm(c)
    expect(requestBan).not.toHaveBeenCalled()
    expect(ElMessage.warning.mock.calls[0][0]).toBe(i18n.global.t('forensic.banReasonRequired'))
  })

  test('填了理由：先 request 拿票，再用同一 token 调 confirm', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    requestBan.mockImplementation(() =>
      Promise.resolve({
        data: {
          success: true,
          message: '待确认',
          data: {
            ok: true,
            token: 'tok-abc',
            cidr: '1.2.3.0/24',
            expiresAt: '2026-10-01T00:10:00Z',
          },
        },
      })
    )
    confirmBan.mockImplementation(() =>
      Promise.resolve({
        data: {
          success: true,
          message: '封禁已提交',
          data: {
            ok: true,
            cidr: '1.2.3.0/24',
            bannedCount: 1,
            results: [{ ip: '1.2.3.0/24', banned: true }],
          },
        },
      })
    )
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    await openBan(c)
    await fillReason(c, '轮换 IP 池，连续爆破')
    await clickConfirm(c)

    // 第一步：cidr + reason，且请求声明 silentErrors（原因由本页渲染）
    expect(requestBan).toHaveBeenCalledTimes(1)
    expect(requestBan.mock.calls[0][0]).toEqual({
      cidr: '1.2.3.0/24',
      reason: '轮换 IP 池，连续爆破',
    })
    expect(requestBan.mock.calls[0][1]).toEqual({ silentErrors: true })

    // 第二步：**原样**提交同一张票（票据一次性、10 分钟失效）
    await waitFor(() => confirmBan.mock.calls.length === 1, { message: 'confirm 已调用' })
    expect(confirmBan.mock.calls[0][0]).toEqual({ token: 'tok-abc', durationHours: 24 })
    expect(confirmBan.mock.calls[0][1]).toEqual({ silentErrors: true })
  })

  test('confirm 用 bannedCount 如实报结果：写进 1 条就报 1 条，不是笼统「已封禁」', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    requestBan.mockImplementation(() =>
      Promise.resolve({
        data: { success: true, data: { ok: true, token: 'tok-1', cidr: '1.2.3.0/24' } },
      })
    )
    confirmBan.mockImplementation(() =>
      Promise.resolve({
        data: {
          success: true,
          data: {
            ok: true,
            cidr: '1.2.3.0/24',
            bannedCount: 1,
            results: [{ ip: '1.2.3.0/24', banned: true }],
          },
        },
      })
    )
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    await openBan(c)
    await fillReason(c, '理由')
    await clickConfirm(c)
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    const shown = ElMessage.success.mock.calls[0][0]
    expect(shown).toBe(i18n.global.t('forensic.banApplied', { cidr: '1.2.3.0/24', count: 1 }))
    // 前提自证：文案里必须真的带上了数字 1（否则「用 bannedCount 报结果」没被钉住）
    expect(shown).toContain('1')
  })

  test('bannedCount=0：必须报「没生效」，绝不提示成功', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    requestBan.mockImplementation(() =>
      Promise.resolve({
        data: { success: true, data: { ok: true, token: 'tok-0', cidr: '1.2.3.0/24' } },
      })
    )
    confirmBan.mockImplementation(() =>
      Promise.resolve({
        data: {
          success: true,
          data: {
            ok: true,
            cidr: '1.2.3.0/24',
            bannedCount: 0,
            results: [{ ip: '1.2.3.0/24', banned: false }],
          },
        },
      })
    )
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    await openBan(c)
    await fillReason(c, '理由')
    await clickConfirm(c)
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '未生效提示' })
    expect(ElMessage.error.mock.calls[0][0]).toBe(
      i18n.global.t('forensic.banAppliedNone', { cidr: '1.2.3.0/24' })
    )
    // 核心判据：「await 返回了」不等于「封上了」，绝不能报成功
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  test('bannedCount < results 长度：报部分生效，带上实际条数与计划条数', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    requestBan.mockImplementation(() =>
      Promise.resolve({
        data: { success: true, data: { ok: true, token: 'tok-p', cidr: '1.2.3.0/24' } },
      })
    )
    confirmBan.mockImplementation(() =>
      Promise.resolve({
        data: {
          success: true,
          data: {
            ok: true,
            cidr: '1.2.3.0/24',
            bannedCount: 2,
            results: [
              { ip: '1.2.3.0/24', banned: true },
              { ip: '1.2.3.0/24', banned: true },
              { ip: '1.2.3.0/24', banned: false },
            ],
          },
        },
      })
    )
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    await openBan(c)
    await fillReason(c, '理由')
    await clickConfirm(c)
    await waitFor(() => ElMessage.warning.mock.calls.length >= 1, { message: '部分生效提示' })
    expect(ElMessage.warning.mock.calls[0][0]).toBe(
      i18n.global.t('forensic.banAppliedPartial', { cidr: '1.2.3.0/24', count: 2, total: 3 })
    )
    expect(ElMessage.success).not.toHaveBeenCalled()
  })
})

describe('ForensicTraceView · request 被拒：按 errors.reason 给具体文案', () => {
  const refusal = (reason) =>
    Object.assign(new Error('refused'), {
      response: {
        status: 400,
        data: {
          success: false,
          message: '网段封禁被拒绝，请查看具体原因',
          errors: { errorCode: 'FORENSIC_POOL_BAN_REFUSED', reason },
        },
      },
    })

  const cases = [
    ['full_range_cidr', 'forensic.banRefusedFullRange'],
    ['whitelist_covers', 'forensic.banRefusedWhitelist'],
    ['operator_inside', 'forensic.banRefusedOperatorInside'],
    ['reason_required', 'forensic.banRefusedReasonRequired'],
    ['unparsable_cidr', 'forensic.banRefusedUnparsable'],
    ['unknown_token', 'forensic.banRefusedUnknownToken'],
    ['token_expired', 'forensic.banRefusedTokenExpired'],
  ]

  test.each(cases)('reason=%s → 展示 %s 的专属文案', async (reason, key) => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    requestBan.mockImplementation(() => Promise.reject(refusal(reason)))
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    const banBtn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banAction'))
    click(banBtn)
    await flush(10)
    const ta = c.find('.ban-summary textarea')
    ta.value = '理由'
    ta.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banConfirm'))
    click(btn)
    await flush(12)

    // 前提自证：词表里确实有这个键（缺键会回落成键名，下面的 toBe 会两边同时回落而恒真）
    expect(i18n.global.te(key)).toBe(true)
    const expected = i18n.global.t(key)
    // 文案必须落到**页面上**（toast 一闪而过，运维要能对着看）
    await waitFor(() => c.find('.ban-refusal') !== null, { message: '拒绝原因渲染到页面' })
    expect(c.find('.ban-refusal').textContent).toContain(expected)
    // 且不是笼统的「操作失败」
    expect(expected).not.toBe(i18n.global.t('forensic.banFailed'))
    // confirm 不得被调用（第一步就被拒了）
    expect(confirmBan).not.toHaveBeenCalled()
  })

  test('operator_inside 文案必须点明「你自己就在这个网段里」（不是泛化失败）', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    requestBan.mockImplementation(() => Promise.reject(refusal('operator_inside')))
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    const banBtn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banAction'))
    click(banBtn)
    await flush(10)
    const ta = c.find('.ban-summary textarea')
    ta.value = '理由'
    ta.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banConfirm'))
    click(btn)
    await flush(12)
    const text = c.find('.ban-refusal').textContent
    expect(text).toContain(i18n.global.t('forensic.banRefusedOperatorInside'))
  })

  test('未知 reason：如实带上原因码，不吞成笼统文案', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    requestBan.mockImplementation(() => Promise.reject(refusal('brand_new_reason')))
    const c = mountView()
    await flush(8)
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类一行' })
    const banBtn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banAction'))
    click(banBtn)
    await flush(10)
    const ta = c.find('.ban-summary textarea')
    ta.value = '理由'
    ta.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banConfirm'))
    click(btn)
    await flush(12)
    const text = c.find('.ban-refusal').textContent
    expect(text).toContain('brand_new_reason')
  })
})

describe('ForensicTraceView · 签名导出', () => {
  test('导出：把 data.pkg 存成 JSON 下载，成功提示带记录条数', async () => {
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
    const createObjectURL = vi.fn(() => 'blob:forensic')
    const revokeObjectURL = vi.fn()
    const realCreateURL = window.URL.createObjectURL
    const realRevokeURL = window.URL.revokeObjectURL
    window.URL.createObjectURL = createObjectURL
    window.URL.revokeObjectURL = revokeObjectURL
    try {
      const pkg = {
        v: 1,
        alg: 'HMAC-SHA256',
        keyId: 'k1',
        exportedAt: '2026-10-01T00:00:00.000Z',
        count: 2,
        digest: 'd',
        manifestRef: null,
        signature: 's',
        records: [tlRow(), tlRow({ seq: 'RUN-13' })],
      }
      exportForensic.mockImplementation(() =>
        Promise.resolve({ data: { success: true, data: { ok: true, pkg } } })
      )
      const c = mountView()
      await flush(8)
      await doTrace(c)
      const btn = c
        .findAll('.glass-btn')
        .find((b) => b.textContent.trim() === i18n.global.t('forensic.exportAction'))
      click(btn)
      await waitFor(() => exportForensic.mock.calls.length === 1, { message: '导出请求' })
      await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '导出成功' })

      expect(createObjectURL).toHaveBeenCalledTimes(1)
      const blob = createObjectURL.mock.calls[0][0]
      expect(blob).toBeInstanceOf(Blob)
      expect(created).toHaveLength(1)
      expect(created[0].href).toBe('blob:forensic')
      expect(created[0].download).toMatch(/^forensic_package_\d{4}-\d{2}-\d{2}\.json$/)
      expect(clickSpy).toHaveBeenCalledTimes(1)
      expect(ElMessage.success.mock.calls[0][0]).toBe(
        i18n.global.t('forensic.exportSuccess', { count: 2 })
      )
      expect(c.errors).toEqual([])
    } finally {
      createSpy.mockRestore()
      window.HTMLAnchorElement.prototype.click = realAnchorClick
      window.URL.createObjectURL = realCreateURL
      window.URL.revokeObjectURL = realRevokeURL
    }
  })

  test('导出无判据：前端拦住，不发导出请求', async () => {
    exportForensic.mockImplementation(() =>
      Promise.resolve({ data: { success: true, data: { ok: true, pkg: {} } } })
    )
    const c = mountView()
    await flush(8)
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.exportAction'))
    click(btn)
    await flush(10)
    expect(exportForensic).not.toHaveBeenCalled()
    expect(ElMessage.warning.mock.calls[0][0]).toBe(i18n.global.t('forensic.noCriteria'))
  })

  test('未配密钥（FORENSIC_EXPORT_NO_SECRET）：不下载、不提示成功', async () => {
    const createObjectURL = vi.fn(() => 'blob:x')
    const realCreateURL = window.URL.createObjectURL
    window.URL.createObjectURL = createObjectURL
    try {
      exportForensic.mockImplementation(() =>
        Promise.reject(
          Object.assign(new Error('no secret'), {
            response: {
              status: 400,
              data: {
                success: false,
                message: '服务端未配置取证导出密钥，请联系管理员',
                errors: { errorCode: 'FORENSIC_EXPORT_NO_SECRET' },
              },
            },
          })
        )
      )
      const c = mountView()
      await flush(8)
      await doTrace(c)
      const btn = c
        .findAll('.glass-btn')
        .find((b) => b.textContent.trim() === i18n.global.t('forensic.exportAction'))
      click(btn)
      await flush(12)
      expect(createObjectURL).not.toHaveBeenCalled()
      expect(ElMessage.success).not.toHaveBeenCalled()
    } finally {
      window.URL.createObjectURL = realCreateURL
    }
  })
})

describe('ForensicTraceView · 时间快捷范围', () => {
  test('点「近 30 天」再查询：since/until 按本地日期覆盖最近 30 天', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    const preset = c
      .findAll('.preset-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.range30d'))
    click(preset)
    await flush(4)
    setInput(c.findAll('.criteria-form .el-input__inner')[0], '1.2.3.4')
    await flush(4)
    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.search'))
    click(btn)
    await flush(10)

    const params = trace.mock.calls[0][0]
    const [since, until] = rangeOfHours(30 * 24)
    expect(params.since).toBe(new Date(`${since}T00:00:00`).toISOString())
    expect(params.until).toBe(new Date(`${until}T23:59:59.999`).toISOString())
  })

  test('预设只改时间范围，不会自己发查询（无判据时点预设也不该有请求）', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    const preset = c
      .findAll('.preset-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.rangeToday'))
    click(preset)
    await flush(8)
    expect(trace).not.toHaveBeenCalled()
  })
})

describe('ForensicTraceView · 一键钻取', () => {
  test('时间线点 IP：以该 IP 重新溯源，并清掉原来的指纹判据', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '', fingerprint: 'ab12cd' })
    await waitFor(() => rowsOf(c, 'forensic-timeline').length === 1, { message: '时间线渲染' })

    const pivot = rowsOf(c, 'forensic-timeline')[0].querySelector('.pivot-link')
    expect(pivot.textContent.trim()).toBe('1.2.3.4')
    click(pivot)
    await waitFor(() => trace.mock.calls.length === 2, { message: '钻取请求发出' })

    const params = trace.mock.calls[1][0]
    expect(params.ip).toBe('1.2.3.4')
    expect(params.fingerprint).toBeUndefined()
    expect(params.ipSegment).toBeUndefined()
    expect(c.findAll('.criteria-form .el-input__inner')[0].value).toBe('1.2.3.4')
  })

  test('网段分布点网段：以 ipSegment 重新溯源', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    await doTrace(c)
    await waitFor(() => c.find('.forensic-segment .pivot-link') !== null, { message: '网段行渲染' })

    click(c.find('.forensic-segment .pivot-link'))
    await waitFor(() => trace.mock.calls.length === 2, { message: '网段钻取请求发出' })
    const params = trace.mock.calls[1][0]
    expect(params.ipSegment).toBe('1.2.3')
    expect(params.ip).toBeUndefined()
    expect(params.fingerprint).toBeUndefined()
  })

  test('「他的 ip 池」点网段：同样可钻取', async () => {
    trace.mockImplementation(() =>
      Promise.resolve(
        traceBody({
          pools: [
            {
              segment: '1.2.3',
              hits: 12,
              distinctIps: 5,
              firstSeen: '2026-10-01T00:00:00.000Z',
              lastSeen: '2026-10-01T01:00:00.000Z',
            },
          ],
        })
      )
    )
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '', fingerprint: 'ab12cd' })
    await waitFor(() => c.find('.forensic-pool .pivot-link') !== null, { message: 'IP 池行渲染' })

    click(c.find('.forensic-pool .pivot-link'))
    await waitFor(() => trace.mock.calls.length === 2, { message: 'IP 池钻取请求发出' })
    expect(trace.mock.calls[1][0].ipSegment).toBe('1.2.3')
  })
})

describe('ForensicTraceView · 聚类先核实再封禁', () => {
  test('聚类行「查看记录」：按该网段溯源，并沿用聚类的实际时间窗', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类渲染' })

    const btn = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.viewRecords'))
    click(btn)
    await waitFor(() => trace.mock.calls.length === 1, { message: '聚类钻取请求发出' })

    const params = trace.mock.calls[0][0]
    expect(params.ipSegment).toBe('1.2.3')
    expect(params.ip).toBeUndefined()
    expect(params.fingerprint).toBeUndefined()
    const since = wallDate(new Date('2026-10-01T00:00:00.000Z'))
    const until = wallDate(new Date('2026-10-02T00:00:00.000Z'))
    expect(params.since).toBe(new Date(`${since}T00:00:00`).toISOString())
    expect(params.until).toBe(new Date(`${until}T23:59:59.999`).toISOString())
  })

  test('封禁确认框「先查看该段记录」：不拿票不落库，只按该段溯源', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类渲染' })
    await openBan(c)

    const review = c
      .findAll('.glass-btn')
      .find((b) => b.textContent.trim() === i18n.global.t('forensic.banReviewFirst'))
    click(review)
    await waitFor(() => trace.mock.calls.length === 1, { message: '核验请求发出' })

    expect(trace.mock.calls[0][0].ipSegment).toBe('1.2.3')
    expect(requestBan).not.toHaveBeenCalled()
    expect(confirmBan).not.toHaveBeenCalled()
  })

  test('查询在途时「查看记录 / 重置」不可点：不会出现「表单已换、结果还是上一份」', async () => {
    clusters.mockImplementation(() => Promise.resolve(clustersBody([clusterRow()])))
    let resolveTrace
    trace.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveTrace = resolve
        })
    )
    const c = mountView()
    await waitFor(() => rowsOf(c, 'forensic-clusters').length === 1, { message: '聚类渲染' })
    await doTrace(c)
    expect(trace).toHaveBeenCalledTimes(1)

    const byText = (text) =>
      c.findAll('.glass-btn').find((b) => b.textContent.trim() === i18n.global.t(text))
    expect(byText('forensic.viewRecords').disabled).toBe(true)
    expect(byText('forensic.reset').disabled).toBe(true)

    resolveTrace(traceBody())
    await flush(10)
  })
})

describe('ForensicTraceView · 深链与判据回显', () => {
  test('带 ?ip=&since=&until= 进入：预填判据并自动查询', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView(PERMS, '/forensic-trace?ip=203.0.113.10&since=2026-10-01&until=2026-10-02')
    await waitFor(() => trace.mock.calls.length === 1, { message: '深链自动查询' })

    const params = trace.mock.calls[0][0]
    expect(params.ip).toBe('203.0.113.10')
    expect(params.since).toBe(new Date('2026-10-01T00:00:00').toISOString())
    expect(params.until).toBe(new Date('2026-10-02T23:59:59.999').toISOString())
    expect(c.findAll('.criteria-form .el-input__inner')[0].value).toBe('203.0.113.10')
  })

  test('深链只有时间没有判据：不自动发查询（避免把全表当溯源）', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    mountView(PERMS, '/forensic-trace?since=2026-10-01&until=2026-10-02')
    await flush(10)
    expect(trace).not.toHaveBeenCalled()
  })

  test('深链 limit 是整串十进制整数才生效（对照：50 生效）', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    mountView(PERMS, '/forensic-trace?ip=203.0.113.10&limit=50')
    await waitFor(() => trace.mock.calls.length === 1, { message: '深链自动查询' })
    expect(trace.mock.calls[0][0].limit).toBe(50)
  })

  test('深链 limit 带尾随字符（999abc）：不静默当 999，回退默认 200', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    mountView(PERMS, '/forensic-trace?ip=203.0.113.10&limit=999abc')
    await waitFor(() => trace.mock.calls.length === 1, { message: '深链自动查询' })
    expect(trace.mock.calls[0][0].limit).toBe(200)
  })

  test('工作台内切 tab（URL 已无判据）：不拿表单里的旧判据重查', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView(PERMS, '/forensic-trace?ip=203.0.113.10')
    await waitFor(() => trace.mock.calls.length === 1, { message: '深链自动查询' })

    await c.router.push('/forensic-trace?tab=attack')
    await flush(10)
    // 判据仍在表单里，但 URL 没有——自动查询只认 URL，切 tab 不应打第二次
    expect(trace).toHaveBeenCalledTimes(1)
  })

  test('判据回显用发起查询时的快照：改表单未重查时，结果与判据不会对不上', async () => {
    trace.mockImplementation(() => Promise.resolve(traceBody()))
    const c = mountView()
    await flush(8)
    await doTrace(c, { ip: '1.2.3.4', fingerprint: '' })
    await waitFor(() => c.find('.criteria-echo') !== null, { message: '判据回显渲染' })
    expect(c.find('.criteria-echo').textContent).toContain('1.2.3.4')

    setInput(c.findAll('.criteria-form .el-input__inner')[0], '9.9.9.9')
    await flush(4)
    expect(c.find('.criteria-echo').textContent).toContain('1.2.3.4')
    expect(c.find('.criteria-echo').textContent).not.toContain('9.9.9.9')
  })

  test('复制查询链接：地址里带当前判据与时间范围', async () => {
    const writeText = vi.fn(() => Promise.resolve())
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    try {
      const c = mountView()
      await flush(8)
      setInput(c.findAll('.criteria-form .el-input__inner')[0], '1.2.3.4')
      await flush(4)
      const btn = c
        .findAll('.glass-btn')
        .find((b) => b.textContent.trim() === i18n.global.t('forensic.copyLink'))
      click(btn)
      await waitFor(() => writeText.mock.calls.length === 1, { message: '链接写入剪贴板' })

      const url = new URL(writeText.mock.calls[0][0])
      expect(url.origin).toBe(window.location.origin)
      expect(url.pathname).toContain('security-analysis')
      expect(url.searchParams.get('tab')).toBe('forensic')
      expect(url.searchParams.get('ip')).toBe('1.2.3.4')
      const [since, until] = rangeOfHours(7 * 24)
      expect(url.searchParams.get('since')).toBe(since)
      expect(url.searchParams.get('until')).toBe(until)
    } finally {
      delete navigator.clipboard
    }
  })
})

// 视图里每个 $t(中文键) 调用都必须在两套 locale 里真实存在。
// 缺陷来源：daterange 的 $t('common.startDate') 两个键从未在任何 locale 注册过，
// 而 vitest 全程绿、intlify 只在 stderr 刷 missing-key 告警 —— 用户看到的是原始键名。
// 所以这条闸不看渲染结果（fallback 会让渲染断言通过），只解析真实模块看键在不在。
describe('ForensicTraceView · i18n 键必须真实存在', () => {
  const resolve = (obj, dotted) =>
    dotted.split('.').reduce((acc, k) => (acc && typeof acc === 'object' ? acc[k] : undefined), obj)

  const usedKeys = () => {
    const src = fs.readFileSync(
      path.resolve(__dirname, '../../views/ForensicTraceView.vue'),
      'utf8'
    )
    const keys = new Set()
    for (const m of src.matchAll(/\$t\(\s*'([^']+)'/g)) keys.add(m[1])
    for (const m of src.matchAll(/\bt\(\s*'([^']+)'/g)) keys.add(m[1])
    return keys
  }

  test('两套 locale 都能解析视图用到的每一个键（zh / en 都要，不能只覆盖一侧）', async () => {
    const zhMod = await import('@/i18n/locales/zh-CN.js')
    const enMod = await import('@/i18n/locales/en-US.js')
    const zh = zhMod.default || zhMod
    const en = enMod.default || enMod
    const used = usedKeys()
    expect(used.size).toBeGreaterThan(50)
    expect([...used].filter((k) => typeof resolve(zh, k) !== 'string')).toEqual([])
    expect([...used].filter((k) => typeof resolve(en, k) !== 'string')).toEqual([])
  })

  test('判据有牙：不存在的键必须解析为 undefined，存在的键必须解析出字符串', async () => {
    const zhMod = await import('@/i18n/locales/zh-CN.js')
    const zh = zhMod.default || zhMod
    expect(resolve(zh, 'common.startDate')).toBeUndefined()
    expect(typeof resolve(zh, 'report.startDate')).toBe('string')
  })
})
