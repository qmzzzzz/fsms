/**
 * IpListView 组件级行为测试（2026-09-18）
 *
 * 覆盖行为面：名单列表加载与渲染（时间列本地时区口径、原因码映射、类型/来源标签、
 * 主命中标记、三种空态文案）、黑白名单切换、分页、IP 命中查询（校验/判定标签/
 * 归一化展示/按名单过滤/自动切换到命中名单/查询模式下的刷新与删除回流）、
 * 新增（载荷与白名单默认原因/时长）、移除（确认/取消/失败）。
 *
 * 注意：IpListView 的按钮**不加 hasPerm 门控**是已判定的非缺陷（路由 meta 已覆盖，
 * 见 roleViewPermission.test.js 的显式断言），本文件不为其写「应有门控」的测试。
 *
 * 期望值一律在本文件内独立计算（Date 本地 getter 补零），不 import @/utils/datetime，
 * 否则实现写错时两边一起错、断言恒真。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const get = vi.fn()
const post = vi.fn()
const del = vi.fn()
const confirm = vi.fn()
vi.mock('@/utils/api', () => ({
  apiClient: {
    get: (...a) => get(...a),
    post: (...a) => post(...a),
    delete: (...a) => del(...a),
  },
  isCanceledError: (e) => Boolean(e && e.code === 'ERR_CANCELED'),
  resolveErrorMessage: () => '码化文案',
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: (...a) => confirm(...a) },
}))

import IpListView from '@/views/IpListView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

const ipRow = (over = {}) => ({
  _id: 'ip1',
  ip: '10.0.0.1',
  type: 'black',
  source: 'manual',
  reason: '',
  expiresAt: null,
  createdAt: null,
  ...over,
})

const listBody = (list, opts = {}) => ({
  data: {
    data: {
      list,
      pagination: { total: opts.total === undefined ? list.length : opts.total },
      counts: {
        black: opts.black === undefined ? list.length : opts.black,
        white: opts.white === undefined ? 0 : opts.white,
      },
    },
  },
})

const queryBody = (over = {}) => ({
  data: {
    data: {
      ip: '10.0.0.5',
      normalizedIP: '10.0.0.5',
      verdict: 'allowed',
      blackMatches: [],
      whiteMatches: [],
      ...over,
    },
  },
})

const listCalls = () => get.mock.calls.filter((c) => c[0] === '/security/ip-list')
const listParams = () => listCalls()[listCalls().length - 1][1].params
const queryCalls = () => get.mock.calls.filter((c) => c[0] === '/security/ip-list/query')
const trs = (c) => c.findAll('.el-table__body-wrapper .el-table__row')
const td = (c, r, col) => Array.from(trs(c)[r].querySelectorAll('td'))[col]

/** 独立计算本地时区的「YYYY-MM-DD HH:mm:ss」（不调用被测实现） */
const localWall = (iso) => {
  const d = new Date(iso)
  const p = (n) => String(n).padStart(2, '0')
  return (
    [d.getFullYear(), p(d.getMonth() + 1), p(d.getDate())].join('-') +
    ' ' +
    [p(d.getHours()), p(d.getMinutes()), p(d.getSeconds())].join(':')
  )
}

/**
 * 打开 el-select 并点选指定文案的选项。
 * 用 aria-controls 精确关联该 select 自己的 listbox：页面同时存在多个 select
 * 且 popper 惰性创建，全局查找会点到别的下拉项，测试变成碰运气。
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

/** 挂载并等待首屏列表落地（get 需已配置好 /security/ip-list 的响应） */
const boot = async (expectedRows) => {
  active = mountComponent(IpListView, {})
  await waitFor(() => listCalls().length >= 1, { message: '名单列表请求已发出' })
  if (expectedRows !== undefined) {
    await waitFor(() => trs(active).length === expectedRows, { message: '名单行渲染完成' })
  }
  await flush(3)
  return active
}

/** 配置 /security/ip-list 的响应并挂载 */
const openList = async (list, opts = {}) => {
  get.mockImplementation((url) =>
    url === '/security/ip-list'
      ? Promise.resolve(listBody(list, opts))
      : Promise.reject(new Error('unexpected url: ' + url))
  )
  return boot(list.length)
}

/** 填入查询框并点「IP 命中查询」 */
const doQuery = async (c, ip) => {
  const input = c.find('.query-bar input')
  input.value = ip
  input.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(4)
  click(c.find('.query-bar button'))
  await flush(10)
}

const addIpBtn = (c) =>
  Array.from(c.find('.add-form').querySelectorAll('button')).find(
    (b) => b.textContent.includes('加入黑名单') || b.textContent.includes('加入白名单')
  )

/** 在新增表单填入 IP（并可选填原因） */
const fillAdd = async (c, ip, reason) => {
  const inputs = c.find('.add-form').querySelectorAll('input')
  inputs[0].value = ip
  inputs[0].dispatchEvent(new window.Event('input', { bubbles: true }))
  if (reason !== undefined) {
    const reasonInput = Array.from(inputs).find(
      (i) => i.placeholder && i.placeholder.includes('选填')
    )
    expect(reasonInput).toBeTruthy()
    reasonInput.value = reason
    reasonInput.dispatchEvent(new window.Event('input', { bubbles: true }))
  }
  await flush(4)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  get.mockReset()
  post.mockReset()
  del.mockReset()
  confirm.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
})

describe('IpListView 列表加载与渲染', () => {
  test('挂载即按黑名单第 1 页请求：行数据、分段计数、总数与无障碍标签正确', async () => {
    const c = await openList([ipRow({ ip: '10.1.2.3' })], { total: 42, black: 30, white: 12 })
    expect(listCalls()).toHaveLength(1)
    expect(listParams()).toEqual({ type: 'black', page: 1, limit: 20 })
    expect(td(c, 0, 0).textContent.trim()).toBe('10.1.2.3')
    expect(c.findAll('.glass-segmented__item').map((b) => b.textContent.trim())).toEqual([
      '30 黑名单',
      '12 白名单',
    ])
    expect(c.find('.glass-segmented').getAttribute('aria-label')).toBe('名单类型切换')
    expect(c.find('.el-pagination__total').textContent.replace(/[^0-9]/g, '')).toBe('42')
    expect(c.errors).toEqual([])
  })

  test('归属地：有 location 时「IP · 归属地」，无 location 只渲染 IP（P2-4）', async () => {
    // 归属地是后端可选增强（CIDR 网段/检索不可用时缺字段），模板必须省略而非渲染空串。
    // 此前零断言：退化成空串或字面 "undefined" 都不会有任何用例变红。
    const c = await openList([
      ipRow({ _id: 'ip1', ip: '10.0.0.1', location: '北京市' }),
      ipRow({ _id: 'ip2', ip: '10.0.0.2', location: null }),
    ])

    const withLoc = td(c, 0, 0).textContent.trim()
    expect(withLoc).toBe('10.0.0.1 · 北京市')
    expect(td(c, 0, 0).querySelector('.ip-location')).not.toBeNull()

    const noLoc = td(c, 1, 0).textContent.trim()
    expect(noLoc).toBe('10.0.0.2')
    expect(noLoc).not.toContain('·')
    expect(noLoc).not.toContain('undefined')
    expect(td(c, 1, 0).querySelector('.ip-location')).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('时间列本地时区口径：生效时间与创建时间都不是 ISO 原串', async () => {
    const expires = '2026-10-01T01:00:00.000Z'
    const created = '2026-09-01T23:30:15.000Z'
    const c = await openList([ipRow({ expiresAt: expires, createdAt: created })])
    const expireCell = td(c, 0, 4).textContent.trim()
    const createdCell = td(c, 0, 5).textContent.trim()
    expect(expireCell).toBe('至 ' + localWall(expires))
    expect(createdCell).toBe(localWall(created))
    for (const cell of [expireCell, createdCell]) {
      expect(cell).not.toContain('T')
      expect(cell).not.toContain('Z')
    }
    expect(localWall(expires)).not.toBe(expires)
    // 前提自检：本用例时区下本地时分秒与 UTC 不同，否则「等于本地」可能恒真
    const d = new Date(expires)
    expect([d.getHours(), d.getMinutes(), d.getSeconds()]).not.toEqual([
      d.getUTCHours(),
      d.getUTCMinutes(),
      d.getUTCSeconds(),
    ])
  })

  test('expiresAt 为空渲染「永久」，createdAt 为空渲染 -（不得落成 1970）', async () => {
    const c = await openList([ipRow({ expiresAt: null, createdAt: null })])
    expect(td(c, 0, 4).textContent.trim()).toBe('永久')
    expect(td(c, 0, 5).textContent.trim()).toBe('-')
  })

  test('原因码映射为可读文案，未知码回退原文，空值为 -', async () => {
    const c = await openList([
      ipRow({ _id: 'a', reason: 'security_policy' }),
      ipRow({ _id: 'b', reason: 'brute_force_auto_ban' }),
      ipRow({ _id: 'c', reason: 'manual_configuration' }),
      ipRow({ _id: 'd', reason: 'trusted_source' }),
      ipRow({ _id: 'e', reason: 'zzz_custom_code' }),
      ipRow({ _id: 'f', reason: '' }),
      // 后端渐进式封禁实际写入的带层级码（securityAlert.js ESCALATION_TIERS）——裸键从不出现在生产
      ipRow({ _id: 'g', reason: 'brute_force_auto_ban_tier1' }),
      ipRow({ _id: 'h', reason: 'brute_force_auto_ban_tier4' }),
      // 管理员自由文本可命中 Object.prototype：必须按原文回退，不能渲染出函数源码
      ipRow({ _id: 'i', reason: 'toString' }),
    ])
    const reasons = [0, 1, 2, 3, 4, 5, 6, 7, 8].map((r) => td(c, r, 3).textContent.trim())
    expect(reasons).toEqual([
      '安全策略',
      '暴力破解自动封禁',
      '手动配置',
      '可信来源',
      'zzz_custom_code',
      '-',
      '暴力破解自动封禁',
      '暴力破解自动封禁',
      'toString',
    ])
  })

  test('类型/来源标签：black/white 与 auto/manual 各自映射且色板不同', async () => {
    const c = await openList([
      ipRow({ _id: 'a', type: 'black', source: 'manual' }),
      ipRow({ _id: 'b', type: 'white', source: 'auto' }),
    ])
    const typeTag = (r) => td(c, r, 1).querySelector('.el-tag')
    const srcTag = (r) => td(c, r, 2).querySelector('.el-tag')
    expect(typeTag(0).textContent.trim()).toBe('黑名单')
    expect(typeTag(0).classList.contains('el-tag--danger')).toBe(true)
    expect(typeTag(1).textContent.trim()).toBe('白名单')
    expect(typeTag(1).classList.contains('el-tag--success')).toBe(true)
    expect(srcTag(0).textContent.trim()).toBe('手动配置')
    expect(srcTag(1).textContent.trim()).toBe('自动检测')
    expect(srcTag(1).classList.contains('el-tag--warning')).toBe(true)
    expect(srcTag(0).classList.contains('el-tag--info')).toBe(true)
  })

  test('空列表按当前名单类型显示各自空态文案（黑白不得互换）', async () => {
    const c = await openList([])
    await waitFor(() => c.find('.empty-tip') !== null, { message: '黑名单空态' })
    expect(c.find('.empty-tip').textContent.trim()).toBe('暂无黑名单记录')
    get.mockImplementation(() => Promise.resolve(listBody([], { total: 0, black: 0, white: 0 })))
    click(c.findAll('.glass-segmented__item')[1])
    await waitFor(
      () =>
        c.find('.empty-tip') !== null &&
        c.find('.empty-tip').textContent.trim() === '暂无白名单记录',
      { message: '白名单空态' }
    )
    expect(c.find('.empty-tip').textContent.trim()).toBe('暂无白名单记录')
  })

  test('列表加载失败：提示「加载失败」、清空列表与总数并显示空态', async () => {
    let n = 0
    get.mockImplementation(() => {
      n += 1
      return n === 1
        ? Promise.resolve(listBody([ipRow()], { total: 42, black: 30, white: 12 }))
        : Promise.reject(new Error('down'))
    })
    const c = await boot(1)
    click(
      Array.from(c.findAll('.table-toolbar button')).find((b) => b.textContent.trim() === '刷新')
    )
    // 契约对齐 alarmView：加载失败由 api.js 响应拦截器统一提示，组件只清态。
    // 原断言把组件那条 error 钉成契约（`calls.length === 1`），于是双提示被锁死。
    await waitFor(() => trs(c).length === 0, { message: '失败后列表清空' })
    await flush(6)
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(trs(c)).toHaveLength(0)
    expect(c.find('.empty-tip').textContent.trim()).toBe('暂无黑名单记录')
    expect(c.find('.el-pagination__total').textContent.replace(/[^0-9]/g, '')).toBe('0')
    expect(c.errors).toEqual([])
  })

  test('路由 abort 的在途请求：静默失败不弹错误（FE-L1）', async () => {
    get.mockRejectedValue(Object.assign(new Error('canceled'), { code: 'ERR_CANCELED' }))
    const c = await boot()
    await flush(20)
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('竞态守卫：慢的旧名单响应不得覆盖新名单结果（含总数）', async () => {
    const pending = []
    get.mockImplementation(() => new Promise((resolve) => pending.push(resolve)))
    const c = await boot()
    await waitFor(() => pending.length === 1, { message: '黑名单请求在途' })
    click(c.findAll('.glass-segmented__item')[1])
    await waitFor(() => pending.length === 2, { message: '白名单请求在途' })
    expect(listParams()).toEqual({ type: 'white', page: 1, limit: 20 })
    pending[1](listBody([ipRow({ _id: 'w1', ip: '10.0.0.9', type: 'white' })], { total: 1 }))
    await waitFor(() => trs(c).length === 1, { message: '白名单结果落地' })
    pending[0](listBody([ipRow({ _id: 'b1', ip: '10.0.0.1' })], { total: 99 }))
    await flush(30)
    expect(td(c, 0, 0).textContent.trim()).toBe('10.0.0.9')
    expect(c.find('.el-pagination__total').textContent.replace(/[^0-9]/g, '')).toBe('1')
  })
})

describe('IpListView 名单切换与分页', () => {
  test('切换白名单：携带 type=white、回到第 1 页并切换描述文案', async () => {
    const c = await openList([ipRow()], { total: 40 })
    click(c.find('.btn-next'))
    await waitFor(() => listParams().page === 2, { message: '先翻到第 2 页' })
    expect(c.find('.list-desc').textContent).toContain('黑名单 IP 将被系统直接拦截')
    click(c.findAll('.glass-segmented__item')[1])
    await waitFor(() => listParams().type === 'white', { message: '白名单请求' })
    expect(listParams()).toEqual({ type: 'white', page: 1, limit: 20 })
    expect(c.find('.list-desc').textContent).toContain('白名单 IP 豁免黑名单拦截')
  })

  test('翻页：page 递增', async () => {
    const c = await openList([ipRow()], { total: 45 })
    click(c.find('.btn-next'))
    await waitFor(() => listParams().page === 2, { message: '第 2 页请求' })
    expect(listParams()).toEqual({ type: 'black', page: 2, limit: 20 })
  })

  test('每页条数改 50：limit 更新且回到第 1 页', async () => {
    const c = await openList([ipRow()], { total: 120 })
    click(c.find('.btn-next'))
    await waitFor(() => listParams().page === 2, { message: '先翻到第 2 页' })
    await pickOption(c.findAll('.el-pagination .el-select__wrapper')[0], '50/page')
    await waitFor(() => listParams().limit === 50, { message: '每页 50 请求' })
    expect(listParams()).toEqual({ type: 'black', page: 1, limit: 50 })
  })
})

describe('IpListView IP 命中查询', () => {
  test('空输入与非法规格（越界 IPv4）各自警告且都不发查询请求', async () => {
    const c = await openList([ipRow()])
    click(c.find('.query-bar button'))
    await flush(8)
    expect(ElMessage.warning).toHaveBeenCalledWith('请输入 IP 地址')
    await doQuery(c, '999.1.1.1')
    expect(ElMessage.warning).toHaveBeenCalledWith('IP 或网段格式不正确')
    expect(queryCalls()).toHaveLength(0)
    expect(c.errors).toEqual([])
  })

  test('合法 IP 查询：参数为输入 IP，命中黑名单时展示判定标签与模式标签', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([], { total: 0 }))
      if (url === '/security/ip-list/query') {
        return Promise.resolve(
          queryBody({
            ip: '10.0.0.5',
            normalizedIP: '10.0.0.0/24',
            verdict: 'blocked',
            blackMatches: [ipRow({ _id: 'm1', ip: '10.0.0.0/24', reason: 'security_policy' })],
          })
        )
      }
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(0)
    await doQuery(c, '10.0.0.5')
    expect(queryCalls()).toHaveLength(1)
    expect(queryCalls()[0][1]).toEqual({ params: { ip: '10.0.0.5' } })
    await waitFor(() => c.find('.query-mode-label') !== null, { message: '进入查询模式' })
    const tag = c.find('.query-bar .el-tag')
    expect(tag.textContent.trim()).toBe('将被拦截（黑名单命中）')
    expect(tag.classList.contains('el-tag--danger')).toBe(true)
    expect(c.find('.query-mode-label').textContent.trim()).toBe('查询结果：10.0.0.5')
    // 归一化结果与输入不同才展示
    expect(c.find('.query-verdict-normalized').textContent.trim()).toBe('→ 10.0.0.0/24')
    expect(trs(c)).toHaveLength(1)
    // 单条命中即组内首条，会带「最宽命中」标记（与后端 primaryBlack 口径一致）
    expect(td(c, 0, 0).textContent.trim()).toBe('10.0.0.0/24最宽命中')
    expect(c.find('.pagination')).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('归一化结果与输入相同时不渲染归一化行', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([], { total: 0 }))
      if (url === '/security/ip-list/query') {
        return Promise.resolve(
          queryBody({
            ip: '10.0.0.5',
            normalizedIP: '10.0.0.5',
            verdict: 'blocked',
            blackMatches: [ipRow({ _id: 'm1', ip: '10.0.0.5' })],
          })
        )
      }
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(0)
    await doQuery(c, '10.0.0.5')
    await waitFor(() => c.findAll('.el-table__body-wrapper .el-table__row').length === 1, {
      message: '查询结果行',
    })
    expect(c.find('.query-verdict-normalized')).toBeNull()
  })

  test('查询结果按当前名单过滤：黑名单两条只显示两条，主命中仅给组内首条打标', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([], { total: 0 }))
      if (url === '/security/ip-list/query') {
        return Promise.resolve(
          queryBody({
            verdict: 'blocked',
            blackMatches: [
              ipRow({ _id: 'm1', ip: '10.0.0.0/16' }),
              ipRow({ _id: 'm2', ip: '10.0.0.0/24' }),
            ],
            whiteMatches: [ipRow({ _id: 'w1', ip: '10.0.0.0/8', type: 'white' })],
          })
        )
      }
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(0)
    await doQuery(c, '10.0.0.5')
    await waitFor(() => trs(c).length === 2, { message: '黑名单命中两行' })
    expect(trs(c).map((tr) => tr.querySelectorAll('td')[0].textContent.trim())).toEqual([
      '10.0.0.0/16最宽命中',
      '10.0.0.0/24',
    ])
    // 切到白名单：行集合随之变化（computed 响应），主命中标记归白名单首条
    click(c.findAll('.glass-segmented__item')[1])
    await waitFor(() => trs(c).length === 1, { message: '白名单命中一行' })
    expect(td(c, 0, 0).textContent.trim()).toBe('10.0.0.0/8最宽命中')
    expect(queryCalls()).toHaveLength(1)
  })

  test('白名单多命中时也只给组内首条打「最宽命中」标记（与黑名单同口径）', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([], { total: 0 }))
      if (url === '/security/ip-list/query') {
        return Promise.resolve(
          queryBody({
            ip: '10.0.0.5',
            normalizedIP: '10.0.0.5',
            verdict: 'whitelisted',
            whiteMatches: [
              ipRow({ _id: 'w1', ip: '10.0.0.0/8', type: 'white' }),
              ipRow({ _id: 'w2', ip: '10.0.0.0/16', type: 'white' }),
            ],
          })
        )
      }
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(0)
    await doQuery(c, '10.0.0.5')
    await waitFor(() => trs(c).length === 2, { message: '白名单命中两行' })
    expect(trs(c).map((tr) => tr.querySelectorAll('td')[0].textContent.trim())).toEqual([
      '10.0.0.0/8最宽命中',
      '10.0.0.0/16',
    ])
    expect(trs(c)[0].querySelectorAll('td')[0].querySelectorAll('.primary-tag')).toHaveLength(1)
    expect(trs(c)[1].querySelectorAll('td')[0].querySelectorAll('.primary-tag')).toHaveLength(0)
  })

  test('仅白名单命中时自动切到白名单视图，避免表格误显示空态', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([], { total: 0 }))
      if (url === '/security/ip-list/query') {
        return Promise.resolve(
          queryBody({
            ip: '10.0.0.5',
            normalizedIP: '10.0.0.5',
            verdict: 'whitelisted',
            whiteMatches: [ipRow({ _id: 'w1', ip: '10.0.0.5', type: 'white' })],
          })
        )
      }
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(0)
    await doQuery(c, '10.0.0.5')
    await waitFor(() => trs(c).length === 1, { message: '白名单命中行' })
    const seg = c.findAll('.glass-segmented__item')
    expect(seg[0].classList.contains('is-active')).toBe(false)
    expect(seg[1].classList.contains('is-active')).toBe(true)
    expect(seg.map((b) => b.textContent.trim())).toEqual(['0 黑名单', '1 白名单'])
    const tag = c.find('.query-bar .el-tag')
    expect(tag.textContent.trim()).toBe('白名单放行')
    expect(tag.classList.contains('el-tag--success')).toBe(true)
    expect(c.find('.empty-tip')).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('完全未命中：判定为「未命中任何名单」，显示空态文案且无分页', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([], { total: 0 }))
      if (url === '/security/ip-list/query') return Promise.resolve(queryBody())
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(0)
    await doQuery(c, '10.0.0.5')
    await waitFor(() => c.find('.query-mode-label') !== null, { message: '进入查询模式' })
    const tag = c.find('.query-bar .el-tag')
    expect(tag.textContent.trim()).toBe('未命中任何名单')
    expect(tag.classList.contains('el-tag--info')).toBe(true)
    expect(trs(c)).toHaveLength(0)
    expect(c.find('.empty-tip').textContent.trim()).toBe('未命中任何名单记录')
    expect(c.find('.pagination')).toBeNull()
  })

  test('查询模式下点「刷新」：退出查询模式、清空输入并重新拉取名单列表', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([ipRow()], { total: 3 }))
      if (url === '/security/ip-list/query') {
        return Promise.resolve(
          queryBody({
            verdict: 'blocked',
            blackMatches: [ipRow({ _id: 'm1', ip: '10.0.0.5' })],
          })
        )
      }
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(1)
    await doQuery(c, '10.0.0.5')
    await waitFor(() => c.find('.query-mode-label') !== null, { message: '进入查询模式' })
    expect(c.find('.pagination')).toBeNull()
    const before = listCalls().length
    click(c.find('.table-toolbar .glass-btn--default'))
    await waitFor(() => listCalls().length === before + 1, { message: '重新拉取名单列表' })
    expect(c.find('.query-mode-label')).toBeNull()
    expect(c.find('.query-bar input').value).toBe('')
    expect(c.find('.pagination')).not.toBeNull()
    expect(listParams()).toEqual({ type: 'black', page: 1, limit: 20 })
    expect(c.errors).toEqual([])
  })

  test('查询失败：退出查询模式并回到名单列表视图，不残留半开的查询态', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([ipRow()], { total: 1 }))
      if (url === '/security/ip-list/query') return Promise.reject(new Error('query down'))
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    const c = await boot(1)
    await doQuery(c, '10.0.0.5')
    expect(queryCalls()).toHaveLength(1)
    await waitFor(() => c.find('.query-mode-label') === null, { message: '退出查询模式' })
    expect(c.find('.pagination')).not.toBeNull()
    expect(trs(c)).toHaveLength(1)
    expect(td(c, 0, 0).textContent.trim()).toBe('10.0.0.1')
    expect(c.errors).toEqual([])
  })
})

describe('IpListView 新增名单条目', () => {
  test('空输入与非法输入各自警告且都不发 POST', async () => {
    const c = await openList([ipRow()])
    click(addIpBtn(c))
    await flush(8)
    expect(ElMessage.warning).toHaveBeenCalledWith('请输入 IP 地址')
    await fillAdd(c, '10.1.1.1/99')
    click(addIpBtn(c))
    await flush(8)
    expect(ElMessage.warning).toHaveBeenCalledWith('IP 或网段格式不正确')
    expect(post).not.toHaveBeenCalled()
  })

  test('黑名单新增：载荷为 IP/type/reason/时长，成功后清空表单、回第 1 页并重载', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([ipRow()], { total: 60 })))
    post.mockResolvedValue({ data: {} })
    const c = await boot(1)
    click(c.find('.btn-next'))
    await waitFor(() => listParams().page === 2, { message: '先翻到第 2 页' })
    await fillAdd(c, '10.9.9.9', '运维出口')
    await pickOption(c.find('.add-form .el-select__wrapper'), '24 小时')
    click(addIpBtn(c))
    await waitFor(() => post.mock.calls.length === 1, { message: '新增请求' })
    expect(post.mock.calls[0][0]).toBe('/security/ip-list')
    expect(post.mock.calls[0][1]).toEqual({
      ip: '10.9.9.9',
      type: 'black',
      reason: '运维出口',
      durationHours: 24,
    })
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('已将 10.9.9.9 黑名单')
    await waitFor(() => listParams().page === 1 && listCalls().length >= 3, {
      message: '回第 1 页重载',
    })
    expect(listParams()).toEqual({ type: 'black', page: 1, limit: 20 })
    const inputs = c.find('.add-form').querySelectorAll('input')
    expect(inputs[0].value).toBe('')
    expect(inputs[2].value).toBe('')
    expect(c.errors).toEqual([])
  })

  test('格式校验边界：合法 CIDR/IPv6 放行，前缀越界/含空格/越界 IPv4 段拒绝', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([], { total: 0 })))
    post.mockResolvedValue({ data: {} })
    const c = await boot(0)
    // 合法：IPv4 CIDR、IPv6 单地址、IPv6 CIDR（前缀 ≤128）、首尾空白（提交前 trim 归一）
    for (const ip of ['10.0.0.0/24', '2001:db8::1', 'fe80::1/64', '10.0.0.1 ']) {
      await fillAdd(c, ip)
      const expected = post.mock.calls.length + 1
      click(addIpBtn(c))
      await waitFor(() => post.mock.calls.length === expected, {
        message: '合法输入应发出新增请求: ' + ip,
      })
      expect(post.mock.calls[post.mock.calls.length - 1][1].ip).toBe(ip.trim())
    }
    // 非法：IPv4 前缀 33、IPv6 前缀 129、内部空格、某段 256、非法主机名
    const accepted = post.mock.calls.length
    for (const ip of ['10.0.0.0/33', 'fe80::1/129', '1.1.1.1 2.2.2.2', '10.0.0.256', 'not-an-ip']) {
      await fillAdd(c, ip)
      click(addIpBtn(c))
      await flush(8)
    }
    expect(post.mock.calls.length).toBe(accepted)
    expect(ElMessage.warning.mock.calls.map((x) => x[0])).toEqual([
      'IP 或网段格式不正确',
      'IP 或网段格式不正确',
      'IP 或网段格式不正确',
      'IP 或网段格式不正确',
      'IP 或网段格式不正确',
    ])
  })

  test('白名单新增：type=white、默认原因为可信来源、未选时长按 0 提交', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([], { total: 0 })))
    post.mockResolvedValue({ data: {} })
    const c = await boot(0)
    click(c.findAll('.glass-segmented__item')[1])
    await waitFor(() => listParams().type === 'white', { message: '切到白名单' })
    expect(addIpBtn(c).textContent.trim()).toBe('加入白名单')
    await fillAdd(c, '10.7.7.7')
    click(addIpBtn(c))
    await waitFor(() => post.mock.calls.length === 1, { message: '新增请求' })
    expect(post.mock.calls[0][1]).toEqual({
      ip: '10.7.7.7',
      type: 'white',
      reason: 'trusted_source',
      durationHours: 0,
    })
    expect(ElMessage.success).toHaveBeenCalledWith('已将 10.7.7.7 白名单')
  })

  test('同一 tick 连点「加入黑名单」三次：只发一个 POST（重入锁）', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([ipRow()], { total: 1 })))
    // 挂起响应，制造「请求在途」窗口；若实现无同步重入锁，三次连点都会穿过去
    let release
    post.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ data: {} })
        })
    )
    const c = await boot(1)
    await fillAdd(c, '10.9.9.9')
    const btn = addIpBtn(c)
    click(btn)
    click(btn)
    click(btn)
    await flush(6)
    expect(post).toHaveBeenCalledTimes(1)
    release()
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    expect(post).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('新增请求在途时按钮禁用，且响应到达后可再次提交', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([ipRow()], { total: 1 })))
    let release
    post.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ data: {} })
        })
    )
    const c = await boot(1)
    await fillAdd(c, '10.9.9.9')
    const btn = addIpBtn(c)
    click(btn)
    await waitFor(() => post.mock.calls.length === 1, { message: '新增请求发出' })
    await waitFor(() => btn.disabled === true, { message: '在途期间按钮禁用' })
    release()
    await waitFor(() => btn.disabled === false, { message: '响应后按钮恢复' })
    await fillAdd(c, '10.9.9.10')
    click(btn)
    await waitFor(() => post.mock.calls.length === 2, { message: '可以再次提交' })
    expect(post.mock.calls[1][1].ip).toBe('10.9.9.10')
    expect(c.errors).toEqual([])
  })
  test('新增失败：按钮恢复可用、输入保留待重试、不报成功', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([], { total: 0 })))
    post.mockRejectedValue(new Error('add down'))
    const c = await boot(0)
    await fillAdd(c, '10.5.5.5')
    const btn = addIpBtn(c)
    click(btn)
    await waitFor(() => post.mock.calls.length === 1, { message: '新增请求' })
    await waitFor(() => btn.disabled === false, { message: '失败后按钮解锁' })
    expect(btn.textContent.trim()).toBe('加入黑名单')
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.find('.add-form').querySelectorAll('input')[0].value).toBe('10.5.5.5')
    expect(c.errors).toEqual([])
  })
})

describe('IpListView 查询重入防护', () => {
  test('同一 tick 连点「IP 命中查询」三次：只发一个查询请求', async () => {
    let release
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([ipRow()], { total: 1 }))
      return new Promise((resolve) => {
        release = () => resolve(queryBody())
      })
    })
    const c = await boot(1)
    const input = c.find('.query-bar input')
    input.value = '10.0.0.5'
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    const btn = c.find('.query-bar button')
    click(btn)
    click(btn)
    click(btn)
    await flush(6)
    expect(queryCalls()).toHaveLength(1)
    release()
    await flush(10)
    expect(queryCalls()).toHaveLength(1)
    expect(c.errors).toEqual([])
  })

  test('查询失败后重入锁释放：可以再次发起查询', async () => {
    get.mockImplementation((url) =>
      url === '/security/ip-list'
        ? Promise.resolve(listBody([ipRow()], { total: 1 }))
        : Promise.reject(new Error('query down'))
    )
    const c = await boot(1)
    await doQuery(c, '10.0.0.5')
    expect(queryCalls()).toHaveLength(1)
    const btn = c.find('.query-bar button')
    await waitFor(() => btn.disabled === false, { message: '失败后按钮解锁' })
    click(btn)
    await waitFor(() => queryCalls().length === 2, { message: '可再次发起查询' })
    expect(c.errors).toEqual([])
  })
})
describe('IpListView 移除名单条目', () => {
  test('确认后按行 _id 删除、提示成功并重载当前名单', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([ipRow({ _id: 'ip-77' })], { total: 1 })))
    confirm.mockResolvedValue('confirm')
    del.mockResolvedValue({ data: {} })
    const c = await boot(1)
    await waitFor(() => c.findAll('.el-table__body-wrapper .glass-btn--link').length === 1, {
      message: '移除按钮渲染完成',
    })
    click(c.findAll('.el-table__body-wrapper .glass-btn--link')[0])
    await waitFor(() => del.mock.calls.length === 1, { message: '删除请求' })
    expect(confirm.mock.calls[0][0]).toBe('确定删除吗？ 10.0.0.1?')
    expect(confirm.mock.calls[0][1]).toBe('提示')
    expect(del).toHaveBeenCalledWith('/security/ip-list/ip-77')
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '删除成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('删除成功')
    await waitFor(() => listCalls().length >= 2, { message: '删除后重载列表' })
    expect(c.errors).toEqual([])
  })

  test('用户放弃（cancel/close）：不发删除请求、不误报删除失败', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([ipRow()], { total: 1 })))
    del.mockResolvedValue({ data: {} })
    const c = await boot(1)
    await waitFor(() => c.findAll('.el-table__body-wrapper .glass-btn--link').length === 1, {
      message: '移除按钮渲染完成',
    })
    confirm.mockRejectedValueOnce('cancel')
    click(c.findAll('.el-table__body-wrapper .glass-btn--link')[0])
    await flush(12)
    expect(del).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
    confirm.mockRejectedValueOnce('close')
    click(c.findAll('.el-table__body-wrapper .glass-btn--link')[0])
    await flush(12)
    expect(del).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
  })

  test('删除失败：提示删除失败且行保留（不得乐观移除）', async () => {
    get.mockImplementation(() => Promise.resolve(listBody([ipRow()], { total: 1 })))
    confirm.mockResolvedValue('confirm')
    del.mockRejectedValue(new Error('del down'))
    const c = await boot(1)
    await waitFor(() => c.findAll('.el-table__body-wrapper .glass-btn--link').length === 1, {
      message: '移除按钮渲染完成',
    })
    click(c.findAll('.el-table__body-wrapper .glass-btn--link')[0])
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '删除失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith('删除失败')
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(trs(c)).toHaveLength(1)
    expect(listCalls()).toHaveLength(1)
    expect(c.errors).toEqual([])
  })

  test('查询模式下删除命中条目：重新执行命中查询而不是拉取名单列表', async () => {
    get.mockImplementation((url) => {
      if (url === '/security/ip-list') return Promise.resolve(listBody([ipRow()], { total: 1 }))
      if (url === '/security/ip-list/query') {
        return Promise.resolve(
          queryBody({
            verdict: 'blocked',
            blackMatches: [ipRow({ _id: 'm-1', ip: '10.0.0.5' })],
          })
        )
      }
      return Promise.reject(new Error('unexpected url: ' + url))
    })
    confirm.mockResolvedValue('confirm')
    del.mockResolvedValue({ data: {} })
    const c = await boot(1)
    await doQuery(c, '10.0.0.5')
    await waitFor(() => c.findAll('.el-table__body-wrapper .glass-btn--link').length === 1, {
      message: '查询命中行渲染完成',
    })
    const beforeQuery = queryCalls().length
    const beforeList = listCalls().length
    click(c.findAll('.el-table__body-wrapper .glass-btn--link')[0])
    await waitFor(() => del.mock.calls.length === 1, { message: '删除请求' })
    expect(del).toHaveBeenCalledWith('/security/ip-list/m-1')
    await waitFor(() => queryCalls().length === beforeQuery + 1, { message: '重新查询' })
    expect(queryCalls()[queryCalls().length - 1][1]).toEqual({ params: { ip: '10.0.0.5' } })
    expect(listCalls()).toHaveLength(beforeList)
  })
})
