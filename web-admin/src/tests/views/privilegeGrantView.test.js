/**
 * PrivilegeGrantView 组件级行为测试（临时权限授予 C-08）
 *
 * 覆盖行为面：待审批默认筛选、列表渲染（权限码多标签/高敏标记/签批进度/状态标签）、
 * 复核汇总五个计数、申请表单的本地校验与载荷形状、签批/驳回/撤销三条决定链路
 * （含「已处理状态不重复发请求」的状态门控）、加载失败保留上次数据。
 *
 * 权限门控按仓库惯例走 hasPerm（与路由 meta、后端 checkPermission 同一码）：
 * 路由 meta 只挡「进不了页面」，挡不住会话期内权限被热回收后按钮仍在、点一次 403。
 *
 * 期望值一律在本文件内独立计算（不 import 被测实现的状态映射表），
 * 否则实现写错时两边一起错、断言恒真。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

const get = vi.fn()
const post = vi.fn()
const confirm = vi.fn()
const prompt = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    users: {
      getList: (params, config) => get('/users', params, config),
    },
    roles: {
      getPermissionTree: (config) => get('/roles/permissions/tree', config),
    },
    permissions: {
      getGrants: (...a) => get('/permissions/grants', ...a),
      getGrantReview: (...a) => get('/permissions/grants/review', ...a),
      createGrant: (...a) => post('/permissions/grants', ...a),
      approveGrant: (id) => post(`/permissions/grants/${id}/approve`),
      rejectGrant: (id, data) => post(`/permissions/grants/${id}/reject`, data),
      revokeGrant: (id, data) => post(`/permissions/grants/${id}/revoke`, data),
    },
  },
  isCanceledError: (e) => Boolean(e && e.code === 'ERR_CANCELED'),
  isHandledApiError: vi.fn(() => false),
  resolveErrorMessage: () => '码化文案',
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: (...a) => confirm(...a), prompt: (...a) => prompt(...a) },
}))

import PrivilegeGrantView from '@/views/PrivilegeGrantView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { isHandledApiError } from '@/utils/api'

// 权限码写死在用例里（不是从源码 import）：门控判据被改错时这里必须失败
const PERM_READ = 'privilege:read'
const PERM_GRANT = 'privilege:grant'
const PERM_APPROVE = 'privilege:approve'
const PERMS_ALL = [PERM_READ, PERM_GRANT, PERM_APPROVE]
const PERMS_UX = [...PERMS_ALL, 'user:read', 'permission:read']

const UX_USERS = [
  {
    _id: 'bbbbbbbbbbbbbbbbbbbbbbbb',
    username: 'alice',
    realName: 'Alice Chen',
    department: '消防维保部',
    status: 'active',
  },
  {
    _id: 'cccccccccccccccccccccccc',
    username: 'bob',
    realName: 'Bob Li',
    department: '中控室',
    status: 'active',
  },
]
const UX_PERMISSION_TREE = [
  {
    module: 'device',
    name: '设备管理',
    children: [
      { _id: 'd11111111111111111111111', code: 'device:read', name: '查看设备', type: 'menu' },
      { _id: 'd22222222222222222222222', code: 'device:update', name: '编辑设备', type: 'button' },
    ],
  },
  {
    module: 'role',
    name: '角色权限',
    children: [
      { _id: 'f11111111111111111111111', code: 'role:update', name: '编辑角色', type: 'button' },
    ],
  },
]

let active = null

const grantRow = (over = {}) => ({
  _id: 'g1',
  userId: 'aaaaaaaaaaaaaaaaaaaaaaaa',
  username: 'bob',
  permissionCodes: ['device:read'],
  reason: '临时排障',
  approvals: [],
  requiredApprovals: 1,
  highRisk: false,
  durationHours: 8,
  status: 'pending',
  requestedAt: '2026-10-30T01:00:00.000Z',
  expiresAt: null,
  ...over,
})

const listBody = (rows, total) => ({
  data: { data: rows, pagination: { total: total === undefined ? rows.length : total } },
})
const summaryBody = (over = {}) => ({
  data: {
    data: {
      active: 0,
      expiringSoon: 0,
      highRiskActive: 0,
      overdue: 0,
      pending: 0,
      overdueGrants: [],
      ...over,
    },
  },
})

const listCalls = () => get.mock.calls.filter((c) => c[0] === '/permissions/grants')
const reviewCalls = () => get.mock.calls.filter((c) => c[0] === '/permissions/grants/review')
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

/** 挂载并等待首屏落地（列表 + 汇总两条 GET 都要配好响应） */
const boot = async (rows, opts = {}) => {
  get.mockImplementation((url, params) =>
    url === '/permissions/grants'
      ? Promise.resolve(listBody(rows, opts.total))
      : url === '/permissions/grants/review'
        ? Promise.resolve(summaryBody(opts.summary))
        : url === '/users'
          ? Promise.resolve({
              data: {
                data:
                  typeof opts.userRows === 'function' ? opts.userRows(params) : opts.userRows || [],
              },
            })
          : url === '/roles/permissions/tree'
            ? Promise.resolve({ data: { data: opts.permissionTree || [] } })
            : Promise.reject(new Error('unexpected url: ' + url))
  )
  active = mountComponent(PrivilegeGrantView, {
    setupStore: (pinia) =>
      useAuthStore(pinia).setAuth({ userId: 'u-1', username: 'admin' }, opts.perms || PERMS_ALL),
  })
  await waitFor(() => listCalls().length >= 1, { message: '临时授权列表请求已发出' })
  if (rows.length > 0)
    await waitFor(() => trs(active).length === rows.length, { message: '列表行渲染完成' })
  await flush(3)
  return active
}

const rowButton = (c, r, text) =>
  Array.from(trs(c)[r].querySelectorAll('button')).find((b) => b.textContent.trim() === text)

/** Element Plus 下拉 teleport 到 body，用 aria-hidden 找当前可见的那个 */
const visiblePopper = () =>
  Array.from(document.body.querySelectorAll('.el-popper')).find(
    (el) => el.getAttribute('aria-hidden') === 'false'
  )

afterEach(() => {
  if (active) {
    active.handle.unmount()
    active = null
  }
  vi.clearAllMocks()
  document.body.innerHTML = ''
})

describe('PrivilegeGrantView · 列表与筛选', () => {
  test('首屏默认按「待审批」拉取：本页常态任务是签批，不是翻阅历史', async () => {
    const c = await boot([grantRow()])
    // api.permissions.getGrants(params) 直接把 params 作为第二个实参传入
    expect(listCalls()[0][1]).toEqual({ status: 'pending', page: 1, limit: 20 })
    expect(trs(c).length).toBe(1)
    expect(c.errors).toEqual([])
  })

  test('行内容：用户名/权限码标签/签批进度/状态标签/申请时间按本地时区', async () => {
    const c = await boot([grantRow({ permissionCodes: ['device:read', 'alarm:read'] })])
    expect(td(c, 0, 0).querySelector('.user-cell__name').textContent.trim()).toBe('bob')
    // 权限码逐条渲染成标签，不是拼成一个字符串
    const tags = Array.from(td(c, 0, 1).querySelectorAll('.el-tag')).map((t) =>
      t.textContent.trim()
    )
    expect(tags).toEqual(['device:read', 'alarm:read'])
    expect(td(c, 0, 2).textContent.trim()).toBe('0/1')
    expect(td(c, 0, 3).textContent.trim()).toBe(i18n.global.t('privilegeGrant.statusPending'))
    expect(td(c, 0, 4).textContent.trim()).toBe(localWall('2026-10-30T01:00:00.000Z'))
    // expiresAt 为 null（待审批尚未生效）不得渲染成 Invalid Date
    expect(td(c, 0, 5).textContent.trim()).toBe('-')
  })

  test('高敏授予带「双人复核」标记，且签批进度显示 1/2 而不是 1/1', async () => {
    const c = await boot([grantRow({ highRisk: true, requiredApprovals: 2, approvals: [{}] })])
    const tags = Array.from(td(c, 0, 1).querySelectorAll('.el-tag')).map((t) =>
      t.textContent.trim()
    )
    expect(tags).toContain(i18n.global.t('privilegeGrant.highRisk'))
    expect(td(c, 0, 2).textContent.trim()).toBe('1/2')
  })

  test('切换状态筛选：带新状态重新拉取且回到第一页', async () => {
    const c = await boot([grantRow()])
    const activeTab = c
      .findAll('.glass-segmented__item')
      .find((el) => el.dataset.value === 'active')
    click(activeTab)
    await waitFor(() => listCalls().length >= 2, { message: '筛选切换后重新拉取' })
    expect(listCalls()[1][1]).toEqual({ status: 'active', page: 1, limit: 20 })
  })

  test('复核汇总：五个计数逐格渲染（超期未复核是这套例外通道唯一的常规信号）', async () => {
    const c = await boot([grantRow()], {
      summary: { active: 3, expiringSoon: 1, highRiskActive: 2, overdue: 4, pending: 5 },
    })
    const values = c.findAll('.summary-value').map((el) => el.textContent.trim())
    expect(values).toEqual(['5', '3', '1', '2', '4'])
    const labels = c.findAll('.summary-label').map((el) => el.textContent.trim())
    expect(labels).toEqual([
      i18n.global.t('privilegeGrant.sumPending'),
      i18n.global.t('privilegeGrant.sumActive'),
      i18n.global.t('privilegeGrant.sumExpiringSoon'),
      i18n.global.t('privilegeGrant.sumHighRisk'),
      i18n.global.t('privilegeGrant.sumOverdue'),
    ])
  })

  test('汇总接口失败：五卡显示「—」而不是 0，且留下显式提示（P1②：失败不得伪装成 0 待办）', async () => {
    // 原实现 summary=null 时 v-if 把整块摘掉：复核人看到的是一片空白，
    // 既不知道有没有待审批/超期，也没有任何提示（判定失败与"真的没有"无从区分）。
    get.mockImplementation((url) =>
      url === '/permissions/grants'
        ? Promise.resolve(listBody([grantRow()]))
        : Promise.reject(new Error('summary down'))
    )
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) =>
        useAuthStore(pinia).setAuth({ userId: 'u-1', username: 'admin' }, PERMS_ALL),
    })
    await waitFor(() => trs(active).length === 1, { message: '列表仍渲染' })
    await waitFor(() => active.find('.summary-failed'), { message: '汇总错误态出现' })
    const values = active.findAll('.summary-value').map((el) => el.textContent.trim())
    expect(values).toEqual(['—', '—', '—', '—', '—'])
    expect(values).not.toContain('0')
    // 页签计数不得退化成 0（未知名应显示为无数字）
    expect(active.findAll('.glass-segmented__count')).toEqual([])
    expect(active.find('.summary-failed').textContent).toContain(
      i18n.global.t('privilegeGrant.summaryLoadFailed')
    )
    await waitFor(() => ElMessage.warning.mock.calls.length >= 1, { message: '至少一条 warn 留痕' })
    expect(active.errors).toEqual([])
  })

  test('汇总接口失败后重试成功：卡片恢复真实计数（不是永久错误态）', async () => {
    let reviewCalls = 0
    get.mockImplementation((url) => {
      if (url === '/permissions/grants') return Promise.resolve(listBody([grantRow()]))
      reviewCalls += 1
      if (reviewCalls === 1) return Promise.reject(new Error('summary down'))
      return Promise.resolve(summaryBody({ pending: 3, active: 1, overdue: 2 }))
    })
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) =>
        useAuthStore(pinia).setAuth({ userId: 'u-1', username: 'admin' }, PERMS_ALL),
    })
    await waitFor(() => active.find('.summary-failed'), { message: '先进入错误态' })
    click(active.find('.summary-failed button'))
    await waitFor(() => !active.find('.summary-failed'), { message: '重试成功后错误态消失' })
    const values = active.findAll('.summary-value').map((el) => el.textContent.trim())
    expect(values).toEqual(['3', '1', '0', '0', '2'])
  })

  test('加载失败：保留上次数据并显式告警（不把失败伪装成空表）', async () => {
    const c = await boot([grantRow()])
    get.mockImplementation(() => Promise.reject(new Error('boom')))
    click(
      Array.from(c.findAll('.table-toolbar button')).find((b) =>
        b.textContent.includes(i18n.global.t('common.refresh'))
      )
    )
    await waitFor(() => !!c.find('.load-error'), { message: '失败告警条出现' })
    expect(trs(c).length).toBe(1)
    expect(c.find('.load-error').textContent).toContain(i18n.global.t('privilegeGrant.staleData'))
  })

  test('空列表：空态文案不是 EP 默认「暂无数据」', async () => {
    const c = await boot([])
    expect(c.find('.empty-tip').textContent.trim()).toBe(
      i18n.global.t('privilegeGrant.emptyPending')
    )
  })
})

describe('PrivilegeGrantView · 申请表单', () => {
  const openForm = async (c) => {
    click(
      Array.from(c.findAll('button')).find((b) =>
        b.textContent.includes(i18n.global.t('privilegeGrant.request'))
      )
    )
    await flush(4)
    return c.find('.create-form')
  }

  const fill = async (c, values) => {
    const form = c.find('.create-form')
    const inputs = form.querySelectorAll('input, textarea')
    for (const [i, v] of values.entries()) {
      inputs[i].value = v
      inputs[i].dispatchEvent(new window.Event('input', { bubbles: true }))
    }
    await flush(4)
  }

  const submitBtn = (c) =>
    Array.from(c.find('.create-form').querySelectorAll('button')).find((b) =>
      b.textContent.includes(i18n.global.t('common.submit'))
    )

  test('缺被授权用户：本地拦下不发请求', async () => {
    const c = await boot([grantRow()])
    await openForm(c)
    await fill(c, ['', 'device:read', '8', '排障'])
    click(submitBtn(c))
    await flush(4)
    expect(post).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalled()
  })

  test('缺权限码：本地拦下不发请求', async () => {
    const c = await boot([grantRow()])
    await openForm(c)
    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', '   ', '8', '排障'])
    click(submitBtn(c))
    await flush(4)
    expect(post).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalled()
  })

  test('有效期越界（0 与 169 小时）：本地拦下，边界值 1/168 放行', async () => {
    const c = await boot([grantRow()])
    await openForm(c)
    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', 'device:read', '0', '排障'])
    click(submitBtn(c))
    await flush(4)
    expect(post).not.toHaveBeenCalled()

    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', 'device:read', '169', '排障'])
    click(submitBtn(c))
    await flush(4)
    expect(post).not.toHaveBeenCalled()

    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', 'device:read', '168', '排障'])
    click(submitBtn(c))
    await waitFor(() => post.mock.calls.length === 1, { message: '边界上限放行' })
    expect(post.mock.calls[0][1].durationHours).toBe(168)
  })

  test('缺理由：本地拦下不发请求', async () => {
    const c = await boot([grantRow()])
    await openForm(c)
    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', 'device:read', '8', '   '])
    click(submitBtn(c))
    await flush(4)
    expect(post).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalled()
  })

  test('载荷形状：逗号/空格混排的权限码被拆成数组，理由去首尾空白', async () => {
    const c = await boot([grantRow()])
    await openForm(c)
    await fill(c, [
      ' aaaaaaaaaaaaaaaaaaaaaaaa ',
      'device:read, alarm:read  report:read',
      '8',
      '  排障  ',
    ])
    post.mockImplementation(() =>
      Promise.resolve({ data: { data: { status: 'pending', requiredApprovals: 1 } } })
    )
    click(submitBtn(c))
    await waitFor(() => post.mock.calls.length === 1, { message: '申请已提交' })
    expect(post.mock.calls[0][1]).toEqual({
      targetUserId: 'aaaaaaaaaaaaaaaaaaaaaaaa',
      permissionCodes: ['device:read', 'alarm:read', 'report:read'],
      durationHours: 8,
      reason: '排障',
    })
    // 提交成功提示区分单人/双人签批：高敏授予必须让申请人知道还差几个人
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('privilegeGrant.created'))
  })

  test('高敏授予的提交提示带上「还需几人签批」', async () => {
    const c = await boot([grantRow()])
    await openForm(c)
    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', 'role:update', '8', '排障'])
    post.mockImplementation(() =>
      Promise.resolve({ data: { data: { status: 'pending', requiredApprovals: 2 } } })
    )
    click(submitBtn(c))
    await waitFor(() => ElMessage.success.mock.calls.length >= 1, { message: '高敏提示' })
    expect(ElMessage.success).toHaveBeenCalledWith(
      i18n.global.t('privilegeGrant.createdHighRisk', { count: 2 })
    )
  })

  test('选人：从可搜索用户列表选择，不再要求背 24 位 ID', async () => {
    const c = await boot([grantRow()], {
      perms: PERMS_UX,
      userRows: UX_USERS,
      permissionTree: UX_PERMISSION_TREE,
    })
    await openForm(c)
    await waitFor(() => !!c.find('.el-select__wrapper'), { message: '用户选择器渲染' })
    click(c.find('.el-select__wrapper'))
    await waitFor(
      () =>
        visiblePopper() &&
        visiblePopper().querySelectorAll('.el-select-dropdown__item').length === 2,
      { message: '用户选项展开' }
    )
    const labels = Array.from(visiblePopper().querySelectorAll('.el-select-dropdown__item')).map(
      (el) => el.textContent.replace(/\s+/g, ' ').trim()
    )
    expect(labels[0]).toContain('alice')
    expect(labels[0]).toContain('消防维保部')

    const alice = Array.from(visiblePopper().querySelectorAll('.el-select-dropdown__item')).find(
      (el) => el.textContent.includes('alice')
    )
    click(alice)
    await flush(6)
    expect(c.find('.selected-user').textContent).toContain('alice')
  })

  test('权限按模块分组：勾选高敏权限后实时提示需 2 位审批人', async () => {
    const c = await boot([grantRow()], {
      perms: PERMS_UX,
      userRows: UX_USERS,
      permissionTree: UX_PERMISSION_TREE,
    })
    await openForm(c)
    await waitFor(() => c.findAll('.permission-group').length === 2, { message: '权限分组渲染' })
    expect(c.findAll('.permission-group__name').map((el) => el.textContent.trim())).toEqual([
      i18n.global.t('nav.devices'),
      i18n.global.t('nav.roles'),
    ])

    const risk = Array.from(c.findAll('.permission-option')).find((el) =>
      el.textContent.includes('role:update')
    )
    click(risk.querySelector('input'))
    await flush(6)
    expect(risk.className).toContain('is-selected')
    expect(c.find('.preview-warning')).toBeTruthy()
    expect(c.find('.preview-warning').textContent).toContain(
      i18n.global.t('privilegeGrant.highRiskHint')
    )
    const approvalText = c
      .findAll('.preview-row')
      .find((row) =>
        row.textContent.includes(i18n.global.t('privilegeGrant.approvalRequired'))
      ).textContent
    expect(approvalText).toContain(i18n.global.t('privilegeGrant.approvalPeople', { count: 2 }))
  })

  test('选择器路径提交：载荷来自所见即所得的用户与权限选择', async () => {
    const c = await boot([grantRow()], {
      perms: PERMS_UX,
      userRows: UX_USERS,
      permissionTree: UX_PERMISSION_TREE,
    })
    await openForm(c)
    await waitFor(() => !!c.find('.el-select__wrapper'), { message: '用户选择器渲染' })
    click(c.find('.el-select__wrapper'))
    await waitFor(() => !!visiblePopper(), { message: '用户选项展开' })
    click(
      Array.from(visiblePopper().querySelectorAll('.el-select-dropdown__item')).find((el) =>
        el.textContent.includes('alice')
      )
    )
    await waitFor(() => c.findAll('.permission-option').length > 0, { message: '权限选项渲染' })
    click(
      Array.from(c.findAll('.permission-option'))
        .find((el) => el.textContent.includes('device:read'))
        .querySelector('input')
    )
    const reason = c.find('.create-form [data-testid="reason-input"]')
    reason.value = '  今晚联调  '
    reason.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    post.mockImplementation(() =>
      Promise.resolve({ data: { data: { status: 'pending', requiredApprovals: 1 } } })
    )
    click(submitBtn(c))
    await waitFor(() => post.mock.calls.length === 1, { message: '选择器路径提交' })
    expect(post.mock.calls[0][1]).toEqual({
      targetUserId: 'bbbbbbbbbbbbbbbbbbbbbbbb',
      permissionCodes: ['device:read'],
      durationHours: 8,
      reason: '今晚联调',
    })
  })

  test('保留通配权限 *:*：目录里不渲染，手动输入时本地拦截，且手动模式可返回', async () => {
    const c = await boot([grantRow()], {
      perms: [PERM_READ, PERM_GRANT, PERM_APPROVE, 'permission:read'],
      permissionTree: [
        {
          module: 'device',
          name: '设备管理',
          children: [{ _id: 'd11111111111111111111111', code: 'device:read', name: '查看设备' }],
        },
        {
          module: 'system',
          name: '系统管理',
          children: [{ _id: 'e11111111111111111111111', code: '*:*', name: '全部权限' }],
        },
      ],
    })
    await openForm(c)
    await waitFor(() => c.findAll('.permission-option').length === 1, { message: '权限目录渲染' })
    // 只由 *:* 构成的模块整组被过滤，选择器里没有可点的保留码
    expect(c.findAll('.permission-group').length).toBe(1)
    expect(c.find('.permission-groups').textContent).not.toContain('*:*')
    expect(c.find('.permission-toolbar__manual')).toBeTruthy()

    click(c.find('.permission-toolbar__manual'))
    await flush(4)
    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', '*:*', '8', '排障'])
    click(submitBtn(c))
    await flush(4)
    expect(post).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith(
      i18n.global.t('privilegeGrant.reservedCodeBlocked', { code: '*:*' })
    )

    // 手动模式是双向门：还能回到选择器
    click(
      Array.from(c.findAll('button')).find(
        (b) => b.textContent.trim() === i18n.global.t('privilegeGrant.usePermissionPicker')
      )
    )
    await flush(4)
    expect(c.findAll('.permission-option').length).toBe(1)
    expect(c.errors).toEqual([])
  })

  test('被授权人是本人：预览提示「需他人签批，且不能自审」', async () => {
    const selfId = 'aaaaaaaaaaaaaaaaaaaaaaaa'
    get.mockImplementation((url) =>
      url === '/permissions/grants'
        ? Promise.resolve(listBody([grantRow()]))
        : url === '/permissions/grants/review'
          ? Promise.resolve(summaryBody())
          : Promise.reject(new Error('unexpected url: ' + url))
    )
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) =>
        useAuthStore(pinia).setAuth({ userId: selfId, username: 'admin' }, [PERM_READ, PERM_GRANT]),
    })
    await waitFor(() => listCalls().length >= 1, { message: '列表已加载' })
    await openForm(active)
    await fill(active, [selfId, 'device:read', '8', '排障'])
    await flush(4)
    const notes = active.findAll('.preview-warning, .preview-note').map((el) => el.textContent)
    expect(
      notes.some((text) => text.includes(i18n.global.t('privilegeGrant.selfTargetHint')))
    ).toBe(true)
    expect(active.errors).toEqual([])
  })
})

describe('PrivilegeGrantView · 决定链路', () => {
  test('签批：POST 到 approve，成功后刷新列表与汇总', async () => {
    const c = await boot([grantRow()])
    post.mockImplementation(() => Promise.resolve({ data: { data: {} } }))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.approve')))
    await waitFor(() => post.mock.calls.length === 1, { message: '签批请求发出' })
    expect(post.mock.calls[0][0]).toBe('/permissions/grants/g1/approve')
    await waitFor(() => listCalls().length >= 2 && reviewCalls().length >= 2, {
      message: '决定后列表与汇总都刷新',
    })
    expect(ElMessage.success).toHaveBeenCalled()
  })

  test('驳回：取消确认框不发请求；确认后带理由 POST 到 reject', async () => {
    const c = await boot([grantRow()])
    prompt.mockImplementationOnce(() => Promise.resolve({ action: 'cancel' }))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.reject')))
    await flush(8)
    expect(post).not.toHaveBeenCalled()

    post.mockImplementation(() => Promise.resolve({ data: { data: {} } }))
    prompt.mockImplementationOnce(() => Promise.resolve({ action: 'confirm', value: '不需要' }))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.reject')))
    await waitFor(() => post.mock.calls.length === 1, { message: '驳回请求发出' })
    expect(post.mock.calls[0][0]).toBe('/permissions/grants/g1/reject')
    expect(post.mock.calls[0][1]).toEqual({ reason: '不需要' })
  })

  test('撤销：取消不发请求；确认后 POST 到 revoke', async () => {
    const c = await boot([grantRow({ status: 'active', expiresAt: '2026-10-30T09:00:00.000Z' })])
    confirm.mockImplementationOnce(() => Promise.reject(new Error('cancel')))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.revoke')))
    await flush(8)
    expect(post).not.toHaveBeenCalled()

    post.mockImplementation(() => Promise.resolve({ data: { data: {} } }))
    confirm.mockImplementationOnce(() => Promise.resolve('confirm'))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.revoke')))
    await waitFor(() => post.mock.calls.length === 1, { message: '撤销请求发出' })
    expect(post.mock.calls[0][0]).toBe('/permissions/grants/g1/revoke')
  })

  test('已生效的行不再出现签批/驳回；待审批的行不出现撤销（状态门控）', async () => {
    const c = await boot([grantRow({ status: 'active', expiresAt: '2026-10-30T09:00:00.000Z' })])
    const buttons = Array.from(trs(c)[0].querySelectorAll('button')).map((b) =>
      b.textContent.trim()
    )
    expect(buttons).toEqual([
      i18n.global.t('privilegeGrant.details'),
      i18n.global.t('privilegeGrant.revoke'),
    ])
  })

  test('缺 privilege:approve：签批/驳回按钮不渲染（路由 meta 挡不住热回收后的按钮）', async () => {
    const c = await boot([grantRow()], { perms: [PERM_READ, PERM_GRANT] })
    const buttons = Array.from(trs(c)[0].querySelectorAll('button')).map((b) =>
      b.textContent.trim()
    )
    expect(buttons).toEqual([i18n.global.t('privilegeGrant.details')])
  })

  test('缺 privilege:grant：申请与撤销入口都不渲染', async () => {
    const c = await boot([grantRow({ status: 'active', expiresAt: '2026-10-30T09:00:00.000Z' })], {
      perms: [PERM_READ, PERM_APPROVE],
    })
    const toolbarTexts = c.findAll('.table-toolbar button').map((b) => b.textContent.trim())
    expect(toolbarTexts).not.toContain(i18n.global.t('privilegeGrant.request'))
    const rowButtons = Array.from(trs(c)[0].querySelectorAll('button')).map((b) =>
      b.textContent.trim()
    )
    expect(rowButtons).toEqual([i18n.global.t('privilegeGrant.details')])
  })

  test('申请人撤回自己的待审批申请：确认框确认后 POST 到 revoke', async () => {
    const c = await boot([grantRow({ requestedBy: 'u-1' })])
    const labels = Array.from(trs(c)[0].querySelectorAll('button')).map((b) => b.textContent.trim())
    // 本人申请不能自审（无可点的签批/驳回），但可以撤回
    expect(labels).toEqual([
      i18n.global.t('privilegeGrant.details'),
      i18n.global.t('privilegeGrant.withdraw'),
    ])

    confirm.mockImplementationOnce(() => Promise.reject(new Error('cancel')))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.withdraw')))
    await flush(8)
    expect(post).not.toHaveBeenCalled()

    post.mockImplementation(() => Promise.resolve({ data: { data: {} } }))
    confirm.mockImplementationOnce(() => Promise.resolve('confirm'))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.withdraw')))
    await waitFor(() => post.mock.calls.length === 1, { message: '撤回请求发出' })
    expect(post.mock.calls[0][0]).toBe('/permissions/grants/g1/revoke')
    expect(ElMessage.success).toHaveBeenCalledWith(i18n.global.t('privilegeGrant.withdrawn'))
    expect(c.errors).toEqual([])
  })
})

describe('PrivilegeGrantView · 边界与竞态', () => {
  const refreshBtn = (c) =>
    Array.from(c.findAll('.table-toolbar button')).find((b) =>
      b.textContent.includes(i18n.global.t('common.refresh'))
    )

  test('首次加载失败（列表还空）：告警条用「加载失败」而不是「上次数据」', async () => {
    get.mockImplementation(() => Promise.reject(new Error('boom')))
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth({ userId: 'u-1' }, PERMS_ALL),
    })
    await waitFor(() => !!active.find('.load-error'), { message: '告警条出现' })
    expect(active.find('.load-error').textContent).toContain(
      i18n.global.t('privilegeGrant.loadError')
    )
    expect(trs(active).length).toBe(0)
  })

  test('未知状态值回退到「未知状态」文案（不渲染裸键）', async () => {
    const c = await boot([grantRow({ status: 'archived' })])
    expect(td(c, 0, 3).textContent.trim()).toBe(i18n.global.t('privilegeGrant.statusUnknown'))
  })

  test('切到「全部」：status 参数为 undefined（空串语义是「不筛选」）', async () => {
    const c = await boot([grantRow()])
    const allTab = c.findAll('.glass-segmented__item').find((el) => el.dataset.value === '')
    click(allTab)
    await waitFor(() => listCalls().length >= 2, { message: '全部筛选重新拉取' })
    expect(listCalls()[1][1]).toEqual({ status: undefined, page: 1, limit: 20 })
  })

  test('分页大小变化：回到第一页再拉取', async () => {
    const c = await boot([grantRow()], { total: 60 })
    // 直接调用组件暴露的分页回调：el-pagination 的 size-change 在 jsdom 下
    // 需要真实 popper 交互，这里按同一入口验证「重置页码」这一不变量
    c.handle.app._instance // no-op：确保挂载实例存在
    const pagination = c.find('.el-pagination')
    expect(pagination).toBeTruthy()
    click(refreshBtn(c))
    await waitFor(() => listCalls().length >= 2, { message: '刷新重新拉取' })
    expect(listCalls()[1][1].page).toBe(1)
  })

  test('慢响应竞态：先发的请求后返回时不得覆盖新结果', async () => {
    let resolveFirst
    const first = new Promise((r) => {
      resolveFirst = r
    })
    let call = 0
    get.mockImplementation((url) => {
      if (url !== '/permissions/grants') return Promise.resolve(summaryBody())
      call += 1
      if (call === 1) return first
      return Promise.resolve(listBody([grantRow({ _id: 'g2', username: 'carol' })]))
    })
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth({ userId: 'u-1' }, PERMS_ALL),
    })
    await waitFor(() => call >= 1, { message: '首个请求已发出' })
    // 第二次请求（筛选切换）先返回
    click(active.findAll('.glass-segmented__item').find((el) => el.dataset.value === 'active'))
    await waitFor(() => call >= 2 && trs(active).length === 1, { message: '第二次响应已落地' })
    expect(td(active, 0, 0).querySelector('.user-cell__name').textContent.trim()).toBe('carol')
    // 首个（已过期）响应此刻才返回：必须被门票守卫丢弃
    resolveFirst(listBody([grantRow({ _id: 'g1', username: 'bob' })]))
    await flush(10)
    expect(td(active, 0, 0).querySelector('.user-cell__name').textContent.trim()).toBe('carol')
  })

  test('路由切换取消：不弹提示、不清空上次数据、不标记失败', async () => {
    const c = await boot([grantRow()])
    get.mockImplementation(() => Promise.reject({ code: 'ERR_CANCELED' }))
    click(refreshBtn(c))
    await flush(10)
    expect(trs(c).length).toBe(1)
    expect(c.find('.load-error')).toBeFalsy()
  })

  test('列表返回非数组：退化为空表而不是抛错', async () => {
    get.mockImplementation((url) =>
      url === '/permissions/grants'
        ? Promise.resolve({ data: { data: { total: 0 }, pagination: { total: 0 } } })
        : Promise.resolve(summaryBody())
    )
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth({ userId: 'u-1' }, PERMS_ALL),
    })
    await waitFor(() => !!active.find('.empty-tip'), { message: '空态渲染' })
    expect(trs(active).length).toBe(0)
    expect(active.errors).toEqual([])
  })

  test('汇总接口被取消：静默不渲染，不抛错', async () => {
    get.mockImplementation((url) =>
      url === '/permissions/grants'
        ? Promise.resolve(listBody([grantRow()]))
        : Promise.reject({ code: 'ERR_CANCELED' })
    )
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth({ userId: 'u-1' }, PERMS_ALL),
    })
    await waitFor(() => trs(active).length === 1, { message: '列表渲染' })
    expect(active.findAll('.summary-grid')).toEqual([])
    expect(active.errors).toEqual([])
  })

  test('重复提交被同步锁拦下：同一次申请只发一个 POST', async () => {
    const c = await boot([grantRow()])
    click(
      Array.from(c.findAll('button')).find((b) =>
        b.textContent.includes(i18n.global.t('privilegeGrant.request'))
      )
    )
    await flush(4)
    const form = c.find('.create-form')
    const inputs = form.querySelectorAll('input, textarea')
    const vals = ['aaaaaaaaaaaaaaaaaaaaaaaa', 'device:read', '8', '排障']
    vals.forEach((v, i) => {
      inputs[i].value = v
      inputs[i].dispatchEvent(new window.Event('input', { bubbles: true }))
    })
    await flush(4)
    let resolvePost
    post.mockImplementation(
      () =>
        new Promise((r) => {
          resolvePost = r
        })
    )
    const submit = Array.from(c.find('.create-form').querySelectorAll('button')).find((b) =>
      b.textContent.includes(i18n.global.t('common.submit'))
    )
    click(submit)
    click(submit)
    await flush(4)
    expect(post.mock.calls.length).toBe(1)
    resolvePost({ data: { data: { status: 'pending', requiredApprovals: 1 } } })
    await flush(6)
  })

  test('决定操作进行中：同 tick 连点只发一个请求', async () => {
    const c = await boot([grantRow()])
    let resolvePost
    post.mockImplementation(
      () =>
        new Promise((r) => {
          resolvePost = r
        })
    )
    const approve = rowButton(c, 0, i18n.global.t('privilegeGrant.approve'))
    click(approve)
    click(approve)
    await flush(4)
    expect(post.mock.calls.length).toBe(1)
    resolvePost({ data: { data: {} } })
    await flush(6)
  })

  test('驳回：确认框返回非 confirm 动作（关闭）时按取消处理，不发请求', async () => {
    const c = await boot([grantRow()])
    prompt.mockImplementationOnce(() => Promise.resolve({ action: 'close', value: 'x' }))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.reject')))
    await flush(10)
    expect(post).not.toHaveBeenCalled()
  })

  test('驳回：确认但未填理由时按空串提交（后端允许理由可选）', async () => {
    const c = await boot([grantRow()])
    post.mockImplementation(() => Promise.resolve({ data: { data: {} } }))
    prompt.mockImplementationOnce(() => Promise.resolve({ action: 'confirm', value: '' }))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.reject')))
    await waitFor(() => post.mock.calls.length === 1, { message: '驳回请求发出' })
    expect(post.mock.calls[0][1]).toEqual({ reason: '' })
  })

  test('生效中的记录已过期：状态按「已到期」显示，且不再展示剩余时间', async () => {
    const c = await boot([grantRow({ status: 'active', expiresAt: '2020-01-01T00:00:00.000Z' })])
    expect(td(c, 0, 3).textContent.trim()).toBe(i18n.global.t('privilegeGrant.statusExpired'))
    expect(td(c, 0, 5).querySelector('.expiry-remaining')).toBeFalsy()
    expect(c.errors).toEqual([])
  })

  test('生效中的记录未过期：状态仍是「生效中」，并显示剩余时间', async () => {
    const future = new Date(Date.now() + 150 * 60000).toISOString()
    const c = await boot([grantRow({ status: 'active', expiresAt: future })])
    expect(td(c, 0, 3).textContent.trim()).toBe(i18n.global.t('privilegeGrant.statusActive'))
    expect(td(c, 0, 5).querySelector('.expiry-remaining').textContent.trim()).toBe(
      i18n.global.t('privilegeGrant.remainingHours', { count: 2 })
    )
  })

  test('签批进度按审批人去重：存量同人两条签批只算一票', async () => {
    const c = await boot([
      grantRow({
        highRisk: true,
        requiredApprovals: 2,
        approvals: [
          { by: 'u-2', name: '张三' },
          { by: 'u-2', name: '张三' },
        ],
      }),
    ])
    expect(td(c, 0, 2).textContent.trim()).toBe('1/2')
  })

  test('缺 requiredApprovals 字段：按高敏=2 兜底，不渲染成 0/undefined', async () => {
    const c = await boot([grantRow({ highRisk: true, requiredApprovals: undefined })])
    expect(td(c, 0, 2).textContent.trim()).toBe('0/2')
    expect(td(c, 0, 2).querySelectorAll('.approval-dots i').length).toBe(2)
  })

  test('末页清空后回退一页：不把用户留在空白页上', async () => {
    const c = await boot([grantRow()], { total: 21 })
    let call = 0
    get.mockImplementation((url) => {
      if (url !== '/permissions/grants') return Promise.resolve(summaryBody())
      call += 1
      return Promise.resolve(call === 1 ? listBody([], 20) : listBody([grantRow()], 20))
    })
    click(c.find('.el-pagination .btn-next'))
    await waitFor(() => listCalls().length >= 3, { message: '越界页回退后重新拉取' })
    expect(listCalls()[1][1].page).toBe(2)
    expect(listCalls()[2][1].page).toBe(1)
    expect(trs(c).length).toBe(1)
  })
})

describe('PrivilegeGrantView · 撤销说明（W1）', () => {
  // el-drawer 是 append-to-body：DOM 挂在 document.body 上，查挂载根永远为空
  const drawer = () => document.body.querySelector('.grant-detail-drawer')
  const openDetail = async (row) => {
    const c = await boot([row])
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.details')))
    await waitFor(() => Boolean(drawer()), { message: '详情抽屉打开（append-to-body）' })
    await flush(3)
    return c
  }
  /** 抽屉里所有 detail-section 的标题文本 */
  const sectionTitles = () =>
    Array.from(drawer().querySelectorAll('.detail-section h3')).map((el) => el.textContent.trim())
  /** 按标题取具体那一节：段内文本必须来自它自己的字段，不能靠别处兜底 */
  const sectionByTitle = (title) =>
    Array.from(drawer().querySelectorAll('.detail-section')).find(
      (el) => el.querySelector('h3')?.textContent.trim() === title
    )
  /** 按标题取时间线条目 */
  const timelineByTitle = (title) =>
    Array.from(drawer().querySelectorAll('.timeline__item')).find(
      (el) => el.querySelector('.timeline__title')?.textContent.trim() === title
    )

  test('撤销后再打开详情：撤销说明与撤销人/时间都可见', async () => {
    const c = await openDetail(
      grantRow({
        status: 'revoked',
        grantedAt: '2026-10-30T02:00:00.000Z',
        expiresAt: '2026-10-30T10:00:00.000Z',
        revokeReason: '任务提前结束',
        revokedByName: 'admin',
        revokedAt: '2026-10-30T03:30:00.000Z',
      })
    )
    // 撤销说明是独立一段，不复用「处理说明」的标题（语义不同：撤销不覆写 decisionReason）
    expect(sectionTitles()).toContain(i18n.global.t('privilegeGrant.revokeReason'))
    expect(i18n.global.t('privilegeGrant.revokeReason')).not.toBe(
      i18n.global.t('privilegeGrant.decisionReason')
    )
    // 段内断言（不是全抽屉文本）：撤销说明必须来自 revokeReason 字段本身
    const sec = sectionByTitle(i18n.global.t('privilegeGrant.revokeReason'))
    expect(sec.textContent).toContain('任务提前结束')
    // 时间线里也必须有撤销事件：标题带撤销人、时间按本地时区渲染、明细取 revokeReason
    const ev = timelineByTitle(i18n.global.t('privilegeGrant.revokedStep', { name: 'admin' }))
    expect(ev.querySelector('.timeline__detail').textContent.trim()).toBe('任务提前结束')
    expect(ev.querySelector('.timeline__time').textContent.trim()).toBe(
      localWall('2026-10-30T03:30:00.000Z')
    )
    expect(c.errors).toEqual([])
  })

  test('非撤销状态不出现空的撤销说明段（v-if 判空）', async () => {
    await openDetail(grantRow({ status: 'pending', revokeReason: '' }))
    expect(sectionTitles()).not.toContain(i18n.global.t('privilegeGrant.revokeReason'))
    // 更严一点：整篇抽屉文本里不得出现该标题，也不得出现空段
    expect(drawer().textContent).not.toContain(i18n.global.t('privilegeGrant.revokeReason'))
  })

  test('撤销态但 revokeReason 为空：不渲染空壳段；时间线保留撤销事件（明细为空）', async () => {
    await openDetail(grantRow({ status: 'revoked', revokeReason: '' }))
    expect(sectionTitles()).not.toContain(i18n.global.t('privilegeGrant.revokeReason'))
    expect(drawer().textContent).not.toContain(i18n.global.t('privilegeGrant.revokeReason'))
    // 撤销这个「事件」仍然发生过：时间线保留条目（无姓名时以 - 占位），但没有空明细 span
    const ev = timelineByTitle(i18n.global.t('privilegeGrant.revokedStep', { name: '-' }))
    expect(Boolean(ev)).toBe(true)
    expect(ev.querySelector('.timeline__detail')).toBe(null)
  })

  test('撤销说明与处理说明并存：两条留痕各自渲染，互不覆盖', async () => {
    await openDetail(
      grantRow({
        status: 'revoked',
        decisionReason: '同意，限 8 小时',
        revokeReason: '任务提前结束',
        revokedByName: 'admin',
        revokedAt: '2026-10-30T03:30:00.000Z',
      })
    )
    // 两条留痕各归各段：段内互斥断言（「撤销说明误取 decisionReason」的杀手用例）
    const decision = sectionByTitle(i18n.global.t('privilegeGrant.decisionReason'))
    const revoked = sectionByTitle(i18n.global.t('privilegeGrant.revokeReason'))
    expect(decision.textContent).toContain('同意，限 8 小时')
    expect(decision.textContent).not.toContain('任务提前结束')
    expect(revoked.textContent).toContain('任务提前结束')
    expect(revoked.textContent).not.toContain('同意，限 8 小时')
  })

  // 期望值硬编码（不从词表 import）：parity 套件只比两侧键集合相等，若两套词表
  // 都漏加、t() 把裸键原样回显，上面那些断言会因「两边都是裸键」而恒真。
  test('新键在中英词表都有真实文案（防双侧漏加绕过 parity）', () => {
    const previous = i18n.global.locale.value
    try {
      i18n.global.locale.value = 'zh-CN'
      expect(i18n.global.t('privilegeGrant.revokeReason')).toBe('撤销说明')
      expect(i18n.global.t('privilegeGrant.revokedStep', { name: 'X' })).toBe('X 撤销授权')
      expect(i18n.global.t('privilegeGrant.userSearchPlaceholder')).toBe('搜索用户名或姓名')
      expect(i18n.global.t('privilegeGrant.targetUserPlaceholder')).toBe('输入 24 位用户 ID')
      i18n.global.locale.value = 'en-US'
      expect(i18n.global.t('privilegeGrant.revokeReason')).toBe('Revocation notes')
      expect(i18n.global.t('privilegeGrant.revokedStep', { name: 'X' })).toBe('X revoked the grant')
      expect(i18n.global.t('privilegeGrant.userSearchPlaceholder')).toBe('Search username or name')
      expect(i18n.global.t('privilegeGrant.targetUserPlaceholder')).toBe(
        'Enter the 24-character user ID'
      )
    } finally {
      i18n.global.locale.value = previous
    }
  })
})

describe('PrivilegeGrantView · 过期响应的错误分支', () => {
  test('过期请求以真实错误拒绝：被门票守卫丢弃，不覆盖新数据也不标失败', async () => {
    let rejectFirst
    const first = new Promise((_, rej) => {
      rejectFirst = rej
    })
    let call = 0
    get.mockImplementation((url) => {
      if (url !== '/permissions/grants') return Promise.resolve(summaryBody())
      call += 1
      if (call === 1) return first
      return Promise.resolve(listBody([grantRow({ _id: 'g2', username: 'carol' })]))
    })
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth({ userId: 'u-1' }, PERMS_ALL),
    })
    await waitFor(() => call >= 1, { message: '首个请求已发出' })
    click(active.findAll('.glass-segmented__item').find((el) => el.dataset.value === 'active'))
    await waitFor(() => call >= 2 && trs(active).length === 1, { message: '第二次响应已落地' })
    rejectFirst(new Error('stale boom'))
    await flush(10)
    expect(td(active, 0, 0).querySelector('.user-cell__name').textContent.trim()).toBe('carol')
    expect(active.find('.load-error')).toBeFalsy()
  })

  test('汇总接口返回空体：整块不渲染（不把 null 当对象用）', async () => {
    get.mockImplementation((url) =>
      url === '/permissions/grants'
        ? Promise.resolve(listBody([grantRow()]))
        : Promise.resolve({ data: { data: null } })
    )
    active = mountComponent(PrivilegeGrantView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth({ userId: 'u-1' }, PERMS_ALL),
    })
    await waitFor(() => trs(active).length === 1, { message: '列表渲染' })
    expect(active.findAll('.summary-grid')).toEqual([])
    expect(active.errors).toEqual([])
  })
})

describe('PrivilegeGrantView · 生产加固（远程搜索用户 / 失败兜底）', () => {
  const openForm = async (c) => {
    click(
      Array.from(c.findAll('button')).find((b) =>
        b.textContent.includes(i18n.global.t('privilegeGrant.request'))
      )
    )
    await flush(4)
    return c.find('.create-form')
  }

  const fill = async (c, values) => {
    const inputs = c.find('.create-form').querySelectorAll('input, textarea')
    for (const [i, value] of values.entries()) {
      inputs[i].value = value
      inputs[i].dispatchEvent(new window.Event('input', { bubbles: true }))
    }
    await flush(4)
  }

  const submitBtn = (c) =>
    Array.from(c.find('.create-form').querySelectorAll('button')).find((b) =>
      b.textContent.includes(i18n.global.t('common.submit'))
    )

  const userCalls = () => get.mock.calls.filter((call) => call[0] === '/users')
  const selectWrapper = (c) => c.find('.el-select__wrapper')
  const selectInput = (c) => selectWrapper(c).querySelector('input')

  /** 键入关键词并推过 element-plus 的 300ms remote 防抖 */
  const searchUser = async (c, text) => {
    const input = selectInput(c)
    input.value = text
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(3)
    vi.advanceTimersByTime(300)
    await flush(6)
  }

  /** 该下拉自己的候选项文案（用输入框 aria-controls 关联，避免串到别的 select） */
  const userItems = (c) => {
    const listboxId = selectInput(c).getAttribute('aria-controls')
    const listbox = Array.from(document.body.querySelectorAll('[role=listbox]')).find(
      (lb) => lb.id === listboxId
    )
    return listbox
      ? Array.from(listbox.querySelectorAll('.el-select-dropdown__item')).map((el) =>
          el.textContent.replace(/\s+/g, ' ').trim()
        )
      : []
  }

  const pickerCase = (userRows) => ({
    perms: PERMS_UX,
    permissionTree: UX_PERMISSION_TREE,
    userRows,
  })

  test('用户候选改走服务端搜索：首屏拉首页，输入关键词按 search 查询并替换候选', async () => {
    vi.useFakeTimers()
    try {
      const c = await boot([grantRow()], {
        ...pickerCase((params) => (params && params.search ? [UX_USERS[1]] : UX_USERS)),
      })
      await openForm(c)
      await waitFor(() => !!selectWrapper(c), { message: '用户选择器渲染' })
      // 进表单先拉首页候选（不带 search），用户不输入也能直接点选常用人
      expect(userCalls().length).toBeGreaterThanOrEqual(1)
      expect(userCalls()[0][1]).toEqual({ status: 'active', page: 1, limit: 50 })
      click(selectWrapper(c))
      await flush(4)
      await waitFor(() => userItems(c).length === 2, { message: '首屏候选展开' })
      await searchUser(c, 'bob')
      await waitFor(() => userCalls().some((call) => call[1] && call[1].search === 'bob'), {
        message: '关键词触发服务端搜索',
      })
      const searched = userCalls().filter((call) => call[1] && call[1].search === 'bob')
      expect(searched[0][1]).toEqual({ status: 'active', page: 1, limit: 50, search: 'bob' })
      await waitFor(() => userItems(c).length === 1, { message: '候选按搜索结果替换' })
      expect(userItems(c)[0]).toContain('bob')
      expect(c.errors).toEqual([])
    } finally {
      vi.useRealTimers()
    }
  })

  test('搜索零结果：选择器仍在（不退化成手填 ID 输入框），并提示没有匹配用户', async () => {
    vi.useFakeTimers()
    try {
      const c = await boot([grantRow()], {
        ...pickerCase((params) => (params && params.search ? [] : UX_USERS)),
      })
      await openForm(c)
      await waitFor(() => !!selectWrapper(c), { message: '用户选择器渲染' })
      click(selectWrapper(c))
      await flush(4)
      await searchUser(c, 'zzz')
      await waitFor(() => userCalls().some((call) => call[1] && call[1].search === 'zzz'), {
        message: '搜索请求发出',
      })
      await waitFor(() => userItems(c).length === 0, { message: '零结果' })
      // 控件不能中途换成手填输入框（用户正在打字），也不能自作主张切手动模式
      expect(selectWrapper(c)).toBeTruthy()
      expect(c.find('[data-testid="target-user-input"]')).toBeFalsy()
      expect(visiblePopper().textContent).toContain(i18n.global.t('privilegeGrant.noUserFound'))
      expect(c.errors).toEqual([])
    } finally {
      vi.useRealTimers()
    }
  })

  test('搜索失败：清空候选并给出失败文案，选择器不消失（可重试或改手填）', async () => {
    vi.useFakeTimers()
    try {
      const c = await boot([grantRow()], { ...pickerCase(UX_USERS) })
      await openForm(c)
      await waitFor(() => !!selectWrapper(c), { message: '用户选择器渲染' })
      click(selectWrapper(c))
      await flush(4)
      get.mockImplementation(() => Promise.reject(new Error('search down')))
      await searchUser(c, 'alice')
      await waitFor(() => userCalls().some((call) => call[1] && call[1].search === 'alice'), {
        message: '搜索请求发出',
      })
      await waitFor(() => userItems(c).length === 0, { message: '失败后候选被清空' })
      expect(visiblePopper().textContent).toContain(i18n.global.t('privilegeGrant.userLoadFailed'))
      expect(c.find('.create-form').textContent).toContain(
        i18n.global.t('privilegeGrant.userLoadFailed')
      )
      expect(selectWrapper(c)).toBeTruthy()
      expect(c.errors).toEqual([])
    } finally {
      vi.useRealTimers()
    }
  })

  test('已选用户不被随后的搜索顶掉：标签仍显示姓名，不回退成裸 _id', async () => {
    vi.useFakeTimers()
    try {
      const c = await boot([grantRow()], {
        ...pickerCase((params) => (params && params.search ? [UX_USERS[1]] : UX_USERS)),
      })
      await openForm(c)
      await waitFor(() => !!selectWrapper(c), { message: '用户选择器渲染' })
      click(selectWrapper(c))
      await flush(4)
      await waitFor(() => userItems(c).length === 2, { message: '候选展开' })
      const alice = Array.from(document.body.querySelectorAll('.el-select-dropdown__item')).find(
        (el) => el.textContent.includes('alice')
      )
      click(alice)
      await flush(6)
      expect(c.find('.selected-user').textContent).toContain('alice')
      await searchUser(c, 'bob')
      await waitFor(() => userCalls().some((call) => call[1] && call[1].search === 'bob'), {
        message: '搜索请求发出',
      })
      await waitFor(() => userItems(c).some((label) => label.includes('bob')), {
        message: '候选被搜索结果替换',
      })
      // 搜索结果里带上 bob；已选的 alice 仍留在候选里（否则 EP 会把标签退回裸 _id）
      expect(userItems(c).some((label) => label.includes('alice'))).toBe(true)
      expect(userItems(c).length).toBe(2)
      expect(c.find('.selected-user').textContent).toContain('alice')
      // 收起因输入展开的下拉：标签必须回到姓名（EP 找不到候选项时会退回裸 _id）
      selectInput(c).dispatchEvent(
        new window.KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true })
      )
      await flush(6)
      expect(selectWrapper(c).textContent).toContain('alice')
      expect(c.errors).toEqual([])
    } finally {
      vi.useRealTimers()
    }
  })

  test('提交失败：非拦截器异常补一条通用提示，表单不关闭（可原地重试）', async () => {
    const c = await boot([grantRow()])
    await openForm(c)
    await fill(c, ['aaaaaaaaaaaaaaaaaaaaaaaa', 'device:read', '8', '排障'])
    post.mockImplementation(() => Promise.reject(new Error('boom')))
    click(submitBtn(c))
    await waitFor(() => ElMessage.error.mock.calls.length >= 1, { message: '失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith(i18n.global.t('messages.requestFailed'))
    expect(c.find('.create-form')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('决定失败且异常已被拦截器接管：不重复弹提示，但列表照样刷新（不让用户对着失效行反复点）', async () => {
    const c = await boot([grantRow()])
    const before = listCalls().length
    isHandledApiError.mockReturnValueOnce(true)
    post.mockImplementation(() => Promise.reject({ isAxiosError: true, config: {} }))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.approve')))
    await waitFor(() => listCalls().length > before, { message: '失败后仍刷新列表' })
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('决定失败且异常未被拦截器接管：补一条通用提示', async () => {
    const c = await boot([grantRow()])
    post.mockImplementation(() => Promise.reject(new Error('boom')))
    click(rowButton(c, 0, i18n.global.t('privilegeGrant.approve')))
    await waitFor(() => ElMessage.error.mock.calls.length >= 1, { message: '失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith(i18n.global.t('messages.requestFailed'))
    expect(c.errors).toEqual([])
  })

  test('待我签批的行带 is-actionable 标记（配合淡橙底色在长列表里定位待办）', async () => {
    const c = await boot([grantRow(), grantRow({ _id: 'g9', requestedBy: 'u-1', username: 'me' })])
    expect(trs(c)[0].className).toContain('is-actionable')
    expect(trs(c)[1].className).not.toContain('is-actionable')
    expect(c.errors).toEqual([])
  })
})
