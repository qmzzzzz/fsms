/**
 * UserView 渲染与交互行为（2026-09-18）
 *
 * 为什么写这些用例：UserView 是全仓写入口最多的页面（新增/编辑/分配角色/重置 MFA/删除），
 * 也是权限门控最密集的页面。既有 roleViewPermission.test.js 只做**源码字符串**断言，
 * 源码里写没写 v-if 与「换一组权限挂载后按钮真的消失」是两回事——
 * 例如 v-if 条件写成 || 恒真、门控挂在错误的元素上、权限码拼错（user:update 写成 users:update），
 * 字符串断言都过得去，真实界面却少一个 / 多一个入口。本文件挂载真实组件，
 * 用多组权限集对照断言入口的「有/无」，并覆盖各写操作的真实请求载荷。
 *
 * 期望值一律在本文件内独立给出（权限码写死、载荷字典字面量），
 * 不调用被测代码的 hasPerm / 工具函数——否则门控判据写错时两边一起错。
 *
 * 环境事实（本轮实测）：
 *  - Element Plus 对话框 teleport 到 body，但组件根内也留有 .el-dialog 副本，
 *    关闭后 overlay 的 style.display 变为 'none'（实测需 2 个 rAF 才落地），
 *    故「对话框已关闭」断言用 waitFor 轮询 display，不写死 tick 数。
 *  - 列表行选择器：.el-table__body-wrapper .el-table__row
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const usersGetList = vi.fn()
const usersCreate = vi.fn()
const usersUpdate = vi.fn()
const usersDelete = vi.fn()
const assignRoles = vi.fn()
const rolesGetAll = vi.fn()
const secGetReg = vi.fn()
const secGetLogin = vi.fn()
const secGetRegister = vi.fn()
const secSetReg = vi.fn()
const secSetLogin = vi.fn()
const secSetRegister = vi.fn()
const resetMfa = vi.fn()
const isCanceledError = vi.fn(() => false)
vi.mock('@/utils/api', () => ({
  api: {
    users: {
      getList: (...a) => usersGetList(...a),
      create: (...a) => usersCreate(...a),
      update: (...a) => usersUpdate(...a),
      delete: (...a) => usersDelete(...a),
      assignRoles: (...a) => assignRoles(...a),
    },
    roles: { getAll: (...a) => rolesGetAll(...a) },
    security: {
      getRegistrationConfig: (...a) => secGetReg(...a),
      getLoginCaptchaConfig: (...a) => secGetLogin(...a),
      getRegisterCaptchaConfig: (...a) => secGetRegister(...a),
      setRegistrationConfig: (...a) => secSetReg(...a),
      setLoginCaptchaConfig: (...a) => secSetLogin(...a),
      setRegisterCaptchaConfig: (...a) => secSetRegister(...a),
      resetUserMfa: (...a) => resetMfa(...a),
    },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))
const enc = vi.fn((v) => Promise.resolve('ENC:' + v))
vi.mock('@/utils/loginCipher', () => ({ encryptPassword: (...a) => enc(...a) }))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
const confirmBox = vi.fn()
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: (...a) => confirmBox(...a) },
}))

import UserView from '@/views/UserView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

// 权限码写死在用例里（不是从源码 import）：门控判据被改错时这里必须失败
const P_BASE = ['user:read']
const P_ALL = [
  'user:read',
  'user:create',
  'user:update',
  'role:assign',
  'user:reset_password',
  'user:delete',
  'security:config',
]

const ROW_SELF = {
  _id: 'me',
  username: 'admin',
  email: 'admin@x.com',
  roles: [],
  status: 'active',
  mfaEnabled: true,
}
const ROW_OTHER = {
  _id: 'u2',
  username: 'bob',
  email: 'b@x.com',
  realName: '鲍勃',
  department: '设备科',
  phone: '13900000000',
  allowedIPs: '10.0.0.1',
  roles: [{ _id: 'r1', name: '管理员', code: 'ADMIN' }],
  status: 'inactive',
  mfaEnabled: true,
}
const ROW_NO_MFA = { ...ROW_OTHER, _id: 'u3', username: 'carol', mfaEnabled: false }

let active = null

const rAF = () => new Promise((r) => requestAnimationFrame(() => r()))
/**
 * waitFor 只推进 nextTick，推不动 Element Plus 的过渡（依赖 rAF，实测需 2 帧）。
 * 这里交替推进 nextTick 与 rAF，轮询的是终态，因此既不写死帧数也不会掩盖永久失败。
 */
const waitForDom = async (predicate, message, tries = 60) => {
  for (let i = 0; i < tries; i += 1) {
    if (predicate()) return
    await flush(1)
    await rAF()
  }
  if (predicate()) return
  throw new Error('waitForDom 超时（' + tries + ' 轮 rAF+nextTick）：' + message)
}
/** 等对话框关闭过渡完全落地 */
const settleDom = async () => {
  for (let i = 0; i < 30; i += 1) {
    await flush(1)
    await rAF()
  }
}

/** 权限集 → 挂载 UserView，等列表行渲染完成 */
const mountUser = async (perms, rows = [ROW_OTHER], total = rows.length) => {
  usersGetList.mockResolvedValue({ data: { data: rows, pagination: { total } } })
  secGetReg.mockResolvedValue({ data: { data: { allowPublicRegistration: true } } })
  secGetLogin.mockResolvedValue({ data: { data: { loginCaptchaEnabled: false } } })
  secGetRegister.mockResolvedValue({ data: { data: { registerCaptchaEnabled: true } } })
  rolesGetAll.mockResolvedValue({
    data: {
      data: [
        { _id: 'r1', name: '管理员' },
        { _id: 'r2', name: '巡检员' },
      ],
    },
  })
  active = mountComponent(UserView, {
    setupStore: (pinia) => {
      const s = useAuthStore(pinia)
      // 用 setAuth 一次性写入身份+权限：userId 决定「是否本人」的判定基准
      s.setAuth('t', 'r', { userId: 'me', username: 'admin' }, perms)
    },
  })
  await waitFor(
    () => active.findAll('.el-table__body-wrapper .el-table__row').length === rows.length,
    {
      message: '用户列表行渲染完成',
    }
  )
  await flush(4)
  return active
}

/** 工具栏按钮文本（顺序即渲染顺序） */
const toolbarLabels = (c) => c.findAll('.table-toolbar .glass-btn').map((b) => b.textContent.trim())
/** 第 n 行操作列按钮文本 */
const rowLabels = (c, n) =>
  Array.from(
    c.findAll('.el-table__body-wrapper .el-table__row')[n].querySelectorAll('.glass-btn--link')
  ).map((b) => b.textContent.trim())
/** 行内按钮（按文本） */
const rowBtn = (c, text) =>
  Array.from(c.findAll('.el-table__body-wrapper .glass-btn--link')).find((b) =>
    b.textContent.includes(text)
  )
/** 工具栏按钮（按文本） */
const toolbarBtn = (c, text) =>
  c.findAll('.table-toolbar .glass-btn').find((b) => b.textContent.includes(text))
/** 对话框内的表单控件（label 前缀 → 控件） */
const fieldByLabel = (dlg, label) => {
  const item = Array.from(dlg.querySelectorAll('.el-form-item')).find((i) => {
    const l = i.querySelector('.el-form-item__label')
    return l && l.textContent.trim().startsWith(label)
  })
  return item ? item.querySelector('input, textarea') : null
}
const setField = async (dlg, label, value) => {
  const el = fieldByLabel(dlg, label)
  el.value = value
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(2)
}
/** 对话框页脚按钮（按文本） */
const footerBtn = (dlg, text) =>
  Array.from(dlg.querySelectorAll('.el-dialog__footer .glass-btn')).find((b) =>
    b.textContent.includes(text)
  )
/** 当前打开对话框的 overlay（用于断言关闭） */
const overlayOf = (c) => c.findAll('.el-overlay').find((o) => o.querySelector('.el-dialog__title'))

afterEach(() => {
  active?.handle.unmount()
  active = null
  for (const m of [
    usersGetList,
    usersCreate,
    usersUpdate,
    usersDelete,
    assignRoles,
    rolesGetAll,
    secGetReg,
    secGetLogin,
    secGetRegister,
    secSetReg,
    secSetLogin,
    secSetRegister,
    resetMfa,
    isCanceledError,
    enc,
    confirmBox,
  ]) {
    m.mockReset()
  }
  isCanceledError.mockReturnValue(false)
  enc.mockImplementation((v) => Promise.resolve('ENC:' + v))
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
})
describe('UserView 写入口权限门控（同组件不同权限集对照）', () => {
  test('仅 user:read：工具栏只有刷新，行内无任何写操作入口', async () => {
    const c = await mountUser(P_BASE)
    // 正例先证明渲染确实发生（否则「没有按钮」可能只是因为页面是空的）
    expect(c.findAll('.el-table__body-wrapper .el-table__row')).toHaveLength(1)
    expect(toolbarLabels(c)).toEqual(['刷新'])
    expect(rowLabels(c, 0)).toEqual([])
    expect(c.findAll('.glass-switch')).toEqual([])
    expect(secGetReg).not.toHaveBeenCalled()
    expect(secGetLogin).not.toHaveBeenCalled()
    expect(secGetRegister).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('全权限：工具栏出现新增用户 + 三个开关，行内四类写入口齐备', async () => {
    const c = await mountUser(P_ALL)
    expect(toolbarLabels(c)).toEqual(['新增用户', '刷新'])
    expect(c.findAll('.glass-switch')).toHaveLength(3)
    expect(rowLabels(c, 0)).toEqual(['编辑', '分配角色', '重置MFA', '删除'])
    expect(secGetReg).toHaveBeenCalledTimes(1)
    expect(secGetLogin).toHaveBeenCalledTimes(1)
    expect(secGetRegister).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('缺 user:create：新增按钮消失，但刷新与其余写入口仍在（差异只来自该权限）', async () => {
    const c = await mountUser(P_ALL.filter((p) => p !== 'user:create'))
    expect(toolbarLabels(c)).toEqual(['刷新'])
    expect(rowLabels(c, 0)).toEqual(['编辑', '分配角色', '重置MFA', '删除'])
  })

  test('缺 user:update：编辑入口消失，分配角色/重置MFA/删除仍在', async () => {
    const c = await mountUser(P_ALL.filter((p) => p !== 'user:update'))
    expect(rowLabels(c, 0)).toEqual(['分配角色', '重置MFA', '删除'])
  })

  test('缺 role:assign：分配角色入口消失，编辑/重置MFA/删除仍在', async () => {
    const c = await mountUser(P_ALL.filter((p) => p !== 'role:assign'))
    expect(rowLabels(c, 0)).toEqual(['编辑', '重置MFA', '删除'])
  })

  test('缺 user:reset_password：重置 MFA 入口消失，删除仍在（两个权限不可互相顶替）', async () => {
    const c = await mountUser(P_ALL.filter((p) => p !== 'user:reset_password'))
    expect(rowLabels(c, 0)).toEqual(['编辑', '分配角色', '删除'])
  })

  test('缺 user:delete：删除入口消失，重置MFA 不受影响', async () => {
    const c = await mountUser(P_ALL.filter((p) => p !== 'user:delete'))
    expect(rowLabels(c, 0)).toEqual(['编辑', '分配角色', '重置MFA'])
  })

  test('缺 security:config：开关整块消失且不发配置请求（不产生 403 噪音）', async () => {
    const c = await mountUser(P_ALL.filter((p) => p !== 'security:config'))
    expect(c.findAll('.glass-switch')).toEqual([])
    expect(c.findAll('.glass-switch__label')).toEqual([])
    expect(secGetReg).not.toHaveBeenCalled()
    expect(secGetLogin).not.toHaveBeenCalled()
    expect(secGetRegister).not.toHaveBeenCalled()
    // 有其他权限，页面主体照常
    expect(toolbarLabels(c)).toEqual(['新增用户', '刷新'])
  })

  test('权限码不可错配：user:read 不能代替 user:create（拼错即失败）', async () => {
    const c = await mountUser(['user:read', 'users:create', 'user:update_x'])
    expect(toolbarLabels(c)).toEqual(['刷新'])
    expect(rowLabels(c, 0)).toEqual([])
  })
})

describe('UserView 自伤防护（不得对自己重置 MFA / 删除）', () => {
  test('自己那行不渲染重置MFA与删除；他人行都渲染', async () => {
    const c = await mountUser(P_ALL, [ROW_SELF, ROW_OTHER])
    expect(rowLabels(c, 0)).toEqual(['编辑', '分配角色'])
    expect(rowLabels(c, 1)).toEqual(['编辑', '分配角色', '重置MFA', '删除'])
  })

  test('只给自己一行且权限齐全时，仍不出现重置MFA/删除（不是「他人行恰好没有」）', async () => {
    const c = await mountUser(P_ALL, [ROW_SELF])
    expect(rowLabels(c, 0)).toEqual(['编辑', '分配角色'])
    // 权限本身是有的：点「编辑」能打开对话框，证明是 isSelf 在拦截而不是权限缺失
    click(c.findAll('.el-table__body-wrapper .glass-btn--link')[0])
    await flush(8)
    expect(c.find('.el-dialog__title').textContent.trim()).toBe('编辑用户')
  })

  test('MFA 未开启的他人行不显示重置MFA（避免对无 MFA 账户发无意义请求）', async () => {
    const c = await mountUser(P_ALL, [ROW_NO_MFA])
    expect(rowLabels(c, 0)).toEqual(['编辑', '分配角色', '删除'])
  })
})
describe('UserView 列表与筛选', () => {
  test('首屏请求参数：页码 1、每页 10、空关键字', async () => {
    const c = await mountUser(P_BASE)
    expect(usersGetList).toHaveBeenCalledWith({ page: 1, limit: 10, search: '' })
    expect(c.errors).toEqual([])
  })

  test('数据未回来时显示骨架、隐藏表格；到达后反转', async () => {
    let release
    usersGetList.mockImplementationOnce(
      () =>
        new Promise((r) => {
          release = () => r({ data: { data: [ROW_OTHER], pagination: { total: 1 } } })
        })
    )
    active = mountComponent(UserView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth('t', 'r', { userId: 'me' }, P_BASE),
    })
    await flush(4)
    expect(active.findAll('.glass-skeleton')).toHaveLength(1)
    expect(active.findAll('.el-table')).toHaveLength(0)
    release()
    await waitFor(() => active.findAll('.el-table__body-wrapper .el-table__row').length === 1, {
      message: '数据到达后表格接管',
    })
    expect(active.findAll('.glass-skeleton')).toEqual([])
    expect(active.errors).toEqual([])
  })

  test('翻页：把目标页码与每页条数透传给接口', async () => {
    const c = await mountUser(P_BASE, [ROW_OTHER], 25)
    usersGetList.mockClear()
    click(c.find('.btn-next'))
    await waitFor(() => usersGetList.mock.calls.length === 1, { message: '翻页请求' })
    expect(usersGetList).toHaveBeenCalledWith({ page: 2, limit: 10, search: '' })
  })

  test('搜索防抖：299ms 不发请求，300ms 发一次且回到第 1 页', async () => {
    vi.useFakeTimers()
    try {
      const c = await mountUser(P_BASE, [ROW_OTHER], 25)
      usersGetList.mockClear()
      const input = c.find('.table-toolbar input')
      input.value = 'bob'
      input.dispatchEvent(new window.Event('input', { bubbles: true }))
      await flush(3)
      vi.advanceTimersByTime(299)
      await flush(3)
      expect(usersGetList).not.toHaveBeenCalled()
      vi.advanceTimersByTime(1)
      await waitFor(() => usersGetList.mock.calls.length === 1, { message: '防抖到期发请求' })
      expect(usersGetList).toHaveBeenCalledWith({ page: 1, limit: 10, search: 'bob' })
    } finally {
      vi.useRealTimers()
    }
  })

  test('回车立即搜索：清掉待触发的防抖，只发一次（不重复请求）', async () => {
    vi.useFakeTimers()
    try {
      const c = await mountUser(P_BASE, [ROW_OTHER], 25)
      usersGetList.mockClear()
      const input = c.find('.table-toolbar input')
      input.value = 'bob'
      input.dispatchEvent(new window.Event('input', { bubbles: true }))
      input.dispatchEvent(new window.KeyboardEvent('keyup', { key: 'Enter', bubbles: true }))
      await waitFor(() => usersGetList.mock.calls.length === 1, { message: '回车立即搜索' })
      expect(usersGetList).toHaveBeenCalledWith({ page: 1, limit: 10, search: 'bob' })
      vi.advanceTimersByTime(500)
      await flush(4)
      expect(usersGetList).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  test('竞态守卫：先发的慢响应回来后不得覆盖新结果', async () => {
    let releaseFirst
    let n = 0
    usersGetList.mockImplementation(() => {
      n += 1
      if (n === 1) {
        return new Promise((r) => {
          releaseFirst = () => r({ data: { data: [ROW_SELF], pagination: { total: 1 } } })
        })
      }
      return Promise.resolve({ data: { data: [ROW_OTHER], pagination: { total: 1 } } })
    })
    active = mountComponent(UserView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth('t', 'r', { userId: 'me' }, P_BASE),
    })
    await flush(4)
    click(active.find('.table-toolbar .glass-btn--default'))
    await waitFor(() => active.text().includes('bob'), { message: '第二次响应落地' })
    expect(releaseFirst).toBeTruthy()
    releaseFirst()
    await flush(24)
    expect(active.text()).toContain('bob')
    expect(active.text()).not.toContain('admin')
    expect(active.errors).toEqual([])
  })

  test('在非第一页搜索：先把页码重置回第 1 页再请求（防停留在超范围空页）', async () => {
    const c = await mountUser(P_BASE, [ROW_OTHER], 25)
    click(c.find('.btn-next'))
    await waitFor(() => usersGetList.mock.calls.length === 2, { message: '翻到第 2 页' })
    expect(usersGetList.mock.calls[1][0]).toEqual({ page: 2, limit: 10, search: '' })
    usersGetList.mockClear()
    const input = c.find('.table-toolbar input')
    input.value = 'bob'
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    input.dispatchEvent(new window.KeyboardEvent('keyup', { key: 'Enter', bubbles: true }))
    await waitFor(() => usersGetList.mock.calls.length === 1, { message: '回车搜索' })
    // 第 2 页的页码绝不能带进搜索结果（否则结果不足时会看到空列表）
    expect(usersGetList).toHaveBeenCalledWith({ page: 1, limit: 10, search: 'bob' })
  })

  test('过期的失败响应：不得清空已成功的新列表，也不弹加载失败', async () => {
    let rejectFirst
    let n = 0
    usersGetList.mockImplementation(() => {
      n += 1
      if (n === 1) {
        return new Promise((_resolve, reject) => {
          rejectFirst = () => reject(new Error('slow failure'))
        })
      }
      return Promise.resolve({ data: { data: [ROW_OTHER], pagination: { total: 1 } } })
    })
    active = mountComponent(UserView, {
      setupStore: (pinia) => useAuthStore(pinia).setAuth('t', 'r', { userId: 'me' }, P_BASE),
    })
    await flush(4)
    click(active.find('.table-toolbar .glass-btn--default'))
    await waitFor(() => active.text().includes('bob'), { message: '新请求成功落地' })
    expect(rejectFirst).toBeTruthy()
    rejectFirst()
    await flush(24)
    // 新请求已成功，过期请求的失败不得反过来把列表清空 / 误报错误
    expect(active.findAll('.el-table__body-wrapper .el-table__row')).toHaveLength(1)
    expect(active.text()).toContain('bob')
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(active.errors).toEqual([])
  })

  test('加载失败：清空列表且组件不弹 toast（提示归拦截器，P2-3）；abort 的取消错误静默', async () => {
    const c = await mountUser(P_BASE, [ROW_OTHER])
    expect(c.findAll('.el-table__body-wrapper .el-table__row')).toHaveLength(1)
    usersGetList.mockRejectedValue(new Error('boom'))
    click(c.find('.table-toolbar .glass-btn--default'))
    // 契约对齐 alarmView：加载失败由 api.js 响应拦截器统一提示，组件只清态。
    // 原断言把组件那条 error 钉成契约（`calls.length === 1`），于是双提示被锁死。
    await waitFor(() => c.findAll('.el-table__body-wrapper .el-table__row').length === 0, {
      message: '失败后列表清空',
    })
    expect(ElMessage.error).not.toHaveBeenCalled()
    // 再走一次 abort 分支：同样不得弹错（组件侧本来就不弹）
    isCanceledError.mockReturnValue(true)
    usersGetList.mockRejectedValue(new Error('canceled'))
    click(c.find('.table-toolbar .glass-btn--default'))
    await waitFor(() => isCanceledError.mock.calls.length >= 2, { message: 'abort 分支被走到' })
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})
describe('UserView 新增用户对话框', () => {
  const openAdd = async (c) => {
    click(toolbarBtn(c, '新增用户'))
    await flush(8)
    return c.find('.el-dialog')
  }

  test('标题为新增、展示密码字段；提交发出加密口令与完整载荷（明文口令绝不上行）', async () => {
    usersCreate.mockResolvedValue({ data: { success: true } })
    const c = await mountUser(['user:read', 'user:create'])
    const dlg = await openAdd(c)
    expect(c.find('.el-dialog__title').textContent.trim()).toBe('新增用户')
    expect(fieldByLabel(dlg, '密码')).toBeTruthy()
    await setField(dlg, '用户名', 'newbie01')
    await setField(dlg, '邮箱', 'n@x.com')
    await setField(dlg, '密码', 'Str0ng-Pass_2026')
    await setField(dlg, '真实姓名', '新人')
    click(footerBtn(dlg, '新增'))
    await waitFor(() => usersCreate.mock.calls.length === 1, { message: '创建请求发出' })
    expect(usersCreate).toHaveBeenCalledWith({
      username: 'newbie01',
      email: 'n@x.com',
      realName: '新人',
      department: '',
      phone: '',
      status: 'active',
      allowedIPs: '',
      encPassword: 'ENC:Str0ng-Pass_2026',
    })
    // 明文口令绝不能出现在载荷里（降级轨才允许 password 字段）
    expect(usersCreate.mock.calls[0][0]).not.toHaveProperty('password')
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('创建成功')
  })

  test('提交成功后对话框关闭并刷新列表', async () => {
    usersCreate.mockResolvedValue({ data: { success: true } })
    const c = await mountUser(['user:read', 'user:create'])
    const dlg = await openAdd(c)
    await setField(dlg, '用户名', 'newbie01')
    await setField(dlg, '邮箱', 'n@x.com')
    await setField(dlg, '密码', 'Str0ng-Pass_2026')
    await setField(dlg, '真实姓名', '新人')
    usersGetList.mockClear()
    click(footerBtn(dlg, '新增'))
    await waitFor(() => usersCreate.mock.calls.length === 1, { message: '创建请求' })
    await waitForDom(() => overlayOf(c).style.display === 'none', '对话框关闭（overlay 隐藏）')
    await waitFor(() => usersGetList.mock.calls.length === 1, { message: '成功后刷新列表' })
    expect(active.errors).toEqual([])
  })

  test('校验失败（用户名过短+邮箱非法）：不发请求、不提示成功，表单进入错误态', async () => {
    const c = await mountUser(['user:read', 'user:create'])
    const dlg = await openAdd(c)
    await setField(dlg, '用户名', 'ab')
    await setField(dlg, '邮箱', 'not-an-email')
    await setField(dlg, '密码', 'Str0ng-Pass_2026')
    await setField(dlg, '真实姓名', '新人')
    click(footerBtn(dlg, '新增'))
    await waitFor(() => dlg.querySelectorAll('.el-form-item.is-error').length > 0, {
      message: '表单错误态出现',
    })
    expect(usersCreate).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(footerBtn(dlg, '新增').disabled).toBe(false)
  })

  test('口令加密失败：阻断提交（不发 create、不弹成功），提示加密失败', async () => {
    enc.mockRejectedValueOnce(new Error('crypto down'))
    const c = await mountUser(['user:read', 'user:create'])
    const dlg = await openAdd(c)
    await setField(dlg, '用户名', 'newbie01')
    await setField(dlg, '邮箱', 'n@x.com')
    await setField(dlg, '密码', 'Str0ng-Pass_2026')
    await setField(dlg, '真实姓名', '新人')
    click(footerBtn(dlg, '新增'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '加密失败提示' })
    expect(enc).toHaveBeenCalledWith('Str0ng-Pass_2026')
    expect(usersCreate).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    // 重入锁必须释放：用 waitFor 轮询终态（若永久卡在 disabled，这里会超时失败）
    await waitFor(() => footerBtn(dlg, '新增').disabled === false, {
      message: '加密失败后按钮解锁',
    })
    expect(dlg.querySelectorAll('.el-form-item.is-error')).toHaveLength(0)
  })

  test('提交失败：提示创建失败、对话框保持打开、按钮解锁可重试', async () => {
    usersCreate.mockRejectedValueOnce(new Error('boom'))
    usersCreate.mockResolvedValueOnce({ data: { success: true } })
    const c = await mountUser(['user:read', 'user:create'])
    const dlg = await openAdd(c)
    await setField(dlg, '用户名', 'newbie01')
    await setField(dlg, '邮箱', 'n@x.com')
    await setField(dlg, '密码', 'Str0ng-Pass_2026')
    await setField(dlg, '真实姓名', '新人')
    click(footerBtn(dlg, '新增'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith('创建失败')
    expect(usersCreate).toHaveBeenCalledTimes(1)
    expect(overlayOf(c).style.display).not.toBe('none')
    click(footerBtn(dlg, '新增'))
    await waitFor(() => usersCreate.mock.calls.length === 2, { message: '重试提交' })
    expect(enc).toHaveBeenCalledTimes(2)
  })

  test('取消后重新打开：表单已重置，标题回到新增（不残留上一次输入）', async () => {
    const c = await mountUser(['user:read', 'user:create'])
    const dlg = await openAdd(c)
    await setField(dlg, '用户名', 'draft-user')
    click(footerBtn(dlg, '取消'))
    await settleDom()
    await openAdd(c)
    expect(c.find('.el-dialog__title').textContent.trim()).toBe('新增用户')
    expect(fieldByLabel(c.find('.el-dialog'), '用户名').value).toBe('')
    expect(c.find('#newUserPassword')).toBeTruthy()
  })
})

describe('UserView 编辑用户对话框', () => {
  const openEdit = async (c) => {
    click(rowBtn(c, '编辑'))
    await flush(8)
    return c.find('.el-dialog')
  }

  test('回填该行字段、用户名只读、不出现密码字段（编辑不改密）', async () => {
    const c = await mountUser(['user:read', 'user:update'])
    const dlg = await openEdit(c)
    expect(c.find('.el-dialog__title').textContent.trim()).toBe('编辑用户')
    expect(fieldByLabel(dlg, '用户名').value).toBe('bob')
    expect(fieldByLabel(dlg, '用户名').disabled).toBe(true)
    expect(fieldByLabel(dlg, '邮箱').value).toBe('b@x.com')
    expect(fieldByLabel(dlg, '真实姓名').value).toBe('鲍勃')
    expect(fieldByLabel(dlg, '部门').value).toBe('设备科')
    expect(fieldByLabel(dlg, '手机号').value).toBe('13900000000')
    expect(fieldByLabel(dlg, 'IP 访问范围').value).toBe('10.0.0.1')
    expect(c.find('#newUserPassword')).toBeNull()
  })

  test('提交更新：PUT 到该行 _id，载荷含改后字段、不含密码与角色', async () => {
    usersUpdate.mockResolvedValue({ data: { success: true } })
    const c = await mountUser(['user:read', 'user:update'])
    const dlg = await openEdit(c)
    await setField(dlg, '真实姓名', '鲍勃二世')
    await setField(dlg, '手机号', '13811112222')
    click(footerBtn(dlg, '保存'))
    await waitFor(() => usersUpdate.mock.calls.length === 1, { message: '更新请求' })
    expect(usersUpdate).toHaveBeenCalledWith('u2', {
      username: 'bob',
      email: 'b@x.com',
      realName: '鲍勃二世',
      department: '设备科',
      phone: '13811112222',
      status: 'inactive',
      allowedIPs: '10.0.0.1',
    })
    expect(usersUpdate.mock.calls[0][1]).not.toHaveProperty('password')
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '更新成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('更新成功')
    expect(enc).not.toHaveBeenCalled()
  })

  test('更新失败：提示更新失败且对话框保持打开（与创建失败文案区分）', async () => {
    usersUpdate.mockRejectedValue(new Error('boom'))
    const c = await mountUser(['user:read', 'user:update'])
    const dlg = await openEdit(c)
    click(footerBtn(dlg, '保存'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '更新失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith('更新失败')
    expect(overlayOf(c).style.display).not.toBe('none')
    expect(c.errors).toEqual([])
  })
})

describe('UserView 账户状态呈现（后端三值枚举不得塌缩成两值）', () => {
  /**
   * 为什么单独一组：后端 User.status 是 active/inactive/locked 三值，而状态呈现原先在
   * 表格与编辑下拉各硬编码一份两值判断，被锁定的账户在列表里显示成「禁用」——
   * 管理员禁用（改登录语义）与管理员锁定（可解、连带清 lockUntil）是两种处置，
   * 看错状态会直接导致错误操作。本组把三值逐条钉住，并钉住"未知取值原样显示"的兜底。
   *
   * 期望值写中文终态（不 import 视图里的映射表）：映射表被改错时两边必须一起错才算漏测。
   */

  /** 用例行：状态列之外的标签列清空（roles 为空 → 角色列不渲染 el-tag） */
  const rowWith = (status) => [{ ...ROW_OTHER, roles: [], status }]

  /**
   * 状态列标签。行内 .el-tag 来自三列：角色（本组用例行不渲染）、状态（effect=light）、
   * 两步验证（effect=plain）。按 plain 排除后必须恰好剩一个——
   * 先证明选取口径本身成立，再拿它做断言，避免取到错标签却"恰好通过"。
   */
  const statusTag = (c) => {
    const row = c.findAll('.el-table__body-wrapper .el-table__row')[0]
    const tags = Array.from(row.querySelectorAll('.el-tag')).filter(
      (el) => !el.className.includes('el-tag--plain')
    )
    expect(tags).toHaveLength(1)
    return tags[0]
  }
  const tagType = (el) => /el-tag--(success|info|warning|danger)/.exec(el.className)[1]

  /** EP 的下拉 teleport 到 body，用 aria-hidden 挑出当前可见的那个 */
  const visiblePopper = () =>
    Array.from(document.body.querySelectorAll('.el-popper')).find(
      (el) => el.getAttribute('aria-hidden') === 'false'
    )
  const dropdownItems = () =>
    Array.from(visiblePopper().querySelectorAll('.el-select-dropdown__item')).map((el) => ({
      label: el.textContent.trim(),
      disabled: el.className.includes('is-disabled'),
    }))

  test('locked → 显示「锁定」且为 warning 色，不得显示成「禁用」', async () => {
    const c = await mountUser(P_BASE, rowWith('locked'))
    const tag = statusTag(c)
    expect(tag.textContent.trim()).toBe('锁定')
    expect(tagType(tag)).toBe('warning')
    expect(tag.textContent).not.toContain('禁用')
    expect(c.errors).toEqual([])
  })

  test('对照：active/inactive 的既有呈现没被改动（正常=success、禁用=info）', async () => {
    const c = await mountUser(P_BASE, [
      { ...ROW_OTHER, roles: [], status: 'active', _id: 'a1', username: 'aa' },
      { ...ROW_OTHER, roles: [], status: 'inactive', _id: 'a2', username: 'bb' },
    ])
    const rows = c.findAll('.el-table__body-wrapper .el-table__row')
    const tagAt = (n) => {
      const tags = Array.from(rows[n].querySelectorAll('.el-tag')).filter(
        (el) => !el.className.includes('el-tag--plain')
      )
      expect(tags).toHaveLength(1)
      return tags[0]
    }
    expect(tagAt(0).textContent.trim()).toBe('正常')
    expect(tagType(tagAt(0))).toBe('success')
    expect(tagAt(1).textContent.trim()).toBe('禁用')
    expect(tagType(tagAt(1))).toBe('info')
  })

  test('后端将来加的新枚举值：原样显示，不塌缩成「禁用」', async () => {
    const c = await mountUser(P_BASE, rowWith('pending_review'))
    const tag = statusTag(c)
    expect(tag.textContent.trim()).toBe('pending_review')
    expect(tag.textContent).not.toContain('禁用')
    // 兜底档不得抛异常（映射表查不到就退回原值 + info 默认色）
    expect(c.errors).toEqual([])
  })

  test('编辑对话框：locked 回显为「锁定」，三个选项都在且 locked 置灰不可选', async () => {
    const c = await mountUser(['user:read', 'user:update'], rowWith('locked'))
    click(rowBtn(c, '编辑'))
    await flush(8)
    const dlg = c.find('.el-dialog')
    // 表单里只有状态一个下拉；先钉住这个前提，后面的单元素查询才不是碰运气
    expect(dlg.querySelectorAll('.el-select')).toHaveLength(1)
    const wrapper = dlg.querySelector('.el-select__wrapper')
    // 回显真实值：原先下拉里没有 locked 项，此处显示的是占位符，
    // 而表单里 status 实际是 locked —— 隐值在界面上完全不可见
    expect(wrapper.textContent.trim()).toBe('锁定')

    click(wrapper)
    await waitForDom(() => visiblePopper() && dropdownItems().length === 3, '状态下拉三个选项')
    expect(dropdownItems()).toEqual([
      { label: '正常', disabled: false },
      { label: '禁用', disabled: false },
      { label: '锁定', disabled: true },
    ])

    // 点了也不改：锁定/解锁走专用接口（会清 lockUntil 并写 user_locked 审计），
    // 编辑框能选中 locked 就是开了一条绕过该接口的旁路
    click(
      Array.from(visiblePopper().querySelectorAll('.el-select-dropdown__item')).find((el) =>
        el.className.includes('is-disabled')
      )
    )
    await flush(6)
    expect(wrapper.textContent.trim()).toBe('锁定')
    expect(c.errors).toEqual([])
  })

  test('locked 当前值不因不可选而丢失：保存仍上行 status=locked', async () => {
    usersUpdate.mockResolvedValue({ data: { success: true } })
    const c = await mountUser(['user:read', 'user:update'], rowWith('locked'))
    click(rowBtn(c, '编辑'))
    await flush(8)
    const dlg = c.find('.el-dialog')
    await setField(dlg, '真实姓名', '鲍勃二世')
    click(footerBtn(dlg, '保存'))
    await waitFor(() => usersUpdate.mock.calls.length === 1, { message: '更新请求' })
    expect(usersUpdate).toHaveBeenCalledWith('u2', {
      username: 'bob',
      email: 'b@x.com',
      realName: '鲍勃二世',
      department: '设备科',
      phone: '13900000000',
      status: 'locked',
      allowedIPs: '10.0.0.1',
    })
  })
})

describe('UserView 分配角色对话框', () => {
  const openRole = async (c) => {
    click(rowBtn(c, '分配角色'))
    await flush(8)
    return c.find('.el-dialog')
  }

  test('打开时拉取可选角色并预选该行已有角色', async () => {
    const c = await mountUser(['user:read', 'role:assign'])
    const dlg = await openRole(c)
    expect(rolesGetAll).toHaveBeenCalledTimes(1)
    expect(dlg.textContent).toContain('bob')
    expect(dlg.textContent).toContain('管理员')
  })

  test('保存：PUT 该用户 _id 且 roles 为选中 id 数组；成功后刷新列表并关闭对话框', async () => {
    assignRoles.mockResolvedValue({ data: { success: true } })
    const c = await mountUser(['user:read', 'role:assign'])
    const dlg = await openRole(c)
    usersGetList.mockClear()
    click(footerBtn(dlg, '保存'))
    await waitFor(() => assignRoles.mock.calls.length === 1, { message: '分配角色请求' })
    expect(assignRoles).toHaveBeenCalledWith('u2', { roles: ['r1'] })
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '保存成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('保存成功')
    // 成功后必须刷新列表（否则界面仍显示旧角色，用户会重复操作）
    await waitFor(() => usersGetList.mock.calls.length === 1, { message: '分配角色成功后刷新列表' })
    await waitForDom(() => overlayOf(c).style.display === 'none', '分配角色成功后关闭对话框')
    expect(c.errors).toEqual([])
  })

  test('保存失败：提示保存失败，不误报成功', async () => {
    assignRoles.mockRejectedValue(new Error('boom'))
    const c = await mountUser(['user:read', 'role:assign'])
    const dlg = await openRole(c)
    click(footerBtn(dlg, '保存'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '保存失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith('保存失败')
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  test('回归：清空全部角色后保存按钮禁用（后端 assignRoles 要求 roles min:1）', async () => {
    // 后端 PUT /:id/roles 的校验是 isArray({min:1})：空角色集会 400「请至少分配一个角色」。
    // 与"有角色时可保存并真实发请求"（上一条用例）对照，证明禁用只由空选择驱动，不是恒禁用。
    assignRoles.mockClear()
    const c = await mountUser(['user:read', 'role:assign'], [{ ...ROW_OTHER, roles: [] }])
    const dlg = await openRole(c)
    const save = footerBtn(dlg, '保存')
    expect(save).toBeTruthy()
    expect(save.disabled).toBe(true)
    click(save)
    await flush(6)
    expect(assignRoles, '空角色不得发起请求（点了也只会撞后端 400）').not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })
})

describe('UserView 删除与重置 MFA', () => {
  test('删除：确认文案带用户名，确认后 DELETE 该行 _id 并刷新', async () => {
    usersDelete.mockResolvedValue({ data: { success: true } })
    confirmBox.mockResolvedValue('confirm')
    const c = await mountUser(['user:read', 'user:delete'])
    usersGetList.mockClear()
    click(rowBtn(c, '删除'))
    await waitFor(() => usersDelete.mock.calls.length === 1, { message: '删除请求' })
    expect(confirmBox).toHaveBeenCalledTimes(1)
    expect(confirmBox.mock.calls[0][0]).toContain('bob')
    expect(confirmBox.mock.calls[0][1]).toBe('提示')
    expect(usersDelete).toHaveBeenCalledWith('u2')
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '删除成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('删除成功')
    await waitFor(() => usersGetList.mock.calls.length === 1, { message: '删除后刷新列表' })
  })

  test('删除取消：不发请求、不弹成功也不误报失败', async () => {
    confirmBox.mockRejectedValue('cancel')
    const c = await mountUser(['user:read', 'user:delete'])
    click(rowBtn(c, '删除'))
    await waitFor(() => confirmBox.mock.calls.length === 1, { message: '确认框已弹出' })
    await flush(20)
    expect(usersDelete).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
  })

  test('重置 MFA：确认后 PUT 该用户，成功后提示与删除文案区分', async () => {
    resetMfa.mockResolvedValue({ data: { success: true } })
    confirmBox.mockResolvedValue('confirm')
    const c = await mountUser(['user:read', 'user:reset_password'])
    click(rowBtn(c, '重置MFA'))
    await waitFor(() => resetMfa.mock.calls.length === 1, { message: '重置请求' })
    expect(confirmBox.mock.calls[0][0]).toContain('bob')
    expect(resetMfa).toHaveBeenCalledWith('u2')
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '重置成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('两步验证已重置')
  })

  test('重置 MFA 取消：不发请求、不弹任何提示（静默）', async () => {
    confirmBox.mockRejectedValue('cancel')
    const c = await mountUser(['user:read', 'user:reset_password'])
    click(rowBtn(c, '重置MFA'))
    await waitFor(() => confirmBox.mock.calls.length === 1, { message: '确认框已弹出' })
    await flush(20)
    expect(resetMfa).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
  })
})

describe('UserView 安全开关', () => {
  test('加载配置后按响应渲染开关文案（未开启的显式标 OFF）', async () => {
    const c = await mountUser(P_ALL)
    expect(c.findAll('.glass-switch__label').map((e) => e.textContent.trim())).toEqual([
      '公开注册',
      '登录验证码 OFF',
      '注册验证码 ON',
    ])
  })

  test('点击开关：按翻转后的目标值提交（三个开关各自独立）', async () => {
    secSetReg.mockResolvedValue({ data: { success: true } })
    secSetLogin.mockResolvedValue({ data: { success: true } })
    secSetRegister.mockResolvedValue({ data: { success: true } })
    const c = await mountUser(P_ALL)
    const switches = c.findAll('.glass-switch')
    click(switches[0])
    await waitFor(() => secSetReg.mock.calls.length === 1, { message: '注册开关请求' })
    expect(secSetReg).toHaveBeenCalledWith({ allowPublicRegistration: false })
    click(switches[1])
    await waitFor(() => secSetLogin.mock.calls.length === 1, { message: '登录验证码开关请求' })
    expect(secSetLogin).toHaveBeenCalledWith({ loginCaptchaEnabled: true })
    click(switches[2])
    await waitFor(() => secSetRegister.mock.calls.length === 1, { message: '注册验证码开关请求' })
    expect(secSetRegister).toHaveBeenCalledWith({ registerCaptchaEnabled: false })
    expect(c.findAll('.glass-switch__label').map((e) => e.textContent.trim())).toEqual([
      '禁用',
      '登录验证码 ON',
      '注册验证码 OFF',
    ])
    expect(c.errors).toEqual([])
  })

  test('注册开关失败同样回滚（三个开关各自独立，不能只回滚其中一个）', async () => {
    secSetReg.mockRejectedValue({ response: { data: { message: '服务端拒绝' } } })
    const c = await mountUser(P_ALL)
    const sw = c.findAll('.glass-switch')[0]
    expect(sw.className).toContain('glass-switch--checked')
    click(sw)
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    expect(c.findAll('.glass-switch__label')[0].textContent.trim()).toBe('公开注册')
    expect(c.findAll('.glass-switch')[0].className).toContain('glass-switch--checked')
  })

  test('注册验证码开关失败同样回滚（默认开启的开关失败后必须回到开启态）', async () => {
    secSetRegister.mockRejectedValue({ response: { data: { message: '服务端拒绝' } } })
    const c = await mountUser(P_ALL)
    expect(c.findAll('.glass-switch__label')[2].textContent.trim()).toBe('注册验证码 ON')
    click(c.findAll('.glass-switch')[2])
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    expect(c.findAll('.glass-switch__label')[2].textContent.trim()).toBe('注册验证码 ON')
    expect(c.findAll('.glass-switch')[2].className).toContain('glass-switch--checked')
  })

  test('开关提交失败：状态回滚到原值，并提示服务端 message', async () => {
    secSetLogin.mockRejectedValue({ response: { data: { message: '服务端拒绝' } } })
    const c = await mountUser(P_ALL)
    click(c.findAll('.glass-switch')[1])
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    expect(ElMessage.error).toHaveBeenCalledWith('服务端拒绝')
    expect(c.findAll('.glass-switch__label')[1].textContent.trim()).toBe('登录验证码 OFF')
  })
})

describe('UserView 列表渲染细节', () => {
  test('行内展示用户名/邮箱/角色/状态/MFA（状态映射为文案而非原始值）', async () => {
    const c = await mountUser(P_BASE)
    const cells = Array.from(
      c.findAll('.el-table__body-wrapper .el-table__row')[0].querySelectorAll('td')
    ).map((td) => td.textContent.replace(/\s+/g, ' ').trim())
    expect(cells[1]).toContain('bob')
    expect(cells[1]).toContain('b@x.com')
    expect(cells.some((x) => x === '鲍勃')).toBe(true)
    expect(cells.some((x) => x === '设备科')).toBe(true)
    expect(cells.some((x) => x === '管理员')).toBe(true)
    expect(cells.some((x) => x === '禁用')).toBe(true)
    expect(cells.some((x) => x === '已开启')).toBe(true)
    expect(c.errors).toEqual([])
  })
})
