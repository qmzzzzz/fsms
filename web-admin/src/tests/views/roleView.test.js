/**
 * RoleView 渲染与交互行为（2026-09-18）
 *
 * 与既有 roleViewPermission.test.js 的分工：那份是**源码字符串**断言（锁定 v-if 文本存在），
 * 本文件挂载真实组件，断言**行为**——换一组权限集挂载后入口真的消失/出现、
 * 保存权限真的 PUT 了正确的 id 与载荷、删除当前角色后选中态落到别人身上、
 * WebSocket 广播真的会触发重拉、以及各类确认框的取消分支不产生请求。
 *
 * 期望值在本文件内独立给出（权限码、id、载荷字面量），不 import 被测工具函数。
 * 权限码取自后端路由（src/routes/roleRoutes.js）与视图 `hasPerm(...)` 的调用口径，
 * 少一个字（role:delete → roles:delete）都必须让用例失败。
 *
 * 环境事实（本轮实测）：
 *  - 角色列表项：.glass-role-item；删除按钮：.role-delete-btn（仅非内置 + 有 role:delete 时渲染）
 *  - 权限项按钮：.glass-perm-btn，选中态 class 含 is-on，新增态 is-added
 *  - 对话框 teleport 到 body，组件根内保留副本；关闭后 overlay style.display='none'（需 2 个 rAF）
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h } from 'vue'
import { RouterView } from 'vue-router'
import { mountComponent, flush, click, waitFor, settleRouter } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const rolesGetList = vi.fn()
const rolesGetById = vi.fn()
const rolesGetTree = vi.fn()
const rolesCreate = vi.fn()
const rolesAssignPerm = vi.fn()
const rolesDelete = vi.fn()
const joinRoom = vi.fn()
const onGiveUp = vi.fn()
const wsOn = vi.fn()
const wsOff = vi.fn()
const releaseWs = vi.fn()
const acquireWs = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    roles: {
      getList: (...a) => rolesGetList(...a),
      getById: (...a) => rolesGetById(...a),
      getPermissionTree: (...a) => rolesGetTree(...a),
      create: (...a) => rolesCreate(...a),
      assignPermissions: (...a) => rolesAssignPerm(...a),
      delete: (...a) => rolesDelete(...a),
      getAll: vi.fn(),
      update: vi.fn(),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('@/utils/websocket', () => ({
  acquireWebSocket: (...a) => {
    acquireWs(...a)
    return {
      joinRoom: (...b) => joinRoom(...b),
      onGiveUp: (...b) => onGiveUp(...b),
      on: (...b) => wsOn(...b),
      off: (...b) => wsOff(...b),
    }
  },
  releaseWebSocket: (...a) => releaseWs(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
const confirmBox = vi.fn()
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: (...a) => confirmBox(...a) },
}))
const notify = vi.fn()
vi.mock('element-plus/es/components/notification/index.mjs', () => ({
  ElNotification: (...a) => notify(...a),
}))

import RoleView from '@/views/RoleView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

const P_READ = ['role:read']
const P_ALL = ['role:read', 'role:create', 'role:assign', 'role:delete']

/** 权限树：单模块两条权限（24 位 ObjectId 才会被展平为真实权限节点） */
const TREE = [
  {
    module: 'device',
    name: '设备管理',
    children: [
      {
        _id: 'aaaaaaaaaaaaaaaaaaaaaaaa',
        name: '查看设备',
        code: 'device:read',
        type: 'menu',
        children: [],
      },
      {
        _id: 'bbbbbbbbbbbbbbbbbbbbbbbb',
        name: '新增设备',
        code: 'device:create',
        type: 'button',
        children: [],
      },
    ],
  },
]
const ROLE_BUILTIN = { _id: 'r1', name: '管理员', code: 'ADMIN', userCount: 3, isBuiltIn: true }
const ROLE_PLAIN = { _id: 'r2', name: '巡检员', code: 'INSPECTOR', userCount: 0, isBuiltIn: false }

let active = null
const rAF = () => new Promise((r) => requestAnimationFrame(() => r()))
/** 交替推进 nextTick 与 rAF，轮询终态（Element Plus 过渡依赖 rAF） */
const waitForDom = async (predicate, message, tries = 60) => {
  for (let i = 0; i < tries; i += 1) {
    if (predicate()) return
    await flush(1)
    await rAF()
  }
  if (predicate()) return
  throw new Error('waitForDom 超时（' + tries + ' 轮）：' + message)
}

/** 挂载 RoleView 并等待角色列表 + 权限树落地 */
const mountRole = async (perms, roles = [ROLE_BUILTIN, ROLE_PLAIN], permissionsByRole = null) => {
  rolesGetList.mockResolvedValue({ data: { data: roles } })
  rolesGetTree.mockResolvedValue({ data: { data: TREE } })
  rolesGetById.mockImplementation((id) =>
    Promise.resolve({
      data: {
        data: {
          _id: id,
          name: id,
          permissions: permissionsByRole ? permissionsByRole[id] || [] : [],
        },
      },
    })
  )
  active = mountComponent(RoleView, {
    setupStore: (pinia) => {
      const s = useAuthStore(pinia)
      s.setPermissions(perms)
    },
  })
  if (roles.length > 0) {
    await waitFor(() => active.findAll('.glass-role-item').length === roles.length, {
      message: '角色列表渲染完成',
    })
    await waitFor(() => active.findAll('.glass-module-card').length === TREE.length, {
      message: '权限模块卡片渲染完成',
    })
  } else {
    await waitFor(() => rolesGetList.mock.calls.length >= 1, { message: '角色列表请求' })
  }
  await flush(6)
  return active
}

/**
 * 角色列表项的结构化读取。
 * 注意不能用 textContent.replace(/\s+/g,' ') 再比对整串：模板里各 span 之间没有空白文本节点，
 * 折叠空白不会凭空插入分隔符（实测得到 "管理员ADMIN3用户管理内置角色"），
 * 那样的期望值只能靠猜，读分项才既稳定又能定位退化点。
 */
const itemParts = (c) =>
  c.findAll('.glass-role-item').map((e) => ({
    name: e.querySelector('.glass-role-item__name').textContent.trim(),
    code: e.querySelector('.glass-role-item__code').textContent.trim(),
    count: e.querySelector('.glass-role-item__count').textContent.trim(),
    builtin: e.querySelector('.glass-role-item__builtin')
      ? e.querySelector('.glass-role-item__builtin').textContent.trim()
      : null,
    canDelete: !!e.querySelector('.role-delete-btn'),
  }))
/** 权限项的结构化读取（勾选标记是独立 span，不能与名称混读） */
const permParts = (c) =>
  c.findAll('.glass-perm-btn').map((b) => ({
    name: b.querySelector('.glass-perm-btn__name').textContent.trim(),
    code: b.querySelector('.glass-perm-btn__code').textContent.trim(),
    type: b.querySelector('.glass-perm-btn__type')
      ? b.querySelector('.glass-perm-btn__type').textContent.trim()
      : null,
    badge: b.querySelector('.glass-perm-btn__badge')
      ? b.querySelector('.glass-perm-btn__badge').textContent.trim()
      : null,
    title: b.getAttribute('title'),
  }))
/** 左面板（角色列表）内的按钮，避免与右面板的同名 class 混淆 */
const leftPanelBtns = (c, sel) => c.findAll('.glass-panel--role .panel-header ' + sel)
/** 右面板（权限编辑）内的按钮 */
const rightPanelBtns = (c, sel) => c.findAll('.glass-panel--permission .panel-header ' + sel)
/** 权限项选中态（按渲染顺序） */
const permOn = (c) => c.findAll('.glass-perm-btn').map((b) => b.className.includes('is-on'))
const permAdded = (c) => c.findAll('.glass-perm-btn').map((b) => b.className.includes('is-added'))
const permRemoved = (c) =>
  c.findAll('.glass-perm-btn').map((b) => b.className.includes('is-removed'))
/** 汇总统计条的可见文本 */
const summary = (c) =>
  c.findAll('.perm-summary__item').map((e) => e.textContent.replace(/\s+/g, ' ').trim())
/** 右侧面板标题当前选中的角色名 + 内置标记 */
const roleTags = (c) => c.findAll('.role-tag').map((e) => e.textContent.trim())

afterEach(() => {
  active?.handle.unmount()
  active = null
  for (const m of [
    rolesGetList,
    rolesGetById,
    rolesGetTree,
    rolesCreate,
    rolesAssignPerm,
    rolesDelete,
    joinRoom,
    onGiveUp,
    wsOn,
    wsOff,
    releaseWs,
    acquireWs,
    confirmBox,
    notify,
  ]) {
    m.mockReset()
  }
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
})
describe('RoleView 写入口权限门控（同组件不同权限集对照）', () => {
  test('仅 role:read：新增按钮不可见、列表无删除按钮、右侧无分配权限按钮', async () => {
    const c = await mountRole(P_READ)
    // 先证明页面确实渲染了内容（否则「没有按钮」可能只是空页）
    expect(itemParts(c)).toEqual([
      { name: '管理员', code: 'ADMIN', count: '3用户管理', builtin: '内置角色', canDelete: false },
      { name: '巡检员', code: 'INSPECTOR', count: '0用户管理', builtin: null, canDelete: false },
    ])
    expect(leftPanelBtns(c, '.glass-btn--primary')).toHaveLength(0)
    expect(c.findAll('.role-delete-btn')).toHaveLength(0)
    expect(rightPanelBtns(c, '.glass-btn--primary')).toHaveLength(0)
    expect(c.errors).toEqual([])
  })

  test('全权限：新增、删除、分配权限三个入口齐备；重置按钮始终可见', async () => {
    const c = await mountRole(P_ALL)
    expect(leftPanelBtns(c, '.glass-btn--primary')).toHaveLength(1)
    expect(c.findAll('.role-delete-btn')).toHaveLength(1)
    expect(rightPanelBtns(c, '.glass-btn--primary')).toHaveLength(1)
    expect(rightPanelBtns(c, '.glass-btn--default')).toHaveLength(1)
    expect(c.errors).toEqual([])
  })

  test('缺 role:create：新增与对话框提交按钮都消失，但删除仍在（差异只来自该权限）', async () => {
    const c = await mountRole(P_ALL.filter((p) => p !== 'role:create'))
    expect(leftPanelBtns(c, '.glass-btn--primary')).toHaveLength(0)
    expect(c.findAll('.role-delete-btn')).toHaveLength(1)
    expect(rightPanelBtns(c, '.glass-btn--primary')).toHaveLength(1)
  })

  test('缺 role:assign：分配权限按钮消失，新增/删除仍在', async () => {
    const c = await mountRole(P_ALL.filter((p) => p !== 'role:assign'))
    expect(rightPanelBtns(c, '.glass-btn--primary')).toHaveLength(0)
    expect(leftPanelBtns(c, '.glass-btn--primary')).toHaveLength(1)
    expect(c.findAll('.role-delete-btn')).toHaveLength(1)
  })

  test('缺 role:delete：删除按钮消失，新增/分配权限仍在', async () => {
    const c = await mountRole(P_ALL.filter((p) => p !== 'role:delete'))
    expect(c.findAll('.role-delete-btn')).toHaveLength(0)
    expect(leftPanelBtns(c, '.glass-btn--primary')).toHaveLength(1)
    expect(rightPanelBtns(c, '.glass-btn--primary')).toHaveLength(1)
  })

  test('权限码不可错配：role:read 不能顶替 role:create / role:assign / role:delete', async () => {
    const c = await mountRole(['role:read', 'roles:create', 'role:assign_x'])
    expect(leftPanelBtns(c, '.glass-btn--primary')).toHaveLength(0)
    expect(c.findAll('.role-delete-btn')).toHaveLength(0)
    expect(rightPanelBtns(c, '.glass-btn--primary')).toHaveLength(0)
  })

  test('内置角色不显示删除按钮（即便有 role:delete），非内置角色显示', async () => {
    const c = await mountRole(P_ALL)
    const items = c.findAll('.glass-role-item')
    expect(items[0].querySelector('.role-delete-btn')).toBeNull()
    expect(items[0].querySelector('.glass-role-item__builtin').textContent.trim()).toBe('内置角色')
    expect(items[1].querySelector('.role-delete-btn')).toBeTruthy()
    expect(items[1].querySelector('.glass-role-item__builtin')).toBeNull()
  })
})

describe('RoleView 角色列表与选中态', () => {
  test('首屏自动选中第一个角色并拉取它的权限（勾选态来自接口）', async () => {
    const c = await mountRole(P_READ, [ROLE_BUILTIN, ROLE_PLAIN], {
      r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }],
    })
    expect(rolesGetList).toHaveBeenCalledTimes(1)
    expect(rolesGetTree).toHaveBeenCalledTimes(1)
    expect(rolesGetById).toHaveBeenCalledWith('r1')
    expect(roleTags(c)).toEqual(['管理员', '内置角色'])
    // 第一条权限已勾选、第二条未勾选（权限集来自 getById，而非「全选」）
    expect(permOn(c)).toEqual([true, false])
    expect(summary(c)).toEqual(['权限总数 2', '已启用 1'])
  })

  test('点击另一个角色：切换选中、重拉它的权限，勾选态随之变化', async () => {
    const c = await mountRole(P_READ, [ROLE_BUILTIN, ROLE_PLAIN], {
      r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }],
      r2: [{ _id: 'bbbbbbbbbbbbbbbbbbbbbbbb' }],
    })
    expect(permOn(c)).toEqual([true, false])
    click(c.findAll('.glass-role-item')[1])
    await waitFor(() => rolesGetById.mock.calls.length === 2, { message: '切换角色后重拉权限' })
    await flush(6)
    expect(rolesGetById).toHaveBeenLastCalledWith('r2')
    expect(roleTags(c)).toEqual(['巡检员'])
    expect(permOn(c)).toEqual([false, true])
  })

  test('有未保存修改时切换角色：先确认；取消则留在原角色且不丢编辑，确认才切换', async () => {
    const c = await mountRole(P_READ, [ROLE_BUILTIN, ROLE_PLAIN], {
      r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }],
      r2: [{ _id: 'bbbbbbbbbbbbbbbbbbbbbbbb' }],
    })
    expect(roleTags(c)).toEqual(['管理员', '内置角色'])
    // 制造未保存修改（新增第二条权限）
    click(c.findAll('.glass-perm-btn')[1])
    await flush(4)
    expect(c.find('.unsaved-hint')).toBeTruthy()
    confirmBox.mockRejectedValue('cancel')
    click(c.findAll('.glass-role-item')[1])
    await waitFor(() => confirmBox.mock.calls.length === 1, { message: '未保存变更确认框' })
    await flush(16)
    expect(confirmBox.mock.calls[0][0]).toBe('当前角色有未保存的权限修改，确定要切换吗？')
    expect(confirmBox.mock.calls[0][1]).toBe('提示')
    // 取消：仍停留在原角色，且用户的编辑原样保留（不静默丢弃）
    expect(roleTags(c)).toEqual(['管理员', '内置角色'])
    expect(permOn(c)).toEqual([true, true])
    expect(rolesGetById).toHaveBeenCalledTimes(1)
    expect(c.find('.unsaved-hint')).toBeTruthy()
    // 确认：切到新角色，勾选态换成新角色的权限
    confirmBox.mockResolvedValue('confirm')
    click(c.findAll('.glass-role-item')[1])
    await waitFor(() => roleTags(c).includes('巡检员'), { message: '确认后切换角色' })
    // 等 r2 的权限真正覆盖掉「上一角色的未保存编辑」（否则会读到 [true,true] 的旧态）
    await waitFor(() => permOn(c)[0] === false, { message: '新角色勾选态落地' })
    expect(confirmBox).toHaveBeenCalledTimes(2)
    expect(permOn(c)).toEqual([false, true])
    expect(c.find('.unsaved-hint')).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('切换角色的竞态守卫：先发的慢响应回来后不得覆盖新角色的勾选态', async () => {
    let releaseSlow
    rolesGetList.mockResolvedValue({ data: { data: [ROLE_BUILTIN, ROLE_PLAIN] } })
    rolesGetTree.mockResolvedValue({ data: { data: TREE } })
    rolesGetById.mockImplementation((id) => {
      if (id === 'r1') {
        return new Promise((r) => {
          releaseSlow = () =>
            r({
              data: {
                data: {
                  _id: 'r1',
                  name: '管理员',
                  permissions: [
                    { _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' },
                    { _id: 'bbbbbbbbbbbbbbbbbbbbbbbb' },
                  ],
                },
              },
            })
        })
      }
      return Promise.resolve({
        data: {
          data: { _id: 'r2', name: '巡检员', permissions: [{ _id: 'bbbbbbbbbbbbbbbbbbbbbbbb' }] },
        },
      })
    })
    active = mountComponent(RoleView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(P_READ),
    })
    await waitFor(() => active.findAll('.glass-role-item').length === 2, { message: '列表' })
    await waitFor(() => active.findAll('.glass-module-card').length === 1, { message: '卡片' })
    await flush(4)
    // 点击第二个角色 → 它的响应（快的）先落地
    click(active.findAll('.glass-role-item')[1])
    await waitFor(() => rolesGetById.mock.calls.length === 2, { message: '第二次请求已发' })
    await waitFor(() => permOn(active)[1] === true, { message: '新角色勾选落地' })
    expect(roleTags(active)).toEqual(['巡检员'])
    // 首次（已过期）的响应现在才返回：必须被丢弃，不能改回管理员的全选态
    expect(releaseSlow).toBeTruthy()
    releaseSlow()
    await flush(24)
    expect(roleTags(active)).toEqual(['巡检员'])
    expect(permOn(active)).toEqual([false, true])
    expect(active.errors).toEqual([])
  })

  test('首屏并行加载：权限树先落地、角色权限按正确 id 拉取，卡片与勾选态都渲染出来', async () => {
    // 断言首屏两条并行链路（Promise.all([loadPermissionTree, loadRoles])）的最终一致状态。
    // 说明：loadRolePermissions 内「filteredModules 为空 → 补拉权限树」这段分支经变异验证为
    // **等价变异体**（删掉它最终渲染与勾选态不变：onMounted 自己的 loadPermissionTree 会补上，
    // 且 handleCurrentChange 也会显式重拉树）——故本用例不宣称覆盖该分支。
    const order = []
    rolesGetList.mockResolvedValue({ data: { data: [ROLE_PLAIN] } })
    rolesGetTree.mockImplementation(() => {
      order.push('tree')
      return Promise.resolve({ data: { data: TREE } })
    })
    rolesGetById.mockImplementation((id) => {
      order.push('byId:' + id)
      return Promise.resolve({ data: { data: { _id: id, name: id, permissions: [] } } })
    })
    active = mountComponent(RoleView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(P_READ),
    })
    await waitFor(() => active.findAll('.glass-role-item').length === 1, { message: '列表' })
    await flush(10)
    expect(order[0]).toBe('tree')
    expect(order).toContain('byId:r2')
    // 权限卡片必须真的渲染出来（证明树被 setTree 落地，而不是只调了接口）
    expect(active.findAll('.glass-module-card')).toHaveLength(1)
    expect(active.findAll('.glass-perm-btn')).toHaveLength(2)
    expect(active.errors).toEqual([])
  })

  test('权限树首次加载失败：加载角色权限时会补拉重试（模块区不会永久空白）', async () => {
    // loadRolePermissions 内「filteredModules 为空 → 先 loadPermissionTree」是树首次失败后
    // 唯一的重试路径（onMounted 的 Promise.all 已完成、不会再跑；切角色/广播路径都另有显式重拉）。
    // 删掉该分支 → 首次失败后权限模块区永久空白，用户只能刷新页面。
    let treeCalls = 0
    rolesGetTree.mockImplementation(() => {
      treeCalls += 1
      // 第 1 次失败；第 2 次（补拉重试）成功
      if (treeCalls === 1) return Promise.reject(new Error('tree down'))
      return Promise.resolve({ data: { data: TREE } })
    })
    rolesGetList.mockResolvedValue({ data: { data: [ROLE_PLAIN] } })
    rolesGetById.mockResolvedValue({
      data: { data: { _id: 'r2', name: '巡检员', permissions: [] } },
    })
    active = mountComponent(RoleView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(P_READ),
    })
    await waitFor(() => active.findAll('.glass-module-card').length === 1, {
      message: '补拉重试后权限卡片渲染出来',
    })
    expect(treeCalls).toBeGreaterThanOrEqual(2)
    expect(active.findAll('.glass-perm-btn')).toHaveLength(2)
    expect(active.errors).toEqual([])
  })

  test('列表加载失败：列表清空为空态，不抛 Vue 错误', async () => {
    rolesGetList.mockRejectedValue(new Error('boom'))
    rolesGetTree.mockResolvedValue({ data: { data: TREE } })
    rolesGetById.mockResolvedValue({ data: { data: { permissions: [] } } })
    active = mountComponent(RoleView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(P_READ),
    })
    await waitFor(() => rolesGetList.mock.calls.length === 1, { message: '列表请求' })
    await flush(10)
    expect(active.findAll('.glass-role-item')).toEqual([])
    // 空态：未选中任何角色
    expect(active.find('.empty-state')).toBeTruthy()
    expect(rolesGetById).not.toHaveBeenCalled()
    expect(active.errors).toEqual([])
  })
})
describe('RoleView 权限编辑与保存', () => {
  test('勾选/取消权限：统计实时变化，出现本次新增/移除标记与未保存提示', async () => {
    const c = await mountRole(P_ALL, [ROLE_BUILTIN], {
      r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }],
    })
    expect(summary(c)).toEqual(['权限总数 2', '已启用 1'])
    expect(c.find('.unsaved-hint')).toBeNull()
    // 新增第二条
    click(c.findAll('.glass-perm-btn')[1])
    await flush(4)
    expect(permOn(c)).toEqual([true, true])
    expect(permAdded(c)).toEqual([false, true])
    expect(summary(c)).toEqual(['权限总数 2', '已启用 2', '本次新增 +1'])
    expect(c.find('.unsaved-hint')).toBeTruthy()
    // 取消第一条
    click(c.findAll('.glass-perm-btn')[0])
    await flush(4)
    expect(permOn(c)).toEqual([false, true])
    expect(permRemoved(c)).toEqual([true, false])
    expect(summary(c)).toEqual(['权限总数 2', '已启用 1', '本次新增 +1', '本次移除 -1'])
  })

  test('重置：勾选态回到该角色原始权限，未保存标记清除', async () => {
    const c = await mountRole(P_ALL, [ROLE_BUILTIN], {
      r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }],
    })
    click(c.findAll('.glass-perm-btn')[1])
    await flush(4)
    expect(permOn(c)).toEqual([true, true])
    click(c.findAll('.header-actions .glass-btn--default')[0])
    await flush(4)
    expect(permOn(c)).toEqual([true, false])
    expect(permRemoved(c)).toEqual([false, false])
    expect(summary(c)).toEqual(['权限总数 2', '已启用 1'])
    expect(c.find('.unsaved-hint')).toBeNull()
  })

  test('保存（非内置角色）：PUT 该角色 _id 与勾选 id 数组，成功后刷新勾选态并提示', async () => {
    rolesAssignPerm.mockResolvedValue({ data: { success: true } })
    const c = await mountRole(P_ALL, [ROLE_PLAIN], { r2: [] })
    click(c.findAll('.glass-perm-btn')[0])
    await flush(4)
    click(c.findAll('.header-actions .glass-btn--primary')[0])
    await waitFor(() => rolesAssignPerm.mock.calls.length === 1, { message: '保存请求' })
    expect(rolesAssignPerm).toHaveBeenCalledWith('r2', {
      permissions: ['aaaaaaaaaaaaaaaaaaaaaaaa'],
    })
    expect(confirmBox).not.toHaveBeenCalled()
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '保存成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('保存成功')
    await flush(8)
    expect(c.find('.unsaved-hint')).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('保存空权限集：先弹清空确认；确认后照常提交空数组（临时冻结角色的合法操作）', async () => {
    rolesAssignPerm.mockResolvedValue({ data: { success: true } })
    confirmBox.mockResolvedValue('confirm')
    const c = await mountRole(P_ALL, [ROLE_PLAIN], { r2: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }] })
    // 取消掉唯一一条 → 空集
    click(c.findAll('.glass-perm-btn')[0])
    await flush(4)
    expect(summary(c)).toEqual(['权限总数 2', '已启用 0', '本次移除 -1'])
    click(c.findAll('.header-actions .glass-btn--primary')[0])
    await waitFor(() => rolesAssignPerm.mock.calls.length === 1, { message: '清空请求' })
    expect(confirmBox).toHaveBeenCalledTimes(1)
    expect(confirmBox.mock.calls[0][0]).toContain('移除该角色的全部权限')
    expect(confirmBox.mock.calls[0][1]).toBe('清空权限确认')
    expect(rolesAssignPerm).toHaveBeenCalledWith('r2', { permissions: [] })
  })

  test('保存空权限集时取消确认：不发请求，未保存状态保留（用户可继续编辑）', async () => {
    confirmBox.mockRejectedValue('cancel')
    const c = await mountRole(P_ALL, [ROLE_PLAIN], { r2: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }] })
    click(c.findAll('.glass-perm-btn')[0])
    await flush(4)
    click(c.findAll('.header-actions .glass-btn--primary')[0])
    await waitFor(() => confirmBox.mock.calls.length === 1, { message: '清空确认框' })
    await flush(16)
    expect(rolesAssignPerm).not.toHaveBeenCalled()
    expect(c.find('.unsaved-hint')).toBeTruthy()
    // 重入锁已释放：能再次点击保存
    await waitFor(() => c.findAll('.header-actions .glass-btn--primary')[0].disabled === false, {
      message: '取消防确认后按钮解锁',
    })
  })

  test('内置角色保存：额外弹内置变更确认；取消则不提交，确认才提交', async () => {
    rolesAssignPerm.mockResolvedValue({ data: { success: true } })
    const c = await mountRole(P_ALL, [ROLE_BUILTIN], { r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }] })
    click(c.findAll('.glass-perm-btn')[1])
    await flush(4)
    confirmBox.mockRejectedValueOnce('cancel')
    click(c.findAll('.header-actions .glass-btn--primary')[0])
    await waitFor(() => confirmBox.mock.calls.length === 1, { message: '内置确认框' })
    await flush(16)
    expect(rolesAssignPerm).not.toHaveBeenCalled()
    expect(confirmBox.mock.calls[0][1]).toBe('内置角色变更确认')
    expect(confirmBox.mock.calls[0][0]).toContain('影响所有持有该角色的用户')
    // 再点一次并确认：这次提交
    click(c.findAll('.header-actions .glass-btn--primary')[0])
    await waitFor(() => rolesAssignPerm.mock.calls.length === 1, { message: '确认后提交' })
    expect(rolesAssignPerm).toHaveBeenCalledWith('r1', {
      permissions: ['aaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbb'],
    })
  })

  test('保存失败：提示由拦截器负责，未保存状态保留（不清空勾选，用户不必重做）', async () => {
    rolesAssignPerm.mockRejectedValue(new Error('boom'))
    const c = await mountRole(P_ALL, [ROLE_PLAIN], { r2: [] })
    click(c.findAll('.glass-perm-btn')[0])
    await flush(4)
    click(c.findAll('.header-actions .glass-btn--primary')[0])
    await waitFor(() => rolesAssignPerm.mock.calls.length === 1, { message: '保存请求' })
    await flush(16)
    expect(permOn(c)).toEqual([true, false])
    expect(c.find('.unsaved-hint')).toBeTruthy()
    await waitFor(() => c.findAll('.header-actions .glass-btn--primary')[0].disabled === false, {
      message: '失败后按钮解锁可重试',
    })
    expect(c.errors).toEqual([])
  })
})

describe('RoleView 权限搜索', () => {
  test('搜索命中/未命中：模块与权限项被过滤，未命中显示空态文案', async () => {
    const c = await mountRole(P_READ)
    const input = c.find('.perm-search input')
    input.value = '新增'
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(6)
    expect(c.findAll('.glass-module-card')).toHaveLength(1)
    expect(permParts(c)).toEqual([
      {
        name: '新增设备',
        code: 'device:create',
        type: '操作',
        badge: null,
        title: 'device:create · 操作',
      },
    ])
    input.value = 'zzz-no-match'
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(6)
    expect(c.findAll('.glass-module-card')).toHaveLength(0)
    expect(c.find('.perm-empty-search').textContent.replace(/\s+/g, ' ').trim()).toBe(
      '未找到匹配的权限「zzz-no-match」'
    )
  })
})
describe('RoleView 新增角色对话框', () => {
  test('打开对话框：标题为新增角色，提交按钮由 role:create 门控', async () => {
    const c = await mountRole(P_ALL)
    click(c.findAll('.panel-header .glass-btn--primary')[0])
    await flush(8)
    const dlg = c.find('.el-dialog')
    expect(dlg.querySelector('.el-dialog__title').textContent.trim()).toBe('新增角色')
    expect(
      Array.from(dlg.querySelectorAll('.el-dialog__footer .glass-btn')).map((b) =>
        b.textContent.trim()
      )
    ).toEqual(['取消', '新增'])
  })

  test('角色编码即时归一：小写与非法字符被转成大写合法编码后才提交', async () => {
    rolesCreate.mockResolvedValue({
      data: { data: { _id: 'r9', name: '夜班巡检', code: 'NIGHT_PATROL' } },
    })
    const c = await mountRole(P_ALL, [ROLE_BUILTIN, ROLE_PLAIN])
    rolesGetList.mockResolvedValue({
      data: {
        data: [
          ROLE_BUILTIN,
          ROLE_PLAIN,
          { _id: 'r9', name: '夜班巡检', code: 'NIGHT_PATROL', userCount: 0, isBuiltIn: false },
        ],
      },
    })
    click(c.findAll('.panel-header .glass-btn--primary')[0])
    await flush(8)
    const dlg = c.find('.el-dialog')
    const nameInput = dlg.querySelector('#roleName')
    nameInput.value = '夜班巡检'
    nameInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    const codeInput = dlg.querySelector('#roleCode')
    codeInput.value = 'night-patrol!46'
    codeInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(6)
    // 即时归一：非法字符被剔除、字母转大写
    expect(codeInput.value).toBe('NIGHTPATROL')
    click(
      Array.from(dlg.querySelectorAll('.el-dialog__footer .glass-btn')).find((b) =>
        b.textContent.includes('新增')
      )
    )
    await waitFor(() => rolesCreate.mock.calls.length === 1, { message: '创建请求' })
    expect(rolesCreate).toHaveBeenCalledWith({
      name: '夜班巡检',
      code: 'NIGHTPATROL',
      description: '',
    })
    expect(ElMessage.success).toHaveBeenCalledWith('创建成功')
  })

  test('创建成功后：对话框关闭、列表重拉并把新角色设为当前选中', async () => {
    rolesCreate.mockResolvedValue({
      data: { data: { _id: 'r9', name: '夜班巡检', code: 'NIGHT_PATROL' } },
    })
    const c = await mountRole(P_ALL, [ROLE_BUILTIN, ROLE_PLAIN])
    rolesGetList.mockResolvedValue({
      data: {
        data: [
          ROLE_BUILTIN,
          ROLE_PLAIN,
          { _id: 'r9', name: '夜班巡检', code: 'NIGHT_PATROL', userCount: 0, isBuiltIn: false },
        ],
      },
    })
    click(c.findAll('.panel-header .glass-btn--primary')[0])
    await flush(8)
    const dlg = c.find('.el-dialog')
    const nameInput = dlg.querySelector('#roleName')
    nameInput.value = '夜班巡检'
    nameInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    const codeInput = dlg.querySelector('#roleCode')
    codeInput.value = 'NIGHT_PATROL'
    codeInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(6)
    click(
      Array.from(dlg.querySelectorAll('.el-dialog__footer .glass-btn')).find((b) =>
        b.textContent.includes('新增')
      )
    )
    await waitFor(() => rolesGetById.mock.calls.some((x) => x[0] === 'r9'), {
      message: '新角色权限被拉取',
    })
    await flush(8)
    // 新角色成为当前选中（右侧面板）
    expect(roleTags(c)).toEqual(['夜班巡检'])
    // 对话框已关闭
    const overlay = c.findAll('.el-overlay').find((o) => o.querySelector('.el-dialog__title'))
    await waitForDom(() => overlay.style.display === 'none', '创建成功后对话框关闭')
    expect(c.errors).toEqual([])
  })

  test('校验失败（名称/编码为空）：不发请求，表单进入错误态', async () => {
    const c = await mountRole(P_ALL)
    click(c.findAll('.panel-header .glass-btn--primary')[0])
    await flush(8)
    const dlg = c.find('.el-dialog')
    click(
      Array.from(dlg.querySelectorAll('.el-dialog__footer .glass-btn')).find((b) =>
        b.textContent.includes('新增')
      )
    )
    await waitFor(() => dlg.querySelectorAll('.el-form-item.is-error').length > 0, {
      message: '必填错误态',
    })
    expect(rolesCreate).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  test('创建失败：不误报成功，对话框保持打开可重试', async () => {
    rolesCreate.mockRejectedValue(new Error('boom'))
    const c = await mountRole(P_ALL)
    click(c.findAll('.panel-header .glass-btn--primary')[0])
    await flush(8)
    const dlg = c.find('.el-dialog')
    const nameInput = dlg.querySelector('#roleName')
    nameInput.value = '夜班巡检'
    nameInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    const codeInput = dlg.querySelector('#roleCode')
    codeInput.value = 'NIGHT_PATROL'
    codeInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(6)
    click(
      Array.from(dlg.querySelectorAll('.el-dialog__footer .glass-btn')).find((b) =>
        b.textContent.includes('新增')
      )
    )
    await waitFor(() => rolesCreate.mock.calls.length === 1, { message: '创建请求' })
    await flush(16)
    expect(ElMessage.success).not.toHaveBeenCalled()
    const overlay = c.findAll('.el-overlay').find((o) => o.querySelector('.el-dialog__title'))
    expect(overlay.style.display).not.toBe('none')
    await waitForDom(
      () =>
        Array.from(dlg.querySelectorAll('.el-dialog__footer .glass-btn')).find((b) =>
          b.textContent.includes('新增')
        ).disabled === false,
      '失败后提交按钮解锁'
    )
  })
})

describe('RoleView 删除角色', () => {
  test('删除非当前角色：确认后 DELETE 该 id，列表重拉但选中态不变', async () => {
    rolesDelete.mockResolvedValue({ data: { success: true } })
    confirmBox.mockResolvedValue('confirm')
    const c = await mountRole(P_ALL)
    expect(roleTags(c)).toEqual(['管理员', '内置角色'])
    rolesGetList.mockResolvedValue({ data: { data: [ROLE_BUILTIN] } })
    click(c.find('.role-delete-btn'))
    await waitFor(() => rolesDelete.mock.calls.length === 1, { message: '删除请求' })
    expect(confirmBox.mock.calls[0][0]).toContain('巡检员')
    expect(rolesDelete).toHaveBeenCalledWith('r2')
    await waitFor(() => c.findAll('.glass-role-item').length === 1, { message: '列表重拉' })
    expect(roleTags(c)).toEqual(['管理员', '内置角色'])
    expect(ElMessage.success).toHaveBeenCalledWith('删除成功')
  })

  test('删除当前选中角色：选中态清空后自动落到剩下的第一个角色（不残留已删角色）', async () => {
    rolesDelete.mockResolvedValue({ data: { success: true } })
    confirmBox.mockResolvedValue('confirm')
    // 初始选中 r1（内置，无删除按钮）；手动切到 r2 再删它
    const c = await mountRole(P_ALL, [ROLE_BUILTIN, ROLE_PLAIN], {
      r1: [],
      r2: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }],
    })
    click(c.findAll('.glass-role-item')[1])
    await waitFor(() => roleTags(c).includes('巡检员'), { message: '切到 r2' })
    // 等 r2 的权限勾选真正落地（getById 是异步的，只等 currentRole 变会读到上一角色的勾选态）
    await waitFor(() => permOn(c)[0] === true, { message: 'r2 勾选态落地' })
    expect(permOn(c)).toEqual([true, false])
    rolesGetList.mockResolvedValue({ data: { data: [ROLE_BUILTIN] } })
    click(c.findAll('.role-delete-btn')[0])
    await waitFor(() => rolesDelete.mock.calls.length === 1, { message: '删除请求' })
    expect(rolesDelete).toHaveBeenCalledWith('r2')
    await waitFor(() => roleTags(c).includes('管理员'), { message: '选中态落到剩余角色' })
    expect(c.findAll('.glass-role-item')).toHaveLength(1)
    // 已删角色的勾选态必须被清掉，不能残留到新选中的角色上
    expect(permOn(c)).toEqual([false, false])
    expect(c.find('.unsaved-hint')).toBeNull()
  })

  test('删除取消：不发请求、不弹成功', async () => {
    confirmBox.mockRejectedValue('cancel')
    const c = await mountRole(P_ALL)
    click(c.find('.role-delete-btn'))
    await waitFor(() => confirmBox.mock.calls.length === 1, { message: '确认框' })
    await flush(16)
    expect(rolesDelete).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(c.findAll('.glass-role-item')).toHaveLength(2)
  })

  test('删除按钮点击不冒泡成「选中该行」（停止传播）', async () => {
    rolesDelete.mockResolvedValue({ data: { success: true } })
    confirmBox.mockResolvedValue('confirm')
    const c = await mountRole(P_ALL)
    expect(roleTags(c)).toEqual(['管理员', '内置角色'])
    click(c.find('.role-delete-btn'))
    await waitFor(() => rolesDelete.mock.calls.length === 1, { message: '删除请求' })
    await flush(12)
    expect(rolesGetById.mock.calls.map((x) => x[0])).toEqual(['r1'])
    expect(roleTags(c)).toEqual(['管理员', '内置角色'])
  })
})
describe('RoleView 未保存变更的离开防护', () => {
  test('有未保存修改时刷新页面：beforeunload 被 preventDefault；无修改时不拦截', async () => {
    const c = await mountRole(P_READ)
    const before = new window.Event('beforeunload', { cancelable: true })
    window.dispatchEvent(before)
    expect(before.defaultPrevented).toBe(false)
    click(c.findAll('.glass-perm-btn')[0])
    await flush(4)
    expect(c.find('.unsaved-hint')).toBeTruthy()
    const after = new window.Event('beforeunload', { cancelable: true })
    window.dispatchEvent(after)
    expect(after.defaultPrevented).toBe(true)
  })

  test('卸载后不再拦截 beforeunload（监听被摘掉，不泄漏）', async () => {
    const c = await mountRole(P_READ)
    click(c.findAll('.glass-perm-btn')[0])
    await flush(4)
    c.handle.unmount()
    active = null
    const ev = new window.Event('beforeunload', { cancelable: true })
    window.dispatchEvent(ev)
    expect(ev.defaultPrevented).toBe(false)
  })

  test('路由离开：有未保存修改先确认；取消则留在原路由，确认才放行', async () => {
    const Host = defineComponent({ render: () => h(RouterView) })
    const routes = [
      { path: '/roles', component: RoleView },
      { path: '/other', component: { render: () => null } },
    ]
    rolesGetList.mockResolvedValue({ data: { data: [ROLE_BUILTIN] } })
    rolesGetTree.mockResolvedValue({ data: { data: TREE } })
    rolesGetById.mockResolvedValue({
      data: { data: { _id: 'r1', name: '管理员', permissions: [] } },
    })
    active = mountComponent(Host, {
      routes,
      initialRoute: '/roles',
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(P_READ),
    })
    await waitFor(() => active.findAll('.glass-module-card').length === 1, { message: '卡片' })
    await flush(4)
    click(active.findAll('.glass-perm-btn')[0])
    await flush(4)
    expect(active.find('.unsaved-hint')).toBeTruthy()
    confirmBox.mockRejectedValue('cancel')
    active.router.push('/other').catch(() => {})
    await settleRouter(active.router)
    await flush(12)
    expect(active.router.currentRoute.value.path).toBe('/roles')
    expect(confirmBox).toHaveBeenCalledTimes(1)
    confirmBox.mockResolvedValue('confirm')
    active.router.push('/other').catch(() => {})
    await settleRouter(active.router)
    await flush(12)
    expect(active.router.currentRoute.value.path).toBe('/other')
    expect(confirmBox).toHaveBeenCalledTimes(2)
  })
})

describe('RoleView 实时推送（WebSocket）接线', () => {
  test('挂载：加入 role-management 房间、注册三个回调，并注册放弃重连提示', async () => {
    const c = await mountRole(P_READ)
    expect(acquireWs).toHaveBeenCalledTimes(1)
    expect(joinRoom).toHaveBeenCalledWith('role-management')
    expect(onGiveUp).toHaveBeenCalledTimes(1)
    expect(wsOn.mock.calls.map((x) => x[0])).toEqual(['role-updated', 'permissions-updated'])
    // 放弃重连必须给出不自动消失的警示（duration=0），否则用户会误信过期数据
    const giveUp = onGiveUp.mock.calls[0][0]
    giveUp()
    await flush(2)
    expect(notify).toHaveBeenCalledTimes(1)
    expect(notify.mock.calls[0][0]).toMatchObject({ type: 'warning', duration: 0 })
    expect(notify.mock.calls[0][0].message).toBe(
      '实时推送连接已中断，当前页面数据可能不是最新。请刷新页面恢复。'
    )
    expect(c.errors).toEqual([])
  })

  test('收到 role-updated：重拉角色列表；收到 permissions-updated：重拉权限树与当前角色权限', async () => {
    const c = await mountRole(P_READ)
    const roleUpdated = wsOn.mock.calls.find((x) => x[0] === 'role-updated')[1]
    const permsUpdated = wsOn.mock.calls.find((x) => x[0] === 'permissions-updated')[1]
    rolesGetList.mockClear()
    rolesGetTree.mockClear()
    rolesGetById.mockClear()
    roleUpdated()
    await waitFor(() => rolesGetList.mock.calls.length === 1, {
      message: 'role-updated 触发列表重拉',
    })
    expect(rolesGetTree).not.toHaveBeenCalled()
    permsUpdated()
    await waitFor(() => rolesGetTree.mock.calls.length === 1, {
      message: 'permissions-updated 触发权限树重拉',
    })
    await waitFor(() => rolesGetById.mock.calls.length === 1, {
      message: 'permissions-updated 重拉当前角色权限',
    })
    expect(rolesGetById).toHaveBeenCalledWith('r1')
    expect(c.errors).toEqual([])
  })

  test('卸载：只解绑本页监听并释放一次引用（不拆掉布局层的订阅）', async () => {
    const c = await mountRole(P_READ)
    c.handle.unmount()
    active = null
    expect(wsOff.mock.calls.map((x) => x[0])).toEqual(['role-updated', 'permissions-updated'])
    expect(releaseWs).toHaveBeenCalledTimes(1)
  })
})

describe('RoleView 权限面板渲染细节', () => {
  test('模块卡片显示模块名/启用计数/百分比，权限项显示名称+编码+类型', async () => {
    const c = await mountRole(P_READ, [ROLE_BUILTIN], {
      r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }],
    })
    const card = c.find('.glass-module-card')
    expect(card.querySelector('.glass-module-card__name').textContent.trim()).toBe('设备管理')
    expect(
      card.querySelector('.glass-module-card__count').textContent.replace(/\s+/g, ' ').trim()
    ).toBe('已启用 1 / 2 (50%)')
    expect(card.querySelector('.glass-module-card__state').textContent.trim()).toBe('部分启用')
    expect(permParts(c)).toEqual([
      {
        name: '查看设备',
        code: 'device:read',
        type: '菜单',
        badge: null,
        title: 'device:read · 菜单',
      },
      {
        name: '新增设备',
        code: 'device:create',
        type: '操作',
        badge: null,
        title: 'device:create · 操作',
      },
    ])
  })

  test('权限全选时模块态为已全选、按钮文案切换为清空本模块', async () => {
    const c = await mountRole(P_READ, [ROLE_BUILTIN], {
      r1: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa' }, { _id: 'bbbbbbbbbbbbbbbbbbbbbbbb' }],
    })
    const card = c.find('.glass-module-card')
    expect(card.querySelector('.glass-module-card__state').textContent.trim()).toBe('已全选')
    expect(card.querySelector('.module-toggle-btn').textContent.trim()).toBe('清空本模块')
    expect(
      card.querySelector('.glass-module-card__count').textContent.replace(/\s+/g, ' ').trim()
    ).toBe('已启用 2 / 2 (100%)')
  })

  test('未选中任何角色时不渲染权限面板主体（空态提示）', async () => {
    rolesGetList.mockResolvedValue({ data: { data: [] } })
    rolesGetTree.mockResolvedValue({ data: { data: TREE } })
    rolesGetById.mockResolvedValue({ data: { data: { permissions: [] } } })
    active = mountComponent(RoleView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(P_READ),
    })
    await flush(12)
    expect(active.find('.empty-state')).toBeTruthy()
    expect(active.find('.empty-state').textContent).toContain('请从左侧选择一个角色进行权限分配')
    expect(active.findAll('.glass-module-card')).toEqual([])
    expect(active.findAll('.perm-summary__item')).toEqual([])
  })

  test('权限树接口失败：模块区为空但不抛 Vue 错误，页面其余部分可用', async () => {
    rolesGetList.mockResolvedValue({ data: { data: [ROLE_PLAIN] } })
    rolesGetTree.mockRejectedValue(new Error('tree down'))
    rolesGetById.mockResolvedValue({
      data: { data: { _id: 'r2', name: '巡检员', permissions: [] } },
    })
    active = mountComponent(RoleView, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(P_READ),
    })
    await waitFor(() => active.findAll('.glass-role-item').length === 1, { message: '角色列表' })
    await flush(12)
    expect(active.findAll('.glass-module-card')).toEqual([])
    expect(roleTags(active)).toEqual(['巡检员'])
    expect(active.find('.perm-empty-search')).toBeTruthy()
    expect(active.errors).toEqual([])
  })
})
