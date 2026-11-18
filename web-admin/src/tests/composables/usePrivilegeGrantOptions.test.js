/**
 * usePrivilegeGrantOptions 行为测试（授权候选项加载域）
 *
 * 锁定契约（2026-11-17 审计 B-DRY 收口后 + 基本行为）：
 *  1. 权限目录展平语义：嵌套权限下钻、虚拟分组节点跳过自身但下钻、
 *     按 code 去重（授权载荷的身份域是 code）、无 code 不收录、
 *     保留通配码（*:*）进 permissionMap 但不渲染进分组选项；
 *  2. 模块名/图标走共享目录（utils/permissionCatalog）单一来源：
 *     已知模块给翻译与专属图标，未知模块回退后端 name / module 码与 📦；
 *  3. 权限门禁：无 permission:read|permission:tree 时目录 unavailable，不发请求；
 *  4. 目录接口失败：unavailable（非取消错误）；
 *  5. 用户候选：无 user:read 时 unavailable；成功按用户名排序并写入 userCache；
 *     首次加载失败退回 unavailable（手填用户 ID 兜底）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, h, createApp } from 'vue'
import i18n from '@/i18n'

const usersGetList = vi.fn()
const getPermissionTree = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    users: { getList: (...a) => usersGetList(...a) },
    roles: { getPermissionTree: (...a) => getPermissionTree(...a) },
  },
  isCanceledError: (e) => e?.name === 'CanceledError',
}))

// 必须在 mock 之后动态导入被测模块
const { usePrivilegeGrantOptions } = await import('@/composables/usePrivilegeGrantOptions')

const oid = (n) => String(n).padStart(24, '0')

/** 权限树 fixture：嵌套权限 / 虚拟分组 / 重复 code / 无 code / 通配码 / 空洞模块 */
const TREE = [
  {
    module: 'device',
    name: '设备管理',
    children: [
      {
        _id: oid(1),
        code: 'device:read',
        name: '设备查看',
        type: 'menu',
        children: [
          // 权限挂权限：子权限的 parent 是另一个权限而非模块
          { _id: oid(11), code: 'device:maintain', name: '设备维护', type: 'button' },
          // 虚拟分组节点：_id 非 ObjectId，跳过自身但下钻子级
          {
            _id: 'group-1',
            name: '定位分组',
            children: [{ _id: oid(12), code: 'device:locate', name: '设备定位', type: 'api' }],
          },
        ],
      },
      { _id: oid(2), code: 'device:write', name: '设备编辑', type: 'menu' },
      // 与 oid(1) 同 code：按 code 去重只保留首个
      { _id: oid(3), code: 'device:read', name: '设备查看副本', type: 'api' },
      // 无 code：对授权无意义，不收录
      { _id: oid(4), name: '无编码节点', type: 'api' },
    ],
  },
  {
    module: 'privilege',
    name: '特权管理',
    children: [
      { _id: oid(21), code: '*:*', name: '通配', type: 'menu' },
      { _id: oid(22), code: 'privilege:grant', name: '授权', type: 'button' },
    ],
  },
  // 空洞模块元素：必须被滤掉而不是抛 TypeError
  null,
]

let mounted = []
/** 在真实组件生命周期 + 真实 i18n 内运行 composable（内部依赖 useI18n） */
const mountOptions = (hasPerm = () => true) => {
  let api = null
  const Host = defineComponent({
    setup() {
      api = usePrivilegeGrantOptions({ hasPerm })
      return () => h('div')
    },
  })
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp(Host)
  app.use(i18n)
  app.mount(root)
  const handle = {
    api: () => api,
    unmount: () => {
      if (handle.done) return
      handle.done = true
      app.unmount()
      root.remove()
    },
  }
  mounted.push(handle)
  return handle
}

beforeEach(() => {
  i18n.global.locale.value = 'zh-CN'
})

afterEach(() => {
  mounted.forEach((m) => m.unmount())
  mounted = []
  usersGetList.mockReset()
  getPermissionTree.mockReset()
})

describe('usePrivilegeGrantOptions 权限目录', () => {
  test('展平语义：嵌套下钻、虚拟分组跳过、code 去重、无 code 不收录、空洞模块滤除', async () => {
    getPermissionTree.mockResolvedValue({ data: { data: TREE } })
    const c = mountOptions()
    await c.api().loadPermissionCatalog()

    expect(c.api().permissionState.value).toBe('ready')
    const groups = c.api().permissionGroups.value
    expect(groups.map((g) => g.module)).toEqual(['device', 'privilege'])

    const device = groups[0]
    expect(device.permissions.map((p) => p.code)).toEqual([
      'device:read',
      'device:maintain',
      'device:locate',
      'device:write',
    ])
    // 去重保留首个：device:read 是 oid(1)（「设备查看副本」oid(3) 被去重）
    expect(device.permissions[0]._id).toBe(oid(1))
    // tagModule：节点补上所属顶层模块
    expect(device.permissions.every((p) => p.module === 'device')).toBe(true)
  })

  test('通配码：进 permissionMap（老记录详情要显名）但不渲染进分组选项', async () => {
    getPermissionTree.mockResolvedValue({ data: { data: TREE } })
    const c = mountOptions()
    await c.api().loadPermissionCatalog()

    expect(c.api().permissionMap.value.has('*:*')).toBe(true)
    expect(c.api().permissionMap.value.get('device:read')._id).toBe(oid(1))
    const privilegeGroup = c.api().permissionGroups.value[1]
    expect(privilegeGroup.permissions.map((p) => p.code)).toEqual(['privilege:grant'])
  })

  test('模块名与图标走共享目录：已知模块给翻译/专属图标，未知模块回退后端名与 📦', async () => {
    getPermissionTree.mockResolvedValue({ data: { data: TREE } })
    const c = mountOptions()
    await c.api().loadPermissionCatalog()

    const groups = c.api().permissionGroups.value
    expect(groups[0].name).toBe('设备管理') // t('nav.devices')
    expect(groups[1].name).toBe('临时授权管理') // t('nav.privilegeGrants')
    expect(groups[0].icon).toBe('🔧')
    expect(groups[1].icon).toBe('🎫')

    // 未知模块：优先后端 name，缺 name 退 module 码；图标退 📦
    expect(c.api().moduleName({ module: 'nope', name: '后端名' })).toBe('后端名')
    expect(c.api().moduleName({ module: 'nope', name: '' })).toBe('nope')
    expect(c.api().moduleName({ module: 'pii', name: 'x' })).toBe('敏感数据导出')
  })

  test('无 permission:read|permission:tree：目录 unavailable，不发请求', async () => {
    const c = mountOptions(() => false)
    await c.api().loadPermissionCatalog()
    expect(c.api().permissionState.value).toBe('unavailable')
    expect(getPermissionTree).not.toHaveBeenCalled()
  })

  test('目录接口失败（非取消）：unavailable，不抛错', async () => {
    getPermissionTree.mockRejectedValue(new Error('tree down'))
    const c = mountOptions()
    await expect(c.api().loadPermissionCatalog()).resolves.toBeUndefined()
    expect(c.api().permissionState.value).toBe('unavailable')
  })
})

describe('usePrivilegeGrantOptions 用户候选', () => {
  test('无 user:read：unavailable，不发请求', async () => {
    const c = mountOptions(() => false)
    await c.api().loadUserOptions()
    expect(c.api().usersState.value).toBe('unavailable')
    expect(usersGetList).not.toHaveBeenCalled()
  })

  test('成功：按用户名排序，userCache 记住对象（换页后已选用户不退回裸 _id）', async () => {
    usersGetList.mockResolvedValue({
      data: {
        data: [
          { _id: 'u2', username: 'bob' },
          { _id: 'u1', username: 'alice' },
        ],
      },
    })
    const c = mountOptions()
    await c.api().loadUserOptions()
    expect(c.api().usersState.value).toBe('ready')
    expect(c.api().userOptions.value.map((u) => u.username)).toEqual(['alice', 'bob'])
    expect(c.api().userCache.value.get('u1').username).toBe('alice')
    // 服务端搜索参数：首页 + 上限 50，有关键词时带 search
    expect(usersGetList.mock.calls[0][0]).toEqual({ status: 'active', page: 1, limit: 50 })
  })

  test('首次加载失败：退回 unavailable（手填用户 ID 兜底），不静默当成功', async () => {
    usersGetList.mockRejectedValue(new Error('users down'))
    const c = mountOptions()
    await expect(c.api().loadUserOptions()).resolves.toBeUndefined()
    expect(c.api().usersState.value).toBe('unavailable')
    expect(c.api().userSearchFailed.value).toBe(false)
  })
})
