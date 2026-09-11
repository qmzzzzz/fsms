/**
 * 权限热同步与运行时形状校验测试
 *
 * 覆盖两组能力：
 *  1. zod schema —— 抓「对象形状漂移」这类无声缺陷（P3-38 是活生生的案例：
 *     三条接口给三种 id 字段，界面判断静默失效，没有任何报错）；
 *  2. authStore 的权限热刷新 —— 管理员改权限后免重登生效的前端侧闭环。
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from '@/store'
import {
  UserSchema,
  PermissionListSchema,
  AuthMeResponseSchema,
  SessionStatusResponseSchema,
  PermissionUpdateEventSchema,
  ApiEnvelopeSchema,
  toPermissionCodes,
  formatIssues,
} from '@/schemas'

const getMeMock = vi.fn()
const getSessionStatusMock = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      getMe: (...args) => getMeMock(...args),
      getSessionStatus: (...args) => getSessionStatusMock(...args),
    },
  },
}))

describe('运行时形状校验（zod）', () => {
  test('UserSchema 接受三种真实来源的形状', () => {
    // POST /auth/login
    expect(
      UserSchema.safeParse({ userId: 'u1', username: 'alice', roles: ['ADMIN'] }).success
    ).toBe(true)
    // GET /auth/me
    expect(
      UserSchema.safeParse({
        id: 'u1',
        username: 'alice',
        roles: [{ name: '管理员', code: 'ADMIN' }],
      }).success
    ).toBe(true)
    // 归一化之后（三个别名齐备）
    expect(
      UserSchema.safeParse({ _id: 'u1', id: 'u1', userId: 'u1', username: 'alice' }).success
    ).toBe(true)
  })

  test('UserSchema 拒绝「一个 id 都没有」的用户对象（P3-38 同类缺陷）', () => {
    const r = UserSchema.safeParse({ username: 'alice' })
    expect(r.success).toBe(false)
    expect(formatIssues(r.error)).toContain('无法确定身份')
  })

  test('UserSchema 允许后端新增字段（宽进：不因多字段告警）', () => {
    const r = UserSchema.safeParse({ id: 'u1', username: 'alice', brandNewField: 42 })
    expect(r.success).toBe(true)
    expect(r.data.brandNewField).toBe(42)
  })

  test('UserSchema 拒绝 username 缺失或类型错误', () => {
    expect(UserSchema.safeParse({ id: 'u1' }).success).toBe(false)
    expect(UserSchema.safeParse({ id: 'u1', username: 123 }).success).toBe(false)
  })

  test('PermissionListSchema 兼容两种后端口径', () => {
    expect(PermissionListSchema.safeParse(['device:read', 'user:*']).success).toBe(true)
    expect(PermissionListSchema.safeParse([{ _id: 'p1', code: 'device:read' }]).success).toBe(true)
  })

  test('PermissionListSchema 拒绝无法归一化的元素', () => {
    expect(PermissionListSchema.safeParse([1, 2]).success).toBe(false)
    expect(PermissionListSchema.safeParse([null]).success).toBe(false)
    // 对象但缺 code：归一化后会凭空消失，属于必须报出的漂移
    expect(PermissionListSchema.safeParse([{ name: '读设备' }]).success).toBe(false)
  })

  test('AuthMeResponseSchema 校验完整响应', () => {
    const ok = {
      success: true,
      message: '获取成功',
      data: {
        user: { id: 'u1', username: 'alice' },
        permissions: ['device:read'],
        menus: [],
        buttons: ['device:create'],
        dataScope: 'all',
      },
    }
    expect(AuthMeResponseSchema.safeParse(ok).success).toBe(true)

    // permissions 变成对象（后端某天忘了 .map(p => p.code)）→ 必须报出
    const drifted = { ...ok, data: { ...ok.data, permissions: [{ nope: 1 }] } }
    expect(AuthMeResponseSchema.safeParse(drifted).success).toBe(false)
  })

  test('SessionStatusResponseSchema 要求 authenticated 为布尔', () => {
    expect(
      SessionStatusResponseSchema.safeParse({ success: true, data: { authenticated: true } })
        .success
    ).toBe(true)
    // 字符串 'true' 会被 if 判真，是典型的静默错误来源
    expect(
      SessionStatusResponseSchema.safeParse({ success: true, data: { authenticated: 'true' } })
        .success
    ).toBe(false)
  })

  test('ApiEnvelopeSchema 覆盖 success/paginated/error 三种响应', () => {
    expect(ApiEnvelopeSchema.safeParse({ success: true, data: [] }).success).toBe(true)
    expect(
      ApiEnvelopeSchema.safeParse({
        success: true,
        data: [],
        pagination: { page: 1, limit: 10, total: 3, totalPages: 1 },
      }).success
    ).toBe(true)
    expect(
      ApiEnvelopeSchema.safeParse({
        success: false,
        message: '数据验证失败',
        errors: { errorCode: 'X' },
      }).success
    ).toBe(true)
    // success 缺失/非布尔 → 前端所有 `if (resp.success)` 判断都会失真
    expect(ApiEnvelopeSchema.safeParse({ data: [] }).success).toBe(false)
    expect(ApiEnvelopeSchema.safeParse({ success: 'yes' }).success).toBe(false)
  })

  test('PermissionUpdateEventSchema 允许缺省 permissionCodes（后端重算失败时刻意省略）', () => {
    expect(PermissionUpdateEventSchema.safeParse({ type: 'permission-sync' }).success).toBe(true)
    expect(
      PermissionUpdateEventSchema.safeParse({
        type: 'permission-sync',
        permissionCodes: ['device:read'],
      }).success
    ).toBe(true)
    // 带了但类型不对 → 报出，前端据此回退到拉 /auth/me
    expect(
      PermissionUpdateEventSchema.safeParse({
        type: 'permission-sync',
        permissionCodes: [{ code: 'device:read' }],
      }).success
    ).toBe(false)
  })

  test('formatIssues 输出 path: message 便于定位', () => {
    const r = UserSchema.safeParse({ id: 'u1', username: 123 })
    expect(formatIssues(r.error)).toMatch(/username:/)
  })
})

describe('toPermissionCodes 归一化', () => {
  test('字符串数组原样通过', () => {
    expect(toPermissionCodes(['a:read', 'b:write'])).toEqual(['a:read', 'b:write'])
  })

  test('对象数组抽取 code', () => {
    expect(toPermissionCodes([{ code: 'a:read' }, { code: 'b:write' }])).toEqual([
      'a:read',
      'b:write',
    ])
  })

  test('混合形态与去重', () => {
    expect(toPermissionCodes(['a:read', { code: 'a:read' }, { code: 'b:write' }])).toEqual([
      'a:read',
      'b:write',
    ])
  })

  test('非数组与不可归一化元素安全降级为空/跳过', () => {
    expect(toPermissionCodes(null)).toEqual([])
    expect(toPermissionCodes(undefined)).toEqual([])
    expect(toPermissionCodes('a:read')).toEqual([])
    expect(toPermissionCodes([null, 1, {}, { code: 'ok:x' }])).toEqual(['ok:x'])
  })
})

describe('authStore 权限热同步', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
    getMeMock.mockReset()
    getSessionStatusMock.mockReset()
  })

  /** 构造已登录状态 */
  const login = (permissions = ['device:read']) => {
    const store = useAuthStore()
    store.setAuth('t', 'r', { userId: 'u1', username: 'alice' }, permissions)
    return store
  }

  test('setAuth 会把 populate 对象数组归一化为 code 字符串', () => {
    const store = useAuthStore()
    store.setAuth('t', 'r', { userId: 'u1', username: 'alice' }, [
      { _id: 'p1', code: 'device:read' },
      { _id: 'p2', code: 'device:create' },
    ])
    expect(store.permissions).toEqual(['device:read', 'device:create'])
    // 归一化结果同时落盘，刷新页面后仍是字符串数组
    expect(JSON.parse(localStorage.getItem('permissions'))).toEqual([
      'device:read',
      'device:create',
    ])
    // 关键：归一化后按钮权限判断才能命中
    expect(store.hasPermission('device:create')).toBe(true)
  })

  test('applyPermissionCodes 就地替换（乐观更新）', () => {
    const store = login(['device:read'])
    expect(store.applyPermissionCodes(['device:read', 'user:read'])).toBe(true)
    expect(store.permissions).toEqual(['device:read', 'user:read'])
    expect(store.hasPermission('user:read')).toBe(true)
  })

  test('applyPermissionCodes 能表达「权限被移除」（整体替换而非合并）', () => {
    const store = login(['device:read', 'device:delete'])
    store.applyPermissionCodes(['device:read'])
    expect(store.permissions).toEqual(['device:read'])
    expect(store.hasPermission('device:delete')).toBe(false)
  })

  test('applyPermissionCodes 在未登录或入参非数组时不应用', () => {
    const store = useAuthStore()
    // 未登录
    expect(store.applyPermissionCodes(['a:b'])).toBe(false)
    store.setAuth('t', 'r', { userId: 'u1', username: 'alice' }, ['device:read'])
    // 入参非数组（后端漏发字段）：保留现有权限，不清空
    expect(store.applyPermissionCodes(undefined)).toBe(false)
    expect(store.permissions).toEqual(['device:read'])
  })

  test('refreshPermissionsFromServer 拉取并替换权限（免重登生效的核心）', async () => {
    const store = login(['device:read'])
    getMeMock.mockResolvedValue({
      data: {
        success: true,
        data: {
          user: { id: 'u1', username: 'alice' },
          permissions: ['device:read', 'user:read', 'role:read'],
        },
      },
    })

    expect(await store.refreshPermissionsFromServer()).toBe(true)
    expect(store.permissions).toEqual(['device:read', 'user:read', 'role:read'])
    // silent401：会话可能刚被强制下线，那属预期结果，不该在此弹二次提示
    expect(getMeMock).toHaveBeenCalledWith({ silent401: true })
  })

  test('refreshPermissionsFromServer 同时归一化 permissions 与 user 形状', async () => {
    const store = login([])
    getMeMock.mockResolvedValue({
      data: {
        success: true,
        data: {
          // 只给 id（/auth/me 的真实口径）
          user: { id: 'u1', username: 'alice' },
          // 给对象数组（populate 口径）
          permissions: [{ code: 'device:read' }],
        },
      },
    })
    await store.refreshPermissionsFromServer()
    expect(store.permissions).toEqual(['device:read'])
    // P3-38：三个别名必须齐备，否则「是否本人」判断失效
    expect(store.currentUser.userId).toBe('u1')
    expect(store.currentUser._id).toBe('u1')
    expect(store.isSelf('u1')).toBe(true)
  })

  test('refreshPermissionsFromServer 失败时保留现有权限（不清空）', async () => {
    const store = login(['device:read'])
    getMeMock.mockRejectedValue(Object.assign(new Error('network down'), { response: undefined }))
    expect(await store.refreshPermissionsFromServer()).toBe(false)
    // 清空会让界面突然「什么都不能点」，而真实原因可能只是网络抖动
    expect(store.permissions).toEqual(['device:read'])
  })

  test('refreshPermissionsFromServer 未登录时直接返回 false 且不发请求', async () => {
    const store = useAuthStore()
    expect(await store.refreshPermissionsFromServer()).toBe(false)
    expect(getMeMock).not.toHaveBeenCalled()
  })

  test('syncPermissionsFromEvent：先乐观更新，再以服务端结果为准', async () => {
    const store = login(['device:read'])
    const seen = []
    getMeMock.mockImplementation(async () => {
      // 断言此刻乐观值已生效（即界面已经先响应了）
      seen.push([...store.permissions])
      return {
        data: {
          success: true,
          data: {
            user: { id: 'u1', username: 'alice' },
            // 服务端的权威结论与推送不同：以服务端为准
            permissions: ['device:read', 'user:read'],
          },
        },
      }
    })

    await store.syncPermissionsFromEvent({
      permissionCodes: ['device:read', 'user:read', 'role:read'],
    })

    expect(seen[0]).toEqual(['device:read', 'user:read', 'role:read'])
    expect(store.permissions).toEqual(['device:read', 'user:read'])
  })

  test('syncPermissionsFromEvent：推送未带 permissionCodes 时直接走权威校验', async () => {
    const store = login(['device:read'])
    getMeMock.mockResolvedValue({
      data: {
        success: true,
        data: { user: { id: 'u1', username: 'alice' }, permissions: ['user:read'] },
      },
    })
    expect(await store.syncPermissionsFromEvent({ type: 'permission-sync' })).toBe(true)
    expect(store.permissions).toEqual(['user:read'])
  })

  test('syncPermissionsFromEvent 未登录时不处理', async () => {
    const store = useAuthStore()
    expect(await store.syncPermissionsFromEvent({ permissionCodes: ['a:b'] })).toBe(false)
    expect(getMeMock).not.toHaveBeenCalled()
  })
})
