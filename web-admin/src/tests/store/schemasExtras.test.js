/**
 * schemas 未覆盖分支补齐（formatIssues 根路径 / LoginResponseSchema）
 *
 * 既有 permissionSync.test.js 已覆盖 UserSchema / PermissionListSchema /
 * AuthMeResponseSchema / ApiEnvelopeSchema / PermissionUpdateEventSchema 与
 * toPermissionCodes，此处只补它没打到的两处：
 *
 *  1. formatIssues 的 `(root)` 分支（schemas/index.js:181 的 `|| '(root)'`）：
 *     顶层校验失败（如 permissions 整个不是数组）时 issue.path 为空数组，
 *     若直接 join('.') 会得到空串，日志行变成 ": Expected array" ——
 *     排查的人看不出是哪个字段漂了，正是该函数要解决的问题本身。
 *  2. LoginResponseSchema：/auth/login 的响应形状（MFA 一期响应无 user），
 *     它是 api.js 响应校验表的入口之一，漂移会导致登录后 currentUser 静默为空。
 */
import { describe, test, expect } from 'vitest'
import { formatIssues, LoginResponseSchema, PermissionListSchema } from '@/schemas'

describe('formatIssues 根路径与多 issue', () => {
  test('顶层（根）校验失败时 path 显示为 (root)，不是空串', () => {
    const r = PermissionListSchema.safeParse('not-an-array')
    expect(r.success).toBe(false)
    expect(formatIssues(r.error)).toMatch(/^\(root\): /)
  })

  test('嵌套路径用点号连接（data.user.username）', () => {
    const r = LoginResponseSchema.safeParse({
      success: true,
      data: { user: { username: 123 } },
    })
    expect(r.success).toBe(false)
    expect(formatIssues(r.error)).toMatch(/data\.user\.username: /)
  })

  test('多个 issue 用 "; " 连接，单行可读', () => {
    const r = LoginResponseSchema.safeParse({
      success: true,
      data: { user: { username: 123, roles: 'ADMIN' } },
    })
    expect(r.success).toBe(false)
    const text = formatIssues(r.error)
    expect(text.split('; ').length).toBeGreaterThanOrEqual(2)
    expect(text).not.toContain('\n')
  })

  test('单条 issue 自身缺 path 字段时按根处理且不抛错', () => {
    // zod 的 issue 恒有 path，但该函数也用于包装其它来源的错误对象；
    // 缺 path 时若不兜底会抛 TypeError，格式化为日志的本意直接失效
    expect(formatIssues({ issues: [{ message: '自定义漂移' }] })).toBe('(root): 自定义漂移')
  })

  test('入参为 null / 无 issues 时返回空串（调用方无需判空）', () => {
    expect(formatIssues(null)).toBe('')
    expect(formatIssues(undefined)).toBe('')
    expect(formatIssues({})).toBe('')
    expect(formatIssues({ issues: [] })).toBe('')
  })
})

describe('LoginResponseSchema（/auth/login 响应）', () => {
  const envelope = (data) => ({ success: true, message: 'ok', data })

  test('MFA 一期响应无 user 也合法（data 可空、user 可缺）', () => {
    expect(LoginResponseSchema.safeParse(envelope({ mfaRequired: true })).success).toBe(true)
    expect(LoginResponseSchema.safeParse(envelope(null)).success).toBe(true)
    expect(LoginResponseSchema.safeParse({ success: true }).success).toBe(true)
  })

  test('完整登录响应合法（token/refreshToken/expires 三种形态）', () => {
    expect(
      LoginResponseSchema.safeParse(
        envelope({
          token: 't',
          refreshToken: 'r',
          expires: 3600,
          user: { userId: 'u1', username: 'alice' },
        })
      ).success
    ).toBe(true)
    expect(
      LoginResponseSchema.safeParse(envelope({ expires: '2026-09-18T00:00:00.000Z' })).success
    ).toBe(true)
  })

  test('expires 既非字符串也非数字时报漂移', () => {
    expect(LoginResponseSchema.safeParse(envelope({ expires: {} })).success).toBe(false)
  })

  test('data.user 存在但形状错误（缺 username）时报漂移', () => {
    expect(LoginResponseSchema.safeParse(envelope({ user: { userId: 'u1' } })).success).toBe(false)
  })

  test('user 缺全部 id 别名时报漂移（P3-38 同类缺陷）', () => {
    expect(LoginResponseSchema.safeParse(envelope({ user: { username: 'alice' } })).success).toBe(
      false
    )
  })

  test('success 非布尔时报漂移（所有 if (resp.success) 判断都会失真）', () => {
    expect(LoginResponseSchema.safeParse({ success: 'true', data: {} }).success).toBe(false)
  })
})
