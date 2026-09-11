/**
 * 后端响应/推送的运行时形状校验（zod）
 *
 * 为什么需要它：前端是纯 JS，后端契约只存在于「约定」里。本仓库已经因此
 * 踩过两次：
 *  1. P3-38：登录返回 userId、/auth/me 返回 id、ProfileView 用后者覆盖前者，
 *     导致 currentUser._id 恒为 undefined，「是否本人」判断静默失效。
 *  2. permissions 数组元素形状在不同接口间不一致（有的给 code 字符串数组，
 *     有的给 populate 后的对象数组），下游 matchPermission 拿到对象会全部不命中。
 * 这类缺陷的共同点：**没有任何一处会报错**，只是行为悄悄不对。
 *
 * 校验策略（宽进严出）：
 *  - 一律用 looseObject（允许后端新增字段，不因为多了个字段就告警）；
 *  - 只对「前端真正依赖的字段」断言类型；
 *  - 校验失败**不阻断**业务流程，只在控制台记录 + 给用户一句提示 ——
 *    形状漂移通常是后端发版引入的，前端此时应尽力渲染而不是白屏。
 *
 * 关于 TypeScript：静态类型无法覆盖「运行时来自网络的数据」，
 * 二者是互补而非替代关系。zod 先行的收益是立即可见的（现在就能捕获漂移），
 * 后续如迁 TS，这些 schema 可直接 z.infer 出类型，不做无用功。
 */

import { z } from 'zod'

/** ObjectId 在 JSON 里恒为非空字符串（后端一律经 JSON.stringify 序列化） */
const ObjectIdLike = z.string().min(1)

/**
 * 权限项：/roles/permissions/tree 与 /auth/me 的 populate 结果
 * code 是前端唯一真正消费的字段（matchPermission 按 code 比对）
 */
export const PermissionItemSchema = z.looseObject({
  _id: ObjectIdLike.optional(),
  code: z.string().min(1),
  name: z.string().optional(),
  type: z.string().optional(),
  module: z.string().nullish(),
})

/**
 * 权限集合：必须能归一化成 string[] 才可供 matchPermission 使用。
 * 兼容两种后端口径（code 字符串数组 / populate 对象数组），
 * 但**不接受**混入 number、null 等无法归一化的元素——那正是要抓的漂移。
 */
export const PermissionListSchema = z.array(z.union([z.string(), PermissionItemSchema]))

/**
 * 用户对象：三条来源（login / auth.me / profile 更新）形状不同，
 * 因此三个 id 别名都是 optional，但 refine 要求**至少存在一个** ——
 * 一个都没有意味着 normalizeUser 无法补齐别名，「是否本人」判断必然失效。
 */
export const UserSchema = z
  .looseObject({
    _id: ObjectIdLike.optional(),
    id: ObjectIdLike.optional(),
    userId: ObjectIdLike.optional(),
    username: z.string().min(1),
    email: z.string().nullish(),
    realName: z.string().nullish(),
    phone: z.string().nullish(),
    department: z.string().nullish(),
    // roles 既可能是 code 字符串数组（login），也可能是 {name,code} 对象数组（/auth/me）
    roles: z
      .array(z.union([z.string(), z.looseObject({ code: z.string().optional() })]))
      .optional(),
    status: z.string().optional(),
  })
  .refine((u) => u._id != null || u.id != null || u.userId != null, {
    message: '用户对象缺少 id/_id/userId，无法确定身份（P3-38 同类缺陷）',
  })

/** 通用响应包络：ApiResponse.success/error/paginated 的共同结构 */
export const ApiEnvelopeSchema = z.looseObject({
  success: z.boolean(),
  message: z.string().nullish(),
  data: z.unknown().nullish(),
  pagination: z
    .looseObject({
      page: z.number().optional(),
      limit: z.number().optional(),
      total: z.number().optional(),
      totalPages: z.number().optional(),
    })
    .nullish(),
  errors: z.unknown().nullish(),
})

/** POST /auth/login 成功响应（MFA 一期响应无 user，故 user 为 optional） */
export const LoginResponseSchema = ApiEnvelopeSchema.extend({
  data: z
    .looseObject({
      token: z.string().optional(),
      refreshToken: z.string().optional(),
      expires: z.union([z.string(), z.number()]).optional(),
      mfaRequired: z.boolean().optional(),
      user: UserSchema.optional(),
    })
    .nullish(),
})

/** GET /auth/me：权限热刷新的事实来源，字段要求最严 */
export const AuthMeResponseSchema = ApiEnvelopeSchema.extend({
  data: z.looseObject({
    user: UserSchema,
    permissions: PermissionListSchema,
    menus: z.array(z.unknown()).optional(),
    buttons: z.array(z.string()).optional(),
    dataScope: z.unknown().nullish(),
  }),
})

/** GET /auth/session：轻量探测，只关心 authenticated 布尔 */
export const SessionStatusResponseSchema = ApiEnvelopeSchema.extend({
  data: z.looseObject({ authenticated: z.boolean() }).nullish(),
})

/**
 * 单条登录会话（UserSession.toClientJSON 的输出）
 *
 * sid 与 current 是**功能正确性**依赖的字段，必须严格断言：
 *  - sid 缺失 → 踢除按钮拿不到目标，点了没反应；
 *  - current 缺失 → 「本设备」标记消失，用户可能把自己踢下线（后端虽然
 *    会拒绝，但用户得到的是一个莫名的 400，而非「这是当前设备」的提示）。
 * 其余为展示字段，缺失只是显示「未知」，故一律 nullish。
 */
export const SessionItemSchema = z.looseObject({
  sid: z.string().min(1),
  current: z.boolean(),
  deviceType: z.string().nullish(),
  browser: z.string().nullish(),
  browserVersion: z.string().nullish(),
  os: z.string().nullish(),
  osVersion: z.string().nullish(),
  deviceVendor: z.string().nullish(),
  deviceModel: z.string().nullish(),
  engine: z.string().nullish(),
  cpu: z.string().nullish(),
  userAgent: z.string().nullish(),
  ip: z.string().nullish(),
  lastIp: z.string().nullish(),
  createdAt: z.string().nullish(),
  lastSeenAt: z.string().nullish(),
  expiresAt: z.string().nullish(),
})

/** GET /auth/sessions：设备级会话列表 */
export const SessionListResponseSchema = ApiEnvelopeSchema.extend({
  data: z
    .looseObject({
      sessions: z.array(SessionItemSchema),
      total: z.number().optional(),
      currentSidPresent: z.boolean().optional(),
    })
    .nullish(),
})

/**
 * WebSocket 权限/角色变更推送
 *
 * permissionCodes 由后端为「当前在线的受影响用户」逐一重算后下发，
 * 是该用户的**完整**权限码集合（不是增量）——只有完整集合才能安全地
 * 直接替换本地状态；增量无法表达「某权限被移除」。
 */
export const PermissionUpdateEventSchema = z.looseObject({
  type: z.string().optional(),
  action: z.string().optional(),
  roleId: ObjectIdLike.optional(),
  roleName: z.string().optional(),
  /** 收件人的完整权限码集合；缺省表示后端未能重算，前端须回退到拉取 /auth/me */
  permissionCodes: z.array(z.string()).optional(),
  timestamp: z.string().optional(),
})

/**
 * 把 zod 的 issues 压成单行日志文本（控制台里一眼能看出哪个字段漂了）
 * @param {import('zod').ZodError} error
 * @returns {string}
 */
export const formatIssues = (error) =>
  (error?.issues || [])
    .map((i) => `${(i.path || []).join('.') || '(root)'}: ${i.message}`)
    .join('; ')

/**
 * 把权限集合归一化为 string[]（唯一出口）
 *
 * 后端两种口径都可能出现，下游 matchPermission 只认字符串。
 * 原实现把 permissions 原样存进 store —— 一旦后端某天改成 populate 对象，
 * 所有按钮权限会全部判否，界面看起来像「权限被收回」。
 * @param {unknown} list
 * @returns {string[]}
 */
export const toPermissionCodes = (list) => {
  if (!Array.isArray(list)) return []
  const codes = []
  for (const item of list) {
    if (typeof item === 'string') {
      codes.push(item)
    } else if (item && typeof item === 'object' && typeof item.code === 'string') {
      codes.push(item.code)
    }
  }
  return [...new Set(codes)]
}
