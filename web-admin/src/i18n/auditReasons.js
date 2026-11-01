/**
 * 审计记录的 reason 文案：只做**展示期**翻译，绝不改写落库内容。
 *
 * 为什么不能在写库时按语言落盘：
 *  - AuditLog 是链式哈希的证据记录（models/AuditLog.js 的字段集被
 *    src/tests/auditFieldSetsImmutable.test.js 整体钉死），加字段等于改契约；
 *  - 同一条记录要能被中文与英文界面各自读懂，落盘只能是**一种**语言。
 * 因此这里按「模板 → 英文模板」的映射在渲染时翻译，参数（IP、用户名、计数）
 * 原样搬运；模板改过或对不上时**原样返回中文**——宁可露出原文，也不能猜测改写。
 *
 * 覆盖范围：src/ 下所有写入 AuditLog.reason 的中文模板（28 条，逐条对照）。
 * 新增审计 reason 时请同步在本文件补一条，并在 auditReasons.test.js 加断言，
 * 否则英文界面会静默回落到中文原文。
 */

/** 数字归一：分开写便于在英文模板里直接插值。 */
const RULES = [
  {
    re: /^启动配置校验通过：JWT\/JWT_REFRESH\/AES\/HMAC 密钥均满足强度要求$/,
    en: () =>
      'Startup configuration validation passed: JWT/JWT_REFRESH/AES/HMAC secrets all meet strength requirements',
  },
  {
    re: /^尝试将 (.+) 加入(黑|白)名单（加入后覆盖全部 (.+) 地址），权限不足$/,
    en: (m) =>
      `Attempted to add ${m[1]} to the ${m[2] === '黑' ? 'block' : 'allow'}list (would cover all ${m[3]} addresses); permission denied`,
  },
  {
    re: /^尝试移除铺满 (.+) 地址的名单条目 (.+)（该条目是全覆盖的组成部分），权限不足$/,
    en: (m) =>
      `Attempted to remove list entry ${m[2]} covering all ${m[1]} addresses (part of full coverage); permission denied`,
  },
  {
    re: /^查询参数值超过 (\d+) 字符：(.+)$/,
    en: (m) => `Query parameter value exceeds ${m[1]} characters: ${m[2]}`,
  },
  {
    re: /^查询参数收到对象\/数组形态取值：(.+)$/,
    en: (m) => `Query parameter received as an object/array: ${m[1]}`,
  },
  { re: /^请求 IP 命中黑名单，已拒绝访问$/, en: () => 'Request IP is blacklisted; access denied' },
  {
    re: /^请求 IP 命中黑名单降级缓存（数据库查询失败），已拒绝访问$/,
    en: () =>
      'Request IP matched the blacklist fallback cache (database lookup failed); access denied',
  },
  {
    re: /^登录 IP 不在允许范围内（(.+)）$/,
    en: (m) => `Sign-in IP is outside the allowed range (${m[1]})`,
  },
  {
    re: /^请求 IP 不在允许范围内（(.+)）$/,
    en: (m) => `Request IP is outside the allowed range (${m[1]})`,
  },
  {
    re: /^写操作 Origin 头为空串（异常来源）$/,
    en: () => 'Write request had an empty Origin header (abnormal source)',
  },
  {
    re: /^写操作来源 (.+) 不在白名单内$/,
    en: (m) => `Write request origin ${m[1]} is not in the allowlist`,
  },
  {
    re: /^管理员注销用户并匿名化其个人身份信息$/,
    en: () => 'Administrator deactivated the account and anonymized the personal data',
  },
  {
    re: /^管理员批量注销 (\d+) 个用户并匿名化$/,
    en: (m) => `Administrator deactivated ${m[1]} accounts in bulk and anonymized them`,
  },
  {
    re: /^管理员重置用户 (.+) 的两步验证并强制下线$/,
    en: (m) => `Administrator reset two-factor authentication for ${m[1]} and forced sign-out`,
  },
  {
    re: /^管理员重置用户 (.+) 的口令，并要求首次登录改密$/,
    en: (m) =>
      `Administrator reset the password for ${m[1]} and requires a password change at next sign-in`,
  },
  {
    re: /^重新生成恢复码失败：动态口令错误$/,
    en: () => 'Recovery-code regeneration failed: invalid one-time code',
  },
  {
    re: /^重新生成恢复码被拒：动态口令所属时间窗已被消费（重放）$/,
    en: () =>
      "Recovery-code regeneration rejected: that code's time window was already used (replay)",
  },
  {
    re: /^重新生成 10 个备用恢复码（旧码作废）$/,
    en: () => 'Regenerated 10 backup recovery codes (previous codes revoked)',
  },
  {
    re: /^生成两步验证密钥（待确认）$/,
    en: () => 'Generated a two-factor secret (pending confirmation)',
  },
  {
    re: /^开启两步验证并生成 10 个备用恢复码$/,
    en: () => 'Enabled two-factor authentication and generated 10 backup recovery codes',
  },
  {
    re: /^关闭两步验证身份验证失败（方式：(.+?)）$/,
    en: (m) =>
      `Identity verification failed when disabling two-factor authentication (method: ${m[1]})`,
  },
  {
    re: /^使用备用恢复码关闭两步验证（已消费一枚恢复码）$/,
    en: () => 'Disabled two-factor authentication with a backup recovery code (one code consumed)',
  },
  { re: /^关闭两步验证$/, en: () => 'Disabled two-factor authentication' },
  {
    re: /^密码已验证，等待两步验证码$/,
    en: () => 'Password verified; awaiting the two-factor code',
  },
  {
    re: /^MFA 验证通道锁定期间尝试登录$/,
    en: () => 'Sign-in attempted while the MFA verification channel was locked',
  },
  { re: /^两步验证码重放$/, en: () => 'Two-factor code replay' },
  { re: /^两步验证码错误$/, en: () => 'Invalid two-factor code' },
  {
    re: /^使用备用恢复码登录（剩余 (\d+) 个）$/,
    en: (m) => `Signed in with a backup recovery code (${m[1]} remaining)`,
  },
]

/**
 * 把审计 reason 翻成英文；**只在英文界面调用**。
 * 非字符串、空串、未命中任何模板 ⇒ 原样返回（不改写证据原文）。
 */
export const translateAuditReason = (reason) => {
  if (typeof reason !== 'string' || !reason) return reason
  for (const rule of RULES) {
    const m = reason.match(rule.re)
    if (m) return rule.en(m)
  }
  return reason
}

/** 供测试与维护用：导出规则条数，新增模板时这条数字必须同步增长。 */
export const AUDIT_REASON_RULE_COUNT = RULES.length

export default translateAuditReason
