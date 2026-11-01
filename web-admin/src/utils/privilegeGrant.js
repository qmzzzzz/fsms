/**
 * 临时授权表单的前端策略常量与纯函数。
 *
 * 这里的上下限与高敏模块清单必须与后端 src/constants/privilegeGrant.js 同尺：
 * 前端只用于即时提示/禁用，最终判据仍在服务端。两边漂移会让"界面说 1 人签批、
 * 后端却要 2 人"这类误导发生，故由 privilegeGrantPolicyParity.test.js 直接对账。
 */
export const MIN_GRANT_HOURS = 1
export const MAX_GRANT_HOURS = 168
export const MAX_GRANT_CODES = 20

/**
 * 保留通配权限码（后端 utils/superAdmin.js 的 RESERVED_WILDCARD_PERMISSION）。
 * 它是「最高权限」的唯一来源，三条授予路径都不允许经临时授权通道申请；
 * 但它在权限目录里是可见的（目录按 status=active 全量列出），因此前端
 * 必须在选择器里把它藏掉：让用户点得中、提交后才 400，是最差的形态。
 */
export const RESERVED_WILDCARD_PERMISSION = '*:*'

export const isReservedCode = (code) => String(code || '').trim() === RESERVED_WILDCARD_PERMISSION

// '''pii''' 与后端同批移入高敏（2026-10-31 审计二-1）：pii:* 通配码覆盖 pii:export，
// 单人签批即可授予等于绕过"未脱敏导出"的复核。前端只做即时提示，判据仍在服务端；
// 两边由 privilegeGrantPolicyParity.test.js 对账，本行不同批改会直接红。
export const HIGH_RISK_MODULES = [
  'user',
  'role',
  'permission',
  'security',
  'system',
  'privilege',
  'pii',
]
export const KNOWN_MODULES = [...HIGH_RISK_MODULES, 'device', 'alarm', 'inspection', 'report']

export const moduleOf = (code) => String(code || '').split(':')[0]

/** 未登记模块按高敏处理，与后端 fail-closed 口径一致 */
export const isHighRiskCode = (code) => {
  const mod = moduleOf(code)
  return HIGH_RISK_MODULES.includes(mod) || !KNOWN_MODULES.includes(mod)
}

export const approvalPolicyOf = (codes) => {
  const highRisk = (Array.isArray(codes) ? codes : []).some(isHighRiskCode)
  return { highRisk, requiredApprovals: highRisk ? 2 : 1 }
}

/** 空格/中英文逗号混排 → 去空、去重、保序 */
export const parsePermissionCodes = (input) => {
  const seen = new Set()
  const codes = []
  String(input || '')
    .split(/[\s,，]+/)
    .map((code) => code.trim())
    .filter(Boolean)
    .forEach((code) => {
      if (seen.has(code)) return
      seen.add(code)
      codes.push(code)
    })
  return codes
}

export const clampDurationHours = (value) => {
  const hours = Number(value)
  if (!Number.isFinite(hours)) return null
  return Math.min(MAX_GRANT_HOURS, Math.max(MIN_GRANT_HOURS, Math.round(hours)))
}

/**
 * 读侧生效态：与后端 activeGrantsForUsers 的判据同尺（status=active 且 expiresAt > now）。
 * 到期回收由独立进程的巡检脚本执行，它停摆时库内 active 记录其实已失效；
 * 缺失/无法解析的 expiresAt 一律按 expired 处理（fail-closed），
 * 避免界面显示比权限判据更乐观。
 */
export const effectiveStatusOf = (grant, now = Date.now()) => {
  const status = String(grant?.status || '')
  if (status !== 'active') return status
  const expires = new Date(grant?.expiresAt).getTime()
  if (!Number.isFinite(expires)) return 'expired'
  return expires > now ? 'active' : 'expired'
}

/** 剩余时间分档：分钟/小时/天；到期返回 expired；缺 expiresAt 返回 null（待生效） */
export const remainingOf = (expiresAt, now = Date.now()) => {
  if (!expiresAt) return null
  const time = new Date(expiresAt).getTime()
  if (!Number.isFinite(time)) return null
  const diff = time - now
  if (diff <= 0) return { kind: 'expired', count: 0 }
  const minutes = Math.ceil(diff / 60000)
  if (minutes < 60) return { kind: 'minutes', count: minutes }
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return { kind: 'hours', count: hours }
  return { kind: 'days', count: Math.floor(hours / 24) }
}
