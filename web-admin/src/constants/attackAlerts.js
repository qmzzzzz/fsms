/**
 * 攻击告警分类码表（前端镜像）——与后端 src/constants/attackEvents.js 对齐。
 *
 * 单一事实来源在后端（ATTACK_EVENT_TYPES / actionsByAttackType），这里只镜像
 * 供视图渲染：tab 选项、规则名下拉与行的分类标签。两侧漂移时页面不会报错，
 * 只会退回裸码——对齐由 tests/i18n/attackAlertsDictionaryParity.test.js 钉住
 * （它直接 createRequire 后端常量与本文件逐项比对，任何一侧单方改动都会红）。
 */

// 分类码清单（顺序即 tab 顺序，与后端 ATTACK_EVENT_TYPES 一致）
export const ATTACK_EVENT_TYPE_CODES = [
  'credential',
  'honeypot',
  'injection',
  'scan',
  'probe',
  'privilege',
  'data_exfil',
  'rate_abuse',
  'anomaly',
]

// 分类 → 注册表 action 切片（与后端 actionsByAttackType 一致，规则名下拉按此分组）
export const ATTACK_EVENT_ACTIONS = {
  credential: [
    'login_failed',
    'brute_force_login',
    'login_captcha_rejected',
    'mfa_verify_failed',
    'mfa_attempt_locked',
    'account_temp_locked',
    'canary_username_attempt',
  ],
  honeypot: ['honeypot_login', 'honeypot_probe', 'honeypot_chain_escalated'],
  injection: ['nosql_injection_attempt', 'sql_injection_attempt'],
  scan: ['scan_probe_detected', 'scan_probe_storm'],
  probe: [
    'ip_range_denied',
    'ip_blacklist_blocked',
    'csrf_origin_denied',
    'malformed_request_blocked',
    'query_param_rejected',
  ],
  privilege: ['permission_abuse', 'privilege_escalation'],
  data_exfil: ['bulk_data_export', 'view_sensitive_data'],
  rate_abuse: ['rate_limit_abuse'],
  anomaly: ['login_unusual_time'],
}

// 全部注册表 action（规则名下拉的全集，顺序稳定）
export const ALL_ATTACK_EVENT_ACTIONS = Object.values(ATTACK_EVENT_ACTIONS).flat()

// action → 分类码（后端不回传分类字段，行的分类标签由前端按注册表派生；
// 未收录的 action 返回 undefined，调用方按「全部攻击」兜底渲染）
const ACTION_TYPE_INDEX = new Map(
  Object.entries(ATTACK_EVENT_ACTIONS).flatMap(([code, actions]) =>
    actions.map((action) => [action, code])
  )
)
export const attackTypeOfAction = (action) => ACTION_TYPE_INDEX.get(action)
