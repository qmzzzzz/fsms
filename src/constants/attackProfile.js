'use strict';

/**
 * IP 攻击行为画像的分类词典（单一事实来源）。
 *
 * 输出只给行为码与计数：报告文案由前端按当前界面语言生成，后端不拼自然语言。
 * 新增分类时必须同时补齐 web-admin 的 zh-CN / en-US 文案，否则前端会回退成裸码。
 */

const ATTACK_CATEGORIES = Object.freeze({
  HONEYPOT: 'honeypot',
  CREDENTIAL_STUFFING: 'credential_stuffing',
  BRUTE_FORCE: 'brute_force',
  ACCOUNT_ENUMERATION: 'account_enumeration',
  UNAUTHORIZED_ACCESS: 'unauthorized_access',
  DATA_EXFILTRATION: 'data_exfiltration',
  INJECTION_PROBE: 'injection_probe',
  PATH_SCANNING: 'path_scanning',
  RATE_LIMIT_ABUSE: 'rate_limit_abuse',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
});

const VERDICTS = Object.freeze({
  NO_DATA: 'no_data',
  CLEAN: 'clean',
  LOW: 'low',
  SUSPICIOUS: 'suspicious',
  ATTACK: 'attack',
  COMPROMISED: 'compromised',
});

const SUGGESTIONS = Object.freeze({
  BLOCK_IP: 'block_ip',
  RESET_CREDENTIALS: 'reset_credentials',
  ENABLE_MFA: 'enable_mfa',
  REVIEW_ACCOUNTS: 'review_accounts',
  REVIEW_ACCESS_CONTROL: 'review_access_control',
  REVIEW_RATE_LIMITS: 'review_rate_limits',
  REVIEW_EXPORTS: 'review_exports',
  REVIEW_HONEYPOT: 'review_honeypot',
  MONITOR: 'monitor',
  VERIFY_SCOPE: 'verify_scope',
  NO_ACTION: 'no_action',
});

// 登录失败口径：包含密码失败、MFA 失败/锁定与人机挑战拦截。
// 它们共同回答"这个 IP 在反复尝试获取账号访问权"，因此都归入凭据攻击族。
const CREDENTIAL_ACTIONS = Object.freeze([
  'login_failed',
  'auth_failed',
  'login_captcha_rejected',
  'mfa_verify_failed',
  'mfa_attempt_locked',
  'account_temp_locked',
  'brute_force_login',
]);

const SUCCESS_LOGIN_ACTIONS = Object.freeze(['login_success']);
const ENUMERATION_ACTIONS = Object.freeze(['canary_username_attempt']);
const HONEYPOT_ACTIONS = Object.freeze([
  'honeypot_login',
  'honeypot_probe',
  'honeypot_chain_escalated',
]);
const UNAUTHORIZED_ACTIONS = Object.freeze([
  'permission_abuse',
  'privilege_escalation',
  'ip_range_denied',
  'csrf_origin_denied',
]);
const EXFIL_ACTIONS = Object.freeze([
  'bulk_data_export',
  'report_export',
  'report_export_pii',
  'security_audit-logs_export',
]);
const INJECTION_ACTIONS = Object.freeze(['query_param_rejected']);
const SCAN_ACTIONS = Object.freeze(['malformed_request_blocked']);
const RATE_LIMIT_ACTIONS = Object.freeze(['rate_limit_abuse']);
const BLOCKLIST_ACTIONS = Object.freeze(['ip_blacklist_blocked']);
const SUSPICIOUS_ACTIONS = Object.freeze([
  'suspicious_ip_activity',
  'login_unusual_time',
  'suspicious_report',
  'view_sensitive_data',
]);

const toSet = (list) => new Set(list);

const CREDENTIAL_SET = toSet(CREDENTIAL_ACTIONS);
const SUCCESS_LOGIN_SET = toSet(SUCCESS_LOGIN_ACTIONS);
const ENUMERATION_SET = toSet(ENUMERATION_ACTIONS);
const HONEYPOT_SET = toSet(HONEYPOT_ACTIONS);
const UNAUTHORIZED_SET = toSet(UNAUTHORIZED_ACTIONS);
const EXFIL_SET = toSet(EXFIL_ACTIONS);
const INJECTION_SET = toSet(INJECTION_ACTIONS);
const SCAN_SET = toSet(SCAN_ACTIONS);
const RATE_LIMIT_SET = toSet(RATE_LIMIT_ACTIONS);
const BLOCKLIST_SET = toSet(BLOCKLIST_ACTIONS);
const SUSPICIOUS_SET = toSet(SUSPICIOUS_ACTIONS);

// 常见扫描器指纹（命中路径本身即是证据，不要求响应码）
const SCANNER_PATH_RE =
  /(?:\/\.env(?:[/.]|$)|\/\.git(?:[/]|$)|wp-admin|wp-login|xmlrpc\.php|phpmyadmin|adminer|actuator|server-status|\/\.aws|\/\.ssh|config\.json|dump\.sql|\.DS_Store|swagger|graphql)/i;

// 注入 / 路径穿越指纹：命中任意一条即归入注入探测
const INJECTION_PATH_RE =
  /(?:\.\.(?:[/\\]|$)|%2e%2e|%252e%252e|etc\/(?:passwd|shadow)|proc\/self|union(?:[\s+%]+)select|(?:'|%27)\s*(?:or|and)\s+(?:'|%27)?\d|sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|<script|%3cscript|javascript:|jndi:|%24%7bjndi|onerror\s*=)/i;

// 4xx 拒绝原因里属于"越权/身份校验"的码（按错误码词根匹配，新增同类码无需再登记）
const UNAUTHORIZED_REASON_RE =
  /(?:PERMISSION|FORBIDDEN|SCOPE|TOKEN|REAUTH|UNAUTHORIZED|CSRF|MFA|ACCOUNT_LOCKED|IP_RANGE)/i;

// 登录入口的 401 是"密码不对"，不是越权；fallback 分类必须排除它
const LOGIN_PATH_RE = /^\/api\/auth\/(?:login|refresh|mfa)/i;

const DEFAULT_WINDOW_HOURS = 168; // 7 天
const MAX_WINDOW_HOURS = 720; // 30 天
const MAX_PROFILE_ROWS = 5000;
const MAX_EVIDENCE_PER_CATEGORY = 8;
const MAX_TOP_ITEMS = 10;
const MAX_TIMELINE_BUCKETS = 60;
const STUFFING_MIN_ACCOUNTS = 3;
const SUSPICIOUS_SUCCESS_MIN_FAILURES = 10;

const CATEGORY_BASE_SCORE = Object.freeze({
  [ATTACK_CATEGORIES.HONEYPOT]: 40,
  [ATTACK_CATEGORIES.CREDENTIAL_STUFFING]: 30,
  [ATTACK_CATEGORIES.BRUTE_FORCE]: 20,
  [ATTACK_CATEGORIES.ACCOUNT_ENUMERATION]: 15,
  [ATTACK_CATEGORIES.UNAUTHORIZED_ACCESS]: 15,
  [ATTACK_CATEGORIES.DATA_EXFILTRATION]: 18,
  [ATTACK_CATEGORIES.INJECTION_PROBE]: 16,
  [ATTACK_CATEGORIES.PATH_SCANNING]: 10,
  [ATTACK_CATEGORIES.RATE_LIMIT_ABUSE]: 15,
  [ATTACK_CATEGORIES.SUSPICIOUS_ACTIVITY]: 8,
});

module.exports = {
  ATTACK_CATEGORIES,
  VERDICTS,
  SUGGESTIONS,
  CREDENTIAL_ACTIONS,
  SUCCESS_LOGIN_ACTIONS,
  ENUMERATION_ACTIONS,
  HONEYPOT_ACTIONS,
  UNAUTHORIZED_ACTIONS,
  EXFIL_ACTIONS,
  INJECTION_ACTIONS,
  SCAN_ACTIONS,
  RATE_LIMIT_ACTIONS,
  BLOCKLIST_ACTIONS,
  SUSPICIOUS_ACTIONS,
  CREDENTIAL_SET,
  SUCCESS_LOGIN_SET,
  ENUMERATION_SET,
  HONEYPOT_SET,
  UNAUTHORIZED_SET,
  EXFIL_SET,
  INJECTION_SET,
  SCAN_SET,
  RATE_LIMIT_SET,
  BLOCKLIST_SET,
  SUSPICIOUS_SET,
  SCANNER_PATH_RE,
  INJECTION_PATH_RE,
  UNAUTHORIZED_REASON_RE,
  LOGIN_PATH_RE,
  DEFAULT_WINDOW_HOURS,
  MAX_WINDOW_HOURS,
  MAX_PROFILE_ROWS,
  MAX_EVIDENCE_PER_CATEGORY,
  MAX_TOP_ITEMS,
  MAX_TIMELINE_BUCKETS,
  STUFFING_MIN_ACCOUNTS,
  SUSPICIOUS_SUCCESS_MIN_FAILURES,
  CATEGORY_BASE_SCORE,
};
