/**
 * 攻击告警分类注册表 ——「安全分析 · 攻击告警查询」读面的单一事实来源。
 *
 * 攻击信号在本仓没有独立集合，全部是 AuditLog 事件型 action 行（constants/audit.js
 * 与 services/*AlertTypes.js）。本表收口「哪些 action 算攻击事件、各归哪类」，
 * 供 attackEventQueryService 的基查询（action $in）与分类计数归并用。
 * 分类按 fsms 检测面划分：LANSEC 参考页的 Suricata 13 类（SQL 注入/命令执行/
 * 挖矿/木马远控）在本仓没有检测源，照搬只会得到永远为 0 的 tab；将来新增检测源
 * 在映射里加一行即可。
 *
 * 硬约束（tests/services/attackEventQueryService.test.js 钉住）：
 *  1) action 全集 ⊆ AUDIT_LOG_ACTIONS——白名单外的 action 记了也筛不出，注册死条目
 *     等于造一个「看似有此类、实际永远查不到」的空 tab；
 *  2) 映射单值——计数按 action 分组回填，一对多会让同一行被数两次；
 *  3) 只收真的会写入 AuditLog 的 action（各条目行尾即写入点，注册时逐一核实）；
 *     只走出站告警不落库的类型（如 audit_chain_* 四族）刻意不收。
 */

// 分类清单（有序：前端 tab 顺序与筛选枚举校验都按它来）。nameKey 指向前端懒加载词典 attackAlerts.types.*，两侧码表对齐由词典 parity 闸钉住。
const ATTACK_EVENT_TYPES = Object.freeze([
  { code: 'credential', nameKey: 'credential' }, // 凭证攻击
  { code: 'honeypot', nameKey: 'honeypot' }, // 蜜罐诱捕
  { code: 'injection', nameKey: 'injection' }, // 注入尝试（SQLi 特征串 + NoSQL 操作符剥离）
  { code: 'scan', nameKey: 'scan' }, // 扫描探测（路径指纹 + 404 风暴）
  { code: 'probe', nameKey: 'probe' }, // 探测与拒绝
  { code: 'privilege', nameKey: 'privilege' }, // 权限滥用
  { code: 'data_exfil', nameKey: 'dataExfil' }, // 数据外泄
  { code: 'rate_abuse', nameKey: 'rateAbuse' }, // 资源滥用
  { code: 'anomaly', nameKey: 'anomaly' }, // 异常行为
]);

// action → 分类码。行尾即审计写入点（逐一核实，非凭白名单推断）。canary_username_attempt
// 归 credential：表现形态是凭证失败，两类都讲得通但映射必须单值，蜜罐 tab 由 honeypot_* 撑起。
const ATTACK_EVENT_ACTION_MAP = Object.freeze({
  login_failed: 'credential', // models/auditLogWriteStatics.js recordLogin
  brute_force_login: 'credential', // services/securityAlert.js checkBruteForce
  login_captcha_rejected: 'credential', // services/loginChallenge.recordCaptchaRejected
  mfa_verify_failed: 'credential', // MFA 两步验证失败（authService/mfa）
  mfa_attempt_locked: 'credential', // MFA 尝试锁定
  account_temp_locked: 'credential', // 登录失败阈值触发的临时锁定（authService）
  canary_username_attempt: 'credential', // services/canaryWatch.js recordGhostAttempt
  honeypot_login: 'honeypot', // services/honeypotWatch.js（+ markForensicTarget）
  honeypot_probe: 'honeypot', // services/honeypotWatch.js（陷阱会话内探测/WS 握手）
  honeypot_chain_escalated: 'honeypot', // services/honeypotChainWatch.js（同 IP 一业务日跨 ≥2 阶段）
  nosql_injection_attempt: 'injection', // services/injectionDetector.js（操作符键剥离留痕）
  sql_injection_attempt: 'injection', // middleware/injectionSignature.js（特征串边缘检测）
  scan_probe_detected: 'scan', // services/scanProbeDetector.js（扫描器路径指纹证据行）
  scan_probe_storm: 'scan', // services/scanProbeDetector.js（404 风暴达标，每窗口一条）
  ip_range_denied: 'probe', // middleware/security/earlyRejection.js（黑名单/来源校验早拒绝）
  ip_blacklist_blocked: 'probe', // middleware/security/earlyRejection.js（审计中间件前的 403）
  csrf_origin_denied: 'probe', // CSRF 来源校验失败
  malformed_request_blocked: 'probe', // 协议合规层（Content-Type/头部/方法畸形）
  query_param_rejected: 'probe', // middleware/queryLimit.js（NoSQL 操作符/超长参数指纹）
  rate_limit_abuse: 'rate_abuse', // services/rateLimitEscalationBan.js（限流触顶升级封禁）
  permission_abuse: 'privilege', // middleware/rbac.js → securityAlertPermissionAbuse
  privilege_escalation: 'privilege', // ipListSegmentGuards / forensicController 等越权尝试
  bulk_data_export: 'data_exfil', // services/securityAlert.js checkBulkExport
  view_sensitive_data: 'data_exfil', // sensitive.js / piiExportQuota / reportExportService
  login_unusual_time: 'anomaly', // services/authService/session.js
});

// 逐条校验分类码合法：拼写错误当场炸在启动期，而不是在查询面表现为一个永远为 0 的分类。
const resolveActionMap = () => {
  const knownCodes = new Set(ATTACK_EVENT_TYPES.map((t) => t.code));
  for (const [action, code] of Object.entries(ATTACK_EVENT_ACTION_MAP)) {
    if (!knownCodes.has(code)) {
      throw new Error(
        `attackEvents 注册表损坏：action '${action}' 映射到未知分类码 '${code}'` +
          `（合法分类：${[...knownCodes].join('/')}）`
      );
    }
  }
  return Object.freeze({ ...ATTACK_EVENT_ACTION_MAP });
};

const RESOLVED_ACTION_MAP = resolveActionMap();

/** action → 分类码；未注册的 action 返回 undefined（调用方决定兜底语义） */
const attackTypeOfAction = (action) => RESOLVED_ACTION_MAP[action];

/** 分类码 → 该分类的 action 数组（顺序稳定，供 $in 切片与规则名下拉复用） */
const actionsByAttackType = (code) =>
  Object.entries(RESOLVED_ACTION_MAP)
    .filter(([, typeCode]) => typeCode === code)
    .map(([action]) => action);

/** 注册表全集：攻击告警读面的基查询谓词（action $in），冻结防调用方 push 漂移 */
const ALL_ATTACK_EVENT_ACTIONS = Object.freeze(Object.keys(RESOLVED_ACTION_MAP));

/** 分类码枚举（查询入参校验白名单），顺序同 ATTACK_EVENT_TYPES */
const ATTACK_EVENT_TYPE_CODES = Object.freeze(ATTACK_EVENT_TYPES.map((t) => t.code));

module.exports = {
  ATTACK_EVENT_TYPES,
  ATTACK_EVENT_TYPE_CODES,
  ALL_ATTACK_EVENT_ACTIONS,
  attackTypeOfAction,
  actionsByAttackType,
};
