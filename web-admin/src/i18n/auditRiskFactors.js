/**
 * 风险因素（riskFactors）的展示期翻译层。
 *
 * 与 auditReasons.js 同一先例：只翻译渲染结果，绝不动落库原文——riskFactors 是
 * 哈希载荷 v6 里受保护的字段，改写入值等于改证据。
 *
 * 为什么需要它：riskFactors 存的是机器码（full_range_cidr_attempt 之类），旧详情
 * 页把码原样砸给客户，看不懂等于没提示。这里给每个码配「短标签 + 悬浮解释」，
 * 客户能看懂「这条记录为什么被标风险」。
 *
 * 未知码原样回退（沿用 auditLabels 惯例）：宁可露出机器码，也不猜一个语义。
 * 新增 risk 码必须同步在本文件登记，否则 src/tests/ci/riskFactorVocabularyGate.test.js
 * 会红——该闸扫描 src 非测试源码里的 riskFactors 字面量与本文件登记集做对齐。
 */

/** 已知风险码 → { zh: [标签, 解释], en: [label, tooltip] }。 */
const REGISTRY = {
  rate_limit_attempt: {
    zh: ['登录被限流拦下', '同一 IP 或同一账户在窗口内的尝试超过配额，未走到口令比对就被拦下'],
    en: [
      'Login blocked by rate limit',
      'Too many attempts from this IP or account in the window; blocked before the password was checked',
    ],
  },
  admin_mfa_reset: {
    zh: ['管理员重置 MFA', '他人的 MFA 凭证被管理员替换：旧认证器即刻失效，需核对操作人与工单'],
    en: [
      "Admin reset another user's MFA",
      'MFA credential replaced by an administrator; the old authenticator stops working',
    ],
  },
  admin_password_reset: {
    zh: ['管理员重置口令', '管理员代重置他人登录口令，临时口令一次性下发并强制改密'],
    en: [
      "Admin reset another user's password",
      'An administrator issued a one-time temporary password with forced rotation',
    ],
  },
  all_sessions_revoked: {
    zh: ['全部会话被吊销', '该用户所有会话（含刷新令牌）同时失效，常见于改密、封禁与安全响应'],
    en: [
      'All sessions revoked',
      'Every session and refresh token of this user was invalidated at once',
    ],
  },
  batch: {
    zh: ['批量操作', '单次请求影响多条数据，需核对影响面与筛选条件'],
    en: ['Batch operation', 'A single request affected multiple records; verify the scope'],
  },
  batch_operation: {
    zh: ['批量操作', '单次请求影响多条数据，需核对影响面与筛选条件'],
    en: ['Batch operation', 'A single request affected multiple records; verify the scope'],
  },
  blacklist_db_degraded: {
    zh: ['黑名单降级放行', '黑名单库查询失败，请求按降级缓存判定——判定链路不再是权威来源'],
    en: [
      'Blacklist served from degraded cache',
      'The blacklist database lookup failed; the decision came from a fallback cache',
    ],
  },
  captcha_absent: {
    zh: ['未提交验证码', '人机校验环节缺少验证码，可能为脚本直连或客户端异常'],
    en: ['Captcha missing', 'No captcha was submitted for the human check step'],
  },
  captcha_mismatch: {
    zh: ['验证码不匹配', '提交的验证码与预期不符，常见于重复提交与脚本重放'],
    en: ['Captcha mismatch', 'The submitted captcha did not match the expected value'],
  },
  csrf_origin_violation: {
    zh: ['写操作来源不符', '写请求的 Origin 不在白名单内，存在跨站请求伪造嫌疑'],
    en: [
      'Write origin not allowlisted',
      'The Origin header of a write request is outside the allowlist (possible CSRF)',
    ],
  },
  deceptive_account_interaction: {
    zh: ['与诱饵账户交互', '请求命中了诱饵/蜜罐账户，几乎一定不是正常用户行为'],
    en: [
      'Interaction with a decoy account',
      'The request touched a decoy/honeypot account — almost never legitimate traffic',
    ],
  },
  delete_operation: {
    zh: ['删除操作', '本记录对应一次删除动作，数据一旦删除不可从审计侧恢复'],
    en: [
      'Delete operation',
      'This record covers a destructive delete; data cannot be restored from audit',
    ],
  },
  empty_origin: {
    zh: ['来源头为空', '写请求的 Origin 是空串（不是缺失），属异常客户端形态'],
    en: [
      'Empty Origin header',
      'The Origin header was an empty string (not absent) — abnormal client',
    ],
  },
  error_response: {
    zh: ['错误响应', '本次请求以 4xx/5xx 结束，详情见响应状态与错误信息'],
    en: ['Error response', 'The request ended with a 4xx/5xx status; see status and error info'],
  },
  excessive_failed_logins: {
    zh: ['登录失败次数超标', '同一账户或同一 IP 连续失败超过阈值，已触发防护'],
    en: [
      'Excessive failed sign-ins',
      'Consecutive failures exceeded the threshold for this account or IP',
    ],
  },
  forced_password_change: {
    zh: ['强制改密', '该账户被要求下一次登录必须修改口令'],
    en: ['Forced password change', 'This account must rotate its password on next sign-in'],
  },
  full_range_cidr_attempt: {
    zh: ['试图加入全网段', '尝试写入 0.0.0.0/0 一类全网段名单条目，会导致防线/限制全局失效'],
    en: [
      'Full-range CIDR attempt',
      'An attempt to add a 0.0.0.0/0 style entry that would cover the entire address space',
    ],
  },
  full_range_cidr_concurrent_bypass: {
    zh: ['并发绕过全网段闸', '通过并发写入绕过全网段校验（竞态），需核对并发时间窗'],
    en: [
      'Full-range guard bypassed concurrently',
      'A race window let a full-range entry through; inspect the concurrent requests',
    ],
  },
  full_range_cidr_no_rescue_path: {
    zh: ['全网段且无救援路径', '名单覆盖全部地址且未保留救援通道，一旦误封将无法自恢复'],
    en: [
      'Full-range without rescue path',
      'The list covers everything and keeps no rescue entry — a mistake would lock everyone out',
    ],
  },
  full_range_cidr_removal_attempt: {
    zh: ['试图移除全网段条目', '尝试删除覆盖全部地址的名单条目，等于拆除防护'],
    en: [
      'Attempt to remove a full-range entry',
      'An attempt to delete a list entry that covers the entire address space',
    ],
  },
  full_range_cidr_rescue_removal_attempt: {
    zh: ['试图移除救援条目', '尝试删除全网段覆盖下的救援通道，会失去自恢复能力'],
    en: [
      'Attempt to remove the rescue entry',
      'Removing the rescue entry would leave no recovery path for a full-range rule',
    ],
  },
  full_range_cidr_super_admin_grant: {
    zh: ['超管授予全网段', '内置超管亲自写入全网段条目，属高爆炸半径操作'],
    en: [
      'Super admin granted full range',
      'The built-in super admin wrote a full-range entry — blast radius is the whole deployment',
    ],
  },
  honeypot_account_socket_attempt: {
    zh: ['蜜罐账户连接尝试', '有连接尝试命中蜜罐账户名，已记录对端地址用于溯源'],
    en: [
      'Honeypot connection attempt',
      'A connection targeted a honeypot account name; peer address recorded',
    ],
  },
  ip_blacklisted: {
    zh: ['IP 命中黑名单', '请求来源地址已在黑名单内，访问被直接拒绝'],
    en: [
      'IP blacklisted',
      'The source address is on the blacklist; the request was rejected outright',
    ],
  },
  ip_range_violation: {
    zh: ['IP 不在允许范围', '登录/操作地址不归属于该账户允许的地址段'],
    en: [
      'IP outside allowed range',
      'The request came from outside the address ranges allowed for this account',
    ],
  },
  large_segment_whitelist: {
    zh: ['大网段白名单', '白名单条目覆盖了较大地址段，放行面比单地址宽得多'],
    en: [
      'Large-segment allowlist entry',
      'The allowlist entry covers a wide address range instead of a single host',
    ],
  },
  mfa_bruteforce: {
    zh: ['MFA 暴力尝试', '同一账户的 MFA 校验连续失败，已计入暴力破解计数'],
    en: ['MFA brute force', 'Repeated MFA verification failures for one account were counted'],
  },
  mfa_code_invalid: {
    zh: ['MFA 码无效', '提交的动态码与当前时间窗不匹配（或已使用）'],
    en: ['Invalid MFA code', 'The submitted code does not match the current time window'],
  },
  mfa_code_replay: {
    zh: ['MFA 码重放', '同一个动态码被重复提交，属典型重放攻击形态'],
    en: ['MFA code replay', 'The same one-time code was submitted twice — classic replay'],
  },
  mfa_code_replayed: {
    zh: ['MFA 码已使用', '该动态码已经完成过一次校验，不得再次使用'],
    en: ['MFA code already used', 'This one-time code has already been consumed once'],
  },
  mfa_counter_unavailable: {
    zh: ['MFA 计数器不可用', 'TOTP 计数器存储不可用，重放防护降级为内存兜底'],
    en: [
      'MFA counter unavailable',
      'The TOTP counter store was unreachable; replay protection fell back to memory',
    ],
  },
  mfa_disabled: {
    zh: ['MFA 被关闭', '该账户的双因子认证被关闭，后续登录只剩单因子'],
    en: ['MFA disabled', 'Two-factor authentication was turned off for this account'],
  },
  multi_hop_proxy: {
    zh: ['多跳代理链', '请求经过多个代理转发（XFF 链过长），真实来源难以确证'],
    en: [
      'Multi-hop proxy chain',
      'The request traversed several proxies; the true origin cannot be established',
    ],
  },
  protocol_violation: {
    zh: ['协议不合规', '请求形态违反接口约定（如错误的方法/头/编码组合）'],
    en: ['Protocol violation', 'The request shape breaks the API contract'],
  },
  query_length_violation: {
    zh: ['查询值超长', '查询参数值超过上限，已拒绝（防注入与拒绝服务）'],
    en: ['Query value too long', 'A query parameter exceeded the length limit and was rejected'],
  },
  query_operator_violation: {
    zh: ['查询操作符注入', '查询参数里出现了 MongoDB 操作符形态的键，已拒绝'],
    en: [
      'Query operator injection',
      'A query parameter carried MongoDB operator keys and was rejected',
    ],
  },
  recovery_code_used: {
    zh: ['使用恢复码', '本次 MFA 校验使用了备用恢复码（离线抄本）'],
    en: ['Recovery code used', 'This MFA verification consumed a backup recovery code'],
  },
  refresh_token_rejected: {
    zh: ['刷新令牌被拒', '刷新令牌无效或已失效，会话未能续期'],
    en: [
      'Refresh token rejected',
      'The refresh token was invalid or expired; the session could not renew',
    ],
  },
  refresh_token_replay: {
    zh: ['刷新令牌重放', '已轮换的刷新令牌被再次使用，可能为令牌泄露'],
    en: ['Refresh token replay', 'A rotated refresh token was used again — possible token theft'],
  },
  unusual_time_access: {
    zh: ['非常规时段访问', '访问发生在该账户平常不活跃的时段'],
    en: ['Unusual-time access', 'The access happened at a time this account is normally inactive'],
  },
  user_anonymized: {
    zh: ['用户已匿名化', '关联用户已完成匿名化处理，原始身份信息不可再关联'],
    en: ['User anonymized', 'The linked user has been anonymized; original identity is unlinkable'],
  },
  canary_username_attempt: {
    zh: ['金丝雀账户尝试', '有登录尝试命中了金丝雀账户名——它是诱饵，正常用户不应触碰'],
    en: [
      'Canary username attempt',
      'A sign-in attempt targeted a canary account name; legitimate users never touch it',
    ],
  },
  honeypot_account_login: {
    zh: ['蜜罐账户登录尝试', '有登录请求指向蜜罐账户，请求体仅保留脱敏后的审计线索'],
    en: [
      'Honeypot account login attempt',
      'A sign-in targeted a honeypot account; only redacted audit clues are kept',
    ],
  },
  honeypot_account_probe: {
    zh: ['蜜罐账户探测', '请求只是探了一下蜜罐账户是否存在，尚未尝试认证'],
    en: ['Honeypot account probe', 'The request only probed whether a honeypot account exists'],
  },
  honeypot_account_write_attempt: {
    zh: ['蜜罐账户写操作', '对蜜罐账户发起了写操作，属于典型攻击试探'],
    en: [
      'Honeypot account write attempt',
      'A write was attempted against a honeypot account — typical probing behaviour',
    ],
  },
  honeypot_chain_escalated: {
    zh: ['蜜罐链升级', '同一个访问者在蜜罐链上连续命中多个阶段，已按升级处理'],
    en: [
      'Honeypot chain escalated',
      'The same visitor hit several honeypot stages in sequence; handled as escalation',
    ],
  },
  nonexistent_account_probe: {
    zh: ['不存在账户探测', '反复尝试登录不存在的账户，常见于账户枚举'],
    en: [
      'Non-existent account probe',
      'Repeated sign-in attempts against accounts that do not exist — account enumeration',
    ],
  },
  full_range_cidr_pool_ban_union_prewrite: {
    zh: ['全网段与封禁并集预写', '即将写入的条目会与封禁集合并成全地址覆盖，写入前已登记'],
    en: [
      'Full-range / ban union pre-write',
      'The pending entry would union with the ban set into full address coverage; logged before writing',
    ],
  },
  full_range_cidr_pool_ban_union_rollback: {
    zh: ['并集写入已回滚', '上一步预写已被回滚，名单恢复为写入前状态'],
    en: [
      'Union write rolled back',
      'The pre-write was rolled back and the list returned to its previous state',
    ],
  },
  // 2026-11-05 攻击检测面四码（injectionSignature / injectionDetector / scanProbeDetector）
  injection_signature: {
    zh: [
      'SQL 注入特征命中',
      '请求参数命中 SQL 注入特征串库（边缘检测留痕，攻击方在探测可注入参数）',
    ],
    en: [
      'SQL injection signature hit',
      'Request matched a SQL injection signature (edge detection; someone probing for injectable parameters)',
    ],
  },
  mongo_operator_strip: {
    zh: [
      'NoSQL 操作符键剥离',
      // 文案里不得出现「$ 紧跟 where」的字面量：SAST 的 mongo-where 规则扫全仓真实文件，
      // 词条命中会让 sastWorkflowInvariants 的「零命中」不变量假红（本条即实测教训）。
      '请求中出现「$」起头的 Mongo 操作符键（where、ne 一族）并被剥离留痕——典型的 NoSQL 注入探测形态',
    ],
    en: [
      'Mongo operator key stripped',
      'Mongo operator keys (the where/ne family with a dollar prefix) were found in the request and stripped (classic NoSQL injection probing)',
    ],
  },
  scanner_path: {
    zh: ['扫描器路径探测', '命中已知扫描器路径指纹（目录爆破/漏洞探测工具的探测路径）'],
    en: [
      'Scanner path fingerprint',
      'Request hit a known scanner path fingerprint (directory brute-force / vulnerability probing tools)',
    ],
  },
  unmatched_path_storm: {
    zh: ['404 未匹配路径风暴', '同一来源在窗口内打出大量 404 未匹配路径——典型的目录爆破节奏'],
    en: [
      '404 unmatched-path storm',
      'One source produced a burst of unmatched (404) paths within the window — typical directory brute-forcing',
    ],
  },
}

/**
 * 风险码族：后端用「前缀 + 运行时取值」拼出来的码，没有可预先列举的清单。
 *
 * chain_stage_：蜜罐链阶段（services/honeypotChainWatch.js:155），阶段名就是各自的审计 action 码。
 * ip_attribution_：封禁/审计落点的归因裁定（utils/ipUtils 的 IP_ATTRIBUTION_KINDS），
 *   拼在 rateLimitEscalationBan.js 与 securityAlertPermissionAbuse.js 的审计因子处。
 *
 * 两族都按前缀翻译而不是逐个登记：漏一个取值，客户界面就直接露出机器码。
 * 未收录的取值原样露出尾部名字——宁可看到 action/裁定码，也不编一个语义。
 */
export const CHAIN_STAGE_PREFIX = 'chain_stage_'
export const IP_ATTRIBUTION_PREFIX = 'ip_attribution_'

const CHAIN_STAGE_LABELS = {
  login_failed: ['登录失败', 'failed sign-in'],
  canary_username_attempt: ['金丝雀账户尝试', 'canary username attempt'],
  honeypot_login: ['蜜罐账户登录', 'honeypot sign-in'],
  honeypot_probe: ['蜜罐内探测', 'honeypot probing'],
}

const IP_ATTRIBUTION_LABELS = {
  direct: ['直连对端', 'direct peer'],
  trusted_proxy: ['受信任代理', 'trusted proxy'],
  public_peer_header: ['公网对端头', 'public peer header'],
}

const isEn = (locale) =>
  String(locale || '')
    .toLowerCase()
    .startsWith('en')

const RISK_FAMILIES = [
  {
    prefix: CHAIN_STAGE_PREFIX,
    zh: '蜜罐链阶段：',
    en: 'Honeypot chain stage: ',
    names: CHAIN_STAGE_LABELS,
    descZh: (name) => '该访问者在蜜罐链上走到了「' + name + '」这一阶段',
    descEn: (name) => 'This visitor reached the ' + name + ' stage of the honeypot chain',
  },
  {
    prefix: IP_ATTRIBUTION_PREFIX,
    zh: 'IP 归属：',
    en: 'IP attribution: ',
    names: IP_ATTRIBUTION_LABELS,
    descZh: (name) => '封禁与审计的落点取自「' + name + '」的裁定，而不是 socket 对端本身',
    descEn: (name) =>
      'The ban and audit target came from the "' + name + '" ruling, not the socket peer',
  },
]

const familyOf = (code) => {
  const text = String(code || '')
  const family = RISK_FAMILIES.find((f) => text.startsWith(f.prefix))
  return family ? { family, name: text.slice(family.prefix.length) } : null
}

/** 码族短标签：不属于任何码族时返回 null，交由上层继续处理 */
export const riskFamilyLabel = (code, locale) => {
  const hit = familyOf(code)
  if (!hit) return null
  const known = hit.family.names[hit.name]
  const name = known ? known[isEn(locale) ? 1 : 0] : hit.name
  return (isEn(locale) ? hit.family.en : hit.family.zh) + name
}

const riskFamilyDesc = (code, locale) => {
  const hit = familyOf(code)
  if (!hit) return ''
  const known = hit.family.names[hit.name]
  const name = known ? known[isEn(locale) ? 1 : 0] : hit.name
  return isEn(locale) ? hit.family.descEn(name) : hit.family.descZh(name)
}
/** 中文自由文本风险因素 → 英文模板（参数原样搬运；对不上就保留中文）。
 *  括号用 [(（]…] 容差形态：securityAlert.js:139 的模板是半角括号，写成全角会让
 *  英文界面静默回退裸中文（本仓已发生过一次，见 auditReasons 同类教训）。 */
const FREE_TEXT_RULES = [
  { re: /^批量数据操作$/, en: () => 'Batch data operation' },
  {
    re: /^限流持续触顶[(（](.+)[)）]$/,
    en: (m) => 'Rate limit continuously saturated (' + m[1] + ')',
  },
  { re: /^限流持续触顶$/, en: () => 'Rate limit continuously saturated' },
  {
    // 括号前允许一个空格：securityAlert.js:139 的模板是半角括号且带前导空格（「超标 (账户:N, IP:M)」）
    re: /^登录失败次数超标 ?[(（]账户:(\d+), IP:(\d+)[)）]$/,
    en: (m) => 'Excessive failed sign-ins (account: ' + m[1] + ', IP: ' + m[2] + ')',
  },
]

const pick = (code, locale) => {
  const entry = REGISTRY[code]
  if (!entry) return null
  return String(locale || '')
    .toLowerCase()
    .startsWith('en')
    ? entry.en
    : entry.zh
}

/** 短标签：未知码原样返回（宁可露出机器码，也不猜语义）。 */
export const riskFactorLabel = (code, locale) => {
  const hit = pick(code, locale)
  if (hit) return hit[0]
  const familyLabel = riskFamilyLabel(code, locale)
  if (familyLabel) return familyLabel
  if (
    String(locale || '')
      .toLowerCase()
      .startsWith('en')
  ) {
    const rule = FREE_TEXT_RULES.find((r) => r.re.test(code))
    if (rule) return code.replace(rule.re, (...args) => rule.en(args))
  }
  return String(code)
}

/** 悬浮解释：未知码返回空串（模板据此不渲染 tooltip）。 */
export const riskFactorDesc = (code, locale) => {
  const hit = pick(code, locale)
  if (hit) return hit[1]
  return riskFamilyDesc(code, locale)
}

/** 已登记的风险码集合（网关互校与测试共用，排序保证断言稳定）。 */
export const RISK_FACTOR_CODES = Object.keys(REGISTRY).sort()

export const RISK_FACTOR_COUNT = RISK_FACTOR_CODES.length

export default riskFactorLabel
