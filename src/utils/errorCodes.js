/**
 * 错误码注册表（后端唯一事实来源）
 *
 * 目的：给前端提供机器可读的稳定错误标识（errors.errorCode），
 * 取代「中文字符串精确匹配」的脆弱翻译方案（后端文案一改前端映射即失效）。
 *
 * 响应契约（与前端 utils/api.js 的 resolveErrorMessage 对齐）：
 *   { success: false, message: <人读文案>, errors: { errorCode: 'MFA_CODE_INVALID', ...params } }
 *
 * 命名规范：DOMAIN_REASON，全大写下划线分隔。
 *
 * 安全约束（M-5 防枚举）：账户禁用/锁定/临时锁定等状态类失败
 * 不得注册区分性错误码——外部响应必须与「用户名或密码错误」完全一致，
 * 否则攻击者可借差异化响应枚举有效用户名。真实原因只进日志与审计。
 *
 * 迁移策略：本表只收录高频认证/安全路径（登录、验证码、MFA、IP 名单校验），
 * 即前端 EN 映射已覆盖的那部分消息；其余 ~270 处调用点保持 message-only
 * 行为不变，按模块渐进迁移（见迭代 backlog）。
 */

const ERROR_CODES = {
  // ================= 认证 =================
  // 登录凭证失败（用户不存在/密码错误/账户禁用/锁定共用，防枚举）
  AUTH_INVALID_CREDENTIALS: { status: 401, message: '用户名或密码错误' },
  // 登录 IP 不在账户允许范围
  //
  // 【已停用于登录路径】（P2-10）：登录接口不再返回此码。
  // allowedIPs 校验发生在密码比对之前，独立的 403 码使攻击者从受限 IP 之外
  // 即可区分「该用户名存在且配置了 IP 白名单」，构成用户名枚举预言机——
  // 与本文件顶部为账户禁用/锁定定下的 M-5 防枚举口径直接冲突。
  // 登录路径统一返回 AUTH_INVALID_CREDENTIALS，真实原因只进日志与审计。
  //
  // 保留注册表条目的原因：refresh 轮换路径同样做 IP 范围校验，
  // 且前端已有中英文案；该路径的调用方必须持有效 refresh token
  // （已证明账号存在），不构成枚举面，可继续使用区分性文案。
  AUTH_IP_RANGE_DENIED: { status: 403, message: '当前 IP 不在您的允许访问范围内' },
  // 当前会话用户已被删除（/auth/me 等自身端点）
  AUTH_USER_NOT_FOUND: { status: 404, message: '用户不存在' },
  // 登录/改密等口令密文轨解密失败（信封损坏、时间窗过期、nonce 重放等统一口径，
  // 不区分具体原因——差异化错误可被用于探测服务端校验逻辑）
  AUTH_ENCRYPTED_CREDENTIAL_INVALID: {
    status: 400,
    message: '口令密文无效或已过期，请刷新页面后重试',
  },

  // ================= 图形验证码 =================
  CAPTCHA_INVALID: { status: 400, message: '验证码错误或已过期' },
  CAPTCHA_SERVICE_UNAVAILABLE: { status: 503, message: '验证码服务繁忙，请稍后重试' },

  // ================= 会话吊销 =================
  // 登出时令牌吊销未能落库（P2-26 fail-closed）
  //
  // 必须是失败响应而非「登出成功」：前端据此保留本地令牌并提示重试，
  // 用户才知道旧令牌仍然有效、需要采取补救（改密码、联系管理员）。
  // 若沿用原先的 fail-open（照常返回成功），被窃取的 access token 会在其
  // 剩余有效期内持续可用，而用户已认为自己安全登出。
  LOGOUT_REVOKE_FAILED: {
    status: 503,
    message: '登出未完成：令牌吊销服务暂不可用，请稍后重试（当前令牌仍然有效）',
  },

  // ================= MFA 两步验证 =================
  // 登录二次验证码错误
  MFA_CODE_INVALID: { status: 401, message: '两步验证码错误' },
  MFA_NOT_ENABLED: { status: 400, message: '两步验证未开启' },
  MFA_NOT_ENABLED_NO_CODES: { status: 400, message: '两步验证未开启，无需生成恢复码' },
  MFA_ALREADY_ENABLED: { status: 400, message: '两步验证已开启' },
  MFA_ALREADY_ENABLED_NO_REPEAT: { status: 400, message: '两步验证已开启，无需重复开启' },
  MFA_SECRET_MISSING: { status: 400, message: '请先生成两步验证密钥' },
  MFA_CODE_FORMAT: { status: 400, message: '请输入 6 位验证码' },
  MFA_CODE_INVALID_SYNC: { status: 400, message: '验证码错误，请确认认证器时间同步后重试' },
  MFA_VERIFY_FAILED: { status: 403, message: '身份验证失败，请提供正确的动态口令或登录密码' },
  MFA_ATTEMPTS_EXCEEDED: { status: 429, message: '验证尝试次数过多，请 10 分钟后再试' },
  MFA_REGEN_CODE_INVALID: { status: 400, message: '验证码错误，请重试' },

  // ================= 用户管理 / 超管不可变 =================
  // 不能删除自己的账户（任何操作者触发，含本人）
  CANNOT_DELETE_SELF: { status: 400, message: '不能删除自己的账户' },
  // 不能删除超级管理员账户（任一超管发起都拒绝）
  CANNOT_DELETE_SUPER_ADMIN: {
    status: 403,
    message: '不能删除超级管理员账户：系统必须保留唯一的最高权限账户',
  },
  // 不能禁用超级管理员账户（因禁用后无任何接口可将其恢复）
  CANNOT_DISABLE_SUPER_ADMIN: {
    status: 403,
    message: '不能禁用超级管理员账户：禁用后无任何接口可将其恢复',
  },
  // 不能锁定超级管理员账户（因锁定后无任何接口可将其解锁）
  CANNOT_LOCK_SUPER_ADMIN: {
    status: 403,
    message: '不能锁定超级管理员账户：锁定后无任何接口可将其解锁',
  },
  // 创建用户时携带 SUPER_ADMIN 角色
  CANNOT_GRANT_SUPER_ADMIN_ON_CREATE: {
    status: 403,
    message: '不能在创建用户时分配超级管理员角色：系统只允许存在一位超级管理员',
  },
  // 超级管理员角色不可被剥离（assignRoles 自锁死防护）
  SUPER_ADMIN_ROLE_NOT_DETACHABLE: {
    status: 403,
    message: '超级管理员角色不可被剥离：该角色是系统唯一的最高权限来源，剥离后无任何接口可将其恢复',
  },
  // 超级管理员角色不可被授予（归属唯一性防护）
  SUPER_ADMIN_ROLE_NOT_GRANTABLE: {
    status: 403,
    message: '超级管理员角色不可被授予：系统只允许存在一位超级管理员，其归属由启动期对账固定',
  },
  // 超管角色权限集不可修改
  SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED: {
    status: 403,
    message: '超级管理员角色的权限不可修改：其通配权限（*:*）由系统启动时对账维护',
  },
  // 超管角色不可克隆
  SUPER_ADMIN_ROLE_NOT_CLONABLE: {
    status: 403,
    message: '超级管理员角色不可克隆调整：克隆会将该账户切换到非内置角色，等同于剥离最高权限',
  },
  // 不能重置超级管理员的两步验证（与角色保护并列的安全要求）
  CANNOT_RESET_MFA_SUPER_ADMIN: {
    status: 403,
    message: '不能重置超级管理员的两步验证',
  },

  // ================= IP 名单校验 =================
  IP_REQUIRED: { status: 400, message: '请提供有效的 IP 地址' },
  IP_SINGLE_REQUIRED: {
    status: 400,
    message: '请提供有效的 IP 地址（支持 IPv4/IPv6 单地址，不含 CIDR 网段）',
  },
  IP_FORMAT_INVALID: {
    status: 400,
    message: 'IP 地址格式无效（支持 IPv4/IPv6/CIDR 网段，示例：192.168.0.0/16、2001:db8::/64）',
  },

  // ================= 报表导出 =================
  // 审计日志导出需额外持有 security:audit（report:export 不足以放行）
  AUDIT_EXPORT_REQUIRES_AUDIT_PERM: {
    status: 403,
    message: '导出审计日志需要审计查看权限（security:audit）',
  },

  // ================= 列表查询参数 =================
  // 查询参数须为标量：对象/数组会作为 Mongo 操作符注入过滤条件
  QUERY_PARAM_MUST_BE_SCALAR: {
    status: 400,
    message: '查询参数格式无效：不接受对象或数组形式的取值',
  },
};

/**
 * 校验注册表完整性（供单测与启动自检使用）：
 * 每个码必须有 status(number) 与 message(非空 string)
 */
const validateRegistry = () => {
  const problems = [];
  for (const [code, def] of Object.entries(ERROR_CODES)) {
    if (typeof def.status !== 'number' || def.status < 400 || def.status > 599) {
      problems.push(`${code}: status 非法（${def.status}）`);
    }
    if (typeof def.message !== 'string' || !def.message.trim()) {
      problems.push(`${code}: message 缺失`);
    }
  }
  return problems;
};

module.exports = {
  ERROR_CODES,
  validateRegistry,
};
