/**
 * 错误码注册表（后端唯一事实来源）
 * 目的：给前端机器可读的稳定错误标识（errors.errorCode），取代「中文字符串精确匹配」的脆弱翻译方案。
 * 响应契约（与前端 utils/api.js 的 resolveErrorMessage 对齐）：{ success: false, message: <人读文案>, errors: { errorCode: 'MFA_CODE_INVALID', ...params } }
 * 命名规范：DOMAIN_REASON，全大写下划线分隔。
 * 安全约束（防枚举）：账户禁用/锁定/临时锁定等状态类失败不得注册区分性错误码——外部响应必须与「用户名或密码错误」完全一致，否则攻击者可借差异化响应枚举有效用户名。真实原因只进日志与审计。
 * 迁移策略：本表只收录高频认证/安全路径（登录、验证码、MFA、IP 名单校验）即前端 EN 映射已覆盖的那部分消息；其余 ~270 处调用点保持 message-only 行为不变，按模块渐进迁移（见迭代 backlog）。
 */

const ERROR_CODES = {
  // ================= 认证 =================
  // 登录凭证失败（用户不存在/密码错误/账户禁用/锁定共用，防枚举）
  AUTH_INVALID_CREDENTIALS: { status: 401, message: '用户名或密码错误' },
  // 登录 IP 不在账户允许范围
  //
  // 【已停用于登录路径】：登录接口不再返回此码。
  // allowedIPs 校验发生在密码比对之前，独立的 403 码使攻击者从受限 IP 之外
  // 即可区分「该用户名存在且配置了 IP 白名单」，构成用户名枚举预言机——
  // 与本文件顶部为账户禁用/锁定定下的防枚举口径直接冲突。
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
  // 登出时令牌吊销未能落库（fail-closed）
  //
  // 必须是失败响应而非「登出成功」：前端据此保留本地令牌并提示重试，
  // 用户才知道旧令牌仍然有效、需要采取补救（改密码、联系管理员）。
  // 若沿用原先的 fail-open（照常返回成功），被窃取的 access token 会在其
  // 剩余有效期内持续可用，而用户已认为自己安全登出。
  LOGOUT_REVOKE_FAILED: {
    status: 503,
    message: '登出未完成：令牌吊销服务暂不可用，请稍后重试（当前令牌仍然有效）',
  },
  // 登出时出示了**不属于自己**的 refresh 令牌（F-100 剩的另一半）
  //
  // 为什么必须整次拒绝（403）而不是"跳过那条、照常登出"：
  // ① 跳过 = 静默忽略一个**安全相关**的异常输入，调用方无从得知有人正拿着
  //    别人的 refresh 串打这个接口——那可能是令牌泄露的探针；
  // ② 旧实现会把它**直接吊销**：任何已认证用户只要拿到（或猜到）他人的
  //    refresh 串，就能在对方毫不知情的情况下终结其会话（会话 DoS），
  //    而登出接口自己还回 200「已登出」。
  // 选 403 而非 400：这是"你出示了不该你出示的东西"，与越权同族。
  // 整次失败意味着不清 cookie、不动会话表——部分成功会让"登出"这件事
  // 处于说不清的状态，正是同门的 fail-open。
  LOGOUT_REFRESH_FOREIGN: {
    status: 403,
    message: '登出未完成：请求中包含不属于当前账号的刷新令牌，已拒绝本次登出',
  },

  // 数据范围不可用（type:'none' / 部门档无部门 / self 档无 userId / 未知 type）
  //
  // 为什么是 403 而不是 200 + 空集：空集让调用方**分不清「没有」与「不能看」**。
  // 前者是"这个部门今天确实没有报警"，后者是"你这个人不在这个部门可见范围里"——
  // 两者的后续动作完全相反（一个继续等数据，一个去找管理员开权限），而响应一模一样。
  // 与"宁声明勿假装完整"同族：导出截断要喊（X-Export-Truncated），范围不可用也要喊。
  // 落点是 middleware/rbac.js 的 applyDataScopeToQuery（列表/统计共用的唯一收口）、
  // services/auditScopeFilter.js 与 services/reportExportService.js 的 scopeFilterFor
  // ——三处原先都回空集。
  DATA_SCOPE_DENIED: {
    status: 403,
    message: '当前账号没有可用的数据范围（未分配部门或权限不足），请联系管理员',
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
  MFA_VERIFY_FAILED: { status: 403, message: '身份验证失败，请提供正确的动态口令或备用恢复码' },
  MFA_SECOND_FACTOR_REQUIRED: {
    status: 403,
    message: '关闭两步验证需提供动态口令或备用恢复码（密码不能单独作为第二因子）',
  },
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

  // P1-2（2026-10-30）：管理员重置口令的边界
  CANNOT_RESET_OWN_PASSWORD_VIA_ADMIN: {
    status: 400,
    message: '不能通过管理员重置接口修改自己的口令，请使用个人资料中的修改密码',
  },
  CANNOT_RESET_PASSWORD_SUPER_ADMIN: {
    status: 403,
    message: '不能重置超级管理员的口令：系统必须保留唯一的最高权限账户',
  },
  PASSWORD_RESET_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '不能重置同级或更高级别账户的口令',
  },
  PASSWORD_RESET_FAILED: {
    status: 500,
    message: '口令重置失败，请重试或联系运维',
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

  // ================= i18n 全量改造：业务与协议错误码 =================
  DATE_PARAM_INVALID: {
    status: 400,
    message: '日期参数格式错误',
  },
  DATE_RANGE_INVALID: {
    status: 400,
    message: '结束日期不能早于开始日期',
  },
  VALIDATION_FAILED: {
    status: 400,
    message: '数据验证失败',
  },
  ALARM_NOT_FOUND: {
    status: 404,
    message: '报警记录不存在',
  },
  ALARM_VIEW_FORBIDDEN: {
    status: 403,
    message: '无权查看该报警记录',
  },
  ALARM_OPERATE_FORBIDDEN: {
    status: 403,
    message: '无权操作该报警记录',
  },
  ALARM_BUILDING_REQUIRED: {
    status: 400,
    message: '请提供报警所在楼栋；关联设备时可自动继承设备楼栋',
  },
  ALARM_ALREADY_HANDLED: {
    status: 409,
    message: '该报警已被处理',
  },
  ALARM_STATUS_NOT_ALLOWED_SHORT: {
    status: 409,
    message: '报警状态不允许此操作',
  },
  ALARM_HANDLE_RESULT_REQUIRED: {
    status: 400,
    message: '请提供处理结果描述',
  },
  ALARM_STATUS_NOT_ALLOWED: {
    status: 409,
    message: '该报警当前状态不允许此操作',
  },
  UNAUTHORIZED_ACCESS: {
    status: 401,
    message: '未授权访问',
  },
  AUDIT_EXPORT_FAILED: {
    status: 500,
    message: '审计日志导出失败',
  },
  LIMIT_MUST_BE_POSITIVE_INT: {
    status: 400,
    message: 'limit 必须是正整数',
  },
  FROM_MUST_BE_LATEST_OR_EARLIEST: {
    status: 400,
    message: 'from 只能是 latest 或 earliest',
  },
  REGISTER_INFO_INVALID: {
    status: 400,
    message: '注册信息无效或已被使用',
  },
  REFRESH_TOKEN_INVALID: {
    status: 401,
    message: '无效的刷新令牌',
  },
  REFRESH_TOKEN_MISSING: {
    status: 400,
    message: '缺少刷新令牌',
  },
  REFRESH_TOKEN_REVOKED: {
    status: 401,
    message: '刷新令牌已失效，请重新登录',
  },
  PASSWORD_CHANGED_RELOGIN: {
    status: 401,
    message: '密码已修改，请重新登录',
  },
  // P1-2：首次登录/管理员重置后未完成改密，业务接口一律拒绝
  PASSWORD_CHANGE_REQUIRED: {
    status: 403,
    message: '当前账户需要先修改密码（首次登录或管理员已重置口令）',
  },
  SESSION_EXPIRED: {
    status: 401,
    message: '会话已失效，请重新登录',
  },
  SECURITY_SERVICE_UNAVAILABLE: {
    status: 503,
    message: '安全服务暂不可用，请稍后重试',
  },
  DEVICE_SESSION_REVOKED: {
    status: 401,
    message: '该设备的登录已被终止，请重新登录',
  },
  REFRESH_TOKEN_EXPIRED: {
    status: 401,
    message: '刷新令牌已过期，请重新登录',
  },
  PASSWORD_CURRENT_AND_NEW_REQUIRED: {
    status: 400,
    message: '请提供当前密码和新密码',
  },
  USER_NOT_FOUND_OR_DELETED: {
    status: 401,
    message: '用户不存在或已被删除',
  },
  PASSWORD_CURRENT_INCORRECT: {
    status: 400,
    message: '当前密码错误',
  },
  PASSWORD_SAME_AS_OLD: {
    status: 400,
    message: '新密码不能与当前密码相同',
  },
  PASSWORD_REUSED_IN_HISTORY: {
    status: 400,
    // 必须点明"最近 N 条"而不是笼统说"不能重复"：用户需要知道边界才能换一个
    // 可用的口令，否则只能猜。N 由 utils/passwordHistory.HISTORY_DEPTH 决定，
    // 前端文案里的数字与该常量同源，不要各写一份。
    message: '新密码不能与最近使用过的密码相同',
  },
  PASSWORD_CHANGED_REVOKE_FAILED: {
    status: 503,
    message: '密码已修改，但会话吊销服务暂不可用，旧登录状态可能仍然有效，请重新登录',
  },
  USER_NOT_FOUND: {
    status: 401,
    message: '用户不存在',
  },
  PHONE_INVALID: {
    status: 400,
    message: '请输入有效的手机号码',
  },
  EMAIL_INVALID: {
    status: 400,
    message: '请输入有效的邮箱地址',
  },
  EMAIL_TAKEN: {
    status: 400,
    message: '该邮箱已被其他用户使用',
  },
  AVATAR_INVALID: {
    status: 400,
    message: '头像图片不合法（仅支持 JPEG/PNG，上限 256 KB）',
  },
  AVATAR_NOT_FOUND: {
    status: 404,
    message: '该用户尚未设置头像',
  },
  CANNOT_REVOKE_CURRENT_SESSION: {
    status: 400,
    message: '不能从会话列表中终止当前设备，请使用退出登录',
  },
  SESSION_NOT_FOUND: {
    status: 404,
    message: '会话不存在或已失效',
  },
  DEVICE_NOT_FOUND: {
    status: 404,
    message: '设备不存在',
  },
  DEVICE_VIEW_FORBIDDEN: {
    status: 403,
    message: '无权查看该设备',
  },
  DEVICE_OPERATE_FORBIDDEN: {
    status: 403,
    message: '无权操作该设备',
  },
  MAINTENANCE_CONTENT_REQUIRED: {
    status: 400,
    message: '请提供维护内容',
  },
  INSPECTION_NOT_FOUND: {
    status: 404,
    message: '巡检记录不存在',
  },
  INSPECTION_VIEW_FORBIDDEN: {
    status: 403,
    message: '无权查看该巡检记录',
  },
  INSPECTION_OPERATE_FORBIDDEN: {
    status: 403,
    message: '无权操作该巡检记录',
  },
  // ================= 取证溯源（T5/T6） =================
  // 溯源至少要给一个维度（IP / 指纹 / 网段）。地址解析不出也走这个码——退化成"匹配不到"的空结果
  // 会让运维以为该 IP 干净，而真相是地址打错了；明确报判据不可用才是诚实的。
  FORENSIC_NO_CRITERIA: {
    status: 400,
    message: '请至少提供一个查询维度（IP、设备指纹或网段），且地址格式必须可解析',
  },
  // 网段封禁被护栏拒绝。原因码在 errors.reason，取值见 constants/banRefusalReason（单一事实来源）；
  // 前端按 reason 给专属文案，笼统的"操作失败"会让运维不知道自己被哪一条挡住。
  FORENSIC_POOL_BAN_REFUSED: {
    status: 400,
    message: '网段封禁被拒绝，请查看具体原因',
  },
  // 未配置 FORENSIC_EXPORT_SECRET / AUDIT_HMAC_SECRET：宁可不导出，也不产出"看起来签过"的包
  FORENSIC_EXPORT_NO_SECRET: {
    status: 400,
    message: '服务端未配置取证导出密钥，请联系管理员',
  },
  // 溯源/聚类/导出自身失败（区别于"判据不可用"）
  FORENSIC_QUERY_FAILED: {
    status: 500,
    message: '取证数据查询失败，请稍后重试',
  },
  IP_LIST_TYPE_INVALID: {
    status: 400,
    message: '名单类型必须为 black（黑名单）或 white（白名单）',
  },
  IP_LIST_DURATION_OUT_OF_RANGE: {
    status: 400,
    message: '生效时长应在 0（永久）至 8760 小时之间',
  },
  IP_FULL_RANGE_SUPER_ADMIN_ONLY: {
    status: 403,
    message:
      '全网段（${normalizedIP}）会命中所有 IP，仅超级管理员可配置；如需限制特定范围请使用更精确的网段',
  },
  IP_COVERED_BY_WHITELIST: {
    status: 400,
    message:
      '该 IP 已被白名单条目（${coveredBy}）覆盖，白名单优先级高于黑名单；如需封禁请先将其移出白名单',
  },
  IP_SEGMENT_WRITE_REFUSED: {
    status: 400,
    message: '该网段写入被拒绝，请查看拒绝原因',
  },
  IP_LIST_ENTRY_NOT_FOUND: {
    status: 404,
    message: '名单记录不存在',
  },
  IP_FULL_RANGE_REMOVE_SUPER_ADMIN_ONLY: {
    status: 403,
    message:
      '全网段（${entry.ip}）名单仅超级管理员可移除：它是限流豁免与信任标记的前提，移除会影响全部 IP 的访问控制',
  },
  PERMISSION_NOT_FOUND: {
    status: 404,
    message: '权限不存在',
  },
  PARENT_PERMISSION_SELF: {
    status: 400,
    message: '父级权限不能是权限自身',
  },
  PARENT_PERMISSION_NOT_FOUND: {
    status: 400,
    message: '父级权限不存在',
  },
  PARENT_PERMISSION_CYCLE: {
    status: 400,
    message: '父级权限设置会形成循环引用（该权限已是目标父级的祖先）',
  },
  PERMISSION_TREE_DEPTH_ANOMALY: {
    status: 400,
    message: '权限树层级异常，请联系管理员核查父级引用',
  },
  PERMISSION_LIST_INVALID: {
    status: 400,
    message: '请提供有效的权限列表',
  },
  EXPORT_FORMAT_UNSUPPORTED: {
    status: 400,
    message: '不支持的导出格式: ${format}',
  },
  // P-2：导出并发闸拒绝。429 而非 503——503 是"本实例不可用"，网关会当成故障并更激进地重试；
  // 导出忙是**容量**问题，配合 Retry-After 按节奏退避才对。
  EXPORT_BUSY: {
    status: 429,
    message: '导出任务繁忙，请稍后重试',
  },
  // A-8：配额用尽。429 而非 403——不是"没有权限"，是"今天不行、稍后可以"。
  PII_EXPORT_QUOTA_EXCEEDED: {
    status: 429,
    message: '今日未脱敏导出已达配额，请稍后再试或联系管理员',
  },
  REPORT_TYPE_UNSUPPORTED: {
    status: 400,
    message: '不支持的报表类型',
  },
  ROLE_NOT_FOUND: {
    status: 404,
    message: '角色不存在',
  },
  ROLE_VIEW_FORBIDDEN: {
    status: 403,
    message: '无权查看该角色',
  },
  ROLE_CODE_TAKEN: {
    status: 400,
    message: '角色编码已存在',
  },
  ROLE_CODE_RESERVED: {
    status: 400,
    message: '该角色编码为内置保留编码，不能用于自定义角色',
  },
  ROLE_CREATE_HIGHER_LEVEL_FORBIDDEN: {
    status: 403,
    message: '无权创建高于自身层级的角色',
  },
  CANNOT_GRANT_WILDCARD_PERMISSION: {
    status: 403,
    message: '不能授予超级管理员权限（*:*）',
  },
  PERMISSION_GRANT_FORBIDDEN: {
    status: 403,
    message: "无权授予以下权限：${lacking.join('、')}",
  },
  ROLE_UPDATE_FORBIDDEN: {
    status: 403,
    message: '无权变更该角色',
  },
  ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN: {
    status: 403,
    message: '无权变更高于自身层级的角色',
  },
  BUILTIN_ROLE_NAME_LEVEL_LOCKED: {
    status: 403,
    message: '内置角色不能修改名称和层级',
  },
  ROLE_STATUS_INVALID: {
    status: 400,
    message: 'status 必须是 active 或 inactive',
  },
  BUILTIN_ROLE_STATUS_LOCKED: {
    status: 403,
    message: '内置角色不能修改状态',
  },
  ROLE_LEVEL_ABOVE_SELF_FORBIDDEN: {
    status: 403,
    message: '无权将角色层级设置为高于自身层级',
  },
  ROLE_NAME_REQUIRED: {
    status: 400,
    message: '角色名称不能为空',
  },
  ROLE_DELETE_FORBIDDEN: {
    status: 403,
    message: '无权删除该角色',
  },
  ROLE_DELETE_HIGHER_LEVEL_FORBIDDEN: {
    status: 403,
    message: '无权删除高于自身层级的角色',
  },
  BUILTIN_ROLE_NOT_DELETABLE: {
    status: 403,
    message: '内置角色不可删除',
  },
  ROLE_IN_USE: {
    status: 400,
    message: '有 ${userCount} 个用户正在使用该角色，请先移除这些用户的角色',
  },
  ROLE_STATE_CONFLICT: {
    status: 409,
    message: '角色状态已被其他操作修改，请刷新后重试',
  },
  PERMISSION_ID_REQUIRED: {
    status: 400,
    message: '请提供至少一个有效的权限 ID',
  },
  PERMISSION_ID_INVALID: {
    status: 400,
    message: '存在无效的权限 ID',
  },
  ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权修改等于或高于自身层级的角色权限',
  },
  ROLE_PERM_BASE_HIGHER_LEVEL_FORBIDDEN: {
    status: 403,
    message: '无权基于高于自身层级的角色调整权限',
  },
  PERMISSION_ASSIGN_FORBIDDEN: {
    status: 403,
    message: "无权分配以下权限：${lacking.join('、')}",
  },
  TARGET_USER_ID_INVALID: {
    status: 400,
    message: '目标用户 ID 格式无效',
  },
  TARGET_USER_NOT_FOUND: {
    status: 404,
    message: '目标用户不存在',
  },
  TARGET_USER_LACKS_ROLE: {
    status: 400,
    message: '目标用户未持有该角色，无法单独调整',
  },
  USER_ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权变更同级或更高级别用户的角色权限',
  },
  PASSWORD_CONFIRM_MISMATCH: {
    status: 400,
    message: '两次输入的新密码不一致',
  },
  PASSWORD_SAME_AS_CURRENT: {
    status: 400,
    message: '新密码不能与当前密码相同',
  },
  SENSITIVE_VIEW_HIGHER_LEVEL_FORBIDDEN: {
    status: 403,
    message: '无权查看更高层级用户的敏感信息',
  },
  SENSITIVE_VIEW_OUT_OF_SCOPE: {
    status: 403,
    message: '无权查看该用户（超出您的数据范围）',
  },
  UNSUPPORTED_DATA_TYPE: {
    status: 400,
    message: '不支持的数据类型',
  },
  REPORT_TARGET_AND_REASON_REQUIRED: {
    status: 400,
    message: '请提供目标类型和原因',
  },
  USER_OPERATE_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权操作同级或更高级别的用户',
  },
  UNLOCK_INACTIVE_ACCOUNT: {
    status: 400,
    message: '该账户已被管理员禁用（inactive），不能通过解锁恢复；请先由管理员启用该账户',
  },
  LOCK_INACTIVE_ACCOUNT: {
    status: 400,
    message: '该账户已被管理员禁用，不能重复锁定',
  },
  ACCOUNT_NOT_LOCKED: {
    status: 400,
    message: '该账户当前未处于锁定状态，无需解锁',
  },
  CANNOT_RESET_OWN_MFA_VIA_ADMIN: {
    status: 400,
    message: '不能通过管理接口重置自己的两步验证，请在个人资料页操作',
  },
  TARGET_MFA_NOT_ENABLED: {
    status: 400,
    message: '该用户未开启两步验证，无需重置',
  },
  MFA_RESET_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权重置同级或更高级别用户的两步验证',
  },
  SESSION_REVOKE_SERVICE_UNAVAILABLE: {
    status: 503,
    message: '会话吊销服务暂不可用，未执行重置，请稍后重试',
  },
  FORCE_LOGOUT_MFA_CLEAR_FAILED: {
    status: 503,
    message: '该用户已被强制下线，但两步验证状态清除失败，请重试',
  },
  SECURITY_OVERVIEW_FORMAT_INVALID: {
    status: 404,
    message: '安全概览数据格式错误',
  },
  SECURITY_OVERVIEW_STRUCTURE_INVALID: {
    status: 404,
    message: '安全概览数据结构错误',
  },
  SECURITY_OVERVIEW_QUERY_FAILED: {
    status: 500,
    message: '安全概览查询失败',
  },
  SECURITY_OVERVIEW_DEGRADED: {
    status: 503,
    message: '安全概览数据暂不可用（查询失败，不代表零风险）',
  },
  RECENT_ALERTS_EMPTY: {
    status: 404,
    message: '最近告警数据为空',
  },
  RECENT_ALERTS_QUERY_FAILED: {
    status: 500,
    message: '最近告警查询失败',
  },
  CONFIG_ALLOW_REGISTRATION_MUST_BE_BOOLEAN: {
    status: 400,
    message: '参数 allowPublicRegistration 必须为布尔值',
  },
  CONFIG_LOGIN_CAPTCHA_MUST_BE_BOOLEAN: {
    status: 400,
    message: '参数 loginCaptchaEnabled 必须为布尔值',
  },
  CONFIG_REGISTER_CAPTCHA_MUST_BE_BOOLEAN: {
    status: 400,
    message: '参数 registerCaptchaEnabled 必须为布尔值',
  },
  USER_VIEW_FORBIDDEN: {
    status: 403,
    message: '无权查看该用户',
  },
  USER_SCOPE_FORBIDDEN: {
    status: 403,
    message: '无权操作该用户（超出您的数据范围）',
  },
  IP_RULES_FORMAT_INVALID: {
    status: 400,
    message: "IP 范围规则格式有误：${check.invalid.join('、')}",
  },
  ROLE_NOT_FOUND_IN_LIST: {
    status: 400,
    message: '包含不存在的角色',
  },
  ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN: {
    status: 403,
    message: '无权分配高于自身层级的角色',
  },
  USER_UPDATE_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权修改同级或更高级别的用户',
  },
  // 修复：数据范围字段（department / allowedIPs）的越界变更。
  // 这两字段是数据可见范围与 IP 访问控制的判定依据，范围外改写等同越权提权。
  USER_SCOPE_FIELD_FORBIDDEN: {
    status: 403,
    message: '无权变更该用户的部门或 IP 访问范围（超出您的数据范围）',
  },
  CANNOT_CHANGE_OWN_STATUS: {
    status: 400,
    message: '不能通过本接口修改自身账户状态，请联系其他管理员处理',
  },
  USER_STATUS_CHANGE_FORBIDDEN: {
    status: 403,
    message: '无权变更用户状态（需要 user:lock 权限）',
  },
  EMAIL_TAKEN_SHORT: {
    status: 400,
    message: '邮箱已被使用',
  },
  ROLE_LIST_INVALID: {
    status: 400,
    message: '请提供有效的角色列表',
  },
  ROLE_ID_INVALID: {
    status: 400,
    message: '存在无效的角色 ID',
  },
  USER_ROLE_ASSIGN_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权变更同级或更高级别用户的角色',
  },
  ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN: {
    status: 403,
    message: "无权分配自身未持有的同级角色：${foreignRoles.join('、')}",
  },
  USER_DELETE_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权删除同级或更高级别的用户',
  },
  USER_ID_LIST_INVALID: {
    status: 400,
    message: '请提供有效的用户 ID 列表',
  },
  BATCH_DELETE_LIMIT_EXCEEDED: {
    status: 400,
    message: '单次批量删除最多 ${BATCH_DELETE_MAX} 个用户',
  },
  USER_ID_FORMAT_INVALID_IN_LIST: {
    status: 400,
    message: "包含非法的用户 ID 格式: ${invalidIds.slice(0, 5).join(', ')}",
  },
  USER_ID_NOT_FOUND_IN_LIST: {
    status: 400,
    message: '包含不存在的用户 ID',
  },
  USER_STATE_CONFLICT: {
    status: 409,
    message: '用户状态已被其他操作修改，请刷新后重试',
  },
  BATCH_DELETE_PEER_OR_HIGHER_FORBIDDEN: {
    status: 403,
    message: '无权删除同级或更高级别的用户：${oversized.username}',
  },
  AUTH_TOKEN_MISSING: {
    status: 401,
    message: '未提供认证令牌',
  },
  AUTH_TOKEN_REVOKED: {
    status: 401,
    message: '认证令牌已失效，请重新登录',
  },
  ACCOUNT_DISABLED: {
    status: 401,
    message: '账户已被禁用，请联系管理员',
  },
  ACCOUNT_LOCKED: {
    status: 401,
    message: '账户已被锁定，请联系管理员',
  },
  ACCOUNT_TEMP_LOCKED: {
    status: 401,
    message: '账户因多次登录失败被临时锁定，请稍后再试',
  },
  AUTH_TOKEN_INVALID: {
    status: 401,
    message: '无效的认证令牌',
  },
  AUTH_TOKEN_EXPIRED: {
    status: 401,
    message: '认证令牌已过期',
  },
  AUTH_PROCESS_FAILED: {
    status: 500,
    message: '认证过程出错',
  },
  JSON_PARSE_FAILED: {
    status: 400,
    message: '请求体 JSON 解析失败',
  },
  PAYLOAD_EXCEEDS_LIMIT: {
    status: 413,
    message: '请求体超过大小限制',
  },
  INTERNAL_ERROR: {
    status: 500,
    message: '服务器内部错误，请稍后重试',
  },
  METRICS_INTERNAL_ONLY: {
    status: 401,
    message: 'metrics 端点仅限内网访问',
  },
  HTTP_METHOD_UNSUPPORTED: {
    status: 405,
    message: '不支持的请求方法：${req.method}',
  },
  HEADER_COUNT_EXCESSIVE: {
    status: 431,
    message: '请求头数量异常',
  },
  HEADER_NAME_INVALID: {
    status: 400,
    message: '请求头格式非法',
  },
  HEADER_VALUE_TOO_LONG: {
    status: 431,
    message: '请求头长度超限',
  },
  HOST_HEADER_INVALID: {
    status: 400,
    message: '请求 Host 非法',
  },
  CONTENT_LENGTH_INVALID: {
    status: 400,
    message: 'Content-Length 头非法',
  },
  PAYLOAD_TOO_LARGE: {
    status: 413,
    message: '请求体过大',
  },
  CONTENT_TYPE_MISSING: {
    status: 400,
    message: '请求缺少 Content-Type 头',
  },
  CONTENT_TYPE_UNSUPPORTED: {
    status: 415,
    message: '不支持的 Content-Type：${mediaType}',
  },
  PERMISSION_DENIED: {
    status: 403,
    message: '您没有执行此操作的权限',
  },
  PERMISSION_CHECK_FAILED: {
    status: 500,
    message: '权限验证过程出错',
  },
  REAUTH_REQUIRED: {
    status: 403,
    message: '敏感操作需要重新验证身份，请提供当前密码或 MFA 验证码',
  },
  REAUTH_PASSWORD_INCORRECT: {
    status: 403,
    message: '当前密码错误，验证未通过',
  },
  REAUTH_MFA_NOT_ENABLED: {
    status: 403,
    message: '未开启两步验证，请使用当前密码验证',
  },
  REAUTH_MFA_REQUIRED: {
    status: 403,
    message: '已开启两步验证，请使用动态口令完成验证',
  },
  REAUTH_MFA_INCORRECT: {
    status: 403,
    message: 'MFA 验证码错误，验证未通过',
  },
  REAUTH_PROCESS_FAILED: {
    status: 500,
    message: '身份验证过程出错',
  },
  REAUTH_TICKET_REQUIRED: {
    status: 401,
    message: '查看审计数据需要先完成二次验证',
  },
  REAUTH_TICKET_INVALID: {
    status: 401,
    message: '二次验证票据无效或已过期，请重新验证',
  },
  IDEMPOTENCY_KEY_REQUIRED: {
    status: 400,
    message: '该操作要求携带 Idempotency-Key 请求头；同一次提交重试请复用同一个键',
  },
  IDEMPOTENCY_KEY_INVALID: {
    status: 400,
    message: 'Idempotency-Key 格式无效：应为 8-64 位可见 ASCII 字符（建议使用 UUID）',
  },
  IDEMPOTENCY_IN_PROGRESS: {
    status: 409,
    message: '同一提交正在处理中，请勿重复提交',
  },
  IDEMPOTENCY_KEY_REUSED: {
    status: 409,
    message: '该 Idempotency-Key 已用于另一次内容不同的提交，请更换键后重试',
  },
  IP_BLOCKED: {
    status: 403,
    message: '您的 IP 已被禁止访问',
  },
  UPLOAD_FILE_TOO_LARGE: {
    status: 400,
    message: '文件 ${file.originalname} 超过最大限制 ${maxSize / 1024 / 1024}MB',
  },
  UPLOAD_TYPE_NOT_ALLOWED: {
    status: 400,
    message: '不允许的文件类型：${file.mimetype}',
  },
  UPLOAD_EXT_NOT_ALLOWED: {
    status: 400,
    message: '不允许的文件扩展名：.${ext}',
  },
  PARAM_MUST_BE_VALID_OBJECT_ID: {
    status: 400,
    message: "参数 ${name || 'id'} 必须是合法的对象 ID",
  },
  PUBLIC_REGISTRATION_DISABLED: {
    status: 403,
    message: '当前系统已关闭公开注册，请联系管理员创建账户',
  },
  REGISTER_SERVICE_UNAVAILABLE: {
    status: 503,
    message: '注册服务暂不可用，请稍后重试',
  },
  // 一-7：未勾选隐私告知同意。400 而非 403——这不是"没有权限"，是本次请求缺少必备的
  // 明示同意（前端必须渲染可点击的告知入口，而不是把同意藏进"注册即表示同意"）。
  PRIVACY_CONSENT_REQUIRED: {
    status: 400,
    message: '请阅读并同意隐私告知后再注册',
  },
  AUDIT_QUERY_FAILED: {
    status: 500,
    message: '审计日志查询失败',
  },
  AUDIT_LOG_NOT_FOUND: {
    status: 404,
    message: '审计日志不存在',
  },
  FULL_RANGE_FORBIDDEN: {
    status: 403,
    message: '全网段名单仅超级管理员可配置或移除',
  },

  SUPER_ADMIN_REQUIRED: {
    status: 403,
    message: '该操作仅超级管理员可执行',
  },
  UPGRADE_DISABLED: {
    status: 503,
    message: '升级未启用，请联系运维开启服务端开关',
  },
  UPGRADE_IMAGE_INVALID: {
    status: 400,
    message: '镜像地址无效：请使用 name@sha256:<64 位十六进制摘要> 形式',
  },
  UPGRADE_IMAGE_NOT_ALLOWED: {
    status: 403,
    message: '镜像仓库不在升级白名单内',
  },
  UPGRADE_ALREADY_RUNNING: {
    status: 409,
    message: '已有升级任务进行中或排队，请等待其结束后再试',
  },
  UPGRADE_QUEUE_UNAVAILABLE: {
    status: 503,
    message: '升级队列不可用（目录不可写或宿主代理离线），请检查部署',
  },
  UPGRADE_JOB_NOT_FOUND: {
    status: 404,
    message: '升级任务不存在',
  },

  PRIVILEGE_DURATION_INVALID: { status: 400, message: '临时授权的有效期应为 1-168 小时' },
  PRIVILEGE_GRANT_INVALID: { status: 400, message: '临时授权申请参数无效' },
  PRIVILEGE_CODE_INVALID: { status: 400, message: '权限码不存在或已停用' },
  PRIVILEGE_GRANT_NOT_FOUND: { status: 404, message: '临时授权记录不存在' },
  PRIVILEGE_GRANT_NOT_PENDING: { status: 409, message: '该授权申请已处理，不能重复审批' },
  PRIVILEGE_GRANT_NOT_ACTIVE: { status: 409, message: '该授权当前不在生效期' },
  PRIVILEGE_SELF_APPROVAL_FORBIDDEN: { status: 403, message: '申请人不得审批自己提交的授权申请' },
  PRIVILEGE_APPROVAL_FORBIDDEN: { status: 403, message: '审批人须自行持有拟授予的权限' },
};

/**
 * 校验注册表完整性（供单测使用）：每个码必须有 status 与 message(非空 string)。
 * status 判据为「400..599 的有限整数」而非仅 typeof number：
 * NaN 与 400.5 都能通过 typeof/区间比较（NaN 的任何比较均为 false），
 * 但两者在 res.status() 处行为不同——NaN 被 codeError 的 `||` 兜底成 400，
 * 400.5 则原样传给 Express 并抛 TypeError（Invalid status code），
 * 使该错误码的每个响应路径在运行期崩溃。注册表是静态数据，
 * 这类笔误必须在自检期暴露，不能等到线上响应时才发现。
 */
const validateRegistry = () => {
  const problems = [];
  for (const [code, def] of Object.entries(ERROR_CODES)) {
    const statusValid = Number.isInteger(def.status) && def.status >= 400 && def.status <= 599;
    if (!statusValid) {
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
