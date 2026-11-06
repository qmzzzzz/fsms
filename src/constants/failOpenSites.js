// 降级台账把站点与可告警信号绑定：只有日志不足以证明防线失效可被发现。
// FAIL_OPEN_SITES 登记护栏失效的降级，必须声明方向并有告警规则覆盖。
// OTHER_ALERT_SIGNALS 登记安全事件；按实际 effect/why 分类，不能把护栏降级归成普通事件。
// PASS_THROUGH 登记无法静态枚举 type 的动态转发点。
// src/tests/ci/failOpenLedgerGate.test.js 对 incSecurityAlert 调用与台账做双向对账。
// 盲区：从未发出 incSecurityAlert 的降级不会被采集，仍须人工审查 why 与 tightening。

/**
 * 降级即护栏失效的站点。
 *
 * `direction` 的取值必须逐条读过代码再写，不接受「大概吧」：
 *   fail-open  = 依赖不可用时**放行**，护栏该拦的没拦（保密性/防滥用降级）
 *   fail-closed= 依赖不可用时**拒绝**，可用性受损
 *   mixed      = 同一个站点在两个键上方向相反（必须写明哪边是哪边）
 */
const FAIL_OPEN_SITES = Object.freeze([
  {
    type: 'ip_blacklist_failopen',
    file: 'middleware/security/ipBlacklist.js',
    fn: 'checkIPBlacklist',
    level: 'high',
    direction: 'fail-open',
    trigger: '降级缓存未命中 且 数据库查询失败',
    effect: '该请求放行，IP 黑名单整层失效（已入库的封禁全部不生效）',
    why: '刻意不 fail-closed：黑名单查询走的是每个请求的热路径，库抖动时若改成拒绝，等价于「库挂 = 全站拒绝」——把一次依赖故障放大成全站不可用。故选择放行 + 显式信号（评价报告 #7），由人决定是否紧急封网。',
    tightening:
      '可收紧方向：改用 last-known-good 快照（stale-while-error），仍拦已知坏 IP 而不拦其他人。未做——需要先确认快照的内存占用与失效窗口口径。',
  },
  {
    type: 'ip_blacklist_failopen',
    file: 'services/websocketService/handshake.js',
    fn: '_assertHandshakeIpNotBanned（authenticateSocket 链路）',
    level: 'high',
    direction: 'fail-open',
    trigger: '握手期名单查询抛错',
    effect: '该地址放行，WS 侧名单失效（HTTP 侧可能仍拦着，两侧口径出现窗口差）',
    why: '与 HTTP 侧同口径（「宁可不拦，也不因一次 DB 抖动把全部实时推送踢下线」）。**复用同一个 type 而非新造**：同一根因、同一条时间序列，新造一个恒真信号只会稀释告警（见 handshake.js:519 的说明）。',
    tightening: '同 HTTP 侧；另需注意两侧是不同进程路径，快照方案要保证同一份来源。',
  },
  {
    type: 'ip_blacklist_failopen',
    file: 'services/websocketService/lifecycle.js',
    fn: '_sweepBannedIps（周期名单复查）',
    level: 'high',
    direction: 'fail-open',
    trigger: '周期复查时名单查询抛错',
    effect: '该地址放行到本次清扫结束，WS 侧名单失效（HTTP 侧可能仍拦着，两侧口径出现窗口差）',
    why: '与握手面共用 resolveHandshakeIPForSecurityDecision、同一份名单快照与同一条 fail-open 口径（「宁可不拦，也不因一次 DB 抖动把全部实时推送踢下线」）。**复用同一个 type 而非新造**：同一根因、同一条时间序列，新造一个恒真信号只会稀释告警。',
    tightening: '同 HTTP 侧；另需注意两侧是不同进程路径，快照方案要保证同一份来源。',
  },
  {
    type: 'ratelimit_store_degraded',
    file: 'middleware/rateLimitStore.js',
    fn: 'noteStoreDegraded',
    level: 'high',
    direction: 'fail-open',
    trigger: '共享限流存储（Redis）运行期异常，降级为进程内计数',
    effect: '多副本下限流配额被放大 N 倍，暴力破解防护同步失真',
    why: '降级而非拒绝：限流是保护层不是准入层，拒绝所有请求等于用限流把自己打挂。信号**每次**都发（计数器的价值在速率，不是"发生过"），日志只发一次并由 `noteStoreRecovered` 复位——本仓已吃过「一次性信号被当成持续信号」的亏（同文件 :66-79）。',
    tightening:
      '收紧方向应落在「配额换算」而不是「拒绝」：降级时按实例数折算阈值，而不是维持原阈值。未做——需要部署侧提供实例数。',
  },
  {
    type: 'audit_wal_permission_not_tightened',
    file: 'services/auditWalPermissions.js',
    fn: 'hardenTarget',
    level: 'high',
    direction: 'fail-open',
    trigger: '启动期对 WAL 目录/文件执行 0700/0600 收紧后回读校验未通过',
    effect:
      'WAL 继续可用（best-effort 语义），但同机其他账户可能读取或改写尚未落库的审计取证——护栏没生效，进程却按“已收紧”继续运行',
    why: '刻意不阻断启动：WAL 不可用会让审计写入整体退化，代价大于本机权限窗口；但“调用过 chmod/icacls”不能自证权限已生效，所以回读失败必须发独立安全告警，由运维在窗口内人工核查，而不是只留一条 error 日志（日志不是告警面）。',
    tightening:
      '可收紧方向：回读失败时把 WAL 切到“仅本进程可写”的临时目录并拒绝复用旧文件；未做——需要先确认切换过程中在途 outbox 的迁移口径。',
  },
  {
    type: 'captcha_active_bound_lost',
    file: 'services/captchaService.js',
    fn: 'generate',
    level: 'high',
    direction: 'fail-open',
    trigger: 'Redis 已就绪但计数命令报错 ⇒ incrWithTtl 返回 null',
    effect:
      '验证码活跃数上限判定整个被跳过（不是"退化为内存判断"——那是内存模式的语义）；洪水保护只剩 captchaLimiter（60 次/5 分钟/IP）与条目 TTL 两层',
    why: '刻意不 fail-closed：验证码是登录前置，Redis 抖动不该把合法用户挡在门外。信号此前**完全缺失**（本台账要修的正是这条）：catch 里的 warn 不可达，可达路径只有 sharedCache 的 debug 级日志，而生产默认 info ⇒ 不落盘。',
    tightening:
      '可收紧方向：把本地影子计数当**单侧上界**用（只在本地数已超限时才拒），与 F-211「配了共享层就绝不拿本地凑全局值」不冲突（该判据反对的是把本地数当全局值，两个方向都偏）。未做——需先确认偏晚触发是否仍能兜住刷取。',
  },
  {
    type: 'captcha_switch_db_fallback',
    file: 'models/SystemConfig.js',
    fn: 'captchaSwitch',
    level: 'medium',
    direction: 'mixed',
    trigger: '读取验证码开关时数据库不可用',
    effect:
      'login 键：静态默认 `LOGIN_CAPTCHA_ENABLED` 默认 false ⇒ **fail-open**（登录验证码被关掉）；register 键：开发/测试沿用静态默认，生产语义强制 true ⇒ **fail-closed**（注册仍需验证码）',
    why: '方向由开关种类与环境共同决定，不是一个统一方向——所以本条的 direction 是 mixed，不写成 fail-open 蒙混过去。登录侧降级后仍有 loginLimiter（凭据型限流）与暴力破解检测兜底，故定 medium 而非 high；注册侧已在生产语义下收紧为 fail-closed。',
    tightening:
      '真正该做的是**收敛降级动作本身**：此前同一个 try/catch 在 3 个调用点各复刻一份、全都没有信号，已收口到 `captchaSwitch(kind)`；register 生产侧已强制开启。是否要把 login 侧也改成 fail-closed 属产品决策（会把 Redis/Mongo 抖动传导为「没人能登录」）。',
  },
  {
    type: 'reauth_grant_store_degraded',
    file: 'services/reauthGrantStore.js',
    fn: 'recordReauthGrant / hasLiveReauthGrant',
    level: 'medium',
    direction: 'fail-closed',
    trigger: '记录或查询 5 分钟二次验证窗口时数据库读写失败',
    effect:
      '窗口既写不进也读不出，该会话只能继续走一次性票据：安全性不降级（票据更严），但全体用户会被反复要求 step-up',
    why: '刻意不 fail-open：认不出窗口就放行等于把"另一次验证"整个取消。但"降级只写日志等于没有可告警信号"（middleware/rateLimitStore.js:54）——一次库抖动会让全站 step-up 率飙升，运维必须能从计数看见，而不是靠翻日志。',
    tightening:
      '可收紧方向：读失败时改用短 TTL 的内存新鲜缓存（只对本进程此前确认过的 sid 放行），把可用性损失限制在"库抖动开始后新发生的 step-up"。未做——需要先确认多副本下的缓存一致口径。',
  },
  {
    type: 'idempotency_degraded',
    file: 'middleware/idempotency.js',
    fn: 'degradeOpen（建索引 / 登记 / 读取 / 回填 / 响应收尾五处）',
    level: 'high',
    direction: 'fail-open',
    trigger: '幂等判据的 keyHash 唯一索引建立失败，或键登记/读取/回填/提前应答收尾时数据库读写失败',
    effect:
      '本次去重整个不生效：同一个 Idempotency-Key 的请求会被**重复执行**（资金/写操作语义上是真实副作用），而客户端只看到一次正常响应',
    why: '刻意 fail-open：中间件在业务之前，把它做成 fail-closed 等于库抖一下就全站 5xx。但"降级只写日志等于没有可告警信号"（middleware/rateLimitStore.js:54）——重复执行是**静默的**，客户端无感、业务侧幂等也可能兜不住，必须能从计数看见。本条此前登记在 OTHER_ALERT_SIGNALS（定义为"安全事件上报，不是降级"），而它自己的 why 写着"是降级"——台账自相矛盾且无任何告警规则覆盖，本闸当时全绿。',
    tightening:
      '可收紧方向：登记失败时不直接放行，而要求下游写操作携带一次性的 requestHash（读-改-写时比对），把去重从"中间件尽力而为"移到"数据层强制"。未做——需要先确认所有写接口都有可比的 requestHash。',
  },
]);

/**
 * 其余 `incSecurityAlert` 站点：**安全事件上报**，不是降级。
 * 登记它们的目的不是给它们加护栏，而是让采集器双向闭合——
 * 否则每新增一个上报点都要重扫一遍才能确认它是不是降级。
 *
 * 注意 `audit_write_failed` 有**两个级别**（medium / high），
 * 这是既有事实而非笔误：两处的严重度语义不同，故按 `type@file` 分条登记。
 */
const OTHER_ALERT_SIGNALS = Object.freeze([
  // 以下四条为攻击检测面（2026-11-05）的安全事件上报信号，非降级
  {
    type: 'nosql_injection_attempt',
    file: 'services/injectionDetector.js',
    level: 'medium',
    why: 'NoSQL 操作符键被剥离（注入尝试留痕）',
  },
  {
    type: 'sql_injection_attempt',
    file: 'middleware/injectionSignature.js',
    level: 'medium',
    why: '请求路径/query 命中 SQLi 特征串（留痕不阻断）',
  },
  {
    type: 'scan_probe_detected',
    file: 'services/scanProbeDetector.js',
    level: 'medium',
    why: '扫描器路径指纹命中（留痕+取证标记）',
  },
  {
    type: 'scan_probe_storm',
    file: 'services/scanProbeDetector.js',
    level: 'high',
    why: '404 风暴达阈值（每窗口一条+取证标记）',
  },
  {
    type: 'audit_write_failed',
    file: 'models/auditLogWriteStatics.js',
    level: 'medium',
    why: '模型静态层审计写入失败',
  },
  {
    type: 'audit_write_failed',
    file: 'utils/auditWriteFailure.js',
    level: 'high',
    why: '与上条同 type、级别更高（该文件是收口后的写入失败归因路径）',
  },
  {
    type: 'security_detection_failed',
    file: 'utils/auditWriteFailure.js',
    level: 'medium',
    why: '检测逻辑自身失败（不是检测到威胁）',
  },
  {
    type: 'audit_hash_compute_failed',
    file: 'services/auditBufferDocs.js',
    level: 'high',
    why: '审计链哈希计算失败 ⇒ 链完整性受影响',
  },
  {
    type: 'audit_hash_compute_failed',
    file: 'models/auditLogHooks.js',
    level: 'high',
    why: '同上条同 type、逐条写入侧：单条文档盖章（pre-save 哈希链）失败时进同一告警面（与批量路径同档）。此前是采集盲区——调用点曾是跨行实参形态，按行匹配的采集器看不见它；全文匹配修复后现身，按 type@file 补登记（2026-11-03）。',
  },
  {
    type: 'legacy_cbc_decrypt_enabled',
    file: 'config/legacyCbcGuard.js',
    level: 'high',
    why: '启动期：仍启用 legacy CBC 解密（降级前的迁移未完成）',
  },
  {
    type: 'login_encrypt_strict_disabled',
    file: 'config/loginEncryptGuard.js',
    level: 'medium',
    why: '启动期：LOGIN_ENCRYPT_STRICT 未开，明文口令轨仍开放（密文轨灰度期的既有代价）。与 legacy_cbc_decrypt_enabled 的区别：不描述迁移未完成的遗留路径被重新暴露，而是描述一个可选加固项默认关闭，且**刻意不阻断启动**——纯 HTTP 内网部署无 WebCrypto，前端只能走明文降级轨，致命闸会拦死一种合法部署形态（判据见 config/loginEncryptGuard.js 文件头）。另注意与 password_history_pepper_rotation 同型的恒正项问题：每次进程启动都会 +1。',
  },
  {
    type: 'password_history_pepper_rotation',
    file: 'config/immutableConfigGuard.js',
    level: 'medium',
    why: '启动期：口令历史 pepper 轮换提醒。**已知问题**：该信号在每次进程启动都会 +1，是 `security_alerts_total` 里的恒正项，而跨类型求和规则 `sum(increase(security_alerts_total[10m])) >= 10` 会被它稀释（crash loop 还会冒充安全事件）。该口径问题尚未拍板，本台账只如实记录，不擅自改判据。',
  },
  {
    type: 'pii_rotation_old_key_lingering',
    file: 'config/immutableConfigGuard.js',
    level: 'medium',
    why: '启动期：旧 PII 加密密钥仍未下线',
  },
  {
    type: 'pii_v1_rows_unmigrated',
    file: 'config/immutableConfigGuard.js',
    level: 'medium',
    why: '启动期：PII v1 行尚未迁移完（type 由常量 PII_V1_ALERT 提供）',
  },
  {
    type: 'rate_limit_triggered',
    file: 'services/rateLimitEscalation.js',
    level: 'medium',
    why: '限流触发计数——是**正常防护动作**，不是降级',
  },
  {
    type: 'rate_limit_auth_abuse',
    file: 'services/rateLimitEscalation.js',
    level: 'high',
    why: '凭据型限流滥用（进入封禁阶梯）',
  },
  {
    type: 'ws_inbound_throttled',
    file: 'services/websocketService/inboundThrottle.js',
    level: 'medium',
    why: 'WebSocket 入站事件持续超速、连接已被断开——是**正常防护动作**（限流生效），不是降级或护栏失效，因此归信号段而不是 FAIL_OPEN_SITES。',
  },
  {
    type: 'trusted_proxy_cidrs_unset',
    file: 'app.js',
    level: 'medium',
    why: '启动期：已启用 trust proxy（TRUST_PROXY_HOPS>0）但未配置 TRUSTED_PROXY_CIDRS ⇒ X-Forwarded-For 的可信判据回落到「对端属私网/回环」（F-01 的兼容档，2026-10-17 仓库负责人明确拍板：不收紧默认行为，只告警）。**归在信号段而不是 FAIL_OPEN_SITES，理由是判据语义不同而不是严重度**：那一组描述「依赖不可用导致的运行期降级」，有恢复动作、有速率含义，共用 SecurityFailOpenSustained 的「持续 10 分钟未恢复」叙事；本条描述的是「这一次部署没给这个变量」——进程重启一次就 +1，没有任何恢复动作能让它消失（配了变量就再也不会发），套用那条规则的文案会给出**错误的处置指引**（依赖全都好好的，缺的是运维的一个变量）。告警由专条 TrustedProxyBoundaryUnset 承担（for: 0m，increase>0 即发），刻意不靠速率型的 SecurityAlertBurst——单次部署只写 1 条，那条规则永远不达标。另注意与 password_history_pepper_rotation 同型的恒正项问题：每次进程启动都会 +1，会稀释跨类型求和规则；该口径问题同属已登记的待拍板项，本台账只如实记录。',
  },
  {
    type: 'proxy_protocol_header_rejected',
    file: 'index.js',
    level: 'high',
    why: '运行期：PROXY protocol 已启用（PROXY_PROTOCOL=on）时，签名可识别的 PROXY v1/v2 头来自 TRUSTED_PROXY_CIDRS 名单之外的对端（untrusted-peer:*），或名单内对端发出了畸形头（malformed-header:*）——连接已被即时断开（fail-closed），未影响任何合法请求的语义。这是「伪造真实客户端 IP」的尝试信号：还原功能等价于重写 socket 地面真相，名单就是重写权的唯一凭据，有人试探这张凭据本身就该被看见。处置：单发多为端口扫描误中签名；高频出现则排查是否有人绕过 LB 直连后端端口（Compose 生产形态后端只绑回环，能直连本身就说明网络面有问题），并核对名单网段是否覆盖了真实 LB。逐条 warn 日志留有 peer 与原因，可与安全审计时间线互证。告警由专条 ProxyProtocolHeaderRejected 承担（for: 0m，increase>0 即发）：伪造尝试天然可以是低频单发，速率型规则会漏掉第一声。',
  },
  {
    type: 'forensic_capture_write_failed',
    file: 'services/forensicCaptureFlush.js',
    level: 'medium',
    why: '取证捕获落库/WAL 失败（P2，2026-10-31）：捕获本身是尽力而为的增强证据，失败时**刻意不阻塞业务响应**（记数 + 限频 warn，请求照常完成）——代价是被标记 IP 的取证证据出现缺口。归信号段而非 FAIL_OPEN_SITES：本条描述「证据留存降级」而不是「准入/护栏放行」，没有"未恢复即持续放行"的方向语义；告警由专条 ForensicCaptureDegraded（for: 10m，warning）承担，类型集合与该条表达式由 src/tests/ci/failOpenLedgerGate.test.js 的 ②b 双向对账（不并进 SecurityFailOpenSustained 的理由写在规则文件内）。调用点随 2026-10-31 的 max-lines 拆分迁到 services/forensicCaptureFlush.js（同一告警语义，未改口径）。',
  },
  {
    type: 'forensic_capture_trigger_unavailable',
    file: 'services/forensicCapture.js',
    level: 'medium',
    why: '取证触发判据不可用（forensicTrigger 模块缺失或抛错）：捕获整体跳过，请求不受影响。与上条同段同理由——这是"取证能力降级"而不是"护栏放行"，故不进 FAIL_OPEN_SITES；告警同由 ForensicCaptureDegraded 承担。',
  },
  {
    type: 'idempotency_lease_takeover',
    file: 'middleware/idempotency.js',
    level: 'medium',
    why: '同键的在途记录超过租约（5 分钟）仍没有结论 ⇒ 按「上一次受理已中断（进程被杀/部署重启/永久挂起）」原子接管并**按首次提交重新执行一次**：键不再钉满 24h（ADR-014 决策 7），代价是「上一次若其实已落库，这一次就是重复写入」而调用方对此无感。归信号段而不进 FAIL_OPEN_SITES：护栏没有失效，只是「没有已交付的结论可回放」这种形状超出了判据的定义域；但重复写入是静默的，必须能从计数看见（同 idempotency_degraded 的纪律）。',
  },
  {
    type: 'admin_initial_password_write_failed',
    file: 'services/initData/adminAccount.js',
    level: 'high',
    why: '启动期：默认管理员初始口令文件写入失败（B7 补登记，2026-11-03）。此前是「隐形 type」——调用点实参跨行，采集器按行匹配看不见它，台账与告警双侧都缺席。事件是 fail-closed 回滚：口令只存在于内存、进程退出即丢失，运维拿不到凭据且启动中止。归信号段而非 FAIL_OPEN_SITES：没有"未恢复即持续放行"的护栏失效语义，是启动期单次事件（一次部署最多 +1）；告警由专条 AdminInitialPasswordGuard 承担（for: 0m，increase>0 即发）——对 SecurityAlertBurst（≥10 条/10min）单次事件永不达标，速率型规则等于没有告警。',
  },
  {
    type: 'admin_initial_password_permission_not_tightened',
    file: 'services/initData/adminAccount.js',
    level: 'high',
    why: '启动期：初始口令文件权限收紧后回读复核未通过（B7 补登记，2026-11-03；同为跨行实参的隐形 type）。后果是明文管理员口令文件对同机其他账户可读，且已按回滚处理（删除文件并中止本次管理员创建；删除也失败时文件仍在盘上）。归信号段而非 FAIL_OPEN_SITES：同上——这是"这一次部署的既成事实"，不是依赖降级；告警同由 AdminInitialPasswordGuard 专条承担，处置动作（确认 ADMIN_INITIAL_PASSWORD 与文件权限、必要时手动删除残留文件）写在该规则的 annotations 里。',
  },
  {
    type: 'ban_ladder_degraded',
    file: 'services/securityAlertIpBans.js',
    level: 'medium',
    why: '自动封禁阶梯统计失败（B8，2026-11-03）：暴力破解链的 countPrior/countPriorOffenses 抛错时按第一档处理（宁少勿滥），但「阶梯事件源查不了」意味着反复触发的 IP 恒被封 1h 而告警面零信号——退化只写 error 日志，日志不是告警面（同 rateLimitStore.js:53 纪律）。归信号段而非 FAIL_OPEN_SITES：护栏（封禁动作）仍在执行且方向是更严不是放行，缺的是档位精度；单次退化只 +1，对速率型规则永不达标，由专条 BanLadderDegraded（for: 0m）承担。',
  },
  {
    type: 'ban_ladder_degraded',
    file: 'services/securityAlertPermissionAbuse.js',
    level: 'medium',
    why: '同上条同 type、不同链：权限滥用链的 countPermissionAbusePrior 抛错时按第一档处理。三链共用一个 type（同一条时间序列、同一条告警），按 type@file 分条登记（与 audit_write_failed 两级分条同形）。',
  },
  {
    type: 'ban_ladder_degraded',
    file: 'services/rateLimitEscalationBan.js',
    level: 'medium',
    why: '同上条同 type、第三条链：限流升级封禁的 30 天窗口计数抛错时按第一档处理。与 brute-force/permission-abuse 分账计数但共用档位与信号名。',
  },
]);

/**
 * 动态转发 type 的调用点：无法静态枚举 type，只能登记"它是转发点"。
 * 采集器对非字面量实参只做「是否登记在案」的检查，不做 type 枚举。
 *
 * 注：`utils/metrics.js` 的 `function incSecurityAlert(type, level)` 是**定义本体**，
 * 不是调用点——采集器显式排除该行（`failOpenLedgerGate.test.js` 的前提自证钉住了这一点）。
 * 第一版曾把它也登记进本表，门禁当场判红（"台账里登记了但代码里没有"），故已删除：
 * 定义本体不需要登记，需要的是**采集器不把它当调用点**。
 */
const PASS_THROUGH = Object.freeze([
  {
    file: 'services/securityAlertDelivery.js',
    arg: 'alertType',
    why: '告警投递门面：type 由调用方给出（`incSecurityAlert(alertType, level)`）',
  },
  {
    file: 'services/captchaService.js',
    arg: '`captcha_${scope}_cap_reached`',
    why: '模板串拼装：type 随 scope（login/register）取值，静态采集器只认单引号字面量；同文件的静态站点 captcha_active_bound_lost 已单独登记在 FAIL_OPEN_SITES。',
  },
  {
    file: 'services/initialPasswordFile.js',
    arg: 'type',
    why: '局部包装器：alert(type) 把 type 作为形参转发；采集器不做跨行/跨函数解析，唯一调用点传的是 admin_initial_password_file_delete_failed 字面量。',
  },
]);

/** 降级站点涉及的告警 type 集合（去重）——用于与 alert-rules.yml 对账 */
const FAIL_OPEN_ALERT_TYPES = Object.freeze(
  [...new Set(FAIL_OPEN_SITES.map((s) => s.type))].sort()
);

module.exports = {
  FAIL_OPEN_SITES,
  OTHER_ALERT_SIGNALS,
  PASS_THROUGH,
  FAIL_OPEN_ALERT_TYPES,
};
