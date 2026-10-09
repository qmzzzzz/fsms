/**
 * fail-open / 降级站点台账（2026-10-09 建立）
 *
 * ## 这份台账要解决什么
 * 本仓有一条成文纪律，在三个地方被重复声明：
 *   · `middleware/security.js:668-672`：「fail-open 放行（缓存未命中）**必须有显式可观测信号**——
 *     否则『DB 挂了 + 全站裸奔』只有一条 error 日志可循」
 *   · `middleware/rateLimitStore.js:53-56`：「降级态只写日志等于没有可告警信号——
 *     `grep 日志` 不是运维动作」
 *   · `services/websocketService.js:723-725`：「fail-open 必须留 `ip_blacklist_failopen` 计数」
 *
 * 但纪律只在**注释里**，没有任何东西把「站点集合」与「每个站点的信号」钉在一起。
 * 后果实测（2026-10-09）：`services/captchaService.js` 的活跃数上限判定被跳过时，
 * 唯一痕迹是 `sharedCache.js:432` 的 `logger.debug`，而生产默认 `LOG_LEVEL=info`
 * （`utils/logger.js:85`）⇒ **debug 不落盘**：没有日志、没有指标、没有告警。
 * 这正是「已修的同类漏了一处」——三处注释在讲同一条纪律，第四处漏了。
 *
 * ## 台账的结构（三段，各有各的判据）
 *  1. `FAIL_OPEN_SITES` —— 降级即护栏失效的站点，**必须**有信号，且信号必须被告警规则覆盖；
 *  2. `OTHER_ALERT_SIGNALS` —— 其余 `incSecurityAlert` 站点（安全事件上报，不是降级）；
 *  3. `PASS_THROUGH` —— 动态转发 type 的两处（投递门面与指标定义本体），无法静态枚举。
 *
 * 完整性由 `src/tests/ci/failOpenLedgerGate.test.js` 双向钉住：
 * 新增一个 `incSecurityAlert` 站点而没进本台账 ⇒ 红；台账里登记了但代码里没有 ⇒ 红。
 * 这条判据的价值在于**逼作者回答一个问题**：「这是降级，还是安全事件上报？」
 * ——降级就必须有信号、有方向声明、有告警覆盖。
 *
 * ## 如实声明：本台账**抓不到**什么
 * 采集器的锚点是 `incSecurityAlert` 的调用点，所以**一个既不发信号、也没被任何人注意到的
 * 新 fail-open 站点不会被本闸抓到**——它压根不出现在采集结果里。
 * 本闸能做到的是：让「已有的信号」无法悄悄消失，并让「新增的信号」必须被归类。
 * 真正的兜底仍是人（见每条的 `why` 与 `tightening`）。把这个盲区写在这里，
 * 是为了避免后人把本闸当成「fail-open 全都被管住了」的证据。
 */

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
    file: 'middleware/security.js',
    fn: 'checkIPBlacklist',
    level: 'high',
    direction: 'fail-open',
    trigger: '降级缓存未命中 且 数据库查询失败',
    effect: '该请求放行，IP 黑名单整层失效（已入库的封禁全部不生效）',
    why:
      '刻意不 fail-closed：黑名单查询走的是每个请求的热路径，库抖动时若改成拒绝，' +
      '等价于「库挂 = 全站拒绝」——把一次依赖故障放大成全站不可用。' +
      '故选择放行 + 显式信号（评价报告 #7），由人决定是否紧急封网。',
    tightening:
      '可收紧方向：改用 last-known-good 快照（stale-while-error），仍拦已知坏 IP 而不拦其他人。' +
      '未做——需要先确认快照的内存占用与失效窗口口径。',
  },
  {
    type: 'ip_blacklist_failopen',
    file: 'services/websocketService.js',
    fn: 'authenticateSocket / 周期名单复查',
    level: 'high',
    direction: 'fail-open',
    trigger: '握手期或周期复查时名单查询抛错',
    effect: '该地址放行，WS 侧名单失效（HTTP 侧可能仍拦着，两侧口径出现窗口差）',
    why:
      '与 HTTP 侧同口径（「宁可不拦，也不因一次 DB 抖动把全部实时推送踢下线」）。' +
      '**复用同一个 type 而非新造**：同一根因、同一条时间序列，' +
      '新造一个恒真信号只会稀释告警（见该文件 :723-725 的说明）。',
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
    why:
      '降级而非拒绝：限流是保护层不是准入层，拒绝所有请求等于用限流把自己打挂。' +
      '信号**每次**都发（计数器的价值在速率，不是"发生过"），' +
      '日志只发一次并由 `noteStoreRecovered` 复位——本仓已吃过' +
      '「一次性信号被当成持续信号」的亏（同文件 :66-79）。',
    tightening:
      '收紧方向应落在「配额换算」而不是「拒绝」：降级时按实例数折算阈值，' +
      '而不是维持原阈值。未做——需要部署侧提供实例数。',
  },
  {
    type: 'captcha_active_bound_lost',
    file: 'services/captchaService.js',
    fn: 'generate',
    level: 'high',
    direction: 'fail-open',
    trigger: 'Redis 已就绪但计数命令报错 ⇒ incrWithTtl 返回 null',
    effect:
      '验证码活跃数上限判定整个被跳过（不是"退化为内存判断"——那是内存模式的语义）；' +
      '洪水保护只剩 captchaLimiter（60 次/5 分钟/IP）与条目 TTL 两层',
    why:
      '刻意不 fail-closed：验证码是登录前置，Redis 抖动不该把合法用户挡在门外。' +
      '信号此前**完全缺失**（本台账要修的正是这条）：catch 里的 warn 不可达，' +
      '可达路径只有 sharedCache 的 debug 级日志，而生产默认 info ⇒ 不落盘。',
    tightening:
      '可收紧方向：把本地影子计数当**单侧上界**用（只在本地数已超限时才拒），' +
      '与 F-211「配了共享层就绝不拿本地凑全局值」不冲突（该判据反对的是把本地数当全局值，' +
      '两个方向都偏）。未做——需先确认偏晚触发是否仍能兜住刷取。',
  },
  {
    type: 'captcha_switch_db_fallback',
    file: 'models/SystemConfig.js',
    fn: 'captchaSwitch',
    level: 'medium',
    direction: 'mixed',
    trigger: '读取验证码开关时数据库不可用',
    effect:
      'login 键：静态默认 `LOGIN_CAPTCHA_ENABLED` 默认 false ⇒ **fail-open**（登录验证码被关掉）；' +
      'register 键：静态默认 `REGISTER_CAPTCHA_ENABLED` 默认 true ⇒ **fail-closed**（注册仍需验证码）',
    why:
      '方向由各键的静态默认决定，不是一个统一方向——所以本条的 direction 是 mixed，' +
      '不写成 fail-open 蒙混过去。登录侧降级后仍有 loginLimiter（凭据型限流）与' +
      '暴力破解检测兜底，故定 medium 而非 high。',
    tightening:
      '真正该做的是**收敛降级动作本身**：此前同一个 try/catch 在 3 个调用点各复刻一份、' +
      '全都没有信号，已收口到 `captchaSwitch(kind)`。是否要把 login 侧改成 fail-closed ' +
      '属产品决策（会把 Redis/Mongo 抖动传导为「没人能登录」）。',
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
    type: 'legacy_cbc_decrypt_enabled',
    file: 'config/legacyCbcGuard.js',
    level: 'high',
    why: '启动期：仍启用 legacy CBC 解密（降级前的迁移未完成）',
  },
  {
    type: 'password_history_pepper_rotation',
    file: 'config/immutableConfigGuard.js',
    level: 'medium',
    why:
      '启动期：口令历史 pepper 轮换提醒。**已知问题**：该信号在每次进程启动都会 +1，' +
      '是 `security_alerts_total` 里的恒正项，而跨类型求和规则 ' +
      '`sum(increase(security_alerts_total[10m])) >= 10` 会被它稀释（crash loop 还会冒充' +
      '安全事件）。该口径问题已登记为待拍板（deliverables/审计复核第3轮…-2026-10-01.md §六），' +
      '本台账只如实记录，不擅自改判据。',
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
