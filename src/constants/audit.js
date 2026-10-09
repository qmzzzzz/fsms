/**
 * 审计日志枚举常量 —— 单一事实来源
 *
 * 用途：消除 AuditLog schema enum 与审计查询校验白名单两处定义的漂移风险。
 * 新增/调整分类时只改本文件，schema 与控制器校验自动同步。
 *
 * 取值必须与 utils/auditMeta.js 的 ROUTE_CATEGORY_MAP 取值全集保持一致，
 * 否则未覆盖的分类会在 insertMany({ordered:false}) 时被 ValidationError 静默丢弃。
 */

// 控制字符/孤立代理项的清洗判据只有一份（utils/helpers.js 的 stripControlChars）：
// 审计的其它请求方可控文本（userAgent、body.reason、errorMessage）都走它，ip 不能例外。
// helpers 自身只依赖 constants/breachedPasswords 与（惰性）constants/timezone，无回环。
const { stripControlChars } = require('../utils/helpers');

const AUDIT_CATEGORIES = [
  'auth',
  'user',
  'role',
  'permission',
  'device',
  'alarm',
  'inspection',
  'security',
  'report',
  'system',
];

const AUDIT_RISK_LEVELS = ['low', 'medium', 'high', 'critical'];

// AUDIT_RISK_LEVELS 是**有序**清单（低→中→高→致命），所以"某档及以上"是这里的一个切片，
// 而不是一句需要人肉复述的话。所有此类判据必须由 riskLevelsAtLeast 派生（F-149）。
// 不这么办的失效模式不是"报错"，是静默漏：给 AUDIT_RISK_LEVELS 新增一档（例如 'urgent'
// 插在 high 与 critical 之间）后，手抄的 `['high','critical']` 会把新档留在"高危"之外，
// 而查询/导出侧的白名单引用的是同一份 AUDIT_RISK_LEVELS、已经放行 ⇒ 新档记录能落库、
// 能在审计页筛出来，却不进任何高危聚合（securityController）、告警取数（securityAlert）、
// 行为基线（behaviorBaseline）与导出等级派生（reportExportService/auditQuery）——
// 安全侧的漏，且没有任何一处会说"这一档没人管"。
// 档位找不到时直接抛：返回半截清单（slice(-1) 之类）等于把上面那个失效模式搬进派生器。
const riskLevelsAtLeast = (level) => {
  const idx = AUDIT_RISK_LEVELS.indexOf(level);
  if (idx < 0) {
    throw new Error(
      `riskLevelsAtLeast('${level}')：'${level}' 不在 AUDIT_RISK_LEVELS 内——` +
        '档位清单改过之后，所有"某档及以上"的判据都要跟着改，不能退回手抄字面量'
    );
  }
  // 冻结的理由同 originCheck.WRITE_METHODS：共享默认值被某个调用方 push 一下就会改掉全部门槛
  return Object.freeze(AUDIT_RISK_LEVELS.slice(idx));
};

// 「高危及以上」＝错误档的判定基础（审计页 level=error、导出里的"错误"标签同一口径）
const AUDIT_ERROR_RISK_LEVELS = riskLevelsAtLeast('high');

// 「警告及以上」。审计页 info 档用的是它的补集（`$nin`）而不是 `$in: ['low']`：
// 这是既有行为，补集形式对 riskLevel 缺失/为 null 的存量文档仍然成立，
// 换成 $in 会让这类文档从 info/warning/error 三个档里同时消失。
const AUDIT_WARNING_OR_HIGHER_RISK_LEVELS = riskLevelsAtLeast('medium');

// 审计记录 method 维的取值全集（单一事实来源：AuditLog schema 的 enum 与所有写入点共用）。
//
// 为什么必须有 HEAD：Express 把 HEAD 路由到 GET 处理器，而全局审计中间件与 authenticate
// 都排在路由之前，所以"带 token 的 HEAD"是常态流量（监控 curl -I、探测脚本、浏览器预取）。
// 原先 enum 只有 5 个动词，这类记录的 method 落在枚举外 ⇒ **整条文档**被 ValidationError 拒掉，
// 且两条落库路径都不说"是 method 越枚举"：
//   - 直写路径 AuditLog.record()：错误进 catch，只剩一行 error 日志 + audit_write_failed 指标，
//     ip_range_denied（riskLevel=high）这类事件在留存里凭空消失；
//   - 缓冲路径 auditBuffer 的 insertMany({ordered:false})：该文档被当成"毒文档"重试数轮后丢弃，
//     与本模块刻意丢弃畸形外部文档的语义混在一起，事后无法区分"客户端畸形"与"我们自己太窄"。
// OPTIONS 由 app.js 的 cors() 在 preflight 分支直接 204 结束（preflightContinue 默认 false），
// 走不到审计层；列进来是防御性收口，避免将来摘掉 cors 或改路由顺序时又回到同一处缺口。
const AUDIT_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

/**
 * method 的落库闸：枚举外的动词一律降级为「不记 method」。
 *
 * 抽成函数不是为了复用而复用——**批量写入路径必须在算哈希之前做同一份降级**。
 * 逐条路径（AuditLog.create）先铸造后算哈希，两侧天然同源；批量路径
 * （auditBuffer → chainBatch → insertMany）先对普通对象算哈希，铸造发生在之后，
 * 于是 schema 的 set 把 method 抹掉时「被哈希的形态」与「落库的形态」分叉，
 * 那条记录从此永远核验不过（永久假篡改），且它自身的完整性保护静默失效——
 * 已经是红的记录再被改也照样红，唯一的"补救"是整库重签（等于销毁取证价值）。
 * 触发它只需一条 `curl -X FOO`：app 级审计中间件在路由匹配之前就跑，收得下任意动词。
 */
const auditMethodOrUndefined = (value) => (AUDIT_HTTP_METHODS.includes(value) ? value : undefined);

/**
 * 审计文本维的落库闸工厂：清洗 + 截断，空文本降级为「不记这一维」。
 *
 * 为什么复用 `stripControlChars` 而不是在这里写一条正则：它同时做了两件本族字段必须做的事，
 * 而自己写一定会漏——控制字符**替换成空格**而非删除（删除会把两段文本粘成一个看似合法的
 * token，见 tests/services/auditSchemaCastRewriters.test.js 钉住的 `ip` 闸形状），以及
 * 截断**之后**把孤立代理项换成 U+FFFD（按 UTF-16 码元
 * slice 的奇数边界会劈开一个代理对，落盘时驱动改写成 U+FFFD，而哈希是内存里算的
 * ⇒ 又是「内存形态 ≠ 落库形态」的永久假篡改，见 tests/utils/auditChainSurrogateArtifact.test.js）。
 *
 * 为什么额外补一次 `trimEnd()`——**幂等**是这一族闸的硬约束，不是洁癖：
 * 批量路径是 `chainBatch` 跑一次（算哈希前）→ `insertMany` 铸造时 schema 的 `set` 再跑一次，
 * 两次结果不同就会让「被哈希的形态」≠「落库的形态」。实测形状：`stripControlChars` 的
 * 顺序是「替换 → trim → 截断」，截断点恰好落在一个被替换出来的空格上时，第二次调用的
 * trim 会再剪掉一个字符 ⇒ 64 的哈希对上 63 的存储。`trimEnd()` 把这一形状在第一次就消掉。
 *
 * 逐条路径（`AuditLog.create`）先铸造后算哈希，天然同源；批量路径先对普通对象算哈希，
 * 所以每个用本工厂产出的闸都必须**在 auditChain.js 里镜像一次**——这条约束由
 * tests/services/auditSchemaCastRewriters.test.js 的注册表钉住，新增闸必须同步登记。
 *
 * 非字符串一律 undefined：`ip`/`userAgent` 来自请求方，`{}`、`[]`、数字都会被 Mongoose
 * 强制转成字符串存进库里（`toString` 的结果既不是"没这个维度"也不是可查询的形态）。
 */
const makeAuditTextFieldGate = (maxLength) => (value) => {
  if (typeof value !== 'string') return undefined;
  const cleaned = stripControlChars(value, maxLength).trimEnd();
  return cleaned === '' ? undefined : cleaned;
};

// 审计 ip 维的上界。IPv6 完整文本最长 45 字符（IPv4 为 15），64 已含余量，
// 超出这个长度的"地址"必然来自请求方（X-Forwarded-For 是被 express 原样采纳的文本）。
const AUDIT_IP_MAX_LENGTH = 64;

/**
 * ip 的落库闸：由 `makeAuditTextFieldGate(AUDIT_IP_MAX_LENGTH)` 生成——清洗、截断、幂等、
 * 非字符串一律降级都住在工厂里，这里只提供上界；空文本降级为「不记 ip」。
 *
 * 与 `auditMethodOrUndefined` 同一个家族，也因此**同样必须在算哈希之前镜像**（见 auditChain.js）。
 * 这里不是"顺手整理字符串"：ip 直接来自 X-Forwarded-For 这类文本，express 不校验其形态，
 * 而在闸出现之前它既没有上界也没有走 `stripControlChars`（`path`/`action` 由 auditMeta
 * 截到 512/96，`method` 由 schema 的 set 降级）。
 *
 * 三条站得住的理由，按实测排序：
 *  1) 无界的请求方可控存储本身就是问题——单条文档能被一条 XFF 撑到数 KB，
 *     审计列表与导出按 ip 列渲染时会带着它一起走。
 *  2) 不可打印字符（LF/CR/NUL/C1/Bidi）会随审计文本进入日志与终端渲染：一条审计记录
 *     能伪造出"下一行"，这是把注入从请求面搬进取证面。
 *  3) 该字段已建索引（`{ip:1,timestamp:-1}`）。实测**非唯一**索引不因超键长拒写，
 *     所以今天不会丢审计；但它一旦改成 unique（或新增 unique 索引），MongoDB 的
 *     1024 字节键上限会立刻把超长记录变成**静默丢一行**——而 record() 吞错只计
 *     audit_write_failed。这正是 method 注释里「宁可少一维，不可丢一行」要防的形态，
 *     补在 schema 单点上，不等它变成事故。
 *
 * 清洗判据（为什么复用 `stripControlChars`、为什么再补一次 `trimEnd`）见上面的 `makeAuditTextFieldGate`：
 * 本族的闸（`ip`、`userAgent`）共用同一段实现，所以这些理由只记一处。
 */
const auditIpOrUndefined = makeAuditTextFieldGate(AUDIT_IP_MAX_LENGTH);

// userAgent 的上界：与"已经自觉清洗"的那五处写入点同值（auditLogWriteStatics 2 处、
// protocolCompliance 1 处、middleware/security 2 处都是 stripControlChars(x, 512)），
// 所以合法值一个都不会被改写。而其余 21 处传的是裸 `req.get('user-agent')`
// （securityController 8 处、mfaController 7 处、ipListController 4 处、authController
// 与 auditController 各 1 处）——Node 的头部上限 ~16KB ⇒ 一条审计文档能被一个 UA 撑到数 KB。
// 闸补在 schema 单点上的意义就在这里：不再要求每个新写入点都记得清洗，
// 本仓已经记录过一次"同一类写入两种口径"的漏洗（middleware/protocolCompliance.js:23-27）。
const AUDIT_USER_AGENT_MAX_LENGTH = 512;

const auditUserAgentOrUndefined = makeAuditTextFieldGate(AUDIT_USER_AGENT_MAX_LENGTH);

// username 维的上界。当前与 `loginValidation` 的 `isLength({max:128})`（authRoutes.js）相等，
// 但**不 import 它**：路由上界管「什么样的请求算合法」，本上界管「这一维存多长」，
// 两者哪天分叉不该互相牵动。注册用户名受 `^[a-zA-Z0-9_]{3,30}$` 约束、realName 类写入 ≤50
// ⇒ 合法值一个都不会被剪；能被剪到的只有请求方构造的垃圾用户名。
const AUDIT_USERNAME_MAX_LENGTH = 128;

/**
 * 审计 username 维的落库闸。**刻意不走 `makeAuditTextFieldGate`**，两处偏离都有实测依据：
 *
 *  1) 非字符串分两类处理，而不是一律降级 undefined。`username` 是 `required: true`，
 *     降级成 undefined 就是把「存得下的输入」变成「整行丢失」——实测 Mongoose 8 的
 *     String 铸造对 `12345`/`true` 转文本入库，对 `{}`/`[1,2]` 抛
 *     `Cast to string failed`（整行被 record() 吞掉，只剩一个 audit_write_failed 计数）。
 *     ip/userAgent 可以「宁可少一维」，username 是这一行的 who，少它就是丢行。
 *     因此 number/boolean 在这里**先收成文本**（实测 `cast(12345)==='12345'`、
 *     `cast(true)==='true'`），而不是原样透传：批量路径是 `chainBatch` 先按 plain object
 *     算哈希、`insertMany` 之后才铸造，透传一个数字就是"被哈希的是 12345、落库的是
 *     '12345'"，而 `canonicalPayload` 类型敏感（`auditChainPayload.js` 对 number 与
 *     string 产出不同 JSON）⇒ 与本闸要防的伪影同形，是一条永久 hash_mismatch。
 *     `null`/`undefined`/object 仍原样透传：前者由 `required` 拒（与今日同形），
 *     后者由铸造抛错拒（收成 `'[object Object]'` 等于把"整行被拒"换成"who 变成垃圾串"）。
 *     覆盖面按"请求体能构造什么"界定：JSON 只有 null/boolean/number/string/array/object，
 *     Date/BigInt 不是未认证请求方可达的形态，不做无据的猜测式兜底。
 *  2) 清洗后为空时**回退到截断原文**而不是 undefined。实测 `'   '`（纯空白）今天照样入库
 *     （`required` 只拒空串），闸若返回 undefined 就是新增一种丢行。回退不破坏本闸的
 *     存在理由：`cleaned === ''` 只在输入全部由空白/C0/C1/Bidi 字符组成时发生，
 *     而孤立代理项会被换成 U+FFFD（非空）——也就是说走到回退分支的串**必然不含代理项**，
 *     截断它不可能劈开一个代理对，因此不会重新引入下面要防的哈希伪影；
 *     残留的只是「一个本身就是垃圾的用户名里带着不可打印字符」，与丢整行相比是可接受的另一侧。
 *     幂等性同样成立：回退值再进本闸仍是同一串。
 *
 * 这一族的**动机本体**（为什么必须在 `chainBatch` 算哈希之前镜像一次）见 `makeAuditTextFieldGate`
 * 的注释，此处不复述。username 独有一条必须补的理由：**它是全仓唯一由未认证请求方直接
 * 决定的被哈希字段**（`authController.js:186` 把 `req.body.username` 原样交给登录失败审计；
 * 路由侧只做了 `.trim()`/`notEmpty`/`isLength(128)`，不碰控制字符与代理项）。实测：
 * 请求体 `{"username":"a\ud800b"}` 里 `JSON.parse` 自己就产出孤立代理项，铸造后内存形态是
 * `61 d800 62`、BSON 落盘形态是 `61 fffd 62`，而哈希在序列化之前算 ⇒ 该记录**读回来复算必然
 * hash_mismatch**，与真实篡改同形，且 `scripts/verify-audit-chain.js` 的退出码是部署门禁
 * （同族另两条触发面已实测记录在 tests/utils/auditChainSurrogateArtifact.test.js）。
 * 控制字符（NUL/CR/Bidi）实测逐字符原样往返、不产生哈希伪影，但会随审计列表与导出进入
 * 终端渲染——与 ip 的第 2 条理由同形。
 *
 * 负结果一并记下（已转成断言，不再只是散文）：2000 字符的 username 用原生 driver 直插
 * 能成功、collated 索引 `{username:1, timestamp:-1}` 不因超键长拒写 ⇒ 这一维在本闸之前
 * 没有「静默丢行」风险，上界的价值是单点防御与渲染口径，不是修一个正在发生的丢数据故障。
 * 见 tests/services/auditUsernameCastGate.test.js 的「超长原始行仍能读回」用例。
 *
 * 两条**实测到的副作用**（本闸的代价，不假装没有）：
 *  - 等值查询也吃 `set`：`countDocuments({username:'a\\u0000b'})` 实际下发的是
 *    `{username:'a b'}`（实测命中清洗后那条、命不中原生 driver 塞进去的裸 'a\\u0000b'）。
 *    于是**存量脏行**（本闸之前写入、username 里真带控制字符的记录）用原文等值查不到，
 *    `securityAlert.js` 那类按 `username` 等值计数的爆破统计在窗口内会少算这些行。
 *  - 区间操作数的两侧**各自**过闸：`{username:{$gte:'a\\u0000', $lt:'a\\u0001'}}` 经 Mongoose
 *    下发时两端都被洗成 `'a'` ⇒ 区间塌空、0 命中（同一条件用原生 driver 查则命中 1 条，实测
 *    见测试）。合法前缀不受影响（两端都不含空白/控制字符时逐字符不变）。
 *    合起来说：**存量脏行在 model 层两条路都查不到**（等值被改写、区间被改写后塌空），
 *    只有原生 driver 的原文查询看得见它——这不是越权面（少看得境不是多看得境），但运维
 *    若要用审计列表去核对闸前的历史痕迹，必须知道这一点。
 */
const cleanAuditUsername = (value) => {
  if (value === null || value === undefined || typeof value === 'object') return value;
  const text = typeof value === 'string' ? value : String(value);
  const cleaned = stripControlChars(text, AUDIT_USERNAME_MAX_LENGTH).trimEnd();
  return cleaned === '' ? text.slice(0, AUDIT_USERNAME_MAX_LENGTH) : cleaned;
};

// 审计页的「日志等级」三级展示口径（由 success + riskLevel 派生，不是库里存的字段）。
// 与 AUDIT_RISK_LEVELS 同理收成单一事实来源：查询侧（utils/auditQuery）、导出侧
// （reportExportService 的枚举校验与 includes 闸门）原先各写一份字面量，
// 单侧增删就会造成"查询放行、导出 400"的口径漂移（E-05 同一类）。
const AUDIT_DISPLAY_LEVELS = ['info', 'warning', 'error'];

// 审计日志 action 枚举白名单
// 分两部分：
//  1) 路由派生型——由 utils/auditMeta 的 deriveAction 从「完整路径」推导，
//     命名规律为 {category}_{子路径}，无子路径时按方法映射 create/update/delete；
//     新增写路由时必须同步补充此处，否则审计页无法按该 action 筛选（validateEnum 返回 400）
//  2) 事件型——由控制器/服务显式写入（登录成败、安全告警、配置变更等），无对应 HTTP 路由语义
// D-1：自 securityController 迁入，供审计查询/导出（auditController）与
// 报表导出（reportController）等多处复用同一份枚举
const AUDIT_LOG_ACTIONS = [
  // ===== 路由派生型 =====
  // 认证类
  'auth_register',
  'auth_login',
  'auth_refresh',
  'auth_password',
  'auth_profile',
  'auth_logout',
  // P3-11：认证类其余路由派生 action（GET 类多为敏感读取，POST 为状态变更）
  'auth_captcha',
  'auth_captcha-status',
  'auth_login-public-key',
  'auth_session',
  'auth_me',
  'auth_mfa_status',
  'auth_mfa_enroll',
  'auth_mfa_enable',
  'auth_mfa_disable',
  'auth_mfa_recovery-codes',
  // 用户/角色/权限类
  'user_create',
  'user_update',
  'user_delete',
  'user_roles',
  'user_batch',
  'role_create',
  'role_update',
  'role_delete',
  'role_permissions',
  'permission_create',
  'permission_update',
  'permission_delete',
  'permission_batch',
  // P3-11：角色列表兜底路由
  'role_all',
  // 业务类
  'device_create',
  'device_update',
  'device_status',
  'device_maintenance',
  'device_delete',
  'device_scrap',
  'alarm_report',
  'alarm_dispatch',
  'alarm_arrive',
  'alarm_resolve',
  'alarm_false-alarm',
  'alarm_cancel',
  'inspection_create',
  'inspection_update',
  'inspection_start',
  'inspection_complete',
  'inspection_review',
  'inspection_cancel',
  'inspection_delete',
  // 安全管理类
  'security_change-password',
  'security_view-sensitive',
  'security_report-suspicious',
  'security_users_lock',
  'security_ip-list',
  'security_config_allowPublicRegistration',
  'security_config_loginCaptchaEnabled',
  // 注册验证码开关（PUT/GET /api/security/config/registerCaptchaEnabled）：
  // 路由已存在但白名单遗漏，审计页按该 action 筛选会被 validateEnum 打 400
  // ——记录进了库却查不出来，属于「审计留痕形同虚设」
  'security_config_registerCaptchaEnabled',
  // WB-1：生产启动期密钥强度审计留痕（validate 已拦截弱密钥，此处记录「已通过」事实）
  'security_key_strength_audit',
  // P3-11：以下派生 action 此前缺失于白名单——审计页按它们筛选会被
  // validateEnum 打 400（记录在库里却筛不出来）。与各路由文件逐一核对：
  'security_view', // GET /api/security（无子路径兜底）
  'security_my-info', // GET /api/security/my-info
  'security_bindings', // GET /api/security/bindings
  'security_stats', // GET /api/security/stats
  'security_overview', // GET /api/security/overview（2026-09-30 GET 默认审计反转后已真实落库）
  'security_alerts', // GET /api/security/alerts
  'security_users_view', // GET 类用户子路径兜底
  'security_users_mfa_reset', // PUT /api/security/users/:userId/mfa/reset
  'security_audit-logs_verify', // GET /api/security/audit-logs/verify
  'security_ip-list_query', // GET /api/security/ip-list/query
  'user_stats', // GET /api/users/stats
  'user_view', // GET /api/users/:id（敏感读取审计）
  'role_view', // GET /api/roles/:id
  'role_permissions_tree', // GET /api/roles/permissions/tree
  'permission_view', // GET /api/permissions/:id
  'device_stats', // GET /api/devices/stats
  'device_expiring', // GET /api/devices/expiring
  'device_reminders', // GET /api/devices/reminders
  'device_view', // GET /api/devices/:id
  'alarm_stats', // GET /api/alarms/stats
  'alarm_view', // GET /api/alarms/:id
  'inspection_stats', // GET /api/inspections/stats
  'inspection_view', // GET /api/inspections/:id
  'report_dashboard', // GET /api/reports/dashboard
  'report_devices', // GET /api/reports/devices
  'report_alarms', // GET /api/reports/alarms
  'report_inspections', // GET /api/reports/inspections
  'report_export', // GET /api/reports/export（GET 默认审计，批量数据出口）
  'security_report', // POST /api/security/report
  'security_my-logs', // GET /api/security/my-logs
  'security_audit-logs', // GET /api/security/audit-logs（GET 默认审计）
  'security_audit-logs_export', // GET /api/security/audit-logs/export
  // 设备级会话管理（sid 为 UUID，已由 deriveAction 剔除动态段）
  'auth_sessions', // GET /api/auth/sessions、DELETE /api/auth/sessions/:sid
  'auth_sessions_others', // DELETE /api/auth/sessions/others

  // ===== 事件型 =====
  // 认证事件
  'login_success',
  'login_failed',
  'login_unusual_time',
  'logout',
  'password_changed',
  'change_password',
  // MFA 两步验证事件（登录 MFA 步骤/开关/恢复码/管理员重置全链路）
  'mfa_challenge',
  'mfa_verify_failed',
  'mfa_attempt_locked',
  'mfa_enroll',
  'mfa_enable',
  'mfa_disable',
  'login_recovery_code',
  'recovery_codes_regenerate',
  'admin_reset_mfa',
  // 设备级会话事件（用户从「登录会话」界面踢除设备）
  'session_revoked',
  'session_revoked_others',
  // 用户状态事件
  'user_locked',
  // P1-11：登录失败计数达阈值触发的 10 分钟临时锁定（authService 写入）。
  // 此前缺失于白名单：记录在库却无法按该 action 筛选（validateEnum 打 400）
  'account_temp_locked',
  'user_unlocked',
  // 安全告警事件
  'brute_force_login',
  // 限流持续触顶的升级封禁事件（rateLimitEscalation 写入，CC 防护闭环）
  'rate_limit_abuse',
  'bulk_data_export',
  'permission_abuse',
  'privilege_escalation',
  'suspicious_ip_activity',
  'suspicious_report',
  'view_sensitive_data',
  'ip_range_denied',
  'audit_log_query',
  'audit_chain_verify',
  // P3-35：早于 auditLog 中间件的 403 拒绝（黑名单命中 / CSRF 来源校验失败）
  // 与协议合规拒绝。此前这三类拒绝只进 logger，审计页无从筛选
  'ip_blacklist_blocked',
  'csrf_origin_denied',
  'malformed_request_blocked',
  // queryLimit 的两类拒绝（参数超长 / 收到对象数组形态的取值）。
  // 与上面三类同族：都发生在 auditLog 之前，此前只进 logger。
  // 不复用 malformed_request_blocked：那一条由协议合规层发出（Content-Type/头部/方法畸形），
  // 这一条是 NoSQL 操作符与资源耗尽探测的指纹，混在一起就分不出"谁在探查询参数"。
  'query_param_rejected',
  // 响应头已发出、流被中途截断时补写的更正事件（errorHandler 的 markResponseAbortedByError）。
  // 不登记就是 P1-11 复发：记录确实落库了，但 validateEnum 对不在白名单的 action 直接 400
  // ⇒ 查询与导出都筛不出它，"这次导出被截断了"这条唯一的线索变成查不到的死角。
  'response_aborted_after_headers',
  // 系统配置事件
  'registration_enabled',
  'registration_disabled',
  'login_captcha_enabled',
  'login_captcha_disabled',
  'register_captcha_enabled',
  'register_captcha_disabled',
  'ip_blacklist_added',
  'ip_blacklist_removed',
  'ip_whitelist_added',
  'ip_whitelist_removed',

  // ===== 历史兼容 =====
  // 修复前（req.path 被剥离导致派生失效）产生的记录，保留以便查询存量数据
  'system_create',
  'system_update',
  'system_delete',
  'batch_delete_users',
  'role_assign_permissions',
  'permission_batch_create',
  'device_status_update',
  'device_maintenance_add',
  'alarm_false_alarm',
];

module.exports = {
  AUDIT_CATEGORIES,
  AUDIT_RISK_LEVELS,
  riskLevelsAtLeast,
  AUDIT_ERROR_RISK_LEVELS,
  AUDIT_WARNING_OR_HIGHER_RISK_LEVELS,
  AUDIT_HTTP_METHODS,
  auditMethodOrUndefined,
  AUDIT_IP_MAX_LENGTH,
  auditIpOrUndefined,
  AUDIT_USER_AGENT_MAX_LENGTH,
  auditUserAgentOrUndefined,
  AUDIT_USERNAME_MAX_LENGTH,
  cleanAuditUsername,
  AUDIT_DISPLAY_LEVELS,
  AUDIT_LOG_ACTIONS,
};
