/**
 * 审计日志模型
 * 记录系统所有敏感操作，用于安全审计和追溯
 */

const mongoose = require('mongoose');
const logger = require('../utils/logger');
const {
  AUDIT_CATEGORIES,
  AUDIT_HTTP_METHODS,
  AUDIT_RISK_LEVELS,
  auditMethodOrUndefined,
  auditIpOrUndefined,
  auditUserAgentOrUndefined,
  cleanAuditUsername,
} = require('../constants/audit');
const { applyWriteStatics } = require('./auditLogWriteStatics');
const { applyQueryStatics } = require('./auditLogQueryStatics');
const { applyHooks } = require('./auditLogHooks');

const auditLogSchema = new mongoose.Schema(
  {
    // 操作基本信息
    // 注：查询维度均为「筛选字段 + 时间倒序」组合，故单字段索引由文件末尾的
    // 复合索引前缀覆盖，此处不再设 index:true，避免写放大（审计是写密集集合）
    action: {
      type: String,
      required: true,
    },
    category: {
      type: String,
      // 必须与 middleware/security.js 的 ROUTE_CATEGORY_MAP 取值全集保持一致：
      // 缺少某个值时，该分类的审计记录会因 ValidationError 被 insertMany({ordered:false})
      // 静默丢弃（既不入库也不告警），造成审计盲区
      // 单一事实来源：constants/audit.js，schema 与控制器校验统一引用，消除漂移
      enum: AUDIT_CATEGORIES,
      required: true,
    },

    // 操作用户
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    username: {
      type: String,
      required: true,
      // 全仓唯一由未认证请求方直接决定的被哈希字段（登录失败审计传 `req.body.username`）。
      // 判据与两处偏离本族工厂的理由（required ⇒ 永不降级为 undefined）见 constants/audit.js。
      // 与 method/ip/userAgent 同规：必须在 auditChain.js 的 chainBatch 里镜像一次，
      // 否则批量路径「先哈希后铸造」会把一条没人碰过的记录变成永久 hash_mismatch。
      set: cleanAuditUsername,
    },

    // 被操作对象（如管理员锁定某用户时记录目标用户）
    // 索引保留登记（F3，2026-10-31 实测）：本字段与 sessionId/fingerprint 三条 index:true
    // 「当前无生产查询点」的口径：扫遍全仓 AuditLog.<静态方法>( 调用点、collection('auditlogs')
    // 直连点与动态构造（auditQuery.js / auditQueryService.js / auditExportService.js /
    // auditChainCheckpoint.js / securityAlert.js / account.js / behaviorBaseline.js），生产码无一按
    // 这三字段过滤；只有测试树按 targetUserId 过滤。写侧实测 +308KB（摊 +5B/条；逐条 216/132/4KB，
    // 20000 文档）。取舍：常数级写放大 vs 将来按此字段取证检索时在最大集合上重建索引（运维窗口 +
    // 写抖动）。触发条件：一旦出现按该字段的过滤查询，这条索引即被使用。
    targetUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      index: true,
    },
    targetUsername: {
      type: String,
    },

    // 举报目标与敏感数据类型：此前 strict:true 未声明这四字段，securityController 的写入被静默
    // 丢弃（举报无法定位对象、敏感查看无法回答「看了哪个字段」）。类型与写入方对齐：
    // targetType/dataType ∈ securityRoutes 枚举，targetId 校验后只可能是 ObjectId 或缺席；
    // 四个 maxlength 均为防御性上限（收窄后的写入口走不到，留给未来写入方）。
    targetType: {
      type: String,
      maxlength: [20, '举报目标类型最长 20 个字符'],
    },
    targetId: {
      type: String,
      maxlength: [100, '举报目标 ID 最长 100 个字符'],
    },
    dataType: {
      type: String,
      maxlength: [20, '敏感数据类型最长 20 个字符'],
    },
    description: {
      type: String,
      maxlength: [500, '举报描述最长 500 个字符'],
    },
    reason: {
      type: String,
    },

    // 请求信息
    method: {
      type: String,
      enum: AUDIT_HTTP_METHODS,
      // 未列入的动词（TRACE / CONNECT 或任意自定义方法——Node 的 HTTP 解析器都收得下，
      // 而 app 级中间件在路由匹配之前就跑，所以它们确实会进审计层）在此降级为「不记 method」，
      // 而不是让整条文档校验失败。判据是取舍：**宁可少一维，不可丢一行**——
      // 丢一行是不可逆的取证缺口（且 record() 只留一行 error 日志、缓冲路径直接丢弃），
      // 少一维仍可由 path/ip/action 定位到同一次请求。
      // 规则本体在 constants/audit.js（auditMethodOrUndefined）：批量写入路径要在
      // **算哈希之前**做同一份降级，否则被哈希的形态与落库的形态分叉 ⇒ 永久假篡改。
      set: auditMethodOrUndefined,
    },
    // 请求路径：仅 HTTP 请求类审计有意义（如 recordSensitiveAction）；
    // 事件型日志（登录、暴力破解告警、锁定/解锁等）无请求路径语义，不设必填，
    // 否则所有事件型审计写入都会校验失败，导致登录审计和暴力破解检测（依赖 login_failed 计数）失效
    path: {
      type: String,
    },
    params: {
      type: Object,
      default: {},
    },
    query: {
      type: Object,
      default: {},
    },
    body: {
      type: Object,
      default: {},
    },
    // 请求/响应头的脱敏副本（含响应正文）：审计详情页的溯源材料。
    // 刻意不设 default——缺省即"未采集"，与空对象可区分；哈希载荷对 undefined 归一为 null，
    // 与落库后缺失该键的形态一致（见 utils/auditChainPayload 的 normalizeValue）。
    // 体积上限与脱敏规则在 models/auditLogSanitizer（sanitizeAuditHeaders /
    // sanitizeAuditResponseBody），此处只声明类型；列表/导出投影见 RESPONSE_EXCLUDE。
    requestHeaders: {
      type: Object,
    },
    responseHeaders: {
      type: Object,
    },
    responseBody: {
      type: mongoose.Schema.Types.Mixed,
    },
    responseBodyTruncated: {
      type: Boolean,
    },
    // 未采集到正文的原因（stream/empty/binary/unserializable）；不设 enum——
    // 将来新增形态若被 enum 拒绝，整条审计会在 insertMany({ordered:false}) 里静默消失。
    responseBodySkipped: {
      type: String,
      maxlength: 32,
    },

    // 响应信息
    statusCode: {
      type: Number,
    },
    success: {
      type: Boolean,
    },
    errorMessage: {
      type: String,
    },
    // 4xx 拒绝原因码（H4）：errorMessage 只有 HTTP 措辞，同一 errorCode 下的细分原因事后不可分辨。
    // 值取 errors.reason || errors.errorCode，成功响应恒缺席；v5 起参与哈希。
    refusalReason: {
      type: String,
    },

    // 网络信息
    ip: {
      type: String,
      // 与 method 同一族的落库闸（判据本体见 constants/audit.js）：ip 直接来自
      // X-Forwarded-For 这类请求方可控文本，express 不校验其形态。上界 + 中和控制字符
      // 都必须在 chainBatch 算哈希**之前**镜像一遍，否则批量路径又是永久假篡改。
      set: auditIpOrUndefined,
    },
    userAgent: {
      type: String,
      // 同族闸（判据与"为什么是 512"见 constants/audit.js）：全仓 21 个写入点传的是裸
      // `req.get('user-agent')`，Node 头部上限 ~16KB ⇒ 上界必须落在 schema 单点，
      // 而不是要求每个新写入点都记得清洗。同样必须在 chainBatch 算哈希前镜像。
      set: auditUserAgentOrUndefined,
    },
    clientInfo: {
      browser: String,
      os: String,
      device: String,
      // 客户端地址的双留痕（口径见 utils/ipUtils.auditClientAddress）：
      // reportedIp 是 req.ip（trust proxy 下可能来自请求方自写的 XFF），
      // socketPeer 是 TCP 对端。两者不一致即说明本次请求带了转发头——
      // 只记安全裁决地址会丢掉这个事实，只记 req.ip 则会把伪造值当证据。
      // 与 ip 同族走 auditIpOrUndefined（上界 + 控制字符中和），且必须参与哈希：
      // 二者都挂在 clientInfo 下，payload 的 V2+ 整对象纳入哈希，无需升版本。
      reportedIp: {
        type: String,
        set: auditIpOrUndefined,
      },
      socketPeer: {
        type: String,
        set: auditIpOrUndefined,
      },
    },

    // 地理位置（可选）
    location: {
      country: String,
      province: String,
      city: String,
    },

    // 风险标记
    riskLevel: {
      type: String,
      // 与 category/method 同一口径：取值全集只有一份（constants/audit.js）。
      // 这里曾各写一份字面量，于是给 AUDIT_RISK_LEVELS 加一档时会出现
      // 「查询/导出侧白名单放行、落库却被 ValidationError 拒」——而缓冲路径的
      // insertMany({ordered:false}) 对毒文档既不报错也不告警，新档的记录凭空消失，
      // 正是本文件 category 注释里写明要消除的那种审计盲区。
      enum: AUDIT_RISK_LEVELS,
      default: 'low',
    },
    riskFactors: [
      {
        type: String,
      },
    ],

    // 会话信息（索引保留登记见上方 targetUserId 段：零生产查询点，保留取舍与写侧数字同处）
    sessionId: {
      type: String,
      index: true,
      sparse: true,
    },

    // 会话指纹：UA + Accept-Language + Accept-Encoding + IP 网段的 SHA-256 摘要（前 32 位）
    // 用途：同一 sessionId 下指纹突变可判定令牌被窃用；索引保留登记同 targetUserId 段（零查询点）。
    fingerprint: {
      type: String,
      index: true,
      sparse: true,
    },

    // 执行时间
    duration: {
      type: Number, // 毫秒
    },

    // ================= 哈希链字段（append-only 完整性保护） =================
    // prevHash：前一条审计记录的 hash（首条为 null）
    // sparse 在这里不省任何空间：稀疏索引排除的是「没有这个键」的文档，null 值照常入索引；
    // 而 default:null 使每条经 schema 写入的记录都带键。口径由
    // tests/models/auditSparseIndexSemantics.test.js 钉住（② 证明 null 进索引，③ 证明只有缺键才被排除）。
    // 选项保留而非删除：物理索引由 migrations/20260831000000-reconcile-audit-index-options.js
    // 以 {sparse:true} 建出，索引选项不能原地修改——schema 与实建不一致会在最大集合上
    // 反复 drop+重建或报 IndexOptionsConflict。
    prevHash: {
      type: String,
      default: null,
      index: true,
      sparse: true,
    },
    hash: {
      type: String,
      default: null,
      index: true,
      sparse: true, // 同 prevHash：稀疏不省空间——写入点恒写 null（auditLogWriteStatics.js:48/54/129-130），实测 4000 行 null 32768B vs 缺键 8192B
    },
    hmac: {
      type: String,
      default: null,
    },
    // 哈希链 payload 口径版本：v1 仅覆盖 9 个核心字段，v2 起全量业务字段纳入保护。
    // 校验端按此字段选择重算口径；null 视为 v1（存量数据）
    hashVersion: {
      type: Number,
      default: null,
    },
    // 哈希计算失败标记（2026-09-30）：auditBuffer 在 flush 时算 hash 抛错（如链锁超时、
    // canonicalPayload 遇到不可序列化字段）⇒ 该批文档以无 hash 落库，**不阻塞落库**。
    //
    // 为什么必须有这个字段：核验器对「无 hash 记录」只有一种解读——出现在带哈希记录
    // **之后**即判 `hash_stripped`（有人 $unset 抹哈希）。而"算 hash 失败仍落库"是
    // 完全良性的成因、且会**持续**产生（每一次链计算异常都留一批），于是真实篡改告警
    // 被常态噪声淹没——正是「幻影链尾」同一条演化路径：反复确认是误报后，
    // 人开始忽略它。这个字段让核验器能把两种成因分开，噪声降级为单独的
    // hash_compute_failed 计数（仍然可见、仍然告警），不进 breaks。
    //
    // 为什么必须是落库字段而不是内存标记：WAL 重放发生在新进程里（崩溃恢复），
    // 内存标记跨不过进程边界；而重放出来的正是这批无哈希文档。
    //
    // 安全边界：攻击者若能写这个字段，说明他已有 DB 写权限——那种情况下他直接
    // $unset hash 更省事，而本字段**不参与哈希**（不在 PAYLOAD_FIELDS_V4 里），
    // 所以它无法被用来"洗白"一条被改过内容的记录：内容篡改仍由 hash_mismatch 抓。
    // 它唯一的影响是把"无哈希"的归因从硬篡改降级为待查，这在审计上是更诚实的表述。
    hashFailure: {
      type: String,
      default: null,
    },

    // 时间戳（不再设 index:true，避免与 TTL 索引冲突）
    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

// ================= 索引设计 =================
// 原则：审计是写密集型集合，每个索引都会带来插入时的 B-tree 维护开销，
// 因此只保留「筛选字段 + timestamp:-1 + _id:-1」形态的复合索引——审计页所有查询都按
// {timestamp:-1,_id:-1} 倒序，最左前缀同时覆盖单字段等值查询，无需再建单字段索引。
//
// 尾部 _id:-1 不可省：二键形态只供 filter 段，时间与 _id 仍阻塞排序 ⇒ 优化器不用它
// （N=2000 实测 category：keys 2000→667、SORT 消失、写侧 +45~49B/条；见迁移
// 20261201000000 与 tests/models/auditListTiebreakExplain.test.js）；冗余单键索引与历史
// {timestamp:1}、旧二键筛选形态，均由 sync-audit-indexes.js / 迁移回收。
auditLogSchema.index({ userId: 1, timestamp: -1, _id: -1 });
auditLogSchema.index({ category: 1, timestamp: -1, _id: -1 });
auditLogSchema.index({ action: 1, timestamp: -1, _id: -1 });
auditLogSchema.index({ riskLevel: 1, timestamp: -1, _id: -1 });
auditLogSchema.index({ success: 1, timestamp: -1, _id: -1 });
auditLogSchema.index({ ip: 1, timestamp: -1, _id: -1 });

/**
 * username 前缀过滤的 collation 口径：与 `User.USERNAME_COLLATION`（`username_ci`）**同口径**——
 * locale `en` / strength 2 忽略大小写与重音，审计页搜 `admin` 必须搜得到存量 `ADMIN`（本机实测确有 1 条）；
 * 两处常量由 `src/tests/models/auditUsernameIndex.test.js` 断言深度相等。
 * 带 collation 的索引**只能**被带同一 collation 的查询命中（反之亦然，查询侧见 `utils/auditQuery.js`、
 * `services/auditQueryService.js`）：换来前缀过滤从 COLLSCAN 变索引范围扫描，本机实测（2000 条）
 * keysExamined 2000 → 1144，而加索引前（6939 条真实数据）子串/前缀/带 `i`/不带 `i` 四种形态**连等值都是 COLLSCAN**。
 * 写放大取舍：本文件上方在意"审计写密集、避免写放大"，本索引是**明知有写放大而新增**的一条——
 * 用户名过滤此前纯 COLLSCAN、代价随留存期线性增长，两字段索引的写放大是常数，不同量级故接受。
 */
const AUDIT_USERNAME_COLLATION = Object.freeze({ locale: 'en', strength: 2 });
auditLogSchema.index(
  { username: 1, timestamp: -1 },
  { collation: AUDIT_USERNAME_COLLATION, background: true, name: 'username_ci_timestamp' }
);

// 分类 + 操作类型联合筛选（审计页常用组合）
auditLogSchema.index({ category: 1, action: 1, timestamp: -1, _id: -1 });
// 审计列表游标分页的排序是 `{ timestamp: -1, _id: -1 }`：续翻子句用
// `{timestamp:v,_id:{$lt:id}}` 做平局裁决，排序必须同带 `_id`，否则同一毫秒内的
// 记录整块跨页漂移（实测：5000 条 / 每页 20 ⇒ 漏 3950 条且提前"到底"）。
// 这条只能**新增**、不能像其它集合那样替换单字段索引：下面那条 `{timestamp:-1}`
// 承担 TTL，而 mongod 6.0.14 实测拒绝在复合索引上挂 expireAfterSeconds
// （`CannotCreateIndex: TTL indexes are single-field indexes`）⇒ 留存期与排序
// 只能各占一条索引。
auditLogSchema.index({ timestamp: -1, _id: -1 });

// 自动过期（可配，默认 180 天）——降序索引同时满足查询排序与 TTL 过期
// 留存期解析下沉到 constants/retention.js 单一声明。
// 此前本文件、logger.js、securityController.js、compliance-check.js 各自解析，
// 三种口径并存：模型钳制到 [90,3650]，其余两处用 `|| 180`——
// AUDIT_RETENTION_DAYS=1 时 TTL 是 90 天，而日志文件只留 1 天、合规仪表盘对外报 1 天。
const { RETENTION_SECONDS } = require('../constants/retention');
auditLogSchema.index({ timestamp: -1 }, { expireAfterSeconds: RETENTION_SECONDS });

const RESPONSE_EXCLUDE = [
  '-body',
  '-params',
  '-query',
  '-hmac',
  // 详情字段（头袋/响应正文）只由 GET /audit-logs/:id 单条读取：
  // 列表一页 20 条各带 8KB 正文会让审计页响应膨胀、也让日常筛选付出无谓的传输成本。
  '-requestHeaders',
  '-responseHeaders',
  '-responseBody',
  '-responseBodyTruncated',
  '-responseBodySkipped',
].join(' ');
applyWriteStatics(auditLogSchema);
applyQueryStatics(auditLogSchema, RESPONSE_EXCLUDE);
auditLogSchema.statics.RESPONSE_EXCLUDE = RESPONSE_EXCLUDE;
// username 前缀过滤的 collation 口径对外暴露：查询侧必须用它 `.collation(...)` 才能
// 命中 `username_ci_timestamp`（与 User.USERNAME_COLLATION 同口径，见上方定义处注释）。
auditLogSchema.statics.AUDIT_USERNAME_COLLATION = AUDIT_USERNAME_COLLATION;
const { setAppendOnlyEnforced, isAppendOnlyEnforced } = applyHooks(auditLogSchema, logger);

// 导出模型
const AuditLogModel = mongoose.model('AuditLog', auditLogSchema);

// 护栏的**只读**状态：合规出口需要报告实际生效值（见 securityController 的 compliance 块）。
// 与下面的 _setAppendOnlyEnforced 不同，读侧不构成"可被关掉防护"的门，故无条件挂载。
AuditLogModel.isAppendOnlyEnforced = isAppendOnlyEnforced;

// append-only 测试开关**仅测试环境导出**。原实现为无条件导出，
// 生产代码只要拿到 AuditLog 模型即可在运行期关闭防篡改护栏（全仓无调用点，
// 但这是「随时可开的门」）。注意：既有测试 AuditLogBehavior.test.js 的
// afterAll 清理路径依赖该符号存在，故不能无条件删除；改为按环境条件挂载，
// 生产环境 AuditLog._setAppendOnlyEnforced 为 undefined。
if (process.env.NODE_ENV === 'test') {
  AuditLogModel._setAppendOnlyEnforced = setAppendOnlyEnforced;
}

module.exports = AuditLogModel;
