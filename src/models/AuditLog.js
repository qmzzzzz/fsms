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
    },

    // 被操作对象（如管理员锁定某用户时记录目标用户）
    targetUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      index: true,
    },
    targetUsername: {
      type: String,
    },

    // P1-12：举报目标与敏感数据类型的显式声明。此前 schema 为 strict:true 且未声明
    // 这四个字段，securityController 写入的 targetType/targetId/dataType/description
    // 被静默丢弃——举报记录无法定位被举报对象、敏感查看记录无法回答「看了哪个字段」。
    // 类型与写入方对齐：
    //  - targetType: securityRoutes 校验为 user|device|alarm|system 之一，长度受限
    //  - targetId:   请求体字符串（用户可传设备/报警 ID），不设 ObjectId 约束
    //  - dataType:   securityRoutes 校验为 phone|email 之一
    //  - description: securityRoutes 限制 <=500 字符
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

    // 网络信息
    ip: {
      type: String,
    },
    userAgent: {
      type: String,
    },
    clientInfo: {
      browser: String,
      os: String,
      device: String,
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

    // 会话信息
    sessionId: {
      type: String,
      index: true,
      sparse: true,
    },

    // 会话指纹：UA + Accept-Language + Accept-Encoding + IP 网段的 SHA-256 摘要（前 32 位）
    // 用途：同一 sessionId 下指纹突变可判定为令牌被窃用；跨会话相同指纹可关联同源攻击者
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
      sparse: true, // 同 prevHash：与 sessionId/fingerprint 不同，那两处无 default，稀疏才真省空间
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
    // 被常态噪声淹没——正是 M-09「幻影链尾」同一条演化路径：反复确认是误报后，
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
// 因此只保留「筛选字段 + timestamp:-1」形态的复合索引——审计页所有查询都按时间倒序，
// 复合索引的最左前缀同时覆盖了单字段等值查询，无需再建单字段索引。
//
// 已移除的冗余索引（由下列复合索引前缀覆盖）：
//   {action:1} {category:1} {userId:1} {statusCode:1} {success:1} {ip:1} {riskLevel:1}
// 历史遗留的 {timestamp:1} 由 scripts/sync-audit-indexes.js 清理；
// schema 不再声明该冗余索引。
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ category: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ riskLevel: 1, timestamp: -1 });
auditLogSchema.index({ success: 1, timestamp: -1 });
auditLogSchema.index({ ip: 1, timestamp: -1 });

/**
 * username 前缀过滤的 collation 口径。
 *
 * 与 `User.USERNAME_COLLATION`（`username_ci` 唯一索引，P3-30）**同口径**：
 * locale `en` / strength 2 = 忽略大小写与重音。用户名在业务上是大小写不敏感的标识，
 * 审计页搜 `admin` 必须能搜到存量里的 `ADMIN`（本机实测存量确有 1 条 `ADMIN`）。
 * 两处常量由 `src/tests/models/auditUsernameIndex.test.js` 断言深度相等，防漂移。
 *
 * 为何索引必须带 collation：带 collation 的索引**只能**被带同一 collation 的查询命中，
 * 反之亦然。这是明确的代价（查询侧见 `utils/auditQuery.js` 与 `services/auditQueryService.js`），
 * 换来的是前缀过滤从 COLLSCAN 变成索引范围扫描——本机实测（2000 条）keysExamined 2000 → 1144；
 * 而在加这条索引之前（6939 条真实数据），子串 / 前缀 / 带 `i` / 不带 `i` 四种形态
 * **连等值查询都是 COLLSCAN**。
 *
 * 写放大取舍：本文件上方特别在意"审计是写密集集合、避免写放大"，本索引是**明知有写放大
 * 而新增**的一条——审计页的用户名过滤此前是纯 COLLSCAN，代价随留存期线性增长，
 * 而一条两字段索引的写放大是常数。两者不是同一量级，故此处接受。
 */
const AUDIT_USERNAME_COLLATION = Object.freeze({ locale: 'en', strength: 2 });
auditLogSchema.index(
  { username: 1, timestamp: -1 },
  { collation: AUDIT_USERNAME_COLLATION, background: true, name: 'username_ci_timestamp' }
);

// 分类 + 操作类型联合筛选（审计页常用组合）
auditLogSchema.index({ category: 1, action: 1, timestamp: -1 });
// 审计列表游标分页的排序是 `{ timestamp: -1, _id: -1 }`：续翻子句用
// `{timestamp:v,_id:{$lt:id}}` 做平局裁决，排序必须同带 `_id`，否则同一毫秒内的
// 记录整块跨页漂移（实测：5000 条 / 每页 20 ⇒ 漏 3950 条且提前"到底"）。
// 这条只能**新增**、不能像其它集合那样替换单字段索引：下面那条 `{timestamp:-1}`
// 承担 TTL，而 mongod 6.0.14 实测拒绝在复合索引上挂 expireAfterSeconds
// （`CannotCreateIndex: TTL indexes are single-field indexes`）⇒ 留存期与排序
// 只能各占一条索引。
auditLogSchema.index({ timestamp: -1, _id: -1 });

// 自动过期（可配，默认 180 天）—— 降序索引同时满足查询排序与 TTL 过期
// P3-46：留存期解析下沉到 constants/retention.js 单一声明。
// 此前本文件、logger.js、securityController.js、compliance-check.js 各自解析，
// 三种口径并存：模型钳制到 [90,3650]，其余两处用 `|| 180`——
// AUDIT_RETENTION_DAYS=1 时 TTL 是 90 天，而日志文件只留 1 天、合规仪表盘对外报 1 天
const { RETENTION_SECONDS } = require('../constants/retention');
auditLogSchema.index({ timestamp: -1 }, { expireAfterSeconds: RETENTION_SECONDS });

const RESPONSE_EXCLUDE = ['-body', '-params', '-query', '-hmac'].join(' ');
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

// P1-32：append-only 测试开关**仅测试环境导出**。原实现为无条件导出，
// 生产代码只要拿到 AuditLog 模型即可在运行期关闭防篡改护栏（全仓无调用点，
// 但这是「随时可开的门」）。注意：既有测试 AuditLogBehavior.test.js 的
// afterAll 清理路径依赖该符号存在，故不能无条件删除；改为按环境条件挂载，
// 生产环境 AuditLog._setAppendOnlyEnforced 为 undefined。
if (process.env.NODE_ENV === 'test') {
  AuditLogModel._setAppendOnlyEnforced = setAppendOnlyEnforced;
}

module.exports = AuditLogModel;
