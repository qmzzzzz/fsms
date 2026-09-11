/**
 * 审计日志模型
 * 记录系统所有敏感操作，用于安全审计和追溯
 */

const mongoose = require('mongoose');
const logger = require('../utils/logger');
const { AUDIT_CATEGORIES } = require('../constants/audit');
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
    reason: {
      type: String,
    },

    // 请求信息
    method: {
      type: String,
      enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
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
      enum: ['low', 'medium', 'high', 'critical'],
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
    prevHash: {
      type: String,
      default: null,
      index: true, // 稀疏索引：仅索引非 null 的记录，旧数据（无 prevHash）不占索引空间
      sparse: true,
    },
    hash: {
      type: String,
      default: null,
      index: true,
      sparse: true, // 与 prevHash 同口径：存量 legacy 记录（hash=null）不挤占索引
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
// 分类 + 操作类型联合筛选（审计页常用组合）
auditLogSchema.index({ category: 1, action: 1, timestamp: -1 });

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
const { setAppendOnlyEnforced } = applyHooks(auditLogSchema, logger);

// 导出模型
const AuditLogModel = mongoose.model('AuditLog', auditLogSchema);

// 暴露测试辅助（生产代码不使用）
AuditLogModel._setAppendOnlyEnforced = setAppendOnlyEnforced;

module.exports = AuditLogModel;
