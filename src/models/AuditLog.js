/**
 * 审计日志模型
 * 记录系统所有敏感操作，用于安全审计和追溯
 */

const mongoose = require('mongoose');
// T-1：顶层引入而非在异步回调里惰性 require——审计写入是 fire-and-forget，
// 其失败回调可能在测试环境销毁后才执行，届时 require() 会抛
// 「import a file after the Jest environment has been torn down」
const logger = require('../utils/logger');
const {
  canonicalPayload,
  computeHash,
  computeHmac,
  CURRENT_PAYLOAD_VERSION,
  rollbackChainTail,
  withChainLock,
  getChainTail,
  advanceChainTail,
} = require('../utils/auditChain');
const { AUDIT_CATEGORIES } = require('../constants/audit');
const { BUSINESS_TIMEZONE, OFF_HOURS_START, OFF_HOURS_END } = require('../constants/timezone');
// T-1：同样顶层化——钩子/静态方法可能在测试环境销毁后执行，惰性 require 会抛错
const { auditPath } = require('../utils/auditMeta');
const { computeFingerprint } = require('../utils/fingerprint');

// 敏感字段脱敏：递归处理嵌套对象与数组，防止嵌套层级中的密码/令牌明文入库
// （与 middleware/security.js 的 auditLog 中间件保持同一口径；此前仅遍历第一层，
//  profile.token / profile.nested.password 之类会明文落库）
const SENSITIVE_KEYS = [
  'password',
  'currentpassword',
  'newpassword',
  'mfacode',
  'token',
  'refreshtoken',
  'secret',
  'apikey',
];
const MAX_SANITIZE_DEPTH = 6;

const sanitizeBody = (body, depth = 0) => {
  // 深度保护，避免循环引用/超深嵌套导致栈溢出
  if (depth > MAX_SANITIZE_DEPTH) return '[深度超限]';
  if (body === null || typeof body !== 'object') return body;
  if (Array.isArray(body)) return body.map((v) => sanitizeBody(v, depth + 1));

  const cleaned = {};
  for (const [k, v] of Object.entries(body)) {
    cleaned[k] = SENSITIVE_KEYS.some((s) => k.toLowerCase().includes(s))
      ? '***'
      : sanitizeBody(v, depth + 1);
  }
  return cleaned;
};

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
// 历史遗留的 {timestamp:1} 与 TTL 的 {timestamp:-1} 重复，需用 scripts/sync-audit-indexes.js 清理。
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

// 静态方法：记录登录日志
// fingerprint/sessionId 为可选参数：登录成功后才有 sessionId（jti 随 token 签发），
// 登录失败时仅有指纹，用于关联同一客户端的连续失败尝试
auditLogSchema.statics.recordLogin = async function (
  userId,
  username,
  ip,
  success,
  userAgent,
  extra = {}
) {
  return await this.create({
    action: success ? 'login_success' : 'login_failed',
    category: 'auth',
    userId,
    username,
    ip,
    userAgent,
    sessionId: extra.sessionId || null,
    fingerprint: extra.fingerprint || null,
    success,
    riskLevel: success ? 'low' : 'medium',
  });
};

// 静态方法：通用业务审计记录（控制器写操作统一入口）
// 内建错误处理：审计失败不影响业务响应，仅记录 warn 日志，调用方无需逐处 catch
auditLogSchema.statics.record = function (entry) {
  return this.create(entry).catch((err) => {
    logger.warn('业务审计落库失败', { action: entry.action || 'unknown', error: err.message });
    return null;
  });
};

// 静态方法：记录敏感操作（自动脱敏 body）
auditLogSchema.statics.recordSensitiveAction = async function (
  userId,
  username,
  action,
  category,
  req,
  res,
  duration
) {
  const riskFactors = [];

  // 风险评估
  if (action.includes('delete')) riskFactors.push('delete_operation');
  if (action.includes('batch')) riskFactors.push('batch_operation');
  if (res.statusCode >= 400) riskFactors.push('error_response');

  // 多级代理链检测：X-Forwarded-For 含多个地址说明请求经过多层转发，
  // 此时 req.ip 的可信度取决于 trust proxy 配置，值得标记。
  // 注意不能写成 `req.ip !== req.get('x-forwarded-for')`——无代理时右侧为 undefined，
  // 表达式恒为 true，会把所有普通操作都标成风险，令风险等级完全失真。
  const forwardedFor = req.get('x-forwarded-for');
  if (forwardedFor && forwardedFor.split(',').length > 1) {
    riskFactors.push('multi_hop_proxy');
  }

  let riskLevel = 'low';
  if (riskFactors.length >= 2) riskLevel = 'high';
  else if (riskFactors.length === 1) riskLevel = 'medium';

  return await this.create({
    action,
    category,
    userId,
    username,
    method: req.method,
    // 用 originalUrl 派生的完整路径：req.path 在多级挂载下已被剥离前缀
    path: auditPath(req),
    params: req.params,
    query: req.query,
    body: sanitizeBody(req.body),
    statusCode: res.statusCode,
    success: res.statusCode < 400,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    sessionId: req.user?.sessionId || null,
    fingerprint: computeFingerprint(req),
    duration,
    riskLevel,
    riskFactors,
  });
};

// 静态方法：获取用户操作历史
auditLogSchema.statics.getUserActivity = async function (userId, options = {}) {
  const { days = 7, limit = 100, category } = options;

  // 上限保护：防止客户端传入超大 limit 拖库（低危-个人日志 limit 上限）
  const safeLimit = Math.max(1, Math.min(limit, 500));
  // days 同样限幅，防止超大窗口扫描
  const safeDays = Math.max(1, Math.min(days, 365));

  const query = {
    userId,
    timestamp: {
      $gte: new Date(Date.now() - safeDays * 24 * 60 * 60 * 1000),
    },
  };

  if (category) {
    query.category = category;
  }

  return await this.find(query)
    .sort({ timestamp: -1 })
    .limit(safeLimit)
    // 必须复用 RESPONSE_EXCLUDE（含 -hmac）：本方法是 /api/security/my-logs 的底层，
    // 任意登录用户可调。若只排除 -body -params -query，响应会同时给出 (hash, hmac)
    // 明文—标签对，一次拉 500 条即可离线穷举 HMAC_SECRET → 伪造 hmac 篡改审计，
    // append-only 防篡改层整体失效。定义与理由见文件末尾 AUDITLOG_RESPONSE_EXCLUDE。
    .select(AUDITLOG_RESPONSE_EXCLUDE);
};

// 静态方法：异常行为检测
auditLogSchema.statics.detectAnomalies = async function (options = {}) {
  const { windowMinutes = 5, threshold = 10 } = options;

  const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);

  // 检测短时间内大量的失败操作（按用户维度）
  const failedOps = await this.aggregate([
    {
      $match: {
        timestamp: { $gte: windowStart },
        success: false,
      },
    },
    {
      $group: {
        _id: '$userId',
        count: { $sum: 1 },
      },
    },
    {
      $match: {
        count: { $gte: threshold },
      },
    },
  ]);

  // 按来源 IP 维度补充聚合：匿名失败（userId=null）若只按用户归并，
  // 不同 IP 的陌生人失败会混入同一条记录，而单 IP 分布式爆破前反而不可见
  const failedOpsByIp = await this.aggregate([
    {
      $match: {
        timestamp: { $gte: windowStart },
        success: false,
      },
    },
    {
      $group: {
        _id: '$ip',
        count: { $sum: 1 },
      },
    },
    {
      $match: {
        count: { $gte: threshold },
      },
    },
  ]);

  // 检测非常规时间操作（使用 UTC+8 时区，适配中国业务场景）
  const unusualTimeOps = await this.aggregate([
    {
      $match: {
        timestamp: { $gte: windowStart },
      },
    },
    {
      $addFields: {
        // $hour 默认使用 UTC，通过 timezone 指定业务时区转换
        // P3-18：时区取 constants/timezone 单一声明（原为 TZ_OFFSET||'+08:00'，
        // 与 securityAlert/behaviorBaseline 的 'Asia/Shanghai' 是两套配置源）
        hour: {
          $hour: {
            date: '$timestamp',
            timezone: BUSINESS_TIMEZONE,
          },
        },
      },
    },
    {
      $match: {
        $or: [
          // P3-7 口径统一：阈值取 constants/timezone 的 OFF_HOURS_*
          // （此前此处为 >= 23，而 securityAlert/behaviorBaseline 为 >= 22，
          // 同一"非常规时间"在三个模块给出两种答案，报表数字互相矛盾）
          { hour: { $lt: OFF_HOURS_END } },
          { hour: { $gte: OFF_HOURS_START } },
        ],
      },
    },
    {
      $group: {
        _id: '$userId',
        count: { $sum: 1 },
      },
    },
    {
      $match: {
        count: { $gte: 5 },
      },
    },
  ]);

  return {
    failedOperations: failedOps,
    failedOperationsByIp: failedOpsByIp,
    unusualTimeOperations: unusualTimeOps,
  };
};

// ================= 对外响应字段排除投影 =================
/**
 * 审计日志对外响应的字段排除投影
 *
 * body/params/query：可能含业务敏感入参，列表页无需回显。
 *
 * hmac：**必须排除**。它是 HMAC-SHA256(HMAC_SECRET, hash) 的输出，
 * 而 hash 本身也在响应里。攻击者同时拿到 (hash, hmac) 明文—标签对后，
 * 即可离线穷举 HMAC_SECRET，无需任何在线请求、不触发限流与审计。
 * 一旦密钥被爆破，攻击者可篡改审计记录并重算合法 hmac，防篡改层彻底失效。
 * hmac 的唯一用途是服务端校验（scripts/verify-audit-chain.js 直读数据库），
 * 客户端从无消费场景。
 *
 * 保留 prevHash/hash/hashVersion：前端「链完整性」展示与导出 manifest 依赖它们，
 * 且单独暴露哈希不构成密钥泄露通道（SHA-256 无密钥参与）。
 */
const AUDITLOG_RESPONSE_EXCLUDE = ['-body', '-params', '-query', '-hmac'].join(' ');

auditLogSchema.statics.RESPONSE_EXCLUDE = AUDITLOG_RESPONSE_EXCLUDE;

// ================= 哈希链与 append-only 钩子 =================

// append-only 执行开关（仅供测试清理使用，生产代码永不调用）
// 通过 AuditLog._setAppendOnlyEnforced(false) 临时关闭后即可 deleteMany 清理测试数据
let _appendOnlyEnforced = true;
function _setAppendOnlyEnforced(value) {
  _appendOnlyEnforced = !!value;
}

/**
 * pre('save') 钩子：在写入前自动计算哈希链
 *
 * 所有通过 create() 落库的审计记录（含 record / recordLogin / recordSensitiveAction
 * 以及控制器中的直接 AuditLog.create 调用）均由此钩子自动维护哈希链。
 * auditBuffer 批量路径不走 create()（使用 insertMany），在 flush() 中手动调 chainBatch 预算。
 *
 * 哈希计算失败时仅告警、不中断保存（记录以无 hash 落库，verify 时计为 legacy 跳过），
 * 保证审计日志不因哈希计算异常而丢失。
 */
auditLogSchema.pre('save', async function () {
  // append-only 封堵 save() 旁路：拦截列表（updateOne/deleteOne/…）不含 document 级
  // save()——加载已有记录→改字段→doc.save() 会带着旧 hash 入库，篡改静默生效。
  // 已有 hash 的非新文档一律拒绝；测试清理走 _setAppendOnlyEnforced(false) 总开关。
  if (!this.isNew && this.hash && _appendOnlyEnforced) {
    throw new Error('审计日志为 append-only，禁止通过 save() 修改已入库记录');
  }

  if (this.hash) {
    if (!this.hmac) {
      try {
        this.hmac = computeHmac(this.hash);
      } catch {
        /* best-effort */
      }
    }
    if (!this.hashVersion) {
      this.hashVersion = CURRENT_PAYLOAD_VERSION;
    }
    return;
  }

  try {
    // M-3：锁内「读链尾→计算→推进链尾」，与 auditBuffer.flush 串行互斥，
    // 消除并发追加时两条记录引用同一 prevHash 的链分叉
    await withChainLock(async () => {
      const prevHash = await getChainTail(this.constructor);
      const payload = canonicalPayload(this.toObject(), CURRENT_PAYLOAD_VERSION);
      this.prevHash = prevHash;
      this.hash = computeHash(prevHash, payload);
      this.hmac = computeHmac(this.hash);
      this.hashVersion = CURRENT_PAYLOAD_VERSION;
      await advanceChainTail(this.hash);
      // 记录回滚锚点：save 失败时在 post('save') 错误钩子中撤销链尾推进，
      // 避免链尾指向一条从未落库的「幻影 hash」（见 auditChain.rollbackChainTail）
      this.$__chainAdvancedFrom = prevHash;
    });
  } catch (err) {
    logger.warn('审计日志哈希链计算失败', { action: this.action, error: err.message });
  }
});

/**
 * post('save') 错误钩子：save 落库失败时回滚 pre-save 中已推进的内存链尾。
 * 仅当链尾仍停在本次写入的 hash 上才回滚；若后续记录已接续（并发场景），
 * 回滚被拒绝并告警——此时 DB 中已存在指向幻影尾的记录，需人工核查断链。
 */
auditLogSchema.post('save', function (err, doc, next) {
  if (err && doc && doc.$__chainAdvancedFrom !== undefined && doc.hash) {
    // rollbackChainTail 现为 async（Redis 模式走 casSet 原子回滚）：
    // 用 Promise 链处理结果，且无论成败都必须调用 next(err)，避免 post 钩子挂起。
    Promise.resolve()
      .then(() => rollbackChainTail(doc.hash, doc.$__chainAdvancedFrom))
      .then((restored) => {
        if (!restored) {
          logger.error(
            `审计日志落库失败且链尾已被后续记录接续（action=${doc.action}），哈希链可能出现幻影分叉，请核查`
          );
        }
        delete doc.$__chainAdvancedFrom;
        next(err);
      })
      .catch(() => {
        delete doc.$__chainAdvancedFrom;
        next(err);
      });
    return;
  }
  next(err);
});

/**
 * append-only 钩子：禁止任何修改/删除操作
 *
 * 审计日志一经写入不可变更，所有 updateOne / deleteOne / deleteMany /
 * replaceOne / findOneAndUpdate / findOneAndDelete 均被拒绝。
 * 注意：pre('validate') 和 pre('save') 不受影响——正常写入路径不受拦截。
 *
 * 测试清理可通过 { bypassAppendOnly: true } 查询选项或 _setAppendOnlyEnforced(false) 绕过。
 */
const APPEND_ONLY_HOOKS = [
  'updateOne',
  'deleteOne',
  'deleteMany',
  'replaceOne',
  'findOneAndUpdate',
  'findOneAndDelete',
];
auditLogSchema.pre(APPEND_ONLY_HOOKS, function (next) {
  // 测试清理绕过：查询选项中携带 bypassAppendOnly=true 时放行
  if (!_appendOnlyEnforced) return next();
  const opts = (this.getOptions && this.getOptions()) || {};
  if (opts.bypassAppendOnly) return next();
  next(new Error('审计日志为 append-only，禁止修改/删除'));
});

// 导出模型
const AuditLogModel = mongoose.model('AuditLog', auditLogSchema);

// 暴露测试辅助（生产代码不使用）
AuditLogModel._setAppendOnlyEnforced = _setAppendOnlyEnforced;

module.exports = AuditLogModel;
