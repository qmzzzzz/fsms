const mongoose = require('mongoose');
const { validateEnum, parseDateBoundary, isValidDateParam } = require('./helpers');
const { normalizeIP, ipQueryCondition } = require('./ipUtils');
const {
  AUDIT_CATEGORIES,
  AUDIT_LOG_ACTIONS,
  AUDIT_RISK_LEVELS,
  AUDIT_DISPLAY_LEVELS,
  AUDIT_ERROR_RISK_LEVELS,
  AUDIT_WARNING_OR_HIGHER_RISK_LEVELS,
} = require('../constants/audit');

const AUDIT_LOG_CATEGORIES = AUDIT_CATEGORIES;
// 原为本地字面量 `['low','medium','high','critical']`——与 constants/audit.js
// 的 AUDIT_RISK_LEVELS 同值但各写一份。导出侧（reportExportService）引用的正是常量版，
// 两份清单一旦单侧增删就会造成「查询 400、导出放行」的口径漂移（E-05 同一类故障）。
const AUDIT_LOG_RISK_LEVELS = AUDIT_RISK_LEVELS;
// 三级展示口径（info/warning/error）同样收成 constants/audit.js 的单一事实来源。
// 原先本文件与导出侧各写一份、只靠注释约定同口径，而 `zzqoder_auditFilterParity`
// 当时钉的是**它自己那三份字面量**（此文件的清单、导出侧的清单、测试里再抄一遍），
// 于是"某侧偷偷多一档"并不会让门禁转红——现在由该测试逐项比对两侧行为。
const AUDIT_LOG_LEVELS = AUDIT_DISPLAY_LEVELS;

/**
 * success 过滤项的严格解析。
 *
 * 原实现 `success === 'true' || success === true` 之后直接落值，于是
 * '1'、'0'、'yes'、'TRUE'、' true'、数组、以及 extended query parser 造出的
 * `{$ne:'x'}` 对象一律静默变成 false —— "筛选条件写错了"退化成"只看失败记录"。
 * 这不是脏数据而是**误导性的空/窄结果集**：审计人员以为按某条件筛过、
 * 实际看到的是另一个集合，且状态码 200 无任何提示。
 * 本仓对同一形状已有判例：前端 AuditLogView 特意排除空串，注释写的就是
 * "否则空串会被后端解析为 false，导致清空筛选=只看失败的错误结果"；
 * L-04 的裁定也是"写坏的规则不许静默放行"。空串只是这个洞的一个入口，
 * 其余值走的是同一条静默路径 ⇒ 统一收口为抛错（调用方 catch 已给 400）。
 */
const parseSuccessFilter = (success) => {
  if (success === 'true' || success === true) return true;
  if (success === 'false' || success === false) return false;
  throw new Error('参数 success 必须是 true 或 false');
};

/**
 * 三级展示口径（level）→ Mongo 条件。
 * 仅在 level 已通过枚举校验后被调用；未知值仍由调用方的 includes 兜底。
 *
 * 两个"某档及以上"的集合来自 constants/audit.js 的派生器（F-149）：原先这里写着
 * `['high','critical']` 与 `['medium','high','critical']` 两份字面量，给
 * AUDIT_RISK_LEVELS 加一档时新档会落在"高危"之外——而查询白名单（同一份 AUDIT_RISK_LEVELS）
 * 已经放行，于是那一档的记录能落库、能被筛出来，却不进任何高危判据，静默漏。
 * info 档用补集（$nin）而不是 `$in: ['low']`：这是既有行为，别当成冗余写法改掉。
 * warning 档仍写标量 'medium'（唯一一处没写成集合的档位），
 * 由 zzqoder_riskLevelSingleSource 的"三档必须完整划分等级空间"断言看着它。
 */
const buildLevelCondition = (level) => {
  if (level === 'error') {
    return { $or: [{ success: false }, { riskLevel: { $in: AUDIT_ERROR_RISK_LEVELS } }] };
  }
  if (level === 'warning') return { success: true, riskLevel: 'medium' };
  return { success: true, riskLevel: { $nin: AUDIT_WARNING_OR_HIGHER_RISK_LEVELS } };
};

/**
 * 入参校验（顺序即原实现的顺序：日期 → 枚举 → userId → ip）。
 * 保持顺序是因为"同时写坏两个参数"时对外抛哪一条消息已经是既有行为，
 * 重排会让同一请求的错误提示换一条，测试与前端文案都会跟着漂。
 */
const assertFiltersValid = ({
  startDate,
  endDate,
  action,
  category,
  riskLevel,
  level,
  userId,
  ip,
}) => {
  // 判据单源 helpers.isValidDateParam：裸 isNaN(new Date(x)) 对 '123' / '2026' 一律放行，
  // 经 parseDateBoundary 静默翻译成"公元 0122 年"的窗口 ⇒ 200 + 一个看不见却看似正常的结果集
  if (!isValidDateParam(startDate)) {
    throw new Error('开始日期格式错误');
  }
  if (!isValidDateParam(endDate)) {
    throw new Error('结束日期格式错误');
  }

  validateEnum(action, AUDIT_LOG_ACTIONS, 'action');
  validateEnum(category, AUDIT_LOG_CATEGORIES, 'category');
  validateEnum(riskLevel, AUDIT_LOG_RISK_LEVELS, 'riskLevel');
  validateEnum(level, AUDIT_LOG_LEVELS, 'level');

  if (userId && !mongoose.Types.ObjectId.isValid(userId)) {
    throw new Error('参数 userId 必须是合法的用户 ID');
  }
  if (ip && !normalizeIP(ip)) {
    throw new Error('参数 ip 必须是合法的 IPv4/IPv6 地址');
  }
};

/**
 * 时间边界（评价报告 #12）：date-only 统一走 parseDateBoundary（业务时区口径）。
 * 原实现 `new Date('YYYY-MM-DDT00:00:00')` 无时区后缀按服务器本地时区解析，
 * UTC 容器下比东八区业务口径早 8 小时，跨日漏数。
 */
const applyTimestampFilter = (query, startDate, endDate) => {
  if (!startDate && !endDate) return;
  query.timestamp = {};
  if (startDate) query.timestamp.$gte = parseDateBoundary(startDate, 'start');
  if (endDate) query.timestamp.$lte = parseDateBoundary(endDate, 'end');
};

/**
 * IP 条件：变体集合从**地址**推导（规范形态 + 原始写法 + IPv4 的 `::ffff:` 映射形态），
 * 见 ipUtils.ipQueryVariants。单值时不加 `$in` 包装，让查询形状与索引保持一致。
 * 原实现只取 [归一化值, 原始 trim 值]，于是"搜规范写法"覆盖不到以映射形态
 * 入库的行（实测同一地址 3553 行漏 63%），且与导出侧各写一份造成口径漂移。
 */
/**
 * IP 条件：变体推导与条件形状统一由 `ipUtils.ipQueryCondition` 决定
 * （查询侧与导出侧共用同一把尺子，各自抄一份就是口径漂移源）。
 * 这里不再重复做合法性判定：`assertFiltersValid` 已保证 ip 非空时归一化必然成功，
 * 再判一次会让读者误以为"存在绕过校验、能拿到 null 的路径"。
 */
const applyIpFilter = (query, rawIp) => {
  if (!rawIp) return;
  query.ip = ipQueryCondition(rawIp);
};

/**
 * 前缀匹配的上界：把末字符码点 +1（'adm' → 'adn'，'zz' → 'zz{'）。
 * 返回 null 表示无上界（输入全为最大码点，此时退化为单边 `$gte`）。
 */
const nextUsernamePrefixUpperBound = (prefix) => {
  const chars = [...prefix];
  for (let i = chars.length - 1; i >= 0; i--) {
    const cp = chars[i].codePointAt(0);
    if (cp < 0x10ffff) {
      chars[i] = String.fromCodePoint(cp + 1);
      return chars.slice(0, i + 1).join('');
    }
  }
  return null;
};

/**
 * username 前缀条件：用范围比较，不用 `$regex`。
 *
 * 原实现是 `{ $regex: escapeRegExp(username), $options: 'i' }`，有两个问题：
 *  1. **不锚定** ⇒ 子串匹配（`adm` 会命中 `damin`，语义上是误报）；
 *  2. **大小写不敏感的正则无法使用索引**——MongoDB 的 `$regex` 实现不感知 collation，
 *     也无法利用大小写不敏感索引。本机实测（2000 条 + `{username:1,timestamp:-1}` 索引）：
 *     「子串 + i」与「前缀锚定 + i」的 keysExamined 完全相同（均 2000 = 扫全部索引键），
 *     即"只把正则改成前缀"若不摘掉 `i`，**收益为零**。
 *
 * 改用范围比较：它是 collation-aware 的，配合带 collation 的索引可做真正的索引范围扫描
 * （同一实测：keysExamined 2000 → 1144），且大小写不敏感语义得以保留——
 * `admin` / `Admin` / `ADMIN` / `administrator` 全部命中，`damin` 不再被误命中。
 * 索引与 collation 常量见 `models/AuditLog.js`。
 */
const usernamePrefixCondition = (prefix) => {
  const upper = nextUsernamePrefixUpperBound(prefix);
  return upper === null ? { $gte: prefix } : { $gte: prefix, $lt: upper };
};

/**
 * 按需给 Query / Aggregate 挂 collation。
 *
 * 为什么必须"按需"而不是统一挂：带 collation 的查询**只能用带同一 collation 的索引**，
 * 于是会把 `{timestamp:-1,_id:-1}` / `{riskLevel:1,timestamp:-1}` 这些不带 collation 的
 * 时间序索引一并屏蔽掉——那等于"给 username 提速"的同时"给其它查询降速"。
 *
 * 反过来，含 username 前缀条件的查询**必须**挂：前缀范围 `[$gte, $lt)` 在默认
 * （二进制）collation 下 `ADMIN` 不落在 `[adm, adn)` 内 ⇒ 会漏掉大小写不同的记录。
 * 即 collation 在此同时是性能开关与正确性开关——这也是导出路径必须与列表路径
 * 用同一口径的原因（否则"列表能搜到、导出搜不到"）。
 */
const withCollation = (query, collation) => (collation ? query.collation(collation) : query);

/** 组装 Mongo 条件（校验已在前一步完成，此处只做形状映射） */
const assembleQuery = ({
  startDate,
  endDate,
  userId,
  username,
  action,
  category,
  ip,
  riskLevel,
  success,
  level,
}) => {
  const query = {};
  applyTimestampFilter(query, startDate, endDate);
  // userId 必须 cast 成 ObjectId 再进条件：同一个 query 对象既喂给 find/countDocuments
  // （Mongoose 按 schema 自动 cast）又喂给 `aggregate([{$match: query}])`（**不做 schema cast**）。
  // 留字符串的后果不是报错而是数字自相矛盾：列表有行、total>0，而 riskLevel 分组统计恒空——
  // 且只有带 ?userId= 的查询会这样（数据范围里 rbac 给的本来就是 ObjectId），
  // 管理员视角一切正常，所以线上极难被发现。判据与 utils/scopeCast.js 同源。
  if (userId) {
    query.userId =
      typeof userId === 'string' && mongoose.Types.ObjectId.isValid(userId)
        ? new mongoose.Types.ObjectId(userId)
        : userId;
  }
  // 前缀匹配（范围比较，非 `$regex`）：语义与索引口径见 usernamePrefixCondition 的注释。
  // 下游必须带 collation 才能命中 `username_ci_timestamp` 索引，故此处同时回报标记。
  if (username) query.username = usernamePrefixCondition(username);
  if (action) query.action = action;
  if (category) query.category = category;
  applyIpFilter(query, ip);
  if (riskLevel) query.riskLevel = riskLevel;
  if (success !== undefined && success !== '') query.success = parseSuccessFilter(success);

  if (level && AUDIT_LOG_LEVELS.includes(level)) {
    query.$and = [...(query.$and || []), buildLevelCondition(level)];
  }
  return query;
};

const buildAuditQuery = (req) => {
  // 显式列出接受的字段：只有这 10 个键会流进下游的校验与组装，
  // 其它 query 参数（page/limit/…）不参与审计条件构造。
  const { startDate, endDate, userId, username, action, category, ip, riskLevel, success, level } =
    req.query;
  const f = {
    startDate,
    endDate,
    userId,
    username,
    action,
    category,
    ip,
    riskLevel,
    success,
    level,
  };

  assertFiltersValid(f);

  return {
    query: assembleQuery(f),
    startDate: f.startDate,
    endDate: f.endDate,
    // 该 query 是否含 username 前缀条件。为 true 时下游必须对 find/countDocuments/aggregate
    // 显式 `.collation(...)`——带 collation 的索引**只能**被带同一 collation 的查询命中；
    // 为 false 时**不得**带 collation，否则会连带屏蔽那些不带 collation 的时间序索引
    // （如 `{timestamp:-1,_id:-1}`），把"给 username 提速"变成"给其它查询降速"。
    usernamePrefix: Boolean(f.username),
  };
};

module.exports = {
  buildAuditQuery,
  parseSuccessFilter,
  buildLevelCondition,
  // 供 auditQueryService / auditExportService 共用（同一份"按需挂 collation"语义，
  // 避免两处各写一份后漂移成"列表挂、导出不挂"）
  withCollation,
  // 仅供测试直调：前缀边界的多字节码点 / 全最大码点退化路径无法经 HTTP 观察
  usernamePrefixCondition,
  nextUsernamePrefixUpperBound,
};
