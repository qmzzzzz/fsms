/**
 * 攻击告警查询服务 ——「安全分析 · 攻击告警查询」读面的查询构建、取页与派生富化。
 *
 * 数据语义：攻击事件 = AuditLog 上命中 constants/attackEvents.js 注册表的 action 行
 * （本仓攻击信号没有独立集合；该注册表是本读面「什么算攻击事件」的单一事实来源）。
 * 分层约束：models 只许在 services 层 require（layeringRatchet 零容忍），控制器只编排。
 *
 * 与 auditQueryService 的关系：同源不同面——审计页查全部 action，本面把视野钉在
 * 注册表全集上。筛选/分页/collation/IP 富化的口径全部复用 utils/auditQuery、
 * utils/cursorPagination 与 withIpLocation 的既有实现，不另造第二份（防口径漂移）：
 * 时间参数沿用审计页的 startDate/endDate（date-only 走业务时区展开），IP 走
 * ipQueryCondition，username 走前缀+collation，severity 切片由 riskLevelsAtLeast 派生。
 */

const AuditLog = require('../models/AuditLog');
const IPBlacklist = require('../models/IPBlacklist');
const logger = require('../utils/logger');
const { listCountOptions, listAggregateOptions } = require('../utils/queryBudget');
const {
  validateEnum,
  parseDateBoundary,
  isValidDateParam,
  escapeRegExp,
} = require('../utils/helpers');
const { ipQueryCondition, normalizeIP } = require('../utils/ipUtils');
const { usernamePrefixCondition, withCollation } = require('../utils/auditQuery');
const { withIpLocation } = require('./auditQueryService');
const { riskLevelsAtLeast, AUDIT_RISK_LEVELS } = require('../constants/audit');
const {
  ALL_ATTACK_EVENT_ACTIONS,
  ATTACK_EVENT_TYPE_CODES,
  actionsByAttackType,
  attackTypeOfAction,
} = require('../constants/attackEvents');

// 与 utils/auditQuery 的审计查询同限：同族读面同代价上限，超窗直接 400
// （auditQueryService 另有响应头级的 warnLargeAuditRange 提示，本面把闸收紧在入参）。
const MAX_RANGE_DAYS = 365;
// 每页上限与 LANSEC 参考页对齐（20/50/100）；normalizePagination 同时钳下限。
const PAGE_LIMIT_MAX = 100;

const badParam = (message) => {
  const err = new Error(message);
  err.status = 400; // 与 validateEnum 同口径：参数错误不是服务故障，调用方原样透传 400 文案
  return err;
};

/**
 * severity 区间 → riskLevel 条件。
 *
 * F-149：「某档及以上」的切片必须由 riskLevelsAtLeast 从有序清单派生，禁手抄
 * 字面量（给 AUDIT_RISK_LEVELS 新增一档时手抄切片会把新档静默漏在判据外）。
 * 「某档及以下」没有现成派生器，同样从 AUDIT_RISK_LEVELS 的有序位置推导，
 * 两端相接即闭区间；min 在 max 之下时区间为空——这不是"查到 0 条"而是
 * 参数矛盾，与 utils/auditQuery 的恒空组合同语义，收口为 400 而非静默空集。
 */
const buildSeverityCondition = (severityMin, severityMax) => {
  if (!severityMin && !severityMax) return null;
  for (const [name, value] of [
    ['severityMin', severityMin],
    ['severityMax', severityMax],
  ]) {
    if (value && !AUDIT_RISK_LEVELS.includes(value)) {
      throw badParam(`参数 ${name} 必须为 ${AUDIT_RISK_LEVELS.join('/')} 之一`);
    }
  }
  let levels = severityMin ? riskLevelsAtLeast(severityMin) : AUDIT_RISK_LEVELS;
  if (severityMax) {
    const maxIdx = AUDIT_RISK_LEVELS.indexOf(severityMax);
    levels = levels.filter((level) => AUDIT_RISK_LEVELS.indexOf(level) <= maxIdx);
  }
  if (levels.length === 0) {
    throw badParam(
      `参数组合恒空：severityMin=${severityMin} 高于 severityMax=${severityMax}，这样查出来一定是 0 条`
    );
  }
  return { riskLevel: { $in: levels } };
};

/**
 * 组装攻击告警查询条件（校验与组装一体：先过的先抛，调用方 catch 后回 400 文案）。
 *
 * 返回 usernamePrefix 旗标与 utils/auditQuery 同语义：为 true 时下游必须对
 * find/countDocuments/aggregate 显式挂 collation，为 false 时不得挂
 * （带 collation 的查询只能命中带同一 collation 的索引，无条件挂会屏蔽时间序索引）。
 *
 * @param {Object} f 显式挑选的筛选字段（调用方不得整包透传 req.query）
 */
// 时间窗：参数名与语义同审计页（isValidDateParam 拦数字形态串，date-only 走
// parseDateBoundary 的业务时区展开——不另起 datetime 语义，避免宿主时区漂移）
const applyTimeWindow = (query, f) => {
  if (!isValidDateParam(f.startDate)) throw badParam('开始日期格式错误');
  if (!isValidDateParam(f.endDate)) throw badParam('结束日期格式错误');
  if (f.startDate && f.endDate) {
    const rangeDays =
      (parseDateBoundary(f.endDate, 'end').getTime() -
        parseDateBoundary(f.startDate, 'start').getTime()) /
      (24 * 60 * 60 * 1000);
    if (rangeDays < 0) throw badParam('结束日期不能早于开始日期');
    if (rangeDays > MAX_RANGE_DAYS) {
      throw badParam(`攻击告警查询时间范围不能超过 ${MAX_RANGE_DAYS} 天`);
    }
  }
  if (f.startDate || f.endDate) {
    query.timestamp = {};
    if (f.startDate) query.timestamp.$gte = parseDateBoundary(f.startDate, 'start');
    if (f.endDate) query.timestamp.$lte = parseDateBoundary(f.endDate, 'end');
  }
};

// 分类切片与规则名等值共用 action 键位，必须在此收口互斥语义：
// 两者同给且规则名不属于该分类 ⇒ 恒空组合，按参数矛盾 400（同 severity 区间）。
const applyActionCondition = (query, f) => {
  const attackType = validateEnum(f.attackType, ATTACK_EVENT_TYPE_CODES, 'attackType');
  if (f.action) {
    if (!ALL_ATTACK_EVENT_ACTIONS.includes(f.action)) {
      throw badParam(`参数 action 必须是攻击告警注册表内的动作之一`);
    }
    if (attackType && attackTypeOfAction(f.action) !== attackType) {
      throw badParam(`参数组合恒空：action=${f.action} 不属于 attackType=${attackType}`);
    }
    query.action = f.action; // 等值命中 {action,timestamp:-1,_id:-1} 索引
    return;
  }
  if (attackType) query.action = { $in: actionsByAttackType(attackType) }; // $in 同样可走该复合索引
};

// 文本维（ip 等值 / username 前缀 / path 部分匹配），判据与审计页同源
const applyTextFilters = (query, f) => {
  if (f.ip) {
    // 与审计页同尺：归一化失败即参数错误；条件形状由 ipQueryCondition 单源
    if (!normalizeIP(f.ip)) throw badParam('参数 ip 必须是合法的 IPv4/IPv6 地址');
    query.ip = ipQueryCondition(f.ip);
  }
  // username 前缀（范围比较 + collation，判据见 utils/auditQuery.usernamePrefixCondition）
  if (f.username !== undefined && f.username !== null && typeof f.username !== 'string') {
    throw badParam('参数 username 必须是字符串');
  }
  if (f.username) query.username = usernamePrefixCondition(f.username);
  // path 非锚定部分匹配：无索引可用（审计页的 body 搜索同级代价），靠
  // MAX_RANGE_DAYS + TTL 留存期兜扫描量；正则必须转义，否则用户输入的
  // `(`/`*` 会把"查告警"变成"抛 CastError"或构造任意谓词。
  if (f.path !== undefined && f.path !== null && typeof f.path !== 'string') {
    throw badParam('参数 path 必须是字符串');
  }
  if (f.path) query.path = { $regex: escapeRegExp(f.path), $options: 'i' };
};

const buildAttackEventFilters = (f = {}) => {
  const query = { action: { $in: ALL_ATTACK_EVENT_ACTIONS } };
  applyTimeWindow(query, f);
  applyActionCondition(query, f);
  applyTextFilters(query, f);
  const severity = buildSeverityCondition(f.severityMin, f.severityMax);
  if (severity) query.riskLevel = severity.riskLevel;
  return { query, usernamePrefix: Boolean(f.username) };
};

/**
 * 取一页（游标与偏移双模，骨架同 auditQueryService 的两个 fetch*）。
 * 排序恒为 {timestamp:-1,_id:-1}（cursorPagination 的全序要求），
 * 投影 RESPONSE_EXCLUDE 裁掉正文/头袋，populate 只取 username（PII 纪律同审计页）。
 */
const fetchAttackEventPage = async ({ query, usernamePrefix, pageNum, limitNum, cursorQuery }) => {
  const collation = usernamePrefix ? AuditLog.AUDIT_USERNAME_COLLATION : null;
  if (cursorQuery) {
    const docs = await withCollation(
      AuditLog.find(cursorQuery)
        .populate('userId', 'username')
        .sort({ timestamp: -1, _id: -1 })
        .limit(limitNum + 1) // 多拉一条只判 hasMore，见 buildCursorResult
        .select(AuditLog.RESPONSE_EXCLUDE),
      collation
    );
    return { docs, total: null, cursorPaged: true };
  }
  const [docs, total] = await Promise.all([
    withCollation(
      AuditLog.find(query)
        .populate('userId', 'username')
        .sort({ timestamp: -1, _id: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .select(AuditLog.RESPONSE_EXCLUDE),
      collation
    ),
    withCollation(AuditLog.countDocuments(query, listCountOptions()), collation),
  ]);
  return { docs, total, cursorPaged: false };
};

/**
 * 处置派生（LANSEC decisions JOIN 的 fsms 对应物）。
 *
 * 口径：处置是「此刻」的状态投影，不是历史封禁记录——IPBlacklist 的行随
 * expiresAt TTL 消失，事件 body 里的 ipBanApplied 又被 RESPONSE_EXCLUDE 裁掉；
 * 历史事实走详情抽屉（GET /audit-logs/:id），本列只回答"这个来源现在怎么样了"：
 *   banned    —— 当前在 IP 黑名单（type:'black'，且未到 expiresAt；行内 expiresAt
 *                到期后靠 TTL 删除，查询瞬间仍以时间为准判一次，不依赖清扫时机）
 *   forensic  —— 在取证触发标记表（isForensicTarget，进程内滑动窗口）：
 *                多实例部署下该标记是各实例本地的，跨实例不聚合——处置列是
 *                运维提示不是合规事实，接受这一口径并在此言明
 *   observing —— 其余（含已被 TTL 清掉的黑名单行：封禁过期即回到观察）
 */
const collectDisposal = async (rows) => {
  const ips = [...new Set(rows.map((row) => row.ip).filter(Boolean))];
  const bannedByNormalizedIp = new Set();
  if (ips.length > 0) {
    const now = Date.now();
    const entries = await IPBlacklist.find({ ip: { $in: ips }, type: 'black' })
      .select('ip expiresAt')
      .lean();
    // 两侧各自 normalizeIP 再对齐：AuditLog.ip 存的是清洗后原文（可能是
    // ::ffff: 映射形态），IPBlacklist 写前归一化——直接文本比对会把"同一个人"
    // 撕成两个键，处置列对这类来源恒显示观察（假阴性），比误报封禁更糟。
    for (const entry of entries) {
      const key = normalizeIP(entry.ip);
      if (!key) continue;
      if (!entry.expiresAt || new Date(entry.expiresAt).getTime() > now) {
        bannedByNormalizedIp.add(key);
      }
    }
  }
  const { isForensicTarget } = require('./forensicTrigger'); // 惰性：进程内 Map，无加载环
  for (const row of rows) {
    const key = row.ip ? normalizeIP(row.ip) : null;
    if (key && bannedByNormalizedIp.has(key)) row.disposal = 'banned';
    else if (row.ip && isForensicTarget(row.ip)) row.disposal = 'forensic';
    else row.disposal = 'observing';
  }
  return rows;
};

/**
 * 处置富化的 fail-soft 外壳：主查询已成功，处置只是派生增强，不该让
 * IPBlacklist 的一瞬抖动把整页拖成 500（withIpLocation 同款取舍）。但失败
 * 不许冒充「观察」——那是对运维撒谎（明明查不到却说"没事"），落到第四档
 * unknown（"此刻不可判定"），方向与 auditScopeFilter 拒绝空集冒充的裁定同源。
 */
const collectDisposalSafely = async (rows) => {
  try {
    return await collectDisposal(rows);
  } catch (error) {
    logger.error(`攻击告警处置富化失败，本页处置列降级为 unknown: ${error.message}`);
    for (const row of rows) row.disposal = 'unknown';
    return rows;
  }
};

/** 取页行的读侧富化：IP 归属地（复用审计页单源）+ 处置派生（fail-soft 外壳） */
const enrichAttackEventRows = async (docs) => {
  const rows = withIpLocation(docs);
  return collectDisposalSafely(rows);
};

/**
 * 分类计数（LANSEC /api/expert/attack-types 的对应物）。
 *
 * $match 用**调用方传入的完整谓词**——分类维由调用方在构建 filters 时剔除
 * （tab 的语义是"给定其它筛选，各类各有多少"，带着 attackType 自身查等于
 * 让其它 tab 恒 0）。$group 落在 action 上再经注册表归并回分类：$match 的
 * action 谓词钉在注册表上，归并理论上不会遇到注册表外的 action；出现时
 * （防御分支）只计入 all 不计入任何分类，宁多报不漏报。
 */
const summarizeByAttackType = async ({ query, usernamePrefix }) => {
  const collation = usernamePrefix ? AuditLog.AUDIT_USERNAME_COLLATION : null;
  const agg = await withCollation(
    AuditLog.aggregate(
      [{ $match: query }, { $group: { _id: '$action', count: { $sum: 1 } } }],
      listAggregateOptions()
    ),
    collation
  );
  const byType = Object.fromEntries(ATTACK_EVENT_TYPE_CODES.map((code) => [code, 0]));
  let all = 0;
  for (const { _id: action, count } of agg) {
    all += count;
    const type = attackTypeOfAction(action);
    if (type && type in byType) byType[type] += count;
  }
  return { all, byType };
};

module.exports = {
  PAGE_LIMIT_MAX,
  MAX_RANGE_DAYS,
  buildAttackEventFilters,
  buildSeverityCondition,
  fetchAttackEventPage,
  enrichAttackEventRows,
  summarizeByAttackType,
  collectDisposal,
  collectDisposalSafely,
};
