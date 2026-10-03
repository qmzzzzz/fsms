/**
 * 审计日志控制器（D-1 自 securityController 拆出）
 *
 * 审计日志的查询、流式导出（CSV + 签名 manifest）与哈希链完整性校验。
 * action 白名单枚举以 constants/audit.js 为单一事实来源。
 */

const AuditLog = require('../models/AuditLog');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { listCountOptions } = require('../utils/queryBudget');
const { normalizePagination } = require('../utils/helpers');
// riskLevel 汇总的 TTL 缓存底座（同一份缓存口径，不再另造一个 Map）
const statsCache = require('./statsCache');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
// 超大时间范围阈值（天）
const AUDIT_LOG_RANGE_WARN_DAYS = 365;

/**
 * 给审计行补 IP 归属地（后台核查视图增强）。
 *
 * mongoose 文档的临时属性不会进 toJSON，须先转 plain object 再挂字段；
 * locate 内部带结果缓存且 fail-soft（任何异常返回 null），单页 ≤1000 行的
 * 逐行查询是微秒级，不构成查询路径的新增开销。
 * @param {Array<object>} docs 分页查询返回的行
 * @returns {Array<object>} 携带 location（可能为 null）的 plain object 行
 */
const withIpLocation = (docs) =>
  docs.map((doc) => {
    const row = typeof doc.toObject === 'function' ? doc.toObject() : doc;
    row.location = require('./ipLocationService').locate(row.ip);
    return row;
  });
/**
 * 把"这次查询要扫多大范围"对外说出来，两个取值：
 *  · `query_range_too_large` —— 两端都给了且跨度 > 365 天；
 *  · `no_time_window` —— 时间窗缺失或只给了一端（审计页默认视图正是这一格）。
 *
 * 后者此前被首句 `if (!startDate || !endDate) return;` 直接早退跳过，而那才是唯一
 * "必然扫满整个留存期"的形态：时间窗缺失时没有任何可收窄的时间谓词，而 username
 * 过滤此前是不锚定的 `$regex`（无索引可用）⇒ 整条查询只能 COLLSCAN；同一次请求还要
 * 为同一谓词付 `countDocuments` + riskLevel 汇总 + 分页 find 三遍扫描
 * （分页 limit 只限制返回行数，不限制扫描量）。
 *
 * 2026-09-28 更新（Top-8 前半）：username 过滤已改为「前缀 + collation 范围查询」，
 * 并补齐 `username_ci_timestamp` 索引（见 `models/AuditLog.js`），带 username 的过滤
 * 不再必然 COLLSCAN。但**本告警仍然成立且必要**——时间窗缺失时的扫描量由留存期决定，
 * 与 username 有没有索引无关。
 *
 * 只发响应头、不打 logger.warn：审计页是高频入口且默认就命中这一格，
 * 打警告等于把日志变成噪声——告警疲劳比缺告警更糟。
 */
const warnLargeAuditRange = ({ startDate, endDate }, res) => {
  if (!startDate || !endDate) {
    res.setHeader('X-Performance-Warning', 'no_time_window');
    return;
  }
  const deltaDays =
    (new Date(endDate).getTime() - new Date(startDate).getTime()) / (24 * 60 * 60 * 1000);
  if (deltaDays > AUDIT_LOG_RANGE_WARN_DAYS) {
    logger.warn(`审计日志查询时间范围过大（${Math.round(deltaDays)}天），可能影响性能`);
    res.setHeader('X-Performance-Warning', 'query_range_too_large');
  }
};

const buildAuditSummary = (summaryAgg) => {
  const summaryMap = new Map(summaryAgg.map((summary) => [summary._id, summary.count]));
  return {
    critical: summaryMap.get('critical') || 0,
    high: summaryMap.get('high') || 0,
    medium: summaryMap.get('medium') || 0,
    low: summaryMap.get('low') || 0,
  };
};

/**
 * riskLevel 汇总的 TTL 缓存（2026-09-26 审计 Top-8 后半：每页全量聚合）
 *
 * 缺陷：汇总 `$group` 只依赖 `query`、与页码无关，却被放在两个取页函数里各写一遍，
 * 于是**每翻一页就为同一谓词重算一次全量聚合**。叠加本文件头注释里那条既有事实
 * （username 过滤的索引已于 2026-09-28 补齐，见 `models/AuditLog.js`），翻 100 页就是
 * 100 次同谓词的全量聚合。
 *
 * 为什么可以容忍 10 秒的滞后：`AuditLog` 是**只追加**集合，缓存里的计数只会比真实值
 * 偏小、不会偏大；而列表本身始终直查（不走缓存）。即"页面上看得见的行"与
 * "汇总里的计数"最多在 10 秒窗口内对不齐，且偏差方向固定（汇总偏小），
 * 不会出现"汇总说有 3 条 critical、翻遍列表只有 2 条"那种看起来像丢数据的方向。
 *
 * 复用 statsCache（而不是再造一个 Map）：它已经带 TTL、容量上限与"内部异常一律
 * 降级为未命中"的 fail-safe 语义——另写一份缓存只会多一处会漂移的口径，
 * 而缓存出错的方向恰恰是"静默返回错数据"。
 *
 * 缓存键长度上限：数据范围里的 department 档会展开成很长的 `$in` 数组，
 * 让这种键进缓存等于用内存换一次查询——超过 2KB 直接不走缓存（宁可不缓存）。
 */
const SUMMARY_CACHE_TTL_SEC = 10;
const SUMMARY_CACHE_MAX_KEY_LEN = 2048;

/** 稳定序列化：对象键排序，保证同一逻辑条件恒得同一缓存键（键序不该决定命中与否） */
const stableStringify = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object' && !(value instanceof Date) && !value._bsontype) {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
};

const summaryCacheKey = (query) => {
  try {
    const key = `audit:risk-summary:${stableStringify(query)}`;
    return key.length > SUMMARY_CACHE_MAX_KEY_LEN ? null : key;
  } catch (_) {
    return null; // 序列化失败就不缓存，绝不因缓存键构造失败而影响查询
  }
};

/** 取 riskLevel 汇总（带 TTL 缓存）；缓存不可用时行为与不带缓存完全一致 */
const summarizeByRiskLevel = async (query, collation) => {
  const key = summaryCacheKey(query);
  if (key) {
    const cached = statsCache.get(key);
    if (cached.hit) return cached.data;
  }
  // 缓存键无需并入 collation：collation 由 query 自身决定（含 username 前缀条件时才带），
  // 同一个 query 不可能对应两种 collation。
  const agg = await withCollation(
    AuditLog.aggregate([{ $match: query }, { $group: { _id: '$riskLevel', count: { $sum: 1 } } }]),
    collation
  );
  if (key) statsCache.set(key, agg, SUMMARY_CACHE_TTL_SEC);
  return agg;
};

// 评价报告 #22/#13：数据范围过滤（all/self/department 翻译 + 部门成员缓存）
// 已拆分至 auditScopeFilter.js（体积棘轮），此处 re-export 保持既有调用面不变。
const applyAuditDataScope = require('./auditScopeFilter').applyAuditDataScope;

const fetchAuditCursorPage = (cursorQuery, query, limitNum, collation) =>
  Promise.all([
    withCollation(
      AuditLog.find(cursorQuery)
        .populate('userId', 'username realName')
        // `_id` 次级排序键与续翻子句 `{timestamp:v,_id:{$lt:id}}` 同向；缺它则同一毫秒
        // 内的审计记录整块跨页漂移（索引见 models/AuditLog.js）
        .sort({ timestamp: -1, _id: -1 })
        .limit(limitNum + 1)
        .select(AuditLog.RESPONSE_EXCLUDE),
      collation
    ),
    // 汇总与页码无关 ⇒ 走 TTL 缓存，续翻不再重算全量 $group（见 summarizeByRiskLevel）
    summarizeByRiskLevel(query, collation),
  ]);

const fetchAuditOffsetPage = (query, skip, limitNum, collation) =>
  Promise.all([
    withCollation(
      AuditLog.find(query)
        .populate('userId', 'username realName')
        // 与游标分支同向：本页末条要拿去 mint nextCursor
        .sort({ timestamp: -1, _id: -1 })
        .skip(skip)
        .limit(limitNum)
        .select(AuditLog.RESPONSE_EXCLUDE),
      collation
    ),
    summarizeByRiskLevel(query, collation),
  ]);

// E-05 整改：本文件此前内联维护了第二份 buildAuditQuery（与 utils/auditQuery.js
// 逐行近似但不相同），两份实现已经漂移——本地副本的 date-only 边界仍走
// `new Date(`${d}T00:00:00`)`（服务器本地时区），而共享实现早已改为
// parseDateBoundary（业务时区，评价报告 #12）。后果是 UTC 容器下
// 查询接口与导出接口对同一天的筛选边界相差 8 小时：
//   UTC 容器 + startDate=2026-09-15
//     查询（本地副本）→ 2026-09-15T00:00:00Z
//     导出（共享实现）→ 2026-09-14T16:00:00Z（业务时区当天 0 点）
//   即导出比查询多算 8 小时，而东八区当天 0-8 点的记录在查询侧被漏掉。
// 现删除本地副本，统一引用 utils/auditQuery.js——重复块与口径漂移一并消除。
const { buildAuditQuery, withCollation } = require('../utils/auditQuery');
/**
 * 查询审计日志（支持多维度筛选）
 * GET /api/security/audit-logs
 *
 * L-13 修复：原实现为「同步 try/catch 包裹 async IIFE」——
 *   try { return (async () => { await ... })(); } catch (e) { ... }
 * 同步 catch 拦不住 IIFE 内部的 reject，故失败时这里专门的
 * logger.error('审计日志查询失败') 与 codeError 都不会执行，错误会逃逸到
 * asyncHandler → 全局 errorHandler，日志变成泛化的 UnhandledError，丢失操作上下文。
 * （不会挂死：调用方在 asyncHandler 内 return 了该 promise，故仍返回 500。）
 * 现改为 async 函数 + await，让 try/catch 真正生效。
 *
 * 游标条件（applyCursorCondition）不在这里的 try 内：它抛的是 400「分页游标无效」，
 * 属客户端输入问题，而本 try 的语义是「查询执行失败」⇒ 500 + AUDIT_QUERY_FAILED
 * + 一条误导性 logger.error。同一条非法游标在设备/告警/巡检三个接口都是 400，
 * 只有审计接口会降级成 5xx。改到调用点与 decodeCursor 同一个 400 出口处理。
 */
const queryAuditCursorPage = async (req, res, query, { limitNum, cursorQuery, collation }) => {
  try {
    const [docs, summaryAgg] = await fetchAuditCursorPage(cursorQuery, query, limitNum, collation);
    const { items, hasMore, nextCursor } = buildCursorResult(docs, limitNum, 'timestamp');
    return ApiResponse.success(
      res,
      {
        data: withIpLocation(items),
        meta: {
          page: null,
          limit: limitNum,
          total: null,
          totalPages: null,
          hasNext: hasMore,
          hasPrev: true,
          nextCursor,
          lastUpdated: new Date().toISOString(),
          count: items.length,
          summary: buildAuditSummary(summaryAgg),
        },
      },
      '获取成功'
    );
  } catch (error) {
    logger.error(`审计日志查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'AUDIT_QUERY_FAILED');
  }
};

// L-13 修复：同上，改为 async 函数 + await，使 try/catch 能真正接管异步失败
const queryAuditOffsetPage = async (req, res, query, { pageNum, limitNum, collation }) => {
  try {
    const total = await withCollation(
      AuditLog.countDocuments(query, listCountOptions()),
      collation
    );
    if (total === 0) {
      return ApiResponse.success(
        res,
        {
          data: [],
          meta: {
            page: pageNum,
            limit: limitNum,
            total: 0,
            totalPages: 0,
            hasNext: false,
            hasPrev: false,
            lastUpdated: new Date().toISOString(),
            count: 0,
            summary: { critical: 0, high: 0, medium: 0, low: 0 },
          },
        },
        '获取成功'
      );
    }

    const [logs, summaryAgg] = await fetchAuditOffsetPage(
      query,
      (pageNum - 1) * limitNum,
      limitNum,
      collation
    );
    const hasNext = pageNum * limitNum < total;
    const lastLog = logs[logs.length - 1];
    return ApiResponse.success(
      res,
      {
        data: withIpLocation(logs),
        meta: {
          page: pageNum,
          limit: limitNum,
          total,
          totalPages: Math.ceil(total / limitNum),
          hasNext,
          hasPrev: pageNum > 1,
          nextCursor:
            hasNext && lastLog
              ? encodeCursor({ v: lastLog.timestamp, id: String(lastLog._id) })
              : null,
          lastUpdated: new Date().toISOString(),
          count: logs.length,
          summary: buildAuditSummary(summaryAgg),
        },
      },
      '获取成功'
    );
  } catch (error) {
    logger.error(`审计日志查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'AUDIT_QUERY_FAILED');
  }
};

const queryAuditLogs = asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, cursor } = req.query;
  let query;
  let startDate;
  let endDate;
  // 仅在 query 含 username 前缀条件时才带 collation：带了会屏蔽掉其它不带 collation 的
  // 时间序索引（见 withCollation 的注释），所以不能无条件挂。
  let collation = null;
  try {
    const built = buildAuditQuery(req);
    ({ query, startDate, endDate } = built);
    collation = built.usernamePrefix ? AuditLog.AUDIT_USERNAME_COLLATION : null;
  } catch (err) {
    return ApiResponse.error(res, err.message, 400);
  }

  warnLargeAuditRange({ startDate, endDate }, res);
  if (!req.user || !req.user.userId) {
    return ApiResponse.codeError(res, 'UNAUTHORIZED_ACCESS');
  }

  ({ query } = await applyAuditDataScope(query, req.user.userId));

  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 1000);
  let cursorQuery = null;
  if (cursor) {
    // 解码与「游标→查询条件」的翻译都在这个 try 里：两步都可能判游标非法并抛 400
    // （decodeCursor 管结构，applyCursorCondition→castCursorValue 管排序键值类型，
    // 例如把设备列表的 deviceCode 游标贴进本接口时 v 不是日期）。
    // 二者必须共用下面这一个 400 出口，不能落到下游那个「执行失败 ⇒ 500」的 catch。
    try {
      cursorQuery = applyCursorCondition(query, {
        sortField: 'timestamp',
        sortDir: -1,
        cursor: decodeCursor(cursor),
        valueType: 'date',
      });
    } catch (err) {
      return ApiResponse.error(res, err.message || '分页游标无效', err.statusCode || 400);
    }
  }

  if (cursorQuery) {
    return queryAuditCursorPage(req, res, query, { limitNum, cursorQuery, collation });
  }
  return queryAuditOffsetPage(req, res, query, { pageNum, limitNum, collation });
});

module.exports = {
  queryAuditLogs,
  applyAuditDataScope,
  // 仅供测试直调：汇总缓存的命中/失效语义无法经 HTTP 断言（外层还叠着
  // 分页、数据范围与响应装配），而"每页重算一次全量聚合"这个缺陷恰恰
  // 只在调用次数上可见。
  summarizeByRiskLevel,
  summaryCacheKey,
};
