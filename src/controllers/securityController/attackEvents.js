/**
 * 安全管理控制器 · 攻击告警查询读口。读档与 /alerts、/audit-logs 同源：
 * security:audit + 二次验证票据，数据范围交 applyAuditDataScope 收口，不新增权限码。
 * **已知且有意接受的副作用**（与画像读口同款）：蜜罐审计行不带 userId（陷阱账号不是
 * 真实业务主体），self/department 两档的谓词按 userId 过滤 ⇒ 这两档恒为空；空表不许
 * 冒充「没有攻击」，出口回传调用者自己的 dataScopeType 自述（/api/auth/me 已在回传）。
 * 本文件不得直接 require 任何 src/models/ 路径（layeringRatchet 零容忍）。
 */

const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { normalizePagination } = require('../../utils/helpers');
const {
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
  encodeCursor,
} = require('../../utils/cursorPagination');
const { applyAuditDataScope } = require('../../services/auditScopeFilter');
const {
  buildAttackEventFilters,
  fetchAttackEventPage,
  enrichAttackEventRows,
  summarizeByAttackType,
  PAGE_LIMIT_MAX,
} = require('../../services/attackEventQueryService');

/**
 * 显式挑选筛选字段：只这几个键流进下游的校验与组装。
 * buildAttackEventFilters 也不得整包吃 req.query（page/limit/cursor 等分页键
 * 不参与条件构造；qs 展开的数组/对象形态在下游逐项判型收口）。
 */
const readFilters = (q) => ({
  startDate: q.startDate,
  endDate: q.endDate,
  ip: q.ip,
  username: q.username,
  attackType: q.attackType,
  severityMin: q.severityMin,
  severityMax: q.severityMax,
  action: q.action,
  path: q.path,
});

// 参数构建阶段的统一 400 出口：客户端输入问题不得降级成 500
// （与 queryAuditLogs 对 buildAuditQuery 的处置同形；文案由 services 层单源给出）
const respondBadRequest = (res, error) =>
  ApiResponse.error(res, error.message || '参数错误', error.statusCode || error.status || 400);

/**
 * GET /api/security/attack-events —— 攻击告警分页查询（游标与偏移双模，同审计列表）
 */
const getAttackEvents = asyncHandler(async (req, res) => {
  let filterQuery;
  let usernamePrefix;
  let pageNum;
  let limitNum;
  try {
    const built = buildAttackEventFilters(readFilters(req.query));
    filterQuery = built.query;
    usernamePrefix = built.usernamePrefix;
    ({ page: pageNum, limit: limitNum } = normalizePagination(
      req.query.page,
      req.query.limit,
      PAGE_LIMIT_MAX
    ));
  } catch (error) {
    return respondBadRequest(res, error);
  }

  try {
    // 数据范围先于游标条件：cursorQuery 是对 baseQuery 的 $and 包裹产物，
    // scope 必须先并入 baseQuery 再包游标（审计列表同序），否则两次 $and 嵌套
    // 会让范围谓词与续翻谓词各成一层，虽语义等价但与审计出口的形状不再可对拍。
    const { query: scopedQuery, dataScope } = await applyAuditDataScope(
      filterQuery,
      req.user.userId
    );

    let cursorQuery = null;
    if (req.query.cursor) {
      // 解码与「游标→查询条件」的翻译共用一个 400 出口：decodeCursor 管结构、
      // applyCursorCondition 管排序键值类型（贴错接口的游标 v 不是日期），
      // 不能落到下游那个「执行失败 ⇒ 500」的 catch（审计侧同判例）。
      try {
        cursorQuery = applyCursorCondition(scopedQuery, {
          sortField: 'timestamp',
          sortDir: -1,
          cursor: decodeCursor(req.query.cursor),
          valueType: 'date',
        });
      } catch (error) {
        return respondBadRequest(res, error);
      }
    }

    const { docs, total, cursorPaged } = await fetchAttackEventPage({
      query: scopedQuery,
      usernamePrefix,
      pageNum,
      limitNum,
      cursorQuery,
    });

    if (cursorPaged) {
      const { items, hasMore, nextCursor } = buildCursorResult(docs, limitNum, 'timestamp');
      const rows = await enrichAttackEventRows(items);
      return ApiResponse.successWithMeta(
        res,
        rows,
        {
          page: null,
          limit: limitNum,
          total: null,
          totalPages: null,
          hasNext: hasMore,
          hasPrev: true,
          nextCursor,
          lastUpdated: new Date().toISOString(),
          count: rows.length,
          dataScopeType: dataScope.type,
        },
        '获取成功'
      );
    }

    const rows = await enrichAttackEventRows(docs);
    const hasNext = pageNum * limitNum < total;
    const lastRow = rows[rows.length - 1];
    return ApiResponse.successWithMeta(
      res,
      rows,
      {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum),
        hasNext,
        hasPrev: pageNum > 1,
        // 偏移模式附带 nextCursor：前端切游标续翻时不必回到第一页重查（审计同款）
        nextCursor:
          hasNext && lastRow
            ? encodeCursor({ v: lastRow.timestamp, id: String(lastRow._id) })
            : null,
        lastUpdated: new Date().toISOString(),
        count: rows.length,
        dataScopeType: dataScope.type,
      },
      '获取成功'
    );
  } catch (error) {
    if (error.isApiError) throw error;
    logger.error(`攻击告警查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'AUDIT_QUERY_FAILED');
  }
});

/**
 * GET /api/security/attack-events/summary —— 分类计数（tab 角标）
 *
 * 语义是「给定其它筛选，各类各有多少」：attackType 自身必须剔除后再构建，
 * 否则选中某个分类时其余 tab 全部恒 0（LANSEC 攻击类型统计同口径）。
 */
const getAttackEventSummary = asyncHandler(async (req, res) => {
  let built;
  try {
    built = buildAttackEventFilters({ ...readFilters(req.query), attackType: undefined });
  } catch (error) {
    return respondBadRequest(res, error);
  }

  try {
    const { query: scopedQuery, dataScope } = await applyAuditDataScope(
      built.query,
      req.user.userId
    );
    const counts = await summarizeByAttackType({
      query: scopedQuery,
      usernamePrefix: built.usernamePrefix,
    });
    return ApiResponse.successWithMeta(
      res,
      counts.byType,
      { all: counts.all, dataScopeType: dataScope.type },
      '获取成功'
    );
  } catch (error) {
    if (error.isApiError) throw error;
    logger.error(`攻击告警分类计数失败: ${error.message}`);
    return ApiResponse.codeError(res, 'AUDIT_QUERY_FAILED');
  }
});

module.exports = { getAttackEvents, getAttackEventSummary };
