/**
 * 列表链查询预算（2026-10-01 审计 finding：服务端时间预算此前只覆盖审计侧）
 *
 * 缺口：审计侧早已把「不锚定 $regex ⇒ COLLSCAN」写进注释并用上 maxTimeMS
 * （models/auditLogQueryStatics.js / services/auditChainVerify.js），而业务列表链
 * （报警 / 设备 / 巡检 / 用户 / 角色 / 权限的 find+countDocuments 成对扫描与统计
 * 聚合）没有任何时间预算——不锚定 `new RegExp(escaped, 'i')` 打在无索引字段
 * （description / realName 等）上时每请求两次全表扫描，一条慢查询就能拖死
 * 事件循环之外的 Mongo 连接池。
 *
 * 预算是**兜底**而不是优化：正常的列表查询走索引远快于此；预算只裁「条件
 * 恶化到全表扫描级别」的尾部，让这类请求以明确超时失败，而不是无限占用。
 * 超时的用户可见形态是 500（Mongoose CastError/执行错误路径），与慢查询日志
 * 共同构成可观测信号。
 *
 * 取值口径：默认 10s——P99 正常列表（毫秒级）的数百倍余量，显著小于
 * 用户感知「页面死了」的阈值；env 可调（LIST_QUERY_MAX_TIME_MS），夹取
 * [500, 300000]，非法值回退默认（与 config 的 envInt 同纪律：宁可回退不可 NaN）。
 */

'use strict';

const DEFAULT_LIST_QUERY_MAX_TIME_MS = 10000;
const MIN_LIST_QUERY_BUDGET_MS = 500;
const MAX_LIST_QUERY_BUDGET_MS = 300000;

/**
 * 解析预算值：未设置取默认；设置了但非正整数或越界按边界/默认收敛，
 * 绝不产出 NaN——`Date.now() + NaN` 式的静默失真在部署脚本层已有先例。
 */
const parseListQueryBudgetMs = (raw) => {
  const s = String(raw === undefined || raw === null ? '' : raw).trim();
  if (!s) return DEFAULT_LIST_QUERY_MAX_TIME_MS;
  if (!/^\d+$/.test(s)) return DEFAULT_LIST_QUERY_MAX_TIME_MS;
  const n = Number(s);
  if (n < MIN_LIST_QUERY_BUDGET_MS) return MIN_LIST_QUERY_BUDGET_MS;
  if (n > MAX_LIST_QUERY_BUDGET_MS) return MAX_LIST_QUERY_BUDGET_MS;
  return n;
};

const LIST_QUERY_BUDGET_MS = parseListQueryBudgetMs(process.env.LIST_QUERY_MAX_TIME_MS);

/** find 链上挂预算：`withListBudget(Model.find(query)).select(...)...` */
const withListBudget = (query) => query.maxTimeMS(LIST_QUERY_BUDGET_MS);

/** countDocuments 的 options 形态：`Model.countDocuments(query, listCountOptions())` */
const listCountOptions = () => ({ maxTimeMS: LIST_QUERY_BUDGET_MS });

/** aggregate 的 options 形态：`Model.aggregate(pipeline, listAggregateOptions())` */
const listAggregateOptions = () => ({ maxTimeMS: LIST_QUERY_BUDGET_MS });

module.exports = {
  DEFAULT_LIST_QUERY_MAX_TIME_MS,
  LIST_QUERY_BUDGET_MS,
  parseListQueryBudgetMs,
  withListBudget,
  listCountOptions,
  listAggregateOptions,
};
