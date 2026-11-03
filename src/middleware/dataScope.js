// 数据范围判定（自 rbac.js 抽出，避免 securityAlert→auditScopeFilter→rbac 惰性环）；内置 GUEST 的 all 档例外见 docs/data-scope.md

const User = require('../models/User');
const ApiError = require('../utils/ApiError');
const { ERROR_CODES } = require('../utils/errorCodes');

/**
 * 数据范围权限检查
 * 根据用户角色层级限制可访问的数据范围
 * 返回的数据范围可用于 Controller 中的查询过滤
 *
 * 数据范围类型（阈值与下方 LEVEL_* 常量同源，不要只改注释）：
 * - all: 全部数据（角色 level >= 9；内置访客也归此档，见下）
 * - department: 本部门/本区域数据（角色 level >= 7）
 * - self: 仅自己创建/负责的数据（角色 level >= 4）
 * - none: 无数据权限（其余 level < 4 的自定义角色）
 *
 *
 * @param {string} userId - 用户 ID
 * @returns {Promise<Object>} 数据范围配置
 */
const getDataScope = async (userId) => {
  const user = await User.findById(userId).populate({
    path: 'roles',
    select: 'level name code',
    // 与权限轴（userPermissionService/permissionHelper 的 match:{status:'active'}）同口径：
    // 管理员停用角色必须让「数据范围」也立即失效。否则停用 SUPER_ADMIN 角色后，
    // getDataScope 仍按其 level 返回 {type:'all'}，10+ 处列表/统计/报表调用方照常全量放行。
    // populate 过滤后若 roles 全被剔除 → 下方 length===0 分支返回 {type:'none'}（deny），fail-closed。
    match: { status: 'active' },
  });

  if (!user) return { type: 'none' };

  // 防御性 filter(Boolean)：实测 mongoose 8.24.1 对 populate+match 未命中的引用是**丢弃元素**
  // （不留 null），故今天它不改变结果；保留它是防未来版本改为留 null 洞 —— 形状由
  // src/tests/populateMatchShape.test.js 钉住（升级会先红），届时 `r.level` 才可能抛错。
  // 过滤后若 roles 全被剔除 → {type:'none'}（deny），fail-closed。
  const activeRoles = (user.roles || []).filter(Boolean);

  // 处理 roles 为空的情况
  if (activeRoles.length === 0) {
    return { type: 'none' };
  }

  const levels = activeRoles.map((r) => r.level || 1);
  const maxLevel = Math.max(...levels);

  // 数据范围层级常量（与 initData.js 中 role level 10/8/6/4/1 对应）
  // L1 修正：种子角色 FIREFIGHTER=4 / GUEST=1，原先 LEVEL_SELF=5 导致消防员
  // （level 4）落入 none 档，"仅自己数据"的既定语义被静默降级为无数据
  const LEVEL_ALL = 9; // 超级管理员：全部数据
  const LEVEL_DEPARTMENT = 7; // 安全管理员/部门主管：本部门数据
  const LEVEL_SELF = 4; // 普通消防员：仅自己创建/负责的数据

  // 内置访客：全量业务数据只读（读操作由 GUEST 的权限码收窄，写操作没有任何权限码）。
  // 必须排在 level 判定之前：访客与更高角色并存时，取并集的最宽档。
  if (activeRoles.some((r) => r.code === 'GUEST')) {
    return { type: 'all' };
  }

  // 根据角色层级返回数据范围
  if (maxLevel >= LEVEL_ALL) {
    return { type: 'all' };
  } else if (maxLevel >= LEVEL_DEPARTMENT) {
    return { type: 'department', department: user.department };
  } else if (maxLevel >= LEVEL_SELF) {
    return { type: 'self', userId };
  } else {
    // 访客/低级别：无数据权限
    return { type: 'none' };
  }
};

/**
 * 数据范围不可用 ⇒ 403（DATA_SCOPE_DENIED）。
 *
 * 走 ApiError 而非直接 res.status：本函数被 Service 层调用（那里没有 res），
 * 由全局 errorHandler 统一映射成 403 响应——与 ApiError 类的既定用途一致。
 */
const deniedDataScope = () =>
  new ApiError(
    ERROR_CODES.DATA_SCOPE_DENIED.message,
    ERROR_CODES.DATA_SCOPE_DENIED.status,
    undefined,
    'DATA_SCOPE_DENIED'
  );

/**
 * 数据范围是否不可用——**唯一一份判据**。
 *
 * 为什么必须单点：这份判据原先只活在 applyDataScopeToQuery 开头的几行里，
 * 而 auditScopeFilter / reportExportService 各自还有一份"deny 就回空集"的私有实现。
 * #12 要求这三处统一改成 403，判据抄三遍必然漂移，漂移的方向一定是"某一条忘了拒"。
 *
 * @param {Object} dataScope getDataScope 的返回值
 * @returns {boolean} true=不可用（调用方应 403）
 */
const isDataScopeDenied = (dataScope) =>
  !dataScope ||
  dataScope.type === 'none' ||
  (dataScope.type === 'department' && !dataScope.department) ||
  (dataScope.type === 'self' && !dataScope.userId) ||
  // 白名单必须含 'all'：它是**可用**范围（最宽的那一档），漏掉就会把超管一律拒掉。
  // 这个漏子第一次跑 edgeCases 的「all：原样放行」就炸了——记在这里免得再犯。
  !['all', 'department', 'self'].includes(dataScope.type);

/**
 * 按请求记忆化（E7）：同一 HTTP 请求内的多次范围判定共享一次 User.findById+populate。
 *
 * 为什么必须有它：一次请求的主链会多次判范围——控制器入口一次、assertRecordInScope 一次、
 * 导出/统计腿再来一两次，每次都是同一条 populate 查询。共享的载体是 **req 本身**
 * （每个请求唯一、随响应丢弃）⇒ 结构上不可能跨请求泄漏；并发调用拿到的是**同一个
 * promise**（第一次调用发起查询，其余 await 它），不是"各自查一次再比结果"。
 * 调度器等非 HTTP 调用方不持 req，继续用裸 getDataScope——语义等价，只是没有请求内记忆化。
 * 失败不留缓存：查询被拒时删掉键，下一个调用点重试而不是共享同一个 rejection。
 */
const REQUEST_SCOPE_KEY = Symbol('dataScope');

const getDataScopeForRequest = (req, userId) => {
  if (!req || typeof req !== 'object') return getDataScope(userId);
  if (!req[REQUEST_SCOPE_KEY]) {
    req[REQUEST_SCOPE_KEY] = getDataScope(userId).catch((err) => {
      delete req[REQUEST_SCOPE_KEY];
      throw err;
    });
  }
  return req[REQUEST_SCOPE_KEY];
};

module.exports = {
  getDataScope,
  getDataScopeForRequest,
  REQUEST_SCOPE_KEY,
  deniedDataScope,
  isDataScopeDenied,
};
