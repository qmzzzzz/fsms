/**
 * userController 查路径：用户列表 / 详情 / 统计。
 */
const ApiResponse = require('../../utils/apiResponse');
const { asyncHandler } = require('../../middleware/errorHandler');
const { getDataScope, assertRecordInScope } = require('../../middleware/rbac');
const { castScopeObjectIds } = require('../../utils/scopeCast');
// 用户统计与用户列表/导出共用同一把尺（含 #12 的范围不可用 ⇒ 403）
const { scopeFilterFor } = require('../../services/reportExportService');
const { validateSort, normalizePagination } = require('../../utils/helpers');
const statsCache = require('../../services/statsCache');
const { businessMonthStart } = require('../../constants/timezone');
const userService = require('../../services/userService');
const { USER_OWNER_FIELD, USER_DEPT_FIELD } = require('./shared');

/**
 * 获取用户列表（支持分页、搜索、过滤）
 * GET /api/users
 */
const getUsers = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search, status, department, role, sort = '-createdAt' } = req.query;

  // 校验并规范化排序参数
  const safeSort = validateSort(sort, {
    allowedFields: [
      'username',
      'email',
      'realName',
      'status',
      'department',
      'createdAt',
      'updatedAt',
      'lastLoginAt',
    ],
    defaultSort: '-createdAt',
  });

  const dataScope = await getDataScope(req.user.userId);
  const { roleFound, query } = await userService.buildListQuery(
    { search, status, department, role },
    dataScope
  );

  // 只剩 roleFound 一判：scopeAllowed 已随 #12 改成"范围不可用即 403"
  // （applyDataScopeToQuery 抛错，errorHandler 统一映射），控制器不再回空分页。
  if (!roleFound) {
    return ApiResponse.paginated(
      res,
      [],
      {
        page: parseInt(page),
        limit: parseInt(limit),
        total: 0,
        totalPages: 0,
      },
      '获取用户列表成功'
    );
  }

  // 规范化分页参数（统一限界）
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit);

  // 执行查询
  const { users, count } = await userService.listUsers(query, safeSort, pageNum, limitNum);

  return ApiResponse.paginated(
    res,
    users,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
    },
    '获取用户列表成功'
  );
});

/**
 * 获取单个用户详情
 * GET /api/users/:id
 */
const getUserById = asyncHandler(async (req, res) => {
  const user = await userService.getUserDetail(req.params.id);

  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 数据范围校验：与列表接口口径一致，防止按 ID 横向越权
  // （本接口在路由上已有 user:read 权限门槛，这里补齐数据范围一致性）
  const { allowed } = await assertRecordInScope(req, user, USER_OWNER_FIELD, USER_DEPT_FIELD);
  if (!allowed) {
    return ApiResponse.codeError(res, 'USER_VIEW_FORBIDDEN');
  }

  return ApiResponse.success(res, user, '获取成功');
});

/**
 * $facet 结果 → 面板形状。任何一臂缺失都落到 0 / 空集，
 * 不让 undefined 流到前端（面板按数值直接参与算式）。
 */
const facetArmCount = (rows) => rows?.[0]?.count || 0;

const mapUserStatsFacet = (facetResult) => ({
  total: facetArmCount(facetResult?.total),
  active: facetArmCount(facetResult?.active),
  inactive: facetArmCount(facetResult?.inactive),
  thisMonth: facetArmCount(facetResult?.thisMonth),
  byDepartment: facetResult?.byDepartment || [],
  byRole: facetResult?.byRole || [],
});

/**
 * 获取用户统计信息
 * GET /api/users/stats
 */
const getUserStats = asyncHandler(async (req, res) => {
  // 数据范围控制：与列表/详情接口口径一致，防止越权看到全组织统计
  const dataScope = await getDataScope(req.user.userId);
  // 走 scopeFilterFor 而不是直接调 buildDataScopeFilter：后者对"范围不可用"只返回
  // `{_id: null}`，于是本接口给出 HTTP 200 + 全零统计——调用方分不清"这个部门没有账号"
  // 与"这个账号没有可见范围"，而这两件的后续动作相反（#12 选项①：一律 403）。
  const scopeFilter = scopeFilterFor('user', dataScope);

  const crypto = require('crypto');
  const scopeFingerprint = crypto
    .createHash('sha1')
    .update(JSON.stringify(scopeFilter))
    .digest('hex')
    .slice(0, 12);
  // 统计缓存：缓存键由用户 ID + 数据范围稳定摘要 + 全局失效代号组成。
  // 代号（A-1）让任何用户写操作都能一次性作废**所有查看者**的旧缓存：
  // 仅按被改用户 id 失效删不掉管理员 B/C 的桶，他们最坏要等 TTL 才看到新数字。
  const cacheKey = `stats:${req.user.userId}:${scopeFingerprint}:g${statsCache.generation()}`;

  // 命中缓存直接返回，避免数据库往返
  const cached = statsCache.get(cacheKey);
  if (cached.hit) {
    return ApiResponse.success(res, cached.data, '获取用户统计成功');
  }

  // 本月起始时间：取业务时区当月 1 日零点（与全站「今日」窗口同源）。
  // 原 setDate(1)+setHours(0,0,0,0) 是服务器本地时区——容器裸跑 UTC 时，
  // 业务时区每月 1 日前 8 小时新建的账号被算进上月，与同接口的其它计数、
  // 仪表盘「今日」口径互相矛盾。
  const startOfMonth = businessMonthStart();

  // $facet 单次聚合：冷缓存时 6 次串行 DB 往返合并为 1 次，降低冷启动/并发抖动
  const [facetResult] = await userService.aggregateStats([
    // Model.aggregate 不做 schema cast：self 范围下 scopeFilter.createdBy 是 JWT 里的
    // 字符串，直接进 $match 对 ObjectId 字段零匹配 → 统计恒 0（列表走 find() 会 cast，
    // 于是"列表有数据、看板全 0"）。与 AlarmService.getAlarmStats 同用 castScopeObjectIds 归一。
    { $match: castScopeObjectIds(scopeFilter) },
    {
      $facet: {
        // 总用户数
        total: [{ $count: 'count' }],
        // 活跃用户数（状态为 active）
        active: [{ $match: { status: 'active' } }, { $count: 'count' }],
        // 禁用用户数
        inactive: [{ $match: { status: 'inactive' } }, { $count: 'count' }],
        // 本月新增用户
        thisMonth: [{ $match: { createdAt: { $gte: startOfMonth } } }, { $count: 'count' }],
        // 按部门统计
        byDepartment: [
          { $match: { status: 'active' } },
          { $group: { _id: '$department', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ],
        // 按角色统计（口径对齐 byDepartment：仅统计 active 用户，
        // 此前 byDepartment 只算 active 而 byRole 算全部，两个维度基数不一致）
        byRole: [
          { $match: { status: 'active' } },
          { $unwind: '$roles' },
          { $group: { _id: '$roles', count: { $sum: 1 } } },
          { $lookup: { from: 'roles', localField: '_id', foreignField: '_id', as: 'role' } },
          { $unwind: '$role' },
          {
            $project: {
              _id: 0,
              roleId: '$_id',
              roleName: '$role.name',
              roleCode: '$role.code',
              count: 1,
            },
          },
          { $sort: { count: -1 } },
        ],
      },
    },
  ]);

  const data = mapUserStatsFacet(facetResult);

  // 写入缓存（TTL 使用配置默认值），便于后续请求直接命中
  statsCache.set(cacheKey, data);

  return ApiResponse.success(res, data, '获取用户统计成功');
});

module.exports = { getUsers, getUserById, getUserStats };
