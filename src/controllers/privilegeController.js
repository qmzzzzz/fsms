/**
 * 临时权限授予控制器：HTTP 编排与入参校验，业务规则全部在 privilegeGrantService。
 */

'use strict';

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');
const { PRIVILEGE_GRANT_STATUSES } = require('../constants/privilegeGrant');
const privilegeGrantService = require('../services/privilegeGrantService');
const accessReviewService = require('../services/accessReviewService');

// ObjectId 形态（24 位十六进制）：PrivilegeGrant.userId 是 ObjectId 引用，
// 命中才允许进服务层拼 Mongo 查询
const OBJECT_ID_SHAPE_RE = /^[0-9a-fA-F]{24}$/;

const failValidation = (req, res) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) return false;
  ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: safeFieldErrors(errors) });
  return true;
};

const operatorOf = (req) => ({ userId: req.user.userId, username: req.user.username });

const createGrant = asyncHandler(async (req, res) => {
  if (failValidation(req, res)) return;
  const { targetUserId, permissionCodes, reason, durationHours } = req.body;
  const grant = await privilegeGrantService.requestGrant({
    targetUserId,
    permissionCodes,
    reason,
    durationHours,
    operator: operatorOf(req),
  });
  return ApiResponse.success(
    res,
    {
      id: grant._id,
      status: grant.status,
      highRisk: grant.highRisk,
      requiredApprovals: grant.requiredApprovals,
      approvals: grant.approvals.length,
    },
    '授权申请已提交，待审批',
    201
  );
});

const approveGrant = asyncHandler(async (req, res) => {
  const grant = await privilegeGrantService.approveGrant({
    grantId: req.params.id,
    operator: operatorOf(req),
  });
  return ApiResponse.success(
    res,
    {
      id: grant._id,
      status: grant.status,
      approvals: grant.approvals.length,
      requiredApprovals: grant.requiredApprovals,
      expiresAt: grant.expiresAt,
    },
    grant.status === 'active' ? '授权已生效' : '已签批，待第二名审批人复核'
  );
});

const rejectGrant = asyncHandler(async (req, res) => {
  const grant = await privilegeGrantService.rejectGrant({
    grantId: req.params.id,
    operator: operatorOf(req),
    reason: req.body && req.body.reason,
  });
  return ApiResponse.success(res, { id: grant._id, status: grant.status }, '授权申请已驳回');
});

const revokeGrant = asyncHandler(async (req, res) => {
  const grant = await privilegeGrantService.revokeGrant({
    grantId: req.params.id,
    operator: operatorOf(req),
    reason: req.body && req.body.reason,
  });
  return ApiResponse.success(res, { id: grant._id, status: grant.status }, '授权已撤销');
});

const listGrants = asyncHandler(async (req, res) => {
  const { page, limit } = normalizePagination(req.query.page, req.query.limit);
  // 审计 2026-11-17 P3：status/userId 此前原样透传给服务层拼 Mongo 查询，唯一的
  // 防线是路由层校验闸——闸被移除或本控制器被复用，`status[$ne]=`、`userId[$gt]=`
  // 这类操作符注入就能直达 find()。这里在控制器层显式收敛：status 限定枚举白名单、
  // userId 限定 ObjectId 形态；白名单/形态之外一律按「未传该筛选项」处理（undefined），
  // 合法输入的行为不变。宁丢一个筛选项，不透传一个不可信形状。
  const status = PRIVILEGE_GRANT_STATUSES.includes(req.query.status) ? req.query.status : undefined;
  const userId =
    typeof req.query.userId === 'string' && OBJECT_ID_SHAPE_RE.test(req.query.userId)
      ? req.query.userId
      : undefined;
  const { items, total } = await privilegeGrantService.listGrants({
    status,
    userId,
    page,
    limit,
  });
  return ApiResponse.paginated(
    res,
    items,
    {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit) || 0,
    },
    '获取临时授权列表成功'
  );
});

const getReviewSummary = asyncHandler(async (req, res) => {
  const summary = await accessReviewService.reviewSummary({});
  const overdue = await accessReviewService.listOverdueGrants({ limit: 50 });
  return ApiResponse.success(res, { ...summary, overdueGrants: overdue }, '获取权限复核汇总成功');
});

module.exports = {
  createGrant,
  approveGrant,
  rejectGrant,
  revokeGrant,
  listGrants,
  getReviewSummary,
};
