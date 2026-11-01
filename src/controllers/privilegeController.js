/**
 * 临时权限授予控制器：HTTP 编排与入参校验，业务规则全部在 privilegeGrantService。
 */

'use strict';

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');
const privilegeGrantService = require('../services/privilegeGrantService');
const accessReviewService = require('../services/accessReviewService');

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
  const { items, total } = await privilegeGrantService.listGrants({
    status: req.query.status,
    userId: req.query.userId,
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
