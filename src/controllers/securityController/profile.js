/**
 * 安全管理控制器 · 撞库画像读口（ADR-013「P2 情报」）
 *
 * 读档与 /alerts、/audit-logs 同源：security:audit + 二次验证票据，数据范围同样交
 * applyAuditDataScope 收口，不新增权限码。**已知且有意接受的副作用**：蜜罐审计行不带 userId
 * （陷阱账号不是真实业务主体），而 self / department 两档的谓词正是按 userId 过滤 —— 这两档
 * 拿到的画像恒为空。空表不许冒充「没有攻击」：出口回传 minSamples 与调用者自己的
 * dataScopeType（调用者的范围不是秘密：/api/auth/me 已经在回传它）。
 * 本文件不得直接 require 任何 src/models/ 路径（layeringRatchet 对新控制器文件零容忍）。
 */

const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { isValidDateParam } = require('../../utils/helpers');
const { applyAuditDataScope } = require('../../services/auditScopeFilter');
const { MIN_SAMPLES } = require('../../constants/stuffingProfile');
const { buildProfile } = require('../../services/stuffingProfile');

const BUSINESS_DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * businessDay 只收 YYYY-MM-DD：businessDayBounds 对坏形状会**静默回落成今天**，那会把
 * 「参数写错」变成一份看起来正常的画像，所以形状在这里判死。只有**整个参数缺席**才算「缺省＝今天」；
 * `?businessDay=`（给了但是空串）与数组形态都按坏形状回 400 —— 与 alarmController 的日期入参口径同向。
 */
const readBusinessDay = (value) => {
  if (value === undefined) {
    return { ok: true, businessDay: undefined };
  }
  if (typeof value !== 'string' || !BUSINESS_DAY_RE.test(value) || !isValidDateParam(value)) {
    return { ok: false };
  }
  return { ok: true, businessDay: value };
};

/**
 * GET /api/security/stuffing-profile —— 撞库画像（按来源段聚合）
 */
const getStuffingProfile = asyncHandler(async (req, res) => {
  try {
    const day = readBusinessDay(req.query.businessDay);
    if (!day.ok) return ApiResponse.codeError(res, 'DATE_PARAM_INVALID');
    const { query: scopeFilter, dataScope } = await applyAuditDataScope({}, req.user.userId);
    const profile = await buildProfile({ businessDay: day.businessDay, scopeFilter });
    return ApiResponse.successWithMeta(
      res,
      profile.entries,
      {
        businessDay: profile.businessDay,
        windowStart: profile.windowStart,
        windowEnd: profile.windowEnd,
        expired: profile.expired,
        droppedUnparsable: profile.droppedUnparsable,
        droppedBelowMin: profile.droppedBelowMin,
        minSamples: MIN_SAMPLES,
        count: profile.entries.length,
        dataScopeType: dataScope.type,
      },
      '获取成功'
    );
  } catch (error) {
    if (error.isApiError) throw error;
    logger.error(`撞库画像查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'AUDIT_QUERY_FAILED');
  }
});

module.exports = { getStuffingProfile };
