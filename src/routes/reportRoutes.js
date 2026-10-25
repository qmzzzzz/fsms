/**
 * 报表统计路由
 * 提供系统各模块的统计分析和数据导出
 */

const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { authenticate, checkPermission, requireReAuthentication } = require('../middleware');
const { strictLimiter, reauthLimiter, reauthUserLimiter } = require('../middleware/rateLimit');
const ApiResponse = require('../utils/apiResponse');
const { PII_NAME_EXPORT_TYPES } = require('../services/reportExportService');

/**
 * GET 导出只有掩码档（L-17）
 *
 * 未脱敏导出改为 POST /export/pii + 二次验证；若 GET 仍按 pii:export 放行全文，
 * 拿到口令的会话就能绕过步进验证直接批量拉真实姓名，两条路径的强度会不一致。
 * 置位后由 reportController.resolveExportMasking 统一消费，非 PII 类型不受影响。
 */
const forceMaskPii = (req, res, next) => {
  req.forceMaskPii = true;
  next();
};

/**
 * POST 未脱敏导出仅对携带真实姓名的报表开放
 *
 * devices/audit 没有姓名列，走这条路径只会白白消耗一次二次验证；
 * 非法类型放在步进验证**之前**拒绝，避免"注定 400"的请求产生凭据侧副作用
 * （与 securityRoutes 的 dataType 白名单同一顺序纪律）。
 */
const requirePiiExportType = (req, res, next) => {
  const raw = req.query.type;
  const type = typeof raw === 'string' && raw ? raw : 'alarms';
  if (!PII_NAME_EXPORT_TYPES.includes(type)) {
    return ApiResponse.codeError(res, 'REPORT_TYPE_UNSUPPORTED', {
      message: `未脱敏导出仅支持 ${PII_NAME_EXPORT_TYPES.join(' / ')}`,
    });
  }
  next();
};

/**
 * @route   GET /api/reports/dashboard
 * @desc    获取综合仪表盘统计
 * @access  Private [report:read]
 */
router.get(
  '/dashboard',
  authenticate,
  checkPermission('report:read'),
  reportController.getDashboardStats
);

/**
 * @route   GET /api/reports/devices
 * @desc    获取设备报表
 * @access  Private [report:read]
 */
router.get(
  '/devices',
  authenticate,
  checkPermission('report:read'),
  reportController.getDeviceReport
);

/**
 * @route   GET /api/reports/alarms
 * @desc    获取报警报表
 * @access  Private [report:read]
 */
router.get(
  '/alarms',
  authenticate,
  checkPermission('report:read'),
  reportController.getAlarmReport
);

/**
 * @route   GET /api/reports/inspections
 * @desc    获取巡检报表
 * @access  Private [report:read]
 */
router.get(
  '/inspections',
  authenticate,
  checkPermission('report:read'),
  reportController.getInspectionReport
);

/**
 * @route   GET /api/reports/export
 * @desc    导出报表数据（挂严格限流：导出为重资源+批量数据出口，防滥用）
 * @access  Private [report:export]
 *
 * L-17：本路径**恒为掩码档**。未脱敏导出只走下方 POST /export/pii
 * （pii:export + 二次验证），避免持会话者绕过步进验证从 GET 批量读取真实姓名。
 */
router.get(
  '/export',
  authenticate,
  checkPermission('report:export'),
  strictLimiter,
  forceMaskPii,
  reportController.exportReport
);

/**
 * @route   POST /api/reports/export/pii
 * @desc    导出未脱敏报表（真实姓名），需 pii:export + 当前口令或 MFA 二次验证
 * @access  Private [report:export + pii:export + reauth]
 *
 * 用 POST 而不是给 GET 加"带凭据"分支：GET 会把密码/MFA 码写进 URL
 * （访问日志、代理日志、Referer），且定时导出任务没有交互因子。
 * 查询参数与 GET 导出完全一致，控制器复用同一编排。
 */
router.post(
  '/export/pii',
  authenticate,
  requirePiiExportType,
  // 与 /security/view-sensitive 同口径：凭据型端点必须挂独立桶的限流，
  // 且限流置于权限查询与口令比对之前。组合桶含 IP，userId 桶堵住假 IP 绕配额。
  strictLimiter,
  reauthLimiter,
  reauthUserLimiter,
  checkPermission('report:export'),
  checkPermission('pii:export'),
  requireReAuthentication(),
  reportController.exportReport
);

module.exports = router;
