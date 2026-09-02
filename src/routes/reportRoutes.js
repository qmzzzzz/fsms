/**
 * 报表统计路由
 * 提供系统各模块的统计分析和数据导出
 */

const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { authenticate, checkPermission } = require('../middleware');
const { strictLimiter } = require('../middleware/rateLimit');

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
 */
router.get(
  '/export',
  authenticate,
  checkPermission('report:export'),
  strictLimiter,
  reportController.exportReport
);

module.exports = router;
