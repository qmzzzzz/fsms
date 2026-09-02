/**
 * 火警报警管理路由
 */

const express = require('express');
const router = express.Router();
const alarmController = require('../controllers/alarmController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { consumeValidation } = require('../middleware/validateQuery');

// P3-17：列表 query 枚举校验。原先 status/level/alarmType 零校验直入
// Service 的查询条件：拼错的值不会报错，只会静默返回空集——
// 调用方无法区分「筛选条件写错」与「确实没有数据」。
// values:'falsy'：前端未选筛选时空串（status=）语义为「不筛选」，不应 400
const listQueryValidation = [
  query('status')
    .optional({ values: 'falsy' })
    .isIn(['pending', 'processing', 'resolved', 'false_alarm', 'cancelled'])
    .withMessage('无效的报警状态'),
  query('level')
    .optional({ values: 'falsy' })
    .isIn(['info', 'warning', 'critical', 'emergency'])
    .withMessage('无效的报警级别'),
  query('alarmType')
    .optional({ values: 'falsy' })
    .isIn(['smoke', 'temp_abnormal', 'manual_button', 'phone_report', 'patrol_find', 'other'])
    .withMessage('无效的报警类型'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
  query('startDate').optional({ values: 'falsy' }).isISO8601().withMessage('开始日期格式无效'),
  query('endDate').optional({ values: 'falsy' }).isISO8601().withMessage('结束日期格式无效'),
];

// 验证规则
const reportAlarmValidation = [
  body('alarmType')
    .isIn(['smoke', 'temp_abnormal', 'manual_button', 'phone_report', 'patrol_find', 'other'])
    .withMessage('无效的报警类型'),
  body('description')
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('报警描述长度应为 1-500 个字符'),
  body('location').optional().isObject(),
  body('location.building')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼栋不能超过 100 个字符'),
  body('location.floor')
    .optional()
    .isString()
    .isLength({ max: 50 })
    .withMessage('楼层不能超过 50 个字符'),
  body('location.room')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('房间不能超过 100 个字符'),
  body('location.detail')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('详细位置不能超过 200 个字符'),
  body('deviceId').optional().isMongoId().withMessage('设备 ID 格式无效'),
  body('level').optional().isIn(['info', 'warning', 'critical', 'emergency']),
  body('reporter.name')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('上报人姓名不能超过 50 个字符'),
  body('reporter.phone')
    .optional()
    .trim()
    .isLength({ max: 20 })
    .withMessage('上报人电话不能超过 20 个字符'),
];

const dispatchValidation = [body('handlerId').optional().isMongoId()];

const resolveValidation = [
  body('handleResult')
    .trim()
    .isLength({ min: 1, max: 1000 })
    .withMessage('处理结果描述长度应为 1-1000 个字符'),
  body('cause').optional().isIn(['fire', 'false_alarm', 'equipment_fault', 'test', 'unknown']),
];

// :id 路径参数必须是合法 ObjectId，防止非法 id 触发 CastError → 500
const mongoIdParamValidation = [param('id').isMongoId().withMessage('无效的报警记录ID')];

// 路由定义
/**
 * @route   GET /api/alarms
 * @desc    获取报警列表
 * @access  Private [alarm:read]
 */
router.get(
  '/',
  authenticate,
  checkPermission('alarm:read'),
  listQueryValidation,
  consumeValidation(),
  alarmController.getAlarms
);

/**
 * @route   GET /api/alarms/stats
 * @desc    获取报警统计信息
 * @access  Private [alarm:read]
 */
router.get('/stats', authenticate, checkPermission('alarm:read'), alarmController.getAlarmStats);

/**
 * @route   GET /api/alarms/:id
 * @desc    获取报警详情
 * @access  Private [alarm:read]
 */
router.get(
  '/:id',
  authenticate,
  checkPermission('alarm:read'),
  mongoIdParamValidation,
  alarmController.getAlarmById
);

/**
 * @route   POST /api/alarms/report
 * @desc    上报火警（手动报警）
 * @access  Private [alarm:create]
 */
router.post(
  '/report',
  authenticate,
  checkPermission('alarm:create'),
  reportAlarmValidation,
  alarmController.reportAlarm
);

/**
 * @route   PUT /api/alarms/:id/dispatch
 * @desc    指派处理人
 * @access  Private [alarm:dispatch]
 */
router.put(
  '/:id/dispatch',
  authenticate,
  checkPermission('alarm:dispatch'),
  [...mongoIdParamValidation, ...dispatchValidation],
  alarmController.dispatchAlarm
);

/**
 * @route   PUT /api/alarms/:id/arrive
 * @desc    到达现场登记
 * @access  Private [alarm:handle]
 */
router.put(
  '/:id/arrive',
  authenticate,
  checkPermission('alarm:handle'),
  mongoIdParamValidation,
  alarmController.arriveAtScene
);

/**
 * @route   PUT /api/alarms/:id/resolve
 * @desc    处理完成
 * @access  Private [alarm:handle]
 */
router.put(
  '/:id/resolve',
  authenticate,
  checkPermission('alarm:handle'),
  [...mongoIdParamValidation, ...resolveValidation],
  alarmController.resolveAlarm
);

/**
 * @route   PUT /api/alarms/:id/false-alarm
 * @desc    标记为误报
 * @access  Private [alarm:handle]
 */
router.put(
  '/:id/false-alarm',
  authenticate,
  checkPermission('alarm:handle'),
  mongoIdParamValidation,
  alarmController.markAsFalseAlarm
);

/**
 * @route   PUT /api/alarms/:id/cancel
 * @desc    取消报警
 * @access  Private [alarm:handle]
 */
router.put(
  '/:id/cancel',
  authenticate,
  checkPermission('alarm:handle'),
  mongoIdParamValidation,
  alarmController.cancelAlarm
);

module.exports = router;
