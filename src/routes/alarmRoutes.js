/**
 * 火警报警管理路由
 */

const express = require('express');
const router = express.Router();
const alarmController = require('../controllers/alarmController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { mustBeString, coordinatesRules } = require('../utils/validationRules');
const { consumeValidation } = require('../middleware/validateQuery');
const { ALARM_LEVELS, ALARM_TYPES, ALARM_STATUSES, ALARM_CAUSES } = require('../constants/alarm');

// P3-17：列表 query 枚举校验。原先 status/level/alarmType 零校验直入
// Service 的查询条件：拼错的值不会报错，只会静默返回空集——
// 调用方无法区分「筛选条件写错」与「确实没有数据」。
// values:'falsy'：前端未选筛选时空串（status=）语义为「不筛选」，不应 400
// F-142：三组清单引用 constants/alarm.js，与 model 的 enum 同一份（原先各抄一份，
// 窄于 schema 的那份会把合法值判成非法）。F-158 把 cause 也接上同一根线（当时漏扫）。
const listQueryValidation = [
  query('status').optional({ values: 'falsy' }).isIn(ALARM_STATUSES).withMessage('无效的报警状态'),
  query('level').optional({ values: 'falsy' }).isIn(ALARM_LEVELS).withMessage('无效的报警级别'),
  query('alarmType').optional({ values: 'falsy' }).isIn(ALARM_TYPES).withMessage('无效的报警类型'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
  query('startDate').optional({ values: 'falsy' }).isISO8601().withMessage('开始日期格式无效'),
  query('endDate').optional({ values: 'falsy' }).isISO8601().withMessage('结束日期格式无效'),
];

// 验证规则
const reportAlarmValidation = [
  body('alarmType').isIn(ALARM_TYPES).withMessage('无效的报警类型'),
  mustBeString('description', '报警描述'),
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
  ...coordinatesRules('location'),
  body('deviceId').optional().isMongoId().withMessage('设备 ID 格式无效'),
  body('level').optional().isIn(ALARM_LEVELS),
  mustBeString('reporter.name', '上报人姓名'),
  body('reporter.name')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('上报人姓名不能超过 50 个字符'),
  mustBeString('reporter.phone', '上报人电话'),
  body('reporter.phone')
    .optional()
    .trim()
    .isLength({ max: 20 })
    .withMessage('上报人电话不能超过 20 个字符'),
];

const dispatchValidation = [body('handlerId').optional().isMongoId()];

const resolveValidation = [
  mustBeString('handleResult', '处理结果描述'),
  body('handleResult')
    .trim()
    .isLength({ min: 1, max: 1000 })
    .withMessage('处理结果描述长度应为 1-1000 个字符'),
  body('cause').optional().isIn(ALARM_CAUSES),
];

// 误报标记与取消两条路的 reason 此前一个规则都没有：
//   · false-alarm 写 FireAlarm.handleResult，schema 的 maxlength:1000 在
//    findOneAndUpdate 路径上默认**不生效**（Mongoose 的 update 不跑校验），
//    所以超长值是原样落库、不是报 400；
//  · cancel 写 processLog[].remark，而 remark 在 schema 里连上限都没有。
// 上限与上面 resolveValidation 的 handleResult 同值（同一份"处理类描述"口径）。
const handleReasonValidation = [
  body('reason')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('原因说明最多 1000 个字符'),
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
  [...mongoIdParamValidation, ...handleReasonValidation],
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
  [...mongoIdParamValidation, ...handleReasonValidation],
  alarmController.cancelAlarm
);

module.exports = router;
