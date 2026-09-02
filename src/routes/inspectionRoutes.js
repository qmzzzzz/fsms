/**
 * 巡检管理路由
 * 巡检计划、执行、审核流程
 */

const express = require('express');
const router = express.Router();
const inspectionController = require('../controllers/inspectionController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { consumeValidation } = require('../middleware/validateQuery');

// P3-17：列表 query 枚举与类型校验。status/inspectionType 拼错时原先
// 静默返回空集，assignedTo 传非 ObjectId 则触发 CastError → 400（错误语义模糊）
// values:'falsy'：前端未选筛选时会把空串带上（status=），optional() 默认只跳过
// undefined，空串会落入 isIn/isMongoId/isISO8601 误判 400；空串语义即「不筛选」
const listQueryValidation = [
  query('status')
    .optional({ values: 'falsy' })
    .isIn(['pending', 'in_progress', 'completed', 'overdue', 'cancelled'])
    .withMessage('无效的巡检状态'),
  query('inspectionType')
    .optional({ values: 'falsy' })
    .isIn(['daily', 'weekly', 'monthly', 'quarterly', 'annual', 'special'])
    .withMessage('无效的巡检类型'),
  query('assignedTo').optional({ values: 'falsy' }).isMongoId().withMessage('执行人 ID 格式无效'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
  query('startDate').optional({ values: 'falsy' }).isISO8601().withMessage('开始日期格式无效'),
  query('endDate').optional({ values: 'falsy' }).isISO8601().withMessage('结束日期格式无效'),
];

// 验证规则
const createValidation = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('巡检标题不能为空')
    .isLength({ max: 200 })
    .withMessage('标题不能超过 200 个字符'),
  body('inspectionType')
    .isIn(['daily', 'weekly', 'monthly', 'quarterly', 'annual', 'special'])
    .withMessage('无效的巡检类型'),
  body('planStartTime').isISO8601().withMessage('请提供有效的计划开始时间'),
  body('planEndTime').isISO8601().withMessage('请提供有效的计划结束时间'),
  body('checkItems').isArray({ min: 1 }).withMessage('至少需要一个检查项目'),
  body('checkItems.*.name')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('检查项目名称不能超过 100 个字符'),
  body('checkItems.*.standard')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('检查标准不能超过 200 个字符'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('描述不能超过 500 个字符'),
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
  body('priority')
    .optional()
    .isString()
    .isLength({ max: 20 })
    .withMessage('优先级不能超过 20 个字符'),
  // 执行人与设备均为模型中的 ObjectId 数组（Inspection.assignedTo / Inspection.devices）
  body('assignedTo').optional().isArray().withMessage('执行人列表必须是数组'),
  body('assignedTo.*').isMongoId().withMessage('执行人 ID 格式无效'),
  body('devices').optional().isArray().withMessage('设备列表必须是数组'),
  body('devices.*').isMongoId().withMessage('设备 ID 格式无效'),
  body('locations').optional().isArray(),
  body('locations.*.building')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼栋不能超过 100 个字符'),
  body('locations.*.floor')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼层不能超过 100 个字符'),
  body('locations.*.area')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('区域不能超过 100 个字符'),
  // P2-19：跨字段校验，与 updateValidation 同口径
  body('planEndTime').custom((value, { req }) => {
    if (!value || !req.body.planStartTime) return true;
    if (new Date(value) <= new Date(req.body.planStartTime)) {
      throw new Error('计划结束时间必须晚于开始时间');
    }
    return true;
  }),
];

// 更新巡检计划：字段全部可选，口径与创建一致
const updateValidation = [
  body('title').optional().trim().isLength({ max: 200 }).withMessage('标题不能超过 200 个字符'),
  body('inspectionType')
    .optional()
    .isIn(['daily', 'weekly', 'monthly', 'quarterly', 'annual', 'special'])
    .withMessage('无效的巡检类型'),
  body('planStartTime').optional().isISO8601().withMessage('请提供有效的计划开始时间'),
  body('planEndTime').optional().isISO8601().withMessage('请提供有效的计划结束时间'),
  body('checkItems').optional().isArray({ min: 1 }).withMessage('至少需要一个检查项目'),
  body('checkItems.*.name')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('检查项目名称不能超过 100 个字符'),
  body('checkItems.*.standard')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('检查标准不能超过 200 个字符'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('描述不能超过 500 个字符'),
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
  body('priority')
    .optional()
    .isString()
    .isLength({ max: 20 })
    .withMessage('优先级不能超过 20 个字符'),
  body('locations').optional().isArray(),
  body('locations.*.building')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼栋不能超过 100 个字符'),
  body('locations.*.floor')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼层不能超过 100 个字符'),
  body('locations.*.area')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('区域不能超过 100 个字符'),
  // 与 createValidation 同口径：updateInspection 同样允许更新这两个数组字段，
  // 缺校验时非 ObjectId 元素会以 CastError 形式回显，悬空引用也无存在性拦截
  body('assignedTo').optional().isArray().withMessage('执行人列表必须是数组'),
  body('assignedTo.*').isMongoId().withMessage('执行人 ID 格式无效'),
  body('devices').optional().isArray().withMessage('设备列表必须是数组'),
  body('devices.*').isMongoId().withMessage('设备 ID 格式无效'),
  // P2-19：跨字段校验。原先两端只各自验 ISO8601，倒置的时间窗（end < start）
  // 可直接落库，使 dashboard/report 的 overdue 与完成率永久失真
  body('planEndTime').custom((value, { req }) => {
    if (!value || !req.body.planStartTime) return true;
    if (new Date(value) <= new Date(req.body.planStartTime)) {
      throw new Error('计划结束时间必须晚于开始时间');
    }
    return true;
  }),
];

const completeValidation = [
  body('result').isIn(['normal', 'abnormal', 'partial']).withMessage('无效的巡检结果'),
  // findings 与 Inspection 模型的子文档数组对齐：此前路由按字符串校验、
  // 服务端按 Array.isArray 消费，导致合法提交被静默丢弃
  body('findings')
    .optional()
    .isArray({ max: 100 })
    .withMessage('巡检发现必须是数组且不超过 100 条'),
  body('findings.*.deviceId')
    .optional({ values: 'falsy' })
    .isMongoId()
    .withMessage('发现关联的设备 ID 格式无效'),
  body('findings.*.issue')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('问题描述不能超过 500 个字符'),
  body('findings.*.severity')
    .optional()
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('严重程度无效'),
  body('findings.*.photo')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('照片地址不能超过 500 个字符'),
  body('findings.*.suggestion')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('整改建议不能超过 500 个字符'),
  body('location').optional().trim().isLength({ max: 100 }).withMessage('地点不能超过 100 个字符'),
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
];

// :id 路径参数必须是合法 ObjectId，防止非法 id 触发 CastError → 500
const mongoIdParamValidation = [param('id').isMongoId().withMessage('无效的巡检记录ID')];

/**
 * @route   GET /api/inspections
 * @desc    获取巡检列表
 * @access  Private [inspection:read]
 */
router.get(
  '/',
  authenticate,
  checkPermission('inspection:read'),
  listQueryValidation,
  consumeValidation(),
  inspectionController.getInspections
);

/**
 * @route   GET /api/inspections/stats
 * @desc    获取巡检统计
 * @access  Private [inspection:read]
 */
router.get(
  '/stats',
  authenticate,
  checkPermission('inspection:read'),
  inspectionController.getInspectionStats
);

/**
 * @route   GET /api/inspections/:id
 * @desc    获取巡检详情
 * @access  Private [inspection:read]
 */
router.get(
  '/:id',
  authenticate,
  checkPermission('inspection:read'),
  mongoIdParamValidation,
  inspectionController.getInspectionById
);

/**
 * @route   POST /api/inspections
 * @desc    创建巡检计划
 * @access  Private [inspection:create]
 */
router.post(
  '/',
  authenticate,
  checkPermission('inspection:create'),
  createValidation,
  inspectionController.createInspection
);

/**
 * @route   PUT /api/inspections/:id
 * @desc    更新巡检计划
 * @access  Private [inspection:create]
 */
router.put(
  '/:id',
  authenticate,
  checkPermission('inspection:create'),
  mongoIdParamValidation,
  updateValidation,
  inspectionController.updateInspection
);

/**
 * @route   PUT /api/inspections/:id/start
 * @desc    开始执行巡检
 * @access  Private [inspection:execute]
 */
router.put(
  '/:id/start',
  authenticate,
  checkPermission('inspection:execute'),
  mongoIdParamValidation,
  inspectionController.startInspection
);

/**
 * @route   PUT /api/inspections/:id/complete
 * @desc    提交巡检结果
 * @access  Private [inspection:execute]
 */
router.put(
  '/:id/complete',
  authenticate,
  checkPermission('inspection:execute'),
  mongoIdParamValidation,
  completeValidation,
  inspectionController.completeInspection
);

// P3-16：review 此前零 body 校验——reviewComment 超长以英文 ValidationError
// 回显（Mongoose maxlength 消息），result 枚举错误值直写库
const reviewValidation = [
  body('result').optional().isIn(['approved', 'rejected']).withMessage('无效的审核结果'),
  body('reviewComment')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('审核意见不能超过 500 个字符'),
];

/**
 * @route   PUT /api/inspections/:id/review
 * @desc    审核巡检结果
 * @access  Private [inspection:review]
 */
router.put(
  '/:id/review',
  authenticate,
  checkPermission('inspection:review'),
  mongoIdParamValidation,
  reviewValidation,
  inspectionController.reviewInspection
);

/**
 * @route   PUT /api/inspections/:id/cancel
 * @desc    取消巡检
 * @access  Private [inspection:create]
 */
router.put(
  '/:id/cancel',
  authenticate,
  checkPermission('inspection:create'),
  mongoIdParamValidation,
  inspectionController.cancelInspection
);

/**
 * @route   DELETE /api/inspections/:id
 * @desc    删除巡检
 * @access  Private [inspection:delete]
 */
router.delete(
  '/:id',
  authenticate,
  checkPermission('inspection:delete'),
  mongoIdParamValidation,
  inspectionController.deleteInspection
);

module.exports = router;
