/**
 * 巡检管理路由
 * 巡检计划、执行、审核流程
 */

const express = require('express');
const router = express.Router();
const inspectionController = require('../controllers/inspectionController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { mustBeString } = require('../utils/validationRules');
const { consumeValidation } = require('../middleware/validateQuery');
// findings.*.severity 的取值全集与 models/Inspection.js 的 enum 同一份（F-149）：
// 校验层与写入层各写一遍字面量时，单侧增删就会让两边对同一个值给出相反结论
const {
  INSPECTION_FINDING_SEVERITIES,
  INSPECTION_TYPES,
  INSPECTION_STATUSES,
  INSPECTION_RESULTS,
  INSPECTION_REVIEW_RESULTS,
} = require('../constants/inspection');

// P3-17：列表 query 枚举与类型校验。status/inspectionType 拼错时原先
// 静默返回空集，assignedTo 传非 ObjectId 则触发 CastError → 400（错误语义模糊）
// values:'falsy'：前端未选筛选时会把空串带上（status=），optional() 默认只跳过
// undefined，空串会落入 isIn/isMongoId/isISO8601 误判 400；空串语义即「不筛选」
const listQueryValidation = [
  query('status')
    .optional({ values: 'falsy' })
    .isIn(INSPECTION_STATUSES)
    .withMessage('无效的巡检状态'),
  query('inspectionType')
    .optional({ values: 'falsy' })
    .isIn(INSPECTION_TYPES)
    .withMessage('无效的巡检类型'),
  query('assignedTo').optional({ values: 'falsy' }).isMongoId().withMessage('执行人 ID 格式无效'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
  query('startDate').optional({ values: 'falsy' }).isISO8601().withMessage('开始日期格式无效'),
  query('endDate').optional({ values: 'falsy' }).isISO8601().withMessage('结束日期格式无效'),
];

// 验证规则
/**
 * 子文档/引用数组的统一长度上限
 *
 * 此前 checkItems / devices / locations / assignedTo 四个数组**完全没有上界**：
 * 1MB 的 body 限制下，一次 `inspection:create` 就能塞进上万个元素，
 * 落库后每次列表/详情读取都要对它们做 `.populate()`（devices→deviceCode/name/type/location，
 * assignedTo→username/realName），于是"一次写入"变成"每次读都付代价"——
 * 单个资产记录膨胀到 16MB 上限后连保存都做不了（同 M5 家族）。
 *
 * 取值依据：findings 已经钉在 100（本次不放宽既有上限），
 * 而 200 覆盖现实中最大的巡检计划（整栋楼的点位），
 * 同时把 populate 扇出与文档体积压在可预测的量级。
 * 注：真正的下界仍应由模型层兜住（见技术文档 6-P 的 M5 待办），这里是 API 边界的第一道。
 */
const MAX_SUBDOC_ITEMS = 200;

// create 与 update 对这一段（checkItems 子文档字段、描述/备注/优先级自由文本）
// 的口径本就要求一致，此前靠两份复制粘贴维持 ⇒ 收敛成一份共享链。
const subdocAndFreeTextValidation = [
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
  mustBeString('description', '描述'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('描述不能超过 500 个字符'),
  mustBeString('remark', '备注'),
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
  body('priority')
    .optional()
    .isString()
    .isLength({ max: 20 })
    .withMessage('优先级不能超过 20 个字符'),
];

const createValidation = [
  mustBeString('title', '巡检标题'),
  body('title')
    .trim()
    .notEmpty()
    .withMessage('巡检标题不能为空')
    .isLength({ max: 200 })
    .withMessage('标题不能超过 200 个字符'),
  body('inspectionType').isIn(INSPECTION_TYPES).withMessage('无效的巡检类型'),
  body('planStartTime').isISO8601().withMessage('请提供有效的计划开始时间'),
  body('planEndTime').isISO8601().withMessage('请提供有效的计划结束时间'),
  body('checkItems')
    .isArray({ min: 1, max: MAX_SUBDOC_ITEMS })
    .withMessage(`检查项目数须在 1-${MAX_SUBDOC_ITEMS} 之间`),
  ...subdocAndFreeTextValidation,
  // 执行人与设备均为模型中的 ObjectId 数组（Inspection.assignedTo / Inspection.devices）
  body('assignedTo')
    .optional()
    .isArray({ max: MAX_SUBDOC_ITEMS })
    .withMessage(`执行人列表不超过 ${MAX_SUBDOC_ITEMS} 人`),
  body('assignedTo.*').isMongoId().withMessage('执行人 ID 格式无效'),
  body('devices')
    .optional()
    .isArray({ max: MAX_SUBDOC_ITEMS })
    .withMessage(`设备列表不超过 ${MAX_SUBDOC_ITEMS} 台`),
  body('devices.*').isMongoId().withMessage('设备 ID 格式无效'),
  body('locations')
    .optional()
    .isArray({ max: MAX_SUBDOC_ITEMS })
    .withMessage(`区域列表不超过 ${MAX_SUBDOC_ITEMS} 处`),
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
  mustBeString('title', '巡检标题'),
  body('title').optional().trim().isLength({ max: 200 }).withMessage('标题不能超过 200 个字符'),
  body('inspectionType').optional().isIn(INSPECTION_TYPES).withMessage('无效的巡检类型'),
  body('planStartTime').optional().isISO8601().withMessage('请提供有效的计划开始时间'),
  body('planEndTime').optional().isISO8601().withMessage('请提供有效的计划结束时间'),
  body('checkItems')
    .optional()
    .isArray({ min: 1, max: MAX_SUBDOC_ITEMS })
    .withMessage(`检查项目数须在 1-${MAX_SUBDOC_ITEMS} 之间`),
  ...subdocAndFreeTextValidation,
  body('locations')
    .optional()
    .isArray({ max: MAX_SUBDOC_ITEMS })
    .withMessage(`区域列表不超过 ${MAX_SUBDOC_ITEMS} 处`),
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
  body('assignedTo')
    .optional()
    .isArray({ max: MAX_SUBDOC_ITEMS })
    .withMessage(`执行人列表不超过 ${MAX_SUBDOC_ITEMS} 人`),
  body('assignedTo.*').isMongoId().withMessage('执行人 ID 格式无效'),
  body('devices')
    .optional()
    .isArray({ max: MAX_SUBDOC_ITEMS })
    .withMessage(`设备列表不超过 ${MAX_SUBDOC_ITEMS} 台`),
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
  body('result').isIn(INSPECTION_RESULTS).withMessage('无效的巡检结果'),
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
  mustBeString('findings.*.issue', '问题描述'),
  body('findings.*.issue')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('问题描述不能超过 500 个字符'),
  body('findings.*.severity')
    .optional()
    .isIn(INSPECTION_FINDING_SEVERITIES)
    .withMessage('严重程度无效'),
  mustBeString('findings.*.photo', '照片地址'),
  body('findings.*.photo')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('照片地址不能超过 500 个字符'),
  mustBeString('findings.*.suggestion', '整改建议'),
  body('findings.*.suggestion')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('整改建议不能超过 500 个字符'),
  mustBeString('location', '地点'),
  body('location').optional().trim().isLength({ max: 100 }).withMessage('地点不能超过 100 个字符'),
  mustBeString('remark', '备注'),
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
  // 2026-09-26 审计 Top5：param 链此前挂而不消费（死校验链）。applyObjectIdParams
  // 的 router.param 兜底会先对非法 id 400，本消费层正常时收不到错误——挂上是为了让
  // 「校验 → 消费 → 控制器」在同处成立，兜底移除后不裸奔
  consumeValidation(),
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
  // SCOPE-EXEMPT: 创建动作无「他人资源」可越权——归属字段 assignedTo 由路由校验器
  // 限定为 ObjectId 数组白名单（inspectionRoutes.js:69-70），服务层不接受其他归属来源。
  // 读取/修改已存在巡检的范围判定见 PUT /:id 等路由（isInspectionInScope）
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
//
// L-05 修复：原校验写的是 body('result')，而控制器消费的是 req.body.reviewResult
//（见 inspectionController 的 review 处理）→ 该校验对真实字段**完全不生效**，
// 注释声称的"已修复"实际未落地。字段名已更正为 reviewResult。
const reviewValidation = [
  body('reviewResult').optional().isIn(INSPECTION_REVIEW_RESULTS).withMessage('无效的审核结果'),
  mustBeString('reviewComment', '审核意见'),
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
 * 取消巡检的 reason
 *
 * 兄弟端点 review 的 reviewComment 早就有 500 上限（见上方 reviewValidation，
 * P3-16），cancel 却一条规则都没挂：控制器 `const { reason } = req.body` 原样
 * 交给 InspectionService 写进 `executionLog[].remark`。
 * Inspection 模型对该字段确实写了 maxlength: 500，但取消走的是
 * `findOneAndUpdate`——默认不跑校验器，所以那条上限在这条路上是装饰：
 * 超长值原样入库，$slice 只裁条数不裁长度，200 条 MB 级字符串可以把整个文档
 * 顶过 16MB 上限，此后这条巡检记录连保存都做不了（永久卡死）。
 *
 * `.isString()` 前置：express-validator 的 trim/isLength 会把值 stringify 后
 * **写回 req.body**，对象 `{}` 因此变成 `'[object Object]'` 并顺利通过长度校验，
 * 最后入库的就是这个字面量（与 securityRoutes 同一口径）。
 */
const cancelValidation = [
  body('reason')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('取消原因必须为字符串')
    .trim()
    .isLength({ max: 500 })
    .withMessage('取消原因不能超过 500 个字符'),
];

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
  cancelValidation,
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
