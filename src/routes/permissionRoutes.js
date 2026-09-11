/**
 * 权限管理路由
 */

const express = require('express');
const router = express.Router();
const permissionController = require('../controllers/permissionController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { consumeValidation } = require('../middleware/validateQuery');

// P3-4/P3-17：列表 query 校验。module/type/status 此前零校验直入 Mongo 过滤
// values:'falsy'：前端未选筛选项时带空串（type=&status=），空串语义为「不筛选」
const listQueryValidation = [
  query('type')
    .optional({ values: 'falsy' })
    .isIn(['menu', 'button', 'api', 'data'])
    .withMessage('无效的权限类型'),
  query('status')
    .optional({ values: 'falsy' })
    .isIn(['active', 'inactive'])
    .withMessage('无效的状态值'),
  query('module').optional().trim().isLength({ max: 50 }).withMessage('模块名不能超过 50 个字符'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 500 }).withMessage('每页数量应在 1-500'),
];

// 路径参数 :id 必须是合法 ObjectId，否则会被 errorHandler 转成"资源 ID 格式无效"
const permissionIdValidation = [param('id').isMongoId().withMessage('权限 ID 格式无效')];

// 验证规则
const createPermissionValidation = [
  body('name').trim().isLength({ min: 1, max: 50 }).withMessage('权限名称长度应为 1-50 个字符'),
  body('code')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('权限编码长度应为 1-50 个字符')
    .matches(/^(\*|[a-z]+):(\*|[a-z_]+)$/)
    .withMessage('权限编码格式应为 module:action，如 user:create 或 user:*')
    // L6：保留通配 *:* 为内置超管专用，运行时不可铸造（纵深防御，分配路径已有拦截）
    .not()
    .equals('*:*')
    .withMessage('不允许创建保留通配权限 *:*'),
  body('type').isIn(['menu', 'button', 'api', 'data']).withMessage('无效的权限类型'),
  body('module')
    .trim()
    .notEmpty()
    .withMessage('所属模块不能为空')
    .isLength({ max: 50 })
    .withMessage('模块名不能超过 50 个字符'),
  body('parent').optional().isMongoId(),
  body('path').optional().trim().isLength({ max: 200 }).withMessage('路径不能超过 200 个字符'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('描述不能超过 200 个字符'),
  body('method').optional().isIn(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*']),
];

// 更新权限：字段全部可选，长度上限对齐 create；
// 控制器 updatePermission 不支持修改 code（前端亦未调用该接口），故移除 code 的无效校验，避免误导
// type/status/parent/sort/method 枚举与 Permission 模型定义对齐，防止非法值直写 DB
const updatePermissionValidation = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('权限名称长度应为 1-50 个字符'),
  body('module')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('所属模块不能为空')
    .isLength({ max: 50 })
    .withMessage('模块名不能超过 50 个字符'),
  body('path').optional().trim().isLength({ max: 200 }).withMessage('路径不能超过 200 个字符'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('描述不能超过 200 个字符'),
  body('type').optional().isIn(['menu', 'button', 'api', 'data']).withMessage('无效的权限类型'),
  body('status').optional().isIn(['active', 'inactive']).withMessage('无效的状态值'),
  // 显式传空值视为清除父级（置顶），仅非空值要求合法 ObjectId
  body('parent').optional({ values: 'falsy' }).isMongoId().withMessage('父级权限 ID 格式无效'),
  body('sort').optional().isInt({ min: 0, max: 9999 }).withMessage('排序值应为 0-9999 的整数'),
  body('method')
    .optional()
    .isIn(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*'])
    .withMessage('无效的请求方法'),
];

const batchCreateValidation = [
  body('permissions')
    .isArray({ min: 1, max: 500 })
    .withMessage('权限列表不能为空且单次最多 500 条'),
  // P2-23：批量路径此前完全没有逐条校验，控制器又不消费 validationResult，
  // 于是 max:500 形同虚设、`*:*` 可被批量铸造、parent 悬空无人拦。
  // 逐条校验与单条创建保持同口径（校验器是唯一事实来源，控制器不再重复实现）。
  body('permissions.*.name')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('权限名称长度应为 1-50 个字符'),
  body('permissions.*.code')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('权限编码长度应为 1-50 个字符')
    .matches(/^(\*|[a-z]+):(\*|[a-z_]+)$/)
    .withMessage('权限编码格式应为 module:action，如 user:create 或 user:*')
    // 与单条创建同口径：保留通配 *:* 为内置超管专用，任何运行时路径都不得铸造
    .not()
    .equals('*:*')
    .withMessage('不允许创建保留通配权限 *:*'),
  body('permissions.*.type').isIn(['menu', 'button', 'api', 'data']).withMessage('无效的权限类型'),
  body('permissions.*.module')
    .trim()
    .notEmpty()
    .withMessage('所属模块不能为空')
    .isLength({ max: 50 })
    .withMessage('模块名不能超过 50 个字符'),
  body('permissions.*.parent')
    .optional({ values: 'falsy' })
    .isMongoId()
    .withMessage('父级权限 ID 格式无效'),
  body('permissions.*.path')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('路径不能超过 200 个字符'),
  body('permissions.*.description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('描述不能超过 200 个字符'),
  body('permissions.*.method')
    .optional()
    .isIn(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*'])
    .withMessage('无效的请求方法'),
  body('permissions.*.sort')
    .optional()
    .isInt({ min: 0, max: 9999 })
    .withMessage('排序值应为 0-9999 的整数'),
];

// 路由定义
/**
 * @route   GET /api/permissions
 * @desc    获取权限列表
 * @access  Private [permission:read]
 */
router.get(
  '/',
  authenticate,
  checkPermission('permission:read'),
  listQueryValidation,
  consumeValidation(),
  permissionController.getPermissions
);

/**
 * @route   GET /api/permissions/:id
 * @desc    获取权限详情
 * @access  Private [permission:read]
 */
router.get(
  '/:id',
  authenticate,
  checkPermission('permission:read'),
  permissionIdValidation,
  permissionController.getPermissionById
);

/**
 * @route   POST /api/permissions
 * @desc    创建权限
 * @access  Private [permission:create]
 */
router.post(
  '/',
  authenticate,
  checkPermission('permission:create'),
  createPermissionValidation,
  permissionController.createPermission
);

/**
 * @route   POST /api/permissions/batch
 * @desc    批量创建权限（用于系统初始化）
 * @access  Private [permission:create]
 */
router.post(
  '/batch',
  authenticate,
  checkPermission('permission:create'),
  batchCreateValidation,
  permissionController.batchCreatePermissions
);

/**
 * @route   PUT /api/permissions/:id
 * @desc    更新权限
 * @access  Private [permission:update]
 */
router.put(
  '/:id',
  authenticate,
  checkPermission('permission:update'),
  permissionIdValidation,
  updatePermissionValidation,
  permissionController.updatePermission
);

/**
 * @route   DELETE /api/permissions/:id
 * @desc    删除权限
 * @access  Private [permission:delete]
 */
router.delete(
  '/:id',
  authenticate,
  checkPermission('permission:delete'),
  permissionIdValidation,
  permissionController.deletePermission
);

module.exports = router;
