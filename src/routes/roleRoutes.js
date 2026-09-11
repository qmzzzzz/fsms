/**
 * 角色管理路由
 */

const express = require('express');
const router = express.Router();
const roleController = require('../controllers/roleController');
const rolePermissionController = require('../controllers/rolePermissionController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { consumeValidation } = require('../middleware/validateQuery');

// P3-4/P3-17：列表 query 校验。status 此前零校验直入 Mongo 过滤
// （search 因控制器 String() 强转反而安全——同类参数三种处理水平，此处统一）
// values:'falsy'：前端未选状态筛选时带空串（status=），空串语义为「不筛选」
const listQueryValidation = [
  query('status')
    .optional({ values: 'falsy' })
    .isIn(['active', 'inactive'])
    .withMessage('无效的状态值'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
];

// 路径参数 :id 必须是合法 ObjectId，否则会被 errorHandler 转成“资源 ID 格式无效”
const roleIdValidation = [param('id').isMongoId().withMessage('角色 ID 格式无效')];

// 验证规则
const createRoleValidation = [
  body('name').trim().isLength({ min: 1, max: 50 }).withMessage('角色名称长度应为 1-50 个字符'),
  body('code')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('角色编码长度应为 1-50 个字符')
    .matches(/^[A-Z_]+$/)
    .withMessage('角色编码只能包含大写字母和下划线'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('描述不能超过 200 个字符'),
  body('level').optional().isInt({ min: 1, max: 10 }),
  body('permissions').optional().isArray(),
];

// 更新角色：字段全部可选，长度上限对齐 create；
// 控制器 updateRole 不支持修改 code（前端亦未提交），故不保留 code 的无效校验，避免误导
const updateRoleValidation = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('角色名称长度应为 1-50 个字符'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('描述不能超过 200 个字符'),
  body('level').optional().isInt({ min: 1, max: 10 }),
];

const assignPermissionsValidation = [
  body('permissions').isArray().withMessage('权限列表必须是数组'),
  // 每个权限 ID 都必须是合法 ObjectId，避免 $in 查询触发 CastError
  body('permissions.*').optional().isMongoId().withMessage('权限 ID 格式无效'),
  // 单用户克隆模式：可选的目标用户 ID（内置角色 + 此字段 → 克隆后单独调整）
  body('targetUserId').optional().isMongoId().withMessage('目标用户 ID 格式无效'),
];

// 路由定义
/**
 * @route   GET /api/roles
 * @desc    获取角色列表（分页）
 * @access  Private [role:read]
 */
router.get(
  '/',
  authenticate,
  checkPermission('role:read'),
  listQueryValidation,
  consumeValidation(),
  roleController.getRoles
);

/**
 * @route   GET /api/roles/all
 * @desc    获取所有可用角色（用于下拉选择）
 * @access  Private [role:read]
 */
router.get('/all', authenticate, checkPermission('role:read'), roleController.getAllRoles);

/**
 * @route   GET /api/roles/permissions/tree
 * @desc    获取权限树形结构
 * @access  Private [permission:read | permission:tree]
 */
router.get(
  '/permissions/tree',
  authenticate,
  checkPermission(['permission:read', 'permission:tree']),
  roleController.getPermissionTree
);

/**
 * @route   GET /api/roles/:id
 * @desc    获取角色详情
 * @access  Private [role:read]
 */
router.get(
  '/:id',
  authenticate,
  checkPermission('role:read'),
  roleIdValidation,
  roleController.getRoleById
);

/**
 * @route   POST /api/roles
 * @desc    创建角色
 * @access  Private [role:create]
 */
router.post(
  '/',
  authenticate,
  checkPermission('role:create'),
  createRoleValidation,
  roleController.createRole
);

/**
 * @route   PUT /api/roles/:id
 * @desc    更新角色信息
 * @access  Private [role:update]
 */
router.put(
  '/:id',
  authenticate,
  checkPermission('role:update'),
  roleIdValidation,
  updateRoleValidation,
  roleController.updateRole
);

/**
 * @route   PUT /api/roles/:id/permissions
 * @desc    为角色分配权限
 * @access  Private [role:assign]
 */
router.put(
  '/:id/permissions',
  authenticate,
  checkPermission('role:assign'),
  roleIdValidation,
  assignPermissionsValidation,
  rolePermissionController.assignPermissions
);

/**
 * @route   DELETE /api/roles/:id
 * @desc    删除角色
 * @access  Private [role:delete]
 */
router.delete(
  '/:id',
  authenticate,
  checkPermission('role:delete'),
  roleIdValidation,
  roleController.deleteRole
);

module.exports = router;
