/**
 * 用户管理路由
 */

const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { validatePasswordStrength } = require('../utils/helpers');
const { MAX_TEXT_LENGTH } = require('../utils/ipRange');
const { consumeValidation } = require('../middleware/validateQuery');
const { USER_STATUS } = require('../utils/constants');

// P3-4/P3-17：列表 query 校验。status 此前零校验直入 Mongo 过滤，
// 传入非法值只会静默返回空集；配合 queryScalarGuard（拦对象/数组形态）
// 构成完整防线——前者防「类型」，此处防「取值」
// values:'falsy'：前端未选状态筛选时带空串（status=），空串语义为「不筛选」
const listQueryValidation = [
  query('status')
    .optional({ values: 'falsy' })
    .isIn(Object.values(USER_STATUS))
    .withMessage('无效的用户状态'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
  query('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('部门名称不能超过 100 个字符'),
  query('role').optional().trim().isLength({ max: 50 }).withMessage('角色编码不能超过 50 个字符'),
];

// IP 访问范围规则：仅做长度与类型的粗校验，
// 语法级校验（含逐条格式回报）在控制器用 validateRules 完成
const allowedIPsCheck = body('allowedIPs')
  .optional({ nullable: true })
  .isString()
  .withMessage('IP 范围规则必须是字符串')
  .isLength({ max: MAX_TEXT_LENGTH })
  .withMessage(`IP 范围规则不超过 ${MAX_TEXT_LENGTH} 个字符`);

// 验证规则
const createUserValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('用户名长度应为 3-30 个字符')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('用户名只能包含字母、数字和下划线'),
  body('email').trim().isEmail().withMessage('请输入有效的邮箱地址').normalizeEmail(),
  body('password')
    .custom((value) => {
      const err = validatePasswordStrength(value);
      if (err) throw new Error(err);
      return true;
    })
    .isLength({ max: 64 })
    .withMessage('密码长度不能超过 64 个字符'),
  body('realName').optional().trim().isLength({ max: 50 }).withMessage('姓名不能超过 50 个字符'),
  body('phone')
    .optional()
    .trim()
    .isLength({ max: 20 })
    .withMessage('手机号不能超过 20 个字符')
    .matches(/^1[3-9]\d{9}$/)
    .withMessage('请输入有效的手机号'),
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('部门不能超过 100 个字符'),
  body('roles').optional().isArray(),
  allowedIPsCheck,
];

// 更新用户信息校验：与创建保持一致的字段长度约束（各字段均可选）
const updateUserValidation = [
  body('email').optional().trim().isEmail().withMessage('请输入有效的邮箱地址'),
  body('realName').optional().trim().isLength({ max: 50 }).withMessage('姓名不能超过 50 个字符'),
  body('phone')
    .optional()
    .trim()
    .isLength({ max: 20 })
    .withMessage('手机号不能超过 20 个字符')
    .matches(/^1[3-9]\d{9}$/)
    .withMessage('请输入有效的手机号'),
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('部门不能超过 100 个字符'),
  body('avatar')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('头像地址不能超过 500 个字符'),
  body('status').optional().isIn(['active', 'inactive', 'locked']).withMessage('无效的用户状态'),
  allowedIPsCheck,
];

const assignRolesValidation = [body('roles').isArray({ min: 1 }).withMessage('请至少分配一个角色')];

// :id 路径参数必须是合法 ObjectId，防止非法 id 触发 CastError → 500
const mongoIdParamValidation = [param('id').isMongoId().withMessage('无效的用户ID')];

// 路由定义
/**
 * @route   GET /api/users/stats
 * @desc    获取用户统计信息
 * @access  Private [user:read]
 */
router.get('/stats', authenticate, checkPermission('user:read'), userController.getUserStats);

/**
 * @route   GET /api/users
 * @desc    获取用户列表（分页）
 * @access  Private [user:read]
 */
router.get(
  '/',
  authenticate,
  checkPermission('user:read'),
  listQueryValidation,
  consumeValidation(),
  userController.getUsers
);

/**
 * @route   GET /api/users/:id
 * @desc    获取单个用户详情
 * @access  Private [user:read]
 */
router.get(
  '/:id',
  authenticate,
  checkPermission('user:read'),
  mongoIdParamValidation,
  userController.getUserById
);

/**
 * @route   POST /api/users
 * @desc    创建用户
 * @access  Private [user:create]
 */
router.post(
  '/',
  authenticate,
  checkPermission('user:create'),
  createUserValidation,
  userController.createUser
);

/**
 * @route   PUT /api/users/:id
 * @desc    更新用户信息
 * @access  Private [user:update]
 */
router.put(
  '/:id',
  authenticate,
  checkPermission('user:update'),
  mongoIdParamValidation,
  updateUserValidation,
  userController.updateUser
);

/**
 * @route   PUT /api/users/:id/roles
 * @desc    分配角色给用户
 * @access  Private [role:assign]
 */
router.put(
  '/:id/roles',
  authenticate,
  checkPermission('role:assign'),
  mongoIdParamValidation,
  assignRolesValidation,
  userController.assignRoles
);

/**
 * @route   DELETE /api/users/batch
 * @desc    批量删除用户
 * @access  Private [user:delete]
 */
router.delete(
  '/batch',
  authenticate,
  checkPermission('user:delete'),
  // G3：ids 数组结构与元素格式前置校验（控制器内已有等价检查并保留作为兜底，
  // 此处统一为 express-validator 口径，与其余端点一致）
  body('ids').isArray({ min: 1, max: 100 }).withMessage('请提供 1-100 个用户 ID'),
  body('ids.*').isMongoId().withMessage('包含非法的用户 ID 格式'),
  userController.batchDeleteUsers
);

/**
 * @route   DELETE /api/users/:id
 * @desc    删除用户
 * @access  Private [user:delete]
 */
router.delete(
  '/:id',
  authenticate,
  checkPermission('user:delete'),
  mongoIdParamValidation,
  userController.deleteUser
);

module.exports = router;
