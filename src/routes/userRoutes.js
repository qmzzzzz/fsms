/**
 * 用户管理路由
 */

const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { mustBeString } = require('../utils/validationRules');
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
  // FE-M3：管理员建号支持口令密文（encPassword，与代设明文双轨）——
  // 密文轨走时明文校验器跳过，强度在控制器解密后补做
  body('encPassword')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('口令密文格式无效')
    .isLength({ max: 1024 })
    .withMessage('口令密文长度异常'),
  body('password')
    .if((value, { req }) => !req.body.encPassword)
    .custom((value) => {
      const err = validatePasswordStrength(value);
      if (err) throw new Error(err);
      return true;
    })
    .isLength({ max: 64 })
    .withMessage('密码长度不能超过 64 个字符'),
  mustBeString('realName', '姓名'),
  body('realName').optional().trim().isLength({ max: 50 }).withMessage('姓名不能超过 50 个字符'),
  body('phone')
    // 可选手机号：前端未填时带空串 ''。.optional() 只跳过 undefined，'' 会流到 .matches 被拒 →
    // 不填手机号就无法建/改用户。与本仓 falsy 可选约定一致（见上方 status 的 values:'falsy' 注释），
    // 且 User.phone 校验器显式允许 ''（清空手机号是合法操作）。
    .optional({ values: 'falsy' })
    .trim()
    .isLength({ max: 20 })
    .withMessage('手机号不能超过 20 个字符')
    .matches(/^1[3-9]\d{9}$/)
    .withMessage('请输入有效的手机号'),
  mustBeString('department', '部门'),
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('部门不能超过 100 个字符'),
  // 角色引用：与下方 assignRolesValidation 同一条闸门。原先只判「是不是数组」，
  // 元素格式不设防 ⇒ userService 的 `Role.find({_id:{$in:['zz']}})` 抛 CastError，
  // 客户端拿到的是「资源 ID 格式无效」且 errors 里没有任何字段明细
  // （它提交的字段名叫 roles，回显却说"资源 ID"）。条数同样无上界。
  body('roles').optional().isArray({ max: 50 }).withMessage('角色列表最多 50 项'),
  body('roles.*').optional().isMongoId().withMessage('角色 ID 格式无效'),
  allowedIPsCheck,
];

// 更新用户信息校验：与创建保持一致的字段长度约束（各字段均可选）
const updateUserValidation = [
  body('email').optional().trim().isEmail().withMessage('请输入有效的邮箱地址'),
  mustBeString('realName', '姓名'),
  body('realName').optional().trim().isLength({ max: 50 }).withMessage('姓名不能超过 50 个字符'),
  body('phone')
    // 可选手机号：前端未填时带空串 ''。.optional() 只跳过 undefined，'' 会流到 .matches 被拒 →
    // 不填手机号就无法建/改用户。与本仓 falsy 可选约定一致（见上方 status 的 values:'falsy' 注释），
    // 且 User.phone 校验器显式允许 ''（清空手机号是合法操作）。
    .optional({ values: 'falsy' })
    .trim()
    .isLength({ max: 20 })
    .withMessage('手机号不能超过 20 个字符')
    .matches(/^1[3-9]\d{9}$/)
    .withMessage('请输入有效的手机号'),
  mustBeString('department', '部门'),
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('部门不能超过 100 个字符'),
  mustBeString('avatar', '头像地址'),
  body('avatar')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('头像地址不能超过 500 个字符'),
  // 与同文件 :21 的查询侧、models/User.js 的 schema enum 同源：此前这里是手抄的三值清单，
  // USER_STATUS 增删档位时只有它不动（校验口径与 schema 各说各话）
  body('status').optional().isIn(Object.values(USER_STATUS)).withMessage('无效的用户状态'),
  allowedIPsCheck,
];

const assignRolesValidation = [
  body('roles').isArray({ min: 1, max: 50 }).withMessage('请至少分配一个角色（最多 50 项）'),
  // 与创建用户同口径：非法元素在 userService 的 $in 查询里炸成 CastError，
  // 错误信息会与提交字段无关
  body('roles.*').optional().isMongoId().withMessage('角色 ID 格式无效'),
];

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
  // 2026-09-26 审计 Top5：param 链此前挂而不消费（死校验链）。applyObjectIdParams
  // 的 router.param 兜底会先对非法 id 400，本消费层正常时收不到错误——挂上是为了让
  // 「校验 → 消费 → 控制器」在同处成立，兜底移除后不裸奔
  consumeValidation(),
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
  // 同 GET /:id：死校验链补消费（非法 id 已被 applyObjectIdParams 先行 400）
  consumeValidation(),
  userController.deleteUser
);

module.exports = router;
