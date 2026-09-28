/**
 * 角色管理路由
 */

const express = require('express');
const router = express.Router();
const roleController = require('../controllers/roleController');
const rolePermissionController = require('../controllers/rolePermissionController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { mustBeString } = require('../utils/validationRules');
const { consumeValidation } = require('../middleware/validateQuery');
// 与 Permission/Role schema 的 status enum 同源（见 constants/permission.js）
const { RESOURCE_STATUSES } = require('../constants/permission');

// P3-4/P3-17：列表 query 校验。status 此前零校验直入 Mongo 过滤
// （search 因控制器 String() 强转反而安全——同类参数三种处理水平，此处统一）
// values:'falsy'：前端未选状态筛选时带空串（status=），空串语义为「不筛选」
const listQueryValidation = [
  query('status').optional({ values: 'falsy' }).isIn(RESOURCE_STATUSES).withMessage('无效的状态值'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
];

// 路径参数 :id 必须是合法 ObjectId，否则会被 errorHandler 转成“资源 ID 格式无效”
const roleIdValidation = [param('id').isMongoId().withMessage('角色 ID 格式无效')];

// 验证规则
const createRoleValidation = [
  mustBeString('name', '角色名称'),
  body('name').trim().isLength({ min: 1, max: 50 }).withMessage('角色名称长度应为 1-50 个字符'),
  body('code')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('角色编码长度应为 1-50 个字符')
    .matches(/^[A-Z_]+$/)
    .withMessage('角色编码只能包含大写字母和下划线'),
  mustBeString('description', '描述'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('描述不能超过 200 个字符'),
  body('level').optional().isInt({ min: 1, max: 10 }),
  // 权限引用数组：与同文件 assignPermissionsValidation 同尺（元素必须是合法
  // ObjectId），并补上两边都缺的条数上界。
  //
  // 原实现只判「是不是数组」，两个方向各漏一次：
  // ① 非超管轨把非法元素交给 roleService.findPermissionsByIds →
  //    `Permission.find({_id:{$in:['zz']}})` 抛 CastError → errorHandler 回
  //    「资源 ID 格式无效」且 errors 里没有任何字段明细（客户端没提交过 ID 字段名，
  //    只知道自己写错了"资源 ID"）；
  // ② 超管轨跳过那次存在性查询，非法元素直达 `Role.create`（models/Role.js
  //    permissions: [ObjectId]）——要么 ValidationError 走同一条无明细的 400，
  //    要么被 cast 层吞掉得到一份**比客户端提交的少**的权限表却回 201（假成功）。
  // 权限授予语义上不允许"少给了还报成功"。
  body('permissions').optional().isArray({ max: 500 }).withMessage('权限列表最多 500 项'),
  body('permissions.*').optional().isMongoId().withMessage('权限 ID 格式无效'),
];

// 更新角色：字段全部可选，长度上限对齐 create；
// 控制器 updateRole 不支持修改 code（前端亦未提交），故不保留 code 的无效校验，避免误导
const updateRoleValidation = [
  mustBeString('name', '角色名称'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('角色名称长度应为 1-50 个字符'),
  mustBeString('description', '描述'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('描述不能超过 200 个字符'),
  body('level').optional().isInt({ min: 1, max: 10 }),
];

const assignPermissionsValidation = [
  // 条数上界与 create 同一条：本端点是「整表替换」，一次提交的长度就是
  // 落库的 permissions 长度，没有上界就等于没有上界（1MB body 下可塞上万个 ID，
  // 每条都要过 $in 查询与 populate）
  body('permissions').isArray({ max: 500 }).withMessage('权限列表最多 500 项'),
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
  // 2026-09-26 审计 Top5：param 链此前挂而不消费（消费点本就不存在的死校验链）。
  // applyObjectIdParams 的 router.param 兜底会先对非法 id 400，本消费层正常时
  // 收不到错误——挂上是为了让「校验 → 消费 → 控制器」在同处成立，兜底移除后不裸奔
  consumeValidation(),
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
  // 同 GET /:id：死校验链补消费（非法 id 已被 applyObjectIdParams 先行 400）
  consumeValidation(),
  roleController.deleteRole
);

module.exports = router;
