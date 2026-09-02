/**
 * 消防设备管理路由
 */

const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { consumeValidation } = require('../middleware/validateQuery');
const { DEVICE_STATUS, DEVICE_TYPE } = require('../utils/constants');

// P3-17：列表 query 枚举校验。status/deviceType 拼错时原先静默返回空集，
// 枚举清单复用 utils/constants 单一声明（避免与模型 enum 漂移）
// values:'falsy'：前端未选筛选时会把空串带上（status=），optional() 默认只跳过
// undefined，空串会落入 isIn 误判 400；空串语义即「不筛选」，与缺省对齐
const listQueryValidation = [
  query('status')
    .optional({ values: 'falsy' })
    .isIn(Object.values(DEVICE_STATUS))
    .withMessage('无效的设备状态'),
  query('deviceType')
    .optional({ values: 'falsy' })
    .isIn(Object.values(DEVICE_TYPE))
    .withMessage('无效的设备类型'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('每页数量应在 1-100'),
  query('building').optional().trim().isLength({ max: 100 }).withMessage('楼栋不能超过 100 个字符'),
  query('floor').optional().trim().isLength({ max: 100 }).withMessage('楼层不能超过 100 个字符'),
];

// 验证规则
const createDeviceValidation = [
  body('deviceCode')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('设备编号不能为空')
    .isLength({ max: 64 })
    .withMessage('设备编号不能超过 64 个字符'),
  body('deviceName')
    .trim()
    .notEmpty()
    .withMessage('设备名称不能为空')
    .isLength({ max: 100 })
    .withMessage('设备名称不能超过 100 个字符'),
  body('deviceType')
    .isIn([
      'fire_alarm',
      'sprinkler',
      'hydrant',
      'extinguisher',
      'smoke_detector',
      'heat_detector',
      'emergency_light',
      'evacuation_sign',
      'fire_door',
      'other',
    ])
    .withMessage('无效的设备类型'),
  body('model').optional().trim().isLength({ max: 100 }).withMessage('型号不能超过 100 个字符'),
  body('manufacturer')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('厂商不能超过 100 个字符'),
  body('installDate').optional().isISO8601().withMessage('请提供有效的安装日期'),
  // 与 update 链口径对齐：投用/到期日期必须是合法 ISO8601，图片最多 10 张（FireDevice.images 为字符串数组）
  body('commissionDate')
    .optional({ values: 'falsy' })
    .isISO8601()
    .withMessage('请提供有效的投用日期'),
  body('expiryDate').optional({ values: 'falsy' }).isISO8601().withMessage('请提供有效的到期日期'),
  body('images').optional().isArray({ max: 10 }).withMessage('图片最多上传 10 张'),
  body('building').optional().trim().isLength({ max: 100 }),
  body('floor').optional().trim().isLength({ max: 100 }),
  body('room').optional().trim().isLength({ max: 100 }),
  body('location').optional().isObject(),
  body('location.building')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼栋不能超过 100 个字符'),
  body('location.floor')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼层不能超过 100 个字符'),
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
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
];

// 更新设备信息校验：字段全部可选，长度上限与 create 一致
const updateDeviceValidation = [
  body('deviceName')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('设备名称不能超过 100 个字符'),
  body('deviceType')
    .optional()
    .isIn([
      'fire_alarm',
      'sprinkler',
      'hydrant',
      'extinguisher',
      'smoke_detector',
      'heat_detector',
      'emergency_light',
      'evacuation_sign',
      'fire_door',
      'other',
    ])
    .withMessage('无效的设备类型'),
  body('model').optional().trim().isLength({ max: 50 }).withMessage('型号不能超过 50 个字符'),
  body('manufacturer')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('厂商不能超过 100 个字符'),
  body('installDate').optional().isISO8601().withMessage('请提供有效的安装日期'),
  body('building').optional().trim().isLength({ max: 100 }),
  body('floor').optional().trim().isLength({ max: 100 }),
  body('room').optional().trim().isLength({ max: 100 }),
  body('location').optional().isObject(),
  body('location.building')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('办公室不能超过 100 个字符'),
  body('location.floor')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('楼层不能超过 100 个字符'),
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
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
  // L3：补齐 create 有而 update 缺的校验，checkCycle 约束 1-365 防负数破坏提醒计算
  // status 已从可更新字段中移除（P2-16）：直写 status 会绕过生命周期状态机，
  // 产生「status=scrapped 但 lifecycleStage=in_use」的矛盾状态。
  // 保留校验器是为了让「传了但值非法」仍返回 400；Service 层对合法值也会显式拒绝，
  // 引导调用方改用状态变更 / 报废接口。
  body('status')
    .optional()
    .isIn(['normal', 'warning', 'fault', 'offline', 'maintenance', 'scrapped'])
    .withMessage('无效的设备状态'),
  body('checkCycle').optional().isInt({ min: 1, max: 365 }).withMessage('检查周期应为 1-365 天'),
  body('expiryDate').optional().isISO8601().withMessage('请提供有效的到期日期'),
];

// 更新设备状态：状态值必须合法
// scrapped 不在此列：报废需要报废原因并推进生命周期，走专门的 /scrap 接口
// （P2-16：允许从通用状态接口进入 scrapped 会绕过 transitionTo 状态机）
const updateDeviceStatusValidation = [
  body('status')
    .isIn(['normal', 'warning', 'fault', 'offline', 'maintenance'])
    .withMessage('无效的设备状态（报废请使用报废接口）'),
];

// 报废设备校验
const scrapDeviceValidation = [
  body('scrapReason')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('报废原因不能超过 200 个字符'),
];

const maintenanceValidation = [
  body('content')
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('维护内容长度应为 1-500 个字符'),
  // 维护类型决定是否顺延检查周期（routine/inspection 顺延，repair/replacement 不顺延），
  // 枚举须与 FireDevice.maintenanceRecord.type 保持一致
  body('type')
    .optional()
    .isIn(['routine', 'repair', 'replacement', 'inspection'])
    .withMessage('无效的维护类型'),
];

// :id 路径参数必须是合法 ObjectId，防止非法 id 触发 CastError → 500
const mongoIdParamValidation = [param('id').isMongoId().withMessage('无效的设备ID')];

// 路由定义
/**
 * @route   GET /api/devices
 * @desc    获取设备列表
 * @access  Private [device:read]
 */
router.get(
  '/',
  authenticate,
  checkPermission('device:read'),
  listQueryValidation,
  consumeValidation(),
  deviceController.getDevices
);

// 静态路由必须置于 :id 动态参数路由之前，否则会被 :id 拦截
/**
 * @route   GET /api/devices/stats
 * @desc    获取设备统计信息
 * @access  Private [device:read]
 */
router.get('/stats', authenticate, checkPermission('device:read'), deviceController.getDeviceStats);

/**
 * @route   GET /api/devices/expiring
 * @desc    获取即将到期设备列表
 * @access  Private [device:read]
 */
router.get(
  '/expiring',
  authenticate,
  checkPermission('device:read'),
  deviceController.getExpiringDevices
);

/**
 * @route   GET /api/devices/reminders
 * @desc    获取设备到期/维护提醒汇总
 * @access  Private [device:read]
 */
router.get(
  '/reminders',
  authenticate,
  checkPermission('device:read'),
  deviceController.getDeviceReminders
);

/**
 * @route   GET /api/devices/:id
 * @desc    获取设备详情
 * @access  Private [device:read]
 */
router.get(
  '/:id',
  authenticate,
  checkPermission('device:read'),
  mongoIdParamValidation,
  deviceController.getDeviceById
);

/**
 * @route   POST /api/devices
 * @desc    创建设备
 * @access  Private [device:create]
 */
router.post(
  '/',
  authenticate,
  checkPermission('device:create'),
  createDeviceValidation,
  deviceController.createDevice
);

/**
 * @route   PUT /api/devices/:id
 * @desc    更新设备信息
 * @access  Private [device:update]
 */
router.put(
  '/:id',
  authenticate,
  checkPermission('device:update'),
  mongoIdParamValidation,
  updateDeviceValidation,
  deviceController.updateDevice
);

/**
 * @route   PUT /api/devices/:id/status
 * @desc    更新设备状态
 * @access  Private [device:update]
 */
router.put(
  '/:id/status',
  authenticate,
  checkPermission('device:update'),
  mongoIdParamValidation,
  updateDeviceStatusValidation,
  deviceController.updateDeviceStatus
);

/**
 * @route   POST /api/devices/:id/maintenance
 * @desc    添加维护记录
 * @access  Private [device:maintain]
 */
router.post(
  '/:id/maintenance',
  authenticate,
  checkPermission('device:maintain'),
  mongoIdParamValidation,
  maintenanceValidation,
  deviceController.addMaintenanceRecord
);

/**
 * @route   DELETE /api/devices/:id
 * @desc    删除设备
 * @access  Private [device:delete]
 */
router.delete(
  '/:id',
  authenticate,
  checkPermission('device:delete'),
  mongoIdParamValidation,
  deviceController.deleteDevice
);

/**
 * @route   PUT /api/devices/:id/scrap
 * @desc    设备报废
 * @access  Private [device:update]
 */
router.put(
  '/:id/scrap',
  authenticate,
  checkPermission('device:update'),
  mongoIdParamValidation,
  scrapDeviceValidation,
  deviceController.scrapDevice
);

module.exports = router;
