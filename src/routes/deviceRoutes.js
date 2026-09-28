/**
 * 消防设备管理路由
 */

const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController');
const { authenticate, checkPermission } = require('../middleware');
const { body, param, query } = require('express-validator');
const { mustBeString, coordinatesRules } = require('../utils/validationRules');
const { consumeValidation } = require('../middleware/validateQuery');
// E-05 整改：设备类型枚举此前在 createDeviceValidation / updateDeviceValidation
// 两处内联展开，与 constants 的 DEVICE_TYPE、模型 enum、文档生成器共 4 份副本。
// 现统一从 constants 取值——新增设备类型只需改这一处。
// 状态两组值改由 constants/deviceStatus 透出（同一份值 + 「可写子集」这条规则只算一次）
const { DEVICE_TYPE } = require('../utils/constants');
const { DEVICE_STATUS_VALUES, DEVICE_STATUS_WRITABLE } = require('../constants/deviceStatus');
const DEVICE_TYPE_VALUES = Object.values(DEVICE_TYPE);

// P3-17：列表 query 枚举校验。status/deviceType 拼错时原先静默返回空集，
// 枚举清单复用 utils/constants 单一声明（避免与模型 enum 漂移）
// values:'falsy'：前端未选筛选时会把空串带上（status=），optional() 默认只跳过
// undefined，空串会落入 isIn 误判 400；空串语义即「不筛选」，与缺省对齐
const listQueryValidation = [
  query('status')
    .optional({ values: 'falsy' })
    .isIn(DEVICE_STATUS_VALUES)
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
  mustBeString('deviceCode', '设备编号'),
  body('deviceCode')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('设备编号不能为空')
    // 上限与 models/FireDevice 的 maxlength:50 对齐。不一致时的后果不是 500，
    // 而是**用户在生产拿不到任何可读原因**：51~64 字符能通过路由校验，
    // 落在模型上变成 ValidationError，而 errorHandler 在生产环境刻意不回传
    // 字段级明细（避免泄露 schema），最终只剩一句笼统的"数据验证失败"。
    // 只有路由校验层能给出"哪个字段、为什么"，所以边界必须写在这一层。
    .isLength({ max: 50 })
    .withMessage('设备编号不能超过 50 个字符'),
  mustBeString('deviceName', '设备名称'),
  body('deviceName')
    .trim()
    .notEmpty()
    .withMessage('设备名称不能为空')
    .isLength({ max: 100 })
    .withMessage('设备名称不能超过 100 个字符'),
  body('deviceType').isIn(DEVICE_TYPE_VALUES).withMessage('无效的设备类型'),
  mustBeString('model', '型号'),
  body('model').optional().trim().isLength({ max: 100 }).withMessage('型号不能超过 100 个字符'),
  mustBeString('manufacturer', '厂商'),
  body('manufacturer')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('厂商不能超过 100 个字符'),
  // installDate 在模型里是 required（FireDevice.js:74-77），路由侧却声明成 optional。
  // 缺字段时拒绝来自 Mongoose，而 errorHandler 在非 development 下把 DB 校验的
  // fieldErrors 整个抹掉 ⇒ 提交者只拿到一句"校验失败"，点不出是哪个必填字段没给。
  // 改成必填只是把那句 400 变成可执行的：今天省略它同样回 400，没有消费者会因此被打断。
  body('installDate').isISO8601().withMessage('请提供安装日期（ISO8601 格式）'),
  // 与 update 链口径对齐：投用/到期日期必须是合法 ISO8601，图片最多 10 张（FireDevice.images 为字符串数组）
  body('commissionDate')
    .optional({ values: 'falsy' })
    .isISO8601()
    .withMessage('请提供有效的投用日期'),
  body('expiryDate').optional({ values: 'falsy' }).isISO8601().withMessage('请提供有效的到期日期'),
  body('images').optional().isArray({ max: 10 }).withMessage('图片最多上传 10 张'),
  // 逐元素长度：模型侧 `images: [String]` 无任何约束（FireDevice.js:149），条数已限 10，
  // 元素长度此前只剩 1MB 的 body 总闸兜着。仓内既无上传接口、前端也不提交该字段
  // ⇒ 它是纯 API 字段，语义只能是"图片 URL"，故按通用 URL 长度上界定界。
  // 注：闸门必须**贴着**它保护的链（`bodyStringGateCoverage` 按前一行判定），
  // 说明文字要放在闸门之前而不是中间。
  mustBeString('images.*', '图片地址'),
  body('images.*')
    .optional({ values: 'null' })
    .isLength({ max: 2048 })
    .withMessage('单张图片地址不能超过 2048 个字符'),
  mustBeString('building', '楼栋'),
  body('building').optional().trim().isLength({ max: 100 }),
  mustBeString('floor', '楼层'),
  body('floor').optional().trim().isLength({ max: 100 }),
  mustBeString('room', '房间'),
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
  ...coordinatesRules('location'),
  mustBeString('remark', '备注'),
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
];

// 更新设备信息校验：字段全部可选，长度上限与 create 一致
// （"一致"现在由 routeSchemaFieldParity.test.js 逐字段对账，不靠注释自觉：
//  `model` 一度是 50 而 create 与模型都是 100 ⇒ 用 API 建出来的 51~100 字符型号，
//  在编辑页整表提交时永远 400，这条记录变成改不动的死数据。）
const updateDeviceValidation = [
  mustBeString('deviceName', '设备名称'),
  body('deviceName')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('设备名称不能超过 100 个字符'),
  body('deviceType').optional().isIn(DEVICE_TYPE_VALUES).withMessage('无效的设备类型'),
  mustBeString('model', '型号'),
  body('model').optional().trim().isLength({ max: 100 }).withMessage('型号不能超过 100 个字符'),
  mustBeString('manufacturer', '厂商'),
  body('manufacturer')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('厂商不能超过 100 个字符'),
  body('installDate').optional().isISO8601().withMessage('请提供有效的安装日期'),
  mustBeString('building', '楼栋'),
  body('building').optional().trim().isLength({ max: 100 }),
  mustBeString('floor', '楼层'),
  body('floor').optional().trim().isLength({ max: 100 }),
  mustBeString('room', '房间'),
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
  ...coordinatesRules('location'),
  mustBeString('remark', '备注'),
  body('remark').optional().trim().isLength({ max: 500 }).withMessage('备注不能超过 500 个字符'),
  // L3：补齐 create 有而 update 缺的校验，checkCycle 约束 1-365 防负数破坏提醒计算
  // status 已从可更新字段中移除（P2-16）：直写 status 会绕过生命周期状态机，
  // 产生「status=scrapped 但 lifecycleStage=in_use」的矛盾状态。
  // 保留校验器是为了让「传了但值非法」仍返回 400；Service 层对合法值也会显式拒绝，
  // 引导调用方改用状态变更 / 报废接口。
  body('status').optional().isIn(DEVICE_STATUS_VALUES).withMessage('无效的设备状态'),
  body('checkCycle').optional().isInt({ min: 1, max: 365 }).withMessage('检查周期应为 1-365 天'),
  body('expiryDate').optional().isISO8601().withMessage('请提供有效的到期日期'),
];

// 更新设备状态：状态值必须合法
// scrapped 不在此列（走专门的 /scrap 接口）：排除规则本身住在 constants/deviceStatus.js，
// 与文档 requestBody 的 enum 同源，不在这里重抄一份五档字面量
const updateDeviceStatusValidation = [
  body('status').isIn(DEVICE_STATUS_WRITABLE).withMessage('无效的设备状态（报废请使用报废接口）'),
];

// 报废设备校验
const scrapDeviceValidation = [
  mustBeString('scrapReason', '报废原因'),
  body('scrapReason')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('报废原因不能超过 200 个字符'),
];

const maintenanceValidation = [
  mustBeString('content', '维护内容'),
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
  // 2026-09-26 审计 Top5：param 链此前挂而不消费（死校验链）。applyObjectIdParams
  // 的 router.param 兜底会先对非法 id 400，本消费层正常时收不到错误——挂上是为了让
  // 「校验 → 消费 → 控制器」在同处成立，兜底移除后不裸奔
  consumeValidation(),
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
  // 同 GET /:id：死校验链补消费（非法 id 已被 applyObjectIdParams 先行 400）
  consumeValidation(),
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
