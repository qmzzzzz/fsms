// 取证溯源路由（T5/T6），挂 /api/security/forensic。独立成文件是因为 securityRoutes.js 有效行已超 300（棘轮 max-lines 1）。读溯源 security:audit，改封禁 security:config；封禁两步都要 strictLimiter（写 IP 名单是重资源操作）。

const express = require('express');
const router = express.Router();
const { body, query } = require('express-validator');
const { authenticate, checkPermission } = require('../middleware');
const { strictLimiter } = require('../middleware/rateLimit');
const { consumeValidation } = require('../middleware/validateQuery');
const forensicController = require('../controllers/forensicController');

const traceValidation = [
  query('ip').optional({ values: 'falsy' }).isString().trim().isLength({ max: 64 }),
  query('fingerprint').optional({ values: 'falsy' }).isString().trim().isLength({ max: 128 }),
  query('deviceKey').optional({ values: 'falsy' }).isString().trim().isLength({ max: 64 }),
  query('ipSegment').optional({ values: 'falsy' }).isString().trim().isLength({ max: 64 }),
  query('since').optional({ values: 'falsy' }).isISO8601().withMessage('起始时间格式无效'),
  query('until').optional({ values: 'falsy' }).isISO8601().withMessage('结束时间格式无效'),
  query('limit').optional({ values: 'falsy' }).isInt({ min: 1, max: 1000 }),
  consumeValidation(),
];

// GET /trace：按 IP / 指纹 / 网段溯源（至少一个维度），Private [security:audit]
router.get(
  '/trace',
  authenticate,
  checkPermission('security:audit'),
  ...traceValidation,
  forensicController.getTrace
);

// GET /clusters：IP 池聚类候选（轮换池建议封段，共享出口只报不建议），Private [security:config]
router.get(
  '/clusters',
  authenticate,
  checkPermission('security:config'),
  query('windowHours').optional({ values: 'falsy' }).isInt({ min: 1, max: 720 }),
  query('minHits').optional({ values: 'falsy' }).isInt({ min: 1, max: 100000 }),
  query('minIps').optional({ values: 'falsy' }).isInt({ min: 1, max: 1000 }),
  query('limit').optional({ values: 'falsy' }).isInt({ min: 1, max: 200 }),
  consumeValidation(),
  forensicController.getClusters
);

// POST /pool-ban/request：申请确认票据（不落库；护栏拒绝时原因见 errors.reason），Private [security:config]
router.post(
  '/pool-ban/request',
  authenticate,
  checkPermission('security:config'),
  strictLimiter,
  body('cidr').isString().trim().notEmpty().withMessage('请提供网段').isLength({ max: 64 }),
  body('reason').isString().trim().notEmpty().withMessage('请填写封禁理由').isLength({ max: 200 }),
  consumeValidation(),
  forensicController.requestPoolBan
);

// POST /pool-ban/confirm：持票落库（票据一次性、10 分钟失效），Private [security:config]。封禁对象是网段（全局安全面），票据即被确认的写入目标本身，无「他人资源」维度
router.post(
  '/pool-ban/confirm',
  authenticate,
  checkPermission('security:config'),
  strictLimiter,
  body('token').isString().trim().notEmpty().withMessage('请提供确认票据').isLength({ max: 128 }),
  body('typedConfirm').optional({ values: 'falsy' }).isString().trim().isLength({ max: 64 }),
  body('durationHours').optional({ values: 'falsy' }).isFloat({ min: 0, max: 8760 }),
  consumeValidation(),
  forensicController.confirmPoolBan // SCOPE-EXEMPT: 写入目标是票据里的网段（全局安全配置），无他人数据范围维度
);

// POST /export：签名导出（签名绑定当天清单锚点，可离线复核），Private [security:audit]
router.post(
  '/export',
  authenticate,
  checkPermission('security:audit'),
  strictLimiter,
  body('ip').optional({ values: 'falsy' }).isString().trim().isLength({ max: 64 }),
  body('fingerprint').optional({ values: 'falsy' }).isString().trim().isLength({ max: 128 }),
  body('ipSegment').optional({ values: 'falsy' }).isString().trim().isLength({ max: 64 }),
  body('since').optional({ values: 'falsy' }).isISO8601().withMessage('起始时间格式无效'),
  body('until').optional({ values: 'falsy' }).isISO8601().withMessage('结束时间格式无效'),
  body('limit').optional({ values: 'falsy' }).isInt({ min: 1, max: 5000 }),
  consumeValidation(),
  forensicController.exportForensic
);

module.exports = router;
