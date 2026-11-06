/**
 * 攻击告警查询读口：security:audit + 二次验证票据，不新增权限码。
 * 与 attackProfileRoutes 同因独立成文件：securityRoutes.js 已顶到 max-lines 棘轮地板。
 * 重资源读面挂 strictLimiter，与 /audit-logs 一致。
 */

const express = require('express');
const router = express.Router();
const securityController = require('../controllers/securityController');
const { authenticate, checkPermission, requireReauthTicket } = require('../middleware');
const { strictLimiter } = require('../middleware/rateLimit');

// 分类计数（tab 角标）：谓词面比列表轻（无取页），但同属审计同源敏感读，链面一致。
router.get(
  '/attack-events/summary',
  authenticate,
  checkPermission('security:audit'),
  requireReauthTicket(),
  strictLimiter,
  securityController.getAttackEventSummary
);

router.get(
  '/attack-events',
  authenticate,
  checkPermission('security:audit'),
  requireReauthTicket(),
  strictLimiter,
  securityController.getAttackEvents
);

module.exports = router;
