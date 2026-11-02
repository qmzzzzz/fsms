/**
 * IP 攻击行为画像读口：security:audit + 二次验证票据，不新增权限码。
 * 与 stuffingProfileRoutes 同因独立成文件：securityRoutes.js 已顶到 max-lines 棘轮地板。
 * 重资源读面挂 strictLimiter，与 /audit-logs 一致。
 */

const express = require('express');
const router = express.Router();
const securityController = require('../controllers/securityController');
const { authenticate, checkPermission, requireReauthTicket } = require('../middleware');
const { strictLimiter } = require('../middleware/rateLimit');

router.get(
  '/attack-profile',
  authenticate,
  checkPermission('security:audit'),
  requireReauthTicket(),
  strictLimiter,
  securityController.getAttackProfile
);

module.exports = router;
