/**
 * 撞库画像读口（ADR-013 P2 情报）：security:audit + 二次验证票据，不新增权限码。独立成文件是因为
 * securityRoutes.js 已顶到 max-lines 棘轮地板（有效行 367），再加一条路由块就要动基线——拆文件
 * 是仓库里的既有解法（forensicRoutes.js 同因）。重资源读面挂 strictLimiter，与 /audit-logs 一致。
 */

const express = require('express');
const router = express.Router();
const securityController = require('../controllers/securityController');
const { authenticate, checkPermission, requireReauthTicket } = require('../middleware');
const { strictLimiter } = require('../middleware/rateLimit');

router.get(
  '/stuffing-profile',
  authenticate,
  checkPermission('security:audit'),
  requireReauthTicket(),
  strictLimiter,
  securityController.getStuffingProfile
);

module.exports = router;
