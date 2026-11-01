// 头像读取路由（/api/avatars）：静态前缀便于审计豁免与独立限流桶。
const express = require('express');
const { param } = require('express-validator');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { avatarReadIpLimiter, avatarReadUserLimiter } = require('../middleware/rateLimit');
const avatarController = require('../controllers/avatarController');

// 顺序契约：IP 桶（认证前）→ authenticate → 用户桶（认证后）；A2：IP 桶改挂 router.use（前缀级）。
router.use(avatarReadIpLimiter);

router.get(
  '/:userId',
  authenticate,
  avatarReadUserLimiter,
  param('userId').isMongoId().withMessage('用户 ID 无效'),
  avatarController.getAvatar
);

module.exports = router;
