/** GET /api/version：匿名版本元数据。匿名=登录页停留期恰逢升级也要能提示刷新；
 * no-store 是唯一失效形态（中间层缓存会让「有更新」永远检测不到）；高频轮询故不进审计
 * （auditLog.js 的 auditGetExcludePaths）。取舍与 ETag 说明见 deployment/hot-upgrade.md。
 */
const express = require('express');
const router = express.Router();
const ApiResponse = require('../utils/apiResponse');
const { getBuildInfo } = require('../config/buildInfo');

router.get('/', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  return ApiResponse.success(res, getBuildInfo(), '获取成功');
});

module.exports = router;
