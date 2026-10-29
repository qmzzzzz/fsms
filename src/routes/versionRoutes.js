/**
 * 版本元数据端点
 *
 * GET /api/version —— 匿名可读，返回**当前处理该请求的实例**的版本标识。
 *
 * 用途只有两个，都不涉及业务数据：
 *   1. 运维确认线上跑的是哪个构建（蓝绿切换后能看出流量落在新色还是旧色）；
 *   2. 前端轮询比对，发现「服务端已升级但本标签页还是旧壳子」时提示刷新。
 *
 * 为什么匿名：前端在登录页也可能停留很久（升级恰好发生在这段时间），
 * 若要求认证，这类会话永远拿不到提示，只能等用户自己刷新。
 *
 * 为什么必须 no-store：这是本端点唯一的失效形态——中间层（nginx / CDN /
 * 企业代理）缓存了这份 JSON，前端就会一直比对到旧的 buildId，于是
 * 「有更新」永远检测不到，且**没有任何报错**。所有缓存都必须显式关掉。
 *
 * 不进审计：它是高频轮询的只读元数据（每次打开标签页 + 每 5 分钟一次），
 * 进审计链只会灌大集合、稀释真实操作痕迹。豁免登记见
 * middleware/security/auditLog.js 的 auditGetExcludePaths。
 */

const express = require('express');
const router = express.Router();
const ApiResponse = require('../utils/apiResponse');
const { getBuildInfo } = require('../config/buildInfo');

router.get('/', (req, res) => {
  // no-store 之外再关掉协商缓存：某些代理对 no-store 处理不严，
  // 而 `no-cache` 强制回源，两者叠加才足以让「换了版本却读到旧 JSON」不成立。
  //
  // 关于 ETag：Express 在 res.send 阶段无条件补 ETag（实测 removeHeader('ETag')
  // 无效——send 里 `if (!this.get('ETag'))` 会重新生成；而 res.set('ETag', false)
  // 会写出字面量 `ETag: false`，更糟）。这里不做无效抵抗：`no-store` 已使合规缓存
  // 不得存储，ETag 因此无从参与条件请求。真要全局关掉得改 app.set('etag')，
  // 那会波及全部 API 的 304 语义，代价远大于收益。
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  return ApiResponse.success(res, getBuildInfo(), '获取成功');
});

module.exports = router;
