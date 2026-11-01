// 热升级：触发只做「校验 + 落签名请求文件」；docker/nginx 动作由宿主 hotUpgradeAgent 执行并重做白名单与摘要校验——本控制器的校验只是输入错误的前置拒绝，不是安全边界本身。

const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { auditClientAddress, clientIpForSecurityDecision } = require('../../utils/ipUtils');
const { getBuildInfo } = require('../../config/buildInfo');
const upgradeService = require('../../services/upgradeService');
const { recordDurably } = require('../../services/auditOutbox');
const { RESERVED_WILDCARD_PERMISSION } = require('../../utils/superAdmin');

const NO_STORE = 'no-store';

/** GET /api/security/upgrade：构建信息 + 代理就绪判据 + 最近任务；reasons 解释按钮为什么是灰的。 */
const getUpgradeOverview = asyncHandler(async (req, res) => {
  const overview = upgradeService.getOverview({ buildInfo: getBuildInfo() });
  // 概览含心跳与任务状态，任何中间层缓存都会让前端一直看到过期状态
  res.set('Cache-Control', NO_STORE);
  return ApiResponse.success(res, overview, '获取成功');
});

/** GET /api/security/upgrade/jobs/:id：状态目录优先，其次 processing/requests（代理写状态前也能看到 queued）。 */
const getUpgradeJob = asyncHandler(async (req, res) => {
  const { jobId: id } = req.params;
  // 非 UUID 直接按不存在处理：避免把任意路径段拼进文件路径
  if (!upgradeService.isJobId(id)) {
    return ApiResponse.codeError(res, 'UPGRADE_JOB_NOT_FOUND');
  }
  let job;
  try {
    job = upgradeService.readJob(id);
  } catch (err) {
    if (err.code === 'UPGRADE_QUEUE_UNAVAILABLE') {
      return ApiResponse.codeError(res, 'UPGRADE_QUEUE_UNAVAILABLE'); // 读不出来 ≠ 任务不存在：归一到 503
    }
    throw err;
  }
  if (!job) return ApiResponse.codeError(res, 'UPGRADE_JOB_NOT_FOUND');
  res.set('Cache-Control', NO_STORE);
  return ApiResponse.success(res, { job }, '获取成功');
});

/** POST /api/security/upgrade/requests   body: { image: 'registry/name@sha256:<64hex>' }
 *  权限：security:config（路由层）+ 唯一超管 *:*（发布版本只由最高权限账户发起）。 */
const triggerUpgrade = asyncHandler(async (req, res) => {
  const permissions = Array.isArray(req.userPermissions) ? req.userPermissions : [];
  if (!permissions.includes(RESERVED_WILDCARD_PERMISSION)) {
    return ApiResponse.codeError(res, 'SUPER_ADMIN_REQUIRED');
  }

  const image = typeof req.body.image === 'string' ? req.body.image.trim() : '';
  let job;
  try {
    ({ job } = upgradeService.createUpgradeRequest({
      image,
      user: req.user,
      sourceIp: clientIpForSecurityDecision(req) || '',
    }));
  } catch (err) {
    // 可预期拒绝映射稳定错误码；失败路径不设 skipGlobalAudit——让全局审计以
    // security_upgrade_requests 记录这次尝试，成功路径才由下面的显式事件覆盖。
    logger.warn('热升级请求被拒绝', {
      code: err.code || 'UPGRADE_UNKNOWN',
      operator: req.user.username,
      image,
      message: err.message,
    });
    return rejectUpgrade(res, err);
  }

  // 先持久化审计再回成功：审计失败时让全局审计记录这次 500（skipGlobalAudit 尚未置位）。
  await recordDurably(
    {
      action: 'upgrade_triggered',
      category: 'security',
      userId: req.user.userId,
      username: req.user.username,
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'high',
      body: { image: job.image, jobId: job.id, targetColor: job.targetColor },
    },
    { auditAction: 'security_config_change', req }
  );
  res.locals.skipGlobalAudit = true;

  logger.warn('热升级请求已入队', {
    jobId: job.id,
    image: job.image,
    operator: req.user.username,
  });
  return ApiResponse.success(res, { job }, '升级请求已入队', 202);
});

/** 拒绝响应逐码写死字面量：静态扫描（emittedErrorCodeCoverage）看不见变量形态，转发 err.code 会让
 *  这五个已注册的码退化成死码；未预期异常交给统一错误处理。 */
function rejectUpgrade(res, err) {
  const params = err.details ? { params: err.details } : {};
  switch (err.code) {
    case 'UPGRADE_DISABLED':
      return ApiResponse.codeError(res, 'UPGRADE_DISABLED', params);
    case 'UPGRADE_IMAGE_INVALID':
      return ApiResponse.codeError(res, 'UPGRADE_IMAGE_INVALID', params);
    case 'UPGRADE_IMAGE_NOT_ALLOWED':
      return ApiResponse.codeError(res, 'UPGRADE_IMAGE_NOT_ALLOWED', params);
    case 'UPGRADE_ALREADY_RUNNING':
      return ApiResponse.codeError(res, 'UPGRADE_ALREADY_RUNNING', params);
    case 'UPGRADE_QUEUE_UNAVAILABLE':
      return ApiResponse.codeError(res, 'UPGRADE_QUEUE_UNAVAILABLE', params);
    default:
      throw err;
  }
}

module.exports = { getUpgradeOverview, getUpgradeJob, triggerUpgrade };
