'use strict';

/**
 * IP 名单写入的两道前置护栏（自 ipListController 抽出：控制器已贴 max-lines 与 complexity 棘轮）。
 * 两者都以「写入后的并集/调用者位置/活跃流量」为判据，与控制器自身的校验/冲突检测分开。
 */

const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const ipListService = require('../services/ipListService');
const { isFullRangeCIDR, normalizeIP } = require('../utils/ipUtils');
const { cidrUnionCoversAll } = require('../utils/cidrCoverage');
const { auditPath } = require('../utils/auditMeta');
const { clientIpForSecurityDecision } = require('../utils/ipUtils');
const { segmentWriteRefusal } = require('../services/ipPoolBan');

/** 加入后同类型名单的并集是否铺满某个地址族（调用方还要用它判"是否属于全网段口径"） */
const coveredFamiliesOf = async (normalizedIP, type) => {
  if (isFullRangeCIDR(normalizedIP)) return [normalizedIP.includes(':') ? 'IPv6' : 'IPv4'];
  const existing = await ipListService.listActiveEntryIps(type);
  const coverage = cidrUnionCoversAll([...existing, normalizedIP]);
  return [coverage.ipv4 && 'IPv4', coverage.ipv6 && 'IPv6'].filter(Boolean);
};

/**
 * 全网段（/0）与"分片铺满"收口：这类条目一次性命中所有客户端——加黑即全站拒服且管理员
 * 自己也无法登录解除，加白使黑名单与限流整体失效。故仅内置超管可配置，两种结局都留高危痕迹
 * （拒绝侧记 privilege_escalation；操作者判定只认生效角色）。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const guardFullRangeCIDR = async (
  req,
  res,
  { normalizedIP, type, coveredFamilies: pre = null }
) => {
  const coveredFamilies = pre || (await coveredFamiliesOf(normalizedIP, type));
  if (coveredFamilies.length === 0) return false;

  const scope = coveredFamilies.join('/');
  if (await ipListService.operatorIsSuperAdmin(req.user.userId)) {
    logger.warn('超级管理员正在添加全网段名单', {
      ip: normalizedIP,
      type,
      coveredFamilies,
      operator: req.user.username,
    });
    return false;
  }
  logger.warn('非超级管理员尝试添加全网段名单', {
    ip: normalizedIP,
    type,
    coveredFamilies,
    operator: req.user.username,
  });
  ipListService.recordPrivilegeEscalation({
    action: 'privilege_escalation',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    userAgent: req.get('user-agent'),
    body: { ip: normalizedIP, type },
    success: false,
    riskLevel: 'critical',
    riskFactors: ['full_range_cidr_attempt'],
    reason: `尝试将 ${normalizedIP} 加入${type === 'black' ? '黑' : '白'}名单（加入后覆盖全部 ${scope} 地址），权限不足`,
  });
  ApiResponse.codeError(res, 'FULL_RANGE_FORBIDDEN', {
    message: `该条目加入后，名单中的网段组合将覆盖全部 ${scope} 地址，会命中所有 IP；仅超级管理员可配置。如需限制特定范围请使用更精确的网段`,
    params: { ip: normalizedIP },
  });
  return true;
};

/**
 * 段写入护栏：加黑网段与 pool-ban 同一套判据（自伤/活跃流量/打字确认）。加白不走（只放行、
 * 不切业务，拦了没法解误封）；单地址不走（无"封段"语义）。
 *
 * **豁免只认「这一条本身是 /0」**，不认「并集铺满」：两者是不同判据。并集铺满说明"这条
 * 写下去会让名单覆盖整个地址族"——那正是更需要看活跃流量的场合，不是豁免理由。两者混用
 * 的实测后果：已有 128.0.0.0/1 时写 0.0.0.0/1（罩住一半 IPv4、含调用者自己）一路 200，
 * 而同样的 0.0.0.0/1 在名单为空时会被拒——**是否被拦取决于名单里已有什么**，判据自相矛盾。
 *
 * 而 /0 本身确实必须豁免：自伤与活跃流量两条对 /0 恒为真（任何请求都在 /0 里），照查等于
 * 永久拒绝，把"仅超管可配全网段"变成死代码。这类条目由 guardFullRangeCIDR 收口
 * （超管判定 + critical 审计），两侧不重叠。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const guardSegmentWrite = async (req, res, { normalizedIP, type, typedConfirm }) => {
  if (type !== 'black' || !normalizedIP.includes('/') || isFullRangeCIDR(normalizedIP))
    return false;
  const refusal = await segmentWriteRefusal({
    cidr: normalizedIP,
    operatorIp: normalizeIP(clientIpForSecurityDecision(req)),
    typedConfirm,
  });
  if (!refusal) return false;
  ApiResponse.codeError(res, 'IP_SEGMENT_WRITE_REFUSED', { params: { reason: refusal } });
  return true;
};

module.exports = { coveredFamiliesOf, guardFullRangeCIDR, guardSegmentWrite };
