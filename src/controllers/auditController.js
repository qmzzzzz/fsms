/**
 * 审计日志控制器（D-1 自 securityController 拆出）
 *
 * 审计日志的查询、流式导出（CSV + 签名 manifest）与哈希链完整性校验。
 * action 白名单枚举以 constants/audit.js 为单一事实来源。
 */

const AuditLog = require('../models/AuditLog');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const {
  buildAuditExportManifest,
  sendAuditExportHeaders,
  streamAuditExport,
  MANIFEST_LINE_PREFIX,
  EXPORT_CSV_HEADER,
} = require('../services/auditExportService');
const { buildAuditQuery } = require('../utils/auditQuery');
const { queryAuditLogs, applyAuditDataScope } = require('../services/auditQueryService');
const { auditPath } = require('../utils/auditMeta');

const exportAuditLogs = asyncHandler(async (req, res) => {
  try {
    // 复用查询筛选逻辑
    let query;
    try {
      ({ query } = buildAuditQuery(req));
    } catch (err) {
      return ApiResponse.error(res, err.message, 400);
    }

    if (!req.user || !req.user.userId) {
      return ApiResponse.codeError(res, 'UNAUTHORIZED_ACCESS');
    }

    ({ query } = await applyAuditDataScope(query, req.user.userId));

    await sendAuditExportHeaders(query, res);
    res.write(`${EXPORT_CSV_HEADER}\n`);
    const counters = await streamAuditExport(query, res);
    const manifest = buildAuditExportManifest(counters);

    // 批量导出检测：导出记录数超过阈值时触发高危审计与告警（补齐导出审计盲区）
    const { checkBulkExport } = require('../services/securityAlert');
    await checkBulkExport(
      req.user.userId,
      req.user.username,
      counters.recordCount,
      'audit_logs_export'
    );

    // manifest 以注释行追加在流末尾 + 响应头双通道：
    // 头部供程序化读取；尾部注释行让下载的文件自带签名信息（Excel 打开时 # 行不产生错位）
    // Record-count and truncation headers were set before the first stream chunk.
    res.write(`${MANIFEST_LINE_PREFIX}${JSON.stringify(manifest)}\n`);
    res.end();
    return undefined;
  } catch (error) {
    logger.error(`审计日志导出失败: ${error.message}`);
    // 流已开始后无法再改状态码发 JSON 错误，只能尽力结束响应
    if (!res.headersSent) {
      return ApiResponse.codeError(res, 'AUDIT_EXPORT_FAILED');
    }
    res.end();
    return undefined;
  }
});

/**
 * 校验审计日志哈希链完整性
 * GET /api/security/audit-logs/verify?limit=20000&from=latest|earliest
 *
 * 运行时可调用的完整性校验（此前只有离线脚本，链有效性从未被在线验证，
 * 「日志防篡改」属被动装饰性控制）。校验逻辑集中在 services/auditChainVerify.js，
 * 与运维脚本共用同一实现，避免两处口径漂移。
 */
const verifyAuditChainIntegrity = asyncHandler(async (req, res) => {
  const { verifyAuditChain, DEFAULT_MAX_RECORDS } = require('../services/auditChainVerify');

  const rawLimit = req.query.limit;
  if (rawLimit !== undefined && !/^\d+$/.test(String(rawLimit))) {
    return ApiResponse.codeError(res, 'LIMIT_MUST_BE_POSITIVE_INT');
  }
  const from = req.query.from;
  if (from !== undefined && !['latest', 'earliest'].includes(from)) {
    return ApiResponse.codeError(res, 'FROM_MUST_BE_LATEST_OR_EARLIEST');
  }

  const report = await verifyAuditChain(AuditLog, {
    maxRecords: rawLimit ? parseInt(rawLimit, 10) : DEFAULT_MAX_RECORDS,
    fromLatest: from !== 'earliest',
  });

  // 断裂即安全事件：必须留痕并告警，不能只作为一次普通查询响应
  if (!report.intact) {
    logger.error(
      `审计链完整性校验发现 ${report.breaks} 处断裂（` +
        `hash_mismatch=${report.byType.hash_mismatch} ` +
        `hmac_missing=${report.byType.hmac_missing} ` +
        `hmac_mismatch=${report.byType.hmac_mismatch} ` +
        `chain_break=${report.byType.chain_break}），` +
        `扫描 ${report.total} 条 by ${req.user.username}`
    );
  }

  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'audit_chain_verify',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    // 只记结论摘要，不记 samples（含 hash 明文，无需二次落库）
    body: { total: report.total, breaks: report.breaks, byType: report.byType },
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: report.intact ? 'low' : 'high',
  }).catch(() => {});

  return ApiResponse.success(res, report, report.intact ? '审计链完整' : '审计链存在断裂');
});

module.exports = {
  queryAuditLogs,
  exportAuditLogs,
  verifyAuditChainIntegrity,
};
