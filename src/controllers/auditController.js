/**
 * 审计日志控制器（D-1 自 securityController 拆出）
 *
 * 审计日志的查询、流式导出（CSV + 签名 manifest）与哈希链完整性校验。
 * action 白名单枚举以 constants/audit.js 为单一事实来源。
 */

const AuditLog = require('../models/AuditLog');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler, markResponseAbortedByError } = require('../middleware/errorHandler');
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
const { onAuditWriteFailure } = require('../utils/auditWriteFailure');

const exportAuditLogs = asyncHandler(async (req, res) => {
  try {
    // 复用查询筛选逻辑
    let query;
    // 与列表接口同一口径：query 含 username 前缀条件时必须带 collation，
    // 否则导出会漏掉大小写不同的记录（默认 collation 下 `ADMIN` 不落在 `[adm, adn)` 内）。
    let collation = null;
    try {
      const built = buildAuditQuery(req);
      ({ query } = built);
      collation = built.usernamePrefix ? AuditLog.AUDIT_USERNAME_COLLATION : null;
    } catch (err) {
      return ApiResponse.error(res, err.message, 400);
    }

    if (!req.user || !req.user.userId) {
      return ApiResponse.codeError(res, 'UNAUTHORIZED_ACCESS');
    }

    ({ query } = await applyAuditDataScope(query, req.user.userId));

    await sendAuditExportHeaders(query, res, collation);
    res.write(`${EXPORT_CSV_HEADER}\n`);
    const counters = await streamAuditExport(query, res, collation);
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
    // 头部供程序化读取；尾部注释行让下载的文件自带摘要信息（Excel 打开时 # 行不产生错位）。
    // 取证时要验"文件有没有被删改"，用的是 `csvSha256`（覆盖表头行 + 全部数据行，
    // 不含本行）；`sha256` 只是记录链哈希的摘要，改单元格它也不会变（见
    // tests/services/auditExportManifestScope.test.js 的 ①②）。
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
    // 半截 CSV 不得被全局审计记成"成功导出"：登记截断事实（标记，或在记录已 latch 时
    // 追加更正事件）。必须在 res.end() **之前**调用——end 会触发 auditLog 的响应包装器。
    // 不外抛 next：本函数的"头已发出"出口按既有契约自行收尾（见
    // tests/controllers/auditExportStreamFailure.test.js），且 logger.error 已在此留痕。
    markResponseAbortedByError(req, res, error.message);
    res.end();
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
  const {
    verifyAuditChain,
    computeChainVerdict,
    DEFAULT_MAX_RECORDS,
  } = require('../services/auditChainVerify');

  const rawLimit = req.query.limit;
  if (rawLimit !== undefined && !/^\d+$/.test(String(rawLimit))) {
    return ApiResponse.codeError(res, 'LIMIT_MUST_BE_POSITIVE_INT');
  }
  const from = req.query.from;
  if (from !== undefined && !['latest', 'earliest'].includes(from)) {
    return ApiResponse.codeError(res, 'FROM_MUST_BE_LATEST_OR_EARLIEST');
  }

  // 在线核验的扫描上限：`limit` 参数只做过数字/枚举校验，此前一路透传到服务层的
  // HARD_MAX_RECORDS(200000)。而核验循环要对每条记录做 SHA-256 + 规范 JSON 序列化，
  // 20 万条会在**单个请求里把事件循环占住数十秒**（白名单 IP 还免 strictLimiter），
  // 同时 20 万条完整文档（含 body/params/query，且必须整档参与哈希重算，不能投影裁剪）
  // 会一次性进内存。脚本走服务层仍能用到 HARD 上限，HTTP 面收口到 DEFAULT。
  const requested = rawLimit ? parseInt(rawLimit, 10) : DEFAULT_MAX_RECORDS;
  const maxRecords = Math.min(requested, DEFAULT_MAX_RECORDS);

  const report = await verifyAuditChain(AuditLog, {
    maxRecords,
    fromLatest: from !== 'earliest',
  });

  // 「能否宣称链完整」用服务层的唯一判据（与运维脚本同源）。
  // report.intact 的字面意思只是"扫过的这些条没断"，它不蕴含三件必须蕴含的事：
  //   ① 扫全了（total 撞上 maxRecords 上限而库里还有更多 ⇒ 只是窗口结论）；
  //   ② 有东西可扫（集合为 0 条时 intact 恒真——绕过模型钩子直连 deleteMany({})
  //      就能造出这个现场，接口若回「审计链完整」等于为灭迹签发合格证明）。
  //      注意②的新口径是"扫到 0 条"而非只有"集合 0 条"：本接口的 collectionTotal
  //      在 scan **之后**才取，清空与并发写入交错即可让估算非 0 而扫描为空。
  //   ③ 扫的是全链而不是某个 filter 的子集（在线侧无 filter 输入，由服务层的
  //      scanned 回显兜住，判据统一挡）。
  // 在线接口刻意不给 allowNoHmac/allowEmpty 这两个豁免口子：那是运维脚本在
  // 知情前提下的一次性动作，不是一个可被反复调用的 HTTP 端点的默认能力。
  const collectionTotal = await AuditLog.estimatedDocumentCount();
  const verdict = computeChainVerdict({
    breaks: report.breaks,
    total: report.total,
    // 阈值用本请求算出的 maxRecords（服务层就是拿它做的窗口，回读嵌套结构只会更脆），
    // 但"这次到底扫了什么"取报告自带的 scanned：filter 只在服务层落地，
    // 由它回显才是事实来源，判据据此把子集校验挡在"完整"之外。
    maxRecords,
    collectionTotal,
    hmacChecked: report.hmacChecked,
    // 整窗无哈希（全 legacy）时不得背书：判据需要知道"扫到的 N 条里有多少条真的带 hash"，
    // 否则"整表 $unset 掉 hash/prevHash/hmac"会被 legacy 全数吸收而拿到 code=0。
    legacy: report.legacy,
    scanned: report.scanned,
  });

  // 断裂即安全事件：必须留痕并告警，不能只作为一次普通查询响应
  if (!report.intact) {
    // 分类计数按报告实际有哪些键打印，不在此硬编码清单：
    // 服务层新增 break 类型（如 hash_stripped）时硬编码那份会把该类断裂从告警里整个抹掉，
    // 于是"发现 N 处断裂"与逐项明细自相矛盾，读告警的人按明细去查就查不到。
    const breakdown = Object.entries(report.byType || {})
      .map(([type, count]) => `${type}=${count}`)
      .join(' ');
    logger.error(
      `审计链完整性校验发现 ${report.breaks} 处断裂（${breakdown}），` +
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
    // 只有判据给出 code=0（全量、无断裂、各层都真跑过、有记录可验）才有资格记 low：
    // 这条审计记录正是"事后证明完整性核验持续有效"的依据，把"没验成"记成 low
    // 等于让留存里出现一批名为核验、实为无证明的绿记录。
    riskLevel: verdict.canAttestIntact ? 'low' : 'high',
  }).catch(onAuditWriteFailure('audit_chain_verify', req));

  // 宣称给"人"看的结论与机器可读字段分开：intact/report 保持原语义，
  // 但话术必须自承不完整——与运维脚本的 INCOMPLETE 同一口径，两处不再各说各话。
  const verifyMessage = verdict.canAttestIntact
    ? '审计链完整'
    : report.breaks > 0
      ? '审计链存在断裂'
      : `审计链未发现断裂，但本次核验不构成完整性证明：${verdict.reasons.join('；')}`;

  // 判据必须**同时**进 payload：上面那句话只对读 message 的人成立。
  // data.intact 的字面意思仍是"扫过的这批没断"，而 Swagger 教的三个字段就是
  // intact/breaks/byType（docs/generate.js 的 ok('返回校验报告（intact/breaks/byType）')），
  // 所以按 data.intact 判绿的 CI 或前端，会在"一条都没验完"的链上签合格证。
  // 这里不复写 intact 的语义（改了会让既有消费方静默换含义），而是把否决结果
  // 并列给出，并带上分母 collectionTotal——没有分母，消费方无从知道扫了多少。
  return ApiResponse.success(
    res,
    {
      ...report,
      canAttestIntact: verdict.canAttestIntact,
      verdictCode: verdict.code,
      verdictReasons: verdict.reasons,
      collectionTotal,
    },
    verifyMessage
  );
});

module.exports = {
  queryAuditLogs,
  exportAuditLogs,
  verifyAuditChainIntegrity,
};
