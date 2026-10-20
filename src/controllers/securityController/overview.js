/**
 * 安全管理控制器 · 概览面（安全统计 / 概览 / 最近告警 / 合规指标块）
 * （2026-10-19 批 3c-3 自 controllers/securityController.js 原样迁出，纯搬家不改语义）
 */

const { AuditLog } = require('./shared');
const ApiResponse = require('../../utils/apiResponse');
const { applyAuditDataScope } = require('../../services/auditScopeFilter');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { RETENTION_DAYS, wasAdjusted: retentionWasAdjusted } = require('../../constants/retention');
const { businessDayBounds } = require('../../constants/timezone');
// 高危档取自 constants/audit.js 由有序等级表切出的同一段（F-149）：概览这里的"高风险操作次数"
// 与告警取数、审计页 level=error、行为基线 highRisk 必须同进同退，各抄一份字面量就会分叉。
const { AUDIT_RISK_LEVELS, AUDIT_ERROR_RISK_LEVELS } = require('../../constants/audit');
// 安全建议码表（i18n）：后端只出稳定码，文案归前端词表——原先这里直接拼中文句子，
// 英文界面下无从翻译。见 constants/securitySuggestions.js 文件头。
const { SECURITY_SUGGESTION_CODES } = require('../../constants/securitySuggestions');

/**
 * 获取系统安全统计
 * GET /api/security/stats
 */
const getSecurityStats = asyncHandler(async (req, res) => {
  // 「今日」起点统一取业务时区零点（单一声明 businessDayBounds）：
  // 原 setHours(0,0,0,0) 依赖服务器本地时区（容器 TZ=Asia/Shanghai 时碰巧正确，
  // 但裸跑/改 TZ 即漂移），与 auditMonitor 告警频控、仪表盘/报表的「今日」
  // 存在分叉隐患。businessDayBounds().start 与全站「今日」口径同源。
  const { start: today } = businessDayBounds();

  // 今日登录统计
  const todayLogins = await AuditLog.countDocuments({
    category: 'auth',
    action: 'login_success',
    timestamp: { $gte: today },
  });

  // 今日失败登录统计
  const todayFailedLogins = await AuditLog.countDocuments({
    category: 'auth',
    action: 'login_failed',
    timestamp: { $gte: today },
  });

  // 高风险操作统计
  const highRiskOps = await AuditLog.countDocuments({
    riskLevel: { $in: AUDIT_ERROR_RISK_LEVELS },
    timestamp: { $gte: today },
  });

  // 异常行为检测
  // 两路聚合都按 userId 分组，返回体里就是"哪些用户"——与 /security/alerts 的行级
  // 列表同性质，故走同一个范围翻译器（口径见 F-B12）。上方的今日登录/高危次数是
  // 全局聚合，是否随范围收窄属另一条口径，此处未动。
  const { query: anomalyScope } = await applyAuditDataScope({}, req.user.userId);
  const anomalies = await AuditLog.detectAnomalies({
    windowMinutes: 60,
    threshold: 5,
    scopeFilter: anomalyScope,
  });

  // 被封禁 IP 数量
  // （实际应从 Redis 或其他存储中获取）

  return ApiResponse.success(
    res,
    {
      overview: {
        todayLogins,
        todayFailedLogins,
        highRiskOperations: highRiskOps,
      },
      anomalies: {
        failedOperationUsers: anomalies.failedOperations,
        unusualTimeUsers: anomalies.unusualTimeOperations,
      },
      securityLevel: todayFailedLogins > 20 || highRiskOps > 10 ? 'high' : 'normal',
    },
    '获取成功'
  );
});

/**
 * 概览对象的形状校验：不合法就直接写出响应并返回 true。
 *
 * 两条判据各自独立（先判"是不是对象"，再判"三个计数是不是数字"），
 * 顺序不能合并——合并后一个 null 会同时命中两条，错误码就分不清了。
 * 码字面量必须留在 codeError 调用的**第二个实参**位置上（写成字符串字面量）：改成"返回错误码字符串、
 * 由调用方 codeError(res, shapeError)"会让 `emittedErrorCodeCoverage` 的提取器
 * 看不见这两个码，它们会被误判成死码。
 *
 * @returns {boolean} true 表示已拒绝并写出响应（调用方应立即 return）
 */
const rejectMalformedOverview = (overview, res) => {
  if (!overview || typeof overview !== 'object') {
    ApiResponse.codeError(res, 'SECURITY_OVERVIEW_FORMAT_INVALID');
    return true;
  }
  // 验证必要的字段
  if (
    typeof overview.criticalAlerts !== 'number' ||
    typeof overview.highAlerts !== 'number' ||
    typeof overview.failedLogins !== 'number'
  ) {
    ApiResponse.codeError(res, 'SECURITY_OVERVIEW_STRUCTURE_INVALID');
    return true;
  }
  return false;
};

/** 非负钳位与缺省值（原实现逐字段展开，取值口径不变） */
const clampOverviewNumbers = (overview) => {
  // 添加默认值
  overview.period = overview.period || `${7}天`;
  // 确保所有数字字段都是非负数
  overview.criticalAlerts = Math.max(0, overview.criticalAlerts);
  overview.highAlerts = Math.max(0, overview.highAlerts);
  overview.failedLogins = Math.max(0, overview.failedLogins);
  // 添加额外的安全指标
  overview.unusualAccess =
    typeof overview.unusualAccess === 'number' ? Math.max(0, overview.unusualAccess) : 0;
  // L-03/riskScore 以 securityAlert.getSecurityOverview 的计算为准
  // （unusualAccess 系数 5）。此前控制器用系数 3 整个重算覆盖，两处口径
  // 漂移后改哪处都会被另一处静默抵消。此处仅做边界钳位，不再重算。
  overview.riskScore = Math.min(
    100,
    Math.max(0, typeof overview.riskScore === 'number' ? overview.riskScore : 0)
  );
};

/** 安全建议：三条阈值各自独立，顺序固定（前端按数组顺序展示） */
const buildOverviewSuggestions = ({ riskScore, failedLogins, unusualAccess }) => {
  const suggestions = [];
  if (riskScore > 70) {
    suggestions.push(SECURITY_SUGGESTION_CODES.HIGH_RISK_SCORE);
  }
  if (failedLogins > 10) {
    suggestions.push(SECURITY_SUGGESTION_CODES.EXCESSIVE_FAILED_LOGINS);
  }
  if (unusualAccess > 5) {
    suggestions.push(SECURITY_SUGGESTION_CODES.UNUSUAL_TIME_ACCESS);
  }
  return suggestions;
};

/**
 * 合规指标块（阶段5.1）：审计日志合规就绪度，供合规仪表盘展示。
 *
 * 整块自带 try/catch：取不到就降级成 `{ error }`，而不是让外层把整个概览
 * 变成 500——面板上"合规项取不到"远好过"安全概览整个打不开"。
 */
const buildComplianceSection = async () => {
  try {
    const { getLatestHash } = require('../../utils/auditChain');
    const auditMonitor = require('../../services/auditMonitor');
    const auditBuffer = require('../../services/auditBuffer');
    // 同一文件的模型入口已由 shared 提供；此处复用，不再二次 require（A-4）
    const AuditLogModel = AuditLog;
    const chainTailHash = await getLatestHash(AuditLogModel);
    return {
      // 对外展示的必须是**实际生效值**而非原始配置值。
      // 原实现 `parseInt(...) || 180` 会把 AUDIT_RETENTION_DAYS=1 如实报成 1，
      // 而数据库 TTL 实为 90 天——合规仪表盘与真实留存不一致，两种方向都危险：
      // 报低了让人误以为不合规去调参，报高了则是对外虚假声明
      retentionDays: RETENTION_DAYS,
      // 配置被钳制/回退时一并暴露，让运维知道自己的配置未被原样采用
      retentionConfigAdjusted: retentionWasAdjusted,
      // 原先这里写死 `appendOnlyEnforced: true`——防篡改护栏的真实状态是
      // models/auditLogHooks.js 里的闭包变量（测试环境可关），而对外合规面板
      // 把它当事实陈述。现在读实际生效值；getter 缺失时让整块落到 catch 报
      // `error`（宁可报"取不到"，也不报一个编出来的 true）。
      appendOnlyEnforced: AuditLogModel.isAppendOnlyEnforced(),
      monitorRunning:
        typeof auditMonitor.isRunning === 'function' ? auditMonitor.isRunning() : false,
      // F-125：isRunning() 只回答"定时器挂着没有"，回答不了"检测有没有在成功跑"。
      // 定时任务最常见的静默失效形态是「面板说活着、实际每轮都失败」，
      // 而 runs/failures/consecutiveFailures/skippedOverlaps 此前只有测试能读
      // ——与本块 auditLoss 修的是同一个缺陷类（有指标、无出口）。
      // 兜底走 null 而不是让它抛：这里抛 TypeError 会把整段 compliance
      // （留存天数/链尾哈希/丢失计数）一起降级成 `{error}`，代价远大于一个字段。
      monitorHealth: typeof auditMonitor.getHealth === 'function' ? auditMonitor.getHealth() : null,
      walEnabled:
        typeof auditBuffer.isWalEnabled === 'function' ? auditBuffer.isWalEnabled() : false,
      // 审计导出没有运行期开关（路由恒挂载），所以这个键不携带信息量；
      // 保留是为了不打破既有消费方，读它的人应当知道它恒为 true。
      exportEnabled: true,
      // F-215：原先写 `!!process.env.LOG_SHIPPING_URL`。那个表达式回答的是
      // "配过这么个变量"，不是"日志正在往 SIEM 送"：变量写成不可解析的串时
      // transport 仍会挂载成功、启动日志仍会打「日志转发已启用」，面板再说一遍
      // 同一个误判没有任何价值（三个取值实测见 utils/logger.js 的 F-215 注释）。
      // 现在读挂载态，判据与邻居 walEnabled / monitorRunning 同口径。
      shippingEnabled:
        typeof logger.isShippingEnabled === 'function' ? logger.isShippingEnabled() : false,
      chainTailHash: chainTailHash || null,
      // 「有没有永久缺失的审计」此前只有测试能读（getStats 无生产读取方）。
      // 合规面板是这些指标唯一该有的地方：任何一项 >0 都意味着有一份需要取证的
      // 完整性缺口（各键的确切含义见下方逐项注释——有的是"已丢"，有的是"会重复"）。
      auditLoss: (() => {
        const s = auditBuffer.getStats();
        return {
          droppedCount: s.droppedCount,
          walDroppedLines: s.walDroppedLines,
          walDiscardedLines: s.walDiscardedLines,
          // 解析不出文档的 WAL 行：不重放也裁不掉，每次重启原地重复出现。
          // 少了这一项，"证据在 WAL 里但永远进不了库"这条失踪路径仍是 0。
          walCorruptLines: s.walCorruptLines,
          // WAL 追加失败：这一项 >0 说的是"崩溃保护层已经失效"，不是"已经丢了"——
          // 记录仍在内存缓冲里，落库成功就无损；但落库前进程退出就是永久缺失，
          // 所以它和上面几项一样需要取证。缺了它，面板会在磁盘根本写不进去时
          // 仍然报 walEnabled: true（追加失败的证据只有一行 warn 日志）。
          walAppendFailures: s.walAppendFailures,
          // 重放补号回写失败：口径与上面几项**不同**——它不是"已经少了记录"，
          // 而是"文件里那批行仍然没有身份，下次重启会被当成新记录再落一份"
          // （重复行 + 哈希链分叉）。放在同一块里是因为运维动作同类：取 WAL 原件核查。
          walRewriteFailures: s.walRewriteFailures,
          // F-217：裁剪侧失败。口径与上面三项都不同——它既不是"少了一条记录"也不是
          // "那批行没有身份"，而是"50MB 硬上限已经越过而这一轮什么都没省下"，
          // 也就是 R-6 正在静默失效（WAL 无界增长）。缺了它，面板在
          // walEnabled:true + 三个计数全 0 时无法与"上限从未被触碰"区分。
          walTrimFailures: s.walTrimFailures,
          outageFailures: s.outageFailures,
        };
      })(),
      // 哨兵用户名（canary）检测状态：count/fromEnv/checked/shadowed/configErrors。
      // checked=false（对账未跑或失败）与 shadowed 非空（名单名被真实账户占用）
      // 都意味着幽灵名检测可能静默失效——此前这类状态只活在启动日志里，
      // 合规面板是它该有的出口（同 monitorHealth 的口径）。
      canaryWatch: (() => {
        const canaryWatch = require('../../services/canaryWatch');
        return canaryWatch.getStatus();
      })(),
    };
  } catch (e) {
    return { error: '合规指标获取失败' };
  }
};

/**
 * 获取安全概览
 * GET /api/security/overview
 */
const getSecurityOverview = asyncHandler(async (req, res) => {
  try {
    const securityAlert = require('../../services/securityAlert');
    const overview = await securityAlert.getSecurityOverview(7);
    // A-2：服务层查询失败时返回 degraded，而不是补齐全 0 字段。必须先于形状校验：
    // 让「数据不可用」显式表现为 503，而不是一张写着 0 风险的面板。
    if (overview && overview.degraded === true) {
      return ApiResponse.codeError(res, 'SECURITY_OVERVIEW_DEGRADED', {
        params: { degraded: true },
      });
    }
    if (rejectMalformedOverview(overview, res)) {
      return;
    }
    clampOverviewNumbers(overview);
    // 添加时间戳（不包含服务器环境信息，防止信息泄露）
    overview.updatedAt = new Date().toISOString();
    overview.version = '1.0.0';
    // 添加安全建议
    overview.suggestions = buildOverviewSuggestions(overview);
    // 原 summary.successRate = (四类事件总数 - 失败登录数) / 总数，
    // 分母混入了告警数——criticalAlerts=100、failedLogins=10 时显示 90.9%，
    // 这个"成功率"没有任何可解释的业务含义（概览里根本没有成功登录计数），
    // 且全仓无任何消费者。直接移除，而非补查询去圆一个伪指标。
    // 添加性能指标
    overview.performance = {
      lastQueryTime: 0, // 后续可以添加实际查询时间
      avgResponseTime: 0, // 后续可以添加平均响应时间
      maxConcurrentConnections: 0, // 后续可以添加最大并发连接数
    };
    overview.compliance = await buildComplianceSection();
    return ApiResponse.success(res, overview, '获取成功');
  } catch (error) {
    logger.error(`安全概览查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'SECURITY_OVERVIEW_QUERY_FAILED');
  }
});

/**
 * 获取最近安全告警
 * GET /api/security/alerts
 */
const getRecentAlerts = asyncHandler(async (req, res) => {
  try {
    const securityAlert = require('../../services/securityAlert');
    // 多取 1 条用于探测是否还有更多：固定取 50 时 hasMore 恒为 false，分页探测失效
    const ALERTS_PAGE_SIZE = 50;
    const alertsRaw = await securityAlert.getRecentAlerts(ALERTS_PAGE_SIZE + 1, req.user.userId);
    if (!alertsRaw || !Array.isArray(alertsRaw)) {
      return ApiResponse.codeError(res, 'RECENT_ALERTS_EMPTY');
    }
    // 据实计算 hasMore 后再截断到页大小，保证返回体与元数据一致
    const hasMore = alertsRaw.length > ALERTS_PAGE_SIZE;
    const alerts = alertsRaw.slice(0, ALERTS_PAGE_SIZE);
    // 修复：仅校验结构性必需字段（_id/timestamp/action）。
    // 原 15 字段全量非空强校验会把缺少任一可选字段（userAgent/statusCode/duration 等）
    // 的合法告警静默丢弃，造成安全告警漏报（监控盲区）。
    const validAlerts = alerts
      .filter(
        (alert) =>
          alert && typeof alert === 'object' && alert._id && alert.timestamp && alert.action
      )
      .map((alert) => ({
        // 先展开原始告警，再对缺失的可选字段兜底，保证前端渲染稳定
        ...alert,
        category: alert.category || 'unknown',
        username: alert.username || 'anonymous',
        riskLevel: alert.riskLevel || 'low',
        ip: alert.ip || '-',
        riskFactors: alert.riskFactors || [],
        statusCode: alert.statusCode ?? 0,
        success: alert.success !== undefined ? alert.success : true,
        duration: alert.duration ?? 0,
        userAgent: alert.userAgent || '-',
        method: alert.method || '-',
        path: alert.path || '-',
      }));
    // 按时间倒序排序
    validAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    // 限制返回数量
    const limitedAlerts = validAlerts.slice(0, ALERTS_PAGE_SIZE);
    // 计算统计摘要：档位键由 AUDIT_RISK_LEVELS 派生（F-149）。原先四行手写 filter，
    // 给等级表加一档就会漏计（total 里算它、四个桶里都没有 ⇒ 摘要之和 ≠ total）。
    // 键序随派生表变成 low→critical（手写版是反的）：本仓前端没有读这个 summary 的地方，
    // 对外契约仍按同名键提供，顺序不承载信息。
    const summary = {
      ...Object.fromEntries(
        AUDIT_RISK_LEVELS.map((level) => [
          level,
          validAlerts.filter((a) => a.riskLevel === level).length,
        ])
      ),
      total: validAlerts.length,
    };
    // 添加元数据
    const response = {
      data: limitedAlerts,
      meta: {
        total: limitedAlerts.length,
        page: 1,
        limit: ALERTS_PAGE_SIZE,
        hasMore,
        lastUpdated: new Date().toISOString(),
        count: limitedAlerts.length,
        summary,
      },
    };
    return ApiResponse.success(res, response, '获取成功');
  } catch (error) {
    // 数据范围不可用（403 DATA_SCOPE_DENIED）必须原样上冒：包成 500 会让
    // "这个账号没有可见范围"表现为"服务端故障"，客户端于是重试一个永远不会
    // 成功的请求，而运维照 500 去查数据库。只有真实故障才折算成
    // RECENT_ALERTS_QUERY_FAILED（原行为不变）。
    if (error.isApiError) throw error;
    logger.error(`最近告警查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'RECENT_ALERTS_QUERY_FAILED');
  }
});

/**
 * ⚠ 已知不一致（本次不改，待统一）：
 * queryAuditLogs / exportAuditLogs / getRecentAlerts 返回体为 { data: {...}, meta } 结构，
 * 经 ApiResponse.success 再包一层后出现 data.data 双层信封，
 * 与其他接口的单层 data 信封不一致；属 API 契约变更，需与前端协同后统一调整。
 */

module.exports = {
  getSecurityStats,
  getSecurityOverview,
  getRecentAlerts,
};
