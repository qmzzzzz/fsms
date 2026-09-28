/**
 * 请求协议合规校验中间件
 *
 * 目的：在业务逻辑之前拦截畸形/非预期的 HTTP 请求，减少下游解析器与控制器
 * 需要处理的异常输入面。属于应用层的轻量「协议净化」，不替代 WAF。
 *
 * 校验项（均可通过 options 关闭或调整）：
 * 1. Content-Type：写操作（POST/PUT/PATCH）必须声明受支持的媒体类型
 * 2. Content-Length：声明值不得超过上限（早于 body 解析即拒绝，避免无谓读流）
 * 3. 请求头卫生：拒绝头部数量异常、单个头部超长、头名非法的请求
 * 4. HTTP 方法白名单：拒绝 TRACE/TRACK/CONNECT 等无业务用途且易被滥用的方法
 * 5. Host 头校验：配置了允许列表时，拒绝 Host 不匹配的请求（防 Host 头注入）
 *    —— 其余四项只有「探针请求」一档整体豁免，判据在 constants/probePaths 的
 *       isProbeRequest（精确路径 + GET/HEAD，不是路径前缀）；Host 另有一份
 *       "只免这一项"的清单（HOST_GATE_EXEMPT_PATHS，判据与安全论证见其定义处）
 *
 * 所有拒绝均记录 warn 级日志并写审计（category=security），便于统计畸形请求趋势。
 */

const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { auditPath } = require('../utils/auditMeta');
// 本文件写的是**认证前、限流后**的协议违规记录（app.js 把 ipLimiter/generalLimiter 挂在
// applyPreBodySecurity 之前，且两个限流器现已按全站挂载）。配额掐住的是"每 IP 每窗口能发多少条"，
// 管不了"过闸的那几条每条都写一次链上审计"——而 user-agent 与 Content-Type 都是攻击者全控的
// 原始字节，却直接进了不可篡改的 AuditLog 与访问日志。姊妹路径 recordEarlyRejection 一直
// 在做 stripControlChars(x,512)，这里漏了——同一类写入两种口径。
const { stripControlChars, redactUrlQuery } = require('../utils/helpers');
const { isProbeRequest } = require('../constants/probePaths');
// T-1：顶层引入——下方 setImmediate 回调属 fire-and-forget，可能在测试环境
// 销毁后才执行，届时惰性 require 会抛「import after torn down」
const AuditLog = require('../models/AuditLog');
const { computeFingerprint } = require('../utils/fingerprint');

// 允许的媒体类型（写操作）
const DEFAULT_ALLOWED_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  // G9：浏览器上报 CSP 违规时固定使用这两种媒体类型，不受调用方控制；
  // 不放行会让上报请求全部被 415 拦掉，report-uri 形同虚设
  'application/csp-report',
  'application/reports+json',
];

// 明确禁止的 HTTP 方法：无业务用途，历史上多次成为跨站追踪/代理滥用的载体
const FORBIDDEN_METHODS = ['TRACE', 'TRACK', 'CONNECT'];

/**
 * 只豁免 Host 一项校验的路径（精确等值，不是前缀）。
 *
 * 为什么 `/metrics` 必须在列（实测结论，不是推测）：Prometheus 的抓取目标是容器服务名
 * （`deployment/observability/prometheus.yml` 的 `targets: ['app:3000']`，发出的
 * Host 就是 `app:3000`），而 compose 强制 `ALLOWED_HOSTS` 只填对外域名
 * （`ALLOWED_HOSTS=${ALLOWED_HOSTS:?...}`）。两侧永不相交 ⇒ 每一次抓取都被判
 * `HOST_HEADER_INVALID` 400 ⇒ `up{job="xf-app"} == 0` 恒成立：按 `up` 判定的
 * BackendDown 永久告警（告警疲劳会把真告警淹掉），而所有**基于指标**的告警
 * （错误率、审计链、登录突增）根本没有数据流进时序库、永不触发。
 * 同一条件下 `/health`、`/readyz` 一直是 200（它们走探针豁免，判据见 constants/probePaths）——
 * 这个不对称就是本条的线索来源。
 *
 * 为什么豁免是安全的：
 *   1. 只豁免 Host。方法白名单、头名/头值卫生、Content-Length 上限对 `/metrics` 照常生效；
 *      也**不**并进探针豁免清单（`constants/probePaths` 的 `PROBE_PATHS`）——那份清单
 *      同时是两处限流器的 skip 依据，并进去等于把 `/metrics` 变成不限流的公开端点。
 *   2. `/metrics` 自己的闸门与 Host 无关：`middleware/metricsAuth` 用的是
 *      `req.socket.remoteAddress`（不可伪造的连接地址）或 Bearer 令牌，
 *      本豁免碰不到它，公网来源照旧 401。
 *   3. Host 头注入在这条路径上没有输出面：响应体是 Prometheus 文本格式，
 *      不反映射 Host（用例逐字比对"换 Host 后响应里不出现新 Host"钉住这一点；
 *      若将来有人把 Host 写进标签，那条用例会先红）。
 *
 * 判定口径：大小写无关（查 Set 前先转小写），但**精确等值**而不是前缀——前缀语义
 * 会让 `/metrics/../api/devices` 这类「以豁免路径开头」的形态一并逃掉 Host 闸门
 * （实测：改成前缀后该形态从 400 HOST_HEADER_INVALID 变成 404，即闸门对它已不再生效）。
 * 尾斜杠形态 `/metrics/` 不豁免：方向是 fail-closed（多要一次 Host 校验），
 * 而 Prometheus 的 `metrics_path` 默认就是精确的 `/metrics`。
 *
 * 刻意不开放成 options/env：放宽一份安全豁免清单应当需要改代码并过一次评审，
 * 而不是某个环境变量悄悄写宽一档。
 */
const HOST_GATE_EXEMPT_PATHS = new Set(['/metrics']);

// 需要 Content-Type 声明的方法
// 写方法清单全仓只有一份（originCheck 导出）。本文件此前自列 3 项、少 DELETE，
// 而 express.json 对 DELETE 同样解析 body ⇒ 携带 JSON 载荷的 DELETE 跳过媒体类型闸门，
// 两道防线对同一种请求的口径相反。
const { WRITE_METHODS: BODY_METHODS } = require('./originCheck');

// 合法 HTTP 头名字符集（RFC 7230 token）
const VALID_HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * 记录协议违规审计（异步，不阻塞拒绝响应）
 */
const recordViolation = (req, violation, detail) => {
  logger.warn('协议合规校验拒绝', {
    violation,
    detail: stripControlChars(detail, 512),
    method: req.method,
    url: redactUrlQuery(req.originalUrl),
  });

  setImmediate(() => {
    try {
      AuditLog.record({
        action: 'malformed_request_blocked',
        category: 'security',
        userId: req.user?.userId,
        username: req.user?.username || 'anonymous',
        sessionId: req.user?.sessionId || null,
        fingerprint: computeFingerprint(req),
        // method 原样交下去即可：取值全集与"越枚举怎么办"由 AuditLog schema
        // （constants/audit.js 的 AUDIT_HTTP_METHODS + setter）单点决定。
        // 原先这里私抄一份 5 动词白名单，与另两处写入点各自漂移。
        method: req.method,
        path: auditPath(req),
        ip: req.ip,
        userAgent: stripControlChars(req.get('user-agent'), 512),
        success: false,
        riskLevel: 'medium',
        riskFactors: ['protocol_violation', violation],
        reason: stripControlChars(detail, 512),
      });
    } catch (e) {
      logger.debug(`协议违规审计写入跳过：${e.message}`);
    }
  });
};

/**
 * 协议合规校验中间件工厂
 *
 * @param {object} options
 * @param {string[]} [options.allowedContentTypes] 允许的写操作媒体类型
 * @param {number} [options.maxContentLength] Content-Length 上限（字节），默认 10MB
 * @param {number} [options.maxHeaderCount] 头部数量上限，默认 60
 * @param {number} [options.maxHeaderValueLength] 单个头部值长度上限，默认 8192
 * @param {string[]} [options.allowedHosts] 允许的 Host（含端口），为空则不校验
 */
const protocolCompliance = (options = {}) => {
  const {
    allowedContentTypes = DEFAULT_ALLOWED_CONTENT_TYPES,
    maxContentLength = 10 * 1024 * 1024,
    maxHeaderCount = 60,
    maxHeaderValueLength = 8192,
    allowedHosts = (process.env.ALLOWED_HOSTS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  } = options;

  return (req, res, next) => {
    const fullPath = auditPath(req);

    // 探针豁免（与两处限流器读同一份 constants/probePaths 判据，不在这里抄第二份）：
    // P3-35：原默认值含 '/api/health'——本服务的健康检查挂在根路径 '/health'
    // （见 app.js 的 app.get('/health')），'/api/health' 从不存在，是死配置。
    // 死配置的危害不只是冗余：它让人误以为「健康检查已全部豁免」，
    // 若日后新增 /api/health 而忘记回看这里，会得到一个意外豁免的端点
    //
    // '/readyz' 必须同列：部署门禁（scripts/deploy.js）与容器健康检查都用
    // `curl http://127.0.0.1:<port>/readyz` 探活，其 Host 头是 `127.0.0.1:<port>`。
    // 一旦按加固要求配了 ALLOWED_HOSTS（只填对外域名），Host 白名单会把这条
    // 本机探针判成 HOST_HEADER_INVALID=400 ⇒ 门禁对完全健康的新版本恒红并自动回滚。
    //
    // 判据从 `matchesAnyPathPrefix(skipPaths, …)` 收成 `isProbeRequest(method, path)`：
    // 前缀 + 不看方法时，`/health` 一名把整个 `/health/...` 子树连同 POST 一起免检，
    // 而本闸门的 Content-Length/Content-Type/头部卫生/方法白名单四项正是挡 body 解析
    // 放大的（app.js 把它挂在 express.json 之前的理由）。与路由同尺这一点保留：
    // `GET /HEALTH` 真实命中 `/health` 的处理，大小写不敏感的判定必须跟着走。
    if (isProbeRequest(req.method, fullPath)) {
      return next();
    }

    // 1. HTTP 方法白名单
    if (FORBIDDEN_METHODS.includes(req.method)) {
      recordViolation(req, 'forbidden_method', `方法 ${req.method} 不被允许`);
      return ApiResponse.codeError(res, 'HTTP_METHOD_UNSUPPORTED', {
        message: `不支持的请求方法：${req.method}`,
        params: { method: req.method },
      });
    }

    // 2. 请求头卫生检查
    const headerNames = Object.keys(req.headers || {});
    if (headerNames.length > maxHeaderCount) {
      recordViolation(
        req,
        'excessive_headers',
        `头部数量 ${headerNames.length} 超过上限 ${maxHeaderCount}`
      );
      return ApiResponse.codeError(res, 'HEADER_COUNT_EXCESSIVE');
    }

    for (const name of headerNames) {
      // Node 已将头名小写化，此处校验字符集，拦截含控制字符/空格的畸形头名
      if (!VALID_HEADER_NAME.test(name)) {
        recordViolation(req, 'invalid_header_name', `非法头名：${name.slice(0, 64)}`);
        return ApiResponse.codeError(res, 'HEADER_NAME_INVALID');
      }
      const value = req.headers[name];
      const len = Array.isArray(value)
        ? value.reduce((sum, v) => sum + String(v).length, 0)
        : String(value ?? '').length;
      if (len > maxHeaderValueLength) {
        recordViolation(req, 'oversized_header', `头部 ${name} 长度 ${len} 超过上限`);
        return ApiResponse.codeError(res, 'HEADER_VALUE_TOO_LONG');
      }
    }

    // 3. Host 头校验（防 Host 头注入导致的密码重置链接投毒等）
    //    豁免只作用于这一条校验，判据与安全论证见 HOST_GATE_EXEMPT_PATHS
    if (allowedHosts.length > 0 && !HOST_GATE_EXEMPT_PATHS.has(fullPath.toLowerCase())) {
      const host = req.get('host');
      if (!host || !allowedHosts.includes(host)) {
        recordViolation(req, 'host_mismatch', `Host 头 ${host || '(空)'} 不在允许列表内`);
        return ApiResponse.codeError(res, 'HOST_HEADER_INVALID');
      }
    }

    // 4. Content-Length 上限（早于 body 解析拒绝）
    const contentLengthRaw = req.get('content-length');
    if (contentLengthRaw !== undefined) {
      const contentLength = Number(contentLengthRaw);
      if (!Number.isFinite(contentLength) || contentLength < 0) {
        recordViolation(
          req,
          'invalid_content_length',
          `Content-Length 值非法：${contentLengthRaw}`
        );
        return ApiResponse.codeError(res, 'CONTENT_LENGTH_INVALID');
      }
      if (contentLength > maxContentLength) {
        recordViolation(
          req,
          'payload_too_large',
          `Content-Length ${contentLength} 超过上限 ${maxContentLength}`
        );
        return ApiResponse.codeError(res, 'PAYLOAD_TOO_LARGE');
      }
    }

    // 5. Content-Type 校验（仅对携带 body 的写操作）
    if (BODY_METHODS.includes(req.method)) {
      const contentLength = Number(req.get('content-length') || 0);
      // Transfer-Encoding 的值大小写不敏感（RFC 9110：token 大小写不敏感，
      // Node 只归一头部名不归一值），且可以是列表（`gzip, chunked`）。
      // 用严格 === 'chunked' 会让 `Transfer-Encoding: Chunked` 被当成"无 body"，
      // 从而跳过 Content-Type 声明要求——正是本条规则要拦的请求形态。
      const hasChunked = String(req.get('transfer-encoding') || '')
        .split(',')
        .some((token) => token.trim().toLowerCase() === 'chunked');
      const hasBody = contentLength > 0 || hasChunked;

      if (hasBody) {
        const contentType = req.get('content-type');
        if (!contentType) {
          recordViolation(req, 'missing_content_type', `${req.method} 请求未声明 Content-Type`);
          return ApiResponse.codeError(res, 'CONTENT_TYPE_MISSING');
        }
        // 只取媒体类型部分，忽略 charset / boundary 等参数
        const mediaType = contentType.split(';')[0].trim().toLowerCase();
        if (!allowedContentTypes.includes(mediaType)) {
          recordViolation(req, 'unsupported_media_type', `不支持的 Content-Type：${mediaType}`);
          return ApiResponse.codeError(res, 'CONTENT_TYPE_UNSUPPORTED', {
            message: `不支持的 Content-Type：${mediaType}`,
            params: { mediaType: mediaType },
          });
        }
      }
    }

    next();
  };
};

module.exports = {
  protocolCompliance,
  DEFAULT_ALLOWED_CONTENT_TYPES,
  FORBIDDEN_METHODS,
};
