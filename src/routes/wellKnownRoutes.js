/**
 * 公共发现端点（无需认证）
 *
 * 1. GET /.well-known/security.txt —— RFC 9116 安全联络信息（G10）
 * 2. POST /csp-report —— CSP 违规上报接收端（G9）
 * 3. POST /client-errors —— 前端运行时异常/Web Vitals 上报接收端（G-1）
 *
 * 均挂在根路径而非 /api 下：security.txt 的路径由 RFC 固定，
 * CSP report-uri 亦需稳定路径；前端异常上报发生在用户会话可能已失效时
 * （401 跳转途中），不能要求认证头。因此它们不经过 /api/ 上挂载的
 * ipLimiter / generalLimiter / originCheck / auditLog，本文件内自带限流。
 */

const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');
const { stripControlChars } = require('../utils/helpers');
const { captureException, isSentryInitialized } = require('../middleware/sentry');

/**
 * CSP 上报专用限流：单 IP 5 分钟 60 条。
 * 上报由浏览器自动发起，一次页面加载可能连带多条违规，配额不能太紧；
 * 但该端点无认证且可被任意构造，必须限流以免成为日志放大器。
 */
const cspReportLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 60,
  keyGenerator: (req) => `csp-report:${req.ip}`,
  standardHeaders: false,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).end(),
});

/**
 * 上报体解析器：浏览器用 application/csp-report（Level 2）或
 * application/reports+json（Reporting API）提交，两者都不会被全局
 * express.json 接管。体积上限 16kb——上报结构固定且很小，
 * 更大的载荷只可能是滥用。
 */
const cspReportParser = express.json({
  type: ['application/csp-report', 'application/reports+json', 'application/json'],
  limit: '16kb',
});

// 上报字段截断长度：blocked-uri 等字段可含超长 data: URI。
// 控制字符清洗复用 helpers.stripControlChars（与审计写入同口径），
// 避免上报内容伪造多行日志
const truncate = (value, max = 256) => {
  if (value === undefined || value === null) return undefined;
  const s = stripControlChars(String(value), max + 1);
  return s.length > max ? `${s.slice(0, max)}...` : s;
};

/**
 * 归一化两种上报格式为统一结构
 * - Level 2: { "csp-report": { "violated-directive": ..., ... } }
 * - Reporting API: [ { type: 'csp-violation', body: { effectiveDirective: ... } } ]
 */
const normalizeReport = (body) => {
  if (Array.isArray(body)) {
    const entry = body.find((r) => r && (r.type === 'csp-violation' || r.body)) || {};
    const b = entry.body || {};
    return {
      directive: b.effectiveDirective || b.violatedDirective,
      blockedUri: b.blockedURL || b.blockedURI,
      documentUri: b.documentURL || b.documentURI,
      disposition: b.disposition,
    };
  }
  const r = (body && (body['csp-report'] || body)) || {};
  return {
    directive: r['effective-directive'] || r['violated-directive'] || r.effectiveDirective,
    blockedUri: r['blocked-uri'] || r.blockedURI,
    documentUri: r['document-uri'] || r.documentURI,
    disposition: r.disposition,
  };
};

/**
 * @route   POST /csp-report
 * @desc    接收浏览器 CSP 违规上报（G9）
 * @access  Public（浏览器自动发起，无法携带认证）
 */
router.post('/csp-report', cspReportLimiter, cspReportParser, (req, res) => {
  // 始终先回 204：上报是单向通知，浏览器不消费响应体；
  // 任何解析失败也不应回错误码，否则会在客户端控制台产生二次噪音
  res.status(204).end();

  try {
    const { directive, blockedUri, documentUri, disposition } = normalizeReport(req.body);
    // 空上报（探测请求/畸形体）不落日志，避免被当作日志注入通道
    if (!directive && !blockedUri) return;

    // 仅写 winston 不写 AuditLog：上报量由客户端页面数量决定，
    // 单个错误配置的第三方脚本即可产生持续流量，落审计集合会污染合规留存。
    logger.warn('CSP 违规上报', {
      directive: truncate(directive, 64),
      blockedUri: truncate(blockedUri),
      documentUri: truncate(documentUri),
      disposition: truncate(disposition, 16),
      ip: req.ip,
      userAgent: truncate(req.get('user-agent'), 200),
    });
  } catch (e) {
    logger.debug(`CSP 上报解析失败：${e.message}`);
  }
});

/**
 * 前端异常上报专用限流：单 IP 5 分钟 30 批。
 * 前端每批最多 10 条、10 秒一轮节流，正常使用远达不到该配额；
 * 端点无认证，限流防日志放大与刷量。
 */
const clientErrorLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  keyGenerator: (req) => `client-errors:${req.ip}`,
  standardHeaders: false,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).end(),
});

/** 上报条目类型白名单（与前端 errorReporter/webVitals 的 kind 对齐） */
const CLIENT_ERROR_KINDS = new Set(['vue', 'window', 'resource', 'promise', 'vitals']);
const MAX_ENTRIES_PER_BATCH = 20;

/**
 * @route   POST /client-errors
 * @desc    接收前端全局错误兜底与 Web Vitals 上报（G-1）
 * @access  Public（异常可能发生在会话失效后，无法要求认证）
 *
 * 载荷结构（前端 web-admin/src/utils/errorReporter.js 产出）：
 *   { source: 'web-admin', entries: [{ t, kind, message, stack, url, count, ... }] }
 */
router.post('/client-errors', clientErrorLimiter, (req, res) => {
  // 与 csp-report 同口径：单向通知，先回 204，解析问题不向客户端回错
  res.status(204).end();

  try {
    const { entries } = req.body || {};
    if (!Array.isArray(entries) || entries.length === 0) return;

    entries.slice(0, MAX_ENTRIES_PER_BATCH).forEach((entry) => {
      if (!entry || typeof entry !== 'object') return;
      const kind = CLIENT_ERROR_KINDS.has(entry.kind) ? entry.kind : 'window';
      const message = truncate(entry.message, 500);
      if (!message) return;

      const context = {
        kind,
        message,
        stack: truncate(entry.stack, 2000),
        pageUrl: truncate(entry.url, 300),
        count: Number.isFinite(entry.count) ? Math.min(entry.count, 10000) : 1,
        ip: req.ip,
        userAgent: truncate(req.get('user-agent'), 200),
      };

      if (kind === 'vitals') {
        // 性能指标走 info 留档即可，不算异常
        logger.info('Web Vitals 上报', context);
        return;
      }

      logger.warn('前端异常上报', context);
      // 转发 Sentry：已配置 DSN 时才上报，未配置时本地日志已是完整留档
      if (isSentryInitialized()) {
        const err = new Error(`[web-admin:${kind}] ${message}`);
        if (context.stack) err.stack = context.stack;
        captureException(err, {
          pageUrl: context.pageUrl,
          count: context.count,
          userAgent: context.userAgent,
        });
      }
    });
  } catch (e) {
    logger.debug(`前端异常上报解析失败：${e.message}`);
  }
});

/**
 * security.txt 内容按请求动态生成（G10）
 *
 * 用动态生成而非静态文件的原因：RFC 9116 要求 Expires 必须存在且不得
 * 超过一年——静态文件必然过期，过期的 security.txt 按规范应被视为无效。
 */
const buildSecurityTxt = (req) => {
  const contact = process.env.SECURITY_CONTACT_EMAIL || 'security@example.com';
  const expires = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
  const canonical =
    process.env.SECURITY_TXT_CANONICAL ||
    `${req.protocol}://${req.get('host')}/.well-known/security.txt`;

  return [
    `Contact: mailto:${contact}`,
    `Expires: ${expires}`,
    'Preferred-Languages: zh-Hans, en',
    `Canonical: ${canonical}`,
    '',
    '# 请勿对生产环境执行拒绝服务、暴力破解或社会工程测试。',
    '# 报告请附复现步骤与影响面说明，我们将在 5 个工作日内回复。',
    '',
  ].join('\n');
};

const securityTxtLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  keyGenerator: (req) => `security-txt:${req.ip}`,
  standardHeaders: false,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).end(),
});

const serveSecurityTxt = (req, res) => {
  res.type('text/plain; charset=utf-8');
  // 允许缓存 1 天：内容变动极少，且避免扫描器反复回源
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(buildSecurityTxt(req));
};

/**
 * @route   GET /.well-known/security.txt
 * @desc    安全联络信息（RFC 9116）
 * @access  Public
 */
router.get('/.well-known/security.txt', securityTxtLimiter, serveSecurityTxt);

// 兼容 RFC 9116 的旧式根路径位置（规范列为「过渡期允许」）
router.get('/security.txt', securityTxtLimiter, serveSecurityTxt);

module.exports = router;
module.exports.buildSecurityTxt = buildSecurityTxt;
module.exports.normalizeReport = normalizeReport;
