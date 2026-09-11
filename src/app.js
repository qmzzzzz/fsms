/**
 * Express 应用工厂
 * 职责：创建并配置 Express 应用实例（中间件、路由、错误处理）
 * 与 server 启动逻辑分离，便于测试和复用（如 supertest 直接 import app）
 */

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const compression = require('compression');

const config = require('./config');
const logger = require('./utils/logger');
const middleware = require('./middleware');
const {
  errorHandler,
  applyPreBodySecurity,
  applyPostBodySecurity,
  generalLimiter,
  ipLimiter,
  auditLog,
  queryLengthLimit,
  queryScalarGuard,
  createOriginCheck,
  checkIPBlacklist,
  authenticate,
  checkPermission,
} = middleware;
const {
  initSentry,
  sentryRequestHandler,
  sentryTracingHandler,
  sentryErrorHandler,
} = require('./middleware/sentry');
const requestId = require('./middleware/requestId');
const { applyObjectIdParams } = require('./middleware/validateObjectId');
const { redactUrlQuery } = require('./utils/helpers');
const {
  metricsMiddleware,
  metricsEndpoint,
  getSnapshot,
  METRICS_ENABLED,
} = require('./utils/metrics');
const { metricsAuth } = require('./middleware/metricsAuth');
const ApiResponse = require('./utils/apiResponse');
const { checkMongoReady } = require('./utils/healthChecks');
const swagger = require('./config/swagger');
const { mountStaticFrontend } = require('./middleware/staticFrontend');

// 导入路由
const {
  authRoutes,
  userRoutes,
  roleRoutes,
  permissionRoutes,
  deviceRoutes,
  alarmRoutes,
  securityRoutes,
  inspectionRoutes,
  reportRoutes,
  wellKnownRoutes,
} = require('./routes');

const sentryInitialized = initSentry();

/**
 * 创建并配置 Express 应用
 * @returns {express.Application}
 */
function createApp() {
  const app = express();

  // trust proxy（M-4 收紧默认值）：
  // - 显式配置 TRUST_PROXY_HOPS > 0 时按其跳数信任（生产 Nginx / 开发 Vite 均为 1 跳）
  // - 未配置时：development 默认信任 1 跳（本机 Vite 代理，仅限开发）
  // - 其余环境（含 production）一律不信任代理头 —— 服务直连暴露时客户端可伪造
  //   X-Forwarded-For 击穿 IP 限流/黑名单/自动封禁，必须显式声明代理拓扑后才启用
  //
  // 非法值（如 TRUST_PROXY_HOPS=abc）此前静默退化为「不信任代理」：反代场景下
  // req.ip 恒为代理 IP，全站共享一个限流桶、审计 IP 全失真，且无任何线索。
  // 生产环境已由 config/validate.js 升级为启动致命错误；此处对所有环境补运行时告警，
  // 保证 staging/dev 的错配同样可被发现。
  const rawTrustProxyHops = process.env.TRUST_PROXY_HOPS;
  const trustProxyHops = parseInt(rawTrustProxyHops, 10);
  if (
    rawTrustProxyHops !== undefined &&
    String(rawTrustProxyHops).trim() !== '' &&
    !(Number.isFinite(trustProxyHops) && trustProxyHops > 0)
  ) {
    logger.warn(
      `TRUST_PROXY_HOPS 取值非法（${rawTrustProxyHops}），已退化为「不信任代理头」：` +
        '若本服务位于反向代理之后，req.ip 将恒为代理 IP，导致限流/封禁/审计 IP 全部失真'
    );
  }
  if (Number.isFinite(trustProxyHops) && trustProxyHops > 0) {
    app.set('trust proxy', trustProxyHops);
  } else if (config.nodeEnv === 'development') {
    app.set('trust proxy', 1);
  } else {
    app.set('trust proxy', false);
  }

  // Express 5 迁移（ADR-007）：v5 默认 query parser 收窄为 simple（嵌套查询
  // 对象解析变化）。本仓列表接口入参虽全为扁平标量，仍显式固定为 extended
  // 与 4.x 行为对齐，消除隐性行为差——该行删除前须重审全部 req.query 用法
  app.set('query parser', 'extended');

  // 请求 ID 追踪（在所有中间件之前，确保日志可关联）
  app.use(requestId);

  // HTTP 指标采集（O-8）：紧随 requestId，先于 IP 黑名单/限流器——
  // 403/429 等早期拒绝同样计入请求指标；采集失败不影响业务响应
  app.use(metricsMiddleware);

  // 子 Router 级 :id / :userId ObjectId 校验（P2-25）
  // 原实现是 app.param('id', ...)：Express 4 的参数回调只对定义它的 router 生效，
  // 不向子 Router 传播，而全部业务路由都挂在子 Router 上 —— 该校验从未执行过
  // （实测 express 4.22.2：子 Router 路由触发次数 = 0）。
  // 非法 :id 一路走到 Mongoose 才抛 CastError 兜成 400，聚合/$match 类用法
  // 则可能走到非预期路径。此处逐个子 Router 注册，使校验真正生效。
  applyObjectIdParams(
    userRoutes,
    roleRoutes,
    permissionRoutes,
    deviceRoutes,
    alarmRoutes,
    inspectionRoutes,
    reportRoutes,
    securityRoutes
  );

  // Sentry 请求和追踪处理器（在所有中间件之前）
  if (sentryInitialized) {
    app.use(sentryRequestHandler());
    app.use(sentryTracingHandler());
  }

  // ================= IP 黑白名单（最高优先级访问控制）=================
  // 必须早于 CORS、securityHeaders、body 解析、限流等一切中间件：
  // - 黑名单命中立即 403，不读请求体、不做 CORS 协商，资源消耗最小
  // - 白名单在此挂 req.ipWhitelisted，后续所有限制类中间件据此豁免
  // 仅依赖 req.ip（trust proxy 已在上方配置完毕），不需要已解析的 body/query
  app.use(checkIPBlacklist);

  // ================= 中间件配置 =================

  // CORS 白名单配置
  // credentials:true 时 origin 必须是明确白名单。开发环境允许 localhost 兜底；
  // staging/production 必须显式配置，防止误部署后把本地开发源放进线上白名单。
  const parsedCorsOrigin = config.corsOrigin
    ? config.corsOrigin
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean)
    : [];
  const corsOrigin =
    parsedCorsOrigin.length > 0
      ? parsedCorsOrigin
      : config.nodeEnv === 'development'
        ? [
            'http://localhost:3001',
            'http://127.0.0.1:3001',
            'http://localhost:5173',
            'http://127.0.0.1:5173',
          ]
        : [];

  app.use(
    cors({
      origin: corsOrigin,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      // G7：曾声明 X-Request-Signature / X-Request-Timestamp，但全仓无任何验签
      // 中间件落地（security.js 未导出 verifyRequestSignature，也无路由引用）。
      // 保留纯占位头会误导审计与客户端接入方，让人以为高权操作已受重放保护，
      // 故按「不实现就不声明」原则移除；后续真正落地验签时再一并恢复。
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
      exposedHeaders: ['X-Request-Id', 'Content-Disposition'],
      credentials: true,
      maxAge: 600,
    })
  );

  // ================= 安全中间件（body 解析之前）=================
  // P3-35：protocolCompliance 必须早于 express.json()，否则「Content-Length
  // 超限即拒绝、不读流」的设计意图被架空——原挂载顺序下 body 已完整解析完毕
  applyPreBodySecurity(app);

  // 请求体解析（上限 1mb：业务载荷均为小表单，收紧以降低内存滥用面）
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // ================= 安全中间件（依赖已解析 body/query）=================
  applyPostBodySecurity(app);

  // 响应压缩（gzip/deflate）：JSON 列表、报表、Swagger 文档等大体积响应显著降低带宽与首屏耗时；
  // 默认仅压缩 ≥1kb 响应，/health 等最小响应不受影响
  app.use(compression());

  // 日志记录
  // P3-32：不用内置的 'combined' 预设——它的 :url token 输出完整 originalUrl，
  // query string 里的令牌/口令会明文长期留存于 combined-*.log。
  // 自定义 token safe-url 复用 helpers.redactUrlQuery 打码，其余字段与 combined 一致，
  // 保证既有日志解析规则（ELK/SIEM 的 combined grok 模式）不受影响。
  morgan.token('safe-url', (req) => redactUrlQuery(req.originalUrl || req.url));
  const COMBINED_SAFE_FORMAT =
    ':remote-addr - :remote-user [:date[clf]] ' +
    '":method :safe-url HTTP/:http-version" :status :res[content-length] ' +
    '":referrer" ":user-agent"';
  if (config.nodeEnv === 'development') {
    app.use(morgan('dev'));
  } else {
    app.use(
      morgan(COMBINED_SAFE_FORMAT, {
        stream: { write: (message) => logger.info(message.trim()) },
      })
    );
  }

  // CSRF 纵深：写操作 Origin/Referer 白名单校验（回应外部报告 CSRF 项）
  // 传入上方已计算的 corsOrigin 白名单（单一配置源）；无来源请求（curl/服务器间调用）放行，
  // 带来源的写请求必须命中白名单，覆盖 SameSite=Lax 之外旧浏览器残余风险
  app.use('/api/', createOriginCheck(corsOrigin));

  // 限流（IP 级 + 通用全局生效；用户级 userLimiter 由 authenticate 在认证成功后执行，
  // 以便按 userId 建键、按实时角色定配额——全局挂载时 req.user 尚未就绪，无法按用户限流）
  app.use('/api/', ipLimiter);
  app.use('/api/', generalLimiter);

  // 查询参数长度限制：搜索框等 GET 入参超长（如粘贴大段文本）直接 400，
  // 避免超长关键字进入数据库正则查询造成负载放大
  app.use('/api/', queryLengthLimit(200));

  // 查询参数标量收敛：qs 会把 ?search[$regex]=x 解析成对象、?status=a&status=b 解析成数组，
  // 而控制器按字符串消费（search.trim() → 500；status 直入 Mongo 过滤 → 操作符注入）。
  // 挂在 applyPostBodySecurity（含 sanitizeMongo）之后，看到的是清洗后的最终形态
  app.use('/api/', queryScalarGuard());

  // 全局审计日志中间件：入参省略，直接使用 security.js 中间件内置默认值
  // （写方法白名单与 GET 敏感读取路径——含 /api/reports/export、
  // /api/security/audit-logs 批量数据出口的 GET 审计——均已在默认值中定义，
  // 此处重复传参会形成两处配置源，日后易漂移不一致）
  app.use('/api/', auditLog());

  // ================= API 路由 =================

  // 健康检查（最小化响应：仅存活信号，不暴露版本/数据库状态等内部信息）
  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // 就绪探针（可观测性）：含 Mongo ping，区分「进程活着」(/health) 与「能干活」——
  // 不 ready 时编排器/LB 摘流量但保持进程运行；Docker HEALTHCHECK 仍用 /health，
  // 避免 Mongo 短暂抖动触发容器重启。
  // M-1：对外只暴露固定枚举（ok/disconnected/timeout/unreachable/error），
  // 驱动原始错误消息仅入服务端日志——本端点不鉴权且被公网探测，
  // 回显 err.message 会泄露主机/端口/副本集/认证细节
  app.get('/readyz', (req, res) => {
    checkMongoReady()
      .then((mongo) => {
        if (!mongo.ok) {
          logger.warn(`就绪探针未通过（mongo=${mongo.reason}）：${mongo.detail}`);
        }
        res.status(mongo.ok ? 200 : 503).json({
          status: mongo.ok ? 'ready' : 'unready',
          checks: { mongo: mongo.ok ? 'ok' : mongo.reason },
          timestamp: new Date().toISOString(),
        });
      })
      .catch((err) => {
        logger.warn(`就绪探针检查异常：${err.message}`);
        res.status(503).json({
          status: 'unready',
          checks: { mongo: 'error' },
          timestamp: new Date().toISOString(),
        });
      });
  });

  // Prometheus 指标端点（O-8）：QPS/延迟直方图/错误计数/安全告警计数，
  // 供运维侧抓取；METRICS_ENABLED=false 可关闭暴露（采集照常）。
  // 应用层鉴权纵深：内网/回环放行 + 可选 METRICS_TOKEN（Bearer），
  // 作为 Nginx 网络层限源之外的第二道防线——Nginx 配置漂移或有人
  // 从容器网络直连 app:3000 时，运行情报不至于裸奔（fail-safe 到拒绝）。
  if (METRICS_ENABLED) {
    app.get('/metrics', metricsAuth, metricsEndpoint);
  }

  // 指标 JSON snapshot（O-8 面板半）：现有 Vue3+ECharts 管理面板直读。
  // 挂在 /api 下走认证 + security:audit 权限——运行时指标属管理面数据，
  // 不得匿名暴露；与 Prometheus /metrics（运维抓取）互为两个消费端。
  app.get('/api/metrics', authenticate, checkPermission('security:audit'), (req, res) => {
    ApiResponse.success(res, getSnapshot(), '获取成功');
  });

  // API 根路径（不再返回接口清单，避免未认证的信息暴露）
  app.get('/api', (req, res) => {
    res.json({ success: true, message: '消防管理系统 API' });
  });

  // 公共发现端点：/.well-known/security.txt（G10）与 /csp-report（G9）
  // 挂在根路径（路径由 RFC 9116 与 CSP report-uri 固定），自带独立限流，
  // 不进入 /api/ 的来源校验与审计链路
  app.use('/', wellKnownRoutes);

  // 挂载路由
  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/roles', roleRoutes);
  app.use('/api/permissions', permissionRoutes);
  app.use('/api/devices', deviceRoutes);
  app.use('/api/alarms', alarmRoutes);
  app.use('/api/inspections', inspectionRoutes);
  app.use('/api/reports', reportRoutes);
  app.use('/api/security', securityRoutes);

  // API 文档（Swagger UI）— 生产环境默认关闭，可通过 ENABLE_API_DOCS=true 开启
  // 开启后可通过 DOCS_USERNAME / DOCS_PASSWORD 设置 Basic Auth 保护
  //
  // P2-30：docsLimiter 必须排在 basicAuth **之前**。限流器只挂 `/api/`，
  // 而文档挂在根路径，此前完全落在限流之外——basicAuth 的 timingSafeEqual
  // 防住了时序侧信道却防不住无限速穷举 DOCS_USERNAME/DOCS_PASSWORD。
  // 顺序颠倒（先 basicAuth）会让每次爆破尝试都先做一次口令比对，限流失去意义。
  if (swagger.isDocsEnabled()) {
    app.use('/api-docs', swagger.docsLimiter, swagger.basicAuth, swagger.serve, swagger.setup);
    app.get('/api-docs.json', swagger.docsLimiter, swagger.basicAuth, (req, res) =>
      res.json(swagger.openapiSpec)
    );
  }

  // 生产前端静态托管（L-1）：直接服务 web-admin 构建产物（含 SPA history 回退）。
  // 必须位于全部业务路由之后（避免吞掉 /api 等前缀）、404 兜底之前。
  // 开发环境与无产物时自动跳过，不影响 Vite 工作流与纯 API 部署
  mountStaticFrontend(app, { logger });

  // 404
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      message: `接口不存在：${req.method} ${req.originalUrl}`,
    });
  });

  // Sentry 错误处理器（在通用 errorHandler 之前）
  if (sentryInitialized) {
    app.use(sentryErrorHandler());
  }

  // 全局错误处理
  app.use(errorHandler);

  return app;
}

module.exports = { createApp, sentryInitialized };
