/**
 * 安全增强中间件门面
 *
 * 对外导出面固定为 23 个名字（见文件底部 module.exports），所有
 * `require('../middleware/security')` 的调用方无需改动。实现分布：
 *   · securityHeaders.js —— CSP/helmet/HSTS/Permissions-Policy/Reporting-Endpoints/Trusted Types
 *   · sanitize.js        —— sanitizeMongo / materializeQuery
 *   · ipBlacklist.js     —— IP 封禁缓存与黑白名单检查、早拒绝审计
 *   · auditLog.js        —— 请求型审计日志中间件与落库
 *   · 本文件             —— preventHPP / requireReAuthentication / fileUploadSecurity / apply*
 *
 * 拆分动机：原文件 ESLint 计 644 代码行（max-lines 300），按「挂载阶段 + 数据依赖」
 * 切段，每段有独立测试面，便于后续单点演进（棘轮只许降不许升）。
 */

const logger = require('../../utils/logger');
const ApiResponse = require('../../utils/apiResponse');
const { ROUTE_CATEGORY_MAP } = require('../../utils/auditMeta');

const securityHeadersModule = require('./securityHeaders');
const {
  securityHeaders,
  attachCspNonce,
  ensureHsts,
  permissionsPolicy,
  reportingEndpoints,
  trustedTypesReportOnly,
  CSP_REPORT_PATH,
  cspReportEnabled,
} = securityHeadersModule;
const sanitizeModule = require('./sanitize');
const { sanitizeMongo, materializeQuery } = sanitizeModule;
const ipBlacklistModule = require('./ipBlacklist');
const {
  checkIPBlacklist,
  isWhitelistExemptionTrustworthy,
  addToBlacklist,
  invalidateIPBlockCache,
  recordEarlyRejection,
} = ipBlacklistModule;
const auditLogModule = require('./auditLog');
const { auditLog } = auditLogModule;

/**
 * 4. HTTP 参数污染防护
 * 防止通过重复参数名进行攻击
 */
const hpp = require('hpp');
const preventHPP = hpp({
  // 不保留数组白名单：所有接口都消费标量 query；重复 key 由 hpp 收敛，
  // 对象/嵌套形态仍由 queryScalarGuard 拒绝，避免两道防线口径冲突。
  whitelist: [],
});

/**
 * 5. 敏感操作二次验证中间件
 * 对于敏感操作要求提供当前密码或 MFA 验证码，防止会话劫持后被冒用
 */
const requireReAuthentication = () => {
  return async (req, res, next) => {
    try {
      // `|| {}` 不是防御性冗余：Express 5 在 JSON 解析器跳过时把 req.body 留成
      // undefined（v4 恒为 {}），对 undefined 解构抛 TypeError 并被下面的 catch 吞成 500——
      // "客户端根本没带凭证"这一正常拒绝因此伪装成服务端故障（还按 UnhandledError 记 error 日志）。
      const { currentPassword, mfaCode } = req.body || {};

      if (!currentPassword && !mfaCode) {
        return ApiResponse.codeError(res, 'REAUTH_REQUIRED');
      }

      // 优先校验当前密码
      if (currentPassword) {
        const User = require('../../models/User');
        const user = await User.findById(req.user.userId).select('+password');
        if (!user) {
          return ApiResponse.codeError(res, 'USER_NOT_FOUND');
        }
        const isValid = await user.comparePassword(currentPassword);
        if (!isValid) {
          logger.warn('敏感操作二次验证失败（密码错误）', { username: req.user.username });
          return ApiResponse.codeError(res, 'REAUTH_PASSWORD_INCORRECT');
        }
        req.reAuthenticated = true;
        return next();
      }

      // MFA 动态口令校验（I-06）：仅对已开启两步验证的用户生效
      //
      // 原实现走裸 `verifyTotp`（只回布尔），既不烧时间窗计数器也不记失败，
      // 于是同一个合法码在 ±1 窗口（约 90s）内可**无限次重放**通过步进验证，
      // 且错误尝试不计数、不锁定——而 6 位码空间只有 10^6。
      // 现对齐仓内既有两处实现：authService.verifyTotpChallenge 的原子消费
      // （以 `mfaLastCounter < counter` 为条件的更新，只有第一个请求能命中，
      //  并发双花由 DB 兜底），以及 mfaService 的失败计数 + 阈值锁定。
      // 与登录共用同一个 mfaLastCounter 字段是有意的：同一个码不得在两个上下文各用一次。
      const { verifyTotpDetailed } = require('../../utils/totp');
      const { decryptMfaSecret } = require('../../utils/mfaSecret');
      const mfaService = require('../../services/mfaService');
      const User = require('../../models/User');

      if (await mfaService.isMfaLocked(req.user.userId)) {
        logger.warn('敏感操作二次验证被拒（MFA 通道临时锁定中）', {
          username: req.user.username,
        });
        return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
      }

      const user = await User.findById(req.user.userId).select('+mfaSecret');
      if (!user) {
        return ApiResponse.codeError(res, 'USER_NOT_FOUND');
      }
      if (!user.mfaEnabled) {
        return ApiResponse.codeError(res, 'REAUTH_MFA_NOT_ENABLED');
      }
      // 库内 mfaSecret 为 AES-GCM 密文（存量明文由 decryptMfaSecret 原样透传）
      // mfaCode 此处必为真值：上面的守卫要求"密码与验证码至少有一个"，而密码分支已 return。
      const totpResult = verifyTotpDetailed(
        decryptMfaSecret(user.mfaSecret),
        String(mfaCode).trim()
      );
      let claimedCounter = false;
      if (totpResult.valid) {
        const advanced = await User.findOneAndUpdate(
          {
            _id: user._id,
            $or: [
              { mfaLastCounter: { $lt: totpResult.counter } },
              { mfaLastCounter: { $exists: false } },
              { mfaLastCounter: null },
            ],
          },
          { $set: { mfaLastCounter: totpResult.counter } },
          { new: true }
        ).catch(() => null);
        claimedCounter = !!advanced;
      }
      if (!totpResult.valid || !claimedCounter) {
        // 重放与口令错误同样计入失败并按同一码拒绝：不向调用方区分
        // "码正确但已消费"，否则本端点又变成一个验证码探测面。
        await mfaService.recordMfaFailure(user);
        logger.warn('敏感操作二次验证失败（MFA 验证码错误或重放）', {
          username: req.user.username,
          replayed: totpResult.valid && !claimedCounter,
        });
        return ApiResponse.codeError(res, 'REAUTH_MFA_INCORRECT');
      }
      await mfaService.resetMfaFailures(user._id);
      req.reAuthenticated = true;
      return next();
    } catch (error) {
      logger.error(`二次验证失败：${error.message}`);
      return ApiResponse.codeError(res, 'REAUTH_PROCESS_FAILED');
    }
  };
};

/**
 * 9. 文件上传安全检查
 * 验证上传文件的类型和大小
 *
 * 注意（预留能力）：当前项目暂无文件上传路由，本中间件尚未被任何路由挂载。
 * 未来引入文件上传功能时，必须在上传路由强制启用本中间件（配合 MIME 白名单、
 * 扩展名校验与大小限制），不可直接裸奔上传接口。
 *
 * 【2026-10-01：扩展名闸由 fail-open 改为构造期 fail-closed】
 * 原实现是 `allowedExts = allowedTypes.map(t => mimeToExt[t]).filter(Boolean)`，
 * 再用 `if (allowedExts.length > 0 && ...)` 短路。于是当 `allowedTypes` 里**一个
 * 都不在** mimeToExt 表里时（表里只有 5 项：jpeg/png/gif/pdf/zip），`filter(Boolean)`
 * 把整组映射结果清空 ⇒ `allowedExts.length === 0` ⇒ **扩展名校验整条消失**，
 * 只剩客户端自报的 `file.mimetype`（`allowedTypes.includes(file.mimetype)` 也一并失效，
 * 因为那条判据同样依赖调用方传的 MIME 与真实类型一致）。即"配置了白名单却等于没配"，
 * 且没有任何信号——这正是本仓纪律里"配了却不生效=最危险"的形态。
 * 今天无 multer 挂载故不可利用，但这类缺口一旦随首个上传路由上线就会同时生效。
 *
 * 收口方式：把映射与校验提到**构造期**（= 路由装配期，即启动期）——
 * 只要 `allowedTypes` 里存在**任何一个**没有扩展名映射的 MIME，直接抛错。
 * 于是运行期不可能再出现"白名单非空但扩展名闸为空"的组合，
 * 短路判据也随之简化为 `allowedTypes.length > 0`（语义变得与直觉一致）。
 * 之所以对"部分未映射"也抛：未映射的那一项在运行期就是一条静默放行，
 * 只抛"全部未映射"会把部分漏洞留在原地。
 */
const MIME_TO_EXT = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
  'application/zip': 'zip',
};

const fileUploadSecurity = (options = {}) => {
  const {
    maxSize = 5 * 1024 * 1024, // 默认 5MB
    allowedTypes = [],
  } = options;

  // 构造期 fail-closed：白名单里每一项都必须有扩展名映射，否则这条防线是纸面的。
  // 抛错而不是降级告警：修复它不需要服务先跑起来（与 ALLOWED_HOSTS 那类致命项同口径）。
  const unmapped = allowedTypes.filter((t) => !MIME_TO_EXT[t]);
  if (unmapped.length > 0) {
    throw new Error(
      `fileUploadSecurity 配置无效：allowedTypes 中的 ${unmapped.join(', ')} 没有对应的` +
        `扩展名映射（当前仅支持 ${Object.keys(MIME_TO_EXT).join(', ')}）。` +
        '继续装配会让扩展名校验整条失效（只凭客户端自报的 MIME 判断）——' +
        '请改用受支持的 MIME，或先在 MIME_TO_EXT 里补齐映射。'
    );
  }
  // 映射后必与 allowedTypes 等长（上面已保证无未映射项），故此处不再 filter(Boolean)：
  // 那个 filter 正是原先 fail-open 的来源。
  const allowedExts = allowedTypes.map((t) => MIME_TO_EXT[t]);

  return async (req, res, next) => {
    if (!req.files || req.files.length === 0) {
      return next();
    }

    for (const file of req.files) {
      // 检查文件大小
      if (file.size > maxSize) {
        return ApiResponse.codeError(res, 'UPLOAD_FILE_TOO_LARGE', {
          message: `文件 ${file.originalname} 超过最大限制 ${maxSize / 1024 / 1024}MB`,
          params: { filename: file.originalname, maxSize: maxSize / 1024 / 1024 },
        });
      }

      // 检查文件类型
      if (allowedTypes.length > 0 && !allowedTypes.includes(file.mimetype)) {
        return ApiResponse.codeError(res, 'UPLOAD_TYPE_NOT_ALLOWED', {
          message: `不允许的文件类型：${file.mimetype}`,
          params: { mimetype: file.mimetype },
        });
      }

      // 检查文件扩展名（防止 MIME 类型欺骗）
      const ext = file.originalname.split('.').pop().toLowerCase();

      if (allowedTypes.length > 0 && !allowedExts.includes(ext)) {
        return ApiResponse.codeError(res, 'UPLOAD_EXT_NOT_ALLOWED', {
          message: `不允许的文件扩展名：.${ext}`,
          params: { ext: ext },
        });
      }
    }

    next();
  };
};

/**
 * 10. 会话安全配置
 * 注意：本项目使用 JWT 认证，不使用 session。此配置仅作参考。
 * 如需启用 session，请使用 express-session 并配置下方选项。
 */

/**
 * 启动期断言：审计 category 枚举一致性防护
 *
 * ROUTE_CATEGORY_MAP（路由前缀 → category 映射）的取值必须全部落在
 * AuditLog schema 的 category enum 内；否则该分类的审计记录会因
 * ValidationError 被 insertMany({ordered:false}) 静默丢弃，形成审计盲区。
 * 不一致时直接抛出错误阻止启动（带病启动不如启动失败），不修改任何映射值。
 */
const assertAuditCategoryConsistency = () => {
  const AuditLog = require('../../models/AuditLog');
  const allowed = AuditLog.schema.path('category').enumValues;
  const mapped = [...new Set(Object.values(ROUTE_CATEGORY_MAP))];
  const invalid = mapped.filter((cat) => !allowed.includes(cat));
  if (invalid.length > 0) {
    throw new Error(
      `审计 category 枚举不一致：ROUTE_CATEGORY_MAP 中的 [${invalid.join(', ')}] ` +
        `不在 AuditLog.schema category enum [${allowed.join(', ')}] 内，` +
        '该分类审计记录将被静默丢弃，请同步两侧取值后再启动'
    );
  }
};

/**
 * 挂载「不依赖已解析 body」的安全中间件
 *
 * 拆分原因：protocolCompliance 的设计意图之一是「Content-Length 超限早于 body
 * 解析即拒绝，避免无谓读流」，但此前整个 applySecurity 挂在 express.json()
 * **之后** —— body 已经被完整读入并解析完，该项收益完全不存在，注释与行为背离。
 * 头部卫生/方法白名单/Host 校验同理：越早拒绝，下游解析器暴露面越小。
 *
 * 响应头卫生不在这里挂载，见下面的 applyResponseHardening（它必须比本函数更早）。
 * @param {import('express').Application} app
 * @returns {void}
 */
const applyPreBodySecurity = (app) => {
  // 启动期防护：审计分类映射与模型枚举不一致时拒绝启动，避免审计静默丢失
  assertAuditCategoryConsistency();

  // 协议合规校验：置于 body 解析之前，畸形请求早拒绝、不进入下游解析
  const { protocolCompliance } = require('../protocolCompliance');
  // 评价报告低危项：Content-Length 上限与 express.json 的 body 上限（1mb）
  // 对齐——原默认 10MB 让 1MB~10MB 的请求在协议层放行后又被 body 解析
  // 413 拒掉，两道闸门口径不一，审计里的拒绝原因也不一致。
  // 业务载荷均为小表单（无文件上传端点），1MB 是两层的统一收口。
  app.use(protocolCompliance({ maxContentLength: 1024 * 1024 }));
};

/**
 * 挂载「纯写响应头」的那一段 —— 必须是 createApp 里最早的中间件
 *
 * 为什么单独成一段、且要排在 IP 黑名单与两个全局限流**之前**：响应头前置此前只做到
 * protocolCompliance 之前，而 ipLimiter/generalLimiter 与 checkIPBlacklist 为了封住
 * "小请求放大成链上审计写入"特意挂得比它更早 ⇒ 全站最早的两类拒绝（429 与黑名单 403）
 * 反而一个安全头都没有，helmet 的 hidePoweredBy 也在这两条路径上失效——被限流/封禁的
 * 响应替攻击者把 `X-Powered-By` 送出来，全站唯此处泄露服务器指纹。
 *
 * 前置不违背限流前移的两条理由：这一段不读 body、不碰数据库，只 setHeader
 * （每请求 16 字节 randomBytes 生成 CSP nonce，开销相对 express 路由可忽略）。
 * 顺序不变量：attachCspNonce 必须先于 securityHeaders（helmet 写 CSP 头时读取 res.locals.cspNonce）。
 * @param {import('express').Application} app
 * @returns {void}
 */
const applyResponseHardening = (app) => {
  app.use(attachCspNonce);
  app.use(securityHeaders);
  app.use(ensureHsts);
  app.use(permissionsPolicy);
  app.use(reportingEndpoints);
  // Trusted Types 灰度：独立 CSP 中间件，只写 Content-Security-Policy-Report-Only，
  // 与上面的 securityHeaders 写出的 Content-Security-Policy 头名不同、互不覆盖。
  // 必须在 reportingEndpoints 之后（report-to 指令依赖它下发的 Reporting-Endpoints 头）。
  app.use(trustedTypesReportOnly);
};

/**
 * 挂载「需要已解析 body/query」的安全中间件
 *
 * 注意：checkIPBlacklist 已移至 app.js 中 CORS 之前独立挂载（见 app.js），
 * 是全站最早的访问控制闸门——黑名单在 body 解析/CORS/安全头/限流之前即拒绝，
 * 白名单标记 req.ipWhitelisted 在此处之前已就绪，供后续所有限制类中间件豁免。
 * @param {import('express').Application} app
 * @returns {void}
 */
const applyPostBodySecurity = (app) => {
  app.use(sanitizeMongo);
  // JSON API 不做全局输入转义，转义责任在输出层（前端渲染/报表导出）
  app.use(preventHPP);
};

/**
 * 一次性挂载全部安全中间件（保留给不区分 body 解析阶段的调用方，如测试）
 * @param {import('express').Application} app
 * @returns {void}
 */
const applySecurity = (app) => {
  applyResponseHardening(app);
  applyPreBodySecurity(app);
  applyPostBodySecurity(app);
};

module.exports = {
  securityHeaders,
  attachCspNonce,
  ensureHsts,
  permissionsPolicy,
  reportingEndpoints,
  trustedTypesReportOnly,
  CSP_REPORT_PATH,
  cspReportEnabled,
  sanitizeMongo,
  materializeQuery,
  preventHPP,
  requireReAuthentication,
  checkIPBlacklist,
  isWhitelistExemptionTrustworthy,
  addToBlacklist,
  invalidateIPBlockCache,
  auditLog,
  fileUploadSecurity,
  recordEarlyRejection,
  applySecurity,
  applyResponseHardening,
  applyPreBodySecurity,
  applyPostBodySecurity,
};
