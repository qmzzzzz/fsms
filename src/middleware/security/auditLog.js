/**
 * 请求型审计日志中间件（自 `middleware/security.js` 拆出，2026-10-18）
 *
 * 内容：auditLog 中间件本体（从路由派生 category/action、写审计缓冲）与
 * persistAuditRecord 各路由分支的落库函数。缓冲与落库失败口径见 services/auditBuffer。
 * 对外导出面由 security/index.js 原样再导出。
 */

const logger = require('../../utils/logger');
const {
  stripControlChars,
  stripControlCharsDeep,
  matchesAnyPathPrefix,
} = require('../../utils/helpers');
const { auditPath, deriveAuditMeta } = require('../../utils/auditMeta');
const { isBodySensitiveKey, sanitizeAuditQuery } = require('../../models/auditLogSanitizer');

/**
 * 8. 审计日志中间件
 * 记录所有敏感操作的详细日志，并持久化到 AuditLog 集合用于操作溯源
 *
 * 本中间件是请求型审计日志的默认入口，自动从路由派生语义 category/action。
 * 例外：需要专用语义/字段的动作（密码修改、敏感数据查看、IP 名单变更、审计链
 * 校验等）由控制器手写 AuditLog.create 并置 res.locals.skipGlobalAudit，跳过
 * 本中间件，避免同一操作产生两条重复记录。该标志共 11 处赋值点
 * （securityController 8 / ipListController 2 / auditController 1，2026-09-17 实测）。
 * P0-5 修复（2026-09-17）：标志必须在**响应时刻**读取（见 doLog）——控制器赋值
 * 发生在本中间件入口之后，入口处读取必然早于赋值。原实现正是在入口只读一次，
 * 标志 100% 失效：每个这类操作都被双写（控制器手写 1 条 + 本中间件按路由再写
 * 1 条，且两条 action/category 不同）。
 *
 * 路径取值约束：category/action 派生与 excludePaths 判断统一使用 req.originalUrl
 * （见 utils/auditMeta）。Express 在 `app.use('/api/', mw)` + `router` 两级挂载下会
 * 逐层剥离 req.path，用 req.path 会导致全部记录退化为 category=system 且排除规则失效。
 *
 * 敏感读取判据（2026-09-30 反转，收口审计报告 §3.4）：GET/HEAD **默认全量审计**，
 * 仅 auditGetExcludePaths 清单显式豁免。原实现是 6 条前缀的**允许清单**（auditGetPaths），
 * 失效形态是 fail-open：新增一条敏感 GET 路由而忘记登记，它就零留痕——设备/报警/
 * 巡检的列表与详情正是一批这样的盲区（HEAD 归一修复只救了已登记的 6 条前缀；列表
 * 与详情共用派生 action `*_view`，无需新增 action 登记；tests/constants/
 * auditActionReachability 的 A 类 25 条即反转前实测的盲区清单，反转后剩 9 条）。
 * 反转后默认 fail-closed：新路由不做任何登记即被审计；想豁免必须在清单里写明理由，
 * 归入口径只有两类：
 *   a) 预认证/登录流程面——无业务数据，调用频率由认证流程决定（每次登录页、
 *      每次登录尝试都打），审计只灌大集合，证据价值由 login_failed/封禁事件承担；
 *   b) 纯自读面——返回的只是**请求者本人**的会话/绑定/日志状态，且被前端在每次
 *      导航时轮询；数据主体即请求者，他人读不到，操作留痕由写路径承担（改密/
 *      MFA 变更/踢会话均为写方法，照常审计）。
 * 已知取舍（如实记录）：看板若轮询设备/报警列表，每次轮询都是一条审计记录——真
 * 发生时按上面口径逐条评估后加入豁免清单，而不是回退到允许清单；匿名/未匹配路径
 * 的 GET 探测也会留痕（与既有 /api/users 行为一致），这正是探测证据。
 */
const auditLog = (options = {}) => {
  // 延迟 require：originCheck 顶层就 require 了本模块（recordEarlyRejection），
  // 反向在顶层 require 会成环拿到半初始化导出
  const { WRITE_METHODS } = require('../originCheck');
  const {
    // 写操作口径的单一事实来源（原此处再写一遍四个方法名，与 originCheck 的 CSRF 闸
    // 各自漂移过：一处加了方法，另一处就出现"拦了但没审计"/"审计了但没拦"）
    operations = WRITE_METHODS,
    excludePaths = ['/api/auth/login', '/api/auth/refresh'],
    // GET/HEAD 敏感读取的**豁免清单**：默认全量审计，命中才跳过（口径与反转依据
    // 见本中间件头部注释）；GET 审计不记录请求体。
    // P0-6 修复（2026-09-17）历史备注：导出类响应只经过 write/end 而非 json/send，
    // 响应包装现覆盖 write/end——本反转不影响该修复，报表/审计导出照常被审计。
    auditGetExcludePaths = [
      // a) 预认证/登录流程面
      '/api/auth/captcha',
      '/api/auth/captcha-status',
      '/api/auth/login-public-key',
      '/api/auth/mfa/status', // 登录第二步轮询
      // b) 纯自读面（数据主体即请求者本人 + 前端高频轮询）
      '/api/auth/session', // 前端路由守卫每次导航轮询
      '/api/auth/me',
      '/api/auth/sessions', // 踢会话是 DELETE（写方法），仍审计
      '/api/security/my-info',
      '/api/security/bindings',
      '/api/security/my-logs',
    ],
  } = options;

  return async (req, res, next) => {
    // 审计用的规范路径（含 /api 前缀，已去查询串）
    const fullPath = auditPath(req);

    // 跳过不需要审计的路径（登录/刷新由 authController 写专用事件型审计，
    // 此处必须用 fullPath 判断，否则排除失效会产生 anonymous 的重复记录）
    if (matchesAnyPathPrefix(excludePaths, fullPath)) {
      return next();
    }

    // 判断是否为需审计的 GET/HEAD 敏感读取：**默认审计，命中豁免清单才跳过**。
    // 必须与路由同尺（大小写不敏感）：GET /API/reports/export 真实执行导出，
    // 若这里做大小写敏感比较，改一个字母大小写即可静默批量取数而零留痕
    // （反转后同尺的意义不变：改大小写换来的只是一条审计记录，不是静默）。
    //
    // HEAD 与 GET 同判：Express 的 Route.dispatch 把 HEAD 归一成 GET
    // （`if (method === 'HEAD') method = 'GET'`），所以 `app.get('/api/reports/export')`
    // 的处理函数对 HEAD **全量执行**——报表导出把 workbook 完整生成一遍、Node 只是
    // 不把响应体写出去。原先只认 `req.method === 'GET'` 时，HEAD 是一条既跑了业务、
    // 又零留痕的口子。实测（真实 createApp，带 user:read 的合法令牌）：
    // GET /api/users 审计增量 1、HEAD /api/users 审计增量 0。反转后 HEAD 与 GET
    // 走同一份豁免清单，整类口子随反转一起闭合。
    // HEAD 已在 constants/audit.js 的 AUDIT_HTTP_METHODS 里，不需要动 schema。
    const isGetAudit =
      (req.method === 'GET' || req.method === 'HEAD') &&
      !matchesAnyPathPrefix(auditGetExcludePaths, fullPath);

    // 只记录指定类型的操作，或未豁免的 GET/HEAD 敏感读取
    if (!operations.includes(req.method) && !isGetAudit) {
      return next();
    }

    // 记录开始时间
    const startTime = Date.now();

    // 保存原始响应方法。统一先 bind 到 res：包装器可能被以任意 this 调用，
    // 且 res.send 内部会再调 res.end，绑定后行为与原生一致。
    const originalJson = res.json.bind(res);
    const originalSend = res.send.bind(res);
    // P0-6：导出类响应只经过 write/end，不经 json/send。部分响应替身
    // （如既有测试的 makeRes()）没有这两个方法，缺失时不包装。
    const originalWrite = typeof res.write === 'function' ? res.write.bind(res) : null;
    const originalEnd = typeof res.end === 'function' ? res.end.bind(res) : null;
    let logged = false;

    // 统一的审计日志记录逻辑
    const doLog = () => {
      // logged 先置位再判定：res.send 内部会调 res.end，第二次进入必须在
      // skip 判定之前就被守卫吃掉，避免重复判定与重复记录
      if (logged) return; // 防止重复记录
      logged = true;

      // P0-5 修复（2026-09-17）：skipGlobalAudit 在**响应时刻**读取。
      // 原实现在中间件入口只检查一次，而 11 处赋值点都在控制器内部、响应之前
      // 才写 res.locals —— 入口检查永远早于赋值，标志 100% 失效，每个这类操作
      // 都被双写（控制器手写 1 条 + 本中间件按路由再写 1 条，action/category 不同）。
      if (res.locals && res.locals.skipGlobalAudit) {
        return; // 控制器已手动记录，本条操作跳过全局审计
      }

      const duration = Date.now() - startTime;
      // 用中间件入口已固化的 fullPath 派生：res.json 时刻 req.path 会被路由二次剥离，
      // 且 req.params 此时才有值，故路径必须取快照而非现读
      const { category, action } = deriveAuditMeta(req);
      // 状态码在流式响应里早在第一个 chunk 之前就已发出（200），此后出错无法回改。
      // 于是"半截 CSV/半截 Excel"会被记成一次**成功导出**——而审计库正是事后追责的
      // 依据，不能替失败的导出背书。由 errorHandler 与导出控制器在"错误终止响应"时
      // 显式打这个标记（人读的原因走 logger.error，这里只翻转机器可读的结论）。
      const abortedAfterHeaders = Boolean(res.locals && res.locals.responseAbortedByError);
      const success = res.statusCode < 400 && !abortedAfterHeaders;
      // 告诉错误处理器"这条审计已经落出去了"：流式响应在**第一个 chunk** 时就记一条
      // （P0-6 的刻意设计，崩溃也不丢记录），且 auditBuffer.push 会同步写 WAL，
      // 之后再改内存对象只会让 WAL 与库不一致。所以事后失败只能追加一条更正事件，
      // 不能就地翻转——这正是 append-only 审计的正确形态。
      if (res.locals) res.locals.auditRecordWritten = true;

      // 异步记录（不阻塞响应）；回调体见模块级 persistAuditRecord（体积棘轮拆分）
      setImmediate(() =>
        persistAuditRecord({ req, res, action, category, success, duration, fullPath, isGetAudit })
      );
    };

    // 拦截 json 响应
    res.json = (body) => {
      doLog();
      return originalJson(body);
    };

    // 同时拦截 send 响应（如导出文件等场景）
    res.send = (body) => {
      doLog();
      return originalSend(body);
    };

    // P0-6 修复（2026-09-17）：导出接口绕过 json/send——
    //   - services/auditExportService.js 直接 res.write(...) / res.end()
    //   - services/reportWorkbookService.js 走 workbook.xlsx.write(res)
    //     （ExcelJS 内部同样是 res.write/res.end）
    // 实测 GET /api/reports/export 与 GET /api/security/audit-logs/export
    // 真实下载成功但 auditBuffer 计数为 0。此处一并包装 write/end：
    //   - 用 rest 参数原样透传（含 write(chunk, encoding, callback) 的三参形态），
    //     返回值原样返回，不改变背压/流控语义；
    //   - logged 守卫保证整条响应只记录一次，多次 write 不会重复留痕；
    //   - 响应替身缺这两个方法时（typeof 守卫）跳过包装，不改变其行为。
    if (originalWrite) {
      res.write = (...args) => {
        doLog();
        return originalWrite(...args);
      };
    }
    if (originalEnd) {
      res.end = (...args) => {
        doLog();
        return originalEnd(...args);
      };
    }

    next();
  };
};

/**
 * 构造并投递一条请求型审计记录（doLog 的 setImmediate 回调体抽出）
 *
 * 抽出原因：该回调体内联在 auditLog 工厂函数里，使函数体达 117 行、doLog 达 64 行，
 * 双双顶爆体积棘轮（max-lines-per-function 100 行）。eslint.ratchet.json 只许降不许升，
 * 故按仓库既有约定拆为模块级函数；本函数即原回调体，逐行搬运、未改行为。
 *
 * 读取时机（抽出前后完全一致，勿提前快照）：
 *   - action/category/success/duration/fullPath/isGetAudit 由调用方在**响应时刻**固化后传入；
 *   - req.get("user-agent") / req.params / req.query / req.body / res.statusCode /
 *     res.statusMessage 仍在本函数执行时（setImmediate 回调时刻）读取。
 *
 * 脱敏口径：SENSITIVE_KEYS 取自 models/auditLogSanitizer（单一事实来源），深度上限与
 * 该模块 MAX_SANITIZE_DEPTH 对齐（P1-10：超限返回占位文案，不得原样返回子树）。
 *
 * @param {object} ctx 由 doLog 传入的响应时刻上下文
 * @returns {void}
 */
const persistAuditRecord = (ctx) => {
  const { req, res, action, category, success, duration, fullPath, isGetAudit } = ctx;
  // 控制字符清洗：userAgent / params / query 为外部可控输入，
  // 含 \n \r \u0000 时会污染下游日志渲染与 SIEM 解析，入库前统一剥离
  const safeUserAgent = stripControlChars(req.get('user-agent'), 512);
  // 键脱敏（此前缺）：body 走 SENSITIVE_KEYS 名单，而 params/query **完全不脱敏**，
  // 于是 `POST /api/auth/refresh?refreshToken=<真 JWT>` 这类经 query 传令牌的请求，
  // 会把可用凭证原样写进不可篡改、且会被定期导出成 CSV 的审计集合——
  // 审计库因此成了凭据库。名单与 body 同源（auditLogSanitizer 单一事实来源，
  // 其匹配是 matchesSensitiveBodyKey：先把键名里的空白/控制字符删掉再比子串，
  // 故 refreshToken/accessToken 能命中，插在词中间的 `pass\u0000word` 也能命中）。
  // query/params 额外并上「查询专用名单」（与 morgan URL 打码同一份口径）：
  // `?code=` / `?otp=` / `?authorization=` 这类裸键不含 token/password 子串，
  // 子串名单抓不到；而只用查询名单又会漏 camelCase（盲区方向相反），所以取并集。
  const safeParams = sanitizeAuditQuery(stripControlCharsDeep(req.params || {}));
  const safeQuery = sanitizeAuditQuery(stripControlCharsDeep(req.query || {}));
  const { computeFingerprint } = require('../../utils/fingerprint');
  const fingerprint = computeFingerprint(req);

  // 1. winston 日志（运维查看）—— 仅写关联指针，不重复写完整审计体
  //    完整审计体已持久化到 AuditLog 集合，此处仅留 reqId 关联线索供日志检索
  logger.info(
    'AUDIT ref=audit act=' +
      action +
      ' reqId=' +
      (req.id || '-') +
      ' u=' +
      (req.user?.username || 'anon')
  );

  // 2. 持久化到 AuditLog 集合（操作溯源/合规留存）
  //    走缓冲批量写（auditBuffer），降低高频写操作下每请求一次 DB 写的入库压力；
  //    事件型审计（AuditLog.record）不经此路径，保持直写以保证暴力破解检测实时性
  const auditBuffer = require('../../services/auditBuffer');
  auditBuffer.push({
    action,
    category,
    userId: req.user?.userId,
    username: req.user?.username || 'anonymous',
    sessionId: req.user?.sessionId || null,
    fingerprint,
    method: req.method,
    path: fullPath,
    params: safeParams,
    query: safeQuery,
    body: isGetAudit
      ? null
      : (() => {
          // 脱敏敏感字段（递归处理嵌套对象与数组，防止嵌套的密码/令牌明文入库）
          // #10：判定函数来自 models/auditLogSanitizer 单一事实来源（含 secret/apikey，
          // 且与它同样先删键名噪声再比子串）
          // P1-10 修复（2026-09-17）：深度超限**不得原样返回子树**。
          // 原实现 `depth > 6` 时 return value，而 sanitizeMongo 的
          // SANITIZE_MAX_DEPTH = 10（本文件上方）——7/8/9 层嵌套的明文
          // 口令因此绕过脱敏进入 auditBuffer（漏网窗口宽 3 层）。
          // 现与 models/auditLogSanitizer 的 MAX_SANITIZE_DEPTH = 6 对齐：
          // 超限返回同一占位文案 '[深度超限]'。
          // 为何未收敛为直接调用该模块的 sanitizeAuditBody：本文件的脱敏
          // 与 sanitizeMongo 的深度窗口同处一条防线，需要独立控制深度常量
          // （常量同值但不同源，直接调用会把本文件的窗口交给被调用方决定）。
          // 两处实现必须在 0–10 层输出逐字节一致，由
          // src/tests/middleware/auditStreamingCoverage.test.js
          // 「0–10 层：中间件脱敏结果与 sanitizeAuditBody 逐字节一致」锁定：
          // 实测把任一侧的深度上限改为 7，该用例立即转红。
          const AUDIT_BODY_MAX_SANITIZE_DEPTH = 6;
          const SANITIZE_DEPTH_EXCEEDED = '[深度超限]';
          const sanitizeValue = (value, depth = 0) => {
            // 深度保护，避免循环引用/超深嵌套导致栈溢出；判定顺序与
            // models/auditLogSanitizer.sanitizeAuditBody 保持一致（先判深度，再判原始类型）
            if (depth > AUDIT_BODY_MAX_SANITIZE_DEPTH) return SANITIZE_DEPTH_EXCEEDED;
            if (value === null || typeof value !== 'object') return value;
            if (Array.isArray(value)) return value.map((v) => sanitizeValue(v, depth + 1));
            const cleaned = {};
            for (const [k, v] of Object.entries(value)) {
              // 必须用 defineProperty 落键：express.json 走 JSON.parse，`{"__proto__":{...}}`
              // 的 __proto__ 是**自身可枚举键**，`cleaned[k] = ...` 会触发 Object.prototype
              // setter 使该键整个消失 ⇒ 攻击探针在审计副本里蒸发。models/auditLogSanitizer.js
              // 早已为此改成 defineProperty，本函数是同一规则的第二份实现，此前漏改。
              Object.defineProperty(cleaned, k, {
                value: isBodySensitiveKey(k.toLowerCase()) ? '***' : sanitizeValue(v, depth + 1),
                enumerable: true,
                writable: true,
                configurable: true,
              });
            }
            return cleaned;
          };
          return stripControlCharsDeep(sanitizeValue(req.body || {}));
        })(),
    statusCode: res.statusCode,
    success,
    errorMessage: success ? undefined : stripControlChars(res.statusMessage, 512),
    ip: req.ip,
    userAgent: safeUserAgent,
    duration,
  });
};
module.exports = {
  auditLog,
};
