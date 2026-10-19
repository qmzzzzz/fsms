/**
 * IP 黑白名单与早拒绝审计（自 `middleware/security.js` 拆出，2026-10-18）
 *
 * 内容：进程内 IP 封禁缓存（ipBlockCache）与降级口径、checkIPBlacklist 主闸门、
 * addToBlacklist 持久化、invalidateIPBlockCache 失效广播、recordEarlyRejection
 * 早拒绝审计（异步写 AuditLog）。fail-open 台账：constants/failOpenSites.js
 * 的 ip_blacklist_failopen 站点之一落在本文件。
 *
 * 注意：ipBlockCache 是**进程内**缓存（多实例不一致窗口见 constants/runtime.js
 * 的单进程清单条目），拆分不改变该语义。
 */

const logger = require('../../utils/logger');
const ApiResponse = require('../../utils/apiResponse');
const { normalizeIP, isClientIpIdentityTrustworthy } = require('../../utils/ipUtils');
const AuditLog = require('../../models/AuditLog');
const { computeFingerprint } = require('../../utils/fingerprint');
const { stripControlChars } = require('../../utils/helpers');
const { auditPath } = require('../../utils/auditMeta');

/**
 * 6. IP 黑白名单检查（全站最高优先级访问控制闸门）
 *
 * 挂载位置：app.js 中 CORS 之前、body 解析之前（早于 securityHeaders/protocolCompliance
 * 等所有其他中间件）。黑名单命中立即 403，不读请求体、不做 CORS 协商、不生成安全头，
 * 把被封禁 IP 的资源消耗压到最低；白名单命中挂 req.ipWhitelisted，供后续所有限制类
 * 中间件（限流/来源校验/query 限制等）豁免。
 *
 * 持久化到 MongoDB，进程重启后不丢失。带进程内缓存：仅在 DB 故障时降级使用
 * （拦截已知恶意 IP），DB 正常时一律以库为准。
 */
// 进程内 IP 缓存：DB 故障时的降级手段（仅缓存已知被封禁的 IP）
// 注意：绝不能在 DB 正常时前置短路——否则管理员解除封禁或加入白名单后，
// 该 IP 仍会被陈旧缓存拦截最长 5 分钟（表现为「界面已解封但依然 403」）
const ipBlockCache = new Map(); // normalizedIp -> expiresAt
const IP_BLOCK_CACHE_TTL_MS = 5 * 60 * 1000;

const ipBlockCacheCleanupTimer = setInterval(
  () => {
    const now = Date.now();
    for (const [ip, expiresAt] of ipBlockCache.entries()) {
      if (expiresAt <= now) ipBlockCache.delete(ip);
    }
  },
  5 * 60 * 1000
);
// P3-36：此处原注释称「setInterval(...).unref?.() 返回 undefined」——实测不成立，
// Node 的 Timeout.unref() 返回 Timeout 自身（`t.unref() === t` 为 true），
// 链式写法同样能拿到句柄。保留「先存句柄再 unref」的写法理由是可读性与
// 可清理性：句柄需要在 gracefulShutdown 里 clearInterval，显式命名比
// 依赖 unref 的返回值更不易误改。
ipBlockCacheCleanupTimer.unref?.();

/**
 * 统一缓存键：归一化后存取，使 ::ffff:1.2.3.4 与 1.2.3.4 命中同一条目。
 * 归一化失败并到一个共享占位键而不是回退原文——原文可能是请求方写的 XFF，
 * 逐请求换文本会把本缓存撑成无上限的键集（口径同 rateLimit.js）。
 * @param {string} ip 原始 IP
 * @returns {string} 缓存键
 */
const ipCacheKey = (ip) => normalizeIP(ip) || 'unknown';

/**
 * 失效降级缓存
 * 名单发生变更（解除封禁、加入白名单等）时调用，避免 DB 故障期沿用陈旧封禁判定。
 * 传入 CIDR 或不传时清空全部（无法从网段反推已缓存的具体 IP）
 * @param {string} [ip] 变更的 IP 或 CIDR；省略则全清
 */
const invalidateIPBlockCache = (ip) => {
  if (!ip || typeof ip !== 'string' || ip.includes('/')) {
    ipBlockCache.clear();
    return;
  }
  ipBlockCache.delete(ipCacheKey(ip));
};

/**
 * 记录「早于 auditLog 中间件的 403 拒绝」审计（P3-35）
 *
 * checkIPBlacklist 与 originCheck 都挂在 auditLog 之前（必须如此：黑名单要在
 * 一切业务处理前拦下，来源校验要在写操作触达控制器前拦下）。副作用是它们的
 * 403 完全不进审计——攻击探测最密集的这段流量在合规留存里是一片空白，
 * 事后既无法统计封禁命中，也无法证明拦截曾生效。
 *
 * 直写 AuditLog.record 而不走 auditBuffer：这类事件量小且属安全信号，
 * 需要即时可查（暴力探测检测也依赖实时性），与 ip_range_denied 同口径。
 * @param {import('express').Request} req
 * @param {{action: string, reason: string, riskFactors: string[], riskLevel?: string, statusCode?: number}} meta
 *        statusCode 缺省 403（黑名单/来源这两类都是拒绝式 403）；
 *        查询形态守卫那类是 400，必须传真实值——审计里记错状态码，
 *        等于让事后统计把"畸形请求被拒"算成"越权被拒"。
 * @returns {void}
 */
const recordEarlyRejection = (req, meta) => {
  setImmediate(() => {
    try {
      AuditLog.record({
        action: meta.action,
        category: 'security',
        userId: req.user?.userId,
        username: req.user?.username || 'anonymous',
        sessionId: req.user?.sessionId || null,
        fingerprint: computeFingerprint(req),
        // method 原样交下去：取值全集与"越枚举怎么办"由 AuditLog schema
        // （constants/audit.js 的 AUDIT_HTTP_METHODS + setter）单点决定。
        // 原先这里私抄一份 5 动词白名单，把 HEAD/OPTIONS 探测**静默降级成无 method 的记录**，
        // 而这类探测恰恰是安全信号——事后看不出它是 HEAD。
        method: req.method,
        path: auditPath(req),
        ip: req.ip,
        userAgent: stripControlChars(req.get('user-agent'), 512),
        statusCode: meta.statusCode || 403,
        success: false,
        riskLevel: meta.riskLevel || 'medium',
        riskFactors: meta.riskFactors,
        reason: stripControlChars(meta.reason, 512),
      });
    } catch (e) {
      logger.debug(`早期拒绝审计写入跳过：${e.message}`);
    }
  });
};

/**
 * 白名单豁免标记（req.ipWhitelisted）的**可信边界**判定（2026-09-26 审计 Top3）
 *
 * 为什么需要：req.ip 在 TRUST_PROXY_HOPS>0 时取自 X-Forwarded-For（生产 compose
 * 默认 1 跳），能直连应用端口的主体（容器网络、误配入口、SSRF 跳板）伪造一跳
 * XFF 即可把 req.ip 变成任意白名单 IP——该标记会被资源型限流（rateLimit.js 的
 * skipIfWhitelisted）、CSRF 来源校验（originCheck.js）、query 长度限制
 * （queryLimit.js queryLengthLimit）同时豁免，一次伪造拿到三重豁免（伪造实测
 * 口径见 tests 的 laneE/xffCredentialLimiter）。修复范式与 metricsAuth 的 M-07
 * 同源：安全豁免只信**不可伪造的 socket 对端**。
 *
 * 三种可发放形态（其余一律不发，宁可不豁免也不能被伪造头买通）：
 *  1) 未启用 trust proxy：req.ip 恒等于 socket 对端，请求头不参与判定；
 *  2) 请求未携带 X-Forwarded-For：即使 trust proxy 开着，req.ip 也只能是 socket 对端；
 *  3) trust proxy 开启且携带 XFF：req.ip 来自请求头，只有 socket 对端属于
 *     内网/回环（即 nginx/容器网络等基础设施，与 metricsAuth 的放行口径一致）时，
 *     该 XFF 才是可信代理写入的（生产 nginx 覆写 `X-Forwarded-For $remote_addr`）。
 * 经 nginx 的正常流量命中 3) ⇒ 白名单不受影响；公网直连+伪造 XFF 落 3) 拒绝侧 ⇒ 豁免不可用（探针 E/A）。
 * 但 3) 认的是"任意内网/回环对端"而非"被指定的代理"：容器网络里的直连方伪造一跳即可同时免黑名单+拿豁免（探针 D）。
 *
 * 判据本体自 2026-10-01 移到 utils/ipUtils.js 的 `isClientIpIdentityTrustworthy`
 * （理由见那里的头注释：认证侧的 allowedIPs 与豁免发放是同一条伪造链的两侧，必须
 * 共用一个事实来源）。本文件保留同名再导出，消费方与既有断言口径不变。
 *
 * 顺带更正本注释的一处旧推断：原先写「黑名单/封禁判定由网络层兜底（仅 nginx 可达
 * 应用端口）」——这个前提在随仓交付的 compose 拓扑里不成立：`docker-compose.yml`
 * 把应用端口发布为 `127.0.0.1:3000:3000`，同一容器网络内的任意服务都能直连 `app:3000`，
 * 其对端地址恰是 RFC1918 ⇒ 命中上面的可信形态 3) ⇒ 单个 XFF 即可把处置目标换成任意
 * 地址。惩罚侧（自动封禁的归属判定）因此不能再靠"网络层兜底"这句话免责。
 *
 * @param {import('express').Request} req
 * @returns {boolean} true=可发放豁免标记
 */
const isWhitelistExemptionTrustworthy = (req) => isClientIpIdentityTrustworthy(req);

const checkIPBlacklist = async (req, res, next) => {
  const clientIP = require('../../utils/ipUtils').clientIpForSecurityDecision(req);

  try {
    const IPBlacklist = require('../../models/IPBlacklist');

    // 黑白名单并行查询（两者共用模型层名单快照，单次加载即可完成两次匹配）
    const [isWhitelisted, isBlocked] = await Promise.all([
      IPBlacklist.isWhitelisted(clientIP),
      IPBlacklist.isBlocked(clientIP),
    ]);

    // 白名单优先：命中则豁免黑名单拦截，并挂标记供限流器豁免。
    // 豁免标记只在可信边界内发放（见 isWhitelistExemptionTrustworthy）：边界不可信时不发
    // 标记、也不拦截——限流与来源校验照常生效。**别把它读成"代价只有豁免"**：下面两次
    // 名单查询取 clientIpForSecurityDecision（#24 R1）：边界外退回 socket 对端 ⇒ 探针 A/B 转拦截；容器内直连（对端 RFC1918）仍判可信形态 3) ⇒ 探针 D 仍可用，关它属 R3。
    if (isWhitelisted) {
      if (isWhitelistExemptionTrustworthy(req)) {
        req.ipWhitelisted = true;
      } else {
        logger.warn(
          `白名单命中但来源边界不可信（公网直连且携带 X-Forwarded-For），豁免标记不下发：${clientIP}`
        );
      }
      // 已被信任的 IP 不应留有封禁缓存，否则 DB 故障期会被误拦
      invalidateIPBlockCache(clientIP);
      return next();
    }

    if (isBlocked) {
      // 写入进程内缓存（5 分钟 TTL），供 DB 故障时降级使用
      ipBlockCache.set(ipCacheKey(clientIP), Date.now() + IP_BLOCK_CACHE_TTL_MS);
      logger.warn(`黑名单 IP 访问被拦截：${clientIP}`);
      recordEarlyRejection(req, {
        action: 'ip_blacklist_blocked',
        reason: '请求 IP 命中黑名单，已拒绝访问',
        riskFactors: ['ip_blacklisted'],
        riskLevel: 'high',
      });
      // 黑名单命中通知（可观测性轮）：按 IP 频控去重后投递 webhook，
      // fire-and-forget 不拖慢拦截路径。
      // F-214：这里必须走统一入口 dispatchNotification，不能写成
      // `void sendNotification(...)`。裸调的 promise 没有 catch，而**下面这个
      // try 抓不到异步 reject**（async 函数不抛异常，它返回 rejected promise），
      // 于是「通知失败不影响主流程」这句注释在裸 void 下是不成立的：它会命中
      // index.js 的 unhandledRejection 分支，而那条分支在所有环境都 process.exit(1)。
      // 换成统一入口之后这个 try/catch 才真的闭合：它覆盖的是 require 与
      // shouldSendAlert 两处同步抛点，没有逃逸的异步路径。
      try {
        const { shouldSendAlert, dispatchNotification } = require('../../services/securityAlert');
        if (shouldSendAlert('blacklist_hit_' + clientIP)) {
          dispatchNotification('ip_blacklist_hit', 'high', '黑名单 IP 访问被拦截：' + clientIP, {
            ip: clientIP,
            path: req.originalUrl,
          });
        }
      } catch (_) {
        /* 通知失败不影响拦截主流程（同步部分；异步部分由统一入口的 catch 负责） */
      }
      return ApiResponse.codeError(res, 'IP_BLOCKED');
    }

    // DB 查询成功且未命中黑名单：清除可能存在的陈旧缓存（解封后立即放行）
    invalidateIPBlockCache(clientIP);
  } catch (err) {
    // DB 故障时才启用降级缓存：仅拦截故障前已确认的恶意 IP，
    // 缓存未命中则放行（避免数据库抖动造成全站不可用），并记录告警
    logger.error(`IP 黑名单查询失败，降级到缓存模式：${err.message}`);
    const cachedExpiry = ipBlockCache.get(ipCacheKey(clientIP));
    if (cachedExpiry && cachedExpiry > Date.now()) {
      logger.warn(`黑名单 IP 访问被拦截（降级缓存）：${clientIP}`);
      recordEarlyRejection(req, {
        action: 'ip_blacklist_blocked',
        reason: '请求 IP 命中黑名单降级缓存（数据库查询失败），已拒绝访问',
        riskFactors: ['ip_blacklisted', 'blacklist_db_degraded'],
        riskLevel: 'high',
      });
      return ApiResponse.codeError(res, 'IP_BLOCKED');
    }
    // 评价报告 #7：fail-open 放行（缓存未命中）必须有显式可观测信号——
    // 否则「DB 挂了 + 全站裸奔」只有一条 error 日志可循。计入
    // security_alerts_total{type=ip_blacklist_failopen,level=high}，
    // 由 alert-rules 的「安全告警突增」规则捕获，运维可据此紧急处置。
    try {
      require('../../utils/metrics').incSecurityAlert('ip_blacklist_failopen', 'high');
    } catch (_) {
      /* 指标端不可用不影响放行主流程 */
    }
    logger.warn(`IP 黑名单降级缓存未命中，fail-open 放行：${clientIP}`);
  }

  next();
};

/**
 * 动态添加 IP 到黑名单（持久化到 MongoDB）
 * 入库前归一化 IP：Node 在 IPv6 栈下 req.ip 形如 ::ffff:1.2.3.4，
 * 若原样入库会与管理员手动录入的 1.2.3.4 产生两条指向同一地址的记录
 * （复合唯一索引 { ip, type } 按文本判重，无法拦截），导致解封时漏删。
 * @param {string} ip - 要封禁的 IP
 * @param {number} durationMs - 封禁时长（毫秒），默认 1 小时
 * @param {string} reason - 封禁原因
 * @param {string} source - 封禁来源（manual/auto）
 * @returns {Promise<{banned: boolean, reason?: string, normalizedIp?: string}>}
 *   本函数**从不抛错**（内部自己 catch 掉持久化失败），所以"await 正常返回"绝不等于"封禁生效"。
 *   成功与否只能靠这个返回值判断，调用方不得按"没抛异常"记成功：
 *   - `{banned:true, normalizedIp}`：黑名单已落库；
 *   - `{banned:false, reason}`：一条记录都没写，reason ∈ unparsable_ip / whitelisted / persist_failed。
 */
const addToBlacklist = async (
  ip,
  durationMs = 3600000,
  reason = 'security_policy',
  source = 'manual'
) => {
  try {
    const IPBlacklist = require('../../models/IPBlacklist');

    const normalizedIp = normalizeIP(ip);
    if (!normalizedIp) {
      logger.warn(`IP 黑名单添加跳过：无法解析的地址 ${ip}`);
      return { banned: false, reason: 'unparsable_ip' };
    }

    // 白名单优先：信任 IP 不做自动封禁（如内网监控探针等可信来源的高频请求）
    const whitelisted = await IPBlacklist.isWhitelisted(normalizedIp).catch(() => false);
    if (whitelisted) {
      logger.info(`IP ${normalizedIp} 在白名单中，跳过自动封禁`);
      return { banned: false, reason: 'whitelisted' };
    }

    await IPBlacklist.blockIP(normalizedIp, { reason, durationMs, source });
    logger.warn(
      `IP 已加入黑名单：${normalizedIp}, 封禁时长：${durationMs / 1000}秒, 原因：${reason}`
    );
    return { banned: true, normalizedIp };
  } catch (err) {
    logger.error(`IP 黑名单添加失败：${ip}, 错误：${err.message}`);
    return { banned: false, reason: 'persist_failed' };
  }
};
module.exports = {
  checkIPBlacklist,
  isWhitelistExemptionTrustworthy,
  addToBlacklist,
  invalidateIPBlockCache,
  recordEarlyRejection,
};
