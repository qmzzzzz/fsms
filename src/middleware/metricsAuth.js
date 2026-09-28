/**
 * /metrics 应用层鉴权纵深（可观测性审计改进项）
 *
 * 背景：/metrics 只暴露 QPS/延迟/错误率/安全告警计数等运行情报，
 * 此前仅靠 Nginx 网络层限源（nginx.conf.example 的 allow/deny），应用层
 * 无任何防线——Nginx 配置漂移、或有人从容器网络直连 app:3000 时即暴露。
 * 本中间件作为第二道防线，与 Nginx 限源纵深互补。
 *
 * 鉴权策略（fail-safe：不确定来源一律拒绝）：
 *  1. 配置了 METRICS_TOKEN 且请求携带正确 Bearer 令牌 → 放行
 *     （供跨网段抓取/经代理收敛出口的场景，与 Nginx 白名单互不依赖）；
 *  2. 来源 IP 属内网/回环（含 IPv4-mapped IPv6）→ 放行，
 *     保持「本机与容器网络 Prometheus 直连」零配置兼容；
 *  3. 其余（公网来源、无法解析的来源、token 缺失/错误）→ 401 拒绝。
 *
 * 配置说明：
 *  - METRICS_TOKEN（可选）：openssl rand -hex 32 生成。未配置时退化为
 *    「仅内网放行」，绝不因缺省而 fail-open 到公网可读；
 *  - 令牌比较用 timingSafeEqual 防时序侧信道；长度不等先短路
 *    （timingSafeEqual 仅接受等长输入；长度差异最多暴露「令牌长度」这一
 *     无关紧要的信息，而全等长路径才是逐字节比较的防侧信道主体）。
 */

// 地址解析统一走 ipUtils（内含严格形态判据），本文件不再直接依赖 ipaddr
const { parseIP } = require('../utils/ipUtils');
const crypto = require('crypto');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');

/**
 * 判断 IP 是否属内网/回环（Prometheus 抓取的合法网段）
 *
 * 解析走 `ipUtils.parseIP`，不再直接 `ipaddr.parse`。这是加固而非修洞，理由如下。
 *
 * 唯一调用方传的是 `req.socket.remoteAddress`（见下方 M-07 注释），它取自 TCP 连接
 * 本身、不受任何请求头影响，且由 OS 给出规范形态（`::ffff:a.b.c.d` 或规范 IPv6）
 * ⇒ 宽松数值形态今天**进不到这个函数**，"XFF 可控即可伪装环回放行 /metrics"在本调用点上不成立。
 *
 * 那这次改什么价值：
 *  1) 本函数是 **exported** 判据。它的输入契约目前是"socket 对端"，但签名和名字
 *     都不体现这一点；一旦有人拿它去判 req.ip（或 M-07 被回退），
 *     `0177.0.0.1` / `0x7f.0.0.1` / `2130706433` / `127.1` 实测一律被判定为环回 ⇒ 放行。
 * 同一根因在名单侧已经关过一次，这里补齐最后一处独立解析器。
 *  2) 全仓 IP 解析回到"一把尺子"：`grep "require('ipaddr.js')" src/` 现在只剩
 *     ipUtils（判据本体）、ipRange（对已归一化的值做 match）、
 *     securityAlertDelivery（输入是 WHATWG URL 归一化后的 hostname，实测同尺）。
 * 拒绝方向不变：parseIP 对"解析不出"与"形态有歧义"都返回 null ⇒ 仍走 fail-safe 拒绝，
 * 不新增拒绝类别，所以真内网/回环抓取（含 `::ffff:` 映射形态）行为分毫未动。
 */
function isPrivateOrLoopback(rawIp) {
  if (!rawIp) return false;
  const ip = parseIP(String(rawIp));
  if (!ip) return false;

  const range = ip.range();
  // ::ffff:a.b.c.d 形式的 IPv4-mapped IPv6 解包回 IPv4 再判段：
  // trust proxy 未启用时 req.ip 常保留该形式，若按 IPv6 段判定会把
  // 本机回环误判为公网，导致本机抓取被拒
  if (ip.kind() === 'ipv6' && range === 'ipv4Mapped') {
    return ['loopback', 'private', 'linkLocal'].includes(ip.toIPv4Address().range());
  }
  // IPv4: loopback/private/linkLocal；IPv6: loopback/uniqueLocal/linkLocal
  return ['loopback', 'private', 'linkLocal', 'uniqueLocal'].includes(range);
}

/** 等长校验 + timingSafeEqual 比较，防逐字节时序侧信道 */
function safeTokenEqual(provided, expected) {
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * 中间件工厂：token 在工厂调用时固化（进程启动期确定），
 * 既避免每请求读 env 的开销，也让测试可用不同 token 独立构建实例
 * @param {string|{token?: string}} [options] 直接传 token 字符串（测试便捷）
 *   或 { token } 选项对象；缺省读 METRICS_TOKEN
 */
function createMetricsAuth(options = {}) {
  const opts = typeof options === 'string' ? { token: options } : options || {};
  const token = opts.token !== undefined ? String(opts.token) : process.env.METRICS_TOKEN || '';

  return function metricsAuth(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    // ① 正确 Bearer 令牌放行（令牌路径优先，供受控的跨网段抓取）
    if (token && bearer && safeTokenEqual(bearer, token)) {
      return next();
    }

    // ② 内网/回环来源放行：容器网络内 Prometheus → app:3000 零配置兼容
    //
    // 【M-07 修复】判定必须用**不可伪造的 socket 对端地址**，不能用 req.ip。
    // req.ip 在启用 trust proxy 时会采纳 X-Forwarded-For：生产环境
    // validate.js 强制 TRUST_PROXY_HOPS，故 req.ip 必然受 XFF 影响。此时
    // 直连 app 端口的攻击者只需发送 `X-Forwarded-For: 127.0.0.1`，req.ip 即
    // 变为回环地址，跳过令牌校验——恰好在本中间件注释声明的防御场景
    //（Nginx 配置漂移、有人从容器网络直连 app:3000）下失效。
    // 后果：泄露 QPS、延迟直方图、错误计数与**安全告警计数**（可据以判断
    // 攻击是否被检测到），属侦察面。
    //
    // req.socket.remoteAddress 取自 TCP 连接本身，不受任何请求头影响。
    const peerIp = req.socket?.remoteAddress || req.connection?.remoteAddress || '';
    if (isPrivateOrLoopback(peerIp)) {
      return next();
    }

    // ③ 其余一律拒绝：公网直连（Nginx 防线已失守的信号）必须在此被拦下
    // 日志同时记录 socket 对端与 req.ip：二者不一致说明有 XFF 伪造尝试
    logger.warn('metrics 端点拒绝非内网来源', {
      peer: peerIp || 'unknown',
      reqIp: req.ip || 'unknown',
    });
    return ApiResponse.codeError(res, 'METRICS_INTERNAL_ONLY');
  };
}

// 默认实例：进程启动期固化 METRICS_TOKEN（生产入口直接使用）
const metricsAuth = createMetricsAuth();

module.exports = { metricsAuth, createMetricsAuth, isPrivateOrLoopback };
