/**
 * /metrics 应用层鉴权（可观测性审计改进项；2026-11-03 收窄私网放行）
 *
 * 背景：/metrics 只暴露 QPS/延迟/错误率/安全告警计数等运行情报。只靠 Nginx 网络层
 * 限源（nginx.conf.example 的 allow/deny）时应用层无任何防线——Nginx 配置漂移、或
 * 有人从容器网络直连 app:3000 即暴露。本中间件作为第二道防线，与 Nginx 限源纵深互补。
 *
 * 鉴权策略（fail-safe：不确定来源一律拒绝）：
 *  1. 配置了 METRICS_TOKEN 且请求携带正确 Bearer 令牌 → 放行
 *     （跨网段/容器网络抓取的统一合法路径，与 Nginx 白名单互不依赖）；
 *  2. socket 对端是**回环**且未声明反代 → 放行，保持「本机 Prometheus 直连」零配置兼容。
 *     例外：`TRUST_PROXY_HOPS > 0` 时**回环对端必须携带令牌**。该拓扑下回环
 *     对端是反代本身而不是抓取方，任何穿过 Nginx 的请求（含 ACL 漂移后
 *     放行的公网请求）在应用层都长得和抓取完全一样——不要求令牌，这道
 *     第二防线就等于不存在。
 *  3. 其余一律 401 拒绝——**含非回环私网对端**（2026-11-03 渗透测试 i760 #21）。
 *     旧版对私网对端零配置放行，理由是「容器网络内 Prometheus 直连」；但私网
 *     只是位置不是身份：与被监控目标同处一个办公网/容器网的任何主机，都能匿名
 *     读到完整路由表（逐路由请求计数）、延迟分布与 security_alerts_total——
 *     后者让攻击者实时判断"我的动作有没有触发告警"，属侦察面。收窄后抓取方
 *     二选一：与应用同机（回环，免令牌），或配置 METRICS_TOKEN（shipped
 *     compose 已透传该 secret，deployment/observability/prometheus.yml 以
 *     bearer_token_file 消费同一份文件）。
 *
 * 配置说明：
 *  - METRICS_TOKEN（可选）：openssl rand -hex 32 生成。未配置时退化为
 *    「仅回环放行」，绝不因缺省而 fail-open 到私网/公网可读；声明了反代
 *    （TRUST_PROXY_HOPS>0）时，经反代访问 /metrics 必须配置并携带它；
 *  - 令牌比较用 timingSafeEqual 防时序侧信道；长度不等先短路
 *    （timingSafeEqual 仅接受等长输入；长度差异最多暴露「令牌长度」这一
 *     无关紧要的信息，而全等长路径才是逐字节比较的防侧信道主体）。
 */

// 地址解析统一走 ipUtils（内含严格形态判据），本文件不再直接依赖 ipaddr。
// isPrivateOrLoopback 的判据本体也已迁入 ipUtils：logShipper 的出站目标门禁
// 需要同一把尺，本文件保留同名再导出以稳定既有引用（测试与豁免判定仍从这里取）。
const { isPrivateOrLoopback, isLoopbackAddress } = require('../utils/ipUtils');
const crypto = require('crypto');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');

/**
 * 判断 IP 是否属内网/回环（历史口径保留：再导出供既有引用方使用）
 *
 * 判据本体在 `utils/ipUtils.isPrivateOrLoopback`。使用契约（勿回退）：调用方必须传
 * `req.socket.remoteAddress` 这类取自 TCP 连接本身、不受任何请求头影响的地址；
 * 宽松数值形态（`0177.0.0.1` / `0x7f.0.0.1` / `2130706433` / `127.1`，ipUtils 的
 * 严格解析一律 null ⇒ false）进不到本判定，"XFF 伪造来源伪装环回"在此不成立。
 */

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
 * @param {string|{token?: string, trustProxyHops?: number|string}} [options] 直接传 token 字符串（测试便捷）
 *   或 { token, trustProxyHops } 选项对象；缺省读 METRICS_TOKEN / TRUST_PROXY_HOPS
 */
function createMetricsAuth(options = {}) {
  const opts = typeof options === 'string' ? { token: options } : options || {};
  const token = opts.token !== undefined ? String(opts.token) : process.env.METRICS_TOKEN || '';
  // 与 config/validate 的运行时归一同一语义：非正整数/缺省都当作"未声明反代"。
  // 非法值不在这里告警——启动期 config/validate 已按同一个判据报错。
  const rawHops =
    opts.trustProxyHops !== undefined ? opts.trustProxyHops : process.env.TRUST_PROXY_HOPS;
  const parsedHops = parseInt(String(rawHops ?? '').trim(), 10);
  const behindProxy = Number.isInteger(parsedHops) && parsedHops > 0;

  return function metricsAuth(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    // ① 正确 Bearer 令牌放行（令牌路径优先，供受控的跨网段抓取）
    if (token && bearer && safeTokenEqual(bearer, token)) {
      return next();
    }

    // ② 判定必须用**不可伪造的 socket 对端地址**，不能用 req.ip。
    // req.ip 在启用 trust proxy 时会采纳 X-Forwarded-For：生产环境
    // validate.js 强制 TRUST_PROXY_HOPS，故 req.ip 必然受 XFF 影响。此时
    // 直连 app 端口的攻击者只需发送 `X-Forwarded-For: 127.0.0.1`，req.ip 即
    // 变为回环地址，跳过令牌校验——恰好在本中间件注释声明的防御场景
    //（Nginx 配置漂移、有人从容器网络直连 app:3000）下失效。
    // req.socket.remoteAddress 取自 TCP 连接本身，不受任何请求头影响。
    const peerIp = req.socket?.remoteAddress || req.connection?.remoteAddress || '';

    // ②a 反代声明生效时，回环对端是反代而不是抓取方：此时"来自回环"不提供任何
    // 区分度（公网请求经 Nginx 转发同样以 127.0.0.1 到达），必须靠令牌区分。
    if (behindProxy && isLoopbackAddress(peerIp)) {
      logger.warn('metrics 端点拒绝：反代拓扑下的回环请求缺少有效 METRICS_TOKEN', {
        peer: peerIp,
        reqIp: req.ip || 'unknown',
      });
      return ApiResponse.codeError(res, 'METRICS_INTERNAL_ONLY');
    }

    // ②b 未声明反代时的零配置放行**只到回环为止**（本机抓取）。
    // 2026-11-03 收窄（渗透测试 i760 #21）：旧版这里放行全部私网对端，
    // 与目标同网段的主机即可匿名读路由表、延迟分布与安全告警计数。
    // 私网抓取方（如 compose 内 Prometheus → app:3000）改走令牌路径 ①。
    if (isLoopbackAddress(peerIp)) {
      return next();
    }

    // ③ 其余一律拒绝：非回环私网与公网直连都必须在此被拦下。
    // 日志同时记录 socket 对端与 req.ip：二者不一致说明有 XFF 伪造尝试
    logger.warn('metrics 端点拒绝非回环来源（私网抓取须配置 METRICS_TOKEN）', {
      peer: peerIp || 'unknown',
      reqIp: req.ip || 'unknown',
    });
    return ApiResponse.codeError(res, 'METRICS_INTERNAL_ONLY');
  };
}

// 默认实例：进程启动期固化 METRICS_TOKEN（生产入口直接使用）
const metricsAuth = createMetricsAuth();

module.exports = { metricsAuth, createMetricsAuth, isPrivateOrLoopback };
