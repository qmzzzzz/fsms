/**
 * 传输加密启动断言（P2-⑧，2026-09-30）——判据收口在本文件
 *
 * 审计缺口核查（deliverables/安全缺口核查-2026-09-30.md P2-⑧）指出：
 * Mongo/Redis 连接串可以在生产里指向非回环主机而完全不加密——凭据与数据明文过网。
 * 风险边界（如实说）：**同宿主 docker 网络**内明文风险有限，所以判据是
 * fail-closed + **显式命名的豁免旗**，而不是默认放行：拓扑变化（分库部署/
 * 云托管实例）时忘关豁免会在启动期被拦下，而不是先明文过网再被人事后发现。
 * docker-compose.yml 即豁免形态（同宿主受信容器网络），注释里写明了摘旗条件。
 *
 * 为什么拆成本文件：validate.js 已顶着体积/复杂度棘轮基线，整段内联会双双
 * 超标——按仓库既有出路按职责拆文件（roleGuards.js / rateLimitEscalationBan.js
 * 先例），判据反而多了一个可独立测试的单一事实来源。
 */

/**
 * 回环主机判定。
 *
 * 刻意不做字符串 includes('localhost')（collectConnectionErrors 旧判据的写法，
 * 连 127.0.0.1 都认不出）：回环是一个**地址性质**，写成 localhost / 127.0.0.1 /
 * [::1] / ::ffff:127.0.0.1 的都是同一条"不出网卡"的事实。判不出的一律按
 * 非回环处理（fail-closed）。
 *
 * 未指定地址 `::` / `0.0.0.0` 不是回环——它是"任意接口"，与 127.0.0.1/::1 恰好
 * 相反，明文连它可能出网卡，故两者一并落在判据外（口径必须对称：曾因只把
 * `0.0.0.0` 留在外面而让 `mongodb://[::]/` 静默跳过 TLS 断言）。
 */
const isLoopbackHostname = (rawHostname) => {
  if (!rawHostname) return false;
  const h = String(rawHostname)
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return (
    h === 'localhost' ||
    h.endsWith('.localhost') ||
    h === '::1' ||
    h === '127.0.0.1' ||
    /^127(\.\d{1,3}){3}$/.test(h) ||
    h.startsWith('::ffff:127.')
  );
};

/**
 * 从 URI 里取主机名；解析失败返回 null（调用方对 null 保持沉默）。
 * mongodb://mongodb+srv://redis:// 都是 `//` 带权形态，WHATWG URL 能取到 hostname；
 * 解析失败意味着 URI 形态本就不合法，传输加密断言不对它发言——
 * 它会由驱动连接失败兜底，也避免这里对替身/脱敏形态的 URI（compose 契约测试
 * 的 secrets 替身是 "DUMMY:mongodb_uri"）误报。
 */
const uriHostname = (uri) => {
  try {
    return new URL(uri).hostname;
  } catch (_) {
    return null;
  }
};

/**
 * 往 errors 里收集 Mongo/Redis 的 host 侧违例（由 validate.js 的
 * collectConnectionErrors 在生产语义下调用；开发环境不进来）。
 * 既有的「不能指向 localhost」一并收口到这里：它与 TLS 断言判的是同一个
 * 对象（连接串的主机形态），分在两个文件只会让人以为那是两套事实来源。
 */
/**
 * Redis 认证闸（2026-10-01 审计 finding：redis 此前无 --requirepass 且与监控栈
 * 同处一张扁平网络——Grafana 任意数据源 URL 即一条无密码写路径：删黑名单键 =
 * 撤销封禁、清限流计数 = 解除封顶）。口令两种携带形态任一：URL userinfo 段，
 * 或 REDIS_PASSWORD（生产 compose 经 REDIS_PASSWORD_FILE 注入，建连点见
 * sharedCache.redisConnectionPassword）；受信内网免认证须显式声明
 * REDIS_AUTH_EXEMPT=true（与 REDIS_TLS_EXEMPT 同族：豁免必须可见，不许静默）。
 *
 * **回环豁免**（与 TLS 闸同一条既有口径）：redis 指向 127.0.0.1/localhost/::1
 * 时只有本机进程可达，无认证的暴露面收敛到本机——production-drill 的临时栈
 * 与单机部署形态靠这条放行（e2e CI 曾因本闸无豁免而红，实测复现）。
 *
 * 独立成函数不只是拆复杂度：它判的是「Redis 上的身份」，与 host 侧的「流量去哪」
 * 是两个维度，分开后各自可独立断言。
 */
const collectRedisAuthErrors = (errors, parsedRedisUrl) => {
  if (isLoopbackHostname(parsedRedisUrl.hostname)) return;
  const hasUrlCredential = Boolean(parsedRedisUrl.username || parsedRedisUrl.password);
  if (
    !hasUrlCredential &&
    !process.env.REDIS_PASSWORD &&
    process.env.REDIS_AUTH_EXEMPT !== 'true'
  ) {
    errors.push(
      'Redis 必须启用认证：REDIS_PASSWORD 未设置且 REDIS_URL 不含凭据段' +
        '（会话缓存/限流计数/IP 黑名单广播全在这上面，无认证等于任何同网容器都能改写）。' +
        '生产拓扑经 compose secrets 注入 REDIS_PASSWORD_FILE；' +
        '确属受信内网的免认证部署请显式声明 REDIS_AUTH_EXEMPT=true'
    );
  }
};

const collectTransportErrors = (errors) => {
  const mongoUri = (process.env.MONGODB_URI || '').trim();

  if (!mongoUri || mongoUri.includes('localhost')) {
    errors.push('MONGODB_URI 不能指向 localhost');
    return;
  }

  const mongoHost = uriHostname(mongoUri);
  const mongoLoopback = isLoopbackHostname(mongoHost);
  const mongoHasTls = /[?&](?:tls|ssl)=true/i.test(mongoUri);
  if (
    mongoHost !== null &&
    !mongoLoopback &&
    !mongoHasTls &&
    process.env.MONGODB_TLS_EXEMPT !== 'true'
  ) {
    errors.push(
      'MONGODB_URI 指向非回环主机但未启用传输加密（URI 追加 ?tls=true）。' +
        '确属同宿主受信容器网络时，显式设置 MONGODB_TLS_EXEMPT=true 并在部署文档记录拓扑依据'
    );
  }

  const redisUrl = (process.env.REDIS_URL || '').trim();
  if (!redisUrl) return;
  let parsedRedisUrl;
  try {
    parsedRedisUrl = new URL(redisUrl);
  } catch (_) {
    return; // URI 形态非法由 collectConnectionErrors 的既有协议校验报错，这里不重复
  }
  if (
    parsedRedisUrl.protocol === 'redis:' &&
    !isLoopbackHostname(parsedRedisUrl.hostname) &&
    process.env.REDIS_TLS_EXEMPT !== 'true'
  ) {
    errors.push(
      'REDIS_URL 指向非回环主机但使用明文 redis:（应改用 rediss:）。' +
        '确属同宿主受信容器网络时，显式设置 REDIS_TLS_EXEMPT=true 并在部署文档记录拓扑依据'
    );
  }

  // Redis 认证闸：判据见 collectRedisAuthErrors 的头注释
  collectRedisAuthErrors(errors, parsedRedisUrl);
};

module.exports = { collectTransportErrors, isLoopbackHostname, uriHostname };
