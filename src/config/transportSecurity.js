/**
 * 传输加密启动断言——Mongo/Redis 连接串指向非回环主机却不加密时拦下启动。
 *
 * 判据是 fail-closed + **显式命名的豁免旗**，不是默认放行：同宿主 docker 网络内
 * 明文风险有限（docker-compose.yml 即该形态，注释写明摘旗条件），但拓扑一变
 * （分库/云托管实例）忘关豁免必须在启动期被拦下，而不是先明文过网再事后发现。
 * 本文件同时收口 host 侧违例（「不能指向 localhost」）与 TLS 断言——两者判的是
 * 同一个对象（连接串的主机形态），分在两处只会让人以为那是两套事实来源。
 * 拆出本文件是因为 validate.js 已顶着体积/复杂度棘轮基线，内联会双双超标。
 */

/**
 * 回环主机判定：回环是**地址性质**，写成 localhost / 127.0.0.1 / [::1] /
 * ::ffff:127.0.0.1 都是同一条"不出网卡"的事实；判不出的一律按非回环处理（fail-closed）。
 * 未指定地址 `::` / `0.0.0.0` 不是回环而是"任意接口"，明文连它可能出网卡，故一并落在
 * 判据外（口径必须对称：只把 `0.0.0.0` 留在外面会让 `mongodb://[::]/` 静默跳过 TLS 断言）。
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
 * 从 URI 取主机名；解析失败返回 null（调用方对 null 保持沉默）：URI 形态本就不合法时
 * 由驱动连接失败兜底，也避免对替身/脱敏形态的 URI（compose 契约测试用 "DUMMY:mongodb_uri"）误报。
 */
const uriHostname = (uri) => {
  try {
    return new URL(uri).hostname;
  } catch (_) {
    return null;
  }
};

/**
 * Redis 认证闸：redis 与监控栈同处一张扁平网络时，Grafana 任意数据源 URL 即一条无密码
 * 写路径（删黑名单键 = 撤销封禁、清限流计数 = 解除封顶）。口令两种携带形态任一：URL
 * userinfo 段，或 REDIS_PASSWORD（生产经 REDIS_PASSWORD_FILE 注入，建连点见
 * sharedCache.redisConnectionPassword）；受信内网免认证须显式声明 REDIS_AUTH_EXEMPT=true
 * ——豁免必须可见，不许静默。
 *
 * **回环豁免**（与 TLS 闸同一条口径）：指向 127.0.0.1/localhost/::1 时只有本机进程可达，
 * 无认证的暴露面收敛到本机——production-drill 临时栈与单机部署形态靠这条放行。
 *
 * 独立成函数不只是拆复杂度：它判的是「Redis 上的身份」，与 host 侧的「流量去哪」是两个维度。
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

/**
 * Mongo 认证缺口告警（**只告警，不阻断启动**）
 *
 * 上面的「不得 localhost」与 TLS 断言解决的是「连到哪」「链路是否被窃听」，
 * **都不解决「谁都能连上」**：mongod 未开 authorization 且 URI 不带凭据时，任何能到达
 * 27017 的对端都能克隆 admin、插后门、删封禁记录、伪造审计链。Redis 侧早有同类认证闸，
 * Mongo 侧是同一条判据的补齐。
 *
 * 不升级为 fail-closed 的原因：存量部署与开发/预览实例普遍无凭据直连本机 mongod，
 * 做成致命闸等于下一次重启直接停机，而修复动作（建账号、改 mongod.cfg、重启库、同步 URI）
 * 必须与运维同步进行。故每次启动只做 loud warning，让缺口保持可见。
 *
 * 判据只认 userinfo 里同时有用户名与口令（`u:p@`）：只写用户名（`u@`）时驱动当无口令处理，
 * 对未开 auth 的实例照样连得上。
 *
 * @returns {string[]} 告警文案数组（空数组 = 无缺口）
 */
const collectMongoAuthWarnings = () => {
  const mongoUri = (process.env.MONGODB_URI || '').trim();
  if (!mongoUri) return [];
  const hasCredentials = /^mongodb(\+srv)?:\/\/[^/@:]+:[^/@]*@/i.test(mongoUri);
  if (hasCredentials) return [];
  // 显式豁免：受信内网里确实跑免认证 mongod 的部署，用命名旗标把噪声关掉。
  // 与 REDIS_AUTH_EXEMPT 同一形态——豁免必须"说出来"，而不是靠没配凭据蒙混。
  if (process.env.MONGODB_AUTH_EXEMPT === 'true') return [];

  return [
    'MONGODB_URI 未携带凭据（应形如 mongodb://<user>:<pass>@<host>/<db>?authSource=...）：' +
      '若 mongod 未开 authorization，任何能到达 27017 的对端都可读写全库——' +
      '克隆管理员、插后门账号、删封禁记录、伪造审计链。TLS 只保护链路，不解决这个问题。' +
      '受信内网的免认证部署请显式设置 MONGODB_AUTH_EXEMPT=true 并在部署文档记录拓扑依据。',
  ];
};

module.exports = {
  collectTransportErrors,
  collectMongoAuthWarnings,
  isLoopbackHostname,
  uriHostname,
};
