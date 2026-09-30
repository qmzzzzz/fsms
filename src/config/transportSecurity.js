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
    h === '::' ||
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
};

module.exports = { collectTransportErrors, isLoopbackHostname, uriHostname };
