// PROXY_PROTOCOL 的启动校验与运行接线共用本解析器，避免安全开关出现两套口径（ADR-021）。
// 只认 off/on；缺省关闭，非法值关闭并报错，防止跳过生产闸的开发环境误启用。
// PROXY 头可改写 socket 地址：生产启用必须显式配置 TRUSTED_PROXY_CIDRS。
// 运行期复用 XFF 的对端名单判据；名单非法时拒绝所有 PROXY 头，不回退信任。

const ENV_KEY = 'PROXY' + '_' + 'PROTOCOL';

/**
 * 「PROXY_PROTOCOL=on + ENABLE_HTTPS=true」组合的拒绝文案（ADR-021 决定 ⑥）。
 * 独立成导出常量的原因：index.js 的接线守卫要用同一条文案，而那边的 max-lines
 * 棘轮只数非注释行、已贴着 300 的上限——长文案放这边，接线处只留一行调用。
 * 文案本身的三条探针实证见 utils/proxyProtocol.js 文件头与本文件收集器注释。
 */
const HTTPS_COMBO_UNSUPPORTED_MESSAGE =
  'PROXY_PROTOCOL=on 与 ENABLE_HTTPS=true 不可同时启用（ADR-021 决定⑥）：PROXY 头还原必须先于 TLS 消费首段字节，而 Node 的 TLSSocket 在句柄层读连接、看不到已消费的头字节，TLS 握手会永久悬挂。请改用 LB 终结 TLS（明文 + PROXY 头直达后端），或 LB 透传 TLS 到宿主 nginx 由 listen proxy_protocol 消费（后端保持 PROXY_PROTOCOL=off）';

const trustedProxies = require('./trustedProxies');

// 生产必须报告非法开关、缺失名单及不支持的 TLS 组合，不能静默按关闭或回环兼容态运行。
const collectProxyProtocolGateErrors = (errors) => {
  const parsed = parseProxyProtocolMode(process.env[ENV_KEY]);
  errors.push(...parsed.errors);
  if (!parsed.enabled) return;
  // TLSSocket 从句柄读取，无法消费前置层 unshift 的握手字节；此组合会永久悬挂，必须拒启。
  // 改由 LB 终结 TLS，或由宿主 nginx 消费 PROXY 头并关闭后端开关（ADR-021）。
  if (process.env.ENABLE_HTTPS === 'true') {
    errors.push(
      `${ENV_KEY}=on 与 ENABLE_HTTPS=true 不可同时启用：PROXY 头还原必须在 TLS 握手前消费` +
        '首段字节，而 Node 的 TLSSocket 在句柄层读连接，看不到已被消费的头字节' +
        '（连接会被接受但 TLS 握手永久悬挂）。请改用 LB 终结 TLS（明文 + PROXY 头直达后端），' +
        '或 LB 透传 TLS 到宿主 nginx 由 listen proxy_protocol 消费（后端保持 PROXY_PROTOCOL=off）'
    );
  }
  const trusted = trustedProxies.parseTrustedProxyCidrs(process.env[trustedProxies.ENV_KEY]);
  if (!trusted.configured) {
    errors.push(
      `${ENV_KEY}=on 时必须配置 ${trustedProxies.ENV_KEY}：` +
        'PROXY protocol 头会直接重写 socket 对端地址（真实客户端 IP 的唯一凭据），' +
        '必须显式声明「哪些对端有权发头」。未配名单时运行期只放行回环对端，' +
        '还原功能形同虚设'
    );
  }
};

/**
 * 解析 PROXY_PROTOCOL（纯函数：不读 process.env、不打日志）。
 *
 * @param {string|undefined} raw process.env[ENV_KEY] 的原始值
 * @returns {{configured: boolean, enabled: boolean, errors: string[]}}
 *   configured=false 仅当「完全没配」（undefined / 空串 / 纯空白）；
 *   配了非法值时 configured=true 且 enabled=false（fail-closed），errors 非空，
 *   由 validate.js 在生产启动面逐条上报。
 */
const parseProxyProtocolMode = (raw) => {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return { configured: false, enabled: false, errors: [] };
  }
  const value = String(raw).trim().toLowerCase();
  if (value === 'off') {
    return { configured: true, enabled: false, errors: [] };
  }
  if (value === 'on') {
    return { configured: true, enabled: true, errors: [] };
  }
  return {
    configured: true,
    enabled: false,
    errors: [
      `${ENV_KEY} 取值非法（当前值：${raw}）：仅接受 off 或 on。` +
        'on 表示允许可信对端（TRUSTED_PROXY_CIDRS 名单内）以 PROXY protocol v1/v2 头声明真实客户端地址；' +
        'off 为默认值，监听路径与未引入本功能前逐字节一致',
    ],
  };
};

let cached;

/**
 * 读取并解析环境变量（memoize：进程内配置不变，逐次重解析纯属浪费）。
 * @returns {ReturnType<typeof parseProxyProtocolMode>}
 */
const resolveProxyProtocol = () => {
  if (!cached) {
    cached = parseProxyProtocolMode(process.env[ENV_KEY]);
  }
  return cached;
};

/** 清空 memoize（仅测试使用，与 resetTrustedProxyCache 同型） */
const resetProxyProtocolCache = () => {
  cached = undefined;
};

module.exports = {
  ENV_KEY,
  HTTPS_COMBO_UNSUPPORTED_MESSAGE,
  parseProxyProtocolMode,
  collectProxyProtocolGateErrors,
  resolveProxyProtocol,
  resetProxyProtocolCache,
};
