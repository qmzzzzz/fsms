/**
 * 登录口令加密 strict 模式的启动期告警（2026-10-10）
 *
 * 单独成模块的两个理由（与 config/legacyCbcGuard.js 同惯例）：
 *   ① config/validate.js 的行数已贴着 max-lines 棘轮上限——该文件自己的注释
 *      就写着「新增校验须放在独立函数内」；
 *   ② 这条判据有一处**反直觉的取舍**（下详），值得有名字与独立文档，而不是
 *      夹在四条并行告警里。
 *
 * 【为什么是「告警 + 计数」而不是「拒绝启动」】
 * LOGIN_ENCRYPT_STRICT=true 关死明文口令轨，前提是浏览器有 WebCrypto
 * （secure context：HTTPS 或 localhost）。项目显式支持「纯 HTTP 内网」部署
 * 形态——那种形态下前端拿不到 crypto.subtle，只能走明文降级轨，strict 会把
 * 全体用户锁在门外。而「这个部署的浏览器是否处于 secure context」只有声明式
 * 判据（collectTlsErrors 同款：ENABLE_HTTPS 或 TRUST_PROXY_HOPS+ALLOWED_HOSTS，
 * 应用无从验证前置反代是否真的终结了 TLS）。判据不牢靠就不能做致命闸，
 * 否则一种合法部署形态会被另一条合法配置组合拦死。
 * 正确的收口是「可见」：loud warning + 安全告警计数（incSecurityAlert），
 * 让「生产长期跑在明文轨上」在告警面可见，而不是只活在启动日志里被淹没。
 *
 * 【计数为什么值得】明文口令进请求体的面（反代日志误记、抓包留档、TLS 配置
 * 疏漏）正是 ADR-001 引入密文轨要收的口子。strict 不开 = 那个口子一直开着。
 * 生产 HTTPS 部署没有任何理由不开——前端已全量支持密文轨（含降级上报），
 * 不存在切换成本。真正需要豁免的只有 HTTP 内网形态，其告警文案已点明。
 */

const STRICT_FLAG_NAME = 'LOGIN_ENCRYPT_STRICT';

/** strict 是否开启（与 src/config/index.js 的 loginEncryptStrict 同口径：仅 'true'） */
const isLoginEncryptStrictEnabled = () => process.env[STRICT_FLAG_NAME] === 'true';

/** 告警文案（拆出来便于测试逐字断言） */
const strictDisabledWarningMessage = () =>
  `${STRICT_FLAG_NAME} 未开启：生产环境允许明文口令字段上行（密文轨虽在前端全量就绪，` +
  '服务端仍会接受未加密的 password 字段——反代日志误记/抓包留档/TLS 配置疏漏的口子）。' +
  '若生产经 HTTPS 访问（浏览器有 WebCrypto），应设为 true 关闭明文轨；' +
  '仅纯 HTTP 内网部署（无 secure context，前端只能明文降级）可保持关闭，此告警属预期。';

/**
 * strict 未开时计入安全告警（指标端在建配置阶段可能尚未就绪，且 validate 是
 * 导出 API：吞掉异常，口径同 utils/auditWriteFailure 的「指标端不可用时仅保留
 * 日志」）。**不影响启动行为**——见文件头的取舍说明。
 *
 * @returns {boolean} strict 是否处于关闭状态（供调用方决定要不要推文案）
 */
const reportStrictDisabledIfSo = () => {
  if (isLoginEncryptStrictEnabled()) return false;
  try {
    require('../utils/metrics').incSecurityAlert('login_encrypt_strict_disabled', 'medium');
  } catch (_) {
    /* 指标端不可用：调用方推的 warning 文案仍是唯一留痕 */
  }
  return true;
};

/**
 * strict 告警的出口（供 validate.js 的 collectProductionWarnings 调用）。
 *
 * @returns {string[]} 告警消息列表（strict 开启时为空数组）
 */
const loginEncryptWarnings = () => {
  if (!reportStrictDisabledIfSo()) return [];
  return [strictDisabledWarningMessage()];
};

module.exports = {
  isLoginEncryptStrictEnabled,
  strictDisabledWarningMessage,
  loginEncryptWarnings,
  STRICT_FLAG_NAME,
};
