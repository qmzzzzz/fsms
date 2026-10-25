/**
 * 部署凭据与出站来源的启动闸（2026-10-24 审计）
 *
 * 三类判据原本各自缺失，且都不在「四个核心密钥」的强度闸覆盖范围内：
 *   - CORS_ORIGIN 只做了「非空 + 不含 *」的存在性检查，不解析 URL、不要求 https；
 *     生产把 http:// 来源与 credentials:true 配在一起，等于允许明文来源携带凭据；
 *   - REDIS_PASSWORD / METRICS_TOKEN / SECURITY_ALERT_WEBHOOK_SECRET /
 *     LOG_SHIPPING_TOKEN 只在「有没有」这一维上校验，一个字符的口令与
 *     openssl rand -hex 32 在启动期不可区分；
 *   - SECURITY_ALERT_WEBHOOK 配了但没配签名密钥时，告警投递照常进行但不带签名，
 *     接收方无法区分伪造/重放。
 *
 * 判据只在生产语义下执行（调用方 validateConfig 已提前返回非生产环境），
 * 所以这里可以要求 https、可以拒绝 http://localhost —— 开发环境的本地来源
 * 不会走到本模块。
 *
 * 独立成文件：validate.js 的体积/复杂度棘轮贴着上限，新增判据按仓库既有惯例
 * 拆到按职责命名的模块（transportSecurity.js / trustedProxies.js 同型）。
 */

// 惰性取 isWeakSecret：validate.js 顶部 require 本模块，此处若顶层反向 require
// 会在加载期成环。调用发生在 validateConfig 内，届时 validate 已完整导出。
let weakSecretChecker;
const isWeak = (value) => {
  if (!weakSecretChecker) weakSecretChecker = require('./validate').isWeakSecret;
  return weakSecretChecker(value);
};

const splitList = (raw) =>
  String(raw || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

/**
 * CORS_ORIGIN 的逐项解析判据。
 *
 * 为什么不能只查 `*`：CORS 的 origin 是**完整来源**（scheme://host[:port]），
 * 浏览器永远不会把带路径/查询的串当 Origin 发出来。写进配置的路径部分不会
 * 匹配任何真实请求，却会让人误以为"这个路径已放行"；带 userinfo 的写法更会
 * 让来源比较失效。显式拒绝这些形态，比让它们静默不生效更容易排查。
 *
 * 生产要求 https：`credentials: true` 下，http 来源与 Secure Cookie 的组合
 * 行为随浏览器而异，且明文来源本身就能被网络攻击者注入。纯 HTTP 内网部署
 * 不是 CORS 的合法理由——那种部署应当把前端与 API 放在同一来源下。
 */
function collectCorsOriginErrors(errors) {
  const raw = (process.env.CORS_ORIGIN || '').trim();
  if (!raw) {
    errors.push('CORS_ORIGIN 必须设置（禁止通配符）');
    return;
  }
  const origins = splitList(raw);
  if (origins.length === 0) {
    errors.push('CORS_ORIGIN 必须设置（禁止通配符）');
    return;
  }

  for (const origin of origins) {
    if (origin === '*') {
      errors.push('CORS_ORIGIN 禁止使用通配符');
      continue;
    }
    let parsed;
    try {
      parsed = new URL(origin);
    } catch (_) {
      errors.push(
        `CORS_ORIGIN 含非法来源「${origin}」：必须是完整来源（scheme://host[:port]），` +
          '不得带路径、查询、fragment 或 userinfo'
      );
      continue;
    }
    if (!['https:', 'http:'].includes(parsed.protocol)) {
      errors.push(`CORS_ORIGIN 含非法协议「${parsed.protocol}」：只接受 https://（生产）`);
      continue;
    }
    if (
      parsed.username ||
      parsed.password ||
      parsed.pathname !== '/' ||
      parsed.search ||
      parsed.hash
    ) {
      errors.push(
        `CORS_ORIGIN 含非法来源「${origin}」：必须是完整来源（scheme://host[:port]），` +
          '不得带路径、查询、fragment 或 userinfo'
      );
      continue;
    }
    if (parsed.protocol === 'http:') {
      errors.push(
        `CORS_ORIGIN 含明文来源「${origin}」：生产环境必须使用 https（credentials:true 下` +
          ' http 来源可被网络攻击者注入）。仅开发环境允许 http://localhost'
      );
    }
  }
}

/** 取 REDIS_URL 里内嵌的口令（userinfo 段，已 percent-decode）；无凭据返回 '' */
function redisUrlPassword() {
  const raw = (process.env.REDIS_URL || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (!parsed.password) return '';
    try {
      return decodeURIComponent(parsed.password);
    } catch (_) {
      return parsed.password;
    }
  } catch (_) {
    return '';
  }
}

const STRENGTH_ERRORS = [
  ['REDIS_PASSWORD', 'Redis 认证口令', '缓存/限流计数/IP 黑名单广播都由它保护'],
  ['METRICS_TOKEN', 'METRICS_TOKEN', '/metrics 暴露服务负载与安全告警计数'],
  ['LOG_SHIPPING_TOKEN', 'LOG_SHIPPING_TOKEN', '该令牌以 Bearer 头发往外部日志端'],
  ['SECURITY_ALERT_WEBHOOK_SECRET', 'SECURITY_ALERT_WEBHOOK_SECRET', '它决定告警签名能否被伪造'],
];

/**
 * 运维凭据的强度判据：设置了就必须强，未设置不在本函数发言
 *（是否必填由各自的功能闸决定：Redis 认证闸、webhook 配置闸等）。
 */
function collectCredentialStrengthErrors(errors) {
  const checked = STRENGTH_ERRORS.map(([envKey, label, impact]) => ({
    label,
    impact,
    value: process.env[envKey],
  }));
  checked.push({
    label: 'REDIS_URL 中内嵌的口令',
    impact: '缓存/限流计数/IP 黑名单广播都由它保护',
    value: redisUrlPassword(),
  });

  for (const { label, impact, value } of checked) {
    if (!value) continue;
    if (isWeak(value)) {
      errors.push(
        `${label} 必须是至少 32 字符的强随机值（可用 openssl rand -hex 32 生成）：` +
          `当前值强度不足，而${impact}`
      );
    }
  }
}

/**
 * 安全告警 webhook 的启动闸。
 *
 * 只判「配置完整性」，不判可达性：URL 是否真的能连、证书是否有效属于运行期
 * 事实，启动期判不了。这里能钉住的是两件配置错误：
 *   1. 明文 http —— 告警载荷含安全事件细节，签名头也会一起明文外发；
 *   2. 配了 URL 却没配签名密钥 —— sendNotification 仍会投递，但不带任何
 *      可验证来源的头，接收方只能"来者不拒"。
 */
function collectAlertWebhookErrors(errors) {
  const raw = (process.env.SECURITY_ALERT_WEBHOOK || '').trim();
  if (!raw) return;

  let parsed;
  try {
    parsed = new URL(raw);
  } catch (_) {
    errors.push('SECURITY_ALERT_WEBHOOK 必须是有效的 URL');
    return;
  }
  if (parsed.protocol !== 'https:') {
    errors.push(
      'SECURITY_ALERT_WEBHOOK 必须使用 https：告警载荷含安全事件细节，' +
        '签名头（时间戳/随机数/HMAC）也会随请求明文外发'
    );
  }
  if (!(process.env.SECURITY_ALERT_WEBHOOK_SECRET || '').trim()) {
    errors.push(
      '配置 SECURITY_ALERT_WEBHOOK 时必须同时设置 SECURITY_ALERT_WEBHOOK_SECRET：' +
        '无签名时接收方无法区分伪造/重放的告警投递'
    );
  }
}

/**
 * 日志外发链路的明文判据（生产语义）。
 *
 * 运行期 transport（utils/logShipper.js）只认 `LOG_SHIPPING_ALLOW_INSECURE=true`
 * 这一个显式放宽；启动期更严一档：带 Bearer 令牌时**连放宽也不允许**——令牌是
 * 直接凭据，不能靠一个"我知道有风险"的旗标就让它在网络上明文出现。
 */
function collectLogShippingErrors(errors) {
  const raw = (process.env.LOG_SHIPPING_URL || '').trim();
  if (!raw) return;

  let parsed;
  try {
    parsed = new URL(raw);
  } catch (_) {
    errors.push('LOG_SHIPPING_URL 必须是有效的 URL');
    return;
  }
  if (parsed.protocol === 'https:') return;

  if (parsed.protocol !== 'http:') {
    errors.push(`LOG_SHIPPING_URL 只接受 http/https，收到 ${parsed.protocol}`);
    return;
  }
  if ((process.env.LOG_SHIPPING_TOKEN || '').trim()) {
    errors.push(
      'LOG_SHIPPING_URL 为明文 http 时禁止配置 LOG_SHIPPING_TOKEN：Bearer 令牌会随日志明文出站，' +
        '请改用 https://（该组合不受 LOG_SHIPPING_ALLOW_INSECURE 放宽）'
    );
    return;
  }
  if (process.env.LOG_SHIPPING_ALLOW_INSECURE !== 'true') {
    errors.push(
      'LOG_SHIPPING_URL 必须是 https://（日志内容不得明文出站）；确需明文端点时显式设置 LOG_SHIPPING_ALLOW_INSECURE=true'
    );
  }
}

/** 运维凭据/webhook/日志外发三组判据的合并入口（validate.js 的行数棘轮决定） */
function collectRuntimeCredentialGuards(errors) {
  collectCredentialStrengthErrors(errors);
  collectAlertWebhookErrors(errors);
  collectLogShippingErrors(errors);
}

/**
 * REQUIRE_PRODUCTION_CONFIG 的失配文案（无失配返回 null）。
 *
 * 该变量是部署方的显式声明："这套配置必须按生产语义校验"。若当前 NODE_ENV
 * 归一后落在开发/预发家族，整套硬闸会静默跳过——声明与事实不符，必须拒绝启动。
 */
function productionSemanticsMismatch() {
  if (process.env.REQUIRE_PRODUCTION_CONFIG !== 'true') return null;
  const raw = process.env.NODE_ENV;
  return (
    'REQUIRE_PRODUCTION_CONFIG=true 但当前环境不会进入生产校验' +
    `（NODE_ENV=${raw === undefined ? '未设置' : JSON.stringify(raw)}）：` +
    '弱密钥 / ALLOWED_HOSTS / REDIS_URL / TLS 等硬闸会被整体跳过。' +
    '请把 NODE_ENV 设为 production（或 prod）；确属开发/预发请移除该变量'
  );
}

module.exports = {
  collectCorsOriginErrors,
  collectRuntimeCredentialGuards,
  productionSemanticsMismatch,
  collectCredentialStrengthErrors,
  collectAlertWebhookErrors,
  collectLogShippingErrors,
};
