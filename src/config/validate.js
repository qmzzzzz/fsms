// 弱密钥黑名单：生产环境禁止使用这些默认值
const WEAK_SECRETS = [
  'default-secret-change-in-production',
  'default-aes-key-change-in-production',
  'default-hmac-secret',
  'your-super-secret-jwt-key-change-in-production',
  'your-refresh-token-secret',
  'change-this-secret',
  '',
];

function isWeakSecret(value) {
  if (!value) return true;
  if (WEAK_SECRETS.includes(value)) return true;
  // 长度不足视为弱密钥
  if (value.length < 32) return true;
  return false;
}

/**
 * 生产环境「加固项缺失」告警（G6）
 *
 * 与 errors 的区别：这些项缺失不会让服务不可用，但会削弱纵深防御，
 * 因此只告警不退出——若升级为致命错误，所有依赖前置反代做 Host 校验的
 * 既有部署都会在升级后直接起不来。
 * @returns {string[]} 告警消息列表（便于测试断言）
 */
function collectProductionWarnings() {
  const warnings = [];

  if (!process.env.ALLOWED_HOSTS || !process.env.ALLOWED_HOSTS.trim()) {
    warnings.push(
      'ALLOWED_HOSTS 未配置：protocolCompliance 的 Host 头白名单校验处于关闭状态，' +
        '若服务直接暴露（无反向代理固定 Host），存在 Host 头注入风险。' +
        '建议设置为对外域名列表，如 ALLOWED_HOSTS=api.example.com,api.example.com:443'
    );
  }

  // M-2 的 TLS 告警已并入 validateConfig 的致命校验（M3，2026-09-11 放宽为
  // 「进程自启 HTTPS 或声明由前置反代终结」二选一），此处不再重复告警——
  // 保留会让 README / .env.example / docker-compose 的标准拓扑（TLS 由前置
  // Nginx 终结、应用明文 HTTP 反代）每次启动都刷一条与本意相悖的告警。

  return warnings;
}

/**
 * M-01：开启 API 文档时必须配置 Basic Auth 凭据。
 *
 * swagger.basicAuth 已改为 fail-closed（无凭据则 503），故缺凭据不会造成
 * 匿名可读；但那是运行期兜底，配置错误应当在启动期就被拦下——否则文档
 * 实际不可用却无人知晓，属"静默失效"。口令下限 16 字符与其余密钥口径一致。
 *
 * 抽为独立函数：validateConfig 已接近 max-lines-per-function 上限
 *（见 eslint.ratchet.json），新增校验须放在独立函数内。
 */
function validateDocsCredentials(errors) {
  if ((process.env.ENABLE_API_DOCS || '').trim().toLowerCase() !== 'true') return;

  const docsUser = (process.env.DOCS_USERNAME || '').trim();
  const docsPass = process.env.DOCS_PASSWORD || '';
  if (!docsUser || !docsPass) {
    errors.push(
      'ENABLE_API_DOCS=true 时必须同时配置 DOCS_USERNAME 与 DOCS_PASSWORD：' +
        '否则 API 文档将按 fail-closed 拒绝访问（配置错误应在启动期暴露，而非运行期静默失效）'
    );
  } else if (docsPass.length < 16) {
    errors.push('DOCS_PASSWORD 至少 16 字符（API 文档暴露全部接口契约与权限编码，需强口令）');
  }
}

// 生产环境配置校验（与 config/index.js 的 validateProductionConfig 保持一致）
function validateConfig() {
  const nodeEnv = process.env.NODE_ENV || 'development';

  if (nodeEnv !== 'production') return;

  const errors = [];

  if (isWeakSecret(process.env.JWT_SECRET)) {
    errors.push('JWT_SECRET 必须设置为至少 32 字符的强随机值，不能使用默认弱密钥');
  }

  if (isWeakSecret(process.env.JWT_REFRESH_SECRET)) {
    errors.push('JWT_REFRESH_SECRET 必须设置为至少 32 字符的强随机值');
  }

  if (isWeakSecret(process.env.AES_SECRET_KEY)) {
    errors.push('AES_SECRET_KEY 必须设置为至少 32 字符的强随机值');
  }

  if (isWeakSecret(process.env.HMAC_SECRET)) {
    errors.push('HMAC_SECRET 必须设置为至少 32 字符的强随机值');
  }

  if (!process.env.MONGODB_URI || process.env.MONGODB_URI.includes('localhost')) {
    errors.push('MONGODB_URI 不能指向 localhost');
  }

  if (!process.env.CORS_ORIGIN) {
    errors.push('CORS_ORIGIN 必须设置（禁止通配符）');
  }
  if ((process.env.CORS_ORIGIN || '').split(',').includes('*')) {
    errors.push('CORS_ORIGIN 禁止使用通配符');
  }

  const redisUrl = (process.env.REDIS_URL || '').trim();
  if (!redisUrl) {
    errors.push('REDIS_URL 必须配置：生产环境限流、IP 黑名单广播与审计链锁不得退化为单实例内存态');
  } else {
    try {
      const parsedRedisUrl = new URL(redisUrl);
      if (!['redis:', 'rediss:'].includes(parsedRedisUrl.protocol)) {
        errors.push('REDIS_URL 协议必须是 redis: 或 rediss:');
      }
    } catch (_) {
      errors.push('REDIS_URL 必须是有效的 Redis 连接地址');
    }
  }

  // M3：生产环境必须配置 ALLOWED_HOSTS（Host 头白名单校验）
  if (!process.env.ALLOWED_HOSTS || !process.env.ALLOWED_HOSTS.trim()) {
    errors.push(
      'ALLOWED_HOSTS 必须配置：生产环境缺少 Host 头白名单，存在缓存投毒与密码重置链接投毒风险'
    );
  }

  // M-01：API 文档凭据校验（抽为独立函数，避免 validateConfig 体积超标——
  // 见 eslint.ratchet.json 的 max-lines-per-function 约束）
  validateDocsCredentials(errors);

  // M3：TLS 终结校验（2026-09-11 放宽版）后置于 TRUST_PROXY_HOPS 校验之后——
  // 判定需要 MAX_TRUST_PROXY_HOPS 与合法的 hops 值。

  // TRUST_PROXY_HOPS 必须是合法跳数，不能只验存在性（AUX-01 / P2-24）
  //
  // 只验 `!process.env.TRUST_PROXY_HOPS` 时，`TRUST_PROXY_HOPS=abc` 能通过校验，
  // 运行时 parseInt → NaN → app.js 落入 `trust proxy = false`，且无任何告警。
  // 后果分两个方向，都很严重：
  //   1. 反代场景下 req.ip 恒为代理 IP：全站共享一个限流桶（一人试错锁死所有人
  //      的登录额度）、自动封禁误封反代 IP 导致全站 403、审计 IP 全部失真；
  //   2. 反向配置过大（如 99）时，Express 会信任 XFF 链中更靠前的元素，
  //      客户端伪造 X-Forwarded-For 即可无限轮换 IP，击穿 IP 级限流/黑名单。
  // 因此取值必须是 1..MAX_TRUST_PROXY_HOPS 的整数（1=单层 Nginx，最常见）。
  const MAX_TRUST_PROXY_HOPS = 5;
  const rawHops = process.env.TRUST_PROXY_HOPS;
  if (!rawHops || !String(rawHops).trim()) {
    errors.push('TRUST_PROXY_HOPS 必须设置（反向代理层数，用于正确获取客户端真实 IP）');
  } else if (!/^\d+$/.test(String(rawHops).trim())) {
    errors.push(
      `TRUST_PROXY_HOPS 必须是正整数（当前值：${rawHops}），非法值会静默退化为「不信任代理」`
    );
  } else {
    const hops = parseInt(rawHops, 10);
    if (hops < 1 || hops > MAX_TRUST_PROXY_HOPS) {
      errors.push(
        `TRUST_PROXY_HOPS 必须在 1..${MAX_TRUST_PROXY_HOPS} 之间（当前值：${hops}）。` +
          '过小会让 req.ip 恒为代理 IP，过大会允许客户端伪造 X-Forwarded-For 轮换 IP 绕过限流'
      );
    }
  }

  // M3（2026-09-11 放宽）：TLS 必须在某一层终结，但「哪一层」由部署形态决定。
  //
  // 原实现只认 ENABLE_HTTPS=true，与 README / .env.example / docker-compose 的目标
  // 形态直接冲突——那里明确写着「TLS 由前置 Nginx 终结，应用进程本身不建议暴露 443」，
  // 且该形态下 ENABLE_HTTPS 必须保持关闭：置 true 会让进程转而加载 ./certs 证书
  // 自起 HTTPS（见 src/index.js 的 HTTPS 分支），证书缺失时直接拒绝启动。
  // 结果是：文档推荐的生产拓扑无法通过生产校验（演练与 CI e2e 一并变红）。
  //
  // 放宽后的判定：以下二者之一成立即可，二者皆无才判致命——
  //   a) 进程自启 HTTPS：ENABLE_HTTPS === 'true'（需自备证书）；
  //   b) 声明由前置反代终结：TRUST_PROXY_HOPS 为 1..MAX_TRUST_PROXY_HOPS 的整数
  //      且 ALLOWED_HOSTS 已配置（反代场景的基本前提，两者本身也已是生产必填）。
  // 注意：这是「声明式」判定，应用无从验证反代是否真的终结了 TLS。若日后要收紧为
  // 显式声明，可引入专用开关（如 TLS_TERMINATED_UPSTREAM=true）并在部署清单固化。
  const tlsInProcess = process.env.ENABLE_HTTPS === 'true';
  const hopsForTls = parseInt(String(process.env.TRUST_PROXY_HOPS || '').trim(), 10);
  const tlsTerminatedUpstream =
    Number.isInteger(hopsForTls) &&
    hopsForTls >= 1 &&
    hopsForTls <= MAX_TRUST_PROXY_HOPS &&
    !!(process.env.ALLOWED_HOSTS || '').trim();
  if (!tlsInProcess && !tlsTerminatedUpstream) {
    errors.push(
      'TLS 未在任一层终结：需 ENABLE_HTTPS=true（进程自启 HTTPS，需自备证书），' +
        '或声明由前置反代终结（TRUST_PROXY_HOPS 取 1..5 且配置 ALLOWED_HOSTS）。' +
        '二者皆无时，登录口令的 ECDH 加密无法抵御主动 MITM'
    );
  }

  if (errors.length > 0) {
    // L-05 修复：启动致命校验改用统一 logger（不再使用 console.error），
    // 保证致命配置错误同样进入结构化日志与日志收集链路。
    // 惰性引入避免 config → validate → logger → config 的加载期循环依赖。
    try {
      const logger = require('../utils/logger');
      logger.error('配置校验失败：');
      errors.forEach((err) => logger.error(`  - ${err}`));
    } catch (e) {
      // 极端情况下 logger 不可用，降级到 stderr，确保信息不丢失
      console.error('配置校验失败：');
      errors.forEach((err) => console.error('  -', err));
    }
    process.exit(1);
  }

  // G6：致命项全部通过后，再输出加固项缺失告警（不阻断启动）
  const warnings = collectProductionWarnings();
  if (warnings.length > 0) {
    try {
      const logger = require('../utils/logger');
      warnings.forEach((w) => logger.warn(`安全加固建议：${w}`));
    } catch (e) {
      warnings.forEach((w) => console.warn('安全加固建议：', w));
    }
  }
}

module.exports = { validateConfig, isWeakSecret, collectProductionWarnings };

// 支持直接执行：node src/config/validate.js
if (require.main === module) {
  validateConfig();
}
