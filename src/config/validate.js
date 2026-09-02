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

  // M-2：TLS 必须在某一层终结。进程未自启 HTTPS（ENABLE_HTTPS=true）时，
  // 只能依赖前置反代——本进程无从验证反代是否真的终结了 TLS，因此以告警
  // 把责任显式交回部署侧。背景：登录口令的 ECDH 加密在纯 HTTP 下挡不住
  // 主动 MITM（攻击者替换公钥即可），它只是纵深，不能替代 TLS。
  if (process.env.ENABLE_HTTPS !== 'true') {
    warnings.push(
      'ENABLE_HTTPS 未启用：本进程将以明文 HTTP 提供服务。生产环境必须由前置 ' +
        'Nginx 终结 TLS（TLSv1.2+、HSTS，配置参考 deployment/nginx.conf.example），' +
        '并确认对外仅开放 443。若服务直接以 HTTP 暴露，登录口令 ECDH 加密' +
        '无法抵御主动 MITM，属阻断级配置错误'
    );
  }

  return warnings;
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
