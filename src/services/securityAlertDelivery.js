/**
 * 安全告警投递服务：负责结构化日志、指标、SSRF 校验与 Webhook 重试。
 * 检测服务只决定是否产生告警，不关心出站投递细节。
 */

const logger = require('../utils/logger');
const { incSecurityAlert } = require('../utils/metrics');

const MAX_ACTIVE_DELIVERIES = Math.max(1, Number(process.env.SECURITY_ALERT_MAX_CONCURRENT) || 5);
let activeDeliveries = 0;

if (
  process.env.NODE_ENV === 'production' &&
  process.env.SECURITY_ALERT_WEBHOOK &&
  !process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST
) {
  logger.warn(
    'SECURITY_ALERT_WEBHOOK 已配置但未设置 SECURITY_ALERT_WEBHOOK_ALLOWLIST：' +
      '若目标为域名，其内网指向无防护；若为明文 http，告警载荷将明文外发。' +
      '生产环境建议 https + 白名单'
  );
}

const isWebhookTargetAllowed = (webhookUrl) => {
  let target;
  try {
    target = new URL(webhookUrl);
  } catch (_) {
    logger.warn('安全告警 webhook URL 无法解析，跳过投递');
    return false;
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    logger.warn('安全告警 webhook 仅允许 http/https，跳过投递');
    return false;
  }

  const targetHost = target.hostname.toLowerCase();
  if (
    targetHost === 'localhost' ||
    targetHost.endsWith('.localhost') ||
    targetHost.endsWith('.local')
  ) {
    logger.warn('安全告警 webhook 禁止指向本机地址，跳过投递');
    return false;
  }

  const allowlist = (process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST || '')
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
  if (allowlist.length > 0 && !allowlist.includes(targetHost)) {
    logger.warn('安全告警 webhook 主机不在 ALLOWLIST 白名单内，跳过投递');
    return false;
  }

  if (/^[0-9a-f.:]+$/i.test(targetHost)) {
    const ipaddr = require('ipaddr.js');
    let parsedIp;
    try {
      parsedIp = ipaddr.parse(targetHost);
    } catch (_) {
      parsedIp = null;
    }
    const forbiddenRanges = [
      'loopback',
      'private',
      'linkLocal',
      'uniqueLocal',
      'reserved',
      'unspecified',
      'carrierGradeNat',
    ];
    if (parsedIp && forbiddenRanges.includes(parsedIp.range())) {
      logger.warn(`安全告警 webhook 禁止指向 ${parsedIp.range()} 地址，跳过投递`);
      return false;
    }
  }
  return true;
};

const buildWebhookBody = ({ alertType, level, message, payload }) =>
  JSON.stringify({
    msgtype: 'text',
    text: {
      content: `【安全告警·${level}】${message}\n类型：${alertType}\n时间：${payload.timestamp}`,
    },
    alert: payload,
  });

const signedHeaders = (body) => {
  const headers = {};
  const secret = process.env.SECURITY_ALERT_WEBHOOK_SECRET;
  if (!secret) return headers;
  const crypto = require('crypto');
  headers['X-Webhook-Signature'] =
    `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;
  return headers;
};

const sendNotification = async (alertType, level, message, data) => {
  const logMethod = level === 'critical' ? 'error' : level === 'high' ? 'warn' : 'info';
  const payload = {
    type: alertType,
    level,
    message,
    timestamp: new Date().toISOString(),
    ...data,
  };

  logger[logMethod]('SECURITY_ALERT', payload);
  incSecurityAlert(alertType, level);

  const webhookUrl = process.env.SECURITY_ALERT_WEBHOOK;
  if (!webhookUrl) return;

  const levelOrder = { low: 1, medium: 2, high: 3, critical: 4 };
  const minLevel = process.env.SECURITY_ALERT_MIN_LEVEL || 'high';
  if ((levelOrder[level] || 0) < (levelOrder[minLevel] || 3)) return;
  if (!isWebhookTargetAllowed(webhookUrl)) return;

  const body = buildWebhookBody({ alertType, level, message, payload });
  const headers = signedHeaders(body);
  const { postJson } = require('../utils/httpPostJson');
  const maxAttempts = 2;

  if (activeDeliveries >= MAX_ACTIVE_DELIVERIES) {
    logger.warn(`安全告警投递并发已达上限 ${MAX_ACTIVE_DELIVERIES}，本条跳过投递（已落库与计数）`);
    return;
  }
  activeDeliveries += 1;
  try {
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const response = await postJson(webhookUrl, headers, body, 5000);
        if (response.ok) return;
        logger.warn(`安全告警投递失败：HTTP ${response.status}（第 ${attempt}/${maxAttempts} 次）`);
      } catch (error) {
        logger.warn(`安全告警投递异常（第 ${attempt}/${maxAttempts} 次）：${error.message}`);
      }
      if (attempt < maxAttempts) await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  } finally {
    activeDeliveries -= 1;
  }
};

module.exports = { sendNotification };
