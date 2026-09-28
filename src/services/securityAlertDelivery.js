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
  logger.error(
    'SECURITY_ALERT_WEBHOOK 已配置但未设置 SECURITY_ALERT_WEBHOOK_ALLOWLIST：' +
      '此时**不会** fail-closed——字面量内网地址（loopback/私网/linkLocal/ULA/CGNAT/保留段）' +
      '仍被网域检查拦下，但**域名型目标不做解析**，其内网指向无防护' +
      '（DNS 重绑定 / 内网域名可绕过本层）；若目标为明文 http，告警载荷还将明文外发。' +
      '生产环境请设置 SECURITY_ALERT_WEBHOOK_ALLOWLIST 显式声明 webhook 主机（并优先 https）'
  );
}

/**
 * 出站网域判定采用**白名单**：ipaddr.js 只有把字面量归为全局单播（'unicast'）才放行。
 *
 * 原先写的是禁止网段黑名单（loopback/private/linkLocal/uniqueLocal/reserved/
 * unspecified/carrierGradeNat）。黑名单的失败方向是错的：**没列到的名字一律当公网**。
 * 实测（ipaddr.js 2.5.0）至少漏掉这几类，而它们都能指向内网：
 *   - rfc6052  64:ff9b::/96 —— NAT64 Well-Known Prefix，目的 IPv4 直接嵌在地址里：
 *     http://[64:ff9b::7f00:1]/ 在有 NAT64 的主机上等价于 127.0.0.1，
 *     http://[64:ff9b::a9fe:a9fe]/ 等价于 169.254.169.254（云元数据）。
 *   - teredo   2001::/32 —— 同样把 IPv4 嵌进地址。
 *   - broadcast 255.255.255.255 / multicast 224/4 / as112 / 文档与基准测试段
 *     （reserved）—— 不可能是合法 webhook 目标。
 * 白名单把这些连同未来新增的特殊网段一并归入拒绝；失败代价是"少投一条告警"
 * （日志、指标与落库都在投递之前），而不是"帮攻击者打穿内网"。
 */
const ALLOWED_WEBHOOK_IP_RANGE = 'unicast';

// 判断一个主机名（可能是 IP 字面量）是否**不属于**允许投递的地址范围。
// 返回 true=禁止；false=全局单播公网地址。非 IP 字面量（域名）返回 false，
// 由上层 ALLOWLIST 白名单与网络层约束——域名的内网指向无法在解析前判定，
// 这一残余风险已由文件头的启动告警明示。
// 绕过点（SSRF 内网探测）：
//  1) IPv6 字面量在 URL 里带方括号（new URL('http://[::1]/').hostname === '[::1]'）——
//     方括号不在 `[0-9a-f.:]` 字符集里，若不剥离，[::1]（loopback）、[fd00::1]（ULA）、
//     [fe80::1]（linkLocal）、[::ffff:127.0.0.1] 会整段跳过网域检查并放行。故先剥方括号。
//     注：十进制/十六进制/八进制（含全角数字）IPv4 已被 WHATWG URL 归一化成点分十进制，
//     无同类绕过——已实测核对。
//  2) IPv4 映射地址 ::ffff:x 的 range() 一律是 'ipv4Mapped'（实测 ipaddr.js 2.5.0），
//     在白名单下**必然**落进拒绝分支——所以必须先 toIPv4Address() 展开再判：
//     ::ffff:127.0.0.1 → loopback（拒绝，与裸写 127.0.0.1 同口径），
//     ::ffff:8.8.8.8   → unicast（放行，否则白名单会误伤合法公网目标）。
const isForbiddenIpLiteral = (targetHost) => {
  const ipLiteral = targetHost.replace(/^\[/, '').replace(/\]$/, '');
  if (!/^[0-9a-f.:]+$/i.test(ipLiteral)) return false;

  const ipaddr = require('ipaddr.js');
  let parsedIp;
  try {
    parsedIp = ipaddr.parse(ipLiteral);
  } catch (_) {
    return false;
  }
  if (
    parsedIp.kind() === 'ipv6' &&
    typeof parsedIp.isIPv4MappedAddress === 'function' &&
    parsedIp.isIPv4MappedAddress()
  ) {
    parsedIp = parsedIp.toIPv4Address();
  }
  if (parsedIp.kind() === 'ipv6') {
    // IPv4 兼容前缀 ::/96（`::10.0.0.1` 经 WHATWG URL 归一后就是 `::a00:1`，
    // 实测 URL 解析器总会把点分改写成十六进制，所以判据看到的是十六进制形态）：
    // ipaddr 给它 range()==='unicast' ⇒ 单看白名单会放行，而它把 IPv4 目的嵌在低 32 位里。
    // 整段按拒绝处理：这是 1990 年代的历史前缀，现代协议栈（Linux/Node）不做 ::/96→IPv4
    // 转换，真实 webhook 目标不可能落在这里；`::`（unspecified）与 `::1`（loopback）
    // 也同属本段，二者本来就该拒。定级为加固而非漏洞——要打穿得依赖 NAT64，
    // 而 `64:ff9b::/96`（rfc6052）已由上面的白名单拒掉。
    const octets = parsedIp.toByteArray();
    if (octets.slice(0, 12).every((byte) => byte === 0)) {
      logger.warn(`安全告警 webhook 禁止 IPv4 兼容前缀 ::/96（${parsedIp.toString()}），跳过投递`);
      return true;
    }
  }
  if (parsedIp.range() !== ALLOWED_WEBHOOK_IP_RANGE) {
    logger.warn(`安全告警 webhook 仅允许全局单播地址，跳过投递（range=${parsedIp.range()}）`);
    return true;
  }
  return false;
};

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

  // IP 字面量的网域判定抽到 isForbiddenIpLiteral（降主函数复杂度，逻辑与日志不变）。
  // 覆盖 IPv6 方括号、::ffff: IPv4 映射等绕过，详见该函数注释。
  if (isForbiddenIpLiteral(targetHost)) {
    return false;
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

  // F-212：`level` 是 winston 的保留字段——`log(level, msg, meta)` 会把 meta 里的 `level`
  // 覆盖成分派级别，实测落盘 `"level":"error"`，"critical" 这个字面串整行消失。
  // 于是 webhook 关掉 / 被 SECURITY_ALERT_MIN_LEVEL 过滤 / 被白名单拒掉这三条 return
  // 之后的路径上，**文件日志是唯一的取证通道**，而它恰好把这条通道最要紧的字段弄丢了：
  // ELK 上 `SECURITY_ALERT AND level:critical` 一类的告警规则永远不会命中，
  // 且 `low` 与 `medium` 都映射到 info（上面 logMethod 的三元的 else 分支），
  // 落盘后字面上不可区分。
  // 只在日志边界另立一个不冲突的键名；`payload` 本体不动 ⇒ 出站 webhook 的
  // `alert.level` 契约与带内消息文本完全不变（改动出站面要同步 OpenAPI/下游解析）。
  logger[logMethod]('SECURITY_ALERT', { ...payload, alertLevel: level });
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

module.exports = { sendNotification, isWebhookTargetAllowed };
