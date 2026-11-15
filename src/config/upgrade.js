/** 热升级队列配置（应用端点与宿主机代理共用口径）：应用容器不挂 docker socket，只落一份仅含 digest 的请求文件，docker/nginx 动作由宿主 scripts/hotUpgradeAgent.js 执行并重新校验白名单。空白名单 = 全拒；这里不抛错，只把「未启用/未就绪」如实报给概览端点，避免一次漏配让服务起不来。 */

const path = require('path');

const trimmed = (value) => (typeof value === 'string' ? value.trim() : '');

/**
 * 未配置（undefined/空白）= 配置缺省是正常状态，静默用默认；已配置但越界/非法 = 错配——按仓内「错配必须出声」口径告警后回落（auditFlushBatchLimit / envNumber 的 onInvalid 同型文案），不再静默吞掉。logger 惰性 require：本文件在配置加载期求值，避免与 logger 的依赖图互相拉扯。
 */
const toPositiveInt = (value, fallback, min, max, name) => {
  const n = Number.parseInt(value, 10);
  if (Number.isFinite(n) && n >= min && n <= max) return n;
  if (value !== undefined && String(value).trim() !== '') {
    require('../utils/logger').warn(
      `${name}=${String(value).trim()} 非法（需 ${min}-${max} 的整数），已回退默认 ${fallback}`
    );
  }
  return fallback;
};

const queueDir = trimmed(process.env.UPGRADE_QUEUE_DIR) || '/var/lib/fsms/upgrade';

module.exports = {
  enabled: trimmed(process.env.UPGRADE_ENABLED).toLowerCase() === 'true', // 显式开关：未设置时端点只读概览，不接受升级请求
  queueDir,
  requestsDir: path.join(queueDir, 'requests'),
  statusDir: path.join(queueDir, 'status'),
  heartbeatFile: path.join(queueDir, 'heartbeat.json'),
  registryAllowlist: trimmed(process.env.HOT_UPGRADE_REGISTRY_ALLOWLIST)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  agentStaleMs:
    toPositiveInt(
      process.env.UPGRADE_AGENT_STALE_SECONDS,
      120,
      30,
      3600,
      'UPGRADE_AGENT_STALE_SECONDS'
    ) * 1000, // 代理心跳超过该时长即视为离线（默认 120s，代理按 15s 写一次）
  requestTtlMs:
    toPositiveInt(
      process.env.UPGRADE_REQUEST_TTL_SECONDS,
      1800,
      60,
      86400,
      'UPGRADE_REQUEST_TTL_SECONDS'
    ) * 1000, // 请求在队列里停留超过该时长后代理拒绝执行（默认 30 分钟）
  historyLimit: toPositiveInt(
    process.env.UPGRADE_HISTORY_LIMIT,
    10,
    1,
    50,
    'UPGRADE_HISTORY_LIMIT'
  ),
};
