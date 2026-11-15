/** CORS 来源白名单单一配置源（审计 2026-11-15）：解析+开发兜底原先在 app.js 与 websocketService 各抄一份会漂移；兜底单源到 utils/constants.DEV_CORS_ORIGINS */

const { DEV_CORS_ORIGINS } = require('../utils/constants');

/** 解析 CORS_ORIGIN 逗号分隔列表：trim + 剔除空项（`", "` 这类全空值得到 []） */
const parseCorsOriginList = (raw) =>
  String(raw || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

/** 未配置 CORS_ORIGIN 时的本地开发兜底清单（与 originCheck 的 DEV_CORS_ORIGINS 单源） */
const devCorsFallback = () => [...DEV_CORS_ORIGINS];

/**
 * 来源归一化（审计 2026-11-15）：浏览器发出的 Origin 恒为小写 host 且省略默认端口
 * （https:443 / http:80），按 WHATWG URL 解析后取 .origin 恰好完成归一（非默认端口保留）。
 * 带路径/查询/userinfo 的形态原样返回——归一化不得把路径级配置放大成裸 host 全域放行
 * （该形态由 deploymentCredentialGuards 在启动期告警）。
 */
const normalizeCorsOrigin = (origin) => {
  const raw = String(origin || '');
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (_) {
    return raw;
  }
  if (
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash
  ) {
    return raw;
  }
  return parsed.origin;
};

module.exports = {
  parseCorsOriginList,
  devCorsFallback,
  normalizeCorsOrigin,
  DEV_CORS_ORIGINS,
};
