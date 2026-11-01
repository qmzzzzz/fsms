/**
 * JWT 多密钥轮换的环境一致性闸（P2-3）：形状错误必须在启动期拒绝，不能按"未配置"静默降级——
 * 降级后仍以单密钥签发（不写 kid），运维以为轮换已生效：新钥从没被用上、旧钥永远删不掉。
 *
 * 校验四件事：JSON 形状与强度（每把钥都要强）；密钥集配置时必须点名当前 kid 且 kid 存在，反向
 * （点名了 kid 却没配集合）同样拒绝；access / refresh 侧不得同值（单钥那对已由 collectSecretErrors
 * 报过）；键名一律按 hasOwnProperty 判——原型属性名（toString 等）会骗过真值判据。
 * 独立成文件：validate.js 体积棘轮贴上限（同 deploymentCredentialGuards.js）。
 */
// 惰性取 isWeakSecret：validate.js 顶部 require 本模块，此处顶层反向 require 会在加载期成环（调用发生在 validateConfig 内，届时 validate 已完整导出）。
let weakSecretChecker;
const isWeak = (value) => {
  if (!weakSecretChecker) weakSecretChecker = require('./validate').isWeakSecret;
  return weakSecretChecker(value);
};

function collectJwtRotationErrors(errors) {
  const parseMap = (name) => {
    const raw = (process.env[name] || '').trim();
    if (!raw) return null;
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (_) {
      errors.push(`${name} 必须是 JSON 对象（形如 {"k1":"<secret>"}），当前无法解析`);
      return null;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      errors.push(`${name} 必须是 JSON 对象（形如 {"k1":"<secret>"}）`);
      return null;
    }
    const entries = Object.entries(parsed);
    if (entries.length === 0) {
      errors.push(`${name} 至少需要配置一个 kid → secret 对`);
      return null;
    }
    const valid = entries.filter(
      ([kid, secret]) => typeof kid === 'string' && kid && typeof secret === 'string' && secret
    );
    if (valid.length !== entries.length) {
      errors.push(`${name} 只能包含非空的 kid → secret 字符串对`);
      return null;
    }
    for (const [kid, secret] of valid) {
      if (isWeak(secret)) {
        errors.push(`${name} 中 kid=${kid} 的密钥必须设置为至少 32 字符的强随机值`);
      }
    }
    return Object.fromEntries(valid);
  };

  const accessMap = parseMap('JWT_SECRETS');
  const refreshMap = parseMap('JWT_REFRESH_SECRETS');

  const checkCurrentKid = (mapName, kidEnv, map) => {
    const kid = (process.env[kidEnv] || '').trim();
    if (!map) {
      // 反向：点了 kid 却没配集合 ⇒ 签发侧静默退回单密钥（不写 kid），轮换从未生效
      if (kid)
        errors.push(kidEnv + '="' + kid + '" 已设置但 ' + mapName + ' 未配置（轮换不会生效）');
      return;
    }
    if (!kid) {
      errors.push(`${mapName} 已配置时必须同时设置 ${kidEnv}（指明当前签发使用的 kid）`);
    } else if (!Object.prototype.hasOwnProperty.call(map, kid)) {
      errors.push(`${kidEnv}="${kid}" 不存在于 ${mapName} 中`);
    }
  };
  checkCurrentKid('JWT_SECRETS', 'JWT_CURRENT_KID', accessMap);
  checkCurrentKid('JWT_REFRESH_SECRETS', 'JWT_REFRESH_CURRENT_KID', refreshMap);

  const legacyAccess = (process.env.JWT_SECRET || '').trim();
  const legacyRefresh = (process.env.JWT_REFRESH_SECRET || '').trim();
  // 单钥相同已在 collectSecretErrors 报过，这里不重复报同一件事
  if (legacyAccess && legacyAccess === legacyRefresh) return;
  const accessValues = new Set([legacyAccess, ...Object.values(accessMap || {})].filter(Boolean));
  const refreshValues = new Set(
    [legacyRefresh, ...Object.values(refreshMap || {})].filter(Boolean)
  );
  if ([...accessValues].some((value) => refreshValues.has(value))) {
    errors.push(
      'JWT_SECRETS / JWT_REFRESH_SECRETS 中存在同值密钥（refresh 令牌可被当作 access 令牌直接使用）'
    );
  }
}

module.exports = { collectJwtRotationErrors };
