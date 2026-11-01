/**
 * JWT 密钥集与 kid 解析（P2-3）：多密钥重叠以支持轮换——签发放进 `header.kid`，验签按 kid 选钥；
 * 无 kid 的历史令牌回退**轮换前的单密钥**（JWT_SECRET / JWT_REFRESH_SECRET）；把该项清空即立刻
 * 吊销全部无 kid 令牌——这是轮换唯一关得掉旧钥的开关（单密钥轮换只能靠全员重新登录）。
 * env：JWT_SECRETS / JWT_REFRESH_SECRETS（JSON 对象 { "k1": "<secret>" }）、JWT_CURRENT_KID /
 *      JWT_REFRESH_CURRENT_KID；未配置密钥集时行为与单密钥完全一致。
 */

const config = require('../config');
const jwt = require('jsonwebtoken');

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const hasOwn = (map, kid) => Object.prototype.hasOwnProperty.call(map, kid);

const normalizeSecrets = (secrets) => {
  if (!isPlainObject(secrets)) return {};
  return Object.fromEntries(
    Object.entries(secrets).filter(
      ([kid, secret]) => typeof kid === 'string' && kid && typeof secret === 'string' && secret
    )
  );
};

const accessSecrets = () => normalizeSecrets(config.jwt.secrets);
const refreshSecrets = () => normalizeSecrets(config.jwt.refreshSecrets);

const currentKeyOf = (kind) => {
  if (kind === 'refresh') {
    const secrets = refreshSecrets();
    const kid = config.jwt.refreshCurrentKid;
    if (kid && hasOwn(secrets, kid)) return { kid, key: secrets[kid] };
    return { kid: null, key: config.jwt.refreshSecret };
  }
  const secrets = accessSecrets();
  const kid = config.jwt.currentKid;
  if (kid && hasOwn(secrets, kid)) return { kid, key: secrets[kid] };
  return { kid: null, key: config.jwt.secret };
};

const keyForHeader = (kind, header) => {
  const kid = header && typeof header.kid === 'string' ? header.kid : '';
  const secrets = kind === 'refresh' ? refreshSecrets() : accessSecrets();
  if (kid) return hasOwn(secrets, kid) ? secrets[kid] : null;
  // 无 kid：轮换前签发的历史令牌必须继续用**轮换前的单密钥**验签。不能回退当前签发钥——
  // 那会让轮换第一步（新增密钥 + currentKid 指向新钥）把全体存量会话踢下线；反过来，把
  // JWT_SECRET 清空即"立刻吊销全部无 kid 令牌"，这是轮换唯一能关掉旧钥的开关（返回 null 由
  // verifyKeyFor 抛 UNKNOWN_KID ⇒ 401）。
  const legacy = kind === 'refresh' ? config.jwt.refreshSecret : config.jwt.secret;
  return legacy || null;
};

/**
 * 取验签用密钥（同步形态）。不能用 jsonwebtoken 的 secretOrPublicKey 回调：库要求回调形态必须异步
 * 调用 verify（实测同步调用直接抛 "verify must be called asynchronous…"），而本仓所有验签点都是
 * 同步 `jwt.verify(`。这里只 decode(complete) 读**未经验证**的 header 选钥，签名校验仍由调用点的
 * jwt.verify 完成：header 被篡改只会选中错误的钥，验签随之失败，不会放行。
 *
 * 未知 kid 抛错而不是回退当前钥：回退会把轮换边界悄悄抹平，"旧钥已删除"的承诺就只剩注释。
 */
const verifyKeyFor = (token, kind) => {
  let header = null;
  try {
    header = jwt.decode(token, { complete: true })?.header || null;
  } catch (_) {
    header = null;
  }
  const key = keyForHeader(kind, header);
  if (!key) {
    const err = new Error(`未知的 JWT key id：${header && header.kid}`);
    err.code = 'JWT_UNKNOWN_KID';
    throw err;
  }
  return key;
};

const signKey = (kind) => currentKeyOf(kind).key;

/**
 * 当前**实际生效**的签发 kid（单钥模式为 null）。
 * 判据与 signKey 同源（currentKeyOf）：env 里点了名、但密钥集中不存在的 kid
 * 不会生效，这里也必须是 null——否则轮换留痕会记下一次"并未发生的切换"。
 */
const signingKids = () => ({
  access: currentKeyOf('access').kid,
  refresh: currentKeyOf('refresh').kid,
});

const signOptions = (kind, expiresIn) => {
  const { kid } = currentKeyOf(kind);
  return {
    algorithm: 'HS256',
    expiresIn,
    ...(kid ? { header: { kid, alg: 'HS256' } } : {}),
  };
};

module.exports = {
  verifyKeyFor,
  signKey,
  signOptions,
  keyForHeader,
  signingKids,
};
