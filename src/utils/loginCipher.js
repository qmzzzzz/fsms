/**
 * 登录口令传输加密（覆盖 POST /api/auth/login、register、password、mfa/disable）
 *
 * 结构（ECIES 式混合加密，与 TLS 1.3 的密钥协商同族）：
 *   前端：生成一次性 ECDH 密钥对，与服务端静态公钥协商出共享密钥，
 *         经 HKDF-SHA256 派生 AES-256-GCM 密钥加密载荷 {p, ts, nonce}；
 *   上行：encPassword = base64(JSON{v:1, x, y, salt, iv, c})，
 *         x/y 为临时公钥坐标（base64url），c 为 AES 密文||16 字节 GCM tag。
 *
 * 为什么用 ECDH 而不是 RSA-OAEP：P-256 即达 128-bit 安全强度且密钥/密文
 * 体积小一个数量级（临时公钥 65 字节 vs RSA-3072 密文 384 字节），
 * 浏览器 WebCrypto 与 Node 原生支持，无第三方依赖。
 *
 * 防重放：ts 限 ±5 分钟窗口；nonce 经 sharedCache 一次性消费——
 * 配置 REDIS_URL 时跨实例共享（任一实例消费后全集群拒绝重放），
 * 未配置时回退进程内去重（单实例语义，与其余共享层口径一致）。
 * 截获密文的攻击者既无法恢复口令（ECDH 共享密钥只有双方可算），
 * 也无法重放原密文（nonce 已消费，载荷被 GCM 认证不可篡改）。
 *
 * 密钥管理：私钥经 LOGIN_ECDH_PRIVATE_KEY(_FILE) 注入（P3-48 约定），
 * 曲线支持 P-256 / P-384，非法曲线或非 EC 密钥直接拒绝。
 * 未配置时惰性生成临时密钥对并告警——私钥不出进程、密文一次性、
 * 前端按会话取公钥，重启换钥无安全损失，仅损失 keyId 诊断连续性。
 */

const crypto = require('crypto');
const logger = require('./logger');
const sharedCache = require('../services/sharedCache');

// 支持的曲线：Node 内部名 → JWK/WebCrypto 名与坐标字节长度
const SUPPORTED_CURVES = {
  prime256v1: { jwk: 'P-256', coordBytes: 32 }, // 128-bit 安全强度
  secp384r1: { jwk: 'P-384', coordBytes: 48 }, // 192-bit 安全强度
};
const DEFAULT_CURVE = 'prime256v1';
// HKDF info 标签：前端（WebCrypto deriveKey 的 info）与后端必须逐字节一致
const HKDF_INFO = Buffer.from('login-credential', 'utf8');
const HKDF_SALT_BYTES = 16;
const HKDF_KEY_BYTES = 32; // AES-256
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const ENVELOPE_MAX_B64_LEN = 1024; // 实际约 600 字符，上限留裕量
const PASSWORD_MAX_CHARS = 128; // 与 loginValidation 明文轨的口令上限一致
const REPLAY_WINDOW_MS = 5 * 60 * 1000; // ts 窗口
// nonce 去重键保留时长：客户端时钟最大可偏 ±5 分钟，信封首次被接受后
// 最长还要再存活一个窗口才彻底超出 ts 窗口，故键取 2 倍窗口（宁可多留）
const NONCE_TTL_MS = REPLAY_WINDOW_MS * 2;
const NONCE_KEY_PREFIX = 'login-nonce:';

/**
 * 解密失败统一抛出。code 仅写服务端日志用于排障，
 * 不回传客户端做区分——差异化错误可被用于探测服务端校验逻辑。
 */
class CredentialError extends Error {
  constructor(code) {
    super(`login credential decrypt failed: ${code}`);
    this.code = code;
  }
}

let keyPair = null; // { privateKeyObj, publicKeyPem, keyId, curve, coordBytes }

function initFromPrivatePem(privateKeyPem) {
  const priv = crypto.createPrivateKey(privateKeyPem);
  // 曲线从密钥本体取：注入 P-256 / P-384 密钥时坐标长度校验自动对齐
  const curveName = priv.asymmetricKeyDetails?.namedCurve;
  const curve = SUPPORTED_CURVES[curveName];
  if (priv.asymmetricKeyType !== 'ec' || !curve) {
    throw new Error(
      `LOGIN_ECDH_PRIVATE_KEY 必须是 P-256/P-384 EC 私钥（当前：${priv.asymmetricKeyType}/${curveName}），` +
        '请重新生成：openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256'
    );
  }

  const pub = crypto.createPublicKey(priv);
  const spkiDer = pub.export({ type: 'spki', format: 'der' });
  keyPair = {
    privateKeyObj: priv,
    privateKeyPem,
    publicKeyPem: pub.export({ type: 'spki', format: 'pem' }).toString(),
    curve: curveName,
    coordBytes: curve.coordBytes,
    // keyId：公钥指纹前 8 位，诊断用（日志/响应），一期不做多密钥并存
    keyId: crypto.createHash('sha256').update(spkiDer).digest('hex').slice(0, 8),
  };
  return keyPair;
}

function ensureKeyPair() {
  if (keyPair) return keyPair;

  // dotenv 不支持多行值：允许用字面量 \n 表示 PEM 换行
  const envPem = (process.env.LOGIN_ECDH_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();
  if (envPem) {
    return initFromPrivatePem(envPem);
  }

  if (process.env.NODE_ENV !== 'test') {
    logger.warn(
      '未配置 LOGIN_ECDH_PRIVATE_KEY，登录口令加密使用本次启动生成的临时密钥对' +
        '（重启后自动换钥，前端会重新获取公钥；生产环境请通过 LOGIN_ECDH_PRIVATE_KEY_FILE 持久注入）'
    );
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: DEFAULT_CURVE,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return initFromPrivatePem(privateKey, publicKey);
}

/** 公钥下发（GET /api/auth/login-public-key），curve 供前端 importKey 使用 */
function getPublicKeyInfo() {
  const kp = ensureKeyPair();
  return {
    publicKey: kp.publicKeyPem,
    keyId: kp.keyId,
    curve: SUPPORTED_CURVES[kp.curve].jwk,
    algorithm: 'ECDH + HKDF-SHA256 + AES-256-GCM',
  };
}

/**
 * 解密并校验口令密文，成功返回明文口令
 * 任何失败一律抛 CredentialError
 *
 * 异步：nonce 一次性消费经 sharedCache 原子占位（配置 REDIS_URL 时跨实例
 * 共享，重放无论命中哪个实例都被拒绝；未配置时回退进程内去重）
 */
async function decryptLoginCredential(envelopeB64) {
  const kp = ensureKeyPair();

  let envelope;
  try {
    if (
      typeof envelopeB64 !== 'string' ||
      envelopeB64.length === 0 ||
      envelopeB64.length > ENVELOPE_MAX_B64_LEN
    ) {
      throw new Error('len');
    }
    envelope = JSON.parse(Buffer.from(envelopeB64, 'base64').toString('utf8'));
  } catch (_) {
    throw new CredentialError('ENVELOPE_FORMAT');
  }

  const { v, x, y, salt, iv, c } = envelope || {};
  if (v !== 1) throw new CredentialError('ENVELOPE_VERSION');

  // 临时公钥坐标（base64url）：长度必须与当前服务端曲线匹配，
  // 错配曲线（如重启换钥后前端缓存未刷新）在 ECDH 之前挡下
  if (
    typeof x !== 'string' ||
    typeof y !== 'string' ||
    Buffer.from(x, 'base64url').length !== kp.coordBytes ||
    Buffer.from(y, 'base64url').length !== kp.coordBytes
  ) {
    throw new CredentialError('ENVELOPE_FORMAT');
  }

  let saltBuf, ivBuf, ctBuf;
  try {
    saltBuf = Buffer.from(String(salt), 'base64');
    ivBuf = Buffer.from(String(iv), 'base64');
    ctBuf = Buffer.from(String(c), 'base64');
  } catch (_) {
    throw new CredentialError('ENVELOPE_FORMAT');
  }
  if (
    saltBuf.length !== HKDF_SALT_BYTES ||
    ivBuf.length !== GCM_IV_BYTES ||
    ctBuf.length <= GCM_TAG_BYTES
  ) {
    throw new CredentialError('ENVELOPE_FORMAT');
  }

  // 1) ECDH 协商共享密钥 + HKDF-SHA256 派生 AES 密钥（与前端 WebCrypto 同参）
  let plain;
  try {
    const ephPub = crypto.createPublicKey({
      key: { kty: 'EC', crv: SUPPORTED_CURVES[kp.curve].jwk, x, y },
      format: 'jwk',
    });
    const shared = crypto.diffieHellman({ privateKey: kp.privateKeyObj, publicKey: ephPub });
    const aesKey = Buffer.from(
      crypto.hkdfSync('sha256', shared, saltBuf, HKDF_INFO, HKDF_KEY_BYTES)
    );

    // 2) AES-256-GCM 解载荷（WebCrypto 输出 = 密文||tag，尾部 16 字节为 tag）
    const tag = ctBuf.subarray(ctBuf.length - GCM_TAG_BYTES);
    const body = ctBuf.subarray(0, ctBuf.length - GCM_TAG_BYTES);
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuf);
    decipher.setAuthTag(tag);
    plain = Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  } catch (_) {
    // 含无效曲线点/错配公钥/认证失败，统一吞并为解密失败
    throw new CredentialError('DECRYPT');
  }

  // 3) 载荷校验：结构 → 时间窗 → nonce 一次性
  let payload;
  try {
    payload = JSON.parse(plain);
  } catch (_) {
    throw new CredentialError('PAYLOAD_FORMAT');
  }
  const { p, ts, nonce } = payload || {};
  if (typeof p !== 'string' || p.length === 0 || p.length > PASSWORD_MAX_CHARS) {
    throw new CredentialError('PAYLOAD_FORMAT');
  }
  if (!Number.isInteger(ts) || Math.abs(Date.now() - ts) > REPLAY_WINDOW_MS) {
    throw new CredentialError('TS_WINDOW');
  }
  if (typeof nonce !== 'string' || !/^[0-9a-f]{16,64}$/i.test(nonce)) {
    throw new CredentialError('NONCE_FORMAT');
  }
  // 一次性消费：SET NX 原子占位，首个到达的实例赢得消费权，
  // 重放（含命中其他实例的副本）在占位失败处被拒
  const firstSeen = await sharedCache.setIfAbsent(NONCE_KEY_PREFIX + nonce, 1, NONCE_TTL_MS);
  if (!firstSeen) {
    throw new CredentialError('NONCE_REPLAY');
  }

  return p;
}

/** 测试钩子：重新生成密钥对（共享层测试钩子另行清理缓存） */
function _resetForTests() {
  keyPair = null;
}

module.exports = {
  CredentialError,
  getPublicKeyInfo,
  decryptLoginCredential,
  _resetForTests,
};
