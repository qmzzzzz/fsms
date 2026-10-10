/**
 * 登录口令传输加密（覆盖 POST /api/auth/login、register、password、mfa/disable）
 *
 * 结构（ECIES 式混合加密，与 TLS 1.3 的密钥协商同族）：
 *   前端：生成一次性 ECDH 密钥对，与服务端静态公钥协商出共享密钥，
 *         经 HKDF-SHA256 派生 AES-256-GCM 密钥加密载荷 {p, ts, nonce}
 *         （AES-GCM 的 additionalData 绑定端点用途，见 CREDENTIAL_AAD）；
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
 * 截获密文的攻击者无法重放原密文（nonce 已消费，载荷被 GCM 认证不可篡改），
 * 也无法恢复口令——但后者以「服务端私钥不泄露」为前提：信封自带临时公钥
 * 坐标，持有静态私钥（LOGIN_ECDH_PRIVATE_KEY_FILE 注入）即可对任一历史
 * 密文重新协商出共享密钥，即无前向保密。临时密钥对模式（见下）相反：
 * 私钥不出进程故历史密文攻不破，但重启即换钥，重启前的密文永久不可解密。
 *
 * 密钥管理：私钥经 LOGIN_ECDH_PRIVATE_KEY(_FILE) 注入（P3-48 约定），
 * 曲线支持 P-256 / P-384，非法曲线或非 EC 密钥直接拒绝。
 * 未配置时惰性生成临时密钥对并告警——私钥不出进程、前端按会话取公钥，
 * 重启换钥无安全损失（仅损失 keyId 诊断连续性）；但重启前产生的密文
 * 在重启后永久无法解密——流量取证须在重启前完成，或持久注入静态私钥。
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
// 信封用途绑定（AAD，2026-10-10）：GCM 的 additionalData 把「本信封只准用于
// 哪个端点」纳入认证范围——没有它时，一条**从未到达服务端**的捕获信封（用户
// 填完表单但提交失败/被丢弃，密文已上线）在 ±5 分钟窗口内可提交到任何接收
// 密文口令的端点：例如把改密页捕获的 encNewPassword 提交到 /login，直接以
// 新口令登录。nonce 去重只能挡「已提交过」的信标，挡不住「从未提交」的。
// 取值前后端必须逐字节一致（同 HKDF_INFO 的口径）；新增接收端点时两边同步加，
// 漏加的那一侧对该端点的信封全部解密失败（fail-closed，不会静默放行）。
// 刻意不把用户名绑进 AAD：跨用户重放会在口令比对处自然失败（401），
// 绑用户名零安全收益，却让前端每个表单多一个必须逐字一致的条件。
const CREDENTIAL_AAD = {
  LOGIN: 'login',
  REGISTER: 'register',
  PASSWORD_CURRENT: 'password:current',
  PASSWORD_NEW: 'password:new',
  MFA_DISABLE: 'mfa:disable',
  USER_CREATE: 'user:create',
};
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
    // 不保留 privateKeyPem：createPrivateKey 之后私钥已在 OpenSSL 句柄里，
    // 再把同一段明文 PEM 挂在 JS 对象上，等于让私钥在 V8 堆里多存一份
    // （堆快照/core dump/将来任何打印 keyPair 的代码都会把它带出去），且无任何读取方。
    publicKeyPem: pub.export({ type: 'spki', format: 'pem' }).toString(),
    curve: curveName,
    coordBytes: curve.coordBytes,
    // keyId：公钥指纹前 8 位，诊断用（日志/响应），一期不做多密钥并存
    keyId: crypto.createHash('sha256').update(spkiDer).digest('hex').slice(0, 8),
    // 完整指纹：前端构建期钉扎（web-admin 的 VITE_LOGIN_PUBLIC_KEY_SHA256）
    // 的取值来源——8 位 keyId 只有 32bit，不足以安全钉扎（可被离线穷举
    // 碰撞），钉扎必须用完整值或其 >=16 位前缀。公钥指纹是公开信息。
    publicKeySha256: crypto.createHash('sha256').update(spkiDer).digest('hex'),
  };
  return keyPair;
}

function ensureKeyPair() {
  if (keyPair) return keyPair;

  // dotenv 不支持多行值：允许用字面量 \n 表示 PEM 换行
  const envPem = (process.env.LOGIN_ECDH_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();
  if (envPem) {
    const kp = initFromPrivatePem(envPem);
    // 完整指纹随启动日志下发：运维据此把 VITE_LOGIN_PUBLIC_KEY_SHA256 钉进
    // 前端构建（防主动 MITM 替换公钥，见 web-admin/src/utils/loginCipher.js
    // ensurePublicKey 的指纹校验）。公钥指纹是公开信息，日志不含秘密。
    logger.info('登录 ECDH 静态私钥已注入', {
      keyId: kp.keyId,
      publicKeySha256: kp.publicKeySha256,
      curve: kp.curve,
    });
    return kp;
  }

  if (process.env.NODE_ENV !== 'test') {
    logger.warn(
      '未配置 LOGIN_ECDH_PRIVATE_KEY，登录口令加密使用本次启动生成的临时密钥对' +
        '（重启后自动换钥，前端会重新获取公钥；生产环境请通过 LOGIN_ECDH_PRIVATE_KEY_FILE 持久注入）'
    );
  }
  // 只绑定 privateKey：initFromPrivatePem 从私钥本体重新导出公钥（createPublicKey），
  // 第二参数从来不是它的入参——留着 publicKey 只会让人误以为下发的公钥经过外部校验。
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: DEFAULT_CURVE,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return initFromPrivatePem(privateKey);
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
 * 阶段 1 —— 信封解析与形状校验（纯结构，不接触任何密钥材料）
 *
 * 长度上限先于解码：信封是外部可控输入，先把量钉住再解析。
 * 临时公钥坐标的长度必须与当前服务端曲线匹配，好让"错配曲线"
 * （重启换钥后前端仍用缓存的旧公钥加密）在 ECDH 之前就被挡下。
 */
function parseCredentialEnvelope(kp, envelopeB64) {
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

  if (
    typeof x !== 'string' ||
    typeof y !== 'string' ||
    Buffer.from(x, 'base64url').length !== kp.coordBytes ||
    Buffer.from(y, 'base64url').length !== kp.coordBytes
  ) {
    throw new CredentialError('ENVELOPE_FORMAT');
  }

  let saltBuf;
  let ivBuf;
  let ctBuf;
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
  return { x, y, saltBuf, ivBuf, ctBuf };
}

/**
 * 阶段 2 —— ECDH 协商 + HKDF-SHA256 派生 + AES-256-GCM 解载荷（与前端 WebCrypto 同参）
 *
 * 无效曲线点 / 公钥错配 / 认证标签不符 / AAD 用途不符 等原因**一律吞并**成
 * DECRYPT：不区分失败原因，免得给探测者"差一点了"的信号。AAD 不符（信封是
 * 为别的端点加密的）与"密钥错了"在对外表现上不可区分，正是这条吞并的延伸。
 */
function decryptCredentialPayload(kp, { x, y, saltBuf, ivBuf, ctBuf }, aad) {
  try {
    const ephPub = crypto.createPublicKey({
      key: { kty: 'EC', crv: SUPPORTED_CURVES[kp.curve].jwk, x, y },
      format: 'jwk',
    });
    const shared = crypto.diffieHellman({ privateKey: kp.privateKeyObj, publicKey: ephPub });
    const aesKey = Buffer.from(
      crypto.hkdfSync('sha256', shared, saltBuf, HKDF_INFO, HKDF_KEY_BYTES)
    );

    // WebCrypto 的输出是 密文||tag，尾部 16 字节即认证标签
    const tag = ctBuf.subarray(ctBuf.length - GCM_TAG_BYTES);
    const body = ctBuf.subarray(0, ctBuf.length - GCM_TAG_BYTES);
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuf);
    decipher.setAuthTag(tag);
    // 用途绑定（AAD）：前端 encrypt 的 additionalData 必须与本端点的用途串
    // 逐字节一致，否则认证标签校验失败——跨端点重放在此被拒
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  } catch (_) {
    throw new CredentialError('DECRYPT');
  }
}

/**
 * 阶段 3 —— 明文载荷结构与时间窗 / nonce 形态校验
 * （一次性消费要落库，留在编排函数里，那里才有 await）
 */
function parseCredentialPayload(plain) {
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
  return { p, nonce };
}

/**
 * 解密并校验口令密文，成功返回明文口令
 * 任何失败一律抛 CredentialError
 *
 * @param {string} envelopeB64 上行信封
 * @param {string} purpose 用途键（CREDENTIAL_AAD 的键，如 'LOGIN'）：决定
 *   GCM 的 AAD——为别的端点加密的信封在此解密失败（跨端点重放防护）。
 *   未知键抛普通 Error（编程错误，不应发生）；两种抛出都落在调用方的
 *   ENC_INVALID 分支，fail-closed 不放行。
 *
 * 异步：nonce 一次性消费经 sharedCache 原子占位（配置 REDIS_URL 时跨实例
 * 共享，重放无论命中哪个实例都被拒绝；未配置时回退进程内去重）
 */
async function decryptLoginCredential(envelopeB64, purpose) {
  const aad = CREDENTIAL_AAD[purpose];
  if (!aad) {
    throw new Error(`decryptLoginCredential: 未知用途键 "${purpose}"（CREDENTIAL_AAD 未定义）`);
  }
  const kp = ensureKeyPair();
  const parts = parseCredentialEnvelope(kp, envelopeB64);
  const plain = decryptCredentialPayload(kp, parts, aad);
  const { p, nonce } = parseCredentialPayload(plain);

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
  CREDENTIAL_AAD,
  getPublicKeyInfo,
  decryptLoginCredential,
  _resetForTests,
};
