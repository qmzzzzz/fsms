/**
 * 测试共用：口令密文构造器（镜像前端 WebCrypto 流程）
 *
 * Node 的 webcrypto 与浏览器实现同一 WebCrypto 标准，用它按前端
 * loginCipher.js 的步骤构造信封，等价于对「前端加密 ⇒ 后端解密」
 * 做跨实现互操作验证。测试密钥与口令均运行期生成，不落凭据字面量。
 */

const crypto = require('crypto');
const { getPublicKeyInfo } = require('../../utils/loginCipher');

/**
 * @param {string} password 明文口令（raw 模式下忽略）
 * @param {object} [options]
 * @param {number}  [options.ts]               载荷时间戳（默认当前时间）
 * @param {string}  [options.nonce]            载荷 nonce（默认随机）
 * @param {string}  [options.serverPublicPem]  指定加密用公钥（默认取当前服务端公钥）
 * @param {string}  [options.curve]            'P-256' | 'P-384'
 * @param {object}  [options.raw]              直接指定信封对象（构造畸形用例），绕过正常加密
 * @returns {Promise<string>} encPassword 字段值
 */
async function buildLoginEnvelope(
  password,
  {
    ts = Date.now(),
    nonce = crypto.randomBytes(16).toString('hex'),
    serverPublicPem = null,
    curve = 'P-256',
    raw = null,
  } = {}
) {
  if (raw) return Buffer.from(JSON.stringify(raw), 'utf8').toString('base64');

  const subtle = crypto.webcrypto.subtle;
  const pem = serverPublicPem || getPublicKeyInfo().publicKey;
  const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const serverPub = await subtle.importKey(
    'spki',
    der,
    { name: 'ECDH', namedCurve: curve },
    false,
    []
  );
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveBits']);
  const sharedBits = curve === 'P-384' ? 384 : 256;
  const shared = await subtle.deriveBits(
    { name: 'ECDH', public: serverPub },
    eph.privateKey,
    sharedBits
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const hkdfKey = await subtle.importKey('raw', shared, { name: 'HKDF' }, false, ['deriveKey']);
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('login-credential') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const jwk = await subtle.exportKey('jwk', eph.publicKey);
  const payload = new TextEncoder().encode(JSON.stringify({ p: password, ts, nonce }));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, payload));
  const b64 = (u8) => Buffer.from(u8).toString('base64');
  return Buffer.from(
    JSON.stringify({
      v: 1,
      x: jwk.x,
      y: jwk.y,
      salt: b64(salt),
      iv: b64(iv),
      c: b64(ct),
    }),
    'utf8'
  ).toString('base64');
}

/** 运行期随机口令（满足强度规则，避免凭据字面量） */
const randomPassword = () => `Aa1!${crypto.randomBytes(12).toString('hex')}`;

/** 进程内生成 EC 测试密钥（P-256/P-384） */
const generateEcKeyPem = (curve = 'prime256v1') =>
  crypto.generateKeyPairSync('ec', {
    namedCurve: curve,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

module.exports = { buildLoginEnvelope, randomPassword, generateEcKeyPem };
