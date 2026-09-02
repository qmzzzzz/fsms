/**
 * 登录口令传输加密（与后端 src/utils/loginCipher.js 对偶）
 *
 * ECIES 式混合加密：一次性 ECDH 密钥对与服务端静态公钥（GET /api/auth/login-public-key）
 * 协商共享密钥，HKDF-SHA256 派生 AES-256-GCM 密钥加密 {p, ts, nonce}。
 * 上行 encPassword = base64(JSON{v:1, x, y, salt, iv, c})，
 * x/y 为临时公钥 JWK 坐标（base64url），c 为 AES 密文||16 字节 GCM tag。
 *
 * 防重放：ts 限 ±5 分钟窗口；nonce 一次性——截获密文的攻击者既无法恢复口令
 * （ECDH 共享密钥只有双方可算），也无法重放原密文（nonce 已消费，GCM 认证防篡改）。
 *
 * 依赖 WebCrypto（crypto.subtle）——仅在 secure context（HTTPS / localhost）可用。
 * 不可用时返回 null，调用方降级明文轨（后端双轨兼容）。
 */
import axios from 'axios'

let cachedKey = null // { keyObj, curve }，会话级缓存；服务端换钥后由 invalidate 清除

export const isTransportCryptoAvailable = () =>
  typeof crypto !== 'undefined' && !!crypto.subtle && typeof TextEncoder !== 'undefined'

const b64Encode = (bytes) => {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}

const toHex = (bytes) =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

// PEM(SPKI) → DER：WebCrypto importKey 只接受二进制
const pemToBytes = (pem) => {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '')
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

async function ensurePublicKey(force = false) {
  if (cachedKey && !force) return cachedKey
  // 直接用 axios 裸调用（同 utils/api.js 的 doRefreshToken 先例）：
  // 公钥获取不需要认证/拦截器/取消链路，保持本模块零重依赖（不引入
  // router/element-plus 导入链），便于单测
  const { data: resp } = await axios.get(
    (import.meta.env.VITE_API_BASE_URL || '/api') + '/auth/login-public-key'
  )
  const pem = resp?.data?.publicKey
  const curve = resp?.data?.curve || 'P-256'
  if (!pem) throw new Error('public key unavailable')
  const keyObj = await crypto.subtle.importKey(
    'spki',
    pemToBytes(pem),
    { name: 'ECDH', namedCurve: curve },
    false,
    []
  )
  cachedKey = { keyObj, curve }
  return cachedKey
}

/** 清除公钥缓存：密文被服务端拒绝（重启换钥/密钥轮换）后重新获取用 */
export const invalidatePublicKeyCache = () => {
  cachedKey = null
}

/**
 * 加密口令，返回 encPassword 字段值；
 * WebCrypto 不可用（非 secure context）时返回 null，由调用方走明文轨
 */
export async function encryptPassword(password) {
  if (!isTransportCryptoAvailable()) return null
  const { keyObj: serverPub, curve } = await ensurePublicKey()

  // 1) 一次性 ECDH 密钥对 → 共享密钥（P-256/P-384 全长）→ HKDF 派生 AES-256 密钥
  //    （盐随机，随信封上行；info 与后端逐字节一致）
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, [
    'deriveBits',
  ])
  const sharedBits = curve === 'P-384' ? 384 : 256
  const shared = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: serverPub },
    eph.privateKey,
    sharedBits
  )
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const hkdfKey = await crypto.subtle.importKey('raw', shared, { name: 'HKDF' }, false, [
    'deriveKey',
  ])
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('login-credential') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  )

  // 2) 载荷 {p, ts, nonce}：nonce 一次性，防截获密文重放
  const jwk = await crypto.subtle.exportKey('jwk', eph.publicKey)
  const nonce = toHex(crypto.getRandomValues(new Uint8Array(16)))
  const payload = new TextEncoder().encode(JSON.stringify({ p: password, ts: Date.now(), nonce }))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, payload))

  // 3) 信封（与后端 decryptLoginCredential 的解析格式逐字段对齐）
  return b64Encode(
    new TextEncoder().encode(
      JSON.stringify({
        v: 1,
        x: jwk.x,
        y: jwk.y,
        salt: b64Encode(salt),
        iv: b64Encode(iv),
        c: b64Encode(ct),
      })
    )
  )
}
