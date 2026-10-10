/**
 * 前端口令加密模块测试（utils/loginCipher.js）
 *
 * 覆盖：信封结构与往返（用 Node crypto 按后端解密逻辑还原载荷，
 * 等价于「浏览器加密 ⇒ 服务端解密」跨实现验证）、公钥缓存与失效、
 * WebCrypto 可用性探测。
 * jsdom 环境无 crypto.subtle，注入 Node 的 WebCrypto（同一标准实现）。
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { webcrypto as nodeWebcrypto } from 'node:crypto'
import nodeCrypto from 'node:crypto'

// jsdom 不提供 crypto.subtle（仅 getRandomValues）；注入 Node 的 WebCrypto。
// loginCipher 仅在调用时使用 crypto（非模块加载期），此注入时机足够。
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { value: nodeWebcrypto, configurable: true })
}

vi.mock('axios', () => ({
  default: { get: vi.fn() },
}))

import axios from 'axios'
import {
  encryptPassword,
  invalidatePublicKeyCache,
  isTransportCryptoAvailable,
} from '@/utils/loginCipher'

// 服务端静态密钥（P-256）：公钥喂给 mock 的公钥接口，私钥用于本地解密验证
const { publicKey: SERVER_PUBLIC_PEM, privateKey: SERVER_PRIVATE_PEM } =
  nodeCrypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })

/** 镜像后端 decryptLoginCredential 的解密逻辑，还原载荷对象 */
const decryptEnvelope = (envelopeB64, aad = 'login') => {
  const inner = JSON.parse(Buffer.from(envelopeB64, 'base64').toString('utf8'))
  const ephPub = nodeCrypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: inner.x, y: inner.y },
    format: 'jwk',
  })
  const shared = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(SERVER_PRIVATE_PEM),
    publicKey: ephPub,
  })
  const aesKey = Buffer.from(
    nodeCrypto.hkdfSync(
      'sha256',
      shared,
      Buffer.from(inner.salt, 'base64'),
      Buffer.from('login-credential'),
      32
    )
  )
  const ct = Buffer.from(inner.c, 'base64')
  const decipher = nodeCrypto.createDecipheriv(
    'aes-256-gcm',
    aesKey,
    Buffer.from(inner.iv, 'base64')
  )
  decipher.setAuthTag(ct.subarray(ct.length - 16))
  // 与后端一致：AAD 绑定端点用途，用途不符时 final() 抛认证失败
  decipher.setAAD(Buffer.from(aad, 'utf8'))
  return JSON.parse(
    Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]).toString(
      'utf8'
    )
  )
}

describe('loginCipher 前端口令加密', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    invalidatePublicKeyCache()
    axios.get.mockResolvedValue({
      data: {
        success: true,
        data: { publicKey: SERVER_PUBLIC_PEM, curve: 'P-256', keyId: 'testkeyid' },
      },
    })
  })

  afterEach(() => {
    // 指纹钉扎用例 stub 的 VITE_ 变量不得泄漏到其余用例（未配置即跳过检查）
    vi.unstubAllEnvs()
  })

  test('WebCrypto 可用性探测为 true（已注入实现）', () => {
    expect(isTransportCryptoAvailable()).toBe(true)
  })

  test('信封往返：后端逻辑可还原口令，载荷含 ts 与 nonce', async () => {
    const password = `Aa1!${Math.random().toString(36).slice(2)}`
    const envelope = await encryptPassword(password, 'LOGIN')

    expect(typeof envelope).toBe('string')
    const inner = JSON.parse(Buffer.from(envelope, 'base64').toString('utf8'))
    expect(inner.v).toBe(1)
    expect(inner.x).toBeTruthy()
    expect(inner.y).toBeTruthy()

    const payload = decryptEnvelope(envelope)
    expect(payload.p).toBe(password)
    expect(Math.abs(Date.now() - payload.ts)).toBeLessThan(60 * 1000)
    expect(payload.nonce).toMatch(/^[0-9a-f]{32}$/)
  })

  test('公钥会话级缓存：两次加密只请求一次公钥', async () => {
    await encryptPassword('cache-check-Aa1', 'LOGIN')
    await encryptPassword('cache-check-Bb2', 'LOGIN')
    expect(axios.get).toHaveBeenCalledTimes(1)
  })

  test('缓存失效后重新获取公钥', async () => {
    await encryptPassword('invalidate-check-Aa1', 'LOGIN')
    expect(axios.get).toHaveBeenCalledTimes(1)

    invalidatePublicKeyCache()
    await encryptPassword('invalidate-check-Bb2', 'LOGIN')
    expect(axios.get).toHaveBeenCalledTimes(2)
  })

  test('两次加密产生不同密文（每次全新临时密钥与 nonce）', async () => {
    const a = await encryptPassword('same-password-Aa1', 'LOGIN')
    const b = await encryptPassword('same-password-Aa1', 'LOGIN')
    expect(a).not.toBe(b)
  })

  test('公钥获取失败时抛错（由调用方降级明文轨）', async () => {
    axios.get.mockRejectedValueOnce(new Error('network down'))
    await expect(encryptPassword('fallback-Aa1', 'LOGIN')).rejects.toThrow()
  })

  test('用途绑定：AAD 参与认证，跨端点用途还原失败', async () => {
    // 与后端 CREDENTIAL_AAD 对偶：信封只能用于加密时声明的端点——
    // 把登录用途的信封按改密端点用途解密，GCM 认证标签校验必须失败
    const password = 'aad-check-Aa1!'
    const envelope = await encryptPassword(password, 'LOGIN')
    expect(decryptEnvelope(envelope, 'login').p).toBe(password)
    expect(() => decryptEnvelope(envelope, 'password:new')).toThrow()
  })

  test('未知用途键抛错（fail-closed，不退回无 AAD 加密）', async () => {
    await expect(encryptPassword('purpose-check-Aa1', 'NOT_A_PURPOSE')).rejects.toThrow(
      /未知用途键/
    )
  })

  // 构建期指纹钉扎（2026-10-10）：公钥信道无内建认证，主动 MITM 可替换公钥——
  // 生产构建把服务端公钥 SHA-256 指纹编入包，取到的公钥与钉扎值不符即拒绝。
  // 服务端测试公钥的指纹（SPKI DER 的 SHA-256，与后端 keyId 同一算法）
  const serverPin = () =>
    nodeCrypto
      .createHash('sha256')
      .update(
        Buffer.from(SERVER_PUBLIC_PEM.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64')
      )
      .digest('hex')

  test('指纹钉扎：与构建期固定值一致时放行', async () => {
    vi.stubEnv('VITE_LOGIN_PUBLIC_KEY_SHA256', serverPin())
    const envelope = await encryptPassword('pin-ok-Aa1', 'LOGIN')
    expect(typeof envelope).toBe('string')
  })

  test('指纹钉扎：公钥被换（MITM/轮换未重建）即拒绝，不降级明文', async () => {
    // 防退化：不符时静默放行 → 主动中间人换钥即可 decrypt-and-forward
    vi.stubEnv('VITE_LOGIN_PUBLIC_KEY_SHA256', 'a'.repeat(64))
    await expect(encryptPassword('pin-bad-Aa1', 'LOGIN')).rejects.toThrow(/fingerprint mismatch/)
  })

  test('指纹钉扎：构建期取值格式非法直接拒绝（防弱钉扎静默生效）', async () => {
    // 防退化：过短/非十六进制取值被忽略 → 部署以为钉了其实没钉
    vi.stubEnv('VITE_LOGIN_PUBLIC_KEY_SHA256', 'xyz')
    await expect(encryptPassword('pin-format-Aa1', 'LOGIN')).rejects.toThrow(/格式无效/)
  })
})
