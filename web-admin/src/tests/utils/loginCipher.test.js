/**
 * 前端口令加密模块测试（utils/loginCipher.js）
 *
 * 覆盖：信封结构与往返（用 Node crypto 按后端解密逻辑还原载荷，
 * 等价于「浏览器加密 ⇒ 服务端解密」跨实现验证）、公钥缓存与失效、
 * WebCrypto 可用性探测。
 * jsdom 环境无 crypto.subtle，注入 Node 的 WebCrypto（同一标准实现）。
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
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
const decryptEnvelope = (envelopeB64) => {
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

  test('WebCrypto 可用性探测为 true（已注入实现）', () => {
    expect(isTransportCryptoAvailable()).toBe(true)
  })

  test('信封往返：后端逻辑可还原口令，载荷含 ts 与 nonce', async () => {
    const password = `Aa1!${Math.random().toString(36).slice(2)}`
    const envelope = await encryptPassword(password)

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
    await encryptPassword('cache-check-Aa1')
    await encryptPassword('cache-check-Bb2')
    expect(axios.get).toHaveBeenCalledTimes(1)
  })

  test('缓存失效后重新获取公钥', async () => {
    await encryptPassword('invalidate-check-Aa1')
    expect(axios.get).toHaveBeenCalledTimes(1)

    invalidatePublicKeyCache()
    await encryptPassword('invalidate-check-Bb2')
    expect(axios.get).toHaveBeenCalledTimes(2)
  })

  test('两次加密产生不同密文（每次全新临时密钥与 nonce）', async () => {
    const a = await encryptPassword('same-password-Aa1')
    const b = await encryptPassword('same-password-Aa1')
    expect(a).not.toBe(b)
  })

  test('公钥获取失败时抛错（由调用方降级明文轨）', async () => {
    axios.get.mockRejectedValueOnce(new Error('network down'))
    await expect(encryptPassword('fallback-Aa1')).rejects.toThrow()
  })
})
