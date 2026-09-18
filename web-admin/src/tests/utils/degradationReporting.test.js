/**
 * P1-17 / P1-18 回归：资源 URL 脱敏 + 降级上报
 *
 * P1-17：initErrorHandling 的资源加载失败分支把 target.src / target.href 原样
 * 拼进上报消息，而 record() 只对 location.href 做 redactUrl——带 ?token=... 的
 * 第三方资源 URL 会明文落入 localStorage 环形缓冲并外发。修复后该分支同样过
 * redactUrl。本套件通过真实事件路径（img 元素 + error 事件）验证，而非直接调
 * redactUrl（既有 errorReporter.test.js 已覆盖该函数本身）。
 *
 * P1-18：4 处「能力降级但流程继续」的路径此前完全静默。修复后 3 处接入
 * reportDegradation（kind=degrade），1 处（vite.config.js，构建期 Node 环境）
 * 无法接入应用层 errorReporter，改用构建期 console.warn——本套件以源码断言
 * 锁定该结论，防止后续误改成 import errorReporter 导致 vite 配置加载失败。
 */
import { describe, test, expect, beforeEach, beforeAll, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  initErrorHandling,
  getLoggedErrors,
  clearLoggedErrors,
  reportDegradation,
} from '@/utils/errorReporter'

const SRC = resolve(__dirname, '../..')
const readSrc = (rel) => readFileSync(resolve(SRC, rel), 'utf8')
const app = { config: {} }

describe('P1-17：资源加载失败的 URL 脱敏', () => {
  beforeAll(() => {
    initErrorHandling(app)
  })

  beforeEach(() => {
    clearLoggedErrors()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  test('带敏感 query 的资源 URL 上报时值被打码、键名保留', () => {
    const img = document.createElement('img')
    img.src = 'https://cdn.example.com/x.png?token=leak&v=2'
    document.body.appendChild(img)
    img.dispatchEvent(new Event('error'))
    img.remove()

    const entry = getLoggedErrors().find((e) => e.kind === 'resource')
    expect(entry).toBeDefined()
    expect(entry.message).toContain('token=***')
    expect(entry.message).toContain('v=2')
    expect(entry.message).not.toContain('leak')
  })
})

describe('P1-18：降级路径上报', () => {
  beforeEach(() => {
    clearLoggedErrors()
  })

  test('reportDegradation 以 kind=degrade 入库并持久化', () => {
    reportDegradation('probe: 降级留痕', { reason: 'test' })
    const entry = getLoggedErrors().find((e) => e.kind === 'degrade')
    expect(entry).toBeDefined()
    expect(entry.message).toBe('probe: 降级留痕')
    expect(entry.reason).toBe('test')
  })

  test('三处应用层降级点已接入 reportDegradation（保持降级行为不变）', () => {
    const sites = [
      ['utils/loginCipher.js', 'loginCipher: WebCrypto 不可用'],
      ['utils/websocket.js', 'websocket: 首次建连失败'],
      ['composables/usePermissionSync.js', 'permissionSync: WebSocket 订阅失败'],
    ]
    for (const [rel, marker] of sites) {
      const src = readSrc(rel)
      expect(src, rel).toContain("import { reportDegradation } from '@/utils/errorReporter'")
      expect(src, rel).toContain(marker)
    }
  })

  test('loginCipher：WebCrypto 不可用时上报降级且返回 null（端到端）', async () => {
    // 本 vitest 环境已提供 crypto.subtle，需临时改写以复现「非 secure context」
    const savedCrypto = globalThis.crypto
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true })
    try {
      const { encryptPassword, isTransportCryptoAvailable } = await import('@/utils/loginCipher')
      expect(isTransportCryptoAvailable()).toBe(false)
      clearLoggedErrors()
      const result = await encryptPassword('Aa1!probe-degrade')
      expect(result).toBeNull()
      const entry = getLoggedErrors().find((e) => e.kind === 'degrade')
      expect(entry).toBeDefined()
      expect(entry.message).toContain('WebCrypto 不可用')
      expect(entry.reason).toBe('insecure-context-or-unsupported-browser')
    } finally {
      Object.defineProperty(globalThis, 'crypto', { value: savedCrypto, configurable: true })
    }
  })
  test('loginCipher 的降级语义未变：仍返回 null（调用方走明文轨）', () => {
    const src = readSrc('utils/loginCipher.js')
    // 上报后必须仍 return null，否则调用方会把它当「加密成功」
    const block = src.slice(src.indexOf('isTransportCryptoAvailable()'))
    expect(block).toContain('reportDegradation(')
    expect(block).toContain('return null')
  })

  test('vite.config.js：构建期不 import 应用层 errorReporter，改用 console.warn', () => {
    const src = readSrc('../vite.config.js')
    // 注释里解释了为何不能接入；但不得真的 import（Node 环境无 import.meta.env）
    expect(src).not.toMatch(/^\s*import\s.*errorReporter/m)
    expect(src).not.toContain("from '@/utils/errorReporter'")
    expect(src).toContain('[vite] preview HTTPS 证书读取失败，仍以 HTTP 启动：')
  })
})
