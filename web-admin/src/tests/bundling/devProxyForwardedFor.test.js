/**
 * dev 代理的 X-Forwarded-For 透传契约
 *
 * 背景（2026-10-28 实测）：预览网关/外层反代已把真实客户端 IP 写进 XFF，但
 * vite dev 代理原先无条件用 `req.socket.remoteAddress` 覆盖该头——外层代理连
 * Vite 的对端是回环地址，于是后端（trust proxy）与审计记录的 IP 恒为
 * 127.0.0.1，真实地址被抹掉。
 *
 * 契约：**有上游 XFF 就透传，缺失才回落 socket 对端**。三个代理块
 * （/api、/client-errors、/socket.io/）必须一致，否则「登录有真实 IP、异常上报
 * 没有」这类半修状态无法被察觉。
 */
import { describe, test, expect, beforeAll } from 'vitest'
import config from '../../../vite.config.js'

const PROXY_PATHS = ['/api', '/client-errors', '/socket.io/']

let resolved

beforeAll(async () => {
  resolved = await config({ command: 'serve', mode: 'development' })
})

/** 触发某个代理块的 configure，返回它实际写入的 XFF 值 */
const forwardedForWrittenBy = (proxyPath, req) => {
  const entry = resolved.server.proxy[proxyPath]
  expect(entry, `${proxyPath} 代理块必须存在`).toBeTruthy()

  const handlers = []
  const fakeProxy = {
    on: (event, handler) => {
      handlers.push({ event, handler })
    },
  }
  entry.configure(fakeProxy)

  const written = {}
  const fakeProxyReq = { setHeader: (name, value) => (written[name] = value) }
  for (const { handler } of handlers) handler(fakeProxyReq, req)
  return written['x-forwarded-for']
}

const reqWith = (headers, remoteAddress = '127.0.0.1') => ({ headers, socket: { remoteAddress } })

describe('dev 代理 X-Forwarded-For 透传', () => {
  for (const proxyPath of PROXY_PATHS) {
    describe(proxyPath, () => {
      test('上游已带 XFF 时原样透传（不覆盖成回环地址）', () => {
        const req = reqWith({ 'x-forwarded-for': '203.0.113.9' })
        expect(forwardedForWrittenBy(proxyPath, req)).toBe('203.0.113.9')
      })

      test('多值/数组形态拼接后透传', () => {
        const req = reqWith({ 'x-forwarded-for': ['203.0.113.9', '198.51.100.7'] })
        expect(forwardedForWrittenBy(proxyPath, req)).toBe('203.0.113.9, 198.51.100.7')
      })

      test('无上游 XFF 时回落 socket 对端（本地直连调试行为不变）', () => {
        const req = reqWith({}, '192.0.2.44')
        expect(forwardedForWrittenBy(proxyPath, req)).toBe('192.0.2.44')
      })
    })
  }
})
