/**
 * 子路径部署 / 监听面 / 外部字体依赖的配置契约
 *
 * 这些缺陷在生产部署后才暴露，单元测试难以从行为侧复现，故直接对构建配置
 * 与入口文件做契约断言：
 *  - PWA manifest 的 start_url/scope/icon 若为根绝对路径，/admin/ 部署后
 *    安装的应用会跳到站点根（空白页）；
 *  - dev/preview 绑定 0.0.0.0 会把带 HMR 与源码映射的服务暴露到局域网；
 *  - Google Fonts 属于第三方阻塞依赖，内网/离线部署会挂起首屏渲染，
 *    且与 CSP 的 font-src/style-src 'self' 冲突。
 */
import { describe, test, expect, beforeAll } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import config from '../../../vite.config.js'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8')

let resolved
let csp

beforeAll(async () => {
  resolved = await config({ command: 'build', mode: 'production' })
  csp = resolved.server.headers['Content-Security-Policy']
})

describe('PWA manifest 子路径安全', () => {
  test('start_url / scope / icon 为相对地址，不锚定站点根', () => {
    const src = read('vite.config.js')
    // 防退化：改回 '/' → /admin/ 部署下安装后打开站点根而非应用
    expect(src).toContain("start_url: '.'")
    expect(src).toContain("scope: '.'")
    expect(src).toContain("src: 'favicon.svg'")
  })

  test('入口 HTML 的资源引用走 %BASE_URL%，且不手写 manifest 链接', () => {
    const html = read('index.html')
    expect(html).toContain('href="%BASE_URL%favicon.svg"')
    expect(html).toContain('src="%BASE_URL%theme-bootstrap.js"')
    // manifest 由 vite-plugin-pwa 按 base 注入；手写会产出两份且路径不受 base 控制
    expect(html).not.toContain('rel="manifest"')
  })
})

describe('开发/预览服务器监听面', () => {
  test('默认只绑定回环地址（显式 --host 才对外）', () => {
    expect(resolved.server.host).toBe('127.0.0.1')
    expect(resolved.preview.host).toBe('127.0.0.1')
  })

  test('生产 CSP 不依赖第三方字体域，字体仅允许 self/data', () => {
    expect(csp).toContain("font-src 'self' data:")
    expect(csp).not.toContain('fonts.googleapis.com')
    expect(csp).not.toContain('fonts.gstatic.com')
  })

  test('样式与入口不再引用 Google Fonts（离线/内网可用）', () => {
    expect(read('src/assets/styles/global.css')).not.toContain('fonts.googleapis.com')
    expect(read('index.html')).not.toContain('fonts.googleapis.com')
  })
})
