import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import fs from 'node:fs'
import path from 'path'
import { fileURLToPath } from 'url'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { VitePWA } from 'vite-plugin-pwa'

// ESM 兼容：获取 __dirname
const __dirname = path.dirname(fileURLToPath(import.meta.url))

// ── Element Plus 深路径按需引入 ────────────────────────────────────────────
// 官方 ElementPlusResolver 的 from 硬编码为 'element-plus/es'（全量入口），
// 于是所有组件都从同一个聚合模块引入。rollup 的 chunk 分配以模块为单位，
// 只要有一个首屏组件引了它，整个模块里「所有被使用到的组件」都会进首屏。
// 实测 date-picker + time-picker 约 217KB（minify 前）就是这样被拖进首屏的，
// 尽管它们只被 4 个懒加载视图使用。改为按组件深路径引入后，chunk 才能按
// 组件粒度拆分。
//
// 注意不能简单地把组件名转 kebab 当目录：ElRadioButton 的代码在 radio/ 下、
// ElTableColumn 在 table/ 下、ElSubMenu 在 menu/ 下。因此这里解析各组件目录
// index.mjs 的真实 export 反查归属，可正确处理这类子组件。
// 未命中映射时回退为官方行为（'element-plus/es'），最坏情况仅是维持现状。
const buildElementPlusComponentMap = () => {
  const base = path.resolve(__dirname, 'node_modules/element-plus/es/components')
  const map = new Map()
  if (!fs.existsSync(base)) return map
  for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const file = path.join(base, entry.name, 'index.mjs')
    if (!fs.existsSync(file)) continue
    const src = fs.readFileSync(file, 'utf8')
    for (const m of src.matchAll(/export\s*\{([^}]*)\}/g)) {
      for (const part of m[1].split(',')) {
        const p = part.trim()
        if (!p) continue
        const as = p.match(/\s+as\s+(\S+)$/)
        const exported = as ? as[1] : p
        if (/^El[A-Z]/.test(exported) && !map.has(exported)) map.set(exported, entry.name)
      }
    }
    for (const m of src.matchAll(/export\s+(?:const|function|class)\s+(El[A-Z][A-Za-z0-9]*)/g)) {
      if (!map.has(m[1])) map.set(m[1], entry.name)
    }
  }
  return map
}

const elementPlusComponentResolver = () => {
  const map = buildElementPlusComponentMap()
  const kebab = (n) =>
    n
      .slice(2)
      .replace(/([a-z])([A-Z])/g, '$1-$2')
      .toLowerCase()
  return {
    type: 'component',
    resolve: (name) => {
      if (!/^El[A-Z]/.test(name)) return
      // <el-icon-xxx> 走图标库；<el-icon> 是容器组件，落在 components/icon
      if (/^ElIcon.+/.test(name)) {
        return { name: name.replace(/^ElIcon/, ''), from: '@element-plus/icons-vue' }
      }
      const dir = map.get(name)
      return {
        name,
        // 必须带 /index.mjs：element-plus 的 exports 规则是 "./es/*" → "./es/*.mjs"，
        // 裸路径 element-plus/es/components/xxx 会被解析成不存在的 xxx.mjs。
        from: dir ? `element-plus/es/components/${dir}/index.mjs` : 'element-plus/es',
        sideEffects: `element-plus/es/components/${kebab(name)}/style/css`,
      }
    },
  }
}

const elementPlusDirectiveResolver = () => {
  const directives = {
    Loading: { importName: 'ElLoadingDirective', dir: 'loading' },
    Popover: { importName: 'ElPopoverDirective', dir: 'popover' },
  }
  return {
    type: 'directive',
    resolve: (name) => {
      const d = directives[name]
      if (!d) return
      return {
        name: d.importName,
        from: `element-plus/es/components/${d.dir}/index.mjs`,
        sideEffects: `element-plus/es/components/${d.dir}/style/css`,
      }
    },
  }
}

// 安全响应头
const buildSecurityHeaders = (mode) => {
  const isDev = mode === 'development'
  // 开发模式需 'unsafe-eval'：vue-i18n 完整构建内置消息编译器，运行时用 new Function()
  // 编译翻译文案，缺 'unsafe-eval' 会被 CSP 拦截（浏览器报 "blocks the use of 'eval'"）
  // 生产构建保持严格 'self'；若生产出现同类拦截，正解是引入 @intlify/unplugin-vue-i18n
  // 做预编译，而不是放宽线上 CSP
  const scriptSrc = isDev ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'" : "script-src 'self'"
  // ← 修改：开发模式放宽 connect-src 协议限制，兼容局域网/热点 IP 访问时的 HMR WebSocket
  // L8：生产 connect-src 仅保留 'self'（API/WS 均经同域 Nginx 代理），
  // 移除部署后不存在的 localhost 遗留项
  const connectSrc = isDev ? "connect-src 'self' ws: wss: http: https:" : "connect-src 'self'"
  return {
    // 开发模块使用 ETag/304 时，损坏的浏览器磁盘缓存会表现为 ERR_CACHE_READ_FAILURE。
    // 开发期禁用 HTTP 缓存可强制每次重新读取源文件和依赖产物。
    'Cache-Control': isDev ? 'no-store' : undefined,
    'Content-Security-Policy': [
      "default-src 'self'",
      scriptSrc,
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "img-src 'self' data: blob:",
      "font-src 'self' data: https://fonts.gstatic.com",
      connectSrc,
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'self'",
      "form-action 'self'",
    ].join('; '),
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy':
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
    // L8：X-XSS-Protection 已废弃（现代浏览器忽略且历史版本可被绕过），移除；
    // XSS 防护由 CSP + 框架默认转义承担
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Frame-Options': 'SAMEORIGIN',
  }
}

// 开发服务器敏感文件拦截
//
// 渗透测试发现的绕过面与对应防护：
//  1. /@fs/D:/... 绝对路径直读绕过 URL 前缀黑名单 → 由下方 server.fs.deny
//     （Vite 内建机制，对 /@fs/ 与模块解析同样生效）+ 插件解码归一化双重拦截；
//  2. %252e/%3A%3A%24DATA 等编码与 NTFS ADS 变体 → 解码两轮后按小写匹配，
//     并显式拦截 ":$DATA" 形态；
//  3. Windows 尾点/尾空格（".env." / ".env "）→ 每段剥离尾部点与空格再匹配。
const SENSITIVE_FILE_PATTERNS = [
  /\.env/i,
  /package(-lock)?\.json$/i,
  /pnpm-lock\.yaml$/i,
  /(^|\/)\.git(\/|$)/i,
  /(^|\/)(vite|postcss)\.config\.(js|ts|mjs|cjs)$/i,
  /\.npmrc$/i,
  /\.(pem|key|crt|pfx)$/i,
]

// 归一化：解码两轮（防双重编码）→ 去查询串 → 按段剥 Windows 尾点尾空格 → 小写
const normalizeUrlPath = (rawUrl) => {
  let u = rawUrl || ''
  for (let i = 0; i < 2; i++) {
    try {
      u = decodeURIComponent(u)
    } catch (_) {
      break
    }
  }
  u = u.split('?')[0]
  return u
    .split('/')
    .map((seg) => seg.replace(/[. ]+$/, ''))
    .join('/')
    .toLowerCase()
}

const isSensitivePath = (normalized) =>
  normalized.includes(':$data') || SENSITIVE_FILE_PATTERNS.some((re) => re.test(normalized))

const isLoopbackReq = (req) => {
  const addr = req.socket?.remoteAddress || ''
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1'
}

// /__open-in-editor 判定必须与 connect 的挂载匹配逻辑对齐：
// connect 对 use("/__open-in-editor", fn) 做前缀匹配，且要求挂载点后一位字符是
// "/" 或 "."（或路径恰好在挂载点结束），大小写不敏感。因此
// /__open-in-editor/xxx、/__open-in-editor.xyz 都会路由到 launch-editor 中间件，
// 而此前用严格相等（path === '/__open-in-editor'）判断，这些变体全部绕过拦截
const isEditorEndpoint = (path) => {
  const route = '/__open-in-editor'
  return path === route || path.startsWith(`${route}/`) || path.startsWith(`${route}.`)
}

const blockSensitiveFilesPlugin = () => ({
  name: 'block-sensitive-files',
  configureServer(server) {
    // 归一化后的 Vite root（小写、正斜杠、去尾斜杠），用于 /@fs/ 越界判断
    const rootNorm = server.config.root.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()

    // 前置阶段：先于 Vite 内部中间件执行，命中即短路
    server.middlewares.use((req, res, next) => {
      const raw = req.url || ''
      const decoded = normalizeUrlPath(raw)

      // 敏感文件：原始串与解码串任一命中即拦（/@fs/ 绝对路径同样会经过本判断）
      if (isSensitivePath(raw.toLowerCase()) || isSensitivePath(decoded)) {
        res.statusCode = 404
        res.setHeader('Content-Type', 'text/plain')
        res.end('Not Found')
        return
      }

      // /@fs/ 越界直读：绝对路径不在 Vite root（web-admin）内时直接 404。
      // 不透传给 Vite 内部处理——其 403 Restricted 页会把请求的磁盘绝对路径
      // 与 allow list 原样回显到响应体（渗透测试已验证），构成路径结构泄露
      if (decoded.startsWith('/@fs/')) {
        const fsPath = decoded.slice('/@fs/'.length).replace(/\\/g, '/')
        if (!fsPath.startsWith(rootNorm + '/')) {
          res.statusCode = 404
          res.setHeader('Content-Type', 'text/plain')
          res.end('Not Found')
          return
        }
      }

      // /__open-in-editor（launch-editor）：仅允许本机回环调用——
      // 该端点会在运行 Vite 的机器上用默认编辑器打开任意文件，
      // 局域网可达时构成"任意文件打开"原语；远程一律 404
      // 路径匹配用 isEditorEndpoint（对齐 connect 前缀匹配语义），
      // decoded 已做两轮解码 + 小写化，编码变体与大小写变体均被覆盖
      const pathOnly = decoded.split('?')[0]
      if (isEditorEndpoint(pathOnly) && !isLoopbackReq(req)) {
        res.statusCode = 404
        res.setHeader('Content-Type', 'text/plain')
        res.end('Not Found')
        return
      }

      next()
    })

    // 后置阶段错误脱敏：Vite 对 transform 异常的兜底 500 会在响应体携带
    // 完整堆栈与磁盘绝对路径（渗透测试已验证）。
    // 注意必须通过 configureServer 的返回函数注册——它在 Vite 内部中间件
    // 安装完毕后才执行；connect 的错误传播是"从出错中间件向后找第一个
    // 错误中间件"，transform 出错调 next(err) 时前置注册的错误中间件
    // 位于其之前、永远收不到（该缺陷已被实测复现：堆栈仍泄露）。
    // 后置注册后本中间件先于 Vite 自带 errorMiddleware 响应，
    // 网络侧只收到无信息量的固定文案；完整堆栈仍打印到开发者终端
    return () => {
      server.middlewares.use((err, _req, res, _next) => {
        try {
          server.config.logger.error(err?.stack || String(err))
        } catch (_) {}
        res.statusCode = 500
        res.setHeader('Content-Type', 'text/plain; charset=utf-8')
        res.end('Internal Server Error')
      })
    }
  },
})

// HMR WebSocket 崩溃防护（报告项 5：单个畸形请求可击杀 dev server，且无自动重启）
//
// 触发向量说明：崩溃已实际发生（外部渗透报告确认），但静态分析未能唯一定位——
// 常见可疑字符（^ | < > { } 等）实测均可被 new URL() 正常解析，不构成向量。
// 候选面包括：upgrade 监听器内的同步异常、插件自定义事件处理器对恶意
// WebSocket payload 的未捕获抛错（emitCustomEvent 无异常隔离）、
// 以及异常路径上的异步 rejection。故按「异常来源」而非「单一向量」做全谱覆盖。
//
// 三层防护（纵深，互为兜底）：
//   L1  upgrade 监听器整体包裹 try/catch —— 拦截握手阶段任何同步抛错，
//       销毁攻击 socket，其余连接与服务不受影响
//   L2  HMR socket 的 message/close 处理器包裹 —— 拦截 Vite 插件自定义事件
//       处理器对恶意 payload 抛错（emitCustomEvent 无异常隔离）
//   L3  进程级 uncaughtException/unhandledRejection 兜底（见 registerProcessGuard）
const hardenDevServerPlugin = () => ({
  name: 'harden-dev-server',
  configureServer(server) {
    // L2：socket 处理器隔离。
    // 此刻 Vite 的 connection 监听器已注册（ws server 在 configureServer 前创建），
    // 本监听器在其后触发，可以把 Vite 挂到 socket 上的 message/close 处理器
    // 替换为带异常隔离的包装版本
    const guardSocketHandler =
      (evt, fn) =>
      (...args) => {
        try {
          const result = fn(...args)
          if (result && typeof result.catch === 'function') {
            result.catch((e) => {
              server.config.logger.error(
                `[ws-guard] HMR socket ${evt} 异步处理异常已拦截：${e?.message || e}`
              )
            })
          }
        } catch (e) {
          server.config.logger.error(
            `[ws-guard] HMR socket ${evt} 处理异常已拦截：${e?.message || e}`
          )
        }
      }

    server.ws.on('connection', (socket) => {
      for (const evt of ['message', 'close']) {
        const handlers = socket.listeners(evt)
        if (!handlers.length) continue
        socket.removeAllListeners(evt)
        for (const fn of handlers) {
          socket.on(evt, guardSocketHandler(evt, fn))
        }
      }
    })

    // L1：upgrade 监听器包裹。
    // 必须在后置钩子做——此时 Vite 内部中间件已安装完毕，HMR 与 ws 代理的
    // upgrade 监听器都已注册，才能一次性全部包裹
    return () => {
      const httpServer = server.httpServer
      if (!httpServer) return

      const upgradeHandlers = httpServer.listeners('upgrade')
      if (!upgradeHandlers.length) return

      httpServer.removeAllListeners('upgrade')
      for (const fn of upgradeHandlers) {
        httpServer.on('upgrade', (req, socket, head) => {
          try {
            fn(req, socket, head)
          } catch (err) {
            server.config.logger.error(
              `[ws-guard] WebSocket 升级处理异常已拦截（进程保持运行）：${err?.message || err}`
            )
            // 抛错发生在握手完成前，socket 上没有 ws 的错误处理器，
            // 必须显式销毁，否则连接悬挂占用资源
            socket.destroy()
          }
        })
      }
    }
  },

  // preview 模式复用同样的 upgrade 包裹（vite preview 的 command 同为 'serve'，
  // 但不走 configureServer 钩子；preview 无 HMR，仅存在 ws 代理面）
  configurePreviewServer(server) {
    return () => {
      const httpServer = server.httpServer
      if (!httpServer) return

      const upgradeHandlers = httpServer.listeners('upgrade')
      if (!upgradeHandlers.length) return

      httpServer.removeAllListeners('upgrade')
      for (const fn of upgradeHandlers) {
        httpServer.on('upgrade', (req, socket, head) => {
          try {
            fn(req, socket, head)
          } catch (err) {
            server.config.logger.error(
              `[ws-guard] WebSocket 升级处理异常已拦截（进程保持运行）：${err?.message || err}`
            )
            socket.destroy()
          }
        })
      }
    }
  },
})

// L3：进程级兜底守卫（报告项 5 的"无自动重启"根治——不让进程死，比重启更优）。
// 仅在 dev/preview serve 场景注册：build 无长驻进程；vitest 会设置 VITEST 环境变量，
// 若在 vitest 进程内吞掉未捕获异常，会把测试运行器自身的失败报告机制打穿。
// 代价说明：吞掉 uncaughtException 后进程可能处于未定义状态，对长驻生产服务不可接受；
// dev server 属开发者本机短生命周期进程，可用性优先于严格性
const registerProcessGuard = (command) => {
  if (command !== 'serve' || process.env.VITEST) return

  const guardSeen = new Map()
  const logGuarded = (kind, err) => {
    // 同签名 10 秒去重：畸形请求可被高频重放，无去重会刷爆终端
    const sig = `${kind}:${err?.message ?? String(err)}`
    const now = Date.now()
    if (now - (guardSeen.get(sig) || 0) < 10000) return
    guardSeen.set(sig, now)
    console.error(`[vite-guard] 已拦截 ${kind}，dev server 保持运行：\n${err?.stack || err}`)
  }
  process.on('uncaughtException', (err) => logGuarded('uncaughtException', err))
  process.on('unhandledRejection', (err) => logGuarded('unhandledRejection', err))
}

export default defineConfig(({ command, mode }) => {
  // L1/L2 见 hardenDevServerPlugin；此处注册 L3 进程级兜底
  registerProcessGuard(command)

  // WB-2：VITE_WS_URL 是「开发期绕过 vite 代理直连后端」的覆盖项
  // （见 src/utils/websocket.js）。生产必须走同源反代（/socket.io/ 由
  // nginx/后端代理），若该变量泄漏进生产构建，WebSocket 会连向开发/内部地址，
  // 属配置事故——构建期硬门禁直接失败，比运行期静默错连安全。
  if (command === 'build' && !process.env.VITEST) {
    const buildEnv = loadEnv(mode, process.cwd(), 'VITE_')
    if (buildEnv.VITE_WS_URL) {
      throw new Error(
        `WB-2：检测到 VITE_WS_URL=${buildEnv.VITE_WS_URL}。` +
          '该变量仅限开发调试，生产构建不允许携带；请从 .env / 构建环境移除后重试。'
      )
    }
  }

  return {
    // vitest 配置（I-02 前端测试基线）：jsdom 提供 localStorage/document，
    // alias 与构建共用；PWA/安全头等插件仅服务 dev/build，测试不加载
    test: {
      environment: 'jsdom',
      include: ['src/tests/**/*.test.js'],
      globals: false,
      // 覆盖率（T-3）：v8 provider 生成可度量报告；reporter 输出终端摘要、lcov
      // （供 codecov 上传）与 json-summary（供 CI 阈值门禁读取）。
      coverage: {
        provider: 'v8',
        reporter: ['text', 'lcov', 'json-summary'],
        include: ['src/**/*.{js,vue}'],
        exclude: ['src/tests/**', 'src/main.js', 'src/**/*.d.ts'],
        // 硬门禁（T-3 棘轮基线）：贴着实测值（st 10.79 / br 9.38 / fn 6.35 /
        // ln 10.53）下方一档，防覆盖率退化。视图组件暂未纳入组件级测试，
        // 故用**全局**阈值而非 perFile（否则未测视图会整体红灯）。
        thresholds: {
          statements: 10,
          branches: 8,
          functions: 5,
          lines: 10,
        },
      },
    },
    plugins: [
      blockSensitiveFilesPlugin(),
      hardenDevServerPlugin(),
      vue(),
      AutoImport({
        imports: ['vue', 'vue-router', 'pinia'],
        // Element Plus 按需：命令式 API 自动导入，样式按组件加载（默认 importStyle: 'css'）
        resolvers: [elementPlusComponentResolver(), elementPlusDirectiveResolver()],
        dts: 'src/auto-imports.d.ts',
      }),
      Components({
        // Element Plus 组件/指令（如 v-loading）自动注册，样式按组件加载（默认 importStyle: 'css'）
        resolvers: [elementPlusComponentResolver(), elementPlusDirectiveResolver()],
        dts: 'src/components.d.ts',
      }),
      VitePWA({
        registerType: 'autoUpdate',
        // favicon.svg 与 manifest.webmanifest 已由下方 globPatterns 覆盖；
        // includeAssets 重复添加会导致生成的 SW 预缓存列表冲突。
        includeAssets: [],
        manifest: {
          name: '消防安全管理系统',
          short_name: '消防管理',
          description: '消防设备巡检、报警处理、安全管理系统',
          theme_color: '#c1121f',
          background_color: '#0a0f1a',
          display: 'standalone',
          start_url: '/',
          scope: '/',
          orientation: 'portrait-primary',
          icons: [
            { src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' },
          ],
        },
        workbox: {
          globPatterns: ['**/*.{js,css,html,svg,png,ico,woff2,webmanifest}'],
          // 仅缓存静态资源：/api 响应含用户、角色、审计等敏感数据，
          // 写入 Cache Storage 后可被 DevTools 读取且登出后仍驻留，故不做运行时缓存
          runtimeCaching: [
            {
              urlPattern: /^https:\/\/fonts\.googleapis\.com\/.*/i,
              handler: 'CacheFirst',
              options: {
                cacheName: 'google-fonts-cache',
                expiration: { maxEntries: 10, maxAgeSeconds: 60 * 60 * 24 * 365 },
              },
            },
          ],
        },
      }),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
      },
    },
    css: {
      postcss: './postcss.config.js',
    },
    server: {
      host: '0.0.0.0', // ← 修改：允许局域网/热点设备访问
      port: 3001,
      // 收紧 dev server CORS（回应外部报告 #2）：Vite 默认用宽松正则反射任意
      // localhost 系 Origin（含 *.localhost 子域），显式收敛为开发白名单。
      // 同源访问（含局域网 IP 直连本页面加载模块/HMR）不经 CORS 校验，不受影响；
      // preview 未单独配置时继承此处的 server.cors
      cors: {
        origin: ['http://localhost:3001', 'http://127.0.0.1:3001'],
      },
      headers: buildSecurityHeaders(mode),
      // Vite 内建文件服务黑名单：对 /@fs/ 绝对路径、模块解析与 ?raw 直读同样生效，
      // 是自定义插件之外的第二道闸（插件负责 URL 层拦截，这里负责文件系统层兜底）
      fs: {
        strict: true,
        deny: [
          '**/.env*',
          '**/*.pem',
          '**/*.{key,crt,pfx}',
          '**/package-lock.json',
          '**/pnpm-lock.yaml',
          '**/.git/**',
          '**/.npmrc',
        ],
      },
      ...(process.env.HTTPS === 'true'
        ? {
            https: (() => {
              try {
                const fs = require('fs')
                return {
                  cert: fs.readFileSync(process.env.TLS_CERT_PATH || '../certs/server.crt'),
                  key: fs.readFileSync(process.env.TLS_KEY_PATH || '../certs/server.key'),
                }
              } catch (e) {
                console.warn('[vite] HTTPS 证书读取失败，仍以 HTTP 启动：', e.message)
                return undefined
              }
            })(),
          }
        : {}),
      proxy: {
        '/api': {
          target: 'http://localhost:3000',
          changeOrigin: true,
          // http-proxy 默认不设置 X-Forwarded-For，需手动透传浏览器侧真实地址，
          // 否则后端（已开启 trust proxy）只能取到代理回环地址 ::1/127.0.0.1
          configure: (proxy) => {
            proxy.on('proxyReq', (proxyReq, req) => {
              const clientIp = req.socket.remoteAddress
              if (clientIp) proxyReq.setHeader('x-forwarded-for', clientIp)
            })
          },
        },
        // 前端异常上报（G-1）：与 /api 同样代理到后端根路径端点
        '/client-errors': {
          target: 'http://localhost:3000',
          changeOrigin: true,
        },
        '/socket.io/': {
          target: 'http://localhost:3000',
          ws: true,
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on('proxyReqWs', (proxyReq, req) => {
              const clientIp = req.socket.remoteAddress
              if (clientIp) proxyReq.setHeader('x-forwarded-for', clientIp)
            })
          },
        },
      },
    },
    preview: {
      host: '0.0.0.0', // ← 修改：preview 模式同样允许外部访问
      port: 3001,
      headers: buildSecurityHeaders(mode),
      fs: {
        strict: true,
        deny: ['**/.env*', '**/*.pem', '**/*.{key,crt,pfx}', '**/package-lock.json', '**/.git/**'],
      },
      ...(process.env.HTTPS === 'true'
        ? {
            https: (() => {
              try {
                const fs = require('fs')
                return {
                  cert: fs.readFileSync(process.env.TLS_CERT_PATH || '../certs/server.crt'),
                  key: fs.readFileSync(process.env.TLS_KEY_PATH || '../certs/server.key'),
                }
              } catch (e) {
                return undefined
              }
            })(),
          }
        : {}),
    },
    build: {
      // 目标浏览器版本：项目已广泛使用 backdrop-filter 等现代特性，
      // es2015 会产出大量无用降级语法，提高到 es2020 可减小产物、降低解析成本
      target: 'es2020',
      // 【L-1/I-3】生产产物禁止携带 sourcemap：.map 可完整还原源码与依赖结构。
      // Vite 默认即 false，此处显式声明防止后续误开；后端静态托管层另对 .map
      // 请求做了纵深拦截（src/middleware/staticFrontend.js）
      sourcemap: false,
      // Vite 8 的 Lightning CSS 压缩器会在部分动态 chunk 中把标准 backdrop-filter
      // 当作可省略前缀，导致 Firefox 失效。这里保留双写属性，交由 gzip 压缩。
      cssMinify: false,
      cssTarget: ['chrome80', 'edge80', 'firefox103', 'safari14'],
      // chunk 大小警告阈值（下调以便及时发现体积回退）
      chunkSizeWarningLimit: 1000,
      rollupOptions: {
        output: {
          manualChunks: (id) => {
            // 注意：此处曾无条件把 node_modules/element-plus 全部合并为一个 chunk。
            // 该规则会覆盖路由懒加载——只被异步视图使用的组件同样被拽进首屏。
            // 实测 date-picker + time-picker 约 215KB（minify 前，占 element-plus 本体 23%）
            // 仅被 InspectionForm / AuditLogView / DeviceView / ReportView 四个懒加载
            // 入口使用，首屏 Dashboard 完全不需要。改由 rollup 按依赖图自动分配：
            // 首屏组件留在主 chunk，仅被异步入口引用的组件落入对应的异步 chunk。
            if (
              id.includes('node_modules/echarts') ||
              id.includes('node_modules\\.pnpm\\echarts')
            ) {
              return 'echarts'
            }
            if (/[\\/]node_modules[\\/](@?vue|vue-router|pinia)[\\/]/.test(id)) {
              return 'vue-vendor'
            }
          },
        },
      },
    },
  }
})
