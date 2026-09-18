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
    // P0-修复（2026-09-17）：原先写死 'Cache-Control': isDev ? 'no-store' : undefined。
    // resolveConfig 在 production 下把该对象合并进 preview.headers，键存在但值为
    // undefined，vite preview 的 send() 调用 res.setHeader('Cache-Control', undefined)
    // 抛 ERR_HTTP_INVALID_HEADER_VALUE → 全站 500（已实测复现）。
    // 条件展开保证该键只在开发态出现，生产态彻底不生成。
    ...(isDev ? { 'Cache-Control': 'no-store' } : {}),
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
  // 版本号单一事实来源：把 package.json 的 version 注入为编译期常量，
  // 供 AboutView 等展示使用。此前组件内手抄了一份字面量（与 package.json 各写一份），
  // 发版后页面会永久显示旧版本（潜伏型漂移，实测 2026-09-18）。
  const pkgVersion = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')
  ).version

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
    // 版本号单一事实来源（见上方 pkgVersion）：编译期常量替换，组件内不得再手抄
    define: {
      __APP_VERSION__: JSON.stringify(pkgVersion),
    },
    // vitest 配置（I-02 前端测试基线）：jsdom 提供 localStorage/document，
    // alias 与构建共用；PWA/安全头等插件仅服务 dev/build，测试不加载
    test: {
      environment: 'jsdom',
      include: ['src/tests/**/*.test.js'],
      globals: false,
      // 组件测试能力（2026-09-18）：.vue 单文件组件经 vue() 插件编译后，
      // 其 import 的 element-plus 组件会连带 `import '.../style/css'`，
      // 而 vitest 默认把 node_modules 依赖外部化给 Node 原生 ESM 加载，
      // Node 不认识 .css 扩展名，挂载即报「Unknown file extension ".css"」。
      // 把 element-plus 交给 Vite 管道内联处理后，CSS 由 Vite 正常吞掉，
      // 从而无需 @vue/test-utils 也能用 createApp 直接挂载视图组件做断言。
      // 这是测试期配置，不进入生产构建产物。
      server: { deps: { inline: ['element-plus'] } },
      // 单例默认超时 5s 在「并行子 agent + 多 worker 抢 CPU」时不够：
      // apiRequestPipeline.test.js 每个用例 vi.resetModules() 重建整个模块图
      // （api/router/store/i18n），冷启动开销叠加 CPU 竞争会偶发越过 5s，
      // 表现为「单跑全绿、全量偶红」的 flaky（实测：同一文件在无竞争时 57/57 绿，
      // 竞争时个别用例超时）。20s 仍能拦住真正的死循环/挂起——本仓最慢的
      // routeTable.test.js 单例约 12s（真实加载 13 个 .vue），远低于该值。
      testTimeout: 20000,
      hookTimeout: 20000,
      // 覆盖率（T-3）：v8 provider 生成可度量报告；reporter 输出终端摘要、lcov
      // （供 codecov 上传）与 json-summary（供 CI 阈值门禁读取）。
      coverage: {
        provider: 'v8',
        reporter: ['text', 'lcov', 'json-summary'],
        include: ['src/**/*.{js,vue}'],
        exclude: ['src/tests/**', 'src/main.js', 'src/**/*.d.ts'],
        // 硬门禁（T-3 棘轮基线）：贴着实测值逐步上调，具体数字见下方
        // thresholds。本注释**不记录实时快照**——原写的「实测 st 11.10 /
        // br 9.76 / fn 6.60 / ln 10.88」早已失实（报告 §10.5 漂移 #12）。
        // 视图组件暂未纳入组件级测试，故用**全局**阈值而非 perFile
        //（否则未测视图会整体红灯）。
        // 2026-09-18 两次收紧：
        //   第一次 10.5/8/5/10.5 → 19/17/11.5/18.5（原阈值只有当时实测的一半，
        //   与本仓后端曾修过的 P3-49 同病：删掉一半测试仍然全绿，等于没有门槛）。
        //   第二次 → 28.5/25.5/21.5/28：本轮补齐 InspectionView / InspectionForm /
        //   InspectionReviewForm 等组件级用例后实测跳到
        //   st 30.03 / br 27.06 / fn 23.34 / ln 29.7（两次运行一致，非抖动）。
        // 第三次 → 78/71.5/71/79：本轮补齐 AlarmView / DashboardView / AuditLogView /
        // AuditLogView / IpListView / ProfileView / SessionManager / PermissionModuleCard
        // 组件级用例后，实测跳到 st 79.92 / br 73.39 / fn 72.84 / ln 80.87
        // （全量 62 文件 / 806 通过 0 失败的一次运行结果）。
        // 第四次 → 92/84/90/93：本轮（2026-09-18 第二轮）新增
        // routeGuard / routeTable / dashboardCharts / app / localeKeyParity /
        // layout / SessionManager / MfaSettingsCard / InspectionView / InspectionForm /
        // AboutView / ReportView / apiRequestPipeline / i18nEntry / useRolePermissions
        // 等测试后，实测跳到 st 94.35 / br 86.38 / fn 92.99 / ln 95.46
        // （全量 84 文件 / 1215 例的一次运行结果）。
        // 仍取「实测下方约 2.4pt」留余量：只拦真实退化，不因 CI 环境抖动误伤。
        // 量化证明（第四次）：临时移出 4 个测试文件后跌至 st 88.1 / br 79.6 /
        // fn 86.4 / ln 89.1，exitCode=1 且 thresholdViolation=true —— 门槛确实在拦。
        // 历史：第一/二/三次收紧见上方注释（10.5 → 19 → 28.5 → 78）。
        thresholds: {
          statements: 92,
          branches: 84,
          functions: 90,
          lines: 93,
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
                return {
                  cert: fs.readFileSync(process.env.TLS_CERT_PATH || '../certs/server.crt'),
                  key: fs.readFileSync(process.env.TLS_KEY_PATH || '../certs/server.key'),
                }
              } catch (e) {
                // P1-18：preview HTTPS 证书读取失败会静默降级为 HTTP（降级本身是设计内的：
                // 证书可能尚未生成），但此前无任何可观测信号——外部访问者遇到的是 HTTP，
                // 而运维在终端里看不到任何提示。构建期配置无法接入应用层 errorReporter：
                // 后者依赖 import.meta.env 与 localStorage/location，Node 环境实测均不可用
                // （TypeError: Cannot read properties of undefined (reading VITE_ERROR_REPORT_URL)），
                // 强行引入只会让 vite 配置加载失败。故改用构建期 console.warn 留痕，
                // 与上方 dev 分支 :530 的既有做法保持一致。
                console.warn('[vite] preview HTTPS 证书读取失败，仍以 HTTP 启动：', e.message)
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
            // P2-52：原实现为 id.includes('node_modules/echarts') ||
            // id.includes('node_modules\\.pnpm\\echarts') —— 前者是无边界的子串匹配
            // （echarts-extra 这类包也会被拽进 echarts chunk，且反斜杠 id 匹配不上），
            // 后者（字符串值 'node_modules\\.pnpm\\echarts'）只对反斜杠 id 命中，
            // 而实测传入的 1277 个 id 全为正斜杠，故在本环境下从未生效（冗余分支）。
            // 另外注意：pnpm 路径末段仍含子串 node_modules/echarts，即便删除该分支
            // 也不会丢失 pnpm 布局的分组——真正的隐患是无边界子串会误伤
            // echarts-extra 这类包，且反斜杠 id 对两个 includes 都匹配不上。
            // 收敛为与下方 vue-vendor 同风格的分隔符无关正则：
            // 要求 node_modules/echarts/ 作为完整路径段出现。
            if (/[\\/]node_modules[\\/]echarts[\\/]/.test(id)) {
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
