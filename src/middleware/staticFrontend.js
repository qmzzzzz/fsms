/**
 * 生产前端静态托管（L-1 / I-3 闭环）
 *
 * 背景：此前生产环境没有任何前端托管落地——app.js 无 express.static，
 * Nginx 配置仅为示例。结果是要么前端只能跑 Vite dev server（对公网暴露
 * 完整源码与依赖图，含 /src/ 与 sourcemap），要么部署者自行拼凑托管，
 * 两条路都构成源码泄露面。
 *
 * 本模块提供后端自托管方案（与 deployment/nginx.conf.example 的 Nginx
 * 托管二选一）：直接服务 web-admin 的构建产物，含——
 *   - SPA history 模式回退（深链/刷新直达前端路由）
 *   - 内容哈希资源长缓存、index.html 与 sw.js 不缓存（发版即时生效）
 *   - 显式拒绝 .map 请求（构建已关 sourcemap，此为纵深拦截；
 *     判定按解码后路径 + 大小写归一，并覆盖 HEAD，见 isDeniedStaticPath）
 *
 * 仅在构建产物真实存在时启用；开发环境保持 Vite 工作流不受影响。
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const config = require('../config');
const { matchesAnyPathPrefix } = require('../utils/helpers');

/** 构建产物目录（容器内为 /app/web-admin/dist，可用 FRONTEND_DIST 覆盖） */
function resolveDistDir() {
  return config.frontend.distDir || path.join(__dirname, '..', '..', 'web-admin', 'dist');
}

/**
 * 是否启用静态托管（config.frontend.serve：'auto' | 'true' | 'false'）：
 * - false 强制关闭（纯 API 节点、或已用 Nginx 托管 dist）
 * - true 强制开启（产物不存在时挂载但请求会 404，启动日志告警）
 * - auto：仅当 NODE_ENV=production 且产物存在（以 index.html 为准）时启用。
 *   刻意不放宽到「一切非 development」：test/staging 环境下静默托管 SPA
 *   会把「未知路径 404」类测试与排查悄悄变成 index.html 200，症状极隐蔽；
 *   非 production 需要托管时请显式 SERVE_FRONTEND=true。
 */
function shouldServeFrontend(distDir = resolveDistDir()) {
  const mode = config.frontend.serve;
  if (mode === 'false') return false;
  if (mode === 'true') return true;
  // 与 config/validate.js 同一环境判据：字面量比较会让 NODE_ENV=prod 的部署
  // 通过硬闸启动（生产校验已 fail-closed），却在这里判定"不是生产"而拒绝托管前端。
  if (!require('../config/validate').requiresProductionSemantics()) return false;
  return fs.existsSync(path.join(distDir, 'index.html'));
}

/** 永不托管的路径前缀：命中即放行给 API/系统路由，不做静态解析 */
const RESERVED_PREFIXES = [
  '/api',
  '/health',
  '/readyz',
  '/metrics',
  '/socket.io',
  '/api-docs',
  '/csp-report',
  '/client-errors',
  '/.well-known',
];

/**
 * 「这一面归静态托管管吗」——**限流豁免判据的唯一事实来源**（2026-09-30）。
 *
 * 此前 rateLimit.js 自带一份判据（安全方法 + 非 `/api/` 前缀），与本文件的
 * RESERVED_PREFIXES 是**两份独立清单**，实测二者对 11 条非 /api 路径里有 8 条
 * 判定相反：
 *
 *   现判据豁免、而本模块并不托管的：/health /readyz /metrics /socket.io
 *                                  /api-docs /csp-report /client-errors /.well-known
 *
 * 其中 /health、/readyz 由 constants/probePaths 的 isProbeRequest 单独兜住，
 * /api-docs、/csp-report、/client-errors、/.well-known 各有专属限流器——
 * 但那都是**各自的补丁**，不是判据本身正确。真正裸奔的两条：
 *   - `/socket.io/`：Socket.IO 的 HTTP long-polling 握手是**未认证 GET**，
 *     而 websocketService 的 MAX_CONNECTIONS=1000 约束的是**已建立连接数**，
 *     不是握手速率 ⇒ 握手面在应用层没有任何限流（`new WebSocketService()` 只在
 *     连接**建立之后**才认证）；
 *   - `/metrics`：metricsAuth 允许内网/回环免令牌，而 app.js 自己写明这条端点的
 *     威胁模型正是「有人从容器网络直连 app:3000」⇒ 该情形下可无限抓取。
 *
 * 两份清单迟早有一份先忘——这与 constants/probePaths 的注释是同一条纪律，
 * 探针清单已经做了单一来源，静态面此前没做。现在由本函数收口：
 * 限流侧只读这一个判据，两侧漂移在结构上不可能发生。
 *
 * 注意方向：判据从「非 /api/ 即豁免」**收窄**为「本模块确实托管的才豁免」，
 * 即豁免集合变小、覆盖变大——新登记的保留前缀会自动重新纳入限流，
 * 而不需要改动限流侧任何代码。
 *
 * @param {import('express').Request} req
 * @returns {boolean} 该请求是否落在静态托管面（安全方法且非保留前缀）
 */
function isStaticSurfaceRequest(req) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  // 与 Express 默认路由同尺（大小写不敏感），否则 GET /API/x 会被判成静态面
  // 而实际落到 API 路由——两份判据不同尺比两份判据不同源更难查
  return !matchesAnyPathPrefix(RESERVED_PREFIXES, req.path);
}

/** 纵深拒绝下发的扩展名（构建已关 sourcemap，此处防配置漂移） */
const DENIED_STATIC_EXTS = ['.map', '.ts'];

/**
 * 判定必须建立在**解码后**的路径上：静态层解析文件前会先 decodeURIComponent
 * （node_modules/send/index.js:881），而 req.path 是未解码的原始段。
 * 两侧口径不一致时 `GET /assets/leak.js%2Emap` 会绕过 endsWith('.map') 被真实下发。
 * 非法百分号编码解码失败 → 按原始路径判定（静态层自己也会 404）。
 * 大小写一并归一：Windows 文件系统不区分大小写，`leak.js.MAP` 在本机可取到同一文件。
 */
function isDeniedStaticPath(rawPath) {
  let target = rawPath;
  try {
    target = decodeURIComponent(rawPath);
  } catch (_) {
    /* 非法编码：保持原始路径 */
  }
  const lower = target.toLowerCase();
  return DENIED_STATIC_EXTS.some((ext) => lower.endsWith(ext));
}

/**
 * 把静态托管挂到 app 上。返回是否启用（供启动日志/测试断言）。
 * 必须挂载在全部业务路由之后、404 兜底之前。
 */
function mountStaticFrontend(app, { logger } = {}) {
  const distDir = resolveDistDir();
  if (!shouldServeFrontend(distDir)) return false;

  const indexFile = path.join(distDir, 'index.html');
  if (!fs.existsSync(indexFile) && logger) {
    logger.warn(
      `SERVE_FRONTEND=true 但未找到构建产物（${indexFile}），前端请求将 404：请先执行 web-admin 构建`
    );
  }

  // 纵深：构建产物不得含 sourcemap；即使未来配置漂移产出 .map，也拒绝下发。
  // GET 与 HEAD 都要拦——HEAD 无响应体但回 200+Content-Length，足以探测产物存在性。
  app.use((req, res, next) => {
    if ((req.method === 'GET' || req.method === 'HEAD') && isDeniedStaticPath(req.path)) {
      return res.status(404).json({ success: false, message: '资源不存在' });
    }
    return next();
  });

  // 带内容哈希的构建资源：一年强缓存（文件名即指纹，内容变更即换 URL）
  app.use(
    '/assets',
    express.static(path.join(distDir, 'assets'), {
      maxAge: '1y',
      immutable: true,
      fallthrough: true,
    })
  );

  // 根目录静态资源（index.html/sw.js/图标等）：不缓存，保证发版与 SW 更新即时生效
  app.use(
    express.static(distDir, {
      index: 'index.html',
      etag: true,
      maxAge: 0,
      setHeaders: (res, filePath) => {
        if (filePath.endsWith('index.html') || filePath.endsWith('sw.js')) {
          res.setHeader('Cache-Control', 'no-cache');
        }
      },
    })
  );

  // SPA history 回退：非保留前缀、未命中静态文件、接受 HTML 的 GET 请求
  // 一律交回 index.html 由前端路由接管；其余（含 POST/非 HTML 请求）落到 404
  app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    // 保留前缀判定与路由同尺（Express 默认大小写不敏感）：否则 GET /API/不存在路径
    // 既进不了 API 路由的 404 JSON，又被这里当成普通前端路径 → 回退 200 SPA HTML
    if (matchesAnyPathPrefix(RESERVED_PREFIXES, req.path)) return next();
    const acceptsHtml = String(req.headers.accept || '').includes('text/html');
    if (!acceptsHtml) return next();
    // send 1.x 对「绝对路径、无 root」走 no-root 解析分支：把整条绝对路径切段做
    // dotfiles 判定（默认 'ignore'），部署目录链上任一段以"."开头（/srv/.releases/…、
    // Windows 的 %TEMP%\.zcode\…）就会对真实存在的 index.html 裸 404——实测
    // Windows 点段临时目录与 Linux 点段发布目录同病。root 模式只对「相对路径」
    // 判定，与 express.static 同形态，语义与原意图完全一致。
    return res.sendFile('index.html', { root: distDir });
  });

  if (logger) logger.info(`前端静态托管已启用：${distDir}`);
  return true;
}

module.exports = {
  mountStaticFrontend,
  shouldServeFrontend,
  resolveDistDir,
  isStaticSurfaceRequest,
  RESERVED_PREFIXES,
};
