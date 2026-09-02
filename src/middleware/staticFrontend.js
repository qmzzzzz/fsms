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
 *   - 显式拒绝 .map 请求（构建已关 sourcemap，此为纵深拦截）
 *
 * 仅在构建产物真实存在时启用；开发环境保持 Vite 工作流不受影响。
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const config = require('../config');

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
  if (process.env.NODE_ENV !== 'production') return false;
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

  // 纵深：构建产物不得含 sourcemap；即使未来配置漂移产出 .map，也拒绝下发
  app.use((req, res, next) => {
    if (req.method === 'GET' && (req.path.endsWith('.map') || req.path.endsWith('.ts'))) {
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
    if (RESERVED_PREFIXES.some((p) => req.path === p || req.path.startsWith(p + '/')))
      return next();
    const acceptsHtml = String(req.headers.accept || '').includes('text/html');
    if (!acceptsHtml) return next();
    return res.sendFile(indexFile);
  });

  if (logger) logger.info(`前端静态托管已启用：${distDir}`);
  return true;
}

module.exports = { mountStaticFrontend, shouldServeFrontend, resolveDistDir };
