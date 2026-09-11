# 多阶段构建
#
# R-5 基础镜像版本固定：
# 全部 node 阶段都必须钉到补丁号，不能只写 `node:22-alpine`。
# 浮动 tag 的后果不是「拿到新版本」而是「不同时间构建出不同的镜像」——
# 出安全问题时无法回答「上线那版用的是哪个 Node」。
#
# 生产建议进一步锁 digest（部署机捕获，不要手抄）：
#   docker pull node:22.14.0-alpine
#   docker inspect --format='{{index .RepoDigests 0}}' node:22.14.0-alpine
# 得到 `node:22.14.0-alpine@sha256:<值>` 后替换下面三处 FROM。
# 各阶段必须用同一个 digest，否则 builder 与 runtime 的 libc/OpenSSL
# 可能不同版本，原生模块在运行时才暴露不兼容。

# Builder 阶段
FROM node:22.14.0-alpine AS builder

WORKDIR /app

# 复制 package 文件
COPY package*.json ./

# 安装所有依赖（含 devDependencies，用于编译/测试）
RUN npm ci && npm cache clean --force

# 复制源代码（显式复制，避免依赖 .dockerignore 排除 .env）
COPY src/ ./src/
COPY package*.json ./

# 前端构建阶段（L-1）：产出 web-admin/dist，供后端 express 静态托管
# （或挂载给 Nginx 托管，二选一）。与后端同版本基础镜像，避免工具链漂移。
FROM node:22.14.0-alpine AS web-builder

WORKDIR /web
COPY web-admin/package*.json ./
RUN npm ci && npm cache clean --force

COPY web-admin/ ./
# vite.config.js 已显式 sourcemap: false（L-1/I-3），产物不含源码映射
RUN npm run build

# Runtime 阶段（版本须与 builder 完全一致，见顶部说明）
FROM node:22.14.0-alpine

WORKDIR /app

# 安装 dumb-init 处理信号 + tzdata 时区支持
RUN apk add --no-cache dumb-init tzdata

# 创建非 root 用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# 从 builder 阶段复制源代码
COPY --from=builder --chown=nodejs:nodejs /app/src ./src
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

# 前端构建产物（L-1 静态托管）：默认路径与 src/middleware/staticFrontend.js
# 的 resolveDistDir 一致（/app/web-admin/dist）。NODE_ENV=production 且产物
# 存在时自动启用；改用 Nginx 托管时在 compose 设 SERVE_FRONTEND=false
COPY --from=web-builder --chown=nodejs:nodejs /web/dist ./web-admin/dist

# 日志目录必须预建并归属 nodejs：
# src/utils/logger.js 在模块加载时同步执行 fs.mkdirSync('/app/logs')，
# 而 /app 由 root 以 755 创建，切到 USER nodejs 后该目录不可写 →
# 容器启动即 EACCES 崩溃、健康检查永远不过。
# auditBuffer 的 WAL 文件（logs/audit-buffer.wal）同样依赖此目录可写。
RUN mkdir -p /app/logs && chown -R nodejs:nodejs /app/logs

# 在 runtime 阶段单独安装生产依赖（不含 devDependencies），并将 node_modules 归属到非 root 用户
RUN npm ci --omit=dev && npm cache clean --force && \
    chown -R nodejs:nodejs node_modules

# 切换到非 root 用户
USER nodejs

# 暴露端口
EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "const http=require('http');const r=http.get('http://localhost:3000/health',res=>process.exit(res.statusCode===200?0:1));r.on('error',()=>process.exit(1));r.setTimeout(5000,()=>process.exit(1));"

# 使用 dumb-init 作为 PID 1
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/index.js"]
