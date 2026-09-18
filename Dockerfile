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
# D-3：迁移文件随镜像分发。原镜像不含 migrations/ 与 migrate-mongo-config.js，
# 而 migrations/README.md 与 deployment/rollback-drill.md 都要求在部署环境执行
# `npm run migrate:up`——在只拉了镜像、没有仓库源码的部署机上，该命令**无一条可执行**。
# 迁移必须与它要变更的代码同版本（迁移描述的是这份 schema 的演进），
# 因此与 src/ 同源打进镜像，而不是让部署机另配一份源码。
COPY migrations/ ./migrations/
COPY migrate-mongo-config.js ./
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

# ===== 构建元数据（D-2）=====
# 为什么需要：镜像推到 registry 后，tag 可以被覆盖、也可以被人为改指。
# 线上出问题时第一个要回答的问题是「这版到底是哪个 commit 构建的」，
# 没有这些标签就只能靠翻 CI 日志反推，而 CI 日志有保留期。
# OCI 标准注解（org.opencontainers.image.*）能被 docker inspect、
# registry API、以及各类制品扫描器直接读取，属于「跟着镜像走」的元数据。
#
# 通过 --build-arg 注入（CI 在 build-push-action 里传，见 .github/workflows/ci.yml）。
# 默认值 unknown 是刻意的：本地 `docker build .` 不传时能一眼看出「不是 CI 产物」，
# 而不是伪装成某个版本。
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG APP_VERSION=unknown
LABEL org.opencontainers.image.revision=$GIT_SHA \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.version=$APP_VERSION \
      org.opencontainers.image.title="fire-safety-rbac-system" \
      org.opencontainers.image.source="https://github.com/qmzzzzz/fsms"

WORKDIR /app

# 安装 dumb-init 处理信号 + tzdata 时区支持
RUN apk add --no-cache dumb-init tzdata

# 创建非 root 用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# 从 builder 阶段复制源代码
COPY --from=builder --chown=nodejs:nodejs /app/src ./src
# D-3：迁移目录与配置（见 builder 阶段说明）
COPY --from=builder --chown=nodejs:nodejs /app/migrations ./migrations
COPY --from=builder --chown=nodejs:nodejs /app/migrate-mongo-config.js ./
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
RUN npm ci --omit=dev && npm cache clean --force

# ===== D-3：迁移执行器 =====
# migrate-mongo 在 package.json 里是 devDependency，上面 `--omit=dev` 会把它排除，
# 于是镜像里即便带了 migrations/ 也**没有执行迁移的工具**——
# `npm run migrate:up` 在纯镜像部署机上依然不可用（文档承诺与镜像能力不一致）。
#
# 这里显式补装，且**版本号从 package.json 的 devDependencies 读取**：
# 在 Dockerfile 里再手抄一个版本号会形成第二个事实来源，
# 升级依赖时漏改一处就变成「迁移用 A 版、开发用 B 版」。
#
# 为何用 --no-save 而不是把 migrate-mongo 移进 dependencies：
#   - 迁移器是**部署期工具**，不是应用运行期依赖，放进 dependencies
#     会让每次 npm ci 都为它解析依赖树、也扩大了生产依赖的安全扫描面；
#   - --no-save 不改动 package.json / package-lock.json，
#     依赖声明保持原样，需要撤销时只改本文件。
# 代价：补装不走 lockfile 的完整性校验（npm 仍会校验 registry 的 integrity），
# 版本上界由 package.json 的 `^` 约束决定，与开发环境同源。
RUN MIGRATE_MONGO_VERSION="$(node -p "require('./package.json').devDependencies['migrate-mongo']" | sed 's/[^0-9.]//g')" && \
    echo "migrate-mongo 版本（读自 package.json）: $MIGRATE_MONGO_VERSION" && \
    npm i --no-save --no-package-lock --omit=dev "migrate-mongo@$MIGRATE_MONGO_VERSION" && \
    npm cache clean --force && \
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
