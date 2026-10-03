# 多阶段构建
#
# R-5 基础镜像版本固定：
# 全部 node 阶段都必须钉到补丁号，不能只写 `node:22-alpine`。
# 浮动 tag 的后果不是「拿到新版本」而是「不同时间构建出不同的镜像」——
# 出安全问题时无法回答「上线那版用的是哪个 Node」。
#
# 已钉 digest（捕获日期 2026-10-01，来源与核验方式见下）：
# 下面三处 FROM 钉在同一 manifest list digest 上：
#   node:22.14.0-alpine@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944
# digest 是多架构 OCI image index（含 linux/amd64 与 linux/arm64 等平台条目）。
# 来源：Docker Hub 官方 tag API（hub.docker.com/v2/...）在捕获当日于本网络不可达
# （DNS 污染），改用两条相互独立的 registry 通道核验并要求逐字节一致：
#   a) docker.m.daocloud.io（Docker Hub 的 pull-through 镜像）按 tag 取 manifest，
#      Docker-Content-Digest = 上述值，且对返回字节本地自算 sha256 与之相等；
#   b) AWS ECR Public 的 docker/library/node（Docker 官方 library 镜像的 AWS 侧
#      重发布）按同 tag 取 manifest，返回字节与 a) 逐字节一致（cmp 通过）。
# digest 是内容寻址的：字节一致 ⇒ 两条通道讲的是同一个上游镜像。
# **三个阶段必须保持同一 digest**：否则 builder 与 runtime 的 libc/OpenSSL
# 可能不同版本，原生模块在运行时才暴露不兼容。
# 部署机复验（一条命令确认该 digest 存在且与 tag 当前指向一致）：
#   docker pull node:22.14.0-alpine@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944
#   docker inspect --format='{{index .RepoDigests 0}}' node:22.14.0-alpine@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944
# scripts/capture-image-digests.sh 仍是部署机侧的复核工具：升级基础镜像时用它
# 重新捕获 digest，并在同一次改动里同步更新三处 FROM 与
# src/tests/security/baseImageDigestPinned.test.js 的钉版字面量（该测试把
# digest 钉成门禁，只改 FROM 不改测试会红灯）。

# Builder 阶段
FROM node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS builder

WORKDIR /app

# 复制 package 文件
COPY package*.json ./

# 安装所有依赖（含 devDependencies）。--ignore-scripts 的安全性判据：
# 本阶段**从不执行任何测试或构建**（下面只 COPY 源文件，全 Dockerfile 无 `npm test`；
# 测试在 CI test job 里跑，不在镜像构建里），devDeps 中唯一带 install 脚本的
# mongodb-memory-server 的 postinstall 只是「预下载 mongod 二进制」，其失败路径是
# process.exit(0)（node_modules/mongodb-memory-server-core/lib/util/postinstallHelper.js:36
# 「Exiting with 0 to not fail the install」），跳过它不会造成任何本阶段缺失的产物。
# 生产侧安装脚本的强不变量另由 scripts/check-prod-install-scripts.js 在 CI 硬门禁。
RUN npm ci --ignore-scripts && npm cache clean --force

# 复制源代码（显式复制，避免依赖 .dockerignore 排除 .env）
COPY src/ ./src/
# D-3：迁移文件随镜像分发。原镜像不含 migrations/ 与 migrate-mongo-config.js，
# 而 migrations/README.md 与 deployment/rollback-drill.md 都要求在部署环境执行
# `npm run migrate:up`——在只拉了镜像、没有仓库源码的部署机上，该命令**无一条可执行**。
# 迁移必须与它要变更的代码同版本（迁移描述的是这份 schema 的演进），
# 因此与 src/ 同源打进镜像，而不是让部署机另配一份源码。
COPY migrations/ ./migrations/
COPY migrate-mongo-config.js ./
# migrate-mongo-config.js 顶层 require('./scripts/destructiveGuard')（目标库判据的
# 唯一事实来源）。镜像原先只 COPY src/ 与 migrations/，于是容器里
# `migrate-mongo status|up`（scripts/deploy.js 的部署步骤）在加载配置那一刻
# MODULE_NOT_FOUND —— 迁移这道闸在任何真实部署里都没执行过，而 CI 用桩 docker
# 观测命令序列，看不到容器内的文件集合。src/tests/deploy/imageRequireClosure.test.js
# 把"COPY 集合必须闭合满足相对 require"钉成门禁。
COPY scripts/destructiveGuard.js ./scripts/
COPY package*.json ./

# 前端构建阶段（L-1）：产出 web-admin/dist，供后端 express 静态托管
# （或挂载给 Nginx 托管，二选一）。与后端同版本基础镜像，避免工具链漂移。
FROM node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS web-builder

WORKDIR /web
COPY web-admin/package*.json ./
# --ignore-scripts 的安全性判据：本阶段只做前端 `npm run build`，
# web-admin 依赖树内带 install 脚本的只有 @parcel/watcher（经 vite→sass 引入，
# node_modules 实测命中；其 install 是原生绑定的按需编译，缺脚本时 npm 落可选
# 预编译平台包），且它是 devDependency——本阶段不跑 vitest（测试在 CI frontend-build job）。
# 本镜像的 node:22.14.0-alpine 在 linux-musl-x64 平台确有 @parcel/watcher 预编译包可回落，
# 故 --ignore-scripts 安全。若未来引入「mac/win 本地构建镜像」，该假设需重新评估。
RUN npm ci --ignore-scripts && npm cache clean --force
# ⚠ 源码必须在 npm ci **之后**、build 之前进镜像：2026-09-30 供应链批次重写本阶段
# 时曾把 `COPY web-admin/ ./` 连同 --ignore-scripts 一起改动而漏掉了这行——
# `npm run build` 跑在只有 node_modules 的 /web 里，vite 连入口模块都解析不到，
# exit 1（CI build job 实测）。缓存优化的标准序：package 文件先行，源码后置。
COPY web-admin/ ./
# vite.config.js 已显式 sourcemap: false（L-1/I-3），产物不含源码映射
RUN npm run build

# Runtime 阶段（digest 须与 builder 完全一致，见顶部说明）
FROM node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80

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
# 运行期加载 migrate-mongo-config.js 需要它（见 builder 阶段说明）。
# 只复制这一个文件，不把整个 scripts/ 塞进镜像：里面的 --apply 破坏性运维脚本
# 一旦被容器里任何一条命令路径引用到，就等于把"改库开关"分发到生产实例上。
COPY --from=builder --chown=nodejs:nodejs /app/scripts/destructiveGuard.js ./scripts/
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

# 在 runtime 阶段单独安装生产依赖（不含 devDependencies），并将 node_modules 归属到非 root 用户。
# --ignore-scripts 的安全性判据：生产树里唯二可能带安装脚本的依赖都已被门禁显式表态——
#   @scarf/scarf 已登记进 PROD_INSTALL_SCRIPT_ALLOWLIST（其 postinstall 仅为遥测上报，
#   跳过不影响功能；它经 swagger-ui-express→swagger-ui-dist 传递进生产树，
#   `npm ls --omit=dev` 实测可见），其余未登记命中为 0。
# 这条不变量由 `node scripts/check-prod-install-scripts.js --omit=dev` 在 CI security-audit
# 硬门禁（当前实测退出码 0），不靠本行注释断言。
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# ===== D-3：迁移执行器 =====
# migrate-mongo 在 package.json 里是 devDependency，上面 `--omit=dev` 会把它排除，
# 于是镜像里即便带了 migrations/ 也**没有执行迁移的工具**——
# `npm run migrate:up` 在纯镜像部署机上依然不可用（文档承诺与镜像能力不一致）。
#
# 这里显式补装，且**版本号读自 package-lock.json 的解析结果**：
# 在 Dockerfile 里再手抄一个版本号会形成第二个事实来源，
# 升级依赖时漏改一处就变成「迁移用 A 版、开发用 B 版」。
#
# 为何不读 package.json 的 devDependencies 区间（此前的做法）：
#   package.json 里是 `^14.0.7` 这样的**约束**，而 dev/CI 的 `npm ci` 装的是 lockfile 里
#   **解析出的具体版本**。用 sed 抹掉 `^` 等于把"区间的下界"当成"实际版本"——
#   只要 lockfile 被单独刷新（`npm update`、`npm audit fix --lockfile-only`、
#   Dependabot 的 lock-only PR），镜像就会安装一个 CI 从未跑过、完整性锚也未覆盖的版本，
#   而这条偏差不会有任何红灯：迁移工具与开发环境用的不是同一个包。
#   读 lockfile 后，镜像里的版本与 `npm ci` 装的版本恒等。
#   取不到值时必须**让构建失败**，而不是带着空串去执行 `npm i migrate-mongo@`：
#   `$(… | sed …)` 的退出码来自管道右端，node 抛错会被吞掉 ⇒ 空版本交给 npm 后
#   行为不确定（可能报错，也可能被解析成 `migrate-mongo@` 的最新标签）。
#
# --ignore-scripts 的安全判据与上面 runtime 的 `npm ci --omit=dev` 同源：
# 该命令同样落在生产闭包内（--omit=dev），migrate-mongo 自身及其生产依赖树
# 若带 install 脚本，会一并被 check-prod-install-scripts.js 的 --omit=dev 变体拦下
# （当前实测该闭包命中 0）。故此处可以安全忽略脚本。
#
# 为何用 --no-save 而不是把 migrate-mongo 移进 dependencies：
#   - 迁移器是**部署期工具**，不是应用运行期依赖，放进 dependencies
#     会让每次 npm ci 都为它解析依赖树、也扩大了生产依赖的安全扫描面；
#   - --no-save 不改动 package.json / package-lock.json，
#     依赖声明保持原样，需要撤销时只改本文件。
# 代价（如实记录，尚未消除）：--no-package-lock 让 npm **完全不读** lockfile，
# 所以只有 migrate-mongo 自身的版本被锚住了，它的**传递依赖树仍是构建期现解析**，
# 与 lockfile 锚（deployment/lockfile-anchor.json）不同源。要彻底闭合，需要二选一：
#   a) 从 builder 阶段（`npm ci` 已按 lockfile 装好全部依赖）按 lockfile 的子树关系
#      COPY migrate-mongo 及其依赖目录；
#   b) 把它移进 dependencies，改走 `npm ci --omit=dev` 的锚定路径。
# 两者都会改变镜像构建的依赖闭包，属结构性改动，未拍板前不做。
RUN MIGRATE_MONGO_VERSION="$(node -p "require('./package-lock.json').packages['node_modules/migrate-mongo'].version" 2>/dev/null)" && \
    if [ -z "$MIGRATE_MONGO_VERSION" ]; then \
      echo '构建失败：无法从 package-lock.json 解析 migrate-mongo 的版本（依赖清单与镜像构建已脱钩，拒绝以不确定版本继续）' >&2; \
      exit 1; \
    fi && \
    echo "migrate-mongo 版本（读自 package-lock.json）: $MIGRATE_MONGO_VERSION" && \
    npm i --no-save --no-package-lock --omit=dev --ignore-scripts "migrate-mongo@$MIGRATE_MONGO_VERSION" && \
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
