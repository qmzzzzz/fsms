# 多阶段构建
#
# R-5 基础镜像版本固定：
# 全部 node 阶段都必须钉到补丁号，不能只写 `node:26-alpine`。
# 浮动 tag 的后果不是「拿到新版本」而是「不同时间构建出不同的镜像」——
# 出安全问题时无法回答「上线那版用的是哪个 Node」。
#
# 已钉 digest（捕获日期 2026-10-20，来源与核验方式见下）：
# 下面三处 FROM 钉在同一 manifest list digest 上：
#   node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5
# digest 是多架构 OCI image index（含 linux/amd64 与 linux/arm64 等平台条目）。
# 来源：Docker Hub 官方 tag API（hub.docker.com/v2/...）在捕获当日于本网络不可达
# （DNS 污染），改用相互独立的 registry 通道核验并要求逐字节一致：
#   a) docker.m.daocloud.io（Docker Hub 的 pull-through 镜像）按 tag 取 manifest，
#      Docker-Content-Digest = 上述值，且对返回字节本地自算 sha256 与之相等；
#   b) AWS ECR Public 的 docker/library/node（Docker 官方 library 镜像的 AWS 侧
#      重发布）与 docker.1ms.run 按同 tag 取 manifest，返回字节与 a) 逐字节一致。
# digest 是内容寻址的：字节一致 ⇒ 各通道讲的是同一个上游镜像。
# **三个阶段必须保持同一 digest**：否则 builder 与 runtime 的 libc/OpenSSL
# 可能不同版本，原生模块在运行时才暴露不兼容。
# 26.12.0 为 2026-10-20 升级后的钉版版本（CI 矩阵 22.x/24.x，engines >=22.12.0）。
# 部署机复验（一条命令确认该 digest 存在且与 tag 当前指向一致）：
#   docker pull node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5
#   docker inspect --format='{{index .RepoDigests 0}}' node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5
# scripts/capture-image-digests.sh 仍是部署机侧的复核工具：升级基础镜像时用它
# 重新捕获 digest，并在同一次改动里同步更新三处 FROM 与
# src/tests/security/baseImageDigestPinned.test.js 的钉版字面量（该测试把
# digest 钉成门禁，只改 FROM 不改测试会红灯）。

# Builder 阶段
FROM node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS builder

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
FROM node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS web-builder

WORKDIR /web
COPY web-admin/package*.json ./
# --ignore-scripts 的安全性判据：本阶段只做前端 `npm run build`，
# web-admin 依赖树内带 install 脚本的只有 @parcel/watcher（经 vite→sass 引入，
# node_modules 实测命中；其 install 是原生绑定的按需编译，缺脚本时 npm 落可选
# 预编译平台包），且它是 devDependency——本阶段不跑 vitest（测试在 CI frontend-build job）。
# 该 node 基础镜像在 linux-musl-x64 平台确有 @parcel/watcher 预编译包可回落，
# 故 --ignore-scripts 安全。若未来引入「mac/win 本地构建镜像」，该假设需重新评估。
RUN npm ci --ignore-scripts && npm cache clean --force
# ⚠ 源码必须在 npm ci **之后**、build 之前进镜像：2026-09-30 供应链批次重写本阶段
# 时曾把 `COPY web-admin/ ./` 连同 --ignore-scripts 一起改动而漏掉了这行——
# `npm run build` 跑在只有 node_modules 的 /web 里，vite 连入口模块都解析不到，
# exit 1（CI build job 实测）。缓存优化的标准序：package 文件先行，源码后置。
COPY web-admin/ ./
# S-2：登录公钥指纹构建期钉扎。前端只能从 import.meta.env 读到它，必须由构建参数注入；
# 同一值还会写进 runtime 阶段的 LOGIN_PUBLIC_KEY_SHA256_PIN，由服务启动时比对当前密钥。
# 未传时为空（本地开发），生产/CI 从 login_ecdh_private_key 计算后传入。
ARG VITE_LOGIN_PUBLIC_KEY_SHA256=
ENV VITE_LOGIN_PUBLIC_KEY_SHA256=$VITE_LOGIN_PUBLIC_KEY_SHA256
# vite.config.js 已显式 sourcemap: false（L-1/I-3），产物不含源码映射
RUN npm run build

# Runtime 阶段（digest 须与 builder 完全一致，见顶部说明）
FROM node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5

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
# S-2：与 web-builder 同一 build-arg，转成运行期指纹后由 src/utils/loginCipher.js
# 在 createApp 时校验——构建用的公钥与运行注入的私钥不一致时启动即失败，
# 而不是等用户登录才发现「前端只认另一把钥匙」。
ARG VITE_LOGIN_PUBLIC_KEY_SHA256=
ENV LOGIN_PUBLIC_KEY_SHA256_PIN=$VITE_LOGIN_PUBLIC_KEY_SHA256
LABEL org.opencontainers.image.revision=$GIT_SHA \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.version=$APP_VERSION \
      org.opencontainers.image.title="fire-safety-rbac-system" \
      org.opencontainers.image.source="https://github.com/qmzzzzz/fsms"

# O-6：镜像自身声明生产环境。此前只靠 compose 注入 NODE_ENV，直接 `docker run`
# 或换编排器时所有 production 分支（安全校验、cookie Secure 等）都会静默失效。
ENV NODE_ENV=production

WORKDIR /app

# 安装 dumb-init 处理信号 + tzdata 时区支持
RUN apk add --no-cache dumb-init tzdata

# 创建非 root 用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# 前端构建产物（L-1 静态托管）：默认路径与 src/middleware/staticFrontend.js
# 的 resolveDistDir 一致（/app/web-admin/dist）。NODE_ENV=production 且产物
# 存在时自动启用；改用 Nginx 托管时在 compose 设 SERVE_FRONTEND=false
COPY --from=web-builder --chown=nodejs:nodejs /web/dist ./web-admin/dist

# 先装依赖、后拷源码（P-1）：npm ci 只依赖 package*.json，原顺序把 src/ 放在
# 安装层之前，任何一行业务代码改动都会击穿 node_modules 缓存，构建时间成倍增加。
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

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
# chown 原先挂在被删掉的 migrate-mongo 补装 RUN 段末尾（F-02）；补装段删掉后
# 它必须留在这里，否则 node_modules 仍归 root，nodejs 用户在运行期无法写入
# （如 migrate-mongo 写临时状态、npm 更新缓存）。
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force && \
    chown -R nodejs:nodejs node_modules

# 从 builder 阶段复制源代码（放在依赖安装之后，见上面的 P-1 说明）
COPY --from=builder --chown=nodejs:nodejs /app/src ./src
# D-3：迁移目录与配置（见 builder 阶段说明）
COPY --from=builder --chown=nodejs:nodejs /app/migrations ./migrations
COPY --from=builder --chown=nodejs:nodejs /app/migrate-mongo-config.js ./
# 运行期加载 migrate-mongo-config.js 需要它（见 builder 阶段说明）。
# 只复制这一个文件，不把整个 scripts/ 塞进镜像：里面的 --apply 破坏性运维脚本
# 一旦被容器里任何一条命令路径引用到，就等于把"改库开关"分发到生产实例上。
COPY --from=builder --chown=nodejs:nodejs /app/scripts/destructiveGuard.js ./scripts/

# ===== D-3 / F-02：迁移执行器 =====
# migrate-mongo 是**部署期**要用的工具（scripts/deploy.js 的 migrate status/up 步骤），
# 但此前它在 devDependencies 里 ⇒ 上面的 `npm ci --omit=dev` 把它排除，镜像里即便带了
# migrations/ 也没有执行迁移的工具。当时的补法是「读 lockfile 取版本 + npm i --no-save
# --no-package-lock」，这只锚住了 migrate-mongo **自身**，它的传递依赖树仍在构建期
# 重新解析（审计 F-02）：同一个 Git 提交可能产出依赖闭包不同的镜像，SBOM 与实际运行的
# 迁移器对不上，回滚到旧代码时迁移工具也未必是当时验证过的那棵树。
#
# 2026-10-17 改为 F-02 修复建议的首选方案：把 migrate-mongo 移进 dependencies。
#   - 它本来就必须在**生产容器内**可执行，放进 dependencies 才是准确的声明
#     （原先"部署期工具不算运行期依赖"的说法与"镜像里要跑迁移"这个事实自相矛盾）；
#   - `npm ci --omit=dev` 一次装好，自身与传递依赖全部由 package-lock.json 锚定，
#     构建期不再有任何解析动作 —— 同一 commit 的依赖闭包唯一；
#   - 代价如实记录：生产依赖扫描面变大。实测只多 11 个包（migrate-mongo + cli-table3
#     + commander + 它们的小依赖），`npm audit --omit=dev` 仍为 0 漏洞，
#     `check-prod-install-scripts.js --omit=dev` 未登记命中仍为 0。
# 迁移文件与配置的 COPY 见上面 builder 阶段的 D-3 段。

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
