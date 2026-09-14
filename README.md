# 消防安全管理系统（Fire Safety RBAC System）

前后端分离的消防设备管理系统。后端基于 Node.js + Express + MongoDB，采用 RBAC 权限模型实现精细化访问控制；前端为 Vue 3 管理后台。覆盖设备台账、火警处置、巡检管理、报表统计等完整业务闭环，内置实时推送、安全审计与容器化部署能力。

## 技术栈

| 层级   | 技术选型                                                                                                       |
| ------ | -------------------------------------------------------------------------------------------------------------- |
| 前端   | Vue 3（Composition API）、Vite、Element Plus、Pinia、Vue Router、ECharts、Axios                                |
| 后端   | Node.js、Express、Mongoose、Socket.IO、JWT（HS256）、winston                                                   |
| 数据库 | MongoDB 6.x                                                                                                    |
| 安全   | helmet、三层限流（IP 级 / 用户级 / 通用）、bcryptjs、AES-256 + HMAC 加密、令牌黑名单、IP 黑名单、全量审计日志  |
| 测试   | Jest + mongodb-memory-server（内存 MongoDB，无需本地实例）                                                     |
| 部署   | Docker 多阶段构建、Docker Compose、GitHub Actions CI（Node 18/20/22 矩阵测试，前端构建 24，镜像 node:22.14.0） |
| 监控   | Prometheus + Grafana + Alertmanager（docker-compose 随栈启动）、Sentry（可选）                                 |

## 功能特性

- **RBAC 权限管控**：菜单 / 按钮 / 接口三级权限模型；内置 5 个角色（超级管理员、安全管理员、消防主管、普通消防员、访客），角色 level 决定数据范围（≥9 全部 / ≥7 本部门 / ≥5 仅本人）；内置角色权限每次启动自动对账收敛，防止权限残留
- **设备管理**：消防设备台账、状态变更、维护记录、报废处理、到期设备定时扫描与提醒（每日一次）
- **报警管理**：火警上报 → 指派处理人 → 到达现场 → 处置完成 / 误报标记 / 取消的完整闭环，配合 WebSocket 实时推送
- **巡检管理**：巡检计划创建 → 开始执行 → 完成填报 → 主管审核，支持取消与删除，含巡检统计
- **报表统计**：仪表盘汇总、设备 / 报警 / 巡检分项报表，支持 Excel 导出
- **安全审计**：所有写操作自动落审计日志、安全告警、用户锁定 / 解锁、公开注册开关动态配置、个人安全信息与登录记录查询
- **实时通信**：Socket.IO 服务，连接需 JWT 认证（含黑名单校验），房间白名单机制，连接数上限 1000，心跳保活与假死连接清理
- **健壮性**：优雅关闭（HTTP → WebSocket → 定时任务 → 数据库依序释放）、未捕获异常统一处理、生产环境配置强校验（启动即拦截弱密钥 / 危险配置）

## 目录结构

```
fsms/
├── src/                        # 后端源码
│   ├── config/                 # 配置中心、数据库连接、生产环境校验
│   ├── controllers/            # 业务控制器（认证/用户/角色/权限/设备/报警/巡检/报表/安全）
│   ├── middleware/             # 中间件（认证、RBAC、限流、安全头、审计、令牌黑名单、错误处理、Sentry）
│   ├── models/                 # Mongoose 模型（User/Role/Permission/FireDevice/FireAlarm/Inspection/AuditLog 等）
│   ├── routes/                 # API 路由（9 个模块）
│   ├── services/               # 服务层（WebSocket、初始化数据、设备到期提醒、安全告警）
│   ├── tests/                  # Jest 测试用例
│   ├── utils/                  # 工具（日志、加密、响应封装、权限辅助）
│   └── index.js                # 应用入口
├── web-admin/                  # 前端源码（Vue 3 + Vite + Element Plus）
│   └── src/
│       ├── views/              # 页面（仪表盘/设备/报警/用户/角色/巡检/报表/审计日志/个人资料等）
│       ├── components/         # 巡检表单等业务组件
│       ├── router/             # 路由与权限守卫
│       ├── store/              # Pinia 状态管理
│       ├── utils/              # Axios 封装、WebSocket 客户端
│       └── layout/             # 后台布局框架
├── scripts/                    # MongoDB 备份 / 恢复脚本
├── .github/workflows/ci.yml    # CI：多版本测试 + 覆盖率 + Docker 镜像构建
├── docker-compose.yml          # 应用 + MongoDB 一键编排
├── Dockerfile                  # 后端多阶段构建（非 root 运行 + 健康检查）
├── docs/                       # 项目文档：架构图/时序图/ER 图/部署拓扑 + ADR
├── deployment/                 # 部署配套：Nginx 示例 / 密钥轮换 / 回滚演练 / 可观测性
│   ├── nginx.conf.example      # Nginx 反向代理示例（TLS 终结、安全响应头、/metrics 限流）
│   ├── secret-rotation.md      # 密钥轮换流程
│   ├── rollback-drill.md       # 回滚演练手册
│   └── observability/          # 监控栈（prometheus.yml 在本子目录，非 deployment/ 根）
│       ├── prometheus.yml      # Prometheus 抓取配置（直连后端 app:3000 的 /metrics）
│       ├── alert-rules.yml     # 告警规则（宕机 / 5xx 错误率 / P95 延迟 / 安全告警突增）
│       ├── alertmanager.yml    # Alertmanager 路由（按 severity 分发；通知渠道为占位，按头注释注入）
│       └── grafana/            # Grafana 数据源与仪表盘（datasources/、dashboards/ 容器启动自动装载）
├── start.bat                   # Windows 一键启动脚本
├── jest.config.js              # 测试配置（覆盖率棘轮：全局 分支79/函数87/语句91/行91，安全关键模块另设独立阈值，只升不降）
└── .env.example                # 环境变量模板
```

## 项目文档

| 文档                                           | 内容                                                                                                |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [docs/architecture.md](./docs/architecture.md) | 系统架构图、登录时序图、ER 图、部署拓扑图（Mermaid）                                                |
| [docs/adr/](./docs/adr/README.md)              | 架构决策记录：登录 ECDH 选型、审计链哈希、密钥管理、单进程锁假设、多实例 Redis 回退、高量级游标分页 |
| [CHANGELOG.md](./CHANGELOG.md)                 | 版本变更日志                                                                                        |

## 快速开始

### 环境要求

- Node.js >= 18（CI 验证版本：18 / 20 / 22）
- MongoDB >= 5（推荐 6.x，本地安装或 Docker 均可）

### 方式一：Windows 一键启动

先确保 MongoDB 服务已运行（`net start MongoDB`），然后双击 `start.bat`。脚本会自动清理 3000/3001 端口占用、依次启动后端与前端，并打开浏览器登录页。

### 方式二：手动启动

```bash
# 1. 安装后端依赖并配置环境变量
npm install
cp .env.example .env    # Windows: copy .env.example .env，然后编辑 .env

# 2. 启动后端（开发模式，自动重启）
npm run dev             # 监听 http://localhost:3000

# 3. 安装前端依赖并启动（新终端）
cd web-admin
npm install
npm run dev             # 监听 http://localhost:3001，/api 自动代理到后端
```

访问 `http://localhost:3001/login` 进入登录页；访问 `http://localhost:3000/health` 检查后端状态。

### API 文档

启动后端后访问 Swagger UI 交互式文档：

- 文档页面：`http://localhost:3000/api-docs`
- 原始规范：`http://localhost:3000/api-docs.json`（OpenAPI 3.0）

涵盖 9 个模块共 86 个接口，支持在线调试（需先通过 `/api/auth/login` 获取 token 并在页面右上角 Authorize 中填入）。

**安全说明**：生产环境默认关闭 API 文档，需显式设置 `ENABLE_API_DOCS=true` 才会暴露。开启后建议同时设置 `DOCS_USERNAME` 和 `DOCS_PASSWORD` 启用 Basic Auth 保护，并在网络层限制仅内网/ VPN 访问。

### 方式三：Docker Compose（生产推荐）

```bash
# 必须先在环境变量或 .env 中设置强密钥
export JWT_SECRET=$(openssl rand -base64 48)
export JWT_REFRESH_SECRET=$(openssl rand -base64 48)
export AES_SECRET_KEY=$(openssl rand -hex 32)
export HMAC_SECRET=$(openssl rand -hex 16)

docker compose up -d
```

编排包含应用服务、MongoDB 6（仅容器内网通信，不暴露宿主机端口）与 Redis 7（同样仅内网），数据持久化到命名卷。生产环境变量校验要求配置 `REDIS_URL`（compose 已注入 `redis://redis:6379`），无需额外设置。

## 环境变量

复制 `.env.example` 为 `.env` 后按需修改。本表仅为核心运行变量节选；完整运行与安全变量（指标端点、ECDH 私钥、CSP 上报、主机白名单、审计保留期等）以 `.env.example` 为准。生产环境建议用 `<NAME>_FILE` 注入密钥文件。

| 变量                                               | 说明                                                          | 默认值                                     |
| -------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------ |
| `PORT`                                             | 后端服务端口                                                  | `3000`                                     |
| `NODE_ENV`                                         | 运行环境                                                      | `development`                              |
| `MONGODB_URI`                                      | MongoDB 连接地址                                              | `mongodb://localhost:27017/fire_safety_db` |
| `REDIS_URL`                                        | Redis 连接地址（生产必填：限流共享、IP 黑名单广播、审计链锁） | -                                          |
| `JWT_SECRET`                                       | 访问令牌密钥（生产必须 ≥32 字符）                             | -                                          |
| `JWT_EXPIRE`                                       | 访问令牌有效期                                                | `2h`                                       |
| `JWT_REFRESH_SECRET`                               | 刷新令牌密钥（生产必须 ≥32 字符）                             | -                                          |
| `JWT_REFRESH_EXPIRE`                               | 刷新令牌有效期                                                | `7d`                                       |
| `AES_SECRET_KEY`                                   | AES 加密密钥（生产必须 ≥32 字符）                             | -                                          |
| `HMAC_SECRET`                                      | HMAC 签名密钥（生产必填）                                     | -                                          |
| `CORS_ORIGIN`                                      | 跨域白名单，逗号分隔（生产必填，禁止通配符）                  | 开发模式默认本机 3001/5173                 |
| `ALLOW_PUBLIC_REGISTRATION`                        | 公开注册开关，生产建议 `false`                                | `false`                                    |
| `ADMIN_INITIAL_PASSWORD`                           | 初始管理员密码；不设置则自动生成随机强密码                    | 随机生成                                   |
| `TRUST_PROXY_HOPS`                                 | 反向代理跳数（生产必填，否则限流/黑名单按代理 IP 计）         | -                                          |
| `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX_REQUESTS` | 通用限流窗口 / 阈值                                           | `900000` / `300`                           |
| `BCRYPT_ROUNDS`                                    | 密码哈希强度                                                  | `12`                                       |
| `LOG_LEVEL`                                        | 日志级别                                                      | `info`                                     |
| `SENTRY_DSN`                                       | Sentry 错误监控（可选）                                       | -                                          |
| `ENABLE_API_DOCS`                                  | 是否暴露 Swagger API 文档（生产默认 false）                   | 开发=true / 生产=false                     |
| `DOCS_USERNAME`                                    | API 文档 Basic Auth 用户名（可选）                            | -                                          |
| `DOCS_PASSWORD`                                    | API 文档 Basic Auth 密码（可选）                              | -                                          |

## 默认账户

首次启动自动创建管理员账户 `admin`：

- 设置了 `ADMIN_INITIAL_PASSWORD` 时使用该密码
- 未设置时自动生成随机强密码，写入项目根目录 `.admin-initial-password` 文件（权限 600，不入日志），登录后请立即修改

## 内置角色

| 角色       | 编码              | level | 职责                                           |
| ---------- | ----------------- | ----- | ---------------------------------------------- |
| 超级管理员 | `SUPER_ADMIN`     | 10    | 全部权限                                       |
| 安全管理员 | `SECURITY_ADMIN`  | 8     | 用户 / 角色管理、安全审计、业务只读监督        |
| 消防主管   | `FIRE_SUPERVISOR` | 6     | 报警全流程处理、巡检审核、设备维护与报废、报表 |
| 普通消防员 | `FIREFIGHTER`     | 4     | 执行巡检、报警上报与处置、设备只读             |
| 访客       | `GUEST`           | 1     | 设备 / 报警 / 巡检 / 报表只读                  |

## API 概览

所有业务接口均需 `Authorization: Bearer <token>`，并通过 RBAC 权限校验。

### 认证 `/api/auth`

| 方法 | 路径        | 说明                                     |
| ---- | ----------- | ---------------------------------------- |
| POST | `/register` | 用户注册（受公开注册开关与严格限流约束） |
| POST | `/login`    | 用户登录（独立登录限流）                 |
| POST | `/refresh`  | 刷新访问令牌                             |
| GET  | `/me`       | 获取当前用户信息                         |
| PUT  | `/password` | 修改密码                                 |
| PUT  | `/profile`  | 更新个人资料                             |
| POST | `/logout`   | 登出（令牌加入黑名单）                   |

### 用户管理 `/api/users`

| 方法   | 路径         | 说明             |
| ------ | ------------ | ---------------- |
| GET    | `/`          | 用户列表（分页） |
| GET    | `/stats`     | 用户统计         |
| GET    | `/:id`       | 用户详情         |
| POST   | `/`          | 创建用户         |
| PUT    | `/:id`       | 更新用户         |
| PUT    | `/:id/roles` | 分配角色         |
| DELETE | `/:id`       | 删除用户         |
| DELETE | `/batch`     | 批量删除用户     |

### 角色管理 `/api/roles`

| 方法   | 路径                | 说明                       |
| ------ | ------------------- | -------------------------- |
| GET    | `/`                 | 当前可见角色列表           |
| GET    | `/all`              | 全部角色                   |
| GET    | `/permissions/tree` | 权限树                     |
| GET    | `/:id`              | 角色详情                   |
| POST   | `/`                 | 创建角色                   |
| PUT    | `/:id`              | 更新角色                   |
| PUT    | `/:id/permissions`  | 分配权限                   |
| DELETE | `/:id`              | 删除角色（内置角色受保护） |

### 权限管理 `/api/permissions`

| 方法   | 路径     | 说明         |
| ------ | -------- | ------------ |
| GET    | `/`      | 权限列表     |
| GET    | `/:id`   | 权限详情     |
| POST   | `/`      | 创建权限     |
| POST   | `/batch` | 批量创建权限 |
| PUT    | `/:id`   | 更新权限     |
| DELETE | `/:id`   | 删除权限     |

### 设备管理 `/api/devices`

| 方法   | 路径               | 说明                 |
| ------ | ------------------ | -------------------- |
| GET    | `/`                | 设备列表（分页筛选） |
| GET    | `/stats`           | 设备统计             |
| GET    | `/expiring`        | 即将到期设备         |
| GET    | `/reminders`       | 到期提醒记录         |
| GET    | `/:id`             | 设备详情             |
| POST   | `/`                | 创建设备             |
| PUT    | `/:id`             | 更新设备             |
| PUT    | `/:id/status`      | 变更设备状态         |
| PUT    | `/:id/scrap`       | 设备报废             |
| POST   | `/:id/maintenance` | 添加维护记录         |
| DELETE | `/:id`             | 删除设备             |

### 报警管理 `/api/alarms`

| 方法 | 路径               | 说明         |
| ---- | ------------------ | ------------ |
| GET  | `/`                | 报警列表     |
| GET  | `/stats`           | 报警统计     |
| GET  | `/:id`             | 报警详情     |
| POST | `/report`          | 上报火警     |
| PUT  | `/:id/dispatch`    | 指派处理人   |
| PUT  | `/:id/arrive`      | 到达现场登记 |
| PUT  | `/:id/resolve`     | 处置完成     |
| PUT  | `/:id/false-alarm` | 标记误报     |
| PUT  | `/:id/cancel`      | 取消报警     |

### 巡检管理 `/api/inspections`

| 方法   | 路径            | 说明         |
| ------ | --------------- | ------------ |
| GET    | `/`             | 巡检列表     |
| GET    | `/stats`        | 巡检统计     |
| GET    | `/:id`          | 巡检详情     |
| POST   | `/`             | 创建巡检计划 |
| PUT    | `/:id`          | 更新巡检计划 |
| PUT    | `/:id/start`    | 开始执行     |
| PUT    | `/:id/complete` | 填报完成     |
| PUT    | `/:id/review`   | 审核         |
| PUT    | `/:id/cancel`   | 取消巡检     |
| DELETE | `/:id`          | 删除巡检     |

### 报表统计 `/api/reports`

| 方法 | 路径           | 说明            |
| ---- | -------------- | --------------- |
| GET  | `/dashboard`   | 仪表盘汇总数据  |
| GET  | `/devices`     | 设备报表        |
| GET  | `/alarms`      | 报警报表        |
| GET  | `/inspections` | 巡检报表        |
| GET  | `/export`      | 导出 Excel 报表 |

### 安全管理 `/api/security`

| 方法    | 路径                              | 说明                     |
| ------- | --------------------------------- | ------------------------ |
| GET     | `/my-info`                        | 当前用户安全信息         |
| GET     | `/bindings`                       | 账户绑定关系             |
| GET     | `/my-logs`                        | 个人操作日志             |
| PUT     | `/change-password`                | 修改密码（登录限流保护） |
| POST    | `/view-sensitive`                 | 敏感信息查看申请（留痕） |
| POST    | `/report`                         | 安全事件上报             |
| GET     | `/stats`                          | 安全统计                 |
| GET     | `/overview`                       | 安全总览                 |
| GET     | `/alerts`                         | 安全告警列表             |
| GET     | `/audit-logs`                     | 审计日志查询             |
| PUT     | `/users/:userId/lock`             | 锁定 / 解锁用户          |
| GET/PUT | `/config/allowPublicRegistration` | 查询 / 切换公开注册开关  |

## WebSocket 实时推送

连接地址与后端同源（`ws://localhost:3000`）。客户端需先发送 `auth` 事件携带 JWT 完成认证（校验签名与令牌黑名单），再加入房间：

| 房间              | 用途                                                             |
| ----------------- | ---------------------------------------------------------------- |
| `role-management` | 角色 / 权限变更推送（`role-updated`、`permission-updated` 事件） |
| `device-alert`    | 设备告警通知                                                     |
| `alarm`           | 火警实时通知                                                     |
| `notification`    | 通用通知                                                         |

## 测试

```bash
npm test                 # 运行全部测试（自动启动内存 MongoDB，无需本地实例）
npm run test:coverage    # 运行测试并输出覆盖率（全局阈值：分支79/函数87/语句91/行91；安全关键模块另设独立阈值，棘轮只升不降）
npm run test:watch       # 监听模式
npm run validate         # 独立校验环境配置
```

## 运维 Runbook（备份 / 恢复 / 升级 / 回滚）

### 备份

```bash
# 备份（输出到 ./backups，gzip 压缩，自动清理 30 天前备份，保留天数可经
# BACKUP_RETENTION_DAYS 调整；凭据经临时配置文件传递，不上命令行）
MONGODB_URI="mongodb://..." ./scripts/backup-mongo.sh

# 容器化部署时对卷数据定时备份（宿主机 crontab 示例，每日 02:00）：
# 0 2 * * * cd /opt/xf && MONGODB_URI="mongodb://..." ./scripts/backup-mongo.sh >> logs/backup.log 2>&1
```

建议至少每日一次全量备份，并把 `./backups` 同步到异机/对象存储——备份与数据库同机存放无法抵御宿主机级故障。

### 恢复

```bash
# 恢复前先停应用（避免恢复过程中业务写入脏数据）：
docker compose stop app

# 恢复（脚本带三道防误操作门禁：回显目标库、交互确认库名、--drop 需显式 RESTORE_DROP=true）
MONGODB_URI="mongodb://..." ./scripts/restore-mongo.sh backups/fire-safety-backup-xxxxxxxx-xxxx.gz

# 恢复后重启应用并验证：
docker compose start app
curl -f http://localhost:3000/health
```

### 升级

1. **升级前必备份**：按上节执行一次全量备份并确认备份文件非空。
2. 拉取新版本代码后运行全量测试确认基线：`npm test`（后端）与 `cd web-admin && npm test`（前端）。
3. 重建并滚动重启（数据在命名卷中，重建容器不影响数据）：

```bash
docker compose build app
docker compose up -d app     # mongo 未变动时不重启
```

4. 升级后观察：`curl /health`、日志 `logs/error-*.log` 无新增错误、登录与核心业务冒烟。

### 回滚

- **应用回滚**：回到上一个正常版本的代码/镜像重新 `docker compose build && up -d app` 即可——应用无状态，会话缓存随进程消亡，用户重新登录。
- **数据回滚**：仅当新版本已发生不兼容写入时才需要。先停应用，按"恢复"节流程回灌升级前的备份，再把应用也回滚到对应版本。
- 回滚后必须排查根因并保留当时的 `logs/` 与审计日志（AuditLog 集合）用于追溯。

## 生产部署清单

生产环境启动时会强制校验以下配置，不满足将直接拒绝启动：

- [ ] `JWT_SECRET`、`JWT_REFRESH_SECRET`、`AES_SECRET_KEY` 均为 ≥32 字符的强随机密钥
- [ ] `HMAC_SECRET` 已设置
- [ ] `MONGODB_URI` 不指向 localhost（使用独立数据库服务）
- [ ] `REDIS_URL` 已配置为有效 Redis 地址（限流共享、IP 黑名单广播、审计链锁依赖；compose 默认 `redis://redis:6379`）
- [ ] `CORS_ORIGIN` 已配置为明确的前端域名白名单（禁止通配符）
- [ ] `TRUST_PROXY_HOPS` 已按反向代理层数设置
- [ ] `ALLOW_PUBLIC_REGISTRATION` 保持 `false`
- [ ] 已修改默认管理员初始密码
- [ ] 已在反向代理层启用 HTTPS 并下发 HSTS（见下节）

## 传输层安全（HTTPS / HSTS）

浏览器按 RFC 6797 仅采纳经 HTTPS 送达的 HSTS，因此 TLS 必须在反向代理层终结，应用层无法在明文 HTTP 上提供真正的 HTTPS/HSTS。生产部署请：

1. 使用受信任 CA 签发的证书，参考 `deployment/nginx.conf.example` 配置 TLS 终结、HTTP→HTTPS 跳转与全套安全响应头（HSTS / CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy / COOP / CORP / X-XSS-Protection）。
2. 后端已内置 `Strict-Transport-Security` 兜底下发（`src/middleware/security.js` 的 `ensureHsts`）；前端开发/预览服务器已在 `web-admin/vite.config.js` 统一下发安全头。这些用于开发期与过渡期，生产最终以反向代理为准。
3. `localhost:3000/3001` 的明文 HTTP 仅用于本地开发调试；扫描器对 localhost 的"未使用 HTTPS/HSTS"项应视为开发环境特性，生产域名以代理层 TLS 为准。

## 可观测性（Prometheus / Grafana / 告警）

监控配置集中在 `deployment/observability/`（注意不是 `deployment/` 根目录），`docker-compose.yml` 已挂载并随编排栈一并启动：

- `deployment/observability/prometheus.yml`：Prometheus 抓取配置，直连后端 `app:3000` 的 `/metrics`（该端点在 Nginx 层按 allow 列表限流，不对公网暴露）。
- `deployment/observability/alert-rules.yml`：4 条内置告警——服务宕机、5xx 错误率 >5%、P95 延迟 >1s、安全告警突增；阈值为保守初值，待压测基线落地后收紧。
- `deployment/observability/alertmanager.yml`：告警触达链路的路由中枢，按 `severity` 分发（critical 即时通道 30 分钟重复提醒，warning 低优先级通道 4 小时），并按实例维度抑制同源重复告警。仓库内为**占位配置**，通知渠道（webhook/SMTP）按文件头注释以私有副本或模板渲染注入，敏感值不入库。
- `deployment/observability/grafana/`：`datasources/` 与 `dashboards/` 由 Grafana provisioning 在容器启动时自动装载，无需界面手配。

## 常见问题

- **前端无法连接后端**：确认后端已在 3000 端口运行；开发模式下前端 `/api` 请求由 Vite 代理转发到 `http://localhost:3000`
- **MongoDB 连接失败**：检查 `.env` 中 `MONGODB_URI` 与服务是否启动（`netstat -ano | findstr ":27017"`）
- **接口返回 401**：令牌过期时调用 `/api/auth/refresh` 刷新；登出后的令牌会进入黑名单
- **页面提示权限不足**：前端路由与后端接口均按 RBAC 校验，请联系管理员为用户分配对应角色

## 许可证

MIT License
