# 系统架构文档

> 优化清单 H-3 建档（2026-08-29）。图均为 Mermaid 源码，GitHub / VS Code / Typora 可直接渲染。
> 安全决策背景另见 [ADR 目录](./adr/README.md)。

## 1. 总体架构

前后端分离：Vue 3 管理后台 + Express REST API + MongoDB，Socket.IO 承载实时推送。

```mermaid
flowchart TB
  subgraph Client["前端 web-admin（Vue3 + Pinia + Element Plus）"]
    Views["视图层：仪表盘/设备/告警/巡检/用户/角色/报表/审计/Profile 等 13 个 View"]
    Store["Pinia store（auth/app）"]
    Api["utils/api.js（axios 封装）"]
    Ws["utils/websocket.js（socket.io-client，引用计数 + 房间）"]
    Cipher["utils/loginCipher.js（WebCrypto 口令信封加密）"]
  end

  subgraph Backend["后端（Express，src/）"]
    MW["中间件链：requestId → metrics → Sentry → IP黑名单 → CORS →\n安全头/限流/查询防护 → morgan → auditLog"]
    Routes["路由（11）：auth / user / role / permission / device /\nalarm / inspection / report / security / wellKnown / index"]
    Ctrl["控制器（9）：auth / user / role / permission / device /\nalarm / inspection / report / security"]
    Svc["服务层（15）：sessionService / userPermissionService /\ncaptchaService / websocketService / auditBuffer / auditMonitor /\nstatsCache / securityAlert / Device·Alarm·Inspection Service 等"]
    Utils["工具：loginCipher / auditChain / encryption /\nlogger(winston) / response 封装"]
    Models["Mongoose 模型（12）"]
  end

  Mongo[("MongoDB 6.x")]
  Socket["Socket.IO（JWT 认证 + 房间白名单 + 连接数上限）"]

  Views --> Store --> Api
  Views --> Ws
  Views --> Cipher
  Api -- "REST /api" --> MW --> Routes --> Ctrl
  Ctrl --> Svc
  Ctrl --> Models
  Svc --> Models
  Svc --> Utils
  Ws <-. "ws(s) /socket.io" .-> Socket
  Socket --> Svc
  Models --> Mongo
```

**分层约定**：请求一律经 路由 → 控制器 → （服务层）→ 模型。已知技术债：部分控制器直连模型（优化清单 D-1），新功能要求强制经服务层。

## 2. 登录时序

```mermaid
sequenceDiagram
  autonumber
  participant U as 浏览器（LoginView + loginCipher）
  participant RL as 限流层（IP/用户/登录专用）
  participant AC as authController.login
  participant CS as captchaService
  participant LC as loginCipher（后端）
  participant DB as User / SystemConfig
  participant SS as sessionService

  U->>U: WebCrypto 生成一次性 ECDH 密钥对，AES-GCM 加密 {口令, ts, nonce}
  U->>RL: POST /api/auth/login（encPassword, mfaCode?）
  RL->>AC: 通过三层限流与入参校验
  AC->>CS: 验证码开关开启时校验图形验证码
  AC->>LC: decryptLoginCredential（±5min 时间窗 + nonce 去重）
  AC->>DB: findByUsername（大小写不敏感）+ 状态/锁定检查
  AC->>AC: IP 白名单校验 → bcrypt 比对（失败计数，≥10 锁 10min）
  alt 已启用 MFA 且未带码
    AC-->>U: { mfaRequired: true }
    U->>AC: 携带 TOTP / 恢复码重试
    AC->>AC: verifyTotp（原子条件更新防重放）或原子消费恢复码
  end
  AC->>SS: generateToken(jti=sid) + createSession（设备指纹）
  SS-->>U: Set-Cookie（httpOnly）+ 登录审计落链
  Note over U,DB: 实时通道：后续 Socket.IO 连接复用 JWT 认证（含令牌黑名单校验）
```

关键实现：`src/controllers/authController/credentials.js`（login 约 L140）、`src/utils/loginCipher.js`、`src/services/sessionService.js`；时序对齐防用户枚举（哑 bcrypt 耗时）。

## 3. 数据模型（ER 图）

```mermaid
erDiagram
  USER ||--o{ USER_SESSION : "登录会话"
  USER }o--o{ ROLE : "roles[]"
  ROLE }o--o{ PERMISSION : "permissions[]"
  PERMISSION ||--o{ PERMISSION : "parent 自引用树"
  USER ||--o{ AUDIT_LOG : "userId / targetUserId"
  USER ||--o{ TOKEN_BLACKLIST : "登出吊销"
  USER ||--o{ SYSTEM_CONFIG : "updatedBy"
  FIRE_DEVICE ||--o{ FIRE_ALARM : "deviceId"
  USER ||--o{ FIRE_ALARM : "上报人/处理人"
  FIRE_DEVICE }o--o{ INSPECTION : "devices[] / findings[]"
  USER }o--o{ INSPECTION : "assignedTo[]"
  USER ||--o{ INSPECTION : "reviewedBy"

  USER {
    string username UK
    string password "bcrypt"
    array roles "ref Role"
    string mfaSecret "AES-GCM 加密"
    int tokenVersion "全局吊销"
    array allowedIPs
    int failedLoginCount
  }
  ROLE {
    string name UK
    array permissions "ref Permission"
    int level "数据范围 ≥9全部/≥7本部门/≥5本人"
    boolean isBuiltIn
  }
  PERMISSION {
    string code UK "module:action"
    string type "menu/button/api/data"
    string parent "自引用"
    string path
    string method
  }
  FIRE_DEVICE {
    int deviceCode "自增"
    string lifecycleStage "状态机"
    array maintenanceRecord
    array inspectionRecord
  }
  FIRE_ALARM {
    int alarmCode "自增"
    string deviceId "ref FireDevice"
    string status "上报→指派→处置闭环"
    array processLog
  }
  INSPECTION {
    array devices "ref FireDevice"
    array assignedTo "ref User"
    string reviewedBy "主管审核"
    string status
  }
  AUDIT_LOG {
    string prevHash
    string hash "SHA-256 链"
    string hmac
    int hashVersion "v1/v2/v3"
    string userId
  }
  USER_SESSION {
    string sid UK "jti"
    string fingerprint
    string status "active/revoked/expired"
    date expiresAt "TTL"
  }
  TOKEN_BLACKLIST {
    string tokenHash UK
    date expiresAt "TTL"
  }
  SYSTEM_CONFIG {
    string key UK
    string updatedBy
  }
```

模型清单：`User / Role / Permission / FireDevice / FireAlarm / Inspection / AuditLog / UserSession / TokenBlacklist / IPBlacklist / SystemConfig`（`src/models/`）。

## 4. 部署拓扑

当前 `docker-compose.yml` 定义的目标生产形态（TLS 终结的 Nginx 在宿主侧，示例配置见 `deployment/nginx.conf.example`）。

**本图以 `docker-compose.yml` 为唯一生成源**（F-06，2026-10-17 重画）。此前的图把 MongoDB 画在
`fire-safety-net` 里、与 app 同网，而实际 compose 中 mongo **只**在 `data-net`（且该网络
`internal: true`）——按旧图排障会连错网络、也会误判"app 能否直连数据面"这个安全边界。
图与 compose 的一致性由 `src/tests/deploy/architectureDocContract.test.js` 钉住：
compose 里增删服务/网络而文档没跟上，那条门禁会红。

```mermaid
flowchart TB
  Internet["互联网"] -->|443 TLS| NGX["宿主 Nginx\nTLS 终结 / 安全头 / gzip\n静态托管 web-admin/dist\n/metrics 限源访问"]
  NGX -->|"/api、/socket.io 反代\n127.0.0.1:3000"| APP
  OPS["运维 / 值班（本机回环）"] -.->|"127.0.0.1:3000 app\n127.0.0.1:3001 grafana\n127.0.0.1:9090 prometheus · 127.0.0.1:9093 alertmanager"| EDGE

  subgraph EDGE["fire-safety-net（bridge，可出网）"]
    PROM["prometheus\n15s 抓取 + 告警规则求值"]
    AM["alertmanager:v0.27.0\n接收器默认占位\n生产以私有副本挂载注入"]
    GRAF["grafana:11.1.0\n看板 / 告警视图"]
  end

  subgraph DATA["data-net（bridge，internal: true）\n不接宿主 NAT、不出外网"]
    MONGO["mongo:6.0.20\nlimits 2g·2cpu / healthcheck ping\nvolumes: mongo-data, mongo-config"]
    REDIS["redis:7-alpine\n限流 / 缓存 / 分布式锁\nvolumes: redis-data"]
  end

  APP["app 容器（node:22.14.0-alpine 三阶段构建）\n非 root / cap_drop ALL / no-new-privileges\nlimits 1g·1.5cpu / 日志轮转 20m×5\n**双网络接入**"]
  APP ---|"接入：被抓取 + 出网发 webhook"| EDGE
  APP ---|"接入：唯一的数据面访问者"| DATA
  PROM -->|"抓取 app:3000/metrics"| APP
  PROM -->|"告警推送 9093"| AM
  GRAF -->|"查询 9090"| PROM
  APP -->|"27017（不暴露宿主）"| MONGO
  APP -->|"6379（不暴露宿主）"| REDIS
  SEC["./secrets/*（chmod 600，仓库外）\njwt/aes/hmac/mongodb_uri…"] -.->|"secrets 挂载 /run/secrets"| APP
  SEC -.->|"mongo_root_username/password"| MONGO
```

**网络边界（三句话，排障时先看这段再看图）**：

1. `fire-safety-net` 是**边缘/监控面**：app、prometheus、alertmanager、grafana 在此网。
   app 的出网能力（`securityAlertDelivery` 的 webhook）与 Prometheus 的抓取都走这张网。
2. `data-net` 是**数据面**且 `internal: true`：mongo、redis 只在此网，**没有宿主端口、不能出外网**。
   监控栈与宿主发布面都摸不到数据面——这条分段直接封掉的反向路径是
   "Grafana 数据源 URL 可配任意地址 ⇒ 可达无密码 redis（删黑名单键 = 撤销封禁、
   清限流计数 = 解除封顶）"，见文末 networks 段的注释与 ADR-005。
3. **app 同时接入两张网**（这是唯一同时接入的服务）：既要被 prometheus 抓取、要出网发告警
   webhook，又要访问 mongo/redis。把数据面单独拆成 internal 网络，才能让"监控面容器直连数据库"
   这件事在**网络层**不成立，而不是靠应用层鉴权兜。新增服务时不要顺手把它加进 `data-net`。

**宿主端口（全部绑 127.0.0.1，不对公网）**：

| 服务         | 宿主端口 | 说明                                    |
| ------------ | -------- | --------------------------------------- |
| app          | 3000     | 由宿主 Nginx 反代；直接访问仅限本机排障 |
| grafana      | 3001     | 容器内 3000，宿主 3000 已被 app 占用    |
| prometheus   | 9090     | 查询 / 状态页                           |
| alertmanager | 9093     | Web UI；Prometheus 经容器网络推送到此   |
| mongo        | 无       | 仅 `data-net`，容器内 27017             |
| redis        | 无       | 仅 `data-net`，容器内 6379              |

要点：

- **密钥注入**：全部经 Docker secrets 文件（`*_FILE`），`environment` 只留非敏感项（见 ADR-003）
- **镜像钉版本**：仓库内所有第三方镜像引用都已钉到 registry digest（`name:tag@sha256:<64hex>`，保留可读 tag）——Dockerfile 的 3 处 `node:22.14.0-alpine`、compose 的 mongo / redis / prometheus / alertmanager / grafana、`.github/workflows/ci.yml` 的 mongo service 容器。digest 的取值与核验口径见 `scripts/verify-image-digests.js`（对返回字节自算 sha256，且要求 ≥2 个运营主体不同的来源一致），对账闸是 `src/tests/security/imageReferenceInventory.test.js`（优化清单 R-5）
- **Redis** 已在 compose 中实际运行（非注释态）：`redis:7-alpine` 钉了 digest，app 以 depends_on 等其健康后启动；承接限流/缓存/分布式锁（R-3/A-1）
- **前端静态托管已落地**（L-1，P0）：由 `src/middleware/staticFrontend.js` 托管 `web-admin/dist`；通过 `SERVE_FRONTEND` 启用、`FRONTEND_DIST` 指定产物目录。内置 `/assets` 一年强缓存 immutable、`index.html` 与 `sw.js` no-cache、SPA history 回退、`.map`/`.ts` 显式拦截，并配套专项测试覆盖。

## 5. 前端结构速览

- 路由：`Layout` 包裹 11 个业务子路由（`meta.permission` 控权）+ 独立登录/注册页；`beforeEach` 做会话恢复与权限校验
- 实时推送场景：权限变更同步（`permission-sync` 定向投递）、告警实时推送、设备状态更新
- 全局兜底：`utils/errorReporter.js` 收敛组件/资源/未处理 Promise 三路错误（G-1）

## 6. 数据一致性与事务策略（第二轮审计 B-3）

第二轮审计（2026-09-03）核对全仓 51 处写点后的结论：仅设备删除（`DeviceService.deleteDevice`）存在真实的跨集合多步写，其余均为单集合原子写。据此确立以下一致性策略：

- **单集合写**：一律依赖 MongoDB 单文档原子性，不引入事务。
- **跨集合多步写**：必须经 `src/utils/transaction.js` 的 `withTransaction` 包裹——副本集/分片拓扑走 session 事务（任一步失败整体回滚）；standalone 拓扑按能力探测**确定性降级**为顺序执行并告警一次（不靠「先写失败再重试」误判能力），此时多集合一致性依赖应用层写入顺序。
- **生产部署**：按副本集部署（docker-compose 的 mongo 为单节点，扩容副本集后事务自动生效，无需改代码）。
- **新增多步写决策顺序**：能否退化为单集合原子写 → 不能则 `withTransaction` → 仍不能则补偿逻辑，禁止裸的多步顺序写。
- 现存多步写点位：设备删除（`deleteDevice`，告警引用 → 巡检引用×2 → 设备删除）。设备报废（`scrapDevice`）的 scrapDate 补录已合并进 `transitionTo` 单次原子写（B-2），不再是多步写。

> 注：本文出现的「优化清单 X-N」为建仓前遗留的历史编号（源文件 `deliverables/待优化项总清单-2026-08-29.md` 从未进入版本库且已不存在），无源可查。该编号体系已废弃，新提交一律使用 `P*/R*/T*`——详见 `CONTRIBUTING.md` §5。
