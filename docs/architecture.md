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

关键实现：`src/controllers/authController.js`（login 约 L264）、`src/utils/loginCipher.js`、`src/services/sessionService.js`；时序对齐防用户枚举（哑 bcrypt 耗时）。

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

当前 `docker-compose.yml` 定义的目标生产形态（TLS 终结的 Nginx 在宿主侧，示例配置见 `deployment/nginx.conf.example`）：

```mermaid
flowchart LR
  Internet["互联网"] -->|443 TLS| NGX["宿主 Nginx\nTLS 终结 / 安全头 / gzip\n静态托管 web-admin/dist\n/metrics 限源访问"]
  NGX -->|"/api、/socket.io 反代\n127.0.0.1:3000"| APP["app 容器（node:22.14.0-alpine 三阶段构建）\n非 root / cap_drop ALL / no-new-privileges\nlimits 1g·1.5cpu / 日志轮转 20m×5"]
  APP -->|"容器内网 27017（不暴露宿主）"| MONGO["mongo:6.0.20\nlimits 2g·2cpu / healthcheck ping\nvolumes: mongo-data, mongo-config"]
  SEC["./secrets/*（chmod 600，仓库外）\njwt/aes/hmac/mongodb_uri…"] -.->|"secrets 挂载 /run/secrets"| APP
  SEC -.->|"mongo_root_username/password"| MONGO
  subgraph NET["fire-safety-net（bridge）"]
    APP
    MONGO
  end
```

要点：

- **密钥注入**：全部经 Docker secrets 文件（`*_FILE`），`environment` 只留非敏感项（见 ADR-003）
- **镜像钉版本**：`node:22.14.0-alpine`、`mongo:6.0.20`；digest 待部署机 `docker pull` 后捕获回填（优化清单 R-5）
- **Redis** 已在 compose 中预留（注释态），规模化时启用并承接限流/缓存/分布式锁（R-3/A-1）
- **待落地**：前端静态托管的生产闭环（L-1，P0）——Nginx 托管 dist 或后端 express.static 二选一，并复测无 `/src/` 与 sourcemap 泄露

## 5. 前端结构速览

- 路由：`Layout` 包裹 11 个业务子路由（`meta.permission` 控权）+ 独立登录/注册页；`beforeEach` 做会话恢复与权限校验
- 实时推送场景：权限变更同步（`permission-sync` 定向投递）、告警实时推送、设备状态更新
- 全局兜底：`utils/errorReporter.js` 收敛组件/资源/未处理 Promise 三路错误（G-1）
