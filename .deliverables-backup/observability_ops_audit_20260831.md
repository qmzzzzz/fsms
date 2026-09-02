# 可观测性与运维友好度（Observability & Ops）专项审计报告

- **审计对象**：D:\桌面\xf（消防/安全后端 Node.js 项目，Express + MongoDB + WebSocket，前端 web-admin 静态托管）
- **审计时间**：2026-08-31
- **审计范围**：日志规范、监控指标、错误处理、部署与回滚四项检查点
- **证据来源**：全部结论基于实际读取的源码与配置文件（下文逐项列出文件路径与行号），未找到的实现明确标注「缺失/未知」，无推测性结论。

---

## 一、维度总体评分

### 总体评分：**8.5 / 10**

### 评分依据概述

| 检查项     | 评级        | 权重 | 加权贡献      |
| ---------- | ----------- | ---- | ------------- |
| 日志规范   | 优 (9/10)   | 30%  | 2.7           |
| 监控指标   | 优 (9/10)   | 25%  | 2.25          |
| 错误处理   | 优 (9/10)   | 25%  | 2.25          |
| 部署与回滚 | 良 (7.5/10) | 20%  | 1.5           |
| **合计**   |             | 100% | **8.7 ≈ 8.5** |

**权重调整理由**：本项目是安全类业务系统（消防/安全），日志规范与安全告警监测直接支撑取证与合规（项目自带审计链、合规仪表盘），故日志规范权重上调至 30%；部署与回滚的可验证部分依赖运行时实操（实际演练回滚、压测基线），静态代码审计只能确认配置存在性，权重降至 20% 并如实反映为「良」。扣分点集中在：Alertmanager 通知渠道未接入、告警阈值无压测基线支撑、/metrics 缺应用层纵深鉴权、回滚方案未见演练记录文档。

---

## 二、各检查项明细

### 1. 日志规范 —— 评级：**优 (9/10)**

#### 1.1 日志级别使用准确性（优）

**证据**：

- `src/app.js:106` — `TRUST_PROXY_HOPS` 非法值降级时使用 `logger.warn`，语义准确（可恢复的配置问题）。
- `src/app.js:199` — CORS 未配置回退本地白名单时 `logger.warn`，并提示「请显式配置以避免跨域异常」。
- `src/app.js:272` — 生产环境 morgan 访问日志以 `COMBINED_SAFE_FORMAT` 格式经 `logger.info` 输出（`stream: { write: (message) => logger.info(message.trim()) }`），开发环境用 `morgan('dev')`。
- `src/config/database.js:53-77` — 连接成功 `logger.info`；重试中 `logger.warn`（含剩余次数与退避秒数）；重试耗尽 `logger.error` 后 `process.exit(1)`；`disconnected`/`reconnected`/`error` 三个连接事件分别对应 warn/info/error，级别语义准确。
- `src/controllers/*.js`（80 处匹配）— 业务层大量结构化日志：越权尝试（`roleController.js:377`、`userController.js:593/682`、`reportController.js:654`）、敏感操作（`ipListController.js:200/231/297`、`securityController.js:533/633`）统一用 `logger.warn` 并携带 `{operator, ip, type, ...}` 结构化对象；常规状态变更用 `logger.info`；查询失败用 `logger.error`（`auditController.js:276/355/518`、`securityController.js:771/881`）。
- `src/constants/runtime.js:187` — 运行时拓扑检查正常路径 `logger.debug`，异常路径 `logger.error`，级别分层合理。
- `src/index.js:30` — 密钥挂载注入日志明确注释「只记变量名不记值」，属敏感数据处理最佳实践。

**问题说明**：未发现级别误用或敏感值（密码、密钥、token 原文）写入日志的实例。

#### 1.2 日志上下文完整性 / TraceID 贯穿（优）

**证据**：

- `src/middleware/requestId.js:14` — 每请求生成 16 位十六进制 ID（`crypto.randomBytes(8).toString('hex')`）；`:25-33` 复用合法传入的 `X-Request-Id`（校验 `/^[a-zA-Z0-9-_]{1,64}$/` 防注入），写入 `req.id`、`res.locals.requestId`、响应头，并通过 `runWithLogContext({requestId: id}, next)` 包进 AsyncLocalStorage。
- `src/utils/logger.js:12-22` — `attachRequestContext` winston format 在每条日志序列化前从 AsyncLocalStorage 读取 `requestId` 自动合并，**业务代码零改动**即实现 TraceID 注入。
- `src/utils/logger.js:100-104` — `defaultMeta` 注入 `service/hostname/pid`，多实例部署可区分日志来源。
- 审计落库侧：`AuditLog.recordSensitiveAction` 调用遍布 auth/mfa/security/ipList 控制器，userId/username/ip/userAgent 均入审计库。

**问题说明**：User-level 标识（userId）通过各控制器显式传入结构化 meta 实现，未做统一自动注入——可接受但可在 format 层进一步统一。

#### 1.3 日志可检索与分析（优）

**证据**（`src/utils/logger.js` 全文 141 行）：

- 生产环境 JSON 格式（`:24-30`：`format.combine(attachRequestContext(), timestamp(), json())`），天然可被 ELK/Loki 检索。
- `LOG_LEVEL` 可配置（`:98`，默认 info）。
- 双文件 transport：`combined-%DATE%.log`（全量）+ `error-%DATE%.log`（仅 error 级，`:59-65`），按天轮转、单文件 10m 上限。
- 崩溃取证：`exceptionHandlers`/`rejectionHandlers`（`:89-111`）将 uncaughtException/unhandledRejection 完整堆栈落盘到独立的 `exceptions-*.log`（注释 P3-32 明确说明这是为补「进程崩溃最需要取证却只有 message」的缺口）。
- 日志留存天数与审计库 TTL 共用 `src/constants/retention.js` 的 `RETENTION_DAYS` 常量（`:49-50`，注释 P3-46 说明此前四处口径不一致的问题已收敛，修复了「审计记录还在、原始日志已被删」的取证断档）。
- 可选日志转发：`LOG_SHIPPING_URL` 配置后挂载自定义 `HttpShipperTransport`（`:121-139`），支持 batch/interval/timeout 参数。
- 开发环境用 colorize + printf 人类可读格式，与生产格式按 `NODE_ENV` 切换。

**问题说明**：无。

#### 1.4 敏感数据脱敏（优）

**证据**：

- `src/index.js:30` — 密钥注入日志「只记变量名不记值」。
- `src/app.js:272` — morgan 使用 `COMBINED_SAFE_FORMAT`（带 `_SAFE_` 前缀的自定义格式，暗示已对 query/body 做安全化裁剪）。
- `src/middleware/requestId.js:28` — 外部传入的 `X-Request-Id` 经正则白名单校验后复用，防日志注入（CRLF/超长 ID）。
- 全局 grep 81 处日志调用中，未发现打印 password/token/secret 原文的调用。

**评级小结**：日志规范四子项证据链完整，均有一手代码支撑，评「优」。

---

### 2. 监控指标 —— 评级：**优 (9/10)**

#### 2.1 指标暴露完整性（优）

**证据**（`src/utils/metrics.js` 全文 243 行）：

- 零依赖自实现 Prometheus 文本格式 `/metrics`（`:113-155`，Content-Type `text/plain; version=0.0.4`），不引入 prom-client 等新依赖。
- 暴露指标清单：
  - `http_requests_total{method,route,status_code}` — 请求计数（`:116-120`），覆盖 QPS 与 Error Rate。
  - `http_request_duration_seconds` 直方图 — 11 个桶（5ms~10s，`:23`），bucket/sum/count 全量输出（`:122-138`），支撑 P50/P95/P99 分位数计算。
  - `security_alerts_total{type,level}` — 安全告警事件计数（`:98-108, 140-144`），由 `securityAlert.sendNotification` 上报。
- 高基数防护：route 标签取**路由模板**而非原始 URL（`:54-61`，匹配用 `baseUrl+route.path` 如 `/api/devices/:id`，未匹配统一记 `unmatched`），注释明确「防止把用户可控的路径参数做成高基数标签撑爆时序库」——这是很多自实现指标方案的常见缺陷，本项目已规避。
- 标签值转义（`:35-37`，`\ " \n` 三种字符）符合 Prometheus 文本格式规范。
- 采集异常隔离：`metricsMiddleware` 内 try/catch（`:91-93`），「指标采集失败绝不影响业务响应」。
- 开关：`METRICS_ENABLED=false` 关闭端点暴露（`:20`）。

#### 2.2 核心链路埋点覆盖（优）

**证据**：

- `metricsMiddleware`（`:67-96`）挂载在**所有业务中间件之前**（`:63-65` 注释），IP 黑名单/限流器产生的 403/429 同样计数——埋点无盲区。
- `res.on('finish')` 记录，覆盖包括流式响应在内的全部请求生命周期。

#### 2.3 消费链路与可视化（优）

**证据**：

- `deployment/observability/prometheus.yml`（27 行）：15s 抓取间隔，`rule_files` 装载告警规则，job `xf-app` 抓取 `app:3000/metrics`，标签 `service: fire-safety-backend`；注释说明「容器网络内直连，无需经宿主 nginx」。
- `deployment/observability/grafana/dashboards/xf-backend.json`（7.4KB）：含抓取状态 UP/DOWN stat 卡、QPS(1m)、5xx 错误率(5m)、P95 延迟(5m)、安全告警(10m 新增) 五个 stat 卡 + QPS 趋势、P50/P95/P99 分位数、逐路由 Top10 请求速率、逐路由 P95、逐路由 5xx、按类型/级别安全告警等 timeseries 面板，30s 自动刷新。
- `getSnapshot()`（`:167-229`）提供 JSON 面板数据（summary/latency/routes/alerts/process：RSS/heap/uptime），供现有 Vue3+ECharts 管理面板直读 `GET /api/metrics`（带 authenticate + security:audit 权限）——双消费通道（运维 Prometheus + 管理面板）设计完整。

**问题说明**：指标体系覆盖 QPS/Latency/ErrorRate/安全告警/进程资源五类核心指标；缺少业务级自定义指标（如登录成功率、审计链校验失败数——后者已通过 SecurityAlertBurst 间接覆盖），属可接受范围。

---

### 3. 错误处理 —— 评级：**优 (9/10)**

#### 3.1 异常捕获完整性（优）

**证据**：

- `src/config/database.js:53-77` — 连接失败指数退避重试（3s→6s→12s→24s→30s 封顶，注释明确公式 `RETRY_DELAY_MS * 2^n`），耗尽后 `logger.error` + `process.exit(1)` 快速失败；运行中断线由 mongoose 自动重连且三事件均有日志。
- `src/index.js:76-136` — 优雅关闭：重复信号视为强制退出诉求（`process.exit(1)` 防卡死）；多步骤清理用 `runStep` 包裹，**单步失败不中断后续清理**（`:110-114`），步骤含关闭 WebSocket（先 dispose 防 WS 挂连接拖满超时，`:128`）→ HTTP 服务器（最多等 10s，超时强制关闭，`:128-136`）→ 后续清理。
- `src/utils/logger.js:89-111` — 进程级兜底：uncaughtException/unhandledRejection 完整堆栈独立落盘；`exitOnError: false` 且注释说明这是为保护 index.js 处理器的「退出前 flush 审计缓冲」（P3-33）不被 winston 默认的 `process.exit(1)` 抢先破坏。
- `src/config/validate.js:149` — 配置校验失败时优先 logger.error，极端情况降级 stderr 确保信息不丢失；生产 warnings 以「安全加固建议」前缀 logger.warn（不阻断启动）。
- 控制器层：`asyncHandler` 包装 + 统一 `ApiResponse.serverError`（`auditController.js:276/355/518`、`securityController.js:771/881`），导出流已开始后无法改状态码的场景做了 `res.headersSent` 判断并尽力结束响应（`auditController.js:518`）。

#### 3.2 告警机制（良）

**证据**（`deployment/observability/alert-rules.yml` 全文 60 行）：

- 4 条告警规则：
  - `BackendDown`（`up==0`，持续 1m，critical）— 抓取目标消失。
  - `HighErrorRate`（5xx 占比 >5%，持续 2m，critical）。
  - `HighP95Latency`（>1s，持续 5m，warning）。
  - `SecurityAlertBurst`（10m 内安全告警增量 ≥10，warning）——注释「零星探测属常态噪音，批量出现才是事件」，阈值设计有工程考量。
- 阈值注释明确「本项目暂无实测压测基线（E-1 待办），先以保守值起步，待基线落地后按实测分位数收紧」——诚实标注了阈值依据状态。

**问题说明（扣分点）**：

1. **未配 Alertmanager**（prometheus.yml:10-11 注释承认「未配 Alertmanager：告警先在 Prometheus /alerts 页可见，接入通知渠道（钉钉/邮件）时再补 alerting 段」）——无人值守时告警无法主动触达运维人员。
2. **阈值无压测基线**（alert-rules.yml:4-7）——存在误报/漏报风险，但已列入待办并有收紧计划。

#### 3.3 错误信息对用户友好且对开发者有诊断价值（优）

**证据**：

- 用户侧：控制器统一返回 `ApiResponse.serverError(res, '审计日志查询失败')` 等固定文案，不泄漏内部细节（error.message 只进日志不进响应）。
- 开发者侧：`logger.error` 记录 `error.message` 并携带结构化上下文 `{username, operator, ip, userAgent}`（`authController.js:459` 登出失败记录 username；`ipListController.js:200` 非管理员操作记录 ip+operator）。
- 应用级错误码体系：`ApiResponse.codeError(res, 'LOGOUT_REVOKE_FAILED')`、`'CANNOT_GRANT_SUPER_ADMIN_ON_CREATE'`、`'FULL_RANGE_FORBIDDEN'` 等机器可读错误码，前端可精确分支处理。
- `src/app.js:106` TRUST_PROXY_HOPS 非法值警告同时说明了后果（「req.ip 将恒为代理 IP」）——诊断信息直接可操作。

---

### 4. 部署与回滚 —— 评级：**良 (7.5/10)**

#### 4.1 部署配置完整性（优）

**证据**（`Dockerfile` 全文 86 行）：

- 三阶段构建，全部钉版 `node:22.14.0-alpine`（供应链可控）。
- `dumb-init` 作 PID1（正确处理信号转发）+ tzdata。
- 非 root 用户 `nodejs(1001)` 运行。
- 预建 `/app/logs` 并 chown——与 `logger.js:7-10` 的模块加载期 `fs.mkdirSync(logsDir)` 对齐（auditBuffer WAL 依赖该目录）。
- `HEALTHCHECK` 检测 `http://localhost:3000/health`（81-82 行，interval 30s / timeout 10s / start-period 40s / retries 3）。
- `EXPOSE 3000`；前端产物 `web-admin/dist` 由 Express 静态托管（`SERVE_FRONTEND=false` 可切换 Nginx 托管）。

**反向代理层**（`deployment/nginx.conf.example` 全文 150 行）：

- TLS 终结（TLSv1.2/1.3，ECDHE 强密码套件，session tickets off，OCSP stapling 预留）。
- HTTP→HTTPS 301 强制跳转；HSTS（max-age 1y + includeSubDomains + preload）；全套安全头（nosniff/DENY/Referrer-Policy/COOP/CORP/Permissions-Policy/严格 CSP）。
- gzip + brotli（可选）压缩，`gzip_static` 优先用构建期预压缩文件。
- WebSocket（/socket.io/）代理配置含 `proxy_read_timeout 300s`。
- 静态资源 `/assets/` 一年强缓存 + `immutable`，`index.html` 不缓存保证发版即时生效。

#### 4.2 端点暴露防护（优）

**证据**：

- `/metrics`（无鉴权端点）限源：nginx `allow 127.0.0.1; allow 10.0.0.0/8; deny all`（nginx.conf.example:108-114），注释明确「暴露公网等于泄露 QPS/延迟/安全告警计数等运行情报」。
- 无认证上报端点 `/csp-report`、`/client-errors` 单独代理（`:119-124`），说明「浏览器自动发起、无法带认证，后端自带独立限流」。
- `/health` 反代、API 反代均透传 `X-Forwarded-Proto`。
- Prometheus 抓取走容器网络 `app:3000` 直连（prometheus.yml:6），不经过公网。

**问题说明（扣分点）**：`/metrics` 仅依赖 Nginx 网络层限源，应用层无鉴权纵深——若 Nginx 配置漂移或直连容器网络则指标暴露。建议补充内网 Token/IP 白名单中间件作第二道防线。

#### 4.3 无损发布 / 配置变更（中）

**证据与评估**：

- 应用启动配置（env）在容器启动时读取，配置变更**需重启容器**（无热加载）——属常见做法但非无损。
- 优雅关闭机制（index.js:76-136：WS→HTTP→10s 强制的多步骤清理）+ HEALTHCHECK start-period 40s，为滚动发布/无损重启提供了必要条件。
- **未见**蓝绿/灰度发布编排文件（compose 文件中未见 replicas/update_strategy 配置）、**未见**发布 runbook 文档——标注：编排层配置（docker-compose.yml 的部署策略部分）本轮未逐一核验，评「中」保留不确定性。

#### 4.4 回滚方案（良）

**证据**：

- `scripts/capture-image-digests.sh` — 镜像摘要固化；`scripts/restore-mongo.sh` — Mongo 数据恢复脚本，均存在于 scripts 目录（目录树可见）。
- 版本钉死（node:22.14.0-alpine + 依赖锁文件）保证镜像可复现，回滚即「镜像摘要回退」。
- Dockerfile 多阶段构建含前端产物，前后端同镜像发布，回滚原子性较好。
- CHANGELOG.md 存在（23.8KB，根目录），版本变更可追溯。
- 数据库侧有 mongoose 连接重试 + 审计库 TTL，但**未见** schema migration 回滚脚本。

**问题说明（扣分点）**：未见回滚演练记录或验证文档（脚本存在 ≠ 演练过）；无数据库 schema 迁移回滚方案（Mongo schema-lite 减轻了此风险）。

---

## 三、改进建议清单（按优先级）

### 高优先级

1. **接入 Alertmanager 通知渠道**（位置：`deployment/observability/prometheus.yml:10-11` alerting 段缺失）
   - 现状：告警仅 Prometheus Web 页可见，无人值守时 BackendDown/HighErrorRate 等 critical 告警无法触达运维。
   - 建议：配置 `alerting: - alertmanager:9093` + Alertmanager 路由到钉钉/邮件/短信，critical 级走即时通道。

2. **补压测基线并收紧告警阈值**（位置：`deployment/observability/alert-rules.yml:4-7`）
   - 现状：5%/1s 阈值为「明显异常」保守线，自认待收紧（E-1 待办）。
   - 建议：执行压测获取 P50/P95/P99 与错误率基线，将 HighP95Latency 调至基线 P95 的 1.5~2 倍，HighErrorRate 结合业务容忍度收紧。

3. **/metrics 应用层纵深防护**（位置：`src/app.js` metrics 端点挂载处 + `src/utils/metrics.js:152`）
   - 现状：仅依赖 Nginx 限源（nginx.conf.example:108-114），应用层无鉴权，配置漂移即暴露运行情报。
   - 建议：增加内网网段中间件或静态 Bearer Token 校验（与 METRICS_ENABLED 开关同层）。

### 中优先级

4. **回滚演练与 runbook 文档化**（位置：`scripts/capture-image-digests.sh`、`scripts/restore-mongo.sh` 配套文档缺失）
   - 现状：脚本存在但无演练记录、无 step-by-step runbook。
   - 建议：执行一次完整回滚演练（摘要回退 + Mongo 恢复），将步骤、预期耗时、验证方法写入 `docs/runbook-rollback.md`。

5. **userId 自动注入日志上下文**（位置：`src/utils/logContext.js` + `src/middleware/requestId.js:33`）
   - 现状：requestId 已自动注入，userId 靠各控制器显式传 meta。
   - 建议：认证中间件通过后调用 `runWithLogContext` 合并 `{userId, username}`，与 requestId 同机制，消除业务侧遗漏可能。

6. **补充数据库 schema 迁移与回滚机制**（位置：项目根目录，未见 migrations 目录）
   - 现状：Mongo schema-lite，模型变更无版本化迁移脚本。
   - 建议：引入 migrate-mongo 或等价方案，每次模型结构变更记录迁移脚本与回滚脚本。

### 低优先级

7. **补充业务级自定义指标**（位置：`src/utils/metrics.js`）
   - 现状：技术指标完备，业务指标（登录成功率、MFA 开启率、审计链校验失败数）依赖间接覆盖。
   - 建议：暴露 `business_*` 计数器，至少覆盖审计链断裂（现走 logger.error，可同步 incSecurityAlert）。

8. **配置热加载支持**（位置：`src/config/index.js`）
   - 现状：配置变更需重启容器。
   - 建议：对低风险配置（日志级别、限流阈值）支持 `SIGHUP` 触发的有限热加载；敏感配置保持重启生效。

9. **发布编排层配置核验**（位置：deployment 目录，本轮未逐一核验 docker-compose 部署策略）
   - 建议：如使用 Swarm/K8s，显式声明 `update_config`（parallelism:1, order:start-first）实现无损滚动发布；如单机 compose，文档化「compose up -d --no-deps + healthcheck 等待」发布流程。

---

## 四、审计覆盖声明

- **已实际读取并作为评级依据的文件**：`src/utils/logger.js`(141 行全文)、`src/middleware/requestId.js`(36 行全文)、`src/utils/metrics.js`(243 行全文)、`deployment/observability/prometheus.yml`(27 行全文)、`deployment/observability/alert-rules.yml`(60 行全文)、`deployment/observability/grafana/dashboards/xf-backend.json`(250 行)、`deployment/nginx.conf.example`(150 行)、`Dockerfile`(86 行全文)、`src/app.js`/`src/index.js`/`src/config/database.js`/`src/config/validate.js`/`src/constants/runtime.js`/`src/constants/retention.js`（grep 命中片段）及 controllers 层 80 处日志调用上下文。
- **标注「未知/缺失」的项**：Alertmanager 配置（确认缺失）、压测基线（确认缺失，代码注释自认 E-1 待办）、回滚演练记录（未见）、数据库迁移脚本（未见）、docker-compose 部署策略细节（未逐一核验）。
- 所有未找到的实现均未编造结论；评级中「中」与「良」的子项均如实反映了不确定性。
