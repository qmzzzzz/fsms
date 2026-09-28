# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

### 新增（2026-09-28）

- **IP 归属地展示（离线零依赖）**：会话管理等后台界面把裸 IP 翻译为「国家·省·市·运营商」。数据采用 ip2region 官方 xdb（Apache-2.0）入库 `src/data/`（约 11MB，Docker `COPY src/` 一并带入镜像），检索器 `src/utils/ip2regionSearcher.js` 以纯 Node 实现 xdb v2 格式（向量索引 + 二分，全内存约微秒级/次），不引入任何 npm 依赖；`src/services/ipLocationService.js` 负责业务口径（复用 `ipUtils.normalizeIP` 收敛 `::ffff:` 形态、内网/保留地址统一标「内网」、IPv6 短路、结果 FIFO 缓存 2048 条、任何异常 fail-soft 返回 null）。`GET /api/auth/sessions` 每条会话新增 `location`（最近活跃 IP）与 `loginLocation`（登录 IP）；会话管理界面在 IP 旁以 `·` 拼接展示。数据刷新：`node scripts/update-ip2region.js`（Gitee→GitHub→jsDelivr→npm 镜像四级数据源 + 结构校验 + 探针查询 + 原子替换），`--check` 只打印当前数据构建日期
- **CC 防护升级闭环**（`src/services/rateLimitEscalation.js`）：限流从「只挡不罚」变为「可观测 + 可升级」——每次 429 上报 `security_alerts_total{type=rate_limit_triggered}`；同一 IP 在 5 分钟窗口内触顶 100 次（`CC_ESCALATION_THRESHOLD` / `CC_ESCALATION_WINDOW_MS` 可调）即按与暴力破解同一条封禁阶梯（1h→4h→24h→7d，30 天审计事件计数升档）自动封禁。防误封设计：白名单 IP 的资源型限流直接 skip 不会产生升级信号；阈值 100 意味着「被告知限速后仍持续高频重试」；凭据型账号维度桶不接入（无 IP 可封）；升级链路全程 fail-soft 不拖垮 429 响应。计数为进程内固定窗口（多实例下按实例数摊薄，少封不误封）
- 数据文件入库配套：`check-utf8` 门禁的常见二进制扩展名清单加入 `.xdb`，`.gitattributes` 钉 `*.xdb binary`

### 变更（2026-09-28）

- **限流键统一 IP 归一化**（总账 §4.4「限流键直接拼原文 req.ip」收口）：全部 IP 维度限流器（general/strict/login/ip/user 未认证分支/captcha/register/pwd-change/reauth 及 wellKnown 三个上报限流器）的键改走 `normalizeRateLimitIp`（与名单侧同一把 `ipUtils.normalizeIP`），消除 `::ffff:1.2.3.4` 与 `1.2.3.4` 双桶导致的「同一来源配额翻倍」；歧义写法回退原文自成桶，fail-closed 语义不变。`ipLimiter` 补显式 handler（响应体与原 message 逐字一致，差异仅多升级信号上报）
- **暴力破解自动封禁判据只看 IP 维度**（总账 R-H2）：`checkBruteForce` 此前以 `max(userFailures, ipFailures)` 达标即封禁**当前请求 IP**——分布式撞单账号时把可能只贡献了 1 次失败的 IP（NAT 出口后的无辜用户/受害者本人）封 1 小时。现改为告警与审计照发（双维度都是真实攻击信号，审计 body 含双维度计数），封禁仅在 `ipFailures` 达阈值时执行
- **wellKnownRoutes 三个限流器接入共享存储**（总账 P-9）：`/csp-report`、`/client-errors`、`/.well-known/security.txt` 的限流计数从每实例独立 MemoryStore 改为 `makeSharedStore`（无 Redis 时行为不变），多副本部署下攻击者不再能对每个副本各刷满一份配额

### 测试基线（2026-09-10 本地实测）

- 后端：130 套件 / 1736 例全绿；覆盖率语句 94.66% / 分支 85.12% / 函数 92.39% / 行 96.07%（含独立设阈模块）

### 新增

- `roleService` / `userService` 服务层：控制器不再直连 Model，跨角色与用户的 RBAC 数据访问统一收口。
- 审计链 v3 换钥工具：`rotate:audit-chain-v3` 支持存量链全量重签、dry-run 预检与 HMAC 校验。
- 回滚演练工具：`drill:rollback` 支持真实 `mongod` 的数据级快照备份、清空模拟故障与归档还原。

- 前端全局错误兜底：`app.config.errorHandler`、`window` 捕获阶段 error（含资源加载失败）、`unhandledrejection` 三路收敛，错误写入 localStorage 环形缓冲（上限 50 条）；配置 `VITE_ERROR_REPORT_URL` 后可批量上报（优化清单 G-1）
- 引入 prettier 3.9.6 与 `format` / `format:check` 脚本，文档与声明式配置（docs/、docker-compose.yml、ci.yml 等）完成格式化（优化清单 O-12，源码区与 CI 门禁待续）
- 集中式 ADR：`docs/adr/` 收录登录 ECDH 选型、审计链哈希设计、密钥管理、单进程锁假设、多实例状态外置与 Redis 回退、高量级列表游标分页六篇架构决策记录（H-2）
- 架构文档：`docs/architecture.md` 提供系统架构图、登录时序图、ER 图与部署拓扑图（Mermaid）（H-3）
- 本 CHANGELOG 建档（H-1）

### 修复

- CI 密钥扫描恢复可用：`gitleaks-action` v2 → v3（v2 目标运行时 Node 20 将于 2026-09-16 从 GitHub runner 移除后无条件失效），并修正 `.gitleaksignore` 指纹——原指纹绑定的提交哈希与当前仓库历史不匹配，导致 3 处测试常量（`src/tests/constants.js` 的假密钥、`src/tests/utils/totp.test.js` 的 RFC 4226 官方向量）被重复上报为泄漏；改绑首提交 `7f92537`，行号按该提交版本登记（AES 测试密钥在该版本为第 29 行，现行为 30）

- 生产 TLS 校验放宽为「二选一」（`src/config/validate.js`）：此前 M3 只认 `ENABLE_HTTPS=true`，与 README / `.env.example` / `docker-compose.yml` 的「TLS 由前置 Nginx 终结、应用明文 HTTP 反代」形态直接冲突——该形态下置 `ENABLE_HTTPS=true` 反而会让进程加载 `./certs` 证书自起 HTTPS（`src/index.js` 的 HTTPS 分支），证书缺失即拒绝启动。后果是文档推荐的生产拓扑无法启动，`npm run test:prod-drill` 与 CI e2e job 一并变红。现放宽为：`ENABLE_HTTPS=true`（进程自启）**或** `TRUST_PROXY_HOPS∈1..5 且 ALLOWED_HOSTS 已配置`（声明由前置反代终结）任一成立即通过；同时删除重复的 M-2 TLS 告警，并更正 `.env.example` 中「ALLOWED_HOSTS 未配置仅告警」的过时说明（实为致命）

## [1.0.0] - 2026-08-29

> 本仓库此前无 CHANGELOG，本条为 1.0.0 的追溯性汇总，依据 README、代码现状与 2026-08-23 ~ 08-29 的修复批次留档整理。

### 新增

- **RBAC 权限管控**：菜单 / 按钮 / 接口三级权限模型；内置 5 个角色（超级管理员、安全管理员、消防主管、普通消防员、访客）；角色 `level` 决定数据范围（≥9 全部 / ≥7 本部门 / ≥5 仅本人）；内置角色权限每次启动自动对账收敛
- **设备管理**：消防设备台账、状态变更、维护记录、报废处理、到期设备定时扫描与提醒（每日一次）
- **报警管理**：火警上报 → 指派处理人 → 到达现场 → 处置完成 / 误报标记 / 取消的完整闭环，配合 WebSocket 实时推送
- **巡检管理**：巡检计划创建 → 开始执行 → 完成填报 → 主管审核，支持取消与删除，含巡检统计
- **报表统计**：仪表盘汇总、设备 / 报警 / 巡检分项报表，支持 Excel 导出
- **安全审计**：写操作全量落审计日志（哈希链 + HMAC 签名）、安全告警、用户锁定 / 解锁、公开注册开关动态配置、个人安全信息与登录记录查询
- **设备级会话管理**：登录会话按设备记录（`usersessions`），支持踢除单台设备、全局 `tokenVersion` 吊销
- **实时通信**：Socket.IO 连接需 JWT 认证（含黑名单校验）、房间白名单、连接数上限 1000、心跳保活与假死连接清理
- **可观测性**：`/metrics` 端点（QPS / 延迟直方图 / 错误 / 安全计数）、winston 日志轮转、Sentry 可选接入
- **部署**：Docker 三阶段构建（非 root 运行、HEALTHCHECK）、Docker Compose（secrets 文件注入、资源限额、日志轮转）、GitHub Actions CI（Node 18/20/22 矩阵）

### 安全

- 登录口令经 ECDH（P-256/P-384）+ HKDF-SHA-256 + AES-256-GCM 信封加密传输，附时间戳窗口与一次性 nonce 防重放；不支持 WebCrypto 的环境自动降级明文兼容轨
- 密钥支持 `*_FILE` 文件注入（Docker secrets）；生产启动强校验拦截弱密钥 / 危险配置（`validate.js`）
- MFA TOTP seed 以 AES-256-GCM 加密落库（`enc:v1:` 前缀）；配套 `scripts/migrate-mfa-secret.js` 支持密钥轮换迁移
- 审计链哈希口径版本化（v1/v2/v3），HMAC 换钥可用 `scripts/resign-audit-hmac.js` 存量重签
- 三层限流（IP 级 / 用户级 / 通用）、登录专用限流、IP 黑名单（含 CIDR）、令牌黑名单、helmet 安全头、CSP
- 容器加固：`resources.limits`（app 1g/1.5cpu、mongo 2g/2cpu）、json-file 日志轮转（20m×5）、`no-new-privileges`、app 容器 `cap_drop ALL`、NODE_OPTIONS 堆上限与限额对齐（R-4）
- 覆盖率棘轮门禁：安全关键模块（security/auth/rbac/tokenBlacklist/encryption/auditChain 等）单独设阈，只升不降

### 修复

以下为 2026-08-23 ~ 08-29 各批次已核实闭环的修复（详见 `deliverables/待优化项总清单-2026-08-29.md` 第四节）：

- **后端 B-2**：`assignRoles` 补「同级」角色归属校验（首版过宽误拦合法授予，经测试纠正为仅约束同级）
- **后端 B-1 / R-2**：`runCleanupSweep` 周期复查 `status`/`tokenVersion`/角色并断开失效连接
- **前端 B-1/B-2/B-3**：`toggleModule` 搜索态语义修正；ReportView/DashboardView 静默 catch 改为 ElMessage 提示
- **F-O1~F-O7**：labelMaps 单一来源、并行请求（Promise.all）、datetime 工具抽取、echarts import 归位、IpListView 关闭误报、导出文件名改本地时区
- **历史批次**：P1×7 / P2×23 / AUX×4 / P3×31 修复核实；O-1~O-5、O-7、O-8、O-10、O-11、O-13、R-6/R-6a 等均已闭环

### 测试基线（2026-08-29 历史快照；当前门禁以 `jest.config.js` 为准）

- 后端：68 套件 / 974 例全绿；覆盖率语句 82.29% / 分支 67.55% / 函数 79.33% / 行 84.56%
- 前端：12 套件 / 169 例全绿
- 双端 ESLint 0 error；`docker compose config` 解析通过
