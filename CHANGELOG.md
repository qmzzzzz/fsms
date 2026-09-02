# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

### 新增

- 前端全局错误兜底：`app.config.errorHandler`、`window` 捕获阶段 error（含资源加载失败）、`unhandledrejection` 三路收敛，错误写入 localStorage 环形缓冲（上限 50 条）；配置 `VITE_ERROR_REPORT_URL` 后可批量上报（优化清单 G-1）
- 引入 prettier 3.9.6 与 `format` / `format:check` 脚本，文档与声明式配置（docs/、docker-compose.yml、ci.yml 等）完成格式化（优化清单 O-12，源码区与 CI 门禁待续）
- 集中式 ADR：`docs/adr/` 收录登录 ECDH 选型、审计链哈希设计、密钥管理、单进程锁假设四篇架构决策记录（H-2）
- 架构文档：`docs/architecture.md` 提供系统架构图、登录时序图、ER 图与部署拓扑图（Mermaid）（H-3）
- 本 CHANGELOG 建档（H-1）

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

### 测试基线（2026-08-29 本地实测）

- 后端：68 套件 / 974 例全绿；覆盖率语句 82.29% / 分支 67.55% / 函数 79.33% / 行 84.56%
- 前端：12 套件 / 169 例全绿
- 双端 ESLint 0 error；`docker compose config` 解析通过
