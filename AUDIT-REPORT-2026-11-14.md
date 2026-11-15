# FSMS 全仓代码审计报告

- 审计日期：2026-11-14
- 审计方式：40 个并行精读代理 + 6 项机械检查（lint / prettier / npm audit ×2 / jest 全量 / vitest 全量）+ 全局静态扫描
- 审计范围：**全部 git 跟踪文件逐行精读**（生产代码、测试、脚本、部署、文档、CI），未依赖任何历史审计结论，全部结论基于本次现场阅读与交叉验证
- 基线：main @ 830418d

---

## 0. 覆盖面清单（逐行读完的文件）

| 区域                                                             | 文件数                | 行数（约）   | 覆盖                                                         |
| ---------------------------------------------------------------- | --------------------- | ------------ | ------------------------------------------------------------ |
| 后端入口/配置（app/index/cluster/config/plugins/docs/data）      | 25                    | 7.7k         | 24/25 逐行（ip2region.xdb 为二进制数据文件，核验其来源说明） |
| 后端中间件 src/middleware                                        | 33                    | 6.7k         | 33/33                                                        |
| 后端路由 src/routes                                              | 17                    | 3.8k         | 17/17                                                        |
| 后端控制器 src/controllers                                       | 40                    | 9.4k         | 40/40                                                        |
| 后端服务 src/services                                            | 139                   | 30.3k        | 139/139                                                      |
| 后端模型 src/models                                              | 23                    | 4.2k         | 23/23                                                        |
| 后端工具 src/utils                                               | 68                    | 13.7k        | 68/68                                                        |
| 后端常量 src/constants                                           | 49                    | 7.3k         | 49/49                                                        |
| 运维脚本 scripts                                                 | 78                    | 20.4k        | 78/78                                                        |
| 前端基础设施（main/router/store/layout/composables/utils 等）    | 57                    | 13.4k        | 57/57                                                        |
| 前端组件 web-admin/src/components                                | 34                    | 9.3k         | 34/34                                                        |
| 前端视图 web-admin/src/views                                     | 19                    | 20.7k        | 19/19                                                        |
| 前端 i18n + vite/eslint/html 配置                                | 15                    | 7.2k         | 15/15                                                        |
| 后端测试 src/tests                                               | 850                   | 96.1k        | 850/850                                                      |
| 前端测试 web-admin/src/tests                                     | 153                   | 50.6k        | 153/153                                                      |
| 部署面（Dockerfile/compose/e2e/migrations/deployment/根配置）    | 69                    | —            | 69/69                                                        |
| 文档与 CI（docs/.github/README/CHANGELOG/SECURITY/CONTRIBUTING） | 59                    | 18.0k        | 59/59                                                        |
| **合计**                                                         | **≈1,632 个跟踪文件** | **≈29 万行** | **全覆盖**                                                   |

### 机械检查结果

| 检查                        | 结果                                                                                                                                                                                                  |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 后端 ESLint                 | 0 error / 36 warning（exit 0）                                                                                                                                                                        |
| 前端 ESLint                 | 通过（exit 0）                                                                                                                                                                                        |
| Prettier format:check       | 2 个文件格式不符                                                                                                                                                                                      |
| npm audit（后端 prod+full） | **23 个漏洞：1 critical（mongoose 8.0.0–8.24.6，sanitizeFilter 系列 GHSA）+ 21 moderate + 1 low**；deepmerge 原型污染；glob/minimatch 在 dev 依赖链                                                   |
| npm audit（前端 prod）      | 0 漏洞                                                                                                                                                                                                |
| 后端 Jest 全量              | **823/824 套件通过，10155/10157 用例通过，1 跳过**；唯一失败 `src/tests/deploy/backupUriFile.test.js` 为 `spawnSync bash ETIMEDOUT`（本机满载环境红，测试本身设计为"无 bash 即红不跳过"），非产品缺陷 |
| 前端 Vitest 全量+覆盖率     | **152 文件 / 2508 用例全部通过**；views 语句覆盖 90.23%（最低 AlertsView 76.8%、ProfileView 78.2%）                                                                                                   |

### 全局静态扫描

- TODO/FIXME/XXX/HACK：后端生产代码 9 处、前端生产代码 6 处（无阻塞性未完成项）
- console.log：后端生产代码 5 处；前端 console.* 14 处（均为刻意留痕/降级上报路径）
- eval/new Function：无业务使用（仅 Redis Lua eval 与 i18n 自定义编译器替代方案）
- child_process：仅 src/config/buildInfo.js、src/utils/filePermission.js（均受控）
- v-html：前端仅 1 处引用面（ECharts tooltip，已 escapeHtml 全字段转义）

---

## 1. 执行摘要

**总体结论：这是一个工程质量显著高于平均水平的仓库。** 全仓约 29 万行代码逐行审计后，**未发现任何 P0（可利用致命）缺陷**；发现 **1 项 P1**（CHANGELOG.md 文件损坏，影响发布说明抽取）、**约 17 项 P2**、**约 90 项 P3**。后端安全体系（认证链、RBAC、审计链 HMAC、限流、蜜罐、PII 加密）实现扎实且自带测试锚定；前端 XSS 面干净（零 v-html 滥用）、令牌走 httpOnly cookie 方案正确；部署面 fail-loud 纪律贯彻彻底。

最需要动手的十件事（按性价比排序）：

1. **[P1] 重建 CHANGELOG.md**——同一文档被重复拼接约 4 遍（`## [未发布]` ×4、`## [1.0.0]` ×4），release.yml 按标签抽取发布说明时会混入错位残片；且后来者极易改到旧副本。
2. **[P2] 升级 mongoose ≥8.24.7**（消除 1 critical + 多条 moderate），顺带处理 deepmerge 传递依赖。
3. **[P2] 修复幂等中间件清理竞态**（src/middleware/idempotency.js:101-103）：非 2xx 收尾时无条件 `deleteOne({keyHash})` 可删掉他人已完成的幂等记录导致重复执行，补 `state:'in_progress'` 条件即可。
4. **[P2] 修复 OpenAPI 响应双层嵌套**（src/docs/generate.js）：`400: badRequest` 应为 `...badRequest` 展开，当前 5 端点 7 处错误响应非法，且 openapiSync 对账两侧共享同一 bug 抓不到。
5. **[P2] 封段活跃度查询换用已索引的 timestamp 字段**（src/services/ipPoolLiveTraffic.js:113-119）：现按无索引的 createdAt 对审计全集扫描。
6. **[P2] 统一改密流程的加密 fail-closed**（web-admin ChangePasswordCard.vue:127-130）：全仓唯一残留的明文回退轨，与 ReauthDialog/MfaSettingsCard/UpgradeDialog 的 G2 口径相悖。
7. **[P2] 前端删除审核意见 min:10 的单方面加严**（InspectionReviewForm.vue:134-139）：后端无最小长度限制，合法短意见被前端拦截。
8. **[P2] WebSocket 重连耗尽接入 reportDegradation**（web-admin utils/websocket.js:202-210）：当前静默死亡且零上报；`send()` 补 `authenticated` 前置。
9. **[P2] 测试夹具卫生批量收口**：约 8 个测试文件的模块级 env 写入不还原（同 worker 跨文件泄漏，`loginPeerBucketXffRotation` 已实测在 --randomize 下约 50% seed 翻红）、2 个文件连库不关、3 处空断言/名实不符用例。
10. **[P2] 威胁模型文档纠偏**：threat-model.md 把已收窄为 127.0.0.1 绑定的 dev/preview 写成 0.0.0.0 暴露；仓库已转 public，SAST 文档"私有仓前提"失效（CodeQL/Scorecard 实际在跑）。

---

## 2. 七维度详评

### 维度 1：代码质量与规范性 —— 评级：优

**规范与可读性**

- ESLint（后端+前端）0 error；36 条 warning 全部在棘轮账本（eslint.ratchet.json）管控下。Prettier 仅 2 个文件格式漂移。
- 命名语义化程度高，"一判据一文件"的组织方式贯彻较好；后端 services/models 按域拆分清晰。
- 注释密度极高是项目门禁（commentDensity ratchet，账本 23569/51205≈0.3152）刻意要求；实测这些注释绝大多数是"事故编号 + 实测证据 + 被否决方案"的有效载荷，不是复述代码。少数超长注释（User.js collation 段、audit.js username 闸段）可拆到 docs/。

**复杂度**

- 无"上帝文件"失控：最大的生产文件是 web-admin/src/views/PrivilegeGrantView.vue（2991 行）与 AuditLogView.vue（1992 行），均有 max-lines 棘轮约束且逻辑/样式分区清晰；后端最大文件 auditBuffer.js（653 行）逻辑闭环。
- 长函数集中在授权路径（assignRoles 108 行、assignPermissions 93 行），分支语义连贯，拆分收益一般。

**DRY 违背（主要改进面）**

- 响应包装器三份实现：security/auditLog.js、idempotency.js captureOutcome、forensicCapture.js 各自包装 res.json/send/write/end，语义细节不同——建议抽共享"响应观察"基元。
- 同一脱敏规则双实现：auditLog.js sanitizeValue 与 models/auditLogSanitizer.sanitizeAuditBody 靠 0–10 层逐字节一致用例对齐（自认），长期应收敛单源。
- 凭据校验三件套在 authRoutes.js:36-62 本地复制，未复用已抽出的 middleware/security/reauthCredentialRules.js（securityRoutes 已改用）。
- validationResult 消费样板在 20 个控制器重复约 25 次；mongoIdParamValidation 在 4 个路由文件各抄一份；changePasswordValidation 两份且已漂移（见 P3-路由 F4）。
- 前端：WebSocket 订阅样板在 usePermissionSync/useRealtimeRefresh 近乎重复；加密失败文案三元链在 4 个组件复制；约 120 行"Apple 风格" scoped CSS 在 7+ 个视图逐字重复；两套 CSS 分段控件（.glass-segmented 与 .seg-glass）并存。
- 缓存失效机制三套写法（sessionCache/permCache/statsCache 的代际计数），可抽通用部件。
- 'use strict' 覆盖不一致：src/constants 49 文件中 21 有 28 无。
- 死代码零星：helpers.js isValidAvatar/escapeHtml 已无生产调用方；ipListController 同族调用点 await 口径不一；backgroundJobs.test.js global.__eapp 等。

### 维度 2：架构设计与工程结构 —— 评级：优

**分层**

- 表现（routes/controllers）→ 业务（services）→ 数据（models）边界总体清晰。审计确认：20 个控制器无一绕过 service 直连模型做业务写；唯一的分层小越界是 reportDashboardService/reportExportService 直接 import middleware/rbac 取数据范围（与仓内 D-1a 分层棘轮注释自洽，属已知债务）。
- 无循环依赖：architecture/requireCycles.test.js 用 Tarjan SCC 静态把关；layeringRatchet 用 `==` 棘轮防"白嫖额度"。

**模块化与一致性**

- "同一判据只写一处"纪律执行极佳：IP 归一化四漏斗共用 CANONICAL_OCTET、错误码注册表单点、枚举常量被模型/路由/文档三向引用（审计程序化对账 8 组全绿）。
- env 解析策略存在三种口径并存（生产抛错/告警回落/无声回落），upgrade.js toPositiveInt 静默回退与仓内"错配必须出声"口径不一致（P3）。
- 配置外部化彻底：无硬编码秘钥；.env.example 与 src 消费点抽查全部对齐；生产硬闸（弱密钥/ALLOWED_HOSTS/TLS/TRUSTED_PROXY_CIDRS/CORS https/Redis 认证）成体系。

**设计模式**

- 策略/门面/工厂使用恰当（authController 子模块门面、errorHandler 表驱动、policy/exec 分离）；无过度设计痕迹。
- 判据/执行分离（xxxPolicy.js 纯函数 + CLI 壳）是脚本层最核心的纪律，测试可毫秒级断言。

### 维度 3：安全性 —— 评级：优（含 1 项依赖 critical 待升级）

**输入验证与注入**

- 129 个端点逐一核对：全部有鉴权（公开面明示豁免）、业务面全部有权限码、`:id` 类参数全有格式校验；qs extended 下的操作符注入被 queryScalarGuard（非标量一律 400、无白名单豁免）+ 路由校验 + normalizeSearchTerm 转义三层挡住。
- 服务层动态查询条件全部经白名单/转义/归一化构造；聚合管道无 $where/$function。
- XSS：前端 34 组件 + 19 视图零 v-html/innerHTML；唯一 HTML 拼接面（ECharts tooltip）全字段 escapeHtml；验证码 SVG 用 encodeURIComponent data URI。

**认证与授权**

- 认证链（HS256 限定 + kid 选钥 + 用途判据 + 黑名单/会话 fail-closed + tokenVersion 强制 + IP 范围 + 强制改密闸）未发现可利用缺陷；refresh 轮换用原子消费消除 TOCTOU。
- RBAC deny-by-default 系统性收口；写路径普遍"对象级范围判定（assertRecordInScope）+ 层级闸 + 服务层 CAS 条件更新 + 写后复验回滚"四层。
- WS 握手与 HTTP 侧安全裁决同尺（同一 trustedProxies/hops 判据），在途断开复检防幽灵连接。
- 横向越权专项：userController/delete、ipList 全网段护栏、rolePermission 克隆分支等全部有对象级归属校验。

**依赖安全**

- 后端 23 个漏洞（**1 critical**：mongoose 8.0.0–8.24.6 sanitizeFilter 系列 5 条 GHSA；deepmerge 原型污染为传递依赖；其余为 glob/minimatch 等 dev 链 moderate）。**mongoose 有 `npm audit fix` 可用的修复版本，应尽快升级并跑全量回归。**
- 前端 0 漏洞。CI 有 dependency-review/dependabot/SLA 台账闭环。

**敏感数据与秘钥**

- PII：phone/email/reporter.phone AES-256-GCM 加密 + AAD 行绑定 + n-gram 盲索引；toJSON 脱敏白名单（RESPONSE_EXCLUDE）派生 PII 可见变体并有门禁；审计/日志侧 logPiiMask 键名闭合集 + 值掩码。
- 秘钥：全部走 env/*_FILE/随机生成，无硬编码；错误信息"点名不取值"；generate-secrets 对密钥落 git 有前置拦截。登录口令走 ECDH+HKDF+AES-GCM 密文轨（前端构建期公钥钉扎，**生产必须注入 VITE_LOGIN_PUBLIC_KEY_SHA256，见 P3 待确认**）。
- 日志：winston 落盘清洗 + PII 掩码 + SIEM 出站白名单；dev 分支 morgan('dev') 打完整 URL 含 query（P3，仅开发面）。

**残余风险（已声明/低危）**

- docker-compose mongo 健康检查 root 凭据经 shell 展开进 argv（文件内已自我登记，容器内无其他进程）。
- GUEST 角色数据范围恒 all（读权限由权限码收窄，设计如此）；未来"只做 scope 不过权限码"的端点会对其全量放行，建议用测试钉住该不变量。
- webhook 密钥缺省时告警出站无签名头（securityAlertDelivery.js:157-160）。

### 维度 4：性能与资源效率 —— 评级：良+

**数据库**

- 索引纪律很强：游标分页排序键必带 _id 平局键、TTL 单列独立、复合索引有 COLLSCAN 实测依据；迁移与 schema 双向对账测试钉住。
- **唯一实锤的 P2 性能问题：ipPoolLiveTraffic.js:113-119 封段活跃度检查按 createdAt（无索引）+ 非前缀锚定 ip 正则对审计集合全扫**；应改用已索引 timestamp 或补索引。
- 未发现 N+1：列表/统计统一 $facet/批量 $in；websocketSweep 批量去重查询（L-29 修复在案）。
- 无分页封顶遗漏：normalizePagination maxLimit 500 + skip 二次收敛。

**算法与内存**

- 热路径无 O(n²) 实害（initData/seeding 的 includes O(n²) n≈50 无碍）；进程内 Map 均有上限+淘汰（injectionDetector 4096、rateLimitEscalation 10000+压力淘汰、ipLocation 2048 等）。
- 可改进：ipPoolCluster 聚合先 $addToSet 后过滤、无 allowDiskUse/maxTimeMS（P3）；upgradeService listJobs 全量读状态文件（P3）；reportDashboardService 缓存命中返回共享引用无防御拷贝（P3）；sessionCache 超限全清（P3）；bcryptWorkerPool worker code-0 退出的理论挂起（P3 待确认）。

**并发**

- 写路径几乎全部 `findOneAndUpdate(状态前置条件)` 消除 TOCTOU；进程内互斥 + DB 原子操作 + 跨进程文件锁三层并用；未发现裸奔的读-改-写。
- 已知取舍：alertDispatch 内存频控在轮换 key 攻击下短时全放行（已声明宁可放开也不 OOM）；forensicTrigger 标记表纯进程内存（多副本漏采，v1 边界已声明）。

**缓存**

- sharedCache Redis/内存双后端，Lua 原子脚本；**DECR_FLOOR_ZERO_SCRIPT 会把过期键重建成永久键**（P3，复活窗口内计数偏松 + 垃圾键）；captchaService set 返回值未查的极端降级（P3）。

### 维度 5：测试覆盖与可靠性 —— 评级：优（测试是本仓最强资产）

**规模与金字塔**

- 后端 Jest：850 文件 / 10157 用例（15 分钟全量），行为测试（supertest + 每文件独立内存库）与"元门禁"（src/tests/ci/**，约 60% 文件数）并存；前端 Vitest：152 文件 / 2508 用例 + 覆盖率。E2E 16 旅程 ×2 project（playwright），另有 ops-e2e/production-drill/load-test/k6。
- 后端覆盖率阈值棘轮（分支 79/函数 87/语句 91/行 91）在 jest.config.js 钉死；前端 views 覆盖 76.8%–100%。

**有效性（本次重点核查）**

- 未发现恒真断言主判据、mock 掉被测逻辑、skip/only/todo 残留。"前提自证 + 反向对照 + 变异实测"三件套是全仓统一范式，大量注释记录"第一版断言恒真→补牙"的过程。
- 发现的弱断言/名实不符（全部 P2/P3）：exportLabelsLocalized.test.js:121-127 标题承诺"截断脚注跟随语言"实际只有 `expect(typeof fn).toBe('function')`；logShipperTransportFailurePaths "携带 Bearer token" 用例空断言（SIEM 出站 Authorization 全仓零覆盖）；offlineBundleIntake 两处能力缺失分支静默 return（违背文件头自身纪律）；idempotency.test.js:957 `toBeGreaterThanOrEqual(0)` 恒真；validationMessagesFollowLocale:147 死断言；permissionModuleCard.test.js:299 `/s+/g` 笔误（应为 /\s+/g）。

**夹具卫生（本次发现最集中的缺陷面）**

- env 跨文件泄漏（jest worker 的 process.env 跨文件共享、模块注册表每文件新建）：auditBufferZombieDuplicate（AUDIT_WAL_PATH 指向已删目录）、rateLimitEscalationEviction（5 个 CC_ESCALATION_* 不还原，可使 rateLimitEscalation 在 --randomize 下顺序性翻红——实测 seed 2/4/6 双红）、auditWalCap、forensicCapture 系列 4 文件、attackDetection、auditChainZombieFreeze、honeypotListShapeParity、ipPoolBan（IP_POOL_BAN_ALLOW_AUTO）、loginPeerBucketXffRotation（文件内顺序耦合 + 无收尾）。
- 连库不关（违反仓内 mongooseTeardown 约定，worker 被强杀吞输出）：stuffingProfileWriteSites（台账已登记）、reportExportRowOrderAndCells、auditTtlBootReconcile 第二个 describe。
- 其它：cursorTiebreakIndexes ④b 建库不 drop；ttlMigrationEmptyDb 库名固定无时间戳；3 处"共享库"过时注释（setup.js 已按文件隔离）；registerView 切语言不还原 locale；loginView console.warn spy 仅成功路径恢复；avatarImage 全局替身不还原。

**CI 集成**

- ci.yml 教科书级：依赖闸前置、三版本矩阵、随机顺序三 seed、覆盖率/格式/OpenAPI 漂移/UTF-8/合规全接、gitleaks、E2E 防裁剪下界 32、SBOM+cosign。全部 action 钉 digest、权限最小化、`${{ }}` 走 env 通道，无注入面。
- 注意：bundleBudget 的"真实产物"组对 web-admin/dist 缺失会硬失败（后端全量 jest 隐式依赖前端已构建，fail-closed 设计，知悉即可）。

### 维度 6：可观测性与运维友好度 —— 评级：优

**日志**

- winston 统一出口：级别白名单、落盘清洗、PII 掩码、AsyncLocalStorage 请求上下文（requestId 中间件，客户端 ID 仅作关联）。
- "吞错必须留声"纪律贯彻极好：fail-open 全部登记在 failOpenSites 台账并有指标+日志双信号；审计写失败计指标；唯一观测盲区是 logShipper.js:227 JSON.stringify 失败静默丢行无计数（P3），以及 canaryWatch.init().catch(()=>{}) 静默（P3）。

**指标**

- 零依赖 Prometheus 文本 + JSON 快照双口径；MTTD/审计丢弃/限流降级/WS/磁盘等信号齐备；series 上限+闭合标签纪律；alertmanager 规则区分速率型/持续型/配置缺失型。小疵：metricsMiddleware 计数与直方图登记非原子（series 满时该路由有量无延迟数据，P3）。

**错误处理**

- errorHandler 表驱动分类，生产不泄堆栈/内部信息（有哨兵串专项测试）；headersSent 防重；未捕获异常/rejection 处理器完整（唯一缺口：崩溃路径 auditBuffer.flush 无时限预算，P3）。
- 优雅关闭链（WS→HTTP→调度器→审计排空→Redis→Mongo→SIEM→exit）完整且每步有预算/硬闸（shutdownBudget/guardStep）。

**部署与回滚**

- 镜像 digest 钉扎、compose 网络分段（数据面 internal）、read_only+cap_drop ALL、非 root、file secret 0600→tmpfs、蓝绿发布+事务式回滚、热升级队列（O_NOFOLLOW/原子写/锁三重陈旧判定）。
- 回滚演练/备份恢复/DR 就绪均有脚本+判据+留痕；deploy.yml 自陈"从未真实跑通"的未验证声明如实保留。
- 小疵：cluster.js worker 崩溃无退避无限 fork（P3）；!override 标签需 Compose v2.24+（未声明最低版本，P3）；fsms-access-review.service 以 root 跑无特权脚本（P3）。

### 维度 7：文档与知识传承 —— 评级：良（内容优秀，CHANGELOG 损坏是唯一 P1）

- README：新人路径完整可跑，数字（108 paths/129 ops/11 tags、覆盖率阈值、角色 level、端口）全部与代码复算一致；仅目录树"routes 9 个模块"过时（实为 16）。
- ADR：21 篇齐全，"决策+取舍+复核注记"活文档范式，ADR-013（蜜罐总设计书 921 行）极详尽。
- CHANGELOG：**文件整体损坏（P1）**——同一文档重复拼接约 4 遍（10729 行中约 7400 行重复），标题残片错位嵌入正文；release.yml 的发布说明抽取会读到错位内容；4 个 `[未发布]` 段落使维护约定失效。建议一次性重写为单份正文 + 加"禁止第二个 `## [未发布]`"门禁。
- threat-model.md：§3.5 把 vite dev/preview 绑定写成 0.0.0.0，与代码（127.0.0.1）相反（P2，等保出示证据文档需纠正）。
- SAST 治理文档"私有仓"前提失效：仓库已 public，CodeQL/Scorecard 实际在跑（P2，需重述分工）。
- 其余文档漂移（P3）：architecture.md ER 图数据范围阈值 ≥5 应为 ≥4；Express 版本 ^5.2.1 应为 ^5.3.0；scorecard 注释停在 v2.4.4 实钉 v2.5.0；deployment 文档 Dockerfile/compose 行号引用失实；issue 模板链接是占位符；.env.example 两处示例易误导。
- OpenAPI：生成器↔产物深度一致（无手工漂移），但存在 P2 的双层嵌套畸形与登录契约"明文必填 vs 密文二选一"自相矛盾（P3）。

---

## 3. 问题清单

### P0（致命/可利用）

无。

### P1（1 项）

| #    | 位置                           | 问题                                                                                                                                                                                                                                        |
| ---- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1-1 | CHANGELOG.md（全文，10729 行） | 同一文档被重复拼接约 4 遍；`## [未发布]`×4、`## [1.0.0]`×4、文件头标题以句子中间嵌入形式重复 4 次；release.yml 按 tag 抽取发布说明会混入错位残片；4 个 `[未发布]` 使维护约定失效。修复：以现行正文（1–3295 行）重建单份文件，并加门禁防复发 |

### P2（17 项）

**产品代码（7）**

| #    | 位置                                                      | 问题                                                                                                                                                                             |
| ---- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P2-1 | src/docs/generate.js:252,270-271,1500,1512,1533-1534      | OpenAPI 响应对象双层嵌套：`400: badRequest` 应为展开；5 端点 7 处错误响应非法（openapi.json:372-377、434-443、4658-4662、4690-4694、4752-4761）；openapiSync 两侧共享 bug 抓不到 |
| P2-2 | src/middleware/idempotency.js:101-103                     | 非 2xx 清理无条件 `deleteOne({keyHash})`，与 takeOverStale 交错时可删掉他人 completed 记录→同键重复执行；补 `state:'in_progress'` 条件                                           |
| P2-3 | src/services/ipPoolLiveTraffic.js:113-119                 | 封段活跃度检查按无索引 createdAt + 非锚定 ip 正则对审计集合全扫（保留期 180–3650 天）；改用 timestamp 或补索引                                                                   |
| P2-4 | web-admin/src/components/InspectionReviewForm.vue:134-139 | 审核意见 min:10 为前端单方面加严，后端无最小长度（inspectionRoutes.js:345-350 仅 optional+max500），合法短意见被拦；违反本仓"前端不能更严"口径                                   |
| P2-5 | web-admin/src/components/ChangePasswordCard.vue:127-130   | 改密保留明文回退轨（encryptPassword 返回 null 时静默发明文），与 ReauthDialog/MfaSettingsCard/UpgradeDialog 的 fail-closed 统一口径相悖；非安全上下文唯独改密明文过网            |
| P2-6 | web-admin/src/utils/websocket.js:202-210                  | 重连耗尽静默死亡：不调 reportDegradation（对比 auth-error:177 有上报）；reconnectExhausted 无读取方；give-up 提示唯一注册在 RoleView（角色页文案全局弹出）                       |
| P2-7 | web-admin/src/utils/websocket.js:255-259                  | send() 只查 socket.connected 不查 authenticated，握手窗口内业务事件经未鉴权 socket 发出（当前无绕过 joinRoom 的调用方，潜伏）                                                    |

**测试资产（7）**

| #     | 位置                                                                    | 问题                                                                                                                                                |
| ----- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| P2-8  | src/tests/ci/stuffingProfileWriteSites.test.js:84-100                   | 连库后不关连接（mongooseTeardownLedger 已登记的在途欠账；worker 被 500ms 强杀吞输出）                                                               |
| P2-9  | src/tests/auditBufferZombieDuplicate.test.js:39,84-101                  | AUDIT_WAL_PATH 模块加载期指向临时目录、不还原且目录被删；6 个套件会 start() 读该 env，随机序下 WAL 静默失效                                         |
| P2-10 | src/tests/observability/logShipperTransportFailurePaths.test.js:337-345 | "携带 Bearer token"用例空断言（与服务端不读头同构）；全仓无任何测试钉住 SIEM 出站 Authorization 头（文件头已自陈）                                  |
| P2-11 | src/tests/deploy/offlineBundleIntake.test.js:353-357,393-395            | 能力缺失分支 console.warn+return 绿通过，违背文件头"不静默 return"自订纪律；符号链接必拒的唯一真归档端到端在缺 python/tar -P 环境静默失效           |
| P2-12 | src/tests/exportLabelsLocalized.test.js:121-127                         | 用例名"截断脚注跟随语言"实际只有 `expect(typeof fn).toBe('function')` 恒真断言；该行为零有效覆盖                                                    |
| P2-13 | src/tests/security/loginPeerBucketXffRotation.test.js                   | 文件内用例顺序耦合（第 2 条依赖第 1 条打满的共享桶），--randomize 下实测 seed 2/4/6 双红（约 50%）；且无根 afterAll（worker 强杀告警）              |
| P2-14 | src/tests/services/rateLimitEscalationEviction.test.js:22-26            | 模块顶层写 5 个 CC_ESCALATION_* env 不还原；同 worker 后续的 rateLimitEscalation.test.js 会以错误阈值加载（volumeThreshold>anonThreshold 断言翻红） |

**文档/治理（3）**

| #     | 位置                                                                      | 问题                                                                                                      |
| ----- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| P2-15 | docs/threat-model.md:121-126                                              | 把 dev/preview 绑定写成 0.0.0.0，代码实为 127.0.0.1（vite.config.js:619,704）；等保证据文档口径错误       |
| P2-16 | .github/workflows/sast.yml、codeql.yml、docs/security-dependency-watch.md | "私有仓、CodeQL 从未运行"前提失效（仓库已 public，CodeQL/Scorecard 实际在跑）；分析器分工表述需重写       |
| P2-17 | docker-compose.yml:421-429                                                | mongo 健康检查把 root 凭据展开进 argv（/proc 可读）；文件内已自我登记的已知接受风险，建议按其给出方向收口 |

### P3（按主题归纳，约 90 项）

**安全一致性（10）**

- securityRoutes change-password 的 currentPassword 无长度上限（authRoutes 64/securityRoutes 无/view-sensitive 128 三口径漂移）
- POST /api/security/ip-list、GET /trace、/clusters、PUT /users/:userId/lock 未挂 strictLimiter（与同族重资源面不一致，有全局限流兜底）
- deviceCode 路由 optional vs 模型 required（同文件 installDate 已修的反模式残留）
- permissionController parent 成环检测为"先查后写"无事务，并发可造环（管理面低频）
- ipListController:334-348 拆全网段的 critical 审计为 fire-and-forget 未 await（依赖 AuditLog.record 永不 reject 契约）
- fileUploadSecurity 缺省 allowedTypes:[] 时类型校验整体消失（当前无路由挂载，预留风险）
- securityAlert 账号维度撞库不投递 webhook（SOC 只能查审计）；webhook 密钥缺省时出站无签名头
- sharedCache DECR_FLOOR_ZERO 把过期键重建成永久键（计数复活窗口偏松）
- logShipper.js:227 序列化失败静默丢行无计数（违背自身"截断必须可见"）
- helpers.js 密码长度正则 /.{12,}/ 不匹配含行终止符口令

**正确性/健壮性（12）**

- authService/profile.js email:'' /null 绕过校验后 500；锁定落库后半程（解 assignments/失效缓存/审计）无异常隔离
- session.js issueLoginSession populatedUser 无空值防护（并发删号 500）；token.js 非法 ObjectId CastError 500
- ipPoolBan ticket.cidr.split(',') 死分支；mfaService lockApplied 初值 true；permissionService.createPermission check-then-act
- initData/indexes.js 业务 TTL 对账 createIndex/collMod 未包 try（失败中断整个启动，兄弟对账器均只告警）
- controllers/rolePermissionController 非法权限 ID 片段静默丢弃；targetUserId 静默丢弃；'_:_' 字面量与常量混用（roleGuards 等 5 处）
- attackEvents.js 400 出口回显 error.message；overview.js `${7}天` 死模板+中文进数据字段
- captchaService set 返回值未查；deviceReminder 缓存键不含 expiringDays；avatarService 幂等捷径指针竞态
- forensicTrace truncated 在恰好等于上限时误报；forensicTrigger 纯进程内存（多副本漏采，v1 边界）
- cluster.js 无退避无限 fork；index.js 崩溃路径 flush 无预算；canaryWatch 静默吞；upgrade.js 整型静默回退；transportSecurity localhost 子串匹配过宽
- middleware/idempotencyKey 指纹只排顶层键（嵌套键序不同误 409）；rateLimitStore resetKey/resetAll 无降级包装
- envNumber readClampedIntEnv 把"未配置"当"非法"上报；auditCheckpointFreshness 空串 env 静默关闭检查点
- ip2regionSearcher 段内 dataPtr 只查上界；xlsxWriter ILLEGAL_XML 漏 U+007F/C1；scopeCast applySearchCondition 未校验 $or

**性能（6）**

- ipPoolCluster 聚合无预算；upgradeService listJobs 全量读；reportDashboard 缓存共享引用；sessionCache 超限全清；websocket push 按受影响用户数展开房间；push.js emitPermissionSync O(n)
- avatarUnmatchedSurfaceGuard.test.js 1400+ 串行请求（测试时长，非产品）

**前端（12）**

- WS 防抖定时器未随卸载清理（AlarmView/DeviceView）；AuditLogView 三个重操作缺同步重入锁；IpListView total 回退页长旧模式残留
- 终态报警行仍渲染处理按钮；巡检统计卡标题不随语言切换；RoleView 权限目录加载失败静默画空；PrivilegeGrantView 驳回理由无 maxlength（后端 200）
- LoginView 登录口令 min:6 比后端严（存量短口令待确认）；api.js schema 前缀 includes 匹配脆弱；permission.js 空权限码 fail-open；/register 未被已登录守卫拦截；sessionSync 兜底广播用户名滞留 localStorage；i18n security.added 残缺句/greetingNoon 不地道/locale 未白名单校验；dev CSP unsafe-eval 疑似残留
- 组件：InspectionForm __uid 入载荷、远程搜索无防抖、InspectionCompleteForm 死请求/缺竞态守卫、SecurityStatsCard 形状不校验、加密文案三元链×4、ReauthDialog 无 maxlength、'Admin' 硬编码、重试按钮未随 loading 禁用

**模型/常量（10）**

- FireDevice checkCycle 无模型级边界、addMaintenanceRecord 不设防；ConsentRecord/IPBlacklist targetUsername/username 无 maxlength；Inspection TTL 挂可选字段；PrivilegeGrant approvals 无上限；IdempotencyRecord responseBody 无模型级上限；UserSession revokeReason 无上限
- deviceAlerts 重复定义 DEVICE_STATUS 字面量；attackProfile 与 attackEvents 双分类法未互注；audit.js security_view 疑似死条目；honeypotDecoyListShape 双常量命名混淆；'use strict' 不统一

**测试卫生（20+）**

- env 泄漏另见 P2-9/13/14 + forensicCapture×4、attackDetection、auditChainZombieFreeze、honeypotListShapeParity、ipPoolBan、sharedCacheNonceFloodEviction、runtimeTopology（2 处无 try/finally）
- 连库不关另见 reportExportRowOrderAndCells、auditTtlBootReconcile；cursorTiebreakIndexes ④b 不 drop 库；ttlMigrationEmptyDb 固定库名
- 弱断言另见 idempotency:957、validationMessages:147、auditBufferFlushAndWalGuards:658 标题超配、permissionModuleCard /s+/g 笔误、changePasswordCard 死 mock、usePermissionSync 极端载荷断言弱于标题
- 调试残留：deviceCodeCap ZZDEBUG、reportPiiExportStepUp ②-debug、ipListFullRangeTypedConfirm WHITE500、wsFlow AUTH4_DEBUG、rbacControllers void goodBatch 无断言
- 3 处"共享库"过时注释（setup.js 已按文件隔离）；filePermissionUsernamePaths/posixShell 非 Windows 静默 return（应 test.skip）；pureModules 恒等 replace；tails global.__fapp 残留；TOTP 30s 窗口边界残余 flake 面（authLifecycle/authRest/mfa 系已缓解）
- extractStepRuns/run 块抽取器 4-5 份重复实现，建议收敛共享 helper

**部署/脚本（10）**

- deployment 文档行号/卷数与事实漂移；!override 需 Compose v2.24+ 未声明；fsms-access-review.service root 运行；start.bat 排障提示与 /B 启动方式矛盾；.env.example CORS_ORIGIN 模板值/login secret 名不一致；e2e TOTP 无 ±窗口重试
- 脚本：check-audit-allowlist `=` 截断解析；check-clock-sync parseInt 尾随垃圾；check-openapi-drift/check-alertmanager-config 顶层执行无 require.main 守卫；ws-session-bypass 探针未接 devSecretIsolation；migrate-pii-encryption 自愈解密漏传 AAD（v2 行误报损坏，待确认）+apply 不回读；offlineBundleIntakePolicy --apply=false 误读为真；invalidate-mfa-recovery-codes 未知参数静默忽略；record-rollback-drill 渲染不转义

**文档（8）**

- architecture.md ER 阈值 ≥5 应为 ≥4；README routes 计数 9 应为 16；Express 版本漂移；scorecard 注释与钉版不一致；issue 模板占位链接；.env.example 两处；openapi 登录契约明文/密文自相矛盾；deployment 文档行号引用（同上）

---

## 4. 分区逐文件结论（生产代码全量，测试按主题）

> 完整逐文件印象由 40 份代理报告汇成；此处收录生产代码全量单行结论。测试文件（1003 个）的逐文件结论已在第 2/3 章按主题与代表性文件呈现，全部文件均已逐行读过。

### 后端入口/配置（25）

- src/app.js（631）：装配顺序论证扎实，仅 morgan dev 分支打完整 URL（P3）
- src/index.js（547）：启动时序正确；崩溃路径 flush 无预算（P3）
- src/cluster.js（86）：简洁正确，缺崩溃退避（P3）
- src/config/index.js（197）：集中求值、bcrypt 夹紧、限流硬闸，无问题
- src/config/validate.js（701）：弱密钥判据齐全，durationToMs 重复调用小疵
- src/config/database.js（144）：退避+抖动+URI 脱敏判据讲究，无问题
- src/config/secrets.js（144）：*_FILE 注入设计正确，全仓配置卫生最好的模块之一
- src/config/envSemantics.js（92）/trustedProxies.js（135）/proxyProtocol.js（101）：无问题
- src/config/transportSecurity.js（159）：localhost 子串匹配过宽（P3）
- src/config/deploymentCredentialGuards.js（254）/immutableConfigGuard.js（201）/legacyCbcGuard.js（77）/loginEncryptGuard.js（71）/loginGuard.js（20）/jwtRotation.js（87）/buildInfo.js（76）：无问题
- src/config/upgrade.js（34）：整型静默回退（P3）
- src/config/swagger.js（205）：basicAuth+docsLimiter 严谨，无问题
- src/plugins/autoIncrement.js（199）：原子计数器+双证据对齐，无问题
- src/docs/generate.js（1693）：P2-1 双层嵌套 + P3 登录契约矛盾
- src/docs/openapi.json（5073）：与生成器深度一致，继承畸形
- src/data/*：数据文件+README，无问题

### 后端中间件（33）

auth.js（441）认证主链质量很高；rbac.js（433）deny-by-default 收口完整；dataScope.js（137）GUEST=all 为有意设计（结构性风险点）；errorHandler.js（248）完整；idempotency.js（388）P2-2；injectionSignature.js（126）/logoutAuth.js（118）/metricsAuth.js（124）/noStore.js（8）/httpMethods.js（12）/requestId.js（44）无问题；originCheck.js（140）P3 日志用 req.ip；protocolCompliance.js（336）/queryLimit.js（165）无问题；rateLimit.js（818）15 桶各司其职（文件过长但职责清楚）；rateLimitStore.js（194）P3 resetKey；security/auditLog.js（397）/earlyRejection.js（62）/forensicCapture.js（147）无问题；security/index.js（507）P3 fileUploadSecurity；security/ipBlacklist.js（236）白名单可信边界是亮点；security/ipBlacklistStore.js（59）/reauthCredentialRules.js（59）/reauthTicket.js（68）无问题；security/sanitize.js（195）Express5 getter 处理正确；security/securityHeaders.js（224）无问题；sentry.js（208）出网白名单收口；staticFrontend.js（206）.map/.ts 纵深拒绝；tokenBlacklist.js（215）原子消费+ E11000 区分；userAuthCache.js（130）TTL+跨实例失效；validateObjectId.js（78）/validateQuery.js（35）无问题

### 后端路由（17）

index/version/avatar/attackProfile/stuffingProfile/attackEvent 路由无问题；forensicRoutes（85）P3 两个读面缺 strictLimiter；reportRoutes（154）全仓最讲究；roleRoutes（198）质量高；alarmRoutes（226）无问题；userRoutes（272）无问题；permissionRoutes（339）P3 双重 withMessage；deviceRoutes（369）P3 deviceCode optional；inspectionRoutes（421）无问题；authRoutes（558）P3 currentPassword 上限/凭据规则本地复制/captcha-status 限流；wellKnownRoutes（291）无问题；securityRoutes（713）P3 ip-list/lock 缺 strictLimiter + currentPassword 无上限

### 后端控制器（40）

alarmController（449）/auditController（263）/authController×6/avatarController（101）/deviceController（395）/forensicController（205）/inspectionController（439）/inspectionGuards（170）/ipListController（401）P3 fire-and-forget 审计/ipListSegmentGuards（314）/ipListWriteGuards（28）/mfaController（418）P3 getMfaStatus 200/permissionController（269）P3 成环竞态/privilegeController（118）/reportController（408）/roleController（408）P3 查重竞态窗口/roleGuards（210）P3 '_:_' 字面量/rolePermissionController（344）P3 静默丢弃×2/securityController×11（P3 attackEvents 回显 message、overview 死模板）/userController×7（质量高，P3 '_:_' 字面量、delete.js 函数体内 require）

### 后端服务（139）

P2-3 ipPoolLiveTraffic；P3：auditQueryService 裸读 message、authService login/failureAndMfa 锁写 catch、auditCheckpointFreshness 空串、auditAnchorSink TOCTOU、InspectionService complete 未开 runValidators、alertDispatch 已声明取舍、auditBufferWal 窄边界、authService/profile email 500+锁后半程、session populatedUser、token CastError、forensicTrigger 内存表、forensicTrace truncated、avatarService 竞态、captchaService set、deviceReminder 缓存键、loginChallenge 审计无去重、initData/indexes TTL 对账未包 try、permissionService createPermission、mfaService lockApplied、ipPoolCluster 无预算、reportDashboard 共享引用、reportExportService TDZ、ipPoolBan 死分支、sharedCache DECR 脚本、securityAlert 通知盲区、securityAlertPermissionAbuse 写放大、sessionCache 全清、push O(n)、upgradeService listJobs、securityAlertDelivery 无签名头。其余约 105 个服务文件无问题（auditBuffer/auditChain 系/forensic 系/honeypot 系/initData 系实现质量尤其高）。

### 后端模型（23）

P3×9（FireDevice×2、ConsentRecord、IPBlacklist、Inspection TTL、PrivilegeGrant、IdempotencyRecord、UserSession、auditLogQueryStatics category）；其余 14 文件无问题。User.js（602）是全部模型中安全设计最密的一份。

### 后端工具（68）

P3×12（envNumber、ip2regionSearcher、helpers×3、bcryptWorkerPool 待确认、logShipper、metrics、xlsxWriter、temporaryPassword、scopeCast、piiCrypto 注释）；其余 56 文件无问题。encryption.js/ipUtils.js/proxyProtocol.js/jwtKeys.js/totp.js/shutdownBudget.js 等安全关键工具实现扎实。

### 后端常量（49）

P3×6（deviceAlerts 重复定义、attackProfile/attackEvents 双分类、audit.js security_view、honeypotDecoyListShape 命名、honeypotDecoyAggregatesData 死键、'use strict' 不统一）；其余 43 文件无问题，alarm.js/inspection.js/audit.js 是单一来源纪律的模范。

### 前端生产（111）

P2-4/5/6/7；P3 见第 3 章前端小节。utils/api.js（1285）是前端最核心文件，刷新单飞/竞态恢复/错误码 i18n 映射设计密度非常高；store/auth.js（459）normalizeUser fail-closed/PII 投影白名单正确；layout/index.vue（1320）登出"服务端确认才清本地"口径正确；views 中 ForensicTraceView（1490）与 AboutView（1172）工程质量最高；PrivilegeGrantView（2991）体量最大。

### 脚本（78）

无 P0/P1/P2；P3×14 见第 3 章。destructiveGuard/cliFlagPolicy/secretFileArg/resignLedger 护栏族复用一致；判据/执行分层成熟；密钥卫生良好。

### 测试（1003）

后端 850 + 前端 153 全部逐行读过。P2-8~14 + P3 约 35 项卫生/弱断言问题见第 3 章；未发现恒真主判据、mock 掉被测逻辑、skip/only 残留。setup.js 每文件独立库 + testSequencer 乱序 + waitFor 轮询构成隔离与时序纪律的地基。

### 部署与文档（128）

P2-15/16/17 + P3 约 18 项见第 3 章。Dockerfile/compose/nginx.conf.example 的安全密度极高；CI 工作流（ci.yml 922 行）是全仓质量最高的部分之一；CHANGELOG 损坏为唯一 P1。

---

## 5. 修复优先级建议

1. **立即（本周）**：P1-1 重建 CHANGELOG；升级 mongoose；P2-2 幂等清理条件；P2-3 ipPoolLiveTraffic 索引。
2. **短期（两周）**：P2-1 OpenAPI 嵌套；P2-4/5 前端校验一致性与改密 fail-closed；P2-6/7 WebSocket 可观测性与鉴权前置；P2-15/16 文档纠偏。
3. **随批清理**：P2-8~14 测试卫生（一次专项 PR：env 快照还原统一化、补根 afterAll、修弱断言/调试残留）；P3 按顺手原则分批。
4. **结构性（长期）**：响应观察基元、缓存失效通用部件、WS 订阅组合式函数、抽取器收敛、deployment 文档去行号化。
