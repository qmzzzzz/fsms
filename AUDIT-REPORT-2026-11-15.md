# fsms 全仓独立审计报告（2026-11-15）

- 审计对象：`D:/桌面/fsms` @ commit `35aa3c3`（"fix(audit): 2026-11-14 全仓审计修复收敛——P1×1、P2×17、P3 全量落地"）
- 审计方式：**全新独立审计**。不依赖、不参考 `AUDIT-REPORT-2026-11-14.md` 及任何历史审计结论（该文件在本次审计中被有意排除在阅读范围外）；全部结论基于当前工作区代码逐行精读独立得出。
- 组织方式：26 个并行审计分区（S00–S07 后端生产代码、T00–T07 后端测试、W00–W04 前端、SC00–SC01 运维脚本、S24 部署资产、S25 CI/迁移/E2E、S26 文档与根配置），每个分区由独立审计代理对分配文件**逐行完整精读**（无抽样、无跳行），并对跨文件疑点回读依赖后独立定性。
- 只读纪律：全程未修改/创建/删除仓库内任何文件。

---

## 0. 执行摘要

| 级别 | 数量 | 含义 |
| --- | --- | --- |
| P0（致命：可直接利用/数据损坏/越权） | **0** | — |
| P1（高：高概率缺陷或安全弱点） | **0** | — |
| P2（中：明确技术债/性能隐患/门禁缺口） | **36** | 见 §3 |
| P3（低：低风险改进/卫生项） | **181** | 见 §4 |

**总体结论**：该仓库（消防/安防管理系统，Express 5 + Mongoose 后端 + Vue 3 前端）的工程与安全水位**显著高于常见同规模项目**。本轮逐行精读 1,765 个跟踪文件中的 1,762 个（其余 3 个为二进制数据文件/生成物/旧报告，见 §1 特殊处理），**未发现任何可直接利用的越权、注入、认证绕过或数据损坏问题**。

安全基本面已系统化落地并相互自洽：认证（登录防枚举/侧信道拉平/MFA 原子消费/刷新轮换/登出全吊销）、授权（RBAC + 数据范围缺省即 deny + 记录级范围闸单源）、审计哈希链（WAL/预铸造/僵尸自愈/外锚/周期核验 fail-closed）、PII 字段级加密（GCM+AAD 行绑定+盲索引）、输入防线（queryScalarGuard/materializeQuery 自证/控制字符清洗/日志 PII 掩码）、限流（IP/账号/对端多维度+降级可观测）、蜜罐与诱饵数据面、离线升级包签名链、CI 全链 SHA 钉死+权限最小化+门禁 fail-closed。测试资产（855 个后端测试文件 + 前端 Vitest 套件）以行为断言为主，普遍带"前提自证+反向对照+变异实测"三件套，无空测试/恒真断言/静默 skip。

剩余 36 项 P2 集中在五类：**性能/资源隐患**（无投影大查询、无界 Map、整文件重写、数组无封顶）、**门禁自身的盲区**（权限码对账闸不扫嵌套目录、compliance-check 仅文本断言、@media print 闸贪婪正则）、**测试间 env/夹具泄漏**（同 worker 进程级污染，`--randomize` 下顺序相关偶发红）、**供应链/部署验证缺口**（mongod 缓存命中不复核哈希、deploy.yml 从未实跑、迁移白名单 fail-open）、**文档-实现漂移**（回滚手册颜色/端口冲突、数据分类台账与加密实现不符、OpenAPI 未收录 8 个实际端点）。181 项 P3 为低风险改进与卫生项。

---

## 1. 审计方法与覆盖率

### 1.1 分区与执行

| 分区 | 范围 | 文件数 | 精读行数 |
| --- | --- | --- | --- |
| S00–S02 | src/services（全部 140 个服务文件，按字母序三等分） | 140 | ≈30,400 |
| S03 | src/controllers + src/routes | 57 | 13,087 |
| S04 | src/config + src/middleware | 50 | 9,428 |
| S05 | src/models + src/utils（前半） | 59 | 11,773 |
| S06 | src/utils（后半）+ src/constants | 83 | 13,557 |
| S07 | src/app.js、index.js、cluster.js、plugins、docs、data | 8 | ≈5,600（代码部分） |
| T00–T07 | src/tests（全部 855 个后端测试文件，八等分） | 855 | ≈219,000 |
| W00–W04 | web-admin（全部 291 个文件：配置/组件/composables/i18n/router/store/utils/views/测试） | 291 | ≈111,600 |
| SC00–SC01 | scripts/（全部 90 个运维脚本） | 90 | 26,608 |
| S24 | Dockerfile、docker-compose、docker/、deployment/（34 个部署资产） | 34 | 6,283 |
| S25 | .github/、migrations/、e2e/、根测试/ESLint/Jest/Playwright 配置 | 40 | 5,494 |
| S26 | 根 dotfiles、package.json(-lock)、根文档、docs/ 全部 40 篇 | 57 | ≈21,000 |
| **合计** | | **1,764 项条目**（含跨分区复读） | **≈475,000 行** |

### 1.2 覆盖率核对（实读 vs `git ls-files`）

- `git ls-files` 跟踪文件：**1,765** 个。
- 26 份分区报告上报的"实际完整读取"清单取并集、路径归一化后：**1,774** 个唯一路径（含少量跨分区交叉复读，如 web-admin 根配置同时被 W00 与 S26 覆盖）。
- **未逐行精读的仅 3 个**，均为有意处理：
  1. `src/data/ip2region.xdb` — 11MB 二进制 IP 库。改做校验链核验：sha256 与 `deployment/ip2region-checksum.json` 内容锚一致、v2 结构校验与三探针通过（S07）。
  2. `src/docs/openapi.json` — 生成物。改做结构校验 + 与 `src/routes/**` 全量路由对账（108 path/129 operation，与生成器逐字节一致；发现 8 个规范外端点，见 P2-12）（S07）。
  3. `AUDIT-REPORT-2026-11-14.md` — 旧审计报告，按"不依赖原有报告"要求**有意不读**。
- 根/前端 `package-lock.json`（2 份）按分区铁律不做逐行，改做依赖风险检查（见 §5）。

### 1.3 辅助扫描

- `npm audit`（根 + web-admin，2026-11-15）：见 §5。
- gitleaks：本机未安装，未执行引擎扫描；作为替代，S26 分区对 `.gitleaks.toml`/`.gitleaksignore` 豁免面、`.env.example` 全文、各配置文件做了人工凭据排查，**未发现真实凭据入库**。
- 各分区代理另做了大量只读交叉核验（路由↔OpenAPI 对账、指标名存在性、脚本↔package.json 一致性、ADR↔代码逐符号比对、README 声明逐项实测等），结果并入各发现。

---

## 2. 七维度总体评估

### 维度 1：代码质量与规范性 —— 良好

命名语义清晰、格式统一（ESLint+Prettier+eslint.ratchet 棘轮+commentDensity 棘轮门禁在 CI 强制）。复杂度控制好：后端单文件最大 1,696 行（generate.js，生成器）；前端存在 4 个超长 God components（AuditLogView 2001 行、PrivilegeGrantView 2997 行、UserView 1617 行、RegisterView 1661 行，P3 已列）。DRY 执行好但仍有热点：登录失败计数逻辑 3 份拷贝、前端 reauth 错误解包 4–5 份拷贝、迁移幂等判据 6 份拷贝（该条已升 P2-35）。注释纪律突出：关键安全取舍均有"为什么"注释与能力边界声明，且有注释密度棘轮防退化。

### 维度 2：架构设计与工程结构 —— 良好

分层（routes→controllers→services→models）边界清晰，layeringRatchet/requireCycles 架构测试在 CI 强制； controllers 直连 models 有基线棘轮。配置全部外部化（env + 0600 密钥文件 + `:?` 强制变量），无硬编码凭据；ENV_KEY 字符串拼接（P3）与少数 CORS/常量双份声明（P3）是残留。两处分层倒置（utils→services 反向依赖）与 /audit-logs 处理器住 service 层为已登记的结构债（P3）。

### 维度 3：安全性 —— 优秀（本轮 0 可利用发现）

输入验证（express-validator 链 + queryScalarGuard + materializeQuery 自证 + mustBeString 闸）、注入防护（NoSQL 注入/原型污染/operator 注入端到端测试钉住）、认证（ECDH 信封密文轨、防枚举时序拉平、MFA TOTP 原子消费、JWT kid 轮换、tokenVersion、会话代际）、授权（checkPermission + 数据范围缺省 deny + 记录级 assertRecordInScope 单源）、敏感数据（PII GCM+AAD、盲索引、日志 PII 掩码、错误响应脱敏、凭据不进 argv/日志）均到位。残留：日志注入小面（rateLimit.js:437 username 插值，P2-07；errorHandler CastError，P3）、白名单豁免"私网对端即可信"判据（已登记 R3 残余风险，P3 复核确认仍成立）、取证 pepper 缺失时摘要退化（P2-05）、photo 字段后端仅限长度（P2-25）。

### 维度 4：性能与资源效率 —— 良好，有 8 项明确隐患

索引设计体系化（游标分页复合索引+平局键，explain 级测试钉住，queryPerformanceIndexes 迁移）；列表普遍分页+游标化；查询预算（queryBudget）与导出并发槽位管控在位。本轮发现的资源隐患：auditChainVerify 无投影 20 万条全字段进内存（P2-01）、forensicCapture ipWindows 无界 Map（P2-02）、forensicCaptureWal 整文件读/重写（P2-04）、devices 导出无投影（P2-06）、FireAlarm.processLog 无封顶（P2-08）、DashboardCharts 主题/语言切换整表重拉、webVitals INP 数组无界、api.js AbortSignal 监听不移除（均 P3）。热路径 O(n²) 未发现；bcrypt 走 Worker 池不阻塞事件循环。

### 维度 5：测试覆盖与可靠性 —— 优秀（测试资产是本仓最强项）

945+ 个测试文件（后端 Jest 855 + 前端 Vitest + Playwright E2E + ops-e2e + production-drill + k6）。覆盖率门禁真实阻断（`jest --coverage` 无 `--if-present`，逐文件阈值棘轮）；异步一律条件等待并以 noFixedSleepRatchet 全树禁绝固定睡眠；故障注入（DB 抖动/EPERM/非 Error 拒绝/部分成功/时钟回拨）覆盖扎实。弱点：个别断言强度不足（refresh 监视器瞄错对象 P2-28、缓存命中断言 P2-15）、权限码对账闸扫描面缺口（P2-20）、同 worker env/夹具泄漏家族（P2-14/16/17/18/21 等）、compliance-check 门禁仅文本断言（P2-13）、deploy.yml 从未实跑（P2-33）。

### 维度 6：可观测性与运维友好度 —— 优秀

结构化日志 + PII 掩码 + 控制字符中和 + SIEM 转发（SSRF/DNS 钉扎防护）+ 断档标记防伪造；Prometheus 指标闭集标签防高基数，告警规则 21 条覆盖错误率/P95/审计丢弃/WAL/磁盘/就绪/fail-open 降级，且指标名经测试对账全部存在；/readyz 双失败路径、优雅关闭总预算+逐步硬闸、蓝绿热升级机制完整。残留：morgan 晚于早期拒绝闸门（403/429 不进访问日志，P3，审计+指标已补偿）、refreshToken 兜底 catch 吞故障成 400 零日志（P3）、getMenuTree 吞 DB 故障成空菜单（P3）、auditChainFence 僵尸冻结无上界无独立告警（P3）。

### 维度 7：文档与知识传承 —— 优秀

README 可核对声明经实测逐项相符（OpenAPI 数、告警数、CI 矩阵、镜像 digest、compose 强制变量）；21 篇 ADR 完整且抽查 ADR-015/019/021 与代码逐符号一致；CHANGELOG 3,253 行可追溯（存在 1 处表格损坏 + 6 条缺日期，P3）；docs/ 18 篇专题文档与实现同步（threat-model 1 处已收口风险未更新，P3）。web-admin/README 过薄（P3）。

---

## 3. P2 发现明细（36 项，全部应排期修复）

### A. 后端生产代码（12 项）

**P2-01 [D4] src/services/auditChainVerify.js:339-356 — 链校验取数无投影，最多 20 万条完整审计文档一次性进内存**
`AuditLog.find(scan.filter, null, windowOptions)...limit(scan.maxRecords)` 无 `.select()`；`HARD_MAX_RECORDS=200000`。哈希校验只需 hash/prevHash/hmac/canonicalPayload 白名单字段，却按全字段（含 body/params/query 大字段）取回。审计集合变大后，管理端 verify 接口一次默认窗口可加载数十至几百 MB，离线脚本按 20 万条上限执行有 OOM 风险。建议：按 `utils/auditChain` 载荷白名单加投影，校验语义不变、内存降一个量级。

**P2-02 [D4] src/services/forensicCapture.js:54,114-127 — 取证单 IP 配额窗口 Map 只写不删，按去重来源 IP 无界增长**
`state.ipWindows.set(ip, win)` 唯一清空点是生产不调用的 `resetForTests()`。代理轮换攻击下不同 IP 数可达万级，内存随攻击规模单调增长永不回收（同仓 alertDispatch/captchaService/auditScopeFilter 同类结构均有界，唯独此处没有）。建议：加容量上限+插入序淘汰，或窗口过期惰性删除。

**P2-03 [D5] src/services/forensicExport.js:68 — verifyExport 对缺 `records` 的畸形包直接抛 TypeError，而非返回 `{ok:false}`**
`digestOf(pkg.records)` → `sha256(canonicalJson(undefined))` 抛 TypeError。该函数是"校验不可信导出包"的安全原语（当前仅测试调用，接上接口即暴露）；校验器被畸形输入打断成 500，违背其自身"任何一步不确定都返回 ok:false 并点名原因"的契约。建议：补 `Array.isArray(pkg.records)` 守卫，与 buildExport 对齐。

**P2-04 [D4] src/services/forensicCaptureWal.js:66,110,178 — WAL 每次裁剪/查容整文件读入内存再原子重写**
`trimBySeqs` 每次成功落库后 readFile→逐行 parse→atomicReplace 整文件；`enforceWalCap`（每 32 次 append 触发）也整文件读入。上限 50MB 下，"DB 故障+捕获风暴"场景每 32 条追加就有一次 50MB 字符串读入+数十万元素数组（内存峰值约 150MB 量级），全部在主事件循环上。建议：按已消费位点增量裁剪，或流式统计只重写保留段。

**P2-05 [D3] src/services/forensicCapturePayload.js:79,85 — pepper 缺失时，取证副本中的口令/恢复码摘要静默退化为无盐 sha256**
`digestOf` 在 `hmacSecret` 取不到时退化为无盐 sha256（utils/passwordHistory 同源）。取证副本正是会落盘、会导出、长期留存的数据；低熵口令在导出件里变成 GPU 可穷举快哈希，且退化完全无日志、无指标。生产语义下 config/validate 强制强 HMAC_SECRET，风险窗口主要是 dev/test 与 config 加载早期。建议：pepper 缺失时不产出可用摘要（`{len, hmac:null}` 或整体 `***`）并打 error。

**P2-06 [D4] src/services/reportExportService.js:126 — devices 导出未声明 select，整文档（含每台最多 200 条维保子文档）被拉进进程**
`EXPORT_MODEL_CONFIG.devices` 无 `select`；行变换只消费 7 列。5000 行上限的设备导出最坏传输并解析约 10^6 个维保子文档后在 addRow 前丢弃。建议：补 select 白名单（与 transforms 消费面一致）。

**P2-07 [D3/D6] src/middleware/rateLimit.js:437 — 未认证 username 只 trim/小写、不清控制字符即插值 printf 格式 warn 日志**
非生产传输下 message 内 `\n` 原样换行 = 伪造整行日志；攻击者提交形如 `admin\n2026-11-15 ERROR audit chain broken` 的用户名并触发账号维度限流即可在 combined-*.log 伪造任意内容，污染取证与人工研判。同文件其余限流器均用结构化 meta，唯独此处漂移。建议：插值前过 `stripControlChars(x, 64)` 或改结构化 meta。

**P2-08 [D4] src/models/FireAlarm.js:144-157 — `processLog` 处置记录数组无封顶、无计数载体**
与 FireDevice.maintenanceRecord/Inspection.executionLog 完全同型，而后两者均做了 200 条尾部封顶+计数字段（理由：数组被详情接口整段返回、被聚合 $unwind、无上限迟早撞 16MB 使文档不可再写）。建议：复用 pushCapped 口径 + `processLogCount` 留痕。

**P2-09 [D5] src/models/IPBlacklist.js:256-260 — `blockIP` 对 NaN/非数值 durationMs 的失败方向是"永久封禁"或管道报错**
`const asked = durationMs > 0 ? durationMs : 0` 把 NaN（上游解析失败的现实来源）静默判为永久封禁，误伤面不可自动恢复；字符串入参还会让 `$add`/`$max` 管道产出错误结果。建议：入口 `Number()` 显式收口，区分"业务永久（0）"与"非数值入参（应抛错/回落默认）"。

**P2-10 [D7] src/constants/dataClassification.js:124-130 — `User.mfaSecret` 台账声明"明文存库"，与实际 AES-256-GCM 加密实现不符**
`utils/mfaSecret.js` 已 fail-closed 加密落库（mfaController.js:195 唯一真实种子写点已加密）。数据分类分级是合规对账唯一声明源，把已加密字段登记为 plain 会低估现有控制、误导等保/个保法评审。建议：`atRest` 改 `'gcm'` 并登记 GCM_WITHOUT_GETTER，同步修正 reason 文案。

**P2-11 [D5] src/index.js:499-500 — SIGTERM/SIGINT 处理器在 listen 之后才注册，启动窗口内信号走默认硬杀**
DB 连接/初始化数据/链尾重同步进行中收到 SIGTERM 会立即终止，缓冲不排空（审计 WAL 重放可兜住数据不丢，但优雅退出完整性在启动窗口不成立，初始化可能截断在中间态）。建议：信号注册提升到模块加载期，启动未完成走短路径退出。

**P2-12 [D7] src/docs/openapi.json — 实际暴露面大于文档：8 个端点未入规范**
`/readyz`、`/metrics`、`/api/metrics`（带鉴权的管理面运行时指标）、`/api-docs`、`/api-docs.json`、`/csp-report`、`/client-errors`、`/.well-known/security.txt`+`/security.txt` 不在 spec 中。其余 108 path/129 operation 与路由实现全量对账零漂移（生成器↔产物逐字节一致，CI 漂移门禁在位）。建议：generate.js 补登这批端点，或在 info.description 显式声明规范外端点清单。

### B. 后端测试资产（12 项）

**P2-13 [D5] src/tests/config/deployScriptInvariants.test.js:276-285 — compliance-check 的留存合规判定只有文本断言，变异实测证明其失明**
文件头自述变异：把 `passed = meetsMinimum && !wasAdjusted` 改成 `passed = meetsMinimum`（机制破坏、文本保留）→ 33/33 全绿。CI 合规门的"留存期被钳制必须判失败"机制无任何可执行测试，revert 该判定 CI 依旧全绿。建议：补行为测试（子进程跑 compliance-check，喂 `wasAdjusted=true` 合成场景断言不通过）。

**P2-14 src/tests/constants/timezone.test.js:78-86 — 假定时器未用 try/finally 还原，断言前抛错即泄漏**
`jest.useFakeTimers().setSystemTime(...)` 后若 `businessDayBounds()` 抛错，`jest.useRealTimers()` 不执行，同 worker 后续所有测试文件的 mongoose/supertest 定时器被冻结，表现为大面积超时、真实原因被掩盖（本仓 reportExportInputGuards 已有 try/finally 正确范式）。建议：循环体包 try/finally。

**P2-15 src/tests/controllers/reportExport.test.js:111-119 — 「二次命中缓存」断言无法证伪缓存回归**
只用 `toEqual` 比对两次响应，删掉控制器缓存读写该用例照样绿——"控制器确实走了 dashboardCache"这层接线无判据。建议：spy `dashboardCache.get` 断言第二次未再聚合，或把用例改名"两次请求结果一致"。

**P2-16 src/tests/controllers/userListFilterAndBulkDeleteBounds.test.js:36-41,99-101 — 共享 `*:*` 权限用 create 播种、afterAll 又删除，破坏并行套件**
内存 MongoDB 是全局单实例、所有 jest worker 共享一库。`Permission.create` 在别 worker 已播种时 E11000 整文件假红；删除共享 `*:*` 后并行套件角色引用悬空，产生顺序相关随机 403。同仓其余套件均用 upsert 复用。建议：改 upsert；afterAll 不删共享权限文档。

**P2-17 src/tests/dataScopeDenyParity.test.js:54-56 — beforeEach `FireDevice.deleteMany({})` 清空整个 devices 集合，摧毁并行设备套件的夹具**
共享库下任何并行依赖设备夹具的套件被中途抹掉 ⇒ 时序性假红。仓库在 rollbackDrillRestoreVerification 已用后缀库修过同族竞态，本文件未采用。建议：专用后缀库或只清自建夹具，afterAll 回收自建设备。

**P2-18 src/tests/middleware/avatarUnmatchedSurfaceGuard.test.js:41-54 — SAVED_ENV 快照只存不还，4 个 env（TRUST_PROXY_HOPS、RATE_LIMIT_*）跨文件泄漏**
`--randomize` 下本文件若排 worker 首位，会把"信任一跳代理 + IP 桶 10 万次"形态注入后续所有套件，产生顺序依赖假红/假绿。建议：顶层 afterAll 按快照归还。

**P2-19 src/tests/fullRangeInactiveSuperAdmin.test.js:64-99 — 固定内置码 SUPER_ADMIN 直接 create 且不清理**
Role.code 唯一索引；同 worker 内 ≥9 个文件同样创建 SUPER_ADMIN，先建者赢、后建者 E11000 整文件红。建议：`findOne ?? create` 幂等取用 + afterAll 按创建清单清理。

**P2-20 src/tests/security/permissionCodeCatalogParity.test.js:40-46 — 权限码对账闸不扫嵌套控制器目录，"路由要求的码必须可授予"对一类文件失效**
`readdirSync` 非递归只扫 routes/controllers/middleware 顶层；`securityController/`、`authController/`、`userController/` 三个子目录里的权限判据全部逃过闸门（且 `hasPermission(userId,'code')` 标识符首参形态不匹配抽取正则）。当前未酿成缺口纯因 `system:read` 恰好也在顶层 rbac.js 被要求。建议：递归遍历 + 纳入双参形态 + 扫描文件数下限自证。

**P2-21 src/tests/services/inspectionExecutionLogCap.test.js:18 — `INSPECTION_EXECUTION_LOG_CAP='3'` 写入后永不还原**
同 worker 后续重新加载 InspectionService 的套件被静默钉在 CAP=3（该目录其他文件均有 env 快照归还纪律，唯独此文件违反）。建议：仿 PREV_ENVS 模式归还。

**P2-22 [D5] src/tests/services/forensicCapturePartialBatch.test.js:163 — 以 `test.failing` 记账的在册缺陷：批量落库部分成功（撞 _id）时新记录进库却不进取证清单**
取证链"进库必入清单"承诺当前真实存在缺口，CI 绿仅因 `.failing` 吸收。建议：排期修复 H-3，修后摘除 `.failing` 转常规门禁。

**P2-23 src/tests/services/websocketCorsAndReauthGuards.test.js:184-204 — cookie 回退用例断言的是"浏览器永不发送"的前提（文件头自陈 [仍有效]）**
握手路径 `/socket.io/` 与 cookie `Path=/api` 不匹配，浏览器不会带该头；`extractHandshakeToken` 的 cookie 回退分支只被不可达输入覆盖。建议：补真实同源 cookie 握手行为用例，或把该边界升级为带期限的台账项。

**P2-24 src/tests/utils/toolCryptoAndOriginGuards.test.js — 自陈残留约 48 行源码/注释文本正则断言**
文案同义改写即红（假红噪音）、被搬进死代码即绿（假绿）；同文件已有"静态→行为断言"改造先例。建议：按既有模式继续改造，无法行为化的注释契约集中到单一文件。

### C. 前端（5 项）

**P2-25 [D3] web-admin/src/components/InspectionCompleteForm.vue:279-290,433-442 — findings.photo 的 URL 格式仅由前端校验，后端只限长度 ≤500（信任边界缺口）**
绕过 UI 直调 API（持 inspection:complete 权限的合法用户或被盗会话）可写入任意 ≤500 字符串（含 `javascript:`、`data:`）。该字段是存储型输入，若任何视图把它渲染为 `<a :href>` 而非 `<img :src>` 即构成存储型 XSS/钓鱼跳转。建议：后端 inspectionRoutes 镜像同一格式判据；渲染侧确保只进 `<img :src>`。

**P2-26 web-admin/src/tests/styles/printStyles.test.js:52 — "@media print 包裹性"闸门贪婪正则可吞掉块后规则**
`/@media\s+print\s*\{[\s\S]*\}\s*$/` 回溯到文件最后一个 `}`；若日后在打印块之后追加屏幕规则会被一并剥掉、断言照样通过——闸门对"块后污染"恒真。建议：按花括号配平剥块 + 位置断言。

**P2-27 [D5] web-admin/src/tests/components/upgradeDialog.test.js — 升级提交的服务端失败路径（triggerUpgrade reject）零覆盖**
系统升级是高危管理动作；"请求已发出但服务端拒绝/超时"时 busy 是否复位、错误提示、能否重试均无测试。建议：补 `mockRejectedValue` 用例断言 ElMessage.error、aria-busy 复位、可重试。

**P2-28 web-admin/src/tests/utils/apiStatusCodes.test.js:118,131 — 「票据 401 不得触发刷新链」的 refresh 监视器瞄错对象，断言永不失败**
`vi.spyOn(apiClient, 'post')` 而刷新链刻意走裸 `axios.post`（同目录 apiRequestPipeline/apiUpgradePollingSupport 已证实）。删掉票据豁免分支该断言仍绿。建议：改 spy `axios.post`。

**P2-29 [D1] 多个前端写入口缺同步重入锁：同一 tick 双击弹双确认框/发重复请求**
位置：UserView.vue:1310(submitForm)/:1375(submitRoleAssignment)/:1183(handleDelete)/:1203(handleResetPassword)/:1229(handleResetMfa)、DeviceView.vue:667、ProfileView.vue:407、InspectionView.vue:452/:483、RoleView.vue:418。`:disabled="dialog.submitting"` 要等一次重渲染才生效，同 tick 第二次点击穿过；确认框类叠出双框并发重复请求，第二次吃 404/409 红错。同仓 AlarmView/LoginView 等已修同型缺陷。建议：按既有模式补同步重入锁（首个 await 前判定并置位），或抽 `withSyncLock(fn)` 统一收口，并补双击用例。

### D. 运维脚本与供应链（1 项）

**P2-30 [D3] scripts/provision-mongod.js:113-146 — mongod 缓存命中分支只核对 `.sha256` 标记文本、不重算二进制哈希，共享缓存目录可被投毒**
缓存根默认 `os.tmpdir()/fsms-mongod`，子目录名完全可预测。共享宿主/自托管 CI 的世界可写 /tmp 上，任何本地账号可预置 `.sha256`（照抄公开锚值）+ 恶意 mongod，脚本把该路径作为 `MONGOMS_SYSTEM_BINARY` 输出，测试进程执行攻击者二进制——供给链锚定在"复用缓存"这一最需要它的场景下失效。建议：命中时对流式重算 sha256 比对锚值；缓存根改用户私有目录（0700）；两处都做更稳。

### E. 部署与运维（2 项）

**P2-31 [D2] deployment/systemd/fsms-access-review.service:28,45,51 — DynamicUser 与生产密钥权限口径互相矛盾，权限复核服务在生产配置下每轮 EACCES 失败**
DynamicUser 即弃 UID 读不到 0600 的 `./secrets/*`；而 secret-rotation.md 生产口径要求 .env 只配 `MONGODB_URI_FILE`。ADR-012 的执行器（每小时到期收敛/reviewSummary 留证）持续失败，运维被迫把明文 URI 写回 .env，正好违反仓库自己的密钥载体纪律。建议：改专用 `User=` + ProtectSystem，或将 secrets 属组化，或在文档明确例外并交部署评审拍板。

**P2-32 [D7] deployment/rollback-drill.md:31-45 — 蓝绿口径与 hot-upgrade.md 冲突（颜色颠倒、端口 3100 vs 3001、机制不同），事故时刻误导回滚操作**
两份自称回滚手册的文档对"当前色叫什么、备色端口几、怎么起第二实例"给出相反答案；实际实现（compose/nginx/hotUpgradePolicy）是 blue=3000、green=3001。建议：rollback-drill.md §2 改写为引用 hot-upgrade.md 既定机制，或加显著勘误注记。

### F. CI/CD 与数据库迁移（3 项）

**P2-33 [D5] .github/workflows/deploy.yml:23-28 — 整条生产部署链从未在 GitHub Actions 真实跑过，仅静态断言背书，首跑即生产**
cosign 验签、digest 钉扎、SSH/自托管投递、hot/rolling 策略的结构正确性有测试，但 runner 标签、SSH 权限、目标机环境、secrets 齐全性只有首跑才暴露。建议：先 staging `dry_run=true`、再 rolling 真实发布，run URL 记入 deploy-workflow-rehearsal.md 留证表；此前任何 production 发布视为未验证。

**P2-34 [D3] migrate-mongo-config.js:41-66 — 迁移目标库白名单 ALLOWED_SOURCE_DB 未设置时完全不校验（fail-open）**
人工/本地执行 `migrate:up` 时 `MONGODB_URI` 误指生产/误指他库只有一行 warn，索引重建/数据回填直接作用于错误库。建议：对写操作将"未设置白名单"升级为拒绝（只读命令可保留宽松）。

**P2-35 [D1] migrations/ 6 个文件 — 约 150 行幂等判据代码（specSig/collationSig/isEquivalentTwin/dropIndexIfExists 等）整份复制且已漂移**
`dropIndexIfExists` 已分叉为"先查后删（自认 TOCTOU）"与"drop 后 catch IndexNotFound"两套实现。任何判据 bug 修复都要同步 5-6 份，漏一份即行为不一致的迁移。建议：抽 `migrations/_lib/indexSpec.js` 共享模块，六迁移统一 require。

### G. 文档与根配置（1 项）

**P2-36 [D3] .gitignore / .dockerignore — 仓库根 21 个 `logs-*.txt` 运行日志（合计 114MB）既未被跟踪也未被忽略**
`git check-ignore logs-audit-jest.txt` rc=1（无规则命中）；.gitignore 只有 `logs/` 与 `*.log`。一次根目录 `git add .`（CONTRIBUTING 只禁了 `-A`/`commit -a`）即把 114MB 日志连同可能的内部信息提交进公开仓库，且全量进入 docker 构建上下文。建议：两个 ignore 文件各加 `/logs-*.txt` 并补注释。

---

## 4. P3 发现清单（181 项，按域归组）

> 均为低风险改进/卫生项，不构成当前可利用风险。每条给出位置与一句话说明；详细证据见对应分区报告（附录 A 索引）。

### 4.1 后端 services / utils / models / constants（55 项）

**认证与会话**
1. `src/services/authService/session.js:277-282` [D5] 登录成功后 `lastLoginAt/failedLoginCount` 回写是全文件唯一未挂 catch 的写操作，DB 抖动把已验证成功的登录打成 500。
2. `src/services/authService/token.js:291` [D1] 账户状态判据硬编码 `'active'`，与 login.js 的 `USER_STATUS.ACTIVE` 双口径并存（F-162 同族漂移风险）。
3. `src/services/authService/login.js:396-460` + `failureAndMfa.js:263-309` [D1] 失败计数/条件重置/锁定/缓存失效四段逻辑双份实现（mfaService 已是第三份），漏改一处即半边防线。
4. `src/services/authService/{login,failureAndMfa,profile}.js` [D2] 以函数内惰性 require 规避 middleware↔service 循环依赖；环仍存在，建议下沉缓存/令牌失效原语到叶子模块。
5. `src/services/loginChallenge.js:45-70` [D4] 登录热路径 3 次串行审计查询，后两个 count 可并行或合并聚合。

**审计链与取证**
6. `src/services/auditChainCheckpoint.js:167-200` [D4] checkTail 逐条 findOne 回溯（≤1024 次往返）；createCheckpoint 全集合 count + 阻塞 `appendFileSync`（离线路径，当前可承受）。
7. `src/services/forensicCapture.js:100-139` [D4] 全局日预算可被单一洪泛源消耗约 1/3（5MB/min×60×24÷10≈720MB），挤占其它攻击源取证空间。
8. `src/services/forensicTrace.js:53` [D5] 超过 32 字符的指纹输入静默变"精确匹配"恒 0 条（0 条会被当成"该 IP 干净"的误导形态）。
9. `src/services/forensicTrace.js:35` [D1] `state.lastError` 从不赋值的死字段，对外暴露"假可观测性"。
10. `src/services/forensicManifestReconcile.js:8-18` [D1] BATCH/chunk 死代码，注释仍称"分批发 IN"。
11. `src/services/forensicManifestPrune.js:32` [D7] 归档年龄按 UTC 日历计算，与清单的业务时区 dateKey 分叉（上海 00:00–08:00 间偏移一天）。
12. `src/services/forensicManifestLock.js:44-51,84-91` [D5] 陈锁接管+finally 无条件 unlink：持锁者停顿超 staleMs 时互斥可短暂破防（概率低）。建议锁内容写 owner token，释放前比对。
13. `src/services/honeypotWatch.js:134,240` [D5] IP 归一化失败时审计行 `ip` 回落攻击者可控原文，违背"不成就不成键"口径。

**IP 与封禁**
14. `src/services/ipPoolBan.js:198-219` [D5] 封段票据确认时刻只复核并集/操作者/打字确认；白名单覆盖与"段内有真实业务流量"两条护栏存在最长 10 分钟 TOCTOU 绕过窗。建议并入 `ticketJudgementRefusal`。
15. `src/services/ipPoolLiveTraffic.js:15-22` [D5] `segmentOfIp` 对压缩形态 IPv6（`2001:db8::1`）失效产出非法 CIDR（当前无生产调用点，潜伏）。

**报告与导出**
16. `src/services/privilegeGrantService.js:114-121` [D4] 审批人资格判定对每个权限码串行查库（最多 20 次往返），可一次取回内存判定。
17. `src/services/privilegeGrantValidation.js:17-24` [D7] 有效期接受小数并四舍五入，与"整数"报错文案不符。
18. `src/services/reportDashboardService.js:204` [D4] 仪表盘缓存命中路径仍每次执行 `getDataScope` 查库（30s 轮询下常驻 DB 负载）。
19. `src/services/userService.js:440-445` [D5] 批量删除无快照路径在"预取 id"与 `deleteMany` 之间存在 TOCTOU，窗口内新命中用户被删但级联（头像/进行中指派）漏清理。
20. `src/services/userPermissionService.js:184,218` [D4] 权限缓存超限即整体 `clear()`；≥2000 人角色做一次权限热同步会把全量缓存拍空引发集中查库。

**WebSocket 与实时**
21. `src/services/websocketService/handshake.js:287-289` [D5] 认证 catch 直接读 `err.message`，非 Error 拒绝让 catch 自身抛 TypeError，客户端既收不到 auth-error 也不被断开（等 30s 超时兜底）。
22. `src/services/websocketService/index.js:33-46` [D2] WS 侧 CORS 回退来源列表与 app.js 手工复制，靠注释约定同步。

**配置与工具**
23. `src/services/piiExportQuota.js:35` [D3] 配额日键硬编码 UTC+8，绕开 `BUSINESS_TIMEZONE` 单一声明。
24. `src/services/initData/adminAccount.js:46-50` [D3] 明文口令文件"先写入、后加固"，Windows 上存在未加固窗口（有回读+回滚兜底）。建议先加固目录/临时文件再写入再 rename。
25. `src/utils/bcryptWorkerPool.js:60-126` [D4] Worker 池初始化中途失败时已创建线程不 terminate，泄漏至进程退出。
26. `src/utils/auditChainFence.js:44-51` [D6] 僵尸 fn 永不落定时分布式锁被无限续租，审计链全实例冻结无时长上界、无独立告警。
27. `src/utils/apiResponse.js:42-64` [D5] `paginated` 对非数值型 meta 字段静默回退默认值（`'2'` → page=1 无信号）。
28. `src/models/auditLogWriteStatics.js:134-137` [D1] riskFactors 用子串匹配判定 delete/batch 操作，未登记 action 变体可能误标。
29. `src/utils/cookie.js:148-163` [D7] `durationToMs` 数值入参语义与 jsonwebtoken 分叉（毫秒 vs 秒），仅靠注释防御。建议对 number 入参直接抛错。
30. `src/utils/auditChain.js:8`、`crashFlush.js:14-15`、`healthChecks.js:121` [D2] utils 反向依赖 services 层（分层倒置，无循环但属结构债）。

**数据模型**
31. `src/models/ConsentRecord.js:17-18` [D3] `ip`/`userAgent` 无长度上限、无控制字符清洗（同族字段在 AuditLog/UserSession 均有落库闸）。
32. `src/models/User.js:329-330` [D3] `toJSON/toObject {getters:true}` 使任何漏加投影的序列化点默认吐出解密明文 phone/email；目前靠投影纪律+userPhoneMaskedEgress 源码闸把守，属默认不安全取向。建议提供"默认掩码、显式申请明文"第二档。

**HTTP 表现层**
33. `src/routes/authRoutes.js:406-423` [D5] POST /mfa/enable 的 mfaCode 校验链挂在 requireReAuthentication 之后且不消费，格式非法验证码先烧共享 MFA 失败锁计数；控制器专属 MFA_CODE_FORMAT 契约不可达。
34. `src/routes/authRoutes.js:296` [D4] GET /auth/session 是打库的未认证端点却无专属限流桶（同族 /captcha-status 挂了 strictLimiter）。
35. `src/routes/reportRoutes.js:138-152` + `authRoutes.js:387-393` [D3] /export/pii 与 /mfa/enroll 是唯二未挂 reauthCredentialValidation 的凭据端点，encCurrentPassword 密文长度不设防。
36. `src/controllers/authController/credentials.js:284-288` [D6] refreshToken 兜底 catch 把包括数据库故障在内的一切异常吞成 400 且零日志，故障期监控只见 400 洪水。
37. `src/controllers/auditController.js:20` [D2] /audit-logs 的路由处理器本体（asyncHandler+req/res）住在 service 层，控制器仅转出，分层口径与全仓相反。
38. `src/routes/versionRoutes.js:10-14` + `src/config/buildInfo.js` [D3] 匿名 /api/version 暴露 version/buildId(git sha)/uptime（有意取舍；可再收紧为单向摘要或登录后返回）。
39. 校验消费双口径（路由级 consumeValidation vs 控制器级 validationResult）并存，当前逐条核实无死链，但历史缺陷类的土壤仍在。建议定单一约定。

**横切 middleware/config**
40. `src/middleware/errorHandler.js:29` [D3] CastError 消息内嵌原始用户输入未清洗即入 printf 日志（同类残余面）。
41. `src/config/proxyProtocol.js:6`、`src/config/trustedProxies.js:27` [D1] 环境变量名用字符串拼接构造（`'PROXY'+'_'+'PROTOCOL'`），破坏全仓 grep 可检索性。
42. `src/config/deploymentCredentialGuards.js:59-97` [D7] CORS 来源校验放行 `:443`/大写 host 等"浏览器永远不会发送"的形态，启动全绿但所有写操作静默 403。建议归一化比对并告警。
43. `src/middleware/security/ipBlacklist.js:120` [D3] 白名单豁免的"私网/回环对端即可信"判据仍未以 TRUSTED_PROXY_CIDRS 为准——同网被攻陷容器伪造一跳 XFF 可买通限流/CSRF/query 三重豁免（代码已登记为接受风险 R3，本轮独立复核确认仍成立）。

**启动/文档/数据**
44. `src/cluster.js:57-67` [D1/D6] 崩溃退避日志与判据自相矛盾：存活≥稳定窗仍打「短命连发 ×0」并对稳定 worker 套 500ms 伪退避。
45. `src/cluster.js:13-17` [D1] CLUSTER_WORKERS 非法值/超上限静默收敛（回落 1/夹取 16）无任何日志。
46. `src/app.js:349-375` [D6] morgan 挂载晚于黑名单/限流闸门，早期 403/429 不进访问日志（审计链 recordEarlyRejection 与 metrics 已补偿，非安全盲区）。
47. `src/plugins/autoIncrement.js:80-84` [D1] `$substrBytes` 偏移按 JS UTF-16 长度计算，前缀引入非 ASCII 时错位（当前全 ASCII，潜伏）。建议 `Buffer.byteLength`。
48. `src/docs/generate.js:1679-1694` [D5] CLI 写 openapi.json 非原子（同仓 update-ip2region 已示范 tmp+rename）。
49. `src/data/README.md:6` [D7] 刷新说明未提 sha256 内容锚；数据为 2024-02-28 版（约 21 个月未刷新），建议定期 `--check` 评估刷新。
50. `src/index.js:533-547` [D5] unhandledRejection 一律排空后退出（fail-fast 取舍）；建议为两类触发源加 Prometheus 计数器使"频繁兜底重启"可见。
51. `src/docs/generate.js:296-301` [D7] /api/auth/session 与同族 /api/auth/captcha-status 的限流口径不一致（文档忠实反映实现；补 strictLimiter 或说明豁免理由）。

**常量数据面（蜜罐诱饵）**
52. `src/constants/honeypotDecoyAggregatesData.js:106-125` [D1] 诱饵授权行 hp-g6 时间线自相矛盾（granted 70h 前 + 24h 时长，expiresAt 却写成 46h 后，且吊销晚于到期却称"提前结束"），可被陷阱会话持有者识别为合成数据。
53. `src/constants/honeypotDecoyMetrics.js:68` [D7] 诱饵 metrics 告警序列含 `unusual_time_access`，但真实系统从不会以该 type 投递告警（定义后无消费点），构成可指纹差异。
54. `src/utils/logPiiMask.js:98-107` [D3] 凭据键掩码后缀集缺口：`authToken`/`apiToken`/`sessionToken`/`deviceToken` 等组合词键归一化后不命中现有名单，令牌可原样落日志。建议补确定性组合词或改"以 token 结尾且不在白名单即 redact"。
55. `src/utils/permissionHelper.js:197-200` [D6] `getMenuTree` 把数据库故障吞成 200+空菜单，故障与"无权限"对外同形；建议区分两种空并补计数指标。

### 4.2 后端测试资产（45 项）

**断言强度/有效性**
1. `src/tests/config/configParams.test.js:51-67` [D5] "越界必须告警"用源码文本断言而非捕获子进程真实 stderr；条件改坏仍绿。
2. `src/tests/config/hmacSecretConsumersSingleSource.test.js:89-94` [D5] 消费点扫描读原文未剥注释（注释里的示例造成假红）。
3. `src/tests/ci/riskFactorVocabularyGate.test.js:77-93` [D5] 风险码扫描同样未剥注释。
4. `src/tests/config/nodeEnvConsumers.test.js:133-150` [D5] 注释剔除只认行首 `//`/`*`/`/*`，无星号续行的块注释会漏剥。
5. `src/tests/controllers/authSessionHandlerArms.test.js:123` [D5] 双可能断言 `expect([200,204]).toContain(status)`，违背本仓"实测钉值"判例。
6. `src/tests/controllers/rbacControllers.test.js` [D5] 部分断言仅查状态码，弱于"状态码+errorCode 成对"惯例。
7. `src/tests/fileAclResetForFiles.test.js:50` [D5] 前置自证断言含恒真析取支（`typeof r.stdout === 'string'` 恒真），无判别力。
8. `src/tests/routes/routeSchemaFieldParity.test.js:269` [D5] `expect(\`${key} => ${plainMax}\`).toBe(同串)` 字面恒真死断言（真实判据在下一行，无覆盖率损失但误导）。
9. `src/tests/security/utf8ScanScope.test.js:50-57` [D5] `test.each` 中 'dist-tool' 用例提前 return，零断言恒过的空测试。
10. `src/tests/utils/datetime.test.js` 对应前端项见 §4.3；后端此处略。

**测试间耦合/env 泄漏（同 worker 进程级）**
11. `src/tests/middleware/forensicRoutesContract.test.js:61`、`src/tests/security/loginPeerBucketXffRotation.test.js:46` [D5] 设 `TRUST_PROXY_HOPS=1` 后不还原，同 worker 后续文件静默运行在 trust proxy=1 档。
12. auditBuffer/WAL 族 6 套件 + logShipper 族 6 套件 [D5] 模块加载期写 `process.env`（AUDIT_WAL_PATH、AUDIT_BUFFER_HARD_LIMIT、LOG_SHIPPING_* 等）不还原；auditBufferPrecastGate/auditChainCheckpointRealTail/auditWalCorruptLineObservability 三处 afterAll 删临时目录后 env 仍指向已删路径。
13. `src/tests/services/auditBufferPrecastGate.test.js:27-29,468-477` 等（同上族）[D5] 同 worker 后续套件若不自设路径调用 `auditBuffer.start()` 会把 WAL 写进已删除目录。
14. `src/tests/migrations/reconcileAuditIndexOptions.test.js:29,41-47` [D5] 唯一在共享 worker 库上反复改写 auditlogs 索引形态的迁移套件，违背同目录声明的隔离纪律。建议改独立后缀库。
15. `src/tests/controllers/securityQuick.test.js:87-119` [D5] 翻转全局 SystemConfig（注册开关/登录验证码开关）后不还原，共享库留下非确定性状态。
16. `src/tests/controllers/changePasswordEncTrack.test.js:14-17` [D5] 前三条用例共享同一账号的 5 次/15 分钟限流预算（已用 3/5），隐式顺序耦合脆弱。
17. 多文件 afterAll 不清理自建用户/角色/IP 封禁 [D5]：adminResetPasswordGates、createUserPeerRoleGate、reportExportAuditPerm、loginEncryption（含 127.0.0.1 封禁残留）、rolePermCloneTargetUserScope、rolePermPeerGuard、roleStatusInvalidatesUserCache、userStatsSelfScopeCast、userStats、sessionManagement、deploy/deviceBuildingScope、deploy/deviceCodeCap。当前"每文件独立空库"下无跨文件影响，但与仓内清理惯例不一致，隔离口径若回退即成夹具泄漏。

**夹具卫生/资源**
18. `src/tests/ci/moduleTrackingGate.test.js:166-184` [D5] 测试运行期向 `src/` 写临时夹具，与并行扫描存在 ENOENT 竞态（同类事故已有先例迁往 .jesttmp）。
19. `src/tests/services/backgroundJobs.test.js:82` [D1] `global.__eapp = createApp()` 死全局赋值，无人消费也无人清理。
20. `src/tests/services/forensicManifest{Lock,Retention,Reconcile}.test.js` [D5] mkdtemp 临时目录（含子进程脚本、锁文件）从不删除。
21. `src/tests/services/deviceScrapTerminalStateAtomic.test.js` [D5] 造出的设备夹具不入库清理，仅靠每文件独立库兜底。
22. `src/tests/services/forensicCaptureHardening.test.js:124,273` [D5] 对 mock 模型的变异未用 try/finally 还原，前一例失败后续级联红难归因。
23. `src/tests/utils/toolCryptoAndOriginGuards.test.js:622-663` [D5] 生产模式 logger 子进程探针在仓库 `logs/` 落盘日志文件（污染工作区）。
24. `src/tests/utils/apiErrorHttpJsonAndLimitGuards.test.js:42-44` [D5] 顶层 `jest.mock('mongoose')` 作用域过宽（仅 autoIncrement describe 需要）。
25. `src/tests/services/wsFlow.test.js:227-237` [D1] 遗留 JOIN_DEBUG 调试输出与无用 socket 捕获。
26. `src/tests/controllers/auditSummaryCache.test.js:37-48` [D5] 白盒操作 statsCache 私有内部（`_store`/`expireAt`），实现换型即碎。
27. `src/tests/controllers/auditExportSlot.test.js:95-103` [D5] `while (true)` 占槽循环无上限保护，acquire 侧回归为永不拒绝时以内存膨胀收场。
28. `src/tests/metricsSeriesFidelity.test.js:58-66,147-158,201-218` [D5] 复位与断言大量依赖 metrics 模块内部 Map（脆性；主判据仍锚在外部可见面）。
29. `src/tests/utils/webVitals.test.js`（前端，见 §4.3）。

**死代码/文档/口径**
30. `src/tests/ci/commentDensityEnforcementStatus.test.js:63` [D7] 过时括号注记"今天实测 exit 1：确有回退"与 commentDensityRatchet 的"当前树必须通过"并存，误导维护者。
31. `src/tests/ci/commentAnchorFreshness.test.js:887` + `bareAnchorAttribution.test.js` [D5] 行号台账体系维护成本高（app.js 锚点单月重钉 6 次），LIVE 地板 42 vs 实际 45 留有 3 条"静默摘除登记"窄缝。
32. `src/tests/services/deviceReminderTruncation.test.js:24-27` [D7] 关于测试库隔离的注释已失效（setup.js 已是每文件独立库），注释与现行为相反。
33. `src/tests/services/initDataLifecycle.test.js:503,568` [D7] 两个用例都编号 B7，追溯歧义。
34. `src/tests/middleware/auth.test.js:163-191` [D5] "JWT Token 基础功能"四例测的是 jsonwebtoken 库本身，对本仓无回归判别力。
35. 死变量与重复脚手架 [D1]：authLifecycle.test.js:65-70 `void superToken`；rbacControllers.test.js `void builtInSuper`×2；authControllerOutcomes 与 authUnknownOutcomeFailClosed 各自重复约 200 行同款 mock+脚手架（可抽 helpers）。
36. `src/tests/controllers/ipListValidationAndConflictGuards.test.js:677-685,723-731` [D5] 审计兜底用例以两次 setImmediate 冲洗等待，若兜底路径改真实异步会偶发读不到（建议统一 waitFor）。
37. `src/tests/deploy/workflowShellSyntax.test.js:108-109` [D5] `BASH_LIKE=/^$|bash|sh|python/i` 与自述设计矛盾：`shell: python` 会被拿去 `bash -n`（假红），`sh` 子串误匹配 pwsh/zsh，skipped 计数验不出"该跳未跳"。
38. `src/tests/security/gateSelfTest.test.js:628-641` [D5] compliance-check 门禁的"缺钩子必须红"仅源码正则验证，未做注入式负检验（建议 jest.doMock 掏空替身在进程内跑 runRegisteredChecks 断言转红）。

**覆盖缺口 [D5]**
39. WS 认证超时闸（authTimer/AUTH_TIMEOUT 断开未认证连接）在 T07 批次 115 文件内无行为用例（所有 authenticateSocket 调用 timer 传 null）。
40. WS 单进程连接上限（MAX_CONNECTIONS_PER_PROCESS=1000）拒绝路径无行为用例（仅 getStats 断言常量）。
41. `src/tests/observability/logShipperTransportFailurePaths.test.js:441-446` [D5] "HTTPS 协议选择"用例从不调用 `_post`，https 出站路径本文件零行为覆盖（scheme 判定由批外 logShipperSchemeAllowlist 部分缓解）。
42. `src/tests/controllers/requestedIdListDeduped.test.js:1108-1125` [D5] 台账自报两处无腿缺口：createRole 权限 id 归一无大小写腿；batchDelete 上限按裸值长度判定（重复 id 可绕过计量）。
43. `src/tests/services/tokenService.test.js` [D5] 覆盖偏薄（仅 2 例 claims 断言；校验路径由 mfaTokenPrimitiveGuards 补齐，refresh 7d 窗口未在本层钉住）。
44. 文本级门禁的误伤面（14 个 single-source/parity 文件）[D5]：断言源码文本形态，prettier 折行/注释措辞调整可造成非语义红；均有正对照与判据自证，属有意取舍，新增同类门禁必须同时交付"正对照+洗白自证"。
45. `src/tests/utils/auditMeta.test.js:339` + `wildcardPermissionSingleSource.test.js:64-72` [D5] 冻结式精确计数（110 / WILDCARD_LITERAL_CENSUS），合法重构即红（有意提醒），建议数字与更新说明同处登记。

### 4.3 前端 web-admin（41 项）

**生产代码**
1. `web-admin/src/components/SecurityStatsCard.vue:165-166` 等 [D3] 权限门控全部是装饰性 UI 判断（v-if/hasPerm/prop 禁用），真实裁决在后端；本范围内未发现仅前端把关的敏感写操作，`/security/stats` 等端点的后端权限中间件覆盖需后端侧持续复核。
2. `web-admin/src/components/SessionManager.vue:280-296` [D1] `load()` 是同族卡片中唯一没用 `useLatestRequest` 竞态门票的列表请求。
3. 8 个卡片组件重复定义同一段 `.card-header` scoped 样式（RecentAlarmsCard/AccountBindingsCard/MyLogsCard/SecurityInfoCard/SecurityStatsCard/ChangePasswordCard/MfaSettingsCard/DashboardCharts），排版调整需改 8 处。
4. `web-admin/src/components/AttackProfileResult.vue:90` [D1] 建议列表 `v-for` 以业务值作 key，重复建议码撞 key。
5. `web-admin/src/components/DashboardCharts.vue:380-392` [D4] 切语言/切主题整体重拉两个报表接口，仅为更新轴标签与配色（有 in-flight 复用，无错序风险，纯多余流量且 GET 落审计日志）。
6. `web-admin/src/assets/styles/view-refine.css:170-217` [D4] 表格行逐行入场动画对大表有感知延迟（已有 reduced-motion 降级）。
7. `web-admin/src/i18n/index.js` + `store/app.js` [D1] 语言偏好只存 sessionStorage，主题存 localStorage——同一对界面偏好持久化策略互相矛盾，新开标签页语言回退。
8. `web-admin/src/layout/index.vue:566-570` [D1] 切语言对同一状态三处重复写入（setLocale + appStore.setLanguage + locale.value），同步靠人肉。
9. `web-admin/src/store/auth.js:336-365` [D3] restoreSession 网络失败且有缓存身份时返回 true（UI 侧 fail-open，注释已声明、后端逐请求鉴权兜底，不构成越权；建议加遥测/提示）。
10. `web-admin/src/router/index.js:240-244` [D1] 未登录深链跳 `/login` 不回传目标路径，登录后一律落 /dashboard。建议 `next({path:'/login', query:{redirect: to.fullPath}})` 并做站内校验。
11. `web-admin/src/data/ipLocationDictionary.json` [D7] 3 处英文译名错误：哥伦比亚→"Columbia"（应 Colombia）、古尔冈→"Gurugon"（应 Gurugram）、北江省→"Bac Ninh"（应 Bac Giang，且与北宁省撞名）。
12. `web-admin/src/store/app.js:90-102` [D1] setThemeMode 不校验取值域（任意字符串静默落入"非 dark 即 system"分支并持久化）。
13. `web-admin/src/views/IpListView.vue:666-679` [D1] handleRemove 的 FULL_RANGE_FORBIDDEN 专属文案分支生产不可达（isHandledApiError 对 axios 错误恒真），而测试 mock 强制该判据为 false 使其假绿。
14. reauth/blob 错误解包逻辑 4-5 处复制 [D1]：AttackAlertsView/AttackProfileView/AuditLogView/StuffingProfileView 各一份 `readReauthErrorCode`；AuditLogView/ReportView 各一份 blob 解包。建议抽 utils。
15. God components [D1/D2]：AuditLogView(2001 行)、PrivilegeGrantView(2997 行)、UserView(1617 行)、RegisterView(1661 行)。建议按 DashboardView 的 D-2 模式拆分。
16. `web-admin/src/views/DashboardView.vue:260,272` [D1] 仍自带 `visibilityState==='visible'` 判据，未走全仓统一的 `isPageHidden`。
17. `web-admin/src/views/AboutView.vue:447-475` [D1] loadMetrics 无竞态守卫，30s 轮询与手动刷新重叠时旧快照可覆盖新快照。
18. `web-admin/src/views/AttackProfileView.vue:294-301` [D1] copyReport 无非安全上下文兜底，与 ForensicTraceView.copyText（textarea 降级）两套口径。
19. `web-admin/src/views/AuditLogView.vue:1345-1348` [D1] exportLogs 绕过 `api.reports.export` 封装直连 apiClient。
20. `web-admin/src/utils/webVitals.js:69-107` [D4] INP 样本数组无上限累积，长驻会话线性增长。建议封顶采样。
21. `web-admin/src/utils/api.js:563-571` [D4] 请求拦截器给调用方 AbortSignal 挂的监听在正常完成路径不移除（长生命周期 controller 上慢性累积）。
22. `web-admin/src/views/RegisterView.vue:768-774` [D1] resetForm 未判空即解引用 formRef（当前表单恒挂载，风险低）。
23. `web-admin/src/views/ReportView.vue:543-577` [D3] 导出对话框的口令/MFA 凭据在导出成功后不清空（不落 storage，纯内存滞留窗口，纵深防御口径）。
24. `web-admin/src/views/IpListView.vue:318-337` [D1] validateIpOrCidr 的 IPv6 分支过松（`/^[0-9a-fA-F:]+$/`，`::::` 可过）。
25. `web-admin/src/utils/attackProfileReport.js:10-13` [D1] Markdown 单元格只中和换行/竖线，不中和 Markdown 语法（仅 `<pre>`/`.md` 下载，无 HTML 渲染路径，无脚本风险；最坏诱导性链接）。
26. `web-admin/src/utils/api.js:650`、`errorReporter.js:656` [D1] 生产模块导出仅供测试用的 `__getDriftCount`/`__isFlushInFlight` 观测点进入生产包。
27. `web-admin/README.md` [D7] 仅含 vue-i18n 钉版说明，无开发上手内容。

**前端测试**
28. `web-admin/src/tests/components/upgradeDialog.test.js:90-137` 等 [D5] 对异步结果用固定 flush 次数或固定 260ms 睡眠断言（基座注释已实测该模式 CI 高负载 flaky），应改条件等待。
29. `web-admin/src/tests/directives/segGlassIntegration.test.js` [D5] 缺 afterEach 兜底卸载，用例中途失败向后续用例泄漏已挂载实例。
30. `web-admin/src/tests/store/authPersistenceNoPii.test.js` [D5] stub location 后未 `vi.unstubAllGlobals()`（对照 authStore.test.js 有还原）。
31. `web-admin/src/tests/router/routeGuard.test.js` [D5] mustChangePassword 强制改密重定向只在 /register 验证，普通受保护页拦截行为未测。
32. `web-admin/src/tests/components/sessionManager.test.js` [D5] 保留若干源码文本断言（dl/dt/dd、word-break、api.js URL 字符串等）——有变异实测依据的有意取舍，长期维护成本。
33. `web-admin/src/tests/composables/usePullToRefresh.test.js` [D5] onRefresh 返回被拒 Promise 的路径未测。
34. `web-admin/src/tests/utils/webVitals.test.js:39-106` [D5] describe 级共享 metrics 数组+单例初始化造成用例间顺序耦合（单抽/乱序即红，假失败方向）。
35. `web-admin/src/tests/utils/apiUpgradePollingSupport.test.js:202` [D5] 固定 `sleep(20)` 等异步登出链，应改 `vi.waitFor` 终态轮询。
36. `web-admin/src/tests/utils/apiRequestPipeline.test.js:1219-1220` [D5] addIPEntry 死通道守卫用正则钉死 api.js 源码排版，纯格式化改动假红。
37. `web-admin/src/tests/utils/datetime.test.js:79` [D5] 恒真断言 `expect(expected.length).toBeGreaterThan(0)`（expected 为非空字面量拼接），无鉴别力。
38. `web-admin/src/tests/utils/errorCodeI18n.test.js:18-20,220-245` [D5] 空 beforeEach；axios method 归一化探针走真实网络（127.0.0.1:1），建议改自定义 adapter。
39. `web-admin/src/tests/views/auditLogView.test.js:1338-1341` [D5] 关闭弹窗用裸 60×10ms 真实定时器轮询，应改 harness 的 waitFor。
40. `web-admin/src/tests/views/dashboardView.test.js:356,381` [D5] 两条竞态用例用真实 1s sleep 制造时序（同仓 deviceView G9 已用假时钟），建议改 `vi.useFakeTimers`。
41. `web-admin/src/tests/components/changePasswordCard.test.js:60,180-184,201-205` [D5] 真实定时器 1700ms 休眠×2 拖慢套件（断言本身有效；建议延时参数可注入或假时钟推进）。

### 4.4 运维脚本（14 项）

1. `scripts/config-drift-check.js:90` [D2] require 了未声明的传递依赖 js-yaml（仅 istanbul 覆盖率工具链间接提供，`npm ci --omit=dev` 运行时镜像中不存在），违背同仓 alertRulesPolicy "不引 js-yaml" 纪律；当前未接 CI 且缺模块时 fail-closed（exit 2）。
2. `scripts/capture-image-digests.sh:70-71` [D7] 注释引用的门禁判据仍是 `node:22.14.0-alpine`，实际 Dockerfile/测试已为 `26.12.0`，误导升级者。
3. `scripts/backup-mongo.sh:42` [D1] 备份目录默认值 `./backups` 按进程 cwd 解析（deploy 主路径传绝对路径安全；手工/cron 从任意目录执行会散落产物），与同仓 audit-chain-checkpoint 已定性的"cron 任意 cwd"缺陷同类。
4. `scripts/alertRulesPolicy.js:224-229` [D1] 区间时长判据不认合法 PromQL 子查询 `[5m:1m]`，潜伏 CI 假红（当前 alert-rules.yml 未用子查询）。
5. `scripts/generate-secrets.js:128-138` [D5] 模块顶层执行 CLI、无 require.main 守卫（同族脚本均已有守卫）；当前无测试 require 它，风格不一致。
6. `scripts/alert-delivery-probe.js:179-190` [D3] 探针记录把目标 webhook URL 原样落盘（可能含 access_token），建议掩码查询串。
7. `scripts/importOfflineBundle.js:72-86,119-127` [D3] 摘要校验按路径打开文件（无 O_NOFOLLOW），lstat 拒链与 open/load 之间存在 TOCTOU 窗口；未对齐同仓 hotUpgradeQueue.readJsonFile 的单 fd 读法。
8. `scripts/offlineBundleIntakePolicy.js:16-21` [D7] 头注释声称解包带 `--no-same-owner --no-same-permissions`，实际 extractArchiveMembers 未传这两个 tar 选项（setuid 位由 hardenTree chmod 清除，实际风险低）。
9. `scripts/offlineBundleIntakePolicy.js:62-63,178-194` [D7] REQUIRED_ENTRIES 注释/报错称"四个条目"，实际声明 3 项。
10. `scripts/hotUpgradePolicy.js:328`、`scripts/offlineBundlePolicy.js:281` [D1] `split('=')` 截断含 `=` 的参数值，与 offlineBundleIntakePolicy 已修正的 `indexOf('=')` 口径不一致。
11. `scripts/revoke-user-sessions.js:33-58` [D3] 同族 --apply 类脚本已统一"--apply + --yes 双确认 + 未知参数拒绝"，本脚本仍单标志且未知参数静默忽略（`--aply` 手误静默退化为演练）。
12. `scripts/login-key-pin.js:108-113` [D1] main() 在模块顶层无条件执行，缺 require.main 守卫。
13. `scripts/update-ip2region.js:207-209` [D3] 原子替换临时文件名固定（`.tmp`）且 writeFileSync 跟随符号链接（仓库目录写权限本身高，纵深补强项）。
14. `scripts/mongoUri.sh:550,572`、`scripts/restore-mongo.sh` [D1] 依赖 `stat -c %s`/`sha256sum` 等 GNU 专有工具形态，非 Linux 平台会响亮失败（fail-closed 方向正确，跨平台提示）。

### 4.5 部署与运维资产（10 项）

1. `docker-compose.yml:162` vs `deployment/systemd/hot-upgrade.env.example:62` [D7] UPGRADE_HISTORY_LIMIT 两侧默认值不一致（10 vs 50），模板却声称"与应用相同"。
2. `deployment/backup-encryption.md`、systemd 单元、rollback-drill.md [D7] 部署路径三文档漂移（/opt/xf、/opt/fsms、/srv/fsms），且跨文档行号引用已失准。
3. `docker-compose.yml:520-524,575-577` [D3] mongo-rs-init 以 argv 传递 root/应用口令，与本文件 healthcheck 已采纳的"口令不进 argv"口径不一致（一次性容器、internal 网络，实际风险低）。
4. `deployment/edge-protection.md:93-102` [D7] 取证日志 awk 速查配方在多跳 XFF（含空格）时字段错位，可能误判攻击规模与来源。
5. `deployment/nginx.conf.example:229` [D3] HSTS `preload` 在示例中无条件下发，与自身"确认全站 HTTPS 后再启用 preload"注释矛盾（回退窗口锁死一年）。
6. `docker-compose.yml:83` [D3] `LOGIN_ENCRYPT_STRICT` 默认 false，而模板自身是 nginx TLS 终结拓扑——标准部署默认关闭登录口令密文轨。建议默认 true 或纳入发布检查单强提醒。
7. `docker-compose.yml:964-1008` [D7] secrets 头注释"务必放在仓库之外的目录"与 secrets 块写死的 `file: ./secrets/*` 相对路径矛盾（./secrets 已 gitignore/.dockerignore，两处表述必有一处误导）。
8. `docker-compose.yml:65,1083-1095` [D2] TRUSTED_PROXY_CIDRS 强制显式配置，但两网络的网桥子网未用 ipam 钉死，正确取值不稳定（网络重建后子网可能变化：信任名单失配或被迫写宽）。
9. `deployment/hot-upgrade.md:277-284` [D7] §4.1 队列布局表格表头重复/错乱，权限矩阵阅读易错。
10. `deployment/deploy-workflow-rehearsal.md` + `rollback-drill-record.md` [D5] 发布工作流与完整回滚演练均未真实执行（文件自述的受控缺口；建议完成 staging dry-run 与含数据级恢复的完整演练后再声称 RTO 已验证）。

### 4.6 CI/CD、迁移与 E2E（8 项）

1. `.github/workflows/ci.yml:709-714` [D7] "16 条无条件旅程 + 9 条条件旅程"注释与实际不符（实为 3 无条件 + 13 条件，共 16；MIN_PASSED=32 门禁数值本身仍有效）。
2. `.github/workflows/release.yml:57-75` [D6] tag 校验的 `git fetch` 未使用已声明的 GITHUB_TOKEN（匿名 fetch 仅公开仓可行），且 `2>/dev/null` 会把 403 误报成"tag 不存在"。
3. `.github/workflows/deploy.yml:181-206,209-212,321-324` [D6] 凭据探测 fail-open 到 self-hosted（无 SSH secrets 且无带标签 runner 时 job 无限排队），两个部署 job 均无 `timeout-minutes`。
4. `.github/CODEOWNERS:6-8` [D3] 单一 owner + 依赖分支保护才生效，实际约束力不可在仓内验证；建议记录分支保护配置快照、为高爆炸半径路径增加第二 owner。
5. `jest.config.js:226,307,315,327,328` [D5] 部分安全相关模块分支覆盖率地板偏低（mfaController 57%、accessReviewService 65%、privilegeGrantService 69%、webhookTargetResolver 67%、userController/shared 70%）；门禁真实阻断，建议下轮棘轮优先收紧这三个权限敏感文件。
6. `.github/semgrep/rules.yml` [D5] 规则全部为文本正则匹配，绕过形态明确（别名/解构/多行）；作为"零命中基线+测试钉住"的防退化门禁成立，深度检测依赖并行 CodeQL 层，分工表述建议明确。
7. `e2e/` [D5] 浏览器旅程缺登出/会话过期/令牌刷新等安全相关旅程，写路径全部依赖进程级 ops-e2e 与人工演练（README 已声明）。建议至少补"登出后访问受保护路由被重定向回 /login"只读旅程。
8. `migrate-mongo-config.js:88` + `migrations/README.md` [D7] `useFileHash:false` 的"改档不重放"陷阱未进 README 正式规范章节（根因说明在某个迁移文件头注释里）；建议把"已应用迁移不可修改"写进迁移编写规范与 migrate:create 模板注释。

另：`ci.yml:591-675` e2e-browser 后端进程无显式 kill 步骤（低优先级卫生项）。

### 4.7 文档与根配置（8 项）

1. `CHANGELOG.md:1674-1675` [D7] 表格行损坏："运维脚本 E"批次②行被多出的 `|` 拆成 6 列，改法/门禁两列错位不可读（全文件唯一结构性损坏；结构闸不查表格列数，建议补判据）。
2. `CHANGELOG.md:916` [D7] 行内代码反引号不配对（`&&` 只开未闭），渲染错乱到下一个反引号。
3. `package.json:32-33` [D7] `security:audit:*` 脚本用 `--audit-level=high`，而 CI 与 SECURITY.md 宣称的基线是 moderate（2026-09-16 收紧）——本地跑文档里的门禁比 CI 弱一档。建议统一为 moderate。
4. `docs/threat-model.md:119` [D7] 残余风险 #3 已过期——logShipper 的 DNS rebinding 窗口已于 2026-10-31 由 `pinnedLookup` 收口，威胁模型仍列为开放残余（多报方向，危害有限但属文档-实现漂移）。
5. `.env.example` [D7] 缺 README 生产清单必填的 `FSMS_SECRETS_DIR`（README:208 声明"以 .env.example 为准"），deployPolicy.js 消费该变量。
6. `CHANGELOG.md` 3189–3239 行 [D7] 6 个条目缺日期，破坏既有"### 类型：标题（日期）"格式（其余 111 个条目均带日期）。
7. `.dockerignore:53-54` [D3] `*.md`/`*.txt` 与其后 `**/*.md`/`**/*.txt` 重复（前者被后者完全覆盖；该文件以逐条解释通配语义著称，冗余规则误导）。
8. `README.md:132` [D7] 快速开始的 bash 代码块内混入 PowerShell 语法（`$env:NODE_ENV`），Git Bash/CMD 用户照敲报错。建议按 shell 拆分说明。

---

## 5. 依赖安全扫描（npm audit，2026-11-15）

### 5.1 后端（根 package.json）

- 结果：**0 critical / 0 high / 19 moderate / 1 low**（共 20 条）。
- 受影响包全部位于**开发/测试工具链**：jest 30 工具族（@jest/core、@jest/transform、babel-plugin-istanbul、test-exclude 等）、glob、minimatch、deepmerge（low）、nodemon（dev）。**生产依赖（express、mongoose、ioredis、jsonwebtoken、socket.io、bcryptjs 等 24 个直接依赖）无一命中已知 advisory**。
- 说明：`fixAvailable` 多为"降级 jest 至 29.7.0"类大版本回退，属工具链取舍；moderate 级均在 dev 树，不进入生产运行时。仓库已有 `check:lockfile` 语义哈希锚、`check-prod-install-scripts`、dependabot 周更与 dependency-review 工作流兜底。

### 5.2 前端（web-admin/package.json）

- 结果：**0 critical / 0 high / 7 moderate / 2 low**（共 9 条）。
- 受影响包全部位于**开发/构建链**：eslint 10（minimatch 传递）、@eslint/*、glob、deepmerge（low，经 vite-plugin-pwa→workbox-build→@rollup/plugin-node-resolve）。**运行时依赖（vue、vue-router、pinia、axios 1.20.0、element-plus、echarts、socket.io-client、zod 等）无一命中**。
- W00 分区锁文件复核：axios ≥1.12（无已知重放/SSRF CVE）、vite 8.3.4、vue 3.5.43 均为新线；重复版本（semver 6/7、minimatch 5/10 等）均为 devDependencies 传递依赖的常态共存，无同包双大版本进入 runtime 链。

### 5.3 结论

依赖面健康：无 high/critical，无生产依赖命中；moderate 项集中在测试/构建工具链，可随 dependabot 常规升级消化（注意 jest 30→29 类"修复"实为降级，建议按 tools 链评估后处理或等上游修复线）。

---

## 6. 正面确认（审计中核实过的强项，供复核参考）

- **零 v-html/innerHTML**（前端 66+291 文件，ESLint `vue/no-v-html: error` 硬门禁）；ECharts tooltip 用户可控类目名全转义。
- **凭据卫生**：token/密码/MFA 密钥不落 localStorage；MFA secret/恢复码卸载擦除；口令全密文轨（ECDH+HKDF+AES-GCM，AAD 用途绑定、构建期公钥指纹钉扎、非安全上下文 fail-closed）；错误上报多层脱敏；`.env.example` 692 行全为占位符。
- **登录防枚举**：六条拒绝路径统一 401 + 哑比对时序拉平；失败计数原子 `$inc`+条件重置；peer 桶+挑战粘滞。
- **审计哈希链**：同步 WAL 行、预铸造闸、僵尸 flush 自愈、毒批逐文档隔离、外锚、周期核验七条否决臂全 fail-closed。
- **测试纪律**：无空测试/恒真断言/静默 skip；条件等待全树强制（noFixedSleepRatchet）；"前提自证+反向对照+变异实测"三件套普及；部署契约测试真校验 deployment/ 不变量。
- **CI 安全**：第三方 action 全 SHA 钉死、workflow 级 `permissions: contents:read`、`persist-credentials:false`、无 `pull_request_target`、`${{ }}` 一律走 env 通道防脚本注入。
- **部署加固**：多阶段构建+三阶段同 digest 钉扎、非 root、cap_drop:ALL、read_only、internal 网络分段、loopback-only 端口、蓝绿热升级 digest+白名单+HMAC 签名。
- **文档**：README 可核对声明逐项实测相符；21 篇 ADR 与代码抽查逐符号一致。

---

## 7. 修复路线图建议

**第一批（高价值、低风险，建议本周）**
1. P2-36：`.gitignore`/`.dockerignore` 补 `/logs-*.txt`（一行，消除 114MB 事故入口）。
2. P2-07 + P3-40：rateLimit.js username 与 errorHandler CastError 日志插值过 `stripControlChars`。
3. P2-10：dataClassification 台账 `User.mfaSecret` 改 `'gcm'`（对账唯一声明源纠偏）。
4. P2-34：migrate 写操作未设 ALLOWED_SOURCE_DB 时拒绝。
5. P2-19/P2-16/P2-17/P2-18/P2-21 + P3 测试 env 族：统一"env 快照归还 + 共享夹具 upsert + 后缀库"三件套，消掉 `--randomize` 假红源。

**第二批（性能/资源，随迭代）**
6. P2-01（auditChainVerify 投影）、P2-06（devices 导出 select）、P2-08（processLog 封顶）、P2-02（ipWindows 淘汰）、P2-04（WAL 增量裁剪）。
7. P3：reportDashboardService 缓存命中免查 dataScope、privilegeGrantService 审批人一次取回、loginChallenge 并行 count。

**第三批（安全纵深）**
8. P2-05（pepper 缺失不产出可用摘要+告警）、P2-25（photo 后端镜像格式判据）、P2-30（mongod 缓存命中重算哈希+私有目录）、P2-29（前端写入口同步重入锁统一收口）。
9. P3-43（logPiiMask 组合词 token 键）、P3-35（/export/pii、/mfa/enroll 补凭据校验链）、P3-34（/auth/session 补 strictLimiter）。

**第四批（验证与文档）**
10. P2-33：deploy.yml staging dry-run + rolling 实跑并留证；P2-31：access-review.service 运行身份与密钥权限对齐；P2-32：rollback-drill.md 口径对齐 hot-upgrade.md。
11. P2-12：openapi.json 补登 8 个规范外端点；P2-35：迁移判据抽 `_lib`；P2-13：compliance-check 补行为测试；P2-20：权限码对账闸递归扫描。
12. P2-03/P2-09/P2-11/P2-22：forensicExport 守卫、IPBlacklist durationMs 收口、信号注册前移、forensicCapturePartialBatch H-3 修复摘 `.failing`。

---

## 8. 附录

### A. 分区报告索引（26 份，含每文件逐行结论与"守护的生产文件"映射）

| 分区 | 范围 | 文件数 | P0 | P1 | P2 | P3 |
| --- | --- | --- | --- | --- | --- | --- |
| S00 | src/services 第 1 批 | 49 | 0 | 0 | 2 | 6 |
| S01 | src/services 第 2 批 | 47 | 0 | 0 | 3 | 11 |
| S02 | src/services 第 3 批 | 44 | 0 | 0 | 1 | 7 |
| S03 | controllers + routes | 57 | 0 | 0 | 0 | 7 |
| S04 | config + middleware | 50 | 0 | 0 | 1 | 4 |
| S05 | models + utils(前) | 59 | 0 | 0 | 2 | 8 |
| S06 | utils(后) + constants | 83 | 0 | 0 | 1 | 4 |
| S07 | app/index/cluster/docs/data | 8 | 0 | 0 | 2 | 8 |
| T00 | tests: app/ci/config/compliance/architecture | 114 | 0 | 0 | 1 | 7 |
| T01 | tests: constants + controllers(前) | 98 | 0 | 0 | 2 | 9 |
| T02 | tests: controllers(后) + deploy + docs | 107 | 0 | 0 | 2 | 5 |
| T03 | tests: docs/middleware/migrations/models 等 | 115 | 0 | 0 | 2 | 4 |
| T04 | tests: models/observability/routes/security(前) | 105 | 0 | 0 | 0 | 5 |
| T05 | tests: security + services(前) | 99 | 0 | 0 | 1 | 4 |
| T06 | tests: services(中) | 102 | 0 | 0 | 2 | 5 |
| T07 | tests: services(后) + 根 + utils | 115 | 0 | 0 | 2 | 6 |
| W00 | web-admin 配置/组件/composables | 66 | 0 | 0 | 1 | 7 |
| W01 | web-admin 基础设施（router/store/i18n/schemas/tests） | 56 | 0 | 0 | 0 | 7 |
| W02 | web-admin 测试（components/composables/i18n/router/store/styles） | 50 | 0 | 0 | 2 | 6 |
| W03 | web-admin 测试（utils + views 前） | 53 | 0 | 0 | 1 | 7 |
| W04 | web-admin views/utils/测试(后) + vite.config | 66 | 0 | 0 | 1 | 14 |
| SC00 | scripts 前 46 | 46 | 0 | 0 | 0 | 6 |
| SC01 | scripts 后 44 | 44 | 0 | 0 | 1 | 8 |
| S24 | 部署资产（Dockerfile/compose/nginx/observability/systemd/md） | 34 | 0 | 0 | 2 | 10 |
| S25 | .github/migrations/e2e/根测试配置 | 40 | 0 | 0 | 3 | 8 |
| S26 | 根配置/根文档/docs+ADR | 57 | 0 | 0 | 1 | 8 |
| **合计** | | **1,764** | **0** | **0** | **36** | **181** |

> 注：文件数合计 1,764 为分区任务条目数（含 web-admin 根配置在 W00/S26 的交叉覆盖）；去重后与 §1.2 覆盖率核对一致。S07 中 openapi.json 与 ip2region.xdb 按 §1.2 特殊处理。

### B. 逐文件明细

26 个分区的逐文件 appendix（每文件一行：路径 — Clean / 问题摘要，后端测试另含"守护的生产文件"推断）紧接本节之后按分区顺序附上（见下方自动续写部分）。

---

# 附录 B：逐文件审计明细（26 个分区，每文件一行）

> 说明：Clean 表示逐行精读未发现需整改问题（不等于零改进空间）。后端测试分区的 appendix 另含依据 require/import 推断的"守护的生产文件"。S07 的 openapi.json（生成物，做结构校验+全量路由对账）与 ip2region.xdb（11MB 二进制，做 sha256 内容锚+结构校验+三探针核验）按特殊处理执行，未逐行。

## S00 — src/services 第 1 批（认证/审计链/取证/蜜罐/限流等，49 文件）

## Per-file appendix（49 个文件，全部逐行读完）

| 文件 | 结论 |
| --- | --- |
| src/services/AlarmService.js | Clean（reporter.phone 明文存库为注释中已声明的残留缺口，读出口已统一收窄 `-reporter.phone`） |
| src/services/DeviceService.js | Clean（状态白名单外显式拒绝、location 合并防越权清空、删除走事务） |
| src/services/InspectionService.js | Clean（四个写操作均原子条件写；executionLog 封顶且截断可数） |
| src/services/accessReviewService.js | Clean |
| src/services/adminAccountAudit.js | Clean（凭据不入审计；经 auditOutbox 持久化留痕） |
| src/services/alertDispatch.js | Clean（频控表有硬上限+整体清空兜底，负值 env 已防） |
| src/services/alertTypes.js | Clean（枚举单源，消除双向依赖） |
| src/services/attackEventQueryService.js | Clean（入参校验完整：severity 区间、action/attackType 互斥、正则转义、时间窗上限） |
| src/services/attackProfile.js | Clean（数据范围经调用方传入，不自行放宽） |
| src/services/attackProfileClassify.js | Clean |
| src/services/attackProfileSummary.js | Clean |
| src/services/attackProfileVerdict.js | Clean |
| src/services/auditAnchorSink.js | Clean（SSRF 三段硬闸：协议→私网/回环/歧义 IPv4→白名单必配） |
| src/services/auditBuffer.js | Clean（僵尸 flush 自愈、毒批逐文档计次、丢弃唯一入口记账） |
| src/services/auditBufferDocs.js | Clean（预铸造闸消掉静默丢文档与哈希形态分叉两族缺口） |
| src/services/auditBufferWal.js | Clean（按 `__walSeq` 精确裁剪、durable 行 fsync、损坏行计数不静默） |
| src/services/auditChainAlertTypes.js | Clean |
| src/services/auditChainCheckpoint.js | P3（F-7：checkTail N+1 回溯；createCheckpoint 阻塞 IO/全集合 count） |
| src/services/auditChainMonitor.js | Clean（指纹去重、投递失败不记水位、单轮闸门+服务端预算） |
| src/services/auditChainVerify.js | P2（F-2：fetchChainWindow 无投影，最大 20 万条全字段进内存） |
| src/services/auditCheckpointFreshness.js | Clean |
| src/services/auditExportService.js | Clean（截断由查询封顶、断连全流尺度监测、manifest HMAC 签名+摘要口径自述） |
| src/services/auditFlushBatchLimit.js | Clean |
| src/services/auditMonitor.js | Clean（三维度独立频控、当日闸不依赖 TTL 竞态） |
| src/services/auditMonitorDetection.js | Clean（MTTD 记账，负延迟不伪造 0） |
| src/services/auditOutbox.js | Clean（先 WAL fsync 再回成功；invalid/wal_disabled 重抛 fail-closed） |
| src/services/auditQueryService.js | Clean（汇总 TTL 缓存、游标/偏移双模、大范围仅响应头提示避免日志噪声） |
| src/services/auditScopeFilter.js | Clean（部门缓存有界+方向性滞后已论证；DB 故障不折算成"无数据"） |
| src/services/auditWalCap.js | Clean（超限裁剪按 durable/普通分级，durable 默认不裁且归档先行） |
| src/services/auditWalPath.js | Clean（库名 encodeURIComponent 单射转义防路径逃逸与交叉重放） |
| src/services/auditWalPermissions.js | Clean（权限收紧后回读验证，失败告警不阻断） |
| src/services/authService/failureAndMfa.js | P3（F-5：与 login.js 重复的计数/锁定逻辑；另 F-8 惰性 require） |
| src/services/authService/index.js | Clean（纯再导出） |
| src/services/authService/login.js | P3（F-5 重复逻辑；F-8 惰性 require） |
| src/services/authService/password.js | Clean（条件更新防并发覆盖管理员重置；退役摘要 bcrypt 比对判不了按放行并留 error） |
| src/services/authService/profile.js | P3（F-8 惰性 require；业务逻辑 Clean：department 不可自助改、层级/状态机校验完整） |
| src/services/authService/session.js | P3（F-3：登录信息回写无 catch；其余 Clean：并发删号 fail-closed、会话降级如实返回 sid=null） |
| src/services/authService/token.js | P3（F-4：硬编码 'active'；轮换/吊销逻辑 Clean） |
| src/services/avatarService.js | Clean（at-rest 加密、读取校验 MIME+hash、指针/记录同事务） |
| src/services/behaviorBaseline.js | Clean（文件头已如实声明"能力已建成、未接线"） |
| src/services/canaryAlertTypes.js | Clean |
| src/services/canaryWatch.js | Clean（审计必写+告警日频控；遮蔽对账 fail-loud） |
| src/services/captchaService.js | Clean（一次性消费、保留键闸门、双配额归还、降级信号齐全） |
| src/services/consentService.js | Clean（查重竞态由唯一索引兜底，落库失败由调用方回滚注册） |
| src/services/deviceReminder.js | Clean（互斥锁+参数化缓存键+partial 降级形状；调度回调全部就地持 catch） |
| src/services/deviceStatsService.js | Clean（单 $facet 同快照、缺省即零结果、缓存键含库名+代际） |
| src/services/exportConcurrency.js | Clean（槽位移交防插队、释放幂等、队列定时器 unref） |
| src/services/forensicCapture.js | P2（F-1：ipWindows 无淘汰；F-6：日预算单源占比算术） |
| src/services/forensicCaptureCodec.js | Clean（字节级封顶留可见标记、凭据头单源判定、canonicalJson 稳定序列化） |

## S01 — src/services 第 2 批（取证/蜜罐/初始化/IP 名单/注入检测，47 文件）

## Per-file appendix

| 文件 | 结论 |
|---|---|
| src/services/forensicCaptureFlush.js | Clean（回填先于告警、校验失败不裁 WAL、WAL 行保留等纪律落实正确；buffer 上限 500 固定，spread-unshift 无风险） |
| src/services/forensicCaptureLifecycle.js | 基本清洁；D7 小项：ANCHOR_TICK_MS=30min 与注释"按分钟级轮询"表述不符（行为无碍） |
| src/services/forensicCapturePayload.js | P2-3：pepper 缺失时凭据摘要退化为无盐 sha256（静默） |
| src/services/forensicCaptureWal.js | P2-2：整文件读/重写模式，积压场景内存与 IO 尖峰 |
| src/services/forensicExport.js | P2-1：verifyExport 对缺 records 的畸形包抛 TypeError 而非 ok:false |
| src/services/forensicManifest.js | Clean（链式哈希、空清单判据、锚点幂等、锁内重读均正确） |
| src/services/forensicManifestLock.js | P3-11：陈锁接管+无条件 unlink 的短暂互斥缺口 |
| src/services/forensicManifestPrune.js | P3-8：today 用 UTC 日期，与业务时区 dateKey 口径分叉 |
| src/services/forensicManifestReconcile.js | P3-7：BATCH/chunk 死代码、注释过时 |
| src/services/forensicManifestRetry.js | Clean（有界、保序、头失败即停） |
| src/services/forensicTrace.js | P3-5（>32 字符指纹静默不命中）+ P3-6（lastError 死字段） |
| src/services/forensicTrigger.js | Clean（LRU 淘汰、逐条不清空、fail-visible、只读判定不续期均正确） |
| src/services/honeypotAlertTypes.js | Clean |
| src/services/honeypotChainWatch.js | Clean（跨轮去重靠审计行、单轮限额、maxTimeMS、consecutiveFailures 归零位置正确） |
| src/services/honeypotDecoy.js | Clean（身份判据只看 DB 标志、归因入口单点、404 同形） |
| src/services/honeypotDecoyFiles.js | Clean（类型集与 EXPORT_MODEL_CONFIG 对齐，'audit' 在更早分支拒绝；workbook 写失败兜底正确） |
| src/services/honeypotDecoySelf.js | Clean（limit/days 钳制、候选 id 24-hex、无原型链风险） |
| src/services/honeypotDecoySelfProfile.js | Clean |
| src/services/honeypotLurePresentation.js | Clean |
| src/services/honeypotWatch.js | P3-4：normalize 失败时审计 ip 回落原文（:134/:240） |
| src/services/initData/adminAccount.js | P3-10：明文口令文件先写后加固的 TOCTOU 窗口（有回读+回滚兜底） |
| src/services/initData/index.js | Clean（初始化顺序论证充分） |
| src/services/initData/indexes.js | Clean（四步索引切换 fail-loud，不制造约束真空期） |
| src/services/initData/permissions.js | Clean |
| src/services/initData/permissionsBusiness.js | Clean |
| src/services/initData/permissionsSystem.js | Clean |
| src/services/initData/roles.js | Clean（AUDIT_VIEWER 只读拆分、level 与权限解耦说明准确） |
| src/services/initData/seeding.js | Clean（11000 容错、软删内置权限恢复、parent 自环纠正、内置角色对账均正确；已核实 Role 模型无软删除，不存在漏恢复路径） |
| src/services/initData/systemConfig.js | Clean（$setOnInsert 防重启覆写、缓存显式失效） |
| src/services/initialPasswordFile.js | Clean（一次性凭据语义、仅默认超管可触发、失败告警） |
| src/services/injectionDetector.js | Clean（fire-and-forget、有界去重、样本清洗截断） |
| src/services/ipListService.js | Clean（populate match 防 inactive 超管误判） |
| src/services/ipLocationService.js | Clean（三态懒加载、哨兵重试、缓存键归一、失败不入缓存） |
| src/services/ipPoolBan.js | P3-14：确认时刻未复核白名单/活跃度护栏（TOCTOU） |
| src/services/ipPoolBanAudit.js | Clean（ObjectId cast 兜底、username 不再用 ObjectId 冒充） |
| src/services/ipPoolCluster.js | Clean（聚合有 maxTimeMS+allowDiskUse:false、非法段宁漏不造） |
| src/services/ipPoolLiveTraffic.js | P3-12：segmentOfIp 对压缩 IPv6 失效；主查询（timestamp 索引驱动+宽漏斗残差过滤）设计正确 |
| src/services/jwtKeyRotationAudit.js | Clean（变化检测+原子认领+失败回退基线） |
| src/services/loginChallenge.js | P3-13：登录路径 3 次串行查询；粘滞层与清零点逻辑正确 |
| src/services/loginRateLimitAudit.js | Clean（有界去重、永不抛） |
| src/services/mfaDisable.js | Clean（消费码+清状态同一条条件写、STATE_CONFLICT 判定正确） |
| src/services/mfaService.js | Clean（pepper 回退已并入 P2-3 统一表述；claimTotpWindow fail-closed、计数失败按已达阈值处理均正确） |
| src/services/permissionCatalog.js | Clean |
| src/services/permissionService.js | Clean（软删除+事务/补偿双路径、11000→409、*:* 不可停用守卫正确） |
| src/services/piiExportQuota.js | P3-9：配额日键硬编码 UTC+8；Redis fail-closed 与审计回退正确 |
| src/services/piiExportWatermark.js | Clean |
| src/services/privilegeGrantHooks.js | Clean（未注册即抛，fail-closed） |

## S02 — src/services 第 3 批（权限/会话/Token/报告/缓存/websocket，44 文件）

## Per-file appendix

| 文件 | 结论 |
| --- | --- |
| src/services/privilegeGrantService.js | P3：审批人资格判定逐码串行查库（N+1）；其余（条件更新状态机、缓存失效顺序、到期读侧判定）健全 |
| src/services/privilegeGrantValidation.js | P3：小数时长被四舍五入，与"整数"文案不符 |
| src/services/rateLimitEscalation.js | Clean（令牌桶/按压力淘汰/归一化取数均成立；进程内计数为已声明取舍） |
| src/services/rateLimitEscalationBan.js | Clean（审计与封禁无条件执行、通知才受频控；先读阶梯后落审计） |
| src/services/realtimeNotifier.js | Clean（载荷仅标识/状态，房间白名单在 WS 门面校验） |
| src/services/reauthGrantStore.js | Clean（fail-open 方向正确且留痕计数） |
| src/services/reauthTicketStore.js | Clean（jti 唯一索引显式预建、fail-closed、11000 区分重放） |
| src/services/reportDashboardService.js | P3：缓存命中路径仍每次 getDataScope 查库 |
| src/services/reportExportService.js | P2：devices 导出无投影拉全文档；其余（公式注入防护、PII 掩码、审计枚举白名单、三态截断对账）健全 |
| src/services/reportStatsService.js | Clean（$facet 收敛、byDay 窗口有上界、口径与 deviceAlerts 同源） |
| src/services/reportTargetService.js | Clean（Object.hasOwn 防原型链、$and 叠加不覆盖范围臂、最小投影） |
| src/services/reportWorkbookService.js | Clean（探针判截断、rowsLost/countDrift 分账、响应终局事件等待） |
| src/services/roleService.js | Clean（$match 前置、CAS 删角色、中断对账、蜜罐排除） |
| src/services/scanProbeDetector.js | Clean（有界计数、去重、fire-and-forget、取证标记吞错） |
| src/services/securityAlert.js | Clean（双维度计数、R-H2 封禁只看 IP 维度、审计/封禁/通知解耦、fail-closed 会话读取） |
| src/services/securityAlertDelivery.js | Clean（SSRF 白名单+IP 钉扎+DNS 重绑定防护、HMAC 含时间戳/nonce、并发上限、缺密钥 fail-closed） |
| src/services/securityAlertIpBans.js | Clean（阶梯事件源用 append-only 审计、$ne:false 剔除只告警行、共享出口宽限） |
| src/services/securityAlertPermissionAbuse.js | Clean（先读阶梯后写审计、封禁按返回值、共享出口护栏） |
| src/services/sessionCap.js | Clean（按 lastSeenAt 淘汰、条件更新防并发误杀） |
| src/services/sessionRevocationEvents.js | Clean（进程内总线、监听器异常不回抛） |
| src/services/sessionService.js | Clean（代际写回闸门、跨实例广播、精准批次失效、fail-closed 校验） |
| src/services/sharedCache/index.js | Clean（set 返回值语义、getDel 原子化、incr/decr 的 Lua 单脚本、setIfAbsent fail-closed） |
| src/services/sharedCache/invalidation.js | Clean（独立订阅连接、吞错契约、未发出也留痕） |
| src/services/sharedCache/memoryStore.js | Clean（critical 键不参与淘汰、饱和告警节流） |
| src/services/sharedCache/scripts.js | Clean（PTTL 先于 DECR 读，残键删除不复活） |
| src/services/sharedCache/state.js | Clean |
| src/services/sharedCacheLocks.js | Clean（CSPRNG 锁令牌、释放/续租按令牌比对、极性文档化） |
| src/services/startupAuditTrail.js | Clean（两条留痕均不阻断启动） |
| src/services/statsCache.js | Clean（generation 全量失效、TTL 上界夹取、显式启停定时器） |
| src/services/stuffingProfile.js | Clean（无模块级样本容器、窗口自述、诱饵成功剔除） |
| src/services/tokenService.js | Clean（type 用途闸、jti/sid 分工、与 authenticate 同口径探测） |
| src/services/upgradeRequestSignature.js | Clean（canonical 分型防串型、timingSafeEqual、密钥长度闸） |
| src/services/upgradeService.js | Clean（readiness 码化、O_NOFOLLOW+大小上限、原子写、入队锁、mtime 两段式列表） |
| src/services/userAnonymizationBatch.js | Clean（快照条件载入、整批中止、凭证排除投影复用） |
| src/services/userPermissionService.js | P3：超限整体 clear 的惊群面（有界、有意）；代际闸门/降级 TTL/批量合并均健全 |
| src/services/userService.js | P3：deleteMany 无快照路径预取/删除 TOCTOU；其余（PII 掩码、盲索引搜索、级联释放、匿名化投影）健全 |
| src/services/webhookTargetResolver.js | Clean（一次解析钉扎、任一地址命中禁段即拒、解析超时） |
| src/services/websocketService/handshake.js | P3：catch 读 err.message 无非 Error 兜底；认证链（黑名单→令牌→用户→蜜罐→锁定→tokenVersion→改密→allowedIPs→会话→在途复检）完整 |
| src/services/websocketService/inboundThrottle.js | Clean（socket.use 全事件覆盖、断开后静默、指标按连接计） |
| src/services/websocketService/index.js | P3：CORS 回退列表与 app.js 重复声明；通配符拒绝、门面 mixin 装配正常 |
| src/services/websocketService/lifecycle.js | Clean（批量复查 $in 化、防重入、名单/会话复查先于授权复查） |
| src/services/websocketService/push.js | Clean（guardSocketHandler 防未处理拒绝、入房白名单+角色复查、未认证 IP 配额、统计不泄露明细） |
| src/services/websocketService/sessionRevocation.js | Clean（sids/all 双匹配面、跨实例按库复查兜底） |
| src/services/websocketService/shared.js | Clean（常量与谓词单源、入站令牌桶参数有依据） |

## S03 — src/controllers + src/routes（57 文件）

## Per-file appendix

| 文件 | 结论 |
| --- | --- |
| src/controllers/alarmController.js | Clean |
| src/controllers/auditController.js | P3-5：/audit-logs 处理器本体在 service 层，控制器仅转出 |
| src/controllers/authController/credentials.js | P3-4：refreshToken 兜底 catch 吞异常成 400 且零日志 |
| src/controllers/authController/index.js | Clean（门面，导出面与实现一一对应） |
| src/controllers/authController/profile.js | Clean |
| src/controllers/authController/session.js | Clean |
| src/controllers/authController/shared.js | Clean |
| src/controllers/avatarController.js | Clean（读取授权/ETag/nosniff+CSP sandbox 齐全） |
| src/controllers/deviceController.js | Clean（scrapDate/days 的边界在 service/常量层已收口） |
| src/controllers/forensicController.js | Clean |
| src/controllers/inspectionController.js | Clean |
| src/controllers/inspectionGuards.js | Clean |
| src/controllers/ipListController.js | Clean |
| src/controllers/ipListSegmentGuards.js | Clean |
| src/controllers/ipListWriteGuards.js | Clean |
| src/controllers/mfaController.js | Clean（P3-1 的根因在路由链顺序，非本文件） |
| src/controllers/permissionController.js | Clean |
| src/controllers/privilegeController.js | Clean |
| src/controllers/reportController.js | Clean（audit 导出越权出口已封、时区参数 400 校验到位） |
| src/controllers/roleController.js | Clean |
| src/controllers/roleGuards.js | Clean |
| src/controllers/rolePermissionController.js | Clean |
| src/controllers/securityController/account.js | Clean |
| src/controllers/securityController/admin.js | Clean（范围闸+层级闸+条件更新+审计先持久化） |
| src/controllers/securityController/attackEvents.js | Clean |
| src/controllers/securityController/config.js | Clean |
| src/controllers/securityController/index.js | Clean（门面） |
| src/controllers/securityController/overview.js | Clean |
| src/controllers/securityController/profile.js | Clean |
| src/controllers/securityController/reauth.js | Clean |
| src/controllers/securityController/shared.js | Clean |
| src/controllers/securityController/sensitive.js | Clean（层级+范围双闸、审计重抛档） |
| src/controllers/securityController/upgrade.js | Clean（控制器内再验 *:*） |
| src/controllers/userController/create.js | Clean |
| src/controllers/userController/delete.js | Clean |
| src/controllers/userController/index.js | Clean（门面） |
| src/controllers/userController/read.js | Clean |
| src/controllers/userController/roles.js | Clean |
| src/controllers/userController/shared.js | Clean |
| src/controllers/userController/update.js | Clean |
| src/routes/alarmRoutes.js | P3-7：写链不挂 consumeValidation，依赖控制器消费（已核实均消费） |
| src/routes/attackEventRoutes.js | Clean |
| src/routes/attackProfileRoutes.js | Clean |
| src/routes/authRoutes.js | P3-1（/mfa/enable 校验序）、P3-2（/session 无专属限流）、P3-3（/mfa/enroll 无凭据校验链） |
| src/routes/avatarRoutes.js | Clean |
| src/routes/deviceRoutes.js | P3-7：同上（写链依赖控制器消费，已核实均消费） |
| src/routes/forensicRoutes.js | Clean |
| src/routes/index.js | Clean |
| src/routes/inspectionRoutes.js | P3-7：同上（写链依赖控制器消费，已核实均消费） |
| src/routes/permissionRoutes.js | P3-7：同上（create/update/batch 依赖控制器消费，已核实均消费） |
| src/routes/reportRoutes.js | P3-3：POST /export/pii 未挂 reauthCredentialValidation |
| src/routes/roleRoutes.js | P3-7：同上（create/update/assign 依赖控制器消费，已核实均消费） |
| src/routes/securityRoutes.js | Clean（链路完整性与消费情况逐条核实无误） |
| src/routes/stuffingProfileRoutes.js | Clean |
| src/routes/userRoutes.js | P3-7：同上（写链依赖控制器消费，已核实均消费） |
| src/routes/versionRoutes.js | P3-6：匿名构建元数据暴露版本/buildId/uptime |
| src/routes/wellKnownRoutes.js | Clean（上报端点限流/截断/脱敏/不进审计链的边界清晰） |

## S04 — src/config + src/middleware（50 文件）

## Per-file appendix

| 文件 | 结论 |
|---|---|
| src/config/buildInfo.js | Clean — 匿名 /api/version 最小字段面正确；git 子进程 1s 超时 + 吞异常，不阻断启动 |
| src/config/database.js | Clean — 连接串 userinfo 脱敏（含 SRV/未转义 `/` 边界）正确；指数退避 + 抖动 + waitQueue 封顶合理 |
| src/config/deploymentCredentialGuards.js | P3-3（CORS 默认端口/大小写形态静默失效）；其余判据（弱口令/webhook/日志外发）fail-closed 正确 |
| src/config/envSemantics.js | Clean — NODE_ENV 归一 fail-closed（空串≠未设置），staging 默认同生产、显式宽松才放行 |
| src/config/immutableConfigGuard.js | Clean — 告警+计数不阻断的取舍有完整论证；旧钥驻留/v1 未迁移判据仅生产生效，合理 |
| src/config/index.js | Clean — 密钥文件注入先于所有 env 读取；限流参数生产越界即抛；bcrypt 10–14 夹取安全 |
| src/config/jwtRotation.js | Clean — kid 集合形状/强度/同值互斥校验完整，hasOwnProperty 防原型属性名 |
| src/config/legacyCbcGuard.js | Clean — 告警+计数不阻断，理由（迁移死锁）成立 |
| src/config/loginEncryptGuard.js | Clean — strict 未开仅告警+计数，HTTP 内网形态豁免论证成立 |
| src/config/loginGuard.js | Clean — 阈值夹取（含粘滞窗 1min–7d）合理 |
| src/config/proxyProtocol.js | P3-2（ENV_KEY 拼接）；判据本身 fail-closed 正确，与 ENABLE_HTTPS 组合拒绝有据 |
| src/config/secrets.js | Clean — BOM/NUL/空文件/尾部换行处理完备，冲突以文件为准并告警 |
| src/config/swagger.js | Clean — basicAuth fail-closed + SHA-256 恒时比较；文档限流共享存储 + 归一化键正确 |
| src/config/transportSecurity.js | Clean — 回环/localhost 判据精确（含 ::ffff: 前缀），TLS/认证闸豁免均需显式旗标 |
| src/config/trustedProxies.js | P3-2（ENV_KEY 拼接）；解析判据（空项/非法/全域网段拒绝、裸地址 /32）fail-closed 正确 |
| src/config/upgrade.js | Clean — 空白名单=全拒；非法值告警后回落 |
| src/config/validate.js | Clean — 生产硬闸覆盖密钥/轮换/连接/Host/TLS/时区/JWT 时长；未识别 NODE_ENV 按生产办 |
| src/middleware/auth.js | Clean — kid 选钥+限算法、用途校验、黑名单/会话 fail-closed 503、tokenVersion 强制、IP 范围用安全裁决地址、缓存失效竞态处理正确；审计写入经 AuditLog.record（永不 reject）安全 |
| src/middleware/dataScope.js | Clean — GUEST=all 为文档化设计（写权限由权限码收口）；范围判定 fail-closed；请求内 promise 记忆化正确 |
| src/middleware/errorHandler.js | P3-1（CastError 消息入日志未清洗）；headersSent/更正事件/双写防护/ApiError code 透传均正确 |
| src/middleware/httpMethods.js | Clean — 写方法单一事实来源，消除了三处漂移 |
| src/middleware/idempotency.js | Clean — 唯一索引判据+原子接管+租约+回放裁剪降级，交错场景（接管后释放键只删自己认领）处理正确 |
| src/middleware/index.js | Clean — 统一导出面，消除双入口 |
| src/middleware/injectionSignature.js | Clean — detect-only、fire-and-forget（guardDetection 永不 reject）、去重 Map 有界 |
| src/middleware/logoutAuth.js | Clean — refresh 回退验签/黑名单完整，错误口径统一到 mapAuthFailure，不匿名放行 |
| src/middleware/metricsAuth.js | Clean — socket 对端裁决 + 反代拓扑强制令牌 + 恒时比较，fail-closed |
| src/middleware/noStore.js | Clean |
| src/middleware/originCheck.js | Clean — 空 Origin 与无 Origin 分开处理（fail-closed 方向）；无 Origin 放行有 SameSite=Lax 兜底且论证成立 |
| src/middleware/protocolCompliance.js | Clean — 五项校验顺序正确，Host 豁免精确等值且只免 Host 一项；审计写入带 .catch |
| src/middleware/queryLimit.js | Clean — 长度/标量双闸独立成立；白名单豁免只给频次型不给形态型，正确 |
| src/middleware/rateLimit.js | P2-1（username 插值日志注入）；限流桶分层（IP/账号/对端/静态面/未匹配/预检）推导完整，XFF 轮换防绕过（loginPeerLimiter）正确 |
| src/middleware/rateLimitStore.js | Clean — 降级/恢复信号可复位、四方法统一降级、init 动态分发，多实例口径诚实 |
| src/middleware/rbac.js | Clean — 权限通配/数据范围全部 fail-closed（缺信息=deny/403）；applyDataScopeToQuery 抛 403 消除「空集≠无范围」歧义 |
| src/middleware/requestId.js | Clean — 服务端生成主键、客户端 ID 仅入日志上下文 |
| src/middleware/security/auditLog.js | Clean — GET/HEAD 默认审计+豁免收窄、skipGlobalAudit 响应时刻读取、深度对齐 6 层、defineProperty 防 __proto__ 蒸发 |
| src/middleware/security/earlyRejection.js | Clean — AuditLog.record 永不 reject，setImmediate 内安全 |
| src/middleware/security/forensicCapture.js | Clean — 不改写响应、finish 后处理、异常只计数 |
| src/middleware/security/index.js | Clean — 步进验证密码/MFA 双通道共享失败锁、TOTP 原子消费防重放；fileUploadSecurity 构造期 fail-closed |
| src/middleware/security/ipBlacklist.js | P3-4（白名单豁免形态 3) 信任任意私网对端，文档化残余风险）；DB 故障降级 fail-open 有 high 级告警计数 |
| src/middleware/security/ipBlacklistStore.js | Clean — 归一化入库、白名单优先、返回值契约明确 |
| src/middleware/security/reauthCredentialRules.js | Clean — strict 模式明文/密文互斥，长度上限与登录链对齐 |
| src/middleware/security/reauthTicket.js | Clean — 窗口优先/票据一次性，存储故障 fail-closed |
| src/middleware/security/sanitize.js | Clean — materializeQuery 物化+自证（不一致即 500 拒绝）是 Express 5 下唯一正确收口；深度上限方向为删除 |
| src/middleware/security/securityHeaders.js | Clean — CSP nonce、Swagger style 豁免收敛到文档路径、Trusted Types 灰度/强制互斥正确 |
| src/middleware/sentry.js | Clean — 采集白名单+beforeSend 出网咽喉双层收口，白名单防未知键，v7/v8 断言带指引 |
| src/middleware/staticFrontend.js | Clean — .map/.ts 解码后判定、sendFile root 模式、SPA 吞没分支也过未匹配探测桶 |
| src/middleware/tokenBlacklist.js | Clean — 存哈希、fail-closed 上抛、E11000 按 keyPattern 区分重放/索引故障，原子消费消除 TOCTOU |
| src/middleware/userAuthCache.js | Clean — 失效标记竞态处理正确，广播 promise 由本模块持有（防 unhandledRejection 退进程） |
| src/middleware/validateObjectId.js | Clean — 子 Router 逐个注册（app.param 死代码问题已修正），WeakSet 幂等 |
| src/middleware/validateQuery.js | Clean — 校验结果统一消费，消除「挂了校验链不读结果」的失效形态 |

### 核实记录（范围外定点取证）

- `src/models/auditLogWriteStatics.js:100-113` — `AuditLog.record` 内部 catch 并计数、resolve(null)，**永不 reject**：auth.js:281、earlyRejection.js:35 的裸调用不构成未处理拒绝风险。
- `src/utils/auditWriteFailure.js` — `guardDetection` 契约为「永不 reject」，injectionSignature 的 fire-and-forget 安全。
- `src/utils/logger.js:32-56,105-150` — 非 生产环境 为 printf（message 内 `\n` 原样换行），生产为 JSON（`\n` 转义但 U+2028–U+202E 不转义）：支撑 P2-1/P3-1 的定级。

## S05 — src/models + src/utils 前半（59 文件）

## Per-file appendix

| 文件 | 结论 |
| --- | --- |
| src/models/AuditLog.js | Clean（索引设计有据；TTL/复合索引/稀疏索引取舍均有实测注释；哈希链字段齐备） |
| src/models/ConsentRecord.js | 问题：ip/userAgent 无长度上限与控制字符清洗（P3） |
| src/models/FireAlarm.js | 问题：processLog 数组无封顶无计数（P2）；其余（PII 加密 AAD 绑定、TTL 闸、索引）Clean |
| src/models/FireDevice.js | Clean（乐观并发、数组封顶、状态机、索引替换而非并存均到位） |
| src/models/ForensicCapture.js | Clean（minimize:false 防哈希复核假阳性；TTL 条件化；索引齐备） |
| src/models/IPBlacklist.js | 问题：blockIP 对 NaN/字符串 durationMs 失败方向危险（P2）；快照缓存/归一化/合并语义本身 Clean |
| src/models/IdempotencyRecord.js | Clean |
| src/models/Inspection.js | Clean（TTL 计龄闸、executionLogCount 截断可数、级联索引补齐） |
| src/models/Permission.js | Clean（软删除过滤覆盖 find/count/distinct/aggregate/写钩子；fail 方向正确） |
| src/models/PrivilegeGrant.js | Clean（双审批上限、快照字段、读路径索引齐备） |
| src/models/ReauthGrant.js | Clean |
| src/models/ReauthTicketUse.js | Clean |
| src/models/Role.js | Clean（内置角色删除保护覆盖 Query/bulkWrite/文档级入口，空过滤器显式拒绝） |
| src/models/SystemConfig.js | Clean（负缓存、'false' 布尔陷阱、验证码降级统一信号均处理；30s 多实例陈旧为已声明权衡） |
| src/models/TokenBlacklist.js | Clean |
| src/models/User.js | 问题：toJSON getters:true 默认吐明文 PII 属默认不安全取向，靠投影纪律与测试闸把守（P3）；其余（PII 加密接线、凭证投影、用户名 collation、密码字节级上限）Clean |
| src/models/UserAvatar.js | Clean |
| src/models/UserSession.js | Clean（update 路径 IP 闸、TTL/复合索引、toClientJSON 脱敏边界清晰） |
| src/models/auditLogHooks.js | Clean（append-only 全入口覆盖、链尾推进锁内原子化、失败盖章降级可观测） |
| src/models/auditLogQueryStatics.js | Clean（聚合预算、阈值统一、时区口径） |
| src/models/auditLogSanitizer.js | Clean（双名单并集、__proto__ 保真、字节预算、截断留痕） |
| src/models/auditLogWriteStatics.js | 问题：riskFactors 子串匹配误标（P3）；其余 Clean |
| src/models/index.js | Clean |
| src/utils/ApiError.js | Clean |
| src/utils/accessLogDevFormat.js | Clean |
| src/utils/apiResponse.js | 问题：paginated 对非数值 meta 静默回退（P3）；错误响应 no-store 等其余 Clean |
| src/utils/auditChain.js | Clean（锁超时/代际/围栏/共享尾可信度处理极其细致）；依赖 services/sharedCache 属分层倒置（P3，见共性问题条目） |
| src/utils/auditChainFence.js | 问题：僵尸永不落定时锁无限续租无上界（P3） |
| src/utils/auditChainPayload.js | Clean（版本化 payload、冻结字段表、v3 快照修正） |
| src/utils/auditChainTail.js | Clean（链尾判据：无子记录者 + 窗口反查，_id 序假设已破除） |
| src/utils/auditMeta.js | Clean（大小写折叠白名单、动态段剔除、伪造段防护） |
| src/utils/auditQuery.js | Clean（恒空组合穷举判定、collation 按需挂载、U+FFFF 哨兵上界有实测） |
| src/utils/auditWriteFailure.js | Clean（非 Error 兜底、迟到失败记账、检测器不外抛外壳） |
| src/utils/avatarImage.js | Clean（严格 Base64、段白名单、EOI 钉尾、解压前尺寸闸） |
| src/utils/avatarImageError.js | Clean |
| src/utils/avatarUrl.js | Clean |
| src/utils/bcryptWorkerPool.js | 问题：初始化中途失败泄漏已建 worker（P3）；队列上限/崩溃兜底/exit 统一处理本身 Clean |
| src/utils/bcryptWorkerThread.js | Clean（操作白名单） |
| src/utils/cidrCoverage.js | Clean（BigInt 区间合并，删除侧对称判定） |
| src/utils/constants.js | Clean（伪枚举已清理并留判据） |
| src/utils/cookie.js | 问题：durationToMs 数值入参语义与 jsonwebtoken 分叉仅注释防御（P3）；其余（__Host- 前缀、双名清理、降级清 refresh）Clean |
| src/utils/crashFlush.js | Clean（硬预算、失败不阻断退出）；依赖 services 属分层倒置（P3 共性条目） |
| src/utils/cursorPagination.js | Clean（空值块/平局裁决/注入防护/长度上限推导自模型） |
| src/utils/dateFormat.js | Clean |
| src/utils/emailKey.js | Clean |
| src/utils/encryption.js | Clean（GCM 形状校验、CBC 默认封死、timingSafeEqual、随机串无偏采样、脱敏兜底全掩码） |
| src/utils/envNumber.js | Clean（未配置与非法分离开） |
| src/utils/errorCodes.js | Clean（防枚举口径明确、注册表自检） |
| src/utils/filePermission.js | Clean（icacls /reset + /inheritance:r 两步、提示与执行共用 argv、校验 fail-closed） |
| src/utils/fingerprint.js | Clean |
| src/utils/forensicDeviceKey.js | Clean |
| src/utils/healthChecks.js | Clean（缓存防放大、reason/detail 分离防拓扑泄露、晚到 rejection 接住） |
| src/utils/helpers.js | Clean（歧义日期回夹、fail-closed 规则解析、敏感键双名单并集、ID 大小写归一） |
| src/utils/httpPostJson.js | Clean（双层超时、settled 守卫、响应体上限） |
| src/utils/idempotencyKey.js | Clean（键哈希加盐、全深度规范化、环防护） |
| src/utils/ip2regionSearcher.js | Clean（加载期全量结构校验、段内字段双界校验、失败哨兵+限时重试） |
| src/utils/ipRange.js | Clean（fail-closed、前导零拒绝、超量整体判无效） |
| src/utils/ipUtils.js | Clean（歧义文本四漏斗共用判据、映射网段换算、惩罚目标裁定闭环） |
| src/utils/jwtKeys.js | Clean（kid 选钥、未知 kid 不回退、legacy 钥可关停） |

## S06 — src/utils 后半 + src/constants（83 文件）

## Per-file appendix（83 文件）

### src/utils（34）
- src/utils/logContext.js — Clean
- src/utils/logPaths.js — Clean
- src/utils/logPiiMask.js — [P3][D3] 凭据键后缀集缺口：authToken/apiToken/sessionToken 等组合词 token 键不被 redact（见发现 4）
- src/utils/logShipper.js — Clean（断档标记/串行 flush/关停排空账目自洽）
- src/utils/logShippingTarget.js — Clean（SSRF 判据 + DNS 钉扎）
- src/utils/logger.js — Clean
- src/utils/loggerFlush.js — Clean
- src/utils/loginCipher.js — Clean（ECIES 信封实现正确）
- src/utils/metrics.js — Clean
- src/utils/metricsAuditDrops.js — Clean
- src/utils/metricsDetection.js — Clean
- src/utils/metricsRuntime.js — Clean
- src/utils/mfaSecret.js — Clean（fail-closed 加密）
- src/utils/mongoDuplicateKey.js — Clean
- src/utils/mongoFailureAttribution.js — Clean（infra/content 双表判据方向保守正确）
- src/utils/passwordHistory.js — Clean
- src/utils/permissionHelper.js — [P3][D6] getMenuTree 吞错返回空菜单（见发现 6）
- src/utils/permissionSync.js — Clean
- src/utils/piiCrypto.js — Clean（v2 AAD 行绑定正确）
- src/utils/pngStructure.js — Clean
- src/utils/proxyProtocol.js — Clean（v1/v2 严格解析 + 钉扎）
- src/utils/queryBudget.js — Clean
- src/utils/reauthTicket.js — Clean
- src/utils/scopeCast.js — Clean（含 $where/$expr/$function 注入闸）
- src/utils/searchPatterns.js — Clean
- src/utils/shutdownBudget.js — Clean
- src/utils/superAdmin.js — Clean
- src/utils/temporaryPassword.js — Clean
- src/utils/tokenPurpose.js — Clean
- src/utils/totp.js — Clean（RFC 6238 实现正确，常量时间比较覆盖全窗口）
- src/utils/transaction.js — Clean（拓扑探测缓存策略正确）
- src/utils/validationRules.js — Clean（safeFieldErrors 防口令出站）
- src/utils/xlsxWriter.js — Clean
- src/utils/zipContainer.js — Clean

### src/constants（49）
- src/constants/alarm.js — Clean
- src/constants/attackEvents.js — Clean（action 全集 ⊆ AUDIT_LOG_ACTIONS 已逐一核对）
- src/constants/attackProfile.js — Clean（auth_failed 为已登记幽灵 token，非缺陷）
- src/constants/audit.js — Clean
- src/constants/backupObjectives.js — Clean
- src/constants/banRefusalReason.js — Clean
- src/constants/breachedPasswords.js — Clean
- src/constants/businessRetention.js — Clean
- src/constants/canaryAccounts.js — Clean
- src/constants/credentialShape.js — Clean
- src/constants/dataClassification.js — [P2][D7] User.mfaSecret 声明 plain 与实际 GCM 加密不符（见发现 1）
- src/constants/dataScopeFields.js — Clean
- src/constants/detectionObjectives.js — Clean
- src/constants/deviceAlerts.js — Clean
- src/constants/deviceStatus.js — Clean
- src/constants/failOpenSites.js — Clean
- src/constants/honeypotAccounts.js — Clean（超管名剔除判据正确）
- src/constants/honeypotDecoy.js — Clean
- src/constants/honeypotDecoyAggregates.js — Clean
- src/constants/honeypotDecoyAggregatesData.js — [P3][D1] hp-g6 时间线自相矛盾（expiresAt 符号/吊销晚于到期，见发现 2）
- src/constants/honeypotDecoyAlarms.js — Clean
- src/constants/honeypotDecoyData.js — Clean
- src/constants/honeypotDecoyDevices.js — Clean
- src/constants/honeypotDecoyFiles.js — Clean（导出面与数据面同一引用，无第二份行）
- src/constants/honeypotDecoyIds.js — Clean
- src/constants/honeypotDecoyInspections.js — Clean
- src/constants/honeypotDecoyListQuery.js — Clean
- src/constants/honeypotDecoyListShape.js — Clean
- src/constants/honeypotDecoyMetrics.js — [P3][D7] alerts 序列含真实系统永不发出的 unusual_time_access（见发现 3）
- src/constants/honeypotDecoyRbac.js — Clean
- src/constants/honeypotDecoySelf.js — Clean
- src/constants/honeypotDecoyShape.js — Clean
- src/constants/honeypotDecoyUsers.js — Clean
- src/constants/honeypotPersonas.js — Clean
- src/constants/honeypotRouteTable.js — Clean
- src/constants/honeypotTicketGate.js — Clean
- src/constants/inspection.js — Clean
- src/constants/ipList.js — Clean
- src/constants/ipLocationCodes.js — Clean
- src/constants/permission.js — Clean
- src/constants/privilegeGrant.js — Clean
- src/constants/probePaths.js — Clean
- src/constants/reportExportColumns.js — Clean
- src/constants/reportExportLabels.js — Clean（中英表头与列定义逐列同序已核对）
- src/constants/retention.js — Clean
- src/constants/runtime.js — Clean
- src/constants/securitySuggestions.js — Clean
- src/constants/stuffingProfile.js — Clean
- src/constants/timezone.js — Clean

## S07 — src/app.js / index.js / cluster.js / plugins / docs / data（8 文件）

## Per-file appendix

| 文件 | 结论 |
|---|---|
| src/app.js | 基本 Clean。P3：morgan 挂载晚于早期拒绝闸门，访问日志缺 403/429 记录（审计链+指标已补偿）。中间件顺序、trust proxy 夹取、CORS 求值、docs basicAuth fail-closed 均核验无恙 |
| src/cluster.js | P3：退避日志与判据矛盾（×0/存活≥稳定窗仍打「短命连发」+500ms 伪退避）；P3：CLUSTER_WORKERS 非法值/上限夹取静默。fork 补偿、转发关停、兜底退出定时器逻辑正确 |
| src/index.js | P2：信号处理器注册过晚（启动窗口 SIGTERM 硬杀，WAL 重放可兜数据）；P3：unhandledRejection fail-fast 设计取舍。优雅关闭链（预算、逐步硬闸、WS 先停、frontServer 处理、SIEM 尾排空）完整 |
| src/plugins/autoIncrement.js | 基本 Clean。P3：$substrBytes 偏移按 UTF-16 长度计算，非 ASCII 前缀会错位（当前全 ASCII，潜伏）。双钩子幂等、对齐双证据判据、无 upsert 的推进防重号设计均正确 |
| src/docs/generate.js | 基本 Clean。P3：CLI 写盘非原子。枚举全部接 constants 单源，anonymous/Idempotency-Key/X-Reauth-Ticket 标记与实现一致 |
| src/data/README.md | 基本 Clean。P3：未提 sha256 内容锚与数据时效（2024-02-28 版）。来源、许可证、入库理由、格式说明与实测一致 |
| src/docs/openapi.json | P2：实际暴露面大于文档（/readyz、/metrics、/api/metrics、/api-docs、well-known 族未入 spec）。与生成器逐字节一致（108 path/129 op，drift 门禁在位），抽 12+ 路径与方法/鉴权/幂等/再验票据标记对账零漂移 |
| src/data/ip2region.xdb | Clean。11,070,083 字节，sha256 与 deployment/ip2region-checksum.json 锚一致；v2 结构校验通过；三探针通过；更新脚本具备内容锚闸+原子替换 |

## 附：核验方法说明（openapi.json 与 ip2region.xdb）

- openapi.json：以 `require('./src/docs/generate')`（L-24 保证无副作用）与已提交产物做 `isDeepStrictEqual` 深比（结果一致）；再用只读脚本从 16 个 route 文件提取全部 `router.<method>` 定义，按 app.js 挂载前缀拼接后与 spec 做 path+method 双向全量比对：除 forensicRoutes 经 `securityRoutes` 内 `router.use('/forensic', …)` 并入（与 spec 的 `/api/security/forensic/*` 一致）及尾斜杠等价形式外，无任何缺失/多出/方法不符；匿名 10 端点、Idempotency-Key 8 端点、X-Reauth-Ticket 9 端点与路由中间件链逐一吻合。
- ip2region.xdb：不逐行（二进制）。以 `src/utils/ip2regionSearcher.loadFromBuffer` 做结构校验（version=2、段索引指针界、65536 桶指针全扫）、sha256 对 `deployment/ip2region-checksum.json` 内容锚、以及 `update-ip2region.js` 同款三探针，全部通过；数据构建时间 2024-02-28。

## T00 — src/tests：app / ci / compliance / architecture / config 等（114 文件）

## Per-file appendix（114 个文件，全部逐行读完）

| 文件 | 结论 | 守护的生产文件（依 require/import 推断） |
|---|---|---|
| src/tests/alarmHandlerCanOperate.test.js | Clean | middleware/rbac.js、constants/dataScopeFields.js、controllers/alarmController（arrive/resolve）、models/FireAlarm、models/User/Role/Permission |
| src/tests/alarmHandlerListVisibility.test.js | Clean | utils/scopeCast.js、services/AlarmService.js |
| src/tests/alarmStatsScopeCast.test.js | Clean | services/AlarmService.js（getAlarmStats）、models/FireAlarm |
| src/tests/app/appBehaviorGuards.test.js | Clean | src/app.js（trust proxy 非法值回退、/api-docs.json Basic Auth）、config/swagger.js |
| src/tests/app/appTrustProxyAndReadyzGuards.test.js | Clean | src/app.js（trust proxy 夹取、/api 根、/readyz 双失败路径、多实例与事务拓扑 fail-closed）、utils/healthChecks、utils/transaction、services/sharedCache |
| src/tests/app/earlyRejectionIpRateLimited.test.js | Clean | src/app.js 挂载顺序（ipLimiter 先于合规闸）、middleware/rateLimit.js、middleware/security（协议违规审计） |
| src/tests/app/earlyRejectionRateLimited.test.js | Clean | 同上（generalLimiter 维度） |
| src/tests/app/earlyRejectionRateLimitedAllSurfaces.test.js | Clean | 限流全表面覆盖（/、/csp-report、/api-docs、/api/*）、探针豁免、静态面 |
| src/tests/app/earlyRejectionSecurityHeaders.test.js | Clean | 安全头栈在早期拒绝响应上的覆盖、app 级 x-powered-by 关闭 |
| src/tests/app/probeExemptionBoundaryAndHeadAudit.test.js | Clean | 探针豁免精确性（路径+方法）、HEAD 审计同尺（utils/auditMeta、审计中间件）、OPTIONS 预检桶 |
| src/tests/app/queryDefenseSingleSource.test.js | Clean | middleware/security（materializeQuery）、middleware/queryLimit、app.js 挂载顺序 |
| src/tests/app/staticSurfaceRateLimitGate.test.js | Clean | middleware/rateLimit.js 与 middleware/staticFrontend.js 判据单一来源、staticSurfaceLimiter |
| src/tests/appendOnlyHashlessRow.test.js | Clean | models/auditLogHooks.js（append-only 护栏不依赖 hash 字段）、models/AuditLog、services/auditChainVerify |
| src/tests/architecture/layeringRatchet.test.js | Clean | controllers/** 分层纪律（直连 models 基线棘轮） |
| src/tests/architecture/requireCycles.test.js | Clean | 全 src 依赖图（无环、惰性 SCC 登记、require 可解析） |
| src/tests/architecture/sensitiveFieldEgressContract.test.js | Clean | models/** 的 select:false 字段出口策略（RESPONSE_EXCLUDE/toClientJSON） |
| src/tests/auditBodyProtoFidelity.test.js | Clean | models/auditLogSanitizer、utils/helpers（stripControlCharsDeep）、models/AuditLog 链一致性 |
| src/tests/auditBufferZombieDuplicate.test.js | Clean | services/auditBuffer、utils/auditChain（链锁超时/僵尸写入幂等）、services/auditBufferWal |
| src/tests/auditCategoryLiteralWhitelist.test.js | Clean | constants/audit（AUDIT_CATEGORIES）vs src/scripts/migrations 手写 category 字面量 |
| src/tests/auditExportDataScope.test.js | Clean | controllers/reportController（export?type=audit）、services/reportExportService、auditQueryService（applyAuditDataScope） |
| src/tests/auditFailedStreamFlag.test.js | Clean | middleware/security（auditLog）、middleware/errorHandler（responseAbortedByError）、services/auditBuffer |
| src/tests/auditFieldSetsImmutable.test.js | Clean | utils/auditChainPayload（冻结字段清单、版本分派） |
| src/tests/auditFilterParity.test.js | Clean | utils/auditQuery、services/reportExportService、constants/audit（枚举同源） |
| src/tests/auditIndexDiff.test.js | Clean | scripts/sync-audit-indexes.js（diffIndexes/verdictLine/describeFatalError） |
| src/tests/auditSpecialKeyPayload.test.js | Clean | models/AuditLog.record（$ 前缀/点号键落库与链自洽）、services/auditChainVerify |
| src/tests/auditTtlMigration.test.js | Clean | migrations/20260919000000-reconcile-audit-ttl-to-retention、constants/retention、migrate-mongo-config |
| src/tests/auditWalLimitsAndLines.test.js | Clean | services/auditBufferWal（大小上限、行尾补齐、按序号裁剪） |
| src/tests/authTemporaryLockExpiryBoundary.test.js | Clean | middleware/auth（assertAccountUsable lockUntil 到期放行） |
| src/tests/backfillTokenVersion.test.js | Clean | migrations/20260830000000-backfill-token-version（up/down 射程） |
| src/tests/backupScriptGuards.test.js | Clean | scripts/backup-mongo.sh（真实子进程 + mongodump 桩） |
| src/tests/behaviorBaselineWindows.test.js | Clean | services/behaviorBaseline（窗口参数校验、去重基数可比性） |
| src/tests/businessDayBoundsDstAdjacency.test.js | Clean | constants/timezone（businessDayBounds 跨夏令时邻接） |
| src/tests/businessDayExtremes.test.js | Clean | constants/timezone（businessDayBounds 极值语义，6 时区全年） |
| src/tests/businessLocalCodePrefix.test.js | Clean | models/FireAlarm、models/FireDevice（buildCodePrefix 业务时区）、plugins/autoIncrement |
| src/tests/businessMonthWindowTimezone.test.js | Clean | constants/timezone（businessMonthStart）、controllers/userController（getUserStats 月界） |
| src/tests/chainVerifyYieldAtScale.test.js | Clean | services/auditChainVerify（每 2000 条让出事件循环） |
| src/tests/ci/auditBufferStartForAuditAssertions.test.js | Clean | 元闸：全测试树的 auditBuffer 启动纪律；scripts/auditCountAssertionScan.js |
| src/tests/ci/banRefusalEnumSingleSource.test.js | Clean | constants/banRefusalReason、services/ipPoolBan、utils/errorCodes、web-admin ForensicTraceView、src/docs/openapi.json |
| src/tests/ci/bareAnchorAttribution.test.js | Clean（见 P3 台账条目） | 元闸：全仓回指式裸行号锚登记 |
| src/tests/ci/ciTestStepWiring.test.js | Clean | .github/workflows/ci.yml（测试步骤存在且真跑） |
| src/tests/ci/ciWorkflowInvariants.test.js | Clean | ci.yml（run 零插值、最小权限、SHA 钉版、工件不外泄） |
| src/tests/ci/codeViewPhantomLedger.test.js | Clean | tests/helpers/jsCodeOnly 视图完整性（src/scripts/e2e/migrations 零幻影） |
| src/tests/ci/commentAnchorFreshness.test.js | Clean（见 P3 台账条目） | 元闸：file:line 注释锚点新鲜度 |
| src/tests/ci/commentBlockIntegrity.test.js | Clean | 元闸：删注释残骸（悬空收尾/缩进断裂/孤儿续行/代码孤峰） |
| src/tests/ci/commentDensityCliContract.test.js | Clean | scripts/commentDensity.js（CLI 契约：未知参数、坏账本 fail-closed） |
| src/tests/ci/commentDensityEnforcementStatus.test.js | Clean（含 P3 过时注记） | scripts/commentDensity.js 的 ENFORCEMENT 声明与事实对账 |
| src/tests/ci/commentDensityRatchet.test.js | Clean | scripts/commentDensity.js（生产注释行只降不升） |
| src/tests/ci/commentViewSingleSource.test.js | Clean | 元闸：测试树内私有"剥注释"复制品封闭清单 |
| src/tests/ci/coverageGateWiring.test.js | Clean | ci.yml npm run 接线、jest.config.js coverageThreshold |
| src/tests/ci/credentialDoorCheckLedger.test.js | Clean | middleware/auth、middleware/logoutAuth、services/authService/{session,token,login}、services/tokenService、services/websocketService/handshake（凭证门对账） |
| src/tests/ci/dataClassificationInventory.test.js | Clean | constants/dataClassification vs models/** schema |
| src/tests/ci/errorCodePlaceholderDefault.test.js | Clean | utils/errorCodes（占位符默认消息）、utils/apiResponse（回退优先级）、全仓 codeError 调用点 |
| src/tests/ci/failOpenLedgerGate.test.js | Clean | constants/failOpenSites vs incSecurityAlert 调用点 vs deployment/observability/alert-rules.yml |
| src/tests/ci/fieldErrorsEgressGate.test.js | Clean | utils/validationRules（safeFieldErrors）、各控制器 fieldErrors 出站点 |
| src/tests/ci/fileOrderSequencer.test.js | Clean | src/tests/testSequencer.js、jest.config.js、ci.yml（文件级 seed） |
| src/tests/ci/helperExportReachability.test.js | Clean | 元闸：tests/helpers/** 导出的消费可达性 |
| src/tests/ci/helpers/childProcessGate.js | Clean（helper） | src/config/buildInfo.js、src/utils/filePermission.js 的 child_process AST 契约 |
| src/tests/ci/helpers/refusalDocContract.js | Clean（helper） | 拒绝码端点级文档对账取数 |
| src/tests/ci/helpers/statusParityContract.js | Clean（helper） | 路由/成功码静态抽取（状态码对账共用取数） |
| src/tests/ci/honeypotAuthOnlyLedger.test.js | Clean | 仅 authenticate 端点台账；services/honeypotDecoy{,Files,Self}、constants/honeypotDecoy |
| src/tests/ci/honeypotDecoyClockLedger.test.js | Clean | constants/honeypotDecoyData、honeypotDecoyAggregates、constants/honeypotDecoy（时间语义） |
| src/tests/ci/honeypotDecoyLedger.test.js | Clean | constants/honeypotDecoy（数据面↔app.js 挂载双向）、services/honeypotDecoyFiles |
| src/tests/ci/honeypotDecoyMetricsShapeParity.test.js | Clean | constants/honeypotDecoyMetrics vs utils/metrics、utils/metricsDetection、metricsRuntime |
| src/tests/ci/honeypotExclusionLedger.test.js | Clean | constants/honeypotAccounts（HONEYPOT_EXCLUDED_FILTER）在 User 查询面的接线台账 |
| src/tests/ci/honeypotListShapeParity.test.js | Clean | constants/honeypotDecoyListShape/ListQuery vs 6 个真实路由校验链与服务 |
| src/tests/ci/honeypotNameOverlapLedger.test.js | Clean | constants/honeypotAccounts vs constants/canaryAccounts、utils/superAdmin |
| src/tests/ci/honeypotPersonaDifferentiation.test.js | Clean | constants/honeypotPersonas、services/honeypotWatch（画像物化接线） |
| src/tests/ci/honeypotRouteTableParity.test.js | Clean | constants/honeypotRouteTable vs src/app.js + src/routes/**（权限/认证/敏感标记/缺票闸） |
| src/tests/ci/honeypotSelfShapeParity.test.js | Clean | constants/honeypotDecoySelf vs services/initData/permissions*、constants/audit、models/Permission |
| src/tests/ci/honeypotTicketGateParity.test.js | Clean | constants/honeypotTicketGate vs middleware/security/reauthTicket.js（逐字同形） |
| src/tests/ci/moduleTrackingGate.test.js | Clean（含 P3 夹具位置注记） | 元闸：解析得到的本地 require 目标必须已入库（git ls-files） |
| src/tests/ci/mongooseTeardownLedger.test.js | Clean | 元闸：连库套件必须关连接（含空壳守卫检测、root afterAll 位置） |
| src/tests/ci/noFixedSleepRatchet.test.js | Clean | 元闸：测试树/e2e 禁固定睡眠（豁免清单复核） |
| src/tests/ci/openapiStatusParity.test.js | Clean | src/docs/openapi.json vs 控制器静态成功码（helpers/statusParityContract） |
| src/tests/ci/openapiUndocumentedFaceParity.test.js | Clean | 未文档化端点的状态码与理由证据 |
| src/tests/ci/permissionCatalogRouteParity.test.js | Clean | services/initData/defaultPermissions vs 全仓 checkPermission vs web-admin 路由 meta |
| src/tests/ci/riskFactorVocabularyGate.test.js | Clean（含 P3 未剥注释注记） | 后端 riskFactors 码集 vs web-admin/src/i18n/auditRiskFactors.js |
| src/tests/ci/runtimeInventoryClaims.test.js | Clean | constants/runtime（SINGLE_PROCESS_DEPENDENCIES 声称 vs 代码） |
| src/tests/ci/sastWorkflowInvariants.test.js | Clean | .github/workflows/sast.yml、.github/semgrep/rules.yml（零命中+有牙） |
| src/tests/ci/shellScriptSyntax.test.js | Clean | 全部已入库 *.sh（按 shebang 选解释器 -n） |
| src/tests/ci/stubReturnTypeParity.test.js | Clean | 测试桩形状 vs node_modules 类型声明（mongodb/mongoose/socket.io/ioredis） |
| src/tests/ci/stuffingProfileContract.test.js | Clean | services/stuffingProfile、constants/stuffingProfile、constants/credentialShape |
| src/tests/ci/stuffingProfileWriteSites.test.js | Clean | services/authService/login.js、services/canaryWatch.js、services/honeypotWatch.js（credentialShape 写入面） |
| src/tests/ci/testHookConsumerGate.test.js | Clean | 元闸：生产码 `_`/`__` 测试钩子导出必须有真实消费者 |
| src/tests/ci/testTokenTtlFloor.test.js | Clean | 元闸：测试夹具 JWT expiresIn 地板（6h）与短 TTL 封闭清单 |
| src/tests/ci/testTreePurity.test.js | Clean | 元闸：src/tests、web-admin/src/tests 下 *.test.js 必须已入库；zzz-* 不得入库 |
| src/tests/ci/userCredentialProjectionLedger.test.js | Clean | services/authService/profile、services/roleService、services/userService 等的 User 读-改-save 投影纪律 |
| src/tests/compliance/auditChain.test.js | Clean | utils/auditChain、models/AuditLog（pre-save 哈希链、append-only、RESPONSE_EXCLUDE）、services/auditChainVerify、services/reportExportService |
| src/tests/compliance/auditChainGeneration.test.js | Clean | utils/auditChain（B-L4/B-L5 代际守卫、F-192 定时器副作用） |
| src/tests/config/configParams.test.js | P3（告警文本断言） | src/config/index.js（bcryptRounds、statsCache）、src/config/swagger.js（docsLimiter）、docker-compose.yml（redis digest） |
| src/tests/config/databaseCredentialRedaction.test.js | Clean | src/config/database.js（redactUriCredentials）+ mongoose 回显行为 |
| src/tests/config/deployScriptInvariants.test.js | P2（compliance-check 行为无测试） | constants/retention、scripts/compliance-check.js、scripts/generate-dev-cert.sh、start.bat、dev-backend.cmd、docker-compose.yml、.gitignore/.dockerignore、src/tests/setup.js、globalTeardown.js |
| src/tests/config/deploymentCredentialGuards.test.js | Clean | src/config/deploymentCredentialGuards.js + config/validate 接线 |
| src/tests/config/disposableSecretIsolation.test.js | Clean | scripts/devSecretIsolation.js + scripts/{e2e-smoke,load-test,production-drill}.js 接线 |
| src/tests/config/docsAccess.test.js | Clean | src/config/swagger.js（isDocsEnabled/basicAuth/renderDocsHtml/openapiSpec） |
| src/tests/config/gateLayerExistence.test.js | Clean | .github/workflows/*.yml 存在性、scripts/{lint-ratchet,check-utf8,compliance-check}.js、eslint.ratchet.json、测试树去重 |
| src/tests/config/hmacSecretConsumersSingleSource.test.js | P3（未剥注释） | HMAC_SECRET 消费点（utils/auditChain、utils/passwordHistory、services/mfaService、utils/encryption、services/auditChainCheckpoint、services/upgradeService）vs deployment/secret-rotation.md |
| src/tests/config/immutableConfigGuard.test.js | Clean | src/config/immutableConfigGuard.js + config/validate（collectProductionWarnings 接线） |
| src/tests/config/migrateConfigHostQualifiedAllowlist.test.js | Clean | migrate-mongo-config.js + scripts/destructiveGuard.js（host 全限定白名单） |
| src/tests/config/mongoAuthWarning.test.js | Clean | src/config/transportSecurity（collectMongoAuthWarnings，只告警不阻断） |
| src/tests/config/mongoTransportParity.test.js | Clean | scripts/mongoUri.sh vs scripts/backup-mongo.sh / restore-mongo.sh（参考解析器逐行 parity） |
| src/tests/config/nodeEnvConsumers.test.js | Clean（含 P3 剥注释缺口） | middleware/sentry、services/securityAlertDelivery 的环境语义消费 + 静态闸 |
| src/tests/config/proxyProtocol.test.js | Clean | src/config/proxyProtocol.js + config/validate + src/index.js 接线 |
| src/tests/config/runbookApplyCommandContract.test.js | Clean | 运维手册 --apply 命令 vs scripts/destructiveGuard 护栏契约 |
| src/tests/config/scriptSecretHydration.test.js | Clean | 全部独立入口（scripts/**、根入口、npm 入口）的密钥回填顺序 |
| src/tests/config/startupGuards.test.js | Clean | config/validate（TZ_BUSINESS、ENABLE_API_DOCS 口径、加固项告警、降级通道、.env.example 覆盖、JWT_EXPIRE） |
| src/tests/config/transportTlsAssertion.test.js | Clean | src/config/transportSecurity（TLS/认证启动断言、回环/未指定地址口径） |
| src/tests/config/trustedProxyCidrs.test.js | Clean | src/config/trustedProxies + utils/ipUtils + src/app.js 接线 |
| src/tests/config/upgradeConfigGuard.test.js | Clean | src/config/upgrade（toPositiveInt 错配出声） |
| src/tests/config/validate.test.js | Clean | src/config/validate（核心编排、TRUST_PROXY_HOPS/CIDRS、TLS 二选一、告警） |
| src/tests/config/validateStagingLeniencyAndConnections.test.js | Clean | config/validate（staging 宽松登记、文档凭据、REDIS_URL 协议） |
| src/tests/config/weakSecretCriteria.test.js | Clean | config/validate（isWeakSecret 五条判据双向） |
| src/tests/config/weakSecretPlaceholder.test.js | Clean | isWeakSecret 占位符/低熵 + .env.example + generate-secrets 产出放行 |
| src/tests/clientIpCanonicalForm.test.js | Clean | utils/ipUtils（normalizeIP/isAmbiguousIpText）、utils/ipRange、models/IPBlacklist |

## T01 — src/tests：constants + controllers 前（98 文件）

## Per-file appendix（路径 — 结论 + 守护的生产文件）

格式：`路径 — [Clean|问题摘要]；守护：...`。Clean 表示未发现需整改的问题（不代表零改进空间，见上文 P3 汇总条目）。

### 根目录
1. src/tests/constants.js — Clean（非测试文件：测试环境常量单源，供 globalSetup/setup 共用）；守护：src/tests/globalSetup.js、src/tests/setup.js 的环境装配一致性。
2. src/tests/constants/alarmEnumSingleSource.test.js — Clean；守护：src/constants/alarm.js、src/models/FireAlarm.js、src/routes/alarmRoutes.js、src/docs/generate.js、src/docs/openapi.json。
3. src/tests/constants/auditActionReachability.test.js — Clean；守护：src/constants/audit.js、src/middleware/security/auditLog.js、src/utils/auditMeta.js、src/routes/*.js、src/tests/helpers/auditWriteSites.js、routeMounts.js。
4. src/tests/constants/auditActionReconciliation.test.js — Clean；守护：src/constants/audit.js、src/tests/helpers/auditWriteSites.js、src/models/auditLogWriteStatics.js、src/services/auditOutbox.js、src/middleware/security.js。
5. src/tests/constants/businessDayBoundsIllegalCalendarDay.test.js — Clean；守护：src/constants/timezone.js、src/utils/helpers.js（parseDateBoundary/isValidDateParam）。
6. src/tests/constants/businessHourSingleSource.test.js — Clean；守护：src/constants/timezone.js（businessHour/businessDateParts/isOffHours）。
7. src/tests/constants/canaryAccounts.test.js — Clean；守护：src/constants/canaryAccounts.js。
8. src/tests/constants/credentialShape.test.js — Clean；守护：src/constants/credentialShape.js、src/utils/helpers.js（isBreachedPassword）。
9. src/tests/constants/deadExportGuard.test.js — Clean；守护：src/utils/constants.js。
10. src/tests/constants/deploymentReplicaProof.test.js — Clean；守护：src/constants/runtime.js（detectMultiProcess/assertSingleProcessAssumptions）。
11. src/tests/constants/detectionTokenGhosts.test.js — Clean；守护：src/services/securityAlert.js、src/constants/audit.js、src/tests/helpers/auditWriteSites.js。
12. src/tests/constants/deviceStatusSingleSource.test.js — Clean；守护：src/constants/deviceStatus.js、src/utils/constants.js、src/models/FireDevice.js、src/routes/deviceRoutes.js、src/services/DeviceService.js、src/docs/generate.js、src/docs/openapi.json。
13. src/tests/constants/honeypotAccounts.test.js — Clean；守护：src/constants/honeypotAccounts.js、src/constants/canaryAccounts.js。
14. src/tests/constants/honeypotDecoyAggregates.test.js — Clean；守护：src/constants/honeypotDecoyAggregates.js、honeypotDecoyAggregatesData.js、honeypotDecoyShape.js、honeypotRouteTable.js、honeypotDecoyData.js、deviceAlerts.js、privilegeGrant.js、src/utils/constants.js、src/constants/inspection.js。
15. src/tests/constants/honeypotPersonas.test.js — Clean；守护：src/constants/honeypotPersonas.js、src/constants/honeypotAccounts.js。
16. src/tests/constants/inspectionEnumSingleSource.test.js — Clean；守护：src/constants/inspection.js、src/models/Inspection.js、src/routes/inspectionRoutes.js、src/services/InspectionService.js、src/services/userService.js、src/services/deviceReminder.js、src/services/reportDashboardService.js、src/docs/generate.js、src/docs/openapi.json。
17. src/tests/constants/permissionStatusSingleSource.test.js — Clean；守护：src/constants/permission.js、src/constants/ipList.js、src/utils/constants.js、src/models/{Permission,Role,User,IPBlacklist}.js、src/routes/{permissionRoutes,roleRoutes,userRoutes,securityRoutes}.js、src/controllers/roleGuards.js、src/controllers/ipListController.js、src/services/userService.js、src/services/authService/login.js、src/middleware/auth.js、src/docs/generate.js。
18. src/tests/constants/podOrdinalShape.test.js — Clean；守护：src/constants/runtime.js（parsePodOrdinal/detectMultiProcess）。
19. src/tests/constants/riskLevelScalarMembership.test.js — Clean；守护：src/constants/audit.js（AUDIT_RISK_LEVELS），扫描 src/scripts/migrations 全部 riskLevel 标量字面量。
20. src/tests/constants/singleProcessInventoryCompleteness.test.js — Clean；守护：src/constants/runtime.js（SINGLE_PROCESS_DEPENDENCIES）及全仓模块级 Map/Set 登记。
21. src/tests/constants/timezone.test.js — **P2（假定时器未 try/finally 还原，:78-86）**；守护：src/constants/timezone.js。
22. src/tests/constants/tzBusinessEnvNormalization.test.js — Clean；守护：src/config/validate.js（collectTimezoneErrors）、src/constants/timezone.js。
23. src/tests/constants/zonedDayBounds.test.js — Clean；守护：src/constants/timezone.js（zonedDayBounds/businessDayBounds）。

### controllers/
24. src/tests/controllers/adminResetPasswordGates.test.js — P3（afterAll 未清理自建用户/角色，见 P3 汇总第 2 条）；守护：src/controllers/securityController/admin.js、shared.js、src/services/{roleService,authService}.js、src/utils/bcryptWorkerPool.js、src/models/{User,Role,Permission}.js。
25. src/tests/controllers/alarmHandleReasonBoundary.test.js — Clean；守护：src/routes/alarmRoutes.js、src/controllers/alarmController.js、src/services/AlarmService.js、src/models/FireAlarm.js。
26. src/tests/controllers/alarmInspectionErrorPaths.test.js — Clean；守护：src/controllers/{alarmController,inspectionController}.js、src/services/{AlarmService,InspectionService}.js、src/utils/helpers.js。
27. src/tests/controllers/alarmReportDeviceScope.test.js — Clean；守护：src/controllers/alarmController.js（reportAlarm）、src/services/AlarmService.js、src/middleware/rbac.js（assertRecordInScope/isDepartmentValueAllowed）、src/models/{FireAlarm,FireDevice}.js。
28. src/tests/controllers/assignRoles.test.js — Clean（915 行承载 6 个主题，见 P3 汇总关于体量的备注，不单列）；守护：src/controllers/userController/roles.js、src/services/userService.js、src/services/initData.js（reconcileSuperAdmin）、src/middleware/rbac.js、src/models/{User,Role}.js。
29. src/tests/controllers/assignRolesInactiveExemption.test.js — Clean；守护：src/services/userService.js（getPermissions/findActiveRolePermissionDocs）、src/controllers/userController/roles.js。
30. src/tests/controllers/attackEvents.test.js — Clean；守护：src/controllers/securityController（attack-events/summary）、src/services/securityAlert.js、src/services/forensicTrigger.js、src/models/{AuditLog,IPBlacklist}.js。
31. src/tests/controllers/attackProfile.test.js — Clean；守护：src/controllers/securityController（attack-profile）、src/services/attackProfileService（聚合链）、src/utils/ipUtils.js、src/models/{AuditLog,IPBlacklist}.js。
32. src/tests/controllers/auditControllerBehavior.test.js — Clean；守护：src/controllers/auditController.js、src/services/auditChainVerify.js。
33. src/tests/controllers/auditControllerErrorPaths.test.js — Clean；守护：src/controllers/auditController.js、src/services/auditChainVerify.js、src/utils/logger.js。
34. src/tests/controllers/auditCursorErrorSemantics.test.js — Clean；守护：src/controllers/auditController.js、src/utils/cursorPagination.js、src/services/auditQueryService.js。
35. src/tests/controllers/auditDataScope.test.js — Clean；守护：src/controllers/auditController.js、src/services/auditScopeFilter.js。
36. src/tests/controllers/auditExportLimitsAndCsvEscaping.test.js — Clean（仅 1 例、偏薄；转义反对照由 reportExportRowOrderAndCells 补位）；守护：src/services/auditExportService.js（csvEscape/manifest）、src/controllers/auditController.js。
37. src/tests/controllers/auditExportManifestBytes.test.js — Clean；守护：src/controllers/auditController.js、src/services/auditExportService.js、src/services/auditQueryService.js、src/services/securityAlert.js。
38. src/tests/controllers/auditExportParamParity.test.js — Clean；守护：src/controllers/{auditController,reportController}.js、src/utils/auditQuery.js、src/services/reportExportService.js。
39. src/tests/controllers/auditExportSlot.test.js — P3（while(true) 无上限，见 P3 汇总第 8 条）；守护：src/controllers/auditController.js、src/services/exportConcurrency.js。
40. src/tests/controllers/auditExportStreamFailure.test.js — Clean；守护：src/controllers/auditController.js、src/services/auditExportService.js。
41. src/tests/controllers/auditExportUsernamePrefixParity.test.js — Clean；守护：src/controllers/reportController.js、src/services/{reportExportService,auditExportService}.js、src/utils/auditQuery.js、src/models/AuditLog.js。
42. src/tests/controllers/auditLogDetail.test.js — Clean；守护：src/controllers/auditController.js（详情端点）、src/models/AuditLog.js。
43. src/tests/controllers/auditLogs.test.js — Clean；守护：src/controllers/auditController.js、src/utils/auditQuery.js、src/services/auditQueryService.js、src/models/AuditLog.js。
44. src/tests/controllers/auditQuerySharedBuilder.test.js — Clean；守护：src/utils/auditQuery.js、src/services/auditQueryService.js。
45. src/tests/controllers/auditReportFixes.test.js — Clean；守护：src/models/AuditLog.js（getUserActivity/链）、src/controllers/auditController.js、src/utils/auditChain.js、src/utils/helpers.js、src/routes/authRoutes.js（标量收敛）、src/routes/userRoutes.js。
46. src/tests/controllers/auditSummaryCache.test.js — P3（白盒操作 statsCache._store，见 P3 汇总第 7 条）；守护：src/services/auditQueryService.js、src/services/statsCache.js、src/models/AuditLog.js。
47. src/tests/controllers/auditUsernamePrefixIndex.test.js — Clean；守护：src/utils/auditQuery.js、src/models/{AuditLog,User}.js、src/services/{auditQueryService,auditExportService}.js、src/controllers/auditController.js。
48. src/tests/controllers/authControllerOutcomes.test.js — Clean（脚手架与 authUnknownOutcomeFailClosed 重复，见 P3 汇总第 10 条）；守护：src/controllers/authController.js、src/services/{authService,sessionService,tokenService}.js、src/utils/cookie.js。
49. src/tests/controllers/authCookies.test.js — Clean；守护：src/utils/cookie.js、src/controllers/authController.js、src/middleware/auth.js、src/services/authService.js。
50. src/tests/controllers/authLifecycle.test.js — P3（死变量 `void superToken`，见 P3 汇总第 10 条；MFA 窗口码在调用点现算，边界风险已被 mfaTotpClaimImplementation 的经验覆盖）；守护：src/controllers/authController.js、src/services/authService.js、src/routes/authRoutes.js、src/models/SystemConfig.js、src/utils/totp.js。
51. src/tests/controllers/authRegisterSessionBinding.test.js — Clean；守护：src/services/authService.js（registerUser）、src/services/{sessionService,tokenService}.js、src/models/UserSession.js。
52. src/tests/controllers/authRest.test.js — Clean；守护：src/controllers/authController.js、src/services/authService.js、src/models/TokenBlacklist.js、src/models/User.js。
53. src/tests/controllers/authSessionHandlerArms.test.js — P3（:123 双可能断言 `[200,204]`，见 P3 汇总第 3 条）；守护：src/controllers/authController/session.js、src/services/sessionService.js。
54. src/tests/controllers/authUnknownOutcomeFailClosed.test.js — Clean；守护：src/controllers/authController.js、src/controllers/securityController.js（全仓 outcome switch fail-closed 闸）。
55. src/tests/controllers/authzSessionRevocationGuards.test.js — Clean；守护：src/services/authService.js、src/controllers/authController.js、src/utils/mfaSecret.js、src/models/User.js、src/middleware/security/ipBlacklist.js。
56. src/tests/controllers/avatarEndpoint.test.js — Clean；守护：src/controllers/authController（avatar）、src/controllers/userController（update）、src/services/avatarService.js、src/models/UserAvatar.js、src/utils/avatarUrl.js、src/services/auditBuffer.js。
57. src/tests/controllers/businessFlow.test.js — Clean；守护：src/controllers/{deviceController,alarmController,inspectionController}.js、src/services/{DeviceService,AlarmService,InspectionService}.js。
58. src/tests/controllers/changePasswordEncTrack.test.js — P3（前三例共享限流预算的隐式耦合，见 P3 汇总第 5 条）；守护：src/controllers/securityController/account.js、src/utils/loginCipher.js、src/middleware/rateLimit.js。
59. src/tests/controllers/changePasswordOutcomeMap.test.js — Clean；守护：src/controllers/securityController/account.js、src/services/authService.js。
60. src/tests/controllers/changePasswordTypeGuard.test.js — Clean；守护：src/routes/{authRoutes,securityRoutes}.js、src/models/User.js（comparePassword）、src/middleware/rateLimit.js。
61. src/tests/controllers/createUserPeerRoleGate.test.js — P3（afterAll 未清理自建用户/角色，见 P3 汇总第 2 条）；守护：src/controllers/userController/create.js、src/controllers/userController/roles.js、src/services/userService.js。
62. src/tests/controllers/createUserScopeGate.test.js — Clean；守护：src/controllers/userController/create.js、src/services/userService.js、src/constants/canaryAccounts.js。
63. src/tests/controllers/cursorPagination.test.js — Clean；守护：src/controllers/{deviceController,alarmController,inspectionController,auditController}.js、src/utils/cursorPagination.js。
64. src/tests/controllers/dashboardCacheCap.test.js — Clean；守护：src/controllers/reportController.js（dashboardCache/enforceDashboardCacheLimit）。
65. src/tests/controllers/dataScopeDenied403.test.js — Clean；守护：src/middleware/rbac.js、src/services/auditScopeFilter.js、src/services/reportStatsService.js（scopeFilterFor）、src/controllers/{securityController,reportController}.js。
66. src/tests/controllers/deviceExpiringTruncation.test.js — Clean；守护：src/controllers/deviceController.js、src/services/DeviceService.js、src/constants/deviceAlerts.js。
67. src/tests/controllers/deviceStatusErrorMapping.test.js — Clean；守护：src/controllers/deviceController.js、src/middleware/errorHandler.js、src/services/DeviceService.js。
68. src/tests/controllers/emailCaseNormalization.test.js — Clean；守护：src/controllers/authController（profile）、src/controllers/userController（update）、src/services/userService.js、src/models/User.js。
69. src/tests/controllers/inspectionGuardRefExistence.test.js — Clean；守护：src/controllers/inspectionGuards.js。
70. src/tests/controllers/inspectionScopeAndSensitiveViewGuards.test.js — Clean（mock 面已在文件头如实自陈并由变异实测佐证真实判定在别处有守卫；真实链路由 inspectionScopeRealE2E 补位）；守护：src/controllers/inspectionController.js、src/controllers/securityController/sensitive.js、src/middleware/rbac.js。
71. src/tests/controllers/inspectionScopeRealE2E.test.js — Clean；守护：src/controllers/inspectionController.js、src/middleware/rbac.js、src/services/InspectionService.js。
72. src/tests/controllers/inspectionWriteErrorMapping.test.js — Clean；守护：src/controllers/inspectionController.js、src/middleware/errorHandler.js、src/services/InspectionService.js。
73. src/tests/controllers/ipListConcurrentUnionGuard.test.js — Clean；守护：src/controllers/ipListController.js、src/services/ipListService.js、src/utils/cidrCoverage.js。
74. src/tests/controllers/ipListFullRangeGrantAndRescueSymmetry.test.js — Clean；守护：src/controllers/ipListController.js、src/services/ipListService.js、src/services/auditBuffer.js。
75. src/tests/controllers/ipListFullRangeRescuePath.test.js — Clean；守护：src/controllers/ipListController.js、src/services/ipListService.js、src/utils/ipUtils.js。
76. src/tests/controllers/ipListFullRangeTypedConfirm.test.js — Clean；守护：src/controllers/ipListController.js、src/constants/banRefusalReason.js、src/services/ipListService.js。
77. src/tests/controllers/ipListSplitUnionBypass.test.js — Clean；守护：src/controllers/ipListController.js、src/utils/cidrCoverage.js。
78. src/tests/controllers/ipListValidationAndConflictGuards.test.js — P3（审计兜底用例以 setImmediate 冲洗等待，见 P3 汇总第 11 条）；守护：src/controllers/ipListController.js、src/services/ipListService.js、src/models/IPBlacklist.js、src/services/auditBuffer.js。
79. src/tests/controllers/loginEncryption.test.js — P3（afterAll 未清理自建用户与 127.0.0.1 封禁残留，见 P3 汇总第 2 条）；守护：src/routes/authRoutes.js、src/controllers/authController.js、src/utils/loginCipher.js、src/models/IPBlacklist.js。
80. src/tests/controllers/mfaControllerErrorPaths.test.js — Clean；守护：src/controllers/mfaController.js、src/services/{mfaService,mfaDisable}.js。
81. src/tests/controllers/mfaControllerOrchestration.test.js — Clean；守护：src/controllers/mfaController.js、src/services/mfaDisable.js。
82. src/tests/controllers/mfaReplayGuardMax.test.js — Clean；守护：src/controllers/mfaController.js、src/services/mfaService.js。
83. src/tests/controllers/mfaTotpClaimImplementation.test.js — Clean；守护：src/controllers/mfaController.js、src/services/mfaService.js、src/models/User.js。
84. src/tests/controllers/mfaWriteCasConcurrency.test.js — Clean；守护：src/controllers/mfaController.js、src/services/{mfaService,sessionService}.js。
85. src/tests/controllers/permissionBatchCreateSemantics.test.js — Clean；守护：src/controllers/permissionController.js、src/services/permissionService.js。
86. src/tests/controllers/permissionCacheInvalidation.test.js — Clean；守护：src/services/userPermissionService.js、src/controllers/{permissionController,roleController,userController}/roles、permissions 写路径。
87. src/tests/controllers/permissionUserValidationGuards.test.js — Clean；守护：src/controllers/permissionController.js、src/controllers/userController/*、src/services/{permissionService,userService}.js。
88. src/tests/controllers/permissionValidationAndCycleGuards.test.js — Clean；守护：src/controllers/permissionController.js、src/services/permissionService.js。
89. src/tests/controllers/rbacControllers.test.js — P3（部分断言仅查状态码，见 P3 汇总第 6 条；`void builtInSuper` 死变量）；守护：src/controllers/{roleController,permissionController}.js、src/controllers/userController/*、src/services/roleService.js。
90. src/tests/controllers/registerPrivacyConsent.test.js — Clean；守护：src/routes/authRoutes.js、src/services/authService.js、src/services/consentService.js、src/models/ConsentRecord.js。
91. src/tests/controllers/reportDateRangeBoundary.test.js — Clean；守护：src/controllers/reportController.js、src/controllers/{alarmController,inspectionController}.js、src/utils/helpers.js。
92. src/tests/controllers/reportExpiringTruncation.test.js — Clean；守护：src/controllers/reportController.js、src/services/reportStatsService.js、src/constants/deviceAlerts.js。
93. src/tests/controllers/reportExport.test.js — **P2（"缓存命中"断言强度不足，:111-119）**；守护：src/controllers/reportController.js、src/services/exportConcurrency.js。
94. src/tests/controllers/reportExportAuditPerm.test.js — P3（afterAll 未清理自建用户/角色，见 P3 汇总第 2 条）；守护：src/controllers/reportController.js、src/routes/reportRoutes.js。
95. src/tests/controllers/reportExportInputGuards.test.js — Clean；守护：src/controllers/reportController.js、src/services/{reportExportService,reportWorkbookService}.js、src/middleware/rbac.js。
96. src/tests/controllers/reportExportRowOrderAndCells.test.js — Clean；守护：src/services/reportExportService.js、src/services/reportWorkbookService.js、src/utils/helpers.js、src/models/FireAlarm.js。
97. src/tests/controllers/reportExportTruncationHeader.test.js — Clean；守护：src/controllers/reportController.js、src/services/reportWorkbookService.js、src/models/AuditLog.js。
98. src/tests/controllers/reportPiiExportStepUp.test.js — Clean；守护：src/controllers/reportController.js（GET 掩码/POST /export/pii 步进验证）、src/services/reportExportService.js、src/middleware/rateLimit.js、src/services/auditBuffer.js。

### 背景佐证（额外完整读取，非审计对象）
- src/tests/setup.js — 证实"每文件全新空库"隔离（:88-101），是上文多条 P3 定级的前提。

## T02 — src/tests：controllers 后 + deploy + docs（107 文件）

## Per-file appendix（107 个文件，全部完整逐行读取）

图例：Clean = 未发现问题；(P3-5) = 夹具不回收；(skip*) = 含显式条件跳过（有 CI 守卫/能力探针，判定为可接受）。

| # | 文件 | 结论 | 守护的生产文件 |
| --- | --- | --- | --- |
| 1 | src/tests/controllers/reportPiiQuotaPreWrite.test.js | Clean | reportController.exportReport、services/piiExportQuota |
| 2 | src/tests/controllers/reportTimezoneParam.test.js | Clean | reportController.resolveQueryTimezone、constants/timezone |
| 3 | src/tests/controllers/requestedIdListDeduped.test.js | Clean（自报缺口见 P3[D5]） | userController(assignRoles/createUser/batchDeleteUsers)、utils/helpers.uniqueIdStrings、inspectionGuards、inspectionController、rolePermissionController |
| 4 | src/tests/controllers/roleAuthorityResolutionPerRequest.test.js | Clean | controllers/roleGuards、roleController.updateRole |
| 5 | src/tests/controllers/roleControllerHierarchyGuards.test.js | Clean（用例名内嵌行号，文件头已自认漂移风险） | roleController、routes/roleRoutes |
| 6 | src/tests/controllers/roleCreatePermissionExistence.test.js | Clean | roleController.createRole、services/roleService、models/Role |
| 7 | src/tests/controllers/roleGrantRevalidation.test.js | Clean | controllers/userController/shared.findGrantViolationAfterWrite |
| 8 | src/tests/controllers/rolePermCloneTargetUserScope.test.js | Clean (P3-5) | rolePermissionController(targetUser 克隆分支)、middleware/rbac.assertRecordInScope |
| 9 | src/tests/controllers/rolePermPeerGuard.test.js | Clean (P3-5) | rolePermissionController.assignPermissions |
| 10 | src/tests/controllers/roleStatusInvalidatesUserCache.test.js | Clean (P3-5) | roleController.updateRole、middleware/auth.invalidateUserCache |
| 11 | src/tests/controllers/securityConfigHandlers.test.js | Clean | securityController/config、services/auditOutbox |
| 12 | src/tests/controllers/securityControllerOutcomeAndGuards.test.js | Clean | securityController（改密映射/锁定/MFA/概览/告警） |
| 13 | src/tests/controllers/securityDeep.test.js | Clean | securityController（stats/view-sensitive/lock/mfa/admin-reset/ip-list）、services/adminAccountAudit |
| 14 | src/tests/controllers/securityOverviewAuditLossProjection.test.js | Clean | securityController.getSecurityOverview、services/auditBuffer.getStats 形状 |
| 15 | src/tests/controllers/securityOverviewShippingChannel.test.js | Clean | securityController(compliance.shippingEnabled)、utils/logger.isShippingEnabled |
| 16 | src/tests/controllers/securityQuick.test.js | **P3**（翻转 SystemConfig 不还原） | securityController(my-info/bindings/config)、models/SystemConfig |
| 17 | src/tests/controllers/securityStatsTimezone.test.js | Clean | securityController.getSecurityStats、constants/timezone.businessDayBounds |
| 18 | src/tests/controllers/sessionManagement.test.js | Clean (P3-5) | authController/session、services/sessionService、models/UserSession |
| 19 | src/tests/controllers/skipGlobalAuditEndToEnd.test.js | Clean | middleware/security(全局审计)、securityController/config |
| 20 | src/tests/controllers/skipGlobalAuditWriteFailure.test.js | Clean | utils/auditWriteFailure、securityController/sensitive、services/auditOutbox、models/auditLogWriteStatics |
| 21 | src/tests/controllers/updateUserAvatarCleanupAndScopeField.test.js | Clean | userController/update、userService(头像清理)、middleware/rateLimit |
| 22 | src/tests/controllers/updateUserMassAssignmentGuard.test.js | Clean | userController/update+create、routes/userRoutes |
| 23 | src/tests/controllers/userControllerBehavior.test.js | Clean | userController(列表/建号/写后回滚)、services/userService |
| 24 | src/tests/controllers/userListFilterAndBulkDeleteBounds.test.js | **P2**（共享 `*:*` create+delete） | userController(列表/批量删除) |
| 25 | src/tests/controllers/userStats.test.js | Clean (P3-5) | userController.getUserStats、services/statsCache |
| 26 | src/tests/controllers/userStatsSelfScopeCast.test.js | Clean (P3-5) | userController.getUserStats、middleware/rbac.buildDataScopeFilter |
| 27 | src/tests/controllers/userStatusRestoreClearsTempLock.test.js | Clean | userController/update.applyProfileFields |
| 28 | src/tests/credentialKeySingleSource.test.js | Clean | utils/helpers、models/auditLogSanitizer |
| 29 | src/tests/credentialRedactionSinks.test.js | Clean | models/auditLogSanitizer、middleware/security/auditLog、models/auditLogWriteStatics、middleware/errorHandler、middleware/originCheck、utils/logger |
| 30 | src/tests/credentialValidityPredicates.test.js | Clean | models/UserSession.isUsable、services/tokenService、middleware/tokenBlacklist |
| 31 | src/tests/crossInstanceInvalidation.test.js | Clean | services/sessionService、statsCache、sharedCache |
| 32 | src/tests/dashboardCacheContract.test.js | Clean | services/reportDashboardService |
| 33 | src/tests/dataScopeDenyParity.test.js | **P2**（beforeEach 清空 devices 集合） | middleware/rbac、services/reportExportService.scopeFilterFor |
| 34 | src/tests/destructiveGuardOrder.test.js | Clean | scripts/destructiveGuard + 7 个破坏性脚本 |
| 35 | src/tests/deviceBuildingScope.test.js | Clean（设备回收、用户/角色留） | middleware/rbac.isDepartmentValueAllowed、deviceController |
| 36 | src/tests/deviceCodeCap.test.js | Clean（同上） | routes/deviceRoutes、models/FireDevice |
| 37 | src/tests/deviceExpiringDaysAndScrapReason.test.js | Clean | constants/deviceAlerts.normalizeExpiringDays、services/DeviceService、deviceController |
| 38 | src/tests/deviceUpdateFieldParity.test.js | Clean | services/DeviceService、routes/deviceRoutes |
| 39 | src/tests/docs/changelogStructureGate.test.js | Clean | scripts/check-changelog-structure、CHANGELOG.md |
| 40 | src/tests/deploy/alertmanagerComposeGate.test.js | Clean | scripts/check-alertmanager-config、docker-compose.yml |
| 41 | src/tests/deploy/alertmanagerConfigPath.test.js | Clean | scripts/alertmanager-config-path、compliance-check、deployPolicy |
| 42 | src/tests/deploy/appEntrypointHomePasswd.test.js | Clean (skip*：无 POSIX shell 时跳过+CI 守卫) | docker/app-entrypoint.sh |
| 43 | src/tests/deploy/appEntrypointQueuePermFallback.test.js | Clean (skip* 同上) | docker/app-entrypoint.sh |
| 44 | src/tests/deploy/appSecretEntrypoint.test.js | Clean | docker/app-entrypoint.sh、Dockerfile、docker-compose.yml |
| 45 | src/tests/deploy/architectureDocContract.test.js | Clean | docs/architecture.md、docker-compose.yml、README、CONTRIBUTING |
| 46 | src/tests/deploy/auditAllowlistGate.test.js | Clean | scripts/check-audit-allowlist、deployment/audit-allowlist.json |
| 47 | src/tests/deploy/backupEncryptionContract.test.js | Clean | scripts/backup-mongo.sh、backupCrypto.sh、restore-mongo.sh |
| 48 | src/tests/deploy/backupFailureArtifactHygiene.test.js | Clean | scripts/backup-mongo.sh、backupCrypto.sh |
| 49 | src/tests/deploy/backupTransport.test.js | Clean | scripts/backup-mongo.sh、mongoUri.sh |
| 50 | src/tests/deploy/backupUriFile.test.js | Clean | scripts/mongoUri.sh、backup-mongo.sh、restore-mongo.sh |
| 51 | src/tests/deploy/bundleBudget.test.js | Clean | scripts/check-bundle-budget、bundleBudgetPolicy、web-admin/bundle-budget.json |
| 52 | src/tests/deploy/ciGateWiring.test.js | Clean | .github/workflows/*、package.json scripts、jest.config.js |
| 53 | src/tests/deploy/ciInstallHardening.test.js | Clean | .github/workflows/ci.yml、scripts/provision-mongod、deployment/mongod-artifacts.json |
| 54 | src/tests/deploy/ciProvisionFailurePropagation.test.js | Clean (skip* 同 42) | .github/workflows/ci.yml(provision 步骤) |
| 55 | src/tests/deploy/cliArgStrictness.test.js | Clean | scripts/deployPolicy、run-rollback-drill、check-bundle-budget、generate-secrets、migrate-pii-encryption |
| 56 | src/tests/deploy/cliSecretArgGate.test.js | Clean | scripts/migrate-mfa-secret、resign-audit-hmac、secretFileArg、offlineBundle*Policy 及手册 |
| 57 | src/tests/deploy/clockSyncPreflight.test.js | Clean | scripts/check-clock-sync |
| 58 | src/tests/deploy/codeowners.test.js | Clean | .github/CODEOWNERS |
| 59 | src/tests/deploy/composeAppHealthcheck.test.js | Clean | docker-compose.yml、Dockerfile |
| 60 | src/tests/deploy/composeEvalScripts.test.js | Clean | docker-compose.yml（内嵌 mongosh 脚本，eslint no-undef 闸） |
| 61 | src/tests/deploy/composeMongodbUriSecretRecipe.test.js | Clean | docker-compose.yml、scripts/generate-secrets（mongoose 解析器实测） |
| 62 | src/tests/deploy/composeProductionContract.test.js | Clean | docker-compose.yml、src/config/validate、config/secrets、deployment/secret-rotation.md |
| 63 | src/tests/deploy/composeSegmentation.test.js | Clean | docker-compose.yml（分段/认证/端口暴露/互斥） |
| 64 | src/tests/deploy/dependencyFixSla.test.js | Clean | deployment/dependency-sla.json、docs/security-dependency-watch.md |
| 65 | src/tests/deploy/deployCommands.test.js | Clean | scripts/deployCommands、deploy.js |
| 66 | src/tests/deploy/deployRun.test.js | Clean | scripts/deploy.js（stubExec 真子进程观测命令序列） |
| 67 | src/tests/deploy/deployScript.test.js | Clean | scripts/deployPolicy、docker-compose.yml、deploy.js |
| 68 | src/tests/deploy/deployWorkflow.test.js | Clean | .github/workflows/deploy.yml |
| 69 | src/tests/deploy/dockerContextScope.test.js | Clean | .dockerignore、Dockerfile |
| 70 | src/tests/deploy/dockerHealthcheckReadyz.test.js | Clean | Dockerfile(HEALTHCHECK) |
| 71 | src/tests/deploy/generateSecretsAddMissing.test.js | Clean | scripts/generate-secrets(--add-missing) |
| 72 | src/tests/deploy/grafanaDashboardO3.test.js | Clean | deployment/observability/grafana/dashboards/xf-backend.json、alert-rules.yml |
| 73 | src/tests/deploy/helpers/composeSource.js | Clean（测试助手） | 服务 deployScript/deployWorkflow 的 `${VAR:?}` 提取 |
| 74 | src/tests/deploy/helpers/dockerignore.js | Clean（测试助手） | 服务 F-09/F-10 两闸的 .dockerignore 语义 |
| 75 | src/tests/deploy/helpers/releaseNotesScript.js | Clean（测试助手） | 服务 releaseNotesPipeline/releaseWorkflow 的 run 体抽取 |
| 76 | src/tests/deploy/helpers/stubExec.js | Clean（测试助手） | 服务 deployRun/hotUpgradeFailureLogs 的子进程档板 |
| 77 | src/tests/deploy/hotUpgradeAgent.test.js | Clean | scripts/hotUpgradeAgent、hotUpgradeQueue、hotUpgradeJob |
| 78 | src/tests/deploy/hotUpgradeFailureLogs.test.js | Clean | scripts/hotUpgrade（失败现场抓取） |
| 79 | src/tests/deploy/hotUpgradeOfflineDispatch.test.js | Clean | scripts/hotUpgradeJob（离线两段链） |
| 80 | src/tests/deploy/hotUpgradePolicy.test.js | Clean | scripts/hotUpgradePolicy、deployment/nginx.conf.example、docker-compose.yml |
| 81 | src/tests/deploy/hotUpgradeQueueContract.test.js | Clean | docker/app-entrypoint.sh、docker-compose.yml、deployment/systemd/* |
| 82 | src/tests/deploy/imageRequireClosure.test.js | Clean | Dockerfile COPY 集合、migrate-mongo-config、src/index.js require 闭包 |
| 83 | src/tests/deploy/importOfflineBundle.test.js | Clean (skip*：symlink 探针) | scripts/importOfflineBundle |
| 84 | src/tests/deploy/installScriptGate.test.js | Clean | scripts/check-prod-install-scripts、两份 package-lock.json |
| 85 | src/tests/deploy/ip2regionChecksum.test.js | Clean | scripts/update-ip2region、deployment/ip2region-checksum.json、src/data/ip2region.xdb |
| 86 | src/tests/deploy/lockfileAnchor.test.js | Clean | scripts/check-lockfile-integrity、deployment/lockfile-anchor.json |
| 87 | src/tests/deploy/loginKeyPinRequired.test.js | Clean | scripts/login-key-pin、ci.yml、Dockerfile |
| 88 | src/tests/deploy/migrateMongoDependencyClosure.test.js | Clean | package.json、package-lock.json、Dockerfile |
| 89 | src/tests/deploy/nginxProxyContract.test.js | Clean | deployment/nginx.conf.example、src/app.js、src/index.js |
| 90 | src/tests/deploy/nginxSourcemapDenyParity.test.js | Clean | deployment/nginx.conf.example、src/middleware/staticFrontend |
| 91 | src/tests/deploy/nodeRuntimeMatrixParity.test.js | Clean | Dockerfile、ci.yml、两份 package.json(engines) |
| 92 | src/tests/deploy/offlineBundleIntake.test.js | Clean (skip*：tar/cygpath 探针) | scripts/offlineBundleIntake |
| 93 | src/tests/deploy/offlineBundleIntakePolicy.test.js | Clean | scripts/offlineBundleIntakePolicy |
| 94 | src/tests/deploy/offlineBundlePolicy.test.js | Clean | scripts/offlineBundlePolicy、hotUpgradePolicy |
| 95 | src/tests/deploy/offlineBundleScan.test.js | Clean | scripts/offlineBundleScan |
| 96 | src/tests/deploy/offlineBundleSignature.test.js | Clean | scripts/offlineBundleSignature |
| 97 | src/tests/deploy/offsitePolicy.test.js | Clean | scripts/deployPolicy.checkBackupOffsite |
| 98 | src/tests/deploy/releaseNotesPipeline.test.js | Clean (skip* 同 42) | .github/workflows/release.yml(抽取步骤) |
| 99 | src/tests/deploy/releaseWorkflow.test.js | Clean (skip* 同 42) | .github/workflows/release.yml |
| 100 | src/tests/deploy/restoreRemoteHardening.test.js | Clean | scripts/restore-mongo.sh（容器侧命令真执行） |
| 101 | src/tests/deploy/restoreTransport.test.js | Clean | scripts/restore-mongo.sh（两条传输路径） |
| 102 | src/tests/deploy/rollbackDrillRestoreVerification.test.js | Clean | scripts/run-rollback-drill（专用后缀库隔离，本身是 P2 同族竞态的正面修法） |
| 103 | src/tests/deploy/runbookCheckCanFail.test.js | Clean | deployment/*.md 等手册 ↔ src/middleware/auth、utils/cookie、utils/errorCodes |
| 104 | src/tests/deploy/runbookSecretSource.test.js | Clean | deployment/*.md 等手册命令 ↔ scripts/* 密钥来源 |
| 105 | src/tests/deploy/secretCarriersIgnored.test.js | Clean | .gitignore/.dockerignore、scripts/generate-secrets（真 git check-ignore） |
| 106 | src/tests/deploy/workflowShellSyntax.test.js | **P3**（BASH_LIKE 误含 python/sh 子串） | .github/workflows/*（run 体 bash -n） |
| 107 | src/tests/deploy/xlsxWriterDependencyClosure.test.js | Clean | package.json/lock、src/utils/xlsxWriter、src/utils/zipContainer |

## T03 — src/tests：docs / middleware / migrations / models / helpers 等（115 文件）

## Per-file appendix（115 项；路径均相对 D:/桌面/fsms）

| # | 文件 | 结论 | 守护的生产文件 |
| --- | --- | --- | --- |
| 1 | src/tests/docs/deliverablesReferenceIndex.test.js | Clean | docs/internal-evidence-index.md；全仓 deliverables/ 引用台账（文档治理） |
| 2 | src/tests/docs/documentationDrift.test.js | Clean | README.md、.env.example、deployment/* 文档、docs/adr/*、package.json(engines)、.github/workflows/deploy.yml |
| 3 | src/tests/docs/openapiSync.test.js | Clean | src/docs/openapi.json、src/routes/*、src/app.js（挂载面）、src/docs/generate.js |
| 4 | src/tests/docs/openapiTagDeclaration.test.js | Clean | src/docs/openapi.json（spec.tags）、README.md |
| 5 | src/tests/edge/edgeCases.test.js | Clean | src/services/auditScopeFilter.js、src/utils/cursorPagination.js、src/utils/ipRange.js |
| 6 | src/tests/emittedErrorCodeCoverage.test.js | Clean | src/utils/errorCodes.js + 全部 codeError/ApiError 发码点（src/**） |
| 7 | src/tests/encryptionRandomAndMasking.test.js | Clean | src/utils/encryption.js（HashUtils/DataMasking） |
| 8 | src/tests/envNumberGuard.test.js | Clean | src/utils/envNumber.js、src/utils/auditChain.js（锁超时） |
| 9 | src/tests/errorHandlerNoInternalLeak.test.js | Clean | src/middleware/errorHandler.js（全分支防内部泄漏） |
| 10 | src/tests/explainSpotcheckContract.test.js | Clean | scripts/perf/explain-spotcheck.js |
| 11 | src/tests/exportAuditLabelsTriState.test.js | Clean | src/services/reportExportService.js（audit 行转换）、src/utils/auditQuery.js（buildLevelCondition）、src/models/AuditLog.js |
| 12 | src/tests/exportColumnDefsPinned.test.js | Clean | src/services/reportExportService.js（四类列定义/行转换） |
| 13 | src/tests/exportLabelsLocalized.test.js | Clean | src/constants/reportExportLabels.js、src/services/reportExportService.js、src/services/reportWorkbookService.js |
| 14 | src/tests/exportTruncationCap.test.js | Clean | src/services/auditExportService.js（limit 上限+1 截断）、src/models/AuditLog.js |
| 15 | src/tests/fileAclDirectoryRecursiveGrant.test.js | Clean（Windows 门控） | src/utils/filePermission.js（目录 /reset /T + /grant:r） |
| 16 | src/tests/fileAclResetForFiles.test.js | P3（:50 恒真析取支） | src/utils/filePermission.js（文件级 /reset） |
| 17 | src/tests/fixtures/README.md | Clean（文档） | 测试夹具约定说明 |
| 18 | src/tests/fixtures/index.js | Clean | 测试共享固件（constants 的测试侧单一来源） |
| 19 | src/tests/fullRangeInactiveSuperAdmin.test.js | P2（夹具泄漏/顺序依赖） | src/utils/superAdmin.js、src/controllers/ipListController.js（全网段守卫） |
| 20 | src/tests/globalSetup.js | Clean | 测试基建（mongodb-memory-server 8.0.34、测试密钥注入、shell 解析） |
| 21 | src/tests/globalTeardown.js | Clean | 测试基建（worker 库清理、mongod 显式停止） |
| 22 | src/tests/helpers/auditChainFixtures.js | Clean | 测试夹具（auditChain 校验器免库夹具，单一实现） |
| 23 | src/tests/helpers/auditWriteSites.js | Clean | 测试取数器（src/** 审计写入点扫描，双向对账共用） |
| 24 | src/tests/helpers/authResponse.js | Clean | 测试辅助（Set-Cookie 取 token） |
| 25 | src/tests/helpers/buildLoginEnvelope.js | Clean | 测试辅助（镜像前端 WebCrypto 信封，互操作验证 src/utils/loginCipher.js） |
| 26 | src/tests/helpers/codeErrorCallScan.js | Clean | 测试取数器（codeError 调用点/注册表解析） |
| 27 | src/tests/helpers/contentLevelWriteError.js | Clean | 测试夹具（MongoBulkWriteError 真实形状） |
| 28 | src/tests/helpers/jsCodeOnly.js | Clean | 测试基建（单遍注释屏蔽视图，文本闸地基） |
| 29 | src/tests/helpers/pollTick.js | Clean | 测试辅助（条件轮询节拍） |
| 30 | src/tests/helpers/posixShell.js | Clean | 测试基建（POSIX shell 行为验证与 PATH 注入） |
| 31 | src/tests/helpers/reauthTicket.js | Clean | 测试辅助（src/utils/reauthTicket.js 本地签发） |
| 32 | src/tests/helpers/routeMounts.js | Clean | 测试取数器（src/app.js 挂载前缀解析） |
| 33 | src/tests/helpers/routeMounts.test.js | Clean | src/tests/helpers/routeMounts.js 自身（解析失败必须抛） |
| 34 | src/tests/helpers/stubPath.js | Clean | 测试基建（shell 内 PATH 桩） |
| 35 | src/tests/helpers/waitFor.js | Clean | 测试辅助（waitFor/waitForStable/flushEventLoop） |
| 36 | src/tests/illegalCalendarDayWithTime.test.js | Clean | src/utils/helpers.js（parseDateBoundary）、src/constants/timezone.js、src/utils/auditQuery.js |
| 37 | src/tests/imageDigestGate.test.js | Clean | scripts/capture-image-digests.sh（真跑 + 失败矩阵 25 臂） |
| 38 | src/tests/imageDigestVerify.test.js | Clean | scripts/verify-image-digests.js（判据 + CLI 退出码） |
| 39 | src/tests/inactiveRoleAuthorization.test.js | Clean | src/middleware/auth.js、src/services/websocketService/{handshake,lifecycle}.js、src/services/authService/{session,token}.js、src/controllers/securityController/sensitive.js |
| 40 | src/tests/inspectionArrayCaps.test.js | Clean | src/routes/inspectionRoutes.js（数组上限校验）、src/models/Inspection.js |
| 41 | src/tests/inspectionAssigneeExists.test.js | Clean | src/routes/inspectionRoutes.js + 巡检写路径执行人存在性闸 |
| 42 | src/tests/inspectionInputBoundary.test.js | Clean | src/routes/inspectionRoutes.js（complete/review/cancel 校验器）、src/services/InspectionService.js |
| 43 | src/tests/inspectionWriteScopeGates.test.js | Clean | src/services/inspectionGuards.js（rejectOutOfScopeReferences）、src/routes/inspectionRoutes.js |
| 44 | src/tests/integrityAttestation.test.js | Clean | src/controllers/auditController.js（verifyAuditChainIntegrity）、src/services/auditChainVerify.js（computeChainVerdict） |
| 45 | src/tests/ipBlacklistEntryNormalization.test.js | Clean | src/models/IPBlacklist.js（normalizeEntryIp/写路径归一） |
| 46 | src/tests/ipQueryAmbiguousRefusal.test.js | Clean | src/controllers/ipListController.js（queryIPMatch）、src/utils/ipUtils.js |
| 47 | src/tests/ipRangeRuleCap.test.js | Clean | src/utils/ipRange.js（MAX_RULE_COUNT 不静默截断） |
| 48 | src/tests/k6JourneyContract.test.js | Clean | scripts/perf/k6-core-journeys.js |
| 49 | src/tests/logShipperSchemeAllowlist.test.js | Clean | src/utils/logShipper.js（scheme 白名单）、src/utils/logShippingTarget.js（SSRF 门禁） |
| 50 | src/tests/loggerBoundaries.test.js | Clean | src/utils/logger.js（级别解析/清洗/序列化/格式分档） |
| 51 | src/tests/loginCipherErrorTaxonomy.test.js | Clean | src/utils/loginCipher.js（错误码分类法） |
| 52 | src/tests/loginIpRangeDeniedAudit.test.js | Clean | src/services/authService/login.js（ip_range_denied 审计与 catch 臂） |
| 53 | src/tests/loginPermissionSnapshotNulls.test.js | Clean | src/services/authService（登录权限快照只含生效角色/权限） |
| 54 | src/tests/loginTimingParity.test.js | Clean | src/services/authService/login.js（拒绝路径比较次数平价 + checkBruteForce） |
| 55 | src/tests/logoutTokenFork.test.js | Clean | src/controllers/authController/session.js（logout）、src/middleware/auth.js（extractAccessToken 同源） |
| 56 | src/tests/metricsSeriesFidelity.test.js | P3（内部 Map 耦合） | src/utils/metrics.js（截断可观测 + 缺省标签两视图同口径） |
| 57 | src/tests/mfaCounterFailClosed.test.js | Clean | src/services/mfaService.js（计数写失败仍锁定 + 告警） |
| 58 | src/tests/mfaLifecycleTotpClaim.test.js | Clean | src/controllers/mfaController.js（disable/regenerate 的窗口认领） |
| 59 | src/tests/middleware/abortedAuditReasonCleaning.test.js | Clean | src/middleware/errorHandler.js（markResponseAbortedByError）、src/utils/helpers.js（stripControlChars） |
| 60 | src/tests/middleware/attackDetectionIntegration.test.js | Clean | src/middleware/security/*（注入检测/扫描探测/取证捕获/限流升级）、src/services/{injectionDetector,scanProbeDetector,forensicTrigger,forensicCapture,rateLimitEscalation}.js |
| 61 | src/tests/middleware/auditRefusalReason.test.js | Clean | src/controllers/ipListController.js、src/middleware/security（refusalReason 落审计） |
| 62 | src/tests/middleware/auditStreamingCoverage.test.js | Clean | src/middleware/security/auditLog.js（write/end 包装）、src/models/auditLogSanitizer.js（深度窗口） |
| 63 | src/tests/middleware/auth.test.js | P3（:163-191 测 jwt 库本身） | src/middleware/auth.js（authenticate：缺头/坏签名/过期/alg:none/tokenVersion/用户不存在） |
| 64 | src/tests/middleware/authMiddlewareFailClosedGuards.test.js | Clean | src/middleware/auth.js（状态拦截/IP 范围/fail-closed 503/缓存淘汰与失效）、src/middleware/userAuthCache.js |
| 65 | src/tests/middleware/authSecondBoundaryAndMfaCache.test.js | Clean | src/middleware/auth.js（passwordChangedAt 秒级边界、缓存失效通道） |
| 66 | src/tests/middleware/avatarUnmatchedSurfaceGuard.test.js | P2（env 泄漏） | src/routes/avatarRoutes.js（router.use 桶）、src/middleware/rateLimit.js（isAvatarReadRequest）、src/middleware/security/auditLog.js |
| 67 | src/tests/middleware/bodyNormalization.test.js | Clean | src/middleware/security/index.js（applyPostBodySecurity/normalizeBody）、src/middleware/security/reauthCredentialRules.js |
| 68 | src/tests/middleware/canonicalizationParity.test.js | Clean | src/utils/auditMeta.js、src/utils/helpers.js（redactUrlQuery/matchesPathPrefix）、src/middleware/protocolCompliance.js |
| 69 | src/tests/middleware/cspNonce.test.js | Clean | src/middleware/security/securityHeaders.js（attachCspNonce 文档路径判定） |
| 70 | src/tests/middleware/dataScopeConvergence.test.js | Clean | src/middleware/rbac.js（applyDataScopeToQuery 收敛点） |
| 71 | src/tests/middleware/dataScopeGuestReadOnly.test.js | Clean | src/middleware/rbac.js（getDataScope 的 GUEST 例外） |
| 72 | src/tests/middleware/dataScopeRequestMemo.test.js | Clean | src/middleware/dataScope.js（按请求记忆化） |
| 73 | src/tests/middleware/errorResponseNoStore.test.js | Clean | src/utils/apiResponse.js、src/middleware/errorHandler.js、src/middleware/rateLimit.js、src/middleware/originCheck.js、src/routes/wellKnownRoutes.js、src/config/swagger.js |
| 74 | src/tests/middleware/forensicCapture.test.js | Clean | src/middleware/security/forensicCapture.js、src/services/forensicCapture.js |
| 75 | src/tests/middleware/forensicCaptureParity.test.js | Clean | src/middleware/security/forensicCapture.js + auditLog（四态字节级对拍） |
| 76 | src/tests/middleware/idempotency.test.js | Clean | src/middleware/idempotency.js、src/utils/idempotencyKey.js、8 条业务路由的幂等接线 |
| 77 | src/tests/middleware/idempotencyDegradeSignal.test.js | Clean | src/middleware/idempotency.js（降级信号 + fail-open 方向） |
| 78 | src/tests/middleware/infraParamRateLimitFailClosed.test.js | Clean | src/middleware/validateObjectId.js、src/middleware/tokenBlacklist.js、scripts/{backup-mongo.sh,restore-mongo.sh,fix-token-blacklist-index.js,verify-audit-chain.js}、dev-vite.cmd、src/config/swagger.js |
| 79 | src/tests/middleware/metricsAuth.test.js | Clean | src/middleware/metricsAuth.js（回环/私网/令牌/反代拓扑） |
| 80 | src/tests/middleware/metricsAuthIpStrictness.test.js | Clean | src/middleware/metricsAuth.js（isPrivateOrLoopback 严格解析）、src/utils/ipUtils.js |
| 81 | src/tests/middleware/metricsHostGateExemption.test.js | Clean | src/middleware/protocolCompliance.js（/metrics 窄豁免）、deployment/observability/prometheus.yml |
| 82 | src/tests/middleware/originCheck.test.js | Clean | src/middleware/originCheck.js、src/app.js（resolveCorsOrigins）、src/utils/constants.js（DEV_CORS_ORIGINS） |
| 83 | src/tests/middleware/passwordChangeGate.test.js | Clean | src/middleware/auth.js（mustChangePassword 放行表/PATTERN） |
| 84 | src/tests/middleware/protocolCompliance.test.js | Clean | src/middleware/protocolCompliance.js（方法/媒体类型/头部/Host/探针豁免） |
| 85 | src/tests/middleware/queryLimit.test.js | Clean | src/middleware/queryLimit.js（长度/标量守卫 + 日志打码） |
| 86 | src/tests/middleware/queryRejectionAuditTrail.test.js | Clean | src/middleware/queryLimit.js（拒绝审计留痕与豁免口径） |
| 87 | src/tests/middleware/rateLimitHandlerOptions.test.js | Clean | src/middleware/rateLimit.js（各桶 handler/keyGenerator） |
| 88 | src/tests/middleware/rateLimitKeyNormalization.test.js | Clean | src/middleware/rateLimit.js（normalizeRateLimitIp/normalizeLoginRateKey）、src/routes/wellKnownRoutes.js、src/config/swagger.js |
| 89 | src/tests/middleware/rateLimitStore.test.js | Clean | src/middleware/rateLimitStore.js（三分支 + init/代理转发） |
| 90 | src/tests/middleware/rateLimitStoreFailover.test.js | Clean | src/middleware/rateLimitStore.js（运行期故障降级 + 可观测信号） |
| 91 | src/tests/middleware/rateLimitStoreReadinessRace.test.js | Clean | src/middleware/rateLimitStore.js（Redis 晚就绪补切换） |
| 92 | src/tests/middleware/rbacSelfScopeExemption.test.js | Clean | src/middleware/rbac.js（isRecordInScope 自有记录短路，none 除外） |
| 93 | src/tests/middleware/rbacWildcardAndDataScopeBounds.test.js | Clean | src/middleware/rbac.js（checkPermission 通配/AND、getDataScope 阈值、buildDataScopeFilter/isRecordInScope/buildRecordScopeFilter） |
| 94 | src/tests/middleware/reauthentication.test.js | Clean | src/middleware/security（requireReAuthentication：密码/MFA/密文 AAD/fail-closed） |
| 95 | src/tests/middleware/registerCaptchaRateLimit.test.js | Clean | src/services/captchaService.js、src/middleware/rateLimit.js（registerIpLimiter） |
| 96 | src/tests/middleware/sanitizeMaterializeArms.test.js | Clean | src/middleware/security/sanitize.js（materializeQuery 两条 fail-closed 臂） |
| 97 | src/tests/middleware/securityApplyAndCategoryGuard.test.js | Clean | src/middleware/security/index.js（applySecurity 顺序、category 枚举启动闸、requireReAuthentication 入参闸） |
| 98 | src/tests/middleware/securityHeaderPolicyHardening.test.js | Clean | src/middleware/security/securityHeaders.js（TT 灰度/强制、CORP/Referrer-Policy 五副本一致）、deployment/nginx.conf.example、web-admin/vite.config.js |
| 99 | src/tests/middleware/securitySanitizeAndBlacklistDegrade.test.js | Clean | src/middleware/security/index.js（sanitizeMongo 深度/原型污染、ensureHsts、checkIPBlacklist 降级缓存、addToBlacklist、fileUploadSecurity、auditLog skip 语义） |
| 100 | src/tests/middleware/sentryOutboundScrub.test.js | Clean | src/middleware/sentry.js（出网白名单咽喉 + 六臂矩阵 + 单一咽喉门禁） |
| 101 | src/tests/middleware/sentrySmoke.test.js | Clean | src/middleware/sentry.js、package.json/@sentry/node 版本一致性 |
| 102 | src/tests/middleware/skipGlobalAuditTiming.test.js | Clean | src/middleware/security/auditLog.js（skipGlobalAudit 响应时刻读取）、src/middleware/queryLimit.js（queryScalarGuard 挂载事实） |
| 103 | src/tests/middleware/staticFrontend.test.js | Clean | src/middleware/staticFrontend.js（启用条件/SPA 回退/缓存策略/.map 拦截） |
| 104 | src/tests/middleware/tokenBlacklistIndex.test.js | Clean | src/middleware/tokenBlacklist.js（E11000 来源区分/fail-closed）、src/services/initData.js（reconcileTokenBlacklistIndexes） |
| 105 | src/tests/middleware/writeMethodSingleSource.test.js | Clean | src/middleware/httpMethods.js、src/middleware/security/auditLog.js、src/services/behaviorBaseline.js |
| 106 | src/tests/middleware/xssProtectionHeader.test.js | Clean | src/middleware/security/securityHeaders.js（X-XSS-Protection 显式 0） |
| 107 | src/tests/migrateConfigFailClosed.test.js | Clean | migrate-mongo-config.js、scripts/deploy.js、scripts/deployCommands.js |
| 108 | src/tests/migrations/auditListTiebreakIndexes.test.js | Clean | migrations/20261201000000-audit-list-tiebreak-indexes.js、src/models/AuditLog.js |
| 109 | src/tests/migrations/auditUsernameCiIndex.test.js | Clean | migrations/20260928000000-audit-username-ci-index.js、src/models/AuditLog.js（collation 三处同源） |
| 110 | src/tests/migrations/cursorTiebreakIndexes.test.js | Clean | migrations/20260926000000-cursor-tiebreak-compound-indexes.js、src/models/{FireAlarm,Inspection,AuditLog}.js |
| 111 | src/tests/migrations/deviceReminderTiebreakIndex.test.js | Clean | migrations/20261103000000-device-reminder-tiebreak-index.js、src/models/FireDevice.js |
| 112 | src/tests/migrations/filterTiebreakCompoundIndexes.test.js | Clean | migrations/20261101000000-filter-tiebreak-compound-indexes.js、src/models/{FireAlarm,Inspection}.js |
| 113 | src/tests/migrations/migrationReadmeLedger.test.js | Clean | migrations/README.md ↔ migrations/*.js 双向台账 |
| 114 | src/tests/migrations/queryPerformanceIndexes.test.js | Clean | migrations/20261021000000-query-performance-indexes.js、src/models/{FireDevice,Inspection,FireAlarm,UserSession}.js |
| 115 | src/tests/migrations/reconcileAuditIndexOptions.test.js | P3（共享库改索引形态，违背同目录隔离纪律） | migrations/20260831000000-reconcile-audit-index-options.js、src/constants/retention.js |

---

## 结论

指定 115 个文件全部逐行读完。测试资产整体处于高水位：判据可证伪、边界成对、异步等待条件化、故障注入配前提自证、文档/路由/索引/脚本均有对账闸。需要修复的只有 2 个中危测试卫生问题（avatarUnmatchedSurfaceGuard 的 env 泄漏、fullRangeInactiveSuperAdmin 的固定码夹具泄漏与顺序依赖）和 4 个低危改进点；无 P0/P1，无被 skip 掩盖的安全面，无固定 sleep 型竞态判据。

## T04 — src/tests：models / observability / routes / security 前（105 文件）

## Per-file appendix（105 文件；Clean = 未发现本级别问题）

| # | 文件 | 结论 | 守护的生产文件 |
|---|------|------|----------------|
| 1 | src/tests/migrations/tokenBlacklistFixScriptBehavior.test.js | Clean | scripts/fix-token-blacklist-index.js |
| 2 | src/tests/migrations/ttlMigrationEmptyDb.test.js | Clean | migrations/20260831000000-reconcile-audit-index-options.js、migrations/20260919000000-reconcile-audit-ttl-to-retention.js |
| 3 | src/tests/models/AuditLog.test.js | Clean | src/models/AuditLog.js、src/utils/auditChain.js、src/services/auditChainVerify.js、src/constants/audit.js、src/constants/retention.js |
| 4 | src/tests/models/AuditLogBehavior.test.js | Clean | src/models/AuditLog.js（ip/userAgent 补界、append-only、调用方 hash 保留）、src/constants/audit.js |
| 5 | src/tests/models/ConsentRecord.test.js | Clean | src/models/ConsentRecord.js、src/services/consentService.js、src/constants/dataClassification.js |
| 6 | src/tests/models/ForensicCapture.test.js | Clean | src/models/ForensicCapture.js、src/constants/businessRetention.js |
| 7 | src/tests/models/IPBlacklist.test.js | Clean | src/models/IPBlacklist.js（含 F-25-7 重复封禁取严、F5 快照失效全写入口） |
| 8 | src/tests/models/User.test.js | Clean | src/models/User.js、src/utils/constants.js |
| 9 | src/tests/models/auditChainConcurrency.test.js | Clean（afterAll 有意留库，文件级独立库下无影响） | src/models/AuditLog.js、src/utils/auditChain.js（哈希链并发不分叉） |
| 10 | src/tests/models/auditListTiebreakExplain.test.js | Clean | src/models/AuditLog.js（索引声明）、src/services/auditQueryService.js、src/utils/auditQuery.js（explain 级锁定无 SORT） |
| 11 | src/tests/models/auditLogAppendOnlyContract.test.js | Clean | src/models/AuditLog.js、src/models/auditLogHooks.js（bypassAppendOnly 契约、生产子进程探针） |
| 12 | src/tests/models/auditLogFieldRetention.test.js | Clean | src/models/AuditLog.js（targetType/targetId/dataType/description 留存）、src/controllers/securityController 写入方 |
| 13 | src/tests/models/auditLogSanitizer.test.js | Clean | src/models/auditLogSanitizer.js、src/middleware/security/auditLog.js、src/utils/helpers.js（stripControlCharsDeep/redactUrlQuery） |
| 14 | src/tests/models/auditRequestContext.test.js | Clean | src/models/auditLogWriteStatics.js（auditRequestContext/recordLogin）、src/models/AuditLog.js |
| 15 | src/tests/models/auditSanitizerDateFidelity.test.js | Clean | src/models/auditLogSanitizer.js、src/utils/auditChainPayload.js（时间戳入哈希覆盖面） |
| 16 | src/tests/models/auditSparseIndexSemantics.test.js | Clean | src/models/AuditLog.js、migrations/20260831000000-reconcile-audit-index-options.js、scripts/sync-audit-indexes.js、src/models/auditLogWriteStatics.js |
| 17 | src/tests/models/builtInRoleCodeSource.test.js | Clean | src/constants/permission.js、src/models/Role.js、src/services/initData/roles.js |
| 18 | src/tests/models/deviceRecordCap.test.js | Clean | src/models/FireDevice.js（pushCapped 尾部封顶+计数） |
| 19 | src/tests/models/inspectionRetentionGate.test.js | Clean | src/models/Inspection.js（pre-validate 计龄闸）、src/constants/businessRetention.js |
| 20 | src/tests/models/roleBuiltInDeleteGuard.test.js | Clean | src/models/Role.js（protectBuiltInRole/protectBuiltInRoleBulk，删除面枚举对账） |
| 21 | src/tests/nodeEnvGateFailsClosed.test.js | Clean | src/config/validate.js、src/utils/cookie.js（NODE_ENV 归一、__Host- cookie） |
| 22 | src/tests/objectIdParamGuard.test.js | Clean | src/app.js（applyObjectIdParams）、src/middleware/validateObjectId.js、全部含 :id/:userId 的子路由 |
| 23 | src/tests/permissionDecisionParity.test.js | Clean | src/utils/permissionHelper.js、src/services/userPermissionService.js（三路径同口径） |
| 24 | src/tests/permissionHelperFailClosed.test.js | Clean | src/utils/permissionHelper.js（hasAllPermissions 空集判否） |
| 25 | src/tests/playwrightConfig.test.js | Clean | playwright.config.js、e2e/**/*.spec.js、web-admin/src（选择器存在性）、.github/workflows/ci.yml（MIN_PASSED 对账） |
| 26 | src/tests/populateMatchShape.test.js | Clean | src/middleware/rbac.js、src/utils/permissionHelper.js（populate+match 数组形状与 deny 分支） |
| 27 | src/tests/queryScalarNoWhitelistExemption.test.js | Clean | src/middleware/queryLimit.js（白名单不豁免标量闸） |
| 28 | src/tests/reauthLimiterBucket.test.js | Clean | src/middleware/rateLimit.js（reauth 与 password-change 桶隔离）、相关路由 |
| 29 | src/tests/reservedWildcardAssignment.test.js | Clean | src/controllers/rolePermissionController.js（分配路径 *:* 防线） |
| 30 | src/tests/reservedWildcardPermission.test.js | Clean | src/services/permissionService.js（savePermission/deletePermission 的保留通配防线） |
| 31 | src/tests/reservedWildcardRoleCreation.test.js | Clean | src/controllers/roleController.js（createRole 铸造路径 *:* 防线） |
| 32 | src/tests/riskLevelSingleSource.test.js | Clean | src/constants/audit.js、src/utils/auditQuery.js、src/constants/inspection.js、src/routes/inspectionRoutes.js |
| 33 | src/tests/rollbackEjson.test.js | Clean | scripts/run-rollback-drill.js（toSerializable/fromSerializable） |
| 34 | src/tests/scopeCastFamily.test.js | Clean | src/utils/scopeCast.js、src/services/InspectionService.js、src/services/DeviceService.js、src/middleware/rbac.js |
| 35 | src/tests/observability/alertRulesSyntax.test.js | Clean | scripts/alertRulesPolicy.js、deployment/observability/alert-rules.yml |
| 36 | src/tests/observability/alertingConfig.test.js | Clean | deployment/observability/{prometheus,alert-rules,alertmanager}.yml、docker-compose.yml、src/utils/metrics*.js |
| 37 | src/tests/observability/auditBufferFlushAndWalGuards.test.js | F4（模块级 env 不还原） | src/services/auditBuffer.js、src/services/auditBufferWal.js、src/models/AuditLog.js |
| 38 | src/tests/observability/auditBufferOutageKeepsAudit.test.js | F4 | src/services/auditBuffer.js、src/utils/mongoFailureAttribution.js、src/services/auditBufferWal.js |
| 39 | src/tests/observability/auditBufferShutdownDrain.test.js | F4 | src/services/auditBuffer.js（flushAndStop 排空真值）、src/services/auditBufferWal.js |
| 40 | src/tests/observability/auditDropMetrics.test.js | Clean | src/utils/metrics.js（metricsAuditDrops）、src/services/auditBuffer.js、deployment/observability/alert-rules.yml |
| 41 | src/tests/observability/auditWALPoisonDiscard.test.js | F4 | src/services/auditBuffer.js、src/services/auditBufferWal.js（毒批归档/重启跳过） |
| 42 | src/tests/observability/auditWalReclaimNotGatedByEnable.test.js | Clean | src/services/auditBuffer.js、src/services/auditBufferDocs.js、src/services/forensicCapture.js（回收不得被 isEnabled 门控的结构门禁+变异自检） |
| 43 | src/tests/observability/auditWalReplayIdempotency.test.js | F4 | src/services/auditBuffer.js、src/services/auditBufferWal.js、src/utils/auditChain.js（跨重启幂等三窗口） |
| 44 | src/tests/observability/auditWalTrimIsPrecise.test.js | F4 | src/services/auditBuffer.js、src/services/auditBufferWal.js（按 __walSeq 精确裁剪） |
| 45 | src/tests/observability/businessMetrics.test.js | Clean | src/utils/metrics.js、src/controllers/authController（登录埋点接线） |
| 46 | src/tests/observability/detectionMetrics.test.js | Clean | src/utils/metricsDetection.js、src/constants/detectionObjectives.js、deployment/observability/alert-rules.yml |
| 47 | src/tests/observability/logShipperCloseDrains.test.js | F4 | src/utils/logShipper.js（close 按批排空、预算、行序） |
| 48 | src/tests/observability/logShipperDnsPinning.test.js | F4 | src/utils/logShippingTarget.js、src/utils/logShipper.js（DNS 钉扎一次解析） |
| 49 | src/tests/observability/logShipperGapMarkerAccounting.test.js | F4 | src/utils/logShipper.js（断档标记记账不变量） |
| 50 | src/tests/observability/logShipperGapMarkerIdentity.test.js | F4 | src/utils/logShipper.js（标记签发身份防伪造） |
| 51 | src/tests/observability/logShipperShutdownWiring.test.js | F4 | src/utils/loggerFlush.js（drainShippingBuffer/bestEffortDrain）、src/index.js、src/utils/crashFlush.js、src/utils/logShipper.js |
| 52 | src/tests/observability/logShipperTransportFailurePaths.test.js | F1 + F4 | src/utils/logShipper.js（log/_trimToCap/_flush 串行闩/_post 失败路径/close） |
| 53 | src/tests/observability/loggerFlush.test.js | Clean | src/utils/loggerFlush.js、src/config/validate.js、src/config/database.js、src/index.js（子进程实证落盘） |
| 54 | src/tests/observability/loggerFlushFailure.test.js | Clean | src/utils/loggerFlush.js（落盘失败不抛错+stderr 留痕） |
| 55 | src/tests/observability/loginAuditTrailFidelity.test.js | Clean | src/models/auditLogSanitizer.js、src/models/auditLogWriteStatics.js、src/services/authService、src/middleware/rateLimit.js、src/middleware/security/auditLog.js |
| 56 | src/tests/observability/metricsMethodLabelClosure.test.js | Clean | src/utils/metrics.js（methodLabelOf 闭集化防高基数） |
| 57 | src/tests/observability/observability.test.js | Clean | src/app.js（/metrics、/readyz）、src/utils/metrics.js、src/services/securityAlert.js |
| 58 | src/tests/observability/readyzSanitize.test.js | Clean | src/utils/healthChecks.js（reason 枚举脱敏、S-M1 缓存 fail-closed） |
| 59 | src/tests/observability/runtimeMetricsCoverage.test.js | Clean | src/utils/metricsRuntime.js、src/utils/metrics.js、src/app.js、src/utils/logShipper.js、deployment/observability/alert-rules.yml |
| 60 | src/tests/plugins/autoCodeCounterReconcile.test.js | Clean | src/plugins/autoIncrement.js（计数器丢失自愈） |
| 61 | src/tests/plugins/autoIncrementConcurrentBirth.test.js | Clean | src/plugins/autoIncrement.js（并发诞生 vs 计数器丢失判别） |
| 62 | src/tests/routes/bodyStringGateCoverage.test.js | Clean | src/routes/*.js（mustBeString 闸覆盖面静态清点+孤儿闸检查） |
| 63 | src/tests/routes/bodyTypeGate.test.js | Clean | src/routes/ 各写路径的非字符串闸（user/device/alarm/inspection/role/permission/security/auth） |
| 64 | src/tests/routes/dataScopeContract.test.js | Clean | src/routes/*.js + src/controllers/*（ADR-008 写路由范围策略登记） |
| 65 | src/tests/routes/forensicRoutesContract.test.js | F3 | src/routes/securityRoutes.js（forensic trace/clusters/pool-ban/export）、src/models/IPBlacklist.js |
| 66 | src/tests/routes/locationCoordinatesBoundary.test.js | Clean | src/routes/deviceRoutes.js、src/routes/alarmRoutes.js、src/models/FireDevice.js、src/models/FireAlarm.js |
| 67 | src/tests/routes/privilegeGrantEndpoints.test.js | Clean | src/routes/permissionRoutes.js（/grants）、src/controllers/privilegeController.js、src/services/privilegeGrantService.js |
| 68 | src/tests/routes/profileFieldClearability.test.js | Clean | src/routes/authRoutes.js（profile）、src/controllers/authController/profile.js、src/models/User.js |
| 69 | src/tests/routes/readPermissionContract.test.js | Clean | src/routes/*.js（GET 鉴权）、src/app.js（app.get 守卫面）、src/controllers/avatarController.js |
| 70 | src/tests/routes/referenceArrayBoundary.test.js | Clean | src/routes/inspectionRoutes.js、src/routes/roleRoutes.js、src/routes/userRoutes.js |
| 71 | src/tests/routes/registerSwitchOrder.test.js | Clean | src/routes/authRoutes.js（register 链装配顺序）、src/models/SystemConfig.js |
| 72 | src/tests/routes/routeGuardBranches.test.js | Clean | src/routes/authRoutes.js（strict 档守卫）、src/routes/securityRoutes.js、src/routes/inspectionRoutes.js、src/routes/reportRoutes.js、src/routes/userRoutes.js |
| 73 | src/tests/routes/routeSchemaFieldParity.test.js | F2 | src/routes/alarmRoutes.js、src/routes/deviceRoutes.js、src/models/FireAlarm.js、src/models/FireDevice.js |
| 74 | src/tests/routes/securityTxtCanonicalSource.test.js | Clean | src/routes/wellKnownRoutes.js、src/middleware/protocolCompliance.js |
| 75 | src/tests/routes/upgradeEndpoint.test.js | Clean | src/routes/securityRoutes.js（upgrade）、src/config/upgrade.js、升级队列服务 |
| 76 | src/tests/routes/versionEndpoint.test.js | Clean | src/routes/versionRoutes.js、src/config/buildInfo.js |
| 77 | src/tests/routes/wellKnown.test.js | Clean | src/routes/wellKnownRoutes.js、src/middleware/sentry.js |
| 78 | src/tests/routes/writePermissionContract.test.js | Clean | src/routes/*.js（写路由权限中间件/豁免登记） |
| 79 | src/tests/scripts/configDriftCheck.test.js | Clean | scripts/config-drift-check.js（+compose/Dockerfile/nginx.conf.example/.env.example 基线对账） |
| 80 | src/tests/scripts/opsE2eEmptySelection.test.js | Clean | scripts/ops-e2e.js（空选集 fail-closed） |
| 81 | src/tests/scripts/verifyAuditExportScript.test.js | Clean | scripts/verify-audit-export.js、src/services/auditExportService.js |
| 82 | src/tests/security/adversarialProbeRegression.test.js | Clean | src/middleware/rbac.js、src/controllers/userController/update.js、src/controllers/deviceController.js、src/routes/authRoutes.js（NoSQL 注入/原型污染端到端） |
| 83 | src/tests/security/alertProbeRecord.test.js | Clean | scripts/alertProbeRecord.js、scripts/alert-delivery-probe.js、scripts/complianceVerdicts.js |
| 84 | src/tests/security/auditViewerRoleSeparation.test.js | Clean | src/services/initData/roles.js（AUDIT_VIEWER）、src/models/Role.js、src/models/Permission.js |
| 85 | src/tests/security/backupPatrolAndDrillRecency.test.js | Clean | scripts/backupIntegrityPolicy.js、src/constants/backupObjectives.js、scripts/backup-integrity-patrol.js、scripts/record-rollback-drill.js、scripts/drReadinessPolicy.js、scripts/backupArtifactScan.js、.github/workflows/dr-readiness.yml |
| 86 | src/tests/security/baseImageDigestPinned.test.js | Clean | Dockerfile、docker-compose.yml（node/redis digest 钉版） |
| 87 | src/tests/security/businessRetentionAndAnonymization.test.js | Clean | src/constants/businessRetention.js、src/services/userService.js（anonymizeById）、scripts/compliance-check.js 接线 |
| 88 | src/tests/security/businessRetentionVerdict.test.js | Clean | scripts/complianceVerdicts.js、src/constants/businessRetention.js、FireAlarm/Inspection/FireDevice/User 模型 TTL 接线 |
| 89 | src/tests/security/chainResignPrecheck.test.js | Clean | scripts/resign-audit-chain-v3.js（改写前预检、拒绝早于改写） |
| 90 | src/tests/security/complianceAlertingGate.test.js | Clean | scripts/compliance-alerting.js、deployment/observability/alertmanager.yml |
| 91 | src/tests/security/complianceGate.test.js | Clean | scripts/compliance-check.js（误报/漏报/注释与字符串欺骗/登记对账/未知参数） |
| 92 | src/tests/security/complianceGuardStateIsReal.test.js | Clean | src/models/AuditLog.js、src/models/auditLogHooks.js（isAppendOnlyEnforced 与钩子同源） |
| 93 | src/tests/security/credentialLimiterPerUserBucket.test.js | Clean | src/middleware/rateLimit.js（账号维度桶）、src/app.js（trust proxy） |
| 94 | src/tests/security/destructiveGuard.test.js | Clean | scripts/destructiveGuard.js（fail-closed 白名单、host:port/db、回退库拒绝） |
| 95 | src/tests/security/filePermissionEnforcementAndVerify.test.js | Clean | src/utils/filePermission.js、scripts/generate-secrets.js（真收紧+复核+非零出口） |
| 96 | src/tests/security/filePermissionFailClosed.test.js | Clean | src/utils/filePermission.js（失败路径、跨平台分支、argv 白名单锁） |
| 97 | src/tests/security/gateSelfTest.test.js | F5 | scripts/lint-ratchet.js、scripts/check-utf8.js、scripts/compliance-check.js、jest.config.js、web-admin/vite.config.js、.github/workflows/ci.yml、src/tests/docs/openapiSync.test.js、src/tests/architecture/requireCycles.test.js（门禁的元门禁） |
| 98 | src/tests/security/hmacResignPrecheck.test.js | Clean | scripts/resign-audit-hmac.js（预检分类、拒绝早于改写、越权需单号） |
| 99 | src/tests/security/imageReferenceInventory.test.js | Clean | Dockerfile、docker-compose.yml、.github/workflows/*.yml、scripts/verify-image-digests.js、scripts/capture-image-digests.sh 三方对账 |
| 100 | src/tests/security/initDataPasswordPersistAndTighten.test.js | Clean | src/services/initData（createDefaultAdmin/persistInitialPassword）、src/utils/filePermission.js |
| 101 | src/tests/security/ipBlacklistClientIdentityR1.test.js | Clean | src/middleware/security（checkIPBlacklist）、src/utils/ipUtils.js、src/config/trustedProxies.js |
| 102 | src/tests/security/jwtKeyRotation.test.js | Clean | src/utils/jwtKeys.js、src/config/jwtRotation.js、src/services/tokenService.js |
| 103 | src/tests/security/jwtKeyRotationAudit.test.js | Clean | src/services/jwtKeyRotationAudit.js（变化检测、并发认领、失败退回） |
| 104 | src/tests/security/loginIpBucketDominator.test.js | Clean | src/routes/authRoutes.js、src/middleware/rateLimit.js（IP 桶唯一治理者不变量） |
| 105 | src/tests/security/loginPeerBucketXffRotation.test.js | F3 | src/routes/authRoutes.js、src/middleware/rateLimit.js（loginPeerLimiter 对端桶） |

---

## 总体评价
这套测试资产的质量显著高于常见工程实践：行为断言为主、大量"前提自证/反向对照/变异记录"三件套、异步一律条件等待、随机顺序下自足（多个文件明确为 `--randomize` 多 seed 做过顺序解耦）。全部 5 个发现均为 P3 级卫生/覆盖补强项，无阻塞性缺陷。

## T05 — src/tests：security + services 前（99 文件）

## Per-file appendix（99 文件）

图例：Clean = 未发现问题；括号内为该文件守护的生产文件（依 require/import 推断）。

### src/tests/security/（26）

1. security/logoutRevokesAllPresentedTokens.test.js — Clean（services/authService、controllers/authController、models/TokenBlacklist、services/sessionService）
2. security/logoutWithExpiredAccessToken.test.js — Clean（routes/authRoutes 登出入口、middleware/logoutAuth、services/authService、services/tokenService、services/sessionService、models/TokenBlacklist）
3. security/migrateMfaWriteVerify.test.js — Clean（scripts/migrate-mfa-secret.js、utils/mfaSecret、utils/encryption）
4. security/migratePiiKeyStrengthGate.test.js — Clean（scripts/migrate-pii-encryption.js、config/validate.isWeakSecret）
5. security/permissionCodeCatalogParity.test.js — P2：扫描面不含嵌套控制器目录与标识符首参的 hasPermission（services/initData 目录、routes/*、controllers/*、middleware/rbac）
6. security/piiMigrationCoversAlarmReporterPhone.test.js — Clean（scripts/migrate-pii-encryption.js、models/FireAlarm、utils/piiCrypto）
7. security/reauthTicketEnforcement.test.js — Clean（utils/reauthTicket、services/reauthTicketStore、services/reauthGrantStore、models/ReauthGrant、controllers/securityController/reauth、routes/securityRoutes）
8. security/reauthTicketOneTimeUse.test.js — Clean（utils/reauthTicket、services/reauthTicketStore、models/ReauthTicketUse、services/reauthGrantStore）
9. security/reportTargetCandidates.test.js — Clean（controllers/securityController/sensitive 的 report-targets、举报范围同值性、constants/dataScopeFields）
10. security/reportTargetIdBoundary.test.js — Clean（routes/securityRoutes 校验链、controllers/securityController/sensitive、models/AuditLog）
11. security/reportTargetRegistryParity.test.js — Clean（routes/securityRoutes.REPORT_TARGET_TYPES、controllers/securityController/sensitive.REPORT_TARGET_KINDS）
12. security/reportTargetScopeAndLimiter.test.js — Clean（routes/securityRoutes、sensitive 控制器、services/{userService,DeviceService,AlarmService}.findScopeFieldsByIds、middleware/rateLimit、constants/dataScopeFields）
13. security/revokeFailurePropagation.test.js — Clean（services/authService.invalidateUserTokens、auth/security 控制器、services/tokenService、services/sessionService）
14. security/scanFaceParity.test.js — Clean（package.json lint/format 脚本、scripts/lint-ratchet.js、eslint.config.js、web-admin/eslint.config.js、.github/workflows/ci.yml）
15. security/securityAlertsScopeParity.test.js — Clean（controllers/securityController /alerts、services/securityAlert.getRecentAlerts、services/auditScopeFilter）
16. security/securityInputBoundary.test.js — Clean（routes/securityRoutes 的 view-sensitive/lock 校验、sensitive 控制器、services/authService.setUserLockStatus）
17. security/statsAnomalyScope.test.js — Clean（securityController stats/overview、services/securityAlert.getSecurityOverview、services/auditScopeFilter、models/AuditLog.detectAnomalies）
18. security/stuffingProfileReadExit.test.js — Clean（stuffingProfileRoutes、securityController stuffing-profile、constants/stuffingProfile、constants/honeypotAccounts、services/auditScopeFilter）
19. security/systemConfigBooleanContract.test.js — Clean（securityController 配置开关、models/SystemConfig、config/index.js）
20. security/tokenPurposeEntryInventory.test.js — Clean（middleware/auth、middleware/logoutAuth、services/tokenService、services/websocketService/handshake、services/authService/token、utils/tokenPurpose）
21. security/tokenPurposeSeparation.test.js — Clean（config/validate.collectSecretErrors、middleware/auth.assertTokenPurpose、services/tokenService）
22. security/userLockBooleanBoundary.test.js — Clean（routes/securityRoutes lock 校验、services/authService.setUserLockStatus、models/AuditLog）
23. security/userPhoneMaskedEgress.test.js — Clean（models/User.RESPONSE_EXCLUDE*、services/userService.toMaskedAdminUser、userController、utils/helpers.SENSITIVE_KEY_SUBSTRINGS、services/auditBuffer）
24. security/utf8ScanScope.test.js — P3：'dist-tool' 空转用例（scripts/check-utf8.js）
25. security/viewSensitiveReauthOrder.test.js — Clean（routes/securityRoutes 链序、sensitive 控制器、services/mfaService）
26. security/whitelistExemptionTrustBoundary.test.js — Clean（middleware/security.isWhitelistExemptionTrustworthy/checkIPBlacklist、middleware/rateLimit、middleware/originCheck、middleware/metricsAuth）

### src/tests/services/（73）

27. services/adminUsernameCollision.test.js — Clean（services/initData/adminAccount、services/initialPasswordFile）
28. services/alarmDetailHandlerPii.test.js — Clean（services/AlarmService 的 handler select 口径）
29. services/alarmDispatchScopeMatrix.test.js — Clean（services/AlarmService.dispatchAlarm 数据范围矩阵）
30. services/alarmReporterPhoneEgress.test.js — Clean（services/AlarmService.ALARM_READ_SELECT 八个读出口）
31. services/alarmReporterPhoneEncryption.test.js — Clean（models/FireAlarm 的 piiCrypto at-rest 钩子）
32. services/alertSeveritySurvivesRender.test.js — Clean（services/securityAlertDelivery、utils/logger）
33. services/assignmentsReleasedOnAccountLock.test.js — Clean（services/authService.setUserLockStatus、services/userService.releaseOpenAssignments）
34. services/attackDetection.test.js — Clean（services/injectionDetector、services/scanProbeDetector）
35. services/attackEventQueryService.test.js — Clean（services/attackEventQueryService、constants/attackEvents）
36. services/attackProfile.test.js — Clean（services/attackProfile 取数层）
37. services/attackProfileSummary.test.js — Clean（services/attackProfileSummary、services/attackProfileClassify）
38. services/auditAnchorSink.test.js — Clean（services/auditAnchorSink、services/auditChainCheckpoint、scripts/audit-chain-checkpoint）
39. services/auditBufferPrecastGate.test.js — P3：AUDIT_WAL_PATH/MAX_BYTES/STAT_INTERVAL env 不归还（services/auditBuffer、services/auditBufferDocs、services/auditBufferWal、services/auditChainVerify、utils/auditChain）
40. services/auditChainBatchCastParity.test.js — Clean（utils/auditChain.chainBatch、models/AuditLog 铸造闸、constants/audit）
41. services/auditChainCheckpoint.test.js — Clean（services/auditChainCheckpoint、scripts/audit-chain-checkpoint）
42. services/auditChainCheckpointExitCodes.test.js — Clean（services/auditCheckpointFreshness、services/auditChainCheckpoint、scripts/audit-chain-checkpoint）
43. services/auditChainCheckpointRealTail.test.js — P3：AUDIT_WAL_PATH env 不归还（services/auditChainCheckpoint、services/auditBuffer、utils/auditChainTail）
44. services/auditChainDistributed.test.js — Clean（utils/auditChain 共享链尾/分布式锁、services/sharedCache、services/auditChainVerify）
45. services/auditChainForkWindowParity.test.js — Clean（services/auditChainVerify 分叉窗口）
46. services/auditChainGuardedIntegrity.test.js — Clean（services/auditChainVerify、services/auditChainMonitor、config/validate）
47. services/auditChainLegacyPrefixWash.test.js — Clean（services/auditChainVerify legacy/verdict）
48. services/auditChainResign.test.js — Clean（models/AuditLog pre-save 串链、services/auditChainVerify、utils/auditChain）
49. services/auditChainSharedTailReal.test.js — Clean（services/sharedCache × utils/auditChain 集成，F-204）
50. services/auditChainVerify.test.js — Clean（services/auditChainVerify.verifyAuditChain/computeChainVerdict）
51. services/auditChainVerifyIdOrder.test.js — Clean（services/auditChainVerify.checkLinkage、utils/auditChainTail）
52. services/auditChainVerifyTimeBudget.test.js — Clean（services/auditChainVerify maxTimeMS、services/auditChainMonitor、models/auditLogQueryStatics）
53. services/auditChainZombieFreeze.test.js — Clean（utils/auditChain.withChainLock 冻结/续租）
54. services/auditExportManifestScope.test.js — Clean（services/auditExportService manifest 口径）
55. services/auditExportManifestSignature.test.js — Clean（services/auditExportService HMAC 签名）
56. services/auditExportService.test.js — Clean（services/auditExportService CSV 流式导出/转义/截断）
57. services/auditExportWriteLineAbort.test.js — Clean（services/auditExportService 中断收手）
58. services/auditMonitorAlertLoop.test.js — Clean（services/auditMonitor 告警闭环与间隔钳制）
59. services/auditMonitorDailyAlertCap.test.js — Clean（services/auditMonitor 当日闸、services/securityAlert 真频控）
60. services/auditMonitorDetectionCoverage.test.js — Clean（services/auditMonitor 窗口/预算/健康、models/auditLogQueryStatics）
61. services/auditMonitorDetectionLag.test.js — Clean（services/auditMonitor MTTD、utils/metricsDetection、services/securityAlertDelivery）
62. services/auditMonitorTimezone.test.js — Clean（services/auditMonitor 业务时区频控键）
63. services/auditOutbox.test.js — Clean（services/auditOutbox）
64. services/auditQueryOperationCatch.test.js — Clean（services/auditQueryService 操作级 catch）
65. services/auditQueryRealNameProjection.test.js — Clean（services/auditQueryService、controllers/auditController populate 投影）
66. services/auditSchemaCastRewriters.test.js — Clean（models/AuditLog set 闸、utils/auditChain.chainBatch 镜像、constants/audit）
67. services/auditScopeFilterDeptCache.test.js — Clean（services/auditScopeFilter 部门缓存上界）
68. services/auditTtlBootReconcile.test.js — Clean（services/initData TTL 对账、constants/retention、models 索引钩子）
69. services/auditUsernameCastGate.test.js — Clean（constants/audit.cleanAuditUsername、models/AuditLog username set、utils/auditChain）
70. services/auditWalCap.test.js — Clean（services/auditBufferWal/auditWalCap 容量上限与计数口径）
71. services/auditWalChainOrphanRejection.test.js — Clean（services/auditBufferWal catch 臂、utils/auditWriteFailure 及同族扩展集）
72. services/auditWalCorruptLineObservability.test.js — P3：AUDIT_WAL_PATH env 不归还（services/auditBufferWal 坏行可观测性）
73. services/auditWalDurableAppend.test.js — Clean（services/auditBufferWal.appendLineDurable、services/auditOutbox.spool）
74. services/auditWalDurableTrim.test.js — Clean（services/auditWalCap 分级裁剪、utils/metricsAuditDrops）
75. services/auditWalPathIsolation.test.js — Clean（services/auditBuffer/auditWalPath 按库派生与穿越防护）
76. services/auditWalPermissionHardening.test.js — Clean（services/auditBufferWal ACL 收紧、utils/filePermission）
77. services/authRegisterDuplicateKey.test.js — Clean（services/authService/session registerUser E11000 归一臂）
78. services/authServiceLoginRefreshGuards.test.js — Clean（services/authService 登录/刷新/注册全分支）
79. services/authServiceLoginResidualBranches.test.js — Clean（services/authService/login 残余分支与 fail-closed 兜底）
80. services/authServiceProfileAndRevocation.test.js — Clean（services/authService 资料/改密/吊销）
81. services/authServiceSideEffectFailureTolerance.test.js — Clean（services/authService 旁路容错与锁定观测面）
82. services/backgroundJobs.test.js — P3：`global.__eapp` 死赋值（services/auditMonitor、deviceReminder、securityAlert、auditChainVerify、auditBuffer、middleware/errorHandler、utils/permissionHelper、utils/apiResponse、utils/ApiError）
83. services/behaviorBaseline.test.js — Clean（services/behaviorBaseline）
84. services/bruteForceBanDimension.test.js — Clean（services/securityAlert.checkBruteForce、middleware/security/ipBlacklistStore）
85. services/businessStateConsistencyInvariants.test.js — Clean（services/DeviceService、AlarmService、deviceReminder、models/FireDevice、constants/dataScopeFields、middleware/rbac、services/auditBuffer）
86. services/businessTtlReconcileEdges.test.js — Clean（services/initData.reconcileBusinessTtlIndexes 边缘分支）
87. services/cacheWriteBackRace.test.js — Clean（services/userPermissionService、services/sessionService 写回竞态）
88. services/canaryWatch.test.js — Clean（services/canaryWatch、services/authService 注册哨兵闸）
89. services/captchaCounterDegradeAndIdempotentCleanup.test.js — Clean（services/captchaService 内存模式与清理定时器）
90. services/captchaRedisModeGuards.test.js — Clean（services/captchaService Redis 模式）
91. services/cursorTiebreakPagination.test.js — Clean（alarms/inspections/audit-logs 游标续翻、utils/cursorPagination）
92. services/dashboardDataScopeApplied.test.js — Clean（services/reportDashboardService $facet 数据范围）
93. services/deviceAlertOutletParity.test.js — Clean（constants/deviceAlerts、DeviceService、deviceReminder、reportStatsService、reportDashboardService）
94. services/deviceCascadeIndexLock.test.js — Clean（services/DeviceService.deleteDevice 级联、models/FireAlarm、models/Inspection 索引）
95. services/deviceCursorContinuity.test.js — Clean（services/DeviceService.getDevices、utils/cursorPagination、models/FireDevice）
96. services/deviceLocationMerge.test.js — Clean（services/DeviceService.updateDevice location 合并）
97. services/deviceRefCleanupAfterWrite.test.js — Clean（DeviceService.findMissingIds、AlarmService.detachDevice、InspectionService.removeMissingDeviceRefs）
98. services/deviceReminderScopeIsolationGuards.test.js — Clean（services/deviceReminder 互斥/缓存/调度器）
99. services/deviceReminderTruncation.test.js — P3：库隔离注释失效（services/deviceReminder 截断探针、utils/queryBudget）

## 覆盖缺口备注（[D] 性质）

- security/permissionCodeCatalogParity.test.js 的扫描面缺口（见 P2）是本轮唯一实质性的防护缺口。
- 未发现被 skip 的测试、恒真断言或依赖固定 sleep 的异步用例；抽查的故障注入路径（DB down、EPERM/ENOSPC、非 Error 拒绝、unhandledRejection）均有真实断言与反向对照。

## T06 — src/tests：services 中（102 文件）

## Per-file appendix（102 个文件 · 守护的生产文件由 require/import 推断）

| # | 文件 | 结论 | 守护的生产文件 |
| --- | --- | --- | --- |
| 1 | deviceScrapTerminalStateAtomic.test.js | Clean（P3：夹具未清理） | models/FireDevice.js; services/DeviceService.js; middleware/errorHandler.js |
| 2 | deviceStatsCache.test.js | Clean | services/DeviceService.js; services/statsCache.js; models/FireDevice.js |
| 3 | exportConcurrency.test.js | Clean | services/exportConcurrency.js; utils/metricsRuntime.js |
| 4 | exportCountDrift.test.js | Clean | services/reportWorkbookService.js; services/reportExportService.js |
| 5 | exportSuccessParity.test.js | Clean | utils/auditQuery.js; services/reportExportService.js |
| 6 | f74NegativeEnvFallback.test.js | Clean | services/auditBuffer.js; services/securityAlert.js |
| 7 | failOpenSignals.test.js | Clean | services/captchaService.js; models/SystemConfig.js; services/sharedCache/* |
| 8 | fireAndForgetAlertSingleEntry.test.js | Clean | services/alertDispatch.js; services/securityAlert.js; services/securityAlertDelivery.js; services/auditMonitor.js; services/auditChainMonitor.js; middleware/security/ipBlacklist.js |
| 9 | forensicCapture.test.js | Clean | services/forensicCapture.js; services/forensicCapturePayload.js; models/ForensicCapture.js; models/auditLogSanitizer.js; utils/logPiiMask.js |
| 10 | forensicCaptureAlertIsolation.test.js | Clean | services/forensicCapture.js; utils/metrics.js; services/forensicTrigger.js |
| 11 | forensicCaptureHardening.test.js | Clean（P3：mock 变异未 try/finally） | services/forensicCapture.js; services/forensicCaptureWal.js; models/ForensicCapture.js |
| 12 | forensicCapturePartialBatch.test.js | P2[D5]（test.failing 记账 H-3） | services/forensicCaptureFlush.js; services/forensicCapture.js; services/forensicManifest.js; services/forensicCaptureCodec.js; models/ForensicCapture.js |
| 13 | forensicCaptureTtlReconcile.test.js | Clean | services/initData/index.js（reconcileBusinessTtlIndexes）; constants/businessRetention.js; models/ForensicCapture.js |
| 14 | forensicCaptureWal.test.js | Clean | services/forensicCaptureWal.js |
| 15 | forensicCaptureWiring.test.js | Clean | src/index.js; utils/crashFlush.js; services/forensicCapture.js |
| 16 | forensicFingerprintQuery.test.js | Clean | services/forensicTrace.js |
| 17 | forensicManifest.test.js | Clean | services/forensicManifest.js |
| 18 | forensicManifestLock.test.js | Clean（P3：tmp 目录未清理） | services/forensicManifestLock.js; services/forensicManifest.js |
| 19 | forensicManifestReconcile.test.js | Clean（P3：tmp 目录未清理） | services/forensicManifestReconcile.js; services/forensicManifest.js; models/ForensicCapture.js |
| 20 | forensicManifestRetention.test.js | Clean（P3：tmp 目录未清理） | services/forensicManifest.js; forensicManifestRetry.js; forensicManifestPrune.js; forensicManifestLock.js |
| 21 | forensicTraceExport.test.js | Clean | services/forensicTrace.js; services/forensicExport.js; models/ForensicCapture.js |
| 22 | forensicTrigger.test.js | Clean | services/forensicTrigger.js; middleware/security/ipBlacklist.js; services/honeypotWatch.js; services/securityAlertIpBans.js |
| 23 | honeypotChainWatch.test.js | Clean | services/honeypotChainWatch.js; constants/timezone.js; models/AuditLog.js |
| 24 | honeypotDecoy.test.js | Clean | services/honeypotDecoy.js; services/honeypotWatch.js; constants/honeypotDecoy.js |
| 25 | honeypotDecoyFiles.test.js | Clean | services/honeypotDecoyFiles.js; services/reportExportService.js; constants/honeypotDecoyFiles.js |
| 26 | honeypotDecoySelf.test.js | Clean | services/honeypotDecoySelf.js; constants/honeypotDecoySelf.js |
| 27 | honeypotSocketGate.test.js | Clean | services/websocketService/handshake.js; services/honeypotWatch.js |
| 28 | honeypotWatch.test.js | Clean | services/honeypotWatch.js; services/authService.js; services/userService.js; services/canaryWatch.js; config/trustedProxies.js |
| 29 | initDataLifecycle.test.js | Clean（P3：B7 编号重复） | services/initData.js; models/{User,Role,Permission,TokenBlacklist,SystemConfig}.js; utils/filePermission.js |
| 30 | initDataParentConvergence.test.js | Clean | services/initData.js（initPermissions）; models/Permission.js |
| 31 | initSystemConfig.test.js | Clean | services/initData.js（initSystemConfig）; models/SystemConfig.js |
| 32 | initialPasswordFileLifecycle.test.js | Clean | services/initialPasswordFile.js |
| 33 | inspectionCursorNullableSortKey.test.js | Clean | services/InspectionService.js; utils/cursorPagination.js; models/Inspection.js |
| 34 | inspectionExecutionLogCap.test.js | P2（env 泄漏） | services/InspectionService.js; models/Inspection.js |
| 35 | inspectionOverdueRemainsWorkable.test.js | Clean | services/InspectionService.js; services/deviceReminder.js; constants/inspection.js |
| 36 | inspectionUpdateAtomicity.test.js | Clean | services/InspectionService.js; models/Inspection.js |
| 37 | ipAttributionPunishTarget.test.js | Clean | utils/ipUtils.js; middleware/security/ipBlacklistStore.js; services/rateLimitEscalation.js; services/securityAlert.js |
| 38 | ipLocationService.test.js | Clean | services/ipLocationService.js; utils/ip2regionSearcher.js; constants/ipLocationCodes.js |
| 39 | ipPoolBan.test.js | Clean | services/ipPoolBan.js; services/ipListService.js; services/ipPoolLiveTraffic.js; services/sharedCache/index.js |
| 40 | ipPoolBanApplyTimeOperator.test.js | Clean | services/ipPoolBan.js; models/IPBlacklist.js |
| 41 | ipPoolBanConfirmUnionRecheck.test.js | Clean | services/ipPoolBan.js; utils/cidrCoverage.js; models/IPBlacklist.js |
| 42 | ipPoolCluster.test.js | Clean | services/ipPoolCluster.js |
| 43 | ipPoolLiveTraffic.test.js | Clean | services/ipPoolLiveTraffic.js; utils/ipUtils.js |
| 44 | lockExpiryResetsAtomic.test.js | Clean | services/authService/failureAndMfa.js; services/authService.js; services/mfaService.js |
| 45 | loginCanaryAttempt.test.js | Clean | services/authService.js; services/canaryWatch.js |
| 46 | loginChallengeAudit.test.js | Clean | services/loginChallenge.js; services/authService.js |
| 47 | loginFailureChallenge.test.js | Clean | services/loginChallenge.js; services/authService.js |
| 48 | loginFailureCounterFailClosed.test.js | Clean | services/authService.js（resolveFailedLoginCount）; models/User.js |
| 49 | loginRateLimitAudit.test.js | Clean | services/loginRateLimitAudit.js; services/loginChallenge.js |
| 50 | mfaDisableRecoveryAtomicWrite.test.js | Clean | services/mfaDisable.js; services/mfaService.js; utils/mfaSecret.js |
| 51 | mfaFactorPathAndLockDuration.test.js | Clean | services/mfaService.js |
| 52 | mfaRevokeAndPepperFallback.test.js | Clean | services/mfaService.js |
| 53 | mfaSilentWriteFailureTrace.test.js | Clean | services/mfaService.js |
| 54 | mfaTokenPrimitiveGuards.test.js | Clean | services/mfaService.js; services/tokenService.js |
| 55 | observabilityWritesNeverReject.test.js | Clean | services/sessionService.js; middleware/auth.js; src/index.js; services/deviceReminder.js; services/auditBuffer.js; services/auditBufferDocs.js; utils/auditWriteFailure.js; services/sharedCache/index.js |
| 56 | outboundAlertContract.test.js | Clean | services/securityAlert.js; services/securityAlertDelivery.js; constants/audit.js |
| 57 | permCacheLifecycle.test.js | Clean | services/userPermissionService.js |
| 58 | permissionBatchSync.test.js | Clean | services/userPermissionService.js; services/websocketService.js |
| 59 | permissionCacheDegradedTtl.test.js | Clean | services/userPermissionService.js; services/sharedCache/index.js |
| 60 | permissionHotReload.test.js | Clean | services/websocketService.js; controllers/roleController.js; controllers/userController.js; services/userPermissionService.js |
| 61 | permissionParentIdCaseAndDedup.test.js | Clean | services/permissionService.js（batchCreatePermissions） |
| 62 | permissionSoftDelete.test.js | Clean | services/permissionService.js; models/Permission.js; services/initData/seeding.js |
| 63 | piiExportQuotaRedis.test.js | Clean | services/piiExportQuota.js |
| 64 | piiExportQuotaWatermark.test.js | Clean | services/piiExportQuota.js; services/piiExportWatermark.js |
| 65 | privilegeGrantFlow.test.js | Clean | services/privilegeGrantService.js; services/accessReviewService.js; services/userPermissionService.js; models/PrivilegeGrant.js; scripts/access-review.js; constants/privilegeGrant.js |
| 66 | privilegeGrantPiiHighRisk.test.js | Clean | constants/privilegeGrant.js; services/initData/permissions.js |
| 67 | privilegeGrantValidationBoundaries.test.js | Clean | services/privilegeGrantValidation.js; constants/privilegeGrant.js |
| 68 | rateLimitEscalation.test.js | Clean | services/rateLimitEscalation.js; services/rateLimitEscalationBan.js; middleware/rateLimit.js; middleware/security/ipBlacklistStore.js |
| 69 | rateLimitEscalationEviction.test.js | Clean | services/rateLimitEscalation.js |
| 70 | realtimeEmitWiring.test.js | Clean | services/AlarmService.js; services/DeviceService.js; services/realtimeNotifier.js |
| 71 | realtimeNotifier.test.js | Clean | services/realtimeNotifier.js; services/websocketService.js |
| 72 | recoveryCodeFormatSingleSource.test.js | Clean | services/mfaService.js; services/authService/failureAndMfa.js; routes/authRoutes.js |
| 73 | refreshAuditTrail.test.js | Clean | services/authService.js; services/sessionService.js |
| 74 | reportExportPiiMasking.test.js | Clean | services/reportExportService.js; controllers/reportController.js; routes/reportRoutes.js |
| 75 | reportStatsCountsAndRate.test.js | Clean | controllers/reportController.js; services/report*Service.js; models/FireDevice.js; models/Inspection.js |
| 76 | reportTargetServiceKindLookup.test.js | Clean | services/reportTargetService.js |
| 77 | reportWorkbookExportIntegrity.test.js | Clean | services/reportWorkbookService.js; services/reportExportService.js; constants/timezone.js |
| 78 | reportWorkbookService.test.js | Clean | services/reportWorkbookService.js |
| 79 | roleDeletionRecovery.test.js | Clean | services/roleService.js; models/Role.js |
| 80 | roleUserCountPipelineLock.test.js | Clean | services/roleService.js; models/User.js |
| 81 | runtimeTopologyAndPerfInvariants.test.js | Clean | constants/runtime.js; utils/auditChain.js; models/SystemConfig.js; services/statsCache.js; services/securityAlert.js; services/websocketService.js |
| 82 | securityAlertLifecycle.test.js | Clean | services/securityAlert.js |
| 83 | securityAlertWriteFailureTolerance.test.js | Clean | services/securityAlert.js; services/securityAlertPermissionAbuse.js |
| 84 | securityAlertDeliveryFailureTrace.test.js | Clean | services/securityAlert.js |
| 85 | securityAlertDetectionQueryFailureTrace.test.js | Clean | services/securityAlert.js |
| 86 | securityAlertGuards.test.js | Clean | services/securityAlert.js; services/securityAlertDelivery.js |
| 87 | securityAlertBanLadder.test.js | Clean | services/securityAlert.js; services/securityAlertIpBans.js; services/securityAlertPermissionAbuse.js; constants/retention.js |
| 88 | securityAlertContainmentDecoupling.test.js | Clean | services/securityAlert.js; services/securityAlertIpBans.js; services/securityAlertPermissionAbuse.js |
| 89 | sessionCrossInstance.test.js | Clean | services/sessionService.js; services/sharedCache/index.js |
| 90 | sessionFailSoft.test.js | Clean | services/sessionService.js |
| 91 | sessionService.test.js | Clean | services/sessionService.js; models/UserSession.js |
| 92 | sharedCacheBackends.test.js | Clean | services/sharedCache/index.js（含 memoryStore/redis 两后端与锁） |
| 93 | sharedCacheNonceFloodEviction.test.js | Clean | services/sharedCache/index.js; utils/loginCipher.js |
| 94 | startupAuditTrail.test.js | Clean | services/startupAuditTrail.js; services/jwtKeyRotationAudit.js |
| 95 | statsCache.test.js | Clean | services/statsCache.js |
| 96 | statsCacheTtlCeiling.test.js | Clean | services/statsCache.js; config/index.js |
| 97 | tokenService.test.js | P3（覆盖偏薄） | services/tokenService.js |
| 98 | updateRolesVersionBump.test.js | Clean | services/userService.js; models/User.js |
| 99 | upgradeService.test.js | Clean | services/upgradeService.js; config/upgrade.js; services/upgradeRequestSignature.js |
| 100 | userListLastLoginIp.test.js | Clean | services/userService.js; models/User.js |
| 101 | userSaveCredentialWipe.test.js | Clean | models/User.js（unselectedCredentialProjection）; services/authService.js; services/userService.js |
| 102 | userSessionIpGate.test.js | Clean | models/UserSession.js; services/sessionService.js |

—— 完 ——

## T07 — src/tests：services 后 + 根目录 + utils（115 文件）

## Per-file appendix（115 文件；"守护的生产文件"由 require/import 推断）

| # | 文件 | 结论 | 守护的生产文件 |
| --- | --- | --- | --- |
| 1 | src/tests/services/walCapTrimFailureTaxonomy.test.js | Clean | services/auditBuffer.js, services/auditBufferWal.js, services/auditWalCap.js |
| 2 | src/tests/services/walReadFailureTaxonomy.test.js | Clean | services/auditBufferWal.js（trimBySeqs/启动重放） |
| 3 | src/tests/services/walStatIntervalEnvContract.test.js | Clean | services/auditBuffer.js（AUDIT_WAL_STAT_INTERVAL 判据） |
| 4 | src/tests/services/webhookDnsPinningAndSigning.test.js | Clean | services/securityAlertDelivery.js, utils/httpPostJson.js |
| 5 | src/tests/services/webhookIpv4CompatibleDeny.test.js | Clean | services/securityAlertDelivery.js（isWebhookTargetAllowed ::/96） |
| 6 | src/tests/services/websocketAllowedIpTrustBoundary.test.js | Clean | services/websocketService（resolveHandshakeIPForSecurityDecision/_assertHandshakeIpAllowed/_assertHandshakeIpNotBanned）, utils/ipUtils, config/trustedProxies |
| 7 | src/tests/services/websocketAuthGhostConnection.test.js | Clean | services/websocketService/handshake.js（authenticateSocket 幽灵连接） |
| 8 | src/tests/services/websocketAuthScope.test.js | Clean | services/websocketService/handshake.js（allowedIPs/sid 会话校验/trust proxy 一致性） |
| 9 | src/tests/services/websocketCorsAndReauthGuards.test.js | P2：cookie 夹具前提失真（自陈 [仍有效]） | services/websocketService（CORS 构造、dispose、extractHandshakeToken、emitRoleUpdate/emitPermissionSync、auth 防重入、join-room 复查、initSharedAdapter） |
| 10 | src/tests/services/websocketHandlerRejectionGuard.test.js | Clean | services/websocketService/push.js（guardSocketHandler 拒绝臂） |
| 11 | src/tests/services/websocketHandshakeIpBan.test.js | Clean | services/websocketService/handshake.js（IP 黑名单闸/清扫 _sweepBannedIps）, models/IPBlacklist |
| 12 | src/tests/services/websocketInboundThrottle.test.js | Clean | services/websocketService/inboundThrottle.js, services/websocketService/shared.js, utils/metricsRuntime.js |
| 13 | src/tests/services/websocketRedisAdapter.test.js | Clean | services/websocketService（initSharedAdapter）, services/sharedCache（redisConnectionPassword） |
| 14 | src/tests/services/websocketSessionRevocationAndQuota.test.js | Clean | services/websocketService（会话吊销联动/未认证 IP 配额）, services/sessionService |
| 15 | src/tests/services/websocketSweep.test.js | Clean | services/websocketService（runCleanupSweep 授权复查） |
| 16 | src/tests/services/websocketTempLockAndRoomRevocation.test.js | Clean | services/websocketService/handshake.js + revalidate（lockUntil 闸/降级清房/投影结构门禁） |
| 17 | src/tests/services/websocketTrustProxyHopsParity.test.js | Clean | config/validate.js（resolveTrustProxyHops）, services/websocketService |
| 18 | src/tests/services/wsFlow.test.js | P3：遗留 JOIN_DEBUG 调试输出 | services/websocketService 全流程 |
| 19 | src/tests/sessionCacheExpiryLag.test.js | Clean | services/sessionService.js（缓存命中复核过期） |
| 20 | src/tests/setup.js | Clean | 测试基础设施（文件级独立库、密钥文件隔离） |
| 21 | src/tests/sharedCacheDegradationLog.test.js | Clean | services/sharedCache.js（Redis 降级失效清单）, constants/runtime.js |
| 22 | src/tests/sharedCacheLockDegradationLogged.test.js | Clean | services/sharedCacheLocks.js（降级 warn，子进程取证） |
| 23 | src/tests/sharedCacheLockToken.test.js | Clean | services/sharedCacheLocks.js（锁令牌 CSPRNG/续租/三原语极性） |
| 24 | src/tests/sharedCacheNonceFailClosed.test.js | Clean | services/sharedCache.js（setIfAbsent/incrWithTtl fail-closed） |
| 25 | src/tests/staticFrontendSourcemapDeny.test.js | Clean | middleware/staticFrontend.js |
| 26 | src/tests/statsScopeFailClosed.test.js | Clean | services/InspectionService.js（getInspectionStats 数据范围 deny） |
| 27 | src/tests/stepUpTotpReplay.test.js | Clean | middleware/security.js（requireReAuthentication）, services/mfaService.js, utils/totp.js |
| 28 | src/tests/systemConfigBooleans.test.js | Clean | models/SystemConfig.js（布尔口径/并发 upsert） |
| 29 | src/tests/testSequencer.js | Clean | jest 文件级乱序 sequencer（JEST_FILE_SEED） |
| 30 | src/tests/totpEmptySecretNoBypass.test.js | Clean | utils/totp.js（退化密钥全拒） |
| 31 | src/tests/transactionProbe.test.js | Clean | utils/transaction.js（拓扑探测缓存策略） |
| 32 | src/tests/userDeleteCascade.test.js | Clean | services/userService.js（deleteById/deleteMany 级联）, services/AlarmService.js, services/InspectionService.js |
| 33 | src/tests/userWritePathScopeParity.test.js | Clean | controllers/userController/*（写路径范围闸）, controllers/securityController/admin.js |
| 34 | src/tests/usernameCharsetAtModel.test.js | Clean | models/User.js（username 字符集模型层收口） |
| 35 | src/tests/verifyChainExitCode.test.js | Clean | scripts/verify-audit-chain.js, services/auditChainVerify.js（computeVerdict 出口契约） |
| 36 | src/tests/verifyScanBound.test.js | Clean | controllers/auditController.js（verifyAuditChainIntegrity limit 钳制） |
| 37 | src/tests/webhookSsrfRangeWhitelist.test.js | Clean | services/securityAlertDelivery.js（出站地址白名单） |
| 38 | src/tests/writeSurfaceControlCharAndHeadersSentGuards.test.js | Clean | middleware/protocolCompliance.js, middleware/errorHandler.js, utils/metrics.js |
| 39 | src/tests/wsProbeVerdict.test.js | Clean | scripts/audit-probes/ws-session-bypass.cjs（三态判据） |
| 40 | src/tests/utils/accessLogDevFormat.test.js | Clean | utils/accessLogDevFormat.js, utils/helpers.js（redactUrlQuery） |
| 41 | src/tests/utils/apiErrorHttpJsonAndLimitGuards.test.js | P3：顶层 mongoose mock 面过宽 | utils/ApiError.js, utils/httpPostJson.js, plugins/autoIncrement.js, services/captchaService.js, middleware/sentry.js, middleware/rateLimit.js |
| 42 | src/tests/utils/apiResponsePaginatedDefaults.test.js | Clean | utils/apiResponse.js（paginated 兜底） |
| 43 | src/tests/utils/auditChainSurrogateArtifact.test.js | Clean | utils/helpers.js（stripControlChars/Deep 代理项）, services/auditChainVerify.js, models/AuditLog.js |
| 44 | src/tests/utils/auditFilterCombination.test.js | Clean | utils/auditQuery.js（恒空组合 400）, constants/audit.js |
| 45 | src/tests/utils/auditIpVariantForms.test.js | Clean | utils/auditQuery.js, services/reportExportService.js, utils/ipUtils.js（ipQueryVariants 单一来源） |
| 46 | src/tests/utils/auditMeta.test.js | P3：冻结计数 110（自陈） | utils/auditMeta.js, constants/audit.js, src/routes/*（action 白名单对账） |
| 47 | src/tests/utils/auditQueryFindAggregateParity.test.js | Clean | utils/auditQuery.js（userId cast，find/aggregate 同尺） |
| 48 | src/tests/utils/auditQueryParamTypeGuard.test.js | Clean | utils/auditQuery.js（username 类型 400） |
| 49 | src/tests/utils/auditWriteFailure.test.js | Clean | utils/auditWriteFailure.js（onAuditWriteFailure/guardDetection/awaitAuditWrite） |
| 50 | src/tests/utils/avatarImage.test.js | Clean | utils/avatarImage.js, utils/pngStructure.js（解压上限夹取） |
| 51 | src/tests/utils/bcryptWorkerPool.test.js | Clean | utils/bcryptWorkerPool.js（回退/强制 worker/初始化失败 G-01） |
| 52 | src/tests/utils/bcryptWorkerPoolCrashFallback.test.js | Clean | utils/bcryptWorkerPool.js（崩溃兜底 G-02/code-0 退出） |
| 53 | src/tests/utils/bcryptWorkerThread.test.js | Clean | utils/bcryptWorkerThread.js（操作白名单 G-03） |
| 54 | src/tests/utils/breachedPasswordMatcher.test.js | Clean | utils/helpers.js, constants/breachedPasswords.js（词干表逐条可达） |
| 55 | src/tests/utils/cidrCoverage.test.js | Clean | utils/cidrCoverage.js |
| 56 | src/tests/utils/clientIpSecurityDecision.test.js | Clean | utils/ipUtils.js（clientIpForSecurityDecision/isClientIpIdentityTrustworthy）, middleware/security.js |
| 57 | src/tests/utils/cryptoKeyGuard.test.js | Clean | utils/encryption.js（密钥守卫/CBC 遗留开关） |
| 58 | src/tests/utils/cursorPagination.test.js | Clean | utils/cursorPagination.js, models/FireDevice.js（F-169 宽度对账） |
| 59 | src/tests/utils/dateBoundaryTzWiring.test.js | Clean | utils/helpers.js（parseDateBoundary/buildDateRangeFilter）, controllers/reportController.js, services/reportStatsService.js, services/honeypotDecoyFiles.js |
| 60 | src/tests/utils/dateFormatPlaceholder.test.js | Clean | utils/dateFormat.js |
| 61 | src/tests/utils/dateParamForms.test.js | Clean | utils/helpers.js, constants/timezone.js |
| 62 | src/tests/utils/dateParamGateSingleSource.test.js | Clean | utils/helpers.js（isValidDateParam 单一来源扫描） |
| 63 | src/tests/utils/durationToMsParity.test.js | Clean | utils/cookie.js（durationToMs/setAuthCookies）, services/sessionService.js |
| 64 | src/tests/utils/encryption.test.js | Clean | utils/encryption.js（GCM 形态闸/HMAC 非规范写法） |
| 65 | src/tests/utils/errorCodes.test.js | Clean | utils/errorCodes.js, utils/apiResponse.js, services/authService（登录防枚举，真实登录对照） |
| 66 | src/tests/utils/filePermissionUsernamePaths.test.js | Clean（非 Windows 显式 skip，带理由） | utils/filePermission.js |
| 67 | src/tests/utils/fingerprint.test.js | Clean | utils/fingerprint.js（F-177 绝对值断言） |
| 68 | src/tests/utils/fingerprintDelimiterFidelity.test.js | Clean | utils/fingerprint.js（转义单射性/黄金值连续性）, utils/auditChainPayload.js |
| 69 | src/tests/utils/forensicDeviceKey.test.js | Clean | utils/forensicDeviceKey.js |
| 70 | src/tests/utils/hardening.test.js | Clean | utils/helpers.js, utils/dateFormat.js, utils/auditMeta.js, services/reportExportService.js, middleware/rbac.js, middleware/dataScope.js, models/Inspection.js |
| 71 | src/tests/utils/healthChecksRedis.test.js | Clean | utils/healthChecks.js（checkRedisReady）, services/sharedCache.js |
| 72 | src/tests/utils/helpers.test.js | Clean | utils/helpers.js（escapeRegExp/分页/口令/排序/清洗/日期） |
| 73 | src/tests/utils/httpPostJsonDeadline.test.js | Clean | utils/httpPostJson.js（协议白名单/绝对截止/断连归因） |
| 74 | src/tests/utils/httpPostJsonPinnedLookup.test.js | Clean | utils/httpPostJson.js（lookup 钉扎） |
| 75 | src/tests/utils/ip2regionSearcher.test.js | Clean | utils/ip2regionSearcher.js（含 F3 off-by-one 合成 xdb） |
| 76 | src/tests/utils/ipAttributionClassification.test.js | Clean | utils/ipUtils.js（classifyIpAttribution/resolvePunishableIp）, config/trustedProxies.js |
| 77 | src/tests/utils/ipRange.test.js | Clean | utils/ipRange.js（解析/校验/匹配/fail-closed） |
| 78 | src/tests/utils/ipScopeIdCanonicalization.test.js | Clean | utils/ipUtils.js（IPv6 作用域标识归一 + 漂移门禁） |
| 79 | src/tests/utils/ipTextStrictness.test.js | Clean | utils/ipUtils.js（四漏斗歧义拒绝） |
| 80 | src/tests/utils/ipUtils.test.js | Clean | utils/ipUtils.js（归一化/CIDR/覆盖判定） |
| 81 | src/tests/utils/ipUtilsMappedCidr.test.js | Clean | utils/ipUtils.js（映射网段收敛/::ffff:0.0.0.0/96 高危） |
| 82 | src/tests/utils/logContext.test.js | Clean | utils/logContext.js, middleware/requestId.js, utils/logger.js |
| 83 | src/tests/utils/logPiiMask.test.js | Clean | utils/logPiiMask.js, utils/logger.js（sanitizeLogInfo 集成） |
| 84 | src/tests/utils/logPiiMaskLinearAndNestedCap.test.js | Clean | utils/logPiiMask.js（U1 线性/嵌套截断） |
| 85 | src/tests/utils/logShippingUrlValidatedAtMount.test.js | Clean | utils/logger.js, utils/logShipper.js, controllers/securityController/overview.js |
| 86 | src/tests/utils/loggerShippingEnv.test.js | Clean | utils/logger.js, utils/logShipper.js（LOG_SHIPPING_* 数值判据） |
| 87 | src/tests/utils/loginCipher.test.js | Clean | utils/loginCipher.js（ECDH 信封/AAD 用途绑定/防重放）, services/sharedCache.js |
| 88 | src/tests/utils/maskIpEmbeddedV4OctetBoundary.test.js | Clean | utils/encryption.js（DataMasking._expandIPv6 边界 255） |
| 89 | src/tests/utils/mongoDuplicateKeyRealShapes.test.js | Clean | utils/mongoDuplicateKey.js（真实驱动形态） |
| 90 | src/tests/utils/mongoDuplicateKeyShapes.test.js | Clean | utils/mongoDuplicateKey.js（writeErrors 逐条码臂） |
| 91 | src/tests/utils/mongoFailureAttribution.test.js | Clean | utils/mongoFailureAttribution.js, services/auditBuffer.js（F-183 派生门禁 + 真库形状） |
| 92 | src/tests/utils/passwordHistory.test.js | Clean | utils/passwordHistory.js, services/authService/password.js, controllers/securityController/admin.js, controllers/authController/profile.js, controllers/securityController/account.js, models/User.js, utils/errorCodes.js |
| 93 | src/tests/utils/permissionHelper.test.js | Clean | utils/permissionHelper.js（maxRoleLevel/getOperatorMaxLevel） |
| 94 | src/tests/utils/permissionHelperClassificationGuards.test.js | Clean | utils/permissionHelper.js（分类/错误分支/停用角色三处同口径） |
| 95 | src/tests/utils/piiEncryption.test.js | Clean | utils/piiCrypto.js, models/User.js, models/FireAlarm.js（v2 AAD/子串盲索引/主密钥守卫） |
| 96 | src/tests/utils/posixShell.test.js | Clean（无 shell 环境显式 skip，带理由） | src/tests/helpers/posixShell.js |
| 97 | src/tests/utils/proxyProtocolFrontServer.test.js | Clean | utils/proxyProtocol.js（createProxyProtocolFrontServer 三态/信任名单/韧性） |
| 98 | src/tests/utils/proxyProtocolParser.test.js | Clean | utils/proxyProtocol.js（v1/v2 解析/重写原语） |
| 99 | src/tests/utils/pureModules.test.js | Clean | utils/encryption.js, services/captchaService.js, services/userPermissionService.js, services/statsCache.js |
| 100 | src/tests/utils/queryBudget.test.js | Clean | utils/queryBudget.js + 8 个列表链服务（AlarmService/DeviceService/InspectionService/userService/roleService/permissionService/auditQueryService/auditExportService） |
| 101 | src/tests/utils/remediationLocksL20L21.test.js | Clean | models/AuditLog.js（detectAnomalies threshold）, middleware/index.js, src/app.js（真实模块图） |
| 102 | src/tests/utils/roleLevelSingleSource.test.js | Clean | utils/permissionHelper.js, constants/dataScopeFields.js（单一来源扫描） |
| 103 | src/tests/utils/scopeCastProtoKey.test.js | Clean | utils/scopeCast.js（__proto__ 自有属性） |
| 104 | src/tests/utils/searchPatternsUndefinedTerm.test.js | Clean | utils/searchPatterns.js |
| 105 | src/tests/utils/shutdownBudgetContract.test.js | Clean | utils/shutdownBudget.js, src/index.js（关停链）, docker-compose.yml |
| 106 | src/tests/utils/shutdownStepOrder.test.js | Clean | src/index.js（SIEM 排空必须链尾） |
| 107 | src/tests/utils/superAdmin.test.js | Clean | utils/superAdmin.js |
| 108 | src/tests/utils/tails.test.js | Clean | middleware/rbac.js, utils/helpers.js, utils/totp.js, utils/cookie.js, utils/fingerprint.js, models/User.js, models/Role.js, models/FireDevice.js, models/IPBlacklist.js, models/AuditLog.js, utils/loginCipher.js, utils/httpPostJson.js, routes/wellKnownRoutes.js |
| 109 | src/tests/utils/tokenPurposeAndConsumers.test.js | Clean | utils/tokenPurpose.js, middleware/auth.js, services/tokenService.js, services/websocketService/handshake.js |
| 110 | src/tests/utils/toolCryptoAndOriginGuards.test.js | P2：自陈残留 ~48 行文本正则断言；P3：生产 logger 探针仓库内落盘 | utils/totp.js, utils/encryption.js, utils/ipRange.js, utils/helpers.js, models/User.js, utils/logShipper.js, middleware/errorHandler.js, middleware/protocolCompliance.js, middleware/rateLimit.js, middleware/originCheck.js, middleware/queryLimit.js, config/swagger.js, config/index.js, middleware/userAuthCache.js, utils/cookie.js, routes/securityRoutes.js, services/initData.js |
| 111 | src/tests/utils/totp.test.js | Clean | utils/totp.js（RFC 4226 向量） |
| 112 | src/tests/utils/transaction.test.js | Clean | utils/transaction.js（standalone 降级） |
| 113 | src/tests/utils/transactionTopology.test.js | Clean | utils/transaction.js（fail-loud/endSession 拒绝臂/源码持有闸） |
| 114 | src/tests/utils/wildcardPermissionSingleSource.test.js | P3：冻结分布账（自陈，有意为之） | utils/superAdmin.js, middleware/rbac.js, utils/permissionHelper.js, controllers/roleGuards.js, routes/permissionRoutes.js, controllers/permissionController.js, services/initData/*, services/userPermissionService.js |
| 115 | src/tests/utils/xlsxWriterGuards.test.js | Clean | utils/xlsxWriter.js |

---

## 结论

115 个文件全部逐行读完。未发现 P0/P1 级测试缺陷：没有空测试、恒真断言、静默 skip 或顺序耦合导致的安全假绿；异步与夹具卫生纪律严格。2 项 P2 均为文件头自陈的已知保真度问题（cookie 夹具前提、文本正则残留），6 项 P3 为调试残留、mock 面过宽、冻结计数与两项本批次范围内的覆盖缺口（WS 认证超时闸、单进程连接上限拒绝路径——不排除由本批次外套件覆盖）。

## W00 — web-admin：配置 / 组件 / composables（66 文件）

## Per-file appendix

| 文件 | 结论 |
| --- | --- |
| web-admin/.env.example | Clean（仅 VITE_ 前缀非敏感变量，上报端点留空默认本地留档） |
| web-admin/.prettierrc | Clean |
| web-admin/README.md | P3[D7] 仅钉版说明，无上手内容 |
| web-admin/bundle-budget.json | Clean（预算与 measured 快照同构，含 floors） |
| web-admin/dev-vite.cmd | Clean |
| web-admin/eslint.config.js | Clean（vue/no-v-html、no-eval 等 error 硬门禁；棘轮注释与规则一致） |
| web-admin/index.html | Clean（robots 三层防收录；theme-bootstrap 外链兼容 CSP self；BASE_URL 相对引用） |
| web-admin/package-lock.json | Clean（无已知风险版本；重复版本均为传递依赖常态，见上文锁文件结论） |
| web-admin/package.json | Clean（engines node>=22.12；scripts 与 budget/eslint 配置一致） |
| web-admin/postcss.config.js | Clean |
| web-admin/public/favicon.svg | Clean |
| web-admin/public/robots.txt | Clean |
| web-admin/public/theme-bootstrap.js | Clean（仅读 themeMode 非敏感偏好；try/catch 全包） |
| web-admin/src/App.vue | Clean（EP locale 深路径引入避免语言包双打） |
| web-admin/src/assets/styles/apple-polish.css | Clean（reduced-motion/transparency 双降级） |
| web-admin/src/assets/styles/apple-refine.css | Clean（弹层/触控/safe-area 体系化；降级完备） |
| web-admin/src/assets/styles/dark.css | Clean（令牌翻转式暗色） |
| web-admin/src/assets/styles/global.css | Clean（设计令牌单一来源；.sk-block 历史重复定义已除并留注释） |
| web-admin/src/assets/styles/print.css | Clean（打印三件套；链接地址输出排除 javascript:/锚点） |
| web-admin/src/assets/styles/view-refine.css | P3[D4] 行入场动画编排（已含降级） |
| web-admin/src/auto-imports.d.ts | Clean（生成文件） |
| web-admin/src/components.d.ts | Clean（生成文件） |
| web-admin/src/components/AccountBindingsCard.vue | Clean（错误态可重试，不展示过期数据） |
| web-admin/src/components/AttackEvidenceTable.vue | Clean（纯渲染，事件上抛） |
| web-admin/src/components/AttackProfileResult.vue | P3[D1] suggestions 以业务码作 key，重复码撞 key |
| web-admin/src/components/AuthPrefs.vue | Clean（认证页主题/语言控件收敛单点） |
| web-admin/src/components/ChangePasswordCard.vue | Clean（密文双轨 fail-closed；登出定时器卸载兜底防「假登录态」） |
| web-admin/src/components/DashboardCharts.vue | P3[D4] 主题/语言切换整表重拉；其余 Clean（tooltip 全转义、resize/dispose 清理、in-flight 复用） |
| web-admin/src/components/DashboardWelcome.vue | Clean（时钟暂停于隐藏页、卸载清理） |
| web-admin/src/components/DeviceMaintenanceDialog.vue | Clean（重入锁先于 await；校验口径与后端一致） |
| web-admin/src/components/DeviceReminderDialog.vue | Clean（partial/skipped/truncated 降级信号显式） |
| web-admin/src/components/ExitOverlay.vue | Clean（Teleport 避开 inert 子树；reduced-motion 分级降级） |
| web-admin/src/components/GlassSegmented.vue | Clean（roving tabindex；RO/resize 清理互斥正确） |
| web-admin/src/components/GlassSkeleton.vue | Clean（aria-label 随语言响应式） |
| web-admin/src/components/InspectionCompleteForm.vue | P2[D3] photo 格式仅前端校验（后端只限长度）；其余 Clean（打开侧复位、设备列表 partial/failed 显式、竞态门票） |
| web-admin/src/components/InspectionForm.vue | Clean（远程搜索双门票；__uid 剥离不入后端契约；Safari 日期手工解析） |
| web-admin/src/components/InspectionReviewForm.vue | Clean（换记录复用实例的打开侧复位 + 门票） |
| web-admin/src/components/LiquidGlassButtons.vue | Clean |
| web-admin/src/components/MfaSettingsCard.vue | Clean（密钥/恢复码内存态最小暴露 + 卸载擦除；busy 同步锁四端点） |
| web-admin/src/components/MyLogsCard.vue | Clean（竞态门票 + 双保险禁用） |
| web-admin/src/components/PasswordStrengthMeter.vue | Clean（与后端准入线同源判据） |
| web-admin/src/components/PermissionModuleCard.vue | Clean（纯渲染层；无 role:assign 时入口禁用但可见） |
| web-admin/src/components/ReauthDialog.vue | Clean（密码/MFA 显式切换；加密 fail-closed） |
| web-admin/src/components/RecentAlarmsCard.vue | Clean（失败/陈旧数据显式区分） |
| web-admin/src/components/RegisterSummary.vue | Clean |
| web-admin/src/components/ReportDialog.vue | Clean（远程搜索 seq 防串台 + 防抖省审计；失败重试出口） |
| web-admin/src/components/RoleFormDialog.vue | Clean（内置角色名称锁与后端同口径；重入锁同步置位） |
| web-admin/src/components/RoleListPanel.vue | Clean（删除/编辑按钮权限 prop 门控，装饰性，后端裁决） |
| web-admin/src/components/ScrambleText.vue | Clean（卸载清 interval） |
| web-admin/src/components/SearchPalette.vue | Clean（焦点圈闭/归还；高亮用插值非 v-html；全局热键清理） |
| web-admin/src/components/SecurityInfoCard.vue | Clean |
| web-admin/src/components/SecurityStatsCard.vue | P3[D3] 挂载即请求、门控全靠父视图（后端须复核）；其余 Clean（schema 校验 + 门票） |
| web-admin/src/components/SessionManager.vue | P3[D1] load() 缺竞态门票；其余 Clean（失败保留旧数据并标注） |
| web-admin/src/components/UpdateNoticeBar.vue | Clean（dismiss 刻意不持久化的理由成立） |
| web-admin/src/components/UpgradeDialog.vue | Clean（digest 钉扎正则；stateEpoch+pollToken+AbortController 三重防错序；409 领养；提交窗口禁关闭） |
| web-admin/src/components/UserAvatar.vue | Clean |
| web-admin/src/composables/useCountUp.js | Clean（raf 逐项清理 + 截断回收） |
| web-admin/src/composables/useLatestRequest.js | Clean |
| web-admin/src/composables/useListLoadState.js | Clean（failed≠empty 契约明确） |
| web-admin/src/composables/usePermission.js | Clean |
| web-admin/src/composables/usePermissionSync.js | Clean（schema 校验、引用计数精确归还） |
| web-admin/src/composables/usePointerGradient.js | Clean |
| web-admin/src/composables/usePullToRefresh.js | Clean（多指/取消路径处理完备） |
| web-admin/src/composables/useRealtimeRefresh.js | Clean |
| web-admin/src/composables/useRolePermissions.js | Clean（搜索态分子分母同口径修复有实测注释） |
| web-admin/src/composables/useStepTransition.js | Clean |

## W01 — web-admin：constants / i18n / router / store / schemas / tests 前（56 文件）

## Per-file appendix

| 文件 | 结论 |
|------|------|
| web-admin/src/constants/attackAlerts.js | Clean — 前端镜像码表，注释声明由 attackAlertsDictionaryParity.test.js 对账后端 |
| web-admin/src/constants/metricsAlertTypes.js | Clean — 告警类型码清单，coverage test 对账 |
| web-admin/src/data/ipLocationDictionary.json | P3-5 — 3 处英文译名错误（Columbia/Gurugon/北江省→Bac Ninh），其余 ~1000 条正常 |
| web-admin/src/directives/segGlass.js | Clean — MutationObserver/ResizeObserver 守卫齐全，unmounted 完整清理 |
| web-admin/src/i18n/auditReasons.js | Clean — 28 条展示期翻译规则，未命中原样返回（不改证据） |
| web-admin/src/i18n/auditRiskFactors.js | Clean — 注册表 + 码族前缀 + 自由文本规则，未知码原样露出 |
| web-admin/src/i18n/index.js | P3-1 相关 — 自研编译器正确；locale 仅存 sessionStorage |
| web-admin/src/i18n/locales/attackAlerts.en-US.js | Clean — 与 zh 78/78 键对齐、占位符一致 |
| web-admin/src/i18n/locales/attackAlerts.zh-CN.js | Clean — 同上 |
| web-admin/src/i18n/locales/attackProfile.en-US.js | Clean — 与 zh 163/163 键对齐、占位符一致 |
| web-admin/src/i18n/locales/attackProfile.zh-CN.js | Clean — 同上 |
| web-admin/src/i18n/locales/en-US.js | Clean — 2006 键，与 zh-CN 全量对齐，占位符/空值零差异 |
| web-admin/src/i18n/locales/stuffingProfile.en-US.js | Clean — 与 zh 40/40 键对齐 |
| web-admin/src/i18n/locales/stuffingProfile.zh-CN.js | Clean — 同上 |
| web-admin/src/i18n/locales/zh-CN.js | Clean — 2006 键，与 en-US 全量对齐 |
| web-admin/src/i18n/systemLabels.js | Clean — 英文侧映射、中文侧保留后端原文，locale 渲染期求值 |
| web-admin/src/layout/index.vue | P3-2 — 切语言三处重复写入；其余（inert 退出遮罩、logout 401/403 语义、定时器清理、a11y）均正确 |
| web-admin/src/main.js | Clean — 错误处理先于挂载、PWA 仅 PROD 装配、DEV SW 清理有守卫 |
| web-admin/src/router/index.js | P3-4 — 深链登录后不回传目标路径；守卫/重定向/权限逻辑本身无缺陷 |
| web-admin/src/schemas/index.js | Clean — zod 契约校验与 toPermissionCodes 归一化设计良好 |
| web-admin/src/store/app.js | P3-1/P3-6 相关 — 语言存 sessionStorage、setThemeMode 无白名单；主题监听器重入清理正确 |
| web-admin/src/store/auth.js | P3-3 — restoreSession 网络失败对缓存身份 fail-open（文档化的可接受权衡）；其余实现严谨 |
| web-admin/src/store/index.js | Clean — barrel 重导出 |
| web-admin/src/store/storage.js | Clean — safeStorage/safeLocal 容错封装与 localStorage 迁移逻辑正确 |
| web-admin/src/tests/app.test.js | Clean — 断言 el-config-provider 实际收到的 locale，反证包差异 |
| web-admin/src/tests/bundling/devProxyForwardedFor.test.js | Clean — XFF 透传契约三代理块一致 |
| web-admin/src/tests/bundling/manualChunks.test.js | Clean — 直接 import 真实 vite.config 的 manualChunks 验证分隔符无关匹配 |
| web-admin/src/tests/bundling/subpathDeployConfig.test.js | Clean — 子路径/PWA/监听面/CSP/版本探测接线契约 |
| web-admin/src/tests/ci/tautologyGuard.test.js | Clean — 恒真断言/skip/only 静态闸，检测器自带正反样本 |
| web-admin/src/tests/components/attackEvidenceTable.test.js | Clean — 空态/行渲染/异形证据 |
| web-admin/src/tests/components/attackProfileResult.test.js | Clean — verdict/containment 分支两侧 |
| web-admin/src/tests/components/authPrefs.test.js | Clean — 主题三态与语言四处一致性 |
| web-admin/src/tests/components/changePasswordCard.test.js | P3-7 — 真实 1700ms 休眠×2；断言本身有效（密文双轨/重入/卸载清理） |
| web-admin/src/tests/components/dashboardCharts.test.js | Clean — tooltip XSS 转义端到端、数据接线、失败/空态区分、生命周期 |
| web-admin/src/tests/components/dashboardWelcome.test.js | Clean — 问候时段边界、时钟、清理 |
| web-admin/src/tests/components/deviceMaintenanceDialog.test.js | Clean — 前置锁/validate 失败/成功失败路径 |
| web-admin/src/tests/components/deviceReminderDialog.test.js | Clean — 降级/截断/空态/失败重试 |
| web-admin/src/tests/components/exitOverlay.test.js | Clean — Teleport 到 body 直下（inert 子树外）等核心断言 |
| web-admin/src/tests/components/glassSegmented.test.js | Clean — 事件契约/键盘/滑块/观察者生命周期 |
| web-admin/src/tests/components/glassSkeleton.test.js | Clean — 5 变体结构 + i18n 跟随 |
| web-admin/src/tests/components/inspectionCompleteForm.test.js | Clean — 载荷契约、缺数据可见化 |
| web-admin/src/tests/components/inspectionForm.test.js | Clean — 时区回填、重入锁、逐行校验、增删 |
| web-admin/src/tests/components/inspectionFormCrossRecordReset.test.js | Clean — 跨记录残留 + 过期响应门票 |
| web-admin/src/tests/components/inspectionFormSearchResidue.test.js | Clean — 远程搜索候选不跨记录残留 |
| web-admin/src/tests/components/inspectionReviewForm.test.js | Clean — 嵌套 populate 形状、本地时区、abort 静默 |
| web-admin/src/tests/components/liquidGlassButtons.test.js | Clean — press 回传自身 id |
| web-admin/src/tests/components/mfaSettingsCard.test.js | Clean — 1263 行覆盖状态互斥/注册/启用/关闭/恢复码/复制降级/重入/防误关 |
| web-admin/src/tests/components/passwordStrengthMeter.test.js | Clean — 五规则逐条、分档边界、双语 |
| web-admin/src/tests/components/permissionModuleCard.test.js | Clean — 纯渲染层契约 + 三处已修复缺陷的回归钉 |
| web-admin/src/tests/components/reauthDialog.test.js | Clean — 加密失败阻断、MFA 6 位门禁、模式切换清空 |
| web-admin/src/tests/components/recentAlarmsCard.test.js | Clean — 表格映射/标签类型/跳转 |
| web-admin/src/tests/components/registerSummary.test.js | Clean — 空值三形态与字符串 "0"/"false" 不误判 |
| web-admin/src/tests/components/reportDialog.test.js | Clean — 界面无 ObjectId、system 不带 targetId、trim 判空、重入 |
| web-admin/src/tests/components/roleFormDialog.test.js | Clean — 编码归一、重入防护、编辑/内置角色门控 |
| web-admin/src/tests/components/roleListPanel.test.js | Clean — 骨架条件、门控四象限、stopPropagation、_id 高亮 |
| web-admin/src/tests/components/scrambleText.test.js | Clean — 扰码动画、卸载清定时器、reduced-motion |

## W02 — web-admin 测试：components / composables / i18n / router / store / styles（50 文件）

## Per-file appendix（50 项；"守护"指该测试实际钉住的生产文件）

| # | 文件（web-admin/src/tests/） | 结论 | 守护的生产文件 |
|---|---|---|---|
| 1 | components/searchPalette.test.js | Clean | components/SearchPalette.vue；store/app（主题/语言动作） |
| 2 | components/securitySelfCards.test.js | Clean | components/SecurityInfoCard.vue、AccountBindingsCard.vue、MyLogsCard.vue；views/ProfileView.vue（接线）；utils/api（security 自助端点封装） |
| 3 | components/securityStatsCard.test.js | Clean | components/SecurityStatsCard.vue（含 schema-drift 形状防护） |
| 4 | components/sessionManager.test.js | P3（保留的源码文本断言，有变异依据） | components/SessionManager.vue；views/ProfileView.vue；utils/api.js（会话端点/schema 顺序）；schemas（SessionItem/SessionListResponse）；i18n session/audit 命名空间 |
| 5 | components/updateNoticeBar.test.js | Clean | components/UpdateNoticeBar.vue |
| 6 | components/upgradeDialog.test.js | P2（triggerUpgrade 失败路径未测 [D5]）；P3（固定 flush 断言） | components/UpgradeDialog.vue；utils/loginCipher（fail-closed 契约） |
| 7 | composables/useCountUp.test.js | Clean | composables/useCountUp.js |
| 8 | composables/useLatestRequest.test.js | Clean | composables/useLatestRequest.js |
| 9 | composables/useListLoadState.test.js | Clean | composables/useListLoadState.js（三态契约，6 个列表视图共用判据） |
| 10 | composables/usePermission.test.js | Clean | composables/usePermission.js；store/auth（权限单源） |
| 11 | composables/usePermissionSync.test.js | Clean | composables/usePermissionSync.js（载荷校验/去噪/连接生命周期/引用计数） |
| 12 | composables/usePointerGradient.test.js | Clean | composables/usePointerGradient.js |
| 13 | composables/usePullToRefresh.test.js | P3（异步 reject 路径未测 [D5]） | composables/usePullToRefresh.js |
| 14 | composables/useRolePermissionsToggle.test.js | Clean | composables/useRolePermissions.js |
| 15 | composables/useStepTransition.test.js | Clean | composables/useStepTransition.js |
| 16 | directives/segGlass.test.js | Clean | directives/segGlass.js |
| 17 | directives/segGlassIntegration.test.js | P3（缺 afterEach 兜底卸载） | directives/segGlass.js × element-plus radio 的 `.is-active` 上游契约 |
| 18 | helpers/componentHarness.js | Clean（基座） | 服务于全部组件/视图测试（非生产代码测试） |
| 19 | i18n/attackAlertsDictionaryParity.test.js | Clean | i18n/locales/attackAlerts.zh-CN/en-US、constants/attackAlerts ↔ 后端 src/constants/attackEvents.js |
| 20 | i18n/attackProfileDictionaryParity.test.js | Clean | i18n/locales/attackProfile.* ↔ 后端 src/constants/attackProfile.js |
| 21 | i18n/auditActionCoverage.test.js | Clean | i18n/locales audit.action ↔ 后端 src/constants/audit.js（AUDIT_LOG_ACTIONS） |
| 22 | i18n/auditReasons.test.js | Clean | i18n/auditReasons.js；views/AuditLogView.vue（翻译接线） |
| 23 | i18n/auditRiskFactors.test.js | Clean | i18n/auditRiskFactors.js |
| 24 | i18n/enumLabelCoverage.test.js | Clean | views/InspectionView.vue、components/InspectionForm.vue、views/AlarmView.vue、views/PrivilegeGrantView.vue、utils/labelMaps.js ↔ 后端 constants/{alarm,inspection,privilegeGrant}.js |
| 25 | i18n/errorCodesI18n.test.js | Clean | i18n/locales errors.* ↔ 后端 src/utils/errorCodes.js |
| 26 | i18n/i18nEntry.test.js | Clean | i18n/index.js（defaultLocale 推导/setLocale/html lang/sessionStorage 容错） |
| 27 | i18n/localeKeyParity.test.js | Clean | i18n/locales/zh-CN.js、en-US.js（双语叶子键集对齐） |
| 28 | i18n/messageCompiler.test.js | Clean | i18n 入口的消息编译器（前导 $ 排除）+ errors 词表参数对齐 |
| 29 | i18n/metricsAlertTypesCoverage.test.js | Clean | constants/metricsAlertTypes.js、locales about.metrics.alertTypes ↔ 后端 services/alertTypes.js、constants/failOpenSites.js |
| 30 | i18n/rawKeys.test.js | Clean | 全 src 源码（中文裸键清零门禁）+ i18n/locales |
| 31 | i18n/stuffingProfileDictionaryParity.test.js | Clean | i18n/locales/stuffingProfile.* ↔ 后端 src/constants/credentialShape.js |
| 32 | i18n/validationMessagesFollowLocale.test.js | P3（260ms 固定等待） | views/UserView.vue、RegisterView.vue、ProfileView.vue、components/RoleFormDialog.vue、InspectionReviewForm.vue（校验文案随 locale 响应式） |
| 33 | layout/layout.test.js | Clean | layout/index.vue（菜单权限过滤/抽屉/主题/登出/面包屑/fullPath key/权限热同步接线） |
| 34 | router/componentFileCase.test.js | Clean | router/index.js 懒加载路径 ↔ 磁盘真实大小写（NTFS/Linux 构建差异） |
| 35 | router/loginRedirectBase.test.js | Clean | utils/api.js、components/ChangePasswordCard.vue、layout/index.vue、views/RegisterView.vue 的 /login 跳转方式 |
| 36 | router/routeGuard.test.js | P3（mustChangePassword 仅测 /register [D5]） | router/index.js（beforeEach 决策表/onError chunk 恢复/scrollBehavior/标题） |
| 37 | router/routeTable.test.js | Clean | router/index.js 路由表声明（懒加载可解析/titleKey/permission 形状/重名/scrollBehavior） |
| 38 | store/appStore.test.js | Clean | store/app.js（主题三态/持久化/DOM 应用） |
| 39 | store/appStoreThemeListener.test.js | Clean | store/app.js initTheme（监听器重入保护/legacy 降级） |
| 40 | store/authPersistenceNoPii.test.js | P3（stub location 未还原） | store/auth.js（toPersistedUser 白名单投影，PII 不落盘） |
| 41 | store/authStore.test.js | Clean | store/auth.js（normalizeUser/setAuth/restoreSession 两步探测/负缓存/跨标签页同步） |
| 42 | store/permissionSync.test.js | Clean | schemas/index.js（User/PermissionList/AuthMe/SessionStatus/PermissionUpdateEvent/ApiEnvelope）+ store/auth.js 热同步 |
| 43 | store/schemasExtras.test.js | Clean | schemas/index.js（formatIssues 根路径、LoginResponseSchema） |
| 44 | store/storage.test.js | Clean | store/storage.js（safeStorage/safeLocal/readSessionState 降级与迁移） |
| 45 | store/storeBarrel.test.js | Clean | store/index.js（导出集合与引用相等契约） |
| 46 | styles/printStyles.test.js | P2（@media print 包裹性闸门贪婪正则） | assets/styles/print.css + main.js 引入顺序 |
| 47 | styles/tooltipTheme.test.js | Clean | assets/styles/apple-refine.css、dark.css（EP 浮层/箭头同色与外壳透明化） |
| 48 | utils/apiDriftLru.test.js | Clean | utils/api.js（schema 漂移去重 LRU 上限） |
| 49 | utils/apiRefreshRaceRecovery.test.js | Clean | utils/api.js（刷新失败判定：仅明确拒绝才登出；503 静默恢复/重放） |
| 50 | utils/apiRemainingBranches.test.js | Clean | utils/api.js（resolveErrorMessage 原型链键防护、响应 config 缺失守卫） |

## 结论

- 计数：**P0=0，P1=0，P2=2，P3=6**（另有 3 处 [D5] 测试缺口并入上述条目）。
- 全部 50 个清单文件（含基座 helper）已 100% 逐行读完，无跳读。
- 未发现 skip/only/空测试/恒真断言；异步等待、隔离与夹具清理总体规范；两处 P2 均为"闸门/覆盖缺口"而非错误断言。

## W03 — web-admin 测试：utils + views 前（53 文件）

## Per-file appendix（53 个文件；「守护的生产文件」以 import/mocked 路径与断言对象为准）

| # | 测试文件 | 结论 | 守护的生产文件 |
| --- | --- | --- | --- |
| 1 | utils/apiRequestPipeline.test.js | Clean（P3#4 涉及 L1219-1220 正则） | src/utils/api.js（请求管线/401 刷新/取消表/形状校验/方法表契约），联动 router/store/i18n |
| 2 | utils/apiStatusCodes.test.js | **P2#1（refresh 监视器瞄错对象）** | src/utils/api.js（状态码归一）+ src/utils/errorCodes.js（后端码表对账） |
| 3 | utils/apiUpgradePollingSupport.test.js | Clean（P3#3 涉及 L202 sleep） | src/utils/api.js（signal 转发/silentErrors/升级端点） |
| 4 | utils/attackProfileReport.test.js | Clean | src/utils/attackProfileReport.js + i18n/locales/attackProfile.{zh-CN,en-US}.js |
| 5 | utils/auditTrace.test.js | Clean | src/utils/auditTrace.js |
| 6 | utils/avatarImage.test.js | Clean | src/utils/avatarImage.js |
| 7 | utils/datetime.test.js | Clean（P3#5 涉及 L79 恒真断言） | src/utils/datetime.js |
| 8 | utils/degradationReporting.test.js | Clean | src/utils/errorReporter.js（reportDegradation）+ src/utils/loginCipher.js + src/utils/websocket.js + src/composables/usePermissionSync.js + vite.config.js（降级接线） |
| 9 | utils/deviceStatusParity.test.js | Clean | 后端 src/constants/deviceStatus.js ↔ 前端 i18n/locales/{zh-CN,en-US}.js、src/views/DeviceView.vue、src/views/ReportView.vue |
| 10 | utils/enterSubmit.test.js | Clean | src/utils/enterSubmit.js |
| 11 | utils/errorCodeI18n.test.js | Clean（P3#6） | src/utils/api.js（ERROR_CODE_I18N_MAP/resolveErrorMessage）+ 两份 locale + axios 行为前提 |
| 12 | utils/errorReporter.test.js | Clean | src/utils/errorReporter.js（三路收集/环形缓冲/redactUrl/字段收口） |
| 13 | utils/errorReporterBufferEdges.test.js | Clean | src/utils/errorReporter.js（上限/截断/扇出/安全摘要，H-1 变异补强） |
| 14 | utils/errorReporterFlushLock.test.js | Clean | src/utils/errorReporter.js（flush 并发锁，P3-67） |
| 15 | utils/errorReporterLifecycle.test.js | Clean | src/utils/errorReporter.js（7 天过期/体积预算，F-03） |
| 16 | utils/errorReporterRedactionShapes.test.js | Clean | src/utils/errorReporter.js（字符串内嵌/URL 键/递归脱敏，F1/F2/F4/F5） |
| 17 | utils/errorReporterSentry.test.js | Clean | src/utils/errorReporter.js（Sentry 可选扇出，G-1 余） |
| 18 | utils/errorReporterStackPreserve.test.js | Clean | src/utils/errorReporter.js（Sentry 原始 stack 透传，P3-68） |
| 19 | utils/haptic.test.js | Clean | src/utils/haptic.js |
| 20 | utils/idempotency.test.js | Clean | src/utils/idempotency.js（对齐后端 KEY_PATTERN） |
| 21 | utils/ipLocationCodeParity.test.js | Clean | src/utils/ipLocationLabels.js + i18n locales ↔ 后端 src/constants/ipLocationCodes.js |
| 22 | utils/ipLocationDictionary.test.js | Clean | src/data/ipLocationDictionary.json + src/utils/ipLocationLabels.js + 后端 src/utils/ip2regionSearcher.js（真实 xdb 对账） |
| 23 | utils/labelMapsSemantics.test.js | Clean | src/utils/labelMaps.js + src/composables/useRolePermissions.js ↔ 后端 src/utils/constants.js、src/constants/alarm.js |
| 24 | utils/loginCipher.test.js | Clean | src/utils/loginCipher.js（信封往返/缓存/指纹钉扎/AAD 用途绑定） |
| 25 | utils/passwordRule.test.js | Clean | src/utils/password.js（passwordStrengthRule/isStrongPassword） |
| 26 | utils/passwordRulesParity.test.js | Clean | 前端 src/utils/password.js ↔ 后端 src/utils/helpers.js（判据对账 A3） |
| 27 | utils/permission.test.js | Clean | src/utils/permission.js |
| 28 | utils/privacyNoticeParity.test.js | Clean | 前端 src/utils/privacyNotice.js ↔ 后端 src/constants/dataClassification.js、src/services/consentService.js |
| 29 | utils/privilegeGrantPolicyParity.test.js | Clean | 前端 src/utils/privilegeGrant.js ↔ 后端 src/constants/privilegeGrant.js、src/utils/superAdmin.js |
| 30 | utils/reauthTicket.test.js | Clean | src/utils/reauthTicket.js |
| 31 | utils/routePrefetch.test.js | Clean | src/utils/routePrefetch.js + src/router/index.js（键对账 + import 字面量对账） |
| 32 | utils/securityLabels.test.js | Clean | src/utils/securityLabels.js |
| 33 | utils/securitySuggestionParity.test.js | Clean | src/utils/securityLabels.js + i18n locales ↔ 后端 src/constants/securitySuggestions.js |
| 34 | utils/sessionDeath401.test.js | Clean | src/utils/api.js（重试后仍 401 的可观测登出） |
| 35 | utils/sessionSyncChannel.test.js | Clean | src/utils/sessionSync.js（通道层全量，§13 V-5） |
| 36 | utils/storageHygiene.test.js | Clean | 全 src 树不变量（禁凭据写 localStorage/sessionStorage，WB-2，扫描器自证） |
| 37 | utils/systemLabels.test.js | Clean | src/i18n/systemLabels.js |
| 38 | utils/updateNotice.test.js | Clean | src/utils/updateNotice.js |
| 39 | utils/versionWatcher.test.js | Clean | src/utils/versionWatcher.js |
| 40 | utils/webVitals.test.js | **P3#2（共享 metrics + 顺序耦合）** | src/utils/webVitals.js |
| 41 | utils/webVitalsBranches.test.js | Clean | src/utils/webVitals.js（W3/W4/W6/W7/W9/W10 分支，H-1） |
| 42 | utils/webVitalsP75.test.js | Clean | src/utils/webVitals.js（INP=P75，P3-69） |
| 43 | utils/websocket.test.js | Clean | src/utils/websocket.js（状态机/房间/引用计数/降级，P1-27、P2-6、P2-7、V-2） |
| 44 | views/aboutVersion.test.js | Clean | src/views/AboutView.vue（__APP_VERSION__ 单一来源）+ vite.config.js + package.json |
| 45 | views/aboutView.test.js | Clean | src/views/AboutView.vue（样式类/i18n 词条）+ src/assets/styles/view-refine.css |
| 46 | views/aboutViewMetrics.test.js | Clean | src/views/AboutView.vue（指标卡行为：权限门控/快照归一化/失败语义/轮询节律） |
| 47 | views/aboutViewUpgrade.test.js | Clean | src/views/AboutView.vue（版本概况+一键升级全链路）+ scripts/hotUpgrade.js（步骤词表对账 WF-11）+ i18n locales |
| 48 | views/alarmView.test.js | Clean | src/views/AlarmView.vue（列表口径/筛选分页/行级动作/上报对话框/实时推送/权限门控） |
| 49 | views/attackAlertsView.test.js | Clean | src/views/AttackAlertsView.vue（分类分段/筛选/角标/失败三态/二次验证/深链） |
| 50 | views/attackProfileView.test.js | Clean | src/views/AttackProfileView.vue（查询主路径/取证钻取/二次验证/一键报告） |
| 51 | views/auditLogExportJsonError.test.js | Clean | src/views/AuditLogView.vue（exportLogs/extractBlobErrorMessage，P2-56） |
| 52 | views/auditLogView.test.js | Clean（P3#8 涉及 L1338-1341） | src/views/AuditLogView.vue（列表/筛选/竞态/导出/详情/告警面板/二次验证/合规监控读数） |
| 53 | views/canceledErrorGuards.test.js | Clean | src/utils/api.js（isCanceledError）+ 全视图 catch 守卫扫描（P1-16） |

### 缺口说明（[D] 标记含义）

- 带 [D] 的条目为测试缺口/质量问题（非生产代码缺陷）。本轮未发现「被 skip 的测试」「空测试」「恒真主断言」；唯一的恒真断言是 datetime.test.js:79 的辅助行（P3#5），唯一失效断言是 apiStatusCodes.test.js 的 refresh 监视器（P2#1）。
- websocket.test.js 文件头如实声明了三块未覆盖面（心跳、真实重连时序、防御性 catch 分支）并给出不可测理由，属诚实边界而非缺口。

## W04 — web-admin：views / utils / views 测试后 + vite.config（66 文件）

## Per-file appendix

| 文件 | 结论 |
| --- | --- |
| web-admin/src/tests/views/dashboardView.test.js | P3：两条竞态用例用真实 1s sleep（:356/:381）；其余断言独立计算期望值、清理完备 |
| web-admin/src/tests/views/deviceView.test.js | Clean（覆盖门控/重入/竞态/清理/i18n，质量高） |
| web-admin/src/tests/views/forensicTraceView.test.js | Clean（含 i18n 键存在性闸与「判据有牙」反证） |
| web-admin/src/tests/views/inspectionView.test.js | Clean |
| web-admin/src/tests/views/ipListView.test.js | P3：mock `isHandledApiError:()=>false` 使 (d) 删除救援文案用例与生产接线不符 |
| web-admin/src/tests/views/loginView.test.js | Clean（:83 注释 stale：仍写「required + min 6」，现行规则为 required-only） |
| web-admin/src/tests/views/privilegeGrantView.test.js | Clean |
| web-admin/src/tests/views/profileView.test.js | Clean |
| web-admin/src/tests/views/profileViewLateMeKeepsEdits.test.js | Clean |
| web-admin/src/tests/views/registerView.test.js | Clean |
| web-admin/src/tests/views/registerViewRender.test.js | Clean |
| web-admin/src/tests/views/reportView.test.js | Clean |
| web-admin/src/tests/views/reportViewCharts.test.js | Clean |
| web-admin/src/tests/views/roleView.test.js | Clean |
| web-admin/src/tests/views/roleViewPermission.test.js | Clean（静态架构闸，文件头已论证为何必须静态断言） |
| web-admin/src/tests/views/securityAnalysisView.test.js | Clean |
| web-admin/src/tests/views/stuffingProfileView.test.js | Clean |
| web-admin/src/tests/views/userView.test.js | Clean（未覆盖 submitForm/分配角色双击，见 P2） |
| web-admin/src/utils/api.js | P3：caller-signal 监听不移除（:563-571）；刷新竞态/取消语义/码化错误/schema-drift LRU 实现正确 |
| web-admin/src/utils/attackProfileReport.js | P3：cell() 不中和 Markdown 语法 |
| web-admin/src/utils/auditLabels.js | Clean |
| web-admin/src/utils/auditTrace.js | Clean |
| web-admin/src/utils/avatarImage.js | Clean（objectURL 均回收） |
| web-admin/src/utils/datetime.js | Clean |
| web-admin/src/utils/encryptionError.js | Clean |
| web-admin/src/utils/enterSubmit.js | Clean |
| web-admin/src/utils/errorReporter.js | Clean（脱敏/保留期/体积预算/并发锁完备；record 依赖全局 location，仅浏览器上下文可用） |
| web-admin/src/utils/forensicLabels.js | Clean |
| web-admin/src/utils/haptic.js | Clean |
| web-admin/src/utils/idempotency.js | Clean |
| web-admin/src/utils/ipLocationLabels.js | Clean |
| web-admin/src/utils/labelMaps.js | Clean |
| web-admin/src/utils/loginCipher.js | Clean（ECDH+HKDF+AES-GCM、AAD 用途绑定、公钥指纹钉扎、失败关闭） |
| web-admin/src/utils/motion.js | Clean |
| web-admin/src/utils/password.js | Clean |
| web-admin/src/utils/permission.js | Clean（fail-closed） |
| web-admin/src/utils/privacyNotice.js | Clean |
| web-admin/src/utils/privilegeGrant.js | Clean |
| web-admin/src/utils/reauthTicket.js | Clean |
| web-admin/src/utils/routePrefetch.js | Clean |
| web-admin/src/utils/securityLabels.js | Clean |
| web-admin/src/utils/sessionSync.js | Clean（镜像键用后即清，边界自述清楚） |
| web-admin/src/utils/updateNotice.js | Clean |
| web-admin/src/utils/versionWatcher.js | Clean（generation/abort/超时/隐藏暂停齐备） |
| web-admin/src/utils/webVitals.js | P3：INP durations 无上限累积 |
| web-admin/src/utils/websocket.js | Clean（引用计数/重连耗尽上报/房间显式撤销齐备） |
| web-admin/src/views/AboutView.vue | P3：loadMetrics 无竞态守卫 |
| web-admin/src/views/AlarmView.vue | Clean |
| web-admin/src/views/AttackAlertsView.vue | P3：readReauthErrorCode 等与另三视图重复 |
| web-admin/src/views/AttackProfileView.vue | P3：copyReport 无非安全上下文兜底；reauth helper 重复 |
| web-admin/src/views/AuditLogView.vue | P3：God component（2001 行）；exportLogs 绕过 api.reports.export；reauth helper 重复 |
| web-admin/src/views/DashboardView.vue | P3：visibilityState 判据未统一到 isPageHidden |
| web-admin/src/views/DeviceView.vue | P2：submitForm（:667）缺同步重入锁；其余 Clean |
| web-admin/src/views/ForensicTraceView.vue | Clean（两步封禁/深链校验/竞态守卫齐备） |
| web-admin/src/views/InspectionView.vue | P2：handleStart（:452）/handleDelete（:483）缺同步重入锁（handleCancel 已有） |
| web-admin/src/views/IpListView.vue | P3：FULL_RANGE_FORBIDDEN 分支生产不可达（:666-679）；IPv6 预检过松（:318-337） |
| web-admin/src/views/LoginView.vue | Clean |
| web-admin/src/views/PrivilegeGrantView.vue | P3：God component（2997 行，样式过半）；逻辑 Clean |
| web-admin/src/views/ProfileView.vue | P2：save()（:407）缺同步重入锁；脏标记/头像 epoch 设计正确 |
| web-admin/src/views/RegisterView.vue | P3：resetForm（:768-774）未判空 formRef；其余 Clean |
| web-admin/src/views/ReportView.vue | P3：导出凭据成功后不清空（:543-577） |
| web-admin/src/views/RoleView.vue | P2：handleDelete（:418）缺同步重入锁；两面失败判据/WS 清理 Clean |
| web-admin/src/views/SecurityAnalysisView.vue | Clean |
| web-admin/src/views/StuffingProfileView.vue | Clean |
| web-admin/src/views/UserView.vue | P2：submitForm/submitRoleAssignment/handleDelete/handleResetPassword/handleResetMfa 缺同步重入锁；揭示流程（epoch 守卫）Clean |
| web-admin/vite.config.js | Clean（安全响应头/敏感文件拦截/HMR 加固/进程守卫/HTTPS 失败关闭齐备） |

## SC00 — scripts 前 46 个

## Per-file appendix

| 文件 | 结论 |
| --- | --- |
| scripts/access-review.js | Clean（默认只读；--review 需 --reviewer；退出码 0/1/2 分层） |
| scripts/alert-delivery-probe.js | P3[D3]：target URL 原样落盘（可能含 webhook token）；其余 Clean |
| scripts/alertProbeRecord.js | Clean（纯判据，三档/五态，探针能力边界如实声明） |
| scripts/alertRulesPolicy.js | P3[D1]：DURATION_RE 不认子查询 `[5m:1m]`（当前规则未用，潜伏误报）；其余 Clean |
| scripts/alertmanager-config-path.js | Clean（路径解析单一口径，读失败与空文件区分） |
| scripts/audit-chain-checkpoint.js | Clean（fail-closed 外锚、INCONCLUSIVE=2、degraded=3、URI 走 env） |
| scripts/audit-probes/README.md | Clean（文档；与 ws-session-bypass.cjs 一致） |
| scripts/audit-probes/ws-session-bypass.cjs | Clean（一次性密钥隔离、内存库、退出码即结论、require.main 守卫） |
| scripts/auditCountAssertionScan.js | Clean（静态扫描器，无 IO 副作用，CRLF/注释剥离处理严谨） |
| scripts/backup-integrity-patrol.js | Clean（编排层，判据/IO 分离；默认 `backups` 相对 cwd 与 backup-mongo 同为 P3 级口径问题，见 backup-mongo 条目） |
| scripts/backup-mongo.sh | P3[D1]：BACKUP_DIR 默认按 cwd；其余 Clean（凭据 0600 配置文件、trap 清理、非空/加密/校验和/异地判据完备） |
| scripts/backupArtifactScan.js | Clean（IO 适配层，错误折成 null 交判据） |
| scripts/backupCrypto.sh | Clean（gpg 默认加密、明文出口显式确认词、与 restore 共用实现） |
| scripts/backupIntegrityPolicy.js | Clean（纯判据，sidecar 契约与 restore 同源） |
| scripts/build-offline-bundle.sh | Clean（digest 从 docker 实际结果取回、签名回验、拒绝覆盖、清理钩子幂等） |
| scripts/bundleBudgetPolicy.js | Clean（纯函数，参数解析严格） |
| scripts/capture-image-digests.sh | P3[D7]：注释中门禁判据版本号过期（22.14.0→实际 26.12.0）；逻辑本身 Clean（多轮加固，CRLF/工具退化均 fail-closed） |
| scripts/check-alertmanager-config.js | Clean（compose 校验容器，判据同源，误配不豁免） |
| scripts/check-audit-allowlist.js | Clean（fail-closed 三判据 + 报告自洽校验，防"汇总/明细矛盾"假绿） |
| scripts/check-bundle-budget.js | Clean（首屏单列计量、路径越界防护、基线损坏拒绝静默重写） |
| scripts/check-changelog-structure.js | Clean（纯判据 + fail-closed 读失败） |
| scripts/check-clock-sync.js | Clean（execFileSync 固定参数、fail-closed exit 2） |
| scripts/check-lockfile-integrity.js | Clean（semantic 哈希锚、缺条目即不一致） |
| scripts/check-openapi-drift.js | Clean（纯判据 + require.main 守卫） |
| scripts/check-prod-install-scripts.js | Clean（版本+integrity 钉扎登记，生产/dev 两档） |
| scripts/check-utf8.js | Clean（扫描面缩水/悬空条目 fail-closed，生成物前缀跳过） |
| scripts/cliFlagPolicy.js | Clean（白名单解析 + 编辑距离建议） |
| scripts/commentDensity.baseline.json | Clean（纯数据账本，无敏感值） |
| scripts/commentDensity.js | Clean（棘轮判据严谨：损坏/空账本/残留均 fail-closed；ENFORCEMENT=false 如实声明） |
| scripts/compliance-alerting.js | Clean（零依赖 YAML url 判据，两级闸） |
| scripts/compliance-check.js | Clean（登记表对账、检查器抛错/未交结论均补记失败） |
| scripts/complianceVerdicts.js | Clean（passed/notReady 两档语义清晰） |
| scripts/config-drift-check.js | P3[D2]：require 未声明的传递依赖 js-yaml（仅 istanbul dev 链提供）；判据本身 Clean（只报条目名不报取值） |
| scripts/deploy.js | Clean（fail-closed 前置、先备份后发布、/readyz 门禁、回滚决策显式化） |
| scripts/deployCommands.js | Clean（纯 argv 构造器，密钥/镜像走 env 不进 argv） |
| scripts/deployPolicy.js | Clean（密钥目录必须在 checkout 外、digest 钉闸、RPO/RTO 发布前置、未知参数拒绝） |
| scripts/destructiveGuard.js | Clean（fail-closed 白名单、回退库拒绝、全限定名比对） |
| scripts/devSecretIsolation.js | Clean（FILE+明文两类置空、顺序不变量成文、明文值不打印） |
| scripts/drReadinessPolicy.js | Clean（日期合法性/未来日期 fail-closed） |
| scripts/e2e-smoke.js | Clean（一次性随机密钥、内存库、14 步门禁自证） |
| scripts/fix-token-blacklist-index.js | Clean（护栏先于 connect、只删单键遗留索引、按库读数复核） |
| scripts/generate-dev-cert.sh | Clean（umask 077 + chmod、拒绝覆盖、失败清理、Windows 限界说明） |
| scripts/generate-secrets.js | P3[D5]：CLI 在模块顶层执行、无 require.main 守卫（当前无测试 require，风格不一致）；其余 Clean |
| scripts/hotUpgrade.js | Clean（蓝绿七步、事务式切流回滚、失败现场抓取、observe 下限） |
| scripts/hotUpgradeAgent.js | Clean（锁/心跳/崩溃恢复/pid 复用上限，离线通道失败不上浮 ready） |
| scripts/hotUpgradeJob.js | Clean（验签+TTL+白名单最终判定、固定 invocation、子进程 SIGTERM→SIGKILL 等退出） |

## 覆盖声明

全部 46 个指定文件已用 Read 工具逐行完整读取（含 commentDensity.baseline.json 的 2350 行分两段读全），无抽样跳过。另核对了 package.json、Dockerfile、docker-compose.yml、deployment/observability/alert-rules.yml、src/tests/security/baseImageDigestPinned.test.js 与 package-lock.json 的相关条目，用于一致性交叉验证；未读取 AUDIT-REPORT-2026-11-14.md 或任何历史审计结论。

## SC01 — scripts 后 44 个

## Per-file appendix

| 文件 | 结论 |
| ---- | ---- |
| scripts/hotUpgradePolicy.js | P3：`split('=')` 截断含 `=` 的参数值。其余 Clean（判据纯函数层，镜像 digest 钉扎/白名单 fail-closed/nginx upstream 解析与自检、布尔旗标严格解析均正确） |
| scripts/hotUpgradeQueue.js | Clean（O_NOFOLLOW 单 fd 读、'wx'+随机临时名+rename 前复核的原子写、陈旧锁三重判据、HMAC 密钥只读不回显） |
| scripts/hotUpgradeStatusSink.js | Clean（复用队列原子写，写失败只告警不中断升级） |
| scripts/importOfflineBundle.js | P3：sha256File 按路径打开存在 lstat↔open TOCTOU。其余 Clean（先校验后 load、RepoDigests 复核、验签 fail-closed、argv 数组） |
| scripts/invalidate-mfa-recovery-codes.js | Clean（双确认 + 白名单先于 connect、回读自证） |
| scripts/lint-ratchet.js | Clean（只降不升守卫、零命中守卫、行数地板缺失判回退） |
| scripts/load-test.js | Clean（一次性密钥隔离、内存库、结果落盘失败不静默） |
| scripts/loadTestEngine.js | Clean（纯引擎，无副作用） |
| scripts/login-key-pin.js | P3：main() 无 require.main 守卫。其余 Clean（--require 强制钉扎 fail-closed） |
| scripts/migrate-mfa-secret.js | Clean（密钥只经文件/env、新钥强度闸、写库回读自证、白名单先于 connect） |
| scripts/migrate-pii-encryption.js | Clean（四阶段档位互斥校验、损坏行不覆盖、回读自证、rotate 临时换钥 finally 还原） |
| scripts/mongoUri.sh | P3：`stat -c %s` 为 GNU 专有。其余 Clean（主机段改写判据极其完备，多通道字节计数互证，凭据不回显） |
| scripts/offlineBundleIntake.js | Clean（只解点名条目、两段解包、落点 lstat、权限收紧、复用导入器判据、结果对象不炸代理） |
| scripts/offlineBundleIntakeArchive.js | Clean（消费归档 fail-soft） |
| scripts/offlineBundleIntakeExec.js | Clean（tar argv 数组、成员名排 `--` 后、路径先过 resolveWithinRoot、Windows 路径适配） |
| scripts/offlineBundleIntakePolicy.js | P3：头注释声称的 tar 选项与实现不符；REQUIRED_ENTRIES"四个条目"表述与 3 项实际不符 |
| scripts/offlineBundlePolicy.js | P3：`split('=')` 截断含 `=` 的值。其余 Clean（manifest 逐字段严格校验、路径穿越三形态拒绝） |
| scripts/offlineBundleScan.js | Clean（fail-soft、字段截断、条数封顶） |
| scripts/offlineBundleSignature.js | Clean（Ed25519 类型钉扎、原始字节验签、sig 大小上限、timingSafe 比较） |
| scripts/ops-e2e.js | Clean（空选集拒绝报绿、子进程隔离、临时目录清理） |
| scripts/ops-e2e/journey.js | Clean |
| scripts/ops-e2e/journeys/alert-delivery.js | Clean |
| scripts/ops-e2e/journeys/backup-restore.js | Clean（一次性 AES 密钥 + isolateDisposableSecrets 防宿主密钥覆写） |
| scripts/ops-e2e/journeys/cross-department.js | Clean |
| scripts/ops-e2e/journeys/deploy-rollback.js | Clean（stub 注入，假 webhook 令牌为明显占位值） |
| scripts/ops-e2e/lib.js | Clean（spawn 数组 argv、超时 SIGKILL、错误不抛出由断言消费） |
| scripts/perf/README.md | Clean（口径、退出码契约、基线留档规则齐备） |
| scripts/perf/explain-spotcheck.js | Clean（autoIndex:false 只读承诺、生产库显式放行、EOF/空库不可判定判红） |
| scripts/perf/k6-core-journeys.js | Clean（凭据仅经 env、Cookie 显式回放、深页单独计量） |
| scripts/production-drill.js | Clean（Worker 隔离负相、门禁自证、库级 error 侦测） |
| scripts/provision-mongod.js | P2：缓存命中不复核二进制内容（共享缓存目录可投毒） |
| scripts/record-rollback-drill.js | Clean（默认 dry-run、字段转义防 markdown 注入、manifest 结构校验拒绝空演练） |
| scripts/resign-audit-chain-v3.js | Clean（改写前核验 + 越权须带单号 + append-only 留痕先于改写） |
| scripts/resign-audit-hmac.js | Clean（五格分类区分"未签"与"疑似被改"，suspect 默认拒绝重签） |
| scripts/resignLedger.js | Clean（append-only、末行损坏拒绝登记、fsync） |
| scripts/restore-mongo.sh | P3：依赖 sha256sum 等 GNU 工具（跨平台提示）。其余 Clean（完整性校验先于解密写库、三道恢复门禁、0600 凭据文件按需创建、容器侧 mktemp 防符号链接/并发覆写、0 字节归档拒绝） |
| scripts/revoke-user-sessions.js | P3：--apply 无 --yes 二次确认、未知参数静默忽略（同族口径漂移） |
| scripts/run-rollback-drill.js | Clean（快照 AES-256-GCM fail-closed、白名单+--yes 先于 connect、回灌条数由库回答） |
| scripts/secretFileArg.js | Clean（密钥不进 argv、错误只点名路径） |
| scripts/sync-audit-indexes.js | Clean（同套判据复核残余差异决定退出码、TTL/部分索引不自动处理） |
| scripts/update-ip2region.js | P3：固定 `.tmp` 名跟随符号链接（纵深补强）。其余 Clean（结构+探针+内容锚三重校验、--accept-new-checksum 人工拍板） |
| scripts/verify-audit-chain.js | Clean（不完整/空集合/全 legacy/hashComputeFailed 均不得退 0，豁免开关显式） |
| scripts/verify-audit-export.js | Clean（字节/链摘要/HMAC 三层校验，timingSafeEqual，时钟前跳检测） |
| scripts/verify-image-digests.js | Clean（自算哈希 + 多独立来源一致 + 必须 manifest list；空选集拒绝报绿；响应体不回显） |

## 一致性核对（package.json / workflows）

- `lint:ratchet → scripts/lint-ratchet.js`、`test:ops-e2e → scripts/ops-e2e.js`、`test:prod-drill → scripts/production-drill.js`、`test:load → scripts/load-test.js`、`rotate:mfa-secret → scripts/migrate-mfa-secret.js`、`rotate:audit-hmac → scripts/resign-audit-hmac.js`、`rotate:audit-chain-v3 → scripts/resign-audit-chain-v3.js`、`drill:rollback → scripts/run-rollback-drill.js`：全部与实际文件一致。
- `.github/workflows/ci.yml` 引用 `scripts/provision-mongod.js`、`scripts/login-key-pin.js`；`sast.yml`/`dependabot.yml` 引用 `scripts/verify-image-digests.js` 的期望表口径：一致。
- 被引用的兄弟文件（deployCommands/destructiveGuard/cliFlagPolicy/devSecretIsolation/backupCrypto.sh/backup-mongo.sh/alert-delivery-probe.js/alertProbeRecord.js/hotUpgrade.js/build-offline-bundle.sh/check-audit-allowlist.js）与配置（deployment/mongod-artifacts.json、deployment/ip2region-checksum.json、eslint.ratchet.json）均存在。

## S24 — 部署资产：Dockerfile / compose / nginx / observability / systemd / deployment（34 文件）

## Per-file appendix（34 个目标文件）

| 文件 | 结论 |
| ---- | ---- |
| Dockerfile | Clean — 多阶段、三阶段同 digest 钉扎、非 root（root 仅入口短暂窗口）、HEALTHCHECK 双探针、secret 不入镜像、--ignore-scripts 判据充分；apk 包未钉版本为微小余项 |
| deployment/audit-allowlist.json | Clean — 两条目均 dev-only、reviewBy 2027-02-01 未过期、fail-closed 判据齐备 |
| deployment/backup-encryption.md | P3 — /opt/xf 路径与他文不一致（其余与 backup-mongo.sh/测试口径一致，边界如实） |
| deployment/clock-sync.md | Clean — 与 check-clock-sync.js、chrony 示例一致 |
| deployment/config-drift-baseline.json | Clean — 实测 scripts/config-drift-check.js 比对 88 项 0 漂移 |
| deployment/dependency-sla.json | Clean — 7/30/90/180/365 与 docs/security-dependency-watch.md 表逐格一致 |
| deployment/deploy-workflow-rehearsal.md | P3 — 真实演练待执行（已如实登记） |
| deployment/edge-protection.md | P3 — 取证 awk 配方在多跳 XFF 时字段错位；分工/降级叙事准确 |
| deployment/gateway-pages/gateway-error.html | Clean — 零外部请求、noindex、内联刷新 |
| deployment/hot-upgrade.md | P3 — §4.1 表头重复；HISTORY 50 与 compose 10 不一致；§10 未实测项披露充分 |
| deployment/ip2region-checksum.json | Clean — bytes=11070083、sha256 实测逐字一致 |
| deployment/lockfile-anchor.json | Clean — 两份 lockfile 语义哈希实测一致 |
| deployment/mongod-artifacts.json | Clean — 8.0.34 双锚与 compose mongo 版本一致 |
| deployment/nginx.conf.example | P3 — HSTS preload 无条件下发；代理头逐块重声明、sourcemap 404、443 兜底、限流三档、/readyz 404 均到位 |
| deployment/observability/alert-rules.yml | Clean — 错误率/P95/审计丢弃/WAL/磁盘/就绪/fail-open 等覆盖完整，指标名全部存在 |
| deployment/observability/alertmanager.yml | Clean — 占位符由 check 容器 fail-closed 把守；inhibit 留空论证充分 |
| deployment/observability/grafana/dashboards/provider.yml | Clean |
| deployment/observability/grafana/dashboards/xf-backend.json | Clean — 表达式指标均存在，与告警口径一致 |
| deployment/observability/grafana/datasources/datasource.yml | Clean — proxy 内网、editable:false |
| deployment/observability/prometheus.yml | Clean — bearer_token_file 与 compose metrics_token 同源；两色同抓与 BackendDown 判据配套 |
| deployment/rollback-drill-record.md | P3 — 仅有开发环境专项演练，示例用 :latest 浮动 tag；模板与计时口径清晰 |
| deployment/rollback-drill.md | P2 — 蓝绿颜色/端口/机制与 hot-upgrade.md 冲突 |
| deployment/secret-rotation.md | Clean — HMAC 六重影响面、PII v1 缺口、JWT_SECRETS env-only 缺口均如实登记 |
| deployment/systemd/chrony.conf.example | Clean — 双上游要求明确；allow 网段需按实调整已注明 |
| deployment/systemd/fsms-access-review.service | P2 — DynamicUser 读不到 0600 secrets，生产口径下每轮失败 |
| deployment/systemd/fsms-access-review.timer | Clean |
| deployment/systemd/fsms-hot-upgrade-agent.service | Clean — root 运行有据，ProtectSystem/ReadWritePaths/ExecStartPre 建目录齐备 |
| deployment/systemd/fsms-hot-upgrade-agent.timer | Clean — OnUnitInactiveSec 15s 与心跳/过期阈值匹配 |
| deployment/systemd/hot-upgrade.env.example | P3 — UPGRADE_HISTORY_LIMIT=50 与 compose 应用侧 10 不一致 |
| dev-backend.cmd | Clean — 指数退避、快失败熔断、跨午夜处理正确 |
| dev-vite.cmd | Clean — strictPort、cd 校验、正常退出不重启 |
| docker-compose.yml | P3 — secrets 路径与"仓库之外"建议矛盾；TRUSTED_PROXY_CIDRS 依赖未钉死网桥子网；LOGIN_ENCRYPT_STRICT 默认 false；其余（分段网络、capability 最小化、只读根、健康检查、rs-init 幂等）均到位 |
| docker/app-entrypoint.sh | Clean — 密钥复制/收紧/重写指针/su-exec 降权、HOME 修正、队列属主矩阵严谨，失败路径均有告警 |
| start.bat | Clean — 探活轮询替代盲等、只杀 node.exe、端口精确匹配 |

## S25 — .github / migrations / e2e / 根测试与构建配置（40 文件）

## Per-file appendix

| 文件 | 结论 |
| ---- | ---- |
| .github/CODEOWNERS | P3-7：单一 owner，效力依赖仓外分支保护（文件自认） |
| .github/ISSUE_TEMPLATE/bug_report.md | Clean（模板含脱敏提示） |
| .github/ISSUE_TEMPLATE/config.yml | Clean（blank_issues_enabled:false + 私密安全通道） |
| .github/ISSUE_TEMPLATE/feature_request.md | Clean |
| .github/ISSUE_TEMPLATE/security-report.md | Clean（引导至 GitHub security advisories） |
| .github/dependabot.yml | Clean（npm×2 + actions + docker，weekly，分组降噪，注释充分） |
| .github/semgrep/rules.yml | P3-9：全正则规则，绕过形态存在；作为零命中基线门禁成立 |
| .github/workflows/ci.yml | P3-4（旅程计数注释失实）、P3-12（e2e 后端无清理）；其余优：权限最小化、SHA 钉死、env 防注入、门禁 fail-closed |
| .github/workflows/codeql.yml | Clean（private==false 判据有据，权限逐项声明，SHA 钉死） |
| .github/workflows/dependency-review.yml | Clean（dependency graph 探测 fail-closed，v5.0.0 钉 SHA） |
| .github/workflows/deploy.yml | P2-1（从未实跑）、P3-6（部署 job 无超时 + self-hosted fail-open 排队）；注入防护（env 通道、正则收口、%q 引用）优秀 |
| .github/workflows/dr-readiness.yml | Clean（周频演练时效门禁，零依赖，只读） |
| .github/workflows/release.yml | P3-5（tag 校验 fetch 未用 token、错误信息误导）；workflow_run 前置 + tag↔commit 双重校验设计好 |
| .github/workflows/sast.yml | Clean（容器 digest 钉死、--validate + --error、SARIF 落 artifact） |
| .github/workflows/scorecard.yml | Clean（read-all + job 级最小化、publish_results、SHA 钉死） |
| e2e/README.md | Clean（"本地绿≠CI绿"披露清楚；P3-10 的覆盖缺口在此有声明） |
| e2e/helpers/auth.js | Clean（凭据全走 env；skipLocallyOrFail fail-closed 设计好） |
| e2e/helpers/totp.js | Clean（RFC 6238 最小实现，无依赖、无泄密面） |
| e2e/journey-fault-injection.spec.js | Clean（注入故障三态断言 + 会话期自愈；前置不可达时 fail-closed） |
| e2e/journey-inspection-alarm.spec.js | Clean（只读巡场，表格骨架断言） |
| e2e/journey-login.spec.js | Clean（401 + success:false + 停留页 + 错误条四重判据，抗假绿） |
| e2e/journey-mfa.spec.js | Clean（±1 窗口重试处理 flake；拒绝文案判别性强） |
| e2e/journey-mobile.spec.js | Clean（显式视口避免 skipped；boundingBox 断言抽屉位移，质量高） |
| e2e/journey-permission-audit.spec.js | Clean（权限树/审计行判据锚定真实 DOM，拒绝语义限定载体） |
| eslint.config.js | Clean（recommended 全量 error；体积/复杂度 warn+棘轮；ignores 修正 .eslintignore 失效问题） |
| eslint.ratchet.json | Clean（__lineCounts 旁路记账键已经 lint-ratchet.js:86-90 特判，非问题） |
| jest.config.js | P3-8（mfaController 57% 等低地板）；collectCoverageFrom 剔除测试基建、babel 插桩取舍有实测依据 |
| migrate-mongo-config.js | P2-2（ALLOWED_SOURCE_DB fail-open）、P3-11（useFileHash:false 陷阱）；惰性 getter 与 destructiveGuard 接线正确 |
| migrations/20260830000000-backfill-token-version.js | Clean（$exists 幂等；down 有意空操作且理由充分） |
| migrations/20260831000000-reconcile-audit-index-options.js | Clean（TTL 取单一来源常量；窄口径 NamespaceNotFound；collMod 原地改 TTL） |
| migrations/20260919000000-reconcile-audit-ttl-to-retention.js | Clean（补"改档不重放"洞；down 明确不回滚并说明理由） |
| migrations/20260926000000-cursor-tiebreak-compound-indexes.js | P2-3（判据代码复制源之一）；本身逻辑严谨 |
| migrations/20260928000000-audit-username-ci-index.js | P2-3（同上）；collation 正确性论证充分 |
| migrations/20261021000000-query-performance-indexes.js | P2-3（同上）；create-only/replace/drop-only 分类清晰 |
| migrations/20261030000000-backfill-password-set-at.js | Clean（$ifNull 兜底；down 射程与写入范围对齐） |
| migrations/20261101000000-filter-tiebreak-compound-indexes.js | P2-3（dropIndexIfExists 先查后删 + 自认 TOCTOU） |
| migrations/20261103000000-device-reminder-tiebreak-index.js | P2-3（同族复制） |
| migrations/20261201000000-audit-list-tiebreak-indexes.js | P2-3（dropIndexIfExists 已漂移为 try/catch 版，证明复制正在分叉） |
| migrations/README.md | P3-11（useFileHash 陷阱未进规范章节）；回滚语义一览表与 10 个文件实测一致（含 2 个不撤销迁移的如实标注） |
| playwright.config.js | Clean（retries:0 与 retain-on-failure 自洽，有对账测试；不上传报告的隐私考量在 ci.yml 落实） |

## 已验证的交叉引用（抽样核实，均成立）

- package.json：`test:coverage`=jest --coverage（阈值真实阻断）、`test:e2e:browser`=playwright test、`lint:ratchet`/`docs:check`/`check:utf8`/`check:changelog`/`format:check`/`migrate:*`/`test:ops-e2e`/`test:prod-drill` 全部存在。
- ci.yml 引用的门禁脚本（check-prod-install-scripts、check-lockfile-integrity、check-audit-allowlist、compliance-check、provision-mongod、login-key-pin、check-clock-sync、e2e-smoke、ops-e2e、production-drill、backup-integrity-patrol）均存在于 scripts/。
- 对账测试存在：src/tests/playwrightConfig.test.js、src/tests/ci/sastWorkflowInvariants.test.js、src/tests/migrations/migrationReadmeLedger.test.js。
- MIN_PASSED=32 与 6 个 spec 共 16 条测试 × 2 project 的总量一致（但 ci.yml 注释对"无条件/条件"的拆分口径错误，见 P3-4）。

## S26 — 根配置 / 根文档 / docs 与 ADR（57 文件）

## Per-file appendix

| 文件 | 结论 |
| ---- | ---- |
| .dockerignore | P3：53-54 行 `*.md`/`*.txt` 与 60-61 行 `**/*` 版重复；另与 .gitignore 同缺根级 `logs-*.txt`（见 P2，按目录论） |
| .editorconfig | Clean（缩进/字符集/尾随空白统一；md 不裁尾随空白、cmd/bat 4 空格，合理） |
| .env.example | P3：缺 README 生产清单要求的 `FSMS_SECRETS_DIR`；其余 Clean——692 行全为占位符/注释值，无真实凭据；与 README/compose/ADR-015 修订同步 |
| .gitattributes | Clean（bat/cmd CRLF、sh LF、*.xdb binary） |
| .gitignore | P2：根级 `logs-*.txt`（114MB/21 文件）未覆盖；其余覆盖面优秀（secrets*/backups/.env/*.pem/*.key/deliverables/work/tmp 均在列），注释完整可追溯 |
| .gitleaks.toml | Clean（extend default + 单数 `[allowlist]`，仅放行两个测试假凭据字面量，有防呆注释） |
| .gitleaksignore | Clean（8 条指纹全部 commit 级窄豁免，3 个 commit 哈希经 git 验证存在） |
| .npmrc | Clean（save-exact + package-lock，无危险配置） |
| .prettierrc | Clean |
| .prettierignore | Clean（忽略生成物与 lockfile，合理） |
| CHANGELOG.md | P3×3：1674-1675 表格行损坏；916 行反引号不配对；3189-3239 六条无日期标题。其余 Clean：3253 行、117 个条目按时间倒序、无重复拼接段落、结构闸 `check:changelog` 通过、与代码/ADR 互相引用可追溯 |
| CONTRIBUTING.md | Clean（环境/门禁/提交/回滚 ref 纪律/跨平台 shell 门禁/安全报告通道完整可执行，与 package.json、start.bat、dev-*.cmd 实物一致） |
| LICENSE | Clean（MIT，与 package.json license 一致） |
| README.md | P3：132 行 bash 块混入 PowerShell 语法。其余 Clean：所有可核对声明（OpenAPI 数、告警数、CI 矩阵、compose 变量、镜像 digest、engines、脚本与 deployment 文件存在性）全部与实物一致；快速开始对新人可执行 |
| SECURITY.md | Clean（报告渠道、SLA、范围、ECDH 密钥处置预案齐备；如实标注旧联系方式为死引用，Private Vulnerability Reporting 为唯一现役通道） |
| docs/adr/README.md | Clean（约定明确：编号只增不复用、状态取值、历史编号废弃说明；索引 21 篇与实物一致） |
| docs/adr/ADR-001 | Clean（背景/决策/理由/备选/后果完整，含 2026-09-28、2026-10-10 两轮复核注记，与 SECURITY.md 密钥管理节互链） |
| docs/adr/ADR-002 | Clean（哈希链+HMAC+版本化取舍清楚，payload 版本单一声明指向 auditChainPayload.js） |
| docs/adr/ADR-003 | Clean（密钥清单/文件注入/启动校验/轮换脚本完整，2026-10-20 现状修订与 CHANGELOG 一致） |
| docs/adr/ADR-004 | Clean（单进程假设 + Redis 锁升级的边界如实） |
| docs/adr/ADR-005 | Clean（sharedCache 双后端 + 生产强制 REDIS_URL + 回退语义，与 compose/validate 一致） |
| docs/adr/ADR-006 | Clean（游标分页含实测矩阵与迁移顺序约束） |
| docs/adr/ADR-007 | Clean（Express5 迁移评估快照 + 2026-09-28/11-14 复核注记，与 package.json express ^5.3.0 一致） |
| docs/adr/ADR-008 | Clean（数据范围"显式登记 + CI 守卫"的论证与局限如实） |
| docs/adr/ADR-009 | Clean（双网络分段与 compose networks/architecture.md §4 互为印证） |
| docs/adr/ADR-010 | Clean（不引入 tracing 的可判定重评条件，罕见的好边界声明） |
| docs/adr/ADR-011 | Clean（注释治理三原则 + 密度棘轮，与 scripts/commentDensity.js 体系一致） |
| docs/adr/ADR-012 | Clean（临时权限授予/复核规则与 privilegeGrant 代码面一致，C-09 残余如实） |
| docs/adr/ADR-013 | Clean（920 行：P0→P2-5 六批演进、边界表、不可达清单、判据台账全部可溯源；与 honeypot* 文件清单一致） |
| docs/adr/ADR-014 | Clean（幂等/回放/租约取舍完整，与 middleware/idempotency.js、CHANGELOG 审计一-1 一致） |
| docs/adr/ADR-015 | Clean（首版 + 2026-11-04 修订同篇呈现，与 loginChallenge.js/loginPeerLimiter 逐符号一致；抽查通过） |
| docs/adr/ADR-016 | Clean（passwordRetiredHash 单条上限的密码学理由与连续重置边界完整） |
| docs/adr/ADR-017 | Clean（Express5 body 归一的实测证据与防线描述一致） |
| docs/adr/ADR-018 | Clean（封段四判据 + 三处踩坑，拒绝原因单源声明与 banRefusalEnumSingleSource 闸一致） |
| docs/adr/ADR-019 | Clean（Ed25519 签名信任链与 fail-soft 边界，抽查文件全部存在；通过） |
| docs/adr/ADR-020 | Clean（单文件传包 + 只解点名条目的收窄论证，与 intake 三脚本一致） |
| docs/adr/ADR-021 | Clean（PROXY protocol 信任边界、三态语义、与 ENABLE_HTTPS 互斥的根因；validate.js/failOpenSites/alert-rules 三处落点抽查一致） |
| docs/architecture.md | Clean（Mermaid 架构/时序/ER/部署拓扑，声明以 compose 为唯一生成源并有契约测试钉住；审计链检查点边界如实） |
| docs/audit-buffer.md | Clean |
| docs/data-classification.md | Clean（台账用法 + 同意链路边界 + L4 取证数据与落盘证据文件口径完整） |
| docs/data-scope.md | Clean（GUEST level-1 归 all 档的理由与 README 角色表一致） |
| docs/env-number.md | Clean |
| docs/export-concurrency.md | Clean（含 2026-11-03 三池拆分，与 .env.example 导出变量一致） |
| docs/forensic-manifest-reconcile.md | Clean（三形态判据 + 窗口语界如实） |
| docs/honeypot-watch.md | Clean |
| docs/incident-response.md | Clean（角色/升级链/命令级遏制清单均绑定真实端点与脚本） |
| docs/internal-evidence-index.md | Clean（deliverables 引用台账，断链四条显式登记待处置） |
| docs/ip-location-service.md | Clean |
| docs/ip-pool-ban.md | Clean（票据外置/敲错不消耗/fail-closed 语义与 ADR-018 一致） |
| docs/mlps2-controls.md | Clean（每条控制项给可出示证据；G8/G9/行为基线未接线/取证降级四处"如实边界"声明尤佳） |
| docs/multi-instance-consistency.md | Clean（外置/进程内两表 + K8s 副本声明 + 容量模型，与 ADR-005、.env.example RUNTIME_INSTANCE_COUNT 一致） |
| docs/pii-export-quota.md | Clean |
| docs/security-dependency-watch.md | Clean（svg-captcha/Express/morgan/dev 树公告/lockfile 锚/SAST 分工/SLA/exceljs 退出生产树，全部带时间戳与失效更正记录；2026-11-14 复核节解决仓库可见性口径） |
| docs/threat-model.md | P3：残余风险 #3（DNS rebinding）已收口未更新；其余 Clean |
| docs/user-permission-service.md | Clean |
| package-lock.json | 按任务豁免未逐行；风险检查 Clean（与 package.json 一致、无已知风险包、重复版本均为工具链正常形态、有锚与门禁兜底） |
| package.json | P3：security:audit 两脚本 `--audit-level=high` 与 CI/SECURITY.md 的 moderate 基线漂移；其余 Clean（engines/scripts/依赖均健康） |
