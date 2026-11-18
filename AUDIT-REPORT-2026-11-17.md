# FSMS 全仓独立审计报告

- **审计日期**：2026-11-17
- **审计对象**：`main` 分支 `f644340`（工作区干净，与远程 origin/main 一致）
- **审计范围**：Git 受控文件全量 **1814 个**（后端 `src/` 1283、管理端 `web-admin/` 305、脚本 `scripts/` 92、文档 `docs/` 40、部署 `deployment/` 28、CI `.github/` 15、迁移 `migrations/` 12、e2e `e2e/` 9、根配置等其余 30）
- **审计方式**：本次为**从零独立重审**——不读取、不引用仓库内两份历史审计报告（`AUDIT-REPORT-2026-11-14.md`、`AUDIT-REPORT-2026-11-15.md`，按纪律仅跳过未审）。全仓切成 **44 个互不重叠的分区**，每分区由独立审计代理对清单内**每个文件逐行精读**（大文件分段续读至末行），统一按 7 维度 × 4 严重级产出发现；主审对 44 份分区报告做了覆盖度程序化对账（1814/1814，详见 §6），并补做 npm audit 依赖 CVE 扫描。
- **七维度**：① 代码质量与规范性 ② 架构设计与工程结构 ③ 安全性 ④ 性能与资源效率 ⑤ 测试覆盖与可靠性 ⑥ 可观测性与运维友好度 ⑦ 文档与知识传承
- **严重级**：P0 = 可直接利用的严重漏洞 / 数据损坏 / 服务不可用；P1 = 高危安全缺陷或核心逻辑错误；P2 = 中等缺陷（校验缺失、资源泄漏、明显性能隐患、严重可维护性、测试盲区）；P3 = 轻微（命名、重复、注释、风格、文档过时）

---

## 执行摘要

**总体结论：0 P0 / 2 P1 / 17 P2 / 281 P3，共 300 条发现。**

这是一个经多轮安全加固后水位相当高的代码库：RBAC 双闸（数据范围 + 层级）、审计日志哈希链与 WAL、PII 字段加密与检索键分离、登录挑战与账户锁定、限流三档、命令面全 argv 数组无 shell 拼接、CI 工作流最小权限 + commit SHA 钉扎、测试端普遍具备"前提自证 + 反向对照 + 变异验证"的断言文化——这些防线在本轮逐行精读中均被核实为**有效实现而非摆设**。未发现任何可直接利用的 P0 漏洞；也没有发现把既有防护误判为问题的情况（各分区对疑似问题均做了可达性/调用方核实后才定级）。

两个 P1 都不属于"可被攻击者直接利用"的类别，而是**可靠性与数据安全**问题：

| # | 位置 | 问题 | 影响 |
|---|------|------|------|
| P1-1 | `src/utils/auditChain.js:184-205`（配合 `src/utils/auditChainFence.js:87`） | 审计链围栏"前驱等待超时"分支会 `fence.freeze()`，但前驱**正常完成**路径不经过唯一解冻点（仅持锁超时分支可达解冻）。多实例 + Redis 锁模式下，一旦前驱临界区总时长（锁等待 + 慢批次）超过 15s 且有排队后继，本实例所有审计链写入从此在 `fence.check()` 永久失败：直写降级为无哈希 legacy、批量 flush 跳过，**直至重启，且无任何告警**（failOpenSites 只登记续租超界形态） | 审计链完整性静默停摆，合规 hash-chain 校验将出现成片 legacy 行 |
| P1-2 | `scripts/generate-dev-cert.sh:35-55` | "证书已存在，拒绝覆盖"守卫的 `exit 1` 会触发 EXIT trap，trap 里的 `rm -f` 把用户**原有的** `server.crt` / `server.key` 当作失败残留删掉 | 守卫反而销毁它要保护的旧私钥，本地开发环境凭据丢失 |

17 个 P2 的主题分布：**测试卫生 7**（共享库夹具污染 / env 泄漏 / 裸创建全局唯一权限码撞 E11000 / 清理签名错误导致空转 / 恒真断言 / mock 退化 / 连接泄漏）、**契约与校验 3**（OpenAPI 与设备创建路由矛盾、`safeInternalPath` 协议相对地址、compose 初始口令生成口径与生产强度闸冲突）、**安全闸 fail-open 1**（`check-audit-allowlist.js` 旗标缺值静默 undefined）、**性能 3**（取证清单同步整读、i18n 双语词表全量打包、回滚演练全量快照无上限）。逐条见各部分"重点发现"。

281 个 P3 集中在：DRY 重复实现（约 15 处双份口径）、死代码/死配置、注释与实现漂移、源码精确计数闸的脆弱性、前端暗色主题遗漏与 God component 收尾。P3 均不构成安全或稳定性风险，适合作为长期偿还清单。

**依赖安全（npm audit，2026-11-17 实测）**：根项目 moderate 19 / high 0 / critical 0；web-admin moderate 7 / high 0 / critical 0。全部风险位于 dev/构建依赖链（jest、eslint、nodemon、vite-plugin-pwa → glob/minimatch/workbox），无运行时生产依赖的 high/critical CVE；此前台账关注的 mongoose GHSA-6972-9mcm-vhwj 已不在当前结果中（mongoose ^8.24.9）。

## 修复优先级建议

1. **立即（P1×2）**：给 `auditChainFence` 的 freeze 增加"前驱正常完成"路径的解冻归属 + 告警埋点（并补一条多实例慢批次回归测试）；`generate-dev-cert.sh` 把覆盖守卫的退出移出 trap 作用域（或 trap 内区分正常/异常退出）。
2. **本迭代（P2×17）**：先修会真实咬人的三类——共享测试库污染与环境变量泄漏（7 条，直接对应 CI 随机红）、`check-audit-allowlist` fail-open（供应链门禁失真）、compose 口令生成口径（标准生产部署首启随机失败）；随后处理 OpenAPI 契约矛盾、`internalPath` 加固、i18n 懒加载、`forensicManifest` 异步化、`run-rollback-drill` 流式化。
3. **长期（P3×281）**：按主题批量偿还——双份口径收敛到单一来源、死代码清理、注释/文档同步性巡检、源码计数闸改为行为断言、God component 继续拆分。

## 总体统计

| 部分 | 范围 | 文件数 | P0 | P1 | P2 | P3 |
|------|------|-------:|---:|---:|---:|---:|
| 第一部分 | 后端业务源码（src/ 非测试） | 399 | 0 | 1 | 2 | 50 |
| 第二部分 | 后端测试（src/tests/） | 884 | 0 | 0 | 10 | 130 |
| 第三部分 | 管理端前端（web-admin/） | 305 | 0 | 0 | 2 | 66 |
| 第四部分 | 脚本 / 文档 / 基础设施 / 依赖 | 226 | 0 | 1 | 3 | 35 |
| **合计** | | **1814** | **0** | **2** | **17** | **281** |

> P3 计数采用逐条明细口径（个别分区报告的概览自计数与明细条目数存在 ±1~9 的口径差，已在相应部分 1.1/2.1/3.1/4.1 中明确标注，以明细为准）。

## 覆盖度声明

- 44 个分区的清单并集 = `git ls-files` 全集（1814 个文件），程序化核对**无重复、无遗漏**。
- 每份分区报告按"有发现（### 条目）∪ 无发现（清单）"给出全量文件名单，汇编时逐分区核对总数与并集，均与清单一致。
- 唯一例外：`deployment/observability/grafana/datasources/datasource.yml` 未列入 infra 分区报告的文件名单，由主审**亲自补读**——内容为 Grafana Prometheus 数据源预配置（内网服务名 `http://prometheus:9090`、`editable: false`、无凭据），未发现问题（见 4.6）。
- 两份历史审计报告按"独立重审"纪律未作为输入，也未复审。

## 报告结构

- **第一部分：后端业务源码** —— 1.1 分区概览 / 1.2 P1·P2 逐条展开 / 1.3 P3 汇总 / 1.4 七维度分析 / 1.5 逐文件附录
- **第二部分：后端测试** —— 2.1~2.5 同构（含测试体系总体评估）
- **第三部分：管理端前端** —— 3.1~3.5 同构
- **第四部分：脚本、文档、基础设施与依赖** —— 4.1~4.7（含 4.5 npm audit、4.6 覆盖度补注）

---
# 第一部分：后端业务源码（src/ 非测试）

> 汇编日期：2026-11-17。输入：be-services-1/2/3/4、be-utils-1/2、be-constants、be-controllers、be-middleware、be-models-config、be-core 共 11 份分区审计报告；应审文件数以 `partitions/be-*.txt` 清单行数为准。全部内容来自输入报告，未作外推；行号原样保留。

## 1.1 分区概览

| 分区 | 文件数（应审/报告实记） | P0 | P1 | P2 | P3 | 一句话评语 |
|---|---|---|---|---|---|---|
| be-services-1 | 36 / 36 | 0 | 0 | 0 | 3 | 全仓防护最密集的服务层（审计链/登录/MFA），无 P0–P2，仅 3 条健壮性/一致性/可观测性改进 |
| be-services-2 | 36 / 36 | 0 | 0 | 1 | 6 | 认证/会话/取证/蜜罐服务加固扎实，1 条取证清单同步整读文件的事件循环性能问题（P2） |
| be-services-3 | 36 / 36 | 0 | 0 | 0 | 6 | 质量显著高于平均水平（IP 封禁/临时授权/MFA/报表），6 条 P3（命名语义/死字段/串行查询等） |
| be-services-4 | 33 / 33 | 0 | 0 | 0 | 5 | 会话/告警/升级/导出服务质量高，5 条 P3 轻微问题，不构成安全缺口 |
| be-utils-1 | 35 / 35 | 0 | 1 | 0 | 2 | 含全后端唯一 P1：审计链围栏「冻结无解冻归属」可致本实例哈希链永久停摆 |
| be-utils-2 | 35 / 35 | 0 | 0 | 0 | 4 | 日志/序列化/校验工具 fail-closed 纪律好，4 条 P3（死代码/重复常量/截断边界） |
| be-constants | 49 / 49 | 0 | 0 | 0 | 5 | 声明/口径层做到单一事实来源+启动期自校验，5 条 P3（注释可读性/冻结一致性/微小重复） |
| be-controllers | 40 / 40 | 0 | 0 | 0 | 2 | 控制器多轮加固后处于高质量状态，2 条 P3（静默吞异常/纵深防御缺口） |
| be-middleware | 33 / 33 | 0 | 0 | 0 | 3 | 中间件 fail-closed 方向一致、注释与实现同步，3 条 P3（并发边界/契约一致性） |
| be-models-config | 41 / 41 | 0 | 0 | 0 | 4 | 模型/配置加固水位很高（PII 加密/append-only 护栏/生产硬闸），4 条 P3 潜在缺口 |
| be-core | 25 / 25 | 0 | 0 | 1 | 10 | 主要问题集中在 OpenAPI 文档与路由校验的契约漂移（1 P2 + 3 P3 文档类），另有少量一致性小疵 |
| **合计** | **399 / 399** | **0** | **1** | **2** | **50** | 后端业务源码整体处于高加固水位，无 P0；发现合计 53 条 |

文件数核对：11 个分区报告自称的审查文件数与 `partitions/` 清单行数**全部一致，无差异**。两处内部记账说明（不影响总数）：be-utils-1 报告按「30 个无发现文件 + 2 个立条文件」列示，其余 3 个文件（auditChainFence.js、crashFlush.js、healthChecks.js）作为证据并入相邻发现条目；be-constants 报告的 43 个无发现文件之外，dataScopeFields.js 作为同型证据并入 privilegeGrant.js 的发现条目。

## 1.2 重点发现（P1/P2 逐条展开）

说明：11 份报告间无同一发现的跨分区重复立条；跨分区出现的同型问题已在对应条目内注明。以下按 P1 在前、P2 在后排列。

### P1

**1. `src/utils/auditChain.js:184-205、211`（配合 `src/utils/auditChainFence.js:27-29、79-96`）| P1 | 安全/可靠性**

- **问题描述**：「前驱等待超时」定时器会把仍在合法飞行中的前驱当成僵尸冻结围栏，且该冻结没有任何解冻归属——本实例审计哈希链将永久停摆（直至重启）。解冻只有两处：`fence.reset()`（仅 `__resetForTest`，生产不调用）与 `waitForZombie` 的 settle，而后者只被「本调用自己持锁超时」分支触达；前驱若正常完成（`timedOut=false`）不经过任何解冻路径。触发场景（需 Redis 已启用）：前驱排队 ~10s 后执行一个 ~10s 慢批次，后继在 t≈16s 触发 waitPrev 定时器执行 `fence.freeze()`，前驱于 t≈20s 正常完成、不解冻，此后本进程所有链写入在 `fence.check()` 处永久失败——`auditBuffer.flush` 直接跳过（记录滞留缓冲与 WAL），`AuditLog.create` 直写路径降级为无哈希 legacy 落库。附带症状：定时器里的 `chainGeneration += 1` 还会把前驱的 `advanceChainTail` 误判为僵尸跳过，链尾指针停止推进（DB 权威尾可自愈，冻结不会）。`failOpenSites.js:302` 已登记的 `audit_chain_zombie_renewal_exceeded` 只覆盖「续租超上界」形态，本形态目前零告警。
- **证据**：
  ```js
  waitTimer = setTimeout(() => {
    chainTailLoaded = false;
    chainTail = null;
    chainGeneration += 1;
    fence.freeze();
    resolve();
  }, chainLockTimeoutMs());
  ```
- **修复建议**：waitPrev 超时分支不要做无主 `freeze()`——该分支已有「链尾失效 + 代际递增」兜底，`freeze()` 应只保留给「本调用持锁超时」的僵尸窗口（那个窗口由 `waitForZombie` 负责解冻）；若保留冻结，则须为该 freeze 登记解冻归属（例如由前驱 promise 最终 settle 时统一收口），并增加「frozen 持续时长」告警指标。

### P2

**2. `src/services/forensicManifest.js:78-97`（经 `:100-119` writeLocked、`:122-155` appendBatch，每次取证批次落库后触发）| P2 | 性能/事件循环**

- **问题描述**：`readLastChainHash` 用 `fs.readFileSync` **整读**当天清单文件取末行 chainHash；`withLock` 内部（forensicManifestLock.js `:41-49`、`:86`、`:106-115`）也全是同步 IO。清单追加跟随取证捕获的 flush 节奏（默认 2s 一轮），而清单文件按业务日持续累积——代码注释自述量级「默认 flush 2s 一次 ⇒ 理论上限约 4.3 万行/天」，按每行 ~230B 计，日终达数 MB～10MB 级，**每次追加都把整个文件同步读一遍**，阻塞与全部请求共享的事件循环，且负载最重的时刻恰是「正被攻击、捕获全开」的时段。
- **证据**：`content = fs.readFileSync(filePath, 'utf8');`（:81）、`const lines = content.split('\n').filter(Boolean);`（:86）
- **修复建议**：进程内按 (dir, 业务日) 缓存「末行 chainHash + 文件字节数」，仅当锁被他人接管或文件长度与缓存不符时才重读；或改为只读文件末尾固定字节解析末行。跨进程正确性已由文件锁保证，缓存只需覆盖「本进程刚写过」这一最常见情形。

**3. `src/docs/openapi.json:1790-1866`（生成器同源：`src/docs/generate.js:651-674`）| P2 | 文档/一致性**

- **问题描述**：创建设备接口的文档契约与路由校验矛盾。文档声称「设备编号自动生成，格式为 类型前缀-年份-序号（如 FA-2026-0001）」，requestBody `required` 仅为 `["deviceName", "deviceType"]`，且 schema 中根本没有 `deviceCode` 字段、`installDate` 为可选属性；但路由层强制两者必填——按文档集成（不传 deviceCode/installDate）必然 400。更深一层：`src/models/FireDevice.js:219` 挂载了 autoIncrement 插件（缺号时原子取号自动生成），`src/services/deviceService.js:168-173` 直接 `FireDevice.create({...fields})`——插件的自动编号能力在 API 路径上被路由校验整体拦死，仅剩脚本/初始化路径可达，「自动生成」机制与 API 边界互相矛盾。
- **证据**：`src/routes/deviceRoutes.js:48-53` `body('deviceCode').trim().notEmpty().withMessage('设备编号不能为空')`；`src/routes/deviceRoutes.js:74` `body('installDate').isISO8601().withMessage('请提供安装日期（ISO8601 格式）')`
- **修复建议**：对齐三方口径——要么路由放行缺省 deviceCode 由插件生成（并在文档保留「自动生成」），要么文档把 deviceCode/installDate 改为必填并从描述中删去「自动生成」。

## 1.3 P3 发现汇总

共 50 条，按主题归组（每条一行：`路径:行号` — 一句话）。

### 性能与资源（7 条）

- `src/services/auditWalCap.js:178` — durable 裁剪分支使用无界 spread，触发 V8 参数上限时硬上限静默失效且 `walTrimFailures` 计数漏记。
- `src/services/attackProfile.js:121` — 画像取数的 countDocuments/find 未挂列表查询预算，偏离同族读面（attackEventQueryService/auditQueryService）既定口径。
- `src/services/forensicCaptureFlush.js:40-44` — insertMany 批无字节数上限，极限情况下逼近 MongoDB 单消息 ~48MB 上限可成「整批失败→回填→反复失败」毒批循环（待确认）。
- `src/services/captchaService.js:278-286` — Redis 模式 verify 对 memStore 回退取到的条目也执行 Redis 侧配额递减，Redis 恢复后会误减其他用户的活跃配额计数（待确认，floor 0 + TTL 自愈）。
- `src/services/ipPoolBan.js:241-254` — banRecommended 对簇列表逐条 `await requestBan`，MAX_BATCH=20 时最坏约 80 次串行 DB/快照往返，可改并发。
- `src/constants/honeypotAccounts.js:58-65` — matchHoneypotName 默认参数每次缺省调用重新解析全部诱饵名，attackProfileSummary 逐行循环下一次画像构建最多重复解析 5000 次。
- `src/cluster.js:97-100` — 短命崩溃退避的补 fork 定时器未 `unref()`，关停后最长 30s 拖住 primary 事件循环，与同文件兜底定时器口径不一致。

### 安全与纵深防御（9 条）

- `src/services/initData/permissionsSystem.js:19-29` — `system:read` 权限码语义过宽，实际授予「查看他人手机号/邮箱全文」接口，管理员易误授（有意设计，故 P3）。
- `src/services/forensicExport.js:17-24、:50、:61-85` — 签名材料不含 `operator`，任何持包者可改写导出归属而签名仍通过。
- `src/services/mfaService.js:32-46` — 恢复码 pepper 拿不到 HMAC 密钥时静默退化为纯 sha256，且无任何运行时告警。
- `src/services/reportExportService.js:179-181、:254` — 掩码导出仍不掩 `reporter.name`，第三方自填姓名随默认掩码档全文外流（文件头已登记为已知残留）。
- `src/services/securityAlert.js:170、:215` — 暴力破解通知频控键使用原始 username 未做 `cleanAuditUsername` 归一，大小写/空白变体各占节流桶、可放大 webhook 投递量。
- `src/services/upgradeService.js:365-377` — `readJob(id)` 把 id 直接拼进文件路径而函数自身不校验 `isJobId`，纵深防御缺口（当前调用方已校验，不可达）。
- `src/controllers/privilegeController.js:85-91` — `listGrants` 把 status/userId 原样传入服务层拼 Mongo 查询，依赖单一路由校验闸，闸被移除/复用即成操作符注入点。
- `src/utils/encryption.js:470-471` — maskIP 最终兜底对认不出的输入原样返回，与同文件 maskPhone/maskEmail/maskIdCard「认不出即全掩码」方向不一致。
- `src/utils/pngStructure.js:34-38` — 调色板图 tRNS/bKGD 长度未与 PLTE 条目数交叉校验，畸形图放行后依赖下游解码器兜底。

### 可观测性与排障（6 条）

- `src/services/authService/failureAndMfa.js:264-294` — MFA/恢复码路径的落锁块与口令主路径几乎逐行重复且已漂移：本路径只写 logger.warn、不写 `account_temp_locked` 审计，合规检索系统性漏掉这类锁定。
- `src/services/ipPoolCluster.js:11、:81-85` — `state.lastError` 声明并对外暴露但全文件无赋值路径恒为 null，聚合失败时运维误判无故障（死字段）。
- `src/services/securityAlertPermissionAbuse.js:143-148` — 权限滥用告警文案只给 `用户 ${userId}`（ObjectId），username 就在入参里却不带，增加 SOC triage 成本。
- `src/utils/logger.js:58-59、:69-78` — 崩溃堆栈在 exceptions-*.log 中被截断阈值封顶（message 8KB、stack 1024 字符），与文件头「完整堆栈可追」声明存在边界差距。
- `src/controllers/securityController/overview.js:253-255` — `buildComplianceSection` 的 catch 静默吞掉异常不写任何日志，面板报错时无法定位子项。
- `src/models/IPBlacklist.js:175-179` — 快照内过期记录的惰性清理 `.catch(() => {})` 吞掉全部错误，删除失败时反复重试且外部完全不可见。

### 一致性与健壮性（9 条）

- `src/services/reportDashboardService.js:62-66、:214` — 模块级 `EMPTY_DASHBOARD` 被原引用返回，违反本文件自声明的「出栈必拷贝」不变式，未来装饰返回体将永久污染缓存。
- `src/middleware/idempotency.js:104-131` — 2xx 收尾的 `updateOne({ keyHash }, ...)` 缺「只准收尾自己的认领」守卫条件，原请求迟到收尾可覆盖他人已完成的判据行。
- `src/middleware/idempotency.js:200-208` — `res.end = (chunk, encoding) => {...}` 丢弃原生第三参数 callback，依赖方回调永不执行会挂起（姊妹包装器均用 `(...args)` 透传）。
- `src/middleware/tokenBlacklist.js:34-37` — `blacklistToken` 未校验 `exp` 为有限数值，NaN 时过期守卫失效、Invalid Date upsert 抛错，参数缺失被放大成「持久化失败」告警。
- `src/models/FireAlarm.js:180-188` — `capProcessLogPush` 对带 `$each` 的批量 `$push` 直接 return，既不加 `$slice` 封顶也不累加 `processLogCount`，未来调用方可绕过 200 条封顶（当前生产写入点均单条，不可达）。
- `src/models/SystemConfig.js:117-125` — `set()` 的 valueType 派生把 `null` 值标成 `'string'`，元数据失真误导后台配置列表展示。
- `src/cluster.js:15-21、:26-39、:113` — `CLUSTER_WORKERS`/`CLUSTER_SHUTDOWN_GRACE_MS` 用 parseInt 宽松解析，`"3abc"`、`"3.7"` 静默截断且不触发告警。
- `src/routes/alarmRoutes.js:118-125`（及 :152-159、:166-172、:192-198、:205-211、:218-224）— 同一文件内校验消费双口径：GET `/` 挂 `consumeValidation()`，POST/PUT 写链只挂校验器靠控制器兜底，后续新增路由易漏一侧。
- `src/services/sessionService.js:354、:377-384` — `validateSession` 把同一 Mongoose 文档按引用缓存并返回给所有调用方，未来调用方一旦原地改写即在 TTL 内污染该 sid 全部请求（待确认，当前唯一消费方只读）。

### 代码质量与 DRY（9 条）

- `src/services/deviceReminder.js:25-29、:124` — 扫描缓存键的缺省值（30 天/200 条）与函数解构缺省值两处各写一份，单侧修改即致缓存键与扫描口径分叉。
- `src/services/forensicTrigger.js:42-51` — 开关常量在模块加载时一次性读取 env，与 forensicCapture「判据时现读」口径不一致，且无 `__resetForTest` 钩子。
- `src/services/reportWorkbookService.js:249` — Content-Disposition 只用带引号 `filename=` 形态，中文表名 xlsx 在主流浏览器下载成百分号乱码文件名，应补 `filename*=UTF-8''`。
- `src/utils/proxyProtocol.js:45、:462` — `SNIFF_LIMIT_BYTES` 是死导出且注释把它描述成承重判据，实际嗅探逻辑从未引用。
- `src/utils/logPiiMask.js:91` — `MAX_NESTED_CHARS = 1024` 与 logger.js 的 `MAX_LOG_FIELD_CHARS` 同语义重复常量，仅靠行内注释对齐。
- `src/constants/privilegeGrant.js:22-42` — `GRANT_LIST_FIELDS` 等共享白名单未 `Object.freeze`，与同目录 audit.js/attackEvents 的冻结纪律不一致（同型：dataScopeFields.js、reportExportColumns.js 等）。
- `src/constants/honeypotDecoy.js:135` — 分钟换算用字面量 `60000`，与同族 honeypotDecoyShape.js 已导出的 `MIN = 60 * 1000` 重复。
- `src/routes/wellKnownRoutes.js:35-44、:128-137、:261-270` — 三个限流器的 store/keyGenerator/handler 三份近乎逐字复制，应抽工厂函数。
- `src/index.js:495` — 24 小时轮询间隔以魔法数字内联，文件内其它周期均有具名常量或注释。

### 文档与注释（10 条）

- `src/constants/audit.js:191` — 注释关键括号内语句 garbled（「少看得境不是多看得境」），username 闸唯一说明存量脏行取舍的论断不可读。
- `src/constants/breachedPasswords.js:6` — 文件头小节标题语句粘连、缺标点，第一句读起来语义错误。
- `src/services/captchaService.js:159-175` — `noteIssueStoreDegraded` 注释未说明「仅 Redis 停机窗口内本实例可验；恢复后旧码作废」，会误导排障。
- `src/models/AuditLog.js:260-265` — `hash` 字段注释引用的行号锚点已失效（真正写入点是 auditLogHooks.js:92-97），应按本仓纪律改为函数名锚点。
- `src/docs/generate.js:1446-1451` — `/api/security/audit-logs/verify` 未登记 `X-Reauth-Ticket` 参数（路由实际挂了 `requireReauthTicket()`），同族端点均登记。
- `src/docs/generate.js:1108-1117` — `/api/security/view-sensitive` requestBody 缺 `targetUserId` 与三个二次验证凭据字段，集成方按文档无法构造可通过验证的请求。
- `src/docs/generate.js:1572-1578` — `/metrics` 的 `security` 声明为 bearerAuth（JWT），实际鉴权是 metricsAuth（内网/回环 + METRICS_TOKEN），JWT 令牌并不能访问。
- `src/plugins/autoIncrement.js:72-80` — 注释称「只数形如 前缀-数字 的编号」，实现正则实际只匹配序号 ≥ seqPadding(4) 位的定宽编号，注释与代码不符（存量短序号待确认）。
- `src/routes/wellKnownRoutes.js:236-237` — 未配置 `SECURITY_CONTACT_EMAIL` 时 security.txt 静默回落占位符 `security@example.com`，生产会把无效联系方式下发给漏洞提交者。
- `src/utils/encryption.js:8`（同型：`src/utils/crashFlush.js:14-15`、`src/utils/healthChecks.js:121`）— utils 层顶层反向依赖 services 层（require sharedCache/auditBuffer/forensicCapture），现状有注释、无环，建议下沉接口或立分层门禁。

## 1.4 七维度分析

**① 代码质量与规范性**：整体水位高——399 个文件仅 53 条发现（P0=0、P1=1、P2=2、P3=50），且除 1 条 P1、2 条 P2 外全部为 P3 轻微问题；be-utils-1 明确以「ESLint/Prettier 已强制的风格不计」为报告门槛，说明基础规范已由工具链兜住。典型优点是注释与实现同步、关键判据附带论证（如 forensicCapture.js:75-76 对开关「每次现读 env」的取舍说明、queryBudget 头注释的预算纪律）。典型问题集中在重复实现漂移（src/services/authService/failureAndMfa.js:264-294 与 login.js:400-445 的落锁块；src/utils/logPiiMask.js:91 与 logger.js:59 同一上限各写一份；src/services/deviceReminder.js:25-29/124 缓存键缺省值两处）、死代码（src/utils/proxyProtocol.js:45、src/services/ipPoolCluster.js:11）与魔法数字（src/constants/honeypotDecoy.js:135 的 60000、src/index.js:495 的 24h）。

**② 架构与工程结构**：分层清晰（routes→controllers→services→models，utils/config/constants 支撑），services 按域拆分为小模块（authService/、forensic*、honeypot*、sharedCache/、websocketService/、initData/），constants 层普遍做到单一事实来源+派生而非抄写+启动期自校验（riskLevelsAtLeast、DECOY_EXPORT_ITEMS、attackEvents.resolveActionMap）。主要结构问题有三：一是 utils→services 顶层反向依赖（src/utils/auditChain.js:8、crashFlush.js:14-15、healthChecks.js:121），环风险与测试替身成本随 services 侧反向引用上行；二是对外文档契约与路由校验的漂移成体系（openapi.json 创建设备接口 P2，generate.js 三处 P3）；三是同类机制口径不一（alarmRoutes.js:118-125 的校验消费双口径、forensicTrigger.js:42-51 与 forensicCapture.js:75-76 的 env 读取时机不一致）。

**③ 安全性**：这是本部分最强的维度。399 个文件未发现任何可直接利用的漏洞（P0=0）；数据范围过滤「缺省即 deny、聚合前 cast ObjectId、$or 合并而非覆盖」，审计「先持久化再回成功」fail-closed，PII at-rest 加密（v2 AAD 行绑定+检索键 select:false）、SSRF 白名单+IP 钉扎、令牌轮换与重放防护、蜜罐防指纹化等防线设计到位且有测试锚点。唯一 P1 亦属安全可靠性交叉：审计链围栏「前驱超时冻结无解冻归属」可致哈希链在本实例静默停摆（src/utils/auditChain.js:184-205、211）。其余安全类发现均为纵深防御/加固型 P3：forensicExport.js:17-24 的 operator 未入签名材料、encryption.js:470-471 的 maskIP 兜底明文返回、upgradeService.js:365-377 的 readJob 缺内部 isJobId 闸、privilegeController.js:85-91 的查询参数透传、pngStructure.js:34-38 的 tRNS 交叉校验缺失、mfaService.js:32-46 的 pepper 静默退化、securityAlert.js:170/215 的频控键未归一、initData/permissionsSystem.js:19-29 的 system:read 语义过宽。

**④ 性能与资源**：常规路径无热点——读面普遍挂 queryBudget 预算、列表走游标分页+复合索引（时间+_id 平局键）、bcrypt 走 worker 池、高基数标签用闭合集。最重的性能问题是 P2 的取证清单同步整读（src/services/forensicManifest.js:78-97，日终数 MB～10MB 的文件每次追加都 readFileSync 整读、阻塞共享事件循环，且恰发生在被攻击时段）。其余为边界/极端场景：auditWalCap.js:178 的无界 spread（数万 durable 行时触发 V8 参数上限、硬上限失效）、ipPoolBan.js:241-254 的逐簇串行 await（最坏约 80 次串行往返）、constants/honeypotAccounts.js:58-65 的画像逐行循环重复解析诱饵名单（最多 5000 次/请求）、forensicCaptureFlush.js:40-44 的 insertMany 批无字节预算（极限 ~48MB 毒批循环，待确认）、cluster.js:97-100 的补 fork 定时器未 unref、captchaService.js:278-286 的回退条目误减 Redis 侧配额（待确认）。

**⑤ 测试与可靠性**：可靠性工程化程度高——大量文件带测试锚点与 `__resetForTest` 钩子，failOpenSites 台账+门禁用例双向对账，启动期自校验（attackEvents.resolveActionMap、timezone 加载期构造 formatter、businessRetention 四道闸），并有多处「同族疑点已核实排除」的记录（如 seeding.js:34/167 的 11000 判据、privilegeGrantService.js:159/184 的 $size 空数组安全性）。可靠性问题多为「当前不可达、未来易踩」型：idempotency.js:104-131 的 2xx 收尾缺守卫（迟到收尾覆盖他人判据行）、models/FireAlarm.js:180-188 的 $each 批量 push 绕过 200 条封顶、reportDashboardService.js:62-66/214 的 EMPTY_DASHBOARD 原引用返回、sessionService.js:354 的缓存文档按引用共享、tokenBlacklist.js:34-37 的 NaN 守卫失效、forensicTrigger.js:42-51 缺测试重置钩子。

**⑥ 可观测性与运维**：观测面完整——metrics/metricsAuditDrops/metricsDetection/metricsRuntime 指标族、fail-open 登记台账+告警、审计/取证留痕、结构化日志+中央脱敏（logger 的 sanitizeLogRecords 在 json/printf 两条链统一收口，be-middleware 复核确认 rateLimit.js 的 meta 风险已在日志层闭环）；「降级必须可见」已成明文纪律。缺口集中在静默失败：securityController/overview.js:253-255 的 catch 吞异常零日志、models/IPBlacklist.js:175-179 的过期清理吞错、ipPoolCluster.js:11/81-85 的 lastError 恒 null 误导运维、logger.js:58-59/69-78 的崩溃堆栈被截断阈值封顶、cluster.js:15-21 的 parseInt 静默截断配置漂移、securityAlertPermissionAbuse.js:143-148 的告警只给 ObjectId、wellKnownRoutes.js:236-237 的 security.txt 占位联系人、mfaService.js:32-46 的 pepper 退化零信号。

**⑦ 文档与知识传承**：代码内注释文化突出——取舍论证、实测依据、日期溯源（be-middleware 的修复注释可追溯 2026-09-17～2026-11-16 多批整改）、SystemConfig.js:233 明确「不写被删代码行号」的锚点纪律、src/data/README.md 登记二进制数据版本。短板恰在「对外文档」：OpenAPI 与实现系统性漂移（openapi.json:1790-1866 创建设备接口 P2；generate.js:1446-1451 缺 X-Reauth-Ticket、:1108-1117 缺二次验证字段、:1572-1578 /metrics security 声明失真），按文档集成会在多处失败。其次是注释腐化：constants/audit.js:191 语句 garbled、breachedPasswords.js:6 断句缺失、models/AuditLog.js:260-265 行号锚点失效、plugins/autoIncrement.js:72-80 注释与正则实现不符、captchaService.js:159-175 注释误导排障。

## 1.5 逐文件附录

格式：有发现文件为 `路径 — N 条（最高 P 级）— 一句话`；无发现文件为纯路径列表。每分区文件总数与分区清单行数一致。

### be-services-1（36 个：有发现 3，无发现 33）

有发现：
- src/services/auditWalCap.js — 1 条（P3）— durable 裁剪无界 spread 可使 WAL 硬上限静默失效且计数漏记。
- src/services/authService/failureAndMfa.js — 1 条（P3）— MFA/恢复码落锁块与口令主路径重复且漏写 `account_temp_locked` 审计。
- src/services/attackProfile.js — 1 条（P3）— countDocuments/find 未挂列表查询预算，偏离同族读面口径。

无发现（33）：src/services/AlarmService.js, src/services/DeviceService.js, src/services/InspectionService.js, src/services/accessReviewService.js, src/services/adminAccountAudit.js, src/services/alertDispatch.js, src/services/alertTypes.js, src/services/attackEventQueryService.js, src/services/attackProfileClassify.js, src/services/attackProfileSummary.js, src/services/attackProfileVerdict.js, src/services/auditAnchorSink.js, src/services/auditBuffer.js, src/services/auditBufferDocs.js, src/services/auditBufferWal.js, src/services/auditChainAlertTypes.js, src/services/auditChainCheckpoint.js, src/services/auditChainMonitor.js, src/services/auditChainVerify.js, src/services/auditCheckpointFreshness.js, src/services/auditExportService.js, src/services/auditFlushBatchLimit.js, src/services/auditMonitor.js, src/services/auditMonitorDetection.js, src/services/auditOutbox.js, src/services/auditQueryService.js, src/services/auditScopeFilter.js, src/services/auditWalPath.js, src/services/auditWalPermissions.js, src/services/authService/index.js, src/services/authService/login.js, src/services/authService/loginCounters.js, src/services/authService/password.js

### be-services-2（36 个：有发现 6，无发现 30）

有发现：
- src/services/forensicManifest.js — 1 条（P2）— 每次清单追加同步整读当天文件，阻塞共享事件循环（forensicManifestLock.js 的同步 IO 已作为本条证据一并引用，不重复立条）。
- src/services/forensicExport.js — 1 条（P3）— 签名材料不含 operator，导出归属字段可被改写而签名仍通过。
- src/services/forensicCaptureFlush.js — 1 条（P3）— insertMany 批无字节预算，极限可成毒批循环（待确认）。
- src/services/captchaService.js — 2 条（P3）— 回退条目误减 Redis 侧他人配额（待确认）；降级注释误导排障。
- src/services/deviceReminder.js — 1 条（P3）— 缓存键缺省值与函数解构缺省值两处各写一份。
- src/services/forensicTrigger.js — 1 条（P3）— 开关常量加载期固化，与 capture 现读口径不一致且无测试重置钩子。

无发现（30）：src/services/authService/profile.js, src/services/authService/session.js, src/services/authService/token.js, src/services/avatarService.js, src/services/behaviorBaseline.js, src/services/canaryAlertTypes.js, src/services/canaryWatch.js, src/services/consentService.js, src/services/deviceStatsService.js, src/services/exportConcurrency.js, src/services/forensicCapture.js, src/services/forensicCaptureCodec.js, src/services/forensicCaptureLifecycle.js, src/services/forensicCapturePayload.js, src/services/forensicCaptureWal.js, src/services/forensicManifestLock.js, src/services/forensicManifestPrune.js, src/services/forensicManifestReconcile.js, src/services/forensicManifestRetry.js, src/services/forensicTrace.js, src/services/honeypotAlertTypes.js, src/services/honeypotChainWatch.js, src/services/honeypotDecoy.js, src/services/honeypotDecoyFiles.js, src/services/honeypotDecoySelf.js, src/services/honeypotDecoySelfProfile.js, src/services/honeypotLurePresentation.js, src/services/honeypotWatch.js, src/services/initData/adminAccount.js, src/services/initData/index.js

### be-services-3（36 个：有发现 6，无发现 30）

有发现：
- src/services/initData/permissionsSystem.js — 1 条（P3）— `system:read` 权限码语义过宽，实际授予他人 PII 全文查看。
- src/services/reportDashboardService.js — 1 条（P3）— EMPTY_DASHBOARD 原引用返回，违反自声明「出栈必拷贝」不变式。
- src/services/ipPoolCluster.js — 1 条（P3）— `state.lastError` 死字段恒为 null，故障时误导运维。
- src/services/mfaService.js — 1 条（P3）— 恢复码 pepper 缺失时静默退化为纯 sha256 且零告警。
- src/services/reportExportService.js — 1 条（P3）— 掩码导出仍不掩 reporter.name，第三方姓名全文外流（已登记的已知残留）。
- src/services/ipPoolBan.js — 1 条（P3）— banRecommended 逐簇串行 await，最坏约 80 次串行往返，可并行。

无发现（30）：src/services/initData/indexes.js, src/services/initData/permissions.js, src/services/initData/permissionsBusiness.js, src/services/initData/roles.js, src/services/initData/seeding.js, src/services/initData/systemConfig.js, src/services/initialPasswordFile.js, src/services/injectionDetector.js, src/services/ipListService.js, src/services/ipLocationService.js, src/services/ipPoolBanAudit.js, src/services/ipPoolLiveTraffic.js, src/services/jwtKeyRotationAudit.js, src/services/loginChallenge.js, src/services/loginRateLimitAudit.js, src/services/mfaDisable.js, src/services/permissionCatalog.js, src/services/permissionService.js, src/services/piiExportQuota.js, src/services/piiExportWatermark.js, src/services/privilegeGrantHooks.js, src/services/privilegeGrantService.js, src/services/privilegeGrantValidation.js, src/services/rateLimitEscalation.js, src/services/rateLimitEscalationBan.js, src/services/realtimeNotifier.js, src/services/reauthGrantStore.js, src/services/reauthTicketStore.js, src/services/reportStatsService.js, src/services/reportTargetService.js

### be-services-4（33 个：有发现 5，无发现 28）

有发现：
- src/services/securityAlert.js — 1 条（P3）— 暴力破解频控键未用 cleanAuditUsername 归一，变体可绕过节流抑制。
- src/services/securityAlertPermissionAbuse.js — 1 条（P3）— 告警文案只给 ObjectId 不给 username，增加 triage 成本。
- src/services/sessionService.js — 1 条（P3）— validateSession 按引用共享缓存文档，未来原地改写会污染缓存（待确认）。
- src/services/upgradeService.js — 1 条（P3）— readJob 缺内部 isJobId 闸，路径安全完全依赖调用方纪律。
- src/services/reportWorkbookService.js — 1 条（P3）— Content-Disposition 缺 filename* 形态，中文文件名下载成乱码。

无发现（28）：src/services/roleService.js, src/services/scanProbeDetector.js, src/services/securityAlertDelivery.js, src/services/securityAlertIpBans.js, src/services/sessionCap.js, src/services/sessionRevocationEvents.js, src/services/sharedCache/index.js, src/services/sharedCache/invalidation.js, src/services/sharedCache/memoryStore.js, src/services/sharedCache/scripts.js, src/services/sharedCache/state.js, src/services/sharedCacheLocks.js, src/services/startupAuditTrail.js, src/services/statsCache.js, src/services/stuffingProfile.js, src/services/tokenService.js, src/services/upgradeRequestSignature.js, src/services/userAnonymizationBatch.js, src/services/userPermissionService.js, src/services/userService.js, src/services/webhookTargetResolver.js, src/services/websocketService/handshake.js, src/services/websocketService/inboundThrottle.js, src/services/websocketService/index.js, src/services/websocketService/lifecycle.js, src/services/websocketService/push.js, src/services/websocketService/sessionRevocation.js, src/services/websocketService/shared.js

### be-utils-1（35 个：有发现 2 + 3 个证据并入文件，无发现 30）

有发现：
- src/utils/auditChain.js（涉及 src/utils/auditChainFence.js）— 1 条（P1）— 前驱等待超时冻结围栏无解冻归属，本实例审计哈希链可永久停摆。
- src/utils/encryption.js — 2 条（P3）— maskIP 兜底对认不出的输入原样明文返回；utils 层顶层反向依赖 services 层（同型：src/utils/crashFlush.js:14-15、src/utils/healthChecks.js:121，并入本条计）。
- src/utils/auditChainFence.js — 0 条独立（P1 发现的证据文件，与 auditChain.js 同条计）。
- src/utils/crashFlush.js — 0 条独立（P3 同型引用，与 encryption.js 架构条同条计）。
- src/utils/healthChecks.js — 0 条独立（P3 同型引用，与 encryption.js 架构条同条计）。

无发现（30）：src/utils/ApiError.js, src/utils/accessLogDevFormat.js, src/utils/apiResponse.js, src/utils/auditChainPayload.js, src/utils/auditChainTail.js, src/utils/auditMeta.js, src/utils/auditQuery.js, src/utils/auditWriteFailure.js, src/utils/avatarImage.js, src/utils/avatarImageError.js, src/utils/avatarUrl.js, src/utils/bcryptWorkerPool.js, src/utils/bcryptWorkerThread.js, src/utils/cidrCoverage.js, src/utils/constants.js, src/utils/cookie.js, src/utils/cursorPagination.js, src/utils/dateFormat.js, src/utils/emailKey.js, src/utils/envNumber.js, src/utils/errorCodes.js, src/utils/filePermission.js, src/utils/fingerprint.js, src/utils/forensicDeviceKey.js, src/utils/helpers.js, src/utils/httpPostJson.js, src/utils/idempotencyKey.js, src/utils/ip2regionSearcher.js, src/utils/ipRange.js, src/utils/ipUtils.js

### be-utils-2（35 个：有发现 4，无发现 31）

有发现：
- src/utils/proxyProtocol.js — 1 条（P3）— SNIFF_LIMIT_BYTES 死导出且注释误称承重判据。
- src/utils/logPiiMask.js — 1 条（P3）— MAX_NESTED_CHARS 与 logger.js 同语义上限重复定义，易静默漂移。
- src/utils/pngStructure.js — 1 条（P3）— tRNS/bKGD 长度未与 PLTE 条目数交叉校验，纵深防御缺口。
- src/utils/logger.js — 1 条（P3）— 崩溃堆栈被截断阈值封顶，与「完整堆栈可追」声明有边界差距。

无发现（31）：src/utils/jwtKeys.js, src/utils/logContext.js, src/utils/logPaths.js, src/utils/logShipper.js, src/utils/logShippingTarget.js, src/utils/loggerFlush.js, src/utils/loginCipher.js, src/utils/metrics.js, src/utils/metricsAuditDrops.js, src/utils/metricsDetection.js, src/utils/metricsRuntime.js, src/utils/mfaSecret.js, src/utils/mongoDuplicateKey.js, src/utils/mongoFailureAttribution.js, src/utils/passwordHistory.js, src/utils/permissionHelper.js, src/utils/permissionSync.js, src/utils/piiCrypto.js, src/utils/queryBudget.js, src/utils/reauthTicket.js, src/utils/scopeCast.js, src/utils/searchPatterns.js, src/utils/shutdownBudget.js, src/utils/superAdmin.js, src/utils/temporaryPassword.js, src/utils/tokenPurpose.js, src/utils/totp.js, src/utils/transaction.js, src/utils/validationRules.js, src/utils/xlsxWriter.js, src/utils/zipContainer.js

（注：xlsxWriter.js 与 zipContainer.js 头部已如实自报「不写 ZIP64」「文件名仅 ASCII」等已声明边界，按「已声明的已知取舍」不计为发现；logPiiMask.js 的宽 redact 策略、loginCipher.js 的无前向保密亦为明示取舍。）

### be-constants（49 个：有发现 5 + 1 个证据并入文件，无发现 43）

有发现：
- src/constants/audit.js — 1 条（P3）— username 闸取舍论断的注释语句 garbled，不可读。
- src/constants/breachedPasswords.js — 1 条（P3）— 文件头小节标题语句粘连、缺标点。
- src/constants/privilegeGrant.js — 1 条（P3）— GRANT_LIST_FIELDS 等共享白名单未 Object.freeze，与同目录冻结纪律不一致（同型含 src/constants/dataScopeFields.js:20，并入本条计）。
- src/constants/honeypotDecoy.js — 1 条（P3）— 分钟换算字面量 60000 与 honeypotDecoyShape.js 的 MIN 重复。
- src/constants/honeypotAccounts.js — 1 条（P3）— matchHoneypotName 默认参数每次重新解析诱饵名单，画像循环下最多 5000 次/请求。
- src/constants/dataScopeFields.js — 0 条独立（privilegeGrant P3 冻结一致性的同型引用，与 privilegeGrant.js 同条计）。

无发现（43）：src/constants/alarm.js, src/constants/attackEvents.js, src/constants/attackProfile.js, src/constants/backupObjectives.js, src/constants/banRefusalReason.js, src/constants/businessRetention.js, src/constants/canaryAccounts.js, src/constants/credentialShape.js, src/constants/dataClassification.js, src/constants/detectionObjectives.js, src/constants/deviceAlerts.js, src/constants/deviceStatus.js, src/constants/failOpenSites.js, src/constants/honeypotDecoyAggregates.js, src/constants/honeypotDecoyAggregatesData.js, src/constants/honeypotDecoyAlarms.js, src/constants/honeypotDecoyData.js, src/constants/honeypotDecoyDevices.js, src/constants/honeypotDecoyFiles.js, src/constants/honeypotDecoyIds.js, src/constants/honeypotDecoyInspections.js, src/constants/honeypotDecoyListQuery.js, src/constants/honeypotDecoyListShape.js, src/constants/honeypotDecoyMetrics.js, src/constants/honeypotDecoyRbac.js, src/constants/honeypotDecoySelf.js, src/constants/honeypotDecoyShape.js, src/constants/honeypotDecoyUsers.js, src/constants/honeypotPersonas.js, src/constants/honeypotRouteTable.js, src/constants/honeypotTicketGate.js, src/constants/inspection.js, src/constants/ipList.js, src/constants/ipLocationCodes.js, src/constants/permission.js, src/constants/probePaths.js, src/constants/reportExportColumns.js, src/constants/reportExportLabels.js, src/constants/retention.js, src/constants/runtime.js, src/constants/securitySuggestions.js, src/constants/stuffingProfile.js, src/constants/timezone.js

### be-controllers（40 个：有发现 2，无发现 38）

有发现：
- src/controllers/securityController/overview.js — 1 条（P3）— buildComplianceSection 的 catch 静默吞异常，服务端零日志。
- src/controllers/privilegeController.js — 1 条（P3）— listGrants 查询参数原样透传，依赖单一路由校验闸，属纵深防御缺口。

无发现（38）：src/controllers/alarmController.js, src/controllers/auditController.js, src/controllers/authController/credentials.js, src/controllers/authController/index.js, src/controllers/authController/profile.js, src/controllers/authController/session.js, src/controllers/authController/shared.js, src/controllers/avatarController.js, src/controllers/deviceController.js, src/controllers/forensicController.js, src/controllers/inspectionController.js, src/controllers/inspectionGuards.js, src/controllers/ipListController.js, src/controllers/ipListSegmentGuards.js, src/controllers/ipListWriteGuards.js, src/controllers/mfaController.js, src/controllers/permissionController.js, src/controllers/reportController.js, src/controllers/roleController.js, src/controllers/roleGuards.js, src/controllers/rolePermissionController.js, src/controllers/securityController/account.js, src/controllers/securityController/admin.js, src/controllers/securityController/attackEvents.js, src/controllers/securityController/config.js, src/controllers/securityController/index.js, src/controllers/securityController/profile.js, src/controllers/securityController/reauth.js, src/controllers/securityController/sensitive.js, src/controllers/securityController/shared.js, src/controllers/securityController/upgrade.js, src/controllers/userController/create.js, src/controllers/userController/delete.js, src/controllers/userController/index.js, src/controllers/userController/read.js, src/controllers/userController/roles.js, src/controllers/userController/shared.js, src/controllers/userController/update.js

### be-middleware（33 个：有发现 2，无发现 31）

有发现：
- src/middleware/idempotency.js — 2 条（P3）— 2xx 收尾 updateOne 缺守卫条件，迟到收尾可覆盖他人判据行；res.end 包装丢弃第三参数 callback。
- src/middleware/tokenBlacklist.js — 1 条（P3）— exp 非数值时 NaN 守卫失效，参数错误被放大成持久化故障告警。

无发现（31）：src/middleware/auth.js, src/middleware/dataScope.js, src/middleware/errorHandler.js, src/middleware/httpMethods.js, src/middleware/index.js, src/middleware/injectionSignature.js, src/middleware/logoutAuth.js, src/middleware/metricsAuth.js, src/middleware/noStore.js, src/middleware/originCheck.js, src/middleware/protocolCompliance.js, src/middleware/queryLimit.js, src/middleware/rateLimit.js, src/middleware/rateLimitStore.js, src/middleware/rbac.js, src/middleware/requestId.js, src/middleware/security/auditLog.js, src/middleware/security/earlyRejection.js, src/middleware/security/forensicCapture.js, src/middleware/security/index.js, src/middleware/security/ipBlacklist.js, src/middleware/security/ipBlacklistStore.js, src/middleware/security/reauthCredentialRules.js, src/middleware/security/reauthTicket.js, src/middleware/security/sanitize.js, src/middleware/security/securityHeaders.js, src/middleware/sentry.js, src/middleware/staticFrontend.js, src/middleware/userAuthCache.js, src/middleware/validateObjectId.js, src/middleware/validateQuery.js

（复核说明，非发现：rateLimit.js:392/497 的 username meta 风险已在 logger.js sanitizeLogRecords 中央收口；earlyRejection.js/injectionSignature.js 的 `AuditLog.record` 无 unhandledRejection 风险；dataScope.js GUEST `{type:'all'}` 为文档化设计；ipBlacklist/idempotency 的 fail-open 均已登记告警指标。）

### be-models-config（41 个：有发现 4，无发现 37）

有发现：
- src/models/FireAlarm.js — 1 条（P3）— $each 批量 push 绕过 200 条封顶且不累加 processLogCount（当前写入点不可达）。
- src/models/IPBlacklist.js — 1 条（P3）— 过期记录惰性清理吞掉全部错误，删除失败不可见。
- src/models/SystemConfig.js — 1 条（P3）— set() 把 null 值的 valueType 标成 'string'，元数据失真。
- src/models/AuditLog.js — 1 条（P3）— hash 字段注释的行号锚点已失效，应改函数名锚点。

无发现（37）：src/models/ConsentRecord.js, src/models/FireDevice.js, src/models/ForensicCapture.js, src/models/IdempotencyRecord.js, src/models/Inspection.js, src/models/Permission.js, src/models/PrivilegeGrant.js, src/models/ReauthGrant.js, src/models/ReauthTicketUse.js, src/models/Role.js, src/models/TokenBlacklist.js, src/models/User.js, src/models/UserAvatar.js, src/models/UserSession.js, src/models/auditLogHooks.js, src/models/auditLogQueryStatics.js, src/models/auditLogSanitizer.js, src/models/auditLogWriteStatics.js, src/models/index.js, src/config/buildInfo.js, src/config/corsOrigins.js, src/config/database.js, src/config/deploymentCredentialGuards.js, src/config/envSemantics.js, src/config/immutableConfigGuard.js, src/config/index.js, src/config/jwtRotation.js, src/config/legacyCbcGuard.js, src/config/loginEncryptGuard.js, src/config/loginGuard.js, src/config/proxyProtocol.js, src/config/secrets.js, src/config/swagger.js, src/config/transportSecurity.js, src/config/trustedProxies.js, src/config/upgrade.js, src/config/validate.js

### be-core（25 个：有发现 7，无发现 18）

有发现：
- src/docs/openapi.json — 1 条（P2）— 创建设备接口文档契约与路由校验矛盾，按文档集成必然 400（生成器同源 src/docs/generate.js:651-674）。
- src/docs/generate.js — 3 条（P3）— /audit-logs/verify 缺 X-Reauth-Ticket 登记；/view-sensitive requestBody 缺 targetUserId 与二次验证凭据字段；/metrics 的 security 声明与实际 metricsAuth 鉴权不符。
- src/plugins/autoIncrement.js — 1 条（P3）— maxPersistedSeq 注释与正则实现不符，只数 ≥4 位定宽序号（存量短序号待确认）。
- src/cluster.js — 2 条（P3）— parseInt 宽松解析致配置漂移不告警；补 fork 定时器未 unref()。
- src/routes/alarmRoutes.js — 1 条（P3）— 同一文件内校验消费双口径并存，后续新增路由易漏一侧。
- src/routes/wellKnownRoutes.js — 2 条（P3）— 三个限流器三份逐字复制应抽工厂；security.txt 联系邮箱缺省时静默回落占位符。
- src/index.js — 1 条（P3）— 24 小时轮询间隔魔法数字内联，无具名常量与注释。

无发现（18）：src/app.js, src/routes/attackEventRoutes.js, src/routes/attackProfileRoutes.js, src/routes/authRoutes.js, src/routes/avatarRoutes.js, src/routes/deviceRoutes.js, src/routes/forensicRoutes.js, src/routes/index.js, src/routes/inspectionRoutes.js, src/routes/permissionRoutes.js, src/routes/reportRoutes.js, src/routes/roleRoutes.js, src/routes/securityRoutes.js, src/routes/stuffingProfileRoutes.js, src/routes/userRoutes.js, src/routes/versionRoutes.js, src/data/README.md, src/data/ip2region.xdb

（说明：src/data/ip2region.xdb 为二进制数据文件，已按结构核验——文件头对应 v2.0 xdb、创建时间戳 2024-02-28，与 README.md 登记的版本/大小 11,070,083 字节一致；src/docs/openapi.json 已逐行读完并与 generate.js 抽样对账，其余枚举均与 constants 同源一致。）
# 第二部分：后端测试（src/tests/，884 文件）

> 本部分由 18 份分区审计报告汇编而成（tests-services-1~4、tests-controllers-1~2、tests-utils-1~2、tests-deploy、tests-ci、tests-security、tests-middleware、tests-obs-config、tests-const-models、tests-subdirs、tests-root-1~3）。全部行号原样保留自输入报告；跨报告重复主题已归并并保留各自出处。

## 2.1 分区概览

| 分区 | 文件数（应审/报告实记） | P0 | P1 | P2 | P3 | 一句话评语 |
|---|---|---|---|---|---|---|
| tests-services-1 | 52/52 | 0 | 0 | 1 | 8 | 质量很高：stamp 隔离、afterAll 清理、前提自证普遍；P2 为 RESPONSE_EXCLUDE 断言在 mock 下退化为恒可满足，其余为清理与源码计数闸类 P3。 |
| tests-services-2 | 52/52 | 0 | 0 | 2 | 12 | 整体很高；两处共享夹具污染（backgroundJobs 审计行/业务夹具不清理、固定用户名+固定口令不清理）为 P2，另有多处 tmpdir 不回收与 env 不还原 P3。 |
| tests-services-3 | 52/52 | 0 | 0 | 1 | 13 * | 显著高于平均；P2 为 privilegeGrantFlow 全量 deleteMany 与自身前缀清理口径自相矛盾（并行共库时互踩），另有源码计数闸、env 无 try/finally 等 P3。 |
| tests-services-4 | 50/50 | 0 | 0 | 1 | 4 | 质量很高；P2 为 walStatIntervalEnvContract 泄漏 AUDIT_WAL_PATH（姊妹文件已修同形问题），其余为 mockRestore 位置、常量 stamp 等 P3。 |
| tests-controllers-1 | 51/51 | 0 | 0 | 0 | 7 | 很高；发现均为 P3（按主题归组，涉 14 文件）：注释仍以"共享内存库"为前提（基建已改每文件独立库）、源码文本闸脆弱、清理切片错位、重复用例。 |
| tests-controllers-2 | 51/51 | 0 | 0 | 0 | 8 | 很高；全部 P3：夹具清理漏项（sesspwd、upblow、cache_* 等）、用例名内嵌已漂移源码行号、直接操作 statsCache._store 私有字段。 |
| tests-utils-1 | 39/39 | 0 | 0 | 0 | 6 | 显著高于水准；P3：密钥 env 不恢复（依赖 setup.js 兜底）、doMock 泄漏、"到期删除"判据被兜绿、200MB 解压炸弹放大 OOM 风险。 |
| tests-utils-2 | 39/39 | 0 | 0 | 0 | 9 | 很高；P3：共享库写入不清理、dropCollection 死代码、queryBudget 闸未剥注释可被注释骗绿、空洞的缓存命中断言。 |
| tests-deploy | 70/70 † | 0 | 0 | 0 | 6 | 显著高于常见；P3 集中在 4 个文件泄漏 tmpdir 临时目录（每轮约 40+ 个）、夹具 `\n` 误写 `/n`、固定文件名写仓库根。 |
| tests-ci | 51/51 | 0 | 0 | 0 | 7 * | meta-gate 集群，"前提自证+反向对照+判据非恒真"三件套齐全；P3：吞退出码形态漏 `|| echo`、精确计数棘轮、头注数字与台账不同步等文档失实。 |
| tests-security | 50/50 | 0 | 0 | 0 | 5 | 很高；P3：审计行断言缺"前提自证"（空集恒绿）、`__proto__` 腿实际到不了服务端、clearEnv 不恢复原值、午夜跨日时间边界。 |
| tests-middleware | 48/48 | 0 | 0 | 1 | 5 | 显著高于平均；P2 为 Swagger 用例 mongoose 连接不关（会导致 jest-worker 强杀并吞输出），P3 含一条恒真包装断言。 |
| tests-obs-config | 50/50 | 0 | 0 | 0 | 4 * | 成熟度高；P3：3 处 deleteMany 漏 `bypassAppendOnly` 致清理空转、logShipper 安全开关 env 泄漏、文本孤岛断言（报告按主题计 4 条，明细 6 文件各 1 条）。 |
| tests-const-models | 46/46 | 0 | 0 | 2 | 7 | 显著高于常见；P2：ConsentRecord 清理调用签名错误（第 3 参被 mongoose 8 忽略）致 append-only 清理永久空转、honeypotDecoyAggregates 键集断言恒真。 |
| tests-subdirs | 71/71 | 0 | 0 | 0 | 8 * | 显著高于一般；P3：顶层 env 不恢复、清理正则大小写失配、遗留调试日志、迁移注释与文件头覆盖声明过时。 |
| tests-root-1 | 38/38 | 0 | 0 | 0 | 5 | 高于平均；P3：append-only 清理死代码、env 三态恢复漏一项、导出断言只数行数不校验集合、JWT 签发小函数 6 文件重复。 |
| tests-root-2 | 38/38 | 0 | 0 | 2 | 3 * | 很高；P2 两处裸 `Permission.create` 播种共享唯一 code（`*:*`、`device:*`）与兄弟套件撞 E11000 假红；P3 为清理口径不一致（明细 5 条）。 |
| tests-root-3 | 36/36 | 0 | 0 | 0 | 4 * | 高于一般；P3：E2E 选择器门禁子串包含可假绿、riskLevel 清单正则只认单引号、reauth 阈值被一并钉死、fail-open 权衡被测试固化（明细 6 条）。 |
| **合计** | **884/884** | **0** | **0** | **10** | **121*** | —— |

\* 该分区报告头部自报的 P3 数与明细条目数不一致：tests-services-3（自报 13/明细 14）、tests-ci（7/8）、tests-obs-config（4/6）、tests-subdirs（8/9）、tests-root-2（3/5）、tests-root-3（4/6）。表中取报告自报值；按明细条目口径全部分区 P3 合计为 **130**。
† tests-deploy 报告概览括号内写"全部 69 个测试/helper 文件"，与其自报审查文件数 70 及分区清单 70 行不一致；按报告"未见问题文件 64 + 有发现 6"实覆盖 70 个文件，判断为笔误。

**文件数核对结论**：18 份报告的"审查文件数"与 partitions/ 下同名清单行数**全部一致**（52/52/52/50、51/51、39/39、70、51、50、48、50、46、71、38/38、36，合计 884）。经程序化比对，每份报告中"有发现文件 ∪ 无发现文件"的并集与对应分区清单**逐一相等**（无多报、无漏报；services-3 的 4 个跨文件发现文件与 services-4 合并条目涉及的 4 个文件均在清单内）。

## 2.2 重点发现（P2 逐条展开；本部分无 P0/P1）

格式：`路径:行号` | 维度 | 问题描述 | 证据 | 修复建议。

1. `src/tests/services/auditExportService.test.js:8-11、76` | 假绿风险（断言退化） | 对 `RESPONSE_EXCLUDE` 的断言在 mock 下退化为 `toHaveBeenCalledWith(undefined)`，钉不住清单内容：mock 工厂只提供 `countDocuments`/`find`，本文件内 `AuditLog.RESPONSE_EXCLUDE` 为 `undefined`；生产代码（src/services/auditExportService.js:80 `.select(AuditLog.RESPONSE_EXCLUDE)`）在该 mock 下实际调用 `select(undefined)`，断言恒可满足。行 72-75 注释声称"同时钉住清单挂了、且挂了没把链字段一起排除掉"，但后半句（若有人给 RESPONSE_EXCLUDE 加上 `-hash`/`-prevHash` 导致导出链摘要永远算不出）在本文件不会变红，属注释承诺了但判据没接线的测试盲区。 | 证据：`jest.mock('../../models/AuditLog', () => ({ countDocuments: jest.fn(), find: jest.fn() }));` … `expect(chain1.select).toHaveBeenCalledWith(AuditLog.RESPONSE_EXCLUDE);` | 期望值改用 `jest.requireActual('../../models/AuditLog').RESPONSE_EXCLUDE`，或直接钉字面内容（如 `expect(actual).toContain('-hmac')` 且 `expect(actual).not.toMatch(/-hash|-prevHash/)`）。

2. `src/tests/services/backgroundJobs.test.js:82-92（afterAll）+ 123-137、219-245、280-292、327-337、362-378、168-177、202-210` | 共享库夹具污染 | 本套件向共享测试库写入大量审计行（含 riskLevel=high/critical 的 brute_force_login、bulk_data_export、permission_abuse 告警行）以及设备/巡检夹具，但 afterAll 只清理 User/Role/IPBlacklist，审计行与业务夹具全部残留，形成"残留高危告警行 + 失败计数行"的跨套件污染面：任何后续按 `success:false`、riskLevel、action 维度做精确计数/聚合的套件都可能因执行顺序而漂移。 | 证据：afterAll 仅含 `await User.deleteOne({ username: \`eadmin${stamp}\` })…await Role2.deleteOne(…)…await require('../../models/IPBlacklist').deleteMany({ source: 'auto' })`（行 85-89），无任何 `AuditLog.deleteMany`；而 `await AuditLog.insertMany(docs)`（行 137、245、292）、`AuditLog.create`（行 329-336）、`auditBuffer.flush()`（行 372-378）、`FireDevice.create`（行 168-177）、`Inspection.create`（行 203-210）均无对应清理；兄弟套件（canaryWatch、bruteForceBanDimension、cursorTiebreakPagination）都按 stamp 清理。 | 在 afterAll 按本文件专用 stamp（`efail${stamp}`、`bf${stamp}`、`bf2${stamp}`、`chain${stamp}`、`bfx${stamp}`、`E-${stamp}-EXP`、`逾期_${stamp}`）补齐 AuditLog/FireDevice/Inspection 清理（append-only 集合用 `{ bypassAppendOnly: true }`，仓内已有先例）。

3. `src/tests/services/businessStateConsistencyInvariants.test.js:181-203（beforeAll）+ 48-52（afterAll）` | 共享库夹具污染 | 用无 stamp 的固定用户名创建三个真实用户（`dispatch_ok`、`dispatch_off`、`dispatch_other`），并使用固定口令 `Qz7#Lm42vTx9`，afterAll 只关闭连接、完全不清理。后果：① 用户名有唯一索引，同库复用会直接 duplicate key 报错，属顺序/环境依赖的脆弱源；② 用户是安全敏感集合，测试用户残留等于向共享库持续注入"可用账户"。此外 `makeDevice`（行 54-60）、`makeInspection`（行 271-278）、`reportAlarm`（行 205-213）产生的设备/巡检/报警也一律不清理。 | 证据：`await User.create({ username: 'dispatch_ok', … password: 'Qz7#Lm42vTx9', … })`（行 182-188、189-195、196-202）；afterAll 仅 `await mongoose.connection.close()`（行 50）。 | 用户名加 stamp 并在 afterAll 按 `_id`/stamp 删除；业务夹具按创建记录的 `_id` 回收（同分区 dashboardDataScopeApplied.test.js 的 createdDocIds 模式）。

4. `src/tests/services/privilegeGrantFlow.test.js:100-106（对照 beforeEach 117-123）` | 共享库夹具污染 / 顺序依赖（待确认） | afterAll 用 `PrivilegeGrant.deleteMany({})` 无前缀限定地清空共享库中全部临时授予，而同文件 beforeEach 特意只按 `username: /^zzpriv_/` 清理，并注明"并行跑时同库其它套件的授予不是本套件的数据"。两处口径自相矛盾：并行 worker 共用同一 Mongo 时，本套件收尾会删掉兄弟套件（如 privilegeGrantPiiHighRisk / accessReview 相关）正在使用的授予夹具，造成与执行顺序/并行度相关的偶发红。 | 证据：`await Promise.all([ PrivilegeGrant.deleteMany({}), User.deleteMany({ username: /^zzpriv_/ }), …])`。 | 改为按本套件可识别的范围清理（如 `targetUserId`/`username` 前缀集合，或记录本套件创建的 grant `_id` 列表后按 id 删）。是否实际成害取决于 CI 是否并行 worker 共库，故标"待确认"。

5. `src/tests/services/walStatIntervalEnvContract.test.js:38-43、60-66、45-54` | env 泄漏 | `AUDIT_WAL_PATH` 泄漏给同 worker 后续套件：`drive()` 每臂改写 `process.env.AUDIT_WAL_PATH`（行 64），但 `beforeAll` 未做快照、`afterAll`（行 45-54）只删除 `AUDIT_WAL_STAT_INTERVAL` 与 `AUDIT_WAL_MAX_BYTES`，最后 `rmSync` 删掉临时目录——`AUDIT_WAL_PATH` 仍指向已删除目录。同目录姊妹文件 walCapTrimFailureTaxonomy.test.js（行 50-56 注释）已明确把同一形态定性为缺陷并修复，本文件是漏网的同形问题。后果：同 worker 后续用到 auditBuffer/WAL 的套件会继承一个指向不存在目录的 WAL 路径，追加全部失败（walAppendFailures 激增），产生与被测代码无关的假红/噪声。 | 证据：`afterAll(() => { auditBuffer.stop(); delete process.env.AUDIT_WAL_STAT_INTERVAL; delete process.env.AUDIT_WAL_MAX_BYTES; … })` 中无 AUDIT_WAL_PATH 处理。 | 照抄 walCapTrimFailureTaxonomy 的做法——`beforeAll` 对 `['AUDIT_WAL_PATH','AUDIT_WAL_MAX_BYTES','AUDIT_WAL_STAT_INTERVAL']` 快照，`afterAll` 按快照还原（undefined 则 delete）。

6. `src/tests/middleware/infraParamRateLimitFailClosed.test.js:308-311、349-352` | 资源泄漏（mongoose 连接） | Swagger 组用例内 `mongoose.connect` 打开连接，但本 describe 没有任何关闭连接的 afterAll。全文件唯一的关连接 afterAll 在行 48-52，属于先跑完的兄弟 describe；且行 110/120 的 `jest.resetModules()` 已在此前执行，Swagger 用例里 `require('mongoose')` 拿到的是全新 mongoose 实例，其连接必然留存到文件结束。本仓自己的台账（src/tests/middleware/auditRefusalReason.test.js:125 注释「mongooseTeardownLedger：漏关会让 jest-worker 强杀并吞输出」）明确记载泄漏连接会导致 worker 被强杀、测试输出被吞——这是 CI 可靠性问题。 | 证据：`const mongoose = require('mongoose'); if (mongoose.connection.readyState === 0) { await mongoose.connect(process.env.MONGODB_URI); }`（:308-311；:349-352 同型，无对应关闭钩子）。 | 在 Swagger describe 增加 `afterAll(async () => { if (mongoose.connection.readyState !== 0) await mongoose.connection.close(); })`，与本文件其余 describe 及全仓惯例对齐。

7. `src/tests/models/ConsentRecord.test.js:33-35、37-42` | 清理调用签名错误（清理永久空转，污染被掩盖） | append-only 集合的清理调用把 `{ bypassAppendOnly: true }` 传成了 deleteMany 的第 3 个实参，而 mongoose 8 的 `Model.deleteMany(conditions, options)` 只有两个形参（node_modules/mongoose/lib/model.js:2054 已核实），第 3 参被整体忽略。于是 options=null，护栏钩子 `bypassed()` 读不到 bypass 标记，在 NODE_ENV=test 下照样拒绝删除；`.catch(() => {})` 再把拒绝吞掉——afterEach/afterAll 的清库是永不生效的空转，consentrecords 残留随每次运行累积（因唯一索引是 userId+policy+version、userId 每次新建，测试不会红，污染被完全掩盖）。 | 证据：`await ConsentRecord.deleteMany({}, null, { bypassAppendOnly: true }).catch(() => {});`（行 34、38 两处）。 | 改成与 AuditLog 套件一致的两参形式 `deleteMany({}, { bypassAppendOnly: true })`；同时建议把 `{}` 过滤器收窄为测试专用的 username/前缀——一旦修好签名，无过滤的全表清空在共享内存库上会误删并行 worker 里 consentRecordIpUaGuard 套件刚写入的行，引入跨 worker 竞态。

8. `src/tests/constants/honeypotDecoyAggregates.test.js:218-225` | 恒真断言 / 覆盖盲区 | 用例标题承诺"键集与键序对真实控制器/服务逐 token 有序核对"，但对被测载荷 `hit.data` 的键集断言是恒真式：`expect(Object.keys(hit.data)).toEqual(expect.arrayContaining([]));`——任何数组都包含空数组，永远绿。该用例实际只核对了控制器源码文本里 token 的出现顺序，10 个聚合端点的诱饵载荷键集/键序是否与真实控制器同形，这一闸完全没有验证；若诱饵 builder 漏键/换序，本闸不会红（grant-list、device-expiring 两处有各自的专用键序用例，其余 8 个端点无此覆盖）。 | 证据：`expect(orderedTokens(codeOf(item.file), tokens)).toBe(true); expect(Object.keys(hit.data)).toEqual(expect.arrayContaining([]));` | 把恒真断言替换为真实比对，例如 `expect(Object.keys(hit.data)).toEqual(tokens)`（按各端点的真实键集逐一定义期望），让"诱饵与真实面同形"的承诺可证伪。

9. `src/tests/inspectionAssigneeExists.test.js:34` | 顺序依赖 / 跨文件假红 | 用裸 `Permission.create` 播种共享通配权限 `*:*`，而 `Permission.code` 有唯一索引（src/models/Permission.js:25 `unique: true`）。同目录及同 worker 库的大量其他套件都在播种同一个 code（inspectionArrayCaps.test.js:39-43、inspectionFindingPhotoUrl.test.js:36-40、inspectionInputBoundary.test.js:73-77、inspectionWriteScopeGates.test.js:65-69，均用 findOneAndUpdate upsert；其他分区的 auditExportDataScope.test.js:52 也是裸 create）。两个播种文件落进同一 worker（worker 内共享同一个测试库，见 globalTeardown.js 注释）时，后跑的那个 `beforeAll` 必然撞 E11000 唯一键，整文件假红——正是本仓 fullRangeInactiveSuperAdmin.test.js 头注（P2-19）记录并修过的同类问题。 | 证据：`const perm = await Permission.create({ name: '通配', code: '*:*', module: 'system' });` | 改成与兄弟文件一致的 `findOneAndUpdate({ code: '*:*' }, { $setOnInsert: {...} }, { upsert: true, new: true })`。

10. `src/tests/loginPermissionSnapshotNulls.test.js:53-59（配合 74-90）` | 顺序依赖 / 跨文件假红 | `makePerm` 用裸 `Permission.create` 创建固定全局 code 的权限（`device:read`、`device:list`、`device:create`、`device:purge` 等，无时间戳后缀），而行 76-77 的角色 code 也是固定值 `ZZQO_${suffix}`。src/tests/security/adversarialProbeRegression.test.js:74-75 会对 `device:read` 做 upsert 播种；两个文件同 worker 时，后跑方在 `beforeAll` 撞 E11000（Permission.code 唯一索引）整文件假红。另外固定 code 在 `--watch` 复用同一内存库重跑时同样会撞唯一键（globalTeardown.js 注释明确说 watch 模式可能复用实例与残留库）。 | 证据：`code: \`device:${action}\`` 与 `code: \`ZZQO_${suffix.toUpperCase()}\``。 | 权限播种改 upsert，或给 code 加本文件 stamp 后缀（角色 code 同理），消除与 adversarialProbeRegression 等文件的碰撞面。

## 2.3 P3 发现汇总

按主题归组；每条一行，格式 `路径:行号` — 一句话。同一报告内同主题多条已并列；跨文件条目保留全部出处。

### 主题 A：临时目录 / 子进程产物不回收
- `src/tests/services/auditAnchorSink.test.js:846-852` — writeTemp() 每次 http-sink 用例都在 os.tmpdir() 新建目录且从不删除，多次全量跑持续累积 audit-anchor-http-*。
- `src/tests/services/forensicManifest.test.js:40（及全文 20+ 处调用）` — mkdtempSync('fc-manifest-') 创建的临时目录从不删除。
- `src/tests/services/forensicManifestLock.test.js:17、40-44` — 临时目录与写入的 _child1.js/_child2.js 子进程脚本均不清理。
- `src/tests/services/forensicManifestRetention.test.js:11（及行 18、65、100 等调用）` — 临时目录一律不回收。
- `src/tests/services/forensicManifestReconcile.test.js:59、77、99、120、140、147、213` — 内联 mkdtempSync 对账目录多数不删除（仅行 224 的用例删了自己那个）。
- `src/tests/middleware/staticFrontend.test.js:17-27` — makeFixtureDist() 每次新建 dist-fixture-* 目录，全文件 6 次调用从不清理。
- `src/tests/deploy/backupTransport.test.js:27-28（全文件 0 处 afterEach/afterAll/rmSync）` — 每用例 makeWorkspace() 的临时目录（含桩产物与假连接串）从不删除，每轮泄漏约 10 个。
- `src/tests/deploy/hotUpgradeAgent.test.js:30-31、104` — makeEnv() 与 HMAC 夹具每用例 mkdtempSync，无任何清理钩子，每轮泄漏约 20 个 fsms-upgrade-*/fsms-hmac-* 目录。
- `src/tests/deploy/hotUpgradeOfflineDispatch.test.js:59-60` — 每用例创建 fsms-offline-dispatch-* 目录，无任何 rmSync/afterAll，每轮泄漏 4 个。
- `src/tests/deploy/offlineBundleScan.test.js:49-51` — makeRoot() 每用例创建 fsms-bundles-* 临时根（"封顶"用例一次写入 MAX_INVALID+MAX_AVAILABLE+6 个包目录），每轮泄漏约 9 个。
- `src/tests/deploy/auditAllowlistGate.test.js:209、283、303-306、327-333` — 5 处把临时 JSON 写进仓库根目录固定文件名（虽有 finally unlink）：污染工作区，且两个并发 jest 进程下固定文件名互相覆盖会偶发红。

### 主题 B：数据库夹具不清理 / 清理不完整 / 清理过宽
- `src/tests/services/alarmDispatchScopeMatrix.test.js:36-40` — 夹具用户名固定（dsx_op/dsx_mate/dsx_far）无 stamp，运行中途被强杀后残留行会让下一轮 User.create 以 E11000 失败且报错点在夹具。
- `src/tests/services/auditChainBatchCastParity.test.js:155-202` — "真实落库往返"向共享内存库 insertMany 带 hash 的链首记录，afterAll 只关连接不删数据，会进入任何未过滤的全窗核验探针。
- `src/tests/services/auditChainResign.test.js:22-32` — 写入 3 条 chain_resign_test 记录，afterAll 只关连接，无清理，长期累积。
- `src/tests/services/backgroundJobs.test.js:87-89` — afterAll 的 `deleteMany({ source: 'auto' })` 清理范围过宽，会删掉共享库中所有自动封禁行（含其他套件夹具）。
- `src/tests/services/authRegisterDuplicateKey.test.js:26-37` — beforeAll 写入 SystemConfig 全局配置行 registerCaptchaEnabled=false，afterAll 不删除，影响同 worker 后续未 mock 验证码开关的注册路径用例。
- `src/tests/services/honeypotDecoy.test.js:97-105` — afterAll `deleteMany({ action: 'honeypot_probe' })` 不带 username 过滤，连带删除其他套件（honeypotDecoyFiles 的 filetrap 账户）写入的探测行。
- `src/tests/services/permCacheLifecycle.test.js:90-94、131-137` — 固定用户名 permcache_survivor/permcache_remote 无 stamp 且创建前不预清理，上轮崩溃残留会使本轮 User.create 直接 E11000。
- `src/tests/services/permissionCacheDegradedTtl.test.js:38-42` — 固定用户名 permcache_p3（afterAll 有清理但 beforeAll 无预清理），同上风险。
- `src/tests/services/permissionHotReload.test.js:265-270` — afterAll 只关连接，不清理 HOTRELOAD_* 角色（含一个 `*:*` 超级权限角色）、hr_admin_*/hr_target_* 用户与 hotreload:* 权限，在共享测试库长期累积。
- `src/tests/services/piiExportQuotaWatermark.test.js:30-39、53-99` — 固定 username 'quota-user'、无 stamp，向真库 auditlogs 写约 20+ 条 view_sensitive_data 审计行，afterAll 只关连接完全不清理，append-only 集合残留跨运行累积。
- `src/tests/controllers/ipListFullRangeGrantAndRescueSymmetry.test.js:132-139` — afterAll 清理切片错位：createdIds=[secRoleId,uSuperId,uSecId]，slice(0,2)/slice(2) 使 uSec 用户与 secRole 角色均未被清理（每文件独立库下暂无实害）。
- `src/tests/controllers/sessionManagement.test.js:56-71、361` — afterAll 声称回收自建账号，但行 361 创建的 sesspwd 用户及其会话不在清理清单。
- `src/tests/controllers/permissionUserValidationGuards.test.js:190-202、502-509` — afterAll 清理正则漏掉行 503-509 创建的 upblow${stamp} 用户。
- `src/tests/controllers/permissionCacheInvalidation.test.js:102-106` — afterAll 仅关连接，不回收固定名夹具：cache_admin/cache_target 用户、CACHE_* 三角色、cacheprobe:* 权限。
- `src/tests/controllers/permissionValidationAndCycleGuards.test.js:71-76、100-305` — perm_admin 用户与 batchok:*/dupe:*/orphan:*/cycle*:*/pwa:* 等权限文档均不在 afterAll 回收。
- `src/tests/controllers/reportExportInputGuards.test.js:598-648、313` — B-4 行序用例创建的 3 条报警种子（ORD${stamp}A/B/C）不在 afterAll 清理正则 `^REXP[AB]${stamp}` 覆盖内。
- `src/tests/utils/auditChainSurrogateArtifact.test.js:61-80` — beforeAll 向真库写入含恶意 user-agent/body 的 AuditLog，afterAll 只关连接、未像同分区同类文件显式 deleteMany（独立库+globalTeardown 兜底，属口径不一致）。
- `src/tests/utils/tails.test.js:40-58` — upsert 的 `*:*` 权限、可能残留的 ADMIN 角色、AuditLog 审计行均未在 afterAll 清理（afterAll 64-73 只清 user/role/device/IPBlacklist）。
- `src/tests/models/auditChainConcurrency.test.js:22-28` — 每次运行向共享 auditlogs 写 40 条 chain_conc_<ts>_* 记录且永不清理（注释自认"留库无副作用"，仅适用于一次性库）。
- `src/tests/routes/bodyTypeGate.test.js:106` — afterAll 角色清理正则 `^${stamp}`（小写）匹配不到 `${stamp}role`.toUpperCase() 的大写角色码，清理意图落空。
- `src/tests/routes/referenceArrayBoundary.test.js:104` — 同上：`^${stamp}` 匹配不到 roleCode() 产生的大写码，BADP/GOOD/ASG/KEEP/ASSIGN 等角色全部残留。
- `src/tests/inspectionAssigneeExists.test.js:68-74` — afterAll 只回收 Inspection 与 User，未回收本文件创建的 Role（ZZIA_${stamp}）与权限，与同目录兄弟套件口径不一致。
- `src/tests/loginPermissionSnapshotNulls.test.js:46-51` — afterAll 只删用户，创建的角色（ZZQO_*）与权限（device:*）全部留在 worker 库。
- `src/tests/inactiveRoleAuthorization.test.js:45-49` — beforeAll 创建的 1 用户、2 角色（ACTIVE_/INACTIVE_${stamp}）、2 权限，afterAll 仅关连接不回收。
- `src/tests/inspectionArrayCaps.test.js:66-72` — afterAll 未回收本文件创建的 Role（ZZAC_${stamp}），同目录其余三个 inspection 套件均回收。

### 主题 C：append-only 集合"死清理"（调用不生效）
- `src/tests/models/consentRecordIpUaGuard.test.js:29-32` — afterAll 的 deleteMany 未带 bypassAppendOnly，ConsentRecord 护栏拒绝后被 .catch 吞掉，是永不生效的死清理，p3consent_* 跨运行残留。
- `src/tests/observability/auditBufferOutageKeepsAudit.test.js:119` — afterEach 清理未传 `bypassAppendOnly: true`，被 append-only 钩子拦截后 `.catch(() => {})` 静默吞掉，清理空转（真实落库的审计行留在本文件库中）。
- `src/tests/observability/auditBufferShutdownDrain.test.js:112` — 同上，用例①/⑥ realInsertMany 落库的记录因此留库。
- `src/tests/observability/auditWalTrimIsPrecise.test.js:93` — 同上（本文件 insertMany 已 mock 暂无实际残留，但写法与同仓契约不一致）。
- `src/tests/auditSpecialKeyPayload.test.js:81-88` — afterAll 的 `AuditLog.deleteMany(...).catch(() => {})` 未传 bypassAppendOnly，静默失效；带 `$` 前缀/点号键的探针审计行永远留库（另注：行 162-163 "本库按 worker 共享"注释在每文件一库拓扑下已过时）。

### 主题 D：env / 全局状态 / mock 状态泄漏
- `src/tests/services/forensicCapture.test.js:276-299、301-329、354-360` — env 与 mock 状态还原未包 try/finally，断言失败即泄漏到同 worker 后续套件（文件头自称"env 泄漏收口"但这几处失败路径会漏）。
- `src/tests/services/forensicTrigger.test.js:169-187、189-225` — FORENSIC_TRIGGER_ENABLED/MAX_IPS 的设置与还原均无 try/finally。
- `src/tests/services/honeypotSocketGate.test.js:126-135` — HONEYPOT_ENABLED 置 'false' 后在用例末尾才置回，未用 try/finally，中间断言失败即把关闭态泄漏给后续用例（随机序下放大）。
- `src/tests/services/honeypotWatch.test.js:205-224、310-318` — HONEYPOT_USERNAMES/HONEYPOT_ENABLED 两处 env 在用例末尾才恢复，无 try/finally。
- `src/tests/services/initDataLifecycle.test.js:122-127（beforeEach）及行 610、641、673、709、1306、1406、1453、1474` — 用例内 SUPER_ADMIN_USERNAME、ADMIN_INITIAL_PASSWORD 等 env 只删不改回，afterAll 亦不还原，残留同 worker。
- `src/tests/services/upgradeService.test.js:32、55-62` — 原值未设时注入 HMAC_SECRET 测试密钥且 afterAll 不还原，会污染断言"HMAC_SECRET 缺失 ⇒ fail-closed"的后续用例。
- `src/tests/utils/encryption.test.js:8-15` — beforeAll 写入 AES_SECRET_KEY/HMAC_SECRET 后全文不恢复（依赖 setup.js 每文件重置兜底，仅同文件内新增"密钥缺失"用例时受扰）。
- `src/tests/utils/bcryptWorkerPool.test.js:34、46` — 前两用例 jest.doMock('bcryptjs') 后未在自身范围 dontMock，mock 注册泄入本文件后续 isolateModules 沙箱，防御责任落在第 4 个"受害"用例上。
- `src/tests/security/businessRetentionAndAnonymization.test.js:32-35` — clearEnv 在 beforeEach/afterEach 无条件 delete 且不恢复原值，若 CI 环境本就设了 BUSINESS_RETENTION_DAYS_* 会被永久删除（同目录 backupPatrolAndDrillRecency、jwtKeyRotation 均为"保存+恢复"口径）。
- `src/tests/observability/logShipperTransportFailurePaths.test.js:59-66` — 模块顶层设置 LOG_SHIPPING_ALLOW_PRIVATE_HOSTS/LOG_SHIPPING_ALLOW_INSECURE 两个安全开关 env 从不还原（afterAll 只还原 setInterval spy），可致同 worker 后续"默认拒绝私网"用例顺序相关偶发红。
- `src/tests/config/deploymentCredentialGuards.test.js:194-204` — withMockedExit 里 logger.error 的 spy 从不 restore（process.exit 有 finally 归还），影响限本文件但与逐项恢复纪律不一致。
- `src/tests/models/ForensicCapture.test.js:146-162` — isolateModules 回调内对 BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE 的 delete/赋值/恢复无 try/finally，任一 expect 失败即残留到同 worker。
- `src/tests/routes/upgradeEndpoint.test.js:21-26（对照 afterAll 126-135）` — 5 个 env 模块顶层设置且 afterAll 不恢复；setup.js 每文件只重置 NODE_ENV/JWT/AES/HMAC/CORS，UPGRADE_ENABLED='true'、HOT_UPGRADE_REGISTRY_ALLOWLIST、UPGRADE_AGENT_STALE_SECONDS 及指向已删目录的 UPGRADE_QUEUE_DIR 会泄漏到同 worker 后续文件。
- `src/tests/routes/wellKnown.test.js:31-35、52-58` — env 快照恢复未包 try/finally（同文件行 61-79 已用 try/finally，口径不一），await/expect 抛错即泄漏。
- `src/tests/auditWalLimitsAndLines.test.js:22-25、35-43` — saved.max 快照了 AUDIT_WAL_MAX_BYTES 却从未用于恢复，afterEach 无条件 delete（同函数对 saved.interval 有完整三态恢复，唯独漏 max）。
- `src/tests/logShipperSchemeAllowlist.test.js:83` — 模块顶层直接 `process.env.LOG_SHIPPING_ALLOW_INSECURE = 'true'` 且从不恢复（本文件其余用例行 181-193 均有 save/restore），泄漏到同 worker 之后运行的所有文件。

### 主题 E：顺序依赖 / 并行互踩 / 时间与环境边界（多带"待确认"）
- `src/tests/services/initDataLifecycle.test.js:134-147` — resetDb() 对共享库全量清空（User/Role/Permission/TokenBlacklist/SystemConfig 的 deleteMany({})），并行 worker 共库时会清掉兄弟套件夹具（待确认 CI 拓扑）。
- `src/tests/services/initDataParentConvergence.test.js:42、89、111、131` — 每个用例开头 Permission.deleteMany({}) 全量清空权限集合，与 initDataLifecycle 等套件并行互踩（待确认）。
- `src/tests/services/inspectionOverdueRemainsWorkable.test.js:86、179、191、206、212` — 直接调用全局 markOverdueInspections()，会把全库所有到期在途巡检改写为 overdue，共享库下翻掉兄弟套件夹具（待确认）。
- `src/tests/services/permissionSoftDelete.test.js:339-345` — estimatedDocumentCount() 前后比对建立在"共享集合无并发写"假设上；行 203-225 "启动自愈"用例会把内置权限 user:read 软删再恢复，期间全局可见（待确认）。
- `src/tests/security/statsAnomalyScope.test.js:114-163、268-295 与 src/tests/security/stuffingProfileReadExit.test.js:47-83、177-202` — 两文件都以"种子时刻与断言时刻落在同一业务日"为隐含前提，业务时区午夜附近跨日执行会假红；概率极低、属已知取舍，建议种子改用"当前业务日正午"锚点。
- `src/tests/models/auditListTiebreakExplain.test.js:47-61` — syncIndexes 后对共享集合 auditlogs 的真实物理索引做 explain 断言；并行 worker 会在同一共享内存库上 dropIndexes+重建，并发时可能拿到被 drop 空的索引集而偶发红（待确认）。
- `src/tests/migrateConfigFailClosed.test.js:103-109（对照文件头 14-16）` — 迁移目标库判据在未设 ALLOWED_SOURCE_DB 时整体放行（fail-open），且该宽松已被本用例钉成回归锚，断言还锚定中文提示文案；属已文档化的待决权衡，建议保持待办可见（标注：待确认，勿当缺陷整改）。

### 主题 F：恒真 / 空洞断言与覆盖盲区
- `src/tests/services/authRegisterDuplicateKey.test.js:39-61` — 撞键归一臂只注入 username_ci 一种 keyPattern，服务注释声称的 emailKey_1 分支无任何用例触达。
- `src/tests/utils/apiErrorHttpJsonAndLimitGuards.test.js:309-317` — 用例名声称"到期条目在清理周期被删除"，但 captchaService.verify 自带过期判定，推进假时钟后无论是否真被 pruneLocal 删除都返回 false；"到期条目真的从存储中被移除"无可证伪断言。
- `src/tests/utils/pureModules.test.js:287-291` — "命中缓存（两次结果一致）"用例 `expect(second).toEqual(first)` 无法区分命中缓存与重新查库，是空洞断言（文件 293-296 已自陈，随后 invalidate 用例补上真判据）。
- `src/tests/security/adversarialProbeRegression.test.js:245-257` — "审计日志不含明文口令"用例缺"审计行确实存在"的前提自证，recent 为空时循环零执行、用例恒绿（当前 login.js:103 有写数据，属健壮性缺口而非恒真空转）。
- `src/tests/middleware/infraParamRateLimitFailClosed.test.js:390-406` — "超出配额后返回 429"与前案共用同一模块级 swagger.docsLimiter 单例计数桶，声明顺序下桶已满 ⇒ 循环第 1 发即 429、用例空转通过；行 393 注释"用独立 app 验证限流器本身"与事实不符（app 独立但 store 共享）。
- `src/tests/middleware/securitySanitizeAndBlacklistDegrade.test.js:552-558` — "GET 敏感读取 → 包装响应并走审计"用例的包装断言只有 `expect(typeof res.json).toBe('function')`（恒真），"走审计"也无任何 auditBuffer.push/AuditLog.record 断言，删除包装逻辑该用例仍绿。
- `src/tests/config/deployScriptInvariants.test.js:276-285` — "compliance-check 的留存检查不再是恒真断言"仍是文本孤岛断言：把 `meetsMinimum && !wasAdjusted` 改成 `meetsMinimum`（机制破坏、标识符保留）时 33/33 全绿；文件头行 12-17 已自陈，属已知残留风险。
- `src/tests/auditExportDataScope.test.js:29-41、110-116` — rowOf 只数 xlsx 数据行数、从不校验导出的是哪些行：凡恰好返回 3 行的错误实现照样双绿；建议把"行数相等"升级为"集合相等"。

### 主题 G：源码文本闸 / 精确计数棘轮（多为有意设计，重构即碎）
- `src/tests/services/alarmReporterPhoneEgress.test.js:210-211` — 把 ALARM_READ_SELECT 出现次数钉死为恰好 9，任何合法重构（新增带投影读路径/合并两处）都会红，红因与缺陷无关。
- `src/tests/services/auditChainCheckpointExitCodes.test.js:197-226` — 对 scripts/audit-chain-checkpoint.js 的正则断言把注释措辞与字面写法也钉死（如 not.toMatch(/链头与计数一致/)），改注释、改等价写法都假红。
- `src/tests/services/auditWalChainOrphanRejection.test.js:184-186、215-228` — errText 站点数、.catch 次数逐字钉死（12/6/9 及 REGISTRY 每文件 sites 值），最高脆度形态（有自证，但合法新增 catch 臂、prettier 折行都红）。
- `src/tests/services/forensicCaptureWiring.test.js:26、30` — 对 src/index.js 源码精确正则匹配（含分号/括号），Prettier/重构改写格式会误红（风险有限）。
- `src/tests/services/（跨文件）源码计数/结构闸` — observabilityWritesNeverReject.test.js:252-254、285-299、428-435（站点数==6、形参集合==['err']、errText==5 等）；rateLimitEscalation.test.js:344-368、375-383（源码先后顺序闸、同步调用点>=6）；outboundAlertContract.test.js:246-259（全仓扫描 dynamic===1，且 allEmitSites() 重复全树读盘 4 次可缓存）；recoveryCodeFormatSingleSource.test.js:35-38（按形状收割正则字面量）；permissionSoftDelete.test.js:347-352（模型源码禁含 `pre('estimatedDocumentCount'`）；privilegeGrantFlow.test.js:1236-1279、1281-1291（错误码发出点清单 toEqual 精确两站点、i18n 文案含占位符）；honeypotSocketGate.test.js:24-28、80-108（方法体切片与出现次数）——均有 fail-loud 锚点与前提自证，属有意识的架构棘轮，重构时需同 PR 更新。
- `src/tests/services/runtimeTopologyAndPerfInvariants.test.js:377-386` — `expect(src).toContain('statsCache.startCleanup()')` 是对 src/index.js 的纯文本断言，文件头行 12-16 已自证把调用搬进永不执行分支后 37 例仍全绿，是该文件唯一不能被变异杀死的判据（已登记的已知边界）。
- `src/tests/utils/auditMeta.test.js:280、341` — 路由采集正则只认单引号字面量路径（双引号/模板串/变量声明的路由被静默漏采），且 `expect(collectActions().size).toBe(110)` 是精确计数源码闸（有变更台账与规模地板自证）。
- `src/tests/utils/toolCryptoAndOriginGuards.test.js:1141-1269` — "注释与实现对齐"describe 全部判据是对注释文本的正则匹配，注释同义改写即误红（文件头已自陈该边界，且有行为面用例兜底）。
- `src/tests/utils/passwordHistory.test.js:130-133、143-144` — 接线门禁把精确表达式与局部变量名钉进正则，仅重命名局部变量就误红（文件头已声明是有意的漂移门禁取舍）。
- `src/tests/controllers/auditQuerySharedBuilder.test.js:43-65`、`auditSummaryCache.test.js:158-178`、`auditUsernamePrefixIndex.test.js:207-249`、`authUnknownOutcomeFailClosed.test.js:148-273`、`auditExportUsernamePrefixParity.test.js:333-370` — 五处源码文本闸门把实现细节（定义位置、精确子串、调用计数）钉进测试（如 summarizeByRiskLevel 恰好 2 次、withCollation 4 次/2 次、压平去注释精确代码串）；均有变异实测与闸自检佐证，属有意识的架构棘轮，建议文件头统一加"本文件含源码文本闸，重构需同步更新"总括注释。
- `src/tests/ci/fieldErrorsEgressGate.test.js:236-243` — `expect(egressSites.filter((s) => isWrapped(s.expr))).toHaveLength(51)` 是精确计数棘轮（注释记录 48→49→50→51 历次手动同步），每新增一个正确调用点都必须改本文件，可考虑改为下界+封闭登记。
- `src/tests/ci/honeypotDecoyMetricsShapeParity.test.js:191、197` — 标签域判据直接依赖 metrics 模块私有内部状态 `metrics._SERIES_STORES` 与 `metrics._MAX_SERIES`，重构内部实现会让本闸碎掉；建议升格为具名导出或注释声明"测试契约面"。
- `src/tests/middleware/errorResponseNoStore.test.js:74-85（及 176-225）` — EXIT_REGISTRY 以精确计数钉死源码形状（sites:1、funnel.callSites:17 等），有负向自证、是刻意回归闸门；同型闸还见于 securityApplyAndCategoryGuard.test.js:57、rateLimitKeyNormalization.test.js:94-97、abortedAuditReasonCleaning.test.js:107-122、writeMethodSingleSource.test.js、sentryOutboundScrub.test.js:526-572，仅需在重构时预期登记值同步成本，登记值旁维持"为什么是这个数"的一行注释。
- `src/tests/routes/authLimiterWiring.test.js:41` — 对 /mfa/enable 中间件链长用精确相等断言 `expect(chain.length).toBe(5)`，而同文件其余断言用下界；任何人插入透传中间件（即使行为等价）都会红。
- `src/tests/playwrightConfig.test.js:145-161` — countJourneys 以行首正则统计旅程数，依赖"一个 test 一行"的书写格式，多行折行会漏计致 MIN_PASSED 下界虚低（当前书写格式下成立，建议 lint 约束或改 AST 统计）。
- `src/tests/reauthLimiterBucket.test.js:92-106（对照文件头 13）` — 文件头声明"钉的是隔离性（不是阈值）"，但第一条用例把 5 次/15 分钟阈值也一并钉死；合理的阈值调整会转红且失败表象与"隔离被破坏"无法区分，容易诱导把隔离修复回退。

### 主题 H：重复夹具 / 重复代码 / 重复用例
- `src/tests/controllers/auditReportFixes.test.js:174-178` — test.each 用例表中 `['对象型 status（操作符注入）', '/api/users?status[$ne]=active']` 完全相同的参数与标签连续出现两次。
- `src/tests/controllers/attackEvents.test.js:417-439` — REGISTRY_ACTIONS 是服务层攻击注册表的手抄副本（刻意独立见证设计），服务层新增 action 且该行出现在列表时会因未同步而误红，需人工同步义务注记。
- `src/tests/{alarmHandlerCanOperate:31-36, authTemporaryLockExpiryBoundary:39-43, auditExportDataScope:75-80, deviceBuildingScope:80-84, deviceCodeCap:54-59, deviceExpiringDaysAndScrapReason:123-127}.test.js` — 测试 JWT 签发小函数 6 处各写一份且 tokenVersion 取值口径互不一致（`|| 0`/硬编码 0/`?? 0`/直取）；口令已有共享构造器（helpers/buildLoginEnvelope.js），令牌建议增加 `signTestToken(user, overrides)` 单一实现。

### 主题 I：注释 / 文档过时失实与误导性残留
- `src/tests/controllers/auditExportLimitsAndCsvEscaping.test.js:5-7、17-18` — 文件头声称守护"超上限必须拒绝；CSV 转义"两条不变式，实际只有 1 条 CSV 转义用例；上限覆盖已迁往分区外文件（由 auditExportBoundary.test.js 更名而来），注释与内容不符。
- `src/tests/controllers/auditLogs.test.js:32-34`、`auditCursorErrorSemantics.test.js:37、158-159`、`authzSessionRevocationGuards.test.js:61`、`createUserPeerRoleGate.test.js:80` — 多处注释仍以"多套件并行共享同一个内存库"为前提陈述设计理由（upsert 防 E11000 等），而 setup.js 已改为每文件独立数据库，前提不再成立；auditCursorErrorSemantics 行 158 还据此把断言放松为"位置关系"，现库已隔离可恢复更强断言。
- `src/tests/controllers/loginEncryption.test.js:7-9` — 文件头注释称"登录请求总数控制在 6 次以内"，实际约 11 次 POST /api/auth/login 且已依赖 unblockIP 缓解；后来者按该注释评估余量会撞 loginLimiter。
- `src/tests/controllers/roleControllerHierarchyGuards.test.js:384、414、445 等 26+ 处` — 大量用例名内嵌源码行号（如 "(line 203)"、"(lines 412-502)"），行号已与实现漂移（文件头 2026-09-20 复核自认"数字已漂移"），重构即失实、误导定位。
- `src/tests/utils/toolCryptoAndOriginGuards.test.js:455` — `await coll.dropCollection?.();` 是恒空转死代码（Collection 上没有 dropCollection 方法），真正的清理是下一行 dropCollection('users')；删除以免误导。
- `src/tests/ci/banRefusalEnumSingleSource.test.js:74-85` — 注释称"每个 reason 字面量都必须来自这张表（或者是 null）"，但断言要求 ipPoolBan.js 里一个 reason 字面量都不许有（比注释严格）；按注释理解写表内码会被误判红。
- `src/tests/ci/mongooseTeardownLedger.test.js:12-14 vs 110-121` — 头注称"剩 3 个从不关连接的脏文件登记在下方 LEDGER"，但 LEDGER 实际只有 2 条，数字与台账不同步。
- `src/tests/ci/mongooseTeardownLedger.test.js:66-68` — 头注称"通道本身由末尾那条'视图口径'用例用临时桩当场打死"，但文件内并不存在这条用例，注释指向一个不存在的守卫。
- `src/tests/ci/credentialDoorCheckLedger.test.js:248` — why 字段路径拼写错误 "eervices/authService/session.js:127"（应为 services/...），降低可复核性。
- `src/tests/security/adversarialProbeRegression.test.js:304-319` — 原型污染端到端用例的 `__proto__` 腿实际到不了服务端（对象字面量里的 `__proto__` 改写原型而非成为自有属性，JSON.stringify 后该键不出现在请求体），用例名/注释声称覆盖与实际不符；断言本身有效。
- `src/tests/routes/forensicRoutesContract.test.js:270-272` — 遗留临时诊断日志（注释自述"即删"但一直未删的 console.error('8d-issued-debug', ...)），仅失败路径触发，属应清理的调试残留。
- `src/tests/migrations/auditUsernameCiIndex.test.js:153-163` — M-3 注释块声称三条 key 漂移用例"对着当前迁移必然是红的"，但实核迁移 up() 现按完整 specSig 比对并删旧重建，各用例今天应全绿；注释描述修复前历史状态却用"现状"措辞，会误导读者以为 CI 存在常红用例。
- `src/tests/edge/edgeCases.test.js:1-13` — 文件头宣称覆盖四类边界，其中第 4 类（protocolCompliance）不在本文件（实际只有 auditScopeFilter/cursorPagination/ipRange 三个 describe），误导覆盖面检索。

### 主题 J：资源占用与句柄残留
- `src/tests/utils/avatarImage.test.js:578` — 解压炸弹用例在测试进程内一次性分配并压缩 200MB 缓冲，而验证目标只需超过 16MiB 夹取值；200MB 峰值叠加 workerIdleMemoryLimit '512MB' 的多 worker 并发放大 worker OOM 风险，建议降到 32MB（判据不变）。
- `src/tests/utils/proxyProtocolFrontServer.test.js:239-242、400-404` — 两处手写探针的 4 秒超时 setTimeout 在成功路径不清理，会拖住 worker 退出最多 4s（建议仿照同文件 probe() 助手补 clearTimeout）。
- `src/tests/services/websocketCorsAndReauthGuards.test.js:374、383-384` — 60 秒 setTimeout 句柄在 authenticateSocket 正常 resolve 后才 clearTimeout；该函数按契约不 reject，风险很低，仅记录。
- `src/tests/services/websocketAuthScope.test.js:252` — `server.close()` 未 await（连接已结束，仅可能留下短暂 open handle），一并归入句柄卫生。

### 主题 K：门禁加固缺口 / 判据可绕过
- `src/tests/services/backgroundJobs.test.js:247、265、273、293` — securityAlert.checkBruteForce/checkBulkExport/checkPermissionAbuse 以真实实现调用且未 spyOn dispatchNotification，若测试环境配置了告警 webhook 环境变量会发起真实外呼（同文件其他用例都 spy 了投递层；待确认 CI env）。
- `src/tests/utils/queryBudget.test.js:76-84` — 接线门禁用未剥注释的 `src.includes('withListBudget')` 判定"已接线"，违背仓内 F-145 纪律（"注释能骗过的闸等于没有闸"）；服务文件注释里提到该字样即可在真实引用被删后继续骗绿，建议先 stripComments 再匹配。
- `src/tests/ci/ciTestStepWiring.test.js:111-119` — swallowsExitCode 只识别七种吞退出码形态，漏掉同样常见的 `|| echo "..."` / `|| printf ...`，`run: npm run test:coverage || echo 'coverage skipped'` 这类写法会绕过它（当前 ci.yml 无此写法，属门禁加固缺口）。
- `src/tests/ci/fieldErrorsEgressGate.test.js:50-55、64-68` — stripComments 只剥整行注释与块注释、不剥行尾注释，`const x = safeFieldErrors(e); // 旧写法是 errors.array()` 会被当成真实出站点 ⇒ 全仓扫描判据假红（当前树无此写法，潜在假红缺口，待确认）。
- `src/tests/constants/auditActionReachability.test.js:117、135` — 路由扫描只认单引号字面量，双引号或模板串声明的路由会被静默漏扫，其派生 action 会被误判为"永不产生"登记进 NEVER_PRODUCED 台账；建议登记该限制或加显式锚点断言。
- `src/tests/playwrightConfig.test.js:224-226（配合 76-88）` — E2E 选择器门禁用子串包含判断"自研 class 在前端源码中存在"，token 若是常见词只要任意注释/标识符里出现即通过，方向上可能假绿（正是该门禁要防的"死选择器"）；建议按 class 定义形态匹配或词边界+上下文校验。
- `src/tests/riskLevelSingleSource.test.js:50-52` — 整树扫描的档位清单正则只认单引号字面量，双引号/反引号/拼接写法可静默绕过整个门禁（F-149 防的"手抄清单漂移"重新打开）；行 150-169 脏样本自检也只喂了单引号样本。
- `src/tests/reauthLimiterBucket.test.js:33-34、62-70` — 限流桶清零依赖手工枚举的 3 种回环 IP 形态（'::ffff:127.0.0.1','127.0.0.1','::1'），若真实组合键呈其他 IPv6 形态，resetKey 全部落空，"跨用例配额污染"会以偶发红形式回来。

### 主题 L：断言写法 / 失败传导 / 夹具保真
- `src/tests/services/adminPasswordAtomicWrite.test.js:98-102、112` — 核心行为断言写在 renameSync 的 mockImplementation 内部，若未来 persistInitialPassword 吞掉 rename 失败继续走，这些内部断言会静默失效；且 renameCalls[0][0] 在 rename 未被调用时抛难懂 TypeError，建议先显式断言 renameCalls.length。
- `src/tests/services/ipLocationService.test.js:91-125` — jest.spyOn(searcher,...) 的 mockRestore 写在断言之后、未置于 finally（afterEach 也无 restoreAllMocks），任一断言失败后被 mock 的 searchRaw/loadDataFile 泄漏到本文件后续用例。
- `src/tests/services/reportWorkbookExportIntegrity.test.js:157-441（13 处）、reportWorkbookService.test.js:97-305（3 处）、securityAlertGuards.test.js:116-147（2 处）、wsFlow.test.js:280-325` — mockRestore()/dontMock() 放在 await/expect 之后、不在 try/finally 或 afterEach 中，断言失败时桩泄漏到同文件后续用例（分区已有 afterEach(jest.restoreAllMocks) 的正确写法可对齐）。
- `src/tests/controllers/auditExportManifestBytes.test.js:84-91` — SinkRes 里 `json(payload) { this.body = payload; }` 以实例属性覆盖原型上的 body() 方法（同名遮蔽）；当前用例都走流式成功路径故无害，复用该桩测 json 错误出口分支会 TypeError。
- `src/tests/controllers/userStats.test.js:74-84、274-287` — 直接读写 statsCache._store 私有 Map 并临时替换其 get 方法；缓存内部结构一旦重构，全部键隔离/失效断言将集体误报或失效，建议暴露测试专用访问器。
- `src/tests/utils/permissionHelper.test.js:51-67` — 清理写在断言之后且 afterAll 只关连接，失败路径会向库残留 LV_A_*/LV_B_* 角色与 lvl_user_* 用户；建议挪入 afterAll 或 try/finally。
- `src/tests/utils/logPiiMaskLinearAndNestedCap.test.js:28-34、74-78` — 两条判据依赖真实计时（耗时比 <8、64KB 掩码 <100ms），已做 min-of-3 与分母下限缓解，但高负载 CI/慢机上仍可能抖动；出现偶发红时优先放大样本间隔而非放宽阈值。
- `src/tests/deploy/deployScript.test.js:709` — 夹具把 `\n` 误写为 `/n`（'receivers:/n  - name: ops-critical\n'），实际产出单行乱串；断言仍成立但验证路径与用例名所述"有接收端但无投递配置"边界已不一致。
- `src/tests/routes/bodyTypeGate.test.js:303` — 权限码字面量退化为常量：stamp 数字已全部映射为字母，`replace(/\D/g,'')` 恒为空串 ⇒ code 恒为 'dev:x'，失去按次唯一性；负向用例一旦转红，重跑会以 E11000 混淆真实失败原因。
- `src/tests/models/AuditLog.test.js:414-434` — alertSpy 装在行 415、restore 在行 434，中间 5 个 expect 无 try/finally；任一失败都会让被静音的 incSecurityAlert 泄漏到本文件后续测试（爆炸半径小）。
- `src/tests/models/riskLevelScalarMembership.test.js:94-97` — 失败信息里的行号回查按"首个 trim 相等的行"定位，同文件存在重复代码行时所有重复站点都报到第一处，诊断可能指错行（行号仅用于报告，影响可定位性）。
- `src/tests/credentialValidityPredicates.test.js:216-222` — '用户被禁用 ⇒ false' 用例改完用户态后不在 try/finally 里恢复，第一个断言失败时 status:'active' 的恢复语句不执行，文件内其后所有用例连环误报（同文件行 265-274 已有正确 try/finally 写法）。
- `src/tests/security/reportTargetCandidates.test.js:336-352` — "单次最多 20 条"用例在断言之后才清理 25 条批量夹具，断言失败时 deleteMany 不执行（afterAll 只清 RTC-DEV 前缀），建议移入 try/finally 或 afterEach。
- `src/tests/middleware/idempotency.test.js:1284-1345` — 用例 (p) 的门闩 releaseLateClaim()（:1322）不在 try/finally 内，若 :1290-1320 任一 waitFor/断言先失败，挂起在门闩上的首个请求永不收尾，worker 内留下永不关闭的在途 socket。

## 2.4 测试体系总体评估

**测试金字塔与覆盖面。** 后端测试呈"宽底座 + 双塔"形态：底座是 884 个 jest 测试文件，覆盖 utils 纯函数、constants/models 单元、services、controllers、middleware、routes 集成（supertest）、app 启动早期行为、migrations、compliance/architecture 合同，直至 edge 边界与 docs 门禁（tests-subdirs 分区）；两座塔分别是部署塔（tests-deploy，70 个文件真跑脚本+桩观测命令序列/落盘产物，覆盖 backup/restore、hot upgrade、offline bundle、compose、release workflow）与 CI meta-gate 塔（tests-ci，51 个文件给"看门闸"本身做自检：workflow 不变量、吞退出码检测、覆盖率闸接线、注释密度棘轮等）。安全语义（鉴权/会话/MFA、审计链与 WAL、取证、蜜罐、限流、PII、SSRF）均有专门覆盖且以行为断言为主（如 tests-root-3 的 verifyChainExitCode、webhookSsrfRangeWhitelist，tests-security 的 reauthTicket 系列等）。

**断言文化。** 前提自证、反向对照与变异验证的普及度显著高于常见仓库：多份报告独立记录了"三件套"惯例——前提自证（防空集恒绿/防 mock 空转，如 tests-deploy 解析器抽空即红、tests-subdirs bodyStringGateCoverage 要求扫描器扫到 ≥50 条）、反向对照（防闸做成一律拒绝，如 controllers 分区负向用例几乎都配正向对照）、变异验证台账（如 controllers-2 的 requestedIdListDeduped.test.js、skipGlobalAuditWriteFailure.test.js 附完整变异台账与"仪器自检"前提腿；services-3 提到 mockRestore 先取次数再还原防恒真）。仍存少数恒真/空洞判据，均已逐条登记：honeypotDecoyAggregates.test.js:218-225 的 `toEqual(expect.arrayContaining([]))`、securitySanitizeAndBlacklistDegrade.test.js:552-558 的 `typeof res.json === 'function'`、pureModules.test.js:287-291 的两次恒等比较、auditExportDataScope.test.js:29-41 的只数行数、auditExportService.test.js:8-11 的 mock 下 undefined 断言——这类是全库最值得优先修复的"假绿"点。

**测试基建。** 核心是 src/tests/setup.js 的"每测试文件独立数据库"（库名带 worker+时间戳+随机后缀，见 tests-root-1 引 setup.js:78-100）叠加 globalTeardown 对 `jest_w*` 库的整体 drop（tests-root-2 引 globalTeardown.js 注释），setup.js 还对每个测试文件重置 NODE_ENV/JWT/AES/HMAC/CORS 等关键 env（tests-subdirs upgradeEndpoint.test.js 注释可证）。这套基建结构性消除了跨文件夹具串扰，使大量"清理不完整"问题被降级为 P3（controllers-1、controllers-2、security、subdirs、root-1 报告均明确据此定级）。需注意的隐患是：部分套件仍按"共享库"旧假设写全量 deleteMany（privilegeGrantFlow.test.js:100-106、initDataLifecycle.test.js:134-147、initDataParentConvergence.test.js:42 等），一旦未来改为并行 worker 共库或复用实例（globalTeardown.js 注释提到 --watch 可能复用），这些全量清理会反过来变成互踩源。

**随机顺序稳定性。** 仓内已有 `--randomize` 顺序打乱的显式防御文化：stamp 化用户名/业务键、增量断言、beforeEach 重建状态（root-3 的 reservedWildcardAssignment 是被点名的正面示例；services-3 总评确认 stamp+相对计数普遍）。剩余的不稳定源集中在三类，均已逐条登记：env/模块状态修改未用 try/finally 归还（主题 D 共 17 条，如 honeypotSocketGate.test.js:126-135、logShipperSchemeAllowlist.test.js:83、walStatIntervalEnvContract.test.js 的 P2）；mockRestore 写在断言之后（ipLocationService.test.js:91-125、reportWorkbookExportIntegrity.test.js 等）；固定用户名/固定 code 无 stamp（permCacheLifecycle.test.js:90-94、reportStatsCountsAndRate.test.js:15、以及 root-2 两个播种撞键 P2）。

**CI 集成。** tests-ci 分区构成完整的"自检闸"体系：ciTestStepWiring 钉住覆盖率步骤不被吞退出码（行 272-274 对前后端各断言一次）、ciWorkflowInvariants/sastWorkflowInvariants 钉 workflow 结构、noFixedSleepRatchet/fileOrderSequencer/testSequencer 管执行纪律，配合 tests-deploy 的 ciGateWiring/ciInstallHardening/ciProvisionFailurePropagation 形成"改动必须过目"的棘轮网络。两个已知缺口：吞退出码形态库漏 `|| echo`/`|| printf`（ciTestStepWiring.test.js:111-119），以及若干精确计数棘轮（fieldErrorsEgressGate.test.js:236-243 的 51 站点）在并行开发下维护成本偏高。另外 mongooseTeardownLedger 把"漏关连接 ⇒ worker 强杀吞输出"列为台账项，而本次审计在 middleware 分区发现的 infraParamRateLimitFailClosed.test.js:308-352 正是这类在逃问题，建议优先闭环。

## 2.5 逐文件附录

按分区列出。有发现的文件格式：`路径 — N 条（最高 P 级）— 一句话`；无发现文件为纯路径列表。各分区"有发现 + 无发现"总数与分区清单行数逐一相等，合计 884。

### tests-services-1（52 = 9 有发现 + 43 无发现）

有发现：
- src/tests/services/auditExportService.test.js — 1 条（P2）— RESPONSE_EXCLUDE 断言在 mock 下退化为 toHaveBeenCalledWith(undefined)，清单内容不可观察。
- src/tests/services/adminPasswordAtomicWrite.test.js — 1 条（P3）— 核心断言写进 renameSync mock 内部，未来吞错实现会静默失效。
- src/tests/services/alarmDispatchScopeMatrix.test.js — 1 条（P3）— 夹具用户名固定无 stamp，强杀残留致下轮 E11000。
- src/tests/services/alarmReporterPhoneEgress.test.js — 1 条（P3）— ALARM_READ_SELECT 次数钉死恰好 9，合法重构误红。
- src/tests/services/auditAnchorSink.test.js — 1 条（P3）— writeTemp 临时目录从不删除。
- src/tests/services/auditChainBatchCastParity.test.js — 1 条（P3）— 真库链首记录 afterAll 不清理。
- src/tests/services/auditChainResign.test.js — 1 条（P3）— 3 条 chain_resign_test 记录不清理。
- src/tests/services/auditChainCheckpointExitCodes.test.js — 1 条（P3）— 源码闸把注释措辞与字面写法钉死。
- src/tests/services/auditWalChainOrphanRejection.test.js — 1 条（P3）— errText/catch 站点数逐字钉死（12/6/9）。

无发现：
src/tests/services/adminUsernameCollision.test.js
src/tests/services/alarmDetailHandlerPii.test.js
src/tests/services/alarmReporterPhoneEncryption.test.js
src/tests/services/alertSeveritySurvivesRender.test.js
src/tests/services/assignmentsReleasedOnAccountLock.test.js
src/tests/services/attackDetection.test.js
src/tests/services/attackEventQueryService.test.js
src/tests/services/attackProfile.test.js
src/tests/services/attackProfileSummary.test.js
src/tests/services/auditBufferPrecastGate.test.js
src/tests/services/auditChainCheckpoint.test.js
src/tests/services/auditChainCheckpointRealTail.test.js
src/tests/services/auditChainDistributed.test.js
src/tests/services/auditChainForkWindowParity.test.js
src/tests/services/auditChainGuardedIntegrity.test.js
src/tests/services/auditChainLegacyPrefixWash.test.js
src/tests/services/auditChainSharedTailReal.test.js
src/tests/services/auditChainVerify.test.js
src/tests/services/auditChainVerifyIdOrder.test.js
src/tests/services/auditChainVerifyProjection.test.js
src/tests/services/auditChainVerifyTimeBudget.test.js
src/tests/services/auditChainZombieFreeze.test.js
src/tests/services/auditExportManifestScope.test.js
src/tests/services/auditExportManifestSignature.test.js
src/tests/services/auditExportWriteLineAbort.test.js
src/tests/services/auditMonitorAlertLoop.test.js
src/tests/services/auditMonitorDailyAlertCap.test.js
src/tests/services/auditMonitorDetectionCoverage.test.js
src/tests/services/auditMonitorDetectionLag.test.js
src/tests/services/auditMonitorTimezone.test.js
src/tests/services/auditOutbox.test.js
src/tests/services/auditQueryOperationCatch.test.js
src/tests/services/auditQueryRealNameProjection.test.js
src/tests/services/auditSchemaCastRewriters.test.js
src/tests/services/auditScopeFilterDeptCache.test.js
src/tests/services/auditTtlBootReconcile.test.js
src/tests/services/auditUsernameCastGate.test.js
src/tests/services/auditWalCap.test.js
src/tests/services/auditWalCorruptLineObservability.test.js
src/tests/services/auditWalDurableAppend.test.js
src/tests/services/auditWalDurableTrim.test.js
src/tests/services/auditWalPathIsolation.test.js
src/tests/services/auditWalPermissionHardening.test.js

### tests-services-2（52 = 11 有发现 + 41 无发现）

有发现：
- src/tests/services/backgroundJobs.test.js — 3 条（最高 P2）— 审计行/设备/巡检夹具 afterAll 不清理（P2）；IPBlacklist deleteMany({source:'auto'}) 过宽；securityAlert 真实调用未 spy 投递层（待确认）。
- src/tests/services/businessStateConsistencyInvariants.test.js — 1 条（P2）— 固定用户名+固定口令创建 3 个真实用户且完全不清理。
- src/tests/services/authRegisterDuplicateKey.test.js — 2 条（P3）— SystemConfig 配置行不清理；emailKey 撞键分支覆盖盲区。
- src/tests/services/forensicCapture.test.js — 1 条（P3）— env/mock 复位无 try/finally，失败路径泄漏。
- src/tests/services/forensicTrigger.test.js — 1 条（P3）— FORENSIC_TRIGGER_* 设置/还原无 try/finally。
- src/tests/services/forensicManifest.test.js — 1 条（P3）— 20+ 处 mkdtemp 临时目录不回收。
- src/tests/services/forensicManifestLock.test.js — 1 条（P3）— 临时目录与子进程脚本不清理。
- src/tests/services/forensicManifestRetention.test.js — 1 条（P3）— 临时目录一律不回收。
- src/tests/services/forensicManifestReconcile.test.js — 1 条（P3）— 对账目录多数不删除。
- src/tests/services/honeypotDecoy.test.js — 1 条（P3）— afterAll 按 action 删除不带 username 过滤，连带删他套件数据。
- src/tests/services/forensicCaptureWiring.test.js — 1 条（P3）— 对 index.js 源码精确正则匹配，依赖格式细节。

无发现：
src/tests/services/authServiceLoginRefreshGuards.test.js
src/tests/services/authServiceLoginResidualBranches.test.js
src/tests/services/authServiceProfileAndRevocation.test.js
src/tests/services/authServiceSideEffectFailureTolerance.test.js
src/tests/services/behaviorBaseline.test.js
src/tests/services/bruteForceBanDimension.test.js
src/tests/services/businessTtlReconcileEdges.test.js
src/tests/services/cacheWriteBackRace.test.js
src/tests/services/canaryWatch.test.js
src/tests/services/captchaCounterDegradeAndIdempotentCleanup.test.js
src/tests/services/captchaRedisModeGuards.test.js
src/tests/services/cursorTiebreakPagination.test.js
src/tests/services/dashboardDataScopeApplied.test.js
src/tests/services/deviceAlertOutletParity.test.js
src/tests/services/deviceCascadeIndexLock.test.js
src/tests/services/deviceCursorContinuity.test.js
src/tests/services/deviceLocationMerge.test.js
src/tests/services/deviceRefCleanupAfterWrite.test.js
src/tests/services/deviceReminderScopeIsolationGuards.test.js
src/tests/services/deviceReminderTruncation.test.js
src/tests/services/deviceScrapTerminalStateAtomic.test.js
src/tests/services/deviceStatsCache.test.js
src/tests/services/exportConcurrency.test.js
src/tests/services/exportCountDrift.test.js
src/tests/services/exportSuccessParity.test.js
src/tests/services/f74NegativeEnvFallback.test.js
src/tests/services/failOpenSignals.test.js
src/tests/services/fireAndForgetAlertSingleEntry.test.js
src/tests/services/forensicCaptureAlertIsolation.test.js
src/tests/services/forensicCaptureHardening.test.js
src/tests/services/forensicCaptureIpWindowCap.test.js
src/tests/services/forensicCapturePartialBatch.test.js
src/tests/services/forensicCapturePayloadDigest.test.js
src/tests/services/forensicCaptureTtlReconcile.test.js
src/tests/services/forensicCaptureWal.test.js
src/tests/services/forensicExport.test.js
src/tests/services/forensicFingerprintQuery.test.js
src/tests/services/forensicTraceExport.test.js
src/tests/services/honeypotChainWatch.test.js
src/tests/services/honeypotDecoyFiles.test.js
src/tests/services/honeypotDecoySelf.test.js

### tests-services-3（52 = 16 有发现 + 36 无发现）

有发现：
- src/tests/services/privilegeGrantFlow.test.js — 1 条（P2）— afterAll 全量 deleteMany({}) 与自身前缀清理口径自相矛盾，并行共库时删兄弟套件授予（待确认）。
- src/tests/services/honeypotSocketGate.test.js — 2 条（P3）— HONEYPOT_ENABLED 还原无 try/finally；源码字符串切片与出现次数钉实现。
- src/tests/services/honeypotWatch.test.js — 1 条（P3）— 两处 env 修改末尾才恢复，无 try/finally。
- src/tests/services/initDataLifecycle.test.js — 2 条（P3）— resetDb 全量清空共享库（待确认）；用例内 env 只删不改回且 afterAll 不还原。
- src/tests/services/initDataParentConvergence.test.js — 1 条（P3）— 每用例 Permission.deleteMany({}) 全量清空，并行互踩（待确认）。
- src/tests/services/inspectionOverdueRemainsWorkable.test.js — 1 条（P3）— 直接调全局 markOverdueInspections 改写全库在途夹具（待确认）。
- src/tests/services/ipLocationService.test.js — 1 条（P3）— mockRestore 在断言之后且无 afterEach restoreAllMocks。
- src/tests/services/permCacheLifecycle.test.js — 1 条（P3）— 固定用户名无 stamp 无预清理，残留致 E11000 难归因。
- src/tests/services/permissionCacheDegradedTtl.test.js — 1 条（P3）— 固定用户名 permcache_p3 无预清理。
- src/tests/services/permissionHotReload.test.js — 1 条（P3）— 夹具（含 *:* 超级权限角色）afterAll 不清理。
- src/tests/services/permissionSoftDelete.test.js — 1 条（P3）— 全库计数与软删窗口依赖"无并发写"假设（待确认）。
- src/tests/services/piiExportQuotaWatermark.test.js — 1 条（P3）— 固定 username 的 20+ 条审计行完全不清理。
- src/tests/services/observabilityWritesNeverReject.test.js — 1 条（P3，跨文件源码计数闸条目）— 站点数/形参集合/errText 计数逐字钉死。
- src/tests/services/rateLimitEscalation.test.js — 1 条（P3，同上）— 源码先后顺序闸与同步调用点计数。
- src/tests/services/outboundAlertContract.test.js — 1 条（P3，同上）— 全仓扫描 dynamic===1；allEmitSites 重复全树读盘 4 次可缓存。
- src/tests/services/recoveryCodeFormatSingleSource.test.js — 1 条（P3，同上）— 按形状收割正则字面量的双层过滤。

无发现：
src/tests/services/honeypotWatchIpKey.test.js
src/tests/services/initSystemConfig.test.js
src/tests/services/initialPasswordFileLifecycle.test.js
src/tests/services/inspectionCursorNullableSortKey.test.js
src/tests/services/inspectionExecutionLogCap.test.js
src/tests/services/inspectionUpdateAtomicity.test.js
src/tests/services/ipAttributionPunishTarget.test.js
src/tests/services/ipPoolBan.test.js
src/tests/services/ipPoolBanApplyTimeOperator.test.js
src/tests/services/ipPoolBanConfirmGuards.test.js
src/tests/services/ipPoolBanConfirmUnionRecheck.test.js
src/tests/services/ipPoolCluster.test.js
src/tests/services/ipPoolLiveTraffic.test.js
src/tests/services/ipPoolLiveTrafficSegment.test.js
src/tests/services/lockExpiryResetsAtomic.test.js
src/tests/services/loginCanaryAttempt.test.js
src/tests/services/loginChallengeAudit.test.js
src/tests/services/loginFailureChallenge.test.js
src/tests/services/loginFailureCounterFailClosed.test.js
src/tests/services/loginRateLimitAudit.test.js
src/tests/services/mfaDisableRecoveryAtomicWrite.test.js
src/tests/services/mfaFactorPathAndLockDuration.test.js
src/tests/services/mfaRevokeAndPepperFallback.test.js
src/tests/services/mfaSilentWriteFailureTrace.test.js
src/tests/services/mfaTokenPrimitiveGuards.test.js
src/tests/services/permCacheEviction.test.js
src/tests/services/permissionBatchSync.test.js
src/tests/services/permissionParentIdCaseAndDedup.test.js
src/tests/services/piiExportQuotaRedis.test.js
src/tests/services/piiExportQuotaTimezone.test.js
src/tests/services/privilegeGrantPiiHighRisk.test.js
src/tests/services/privilegeGrantValidationBoundaries.test.js
src/tests/services/rateLimitEscalationEviction.test.js
src/tests/services/realtimeEmitWiring.test.js
src/tests/services/realtimeNotifier.test.js
src/tests/services/refreshAuditTrail.test.js

### tests-services-4（50 = 10 有发现 + 40 无发现）

有发现：
- src/tests/services/walStatIntervalEnvContract.test.js — 1 条（P2）— AUDIT_WAL_PATH 不快照不还原，泄漏指向已删目录的路径给同 worker 后续套件。
- src/tests/services/upgradeService.test.js — 1 条（P3）— 原值未设时注入的 HMAC_SECRET 不还原。
- src/tests/services/reportStatsCountsAndRate.test.js — 1 条（P3）— 夹具 stamp 为常量，前次中途崩溃后失去自愈能力。
- src/tests/services/runtimeTopologyAndPerfInvariants.test.js — 1 条（P3）— 对 index.js 的纯文本调用断言是不能被变异杀死的判据（已自陈登记）。
- src/tests/services/reportWorkbookExportIntegrity.test.js — 1 条（P3，多文件合并条目）— findSpy.mockRestore() 均排在断言之后。
- src/tests/services/reportWorkbookService.test.js — 1 条（P3，同合并条目）— mockRestore 在断言之后。
- src/tests/services/securityAlertGuards.test.js — 1 条（P3，同合并条目）— spy.mockRestore 在断言之后。
- src/tests/services/wsFlow.test.js — 1 条（P3，同合并条目）— dontMock 在断言之后，失败时抛错桩残留。
- src/tests/services/websocketCorsAndReauthGuards.test.js — 1 条（P3，同合并条目）— 60s setTimeout 句柄晚清（仅记录）。
- src/tests/services/websocketAuthScope.test.js — 1 条（P3，同合并条目）— server.close() 未 await（仅记录）。

无发现：
src/tests/services/reportExportDevicesProjection.test.js
src/tests/services/reportExportPiiMasking.test.js
src/tests/services/reportTargetServiceKindLookup.test.js
src/tests/services/roleDeletionRecovery.test.js
src/tests/services/roleUserCountPipelineLock.test.js
src/tests/services/securityAlertBanLadder.test.js
src/tests/services/securityAlertContainmentDecoupling.test.js
src/tests/services/securityAlertDeliveryFailureTrace.test.js
src/tests/services/securityAlertDetectionQueryFailureTrace.test.js
src/tests/services/securityAlertLifecycle.test.js
src/tests/services/securityAlertWriteFailureTolerance.test.js
src/tests/services/sessionCrossInstance.test.js
src/tests/services/sessionFailSoft.test.js
src/tests/services/sessionService.test.js
src/tests/services/sharedCacheBackends.test.js
src/tests/services/sharedCacheNonceFloodEviction.test.js
src/tests/services/startupAuditTrail.test.js
src/tests/services/statsCache.test.js
src/tests/services/statsCacheTtlCeiling.test.js
src/tests/services/tokenService.test.js
src/tests/services/updateRolesVersionBump.test.js
src/tests/services/userBulkDeleteToctou.test.js
src/tests/services/userListLastLoginIp.test.js
src/tests/services/userSaveCredentialWipe.test.js
src/tests/services/userSessionIpGate.test.js
src/tests/services/walCapTrimFailureTaxonomy.test.js
src/tests/services/walReadFailureTaxonomy.test.js
src/tests/services/webhookDnsPinningAndSigning.test.js
src/tests/services/webhookIpv4CompatibleDeny.test.js
src/tests/services/websocketAllowedIpTrustBoundary.test.js
src/tests/services/websocketAuthGhostConnection.test.js
src/tests/services/websocketHandlerRejectionGuard.test.js
src/tests/services/websocketHandshakeIpBan.test.js
src/tests/services/websocketHandshakeNonErrorRejection.test.js
src/tests/services/websocketInboundThrottle.test.js
src/tests/services/websocketRedisAdapter.test.js
src/tests/services/websocketSessionRevocationAndQuota.test.js
src/tests/services/websocketSweep.test.js
src/tests/services/websocketTempLockAndRoomRevocation.test.js
src/tests/services/websocketTrustProxyHopsParity.test.js

### tests-controllers-1（51 = 14 有发现 + 37 无发现）

有发现：
- src/tests/controllers/auditExportLimitsAndCsvEscaping.test.js — 1 条（P3）— 文件头声称守护"硬上限"但无用例，注释与内容不符。
- src/tests/controllers/auditLogs.test.js — 1 条（P3，注释过时组）— 注释仍以"并行共享同一内存库"为前提。
- src/tests/controllers/auditCursorErrorSemantics.test.js — 1 条（P3，注释过时组）— 同上，且据过时前提把断言放松为"位置关系"。
- src/tests/controllers/authzSessionRevocationGuards.test.js — 1 条（P3，注释过时组）— 注释前提过时。
- src/tests/controllers/createUserPeerRoleGate.test.js — 1 条（P3，注释过时组）— 注释前提过时。
- src/tests/controllers/ipListFullRangeGrantAndRescueSymmetry.test.js — 1 条（P3）— afterAll 清理切片错位，漏删一个用户和一个角色。
- src/tests/controllers/auditReportFixes.test.js — 1 条（P3）— test.each 用例表完全重复一行。
- src/tests/controllers/auditExportManifestBytes.test.js — 1 条（P3）— SinkRes 的 json 实例属性遮蔽原型 body 方法。
- src/tests/controllers/auditQuerySharedBuilder.test.js — 1 条（P3，源码文本闸组）— 全仓扫描钉"buildAuditQuery 只能定义在 utils/auditQuery.js"。
- src/tests/controllers/auditSummaryCache.test.js — 1 条（P3，源码文本闸组）— 精确计数 2 次/1 处。
- src/tests/controllers/auditUsernamePrefixIndex.test.js — 1 条（P3，源码文本闸组）— withCollation 计数与精确三元子串。
- src/tests/controllers/authUnknownOutcomeFailClosed.test.js — 1 条（P3，源码文本闸组）— 全仓 switch(outcome) 结构闸。
- src/tests/controllers/auditExportUsernamePrefixParity.test.js — 1 条（P3，源码文本闸组）— 压平去注释后的精确代码串。
- src/tests/controllers/attackEvents.test.js — 1 条（P3）— REGISTRY_ACTIONS 手抄副本，需人工同步义务。

无发现：
src/tests/controllers/adminResetPasswordGates.test.js
src/tests/controllers/alarmHandleReasonBoundary.test.js
src/tests/controllers/alarmInspectionErrorPaths.test.js
src/tests/controllers/alarmReportDeviceScope.test.js
src/tests/controllers/assignRoles.test.js
src/tests/controllers/assignRolesInactiveExemption.test.js
src/tests/controllers/attackProfile.test.js
src/tests/controllers/auditControllerBehavior.test.js
src/tests/controllers/auditControllerErrorPaths.test.js
src/tests/controllers/auditDataScope.test.js
src/tests/controllers/auditExportParamParity.test.js
src/tests/controllers/auditExportSlot.test.js
src/tests/controllers/auditExportStreamFailure.test.js
src/tests/controllers/auditLogDetail.test.js
src/tests/controllers/authControllerOutcomes.test.js
src/tests/controllers/authCookies.test.js
src/tests/controllers/authLifecycle.test.js
src/tests/controllers/authRegisterSessionBinding.test.js
src/tests/controllers/authRest.test.js
src/tests/controllers/authSessionHandlerArms.test.js
src/tests/controllers/avatarEndpoint.test.js
src/tests/controllers/businessFlow.test.js
src/tests/controllers/changePasswordEncTrack.test.js
src/tests/controllers/changePasswordOutcomeMap.test.js
src/tests/controllers/changePasswordTypeGuard.test.js
src/tests/controllers/createUserScopeGate.test.js
src/tests/controllers/cursorPagination.test.js
src/tests/controllers/dashboardCacheCap.test.js
src/tests/controllers/dataScopeDenied403.test.js
src/tests/controllers/deviceExpiringTruncation.test.js
src/tests/controllers/deviceStatusErrorMapping.test.js
src/tests/controllers/emailCaseNormalization.test.js
src/tests/controllers/inspectionGuardRefExistence.test.js
src/tests/controllers/inspectionScopeAndSensitiveViewGuards.test.js
src/tests/controllers/inspectionScopeRealE2E.test.js
src/tests/controllers/inspectionWriteErrorMapping.test.js
src/tests/controllers/ipListConcurrentUnionGuard.test.js

### tests-controllers-2（51 = 8 有发现 + 43 无发现）

有发现：
- src/tests/controllers/loginEncryption.test.js — 1 条（P3）— 头注"登录请求控制在 6 次以内"与实际约 11 次不符。
- src/tests/controllers/roleControllerHierarchyGuards.test.js — 1 条（P3）— 大量用例名内嵌已漂移的源码行号。
- src/tests/controllers/sessionManagement.test.js — 1 条（P3）— sesspwd 用户及其会话不在 afterAll 清理清单。
- src/tests/controllers/permissionUserValidationGuards.test.js — 1 条（P3）— 清理正则漏掉 upblow${stamp} 用户。
- src/tests/controllers/permissionCacheInvalidation.test.js — 1 条（P3）— 固定名用户/角色/权限夹具不回收。
- src/tests/controllers/permissionValidationAndCycleGuards.test.js — 1 条（P3）— perm_admin 与各前缀权限文档不回收。
- src/tests/controllers/reportExportInputGuards.test.js — 1 条（P3）— B-4 行序种子（ORD${stamp}*）不在清理正则内。
- src/tests/controllers/userStats.test.js — 1 条（P3）— 直接读写 statsCache._store 私有 Map 并替换其 get。

无发现：
src/tests/controllers/ipListFullRangeRescuePath.test.js
src/tests/controllers/ipListFullRangeTypedConfirm.test.js
src/tests/controllers/ipListSplitUnionBypass.test.js
src/tests/controllers/ipListValidationAndConflictGuards.test.js
src/tests/controllers/mfaControllerErrorPaths.test.js
src/tests/controllers/mfaControllerOrchestration.test.js
src/tests/controllers/mfaReplayGuardMax.test.js
src/tests/controllers/mfaTotpClaimImplementation.test.js
src/tests/controllers/mfaWriteCasConcurrency.test.js
src/tests/controllers/permissionBatchCreateSemantics.test.js
src/tests/controllers/rbacControllers.test.js
src/tests/controllers/registerPrivacyConsent.test.js
src/tests/controllers/reportDateRangeBoundary.test.js
src/tests/controllers/reportExpiringTruncation.test.js
src/tests/controllers/reportExport.test.js
src/tests/controllers/reportExportAuditPerm.test.js
src/tests/controllers/reportExportRowOrderAndCells.test.js
src/tests/controllers/reportExportTruncationHeader.test.js
src/tests/controllers/reportPiiExportStepUp.test.js
src/tests/controllers/reportPiiQuotaPreWrite.test.js
src/tests/controllers/reportTimezoneParam.test.js
src/tests/controllers/requestedIdListDeduped.test.js
src/tests/controllers/roleAuthorityResolutionPerRequest.test.js
src/tests/controllers/roleCreatePermissionExistence.test.js
src/tests/controllers/roleGrantRevalidation.test.js
src/tests/controllers/rolePermCloneTargetUserScope.test.js
src/tests/controllers/rolePermPeerGuard.test.js
src/tests/controllers/roleStatusInvalidatesUserCache.test.js
src/tests/controllers/securityConfigHandlers.test.js
src/tests/controllers/securityControllerOutcomeAndGuards.test.js
src/tests/controllers/securityDeep.test.js
src/tests/controllers/securityOverviewAuditLossProjection.test.js
src/tests/controllers/securityOverviewShippingChannel.test.js
src/tests/controllers/securityQuick.test.js
src/tests/controllers/securityStatsTimezone.test.js
src/tests/controllers/skipGlobalAuditEndToEnd.test.js
src/tests/controllers/skipGlobalAuditWriteFailure.test.js
src/tests/controllers/updateUserAvatarCleanupAndScopeField.test.js
src/tests/controllers/updateUserMassAssignmentGuard.test.js
src/tests/controllers/userControllerBehavior.test.js
src/tests/controllers/userListFilterAndBulkDeleteBounds.test.js
src/tests/controllers/userStatsSelfScopeCast.test.js
src/tests/controllers/userStatusRestoreClearsTempLock.test.js

### tests-utils-1（39 = 6 有发现 + 33 无发现）

有发现：
- src/tests/utils/encryption.test.js — 1 条（P3）— 密钥 env 写入后不恢复（依赖 setup.js 每文件重置兜底）。
- src/tests/utils/bcryptWorkerPool.test.js — 1 条（P3）— doMock 不收回，防泄漏责任落在"受害"用例上。
- src/tests/utils/apiErrorHttpJsonAndLimitGuards.test.js — 1 条（P3）— "到期条目被删除"断言被 verify 自带过期判定兜绿，清理行为无可证伪判据。
- src/tests/utils/auditMeta.test.js — 1 条（P3）— 路由正则只认单引号路径 + 精确计数 110 的源码闸。
- src/tests/utils/avatarImage.test.js — 1 条（P3）— 200MB 解压炸弹夹具放大 worker OOM 风险。
- src/tests/utils/auditChainSurrogateArtifact.test.js — 1 条（P3）— 真库敌意审计行不显式清理（独立库兜底，口径不一致）。

无发现：
src/tests/utils/accessLogDevFormat.test.js
src/tests/utils/apiResponsePaginatedDefaults.test.js
src/tests/utils/auditChainFenceRenewalBound.test.js
src/tests/utils/auditFilterCombination.test.js
src/tests/utils/auditIpVariantForms.test.js
src/tests/utils/auditQueryFindAggregateParity.test.js
src/tests/utils/auditQueryParamTypeGuard.test.js
src/tests/utils/auditWriteFailure.test.js
src/tests/utils/bcryptWorkerPoolCrashFallback.test.js
src/tests/utils/bcryptWorkerThread.test.js
src/tests/utils/breachedPasswordMatcher.test.js
src/tests/utils/cidrCoverage.test.js
src/tests/utils/clientIpSecurityDecision.test.js
src/tests/utils/cryptoKeyGuard.test.js
src/tests/utils/cursorPagination.test.js
src/tests/utils/dateBoundaryTzWiring.test.js
src/tests/utils/dateFormatPlaceholder.test.js
src/tests/utils/dateParamForms.test.js
src/tests/utils/dateParamGateSingleSource.test.js
src/tests/utils/durationToMsParity.test.js
src/tests/utils/errorCodes.test.js
src/tests/utils/filePermissionUsernamePaths.test.js
src/tests/utils/fingerprint.test.js
src/tests/utils/fingerprintDelimiterFidelity.test.js
src/tests/utils/forensicDeviceKey.test.js
src/tests/utils/hardening.test.js
src/tests/utils/healthChecksRedis.test.js
src/tests/utils/helpers.test.js
src/tests/utils/httpPostJsonDeadline.test.js
src/tests/utils/httpPostJsonPinnedLookup.test.js
src/tests/utils/ip2regionSearcher.test.js
src/tests/utils/ipAttributionClassification.test.js
src/tests/utils/ipRange.test.js

### tests-utils-2（39 = 8 有发现 + 31 无发现）

有发现：
- src/tests/utils/tails.test.js — 1 条（P3）— `*:*` 权限、ADMIN 角色、审计行三处共享库写入不清理。
- src/tests/utils/toolCryptoAndOriginGuards.test.js — 2 条（P3）— dropCollection 死代码误导；"注释与实现对齐"全部为文本正则闸。
- src/tests/utils/proxyProtocolFrontServer.test.js — 1 条（P3）— 两处 4 秒探针超时 timer 成功路径不清理。
- src/tests/utils/permissionHelper.test.js — 1 条（P3）— 清理写在断言之后，失败路径残留角色与用户。
- src/tests/utils/logPiiMaskLinearAndNestedCap.test.js — 1 条（P3）— 真实计时判据在慢机/高负载 CI 上可能抖动。
- src/tests/utils/passwordHistory.test.js — 1 条（P3）— 接线门禁钉死精确表达式与局部变量名（有意取舍）。
- src/tests/utils/queryBudget.test.js — 1 条（P3）— 未剥注释的 includes 判定可被注释骗绿。
- src/tests/utils/pureModules.test.js — 1 条（P3）— "命中缓存"用例为两次恒等比较的空洞断言。

无发现：
src/tests/utils/ipScopeIdCanonicalization.test.js
src/tests/utils/ipTextStrictness.test.js
src/tests/utils/ipUtils.test.js
src/tests/utils/ipUtilsMappedCidr.test.js
src/tests/utils/logContext.test.js
src/tests/utils/logPiiMask.test.js
src/tests/utils/logShippingUrlValidatedAtMount.test.js
src/tests/utils/loggerShippingEnv.test.js
src/tests/utils/loginCipher.test.js
src/tests/utils/maskIpEmbeddedV4OctetBoundary.test.js
src/tests/utils/metricsRuntimeRejectionCounter.test.js
src/tests/utils/mongoDuplicateKeyRealShapes.test.js
src/tests/utils/mongoDuplicateKeyShapes.test.js
src/tests/utils/mongoFailureAttribution.test.js
src/tests/utils/permissionHelperClassificationGuards.test.js
src/tests/utils/piiEncryption.test.js
src/tests/utils/posixShell.test.js
src/tests/utils/proxyProtocolParser.test.js
src/tests/utils/remediationLocksL20L21.test.js
src/tests/utils/roleLevelSingleSource.test.js
src/tests/utils/scopeCastProtoKey.test.js
src/tests/utils/searchPatternsUndefinedTerm.test.js
src/tests/utils/shutdownBudgetContract.test.js
src/tests/utils/shutdownStepOrder.test.js
src/tests/utils/superAdmin.test.js
src/tests/utils/tokenPurposeAndConsumers.test.js
src/tests/utils/totp.test.js
src/tests/utils/transaction.test.js
src/tests/utils/transactionTopology.test.js
src/tests/utils/wildcardPermissionSingleSource.test.js
src/tests/utils/xlsxWriterGuards.test.js

### tests-deploy（70 = 6 有发现 + 64 无发现）

有发现：
- src/tests/deploy/backupTransport.test.js — 1 条（P3）— 全文件无任何清理钩子，每轮泄漏约 10 个临时目录。
- src/tests/deploy/hotUpgradeAgent.test.js — 1 条（P3）— 每用例 mkdtempSync 且无清理，每轮泄漏约 20 个目录。
- src/tests/deploy/hotUpgradeOfflineDispatch.test.js — 1 条（P3）— 每轮泄漏 4 个 fsms-offline-dispatch-* 目录。
- src/tests/deploy/offlineBundleScan.test.js — 1 条（P3）— 每轮泄漏约 9 个 fsms-bundles-* 临时根。
- src/tests/deploy/auditAllowlistGate.test.js — 1 条（P3）— 5 处把临时 JSON 写进仓库根目录固定文件名，污染工作区且并发互撞。
- src/tests/deploy/deployScript.test.js — 1 条（P3）— 夹具 `\n` 误写 `/n`，验证路径与用例名所述边界不一致。

无发现：
src/tests/deploy/alertDeliveryProbeMask.test.js
src/tests/deploy/alertmanagerComposeGate.test.js
src/tests/deploy/alertmanagerConfigPath.test.js
src/tests/deploy/appEntrypointHomePasswd.test.js
src/tests/deploy/appEntrypointQueuePermFallback.test.js
src/tests/deploy/appSecretEntrypoint.test.js
src/tests/deploy/architectureDocContract.test.js
src/tests/deploy/backupEncryptionContract.test.js
src/tests/deploy/backupFailureArtifactHygiene.test.js
src/tests/deploy/backupUriFile.test.js
src/tests/deploy/bundleBudget.test.js
src/tests/deploy/ciGateWiring.test.js
src/tests/deploy/ciInstallHardening.test.js
src/tests/deploy/ciProvisionFailurePropagation.test.js
src/tests/deploy/cliArgStrictness.test.js
src/tests/deploy/cliSecretArgGate.test.js
src/tests/deploy/clockSyncPreflight.test.js
src/tests/deploy/codeowners.test.js
src/tests/deploy/composeAppHealthcheck.test.js
src/tests/deploy/composeEvalScripts.test.js
src/tests/deploy/composeMongodbUriSecretRecipe.test.js
src/tests/deploy/composeProductionContract.test.js
src/tests/deploy/composeSegmentation.test.js
src/tests/deploy/dependencyFixSla.test.js
src/tests/deploy/deployCommands.test.js
src/tests/deploy/deployRun.test.js
src/tests/deploy/deployWorkflow.test.js
src/tests/deploy/dockerContextScope.test.js
src/tests/deploy/dockerHealthcheckReadyz.test.js
src/tests/deploy/generateSecretsAddMissing.test.js
src/tests/deploy/grafanaDashboardO3.test.js
src/tests/deploy/helpers/composeSource.js
src/tests/deploy/helpers/dockerignore.js
src/tests/deploy/helpers/releaseNotesScript.js
src/tests/deploy/helpers/stubExec.js
src/tests/deploy/hotUpgradeFailureLogs.test.js
src/tests/deploy/hotUpgradePolicy.test.js
src/tests/deploy/hotUpgradeQueueContract.test.js
src/tests/deploy/imageRequireClosure.test.js
src/tests/deploy/importOfflineBundle.test.js
src/tests/deploy/installScriptGate.test.js
src/tests/deploy/ip2regionChecksum.test.js
src/tests/deploy/lockfileAnchor.test.js
src/tests/deploy/loginKeyPinRequired.test.js
src/tests/deploy/migrateMongoDependencyClosure.test.js
src/tests/deploy/nginxProxyContract.test.js
src/tests/deploy/nginxSourcemapDenyParity.test.js
src/tests/deploy/nodeRuntimeMatrixParity.test.js
src/tests/deploy/offlineBundleIntake.test.js
src/tests/deploy/offlineBundleIntakePolicy.test.js
src/tests/deploy/offlineBundlePolicy.test.js
src/tests/deploy/offlineBundleSignature.test.js
src/tests/deploy/offsitePolicy.test.js
src/tests/deploy/provisionMongodCache.test.js
src/tests/deploy/releaseNotesPipeline.test.js
src/tests/deploy/releaseWorkflow.test.js
src/tests/deploy/restoreRemoteHardening.test.js
src/tests/deploy/restoreTransport.test.js
src/tests/deploy/rollbackDrillRestoreVerification.test.js
src/tests/deploy/runbookCheckCanFail.test.js
src/tests/deploy/runbookSecretSource.test.js
src/tests/deploy/secretCarriersIgnored.test.js
src/tests/deploy/workflowShellSyntax.test.js
src/tests/deploy/xlsxWriterDependencyClosure.test.js

### tests-ci（51 = 6 有发现 + 45 无发现）

有发现：
- src/tests/ci/banRefusalEnumSingleSource.test.js — 1 条（P3）— 注释与断言口径不一致（注释较宽松，断言禁一切字面量）。
- src/tests/ci/ciTestStepWiring.test.js — 1 条（P3）— 吞退出码形态漏 `|| echo` / `|| printf`，覆盖率步骤可被这样绕过（当前 ci.yml 无此写法）。
- src/tests/ci/fieldErrorsEgressGate.test.js — 2 条（P3）— stripComments 不剥行尾注释（潜在假红缺口，待确认）；51 个安全包装站点的精确计数棘轮。
- src/tests/ci/honeypotDecoyMetricsShapeParity.test.js — 1 条（P3）— 判据依赖 metrics 私有状态 _SERIES_STORES/_MAX_SERIES。
- src/tests/ci/mongooseTeardownLedger.test.js — 2 条（P3）— 头注"剩 3 个"与台账 2 条不同步；头注指向一条不存在的"视图口径"用例。
- src/tests/ci/credentialDoorCheckLedger.test.js — 1 条（P3）— why 字段路径错字 "eervices/..."。

无发现：
src/tests/ci/auditBufferStartForAuditAssertions.test.js
src/tests/ci/bareAnchorAttribution.test.js
src/tests/ci/ciWorkflowInvariants.test.js
src/tests/ci/codeViewPhantomLedger.test.js
src/tests/ci/commentAnchorFreshness.test.js
src/tests/ci/commentBlockIntegrity.test.js
src/tests/ci/commentDensityCliContract.test.js
src/tests/ci/commentDensityEnforcementStatus.test.js
src/tests/ci/commentDensityRatchet.test.js
src/tests/ci/commentViewSingleSource.test.js
src/tests/ci/coverageGateWiring.test.js
src/tests/ci/dataClassificationInventory.test.js
src/tests/ci/errorCodePlaceholderDefault.test.js
src/tests/ci/failOpenLedgerGate.test.js
src/tests/ci/fileOrderSequencer.test.js
src/tests/ci/helperExportReachability.test.js
src/tests/ci/helpers/childProcessGate.js
src/tests/ci/helpers/refusalDocContract.js
src/tests/ci/helpers/statusParityContract.js
src/tests/ci/honeypotAuthOnlyLedger.test.js
src/tests/ci/honeypotDecoyClockLedger.test.js
src/tests/ci/honeypotDecoyLedger.test.js
src/tests/ci/honeypotExclusionLedger.test.js
src/tests/ci/honeypotListShapeParity.test.js
src/tests/ci/honeypotNameOverlapLedger.test.js
src/tests/ci/honeypotPersonaDifferentiation.test.js
src/tests/ci/honeypotRouteTableParity.test.js
src/tests/ci/honeypotSelfShapeParity.test.js
src/tests/ci/honeypotTicketGateParity.test.js
src/tests/ci/moduleTrackingGate.test.js
src/tests/ci/noFixedSleepRatchet.test.js
src/tests/ci/openapiStatusParity.test.js
src/tests/ci/openapiUndocumentedFaceParity.test.js
src/tests/ci/permissionCatalogRouteParity.test.js
src/tests/ci/riskFactorVocabularyGate.test.js
src/tests/ci/runtimeInventoryClaims.test.js
src/tests/ci/sastWorkflowInvariants.test.js
src/tests/ci/shellScriptSyntax.test.js
src/tests/ci/stubReturnTypeParity.test.js
src/tests/ci/stuffingProfileContract.test.js
src/tests/ci/stuffingProfileWriteSites.test.js
src/tests/ci/testHookConsumerGate.test.js
src/tests/ci/testTokenTtlFloor.test.js
src/tests/ci/testTreePurity.test.js
src/tests/ci/userCredentialProjectionLedger.test.js

### tests-security（50 = 5 有发现 + 45 无发现）

有发现：
- src/tests/security/adversarialProbeRegression.test.js — 2 条（P3）— 审计行断言缺"前提自证"（空集恒绿缺口）；`__proto__` 腿实际到不了服务端，注释覆盖声明与实际不符。
- src/tests/security/reportTargetCandidates.test.js — 1 条（P3）— 25 条批量夹具在断言之后才清理。
- src/tests/security/businessRetentionAndAnonymization.test.js — 1 条（P3）— clearEnv 无条件 delete 不恢复原值。
- src/tests/security/statsAnomalyScope.test.js — 1 条（P3，与 stuffingProfileReadExit 合并）— 种子与断言依赖同业务日，午夜跨日假红窗口（待确认）。
- src/tests/security/stuffingProfileReadExit.test.js — 1 条（P3，同上合并条目）— 同上。

无发现：
src/tests/security/alertProbeRecord.test.js
src/tests/security/auditViewerRoleSeparation.test.js
src/tests/security/backupPatrolAndDrillRecency.test.js
src/tests/security/baseImageDigestPinned.test.js
src/tests/security/businessRetentionVerdict.test.js
src/tests/security/chainResignPrecheck.test.js
src/tests/security/complianceAlertingGate.test.js
src/tests/security/complianceGate.test.js
src/tests/security/complianceGuardStateIsReal.test.js
src/tests/security/credentialLimiterPerUserBucket.test.js
src/tests/security/destructiveGuard.test.js
src/tests/security/filePermissionEnforcementAndVerify.test.js
src/tests/security/filePermissionFailClosed.test.js
src/tests/security/gateSelfTest.test.js
src/tests/security/hmacResignPrecheck.test.js
src/tests/security/imageReferenceInventory.test.js
src/tests/security/initDataPasswordPersistAndTighten.test.js
src/tests/security/ipBlacklistClientIdentityR1.test.js
src/tests/security/jwtKeyRotation.test.js
src/tests/security/jwtKeyRotationAudit.test.js
src/tests/security/loginIpBucketDominator.test.js
src/tests/security/loginPeerBucketXffRotation.test.js
src/tests/security/logoutRevokesAllPresentedTokens.test.js
src/tests/security/logoutWithExpiredAccessToken.test.js
src/tests/security/migrateMfaWriteVerify.test.js
src/tests/security/migratePiiKeyStrengthGate.test.js
src/tests/security/permissionCodeCatalogParity.test.js
src/tests/security/piiMigrationCoversAlarmReporterPhone.test.js
src/tests/security/reauthTicketEnforcement.test.js
src/tests/security/reauthTicketOneTimeUse.test.js
src/tests/security/reportTargetIdBoundary.test.js
src/tests/security/reportTargetRegistryParity.test.js
src/tests/security/reportTargetScopeAndLimiter.test.js
src/tests/security/revokeFailurePropagation.test.js
src/tests/security/scanFaceParity.test.js
src/tests/security/securityAlertsScopeParity.test.js
src/tests/security/securityInputBoundary.test.js
src/tests/security/systemConfigBooleanContract.test.js
src/tests/security/tokenPurposeEntryInventory.test.js
src/tests/security/tokenPurposeSeparation.test.js
src/tests/security/userLockBooleanBoundary.test.js
src/tests/security/userPhoneMaskedEgress.test.js
src/tests/security/utf8ScanScope.test.js
src/tests/security/viewSensitiveReauthOrder.test.js
src/tests/security/whitelistExemptionTrustBoundary.test.js

### tests-middleware（48 = 5 有发现 + 43 无发现）

有发现：
- src/tests/middleware/infraParamRateLimitFailClosed.test.js — 2 条（最高 P2）— Swagger 用例 mongoose 连接不关、worker 可能被强杀吞输出（P2）；429 用例与洪水用例共享限流桶空转通过且注释失实（P3）。
- src/tests/middleware/securitySanitizeAndBlacklistDegrade.test.js — 1 条（P3）— `expect(typeof res.json).toBe('function')` 恒真，包装与审计均无真判据。
- src/tests/middleware/idempotency.test.js — 1 条（P3）— 门闩 releaseLateClaim() 不在 try/finally 内，失败路径留下永不关闭的在途 socket。
- src/tests/middleware/staticFrontend.test.js — 1 条（P3）— 夹具临时目录从不清理，每轮累积 6 个。
- src/tests/middleware/errorResponseNoStore.test.js — 1 条（P3）— EXIT_REGISTRY 精确计数闸（有意设计，登记备查）。

无发现：
src/tests/middleware/abortedAuditReasonCleaning.test.js
src/tests/middleware/attackDetectionIntegration.test.js
src/tests/middleware/auditRefusalReason.test.js
src/tests/middleware/auditStreamingCoverage.test.js
src/tests/middleware/auth.test.js
src/tests/middleware/authMiddlewareFailClosedGuards.test.js
src/tests/middleware/authSecondBoundaryAndMfaCache.test.js
src/tests/middleware/avatarUnmatchedSurfaceGuard.test.js
src/tests/middleware/bodyNormalization.test.js
src/tests/middleware/canonicalizationParity.test.js
src/tests/middleware/cspNonce.test.js
src/tests/middleware/dataScopeConvergence.test.js
src/tests/middleware/dataScopeGuestReadOnly.test.js
src/tests/middleware/dataScopeRequestMemo.test.js
src/tests/middleware/forensicCapture.test.js
src/tests/middleware/forensicCaptureParity.test.js
src/tests/middleware/idempotencyDegradeSignal.test.js
src/tests/middleware/metricsAuth.test.js
src/tests/middleware/metricsAuthIpStrictness.test.js
src/tests/middleware/metricsHostGateExemption.test.js
src/tests/middleware/originCheck.test.js
src/tests/middleware/passwordChangeGate.test.js
src/tests/middleware/protocolCompliance.test.js
src/tests/middleware/queryLimit.test.js
src/tests/middleware/queryRejectionAuditTrail.test.js
src/tests/middleware/rateLimitHandlerOptions.test.js
src/tests/middleware/rateLimitKeyNormalization.test.js
src/tests/middleware/rateLimitStore.test.js
src/tests/middleware/rateLimitStoreFailover.test.js
src/tests/middleware/rateLimitStoreReadinessRace.test.js
src/tests/middleware/rbacSelfScopeExemption.test.js
src/tests/middleware/rbacWildcardAndDataScopeBounds.test.js
src/tests/middleware/reauthentication.test.js
src/tests/middleware/registerCaptchaRateLimit.test.js
src/tests/middleware/sanitizeMaterializeArms.test.js
src/tests/middleware/securityApplyAndCategoryGuard.test.js
src/tests/middleware/securityHeaderPolicyHardening.test.js
src/tests/middleware/sentryOutboundScrub.test.js
src/tests/middleware/sentrySmoke.test.js
src/tests/middleware/skipGlobalAuditTiming.test.js
src/tests/middleware/tokenBlacklistIndex.test.js
src/tests/middleware/writeMethodSingleSource.test.js
src/tests/middleware/xssProtectionHeader.test.js

### tests-obs-config（50 = 6 有发现 + 44 无发现）

有发现：
- src/tests/observability/logShipperTransportFailurePaths.test.js — 1 条（P3）— 模块顶层设置的两个安全开关 env 从不还原。
- src/tests/observability/auditBufferOutageKeepsAudit.test.js — 1 条（P3）— afterEach 清理漏 bypassAppendOnly，被 append-only 钩子拦截后静默吞掉，清理空转。
- src/tests/observability/auditBufferShutdownDrain.test.js — 1 条（P3）— 同上，真实落库记录留库。
- src/tests/observability/auditWalTrimIsPrecise.test.js — 1 条（P3）— 同上（insertMany 已 mock，暂无实际残留）。
- src/tests/config/deploymentCredentialGuards.test.js — 1 条（P3）— withMockedExit 中 logger.error 的 spy 从不 restore。
- src/tests/config/deployScriptInvariants.test.js — 1 条（P3）— 文本孤岛断言只保证"标识符在场"，防不住机制被改坏（已知残留）。

无发现：
src/tests/observability/alertRulesSyntax.test.js
src/tests/observability/alertingConfig.test.js
src/tests/observability/auditBufferFlushAndWalGuards.test.js
src/tests/observability/auditDropMetrics.test.js
src/tests/observability/auditWALPoisonDiscard.test.js
src/tests/observability/auditWalReclaimNotGatedByEnable.test.js
src/tests/observability/auditWalReplayIdempotency.test.js
src/tests/observability/businessMetrics.test.js
src/tests/observability/detectionMetrics.test.js
src/tests/observability/logShipperCloseDrains.test.js
src/tests/observability/logShipperDnsPinning.test.js
src/tests/observability/logShipperGapMarkerAccounting.test.js
src/tests/observability/logShipperGapMarkerIdentity.test.js
src/tests/observability/logShipperShutdownWiring.test.js
src/tests/observability/loggerFlush.test.js
src/tests/observability/loggerFlushFailure.test.js
src/tests/observability/loginAuditTrailFidelity.test.js
src/tests/observability/metricsMethodLabelClosure.test.js
src/tests/observability/observability.test.js
src/tests/observability/readyzSanitize.test.js
src/tests/observability/runtimeMetricsCoverage.test.js
src/tests/config/configParams.test.js
src/tests/config/corsOrigins.test.js
src/tests/config/databaseCredentialRedaction.test.js
src/tests/config/disposableSecretIsolation.test.js
src/tests/config/docsAccess.test.js
src/tests/config/gateLayerExistence.test.js
src/tests/config/hmacSecretConsumersSingleSource.test.js
src/tests/config/immutableConfigGuard.test.js
src/tests/config/migrateConfigHostQualifiedAllowlist.test.js
src/tests/config/mongoAuthWarning.test.js
src/tests/config/mongoTransportParity.test.js
src/tests/config/nodeEnvConsumers.test.js
src/tests/config/proxyProtocol.test.js
src/tests/config/runbookApplyCommandContract.test.js
src/tests/config/scriptSecretHydration.test.js
src/tests/config/startupGuards.test.js
src/tests/config/transportTlsAssertion.test.js
src/tests/config/trustedProxyCidrs.test.js
src/tests/config/upgradeConfigGuard.test.js
src/tests/config/validate.test.js
src/tests/config/validateStagingLeniencyAndConnections.test.js
src/tests/config/weakSecretCriteria.test.js
src/tests/config/weakSecretPlaceholder.test.js

### tests-const-models（46 = 9 有发现 + 37 无发现）

有发现：
- src/tests/models/ConsentRecord.test.js — 1 条（P2）— deleteMany 第 3 参被 mongoose 8 忽略，bypassAppendOnly 不生效，清库永久空转。
- src/tests/constants/honeypotDecoyAggregates.test.js — 1 条（P2）— 键集断言 toEqual(expect.arrayContaining([])) 恒真，8 个端点键序无验证。
- src/tests/models/consentRecordIpUaGuard.test.js — 1 条（P3）— 漏 bypassAppendOnly 的死清理，p3consent_* 跨运行残留。
- src/tests/models/AuditLog.test.js — 1 条（P3）— alertSpy 的 restore 前有 5 个 expect 且无 try/finally。
- src/tests/models/riskLevelScalarMembership.test.js — 1 条（P3）— 重复代码行导致行号回查指错（仅影响诊断定位）。
- src/tests/models/ForensicCapture.test.js — 1 条（P3）— env 变异与恢复无 try/finally，失败即残留同 worker。
- src/tests/constants/auditActionReachability.test.js — 1 条（P3）— 路由扫描只认单引号字面量，其他写法静默漏扫。
- src/tests/models/auditListTiebreakExplain.test.js — 1 条（P3）— 对共享集合物理索引的 explain 断言在并行重建时偶发红（待确认）。
- src/tests/models/auditChainConcurrency.test.js — 1 条（P3）— 每轮 40 条审计行留库（已知取舍，仅适用于一次性库）。

无发现：
src/tests/constants/alarmEnumSingleSource.test.js
src/tests/constants/auditActionReconciliation.test.js
src/tests/constants/businessDayBoundsIllegalCalendarDay.test.js
src/tests/constants/businessHourSingleSource.test.js
src/tests/constants/canaryAccounts.test.js
src/tests/constants/credentialShape.test.js
src/tests/constants/deadExportGuard.test.js
src/tests/constants/deploymentReplicaProof.test.js
src/tests/constants/detectionTokenGhosts.test.js
src/tests/constants/deviceStatusSingleSource.test.js
src/tests/constants/honeypotAccounts.test.js
src/tests/constants/honeypotDecoyGrantTimeline.test.js
src/tests/constants/honeypotDecoyMetricsAlerts.test.js
src/tests/constants/honeypotPersonas.test.js
src/tests/constants/inspectionEnumSingleSource.test.js
src/tests/constants/permissionStatusSingleSource.test.js
src/tests/constants/podOrdinalShape.test.js
src/tests/constants/singleProcessInventoryCompleteness.test.js
src/tests/constants/timezone.test.js
src/tests/constants/tzBusinessEnvNormalization.test.js
src/tests/constants/zonedDayBounds.test.js
src/tests/models/AuditLogBehavior.test.js
src/tests/models/IPBlacklist.test.js
src/tests/models/User.test.js
src/tests/models/auditLogAppendOnlyContract.test.js
src/tests/models/auditLogFieldRetention.test.js
src/tests/models/auditLogSanitizer.test.js
src/tests/models/auditRequestContext.test.js
src/tests/models/auditSanitizerDateFidelity.test.js
src/tests/models/auditSensitiveActionRiskFactors.test.js
src/tests/models/auditSparseIndexSemantics.test.js
src/tests/models/builtInRoleCodeSource.test.js
src/tests/models/deviceRecordCap.test.js
src/tests/models/fireAlarmProcessLogCap.test.js
src/tests/models/inspectionRetentionGate.test.js
src/tests/models/ipBlacklistBlockIpGuard.test.js
src/tests/models/roleBuiltInDeleteGuard.test.js

### tests-subdirs（71 = 8 有发现 + 63 无发现）

有发现：
- src/tests/routes/upgradeEndpoint.test.js — 1 条（P3）— 5 个 env 模块顶层设置且 afterAll 不恢复，泄漏同 worker。
- src/tests/routes/authLimiterWiring.test.js — 1 条（P3）— /mfa/enable 中间件链长精确相等断言，重构即碎。
- src/tests/routes/bodyTypeGate.test.js — 2 条（P3）— 权限码退化为恒 'dev:x'；afterAll 角色清理正则大小写失配。
- src/tests/routes/referenceArrayBoundary.test.js — 1 条（P3）— 清理正则匹配不到大写角色码，角色全部残留。
- src/tests/routes/forensicRoutesContract.test.js — 1 条（P3）— 遗留"即删"的临时诊断日志。
- src/tests/routes/wellKnown.test.js — 1 条（P3）— env 快照恢复未包 try/finally（同文件他处已用）。
- src/tests/migrations/auditUsernameCiIndex.test.js — 1 条（P3）— M-3 注释描述修复前历史却用"现状"措辞，误导为常红用例。
- src/tests/edge/edgeCases.test.js — 1 条（P3）— 文件头宣称的第 4 类边界（protocolCompliance）不在本文件。

无发现：
src/tests/routes/bodyStringGateCoverage.test.js
src/tests/routes/dataScopeContract.test.js
src/tests/routes/locationCoordinatesBoundary.test.js
src/tests/routes/privilegeGrantEndpoints.test.js
src/tests/routes/profileFieldClearability.test.js
src/tests/routes/readPermissionContract.test.js
src/tests/routes/registerSwitchOrder.test.js
src/tests/routes/routeGuardBranches.test.js
src/tests/routes/routeSchemaFieldParity.test.js
src/tests/routes/securityTxtCanonicalSource.test.js
src/tests/routes/versionEndpoint.test.js
src/tests/routes/writePermissionContract.test.js
src/tests/helpers/auditChainFixtures.js
src/tests/helpers/auditWriteSites.js
src/tests/helpers/authResponse.js
src/tests/helpers/buildLoginEnvelope.js
src/tests/helpers/codeErrorCallScan.js
src/tests/helpers/contentLevelWriteError.js
src/tests/helpers/jsCodeOnly.js
src/tests/helpers/pollTick.js
src/tests/helpers/posixShell.js
src/tests/helpers/reauthTicket.js
src/tests/helpers/routeMounts.js
src/tests/helpers/routeMounts.test.js
src/tests/helpers/stubPath.js
src/tests/helpers/waitFor.js
src/tests/migrations/auditListTiebreakIndexes.test.js
src/tests/migrations/cursorTiebreakIndexes.test.js
src/tests/migrations/deviceReminderTiebreakIndex.test.js
src/tests/migrations/filterTiebreakCompoundIndexes.test.js
src/tests/migrations/migrationReadmeLedger.test.js
src/tests/migrations/queryPerformanceIndexes.test.js
src/tests/migrations/reconcileAuditIndexOptions.test.js
src/tests/migrations/tokenBlacklistFixScriptBehavior.test.js
src/tests/migrations/ttlMigrationEmptyDb.test.js
src/tests/app/appBehaviorGuards.test.js
src/tests/app/appTrustProxyAndReadyzGuards.test.js
src/tests/app/earlyRejectionIpRateLimited.test.js
src/tests/app/earlyRejectionRateLimited.test.js
src/tests/app/earlyRejectionRateLimitedAllSurfaces.test.js
src/tests/app/earlyRejectionSecurityHeaders.test.js
src/tests/app/probeExemptionBoundaryAndHeadAudit.test.js
src/tests/app/queryDefenseSingleSource.test.js
src/tests/app/staticSurfaceRateLimitGate.test.js
src/tests/docs/changelogStructureGate.test.js
src/tests/docs/deliverablesReferenceIndex.test.js
src/tests/docs/documentationDrift.test.js
src/tests/docs/openapiSync.test.js
src/tests/docs/openapiTagDeclaration.test.js
src/tests/scripts/configDriftCheck.test.js
src/tests/scripts/configDriftYaml.test.js
src/tests/scripts/opsE2eEmptySelection.test.js
src/tests/scripts/verifyAuditExportScript.test.js
src/tests/compliance/auditChain.test.js
src/tests/compliance/auditChainGeneration.test.js
src/tests/compliance/retentionComplianceBehavior.test.js
src/tests/architecture/layeringRatchet.test.js
src/tests/architecture/requireCycles.test.js
src/tests/architecture/sensitiveFieldEgressContract.test.js
src/tests/plugins/autoCodeCounterReconcile.test.js
src/tests/plugins/autoIncrementConcurrentBirth.test.js
src/tests/fixtures/README.md
src/tests/fixtures/index.js

### tests-root-1（38 = 9 有发现 + 29 无发现）

有发现：
- src/tests/auditSpecialKeyPayload.test.js — 1 条（P3）— afterAll 的 append-only 清理未传 bypassAppendOnly，静默失效的死代码。
- src/tests/auditWalLimitsAndLines.test.js — 1 条（P3）— saved.max 快照未用于恢复，afterEach 无条件 delete。
- src/tests/auditExportDataScope.test.js — 1 条（P3）— 导出断言只数行数不校验集合，"错集合恰好同行数"仍双绿。
- src/tests/credentialValidityPredicates.test.js — 1 条（P3）— 用户状态恢复不在 try/finally，首断言失败即连环误报。
- src/tests/alarmHandlerCanOperate.test.js — 1 条（P3，JWT 签发重复组）— 本地 jwt.sign 小函数重复且 tokenVersion 口径不一。
- src/tests/authTemporaryLockExpiryBoundary.test.js — 1 条（P3，同组）— 同上。
- src/tests/deviceBuildingScope.test.js — 1 条（P3，同组）— 同上。
- src/tests/deviceCodeCap.test.js — 1 条（P3，同组）— 同上。
- src/tests/deviceExpiringDaysAndScrapReason.test.js — 1 条（P3，同组）— 同上。

无发现：
src/tests/alarmHandlerListVisibility.test.js
src/tests/alarmStatsScopeCast.test.js
src/tests/appendOnlyHashlessRow.test.js
src/tests/auditBodyProtoFidelity.test.js
src/tests/auditBufferZombieDuplicate.test.js
src/tests/auditCategoryLiteralWhitelist.test.js
src/tests/auditFailedStreamFlag.test.js
src/tests/auditFieldSetsImmutable.test.js
src/tests/auditFilterParity.test.js
src/tests/auditIndexDiff.test.js
src/tests/auditTtlMigration.test.js
src/tests/backfillTokenVersion.test.js
src/tests/backupScriptGuards.test.js
src/tests/behaviorBaselineWindows.test.js
src/tests/businessDayBoundsDstAdjacency.test.js
src/tests/businessDayExtremes.test.js
src/tests/businessLocalCodePrefix.test.js
src/tests/businessMonthWindowTimezone.test.js
src/tests/chainVerifyYieldAtScale.test.js
src/tests/clientIpCanonicalForm.test.js
src/tests/clusterCrashBackoff.test.js
src/tests/constants.js
src/tests/credentialKeySingleSource.test.js
src/tests/credentialRedactionSinks.test.js
src/tests/crossInstanceInvalidation.test.js
src/tests/dashboardCacheContract.test.js
src/tests/dataScopeDenyParity.test.js
src/tests/destructiveGuardOrder.test.js
src/tests/deviceUpdateFieldParity.test.js

### tests-root-2（38 = 5 有发现 + 33 无发现）

有发现：
- src/tests/inspectionAssigneeExists.test.js — 2 条（最高 P2）— 裸 Permission.create 播种 `*:*` 与兄弟套件撞 E11000 假红（P2）；Role/权限不回收（P3）。
- src/tests/loginPermissionSnapshotNulls.test.js — 2 条（最高 P2）— 固定 code 裸 create 与 adversarialProbeRegression 撞 E11000 假红（P2）；角色与权限不回收（P3）。
- src/tests/logShipperSchemeAllowlist.test.js — 1 条（P3）— 顶层放宽 LOG_SHIPPING_ALLOW_INSECURE 从不恢复。
- src/tests/inactiveRoleAuthorization.test.js — 1 条（P3）— beforeAll 夹具（用户/角色/权限）afterAll 不回收。
- src/tests/inspectionArrayCaps.test.js — 1 条（P3）— Role（ZZAC_${stamp}）不回收，与兄弟文件口径不一。

无发现：
src/tests/emittedErrorCodeCoverage.test.js
src/tests/encryptionRandomAndMasking.test.js
src/tests/envNumberGuard.test.js
src/tests/errorHandlerNoInternalLeak.test.js
src/tests/explainSpotcheckContract.test.js
src/tests/exportAuditLabelsTriState.test.js
src/tests/exportColumnDefsPinned.test.js
src/tests/exportLabelsLocalized.test.js
src/tests/exportTruncationCap.test.js
src/tests/fileAclDirectoryRecursiveGrant.test.js
src/tests/fileAclResetForFiles.test.js
src/tests/fullRangeInactiveSuperAdmin.test.js
src/tests/globalSetup.js
src/tests/globalTeardown.js
src/tests/illegalCalendarDayWithTime.test.js
src/tests/imageDigestGate.test.js
src/tests/imageDigestVerify.test.js
src/tests/inspectionFindingPhotoUrl.test.js
src/tests/inspectionInputBoundary.test.js
src/tests/inspectionWriteScopeGates.test.js
src/tests/integrityAttestation.test.js
src/tests/ipBlacklistEntryNormalization.test.js
src/tests/ipQueryAmbiguousRefusal.test.js
src/tests/ipRangeRuleCap.test.js
src/tests/k6JourneyContract.test.js
src/tests/loggerBoundaries.test.js
src/tests/loginCipherErrorTaxonomy.test.js
src/tests/loginIpRangeDeniedAudit.test.js
src/tests/loginTimingParity.test.js
src/tests/logoutTokenFork.test.js
src/tests/metricsSeriesFidelity.test.js
src/tests/mfaCounterFailClosed.test.js
src/tests/mfaLifecycleTotpClaim.test.js

### tests-root-3（36 = 4 有发现 + 32 无发现）

有发现：
- src/tests/playwrightConfig.test.js — 2 条（P3）— E2E 选择器门禁子串包含判断可假绿；countJourneys 行首正则漏计折行 test。
- src/tests/riskLevelSingleSource.test.js — 1 条（P3）— 档位清单正则只认单引号，双引号/反引号写法可静默绕过门禁。
- src/tests/reauthLimiterBucket.test.js — 2 条（P3）— 把 5 次/15 分钟阈值也一并钉死；限流桶清零依赖手工枚举的 3 种 IP 形态。
- src/tests/migrateConfigFailClosed.test.js — 1 条（P3）— fail-open 权衡被测试固化成回归锚（已文档化待决项，勿当缺陷整改）。

无发现：
src/tests/nodeEnvGateFailsClosed.test.js
src/tests/objectIdParamGuard.test.js
src/tests/permissionDecisionParity.test.js
src/tests/permissionHelperFailClosed.test.js
src/tests/populateMatchShape.test.js
src/tests/queryScalarNoWhitelistExemption.test.js
src/tests/reservedWildcardAssignment.test.js
src/tests/reservedWildcardPermission.test.js
src/tests/reservedWildcardRoleCreation.test.js
src/tests/rollbackEjson.test.js
src/tests/scopeCastFamily.test.js
src/tests/sessionCacheExpiryLag.test.js
src/tests/setup.js
src/tests/sharedCacheDegradationLog.test.js
src/tests/sharedCacheLockDegradationLogged.test.js
src/tests/sharedCacheLockToken.test.js
src/tests/sharedCacheNonceFailClosed.test.js
src/tests/staticFrontendSourcemapDeny.test.js
src/tests/statsScopeFailClosed.test.js
src/tests/stepUpTotpReplay.test.js
src/tests/systemConfigBooleans.test.js
src/tests/testSequencer.js
src/tests/totpEmptySecretNoBypass.test.js
src/tests/transactionProbe.test.js
src/tests/userDeleteCascade.test.js
src/tests/userWritePathScopeParity.test.js
src/tests/usernameCharsetAtModel.test.js
src/tests/verifyChainExitCode.test.js
src/tests/verifyScanBound.test.js
src/tests/webhookSsrfRangeWhitelist.test.js
src/tests/writeSurfaceControlCharAndHeadersSentGuards.test.js
src/tests/wsProbeVerdict.test.js

---

### 附录核对说明
- 各分区"有发现 + 无发现"合计：services-1 9+43=52；services-2 11+41=52；services-3 16+36=52；services-4 10+40=50；controllers-1 14+37=51；controllers-2 8+43=51；utils-1 6+33=39；utils-2 8+31=39；deploy 6+64=70；ci 6+45=51；security 5+45=50；middleware 5+43=48；obs-config 6+44=50；const-models 9+37=46；subdirs 8+63=71；root-1 9+29=38；root-2 5+33=38；root-3 4+32=36。总计 884，与分区清单总行数一致。
- 两处报告内部归类冲突已按"有发现"处理并在对应分区注明：controllers-1 的 authzSessionRevocationGuards（报告同时列入"注释过时"组与无发现清单）、services-4 的 websocketCorsAndReauthGuards 与 websocketAuthScope（报告同时列入合并 P3 条目与无发现清单）。
# 第三部分：管理端前端（web-admin/）

> 本部分由 10 份 web-admin 分区审计报告汇编而成（wa-views-1、wa-views-2、wa-components、wa-utils、wa-framework、wa-composables-assets、wa-tests-1、wa-tests-2、wa-tests-3、wa-root），所有行号与结论均原样保留自源报告。

## 3.1 分区概览

| 分区 | 文件数（应审/报告实记） | P0 | P1 | P2 | P3 | 一句话评语 |
|---|---|---|---|---|---|---|
| wa-views-1（views 前 12 文件） | 12 / 12 | 0 | 0 | 0 | 10 | 视图整体质量高，XSS、敏感数据落 DOM/日志、权限门控、竞态与清理均未见实际问题，余为死字段、catch 口径与样式重复等轻微项。 |
| wa-views-2（views 后 11 文件） | 11 / 11 | 0 | 0 | 0 | 6 | 全仓防护修整最密集的视图层，竞态守卫、重入锁、三态分离与幂等键齐备，余为 God component 与一致性小项。 |
| wa-components | 34 / 34 | 0 | 0 | 0 | 5 | 质量很高，口令密文轨、MFA、恢复码、图表转义等安全路径成体系，余为业务失败静默、暗色白块与死代码。 |
| wa-utils | 32 / 32 | 0 | 0 | 1 | 5 | 请求管线、错误打码、fail-closed 降级加固到位；P2 为 internalPath 的 `/\` 开放重定向形态（当前不可直接利用），余为 DRY/一致性。 |
| wa-framework | 25 / 25 | 0 | 0 | 1 | 5 | 路由守卫、auth store、i18n 防护到位；P2 为入口双语词表全量静态打包造成的首屏死重。 |
| wa-composables-assets | 20 / 20 | 0 | 0 | 0 | 7 | composables 职责单一、清理成对、竞态防护到位；余为重复实现与边界加固，另有 1 条跨文件测试盲区提示。 |
| wa-tests-1 | 53 / 53 | 0 | 0 | 0 | 5 | 断言落在可观测行为、mock 卫生良好、恒真断言有静态闸兜底；余为断言强度与源码文本脆弱性。 |
| wa-tests-2 | 53 / 53 | 0 | 0 | 0 | 6 | 可证伪断言 + 后端单一事实来源推导成体系；余为共享状态还原位置与模块单例隔离。 |
| wa-tests-3 | 51 / 51 | 0 | 0 | 0 | 5 | 行为断言 + 前提自证成体系，历史缺陷回归到位；余为 locale 还原位置与重复断言。 |
| wa-root | 14 / 14 | 0 | 0 | 0 | 7 | 构建安全头、dev 敏感文件拦截与 lockfile 供应链核查干净；余为文档可运行性、license 漂移等低危一致性问题。 |
| **合计** | **305 / 305** | **0** | **0** | **2** | **61** | — |

**核对说明：**
- 文件数核对：10 个分区的报告自称审查文件数与 `partitions/` 下同名清单行数**全部一致**（12=12、11=11、34=34、32=32、25=25、20=20、53=53、53=53、51=51、14=14），合计 305 = 305，无差异。
- P3 计数说明：上表 P3 列为各报告概览的自称统计（合计 61）。逐条明细实数为 **66 条**：wa-views-1（自称 10 / 明细 11）、wa-views-2（6 / 7）、wa-utils（5 / 6）、wa-root（7 / 8）四个分区的概览计数比明细各少 1 条；wa-composables-assets 另有 1 条跨文件「测试盲区提示（P3）」未计入其概览数。本报告 3.2/3.3 以逐条明细为准。

## 3.2 重点发现（P2 逐条展开；本部分无 P0/P1）

本部分（web-admin/ 全部 10 个分区）**未发现 P0、P1 级问题**；P2 共 2 条，逐条展开如下。

### P2-1 `web-admin/src/utils/internalPath.js:6-10` ｜ 安全性（开放重定向 / 纵深防御）

- **问题描述**：`safeInternalPath` 未拒绝 `/\evil.com` 形态的协议相对地址，构成经典 `/\` 开放重定向绕过形态。当前唯一消费方 `LoginView.vue:457` 走 `router.push(...)`（应用内路由，`/\evil.com` 只会落到应用内 404，不可跨域），故今日不可直接利用；配套测试 `web-admin/src/tests/router/loginRedirect.test.js:137-156` 也未覆盖该形态。属安全控件契约缺口。
- **证据**：`if (!value.startsWith('/') || value.startsWith('//')) return fallback` —— `/\evil.com` 以 `/` 开头且不以 `//` 开头，校验通过；而 WHATWG URL 规范在特殊协议（http/https/ws 等）下将 `\` 视同 `/`，一旦返回值被用于 `location.href` / `window.open` / 锚点 href 即构成开放重定向。
- **修复建议**：补充 `value.startsWith('/\\')`（及 `value.includes('\\')` 于开头段）判定，或改用 `new URL(value, location.origin)` 后比对 origin，并补对应用例。

### P2-2 `web-admin/src/i18n/index.js:2-3、75-78` ｜ 性能与资源（i18n 包体 / 首屏）

- **问题描述**：入口词表 zh-CN / en-US 双语全量静态打包，二者经 main.js → i18n 静态链全部进入首屏 chunk，运行时永远只用其一，约 34-37KB gzip 纯属死重；且登录页（最高频入口）同样承担。本仓已为 gzip 预算把 attackAlerts/attackProfile/stuffingProfile 词典拆出懒加载（见各词典头注释），入口级双语全量加载是同一预算下最后一块明显欠账。
- **证据**：`import zhCN from './locales/zh-CN'`、`import enUS from './locales/en-US'`、`const messages = { 'zh-CN': zhCN, 'en-US': enUS }`；zh-CN.js 实测 110.9KB（gzip 36.6KB）、en-US.js 115.7KB（gzip 34.0KB）。
- **修复建议**：`import.meta.glob('./locales/*.js')` 按 locale 懒加载，`setLocale` 内异步补载（切换瞬间可先回落当前语言或显示加载态），与既有词典拆分口径一致。

## 3.3 P3 发现汇总

按主题归组，每条一行（括号内为出处分区；同一行合并了少数跨文件同源问题）。

### A. God component 与架构一致性
- `web-admin/src/views/PrivilegeGrantView.vue:1-822（全文 1529 行）` — template 承载五块 UI、script 约 700 行，创建表单（行 87-478）宜拆独立子组件。（wa-views-2）
- `web-admin/src/views/PrivilegeGrantView.vue:1217-1222` — 用 `document.querySelector('.create-form')` 定位面板而非模板 ref，类名改名即静默失效。（wa-views-2）
- `web-admin/src/views/PrivilegeGrantView.vue:1274` — 视图直接重置组合式函数私有的失败标记 `userSearchFailed`，跨层写入他人状态。（wa-views-2）
- `web-admin/src/views/PrivilegeGrantView.vue:967-985、1202-1208` — 「即将到期」「高敏生效中」汇总卡点击落到泛化 `active` 筛选，卡片指标与点击结果语义不一致（待确认）。（wa-views-2）
- `web-admin/src/views/IpListView.vue:413、498、616、671、772、798、815、818` — 8 处直接裸调 `apiClient.get/post/delete('/security/ip-list...')`，绕过 `api.js` 接口封装层。（wa-views-1）

### B. DRY 与重复实现
- `web-admin/src/views/AlarmView.vue:978-1018` — 约 40 行「Apple 风格增量」样式与 AboutView:1139-1179、DeviceView:1187-1227、InspectionView:637-677、IpListView:980-1020（DashboardView:635-681 部分重复）逐字重复。（wa-views-1）
- `web-admin/src/utils/api.js:377 与 web-admin/src/utils/reauthError.js:12` — `REAUTH_TICKET_ERROR_CODES` 与错误码读取逻辑两处重复（循环依赖所致），建议下沉无依赖叶子模块。（wa-utils）
- `web-admin/src/utils/api.js:357 与 web-admin/src/utils/loginCipher.js:72` — `API_BASE_URL` 多处独立派生（versionWatcher.js:46-49 亦参与、口径不一），建议抽叶子常量模块。（wa-utils）
- `web-admin/src/utils/datetime.js:27-30、50-51` — `formatTime` 与 `toLocalWallClock` 各自重复拼装「YYYY-MM-DD HH:mm:ss」。（wa-utils）
- `web-admin/src/store/storage.js:18-53、66-99` — `safeStorage` 与 `safeLocal` 五个方法为两份同构拷贝，建议 `createSafeStorage(backing)` 工厂收敛。（wa-framework）
- `web-admin/src/store/app.js:28` — 默认语言推断与 i18n/index.js:34-35 重复实现，且 `navigator.language` 为空时兜底口径不一致（store 镜像 en-US、i18n 实际 zh-CN）。（wa-framework）
- `web-admin/src/composables/useRolePermissions.js:13-20、63-73、26-43 与 usePrivilegeGrantOptions.js:28-59、120-131` — 模块图标/名称映射与权限树扁平化双实现，去重键（`_id` vs `code`）与模块集合（6 vs 11）已漂移。（wa-composables-assets）

### C. 死代码与死配置
- `web-admin/src/views/AlarmView.vue:329` — `page.total` 从未读写，分页总数实际由 `listState.total` 托管。（wa-views-1）
- `web-admin/src/views/DeviceView.vue:441` — `page.total` 从未使用（总数由 `list.total` 托管）。（wa-views-1）
- `web-admin/src/views/InspectionView.vue:277` — `page.total` 从未使用（总数由 `listState.total` 托管）。（wa-views-1）
- `web-admin/src/components/InspectionCompleteForm.vue:216-229` — prop `inspectionTitle` 声明但从未消费，属死契约。（wa-components）
- `web-admin/src/components/InspectionCompleteForm.vue:325-339` — `validateFindings` 首分支 `result === 'normal' && value.length === 0` 不可达（包装器已提前 callback）。（wa-components）
- `web-admin/eslint.config.js:126` — `files` 含仓库中不存在的 `vitest.config.js`，死配置。（wa-root）

### D. 错误处理与可靠性口径
- `web-admin/src/views/AlarmView.vue:792-796` — `resolve()` 的 catch 只排除 `'cancel'` 未排除 `'close'`，与同文件其余三个 handler 双判据口径不一。（wa-views-1）
- `web-admin/src/views/DeviceView.vue:661-665` — `handleDelete` 的 catch 只判 `'cancel'`，同文件 handleChangeStatus/handleScrap 均为双判据。（wa-views-1）
- `web-admin/src/components/MfaSettingsCard.vue:357-363` — `enrollMfa` 对「HTTP 2xx 但 success:false」静默无提示（同文件其余三个写入口均有兜底）。（wa-components）
- `web-admin/src/components/DeviceMaintenanceDialog.vue:116-128` — `submit` 直接访问 `props.device._id` 未判空，父组件传 null 时点击确认抛 TypeError。（wa-components）
- `web-admin/src/utils/api.js:784-786` — 认证入口判定用裸 `includes`，`/auth/login-public-key` 会误命中 `/auth/login` 前缀（当前免鉴权无实害，属潜在漂移）。（wa-utils）
- `web-admin/src/utils/errorReporter.js:609-653` — flush 失败后不重新排程，收集端短暂不可达时待发批次可能长期滞留。（wa-utils）
- `web-admin/src/store/auth.js:383-404、415-465` — 登出/会话被覆盖时未重置 `postLoginRedirect`，同页「过期→登出→再登录」会复用上次深链目标。（wa-framework）
- `web-admin/src/router/index.js:158-187` — chunk 加载失败 15s 重试窗口内二次失败直接静默返回，无兜底路径或留痕。（wa-framework）
- `web-admin/src/views/DashboardView.vue:191-203` — `defineAsyncComponent` 未配 errorComponent，echarts chunk（约 583KB）加载失败后图表区永久空白。（wa-views-1）
- `web-admin/src/views/ReportView.vue:505-512` — 图表数据加载失败被完全静默，空白画布与「无数据」视觉不可区分。（wa-views-2）
- `web-admin/src/views/UserView.vue:1160-1182` — `handleBatchDelete` 未像同文件其他写操作那样加同步重入锁，双击会排队两次确认。（wa-views-2）
- `web-admin/src/composables/useCountUp.js:13` — `prefersReducedMotion()` 在模块加载时固化，会话中途开启「减弱动效」不生效。（wa-composables-assets）
- `web-admin/src/composables/useRolePermissions.js:274-284、195-220` — 勾选后又取消、集合回到与原始一致时 `hasUnsavedChanges` 不复位，产生未保存变更误报。（wa-composables-assets）
- `web-admin/src/composables/useRealtimeRefresh.js:24-48` — `joinRoom` 中途抛错不回滚已加入房间，且 catch 置空后卸载清理被短路（待确认，实际触发概率低）。（wa-composables-assets）
- `web-admin/src/composables/usePullToRefresh.js:76-83` — `onRefresh` 异常被双层静默吞掉，无上报或提示，契约会吃掉未来调用方的错误。（wa-composables-assets）

### E. 展示与交互一致性
- `web-admin/src/views/AttackAlertsView.vue:45-57`（AuditLogView.vue:7-17 同型） — `el-date-picker` 同时绑定 `@change` 与 `@clear`，部分 element-plus 版本清空时可能双触发相同查询（待确认）。（wa-views-1）
- `web-admin/src/views/AttackAlertsView.vue:101` — 静态字符串走了不必要的动态绑定 `:data-test="'alerts-filter-action'"`。（wa-views-1）
- `web-admin/src/views/AuditLogView.vue:723-725` — responseBody 的 `<pre>` 插值放在独立缩进行，与同文件其余 5 处写法不一致，预览多出前置换行与缩进。（wa-views-1）
- `web-admin/src/layout/index.vue:612-619` — `handleCommand` 的 `profile` 与 `password` 两个 case 完全相同，误导维护者。（wa-framework）

### F. 暗色主题
- `web-admin/src/components/AttackProfileResult.vue:539-545` — `.category-card` 硬编码 `background: #fff` 且全文件无 `html.dark` 覆盖，暗色主题下渲染成刺眼白块。（wa-components）

### G. 性能
- `web-admin/src/composables/usePointerGradient.js:21-29` — 每次 pointermove 都执行 `getBoundingClientRect()` 强制布局读取，与文件头「无重排开销」注释不符。（wa-composables-assets）
- （i18n 双语词表包体问题为 P2，见 3.2 P2-2，此处不重复计。）

### H. 安全余项（P3）
- `web-admin/src/views/UserView.vue:1356-1357`（另见 RegisterView.vue:725-726） — `encryptPassword` 返回 null（非安全上下文）时回退明文口令上行，与 ReportView.vue:624-628 的阻断口径不一，三处宜统一并写入文档（待确认）。（wa-views-2）
- `web-admin/vite.config.js:653-702` — 三个 dev 代理把客户端自带的 `x-forwarded-for` 原样透传给后端，`--host 0.0.0.0` 联调时局域网客户端可伪造 XFF 污染审计 IP（dev-only 取舍）。（wa-root）
- `web-admin/vite.config.js:233-300、704-721` — `blockSensitiveFilesPlugin` 只实现 `configureServer`，`vite preview` 无 URL 层敏感文件拦截，且 preview.fs.deny 比 server.fs.deny 少 `pnpm-lock.yaml` 与 `.npmrc`。（wa-root）

### I. 工程规范与文档
- `web-admin/README.md:8-12` — 快速上手安装步骤按非 workspace 现实不可运行（根目录无 workspaces，按操作后 `npm run dev` 将因缺少 vite 失败）。（wa-root）
- `web-admin/index.html:15-16、25` — 注释要求资源一律走 BASE_URL，但入口脚本写死 `src="/src/main.js"`，`--base=/admin/` 启动 dev server 时首屏 404，与注释矛盾。（wa-root）
- `web-admin/package.json:1-59` — 缺 `"private": true`，不可发布应用存在被误 publish 的理论风险。（wa-root）
- `web-admin/package.json:36` — `vue-i18n: 11.4.16` 为唯一精确锁定且无理由说明，版本约束策略不统一。（wa-root）
- `web-admin/package-lock.json:10` — lockfile 根 license 为 ISC，与 package.json:24 的 MIT 漂移（改 license 后未重新生成）。（wa-root）

### J. 测试卫生、断言强度与脆弱性
- `web-admin/src/tests/bundling/subpathDeployConfig.test.js:31-35、66-73` — 对源码文本字面量做 `toContain`（精确到箭头函数与引号风格），格式化改动即假红。（wa-tests-1）
- `web-admin/src/tests/components/attackEvidenceTable.test.js:42、70` — `expect(vm.text()).not.toContain('undefined')` 近恒真，缺已知 action 码投影文案的正向断言。（wa-tests-1）
- `web-admin/src/tests/components/dashboardCharts.test.js:339、657` — 两个不同 describe 重复使用组前缀 `C.`，误导读者。（wa-tests-1）
- `web-admin/src/tests/helpers/componentHarness.js:135-138、151` — `mountComponent` 返回 `{ handle, ...handle }` 把 `element` getter 求值一次固化为快照属性。（wa-tests-1）
- `web-admin/src/tests/i18n/attackAlertsDictionaryParity.test.js:97、115` — `backendCodesSet` 先使用后声明，排布误导读者且与同文件其它写法不一致。（wa-tests-1）
- `web-admin/src/tests/router/loginRedirect.test.js:159-165` — 「取用即清空」用例为同义反复，无任何生产代码参与，属假防护。（wa-tests-2）
- `web-admin/src/tests/layout/layout.test.js:816-836、1147-1169` — `process.off('unhandledRejection')` 注销未放 finally 且位于多个 await 之后，用例失败时监听器泄漏造成顺序依赖型假红。（wa-tests-2）
- `web-admin/src/tests/router/routeGuard.test.js:255-263、265-275、405-416` — 文件级共享 `mockStore` 的 `mustChangePassword` 靠用例尾部就地还原，前面断言失败则后续用例成片误导。（wa-tests-2）
- `web-admin/src/tests/utils/apiStatusCodes.test.js:39-47、142-155` — 本文件是 api 系列唯一不做 `vi.resetModules()` 逐用例隔离的，且「有牙对照」用例未排干异步登出链，乱序下可偶发假红。（wa-tests-2）
- `web-admin/src/tests/i18n/metricsAlertTypesCoverage.test.js:56-65` — 手工维护的 `INDIRECT_ALERT_TYPES` 补偿清单对后端未来「变量/模板形态」新增告警类型天然盲（已注释声明的固有盲区）。（wa-tests-2）
- `web-admin/src/tests/i18n/auditReasons.test.js:85-102` — 「接线闸」对源码压缩后精确表达式匹配，绑定具体变量名与写法，等价重构即误红（有意取舍，记录在案）。（wa-tests-2）
- `web-admin/src/tests/views/registerViewRender.test.js:218-236` — 语言切换用例把 locale 还原写在用例末尾而非 afterEach，断言失败时 en-US 泄漏给后续用例。（wa-tests-3）
- `web-admin/src/tests/views/loginView.test.js:424-437、462-477` — 同上，两条语言切换用例的 locale 还原不在 afterEach。（wa-tests-3）
- `web-admin/src/tests/views/auditLogExportJsonError.test.js:25-57` — 用花括号深度计数从 SFC 源码切出函数体再 `new Function` 执行，与源码排版耦合（失败形态是响亮的红，故 P3）。（wa-tests-3）
- `web-admin/src/tests/views/ipListView.test.js:1270-1271` — 连续两条完全相同的断言，复制粘贴残留。（wa-tests-3）
- `web-admin/src/tests/views/dashboardView.test.js:175、188` — afterEach 中 `vi.useRealTimers()` 被调用两次，无害冗余。（wa-tests-3）
- `web-admin/src/tests/composables/（跨文件）` — 12 个 composables 仅覆盖 9 个，`useRealtimeRefresh`、`usePrivilegeGrantList`、`usePrivilegeGrantOptions` 缺专属单测。（wa-composables-assets）

## 3.4 七维度分析

**① 代码质量与规范性**：整体规范性高，命名、注释与代码同步度好，未发现真实凭据/PII 泄漏。散落的死代码与死字段（`AlarmView.vue:329`、`DeviceView.vue:441`、`InspectionView.vue:277` 的 `page.total`；`InspectionCompleteForm.vue:216-229` 死 prop 与 `325-339` 不可达分支；`eslint.config.js:126` 死配置）及重复断言（`ipListView.test.js:1270-1271`、`dashboardView.test.js:175/188`）属打磨级问题。DRY 债相对集中：Apple 风格样式五文件重复（`AlarmView.vue:978-1018` 等）、`API_BASE_URL` 三处派生（`api.js:357`、`loginCipher.js:72`、`versionWatcher.js:46-49`）、REAUTH 错误码两处（`api.js:377`、`reauthError.js:12`）、`safeStorage` 双拷贝（`store/storage.js:18-53/66-99`）与权限图标/扁平化双实现（`useRolePermissions.js:13-20`、`usePrivilegeGrantOptions.js:28-59`）。

**② 架构与工程结构（含 composables 化进展）**：分层清晰（views / components / composables / utils / store / router / i18n / schemas），composables 化进展良好——12 个 composables 职责单一、清理成对，`useLatestRequest` 竞态门票与 `useListLoadState` 三态契约已成体系，测试覆盖 9/12（盲区：useRealtimeRefresh、usePrivilegeGrantList、usePrivilegeGrantOptions）。遗留架构债主要是 `PrivilegeGrantView.vue` 仍是 1529 行 God component（template 822 行，行 1-822），并存在跨层写状态（行 1274）与 DOM 查询代替 ref（行 1217-1222）；`IpListView.vue` 8 处裸调 apiClient 绕过 api 封装层（行 413 等）。store 层还有 storage 双拷贝与默认语言双实现（`store/app.js:28` vs `i18n/index.js:34-35`）待收口。

**③ 安全性（XSS / Token 存储 / 权限纵深）**：整体态势好。全部分区未见 v-html / innerHTML / eval、localStorage/sessionStorage 存敏感数据、window.opener 滥用；口令密文轨 fail-closed、MFA 瞬态密钥卸载擦除、恢复码一次性展示、权限推送 zod 校验并过滤 `*:*` 通配、错误上报 URL/凭据打码均已成体系。两项值得关注：一是 `internalPath.js:6-10` 未拒绝 `/\evil.com` 协议相对形态（P2，当前唯一消费方走 router.push 不可跨域，属纵深缺口）；二是 `UserView.vue:1356-1357`（另见 RegisterView.vue:725-726）在 WebCrypto 不可用时回退明文口令上行，与 `ReportView.vue:624-628` 的阻断口径不一（P3 待确认）。权限纵深方面，前端 hasPerm 门控与后端权限码逐一对齐，属展示层收口而非唯一闸。

**④ 性能与资源（i18n 包体、监听器清理）**：最主要欠账是 `i18n/index.js:2-3、75-78` 将双语词表（合计 gzip 约 70KB）全量静态打进首屏，运行时只用其一，登录页同样承担；词典级懒加载已有先例，入口级拆分是最后一块。其次是 `usePointerGradient.js:21-29` 每次 pointermove 强制布局读取。监听器/定时器/ResizeObserver/WebSocket 的卸载清理纪律整体优秀（composables 成对释放、视图层卸载清理成体系、WebSocket 引用计数），仅 `useCountUp.js:13` 的 reduced-motion 标志在模块加载时固化一处置后。

**⑤ 测试与可靠性**：测试是 web-admin 最强项——157 个测试文件断言普遍落在可观测行为（DOM/请求载荷/路由/副作用），普遍带「前提自证 / 反例对照 / 变异验证」，恒真断言由 `ci/tautologyGuard.test.js` 静态闸兜底。改进点集中在：源码文本字面量断言的脆弱性（`subpathDeployConfig.test.js:31-35`、`auditReasons.test.js:85-102`）、近恒真断言（`attackEvidenceTable.test.js:42`）、共享状态还原位置（`routeGuard.test.js:255-275`、`layout.test.js:816-836`、`registerViewRender.test.js:218-236`、`loginView.test.js:424-437`）与模块单例隔离（`apiStatusCodes.test.js:39-47`）。产品代码侧可靠性余项：`MfaSettingsCard.vue:357-363` 业务失败静默、`DashboardView.vue:191-203` 异步图表无 errorComponent、`ReportView.vue:505-512` 图表失败无持久失败态、`router/index.js:158-187` chunk 二次失败静默。

**⑥ 可观测性**：errorReporter 体系（URL/凭据脱敏、缓冲、pagehide 兜底）+ webVitals + reportDegradation 齐备，且有专门测试族覆盖（errorReporter* 7 个测试文件）。待补的一环是 `errorReporter.js:609-653` flush 失败后不重新排程，收集端短暂不可达时滞留批次可能长期滞留。同类「失败不可见」漏网还有：`usePullToRefresh.js:76-83` 双层吞掉刷新异常、`DashboardView.vue:191-203` 图表加载失败仅控制台告警、`router/index.js:158-187` 窗口内二次失败无留痕，建议统一接入 errorReporter / reportDegradation。

**⑦ 文档与知识传承**：代码内注释质量高——大量「为什么」级注释、历史审计编号回链（WF-07、WB-2/L8/P0 等）与修复说明，wa-components 报告的复核说明章节也体现了防误报纪律，知识传承在代码层扎实。短板在面向使用者的文档：`README.md:8-12` 的安装步骤按非 workspace 现实不可运行；`index.html:15-16` 注释与行 25 写死路径自相矛盾；`package.json:36` 精确锁定 vue-i18n 无理由说明。建议补 README 修正、共享 util 契约文档（如 encryptPassword 降级口径三处统一）与依赖锁定策略说明。

## 3.5 逐文件附录

### 分区 wa-views-1（12 个文件）

有发现（7 个）：
- `web-admin/src/views/AlarmView.vue` — 3 条（P3） — page.total 死字段、resolve catch 口径不一、Apple 风格样式五处重复。
- `web-admin/src/views/AttackAlertsView.vue` — 2 条（P3） — date-picker @change+@clear 疑似双触发、静态字符串动态绑定。
- `web-admin/src/views/AuditLogView.vue` — 1 条（P3） — responseBody pre 插值缩进与其余 5 处不一致（行 7-17 另有 date-picker 同型问题）。
- `web-admin/src/views/DashboardView.vue` — 1 条（P3） — 异步图表组件缺 errorComponent，加载失败永久空白。
- `web-admin/src/views/DeviceView.vue` — 2 条（P3） — page.total 死字段、handleDelete catch 口径不一。
- `web-admin/src/views/InspectionView.vue` — 1 条（P3） — page.total 死字段。
- `web-admin/src/views/IpListView.vue` — 1 条（P3） — 8 处裸调 apiClient 绕过 api.js 封装层。

无发现（5 个）：
- web-admin/src/views/AboutView.vue
- web-admin/src/views/AttackProfileView.vue
- web-admin/src/views/AuditLogView.css
- web-admin/src/views/ForensicTraceView.vue
- web-admin/src/views/LoginView.vue

### 分区 wa-views-2（11 个文件）

有发现（3 个）：
- `web-admin/src/views/PrivilegeGrantView.vue` — 4 条（P3） — God component、querySelector 定位面板、跨层重置组合式函数状态、汇总卡点击语义不一致。
- `web-admin/src/views/ReportView.vue` — 1 条（P3） — 图表加载失败完全静默，无持久失败态与重试入口。
- `web-admin/src/views/UserView.vue` — 2 条（P3） — handleBatchDelete 缺同步重入锁、encryptPassword null 回退与 ReportView 口径不一。

无发现（8 个）：
- web-admin/src/views/PrivilegeGrantView.css
- web-admin/src/views/ProfileView.vue
- web-admin/src/views/RegisterView.css
- web-admin/src/views/RegisterView.vue
- web-admin/src/views/RoleView.vue
- web-admin/src/views/SecurityAnalysisView.vue
- web-admin/src/views/StuffingProfileView.vue
- web-admin/src/views/UserView.css

### 分区 wa-components（34 个文件）

有发现（4 个）：
- `web-admin/src/components/AttackProfileResult.vue` — 1 条（P3） — .category-card 硬编码 #fff 且无暗色覆盖。
- `web-admin/src/components/DeviceMaintenanceDialog.vue` — 1 条（P3） — submit 未判 props.device 空。
- `web-admin/src/components/InspectionCompleteForm.vue` — 2 条（P3） — inspectionTitle 死 prop、validateFindings 不可达分支。
- `web-admin/src/components/MfaSettingsCard.vue` — 1 条（P3） — enrollMfa 对 2xx 但 success:false 静默无提示。

无发现（30 个）：
- web-admin/src/components/AccountBindingsCard.vue
- web-admin/src/components/AttackEvidenceTable.vue
- web-admin/src/components/AuthPrefs.vue
- web-admin/src/components/ChangePasswordCard.vue
- web-admin/src/components/DashboardCharts.vue
- web-admin/src/components/DashboardWelcome.vue
- web-admin/src/components/DeviceReminderDialog.vue
- web-admin/src/components/ExitOverlay.vue
- web-admin/src/components/GlassSegmented.vue
- web-admin/src/components/GlassSkeleton.vue
- web-admin/src/components/InspectionForm.vue
- web-admin/src/components/InspectionReviewForm.vue
- web-admin/src/components/LiquidGlassButtons.vue
- web-admin/src/components/MyLogsCard.vue
- web-admin/src/components/PasswordStrengthMeter.vue
- web-admin/src/components/PermissionModuleCard.vue
- web-admin/src/components/ReauthDialog.vue
- web-admin/src/components/RecentAlarmsCard.vue
- web-admin/src/components/RegisterSummary.vue
- web-admin/src/components/ReportDialog.vue
- web-admin/src/components/RoleFormDialog.vue
- web-admin/src/components/RoleListPanel.vue
- web-admin/src/components/ScrambleText.vue
- web-admin/src/components/SearchPalette.vue
- web-admin/src/components/SecurityInfoCard.vue
- web-admin/src/components/SecurityStatsCard.vue
- web-admin/src/components/SessionManager.vue
- web-admin/src/components/UpdateNoticeBar.vue
- web-admin/src/components/UpgradeDialog.vue
- web-admin/src/components/UserAvatar.vue

### 分区 wa-utils（32 个文件）

有发现（5 个）：
- `web-admin/src/utils/api.js` — 3 条（最高 P3） — 认证入口裸 includes 前缀误命中、REAUTH 错误码两处重复、API_BASE_URL 多处派生。
- `web-admin/src/utils/datetime.js` — 1 条（P3） — 时间串拼装两处重复。
- `web-admin/src/utils/errorReporter.js` — 1 条（P3） — flush 失败不重新排程，待发批次滞留。
- `web-admin/src/utils/internalPath.js` — 1 条（P2） — 未拒绝 `/\evil.com` 协议相对地址（当前不可直接利用）。
- `web-admin/src/utils/loginCipher.js` — 1 条（P3） — 公钥地址内联派生 API_BASE_URL，与 api.js 口径可能漂移。

无发现（27 个）：
- web-admin/src/utils/attackProfileReport.js
- web-admin/src/utils/auditLabels.js
- web-admin/src/utils/auditTrace.js
- web-admin/src/utils/avatarImage.js
- web-admin/src/utils/copyText.js
- web-admin/src/utils/encryptionError.js
- web-admin/src/utils/enterSubmit.js
- web-admin/src/utils/forensicLabels.js
- web-admin/src/utils/haptic.js
- web-admin/src/utils/idempotency.js
- web-admin/src/utils/ipLocationLabels.js
- web-admin/src/utils/labelMaps.js
- web-admin/src/utils/motion.js
- web-admin/src/utils/password.js
- web-admin/src/utils/permission.js
- web-admin/src/utils/privacyNotice.js
- web-admin/src/utils/privilegeGrant.js
- web-admin/src/utils/reauthError.js
- web-admin/src/utils/reauthTicket.js
- web-admin/src/utils/routePrefetch.js
- web-admin/src/utils/securityLabels.js
- web-admin/src/utils/sessionSync.js
- web-admin/src/utils/updateNotice.js
- web-admin/src/utils/versionWatcher.js
- web-admin/src/utils/webVitals.js
- web-admin/src/utils/websocket.js
- web-admin/src/utils/withSyncLock.js

### 分区 wa-framework（25 个文件）

有发现（6 个）：
- `web-admin/src/i18n/index.js` — 1 条（P2） — 入口双语词表全量静态打包进首屏，约 34-37KB gzip 死重。
- `web-admin/src/layout/index.vue` — 1 条（P3） — handleCommand 的 profile 与 password 两个 case 完全相同。
- `web-admin/src/router/index.js` — 1 条（P3） — chunk 重试窗口内二次失败静默返回，无兜底路径。
- `web-admin/src/store/app.js` — 1 条（P3） — 默认语言推断与 i18n 重复实现且空值兜底口径不一致。
- `web-admin/src/store/auth.js` — 1 条（P3） — 登出/会话覆盖未重置 postLoginRedirect。
- `web-admin/src/store/storage.js` — 1 条（P3） — safeStorage/safeLocal 五方法两份同构拷贝。

无发现（19 个）：
- web-admin/src/App.vue
- web-admin/src/constants/attackAlerts.js
- web-admin/src/constants/metricsAlertTypes.js
- web-admin/src/data/ipLocationDictionary.json
- web-admin/src/directives/segGlass.js
- web-admin/src/i18n/auditReasons.js
- web-admin/src/i18n/auditRiskFactors.js
- web-admin/src/i18n/locales/attackAlerts.en-US.js
- web-admin/src/i18n/locales/attackAlerts.zh-CN.js
- web-admin/src/i18n/locales/attackProfile.en-US.js
- web-admin/src/i18n/locales/attackProfile.zh-CN.js
- web-admin/src/i18n/locales/en-US.js
- web-admin/src/i18n/locales/stuffingProfile.en-US.js
- web-admin/src/i18n/locales/stuffingProfile.zh-CN.js
- web-admin/src/i18n/locales/zh-CN.js
- web-admin/src/i18n/systemLabels.js
- web-admin/src/main.js
- web-admin/src/schemas/index.js
- web-admin/src/store/index.js

### 分区 wa-composables-assets（20 个文件）

有发现（6 个）：
- `web-admin/src/composables/useCountUp.js` — 1 条（P3） — reduced-motion 标志模块加载时固化，会话中途开启不生效。
- `web-admin/src/composables/usePointerGradient.js` — 1 条（P3） — 每次 pointermove 强制布局读取，与头注释不符。
- `web-admin/src/composables/usePrivilegeGrantOptions.js` — 1 条（P3） — 与 useRolePermissions 重复的图标/名称映射与权限树扁平化。
- `web-admin/src/composables/usePullToRefresh.js` — 1 条（P3） — onRefresh 异常被双层吞掉，无上报。
- `web-admin/src/composables/useRealtimeRefresh.js` — 1 条（P3） — joinRoom 部分失败不回滚且清理被短路（待确认）。
- `web-admin/src/composables/useRolePermissions.js` — 2 条（P3） — hasUnsavedChanges 复原后不复位、图标/扁平化映射与 usePrivilegeGrantOptions 重复。

无发现（14 个）：
- web-admin/src/assets/styles/apple-polish.css
- web-admin/src/assets/styles/apple-refine.css
- web-admin/src/assets/styles/dark.css
- web-admin/src/assets/styles/global.css
- web-admin/src/assets/styles/print.css
- web-admin/src/assets/styles/view-refine.css
- web-admin/src/auto-imports.d.ts
- web-admin/src/components.d.ts
- web-admin/src/composables/useLatestRequest.js
- web-admin/src/composables/useListLoadState.js
- web-admin/src/composables/usePermission.js
- web-admin/src/composables/usePermissionSync.js
- web-admin/src/composables/usePrivilegeGrantList.js
- web-admin/src/composables/useStepTransition.js

跨文件提示（P3，不计入单文件）：`web-admin/src/tests/composables/` 覆盖 9/12 个 composables，`useRealtimeRefresh.js`、`usePrivilegeGrantList.js`、`usePrivilegeGrantOptions.js` 缺专属单测。

### 分区 wa-tests-1（53 个文件）

有发现（5 个）：
- `web-admin/src/tests/bundling/subpathDeployConfig.test.js` — 1 条（P3） — 对源码文本字面量做 toContain 断言，格式化改动即假红。
- `web-admin/src/tests/components/attackEvidenceTable.test.js` — 1 条（P3） — not.toContain('undefined') 近恒真，缺投影文案正向断言。
- `web-admin/src/tests/components/dashboardCharts.test.js` — 1 条（P3） — 两个 describe 重复使用组前缀 C.。
- `web-admin/src/tests/helpers/componentHarness.js` — 1 条（P3） — 展开 handle 固化 element getter 为挂载时刻快照。
- `web-admin/src/tests/i18n/attackAlertsDictionaryParity.test.js` — 1 条（P3） — 常量先使用后声明，排布误导读者。

无发现（48 个）：
- web-admin/src/tests/app.test.js
- web-admin/src/tests/bundling/devProxyForwardedFor.test.js
- web-admin/src/tests/bundling/manualChunks.test.js
- web-admin/src/tests/ci/tautologyGuard.test.js
- web-admin/src/tests/components/attackProfileResult.test.js
- web-admin/src/tests/components/authPrefs.test.js
- web-admin/src/tests/components/changePasswordCard.test.js
- web-admin/src/tests/components/dashboardWelcome.test.js
- web-admin/src/tests/components/deviceMaintenanceDialog.test.js
- web-admin/src/tests/components/deviceReminderDialog.test.js
- web-admin/src/tests/components/exitOverlay.test.js
- web-admin/src/tests/components/glassSegmented.test.js
- web-admin/src/tests/components/glassSkeleton.test.js
- web-admin/src/tests/components/inspectionCompleteForm.test.js
- web-admin/src/tests/components/inspectionForm.test.js
- web-admin/src/tests/components/inspectionFormCrossRecordReset.test.js
- web-admin/src/tests/components/inspectionFormSearchResidue.test.js
- web-admin/src/tests/components/inspectionReviewForm.test.js
- web-admin/src/tests/components/liquidGlassButtons.test.js
- web-admin/src/tests/components/mfaSettingsCard.test.js
- web-admin/src/tests/components/passwordStrengthMeter.test.js
- web-admin/src/tests/components/permissionModuleCard.test.js
- web-admin/src/tests/components/reauthDialog.test.js
- web-admin/src/tests/components/recentAlarmsCard.test.js
- web-admin/src/tests/components/registerSummary.test.js
- web-admin/src/tests/components/reportDialog.test.js
- web-admin/src/tests/components/roleFormDialog.test.js
- web-admin/src/tests/components/roleListPanel.test.js
- web-admin/src/tests/components/scrambleText.test.js
- web-admin/src/tests/components/searchPalette.test.js
- web-admin/src/tests/components/securitySelfCards.test.js
- web-admin/src/tests/components/securityStatsCard.test.js
- web-admin/src/tests/components/sessionManager.test.js
- web-admin/src/tests/components/updateNoticeBar.test.js
- web-admin/src/tests/components/upgradeDialog.test.js
- web-admin/src/tests/composables/useCountUp.test.js
- web-admin/src/tests/composables/useLatestRequest.test.js
- web-admin/src/tests/composables/useListLoadState.test.js
- web-admin/src/tests/composables/usePermission.test.js
- web-admin/src/tests/composables/usePermissionSync.test.js
- web-admin/src/tests/composables/usePointerGradient.test.js
- web-admin/src/tests/composables/usePullToRefresh.test.js
- web-admin/src/tests/composables/useRolePermissionsToggle.test.js
- web-admin/src/tests/composables/useStepTransition.test.js
- web-admin/src/tests/directives/segGlass.test.js
- web-admin/src/tests/directives/segGlassIntegration.test.js
- web-admin/src/tests/i18n/attackProfileDictionaryParity.test.js
- web-admin/src/tests/i18n/auditActionCoverage.test.js

### 分区 wa-tests-2（53 个文件）

有发现（6 个）：
- `web-admin/src/tests/i18n/auditReasons.test.js` — 1 条（P3） — 对源码压缩后精确表达式匹配，等价重构即误红（有意取舍）。
- `web-admin/src/tests/i18n/metricsAlertTypesCoverage.test.js` — 1 条（P3） — 手工补偿清单对后端变量形态新增告警类型天然盲。
- `web-admin/src/tests/layout/layout.test.js` — 1 条（P3） — unhandledRejection 注销未入 finally，失败时监听器泄漏。
- `web-admin/src/tests/router/loginRedirect.test.js` — 1 条（P3） — 「取用即清空」用例同义反复，无生产代码参与。
- `web-admin/src/tests/router/routeGuard.test.js` — 1 条（P3） — 共享 mockStore 靠用例尾部就地还原，前面失败则成片误导。
- `web-admin/src/tests/utils/apiStatusCodes.test.js` — 1 条（P3） — 未逐用例隔离模块单例，异步登出链未排干，乱序可偶发假红。

无发现（47 个）：
- web-admin/src/tests/i18n/auditRiskFactors.test.js
- web-admin/src/tests/i18n/enumLabelCoverage.test.js
- web-admin/src/tests/i18n/errorCodesI18n.test.js
- web-admin/src/tests/i18n/i18nEntry.test.js
- web-admin/src/tests/i18n/localeKeyParity.test.js
- web-admin/src/tests/i18n/messageCompiler.test.js
- web-admin/src/tests/i18n/rawKeys.test.js
- web-admin/src/tests/i18n/stuffingProfileDictionaryParity.test.js
- web-admin/src/tests/i18n/validationMessagesFollowLocale.test.js
- web-admin/src/tests/router/componentFileCase.test.js
- web-admin/src/tests/router/loginRedirectBase.test.js
- web-admin/src/tests/router/routeTable.test.js
- web-admin/src/tests/store/appStore.test.js
- web-admin/src/tests/store/appStoreThemeListener.test.js
- web-admin/src/tests/store/authPersistenceNoPii.test.js
- web-admin/src/tests/store/authStore.test.js
- web-admin/src/tests/store/permissionSync.test.js
- web-admin/src/tests/store/schemasExtras.test.js
- web-admin/src/tests/store/storage.test.js
- web-admin/src/tests/store/storeBarrel.test.js
- web-admin/src/tests/styles/printStyles.test.js
- web-admin/src/tests/styles/tooltipTheme.test.js
- web-admin/src/tests/utils/apiAbortSignalLifecycle.test.js
- web-admin/src/tests/utils/apiDriftLru.test.js
- web-admin/src/tests/utils/apiRefreshRaceRecovery.test.js
- web-admin/src/tests/utils/apiRemainingBranches.test.js
- web-admin/src/tests/utils/apiRequestPipeline.test.js
- web-admin/src/tests/utils/apiUpgradePollingSupport.test.js
- web-admin/src/tests/utils/attackProfileReport.test.js
- web-admin/src/tests/utils/auditTrace.test.js
- web-admin/src/tests/utils/avatarImage.test.js
- web-admin/src/tests/utils/datetime.test.js
- web-admin/src/tests/utils/degradationReporting.test.js
- web-admin/src/tests/utils/devOnlyExports.test.js
- web-admin/src/tests/utils/deviceStatusParity.test.js
- web-admin/src/tests/utils/enterSubmit.test.js
- web-admin/src/tests/utils/errorCodeI18n.test.js
- web-admin/src/tests/utils/errorReporter.test.js
- web-admin/src/tests/utils/errorReporterBufferEdges.test.js
- web-admin/src/tests/utils/errorReporterFlushLock.test.js
- web-admin/src/tests/utils/errorReporterLifecycle.test.js
- web-admin/src/tests/utils/errorReporterRedactionShapes.test.js
- web-admin/src/tests/utils/errorReporterSentry.test.js
- web-admin/src/tests/utils/errorReporterStackPreserve.test.js
- web-admin/src/tests/utils/haptic.test.js
- web-admin/src/tests/utils/idempotency.test.js
- web-admin/src/tests/utils/ipLocationCodeParity.test.js

### 分区 wa-tests-3（51 个文件）

有发现（5 个）：
- `web-admin/src/tests/views/auditLogExportJsonError.test.js` — 1 条（P3） — 花括号深度计数从 SFC 源码切函数体，与源码排版耦合。
- `web-admin/src/tests/views/dashboardView.test.js` — 1 条（P3） — afterEach 中 useRealTimers 重复调用两次。
- `web-admin/src/tests/views/ipListView.test.js` — 1 条（P3） — 连续两条完全相同断言，复制粘贴残留。
- `web-admin/src/tests/views/loginView.test.js` — 1 条（P3） — 两条语言切换用例的 locale 还原不在 afterEach。
- `web-admin/src/tests/views/registerViewRender.test.js` — 1 条（P3） — locale 还原写在用例末尾而非 afterEach，与姊妹文件不同步。

无发现（46 个）：
- web-admin/src/tests/utils/ipLocationDictionary.test.js
- web-admin/src/tests/utils/labelMapsSemantics.test.js
- web-admin/src/tests/utils/loginCipher.test.js
- web-admin/src/tests/utils/passwordRule.test.js
- web-admin/src/tests/utils/passwordRulesParity.test.js
- web-admin/src/tests/utils/permission.test.js
- web-admin/src/tests/utils/privacyNoticeParity.test.js
- web-admin/src/tests/utils/privilegeGrantPolicyParity.test.js
- web-admin/src/tests/utils/reauthTicket.test.js
- web-admin/src/tests/utils/routePrefetch.test.js
- web-admin/src/tests/utils/securityLabels.test.js
- web-admin/src/tests/utils/securitySuggestionParity.test.js
- web-admin/src/tests/utils/sessionDeath401.test.js
- web-admin/src/tests/utils/sessionSyncChannel.test.js
- web-admin/src/tests/utils/storageHygiene.test.js
- web-admin/src/tests/utils/systemLabels.test.js
- web-admin/src/tests/utils/updateNotice.test.js
- web-admin/src/tests/utils/versionWatcher.test.js
- web-admin/src/tests/utils/webVitals.test.js
- web-admin/src/tests/utils/webVitalsBranches.test.js
- web-admin/src/tests/utils/webVitalsP75.test.js
- web-admin/src/tests/utils/websocket.test.js
- web-admin/src/tests/utils/withSyncLock.test.js
- web-admin/src/tests/views/aboutVersion.test.js
- web-admin/src/tests/views/aboutView.test.js
- web-admin/src/tests/views/aboutViewMetrics.test.js
- web-admin/src/tests/views/aboutViewUpgrade.test.js
- web-admin/src/tests/views/alarmView.test.js
- web-admin/src/tests/views/attackAlertsView.test.js
- web-admin/src/tests/views/attackProfileView.test.js
- web-admin/src/tests/views/auditLogView.test.js
- web-admin/src/tests/views/canceledErrorGuards.test.js
- web-admin/src/tests/views/deviceView.test.js
- web-admin/src/tests/views/forensicTraceView.test.js
- web-admin/src/tests/views/inspectionView.test.js
- web-admin/src/tests/views/privilegeGrantView.test.js
- web-admin/src/tests/views/profileView.test.js
- web-admin/src/tests/views/profileViewLateMeKeepsEdits.test.js
- web-admin/src/tests/views/registerView.test.js
- web-admin/src/tests/views/reportView.test.js
- web-admin/src/tests/views/reportViewCharts.test.js
- web-admin/src/tests/views/roleView.test.js
- web-admin/src/tests/views/roleViewPermission.test.js
- web-admin/src/tests/views/securityAnalysisView.test.js
- web-admin/src/tests/views/stuffingProfileView.test.js
- web-admin/src/tests/views/userView.test.js

### 分区 wa-root（14 个文件）

有发现（6 个）：
- `web-admin/README.md` — 1 条（P3） — 快速上手安装步骤按非 workspace 现实不可运行。
- `web-admin/eslint.config.js` — 1 条（P3） — files 含仓库中不存在的 vitest.config.js，死配置。
- `web-admin/index.html` — 1 条（P3） — 注释要求走 BASE_URL 但入口脚本写死根绝对路径，自相矛盾。
- `web-admin/package-lock.json` — 1 条（P3） — 根 license ISC 与 package.json 的 MIT 漂移。
- `web-admin/package.json` — 2 条（P3） — 缺 "private": true；vue-i18n 唯一精确锁定且无理由说明。
- `web-admin/vite.config.js` — 2 条（P3） — dev 代理透传客户端 XFF 可被伪造；preview 模式缺敏感文件拦截且 deny 清单少两项。

无发现（8 个）：
- web-admin/.env.example
- web-admin/.prettierrc
- web-admin/bundle-budget.json
- web-admin/dev-vite.cmd
- web-admin/postcss.config.js
- web-admin/public/favicon.svg
- web-admin/public/robots.txt
- web-admin/public/theme-bootstrap.js

---
（附录文件总数核对：12 + 11 + 34 + 32 + 25 + 20 + 53 + 53 + 51 + 14 = 305，与分区清单总行数一致。）
# 第四部分：脚本、文档、基础设施与依赖

> 汇编自 5 份分区审计报告（scripts-1、scripts-2、docs-github、infra、root-configs）及 2026-11-17 实测 npm audit 依赖扫描结果。所有发现均原样保留原报告的路径与行号。

## 4.1 分区概览

| 分区 | 文件数（应审/报告实记） | P0 | P1 | P2 | P3 | 一句话评语 |
|---|---|---|---|---|---|---|
| scripts-1 | 46 / 46 | 0 | 1 | 1 | 5 | 运维脚本高水准：argv 拼接、密钥走 env/`*_FILE`、临时文件 0600、fail-closed 判据齐备；残余 1 个 P1（证书守卫误删旧私钥）与旗标缺值 fail-open |
| scripts-2 | 46 / 46 | 0 | 0 | 1 | 8 | 安全姿态很高（无 shell 拼接、无字面量凭据、破坏性操作双确认），主要问题是回滚演练全量快照 OOM 风险与 8 条 P3 级加固/一致性尾巴 |
| docs-github | 55 / 55 | 0 | 0 | 0 | 10 | 文档与代码一致性经抽查全部吻合，8 个 CI 工作流权限/钉 SHA 全部合规；仅存文档路径失准与 CI job 超时/并发配置缺失 |
| infra | 50 / 50 | 0 | 0 | 0 | 4 | 部署配置自洽且有契约测试与 drift 基线把守；4 条 P3 均为面板/文档/死配置级漂移，无可利用漏洞 |
| root-configs | 29 / 26 | 0 | 0 | 1 | 8 | 根配置质量高（占位符 env、digest 钉扎、secrets 文件注入、网络分段）；问题集中在模板产出与代码判据不一致及少量清单漂移 |
| **合计** | **226 / 223** | **0** | **1** | **3** | **35** | — |

**文件数核对差异说明**：root-configs 分区报告自称「审查文件数：26（分区清单共 28 项，跳过 2 份历史审计报告）」，但分区清单 `partitions/root-configs.txt` 实为 **29 行**；扣除按纪律跳过的 2 份（AUDIT-REPORT-2026-11-14.md、AUDIT-REPORT-2026-11-15.md），实审应为 **27** 个。报告少记 1。经逐项核对，报告的「未见问题文件（20）+ 有发现文件（7）+ 纪律跳过（2）」并集恰好等于清单 29 项，**覆盖无缺口**，属报告自计数口径偏差而非漏审。其余 4 个分区报告实记数与清单行数完全一致。

## 4.2 重点发现（P1/P2 逐条展开）

### 4.2.1 `scripts/generate-dev-cert.sh:35-55` | P1 | 安全性/可靠性 | EXIT trap 误删既有证书与私钥
- **问题描述**：「拒绝覆盖既有证书」守卫触发的 `exit 1` 会被 EXIT trap 当作失败清理，反而删除用户已存在的证书与私钥——与脚本自述意图（“旧私钥一旦覆盖无法找回”）恰好相反。
- **证据**：行 35-41 守卫中 `exit 1` 触发行 55 的 `trap cleanup_on_failure EXIT`；`cleanup_on_failure` 内 `status=$?` 非零即执行 `rm -f "$KEY" "$CERT"`，此时两文件正是被守卫保护的旧文件。若该私钥已复制进内网信任库或正被本地 HTTPS 服务加载，删除即造成 TLS 中断与凭据丢失。
- **修复建议**：仅在“本次运行确实创建了证书”后才允许清理（openssl 成功后置 `CREATED=1`，trap 内 `[ "$CREATED" = 1 ]` 才 rm）；或将 trap 安装推迟到存在性检查之后。

### 4.2.2 `scripts/check-audit-allowlist.js:297/303/127` | P2 | 安全性（fail-open） | 旗标缺值静默取 undefined，过期豁免判据整体失效
- **问题描述**：`--today`（及 `--report`/`--allowlist`）缺值时静默取 `undefined`，`node scripts/check-audit-allowlist.js --today`（漏敲日期）不报用法错误，而是“今天=undefined”导致 `expired` 恒空，过期豁免项全部静默放行——失败方向是 fail-open，且与同仓 deployPolicy/bundleBudgetPolicy/generate-secrets「缺值一律报错，绝不猜」的纪律相悖。
- **证据**：行 297 `const value = inline !== undefined ? inline : argv[++i];`（旗标在末尾时为 undefined）；行 303 `opts.today = value`；行 127 `expired: allowlist.entries.filter((e) => e.reviewBy < today)`（`x < undefined` 恒 false）。`--report`/`--allowlist` 缺值虽以退出码 2 收场，但报错文案（“无法读取/解析 audit 报告 undefined”）不指向真正手误。
- **修复建议**：值缺失（下一个 token 不存在或以 `--` 开头）时立即 `errors.push` 并退出 2，与同族脚本对齐。

### 4.2.3 `scripts/run-rollback-drill.js:198-209` | P2 | 性能与资源 | 全量快照无上限内存化，GB 级集合 OOM 风险
- **问题描述**：backupCollection 对整集合 `find({}).toArray()` 一次性载入内存，随后 `JSON.stringify`、`gzipSync`、AES 加密各再复制一份，峰值内存约为集合体积的数倍且无任何上限；auditlogs/users 在真实库上易达 GB 级，OOM 时演练中断（快照先于 deleteMany 完成，OOM 不损数据，回灌段失败可整脚本重跑自愈）。
- **证据**：行 198-209 `const docs = await collection.find({}).toArray();` … `const payload = encryptBackup(zlib.gzipSync(JSON.stringify(docs.map(toSerializable))));`。同仓 `importOfflineBundle.js` 为同类大对象校验专门实现了流式 sha256（注释明确以 OOM 为失效形态），本脚本却对自家快照无上限全量内存化。
- **修复建议**：改用 cursor 流式写 NDJSON（脚本后缀本就是 `.ndjson.gz`，逐条序列化 + 流式 gzip/加密即可）；或至少按批次分片 + 显式文档数/字节上限，超限 fail-closed。

### 4.2.4 `docker-compose.yml:1011`（配合 `scripts/generate-secrets.js:192`） | P2 | 可靠性/配置一致性 | 管理员初始口令生成口径与生产强度闸冲突
- **问题描述**：compose 密钥生成口径产出的 `admin_initial_password` 为 base64(24 字节)=32 字符，字符集仅 `[A-Za-z0-9+/]`（24 字节无 `=` 填充），“特殊字符”只能靠 `+`/`/`（每字符约 3.1% 概率），约 **36% 的生成结果不含任何特殊字符**。该值经 `ADMIN_INITIAL_PASSWORD_FILE` 注入后走 `resolveInitialAdminPassword()` 的强度闸，不满足即抛错拒绝启动——compose 标准生产部署首次启动约 1/3 概率初始化失败。
- **证据**：compose 手抄清单 `# openssl rand -base64 24 | tr -d '\n' > ./secrets/admin_initial_password`（docker-compose.yml:1011）；生成器 `admin_initial_password: b64(24)`（scripts/generate-secrets.js:192）；消费点 `if (requiresProductionSemantics()) { const strengthError = validatePasswordStrength(explicitPassword); if (strengthError) { throw new Error('ADMIN_INITIAL_PASSWORD 不满足口令强度要求...') } }`（src/services/initData/adminAccount.js:137-144，判据 src/utils/helpers.js:91 `PASSWORD_SPECIAL_REGEX` + 行 100-106 四类字符规则）。报错响亮、可手工补救，但属模板自身自相矛盾。
- **修复建议**：生成侧改为保证四类字符的形态（参照应用内 `generateInitialAdminPassword()` 的 `Aa1!` + hex 前缀法），或 compose/generate-secrets 同步给出「含特殊字符」的生成命令。

## 4.3 P3 发现汇总（35 条，按主题归组）

**A. 死代码 / 注释与实现失同步（9 条）**
- `scripts/auditCountAssertionScan.js:30/272-273/440` — ASSERT_WINDOW 死常量全文件无引用，行 272 JSDoc 仍描述旧行开窗语义，实现已改字符开窗。
- `scripts/commentDensity.js:385-392` — `--update-baseline` 分支内联手写与 `refusalDetails()` 同构的拒绝明细拼装，两处文案必然漂移。
- `scripts/offlineBundleIntakePolicy.js:296-300` — 悬空函数文档注释，其描述的“挑文件条目”函数已不存在，直接衔接 `const FLAGS`。
- `scripts/configDriftYaml.js:全文件` — 缺文件头/能力边界说明；行 63-82 对重复键静默后者覆盖，用作漂移检测底座存在盲区。
- `scripts/configDriftYamlLex.js:全文件` — 缺文件头/词法能力边界说明。
- `deployment/secret-rotation.md:415-416` — 交叉引用「六重影响」实为「七重影响」（第 7 个消费点加入后未回改）。
- `README.md:478` — 备份 crontab 示例残留旧路径 `/opt/xf`，照抄到 /opt/fsms 部署会备份失败。
- `README.md:458` — `security:audit` 描述仍写 “high 及以上”，package.json:32-34 实为 `--audit-level=moderate`。
- `CONTRIBUTING.md:9` — Node 版本要求写「CI 另测 24」，实际 CI 矩阵 22/24/26、生产镜像 node:26.12.0-alpine。

**B. CI 治理与效率（6 条）**
- `.github/workflows/ci.yml:1-25` — 未配置 `concurrency` 组，同分支连续 push/push+PR 并行重复消耗 runner。
- `.github/workflows/ci.yml:140-147、249-257` — 3 个 Node leg 各跑一次前端构建 + 全量套件按 3 seed 重跑（3×3=9 次额外全量 Jest），建议收敛到单 leg。
- `.github/workflows/codeql.yml:12-14` — `analyze` job 未设 `timeout-minutes`（默认 360 分钟）。
- `.github/workflows/dependency-review.yml:22-24` — job 未设 `timeout-minutes`。
- `.github/workflows/dr-readiness.yml:34-38` — `drill-recency` job 未设 `timeout-minutes`。
- `.github/workflows/release.yml:31-45` — `release` job 未设 `timeout-minutes`。

**C. 安全纵深加固（4 条）**
- `docker/app-entrypoint.sh:118-130` — UPGRADE_QUEUE_DIR 系统目录黑名单漏 `/opt`、`/srv`、`/boot`、`/bin`、`/lib`、`/proc`、`/sys`、`/dev`，误配成 bind-mount 宿主目录时会对宿主目录树 chown/chmod。
- `scripts/resignLedger.js:95-101` — append-only 留痕文件 `openSync(path,'a')` 未指定 mode，落地 0644，应 0600 并 fchmod 兜底。
- `scripts/update-ip2region.js:221-224` — 临时文件“检查后写入”留有理论 TOCTOU 窗口，建议改 `openSync(tmp,'wx',0o600)`。
- `scripts/importOfflineBundle.js:197-223` — resolveBundleDir 用 `statSync` 跟随符号链接，未像 payload 层那样 lstat 拒链（待确认，缓解因素充分）。

**D. 护栏次序与可测性（3 条）**
- `scripts/perf/explain-spotcheck.js:167-179` — 生产库守卫在 `mongoose.connect` 之后才判，被拒绝的执行已完成对目标库的握手。
- `scripts/verify-audit-export.js:240` — `main()` 模块顶层无条件执行、无导出，纯判据函数无法单测。
- `scripts/revoke-user-sessions.js:33-112` — 参数解析/护栏/执行 IIFE 全在顶层，无 `require.main === module` 守卫、无导出。

**E. 依赖与清单一致性（3 条）**
- `package.json:70`（对应 `package-lock.json:27`） — mongoose 声明 `^8.24.9` 而锁文件根块仍记 `^8.0.3`，manifest↔锁文件根块漂移，现有 check:lockfile 语义锚检测不到。
- `package.json:80-82` — `overrides: { "uuid": "^11.1.1" }` 在锁文件中无任何记录，overrides 未随锁文件固化。
- `package.json:全文` — 未声明 `"private": true`，`npm publish` 理论可达，与本仓供应链纪律不匹配。

**F. 可观测性（2 条）**
- `deployment/observability/grafana/dashboards/xf-backend.json:531-538` — fail-open 面板 type 正则只覆盖告警规则（alert-rules.yml:94）9 类中的 4 类，5 类 critical 降级告警时面板无曲线。
- `docs/incident-response.md:22-23` — 告警规则引用不存在的 `observability/alert-rules.yml`，实际路径为 `deployment/observability/alert-rules.yml`。

**G. 文档冗余与引用未入库（3 条）**
- `docs/pii-export-quota.md:22-28` — 文末两小节以残片形式重复前文已完整表述的 INCR/TTL/`null=未配置` 语义。
- `docs/adr/ADR-013-蜜罐账户与诱饵登录.md:666` — 引用未入版本库的 `work/hp-edge-cases.md`，干净 checkout 打不开。
- `docs/adr/ADR-017-无body请求的body归一.md:19` — 引用未入库的 `work/lead/probe-body5.cjs`，干净 checkout 无法复核。

**H. 运维脚本/模板一致性（2 条）**
- `start.bat:97-105` — 前端缺 node_modules 时执行 `npm install`（非 `npm ci`），可能弄脏锁文件触发 CI 锁文件锚红灯。
- `Dockerfile:158` — `apk add dumb-init tzdata su-exec` 未钉版本/digest，同 digest 不同构建时间最终层可漂移。

**I. 迁移死配置（1 条，涉 7 个文件）**
- `migrations/20260831000000-reconcile-audit-index-options.js:77,89,99`、`20260926000000:123,141`、`20260928000000:108`、`20261021000000:142,168,174`、`20261101000000:156,167`、`20261103000000:79,90`、`20261201000000:134,145` — `createIndex(..., { background: true })` 在 mongod 8.0.34 是服务端忽略的 no-op（`_lib/indexSpec.js:91` 自述不进签名），属死配置，20260831000000:16 注释仍写「后台构建，低峰执行」易误导。

**J. 脚本健壮性（1 条）**
- `scripts/alert-delivery-probe.js:112-116` — postAlerts 对响应体无大小上限、无界累积，宜比照 hotUpgrade.js 设 maxBuffer（如 64KB 即断）。

**K. 可移植性（1 条）**
- `scripts/offlineBundleIntakePolicy.js:79-99` — 清单行正则假定 GNU tar 日期布局，bsdtar（macOS/部分容器）环境会以“缺少必需条目”误报（方向 fail-closed，不误解包）。

## 4.4 七维度分析

**① 代码质量与规范性**：整体显著高于常见运维脚本水准——文件头用途/退出码说明、fail-closed 判据、argv 数组拼接、密钥只走 env/`*_FILE`、临时文件 0600 + trap 清理基本齐备。残余问题集中在死代码与注释失同步：`scripts/auditCountAssertionScan.js:30` 死常量、`scripts/offlineBundleIntakePolicy.js:296-300` 悬空注释、7 个迁移的 `background:true` 死配置（如 `migrations/20260831000000:77`）、`scripts/commentDensity.js:385-392` 内联重复逻辑。`scripts/configDriftYaml.js` 与 `configDriftYamlLex.js` 缺少同仓惯例的文件头能力边界说明。

**② 架构与工程结构**：分区组织清晰（scripts/perf、scripts/ops-e2e、scripts/audit-probes、migrations/_lib），跨文件契约经只读交叉验证成立（destructiveGuard 的 isFallback、deployCommands 的 HOT_UPGRADE_IMAGE 只经 env）。结构性短板在依赖清单治理：`package.json:70` 与 `package-lock.json:27` 的 mongoose 范围漂移暴露了 check-lockfile-integrity.js 只锚锁文件本身、检测不到「manifest↔锁文件根块」漂移的盲区；叠加 overrides 未落盘（`package.json:80-82`）与缺 `private:true`，供应链治理链条存在末梢缺口。

**③ 安全性（CI 权限/钉 SHA、容器加固、密钥处理）**：CI 侧 8 个工作流全部声明最小化 permissions、第三方 action 全部钉 commit SHA，无 `pull_request_target`、无 `${{ github.event.* }}` 直入 shell、fork PR 路径无 secrets 暴露（docs-github 分区逐项核验），deploy.yml 的 digest 钉死 + cosign 验签 + known_hosts fail-closed 均为正确实现。容器侧主要缺口是 `docker/app-entrypoint.sh:118-130` 的 UPGRADE_QUEUE_DIR 黑名单不完整（漏 /opt、/srv、/boot 等）。密钥处理总体规范，残余风险为 `scripts/resignLedger.js:95-101` 留痕文件 0644、`scripts/update-ip2region.js:221-224` 理论 TOCTOU、`scripts/importOfflineBundle.js:197-223` statSync 跟链（待确认）；`scripts/check-audit-allowlist.js:297` 旗标缺值 fail-open 与 `scripts/generate-dev-cert.sh:35-55` 误删旧私钥是本部分仅有的 P1/P2 级安全问题。

**④ 性能与资源**：最大风险点是 `scripts/run-rollback-drill.js:198-209` 的全量快照无上限内存化（GB 级集合 OOM）；次为 `scripts/alert-delivery-probe.js:112-116` 响应体无界累积。CI 侧 `.github/workflows/ci.yml:140-147、249-257` 的 3 leg × 3 seed 重复全量套件与三次前端构建使 test job 时长接近翻倍（有书面理由的有意取舍，但边际收益递减）。

**⑤ 测试与可靠性**：`scripts/verify-audit-export.js:240` 与 `scripts/revoke-user-sessions.js:33-112` 缺 `require.main` 守卫与导出，纯判据不可单测，与同族脚本（lint-ratchet.js、resign-audit-hmac.js 等）已建立的口径不一致；`scripts/perf/explain-spotcheck.js:167-179` 守卫次序违背“被拒绝的执行不向目标库握手”纪律。e2e 门禁数字自洽（6 spec × 17 用例 × 2 project = 34，e2e/README），对“假绿”有 fail-closed 门禁。可靠性层面最实际的问题是 `docker-compose.yml:1011` 初始口令口径与强度闸冲突——生产首启约 36% 概率失败，但报错响亮可人工补救；`start.bat:97-105` 的 npm install 则可能弄脏锁文件触发 CI 红灯。

**⑥ 可观测性与运维**：面板与告警存在实质不对齐——`deployment/observability/grafana/dashboards/xf-backend.json:531-538` 的 fail-open 面板只覆盖告警规则（alert-rules.yml:94）9 类 type 中的 4 类，5 类 critical 降级触发告警时值班在面板上看不到曲线，易误判为误报；`docs/incident-response.md:22-23` 的告警规则路径错误会拖慢应急。CI 治理缺口：ci.yml 缺 concurrency，codeql/dependency-review/dr-readiness/release 四个 workflow 缺 timeout-minutes。Grafana 数据源预配置（datasource.yml，主审补读）为内网服务名、editable:false、无凭据，无问题。仓库自我登记的两项未闭环事项（deployment/deploy-workflow-rehearsal.md:63-66 首次 staging 演练待执行、deployment/rollback-drill-record.md:16-20 完整回滚演练与 RTO 4h 验证未真实执行，已有 dr-readiness.yml 周期判红兜底）应继续跟踪。

**⑦ 文档与知识传承（文档与代码同步度）**：同步度整体很高——docs/architecture.md 的路由数 16、控制器数 16、服务层 112、模型 18 及宿主端口表（3000/3001/9090/9093 全绑 127.0.0.1）均实测相符；文档引用的 60+ 脚本/测试/deployment 路径逐一存在；package.json 的 express ^5.3.0、morgan ^1.12.1 与 ADR-007/security-dependency-watch.md 记载一致。残余漂移：`deployment/secret-rotation.md:415-416`「六重影响」实为七重、`README.md:478` 残留 /opt/xf 旧路径、`README.md:458` audit-level 描述滞后一档、`CONTRIBUTING.md:9` Node 矩阵滞后、`docs/pii-export-quota.md:22-28` 整节重复；`docs/adr/ADR-013:666`、`docs/adr/ADR-017:19` 引用未入库的 work/ 路径，干净 checkout 不可复核，建议纳入 docs/internal-evidence-index.md 的登记口径。

## 4.5 依赖安全扫描（npm audit，2026-11-17 实测）

**根项目**：moderate 19 / high 0 / critical 0。
- minimatch GHSA-g3hv-75wg-m249（globparts DoS）经 jest/glob、nodemon（直接依赖）、test-exclude 传入，均为 dev 链。
- jest-runtime / jest-snapshot 经 @jest/transform 的 moderate。
- 修复多为可用；个别需将 jest 降回 29.7.0（semver major，需评估）。

**web-admin**：moderate 7 / high 0 / critical 0。
- glob GHSA-3g3m-2fjr-6pw4（AbortSignal 绕过）经 workbox-build → vite-plugin-pwa（直接依赖）。
- minimatch 经 eslint 链。
- 修复建议：vite-plugin-pwa 1.1.0（降级）与 @eslint/js 9.39.5。

**结论**：无运行时生产依赖的 high/critical CVE；风险集中在 dev/构建链。此前台账关注的 mongoose GHSA-6972-9mcm-vhwj 已不在当前审计结果中（mongoose ^8.24.9）。

## 4.6 覆盖度补注

1. `deployment/observability/grafana/datasources/datasource.yml` 未列入 infra 分区报告，由主审亲自补读：内容为 Grafana Prometheus 数据源预配置（内网服务名 `http://prometheus:9090`、`editable: false`、无凭据），未发现问题。
2. 仓库根两份历史审计报告（`AUDIT-REPORT-2026-11-14.md`、`AUDIT-REPORT-2026-11-15.md`）按「独立重审」纪律未作为输入，root-configs 分区亦按同一纪律跳过未审。
3. infra 分区报告另登记两项「仓库内已自我登记的未闭环事项」（非新发现，不计入发现统计）：`deployment/deploy-workflow-rehearsal.md:63-66`（deploy.yml 首次真实 staging 演练待执行，阻塞项为 staging runner / SSH 四密钥）与 `deployment/rollback-drill-record.md:16-20`（完整回滚演练与 RTO 4h 验证未真实执行，文件头已声明不得对外声称已完成，有 dr-readiness.yml 周期判红兜底）。

## 4.7 逐文件附录

### 分区 scripts-1（46 个文件）

**有发现（7 个）：**
- `scripts/generate-dev-cert.sh` — 1 条（P1）— EXIT trap 把守卫的 exit 1 当失败清理，误删既有证书与私钥。
- `scripts/check-audit-allowlist.js` — 1 条（P2）— 旗标缺值静默取 undefined，--today 漏敲使过期豁免判据整体 fail-open。
- `scripts/auditCountAssertionScan.js` — 1 条（P3）— ASSERT_WINDOW 死常量，JSDoc 与字符开窗实现失同步。
- `scripts/commentDensity.js` — 1 条（P3）— --update-baseline 分支内联重复 refusalDetails 的拒绝明细拼装。
- `scripts/configDriftYaml.js` — 1 条（P3）— 缺文件头说明；重复键静默后者覆盖，漂移检测存在盲区。
- `scripts/configDriftYamlLex.js` — 1 条（P3）— 缺文件头/词法能力边界说明。
- `scripts/alert-delivery-probe.js` — 1 条（P3）— postAlerts 响应体无大小上限，无界累积。

**无发现（39 个）：**
scripts/access-review.js
scripts/alertProbeRecord.js
scripts/alertRulesPolicy.js
scripts/alertmanager-config-path.js
scripts/audit-chain-checkpoint.js
scripts/audit-probes/README.md
scripts/audit-probes/ws-session-bypass.cjs
scripts/backup-integrity-patrol.js
scripts/backup-mongo.sh
scripts/backupArtifactScan.js
scripts/backupCrypto.sh
scripts/backupIntegrityPolicy.js
scripts/build-offline-bundle.sh
scripts/bundleBudgetPolicy.js
scripts/capture-image-digests.sh
scripts/check-alertmanager-config.js
scripts/check-bundle-budget.js
scripts/check-changelog-structure.js
scripts/check-clock-sync.js
scripts/check-lockfile-integrity.js
scripts/check-openapi-drift.js
scripts/check-prod-install-scripts.js
scripts/check-utf8.js
scripts/cliFlagPolicy.js
scripts/commentDensity.baseline.json
scripts/compliance-alerting.js
scripts/compliance-check.js
scripts/complianceVerdicts.js
scripts/config-drift-check.js
scripts/deploy.js
scripts/deployCommands.js
scripts/deployPolicy.js
scripts/destructiveGuard.js
scripts/devSecretIsolation.js
scripts/drReadinessPolicy.js
scripts/e2e-smoke.js
scripts/fix-token-blacklist-index.js
scripts/generate-secrets.js
scripts/hotUpgrade.js

### 分区 scripts-2（46 个文件）

**有发现（8 个）：**
- `scripts/run-rollback-drill.js` — 1 条（P2）— 快照对整集合全量 toArray() 内存化，GB 级集合有 OOM 风险。
- `scripts/offlineBundleIntakePolicy.js` — 2 条（P3）— 悬空函数文档注释；清单正则仅支持 GNU tar 布局，bsdtar 环境误报。
- `scripts/perf/explain-spotcheck.js` — 1 条（P3）— 生产库守卫在 mongoose.connect 之后才判，先握手后拒绝。
- `scripts/importOfflineBundle.js` — 1 条（P3）— resolveBundleDir 用 statSync 跟随符号链接，未与 payload 层同口径拒链（待确认）。
- `scripts/resignLedger.js` — 1 条（P3）— append-only 留痕文件未按 0600 创建，落地 0644。
- `scripts/update-ip2region.js` — 1 条（P3）— 临时文件“检查后写入”留有理论 TOCTOU 窗口。
- `scripts/verify-audit-export.js` — 1 条（P3）— 模块顶层无条件执行、无导出，纯判据函数不可单测。
- `scripts/revoke-user-sessions.js` — 1 条（P3）— 参数解析/护栏/执行 IIFE 全在顶层，无 require.main 守卫无导出。

**无发现（38 个）：**
scripts/hotUpgradeAgent.js
scripts/hotUpgradeJob.js
scripts/hotUpgradePolicy.js
scripts/hotUpgradeQueue.js
scripts/hotUpgradeStatusSink.js
scripts/invalidate-mfa-recovery-codes.js
scripts/lint-ratchet.js
scripts/load-test.js
scripts/loadTestEngine.js
scripts/login-key-pin.js
scripts/migrate-mfa-secret.js
scripts/migrate-pii-encryption.js
scripts/mongoUri.sh
scripts/offlineBundleIntake.js
scripts/offlineBundleIntakeArchive.js
scripts/offlineBundleIntakeExec.js
scripts/offlineBundlePolicy.js
scripts/offlineBundleScan.js
scripts/offlineBundleSignature.js
scripts/ops-e2e.js
scripts/ops-e2e/journey.js
scripts/ops-e2e/journeys/alert-delivery.js
scripts/ops-e2e/journeys/backup-restore.js
scripts/ops-e2e/journeys/cross-department.js
scripts/ops-e2e/journeys/deploy-rollback.js
scripts/ops-e2e/lib.js
scripts/perf/README.md
scripts/perf/k6-core-journeys.js
scripts/production-drill.js
scripts/provision-mongod.js
scripts/record-rollback-drill.js
scripts/resign-audit-chain-v3.js
scripts/resign-audit-hmac.js
scripts/restore-mongo.sh
scripts/secretFileArg.js
scripts/sync-audit-indexes.js
scripts/verify-audit-chain.js
scripts/verify-image-digests.js

### 分区 docs-github（55 个文件）

**有发现（9 个）：**
- `docs/incident-response.md` — 1 条（P3）— 告警规则引用不存在的 observability/ 相对路径。
- `docs/adr/ADR-013-蜜罐账户与诱饵登录.md` — 1 条（P3）— 引用未入库的 work/hp-edge-cases.md。
- `docs/adr/ADR-017-无body请求的body归一.md` — 1 条（P3）— 引用未入库的 work/lead/probe-body5.cjs。
- `docs/pii-export-quota.md` — 1 条（P3）— 文末两小节重复前文 INCR/TTL 语义。
- `.github/workflows/ci.yml` — 2 条（P3）— 缺 concurrency 组；矩阵内前端构建×3 与随机门禁 3×3 重复 workload。
- `.github/workflows/codeql.yml` — 1 条（P3）— analyze job 未设 timeout-minutes。
- `.github/workflows/dependency-review.yml` — 1 条（P3）— job 未设 timeout-minutes。
- `.github/workflows/dr-readiness.yml` — 1 条（P3）— drill-recency job 未设 timeout-minutes。
- `.github/workflows/release.yml` — 1 条（P3）— release job 未设 timeout-minutes。

**无发现（46 个）：**
docs/adr/ADR-001-登录口令ECDH信封加密.md
docs/adr/ADR-002-审计链哈希设计.md
docs/adr/ADR-003-密钥管理策略.md
docs/adr/ADR-004-审计链单进程锁假设.md
docs/adr/ADR-005-多实例状态外置与Redis回退策略.md
docs/adr/ADR-006-高量级列表游标分页选型.md
docs/adr/ADR-007-express5迁移评估与决策.md
docs/adr/ADR-008-数据范围强制方式.md
docs/adr/ADR-009-网络分段与数据面隔离.md
docs/adr/ADR-010-不引入分布式追踪的适用边界.md
docs/adr/ADR-011-注释治理-源码只保留当前约束.md
docs/adr/ADR-012-临时权限授予与定期复核.md
docs/adr/ADR-014-请求级幂等与响应回放.md
docs/adr/ADR-015-登录失败触发的人机挑战与锁定收口.md
docs/adr/ADR-016-管理员重置口令后的口令复用收口.md
docs/adr/ADR-018-封段护栏判据.md
docs/adr/ADR-019-离线升级包与Ed25519签名.md
docs/adr/ADR-020-离线包单文件传包与代理解包落位.md
docs/adr/ADR-021-L4边界PROXYprotocol接入与信任边界.md
docs/adr/README.md
docs/architecture.md
docs/audit-buffer.md
docs/data-classification.md
docs/data-scope.md
docs/env-number.md
docs/export-concurrency.md
docs/forensic-manifest-reconcile.md
docs/honeypot-watch.md
docs/internal-evidence-index.md
docs/ip-location-service.md
docs/ip-pool-ban.md
docs/mlps2-controls.md
docs/multi-instance-consistency.md
docs/security-dependency-watch.md
docs/threat-model.md
docs/user-permission-service.md
.github/CODEOWNERS
.github/ISSUE_TEMPLATE/bug_report.md
.github/ISSUE_TEMPLATE/config.yml
.github/ISSUE_TEMPLATE/feature_request.md
.github/ISSUE_TEMPLATE/security-report.md
.github/dependabot.yml
.github/semgrep/rules.yml
.github/workflows/deploy.yml
.github/workflows/sast.yml
.github/workflows/scorecard.yml

### 分区 infra（50 个文件）

**有发现（10 个）：**
- `deployment/observability/grafana/dashboards/xf-backend.json` — 1 条（P3）— fail-open 面板 type 正则只覆盖告警规则 9 类中的 4 类。
- `deployment/secret-rotation.md` — 1 条（P3）— 交叉引用「六重影响」实为「七重影响」。
- `migrations/20260831000000-reconcile-audit-index-options.js` — 1 条（P3）— background:true 为 mongod 8.0 no-op 死配置（7 个迁移文件共有发现）。
- `migrations/20260926000000-cursor-tiebreak-compound-indexes.js` — 1 条（P3）— 同上（background:true 死配置）。
- `migrations/20260928000000-audit-username-ci-index.js` — 1 条（P3）— 同上（background:true 死配置）。
- `migrations/20261021000000-query-performance-indexes.js` — 1 条（P3）— 同上（background:true 死配置）。
- `migrations/20261101000000-filter-tiebreak-compound-indexes.js` — 1 条（P3）— 同上（background:true 死配置）。
- `migrations/20261103000000-device-reminder-tiebreak-index.js` — 1 条（P3）— 同上（background:true 死配置）。
- `migrations/20261201000000-audit-list-tiebreak-indexes.js` — 1 条（P3）— 同上（background:true 死配置）。
- `docker/app-entrypoint.sh` — 1 条（P3）— UPGRADE_QUEUE_DIR 系统目录黑名单不完整（漏 /opt、/srv、/boot 等）。

> 注：原报告的「未见问题文件」名单同时列出了上述 7 个迁移文件，但发现详情中明确它们携带 background:true 死配置发现；本附录按发现详情把它们归入“有发现”侧，以保证 50 个文件不重不漏。

**无发现（40 个，含主审补读的 datasource.yml）：**
deployment/audit-allowlist.json
deployment/backup-encryption.md
deployment/clock-sync.md
deployment/config-drift-baseline.json
deployment/dependency-sla.json
deployment/deploy-workflow-rehearsal.md
deployment/edge-protection.md
deployment/gateway-pages/gateway-error.html
deployment/hot-upgrade.md
deployment/ip2region-checksum.json
deployment/lockfile-anchor.json
deployment/mongod-artifacts.json
deployment/nginx.conf.example
deployment/observability/alert-rules.yml
deployment/observability/alertmanager.yml
deployment/observability/grafana/dashboards/provider.yml
deployment/observability/grafana/datasources/datasource.yml（主审补读，未发现问题）
deployment/observability/prometheus.yml
deployment/rollback-drill-record.md
deployment/rollback-drill.md
deployment/systemd/chrony.conf.example
deployment/systemd/fsms-access-review.service
deployment/systemd/fsms-access-review.timer
deployment/systemd/fsms-hot-upgrade-agent.service
deployment/systemd/fsms-hot-upgrade-agent.timer
deployment/systemd/hot-upgrade.env.example
migrations/20260830000000-backfill-token-version.js
migrations/20260919000000-reconcile-audit-ttl-to-retention.js
migrations/20261030000000-backfill-password-set-at.js
migrations/README.md
migrations/_lib/indexSpec.js
e2e/README.md
e2e/helpers/auth.js
e2e/helpers/totp.js
e2e/journey-fault-injection.spec.js
e2e/journey-inspection-alarm.spec.js
e2e/journey-login.spec.js
e2e/journey-mfa.spec.js
e2e/journey-mobile.spec.js
e2e/journey-permission-audit.spec.js

### 分区 root-configs（29 个文件；2 个按纪律跳过）

**有发现（7 个）：**
- `docker-compose.yml` — 1 条（P2）— 管理员初始口令 base64 生成口径约 36% 概率不含特殊字符，过不了生产强度闸。
- `package.json` — 3 条（P3）— mongoose 范围与锁文件根块漂移；overrides 未随锁文件固化；未声明 private:true。
- `package-lock.json` — 1 条（P3）— 根块 mongoose ^8.0.3 与 package.json:70 ^8.24.9 漂移（同一问题的锁文件侧）。
- `README.md` — 2 条（P3）— 备份 crontab 残留 /opt/xf 旧路径；security:audit 描述滞后（实为 moderate）。
- `CONTRIBUTING.md` — 1 条（P3）— Node 版本矩阵描述滞后（CI 实测 22/24/26，镜像 26.12.0）。
- `start.bat` — 1 条（P3）— 前端缺 node_modules 时用 npm install 而非 npm ci，可能弄脏锁文件。
- `Dockerfile` — 1 条（P3）— apk add dumb-init/tzdata/su-exec 未钉版本/digest。

**按纪律跳过（2 个）：**
AUDIT-REPORT-2026-11-14.md
AUDIT-REPORT-2026-11-15.md

**无发现（20 个）：**
.dockerignore
.editorconfig
.env.example
.gitattributes
.gitignore
.gitleaks.toml
.gitleaksignore
.npmrc
.prettierignore
.prettierrc
CHANGELOG.md
dev-backend.cmd
dev-vite.cmd
eslint.config.js
eslint.ratchet.json
jest.config.js
LICENSE
migrate-mongo-config.js
playwright.config.js
SECURITY.md
