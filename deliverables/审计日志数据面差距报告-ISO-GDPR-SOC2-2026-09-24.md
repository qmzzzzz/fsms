# 审计日志数据面差距报告（ISO 级 · GDPR/SOC2 数据面视角 · 目标量级千万级/天）

日期：2026-09-24　测量者：实现线会话　方式：本轮全部结论逐条 `Read`/`grep`/`node -e` 实测，命令见文末附录。

本报告的性质：**差距清单**，不是方案。按你选的口径（GDPR/SOC2 那类数据面视角 + 「每天千万级以上」写入量 + 需要离线长期保存），并遵守你「先给差距报告，再决定基础设施」的前置条件——全文不含任何基建选型，涉及外部系统的条目只写"这一格现在是空的"。

三条阅读约定：

1. 每条差距的"现状"必须能被 `file:line` 复核；我写不出处的就是没读过的，没读过的不写。
2. 数字分两种：**实测**（代码里的常量 / `schema.indexes()` 的真实返回）与**推导**（由你给的日量做的算术）。推导值一律标注，因为它是"量级判断"而不是"能力上限"。
3. 本轮实测**推翻了我自己上一轮报给你的两条结论**，原文与更正放在 §5，不悄悄改写。

---

## 1. 一页结论

差距分三类，性质完全不同，闭合代价也完全不同：

| 类别                           | 一句话                                                                   | 闭合是否需要新依赖/基建          |
| ------------------------------ | ------------------------------------------------------------------------ | -------------------------------- |
| **A 能力已在后端、界面不可达** | 合规读数、链核验、取证级导出三套东西服务端全在跑，前端一次都没接上       | **不需要**，纯前端接线           |
| **B 规模不匹配**               | 现有结构按"低频、热查询"设计，按千万级/天看有多个秒级/分钟级硬窗口       | 部分需要（存储分层），部分不需要 |
| **C 数据面控制缺失**           | 时间可信、数据最小化、主体权利、可验证归档、插入伪造不可检——这五格是空的 | 前两格纯代码，后三格要先定口径   |

A 类里最刺眼的一条，具体到行：`web-admin/src/views/AuditLogView.vue:497` 已经在向 `/security/overview` 发请求，`securityController.js:682-715` 已经把 8 个合规键 + 4 个审计丢失计数器放进同一个响应体，而前端 `:499-505` 只挑走 `criticalAlerts / highAlerts / failedLogins` 三个统计卡字段。**数据已经到了浏览器，然后被丢掉。**

---

## 2. 本报告引用的实测常数

后面所有推导都只用这张表里的数，不再引入新数字。

| 常数                         | 值                  | 出处（实测）                                                                                    |
| ---------------------------- | ------------------- | ----------------------------------------------------------------------------------------------- |
| 批量落库触发条数             | 100                 | `src/services/auditBuffer.js:24`                                                                |
| 定时落库间隔                 | 2000 ms             | `src/services/auditBuffer.js:26`                                                                |
| 缓冲硬上限（超过丢**最旧**） | 10000 条            | `src/services/auditBuffer.js:36`、`:109-119`                                                    |
| 批次最大重试次数             | 5                   | `src/services/auditBuffer.js:50`                                                                |
| 关停排空预算                 | 2000 ms             | `src/services/auditBuffer.js:54`                                                                |
| 审计链锁持有超时             | 15000 ms            | `src/utils/auditChain.js:124`                                                                   |
| AuditLog 非 `_id` 索引条数   | **13**              | `node -e "require('./src/models/AuditLog').schema.indexes().length"`                            |
| TTL（默认留存）              | 15552000 s = 180 天 | 同上（`expireAfterSeconds`），声明处 `src/models/AuditLog.js:227`                               |
| 在线链核验窗口               | 20000 条            | `src/services/auditChainVerify.js:66`，HTTP 侧收口 `src/controllers/auditController.js:102-108` |
| 核验脚本硬上限               | 200000 条           | `src/services/auditChainVerify.js:67`                                                           |
| 导出行硬上限                 | 50000 条            | `src/services/auditExportService.js:5`                                                          |
| SIEM 转发缓冲上限            | 5000 条             | `src/utils/logShipper.js:35`                                                                    |

你给的量级换算成同单位（**以下全是推导，不是实测**）：1000 万条/天 ≈ **116 条/秒**均值；180 天留存 ⇒ 集合内约 **1.8×10⁹** 条文档。

---

## 3. A 类：后端已有 / 前端缺失（逐项带证据）

判据来源：GDPR Art.5(2)/Art.24（可证明的合规性）、SOC2 CC7.2（监控与异常识别）、CC4.1（证据留存）。这三条的共同要求都不是"有功能"，而是"**能在审计时拿出证据**"——界面不可达在合规语境下等同于不具备。

| #   | 后端能力                                                                                      | 后端证据                                                                        | 前端实测（`grep`，含测试目录）                                                                                                                                                                                                            |
| --- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1  | 哈希链完整性核验（hash 重算 + hmac + 链接性）                                                 | `src/routes/securityRoutes.js:286-292` → `verifyAuditChainIntegrity`            | `audit-logs/verify` **0 命中**                                                                                                                                                                                                            |
| A2  | 取证级导出：CSV + 签名 manifest + `csvSha256` 交付字节摘要                                    | `src/services/auditExportService.js:43,60,170,184-192`、`auditController.js:56` | `audit-logs/export` **0 命中**；`AuditLogView.vue:554-562` 的"导出"按钮走 `/reports/export?type=audit`（`reportController.js:219-230`，权限闸门是对的且已实测），但**那条链路不产出 `csvSha256`**——用户在界面上拿得到导出、拿不到保真摘要 |
| A3  | 合规就绪度读数（实际生效留存、钳制标记、护栏生效值、监控运行、WAL、转发、链尾、四类丢失计数） | `src/controllers/securityController.js:682-715`                                 | 8 个键名 + `auditLoss` 在前端非测试代码 **0 命中**；响应被 `AuditLogView.vue:497` 取回后丢弃                                                                                                                                              |
| A4  | 数据主体自助出口 `/security/my-info`、`/my-logs`、`/bindings`、`/view-sensitive`              | 四条路由在 `securityRoutes.js` 的 `@route` 清单内                               | 无调用点；但权限名的 i18n **已经翻好了**（`zh-CN.js:671-673`、`en-US.js:675-677`）——半成品状态，不是遗漏                                                                                                                                  |
| A5  | `GET /security/stats`                                                                         | 同上                                                                            | **0 命中**                                                                                                                                                                                                                                |
| A6  | 证据字段 `hash` / `hmac` / `prevHash` 的展示                                                  | 字段在（`AuditLog.js:169-190`）                                                 | 前端 0 命中，且查询侧本就不返回（`AuditLog.js:229` `RESPONSE_EXCLUDE`）——列表接口设计上给不了，需要 A1 那条核验/明细口                                                                                                                    |

**A 类里唯一"已经通了"的一条，要说清楚免得被误当成缺口**：指标面 `/api/metrics`（`src/app.js:322`，`security:audit` 门控）→ `getSnapshot()` 含 `alerts`（`src/utils/metrics.js:304,324`）→ `AboutView.vue:109-115,191` 渲染。所以 `audit_write_failed`、`audit_anomaly_detected` 这类告警计数在"关于"页是**看得见**的。看得见 ≠ 看得懂：它落在一个通用告警标签列表里，不在审计页，也不带"这条意味着审计链出现了缺口"的解释。

A 类的共同特征：**零新依赖、零后端改动、零基建**。差的就是 `api.js` 里三个绑定 + `AuditLogView` 一个卡片区 + 两个按钮。

---

## 4. B 类：按千万级/天重看现有结构

这一节的每一条都不指控"写错了"——它们在低频前提下是合理的，甚至是明显深思过的（幂等重放、按 `__walSeq` 精确裁剪、僵尸批次撤回这些我在 `auditBuffer.js:240-338` 逐行读过）。问题是**把它们放到 116 条/秒均值下，窗口从"永远不会碰到"变成"日常会碰到"**。

### B1 全局单链 = 所有审计追加串行走一把锁（吞吐 + 完整性耦合）

`src/services/auditBuffer.js:264-279`：整批 `chainBatch` → `insertMany` → `advanceChainTail` 全部在 `withChainLock` 内完成；Redis 就绪时还要在进程内锁之上再拿一把跨实例锁（`src/utils/auditChain.js:173-191`）。锁持有超时 15 s（`:124`），**超时的处置是把这一批降级成无 hash 落库**（`:139-146`）。

于是吞吐与完整性被绑成同一个量：盘慢/锁排队 → 超时 → 无 hash 记录批量增加 → "防篡改"承诺的覆盖面缩水。

**这一句我第一版写重了，按实测更正**：降级**不是无痕的**，但要换个面才知道。写入侧确实只有一行 warn、没有计数汇总（`auditBuffer.js:272`）；核验侧会检出——`src/services/auditChainVerify.js:25-32`（P2 级修正）把"出现在带 hash 记录**之后**"的无 hash 记录计为 `breaks` 里的 `type=hash_stripped`，而不是笼统算 legacy。所以准确说法是**"可检出、但无即时告警"**：要等到有人跑一次核验（而核验是窗口制的，见 C4/C5）。推导：均值 116 条/秒 ÷ 每批 100 条 ≈ 每秒 1.2 次批落库，每次都要过同一把锁 + 一次 13 索引维护。

这一条是本轮**修正**过的结论：链尾"读→算→写"竞争本身已被 M-3/A-1 关掉（见 §5-②），剩下的不是正确性缺陷，是**单序列化点**的规模问题，以及"降级无汇总指标"这一格空白。

### B2 缓冲硬上限把"可容忍停顿"压到秒级

`BUFFER_HARD_LIMIT = 10000`，超出即 `buffer.splice(0, overflow)` **丢最旧**并计 `droppedCount`（`auditBuffer.js:36,109-119`）。推导：116 条/秒下 10000 条 ≈ **86 秒**积压；峰值按 10× 估则 ≈ **8.6 秒**。也就是说，落库侧卡顿几十秒量级就会开始丢审计——好消息是丢得**可观测**（`droppedCount` 在 `:547-553` 暴露、并出现在 A3 的合规块里），且 WAL 行留在磁盘（`:117-118` 日志原文）。需要拍板的是这够不够：86 秒的容忍窗口对"每日千万级"是偏紧还是合适，取决于你们生产盘的实际 p99，而这个数**本仓没有实测**（见 B4）。

### B3 索引数与留存量的乘积没人算过

`schema.indexes()` 实测 **13 条**非 `_id` 索引（5 条单字段/sparse + 7 条复合 + 1 条 TTL）。文件里 `AuditLog.js:203-219` 的注释说明这是刻意的写放大取舍——低频下这个取舍是对的。1.8×10⁹ 文档下它变成：索引总体积与写放大是**未测过的量**，而它正好落在 B1 的锁窗口里（索引维护在 `insertMany` 内）。

### B4 现有可压测入口（不需要新依赖）

`scripts/load-test.js`、`scripts/perf/k6-core-journeys.js`、`scripts/production-drill.js`、`scripts/perf/explain-spotcheck.js` 都在仓里。**B 类全部四条的判据都应该是压测出来的曲线，不是本报告算出来的算术**；上面的推导值只用来定"该测哪一段"：审计写入 p99 vs 116/1157 条每秒两档、锁超时降级计数、13 索引的插入放大、86 秒容忍窗口的真实性。

---

## 5. 撤回与更正（本线上一轮报给你的两条；① 本轮又被自己更正一次，原文保留）

这两条是我在回答"安全方面还差什么"时给的，**都不成立**。留原文，别改历史。（① 的"不成立"本身在 22:5x 被推翻，见 ①-补。）

**① 撤回：「F-124b 会造成整条审计静默丢失，且没有 `audit_write_failed` 指标」——错。**

实测：`AuditLog.record` 的 catch 就是在打这个指标（`src/models/auditLogWriteStatics.js:63-76`，`incSecurityAlert('audit_write_failed','medium')`，注释写明出处是评价报告 #8）；而带 `\0` 键的**请求型**审计根本不走 `record`，走缓冲批量（`src/middleware/security.js:770` → `auditBuffer.push`），在那里被判为"内容可归因失败"：计次后**只丢毒文档、同批其余留在缓冲继续重试**，并把其 WAL 行归档移走，`droppedCount` 计入（`src/services/auditBuffer.js:349-366`），且 `droppedCount` 已透出到合规读数（`:547-553` → `securityController.js:706-714`）。
更正后的严重度：**能让特定请求的审计不落库，但有计数、有 error 级日志、有合规面板出口**（只是那个出口前端不显示 ⇒ 回到 A3）。它不是"静默灭迹"。台账 §44.3 里那条"只报不修"的判断仍然成立，但**理由要按这条换掉**。

**①-补（同日 22:5x，本条**覆盖上面 ① 的结论**，①原文按「别改历史」保留）**：上面那次撤回**撤过头了**——F-124b 逐路径实测后是**部分成立**，而且我据以撤回的那两条证据只覆盖了它没在说的那两支。

- 我复现了它（跑对方探针 `D:/tmp/probe_bson_nul_key.js`，直调仓内 `bson`，exit 0）：键含 `\0` ⇒ `BSONError: key ... must not contain null bytes`；`\t` 与空格**放行**。
- ① 举的 `record()`（有 medium 指标）与缓冲批量（有 `droppedCount`）**都成立**，但 F-124b 说的是**直连**那一支：`AuditLog.recordSensitiveAction`（`auditLogWriteStatics.js:100-124`）static **自身无 catch**，载荷含 `body: sanitizeAuditBody(req.body)`（`:113`）正是 `\0` 键的载体，而它的 4 个调用点（`authController.js:362/379/594/620`）一律只 `.catch(e => logger.warn(...))` ⇒ **确实无 `audit_write_failed` 指标**。原判逐字为真。
- 同族对照：`recordLogin` 的 **6 个**调用点（`authService.js:234/305/335/358/416/823`）**全部**接了 `utils/auditWriteFailure.onAuditWriteFailure`（high）⇒ 这是本台账反复出现的**「已修的同类漏了一处」**族，不是新设计缺陷。
- 咽喉定位（比原判更宽）：`\0` 键能穿过清洗层的唯一原因是 `models/auditLogSanitizer.js:52-64` 的 `walk` **原样保留键名**（`defineProperty(cleaned, key, ...)`），而 `body` 与 `params`/`query` **共用**它（`:69`/`:72`）⇒ `%00` 编码的查询键同病。修法与本仓已有口径同源：`utils/helpers.js:370` 的 `stripControlCharsDeep` 已对**键**做 `stripControlChars(k, 128)`，`walk` 里照做即可（实测 `pass\0word` → `pass word`，BSON 放行，**值一行不动** ⇒ 化解"会截值到 1024"的两难）。两条副作用须同写：撞键（`a\0b` 与 `a\tb` 同为 `a b`，后写覆盖，属保真问题）；**不构成脱敏绕过**（F-124 后 `matchesSensitiveBodyKey` 把键压平，`to\0ken` 前后都命中）。
- 结论改判：**F-124b 成立（指标面缺、载体在 `walk`），落地仍归对方车道**；本线已把上述结论回在 `D:/tmp/qoder-handoff-f124-and-flake.md` 末尾。

**② 撤回：「审计链链尾是读-改-写两步可交错的竞争」——那是已修问题的记载文本，不是现存缺陷。**

`src/utils/auditChain.js:88-98` 那段注释描述的是 M-3 修复**之前**的行为；现状是进程内互斥 + 内存链尾指针（`:99-105`、`:148-238`），Redis 就绪时叠加跨实例锁与共享链尾（`:173-191`、`:247-262`），拿不到锁时"绝不无锁推进链尾"而是标失效+抛错走降级（`:181-191`）。`:335-336` 还留着一句关键实测：当初断链主因是**默认值补齐**（AUX-02），`chain_break` 实测仅 12 条且无一发生在同毫秒——即"互斥锁本身是有效的"。我在 B1 保留的只有规模与降级可见性两件事。

---

## 6. C 类：数据面控制缺失（GDPR/SOC2 视角的五格空白）

| #   | 要求（数据面）                                 | 现状（实测）                                                                                                                                                                                                                                                                                                 | 差距                                                                                                                                                                                                                                                                                                                         |
| --- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1  | **时间可信**：留存记录的时间可作为证据         | 全仓 `grep -niE "ntp\|chrony\|timesync\|clock.?(skew\|drift)"` 在 js/md/yml/sh/Dockerfile **0 命中**；`serverTime/receiptTime/clientTimestamp/eventTime` **0 命中**；`timestamp` 由应用进程 `Date.now` 生成（`AuditLog.js:193-196`）                                                                         | 没有任何时间同步控制、没有"事件时间 vs 接收时间"双戳、没有漂移/回拨检测。哈希链把时间钉进了 payload，因此主机回拨会造出**时间上倒退但链上合法**的记录，而现有核验判据不看单调性                                                                                                                                              |
| C2  | **数据最小化**：只留该留的字段                 | `params/query/body` 整包入库（`AuditLog.js:91-102`），`reason`/`path`/`errorMessage` 无 `maxlength`（UA 在写入侧截 512）；脱敏是**两份启发式名单的并集**（`src/utils/helpers.js` `SENSITIVE_KEY_SUBSTRINGS` 8 项 + 下划线边界名单），F-124 只是把键名噪声压平                                                | 名单式脱敏的天花板就是"改名即绕过"（我上一轮已认这个天花板）。数据面正解是**控制器侧字段白名单**：不写进审计的字段才是安全的字段。这一格是设计选择，不是 bug                                                                                                                                                                 |
| C3  | **数据主体权利**：访问/删除某人的个人数据      | append-only 护栏 9 个钩子全在（`compliance-check.js:111-117` 的低限清单含 `deleteMany`/`updateMany`/`bulkWrite`）；`grep -niE "erasure\|anonymi[sz]\|pseudonymi[sz]"` 在 src/scripts/docs **0 命中**                                                                                                         | 没有任何"按主体匿名化/删除"的合规出口，也没有记录"为什么留存属于 Art.17(3)(e) 例外"的声明。这与 append-only 是**真冲突**，需要法务口径而不是代码                                                                                                                                                                             |
| C4  | **可验证归档**：离线长期保存且日后能自证完整   | 留存只有一层热 TTL（180 天，`AuditLog.js:227`）；交付只有 CSV/xlsx，`EXPORT_HARD_LIMIT = 50000` 行硬截断并写 `manifest.notice`（`auditExportService.js:5,192`）；`csvSha256` 只覆盖**单次交付字节**（`:170`）                                                                                                | 千万级/天下 50000 行上限 ≈ **7 分钟**的流（推导），单个导出窗口永远覆盖不了一天，更没有"按天/按段的签名锚点"可留档。核验窗口同样封顶：在线 20000 条 ≈ **172 秒**的流（推导）对 1.8×10⁹ 的留存集合 ⇒ **完整性结论的覆盖面约为留存面的百万分之一**。这一格是 B1 分段锚点设计与 C4 归档的共同缺口，也是本报告里最"结构性"的一条 |
| C5  | **插入伪造记录也要能检出**（不可抵赖的另一半） | `src/services/auditChainVerify.js:23` 写着「窗口足够小（`LINK_WINDOW_SIZE`，实测 = 256，`:62`），删除或插入记录仍会立即暴露」，而同一段 `:34-38` 又自陈「**已知检出上限（不得当作已修好）**：插入一条 prevHash 指向链中已有 hash 的伪造记录，在本设计下不可检出——滑动窗口只要求 prevHash 命中近期任一 hash」 | 删除/改写可检出（`hash_stripped`、断链），**插入不可检出**；而且 `:23` 与 `:34-38` **互相矛盾**——按前者读会得出"插入已覆盖"的反向结论。修法：给每条记录一个参与哈希的 `chainIndex`，使父子关系严格线性 ⇒ 需全量重签的格式升级（与 §8-5 的分段锚点是同一次改动）                                                              |

（C4 里"核验窗口 ÷ 留存总量"的比例要说清口径：这不是缺陷，`auditController.js:117-128` 的 `computeChainVerdict` 明确拒绝把窗口结论说成"链完整"，还要 `estimatedDocumentCount` 交叉判①②两件事——**代码是诚实的**，缺的是能把 1.8×10⁹ 全量证一遍的机制。）

---

## 7. 现有合规门禁实际覆盖到哪

`scripts/compliance-check.js`（295 行，7 项，已接进 CI）——**逐条读完的结论：7 项全是"接线检查"，没有一项是行为验证**，而且脚本自己在两处注释里承认了这点：

| 项  | 检查内容             | 性质（实测判据）                                                                              |
| --- | -------------------- | --------------------------------------------------------------------------------------------- |
| 1   | 留存天数             | 断言**原始配置值**且拒绝静默钳制（`:42-68`，P3-46 修掉了原来的恒真判据）——这条是真判据        |
| 2   | append-only 钩子注册 | 读 `schema.s.hooks._pres` 比对清单 + 独立低限（`:111-118`），防"清单与注册同步缩水"的自我认证 |
| 3   | 导出接口存在         | 函数存在 + 路由文件正则（`:146-160`）                                                         |
| 4   | auditMonitor 挂载    | 对 `index.js` **源码做正则**（`:181-183`）                                                    |
| 5   | 哈希链字段存在       | `paths.prevHash/hash` 存在即绿（`:202-218`）——**不验链**                                      |
| 6   | WAL 兜底             | 只验 `push`/`isWalEnabled` 两个符号是函数；`:226-228` 原话："这条是接线检查，不是能力已生效"  |
| 7   | SIEM 转发            | 三态；`:247-249` 原话：原判据 `passed = transportAvailable` 在 require 成功时恒真             |

差距的准确说法：**"字段存在"不等于"护栏生效"，"符号是函数"不等于"兜底可用"**。真正做过行为验证的是测试（如 F-106 端到端钉 `csvSha256`、F-109 钉 footer 伪造免疫、F-97 钉 WAL 按序号裁剪），但那些在 jest 里，不在合规出口里——所以对外出具"合规就绪度"时，这张 7 项清单证明的是"代码接好了线"，不是"这套东西在千万级/天还成立"。

---

## 8. 需要你拍板的（我不替你定）

1. **A 类要不要现在闭合**：三项（合规卡 / 核验入口 / 取证导出入口）纯前端接线，零新依赖。工作量集中在 `AuditLogView.vue` 与 `api.js` 绑定，另需配可证伪用例。
2. **C1 时间可信做到什么程度**：只加"接收时间双戳 + 偏移超阈值告警"（纯代码），还是一路做到与外部时间源对齐（基建，你已说后议）。
3. **C2 是否接受把脱敏从"名单"改成"白名单"**：这会改变审计里能看到什么，属于业务可见性收缩，我不擅自改。
4. **C3 主体权利与 append-only 的冲突**：需要法务给口径（保留例外援引哪一条），代码才有正确的默认值。
5. **C4 是否把"分段链 + 每日锚点"列为下一版结构目标**：这是 B1 与 C4 的共同解，但会动哈希链口径（v5）与存量重签流程，属于结构性改动，必须你点头。
6. **B 类要不要先压测再谈结构**：我的建议是先压（仓里已有工具，零新依赖），因为 B1-B4 的严重度排序**只有实测曲线能定**。

---

## 附：本报告全部结论的复现命令

```bash
# 索引与 TTL（13 条 / 15552000s）
node -e "console.log(require('./src/models/AuditLog').schema.indexes())"
# 缓冲与链路常量
grep -nE "^(const|let) (BUFFER|FLUSH|MAX_BATCH)[A-Z_]*" src/services/auditBuffer.js
grep -n "CHAIN_LOCK_TIMEOUT_MS = " src/utils/auditChain.js
# 导出/核验上限
grep -nE "EXPORT_HARD_LIMIT = |DEFAULT_MAX_RECORDS = |HARD_MAX_RECORDS = " src/services/auditExportService.js src/services/auditChainVerify.js
# A 类前端 0 引用（逐条）
for p in audit-logs/verify audit-logs/export compliance auditLoss chainTailHash appendOnlyEnforced walEnabled monitorRunning retentionDays shippingEnabled security/stats hmac prevHash; do
  printf "%-22s %s\n" "$p" "$(grep -rl "$p" web-admin/src --include='*.vue' --include='*.js' | grep -v '/tests/' | wc -l)"
done
# C1/C3 空白项
grep -rniE "ntp|chrony|timesync|clock.?(skew|drift)" src scripts docs deployment Dockerfile* .github 2>/dev/null
grep -rniE "erasure|anonymi[sz]|pseudonymi[sz]" src scripts docs --include="*.js" --include="*.md"
```
