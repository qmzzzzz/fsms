# 等保 2.0 控制项对照表（MLPS 2.0 Control Mapping）

> 对应审计缺口：`deliverables/安全缺口核查-2026-09-30.md` P3-⑮。
> 口径：只列**可出示证据**的对照，证据是文件/测试/端点，不是口号。
> 代码注释里多处按等保 2.0 设计（`constants/retention.js:22`、`utils/superAdmin.js:12`、
> `services/behaviorBaseline.js:19`）——本表把这些散点收拢成测评可交的材料。
> 对照粒度为安全通用要求（GB/T 22239-2019）第三级的常见重点项，非逐条全集。

## 安全通信网络

| 控制项要求        | 本系统证据                                                                                                                                                                                |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 传输完整性/保密性 | 生产启动断言：非回环 Mongo 必须 `tls=true`、Redis 必须 `rediss:`（`config/transportSecurity.js` + 测试 `transportTlsAssertion.test.js`）；同宿主豁免显式声明（`docker-compose.yml` 注释） |
| 出站目标管控      | 日志转发仅 http/https 且拒绝私网/回环/链路本地目标（`utils/logShipper.js`，测试 `logShipperSchemeAllowlist`）                                                                             |

## 安全计算环境 — 身份鉴别

| 控制项要求         | 本系统证据                                                                                                                         |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| 口令复杂度与强度   | `validatePasswordStrength`（长度≥12、四类字符、弱口令**词干**比对 G8：`constants/breachedPasswords.js` 123 条词干 × 逐条可达用例） |
| 口令不得与近期重复 | `User.passwordHistory`（HMAC 摘要最近 N 条，A→B→A 拒绝；`utils/passwordHistory.js` + 20 例门禁）                                   |
| 登录失败处理       | 失败计数 + 临时锁定（`account_temp_locked`）+ MFA 锁定                                                                             |
| 双因素             | MFA 全链路（TOTP + 恢复码 + 管理员重置，`mfaController`/`mfaService`）                                                             |
| 远程管理防窃听     | 生产强制 HTTPS 或声明反代终结（M3 二选一校验，`validate.js`）                                                                      |

> **G8 的如实边界（不夸大，测评时按此口径答）**：该清单是**人工维护的高频弱口令词干表**，
> 不是撞库/泄露口令库。它覆盖「满足复杂度规则、却位于所有字典前列」的那一族
> （`Word@12345` 同源变异）；**长尾覆盖不了**——不在表内的已泄露口令（如 `MyDog2019!`）
> 需要 HIBP 那类真实泄露库才能查到。2026-10-09 实测：186 条「过策略且未被本表拦截」的
> 构造样本中，HIBP 仍能再命中 110 条（59.1%）。
> 匹配语义与不变量（含「为何仍是词干表而非在线泄露库」）见 `src/constants/breachedPasswords.js` 文件头；
> 逐条可达性与精度由 `src/tests/utils/breachedPasswordMatcher.test.js` 设防。

## 安全计算环境 — 访问控制

| 控制项要求         | 本系统证据                                                                     |
| ------------------ | ------------------------------------------------------------------------------ |
| 按角色授权         | RBAC 逐路由中间件；写接口权限契约门禁（`writePermissionContract`）             |
| 授权粒度           | 数据范围（本人/本部门/全部，`applyDataScopeToQuery`）+ 读接口鉴权契约（F-196） |
| 默认账号处置       | 超管唯一性强制（`utils/superAdmin.js`）；初始口令生产强校验                    |
| 敏感标记与访问留痕 | 敏感数据查看显式声明并写 `view_sensitive_data` 审计（P1-12）                   |

## 安全计算环境 — 数据完整性 / 保密性

| 控制项要求   | 本系统证据                                                                                                                                                     |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 鉴别信息保密 | bcrypt（12 rounds）+ `select:false`；口令历史摘要 HMAC+pepper                                                                                                  |
| 个人信息保密 | phone at-rest AES-256-GCM（`utils/piiCrypto.js`）+ 迁移/轮换脚本；realName 暂明文（姓名模糊检索依赖，2026-09-30 决策申报，见 `docs/threat-model.md` 残余风险） |
| 数据备份恢复 | 备份默认 gpg 加密 + sha256 + 异地副本钩子 + 失败即整体失败（`deployment/backup-encryption.md`）                                                                |

## 安全计算环境 — 剩余信息保护 / 入侵防范

| 控制项要求           | 本系统证据                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| 入侵防范（输入校验） | Mongo 操作符清洗、query 物化（Express 5）、body 字符串闸门、NoSQL 注入防护（`securitySanitizeAndBlacklistDegrade` 门禁）  |
| 恶意代码/攻击探测    | CC 分桶升级封禁 + 阶梯；早于审计层的拒绝全留痕（`ip_blacklist_blocked`/`csrf_origin_denied`/`malformed_request_blocked`） |
| 供应链               | lockfile 钉版 + audit 硬门禁 + SBOM + cosign 签名 + provenance + 生产树禁安装脚本（P2-⑩/⑫）                               |

## 安全审计（核心项）

| 控制项要求         | 本系统证据                                                                                                       |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| 覆盖每个用户与操作 | 全部写方法 + 全部未豁免 GET/HEAD（判据反转，2026-09-30）；预认证/纯自读显式豁免清单（`auditGetExcludePaths`）    |
| 审计不可篡改       | append-only 钩子 + 哈希链 + HMAC（compliance-check.js 常态校验挂载）                                             |
| 审计记录留存       | ≥90 天（`constants/retention.js`，区间 90..3650 由环境变量显式声明）                                             |
| 可查询/可导出      | 审计页按 action/category/riskLevel 过滤；CSV/Excel 导出（含流式截断的更正事件 `response_aborted_after_headers`） |
| 审计进程保护       | 审计写入失败不影响业务但必留痕（`auditWriteFailure`），WAL 兜底先落盘                                            |

## 安全运维管理

| 控制项要求 | 本系统证据                                                                      |
| ---------- | ------------------------------------------------------------------------------- |
| 应急预案   | `docs/incident-response.md`（角色/时限/命令级动作）                             |
| 变更/回滚  | `deployment/rollback-drill.md` + deploy.js 顺序门禁（备份先于切换）             |
| 密钥管理   | `deployment/secret-rotation.md` + `scripts/resign-audit-*.js` 族 + PII 轮换脚本 |
| 威胁建模   | `docs/threat-model.md`（STRIDE，残余风险如实申报）                              |
