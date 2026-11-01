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

| 控制项要求         | 本系统证据                                                                                                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 口令复杂度与强度   | `validatePasswordStrength`（长度≥12、四类字符、弱口令**词干**比对 G8：`constants/breachedPasswords.js` 123 条词干 × 逐条可达用例）                                                                                                                                |
| 口令不得与近期重复 | `User.passwordHistory`（HMAC 摘要最近 N 条，A→B→A 拒绝；`utils/passwordHistory.js` + 20 例门禁）；**管理员重置过的口令另留一条 bcrypt 退役摘要**（`User.passwordRetiredHash`，改密时比对即拒：重置路径拿不到旧口令明文、算不出 HMAC 摘要，见 `docs/adr/ADR-016`） |
| 登录失败处理       | 失败计数 + 临时锁定（`account_temp_locked`）+ MFA 锁定；连续失败 3 次即由 `services/loginChallenge` 要求人机验证（与验证码静态开关无关，闸门先于口令比对，故无验证码的尝试推不到锁定阈值）；被该闸门拦下的尝试落 `login_captcha_rejected`（留痕、不计入失败计数） |
| 双因素             | MFA 全链路能力具备（TOTP + 恢复码 + 管理员重置，`mfaController`/`mfaService`）；**管理员强制未启用**（产品决策，见 P1-1 说明），账号可自愿开启                                                                                                                    |
| 远程管理防窃听     | 生产强制 HTTPS 或声明反代终结（M3 二选一校验，`validate.js`）                                                                                                                                                                                                     |

> **G8 的如实边界（不夸大，测评时按此口径答）**：该清单是**人工维护的高频弱口令词干表**，
> 不是撞库/泄露口令库。它覆盖「满足复杂度规则、却位于所有字典前列」的那一族
> （`Word@12345` 同源变异）；**长尾覆盖不了**——不在表内的已泄露口令（如 `MyDog2019!`）
> 需要 HIBP 那类真实泄露库才能查到。2026-10-09 实测：186 条「过策略且未被本表拦截」的
> 构造样本中，HIBP 仍能再命中 110 条（59.1%）。
> 匹配语义与不变量（含「为何仍是词干表而非在线泄露库」）见 `src/constants/breachedPasswords.js` 文件头；
> 逐条可达性与精度由 `src/tests/utils/breachedPasswordMatcher.test.js` 设防。

## 安全计算环境 — 访问控制

| 控制项要求           | 本系统证据                                                                                                                                                                                                                                                                                                                                               |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 按角色授权           | RBAC 逐路由中间件；写接口权限契约门禁（`writePermissionContract`）                                                                                                                                                                                                                                                                                       |
| 授权粒度             | 数据范围（本人/本部门/全部，`applyDataScopeToQuery`）+ 读接口鉴权契约（F-196）                                                                                                                                                                                                                                                                           |
| 默认账号处置         | 超管唯一性强制（`utils/superAdmin.js`）；初始口令生产环境强制强度校验，且首次登录 `mustChangePassword` 强制改密后方可访问业务接口                                                                                                                                                                                                                        |
| 数据分类分级         | `src/constants/dataClassification.js` 是唯一台账（L1–L4 + 静态存储形态 + 个人信息标记 + 同意范围），由 `tests/ci/dataClassificationInventory.test.js` 与真实 schema 双向对拍（模型闭合 / 声明路径真实 / 个人信息不得降级 / `select:false` 全登记 / 加密声明与 getter 互证）；使用说明见 `docs/data-classification.md`                                    |
| 个人信息处理告知同意 | 自助注册必须明示同意：路由校验 `privacyConsent === true`（非布尔真值一律 400）+ 服务层 fail-closed 复判 + **签发令牌前**落 `ConsentRecord`（落库失败回滚账号）；记录 append-only、`{userId,policy,version}` 唯一、改版不继承旧同意。告知全文在注册页可点开（版本与范围与后端逐字对拍），**不写"注册即表示同意"**；管理员建号属组织法定基础，不写同意记录 |
| 敏感标记与访问留痕   | 敏感数据查看显式声明并写 `view_sensitive_data` 审计（P1-12）                                                                                                                                                                                                                                                                                             |
| 特权/临时权限最小化  | 临时提权走「申请 → 审批 → 到期失效」闭环（`services/privilegeGrantService.js`，端点 `/api/permissions/grants`）：申请人不得自审（`PRIVILEGE_SELF_APPROVAL_FORBIDDEN`）、高敏码需 2 名不同审批人、审批人须自持该码、有效期 1–168 小时；**到期在读取路径强制**（`status==='active' && expiresAt>now`），不依赖后台任务（ADR-012）                          |
| 权限定期复核         | `services/accessReviewService.js` + `scripts/access-review.js`（`--expire` 状态收敛、`--fail-on-overdue` 可挂 CI）；超期阈值 90 天（`constants/privilegeGrant.js`）；`deployment/systemd/fsms-access-review.timer` 每小时巡检并留 journal 证据                                                                                                           |
| 权限变更双人复核留痕 | 审批链以快照落库（`PrivilegeGrant.approvals[{by,name,at}]`，审批人改名/删号后仍可追溯到当时的人）；审计 action 为 `permission_grants{,_approve,_reject,_revoke}`，与权限目录同 category                                                                                                                                                                  |

> **G9 的如实边界（特权账号管理，C-09 只落地一半）**：本系统实现的是「谁能拿到高敏权限、谁批的、什么时候到期」的闭环，
> **不含**堡垒机/跳板机会话代理与 JIT 提权会话录屏——「拿到权限之后在哪个通道上操作」仍由操作系统与运维流程保证。
> 测评时按此口径答，不要把它说成完整的特权账号管理（见 `docs/adr/ADR-012-临时权限授予与定期复核.md` 的「后果与局限」）。

## 安全计算环境 — 数据完整性 / 保密性

| 控制项要求   | 本系统证据                                                                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 鉴别信息保密 | bcrypt（12 rounds）+ `select:false`；口令历史摘要 HMAC+pepper；退役口令摘要 bcrypt（同样 `select:false` + 响应投影排除，常态 1 条）                                 |
| 个人信息保密 | phone at-rest AES-256-GCM（`utils/piiCrypto.js`）+ 迁移/轮换脚本；realName 暂明文（姓名模糊检索依赖，2026-09-30 决策申报，见 `docs/threat-model.md` 残余风险）      |
| 数据备份恢复 | 备份默认 gpg 加密 + sha256；生产发布强制要求异地副本（`BACKUP_OFFSITE_CMD`/`BACKUP_OFFSITE_DIR`），缺失即拒绝发布；逻辑恢复演练见 `deployment/backup-encryption.md` |

## 安全计算环境 — 剩余信息保护 / 入侵防范

| 控制项要求           | 本系统证据                                                                                                                                                                                                                                                        |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 入侵防范（输入校验） | Mongo 操作符清洗、query 物化（Express 5）、body 字符串闸门、NoSQL 注入防护（`securitySanitizeAndBlacklistDegrade` 门禁）                                                                                                                                          |
| 恶意代码/攻击探测    | CC 分桶升级封禁 + 阶梯；早于审计层的拒绝全留痕（`ip_blacklist_blocked`/`csrf_origin_denied`/`malformed_request_blocked`）                                                                                                                                         |
| 供应链               | lockfile 钉版 + audit 硬门禁 + SBOM + cosign 签名 + provenance + 生产树禁安装脚本（P2-⑩/⑫）                                                                                                                                                                       |
| 攻击溯源与取证       | 边缘取证日志格式 `fsms_forensic` 与 TLS 取证头（`deployment/nginx.conf.example`，启用与观察见 `deployment/edge-protection.md`）；应用侧取证触发标记表 `services/forensicTrigger.js`（滑动续期 30 分钟、容量 LRU、fail-open 但计数可见）决定「是否升级为全量捕获」 |

## 安全审计（核心项）

| 控制项要求         | 本系统证据                                                                                                                                                                                                 |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 覆盖每个用户与操作 | 全部写方法 + 全部未豁免 GET/HEAD（判据反转，2026-09-30）；预认证/纯自读显式豁免清单（`auditGetExcludePaths`）                                                                                              |
| 审计不可篡改       | append-only 钩子 + 哈希链 + HMAC（compliance-check.js 常态校验挂载）                                                                                                                                       |
| 审计记录留存       | ≥90 天（`constants/retention.js`，区间 90..3650 由环境变量显式声明）                                                                                                                                       |
| 可查询/可导出      | 审计页按 action/category/riskLevel 过滤；CSV/Excel 导出（含流式截断的更正事件 `response_aborted_after_headers`）                                                                                           |
| 审计进程保护       | 审计写入失败不影响业务但必留痕（`auditWriteFailure`），WAL 兜底先落盘                                                                                                                                      |
| 取证留痕可复现     | 取证窗口开启/关闭与按 IP 统计速查见 `deployment/edge-protection.md`；XFF 原链只作留证，封禁与限流一律取 `utils/ipUtils.js` 的 `clientIpForSecurityDecision`（可信边界内 `req.ip`，边界外退回 socket 对端） |

> **取证的如实边界（测评时按此口径答）**：应用侧日志在压力下**会先降级**——连接层被打满时请求进不到应用，
> 应用既看不到也记不下（机理与观察方法见 `deployment/edge-protection.md`）。边缘取证日志是同一窗口的补充证据源，
> 但它同样会在队列/磁盘打满时丢条目。所以「日志条数」只能作为攻击规模的**下界**汇报，不能当作完整证据；
> 边缘 `deny` 快通道**不产生审计事件**，不能作为「已处置」的证据。

## 安全运维管理

| 控制项要求   | 本系统证据                                                                                                                                                                                                                                                     |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 应急预案     | `docs/incident-response.md`（角色/时限/命令级动作）                                                                                                                                                                                                            |
| 变更/回滚    | `deployment/rollback-drill.md` + deploy.js 顺序门禁（备份先于切换）                                                                                                                                                                                            |
| 密钥管理     | `deployment/secret-rotation.md` + `scripts/resign-audit-*.js` 族 + PII 轮换脚本                                                                                                                                                                                |
| 威胁建模     | `docs/threat-model.md`（STRIDE，残余风险如实申报）                                                                                                                                                                                                             |
| 时钟同步     | 生产发布前 `scripts/check-clock-sync.js` 核验宿主 NTP（timedatectl/chrony），判不了即拒绝；见 `deployment/clock-sync.md`                                                                                                                                       |
| 配置漂移检测 | `scripts/config-drift-check.js` 把容器安全标志、Dockerfile `USER`/`HEALTHCHECK`、nginx TLS 指令与 `.env.example` 的安全键逐项摘要，与 `deployment/config-drift-baseline.json` 对账（只报条目名、不报取值）；用例 `configDriftCheck.test.js` 钉住「基线不撒谎」 |
