# 威胁模型（Threat Model）

> 对应审计缺口：`deliverables/安全缺口核查-2026-09-30.md` P3-⑬。
> 口径：STRIDE 按面分解，每一项都绑定**本仓已落地**的缓解（含文件位置）与已知残余风险。
> 本文档是活的：新增防线/新增面都要同步，测评时可据此逐条出示证据。

## 1. 资产与信任边界

| 资产     | 说明                                                    | 泄露后果                    |
| -------- | ------------------------------------------------------- | --------------------------- |
| 业务库   | mongo（人员 PII + 设备/报警/巡检记录）                  | 人员名录与运营史外泄        |
| 审计集合 | append-only 哈希链 + HMAC（`models/auditLogHooks.js`）  | 被改写 = 追责依据失效       |
| 密钥     | JWT×2 / AES / HMAC / gpg 私钥                           | 冒充任意身份 / 解密全量数据 |
| 备份     | `.gz.gpg` + 校验和（`deployment/backup-encryption.md`） | 同业务库                    |
| 凭据     | 用户口令（bcryptjs 12 rounds + 复用历史）               | 账号接管                    |

边界：浏览器 ↔（HTTPS/反代）↔ Express app ↔（同宿主 compose 网络，TLS 豁免显式
声明 `MONGODB_TLS_EXEMPT`，见 `config/transportSecurity.js`）↔ mongo/redis；
出站仅限 SIEM 转发（目标门禁 `utils/logShipper.js`）与告警 webhook。

## 2. 威胁 → 缓解对照

### S 冒充（Spoofing）

- 口令登录：bcrypt + 登录限流 + 失败锁定（`account_temp_locked`）+ MFA 全链路
  （enroll/challenge/recovery-code，`services/mfaService.js`）；连续失败 3 次触发的
  人机挑战闸门（`services/loginChallenge.js`）拦在口令比对之前，使「知道用户名就能把账户
  锁 10 分钟」的可用性 DoS 不再成立；闸门拦下的尝试写 `login_captcha_rejected`
  （只留痕、不进任何失败计数，见 `docs/adr/ADR-015` 决策 7）；
- 会话：access 2h（`JWT_EXPIRE` 默认值）/ refresh 7d 双密钥（`validate.js` 强制两钥不同），
  tokenVersion 全局吊销、设备级会话吊销（sid）；
- 冒充管理员：超管角色唯一性由 `utils/superAdmin.js` 强制（克隆角色被拒）。
- 残余：凭据在别处泄露（转 3.4 应急）。

### T 篡改（Tampering）

- 审计链：v4 字段冻结快照 + 哈希链 + HMAC（`auditFieldSetsImmutable` 门禁）；
  周期性 HMAC 签名检查点（`services/auditChainCheckpoint.js` + `scripts/audit-chain-checkpoint.js`）
  补上「锚点后插枝」与「尾部截断」的检出盲区；
- 请求体：Mongo 操作符递归清洗（`sanitizeMongo`）+ `req.query` 物化（Express 5 下
  原地清洗无效，`materializeQuery` 读一次→清洗→defineProperty→回读自证）；
- PII 列：AES-GCM 认证标签——密文被改即解密失败，不静默降级（`utils/piiCrypto.js`）。
- 残余：检查点文件与数据库默认同机，能同时改写两者的人可一并伪造；外部锚定
  （WORM/时间戳服务）需由运维按 `docs/architecture.md` §7 落地。检查点之后新增
  又删除的记录，同样需更晚的检查点才能发现。

### R 抵赖（Repudiation）

- 全量操作审计：写方法 + **全部未豁免 GET/HEAD**（2026-09-30 判据反转，
  `middleware/security.js` auditGetExcludePaths）；HEAD 归一 GET 同尺留痕；
- 敏感读取 403 也留痕（静默探测面清零，`probeExemptionBoundaryAndHeadAudit`）；
- 审计留存 ≥90 天（`constants/retention.js`），导出链路全覆盖（P0-6 write/end 包装）。

### I 信息泄露（Information Disclosure）

- PII at-rest 加密（phone，GCM；realName 暂明文见残余风险）+ 备份加密 + 异地副本（P1-①/②）；
- 传输：生产强制 `tls=true`/`rediss:`（豁免须显式旗标）；
- 响应投影：凭证级字段 `select:false` + `RESPONSE_EXCLUDE` 双道；
- 权限：RBAC + 数据范围（`applyDataScopeToQuery`），GET 接口鉴权契约门禁（F-196）。
- 未脱敏导出（真实姓名）另有三重收口（A-8）：`pii:export` + 当场二次验证之外，① 每日配额按**滚动
  24h** 计（`services/piiExportQuota.js`，读失败 fail-closed 拒发；用尽回 429 + `Retry-After`）；
  ② 水印四路同号（文件名后缀 / 工作簿属性 / 表尾可见行 / 响应头 `X-Export-Trace-Id`，
  `services/piiExportWatermark.js`）；③ 追溯号与用途随 `view_sensitive_data` 审计落库。
- 残余：PII 在**响应体与导出文件**中仍是明文（at-rest 口径）。未脱敏导出**未做双人审批**
  （无审批工作流基础设施、前端未接入该字段），补偿即上一条的配额/水印/审计，叠加
  `pii:export` 并入高风险模块后的授予面收窄。

### D 拒绝服务（Denial of Service）

- 限流矩阵：general/ip/strict/auth/captcha/静态面分桶，令牌桶；
- CC 升级封禁：分桶阈值 + 阶梯升档 + 计数表有界淘汰（`rateLimitEscalation*`）；
- 资源闸：body 1MB、query 长度/标量闸、深分页收敛、备份目录清理硬判。
- 残余：应用层限流前的慢速连接（slowloris）依赖反代（nginx timeout）。

### E 权限提升（Elevation of Privilege）

- 逐路由权限中间件（writePermissionContract / readPermissionContract 双闸）；
- 角色层级闸 + 数据范围越界即 403；权限变更走专门 action 审计；
- 未登记的 controller→models 直连被分层棘轮拦截（`layeringRatchet`）。

### 供应链（横切面）

- lockfile 钉版 + `npm audit` 硬门禁 + dependency-review + CodeQL + gitleaks；
- SBOM（CycloneDX）随构建产出、镜像 cosign keyless 签名 + SLSA provenance；
- 安装脚本登记门禁（`scripts/check-prod-install-scripts.js`，判据取**两份** lockfile）：
  生产树（非 dev 条目，如 `@scarf/scarf` 经 swagger-ui-dist 传递引入）零容忍、
  dev 树（如 `mongodb-memory-server` 预下载 mongod）逐个评审登记，登记键为
  `name@version + integrity`（同名包的未来版本不会自动豁免）；两档均在 CI 硬门禁，
  且位于 **任何 `npm ci` 之前**（`dependency-policy` 作业）；CI 安装一律 `--ignore-scripts`，
  mongod 改由 `deployment/mongod-artifacts.json` 的 SHA-256 锚预置；
- `save-exact=true`（`.npmrc`）从源头杜绝 caret 漂移；
- **lockfile 完整性锚**（`scripts/check-lockfile-integrity.js` + `deployment/lockfile-anchor.json`）：
  把「上次人工拍板时锁文件长什么样」固化成 semantic 哈希写进版本库，任何改动必在 diff 现形；
  与安装脚本登记同属 `dependency-policy` 作业（安装前判定）；
  **与上面的 SBOM 互补而非替代**——SBOM/provenance 是**构建时产出**，描述「这次构建用了什么、
  来自哪里」，但不比对「与上次是否一致」：一个夹带改 `integrity` 字段的 PR 会被 SBOM
  忠实记录、被 `provenance` 证明「来自这次构建」，**没有任何一环能发现「它变了」**。

## 3. 已知残余风险（如实申报）

1. 同宿主 compose 网络明文（TLS 豁免显式声明）——拓扑拆分时摘旗标；
2. realName 暂以明文存储（2026-09-30 决策：姓名片段模糊检索是用户列表的日常能力，
   正则对密文不成立）——转入加密需先给姓名检索另立方案（独立检索索引/搜索引擎）；
3. logShipper 主机名目标的 DNS rebinding 窗口（纵深防御口径，见其头注）；
4. 轮换 `HMAC_SECRET` 后口令复用历史归零（`passwordHistory.test.js` 头注的取舍）；
5. **开发/预览服务器的源码可读面（仅开发期，不构成生产面）**：`web-admin/vite.config.js`
   把 `server.host` 与 `preview.host` 都绑定 `0.0.0.0`（真机/热点调试需要），
   同网段可访问者能读取前端源码（`src/**` 不在敏感文件黑名单内）、使用 HMR 通道。
   生产面不受影响（dev/preview 不参与部署，生产为 `dist/` 静态托管 + 反代），
   但**禁止把 3001 端口发布到公网**；对外演示须用生产构建而非 `npm run preview`。
   暴露内容对照表与自查清单见 `README.md` 的「开发/预览服务器的暴露边界」。
6. **同意链路的边界（一-7）**：隐私同意只在**自助注册**强制，存量账号在告知改版后不会被要求
   重新同意；不存在撤回同意的自助入口（只能联系管理员注销）。告知正文写明「撤回同意将导致
   无法继续使用自助注册的账号」，但界面侧没有一键撤回——测评时按此口径答。管理员建号
   属组织法定基础（《个人信息保护法》第十三条），不写同意记录。
7. **分类分级抓不到"登记了错误等级"**：`tests/ci/dataClassificationInventory.test.js` 强制的是
   「声明与 schema 实况一致」（模型闭合、路径真实、个人信息不降级、`select:false` 全登记、
   加密与 getter 互证），新字段被登记成错误等级只能靠评审发现。日志正文与审计 `details`
   里的自由文本不在台账逐字段覆盖内，按整模型等级继承。
8. **重置口令的复用收口只覆盖一代（审计二-2）**：`User.passwordRetiredHash` 留的是「最近一次重置替换掉的
   **用户自选**那一代口令」的 bcrypt 摘要，上限 1 条（见 `docs/adr/ADR-016`）——连续重置不会用临时口令
   顶掉它，但把口令改回**更早**的退役口令（跨两次以上「重置→改密」）仍不被拦。它同时是一份可离线爆破的
   L4 凭证材料；上限取 1 条是为把改密端点的额外成本钉死在一次 bcrypt 比对（~250–300ms）。重置前的口令明文
   不可知，这在该场景下是唯一可行的形态（不要求用户提供旧口令，否则救济通道就废了）。覆盖窗口的边界由
   `adminResetPasswordGates.test.js` 里那条「已声明残留」用例钉死（改密后再重置会顶掉上一代摘要）。用户注销（删除权）
   时这份摘要随匿名化一并抹掉，故不构成「注销后仍留凭证材料」；命中退役摘要时前端文案仍说「最近 N 条」
   （实际可能更早），属已声明的下界表述。
