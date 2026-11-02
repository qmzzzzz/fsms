# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

### 加固：热升级失败分支自动抓取目标色容器日志（学 a033/LANSEC 的 die 前 dump）（2026-11-02）

> 缺口：`becomes not-ready` 与「观察期判负」两条分支原先只回一句判据（`ready.reason` /
> `observed.reason`），根因（栈、连接错误、迁移报错）留在目标色容器自己的日志里——运维必须
> 再上一次机器 `docker compose logs`。同族系统 a033/LANSEC 的 `install.sh` 在每次 die 之前都会
> dump `systemctl status` + `journalctl`，本仓取同一手法但**只取必要的那一截**。

- **抓取点**：`scripts/hotUpgrade.js` 的两条失败分支各抓一次目标色容器日志尾巴
  （`docker compose logs --no-color --tail 80`，`execFileSync` 捕获、超时 10s、总字节封顶
  64KB）；`aborted_not_ready` 与 `rolled_back` 分支追加进任务说明，`rollback_failed` 保持
  短句紧急文案（下一步动作是人工上机确认流量，长日志只会稀释结论）。
- **两条通道分离**：完整尾巴进宿主留痕 `logs/hot-upgrade-*.json` 的 `targetLogsTail`
  （0600，事后复盘）；按行边界截断的短片段（≤1500 字）进 `status.message`（应用侧轮询可见，
  status 有 64KB 读取上限）。前端 `.upgrade-message` 加 `white-space: pre-line` 让多行日志逐行可读。
- **三条边界**：抓取永不阻断（docker 不可用/容器已停/输出超限都只记一行，主判决始终来自
  就绪探测与观察窗口本身）；有界（行数与字符数都封顶，日志尾巴是诊断样本不是归档）；
  抓取先于停容器执行（`stop` 之后再抓只剩 docker 自己记的那截）。
- **档板与命令注入面**：`captureTargetLogs` 的 argv 逐项构造，服务名先过
  `LOG_TARGET_SERVICES` 枚举白名单、`--tail` 取值固化为字符串常量（Mimosa 的
  「不可信命令参数向量」判据要求 argv 每个动态元素都来自封闭集合，此处在代码层可复核）。
- **登记面**：`deployment/hot-upgrade.md` §7 失败模式表两行改为「容器日志尾巴已进任务说明
  与留痕」+ 新增「失败现场自动抓取」小段（含三条边界与数值）；`eslint.ratchet.json` 的
  `scripts/hotUpgrade.js` 行数地板 334 → 394（功能新增 60 行，按脚本自述的唯一合规路径
  **人工扩基线**并让评审在 diff 里可见）。
- **门禁**：新增 `src/tests/deploy/hotUpgradeFailureLogs.test.js`（6 用例）——两条真跑
  脚本的端到端用例（`--require` 以 **argv 形态**注入 stubExec 与就绪档板，不经
  `NODE_OPTIONS` 字符串拼接）分别钉住「日志进两张表且抓取先于停容器」与「抓取失败不留
  空话式附录、主判决不变」；四条纯函数用例钉住 `buildLogSnippet` 的行边界截断语义
  （未超上限原样保留、超上限从换行起步——半行开头会让运维误以为日志缺行）。

### 新增：离线升级包一键化 + Ed25519 包签名（ADR-019）（2026-11-02）

> 目标：把 air-gap / 内网机器的升级从「两条人工 SSH 命令（导入 + 换装）」变成与在线
> 同门槛的应用内一键流程，同时堵上离线包「manifest 与 payload 可被整体重写」这个
> 只能靠搬运通道可信兜底的缺口。宿主侧骨架（打包脚本 / 判据层 / 导入 CLI / `--offline`
> 换装）于 2026-11-01 落地（25d05a1），本轮补齐触发链路与信任锚。

- **触发链路（同一队列、同一端点、同一套安全门）**：`POST /api/security/upgrade/requests`
  的 body 增加 `mode: 'registry' | 'offline'`（缺省 registry，路由层 `isIn` 白名单）。
  security:config + 唯一超管 + 步进验证 + strictLimiter 原样复用——**离线不是绕开二次
  验证的通道**。宿主代理按 mode 分派：先 `importOfflineBundle.js --apply`（包目录由代理
  在受管 bundles 目录内按 digest 定位，`--bundle-root` 钉死；请求只点名镜像，指定不了
  目录），成功后才 `hotUpgrade.js --offline` 走蓝绿七步；定位不到包 / 导入退出码非 0
  都停在第一段（终态 `aborted_import_failed`：未切流、未动数据）。
- **签名 canonical 按 mode 分型**（`src/services/upgradeRequestSignature.js`）：registry
  维持历史 4 段格式逐字节不变（应用与宿主脚本滚动期互不丢请求），offline 追加第 5 段；
  走哪型由请求里的 mode 唯一决定——在线签名贴到离线请求、离线签名剥掉 mode 冒充在线，
  两条旁路都验签必红（测试钉住）。
- **Ed25519 包签名（信任链收口）**：构建机 `build-offline-bundle.sh --sign-key <pem>`
  对 manifest.json 的**原始字节**签名（`openssl pkeyutl -sign -rawin`，需 OpenSSL ≥ 3.0，
  签完即回验；刻意不做 JSON canonical——canonical 化会把「字节被改过」洗白成「语义相同」），
  产出 `manifest.sig` 并计入 SHA256SUMS；目标机 `importOfflineBundle.js --pubkey-file` /
  代理 env `OFFLINE_BUNDLE_VERIFY_PUBKEY` 验签（node:crypto 内置 Ed25519，零新依赖）。
  **配置公钥 = fail-closed**：未签名/验签失败的包一律拒绝；未配置 = 放行但留痕明示
  `signature: 'unchecked'`。信任链 `公钥 → manifest 字节 → manifest 内 payload sha256`
  传递覆盖整包——「包被整体重写」从不可检测变为可检测。
- **可用性公布（心跳 bundles）**：代理每轮扫描 `OFFLINE_BUNDLE_DIR`（只读 manifest +
  纯判据 + 白名单，**不算 payload 哈希**——GB 级×N 每 15s 一轮不可承受），
  available/invalid 各限 10 条、逐字段截断写入心跳；应用 `readHeartbeat → getOverview`
  透传，前端「关于」页升级弹窗出现「离线包」来源下拉。三条 fail-soft 纪律：目录不存在
  = 未启用离线通道；目录不可读/坏包只折进 reasons 与 invalid，**ready 不变红**（离线坏了
  不拖垮在线）；心跳里的包是「自称通过校验的候选」，不是完整性背书。
- **前端（web-admin）**：`UpgradeDialog` 加「镜像来源」切换——在线手输 digest / 离线从
  心跳公布的包中选择（空列表时 radio 禁用并给出处置提示）；提交显式带 mode；进度弹窗
  加「来源」行与两个新步骤名（导入离线包 / 启动离线换装）；`AboutView.normalizeUpgrade`
  补 `bundles`/`mode` 白名单归一（旧代码逐字段重建快照会把新字段静默丢弃——实测踩中，
  见 ADR-019「踩过的坑」）；中英文案齐备。
- **GB 级包刻意不走应用内上传**：容器只读、无 multipart 栈、body 上限 1MB，且 bundles
  必须保持 root-only（0700）——**能写这个目录的账号 = 能决定线上跑什么代码**，落位
  一律由运维 scp/USB 完成（`deployment/hot-upgrade.md` §3.3 三步 Runbook：构建 `--sign-key`
  → 搬运落位 → 应用内选包一键 / CLI 兜底）。
- **登记面**：`deployment/systemd/hot-upgrade.env.example` 增 `OFFLINE_BUNDLE_VERIFY_PUBKEY`
  （含 openssl 密钥生成与落位命令）；`deployment/hot-upgrade.md` §3.3 重写为完整 Runbook、
  §4 心跳 bundles 字段、§9「不做签名」改写为「签名已引入（ADR-019）、仍不自做解包」、
  §10 增补「离线一键链路未在 air-gap 真机实测（含 openssl 签 / node 验的跨工具互操作）」；
  OpenAPI 的 triggerUpgrade body 同步 mode 字段。
- **门禁（新增/更新测试）**：`offlineBundleSignature.test.js`（签验回环、单字节篡改必红、
  CRLF 算篡改、密钥类型收紧）、`offlineBundleScan.test.js`（字段映射、坏包隔离、fail-soft、
  封顶）、`hotUpgradeOfflineDispatch.test.js`（两段顺序不可反、导入失败停第一段、定位不到
  零执行、registry 不被带偏——进程内 spawn 档板）、`offlineBundlePolicy.test.js`（`--pubkey-file`
  进闭合清单）、`hotUpgradeAgent.test.js`（mode 判据、签名分型、心跳 bundles）、
  `deployCommands.test.js`（`--offline` / `buildImportBundleInvocation`）、
  `upgradeService.test.js`（mode 入队与签名分型、bundles 透传）、`upgradeEndpoint.test.js`
  （mode isIn 400、审计 body 记 mode）、`aboutViewUpgrade.test.js`（离线来源切换/选包/提交）。

### 收口：前置人机层拦下的登录尝试落库留痕（审计二-3，裁决取「落库留痕」）（2026-11-01）

原缺口：ADR-015 的闸门（静态验证码开关 ∪ 失败触发的挑战）拦在口令比对之前，被拦下的尝试
**零留痕**——`/api/auth/login` 被全局审计按 `excludePaths` 排除，登录链自己只写成功与"口令错"
两类行，于是"谁在反复撞这道闸、撞的是哪个用户名、来自哪个 IP、是开关要求还是连续失败触发"
在审计库里全都答不上来；而这条路径恰恰是自动化爆破被挡住的地方（最该看见的地方）。ADR-015 末条
把这件事写成"刻意接受的观测缺口"并挂到审计二-3 等裁决，本轮裁决取 **B 落库留痕**。

修法：`services/loginChallenge.js` 新增 `recordCaptchaRejected(...)`，在 `resolveLoginPassword`
的验证码拒绝分支写一条**独立动作** `login_captcha_rejected`（`category:auth`、`success:false`、
`riskLevel:medium`；`reason` 记录"哪一层要求的"= `captcha_switch` / `challenge_required`；
`riskFactors` 记录"没带验证码"= `captcha_absent` 还是"带错"= `captcha_mismatch`）。三条边界：

- **不进任何失败计数**：该动作既不在 `loginChallenge.FAILURE_ACTIONS`，也不进
  `securityAlert.checkBruteForce` 的统计动作集合。否则「被拦下」会自我维持——撞得越多、闸门越
  不可能关；且闸门拒绝会被误报成口令爆破。写入量本身已被 `loginLimiter`（10 次/15 分钟/IP）与
  `loginUserLimiter`（20 次/15 分钟/账号）定上界，无需为此再发明一条独立配额。
- **不改变对外口径与耗时特征**：仍是 400 `CAPTCHA_INVALID`；不存在的用户名与存在的用户名写同一
  形态的行（判据与留痕都不查 `User`），不构成存在性预言机；写入走 `await awaitAuditWrite(...)`
  有界等待（审计库卡住时不把登录接口挂死），写失败走 `onAuditWriteFailure`
  （error 日志 + `audit_write_failed{high}`，永不 reject），故审计库故障不影响拒绝语义。
- **不开新的 fail-open 位点**：留痕失败不改判定（照旧拒绝），因此不进 `failOpenSites` 台账。
  `reason` 是自由文本字段、schema 侧无清洗，而本函数是导出件 ⇒ 只写闭集（`captcha_switch` /
  `challenge_required` / `unspecified`）里的值：调用方传什么都不会原样落库。

登记面同步：`constants/audit.js` 事件型白名单新增 `login_captcha_rejected`；前端
`web-admin/src/i18n/locales/{zh-CN,en-US}.js` 的 `audit.action` 两族补文案（`auditActionCoverage`
门禁要求 zh/en 全覆盖、非空且互不相同）；导出侧 `constants/reportExportLabels.js` 的中英动作名同步
（该闸只要求 zh/en 键集对齐，缺一侧即红）。

门禁：新增 `src/tests/services/loginChallengeAudit.test.js`（8 条）——① 挑战闸门拦下写一条
`reason=challenge_required` 的行，且**判据口径全部动作的计数停在阈值**、`failedLoginCount` 不变、
`checkBruteForce` 未被调用；② 静态开关拦下 `reason=captcha_switch`，并区分"没带"与"带错"；
③ 不存在的用户名同样留痕、同一对外口径；④ 审计写失败仍 400 且按 high 档记账（反向对照：
把守卫换回 `.catch(() => {})` 这条会红）；⑤ 畸形 username 不产噪声行、不抛，且对照一条合法用户名
确实写得进去；⑥ 请求方可控的 `ip`/`userAgent` 仍走 schema 单点闸（≤64 / ≤512、无控制字符）；⑦ 模型层**同步**抛
（未就绪 / CastError）不外溢成 500，仍按 high 记账（`.catch(...)` 只接得住 rejection，接不住 throw）。
另有一条登记面用例（动作在白名单内、且不在 `FAILURE_ACTIONS` 里）。三处把
`services/loginChallenge` 整模块替身的用例桩（`loginTimingParity`、`authServiceLoginResidualBranches`、
`authServiceSideEffectFailureTolerance`）同步补上新导出（桩与真实导出不同形时，走到该分支的用例会以
TypeError 假红），残余分支用例另加一条「留痕写的不是 `login_failed` 行、而是独立动作」的断言。ADR-015 决策 7 记录该裁决，
并改写末条"观测缺口"为两条**残留**：该行区分不出"真人输错"与"脚本"；留痕不反馈到闸门自身。

### 收口：管理员重置口令后的口令复用（审计二-2）（2026-11-01）

原缺口：管理员重置口令（P1-2 救济主通道）只签发临时口令、踢会话、置 `mustChangePassword`，**被替换掉的那一代口令没有任何留痕**。于是「重置 → 首改 → 再改回重置前那条口令」是通的：`PASSWORD_REUSED` 只查 `User.passwordHistory`，而重置路径没有（也算不出）往历史里写东西——历史记的是旧口令的 **HMAC 摘要**，算摘要要明文，重置路径手上只有库里那条 bcrypt 摘要。也就是说：管理员这道救济动作可以被用户自己撤销，撤销回来的正是最该作废的那条口令。

修法是给「知道摘要、但没有明文」补一个载体：`models/User.js` 新增 `passwordRetiredHash`（`{ type:String, select:false }`，**不设 default**——default 会让裸载入的文档把默认值写进 save 的 `$set`，反过来抹掉保护），并进 `USER_RESPONSE_EXCLUDE_FIELDS`（与 `password` / `passwordHistory` 同规格，只排不减）。重置路径 `securityController/admin.js` 用 `.select('+password')` 取出旧摘要，在**同一条原子条件更新**里写 `passwordRetiredHash: user.password || null`；改密路径 `authService/password.js` 在 HMAC 历史之后追加一次 `bcryptWorker.compare`，命中即返回 `PASSWORD_REUSED`（与历史命中共用同一个码：用户要做的动作相同，拆码只多一份前端文案；服务端日志把两个来源分开）。判据自带形态闸（`/^\$2[aby]\$/`）与失败口径：形态不对 / 比对抛错 ⇒ error 日志 + **本条按放行处理**（加强层不允许把改密端点变成 DoS 面）。

刻意取舍（全文见 `docs/adr/ADR-016`，并进 `docs/threat-model.md` §3 残余）：上限 **1 条**——bcrypt 每条约 250–300ms，`utils/passwordHistory.js` 的 `HISTORY_DEPTH=5` 走 HMAC 正是为避开这个成本，退役摘要留 N 条会让改密端点背 N×250ms；代价是跨两次以上重置的更早口令不在覆盖内，且库里多一份可离线爆破的 L4 凭证材料。备选 (B)「重置时把临时口令写进 `passwordHistory`」被否：它挡不住这条链（`P0` 仍不在历史里），还会让 `passwordHistory` 混进两种来源的条目。

边界（同日补齐）：① **连续两次重置**（临时口令没送达 / 过期，运维上常见）替换掉的只是管理员签发的临时口令——若照写覆盖，真正要防的那一代用户自选口令会**静默**重新变得可设回。取值规则收敛到 `admin.js::retiredHashForReset`：仅当当前口令不是未被消费的临时口令（`mustChangePassword` 未被清）时才更新退役摘要，并新增真库用例（连重两次 → 最初口令仍被 `PASSWORD_REUSED` 拒）。④ **残留的边界也被钉死**：`adminResetPasswordGates.test.js` 增一条「已声明残留」用例——用户成功改密（`mustChangePassword` 已清）后再重置，退役摘要被新一代顶掉，最初那代随之可设回。这不是期望行为，而是把 ADR-016 里「只覆盖一代」的残留从散文变成可执行的边界：没有它，那三条绿用例只证明「保护在」，读不出「保护到哪为止」。② **删除权**：`services/userService.js` 的匿名化把 `passwordRetiredHash` 与口令改写同批置空——注销后不留可离线爆破的 L4 材料，`businessRetentionAndAnonymization.test.js` 增「挂摘要 → 匿名化 → 读回为 null」判据。③ 文案口径按 ADR-016 接受复用：命中退役摘要时前端仍说「最近 N 条」，被拒口令可能比 N 条更早，属**下界**表述（用户动作相同），已写进 ADR「后果与局限」。

门禁：`adminResetPasswordGates.test.js` 增三条真实 Mongo 用例（连续重置为第三条）——① 读回校验 `passwordRetiredHash` 是旧口令的 bcrypt 摘要（且不是新签发的临时口令，`passwordHistory` 仍为空）；② 闭环：重置后把口令改回重置前那条 → `PASSWORD_REUSED`，换全新口令 → `OK` 且 `forced=true`，再试一次仍被拒（退役摘要不随一次成功改密被清掉）。`passwordHistory.test.js` 增两条接线不变量（重置端必须 `.select('+password')` 且写该字段；改密端必须读出来并真的比对——**只写不读同样是缺陷**）。清单同步：`userCredentialProjectionLedger` 10 → 11 条凭证投影路径、`userSaveCredentialWipe` 的 `CREDENTIAL_PATHS`、`models/User.test.js` 的两张清单、`updateUserMassAssignmentGuard` 的特权字段清单、`constants/dataClassification.js` 逐字段台账（57 → 58，L4 / bcrypt / 归属 account 同意范围）。

### 收口：数据分类分级台账与注册同意记录（审计一-7）（2026-11-01）

原缺口两半：① 仓里对「哪些字段是个人信息 / 敏感数据」只有零散口径（`piiCrypto` 的加密范围、
各模型的 `select:false` 清单、审计脱敏名单），**没有任何一处**能回答「`User.email` 属于第几级、
依据是什么、静态存储是否已加密」——等保 2.0 与《个人信息保护法》要求的「数据分类分级」不可核对，
新增字段时没人能判断它该不该加密、该不该进脱敏名单、该不该要单独同意；② 注册页只有一句
「注册即表示同意」式的暗示，**没有任何同意记录**——同意是不可证明的，改版也区分不出用户同意的是哪一版。

① **台账**：新增 `src/constants/dataClassification.js` 作唯一声明面——四级分类（L1 公开 / L2 内部 /
L3 敏感 / L4 关键，每级附判定依据）、静态存储形态（`gcm`/`hmac`/`sha256`/`bcrypt`/`plain`）、
逐模型基线（18 个模型）+ 58 条逐字段声明（等级 / 静态形态 / 是否个人信息 / 依据 / 归属的同意范围），
以及同意范围表 `CONSENT_SCOPES`（每项注明是「向用户告知 notice」还是「组织法定基础 legalBasis」）。
`classifyField(model, path)` 是唯一查询入口；未登记模型返回 `null` 而非猜默认等级——"猜"正是本项要消灭的东西。

② **同意记录**：新增 `models/ConsentRecord.js`（append-only，与 `auditLogHooks` 同宽的 9 类写入口全拦；
`{userId,policy,version}` 唯一索引 ⇒ 重复提交幂等；`consentStatus()` 只认**现行版本** ⇒ 改版不继承旧同意）
与 `services/consentService.js`（版本号与范围清单的唯一事实源，范围从 `CONSENT_SCOPES` 的 notice 项派生，不手抄第二份）。
注册链路三道闸：路由 `body('privacyConsent').custom((v) => v === true)`（缺省 / `'true'` / `1` / `{}` / `false`
一律字段级 400）、服务层 fail-closed 复判（`outcome='CONSENT_REQUIRED'`）、**签发令牌之前**落库且落库失败回滚账号
（`REGISTER_SERVICE_UNAVAILABLE`）——绝不留下「有账号、无同意证据」的用户。新增错误码 `PRIVACY_CONSENT_REQUIRED`（400）

- 中英词条 + `ERROR_CODE_I18N_MAP`。前端 `RegisterView.vue` 末步增勾选框与可点开的告知全文（版本号与范围来自
  `web-admin/src/utils/privacyNotice.js`，与后端逐字对拍）；勾选框用 `validator` 判 `value === true` 而非 `required:true`
  （`el-checkbox` 的 `false` 会被 `required` 判成"有值"，那样勾选框形同虚设）。

门禁：`src/tests/ci/dataClassificationInventory.test.js`（7 条，用**真实加载的 schema** 对拍）——反空自证、
模型清单双向闭合、声明路径真实存在、个人信息正则命中全部登记且不得降级到 L2 以下、`select:false` 全登记、
`atRest='gcm'` 与 schema getter 双向互证（例外只来自 `GCM_WITHOUT_GETTER` 且理由非空）。
用例另增 `src/tests/models/ConsentRecord.test.js`（7 条：范围派生 / 幂等 / 改版不继承 / append-only 逐写入口真调 / 唯一索引）、
`src/tests/controllers/registerPrivacyConsent.test.js`（5 条：缺字段与五种非布尔真值一律拒绝且**账号未创建**、
绕过路由直调服务层同样拒绝、成功时记录与账号同主体、记录落库失败回滚账号）、
`web-admin/src/tests/utils/privacyNoticeParity.test.js`（4 条前后端常量对拍）。

如实申报的**边界**：同意只覆盖**自助注册**；管理员建号属组织法定基础（《个人信息保护法》第十三条），不写同意记录；
存量账号在告知改版后不会被要求重新同意；无撤回同意的自助入口（见 `docs/threat-model.md` §3 第 6 条）；
台账门禁抓「声明与实况不一致」，抓不到「新字段登记了错误等级」。台账用法见 `docs/data-classification.md`，
等保对照新增两行见 `docs/mlps2-controls.md`。

### 收口：未脱敏导出的配额 / 水印 / 追溯留痕（审计一-8）（2026-10-31）

原缺口：`POST /api/reports/export/pii` 的强度只有「`pii:export` + 当场二次验证」两道门，门里面
**没有次数上限**、文件上**没有归属标记**——拿到 `pii:export` 的账号一天内可以把真实姓名批量
拉走任意次；文件一旦离开系统（邮件 / 网盘 / U 盘），审计链再管不到它：知道"有人导出过"，
答不上"外泄的这份是哪一次"。

三层补法（掩码档行为一字未动）：

① **配额**：新增 `services/piiExportQuota.js`，按**滚动 24h** 窗口数留痕本身（`view_sensitive_data`
/ `dataType=export_realname`），不另造计数表；默认每人 5 次/天（`PII_EXPORT_DAILY_QUOTA`，钳 1..100），
用尽时 429 `PII_EXPORT_QUOTA_EXCEEDED` + `Retry-After`（指向"最早一次滑出窗口"还需多久）。
判据读失败一律上抛（fail-closed）：绝不在"不知道今天已经导了几次"的时候放行。闸挂在二次验证
**之前**——注定被配额拒绝的请求不该先烧掉一次凭据尝试（与 `requirePiiExportType` 同一顺序纪律）。
② **水印四路同号**：新增 `services/piiExportWatermark.js`，16 位 hex 追溯号同时进文件名后缀、
工作簿属性（creator/lastModifiedBy/description/keywords）、表尾可见行与响应头
`X-Export-Trace-Id`；判据与留痕同一处（打标而不留痕等于把文件钉在一个审计里不存在的追溯号上）。
③ **留痕补字段**：`auditUnmaskedPiiExport` 的 `body` 增加 `traceId` / `purpose`——审计与文件同号，
一份外流件可反查到导出人与那一份导出记录。用途（`purpose`）随请求体记录、不强制（前端未接入，
强制填写会把整条路径堵死）。

如实申报的**残余**：未实现双人审批（本系统没有审批工作流基础设施），补偿是上列三条 + `pii:export`
并入高风险模块（审计二-1）。

用例：新增 `src/tests/services/piiExportQuotaWatermark.test.js`（11 条：窗口 / 判据形状 / 分流三类负前提

- 水印判据与文案）；`src/tests/controllers/reportPiiExportStepUp.test.js` 增水印四路断言（响应头 / 表尾行 /
  文件名 / 工作簿属性 / 审计同号）与配额用尽（429 + `Retry-After`）两段；
  `src/tests/services/reportExportPiiMasking.test.js` 的接线闸同步钉住两条新链（配额在 `pii:export` 之后、
  二次验证之前）。前端补 `errors.piiExportQuotaExceeded` 中英词条与 `ERROR_CODE_I18N_MAP` 映射。

### 收口：私有仓 SAST（Semgrep + 仓库自持规则包）与依赖修复时限（SLA）（审计一-5）（2026-10-31）

原缺口两半：① `.github/workflows/codeql.yml` 的第一层判据是 `repository.private == false`，本仓是私有仓，
于是**一个静态分析器都没在跑**，findings 只能靠人工评审撞见；② 仓库里没有任何写下来的修复时限，
advisory"什么时候必须修"只能靠口头约定。

补法：新增 `.github/workflows/sast.yml`（Semgrep OSS；容器镜像按 digest 钉死
`semgrep/semgrep:1.183.0@sha256:2e45517a…`，并登记进 `scripts/verify-image-digests.js` 的期望表与镜像面账），
规则来自仓库自持的 `.github/semgrep/rules.yml`（7 条：`jwt.verify` 少算法白名单 / 关 TLS 校验 / MD5 /
`eval`-`new Function` / `child_process` 的 `shell: true` / Mongo `$where` / `res.redirect(req.*)`）。
不依赖 GHAS（私有仓的 SARIF 上传会被拒 ⇒ 落 `semgrep-sarif` 制品），`--metrics=off` + 本地 `--config`
⇒ 私有源码不出 runner；扫描带 `--error` ⇒ 命中即阻断。规则包先过 `--validate`，规则条数 / 排除面 /
零命中由 `src/tests/ci/sastWorkflowInvariants.test.js` 逐条判（零命中是入场券，且每条规则必须在自己的
违反样例上命中，防空转）。

另一半是写下来的 SLA：`deployment/dependency-sla.json` 与 `docs/security-dependency-watch.md` 的同一张表
（critical 7 / high 30 / moderate 90 / low 180 / info 365 天），由 `src/tests/deploy/dependencyFixSla.test.js`
逐格对账，硬上限写在同一用例里（数字只许收紧）。执行点三条：未登记一律阻断
（`scripts/check-audit-allowlist.js`，严于 SLA）· 已登记项的 `reviewBy` 到期即红 · SAST findings 阻断。

### 修复：退出遮罩在「系统已关闭动画」的机器上完全静止（2026-10-31）

> 现象：退出登录时 `ExitOverlay` 遮罩样式正确但一动不动——进度环不转、进出场无淡入，像卡死了。

根因不在组件，而在**机器级设置**：Windows「辅助功能 → 视觉效果 → 动画效果」关闭时（`HKCU\Control Panel\Desktop\WindowMetrics\MinAnimate=0`，
`SystemParametersInfo(SPI_GETCLIENTAREAANIMATION)` 返回 0），Chromium/Edge 对**每个页面**都报
`prefers-reduced-motion: reduce`；而本仓的无障碍降级写在各组件自己的 `@media (prefers-reduced-motion: reduce)` 块里，
`ExitOverlay.vue` 原先也把 `.exit-overlay__spinner` 与 `.exit-fade-*` 一并 `animation: none` / `transition: none`，
于是遮罩只剩静态画面。**同一份代码在默认设置的机器上正常**，所以只在个别机器复现。

按「区分必要反馈与装饰性动效」收窄降级口径（`web-admin/src/components/ExitOverlay.vue`）：遮罩显示期间
下层已 `inert`、没有任何可操作面，① **进度环是唯一的活动信号**——停转与「卡死」不可区分，按必要反馈保留旋转；
② **进出场本就是纯 `opacity` 过渡**（无位移/缩放），与全局降级口径（`apple-polish` 把过渡统一降为 opacity）一致，保留；
③ **呼吸光是纯装饰、不承载信息**，仍按 `reduce` 关闭。样式、配色、尺寸、文案一律未动。

用例：`web-admin/src/tests/components/exitOverlay.test.js` 增 3 条静态不变量（jsdom 不注入 SFC scoped 样式，只能读源码）——
`reduce` 块外仍有 `animation: exit-spin 0.8s linear infinite` 且块内不含 `.exit-overlay__spinner`；
`reduce` 块内无 `transition: none` 且保留 0.4s/0.3s 的 opacity 过渡；`reduce` 块内 `.exit-overlay__icon` 仍 `animation: none`。
原件 5 条不变，共 8 条。真实 Chrome 156 实测（先 `emulateMedia({reducedMotion:null})` 清掉 Playwright 默认注入的
`no-preference` 覆写，才拿得到系统真值）：系统真值 `reduce=true` 的环境下 `opacity` 0→0.15→0.46→…→1、
`animation-name: exit-spin-*`/`0.8s`/`running`、逐帧 `transform` 变化 77 次（在转）、`icon` 为 `none`（装饰仍降级），
全流程无控制台报错；`dist` 产物 CSS 中 `@media (prefers-reduced-motion: reduce)` 内只剩 `.exit-overlay__icon{animation:none}`。

### 收口：二次验证票据一次性 + 会话级窗口（审计一-3）（2026-10-31）

原实现：`POST /security/reauth` 用当前口令换一张 5 分钟票据，票据只绑 `uid` + `sid`，**没有 jti、不做消费记录**。
于是同一张票在窗口内可以无限次重放——票据是 bearer 凭据，泄漏一次（XSS / 崩溃转储 / 调试器 / 代理日志）
就等于整个窗口内三条审计读取（列表 / 告警 / 取证导出）的读取权，且事后无法从服务端判断「这张票被用过几次」。

改成两条并存的路径：

1. **会话级窗口**（`src/models/ReauthGrant.js` + `src/services/reauthGrantStore.js`）：step-up 成功后按
   `sid`（access token 的 `jti`）落一条 5 分钟记录（TTL 索引自清）。窗口内凭**有效访问令牌**即可读取，
   **客户端不再持有任何凭据**——换设备、被踢下线、会话吊销都会让窗口随之失效（窗口绑的是那一个会话，
   不是那一个人）。审计页首屏一次是三条受保护读取，「一次验证」仍然成立。
2. **一次性票据**（`src/models/ReauthTicketUse.js` + `src/services/reauthTicketStore.js`）：给没有会话上下文的
   API 客户端。票据载荷加 `jti`（32 位 hex，16 字节随机），中间件校验通过后**立即消费**：
   `ReauthTicketUse.jti` 上有唯一索引，插入成功＝这张票没用过，`E11000` ＝重放。判据落在 Mongo 而不是
   进程内存，多实例部署下同样成立（本仓生产是单节点副本集，但判据不该依赖「只有一个进程」这个偶然事实）。

失败方向分开定：**票据消费 fail-closed**（存储不可用 ⇒ 抛 500。读不到判据就不能声称这张票没用过，
而审计读取本来就要读 Mongo，不算额外可用性代价）；**窗口记录/查询 fail-open**（落库失败只告警，
调用方拿到的票据仍可用；查询失败按「无窗口」处理、退回票据路径）。丢掉便利 ≠ 丢掉唯一性判断。

重放对外仍报同一个 `REAUTH_TICKET_INVALID`：对合法持票人来说可行动作与「票据无效/过期」完全一样
（重新 step-up），区分两者只会给重放者多一个信号位。重放事实只进服务端 warn 日志（含 username / path）。

`jti` 缺失或形状不符一律判无效（滚动升级期间不设兼容豁免：代价只是老票据持有者重新验证一次）。
前端同步收口：`web-admin/src/utils/reauthTicket.js` 不再存票据（内存里那张可重放的凭据消失），
`api.js` 去掉 `X-Reauth-Ticket` 请求头，`AuditLogView` 去掉「本地没票就直接弹框」的前置判断
——那等于把授权判据复制成一份更弱、且与服务端不同步的客户端版本；现在统一由 401 `REAUTH_TICKET_*` 驱动弹框。

用例：`reauthTicketOneTimeUse.test.js`（9）覆盖 jti 存在性/随机性、无 jti 旧票无效、畸形 jti、
首次/二次消费、并发 5 路单赢家、非 11000 错误 fail-closed、TTL 与 unique 索引实据；
`reauthTicketEnforcement.test.js`（18）覆盖 HTTP 链路：窗口放行三条读取、窗口不跨会话借用、
票据重放换端点仍拒、并发双发只有一个进控制器。

### 收口：出站目标两处「配了才管」的允许清单（审计一-4）（2026-10-31）

**① 审计锚点（`src/services/auditAnchorSink.js`）**：`AUDIT_ANCHOR_SINK` 指向的 http 端点在
`AUDIT_ANCHOR_ALLOWLIST` 为空时**照收**。锚点载荷是链头哈希 + 条数 + 签名——一份权威的审计摘要，
每小时外发一次。误配（粘贴错、环境变量串了）就等于把审计摘要持续寄给陌生主机，而 cron 的告警没人看。
现在空清单直接 fail-closed（`allowlist_not_configured`），并新增私网/回环/歧义 IPv4 拒绝
（`host_private_not_allowed`，`AUDIT_ANCHOR_ALLOW_PRIVATE_HOSTS` 显式放行内网锚点）、
非清单主机拒绝（`host_not_allowlisted`）。

**② 日志外发（`src/utils/logShippingTarget.js`，从 `logShipper` 抽出）**：此前声明的「后续加固项」是
**解析一次、连接另一次**——`pinShippingTarget` 校验的是解析结果，`http.request` 又按主机名重新解析，
中间那一段就是 DNS 重绑定窗口（攻击者控制的 DNS 先回公网地址过闸、再回内网地址收数据）。
现在解析**只做一次**并把地址集注入 `http.request` 的 `lookup`（`pinnedLookup`），连接目标就是校验过的那一个；
主机名条目（`LOG_SHIPPING_ALLOW_PRIVATE_HOSTS`）按「名字被显式豁免」判，IP/CIDR 条目按解析出的每个地址判，
A/AAAA 中**任一**落在禁区就整条投递拒绝（不做「挑一个能用的地址」的降级）。解析超时 3 秒。

### 加固：生产镜像不再产出未钉扎前端的包（审计一-6）（2026-10-31）

`scripts/login-key-pin.js` 增加 `--require`（或 `REQUIRE_LOGIN_KEY_PIN=true`）：缺登录公钥摘要时**非零退出**
（原行为是打一条 `::warning::` 然后照常产出镜像）。release 的 `build` job 改为 `--require`，
并把 `REQUIRE_LOGIN_KEY_PIN=1` 作为 build-arg 传进 `Dockerfile`；`web-builder` 阶段另有一道闸，
`REQUIRE_LOGIN_KEY_PIN=1` 且 `VITE_LOGIN_PUBLIC_KEY_SHA256` 为空时直接 `exit 1`。
两道闸是刻意的：`login-key-pin.js` 那一道保证 CI 侧「没有秘密就不发版」，Dockerfile 那一道保证
**绕过 CI 手工 build** 也产不出未钉扎的镜像（公钥钉扎是登录口令信封加密的信任根，未钉扎的包等于把
「服务端公钥」交给任意中间人替换）。PR / 本地构建保持宽松（缺摘要只警告、产物照出），
因为那里本来就没有可部署的信任根。

### 变更：`pii` 模块并入高风险（审计二-1）（2026-10-31）

`pii:*` 与 `pii:export` 此前可由**单人**审批发放，而 `system:read` 这类只读权限却要双人——
方向是反的：前者能导出未脱敏的个人信息。`src/constants/privilegeGrant.js` 与
`web-admin/src/utils/privilegeGrant.js` 同步把 `pii` 移入 `HIGH_RISK_MODULES`（前后端同源同锁步，
另有 parity 用例钉住两侧数组不得漂移），于是 `pii:*` / `pii:export` / `pii:read` 一律
`{ highRisk: true, requiredApprovals: 2 }`。判据读的是**权限码前缀**而不是 `Permission.module`：
授予对象是码，判据也必须是码，否则一条 `module` 字段写错就能把高风险授权降级成单人审批。

### 新增：请求级幂等与响应回放（审计一-1）（2026-10-31）

写接口此前对「同一次提交到达两次」没有任何判据：客户端重试、双击、代理重放、断线重连都会
把同一次操作变成两条记录（批量删除、角色分配、设备绑定这类操作尤其难回收）。新增
`src/middleware/idempotency.js`，按请求头 `Idempotency-Key` 取键：

1. **同键同载荷** ⇒ 原样回放第一次的 2xx 响应，并带 `Idempotency-Replayed: true`；
2. **同键不同载荷** ⇒ 409 `IDEMPOTENCY_KEY_REUSED`（键被复用成另一件事，不能静默回放）；
3. **上一请求在途** ⇒ 409 `IDEMPOTENCY_IN_PROGRESS`（不是排队等待：等待会把「在途」变成
   一个可被外部拉长的挂起点）；
4. **业务返回非 2xx** ⇒ 释放键（失败必须允许重试，否则一次 500 就把这次提交锁死一天）；
5. **存储不可用** ⇒ fail-open 放行并 warn（丢的是去重便利；fail-closed 会把一次 Mongo 抖动
   放大成全站写不了——与二次验证票据「消费必须 fail-closed」是相反的取舍，理由见 ADR-014）。

判据形态：键只存**哈希**（`sha256`，`src/models/IdempotencyRecord.js`），载荷存规范化后
的 sha256 指纹，24 小时 TTL 自清；单条记录的响应体上限 64 KiB（大导出不留在记录里，
未脱敏导出因此**不接**本中间件）。中间件挂在 `checkPermission(...)` **之后**：未授权调用方
拿不到键空间（否则可以用猜键的方式把别人的键提前占死）。键**默认可选**——不带就完全跳过，
`required: true` 是给日后需要强制的那条路由留的开关，现有 105 个调用点不因此改变行为。

接线：`user`/`role`/`device`/`inspection`/`alarm`/`permission` 六组写路由（含 8 个 POST 端点）；
`app.js` 的 CORS `allowedHeaders` 加 `Idempotency-Key`、`exposedHeaders` 加
`Idempotency-Replayed`（不暴露的话浏览器侧读不到回放标记）。前端 `web-admin/src/utils/idempotency.js`
提供 `createSubmissionKey()`：**每次提交意图**生成一枚键、失败重试复用同一枚、成功即作废；
`api.js` 的写方法签名改为 `(data, config)` 以便透传请求头。

用例：`src/tests/middleware/idempotency.test.js` 15 条（回放/载荷不符/在途/非 2xx 释放/
存储故障 fail-open/键格式非法/缺键跳过…）、`web-admin/src/tests/utils/idempotency.test.js` 7 条。
取舍与未采纳方案见 `docs/adr/ADR-014-请求级幂等与响应回放.md`。

**补：在途记录租约（ADR-014 决策 7，2026-11-01）。** 上述实现有一处真缺口：`in_progress` 只有
「有人来收尾」时才会结束，而**进程被杀**（OOM / SIGKILL / 滚动重启）、事件循环永久挂起、
客户端在响应头发出前断开，这三种情形都不会再进收尾分支——那一行会停在 `in_progress`，
`expiresAt` 却仍是「认领 + 24h」。结果是同一枚键在这一整天内的每次重试都只能拿到 409
`IDEMPOTENCY_IN_PROGRESS`，服务端没有任何恢复动作，用户只能刷新页面换一枚新键（前端键只在
内存里，刷新即换）——所以它是「可自愈但不可见」，不是「不可恢复」，但对脚本/第三方调用方是真死锁。
现在 `in_progress` 带 5 分钟租约：超租约仍无结论即视为无主，同键重试以条件更新
（`state: 'in_progress'` + `expiresAt ≤ 现在 + 保留窗口 − 租约`）**原子接管**并按首次提交执行一次，
接管同时重置 `expiresAt`（并发接管只有一个赢家），每次接管发 `idempotency_lease_takeover`
（medium，登记在 `constants/failOpenSites.js`）。代价写在 ADR-014 后果里：若上一次其实已落库，
接管会重复写一次且调用方无感——用可观测的偶发重复换掉无出口的长时间拒绝。租约内仍在途的请求
行为完全不变（照旧 409，不发信号）。用例见 `idempotency.test.js` 的 `(h)`–`(n)`。

**补：判据载体的存在性（ADR-014 决策 8）。** 同一轮里还补了 `autoIndex` 型的静默失效：
mongo 的 `autoIndex` 在后台建索引，失败只打日志、插入照常成功——索引不在时「两个并发同键」都能进，
去重静默失效而日志全绿（`tokenblacklists.token_1` 是同类先例）。现在中间件在首个带键请求前显式
`createIndexes()`；建不起来就不把插入当判据，走同一条 fail-open 出口并计入 `idempotency_degraded`，
失败不缓存、下一请求重试。用例见 `idempotencyDegradeSignal.test.js`。

### 修复：登录防爆破收口——失败触发的人机挑战 + 锁定不可被廉价触发（审计一-2）（2026-10-31）

两处缺口同源：**登录链没有任何"失败到一定次数就要求人机验证"的台阶**。
一是图形验证码的静态开关**默认关闭**（`LOGIN_CAPTCHA_ENABLED` 未设即 false，系统配置表无记录也回落 false），
于是默认部署下登录链没有前置层；二是账户级临时锁定由"连续失败 10 次"直接写 `User.lockUntil`，
而触发它只需要知道用户名——攻击者可以反复把任意已知账户锁 10 分钟（可用性 DoS）。

新增 `src/services/loginChallenge.js`（`isChallengeRequired`）并接到登录前置层
（`authService.resolveLoginPassword`）：**同一用户名的连续失败**（自最近一次成功登录起算、
窗口 15 分钟，与凭据型限流的窗口对齐）达到 3 次后，该用户名的登录必须先过人机验证，
**与静态开关无关**。闸门拦在口令比对之前，因此被拦下的尝试既不推进 `failedLoginCount`、
也不写任何失败计数行——无验证码的一方推不到 `MAX_FAILED_LOGINS`，锁定窗口对它**不可达**
（它们此后落一条独立动作 `login_captcha_rejected`，只留痕、不进计数：审计二-3 裁决取「落库留痕」，
见上方同名条目与 ADR-015 决策 7）
（攻击者拿不到批量爆破，也拿不到"锁死账户主人"这条 DoS 路径）；而 `lockUntil` 的语义
本身没有改动：`middleware/auth.js`、令牌刷新、WebSocket 三处门禁照旧按 `lockUntil` 拒绝。

判据与「账户是否**存在**」无关是有意的：计数走 `AuditLog` 的 `login_failed` / `auth_failed`
（与 `securityAlert.checkBruteForce` 统计同一批动作），本仓在"用户不存在"分支同样写这两类行，
于是不存在的用户名与存在的用户名**拿到同一个 `CAPTCHA_INVALID`**（用例钉住：无用户名存在性预言机）。
判据读取失败时按 **fail-closed** 处理（要求挑战）而不是静默放行；这不属于"降级即放行"，
所以不进 `failOpenSites` 台账（该读取失败同时意味着登录本来就查不到用户，同一个依赖）。

锁定窗口对**能过人机验证的人**不再是硬墙：`assertAccountUsable` 的临时锁定分支新增
`captchaVerified` 放行臂（口令错仍落到统一 401，账户主人凭正确口令登录并清锁，
会话签发处的 `lockUntil: null` 连带清锁）。否则"任何人凭 10 次失败就能让账户主人在窗口内
完全登不进来"这条 DoS 仍然成立。

前端 `LoginView.vue`：收到 `CAPTCHA_INVALID` 且本地未渲染验证码区时补渲染验证码输入 + 拉新图 +
提示 `login.captchaChallengeRequired`；此前该响应只会在开关关闭时显示"验证码错误或已过期"，
而界面上没有任何输入框（用户无出口）。

用例：`src/tests/services/loginFailureChallenge.test.js` 6 条（阈值内统一 401 / 越阈要验证码且计数停在阈值 /
带验证码放行且真实失败照常计数 / 连续失败的起点是最近一次成功登录 / 不存在用户名同一口径 / 窗口外不计入 /
判据不可读 fail-closed）；`web-admin/src/tests/views/loginView.test.js` +1 条。
三个既有套件（`loginTimingParity`、`authServiceLoginResidualBranches`、
`authServiceSideEffectFailureTolerance`）整模块替换挑战判据——它们的被测对象是**前置层之外**的
比较次数/残余分支/旁路兜底，判据留在真值上会把被测链整体改写成 `CAPTCHA_INVALID`（文件内已注明理由）。
完整取舍、未采纳方案与残余风险见 `docs/adr/ADR-015-登录失败触发的人机挑战与锁定收口.md`。

### 新增门禁：模块入库闭包（被引用的本地模块必须已入库）（2026-10-31）

第十轮逐条核对工作树时发现 `git status` 里混着 **5 个源码文件根本没入库**：`src/constants/reportExportColumns.js`（被
`reportExportService` 引用）、`src/utils/pngStructure.js` 与 `src/utils/avatarImageError.js`（被 `avatarImage` 引用）、
`web-admin/src/i18n/auditReasons.js`（被 `AuditLogView` 引用）、`src/tests/deploy/helpers/releaseNotesScript.js`（被两个 deploy 套件引用）。
本机跑什么都绿 —— 文件就在盘上；**干净克隆会直接 `MODULE_NOT_FOUND`**。这不是「某条判据写错了」，而是「交付物不完整」，
本地门禁天然看不见：`requireCycles` 只判「解析得到真实文件」，`testTreePurity` 只判「src/tests 下 `*.test.js` 入库」，
而这条缝（**能解析、但没入库**）正好落在两者之间。

新增 `src/tests/ci/moduleTrackingGate.test.js`：扫 src / scripts / migrations / e2e / web-admin/src，
只查**解析得到**的本地说明符（`./` `../` `@/`）——解析不到的留给 `requireCycles`，避免第二份真源；注释先剥（走共享
`helpers/jsCodeOnly`，不另写一份剥离正则，`commentViewSingleSource` 会抓复制品）。
前提自证：实测解析得到的本地引用 **5025** 条，断言 >3000（采集器坏掉时这个数会塌，那时「0 条违规」是假绿）；
反向自证：仓库内造一个未入库夹具喂给 `survey()` 必须被点名，指向已入库目标必须不被点名。
变异：`git rm --cached src/utils/pngStructure.js` ⇒ 红并点名「`avatarImage.js` 引用 `./pngStructure` ⇒ 未入库」；`git add` 还原 ⇒ 4/4 绿。
五个文件已一并 `git add`（此前 `work/` 目录里的报告也按证据目录口径入库）；`git status` 未跟踪条目现为 0。

### 加固：IFS 固定腿改「字面量」+ 行数判据钉 `LC_ALL=C`（2026-10-31）

> 来源：`work/audit-round8-ifs-posix.md`、`work/audit-round9-ifs-literal.md`（两轮对抗性复攻）。

**一、`IFS=$(printf …)` 本身是一条可执行依赖。** 上一轮把三处 od 解析循环的 IFS 固定腿写成
`IFS=$(printf ' \t\n_'); IFS=${IFS%_}`（哨兵是为了绕开命令替换吃掉行尾换行）。但命令替换会把
`printf` 拉进**运行时依赖**：`bash script.sh` 会 source `$BASH_ENV`，那里面定义一个 `printf()`
同名函数就优先于内建。实测（BASH_ENV 里 `printf(){ printf ' '; }`）：capture 的 `od` 腿 IFS 退化
成单空格 ⇒ 行尾 token 连换行被切走 ⇒ `case 0d` 漏计 ⇒ **rc=0、177 B 的 CRLF 文件被重写成 314 B、
CR=0**；`mongoUri.sh` 同条件下含 NUL 的密钥文件被静默放行。

改法：`scripts/mongoUri.sh`（validate / hydrate 两处）与 `scripts/capture-image-digests.sh` 的固定腿
一律改成**单引号字面量跨行**写「换行/制表/空格」三字节：

```sh
  IFS='
	 '
```

没有命令替换、不调用任何命令（bash / dash / msys-sh 实测 IFS 字节均为 `0a 09 20`，与默认 IFS 同集），
BASH_ENV 无从注入；`IFS=$_ifs_saved` 的成对恢复不变。

**二、`mongoUri.sh` 的行数判据漏了 `LC_ALL=C`。** `grep -c '[^[:space:]]'` 的「算不算空白」随
locale 走：同一个只含 U+00A0(NBSP) 的文件，C 下计 1 行、`en_US.UTF-8` / `C.UTF-8` 下计 0 行（被当
空白 ⇒ 报「空文件」）。两行 NBSP 样本更狠：未钉时 `en_US` 下计 1 行 ⇒ **rc=0 放行**（只取第一行），
C 下计 2 行 ⇒ 拒。现在与同文件其它 grep/sed 一样钉死 `LC_ALL=C`，「同一输入同一裁决」不再依赖宿主 locale。

**三、契约用例收紧到「按字节判」并覆盖每一处循环。** `src/tests/imageDigestGate.test.js` 原来只
`toMatch(/IFS=\$(printf/)`，两轮复攻各打穿一次：只删 `_` 哨兵（`IFS=$(printf ' \t\n')`，缺换行）
仍绿、把四行注释掉但文字留着也仍绿（`toMatch` 命中了注释）。现在**先剥注释行**，再逐处（不是只看
第一处）断言：保存行在窗口内、字面量是相邻两行且右值字节集合恰为 `{09,0a,20}`、窗口内不许出现
`IFS=$(…`、保存→字面量→循环的顺序、循环后 <=12 行内成对恢复。第九轮复攻的「诱饵块」形态
（真腿前插一段合规块、真腿退化成 `IFS=' '`）在逐处检查下也变红。

变异矩阵（全部实测）：移出窗口 / `IFS=' '` / 删恢复行 / 少一字节 / 四行注释化 / 回退 `$(printf …)`
／诱饵块 ⇒ 7/7 红；恢复后脚本 sha 逐字节相同。

### 修复：迁移幂等判据只看 collation 不看 key（M-1/M-2）+ 全仓 walk 的并发删除竞态（2026-10-31）

> 来源：`work/audit-round8-compose-migrations.md`、`work/audit-round8-ifs-posix.md` 与 `work/lead/fullrun-4.log` 的四条红复核。

**一、`20260928000000-audit-username-ci-index` 的「已存在就跳过」判据漏比 key。** 只比 collation（locale+strength）
意味着 key 漂移时**静默跳过**：实测同名索引 key 变成 `{username:1}` 或反序 `{timestamp:-1, username:1}` 都被
「collation 一致，跳过」放过，而反序/`caseLevel` 形态让查询退化为 `SORT>COLLSCAN`（20k 条 docs 20000 / keys 0；
100k 条同样从 COLLSCAN（扫描全部文档）变成 IXSCAN（扫描命中块）——**只看方向与扫描量，绝对值随机器与负载浮动**）。同 key 但**名字不同**的索引则让 `createIndex` 直接抛 85
IndexOptionsConflict（实测原文 `Index already exists with a different name: username_1_timestamp_-1`）⇒ 整次
migrate 中断。现在 up() 同时比 key（**带顺序**的逐字段签名）与 collation：漂移则删重建；异名同 key 先删那条
再按声明名重建，收敛到一条。同形态还在另三个迁移（`20260926…` / `20261021…` / `20261101…`），同批处理。

**二、`scripts/check-utf8.js` 的 `walk` 有 readdir→stat 竞态（假红）。** 全量并行跑时
`src/tests/security/gateSelfTest.test.js` 会在仓库根下 `mkdtempSync('.lint-ratchet-selftest-')` 造夹具、用完即删；
同时 `src/tests/docs/deliverablesReferenceIndex.test.js` 正在 `walk` 全仓 —— readdir 拿到名字、stat 之前目录已被删，
整个套件报 `ENOENT … stat '.lint-ratchet-selftest-D0Y6cO'`（`fullrun-4.log` 的那条红）。编码内容一个字节没变。
现在 walk 把「消失」分成两种：**瞬时消失**（并发删/改名，竞态）跳过；**持续缺失**（悬空链接/目录联接，
名字还在、目标已删）报红 `DANGLING_ENTRIES` 并以 exit 1 收场（HEAD 版此时是未捕获 ENOENT 直接崩——
「崩」不是「红」）。区分手段是 stat/readdir 报 ENOENT 后再 `lstat` 一次（不跟随链接）。其余错误
（EACCES/EIO/ELOOP…）照旧上抛，**lstat 复核自己抛错时也上抛**（复核不可用 ≠ 没问题）；把整段吞掉
等于把「看不见」当成「没问题」。扫描面整体缩水另有 `collectScanSet` 的三条判据兜底。
变异证明（矩阵 8 组，每次还原后 sha 不变）：整段吞掉 ⇒ 4 红；只 readdir 腿吞 ⇒ 2 红；lstat 成功也跳过 ⇒ 2 红；
不复核 ⇒ 4 红；只放过 ENOENT ⇒ 2 红。实测端到端：仓库内挂一个悬空目录联接，改动前静默 exit 0，改动后 exit 1 并打印该路径。

**三、`grafana-secret-init` 收进 `observability` profile（D3）。** 默认栈此前会为一个不启动的服务建密钥：
实测默认栈服务数 10→9（只少它），`config --format json` 里 `grafana_admin_password` 与 `grafana-secrets` 卷不再
materialize；`--profile observability` 前后完全一致（11 个）。`deployPolicy.REQUIRED_SECRET_FILES` 仍强制 grafana
口令（登记 D3b，未改）。

**四、临时权限授予的留痕不得被撤销覆写。** 撤销此前把 `decidedBy/decidedAt/decisionReason` 覆盖成撤销者，
批准轨迹消失（实测：撤销后 `decidedBy` 从批准人变撤销者）。现在撤销只写 `revokedBy/revokedByName/revokedAt/
revokeReason`，批准留痕原样保留；撤销/驳回日志补回 `{from,to,wasActive}`；`flow` 里一条恒真的 `toBeTruthy()`
换成对读侧缓存的精确断言（旧断言在同一变异下仍绿）。

### 收口：注释密度棘轮基线更新（2026-10-31）

回归清零后按流程重生成基线：新登记文件含 `reportExportColumns`/`pngStructure`/`avatarImageError`（完整清单见 `eslint.ratchet.json` 的增删行，此处不重复点名），
总量 22482（本轮前工作区快照为 22484，两行来自既有文件压缩；该数字以 `scripts/commentDensity.js` 现算为准）。临时测量副本 `zzTmpMeasurePre.js` 不在清单（早已删除）。
`commentDensityRatchet` 5/5 绿。

### 加固：四处「拿数量当判据」的 shell 闸 → 「真实载荷互补计数 + 独立字节通道」（2026-10-30/31）

> 来源：`work/audit-round4-toolfailopen.md` 与 `work/audit-round5-toolfailopen.md`（两轮对抗性复攻）、
> 收口说明 `work/fix-round4-toolfailopen-r5.md`。第二轮把 fail-open 从 `tr` 搬到 **`wc`**（退出 0、
> 打印 0 ⇒ 两个计数都是 0 ⇒「相等」⇒ 放行；实测 CRLF 的 Dockerfile 被重写成 LF 并钉上 digest、
> UTF-16 密钥文件被吃成「字形相同」的连接串）；同族还有 `tr` 退化成 `cat`（一个字节都不删）、
> `grep -c` 静默空输出（`[ "" -eq 0 ]` 取假分支）、`[ "" -le 0 ]`。第三轮又暴露：**固定串自检
> 本身就是漏洞**——工具「对短输入正常、对真实载荷透传」时自检与相等判据一起被骗过（实测：换行
> 连接串放行、UTF-16 文件被静默改写）。第五轮再下一层：`capture` 的 `od` 手工解析器把行尾 token
> 连换行一起切走 ⇒ 落在 16 字节边界上的 CR 全部漏计（共谋 `tr` 下 CRLF 被静默改写、rc=0）。

第七轮复攻把这条腿做成**可移植**的：`（手写 while 把行尾 token 连换行切走 ⇒ 16 字节边界的 CR 漏计 ⇒
共谋 `tr` 下 CRLF 被静默改写）；第六轮复攻又暴露同一族的环境依赖：`mongoUri.sh`被`source` 时
word splitting 用调用方 IFS，`IFS=' '`+ 两向共谋`tr`⇒ 含 NUL 的密钥文件被接受。两处 od 循环改成
局部`_ifs_saved=$IFS; IFS=（每条腿的失败方向都与「拒绝」一致）：**互补绝对计数**
（允许字节数 + 禁止字节数 == 总字节数；`tr` 不过滤 ⇒ 两边都等于总数 ⇒ 判「检测不可用」）、
**直接数违禁字节**（换行 / NUL / CR 必须为 0 —— 内容相关退化在这条上藏不住）、**`od`逐字节
目视**（不经`tr`/`wc` 的独立字节通道：token 数必须等于总字节数、`0d` 等违禁 token 逐项判定）：

- `scripts/mongoUri.sh::mongo_validate_uri`：`${#_uri}`（shell 内建）交叉 + 互补计数闭合 +
  直接数违禁字节 + `od` token 区间目视（`for … in $var` 解析）。
- `scripts/mongoUri.sh::mongo_hydrate_uri`：`stat -c %s` 与 `wc` 独立交叉、`[ -s ]` 自相矛盾守卫、
  `_n`（行数）形状校验、互补计数闭合 + NUL 直数 + `od` 目视。
- `scripts/capture-image-digests.sh`：同上三腿 + 直接数 CR 字节；`od` 解析用 `for … in $var`
  （第五轮实测：手写 while 对行尾 token 漏计 ⇒ 16 字节边界的 CR 看不见 ⇒ 共谋 `tr` 下 CRLF 被
  静默改写 rc=0；修复后同一夹具「有 7 个 CR」拒绝落笔）。为什么不用 `grep`（第一版就是它）：
  MSYS/Git Bash 的 grep 走文本模式，CRLF 被当成行尾、CR 在匹配前就被吃掉——实测 `LC_ALL=C grep -q
-e "$(printf '\r')"` 对 CRLF 文件返回 1（＝「没有 CR」），那样的所谓独立腿在 Windows 上恒绿。
  `tr`/`wc`/`od` 是字节流、不认行尾，两个平台同一语义。
- `scripts/backup-mongo.sh`：归档字节数先过「非空 + 纯数字」形状校验，再比 `-le 0`。

用例（红→绿→红→绿，逐条变异取证，全部落在上表各条腿上）：`src/tests/deploy/backupUriFile.test.js`
45 条、`src/tests/imageDigestGate.test.js` 62 条（含第五轮新增 3 条：同源共谋 `tr` + CR 全部落在
16 字节边界 ⇒ 必须拒；`od` 桩只吐 3 个 token ⇒ 判「目视不可用」；`od` 对内容说谎 ⇒ 兜底腿仍拒）、
`src/tests/backupScriptGuards.test.js` 11 条。关键变异：摘互补和式 ⇒ 红；摘 NUL 拒绝臂需与 `od`
NUL 臂双摘才红（两臂冗余是设计，单摘时另一臂仍拦）；摘 `capture` 的 `od_cr` 腿 / 直接计数腿 /
token 数腿 ⇒ 各自用例以 rc=0 的 fail-open 复现变红；还原后所有文件 sha256 与改前一致。

> 顺带修正 `src/tests/deploy/backupUriFile.test.js` 的「前提自证：删掉 NUL 闸」用例：它按「第一个 `fi`」
> 定位删除区间，而本轮在它前面插了新腿，冷启动会**删掉半截**、留下悬空的 `_file_nonnull` 引用 ——
> 那正是这条用例自己要防的静默错删。现在按两条 NUL 臂（直接计数 + `od`）各自的 `if` 行成对定位，
> 找不到就抛（判据变了 ⇒ 同步用例），不许静默跳过。

### 修复：权限软删除的「只读墓碑」被写路径绕过（D5，2026-10-30）

> 来源：`work/audit-round3-config-mw.md` 的 D5。

`src/models/Permission.js` 的软删除过滤原本只挂 `/^find/` 与 `countDocuments`，
而模型自己的承诺是「文档永不离开集合、保留期后可复核」——`updateOne`/`updateMany` 一条就能
**就地改掉已删除的行**，`distinct`/`aggregate` 则会把已删除的 code 重新吐出来（审计实测：
`updateOne({_id}, {$set:{name}})` 对已删除文档返回 `modifiedCount: 1`）。

现在把覆盖面扩到 `updateOne`/`updateMany`/`replaceOne`、`distinct`、`estimatedDocumentCount`
与 `aggregate`（管道首部注入 `$match`），并保留两个**显式**放行口子：过滤条件自己写了 `deletedAt`，
或更新文档本身在动 `deletedAt`（软删除/恢复这类状态变更——`permissionService` 的恢复补偿
`updateOne({_id}, {$set:{deletedAt:null}})` 正是这种形态，不能把它吃掉）。
`deleteOne`/`deleteMany` **有意不加**：非测试代码里零调用方，而测试清理与运维删除需要硬删；
把它留给「谁真要在生产硬删已删除的权限」时显式决定（本轮不替未来做决定）。

用例（`src/tests/services/permissionSoftDelete.test.js` 三条）：写路径不命中（活跃行对照命中）、
两条放行口子仍有效、`distinct`/`aggregate` 不泄露。实测变异（撤掉写过滤 + 撤掉 distinct/aggregate 注入）
⇒ 正好两条新用例红（`Expected: 0 / Received: 1`）；还原 ⇒ 10/10 绿。

### 加固：三处「缺 shell 就整组静默跳过」的门禁补上 CI 守卫（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S2 —— 与 `imageDigestGate.test.js:80-89` 的既定先例不一致。

`backupScriptGuards`、`ciProvisionFailurePropagation`、`appEntrypointQueuePermFallback` 三份行为闸都写着
`const group = BASH ? describe : describe.skip`：本机（Windows/MSYS）探不到 POSIX shell 时**整组跳过**。
在本机这是合理的降级，但在 **CI（ubuntu）上探不到 shell 就是探测本身坏了** —— 此时整组零断言的绿
与「这些不变量根本没被验证」是同一件事，而且没人会去数 skipped 的条数。

现在三份文件都补上 `if (!BASH && process.env.CI)` 的守卫：CI 上解析不到 shell ⇒ 直接红（口径同 imageDigestGate 的先例）。
实测（临时让候选表返回空 + `CI=1`）：三份守卫同时红并给出「本文件全部覆盖都是假的」的原因；
恢复候选表后 `CI=1` 下 3 suites / 21 tests 全绿。

### 加固：仓库 shell 脚本的语法闸 + 两处 spawnSync 超时兜底（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S3/S4（疑似）。

- **新增 `src/tests/ci/shellScriptSyntax.test.js`（S4）**：每份**已入库**的 `*.sh` 都要用它
  **shebang 指定的解释器**过一遍 `-n`（`#!/bin/sh` 用 `sh -n`、`#!/usr/bin/env bash` 用 `bash -n`），
  并单独钉住 `docker/app-entrypoint.sh` 必须按 **sh（dash 语义）** 检查，不许被 bash 顶替。
  此前仓库只有 workflow 的 `run:` 块有 `bash -n` 闸，脚本本体一个语法判据都没有 ——
  而 `docker/app-entrypoint.sh` 一旦语法错误，后果是**容器起不来**，要等下一次部署才发现。
  反向自证用**同一个** `checkScript()`：造一份少 `fi` 的脚本必须报红、同目录合法的必须绿、
  没有 shebang 的必须判否（不许静默跳过）。实测把 entrypoint 的收尾 `fi` 去掉 ⇒ 闸红并给出 dash 的报错行号；还原 ⇒ 绿。
- **两处 `spawnSync` 补 `timeout: 30000`（S3）**：`appEntrypointQueuePermFallback` 与
  `ciProvisionFailurePropagation` 的夹具子 shell 卡住时，应当红在断言上（超时 ⇒ `status=null`），
  而不是把整条流水线拖到 CI 超时。

### 修复：「工具在不在」的自证 ≠ 「这一次判据能不能执行」（2026-10-30）

> 来源：`work/audit-round3-toolfailopen.md`（第三轮审计对上一轮修复的**再攻击**）。
> 上一轮给两处字节判据装了「工具缺失 ⇒ 拒绝」的探针，本轮被证明**探针与判据不是同一个调用形态**：
> 探针证明「本机有 tr」，判据需要的是「这一次 tr 真的跑起来了」。两者之间的失败面无人观测。

三个实测反例（第三轮审计给出端到端复现，本轮已逐条用用例钉住）：

1. `scripts/mongoUri.sh` 的「单行纯可打印 ASCII」：探针跑 `tr -d 'a'`（单字符集合），
   判据跑 `tr -d '\041-\176'`（八进制区间集合）。只让后者失败 ⇒ `$(…; printf '~')` 恰好等于 `~` ⇒
   **带换行的连接串 rc=0**，换行会成为 mongodump/mongorestore 配置的第二行。
2. `scripts/mongoUri.sh` 的 NUL 判据：正常值就是 0，与「tr 死了、wc 读空 stdin 打印 0」不可分 ⇒
   UTF-16LE 密钥文件 rc=0（目标库名被改坏）。只有「管道首尾同时死」才偶然拒绝。
3. `scripts/capture-image-digests.sh` 的 CR 判据：探针走**管道输入**，判据走**文件重定向输入** ⇒
   后者失败被读成「没有 CR」⇒ 把 CRLF 的 Dockerfile 重写成 LF 并钉版，**exit 0**。

**改法（两处同一条通则）**：不用探针兜，直接让判据**自己会失败**——改成两个**字节计数相比**，
并先做「非空 + 纯数字」形状校验：

- mongoUri：可打印字节数 == 总字节数（`wc -c` 拿总数；`tr -cd '\041-\176'` 拿可打印数）；
  NUL 判据同理，比的是「非 NUL 字节数 == 总字节数」——**用非 NUL 而不是 NUL 计数**，
  因为后者的正常值就是 0，与工具的失败输出不可分。
- capture-image-digests：非 CR 字节数 == 总字节数。

于是**工具的失败方向与判据的拒绝方向一致**：tr 任何形态失败 ⇒ 计数变成 0（或形状非法）⇒ 与总数不等 ⇒
拒绝。空值两边都是 0，由后序判据（scheme / 空文件）给出准确原因。

**证据**：`backupUriFile.test.js` 34/34、`imageDigestGate.test.js` 56/56、
`backupScriptGuards.test.js` + `backupFailureArtifactHygiene.test.js` 29/29；
新增 5 条用例在**回退脚本**后恰好全红（探针形态失败 / NUL 形态失败 / 文件重定向形态失败 / 两种「无 tr」形态），
改回后全绿。桩是否真的生效由用例自己观测（打印 `tr=` 的解析结果，并要求落在桩目录里）。

### 修复：跨平台夹具 `exec` 的两种失效形态（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的「疑似（高）」。`src/tests/helpers/stubPath.js` 把「PATH 桩目录」
> 收口到孩子 shell 内部（MSYS 启动时会前置 `/mingw64/bin:/usr/bin`，从 Node 侧改 `env.PATH` 无效），
> 但它的 `exec` 形态选错了两次，两次都不会让套件「变红得有意义」。

- **`exec "$@"`（直接 exec 脚本文件）依赖可执行位**：本仓 `scripts/*.sh` 在 git 里全是 `100644`。
  MSYS 下照样能跑（shell 自己读文件），Linux 上 `execve` 直接 `EACCES`，非交互 shell 随即退出 ⇒
  两个备份套件会在 CI 上整片**假红**。
- **改成 `exec "$0"` 会静默毁掉夹具**：Windows 上 `$0` 是 `…/Git/bin/bash.exe`，重起一个 Windows 进程
  让 MSYS 再走一遍启动注入，`/mingw64/bin:/usr/bin` 被塞回 PATH 最前 ⇒ 桩目录失效。实测 PATH 首项变成
  `/mingw64/bin`、`date` 命中 `/usr/bin/date`，用例报出真日期（`fire-safety-backup-20261030-205053.gz`）。
  这比假红更坏：套件是红的，但红在夹具，而夹具失效本身不报警。
- **最终写法 `exec bash "$@"`**：按 PATH 解析到 MSYS 本体，不重走启动注入、走解释器与可执行位无关，
  两个平台语义一致。实测改后 `backupScriptGuards`（10 例）+ `backupFailureArtifactHygiene`（19 例）全绿，
  含那条「同名归档存在时拒绝覆盖」的确定性时间戳用例。

### 加固：第二轮逐行审计的「闸没有判别力」收口（2026-10-30）

> 来源：`work/audit-round2-infra.md`（132 行，逐条 file:line + 真跑复现）。这些缺陷的共同形状不是
> 「代码写错」，而是**闸自己不会红**：注释里声明的不变量，没有任何一条判据能单独钉住它。

- **逐条 `&&` 无人守**：`appEntrypointQueuePermFallback.test.js` 的夹具只有「整类命令全失败」一档，
  于是 `docker/app-entrypoint.sh:135` 的 `&&` 删掉后 4/4 仍绿（链上第一条就断，中间失败跑不到）。
  夹具改为「第 N 次调用失败，N=1..8」逐条注入，并加一条反向对照：把 `&&` 换成分号的**历史形态**
  喂进同一夹具，第 2 条失败必须被静默吞掉（证明本闸抓得住它）。
- **正则判别力为零**：`hotUpgradeQueueContract.test.js:135` 的 `/…(?: &&)?$/m` 对「有/没有 `&&`」都真。
  改成必需的 ` &&# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

，并补一条前提自证：整块 8 条命令之间必须恰好 7 个 `&&`。

- **`test -n "$MONGOD"` 无判据**：`.github/workflows/ci.yml:137/:508` 的这行删掉后整族仍绿，
  而「provision 退出 0 但什么都没打印」正是该步骤自述的头号危害（空值让 MongoBinary 回落到
  未经仓库 SHA-256 锚的下载）。补「exit 0 + 空输出 ⇒ 步骤必须红且不写空值」用例，
  并从**抽取到的真实步骤体**删掉那一行做前世版自证（不抄副本）。
- **「失败即放行」语义未钉**：`app-entrypoint.sh:148` 的 `return 0` 换成 `exit 1`（容器起不来）闸仍绿。
  逐条注入的用例现在同时断言 `rc=0`：失败必须告警放行，而不是把容器弄得起不来。
- **探针假阳性**：`helpers/posixShell.js` 的可用性判据用 `includes`，而 MSYS 的 `echo.exe` 会把参数
  原样回显（标记于是「包含」在 stdout 里）⇒ 一个根本不是 shell 的可执行文件被判为可用。
  改成**严格相等**（标记必须独占 stdout），并补一条用「只回显 argv」的可执行文件做的反向对照。
- 实测（Windows / Git Bash，非 Linux 权威）：入口脚本变异 `&&` → `; true &&`（`&&` 计数不变、语义已断）
  ⇒ 用例红在「第 1 条失败却被吞」；还原 ⇒ 绿。`hotUpgradeQueueContract` 删掉一个 `&&` ⇒ 红；还原 ⇒ 绿。
  `posixShell` 探针退回 `includes` ⇒ 新用例红；还原 ⇒ 7/7 绿。

### 修复：两处「工具缺失即静默放行」的字节级判据改为失败关（2026-10-30）

> 来源：第一轮逐行审计的 A6（运维脚本族的 fail-open）。两处的形状相同：判据由外部工具执行，
> 而工具失败时命令替换得到的是**空串**，与「值/文件本来就干净」不可分。

- `scripts/mongoUri.sh` 的 `mongo_validate_uri`：「单行纯可打印 ASCII」判据由 `tr` 执行。实测（PATH 里没有 `tr`）
  带真换行的连接串照样 rc=0 —— 那个换行会被写成 `mongodump`/`mongorestore` 配置文件（0600）的第二行，
  正是这条判据存在的理由（同文件顶部 2026-10-03 的取证）。现在先让字节通道**自证**：`'ab'` 删掉 `'a'` 必须恰好
  剩下 `'b'`；量不到就拒绝放行（fail-closed）。
- `scripts/capture-image-digests.sh` 的 CR 检测（`tr -dc '\r' | wc -c`）同理：`wc` 照旧输出 `0`，与「文件里没有 CR」
  不可分 ⇒ 检测被整体跳过，MSYS 的 `sed`/`gawk` 顺手吃掉 CR，脚本会把 CRLF 静默改写成 LF 并报成功。
  现在先用一个已知含 CR 的输入证明通道是活的，量不到即拒绝落笔（与同脚本 :47 的 `docker` 存在性检查同一口径）。
- 用例：`src/tests/deploy/backupUriFile.test.js` 新增 3 条（含「tr 在位」的前提自证与「无法校验即拒绝」），
  `src/tests/imageDigestGate.test.js` 新增 1 条（含「同一夹具在真 tr 下必须成功」的反向前提）。
  两处守卫都以「临时摘掉判据 ⇒ 用例必须红」证伪过（实测 2 红 / 1 红），再还原为绿。
- 同批：`src/tests/middleware/avatarUnmatchedSurfaceGuard.test.js` 的固定 30ms 睡眠换成条件等待
  （`helpers/waitFor` / `waitForStable`），修掉 `noFixedSleepRatchet` 的回退。

### 新增：临时权限授予与定期复核（C-08 / C-09）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 C-08 / C-09 控制项实现；决策与取舍见 `docs/adr/ADR-012-临时权限授予与定期复核.md`。

- **端点**：`GET /api/permissions/grants`（列表，按 status/userId 过滤）、`GET /api/permissions/grants/review`（复核汇总 + 超期清单）、`POST /api/permissions/grants`（申请）、`POST /api/permissions/grants/:id/{approve,reject,revoke}`。权限码 `privilege:read` / `privilege:grant` / `privilege:approve` 已进目录与菜单。
- **不变量**：到期在**读取路径**判定（`status==='active' && expiresAt > now`），后台 `expireDue` 只收敛状态；申请人不得自审；高敏模块（user/role/permission/security/system/privilege）的码需 2 名不同审批人；审批人必须自持被授予的每个码；每次状态变更都失效目标用户权限缓存（钩子缺失时抛错，fail-closed）。
- **数据**：新集合 `PrivilegeGrant`（`models/PrivilegeGrant.js`），审批链以 `{by,name,at}` 快照落库，终态记录不删除（审计可回看）；索引 `{userId,status,expiresAt}` 与 `{status,expiresAt,createdAt}`。
- **审计**：新增 action `permission_grants`、`permission_grants_review`、`permission_grants_approve`、`permission_grants_reject`、`permission_grants_revoke`（category 仍为 `permission`，见 ADR-012「为什么不新开 privilege 分类」）；派生动作由 `/api/permissions/grants` 前缀自然得出，无手工登记路径。
- **运维**：`scripts/access-review.js`（默认输出 JSON 汇总；`--expire` 收敛过期状态；`--fail-on-overdue` 退出码 1 可挂 CI）+ `deployment/systemd/fsms-access-review.{service,timer}` 每小时巡检。
- **用例**：`src/tests/services/privilegeGrantFlow.test.js`（21 例规则：到期失效、双人复核、自审/无码阻断、并发签批、驳回与撤销的状态机单向、复核登记、服务层入参兜底、被授权账户不可用、权限判定与缓存失效两处钩子缺失时 fail-closed）、`src/tests/routes/privilegeGrantEndpoints.test.js`（7 例：鉴权、校验链、全链路、双人复核、自审阻断、驳回端点、审计派生 action 入缓冲）。

- **覆盖率门槛**：`services/privilegeGrantService.js`、`services/accessReviewService.js`、`controllers/privilegeController.js`、`constants/privilegeGrant.js` 在 `jest.config.js` 单独设阈值（取「实测 −5pt(分支) / −3pt(函数)」，向下取整），不并入 global 均值——这几个模块退化时的表现是安全结论错误，不是报错。同批拆出的 `services/privilegeGrantHooks.js`（两个外部钩子，未注册即抛）与 `services/privilegeGrantValidation.js`（`grantError` 与有效期/权限码归一的单一出口）也各带阈值，拆分的动因是 `max-lines` 棘轮（服务本体已越过 300 行），语义与导出面逐字不变。
- **Web 端入口**：`web-admin/src/views/PrivilegeGrantView.vue`（菜单 `/system/privilege-grants`，路由 `meta.permission = privilege:read`）——状态筛选（默认「待审批」）、复核汇总五计数、申请表单（权限码逗号/空格混排解析、有效期 1-168 小时本地校验）、签批/驳回/撤销三条决定链路；按钮按 `privilege:grant|approve` 门控（与后端 `checkPermission` 同码），高敏提交提示显式给出「还需几人签批」。用例 `web-admin/src/tests/views/privilegeGrantView.test.js`（34 例，分支覆盖率 90/90）。
- **未落地（如实申报）**：堡垒机/跳板机与 JIT 会话录屏（C-09 的另一半）尚未实现——「谁能拿到高敏码」已可控可追会过期，但「拿到之后在什么通道上操作」仍由操作系统与运维流程保证。

### 新增：部署面配置漂移检测（M-05）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 M-05 控制项实现。

- **脚本**：`scripts/config-drift-check.js`，把 compose 的容器安全标志（`read_only`/`cap_drop`/`security_opt`/`user`/`tmpfs`/`networks`/内存上限…）、Dockerfile 的 `USER` 与 `HEALTHCHECK`、nginx 模板的 TLS 与安全响应头、`.env.example` 的安全相关键**逐项摘要**（sha256 前 16 位），与 `deployment/config-drift-baseline.json` 对账。
- **输出纪律**：只打印条目名与 `ADDED/REMOVED/CHANGED`，**不打印取值**——配置模板里可能夹带密钥样例，回显会把基线本身变成泄露面。`--json` 供机器消费，`--update` 重写基线（须与变更同轮提交）。
- **退出码**：0 无漂移、1 有漂移、2 输入不可解析或基线缺失（宁可报 2 也不给空账面）。
- **边界（如实申报）**：检的是**仓库内**的配置面，即漂移被引入的地方；不读 `process.env`，因此不能替代「运行时配置与基线对账」（后者由启动期断言与 `config/validate.js` 负责）。
- **用例**：`src/tests/scripts/configDriftCheck.test.js`（5 例：抽面有效、无关项不入账且取值不落明文、改值/删项/加项各自被识别、仓库基线不撒谎、CLI 退出码与 `--json` 契约）。

### 新增：用户头像上传（2026-10-30）

> 依据 `deliverables/头像上传功能-计划报告-2026-10-30.md` 评审后的 v2 修订实现。

- **端点**：`PUT /api/auth/avatar`（本人上传/替换，JSON data URI）、`DELETE /api/auth/avatar`
  （本人移除，幂等）、`GET /api/avatars/:userId?v=<hash16>`（本人直通；他人需 `user:read`
  且通过用户数据范围校验，与 `GET /api/users/:id` 同一把尺）。
- **存储**：新集合 `UserAvatar`（`_id = userId`，1:1），图片二进制以 Base64 经 `encryptPii`
  v2（AAD 绑定 `{subjectId, field:'data'}`）加密落库；`data` 为 `select:false`，读取时解密后
  复核 magic bytes 与 SHA-256，防篡改/错配。不落磁盘卷（容器 `read_only: true`）。
- **校验**：仅 JPEG/PNG，原始上限 256 KB，16–1024 px 且 ≤1 MP；拒绝 APNG 与带 EXIF/文本
  元数据的图片（不做"服务端剥离"——剥离需解析全部段，直接拒绝边界更小）。
- **一致性**：上传/移除在事务内同时写 `UserAvatar` 与 `User.avatar`；`PUT /api/auth/profile`
  与 `PUT /api/users/:id` 的 `avatar: ''` 同事务删除记录，避免"指针清了、图还能拉"。
  删号/批量删/匿名化级联删除头像记录。
- **D3 收口**：资料更新只接受**服务端为目标用户生成**的 `/api/avatars/<id>?v=<hash16>`；
  外部 URL / 相对路径 / data URI 一律 400（data URI 会绕过上传校验、加密与尺寸限制）。
- **审计与限流**：新增 action `auth_avatar`（写）/ `avatar_view`（读路由派生，读默认豁免）；
  审计体对头像 data URI 打码为 `***`（窄键规则，不并进全局敏感键子串名单）。
  读路径独立限流桶：预认证 IP 600/15min、认证后用户 1200/15min；响应带
  `ETag` + `Cache-Control: private, no-cache` + `Vary: Cookie`，命中 `If-None-Match` 返回 304。
- **前端**：新增 `UserAvatar.vue`（失败回退首字母）与 `utils/avatarImage.js`
  （中心方形裁切 + 512×512 JPEG q0.85，超 400000 字符自动降质/降尺寸）；
  个人资料页提供更换/移除入口，顶栏、欢迎卡、用户列表统一改用该组件。
- **复核修复（同日）**：图片校验改为"结构解析到文件尾"——JPEG 必须扫描到 EOI 且
  EOI 为最后一个标记，PNG 必须存在 IEND 且 IEND 为最后一个 chunk（另要求至少一个
  `IDAT`）；EOI/IEND 之后夹带 HTML/ZIP/自定义数据一律拒绝，并补回归用例。
  `useravatars.data` 同时纳入 `scripts/migrate-pii-encryption.js` 的 `PII_TARGETS` 与
  `deployment/secret-rotation.md`、ADR-003 的 PII 清单——否则轮换 `AES_SECRET_KEY`
  后头像密文无法解密。头像读取响应另显式下发 `X-Content-Type-Options: nosniff` 与
  `Content-Security-Policy: default-src 'none'; sandbox`，即使直接导航到图片 URL
  也不会把 polyglot 响应渲染成可执行文档。
- **夹带面再收口（同日）**：段/chunk 判定由"黑名单"改为**白名单**——黑名单漏一个
  APPn/chunk 就是一条夹带通道。JPEG 只放行 APP0（标准 14 字节 JFIF，带缩略图即拒）、
  APP2（单段完整 ICC_PROFILE：序号/总数为 1、声明长度与实际一致、profile 含 `acsp`
  签名）、APP14（定长 12 字节 Adobe 头）、DQT/DHT/DAC/DRI/SOF/SOS；其余 APPn 一律
  `JPEG_UNSUPPORTED_SEGMENT`。
  PNG 只放行 IHDR/PLTE/IDAT/IEND 与 sRGB/gAMA/cHRM/pHYs/sBIT/bKGD/tRNS/acTL，且定长
  chunk 的长度必须精确，其余（iCCP/sPLT/hIST/私有 chunk）一律 `PNG_UNSUPPORTED_CHUNK`。
  Chromium canvas 与 System.Drawing 的真实编码产物（JPEG 带 ICC APP2、PNG 带
  sRGB/gAMA/pHYs）实测全部通过。同时收紧边界：空 `IDAT`、重复 `IHDR`、扫描数据为空
  的 JPEG 一律拒——否则会存下"结构自洽但解不开"的坏头像。
- **特殊情况收口（同日）**：白名单只挡"夹带"，挡不住"结构自洽但解不开"，补齐四处语义判据——
  ① PNG `IHDR` 的位深/色型必须落在规范表 11.1 的合法组合内，压缩法/滤波法必须为 0（否则
  `bitDepth=3`、`colorType=7`、`compression=99` 这类头能过白名单）；② `IDAT` 必须是真能解压的
  zlib 流，且解压字节数**恰好**等于声明尺寸的原始行字节数——只查结构会放过解压炸弹（实测
  203 KB 的 PNG 声明 16×16、`IDAT` 解出 200 MB）；`maxOutputLength` 让超限在解压过程中中断，
  另核对 `engine.bytesWritten` 与 `IDAT` 总长，堵住"流尾巴夹带未消费字节"；③ 隔行（Adam7）
  一律 `PNG_INTERLACE_UNSUPPORTED`——本仓合法流量全是 canvas 重编码产物（`interlace` 恒 0），
  而 Adam7 的行布局无法用一个定长字节数核对，放行等于给炸弹留后门；④ 调色板图必须有
  `PLTE` 且在 `IDAT` 之前、长度是 3 的倍数，JPEG `SOF` 的 `Nf` 必须 1–4 且与段长 `2+6+3Nf`
  自洽（`Nf=0` 的帧头解不出一个像素）。
  同轮把 PNG 结构解析拆到 `utils/pngStructure.js`、错误类型拆到 `utils/avatarImageError.js`，
  避免 `utils/avatarImage.js` 撞 `max-lines` 棘轮（注释净增 0 行）。
  实测最坏情况成本：1024×1024 PNG 7.2 ms/次、3.8 千段 JPEG 2.7 ms/次，256 KB 上限不变。
  - **结构自洽性再收口（同日）**：把“白名单里的每个结构件都必须真的自洽”补齐——
    PNG 逐 chunk 核对 CRC（否则整张图除了签名外每个字节都能被改写而无人发现），
    `IDAT` 之后除 `IEND` 不得再有任何 chunk，同一 chunk 不得重复（`PLTE`/`tRNS`/`bKGD`/
    `sBIT`/`sRGB`/`gAMA`/`cHRM`/`pHYs`/`acTL` 各限一次），变量长度 chunk 的长度按色型定值
    （`sBIT`/`bKGD`/`tRNS` 各有表，`tRNS` 对调色板图限 1–256），灰度图（`colorType` 0/4）
    不允许 `PLTE`；JPEG 的 `DQT`/`DHT`/`SOS` 长度必须被段内表结构整除（`Pq/Tq`+64|128、
    `Tc/Th`+16+符号和、`6+2Nf`）——不校验长度时这三种段就是“合法段名 + 任意字节”的通道。
    变异测试实测：PNG 逐字节翻位 3 种掩码 × 96 字节全数被拒，JPEG 197 字节全数被拒，
    2764 例变异（翻位/截断/插入）无一崩溃。
    真实编码器产物仍全通过：Chromium canvas 的 12 段 `IDAT` PNG、带 alpha 的 PNG、
    512×512 JPEG q0.85，以及 System.Drawing 的 RGB/ARGB/8 位调色板 PNG 与 JPEG。
    成本重测（含 CRC 与全部语义校验）：1024×1024 RGBA PNG 3.7 ms/次、21333 chunk 洪水
    1.1 ms/次、3711 段 DQT 洪水 1.8 ms/次、1039 段 `IDAT` 1.7 ms/次，256 KB 上限不变。

### 安全改造：账号救济 / 删除匿名化 / 异地备份 / 时钟基线（2026-10-30）

> 依据 `deliverables/安全改造待办-2026-10-30.md`。按用户明确要求，**不实施强制 MFA（P1-1）**：
> MFA 能力保持现状，管理员强制开关不启用，文档口径同步改为「能力具备、未强制」。

- **P1-2 账号救济（管理员轨）**：新增 `PUT /api/security/users/:userId/password/reset`，
  权限 `user:reset_password` + 二次验证 + 数据范围/层级/内置超管保护；生成一次性临时口令
  （≥12 位、四类字符），`tokenVersion++` + 吊销全部会话 + `mustChangePassword=true`，
  审计 `admin_reset_password`（临时口令不入审计/日志）。首次登录只放行改密/me/logout，
  改密完成清标记并审计 `password_force_changed`。内部系统无邮件通道，自助找回轨不做。
- **P1-3 删除改匿名化**：单删/批量删除改走 `userService.anonymizeById/anonymizeMany`，
  保留 `_id/username` 维持审计引用，抹除 realName/phone/email/avatar 并置 inactive，
  释放进行中指派，审计 `user_anonymized`；硬删除只保留建号回滚与测试夹具。
- **P1-4 异地备份**：`deployPolicy.checkBackupOffsite` 在 `DEPLOY_ENFORCE_OFFSITE=true`
  或 `NODE_ENV=production` 时要求 `BACKUP_OFFSITE_CMD/DIR`；`BACKUP_REQUIRE_OFFSITE=true`
  使备份脚本缺配置即失败。补 gpg 密钥轮换、逻辑恢复演练记录模板与生产部署清单。
- **P1-5 时钟基线**：新增 `scripts/check-clock-sync.js`（timedatectl/chrony，偏移阈值可配，
  判不了退出 2）、`deployment/systemd/chrony.conf.example` 与 `deployment/clock-sync.md`；
  self-hosted/SSH 部署在正式发布前调用，dry-run 跳过。
- **审计与前端**：新增 action `admin_reset_password`/`password_force_changed`/`user_anonymized`/
  `security_users_password_reset`，中英文标签同步；登录响应与 `/auth/me` 下发
  `mustChangePassword`，前端登录后直达个人资料页并由路由守卫收敛，用户删除提示改为
  「已注销并匿名化」。

### 新增：应用内一键蓝绿升级（2026-10-30）

> 目标：把「发版」从「SSH 上去敲命令」变成「应用里点一次按钮」，同时不让应用容器
> 拿到宿主的 docker / nginx 控制面——那条路等于把容器逃逸做成常驻攻击面。

- **契约：文件队列 + 双向重校验**。应用只往共享队列目录（`UPGRADE_QUEUE_DIR`，compose
  以 bind mount 与宿主共享）写一份 **HMAC 签名**的请求文件，宿主机上的
  `scripts/hotUpgradeAgent.js`（systemd timer）重新校验摘要与仓库白名单后才执行
  `scripts/hotUpgrade.js`。应用侧的校验只是输入错误的前置拒绝，不是安全边界本身。
- **镜像必须 digest 钉扎**：只接受 `registry/repo@sha256:<64hex>`，tag 一律拒绝
  （tag 可被覆盖，审计里记的版本会与线上跑的不是一回事）；仓库前缀须命中
  `HOT_UPGRADE_REGISTRY_ALLOWLIST`，**空白名单 = 全拒**（fail-closed，不是全放）。
- **新端点**：`GET /api/security/upgrade`（构建信息 + 就绪判据逐条原因 + 最近任务）、
  `GET /api/security/upgrade/jobs/{jobId}`、`POST /api/security/upgrade/requests`
  （路由层 `security:config` + 函数内唯一超管 `*:*` + 二次验证凭据 / `X-Reauth-Ticket`）。
  三条路径已进 `src/docs/generate.js` 与产物，`openapiSync` 双向对账。
- **审计先落盘再回 202**：`upgrade_triggered`（`riskLevel: high`，含 jobId / 镜像 / 来源 IP）
  走 `recordDurably`；失败路径不设 `skipGlobalAudit`，由全局审计记录这次尝试。
- **队列读写加固**：请求文件 `0600`（随机临时名 + `wx` 打开 + fsync + rename，
  避免可预测临时名被符号链接劫持）、只读侧单 fd 读取（`O_NOFOLLOW`）、心跳缺 `ready`
  或时钟回拨一律判未就绪。
- **前端**：`AboutView` 版本卡 + `UpgradeDialog`（镜像地址、二次验证、进度步骤），
  中英文案齐备；`utils/api.js` 增加对应调用。
- **运维面**：`deployment/systemd/{fsms-hot-upgrade-agent.service,.timer}` 与
  `hot-upgrade.env.example`；`deployment/hot-upgrade.md` 第 3 节补「应用内一键升级」流程；
  `deployment/secret-rotation.md` 把 `HMAC_SECRET` 的影响面从「五个消费点」更新为**六个**
  （第 6 个是升级请求签名：换钥后只让在途请求被拒，重发即可，既无迁移手段也不需要迁移）。
- **门禁同步登记**：`.env.example` 补 `UPGRADE_QUEUE_DIR`；`services/upgradeService.js`
  的 `TERMINAL_STATES/ACTIVE_STATES` 进单进程豁免表（静态字面量词表，无跨进程语义）；
  日期解析收口到 `utils/helpers.toEpochMs`（裸 `Date.parse` 只允许一处）；
  `controllers/securityController/upgrade.js#triggerUpgrade` 进可靠审计登记表；
  升级错误码改成逐码字面量发出（动态查表会让五个已注册的码退化成死码）。
- **默认关闭**：`UPGRADE_ENABLED=false` 时概览仍可读（按钮不可用并给出原因），
  POST 返回 `UPGRADE_DISABLED`。
- **对外命名**：应用内入口统一称「一键升级」（原「一键热升级」）——弹窗标题、不可用/白名单
  错误文案（中英）、接口兜底 message 与 OpenAPI 摘要同步去「热」字，与「蓝绿切换」的语义对齐。

### 加固：升级链路的第二轮逐行审计收口（2026-10-30）

> 依据多子代理逐行审计报告（部署/脚本/后端/前端/门禁五路）。这一轮**不新增能力**，
> 只把「升级看起来成功、实际没成」与「把权限收紧做成功能失效」两类形态从链路上消掉。

- **队列属主矩阵**（`docker/app-entrypoint.sh`）：应用只写 `requests/`、只读 `status/processing/`。
  原先一律 `chown nodejs` 让被攻陷的应用可以删 `processing/.agent.lock`（升级永久显示进行中）、
  伪造 `status/<id>` 为 `succeeded`（界面假成功、请求被丢弃）、清空 `rejected/`（验签失败留证消失）。
  现改为 `requests=nodejs:nodejs 0700`、`status/processing=root:nodejs 0750`、`rejected=root:root 0700`；
  顺序固定为「收回 root → chmod → 交出属主」（`cap_drop: ALL` 且不补 `FOWNER`，对已属 nodejs 的
  目录 chmod 必然 EPERM，而入口是 `set -eu`——第二次启动/app-green/一次性迁移容器都会因此起不来）。
  另拒绝对 `/`、`/etc` 等系统目录改属主，`find -xdev` 不跨文件系统、不跟随符号链接。
- **蓝绿互不踩**：`app-green` 显式 `AUDIT_WAL_PATH=/app/logs/audit-buffer.green.wal`——两色共用
  `app-logs` 卷时，按库名派生的 WAL 会被两个进程同时追加，而 WAL 的全部价值是崩溃重放，
  双写者让「谁写的、该不该重放」不可判定（重复插入 → 哈希链分叉）。
- **CI 的 hot 分支补 `--apply`**：此前直接调 `hotUpgrade.js` 而未加 `--apply`，脚本按设计走演练
  分支并**以 2 退出**——流水线会「成功打印了计划」，线上什么都没变。现两条模式（本地/SSH）
  都显式在 `--apply` 与 `--dry-run` 之间二选一。
- **布尔旗标严格解析**（`scripts/hotUpgradePolicy.js`）：`--apply=false` 此前被当成「出现过就是真」，
  模板里写 `--apply=${{ inputs.apply }}` 且值为 false 时会真的开始切流。现在只接受 true/false（含 1/0、yes/no），
  其他值报错而不是猜。
- **代理锁的 pid 复用**（`scripts/hotUpgradeQueue.js`）：锁新增 `/proc/<pid>/stat` 的启动时刻与 3h 锁龄上限，
  空锁文件/损坏锁/pid 被复用都能接管；此前只判 `kill(pid,0)`，一个恰好复用旧 pid 的无关进程会让按钮
  永远显示「另一个升级正在进行中」。
- **只读侧单 fd**：`readJsonFile` 改为 `openSync(O_NOFOLLOW)` + `fstat` + 从 fd 读——原先 `statSync` 后按路径
  `readFileSync` 是两次解析，应用对 `requests/` 可写时可换成符号链接，让 root 代理读到任意宿主文件。
- **写入与观测**：`status/processing` 文件 `0640`（属组＝队列目录属组，应用可读、other 不可读）；
  `hotUpgradeJob` 记录子进程 pid 失败时 `SIGTERM` 回收进程并如实报错（原先会留下无人跟踪的升级进程）；
  起备色补 `--no-build`（compose 里 app 段带 `build:`，否则会在部署机上重建当前源码，线上跑的就不是请求里的 digest）；
  观察期未通过**回滚成功后才**停新色（回滚失败分支不停，否则可能把仍在接流量的容器杀掉）。
- **监控**：`prometheus.yml` 同时抓 `app:3000` 与 `app-green:3000`；`BackendDown` 改为
  `sum(up{job="xf-app"}) == 0`——逐实例判会让平时根本没起的备色永久点亮告警，而永远在响的告警等于没有告警。
- **systemd 加固**：代理单元补 `NoNewPrivileges/Umask=0077/PrivateTmp/ProtectHome/ProtectSystem=full`
  与 `ReadWritePaths`；`hot-upgrade.env.example` 补 `MONGODB_URI_FILE`/`BACKUP_ENCRYPTION`/
  `BACKUP_GPG_RECIPIENT`——代理的环境**只来自该文件**，缺任一项时第一个升级请求都会停在备份步。
- **门禁同步**：`LAZY_SCC` 登记 `config/jwtRotation.js`（真实惰性环）、单进程豁免表登记
  `middleware/auth.js` 的 `PASSWORD_CHANGE_ALLOWED_PATHS`（静态只读 Set）；三处环境相关的用例判据收窄到
  「本子系统自己的那几条文案」（ACL 噪声另有专门用例钉住），而不是靠机器上有没有 `USERNAME`/`bash` 决定红绿。

### CI 修复：锁文件锚未重算 + 三处用例随实现漂移（2026-10-30）

> 现象：`CI` 从 `6415fd6` 起红，且**只红在第一个作业** `dependency-policy`——
> 后面 `test`/`e2e`/`e2e-browser`/`build` 全部 `needs: dependency-policy`，
> 一个闸失败就把整条流水线的可见性一起挡掉。本地逐闸复跑后发现：闸背后还压着
> 三处**与依赖无关**的红（`test` 作业一旦被放行就会立刻暴露），故一并修。

- **锁文件锚（`dependency-policy` 唯一的红）**：`6415fd6` 把 `vue-i18n` 从
  `9.14.5` 升到 `11.4.16`（v9/v10 已被上游标记 deprecated 并停止维护），
  `web-admin/package.json` 与 `package-lock.json` 都改了，但
  `deployment/lockfile-anchor.json` 没重算 ⇒ `LOCKFILE_ANCHOR_MISMATCH`。
  处理口径按锚文件自身的提示走：先人工复核锁文件 diff（仅 `vue-i18n` /
  `@intlify/*` 一族，`resolved` 全为 registry.npmjs.org、integrity 随版本同步变更，
  无夹带），再 `npm ci --dry-run` 确认锁文件与 package.json 自洽，最后
  `node scripts/check-lockfile-integrity.js --update`。**不是**回退依赖：
  v9 已停止维护，回退等于把 EOL 依赖留在发布基线上。
- **compose 告警配置链（`test`）**：`894f1de` 的 F-15 把 alertmanager 的配置挂载
  从「直接 bind mount 宿主文件」改成「一次性 `alertmanager-config-init` 复制进
  命名卷并 chown 65534，alertmanager 只读消费该卷」（宿主 0600 文件容器内 nobody
  读不到）。`alertingConfig.test.js` 与 `alertmanagerComposeGate.test.js` 仍断言
  旧的 bind mount 形状。改为钉新链条的三段——校验容器、初始化容器都取同一个
  `${ALERTMANAGER_CONFIG_PATH:-…}`，运行侧只消费 `alertmanager-config` 卷且
  `depends_on` 初始化容器 `service_completed_successfully`。「校验的是 A、跑的是 B」
  这条原始不变量原样保留，只是中间多了一跳。
- **单进程依赖清单（`test`）**：`6415fd6` 新增的 `controllers/ipListWriteGuards.js`
  带模块级 `Set`（`IP_LIST_WRITE_FIELDS`，写路径字段白名单），未进
  `SINGLE_PROCESS_DEPENDENCIES` 也未进豁免表。按既有口径补豁免条目（静态字面量
  词表、只读、无跨进程语义），与 `routes/wellKnownRoutes.js` 的 `CLIENT_ERROR_KINDS`
  同族——**不是**登记进清单：登记会让启动期对运维误报"多实例下这条会失效"。
- **NODE_ENV 未设置（`test`）**：`93519ae` 起 `validate.js` 对「`NODE_ENV` 键根本
  不存在」直接拒绝启动（缺失时无法区分"开发机裸跑"与"生产容器漏配"，按开发语义
  放行等于弱密钥/Host/Redis/TLS 四类校验一起静默跳过），README 部署清单与
  `.env.example` 已同口径。`nodeEnvGateFailsClosed.test.js` 仍把「未设置」放在
  「允许跳过生产校验」那张表里。改为单列一条：未设置 ⇒ 拒绝启动；同时保留
  `normalizeNodeEnv()` 对 `undefined` 仍返回 `development`（其他模块依赖这个归一值，
  改它会波及一圈无关判据）——两件事分开钉。
- **WS 握手用例夹具（`test`）**：`93519ae` 让握手期 IP 判定在「取不到客户端地址」
  时 fail-closed（`无法验证网络来源`），`#9` 又加了按来源 IP 的未认证连接准入表。
  两处夹具因此失真：`wsFlow.test.js` 的假 socket 有 `handshake` 但**没有**
  `address`，`tokenPurposeAndConsumers.test.js` 的假 socket 连 `handshake` 都没有
  ⇒ 认证分支一条都跑不到（表现为 8s 超时 / 断言拿到「无法验证网络来源」）。
  补 `address: '127.0.0.1'`；`wsFlow` 的假服务实例补
  `unauthConnectionsByIp = new Map()`（真实构造器在 `index.js:66` 初始化）；
  `tokenPurpose` 补桩 `models/IPBlacklist`（该套件没有真实 DB，不桩就会以
  「网络黑名单校验暂不可用」fail-closed）。被测判据一条没放松。

> **本机复跑的两处"红"不是 CI 红，未改代码**：`backupEncryptionContract` /
> `backupTransport` 在本机失败的原因是本会话工具链注入的 `rm` 垫片拒绝
> Windows 盘符路径（`[safe-delete][SAFE_DELETE_INVALID_PATH] embedded drive prefix`），
> 把 `safe-bin` 从 `PATH` 移出后同一脚本行为正确（半成品归档确实被删）。
> CI 是 ubuntu + 真 coreutils `rm`，不受影响。

---

### 修复（2026-10-28 · dev 代理覆盖上游 X-Forwarded-For，审计与限流只见内网地址）

> 现象：经外层反代/预览网关访问时，后端审计与限流记录的客户端 IP 恒为
> `127.0.0.1`/`::1`，真实地址丢失。

- 根因：`web-admin/vite.config.js` 的 dev 代理无条件用 `req.socket.remoteAddress`
  覆盖 `X-Forwarded-For`。外层代理已经把真实 IP 写进该头，而它连 Vite 的对端是回环
  地址，覆盖等于把真实地址抹掉。
- 修复：`/api`、`/client-errors`、`/socket.io/` 三个代理块统一改为「上游有 XFF 则
  原样透传（数组形态拼接），缺失才回落 socket 对端」。本地直连 dev server 的行为不变。
- 测试：新增 `web-admin/src/tests/bundling/devProxyForwardedFor.test.js`，对三个代理块
  分别钉住「透传 / 多值拼接 / 回落」三条契约。

---

### CI 修复：runner 内核误报导致 e2e-browser 起不来 Mongo（2026-10-28）

> 现象：`CI` 的 `e2e-browser` 在 **Start full stack** 步骤失败，后端日志是
> `connect ECONNREFUSED 127.0.0.1:27017`，看起来像服务没起来；`test`/`e2e` 全绿。
> 定位到真正原因不在本仓代码：

- **根因**：GitHub 自镜像 `20261018.339.1` 起把内核抬到 `7.0.0-1017-azure`，其
  `/proc/version_signature` 实为上游 **7.0.14**；而 MongoDB 8.0.x 只读 `uname -r`（得 `7.0.0`），
  误判进 SERVER-121912 的「6.19–7.0.13 不兼容区间」，启动即以 fatal `12257600` 退出。
  上游误报修在 SERVER-131779，**8.0.34 没有**（8.0.x 最新即 8.0.34，2026-10-13 发布）。
  旁证：同一次运行里 `e2e` 落在旧镜像 `20261012.334` 上，同一份 mongod 8.0.34 正常启动并通过。
  外部登记：`actions/runner-images#15005`（open，GitHub 工程师给出的临时变通即回 `ubuntu-22.04`）。
- **为什么换二进制绕不过**：把官方 tarball（sha256 与仓内锚一致）解开后，该 fatal 串在 `mongod`
  二进制内可直接检索到——闸是编进 mongod 的，不是 Docker 镜像特有的。故 `test`/`e2e` 的
  `MONGOMS_SYSTEM_BINARY` 路径同样会在新内核上失败，只是尚未落到新内核宿主机而已。
- **修法**：`test`/`e2e`/`e2e-browser` 三个用真实 mongod 的 job 钉 `runs-on: ubuntu-22.04`
  （其余 job 保持 `ubuntu-latest`）；`deployment/mongod-artifacts.json` 增补 `ubuntu2204` 条目
  （2404 包要求 glibc 2.39，22.04 的 2.35 跑不了），sha256 `8eef2a82…c7aced43` 取
  `downloads.mongodb.org/current.json` 官方值与自算字节哈希**逐字一致**的双锚。
  不动的部分：mongo 镜像仍钉 8.0.34 及其 digest（生产 compose 口径不变），三方对账闸不受影响。
- **回滚条件**：MongoDB 8.0.35 发布并完成 digest/sha256 对账，或 runner 内核进入 ≥7.0.14 区间。

---

### 审计第五轮复核：逐条回源码验证、修成立项、登记不成立与暂缓项（2026-10-26）

> 承接 `deliverables/audit-2026-10-26/audit-report.md`（复核基线 `4a1bdae` + 工作区）。
> 先把 P1/P2/P3 全部结论逐条回到当前源码与实跑结果复核，再只修验证成立的部分；
> 报告补第九节复核记录。**不修不存在的问题，也不沿用报告里的数字。**

| 项                          | 复核结论     | 处理                                                                                                                                                                                                                                                                                              |
| --------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1-1 工作区卫生             | 成立         | 删除 `.jest-*`/`.vitest-*` 日志、`.ci-repro.log`、`.tmp-probe.json` 与 4 个 `.lint-ratchet-selftest-*` 残骸；`.env` 的 `HMAC_SECRET` 19 → 43 字符（dev 文件、gitignored；本地既有审计 HMAC/二次验证票据随之不可验，重登即恢复）。`logs/`、`.mimosa/`、`CHANGELOG.md.bak` 是运行产物且已忽略，保留 |
| P2-1 假 performance 指标    | 成立         | 删除 `overview.performance` 三字段（无消费方且与 A-2「不可用≠零值」冲突），真实指标仍在 `/metrics`                                                                                                                                                                                                |
| P2-2 `data.data` 双层信封   | **部分成立** | 审计列表（游标/偏移两臂）与 `getRecentAlerts` 改用新增的 `ApiResponse.successWithMeta`（`data`/`meta` 平级），前端 `AuditLogView` 同步；`exportAuditLogs` 是流式 CSV，不经 `ApiResponse`，报告把它算进来不准确                                                                                    |
| P2-3 权限列表上限           | 成立         | `permissionRoutes` 的 `limit` 500 → 100                                                                                                                                                                                                                                                           |
| P2-4 authRoutes 错位注释    | 成立         | 删除两处错贴的 PERMISSION-EXEMPT 注释（`refresh` 在 `:325`）                                                                                                                                                                                                                                      |
| P2-6 设备统计无缓存         | 成立         | 新增 `services/deviceStatsService.js`：`scopeFilter` 序列化键 + 15s TTL + 单次 8 臂 `$facet`；7 条写路径统一 `invalidateDeviceStats`（代际防旧值写回 + `sharedCache` 跨实例广播）。`DeviceService` 只留委派，守住 max-lines 棘轮                                                                  |
| P3-3 wellKnown 未入 OpenAPI | **不成立**   | `openapiSync` 两条用例明文钉住「wellKnownRoutes 属于豁免面（不进 `openapi.json`，且豁免有据）」，是有测试保护的设计而非漏登记                                                                                                                                                                     |
| P2-5 / P3-1/2/4/5/6/8       | 暂缓         | warning 全在棘轮基线内、0 error；拆分与产品/运维决策按报告原路径排期                                                                                                                                                                                                                              |
| 锚点与密度同步              | 必做         | `DeviceService.js:445→deviceStatsService.js:82`、`auditQueryService.js:320→:314`、`statsCache.js:155/201→:159/:230`、`DeviceService` 计数 `:108/:502→:110/:444`；7 处引用注释与 2 个消费方断言同步；`statsCache`/`apiResponse` 注释压回密度基线（98→97、59→59）                                   |
| 验收                        | —            | 全量 `jest` **644/644 套件、7,956/7,956 例**；前端 `auditLogView` 44/44；`lint` 0 error/14 warn、`lint:ratchet`/`format:check`/`docs:check`（86 path / 105 operation）全绿；锚点两闸 28/28、`commentDensityRatchet` 5/5、路由契约 44/44                                                           |

---

### 审计第四轮：惰性环 4 → 1 个分量、台账单源化、注释治理落 ADR-011（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §15.2 如实登记的「A-1 剩余三个分量未做」，
> 并一并收口 **Q-3/T-6**（多份台账各自手抄实现清单）与 **Q-1**（生产注释混入变更史）。
> 报告补第 16 节。所有修复先复现红点再改，没有放宽任何断言。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A-1 惰性环清零   | 强连通分量 **4 → 1**、模块 **36 → 22**。新叶子：`middleware/userAuthCache.js`（用户缓存与失效广播，断 `auth ↔ tokenBlacklist`）、`middleware/dataScope.js`、`middleware/httpMethods.js`、`middleware/security/ipBlacklistStore.js`（封禁原语）、`middleware/security/earlyRejection.js`（早拒绝审计）、`services/alertTypes.js`、`services/alertDispatch.js`（告警链断环）。`models/User.js` 删除三个权限薄代理，调用方直接走 `userPermissionService`。`LAZY_SCC` 只剩 config/audit/metrics 22 模块，保留理由写在 `requireCycles` 头 |
| A-1 行为保持     | `addToBlacklist` 在两个封禁模块保留**调用时取属性**的薄包装（解构会在加载期固化绑定，测试就无法替换封禁结果）；F-160 的 `await addToBlacklist(` 文本门禁继续命中。6 个封禁/升级套件的注入点迁移到 `ipBlacklistStore`，是跟随唯一写入原语，不是放宽断言                                                                                                                                                                                                                                                                               |
| Q-3/T-6 台账单源 | 写方法名单收敛到 `middleware/httpMethods.js`（originCheck / security/auditLog / protocolCompliance / behaviorBaseline 四处不再各抄一份）；审计分类测试改为引用 `constants/audit.js` 的 `AUDIT_CATEGORIES`；Redis 降级失效清单改为从 `SINGLE_PROCESS_DEPENDENCIES` 过滤派生                                                                                                                                                                                                                                                           |
| Q-1 注释治理     | 新增 `docs/adr/ADR-011-注释治理-源码只保留当前约束.md`：源码只写当前约束与不明显的 Why，变更史归 CHANGELOG、权衡归 ADR、锚点优先符号。`securityHeaders.js` 整行注释 180 → **102**（生产注释 22,504 → **22,426** 行，−78）                                                                                                                                                                                                                                                                                                            |
| Q-1 密度棘轮     | 新增 `scripts/commentDensity.js` + `scripts/commentDensity.baseline.json`（258 文件 / 22,426 注释 / 34,798 代码）与 `src/tests/ci/commentDensityRatchet.test.js`（5 例：统计面自证、只降不升、新文件密度 ≤ 30%、反向对照、总量对账）。`--update-baseline` 遇回归直接拒绝                                                                                                                                                                                                                                                             |
| 棘轮实测         | A-1 给两个封禁模块各加 1 行说明后，棘轮立即报 2 处回归并拒绝收紧基线；按 Q-1 口径把 3 行历史压成 2 行后才写回基线——证明它不是「写完就绿」的摆设                                                                                                                                                                                                                                                                                                                                                                                      |
| 测试重定向       | `auditScopeFilterDeptCache` / `edgeCases` / `auditQueryOperationCatch` 的桩从 `middleware/rbac` 改到 `middleware/dataScope`（后者才是 `auditScopeFilter` 的叶子依赖；旧桩失效时真实查询打未连接 Mongo，表现为 10s 超时且日志为空）；`websocketRedisAdapter` 的 `sharedCache` 桩补 `onInvalidate`（`userPermissionService` 在加载期注册）；`sharedCacheDegradationLog` 改为派生清单（手抄版已漂移成 `middleware/auth.js`）；`reportPiiExportStepUp` 的审计断言改为轮询到真实落库（全量并发下响应先回、行尚未可见）                    |
| 验收             | 全量 `jest` **643/643 套件、7,950/7,950 例全绿**；`requireCycles` 6/6、`commentDensityRatchet` 5/5、封禁链 57 例、定向回归 179 例全绿；`npm run lint` / `lint:ratchet` 0 error（14 条既有 warning 未超基线）、`docs:check`（86 path / 105 operation）与 `format:check` 一致                                                                                                                                                                                                                                                          |

---

### 审计剩余项收口：事务拓扑 fail-closed、导出并发闸、日志 PII 掩码、运行指标补齐（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §14.5 的"仍未处置"清单。
> 本轮把 `P-1`/`P-2`/`O-1`/`O-2`/`O-3`/`T-3`/`T-4` 做掉，`A-1` 解掉一个强连通分量
> （40 → 36 模块），剩余三个分量属需改所有权的重构，**只登记不改结构**（报告 §15.2）。

| 项                       | 内容                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-1 事务拓扑 fail-closed | 生产语义下探测到 `standalone`（多集合写非原子、失败留残骸）⇒ `/readyz` 判 503（`checks.topology=transactions_degraded`），**不阻断启动**。判据落在 `utils/transaction.js` 的 `transactionReadinessBlocker()`，与既有的多实例闸合并成单一 `topologyBlocker`，同时命中时**多实例优先**（它同时影响审计链与限流计数，且修法与事务拓扑无关）                                      |
| P-2 导出并发闸           | 新增 `services/exportConcurrency.js`：上限 2 / 有界队列 8 / 排队超时 30s，全部可经 `EXPORT_MAX_CONCURRENCY`、`EXPORT_MAX_QUEUE`、`EXPORT_QUEUE_TIMEOUT_MS` 调整并在越界时**钳制 + 一次性告警**。队列满或超时 → 429 `EXPORT_BUSY` + `Retry-After`。释放幂等、槽位**移交**给 waiter（不"先减再加"，避免空窗被第三个请求插队）                                                   |
| O-1 日志 PII 集中掩码    | 新增 `utils/logPiiMask.js`，接在 `logger.sanitizeLogInfo` 末尾（清洗 → 截断 → 掩码）。判定顺序 **email → 身份证 → 手机号**（身份证必须先于手机号，否则 18 位号码会被手机号正则切碎）；键名用闭合集 + 后缀判定，**刻意不含 `token`** 后缀以免误伤 `tokenVersion`；`requestId`/`userId`/`socketId` 作为结构性标识不掩。`LOG_PII_MASK=false` 可关，关闭时在生产语义下落一条 warn |
| O-2 运行指标补齐         | 新增 `export_inflight`、`export_queued`、`export_rejected_total{reason}`、`ws_connections`、`ws_inbound_throttled_total`、`ws_inbound_disconnects_total`。WS 连接数用**拉取式** `registerWsConnectionSource`（4 处增删点任一漏推都会让 gauge 长期偏高，拉取式免掉这个失效面）；文本与 JSON 快照两通道同源                                                                     |
| O-3 tracing 适用边界     | 新增 `docs/adr/ADR-010-不引入分布式追踪的适用边界.md`：把 `requestId` 能覆盖什么、跨进程边界为何断在这里、什么条件下该重新评估，写成可证伪的判据而不是"暂时不做"                                                                                                                                                                                                              |
| A-1 惰性环（部分）       | 抽出零 require 叶子 `src/config/envSemantics.js`（环境别名/生产语义判据），`config/validate.js` 改为 re-export。实测强连通分量 40 → **36** 模块，`requireCycles` 的 `LAZY_SCC[0]` 26 → **22**                                                                                                                                                                                 |
| T-3 路由分支补测         | 新增 `routes/routeGuardBranches.test.js` 9 例：strict 档两条守卫（明文注册被拒、enc+明文并存被拒）与改密接口、巡检时间窗倒置、`POST /reports/export/pii` 类型白名单、创建用户口令 64 字符上限，均带反向对照                                                                                                                                                                   |
| T-4 sharedCache 故障注入 | 41 → **47** 例，覆盖三类"总闸式注入看不见"的形态：单条命令失败（`GETDEL` 抛错走 get→del 降级，两步必须落在同一份内存回退上）、`DECR` 回收路径（真实现此前零覆盖）、连接级故障的**日志节流**（未就绪期的重试风暴不得刷 error 日志）。三处逐一做变异，确认变红后还原                                                                                                            |

---

### 七维审计复核：把「报告结论」逐条回源码验证，再修真正成立的那几条（2026-10-25）

> `deliverables/audit-2026-10-25/audit-report.md` 的基线是 `01e08f7`。复核时 HEAD 已是
> `170467c`，**报告里的大部分数字已经过期**（380/109 个文件、28 套件 56 用例红、19 条环）。
> 本轮先把每条结论回到当前源码与实跑结果上验证，再只修验证成立的部分；报告已就地打叉
> 并补第 13 节复核记录。**不修不存在的问题，也不沿用别人的数字。**

| 项                                          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-4 压测脚本（修）                          | `scripts/load-test.js` 仍在读 `r.body.data.token`，而登录早已只下发 httpOnly Cookie（I-01）⇒ 登录步必然抛错，E/D 两相**从未真正执行过**。改为从 `Set-Cookie` 取 `access_token` 显式回放（`loadTestEngine` 增加 `cookie` 通道，与 k6 脚本同口径）。**实跑证据**：`npm run test:load` 8 通过 0 失败，B/C/E/D/D+ 全绿，基线已落 `logs/load-baseline.json`——这是本仓第一份可信的压测结果                                                                                                                                                                                                                                                                                                    |
| 压测 D 相与新封禁策略冲突（修，报告未发现） | #21 之后 IP 封禁要求「同一 IP 失败过 ≥2 个不同账号」，而脚本只打一个用户名 ⇒ 即使取到凭据也永远等不到 403。改为两个一次性靶用户交替失败，并显式断言「401 覆盖 ≥2 个账号」。实跑日志确认 `distinctAccounts:2, ipBanApplied:true`                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| A-2 就绪闸（修，已在工作区）                | 多实例且无分布式审计锁时 `/readyz` 判 503（`checks.topology`），不再只打日志；`constants/runtime.js` 把重复的 Redis 就绪探测抽成 `sharedCacheReady()` 一处                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| A-1 惰性环（登记，不是消除）                | 报告写的「19 条」在任何枚举口径下都复现不出来。实测：**4 个强连通分量 / 40 个模块 / 122 条简单环**（长度 ≤9）。新增 `requireCycles` 用例按**分量**逐条登记，新增或消失都会红——分量是与遍历顺序无关的不变量，条数不是                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| T-1 MFA（补测）                             | `mfaController` 分支 64.58% → **87.5%**，函数覆盖 80% → **100%**（补 `getMfaStatus` 三例：余量如实、已关闭为 0、用户不存在不抛）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| T-2 二次验证（补测）                        | `securityController/reauth.js` 分支 50% → **100%**：补「令牌无 sid 时按未绑定会话签发，且不认任何具体会话」                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 锚点台账（同步）                            | A-2 改动使 `app.js` 行号整体后移，7 处 `LIVE` 登记与 4 个文件里的引用注释逐条改到新行号（`:205→:206`、`:249→:250`、`:487→:500`、`:546→:559`、`:550→:563`、`435-457→435-479`、`460→:473`），手册 `:297→:302` ；同日 `src/app.js` 的 `recordReadyz` 判据由 prettier 展开的九行嵌套三元收成 `?.` + `??` 单行形态（`format:check` 原本就在这个文件上红），行号再迁 3 行，登记同步到 `:462/:476/:503/:562/:566` 与 `435-482`；顺带发现 `queryLimit.test.js` 引用的 `app.js:536` 本就失实（真实落点是 `:592` 的 `query parser`），一并改对                                                                                                                                                    |
| 文档对账（修判据）                          | `documentationDrift` 的 bash 续行断言在 CRLF 检出下必然假红（同一份文档 Windows 红、CI 绿）。改在 `read()` 入口统一行尾——行尾是检出形态，不是内容事实                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 指标契约（同步）                            | `runtimeMetricsCoverage` 的 `/readyz` 判定正则绑定死了旧的三元表达式形状，A-2 加一档拓扑阻断即假红。改为钉三件语义（`ready ? 'ok'` / `mongo.ok ? redis.reason` / `topologyBlocker.reason`），并保留可失败反证                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 信号用例（修竞速）                          | `imageDigestGate` 的 SIGTERM 用例写死「睡 1 秒再发信号」，而 Windows/MSYS 起一个 sh+替身要 2–3 秒 ⇒ 替身日志为空、被判成"脚本没被叫醒"。改为**等替身留下第一行日志再发信号**（判据更严，不再依赖机器速度）                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 随机顺序 worker 崩溃（修，CI 实证）         | CI 的 `Test order independence (randomized)` 在 `170467c` 上是红的（`test (26.x)` 失败、22/24 被 fail-fast 取消），红点是 `appTrustProxyAndReadyzGuards` 的 `Jest worker encountered 4 child process exceptions`。根因不在断言：`auditLog` 用 `setImmediate` 异步落库，而回调体里才惰性 require `utils/fingerprint`；文件跑完、Jest 拆环境后回调才被调度，require 拿到 `undefined` ⇒ `TypeError: Cannot destructure property 'computeFingerprint'` 抛在测试框架之外，**直接崩 worker**（同文件按默认顺序却全绿，是典型的顺序耦合指纹）。修法：该套件 `afterAll` 放完一个 tick；修复后按三个 seed 各跑两次该文件 6/6 绿，再按 CI 口径跑全量三 seed，`appTrustProxy` 不再出现 worker 崩溃 |
| 测试树纯净性（入库）                        | 3 个新增用例（T-1/T-2/T-5 与 P-3 降级 TTL）与 `scripts/check-openapi-drift.js` 此前未跟踪，`testTreePurity` 因此红；已入库                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| D-1 OpenAPI 门禁（修，已在工作区）          | 新增 `npm run docs:check` 并在 CI 阻断；反证过：给生成器注入一条 path 后比较必然为 false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

### 告警抑制规则移除、nginx 显式拒绝 `/readyz`、Node 运行时进 CI 矩阵、5 条"假绿"测试逐条复核（2026-10-24）

> 审计第二批 6 项。其中 **2 项经复核不成立**（compose app 的 healthcheck、两个"假绿"测试），
> 记录在下方表格的对应行——不修一个不存在的问题，与修一个真问题同等重要。

| 项                            | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 告警抑制规则（移除）          | `alertmanager.yml` 原为「任何 critical 抑制同实例任何 warning，`equal:['instance']`」，理由写的是「BackendDown 时 HighP95Latency 必然伴随」。复核后整条移除，三条理由写进文件：①该理由**事实错误**——目标停止导出指标后 `rate()` 无样本，延迟告警根本不会触发；②即便成立，`equal:['instance']` 也匹配不到 `ReadinessProbeMissing` 的 `absent()` 分支（`absent()` 只回填选择器里的 `job`），而那正是"后端真挂了"时唯一会亮的伴随告警；③若真能生效，`AuditRecordsDropped`(critical) 会压掉同实例 `DiskSpaceLow`(warning)——把**根因**信号静默掉。同时留了新增抑制的三条门槛（alertname 精确 / target 是 source 的纯后果 / equal 标签两侧必然存在）                                                                          |
| 告警标签（修）                | `alert-rules.yml` 的 `HighErrorRate`、`SecurityAlertBurst` 由 bare `sum(...)` 改为 `sum by (instance)`。理由不是"为了让抑制能匹配"（那条规则已移除），而是多实例部署下 bare `sum` 会把全部标签丢掉：告警分不清哪台机器出错、面板无法按实例下钻、`{{ $labels.instance }}` 渲染成空串。单实例环境里这个缺陷"看起来完全正常"，所以只能靠契约测试钉住                                                                                                                                                                                                                                                                                                                                                                       |
| nginx `/readyz`（修）         | `deployment/nginx.conf.example` 此前只有注释「/readyz 刻意不对外」，配置上无任何对应指令 ⇒ 落进 `location /` 的 `try_files` 返回 **200 + index.html**。外部拨测配了这个地址会**恒判健康**（它探的是 nginx 能否返回 HTML，不是 Mongo 可不可达）。新增 `location = /readyz { return 404; }`：精确匹配、不反代、用 404 而非 403（403 等于确认"该路径存在且被保护"）                                                                                                                                                                                                                                                                                                                                                        |
| compose healthcheck（不成立） | `docker-compose.yml` 的 app 服务确实没有 `healthcheck`，但**不是缺陷**：健康检查来自镜像（`Dockerfile:201` 的 `HEALTHCHECK --interval=30s`），Compose 在服务未声明时原样继承；mongo/redis 要在 compose 里写，是因为它们的官方镜像不带。**反过来补一条是有害的**——compose 侧手写的通常只探 `/health`，会整体顶掉镜像侧"并行探 `/readyz` + `/health`、退出码只取 health"的口径。已补契约测试钉住该形态，compose 该块内写明不要补的理由                                                                                                                                                                                                                                                                                    |
| Node 运行时（修）             | 生产镜像 `node:26.12.0-alpine`，CI 矩阵只有 `22.x/24.x` ⇒ **实际发布到生产的运行时从未被任何 CI 用例执行过**。矩阵加 `26.x`（`[22.x, 24.x, 26.x]`，分别对应 `engines` 下界 / 当前 LTS / 发布基线），并新增 `nodeRuntimeMatrixParity.test.js` 把"镜像主版本 ∈ 矩阵、三处 FROM 一致、`engines` 下界 ∈ 矩阵"钉成闸门。选加矩阵而非降镜像版本：后者要回退一次四天前做过三源核验的升级，前者只增加验证、不改生产行为                                                                                                                                                                                                                                                                                                         |
| 前端 PII（修）                | `web-admin` 的 `currentUser` 落 localStorage 时改为白名单投影（`userId`/`id`/`_id`/`username`/`roles`），不再写入 `email`/`realName`/`phone` 等 PII。httpOnly cookie 的收益此前被明文 PII 抵消。新增 `authPersistenceNoPii.test.js` 6 例：白名单闭合性、登录与 `/auth/me` 两条路径不落 PII、内存态仍保留完整字段、刷新后身份骨架可用、历史脏数据被覆盖                                                                                                                                                                                                                                                                                                                                                                  |
| 5 条"假绿"测试                | 3 条成立并已修（见下），2 条不成立。①`authMiddlewareFailClosedGuards`：三条 `not.toThrow()` 换成可观察后果（库里改 inactive → 失效后必须 401），**变异复测**从"11 例全绿"变为"1 例红"；②`User.test.js`：从"字段存在"改为按**选项值**断言（10 个凭证字段 `select:false`、西里尔同形字 `аdmin` 必须被拒、72 **字节**边界、`status.enum` 与 `USER_STATUS` 同源、`username_ci` 的 collation）；③`mfaReplayGuardMax`：补"先认领再写库"的顺序断言（原断言对换序完全免疫）。**不成立**的 2 条：`mfaControllerOrchestration` 的认领失败分支已在 `mfaReplayGuardMax:118` 覆盖；`securityConfigHandlers` 的读回一致已由 `systemConfigBooleanContract.test.js`（真实 Mongo）覆盖——两处都在文件头写明了分工，避免同一结论被再次提出 |
| 契约测试                      | 新增 `composeAppHealthcheck.test.js`（5 例）、`nodeRuntimeMatrixParity.test.js`（5 例）、`authPersistenceNoPii.test.js`（6 例）；`nginxProxyContract` +1 例、`alertingConfig` +6 例。三处变异实测：`return 404`→`200` 变红、`sum by (instance)`→bare `sum(` 红 2 例、给 app 补 healthcheck 变红 1 例                                                                                                                                                                                                                                                                                                                                                                                                                    |

### WS 绕过探针改为两个单违规场景，并要求拒绝理由可归因（2026-10-24）

> 审计 P2：`scripts/audit-probes/ws-session-bypass.cjs` 只用一个令牌，**同时**带
> 「已吊销会话」与「非白名单 IP」两条违规，判据是"收到任何 `auth-error` 就算拒绝"。
> 于是它只证明了**至少一条**控制在生效：把 `sid` 校验删掉、只留 IP 校验，探针照样
> `exit 0` 报"P0-2 修复在位"。对一个有两条独立控制项的漏洞，"至少一条"不是证据。
> 另外 HTTP 侧只 `console.log` 状态码、从不校验，一个 500 或"因别的原因 401"也会被
> 当成有效对照。

| 项            | 内容                                                                                                                                                                                                                                         |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 场景拆分      | 拆成 `session_revoked`（会话已吊销 + IP 不限制）与 `ip_not_allowed`（会话正常 + IP 不在白名单），每个场景只带一条违规。两个用户、两个会话、两个令牌，`allowedIPs` 与 `sessionStatus` 互斥地只坏一个                                          |
| 理由归因      | `decideVerdict` 新增 `expected` 参数：必须收到 `auth-error` **且文案匹配本场景那条控制**才判 `rejected`。不匹配、或调用方未声明期望 → `inconclusive`（exit 2），不再算通过。帧里没有错误码，文案是唯一通道，故文案改动会让探针变红而不是变绿 |
| HTTP 前置对照 | 改为断言 `status + errorCode`（`401/DEVICE_SESSION_REVOKED`、`403/AUTH_IP_RANGE_DENIED`）。不符即判 `inconclusive`：同一令牌在 HTTP 侧不是因本场景那条规则被拒时，WS 侧的"被拒"无法归因                                                      |
| 服务端观察    | 不再取 `[...clients.values()][0]`（多场景同进程时会拿到上一场景的残留或未认证占位条目），改为按**本场景 userId** 精确匹配；第 5 步同时打印实际收到的下行帧，让证据可见                                                                       |
| 体积          | `makeClients` 的 get/post 合并为一个 `send(method, path, body)`，抵消新增逻辑，维持 `max-lines` 300 以内                                                                                                                                     |
| 测试          | `src/tests/wsProbeVerdict.test.js` 6 例 → 9 例：新增「理由不匹配 ⇒ 不可判定」「两场景理由互不通用（互为反例）」「未声明期望理由 ⇒ 不可判定」，并钉住场景表仍是两个单违规场景                                                                 |
| 可证伪性      | 实测三组：① 两条控制都摘 → `bypass,bypass exit=1`；② **只摘 IP 校验** → `rejected,bypass exit=1`（旧判据在这种情形下会给 exit 0）；③ 恢复后 → `rejected,rejected exit=0`，两场景各自拿到自己的 `auth-error` 帧                               |

### MFA 关闭与恢复码重生成改为条件写（CAS）（2026-10-24）

> 审计 P2：`mfaController.js` 四个状态变更写点里，`mfaEnroll`（:174）与 `mfaEnable`（:273）
> 已是条件写，注释还写着「下发即生效，不得被并发请求静默回收」；而
> `regenerateRecoveryCodes`（:104）与 `mfaDisable`（:368）仍是 `findByIdAndUpdate(_id)`
> **无条件覆盖**。同一份文件里同一条不变量，修了两处漏了两处。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 重生成 CAS | 过滤条件改为 `{_id, mfaEnabled:true, 旧码组全等}`。两次并发重生成携带**相邻窗口**的不同码时两次 `claimTotpWindow` 都会成功（窗口不同不算重放），后到者原会顶掉先到者刚下发的 10 张——调用方已抄走的那组全部作废，而两个响应都宣称"已生成"。空数组分支用 `$in: [[], null]` 覆盖"字段缺失"的历史文档（Mongoose 读时补 `default:[]`，库里没有该字段，直接写 `[]` 会永不命中 ⇒ 这类用户永久 409） |
| 关闭 CAS   | 过滤条件改为 `{_id, mfaEnabled:true, **本次验证过的 mfaSecret**}`。验证是对 `user.mfaSecret` 解密后做的；该字段被并发 enroll/enable 换掉后，无条件写仍会 `mfaEnabled:false + mfaSecret:''`，把本次从未证明过控制权的**新登记**一起清掉，审计还记成"用户关闭 MFA"                                                                                                                             |
| 落空归因   | 两处 CAS 落空后重读一次：已关 → `MFA_NOT_ENABLED`（不再记第二条"成功关闭"审计）、码组被换 → `USER_STATE_CONFLICT`、无 MFA → `MFA_NOT_ENABLED_NO_CODES`。**落空时绝不返回本次生成的码**——它们从未生效                                                                                                                                                                                         |
| 分层       | `mfaDisable` 的第二因子判定（TOTP 优先 / 恢复码兜底）移入 `mfaService.verifyDisableFactor`：这是"什么算验证通过"的领域判定，controller 只该决定"通过后写什么、失败回什么码"。顺带把控制器压回 `max-lines` 300 以内                                                                                                                                                                           |
| 测试       | 新增 `src/tests/controllers/mfaWriteCasConcurrency.test.js`（4 例，**真实 Mongo**，用闸门制造确定性交错而非 sleep）：① 并发重生成恰好一次 200，且成功响应下发的 10 张码**逐张**能对上库内摘要；② 关闭与新登记并发时旧密钥的验证不得清掉新登记；③ 缺 `mfaRecoveryCodes` 字段的历史文档仍可重生成；④ 无并发时两端点照常成功（CAS 不得把正当用户挡在门外）                                      |
| 可证伪性   | 已做变异验证：把两处过滤条件临时改回 `{_id}` 后，用例 ①② 立即变红（实测 `Expected length: 1 / Received length: 2`，两份响应各带一组不同的 10 张码），用例 ③④ 保持绿 —— 说明断言钉的是 CAS 本身，不是环境                                                                                                                                                                                     |

### 迁移脚本参数严格化，且不再在 require 时连库（2026-10-21）

> 审计 P2：`scripts/migrate-pii-encryption.js` 用五个独立 `if` 解析开关，未知参数一律当没看见。
> `--keys-onl`（少一个字母）不会报错，`keysOnly` 保持 false ⇒ 退化为**默认全量模式**
> （加密列 + 回填检索键 + 升级 v1），而操作者以为只补键。同一文件还在模块顶层无条件
> `main()`：任何 `require()` 都会立刻连库并扫描改写 PII。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 参数严格化 | 新增 `scripts/cliFlagPolicy.js`（本仓第四份「开关白名单」实现，抽出来共用）：`parseFlags(argv, allowed)` 把白名单外 token 全部收进 `errors`；建议用**编辑距离 ≤ 2**（全等抹平法对"少一个字母"永不命中，而那正是最危险的误输）。`migrate-pii-encryption.parseArgs(argv)` 返回 `{args, errors}`，`main()` 在**任何副作用之前**以退出码 2 拒绝 |
| 顶层执行   | `main()` 改为 `if (require.main === module)`；`--rotate` 的密钥快照本就在 `main()` 内有等价语句，删掉顶层重复。`parseArgs` / `MODE_FLAGS` / `PII_TARGETS` 导出供测试                                                                                                                                                                        |
| 文档闸     | `runbookSecretSource.test.js` 的 `EXTRA_SECRETS` 补 `run-rollback-drill.js: ['AES_SECRET_KEY']`——快照加密后缺密钥即 exit 2，手册 cron 必须自带来源，否则预发演练静默失败                                                                                                                                                                    |
| 测试       | `src/tests/deploy/cliArgStrictness.test.js` 增用例 19-23（合法全给不误伤 / 拼错必须报错且不猜真 / 位置参数拒绝 / 子进程实测退出码 2 且不连库 / `require` 不触发 `main`）；同时把 `generate-secrets` 的密钥清单钉数补上 `mongo_keyfile`（并行改动新增，钉数按设计要求显式确认）                                                              |

### 举报对话框改为可搜索对象选择器（2026-10-21）

> 缺陷（可用性）：举报对话框把「对象 ID」摆给用户填 24 位 ObjectId，而一线人员拿不到该值
> —— 它只出现在接口响应里，界面上从不显示。记录型举报（用户/设备/报警记录）实际不可用。

| 项       | 内容                                                                                                                                                                                                                                                                     |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 前端控件 | `ReportDialog.vue` 的记录型目标由 ID 输入框改为远程搜索下拉：界面只出现名称/编号，`targetId` 作为选中值随载荷上行、用户不可见。输入防抖 300ms（每次输入只落一条审计）、请求序号防「后发先至」覆盖、选中项在候选刷新后仍保留标签                                          |
| 新端点   | `GET /api/security/report-targets?type=&keyword=`：免权限码（举报对全员开放），候选集按**举报人数据范围**过滤，每类上限 20 条；投影不含 phone/email、报警描述、上报人姓名                                                                                                |
| 同判据   | 新增 `rbac.buildRecordScopeFilter`，与核验侧的 `isRecordInScope` **逐臂同值**（含「本人 `_id` 短路」、department 缺失仍放行本人、`none` 一律 deny）。`buildDataScopeFilter` 在这两处边界上并不等价——直接复用它会出现「下拉里选不到自己」或「选得到却提交 403」           |
| 限流     | 候选查询消耗 `authenticate` 内的账号级 userLimiter（200/15min），与举报提交的独立 20 次写配额分开：搜索不会吃掉提交配额（否则 429 文案会指向「提交过于频繁」，根因不可见）                                                                                               |
| 文档     | `src/docs/generate.js` 补 `/api/security/report-targets` 并重生成产物；端点经 `securityRoutes` 直接注册（不走 `router.use` 子挂载——openapiSync 的采集对子挂载是盲区，塞进去等于绕过文档门禁）                                                                            |
| 测试     | 新增 `src/tests/security/reportTargetCandidates.test.js`（16 例：免权限码可达 / 范围一致性 / **候选与提交核验同值** / 最小投影 / 参数边界 / 20 条上限与独立配额）；`web-admin/src/tests/components/reportDialog.test.js` 重写为 13 例，含「界面上不出现对象 ID」回归锚点 |

### 审计 WAL 裁剪按持久化承诺分级 + 回滚演练备份加密（2026-10-21）

> 按 `deliverables/七维审计终稿-核验版-2026-10-21.md` 的两项 P1 整改。
> 旧结论「outbox 先落 WAL 名不副实」已在工作树中修复（`auditOutbox.js` 已 `await appendLineDurable` 并 fsync），
> 但**裁剪侧**仍会把这些已 fsync 的行按位置丢出主 WAL，本节点修的是这一半。

| 项           | 内容                                                                                                                                                                                                                                                                                                                                                                    |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WAL 裁剪分级 | `auditOutbox.js` 写出的行带 `__walDurable`；`auditWalCap.enforceWalLimit` 改为**普通行优先丢、durable 行默认不丢**。普通行不足时记 `walDurableTrimRefusals` 并停手（WAL 继续超限，这是有意取舍），只有显式 `AUDIT_WAL_ALLOW_DURABLE_TRIM=true` 才裁 durable 并计 `walDurableDropped`。理由：`.discarded` 永不回灌，按位置裁剪等于把「已回成功」改成「落盘但永久不入库」 |
| 重放剥离     | `auditBufferWal.stampReplaySeqs` 在交给缓冲前删除 `__walDurable`（保留 `__walSeq`），避免 WAL 记账字段进入 Mongo 文档；回写补号行在删除**之前**序列化，否则会丢标记                                                                                                                                                                                                     |
| 面板投影     | `securityController/overview.js` 的 `auditLoss` 新增两项；`AuditLogView.vue` 的 `auditLossTotal` 计入 `walDurableDropped`（承诺缺失），`walDurableTrimRefusals` 只进明细（此刻尚未丢记录，处置方向是扩容而非取证）                                                                                                                                                      |
| 演练备份加密 | `run-rollback-drill.js` 由明文 gzip 改为 gzip 后 AES-256-GCM（魔数 `FSMSBK1`，密钥由 `AES_SECRET_KEY` 派生），缺密钥直接退出、不退回明文；`.discarded` 同族：`restoreCollection` 按魔数识别，改造前的明文快照仍可回灌但显式告警                                                                                                                                         |
| 可观测性     | `metricsAuditDrops` 新增 reason `wal_durable_lost`（由 `auditWalCap` 在显式开关裁掉 durable 行时上报，自动被既有 `AuditRecordsDropped` critical 规则覆盖）；新增计数器 `audit_wal_durable_trim_refusals_total` 与告警 `AuditWalTrimRefused`（warning）——「拒绝裁剪」意味着 WAL 无界增长，必须在写满磁盘前可见                                                           |
| 文档对齐     | `deployment/backup-encryption.md` 删除「单人拿不到完整链」这一与设计矛盾的断言，改为「默认无口令私钥下该控制不成立」并给出两条可兑现路径（口令分离 / 人员分离）；`deployment/rollback-drill.md` 的 cron 示例补 `AES_SECRET_KEY_FILE`，并新增第 5 条纪律（缺密钥退出码 2 是 fail-closed，不是配置错误）                                                                  |
| 测试         | 新增 `src/tests/services/auditWalDurableTrim.test.js`（5 例：durable 全留 / 拒绝裁剪 / 显式放开 / 全 durable 不动文件 / 重放剥字段，含两条 Prometheus 上报断言）；`rollbackDrillRestoreVerification.test.js` 增「归档必须带 FSMSBK1 魔数且不得同时留下明文 .ndjson.gz」与 `manifest.encrypted` 断言；`auditDropMetrics.test.js` 的 reason 闭合集合断言扩到五项          |

### 搜索面板新增可见关闭按钮、隐藏 ESC 提示（2026-10-21）

> 全屏态下 ESC 先被浏览器用于退出全屏（`keydown` 的 `preventDefault` 拦不住），把 ESC 当关闭卖点展示会误导；改为「按钮是可见入口，ESC 静默保留」。

| 项         | 内容                                                                                                                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 组件行为   | `web-admin/src/components/SearchPalette.vue` 输入行右侧新增 `.search-palette__close` 按钮（`aria-label`/`title` 取 `common.close`，纳入既有 Tab 焦点陷阱）。ESC、遮罩点击、⌘K/Ctrl+K 再次按下仍照旧可关闭，只是 ESC 不再出现在 UI 上 |
| 提示与词表 | 页脚去掉 `ESC 关闭` 提示、输入行去掉 ESC 键帽（页脚只剩 ↑↓ 与 ↵）；随之无引用的 `common.searchHintClose` 从中英词表删除（两语言同步，键位仍对齐）                                                                                    |
| 测试       | `web-admin/src/tests/components/searchPalette.test.js` 新增「关闭按钮可关」与「UI 无 ESC 字样（kbd 与页脚）」断言；ESC 关闭与焦点归还用例保持原契约                                                                                  |

### 七维审计 2026-10-20：审计链检查点 / 固定睡眠门禁 / 运维关键路径 E2E

> 按 `deliverables/七维深度审计报告-2026-10-20.md` 整改。本节只记录三项中危的**结构性**修复；
> 其余按报告编号分散落在各模块的修复不在此逐条复述。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S-8 审计链外部锚 | 新增 `scripts/audit-chain-checkpoint.js` 与 `src/services/auditChainCheckpoint.js`：把链头与记录数写成 HMAC 签名的 JSONL 检查点，校验时逐行验签并核对锚点。可检出分支插入 / 链头替换 / 锚点前截断 / 检查点文件被改；**残余边界**（锚点与库同机、锚点后先加后删）已在 `docs/architecture.md` §7 与 `docs/threat-model.md` 明示，不宣称完整防篡改                                                                                                                                             |
| T-2 固定睡眠     | 新增 `src/tests/helpers/waitFor.js`（条件轮询）与 `src/tests/ci/noFixedSleepRatchet.test.js`：固定 `setTimeout` 收进棘轮，新增一处即红；真实网络/进程等待改走健康检查与事件，定时器逻辑用 fake timers                                                                                                                                                                                                                                                                                       |
| T-1 运维 E2E     | 新增 `scripts/ops-e2e.js` 与 `scripts/ops-e2e/journeys/*` 四条旅程：告警投递探针、部署失败→自动回滚、备份→恢复→校验、跨部门越权。各自独立子进程 + 内存 Mongo + 随机端口 + 本地假 Alertmanager；CI 的 `e2e` job 新增 `npm run test:ops-e2e` 并登记进 `ciGateWiring`。浏览器 no-skip 门禁（`MIN_PASSED=32`、`skipped==0`）未改动                                                                                                                                                              |
| O-5 部署演练     | `scripts/deployCommands.js` 抽出全部外发命令的 argv 构造（部署脚本不再自带命令字面量），`--dry-run` 打印与实际执行同源的真实命令；新增 `src/tests/deploy/deployCommands.test.js`。首次 `dry_run=true` 真实演练的步骤与留证表登记在 `deployment/deploy-workflow-rehearsal.md`——**真实 run 尚未执行**（需预发环境），未留证前 deploy.yml 的「未验证声明」保留。T-4 的预发定期演练 cron 见 `deployment/rollback-drill.md` §5.5；S-9 的 CI 开发机隔离口径见 `docs/security-dependency-watch.md` |
| 冒烟测试修正     | I-01 改为令牌只经 httpOnly cookie 下发后，`scripts/e2e-smoke.js` 仍从响应体取 `data.token`，导致 9 步 401（CI 必红）。改为从 `Set-Cookie` 取 `access_token`，继续用 Bearer 路径覆盖 `authenticate`                                                                                                                                                                                                                                                                                          |

### lint 棘轮批 1–3c：大文件目录化拆分与阈值重设（2026-10-18/19）

> 本轮是**纯搬家 + 度量收敛**：`security.js`、`authService.js`、`websocketService.js`、
> `authController.js`、`userController.js`、`securityController.js`、`sharedCache.js`、`initData.js`
> 按职责拆入同名目录（入口文件保留原有导出形态），复杂度与函数体积告警逐批下降。
> 业务语义未变；覆盖率/体积棘轮的键随路径迁移同步重设，并有 `coverageGateWiring` 与
> 分层棘轮测试守住“拆分后门槛没有被悄悄放宽”。针对拆分中暴露的 `max-lines` 最后若干条，
> 批 3a/3c 只做内容保持式迁移，未借机改行为。

### 响应头加固：X-XSS-Protection 测试守护 + Trusted Types 灰度 + CORP/Referrer-Policy 口径统一到 same-origin（2026-10-15 · 按 `deliverables/安全加固待办清单-2026-10-15.md` 的 P1+P2 逐项落地）

> 清单 P1（Trusted Types report-only）与 P2（COEP 决策记录 / CORP / Referrer-Policy）四项全部落地；P3 的 CSRF 双保险按清单自陈「不做也不构成缺口；仅在明确有子域/多应用共站时做」未做（本仓 nginx 单 `server_name`、无子域前端，已复核）。
>
> 落地过程中发现**三处清单本身没写准的地方**，一并记录：
> ① 清单给的 Trusted Types 写法（`useDefaults:false` + 只写 `require-trusted-types-for`）在 helmet 7.2.0 下**构造期直接抛错**——`normalizeDirectives()` 要求「必须有 default-src，除非显式 `dangerouslyDisableDefaultSrc`」，且该检查对 `reportOnly` 一视同仁（回源 `node_modules/helmet/index.cjs:90-92`，已实测复现）。照抄会让整个 app 起不来。已改为显式摘掉 `default-src`，下发结果就是单条 `require-trusted-types-for 'script'`，不会把 helmet 的全套默认指令拖进灰度策略制造噪音。
> ② Referrer-Policy 实际有**五份**副本，清单只列了 4 处，漏了 `web-admin/vite.config.js` 的 `buildSecurityHeaders`（vite dev/preview 这条托管路径）。五份已一并改，并由新用例钉住取值一致。
> ③ 顺带发现 `src/tests/controllers/roleControllerHierarchyGuards.test.js` 中「角色/权限审计全部由全局中间件派生（`utils/auditMeta.js:85-103` → `middleware/security.js:648`；挂载 `src/app.js:325-326`）」这句的**三个锚点全部指错位置**（其中 `security.js:648` 在 HEAD 就已落在 `checkIPBlacklist` 的 `IP_BLOCKED` 行，内容保持式迁移只会把它一路带下来）。已按真实落点更正为派生定义 / 派生调用 / 中间件挂载。

| 项                         | 内容                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trusted Types 灰度（P1）   | `src/middleware/security.js` 新增独立中间件 `trustedTypesReportOnly`，挂到 `applyResponseHardening()` 的 `reportingEndpoints` 之后。只写 `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'`，与主 CSP 头名不同、互不覆盖；`CSP_REPORT_ENABLED=true` 时附带 `report-uri`/`report-to`（复用既有 `/csp-report` 与 `csp-endpoint`），关闭时一条多余指令都不下发。**只上报不阻断**，对现有行为零影响 |
| COEP 决策记录（P2）        | `crossOriginEmbedderPolicy: false` 处补注释：为何关闭（无跨源隔离需求；开启会拦掉 Swagger UI 自注入资源、Google Fonts、导出 `blob:` 下载）、什么条件下应重新评估（含「`credentialless` 不是免费开关」这条反面证据）。此前全仓无任何 COEP 决策留痕                                                                                                                                                                      |
| CORP 收紧（P2）            | `crossOriginResourcePolicy` 由 `same-site` → `same-origin`，与 nginx 三份副本、`web-admin/vite.config.js` 及 helmet 7 默认值（`index.cjs:168`）对齐。同源反代拓扑下前后端同源，对同源 fetch 无影响                                                                                                                                                                                                                     |
| Referrer-Policy 收紧（P2） | 5 处由 `strict-origin-when-cross-origin` → `same-origin`：`src/middleware/security.js:139`、`deployment/nginx.conf.example:108`/`:175`/`:217`、`web-admin/vite.config.js:134`。前置确认已实测：跨源子资源仅 Google Fonts（不依赖 Referer）、全仓无外部跳转/防盗链/外链来源分析、后端唯一 Referer 消费点是 `originCheck.js` 的 Origin 缺失回退（同源请求照常携带 Referer）                                              |
| X-XSS-Protection 守护      | 新增 `src/tests/middleware/xssProtectionHeader.test.js`（5 例）钉住「下发且精确等于 `'0'`」与「恰好一个头」——该头此前全仓无断言，误改为 `false`（= 完全不设该头）不会有任何红灯。变异实测：`xssFilter: false` ⇒ 前 4 条转红。同时更正 `security.js` 中语义写反的旧注释（`xssFilter: true` 的语义本就是下发 `0`，照字面读会以为这是"开启保护"）                                                                         |
| 锚点同步                   | `security.js` 净 +82 行 ⇒ 指向其 123 行之后的 **9 处**锚点逐条迁移（`:608`→`:685`、`:666`→`:743`、`:686-690`→`:763-767`），涉及 5 个源码/文档 + 4 个测试文件；`git grep` 核验旧值 0 残留、新值一一对应，`commentAnchorFreshness` + `bareAnchorAttribution` 全绿                                                                                                                                                        |
| 新用例                     | 新增 `src/tests/middleware/securityHeaderPolicyHardening.test.js`（11 例）：report-only 头取值 / 不污染强制 CSP / 上报开关两态 / CORP 与 Referrer-Policy 五份副本取值一致 + 两类可证伪反证。变异实测：摘掉 `app.use(trustedTypesReportOnly)` ⇒ 4 条转红；CORP 回退 `same-site` ⇒ 2 条转红（断言有牙，非空洞）                                                                                                          |
| 门禁联动                   | 两个新用例文件均已 `git add`：`testTreePurity` 要求 `src/tests/**` 下不得存在未跟踪的 `*.test.js`（放在那里 `testMatch` 一定会执行它）                                                                                                                                                                                                                                                                                 |

### 修 CI 真红：审计 action 对账闸补登 roleController updated 广播载荷（2026-10-11 · 678e211 漏登）

> 678e211 给 updateRole 补 role-updated 广播时加了 action: 'updated' 载荷字段，但未同步 auditActionReconciliation 的 NOT_AUDIT_ACTION_LITERALS 排除清单（该闸要求每个 action 字面量要么有写入形态认领、要么逐条登记家族与出处；同文件 created/deleted 两条广播载荷均在册）。f4afd88 的 CI 止步于 lint ratchet 未跑到该步、f6bf4e7 早于 678e211，故此前未暴露。按既有机制补登（ws 家族，tally 5→6），并改准两处被 678e211 移动而过时的行号出处。

### 登录加密轨道安全收口七项（2026-10-10 · 外部审计 8 项发现逐项处置：限流漏配 / 对客预言机 / 信封不绑用途 / 公钥无钉扎 / strict 无生产收口 / PFS 未文档化 / dev 链存量 CVE）

> 对登录口令 ECDH 密文轨（ADR-001）的一轮外部审计逐项修复。另有两项审计结论经核对已过期：nginx 边层 Permissions-Policy 与 transportSecurity 的 HTTPS 断言在受审版本前已落地，本次仅复核确认、无改动。

| 项                             | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/mfa/enable` 补限流           | enroll/disable/recovery-codes 都有 strictLimiter，唯独「确认开启」那步漏配；已补齐。危害有界（爆破只能加速攻击者给自己的账户开 MFA），属一致性收口                                                                                                                                                                                                                                                                                                                |
| 登录 ENC_INVALID 对客统一      | 解密失败原映射 400 `AUTH_ENCRYPTED_CREDENTIAL_INVALID`，与 `AUTH_INVALID_CREDENTIALS` 可区分 ⇒ nonce 消费/时间窗弱预言机，与 loginCipher「失败原因不回传客户端做区分」的设计意图相悖。登录端点改为统一 401 `AUTH_INVALID_CREDENTIALS`；register/changePassword/mfaDisable/userCreate **保留**独立错误码——那些端点输入由攻击者自控（注册新用户、改自己口令），无预言机价值，且前端公钥缓存自愈依赖该码触发（自愈判定改由 `web-admin/src/utils/api.js` 按端点承担） |
| 信封绑定端点用途（AAD）        | 载荷原本只有 `{p, ts, nonce}`：一条**从未到达服务端**的捕获信封（提交失败/被丢弃，密文已上线）可在 ±5 分钟窗口内提交到任何接收密文口令的端点。新增 `CREDENTIAL_AAD`（login / register / password:current / password:new / mfa:disable / user:create）纳入 GCM additionalData，跨端点信封解密失败；刻意**不**绑用户名——跨用户重放会在口令比对处自然 401，绑用户名零收益却让每个前端表单多一个必须逐字一致的条件                                                    |
| 公钥指纹钉扎（防主动 MITM）    | 公钥经同一信道下发、不固定不验签，主动中间人替换公钥即可解密再转发——「截获密文无法恢复口令」只对被动窃听成立。构建期把公钥 SHA-256 指纹钉进前端包（`VITE_LOGIN_PUBLIC_KEY_SHA256`，≥16 位 hex 前缀），`ensurePublicKey` 对**取到的 PEM** 自行计算并比对，不符抛 `PUBLIC_KEY_PIN_MISMATCH` 且不得降级明文；指纹取自服务端启动日志的 `publicKeySha256` 字段（公钥指纹是公开信息）                                                                                   |
| strict 未开的启动期告警        | 新增 `src/config/loginEncryptGuard.js`：`LOGIN_ENCRYPT_STRICT` 未开时 loud warning + `incSecurityAlert('login_encrypt_strict_disabled', medium)`（已登记进 `failOpenSites` 台账）。**刻意不阻断启动**：strict 关死明文轨的前提是浏览器有 WebCrypto，而纯 HTTP 内网形态拿不到——致命闸会拦死一种合法部署形态；收口方式是「可见」而非「拒绝」                                                                                                                        |
| PFS 与轮换文档化               | `SECURITY.md` 新增「登录口令加密的密钥管理」：静态私钥 = 无前向保密，泄露按**口令泄露**处置（轮换私钥 + 强制全体改密），不是单纯换钥；轮换须与前端钉扎包一起发布（只换服务端私钥 ⇒ 全部登录被 `PUBLIC_KEY_PIN_MISMATCH` 阻断）。ADR-001 补三条决策记录（PFS 局限 / 钉扎收口 / AAD 绑定与 ENC_INVALID 合并的理由）；`deployment/secret-rotation.md` 补钉扎联动段                                                                                                   |
| dev 链存量 CVE（仅记录，未动） | `npm audit`：生产依赖 0 漏洞，35 个（5 moderate / 30 high）全在 jest 开发链（js-yaml→argparse→sprintf-js 等，经 istanbul 传入）。`npm audit fix` 非破坏性无效；`--force` 仅升 jest@30.5.2（breaking 大版本，559 个套件重度依赖 jest 29 配置与全局 setup）。CI 安全门禁为 `--omit=dev` 口径（生产 0 漏洞即过）。**决策：本次不升级**，建议维护窗口单独做 jest 29→30 并全量验证                                                                                     |

### 补装 login_ecdh_private_key 并修正 loginCipher 的前向保密表述（2026-10-10 · compose 挂了 10 个 secret 唯独漏了登录 ECDH 私钥，轮换手册里这把钥匙的流程从未生效）

> `src/config/secrets.js` 的 `FILE_BACKED_SECRETS` 早已支持 `LOGIN_ECDH_PRIVATE_KEY_FILE`，`scripts/generate-secrets.js` 也一直产出 `login_ecdh_private_key`（P-256 PEM），但 `docker-compose.yml` 从未装配它：app 的 `environment:` 没有对应 `_FILE` 指针，app 服务与顶层 `secrets:` 也没有对应定义。后果是生产部署下服务每次启动惰性生成临时密钥对——`deployment/secret-rotation.md` 里这把钥匙的轮换流程从不生效，且重启前的历史登录密文永久无法解密（做流量取证须在重启前完成）。另修正 `src/utils/loginCipher.js` 头注释：「截获密文的攻击者无法恢复口令」仅在私钥不泄露时成立，静态私钥 + 历史密文 = 明文（无前向保密），注释已补上前提与两种模式的取舍。

| 项           | 内容                                                                                                                                                                                                                                                                                               |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| compose 装配 | app `environment:` 补 `LOGIN_ECDH_PRIVATE_KEY_FILE=/run/secrets/login_ecdh_private_key`；app 服务与顶层 `secrets:` 补 `login_ecdh_private_key`（`file: ./secrets/login_ecdh_private_key`）；头注释手抄清单补 `openssl genpkey` 一条（原「首选」注释里"本清单遗漏"的说法随之失效）                  |
| 注释修正     | `src/utils/loginCipher.js` 头注释把「无法恢复口令」改为带前提的表述：信封自带临时公钥坐标，持静态私钥即可解密任一历史密文（无前向保密）；临时密钥对模式反之——重启前的密文永久不可解密                                                                                                              |
| 契约测试     | `composeProductionContract.test.js`：新变量进 ENV_KEYS 与 fileMap，`/run/secrets/login_ecdh_private_key` 的替身改为真实 EC PEM；新增「文件注入密钥装配三方一致」用例（environment `*_FILE` ↔ app secrets 清单 ↔ 顶层 secrets，且轮换手册点名的文件注入密钥必须全部在装），两类漏法各有一条反向自证 |
| 手册         | `deployment/secret-rotation.md` 的 `LOGIN_ECDH_PRIVATE_KEY` 行后补机制段：经 secret 文件注入，换钥＝随批替换文件后重启；未配置时重启前的密文永久不可解密                                                                                                                                           |

### 下拉浮层边角打磨：表面只画一层（2026-10-09 · 双层表面叠出双边框与错角，边角不圆润）

> 顶栏用户菜单与语言/主题下拉的浮层边角发毛、不圆润。复现定位到根因是**两层表面**：Element Plus 把浮层表面（底色/描边/阴影）画在外壳 .el-dropdown__popper.el-popper 上，还带着 base 的 5px 11px 内边距与 global.css 的 10px 圆角；pple-refine.css 又把表面画在内层 .el-dropdown-menu（12px 圆角 + 1px 描边 + 6px 内边距）。两层半径、描边、内边距全不一致，圆角处叠出双边框与错角。暗色还多一层脱节：html.dark .el-popper 的 --xf-gray-50 实底框围着半透明菜单。

| 项       | 内容                                                                                                                                                                                                               |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 外壳透明 | .el-dropdown__popper.el-popper 的 padding/background/border/box-shadow 全部清空（带 !important），表面只由 .el-dropdown-menu 画一层；箭头是外壳子元素、::before 自带配色，位置不受影响                             |
| 暗色再盖 | html.dark .el-popper 的实底/描边两条声明带 !important 且特异性 (0,2,1) 压过上面的 (0,2,0)，用 html.dark .el-dropdown__popper.el-popper 对 ackground/border 再盖一次，否则暗色菜单四周围一圈 --xf-gray-50 实底框    |
| 箭头同源 | 亮色下拉箭头描边改为跟随菜单的 --xf-border-color（EP 默认取 --el-border-color-light #e4e7ed，箭头根部露一截异色），底色取 EP 给菜单的 --el-bg-color-overlay；依旧不写 !important——placement 的透明边规则必须继续赢 |
| 不变量   | web-admin/src/tests/styles/tooltipTheme.test.js 补两例：外壳透明四件套 + 暗色再盖两条；亮色箭头与菜单描边同源、底色同源 EP overlay，并进「不能带 !important」循环                                                  |

### fail-open 降级补信号 + 持续型告警 + 站点台账门禁（2026-10-09 · 同一个降级动作被复刻 3 份，且全都没有可告警信号）

> 本仓早有明文纪律（`middleware/security.js:763-767`、`middleware/rateLimitStore.js:53-56`、
> `services/websocketService.js:723-725` 三处自陈）：「fail-open 放行必须有显式可观测信号——
> 否则『DB 挂了 + 全站裸奔』只有一条 error 日志可循」「降级态只写日志等于没有可告警信号——
> `grep 日志` 不是运维动作」。**验证码开关这条链没做到**：`isLoginCaptchaEnabled` /
> `isRegisterCaptchaEnabled` 自身没有 try/catch，真正做降级的是调用点，而同一段 try/catch
> 被复刻了 **3 份**（`authService.registerUser`、`authService.resolveLoginPassword`、
> `authController.getCaptchaStatus`），三份都是空 catch、都不发信号。

| 项          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 收口        | 新增 `SystemConfig.captchaSwitch(kind)`：静态默认兜底 + 降级信号只在这一处发生；3 个调用点改为调它，各自手写的 try/catch 删除                                                                                                                                                                                                                                                                                              |
| 新信号      | `captcha_switch_db_fallback`（level `medium`）——验证码只是登录链**前置层**，降级后凭据型限流与爆破检测仍在，故与 `ip_blacklist_failopen` 的 `high` 不同级                                                                                                                                                                                                                                                                  |
| 第二个信号  | `captcha_active_bound_lost`（level `high`）：`captchaService.generate` 在「Redis 已启用但活跃数读取失败」时不设上限放行。**真正的放行点在 `active === null` 而非 `catch`**——`sharedCache.incrWithTtl` 两条降级路径都返回 `null`、从不抛，原先那个 catch 不可达、也永远发不出信号                                                                                                                                           |
| 告警        | 新增 `SecurityFailOpenSustained`（`for: 10m`，critical）。**按 type 分开判、不跨类型求和**：求和会掺进启动期恒正项（`immutableConfigGuard`/`legacyCbcGuard` 进程启动即写 `security_alerts_total`），既稀释真实突发、又让 crash loop 冒充安全事件；**用持续型而非速率型**：`SecurityAlertBurst` 是「10 分钟 ≥10 条」，而 fail-open 的危险形态恰是低速而持续，速率型可以永远不达标                                           |
| 台账 + 门禁 | 新增 `constants/failOpenSites.js`（5 个 fail-open 站点 + 10 个其它信号 + 1 个转发点，逐条声明 `direction/trigger/effect/why/tightening`）与 `tests/ci/failOpenLedgerGate.test.js`（8 例）：代码里的静态站点 ⇄ 台账条目双向闭合；每条 type 必须被持续型规则覆盖（**登记信号 ≠ 接上告警**）；反向也拦（规则点名不存在的 type 要红）                                                                                          |
| 刻意不做    | **不自动收紧**。把 fail-open 自动翻成 fail-closed 会把「保密性降级」转成「可用性事故」，且恰好发生在系统已经不健康时（黑名单 fail-closed = 库挂时全站请求无法验证；验证码 fail-closed = 没人能登录）。是否收紧是产品决策，不是告警规则能代做的                                                                                                                                                                             |
| 用例        | 新增 `tests/services/failOpenSignals.test.js`（11 例，含反向对照：两个 type 必须真能渲染进 `formatPrometheus()`）；`authControllerOutcomes.test.js` 的两条 `getCaptchaStatus` 重写到新接缝并**补前提自证**（断言真的调了 `captchaSwitch`）——原写法在该文件的 `../../models` 部分 mock 下会因 `captchaSwitch` 是 `undefined` 抛错、被兜底网吞掉而"通过"，等于在断言静态默认值                                               |
| 文档        | `README.md` 新增「开发/预览服务器的暴露边界」：dev 与 preview **都**绑 `0.0.0.0`，dev 下发**未打包源码**而 `src/**` 不在敏感文件黑名单内 ⇒ 禁止把 3001 发布到公网；`docs/threat-model.md` §3 增第 5 条（明确标注「仅开发期、不构成生产面」）；`docs/incident-response.md` §2 增「护栏失效信号」一条（该规则触发时，「没看到拦截」不能当作「没被攻击」的证据）。顺带修正 `README.md` 已过期的「4 条内置告警」（实为 13 条） |
| 锚点迁移    | 本轮删行使 `authService.js` -7 行、`authController.js` +13 行，全仓 **32 处**注释锚点随行号迁移（逐条按「迁移后该行内容 == 迁移前该行在 HEAD 的内容」核验）；`bareAnchorAttribution.test.js` 的回指台账两处坐标同步随迁。另修正 `statsAnomalyScope.test.js` 一处**本就指错**的锚点（写 `securityController.js:284`，而 `getSecurityStats` 实为 `:317`）                                                                    |

### 顶栏入口提示统一走 Element Plus 浮层 + 浮层箭头主题适配（2026-10-09 · 语言/主题图标此前挂的是浏览器原生 title）

> 顶栏语言/主题入口把提示写在 `el-icon` 的 `:title` 上，走浏览器原生提示——样式、字号、圆角与出现时机全由浏览器决定，和搜索/刷新/全屏的 `el-tooltip` 浮层是两套观感。本批把两处统一成 `el-tooltip`；顺着这条线查浮层配色时，又发现 Element Plus 的箭头是**独立元素**、取的是另一套变量，仓库只改了浮层底色，亮/暗两个主题下尖角都露着异色（暗色下拉菜单甚至挂一块异色三角）。

| 项       | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 统一提示 | `web-admin/src/layout/index.vue`：语言/主题的 `el-icon` 去掉 `:title`，外面套 `el-tooltip`（`placement="bottom"`，与搜索/刷新同规格）。**不能**反过来把 tooltip 塞进 `el-dropdown` 里——`el-tooltip` 的根是 `ElPopper`（`inheritAttrs: false`），dropdown 经 `ElOnlyChild` 下发的 `role`/`tabindex`/`id`/`aria-*` 与 forward-ref 会在那一层被吃掉，下拉直接点不开（实测：菜单浮层不再出现）                                                                                                                                                                                                                                                                                                                                       |
| 防叠放   | 下拉展开期间用 `:disabled` 收起提示：菜单浮层与提示浮层同位叠放会互相盖住，而展开时指针停在图标上不产生 `mouseleave`，提示不会自行消失。状态由 `@visible-change` 回写，两个入口互斥共用一个 ref                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 箭头同色 | `apple-refine.css` 新增四条 `.el-popper__arrow::before` 规则（亮色 tooltip / 暗色 tooltip / 暗色下拉菜单 / 暗色 `.is-light`，末条见「续修」），底色与描边逐一对齐浮层。箭头规则**不能**加 `!important`：朝浮层的那两条边由 EP 的 placement 规则置 `transparent`，那条规则带 `!important` 必须继续赢，否则旋转 45° 的方块会露出实心方角                                                                                                                                                                                                                                                                                                                                                                                           |
| 暗色描边 | `html.dark .el-popper.is-dark` 补上自己的 `border`：原先不写，暗色边悄悄吃亮色那条 `.el-popper.is-dark` 的边（两条特异性相同、后者在源流里更晚），改亮色配色会把暗色一起带跑                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 用例     | `web-admin/src/tests/layout/layout.test.js`：定位辅助从「按 title 找图标」改成文件原有的图标 path oracle（title 已不存在）；新增 `布局 · 顶栏入口悬停提示` 四条——顶栏图标一律不留原生 title、语言/主题悬停出 EP 浮层且文案走 i18n、下拉展开期间只剩菜单浮层。`web-admin/src/tests/styles/tooltipTheme.test.js`：读 CSS 源码比对「箭头与浮层同色」+ 箭头规则不带 `!important`，两条变异（箭头改回白、箭头加 `!important`）均能测红；续修新增两例——「暗色 date-picker 箭头与 `html.dark .el-popper` 实底同色」（表面规则在 dark.css，测试改读两个样式文件）与「`.is-light` 规则必须 `:not(.el-dropdown__popper)`」（特异性 (0,5,2) 高于下拉箭头规则 (0,3,2)，不排除会把半透明下拉箭头打成实底），第三种变异（删掉 `:not`）同样测红 |
| 续修     | 暗色 `.is-light` 浮层（`el-date-picker`，经 `ElTooltip effect="light"` 带 `is-light`）的箭头补上 `--xf-gray-50`/`--xf-border-color`：EP 的 `.is-light` 箭头取 `--el-popper-bg-color-light`（=`--el-bg-color-overlay`，EP 暗色 `#1d1e1f` 中性灰）与 `--el-border-color-light`（`#414243`），与 `#0f172a` 表面对不上。选择器必须 `:not(.el-dropdown__popper)`：下拉菜单表面是半透明 `rgba(30,41,59,.95)`，而 `.is-light` 规则特异性更高，不排除会把下拉箭头一起打成实底。`el-select` 浮层不渲染箭头，无需处理                                                                                                                                                                                                                      |

### 弱口令黑名单：匹配器口径修复 + 词干表扩充（2026-10-09 · 原 40 条里 24 条永远命中不了）

> 本批**不改依赖、不引入外部服务**。改的是「清单里的条目到底能不能被命中」。
> 旧实现是 40 条**口令字面量**，而归一化只做「末尾 ≥4 位数字收敛为 3 位」且**只归一化
> 口令侧**——两侧口径不一致的后果：实测 **24 条永远命中不了**，有效字典只有 **16 个词干**，
> 而文件看起来有 40 条。`helpers.test.js` 断言 `isBreachedPassword('admin@123') === true`
> 也是误导性的：生产路径上黑名单排在长度/复杂度之后，9 位口令根本走不到黑名单。

| 项       | 内容                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因     | **匹配器与数据口径不一致，不是数据错**。清单里 `passw0rd!` / `p@ssw0rd` / `1qaz@wsx` / `abcd1234!` 这种写法本身就说明作者意图是「按词干匹配」；而旧匹配器要求字面量全等。死条目分两族：①8~11 位条目先被长度规则拒掉；②以 ≥4 位数字结尾的条目永远不等于任何口令的归一化结果                                                       |
| 改法     | 表改为**词干**（`constants/breachedPasswords.js`，40 条字面量 → 123 条词干）；归一化只保留一份且在口令侧：小写 → 去所有非字母数字 → 去末尾连续数字。两侧口径因此不可能再漂移                                                                                                                                                     |
| 不变量   | 每个词干至少含 2 个字母。这是**必要条件**：归一化不重排字母，故口令的字母序列（小写）必须等于词干的字母序列，而策略要求同时含大写与小写 ⇒ 字母数 <2 的词干在策略下不可达                                                                                                                                                         |
| 覆盖变化 | 有效词干 16 → 123（**+107**）；`Passw0rd!1234`、`P@ssw0rd1234!`、`Abcd1234!5678`、`1Qaz@Wsx1234!` 等由漏变拦；精度用例同时钉住 12 条强口令不被误伤（`SunshineRain99!` 归一化后是 `sunshinerain`，不是词干）                                                                                                                      |
| 用例     | 新增 `src/tests/utils/breachedPasswordMatcher.test.js`（176 例）：逐条为 123 个词干构造「除黑名单外无懈可击」的反例并断言被拦；表内条目必须已是词干（混入字面量即红）；回归指纹；精度；边界；原 16 条不回退                                                                                                                      |
| 失败策略 | 本批**不接** HIBP。若将来要接，失败策略**已预先拍板**：**fail-open + 指标 + 启动日志告警**，且必须带超时与缓存——不让第三方可用性拖垮改密链路                                                                                                                                                                                     |
| 文档     | `docs/mlps2-controls.md` 的 G8 证据补上「清单规模 + 用例文件」，并新增一段**如实边界声明**（是高频词干表，不是泄露库；长尾覆盖不了）；`breachedPasswords.js` 文件头修正「以隐私为由拒绝 HIBP」的**不完整推论**（原话本身准确：range API 确实只收 SHA-1 前 5 位；但真正有分量的理由是多一个运行时外部依赖及其失败策略，原文没写） |

三处测试夹具注释同步更新（`authCookies.test.js` / `changePasswordTypeGuard.test.js` /
`sessionManagement.test.js`）：导出名 `BREACHED_PASSWORDS` → `BREACHED_PASSWORD_STEMS`，
且 `Test@12345 归一化后为 test@123` 的解释已不成立（现在一步归一化成 `test`）。
三处夹具口令均经 `deliverables/probe-matcher-behavior.js` 复核为新口径下的安全值。

### IP 归属地英文化（2026-10-09 · 私网/环回地址的 `location` 从中文文案改为稳定码）

> 缺陷形状与 `constants/securitySuggestions.js` 那次同族：**后端把文案拼死，前端就永远翻不动**。
> `ipLocationService` 把私网/环回地址收敛成中文两字「内网」直接下发，而三个消费面
> （会话管理、审计日志列表 + 详情弹窗、IP 黑白名单）都是 `· {{ row.location }}` 原样渲染——
> 管理员把界面切到 en-US，IP 旁边那一格仍是中文。公网 IP 的归属地是 ip2region 数据文本
> （「中国·广东省·深圳市·电信」），不在本次范围：数据侧本地化是另一个议题。

| 项     | 内容                                                                                                                                                                                                                                                                                                                                             |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 根因   | 展示文本由后端拼好并焊进 API 响应：私网这一支既非数据也非用户输入，而是**服务层自己写死的中文**，vue-i18n 对已定型的字符串无从下手                                                                                                                                                                                                               |
| 修法   | 沿用仓内既有口径（`utils/labelMaps.js` 的 DEVICE_TYPE、`utils/auditLabels.js` 的 `audit.action.*`、`constants/securitySuggestions.js`）：**后端只出稳定码，文案归前端词表**。新增 `src/constants/ipLocationCodes.js`（单一来源，当前一码 `private`），`ipLocationService` 的 IPv4 数据侧（xdb 的「内网IP」）与 IPv6 range 判定两支都改为产出该码 |
| 前端   | 新增 `web-admin/src/utils/ipLocationLabels.js`（三处消费方共用一份映射，与 securityLabels/auditLabels 同形状：调用方传 `t`、未知值原样透传），词表新增 `ipLocation.private`（zh「内网」/ en "Internal network"）                                                                                                                                 |
| 兼容性 | `location` 类型不变（string\|null）；老后端下发的中文「内网」按原样透传（与修复前一致，不回退成空白），滚动发布不会出现空归属地                                                                                                                                                                                                                  |
| 对账闸 | 新增 `web-admin/src/tests/utils/ipLocationCodeParity.test.js`：`createRequire` 后端码表逐一对账双语词表，并断言英文侧不得残留 CJK——「后端加一码、前端漏翻」变红，而不是在界面上静默显示裸码                                                                                                                                                      |
| 用例   | 后端 `ipLocationService.test.js`（私网取值不含中日韩字符）、`sessionService.test.js`（内网 IP 两字段均为稳定码）；前端三个视图各补一条「切 en-US → Internal network、公网数据文本原样」的语言跟随用例                                                                                                                                            |

### IP 归属地英文化·续（2026-10-09 · 公网归属地的中英对照词典：数据段也跟随界面语言）

> 上一节只解决了「内网」那一格（后端写死的中文）。公网 IP 的归属地是 ip2region xdb 的
> **数据原文**——库里只有中文一份，于是切到 en-US 后「中国·浙江省·杭州市·阿里云」照样是中文：
> 实测全部地区段里 **89.9% 的出现次数是中文**，只修私网标签等于修了个零头。

| 项     | 内容                                                                                                                                                                                                                                                                                                                              |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 修法   | 新增 `web-admin/src/data/ipLocationDictionary.json`（1024 条中英对照）；`utils/ipLocationLabels.js` 按当前 locale **逐段**译名后以 `·` 重拼，词典未收录的段原样透传（不把整块归属地抹掉）。语言判定读 i18n 实例的 locale（非中文界面一律英文），渲染期读 ref 即建立响应式依赖，切语言重算                                         |
| 词典   | 国家名 244 条由 `Intl.DisplayNames` 按 ISO 3166-1 **双向生成**（zh 键 ↔ en 值，不手抄 244 条）；省州 / 城市 / 运营商人工校对。实测覆盖 CJK 出现次数 **98.06%**（国家 100%、省州 98.6%、城市 93.2%、运营商 96.7%）                                                                                                                 |
| 豁免   | 10 条高频段登记未收录（`内网IP` + 9 个译名不确定的段），理由逐条写在测试里，**上限 12 条**且每条键必须仍在数据里。口径：宁可以英文界面回退中文，也不把没把握的译名写进词典——**错的译名比中文更难发现**                                                                                                                            |
| 闸     | `web-admin/src/tests/utils/ipLocationDictionary.test.js` 直接对**真实 xdb** 取数（复用后端 `loadFromBuffer` 解析指针，只补段索引遍历）：国家/省州 100%、城市/运营商高频段（出现次数 ≥ 阈值）除登记豁免外全覆盖、整体覆盖率 ≥ 98%、词典无陈旧键、译文不含中文、豁免不越上限。数据刷新带入新地名 ⇒ 测试列出缺哪些，而不是靠用户发现 |
| 体积   | 词典经三个懒加载视图进入**异步分块**：首屏 `entryJsGzip` +1.1 KB，总 gzip +19.4 KB；五项预算均仍有余量（`check-bundle-budget` 通过），基线未动                                                                                                                                                                                    |
| 兼容性 | `location` 契约不变（仍是 string）；中文界面行为零变化（数据本就是中文，不过词典）                                                                                                                                                                                                                                                |

### 依赖审计：dev 树盲区补门禁（2026-10-09 · `security-audit` 只审 `--omit=dev`）

> 本批**不改依赖树**。改的是「谁在被审」：CI 两处 audit 都是 `npm audit --omit=dev`，
> 于是 devDependencies 的 advisory 永远不会让构建失败。实测含 dev **35 条（30 high / 5 moderate）**，
> `--omit=dev` 为 **0**，web-admin 两侧均为 0。

| 项                 | 内容                                                                                                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因               | 35 条包维度告警**只由 2 条公告**传染而来：`GHSA-vfj7-8cjw-p6xm`（braces，high，栈耗尽 DoS）与 `GHSA-hp3w-g68c-fv3c`（sprintf-js，moderate）                                                                                                                 |
| 为何不能 overrides | 两条公告的 `first_patched_version` 均为 **null**，受影响区间上界就是 registry 的 latest（braces 3.0.3 / sprintf-js 1.1.3）⇒ **无版本可指向**，与 uuid override 的前提不同                                                                                   |
| 为何不升 jest 30   | 实测（隔离探针）：jest 30 + nodemon = 3 high / 19 moderate；jest 30 去 nodemon = 0 high / 19 moderate。**moderate 反而由 5 升到 19**，且清不掉 `js-yaml@3 → argparse@1 → sprintf-js` 链                                                                     |
| 可达性             | 两条链实测**不可达**：braces 需攻击者可控 glob（本仓输入只有 jest CLI/config 与 nodemon ignore）；argparse 只被 `js-yaml/bin/js-yaml.js` 引用，`load-nyc-config` 走 `lib/js-yaml.js` 不加载它 ⇒ 性质是卫生问题，非可利用漏洞                                |
| 改法               | 新增 `scripts/check-audit-allowlist.js`（含 dev 审计**硬门禁 + 显式允许清单**）+ `deployment/audit-allowlist.json`（登记两条无补丁公告，含理由/可达性/复核期限 `2027-01-31`）；`ci.yml` 的 `security-audit` 作业新增一步；`ciGateWiring.test.js` 登记新门禁 |
| fail-closed 三判据 | ①未登记 ⇒ 红；②`reviewBy` 过期 ⇒ 红；③清单项在本次报告里**已无对应公告** ⇒ 红，必须删行（防清单只增不减）                                                                                                                                                   |
| 文档               | `docs/security-dependency-watch.md` 修正「含 dev 0 漏洞」的过期结论（该结论是 2026-09-16 时点，上游 09-18 / 09-24 才发公告 ⇒ 时间性回归，非本批引入），并登记两条已知例外                                                                                   |

判据来源是**根因公告**而非受影响包（35 条 = 2 条根因），故清单按 GHSA 编号登记，
不按包名——按包登记必然得到一份腐烂清单。

### CI 覆盖率门禁修复（2026-10-08 · `#13 Run tests with coverage` 三条阈值未达标）

> 这条红**不是**本批引入，而是被下一节的修复**逼出来的**：`#11 Run tests` / `#12` 修绿之前，
> `#13` 每轮都被前序 step 的失败 skip/cancel，从未真正执行。根因是 `ccddabc`
> （2026-10-03 并行会话批次）给两个文件新增了**从未被执行过**的函数/分支，
> 而阈值是 2026-09-04 / 2026-09-30 定的。

| 文件                             | 阈值（fn/br） | 修复前实测                 | 根因（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                                                                                                                    | 改法                                                                                                                                                                                                                                                                                    |
| -------------------------------- | ------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/middleware/auth.js`         | 90 / 87       | fn **87.5%**               | `ccddabc` 给 `invalidateUserCache` 补了 `publishInvalidate(...).catch((err) => …)`，函数数 15 → 16（14/15 变 14/16）。覆盖它的 `roleStatusInvalidatesUserCache.test.js` 把整个 `invalidateUserCache` `jest.mock` 掉了，只断言"被调用"，从不碰函数体                                                                                                                  | `observabilityWritesNeverReject.test.js` 新增 L7：三种拒绝形态（Error / undefined / 无 message 对象）下断言不抛 + warn 文案逐字。注：该键是 `auth:user:`；同一调用链上 `userPermissionService` 还会广播一条 `permcache:` 键（`userPermissionService.js:191`），故判据按前缀点名而非计数 |
| `src/services/deviceReminder.js` | 97 / 90       | fn **90%** / br **86.79%** | 调度器里两处 `markOverdueInspections().catch(...)`（`ccddabc` 新增）从未执行。**且普通 DB 故障驱动不了它们**——`markOverdueInspections` 整段体在 try/catch 内、**永不 reject**，这两条箭头是**第二道防线**，只在第一道被破坏（内层 catch 体自身抛错）时才生效。第一版用例正是用 DB 故障驱动的，实测 `logger.error` 只收到内层那条 `巡检逾期标记失败：…`，箭头一次没跑 | `deviceReminderScopeIsolationGuards.test.js` 新增 2 例：让**内层** `logger.error` 抛错以打断第一道防线，两种形态（Error / undefined）各一条，把 `${err?.message ?? err}` 的两条路径都走到                                                                                               |

**为什么是补测试而不是下调阈值**：`jest.config.js` 有明确纪律「每条阈值 = 实测下方 5pt(分支) / 3pt(函数)，
只紧不松」；2026-09-30 那次 auth.js `functions 97 → 90` 是**修正推导错误**（原值按"实测 100%"机械套用，
真值 93.33%，那条 setInterval 回调是刻意不覆盖的）。本批两处缺口**都可以被行为用例覆盖**，
所以按同一纪律应补测试。

修复后实测（全量 `jest --coverage`）：`auth.js` 函数 **100%** / 分支 **92.59%**；
`deviceReminder.js` 函数 **100%** / 分支 **94.33%**——两项阈值均达标。

复跑事实：两套件 `jest <两个文件>` **40/40 通过**；`jest src/tests/ci/ --runInBand` **15/16 通过**
（`testTreePurity` 因 `execFileSync('git')` 被本机沙箱拦而红，与下一节同一条环境性假红，
该套件只判"测试文件是否入库"，不涉及本次改动）。

### CI 真红修复（2026-10-08 · `test` 腿两条既有红：断言读错流 + 循环复用夹具撞秒级归档名）

> 两条在基线 run `37711343020`（`b7834f1`，本批之前）上**逐字相同** ⇒ 既有红，非本批引入。
> `security-audit` 腿已由 `5ab7e91` 修绿（上游 2026-10-05T22:50–23:31Z 一次批量公告刷新，
> `compression` / `proxy-addr` / `source-map-js` / `@vue/server-renderer` 四条与本仓依赖面无关），
> 此后只剩这两条挡住 `test (20.x)` / `test (22.x)`，并连带 `build` 被 skip。

| #   | 缺陷（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                        | 改法                                                                          | 证据                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `imageDigestGate.test.js` 的 SIGTERM 用例把 `d.stdout + d.stderr` 拼成一个串再断言 `/RC=143$/`。驱动脚本的 `printf "RC=%s\n"` 走 stdout，而 `wait` 被信号打断时 shell 把作业终止语写**自己的 stderr** ⇒ 拼完是 `"RC=143\nTerminated"`，`$` 锚点恒不成立                  | rc 只认 `d.stdout`；`printed` 保留，继续用于「不得出现 KILLFAILED」的否定断言 | 用 dash（CI 的 `/bin/sh`）跑同一个驱动脚本：stdout=`RC=143`、stderr=`Terminated`                                                    |
| ②   | `backupFailureArtifactHygiene.test.js` 的三轮 `for (const blank of [...])` 复用 `beforeEach` 的同一个夹具。归档名只到**秒**，而"只含空白"的判据落在异地副本那一步（加密归档已定稿落盘）⇒ 第 2 轮同秒撞名，先命中「目标加密归档已存在，拒绝覆盖」，断言变成在测另一条判据 | 每轮自建 `mkwork()`、`finally` 拆掉，三条之间只差 `blank` 一个变量            | 固定时间戳的 `date` 替身把"同秒"从偶发变确定性：共用夹具第 2 轮复现出与 CI 同形的「拒绝覆盖」；每轮新夹具三轮全部「只含空白」+ rc=1 |

为什么本地一直没暴露：两套件都是 shell-out 型，本机 `spawnSync` 对任何可执行文件返回 `EBUSY`
（逐 host 探针 `status=null` / `error=EBUSY`），本地根本跑不到断言。另有一条会误导归因的环境差异：
本机 `rm` 被安全包装器接管，单次约 10–13 s，把单轮备份脚本从 CI 的亚秒级拖到 **31 s**——
"本地复现不出同秒撞名"正是这个延迟造成的。

复跑事实：`prettier --check` 两文件通过、`eslint` 两文件 RC=0、`jest src/tests/ci/ --runInBand`
**15/16 通过**（`testTreePurity` 因 `execFileSync('git')` 被 EBUSY 拦而红，属环境性假红，
且该套件只判"测试文件是否入库"，不涉及本次改动）。

### 运维脚本 E（2026-10-04 · 备份/恢复/密钥生成的失败面：容器侧那段命令第一次被真跑一遍，收紧失败第一次非零退出）

> 这一族的形状全都一样：**成功回显与失败信号在出口处不对账**。备份脚本对"一条都没跑"的异地命令
> 回显"已完成异地副本"；容器侧对一份 0 字节归档返回 0 并打印 `Restore completed successfully`；
> 密钥生成对"11 个文件一个都没收紧"照样退 0——三处都把没做过的事记成了做过。
>
> 方法上是本仓第一次让 `docker` **桩真的执行**容器侧命令（把 `-c` 后面那段交回 bash，容器内的
> `mongodump`/`mongorestore` 由 PATH 上的桩充当）。此前所有 docker 门禁只记 argv 与 stdin，
> 于是容器侧那七八行的缺陷谁都不判——注释里"用完即删""不落盘"都是没有实物的一句话。
> 新增断言一律配**前世版自证**（把脚本副本还原成修前形态，证明断言真能红）。

已落地：

| #   | 缺陷（读源码确认，非推断）                                                                                                                                                            | 改法                                                                                                                                                                 | 门禁（行为级，不是 grep）                                                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `backup-mongo.sh` 在 `case` **之前**无条件 `mktemp + 写入含口令的 URI`，而 docker 传输（默认）从头到尾没人读它 ⇒ 每次备份都在宿主盘上留一份 0600 明文口令                             | 配置文件挪进 `local` 分支按需创建；docker 分支只经 stdin 送 `uri:` 行                                                                                                | `backupFailureArtifactHygiene` C.1：docker 跑完 `"$TMPDIR"/*` 里**一个** `^uri: ` 结构的文件都没有；反向对照 local 恰好探到 1 个                                                                                                                                                               |
| ②   | 备份侧容器内路径写死 `/tmp/.mongodump-backup`，且 `cat`/`printf` 不判返回码（与 peer 已修的恢复侧同源）                                                                               | `mktemp` + 每步 `                                                                                                                                                    |                                                                                                                                                                                                                                                                                                | { rm -f "$cfg"; exit 1; }` | C.1 的 `DOCKER .*exec -T mongo sh -c` 自证 + 断言 argv 上没有口令字面量 |
| ③   | `BACKUP_OFFSITE_CMD` 含换行/回车时按"一条命令"解析只执行**第一行**，却把整份配置回显成 `Offsite copy completed` ⇒ 多行 env、CRLF 写的 env、误粘两条命令三种现场都记账为"异地副本已做" | 执行前拒绝（一条都不跑），并把 `\\r` 的 CRLF 出路点名                                                                                                                | C.2 三腿：多行/内嵌 `\\r` ⇒ rc≠0 且桩一次都没被调用、归档不被动；尾随单个换行 ⇒ 仍放行且回显文本逐字节等于那条命令（正向对照，防过度收紧）                                                                                                                                                     |
| ④   | `generate-secrets.js` 逐个收紧密钥文件时**丢弃返回值**，且目录级复核不通过也只 `console.log` 后 `exit 0` ⇒ `generate-secrets … && 下一步` 在密钥仍可被本机其他用户读写时继续推进      | 收返回值聚合成 `fileFailures` 点名清单；`check.tightened && fileFailures.length === 0` 之外一律 **非零退出**；产物保留不删（内容有效，毁掉只会把运维推向手搓随机值） | `filePermissionEnforcementAndVerify` 新 describe 5 腿：`node -r <preload>` 把 `src/utils/filePermission` 顶成可编程桩（真实宿主造不出"icacls 被拒"），目录失败/复核失败/仅文件失败三档各钉 rc=1 + stderr 点名 + 成功文案缺席；**前世版腿**：删掉返回值检查的副本在同一份桩下 rc=0 还打印成功行 |

同批的"探针"改造：宿主机凭据落点的探测从**按文件名**（`mongorestore-config.*`）改成**按内容结构**
（首行匹配 `^uri: `），与本批次前 peer 在 `restoreTransport.test.js` 里立的同一把尺子对齐——按名字探的是
"祸害叫什么"，改名即失明。

**押后（本轮不入库，见下方协调项）**：`restore-mongo.sh` 的两条同族修复——⑤ `RESTORE_SKIP_CHECKSUM=true`
把"哈希对不上"一起豁免（该开关的原意是"恢复本来就没有校验和的老归档"，实现出来却允许把一份已知损坏/
被替换的归档写进生产库；前者缺的是证据，后者是**反证**）；⑥ 容器侧固定名 + 不判返回码 + 0 字节归档被记成
一次成功恢复。改动与门禁都写好了并且是绿的（`backupEncryptionContract` 新增 3 腿 + 新文件
`restoreRemoteHardening.test.js` 7 腿，后者让 docker 桩执行容器侧命令，配 canary 预创建、两次运行路径互不相同、
0 字节拒收、空 stdin 停在 `read` 四个面，外加前世版翻转腿），但 ⑥ 撞上一条**已在 HEAD 里**的 peer 门禁：
`src/tests/deploy/restoreTransport.test.js:185` 字面钉死 `rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive`。
该文件的意图（"容器侧凭据用完即删"）在 mktemp 形态下依然成立，字面却必然失效；而它在我的改动范围之外，
工作树里还叠着同一位 peer 未提交的探测器改造——按行拆开提交做不到，于是整条 ⑥（连带只依赖它的 ⑤ 与两份测试）
押后，等那条字面 pin 换成判 `rm -f "$cfg" "$arch"` 之后单独入库。

协调项（交给并行会话或下一批）：

1. `restoreTransport.test.js:185` 的字面断言改成结构判据（清理了 `cfg`/`arch` 两个变量，而不是清理了某两个名字），
   随后 `scripts/restore-mongo.sh` + `src/tests/deploy/{backupEncryptionContract,restoreRemoteHardening}.test.js` 一起落地。
2. `deployment/backup-encryption.md` 里 `RESTORE_SKIP_CHECKSUM` 的口径要与 ⑤ 同步（文档现在描述的是"整段跳过"的旧语义）。

复跑事实：`src/tests/deploy` + `src/tests/security` 全量 **755 passed / 8 failed / 763**，两条红点各有其主——
`bundleBudget.test.js` 7 条是真实 `web-admin/dist` 的 `entryCssGzip 21900 B > 预算 19000 B`（并行会话新增
`apple-refine.css` 后重建产物而未重置基线，本批未碰任何前端文件）；`restoreTransport.test.js` 1 条即上面 ⑥。
本批相关 5 个文件 **67 passed**。`npx eslint src scripts --quiet` 0 项、`lint-ratchet` 通过（21 个含 warn 文件
均未超基线）、`check-utf8` 全绿（1061 个文件）、`prettier --check` 对改动文件全部通过。

### 供应链 D（2026-10-04 · 上一批的 21/21 变异矩阵被独立审计复跑出 9 条存活变异：逐条封红，并把"只有真实数据全对才绿"那一族补成夹具可证伪）

> 上一批自己写的变异矩阵（9+12 条）判的是"解析器/流程被改坏会不会漏"，但**漏掉了另一族**：
> 判据的输入在仓库里恰好是"全对"的，于是任何**削弱比较本身**的改动都没有实物能打红。
> 独立审计员逐行复跑后点名 9 条存活变异（下表 M/D 编号），其中两条正是"防投毒"链条上最关键的位：
> `repo` 判据放行了官方镜像的裸短名（第三个来源静默退化成两源），以及打印面把**硬报错**算进"可用"。

九条存活变异与本轮的封堵（每条都配了 arm，见下面矩阵）：

| 编号 | 原缺陷（存活原因）                                                                                                                                                   | 本轮改法                                                                                                                                                                                        |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M9   | `expect([shortName, 'library/'+shortName]).toContain(e.repo)` 二选一 ⇒ 官方镜像登记成裸短名照样绿，而 ECR 的 `map()` 靠 `library/` 前缀判托管 ⇒ "三源一致"悄悄变两源 | 改成 `repo` 由 `ref` **唯一决定**的 `toBe`；再加"声称用过 ECR ⇒ `map()` 必须给得出路径"的 ③ 号腿                                                                                                |
| M6   | digest 对账写成"长度不同才不符"仍全绿（表与文件全等，判据无实物）                                                                                                    | 对账逻辑抽成纯函数 `reconcile(refs, table)`，用**同长度、末位不同**的夹具 digest 直接打红；孤儿/陈行/不符三类各钉独立断言                                                                       |
| M7   | `sources`/`sites` 两列只判"非空" ⇒ 改成任意假话都绿                                                                                                                  | 新增一条可证伪用例：散文里所有像主机名的 token 必须**恰好等于**来源表里被点名的集合；点名数 ≥2；ECR 声称⇔可映射；`sites` 与扫描面**逐文件双向**对齐（多说不说都红）；引用点总数 `[1,1,1,1,2,3]` |
| M2   | `--only ,` ⇒ `split/filter` 得空数组（JS 里为真值）⇒ 六行全被排除 ⇒ 打印"核验 0 个引用 … 全部通过"退 0                                                               | 抽纯函数 `planRuns(argv, table)`，命中 0 行 ⇒ **退出码 2** 并点名"拒绝把空跑报成通过"                                                                                                           |
| M3   | `tag = ref.slice(ref.indexOf(':')+1)` 与 `lastIndexOf` 在真实六行上无差别（都只有一个冒号）                                                                          | 抽 `tagOf(ref)` + 端口夹具（`reg.example.com:5000/team/app:1.2.3` ⇒ `1.2.3`），另钉"真实六行切出的 tag 不含斜杠也不含冒号"                                                                      |
| D6   | 非 JSON 响应体走 `JSON.parse` 的原生异常文本 ⇒ 响应体前若干字符进日志（违反"外部响应体一律不回显"）                                                                  | `try/catch` 包住，报错只说"响应体不是 JSON（N 字节，内容未回显）"；用例同时钉 `not.toMatch(/<html>/)`                                                                                           |
| D13  | 打印面 `可用 = 非跳过的来源数` ⇒ **HTTP 500 / 非 JSON 的硬报错被算进"可用"**，`2/3（可用 3）`是给读者的一句话谎言                                                    | 分母改成 `应答`（拿到摘要的来源数），另起两位 `跳过 N，报错 1`；报错行前缀写"报错："。用例直接断言整行文本                                                                                      |
| D10  | `isIndex` 的 `every` 改成 `some` 存活（夹具只喂过"两条都单层"）                                                                                                      | 新增混合腿（一条 index + 一条单层）**两种顺序各判一次**：`ok` 必须 false，而 `agreeCount` 仍为 2（判据①与③不许混成一团）                                                                        |
| D5   | `judge` 不透传 `bytes` 时输出念 `undefined 字节`/`0 字节`，而用例只判 `/(\d+) 字节/`                                                                                 | `bytes` 过一道；断言改成**真实字节数**（"对返回字节自算 sha256"这句话唯一的实物证据就是它）                                                                                                     |

同批补强的三处（审计员另外点名的"判据依赖仓库内容配合"）：

- `workflowFileNames(names)` 从 `targetFiles()` 抽成纯函数并喂夹具：`.yaml` 分支在本仓**没有实例**，
  真实扫描面证不了它没写错；同时钉住"排序与 `readdirSync` 顺序无关"与噪音后缀（`yml`/`ci.yml.bak`/`x.YML`）。
- 永真断言替换：原来那条 `all.some(r => /<64 位 hex>|<捕获值>|示例/.test(r.value)) === false` 不可能红
  （扫到的 value 全都过了解析器）。改成**否定语料自证**：注释里带 `@sha256:` 的行按文件精确计数
  （Dockerfile 3 / compose 2 / deploy.yml 1），并断言它们既不进 `all` 也不进 `unreachable`——
  compose 的 mongo 段那条**反引号包裹的 `image: …<捕获值>`** 正是"注释排除一删就红"的实物。
- 替身自己也进判据：`resp()` 的大小写归一化在**存/取两面**各钉一条直接断言（删任一半就有用例红），
  外加 `ok` 的算法（404 false / 201 true）。上一轮的"header 各种大小写都要读得到"只在此之上才有意义。

退出码外壳（`process.exit(code)` 那一层）第一次进了门禁：`main(argv, table = EXPECTED)` 与
`planRuns(argv, table = EXPECTED)` 都接受表注入，于是"表本身写坏"与"命中 0 行"这两档在**触网之前**
就能被夹具判（真实仓库里表现在是好的，少这个注入点这两条分支永远走不到）；再用 `spawnSync` 真跑三次
脚本判 2 号路径的退出码与 stderr 文案，把"返回值→退出码"的接线也钉住（挑的都是不联网的分支，
所以门禁仍然离线）。

变异矩阵 **22 条 arm = 21 CAUGHT + 1 条刻意负对照**（`/c/tmp/mut-d.js`，跑完四个文件 sha1 逐字节还原）：
判据侧 arm（空跑守卫、`return plan.code`、`process.exit(code)`、`indexOf`、非 JSON 回显、分母把报错算进来、
`every→some`、`bytes` 不透传、下限归零、替身存/取不归一化 ×2）+ 数据侧 arm（官方镜像裸短名、
第三方命名空间被加 `library/` 前缀、表内 digest 末位改一位、`sites` 指错文件、`sources` 编造来源名、
声称用了 ECR 但其实不托管、compose 退回裸 tag）+ 闸自身（注释排除、对账退化成比长度、`.yaml` 分支）。
唯一一条"预期存活"是**负对照**：把 `repo` 判据退回二选一并同时喂"第三方命名空间被加 `library/` 前缀"
这条数据缺陷 ⇒ 13 条全绿，用来证明严格版 `toBe` 是唯一能抓它的判据，而不是装饰。

复跑事实（不联网的闸与联网的工具各一次）：`node scripts/verify-image-digests.js` 6 引用全 PASS、
**退出码 0**；本轮 `docker.1ms.run` 起效后 redis/mongo 为三源一致；`public.ecr.aws` 对 redis/mongo
仍**不发** `Docker-Content-Digest`（三态输出的实证），对 node 这一次直接 `fetch failed`——输出如实念成
`一致来源 2/2（跳过 0，报错 1）`，旧写法这里会念"可用 3"。散文里的取证数字第一次可复核：
`index 7 个条目`（mongo）与 `index 3 个条目`（grafana）与实测一致，其余来源逐条打印条目数与字节数。

未收（诚实清单）：

- `captured` 仍是人手写日期，闸只判形状。本批把 `sources`/`sites` 变成可证伪，但**取证日期**没有
  仓库内可对齐的事实来源（对表情的最硬约束是：某行 `sources` 写了 `public.ecr.aws` 而该 repo 在
  ECR 上不存在 ⇒ 红，见 ③）。
- "来源表三条腿全活"不是判据：某条腿抖动报错时，只要 ≥2 源一致脚本仍退 0（这是设计——独立性要求
  的是**运营主体不同**，不是三条全响）。`reasons` 会把报错的腿点名，但不改结论。
- `sources` 散文里的 `index N 个条目`只有 mongo/grafana 两条写了数字，本批不强制其余四条补齐
  （工具已经逐条打印，补不补只影响人读表时的方便）。
- `verify-image-digests.js` 仍不进 CI（联网门禁红了之后人先怀疑网络）。

同批收到两份独立逐行审计报告（`scripts/*.sh` 5 条：备份默认 docker 传输把全库口令写进宿主 `/tmp`
且无人读取、`RESTORE_SKIP_CHECKSUM=true` 连"校验和不匹配"一起跳过、`generate-secrets.js` 权限收紧
失败仍退 0、多行 `BACKUP_OFFSITE_CMD` 只跑第一行却宣布跑完、容器侧固定 `/tmp` 路径 + `cat` 不检查；
`src/services`+`src/controllers` 5 条：部门成员缓存无失效钩子导致 ≤30 s 跨部门可见、告警 `meta.total`
取自分页而 `hasMore` 在过滤前算、`rolePermissionController` 把畸形权限 ID 静默丢弃后整体覆写、
MFA 恢复码集 last-write-wins、`User.findById` 结果未守卫）。**本批未动这些文件**（属于并发会话在飞
范围与另一条链路），逐条自行复核后排入下一批。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 13 + `imageDigestVerify` 19 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **90 绿**（上一批 77）；元门禁 13 套 123 例
仅 1 红，且是 `ci/testTreePurity` 列出 7 份他人未入库的 `*.test.js`（本批只改既有用例文件，未新增）；
`ci/commentAnchorFreshness` 与 `ci/bareAnchorAttribution` 本轮**转绿**（他人会话已把 `runtime.js:88` 的
锚点同步到 `statsCache.js:147/157`）。`eslint src scripts --quiet` 0 error；`lint-ratchet` 通过
（21 个 warn 文件均未超基线，`main` 拆出 `planRuns` 后复杂度未升）；`check-utf8` 1050 文件通过；
prettier 对本批三个文件 `--write` 后 `--check` 通过。

### 供应链 C（2026-10-04 · 「全仓镜像都已钉版」第一次变成机器可判的账：6 个引用 × 3 处事实来源，配上不联网的两把闸）

> 上一批的诚实清单欠了三件事：compose 的 mongo / prometheus / alertmanager / grafana 与 `ci.yml`
> 的 service 容器还是可变 tag；三处"全覆盖式表述"是失实的；而"脚本能跑"与"文件真的钉完了"之间
> 没有任何东西在对账。这批一次性收掉：**引用面账**（`src/tests/security/imageReferenceInventory.test.js`）
> 把真实文件 ↔ 期望表 ↔ 脚本常量 ↔ 老闸字面量四处钉成同一笔账，**判据行为账**
> （`src/tests/imageDigestVerify.test.js`）把新工具的三条放行判据逐个做成可打红的用例。

钉版落地（本轮补 5 条，仓库内第三方引用至此 6 个 / 全部 `name:tag@sha256:<64hex>`，保留可读 tag）：

- `docker-compose.yml`：mongo `eb581912…`、prometheus `075b1ba2…`、alertmanager `e13b6ed5…`、
  grafana `079600c9…`（redis `858f009f…` 上一批已钉）；`.github/workflows/ci.yml` 的 service
  容器 mongo 与 compose **同一个 digest**（不同则 CI 是在"另一个 mongod"上跑绿的，而日志看不出区别）。
  `${APP_IMAGE:-fire-safety-app:local}` 是本机构建产物，不属于第三方供应链输入，分类器把它归"动态"。
- **取值不需要 docker**：新增 `scripts/verify-image-digests.js`（零依赖，只用 node 内置 `fetch`/`crypto`）
  对 registry 的 manifest 端点取**原始字节**自算 sha256——这就是该 manifest 的 digest，`Docker-Content-Digest`
  只作旁证不作结论。放行要三条同时成立：①自算值等于期望表值；②≥`--min-sources`（默认 2）个
  **运营主体不同**的来源给同一个值（`public.ecr.aws` 是 AWS 自己发布的 official 面，另两个是不同
  运营商的 Hub pull-through 缓存）；③拿到的必须是 manifest 列表 / OCI index——钉单层摘要等于锁死一个
  architecture。`captured`/`sources` 两列记录取证现场，不是装饰。
- 本批落地时与今日复跑都是三源/两源一致：**6 引用全 PASS（退出码 0）**。prom/grafana 只有两源
  是实测事实：ECR Public 对这些命名空间就是 404（不托管 ⇒ `skipped`，与"来源报错"分成两类，
  混同会把坏掉的 registry 路径念成"这条腿今天没说话"）。

两把新闸的判据（都不联网；联网核验仍是人跑一次的工具，理由见"未收"⑤）：

- `security/imageReferenceInventory`（9 条）：扫描面自证（8 个文件 / 11 条指令行 / byFile 精确到
  Dockerfile 3 + compose 6 + ci.yml 2 / 2 条动态 / 9 条 registry 引用，解析塌缩不许静默绿）；
  行分类器与钉版解析器各带**夹具**自证（13 例分类表 + 6 例拒绝表；注释排除、YAML 键大小写敏感、
  `image:` 后必须有空白、`(^|[^A-Za-z0-9_.-])image:` 词边界，都不靠仓库内容配合）；双向对账
  （孤儿引用 / digest 不符 / 期望表过期条目 / `present.size === EXPECTED.length`）；同 tag 必须同
  digest；`capture-image-digests.sh` 的 `NODE_TAG`/`MONGO_TAG` 与 `baseImageDigestPinned` 的字面量
  交叉对账，脚本管不到的 4 条引用点名列出。变异 **9/9 全红**（grafana 解钉、表内 digest 分叉、
  CI↔compose 分叉、解析器收大写、删注释排除、表里放不存在的引用、redis 写成序列项、大写 digest、
  `image:` 去空格），四份被改文件 sha1 逐字节还原。
- `imageDigestVerify`（10 条，`global.fetch` 替身）：judge 三条判据各自能单独把结论打回 false
  （含"两源一致但是单层"这一臂）+ `min-sources` 调大必须变红 + `headerMatches` 三态；fetchOne 的
  替身故意让 header 与字节摘要**不相等**，钉住"取的是字节"；单层响应体 `entries` 必须归 0（判据③
  唯一的输入）；Bearer 流程把 URL 序列与 `Authorization` 序列逐位钉死（少一步重试、或取 token 那步
  带上凭据都要红）；`realm=`/`Realm=` 两种写法都认，解析不出 realm 时报错而不是静默匿名直连；
  `token` 与 `access_token` 两个字段名都认。变异 **12/12 全红**，同样逐字节还原。

脚本侧顺手修掉的真缺陷（都是写用例时暴露的，不在"计划改"之列）：

- `anonymousToken` 按小写 `realm=` 匹配：registry 生态里 `Realm=` 真实存在，只认一种会让那条来源
  常年报"响应里没有 Bearer 挑战"，运维第一反应是怀疑网络而不是脚本。改为 `i` 匹配；同时它的旧注释
  写着"没有 realm 就当作公开端点直连"，而代码从第一版起就是 throw——注释失实已改（静默直连的产物
  是一个要鉴权的端点用匿名身份返回 401，最后被归因成"这个来源没说话"）。
- 旧结构是"先探测再取"：公开端点（来源表里两个都是）会为每个引用**把 manifest 下载两遍**，第一遍
  响应体整批扔掉。改成一次请求、非 200 才按挑战取 token 重试一次，重试目标仍是同一 URL、token 只流向
  `realm` 指定的地址。
- 输出侧把"来源没发 `Docker-Content-Digest`"念成"header 相符"——ECR Public 实测就不发这个 header，
  等于每轮三行假话。改成三态（相符 / 与自算摘要不符 / 来源未发），且认不出的值一律落到**不作断言**
  那一档（默认值不能是"通过"）。
- 新增上面那句三态判断立刻触发 `lint-ratchet` 的 `[complexity] 0→1` 回退（`main` 贴着上限 15）。
  拆出 `printVerdict` / `headerNote` 把复杂度降回基线，**没有**收紧基线。

口径同步（三处失实表述随本批改掉）：`docs/architecture.md` 原写"digest 待部署机捕获"（部署机什么都没
跑、值已经在仓库里 ⇒ 已是假话）⇒ 改为全部已钉 + 指路取值口径与对账闸；`.github/dependabot.yml` 的 docker 段补上第三处站点
（期望表，漏改由新闸判红）；`security/baseImageDigestPinned` 文件头原来只承认一条升级路径（部署机跑
`capture-image-digests.sh`）⇒ 补成两条，并明说本闸覆盖面早就不止 node/redis（它保留的是"三阶段同
digest"这条工具链漂移不变量与最早的两条字面量）。compose 里那条 `#（它 pull 之后把输出追加为…）`
示例行**故意留着**：它是 shell 脚本自证文案的一部分，删了脚本的说法就不成立了。

未收（诚实清单）：

- 本批不新增依赖 ⇒ 三个来源里两个是第三方缓存，独立性建立在"缓存不重打包"这个前提上，不是密码学
  证明。要证伪投毒只能把 digest 与上游签名（Notary / content trust）对上，本批不做。
- 期望表的 `captured` 是人手写的日期，闸只判形状（`^\d{4}-\d{2}-\d{2}$`）不判真伪；`sources` 列同理。
- `--only` 里写了表里没有的引用 ⇒ 退出码 2 并点名，但"新镜像进表"这件事仍靠人记得；`imageReferenceInventory`
  能抓到的是**文件里出现**而表里没有的引用，反向（表里有、文件里全删了）也能抓，靠条数相等那条。
- `verify-image-digests.js` 不进 CI：联网门禁红了之后人先怀疑网络，那正是最容易被人为绕开的形态。
  机器只保证仓库内四处事实来源对得上；外部事实变了要靠人跑一次，或等 Dependabot 把 tag 改掉触发红。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 9 + `imageDigestVerify` 10 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **77 绿**；`node scripts/verify-image-digests.js`
全表 6 引用 **PASS，退出码 0**；元门禁 18 套 239 例中 4 红，全部指向并发会话——`ci/testTreePurity`
列出的 7 份未入库用例里有 5 份是他人在飞的 `*.test.js`（本批 2 份随本批入库），另 3 条锚点红是
`src/services/statsCache.js` 顶部插入 35 行把 `src/constants/runtime.js:88` 钉住的
`publishInvalidate`/`onInvalidate` 从 **114/124 移到 147/157**，锚点与台账应由该会话同步（本批不代改
他人文件）。`eslint src scripts --quiet` 0 error（`AbortSignal` 是本仓 globals 白名单缺的一项，已补）；
`lint-ratchet` 通过（21 个 warn 文件均未超基线）；`check-utf8` 1049 文件通过；prettier 对本批全部文件
通过，工作树里两份他人文件仍未格式化（不代改）；`git diff -- Dockerfile` 为空（上一批已钉完），
`docker-compose.yml` 只动了本轮那 4 处 `image:` 与其注释块，`.github/workflows/ci.yml` 只动了 service
容器的 1 处。

### 供应链（2026-10-04 · 把上一批的脚本逐个改坏：五条真缺陷全都属于"把没做完说成做完了"，而闸的共同毛病是只会说"非零"）

> 这批的输入不是新代码，而是**对同日上一批落地的 `scripts/capture-image-digests.sh` 做变异测试**：
> 派三个子 agent 逐行审计，再手工把脚本一条条改坏，看闸会不会红。结果两边各中一处系统病——
> 脚本侧五条缺陷全在同一类上（**报成功而事情没做完**），闸侧的根病是**失败臂只判 `rc !== 0`**：
> 把整份脚本换成一个语法错误的文件时，14 条"必须拒绝"的用例全部照绿，因为它们不看是谁在说话。
> 下面每条都附复现形状，不读脚本也能验。

脚本侧（`scripts/capture-image-digests.sh`）：

- **①「够不着」只在整文件都够不着时才报**（最坏的一条）。分类器先看指令词、再取第一个字段当值，
  字段不属于本镜像 ⇒ `next`；这条 `next` 顺手把"值压根不在能锚定的位置上"也吞了。于是同一文件里
  一条 `FROM --platform=$BUILDPLATFORM node:22.14.0-alpine AS b` + 一条正常 `FROM` 时，前者被当成
  不相干的镜像行放过 ⇒ 打印"钉好 1 条 / 已替换并校验"，文件里**留着一条可变 tag**。compose 的
  `image: ${MONGO_IMAGE:-mongo:6.0.20}` 同形。修：含 tag 字面串却没取到值、且不是注释行 ⇒ 新增
  `unreach` 类 ⇒ 停手并给行号（`--platform=` 与变量展开都归到"指令行但取不到值"这一支）。
- **② 外部输出按行判 ⇒ 多行可以伪造脚本的判据**。`grep -Eq '@sha256:[0-9a-f]{64}$'` 是**按行**判的，
  而 `${raw%@*}` 取的是**最后一个** `@` 之前的全部内容 ⇒ `docker inspect` 返回"一行合法引用 + 任意
  一行"时，形状判据与仓库名判据双双通过；`--apply` 只是碰巧撞在 `sed` 的 unterminated s command 上，
  不加 `--apply` 则 rc=0 并把那一行**原样打进给运维的粘贴块**（把外部输出当代码用）。修：先要求
  **恰好一行**，行数不对就拒收，且**不回显内容**——多行输出可以伪造本脚本自己的日志行。
- **③ CRLF 行尾：同一输入在两台上是两种结果**。MSYS 的 gawk 与 GNU sed 会吃掉行尾的 CR（⇒ 整份
  部署文件的行尾被静默改成 LF 还报成功），Linux 的 gawk 留着 CR（⇒ 判成"形态不认识"而拒改）。
  检测必须走**字节**通道：本机 `grep -q "$CR"` 与 `awk '/\r/'` 对同一份文件都报 0 处，`od -c` 明明
  看得见 `\r`——文本模式在读取时就把 CRLF 换成了 LF。改成 `tr -dc '\r' < file | wc -c`，非零即拒，
  并把"请先把行尾改成 LF"作为可执行建议打出来。
- **④ 信号只清了残留，没有停下手**。`trap 'cleanup_pin_tmp' EXIT HUP INT TERM` 里那三个信号句柄跑完
  清理就**继续执行**：运维按 Ctrl-C 之后脚本照样把两个目标文件写完、照样打印"已替换并校验"、照样
  rc=0（在 15MB 夹具上实测：SIGINT 之后两个文件都已落盘）。修：`on_signal` 清理之后
  `exit $((128 + sig))`；实测 SIGTERM ⇒ rc=143、两文件逐字节原样、无 `*.pin.tmp`。
- **⑤ 全文刷新缺名字边界 ⇒ 两种真实损坏**。`s%tag@sha256:[0-9a-f]{64}%…%g` 不带边界时：
  前无边界会把 `myorg/mongo:6.0.20@sha256:…`（别人的命名空间）里的同名子串当成自己的引用改掉，
  注释从"别人的仓库"变成一张假证；后无边界会把 `@sha256:` 后面 68 位十六进制的前 64 位换掉、
  留下 4 位尾巴，产出一行**看起来完全合法**的钉版引用。修：两侧各加边界字符类
  `(^|[^A-Za-z0-9._/:@-])` / `([^0-9a-f]|$)`，定界符仍是 `%`（`|` 是 ERE 的选择运算符）。

闸侧（`src/tests/imageDigestGate.test.js`，38 → **54 用例全部真跑**）：

- 失败矩阵 14 → **25 臂**，每臂判**精确退出码 + 原因文案（逐行匹配 `^错误：`）+ `第 N 行` 的行号契约**
  再加共同后置条件（两目标逐字节不变、不留临时文件）。新增臂：digest 只有 63 位 / 只有 8 位 /
  大写十六进制（三条各**只违反一件事**——旧夹具 `sha256:short` 同时违反字符集与长度，于是删掉 `{64}`
  或放开大写都不会红）、多行 inspect 输出、CRLF、命名空间前缀、`image:` 后无空白、混合写法两臂、
  缺目标文件两臂（"不存在"与"够不着"是两条不同的臂）。
- **差分语料三条**：输入 → 脚本自己声明的处置计划（`待钉 N 条、待刷新 M 条、已是本次 digest K 条`）
  → **逐字节期望产物**，三格同时判，并加两条越界自证（改动行必须都含 tag 字面串；行数不许变）。
  这是①和⑤那类"少报一笔 / 多改一笔"唯一的交集防线——按形态写的判据两边都看不见。
- docker 调用**序列**断言（`info → pull node → pull mongo → inspect node → inspect mongo`）取代
  `calls.length >= 4`：条数挡不住"从不 pull mongo 就直接 inspect"（本地恰好有旧镜像时照样拿到 digest，
  钉上去的是过期摘要）。
- **SIGTERM 用例**：docker 替身每次睡 1 秒（整轮约 5 秒），驱动脚本在第 1 秒发信号——那一刻离第一次
  落笔还差整个 capture + 分类阶段，所以"信号之后文件有没有被动"是稳定差值而不是竞速。
- `findShell()` 探不到带 awk/sed 的 sh 时整组 `describe.skip`，等于 54 条零断言的绿 ⇒ CI 上单独一条红
  （ubuntu runner 一定有 `/bin/sh`，探不到就是探测本身坏了）。
- `run()` 读目标文件改成缺文件返回 `null`：否则"脚本没碰它"和"那个文件根本不存在"会混成同一条异常。

未收（诚实清单）：SIGTERM 用例的时机靠"裕度 3 秒"而不是同步点——若 runner 上 `sleep` 被替换成
非阻塞实现，它会退化成竞速，这条得盯；`.sh` 依旧不在 eslint/prettier 覆盖内（无 parser、本批不新增
依赖），脚本的验证手段只有 `sh -n` + 本文件真跑；两条 `mv` 之间不原子。上一批那条"未收"仍然成立：
compose 的 mongo / prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器
都还是可变 tag（没有 `docker pull` 证据就不臆造 digest），三处全覆盖式表述要和下批的镜像引用面账
一起改。

验证：`sh -n` 通过；`npx jest --runInBand src/tests/imageDigestGate.test.js` = **54 绿**（含 SIGTERM
腿实测 rc=143）；`security/baseImageDigestPinned` 4 绿、`ci/commentAnchorFreshness` 13 绿、
`ci/codeViewPhantomLedger` 5 绿（共享 helper `jsCodeOnly` 的幻影已被并发会话修到 0，本文件在旧台账里
的 32 行登记项随之消失——那份修复此刻还在工作树里未提交，若被回退这把闸会自己红，不会静默放行）。
`deploy/deployScript` 56 绿；`eslint --quiet` 0 error、`lint-ratchet` 通过（21 个 warn 文件未超基线）、
prettier 与 `check-utf8` 通过（1042 文件）；`git status -- Dockerfile docker-compose.yml` 为空 ⇒
本轮全部 `--apply` 都跑在 `--root` 临时根里，真实部署文件逐字节未动。

### 供应链（2026-10-04 · 唯一能修"半钉仓库"的脚本自己拒绝再跑：已钉从报错改成按目标跳过，digest 刷新与"够不着就停手"补齐）

> 起点是 `src/tests/security/baseImageDigestPinned.test.js` 的文件头——它把升级路径写成
> "在部署机跑 `scripts/capture-image-digests.sh` 重新捕获，再同步闸里的字面量"。上一轮把产物
> 口径与双 digest 修好之后，这条路径**仍然一步都走不通**：check 阶段把"这一行已经是
> `tag@sha256:…`"当成错误直接退出。而本仓库今天的真实状态恰好是混合仓库——Dockerfile 三条
> `FROM` 全钉死、compose 的 mongo 没钉 ⇒ 脚本在第一个目标就停手，永远到不了需要它的那个目标。
> 也就是说闸的注释把自己否证了：它点名的唯一工具，对着真实仓库跑必然红。
> 实测入口很简单：`sh scripts/capture-image-digests.sh --apply` 在本仓库根跑一次即可复现。

> 第二类更隐蔽，是"报告成功而什么都没做"的**反向版本**。判"这条引用够不够得着"用的是无锚定
> 子串计数，而替换用的是锚定正则——两套口径不同，于是这些形态被判成"可改"、进了落笔分支，
> 替换却一条都不匹配（`sed` 无匹配仍然 rc=0）⇒ 打印"已替换并校验"，文件一字未改：
> `FROM --platform=… node:22.14.0-alpine`（值不在能锚定的位置）、compose 的引号包裹值
> `"mongo:6.0.20"`、序列项 `- image: mongo:6.0.20`、折叠标量、`${MONGO_IMAGE}` 变量展开、
> `node:22.14.0-alpine @sha256:…`（tag 与 `@` 之间夹空白）、以及无 tag 的纯 digest 钉版
> （旧上一版脚本自己写坏出来的形态）。每一类都留下同一个后果：仍指向可变 tag 的引用被当成
> 已固定提交上去。

修（`scripts/capture-image-digests.sh` 的 check→stage→commit 三相，判据从"数子串"换成"分类值 token"）：

- **单遍分类器**（awk，只限 POSIX 构造，CI 的 mawk 与本机的 gawk 同结果）：按"行首 = 可选缩进 +
  指令词（`FROM` / `image:`）+ 空白"锚定，取整个值做 token，再按镜像名（剥 `@…`、剥最后一个 `/`
  之前的仓库名与 tag）过滤掉不相干的镜像行——redis / prometheus / `${APP_IMAGE:-…}` 不会被误判。
  值分四类：`待钉 bare`、`已钉 same`、`待刷新 refresh`（钉在**别的** 64hex 上）、其余一律
  `够不着` ⇒ 立即停手、零写入、只打**行号与形态名**（不回显整行）。分类器只按脚本顶部的 tag
  常量精确匹配，不做模糊猜测；指向本镜像的引用一条都找不到同样报错（脚本常量与仓库漂移是
  另一类事故）。
- **按目标跳过，而不是整体报错**：`same` 让该目标原样不动并明打"本次跳过（不改动）"，
  混合仓库因此能收敛（已钉行一笔不碰、未钉行钉上）；`refresh` 让滚动同名 tag 换 digest 的升级
  路径真的存在。**整体 no-op 仍然是错误**（两个目标都 `same` ⇒ 红），保住"报告成功但一字未改"
  那条老缺陷的判据。
- stage 用两条 `sed -E` 表达式：① 锚定的裸 tag 追加本次 digest；② 全文 `tag@sha256:<64hex>` →
  本次 digest，**故意不带锚定**——Dockerfile 顶部的用法注释里也写了完整钉版引用，只改指令行会把
  "正确示例"变成"错误示例"，而那正是本脚本要躲开的第一类失效。产物先落 `*.pin.tmp`，再用**同一个
  分类器复查预演结果**：仍残留 `待钉`/`待刷新`、或指向本镜像的条数变了 ⇒ 删临时文件退出；
  分类说"要改"而 `cmp` 判逐字节一致 ⇒ 报"分类与替换不一致"退出（这是自我矛盾探测器，不是保险丝）。
  commit 阶段 `mv` 之后对盘上的真实文件再 classify 一次。两个 `mv` 之间不是原子的，这条边界
  明写在脚本注释里，没有假装成原子替换。
- 计划可见：check 阶段就打印每个目标"待钉 N 条、待刷新 M 条、已是本次 digest K 条 ⇒ 会改动/跳过"，
  跑之前就知道这次动哪几条。

本轮实测到、并写进注释当教训的三处自身缺陷：POSIX sh 没有 `local`，`classify_ref` 覆写全局
`file` ⇒ `cmp -s "$file" "$tmp"` 变成"临时文件与自己比"，每一次合法运行都被报成"逐字节一致"；
`plan_ref` 读的是全局计数，两个目标都 probe 完再统一打印 ⇒ compose 的计数被打在 Dockerfile 标签下；
`sed` 用 `|` 作定界符与 ERE 的选择运算符撞车（`unknown option to 's'`）⇒ 换成 `%`（registry 引用
文法不含 `%`）。

闸（`src/tests/imageDigestGate.test.js`，38 用例全部真跑，PATH 插 docker 替身，不用扫源码文本）：
失败矩阵从 7 臂扩到 14 臂，新增 6 条"够不着"臂（`--platform=`、夹空白、无 tag 纯 digest、
引号包裹、序列项、折叠标量、变量展开），共同后置条件是**目标文件逐字节不变 + 目录里没有
`*.pin.tmp`**；表宽自证同步改成 14（jest-each 少喂一格是超时假绿，不是失败）。新增成功腿：
混合仓库（已钉的 DF 一笔不碰、compose 钉上、打印"跳过"）、`refresh`（含注释示例自愈、断言旧
digest 不再出现在文件里、复跑判 no-op）、单行内混合收敛、`FROM  node:…` 双空格；命名空间腿把
脚本的 `repo_of_ref`/`norm_repo` 抽进 sh 夹具跑 7 个真实引用（`node`→`docker.io/library/node`、
`prom/prometheus`、带端口的 registry 必须保留原样，反向 2 例必须 REJECT）并断言 ACCEPT 集非空——
只比末段会把别人的仓库当成自己的。零串扰自检保持：真实 `Dockerfile` 与 `docker-compose.yml` 的
base64 前后相等，本轮实测 `git diff -- Dockerfile docker-compose.yml` 为空。

未收（诚实清单，留作下一批）：compose 的 mongo 本身仍未钉（本轮没有 `docker pull` 证据，不臆造
digest），prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器同理；
`baseImageDigestPinned` 的标题、compose 里"digest 由部署机 docker pull 后捕获追加"的注释、
`docs/architecture.md` 的"镜像钉版本：node、mongo"这三处**全覆盖式表述**与上述现状不符，
要和那份清单同批一起改成可核对的范围。`.sh` 不在 eslint/prettier 的覆盖里（无 parser），
本文件的验证手段只有 `sh -n` + 真跑。

验证：`sh -n` 通过；14 形态探测（临时夹具 + docker 替身，digest 用假值）全 PASS，且每次成功之后
复跑都被判 no-op 红；对真实仓库跑 dry 分类 ⇒ 三条 `FROM` 与三处注释引用识别为待刷新，
redis/prometheus/alertmanager/grafana/`${APP_IMAGE}` 与 Dockerfile 的散文行一笔不碰；
`npx jest --runInBand` 跑 `imageDigestGate` + `security/baseImageDigestPinned` +
`ci/commentAnchorFreshness` = 55 绿、`deploy/deployScript` = 56 绿、`ci/codeViewPhantomLedger` 绿；
`eslint src scripts --quiet` 0 error、`lint-ratchet` 通过、prettier 与 `check-utf8` 通过。

### 运维手册（2026-10-04 · 轮换手册 ① 发的 cookie 名服务端根本不读，"旧令牌必须立即失效"是一项不可能失败的检查）

> 起点是运维侧 P2-3（`deployment/secret-rotation.md` 的 L-01 ①）。复现只需一次函数调用：
> `extractAccessToken({headers:{cookie:'accessToken=X'}})` → `null`，而
> `extractAccessToken({headers:{cookie:'access_token=X'}})` → `X`。服务端只有
> `ACCESS_COOKIE_NAME='access_token'` 这一个名字（`src/utils/cookie.js` 的导出，
> `src/middleware/auth.js` 的 extractAccessToken 是 /api/auth/me 上 authenticate 的第一步），
> 手册却教运维发 `accessToken=`——名字对不上时走的是 `AUTH_TOKEN_MISSING`（"没带令牌"），
> 而轮换真正生效时走的是 `AUTH_TOKEN_INVALID`（验签失败），**两者同为 401**
> （`src/utils/errorCodes.js` 里两条的 status 都是 401，这条前提已被钉进用例）。
>
> 于是这项检查有两层失效，第二层更根本：判据只写"预期 401"、没有轮换前的正向对照，
> 匿名请求同样 401。**"检查通过"与"检查没跑"输出完全一样**，这样的判据不是弱，是零。
> 换句话说：即便当初把名字写对了，这一条也什么都没证明。
>
> 修（`deployment/secret-rotation.md` ①）：名字改回 `access_token`；补轮换前的同命令对照
> （必须 200，不是 200 就先修命令别开始轮换）；判据从状态码换成 `errors.errorCode`，
> 并把三种 401 的读法写进手册——`AUTH_TOKEN_INVALID`＝旧密钥确实没了、
> `AUTH_TOKEN_MISSING`＝令牌没被读到（不是轮换成功的证据）、`AUTH_TOKEN_EXPIRED`＝样本本来
> 就过期，证明不了任何事，重新登录换令牌再测。
>
> 闸（新增 `src/tests/deploy/runbookCheckCanFail.test.js`，7 用例）守两条同根判据：
> **A 是行为重放而不是字符串比对**——文档里每条 `Cookie: <name>=…` 与 `curl -b <name>=…`
> 的名字拼成真实请求头喂给服务端读取点（access 走 extractAccessToken，refresh 走四处共用的
> `getCookies(req)[REFRESH_COOKIE_NAME]`），断言取得回值；合法名集合由 `src/utils/cookie.js`
> 的 `*_COOKIE_NAME` 导出派生，且**每个导出名必须登记一条读取点**（加名不登记即红，闸不另立
> 第二份清单）。**B 是"负面判据必须自带对照"**——代码块里出现 401/403 时同块必须有 200 级
> 正向对照或同一状态码下可区分的 errorCode/AUTH_* 码。覆盖域沿用 runbookSecretSource 的
> "说明书"口径，刻意排除 CHANGELOG/deliverables/docs/adr——本条 CHANGELOG 里写着的
> `accessToken=` 是证据，不是指令。端点归属（把 refresh 发给 /me）是已声明的边界，不收。
>
> 变异（真文档上跑，每次只动一处，跑完逐字节还原）：把 ① 的名字改回 `accessToken` ⇒
> **恰好 1 红**（判据 A）；把 ① 整段还原成缺陷形状（只留"预期 401"）⇒ **恰好 1 红**（判据 B）。
> no-op 基线 7/7，扫描器不是空的（前提自证：真文档 ≥1 条 Cookie 名且必须来自被修的文件）。
>
> 验证：新闸 7/7；`ci/commentAnchorFreshness` + `testTreePurity` + `src/tests/deploy` 全套
> 400/407 绿，7 处红**全部**在 `deploy/bundleBudget`（并发会话正在改 web-admin，
> 前端产物超出现有预算基线；与本批无关，本批一个字节都没碰前端）；
> eslint 0 error；prettier 对新文件与手册均 unchanged。服务端代码零改动——
> 缺陷在文档，闸把文档接进了代码。

### 供应链（2026-10-03 · `capture-image-digests.sh` 的产物会被本仓自己的钉版门禁判红，还会把已钉过的行改成双 digest）

> 起点是运维侧 P2-4（"脚本在已钉版仓库上不可操作"）。复现成立，但**失效方向判反了**：
> 它不是拒绝工作，而是**开心地工作并打印成功**。2026-10-03 对着本仓库真实的
> `Dockerfile`（三条 FROM 都是 `node:22.14.0-alpine@sha256:9bef…`）抽出脚本的
> `check_ref` / `stage_ref` 单独跑：check 返回 0（放行），stage 产出
> **3 条 `@sha256:[0-9a-f]{64}@sha256:` 的双 digest**，脚本随后打印"已替换并校验"。
> 根因是一句无边界的前缀匹配：钉版形态**仍然包含**脚本常量 `FROM node:22.14.0-alpine`，
> 于是 `grep -qF "$old"` 把"已经钉过"读成"还能改"，`s|$old|$new|g` 再在它前面插一个新 digest。
>
> 顺着这条线查下去撞出第二类、也更严重：**`RepoDigests[0]` 天生不带 tag**
> （`docker.io/library/node@sha256:…`，本仓 2026-10-02 已实测），而旧实现把整串当引用写入，
> 产物就是无 tag 的 `FROM docker.io/library/node@sha256:…`。本仓的钉版口径是**保留可读 tag**
> ——`baseImageDigestPinned.test.js` 的 FROM 判据 `/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/`、
> `deploy/deployScript.test.js:118` 的 `<repo>:<tag>@sha256:…`、`docker-compose.yml:159` 的
> "纯 digest 看不出版本，排障时得先 inspect"三处同源，真实文件也全是这个形态。
> 也就是说 `baseImageDigestPinned` 的文件头把"跑这个脚本重新捕获"写成升级路径，
> 而**照这条路跑一次，红的一定是它自己**。这个矛盾在审计复核第 20 轮 §A3 已判过、
> 挂在"等拍板"上；本轮按证据收敛（口径由 3 处文档/闸 + 全部真实文件定死，不是二选一的风格题）。
> 顺带更正第 20 轮的一句推断：它写"改成追加式之后双 digest 自然失去土壤"——**恰好相反**，
> 追加式的产物 `tag@sha256:…` 正是 `tag` 的前缀扩展，边界判据从此是承重墙而不是保险丝。

- `capture_digest`：**只取 `@sha256:<hex>` 尾巴追加到 `$tag` 上**，不再回传 RepoDigests 原文；
  另加仓库名一致性校验（`docker.io/library/node` 对 `node` 放行，`…/alpine` 对 `node` 拒绝）——
  追加式写法若拿到的 digest 其实属于别的镜像，写出去的就是"这个 tag 指向那个 digest"这个
  不成立的断言，只能等构建期 pull 才炸。形状判据（`@sha256:[0-9a-f]{64}$`）拦不住它，实测过。
- `check_ref` / `stage_ref`：子串判据换成**边界口径**——"含 `old` 的指令行数 − 含 `old@` 的
  指令行数 > 0"才算可改，替换用 BRE 把 `old` 锚在空白或行尾（`\([[:space:]]\)` / `$` 两式）。
  于是"已钉 Dockerfile + 未钉 compose"这个**本仓库今天的形状**从"改坏还报成功"变成
  早退报错、逐字节不变、不留临时文件；混合仓库（有的阶段钉了、有的没钉）则一笔不碰已钉的、
  只钉未钉的，且改完再跑会正确报 no-op 而不是二次污染。
- 打印口径与脚本头部注释同步改为"直接可用于 `name:tag@sha256:<hex>` 的钉版引用"，
  收尾提示补上那条会把矛盾的闸（`npx jest src/tests/security/baseImageDigestPinned.test.js`）。
- `src/tests/imageDigestGate.test.js`（实跑 19 → **27 格**）：删掉那条把错误口径钉成**必要条件**的
  旧断言 `expect(r.dockerfile).not.toContain('node:22.14.0-alpine')`——它正是两道闸互不相容
  却各自全绿的成因；替身补 `qualified`（全限定 RepoDigests）与 `wrongname` 两个模式，
  新增 6 格：产物形态按**闸的原判据**逐条 FROM 实跑、短名与全限定两种 docker 名号收敛成同一串、
  "已钉 Dockerfile + 未钉 compose"现场必须报错、混合仓库只钉未钉的那条且二次运行不再污染、
  名号对不上必须拒（含"换回 node 就放行"的反向自证）；
  前缀陷阱另配一格前提自证（把 `@` 换成空格时三条判据必须同时翻转）。
  失败矩阵 5 → 7 臂，表宽用例改为 `widths: [4]` + `rows: 7`，行数本身也在台账里留痕。
- 变异证明（每个变异体跑整套，跑完即还原）：**M1** 判据+替换回到无边界 ⇒ 6 红
  （含两条新格与"幂等重跑""compose 漂移不留半钉"）；**M2** 直接回传 RepoDigests 原文 ⇒ 6 红
  （含"产物形态按闸判据"与"名号口径无关"）；**M3** 去掉仓库名校验 ⇒ 恰好 2 红（wrongname 两臂）。
- 验证：`imageDigestGate` 27/27；邻近两闸 `baseImageDigestPinned` + `deploy/deployScript` 60/60，
  注释锚点闸 `ci/commentAnchorFreshness` 13/13；`sh -n` 通过；eslint 0 error；prettier 对测试文件 unchanged。
  真实 `Dockerfile` / `docker-compose.yml` 一个字节未动（套件里有 sha 前后比对兜住）。

### 安全（2026-10-03 · 审计链核验脚本把"报告里已见的缺口"在出口处丢了，PASS 照打）

> 起点是运维侧一条待核判断（P1-1）。我自己复现了一遍，成立，而且比原判据更宽：
> 漏传的不止一个脚本。现场（`node scripts/verify-audit-chain.js` 对着真库）——
> 链尾一条 `hashFailure` 记录（写侧算 hash 抛错后照常落库，`AuditLog.hashFailure` 的既定形态）：
> 报告 `total=3 breaks=0 legacy=0 hashComputeFailed=1`，
> 而 CLI 打 `VERDICT: PASS（全量、无断裂、hmac 已校验）`、**退 0**。
> `deployment/rollback-drill.md:111` 与 `deployment/secret-rotation.md:397` 正是拿
> "退出码 0"当验收条件的那两步，于是链上不可追认的缺口穿过了验收。

- `scripts/verify-audit-chain.js`、`scripts/resign-audit-chain-v3.js` 各补一行
  `hashComputeFailed: <report>.hashComputeFailed`。判据（`computeChainVerdict`）这一格
  本来就有实现且正确，**坏的只是调用方**：`src/controllers/auditController.js`、
  `src/services/auditChainMonitor.js` 都回传了，两个运维脚本没有。
  修复后同一现场 ⇒ `INCOMPLETE` 退 2（复现脚本前后各跑一次，只差那一行）。
- 判据 `hasUnattestableGapOf` 的 JSDoc 里那句**失实前提**已就地更正：原文写"它由
  verifyAuditChain 恒回填，唯一漏传路径是旧调用方"——实测两个现役调用方就在漏传，
  而报告确实恒回填该字段。缺省方向（漏传按 0）**保持不变**：把它翻成 fail-closed 会让
  判据对任何不带该字段的调用报 INCOMPLETE，而真值表用例与在线侧构造的字段子集调用都属
  正常用法；本仓对"未来调用方漏传"的既有机制是逐调用点门禁，不是把判据调瞎。
- `src/tests/verifyChainExitCode.test.js` 把原来那份**硬编码三个文件名**的 scanned 回传断言
  换成**全仓枚举**（`src/` 去 tests + `scripts/`，按花括号配对取出每个调用点的对象字面量，
  逐个查 `scanned` / `hashComputeFailed`；纯 `computeChainVerdict(外部对象)` 形态按
  "静态看不见字段"点名）。实测 4 个调用点，全部合规。新增 CLI 端到端一格：
  真库真链尾真 `hashFailure` ⇒ 先自证"报告看得见缺口且不是篡改"，再验退 2、理由点名缺口、
  **绝不出现 PASS**，且 `--allow-empty --allow-no-hmac --allow-all-legacy` 三个豁免同时给也盖不住；
  `finally` 还原后必须回到退 0。
- 变异实测（不是推演）：删掉 CLI 那一行 ⇒ 枚举闸、CLI 端到端、scanned 那格**三条一起红**；
  删掉 resign 脚本那一行 ⇒ 枚举红并点名该文件。两处都已还原（`grep -c` 各 1）。
  反向自证 4 形：少 `scanned`、少 `hashComputeFailed`、同文件第二个调用点漏传、
  非字面量调用，各自都被点名。
- `scripts/verify-audit-chain.js` 头注释的退出码清单补上第五类不完整（缺口无任何豁免口子），
  此前它只列了截断 / 无 hmac / 空集合 / 整窗无哈希四类。
- 验证：`verifyChainExitCode` + `auditChainGuardedIntegrity` 45/45；
  `commentAnchorFreshness` 13/13（新增的 4 处引用都取到实文件实行号）；
  `npm run lint` 0 error、`lint:ratchet` 通过（21 个 warn 文件未超基线）；prettier 已格式化。

### 质量（2026-10-03 · 「任何新增验签入口都必须引用同一份判据」这句话，判据是注释而不是代码）

> 读 `src/utils/tokenPurpose.js` 时发现它的收敛承诺没有闸：
> `src/tests/utils/tokenPurposeAndConsumers.test.js` 的「三个入口都引用 utils/tokenPurpose」
> 用的是**手写死的三个文件名**。它证的是"这三份今天还引用着"，不是"没有第四份"——
> 新增一处 `jwt.verify(t, config.jwt.secret)` 而忘了用途闸，两个闸都照常绿。
> 而同一个文件里其实已经有全仓扫描的机器（另一条用例扫的是"不许内联写第二份 type 比较"），
> 只是没扫这一维。

- 新增 `src/tests/security/tokenPurposeEntryInventory.test.js`（7 格）：**枚举** `src/` 下所有
  用 access 密钥验签的调用（剥注释后按调用点判，`refreshSecret` 那一侧不算），未引用判据的
  必须出现在豁免表里。实测全仓 5 处：`middleware/auth.js`、`services/tokenService.js`、
  `services/websocketService.js` 引用判据；`middleware/logoutAuth.js`、`services/authService.js`
  是豁免。清单钉成**双向**不变量：多一处红、少一处也红。
- 两条豁免各绑一条**行为**用例，不是文件名白名单：
  · 登出入口那次未套判据的验签只决定"走哪条身份通路"，权威判定仍在 `authenticate()` 里 ——
  拿 `type:'refresh'` 的载荷用 access 密钥签（= 两把密钥被配成同值时攻击者手里的东西）打
  `/logout` ⇒ 401 且错误码必须是 `AUTH_TOKEN_INVALID`（换成"缺失/过期"那两条 401 本用例就
  指错了方向），并且 `req.user` 根本没被构造；
  · 吊销路径少一道用途闸的失效方向是**多吊销一条**而不是**多放行一个** —— 同形态串填进
  `revokeTokensOnLogout` 的 `accessToken` 槽 ⇒ 唯一的副作用是写黑名单。
  哪天有人改动让根据不再成立（比如在吊销路径上开始用 payload 构造身份），红的是这两条行为用例，
  不是清单。
- 反向自证 + 实跑 mutation：给分类器喂一段"没引用判据的 verify"与"引用了判据的 verify"，
  两者必须给出相反答案，且注释里提到的 `jwt.verify` 不算入口；再把一个合成入口临时写进
  `src/utils/superAdmin.js` 真跑一次 ⇒「清单逐条归队」与「规模钉住」两条立刻红并点名
  `src/utils/superAdmin.js ⇒ jwt.verify(t, config.jwt.secret, …)`，随后恢复原文件（`git diff` 空）。
- `src/utils/tokenPurpose.js` 的头注释补上这句承诺现在由谁执行，并把实测的 5 处入口写进去。

### 安全（2026-10-03 · 轮换手册把**两代**真凭据指向一个没被忽略的目录，而生成器"缺哪个补哪个"）

> 触发形态直接写在手册里：`deployment/secret-rotation.md` 第 1 步 `generate-secrets.js
--out ./secrets-new`（即将上线的那套），第 4 步 `mv ./secrets ./secrets-old`（刚刚下线的
> **全套生产密钥**）。而 `.gitignore` 当时只有 `secrets/` 一条——目录名不同，一条都挡不住；
> 本仓库是公开仓库，轮换做完那天一次 `git add -A` 就把新旧两代凭据一起推上去。
> `.dockerignore` 同族：docker 的忽略模式按**整段路径**匹配，`secrets` 匹配不到 `secrets-new`，
> 所以一次 `docker compose build` 会把两代真凭据送进构建上下文（镜像层里删不掉）。

- `.gitignore` 加 `secrets-*/`、`.dockerignore` 加 `secrets-*`，各带一句"为什么不是 `secrets`"。
- 新增 `src/tests/deploy/secretCarriersIgnored.test.js`（14 格）。要点是**哪些目录会装凭据不写死清单**，
  而是从手册/compose/README 自己的文本里抓 `--out <dir>` 与 `mv <src> <dst>` 两种入口：
  将来文档新起一个 `./secrets-staging` 而忘了忽略，本闸变红；写死清单则它永远绿着，
  而漏的恰好是那个新名字。git 侧的"是否被忽略"交给 `git check-ignore` 本身（与
  `scripts/mongoUri.sh` 同一条规矩：判据按参考解析器怎么读来定），并配一条**反向自证**
  （同一条命令对没被忽略的目录回 1）——否则探测器坏掉时全部用例会一起假绿。
- `generate-secrets.js` 前置检查 A（落盘之前问 git）：`--out` 目标在仓库内而 git 不认它被忽略
  ⇒ 退出码 1，**一个文件都不写**。退出码逐档实测：0=命中规则；1=在仓库内但不报忽略；
  128=判不了（仓库外 / 容器里没有 `.git` / 没装 git）。只有 1 拒，128 只把"没判成"说出来——
  拦下一条轮换/DR 路径换来的安全性是负的。判 git 时的 cwd 取**目标最近的已存在祖先目录**
  而不是调用方所在目录：`--out ~/keys` 而家目录本身是个 dotfiles 仓库时，用调用方 cwd 会一律
  判成 128 而放行，而那正是必须拦的形状。
- rc=1 其实合并了**两**种形态（都实测，话术两种都点名）：没有规则命中它；规则有了但文件
  **已经在 index 里**（先 `git add`、事后才补 `.gitignore`）。第二种更要紧——它就是"密钥已经
  进了公开仓库"的状态，所以这里**刻意不加** `--no-index`。这条加没加不是风格问题，实跑过：
  加上后前置检查 A 放行，`--force` 一路 rc=0 把已入库那颗 `jwt_secret` 覆盖成新生成的随机值
  （历史里一份、工作目录里另一份，且再没有任何一环报警）。用例把这一格钉住，含"旧字节必须
  原样还在"与"`--force` 也救不了"两条断言。
- `generate-secrets.js` 前置检查 B：目录里已有密钥时不再"缺哪个补哪个"。原实现逐个
  `已存在，跳过`，一次中断后的重跑会产出**混合代次**目录——多数密钥彼此独立看不出来，但
  `mongodb_uri` 是把 `mongo_root_password` 拼进去生成的：mongo 初始化用旧口令建用户、应用拿
  对不上号的连接串连库，轮换"成功"结束后第一次连库就认证失败，而现场证据是两份刚生成的
  0600 文件。现在要么 `--force` 重做整套、要么拒绝；用例在 `--force` 之后现场断言
  `mongodb_uri` 里拼的就是同目录那份 `mongo_root_password`，把这对耦合写成判据而不只是注释。
- 两处**自我纠正**（都因为"注释不执行"）：① 我先前在注释里写"用目录名探测会假绿"，实测三组
  形态（`s/`、`s/`+反向 `!s/jwt_secret`、文件先入 index 再补规则）里目录名与文件名探针的命中
  结果**完全一致**，那句是没取证就下的结论，已删；② 拒绝话术原本指向手册的「失陷处置」小节，
  而 `secret-rotation.md` 里根本没有这一节（grep 过），改成它真实存在的轮换流程 + `git rm --cached`。
- 顺带修掉自己上一次提交造成的两处陈旧行号引用：`28f7247` 插入 NUL 守卫后
  `process.env[name] = value` 从 `src/config/secrets.js:113` 挪到了 `:134`，
  `scripts/devSecretIsolation.js` 与 `disposableSecretIsolation.test.js` 的锚点跟着改对
  （`commentAnchorFreshness` 报的，不是豁免掉的）。

### 安全（2026-10-03 · 破坏性恢复的**默认**传输路径从来没有一个用例跑过，而它正在宿主机上多留一份凭据）

> 背景：给 `restore-mongo.sh` 补用例时发现，本仓所有真跑过它的地方（backupUriFile /
> backupEncryptionContract / infraParam…）都显式设了 `MONGO_RESTORE_TRANSPORT=local`，
> 而 README 与 deployment/backup-encryption.md 教的恰恰是**默认那条 docker**——compose 里
> mongo 只 `expose` 不 `publish`，宿主机连不上，mongorestore 必须在容器内跑。
> 于是"数据级回滚抓手"的默认路径在修前**从未被任何用例执行过**：主机段改写的拒绝、
> `--drop` 的拼接、凭据在容器内即删、归档经 stdin 流向容器，没有一条是被证过的事实。
> 备份侧的 docker 拒绝同样没人跑过（`backupTransport.test.js` 只演过它成功的那格）。

- 新增 `src/tests/deploy/restoreTransport.test.js`（8 格）：桩 `docker` 把 argv 与 stdin
  分别落盘，断言的是**真正送进容器的那条命令与那段字节流**——`uri:` 行主机段已换成
  容器内地址、库名与 `authSource` 原样保留、归档字节确实跟在配置行后面流进去、
  argv 上没有凭据、容器侧 `/tmp/.mongorestore.cfg` 与 `.archive` 都在同一条远端命令里 `rm -f`。
  `--drop` 在两条分支各写一遍（local 拼数组、docker 拼远端字符串），所以两侧都演
  "开了有、没开无"——这是防漂移，不是重复断言。
- 实测到的**修复**：`restore-mongo.sh` 原先在分支之前就无条件 `umask 077 + mktemp +
写入含口令的 URI`，而 docker 路径从头到尾没人读那个文件——它在宿主机磁盘上实打实
  留了一次凭据（DR 现场往往是笔记本/运维机），**而下方的注释一直声称"含凭据的 URI
  不落宿主机临时文件"，那句当时是失实的**。创建挪进 `local)` 分支（`--config` 只吃文件，
  那里是必需的），注释与代码这才一致。判据"宿主机上有没有 `mongorestore-config.*`"由
  两个桩**共用同一段探测代码**：local 必须探到、docker 必须探不到，探测器坏掉时不可能
  只让 docker 那一格假绿。把修前那段贴回去，两条用例立刻变红（docker 那格探到文件名、
  local 那格数出 2 个文件）——这次 mutation 实跑过，不是推演。
- 备份侧补上缺失的那格：URI 主机段无法改写 ⇒ 非零退出、`docker.argv`/`docker.stdin`
  根本没被创建、`backups/` 里不留半成品归档，且拒绝信息不回显口令字节。
- 一个**否证的结论**（原先记成高危，源码读下来不成立）：曾判断"备份只导出 URI 里那个库，
  恢复却不带 `--nsInclude` ⇒ 归档里有几个库就覆写几个库"。mongo-tools 100.9 的
  `common/options` 在没有显式 `--db` 时把**连接串里的库名**赋给 `opts.DB`，mongodump 只为
  那一个库建 intents，mongorestore 则把 `[库名.*]` 当作 includes 过滤归档条目——
  两侧范围因此**同一个库**，没有错配。这条不改任何破坏性参数（`--drop` 的口径维持原样），
  改为把口径写进 `backup-mongo.sh` 的注释并标明它是**读源码得来的、本机无二进制可实测**。
- 一条**待拍板的不对称**（没在门禁里偷偷改语义）：含未转义 `@` 的口令，docker 分支硬拒、
  local 分支放行（备份侧同形）。方向不同是有理由的——docker 必须知道"哪段是主机"才能替换，
  两个读者读法相反时替换就是猜；local 从不改写，歧义不是脚本引入的，且两种读法下的
  **库名相同**，确认门禁没有被绕过。残余风险是"横幅里的主机不一定是实际拨号的主机"，
  而 Go 驱动本机不可测。压平它要开始拒绝一批现在能跑的口令，因此留给人决定，
  新用例只把现状钉住并注明是钉现状、不是背书。

### 安全（2026-10-03 · UTF-16 密钥文件：bash 侧把连接串改坏、Node 侧把密钥截成一个字符，两边都 rc=0）

> 背景：`*_FILE` 约定有两个读者，它们吃掉"坏字节"的方式**相反**，而两个都不报警。
> 触发形态是运维用记事本/PowerShell 把密钥"另存为 Unicode"——UTF-16LE 里每个 ASCII
> 字符后面都跟一个 `00`，肉眼看文件内容完全正常。
>
> - **bash 侧**（`scripts/mongoUri.sh` 的 `mongo_hydrate_uri`）：`_body=$(cat -- "$_file")`
>   这一步命令替换就把 NUL **删掉**了（bash 只在 stderr 留一行 warning，退出码仍是 0），
>   于是后面四条判据（单行 / 纯可打印 ASCII / scheme / 非空）校验的是**改写后的串**，
>   不是文件里的字节。实测（bash 5.3.9）：UTF-16LE 的
>   `mongodb://fsms:pw@h/db` 剥掉 NUL 后字形与正确值一模一样 ⇒ 放行；把 NUL 埋在库名中间
>   （`…/fsms<NUL>x`）则放行一个"没人写过的库"，rc=0。
> - **Node 侧**（`src/config/secrets.js` 的 `hydrateSecretsFromFiles`）：`readFileSync(…,'utf8')`
>   把 NUL **留在** JS 字符串里，`trim()` 不认它是空白（所以既不裁也不告警），
>   随后 `process.env[name] = value` 在第一个 NUL 处**截断**。实测（Windows / Node 24.18）：
>   `process.env.X='A\0b'` 不抛错、回读得到 `'A'`；把 UTF-16 的 AES 密钥喂进去，
>   注入值是 1 个字符，`loaded` 照常包含该键、`warnings` 为空。
>
> 哪些会被下游拦住纯属巧合，所以不能拿它当"没问题"的证据：`JWT_SECRET` /
> `JWT_REFRESH_SECRET` / `AES_SECRET_KEY` / `HMAC_SECRET` 有 ≥32 长度闸、`DOCS_PASSWORD` 有
> ≥16 闸（这些会启动失败，吵得响）；`METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` /
> `LOG_SHIPPING_TOKEN` / `MONGO_ROOT_PASSWORD` / `SENTRY_DSN` / `REDIS_URL` 没有长度判据，
> 它们的形态是"进程活着但对不上"——其中 webhook 签名密钥被截断等于**安全告警静默丢弃**。
> 反向核验过一条更吓人的假设，结论是否定的：`ADMIN_INITIAL_PASSWORD` 被截断**不会**
> 造出 1 字符管理员口令，`models/User.js:67` 的 `minlength: 12` 会在 `User.create` 抛错。

- `scripts/mongoUri.sh`：在任何命令替换**之前**按原始文件字节判 NUL
  （`tr -dc '\000' < file | wc -c`），非零即拒绝并点名文件与"UTF-16/二进制另存为"这一成因。
  判据写成"剩下的字节个数 ≠ 0"而不是"grep 到就算"：`tr` 自身失败时残串是空串，
  `"" != "0"` 照样点亮 ⇒ fail-closed。
- `src/config/secrets.js`：在唯一的注入入口抛错，早于赋值也早于"空文件"判定
  （`'\0'` 单字符文件若走到赋值，得到的会是**空**环境变量）。只拒 NUL，不拒"所有控制字符"——
  `LOGIN_ECDH_PRIVATE_KEY` 是多行 PEM，中间的 `\n` 合法，一刀切会把正常部署拦死。
- 报错只点名变量名与文件路径，不回显任何密钥字节（新增一条用例钉住这点）。
- 新增 4 条 shell 侧 + 6 条 Node 侧用例，其中两条是**闸内的变异自证**：
  `backupUriFile.test.js` 按代码特征删掉 NUL 闸那段、用同一份 UTF-16 夹具重跑备份，
  必须变成 rc=0 且产出归档——这证明"红"确实来自那道闸，而不是被别的东西凑出来的绿；
  找不到判据行就直接抛错，避免上一轮踩过的"变异没落地、用例对着未改动的文件保持绿"。
  Node 侧配套一条反向自证：多行 PEM 照常注入，证明判据没退化成拒绝一切。
- 记一条踩过的测试环境坑：**平台事实不能在 jest 进程里量**。第一版把
  `process.env.X='A\0b'` 的回读断言写在用例里，jest-environment-node 用自己的对象代理
  `process.env`，NUL 能原样往返 ⇒ 把"真实进程会截断"这条前提判成了假。改为 spawn 子进程量，
  并把判据写成"长度不是 3"（截断得到 1、或某平台直接拒绝赋值都算通过），
  这样 Linux 上的表现尚未实测也不会成为跨平台红灯。

### 安全（2026-10-03 · 异地副本的"空命令假成功"：`BACKUP_OFFSITE_CMD=" "` 时一次都没复制，回显却写 completed）

> 背景：`scripts/backup-mongo.sh` 的异地副本那一步，头部注释早就写着原则
> 「被吞掉的异地失败比没有异地更危险——它让运维以为自己有异地副本」。判据却是
> `[ -n "$BACKUP_OFFSITE_CMD" ]`：**非空**不等于**有词**。实测（bash 5.3.9）
> `BACKUP_OFFSITE_CMD=" "`（env 文件里多打一个空格就够了）会走进分支，
> `read -r -a` 切出 0 个词，而 `"${空数组[@]}"` 落在命令位置是一条**空命令**——返回 0。
> 于是异地副本一次都没有执行，回显却是 `Offsite copy completed:`，连未配置那支的
> `Warning` 都不打。这是那条原则里最坏的形态：它连"失败"都不是，没有任何信号可看，
> cron 邮件里是一次"带异地副本的成功备份"，而备份实际只存在于本机（与数据库同机，
> 宿主机级故障时等于没有备份）。

- 判据从"字符串是否非空"改成"**是否切出至少一个词**"：`${#OFFSITE_ARGS[@]} -gt 0` 才执行；
  配置了却全是空白 ⇒ 单独一句 `Error`（说清是配错了，不是没配）并 `exit 1`，与异地命令
  失败同档——那档本来就是 `exit 1`，没有新的中断面。
- 未设置那一支不变（仍是 Warning + 退出码 0），且新增一条反向自证钉住它：
  新分支不得把"没配异地"吞成失败。
- 顺带让 `"${OFFSITE_ARGS[@]}"` 只在词数 > 0 时展开。旧写法在老 bash（4.2/4.3，RHEL7 一类
  宿主）的 `set -u` 下展开空数组会直接掐死调用方——那是"备份跑到最后一步才崩"，
  比这次的静默更响，但同一处判据一次修掉。
- 三条新用例（真跑脚本 + PATH 桩 mongodump/gpg/offsite-ok）：空白值 ⇒ 退出码 1 且
  **不得**出现 `Offsite copy completed`；真命令 ⇒ 桩确实被调用过、且拿得到定稿后的
  `BACKUP_FILE`/`BACKUP_SHA256`；未设置 ⇒ 只有 Warning、退出码 0。
  旧实现下第一条为红（已实测），后两条在旧实现下也是绿 ⇒ 信号只由第一条承担。

### 安全（2026-10-03 · 主机段改写的 13 条拒绝收拢成一句句能定位的原因，并改掉上一轮两处失实论证）

> 背景：`scripts/mongoUri.sh` 的 `mongo_swap_host` 上一轮已经按参考解析器的读法重做了取段，
> 但拒绝路径只剩一个退出码。本会话实测出两类问题，一类是现场可用性，一类是**注释里写的
> 事实站不住**——后者更贵，因为它会让下一个读者照着错的模型改这段代码。
>
> 1. **汇总句几乎总是指向错误的变量**：13 个互不相同的失效方向全部折叠成调用方那一句
>    「无法把 URI 主机段改写为容器内地址（`<目标>`），请检查 `MONGODB_URI` 形态」。
>    `MONGO_CONTAINER_HOST` 为空或拼错时同样 rc=1，而运维被告知去查 URI——在恢复窗口里
>    这是把人往错误的文件上引。
> 2. **少给一个参数会打断调用方**：本文件被 `set -u` 的脚本 source，`mongo_swap_host x`
>    原先以 `$2: unbound variable` 中断**调用方**，走不到任何一条能看懂的拒绝。

- 新增 `mongo_swap_refuse`：每条拒绝往 stderr 打一行**原因类别**（未转义 `@`、空凭据段、
  种子列表空项、越界端口、`+srv` 带端口/带逗号、目标地址非法……），只点变量名与形态，
  **绝不回显 URI 或口令的任何字节**——这是凭据，点名不取值。调用方那句汇总改为
  「拒绝执行；上一行点名是哪条判据拦下的」，不再独自承担定位责任。
- `mongo_swap_host` 的入参取 `${1:-}` / `${2:-}`：缺参数现在是一条拒绝，而不是一次崩溃。
- 顺带修掉一处**指错变量的标签**（是新测试在跑的时候自己撞出来的）：改写产物过值判据时，
  标签原先写成「`MONGO_CONTAINER_HOST` 改写后的连接串 含空白、换行…」，于是 URI 里带换行时
  运维被告知去查那个本来就没问题的变量。走到这一步时 `_scheme` 由 case 字面量决定、
  `_target` 刚过 `mongo_valid_hostport`（单行纯可打印 ASCII），可能带越界字节的只剩凭据段与尾部
  ⇒ 标签改为点名 `MONGODB_URI`，这是**可证明的**归因而不是措辞偏好。
- 纠正上一轮写下的两条**失实论证**（都已实测取证，判据本身不变）：
  - 「参考解析器把 `a,,b` 读成少一个主机」不成立——它**接受**并读成
    `hosts=["a:27017", ":27017", "b:27017"]`，即多出一个空主机名的种子。所以这一条是
    「刻意比解析器严」，不是「它也会拒」；`a@b@c` 同理，实测它**不报错**而是静默把主机
    换成没人写过的那一段。本机实测的两个读者对同一条串给出相反答案
    （`mongodb://u:p@ss@h:27017/db` ⇒ JS 包按**第一个** `@` 切凭据 ⇒ `hosts=["ss:27017"]`；
    Node 的 WHATWG `new URL` 按**最后一个** `@` 定界 userinfo ⇒ `hostname=h`）。
    原先这里写着"Go 驱动按 RFC 3986 取最后一个"——Go 驱动本机没有二进制，那一直是**推断**，
    不该写成实测。判据因此不赌读者：两个读者读法相反的形态一律硬拒。
  - 「刻意更严的两处」实际是四处，漏记了种子列表空项与值里的空白字节两条同族判据。
- 交代一条**能力边界**，防止 parity 全绿被读成"已验证过 mongodump"：本仓 parity 闸用的
  参考解析器是 JS 包（`mongoose` 内嵌的 `mongodb-connection-string-url`），而真正消费产物的是
  mongodump / mongorestore 的 **Go 驱动**；这台机器上没有 mongodump，所以 parity 只能证到
  "与 JS 包同口径"。已知两边读法不一致的形态就是上面的裸 `@` 分界——判据一律取更严的一侧。

### 供应链（2026-10-03 · `capture-image-digests.sh` 不再能留下"半钉"仓库，也不再吞别人的临时文件）

> 背景：这个脚本把 Dockerfile / compose 的基础镜像从可变 tag 换成 registry digest。上一轮已经补上
> "sed 无匹配仍返回 0"的静默 no-op 校验，但落笔顺序还是**边检查边写、两个目标顺序跑**。本轮真跑
> （PATH 插 docker 替身 + `--root` 指向临时仓库副本）实测出三种失效形态，都属"报成功/报错都看不出来"：
>
> 1. **半钉仓库**：compose 的 tag 与脚本常量漂移 ⇒ 第一轮把 Dockerfile 改成 digest，第二步才报错退出，
>    仓库留下"Dockerfile 已钉、compose 仍指向可变 tag"。
> 2. **死路**：照报错把 compose 修好再跑第二次，脚本在 Dockerfile 那一步就撞
>    "已经存在 @sha256 钉版引用"退出 ⇒ compose **永远钉不上**，唯一能修它的脚本自己拒绝再跑。
> 3. **吞别人的文件**：`sed > $file.pin.tmp; mv $tmp $file` 会把上一次中断留下（或人工放置）的
>    `Dockerfile.pin.tmp` 静默吃掉——探针读到的是 ENOENT，而退出码 0。

- 落笔改成**三相**：`check_ref`（只读，两个目标都确认可改，含"临时文件此前不存在"）→ `stage_ref`
  （只写临时文件并预演校验）→ `commit_ref`（`mv` 改名 + 落笔后复核）。任何一步失败，两个目标文件
  都逐字节不变、目录里没有残留临时文件。
- `trap … EXIT HUP INT TERM` 只清理**本脚本确认过"原本不存在"**的临时文件：`PIN_TMP_*` 两个全局量先置空，
  `check_ref` 通过之后才赋值。直觉写法 `trap 'rm -f "$ROOT"/*.pin.tmp' EXIT` 会在报错退出的那一刻删掉
  运维的文件——变异实验（把 `-e` 门禁摘掉）证明这条判据是承重的：残留内容变成 `<<DELETED>>`、退出码 0。
- 诚实交代残余边界：两条 `mv` 之间不是原子的（跨两个文件不存在单次 rename）。check 已确认两文件都在且
  都可改、stage 已验过改好的产物，失败面从"任何解析/匹配错"缩到"同目录 rename 本身出错"。
- 测试 `src/tests/imageDigestGate.test.js` 10 → 19 条：新增原子性（第二个目标漂移时第一个必须 `toBe`
  原始字节）、自愈（修好 compose 后重跑必须 rc=0 两边都钉上）、残留（拒绝 + 不覆盖 + 退出时不删 +
  删掉后能正常钉版），以及失败臂矩阵（tag 漂移×2 / digest 取不到 / 伪 digest / 未知参数）的公共后置条件。
  逐条做过变异反证：`M1_order`（把 compose 的检查挪到 Dockerfile 落笔之后）点亮前两条，
  `M2_noTempGate`（摘掉临时文件门禁）点亮第三条；control 三场景全绿。
- 夹具侧补两条门禁自身的自证：`tmps` 过滤器在残留用例里必须**看得见**那个文件（否则"失败不留临时文件"
  是空集造成的假绿）；`test.each` 的表宽必须等于处理函数形参个数——窄一格 jest-each 会注入 `done`，
  用例不失败而是卡满 30s 超时。

### 安全（2026-10-03 · 备份的主机段改写按参考解析器的读法重做：静默连到别处、合法 URI 被拒、坏端口被顺手换掉）

> 背景：`scripts/mongoUri.sh` 上一轮已经把那句 `sed -E "s#^((mongodb(\+srv)?://)…#"` 换成纯 shell
> 字符串重建，但**取哪一段**的判据还是那套 `case */* | \?* | *` 三分支 + `##*@` 切凭据。
> 本轮拿参考解析器（`mongoose.mongo.MongoClient`，即 `src/config/database.js:51` 讨论的那份内嵌
> `mongodb-connection-string-url`）逐条形对照，实测五条同根缺陷，全部与"备份到底连了谁"有关：
>
> 1. **静默改错主机**：`mongodb://u:p@db.internal:27017?appname=bob@corp`（无路径、查询串里有裸 `@`）
>    ⇒ rc=0，产物 `…@db.internal:27017?appname=bob@127.0.0.1:27017`。主机段一动没动、目标地址被拼进
>    查询串，而解析器把它读成 `hosts=["db.internal:27017"]`（**不报错**）——横幅承诺 127.0.0.1，
>    mongodump 连的是 db.internal，退出码却可以是 0。根因：第三分支把整串当 authority，再按**最后**一个 `@` 切凭据。
> 2. **副本集种子列表被拒**：`mongodb://a:27017,b:27017/db?replicaSet=rs0` ⇒ rc=1（逗号不在字符集里）——
>    合法 URI 备份不了，报的却是"形态异常"。
> 3. **无路径带查询被拒**：`mongodb://h:27017?directConnection=true` ⇒ rc=1（`\?*` 只匹配以 `?` **开头**的串）。
> 4. **IPv6 容器地址当目标被拒**：`MONGO_CONTAINER_HOST='[::1]:27017'` ⇒ rc=1，而 URI 里写同一段是放行的
>    ——同一件事两侧判据不一致。
> 5. **交回 mongodump 自己都不认的串**：`mongodb://a@b@c:27017/db` 与 `mongodb+srv://…` 带端口的产物
>    （`+srv` 禁止端口）都是 rc=0。

- 取段判据改成按**解析器怎么读主机段**来定：authority 终止于第一个 `/ ? #`，凭据与主机的分界取**第一个**
  `@`，主机段允许逗号分隔的种子列表且每项都得过 `host[:port]`/`[IPv6][:port]` 判据，主机段已等于目标地址
  ⇒ 合法空操作放行（上一版那条假阳性就是这一形态），其余认不出来的一律硬失败。
- 新增四个可复用判据：`mongo_valid_hostport` / `mongo_valid_hostlist` / `mongo_valid_userinfo` / `mongo_valid_port`。
  端口区间那条是新发现的第二类失效方向：`h:0`（'Invalid port (zero) with hostname'）与 `h:65536`
  （'Unable to parse h:65536 with URL'）解析器都报错，而我们放行等于**顺手把坏端口换成目标端口**——
  现场拿到的是一个从来不存在、也从来没被 mongodump 拒过的 URI。区间判据写成字符串比较而不是 `$(( ))`：
  shell 把 0 前缀当八进制（`08` 直接算错），而解析器把 `07017` 读成 7017。
- 一条**负结果**记录在案，防止下一个读者把 `#` 也当成缺陷：`mongodb://h#1/db` 曾被写成"解析器读成
  `["h#1"]`、我们比它严"，实测不成立——它在 `#` 处终止 authority 读成 `hosts=["h:27017"]`、db 仍是 `db`，
  与我们的取段口径完全一致 ⇒ 放行，由 parity 闸逐条比对产物。
- `src/tests/config/mongoTransportParity.test.js` 60 → **160 例**，承重的那条是新加的**参考解析器 parity 闸**：
  真值表里每一条 rc=0 的产物都重新真跑一遍并交给 `new MongoClient(…)` 读，要求
  `hosts === [目标地址]`、库名与凭据逐字不动；输入本来就解析不动的那一类只有"两边同一句错"才判为继承
  （唯一一条：`?drop:true` 撞驱动的 option 白名单）。清单从真值表**推导**而不是另抄一份，新加一条自动进闸。
  闸自身由六条合成违例（旧写法的真实产物）反向自证，含上面缺陷 1 那条"解析器不报错却连到别处"的形态。
- 一条夹具层的坑记进注释与判据：jest-each@29.7.0 的 `applyArguments`（`bind.js:78-80`）在
  **行数组比测试函数声明的形参短**时会把 `done` 注入成最后一个实参 ⇒ 那些行不是断言失败而是**超时**。
  实测一次跑出 5 条 30 秒超时 + 1 条真失败，看起来像整道闸坏了。现在 trailing 形参带默认值
  （`Function.length` 停在第一个默认值之前），并有一条表宽判据配合成违例钉住它。

### 安全（2026-10-03 · 一次性 harness 的第二根暴露轴：宿主上的明文密钥，不只 `*_FILE`）

> 背景：`scripts/devSecretIsolation.js` 上一版把宿主的 `*_FILE` 指针全量置空，但它只看指针。
> 密钥有**两根正交的轴**——形态（`<NAME>_FILE` 指针 / `<NAME>` 明文值）与通道（宿主 `export` / `.env`），
> 上一版按通道堵了两格，形态那一根整条没堵。而明文形态不是事故形态：`.env.example:2`
> 就明写「JWT_SECRET / AES_SECRET_KEY 等可以直接写在本文件（适合本地开发）」。
> 本机实测（`node -e` 枚举 `FILE_BACKED_SECRETS`）：仓库根 `.env` 今天正带着 6 个明文密钥，
> 其中 `MONGODB_URI` / `ADMIN_INITIAL_PASSWORD` 与一次性 harness 要用的值是同一类东西。

- **守卫按名字全量置空两类**：`<NAME>_FILE` 与 `<NAME>`。漏掉的这一类比原来那条更宽，
  因为 harness 只覆写它记得的那几个名字，其余名字一个都不碰，于是明文值直接穿过 dotenv 被读到：
  `REDIS_URL` ⇒ 冒烟的验证码/限流计数读写宿主那台 Redis；`SECURITY_ALERT_WEBHOOK_SECRET`
  ⇒ 冒烟造的假告警签名有效、真推到值班群；`SENTRY_DSN` / `LOG_SHIPPING_TOKEN` ⇒ 测试流量进真实观测面；
  `ADMIN_INITIAL_PASSWORD` / `MONGO_ROOT_PASSWORD` ⇒ 播种与清理动的是真凭据。
- **由此新增一条顺序不变量**：置空明文值意味着 harness 自己的一次性赋值必须**晚于**守卫
  （先赋值再调守卫会被擦掉）。接线闸原来只钉"早于 `require('../src/index.js')`"，
  现在同时钉"早于任何 `process.env.<密钥名>[/_FILE] =` 赋值"，并带三条负向对照
  （非密钥赋值不算、生成的子脚本里整行是字符串字面量的赋值不算、真赋值提到守卫前必须点名）。
- **"空串会不会变成第三种状态"有专门用例**：这几个名字在 `src/config` 里没有字段，消费方直读 env
  （`sharedCache.js:52` 的 `(process.env.REDIS_URL || '').trim() !== ''`、`initData.js:770` 的
  `if (process.env.ADMIN_INITIAL_PASSWORD)`），置空与"宿主本来没配"逐点等价；用例钉的是**真实源码行**，
  判据写法改成 `!== undefined` 立刻红。
- **告警点名不取值**：`*_FILE` 条目打路径（值本身是路径），明文条目只打名字并注明"值不打印"——
  报错里复读密钥等于把它从 env 搬进 stdout/stderr，CI 日志保留时间通常更长（同一口径见 `scripts/secretFileArg.js`）。
- **`src/tests/config/disposableSecretIsolation.test.js` 12 → 19 例**：来源臂从两条加到三条
  （`export` / `.env` 混装 / **`.env` 里只有明文、一个 `*_FILE` 都没有**）。第三条臂就是上一版的靶子：
  它的 `uri`/`jwt` 本来就是一次性值，"全绿"完全可以和"真 Redis、真初始口令已接上"同时成立。
  真值表随之扩到九格，`del × {dotenv, plain}` 两臂共同钉住"置空而非删除"对**两类**都承重；
  `rootPw` 的期望从 `undefined` 改成 `''`（`undefined` 只证"没 hydrate"，`''` 才证"宿主明文也没接上"），
  并在探针里给所有 env 观测加 `?? null`——`JSON.stringify` 会丢掉 `undefined` 键，
  那样"挡住了"与"夹具压根没跑"分不开，是一条空断言；另补一条**真文件减法自证**：
  擦掉置空明文的那两行、只留置空指针，明文轴必须立刻漏且被点名。
- 单位夹具改用"先全部置空"而不是 `delete` 构造"宿主干净"：本 describe 的 cwd 是仓库根，
  那里真有一个带 6 个明文密钥的 `.env`，`delete` 会被守卫内的 dotenv 填回来——
  这正是实现选择置空而非删除的同一条理由。
- **真 harness 复跑**：`REDIS_URL=… ADMIN_INITIAL_PASSWORD=… SENTRY_DSN=… node scripts/e2e-smoke.js`
  ⇒ 守卫打印 3 条明文点名（无值）、`[E2E] 结果：14 通过, 0 失败`、退出码 0；
  不带毒环境的裸跑同样 14/14 绿。

### 安全（2026-10-03 · 备份/恢复：主机段改写去掉 sed，失败现场不留明文归档）

> 背景：`scripts/mongoUri.sh` 是备份与恢复共用的唯一一份 URI 判据，它自己却是
> `sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1${MONGO_CONTAINER_HOST}#"`——
> 两条注入路径都落在这句替换上，而落点都是 mongodump/mongorestore 的 **0600 配置文件**：
> 配置里唯一由调用方决定的就是那一行 `uri:`。

- **`mongo_swap_host` 改为纯 shell 字符串重建**（scheme / authority / tail 三段用参数展开切开）。
  sed 形态的两个实测失效：① 替换串里的字面 `\n` 被 GNU sed 展开成**真换行** ⇒
  `MONGO_CONTAINER_HOST='127.0.0.1:27017\ncollection:auditLog'` 能给配置追加第二行，
  单集合导出被记成一次成功的全量备份；② 口令里未转义的 `/` 提前终结 `[^/]*` 那次匹配 ⇒
  替换错位（`mongodb://u:p/x@h:27017/db` → `mongodb://127.0.0.1:27017/x@h:27017/db`），
  **凭据被静默丢弃**而横幅承诺的仍是 `h:27017`/`db`。
- **`MONGO_CONTAINER_HOST` 新增字符集判据**（`[A-Za-z0-9.:_-]`，且端口必须是数字、
  IPv6 字面量 `[::1]:27017` 单独放行）。换行、空格、`\`、`;`、`|`、反引号、`$` 全部进不来。
- **切出来的主机段必须"确实是一个 authority"**：认不出来就拒（`u:p`、`mongo:abc`、`mongo:`、
  `[::1]:abc` 都在这一条）。第一版在这里补过一条"有凭据且路径里含 `@` ⇒ 拒"，实测把
  `mongodb://u:p@mongo/db@name` 一起误杀（库名带 `@` 合法，authority 终止于第一个 `/`），
  已由精确判据取代。
- **两条出口都过值判据**：改写那一支与"主机段本来就等于目标地址"的合法空操作那一支。
  少了后者，`$'mongodb://127.0.0.1:27017/fsms\ndrop:true'` 配 `MONGO_CONTAINER_HOST=127.0.0.1:27017`
  会绕过全部检查被原样交回调用方。
- **`mongo_validate_uri` 的越界字节判据补哨兵**：`$(… | tr -d '\041-\176')` 非空这个写法漏在
  **命令替换会剥掉尾部全部换行**——载荷 `…?authSource=admin\ndrop:true` 的注入部分本身全是
  可打印 ASCII，残串为空 ⇒ 放行，`drop:true` 成为配置文件的第二行，而门禁与横幅都声明相反。
  现在先补一个 `~` 再比，判据无歧义。
- **`backup-mongo.sh` 的加密门禁提到 `mongodump` 之前**（新增 `crypto_precheck_backup`，
  与 `crypto_encrypt` 同源）。原先 `gpg` 不在 PATH 或 `BACKUP_GPG_RECIPIENT` 没配时，
  脚本先花几分钟导出整个明文全量库（人员 PII + 不可篡改审计集合）再在加密步失败退出，
  而 `set -e` 直接带走 ⇒ "写完就删明文"那行永远执行不到，**每次失败都往 `backups/`
  多留一份明文**。现在三种不可用形态都在创建目录之前拒绝。
- **未定稿产物由 `cleanup` 一律删除（`FINALIZED` 标志）**。失败产物与成功产物同名
  （`fire-safety-backup-*.gz[.gpg][.sha256]`），留着就会被 retention 清单、回滚演练与
  "最近一次备份"的报表挑中。定稿点（密文 + 校验和都在手且非空）之后反向成立：
  一个都不能删——异地副本失败按设计整体失败，那时已到手的本地副本仍是回滚抓手。
  `deployment/backup-encryption.md` 的失败语义两条已同步。
- **闸**：`src/tests/config/mongoTransportParity.test.js` 15 → 41 例（真跑 bash 的行为真值表 +
  目标地址字符集九臂 + 值判据的 LF/CR 成对臂；结构层的"反向前提"换了方向——原先断言
  那句 sed 还在共享实现里，现在断言改写函数体内不许出现 sed，并用历史写法作合成违例
  证明判据非空集，注释过滤本身也自证）。夹具改经单引号安全转义传入（`$`/反引号不得被
  bash 先展开一次），CR 载荷由 shell `printf` 现场构造（Node 传 `bash -c` 时裸 CR 会在
  传输层被吃掉，测到的是"没有 CR 的串"——假绿）。
- **新闸 `src/tests/deploy/backupFailureArtifactHygiene.test.js`（9 例）**：真进程 + 桩
  mongodump/gpg（PATH 注入），断言的是"目录里到底有什么文件、桩有没有被调用"。
  含一处前世版对照：从脚本副本里按缩进反向引用删掉 `FINALIZED` 块（并 `bash -n` 证明它仍是
  合法脚本），同一夹具必须**留下明文归档**，否则这条断言抓不住回退。
  `backupUriFile.test.js` 的 SIGINT 用例同时补上"打断后目录里不得留半截归档"。

### 安全（2026-10-03 · 密钥轮换的密钥不再经过命令行）

> 背景：仓里所有密钥早已统一成 `<NAME>_FILE` 口径，唯独密钥轮换这一族还留着
> `--new-key <KEY>`：把值写在 argv 上，同一个密钥就同时出现在
> `/proc/<pid>/cmdline`（Linux 默认 0444 ⇒ 同机任意本地用户可读，而一次全量迁移要跑几分钟，
> 窗口足够长；`ps(1)` / 任务管理器同理）、shell 历史（`HISTCONTROL=ignorespace` 只是
> "记得在前面加空格"的人为约定，不是机制）、以及任何 `set -x` 的 CI 日志。
> 同一门安全要求上的两个标准，收口成一条。

- **新增 `scripts/secretFileArg.js`**：`readSecretFile` 把"密钥文件"的形状判据写死——
  恰好一行非空内容、去 UTF-8 BOM 与 CR/尾空白、字符集限 `0x21–0x7E`（与 shell 侧
  `mongoUri.sh` 的 `tr -d '\041-\176'` 同判据）；读不到、多行、含空白一律**硬失败**，
  绝不"取第一条非空行"蒙过去。`resolveSecretSource` 的优先级与 shell 侧一致：
  **显式 `--*-file` 赢过环境变量**（命令行点名的是"这一次轮换要用的值"，不能被 shell 里
  残留的同名变量悄悄改写），两者都给时只打一行提示且**只点名不取值**。
  所有错误信息只含标签与路径——一条"密钥泄漏"的报错如果把密钥再打一遍，
  就是把它从 argv 换成了 stdout/stderr，而 CI 日志的保留时间通常更长。
- **`migrate-mfa-secret.js` / `resign-audit-hmac.js` 改为 `--new-key-file` / `--old-key-file`**，
  旧形态不是"删掉了事"而是**具名拒绝**（exit 2 并指向替代写法）。具名而非落到
  `未知参数：${argv[i]}` 那条默认分支是刻意的：默认分支打印 `argv[i]`，而循环下一步就是
  那个密钥本身——报错本身就成了第二次泄漏。
- **一处有意的收窄**：`--*-file` 只接受 ASCII 密钥；密钥本身含非 ASCII 的用户仍走环境变量
  （env 不经 `/proc/<pid>/cmdline`，不在这条禁令范围），报错里直接写明这条路。
- **手册同步改口径，并顺手拆掉一个更常见的事故源**：`deployment/secret-rotation.md` 原先第 0 步
  `openssl rand -hex 32` 让人"记下输出"、第 3 步 `printf '%s' '<新KEY>' > 载体` 让人**再敲一遍**——
  重敲一次打错一个字符，数据已经用新钥加密完毕而应用拿的是另一把钥，比不改更糟。现在生成即落盘
  （`umask 077` + 单行文件），迁移用 `--new-key-file` 指它，换钥用 `mv` 把同一份字节扶正；
  全量轮换一节本就由 `generate-secrets.js` 产出文件，直接指过去即可。
- **新闸 `src/tests/deploy/cliSecretArgGate.test.js`（20 例）**，三层判据：
  静态完备性用**派生枚举**（"从 argv 取值"的判据是 `argv[i] === '--x'` 之后 60 字符窗口内的
  `argv[++i]`，因此具名拒绝分支不会被误判成还在收密钥），任何密钥类选项必须以 `-file` 结尾，
  文档里 `node scripts/…` 形态的命令行只允许使用该脚本确实接受的那些选项——新写第三个轮换脚本
  时这条闸自动对它提要求，不需要有人记得来登记；行为闸真起子进程传 canary，断言 exit 2、
  点名替代写法、**canary 一个字节都不出现在 stdout/stderr**、且看不到"已连接"（拒绝早于连库）；
  再加 `--new-key-file` 成功路径"值进内存但不进输出"与优先级提示。
  自证：合成违规（`--new-key` / `--db-password`）与真文件减法（把手册里的 `-file` 去掉）都能点亮。
- 受影响的既有套件同步迁移到新形态并复跑绿：`destructiveGuardOrder`（9 例，夹具改为真实密钥文件——
  必须是**能过强度校验**的密钥，否则 migrate 会以"拒绝迁移"而非断言的"拒绝执行"退出）、
  `hmacResignPrecheck`（8 例）、`runbookApplyCommandContract`、`migrateMfaWriteVerify`。

### 安全（2026-10-03 · 冒烟/压测/演练不得接回真实基础设施）

> 背景：`src/config/index.js:10-11` 在 **require 期**就调 `hydrateSecretsFromFiles()`，而冲突规则是
> **文件优先**（`src/config/secrets.js:113` 无条件 `process.env[name] = value`）。三个 harness
> （`e2e-smoke` / `load-test` / `production-drill`）的形状是「先设一次性 env，再 `require('../src/index.js')`」，
> 于是只要宿主上还留着 `*_FILE`，回填就会把一次性 `MONGODB_URI` 覆写成真实库连接串——**并且不报错**。
> 后果不是测试变红，是**写**：`npm run test:e2e` 往那个库播种管理员、建用户、发告警；
> `npm run test:load` 往它打五相压测流量并写审计。

- **新增 `scripts/devSecretIsolation.js`**：按 `FILE_BACKED_SECRETS` 全量把 `*_FILE` **置空**。
  两个来源都必须堵（第一版只堵了第一条，实测被打回）：宿主 shell 的 `export`
  （`deployment/secret-rotation.md` 要求每条命令自带 `*_FILE` 前缀，把它 export 起来是最省事的顺手做法），
  以及 `.env` 里写着 `*_FILE`（`.env.example:12` 的生产口径 b)）。第二条的关键在时序：dotenv 跑在
  hydrate 的前一行，守卫只看"当前 `process.env` 里有没有"就会漏掉整条路径，故守卫自己先 `require('dotenv').config()`。
- **置空而非 `delete` 是承重的**：dotenv 16.6.1 对"已定义"的键不覆盖（空串也算已定义），
  但会重新填充被 `delete` 掉的键；`secrets.js:71` 又把空路径当"未配置"跳过。
  六格真值表把这条钉死：`del × .env` 那一臂**仍然被覆写**，所以"觉得 delete 更干净"的改法立刻红。
- **刻意不做的两个替代**：用 `NODE_ENV` 跳过回填（`production-drill` 自己要 `NODE_ENV=production`，
  跳过等于演练失去生产同构性，而那正是它存在的意义）；把 hydrate 改成"环境变量优先"
  （推翻一个深思熟虑的安全决定——挂载 secret 必须压过残留的 `.env` 明文，否则轮换看起来生效实则没生效）。
- **新闸 `src/tests/config/disposableSecretIsolation.test.js`（12 例）**：真子进程 + 真 `src/config`，
  断言的是"配置对象里到底是哪个 URI"而不是脚本里有没有某个字符串。含 `MONGO_ROOT_PASSWORD`
  这一臂：harness 从不给它赋值，回填却照样把真实值填进去 ⇒ 危害不止"它记得覆写的那几个键"，
  同时反向钉住守卫自己绝不 hydrate。
- **顺手拆掉上一轮自带的一颗定时炸弹**：`backupUriFile.test.js` 的 SIGINT 用例让外面的
  `sleep 0.4` 与桩里 `sleep 1.2` 赛跑，本机并行跑 `src/tests/config src/tests/deploy` 时漂了
  （归档写完信号才到 ⇒ "Backup completed successfully" 照打 ⇒ 用例红）。改成由桩在
  **半截归档落盘的那一刻** `kill -INT "$PPID"`：红绿只取决于脚本自己的 trap 语义，
  不再取决于机器当时有多忙。
- **既有闸 `scriptSecretHydration.test.js`（14 → 16 例）被这次改动撞红一次，且它是对的**：
  守卫用 `process.env[name + '_FILE']` 动态键读密钥注入项，按闸的口径就是"读取者"，
  而它的合规写法（在库内调 `hydrateSecretsFromFiles()`）恰恰是它要防的那个动作。
  因此给的是**逐名取证**的"共享库"豁免：原来那句 `consumers.length >= 4` 是全局计数，
  新登记的库蹭得到同一句结论却可能压根没人调用；改成每条豁免各自要求"被至少一个入口 require"
  （引入点判据在这里**刻意收紧**：读点判据宽松只会多算一个读取，豁免前提判据宽松则让空白条看起来有主）
  - "库里没有 `require.main === module` 入口支"，并补一条**真文件减法**：把三个 harness 的 require 全擦掉，
    豁免必须当场失效。

### 安全（2026-10-03 · 备份/恢复 shell 的输入校验与退出路径）

> 背景：上一轮给 shell 侧接上 `*_FILE` 后，逐行审计发现"能跑起来"和"不会把凭据/目标库交给
> 一个没人校验的字符串"是两件事。九条 CONFIRMED 全部按缺陷本身定级，不看发现者的措辞。

- **显式 `MONGODB_URI` 此前完全不校验**（只有文件那条路校验）。最糟的一条：连接串里嵌一个换行，
  `printf 'uri: %s\n'` 写进 mongodump 的 `--config` 后，第二行就成了**配置文件里的一行选项**——
  `…@host/db\n drop: true` 直接越过恢复侧所有门禁把"删库再恢复"追加进去。
  新增共享判据 `mongo_validate_uri`（整串必须是单行纯可打印 ASCII + `mongodb(+srv)://` 前缀），
  两个来源同闸。
- **缺 `--` 操作数分隔符**：`MONGODB_URI_FILE=-c` 会被 `cat`/`grep` 当选项 ⇒ 读的是**调用方的 stdin**
  而不是那个文件。补 `--`，并用真子进程断言"打开的是那个文件"。
- **告警回显会泄出口令尾巴**：`${MONGODB_URI#*://}` 之后接 `${…*@}` 是最短匹配，
  口令里含未转义 `@` 时把口令后半段连同主机名一起打进日志。改最长匹配，并补含 `@` 口令的夹具。
- **恢复目标必须由字面决定**：URI 不含库名时，目标库由**归档内容**决定，
  而 `RESTORE_CONFIRM` 的核对退化成"输入就是整串 URI 本身"——一个可猜的哨兵。
  现在缺库名直接拒绝执行（门禁的前提是目标 identifiable），正向对照同夹具带库名放行。
- **`trap cleanup EXIT INT TERM` 不自己 exit**：SIGINT 打断备份时，清理跑完继续往下执行，
  实测打印「Backup completed successfully」而产物只有 5 字节。三条 trap 各自补 `exit 130/143`。
- **`local` 传输分支失败后留 0 字节归档**：`docker` 分支早就处理了（重定向在失败前就建了文件），
  `local` 分支没有——一个躺在 `backups/` 里的空 `.gz` 在回滚清单上"就是一次备份"。同一处理补齐。
- **`grep -c` 无命中时把 `-c` 当选项吃 stdin**，且失败路径留下的空串会让 `[ "$_n" -eq 0 ]`
  报 integer expression。改成先 `cat` 进变量再从 stdin 计数。
- 测试：`backupUriFile.test.js` 17 → 23 例、`backupTransport.test.js` 7 → 8 例，每例都带**正向对照**
  （证明不是靠"永远判红"混过去的）。`src/tests/config` + `src/tests/deploy` 合计 632/632 绿。

### 运维可用性（2026-10-03 · `*_FILE` 这条线的最后一公里：shell 侧解析 + 手册里每条命令行自带密钥）

> 背景：前两轮把 Node 侧的六个运维脚本 + `npm run validate` 都接上了 `<NAME>_FILE` 回填，
> 但**备份/恢复是 shell 脚本**，而手册里的命令行为它们提供的是明文 `MONGODB_URI=`。
> 两条都在生产口径（`.env.example:12` 的 b)「只配 `*_FILE`，`.env` 不写同名变量」）下失效。

- **finding：`scripts/backup-mongo.sh` / `restore-mongo.sh` 只认明文 `MONGODB_URI`**。
  生产宿主机上只有 `./secrets/mongodb_uri` 这个文件，于是每日 cron 每晚 `exit 1`、
  **零归档**，而 cron 的 stderr 没人读——备份线静默停摆可以拖到第一次真要恢复的那天。
  修法：共享实现 `scripts/mongoUri.sh` 里加 `mongo_hydrate_uri`，两个调用点各三行改过去，
  仍保持"凭据不进 argv"（连接串走 mongodump/mongorestore 的临时 `--config` 文件）。
- **一处刻意与 Node 侧相反**：shell 里**显式 `MONGODB_URI` 赢**（`secrets.js:106-113` 是文件赢）。
  理由：恢复的目标库必须由这一行的字面内容决定，不能被环境里残留的 `*_FILE` 静默改写到
  另一个库——把备份写进错库远比连不上严重。并存时打 Warning，README 与手册都写明这层反向。
  坏文件（空 / 多行 / 不是连接串 / 含空白或控制字符）**硬失败**，不像应用侧只告警。
- **夹具暴露的实测纠偏**：`printf 'mongodb+srv://u:p%40ss@h/db'` 里 `%40s` 被 printf 当宽度
  说明符，写出 40 个空格，而首版形状检查**照样放行**（只裁了尾部）。改成"整串必须落在
  0x21–0x7E"后该形态才被判红。同批 probe 还纠正了 `tr` 的两处写法：八进制只认三位
  （`\0176` 会解析成 `\017`+`6`），且空格属于可打印区（`tr -d '\040-\176'` 会把内嵌空格删掉
  而不是查出来）——`*[! -~]*)` 那版更是 `bash -n` 直接报语法错，而语法错让 source 中断，
  导致当轮所有"应当被拒"的 probe 空过（正向样本才暴露了它）。
- **新闸 `src/tests/deploy/backupUriFile.test.js`（17 例）**：真 `bash` + 桩 `mongodump`/
  `mongorestore`，断言的是"文件里的串真的进了 `--config` 内容"而不是脚本自报成功；
  含**前世版减法自证**（把 `mongo_hydrate_uri` 换成只认 `MONGODB_URI` 的旧实现 ⇒ 同一夹具
  必须红）、四种真实密钥文件形态（无尾换行 / 尾换行 / CRLF+空行 / PowerShell BOM）、
  以及 hydrate 之后凭据仍不出现在 argv。
- **新闸 `src/tests/deploy/runbookSecretSource.test.js`（10 例）**：把手册当成可执行契约扫——
  语料 **40 条命令行 / 31 条需要连库**，五通道：缺 `MONGODB_URI(_FILE)`、缺该脚本额外的
  `HMAC_SECRET`/`AES_SECRET_KEY`、命令行出现 `*_FILE=/run/secrets`（那是容器内路径）、
  经 `docker compose exec` 跑 ops 脚本、`--apply` 未配 `ALLOWED_SOURCE_DB`。
  自证三件：前提（条数下限 + 被调用脚本文件必须都存在）、每通道合成违例、
  **真实文件减法**（把 31 条真实命令逐一抹掉前缀喂回同一条通道，全部必须点亮）。
- **判据取舍（记下来以免下轮又被"放宽"回去）**：围栏内位置无关，所以注释形态的 crontab
  示例、`cd /opt/xf && …` 复合行都在检查范围；围栏外抓**每个**内联代码 span，所以
  「- **处置**：`node scripts/…`」这种带标签写法不是盲区（实测把语料从 36 条提到 40 条）。
  但同一条 `--apply` 命令当时**仍然**看不见：它写在跨两行的内联代码里（`\` 续行 + 未闭合的
  span），任何 span 判据都读不到——所以把它连同演练那条一起搬进 ```bash 围栏，
  这才是让它受检的动作。代价是文本判据分不出"这样写"与"不要这样写"，于是把手册里
  `docker compose exec -T app node scripts/x.js` 那条反例拆成两个 span——
  **不给判据开"这条不算"的豁免口**。
  表格行按"记录/状态"排除，覆盖域只含说明书（`deployment/*.md`、`docs/incident-response.md`、
  `README.md`、`SECURITY.md`、`migrations/README.md`），不含 CHANGELOG/`deliverables`/`docs/adr`。
- **我自己写错的两句论证（自查后改掉，没有留到现场）**：
  ① `deployment/secret-rotation.md` 曾写「缺 `MONGODB_URI` 时脚本自己会红」——
  `destructiveGuard.resolveMongoUri` 只打一行 stderr 告警就**回退本地库**，而
  `assertApplyAllowed` 在 `apply=false` 时直接放行，真实症状是"数出来的是开发库的 v1 行数"；
  ② 反证了一个听起来合理的建议：`docker compose exec -T app node scripts/…` **不是**
  宿主机缺密钥的补救路径，镜像里只有 `scripts/destructiveGuard.js`（`Dockerfile:122-124`，
  故意的：容器被攻破时拿不到带 `--apply` 的灭迹工具），那条路径只会 `Cannot find module`。
  能进容器的只有 `npm run validate`（= `node src/config/validate.js`，`src/` 在镜像里）。
- **文档同步**：`secret-rotation.md` 新增「执行位置与 `*_FILE` 前缀」一节（含逐脚本所需密钥表）、
  `backup-encryption.md` cron 行、`rollback-drill.md` 备份/校验行、`incident-response.md` 两条处置命令、
  `README.md` 备份/恢复块。`rollback-drill-record.md` **只改检查单模板那一行**，
  已完成演练的历史行原样不动——为了让闸变绿去改写演练记录等于伪造现场。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 37 套件 / 612 例全绿；
  `npx eslint` 两个新文件 0 问题；`npx prettier --check docs deployment README.md migrations src/tests/deploy`
  全绿；`node scripts/lint-ratchet.js` 仅剩并发线在改的 `src/services/securityAlert.js`
  （complexity/max-lines 各 0→1），本批新增文件未引入任何 warn。

### 运维可用性（2026-10-03 · `npm run validate` 是这条线的第三个入口，而它一直站在闸外）

> 背景：`*_FILE` 回填（P3-48）只在 require 到 `src/config` 的入口自动发生。上一轮补了六个
> 运维脚本并立了 `scriptSecretHydration.test.js` 这条闸；本轮由并发审计线（lane-hydration-audit）
> 逐条攻击那条闸的判据，查出**四个漏判形态**和**第三个同类入口**。

- **finding：`node src/config/validate.js`（= `npm run validate`）在 `*_FILE` 部署下报四条假弱密钥**。
  它不经过 `src/config/index.js:11`，没人回填，于是 `collectSecretErrors` 读到 `undefined`，
  报「JWT_SECRET / JWT_REFRESH_SECRET / AES_SECRET_KEY / HMAC_SECRET 必须设置为至少 32 字符」
  并以 1 退出。而 `deployment/secret-rotation.md:156` 正是拿这一步的退出码当
  "轮换后配置自洽"的证据——密钥轮换流程的收尾在容器里做不到。
  失效形态也和其余六个不同：它们症状是"读不到"，这条是**"密钥看起来弱"**，
  会把排查方向直接带到"是不是运维把密钥换短了"上去。
- **我自己的修法被打回了第一次（如实记录）**：第一版按位置判据把 hydrate 放在
  `validate.js` 文件顶部（这样"hydrate 早于首次读取"在源码位置上成立、可被闸钉住）。
  结果连带打红 5 个配置套件（validate / startupGuards / weakSecretPlaceholder /
  transportTlsAssertion / immutableConfigGuard）。根因不是测试写错，是**判据形状与文件形状不匹配**：
  `validate.js` 同时是库（app.js / index.js / staticFrontend.js / websocketService.js 都 require 它）
  和进程入口，而"库在 require 期覆写调用方的 `process.env`"本身就是不该有的副作用——
  `src/tests/setup.js` 给每个 worker 预置了四把 `*_FILE` 临时副本，凡"先设 env、后 require"
  的夹具都被回填悄悄改回测试密钥。`index.js` 能那么做是因为它自己就是应用入口。
  最终改法：hydrate 放进 `if (require.main === module)` 入口支，先回填再 `validateConfig()`。
  A/B 实测（只给 `*_FILE`、`NODE_ENV=production`）：A 臂（预加载删掉 `*_FILE`，复现"回填没发生"）
  四条假弱密钥 + 「MONGODB_URI 不能指向 localhost」全在；B 臂（当前代码，走真实 CLI）
  弱密钥计数 0，剩下的是我没给的 `CORS_ORIGIN` / `REDIS_URL` / `ALLOWED_HOSTS` /
  `TRUST_PROXY_HOPS`——与密钥无关。
- **finding：闸的读点判据只认一种书写形态**。审计线逐条攻击后确认四处漏判：
  ① 注释里提到 `hydrateSecretsFromFiles()` 就算证据（删掉真调用、留一句注释即绿）；
  ② 解构 `const { MONGODB_URI } = process.env`、别名 `const env = process.env; env.X`、
  动态键 `process.env[k]` 三种读法一律看不见——**看不见比判错更坏**，那等于静默豁免；
  ③ 护栏代读通道 `resolveMongoUri()` 的 require 正则不认带扩展名（`'./destructiveGuard.js'`）
  和 `require(path.join(__dirname, 'destructiveGuard'))` 两种写法，
  而 `fix-token-blacklist-index.js` 唯一的读取通道就是它——上一轮那个"静默回退本地库"的
  缺陷类别因此可以再次溜过；④ 扫描范围只有 `scripts/**`，既不含 package.json 里
  `node <file>` 形态的 npm 入口（`src/config/validate.js` 就是这么漏的），也不含根目录
  `migrate-mongo-config.js`。后者是本轮新发现：`npm run migrate:up` 是以**裸命令名**调 CLI，
  `node <file>` 匹配看不见它，而 CLI 会把同目录的 `migrate-mongo-config.js` 当模块加载——
  那个文件里既有 `resolveMongoUri()`，也有一行上一轮补的 hydrate，**但那行一直站在闸外**，
  删掉不会有任何测试变红。
- **闸改造**：判据抽成三个纯函数（`findHydrationOffender` / `findCliEntryOffender` / `topLevelReads`）
  以便被合成源码直接攻击。注释先剥（逐字符走并跟踪引号，`'mongodb://127.0.0.1/db'` 里的 `//`
  不能当注释起点）；动态键按"可能是读取"计（多算无害，少算是静默漏判）；护栏 require 放宽到
  「`require(` 之后、右括号之前出现 destructiveGuard」。扫描范围三处并集，每处各由一条前提自证钉住。
  新增三条豁免都带**可执行**证据而不是一句注释：豁免一（自带临时值的探针）逐个名字找到赋值处、
  豁免二（共享库 `destructiveGuard.js`）用"确实被 ≥4 个入口 require"自证、
  豁免三（库兼入口）的前提是该文件**没有任何模块顶层读取**（用括号深度算，`depthAt`）——
  前提一破用例即红，逼着改法回到正题。压测/演练三个入口今天不读文件型密钥，
  因此**不许预先占豁免位**（`expect(CLI_ENTRY_BLOCKS).not.toContain(f)` 那类反向钉）。
  减法自证两处：把六个脚本各自的 hydrate 擦掉 ⇒ 闸逐个点名（`verdict` 必须含 hydrate，
  并断言 `stripped !== a.code` 防止"减法没真的动"）；`migrate-mongo-config.js` 同做一遍。
- **工具层陷阱（影响结论可信度，单独记）**：本会话的 Bash 里 `env VAR=x node …` 这种前缀
  **静默不执行**（rc=0、无任何输出），于是第一版 A/B 探针两臂都数到 0 条错误，
  看起来像"缺陷不存在"。同一份 env 用 bash 原生 `VAR=x node …` 前缀跑，才拿到 4 vs 0。
  与上一轮 `'j'.repeat(48)` 夹具被 `isWeakSecret` 判弱那次同一性质：**探针自己坏掉时，
  它给出的"否证"和"证伪"长得一模一样**，所以每条 A/B 都要先证明两臂至少各产出过非零信号。
- 验证：`npx jest src/tests/config src/tests/deploy` ⇒ 35 套件 / 585 条全绿；
  `scriptSecretHydration.test.js` 单跑 15/15；`prettier --check`、`eslint` 对改动的两个文件 0 问题；
  `node scripts/lint-ratchet.js` 对我改的两个文件无回退（现存回退在 `src/services/securityAlert.js`，
  属并发会话在改的文件，未动）。本轮没改 `docker-compose.yml`、`scripts/*.js` 与任何文档。

### 部署（2026-10-03 · SSH 部署路径上 digest 钉死闸一直是静默关闭的 + compose 密钥闸的清单只有 5/15）

> 背景：本轮由「`*_FILE` 密钥回填」那条线连带查出。三条 finding 都属于同一类形状——
> **配了但没送达**、**清单抄短了**、**断言扫空了**——共同点是工作流和 jest 全都绿。

- **finding：`DEPLOY_REQUIRE_DIGEST_PIN` 在 SSH 路径上从未到达 `deploy.js`**。
  `deploy-ssh` 的 `env:` 块里写着 `DEPLOY_REQUIRE_DIGEST_PIN: 'true'`，注释还注明
  「与 self-hosted 同口径」——但两条路径的送达形态根本不同：`deploy-self-hosted` 在
  部署机 runner 上直接 `node scripts/deploy.js`，step env 就是进程 env；`deploy-ssh` 的
  `node` 跑在**目标机**上，而 ssh 既不转发本地环境变量，`SendEnv` 又只在目标机 sshd
  显式 `AcceptEnv` 该变量名时才生效（默认只放行 `LANG/LC_*`）。于是那道"拒绝非 digest
  引用"的兜底闸在 SSH 路径上始终不存在。
  讽刺的是判据早就写过这条口径：本文件 `compose 里每个 :? 变量都由两条部署路径下发`
  那条用例的注释就是「env 里有但没 SendEnv = 目标机收不到」——只是没把同一口径用到
  兜底闸上，而 ⑤ 的断言形状（`expect(ssh).toMatch(/DEPLOY_REQUIRE_DIGEST_PIN: 'true'/)`）
  恰好只查"配了"，替这个洞做了一套完整的掩护。
  如实定级：**这是纵深防御缺一段，不是可利用漏洞**——`IMAGE_TAG` 本身由 preflight 解析
  并过 `sha256:[0-9a-f]{64}` 校验，实际 pull 的就是 digest 引用；闸要防的是"误配/绕过
  preflight 直接把 tag 传进来"，而那条路径上它形同不存在。
- 修法：把它拼进远程命令，并用 `${var:?}` 而不是 `$var`——漏配时报错退出，
  而不是展开成空串让 `deploy.js` 把闸读成"关"（那正是本 finding 的原始形态）。
  不走 `SendEnv`：那要求目标机 sshd 配合，且会撞红上面那条"SendEnv 恰好等于 compose
  硬声明项"的用例。bash 实测两向：置 `true` 时远程命令串为
  `… DEPLOY_REQUIRE_DIGEST_PIN='true' node scripts/deploy.js --dry-run`；
  漏配时 `bash` 立刻退 1 并打印「deploy-ssh 未下发 digest 钉死闸」。
- **闸改造**：`run: |` 扫描器从 describe 内的闭包抽成模块作用域纯函数
  （`collectRunLines(text)` / `deployInvokeLines(text)` / `digestPinDelivered(text)`），
  `allRunLines` 改为委托——同一个 job 可能有多个 step，"取第一个 run"会取到
  Prepare SSH 而不是部署命令（本仓 helper 的注释里就写着这条，但 ⑤ 没用它）。
  抽成纯函数是为了**反向自证**：把修复前的命令串喂进 `digestPinDelivered` 必须判 false。
  变异实测：只删远程命令串里那段（env 块保持"配了"）⇒ ⑤ 当场红在第 248 行
  `expect(digestPinDelivered(ssh)).toBe(true)`（Expected true / Received false），
  其余 16 条不动——正是原洞的签名：所有旧断言都不看送达。
- **finding：compose 密钥闸的名字清单是抄的，5 个 vs `FILE_BACKED_SECRETS` 的 15 个**。
  `docker-compose 不再用 environment 传任何密钥` 把 JWT/REFRESH/AES/HMAC/MONGODB_URI
  五个名字写死在断言里；其余 10 个（`DOCS_PASSWORD` / `LOG_SHIPPING_TOKEN` /
  `METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` / `SENTRY_DSN` /
  `LOGIN_ECDH_PRIVATE_KEY` / `REDIS_URL` …）哪天被写成 `- X=${X}` 明文注入，闸一声不响。
  改为清单从 `src/config/secrets.js` 反向推导（新增文件型密钥不必回来改用例，
  与 compose `:?` 清单闸同套路）。
  实测现状：7/15 走 `_FILE`（含 `REDIS_PASSWORD`），`REDIS_URL=redis://redis:6379` 明文，
  其余 7 个今天压根不在 app 的 environment 里 ⇒ 新判据对它们是"不许以明文出现"，
  不需要动 compose。**唯一豁免 `REDIS_URL` 不写在注释里，条件就地可执行**：
  URL 里一旦出现 `//…@`（口令 userinfo）立刻判红——redis 只挂在
  `data-net: internal: true` 上、口令走 `REDIS_PASSWORD_FILE`，这条豁免成立当且仅当
  它不含凭据。反向自证用合成源（真实 compose 是并发会话共享的文件，不临时改它）：
  把 `HMAC_SECRET_FILE` 换回明文 ⇒ 抓到；换成第 6+ 个名字 `DOCS_PASSWORD` 再试一次
  （这条才真正证明"扩清单"这件事本身有效）；给 REDIS_URL 塞口令 ⇒ 豁免失效；
  喂一份认不出 app 服务的文本 ⇒ 全部名字按违规上报（判据失效不许静默放行）。
- **新增：`/run/secrets/<名>` 三处一致性闸**（environment 的 `_FILE` 引用、服务级
  `secrets:` 列表、顶层 `secrets:` 段）。漏声明的后果不是"没密钥"而是"启动即崩"——
  `hydrateSecretsFromFiles` 对不可读的 `_FILE` 直接抛错，运维看到的是一条与密钥无关的
  启动失败。顺带钉住顶层每个 `file:` 必须落在 `./secrets/`（`.gitignore` 与
  `.dockerignore` 只排除这一个目录，指到别处等于把密钥放回版本库与构建上下文）。
  合成夹具 `CLEAN` / `ORPHAN` 各证一侧：`b_secret` 顶层声明了却没挂到 app ⇒
  `missingFromService` 抓到、`missingFromTopLevel` 必须为空（判据认的是"两处一致性"，
  不是一刀切盯 environment）。
- **自查出一条假绿（自己写自己抓）**：本条第一版的顶层扫描用了
  `/^ {2}[a-z0-9_]+:\n {4}file: (\S+)$/gm`——本仓库文件是 CRLF，`:` 与 `\n` 之间夹着
  `\r`，这条正则**恒不匹配**，那个 `for` 循环体一次都没执行，而用例是绿的。
  这正是本仓踩过两次、写在 `deployWorkflow.test.js` 注释里的坑（"不用 $ 锚点：
  本仓库工作流是 CRLF，`\r` 会让行尾锚定的正则恒不匹配（实测过）"），我照样踩了。
  现在所有 compose 扫描统一先 `split(/\r?\n/)` 再逐行匹配，并把这类"取到多少条"
  写进前提自证（`referenced.length >= 7`、`targets.length >= referenced.length`、
  每个 `file:` 必须是字符串）。
- 核过撤销的怀疑：`ADMIN_INITIAL_PASSWORD_FILE` 曾被记为"compose 接了但应用不读"的
  疑似死接线——`src/services/initData.js:770,833` 确实在读它（初始管理员口令），
  嫌疑撤销。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 35 套件 / 578 条全绿；
  `prettier --check` 与 `eslint` 对改动的三个文件均 0 问题。
  本轮未改 `docker-compose.yml` 与 `scripts/deployPolicy.js`（判据变了，配置没变）。

### 运维可用性（2026-10-03 · `*_FILE` 密钥部署下六个独立脚本拿不到连接串）

> 背景：`src/config/secrets.js` 的 `<NAME>_FILE` 约定（P3-48：密钥走文件挂载，不进
> `docker inspect` / `compose config` / 子进程继承）只在**require 到 `src/config` 的入口**
> 自动回填 process.env。运维手边的独立脚本几乎都是 `require('dotenv').config()` +
> 直读 `process.env.MONGODB_URI`，这两者从来没接上。
>
> **本轮推翻了自己的第一版判据**：先用静态依赖图筛"哪些脚本需要补 hydrate"，
> `verify-audit-chain.js` 的图确实通向 `src/config`（auditChainVerify → utils/auditChain →
> 函数体内 `require('../config')`），按图它不需要改。改成动态探测（只给 `MONGODB_URI_FILE`、
> 显式把 `MONGODB_URI` 置空、目标端口 1）后结论相反——那是**懒 require**，脚本在 `main()`
> 里读 env 时它还没执行。静态图在这里会给出假绿。

- 实测（修前）：`verify-audit-chain` / `revoke-user-sessions` / `run-rollback-drill` /
  `sync-audit-indexes` / `perf/explain-spotcheck` 读到空串，开局报错退出；
  `fix-token-blacklist-index` 更隐蔽——`resolveMongoUri` **静默回退本地默认库**并打印
  「已连接：127.0.0.1:27017/fire_safety_db」，运维以为在清生产索引。
  同族 `resign-audit-hmac.js` / `resign-audit-chain-v3.js` 因为显式调了 hydrate 一直正常，
  它们同时充当探测方法学的正向对照（对照组判"已 hydrate"，说明判据不是在猜）。
- 后果直接落在文档化的运维步骤上：`deployment/secret-rotation.md` 的 HMAC 轮换第 0/4/5 步
  都要求 `node scripts/verify-audit-chain.js` 且注明"要求退出码 0"，
  在 `*_FILE` 部署里这一步**做不到**——第 5 步会退 1，轮换完成后无人给出链条干净的证据。
- 六个脚本各自补 `require('../src/config/secrets').hydrateSecretsFromFiles();`
  （紧跟 `dotenv`，早于任何 env 读取），与本仓既有同族写法一致。
  不用"把 hydrate 塞进 `destructiveGuard.js`"这种集中式改法：它是被 require 的库，
  无权决定进程何时回填，而且 `verify-audit-chain` / `explain-spotcheck` 根本不经它。
- 新闸 `src/tests/config/scriptSecretHydration.test.js`（8 条，逐条能被打红）：
  读取文件型密钥的入口必须**自己**显式 hydrate，且早于首次读取。
  读点有两条通道，只钉第一条会漏——`fix-token-blacklist-index` 唯一的读取通道是
  `require('./destructiveGuard')` 代读，所以把护栏引入点也按读点计（否则删掉它的
  hydrate 行，闸照样绿）。
  判据自证：合成源码攻击（缺 hydrate / hydrate 太晚 / 只赋值不读 / `===` 比较 /
  `JWT_SECRET_V2` 前缀同名）各一条；豁免两条各自带证据——
  `audit-probes/ws-session-bypass.cjs` 必须能为每个读到的名字指出赋值处，
  `destructiveGuard.js` 必须真的被 ≥4 个入口 require；
  压测/演练入口（e2e-smoke / load-test / production-drill）今天只写不读，
  因此**不许预先占豁免位**，哪天它们开始读 env 就会撞红再登记。
  变异实测（用真实文件，不是合成源码）：删掉 `fix-token-blacklist-index.js` 的 hydrate 行
  ⇒ 闸当场报出该文件（「读取文件型密钥 MONGODB_URI，但整个文件没有调用
  hydrateSecretsFromFiles()」），恢复后 8/8 绿——这条正是"只钉直读通道"时会静默漏掉的那个脚本。
- 核过不动的：`scripts/*.sh`（backup/restore）按文档就是 `MONGODB_URI='<连接串>' ./scripts/...`
  显式传值（secret-rotation.md:277），不经 Node 的 env 回填路径。
- 实测（修后）：同一探针下六个脚本全部改为"拿文件值去连"（端口 1 上超时被杀，
  即它们真的读到了 `*_FILE` 里的连接串）。
  另用真实内存 MongoDB 端到端跑 `verify-audit-chain.js`：只给 `MONGODB_URI_FILE`
  （文件内容**故意带尾部换行**）时它连上了库并打印
  「VERDICT: INCOMPLETE — 审计集合为空（0 条）：无记录可验」——这条判定只有连接成功才可能给出，
  空集合是夹具本身没种记录；两者都不给时退 1「未提供 MONGODB_URI」，
  作为反向对照证明前一条不是默认值蒙出来的。

### 修复（2026-10-03 · 上一轮 PII 收窄的两处回归：揭示迟到写入 + 审计副本仍存明文号码）

> 背景：四路并行逐行审计复核 2026-10-02 的两批改动，各命中一条**由那批改动自己引出**的缺陷。
> 两条都已回源核实并做变异实测，不是推测。

- **lane-B #1｜`web-admin/src/views/UserView.vue` 的 `doReveal` 迟到写入守卫**。
  原实现 `await` 之后无条件 `dialog.form.phone = full; dialog.phoneBaseline = full`，
  既不校验目标行也不校验弹层是否还开着。可达路径：点「查看完整号码」后请求飞行期间
  ESC 掉 step-up、关掉编辑框、再点另一行的「编辑」⇒ **A 的明文连同基线一起落进 B 的表单**，
  而界面上的提示恰好是「清空并提交即删除」⇒ 管理员照着删空再保存，
  抹掉的是 **B 的真实号码**。修法是发请求前把 `reveal.userId` 快照成 `targetUserId`
  （step-up 一关 `resetReveal` 就会把它清空，事后读不到），响应回来只在
  `dialog.form._id === targetUserId` 时写入。只比 `_id` 不叠加 `dialog.visible`/`isEdit`：
  关框必走 `resetForm`（`_id` 归 null）、新增框同样是 null，多余的两个条件恒真且**写不出
  能覆盖它们的用例**，留着就是无人验证的死分支。
  门禁：`web-admin/src/tests/views/userView.test.js` 新增两条（切到另一行 / 切到新增框），
  夹具用**手工 defer 的 Promise**——`mockResolvedValue` 在下一个微任务就落地，
  任何迟到守卫都来不及被触发，用例会退化成恒真。
  变异实测：把守卫改成 `if (false && …)` ⇒ 两条同时转红（`expected '13900000000' to be ''`），
  恢复后 61/61 绿。
- **lane-A #2｜`src/utils/helpers.js` 的 `SENSITIVE_KEY_SUBSTRINGS` 补 `phone`**。
  名单原本只管"凭据"，于是 `PUT /api/users/:id`、`POST /api/alarms/report` 这些**写路径**
  把手机号明文留在了 `AuditLog.body` 里，而 `services/securityAlert.getRecentAlerts`
  的投影含 `body` ⇒ `GET /api/security/alerts` 把它再下发一次；`auditBuffer` 的明文 WAL
  同样带着它。结果：持 `security:audit` 的账号无需口令、无需 `system:read`、
  不写一条 `view_sensitive_data`，就能读到任意用户与任意报警上报人的完整号码——
  上一轮"读接口停发明文"只堵了响应侧，**审计侧是同一条合规通道的另一半旁路**，
  而当时新增的 egress 门禁全绿（它只盯响应体），这正是那条门禁的盲区。
  改的是单一事实来源：`auditLogSanitizer` 与 `middleware/security.js` 的两条脱敏流水线、
  以及 morgan 的 URL 打码（`isCredentialQueryKey` 取并集）同时生效，
  扁平 `phone` / 嵌套 `reporter.phone` / camelCase `workPhone` / 敏感键装数组四种形态一起收，
  `?phone=` 在访问日志里同步打码。既有用例 `auditLogSanitizer.test.js`「真实中间件驱动」
  按名单逐键构造请求体，因此**免费**获得了对 `phone` 的端到端覆盖。
  不误伤边界保持原样：`postcode` / `zipcode` 不含 `phone` 子串，值仍可读。
  门禁：`src/tests/models/auditLogSanitizer.test.js` 新增一组 5 条（形态覆盖 + 键名噪声 +
  不误伤 + query/URL 同口径），`src/tests/security/userPhoneMaskedEgress.test.js` 新增一条
  **真实路由**用例（发一次带明文的 PUT → `auditBuffer.flush()` → 读回审计行，
  断 `body.phone === '***'`、序列化不含明文，并用 `body.realName` 证明不是"整块抹掉"）。
  变异实测：从名单里删掉 `phone` ⇒ 4 条同时转红（含真实路由那条），恢复后 12/12 + 11/11 绿。
- **如实声明的残留**：脱敏判定只看**键名**，不做值形态扫描。因此装在非敏感键下的号码
  （`{contacts:['139…']}`、备注文本里的号码）仍会进审计副本——这是刻意止步，
  不是漏网：按 11 位正则扫值会连带抹掉报警描述/备注里的号码，取证价值损失大于收益。
  该边界已写成一条可执行用例（「如实声明边界」），要跨过它需要单独拍板。
  `AuditLog` 里的**历史**明文行不会因本改动消失，清理属数据迁移议题，另行决策。
- 消费方核实：全仓非测试代码只有 `securityAlert.js:84` 按 `body.ipAttempts` 取数，
  没有任何逻辑依赖审计 body 里的手机号可读；现有测试无一断言审计副本含明文号码。
- 文档同批（lane-C #8 的实证条目）：`controllers/securityController.js` 里三处注释错位——
  「举报异常行为 POST /security/report」的标题悬在空处、举报核验的整段 JSDoc（含 `@returns`）
  挂在 `REPORT_TARGET_KINDS` 这张**对象表**头上、还有一段描述 `buildAuditLogQuery` 的 JSDoc
  紧跟在 `getRegistrationConfig` 的文档之前（该函数早已搬到 `utils/auditQuery.js` 的
  `buildAuditQuery`，全仓不存在同名符号）。按"注释只描述它紧邻的代码"重挂，
  并删掉那段失效的构建器文档。改动纯注释：逐行比对确认代码行零差异（只少一个空行）。

### 修复（2026-10-02 · 管理员用户读接口停发明文手机号，改走「脱敏下发 + step-up 揭示」）

> 背景：上一轮把 `reporter.phone` 从报警读出路径摘掉后，同一列在**用户管理**上更严重：
> `models/User.js` 的 `phone` 有 getter 透明解密，且 schema 的 `toJSON/toObject` 只设了
> `getters:true` 没有 `transform` ⇒ 任何**不带投影**的读取都会把明文号码整体发出去。
> 原 `User.RESPONSE_EXCLUDE` 排了 password/phoneKey 等 9 项却**没排 phone**，
> 于是列表 / 详情 / 建号回显 / 改号回显 / 角色回显**五条路径**全部明文下发。
> 后果不只是"看得到"：明文一旦进列表，`POST /api/security/view-sensitive`
> 那条专为手机号建的合规通道（step-up 二次验证 + `view_sensitive_data` 审计 +
> 审计写失败即不返回明文）就被彻底架空——想查号码的人不需要口令，翻页就行。
> 拍板口径：**表格默认脱敏 + 按需 step-up**（用户明确选择服务端一起收窄，不是前端打码）。

- `models/User.js`：`RESPONSE_EXCLUDE` 改为由字段数组拼出，新增 `-phone` 进默认排除；
  派生出 `RESPONSE_EXCLUDE_PHONE_VISIBLE`（同一份数组**滤掉** `-phone`）。
  用数组而不是对字符串做 `replace(' -phone','')`：字符串手术在字段顺序变动时会**静默失配**，
  失配后的表现恰好是"明文照发、门禁照绿"。变体名字本身就写着危险，注释规定它只能与
  `toMaskedAdminUser` 配对使用。
- `services/userService.js`：新增读模型 `toMaskedAdminUser(doc)` —— `phoneMasked =
DataMasking.maskPhone(obj.phone)` 后 **`delete obj.phone`**。四个管理员读函数
  （`listUsers` / `getUserDetail` / `getCreatedUser` / `getUpdatedUser`）改用
  `RESPONSE_EXCLUDE_PHONE_VISIBLE` 并统一过这个函数：投影留着 phone 是为了让**解密 getter
  在服务端跑一次**，脱敏只在服务端这一处做——`maskPhone` **不幂等**（对 `138****5678`
  再打一次得到 `****`），所以前端一律不再打码，只做展示。
- **响应字段改名成 `phoneMasked` 而不是 `phone: 脱敏值`**（有意偏离 `my-info` 的既有口径）：
  编辑对话框会把行对象灌进表单，而 `userController.js` 用 `if (phone !== undefined)` 落库、
  路由校验是 `/^1[3-9]\d{9}$/` ⇒ 叫 `phone` 的展示值只有两种结局，且**都是坏的**：
  原样回传被 400 拒掉，或被当成"用户想清空号码"抹掉真值。改名让"这是展示值、不是可写字段"
  在类型上就不可能被搞混。
- `web-admin/src/views/UserView.vue`：列表列读 `phoneMasked`；编辑对话框**不再回填**手机号，
  改为输入框旁一个「查看完整号码」→ 二级 step-up 弹层（只收当前登录口令）→
  `POST /api/security/view-sensitive` 返回的 `full` 才进输入框。提交按**脏字段**发键：
  未揭示 / 揭示后未改 ⇒ 不发 `phone`；揭示后删空 ⇒ 发 `''`（这才是真的清空）。
  提示语随 `phoneBaseline` 切换，两处状态各自说清"留空即不修改"和"已载入现值"。
  step-up 的口令由 el-dialog `@closed` 单一清理点负责（打开时再清一次是冗余，
  冗余那处会让清理逻辑被改坏时测试照样绿）。
- **有意的边界，不一起收窄**：自助通道 `GET /api/auth/me` 与 `PUT /api/auth/profile`
  仍返回本人明文号码——那是用户自己的数据、且编辑页需要现值；`utils/permissionHelper.js`
  处早已写明"回填脱敏值会污染数据或阻断保存"。这条边界用一条**反向**用例钉住
  （`/auth/me` 必须还能拿到明文），免得下一个人"顺手统一"。
- 消费方核实：web-admin 里 `users.getList` 的 phone 只有 UserView 一处读，ProfileView 读的是
  `/auth/me`，RegisterView 是自己的表单 ⇒ 停发零界面功能损失。搜索侧无残留 oracle：
  列表 `search` 的 `$or` 只覆盖 username/email/realName，`phoneKey` 全仓**无** `find({phoneKey})`
  （`models/User.js:270-277` 已记为"已供未接"）。
- 文档同批：`openapi.json` 建号请求体的 `phone` 补 description「仅接受写入；
  列表/详情/建号/改号/角色回显返回 phoneMasked，不含该字段」（`src/docs/generate.js` 重生成）。
- **门禁**：新套件 `src/tests/security/userPhoneMaskedEgress.test.js`（10 例）——
  夹具自证（不带投影的裸读确实能拿到明文，证明排除不是空转）/ 两条投影只相差 `-phone` /
  五条响应路径逐个断言 `'phone' in payload === false` **且** `JSON.stringify` 不含明文
  **且** `phoneMasked` 值正确（只断言"没有"会让整列被删也测成通过）/ 边界自证
  （省略键 ≠ 清空；把 `139****1122` 提交上去必须 400 **且库里原值未变**）/
  view-sensitive 揭示与 `/auth/me` 两条反向钉 / 源码文本闸：`RESPONSE_EXCLUDE_PHONE_VISIBLE`
  出现处必须紧邻 `toMaskedAdminUser`（防"换投影忘了脱敏"），并钉住 `delete obj.phone;`。
  变异实测三臂：摘投影 → 5 红；摘 `delete obj.phone` → 2 红；把变体名改回基名（模拟漏接）→ 1 红。
- 前端门禁：`userView.test.js` 新增 9 例（脱敏列渲染 / 新增框无揭示入口 / 空口令不发请求 /
  揭示请求形状 / 揭示后不改不发键 / 揭示后删空发 `''` / 揭示失败不污染也不误发 /
  口令不跨次残留 / 关外层时二级弹层一并收起）。step-up 是嵌套对话框，`append-to-body` 后
  节点挂在 body 上，"是否关闭"只能断言 overlay 的 `display` 终态——EP 关闭后 DOM 仍在，
  断言节点消失会得到一条恒真的假绿。变异实测三臂：提交无条件带 `phone` → 3 红；
  列改回 `row.phone` → 1 红；摘掉 `@closed` 清理 / 摘掉外层关闭 → 各自对应那条红。
- **如实声明残留**：库里仍是可解密的密文（本改动只收窄**下发面**）；操作者**本人**的明文手机号
  仍会写进 `localStorage.currentUser`（`/auth/me` 的形状），是否连浏览器持久化一起收窄
  需要单独拍板——它会改变刷新后 ProfileView 的短暂空值表现，且 email/realName 同批同性质。

### 修复（2026-10-02 · 报警读出路径停发 `reporter.phone`）

> 背景：四路逐行审计的 lane-B 报出一条新缺陷并回源核实。`FireAlarm.reporter.phone`
> 是**明文存的第三方手机号**，不属于 `models/User.js` 那套「getter 解密 +
> `POST /api/security/view-sensitive` step-up + `view_sensitive_data` 审计」通道；
> 而报警的读出路径原本一条根文档投影都没有 ⇒ 任何持 `alarm:read` 且落在该条范围内的
> 账号都能**整页批量**读到它，无二次验证、无 `system:read`、无留痕——把仓里专为
> 手机号建的合规通道架空。同一 model 上的 `handler.phone` 正因同样理由被收窄过
> （`alarmDetailHandlerPii.test.js`），这条是同一列的邻接漏点。
> 拍板口径：**读出全部停发**（对齐 handler.phone 先例），不做静态加密改造。

- `services/AlarmService.js`：新增模块级 `ALARM_READ_SELECT = '-reporter.phone'`，
  **八处**调用点全部引用同一个常量——游标列表 / offset 列表 / 详情用 `.select()`，
  五个处置接口（dispatch/arrive/resolve/false-alarm/cancel）用 `options.projection`。
  后者是这次真正容易被漏掉的部分：它们把 `findOneAndUpdate` 的 `updated` 文档原样回给
  客户端，只修列表与详情等于同一列从这五个口整块漏出去，而 CI 仍全绿（那五个响应体
  本来没有用例读过）。
- **有意的例外**：`POST /api/alarms/report` 回显 create 出来的文档，其中含提交者自己
  刚写进去的号码——不构成新的读取，故不改（已把这条写进常量的 JSDoc，免得被当成漏点
  重新发现或"顺手补上"）。
- **如实声明残留缺口**：值仍明文存在库里；备份转储与密钥轮换的保护缺口**不随本改动关闭**。
  将来若要开放"回拨上报人"，正确做法是给它一条与 User PII 同级的揭示通道，
  而不是把这一列加回读接口。
- 消费方核实：web-admin 全文 0 处读 `reporter.phone`/`reporterPhone`，报表导出只取
  `reporter.name`（`reportExportService.js:266`），e2e 0 处 ⇒ 停发零界面功能损失。
- 文档同批：`models/FireAlarm.js` 的 `reporter.phone` 注释写明"明文存储 + 读接口不回传"，
  `openapi.json` 的请求体字段补 description「仅接受写入，列表/详情/处置响应均不返回」。
- **门禁**：新套件 `src/tests/services/alarmReporterPhoneEgress.test.js`（7 例：
  夹具自证裸查询能拿到明文 / 详情 / offset 列表 / 游标列表 / 五个处置回显 / 状态机前提自证 /
  源码文本闸）。每条排除断言都带反向证据（`reporter.name` 必须还在），防止"整个子文档被
  删了"或"populate 没生效"伪装成通过。源码闸的窗口取「到下一个调用点为止」而不是固定字数
  ——`resolveAlarm` 的 `$push` 文案块就比 420 字符长，固定窗口会对正确的代码报红。
  变异实测两臂：摘掉详情的 `.select` → 行为与源码闸 2 红；只摘 `cancelAlarm` 一处的
  `projection` → 处置回显 + 状态机自证 + 源码闸 3 红（证明"只修一条"确实会被抓住）。

### 测试（2026-10-01 · 两处 HEAD 上就存在的红灯）

> 全量 `npx jest --ci` + `npm run format:check` 复跑时发现：不需要本轮任何改动，main 上已经有
> 三条用例与一条格式闸是红的。CI 跑这两条（`ci.yml` 的 jest 与 `:79` 的 format:check）⇒ 合并队列
> 上任何后续提交都会被这两处**别人的**失败误判成"本提交引入的回归"，所以先修它们。

- **`websocketRedisAdapter.test.js` 落后于 Redis 认证改造（2 例红）**：`2816d68` 给订阅端补了
  `password: sharedCache.redisConnectionPassword()`（`websocketService.js:260`），但该套件的
  `jest.mock('../../services/sharedCache')` 工厂只造了 `isRedisEnabled`/`getRedisClient` 两个键。
  失败形态很有教育意义：第一条是 `toHaveBeenCalledWith` 的对象不匹配，第二条**不是**它声称要测的
  "挂载失败降级"，而是桩自身缺键抛出的 `sharedCache.redisConnectionPassword is not a function`
  被 `catch` 吞掉后进了同一条 warn 分支——断言只匹配 `stringContaining`，于是"桩坏了"伪装成
  "降级路径测过了"。收口：桩补该函数并返回哨兵值，断言要求哨兵出现在 `new Redis` 的 options 里
  （`toHaveBeenCalledWith` 是全等对象匹配，多键/少键/漏传都红 ⇒ 这条现在是"口令必须外发到
  订阅端"的真闸，而不是只让套件变绿）。
- **`piiEncryption.test.js` 格式（1 条格式闸红）**：`4402562` 移除未使用导入时留下了未过 prettier 的
  解构折行。本轮只做格式化（1 增 6 删，零行为变化）。

### 修复（2026-10-01 · `POST /api/security/report` 的目标核验与账号配额）

> 背景：该端点刻意不挂权限码（人人可举报是产品设计），但路由注释自称「本人资源…无越权面」
> 是**假的**——上报内容由调用者撰写，`targetId` 指向的却是别人的记录。修复前任何登录用户
> 都能提交任意 `targetId`（不校验存在性、不校验范围、无独立配额），服务端原样写进一条
> `riskLevel:'high'` 的审计行，而安全概览的「高风险操作数」与告警取数都读这批行。

- **路由层**：`targetId` 的形态由 `targetType` 决定——记录型（user/device/alarm）必须是非空
  字符串且为 ObjectId；`system` 型**禁止携带**（否则把类型改成 system 就绕过整条核验）。
  `.exists({ values:'falsy' })` 承担的是文案而不是拒绝：删掉它后面的 `isString` 会给同一个
  400 和同一个 path，变异实测确认「只看状态码+path」的用例是绿的但不设防，故用例断言 msg。
- **控制器**：记录型目标必须**真实存在**（否则 404，`USER_NOT_FOUND` 在注册表里是 401 的
  登录语义，此处显式改 404）且**落在举报人的数据范围内**（否则 403）。范围判定复用
  `rbac.assertRecordInScope` + `DATA_SCOPE_FIELDS` 单一声明，与各自详情/写路径同判据；
  404/403 的先后与 `deviceController.js:122/124`、`alarmController.js:156/158` 的既有口径
  一致（存在性预言机在每条授权读路径上本来就存在，本处不新引入一类泄露）。
  自由文本 `reason`/`description` 不受影响：被约束的是"结构化字段必须是真记录"。
- **限流**：新增账号维度桶 `securityReportUserLimiter`（20 次/15 分钟，键 `report-user:<userId>`，
  不含 IP 成分）。与凭据型姊妹桶同一口径：**并列**而不是把 IP 从组合键里删掉；同样
  **不接** `noteRateLimitHit`（账号桶没有可封的 IP）。阈值刻意不导出：测试里钉死 20 并同时
  校验服务端声明的 `RateLimit-Limit`，改配额会让用例变红而不是自动适配。
- **分层**：数据访问经 services 的 `findScopeFieldsByIds`（`AlarmService` 补该 getter，
  投影 `reporter.userId handler location.building`），控制器不新增直连 model——
  初版直连 FireDevice/FireAlarm 被 `architecture/layeringRatchet` 判红（5→7）后改的。
  连带：`skipGlobalAuditWriteFailure.test.js` 的 `models/User` 桩只提供了 `findById`，
  而 `userService.findScopeFieldsByIds` 的形状是 `find().select().lean()` ⇒ 桩补该链路并返回
  与夹具 `targetId` 同 `_id` 的记录，否则该套件两条举报用例先撞 `TypeError`，
  走不到它要测的审计写入点（全量跑实测到）。
- **门禁**：新套件 `src/tests/security/reportTargetScopeAndLimiter.test.js`（23 例：存在性、
  三条范围臂的放行与拒绝、绕口封堵、配额与 XFF 轮换、trust proxy 前提自证、
  投影完备性静态闸）+ 改写 `reportTargetIdBoundary.test.js`（形状边界，7 例）。
  变异实测 5 臂：中和范围臂→B 组 4 红；摘掉限流→D 组 2 红；删 `.exists`→msg 断言红；
  删 system 反例→绕口封堵红；删存在性→A 组与边界 404 判据 3 红；删投影一列→B/E 同时红。
- 文档同批收窄：`models/AuditLog.js` 的 `targetId` 契约注释、`PERMISSION-EXEMPT` 理由改写为
  如实版本、`src/docs/openapi.json` 重生成（targetId 加 ObjectId pattern + 403/404 响应）。

### 修复（2026-10-01 · 13 项报告回源复核后的三处落地）

> 背景：对一份 13 条的审计报告**逐条回源复核**，其中 8 条已在 19:21~20:50 的提交里闭环、
> 1 条（封禁目标可伪造）在他方在途、4 条未动。本轮落地的是**报告里没有的三处**——
> 两条由复核过程新发现，一条属报告第 13 条所在的低优先段。

- **N1 HMAC_SECRET 消费点清单收敛为单一来源**。复核发现同一份仓库里存在**三份互不相同**的清单：
  `deployment/secret-rotation.md` 写「**两个**消费点」（审计链 + 口令历史），
  `deliverables/AGENT工作总账与待办` 的 F-26 写「三个」（审计链 + MFA 恢复码 pepper + 数据签名密钥，
  **漏了口令历史**），而真实源码是**四个**（`src/utils/auditChain.js` / `src/utils/passwordHistory.js` /
  `src/services/mfaService.js` / `src/utils/encryption.js`）。手册全文 `恢复码` **0 命中**——
  而恢复码是用户丢掉认证器时的唯一逃生门，换钥后静默失效，故障只在"某个人手机丢了"那天暴露。
  收口：① 手册改成四消费点表（含"只有第 1 个有迁移工具"的非对称事实）；
  ② 新增门禁 `src/tests/config/hmacSecretConsumersSingleSource.test.js`——扫描 `src/`（排除
  `src/tests` 与 `src/config` 装载面）里**取值访问** `HMAC_SECRET` 的文件，要求集合恰好等于登记清单，
  并要求手册逐个点名。判据取「取值访问」而非「提到 HMAC_SECRET」：注释/报错文案/校验器里都会出现
  大写 `HMAC_SECRET`，算进来会让清单被噪声撑大、反而失去意义（`services/auditChainVerify.js` 的
  `computeHmac` 是从 `utils/auditChain.js` 导入的，密钥取值不在它那里，故不重复计）
  - 门禁：新套件 9 例（含"扫描基线非空"防"零命中被当成通过"、"手册必须点名恢复码"作回归哨兵）
- **N2 PII v1 存量行的静默缺口补启动期告警**。10-01 把写侧切到 v2（AAD 行绑定）时读侧刻意保留 v1 兼容，
  代价是 **v1 密文与行身份无关**——`utils/piiCrypto.js` 的 v1 分支 `aad` 保持 `null`、`if (aad)` 永不
  `setAAD`，于是把 A 行的 `enc.v1.…` 复制到 B 行，B 行的 getter（`models/User.js:105-106` 虽已传
  `{subjectId, field:'phone'}`）会**正常解出 A 的明文**。写侧不再产 v1，但**存量行不会被自动升级**，
  而升级唯一入口是手工跑迁移脚本，**没有任何启动期信号**（`src/config` 下只有 `pii_rotation_old_key_lingering`
  那条旧钥告警，与"v1 未迁移"无关）。收口：`config/immutableConfigGuard.js` 增加第三项
  `pii_v1_rows_unmigrated`（生产 + PII 主密钥可用 ⇒ 告警 + `incSecurityAlert`，**不阻断启动**，
  口径同 immutable 档位），并写进轮换手册收尾清单
  - **如实声明边界**：该告警的判据是"代码仍支持读 v1"，**不是"库里还有 v1 行"**——启动路径
    （`config/validate.js`）在 mongoose 连接**之前**执行，不连库，故它**不会自行消失**。要判"迁完了没"
    只有一条路：`node scripts/migrate-pii-encryption.js`（演练模式、只读）看剩余行数。这条边界已写进
    手册与告警文案，否则运维会拿"告警还在"误判成"没迁完"
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **2 条反向断言**：非生产不得告警、
    主密钥缺失不得告警）。**变异实测被杀**：把判据改成 `NODE_ENV !== 'never-matches' && true` ⇒
    4 条红（2 条反向断言 + 2 条既有的 `toHaveLength(1)`），改回后 29/29 绿
  - **待拍板（未落地）**：更彻底的做法是把 v1 读路径也改成 fail-closed（镜像 `ALLOW_LEGACY_CBC_DECRYPT`：
    缺 `ALLOW_PII_V1_DECRYPT=true` 即抛），那样"库里有 v1 行"会当场变成响亮的读错误。
    未做是因为它是**生产行为变更**（升级即可能让存量行读失败），按本仓纪律属"需人拍板"那一档
- **#12 上传扩展名闸由 fail-open 改为构造期 fail-closed**。`middleware/security.js` 原实现是
  `allowedExts = allowedTypes.map(t => MIME_TO_EXT[t]).filter(Boolean)` 配 `if (allowedExts.length > 0 && …)`
  短路：白名单里**一个都映射不到**时 `filter(Boolean)` 把结果清空 ⇒ **扩展名校验整条消失**，
  只剩客户端自报的 MIME。今天无 multer 挂载故不可利用，但"配了却不生效"一旦随首个上传路由上线就会同时生效。
  收口：MIME→扩展名映射与校验提到**构造期**（= 路由装配期，即启动期），`allowedTypes` 里存在**任何一个**
  未映射项即抛错（只抛"全部未映射"会把部分静默放行留在原地），运行期不可能再出现"白名单非空但扩展名闸为空"
  的组合，短路判据随之简化为 `allowedTypes.length > 0`
  - 门禁：`securitySanitizeAndBlacklistDegrade.test.js` 追加 5 例（全部未映射抛 / 部分未映射抛 /
    报错点名支持集 / 空白名单不抛 / 受支持白名单不抛——最后两条防"一律抛"的恒真实现），该套件 30/30 绿
  - 已知边界：本次**只**修扩展名闸的 fail-open，未新增任何上传路由；中间件仍是"预留能力、无路由挂载"

### 修复（2026-09-30 · 安全缺口核查落地）

- **敏感 GET 读取审计判据反转（P1-④）+ PII at-rest 加密（P1-②）+ 备份加密（P1-①）等七项缺口收口**（对照 `deliverables/安全缺口核查-2026-09-30.md`，其中 P1-④ 与 P2-⑥ 已于本日早先提交落地）：
  - **P2-⑧ 传输加密启动断言**：生产环境 Mongo 非回环主机必须 `tls=true`、Redis 必须 `rediss:`，豁免走显式旗标 `MONGODB_TLS_EXEMPT`/`REDIS_TLS_EXEMPT`（同宿主 compose 即豁免使用者，拆分拓扑忘摘旗标会被启动期拦截）；判据收口 `config/transportSecurity.js`（回环判定吃 127.0.0.1/::1/IPv4-mapped/localhost 全形态；hostname 解析不出保持沉默——compose 契约测试的替身 URI 不被误杀）
  - **P2-⑨ 出站目标门禁**：`LOG_SHIPPING_URL` 在 scheme 白名单之外再拒内网/回环/链路本地目标（云元数据端点是经典 SSRF 目标）；歧义 IPv4 形态（127.1/2130706433/0x7f.0.0.1，严格解析判 null 但 OS 仍按回环连）一并拒绝；内网 SIEM 用 `LOG_SHIPPING_ALLOW_PRIVATE_HOSTS` 显式放行（主机名/IP/CIDR，与 IP 名单同一把尺）。判据 `isPrivateOrLoopback` 自 metricsAuth 迁入 `utils/ipUtils.js` 单一来源（middleware→utils 反向依赖会破分层）
  - **P1-① 备份加密 + 校验和 + 异地副本**：`backup-mongo.sh` 默认 gpg 非对称加密（备份宿主机只放公钥，私钥托管异地），明文出口 `BACKUP_ENCRYPTION=plaintext-acknowledged`（取值即确认词）；产物三件套 .gz.gpg + .sha256 + `BACKUP_OFFSITE_CMD` 异地钩子（argv 解析不经 shell 展开、失败即整体失败）；`restore-mongo.sh` 按后缀自动解密；加密/解密/校验和收口 `scripts/backupCrypto.sh`（与 mongoUri.sh 同一共享范式）；恢复演练与密钥托管见 `deployment/backup-encryption.md`
  - **P1-② PII at-rest 加密（范围修订）**：`phone` 走随机 IV AES-256-GCM（`utils/piiCrypto.js`，密文带 `enc.v1` 版本前缀供轮换），精确检索走 HMAC 检索键 `phoneKey`（select:false + 索引）——相等性不泄漏在密文列里；存量明文**读路径透传**（迁移前的旧行照常可读），写侧 `pre('validate')` 钩子加密（手机号格式校验随钩子前移到明文阶段，错误文案逐字不变）；迁移/轮换脚本 `scripts/migrate-pii-encryption.js`（演练/apply 双模，损坏行点名不覆盖，同族 allowlist 门禁）。**realName 暂不加密**（2026-09-30 决策）：姓名片段模糊检索是用户列表的日常能力，正则对密文不成立，加密它等于砍掉该能力——用户列表搜索继续覆盖 username/email/realName；`realName` 转入加密需先给姓名检索另立方案，脚本对加密窗口内已产生的密文行自动解回明文自愈
  - **P2-⑩ 供应链可追溯**：CI 构建产出 CycloneDX SBOM 并上传 artifact；镜像 `provenance: true` + cosign keyless 签名（build 作业补 `id-token: write`）
  - **P2-⑫ 依赖钉版**：`.npmrc` `save-exact=true` 从源头杜绝 caret 漂移；新增 CI 硬门禁「生产依赖树禁止任何 install 脚本」（`scripts/check-prod-install-scripts.js`，fail-closed + 显式白名单——比 --ignore-scripts 更强：ignore-scripts 只让本机跳过，树里有没有脚本没人看）
  - **P3-⑬⑭⑮ 治理文档三份**：`docs/threat-model.md`（STRIDE + 残余风险如实申报）、`docs/incident-response.md`（角色/时限/命令级遏制清单，全部绑定本系统实际存在的端点与脚本）、`docs/mlps2-controls.md`（等保 2.0 第三级重点项对照，每条挂文件/测试/端点证据）
  - 门禁：`transportTlsAssertion`（9 例）/ `backupEncryptionContract`（stub gpg 行为链）/ `piiEncryption`（纯判据 + 真实 Mongo 接线，9 例）/ logShipper 出站目标真值表（27 例）等新增约 60 例；既有 backupTransport/backupScriptGuards 夹具显式声明明文确认出口，保持其原断言对象不变

### 修复（2026-09-30 · 供应链完整性锚 + PII 旧钥残留守卫）

- **P2-⑩ 补：lockfile 完整性锚**（`scripts/check-lockfile-integrity.js` + `deployment/lockfile-anchor.json` + `npm run check:lockfile` + CI `security-audit` 一步）。已有的 SBOM/cosign/provenance 回答的是「我用了哪些组件」与「镜像来源可证」，但**不比对「依赖树与上次拍板时是否一致」**——一个夹带改 `integrity` 的 PR 会被 SBOM 忠实记录、却被当成正常构建。本锚把「上次人工拍板时锁文件长什么样」固化成哈希写进版本库，任何改动必在 diff 现形。判据口径是 **semantic 哈希**（`JSON.parse` → key 排序 → 紧凑序列化 → SHA-256）：**用原始字节哈希会在 CRLF/LF 间漂移**（开发机 Windows/CI ubuntu），后果不是「偶尔红」而是 **CI 恒假红**，而假红第一次出现就会被 `continue-on-error` 消化掉、等于没有门禁。覆盖面 2 份（后端 + `web-admin`；`zznpmtest/` 已 gitignore 故不纳入）。fail-closed：锁文件缺失/解析失败/锚缺失一律 exit 1
  - 门禁：`src/tests/deploy/lockfileAnchor.test.js` 11 例，真调脚本导出的纯函数（**不复刻判据**）；核心是「同一 JSON 的 CRLF 与 LF 版本必须同哈希」——把上述决定性实验固化成回归闸。篡改一处 `integrity` 实测 `exit=1` 且报错点名文件与期望/实际值
  - **如实声明边界**：本锚**不是 SBOM**，挡住的是「锁文件被改」，**挡不住「上游包本身被投毒且 lockfile/integrity 未变」**
- **P1-② 补：PII 轮换旧钥残留守卫**。`scripts/migrate-pii-encryption.js:48-53,106` 把 `PII_ROTATION_OLD_AES_KEY`（**旧主密钥明文**）作为 `--rotate` 的输入参数，但**没有任何地方要求轮换后清理它**——不在启动校验面、不在轮换手册收尾清单、不在脚本输出里。它是**过程残留物**而非运行时配置：一旦驻留生产环境，**轮换等于白做**（轮换的前提是「假定旧钥已泄露」，而旧钥 + 轮换前备份归档仍可解出当时全部 PII）。三处收口：① 启动期生产环境检测（并入 `config/immutableConfigGuard.js`，**告警 + `incSecurityAlert`，不阻断启动**——口径同 immutable 档位，它可恢复而阻断会让疏忽变成停机事故）；② 轮换手册收尾清单加一条；③ `--rotate --apply` 成功且无损坏行时脚本主动打印清理提示（运维跑完就在看这个输出，命中率最高）。空串/纯空白判为「无残留」（`.env` 写 `KEY=`、compose 传空值是常见 unset 等价物，判成残留会造成恒真误报）
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **4 条反向断言**：无旧钥不得告警、非生产不得告警、空串不得告警、无残留不得顶掉既有告警）。**4 组变异全部被杀**（去掉生产条件 1 红 / 去掉空串判断 2 红 / 守卫恒真 6 红 / 去掉 `incSecurityAlert` 1 红）——反向断言不是摆设
  - 同时记录一处会咬人的内部行为（非缺陷）：`--rotate` 执行期间脚本把 `AES_SECRET_KEY` 临时指向**旧钥**（`:106`），结束后恢复；当前是独立 CLI 故风险低，但**勿把迁移逻辑内联进服务进程**，否则轮换窗口内服务会用旧钥加密新数据
- **测试基建：`ciGateWiring` 的门禁清单补防瘦身断言**。`CI_ENFORCED_GATE_SCRIPTS` 此前只有**正向**检查（登记了 → 必须被 CI 调用）。变异实测：删掉清单任一行，套件只是「少跑一条」，**13/13 依然全绿** ⇒ 清单可被静默删行、被删掉的门禁从此无人守护且无任何测试变红。补反向断言：从 workflow 文本抽出实际调用的 `scripts/*.js`，要求全部已登记或已进**显式豁免清单**（豁免附理由，如 `scripts/deploy.js` 是部署脚本、非判定类门禁）。用显式豁免而非放宽匹配，是为了让「为什么它不算门禁」这个判断本身可审计。变异验证：删登记行 ⇒ 1 条红

### 新增（2026-09-30）

- **口令复用历史**：此前 `changeUserPassword` 里只有 `SAME_PASSWORD`（"不能与**当前**口令相同"），A→B→A 这种两步复用完全放行；`helpers.validatePasswordStrength` 只覆盖长度/复杂度/泄露库，全仓零处检查复用。现 `User.passwordHistory` 保存最近 N 条（默认 5，`PASSWORD_HISTORY_DEPTH` 可调，上限 24）**已退役**口令的 HMAC-SHA256 摘要，改密时逐条比对并拒绝，写入被替换掉的旧口令。摘要用 HMAC 而非 bcrypt：历史条目的用途是**等值比较**（比较时明文就在手里），bcrypt 的"慢"是为离线爆破服务的，此处不适用，而代价很实在——rounds=12 下每条 250~300ms、保留 5 条即 1.5 秒且全部挂在改密端点上，而 `passwordChangeLimiter` 只按 user+ip 限到 5 次/15 分钟、**没有全局护栏**，N 个账号就能把 CPU 打满。沿用本仓已有的同类先例 `services/mfaService.hashRecoveryCode`（HMAC + pepper，未配密钥时退化 sha256）。新增错误码 `PASSWORD_REUSED_IN_HISTORY`（400），两个改密端点（`/api/auth/password` 与 `/api/security/change-password`）映射一致，文案里的 N 由后端 `params.historyDepth` 下发，前端不写死数字
  - 已知取舍（如实记录而非假装解决）：轮换 `HMAC_SECRET` 后既有摘要全部对不上 ⇒ 历史长度归零，轮换窗口内复用防线短暂变弱。审计链 HMAC 那套重签工具在这里**不适用**——没有明文就无法重算
  - 门禁：`src/tests/utils/passwordHistory.test.js` 20 例。除判定语义与 A→B→A 行为级用例外，另有**接线不变量**（`.select('+passwordHistory')`、成功后写历史、schema `select:false`、两个控制器 outcome 映射、错误码 4xx、前端登记）——语义测对了而没接线是这类修复最常见的落地失败形态，那时下面所有语义测试仍会全绿

### 变更（2026-09-30）

- **敏感 GET 读取审计判据反转：6 条允许清单 → 默认全量 + 显式豁免清单**（`middleware/security.js` 的 `auditGetPaths` → `auditGetExcludePaths`，收口审计报告 §3.4）。原判据是 fail-open：新增一条敏感 GET 路由而忘记登记即零留痕——设备/报警/巡检的**列表与详情**正是一批这样的盲区（P0 时的 HEAD 归一修复只救了已登记的 6 条前缀；列表与详情共用派生 action `*_view`，故无需新增 action 登记）。反转后 GET/HEAD 默认审计，豁免清单只剩两类、逐条写明理由：a) 预认证/登录流程面（captcha/captcha-status/login-public-key/mfa-status，无业务数据且调用频率由认证流程决定）；b) 纯自读面（session/me/sessions/my-info/bindings/my-logs——数据主体即请求者本人且被前端每次导航轮询，操作留痕由写路径承担：改密/MFA 变更/踢会话均为写方法照常审计）。fail-closed 的直接后果：未匹配路径的 GET 探测与匿名 401 也会在审计里留痕（与既有 `/api/users` 行为一致），审计记录量随读取流量上升属预期成本；运维看板若高频轮询设备/报警列表，按 security.js auditLog 头注口径逐条评估后加豁免，**不回退允许清单**。守卫同步：`auditActionReachability` 台账 A 类 25→9（16 条随反转为真实落库并从台账移除），解析器改读 `auditGetExcludePaths` 并反转判定
- **CC 防护升级：限流信号按类别分桶，阀值差 10 倍**（`src/services/rateLimitEscalation.js`，拆出 `rateLimitEscalationBan.js`）。此前全仓只有**一个**阀值（30 次/5 分钟），而喂进这个计数器的 7 个限流器**合法拒绝率相差两个数量级**——把「30 次 captcha 拒绝」与「30 次任意请求拒绝」当成同一种证据。实际后果是两条具体的误封：① `strict` 是**已认证**端点（refresh / MFA / 报表导出 / 审计导出 / 重置他人密码），一个管理员给 20 名新员工批量开户 = 60 次操作，**共享出口 IP 的整间办公室被封 1 小时**——而越界的是账号不是 IP；② `general`/`ip` 是体量信号，其配额在 NAT 共享出口下本就被多人分摊。现分三类各用各的阀值：`ANON_ABUSE`（captcha/login-ip/register，默认 10，封 IP）、`VOLUME`（general/ip，默认 **100**——原取 30 时这一档被误伤，100 才是它的量纲，封 IP）、`AUTH`（strict/user-ip，默认 30，**只告警不封 IP**，处置走账号侧）。混检不提前：10 次 captcha + 90 次 general 不会让 ANON_ABUSE 到点
- **固定窗口 → 令牌桶**（同上）。原实现的固定窗口有两个固有缺陷：**边界突发**（窗口末秒打满 N 次、次秒重开再打 N 次可取到 2N 速率）与**升级即清零**（达阈值后 `count = 0; windowStart = now`，封禁若恰好失败则下一轮又白拿一整个窗口）。令牌桶按 `阀值/窗口` 匀速回填，两个缺陷一并消除；持续速率恰好等于阀值的攻击者不再触发（等于预算本就不该被封）。代价是纯突发打满 N 次要第 N+1 次才封——这是去掉时序后门的代价，不是弱化
- **处置与通知解耦**（`src/services/rateLimitEscalationBan.js`）。原实现 `if (!shouldSendAlert(...)) return;` 把**审计与封禁一起挡在门外**：封禁失败（写库故障 / 命中白名单）时 5 分钟内的重试也被吞掉，而审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 档」。现审计与封禁无条件执行，只有 `dispatchNotification` 受频控约束
- **计数表淘汰：`clear()` → 压力升序有界淘汰**（同上）。`hits.clear()` 是一条**可主动触发的旁路**：攻击者轮换满额 IP 就能把所有人的计数归零。改为先清已回填的，仍满则牺牲「最接近升级」程度最低的条目。刻意**不按最旧优先**——那同样是旁路：被牺牲的会是积累已久、正要升级的那条，而攻击者新轮换进来的垃圾（压力 1）反倒留在表里。淘汰顺序必须由**安全价值**决定，不由时间决定
- **审计记全量构成**（同上）。原实现只把**触发阀值的那一个限流器**写进 `body.limiter`，于是「10 次 captcha + 20 次 general」被记成「general 触发」，事后复盘归因错误。现写 `body.mix`（各限流器计数）+ `body.total` + `body.className`
- 新增 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH` / `CC_ESCALATION_EVICT_RATIO` 五个环境变量（此前 `CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 已于本轮移除），`.env.example` 补全分类判据与推导依据

### 修复（2026-09-30）

- **immutable 档位（改配置需配套数据迁移）在启动期完全静默，运维改了配置直接重启无任何提示**（新增 `src/config/immutableConfigGuard.js` + `src/tests/config/immutableConfigGuard.test.js` 10 例）。`HMAC_SECRET` 在本仓有两个消费点：审计链 `hmac`（有 `scripts/resign-audit-hmac.js` 重签工具可迁移）与**口令复用历史摘要的 pepper**（`utils/passwordHistory.js`，**没有也不可能有配套工具**——历史里存的是 `HMAC(旧钥, 旧口令)` 的 hex，无明文无从重算）。`deployment/secret-rotation.md` 的「各密钥轮换影响面」表只写了前者，收尾清单也没提后者 ⇒ 运维照 Runbook 做完全量轮换，口令复用防线已归零而手册不吭声。现启动期推一条 warning（文案点名 pepper / 历史归零 / 无重签工具 / 指向手册），并计 `incSecurityAlert('password_history_pepper_rotation','medium')`——口径与 `ALLOW_LEGACY_CBC_DECRYPT` 的既有加固完全一致（"可检测 ≠ 已告警"）。**刻意不阻断启动**：该配置的合法取值本身包含"已知代价"那一档，要拦的是**静默**不是取舍。手册同步补该影响面小节、收尾清单条目，以及 `PASSWORD_HISTORY_DEPTH` **调小**（唯一不动密钥却同样让存量对不上的项，`sanitizeHistory` 读取侧截断）的说明。**实测变异验证**：把 immutable 的 push 塞进 CBC 的 `if` 块 ⇒ 2 条红；去掉 `incSecurityAlert` ⇒ 1 条红
- **安装脚本门禁的可证伪性为零（"测试复刻了一份判据"）**（`scripts/check-prod-install-scripts.js` / `src/tests/deploy/installScriptGate.test.js`）。该门禁是 Dockerfile 里 `npm ci --omit=dev --ignore-scripts` 安全性成立的**唯一依据**，而它初版的测试把判定语义**复刻**了一遍（自写 `classify`），注释还自称"可证伪"。**实测证伪**：把筛选条件 `omitDev ? !e.dev : e.dev` 写反（生产树与 dev 树颠倒 ⇒ 门禁退化成"永远失败"），复刻版测试 **6/6 全绿**。这是一类通用的失效形态——复刻一份判据等于测试了一个平行实现，与被测对象是否还正确无关。现脚本导出纯函数 `evaluate(lock, omitDev)` 并加 `require.main === module` 守卫，测试**真调**它；同一变异下 6 条变红。另：白名单按依赖树分两档（生产树命中即红 / dev 树逐个登记理由），判据改用 `package-lock.json` 的 `hasInstallScript` + `dev` 标记（实测 `npm ls --json` 的节点**不含 scripts 字段**，1317 节点 0 命中，故不能作判据来源）、白名单登记 `@scarf/scarf`（锁文件 `dev:false`，经 swagger-ui-express 传递引入生产树）与 `mongodb-memory-server` / `fsevents`
- **`npm ci --ignore-scripts` 的落点（CI 4 处 + Dockerfile 3 处，逐处给判据而非一刀切）**：`Dockerfile` 三处**全加**（builder 阶段从不跑测试、web-builder 与 runtime 均与 mongod 无关，且 runtime 那处由 `--omit=dev` 档门禁保证"没有脚本需要忽略"），`migrate-mongo` 补装命令一并加。CI 侧**刻意只给 e2e-browser 加**（其 Mongo 来自 `mongo:6.0.20` service 容器，不依赖 `mongodb-memory-server`）；`test` 与 `e2e` 作业**不加**——它们真的需要内存 Mongo 的 mongod 二进制，跳过安装脚本会把「安装期一次性下载」挪进 jest worker / 脚本进程，而本仓已有 `mongodb-memory-server` 子进程句柄与 jest 退出竞态的实证记录（`ci.yml` 的 `--forceExit` 头注）。判据：跳脚本不会让 `npm ci` 失败（`postinstallHelper.js` 失败路径是 `process.exit(0)`），代价是时序面，不是安装成败- **`checkBruteForce` 的通知频控挡在审计与封禁之前（与 CC 那条线同源，是同一轮修法的漏网）**。`securityAlert.js` 里两行 `shouldSendAlert`（账户维度 + IP 维度）排在阶梯统计 / 审计落库 / `addToBlacklist` **之前**，任一命中即 `return`，把三件事一起关在门外。后果不是少一条通知：① 封禁**失败**（白名单命中 / 黑名单写库故障）时 5 分钟内的重试被这行吞掉——而"封禁没生效"恰恰最需要重试；② 审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 次」。修法与 `rateLimitEscalationBan.js` 同一条纪律：**统计 / 审计 / 封禁无条件执行，频控只约束 `dispatchNotification`**。两个去重键保持内联（键里同时含 username 与归一化 IP）且短路语义逐字保留（`||`——任一维度放行即投递，改 `|` 会多消费一个 key 使抑制变强）。**实测变异验证**：把闸移回原位后 2 条用例红
- **`checkPermissionAbuse` 只告警、不封任何东西（唯一一处"跨层探测已认证权限边界"的哨兵没有遏制手段）**（新增 `src/services/securityAlertPermissionAbuse.js`）。该检测器此前整条路径只有「审计 + 通知」，另两个检测器都有封禁动作。缺口是：攻击者只要拿到一份**有效凭据**，把权限探测压到每 5 分钟 < 20 次，就能永久试探权限边界——每次都不达阈值 ⇒ 无告警、无审计、无遏制（20 次/5 分钟这条阈值只挡"不会隐藏自己的人"）。现达阈值时对**来源 IP** 走与暴力破解同一条渐进式封禁阶梯（1h→4h→24h→7d），事件源是独立的 `action=permission_abuse`（与 `brute_force_login` 分账，各数各的，只共用时长档位与 30 天窗口，新增 `IPBanEvents.countPermissionAbusePrior`）；无 IP 上下文时只告警不封（不得把 `undefined` 当 IP 封）。同样的处置/通知解耦、同样的"先读阶梯后写审计"、同样的按返回值分派（F-160 口径：`addToBlacklist` 从不抛错，白名单/写库失败时"已封禁"日志就是纸面防线撒谎）。处置侧整块抽到新文件是体积债收口（`securityAlert.js` 净代码行已贴 300 上限）。**实测变异验证**：跳过封禁后 3 条用例红
- **出站告警契约闸的两处能力缺口**（`src/tests/services/outboundAlertContract.test.js` / `fireAndForgetAlertSingleEntry.test.js`）：① 判据只认**裸** `ALERT_TYPES.X`，不认带模块前缀的 `securityAlert.ALERT_TYPES.X`——而后者语义完全等价且跨模块调用时必须用；`auditChainMonitor.js` 的调用点原是三表达式，拆成 if/else 后双闸齐红。现解析器接受可选前缀（键的真实性仍逐条校验）。② `sendNotification` 白名单未登记 `auditChainMonitor.js`（它是第二个 `await` 侧调用点，要拿投递结果做自己的记账），按该闸的设计意图显式登记。**注**：这两处是上一轮审计链守护闭环引入的欠账，非本轮新增缺陷
- **`backgroundJobs.test.js` 的频控断言钉的是被修掉的旧行为**：原断言「5 分钟频控窗口内第二次检测不再写审计」，正是上面第一条缺陷的形状。已改为「通知不重复，但**审计必须照写**」（`after === before + 1`）；另把 `securityAlertWriteFailureTolerance.test.js` 的"写入成功不打 error"反向对照显式桩掉封禁链路——该用例的命题是"审计写入成功"，不该被"这个 IP 恰好能不能被封"污染
- 门禁：新增 `src/tests/services/securityAlertContainmentDecoupling.test.js`（7 例：频控命中时审计/封禁照做、封禁失败后重试不被吞且阶梯升档、权限滥用必须真的封 IP、权限滥用阶梯独立分账、无 IP 不封、两条 `shouldSendAlert` 位置文本闸）

- **`auditChainMonitor.runVerification` 的函数体积债（101/100，上一轮的欠账）**：该文件是未跟踪新文件，不在棘轮基线里，于是它的 `max-lines-per-function` 超标要到下一次全量跑才暴露。把「告警投递」整块（`noticeData` 组装 + 按 `hasBreaks` 的 if/else 静态分派）抽成 `dispatchChainAlert`——拆函数正是本仓对体积债的既定处置。顺带把「档位/类型不得写成三元表达式」这条约束的注释挪进新函数，让它有独立的注释位而不容易被后来的重构顺手"简化"掉。行为逐字不变（`outboundAlertContract` / `fireAndForgetAlertSingleEntry` / `auditChainGuardedIntegrity` 三套件 31 例全绿）
- **补上一轮遗漏的 prettier 格式**（`auditChainMonitor.js` / `securityAlert.js` / `auditBufferFlushAndWalGuards.test.js` / `securityAlertContainmentDecoupling.test.js` 四文件）。`npm run format:check` 自那轮起就是红的

- **`web-admin/src/tests/build/` 被 `.gitignore` 的 `build/` 规则吞掉，一份正牌回归测试从未进过 CI**。该目录下是 `manualChunks.test.js`（P2-52 回归，4 例，直接 `import` 真实 `vite.config.js` 调 `manualChunks`，注释里记着实测更正与反证记录）。`.gitignore:46` 的 `build/` 是为构建产物加的，而它**无前导斜杠 ⇒ 匹配任意层级的 `build` 目录**，于是测试目录被一起吃掉。后果是它在本地跑、在 CI 上根本不存在（本地前端 1431 例含它，CI 从未执行）。已把目录改名为 `web-admin/src/tests/bundling/`（不改 `.gitignore`：`build/` 规则本身有其必要，不该为一个测试目录放宽）
- **门禁：测试树纯净性**（新增 `src/tests/ci/testTreePurity.test.js` 5 例）。`testMatch` 是「任意层级下的 `src/tests/` 里的 `*.test.js`」，因此放在那里的**任何** `.test.js` 都会被执行——包括从未提交、只是调试时落下的草稿。这类失效形态是"不出错、只污染信号"：草稿的 pass/fail 混进总数，而**本该入库**的用例一旦漏 `git add` 则是本地全绿、CI 上压根不存在。两条方向相反的判据：未跟踪 ⇒ 报红（给出"入库或挪出"两条出路）；已跟踪的 `zzz-*.test.js` ⇒ 报红（`.gitignore` 只约束未入库，管不住 `git add .`，而当初那批 8 个探针 / 591 行 / 51 test / 0 expect 正是这么进去的）。判据用 `!tracked.has(f)` 而非 `ls-files --others --exclude-standard`：**被 gitignore 误伤的文件正是本条门禁上线当天抓到的第一个案例**，用 `--exclude-standard` 它会隐身
- **补上 `d72872c` 漏同步的两处断言**（`auditQuerySharedBuilder.test.js` / `auditQueryFindAggregateParity.test.js`）：该提交把 username 前缀查询的上界从「末字符码点 +1」改为追加 collation 哨兵 `U+FFFF`（ICU 排序下前者对 `z`/`Z`/`9` 等末字符构成**空区间**），并同步了 `auditUsernamePrefixIndex.test.js` 的契约，却漏掉了另两处同样断言该 helper 输出形状的用例 ⇒ HEAD 上稳定 2 红。断言已改为钉哨兵形状；哨兵在 collation 下确实恒大于任何 `prefix + <已分配字符>` 仍由 `auditUsernamePrefixIndex.test.js` 的 DB 回归用例负责，不在此处重复造一个纸面断言

- **`req.query` 物化：Express 5 下 query 注入防线此前靠注释撑着**（新增 `middleware/security.js` 的 `materializeQuery`）。`req.query` 是原型上的 getter（`express/lib/request.js: defineGetter(req, 'query', ...)`），每次访问重新解析 URL，于是 `sanitizeMongo` 与 `hpp` 对 query 的原地清洗是**彻底空操作**——实测（Express 5.2.1 + supertest）`delete req.query.search` 之后**同一 handler 同一 tick** 内回读 `Object.keys(req.query)` 仍带 `search`，比 P1-33 记录的"下次访问才丢"更彻底。现改为读一次 → 复用 `deepSanitizeKeys` 清洗 → `Object.defineProperty` 物化成自有数据属性 → **回读自证身份，不等即拒绝请求并 error 级留痕**（物化失效是零报错事件，"服务不可用"远好过带着未清洗的 query 继续服务）。附带收益：解析次数从"每个消费者一次"降到全请求一次。`sanitizeMongo` 已移除对 `req.query` 的遍历——留着只会让人误以为 query 有两道防线
- **静态面限流判据单一来源 + 补上零预算**（`middleware/staticFrontend.js` / `rateLimit.js`）。此前限流侧判据是"安全方法 + 非 `/api/` 前缀"，与 `staticFrontend` 的 `RESERVED_PREFIXES` 是两份独立清单，实测对 11 条非 `/api` 路径有 **8 条判定相反**。逐条核对后真正裸奔的两条：`/socket.io/`（Socket.IO HTTP long-polling 握手是未认证 GET，而 `MAX_CONNECTIONS=1000` 约束的是**已建立连接数**、`authenticateSocket` 在连接建立之后才跑 ⇒ 握手面应用层零限流）与 `/metrics`（`metricsAuth` 允许内网免令牌，而 `app.js` 自陈的威胁模型正是"容器网络内直连 app:3000"）。判据现由 `isStaticSurfaceRequest` 单一来源提供，豁免集合**收窄**（新登记的保留前缀自动重新纳入限流，限流侧无需改动）。另新增 `staticSurfaceLimiter`：静态面此前被整体豁免，而豁免的代价是**零预算**（单 IP 可无限拉 `/assets/*`）；现按"按成本分桶"给它自己的宽松桶（12000 次/15 分钟，按 34 静态请求/页 × 30 人 NAT × 10 次页面加载 = 10200 留 18% 余量推导），429 文案与通用限流刻意区分，且**不接入 CC 封禁升级阶梯**（静态面被限流多为出口聚合，接上去会把误封从单个 IP 放大到整个办公室）
- **门禁：把"注释级约定"变成可执行不变量**（新增 `src/tests/app/queryDefenseSingleSource.test.js` 11 例、`staticSurfaceRateLimitGate.test.js` 17 例）。前者刻意跑在**真实 express 实例 + supertest** 上并含一条**反向对照**（未物化时 `req.query` 确实不是自有属性、确实跨读取不稳定）——因为既有那组 `sanitizeMongo` 单测用的是手搓 `req` 桩，桩上的 `query` 是普通属性，**结构上不可能**发现 Express 5 的 getter 前提；本次同时把该单测里断言 `query: 10` 的那条改成如实反映"query 不再经过 sanitizeMongo"。后者钉住判据单一来源、8 条分歧路径逐条归属、大小写同尺、以及静态面不再是零预算
- ~~**CC 升级封禁阈值 100 → 30，并新增预警档**~~ —— **本条已被上方「变更」段的分类分桶方案取代，保留在此仅说明演进过程**：单一阀值（无论 100 还是 30）的问题不在数值，而在它把 7 个合法拒绝率相差两个数量级的限流器加进了同一个桶；`CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 两个变量均已移除，改为按类别的 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH`。原判断里成立的部分（`generalLimiter` 触顶后窗口内每条请求都是 429、真攻击 5 分钟可刷出数千次）已被吸收进 `ANON_ABUSE` 的推导

- **`package.json` 的 `engines.node` 与前端实际要求对齐**：`>=18` 与 `web-admin` 的 Vite 8.1.4（`engines.node: ^20.19.0 || >=22.12.0`）冲突——声明允许的 Node 18 上 `npm ci` 能装完依赖，但 `npm run build` 结构性失败。改为 `^20.19.0 || >=22.12.0`，与 CI 的 `[20.x, 22.x]` 矩阵、前端 job 的 `24.x`、Dockerfile 的 `node:22.14.0-alpine` 落在同一条区间上
- **`.dockerignore` 补齐被漏掉的构建上下文**：Docker 的忽略模式只从上下文根起算，bare `coverage` **不匹配** `web-admin/coverage`（与本文件必须写全 `web-admin/node_modules` / `web-admin/dist` 是同一条语义），而 `web-builder` 阶段是 `COPY web-admin/ ./` ⇒ 3.2 MB 前端覆盖率报告与 4 个 `coverage-zz*` 残留目录一直进构建上下文与镜像层。同时补 `web-admin/.mimosa`、`.mimosa`、`.jesttmp`（本机 82 MB）、`playwright-report`（9.5 MB）、`test-results`、`.lint-ratchet-selftest-*`、`zztmpctl`/`zznpmtest`（含自带 `node_modules` ~93 MB）与 `.admin-initial-password`（当前超管明文口令，59 字节）。后几项目前因 Dockerfile 走 `COPY` 白名单路径而未泄漏，但任何将来新增的宽泛 `COPY .` 都会一次性引爆

### 新增（2026-09-28）

- **IP 归属地展示（离线零依赖）**：会话管理、审计日志列表、IP 黑白名单等后台界面把裸 IP 翻译为「国家·省·市·运营商」。数据采用 ip2region 官方 xdb（Apache-2.0）入库 `src/data/`（约 11MB，Docker `COPY src/` 一并带入镜像），检索器 `src/utils/ip2regionSearcher.js` 以纯 Node 实现 xdb v2 格式（向量索引 + 二分，全内存约微秒级/次），不引入任何 npm 依赖；`src/services/ipLocationService.js` 负责业务口径（复用 `ipUtils.normalizeIP` 收敛 `::ffff:` 形态、内网/保留地址统一标「内网」含 IPv6 回环/链路本地/ULA、结果 FIFO 缓存 2048 条、任何异常 fail-soft 返回 null）。`GET /api/auth/sessions` 每条会话新增 `location`（最近活跃 IP）与 `loginLocation`（登录 IP）；审计日志两条分页路径与 IP 名单列表逐行补 `location`；前端在 IP 旁以 `·` 拼接展示（后端缺字段/CIDR 网段自动省略）。数据刷新：`node scripts/update-ip2region.js`（Gitee→GitHub→jsDelivr→npm 镜像四级数据源 + 结构校验 + 探针查询 + 原子替换），`--check` 只打印当前数据构建日期
- **CC 防护升级闭环**（`src/services/rateLimitEscalation.js`）：限流从「只挡不罚」变为「可观测 + 可升级」——每次 429 上报 `security_alerts_total{type=rate_limit_triggered}`；同一 IP 在 5 分钟窗口内触顶达阈值（`CC_ESCALATION_THRESHOLD` / `CC_ESCALATION_WINDOW_MS` 可调，**2026-09-30 起已重构为按类别分桶（见上方「变更」段：单一阀值与预警档均已移除）**）即按与暴力破解同一条封禁阶梯（1h→4h→24h→7d，30 天审计事件计数升档）自动封禁。防误封设计：白名单 IP 的资源型限流直接 skip 不会产生升级信号；凭据型账号维度桶不接入（无 IP 可封）；升级链路全程 fail-soft 不拖垮 429 响应。计数为进程内固定窗口（多实例下按实例数摊薄，少封不误封）
- 数据文件入库配套：`check-utf8` 门禁的常见二进制扩展名清单加入 `.xdb`，`.gitattributes` 钉 `*.xdb binary`

### 变更（2026-09-28）

- **限流键统一 IP 归一化**（总账 §4.4「限流键直接拼原文 req.ip」收口）：全部 IP 维度限流器（general/strict/login/ip/user 未认证分支/captcha/register/pwd-change/reauth 及 wellKnown 三个上报限流器）的键改走 `normalizeRateLimitIp`（与名单侧同一把 `ipUtils.normalizeIP`），消除 `::ffff:1.2.3.4` 与 `1.2.3.4` 双桶导致的「同一来源配额翻倍」；歧义写法回退原文自成桶，fail-closed 语义不变。`ipLimiter` 补显式 handler（响应体与原 message 逐字一致，差异仅多升级信号上报）
- **暴力破解自动封禁判据只看 IP 维度**（总账 R-H2）：`checkBruteForce` 此前以 `max(userFailures, ipFailures)` 达标即封禁**当前请求 IP**——分布式撞单账号时把可能只贡献了 1 次失败的 IP（NAT 出口后的无辜用户/受害者本人）封 1 小时。现改为告警与审计照发（双维度都是真实攻击信号，审计 body 含双维度计数），封禁仅在 `ipFailures` 达阈值时执行
- **wellKnownRoutes 三个限流器接入共享存储**（总账 P-9）：`/csp-report`、`/client-errors`、`/.well-known/security.txt` 的限流计数从每实例独立 MemoryStore 改为 `makeSharedStore`（无 Redis 时行为不变），多副本部署下攻击者不再能对每个副本各刷满一份配额

### 测试基线

- 后端：477 个套件 / 4583 个用例文件（2026-09-30 按文件数与 `test()/it()` 声明数实测；此前记的「130 套件 / 1736 例」与 `jest.config.js` 注释里的「280 套 / 3300+ 例」均已失真一个台阶）
- 覆盖率阈值：全局 br 79 / fn 87 / ln 91 / st 91，另 36 个安全关键文件单独设阈；**不复写实时覆盖率数值**——要当前数字看 `npm run test:coverage` 的输出，写死即立刻失真

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
  \t\n'`（循环后还原），并补一条「source 注入 `IFS=' '` + 共谋 tr」
的能红用例（`backupUriFile.test.js` 45→46）。`capture` 是子 shell 执行的脚本、IFS 传不进来，
只在注释写明不对称。
四处判据最终统一为**三条真实载荷腿**（每条腿的失败方向都与「拒绝」一致）：**互补绝对计数**
（允许字节数 + 禁止字节数 == 总字节数；`tr` 不过滤 ⇒ 两边都等于总数 ⇒ 判「检测不可用」）、
**直接数违禁字节**（换行 / NUL / CR 必须为 0 —— 内容相关退化在这条上藏不住）、**`od`逐字节
目视**（不经`tr`/`wc` 的独立字节通道：token 数必须等于总字节数、`0d` 等违禁 token 逐项判定）：

- `scripts/mongoUri.sh::mongo_validate_uri`：`${#_uri}`（shell 内建）交叉 + 互补计数闭合 +
  直接数违禁字节 + `od` token 区间目视（`for … in $var` 解析）。
- `scripts/mongoUri.sh::mongo_hydrate_uri`：`stat -c %s` 与 `wc` 独立交叉、`[ -s ]` 自相矛盾守卫、
  `_n`（行数）形状校验、互补计数闭合 + NUL 直数 + `od` 目视。
- `scripts/capture-image-digests.sh`：同上三腿 + 直接数 CR 字节；`od` 解析用 `for … in $var`
  （第五轮实测：手写 while 对行尾 token 漏计 ⇒ 16 字节边界的 CR 看不见 ⇒ 共谋 `tr` 下 CRLF 被
  静默改写 rc=0；修复后同一夹具「有 7 个 CR」拒绝落笔）。为什么不用 `grep`（第一版就是它）：
  MSYS/Git Bash 的 grep 走文本模式，CRLF 被当成行尾、CR 在匹配前就被吃掉——实测 `LC_ALL=C grep -q
-e "$(printf '\r')"` 对 CRLF 文件返回 1（＝「没有 CR」），那样的所谓独立腿在 Windows 上恒绿。
  `tr`/`wc`/`od` 是字节流、不认行尾，两个平台同一语义。
- `scripts/backup-mongo.sh`：归档字节数先过「非空 + 纯数字」形状校验，再比 `-le 0`。

用例（红→绿→红→绿，逐条变异取证，全部落在上表各条腿上）：`src/tests/deploy/backupUriFile.test.js`
45 条、`src/tests/imageDigestGate.test.js` 62 条（含第五轮新增 3 条：同源共谋 `tr` + CR 全部落在
16 字节边界 ⇒ 必须拒；`od` 桩只吐 3 个 token ⇒ 判「目视不可用」；`od` 对内容说谎 ⇒ 兜底腿仍拒）、
`src/tests/backupScriptGuards.test.js` 11 条。关键变异：摘互补和式 ⇒ 红；摘 NUL 拒绝臂需与 `od`
NUL 臂双摘才红（两臂冗余是设计，单摘时另一臂仍拦）；摘 `capture` 的 `od_cr` 腿 / 直接计数腿 /
token 数腿 ⇒ 各自用例以 rc=0 的 fail-open 复现变红；还原后所有文件 sha256 与改前一致。

> 顺带修正 `src/tests/deploy/backupUriFile.test.js` 的「前提自证：删掉 NUL 闸」用例：它按「第一个 `fi`」
> 定位删除区间，而本轮在它前面插了新腿，冷启动会**删掉半截**、留下悬空的 `_file_nonnull` 引用 ——
> 那正是这条用例自己要防的静默错删。现在按两条 NUL 臂（直接计数 + `od`）各自的 `if` 行成对定位，
> 找不到就抛（判据变了 ⇒ 同步用例），不许静默跳过。

### 修复：权限软删除的「只读墓碑」被写路径绕过（D5，2026-10-30）

> 来源：`work/audit-round3-config-mw.md` 的 D5。

`src/models/Permission.js` 的软删除过滤原本只挂 `/^find/` 与 `countDocuments`，
而模型自己的承诺是「文档永不离开集合、保留期后可复核」——`updateOne`/`updateMany` 一条就能
**就地改掉已删除的行**，`distinct`/`aggregate` 则会把已删除的 code 重新吐出来（审计实测：
`updateOne({_id}, {$set:{name}})` 对已删除文档返回 `modifiedCount: 1`）。

现在把覆盖面扩到 `updateOne`/`updateMany`/`replaceOne`、`distinct`、`estimatedDocumentCount`
与 `aggregate`（管道首部注入 `$match`），并保留两个**显式**放行口子：过滤条件自己写了 `deletedAt`，
或更新文档本身在动 `deletedAt`（软删除/恢复这类状态变更——`permissionService` 的恢复补偿
`updateOne({_id}, {$set:{deletedAt:null}})` 正是这种形态，不能把它吃掉）。
`deleteOne`/`deleteMany` **有意不加**：非测试代码里零调用方，而测试清理与运维删除需要硬删；
把它留给「谁真要在生产硬删已删除的权限」时显式决定（本轮不替未来做决定）。

用例（`src/tests/services/permissionSoftDelete.test.js` 三条）：写路径不命中（活跃行对照命中）、
两条放行口子仍有效、`distinct`/`aggregate` 不泄露。实测变异（撤掉写过滤 + 撤掉 distinct/aggregate 注入）
⇒ 正好两条新用例红（`Expected: 0 / Received: 1`）；还原 ⇒ 10/10 绿。

### 加固：三处「缺 shell 就整组静默跳过」的门禁补上 CI 守卫（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S2 —— 与 `imageDigestGate.test.js:80-89` 的既定先例不一致。

`backupScriptGuards`、`ciProvisionFailurePropagation`、`appEntrypointQueuePermFallback` 三份行为闸都写着
`const group = BASH ? describe : describe.skip`：本机（Windows/MSYS）探不到 POSIX shell 时**整组跳过**。
在本机这是合理的降级，但在 **CI（ubuntu）上探不到 shell 就是探测本身坏了** —— 此时整组零断言的绿
与「这些不变量根本没被验证」是同一件事，而且没人会去数 skipped 的条数。

现在三份文件都补上 `if (!BASH && process.env.CI)` 的守卫：CI 上解析不到 shell ⇒ 直接红（口径同 imageDigestGate 的先例）。
实测（临时让候选表返回空 + `CI=1`）：三份守卫同时红并给出「本文件全部覆盖都是假的」的原因；
恢复候选表后 `CI=1` 下 3 suites / 21 tests 全绿。

### 加固：仓库 shell 脚本的语法闸 + 两处 spawnSync 超时兜底（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S3/S4（疑似）。

- **新增 `src/tests/ci/shellScriptSyntax.test.js`（S4）**：每份**已入库**的 `*.sh` 都要用它
  **shebang 指定的解释器**过一遍 `-n`（`#!/bin/sh` 用 `sh -n`、`#!/usr/bin/env bash` 用 `bash -n`），
  并单独钉住 `docker/app-entrypoint.sh` 必须按 **sh（dash 语义）** 检查，不许被 bash 顶替。
  此前仓库只有 workflow 的 `run:` 块有 `bash -n` 闸，脚本本体一个语法判据都没有 ——
  而 `docker/app-entrypoint.sh` 一旦语法错误，后果是**容器起不来**，要等下一次部署才发现。
  反向自证用**同一个** `checkScript()`：造一份少 `fi` 的脚本必须报红、同目录合法的必须绿、
  没有 shebang 的必须判否（不许静默跳过）。实测把 entrypoint 的收尾 `fi` 去掉 ⇒ 闸红并给出 dash 的报错行号；还原 ⇒ 绿。
- **两处 `spawnSync` 补 `timeout: 30000`（S3）**：`appEntrypointQueuePermFallback` 与
  `ciProvisionFailurePropagation` 的夹具子 shell 卡住时，应当红在断言上（超时 ⇒ `status=null`），
  而不是把整条流水线拖到 CI 超时。

### 修复：「工具在不在」的自证 ≠ 「这一次判据能不能执行」（2026-10-30）

> 来源：`work/audit-round3-toolfailopen.md`（第三轮审计对上一轮修复的**再攻击**）。
> 上一轮给两处字节判据装了「工具缺失 ⇒ 拒绝」的探针，本轮被证明**探针与判据不是同一个调用形态**：
> 探针证明「本机有 tr」，判据需要的是「这一次 tr 真的跑起来了」。两者之间的失败面无人观测。

三个实测反例（第三轮审计给出端到端复现，本轮已逐条用用例钉住）：

1. `scripts/mongoUri.sh` 的「单行纯可打印 ASCII」：探针跑 `tr -d 'a'`（单字符集合），
   判据跑 `tr -d '\041-\176'`（八进制区间集合）。只让后者失败 ⇒ `$(…; printf '~')` 恰好等于 `~` ⇒
   **带换行的连接串 rc=0**，换行会成为 mongodump/mongorestore 配置的第二行。
2. `scripts/mongoUri.sh` 的 NUL 判据：正常值就是 0，与「tr 死了、wc 读空 stdin 打印 0」不可分 ⇒
   UTF-16LE 密钥文件 rc=0（目标库名被改坏）。只有「管道首尾同时死」才偶然拒绝。
3. `scripts/capture-image-digests.sh` 的 CR 判据：探针走**管道输入**，判据走**文件重定向输入** ⇒
   后者失败被读成「没有 CR」⇒ 把 CRLF 的 Dockerfile 重写成 LF 并钉版，**exit 0**。

**改法（两处同一条通则）**：不用探针兜，直接让判据**自己会失败**——改成两个**字节计数相比**，
并先做「非空 + 纯数字」形状校验：

- mongoUri：可打印字节数 == 总字节数（`wc -c` 拿总数；`tr -cd '\041-\176'` 拿可打印数）；
  NUL 判据同理，比的是「非 NUL 字节数 == 总字节数」——**用非 NUL 而不是 NUL 计数**，
  因为后者的正常值就是 0，与工具的失败输出不可分。
- capture-image-digests：非 CR 字节数 == 总字节数。

于是**工具的失败方向与判据的拒绝方向一致**：tr 任何形态失败 ⇒ 计数变成 0（或形状非法）⇒ 与总数不等 ⇒
拒绝。空值两边都是 0，由后序判据（scheme / 空文件）给出准确原因。

**证据**：`backupUriFile.test.js` 34/34、`imageDigestGate.test.js` 56/56、
`backupScriptGuards.test.js` + `backupFailureArtifactHygiene.test.js` 29/29；
新增 5 条用例在**回退脚本**后恰好全红（探针形态失败 / NUL 形态失败 / 文件重定向形态失败 / 两种「无 tr」形态），
改回后全绿。桩是否真的生效由用例自己观测（打印 `tr=` 的解析结果，并要求落在桩目录里）。

### 修复：跨平台夹具 `exec` 的两种失效形态（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的「疑似（高）」。`src/tests/helpers/stubPath.js` 把「PATH 桩目录」
> 收口到孩子 shell 内部（MSYS 启动时会前置 `/mingw64/bin:/usr/bin`，从 Node 侧改 `env.PATH` 无效），
> 但它的 `exec` 形态选错了两次，两次都不会让套件「变红得有意义」。

- **`exec "$@"`（直接 exec 脚本文件）依赖可执行位**：本仓 `scripts/*.sh` 在 git 里全是 `100644`。
  MSYS 下照样能跑（shell 自己读文件），Linux 上 `execve` 直接 `EACCES`，非交互 shell 随即退出 ⇒
  两个备份套件会在 CI 上整片**假红**。
- **改成 `exec "$0"` 会静默毁掉夹具**：Windows 上 `$0` 是 `…/Git/bin/bash.exe`，重起一个 Windows 进程
  让 MSYS 再走一遍启动注入，`/mingw64/bin:/usr/bin` 被塞回 PATH 最前 ⇒ 桩目录失效。实测 PATH 首项变成
  `/mingw64/bin`、`date` 命中 `/usr/bin/date`，用例报出真日期（`fire-safety-backup-20261030-205053.gz`）。
  这比假红更坏：套件是红的，但红在夹具，而夹具失效本身不报警。
- **最终写法 `exec bash "$@"`**：按 PATH 解析到 MSYS 本体，不重走启动注入、走解释器与可执行位无关，
  两个平台语义一致。实测改后 `backupScriptGuards`（10 例）+ `backupFailureArtifactHygiene`（19 例）全绿，
  含那条「同名归档存在时拒绝覆盖」的确定性时间戳用例。

### 加固：第二轮逐行审计的「闸没有判别力」收口（2026-10-30）

> 来源：`work/audit-round2-infra.md`（132 行，逐条 file:line + 真跑复现）。这些缺陷的共同形状不是
> 「代码写错」，而是**闸自己不会红**：注释里声明的不变量，没有任何一条判据能单独钉住它。

- **逐条 `&&` 无人守**：`appEntrypointQueuePermFallback.test.js` 的夹具只有「整类命令全失败」一档，
  于是 `docker/app-entrypoint.sh:135` 的 `&&` 删掉后 4/4 仍绿（链上第一条就断，中间失败跑不到）。
  夹具改为「第 N 次调用失败，N=1..8」逐条注入，并加一条反向对照：把 `&&` 换成分号的**历史形态**
  喂进同一夹具，第 2 条失败必须被静默吞掉（证明本闸抓得住它）。
- **正则判别力为零**：`hotUpgradeQueueContract.test.js:135` 的 `/…(?: &&)?$/m` 对「有/没有 `&&`」都真。
  改成必需的 ` &&# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

，并补一条前提自证：整块 8 条命令之间必须恰好 7 个 `&&`。

- **`test -n "$MONGOD"` 无判据**：`.github/workflows/ci.yml:137/:508` 的这行删掉后整族仍绿，
  而「provision 退出 0 但什么都没打印」正是该步骤自述的头号危害（空值让 MongoBinary 回落到
  未经仓库 SHA-256 锚的下载）。补「exit 0 + 空输出 ⇒ 步骤必须红且不写空值」用例，
  并从**抽取到的真实步骤体**删掉那一行做前世版自证（不抄副本）。
- **「失败即放行」语义未钉**：`app-entrypoint.sh:148` 的 `return 0` 换成 `exit 1`（容器起不来）闸仍绿。
  逐条注入的用例现在同时断言 `rc=0`：失败必须告警放行，而不是把容器弄得起不来。
- **探针假阳性**：`helpers/posixShell.js` 的可用性判据用 `includes`，而 MSYS 的 `echo.exe` 会把参数
  原样回显（标记于是「包含」在 stdout 里）⇒ 一个根本不是 shell 的可执行文件被判为可用。
  改成**严格相等**（标记必须独占 stdout），并补一条用「只回显 argv」的可执行文件做的反向对照。
- 实测（Windows / Git Bash，非 Linux 权威）：入口脚本变异 `&&` → `; true &&`（`&&` 计数不变、语义已断）
  ⇒ 用例红在「第 1 条失败却被吞」；还原 ⇒ 绿。`hotUpgradeQueueContract` 删掉一个 `&&` ⇒ 红；还原 ⇒ 绿。
  `posixShell` 探针退回 `includes` ⇒ 新用例红；还原 ⇒ 7/7 绿。

### 修复：两处「工具缺失即静默放行」的字节级判据改为失败关（2026-10-30）

> 来源：第一轮逐行审计的 A6（运维脚本族的 fail-open）。两处的形状相同：判据由外部工具执行，
> 而工具失败时命令替换得到的是**空串**，与「值/文件本来就干净」不可分。

- `scripts/mongoUri.sh` 的 `mongo_validate_uri`：「单行纯可打印 ASCII」判据由 `tr` 执行。实测（PATH 里没有 `tr`）
  带真换行的连接串照样 rc=0 —— 那个换行会被写成 `mongodump`/`mongorestore` 配置文件（0600）的第二行，
  正是这条判据存在的理由（同文件顶部 2026-10-03 的取证）。现在先让字节通道**自证**：`'ab'` 删掉 `'a'` 必须恰好
  剩下 `'b'`；量不到就拒绝放行（fail-closed）。
- `scripts/capture-image-digests.sh` 的 CR 检测（`tr -dc '\r' | wc -c`）同理：`wc` 照旧输出 `0`，与「文件里没有 CR」
  不可分 ⇒ 检测被整体跳过，MSYS 的 `sed`/`gawk` 顺手吃掉 CR，脚本会把 CRLF 静默改写成 LF 并报成功。
  现在先用一个已知含 CR 的输入证明通道是活的，量不到即拒绝落笔（与同脚本 :47 的 `docker` 存在性检查同一口径）。
- 用例：`src/tests/deploy/backupUriFile.test.js` 新增 3 条（含「tr 在位」的前提自证与「无法校验即拒绝」），
  `src/tests/imageDigestGate.test.js` 新增 1 条（含「同一夹具在真 tr 下必须成功」的反向前提）。
  两处守卫都以「临时摘掉判据 ⇒ 用例必须红」证伪过（实测 2 红 / 1 红），再还原为绿。
- 同批：`src/tests/middleware/avatarUnmatchedSurfaceGuard.test.js` 的固定 30ms 睡眠换成条件等待
  （`helpers/waitFor` / `waitForStable`），修掉 `noFixedSleepRatchet` 的回退。

### 新增：临时权限授予与定期复核（C-08 / C-09）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 C-08 / C-09 控制项实现；决策与取舍见 `docs/adr/ADR-012-临时权限授予与定期复核.md`。

- **端点**：`GET /api/permissions/grants`（列表，按 status/userId 过滤）、`GET /api/permissions/grants/review`（复核汇总 + 超期清单）、`POST /api/permissions/grants`（申请）、`POST /api/permissions/grants/:id/{approve,reject,revoke}`。权限码 `privilege:read` / `privilege:grant` / `privilege:approve` 已进目录与菜单。
- **不变量**：到期在**读取路径**判定（`status==='active' && expiresAt > now`），后台 `expireDue` 只收敛状态；申请人不得自审；高敏模块（user/role/permission/security/system/privilege）的码需 2 名不同审批人；审批人必须自持被授予的每个码；每次状态变更都失效目标用户权限缓存（钩子缺失时抛错，fail-closed）。
- **数据**：新集合 `PrivilegeGrant`（`models/PrivilegeGrant.js`），审批链以 `{by,name,at}` 快照落库，终态记录不删除（审计可回看）；索引 `{userId,status,expiresAt}` 与 `{status,expiresAt,createdAt}`。
- **审计**：新增 action `permission_grants`、`permission_grants_review`、`permission_grants_approve`、`permission_grants_reject`、`permission_grants_revoke`（category 仍为 `permission`，见 ADR-012「为什么不新开 privilege 分类」）；派生动作由 `/api/permissions/grants` 前缀自然得出，无手工登记路径。
- **运维**：`scripts/access-review.js`（默认输出 JSON 汇总；`--expire` 收敛过期状态；`--fail-on-overdue` 退出码 1 可挂 CI）+ `deployment/systemd/fsms-access-review.{service,timer}` 每小时巡检。
- **用例**：`src/tests/services/privilegeGrantFlow.test.js`（21 例规则：到期失效、双人复核、自审/无码阻断、并发签批、驳回与撤销的状态机单向、复核登记、服务层入参兜底、被授权账户不可用、权限判定与缓存失效两处钩子缺失时 fail-closed）、`src/tests/routes/privilegeGrantEndpoints.test.js`（7 例：鉴权、校验链、全链路、双人复核、自审阻断、驳回端点、审计派生 action 入缓冲）。

- **覆盖率门槛**：`services/privilegeGrantService.js`、`services/accessReviewService.js`、`controllers/privilegeController.js`、`constants/privilegeGrant.js` 在 `jest.config.js` 单独设阈值（取「实测 −5pt(分支) / −3pt(函数)」，向下取整），不并入 global 均值——这几个模块退化时的表现是安全结论错误，不是报错。同批拆出的 `services/privilegeGrantHooks.js`（两个外部钩子，未注册即抛）与 `services/privilegeGrantValidation.js`（`grantError` 与有效期/权限码归一的单一出口）也各带阈值，拆分的动因是 `max-lines` 棘轮（服务本体已越过 300 行），语义与导出面逐字不变。
- **Web 端入口**：`web-admin/src/views/PrivilegeGrantView.vue`（菜单 `/system/privilege-grants`，路由 `meta.permission = privilege:read`）——状态筛选（默认「待审批」）、复核汇总五计数、申请表单（权限码逗号/空格混排解析、有效期 1-168 小时本地校验）、签批/驳回/撤销三条决定链路；按钮按 `privilege:grant|approve` 门控（与后端 `checkPermission` 同码），高敏提交提示显式给出「还需几人签批」。用例 `web-admin/src/tests/views/privilegeGrantView.test.js`（34 例，分支覆盖率 90/90）。
- **未落地（如实申报）**：堡垒机/跳板机与 JIT 会话录屏（C-09 的另一半）尚未实现——「谁能拿到高敏码」已可控可追会过期，但「拿到之后在什么通道上操作」仍由操作系统与运维流程保证。

### 新增：部署面配置漂移检测（M-05）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 M-05 控制项实现。

- **脚本**：`scripts/config-drift-check.js`，把 compose 的容器安全标志（`read_only`/`cap_drop`/`security_opt`/`user`/`tmpfs`/`networks`/内存上限…）、Dockerfile 的 `USER` 与 `HEALTHCHECK`、nginx 模板的 TLS 与安全响应头、`.env.example` 的安全相关键**逐项摘要**（sha256 前 16 位），与 `deployment/config-drift-baseline.json` 对账。
- **输出纪律**：只打印条目名与 `ADDED/REMOVED/CHANGED`，**不打印取值**——配置模板里可能夹带密钥样例，回显会把基线本身变成泄露面。`--json` 供机器消费，`--update` 重写基线（须与变更同轮提交）。
- **退出码**：0 无漂移、1 有漂移、2 输入不可解析或基线缺失（宁可报 2 也不给空账面）。
- **边界（如实申报）**：检的是**仓库内**的配置面，即漂移被引入的地方；不读 `process.env`，因此不能替代「运行时配置与基线对账」（后者由启动期断言与 `config/validate.js` 负责）。
- **用例**：`src/tests/scripts/configDriftCheck.test.js`（5 例：抽面有效、无关项不入账且取值不落明文、改值/删项/加项各自被识别、仓库基线不撒谎、CLI 退出码与 `--json` 契约）。

### 新增：用户头像上传（2026-10-30）

> 依据 `deliverables/头像上传功能-计划报告-2026-10-30.md` 评审后的 v2 修订实现。

- **端点**：`PUT /api/auth/avatar`（本人上传/替换，JSON data URI）、`DELETE /api/auth/avatar`
  （本人移除，幂等）、`GET /api/avatars/:userId?v=<hash16>`（本人直通；他人需 `user:read`
  且通过用户数据范围校验，与 `GET /api/users/:id` 同一把尺）。
- **存储**：新集合 `UserAvatar`（`_id = userId`，1:1），图片二进制以 Base64 经 `encryptPii`
  v2（AAD 绑定 `{subjectId, field:'data'}`）加密落库；`data` 为 `select:false`，读取时解密后
  复核 magic bytes 与 SHA-256，防篡改/错配。不落磁盘卷（容器 `read_only: true`）。
- **校验**：仅 JPEG/PNG，原始上限 256 KB，16–1024 px 且 ≤1 MP；拒绝 APNG 与带 EXIF/文本
  元数据的图片（不做"服务端剥离"——剥离需解析全部段，直接拒绝边界更小）。
- **一致性**：上传/移除在事务内同时写 `UserAvatar` 与 `User.avatar`；`PUT /api/auth/profile`
  与 `PUT /api/users/:id` 的 `avatar: ''` 同事务删除记录，避免"指针清了、图还能拉"。
  删号/批量删/匿名化级联删除头像记录。
- **D3 收口**：资料更新只接受**服务端为目标用户生成**的 `/api/avatars/<id>?v=<hash16>`；
  外部 URL / 相对路径 / data URI 一律 400（data URI 会绕过上传校验、加密与尺寸限制）。
- **审计与限流**：新增 action `auth_avatar`（写）/ `avatar_view`（读路由派生，读默认豁免）；
  审计体对头像 data URI 打码为 `***`（窄键规则，不并进全局敏感键子串名单）。
  读路径独立限流桶：预认证 IP 600/15min、认证后用户 1200/15min；响应带
  `ETag` + `Cache-Control: private, no-cache` + `Vary: Cookie`，命中 `If-None-Match` 返回 304。
- **前端**：新增 `UserAvatar.vue`（失败回退首字母）与 `utils/avatarImage.js`
  （中心方形裁切 + 512×512 JPEG q0.85，超 400000 字符自动降质/降尺寸）；
  个人资料页提供更换/移除入口，顶栏、欢迎卡、用户列表统一改用该组件。
- **复核修复（同日）**：图片校验改为"结构解析到文件尾"——JPEG 必须扫描到 EOI 且
  EOI 为最后一个标记，PNG 必须存在 IEND 且 IEND 为最后一个 chunk（另要求至少一个
  `IDAT`）；EOI/IEND 之后夹带 HTML/ZIP/自定义数据一律拒绝，并补回归用例。
  `useravatars.data` 同时纳入 `scripts/migrate-pii-encryption.js` 的 `PII_TARGETS` 与
  `deployment/secret-rotation.md`、ADR-003 的 PII 清单——否则轮换 `AES_SECRET_KEY`
  后头像密文无法解密。头像读取响应另显式下发 `X-Content-Type-Options: nosniff` 与
  `Content-Security-Policy: default-src 'none'; sandbox`，即使直接导航到图片 URL
  也不会把 polyglot 响应渲染成可执行文档。
- **夹带面再收口（同日）**：段/chunk 判定由"黑名单"改为**白名单**——黑名单漏一个
  APPn/chunk 就是一条夹带通道。JPEG 只放行 APP0（标准 14 字节 JFIF，带缩略图即拒）、
  APP2（单段完整 ICC_PROFILE：序号/总数为 1、声明长度与实际一致、profile 含 `acsp`
  签名）、APP14（定长 12 字节 Adobe 头）、DQT/DHT/DAC/DRI/SOF/SOS；其余 APPn 一律
  `JPEG_UNSUPPORTED_SEGMENT`。
  PNG 只放行 IHDR/PLTE/IDAT/IEND 与 sRGB/gAMA/cHRM/pHYs/sBIT/bKGD/tRNS/acTL，且定长
  chunk 的长度必须精确，其余（iCCP/sPLT/hIST/私有 chunk）一律 `PNG_UNSUPPORTED_CHUNK`。
  Chromium canvas 与 System.Drawing 的真实编码产物（JPEG 带 ICC APP2、PNG 带
  sRGB/gAMA/pHYs）实测全部通过。同时收紧边界：空 `IDAT`、重复 `IHDR`、扫描数据为空
  的 JPEG 一律拒——否则会存下"结构自洽但解不开"的坏头像。
- **特殊情况收口（同日）**：白名单只挡"夹带"，挡不住"结构自洽但解不开"，补齐四处语义判据——
  ① PNG `IHDR` 的位深/色型必须落在规范表 11.1 的合法组合内，压缩法/滤波法必须为 0（否则
  `bitDepth=3`、`colorType=7`、`compression=99` 这类头能过白名单）；② `IDAT` 必须是真能解压的
  zlib 流，且解压字节数**恰好**等于声明尺寸的原始行字节数——只查结构会放过解压炸弹（实测
  203 KB 的 PNG 声明 16×16、`IDAT` 解出 200 MB）；`maxOutputLength` 让超限在解压过程中中断，
  另核对 `engine.bytesWritten` 与 `IDAT` 总长，堵住"流尾巴夹带未消费字节"；③ 隔行（Adam7）
  一律 `PNG_INTERLACE_UNSUPPORTED`——本仓合法流量全是 canvas 重编码产物（`interlace` 恒 0），
  而 Adam7 的行布局无法用一个定长字节数核对，放行等于给炸弹留后门；④ 调色板图必须有
  `PLTE` 且在 `IDAT` 之前、长度是 3 的倍数，JPEG `SOF` 的 `Nf` 必须 1–4 且与段长 `2+6+3Nf`
  自洽（`Nf=0` 的帧头解不出一个像素）。
  同轮把 PNG 结构解析拆到 `utils/pngStructure.js`、错误类型拆到 `utils/avatarImageError.js`，
  避免 `utils/avatarImage.js` 撞 `max-lines` 棘轮（注释净增 0 行）。
  实测最坏情况成本：1024×1024 PNG 7.2 ms/次、3.8 千段 JPEG 2.7 ms/次，256 KB 上限不变。
  - **结构自洽性再收口（同日）**：把“白名单里的每个结构件都必须真的自洽”补齐——
    PNG 逐 chunk 核对 CRC（否则整张图除了签名外每个字节都能被改写而无人发现），
    `IDAT` 之后除 `IEND` 不得再有任何 chunk，同一 chunk 不得重复（`PLTE`/`tRNS`/`bKGD`/
    `sBIT`/`sRGB`/`gAMA`/`cHRM`/`pHYs`/`acTL` 各限一次），变量长度 chunk 的长度按色型定值
    （`sBIT`/`bKGD`/`tRNS` 各有表，`tRNS` 对调色板图限 1–256），灰度图（`colorType` 0/4）
    不允许 `PLTE`；JPEG 的 `DQT`/`DHT`/`SOS` 长度必须被段内表结构整除（`Pq/Tq`+64|128、
    `Tc/Th`+16+符号和、`6+2Nf`）——不校验长度时这三种段就是“合法段名 + 任意字节”的通道。
    变异测试实测：PNG 逐字节翻位 3 种掩码 × 96 字节全数被拒，JPEG 197 字节全数被拒，
    2764 例变异（翻位/截断/插入）无一崩溃。
    真实编码器产物仍全通过：Chromium canvas 的 12 段 `IDAT` PNG、带 alpha 的 PNG、
    512×512 JPEG q0.85，以及 System.Drawing 的 RGB/ARGB/8 位调色板 PNG 与 JPEG。
    成本重测（含 CRC 与全部语义校验）：1024×1024 RGBA PNG 3.7 ms/次、21333 chunk 洪水
    1.1 ms/次、3711 段 DQT 洪水 1.8 ms/次、1039 段 `IDAT` 1.7 ms/次，256 KB 上限不变。

### 安全改造：账号救济 / 删除匿名化 / 异地备份 / 时钟基线（2026-10-30）

> 依据 `deliverables/安全改造待办-2026-10-30.md`。按用户明确要求，**不实施强制 MFA（P1-1）**：
> MFA 能力保持现状，管理员强制开关不启用，文档口径同步改为「能力具备、未强制」。

- **P1-2 账号救济（管理员轨）**：新增 `PUT /api/security/users/:userId/password/reset`，
  权限 `user:reset_password` + 二次验证 + 数据范围/层级/内置超管保护；生成一次性临时口令
  （≥12 位、四类字符），`tokenVersion++` + 吊销全部会话 + `mustChangePassword=true`，
  审计 `admin_reset_password`（临时口令不入审计/日志）。首次登录只放行改密/me/logout，
  改密完成清标记并审计 `password_force_changed`。内部系统无邮件通道，自助找回轨不做。
- **P1-3 删除改匿名化**：单删/批量删除改走 `userService.anonymizeById/anonymizeMany`，
  保留 `_id/username` 维持审计引用，抹除 realName/phone/email/avatar 并置 inactive，
  释放进行中指派，审计 `user_anonymized`；硬删除只保留建号回滚与测试夹具。
- **P1-4 异地备份**：`deployPolicy.checkBackupOffsite` 在 `DEPLOY_ENFORCE_OFFSITE=true`
  或 `NODE_ENV=production` 时要求 `BACKUP_OFFSITE_CMD/DIR`；`BACKUP_REQUIRE_OFFSITE=true`
  使备份脚本缺配置即失败。补 gpg 密钥轮换、逻辑恢复演练记录模板与生产部署清单。
- **P1-5 时钟基线**：新增 `scripts/check-clock-sync.js`（timedatectl/chrony，偏移阈值可配，
  判不了退出 2）、`deployment/systemd/chrony.conf.example` 与 `deployment/clock-sync.md`；
  self-hosted/SSH 部署在正式发布前调用，dry-run 跳过。
- **审计与前端**：新增 action `admin_reset_password`/`password_force_changed`/`user_anonymized`/
  `security_users_password_reset`，中英文标签同步；登录响应与 `/auth/me` 下发
  `mustChangePassword`，前端登录后直达个人资料页并由路由守卫收敛，用户删除提示改为
  「已注销并匿名化」。

### 新增：应用内一键蓝绿升级（2026-10-30）

> 目标：把「发版」从「SSH 上去敲命令」变成「应用里点一次按钮」，同时不让应用容器
> 拿到宿主的 docker / nginx 控制面——那条路等于把容器逃逸做成常驻攻击面。

- **契约：文件队列 + 双向重校验**。应用只往共享队列目录（`UPGRADE_QUEUE_DIR`，compose
  以 bind mount 与宿主共享）写一份 **HMAC 签名**的请求文件，宿主机上的
  `scripts/hotUpgradeAgent.js`（systemd timer）重新校验摘要与仓库白名单后才执行
  `scripts/hotUpgrade.js`。应用侧的校验只是输入错误的前置拒绝，不是安全边界本身。
- **镜像必须 digest 钉扎**：只接受 `registry/repo@sha256:<64hex>`，tag 一律拒绝
  （tag 可被覆盖，审计里记的版本会与线上跑的不是一回事）；仓库前缀须命中
  `HOT_UPGRADE_REGISTRY_ALLOWLIST`，**空白名单 = 全拒**（fail-closed，不是全放）。
- **新端点**：`GET /api/security/upgrade`（构建信息 + 就绪判据逐条原因 + 最近任务）、
  `GET /api/security/upgrade/jobs/{jobId}`、`POST /api/security/upgrade/requests`
  （路由层 `security:config` + 函数内唯一超管 `*:*` + 二次验证凭据 / `X-Reauth-Ticket`）。
  三条路径已进 `src/docs/generate.js` 与产物，`openapiSync` 双向对账。
- **审计先落盘再回 202**：`upgrade_triggered`（`riskLevel: high`，含 jobId / 镜像 / 来源 IP）
  走 `recordDurably`；失败路径不设 `skipGlobalAudit`，由全局审计记录这次尝试。
- **队列读写加固**：请求文件 `0600`（随机临时名 + `wx` 打开 + fsync + rename，
  避免可预测临时名被符号链接劫持）、只读侧单 fd 读取（`O_NOFOLLOW`）、心跳缺 `ready`
  或时钟回拨一律判未就绪。
- **前端**：`AboutView` 版本卡 + `UpgradeDialog`（镜像地址、二次验证、进度步骤），
  中英文案齐备；`utils/api.js` 增加对应调用。
- **运维面**：`deployment/systemd/{fsms-hot-upgrade-agent.service,.timer}` 与
  `hot-upgrade.env.example`；`deployment/hot-upgrade.md` 第 3 节补「应用内一键升级」流程；
  `deployment/secret-rotation.md` 把 `HMAC_SECRET` 的影响面从「五个消费点」更新为**六个**
  （第 6 个是升级请求签名：换钥后只让在途请求被拒，重发即可，既无迁移手段也不需要迁移）。
- **门禁同步登记**：`.env.example` 补 `UPGRADE_QUEUE_DIR`；`services/upgradeService.js`
  的 `TERMINAL_STATES/ACTIVE_STATES` 进单进程豁免表（静态字面量词表，无跨进程语义）；
  日期解析收口到 `utils/helpers.toEpochMs`（裸 `Date.parse` 只允许一处）；
  `controllers/securityController/upgrade.js#triggerUpgrade` 进可靠审计登记表；
  升级错误码改成逐码字面量发出（动态查表会让五个已注册的码退化成死码）。
- **默认关闭**：`UPGRADE_ENABLED=false` 时概览仍可读（按钮不可用并给出原因），
  POST 返回 `UPGRADE_DISABLED`。
- **对外命名**：应用内入口统一称「一键升级」（原「一键热升级」）——弹窗标题、不可用/白名单
  错误文案（中英）、接口兜底 message 与 OpenAPI 摘要同步去「热」字，与「蓝绿切换」的语义对齐。

### 加固：升级链路的第二轮逐行审计收口（2026-10-30）

> 依据多子代理逐行审计报告（部署/脚本/后端/前端/门禁五路）。这一轮**不新增能力**，
> 只把「升级看起来成功、实际没成」与「把权限收紧做成功能失效」两类形态从链路上消掉。

- **队列属主矩阵**（`docker/app-entrypoint.sh`）：应用只写 `requests/`、只读 `status/processing/`。
  原先一律 `chown nodejs` 让被攻陷的应用可以删 `processing/.agent.lock`（升级永久显示进行中）、
  伪造 `status/<id>` 为 `succeeded`（界面假成功、请求被丢弃）、清空 `rejected/`（验签失败留证消失）。
  现改为 `requests=nodejs:nodejs 0700`、`status/processing=root:nodejs 0750`、`rejected=root:root 0700`；
  顺序固定为「收回 root → chmod → 交出属主」（`cap_drop: ALL` 且不补 `FOWNER`，对已属 nodejs 的
  目录 chmod 必然 EPERM，而入口是 `set -eu`——第二次启动/app-green/一次性迁移容器都会因此起不来）。
  另拒绝对 `/`、`/etc` 等系统目录改属主，`find -xdev` 不跨文件系统、不跟随符号链接。
- **蓝绿互不踩**：`app-green` 显式 `AUDIT_WAL_PATH=/app/logs/audit-buffer.green.wal`——两色共用
  `app-logs` 卷时，按库名派生的 WAL 会被两个进程同时追加，而 WAL 的全部价值是崩溃重放，
  双写者让「谁写的、该不该重放」不可判定（重复插入 → 哈希链分叉）。
- **CI 的 hot 分支补 `--apply`**：此前直接调 `hotUpgrade.js` 而未加 `--apply`，脚本按设计走演练
  分支并**以 2 退出**——流水线会「成功打印了计划」，线上什么都没变。现两条模式（本地/SSH）
  都显式在 `--apply` 与 `--dry-run` 之间二选一。
- **布尔旗标严格解析**（`scripts/hotUpgradePolicy.js`）：`--apply=false` 此前被当成「出现过就是真」，
  模板里写 `--apply=${{ inputs.apply }}` 且值为 false 时会真的开始切流。现在只接受 true/false（含 1/0、yes/no），
  其他值报错而不是猜。
- **代理锁的 pid 复用**（`scripts/hotUpgradeQueue.js`）：锁新增 `/proc/<pid>/stat` 的启动时刻与 3h 锁龄上限，
  空锁文件/损坏锁/pid 被复用都能接管；此前只判 `kill(pid,0)`，一个恰好复用旧 pid 的无关进程会让按钮
  永远显示「另一个升级正在进行中」。
- **只读侧单 fd**：`readJsonFile` 改为 `openSync(O_NOFOLLOW)` + `fstat` + 从 fd 读——原先 `statSync` 后按路径
  `readFileSync` 是两次解析，应用对 `requests/` 可写时可换成符号链接，让 root 代理读到任意宿主文件。
- **写入与观测**：`status/processing` 文件 `0640`（属组＝队列目录属组，应用可读、other 不可读）；
  `hotUpgradeJob` 记录子进程 pid 失败时 `SIGTERM` 回收进程并如实报错（原先会留下无人跟踪的升级进程）；
  起备色补 `--no-build`（compose 里 app 段带 `build:`，否则会在部署机上重建当前源码，线上跑的就不是请求里的 digest）；
  观察期未通过**回滚成功后才**停新色（回滚失败分支不停，否则可能把仍在接流量的容器杀掉）。
- **监控**：`prometheus.yml` 同时抓 `app:3000` 与 `app-green:3000`；`BackendDown` 改为
  `sum(up{job="xf-app"}) == 0`——逐实例判会让平时根本没起的备色永久点亮告警，而永远在响的告警等于没有告警。
- **systemd 加固**：代理单元补 `NoNewPrivileges/Umask=0077/PrivateTmp/ProtectHome/ProtectSystem=full`
  与 `ReadWritePaths`；`hot-upgrade.env.example` 补 `MONGODB_URI_FILE`/`BACKUP_ENCRYPTION`/
  `BACKUP_GPG_RECIPIENT`——代理的环境**只来自该文件**，缺任一项时第一个升级请求都会停在备份步。
- **门禁同步**：`LAZY_SCC` 登记 `config/jwtRotation.js`（真实惰性环）、单进程豁免表登记
  `middleware/auth.js` 的 `PASSWORD_CHANGE_ALLOWED_PATHS`（静态只读 Set）；三处环境相关的用例判据收窄到
  「本子系统自己的那几条文案」（ACL 噪声另有专门用例钉住），而不是靠机器上有没有 `USERNAME`/`bash` 决定红绿。

### CI 修复：锁文件锚未重算 + 三处用例随实现漂移（2026-10-30）

> 现象：`CI` 从 `6415fd6` 起红，且**只红在第一个作业** `dependency-policy`——
> 后面 `test`/`e2e`/`e2e-browser`/`build` 全部 `needs: dependency-policy`，
> 一个闸失败就把整条流水线的可见性一起挡掉。本地逐闸复跑后发现：闸背后还压着
> 三处**与依赖无关**的红（`test` 作业一旦被放行就会立刻暴露），故一并修。

- **锁文件锚（`dependency-policy` 唯一的红）**：`6415fd6` 把 `vue-i18n` 从
  `9.14.5` 升到 `11.4.16`（v9/v10 已被上游标记 deprecated 并停止维护），
  `web-admin/package.json` 与 `package-lock.json` 都改了，但
  `deployment/lockfile-anchor.json` 没重算 ⇒ `LOCKFILE_ANCHOR_MISMATCH`。
  处理口径按锚文件自身的提示走：先人工复核锁文件 diff（仅 `vue-i18n` /
  `@intlify/*` 一族，`resolved` 全为 registry.npmjs.org、integrity 随版本同步变更，
  无夹带），再 `npm ci --dry-run` 确认锁文件与 package.json 自洽，最后
  `node scripts/check-lockfile-integrity.js --update`。**不是**回退依赖：
  v9 已停止维护，回退等于把 EOL 依赖留在发布基线上。
- **compose 告警配置链（`test`）**：`894f1de` 的 F-15 把 alertmanager 的配置挂载
  从「直接 bind mount 宿主文件」改成「一次性 `alertmanager-config-init` 复制进
  命名卷并 chown 65534，alertmanager 只读消费该卷」（宿主 0600 文件容器内 nobody
  读不到）。`alertingConfig.test.js` 与 `alertmanagerComposeGate.test.js` 仍断言
  旧的 bind mount 形状。改为钉新链条的三段——校验容器、初始化容器都取同一个
  `${ALERTMANAGER_CONFIG_PATH:-…}`，运行侧只消费 `alertmanager-config` 卷且
  `depends_on` 初始化容器 `service_completed_successfully`。「校验的是 A、跑的是 B」
  这条原始不变量原样保留，只是中间多了一跳。
- **单进程依赖清单（`test`）**：`6415fd6` 新增的 `controllers/ipListWriteGuards.js`
  带模块级 `Set`（`IP_LIST_WRITE_FIELDS`，写路径字段白名单），未进
  `SINGLE_PROCESS_DEPENDENCIES` 也未进豁免表。按既有口径补豁免条目（静态字面量
  词表、只读、无跨进程语义），与 `routes/wellKnownRoutes.js` 的 `CLIENT_ERROR_KINDS`
  同族——**不是**登记进清单：登记会让启动期对运维误报"多实例下这条会失效"。
- **NODE_ENV 未设置（`test`）**：`93519ae` 起 `validate.js` 对「`NODE_ENV` 键根本
  不存在」直接拒绝启动（缺失时无法区分"开发机裸跑"与"生产容器漏配"，按开发语义
  放行等于弱密钥/Host/Redis/TLS 四类校验一起静默跳过），README 部署清单与
  `.env.example` 已同口径。`nodeEnvGateFailsClosed.test.js` 仍把「未设置」放在
  「允许跳过生产校验」那张表里。改为单列一条：未设置 ⇒ 拒绝启动；同时保留
  `normalizeNodeEnv()` 对 `undefined` 仍返回 `development`（其他模块依赖这个归一值，
  改它会波及一圈无关判据）——两件事分开钉。
- **WS 握手用例夹具（`test`）**：`93519ae` 让握手期 IP 判定在「取不到客户端地址」
  时 fail-closed（`无法验证网络来源`），`#9` 又加了按来源 IP 的未认证连接准入表。
  两处夹具因此失真：`wsFlow.test.js` 的假 socket 有 `handshake` 但**没有**
  `address`，`tokenPurposeAndConsumers.test.js` 的假 socket 连 `handshake` 都没有
  ⇒ 认证分支一条都跑不到（表现为 8s 超时 / 断言拿到「无法验证网络来源」）。
  补 `address: '127.0.0.1'`；`wsFlow` 的假服务实例补
  `unauthConnectionsByIp = new Map()`（真实构造器在 `index.js:66` 初始化）；
  `tokenPurpose` 补桩 `models/IPBlacklist`（该套件没有真实 DB，不桩就会以
  「网络黑名单校验暂不可用」fail-closed）。被测判据一条没放松。

> **本机复跑的两处"红"不是 CI 红，未改代码**：`backupEncryptionContract` /
> `backupTransport` 在本机失败的原因是本会话工具链注入的 `rm` 垫片拒绝
> Windows 盘符路径（`[safe-delete][SAFE_DELETE_INVALID_PATH] embedded drive prefix`），
> 把 `safe-bin` 从 `PATH` 移出后同一脚本行为正确（半成品归档确实被删）。
> CI 是 ubuntu + 真 coreutils `rm`，不受影响。

---

### 修复（2026-10-28 · dev 代理覆盖上游 X-Forwarded-For，审计与限流只见内网地址）

> 现象：经外层反代/预览网关访问时，后端审计与限流记录的客户端 IP 恒为
> `127.0.0.1`/`::1`，真实地址丢失。

- 根因：`web-admin/vite.config.js` 的 dev 代理无条件用 `req.socket.remoteAddress`
  覆盖 `X-Forwarded-For`。外层代理已经把真实 IP 写进该头，而它连 Vite 的对端是回环
  地址，覆盖等于把真实地址抹掉。
- 修复：`/api`、`/client-errors`、`/socket.io/` 三个代理块统一改为「上游有 XFF 则
  原样透传（数组形态拼接），缺失才回落 socket 对端」。本地直连 dev server 的行为不变。
- 测试：新增 `web-admin/src/tests/bundling/devProxyForwardedFor.test.js`，对三个代理块
  分别钉住「透传 / 多值拼接 / 回落」三条契约。

---

### CI 修复：runner 内核误报导致 e2e-browser 起不来 Mongo（2026-10-28）

> 现象：`CI` 的 `e2e-browser` 在 **Start full stack** 步骤失败，后端日志是
> `connect ECONNREFUSED 127.0.0.1:27017`，看起来像服务没起来；`test`/`e2e` 全绿。
> 定位到真正原因不在本仓代码：

- **根因**：GitHub 自镜像 `20261018.339.1` 起把内核抬到 `7.0.0-1017-azure`，其
  `/proc/version_signature` 实为上游 **7.0.14**；而 MongoDB 8.0.x 只读 `uname -r`（得 `7.0.0`），
  误判进 SERVER-121912 的「6.19–7.0.13 不兼容区间」，启动即以 fatal `12257600` 退出。
  上游误报修在 SERVER-131779，**8.0.34 没有**（8.0.x 最新即 8.0.34，2026-10-13 发布）。
  旁证：同一次运行里 `e2e` 落在旧镜像 `20261012.334` 上，同一份 mongod 8.0.34 正常启动并通过。
  外部登记：`actions/runner-images#15005`（open，GitHub 工程师给出的临时变通即回 `ubuntu-22.04`）。
- **为什么换二进制绕不过**：把官方 tarball（sha256 与仓内锚一致）解开后，该 fatal 串在 `mongod`
  二进制内可直接检索到——闸是编进 mongod 的，不是 Docker 镜像特有的。故 `test`/`e2e` 的
  `MONGOMS_SYSTEM_BINARY` 路径同样会在新内核上失败，只是尚未落到新内核宿主机而已。
- **修法**：`test`/`e2e`/`e2e-browser` 三个用真实 mongod 的 job 钉 `runs-on: ubuntu-22.04`
  （其余 job 保持 `ubuntu-latest`）；`deployment/mongod-artifacts.json` 增补 `ubuntu2204` 条目
  （2404 包要求 glibc 2.39，22.04 的 2.35 跑不了），sha256 `8eef2a82…c7aced43` 取
  `downloads.mongodb.org/current.json` 官方值与自算字节哈希**逐字一致**的双锚。
  不动的部分：mongo 镜像仍钉 8.0.34 及其 digest（生产 compose 口径不变），三方对账闸不受影响。
- **回滚条件**：MongoDB 8.0.35 发布并完成 digest/sha256 对账，或 runner 内核进入 ≥7.0.14 区间。

---

### 审计第五轮复核：逐条回源码验证、修成立项、登记不成立与暂缓项（2026-10-26）

> 承接 `deliverables/audit-2026-10-26/audit-report.md`（复核基线 `4a1bdae` + 工作区）。
> 先把 P1/P2/P3 全部结论逐条回到当前源码与实跑结果复核，再只修验证成立的部分；
> 报告补第九节复核记录。**不修不存在的问题，也不沿用报告里的数字。**

| 项                          | 复核结论     | 处理                                                                                                                                                                                                                                                                                              |
| --------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1-1 工作区卫生             | 成立         | 删除 `.jest-*`/`.vitest-*` 日志、`.ci-repro.log`、`.tmp-probe.json` 与 4 个 `.lint-ratchet-selftest-*` 残骸；`.env` 的 `HMAC_SECRET` 19 → 43 字符（dev 文件、gitignored；本地既有审计 HMAC/二次验证票据随之不可验，重登即恢复）。`logs/`、`.mimosa/`、`CHANGELOG.md.bak` 是运行产物且已忽略，保留 |
| P2-1 假 performance 指标    | 成立         | 删除 `overview.performance` 三字段（无消费方且与 A-2「不可用≠零值」冲突），真实指标仍在 `/metrics`                                                                                                                                                                                                |
| P2-2 `data.data` 双层信封   | **部分成立** | 审计列表（游标/偏移两臂）与 `getRecentAlerts` 改用新增的 `ApiResponse.successWithMeta`（`data`/`meta` 平级），前端 `AuditLogView` 同步；`exportAuditLogs` 是流式 CSV，不经 `ApiResponse`，报告把它算进来不准确                                                                                    |
| P2-3 权限列表上限           | 成立         | `permissionRoutes` 的 `limit` 500 → 100                                                                                                                                                                                                                                                           |
| P2-4 authRoutes 错位注释    | 成立         | 删除两处错贴的 PERMISSION-EXEMPT 注释（`refresh` 在 `:325`）                                                                                                                                                                                                                                      |
| P2-6 设备统计无缓存         | 成立         | 新增 `services/deviceStatsService.js`：`scopeFilter` 序列化键 + 15s TTL + 单次 8 臂 `$facet`；7 条写路径统一 `invalidateDeviceStats`（代际防旧值写回 + `sharedCache` 跨实例广播）。`DeviceService` 只留委派，守住 max-lines 棘轮                                                                  |
| P3-3 wellKnown 未入 OpenAPI | **不成立**   | `openapiSync` 两条用例明文钉住「wellKnownRoutes 属于豁免面（不进 `openapi.json`，且豁免有据）」，是有测试保护的设计而非漏登记                                                                                                                                                                     |
| P2-5 / P3-1/2/4/5/6/8       | 暂缓         | warning 全在棘轮基线内、0 error；拆分与产品/运维决策按报告原路径排期                                                                                                                                                                                                                              |
| 锚点与密度同步              | 必做         | `DeviceService.js:445→deviceStatsService.js:82`、`auditQueryService.js:320→:314`、`statsCache.js:155/201→:159/:230`、`DeviceService` 计数 `:108/:502→:110/:444`；7 处引用注释与 2 个消费方断言同步；`statsCache`/`apiResponse` 注释压回密度基线（98→97、59→59）                                   |
| 验收                        | —            | 全量 `jest` **644/644 套件、7,956/7,956 例**；前端 `auditLogView` 44/44；`lint` 0 error/14 warn、`lint:ratchet`/`format:check`/`docs:check`（86 path / 105 operation）全绿；锚点两闸 28/28、`commentDensityRatchet` 5/5、路由契约 44/44                                                           |

---

### 审计第四轮：惰性环 4 → 1 个分量、台账单源化、注释治理落 ADR-011（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §15.2 如实登记的「A-1 剩余三个分量未做」，
> 并一并收口 **Q-3/T-6**（多份台账各自手抄实现清单）与 **Q-1**（生产注释混入变更史）。
> 报告补第 16 节。所有修复先复现红点再改，没有放宽任何断言。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A-1 惰性环清零   | 强连通分量 **4 → 1**、模块 **36 → 22**。新叶子：`middleware/userAuthCache.js`（用户缓存与失效广播，断 `auth ↔ tokenBlacklist`）、`middleware/dataScope.js`、`middleware/httpMethods.js`、`middleware/security/ipBlacklistStore.js`（封禁原语）、`middleware/security/earlyRejection.js`（早拒绝审计）、`services/alertTypes.js`、`services/alertDispatch.js`（告警链断环）。`models/User.js` 删除三个权限薄代理，调用方直接走 `userPermissionService`。`LAZY_SCC` 只剩 config/audit/metrics 22 模块，保留理由写在 `requireCycles` 头 |
| A-1 行为保持     | `addToBlacklist` 在两个封禁模块保留**调用时取属性**的薄包装（解构会在加载期固化绑定，测试就无法替换封禁结果）；F-160 的 `await addToBlacklist(` 文本门禁继续命中。6 个封禁/升级套件的注入点迁移到 `ipBlacklistStore`，是跟随唯一写入原语，不是放宽断言                                                                                                                                                                                                                                                                               |
| Q-3/T-6 台账单源 | 写方法名单收敛到 `middleware/httpMethods.js`（originCheck / security/auditLog / protocolCompliance / behaviorBaseline 四处不再各抄一份）；审计分类测试改为引用 `constants/audit.js` 的 `AUDIT_CATEGORIES`；Redis 降级失效清单改为从 `SINGLE_PROCESS_DEPENDENCIES` 过滤派生                                                                                                                                                                                                                                                           |
| Q-1 注释治理     | 新增 `docs/adr/ADR-011-注释治理-源码只保留当前约束.md`：源码只写当前约束与不明显的 Why，变更史归 CHANGELOG、权衡归 ADR、锚点优先符号。`securityHeaders.js` 整行注释 180 → **102**（生产注释 22,504 → **22,426** 行，−78）                                                                                                                                                                                                                                                                                                            |
| Q-1 密度棘轮     | 新增 `scripts/commentDensity.js` + `scripts/commentDensity.baseline.json`（258 文件 / 22,426 注释 / 34,798 代码）与 `src/tests/ci/commentDensityRatchet.test.js`（5 例：统计面自证、只降不升、新文件密度 ≤ 30%、反向对照、总量对账）。`--update-baseline` 遇回归直接拒绝                                                                                                                                                                                                                                                             |
| 棘轮实测         | A-1 给两个封禁模块各加 1 行说明后，棘轮立即报 2 处回归并拒绝收紧基线；按 Q-1 口径把 3 行历史压成 2 行后才写回基线——证明它不是「写完就绿」的摆设                                                                                                                                                                                                                                                                                                                                                                                      |
| 测试重定向       | `auditScopeFilterDeptCache` / `edgeCases` / `auditQueryOperationCatch` 的桩从 `middleware/rbac` 改到 `middleware/dataScope`（后者才是 `auditScopeFilter` 的叶子依赖；旧桩失效时真实查询打未连接 Mongo，表现为 10s 超时且日志为空）；`websocketRedisAdapter` 的 `sharedCache` 桩补 `onInvalidate`（`userPermissionService` 在加载期注册）；`sharedCacheDegradationLog` 改为派生清单（手抄版已漂移成 `middleware/auth.js`）；`reportPiiExportStepUp` 的审计断言改为轮询到真实落库（全量并发下响应先回、行尚未可见）                    |
| 验收             | 全量 `jest` **643/643 套件、7,950/7,950 例全绿**；`requireCycles` 6/6、`commentDensityRatchet` 5/5、封禁链 57 例、定向回归 179 例全绿；`npm run lint` / `lint:ratchet` 0 error（14 条既有 warning 未超基线）、`docs:check`（86 path / 105 operation）与 `format:check` 一致                                                                                                                                                                                                                                                          |

---

### 审计剩余项收口：事务拓扑 fail-closed、导出并发闸、日志 PII 掩码、运行指标补齐（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §14.5 的"仍未处置"清单。
> 本轮把 `P-1`/`P-2`/`O-1`/`O-2`/`O-3`/`T-3`/`T-4` 做掉，`A-1` 解掉一个强连通分量
> （40 → 36 模块），剩余三个分量属需改所有权的重构，**只登记不改结构**（报告 §15.2）。

| 项                       | 内容                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-1 事务拓扑 fail-closed | 生产语义下探测到 `standalone`（多集合写非原子、失败留残骸）⇒ `/readyz` 判 503（`checks.topology=transactions_degraded`），**不阻断启动**。判据落在 `utils/transaction.js` 的 `transactionReadinessBlocker()`，与既有的多实例闸合并成单一 `topologyBlocker`，同时命中时**多实例优先**（它同时影响审计链与限流计数，且修法与事务拓扑无关）                                      |
| P-2 导出并发闸           | 新增 `services/exportConcurrency.js`：上限 2 / 有界队列 8 / 排队超时 30s，全部可经 `EXPORT_MAX_CONCURRENCY`、`EXPORT_MAX_QUEUE`、`EXPORT_QUEUE_TIMEOUT_MS` 调整并在越界时**钳制 + 一次性告警**。队列满或超时 → 429 `EXPORT_BUSY` + `Retry-After`。释放幂等、槽位**移交**给 waiter（不"先减再加"，避免空窗被第三个请求插队）                                                   |
| O-1 日志 PII 集中掩码    | 新增 `utils/logPiiMask.js`，接在 `logger.sanitizeLogInfo` 末尾（清洗 → 截断 → 掩码）。判定顺序 **email → 身份证 → 手机号**（身份证必须先于手机号，否则 18 位号码会被手机号正则切碎）；键名用闭合集 + 后缀判定，**刻意不含 `token`** 后缀以免误伤 `tokenVersion`；`requestId`/`userId`/`socketId` 作为结构性标识不掩。`LOG_PII_MASK=false` 可关，关闭时在生产语义下落一条 warn |
| O-2 运行指标补齐         | 新增 `export_inflight`、`export_queued`、`export_rejected_total{reason}`、`ws_connections`、`ws_inbound_throttled_total`、`ws_inbound_disconnects_total`。WS 连接数用**拉取式** `registerWsConnectionSource`（4 处增删点任一漏推都会让 gauge 长期偏高，拉取式免掉这个失效面）；文本与 JSON 快照两通道同源                                                                     |
| O-3 tracing 适用边界     | 新增 `docs/adr/ADR-010-不引入分布式追踪的适用边界.md`：把 `requestId` 能覆盖什么、跨进程边界为何断在这里、什么条件下该重新评估，写成可证伪的判据而不是"暂时不做"                                                                                                                                                                                                              |
| A-1 惰性环（部分）       | 抽出零 require 叶子 `src/config/envSemantics.js`（环境别名/生产语义判据），`config/validate.js` 改为 re-export。实测强连通分量 40 → **36** 模块，`requireCycles` 的 `LAZY_SCC[0]` 26 → **22**                                                                                                                                                                                 |
| T-3 路由分支补测         | 新增 `routes/routeGuardBranches.test.js` 9 例：strict 档两条守卫（明文注册被拒、enc+明文并存被拒）与改密接口、巡检时间窗倒置、`POST /reports/export/pii` 类型白名单、创建用户口令 64 字符上限，均带反向对照                                                                                                                                                                   |
| T-4 sharedCache 故障注入 | 41 → **47** 例，覆盖三类"总闸式注入看不见"的形态：单条命令失败（`GETDEL` 抛错走 get→del 降级，两步必须落在同一份内存回退上）、`DECR` 回收路径（真实现此前零覆盖）、连接级故障的**日志节流**（未就绪期的重试风暴不得刷 error 日志）。三处逐一做变异，确认变红后还原                                                                                                            |

---

### 七维审计复核：把「报告结论」逐条回源码验证，再修真正成立的那几条（2026-10-25）

> `deliverables/audit-2026-10-25/audit-report.md` 的基线是 `01e08f7`。复核时 HEAD 已是
> `170467c`，**报告里的大部分数字已经过期**（380/109 个文件、28 套件 56 用例红、19 条环）。
> 本轮先把每条结论回到当前源码与实跑结果上验证，再只修验证成立的部分；报告已就地打叉
> 并补第 13 节复核记录。**不修不存在的问题，也不沿用别人的数字。**

| 项                                          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-4 压测脚本（修）                          | `scripts/load-test.js` 仍在读 `r.body.data.token`，而登录早已只下发 httpOnly Cookie（I-01）⇒ 登录步必然抛错，E/D 两相**从未真正执行过**。改为从 `Set-Cookie` 取 `access_token` 显式回放（`loadTestEngine` 增加 `cookie` 通道，与 k6 脚本同口径）。**实跑证据**：`npm run test:load` 8 通过 0 失败，B/C/E/D/D+ 全绿，基线已落 `logs/load-baseline.json`——这是本仓第一份可信的压测结果                                                                                                                                                                                                                                                                                                    |
| 压测 D 相与新封禁策略冲突（修，报告未发现） | #21 之后 IP 封禁要求「同一 IP 失败过 ≥2 个不同账号」，而脚本只打一个用户名 ⇒ 即使取到凭据也永远等不到 403。改为两个一次性靶用户交替失败，并显式断言「401 覆盖 ≥2 个账号」。实跑日志确认 `distinctAccounts:2, ipBanApplied:true`                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| A-2 就绪闸（修，已在工作区）                | 多实例且无分布式审计锁时 `/readyz` 判 503（`checks.topology`），不再只打日志；`constants/runtime.js` 把重复的 Redis 就绪探测抽成 `sharedCacheReady()` 一处                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| A-1 惰性环（登记，不是消除）                | 报告写的「19 条」在任何枚举口径下都复现不出来。实测：**4 个强连通分量 / 40 个模块 / 122 条简单环**（长度 ≤9）。新增 `requireCycles` 用例按**分量**逐条登记，新增或消失都会红——分量是与遍历顺序无关的不变量，条数不是                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| T-1 MFA（补测）                             | `mfaController` 分支 64.58% → **87.5%**，函数覆盖 80% → **100%**（补 `getMfaStatus` 三例：余量如实、已关闭为 0、用户不存在不抛）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| T-2 二次验证（补测）                        | `securityController/reauth.js` 分支 50% → **100%**：补「令牌无 sid 时按未绑定会话签发，且不认任何具体会话」                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 锚点台账（同步）                            | A-2 改动使 `app.js` 行号整体后移，7 处 `LIVE` 登记与 4 个文件里的引用注释逐条改到新行号（`:205→:206`、`:249→:250`、`:487→:500`、`:546→:559`、`:550→:563`、`435-457→435-479`、`460→:473`），手册 `:297→:302` ；同日 `src/app.js` 的 `recordReadyz` 判据由 prettier 展开的九行嵌套三元收成 `?.` + `??` 单行形态（`format:check` 原本就在这个文件上红），行号再迁 3 行，登记同步到 `:462/:476/:503/:562/:566` 与 `435-482`；顺带发现 `queryLimit.test.js` 引用的 `app.js:536` 本就失实（真实落点是 `:592` 的 `query parser`），一并改对                                                                                                                                                    |
| 文档对账（修判据）                          | `documentationDrift` 的 bash 续行断言在 CRLF 检出下必然假红（同一份文档 Windows 红、CI 绿）。改在 `read()` 入口统一行尾——行尾是检出形态，不是内容事实                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 指标契约（同步）                            | `runtimeMetricsCoverage` 的 `/readyz` 判定正则绑定死了旧的三元表达式形状，A-2 加一档拓扑阻断即假红。改为钉三件语义（`ready ? 'ok'` / `mongo.ok ? redis.reason` / `topologyBlocker.reason`），并保留可失败反证                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 信号用例（修竞速）                          | `imageDigestGate` 的 SIGTERM 用例写死「睡 1 秒再发信号」，而 Windows/MSYS 起一个 sh+替身要 2–3 秒 ⇒ 替身日志为空、被判成"脚本没被叫醒"。改为**等替身留下第一行日志再发信号**（判据更严，不再依赖机器速度）                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 随机顺序 worker 崩溃（修，CI 实证）         | CI 的 `Test order independence (randomized)` 在 `170467c` 上是红的（`test (26.x)` 失败、22/24 被 fail-fast 取消），红点是 `appTrustProxyAndReadyzGuards` 的 `Jest worker encountered 4 child process exceptions`。根因不在断言：`auditLog` 用 `setImmediate` 异步落库，而回调体里才惰性 require `utils/fingerprint`；文件跑完、Jest 拆环境后回调才被调度，require 拿到 `undefined` ⇒ `TypeError: Cannot destructure property 'computeFingerprint'` 抛在测试框架之外，**直接崩 worker**（同文件按默认顺序却全绿，是典型的顺序耦合指纹）。修法：该套件 `afterAll` 放完一个 tick；修复后按三个 seed 各跑两次该文件 6/6 绿，再按 CI 口径跑全量三 seed，`appTrustProxy` 不再出现 worker 崩溃 |
| 测试树纯净性（入库）                        | 3 个新增用例（T-1/T-2/T-5 与 P-3 降级 TTL）与 `scripts/check-openapi-drift.js` 此前未跟踪，`testTreePurity` 因此红；已入库                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| D-1 OpenAPI 门禁（修，已在工作区）          | 新增 `npm run docs:check` 并在 CI 阻断；反证过：给生成器注入一条 path 后比较必然为 false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

### 告警抑制规则移除、nginx 显式拒绝 `/readyz`、Node 运行时进 CI 矩阵、5 条"假绿"测试逐条复核（2026-10-24）

> 审计第二批 6 项。其中 **2 项经复核不成立**（compose app 的 healthcheck、两个"假绿"测试），
> 记录在下方表格的对应行——不修一个不存在的问题，与修一个真问题同等重要。

| 项                            | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 告警抑制规则（移除）          | `alertmanager.yml` 原为「任何 critical 抑制同实例任何 warning，`equal:['instance']`」，理由写的是「BackendDown 时 HighP95Latency 必然伴随」。复核后整条移除，三条理由写进文件：①该理由**事实错误**——目标停止导出指标后 `rate()` 无样本，延迟告警根本不会触发；②即便成立，`equal:['instance']` 也匹配不到 `ReadinessProbeMissing` 的 `absent()` 分支（`absent()` 只回填选择器里的 `job`），而那正是"后端真挂了"时唯一会亮的伴随告警；③若真能生效，`AuditRecordsDropped`(critical) 会压掉同实例 `DiskSpaceLow`(warning)——把**根因**信号静默掉。同时留了新增抑制的三条门槛（alertname 精确 / target 是 source 的纯后果 / equal 标签两侧必然存在）                                                                          |
| 告警标签（修）                | `alert-rules.yml` 的 `HighErrorRate`、`SecurityAlertBurst` 由 bare `sum(...)` 改为 `sum by (instance)`。理由不是"为了让抑制能匹配"（那条规则已移除），而是多实例部署下 bare `sum` 会把全部标签丢掉：告警分不清哪台机器出错、面板无法按实例下钻、`{{ $labels.instance }}` 渲染成空串。单实例环境里这个缺陷"看起来完全正常"，所以只能靠契约测试钉住                                                                                                                                                                                                                                                                                                                                                                       |
| nginx `/readyz`（修）         | `deployment/nginx.conf.example` 此前只有注释「/readyz 刻意不对外」，配置上无任何对应指令 ⇒ 落进 `location /` 的 `try_files` 返回 **200 + index.html**。外部拨测配了这个地址会**恒判健康**（它探的是 nginx 能否返回 HTML，不是 Mongo 可不可达）。新增 `location = /readyz { return 404; }`：精确匹配、不反代、用 404 而非 403（403 等于确认"该路径存在且被保护"）                                                                                                                                                                                                                                                                                                                                                        |
| compose healthcheck（不成立） | `docker-compose.yml` 的 app 服务确实没有 `healthcheck`，但**不是缺陷**：健康检查来自镜像（`Dockerfile:201` 的 `HEALTHCHECK --interval=30s`），Compose 在服务未声明时原样继承；mongo/redis 要在 compose 里写，是因为它们的官方镜像不带。**反过来补一条是有害的**——compose 侧手写的通常只探 `/health`，会整体顶掉镜像侧"并行探 `/readyz` + `/health`、退出码只取 health"的口径。已补契约测试钉住该形态，compose 该块内写明不要补的理由                                                                                                                                                                                                                                                                                    |
| Node 运行时（修）             | 生产镜像 `node:26.12.0-alpine`，CI 矩阵只有 `22.x/24.x` ⇒ **实际发布到生产的运行时从未被任何 CI 用例执行过**。矩阵加 `26.x`（`[22.x, 24.x, 26.x]`，分别对应 `engines` 下界 / 当前 LTS / 发布基线），并新增 `nodeRuntimeMatrixParity.test.js` 把"镜像主版本 ∈ 矩阵、三处 FROM 一致、`engines` 下界 ∈ 矩阵"钉成闸门。选加矩阵而非降镜像版本：后者要回退一次四天前做过三源核验的升级，前者只增加验证、不改生产行为                                                                                                                                                                                                                                                                                                         |
| 前端 PII（修）                | `web-admin` 的 `currentUser` 落 localStorage 时改为白名单投影（`userId`/`id`/`_id`/`username`/`roles`），不再写入 `email`/`realName`/`phone` 等 PII。httpOnly cookie 的收益此前被明文 PII 抵消。新增 `authPersistenceNoPii.test.js` 6 例：白名单闭合性、登录与 `/auth/me` 两条路径不落 PII、内存态仍保留完整字段、刷新后身份骨架可用、历史脏数据被覆盖                                                                                                                                                                                                                                                                                                                                                                  |
| 5 条"假绿"测试                | 3 条成立并已修（见下），2 条不成立。①`authMiddlewareFailClosedGuards`：三条 `not.toThrow()` 换成可观察后果（库里改 inactive → 失效后必须 401），**变异复测**从"11 例全绿"变为"1 例红"；②`User.test.js`：从"字段存在"改为按**选项值**断言（10 个凭证字段 `select:false`、西里尔同形字 `аdmin` 必须被拒、72 **字节**边界、`status.enum` 与 `USER_STATUS` 同源、`username_ci` 的 collation）；③`mfaReplayGuardMax`：补"先认领再写库"的顺序断言（原断言对换序完全免疫）。**不成立**的 2 条：`mfaControllerOrchestration` 的认领失败分支已在 `mfaReplayGuardMax:118` 覆盖；`securityConfigHandlers` 的读回一致已由 `systemConfigBooleanContract.test.js`（真实 Mongo）覆盖——两处都在文件头写明了分工，避免同一结论被再次提出 |
| 契约测试                      | 新增 `composeAppHealthcheck.test.js`（5 例）、`nodeRuntimeMatrixParity.test.js`（5 例）、`authPersistenceNoPii.test.js`（6 例）；`nginxProxyContract` +1 例、`alertingConfig` +6 例。三处变异实测：`return 404`→`200` 变红、`sum by (instance)`→bare `sum(` 红 2 例、给 app 补 healthcheck 变红 1 例                                                                                                                                                                                                                                                                                                                                                                                                                    |

### WS 绕过探针改为两个单违规场景，并要求拒绝理由可归因（2026-10-24）

> 审计 P2：`scripts/audit-probes/ws-session-bypass.cjs` 只用一个令牌，**同时**带
> 「已吊销会话」与「非白名单 IP」两条违规，判据是"收到任何 `auth-error` 就算拒绝"。
> 于是它只证明了**至少一条**控制在生效：把 `sid` 校验删掉、只留 IP 校验，探针照样
> `exit 0` 报"P0-2 修复在位"。对一个有两条独立控制项的漏洞，"至少一条"不是证据。
> 另外 HTTP 侧只 `console.log` 状态码、从不校验，一个 500 或"因别的原因 401"也会被
> 当成有效对照。

| 项            | 内容                                                                                                                                                                                                                                         |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 场景拆分      | 拆成 `session_revoked`（会话已吊销 + IP 不限制）与 `ip_not_allowed`（会话正常 + IP 不在白名单），每个场景只带一条违规。两个用户、两个会话、两个令牌，`allowedIPs` 与 `sessionStatus` 互斥地只坏一个                                          |
| 理由归因      | `decideVerdict` 新增 `expected` 参数：必须收到 `auth-error` **且文案匹配本场景那条控制**才判 `rejected`。不匹配、或调用方未声明期望 → `inconclusive`（exit 2），不再算通过。帧里没有错误码，文案是唯一通道，故文案改动会让探针变红而不是变绿 |
| HTTP 前置对照 | 改为断言 `status + errorCode`（`401/DEVICE_SESSION_REVOKED`、`403/AUTH_IP_RANGE_DENIED`）。不符即判 `inconclusive`：同一令牌在 HTTP 侧不是因本场景那条规则被拒时，WS 侧的"被拒"无法归因                                                      |
| 服务端观察    | 不再取 `[...clients.values()][0]`（多场景同进程时会拿到上一场景的残留或未认证占位条目），改为按**本场景 userId** 精确匹配；第 5 步同时打印实际收到的下行帧，让证据可见                                                                       |
| 体积          | `makeClients` 的 get/post 合并为一个 `send(method, path, body)`，抵消新增逻辑，维持 `max-lines` 300 以内                                                                                                                                     |
| 测试          | `src/tests/wsProbeVerdict.test.js` 6 例 → 9 例：新增「理由不匹配 ⇒ 不可判定」「两场景理由互不通用（互为反例）」「未声明期望理由 ⇒ 不可判定」，并钉住场景表仍是两个单违规场景                                                                 |
| 可证伪性      | 实测三组：① 两条控制都摘 → `bypass,bypass exit=1`；② **只摘 IP 校验** → `rejected,bypass exit=1`（旧判据在这种情形下会给 exit 0）；③ 恢复后 → `rejected,rejected exit=0`，两场景各自拿到自己的 `auth-error` 帧                               |

### MFA 关闭与恢复码重生成改为条件写（CAS）（2026-10-24）

> 审计 P2：`mfaController.js` 四个状态变更写点里，`mfaEnroll`（:174）与 `mfaEnable`（:273）
> 已是条件写，注释还写着「下发即生效，不得被并发请求静默回收」；而
> `regenerateRecoveryCodes`（:104）与 `mfaDisable`（:368）仍是 `findByIdAndUpdate(_id)`
> **无条件覆盖**。同一份文件里同一条不变量，修了两处漏了两处。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 重生成 CAS | 过滤条件改为 `{_id, mfaEnabled:true, 旧码组全等}`。两次并发重生成携带**相邻窗口**的不同码时两次 `claimTotpWindow` 都会成功（窗口不同不算重放），后到者原会顶掉先到者刚下发的 10 张——调用方已抄走的那组全部作废，而两个响应都宣称"已生成"。空数组分支用 `$in: [[], null]` 覆盖"字段缺失"的历史文档（Mongoose 读时补 `default:[]`，库里没有该字段，直接写 `[]` 会永不命中 ⇒ 这类用户永久 409） |
| 关闭 CAS   | 过滤条件改为 `{_id, mfaEnabled:true, **本次验证过的 mfaSecret**}`。验证是对 `user.mfaSecret` 解密后做的；该字段被并发 enroll/enable 换掉后，无条件写仍会 `mfaEnabled:false + mfaSecret:''`，把本次从未证明过控制权的**新登记**一起清掉，审计还记成"用户关闭 MFA"                                                                                                                             |
| 落空归因   | 两处 CAS 落空后重读一次：已关 → `MFA_NOT_ENABLED`（不再记第二条"成功关闭"审计）、码组被换 → `USER_STATE_CONFLICT`、无 MFA → `MFA_NOT_ENABLED_NO_CODES`。**落空时绝不返回本次生成的码**——它们从未生效                                                                                                                                                                                         |
| 分层       | `mfaDisable` 的第二因子判定（TOTP 优先 / 恢复码兜底）移入 `mfaService.verifyDisableFactor`：这是"什么算验证通过"的领域判定，controller 只该决定"通过后写什么、失败回什么码"。顺带把控制器压回 `max-lines` 300 以内                                                                                                                                                                           |
| 测试       | 新增 `src/tests/controllers/mfaWriteCasConcurrency.test.js`（4 例，**真实 Mongo**，用闸门制造确定性交错而非 sleep）：① 并发重生成恰好一次 200，且成功响应下发的 10 张码**逐张**能对上库内摘要；② 关闭与新登记并发时旧密钥的验证不得清掉新登记；③ 缺 `mfaRecoveryCodes` 字段的历史文档仍可重生成；④ 无并发时两端点照常成功（CAS 不得把正当用户挡在门外）                                      |
| 可证伪性   | 已做变异验证：把两处过滤条件临时改回 `{_id}` 后，用例 ①② 立即变红（实测 `Expected length: 1 / Received length: 2`，两份响应各带一组不同的 10 张码），用例 ③④ 保持绿 —— 说明断言钉的是 CAS 本身，不是环境                                                                                                                                                                                     |

### 迁移脚本参数严格化，且不再在 require 时连库（2026-10-21）

> 审计 P2：`scripts/migrate-pii-encryption.js` 用五个独立 `if` 解析开关，未知参数一律当没看见。
> `--keys-onl`（少一个字母）不会报错，`keysOnly` 保持 false ⇒ 退化为**默认全量模式**
> （加密列 + 回填检索键 + 升级 v1），而操作者以为只补键。同一文件还在模块顶层无条件
> `main()`：任何 `require()` 都会立刻连库并扫描改写 PII。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 参数严格化 | 新增 `scripts/cliFlagPolicy.js`（本仓第四份「开关白名单」实现，抽出来共用）：`parseFlags(argv, allowed)` 把白名单外 token 全部收进 `errors`；建议用**编辑距离 ≤ 2**（全等抹平法对"少一个字母"永不命中，而那正是最危险的误输）。`migrate-pii-encryption.parseArgs(argv)` 返回 `{args, errors}`，`main()` 在**任何副作用之前**以退出码 2 拒绝 |
| 顶层执行   | `main()` 改为 `if (require.main === module)`；`--rotate` 的密钥快照本就在 `main()` 内有等价语句，删掉顶层重复。`parseArgs` / `MODE_FLAGS` / `PII_TARGETS` 导出供测试                                                                                                                                                                        |
| 文档闸     | `runbookSecretSource.test.js` 的 `EXTRA_SECRETS` 补 `run-rollback-drill.js: ['AES_SECRET_KEY']`——快照加密后缺密钥即 exit 2，手册 cron 必须自带来源，否则预发演练静默失败                                                                                                                                                                    |
| 测试       | `src/tests/deploy/cliArgStrictness.test.js` 增用例 19-23（合法全给不误伤 / 拼错必须报错且不猜真 / 位置参数拒绝 / 子进程实测退出码 2 且不连库 / `require` 不触发 `main`）；同时把 `generate-secrets` 的密钥清单钉数补上 `mongo_keyfile`（并行改动新增，钉数按设计要求显式确认）                                                              |

### 举报对话框改为可搜索对象选择器（2026-10-21）

> 缺陷（可用性）：举报对话框把「对象 ID」摆给用户填 24 位 ObjectId，而一线人员拿不到该值
> —— 它只出现在接口响应里，界面上从不显示。记录型举报（用户/设备/报警记录）实际不可用。

| 项       | 内容                                                                                                                                                                                                                                                                     |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 前端控件 | `ReportDialog.vue` 的记录型目标由 ID 输入框改为远程搜索下拉：界面只出现名称/编号，`targetId` 作为选中值随载荷上行、用户不可见。输入防抖 300ms（每次输入只落一条审计）、请求序号防「后发先至」覆盖、选中项在候选刷新后仍保留标签                                          |
| 新端点   | `GET /api/security/report-targets?type=&keyword=`：免权限码（举报对全员开放），候选集按**举报人数据范围**过滤，每类上限 20 条；投影不含 phone/email、报警描述、上报人姓名                                                                                                |
| 同判据   | 新增 `rbac.buildRecordScopeFilter`，与核验侧的 `isRecordInScope` **逐臂同值**（含「本人 `_id` 短路」、department 缺失仍放行本人、`none` 一律 deny）。`buildDataScopeFilter` 在这两处边界上并不等价——直接复用它会出现「下拉里选不到自己」或「选得到却提交 403」           |
| 限流     | 候选查询消耗 `authenticate` 内的账号级 userLimiter（200/15min），与举报提交的独立 20 次写配额分开：搜索不会吃掉提交配额（否则 429 文案会指向「提交过于频繁」，根因不可见）                                                                                               |
| 文档     | `src/docs/generate.js` 补 `/api/security/report-targets` 并重生成产物；端点经 `securityRoutes` 直接注册（不走 `router.use` 子挂载——openapiSync 的采集对子挂载是盲区，塞进去等于绕过文档门禁）                                                                            |
| 测试     | 新增 `src/tests/security/reportTargetCandidates.test.js`（16 例：免权限码可达 / 范围一致性 / **候选与提交核验同值** / 最小投影 / 参数边界 / 20 条上限与独立配额）；`web-admin/src/tests/components/reportDialog.test.js` 重写为 13 例，含「界面上不出现对象 ID」回归锚点 |

### 审计 WAL 裁剪按持久化承诺分级 + 回滚演练备份加密（2026-10-21）

> 按 `deliverables/七维审计终稿-核验版-2026-10-21.md` 的两项 P1 整改。
> 旧结论「outbox 先落 WAL 名不副实」已在工作树中修复（`auditOutbox.js` 已 `await appendLineDurable` 并 fsync），
> 但**裁剪侧**仍会把这些已 fsync 的行按位置丢出主 WAL，本节点修的是这一半。

| 项           | 内容                                                                                                                                                                                                                                                                                                                                                                    |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WAL 裁剪分级 | `auditOutbox.js` 写出的行带 `__walDurable`；`auditWalCap.enforceWalLimit` 改为**普通行优先丢、durable 行默认不丢**。普通行不足时记 `walDurableTrimRefusals` 并停手（WAL 继续超限，这是有意取舍），只有显式 `AUDIT_WAL_ALLOW_DURABLE_TRIM=true` 才裁 durable 并计 `walDurableDropped`。理由：`.discarded` 永不回灌，按位置裁剪等于把「已回成功」改成「落盘但永久不入库」 |
| 重放剥离     | `auditBufferWal.stampReplaySeqs` 在交给缓冲前删除 `__walDurable`（保留 `__walSeq`），避免 WAL 记账字段进入 Mongo 文档；回写补号行在删除**之前**序列化，否则会丢标记                                                                                                                                                                                                     |
| 面板投影     | `securityController/overview.js` 的 `auditLoss` 新增两项；`AuditLogView.vue` 的 `auditLossTotal` 计入 `walDurableDropped`（承诺缺失），`walDurableTrimRefusals` 只进明细（此刻尚未丢记录，处置方向是扩容而非取证）                                                                                                                                                      |
| 演练备份加密 | `run-rollback-drill.js` 由明文 gzip 改为 gzip 后 AES-256-GCM（魔数 `FSMSBK1`，密钥由 `AES_SECRET_KEY` 派生），缺密钥直接退出、不退回明文；`.discarded` 同族：`restoreCollection` 按魔数识别，改造前的明文快照仍可回灌但显式告警                                                                                                                                         |
| 可观测性     | `metricsAuditDrops` 新增 reason `wal_durable_lost`（由 `auditWalCap` 在显式开关裁掉 durable 行时上报，自动被既有 `AuditRecordsDropped` critical 规则覆盖）；新增计数器 `audit_wal_durable_trim_refusals_total` 与告警 `AuditWalTrimRefused`（warning）——「拒绝裁剪」意味着 WAL 无界增长，必须在写满磁盘前可见                                                           |
| 文档对齐     | `deployment/backup-encryption.md` 删除「单人拿不到完整链」这一与设计矛盾的断言，改为「默认无口令私钥下该控制不成立」并给出两条可兑现路径（口令分离 / 人员分离）；`deployment/rollback-drill.md` 的 cron 示例补 `AES_SECRET_KEY_FILE`，并新增第 5 条纪律（缺密钥退出码 2 是 fail-closed，不是配置错误）                                                                  |
| 测试         | 新增 `src/tests/services/auditWalDurableTrim.test.js`（5 例：durable 全留 / 拒绝裁剪 / 显式放开 / 全 durable 不动文件 / 重放剥字段，含两条 Prometheus 上报断言）；`rollbackDrillRestoreVerification.test.js` 增「归档必须带 FSMSBK1 魔数且不得同时留下明文 .ndjson.gz」与 `manifest.encrypted` 断言；`auditDropMetrics.test.js` 的 reason 闭合集合断言扩到五项          |

### 搜索面板新增可见关闭按钮、隐藏 ESC 提示（2026-10-21）

> 全屏态下 ESC 先被浏览器用于退出全屏（`keydown` 的 `preventDefault` 拦不住），把 ESC 当关闭卖点展示会误导；改为「按钮是可见入口，ESC 静默保留」。

| 项         | 内容                                                                                                                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 组件行为   | `web-admin/src/components/SearchPalette.vue` 输入行右侧新增 `.search-palette__close` 按钮（`aria-label`/`title` 取 `common.close`，纳入既有 Tab 焦点陷阱）。ESC、遮罩点击、⌘K/Ctrl+K 再次按下仍照旧可关闭，只是 ESC 不再出现在 UI 上 |
| 提示与词表 | 页脚去掉 `ESC 关闭` 提示、输入行去掉 ESC 键帽（页脚只剩 ↑↓ 与 ↵）；随之无引用的 `common.searchHintClose` 从中英词表删除（两语言同步，键位仍对齐）                                                                                    |
| 测试       | `web-admin/src/tests/components/searchPalette.test.js` 新增「关闭按钮可关」与「UI 无 ESC 字样（kbd 与页脚）」断言；ESC 关闭与焦点归还用例保持原契约                                                                                  |

### 七维审计 2026-10-20：审计链检查点 / 固定睡眠门禁 / 运维关键路径 E2E

> 按 `deliverables/七维深度审计报告-2026-10-20.md` 整改。本节只记录三项中危的**结构性**修复；
> 其余按报告编号分散落在各模块的修复不在此逐条复述。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S-8 审计链外部锚 | 新增 `scripts/audit-chain-checkpoint.js` 与 `src/services/auditChainCheckpoint.js`：把链头与记录数写成 HMAC 签名的 JSONL 检查点，校验时逐行验签并核对锚点。可检出分支插入 / 链头替换 / 锚点前截断 / 检查点文件被改；**残余边界**（锚点与库同机、锚点后先加后删）已在 `docs/architecture.md` §7 与 `docs/threat-model.md` 明示，不宣称完整防篡改                                                                                                                                             |
| T-2 固定睡眠     | 新增 `src/tests/helpers/waitFor.js`（条件轮询）与 `src/tests/ci/noFixedSleepRatchet.test.js`：固定 `setTimeout` 收进棘轮，新增一处即红；真实网络/进程等待改走健康检查与事件，定时器逻辑用 fake timers                                                                                                                                                                                                                                                                                       |
| T-1 运维 E2E     | 新增 `scripts/ops-e2e.js` 与 `scripts/ops-e2e/journeys/*` 四条旅程：告警投递探针、部署失败→自动回滚、备份→恢复→校验、跨部门越权。各自独立子进程 + 内存 Mongo + 随机端口 + 本地假 Alertmanager；CI 的 `e2e` job 新增 `npm run test:ops-e2e` 并登记进 `ciGateWiring`。浏览器 no-skip 门禁（`MIN_PASSED=32`、`skipped==0`）未改动                                                                                                                                                              |
| O-5 部署演练     | `scripts/deployCommands.js` 抽出全部外发命令的 argv 构造（部署脚本不再自带命令字面量），`--dry-run` 打印与实际执行同源的真实命令；新增 `src/tests/deploy/deployCommands.test.js`。首次 `dry_run=true` 真实演练的步骤与留证表登记在 `deployment/deploy-workflow-rehearsal.md`——**真实 run 尚未执行**（需预发环境），未留证前 deploy.yml 的「未验证声明」保留。T-4 的预发定期演练 cron 见 `deployment/rollback-drill.md` §5.5；S-9 的 CI 开发机隔离口径见 `docs/security-dependency-watch.md` |
| 冒烟测试修正     | I-01 改为令牌只经 httpOnly cookie 下发后，`scripts/e2e-smoke.js` 仍从响应体取 `data.token`，导致 9 步 401（CI 必红）。改为从 `Set-Cookie` 取 `access_token`，继续用 Bearer 路径覆盖 `authenticate`                                                                                                                                                                                                                                                                                          |

### lint 棘轮批 1–3c：大文件目录化拆分与阈值重设（2026-10-18/19）

> 本轮是**纯搬家 + 度量收敛**：`security.js`、`authService.js`、`websocketService.js`、
> `authController.js`、`userController.js`、`securityController.js`、`sharedCache.js`、`initData.js`
> 按职责拆入同名目录（入口文件保留原有导出形态），复杂度与函数体积告警逐批下降。
> 业务语义未变；覆盖率/体积棘轮的键随路径迁移同步重设，并有 `coverageGateWiring` 与
> 分层棘轮测试守住“拆分后门槛没有被悄悄放宽”。针对拆分中暴露的 `max-lines` 最后若干条，
> 批 3a/3c 只做内容保持式迁移，未借机改行为。

### 响应头加固：X-XSS-Protection 测试守护 + Trusted Types 灰度 + CORP/Referrer-Policy 口径统一到 same-origin（2026-10-15 · 按 `deliverables/安全加固待办清单-2026-10-15.md` 的 P1+P2 逐项落地）

> 清单 P1（Trusted Types report-only）与 P2（COEP 决策记录 / CORP / Referrer-Policy）四项全部落地；P3 的 CSRF 双保险按清单自陈「不做也不构成缺口；仅在明确有子域/多应用共站时做」未做（本仓 nginx 单 `server_name`、无子域前端，已复核）。
>
> 落地过程中发现**三处清单本身没写准的地方**，一并记录：
> ① 清单给的 Trusted Types 写法（`useDefaults:false` + 只写 `require-trusted-types-for`）在 helmet 7.2.0 下**构造期直接抛错**——`normalizeDirectives()` 要求「必须有 default-src，除非显式 `dangerouslyDisableDefaultSrc`」，且该检查对 `reportOnly` 一视同仁（回源 `node_modules/helmet/index.cjs:90-92`，已实测复现）。照抄会让整个 app 起不来。已改为显式摘掉 `default-src`，下发结果就是单条 `require-trusted-types-for 'script'`，不会把 helmet 的全套默认指令拖进灰度策略制造噪音。
> ② Referrer-Policy 实际有**五份**副本，清单只列了 4 处，漏了 `web-admin/vite.config.js` 的 `buildSecurityHeaders`（vite dev/preview 这条托管路径）。五份已一并改，并由新用例钉住取值一致。
> ③ 顺带发现 `src/tests/controllers/roleControllerHierarchyGuards.test.js` 中「角色/权限审计全部由全局中间件派生（`utils/auditMeta.js:85-103` → `middleware/security.js:648`；挂载 `src/app.js:325-326`）」这句的**三个锚点全部指错位置**（其中 `security.js:648` 在 HEAD 就已落在 `checkIPBlacklist` 的 `IP_BLOCKED` 行，内容保持式迁移只会把它一路带下来）。已按真实落点更正为派生定义 / 派生调用 / 中间件挂载。

| 项                         | 内容                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trusted Types 灰度（P1）   | `src/middleware/security.js` 新增独立中间件 `trustedTypesReportOnly`，挂到 `applyResponseHardening()` 的 `reportingEndpoints` 之后。只写 `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'`，与主 CSP 头名不同、互不覆盖；`CSP_REPORT_ENABLED=true` 时附带 `report-uri`/`report-to`（复用既有 `/csp-report` 与 `csp-endpoint`），关闭时一条多余指令都不下发。**只上报不阻断**，对现有行为零影响 |
| COEP 决策记录（P2）        | `crossOriginEmbedderPolicy: false` 处补注释：为何关闭（无跨源隔离需求；开启会拦掉 Swagger UI 自注入资源、Google Fonts、导出 `blob:` 下载）、什么条件下应重新评估（含「`credentialless` 不是免费开关」这条反面证据）。此前全仓无任何 COEP 决策留痕                                                                                                                                                                      |
| CORP 收紧（P2）            | `crossOriginResourcePolicy` 由 `same-site` → `same-origin`，与 nginx 三份副本、`web-admin/vite.config.js` 及 helmet 7 默认值（`index.cjs:168`）对齐。同源反代拓扑下前后端同源，对同源 fetch 无影响                                                                                                                                                                                                                     |
| Referrer-Policy 收紧（P2） | 5 处由 `strict-origin-when-cross-origin` → `same-origin`：`src/middleware/security.js:139`、`deployment/nginx.conf.example:108`/`:175`/`:217`、`web-admin/vite.config.js:134`。前置确认已实测：跨源子资源仅 Google Fonts（不依赖 Referer）、全仓无外部跳转/防盗链/外链来源分析、后端唯一 Referer 消费点是 `originCheck.js` 的 Origin 缺失回退（同源请求照常携带 Referer）                                              |
| X-XSS-Protection 守护      | 新增 `src/tests/middleware/xssProtectionHeader.test.js`（5 例）钉住「下发且精确等于 `'0'`」与「恰好一个头」——该头此前全仓无断言，误改为 `false`（= 完全不设该头）不会有任何红灯。变异实测：`xssFilter: false` ⇒ 前 4 条转红。同时更正 `security.js` 中语义写反的旧注释（`xssFilter: true` 的语义本就是下发 `0`，照字面读会以为这是"开启保护"）                                                                         |
| 锚点同步                   | `security.js` 净 +82 行 ⇒ 指向其 123 行之后的 **9 处**锚点逐条迁移（`:608`→`:685`、`:666`→`:743`、`:686-690`→`:763-767`），涉及 5 个源码/文档 + 4 个测试文件；`git grep` 核验旧值 0 残留、新值一一对应，`commentAnchorFreshness` + `bareAnchorAttribution` 全绿                                                                                                                                                        |
| 新用例                     | 新增 `src/tests/middleware/securityHeaderPolicyHardening.test.js`（11 例）：report-only 头取值 / 不污染强制 CSP / 上报开关两态 / CORP 与 Referrer-Policy 五份副本取值一致 + 两类可证伪反证。变异实测：摘掉 `app.use(trustedTypesReportOnly)` ⇒ 4 条转红；CORP 回退 `same-site` ⇒ 2 条转红（断言有牙，非空洞）                                                                                                          |
| 门禁联动                   | 两个新用例文件均已 `git add`：`testTreePurity` 要求 `src/tests/**` 下不得存在未跟踪的 `*.test.js`（放在那里 `testMatch` 一定会执行它）                                                                                                                                                                                                                                                                                 |

### 修 CI 真红：审计 action 对账闸补登 roleController updated 广播载荷（2026-10-11 · 678e211 漏登）

> 678e211 给 updateRole 补 role-updated 广播时加了 action: 'updated' 载荷字段，但未同步 auditActionReconciliation 的 NOT_AUDIT_ACTION_LITERALS 排除清单（该闸要求每个 action 字面量要么有写入形态认领、要么逐条登记家族与出处；同文件 created/deleted 两条广播载荷均在册）。f4afd88 的 CI 止步于 lint ratchet 未跑到该步、f6bf4e7 早于 678e211，故此前未暴露。按既有机制补登（ws 家族，tally 5→6），并改准两处被 678e211 移动而过时的行号出处。

### 登录加密轨道安全收口七项（2026-10-10 · 外部审计 8 项发现逐项处置：限流漏配 / 对客预言机 / 信封不绑用途 / 公钥无钉扎 / strict 无生产收口 / PFS 未文档化 / dev 链存量 CVE）

> 对登录口令 ECDH 密文轨（ADR-001）的一轮外部审计逐项修复。另有两项审计结论经核对已过期：nginx 边层 Permissions-Policy 与 transportSecurity 的 HTTPS 断言在受审版本前已落地，本次仅复核确认、无改动。

| 项                             | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/mfa/enable` 补限流           | enroll/disable/recovery-codes 都有 strictLimiter，唯独「确认开启」那步漏配；已补齐。危害有界（爆破只能加速攻击者给自己的账户开 MFA），属一致性收口                                                                                                                                                                                                                                                                                                                |
| 登录 ENC_INVALID 对客统一      | 解密失败原映射 400 `AUTH_ENCRYPTED_CREDENTIAL_INVALID`，与 `AUTH_INVALID_CREDENTIALS` 可区分 ⇒ nonce 消费/时间窗弱预言机，与 loginCipher「失败原因不回传客户端做区分」的设计意图相悖。登录端点改为统一 401 `AUTH_INVALID_CREDENTIALS`；register/changePassword/mfaDisable/userCreate **保留**独立错误码——那些端点输入由攻击者自控（注册新用户、改自己口令），无预言机价值，且前端公钥缓存自愈依赖该码触发（自愈判定改由 `web-admin/src/utils/api.js` 按端点承担） |
| 信封绑定端点用途（AAD）        | 载荷原本只有 `{p, ts, nonce}`：一条**从未到达服务端**的捕获信封（提交失败/被丢弃，密文已上线）可在 ±5 分钟窗口内提交到任何接收密文口令的端点。新增 `CREDENTIAL_AAD`（login / register / password:current / password:new / mfa:disable / user:create）纳入 GCM additionalData，跨端点信封解密失败；刻意**不**绑用户名——跨用户重放会在口令比对处自然 401，绑用户名零收益却让每个前端表单多一个必须逐字一致的条件                                                    |
| 公钥指纹钉扎（防主动 MITM）    | 公钥经同一信道下发、不固定不验签，主动中间人替换公钥即可解密再转发——「截获密文无法恢复口令」只对被动窃听成立。构建期把公钥 SHA-256 指纹钉进前端包（`VITE_LOGIN_PUBLIC_KEY_SHA256`，≥16 位 hex 前缀），`ensurePublicKey` 对**取到的 PEM** 自行计算并比对，不符抛 `PUBLIC_KEY_PIN_MISMATCH` 且不得降级明文；指纹取自服务端启动日志的 `publicKeySha256` 字段（公钥指纹是公开信息）                                                                                   |
| strict 未开的启动期告警        | 新增 `src/config/loginEncryptGuard.js`：`LOGIN_ENCRYPT_STRICT` 未开时 loud warning + `incSecurityAlert('login_encrypt_strict_disabled', medium)`（已登记进 `failOpenSites` 台账）。**刻意不阻断启动**：strict 关死明文轨的前提是浏览器有 WebCrypto，而纯 HTTP 内网形态拿不到——致命闸会拦死一种合法部署形态；收口方式是「可见」而非「拒绝」                                                                                                                        |
| PFS 与轮换文档化               | `SECURITY.md` 新增「登录口令加密的密钥管理」：静态私钥 = 无前向保密，泄露按**口令泄露**处置（轮换私钥 + 强制全体改密），不是单纯换钥；轮换须与前端钉扎包一起发布（只换服务端私钥 ⇒ 全部登录被 `PUBLIC_KEY_PIN_MISMATCH` 阻断）。ADR-001 补三条决策记录（PFS 局限 / 钉扎收口 / AAD 绑定与 ENC_INVALID 合并的理由）；`deployment/secret-rotation.md` 补钉扎联动段                                                                                                   |
| dev 链存量 CVE（仅记录，未动） | `npm audit`：生产依赖 0 漏洞，35 个（5 moderate / 30 high）全在 jest 开发链（js-yaml→argparse→sprintf-js 等，经 istanbul 传入）。`npm audit fix` 非破坏性无效；`--force` 仅升 jest@30.5.2（breaking 大版本，559 个套件重度依赖 jest 29 配置与全局 setup）。CI 安全门禁为 `--omit=dev` 口径（生产 0 漏洞即过）。**决策：本次不升级**，建议维护窗口单独做 jest 29→30 并全量验证                                                                                     |

### 补装 login_ecdh_private_key 并修正 loginCipher 的前向保密表述（2026-10-10 · compose 挂了 10 个 secret 唯独漏了登录 ECDH 私钥，轮换手册里这把钥匙的流程从未生效）

> `src/config/secrets.js` 的 `FILE_BACKED_SECRETS` 早已支持 `LOGIN_ECDH_PRIVATE_KEY_FILE`，`scripts/generate-secrets.js` 也一直产出 `login_ecdh_private_key`（P-256 PEM），但 `docker-compose.yml` 从未装配它：app 的 `environment:` 没有对应 `_FILE` 指针，app 服务与顶层 `secrets:` 也没有对应定义。后果是生产部署下服务每次启动惰性生成临时密钥对——`deployment/secret-rotation.md` 里这把钥匙的轮换流程从不生效，且重启前的历史登录密文永久无法解密（做流量取证须在重启前完成）。另修正 `src/utils/loginCipher.js` 头注释：「截获密文的攻击者无法恢复口令」仅在私钥不泄露时成立，静态私钥 + 历史密文 = 明文（无前向保密），注释已补上前提与两种模式的取舍。

| 项           | 内容                                                                                                                                                                                                                                                                                               |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| compose 装配 | app `environment:` 补 `LOGIN_ECDH_PRIVATE_KEY_FILE=/run/secrets/login_ecdh_private_key`；app 服务与顶层 `secrets:` 补 `login_ecdh_private_key`（`file: ./secrets/login_ecdh_private_key`）；头注释手抄清单补 `openssl genpkey` 一条（原「首选」注释里"本清单遗漏"的说法随之失效）                  |
| 注释修正     | `src/utils/loginCipher.js` 头注释把「无法恢复口令」改为带前提的表述：信封自带临时公钥坐标，持静态私钥即可解密任一历史密文（无前向保密）；临时密钥对模式反之——重启前的密文永久不可解密                                                                                                              |
| 契约测试     | `composeProductionContract.test.js`：新变量进 ENV_KEYS 与 fileMap，`/run/secrets/login_ecdh_private_key` 的替身改为真实 EC PEM；新增「文件注入密钥装配三方一致」用例（environment `*_FILE` ↔ app secrets 清单 ↔ 顶层 secrets，且轮换手册点名的文件注入密钥必须全部在装），两类漏法各有一条反向自证 |
| 手册         | `deployment/secret-rotation.md` 的 `LOGIN_ECDH_PRIVATE_KEY` 行后补机制段：经 secret 文件注入，换钥＝随批替换文件后重启；未配置时重启前的密文永久不可解密                                                                                                                                           |

### 下拉浮层边角打磨：表面只画一层（2026-10-09 · 双层表面叠出双边框与错角，边角不圆润）

> 顶栏用户菜单与语言/主题下拉的浮层边角发毛、不圆润。复现定位到根因是**两层表面**：Element Plus 把浮层表面（底色/描边/阴影）画在外壳 .el-dropdown__popper.el-popper 上，还带着 base 的 5px 11px 内边距与 global.css 的 10px 圆角；pple-refine.css 又把表面画在内层 .el-dropdown-menu（12px 圆角 + 1px 描边 + 6px 内边距）。两层半径、描边、内边距全不一致，圆角处叠出双边框与错角。暗色还多一层脱节：html.dark .el-popper 的 --xf-gray-50 实底框围着半透明菜单。

| 项       | 内容                                                                                                                                                                                                               |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 外壳透明 | .el-dropdown__popper.el-popper 的 padding/background/border/box-shadow 全部清空（带 !important），表面只由 .el-dropdown-menu 画一层；箭头是外壳子元素、::before 自带配色，位置不受影响                             |
| 暗色再盖 | html.dark .el-popper 的实底/描边两条声明带 !important 且特异性 (0,2,1) 压过上面的 (0,2,0)，用 html.dark .el-dropdown__popper.el-popper 对 ackground/border 再盖一次，否则暗色菜单四周围一圈 --xf-gray-50 实底框    |
| 箭头同源 | 亮色下拉箭头描边改为跟随菜单的 --xf-border-color（EP 默认取 --el-border-color-light #e4e7ed，箭头根部露一截异色），底色取 EP 给菜单的 --el-bg-color-overlay；依旧不写 !important——placement 的透明边规则必须继续赢 |
| 不变量   | web-admin/src/tests/styles/tooltipTheme.test.js 补两例：外壳透明四件套 + 暗色再盖两条；亮色箭头与菜单描边同源、底色同源 EP overlay，并进「不能带 !important」循环                                                  |

### fail-open 降级补信号 + 持续型告警 + 站点台账门禁（2026-10-09 · 同一个降级动作被复刻 3 份，且全都没有可告警信号）

> 本仓早有明文纪律（`middleware/security.js:763-767`、`middleware/rateLimitStore.js:53-56`、
> `services/websocketService.js:723-725` 三处自陈）：「fail-open 放行必须有显式可观测信号——
> 否则『DB 挂了 + 全站裸奔』只有一条 error 日志可循」「降级态只写日志等于没有可告警信号——
> `grep 日志` 不是运维动作」。**验证码开关这条链没做到**：`isLoginCaptchaEnabled` /
> `isRegisterCaptchaEnabled` 自身没有 try/catch，真正做降级的是调用点，而同一段 try/catch
> 被复刻了 **3 份**（`authService.registerUser`、`authService.resolveLoginPassword`、
> `authController.getCaptchaStatus`），三份都是空 catch、都不发信号。

| 项          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 收口        | 新增 `SystemConfig.captchaSwitch(kind)`：静态默认兜底 + 降级信号只在这一处发生；3 个调用点改为调它，各自手写的 try/catch 删除                                                                                                                                                                                                                                                                                              |
| 新信号      | `captcha_switch_db_fallback`（level `medium`）——验证码只是登录链**前置层**，降级后凭据型限流与爆破检测仍在，故与 `ip_blacklist_failopen` 的 `high` 不同级                                                                                                                                                                                                                                                                  |
| 第二个信号  | `captcha_active_bound_lost`（level `high`）：`captchaService.generate` 在「Redis 已启用但活跃数读取失败」时不设上限放行。**真正的放行点在 `active === null` 而非 `catch`**——`sharedCache.incrWithTtl` 两条降级路径都返回 `null`、从不抛，原先那个 catch 不可达、也永远发不出信号                                                                                                                                           |
| 告警        | 新增 `SecurityFailOpenSustained`（`for: 10m`，critical）。**按 type 分开判、不跨类型求和**：求和会掺进启动期恒正项（`immutableConfigGuard`/`legacyCbcGuard` 进程启动即写 `security_alerts_total`），既稀释真实突发、又让 crash loop 冒充安全事件；**用持续型而非速率型**：`SecurityAlertBurst` 是「10 分钟 ≥10 条」，而 fail-open 的危险形态恰是低速而持续，速率型可以永远不达标                                           |
| 台账 + 门禁 | 新增 `constants/failOpenSites.js`（5 个 fail-open 站点 + 10 个其它信号 + 1 个转发点，逐条声明 `direction/trigger/effect/why/tightening`）与 `tests/ci/failOpenLedgerGate.test.js`（8 例）：代码里的静态站点 ⇄ 台账条目双向闭合；每条 type 必须被持续型规则覆盖（**登记信号 ≠ 接上告警**）；反向也拦（规则点名不存在的 type 要红）                                                                                          |
| 刻意不做    | **不自动收紧**。把 fail-open 自动翻成 fail-closed 会把「保密性降级」转成「可用性事故」，且恰好发生在系统已经不健康时（黑名单 fail-closed = 库挂时全站请求无法验证；验证码 fail-closed = 没人能登录）。是否收紧是产品决策，不是告警规则能代做的                                                                                                                                                                             |
| 用例        | 新增 `tests/services/failOpenSignals.test.js`（11 例，含反向对照：两个 type 必须真能渲染进 `formatPrometheus()`）；`authControllerOutcomes.test.js` 的两条 `getCaptchaStatus` 重写到新接缝并**补前提自证**（断言真的调了 `captchaSwitch`）——原写法在该文件的 `../../models` 部分 mock 下会因 `captchaSwitch` 是 `undefined` 抛错、被兜底网吞掉而"通过"，等于在断言静态默认值                                               |
| 文档        | `README.md` 新增「开发/预览服务器的暴露边界」：dev 与 preview **都**绑 `0.0.0.0`，dev 下发**未打包源码**而 `src/**` 不在敏感文件黑名单内 ⇒ 禁止把 3001 发布到公网；`docs/threat-model.md` §3 增第 5 条（明确标注「仅开发期、不构成生产面」）；`docs/incident-response.md` §2 增「护栏失效信号」一条（该规则触发时，「没看到拦截」不能当作「没被攻击」的证据）。顺带修正 `README.md` 已过期的「4 条内置告警」（实为 13 条） |
| 锚点迁移    | 本轮删行使 `authService.js` -7 行、`authController.js` +13 行，全仓 **32 处**注释锚点随行号迁移（逐条按「迁移后该行内容 == 迁移前该行在 HEAD 的内容」核验）；`bareAnchorAttribution.test.js` 的回指台账两处坐标同步随迁。另修正 `statsAnomalyScope.test.js` 一处**本就指错**的锚点（写 `securityController.js:284`，而 `getSecurityStats` 实为 `:317`）                                                                    |

### 顶栏入口提示统一走 Element Plus 浮层 + 浮层箭头主题适配（2026-10-09 · 语言/主题图标此前挂的是浏览器原生 title）

> 顶栏语言/主题入口把提示写在 `el-icon` 的 `:title` 上，走浏览器原生提示——样式、字号、圆角与出现时机全由浏览器决定，和搜索/刷新/全屏的 `el-tooltip` 浮层是两套观感。本批把两处统一成 `el-tooltip`；顺着这条线查浮层配色时，又发现 Element Plus 的箭头是**独立元素**、取的是另一套变量，仓库只改了浮层底色，亮/暗两个主题下尖角都露着异色（暗色下拉菜单甚至挂一块异色三角）。

| 项       | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 统一提示 | `web-admin/src/layout/index.vue`：语言/主题的 `el-icon` 去掉 `:title`，外面套 `el-tooltip`（`placement="bottom"`，与搜索/刷新同规格）。**不能**反过来把 tooltip 塞进 `el-dropdown` 里——`el-tooltip` 的根是 `ElPopper`（`inheritAttrs: false`），dropdown 经 `ElOnlyChild` 下发的 `role`/`tabindex`/`id`/`aria-*` 与 forward-ref 会在那一层被吃掉，下拉直接点不开（实测：菜单浮层不再出现）                                                                                                                                                                                                                                                                                                                                       |
| 防叠放   | 下拉展开期间用 `:disabled` 收起提示：菜单浮层与提示浮层同位叠放会互相盖住，而展开时指针停在图标上不产生 `mouseleave`，提示不会自行消失。状态由 `@visible-change` 回写，两个入口互斥共用一个 ref                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 箭头同色 | `apple-refine.css` 新增四条 `.el-popper__arrow::before` 规则（亮色 tooltip / 暗色 tooltip / 暗色下拉菜单 / 暗色 `.is-light`，末条见「续修」），底色与描边逐一对齐浮层。箭头规则**不能**加 `!important`：朝浮层的那两条边由 EP 的 placement 规则置 `transparent`，那条规则带 `!important` 必须继续赢，否则旋转 45° 的方块会露出实心方角                                                                                                                                                                                                                                                                                                                                                                                           |
| 暗色描边 | `html.dark .el-popper.is-dark` 补上自己的 `border`：原先不写，暗色边悄悄吃亮色那条 `.el-popper.is-dark` 的边（两条特异性相同、后者在源流里更晚），改亮色配色会把暗色一起带跑                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 用例     | `web-admin/src/tests/layout/layout.test.js`：定位辅助从「按 title 找图标」改成文件原有的图标 path oracle（title 已不存在）；新增 `布局 · 顶栏入口悬停提示` 四条——顶栏图标一律不留原生 title、语言/主题悬停出 EP 浮层且文案走 i18n、下拉展开期间只剩菜单浮层。`web-admin/src/tests/styles/tooltipTheme.test.js`：读 CSS 源码比对「箭头与浮层同色」+ 箭头规则不带 `!important`，两条变异（箭头改回白、箭头加 `!important`）均能测红；续修新增两例——「暗色 date-picker 箭头与 `html.dark .el-popper` 实底同色」（表面规则在 dark.css，测试改读两个样式文件）与「`.is-light` 规则必须 `:not(.el-dropdown__popper)`」（特异性 (0,5,2) 高于下拉箭头规则 (0,3,2)，不排除会把半透明下拉箭头打成实底），第三种变异（删掉 `:not`）同样测红 |
| 续修     | 暗色 `.is-light` 浮层（`el-date-picker`，经 `ElTooltip effect="light"` 带 `is-light`）的箭头补上 `--xf-gray-50`/`--xf-border-color`：EP 的 `.is-light` 箭头取 `--el-popper-bg-color-light`（=`--el-bg-color-overlay`，EP 暗色 `#1d1e1f` 中性灰）与 `--el-border-color-light`（`#414243`），与 `#0f172a` 表面对不上。选择器必须 `:not(.el-dropdown__popper)`：下拉菜单表面是半透明 `rgba(30,41,59,.95)`，而 `.is-light` 规则特异性更高，不排除会把下拉箭头一起打成实底。`el-select` 浮层不渲染箭头，无需处理                                                                                                                                                                                                                      |

### 弱口令黑名单：匹配器口径修复 + 词干表扩充（2026-10-09 · 原 40 条里 24 条永远命中不了）

> 本批**不改依赖、不引入外部服务**。改的是「清单里的条目到底能不能被命中」。
> 旧实现是 40 条**口令字面量**，而归一化只做「末尾 ≥4 位数字收敛为 3 位」且**只归一化
> 口令侧**——两侧口径不一致的后果：实测 **24 条永远命中不了**，有效字典只有 **16 个词干**，
> 而文件看起来有 40 条。`helpers.test.js` 断言 `isBreachedPassword('admin@123') === true`
> 也是误导性的：生产路径上黑名单排在长度/复杂度之后，9 位口令根本走不到黑名单。

| 项       | 内容                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因     | **匹配器与数据口径不一致，不是数据错**。清单里 `passw0rd!` / `p@ssw0rd` / `1qaz@wsx` / `abcd1234!` 这种写法本身就说明作者意图是「按词干匹配」；而旧匹配器要求字面量全等。死条目分两族：①8~11 位条目先被长度规则拒掉；②以 ≥4 位数字结尾的条目永远不等于任何口令的归一化结果                                                       |
| 改法     | 表改为**词干**（`constants/breachedPasswords.js`，40 条字面量 → 123 条词干）；归一化只保留一份且在口令侧：小写 → 去所有非字母数字 → 去末尾连续数字。两侧口径因此不可能再漂移                                                                                                                                                     |
| 不变量   | 每个词干至少含 2 个字母。这是**必要条件**：归一化不重排字母，故口令的字母序列（小写）必须等于词干的字母序列，而策略要求同时含大写与小写 ⇒ 字母数 <2 的词干在策略下不可达                                                                                                                                                         |
| 覆盖变化 | 有效词干 16 → 123（**+107**）；`Passw0rd!1234`、`P@ssw0rd1234!`、`Abcd1234!5678`、`1Qaz@Wsx1234!` 等由漏变拦；精度用例同时钉住 12 条强口令不被误伤（`SunshineRain99!` 归一化后是 `sunshinerain`，不是词干）                                                                                                                      |
| 用例     | 新增 `src/tests/utils/breachedPasswordMatcher.test.js`（176 例）：逐条为 123 个词干构造「除黑名单外无懈可击」的反例并断言被拦；表内条目必须已是词干（混入字面量即红）；回归指纹；精度；边界；原 16 条不回退                                                                                                                      |
| 失败策略 | 本批**不接** HIBP。若将来要接，失败策略**已预先拍板**：**fail-open + 指标 + 启动日志告警**，且必须带超时与缓存——不让第三方可用性拖垮改密链路                                                                                                                                                                                     |
| 文档     | `docs/mlps2-controls.md` 的 G8 证据补上「清单规模 + 用例文件」，并新增一段**如实边界声明**（是高频词干表，不是泄露库；长尾覆盖不了）；`breachedPasswords.js` 文件头修正「以隐私为由拒绝 HIBP」的**不完整推论**（原话本身准确：range API 确实只收 SHA-1 前 5 位；但真正有分量的理由是多一个运行时外部依赖及其失败策略，原文没写） |

三处测试夹具注释同步更新（`authCookies.test.js` / `changePasswordTypeGuard.test.js` /
`sessionManagement.test.js`）：导出名 `BREACHED_PASSWORDS` → `BREACHED_PASSWORD_STEMS`，
且 `Test@12345 归一化后为 test@123` 的解释已不成立（现在一步归一化成 `test`）。
三处夹具口令均经 `deliverables/probe-matcher-behavior.js` 复核为新口径下的安全值。

### IP 归属地英文化（2026-10-09 · 私网/环回地址的 `location` 从中文文案改为稳定码）

> 缺陷形状与 `constants/securitySuggestions.js` 那次同族：**后端把文案拼死，前端就永远翻不动**。
> `ipLocationService` 把私网/环回地址收敛成中文两字「内网」直接下发，而三个消费面
> （会话管理、审计日志列表 + 详情弹窗、IP 黑白名单）都是 `· {{ row.location }}` 原样渲染——
> 管理员把界面切到 en-US，IP 旁边那一格仍是中文。公网 IP 的归属地是 ip2region 数据文本
> （「中国·广东省·深圳市·电信」），不在本次范围：数据侧本地化是另一个议题。

| 项     | 内容                                                                                                                                                                                                                                                                                                                                             |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 根因   | 展示文本由后端拼好并焊进 API 响应：私网这一支既非数据也非用户输入，而是**服务层自己写死的中文**，vue-i18n 对已定型的字符串无从下手                                                                                                                                                                                                               |
| 修法   | 沿用仓内既有口径（`utils/labelMaps.js` 的 DEVICE_TYPE、`utils/auditLabels.js` 的 `audit.action.*`、`constants/securitySuggestions.js`）：**后端只出稳定码，文案归前端词表**。新增 `src/constants/ipLocationCodes.js`（单一来源，当前一码 `private`），`ipLocationService` 的 IPv4 数据侧（xdb 的「内网IP」）与 IPv6 range 判定两支都改为产出该码 |
| 前端   | 新增 `web-admin/src/utils/ipLocationLabels.js`（三处消费方共用一份映射，与 securityLabels/auditLabels 同形状：调用方传 `t`、未知值原样透传），词表新增 `ipLocation.private`（zh「内网」/ en "Internal network"）                                                                                                                                 |
| 兼容性 | `location` 类型不变（string\|null）；老后端下发的中文「内网」按原样透传（与修复前一致，不回退成空白），滚动发布不会出现空归属地                                                                                                                                                                                                                  |
| 对账闸 | 新增 `web-admin/src/tests/utils/ipLocationCodeParity.test.js`：`createRequire` 后端码表逐一对账双语词表，并断言英文侧不得残留 CJK——「后端加一码、前端漏翻」变红，而不是在界面上静默显示裸码                                                                                                                                                      |
| 用例   | 后端 `ipLocationService.test.js`（私网取值不含中日韩字符）、`sessionService.test.js`（内网 IP 两字段均为稳定码）；前端三个视图各补一条「切 en-US → Internal network、公网数据文本原样」的语言跟随用例                                                                                                                                            |

### IP 归属地英文化·续（2026-10-09 · 公网归属地的中英对照词典：数据段也跟随界面语言）

> 上一节只解决了「内网」那一格（后端写死的中文）。公网 IP 的归属地是 ip2region xdb 的
> **数据原文**——库里只有中文一份，于是切到 en-US 后「中国·浙江省·杭州市·阿里云」照样是中文：
> 实测全部地区段里 **89.9% 的出现次数是中文**，只修私网标签等于修了个零头。

| 项     | 内容                                                                                                                                                                                                                                                                                                                              |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 修法   | 新增 `web-admin/src/data/ipLocationDictionary.json`（1024 条中英对照）；`utils/ipLocationLabels.js` 按当前 locale **逐段**译名后以 `·` 重拼，词典未收录的段原样透传（不把整块归属地抹掉）。语言判定读 i18n 实例的 locale（非中文界面一律英文），渲染期读 ref 即建立响应式依赖，切语言重算                                         |
| 词典   | 国家名 244 条由 `Intl.DisplayNames` 按 ISO 3166-1 **双向生成**（zh 键 ↔ en 值，不手抄 244 条）；省州 / 城市 / 运营商人工校对。实测覆盖 CJK 出现次数 **98.06%**（国家 100%、省州 98.6%、城市 93.2%、运营商 96.7%）                                                                                                                 |
| 豁免   | 10 条高频段登记未收录（`内网IP` + 9 个译名不确定的段），理由逐条写在测试里，**上限 12 条**且每条键必须仍在数据里。口径：宁可以英文界面回退中文，也不把没把握的译名写进词典——**错的译名比中文更难发现**                                                                                                                            |
| 闸     | `web-admin/src/tests/utils/ipLocationDictionary.test.js` 直接对**真实 xdb** 取数（复用后端 `loadFromBuffer` 解析指针，只补段索引遍历）：国家/省州 100%、城市/运营商高频段（出现次数 ≥ 阈值）除登记豁免外全覆盖、整体覆盖率 ≥ 98%、词典无陈旧键、译文不含中文、豁免不越上限。数据刷新带入新地名 ⇒ 测试列出缺哪些，而不是靠用户发现 |
| 体积   | 词典经三个懒加载视图进入**异步分块**：首屏 `entryJsGzip` +1.1 KB，总 gzip +19.4 KB；五项预算均仍有余量（`check-bundle-budget` 通过），基线未动                                                                                                                                                                                    |
| 兼容性 | `location` 契约不变（仍是 string）；中文界面行为零变化（数据本就是中文，不过词典）                                                                                                                                                                                                                                                |

### 依赖审计：dev 树盲区补门禁（2026-10-09 · `security-audit` 只审 `--omit=dev`）

> 本批**不改依赖树**。改的是「谁在被审」：CI 两处 audit 都是 `npm audit --omit=dev`，
> 于是 devDependencies 的 advisory 永远不会让构建失败。实测含 dev **35 条（30 high / 5 moderate）**，
> `--omit=dev` 为 **0**，web-admin 两侧均为 0。

| 项                 | 内容                                                                                                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因               | 35 条包维度告警**只由 2 条公告**传染而来：`GHSA-vfj7-8cjw-p6xm`（braces，high，栈耗尽 DoS）与 `GHSA-hp3w-g68c-fv3c`（sprintf-js，moderate）                                                                                                                 |
| 为何不能 overrides | 两条公告的 `first_patched_version` 均为 **null**，受影响区间上界就是 registry 的 latest（braces 3.0.3 / sprintf-js 1.1.3）⇒ **无版本可指向**，与 uuid override 的前提不同                                                                                   |
| 为何不升 jest 30   | 实测（隔离探针）：jest 30 + nodemon = 3 high / 19 moderate；jest 30 去 nodemon = 0 high / 19 moderate。**moderate 反而由 5 升到 19**，且清不掉 `js-yaml@3 → argparse@1 → sprintf-js` 链                                                                     |
| 可达性             | 两条链实测**不可达**：braces 需攻击者可控 glob（本仓输入只有 jest CLI/config 与 nodemon ignore）；argparse 只被 `js-yaml/bin/js-yaml.js` 引用，`load-nyc-config` 走 `lib/js-yaml.js` 不加载它 ⇒ 性质是卫生问题，非可利用漏洞                                |
| 改法               | 新增 `scripts/check-audit-allowlist.js`（含 dev 审计**硬门禁 + 显式允许清单**）+ `deployment/audit-allowlist.json`（登记两条无补丁公告，含理由/可达性/复核期限 `2027-01-31`）；`ci.yml` 的 `security-audit` 作业新增一步；`ciGateWiring.test.js` 登记新门禁 |
| fail-closed 三判据 | ①未登记 ⇒ 红；②`reviewBy` 过期 ⇒ 红；③清单项在本次报告里**已无对应公告** ⇒ 红，必须删行（防清单只增不减）                                                                                                                                                   |
| 文档               | `docs/security-dependency-watch.md` 修正「含 dev 0 漏洞」的过期结论（该结论是 2026-09-16 时点，上游 09-18 / 09-24 才发公告 ⇒ 时间性回归，非本批引入），并登记两条已知例外                                                                                   |

判据来源是**根因公告**而非受影响包（35 条 = 2 条根因），故清单按 GHSA 编号登记，
不按包名——按包登记必然得到一份腐烂清单。

### CI 覆盖率门禁修复（2026-10-08 · `#13 Run tests with coverage` 三条阈值未达标）

> 这条红**不是**本批引入，而是被下一节的修复**逼出来的**：`#11 Run tests` / `#12` 修绿之前，
> `#13` 每轮都被前序 step 的失败 skip/cancel，从未真正执行。根因是 `ccddabc`
> （2026-10-03 并行会话批次）给两个文件新增了**从未被执行过**的函数/分支，
> 而阈值是 2026-09-04 / 2026-09-30 定的。

| 文件                             | 阈值（fn/br） | 修复前实测                 | 根因（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                                                                                                                    | 改法                                                                                                                                                                                                                                                                                    |
| -------------------------------- | ------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/middleware/auth.js`         | 90 / 87       | fn **87.5%**               | `ccddabc` 给 `invalidateUserCache` 补了 `publishInvalidate(...).catch((err) => …)`，函数数 15 → 16（14/15 变 14/16）。覆盖它的 `roleStatusInvalidatesUserCache.test.js` 把整个 `invalidateUserCache` `jest.mock` 掉了，只断言"被调用"，从不碰函数体                                                                                                                  | `observabilityWritesNeverReject.test.js` 新增 L7：三种拒绝形态（Error / undefined / 无 message 对象）下断言不抛 + warn 文案逐字。注：该键是 `auth:user:`；同一调用链上 `userPermissionService` 还会广播一条 `permcache:` 键（`userPermissionService.js:191`），故判据按前缀点名而非计数 |
| `src/services/deviceReminder.js` | 97 / 90       | fn **90%** / br **86.79%** | 调度器里两处 `markOverdueInspections().catch(...)`（`ccddabc` 新增）从未执行。**且普通 DB 故障驱动不了它们**——`markOverdueInspections` 整段体在 try/catch 内、**永不 reject**，这两条箭头是**第二道防线**，只在第一道被破坏（内层 catch 体自身抛错）时才生效。第一版用例正是用 DB 故障驱动的，实测 `logger.error` 只收到内层那条 `巡检逾期标记失败：…`，箭头一次没跑 | `deviceReminderScopeIsolationGuards.test.js` 新增 2 例：让**内层** `logger.error` 抛错以打断第一道防线，两种形态（Error / undefined）各一条，把 `${err?.message ?? err}` 的两条路径都走到                                                                                               |

**为什么是补测试而不是下调阈值**：`jest.config.js` 有明确纪律「每条阈值 = 实测下方 5pt(分支) / 3pt(函数)，
只紧不松」；2026-09-30 那次 auth.js `functions 97 → 90` 是**修正推导错误**（原值按"实测 100%"机械套用，
真值 93.33%，那条 setInterval 回调是刻意不覆盖的）。本批两处缺口**都可以被行为用例覆盖**，
所以按同一纪律应补测试。

修复后实测（全量 `jest --coverage`）：`auth.js` 函数 **100%** / 分支 **92.59%**；
`deviceReminder.js` 函数 **100%** / 分支 **94.33%**——两项阈值均达标。

复跑事实：两套件 `jest <两个文件>` **40/40 通过**；`jest src/tests/ci/ --runInBand` **15/16 通过**
（`testTreePurity` 因 `execFileSync('git')` 被本机沙箱拦而红，与下一节同一条环境性假红，
该套件只判"测试文件是否入库"，不涉及本次改动）。

### CI 真红修复（2026-10-08 · `test` 腿两条既有红：断言读错流 + 循环复用夹具撞秒级归档名）

> 两条在基线 run `37711343020`（`b7834f1`，本批之前）上**逐字相同** ⇒ 既有红，非本批引入。
> `security-audit` 腿已由 `5ab7e91` 修绿（上游 2026-10-05T22:50–23:31Z 一次批量公告刷新，
> `compression` / `proxy-addr` / `source-map-js` / `@vue/server-renderer` 四条与本仓依赖面无关），
> 此后只剩这两条挡住 `test (20.x)` / `test (22.x)`，并连带 `build` 被 skip。

| #   | 缺陷（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                        | 改法                                                                          | 证据                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `imageDigestGate.test.js` 的 SIGTERM 用例把 `d.stdout + d.stderr` 拼成一个串再断言 `/RC=143$/`。驱动脚本的 `printf "RC=%s\n"` 走 stdout，而 `wait` 被信号打断时 shell 把作业终止语写**自己的 stderr** ⇒ 拼完是 `"RC=143\nTerminated"`，`$` 锚点恒不成立                  | rc 只认 `d.stdout`；`printed` 保留，继续用于「不得出现 KILLFAILED」的否定断言 | 用 dash（CI 的 `/bin/sh`）跑同一个驱动脚本：stdout=`RC=143`、stderr=`Terminated`                                                    |
| ②   | `backupFailureArtifactHygiene.test.js` 的三轮 `for (const blank of [...])` 复用 `beforeEach` 的同一个夹具。归档名只到**秒**，而"只含空白"的判据落在异地副本那一步（加密归档已定稿落盘）⇒ 第 2 轮同秒撞名，先命中「目标加密归档已存在，拒绝覆盖」，断言变成在测另一条判据 | 每轮自建 `mkwork()`、`finally` 拆掉，三条之间只差 `blank` 一个变量            | 固定时间戳的 `date` 替身把"同秒"从偶发变确定性：共用夹具第 2 轮复现出与 CI 同形的「拒绝覆盖」；每轮新夹具三轮全部「只含空白」+ rc=1 |

为什么本地一直没暴露：两套件都是 shell-out 型，本机 `spawnSync` 对任何可执行文件返回 `EBUSY`
（逐 host 探针 `status=null` / `error=EBUSY`），本地根本跑不到断言。另有一条会误导归因的环境差异：
本机 `rm` 被安全包装器接管，单次约 10–13 s，把单轮备份脚本从 CI 的亚秒级拖到 **31 s**——
"本地复现不出同秒撞名"正是这个延迟造成的。

复跑事实：`prettier --check` 两文件通过、`eslint` 两文件 RC=0、`jest src/tests/ci/ --runInBand`
**15/16 通过**（`testTreePurity` 因 `execFileSync('git')` 被 EBUSY 拦而红，属环境性假红，
且该套件只判"测试文件是否入库"，不涉及本次改动）。

### 运维脚本 E（2026-10-04 · 备份/恢复/密钥生成的失败面：容器侧那段命令第一次被真跑一遍，收紧失败第一次非零退出）

> 这一族的形状全都一样：**成功回显与失败信号在出口处不对账**。备份脚本对"一条都没跑"的异地命令
> 回显"已完成异地副本"；容器侧对一份 0 字节归档返回 0 并打印 `Restore completed successfully`；
> 密钥生成对"11 个文件一个都没收紧"照样退 0——三处都把没做过的事记成了做过。
>
> 方法上是本仓第一次让 `docker` **桩真的执行**容器侧命令（把 `-c` 后面那段交回 bash，容器内的
> `mongodump`/`mongorestore` 由 PATH 上的桩充当）。此前所有 docker 门禁只记 argv 与 stdin，
> 于是容器侧那七八行的缺陷谁都不判——注释里"用完即删""不落盘"都是没有实物的一句话。
> 新增断言一律配**前世版自证**（把脚本副本还原成修前形态，证明断言真能红）。

已落地：

| #   | 缺陷（读源码确认，非推断）                                                                                                                                                            | 改法                                                                                                                                                                 | 门禁（行为级，不是 grep）                                                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `backup-mongo.sh` 在 `case` **之前**无条件 `mktemp + 写入含口令的 URI`，而 docker 传输（默认）从头到尾没人读它 ⇒ 每次备份都在宿主盘上留一份 0600 明文口令                             | 配置文件挪进 `local` 分支按需创建；docker 分支只经 stdin 送 `uri:` 行                                                                                                | `backupFailureArtifactHygiene` C.1：docker 跑完 `"$TMPDIR"/*` 里**一个** `^uri: ` 结构的文件都没有；反向对照 local 恰好探到 1 个                                                                                                                                                               |
| ②   | 备份侧容器内路径写死 `/tmp/.mongodump-backup`，且 `cat`/`printf` 不判返回码（与 peer 已修的恢复侧同源）                                                                               | `mktemp` + 每步 `                                                                                                                                                    |                                                                                                                                                                                                                                                                                                | { rm -f "$cfg"; exit 1; }` | C.1 的 `DOCKER .*exec -T mongo sh -c` 自证 + 断言 argv 上没有口令字面量 |
| ③   | `BACKUP_OFFSITE_CMD` 含换行/回车时按"一条命令"解析只执行**第一行**，却把整份配置回显成 `Offsite copy completed` ⇒ 多行 env、CRLF 写的 env、误粘两条命令三种现场都记账为"异地副本已做" | 执行前拒绝（一条都不跑），并把 `\\r` 的 CRLF 出路点名                                                                                                                | C.2 三腿：多行/内嵌 `\\r` ⇒ rc≠0 且桩一次都没被调用、归档不被动；尾随单个换行 ⇒ 仍放行且回显文本逐字节等于那条命令（正向对照，防过度收紧）                                                                                                                                                     |
| ④   | `generate-secrets.js` 逐个收紧密钥文件时**丢弃返回值**，且目录级复核不通过也只 `console.log` 后 `exit 0` ⇒ `generate-secrets … && 下一步` 在密钥仍可被本机其他用户读写时继续推进      | 收返回值聚合成 `fileFailures` 点名清单；`check.tightened && fileFailures.length === 0` 之外一律 **非零退出**；产物保留不删（内容有效，毁掉只会把运维推向手搓随机值） | `filePermissionEnforcementAndVerify` 新 describe 5 腿：`node -r <preload>` 把 `src/utils/filePermission` 顶成可编程桩（真实宿主造不出"icacls 被拒"），目录失败/复核失败/仅文件失败三档各钉 rc=1 + stderr 点名 + 成功文案缺席；**前世版腿**：删掉返回值检查的副本在同一份桩下 rc=0 还打印成功行 |

同批的"探针"改造：宿主机凭据落点的探测从**按文件名**（`mongorestore-config.*`）改成**按内容结构**
（首行匹配 `^uri: `），与本批次前 peer 在 `restoreTransport.test.js` 里立的同一把尺子对齐——按名字探的是
"祸害叫什么"，改名即失明。

**押后（本轮不入库，见下方协调项）**：`restore-mongo.sh` 的两条同族修复——⑤ `RESTORE_SKIP_CHECKSUM=true`
把"哈希对不上"一起豁免（该开关的原意是"恢复本来就没有校验和的老归档"，实现出来却允许把一份已知损坏/
被替换的归档写进生产库；前者缺的是证据，后者是**反证**）；⑥ 容器侧固定名 + 不判返回码 + 0 字节归档被记成
一次成功恢复。改动与门禁都写好了并且是绿的（`backupEncryptionContract` 新增 3 腿 + 新文件
`restoreRemoteHardening.test.js` 7 腿，后者让 docker 桩执行容器侧命令，配 canary 预创建、两次运行路径互不相同、
0 字节拒收、空 stdin 停在 `read` 四个面，外加前世版翻转腿），但 ⑥ 撞上一条**已在 HEAD 里**的 peer 门禁：
`src/tests/deploy/restoreTransport.test.js:185` 字面钉死 `rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive`。
该文件的意图（"容器侧凭据用完即删"）在 mktemp 形态下依然成立，字面却必然失效；而它在我的改动范围之外，
工作树里还叠着同一位 peer 未提交的探测器改造——按行拆开提交做不到，于是整条 ⑥（连带只依赖它的 ⑤ 与两份测试）
押后，等那条字面 pin 换成判 `rm -f "$cfg" "$arch"` 之后单独入库。

协调项（交给并行会话或下一批）：

1. `restoreTransport.test.js:185` 的字面断言改成结构判据（清理了 `cfg`/`arch` 两个变量，而不是清理了某两个名字），
   随后 `scripts/restore-mongo.sh` + `src/tests/deploy/{backupEncryptionContract,restoreRemoteHardening}.test.js` 一起落地。
2. `deployment/backup-encryption.md` 里 `RESTORE_SKIP_CHECKSUM` 的口径要与 ⑤ 同步（文档现在描述的是"整段跳过"的旧语义）。

复跑事实：`src/tests/deploy` + `src/tests/security` 全量 **755 passed / 8 failed / 763**，两条红点各有其主——
`bundleBudget.test.js` 7 条是真实 `web-admin/dist` 的 `entryCssGzip 21900 B > 预算 19000 B`（并行会话新增
`apple-refine.css` 后重建产物而未重置基线，本批未碰任何前端文件）；`restoreTransport.test.js` 1 条即上面 ⑥。
本批相关 5 个文件 **67 passed**。`npx eslint src scripts --quiet` 0 项、`lint-ratchet` 通过（21 个含 warn 文件
均未超基线）、`check-utf8` 全绿（1061 个文件）、`prettier --check` 对改动文件全部通过。

### 供应链 D（2026-10-04 · 上一批的 21/21 变异矩阵被独立审计复跑出 9 条存活变异：逐条封红，并把"只有真实数据全对才绿"那一族补成夹具可证伪）

> 上一批自己写的变异矩阵（9+12 条）判的是"解析器/流程被改坏会不会漏"，但**漏掉了另一族**：
> 判据的输入在仓库里恰好是"全对"的，于是任何**削弱比较本身**的改动都没有实物能打红。
> 独立审计员逐行复跑后点名 9 条存活变异（下表 M/D 编号），其中两条正是"防投毒"链条上最关键的位：
> `repo` 判据放行了官方镜像的裸短名（第三个来源静默退化成两源），以及打印面把**硬报错**算进"可用"。

九条存活变异与本轮的封堵（每条都配了 arm，见下面矩阵）：

| 编号 | 原缺陷（存活原因）                                                                                                                                                   | 本轮改法                                                                                                                                                                                        |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M9   | `expect([shortName, 'library/'+shortName]).toContain(e.repo)` 二选一 ⇒ 官方镜像登记成裸短名照样绿，而 ECR 的 `map()` 靠 `library/` 前缀判托管 ⇒ "三源一致"悄悄变两源 | 改成 `repo` 由 `ref` **唯一决定**的 `toBe`；再加"声称用过 ECR ⇒ `map()` 必须给得出路径"的 ③ 号腿                                                                                                |
| M6   | digest 对账写成"长度不同才不符"仍全绿（表与文件全等，判据无实物）                                                                                                    | 对账逻辑抽成纯函数 `reconcile(refs, table)`，用**同长度、末位不同**的夹具 digest 直接打红；孤儿/陈行/不符三类各钉独立断言                                                                       |
| M7   | `sources`/`sites` 两列只判"非空" ⇒ 改成任意假话都绿                                                                                                                  | 新增一条可证伪用例：散文里所有像主机名的 token 必须**恰好等于**来源表里被点名的集合；点名数 ≥2；ECR 声称⇔可映射；`sites` 与扫描面**逐文件双向**对齐（多说不说都红）；引用点总数 `[1,1,1,1,2,3]` |
| M2   | `--only ,` ⇒ `split/filter` 得空数组（JS 里为真值）⇒ 六行全被排除 ⇒ 打印"核验 0 个引用 … 全部通过"退 0                                                               | 抽纯函数 `planRuns(argv, table)`，命中 0 行 ⇒ **退出码 2** 并点名"拒绝把空跑报成通过"                                                                                                           |
| M3   | `tag = ref.slice(ref.indexOf(':')+1)` 与 `lastIndexOf` 在真实六行上无差别（都只有一个冒号）                                                                          | 抽 `tagOf(ref)` + 端口夹具（`reg.example.com:5000/team/app:1.2.3` ⇒ `1.2.3`），另钉"真实六行切出的 tag 不含斜杠也不含冒号"                                                                      |
| D6   | 非 JSON 响应体走 `JSON.parse` 的原生异常文本 ⇒ 响应体前若干字符进日志（违反"外部响应体一律不回显"）                                                                  | `try/catch` 包住，报错只说"响应体不是 JSON（N 字节，内容未回显）"；用例同时钉 `not.toMatch(/<html>/)`                                                                                           |
| D13  | 打印面 `可用 = 非跳过的来源数` ⇒ **HTTP 500 / 非 JSON 的硬报错被算进"可用"**，`2/3（可用 3）`是给读者的一句话谎言                                                    | 分母改成 `应答`（拿到摘要的来源数），另起两位 `跳过 N，报错 1`；报错行前缀写"报错："。用例直接断言整行文本                                                                                      |
| D10  | `isIndex` 的 `every` 改成 `some` 存活（夹具只喂过"两条都单层"）                                                                                                      | 新增混合腿（一条 index + 一条单层）**两种顺序各判一次**：`ok` 必须 false，而 `agreeCount` 仍为 2（判据①与③不许混成一团）                                                                        |
| D5   | `judge` 不透传 `bytes` 时输出念 `undefined 字节`/`0 字节`，而用例只判 `/(\d+) 字节/`                                                                                 | `bytes` 过一道；断言改成**真实字节数**（"对返回字节自算 sha256"这句话唯一的实物证据就是它）                                                                                                     |

同批补强的三处（审计员另外点名的"判据依赖仓库内容配合"）：

- `workflowFileNames(names)` 从 `targetFiles()` 抽成纯函数并喂夹具：`.yaml` 分支在本仓**没有实例**，
  真实扫描面证不了它没写错；同时钉住"排序与 `readdirSync` 顺序无关"与噪音后缀（`yml`/`ci.yml.bak`/`x.YML`）。
- 永真断言替换：原来那条 `all.some(r => /<64 位 hex>|<捕获值>|示例/.test(r.value)) === false` 不可能红
  （扫到的 value 全都过了解析器）。改成**否定语料自证**：注释里带 `@sha256:` 的行按文件精确计数
  （Dockerfile 3 / compose 2 / deploy.yml 1），并断言它们既不进 `all` 也不进 `unreachable`——
  compose 的 mongo 段那条**反引号包裹的 `image: …<捕获值>`** 正是"注释排除一删就红"的实物。
- 替身自己也进判据：`resp()` 的大小写归一化在**存/取两面**各钉一条直接断言（删任一半就有用例红），
  外加 `ok` 的算法（404 false / 201 true）。上一轮的"header 各种大小写都要读得到"只在此之上才有意义。

退出码外壳（`process.exit(code)` 那一层）第一次进了门禁：`main(argv, table = EXPECTED)` 与
`planRuns(argv, table = EXPECTED)` 都接受表注入，于是"表本身写坏"与"命中 0 行"这两档在**触网之前**
就能被夹具判（真实仓库里表现在是好的，少这个注入点这两条分支永远走不到）；再用 `spawnSync` 真跑三次
脚本判 2 号路径的退出码与 stderr 文案，把"返回值→退出码"的接线也钉住（挑的都是不联网的分支，
所以门禁仍然离线）。

变异矩阵 **22 条 arm = 21 CAUGHT + 1 条刻意负对照**（`/c/tmp/mut-d.js`，跑完四个文件 sha1 逐字节还原）：
判据侧 arm（空跑守卫、`return plan.code`、`process.exit(code)`、`indexOf`、非 JSON 回显、分母把报错算进来、
`every→some`、`bytes` 不透传、下限归零、替身存/取不归一化 ×2）+ 数据侧 arm（官方镜像裸短名、
第三方命名空间被加 `library/` 前缀、表内 digest 末位改一位、`sites` 指错文件、`sources` 编造来源名、
声称用了 ECR 但其实不托管、compose 退回裸 tag）+ 闸自身（注释排除、对账退化成比长度、`.yaml` 分支）。
唯一一条"预期存活"是**负对照**：把 `repo` 判据退回二选一并同时喂"第三方命名空间被加 `library/` 前缀"
这条数据缺陷 ⇒ 13 条全绿，用来证明严格版 `toBe` 是唯一能抓它的判据，而不是装饰。

复跑事实（不联网的闸与联网的工具各一次）：`node scripts/verify-image-digests.js` 6 引用全 PASS、
**退出码 0**；本轮 `docker.1ms.run` 起效后 redis/mongo 为三源一致；`public.ecr.aws` 对 redis/mongo
仍**不发** `Docker-Content-Digest`（三态输出的实证），对 node 这一次直接 `fetch failed`——输出如实念成
`一致来源 2/2（跳过 0，报错 1）`，旧写法这里会念"可用 3"。散文里的取证数字第一次可复核：
`index 7 个条目`（mongo）与 `index 3 个条目`（grafana）与实测一致，其余来源逐条打印条目数与字节数。

未收（诚实清单）：

- `captured` 仍是人手写日期，闸只判形状。本批把 `sources`/`sites` 变成可证伪，但**取证日期**没有
  仓库内可对齐的事实来源（对表情的最硬约束是：某行 `sources` 写了 `public.ecr.aws` 而该 repo 在
  ECR 上不存在 ⇒ 红，见 ③）。
- "来源表三条腿全活"不是判据：某条腿抖动报错时，只要 ≥2 源一致脚本仍退 0（这是设计——独立性要求
  的是**运营主体不同**，不是三条全响）。`reasons` 会把报错的腿点名，但不改结论。
- `sources` 散文里的 `index N 个条目`只有 mongo/grafana 两条写了数字，本批不强制其余四条补齐
  （工具已经逐条打印，补不补只影响人读表时的方便）。
- `verify-image-digests.js` 仍不进 CI（联网门禁红了之后人先怀疑网络）。

同批收到两份独立逐行审计报告（`scripts/*.sh` 5 条：备份默认 docker 传输把全库口令写进宿主 `/tmp`
且无人读取、`RESTORE_SKIP_CHECKSUM=true` 连"校验和不匹配"一起跳过、`generate-secrets.js` 权限收紧
失败仍退 0、多行 `BACKUP_OFFSITE_CMD` 只跑第一行却宣布跑完、容器侧固定 `/tmp` 路径 + `cat` 不检查；
`src/services`+`src/controllers` 5 条：部门成员缓存无失效钩子导致 ≤30 s 跨部门可见、告警 `meta.total`
取自分页而 `hasMore` 在过滤前算、`rolePermissionController` 把畸形权限 ID 静默丢弃后整体覆写、
MFA 恢复码集 last-write-wins、`User.findById` 结果未守卫）。**本批未动这些文件**（属于并发会话在飞
范围与另一条链路），逐条自行复核后排入下一批。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 13 + `imageDigestVerify` 19 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **90 绿**（上一批 77）；元门禁 13 套 123 例
仅 1 红，且是 `ci/testTreePurity` 列出 7 份他人未入库的 `*.test.js`（本批只改既有用例文件，未新增）；
`ci/commentAnchorFreshness` 与 `ci/bareAnchorAttribution` 本轮**转绿**（他人会话已把 `runtime.js:88` 的
锚点同步到 `statsCache.js:147/157`）。`eslint src scripts --quiet` 0 error；`lint-ratchet` 通过
（21 个 warn 文件均未超基线，`main` 拆出 `planRuns` 后复杂度未升）；`check-utf8` 1050 文件通过；
prettier 对本批三个文件 `--write` 后 `--check` 通过。

### 供应链 C（2026-10-04 · 「全仓镜像都已钉版」第一次变成机器可判的账：6 个引用 × 3 处事实来源，配上不联网的两把闸）

> 上一批的诚实清单欠了三件事：compose 的 mongo / prometheus / alertmanager / grafana 与 `ci.yml`
> 的 service 容器还是可变 tag；三处"全覆盖式表述"是失实的；而"脚本能跑"与"文件真的钉完了"之间
> 没有任何东西在对账。这批一次性收掉：**引用面账**（`src/tests/security/imageReferenceInventory.test.js`）
> 把真实文件 ↔ 期望表 ↔ 脚本常量 ↔ 老闸字面量四处钉成同一笔账，**判据行为账**
> （`src/tests/imageDigestVerify.test.js`）把新工具的三条放行判据逐个做成可打红的用例。

钉版落地（本轮补 5 条，仓库内第三方引用至此 6 个 / 全部 `name:tag@sha256:<64hex>`，保留可读 tag）：

- `docker-compose.yml`：mongo `eb581912…`、prometheus `075b1ba2…`、alertmanager `e13b6ed5…`、
  grafana `079600c9…`（redis `858f009f…` 上一批已钉）；`.github/workflows/ci.yml` 的 service
  容器 mongo 与 compose **同一个 digest**（不同则 CI 是在"另一个 mongod"上跑绿的，而日志看不出区别）。
  `${APP_IMAGE:-fire-safety-app:local}` 是本机构建产物，不属于第三方供应链输入，分类器把它归"动态"。
- **取值不需要 docker**：新增 `scripts/verify-image-digests.js`（零依赖，只用 node 内置 `fetch`/`crypto`）
  对 registry 的 manifest 端点取**原始字节**自算 sha256——这就是该 manifest 的 digest，`Docker-Content-Digest`
  只作旁证不作结论。放行要三条同时成立：①自算值等于期望表值；②≥`--min-sources`（默认 2）个
  **运营主体不同**的来源给同一个值（`public.ecr.aws` 是 AWS 自己发布的 official 面，另两个是不同
  运营商的 Hub pull-through 缓存）；③拿到的必须是 manifest 列表 / OCI index——钉单层摘要等于锁死一个
  architecture。`captured`/`sources` 两列记录取证现场，不是装饰。
- 本批落地时与今日复跑都是三源/两源一致：**6 引用全 PASS（退出码 0）**。prom/grafana 只有两源
  是实测事实：ECR Public 对这些命名空间就是 404（不托管 ⇒ `skipped`，与"来源报错"分成两类，
  混同会把坏掉的 registry 路径念成"这条腿今天没说话"）。

两把新闸的判据（都不联网；联网核验仍是人跑一次的工具，理由见"未收"⑤）：

- `security/imageReferenceInventory`（9 条）：扫描面自证（8 个文件 / 11 条指令行 / byFile 精确到
  Dockerfile 3 + compose 6 + ci.yml 2 / 2 条动态 / 9 条 registry 引用，解析塌缩不许静默绿）；
  行分类器与钉版解析器各带**夹具**自证（13 例分类表 + 6 例拒绝表；注释排除、YAML 键大小写敏感、
  `image:` 后必须有空白、`(^|[^A-Za-z0-9_.-])image:` 词边界，都不靠仓库内容配合）；双向对账
  （孤儿引用 / digest 不符 / 期望表过期条目 / `present.size === EXPECTED.length`）；同 tag 必须同
  digest；`capture-image-digests.sh` 的 `NODE_TAG`/`MONGO_TAG` 与 `baseImageDigestPinned` 的字面量
  交叉对账，脚本管不到的 4 条引用点名列出。变异 **9/9 全红**（grafana 解钉、表内 digest 分叉、
  CI↔compose 分叉、解析器收大写、删注释排除、表里放不存在的引用、redis 写成序列项、大写 digest、
  `image:` 去空格），四份被改文件 sha1 逐字节还原。
- `imageDigestVerify`（10 条，`global.fetch` 替身）：judge 三条判据各自能单独把结论打回 false
  （含"两源一致但是单层"这一臂）+ `min-sources` 调大必须变红 + `headerMatches` 三态；fetchOne 的
  替身故意让 header 与字节摘要**不相等**，钉住"取的是字节"；单层响应体 `entries` 必须归 0（判据③
  唯一的输入）；Bearer 流程把 URL 序列与 `Authorization` 序列逐位钉死（少一步重试、或取 token 那步
  带上凭据都要红）；`realm=`/`Realm=` 两种写法都认，解析不出 realm 时报错而不是静默匿名直连；
  `token` 与 `access_token` 两个字段名都认。变异 **12/12 全红**，同样逐字节还原。

脚本侧顺手修掉的真缺陷（都是写用例时暴露的，不在"计划改"之列）：

- `anonymousToken` 按小写 `realm=` 匹配：registry 生态里 `Realm=` 真实存在，只认一种会让那条来源
  常年报"响应里没有 Bearer 挑战"，运维第一反应是怀疑网络而不是脚本。改为 `i` 匹配；同时它的旧注释
  写着"没有 realm 就当作公开端点直连"，而代码从第一版起就是 throw——注释失实已改（静默直连的产物
  是一个要鉴权的端点用匿名身份返回 401，最后被归因成"这个来源没说话"）。
- 旧结构是"先探测再取"：公开端点（来源表里两个都是）会为每个引用**把 manifest 下载两遍**，第一遍
  响应体整批扔掉。改成一次请求、非 200 才按挑战取 token 重试一次，重试目标仍是同一 URL、token 只流向
  `realm` 指定的地址。
- 输出侧把"来源没发 `Docker-Content-Digest`"念成"header 相符"——ECR Public 实测就不发这个 header，
  等于每轮三行假话。改成三态（相符 / 与自算摘要不符 / 来源未发），且认不出的值一律落到**不作断言**
  那一档（默认值不能是"通过"）。
- 新增上面那句三态判断立刻触发 `lint-ratchet` 的 `[complexity] 0→1` 回退（`main` 贴着上限 15）。
  拆出 `printVerdict` / `headerNote` 把复杂度降回基线，**没有**收紧基线。

口径同步（三处失实表述随本批改掉）：`docs/architecture.md` 原写"digest 待部署机捕获"（部署机什么都没
跑、值已经在仓库里 ⇒ 已是假话）⇒ 改为全部已钉 + 指路取值口径与对账闸；`.github/dependabot.yml` 的 docker 段补上第三处站点
（期望表，漏改由新闸判红）；`security/baseImageDigestPinned` 文件头原来只承认一条升级路径（部署机跑
`capture-image-digests.sh`）⇒ 补成两条，并明说本闸覆盖面早就不止 node/redis（它保留的是"三阶段同
digest"这条工具链漂移不变量与最早的两条字面量）。compose 里那条 `#（它 pull 之后把输出追加为…）`
示例行**故意留着**：它是 shell 脚本自证文案的一部分，删了脚本的说法就不成立了。

未收（诚实清单）：

- 本批不新增依赖 ⇒ 三个来源里两个是第三方缓存，独立性建立在"缓存不重打包"这个前提上，不是密码学
  证明。要证伪投毒只能把 digest 与上游签名（Notary / content trust）对上，本批不做。
- 期望表的 `captured` 是人手写的日期，闸只判形状（`^\d{4}-\d{2}-\d{2}$`）不判真伪；`sources` 列同理。
- `--only` 里写了表里没有的引用 ⇒ 退出码 2 并点名，但"新镜像进表"这件事仍靠人记得；`imageReferenceInventory`
  能抓到的是**文件里出现**而表里没有的引用，反向（表里有、文件里全删了）也能抓，靠条数相等那条。
- `verify-image-digests.js` 不进 CI：联网门禁红了之后人先怀疑网络，那正是最容易被人为绕开的形态。
  机器只保证仓库内四处事实来源对得上；外部事实变了要靠人跑一次，或等 Dependabot 把 tag 改掉触发红。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 9 + `imageDigestVerify` 10 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **77 绿**；`node scripts/verify-image-digests.js`
全表 6 引用 **PASS，退出码 0**；元门禁 18 套 239 例中 4 红，全部指向并发会话——`ci/testTreePurity`
列出的 7 份未入库用例里有 5 份是他人在飞的 `*.test.js`（本批 2 份随本批入库），另 3 条锚点红是
`src/services/statsCache.js` 顶部插入 35 行把 `src/constants/runtime.js:88` 钉住的
`publishInvalidate`/`onInvalidate` 从 **114/124 移到 147/157**，锚点与台账应由该会话同步（本批不代改
他人文件）。`eslint src scripts --quiet` 0 error（`AbortSignal` 是本仓 globals 白名单缺的一项，已补）；
`lint-ratchet` 通过（21 个 warn 文件均未超基线）；`check-utf8` 1049 文件通过；prettier 对本批全部文件
通过，工作树里两份他人文件仍未格式化（不代改）；`git diff -- Dockerfile` 为空（上一批已钉完），
`docker-compose.yml` 只动了本轮那 4 处 `image:` 与其注释块，`.github/workflows/ci.yml` 只动了 service
容器的 1 处。

### 供应链（2026-10-04 · 把上一批的脚本逐个改坏：五条真缺陷全都属于"把没做完说成做完了"，而闸的共同毛病是只会说"非零"）

> 这批的输入不是新代码，而是**对同日上一批落地的 `scripts/capture-image-digests.sh` 做变异测试**：
> 派三个子 agent 逐行审计，再手工把脚本一条条改坏，看闸会不会红。结果两边各中一处系统病——
> 脚本侧五条缺陷全在同一类上（**报成功而事情没做完**），闸侧的根病是**失败臂只判 `rc !== 0`**：
> 把整份脚本换成一个语法错误的文件时，14 条"必须拒绝"的用例全部照绿，因为它们不看是谁在说话。
> 下面每条都附复现形状，不读脚本也能验。

脚本侧（`scripts/capture-image-digests.sh`）：

- **①「够不着」只在整文件都够不着时才报**（最坏的一条）。分类器先看指令词、再取第一个字段当值，
  字段不属于本镜像 ⇒ `next`；这条 `next` 顺手把"值压根不在能锚定的位置上"也吞了。于是同一文件里
  一条 `FROM --platform=$BUILDPLATFORM node:22.14.0-alpine AS b` + 一条正常 `FROM` 时，前者被当成
  不相干的镜像行放过 ⇒ 打印"钉好 1 条 / 已替换并校验"，文件里**留着一条可变 tag**。compose 的
  `image: ${MONGO_IMAGE:-mongo:6.0.20}` 同形。修：含 tag 字面串却没取到值、且不是注释行 ⇒ 新增
  `unreach` 类 ⇒ 停手并给行号（`--platform=` 与变量展开都归到"指令行但取不到值"这一支）。
- **② 外部输出按行判 ⇒ 多行可以伪造脚本的判据**。`grep -Eq '@sha256:[0-9a-f]{64}$'` 是**按行**判的，
  而 `${raw%@*}` 取的是**最后一个** `@` 之前的全部内容 ⇒ `docker inspect` 返回"一行合法引用 + 任意
  一行"时，形状判据与仓库名判据双双通过；`--apply` 只是碰巧撞在 `sed` 的 unterminated s command 上，
  不加 `--apply` 则 rc=0 并把那一行**原样打进给运维的粘贴块**（把外部输出当代码用）。修：先要求
  **恰好一行**，行数不对就拒收，且**不回显内容**——多行输出可以伪造本脚本自己的日志行。
- **③ CRLF 行尾：同一输入在两台上是两种结果**。MSYS 的 gawk 与 GNU sed 会吃掉行尾的 CR（⇒ 整份
  部署文件的行尾被静默改成 LF 还报成功），Linux 的 gawk 留着 CR（⇒ 判成"形态不认识"而拒改）。
  检测必须走**字节**通道：本机 `grep -q "$CR"` 与 `awk '/\r/'` 对同一份文件都报 0 处，`od -c` 明明
  看得见 `\r`——文本模式在读取时就把 CRLF 换成了 LF。改成 `tr -dc '\r' < file | wc -c`，非零即拒，
  并把"请先把行尾改成 LF"作为可执行建议打出来。
- **④ 信号只清了残留，没有停下手**。`trap 'cleanup_pin_tmp' EXIT HUP INT TERM` 里那三个信号句柄跑完
  清理就**继续执行**：运维按 Ctrl-C 之后脚本照样把两个目标文件写完、照样打印"已替换并校验"、照样
  rc=0（在 15MB 夹具上实测：SIGINT 之后两个文件都已落盘）。修：`on_signal` 清理之后
  `exit $((128 + sig))`；实测 SIGTERM ⇒ rc=143、两文件逐字节原样、无 `*.pin.tmp`。
- **⑤ 全文刷新缺名字边界 ⇒ 两种真实损坏**。`s%tag@sha256:[0-9a-f]{64}%…%g` 不带边界时：
  前无边界会把 `myorg/mongo:6.0.20@sha256:…`（别人的命名空间）里的同名子串当成自己的引用改掉，
  注释从"别人的仓库"变成一张假证；后无边界会把 `@sha256:` 后面 68 位十六进制的前 64 位换掉、
  留下 4 位尾巴，产出一行**看起来完全合法**的钉版引用。修：两侧各加边界字符类
  `(^|[^A-Za-z0-9._/:@-])` / `([^0-9a-f]|$)`，定界符仍是 `%`（`|` 是 ERE 的选择运算符）。

闸侧（`src/tests/imageDigestGate.test.js`，38 → **54 用例全部真跑**）：

- 失败矩阵 14 → **25 臂**，每臂判**精确退出码 + 原因文案（逐行匹配 `^错误：`）+ `第 N 行` 的行号契约**
  再加共同后置条件（两目标逐字节不变、不留临时文件）。新增臂：digest 只有 63 位 / 只有 8 位 /
  大写十六进制（三条各**只违反一件事**——旧夹具 `sha256:short` 同时违反字符集与长度，于是删掉 `{64}`
  或放开大写都不会红）、多行 inspect 输出、CRLF、命名空间前缀、`image:` 后无空白、混合写法两臂、
  缺目标文件两臂（"不存在"与"够不着"是两条不同的臂）。
- **差分语料三条**：输入 → 脚本自己声明的处置计划（`待钉 N 条、待刷新 M 条、已是本次 digest K 条`）
  → **逐字节期望产物**，三格同时判，并加两条越界自证（改动行必须都含 tag 字面串；行数不许变）。
  这是①和⑤那类"少报一笔 / 多改一笔"唯一的交集防线——按形态写的判据两边都看不见。
- docker 调用**序列**断言（`info → pull node → pull mongo → inspect node → inspect mongo`）取代
  `calls.length >= 4`：条数挡不住"从不 pull mongo 就直接 inspect"（本地恰好有旧镜像时照样拿到 digest，
  钉上去的是过期摘要）。
- **SIGTERM 用例**：docker 替身每次睡 1 秒（整轮约 5 秒），驱动脚本在第 1 秒发信号——那一刻离第一次
  落笔还差整个 capture + 分类阶段，所以"信号之后文件有没有被动"是稳定差值而不是竞速。
- `findShell()` 探不到带 awk/sed 的 sh 时整组 `describe.skip`，等于 54 条零断言的绿 ⇒ CI 上单独一条红
  （ubuntu runner 一定有 `/bin/sh`，探不到就是探测本身坏了）。
- `run()` 读目标文件改成缺文件返回 `null`：否则"脚本没碰它"和"那个文件根本不存在"会混成同一条异常。

未收（诚实清单）：SIGTERM 用例的时机靠"裕度 3 秒"而不是同步点——若 runner 上 `sleep` 被替换成
非阻塞实现，它会退化成竞速，这条得盯；`.sh` 依旧不在 eslint/prettier 覆盖内（无 parser、本批不新增
依赖），脚本的验证手段只有 `sh -n` + 本文件真跑；两条 `mv` 之间不原子。上一批那条"未收"仍然成立：
compose 的 mongo / prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器
都还是可变 tag（没有 `docker pull` 证据就不臆造 digest），三处全覆盖式表述要和下批的镜像引用面账
一起改。

验证：`sh -n` 通过；`npx jest --runInBand src/tests/imageDigestGate.test.js` = **54 绿**（含 SIGTERM
腿实测 rc=143）；`security/baseImageDigestPinned` 4 绿、`ci/commentAnchorFreshness` 13 绿、
`ci/codeViewPhantomLedger` 5 绿（共享 helper `jsCodeOnly` 的幻影已被并发会话修到 0，本文件在旧台账里
的 32 行登记项随之消失——那份修复此刻还在工作树里未提交，若被回退这把闸会自己红，不会静默放行）。
`deploy/deployScript` 56 绿；`eslint --quiet` 0 error、`lint-ratchet` 通过（21 个 warn 文件未超基线）、
prettier 与 `check-utf8` 通过（1042 文件）；`git status -- Dockerfile docker-compose.yml` 为空 ⇒
本轮全部 `--apply` 都跑在 `--root` 临时根里，真实部署文件逐字节未动。

### 供应链（2026-10-04 · 唯一能修"半钉仓库"的脚本自己拒绝再跑：已钉从报错改成按目标跳过，digest 刷新与"够不着就停手"补齐）

> 起点是 `src/tests/security/baseImageDigestPinned.test.js` 的文件头——它把升级路径写成
> "在部署机跑 `scripts/capture-image-digests.sh` 重新捕获，再同步闸里的字面量"。上一轮把产物
> 口径与双 digest 修好之后，这条路径**仍然一步都走不通**：check 阶段把"这一行已经是
> `tag@sha256:…`"当成错误直接退出。而本仓库今天的真实状态恰好是混合仓库——Dockerfile 三条
> `FROM` 全钉死、compose 的 mongo 没钉 ⇒ 脚本在第一个目标就停手，永远到不了需要它的那个目标。
> 也就是说闸的注释把自己否证了：它点名的唯一工具，对着真实仓库跑必然红。
> 实测入口很简单：`sh scripts/capture-image-digests.sh --apply` 在本仓库根跑一次即可复现。

> 第二类更隐蔽，是"报告成功而什么都没做"的**反向版本**。判"这条引用够不够得着"用的是无锚定
> 子串计数，而替换用的是锚定正则——两套口径不同，于是这些形态被判成"可改"、进了落笔分支，
> 替换却一条都不匹配（`sed` 无匹配仍然 rc=0）⇒ 打印"已替换并校验"，文件一字未改：
> `FROM --platform=… node:22.14.0-alpine`（值不在能锚定的位置）、compose 的引号包裹值
> `"mongo:6.0.20"`、序列项 `- image: mongo:6.0.20`、折叠标量、`${MONGO_IMAGE}` 变量展开、
> `node:22.14.0-alpine @sha256:…`（tag 与 `@` 之间夹空白）、以及无 tag 的纯 digest 钉版
> （旧上一版脚本自己写坏出来的形态）。每一类都留下同一个后果：仍指向可变 tag 的引用被当成
> 已固定提交上去。

修（`scripts/capture-image-digests.sh` 的 check→stage→commit 三相，判据从"数子串"换成"分类值 token"）：

- **单遍分类器**（awk，只限 POSIX 构造，CI 的 mawk 与本机的 gawk 同结果）：按"行首 = 可选缩进 +
  指令词（`FROM` / `image:`）+ 空白"锚定，取整个值做 token，再按镜像名（剥 `@…`、剥最后一个 `/`
  之前的仓库名与 tag）过滤掉不相干的镜像行——redis / prometheus / `${APP_IMAGE:-…}` 不会被误判。
  值分四类：`待钉 bare`、`已钉 same`、`待刷新 refresh`（钉在**别的** 64hex 上）、其余一律
  `够不着` ⇒ 立即停手、零写入、只打**行号与形态名**（不回显整行）。分类器只按脚本顶部的 tag
  常量精确匹配，不做模糊猜测；指向本镜像的引用一条都找不到同样报错（脚本常量与仓库漂移是
  另一类事故）。
- **按目标跳过，而不是整体报错**：`same` 让该目标原样不动并明打"本次跳过（不改动）"，
  混合仓库因此能收敛（已钉行一笔不碰、未钉行钉上）；`refresh` 让滚动同名 tag 换 digest 的升级
  路径真的存在。**整体 no-op 仍然是错误**（两个目标都 `same` ⇒ 红），保住"报告成功但一字未改"
  那条老缺陷的判据。
- stage 用两条 `sed -E` 表达式：① 锚定的裸 tag 追加本次 digest；② 全文 `tag@sha256:<64hex>` →
  本次 digest，**故意不带锚定**——Dockerfile 顶部的用法注释里也写了完整钉版引用，只改指令行会把
  "正确示例"变成"错误示例"，而那正是本脚本要躲开的第一类失效。产物先落 `*.pin.tmp`，再用**同一个
  分类器复查预演结果**：仍残留 `待钉`/`待刷新`、或指向本镜像的条数变了 ⇒ 删临时文件退出；
  分类说"要改"而 `cmp` 判逐字节一致 ⇒ 报"分类与替换不一致"退出（这是自我矛盾探测器，不是保险丝）。
  commit 阶段 `mv` 之后对盘上的真实文件再 classify 一次。两个 `mv` 之间不是原子的，这条边界
  明写在脚本注释里，没有假装成原子替换。
- 计划可见：check 阶段就打印每个目标"待钉 N 条、待刷新 M 条、已是本次 digest K 条 ⇒ 会改动/跳过"，
  跑之前就知道这次动哪几条。

本轮实测到、并写进注释当教训的三处自身缺陷：POSIX sh 没有 `local`，`classify_ref` 覆写全局
`file` ⇒ `cmp -s "$file" "$tmp"` 变成"临时文件与自己比"，每一次合法运行都被报成"逐字节一致"；
`plan_ref` 读的是全局计数，两个目标都 probe 完再统一打印 ⇒ compose 的计数被打在 Dockerfile 标签下；
`sed` 用 `|` 作定界符与 ERE 的选择运算符撞车（`unknown option to 's'`）⇒ 换成 `%`（registry 引用
文法不含 `%`）。

闸（`src/tests/imageDigestGate.test.js`，38 用例全部真跑，PATH 插 docker 替身，不用扫源码文本）：
失败矩阵从 7 臂扩到 14 臂，新增 6 条"够不着"臂（`--platform=`、夹空白、无 tag 纯 digest、
引号包裹、序列项、折叠标量、变量展开），共同后置条件是**目标文件逐字节不变 + 目录里没有
`*.pin.tmp`**；表宽自证同步改成 14（jest-each 少喂一格是超时假绿，不是失败）。新增成功腿：
混合仓库（已钉的 DF 一笔不碰、compose 钉上、打印"跳过"）、`refresh`（含注释示例自愈、断言旧
digest 不再出现在文件里、复跑判 no-op）、单行内混合收敛、`FROM  node:…` 双空格；命名空间腿把
脚本的 `repo_of_ref`/`norm_repo` 抽进 sh 夹具跑 7 个真实引用（`node`→`docker.io/library/node`、
`prom/prometheus`、带端口的 registry 必须保留原样，反向 2 例必须 REJECT）并断言 ACCEPT 集非空——
只比末段会把别人的仓库当成自己的。零串扰自检保持：真实 `Dockerfile` 与 `docker-compose.yml` 的
base64 前后相等，本轮实测 `git diff -- Dockerfile docker-compose.yml` 为空。

未收（诚实清单，留作下一批）：compose 的 mongo 本身仍未钉（本轮没有 `docker pull` 证据，不臆造
digest），prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器同理；
`baseImageDigestPinned` 的标题、compose 里"digest 由部署机 docker pull 后捕获追加"的注释、
`docs/architecture.md` 的"镜像钉版本：node、mongo"这三处**全覆盖式表述**与上述现状不符，
要和那份清单同批一起改成可核对的范围。`.sh` 不在 eslint/prettier 的覆盖里（无 parser），
本文件的验证手段只有 `sh -n` + 真跑。

验证：`sh -n` 通过；14 形态探测（临时夹具 + docker 替身，digest 用假值）全 PASS，且每次成功之后
复跑都被判 no-op 红；对真实仓库跑 dry 分类 ⇒ 三条 `FROM` 与三处注释引用识别为待刷新，
redis/prometheus/alertmanager/grafana/`${APP_IMAGE}` 与 Dockerfile 的散文行一笔不碰；
`npx jest --runInBand` 跑 `imageDigestGate` + `security/baseImageDigestPinned` +
`ci/commentAnchorFreshness` = 55 绿、`deploy/deployScript` = 56 绿、`ci/codeViewPhantomLedger` 绿；
`eslint src scripts --quiet` 0 error、`lint-ratchet` 通过、prettier 与 `check-utf8` 通过。

### 运维手册（2026-10-04 · 轮换手册 ① 发的 cookie 名服务端根本不读，"旧令牌必须立即失效"是一项不可能失败的检查）

> 起点是运维侧 P2-3（`deployment/secret-rotation.md` 的 L-01 ①）。复现只需一次函数调用：
> `extractAccessToken({headers:{cookie:'accessToken=X'}})` → `null`，而
> `extractAccessToken({headers:{cookie:'access_token=X'}})` → `X`。服务端只有
> `ACCESS_COOKIE_NAME='access_token'` 这一个名字（`src/utils/cookie.js` 的导出，
> `src/middleware/auth.js` 的 extractAccessToken 是 /api/auth/me 上 authenticate 的第一步），
> 手册却教运维发 `accessToken=`——名字对不上时走的是 `AUTH_TOKEN_MISSING`（"没带令牌"），
> 而轮换真正生效时走的是 `AUTH_TOKEN_INVALID`（验签失败），**两者同为 401**
> （`src/utils/errorCodes.js` 里两条的 status 都是 401，这条前提已被钉进用例）。
>
> 于是这项检查有两层失效，第二层更根本：判据只写"预期 401"、没有轮换前的正向对照，
> 匿名请求同样 401。**"检查通过"与"检查没跑"输出完全一样**，这样的判据不是弱，是零。
> 换句话说：即便当初把名字写对了，这一条也什么都没证明。
>
> 修（`deployment/secret-rotation.md` ①）：名字改回 `access_token`；补轮换前的同命令对照
> （必须 200，不是 200 就先修命令别开始轮换）；判据从状态码换成 `errors.errorCode`，
> 并把三种 401 的读法写进手册——`AUTH_TOKEN_INVALID`＝旧密钥确实没了、
> `AUTH_TOKEN_MISSING`＝令牌没被读到（不是轮换成功的证据）、`AUTH_TOKEN_EXPIRED`＝样本本来
> 就过期，证明不了任何事，重新登录换令牌再测。
>
> 闸（新增 `src/tests/deploy/runbookCheckCanFail.test.js`，7 用例）守两条同根判据：
> **A 是行为重放而不是字符串比对**——文档里每条 `Cookie: <name>=…` 与 `curl -b <name>=…`
> 的名字拼成真实请求头喂给服务端读取点（access 走 extractAccessToken，refresh 走四处共用的
> `getCookies(req)[REFRESH_COOKIE_NAME]`），断言取得回值；合法名集合由 `src/utils/cookie.js`
> 的 `*_COOKIE_NAME` 导出派生，且**每个导出名必须登记一条读取点**（加名不登记即红，闸不另立
> 第二份清单）。**B 是"负面判据必须自带对照"**——代码块里出现 401/403 时同块必须有 200 级
> 正向对照或同一状态码下可区分的 errorCode/AUTH_* 码。覆盖域沿用 runbookSecretSource 的
> "说明书"口径，刻意排除 CHANGELOG/deliverables/docs/adr——本条 CHANGELOG 里写着的
> `accessToken=` 是证据，不是指令。端点归属（把 refresh 发给 /me）是已声明的边界，不收。
>
> 变异（真文档上跑，每次只动一处，跑完逐字节还原）：把 ① 的名字改回 `accessToken` ⇒
> **恰好 1 红**（判据 A）；把 ① 整段还原成缺陷形状（只留"预期 401"）⇒ **恰好 1 红**（判据 B）。
> no-op 基线 7/7，扫描器不是空的（前提自证：真文档 ≥1 条 Cookie 名且必须来自被修的文件）。
>
> 验证：新闸 7/7；`ci/commentAnchorFreshness` + `testTreePurity` + `src/tests/deploy` 全套
> 400/407 绿，7 处红**全部**在 `deploy/bundleBudget`（并发会话正在改 web-admin，
> 前端产物超出现有预算基线；与本批无关，本批一个字节都没碰前端）；
> eslint 0 error；prettier 对新文件与手册均 unchanged。服务端代码零改动——
> 缺陷在文档，闸把文档接进了代码。

### 供应链（2026-10-03 · `capture-image-digests.sh` 的产物会被本仓自己的钉版门禁判红，还会把已钉过的行改成双 digest）

> 起点是运维侧 P2-4（"脚本在已钉版仓库上不可操作"）。复现成立，但**失效方向判反了**：
> 它不是拒绝工作，而是**开心地工作并打印成功**。2026-10-03 对着本仓库真实的
> `Dockerfile`（三条 FROM 都是 `node:22.14.0-alpine@sha256:9bef…`）抽出脚本的
> `check_ref` / `stage_ref` 单独跑：check 返回 0（放行），stage 产出
> **3 条 `@sha256:[0-9a-f]{64}@sha256:` 的双 digest**，脚本随后打印"已替换并校验"。
> 根因是一句无边界的前缀匹配：钉版形态**仍然包含**脚本常量 `FROM node:22.14.0-alpine`，
> 于是 `grep -qF "$old"` 把"已经钉过"读成"还能改"，`s|$old|$new|g` 再在它前面插一个新 digest。
>
> 顺着这条线查下去撞出第二类、也更严重：**`RepoDigests[0]` 天生不带 tag**
> （`docker.io/library/node@sha256:…`，本仓 2026-10-02 已实测），而旧实现把整串当引用写入，
> 产物就是无 tag 的 `FROM docker.io/library/node@sha256:…`。本仓的钉版口径是**保留可读 tag**
> ——`baseImageDigestPinned.test.js` 的 FROM 判据 `/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/`、
> `deploy/deployScript.test.js:118` 的 `<repo>:<tag>@sha256:…`、`docker-compose.yml:159` 的
> "纯 digest 看不出版本，排障时得先 inspect"三处同源，真实文件也全是这个形态。
> 也就是说 `baseImageDigestPinned` 的文件头把"跑这个脚本重新捕获"写成升级路径，
> 而**照这条路跑一次，红的一定是它自己**。这个矛盾在审计复核第 20 轮 §A3 已判过、
> 挂在"等拍板"上；本轮按证据收敛（口径由 3 处文档/闸 + 全部真实文件定死，不是二选一的风格题）。
> 顺带更正第 20 轮的一句推断：它写"改成追加式之后双 digest 自然失去土壤"——**恰好相反**，
> 追加式的产物 `tag@sha256:…` 正是 `tag` 的前缀扩展，边界判据从此是承重墙而不是保险丝。

- `capture_digest`：**只取 `@sha256:<hex>` 尾巴追加到 `$tag` 上**，不再回传 RepoDigests 原文；
  另加仓库名一致性校验（`docker.io/library/node` 对 `node` 放行，`…/alpine` 对 `node` 拒绝）——
  追加式写法若拿到的 digest 其实属于别的镜像，写出去的就是"这个 tag 指向那个 digest"这个
  不成立的断言，只能等构建期 pull 才炸。形状判据（`@sha256:[0-9a-f]{64}$`）拦不住它，实测过。
- `check_ref` / `stage_ref`：子串判据换成**边界口径**——"含 `old` 的指令行数 − 含 `old@` 的
  指令行数 > 0"才算可改，替换用 BRE 把 `old` 锚在空白或行尾（`\([[:space:]]\)` / `$` 两式）。
  于是"已钉 Dockerfile + 未钉 compose"这个**本仓库今天的形状**从"改坏还报成功"变成
  早退报错、逐字节不变、不留临时文件；混合仓库（有的阶段钉了、有的没钉）则一笔不碰已钉的、
  只钉未钉的，且改完再跑会正确报 no-op 而不是二次污染。
- 打印口径与脚本头部注释同步改为"直接可用于 `name:tag@sha256:<hex>` 的钉版引用"，
  收尾提示补上那条会把矛盾的闸（`npx jest src/tests/security/baseImageDigestPinned.test.js`）。
- `src/tests/imageDigestGate.test.js`（实跑 19 → **27 格**）：删掉那条把错误口径钉成**必要条件**的
  旧断言 `expect(r.dockerfile).not.toContain('node:22.14.0-alpine')`——它正是两道闸互不相容
  却各自全绿的成因；替身补 `qualified`（全限定 RepoDigests）与 `wrongname` 两个模式，
  新增 6 格：产物形态按**闸的原判据**逐条 FROM 实跑、短名与全限定两种 docker 名号收敛成同一串、
  "已钉 Dockerfile + 未钉 compose"现场必须报错、混合仓库只钉未钉的那条且二次运行不再污染、
  名号对不上必须拒（含"换回 node 就放行"的反向自证）；
  前缀陷阱另配一格前提自证（把 `@` 换成空格时三条判据必须同时翻转）。
  失败矩阵 5 → 7 臂，表宽用例改为 `widths: [4]` + `rows: 7`，行数本身也在台账里留痕。
- 变异证明（每个变异体跑整套，跑完即还原）：**M1** 判据+替换回到无边界 ⇒ 6 红
  （含两条新格与"幂等重跑""compose 漂移不留半钉"）；**M2** 直接回传 RepoDigests 原文 ⇒ 6 红
  （含"产物形态按闸判据"与"名号口径无关"）；**M3** 去掉仓库名校验 ⇒ 恰好 2 红（wrongname 两臂）。
- 验证：`imageDigestGate` 27/27；邻近两闸 `baseImageDigestPinned` + `deploy/deployScript` 60/60，
  注释锚点闸 `ci/commentAnchorFreshness` 13/13；`sh -n` 通过；eslint 0 error；prettier 对测试文件 unchanged。
  真实 `Dockerfile` / `docker-compose.yml` 一个字节未动（套件里有 sha 前后比对兜住）。

### 安全（2026-10-03 · 审计链核验脚本把"报告里已见的缺口"在出口处丢了，PASS 照打）

> 起点是运维侧一条待核判断（P1-1）。我自己复现了一遍，成立，而且比原判据更宽：
> 漏传的不止一个脚本。现场（`node scripts/verify-audit-chain.js` 对着真库）——
> 链尾一条 `hashFailure` 记录（写侧算 hash 抛错后照常落库，`AuditLog.hashFailure` 的既定形态）：
> 报告 `total=3 breaks=0 legacy=0 hashComputeFailed=1`，
> 而 CLI 打 `VERDICT: PASS（全量、无断裂、hmac 已校验）`、**退 0**。
> `deployment/rollback-drill.md:111` 与 `deployment/secret-rotation.md:397` 正是拿
> "退出码 0"当验收条件的那两步，于是链上不可追认的缺口穿过了验收。

- `scripts/verify-audit-chain.js`、`scripts/resign-audit-chain-v3.js` 各补一行
  `hashComputeFailed: <report>.hashComputeFailed`。判据（`computeChainVerdict`）这一格
  本来就有实现且正确，**坏的只是调用方**：`src/controllers/auditController.js`、
  `src/services/auditChainMonitor.js` 都回传了，两个运维脚本没有。
  修复后同一现场 ⇒ `INCOMPLETE` 退 2（复现脚本前后各跑一次，只差那一行）。
- 判据 `hasUnattestableGapOf` 的 JSDoc 里那句**失实前提**已就地更正：原文写"它由
  verifyAuditChain 恒回填，唯一漏传路径是旧调用方"——实测两个现役调用方就在漏传，
  而报告确实恒回填该字段。缺省方向（漏传按 0）**保持不变**：把它翻成 fail-closed 会让
  判据对任何不带该字段的调用报 INCOMPLETE，而真值表用例与在线侧构造的字段子集调用都属
  正常用法；本仓对"未来调用方漏传"的既有机制是逐调用点门禁，不是把判据调瞎。
- `src/tests/verifyChainExitCode.test.js` 把原来那份**硬编码三个文件名**的 scanned 回传断言
  换成**全仓枚举**（`src/` 去 tests + `scripts/`，按花括号配对取出每个调用点的对象字面量，
  逐个查 `scanned` / `hashComputeFailed`；纯 `computeChainVerdict(外部对象)` 形态按
  "静态看不见字段"点名）。实测 4 个调用点，全部合规。新增 CLI 端到端一格：
  真库真链尾真 `hashFailure` ⇒ 先自证"报告看得见缺口且不是篡改"，再验退 2、理由点名缺口、
  **绝不出现 PASS**，且 `--allow-empty --allow-no-hmac --allow-all-legacy` 三个豁免同时给也盖不住；
  `finally` 还原后必须回到退 0。
- 变异实测（不是推演）：删掉 CLI 那一行 ⇒ 枚举闸、CLI 端到端、scanned 那格**三条一起红**；
  删掉 resign 脚本那一行 ⇒ 枚举红并点名该文件。两处都已还原（`grep -c` 各 1）。
  反向自证 4 形：少 `scanned`、少 `hashComputeFailed`、同文件第二个调用点漏传、
  非字面量调用，各自都被点名。
- `scripts/verify-audit-chain.js` 头注释的退出码清单补上第五类不完整（缺口无任何豁免口子），
  此前它只列了截断 / 无 hmac / 空集合 / 整窗无哈希四类。
- 验证：`verifyChainExitCode` + `auditChainGuardedIntegrity` 45/45；
  `commentAnchorFreshness` 13/13（新增的 4 处引用都取到实文件实行号）；
  `npm run lint` 0 error、`lint:ratchet` 通过（21 个 warn 文件未超基线）；prettier 已格式化。

### 质量（2026-10-03 · 「任何新增验签入口都必须引用同一份判据」这句话，判据是注释而不是代码）

> 读 `src/utils/tokenPurpose.js` 时发现它的收敛承诺没有闸：
> `src/tests/utils/tokenPurposeAndConsumers.test.js` 的「三个入口都引用 utils/tokenPurpose」
> 用的是**手写死的三个文件名**。它证的是"这三份今天还引用着"，不是"没有第四份"——
> 新增一处 `jwt.verify(t, config.jwt.secret)` 而忘了用途闸，两个闸都照常绿。
> 而同一个文件里其实已经有全仓扫描的机器（另一条用例扫的是"不许内联写第二份 type 比较"），
> 只是没扫这一维。

- 新增 `src/tests/security/tokenPurposeEntryInventory.test.js`（7 格）：**枚举** `src/` 下所有
  用 access 密钥验签的调用（剥注释后按调用点判，`refreshSecret` 那一侧不算），未引用判据的
  必须出现在豁免表里。实测全仓 5 处：`middleware/auth.js`、`services/tokenService.js`、
  `services/websocketService.js` 引用判据；`middleware/logoutAuth.js`、`services/authService.js`
  是豁免。清单钉成**双向**不变量：多一处红、少一处也红。
- 两条豁免各绑一条**行为**用例，不是文件名白名单：
  · 登出入口那次未套判据的验签只决定"走哪条身份通路"，权威判定仍在 `authenticate()` 里 ——
  拿 `type:'refresh'` 的载荷用 access 密钥签（= 两把密钥被配成同值时攻击者手里的东西）打
  `/logout` ⇒ 401 且错误码必须是 `AUTH_TOKEN_INVALID`（换成"缺失/过期"那两条 401 本用例就
  指错了方向），并且 `req.user` 根本没被构造；
  · 吊销路径少一道用途闸的失效方向是**多吊销一条**而不是**多放行一个** —— 同形态串填进
  `revokeTokensOnLogout` 的 `accessToken` 槽 ⇒ 唯一的副作用是写黑名单。
  哪天有人改动让根据不再成立（比如在吊销路径上开始用 payload 构造身份），红的是这两条行为用例，
  不是清单。
- 反向自证 + 实跑 mutation：给分类器喂一段"没引用判据的 verify"与"引用了判据的 verify"，
  两者必须给出相反答案，且注释里提到的 `jwt.verify` 不算入口；再把一个合成入口临时写进
  `src/utils/superAdmin.js` 真跑一次 ⇒「清单逐条归队」与「规模钉住」两条立刻红并点名
  `src/utils/superAdmin.js ⇒ jwt.verify(t, config.jwt.secret, …)`，随后恢复原文件（`git diff` 空）。
- `src/utils/tokenPurpose.js` 的头注释补上这句承诺现在由谁执行，并把实测的 5 处入口写进去。

### 安全（2026-10-03 · 轮换手册把**两代**真凭据指向一个没被忽略的目录，而生成器"缺哪个补哪个"）

> 触发形态直接写在手册里：`deployment/secret-rotation.md` 第 1 步 `generate-secrets.js
--out ./secrets-new`（即将上线的那套），第 4 步 `mv ./secrets ./secrets-old`（刚刚下线的
> **全套生产密钥**）。而 `.gitignore` 当时只有 `secrets/` 一条——目录名不同，一条都挡不住；
> 本仓库是公开仓库，轮换做完那天一次 `git add -A` 就把新旧两代凭据一起推上去。
> `.dockerignore` 同族：docker 的忽略模式按**整段路径**匹配，`secrets` 匹配不到 `secrets-new`，
> 所以一次 `docker compose build` 会把两代真凭据送进构建上下文（镜像层里删不掉）。

- `.gitignore` 加 `secrets-*/`、`.dockerignore` 加 `secrets-*`，各带一句"为什么不是 `secrets`"。
- 新增 `src/tests/deploy/secretCarriersIgnored.test.js`（14 格）。要点是**哪些目录会装凭据不写死清单**，
  而是从手册/compose/README 自己的文本里抓 `--out <dir>` 与 `mv <src> <dst>` 两种入口：
  将来文档新起一个 `./secrets-staging` 而忘了忽略，本闸变红；写死清单则它永远绿着，
  而漏的恰好是那个新名字。git 侧的"是否被忽略"交给 `git check-ignore` 本身（与
  `scripts/mongoUri.sh` 同一条规矩：判据按参考解析器怎么读来定），并配一条**反向自证**
  （同一条命令对没被忽略的目录回 1）——否则探测器坏掉时全部用例会一起假绿。
- `generate-secrets.js` 前置检查 A（落盘之前问 git）：`--out` 目标在仓库内而 git 不认它被忽略
  ⇒ 退出码 1，**一个文件都不写**。退出码逐档实测：0=命中规则；1=在仓库内但不报忽略；
  128=判不了（仓库外 / 容器里没有 `.git` / 没装 git）。只有 1 拒，128 只把"没判成"说出来——
  拦下一条轮换/DR 路径换来的安全性是负的。判 git 时的 cwd 取**目标最近的已存在祖先目录**
  而不是调用方所在目录：`--out ~/keys` 而家目录本身是个 dotfiles 仓库时，用调用方 cwd 会一律
  判成 128 而放行，而那正是必须拦的形状。
- rc=1 其实合并了**两**种形态（都实测，话术两种都点名）：没有规则命中它；规则有了但文件
  **已经在 index 里**（先 `git add`、事后才补 `.gitignore`）。第二种更要紧——它就是"密钥已经
  进了公开仓库"的状态，所以这里**刻意不加** `--no-index`。这条加没加不是风格问题，实跑过：
  加上后前置检查 A 放行，`--force` 一路 rc=0 把已入库那颗 `jwt_secret` 覆盖成新生成的随机值
  （历史里一份、工作目录里另一份，且再没有任何一环报警）。用例把这一格钉住，含"旧字节必须
  原样还在"与"`--force` 也救不了"两条断言。
- `generate-secrets.js` 前置检查 B：目录里已有密钥时不再"缺哪个补哪个"。原实现逐个
  `已存在，跳过`，一次中断后的重跑会产出**混合代次**目录——多数密钥彼此独立看不出来，但
  `mongodb_uri` 是把 `mongo_root_password` 拼进去生成的：mongo 初始化用旧口令建用户、应用拿
  对不上号的连接串连库，轮换"成功"结束后第一次连库就认证失败，而现场证据是两份刚生成的
  0600 文件。现在要么 `--force` 重做整套、要么拒绝；用例在 `--force` 之后现场断言
  `mongodb_uri` 里拼的就是同目录那份 `mongo_root_password`，把这对耦合写成判据而不只是注释。
- 两处**自我纠正**（都因为"注释不执行"）：① 我先前在注释里写"用目录名探测会假绿"，实测三组
  形态（`s/`、`s/`+反向 `!s/jwt_secret`、文件先入 index 再补规则）里目录名与文件名探针的命中
  结果**完全一致**，那句是没取证就下的结论，已删；② 拒绝话术原本指向手册的「失陷处置」小节，
  而 `secret-rotation.md` 里根本没有这一节（grep 过），改成它真实存在的轮换流程 + `git rm --cached`。
- 顺带修掉自己上一次提交造成的两处陈旧行号引用：`28f7247` 插入 NUL 守卫后
  `process.env[name] = value` 从 `src/config/secrets.js:113` 挪到了 `:134`，
  `scripts/devSecretIsolation.js` 与 `disposableSecretIsolation.test.js` 的锚点跟着改对
  （`commentAnchorFreshness` 报的，不是豁免掉的）。

### 安全（2026-10-03 · 破坏性恢复的**默认**传输路径从来没有一个用例跑过，而它正在宿主机上多留一份凭据）

> 背景：给 `restore-mongo.sh` 补用例时发现，本仓所有真跑过它的地方（backupUriFile /
> backupEncryptionContract / infraParam…）都显式设了 `MONGO_RESTORE_TRANSPORT=local`，
> 而 README 与 deployment/backup-encryption.md 教的恰恰是**默认那条 docker**——compose 里
> mongo 只 `expose` 不 `publish`，宿主机连不上，mongorestore 必须在容器内跑。
> 于是"数据级回滚抓手"的默认路径在修前**从未被任何用例执行过**：主机段改写的拒绝、
> `--drop` 的拼接、凭据在容器内即删、归档经 stdin 流向容器，没有一条是被证过的事实。
> 备份侧的 docker 拒绝同样没人跑过（`backupTransport.test.js` 只演过它成功的那格）。

- 新增 `src/tests/deploy/restoreTransport.test.js`（8 格）：桩 `docker` 把 argv 与 stdin
  分别落盘，断言的是**真正送进容器的那条命令与那段字节流**——`uri:` 行主机段已换成
  容器内地址、库名与 `authSource` 原样保留、归档字节确实跟在配置行后面流进去、
  argv 上没有凭据、容器侧 `/tmp/.mongorestore.cfg` 与 `.archive` 都在同一条远端命令里 `rm -f`。
  `--drop` 在两条分支各写一遍（local 拼数组、docker 拼远端字符串），所以两侧都演
  "开了有、没开无"——这是防漂移，不是重复断言。
- 实测到的**修复**：`restore-mongo.sh` 原先在分支之前就无条件 `umask 077 + mktemp +
写入含口令的 URI`，而 docker 路径从头到尾没人读那个文件——它在宿主机磁盘上实打实
  留了一次凭据（DR 现场往往是笔记本/运维机），**而下方的注释一直声称"含凭据的 URI
  不落宿主机临时文件"，那句当时是失实的**。创建挪进 `local)` 分支（`--config` 只吃文件，
  那里是必需的），注释与代码这才一致。判据"宿主机上有没有 `mongorestore-config.*`"由
  两个桩**共用同一段探测代码**：local 必须探到、docker 必须探不到，探测器坏掉时不可能
  只让 docker 那一格假绿。把修前那段贴回去，两条用例立刻变红（docker 那格探到文件名、
  local 那格数出 2 个文件）——这次 mutation 实跑过，不是推演。
- 备份侧补上缺失的那格：URI 主机段无法改写 ⇒ 非零退出、`docker.argv`/`docker.stdin`
  根本没被创建、`backups/` 里不留半成品归档，且拒绝信息不回显口令字节。
- 一个**否证的结论**（原先记成高危，源码读下来不成立）：曾判断"备份只导出 URI 里那个库，
  恢复却不带 `--nsInclude` ⇒ 归档里有几个库就覆写几个库"。mongo-tools 100.9 的
  `common/options` 在没有显式 `--db` 时把**连接串里的库名**赋给 `opts.DB`，mongodump 只为
  那一个库建 intents，mongorestore 则把 `[库名.*]` 当作 includes 过滤归档条目——
  两侧范围因此**同一个库**，没有错配。这条不改任何破坏性参数（`--drop` 的口径维持原样），
  改为把口径写进 `backup-mongo.sh` 的注释并标明它是**读源码得来的、本机无二进制可实测**。
- 一条**待拍板的不对称**（没在门禁里偷偷改语义）：含未转义 `@` 的口令，docker 分支硬拒、
  local 分支放行（备份侧同形）。方向不同是有理由的——docker 必须知道"哪段是主机"才能替换，
  两个读者读法相反时替换就是猜；local 从不改写，歧义不是脚本引入的，且两种读法下的
  **库名相同**，确认门禁没有被绕过。残余风险是"横幅里的主机不一定是实际拨号的主机"，
  而 Go 驱动本机不可测。压平它要开始拒绝一批现在能跑的口令，因此留给人决定，
  新用例只把现状钉住并注明是钉现状、不是背书。

### 安全（2026-10-03 · UTF-16 密钥文件：bash 侧把连接串改坏、Node 侧把密钥截成一个字符，两边都 rc=0）

> 背景：`*_FILE` 约定有两个读者，它们吃掉"坏字节"的方式**相反**，而两个都不报警。
> 触发形态是运维用记事本/PowerShell 把密钥"另存为 Unicode"——UTF-16LE 里每个 ASCII
> 字符后面都跟一个 `00`，肉眼看文件内容完全正常。
>
> - **bash 侧**（`scripts/mongoUri.sh` 的 `mongo_hydrate_uri`）：`_body=$(cat -- "$_file")`
>   这一步命令替换就把 NUL **删掉**了（bash 只在 stderr 留一行 warning，退出码仍是 0），
>   于是后面四条判据（单行 / 纯可打印 ASCII / scheme / 非空）校验的是**改写后的串**，
>   不是文件里的字节。实测（bash 5.3.9）：UTF-16LE 的
>   `mongodb://fsms:pw@h/db` 剥掉 NUL 后字形与正确值一模一样 ⇒ 放行；把 NUL 埋在库名中间
>   （`…/fsms<NUL>x`）则放行一个"没人写过的库"，rc=0。
> - **Node 侧**（`src/config/secrets.js` 的 `hydrateSecretsFromFiles`）：`readFileSync(…,'utf8')`
>   把 NUL **留在** JS 字符串里，`trim()` 不认它是空白（所以既不裁也不告警），
>   随后 `process.env[name] = value` 在第一个 NUL 处**截断**。实测（Windows / Node 24.18）：
>   `process.env.X='A\0b'` 不抛错、回读得到 `'A'`；把 UTF-16 的 AES 密钥喂进去，
>   注入值是 1 个字符，`loaded` 照常包含该键、`warnings` 为空。
>
> 哪些会被下游拦住纯属巧合，所以不能拿它当"没问题"的证据：`JWT_SECRET` /
> `JWT_REFRESH_SECRET` / `AES_SECRET_KEY` / `HMAC_SECRET` 有 ≥32 长度闸、`DOCS_PASSWORD` 有
> ≥16 闸（这些会启动失败，吵得响）；`METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` /
> `LOG_SHIPPING_TOKEN` / `MONGO_ROOT_PASSWORD` / `SENTRY_DSN` / `REDIS_URL` 没有长度判据，
> 它们的形态是"进程活着但对不上"——其中 webhook 签名密钥被截断等于**安全告警静默丢弃**。
> 反向核验过一条更吓人的假设，结论是否定的：`ADMIN_INITIAL_PASSWORD` 被截断**不会**
> 造出 1 字符管理员口令，`models/User.js:67` 的 `minlength: 12` 会在 `User.create` 抛错。

- `scripts/mongoUri.sh`：在任何命令替换**之前**按原始文件字节判 NUL
  （`tr -dc '\000' < file | wc -c`），非零即拒绝并点名文件与"UTF-16/二进制另存为"这一成因。
  判据写成"剩下的字节个数 ≠ 0"而不是"grep 到就算"：`tr` 自身失败时残串是空串，
  `"" != "0"` 照样点亮 ⇒ fail-closed。
- `src/config/secrets.js`：在唯一的注入入口抛错，早于赋值也早于"空文件"判定
  （`'\0'` 单字符文件若走到赋值，得到的会是**空**环境变量）。只拒 NUL，不拒"所有控制字符"——
  `LOGIN_ECDH_PRIVATE_KEY` 是多行 PEM，中间的 `\n` 合法，一刀切会把正常部署拦死。
- 报错只点名变量名与文件路径，不回显任何密钥字节（新增一条用例钉住这点）。
- 新增 4 条 shell 侧 + 6 条 Node 侧用例，其中两条是**闸内的变异自证**：
  `backupUriFile.test.js` 按代码特征删掉 NUL 闸那段、用同一份 UTF-16 夹具重跑备份，
  必须变成 rc=0 且产出归档——这证明"红"确实来自那道闸，而不是被别的东西凑出来的绿；
  找不到判据行就直接抛错，避免上一轮踩过的"变异没落地、用例对着未改动的文件保持绿"。
  Node 侧配套一条反向自证：多行 PEM 照常注入，证明判据没退化成拒绝一切。
- 记一条踩过的测试环境坑：**平台事实不能在 jest 进程里量**。第一版把
  `process.env.X='A\0b'` 的回读断言写在用例里，jest-environment-node 用自己的对象代理
  `process.env`，NUL 能原样往返 ⇒ 把"真实进程会截断"这条前提判成了假。改为 spawn 子进程量，
  并把判据写成"长度不是 3"（截断得到 1、或某平台直接拒绝赋值都算通过），
  这样 Linux 上的表现尚未实测也不会成为跨平台红灯。

### 安全（2026-10-03 · 异地副本的"空命令假成功"：`BACKUP_OFFSITE_CMD=" "` 时一次都没复制，回显却写 completed）

> 背景：`scripts/backup-mongo.sh` 的异地副本那一步，头部注释早就写着原则
> 「被吞掉的异地失败比没有异地更危险——它让运维以为自己有异地副本」。判据却是
> `[ -n "$BACKUP_OFFSITE_CMD" ]`：**非空**不等于**有词**。实测（bash 5.3.9）
> `BACKUP_OFFSITE_CMD=" "`（env 文件里多打一个空格就够了）会走进分支，
> `read -r -a` 切出 0 个词，而 `"${空数组[@]}"` 落在命令位置是一条**空命令**——返回 0。
> 于是异地副本一次都没有执行，回显却是 `Offsite copy completed:`，连未配置那支的
> `Warning` 都不打。这是那条原则里最坏的形态：它连"失败"都不是，没有任何信号可看，
> cron 邮件里是一次"带异地副本的成功备份"，而备份实际只存在于本机（与数据库同机，
> 宿主机级故障时等于没有备份）。

- 判据从"字符串是否非空"改成"**是否切出至少一个词**"：`${#OFFSITE_ARGS[@]} -gt 0` 才执行；
  配置了却全是空白 ⇒ 单独一句 `Error`（说清是配错了，不是没配）并 `exit 1`，与异地命令
  失败同档——那档本来就是 `exit 1`，没有新的中断面。
- 未设置那一支不变（仍是 Warning + 退出码 0），且新增一条反向自证钉住它：
  新分支不得把"没配异地"吞成失败。
- 顺带让 `"${OFFSITE_ARGS[@]}"` 只在词数 > 0 时展开。旧写法在老 bash（4.2/4.3，RHEL7 一类
  宿主）的 `set -u` 下展开空数组会直接掐死调用方——那是"备份跑到最后一步才崩"，
  比这次的静默更响，但同一处判据一次修掉。
- 三条新用例（真跑脚本 + PATH 桩 mongodump/gpg/offsite-ok）：空白值 ⇒ 退出码 1 且
  **不得**出现 `Offsite copy completed`；真命令 ⇒ 桩确实被调用过、且拿得到定稿后的
  `BACKUP_FILE`/`BACKUP_SHA256`；未设置 ⇒ 只有 Warning、退出码 0。
  旧实现下第一条为红（已实测），后两条在旧实现下也是绿 ⇒ 信号只由第一条承担。

### 安全（2026-10-03 · 主机段改写的 13 条拒绝收拢成一句句能定位的原因，并改掉上一轮两处失实论证）

> 背景：`scripts/mongoUri.sh` 的 `mongo_swap_host` 上一轮已经按参考解析器的读法重做了取段，
> 但拒绝路径只剩一个退出码。本会话实测出两类问题，一类是现场可用性，一类是**注释里写的
> 事实站不住**——后者更贵，因为它会让下一个读者照着错的模型改这段代码。
>
> 1. **汇总句几乎总是指向错误的变量**：13 个互不相同的失效方向全部折叠成调用方那一句
>    「无法把 URI 主机段改写为容器内地址（`<目标>`），请检查 `MONGODB_URI` 形态」。
>    `MONGO_CONTAINER_HOST` 为空或拼错时同样 rc=1，而运维被告知去查 URI——在恢复窗口里
>    这是把人往错误的文件上引。
> 2. **少给一个参数会打断调用方**：本文件被 `set -u` 的脚本 source，`mongo_swap_host x`
>    原先以 `$2: unbound variable` 中断**调用方**，走不到任何一条能看懂的拒绝。

- 新增 `mongo_swap_refuse`：每条拒绝往 stderr 打一行**原因类别**（未转义 `@`、空凭据段、
  种子列表空项、越界端口、`+srv` 带端口/带逗号、目标地址非法……），只点变量名与形态，
  **绝不回显 URI 或口令的任何字节**——这是凭据，点名不取值。调用方那句汇总改为
  「拒绝执行；上一行点名是哪条判据拦下的」，不再独自承担定位责任。
- `mongo_swap_host` 的入参取 `${1:-}` / `${2:-}`：缺参数现在是一条拒绝，而不是一次崩溃。
- 顺带修掉一处**指错变量的标签**（是新测试在跑的时候自己撞出来的）：改写产物过值判据时，
  标签原先写成「`MONGO_CONTAINER_HOST` 改写后的连接串 含空白、换行…」，于是 URI 里带换行时
  运维被告知去查那个本来就没问题的变量。走到这一步时 `_scheme` 由 case 字面量决定、
  `_target` 刚过 `mongo_valid_hostport`（单行纯可打印 ASCII），可能带越界字节的只剩凭据段与尾部
  ⇒ 标签改为点名 `MONGODB_URI`，这是**可证明的**归因而不是措辞偏好。
- 纠正上一轮写下的两条**失实论证**（都已实测取证，判据本身不变）：
  - 「参考解析器把 `a,,b` 读成少一个主机」不成立——它**接受**并读成
    `hosts=["a:27017", ":27017", "b:27017"]`，即多出一个空主机名的种子。所以这一条是
    「刻意比解析器严」，不是「它也会拒」；`a@b@c` 同理，实测它**不报错**而是静默把主机
    换成没人写过的那一段。本机实测的两个读者对同一条串给出相反答案
    （`mongodb://u:p@ss@h:27017/db` ⇒ JS 包按**第一个** `@` 切凭据 ⇒ `hosts=["ss:27017"]`；
    Node 的 WHATWG `new URL` 按**最后一个** `@` 定界 userinfo ⇒ `hostname=h`）。
    原先这里写着"Go 驱动按 RFC 3986 取最后一个"——Go 驱动本机没有二进制，那一直是**推断**，
    不该写成实测。判据因此不赌读者：两个读者读法相反的形态一律硬拒。
  - 「刻意更严的两处」实际是四处，漏记了种子列表空项与值里的空白字节两条同族判据。
- 交代一条**能力边界**，防止 parity 全绿被读成"已验证过 mongodump"：本仓 parity 闸用的
  参考解析器是 JS 包（`mongoose` 内嵌的 `mongodb-connection-string-url`），而真正消费产物的是
  mongodump / mongorestore 的 **Go 驱动**；这台机器上没有 mongodump，所以 parity 只能证到
  "与 JS 包同口径"。已知两边读法不一致的形态就是上面的裸 `@` 分界——判据一律取更严的一侧。

### 供应链（2026-10-03 · `capture-image-digests.sh` 不再能留下"半钉"仓库，也不再吞别人的临时文件）

> 背景：这个脚本把 Dockerfile / compose 的基础镜像从可变 tag 换成 registry digest。上一轮已经补上
> "sed 无匹配仍返回 0"的静默 no-op 校验，但落笔顺序还是**边检查边写、两个目标顺序跑**。本轮真跑
> （PATH 插 docker 替身 + `--root` 指向临时仓库副本）实测出三种失效形态，都属"报成功/报错都看不出来"：
>
> 1. **半钉仓库**：compose 的 tag 与脚本常量漂移 ⇒ 第一轮把 Dockerfile 改成 digest，第二步才报错退出，
>    仓库留下"Dockerfile 已钉、compose 仍指向可变 tag"。
> 2. **死路**：照报错把 compose 修好再跑第二次，脚本在 Dockerfile 那一步就撞
>    "已经存在 @sha256 钉版引用"退出 ⇒ compose **永远钉不上**，唯一能修它的脚本自己拒绝再跑。
> 3. **吞别人的文件**：`sed > $file.pin.tmp; mv $tmp $file` 会把上一次中断留下（或人工放置）的
>    `Dockerfile.pin.tmp` 静默吃掉——探针读到的是 ENOENT，而退出码 0。

- 落笔改成**三相**：`check_ref`（只读，两个目标都确认可改，含"临时文件此前不存在"）→ `stage_ref`
  （只写临时文件并预演校验）→ `commit_ref`（`mv` 改名 + 落笔后复核）。任何一步失败，两个目标文件
  都逐字节不变、目录里没有残留临时文件。
- `trap … EXIT HUP INT TERM` 只清理**本脚本确认过"原本不存在"**的临时文件：`PIN_TMP_*` 两个全局量先置空，
  `check_ref` 通过之后才赋值。直觉写法 `trap 'rm -f "$ROOT"/*.pin.tmp' EXIT` 会在报错退出的那一刻删掉
  运维的文件——变异实验（把 `-e` 门禁摘掉）证明这条判据是承重的：残留内容变成 `<<DELETED>>`、退出码 0。
- 诚实交代残余边界：两条 `mv` 之间不是原子的（跨两个文件不存在单次 rename）。check 已确认两文件都在且
  都可改、stage 已验过改好的产物，失败面从"任何解析/匹配错"缩到"同目录 rename 本身出错"。
- 测试 `src/tests/imageDigestGate.test.js` 10 → 19 条：新增原子性（第二个目标漂移时第一个必须 `toBe`
  原始字节）、自愈（修好 compose 后重跑必须 rc=0 两边都钉上）、残留（拒绝 + 不覆盖 + 退出时不删 +
  删掉后能正常钉版），以及失败臂矩阵（tag 漂移×2 / digest 取不到 / 伪 digest / 未知参数）的公共后置条件。
  逐条做过变异反证：`M1_order`（把 compose 的检查挪到 Dockerfile 落笔之后）点亮前两条，
  `M2_noTempGate`（摘掉临时文件门禁）点亮第三条；control 三场景全绿。
- 夹具侧补两条门禁自身的自证：`tmps` 过滤器在残留用例里必须**看得见**那个文件（否则"失败不留临时文件"
  是空集造成的假绿）；`test.each` 的表宽必须等于处理函数形参个数——窄一格 jest-each 会注入 `done`，
  用例不失败而是卡满 30s 超时。

### 安全（2026-10-03 · 备份的主机段改写按参考解析器的读法重做：静默连到别处、合法 URI 被拒、坏端口被顺手换掉）

> 背景：`scripts/mongoUri.sh` 上一轮已经把那句 `sed -E "s#^((mongodb(\+srv)?://)…#"` 换成纯 shell
> 字符串重建，但**取哪一段**的判据还是那套 `case */* | \?* | *` 三分支 + `##*@` 切凭据。
> 本轮拿参考解析器（`mongoose.mongo.MongoClient`，即 `src/config/database.js:51` 讨论的那份内嵌
> `mongodb-connection-string-url`）逐条形对照，实测五条同根缺陷，全部与"备份到底连了谁"有关：
>
> 1. **静默改错主机**：`mongodb://u:p@db.internal:27017?appname=bob@corp`（无路径、查询串里有裸 `@`）
>    ⇒ rc=0，产物 `…@db.internal:27017?appname=bob@127.0.0.1:27017`。主机段一动没动、目标地址被拼进
>    查询串，而解析器把它读成 `hosts=["db.internal:27017"]`（**不报错**）——横幅承诺 127.0.0.1，
>    mongodump 连的是 db.internal，退出码却可以是 0。根因：第三分支把整串当 authority，再按**最后**一个 `@` 切凭据。
> 2. **副本集种子列表被拒**：`mongodb://a:27017,b:27017/db?replicaSet=rs0` ⇒ rc=1（逗号不在字符集里）——
>    合法 URI 备份不了，报的却是"形态异常"。
> 3. **无路径带查询被拒**：`mongodb://h:27017?directConnection=true` ⇒ rc=1（`\?*` 只匹配以 `?` **开头**的串）。
> 4. **IPv6 容器地址当目标被拒**：`MONGO_CONTAINER_HOST='[::1]:27017'` ⇒ rc=1，而 URI 里写同一段是放行的
>    ——同一件事两侧判据不一致。
> 5. **交回 mongodump 自己都不认的串**：`mongodb://a@b@c:27017/db` 与 `mongodb+srv://…` 带端口的产物
>    （`+srv` 禁止端口）都是 rc=0。

- 取段判据改成按**解析器怎么读主机段**来定：authority 终止于第一个 `/ ? #`，凭据与主机的分界取**第一个**
  `@`，主机段允许逗号分隔的种子列表且每项都得过 `host[:port]`/`[IPv6][:port]` 判据，主机段已等于目标地址
  ⇒ 合法空操作放行（上一版那条假阳性就是这一形态），其余认不出来的一律硬失败。
- 新增四个可复用判据：`mongo_valid_hostport` / `mongo_valid_hostlist` / `mongo_valid_userinfo` / `mongo_valid_port`。
  端口区间那条是新发现的第二类失效方向：`h:0`（'Invalid port (zero) with hostname'）与 `h:65536`
  （'Unable to parse h:65536 with URL'）解析器都报错，而我们放行等于**顺手把坏端口换成目标端口**——
  现场拿到的是一个从来不存在、也从来没被 mongodump 拒过的 URI。区间判据写成字符串比较而不是 `$(( ))`：
  shell 把 0 前缀当八进制（`08` 直接算错），而解析器把 `07017` 读成 7017。
- 一条**负结果**记录在案，防止下一个读者把 `#` 也当成缺陷：`mongodb://h#1/db` 曾被写成"解析器读成
  `["h#1"]`、我们比它严"，实测不成立——它在 `#` 处终止 authority 读成 `hosts=["h:27017"]`、db 仍是 `db`，
  与我们的取段口径完全一致 ⇒ 放行，由 parity 闸逐条比对产物。
- `src/tests/config/mongoTransportParity.test.js` 60 → **160 例**，承重的那条是新加的**参考解析器 parity 闸**：
  真值表里每一条 rc=0 的产物都重新真跑一遍并交给 `new MongoClient(…)` 读，要求
  `hosts === [目标地址]`、库名与凭据逐字不动；输入本来就解析不动的那一类只有"两边同一句错"才判为继承
  （唯一一条：`?drop:true` 撞驱动的 option 白名单）。清单从真值表**推导**而不是另抄一份，新加一条自动进闸。
  闸自身由六条合成违例（旧写法的真实产物）反向自证，含上面缺陷 1 那条"解析器不报错却连到别处"的形态。
- 一条夹具层的坑记进注释与判据：jest-each@29.7.0 的 `applyArguments`（`bind.js:78-80`）在
  **行数组比测试函数声明的形参短**时会把 `done` 注入成最后一个实参 ⇒ 那些行不是断言失败而是**超时**。
  实测一次跑出 5 条 30 秒超时 + 1 条真失败，看起来像整道闸坏了。现在 trailing 形参带默认值
  （`Function.length` 停在第一个默认值之前），并有一条表宽判据配合成违例钉住它。

### 安全（2026-10-03 · 一次性 harness 的第二根暴露轴：宿主上的明文密钥，不只 `*_FILE`）

> 背景：`scripts/devSecretIsolation.js` 上一版把宿主的 `*_FILE` 指针全量置空，但它只看指针。
> 密钥有**两根正交的轴**——形态（`<NAME>_FILE` 指针 / `<NAME>` 明文值）与通道（宿主 `export` / `.env`），
> 上一版按通道堵了两格，形态那一根整条没堵。而明文形态不是事故形态：`.env.example:2`
> 就明写「JWT_SECRET / AES_SECRET_KEY 等可以直接写在本文件（适合本地开发）」。
> 本机实测（`node -e` 枚举 `FILE_BACKED_SECRETS`）：仓库根 `.env` 今天正带着 6 个明文密钥，
> 其中 `MONGODB_URI` / `ADMIN_INITIAL_PASSWORD` 与一次性 harness 要用的值是同一类东西。

- **守卫按名字全量置空两类**：`<NAME>_FILE` 与 `<NAME>`。漏掉的这一类比原来那条更宽，
  因为 harness 只覆写它记得的那几个名字，其余名字一个都不碰，于是明文值直接穿过 dotenv 被读到：
  `REDIS_URL` ⇒ 冒烟的验证码/限流计数读写宿主那台 Redis；`SECURITY_ALERT_WEBHOOK_SECRET`
  ⇒ 冒烟造的假告警签名有效、真推到值班群；`SENTRY_DSN` / `LOG_SHIPPING_TOKEN` ⇒ 测试流量进真实观测面；
  `ADMIN_INITIAL_PASSWORD` / `MONGO_ROOT_PASSWORD` ⇒ 播种与清理动的是真凭据。
- **由此新增一条顺序不变量**：置空明文值意味着 harness 自己的一次性赋值必须**晚于**守卫
  （先赋值再调守卫会被擦掉）。接线闸原来只钉"早于 `require('../src/index.js')`"，
  现在同时钉"早于任何 `process.env.<密钥名>[/_FILE] =` 赋值"，并带三条负向对照
  （非密钥赋值不算、生成的子脚本里整行是字符串字面量的赋值不算、真赋值提到守卫前必须点名）。
- **"空串会不会变成第三种状态"有专门用例**：这几个名字在 `src/config` 里没有字段，消费方直读 env
  （`sharedCache.js:52` 的 `(process.env.REDIS_URL || '').trim() !== ''`、`initData.js:770` 的
  `if (process.env.ADMIN_INITIAL_PASSWORD)`），置空与"宿主本来没配"逐点等价；用例钉的是**真实源码行**，
  判据写法改成 `!== undefined` 立刻红。
- **告警点名不取值**：`*_FILE` 条目打路径（值本身是路径），明文条目只打名字并注明"值不打印"——
  报错里复读密钥等于把它从 env 搬进 stdout/stderr，CI 日志保留时间通常更长（同一口径见 `scripts/secretFileArg.js`）。
- **`src/tests/config/disposableSecretIsolation.test.js` 12 → 19 例**：来源臂从两条加到三条
  （`export` / `.env` 混装 / **`.env` 里只有明文、一个 `*_FILE` 都没有**）。第三条臂就是上一版的靶子：
  它的 `uri`/`jwt` 本来就是一次性值，"全绿"完全可以和"真 Redis、真初始口令已接上"同时成立。
  真值表随之扩到九格，`del × {dotenv, plain}` 两臂共同钉住"置空而非删除"对**两类**都承重；
  `rootPw` 的期望从 `undefined` 改成 `''`（`undefined` 只证"没 hydrate"，`''` 才证"宿主明文也没接上"），
  并在探针里给所有 env 观测加 `?? null`——`JSON.stringify` 会丢掉 `undefined` 键，
  那样"挡住了"与"夹具压根没跑"分不开，是一条空断言；另补一条**真文件减法自证**：
  擦掉置空明文的那两行、只留置空指针，明文轴必须立刻漏且被点名。
- 单位夹具改用"先全部置空"而不是 `delete` 构造"宿主干净"：本 describe 的 cwd 是仓库根，
  那里真有一个带 6 个明文密钥的 `.env`，`delete` 会被守卫内的 dotenv 填回来——
  这正是实现选择置空而非删除的同一条理由。
- **真 harness 复跑**：`REDIS_URL=… ADMIN_INITIAL_PASSWORD=… SENTRY_DSN=… node scripts/e2e-smoke.js`
  ⇒ 守卫打印 3 条明文点名（无值）、`[E2E] 结果：14 通过, 0 失败`、退出码 0；
  不带毒环境的裸跑同样 14/14 绿。

### 安全（2026-10-03 · 备份/恢复：主机段改写去掉 sed，失败现场不留明文归档）

> 背景：`scripts/mongoUri.sh` 是备份与恢复共用的唯一一份 URI 判据，它自己却是
> `sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1${MONGO_CONTAINER_HOST}#"`——
> 两条注入路径都落在这句替换上，而落点都是 mongodump/mongorestore 的 **0600 配置文件**：
> 配置里唯一由调用方决定的就是那一行 `uri:`。

- **`mongo_swap_host` 改为纯 shell 字符串重建**（scheme / authority / tail 三段用参数展开切开）。
  sed 形态的两个实测失效：① 替换串里的字面 `\n` 被 GNU sed 展开成**真换行** ⇒
  `MONGO_CONTAINER_HOST='127.0.0.1:27017\ncollection:auditLog'` 能给配置追加第二行，
  单集合导出被记成一次成功的全量备份；② 口令里未转义的 `/` 提前终结 `[^/]*` 那次匹配 ⇒
  替换错位（`mongodb://u:p/x@h:27017/db` → `mongodb://127.0.0.1:27017/x@h:27017/db`），
  **凭据被静默丢弃**而横幅承诺的仍是 `h:27017`/`db`。
- **`MONGO_CONTAINER_HOST` 新增字符集判据**（`[A-Za-z0-9.:_-]`，且端口必须是数字、
  IPv6 字面量 `[::1]:27017` 单独放行）。换行、空格、`\`、`;`、`|`、反引号、`$` 全部进不来。
- **切出来的主机段必须"确实是一个 authority"**：认不出来就拒（`u:p`、`mongo:abc`、`mongo:`、
  `[::1]:abc` 都在这一条）。第一版在这里补过一条"有凭据且路径里含 `@` ⇒ 拒"，实测把
  `mongodb://u:p@mongo/db@name` 一起误杀（库名带 `@` 合法，authority 终止于第一个 `/`），
  已由精确判据取代。
- **两条出口都过值判据**：改写那一支与"主机段本来就等于目标地址"的合法空操作那一支。
  少了后者，`$'mongodb://127.0.0.1:27017/fsms\ndrop:true'` 配 `MONGO_CONTAINER_HOST=127.0.0.1:27017`
  会绕过全部检查被原样交回调用方。
- **`mongo_validate_uri` 的越界字节判据补哨兵**：`$(… | tr -d '\041-\176')` 非空这个写法漏在
  **命令替换会剥掉尾部全部换行**——载荷 `…?authSource=admin\ndrop:true` 的注入部分本身全是
  可打印 ASCII，残串为空 ⇒ 放行，`drop:true` 成为配置文件的第二行，而门禁与横幅都声明相反。
  现在先补一个 `~` 再比，判据无歧义。
- **`backup-mongo.sh` 的加密门禁提到 `mongodump` 之前**（新增 `crypto_precheck_backup`，
  与 `crypto_encrypt` 同源）。原先 `gpg` 不在 PATH 或 `BACKUP_GPG_RECIPIENT` 没配时，
  脚本先花几分钟导出整个明文全量库（人员 PII + 不可篡改审计集合）再在加密步失败退出，
  而 `set -e` 直接带走 ⇒ "写完就删明文"那行永远执行不到，**每次失败都往 `backups/`
  多留一份明文**。现在三种不可用形态都在创建目录之前拒绝。
- **未定稿产物由 `cleanup` 一律删除（`FINALIZED` 标志）**。失败产物与成功产物同名
  （`fire-safety-backup-*.gz[.gpg][.sha256]`），留着就会被 retention 清单、回滚演练与
  "最近一次备份"的报表挑中。定稿点（密文 + 校验和都在手且非空）之后反向成立：
  一个都不能删——异地副本失败按设计整体失败，那时已到手的本地副本仍是回滚抓手。
  `deployment/backup-encryption.md` 的失败语义两条已同步。
- **闸**：`src/tests/config/mongoTransportParity.test.js` 15 → 41 例（真跑 bash 的行为真值表 +
  目标地址字符集九臂 + 值判据的 LF/CR 成对臂；结构层的"反向前提"换了方向——原先断言
  那句 sed 还在共享实现里，现在断言改写函数体内不许出现 sed，并用历史写法作合成违例
  证明判据非空集，注释过滤本身也自证）。夹具改经单引号安全转义传入（`$`/反引号不得被
  bash 先展开一次），CR 载荷由 shell `printf` 现场构造（Node 传 `bash -c` 时裸 CR 会在
  传输层被吃掉，测到的是"没有 CR 的串"——假绿）。
- **新闸 `src/tests/deploy/backupFailureArtifactHygiene.test.js`（9 例）**：真进程 + 桩
  mongodump/gpg（PATH 注入），断言的是"目录里到底有什么文件、桩有没有被调用"。
  含一处前世版对照：从脚本副本里按缩进反向引用删掉 `FINALIZED` 块（并 `bash -n` 证明它仍是
  合法脚本），同一夹具必须**留下明文归档**，否则这条断言抓不住回退。
  `backupUriFile.test.js` 的 SIGINT 用例同时补上"打断后目录里不得留半截归档"。

### 安全（2026-10-03 · 密钥轮换的密钥不再经过命令行）

> 背景：仓里所有密钥早已统一成 `<NAME>_FILE` 口径，唯独密钥轮换这一族还留着
> `--new-key <KEY>`：把值写在 argv 上，同一个密钥就同时出现在
> `/proc/<pid>/cmdline`（Linux 默认 0444 ⇒ 同机任意本地用户可读，而一次全量迁移要跑几分钟，
> 窗口足够长；`ps(1)` / 任务管理器同理）、shell 历史（`HISTCONTROL=ignorespace` 只是
> "记得在前面加空格"的人为约定，不是机制）、以及任何 `set -x` 的 CI 日志。
> 同一门安全要求上的两个标准，收口成一条。

- **新增 `scripts/secretFileArg.js`**：`readSecretFile` 把"密钥文件"的形状判据写死——
  恰好一行非空内容、去 UTF-8 BOM 与 CR/尾空白、字符集限 `0x21–0x7E`（与 shell 侧
  `mongoUri.sh` 的 `tr -d '\041-\176'` 同判据）；读不到、多行、含空白一律**硬失败**，
  绝不"取第一条非空行"蒙过去。`resolveSecretSource` 的优先级与 shell 侧一致：
  **显式 `--*-file` 赢过环境变量**（命令行点名的是"这一次轮换要用的值"，不能被 shell 里
  残留的同名变量悄悄改写），两者都给时只打一行提示且**只点名不取值**。
  所有错误信息只含标签与路径——一条"密钥泄漏"的报错如果把密钥再打一遍，
  就是把它从 argv 换成了 stdout/stderr，而 CI 日志的保留时间通常更长。
- **`migrate-mfa-secret.js` / `resign-audit-hmac.js` 改为 `--new-key-file` / `--old-key-file`**，
  旧形态不是"删掉了事"而是**具名拒绝**（exit 2 并指向替代写法）。具名而非落到
  `未知参数：${argv[i]}` 那条默认分支是刻意的：默认分支打印 `argv[i]`，而循环下一步就是
  那个密钥本身——报错本身就成了第二次泄漏。
- **一处有意的收窄**：`--*-file` 只接受 ASCII 密钥；密钥本身含非 ASCII 的用户仍走环境变量
  （env 不经 `/proc/<pid>/cmdline`，不在这条禁令范围），报错里直接写明这条路。
- **手册同步改口径，并顺手拆掉一个更常见的事故源**：`deployment/secret-rotation.md` 原先第 0 步
  `openssl rand -hex 32` 让人"记下输出"、第 3 步 `printf '%s' '<新KEY>' > 载体` 让人**再敲一遍**——
  重敲一次打错一个字符，数据已经用新钥加密完毕而应用拿的是另一把钥，比不改更糟。现在生成即落盘
  （`umask 077` + 单行文件），迁移用 `--new-key-file` 指它，换钥用 `mv` 把同一份字节扶正；
  全量轮换一节本就由 `generate-secrets.js` 产出文件，直接指过去即可。
- **新闸 `src/tests/deploy/cliSecretArgGate.test.js`（20 例）**，三层判据：
  静态完备性用**派生枚举**（"从 argv 取值"的判据是 `argv[i] === '--x'` 之后 60 字符窗口内的
  `argv[++i]`，因此具名拒绝分支不会被误判成还在收密钥），任何密钥类选项必须以 `-file` 结尾，
  文档里 `node scripts/…` 形态的命令行只允许使用该脚本确实接受的那些选项——新写第三个轮换脚本
  时这条闸自动对它提要求，不需要有人记得来登记；行为闸真起子进程传 canary，断言 exit 2、
  点名替代写法、**canary 一个字节都不出现在 stdout/stderr**、且看不到"已连接"（拒绝早于连库）；
  再加 `--new-key-file` 成功路径"值进内存但不进输出"与优先级提示。
  自证：合成违规（`--new-key` / `--db-password`）与真文件减法（把手册里的 `-file` 去掉）都能点亮。
- 受影响的既有套件同步迁移到新形态并复跑绿：`destructiveGuardOrder`（9 例，夹具改为真实密钥文件——
  必须是**能过强度校验**的密钥，否则 migrate 会以"拒绝迁移"而非断言的"拒绝执行"退出）、
  `hmacResignPrecheck`（8 例）、`runbookApplyCommandContract`、`migrateMfaWriteVerify`。

### 安全（2026-10-03 · 冒烟/压测/演练不得接回真实基础设施）

> 背景：`src/config/index.js:10-11` 在 **require 期**就调 `hydrateSecretsFromFiles()`，而冲突规则是
> **文件优先**（`src/config/secrets.js:113` 无条件 `process.env[name] = value`）。三个 harness
> （`e2e-smoke` / `load-test` / `production-drill`）的形状是「先设一次性 env，再 `require('../src/index.js')`」，
> 于是只要宿主上还留着 `*_FILE`，回填就会把一次性 `MONGODB_URI` 覆写成真实库连接串——**并且不报错**。
> 后果不是测试变红，是**写**：`npm run test:e2e` 往那个库播种管理员、建用户、发告警；
> `npm run test:load` 往它打五相压测流量并写审计。

- **新增 `scripts/devSecretIsolation.js`**：按 `FILE_BACKED_SECRETS` 全量把 `*_FILE` **置空**。
  两个来源都必须堵（第一版只堵了第一条，实测被打回）：宿主 shell 的 `export`
  （`deployment/secret-rotation.md` 要求每条命令自带 `*_FILE` 前缀，把它 export 起来是最省事的顺手做法），
  以及 `.env` 里写着 `*_FILE`（`.env.example:12` 的生产口径 b)）。第二条的关键在时序：dotenv 跑在
  hydrate 的前一行，守卫只看"当前 `process.env` 里有没有"就会漏掉整条路径，故守卫自己先 `require('dotenv').config()`。
- **置空而非 `delete` 是承重的**：dotenv 16.6.1 对"已定义"的键不覆盖（空串也算已定义），
  但会重新填充被 `delete` 掉的键；`secrets.js:71` 又把空路径当"未配置"跳过。
  六格真值表把这条钉死：`del × .env` 那一臂**仍然被覆写**，所以"觉得 delete 更干净"的改法立刻红。
- **刻意不做的两个替代**：用 `NODE_ENV` 跳过回填（`production-drill` 自己要 `NODE_ENV=production`，
  跳过等于演练失去生产同构性，而那正是它存在的意义）；把 hydrate 改成"环境变量优先"
  （推翻一个深思熟虑的安全决定——挂载 secret 必须压过残留的 `.env` 明文，否则轮换看起来生效实则没生效）。
- **新闸 `src/tests/config/disposableSecretIsolation.test.js`（12 例）**：真子进程 + 真 `src/config`，
  断言的是"配置对象里到底是哪个 URI"而不是脚本里有没有某个字符串。含 `MONGO_ROOT_PASSWORD`
  这一臂：harness 从不给它赋值，回填却照样把真实值填进去 ⇒ 危害不止"它记得覆写的那几个键"，
  同时反向钉住守卫自己绝不 hydrate。
- **顺手拆掉上一轮自带的一颗定时炸弹**：`backupUriFile.test.js` 的 SIGINT 用例让外面的
  `sleep 0.4` 与桩里 `sleep 1.2` 赛跑，本机并行跑 `src/tests/config src/tests/deploy` 时漂了
  （归档写完信号才到 ⇒ "Backup completed successfully" 照打 ⇒ 用例红）。改成由桩在
  **半截归档落盘的那一刻** `kill -INT "$PPID"`：红绿只取决于脚本自己的 trap 语义，
  不再取决于机器当时有多忙。
- **既有闸 `scriptSecretHydration.test.js`（14 → 16 例）被这次改动撞红一次，且它是对的**：
  守卫用 `process.env[name + '_FILE']` 动态键读密钥注入项，按闸的口径就是"读取者"，
  而它的合规写法（在库内调 `hydrateSecretsFromFiles()`）恰恰是它要防的那个动作。
  因此给的是**逐名取证**的"共享库"豁免：原来那句 `consumers.length >= 4` 是全局计数，
  新登记的库蹭得到同一句结论却可能压根没人调用；改成每条豁免各自要求"被至少一个入口 require"
  （引入点判据在这里**刻意收紧**：读点判据宽松只会多算一个读取，豁免前提判据宽松则让空白条看起来有主）
  - "库里没有 `require.main === module` 入口支"，并补一条**真文件减法**：把三个 harness 的 require 全擦掉，
    豁免必须当场失效。

### 安全（2026-10-03 · 备份/恢复 shell 的输入校验与退出路径）

> 背景：上一轮给 shell 侧接上 `*_FILE` 后，逐行审计发现"能跑起来"和"不会把凭据/目标库交给
> 一个没人校验的字符串"是两件事。九条 CONFIRMED 全部按缺陷本身定级，不看发现者的措辞。

- **显式 `MONGODB_URI` 此前完全不校验**（只有文件那条路校验）。最糟的一条：连接串里嵌一个换行，
  `printf 'uri: %s\n'` 写进 mongodump 的 `--config` 后，第二行就成了**配置文件里的一行选项**——
  `…@host/db\n drop: true` 直接越过恢复侧所有门禁把"删库再恢复"追加进去。
  新增共享判据 `mongo_validate_uri`（整串必须是单行纯可打印 ASCII + `mongodb(+srv)://` 前缀），
  两个来源同闸。
- **缺 `--` 操作数分隔符**：`MONGODB_URI_FILE=-c` 会被 `cat`/`grep` 当选项 ⇒ 读的是**调用方的 stdin**
  而不是那个文件。补 `--`，并用真子进程断言"打开的是那个文件"。
- **告警回显会泄出口令尾巴**：`${MONGODB_URI#*://}` 之后接 `${…*@}` 是最短匹配，
  口令里含未转义 `@` 时把口令后半段连同主机名一起打进日志。改最长匹配，并补含 `@` 口令的夹具。
- **恢复目标必须由字面决定**：URI 不含库名时，目标库由**归档内容**决定，
  而 `RESTORE_CONFIRM` 的核对退化成"输入就是整串 URI 本身"——一个可猜的哨兵。
  现在缺库名直接拒绝执行（门禁的前提是目标 identifiable），正向对照同夹具带库名放行。
- **`trap cleanup EXIT INT TERM` 不自己 exit**：SIGINT 打断备份时，清理跑完继续往下执行，
  实测打印「Backup completed successfully」而产物只有 5 字节。三条 trap 各自补 `exit 130/143`。
- **`local` 传输分支失败后留 0 字节归档**：`docker` 分支早就处理了（重定向在失败前就建了文件），
  `local` 分支没有——一个躺在 `backups/` 里的空 `.gz` 在回滚清单上"就是一次备份"。同一处理补齐。
- **`grep -c` 无命中时把 `-c` 当选项吃 stdin**，且失败路径留下的空串会让 `[ "$_n" -eq 0 ]`
  报 integer expression。改成先 `cat` 进变量再从 stdin 计数。
- 测试：`backupUriFile.test.js` 17 → 23 例、`backupTransport.test.js` 7 → 8 例，每例都带**正向对照**
  （证明不是靠"永远判红"混过去的）。`src/tests/config` + `src/tests/deploy` 合计 632/632 绿。

### 运维可用性（2026-10-03 · `*_FILE` 这条线的最后一公里：shell 侧解析 + 手册里每条命令行自带密钥）

> 背景：前两轮把 Node 侧的六个运维脚本 + `npm run validate` 都接上了 `<NAME>_FILE` 回填，
> 但**备份/恢复是 shell 脚本**，而手册里的命令行为它们提供的是明文 `MONGODB_URI=`。
> 两条都在生产口径（`.env.example:12` 的 b)「只配 `*_FILE`，`.env` 不写同名变量」）下失效。

- **finding：`scripts/backup-mongo.sh` / `restore-mongo.sh` 只认明文 `MONGODB_URI`**。
  生产宿主机上只有 `./secrets/mongodb_uri` 这个文件，于是每日 cron 每晚 `exit 1`、
  **零归档**，而 cron 的 stderr 没人读——备份线静默停摆可以拖到第一次真要恢复的那天。
  修法：共享实现 `scripts/mongoUri.sh` 里加 `mongo_hydrate_uri`，两个调用点各三行改过去，
  仍保持"凭据不进 argv"（连接串走 mongodump/mongorestore 的临时 `--config` 文件）。
- **一处刻意与 Node 侧相反**：shell 里**显式 `MONGODB_URI` 赢**（`secrets.js:106-113` 是文件赢）。
  理由：恢复的目标库必须由这一行的字面内容决定，不能被环境里残留的 `*_FILE` 静默改写到
  另一个库——把备份写进错库远比连不上严重。并存时打 Warning，README 与手册都写明这层反向。
  坏文件（空 / 多行 / 不是连接串 / 含空白或控制字符）**硬失败**，不像应用侧只告警。
- **夹具暴露的实测纠偏**：`printf 'mongodb+srv://u:p%40ss@h/db'` 里 `%40s` 被 printf 当宽度
  说明符，写出 40 个空格，而首版形状检查**照样放行**（只裁了尾部）。改成"整串必须落在
  0x21–0x7E"后该形态才被判红。同批 probe 还纠正了 `tr` 的两处写法：八进制只认三位
  （`\0176` 会解析成 `\017`+`6`），且空格属于可打印区（`tr -d '\040-\176'` 会把内嵌空格删掉
  而不是查出来）——`*[! -~]*)` 那版更是 `bash -n` 直接报语法错，而语法错让 source 中断，
  导致当轮所有"应当被拒"的 probe 空过（正向样本才暴露了它）。
- **新闸 `src/tests/deploy/backupUriFile.test.js`（17 例）**：真 `bash` + 桩 `mongodump`/
  `mongorestore`，断言的是"文件里的串真的进了 `--config` 内容"而不是脚本自报成功；
  含**前世版减法自证**（把 `mongo_hydrate_uri` 换成只认 `MONGODB_URI` 的旧实现 ⇒ 同一夹具
  必须红）、四种真实密钥文件形态（无尾换行 / 尾换行 / CRLF+空行 / PowerShell BOM）、
  以及 hydrate 之后凭据仍不出现在 argv。
- **新闸 `src/tests/deploy/runbookSecretSource.test.js`（10 例）**：把手册当成可执行契约扫——
  语料 **40 条命令行 / 31 条需要连库**，五通道：缺 `MONGODB_URI(_FILE)`、缺该脚本额外的
  `HMAC_SECRET`/`AES_SECRET_KEY`、命令行出现 `*_FILE=/run/secrets`（那是容器内路径）、
  经 `docker compose exec` 跑 ops 脚本、`--apply` 未配 `ALLOWED_SOURCE_DB`。
  自证三件：前提（条数下限 + 被调用脚本文件必须都存在）、每通道合成违例、
  **真实文件减法**（把 31 条真实命令逐一抹掉前缀喂回同一条通道，全部必须点亮）。
- **判据取舍（记下来以免下轮又被"放宽"回去）**：围栏内位置无关，所以注释形态的 crontab
  示例、`cd /opt/xf && …` 复合行都在检查范围；围栏外抓**每个**内联代码 span，所以
  「- **处置**：`node scripts/…`」这种带标签写法不是盲区（实测把语料从 36 条提到 40 条）。
  但同一条 `--apply` 命令当时**仍然**看不见：它写在跨两行的内联代码里（`\` 续行 + 未闭合的
  span），任何 span 判据都读不到——所以把它连同演练那条一起搬进 ```bash 围栏，
  这才是让它受检的动作。代价是文本判据分不出"这样写"与"不要这样写"，于是把手册里
  `docker compose exec -T app node scripts/x.js` 那条反例拆成两个 span——
  **不给判据开"这条不算"的豁免口**。
  表格行按"记录/状态"排除，覆盖域只含说明书（`deployment/*.md`、`docs/incident-response.md`、
  `README.md`、`SECURITY.md`、`migrations/README.md`），不含 CHANGELOG/`deliverables`/`docs/adr`。
- **我自己写错的两句论证（自查后改掉，没有留到现场）**：
  ① `deployment/secret-rotation.md` 曾写「缺 `MONGODB_URI` 时脚本自己会红」——
  `destructiveGuard.resolveMongoUri` 只打一行 stderr 告警就**回退本地库**，而
  `assertApplyAllowed` 在 `apply=false` 时直接放行，真实症状是"数出来的是开发库的 v1 行数"；
  ② 反证了一个听起来合理的建议：`docker compose exec -T app node scripts/…` **不是**
  宿主机缺密钥的补救路径，镜像里只有 `scripts/destructiveGuard.js`（`Dockerfile:122-124`，
  故意的：容器被攻破时拿不到带 `--apply` 的灭迹工具），那条路径只会 `Cannot find module`。
  能进容器的只有 `npm run validate`（= `node src/config/validate.js`，`src/` 在镜像里）。
- **文档同步**：`secret-rotation.md` 新增「执行位置与 `*_FILE` 前缀」一节（含逐脚本所需密钥表）、
  `backup-encryption.md` cron 行、`rollback-drill.md` 备份/校验行、`incident-response.md` 两条处置命令、
  `README.md` 备份/恢复块。`rollback-drill-record.md` **只改检查单模板那一行**，
  已完成演练的历史行原样不动——为了让闸变绿去改写演练记录等于伪造现场。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 37 套件 / 612 例全绿；
  `npx eslint` 两个新文件 0 问题；`npx prettier --check docs deployment README.md migrations src/tests/deploy`
  全绿；`node scripts/lint-ratchet.js` 仅剩并发线在改的 `src/services/securityAlert.js`
  （complexity/max-lines 各 0→1），本批新增文件未引入任何 warn。

### 运维可用性（2026-10-03 · `npm run validate` 是这条线的第三个入口，而它一直站在闸外）

> 背景：`*_FILE` 回填（P3-48）只在 require 到 `src/config` 的入口自动发生。上一轮补了六个
> 运维脚本并立了 `scriptSecretHydration.test.js` 这条闸；本轮由并发审计线（lane-hydration-audit）
> 逐条攻击那条闸的判据，查出**四个漏判形态**和**第三个同类入口**。

- **finding：`node src/config/validate.js`（= `npm run validate`）在 `*_FILE` 部署下报四条假弱密钥**。
  它不经过 `src/config/index.js:11`，没人回填，于是 `collectSecretErrors` 读到 `undefined`，
  报「JWT_SECRET / JWT_REFRESH_SECRET / AES_SECRET_KEY / HMAC_SECRET 必须设置为至少 32 字符」
  并以 1 退出。而 `deployment/secret-rotation.md:156` 正是拿这一步的退出码当
  "轮换后配置自洽"的证据——密钥轮换流程的收尾在容器里做不到。
  失效形态也和其余六个不同：它们症状是"读不到"，这条是**"密钥看起来弱"**，
  会把排查方向直接带到"是不是运维把密钥换短了"上去。
- **我自己的修法被打回了第一次（如实记录）**：第一版按位置判据把 hydrate 放在
  `validate.js` 文件顶部（这样"hydrate 早于首次读取"在源码位置上成立、可被闸钉住）。
  结果连带打红 5 个配置套件（validate / startupGuards / weakSecretPlaceholder /
  transportTlsAssertion / immutableConfigGuard）。根因不是测试写错，是**判据形状与文件形状不匹配**：
  `validate.js` 同时是库（app.js / index.js / staticFrontend.js / websocketService.js 都 require 它）
  和进程入口，而"库在 require 期覆写调用方的 `process.env`"本身就是不该有的副作用——
  `src/tests/setup.js` 给每个 worker 预置了四把 `*_FILE` 临时副本，凡"先设 env、后 require"
  的夹具都被回填悄悄改回测试密钥。`index.js` 能那么做是因为它自己就是应用入口。
  最终改法：hydrate 放进 `if (require.main === module)` 入口支，先回填再 `validateConfig()`。
  A/B 实测（只给 `*_FILE`、`NODE_ENV=production`）：A 臂（预加载删掉 `*_FILE`，复现"回填没发生"）
  四条假弱密钥 + 「MONGODB_URI 不能指向 localhost」全在；B 臂（当前代码，走真实 CLI）
  弱密钥计数 0，剩下的是我没给的 `CORS_ORIGIN` / `REDIS_URL` / `ALLOWED_HOSTS` /
  `TRUST_PROXY_HOPS`——与密钥无关。
- **finding：闸的读点判据只认一种书写形态**。审计线逐条攻击后确认四处漏判：
  ① 注释里提到 `hydrateSecretsFromFiles()` 就算证据（删掉真调用、留一句注释即绿）；
  ② 解构 `const { MONGODB_URI } = process.env`、别名 `const env = process.env; env.X`、
  动态键 `process.env[k]` 三种读法一律看不见——**看不见比判错更坏**，那等于静默豁免；
  ③ 护栏代读通道 `resolveMongoUri()` 的 require 正则不认带扩展名（`'./destructiveGuard.js'`）
  和 `require(path.join(__dirname, 'destructiveGuard'))` 两种写法，
  而 `fix-token-blacklist-index.js` 唯一的读取通道就是它——上一轮那个"静默回退本地库"的
  缺陷类别因此可以再次溜过；④ 扫描范围只有 `scripts/**`，既不含 package.json 里
  `node <file>` 形态的 npm 入口（`src/config/validate.js` 就是这么漏的），也不含根目录
  `migrate-mongo-config.js`。后者是本轮新发现：`npm run migrate:up` 是以**裸命令名**调 CLI，
  `node <file>` 匹配看不见它，而 CLI 会把同目录的 `migrate-mongo-config.js` 当模块加载——
  那个文件里既有 `resolveMongoUri()`，也有一行上一轮补的 hydrate，**但那行一直站在闸外**，
  删掉不会有任何测试变红。
- **闸改造**：判据抽成三个纯函数（`findHydrationOffender` / `findCliEntryOffender` / `topLevelReads`）
  以便被合成源码直接攻击。注释先剥（逐字符走并跟踪引号，`'mongodb://127.0.0.1/db'` 里的 `//`
  不能当注释起点）；动态键按"可能是读取"计（多算无害，少算是静默漏判）；护栏 require 放宽到
  「`require(` 之后、右括号之前出现 destructiveGuard」。扫描范围三处并集，每处各由一条前提自证钉住。
  新增三条豁免都带**可执行**证据而不是一句注释：豁免一（自带临时值的探针）逐个名字找到赋值处、
  豁免二（共享库 `destructiveGuard.js`）用"确实被 ≥4 个入口 require"自证、
  豁免三（库兼入口）的前提是该文件**没有任何模块顶层读取**（用括号深度算，`depthAt`）——
  前提一破用例即红，逼着改法回到正题。压测/演练三个入口今天不读文件型密钥，
  因此**不许预先占豁免位**（`expect(CLI_ENTRY_BLOCKS).not.toContain(f)` 那类反向钉）。
  减法自证两处：把六个脚本各自的 hydrate 擦掉 ⇒ 闸逐个点名（`verdict` 必须含 hydrate，
  并断言 `stripped !== a.code` 防止"减法没真的动"）；`migrate-mongo-config.js` 同做一遍。
- **工具层陷阱（影响结论可信度，单独记）**：本会话的 Bash 里 `env VAR=x node …` 这种前缀
  **静默不执行**（rc=0、无任何输出），于是第一版 A/B 探针两臂都数到 0 条错误，
  看起来像"缺陷不存在"。同一份 env 用 bash 原生 `VAR=x node …` 前缀跑，才拿到 4 vs 0。
  与上一轮 `'j'.repeat(48)` 夹具被 `isWeakSecret` 判弱那次同一性质：**探针自己坏掉时，
  它给出的"否证"和"证伪"长得一模一样**，所以每条 A/B 都要先证明两臂至少各产出过非零信号。
- 验证：`npx jest src/tests/config src/tests/deploy` ⇒ 35 套件 / 585 条全绿；
  `scriptSecretHydration.test.js` 单跑 15/15；`prettier --check`、`eslint` 对改动的两个文件 0 问题；
  `node scripts/lint-ratchet.js` 对我改的两个文件无回退（现存回退在 `src/services/securityAlert.js`，
  属并发会话在改的文件，未动）。本轮没改 `docker-compose.yml`、`scripts/*.js` 与任何文档。

### 部署（2026-10-03 · SSH 部署路径上 digest 钉死闸一直是静默关闭的 + compose 密钥闸的清单只有 5/15）

> 背景：本轮由「`*_FILE` 密钥回填」那条线连带查出。三条 finding 都属于同一类形状——
> **配了但没送达**、**清单抄短了**、**断言扫空了**——共同点是工作流和 jest 全都绿。

- **finding：`DEPLOY_REQUIRE_DIGEST_PIN` 在 SSH 路径上从未到达 `deploy.js`**。
  `deploy-ssh` 的 `env:` 块里写着 `DEPLOY_REQUIRE_DIGEST_PIN: 'true'`，注释还注明
  「与 self-hosted 同口径」——但两条路径的送达形态根本不同：`deploy-self-hosted` 在
  部署机 runner 上直接 `node scripts/deploy.js`，step env 就是进程 env；`deploy-ssh` 的
  `node` 跑在**目标机**上，而 ssh 既不转发本地环境变量，`SendEnv` 又只在目标机 sshd
  显式 `AcceptEnv` 该变量名时才生效（默认只放行 `LANG/LC_*`）。于是那道"拒绝非 digest
  引用"的兜底闸在 SSH 路径上始终不存在。
  讽刺的是判据早就写过这条口径：本文件 `compose 里每个 :? 变量都由两条部署路径下发`
  那条用例的注释就是「env 里有但没 SendEnv = 目标机收不到」——只是没把同一口径用到
  兜底闸上，而 ⑤ 的断言形状（`expect(ssh).toMatch(/DEPLOY_REQUIRE_DIGEST_PIN: 'true'/)`）
  恰好只查"配了"，替这个洞做了一套完整的掩护。
  如实定级：**这是纵深防御缺一段，不是可利用漏洞**——`IMAGE_TAG` 本身由 preflight 解析
  并过 `sha256:[0-9a-f]{64}` 校验，实际 pull 的就是 digest 引用；闸要防的是"误配/绕过
  preflight 直接把 tag 传进来"，而那条路径上它形同不存在。
- 修法：把它拼进远程命令，并用 `${var:?}` 而不是 `$var`——漏配时报错退出，
  而不是展开成空串让 `deploy.js` 把闸读成"关"（那正是本 finding 的原始形态）。
  不走 `SendEnv`：那要求目标机 sshd 配合，且会撞红上面那条"SendEnv 恰好等于 compose
  硬声明项"的用例。bash 实测两向：置 `true` 时远程命令串为
  `… DEPLOY_REQUIRE_DIGEST_PIN='true' node scripts/deploy.js --dry-run`；
  漏配时 `bash` 立刻退 1 并打印「deploy-ssh 未下发 digest 钉死闸」。
- **闸改造**：`run: |` 扫描器从 describe 内的闭包抽成模块作用域纯函数
  （`collectRunLines(text)` / `deployInvokeLines(text)` / `digestPinDelivered(text)`），
  `allRunLines` 改为委托——同一个 job 可能有多个 step，"取第一个 run"会取到
  Prepare SSH 而不是部署命令（本仓 helper 的注释里就写着这条，但 ⑤ 没用它）。
  抽成纯函数是为了**反向自证**：把修复前的命令串喂进 `digestPinDelivered` 必须判 false。
  变异实测：只删远程命令串里那段（env 块保持"配了"）⇒ ⑤ 当场红在第 248 行
  `expect(digestPinDelivered(ssh)).toBe(true)`（Expected true / Received false），
  其余 16 条不动——正是原洞的签名：所有旧断言都不看送达。
- **finding：compose 密钥闸的名字清单是抄的，5 个 vs `FILE_BACKED_SECRETS` 的 15 个**。
  `docker-compose 不再用 environment 传任何密钥` 把 JWT/REFRESH/AES/HMAC/MONGODB_URI
  五个名字写死在断言里；其余 10 个（`DOCS_PASSWORD` / `LOG_SHIPPING_TOKEN` /
  `METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` / `SENTRY_DSN` /
  `LOGIN_ECDH_PRIVATE_KEY` / `REDIS_URL` …）哪天被写成 `- X=${X}` 明文注入，闸一声不响。
  改为清单从 `src/config/secrets.js` 反向推导（新增文件型密钥不必回来改用例，
  与 compose `:?` 清单闸同套路）。
  实测现状：7/15 走 `_FILE`（含 `REDIS_PASSWORD`），`REDIS_URL=redis://redis:6379` 明文，
  其余 7 个今天压根不在 app 的 environment 里 ⇒ 新判据对它们是"不许以明文出现"，
  不需要动 compose。**唯一豁免 `REDIS_URL` 不写在注释里，条件就地可执行**：
  URL 里一旦出现 `//…@`（口令 userinfo）立刻判红——redis 只挂在
  `data-net: internal: true` 上、口令走 `REDIS_PASSWORD_FILE`，这条豁免成立当且仅当
  它不含凭据。反向自证用合成源（真实 compose 是并发会话共享的文件，不临时改它）：
  把 `HMAC_SECRET_FILE` 换回明文 ⇒ 抓到；换成第 6+ 个名字 `DOCS_PASSWORD` 再试一次
  （这条才真正证明"扩清单"这件事本身有效）；给 REDIS_URL 塞口令 ⇒ 豁免失效；
  喂一份认不出 app 服务的文本 ⇒ 全部名字按违规上报（判据失效不许静默放行）。
- **新增：`/run/secrets/<名>` 三处一致性闸**（environment 的 `_FILE` 引用、服务级
  `secrets:` 列表、顶层 `secrets:` 段）。漏声明的后果不是"没密钥"而是"启动即崩"——
  `hydrateSecretsFromFiles` 对不可读的 `_FILE` 直接抛错，运维看到的是一条与密钥无关的
  启动失败。顺带钉住顶层每个 `file:` 必须落在 `./secrets/`（`.gitignore` 与
  `.dockerignore` 只排除这一个目录，指到别处等于把密钥放回版本库与构建上下文）。
  合成夹具 `CLEAN` / `ORPHAN` 各证一侧：`b_secret` 顶层声明了却没挂到 app ⇒
  `missingFromService` 抓到、`missingFromTopLevel` 必须为空（判据认的是"两处一致性"，
  不是一刀切盯 environment）。
- **自查出一条假绿（自己写自己抓）**：本条第一版的顶层扫描用了
  `/^ {2}[a-z0-9_]+:\n {4}file: (\S+)$/gm`——本仓库文件是 CRLF，`:` 与 `\n` 之间夹着
  `\r`，这条正则**恒不匹配**，那个 `for` 循环体一次都没执行，而用例是绿的。
  这正是本仓踩过两次、写在 `deployWorkflow.test.js` 注释里的坑（"不用 $ 锚点：
  本仓库工作流是 CRLF，`\r` 会让行尾锚定的正则恒不匹配（实测过）"），我照样踩了。
  现在所有 compose 扫描统一先 `split(/\r?\n/)` 再逐行匹配，并把这类"取到多少条"
  写进前提自证（`referenced.length >= 7`、`targets.length >= referenced.length`、
  每个 `file:` 必须是字符串）。
- 核过撤销的怀疑：`ADMIN_INITIAL_PASSWORD_FILE` 曾被记为"compose 接了但应用不读"的
  疑似死接线——`src/services/initData.js:770,833` 确实在读它（初始管理员口令），
  嫌疑撤销。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 35 套件 / 578 条全绿；
  `prettier --check` 与 `eslint` 对改动的三个文件均 0 问题。
  本轮未改 `docker-compose.yml` 与 `scripts/deployPolicy.js`（判据变了，配置没变）。

### 运维可用性（2026-10-03 · `*_FILE` 密钥部署下六个独立脚本拿不到连接串）

> 背景：`src/config/secrets.js` 的 `<NAME>_FILE` 约定（P3-48：密钥走文件挂载，不进
> `docker inspect` / `compose config` / 子进程继承）只在**require 到 `src/config` 的入口**
> 自动回填 process.env。运维手边的独立脚本几乎都是 `require('dotenv').config()` +
> 直读 `process.env.MONGODB_URI`，这两者从来没接上。
>
> **本轮推翻了自己的第一版判据**：先用静态依赖图筛"哪些脚本需要补 hydrate"，
> `verify-audit-chain.js` 的图确实通向 `src/config`（auditChainVerify → utils/auditChain →
> 函数体内 `require('../config')`），按图它不需要改。改成动态探测（只给 `MONGODB_URI_FILE`、
> 显式把 `MONGODB_URI` 置空、目标端口 1）后结论相反——那是**懒 require**，脚本在 `main()`
> 里读 env 时它还没执行。静态图在这里会给出假绿。

- 实测（修前）：`verify-audit-chain` / `revoke-user-sessions` / `run-rollback-drill` /
  `sync-audit-indexes` / `perf/explain-spotcheck` 读到空串，开局报错退出；
  `fix-token-blacklist-index` 更隐蔽——`resolveMongoUri` **静默回退本地默认库**并打印
  「已连接：127.0.0.1:27017/fire_safety_db」，运维以为在清生产索引。
  同族 `resign-audit-hmac.js` / `resign-audit-chain-v3.js` 因为显式调了 hydrate 一直正常，
  它们同时充当探测方法学的正向对照（对照组判"已 hydrate"，说明判据不是在猜）。
- 后果直接落在文档化的运维步骤上：`deployment/secret-rotation.md` 的 HMAC 轮换第 0/4/5 步
  都要求 `node scripts/verify-audit-chain.js` 且注明"要求退出码 0"，
  在 `*_FILE` 部署里这一步**做不到**——第 5 步会退 1，轮换完成后无人给出链条干净的证据。
- 六个脚本各自补 `require('../src/config/secrets').hydrateSecretsFromFiles();`
  （紧跟 `dotenv`，早于任何 env 读取），与本仓既有同族写法一致。
  不用"把 hydrate 塞进 `destructiveGuard.js`"这种集中式改法：它是被 require 的库，
  无权决定进程何时回填，而且 `verify-audit-chain` / `explain-spotcheck` 根本不经它。
- 新闸 `src/tests/config/scriptSecretHydration.test.js`（8 条，逐条能被打红）：
  读取文件型密钥的入口必须**自己**显式 hydrate，且早于首次读取。
  读点有两条通道，只钉第一条会漏——`fix-token-blacklist-index` 唯一的读取通道是
  `require('./destructiveGuard')` 代读，所以把护栏引入点也按读点计（否则删掉它的
  hydrate 行，闸照样绿）。
  判据自证：合成源码攻击（缺 hydrate / hydrate 太晚 / 只赋值不读 / `===` 比较 /
  `JWT_SECRET_V2` 前缀同名）各一条；豁免两条各自带证据——
  `audit-probes/ws-session-bypass.cjs` 必须能为每个读到的名字指出赋值处，
  `destructiveGuard.js` 必须真的被 ≥4 个入口 require；
  压测/演练入口（e2e-smoke / load-test / production-drill）今天只写不读，
  因此**不许预先占豁免位**，哪天它们开始读 env 就会撞红再登记。
  变异实测（用真实文件，不是合成源码）：删掉 `fix-token-blacklist-index.js` 的 hydrate 行
  ⇒ 闸当场报出该文件（「读取文件型密钥 MONGODB_URI，但整个文件没有调用
  hydrateSecretsFromFiles()」），恢复后 8/8 绿——这条正是"只钉直读通道"时会静默漏掉的那个脚本。
- 核过不动的：`scripts/*.sh`（backup/restore）按文档就是 `MONGODB_URI='<连接串>' ./scripts/...`
  显式传值（secret-rotation.md:277），不经 Node 的 env 回填路径。
- 实测（修后）：同一探针下六个脚本全部改为"拿文件值去连"（端口 1 上超时被杀，
  即它们真的读到了 `*_FILE` 里的连接串）。
  另用真实内存 MongoDB 端到端跑 `verify-audit-chain.js`：只给 `MONGODB_URI_FILE`
  （文件内容**故意带尾部换行**）时它连上了库并打印
  「VERDICT: INCOMPLETE — 审计集合为空（0 条）：无记录可验」——这条判定只有连接成功才可能给出，
  空集合是夹具本身没种记录；两者都不给时退 1「未提供 MONGODB_URI」，
  作为反向对照证明前一条不是默认值蒙出来的。

### 修复（2026-10-03 · 上一轮 PII 收窄的两处回归：揭示迟到写入 + 审计副本仍存明文号码）

> 背景：四路并行逐行审计复核 2026-10-02 的两批改动，各命中一条**由那批改动自己引出**的缺陷。
> 两条都已回源核实并做变异实测，不是推测。

- **lane-B #1｜`web-admin/src/views/UserView.vue` 的 `doReveal` 迟到写入守卫**。
  原实现 `await` 之后无条件 `dialog.form.phone = full; dialog.phoneBaseline = full`，
  既不校验目标行也不校验弹层是否还开着。可达路径：点「查看完整号码」后请求飞行期间
  ESC 掉 step-up、关掉编辑框、再点另一行的「编辑」⇒ **A 的明文连同基线一起落进 B 的表单**，
  而界面上的提示恰好是「清空并提交即删除」⇒ 管理员照着删空再保存，
  抹掉的是 **B 的真实号码**。修法是发请求前把 `reveal.userId` 快照成 `targetUserId`
  （step-up 一关 `resetReveal` 就会把它清空，事后读不到），响应回来只在
  `dialog.form._id === targetUserId` 时写入。只比 `_id` 不叠加 `dialog.visible`/`isEdit`：
  关框必走 `resetForm`（`_id` 归 null）、新增框同样是 null，多余的两个条件恒真且**写不出
  能覆盖它们的用例**，留着就是无人验证的死分支。
  门禁：`web-admin/src/tests/views/userView.test.js` 新增两条（切到另一行 / 切到新增框），
  夹具用**手工 defer 的 Promise**——`mockResolvedValue` 在下一个微任务就落地，
  任何迟到守卫都来不及被触发，用例会退化成恒真。
  变异实测：把守卫改成 `if (false && …)` ⇒ 两条同时转红（`expected '13900000000' to be ''`），
  恢复后 61/61 绿。
- **lane-A #2｜`src/utils/helpers.js` 的 `SENSITIVE_KEY_SUBSTRINGS` 补 `phone`**。
  名单原本只管"凭据"，于是 `PUT /api/users/:id`、`POST /api/alarms/report` 这些**写路径**
  把手机号明文留在了 `AuditLog.body` 里，而 `services/securityAlert.getRecentAlerts`
  的投影含 `body` ⇒ `GET /api/security/alerts` 把它再下发一次；`auditBuffer` 的明文 WAL
  同样带着它。结果：持 `security:audit` 的账号无需口令、无需 `system:read`、
  不写一条 `view_sensitive_data`，就能读到任意用户与任意报警上报人的完整号码——
  上一轮"读接口停发明文"只堵了响应侧，**审计侧是同一条合规通道的另一半旁路**，
  而当时新增的 egress 门禁全绿（它只盯响应体），这正是那条门禁的盲区。
  改的是单一事实来源：`auditLogSanitizer` 与 `middleware/security.js` 的两条脱敏流水线、
  以及 morgan 的 URL 打码（`isCredentialQueryKey` 取并集）同时生效，
  扁平 `phone` / 嵌套 `reporter.phone` / camelCase `workPhone` / 敏感键装数组四种形态一起收，
  `?phone=` 在访问日志里同步打码。既有用例 `auditLogSanitizer.test.js`「真实中间件驱动」
  按名单逐键构造请求体，因此**免费**获得了对 `phone` 的端到端覆盖。
  不误伤边界保持原样：`postcode` / `zipcode` 不含 `phone` 子串，值仍可读。
  门禁：`src/tests/models/auditLogSanitizer.test.js` 新增一组 5 条（形态覆盖 + 键名噪声 +
  不误伤 + query/URL 同口径），`src/tests/security/userPhoneMaskedEgress.test.js` 新增一条
  **真实路由**用例（发一次带明文的 PUT → `auditBuffer.flush()` → 读回审计行，
  断 `body.phone === '***'`、序列化不含明文，并用 `body.realName` 证明不是"整块抹掉"）。
  变异实测：从名单里删掉 `phone` ⇒ 4 条同时转红（含真实路由那条），恢复后 12/12 + 11/11 绿。
- **如实声明的残留**：脱敏判定只看**键名**，不做值形态扫描。因此装在非敏感键下的号码
  （`{contacts:['139…']}`、备注文本里的号码）仍会进审计副本——这是刻意止步，
  不是漏网：按 11 位正则扫值会连带抹掉报警描述/备注里的号码，取证价值损失大于收益。
  该边界已写成一条可执行用例（「如实声明边界」），要跨过它需要单独拍板。
  `AuditLog` 里的**历史**明文行不会因本改动消失，清理属数据迁移议题，另行决策。
- 消费方核实：全仓非测试代码只有 `securityAlert.js:84` 按 `body.ipAttempts` 取数，
  没有任何逻辑依赖审计 body 里的手机号可读；现有测试无一断言审计副本含明文号码。
- 文档同批（lane-C #8 的实证条目）：`controllers/securityController.js` 里三处注释错位——
  「举报异常行为 POST /security/report」的标题悬在空处、举报核验的整段 JSDoc（含 `@returns`）
  挂在 `REPORT_TARGET_KINDS` 这张**对象表**头上、还有一段描述 `buildAuditLogQuery` 的 JSDoc
  紧跟在 `getRegistrationConfig` 的文档之前（该函数早已搬到 `utils/auditQuery.js` 的
  `buildAuditQuery`，全仓不存在同名符号）。按"注释只描述它紧邻的代码"重挂，
  并删掉那段失效的构建器文档。改动纯注释：逐行比对确认代码行零差异（只少一个空行）。

### 修复（2026-10-02 · 管理员用户读接口停发明文手机号，改走「脱敏下发 + step-up 揭示」）

> 背景：上一轮把 `reporter.phone` 从报警读出路径摘掉后，同一列在**用户管理**上更严重：
> `models/User.js` 的 `phone` 有 getter 透明解密，且 schema 的 `toJSON/toObject` 只设了
> `getters:true` 没有 `transform` ⇒ 任何**不带投影**的读取都会把明文号码整体发出去。
> 原 `User.RESPONSE_EXCLUDE` 排了 password/phoneKey 等 9 项却**没排 phone**，
> 于是列表 / 详情 / 建号回显 / 改号回显 / 角色回显**五条路径**全部明文下发。
> 后果不只是"看得到"：明文一旦进列表，`POST /api/security/view-sensitive`
> 那条专为手机号建的合规通道（step-up 二次验证 + `view_sensitive_data` 审计 +
> 审计写失败即不返回明文）就被彻底架空——想查号码的人不需要口令，翻页就行。
> 拍板口径：**表格默认脱敏 + 按需 step-up**（用户明确选择服务端一起收窄，不是前端打码）。

- `models/User.js`：`RESPONSE_EXCLUDE` 改为由字段数组拼出，新增 `-phone` 进默认排除；
  派生出 `RESPONSE_EXCLUDE_PHONE_VISIBLE`（同一份数组**滤掉** `-phone`）。
  用数组而不是对字符串做 `replace(' -phone','')`：字符串手术在字段顺序变动时会**静默失配**，
  失配后的表现恰好是"明文照发、门禁照绿"。变体名字本身就写着危险，注释规定它只能与
  `toMaskedAdminUser` 配对使用。
- `services/userService.js`：新增读模型 `toMaskedAdminUser(doc)` —— `phoneMasked =
DataMasking.maskPhone(obj.phone)` 后 **`delete obj.phone`**。四个管理员读函数
  （`listUsers` / `getUserDetail` / `getCreatedUser` / `getUpdatedUser`）改用
  `RESPONSE_EXCLUDE_PHONE_VISIBLE` 并统一过这个函数：投影留着 phone 是为了让**解密 getter
  在服务端跑一次**，脱敏只在服务端这一处做——`maskPhone` **不幂等**（对 `138****5678`
  再打一次得到 `****`），所以前端一律不再打码，只做展示。
- **响应字段改名成 `phoneMasked` 而不是 `phone: 脱敏值`**（有意偏离 `my-info` 的既有口径）：
  编辑对话框会把行对象灌进表单，而 `userController.js` 用 `if (phone !== undefined)` 落库、
  路由校验是 `/^1[3-9]\d{9}$/` ⇒ 叫 `phone` 的展示值只有两种结局，且**都是坏的**：
  原样回传被 400 拒掉，或被当成"用户想清空号码"抹掉真值。改名让"这是展示值、不是可写字段"
  在类型上就不可能被搞混。
- `web-admin/src/views/UserView.vue`：列表列读 `phoneMasked`；编辑对话框**不再回填**手机号，
  改为输入框旁一个「查看完整号码」→ 二级 step-up 弹层（只收当前登录口令）→
  `POST /api/security/view-sensitive` 返回的 `full` 才进输入框。提交按**脏字段**发键：
  未揭示 / 揭示后未改 ⇒ 不发 `phone`；揭示后删空 ⇒ 发 `''`（这才是真的清空）。
  提示语随 `phoneBaseline` 切换，两处状态各自说清"留空即不修改"和"已载入现值"。
  step-up 的口令由 el-dialog `@closed` 单一清理点负责（打开时再清一次是冗余，
  冗余那处会让清理逻辑被改坏时测试照样绿）。
- **有意的边界，不一起收窄**：自助通道 `GET /api/auth/me` 与 `PUT /api/auth/profile`
  仍返回本人明文号码——那是用户自己的数据、且编辑页需要现值；`utils/permissionHelper.js`
  处早已写明"回填脱敏值会污染数据或阻断保存"。这条边界用一条**反向**用例钉住
  （`/auth/me` 必须还能拿到明文），免得下一个人"顺手统一"。
- 消费方核实：web-admin 里 `users.getList` 的 phone 只有 UserView 一处读，ProfileView 读的是
  `/auth/me`，RegisterView 是自己的表单 ⇒ 停发零界面功能损失。搜索侧无残留 oracle：
  列表 `search` 的 `$or` 只覆盖 username/email/realName，`phoneKey` 全仓**无** `find({phoneKey})`
  （`models/User.js:270-277` 已记为"已供未接"）。
- 文档同批：`openapi.json` 建号请求体的 `phone` 补 description「仅接受写入；
  列表/详情/建号/改号/角色回显返回 phoneMasked，不含该字段」（`src/docs/generate.js` 重生成）。
- **门禁**：新套件 `src/tests/security/userPhoneMaskedEgress.test.js`（10 例）——
  夹具自证（不带投影的裸读确实能拿到明文，证明排除不是空转）/ 两条投影只相差 `-phone` /
  五条响应路径逐个断言 `'phone' in payload === false` **且** `JSON.stringify` 不含明文
  **且** `phoneMasked` 值正确（只断言"没有"会让整列被删也测成通过）/ 边界自证
  （省略键 ≠ 清空；把 `139****1122` 提交上去必须 400 **且库里原值未变**）/
  view-sensitive 揭示与 `/auth/me` 两条反向钉 / 源码文本闸：`RESPONSE_EXCLUDE_PHONE_VISIBLE`
  出现处必须紧邻 `toMaskedAdminUser`（防"换投影忘了脱敏"），并钉住 `delete obj.phone;`。
  变异实测三臂：摘投影 → 5 红；摘 `delete obj.phone` → 2 红；把变体名改回基名（模拟漏接）→ 1 红。
- 前端门禁：`userView.test.js` 新增 9 例（脱敏列渲染 / 新增框无揭示入口 / 空口令不发请求 /
  揭示请求形状 / 揭示后不改不发键 / 揭示后删空发 `''` / 揭示失败不污染也不误发 /
  口令不跨次残留 / 关外层时二级弹层一并收起）。step-up 是嵌套对话框，`append-to-body` 后
  节点挂在 body 上，"是否关闭"只能断言 overlay 的 `display` 终态——EP 关闭后 DOM 仍在，
  断言节点消失会得到一条恒真的假绿。变异实测三臂：提交无条件带 `phone` → 3 红；
  列改回 `row.phone` → 1 红；摘掉 `@closed` 清理 / 摘掉外层关闭 → 各自对应那条红。
- **如实声明残留**：库里仍是可解密的密文（本改动只收窄**下发面**）；操作者**本人**的明文手机号
  仍会写进 `localStorage.currentUser`（`/auth/me` 的形状），是否连浏览器持久化一起收窄
  需要单独拍板——它会改变刷新后 ProfileView 的短暂空值表现，且 email/realName 同批同性质。

### 修复（2026-10-02 · 报警读出路径停发 `reporter.phone`）

> 背景：四路逐行审计的 lane-B 报出一条新缺陷并回源核实。`FireAlarm.reporter.phone`
> 是**明文存的第三方手机号**，不属于 `models/User.js` 那套「getter 解密 +
> `POST /api/security/view-sensitive` step-up + `view_sensitive_data` 审计」通道；
> 而报警的读出路径原本一条根文档投影都没有 ⇒ 任何持 `alarm:read` 且落在该条范围内的
> 账号都能**整页批量**读到它，无二次验证、无 `system:read`、无留痕——把仓里专为
> 手机号建的合规通道架空。同一 model 上的 `handler.phone` 正因同样理由被收窄过
> （`alarmDetailHandlerPii.test.js`），这条是同一列的邻接漏点。
> 拍板口径：**读出全部停发**（对齐 handler.phone 先例），不做静态加密改造。

- `services/AlarmService.js`：新增模块级 `ALARM_READ_SELECT = '-reporter.phone'`，
  **八处**调用点全部引用同一个常量——游标列表 / offset 列表 / 详情用 `.select()`，
  五个处置接口（dispatch/arrive/resolve/false-alarm/cancel）用 `options.projection`。
  后者是这次真正容易被漏掉的部分：它们把 `findOneAndUpdate` 的 `updated` 文档原样回给
  客户端，只修列表与详情等于同一列从这五个口整块漏出去，而 CI 仍全绿（那五个响应体
  本来没有用例读过）。
- **有意的例外**：`POST /api/alarms/report` 回显 create 出来的文档，其中含提交者自己
  刚写进去的号码——不构成新的读取，故不改（已把这条写进常量的 JSDoc，免得被当成漏点
  重新发现或"顺手补上"）。
- **如实声明残留缺口**：值仍明文存在库里；备份转储与密钥轮换的保护缺口**不随本改动关闭**。
  将来若要开放"回拨上报人"，正确做法是给它一条与 User PII 同级的揭示通道，
  而不是把这一列加回读接口。
- 消费方核实：web-admin 全文 0 处读 `reporter.phone`/`reporterPhone`，报表导出只取
  `reporter.name`（`reportExportService.js:266`），e2e 0 处 ⇒ 停发零界面功能损失。
- 文档同批：`models/FireAlarm.js` 的 `reporter.phone` 注释写明"明文存储 + 读接口不回传"，
  `openapi.json` 的请求体字段补 description「仅接受写入，列表/详情/处置响应均不返回」。
- **门禁**：新套件 `src/tests/services/alarmReporterPhoneEgress.test.js`（7 例：
  夹具自证裸查询能拿到明文 / 详情 / offset 列表 / 游标列表 / 五个处置回显 / 状态机前提自证 /
  源码文本闸）。每条排除断言都带反向证据（`reporter.name` 必须还在），防止"整个子文档被
  删了"或"populate 没生效"伪装成通过。源码闸的窗口取「到下一个调用点为止」而不是固定字数
  ——`resolveAlarm` 的 `$push` 文案块就比 420 字符长，固定窗口会对正确的代码报红。
  变异实测两臂：摘掉详情的 `.select` → 行为与源码闸 2 红；只摘 `cancelAlarm` 一处的
  `projection` → 处置回显 + 状态机自证 + 源码闸 3 红（证明"只修一条"确实会被抓住）。

### 测试（2026-10-01 · 两处 HEAD 上就存在的红灯）

> 全量 `npx jest --ci` + `npm run format:check` 复跑时发现：不需要本轮任何改动，main 上已经有
> 三条用例与一条格式闸是红的。CI 跑这两条（`ci.yml` 的 jest 与 `:79` 的 format:check）⇒ 合并队列
> 上任何后续提交都会被这两处**别人的**失败误判成"本提交引入的回归"，所以先修它们。

- **`websocketRedisAdapter.test.js` 落后于 Redis 认证改造（2 例红）**：`2816d68` 给订阅端补了
  `password: sharedCache.redisConnectionPassword()`（`websocketService.js:260`），但该套件的
  `jest.mock('../../services/sharedCache')` 工厂只造了 `isRedisEnabled`/`getRedisClient` 两个键。
  失败形态很有教育意义：第一条是 `toHaveBeenCalledWith` 的对象不匹配，第二条**不是**它声称要测的
  "挂载失败降级"，而是桩自身缺键抛出的 `sharedCache.redisConnectionPassword is not a function`
  被 `catch` 吞掉后进了同一条 warn 分支——断言只匹配 `stringContaining`，于是"桩坏了"伪装成
  "降级路径测过了"。收口：桩补该函数并返回哨兵值，断言要求哨兵出现在 `new Redis` 的 options 里
  （`toHaveBeenCalledWith` 是全等对象匹配，多键/少键/漏传都红 ⇒ 这条现在是"口令必须外发到
  订阅端"的真闸，而不是只让套件变绿）。
- **`piiEncryption.test.js` 格式（1 条格式闸红）**：`4402562` 移除未使用导入时留下了未过 prettier 的
  解构折行。本轮只做格式化（1 增 6 删，零行为变化）。

### 修复（2026-10-01 · `POST /api/security/report` 的目标核验与账号配额）

> 背景：该端点刻意不挂权限码（人人可举报是产品设计），但路由注释自称「本人资源…无越权面」
> 是**假的**——上报内容由调用者撰写，`targetId` 指向的却是别人的记录。修复前任何登录用户
> 都能提交任意 `targetId`（不校验存在性、不校验范围、无独立配额），服务端原样写进一条
> `riskLevel:'high'` 的审计行，而安全概览的「高风险操作数」与告警取数都读这批行。

- **路由层**：`targetId` 的形态由 `targetType` 决定——记录型（user/device/alarm）必须是非空
  字符串且为 ObjectId；`system` 型**禁止携带**（否则把类型改成 system 就绕过整条核验）。
  `.exists({ values:'falsy' })` 承担的是文案而不是拒绝：删掉它后面的 `isString` 会给同一个
  400 和同一个 path，变异实测确认「只看状态码+path」的用例是绿的但不设防，故用例断言 msg。
- **控制器**：记录型目标必须**真实存在**（否则 404，`USER_NOT_FOUND` 在注册表里是 401 的
  登录语义，此处显式改 404）且**落在举报人的数据范围内**（否则 403）。范围判定复用
  `rbac.assertRecordInScope` + `DATA_SCOPE_FIELDS` 单一声明，与各自详情/写路径同判据；
  404/403 的先后与 `deviceController.js:122/124`、`alarmController.js:156/158` 的既有口径
  一致（存在性预言机在每条授权读路径上本来就存在，本处不新引入一类泄露）。
  自由文本 `reason`/`description` 不受影响：被约束的是"结构化字段必须是真记录"。
- **限流**：新增账号维度桶 `securityReportUserLimiter`（20 次/15 分钟，键 `report-user:<userId>`，
  不含 IP 成分）。与凭据型姊妹桶同一口径：**并列**而不是把 IP 从组合键里删掉；同样
  **不接** `noteRateLimitHit`（账号桶没有可封的 IP）。阈值刻意不导出：测试里钉死 20 并同时
  校验服务端声明的 `RateLimit-Limit`，改配额会让用例变红而不是自动适配。
- **分层**：数据访问经 services 的 `findScopeFieldsByIds`（`AlarmService` 补该 getter，
  投影 `reporter.userId handler location.building`），控制器不新增直连 model——
  初版直连 FireDevice/FireAlarm 被 `architecture/layeringRatchet` 判红（5→7）后改的。
  连带：`skipGlobalAuditWriteFailure.test.js` 的 `models/User` 桩只提供了 `findById`，
  而 `userService.findScopeFieldsByIds` 的形状是 `find().select().lean()` ⇒ 桩补该链路并返回
  与夹具 `targetId` 同 `_id` 的记录，否则该套件两条举报用例先撞 `TypeError`，
  走不到它要测的审计写入点（全量跑实测到）。
- **门禁**：新套件 `src/tests/security/reportTargetScopeAndLimiter.test.js`（23 例：存在性、
  三条范围臂的放行与拒绝、绕口封堵、配额与 XFF 轮换、trust proxy 前提自证、
  投影完备性静态闸）+ 改写 `reportTargetIdBoundary.test.js`（形状边界，7 例）。
  变异实测 5 臂：中和范围臂→B 组 4 红；摘掉限流→D 组 2 红；删 `.exists`→msg 断言红；
  删 system 反例→绕口封堵红；删存在性→A 组与边界 404 判据 3 红；删投影一列→B/E 同时红。
- 文档同批收窄：`models/AuditLog.js` 的 `targetId` 契约注释、`PERMISSION-EXEMPT` 理由改写为
  如实版本、`src/docs/openapi.json` 重生成（targetId 加 ObjectId pattern + 403/404 响应）。

### 修复（2026-10-01 · 13 项报告回源复核后的三处落地）

> 背景：对一份 13 条的审计报告**逐条回源复核**，其中 8 条已在 19:21~20:50 的提交里闭环、
> 1 条（封禁目标可伪造）在他方在途、4 条未动。本轮落地的是**报告里没有的三处**——
> 两条由复核过程新发现，一条属报告第 13 条所在的低优先段。

- **N1 HMAC_SECRET 消费点清单收敛为单一来源**。复核发现同一份仓库里存在**三份互不相同**的清单：
  `deployment/secret-rotation.md` 写「**两个**消费点」（审计链 + 口令历史），
  `deliverables/AGENT工作总账与待办` 的 F-26 写「三个」（审计链 + MFA 恢复码 pepper + 数据签名密钥，
  **漏了口令历史**），而真实源码是**四个**（`src/utils/auditChain.js` / `src/utils/passwordHistory.js` /
  `src/services/mfaService.js` / `src/utils/encryption.js`）。手册全文 `恢复码` **0 命中**——
  而恢复码是用户丢掉认证器时的唯一逃生门，换钥后静默失效，故障只在"某个人手机丢了"那天暴露。
  收口：① 手册改成四消费点表（含"只有第 1 个有迁移工具"的非对称事实）；
  ② 新增门禁 `src/tests/config/hmacSecretConsumersSingleSource.test.js`——扫描 `src/`（排除
  `src/tests` 与 `src/config` 装载面）里**取值访问** `HMAC_SECRET` 的文件，要求集合恰好等于登记清单，
  并要求手册逐个点名。判据取「取值访问」而非「提到 HMAC_SECRET」：注释/报错文案/校验器里都会出现
  大写 `HMAC_SECRET`，算进来会让清单被噪声撑大、反而失去意义（`services/auditChainVerify.js` 的
  `computeHmac` 是从 `utils/auditChain.js` 导入的，密钥取值不在它那里，故不重复计）
  - 门禁：新套件 9 例（含"扫描基线非空"防"零命中被当成通过"、"手册必须点名恢复码"作回归哨兵）
- **N2 PII v1 存量行的静默缺口补启动期告警**。10-01 把写侧切到 v2（AAD 行绑定）时读侧刻意保留 v1 兼容，
  代价是 **v1 密文与行身份无关**——`utils/piiCrypto.js` 的 v1 分支 `aad` 保持 `null`、`if (aad)` 永不
  `setAAD`，于是把 A 行的 `enc.v1.…` 复制到 B 行，B 行的 getter（`models/User.js:105-106` 虽已传
  `{subjectId, field:'phone'}`）会**正常解出 A 的明文**。写侧不再产 v1，但**存量行不会被自动升级**，
  而升级唯一入口是手工跑迁移脚本，**没有任何启动期信号**（`src/config` 下只有 `pii_rotation_old_key_lingering`
  那条旧钥告警，与"v1 未迁移"无关）。收口：`config/immutableConfigGuard.js` 增加第三项
  `pii_v1_rows_unmigrated`（生产 + PII 主密钥可用 ⇒ 告警 + `incSecurityAlert`，**不阻断启动**，
  口径同 immutable 档位），并写进轮换手册收尾清单
  - **如实声明边界**：该告警的判据是"代码仍支持读 v1"，**不是"库里还有 v1 行"**——启动路径
    （`config/validate.js`）在 mongoose 连接**之前**执行，不连库，故它**不会自行消失**。要判"迁完了没"
    只有一条路：`node scripts/migrate-pii-encryption.js`（演练模式、只读）看剩余行数。这条边界已写进
    手册与告警文案，否则运维会拿"告警还在"误判成"没迁完"
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **2 条反向断言**：非生产不得告警、
    主密钥缺失不得告警）。**变异实测被杀**：把判据改成 `NODE_ENV !== 'never-matches' && true` ⇒
    4 条红（2 条反向断言 + 2 条既有的 `toHaveLength(1)`），改回后 29/29 绿
  - **待拍板（未落地）**：更彻底的做法是把 v1 读路径也改成 fail-closed（镜像 `ALLOW_LEGACY_CBC_DECRYPT`：
    缺 `ALLOW_PII_V1_DECRYPT=true` 即抛），那样"库里有 v1 行"会当场变成响亮的读错误。
    未做是因为它是**生产行为变更**（升级即可能让存量行读失败），按本仓纪律属"需人拍板"那一档
- **#12 上传扩展名闸由 fail-open 改为构造期 fail-closed**。`middleware/security.js` 原实现是
  `allowedExts = allowedTypes.map(t => MIME_TO_EXT[t]).filter(Boolean)` 配 `if (allowedExts.length > 0 && …)`
  短路：白名单里**一个都映射不到**时 `filter(Boolean)` 把结果清空 ⇒ **扩展名校验整条消失**，
  只剩客户端自报的 MIME。今天无 multer 挂载故不可利用，但"配了却不生效"一旦随首个上传路由上线就会同时生效。
  收口：MIME→扩展名映射与校验提到**构造期**（= 路由装配期，即启动期），`allowedTypes` 里存在**任何一个**
  未映射项即抛错（只抛"全部未映射"会把部分静默放行留在原地），运行期不可能再出现"白名单非空但扩展名闸为空"
  的组合，短路判据随之简化为 `allowedTypes.length > 0`
  - 门禁：`securitySanitizeAndBlacklistDegrade.test.js` 追加 5 例（全部未映射抛 / 部分未映射抛 /
    报错点名支持集 / 空白名单不抛 / 受支持白名单不抛——最后两条防"一律抛"的恒真实现），该套件 30/30 绿
  - 已知边界：本次**只**修扩展名闸的 fail-open，未新增任何上传路由；中间件仍是"预留能力、无路由挂载"

### 修复（2026-09-30 · 安全缺口核查落地）

- **敏感 GET 读取审计判据反转（P1-④）+ PII at-rest 加密（P1-②）+ 备份加密（P1-①）等七项缺口收口**（对照 `deliverables/安全缺口核查-2026-09-30.md`，其中 P1-④ 与 P2-⑥ 已于本日早先提交落地）：
  - **P2-⑧ 传输加密启动断言**：生产环境 Mongo 非回环主机必须 `tls=true`、Redis 必须 `rediss:`，豁免走显式旗标 `MONGODB_TLS_EXEMPT`/`REDIS_TLS_EXEMPT`（同宿主 compose 即豁免使用者，拆分拓扑忘摘旗标会被启动期拦截）；判据收口 `config/transportSecurity.js`（回环判定吃 127.0.0.1/::1/IPv4-mapped/localhost 全形态；hostname 解析不出保持沉默——compose 契约测试的替身 URI 不被误杀）
  - **P2-⑨ 出站目标门禁**：`LOG_SHIPPING_URL` 在 scheme 白名单之外再拒内网/回环/链路本地目标（云元数据端点是经典 SSRF 目标）；歧义 IPv4 形态（127.1/2130706433/0x7f.0.0.1，严格解析判 null 但 OS 仍按回环连）一并拒绝；内网 SIEM 用 `LOG_SHIPPING_ALLOW_PRIVATE_HOSTS` 显式放行（主机名/IP/CIDR，与 IP 名单同一把尺）。判据 `isPrivateOrLoopback` 自 metricsAuth 迁入 `utils/ipUtils.js` 单一来源（middleware→utils 反向依赖会破分层）
  - **P1-① 备份加密 + 校验和 + 异地副本**：`backup-mongo.sh` 默认 gpg 非对称加密（备份宿主机只放公钥，私钥托管异地），明文出口 `BACKUP_ENCRYPTION=plaintext-acknowledged`（取值即确认词）；产物三件套 .gz.gpg + .sha256 + `BACKUP_OFFSITE_CMD` 异地钩子（argv 解析不经 shell 展开、失败即整体失败）；`restore-mongo.sh` 按后缀自动解密；加密/解密/校验和收口 `scripts/backupCrypto.sh`（与 mongoUri.sh 同一共享范式）；恢复演练与密钥托管见 `deployment/backup-encryption.md`
  - **P1-② PII at-rest 加密（范围修订）**：`phone` 走随机 IV AES-256-GCM（`utils/piiCrypto.js`，密文带 `enc.v1` 版本前缀供轮换），精确检索走 HMAC 检索键 `phoneKey`（select:false + 索引）——相等性不泄漏在密文列里；存量明文**读路径透传**（迁移前的旧行照常可读），写侧 `pre('validate')` 钩子加密（手机号格式校验随钩子前移到明文阶段，错误文案逐字不变）；迁移/轮换脚本 `scripts/migrate-pii-encryption.js`（演练/apply 双模，损坏行点名不覆盖，同族 allowlist 门禁）。**realName 暂不加密**（2026-09-30 决策）：姓名片段模糊检索是用户列表的日常能力，正则对密文不成立，加密它等于砍掉该能力——用户列表搜索继续覆盖 username/email/realName；`realName` 转入加密需先给姓名检索另立方案，脚本对加密窗口内已产生的密文行自动解回明文自愈
  - **P2-⑩ 供应链可追溯**：CI 构建产出 CycloneDX SBOM 并上传 artifact；镜像 `provenance: true` + cosign keyless 签名（build 作业补 `id-token: write`）
  - **P2-⑫ 依赖钉版**：`.npmrc` `save-exact=true` 从源头杜绝 caret 漂移；新增 CI 硬门禁「生产依赖树禁止任何 install 脚本」（`scripts/check-prod-install-scripts.js`，fail-closed + 显式白名单——比 --ignore-scripts 更强：ignore-scripts 只让本机跳过，树里有没有脚本没人看）
  - **P3-⑬⑭⑮ 治理文档三份**：`docs/threat-model.md`（STRIDE + 残余风险如实申报）、`docs/incident-response.md`（角色/时限/命令级遏制清单，全部绑定本系统实际存在的端点与脚本）、`docs/mlps2-controls.md`（等保 2.0 第三级重点项对照，每条挂文件/测试/端点证据）
  - 门禁：`transportTlsAssertion`（9 例）/ `backupEncryptionContract`（stub gpg 行为链）/ `piiEncryption`（纯判据 + 真实 Mongo 接线，9 例）/ logShipper 出站目标真值表（27 例）等新增约 60 例；既有 backupTransport/backupScriptGuards 夹具显式声明明文确认出口，保持其原断言对象不变

### 修复（2026-09-30 · 供应链完整性锚 + PII 旧钥残留守卫）

- **P2-⑩ 补：lockfile 完整性锚**（`scripts/check-lockfile-integrity.js` + `deployment/lockfile-anchor.json` + `npm run check:lockfile` + CI `security-audit` 一步）。已有的 SBOM/cosign/provenance 回答的是「我用了哪些组件」与「镜像来源可证」，但**不比对「依赖树与上次拍板时是否一致」**——一个夹带改 `integrity` 的 PR 会被 SBOM 忠实记录、却被当成正常构建。本锚把「上次人工拍板时锁文件长什么样」固化成哈希写进版本库，任何改动必在 diff 现形。判据口径是 **semantic 哈希**（`JSON.parse` → key 排序 → 紧凑序列化 → SHA-256）：**用原始字节哈希会在 CRLF/LF 间漂移**（开发机 Windows/CI ubuntu），后果不是「偶尔红」而是 **CI 恒假红**，而假红第一次出现就会被 `continue-on-error` 消化掉、等于没有门禁。覆盖面 2 份（后端 + `web-admin`；`zznpmtest/` 已 gitignore 故不纳入）。fail-closed：锁文件缺失/解析失败/锚缺失一律 exit 1
  - 门禁：`src/tests/deploy/lockfileAnchor.test.js` 11 例，真调脚本导出的纯函数（**不复刻判据**）；核心是「同一 JSON 的 CRLF 与 LF 版本必须同哈希」——把上述决定性实验固化成回归闸。篡改一处 `integrity` 实测 `exit=1` 且报错点名文件与期望/实际值
  - **如实声明边界**：本锚**不是 SBOM**，挡住的是「锁文件被改」，**挡不住「上游包本身被投毒且 lockfile/integrity 未变」**
- **P1-② 补：PII 轮换旧钥残留守卫**。`scripts/migrate-pii-encryption.js:48-53,106` 把 `PII_ROTATION_OLD_AES_KEY`（**旧主密钥明文**）作为 `--rotate` 的输入参数，但**没有任何地方要求轮换后清理它**——不在启动校验面、不在轮换手册收尾清单、不在脚本输出里。它是**过程残留物**而非运行时配置：一旦驻留生产环境，**轮换等于白做**（轮换的前提是「假定旧钥已泄露」，而旧钥 + 轮换前备份归档仍可解出当时全部 PII）。三处收口：① 启动期生产环境检测（并入 `config/immutableConfigGuard.js`，**告警 + `incSecurityAlert`，不阻断启动**——口径同 immutable 档位，它可恢复而阻断会让疏忽变成停机事故）；② 轮换手册收尾清单加一条；③ `--rotate --apply` 成功且无损坏行时脚本主动打印清理提示（运维跑完就在看这个输出，命中率最高）。空串/纯空白判为「无残留」（`.env` 写 `KEY=`、compose 传空值是常见 unset 等价物，判成残留会造成恒真误报）
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **4 条反向断言**：无旧钥不得告警、非生产不得告警、空串不得告警、无残留不得顶掉既有告警）。**4 组变异全部被杀**（去掉生产条件 1 红 / 去掉空串判断 2 红 / 守卫恒真 6 红 / 去掉 `incSecurityAlert` 1 红）——反向断言不是摆设
  - 同时记录一处会咬人的内部行为（非缺陷）：`--rotate` 执行期间脚本把 `AES_SECRET_KEY` 临时指向**旧钥**（`:106`），结束后恢复；当前是独立 CLI 故风险低，但**勿把迁移逻辑内联进服务进程**，否则轮换窗口内服务会用旧钥加密新数据
- **测试基建：`ciGateWiring` 的门禁清单补防瘦身断言**。`CI_ENFORCED_GATE_SCRIPTS` 此前只有**正向**检查（登记了 → 必须被 CI 调用）。变异实测：删掉清单任一行，套件只是「少跑一条」，**13/13 依然全绿** ⇒ 清单可被静默删行、被删掉的门禁从此无人守护且无任何测试变红。补反向断言：从 workflow 文本抽出实际调用的 `scripts/*.js`，要求全部已登记或已进**显式豁免清单**（豁免附理由，如 `scripts/deploy.js` 是部署脚本、非判定类门禁）。用显式豁免而非放宽匹配，是为了让「为什么它不算门禁」这个判断本身可审计。变异验证：删登记行 ⇒ 1 条红

### 新增（2026-09-30）

- **口令复用历史**：此前 `changeUserPassword` 里只有 `SAME_PASSWORD`（"不能与**当前**口令相同"），A→B→A 这种两步复用完全放行；`helpers.validatePasswordStrength` 只覆盖长度/复杂度/泄露库，全仓零处检查复用。现 `User.passwordHistory` 保存最近 N 条（默认 5，`PASSWORD_HISTORY_DEPTH` 可调，上限 24）**已退役**口令的 HMAC-SHA256 摘要，改密时逐条比对并拒绝，写入被替换掉的旧口令。摘要用 HMAC 而非 bcrypt：历史条目的用途是**等值比较**（比较时明文就在手里），bcrypt 的"慢"是为离线爆破服务的，此处不适用，而代价很实在——rounds=12 下每条 250~300ms、保留 5 条即 1.5 秒且全部挂在改密端点上，而 `passwordChangeLimiter` 只按 user+ip 限到 5 次/15 分钟、**没有全局护栏**，N 个账号就能把 CPU 打满。沿用本仓已有的同类先例 `services/mfaService.hashRecoveryCode`（HMAC + pepper，未配密钥时退化 sha256）。新增错误码 `PASSWORD_REUSED_IN_HISTORY`（400），两个改密端点（`/api/auth/password` 与 `/api/security/change-password`）映射一致，文案里的 N 由后端 `params.historyDepth` 下发，前端不写死数字
  - 已知取舍（如实记录而非假装解决）：轮换 `HMAC_SECRET` 后既有摘要全部对不上 ⇒ 历史长度归零，轮换窗口内复用防线短暂变弱。审计链 HMAC 那套重签工具在这里**不适用**——没有明文就无法重算
  - 门禁：`src/tests/utils/passwordHistory.test.js` 20 例。除判定语义与 A→B→A 行为级用例外，另有**接线不变量**（`.select('+passwordHistory')`、成功后写历史、schema `select:false`、两个控制器 outcome 映射、错误码 4xx、前端登记）——语义测对了而没接线是这类修复最常见的落地失败形态，那时下面所有语义测试仍会全绿

### 变更（2026-09-30）

- **敏感 GET 读取审计判据反转：6 条允许清单 → 默认全量 + 显式豁免清单**（`middleware/security.js` 的 `auditGetPaths` → `auditGetExcludePaths`，收口审计报告 §3.4）。原判据是 fail-open：新增一条敏感 GET 路由而忘记登记即零留痕——设备/报警/巡检的**列表与详情**正是一批这样的盲区（P0 时的 HEAD 归一修复只救了已登记的 6 条前缀；列表与详情共用派生 action `*_view`，故无需新增 action 登记）。反转后 GET/HEAD 默认审计，豁免清单只剩两类、逐条写明理由：a) 预认证/登录流程面（captcha/captcha-status/login-public-key/mfa-status，无业务数据且调用频率由认证流程决定）；b) 纯自读面（session/me/sessions/my-info/bindings/my-logs——数据主体即请求者本人且被前端每次导航轮询，操作留痕由写路径承担：改密/MFA 变更/踢会话均为写方法照常审计）。fail-closed 的直接后果：未匹配路径的 GET 探测与匿名 401 也会在审计里留痕（与既有 `/api/users` 行为一致），审计记录量随读取流量上升属预期成本；运维看板若高频轮询设备/报警列表，按 security.js auditLog 头注口径逐条评估后加豁免，**不回退允许清单**。守卫同步：`auditActionReachability` 台账 A 类 25→9（16 条随反转为真实落库并从台账移除），解析器改读 `auditGetExcludePaths` 并反转判定
- **CC 防护升级：限流信号按类别分桶，阀值差 10 倍**（`src/services/rateLimitEscalation.js`，拆出 `rateLimitEscalationBan.js`）。此前全仓只有**一个**阀值（30 次/5 分钟），而喂进这个计数器的 7 个限流器**合法拒绝率相差两个数量级**——把「30 次 captcha 拒绝」与「30 次任意请求拒绝」当成同一种证据。实际后果是两条具体的误封：① `strict` 是**已认证**端点（refresh / MFA / 报表导出 / 审计导出 / 重置他人密码），一个管理员给 20 名新员工批量开户 = 60 次操作，**共享出口 IP 的整间办公室被封 1 小时**——而越界的是账号不是 IP；② `general`/`ip` 是体量信号，其配额在 NAT 共享出口下本就被多人分摊。现分三类各用各的阀值：`ANON_ABUSE`（captcha/login-ip/register，默认 10，封 IP）、`VOLUME`（general/ip，默认 **100**——原取 30 时这一档被误伤，100 才是它的量纲，封 IP）、`AUTH`（strict/user-ip，默认 30，**只告警不封 IP**，处置走账号侧）。混检不提前：10 次 captcha + 90 次 general 不会让 ANON_ABUSE 到点
- **固定窗口 → 令牌桶**（同上）。原实现的固定窗口有两个固有缺陷：**边界突发**（窗口末秒打满 N 次、次秒重开再打 N 次可取到 2N 速率）与**升级即清零**（达阈值后 `count = 0; windowStart = now`，封禁若恰好失败则下一轮又白拿一整个窗口）。令牌桶按 `阀值/窗口` 匀速回填，两个缺陷一并消除；持续速率恰好等于阀值的攻击者不再触发（等于预算本就不该被封）。代价是纯突发打满 N 次要第 N+1 次才封——这是去掉时序后门的代价，不是弱化
- **处置与通知解耦**（`src/services/rateLimitEscalationBan.js`）。原实现 `if (!shouldSendAlert(...)) return;` 把**审计与封禁一起挡在门外**：封禁失败（写库故障 / 命中白名单）时 5 分钟内的重试也被吞掉，而审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 档」。现审计与封禁无条件执行，只有 `dispatchNotification` 受频控约束
- **计数表淘汰：`clear()` → 压力升序有界淘汰**（同上）。`hits.clear()` 是一条**可主动触发的旁路**：攻击者轮换满额 IP 就能把所有人的计数归零。改为先清已回填的，仍满则牺牲「最接近升级」程度最低的条目。刻意**不按最旧优先**——那同样是旁路：被牺牲的会是积累已久、正要升级的那条，而攻击者新轮换进来的垃圾（压力 1）反倒留在表里。淘汰顺序必须由**安全价值**决定，不由时间决定
- **审计记全量构成**（同上）。原实现只把**触发阀值的那一个限流器**写进 `body.limiter`，于是「10 次 captcha + 20 次 general」被记成「general 触发」，事后复盘归因错误。现写 `body.mix`（各限流器计数）+ `body.total` + `body.className`
- 新增 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH` / `CC_ESCALATION_EVICT_RATIO` 五个环境变量（此前 `CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 已于本轮移除），`.env.example` 补全分类判据与推导依据

### 修复（2026-09-30）

- **immutable 档位（改配置需配套数据迁移）在启动期完全静默，运维改了配置直接重启无任何提示**（新增 `src/config/immutableConfigGuard.js` + `src/tests/config/immutableConfigGuard.test.js` 10 例）。`HMAC_SECRET` 在本仓有两个消费点：审计链 `hmac`（有 `scripts/resign-audit-hmac.js` 重签工具可迁移）与**口令复用历史摘要的 pepper**（`utils/passwordHistory.js`，**没有也不可能有配套工具**——历史里存的是 `HMAC(旧钥, 旧口令)` 的 hex，无明文无从重算）。`deployment/secret-rotation.md` 的「各密钥轮换影响面」表只写了前者，收尾清单也没提后者 ⇒ 运维照 Runbook 做完全量轮换，口令复用防线已归零而手册不吭声。现启动期推一条 warning（文案点名 pepper / 历史归零 / 无重签工具 / 指向手册），并计 `incSecurityAlert('password_history_pepper_rotation','medium')`——口径与 `ALLOW_LEGACY_CBC_DECRYPT` 的既有加固完全一致（"可检测 ≠ 已告警"）。**刻意不阻断启动**：该配置的合法取值本身包含"已知代价"那一档，要拦的是**静默**不是取舍。手册同步补该影响面小节、收尾清单条目，以及 `PASSWORD_HISTORY_DEPTH` **调小**（唯一不动密钥却同样让存量对不上的项，`sanitizeHistory` 读取侧截断）的说明。**实测变异验证**：把 immutable 的 push 塞进 CBC 的 `if` 块 ⇒ 2 条红；去掉 `incSecurityAlert` ⇒ 1 条红
- **安装脚本门禁的可证伪性为零（"测试复刻了一份判据"）**（`scripts/check-prod-install-scripts.js` / `src/tests/deploy/installScriptGate.test.js`）。该门禁是 Dockerfile 里 `npm ci --omit=dev --ignore-scripts` 安全性成立的**唯一依据**，而它初版的测试把判定语义**复刻**了一遍（自写 `classify`），注释还自称"可证伪"。**实测证伪**：把筛选条件 `omitDev ? !e.dev : e.dev` 写反（生产树与 dev 树颠倒 ⇒ 门禁退化成"永远失败"），复刻版测试 **6/6 全绿**。这是一类通用的失效形态——复刻一份判据等于测试了一个平行实现，与被测对象是否还正确无关。现脚本导出纯函数 `evaluate(lock, omitDev)` 并加 `require.main === module` 守卫，测试**真调**它；同一变异下 6 条变红。另：白名单按依赖树分两档（生产树命中即红 / dev 树逐个登记理由），判据改用 `package-lock.json` 的 `hasInstallScript` + `dev` 标记（实测 `npm ls --json` 的节点**不含 scripts 字段**，1317 节点 0 命中，故不能作判据来源）、白名单登记 `@scarf/scarf`（锁文件 `dev:false`，经 swagger-ui-express 传递引入生产树）与 `mongodb-memory-server` / `fsevents`
- **`npm ci --ignore-scripts` 的落点（CI 4 处 + Dockerfile 3 处，逐处给判据而非一刀切）**：`Dockerfile` 三处**全加**（builder 阶段从不跑测试、web-builder 与 runtime 均与 mongod 无关，且 runtime 那处由 `--omit=dev` 档门禁保证"没有脚本需要忽略"），`migrate-mongo` 补装命令一并加。CI 侧**刻意只给 e2e-browser 加**（其 Mongo 来自 `mongo:6.0.20` service 容器，不依赖 `mongodb-memory-server`）；`test` 与 `e2e` 作业**不加**——它们真的需要内存 Mongo 的 mongod 二进制，跳过安装脚本会把「安装期一次性下载」挪进 jest worker / 脚本进程，而本仓已有 `mongodb-memory-server` 子进程句柄与 jest 退出竞态的实证记录（`ci.yml` 的 `--forceExit` 头注）。判据：跳脚本不会让 `npm ci` 失败（`postinstallHelper.js` 失败路径是 `process.exit(0)`），代价是时序面，不是安装成败- **`checkBruteForce` 的通知频控挡在审计与封禁之前（与 CC 那条线同源，是同一轮修法的漏网）**。`securityAlert.js` 里两行 `shouldSendAlert`（账户维度 + IP 维度）排在阶梯统计 / 审计落库 / `addToBlacklist` **之前**，任一命中即 `return`，把三件事一起关在门外。后果不是少一条通知：① 封禁**失败**（白名单命中 / 黑名单写库故障）时 5 分钟内的重试被这行吞掉——而"封禁没生效"恰恰最需要重试；② 审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 次」。修法与 `rateLimitEscalationBan.js` 同一条纪律：**统计 / 审计 / 封禁无条件执行，频控只约束 `dispatchNotification`**。两个去重键保持内联（键里同时含 username 与归一化 IP）且短路语义逐字保留（`||`——任一维度放行即投递，改 `|` 会多消费一个 key 使抑制变强）。**实测变异验证**：把闸移回原位后 2 条用例红
- **`checkPermissionAbuse` 只告警、不封任何东西（唯一一处"跨层探测已认证权限边界"的哨兵没有遏制手段）**（新增 `src/services/securityAlertPermissionAbuse.js`）。该检测器此前整条路径只有「审计 + 通知」，另两个检测器都有封禁动作。缺口是：攻击者只要拿到一份**有效凭据**，把权限探测压到每 5 分钟 < 20 次，就能永久试探权限边界——每次都不达阈值 ⇒ 无告警、无审计、无遏制（20 次/5 分钟这条阈值只挡"不会隐藏自己的人"）。现达阈值时对**来源 IP** 走与暴力破解同一条渐进式封禁阶梯（1h→4h→24h→7d），事件源是独立的 `action=permission_abuse`（与 `brute_force_login` 分账，各数各的，只共用时长档位与 30 天窗口，新增 `IPBanEvents.countPermissionAbusePrior`）；无 IP 上下文时只告警不封（不得把 `undefined` 当 IP 封）。同样的处置/通知解耦、同样的"先读阶梯后写审计"、同样的按返回值分派（F-160 口径：`addToBlacklist` 从不抛错，白名单/写库失败时"已封禁"日志就是纸面防线撒谎）。处置侧整块抽到新文件是体积债收口（`securityAlert.js` 净代码行已贴 300 上限）。**实测变异验证**：跳过封禁后 3 条用例红
- **出站告警契约闸的两处能力缺口**（`src/tests/services/outboundAlertContract.test.js` / `fireAndForgetAlertSingleEntry.test.js`）：① 判据只认**裸** `ALERT_TYPES.X`，不认带模块前缀的 `securityAlert.ALERT_TYPES.X`——而后者语义完全等价且跨模块调用时必须用；`auditChainMonitor.js` 的调用点原是三表达式，拆成 if/else 后双闸齐红。现解析器接受可选前缀（键的真实性仍逐条校验）。② `sendNotification` 白名单未登记 `auditChainMonitor.js`（它是第二个 `await` 侧调用点，要拿投递结果做自己的记账），按该闸的设计意图显式登记。**注**：这两处是上一轮审计链守护闭环引入的欠账，非本轮新增缺陷
- **`backgroundJobs.test.js` 的频控断言钉的是被修掉的旧行为**：原断言「5 分钟频控窗口内第二次检测不再写审计」，正是上面第一条缺陷的形状。已改为「通知不重复，但**审计必须照写**」（`after === before + 1`）；另把 `securityAlertWriteFailureTolerance.test.js` 的"写入成功不打 error"反向对照显式桩掉封禁链路——该用例的命题是"审计写入成功"，不该被"这个 IP 恰好能不能被封"污染
- 门禁：新增 `src/tests/services/securityAlertContainmentDecoupling.test.js`（7 例：频控命中时审计/封禁照做、封禁失败后重试不被吞且阶梯升档、权限滥用必须真的封 IP、权限滥用阶梯独立分账、无 IP 不封、两条 `shouldSendAlert` 位置文本闸）

- **`auditChainMonitor.runVerification` 的函数体积债（101/100，上一轮的欠账）**：该文件是未跟踪新文件，不在棘轮基线里，于是它的 `max-lines-per-function` 超标要到下一次全量跑才暴露。把「告警投递」整块（`noticeData` 组装 + 按 `hasBreaks` 的 if/else 静态分派）抽成 `dispatchChainAlert`——拆函数正是本仓对体积债的既定处置。顺带把「档位/类型不得写成三元表达式」这条约束的注释挪进新函数，让它有独立的注释位而不容易被后来的重构顺手"简化"掉。行为逐字不变（`outboundAlertContract` / `fireAndForgetAlertSingleEntry` / `auditChainGuardedIntegrity` 三套件 31 例全绿）
- **补上一轮遗漏的 prettier 格式**（`auditChainMonitor.js` / `securityAlert.js` / `auditBufferFlushAndWalGuards.test.js` / `securityAlertContainmentDecoupling.test.js` 四文件）。`npm run format:check` 自那轮起就是红的

- **`web-admin/src/tests/build/` 被 `.gitignore` 的 `build/` 规则吞掉，一份正牌回归测试从未进过 CI**。该目录下是 `manualChunks.test.js`（P2-52 回归，4 例，直接 `import` 真实 `vite.config.js` 调 `manualChunks`，注释里记着实测更正与反证记录）。`.gitignore:46` 的 `build/` 是为构建产物加的，而它**无前导斜杠 ⇒ 匹配任意层级的 `build` 目录**，于是测试目录被一起吃掉。后果是它在本地跑、在 CI 上根本不存在（本地前端 1431 例含它，CI 从未执行）。已把目录改名为 `web-admin/src/tests/bundling/`（不改 `.gitignore`：`build/` 规则本身有其必要，不该为一个测试目录放宽）
- **门禁：测试树纯净性**（新增 `src/tests/ci/testTreePurity.test.js` 5 例）。`testMatch` 是「任意层级下的 `src/tests/` 里的 `*.test.js`」，因此放在那里的**任何** `.test.js` 都会被执行——包括从未提交、只是调试时落下的草稿。这类失效形态是"不出错、只污染信号"：草稿的 pass/fail 混进总数，而**本该入库**的用例一旦漏 `git add` 则是本地全绿、CI 上压根不存在。两条方向相反的判据：未跟踪 ⇒ 报红（给出"入库或挪出"两条出路）；已跟踪的 `zzz-*.test.js` ⇒ 报红（`.gitignore` 只约束未入库，管不住 `git add .`，而当初那批 8 个探针 / 591 行 / 51 test / 0 expect 正是这么进去的）。判据用 `!tracked.has(f)` 而非 `ls-files --others --exclude-standard`：**被 gitignore 误伤的文件正是本条门禁上线当天抓到的第一个案例**，用 `--exclude-standard` 它会隐身
- **补上 `d72872c` 漏同步的两处断言**（`auditQuerySharedBuilder.test.js` / `auditQueryFindAggregateParity.test.js`）：该提交把 username 前缀查询的上界从「末字符码点 +1」改为追加 collation 哨兵 `U+FFFF`（ICU 排序下前者对 `z`/`Z`/`9` 等末字符构成**空区间**），并同步了 `auditUsernamePrefixIndex.test.js` 的契约，却漏掉了另两处同样断言该 helper 输出形状的用例 ⇒ HEAD 上稳定 2 红。断言已改为钉哨兵形状；哨兵在 collation 下确实恒大于任何 `prefix + <已分配字符>` 仍由 `auditUsernamePrefixIndex.test.js` 的 DB 回归用例负责，不在此处重复造一个纸面断言

- **`req.query` 物化：Express 5 下 query 注入防线此前靠注释撑着**（新增 `middleware/security.js` 的 `materializeQuery`）。`req.query` 是原型上的 getter（`express/lib/request.js: defineGetter(req, 'query', ...)`），每次访问重新解析 URL，于是 `sanitizeMongo` 与 `hpp` 对 query 的原地清洗是**彻底空操作**——实测（Express 5.2.1 + supertest）`delete req.query.search` 之后**同一 handler 同一 tick** 内回读 `Object.keys(req.query)` 仍带 `search`，比 P1-33 记录的"下次访问才丢"更彻底。现改为读一次 → 复用 `deepSanitizeKeys` 清洗 → `Object.defineProperty` 物化成自有数据属性 → **回读自证身份，不等即拒绝请求并 error 级留痕**（物化失效是零报错事件，"服务不可用"远好过带着未清洗的 query 继续服务）。附带收益：解析次数从"每个消费者一次"降到全请求一次。`sanitizeMongo` 已移除对 `req.query` 的遍历——留着只会让人误以为 query 有两道防线
- **静态面限流判据单一来源 + 补上零预算**（`middleware/staticFrontend.js` / `rateLimit.js`）。此前限流侧判据是"安全方法 + 非 `/api/` 前缀"，与 `staticFrontend` 的 `RESERVED_PREFIXES` 是两份独立清单，实测对 11 条非 `/api` 路径有 **8 条判定相反**。逐条核对后真正裸奔的两条：`/socket.io/`（Socket.IO HTTP long-polling 握手是未认证 GET，而 `MAX_CONNECTIONS=1000` 约束的是**已建立连接数**、`authenticateSocket` 在连接建立之后才跑 ⇒ 握手面应用层零限流）与 `/metrics`（`metricsAuth` 允许内网免令牌，而 `app.js` 自陈的威胁模型正是"容器网络内直连 app:3000"）。判据现由 `isStaticSurfaceRequest` 单一来源提供，豁免集合**收窄**（新登记的保留前缀自动重新纳入限流，限流侧无需改动）。另新增 `staticSurfaceLimiter`：静态面此前被整体豁免，而豁免的代价是**零预算**（单 IP 可无限拉 `/assets/*`）；现按"按成本分桶"给它自己的宽松桶（12000 次/15 分钟，按 34 静态请求/页 × 30 人 NAT × 10 次页面加载 = 10200 留 18% 余量推导），429 文案与通用限流刻意区分，且**不接入 CC 封禁升级阶梯**（静态面被限流多为出口聚合，接上去会把误封从单个 IP 放大到整个办公室）
- **门禁：把"注释级约定"变成可执行不变量**（新增 `src/tests/app/queryDefenseSingleSource.test.js` 11 例、`staticSurfaceRateLimitGate.test.js` 17 例）。前者刻意跑在**真实 express 实例 + supertest** 上并含一条**反向对照**（未物化时 `req.query` 确实不是自有属性、确实跨读取不稳定）——因为既有那组 `sanitizeMongo` 单测用的是手搓 `req` 桩，桩上的 `query` 是普通属性，**结构上不可能**发现 Express 5 的 getter 前提；本次同时把该单测里断言 `query: 10` 的那条改成如实反映"query 不再经过 sanitizeMongo"。后者钉住判据单一来源、8 条分歧路径逐条归属、大小写同尺、以及静态面不再是零预算
- ~~**CC 升级封禁阈值 100 → 30，并新增预警档**~~ —— **本条已被上方「变更」段的分类分桶方案取代，保留在此仅说明演进过程**：单一阀值（无论 100 还是 30）的问题不在数值，而在它把 7 个合法拒绝率相差两个数量级的限流器加进了同一个桶；`CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 两个变量均已移除，改为按类别的 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH`。原判断里成立的部分（`generalLimiter` 触顶后窗口内每条请求都是 429、真攻击 5 分钟可刷出数千次）已被吸收进 `ANON_ABUSE` 的推导

- **`package.json` 的 `engines.node` 与前端实际要求对齐**：`>=18` 与 `web-admin` 的 Vite 8.1.4（`engines.node: ^20.19.0 || >=22.12.0`）冲突——声明允许的 Node 18 上 `npm ci` 能装完依赖，但 `npm run build` 结构性失败。改为 `^20.19.0 || >=22.12.0`，与 CI 的 `[20.x, 22.x]` 矩阵、前端 job 的 `24.x`、Dockerfile 的 `node:22.14.0-alpine` 落在同一条区间上
- **`.dockerignore` 补齐被漏掉的构建上下文**：Docker 的忽略模式只从上下文根起算，bare `coverage` **不匹配** `web-admin/coverage`（与本文件必须写全 `web-admin/node_modules` / `web-admin/dist` 是同一条语义），而 `web-builder` 阶段是 `COPY web-admin/ ./` ⇒ 3.2 MB 前端覆盖率报告与 4 个 `coverage-zz*` 残留目录一直进构建上下文与镜像层。同时补 `web-admin/.mimosa`、`.mimosa`、`.jesttmp`（本机 82 MB）、`playwright-report`（9.5 MB）、`test-results`、`.lint-ratchet-selftest-*`、`zztmpctl`/`zznpmtest`（含自带 `node_modules` ~93 MB）与 `.admin-initial-password`（当前超管明文口令，59 字节）。后几项目前因 Dockerfile 走 `COPY` 白名单路径而未泄漏，但任何将来新增的宽泛 `COPY .` 都会一次性引爆

### 新增（2026-09-28）

- **IP 归属地展示（离线零依赖）**：会话管理、审计日志列表、IP 黑白名单等后台界面把裸 IP 翻译为「国家·省·市·运营商」。数据采用 ip2region 官方 xdb（Apache-2.0）入库 `src/data/`（约 11MB，Docker `COPY src/` 一并带入镜像），检索器 `src/utils/ip2regionSearcher.js` 以纯 Node 实现 xdb v2 格式（向量索引 + 二分，全内存约微秒级/次），不引入任何 npm 依赖；`src/services/ipLocationService.js` 负责业务口径（复用 `ipUtils.normalizeIP` 收敛 `::ffff:` 形态、内网/保留地址统一标「内网」含 IPv6 回环/链路本地/ULA、结果 FIFO 缓存 2048 条、任何异常 fail-soft 返回 null）。`GET /api/auth/sessions` 每条会话新增 `location`（最近活跃 IP）与 `loginLocation`（登录 IP）；审计日志两条分页路径与 IP 名单列表逐行补 `location`；前端在 IP 旁以 `·` 拼接展示（后端缺字段/CIDR 网段自动省略）。数据刷新：`node scripts/update-ip2region.js`（Gitee→GitHub→jsDelivr→npm 镜像四级数据源 + 结构校验 + 探针查询 + 原子替换），`--check` 只打印当前数据构建日期
- **CC 防护升级闭环**（`src/services/rateLimitEscalation.js`）：限流从「只挡不罚」变为「可观测 + 可升级」——每次 429 上报 `security_alerts_total{type=rate_limit_triggered}`；同一 IP 在 5 分钟窗口内触顶达阈值（`CC_ESCALATION_THRESHOLD` / `CC_ESCALATION_WINDOW_MS` 可调，**2026-09-30 起已重构为按类别分桶（见上方「变更」段：单一阀值与预警档均已移除）**）即按与暴力破解同一条封禁阶梯（1h→4h→24h→7d，30 天审计事件计数升档）自动封禁。防误封设计：白名单 IP 的资源型限流直接 skip 不会产生升级信号；凭据型账号维度桶不接入（无 IP 可封）；升级链路全程 fail-soft 不拖垮 429 响应。计数为进程内固定窗口（多实例下按实例数摊薄，少封不误封）
- 数据文件入库配套：`check-utf8` 门禁的常见二进制扩展名清单加入 `.xdb`，`.gitattributes` 钉 `*.xdb binary`

### 变更（2026-09-28）

- **限流键统一 IP 归一化**（总账 §4.4「限流键直接拼原文 req.ip」收口）：全部 IP 维度限流器（general/strict/login/ip/user 未认证分支/captcha/register/pwd-change/reauth 及 wellKnown 三个上报限流器）的键改走 `normalizeRateLimitIp`（与名单侧同一把 `ipUtils.normalizeIP`），消除 `::ffff:1.2.3.4` 与 `1.2.3.4` 双桶导致的「同一来源配额翻倍」；歧义写法回退原文自成桶，fail-closed 语义不变。`ipLimiter` 补显式 handler（响应体与原 message 逐字一致，差异仅多升级信号上报）
- **暴力破解自动封禁判据只看 IP 维度**（总账 R-H2）：`checkBruteForce` 此前以 `max(userFailures, ipFailures)` 达标即封禁**当前请求 IP**——分布式撞单账号时把可能只贡献了 1 次失败的 IP（NAT 出口后的无辜用户/受害者本人）封 1 小时。现改为告警与审计照发（双维度都是真实攻击信号，审计 body 含双维度计数），封禁仅在 `ipFailures` 达阈值时执行
- **wellKnownRoutes 三个限流器接入共享存储**（总账 P-9）：`/csp-report`、`/client-errors`、`/.well-known/security.txt` 的限流计数从每实例独立 MemoryStore 改为 `makeSharedStore`（无 Redis 时行为不变），多副本部署下攻击者不再能对每个副本各刷满一份配额

### 测试基线

- 后端：477 个套件 / 4583 个用例文件（2026-09-30 按文件数与 `test()/it()` 声明数实测；此前记的「130 套件 / 1736 例」与 `jest.config.js` 注释里的「280 套 / 3300+ 例」均已失真一个台阶）
- 覆盖率阈值：全局 br 79 / fn 87 / ln 91 / st 91，另 36 个安全关键文件单独设阈；**不复写实时覆盖率数值**——要当前数字看 `npm run test:coverage` 的输出，写死即立刻失真

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
  \t\n'`不是 POSIX（busybox/老 dash 会把它当字面量、
od 腿失明 ⇒ fail-open），三处改成`IFS=$(printf ' \t\n_'); IFS=${IFS%_}`（逐字节等值 20 09 0a）；
`capture` 也补了同款固定腿——`bash script.sh`会 source`$BASH_ENV`，上一轮「新进程重置 IFS」的
论断被证伪（审计实测 rc=0、177→314 B、CR=0 静默改写），该腿用文本契约钉住（行为级证据在
`backupUriFile.test.js`）；两处 `[[:space:]]`判据补`LC_ALL=C`（NBSP 在不同 locale 下命中不同）。
第五轮复攻修 `capture`的 od 解析器（手写 while 把行尾 token 连换行切走 ⇒ 16 字节边界的 CR 漏计 ⇒
共谋`tr` 下 CRLF 被静默改写）；第六轮复攻又暴露同一族的环境依赖：`mongoUri.sh`被`source` 时
word splitting 用调用方 IFS，`IFS=' '`+ 两向共谋`tr`⇒ 含 NUL 的密钥文件被接受。两处 od 循环改成
局部`_ifs_saved=$IFS; IFS=（每条腿的失败方向都与「拒绝」一致）：**互补绝对计数**
  （允许字节数 + 禁止字节数 == 总字节数；`tr` 不过滤 ⇒ 两边都等于总数 ⇒ 判「检测不可用」）、
  **直接数违禁字节**（换行 / NUL / CR 必须为 0 —— 内容相关退化在这条上藏不住）、**`od`逐字节
  目视**（不经`tr`/`wc` 的独立字节通道：token 数必须等于总字节数、`0d` 等违禁 token 逐项判定）：

- `scripts/mongoUri.sh::mongo_validate_uri`：`${#_uri}`（shell 内建）交叉 + 互补计数闭合 +
  直接数违禁字节 + `od` token 区间目视（`for … in $var` 解析）。
- `scripts/mongoUri.sh::mongo_hydrate_uri`：`stat -c %s` 与 `wc` 独立交叉、`[ -s ]` 自相矛盾守卫、
  `_n`（行数）形状校验、互补计数闭合 + NUL 直数 + `od` 目视。
- `scripts/capture-image-digests.sh`：同上三腿 + 直接数 CR 字节；`od` 解析用 `for … in $var`
  （第五轮实测：手写 while 对行尾 token 漏计 ⇒ 16 字节边界的 CR 看不见 ⇒ 共谋 `tr` 下 CRLF 被
  静默改写 rc=0；修复后同一夹具「有 7 个 CR」拒绝落笔）。为什么不用 `grep`（第一版就是它）：
  MSYS/Git Bash 的 grep 走文本模式，CRLF 被当成行尾、CR 在匹配前就被吃掉——实测 `LC_ALL=C grep -q
-e "$(printf '\r')"` 对 CRLF 文件返回 1（＝「没有 CR」），那样的所谓独立腿在 Windows 上恒绿。
  `tr`/`wc`/`od` 是字节流、不认行尾，两个平台同一语义。
- `scripts/backup-mongo.sh`：归档字节数先过「非空 + 纯数字」形状校验，再比 `-le 0`。

用例（红→绿→红→绿，逐条变异取证，全部落在上表各条腿上）：`src/tests/deploy/backupUriFile.test.js`
45 条、`src/tests/imageDigestGate.test.js` 62 条（含第五轮新增 3 条：同源共谋 `tr` + CR 全部落在
16 字节边界 ⇒ 必须拒；`od` 桩只吐 3 个 token ⇒ 判「目视不可用」；`od` 对内容说谎 ⇒ 兜底腿仍拒）、
`src/tests/backupScriptGuards.test.js` 11 条。关键变异：摘互补和式 ⇒ 红；摘 NUL 拒绝臂需与 `od`
NUL 臂双摘才红（两臂冗余是设计，单摘时另一臂仍拦）；摘 `capture` 的 `od_cr` 腿 / 直接计数腿 /
token 数腿 ⇒ 各自用例以 rc=0 的 fail-open 复现变红；还原后所有文件 sha256 与改前一致。

> 顺带修正 `src/tests/deploy/backupUriFile.test.js` 的「前提自证：删掉 NUL 闸」用例：它按「第一个 `fi`」
> 定位删除区间，而本轮在它前面插了新腿，冷启动会**删掉半截**、留下悬空的 `_file_nonnull` 引用 ——
> 那正是这条用例自己要防的静默错删。现在按两条 NUL 臂（直接计数 + `od`）各自的 `if` 行成对定位，
> 找不到就抛（判据变了 ⇒ 同步用例），不许静默跳过。

### 修复：权限软删除的「只读墓碑」被写路径绕过（D5，2026-10-30）

> 来源：`work/audit-round3-config-mw.md` 的 D5。

`src/models/Permission.js` 的软删除过滤原本只挂 `/^find/` 与 `countDocuments`，
而模型自己的承诺是「文档永不离开集合、保留期后可复核」——`updateOne`/`updateMany` 一条就能
**就地改掉已删除的行**，`distinct`/`aggregate` 则会把已删除的 code 重新吐出来（审计实测：
`updateOne({_id}, {$set:{name}})` 对已删除文档返回 `modifiedCount: 1`）。

现在把覆盖面扩到 `updateOne`/`updateMany`/`replaceOne`、`distinct`、`estimatedDocumentCount`
与 `aggregate`（管道首部注入 `$match`），并保留两个**显式**放行口子：过滤条件自己写了 `deletedAt`，
或更新文档本身在动 `deletedAt`（软删除/恢复这类状态变更——`permissionService` 的恢复补偿
`updateOne({_id}, {$set:{deletedAt:null}})` 正是这种形态，不能把它吃掉）。
`deleteOne`/`deleteMany` **有意不加**：非测试代码里零调用方，而测试清理与运维删除需要硬删；
把它留给「谁真要在生产硬删已删除的权限」时显式决定（本轮不替未来做决定）。

用例（`src/tests/services/permissionSoftDelete.test.js` 三条）：写路径不命中（活跃行对照命中）、
两条放行口子仍有效、`distinct`/`aggregate` 不泄露。实测变异（撤掉写过滤 + 撤掉 distinct/aggregate 注入）
⇒ 正好两条新用例红（`Expected: 0 / Received: 1`）；还原 ⇒ 10/10 绿。

### 加固：三处「缺 shell 就整组静默跳过」的门禁补上 CI 守卫（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S2 —— 与 `imageDigestGate.test.js:80-89` 的既定先例不一致。

`backupScriptGuards`、`ciProvisionFailurePropagation`、`appEntrypointQueuePermFallback` 三份行为闸都写着
`const group = BASH ? describe : describe.skip`：本机（Windows/MSYS）探不到 POSIX shell 时**整组跳过**。
在本机这是合理的降级，但在 **CI（ubuntu）上探不到 shell 就是探测本身坏了** —— 此时整组零断言的绿
与「这些不变量根本没被验证」是同一件事，而且没人会去数 skipped 的条数。

现在三份文件都补上 `if (!BASH && process.env.CI)` 的守卫：CI 上解析不到 shell ⇒ 直接红（口径同 imageDigestGate 的先例）。
实测（临时让候选表返回空 + `CI=1`）：三份守卫同时红并给出「本文件全部覆盖都是假的」的原因；
恢复候选表后 `CI=1` 下 3 suites / 21 tests 全绿。

### 加固：仓库 shell 脚本的语法闸 + 两处 spawnSync 超时兜底（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S3/S4（疑似）。

- **新增 `src/tests/ci/shellScriptSyntax.test.js`（S4）**：每份**已入库**的 `*.sh` 都要用它
  **shebang 指定的解释器**过一遍 `-n`（`#!/bin/sh` 用 `sh -n`、`#!/usr/bin/env bash` 用 `bash -n`），
  并单独钉住 `docker/app-entrypoint.sh` 必须按 **sh（dash 语义）** 检查，不许被 bash 顶替。
  此前仓库只有 workflow 的 `run:` 块有 `bash -n` 闸，脚本本体一个语法判据都没有 ——
  而 `docker/app-entrypoint.sh` 一旦语法错误，后果是**容器起不来**，要等下一次部署才发现。
  反向自证用**同一个** `checkScript()`：造一份少 `fi` 的脚本必须报红、同目录合法的必须绿、
  没有 shebang 的必须判否（不许静默跳过）。实测把 entrypoint 的收尾 `fi` 去掉 ⇒ 闸红并给出 dash 的报错行号；还原 ⇒ 绿。
- **两处 `spawnSync` 补 `timeout: 30000`（S3）**：`appEntrypointQueuePermFallback` 与
  `ciProvisionFailurePropagation` 的夹具子 shell 卡住时，应当红在断言上（超时 ⇒ `status=null`），
  而不是把整条流水线拖到 CI 超时。

### 修复：「工具在不在」的自证 ≠ 「这一次判据能不能执行」（2026-10-30）

> 来源：`work/audit-round3-toolfailopen.md`（第三轮审计对上一轮修复的**再攻击**）。
> 上一轮给两处字节判据装了「工具缺失 ⇒ 拒绝」的探针，本轮被证明**探针与判据不是同一个调用形态**：
> 探针证明「本机有 tr」，判据需要的是「这一次 tr 真的跑起来了」。两者之间的失败面无人观测。

三个实测反例（第三轮审计给出端到端复现，本轮已逐条用用例钉住）：

1. `scripts/mongoUri.sh` 的「单行纯可打印 ASCII」：探针跑 `tr -d 'a'`（单字符集合），
   判据跑 `tr -d '\041-\176'`（八进制区间集合）。只让后者失败 ⇒ `$(…; printf '~')` 恰好等于 `~` ⇒
   **带换行的连接串 rc=0**，换行会成为 mongodump/mongorestore 配置的第二行。
2. `scripts/mongoUri.sh` 的 NUL 判据：正常值就是 0，与「tr 死了、wc 读空 stdin 打印 0」不可分 ⇒
   UTF-16LE 密钥文件 rc=0（目标库名被改坏）。只有「管道首尾同时死」才偶然拒绝。
3. `scripts/capture-image-digests.sh` 的 CR 判据：探针走**管道输入**，判据走**文件重定向输入** ⇒
   后者失败被读成「没有 CR」⇒ 把 CRLF 的 Dockerfile 重写成 LF 并钉版，**exit 0**。

**改法（两处同一条通则）**：不用探针兜，直接让判据**自己会失败**——改成两个**字节计数相比**，
并先做「非空 + 纯数字」形状校验：

- mongoUri：可打印字节数 == 总字节数（`wc -c` 拿总数；`tr -cd '\041-\176'` 拿可打印数）；
  NUL 判据同理，比的是「非 NUL 字节数 == 总字节数」——**用非 NUL 而不是 NUL 计数**，
  因为后者的正常值就是 0，与工具的失败输出不可分。
- capture-image-digests：非 CR 字节数 == 总字节数。

于是**工具的失败方向与判据的拒绝方向一致**：tr 任何形态失败 ⇒ 计数变成 0（或形状非法）⇒ 与总数不等 ⇒
拒绝。空值两边都是 0，由后序判据（scheme / 空文件）给出准确原因。

**证据**：`backupUriFile.test.js` 34/34、`imageDigestGate.test.js` 56/56、
`backupScriptGuards.test.js` + `backupFailureArtifactHygiene.test.js` 29/29；
新增 5 条用例在**回退脚本**后恰好全红（探针形态失败 / NUL 形态失败 / 文件重定向形态失败 / 两种「无 tr」形态），
改回后全绿。桩是否真的生效由用例自己观测（打印 `tr=` 的解析结果，并要求落在桩目录里）。

### 修复：跨平台夹具 `exec` 的两种失效形态（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的「疑似（高）」。`src/tests/helpers/stubPath.js` 把「PATH 桩目录」
> 收口到孩子 shell 内部（MSYS 启动时会前置 `/mingw64/bin:/usr/bin`，从 Node 侧改 `env.PATH` 无效），
> 但它的 `exec` 形态选错了两次，两次都不会让套件「变红得有意义」。

- **`exec "$@"`（直接 exec 脚本文件）依赖可执行位**：本仓 `scripts/*.sh` 在 git 里全是 `100644`。
  MSYS 下照样能跑（shell 自己读文件），Linux 上 `execve` 直接 `EACCES`，非交互 shell 随即退出 ⇒
  两个备份套件会在 CI 上整片**假红**。
- **改成 `exec "$0"` 会静默毁掉夹具**：Windows 上 `$0` 是 `…/Git/bin/bash.exe`，重起一个 Windows 进程
  让 MSYS 再走一遍启动注入，`/mingw64/bin:/usr/bin` 被塞回 PATH 最前 ⇒ 桩目录失效。实测 PATH 首项变成
  `/mingw64/bin`、`date` 命中 `/usr/bin/date`，用例报出真日期（`fire-safety-backup-20261030-205053.gz`）。
  这比假红更坏：套件是红的，但红在夹具，而夹具失效本身不报警。
- **最终写法 `exec bash "$@"`**：按 PATH 解析到 MSYS 本体，不重走启动注入、走解释器与可执行位无关，
  两个平台语义一致。实测改后 `backupScriptGuards`（10 例）+ `backupFailureArtifactHygiene`（19 例）全绿，
  含那条「同名归档存在时拒绝覆盖」的确定性时间戳用例。

### 加固：第二轮逐行审计的「闸没有判别力」收口（2026-10-30）

> 来源：`work/audit-round2-infra.md`（132 行，逐条 file:line + 真跑复现）。这些缺陷的共同形状不是
> 「代码写错」，而是**闸自己不会红**：注释里声明的不变量，没有任何一条判据能单独钉住它。

- **逐条 `&&` 无人守**：`appEntrypointQueuePermFallback.test.js` 的夹具只有「整类命令全失败」一档，
  于是 `docker/app-entrypoint.sh:135` 的 `&&` 删掉后 4/4 仍绿（链上第一条就断，中间失败跑不到）。
  夹具改为「第 N 次调用失败，N=1..8」逐条注入，并加一条反向对照：把 `&&` 换成分号的**历史形态**
  喂进同一夹具，第 2 条失败必须被静默吞掉（证明本闸抓得住它）。
- **正则判别力为零**：`hotUpgradeQueueContract.test.js:135` 的 `/…(?: &&)?$/m` 对「有/没有 `&&`」都真。
  改成必需的 ` &&# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

，并补一条前提自证：整块 8 条命令之间必须恰好 7 个 `&&`。

- **`test -n "$MONGOD"` 无判据**：`.github/workflows/ci.yml:137/:508` 的这行删掉后整族仍绿，
  而「provision 退出 0 但什么都没打印」正是该步骤自述的头号危害（空值让 MongoBinary 回落到
  未经仓库 SHA-256 锚的下载）。补「exit 0 + 空输出 ⇒ 步骤必须红且不写空值」用例，
  并从**抽取到的真实步骤体**删掉那一行做前世版自证（不抄副本）。
- **「失败即放行」语义未钉**：`app-entrypoint.sh:148` 的 `return 0` 换成 `exit 1`（容器起不来）闸仍绿。
  逐条注入的用例现在同时断言 `rc=0`：失败必须告警放行，而不是把容器弄得起不来。
- **探针假阳性**：`helpers/posixShell.js` 的可用性判据用 `includes`，而 MSYS 的 `echo.exe` 会把参数
  原样回显（标记于是「包含」在 stdout 里）⇒ 一个根本不是 shell 的可执行文件被判为可用。
  改成**严格相等**（标记必须独占 stdout），并补一条用「只回显 argv」的可执行文件做的反向对照。
- 实测（Windows / Git Bash，非 Linux 权威）：入口脚本变异 `&&` → `; true &&`（`&&` 计数不变、语义已断）
  ⇒ 用例红在「第 1 条失败却被吞」；还原 ⇒ 绿。`hotUpgradeQueueContract` 删掉一个 `&&` ⇒ 红；还原 ⇒ 绿。
  `posixShell` 探针退回 `includes` ⇒ 新用例红；还原 ⇒ 7/7 绿。

### 修复：两处「工具缺失即静默放行」的字节级判据改为失败关（2026-10-30）

> 来源：第一轮逐行审计的 A6（运维脚本族的 fail-open）。两处的形状相同：判据由外部工具执行，
> 而工具失败时命令替换得到的是**空串**，与「值/文件本来就干净」不可分。

- `scripts/mongoUri.sh` 的 `mongo_validate_uri`：「单行纯可打印 ASCII」判据由 `tr` 执行。实测（PATH 里没有 `tr`）
  带真换行的连接串照样 rc=0 —— 那个换行会被写成 `mongodump`/`mongorestore` 配置文件（0600）的第二行，
  正是这条判据存在的理由（同文件顶部 2026-10-03 的取证）。现在先让字节通道**自证**：`'ab'` 删掉 `'a'` 必须恰好
  剩下 `'b'`；量不到就拒绝放行（fail-closed）。
- `scripts/capture-image-digests.sh` 的 CR 检测（`tr -dc '\r' | wc -c`）同理：`wc` 照旧输出 `0`，与「文件里没有 CR」
  不可分 ⇒ 检测被整体跳过，MSYS 的 `sed`/`gawk` 顺手吃掉 CR，脚本会把 CRLF 静默改写成 LF 并报成功。
  现在先用一个已知含 CR 的输入证明通道是活的，量不到即拒绝落笔（与同脚本 :47 的 `docker` 存在性检查同一口径）。
- 用例：`src/tests/deploy/backupUriFile.test.js` 新增 3 条（含「tr 在位」的前提自证与「无法校验即拒绝」），
  `src/tests/imageDigestGate.test.js` 新增 1 条（含「同一夹具在真 tr 下必须成功」的反向前提）。
  两处守卫都以「临时摘掉判据 ⇒ 用例必须红」证伪过（实测 2 红 / 1 红），再还原为绿。
- 同批：`src/tests/middleware/avatarUnmatchedSurfaceGuard.test.js` 的固定 30ms 睡眠换成条件等待
  （`helpers/waitFor` / `waitForStable`），修掉 `noFixedSleepRatchet` 的回退。

### 新增：临时权限授予与定期复核（C-08 / C-09）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 C-08 / C-09 控制项实现；决策与取舍见 `docs/adr/ADR-012-临时权限授予与定期复核.md`。

- **端点**：`GET /api/permissions/grants`（列表，按 status/userId 过滤）、`GET /api/permissions/grants/review`（复核汇总 + 超期清单）、`POST /api/permissions/grants`（申请）、`POST /api/permissions/grants/:id/{approve,reject,revoke}`。权限码 `privilege:read` / `privilege:grant` / `privilege:approve` 已进目录与菜单。
- **不变量**：到期在**读取路径**判定（`status==='active' && expiresAt > now`），后台 `expireDue` 只收敛状态；申请人不得自审；高敏模块（user/role/permission/security/system/privilege）的码需 2 名不同审批人；审批人必须自持被授予的每个码；每次状态变更都失效目标用户权限缓存（钩子缺失时抛错，fail-closed）。
- **数据**：新集合 `PrivilegeGrant`（`models/PrivilegeGrant.js`），审批链以 `{by,name,at}` 快照落库，终态记录不删除（审计可回看）；索引 `{userId,status,expiresAt}` 与 `{status,expiresAt,createdAt}`。
- **审计**：新增 action `permission_grants`、`permission_grants_review`、`permission_grants_approve`、`permission_grants_reject`、`permission_grants_revoke`（category 仍为 `permission`，见 ADR-012「为什么不新开 privilege 分类」）；派生动作由 `/api/permissions/grants` 前缀自然得出，无手工登记路径。
- **运维**：`scripts/access-review.js`（默认输出 JSON 汇总；`--expire` 收敛过期状态；`--fail-on-overdue` 退出码 1 可挂 CI）+ `deployment/systemd/fsms-access-review.{service,timer}` 每小时巡检。
- **用例**：`src/tests/services/privilegeGrantFlow.test.js`（21 例规则：到期失效、双人复核、自审/无码阻断、并发签批、驳回与撤销的状态机单向、复核登记、服务层入参兜底、被授权账户不可用、权限判定与缓存失效两处钩子缺失时 fail-closed）、`src/tests/routes/privilegeGrantEndpoints.test.js`（7 例：鉴权、校验链、全链路、双人复核、自审阻断、驳回端点、审计派生 action 入缓冲）。

- **覆盖率门槛**：`services/privilegeGrantService.js`、`services/accessReviewService.js`、`controllers/privilegeController.js`、`constants/privilegeGrant.js` 在 `jest.config.js` 单独设阈值（取「实测 −5pt(分支) / −3pt(函数)」，向下取整），不并入 global 均值——这几个模块退化时的表现是安全结论错误，不是报错。同批拆出的 `services/privilegeGrantHooks.js`（两个外部钩子，未注册即抛）与 `services/privilegeGrantValidation.js`（`grantError` 与有效期/权限码归一的单一出口）也各带阈值，拆分的动因是 `max-lines` 棘轮（服务本体已越过 300 行），语义与导出面逐字不变。
- **Web 端入口**：`web-admin/src/views/PrivilegeGrantView.vue`（菜单 `/system/privilege-grants`，路由 `meta.permission = privilege:read`）——状态筛选（默认「待审批」）、复核汇总五计数、申请表单（权限码逗号/空格混排解析、有效期 1-168 小时本地校验）、签批/驳回/撤销三条决定链路；按钮按 `privilege:grant|approve` 门控（与后端 `checkPermission` 同码），高敏提交提示显式给出「还需几人签批」。用例 `web-admin/src/tests/views/privilegeGrantView.test.js`（34 例，分支覆盖率 90/90）。
- **未落地（如实申报）**：堡垒机/跳板机与 JIT 会话录屏（C-09 的另一半）尚未实现——「谁能拿到高敏码」已可控可追会过期，但「拿到之后在什么通道上操作」仍由操作系统与运维流程保证。

### 新增：部署面配置漂移检测（M-05）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 M-05 控制项实现。

- **脚本**：`scripts/config-drift-check.js`，把 compose 的容器安全标志（`read_only`/`cap_drop`/`security_opt`/`user`/`tmpfs`/`networks`/内存上限…）、Dockerfile 的 `USER` 与 `HEALTHCHECK`、nginx 模板的 TLS 与安全响应头、`.env.example` 的安全相关键**逐项摘要**（sha256 前 16 位），与 `deployment/config-drift-baseline.json` 对账。
- **输出纪律**：只打印条目名与 `ADDED/REMOVED/CHANGED`，**不打印取值**——配置模板里可能夹带密钥样例，回显会把基线本身变成泄露面。`--json` 供机器消费，`--update` 重写基线（须与变更同轮提交）。
- **退出码**：0 无漂移、1 有漂移、2 输入不可解析或基线缺失（宁可报 2 也不给空账面）。
- **边界（如实申报）**：检的是**仓库内**的配置面，即漂移被引入的地方；不读 `process.env`，因此不能替代「运行时配置与基线对账」（后者由启动期断言与 `config/validate.js` 负责）。
- **用例**：`src/tests/scripts/configDriftCheck.test.js`（5 例：抽面有效、无关项不入账且取值不落明文、改值/删项/加项各自被识别、仓库基线不撒谎、CLI 退出码与 `--json` 契约）。

### 新增：用户头像上传（2026-10-30）

> 依据 `deliverables/头像上传功能-计划报告-2026-10-30.md` 评审后的 v2 修订实现。

- **端点**：`PUT /api/auth/avatar`（本人上传/替换，JSON data URI）、`DELETE /api/auth/avatar`
  （本人移除，幂等）、`GET /api/avatars/:userId?v=<hash16>`（本人直通；他人需 `user:read`
  且通过用户数据范围校验，与 `GET /api/users/:id` 同一把尺）。
- **存储**：新集合 `UserAvatar`（`_id = userId`，1:1），图片二进制以 Base64 经 `encryptPii`
  v2（AAD 绑定 `{subjectId, field:'data'}`）加密落库；`data` 为 `select:false`，读取时解密后
  复核 magic bytes 与 SHA-256，防篡改/错配。不落磁盘卷（容器 `read_only: true`）。
- **校验**：仅 JPEG/PNG，原始上限 256 KB，16–1024 px 且 ≤1 MP；拒绝 APNG 与带 EXIF/文本
  元数据的图片（不做"服务端剥离"——剥离需解析全部段，直接拒绝边界更小）。
- **一致性**：上传/移除在事务内同时写 `UserAvatar` 与 `User.avatar`；`PUT /api/auth/profile`
  与 `PUT /api/users/:id` 的 `avatar: ''` 同事务删除记录，避免"指针清了、图还能拉"。
  删号/批量删/匿名化级联删除头像记录。
- **D3 收口**：资料更新只接受**服务端为目标用户生成**的 `/api/avatars/<id>?v=<hash16>`；
  外部 URL / 相对路径 / data URI 一律 400（data URI 会绕过上传校验、加密与尺寸限制）。
- **审计与限流**：新增 action `auth_avatar`（写）/ `avatar_view`（读路由派生，读默认豁免）；
  审计体对头像 data URI 打码为 `***`（窄键规则，不并进全局敏感键子串名单）。
  读路径独立限流桶：预认证 IP 600/15min、认证后用户 1200/15min；响应带
  `ETag` + `Cache-Control: private, no-cache` + `Vary: Cookie`，命中 `If-None-Match` 返回 304。
- **前端**：新增 `UserAvatar.vue`（失败回退首字母）与 `utils/avatarImage.js`
  （中心方形裁切 + 512×512 JPEG q0.85，超 400000 字符自动降质/降尺寸）；
  个人资料页提供更换/移除入口，顶栏、欢迎卡、用户列表统一改用该组件。
- **复核修复（同日）**：图片校验改为"结构解析到文件尾"——JPEG 必须扫描到 EOI 且
  EOI 为最后一个标记，PNG 必须存在 IEND 且 IEND 为最后一个 chunk（另要求至少一个
  `IDAT`）；EOI/IEND 之后夹带 HTML/ZIP/自定义数据一律拒绝，并补回归用例。
  `useravatars.data` 同时纳入 `scripts/migrate-pii-encryption.js` 的 `PII_TARGETS` 与
  `deployment/secret-rotation.md`、ADR-003 的 PII 清单——否则轮换 `AES_SECRET_KEY`
  后头像密文无法解密。头像读取响应另显式下发 `X-Content-Type-Options: nosniff` 与
  `Content-Security-Policy: default-src 'none'; sandbox`，即使直接导航到图片 URL
  也不会把 polyglot 响应渲染成可执行文档。
- **夹带面再收口（同日）**：段/chunk 判定由"黑名单"改为**白名单**——黑名单漏一个
  APPn/chunk 就是一条夹带通道。JPEG 只放行 APP0（标准 14 字节 JFIF，带缩略图即拒）、
  APP2（单段完整 ICC_PROFILE：序号/总数为 1、声明长度与实际一致、profile 含 `acsp`
  签名）、APP14（定长 12 字节 Adobe 头）、DQT/DHT/DAC/DRI/SOF/SOS；其余 APPn 一律
  `JPEG_UNSUPPORTED_SEGMENT`。
  PNG 只放行 IHDR/PLTE/IDAT/IEND 与 sRGB/gAMA/cHRM/pHYs/sBIT/bKGD/tRNS/acTL，且定长
  chunk 的长度必须精确，其余（iCCP/sPLT/hIST/私有 chunk）一律 `PNG_UNSUPPORTED_CHUNK`。
  Chromium canvas 与 System.Drawing 的真实编码产物（JPEG 带 ICC APP2、PNG 带
  sRGB/gAMA/pHYs）实测全部通过。同时收紧边界：空 `IDAT`、重复 `IHDR`、扫描数据为空
  的 JPEG 一律拒——否则会存下"结构自洽但解不开"的坏头像。
- **特殊情况收口（同日）**：白名单只挡"夹带"，挡不住"结构自洽但解不开"，补齐四处语义判据——
  ① PNG `IHDR` 的位深/色型必须落在规范表 11.1 的合法组合内，压缩法/滤波法必须为 0（否则
  `bitDepth=3`、`colorType=7`、`compression=99` 这类头能过白名单）；② `IDAT` 必须是真能解压的
  zlib 流，且解压字节数**恰好**等于声明尺寸的原始行字节数——只查结构会放过解压炸弹（实测
  203 KB 的 PNG 声明 16×16、`IDAT` 解出 200 MB）；`maxOutputLength` 让超限在解压过程中中断，
  另核对 `engine.bytesWritten` 与 `IDAT` 总长，堵住"流尾巴夹带未消费字节"；③ 隔行（Adam7）
  一律 `PNG_INTERLACE_UNSUPPORTED`——本仓合法流量全是 canvas 重编码产物（`interlace` 恒 0），
  而 Adam7 的行布局无法用一个定长字节数核对，放行等于给炸弹留后门；④ 调色板图必须有
  `PLTE` 且在 `IDAT` 之前、长度是 3 的倍数，JPEG `SOF` 的 `Nf` 必须 1–4 且与段长 `2+6+3Nf`
  自洽（`Nf=0` 的帧头解不出一个像素）。
  同轮把 PNG 结构解析拆到 `utils/pngStructure.js`、错误类型拆到 `utils/avatarImageError.js`，
  避免 `utils/avatarImage.js` 撞 `max-lines` 棘轮（注释净增 0 行）。
  实测最坏情况成本：1024×1024 PNG 7.2 ms/次、3.8 千段 JPEG 2.7 ms/次，256 KB 上限不变。
  - **结构自洽性再收口（同日）**：把“白名单里的每个结构件都必须真的自洽”补齐——
    PNG 逐 chunk 核对 CRC（否则整张图除了签名外每个字节都能被改写而无人发现），
    `IDAT` 之后除 `IEND` 不得再有任何 chunk，同一 chunk 不得重复（`PLTE`/`tRNS`/`bKGD`/
    `sBIT`/`sRGB`/`gAMA`/`cHRM`/`pHYs`/`acTL` 各限一次），变量长度 chunk 的长度按色型定值
    （`sBIT`/`bKGD`/`tRNS` 各有表，`tRNS` 对调色板图限 1–256），灰度图（`colorType` 0/4）
    不允许 `PLTE`；JPEG 的 `DQT`/`DHT`/`SOS` 长度必须被段内表结构整除（`Pq/Tq`+64|128、
    `Tc/Th`+16+符号和、`6+2Nf`）——不校验长度时这三种段就是“合法段名 + 任意字节”的通道。
    变异测试实测：PNG 逐字节翻位 3 种掩码 × 96 字节全数被拒，JPEG 197 字节全数被拒，
    2764 例变异（翻位/截断/插入）无一崩溃。
    真实编码器产物仍全通过：Chromium canvas 的 12 段 `IDAT` PNG、带 alpha 的 PNG、
    512×512 JPEG q0.85，以及 System.Drawing 的 RGB/ARGB/8 位调色板 PNG 与 JPEG。
    成本重测（含 CRC 与全部语义校验）：1024×1024 RGBA PNG 3.7 ms/次、21333 chunk 洪水
    1.1 ms/次、3711 段 DQT 洪水 1.8 ms/次、1039 段 `IDAT` 1.7 ms/次，256 KB 上限不变。

### 安全改造：账号救济 / 删除匿名化 / 异地备份 / 时钟基线（2026-10-30）

> 依据 `deliverables/安全改造待办-2026-10-30.md`。按用户明确要求，**不实施强制 MFA（P1-1）**：
> MFA 能力保持现状，管理员强制开关不启用，文档口径同步改为「能力具备、未强制」。

- **P1-2 账号救济（管理员轨）**：新增 `PUT /api/security/users/:userId/password/reset`，
  权限 `user:reset_password` + 二次验证 + 数据范围/层级/内置超管保护；生成一次性临时口令
  （≥12 位、四类字符），`tokenVersion++` + 吊销全部会话 + `mustChangePassword=true`，
  审计 `admin_reset_password`（临时口令不入审计/日志）。首次登录只放行改密/me/logout，
  改密完成清标记并审计 `password_force_changed`。内部系统无邮件通道，自助找回轨不做。
- **P1-3 删除改匿名化**：单删/批量删除改走 `userService.anonymizeById/anonymizeMany`，
  保留 `_id/username` 维持审计引用，抹除 realName/phone/email/avatar 并置 inactive，
  释放进行中指派，审计 `user_anonymized`；硬删除只保留建号回滚与测试夹具。
- **P1-4 异地备份**：`deployPolicy.checkBackupOffsite` 在 `DEPLOY_ENFORCE_OFFSITE=true`
  或 `NODE_ENV=production` 时要求 `BACKUP_OFFSITE_CMD/DIR`；`BACKUP_REQUIRE_OFFSITE=true`
  使备份脚本缺配置即失败。补 gpg 密钥轮换、逻辑恢复演练记录模板与生产部署清单。
- **P1-5 时钟基线**：新增 `scripts/check-clock-sync.js`（timedatectl/chrony，偏移阈值可配，
  判不了退出 2）、`deployment/systemd/chrony.conf.example` 与 `deployment/clock-sync.md`；
  self-hosted/SSH 部署在正式发布前调用，dry-run 跳过。
- **审计与前端**：新增 action `admin_reset_password`/`password_force_changed`/`user_anonymized`/
  `security_users_password_reset`，中英文标签同步；登录响应与 `/auth/me` 下发
  `mustChangePassword`，前端登录后直达个人资料页并由路由守卫收敛，用户删除提示改为
  「已注销并匿名化」。

### 新增：应用内一键蓝绿升级（2026-10-30）

> 目标：把「发版」从「SSH 上去敲命令」变成「应用里点一次按钮」，同时不让应用容器
> 拿到宿主的 docker / nginx 控制面——那条路等于把容器逃逸做成常驻攻击面。

- **契约：文件队列 + 双向重校验**。应用只往共享队列目录（`UPGRADE_QUEUE_DIR`，compose
  以 bind mount 与宿主共享）写一份 **HMAC 签名**的请求文件，宿主机上的
  `scripts/hotUpgradeAgent.js`（systemd timer）重新校验摘要与仓库白名单后才执行
  `scripts/hotUpgrade.js`。应用侧的校验只是输入错误的前置拒绝，不是安全边界本身。
- **镜像必须 digest 钉扎**：只接受 `registry/repo@sha256:<64hex>`，tag 一律拒绝
  （tag 可被覆盖，审计里记的版本会与线上跑的不是一回事）；仓库前缀须命中
  `HOT_UPGRADE_REGISTRY_ALLOWLIST`，**空白名单 = 全拒**（fail-closed，不是全放）。
- **新端点**：`GET /api/security/upgrade`（构建信息 + 就绪判据逐条原因 + 最近任务）、
  `GET /api/security/upgrade/jobs/{jobId}`、`POST /api/security/upgrade/requests`
  （路由层 `security:config` + 函数内唯一超管 `*:*` + 二次验证凭据 / `X-Reauth-Ticket`）。
  三条路径已进 `src/docs/generate.js` 与产物，`openapiSync` 双向对账。
- **审计先落盘再回 202**：`upgrade_triggered`（`riskLevel: high`，含 jobId / 镜像 / 来源 IP）
  走 `recordDurably`；失败路径不设 `skipGlobalAudit`，由全局审计记录这次尝试。
- **队列读写加固**：请求文件 `0600`（随机临时名 + `wx` 打开 + fsync + rename，
  避免可预测临时名被符号链接劫持）、只读侧单 fd 读取（`O_NOFOLLOW`）、心跳缺 `ready`
  或时钟回拨一律判未就绪。
- **前端**：`AboutView` 版本卡 + `UpgradeDialog`（镜像地址、二次验证、进度步骤），
  中英文案齐备；`utils/api.js` 增加对应调用。
- **运维面**：`deployment/systemd/{fsms-hot-upgrade-agent.service,.timer}` 与
  `hot-upgrade.env.example`；`deployment/hot-upgrade.md` 第 3 节补「应用内一键升级」流程；
  `deployment/secret-rotation.md` 把 `HMAC_SECRET` 的影响面从「五个消费点」更新为**六个**
  （第 6 个是升级请求签名：换钥后只让在途请求被拒，重发即可，既无迁移手段也不需要迁移）。
- **门禁同步登记**：`.env.example` 补 `UPGRADE_QUEUE_DIR`；`services/upgradeService.js`
  的 `TERMINAL_STATES/ACTIVE_STATES` 进单进程豁免表（静态字面量词表，无跨进程语义）；
  日期解析收口到 `utils/helpers.toEpochMs`（裸 `Date.parse` 只允许一处）；
  `controllers/securityController/upgrade.js#triggerUpgrade` 进可靠审计登记表；
  升级错误码改成逐码字面量发出（动态查表会让五个已注册的码退化成死码）。
- **默认关闭**：`UPGRADE_ENABLED=false` 时概览仍可读（按钮不可用并给出原因），
  POST 返回 `UPGRADE_DISABLED`。
- **对外命名**：应用内入口统一称「一键升级」（原「一键热升级」）——弹窗标题、不可用/白名单
  错误文案（中英）、接口兜底 message 与 OpenAPI 摘要同步去「热」字，与「蓝绿切换」的语义对齐。

### 加固：升级链路的第二轮逐行审计收口（2026-10-30）

> 依据多子代理逐行审计报告（部署/脚本/后端/前端/门禁五路）。这一轮**不新增能力**，
> 只把「升级看起来成功、实际没成」与「把权限收紧做成功能失效」两类形态从链路上消掉。

- **队列属主矩阵**（`docker/app-entrypoint.sh`）：应用只写 `requests/`、只读 `status/processing/`。
  原先一律 `chown nodejs` 让被攻陷的应用可以删 `processing/.agent.lock`（升级永久显示进行中）、
  伪造 `status/<id>` 为 `succeeded`（界面假成功、请求被丢弃）、清空 `rejected/`（验签失败留证消失）。
  现改为 `requests=nodejs:nodejs 0700`、`status/processing=root:nodejs 0750`、`rejected=root:root 0700`；
  顺序固定为「收回 root → chmod → 交出属主」（`cap_drop: ALL` 且不补 `FOWNER`，对已属 nodejs 的
  目录 chmod 必然 EPERM，而入口是 `set -eu`——第二次启动/app-green/一次性迁移容器都会因此起不来）。
  另拒绝对 `/`、`/etc` 等系统目录改属主，`find -xdev` 不跨文件系统、不跟随符号链接。
- **蓝绿互不踩**：`app-green` 显式 `AUDIT_WAL_PATH=/app/logs/audit-buffer.green.wal`——两色共用
  `app-logs` 卷时，按库名派生的 WAL 会被两个进程同时追加，而 WAL 的全部价值是崩溃重放，
  双写者让「谁写的、该不该重放」不可判定（重复插入 → 哈希链分叉）。
- **CI 的 hot 分支补 `--apply`**：此前直接调 `hotUpgrade.js` 而未加 `--apply`，脚本按设计走演练
  分支并**以 2 退出**——流水线会「成功打印了计划」，线上什么都没变。现两条模式（本地/SSH）
  都显式在 `--apply` 与 `--dry-run` 之间二选一。
- **布尔旗标严格解析**（`scripts/hotUpgradePolicy.js`）：`--apply=false` 此前被当成「出现过就是真」，
  模板里写 `--apply=${{ inputs.apply }}` 且值为 false 时会真的开始切流。现在只接受 true/false（含 1/0、yes/no），
  其他值报错而不是猜。
- **代理锁的 pid 复用**（`scripts/hotUpgradeQueue.js`）：锁新增 `/proc/<pid>/stat` 的启动时刻与 3h 锁龄上限，
  空锁文件/损坏锁/pid 被复用都能接管；此前只判 `kill(pid,0)`，一个恰好复用旧 pid 的无关进程会让按钮
  永远显示「另一个升级正在进行中」。
- **只读侧单 fd**：`readJsonFile` 改为 `openSync(O_NOFOLLOW)` + `fstat` + 从 fd 读——原先 `statSync` 后按路径
  `readFileSync` 是两次解析，应用对 `requests/` 可写时可换成符号链接，让 root 代理读到任意宿主文件。
- **写入与观测**：`status/processing` 文件 `0640`（属组＝队列目录属组，应用可读、other 不可读）；
  `hotUpgradeJob` 记录子进程 pid 失败时 `SIGTERM` 回收进程并如实报错（原先会留下无人跟踪的升级进程）；
  起备色补 `--no-build`（compose 里 app 段带 `build:`，否则会在部署机上重建当前源码，线上跑的就不是请求里的 digest）；
  观察期未通过**回滚成功后才**停新色（回滚失败分支不停，否则可能把仍在接流量的容器杀掉）。
- **监控**：`prometheus.yml` 同时抓 `app:3000` 与 `app-green:3000`；`BackendDown` 改为
  `sum(up{job="xf-app"}) == 0`——逐实例判会让平时根本没起的备色永久点亮告警，而永远在响的告警等于没有告警。
- **systemd 加固**：代理单元补 `NoNewPrivileges/Umask=0077/PrivateTmp/ProtectHome/ProtectSystem=full`
  与 `ReadWritePaths`；`hot-upgrade.env.example` 补 `MONGODB_URI_FILE`/`BACKUP_ENCRYPTION`/
  `BACKUP_GPG_RECIPIENT`——代理的环境**只来自该文件**，缺任一项时第一个升级请求都会停在备份步。
- **门禁同步**：`LAZY_SCC` 登记 `config/jwtRotation.js`（真实惰性环）、单进程豁免表登记
  `middleware/auth.js` 的 `PASSWORD_CHANGE_ALLOWED_PATHS`（静态只读 Set）；三处环境相关的用例判据收窄到
  「本子系统自己的那几条文案」（ACL 噪声另有专门用例钉住），而不是靠机器上有没有 `USERNAME`/`bash` 决定红绿。

### CI 修复：锁文件锚未重算 + 三处用例随实现漂移（2026-10-30）

> 现象：`CI` 从 `6415fd6` 起红，且**只红在第一个作业** `dependency-policy`——
> 后面 `test`/`e2e`/`e2e-browser`/`build` 全部 `needs: dependency-policy`，
> 一个闸失败就把整条流水线的可见性一起挡掉。本地逐闸复跑后发现：闸背后还压着
> 三处**与依赖无关**的红（`test` 作业一旦被放行就会立刻暴露），故一并修。

- **锁文件锚（`dependency-policy` 唯一的红）**：`6415fd6` 把 `vue-i18n` 从
  `9.14.5` 升到 `11.4.16`（v9/v10 已被上游标记 deprecated 并停止维护），
  `web-admin/package.json` 与 `package-lock.json` 都改了，但
  `deployment/lockfile-anchor.json` 没重算 ⇒ `LOCKFILE_ANCHOR_MISMATCH`。
  处理口径按锚文件自身的提示走：先人工复核锁文件 diff（仅 `vue-i18n` /
  `@intlify/*` 一族，`resolved` 全为 registry.npmjs.org、integrity 随版本同步变更，
  无夹带），再 `npm ci --dry-run` 确认锁文件与 package.json 自洽，最后
  `node scripts/check-lockfile-integrity.js --update`。**不是**回退依赖：
  v9 已停止维护，回退等于把 EOL 依赖留在发布基线上。
- **compose 告警配置链（`test`）**：`894f1de` 的 F-15 把 alertmanager 的配置挂载
  从「直接 bind mount 宿主文件」改成「一次性 `alertmanager-config-init` 复制进
  命名卷并 chown 65534，alertmanager 只读消费该卷」（宿主 0600 文件容器内 nobody
  读不到）。`alertingConfig.test.js` 与 `alertmanagerComposeGate.test.js` 仍断言
  旧的 bind mount 形状。改为钉新链条的三段——校验容器、初始化容器都取同一个
  `${ALERTMANAGER_CONFIG_PATH:-…}`，运行侧只消费 `alertmanager-config` 卷且
  `depends_on` 初始化容器 `service_completed_successfully`。「校验的是 A、跑的是 B」
  这条原始不变量原样保留，只是中间多了一跳。
- **单进程依赖清单（`test`）**：`6415fd6` 新增的 `controllers/ipListWriteGuards.js`
  带模块级 `Set`（`IP_LIST_WRITE_FIELDS`，写路径字段白名单），未进
  `SINGLE_PROCESS_DEPENDENCIES` 也未进豁免表。按既有口径补豁免条目（静态字面量
  词表、只读、无跨进程语义），与 `routes/wellKnownRoutes.js` 的 `CLIENT_ERROR_KINDS`
  同族——**不是**登记进清单：登记会让启动期对运维误报"多实例下这条会失效"。
- **NODE_ENV 未设置（`test`）**：`93519ae` 起 `validate.js` 对「`NODE_ENV` 键根本
  不存在」直接拒绝启动（缺失时无法区分"开发机裸跑"与"生产容器漏配"，按开发语义
  放行等于弱密钥/Host/Redis/TLS 四类校验一起静默跳过），README 部署清单与
  `.env.example` 已同口径。`nodeEnvGateFailsClosed.test.js` 仍把「未设置」放在
  「允许跳过生产校验」那张表里。改为单列一条：未设置 ⇒ 拒绝启动；同时保留
  `normalizeNodeEnv()` 对 `undefined` 仍返回 `development`（其他模块依赖这个归一值，
  改它会波及一圈无关判据）——两件事分开钉。
- **WS 握手用例夹具（`test`）**：`93519ae` 让握手期 IP 判定在「取不到客户端地址」
  时 fail-closed（`无法验证网络来源`），`#9` 又加了按来源 IP 的未认证连接准入表。
  两处夹具因此失真：`wsFlow.test.js` 的假 socket 有 `handshake` 但**没有**
  `address`，`tokenPurposeAndConsumers.test.js` 的假 socket 连 `handshake` 都没有
  ⇒ 认证分支一条都跑不到（表现为 8s 超时 / 断言拿到「无法验证网络来源」）。
  补 `address: '127.0.0.1'`；`wsFlow` 的假服务实例补
  `unauthConnectionsByIp = new Map()`（真实构造器在 `index.js:66` 初始化）；
  `tokenPurpose` 补桩 `models/IPBlacklist`（该套件没有真实 DB，不桩就会以
  「网络黑名单校验暂不可用」fail-closed）。被测判据一条没放松。

> **本机复跑的两处"红"不是 CI 红，未改代码**：`backupEncryptionContract` /
> `backupTransport` 在本机失败的原因是本会话工具链注入的 `rm` 垫片拒绝
> Windows 盘符路径（`[safe-delete][SAFE_DELETE_INVALID_PATH] embedded drive prefix`），
> 把 `safe-bin` 从 `PATH` 移出后同一脚本行为正确（半成品归档确实被删）。
> CI 是 ubuntu + 真 coreutils `rm`，不受影响。

---

### 修复（2026-10-28 · dev 代理覆盖上游 X-Forwarded-For，审计与限流只见内网地址）

> 现象：经外层反代/预览网关访问时，后端审计与限流记录的客户端 IP 恒为
> `127.0.0.1`/`::1`，真实地址丢失。

- 根因：`web-admin/vite.config.js` 的 dev 代理无条件用 `req.socket.remoteAddress`
  覆盖 `X-Forwarded-For`。外层代理已经把真实 IP 写进该头，而它连 Vite 的对端是回环
  地址，覆盖等于把真实地址抹掉。
- 修复：`/api`、`/client-errors`、`/socket.io/` 三个代理块统一改为「上游有 XFF 则
  原样透传（数组形态拼接），缺失才回落 socket 对端」。本地直连 dev server 的行为不变。
- 测试：新增 `web-admin/src/tests/bundling/devProxyForwardedFor.test.js`，对三个代理块
  分别钉住「透传 / 多值拼接 / 回落」三条契约。

---

### CI 修复：runner 内核误报导致 e2e-browser 起不来 Mongo（2026-10-28）

> 现象：`CI` 的 `e2e-browser` 在 **Start full stack** 步骤失败，后端日志是
> `connect ECONNREFUSED 127.0.0.1:27017`，看起来像服务没起来；`test`/`e2e` 全绿。
> 定位到真正原因不在本仓代码：

- **根因**：GitHub 自镜像 `20261018.339.1` 起把内核抬到 `7.0.0-1017-azure`，其
  `/proc/version_signature` 实为上游 **7.0.14**；而 MongoDB 8.0.x 只读 `uname -r`（得 `7.0.0`），
  误判进 SERVER-121912 的「6.19–7.0.13 不兼容区间」，启动即以 fatal `12257600` 退出。
  上游误报修在 SERVER-131779，**8.0.34 没有**（8.0.x 最新即 8.0.34，2026-10-13 发布）。
  旁证：同一次运行里 `e2e` 落在旧镜像 `20261012.334` 上，同一份 mongod 8.0.34 正常启动并通过。
  外部登记：`actions/runner-images#15005`（open，GitHub 工程师给出的临时变通即回 `ubuntu-22.04`）。
- **为什么换二进制绕不过**：把官方 tarball（sha256 与仓内锚一致）解开后，该 fatal 串在 `mongod`
  二进制内可直接检索到——闸是编进 mongod 的，不是 Docker 镜像特有的。故 `test`/`e2e` 的
  `MONGOMS_SYSTEM_BINARY` 路径同样会在新内核上失败，只是尚未落到新内核宿主机而已。
- **修法**：`test`/`e2e`/`e2e-browser` 三个用真实 mongod 的 job 钉 `runs-on: ubuntu-22.04`
  （其余 job 保持 `ubuntu-latest`）；`deployment/mongod-artifacts.json` 增补 `ubuntu2204` 条目
  （2404 包要求 glibc 2.39，22.04 的 2.35 跑不了），sha256 `8eef2a82…c7aced43` 取
  `downloads.mongodb.org/current.json` 官方值与自算字节哈希**逐字一致**的双锚。
  不动的部分：mongo 镜像仍钉 8.0.34 及其 digest（生产 compose 口径不变），三方对账闸不受影响。
- **回滚条件**：MongoDB 8.0.35 发布并完成 digest/sha256 对账，或 runner 内核进入 ≥7.0.14 区间。

---

### 审计第五轮复核：逐条回源码验证、修成立项、登记不成立与暂缓项（2026-10-26）

> 承接 `deliverables/audit-2026-10-26/audit-report.md`（复核基线 `4a1bdae` + 工作区）。
> 先把 P1/P2/P3 全部结论逐条回到当前源码与实跑结果复核，再只修验证成立的部分；
> 报告补第九节复核记录。**不修不存在的问题，也不沿用报告里的数字。**

| 项                          | 复核结论     | 处理                                                                                                                                                                                                                                                                                              |
| --------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1-1 工作区卫生             | 成立         | 删除 `.jest-*`/`.vitest-*` 日志、`.ci-repro.log`、`.tmp-probe.json` 与 4 个 `.lint-ratchet-selftest-*` 残骸；`.env` 的 `HMAC_SECRET` 19 → 43 字符（dev 文件、gitignored；本地既有审计 HMAC/二次验证票据随之不可验，重登即恢复）。`logs/`、`.mimosa/`、`CHANGELOG.md.bak` 是运行产物且已忽略，保留 |
| P2-1 假 performance 指标    | 成立         | 删除 `overview.performance` 三字段（无消费方且与 A-2「不可用≠零值」冲突），真实指标仍在 `/metrics`                                                                                                                                                                                                |
| P2-2 `data.data` 双层信封   | **部分成立** | 审计列表（游标/偏移两臂）与 `getRecentAlerts` 改用新增的 `ApiResponse.successWithMeta`（`data`/`meta` 平级），前端 `AuditLogView` 同步；`exportAuditLogs` 是流式 CSV，不经 `ApiResponse`，报告把它算进来不准确                                                                                    |
| P2-3 权限列表上限           | 成立         | `permissionRoutes` 的 `limit` 500 → 100                                                                                                                                                                                                                                                           |
| P2-4 authRoutes 错位注释    | 成立         | 删除两处错贴的 PERMISSION-EXEMPT 注释（`refresh` 在 `:325`）                                                                                                                                                                                                                                      |
| P2-6 设备统计无缓存         | 成立         | 新增 `services/deviceStatsService.js`：`scopeFilter` 序列化键 + 15s TTL + 单次 8 臂 `$facet`；7 条写路径统一 `invalidateDeviceStats`（代际防旧值写回 + `sharedCache` 跨实例广播）。`DeviceService` 只留委派，守住 max-lines 棘轮                                                                  |
| P3-3 wellKnown 未入 OpenAPI | **不成立**   | `openapiSync` 两条用例明文钉住「wellKnownRoutes 属于豁免面（不进 `openapi.json`，且豁免有据）」，是有测试保护的设计而非漏登记                                                                                                                                                                     |
| P2-5 / P3-1/2/4/5/6/8       | 暂缓         | warning 全在棘轮基线内、0 error；拆分与产品/运维决策按报告原路径排期                                                                                                                                                                                                                              |
| 锚点与密度同步              | 必做         | `DeviceService.js:445→deviceStatsService.js:82`、`auditQueryService.js:320→:314`、`statsCache.js:155/201→:159/:230`、`DeviceService` 计数 `:108/:502→:110/:444`；7 处引用注释与 2 个消费方断言同步；`statsCache`/`apiResponse` 注释压回密度基线（98→97、59→59）                                   |
| 验收                        | —            | 全量 `jest` **644/644 套件、7,956/7,956 例**；前端 `auditLogView` 44/44；`lint` 0 error/14 warn、`lint:ratchet`/`format:check`/`docs:check`（86 path / 105 operation）全绿；锚点两闸 28/28、`commentDensityRatchet` 5/5、路由契约 44/44                                                           |

---

### 审计第四轮：惰性环 4 → 1 个分量、台账单源化、注释治理落 ADR-011（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §15.2 如实登记的「A-1 剩余三个分量未做」，
> 并一并收口 **Q-3/T-6**（多份台账各自手抄实现清单）与 **Q-1**（生产注释混入变更史）。
> 报告补第 16 节。所有修复先复现红点再改，没有放宽任何断言。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A-1 惰性环清零   | 强连通分量 **4 → 1**、模块 **36 → 22**。新叶子：`middleware/userAuthCache.js`（用户缓存与失效广播，断 `auth ↔ tokenBlacklist`）、`middleware/dataScope.js`、`middleware/httpMethods.js`、`middleware/security/ipBlacklistStore.js`（封禁原语）、`middleware/security/earlyRejection.js`（早拒绝审计）、`services/alertTypes.js`、`services/alertDispatch.js`（告警链断环）。`models/User.js` 删除三个权限薄代理，调用方直接走 `userPermissionService`。`LAZY_SCC` 只剩 config/audit/metrics 22 模块，保留理由写在 `requireCycles` 头 |
| A-1 行为保持     | `addToBlacklist` 在两个封禁模块保留**调用时取属性**的薄包装（解构会在加载期固化绑定，测试就无法替换封禁结果）；F-160 的 `await addToBlacklist(` 文本门禁继续命中。6 个封禁/升级套件的注入点迁移到 `ipBlacklistStore`，是跟随唯一写入原语，不是放宽断言                                                                                                                                                                                                                                                                               |
| Q-3/T-6 台账单源 | 写方法名单收敛到 `middleware/httpMethods.js`（originCheck / security/auditLog / protocolCompliance / behaviorBaseline 四处不再各抄一份）；审计分类测试改为引用 `constants/audit.js` 的 `AUDIT_CATEGORIES`；Redis 降级失效清单改为从 `SINGLE_PROCESS_DEPENDENCIES` 过滤派生                                                                                                                                                                                                                                                           |
| Q-1 注释治理     | 新增 `docs/adr/ADR-011-注释治理-源码只保留当前约束.md`：源码只写当前约束与不明显的 Why，变更史归 CHANGELOG、权衡归 ADR、锚点优先符号。`securityHeaders.js` 整行注释 180 → **102**（生产注释 22,504 → **22,426** 行，−78）                                                                                                                                                                                                                                                                                                            |
| Q-1 密度棘轮     | 新增 `scripts/commentDensity.js` + `scripts/commentDensity.baseline.json`（258 文件 / 22,426 注释 / 34,798 代码）与 `src/tests/ci/commentDensityRatchet.test.js`（5 例：统计面自证、只降不升、新文件密度 ≤ 30%、反向对照、总量对账）。`--update-baseline` 遇回归直接拒绝                                                                                                                                                                                                                                                             |
| 棘轮实测         | A-1 给两个封禁模块各加 1 行说明后，棘轮立即报 2 处回归并拒绝收紧基线；按 Q-1 口径把 3 行历史压成 2 行后才写回基线——证明它不是「写完就绿」的摆设                                                                                                                                                                                                                                                                                                                                                                                      |
| 测试重定向       | `auditScopeFilterDeptCache` / `edgeCases` / `auditQueryOperationCatch` 的桩从 `middleware/rbac` 改到 `middleware/dataScope`（后者才是 `auditScopeFilter` 的叶子依赖；旧桩失效时真实查询打未连接 Mongo，表现为 10s 超时且日志为空）；`websocketRedisAdapter` 的 `sharedCache` 桩补 `onInvalidate`（`userPermissionService` 在加载期注册）；`sharedCacheDegradationLog` 改为派生清单（手抄版已漂移成 `middleware/auth.js`）；`reportPiiExportStepUp` 的审计断言改为轮询到真实落库（全量并发下响应先回、行尚未可见）                    |
| 验收             | 全量 `jest` **643/643 套件、7,950/7,950 例全绿**；`requireCycles` 6/6、`commentDensityRatchet` 5/5、封禁链 57 例、定向回归 179 例全绿；`npm run lint` / `lint:ratchet` 0 error（14 条既有 warning 未超基线）、`docs:check`（86 path / 105 operation）与 `format:check` 一致                                                                                                                                                                                                                                                          |

---

### 审计剩余项收口：事务拓扑 fail-closed、导出并发闸、日志 PII 掩码、运行指标补齐（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §14.5 的"仍未处置"清单。
> 本轮把 `P-1`/`P-2`/`O-1`/`O-2`/`O-3`/`T-3`/`T-4` 做掉，`A-1` 解掉一个强连通分量
> （40 → 36 模块），剩余三个分量属需改所有权的重构，**只登记不改结构**（报告 §15.2）。

| 项                       | 内容                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-1 事务拓扑 fail-closed | 生产语义下探测到 `standalone`（多集合写非原子、失败留残骸）⇒ `/readyz` 判 503（`checks.topology=transactions_degraded`），**不阻断启动**。判据落在 `utils/transaction.js` 的 `transactionReadinessBlocker()`，与既有的多实例闸合并成单一 `topologyBlocker`，同时命中时**多实例优先**（它同时影响审计链与限流计数，且修法与事务拓扑无关）                                      |
| P-2 导出并发闸           | 新增 `services/exportConcurrency.js`：上限 2 / 有界队列 8 / 排队超时 30s，全部可经 `EXPORT_MAX_CONCURRENCY`、`EXPORT_MAX_QUEUE`、`EXPORT_QUEUE_TIMEOUT_MS` 调整并在越界时**钳制 + 一次性告警**。队列满或超时 → 429 `EXPORT_BUSY` + `Retry-After`。释放幂等、槽位**移交**给 waiter（不"先减再加"，避免空窗被第三个请求插队）                                                   |
| O-1 日志 PII 集中掩码    | 新增 `utils/logPiiMask.js`，接在 `logger.sanitizeLogInfo` 末尾（清洗 → 截断 → 掩码）。判定顺序 **email → 身份证 → 手机号**（身份证必须先于手机号，否则 18 位号码会被手机号正则切碎）；键名用闭合集 + 后缀判定，**刻意不含 `token`** 后缀以免误伤 `tokenVersion`；`requestId`/`userId`/`socketId` 作为结构性标识不掩。`LOG_PII_MASK=false` 可关，关闭时在生产语义下落一条 warn |
| O-2 运行指标补齐         | 新增 `export_inflight`、`export_queued`、`export_rejected_total{reason}`、`ws_connections`、`ws_inbound_throttled_total`、`ws_inbound_disconnects_total`。WS 连接数用**拉取式** `registerWsConnectionSource`（4 处增删点任一漏推都会让 gauge 长期偏高，拉取式免掉这个失效面）；文本与 JSON 快照两通道同源                                                                     |
| O-3 tracing 适用边界     | 新增 `docs/adr/ADR-010-不引入分布式追踪的适用边界.md`：把 `requestId` 能覆盖什么、跨进程边界为何断在这里、什么条件下该重新评估，写成可证伪的判据而不是"暂时不做"                                                                                                                                                                                                              |
| A-1 惰性环（部分）       | 抽出零 require 叶子 `src/config/envSemantics.js`（环境别名/生产语义判据），`config/validate.js` 改为 re-export。实测强连通分量 40 → **36** 模块，`requireCycles` 的 `LAZY_SCC[0]` 26 → **22**                                                                                                                                                                                 |
| T-3 路由分支补测         | 新增 `routes/routeGuardBranches.test.js` 9 例：strict 档两条守卫（明文注册被拒、enc+明文并存被拒）与改密接口、巡检时间窗倒置、`POST /reports/export/pii` 类型白名单、创建用户口令 64 字符上限，均带反向对照                                                                                                                                                                   |
| T-4 sharedCache 故障注入 | 41 → **47** 例，覆盖三类"总闸式注入看不见"的形态：单条命令失败（`GETDEL` 抛错走 get→del 降级，两步必须落在同一份内存回退上）、`DECR` 回收路径（真实现此前零覆盖）、连接级故障的**日志节流**（未就绪期的重试风暴不得刷 error 日志）。三处逐一做变异，确认变红后还原                                                                                                            |

---

### 七维审计复核：把「报告结论」逐条回源码验证，再修真正成立的那几条（2026-10-25）

> `deliverables/audit-2026-10-25/audit-report.md` 的基线是 `01e08f7`。复核时 HEAD 已是
> `170467c`，**报告里的大部分数字已经过期**（380/109 个文件、28 套件 56 用例红、19 条环）。
> 本轮先把每条结论回到当前源码与实跑结果上验证，再只修验证成立的部分；报告已就地打叉
> 并补第 13 节复核记录。**不修不存在的问题，也不沿用别人的数字。**

| 项                                          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-4 压测脚本（修）                          | `scripts/load-test.js` 仍在读 `r.body.data.token`，而登录早已只下发 httpOnly Cookie（I-01）⇒ 登录步必然抛错，E/D 两相**从未真正执行过**。改为从 `Set-Cookie` 取 `access_token` 显式回放（`loadTestEngine` 增加 `cookie` 通道，与 k6 脚本同口径）。**实跑证据**：`npm run test:load` 8 通过 0 失败，B/C/E/D/D+ 全绿，基线已落 `logs/load-baseline.json`——这是本仓第一份可信的压测结果                                                                                                                                                                                                                                                                                                    |
| 压测 D 相与新封禁策略冲突（修，报告未发现） | #21 之后 IP 封禁要求「同一 IP 失败过 ≥2 个不同账号」，而脚本只打一个用户名 ⇒ 即使取到凭据也永远等不到 403。改为两个一次性靶用户交替失败，并显式断言「401 覆盖 ≥2 个账号」。实跑日志确认 `distinctAccounts:2, ipBanApplied:true`                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| A-2 就绪闸（修，已在工作区）                | 多实例且无分布式审计锁时 `/readyz` 判 503（`checks.topology`），不再只打日志；`constants/runtime.js` 把重复的 Redis 就绪探测抽成 `sharedCacheReady()` 一处                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| A-1 惰性环（登记，不是消除）                | 报告写的「19 条」在任何枚举口径下都复现不出来。实测：**4 个强连通分量 / 40 个模块 / 122 条简单环**（长度 ≤9）。新增 `requireCycles` 用例按**分量**逐条登记，新增或消失都会红——分量是与遍历顺序无关的不变量，条数不是                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| T-1 MFA（补测）                             | `mfaController` 分支 64.58% → **87.5%**，函数覆盖 80% → **100%**（补 `getMfaStatus` 三例：余量如实、已关闭为 0、用户不存在不抛）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| T-2 二次验证（补测）                        | `securityController/reauth.js` 分支 50% → **100%**：补「令牌无 sid 时按未绑定会话签发，且不认任何具体会话」                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 锚点台账（同步）                            | A-2 改动使 `app.js` 行号整体后移，7 处 `LIVE` 登记与 4 个文件里的引用注释逐条改到新行号（`:205→:206`、`:249→:250`、`:487→:500`、`:546→:559`、`:550→:563`、`435-457→435-479`、`460→:473`），手册 `:297→:302` ；同日 `src/app.js` 的 `recordReadyz` 判据由 prettier 展开的九行嵌套三元收成 `?.` + `??` 单行形态（`format:check` 原本就在这个文件上红），行号再迁 3 行，登记同步到 `:462/:476/:503/:562/:566` 与 `435-482`；顺带发现 `queryLimit.test.js` 引用的 `app.js:536` 本就失实（真实落点是 `:592` 的 `query parser`），一并改对                                                                                                                                                    |
| 文档对账（修判据）                          | `documentationDrift` 的 bash 续行断言在 CRLF 检出下必然假红（同一份文档 Windows 红、CI 绿）。改在 `read()` 入口统一行尾——行尾是检出形态，不是内容事实                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 指标契约（同步）                            | `runtimeMetricsCoverage` 的 `/readyz` 判定正则绑定死了旧的三元表达式形状，A-2 加一档拓扑阻断即假红。改为钉三件语义（`ready ? 'ok'` / `mongo.ok ? redis.reason` / `topologyBlocker.reason`），并保留可失败反证                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 信号用例（修竞速）                          | `imageDigestGate` 的 SIGTERM 用例写死「睡 1 秒再发信号」，而 Windows/MSYS 起一个 sh+替身要 2–3 秒 ⇒ 替身日志为空、被判成"脚本没被叫醒"。改为**等替身留下第一行日志再发信号**（判据更严，不再依赖机器速度）                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 随机顺序 worker 崩溃（修，CI 实证）         | CI 的 `Test order independence (randomized)` 在 `170467c` 上是红的（`test (26.x)` 失败、22/24 被 fail-fast 取消），红点是 `appTrustProxyAndReadyzGuards` 的 `Jest worker encountered 4 child process exceptions`。根因不在断言：`auditLog` 用 `setImmediate` 异步落库，而回调体里才惰性 require `utils/fingerprint`；文件跑完、Jest 拆环境后回调才被调度，require 拿到 `undefined` ⇒ `TypeError: Cannot destructure property 'computeFingerprint'` 抛在测试框架之外，**直接崩 worker**（同文件按默认顺序却全绿，是典型的顺序耦合指纹）。修法：该套件 `afterAll` 放完一个 tick；修复后按三个 seed 各跑两次该文件 6/6 绿，再按 CI 口径跑全量三 seed，`appTrustProxy` 不再出现 worker 崩溃 |
| 测试树纯净性（入库）                        | 3 个新增用例（T-1/T-2/T-5 与 P-3 降级 TTL）与 `scripts/check-openapi-drift.js` 此前未跟踪，`testTreePurity` 因此红；已入库                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| D-1 OpenAPI 门禁（修，已在工作区）          | 新增 `npm run docs:check` 并在 CI 阻断；反证过：给生成器注入一条 path 后比较必然为 false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

### 告警抑制规则移除、nginx 显式拒绝 `/readyz`、Node 运行时进 CI 矩阵、5 条"假绿"测试逐条复核（2026-10-24）

> 审计第二批 6 项。其中 **2 项经复核不成立**（compose app 的 healthcheck、两个"假绿"测试），
> 记录在下方表格的对应行——不修一个不存在的问题，与修一个真问题同等重要。

| 项                            | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 告警抑制规则（移除）          | `alertmanager.yml` 原为「任何 critical 抑制同实例任何 warning，`equal:['instance']`」，理由写的是「BackendDown 时 HighP95Latency 必然伴随」。复核后整条移除，三条理由写进文件：①该理由**事实错误**——目标停止导出指标后 `rate()` 无样本，延迟告警根本不会触发；②即便成立，`equal:['instance']` 也匹配不到 `ReadinessProbeMissing` 的 `absent()` 分支（`absent()` 只回填选择器里的 `job`），而那正是"后端真挂了"时唯一会亮的伴随告警；③若真能生效，`AuditRecordsDropped`(critical) 会压掉同实例 `DiskSpaceLow`(warning)——把**根因**信号静默掉。同时留了新增抑制的三条门槛（alertname 精确 / target 是 source 的纯后果 / equal 标签两侧必然存在）                                                                          |
| 告警标签（修）                | `alert-rules.yml` 的 `HighErrorRate`、`SecurityAlertBurst` 由 bare `sum(...)` 改为 `sum by (instance)`。理由不是"为了让抑制能匹配"（那条规则已移除），而是多实例部署下 bare `sum` 会把全部标签丢掉：告警分不清哪台机器出错、面板无法按实例下钻、`{{ $labels.instance }}` 渲染成空串。单实例环境里这个缺陷"看起来完全正常"，所以只能靠契约测试钉住                                                                                                                                                                                                                                                                                                                                                                       |
| nginx `/readyz`（修）         | `deployment/nginx.conf.example` 此前只有注释「/readyz 刻意不对外」，配置上无任何对应指令 ⇒ 落进 `location /` 的 `try_files` 返回 **200 + index.html**。外部拨测配了这个地址会**恒判健康**（它探的是 nginx 能否返回 HTML，不是 Mongo 可不可达）。新增 `location = /readyz { return 404; }`：精确匹配、不反代、用 404 而非 403（403 等于确认"该路径存在且被保护"）                                                                                                                                                                                                                                                                                                                                                        |
| compose healthcheck（不成立） | `docker-compose.yml` 的 app 服务确实没有 `healthcheck`，但**不是缺陷**：健康检查来自镜像（`Dockerfile:201` 的 `HEALTHCHECK --interval=30s`），Compose 在服务未声明时原样继承；mongo/redis 要在 compose 里写，是因为它们的官方镜像不带。**反过来补一条是有害的**——compose 侧手写的通常只探 `/health`，会整体顶掉镜像侧"并行探 `/readyz` + `/health`、退出码只取 health"的口径。已补契约测试钉住该形态，compose 该块内写明不要补的理由                                                                                                                                                                                                                                                                                    |
| Node 运行时（修）             | 生产镜像 `node:26.12.0-alpine`，CI 矩阵只有 `22.x/24.x` ⇒ **实际发布到生产的运行时从未被任何 CI 用例执行过**。矩阵加 `26.x`（`[22.x, 24.x, 26.x]`，分别对应 `engines` 下界 / 当前 LTS / 发布基线），并新增 `nodeRuntimeMatrixParity.test.js` 把"镜像主版本 ∈ 矩阵、三处 FROM 一致、`engines` 下界 ∈ 矩阵"钉成闸门。选加矩阵而非降镜像版本：后者要回退一次四天前做过三源核验的升级，前者只增加验证、不改生产行为                                                                                                                                                                                                                                                                                                         |
| 前端 PII（修）                | `web-admin` 的 `currentUser` 落 localStorage 时改为白名单投影（`userId`/`id`/`_id`/`username`/`roles`），不再写入 `email`/`realName`/`phone` 等 PII。httpOnly cookie 的收益此前被明文 PII 抵消。新增 `authPersistenceNoPii.test.js` 6 例：白名单闭合性、登录与 `/auth/me` 两条路径不落 PII、内存态仍保留完整字段、刷新后身份骨架可用、历史脏数据被覆盖                                                                                                                                                                                                                                                                                                                                                                  |
| 5 条"假绿"测试                | 3 条成立并已修（见下），2 条不成立。①`authMiddlewareFailClosedGuards`：三条 `not.toThrow()` 换成可观察后果（库里改 inactive → 失效后必须 401），**变异复测**从"11 例全绿"变为"1 例红"；②`User.test.js`：从"字段存在"改为按**选项值**断言（10 个凭证字段 `select:false`、西里尔同形字 `аdmin` 必须被拒、72 **字节**边界、`status.enum` 与 `USER_STATUS` 同源、`username_ci` 的 collation）；③`mfaReplayGuardMax`：补"先认领再写库"的顺序断言（原断言对换序完全免疫）。**不成立**的 2 条：`mfaControllerOrchestration` 的认领失败分支已在 `mfaReplayGuardMax:118` 覆盖；`securityConfigHandlers` 的读回一致已由 `systemConfigBooleanContract.test.js`（真实 Mongo）覆盖——两处都在文件头写明了分工，避免同一结论被再次提出 |
| 契约测试                      | 新增 `composeAppHealthcheck.test.js`（5 例）、`nodeRuntimeMatrixParity.test.js`（5 例）、`authPersistenceNoPii.test.js`（6 例）；`nginxProxyContract` +1 例、`alertingConfig` +6 例。三处变异实测：`return 404`→`200` 变红、`sum by (instance)`→bare `sum(` 红 2 例、给 app 补 healthcheck 变红 1 例                                                                                                                                                                                                                                                                                                                                                                                                                    |

### WS 绕过探针改为两个单违规场景，并要求拒绝理由可归因（2026-10-24）

> 审计 P2：`scripts/audit-probes/ws-session-bypass.cjs` 只用一个令牌，**同时**带
> 「已吊销会话」与「非白名单 IP」两条违规，判据是"收到任何 `auth-error` 就算拒绝"。
> 于是它只证明了**至少一条**控制在生效：把 `sid` 校验删掉、只留 IP 校验，探针照样
> `exit 0` 报"P0-2 修复在位"。对一个有两条独立控制项的漏洞，"至少一条"不是证据。
> 另外 HTTP 侧只 `console.log` 状态码、从不校验，一个 500 或"因别的原因 401"也会被
> 当成有效对照。

| 项            | 内容                                                                                                                                                                                                                                         |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 场景拆分      | 拆成 `session_revoked`（会话已吊销 + IP 不限制）与 `ip_not_allowed`（会话正常 + IP 不在白名单），每个场景只带一条违规。两个用户、两个会话、两个令牌，`allowedIPs` 与 `sessionStatus` 互斥地只坏一个                                          |
| 理由归因      | `decideVerdict` 新增 `expected` 参数：必须收到 `auth-error` **且文案匹配本场景那条控制**才判 `rejected`。不匹配、或调用方未声明期望 → `inconclusive`（exit 2），不再算通过。帧里没有错误码，文案是唯一通道，故文案改动会让探针变红而不是变绿 |
| HTTP 前置对照 | 改为断言 `status + errorCode`（`401/DEVICE_SESSION_REVOKED`、`403/AUTH_IP_RANGE_DENIED`）。不符即判 `inconclusive`：同一令牌在 HTTP 侧不是因本场景那条规则被拒时，WS 侧的"被拒"无法归因                                                      |
| 服务端观察    | 不再取 `[...clients.values()][0]`（多场景同进程时会拿到上一场景的残留或未认证占位条目），改为按**本场景 userId** 精确匹配；第 5 步同时打印实际收到的下行帧，让证据可见                                                                       |
| 体积          | `makeClients` 的 get/post 合并为一个 `send(method, path, body)`，抵消新增逻辑，维持 `max-lines` 300 以内                                                                                                                                     |
| 测试          | `src/tests/wsProbeVerdict.test.js` 6 例 → 9 例：新增「理由不匹配 ⇒ 不可判定」「两场景理由互不通用（互为反例）」「未声明期望理由 ⇒ 不可判定」，并钉住场景表仍是两个单违规场景                                                                 |
| 可证伪性      | 实测三组：① 两条控制都摘 → `bypass,bypass exit=1`；② **只摘 IP 校验** → `rejected,bypass exit=1`（旧判据在这种情形下会给 exit 0）；③ 恢复后 → `rejected,rejected exit=0`，两场景各自拿到自己的 `auth-error` 帧                               |

### MFA 关闭与恢复码重生成改为条件写（CAS）（2026-10-24）

> 审计 P2：`mfaController.js` 四个状态变更写点里，`mfaEnroll`（:174）与 `mfaEnable`（:273）
> 已是条件写，注释还写着「下发即生效，不得被并发请求静默回收」；而
> `regenerateRecoveryCodes`（:104）与 `mfaDisable`（:368）仍是 `findByIdAndUpdate(_id)`
> **无条件覆盖**。同一份文件里同一条不变量，修了两处漏了两处。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 重生成 CAS | 过滤条件改为 `{_id, mfaEnabled:true, 旧码组全等}`。两次并发重生成携带**相邻窗口**的不同码时两次 `claimTotpWindow` 都会成功（窗口不同不算重放），后到者原会顶掉先到者刚下发的 10 张——调用方已抄走的那组全部作废，而两个响应都宣称"已生成"。空数组分支用 `$in: [[], null]` 覆盖"字段缺失"的历史文档（Mongoose 读时补 `default:[]`，库里没有该字段，直接写 `[]` 会永不命中 ⇒ 这类用户永久 409） |
| 关闭 CAS   | 过滤条件改为 `{_id, mfaEnabled:true, **本次验证过的 mfaSecret**}`。验证是对 `user.mfaSecret` 解密后做的；该字段被并发 enroll/enable 换掉后，无条件写仍会 `mfaEnabled:false + mfaSecret:''`，把本次从未证明过控制权的**新登记**一起清掉，审计还记成"用户关闭 MFA"                                                                                                                             |
| 落空归因   | 两处 CAS 落空后重读一次：已关 → `MFA_NOT_ENABLED`（不再记第二条"成功关闭"审计）、码组被换 → `USER_STATE_CONFLICT`、无 MFA → `MFA_NOT_ENABLED_NO_CODES`。**落空时绝不返回本次生成的码**——它们从未生效                                                                                                                                                                                         |
| 分层       | `mfaDisable` 的第二因子判定（TOTP 优先 / 恢复码兜底）移入 `mfaService.verifyDisableFactor`：这是"什么算验证通过"的领域判定，controller 只该决定"通过后写什么、失败回什么码"。顺带把控制器压回 `max-lines` 300 以内                                                                                                                                                                           |
| 测试       | 新增 `src/tests/controllers/mfaWriteCasConcurrency.test.js`（4 例，**真实 Mongo**，用闸门制造确定性交错而非 sleep）：① 并发重生成恰好一次 200，且成功响应下发的 10 张码**逐张**能对上库内摘要；② 关闭与新登记并发时旧密钥的验证不得清掉新登记；③ 缺 `mfaRecoveryCodes` 字段的历史文档仍可重生成；④ 无并发时两端点照常成功（CAS 不得把正当用户挡在门外）                                      |
| 可证伪性   | 已做变异验证：把两处过滤条件临时改回 `{_id}` 后，用例 ①② 立即变红（实测 `Expected length: 1 / Received length: 2`，两份响应各带一组不同的 10 张码），用例 ③④ 保持绿 —— 说明断言钉的是 CAS 本身，不是环境                                                                                                                                                                                     |

### 迁移脚本参数严格化，且不再在 require 时连库（2026-10-21）

> 审计 P2：`scripts/migrate-pii-encryption.js` 用五个独立 `if` 解析开关，未知参数一律当没看见。
> `--keys-onl`（少一个字母）不会报错，`keysOnly` 保持 false ⇒ 退化为**默认全量模式**
> （加密列 + 回填检索键 + 升级 v1），而操作者以为只补键。同一文件还在模块顶层无条件
> `main()`：任何 `require()` 都会立刻连库并扫描改写 PII。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 参数严格化 | 新增 `scripts/cliFlagPolicy.js`（本仓第四份「开关白名单」实现，抽出来共用）：`parseFlags(argv, allowed)` 把白名单外 token 全部收进 `errors`；建议用**编辑距离 ≤ 2**（全等抹平法对"少一个字母"永不命中，而那正是最危险的误输）。`migrate-pii-encryption.parseArgs(argv)` 返回 `{args, errors}`，`main()` 在**任何副作用之前**以退出码 2 拒绝 |
| 顶层执行   | `main()` 改为 `if (require.main === module)`；`--rotate` 的密钥快照本就在 `main()` 内有等价语句，删掉顶层重复。`parseArgs` / `MODE_FLAGS` / `PII_TARGETS` 导出供测试                                                                                                                                                                        |
| 文档闸     | `runbookSecretSource.test.js` 的 `EXTRA_SECRETS` 补 `run-rollback-drill.js: ['AES_SECRET_KEY']`——快照加密后缺密钥即 exit 2，手册 cron 必须自带来源，否则预发演练静默失败                                                                                                                                                                    |
| 测试       | `src/tests/deploy/cliArgStrictness.test.js` 增用例 19-23（合法全给不误伤 / 拼错必须报错且不猜真 / 位置参数拒绝 / 子进程实测退出码 2 且不连库 / `require` 不触发 `main`）；同时把 `generate-secrets` 的密钥清单钉数补上 `mongo_keyfile`（并行改动新增，钉数按设计要求显式确认）                                                              |

### 举报对话框改为可搜索对象选择器（2026-10-21）

> 缺陷（可用性）：举报对话框把「对象 ID」摆给用户填 24 位 ObjectId，而一线人员拿不到该值
> —— 它只出现在接口响应里，界面上从不显示。记录型举报（用户/设备/报警记录）实际不可用。

| 项       | 内容                                                                                                                                                                                                                                                                     |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 前端控件 | `ReportDialog.vue` 的记录型目标由 ID 输入框改为远程搜索下拉：界面只出现名称/编号，`targetId` 作为选中值随载荷上行、用户不可见。输入防抖 300ms（每次输入只落一条审计）、请求序号防「后发先至」覆盖、选中项在候选刷新后仍保留标签                                          |
| 新端点   | `GET /api/security/report-targets?type=&keyword=`：免权限码（举报对全员开放），候选集按**举报人数据范围**过滤，每类上限 20 条；投影不含 phone/email、报警描述、上报人姓名                                                                                                |
| 同判据   | 新增 `rbac.buildRecordScopeFilter`，与核验侧的 `isRecordInScope` **逐臂同值**（含「本人 `_id` 短路」、department 缺失仍放行本人、`none` 一律 deny）。`buildDataScopeFilter` 在这两处边界上并不等价——直接复用它会出现「下拉里选不到自己」或「选得到却提交 403」           |
| 限流     | 候选查询消耗 `authenticate` 内的账号级 userLimiter（200/15min），与举报提交的独立 20 次写配额分开：搜索不会吃掉提交配额（否则 429 文案会指向「提交过于频繁」，根因不可见）                                                                                               |
| 文档     | `src/docs/generate.js` 补 `/api/security/report-targets` 并重生成产物；端点经 `securityRoutes` 直接注册（不走 `router.use` 子挂载——openapiSync 的采集对子挂载是盲区，塞进去等于绕过文档门禁）                                                                            |
| 测试     | 新增 `src/tests/security/reportTargetCandidates.test.js`（16 例：免权限码可达 / 范围一致性 / **候选与提交核验同值** / 最小投影 / 参数边界 / 20 条上限与独立配额）；`web-admin/src/tests/components/reportDialog.test.js` 重写为 13 例，含「界面上不出现对象 ID」回归锚点 |

### 审计 WAL 裁剪按持久化承诺分级 + 回滚演练备份加密（2026-10-21）

> 按 `deliverables/七维审计终稿-核验版-2026-10-21.md` 的两项 P1 整改。
> 旧结论「outbox 先落 WAL 名不副实」已在工作树中修复（`auditOutbox.js` 已 `await appendLineDurable` 并 fsync），
> 但**裁剪侧**仍会把这些已 fsync 的行按位置丢出主 WAL，本节点修的是这一半。

| 项           | 内容                                                                                                                                                                                                                                                                                                                                                                    |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WAL 裁剪分级 | `auditOutbox.js` 写出的行带 `__walDurable`；`auditWalCap.enforceWalLimit` 改为**普通行优先丢、durable 行默认不丢**。普通行不足时记 `walDurableTrimRefusals` 并停手（WAL 继续超限，这是有意取舍），只有显式 `AUDIT_WAL_ALLOW_DURABLE_TRIM=true` 才裁 durable 并计 `walDurableDropped`。理由：`.discarded` 永不回灌，按位置裁剪等于把「已回成功」改成「落盘但永久不入库」 |
| 重放剥离     | `auditBufferWal.stampReplaySeqs` 在交给缓冲前删除 `__walDurable`（保留 `__walSeq`），避免 WAL 记账字段进入 Mongo 文档；回写补号行在删除**之前**序列化，否则会丢标记                                                                                                                                                                                                     |
| 面板投影     | `securityController/overview.js` 的 `auditLoss` 新增两项；`AuditLogView.vue` 的 `auditLossTotal` 计入 `walDurableDropped`（承诺缺失），`walDurableTrimRefusals` 只进明细（此刻尚未丢记录，处置方向是扩容而非取证）                                                                                                                                                      |
| 演练备份加密 | `run-rollback-drill.js` 由明文 gzip 改为 gzip 后 AES-256-GCM（魔数 `FSMSBK1`，密钥由 `AES_SECRET_KEY` 派生），缺密钥直接退出、不退回明文；`.discarded` 同族：`restoreCollection` 按魔数识别，改造前的明文快照仍可回灌但显式告警                                                                                                                                         |
| 可观测性     | `metricsAuditDrops` 新增 reason `wal_durable_lost`（由 `auditWalCap` 在显式开关裁掉 durable 行时上报，自动被既有 `AuditRecordsDropped` critical 规则覆盖）；新增计数器 `audit_wal_durable_trim_refusals_total` 与告警 `AuditWalTrimRefused`（warning）——「拒绝裁剪」意味着 WAL 无界增长，必须在写满磁盘前可见                                                           |
| 文档对齐     | `deployment/backup-encryption.md` 删除「单人拿不到完整链」这一与设计矛盾的断言，改为「默认无口令私钥下该控制不成立」并给出两条可兑现路径（口令分离 / 人员分离）；`deployment/rollback-drill.md` 的 cron 示例补 `AES_SECRET_KEY_FILE`，并新增第 5 条纪律（缺密钥退出码 2 是 fail-closed，不是配置错误）                                                                  |
| 测试         | 新增 `src/tests/services/auditWalDurableTrim.test.js`（5 例：durable 全留 / 拒绝裁剪 / 显式放开 / 全 durable 不动文件 / 重放剥字段，含两条 Prometheus 上报断言）；`rollbackDrillRestoreVerification.test.js` 增「归档必须带 FSMSBK1 魔数且不得同时留下明文 .ndjson.gz」与 `manifest.encrypted` 断言；`auditDropMetrics.test.js` 的 reason 闭合集合断言扩到五项          |

### 搜索面板新增可见关闭按钮、隐藏 ESC 提示（2026-10-21）

> 全屏态下 ESC 先被浏览器用于退出全屏（`keydown` 的 `preventDefault` 拦不住），把 ESC 当关闭卖点展示会误导；改为「按钮是可见入口，ESC 静默保留」。

| 项         | 内容                                                                                                                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 组件行为   | `web-admin/src/components/SearchPalette.vue` 输入行右侧新增 `.search-palette__close` 按钮（`aria-label`/`title` 取 `common.close`，纳入既有 Tab 焦点陷阱）。ESC、遮罩点击、⌘K/Ctrl+K 再次按下仍照旧可关闭，只是 ESC 不再出现在 UI 上 |
| 提示与词表 | 页脚去掉 `ESC 关闭` 提示、输入行去掉 ESC 键帽（页脚只剩 ↑↓ 与 ↵）；随之无引用的 `common.searchHintClose` 从中英词表删除（两语言同步，键位仍对齐）                                                                                    |
| 测试       | `web-admin/src/tests/components/searchPalette.test.js` 新增「关闭按钮可关」与「UI 无 ESC 字样（kbd 与页脚）」断言；ESC 关闭与焦点归还用例保持原契约                                                                                  |

### 七维审计 2026-10-20：审计链检查点 / 固定睡眠门禁 / 运维关键路径 E2E

> 按 `deliverables/七维深度审计报告-2026-10-20.md` 整改。本节只记录三项中危的**结构性**修复；
> 其余按报告编号分散落在各模块的修复不在此逐条复述。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S-8 审计链外部锚 | 新增 `scripts/audit-chain-checkpoint.js` 与 `src/services/auditChainCheckpoint.js`：把链头与记录数写成 HMAC 签名的 JSONL 检查点，校验时逐行验签并核对锚点。可检出分支插入 / 链头替换 / 锚点前截断 / 检查点文件被改；**残余边界**（锚点与库同机、锚点后先加后删）已在 `docs/architecture.md` §7 与 `docs/threat-model.md` 明示，不宣称完整防篡改                                                                                                                                             |
| T-2 固定睡眠     | 新增 `src/tests/helpers/waitFor.js`（条件轮询）与 `src/tests/ci/noFixedSleepRatchet.test.js`：固定 `setTimeout` 收进棘轮，新增一处即红；真实网络/进程等待改走健康检查与事件，定时器逻辑用 fake timers                                                                                                                                                                                                                                                                                       |
| T-1 运维 E2E     | 新增 `scripts/ops-e2e.js` 与 `scripts/ops-e2e/journeys/*` 四条旅程：告警投递探针、部署失败→自动回滚、备份→恢复→校验、跨部门越权。各自独立子进程 + 内存 Mongo + 随机端口 + 本地假 Alertmanager；CI 的 `e2e` job 新增 `npm run test:ops-e2e` 并登记进 `ciGateWiring`。浏览器 no-skip 门禁（`MIN_PASSED=32`、`skipped==0`）未改动                                                                                                                                                              |
| O-5 部署演练     | `scripts/deployCommands.js` 抽出全部外发命令的 argv 构造（部署脚本不再自带命令字面量），`--dry-run` 打印与实际执行同源的真实命令；新增 `src/tests/deploy/deployCommands.test.js`。首次 `dry_run=true` 真实演练的步骤与留证表登记在 `deployment/deploy-workflow-rehearsal.md`——**真实 run 尚未执行**（需预发环境），未留证前 deploy.yml 的「未验证声明」保留。T-4 的预发定期演练 cron 见 `deployment/rollback-drill.md` §5.5；S-9 的 CI 开发机隔离口径见 `docs/security-dependency-watch.md` |
| 冒烟测试修正     | I-01 改为令牌只经 httpOnly cookie 下发后，`scripts/e2e-smoke.js` 仍从响应体取 `data.token`，导致 9 步 401（CI 必红）。改为从 `Set-Cookie` 取 `access_token`，继续用 Bearer 路径覆盖 `authenticate`                                                                                                                                                                                                                                                                                          |

### lint 棘轮批 1–3c：大文件目录化拆分与阈值重设（2026-10-18/19）

> 本轮是**纯搬家 + 度量收敛**：`security.js`、`authService.js`、`websocketService.js`、
> `authController.js`、`userController.js`、`securityController.js`、`sharedCache.js`、`initData.js`
> 按职责拆入同名目录（入口文件保留原有导出形态），复杂度与函数体积告警逐批下降。
> 业务语义未变；覆盖率/体积棘轮的键随路径迁移同步重设，并有 `coverageGateWiring` 与
> 分层棘轮测试守住“拆分后门槛没有被悄悄放宽”。针对拆分中暴露的 `max-lines` 最后若干条，
> 批 3a/3c 只做内容保持式迁移，未借机改行为。

### 响应头加固：X-XSS-Protection 测试守护 + Trusted Types 灰度 + CORP/Referrer-Policy 口径统一到 same-origin（2026-10-15 · 按 `deliverables/安全加固待办清单-2026-10-15.md` 的 P1+P2 逐项落地）

> 清单 P1（Trusted Types report-only）与 P2（COEP 决策记录 / CORP / Referrer-Policy）四项全部落地；P3 的 CSRF 双保险按清单自陈「不做也不构成缺口；仅在明确有子域/多应用共站时做」未做（本仓 nginx 单 `server_name`、无子域前端，已复核）。
>
> 落地过程中发现**三处清单本身没写准的地方**，一并记录：
> ① 清单给的 Trusted Types 写法（`useDefaults:false` + 只写 `require-trusted-types-for`）在 helmet 7.2.0 下**构造期直接抛错**——`normalizeDirectives()` 要求「必须有 default-src，除非显式 `dangerouslyDisableDefaultSrc`」，且该检查对 `reportOnly` 一视同仁（回源 `node_modules/helmet/index.cjs:90-92`，已实测复现）。照抄会让整个 app 起不来。已改为显式摘掉 `default-src`，下发结果就是单条 `require-trusted-types-for 'script'`，不会把 helmet 的全套默认指令拖进灰度策略制造噪音。
> ② Referrer-Policy 实际有**五份**副本，清单只列了 4 处，漏了 `web-admin/vite.config.js` 的 `buildSecurityHeaders`（vite dev/preview 这条托管路径）。五份已一并改，并由新用例钉住取值一致。
> ③ 顺带发现 `src/tests/controllers/roleControllerHierarchyGuards.test.js` 中「角色/权限审计全部由全局中间件派生（`utils/auditMeta.js:85-103` → `middleware/security.js:648`；挂载 `src/app.js:325-326`）」这句的**三个锚点全部指错位置**（其中 `security.js:648` 在 HEAD 就已落在 `checkIPBlacklist` 的 `IP_BLOCKED` 行，内容保持式迁移只会把它一路带下来）。已按真实落点更正为派生定义 / 派生调用 / 中间件挂载。

| 项                         | 内容                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trusted Types 灰度（P1）   | `src/middleware/security.js` 新增独立中间件 `trustedTypesReportOnly`，挂到 `applyResponseHardening()` 的 `reportingEndpoints` 之后。只写 `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'`，与主 CSP 头名不同、互不覆盖；`CSP_REPORT_ENABLED=true` 时附带 `report-uri`/`report-to`（复用既有 `/csp-report` 与 `csp-endpoint`），关闭时一条多余指令都不下发。**只上报不阻断**，对现有行为零影响 |
| COEP 决策记录（P2）        | `crossOriginEmbedderPolicy: false` 处补注释：为何关闭（无跨源隔离需求；开启会拦掉 Swagger UI 自注入资源、Google Fonts、导出 `blob:` 下载）、什么条件下应重新评估（含「`credentialless` 不是免费开关」这条反面证据）。此前全仓无任何 COEP 决策留痕                                                                                                                                                                      |
| CORP 收紧（P2）            | `crossOriginResourcePolicy` 由 `same-site` → `same-origin`，与 nginx 三份副本、`web-admin/vite.config.js` 及 helmet 7 默认值（`index.cjs:168`）对齐。同源反代拓扑下前后端同源，对同源 fetch 无影响                                                                                                                                                                                                                     |
| Referrer-Policy 收紧（P2） | 5 处由 `strict-origin-when-cross-origin` → `same-origin`：`src/middleware/security.js:139`、`deployment/nginx.conf.example:108`/`:175`/`:217`、`web-admin/vite.config.js:134`。前置确认已实测：跨源子资源仅 Google Fonts（不依赖 Referer）、全仓无外部跳转/防盗链/外链来源分析、后端唯一 Referer 消费点是 `originCheck.js` 的 Origin 缺失回退（同源请求照常携带 Referer）                                              |
| X-XSS-Protection 守护      | 新增 `src/tests/middleware/xssProtectionHeader.test.js`（5 例）钉住「下发且精确等于 `'0'`」与「恰好一个头」——该头此前全仓无断言，误改为 `false`（= 完全不设该头）不会有任何红灯。变异实测：`xssFilter: false` ⇒ 前 4 条转红。同时更正 `security.js` 中语义写反的旧注释（`xssFilter: true` 的语义本就是下发 `0`，照字面读会以为这是"开启保护"）                                                                         |
| 锚点同步                   | `security.js` 净 +82 行 ⇒ 指向其 123 行之后的 **9 处**锚点逐条迁移（`:608`→`:685`、`:666`→`:743`、`:686-690`→`:763-767`），涉及 5 个源码/文档 + 4 个测试文件；`git grep` 核验旧值 0 残留、新值一一对应，`commentAnchorFreshness` + `bareAnchorAttribution` 全绿                                                                                                                                                        |
| 新用例                     | 新增 `src/tests/middleware/securityHeaderPolicyHardening.test.js`（11 例）：report-only 头取值 / 不污染强制 CSP / 上报开关两态 / CORP 与 Referrer-Policy 五份副本取值一致 + 两类可证伪反证。变异实测：摘掉 `app.use(trustedTypesReportOnly)` ⇒ 4 条转红；CORP 回退 `same-site` ⇒ 2 条转红（断言有牙，非空洞）                                                                                                          |
| 门禁联动                   | 两个新用例文件均已 `git add`：`testTreePurity` 要求 `src/tests/**` 下不得存在未跟踪的 `*.test.js`（放在那里 `testMatch` 一定会执行它）                                                                                                                                                                                                                                                                                 |

### 修 CI 真红：审计 action 对账闸补登 roleController updated 广播载荷（2026-10-11 · 678e211 漏登）

> 678e211 给 updateRole 补 role-updated 广播时加了 action: 'updated' 载荷字段，但未同步 auditActionReconciliation 的 NOT_AUDIT_ACTION_LITERALS 排除清单（该闸要求每个 action 字面量要么有写入形态认领、要么逐条登记家族与出处；同文件 created/deleted 两条广播载荷均在册）。f4afd88 的 CI 止步于 lint ratchet 未跑到该步、f6bf4e7 早于 678e211，故此前未暴露。按既有机制补登（ws 家族，tally 5→6），并改准两处被 678e211 移动而过时的行号出处。

### 登录加密轨道安全收口七项（2026-10-10 · 外部审计 8 项发现逐项处置：限流漏配 / 对客预言机 / 信封不绑用途 / 公钥无钉扎 / strict 无生产收口 / PFS 未文档化 / dev 链存量 CVE）

> 对登录口令 ECDH 密文轨（ADR-001）的一轮外部审计逐项修复。另有两项审计结论经核对已过期：nginx 边层 Permissions-Policy 与 transportSecurity 的 HTTPS 断言在受审版本前已落地，本次仅复核确认、无改动。

| 项                             | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/mfa/enable` 补限流           | enroll/disable/recovery-codes 都有 strictLimiter，唯独「确认开启」那步漏配；已补齐。危害有界（爆破只能加速攻击者给自己的账户开 MFA），属一致性收口                                                                                                                                                                                                                                                                                                                |
| 登录 ENC_INVALID 对客统一      | 解密失败原映射 400 `AUTH_ENCRYPTED_CREDENTIAL_INVALID`，与 `AUTH_INVALID_CREDENTIALS` 可区分 ⇒ nonce 消费/时间窗弱预言机，与 loginCipher「失败原因不回传客户端做区分」的设计意图相悖。登录端点改为统一 401 `AUTH_INVALID_CREDENTIALS`；register/changePassword/mfaDisable/userCreate **保留**独立错误码——那些端点输入由攻击者自控（注册新用户、改自己口令），无预言机价值，且前端公钥缓存自愈依赖该码触发（自愈判定改由 `web-admin/src/utils/api.js` 按端点承担） |
| 信封绑定端点用途（AAD）        | 载荷原本只有 `{p, ts, nonce}`：一条**从未到达服务端**的捕获信封（提交失败/被丢弃，密文已上线）可在 ±5 分钟窗口内提交到任何接收密文口令的端点。新增 `CREDENTIAL_AAD`（login / register / password:current / password:new / mfa:disable / user:create）纳入 GCM additionalData，跨端点信封解密失败；刻意**不**绑用户名——跨用户重放会在口令比对处自然 401，绑用户名零收益却让每个前端表单多一个必须逐字一致的条件                                                    |
| 公钥指纹钉扎（防主动 MITM）    | 公钥经同一信道下发、不固定不验签，主动中间人替换公钥即可解密再转发——「截获密文无法恢复口令」只对被动窃听成立。构建期把公钥 SHA-256 指纹钉进前端包（`VITE_LOGIN_PUBLIC_KEY_SHA256`，≥16 位 hex 前缀），`ensurePublicKey` 对**取到的 PEM** 自行计算并比对，不符抛 `PUBLIC_KEY_PIN_MISMATCH` 且不得降级明文；指纹取自服务端启动日志的 `publicKeySha256` 字段（公钥指纹是公开信息）                                                                                   |
| strict 未开的启动期告警        | 新增 `src/config/loginEncryptGuard.js`：`LOGIN_ENCRYPT_STRICT` 未开时 loud warning + `incSecurityAlert('login_encrypt_strict_disabled', medium)`（已登记进 `failOpenSites` 台账）。**刻意不阻断启动**：strict 关死明文轨的前提是浏览器有 WebCrypto，而纯 HTTP 内网形态拿不到——致命闸会拦死一种合法部署形态；收口方式是「可见」而非「拒绝」                                                                                                                        |
| PFS 与轮换文档化               | `SECURITY.md` 新增「登录口令加密的密钥管理」：静态私钥 = 无前向保密，泄露按**口令泄露**处置（轮换私钥 + 强制全体改密），不是单纯换钥；轮换须与前端钉扎包一起发布（只换服务端私钥 ⇒ 全部登录被 `PUBLIC_KEY_PIN_MISMATCH` 阻断）。ADR-001 补三条决策记录（PFS 局限 / 钉扎收口 / AAD 绑定与 ENC_INVALID 合并的理由）；`deployment/secret-rotation.md` 补钉扎联动段                                                                                                   |
| dev 链存量 CVE（仅记录，未动） | `npm audit`：生产依赖 0 漏洞，35 个（5 moderate / 30 high）全在 jest 开发链（js-yaml→argparse→sprintf-js 等，经 istanbul 传入）。`npm audit fix` 非破坏性无效；`--force` 仅升 jest@30.5.2（breaking 大版本，559 个套件重度依赖 jest 29 配置与全局 setup）。CI 安全门禁为 `--omit=dev` 口径（生产 0 漏洞即过）。**决策：本次不升级**，建议维护窗口单独做 jest 29→30 并全量验证                                                                                     |

### 补装 login_ecdh_private_key 并修正 loginCipher 的前向保密表述（2026-10-10 · compose 挂了 10 个 secret 唯独漏了登录 ECDH 私钥，轮换手册里这把钥匙的流程从未生效）

> `src/config/secrets.js` 的 `FILE_BACKED_SECRETS` 早已支持 `LOGIN_ECDH_PRIVATE_KEY_FILE`，`scripts/generate-secrets.js` 也一直产出 `login_ecdh_private_key`（P-256 PEM），但 `docker-compose.yml` 从未装配它：app 的 `environment:` 没有对应 `_FILE` 指针，app 服务与顶层 `secrets:` 也没有对应定义。后果是生产部署下服务每次启动惰性生成临时密钥对——`deployment/secret-rotation.md` 里这把钥匙的轮换流程从不生效，且重启前的历史登录密文永久无法解密（做流量取证须在重启前完成）。另修正 `src/utils/loginCipher.js` 头注释：「截获密文的攻击者无法恢复口令」仅在私钥不泄露时成立，静态私钥 + 历史密文 = 明文（无前向保密），注释已补上前提与两种模式的取舍。

| 项           | 内容                                                                                                                                                                                                                                                                                               |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| compose 装配 | app `environment:` 补 `LOGIN_ECDH_PRIVATE_KEY_FILE=/run/secrets/login_ecdh_private_key`；app 服务与顶层 `secrets:` 补 `login_ecdh_private_key`（`file: ./secrets/login_ecdh_private_key`）；头注释手抄清单补 `openssl genpkey` 一条（原「首选」注释里"本清单遗漏"的说法随之失效）                  |
| 注释修正     | `src/utils/loginCipher.js` 头注释把「无法恢复口令」改为带前提的表述：信封自带临时公钥坐标，持静态私钥即可解密任一历史密文（无前向保密）；临时密钥对模式反之——重启前的密文永久不可解密                                                                                                              |
| 契约测试     | `composeProductionContract.test.js`：新变量进 ENV_KEYS 与 fileMap，`/run/secrets/login_ecdh_private_key` 的替身改为真实 EC PEM；新增「文件注入密钥装配三方一致」用例（environment `*_FILE` ↔ app secrets 清单 ↔ 顶层 secrets，且轮换手册点名的文件注入密钥必须全部在装），两类漏法各有一条反向自证 |
| 手册         | `deployment/secret-rotation.md` 的 `LOGIN_ECDH_PRIVATE_KEY` 行后补机制段：经 secret 文件注入，换钥＝随批替换文件后重启；未配置时重启前的密文永久不可解密                                                                                                                                           |

### 下拉浮层边角打磨：表面只画一层（2026-10-09 · 双层表面叠出双边框与错角，边角不圆润）

> 顶栏用户菜单与语言/主题下拉的浮层边角发毛、不圆润。复现定位到根因是**两层表面**：Element Plus 把浮层表面（底色/描边/阴影）画在外壳 .el-dropdown__popper.el-popper 上，还带着 base 的 5px 11px 内边距与 global.css 的 10px 圆角；pple-refine.css 又把表面画在内层 .el-dropdown-menu（12px 圆角 + 1px 描边 + 6px 内边距）。两层半径、描边、内边距全不一致，圆角处叠出双边框与错角。暗色还多一层脱节：html.dark .el-popper 的 --xf-gray-50 实底框围着半透明菜单。

| 项       | 内容                                                                                                                                                                                                               |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 外壳透明 | .el-dropdown__popper.el-popper 的 padding/background/border/box-shadow 全部清空（带 !important），表面只由 .el-dropdown-menu 画一层；箭头是外壳子元素、::before 自带配色，位置不受影响                             |
| 暗色再盖 | html.dark .el-popper 的实底/描边两条声明带 !important 且特异性 (0,2,1) 压过上面的 (0,2,0)，用 html.dark .el-dropdown__popper.el-popper 对 ackground/border 再盖一次，否则暗色菜单四周围一圈 --xf-gray-50 实底框    |
| 箭头同源 | 亮色下拉箭头描边改为跟随菜单的 --xf-border-color（EP 默认取 --el-border-color-light #e4e7ed，箭头根部露一截异色），底色取 EP 给菜单的 --el-bg-color-overlay；依旧不写 !important——placement 的透明边规则必须继续赢 |
| 不变量   | web-admin/src/tests/styles/tooltipTheme.test.js 补两例：外壳透明四件套 + 暗色再盖两条；亮色箭头与菜单描边同源、底色同源 EP overlay，并进「不能带 !important」循环                                                  |

### fail-open 降级补信号 + 持续型告警 + 站点台账门禁（2026-10-09 · 同一个降级动作被复刻 3 份，且全都没有可告警信号）

> 本仓早有明文纪律（`middleware/security.js:763-767`、`middleware/rateLimitStore.js:53-56`、
> `services/websocketService.js:723-725` 三处自陈）：「fail-open 放行必须有显式可观测信号——
> 否则『DB 挂了 + 全站裸奔』只有一条 error 日志可循」「降级态只写日志等于没有可告警信号——
> `grep 日志` 不是运维动作」。**验证码开关这条链没做到**：`isLoginCaptchaEnabled` /
> `isRegisterCaptchaEnabled` 自身没有 try/catch，真正做降级的是调用点，而同一段 try/catch
> 被复刻了 **3 份**（`authService.registerUser`、`authService.resolveLoginPassword`、
> `authController.getCaptchaStatus`），三份都是空 catch、都不发信号。

| 项          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 收口        | 新增 `SystemConfig.captchaSwitch(kind)`：静态默认兜底 + 降级信号只在这一处发生；3 个调用点改为调它，各自手写的 try/catch 删除                                                                                                                                                                                                                                                                                              |
| 新信号      | `captcha_switch_db_fallback`（level `medium`）——验证码只是登录链**前置层**，降级后凭据型限流与爆破检测仍在，故与 `ip_blacklist_failopen` 的 `high` 不同级                                                                                                                                                                                                                                                                  |
| 第二个信号  | `captcha_active_bound_lost`（level `high`）：`captchaService.generate` 在「Redis 已启用但活跃数读取失败」时不设上限放行。**真正的放行点在 `active === null` 而非 `catch`**——`sharedCache.incrWithTtl` 两条降级路径都返回 `null`、从不抛，原先那个 catch 不可达、也永远发不出信号                                                                                                                                           |
| 告警        | 新增 `SecurityFailOpenSustained`（`for: 10m`，critical）。**按 type 分开判、不跨类型求和**：求和会掺进启动期恒正项（`immutableConfigGuard`/`legacyCbcGuard` 进程启动即写 `security_alerts_total`），既稀释真实突发、又让 crash loop 冒充安全事件；**用持续型而非速率型**：`SecurityAlertBurst` 是「10 分钟 ≥10 条」，而 fail-open 的危险形态恰是低速而持续，速率型可以永远不达标                                           |
| 台账 + 门禁 | 新增 `constants/failOpenSites.js`（5 个 fail-open 站点 + 10 个其它信号 + 1 个转发点，逐条声明 `direction/trigger/effect/why/tightening`）与 `tests/ci/failOpenLedgerGate.test.js`（8 例）：代码里的静态站点 ⇄ 台账条目双向闭合；每条 type 必须被持续型规则覆盖（**登记信号 ≠ 接上告警**）；反向也拦（规则点名不存在的 type 要红）                                                                                          |
| 刻意不做    | **不自动收紧**。把 fail-open 自动翻成 fail-closed 会把「保密性降级」转成「可用性事故」，且恰好发生在系统已经不健康时（黑名单 fail-closed = 库挂时全站请求无法验证；验证码 fail-closed = 没人能登录）。是否收紧是产品决策，不是告警规则能代做的                                                                                                                                                                             |
| 用例        | 新增 `tests/services/failOpenSignals.test.js`（11 例，含反向对照：两个 type 必须真能渲染进 `formatPrometheus()`）；`authControllerOutcomes.test.js` 的两条 `getCaptchaStatus` 重写到新接缝并**补前提自证**（断言真的调了 `captchaSwitch`）——原写法在该文件的 `../../models` 部分 mock 下会因 `captchaSwitch` 是 `undefined` 抛错、被兜底网吞掉而"通过"，等于在断言静态默认值                                               |
| 文档        | `README.md` 新增「开发/预览服务器的暴露边界」：dev 与 preview **都**绑 `0.0.0.0`，dev 下发**未打包源码**而 `src/**` 不在敏感文件黑名单内 ⇒ 禁止把 3001 发布到公网；`docs/threat-model.md` §3 增第 5 条（明确标注「仅开发期、不构成生产面」）；`docs/incident-response.md` §2 增「护栏失效信号」一条（该规则触发时，「没看到拦截」不能当作「没被攻击」的证据）。顺带修正 `README.md` 已过期的「4 条内置告警」（实为 13 条） |
| 锚点迁移    | 本轮删行使 `authService.js` -7 行、`authController.js` +13 行，全仓 **32 处**注释锚点随行号迁移（逐条按「迁移后该行内容 == 迁移前该行在 HEAD 的内容」核验）；`bareAnchorAttribution.test.js` 的回指台账两处坐标同步随迁。另修正 `statsAnomalyScope.test.js` 一处**本就指错**的锚点（写 `securityController.js:284`，而 `getSecurityStats` 实为 `:317`）                                                                    |

### 顶栏入口提示统一走 Element Plus 浮层 + 浮层箭头主题适配（2026-10-09 · 语言/主题图标此前挂的是浏览器原生 title）

> 顶栏语言/主题入口把提示写在 `el-icon` 的 `:title` 上，走浏览器原生提示——样式、字号、圆角与出现时机全由浏览器决定，和搜索/刷新/全屏的 `el-tooltip` 浮层是两套观感。本批把两处统一成 `el-tooltip`；顺着这条线查浮层配色时，又发现 Element Plus 的箭头是**独立元素**、取的是另一套变量，仓库只改了浮层底色，亮/暗两个主题下尖角都露着异色（暗色下拉菜单甚至挂一块异色三角）。

| 项       | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 统一提示 | `web-admin/src/layout/index.vue`：语言/主题的 `el-icon` 去掉 `:title`，外面套 `el-tooltip`（`placement="bottom"`，与搜索/刷新同规格）。**不能**反过来把 tooltip 塞进 `el-dropdown` 里——`el-tooltip` 的根是 `ElPopper`（`inheritAttrs: false`），dropdown 经 `ElOnlyChild` 下发的 `role`/`tabindex`/`id`/`aria-*` 与 forward-ref 会在那一层被吃掉，下拉直接点不开（实测：菜单浮层不再出现）                                                                                                                                                                                                                                                                                                                                       |
| 防叠放   | 下拉展开期间用 `:disabled` 收起提示：菜单浮层与提示浮层同位叠放会互相盖住，而展开时指针停在图标上不产生 `mouseleave`，提示不会自行消失。状态由 `@visible-change` 回写，两个入口互斥共用一个 ref                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 箭头同色 | `apple-refine.css` 新增四条 `.el-popper__arrow::before` 规则（亮色 tooltip / 暗色 tooltip / 暗色下拉菜单 / 暗色 `.is-light`，末条见「续修」），底色与描边逐一对齐浮层。箭头规则**不能**加 `!important`：朝浮层的那两条边由 EP 的 placement 规则置 `transparent`，那条规则带 `!important` 必须继续赢，否则旋转 45° 的方块会露出实心方角                                                                                                                                                                                                                                                                                                                                                                                           |
| 暗色描边 | `html.dark .el-popper.is-dark` 补上自己的 `border`：原先不写，暗色边悄悄吃亮色那条 `.el-popper.is-dark` 的边（两条特异性相同、后者在源流里更晚），改亮色配色会把暗色一起带跑                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 用例     | `web-admin/src/tests/layout/layout.test.js`：定位辅助从「按 title 找图标」改成文件原有的图标 path oracle（title 已不存在）；新增 `布局 · 顶栏入口悬停提示` 四条——顶栏图标一律不留原生 title、语言/主题悬停出 EP 浮层且文案走 i18n、下拉展开期间只剩菜单浮层。`web-admin/src/tests/styles/tooltipTheme.test.js`：读 CSS 源码比对「箭头与浮层同色」+ 箭头规则不带 `!important`，两条变异（箭头改回白、箭头加 `!important`）均能测红；续修新增两例——「暗色 date-picker 箭头与 `html.dark .el-popper` 实底同色」（表面规则在 dark.css，测试改读两个样式文件）与「`.is-light` 规则必须 `:not(.el-dropdown__popper)`」（特异性 (0,5,2) 高于下拉箭头规则 (0,3,2)，不排除会把半透明下拉箭头打成实底），第三种变异（删掉 `:not`）同样测红 |
| 续修     | 暗色 `.is-light` 浮层（`el-date-picker`，经 `ElTooltip effect="light"` 带 `is-light`）的箭头补上 `--xf-gray-50`/`--xf-border-color`：EP 的 `.is-light` 箭头取 `--el-popper-bg-color-light`（=`--el-bg-color-overlay`，EP 暗色 `#1d1e1f` 中性灰）与 `--el-border-color-light`（`#414243`），与 `#0f172a` 表面对不上。选择器必须 `:not(.el-dropdown__popper)`：下拉菜单表面是半透明 `rgba(30,41,59,.95)`，而 `.is-light` 规则特异性更高，不排除会把下拉箭头一起打成实底。`el-select` 浮层不渲染箭头，无需处理                                                                                                                                                                                                                      |

### 弱口令黑名单：匹配器口径修复 + 词干表扩充（2026-10-09 · 原 40 条里 24 条永远命中不了）

> 本批**不改依赖、不引入外部服务**。改的是「清单里的条目到底能不能被命中」。
> 旧实现是 40 条**口令字面量**，而归一化只做「末尾 ≥4 位数字收敛为 3 位」且**只归一化
> 口令侧**——两侧口径不一致的后果：实测 **24 条永远命中不了**，有效字典只有 **16 个词干**，
> 而文件看起来有 40 条。`helpers.test.js` 断言 `isBreachedPassword('admin@123') === true`
> 也是误导性的：生产路径上黑名单排在长度/复杂度之后，9 位口令根本走不到黑名单。

| 项       | 内容                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因     | **匹配器与数据口径不一致，不是数据错**。清单里 `passw0rd!` / `p@ssw0rd` / `1qaz@wsx` / `abcd1234!` 这种写法本身就说明作者意图是「按词干匹配」；而旧匹配器要求字面量全等。死条目分两族：①8~11 位条目先被长度规则拒掉；②以 ≥4 位数字结尾的条目永远不等于任何口令的归一化结果                                                       |
| 改法     | 表改为**词干**（`constants/breachedPasswords.js`，40 条字面量 → 123 条词干）；归一化只保留一份且在口令侧：小写 → 去所有非字母数字 → 去末尾连续数字。两侧口径因此不可能再漂移                                                                                                                                                     |
| 不变量   | 每个词干至少含 2 个字母。这是**必要条件**：归一化不重排字母，故口令的字母序列（小写）必须等于词干的字母序列，而策略要求同时含大写与小写 ⇒ 字母数 <2 的词干在策略下不可达                                                                                                                                                         |
| 覆盖变化 | 有效词干 16 → 123（**+107**）；`Passw0rd!1234`、`P@ssw0rd1234!`、`Abcd1234!5678`、`1Qaz@Wsx1234!` 等由漏变拦；精度用例同时钉住 12 条强口令不被误伤（`SunshineRain99!` 归一化后是 `sunshinerain`，不是词干）                                                                                                                      |
| 用例     | 新增 `src/tests/utils/breachedPasswordMatcher.test.js`（176 例）：逐条为 123 个词干构造「除黑名单外无懈可击」的反例并断言被拦；表内条目必须已是词干（混入字面量即红）；回归指纹；精度；边界；原 16 条不回退                                                                                                                      |
| 失败策略 | 本批**不接** HIBP。若将来要接，失败策略**已预先拍板**：**fail-open + 指标 + 启动日志告警**，且必须带超时与缓存——不让第三方可用性拖垮改密链路                                                                                                                                                                                     |
| 文档     | `docs/mlps2-controls.md` 的 G8 证据补上「清单规模 + 用例文件」，并新增一段**如实边界声明**（是高频词干表，不是泄露库；长尾覆盖不了）；`breachedPasswords.js` 文件头修正「以隐私为由拒绝 HIBP」的**不完整推论**（原话本身准确：range API 确实只收 SHA-1 前 5 位；但真正有分量的理由是多一个运行时外部依赖及其失败策略，原文没写） |

三处测试夹具注释同步更新（`authCookies.test.js` / `changePasswordTypeGuard.test.js` /
`sessionManagement.test.js`）：导出名 `BREACHED_PASSWORDS` → `BREACHED_PASSWORD_STEMS`，
且 `Test@12345 归一化后为 test@123` 的解释已不成立（现在一步归一化成 `test`）。
三处夹具口令均经 `deliverables/probe-matcher-behavior.js` 复核为新口径下的安全值。

### IP 归属地英文化（2026-10-09 · 私网/环回地址的 `location` 从中文文案改为稳定码）

> 缺陷形状与 `constants/securitySuggestions.js` 那次同族：**后端把文案拼死，前端就永远翻不动**。
> `ipLocationService` 把私网/环回地址收敛成中文两字「内网」直接下发，而三个消费面
> （会话管理、审计日志列表 + 详情弹窗、IP 黑白名单）都是 `· {{ row.location }}` 原样渲染——
> 管理员把界面切到 en-US，IP 旁边那一格仍是中文。公网 IP 的归属地是 ip2region 数据文本
> （「中国·广东省·深圳市·电信」），不在本次范围：数据侧本地化是另一个议题。

| 项     | 内容                                                                                                                                                                                                                                                                                                                                             |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 根因   | 展示文本由后端拼好并焊进 API 响应：私网这一支既非数据也非用户输入，而是**服务层自己写死的中文**，vue-i18n 对已定型的字符串无从下手                                                                                                                                                                                                               |
| 修法   | 沿用仓内既有口径（`utils/labelMaps.js` 的 DEVICE_TYPE、`utils/auditLabels.js` 的 `audit.action.*`、`constants/securitySuggestions.js`）：**后端只出稳定码，文案归前端词表**。新增 `src/constants/ipLocationCodes.js`（单一来源，当前一码 `private`），`ipLocationService` 的 IPv4 数据侧（xdb 的「内网IP」）与 IPv6 range 判定两支都改为产出该码 |
| 前端   | 新增 `web-admin/src/utils/ipLocationLabels.js`（三处消费方共用一份映射，与 securityLabels/auditLabels 同形状：调用方传 `t`、未知值原样透传），词表新增 `ipLocation.private`（zh「内网」/ en "Internal network"）                                                                                                                                 |
| 兼容性 | `location` 类型不变（string\|null）；老后端下发的中文「内网」按原样透传（与修复前一致，不回退成空白），滚动发布不会出现空归属地                                                                                                                                                                                                                  |
| 对账闸 | 新增 `web-admin/src/tests/utils/ipLocationCodeParity.test.js`：`createRequire` 后端码表逐一对账双语词表，并断言英文侧不得残留 CJK——「后端加一码、前端漏翻」变红，而不是在界面上静默显示裸码                                                                                                                                                      |
| 用例   | 后端 `ipLocationService.test.js`（私网取值不含中日韩字符）、`sessionService.test.js`（内网 IP 两字段均为稳定码）；前端三个视图各补一条「切 en-US → Internal network、公网数据文本原样」的语言跟随用例                                                                                                                                            |

### IP 归属地英文化·续（2026-10-09 · 公网归属地的中英对照词典：数据段也跟随界面语言）

> 上一节只解决了「内网」那一格（后端写死的中文）。公网 IP 的归属地是 ip2region xdb 的
> **数据原文**——库里只有中文一份，于是切到 en-US 后「中国·浙江省·杭州市·阿里云」照样是中文：
> 实测全部地区段里 **89.9% 的出现次数是中文**，只修私网标签等于修了个零头。

| 项     | 内容                                                                                                                                                                                                                                                                                                                              |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 修法   | 新增 `web-admin/src/data/ipLocationDictionary.json`（1024 条中英对照）；`utils/ipLocationLabels.js` 按当前 locale **逐段**译名后以 `·` 重拼，词典未收录的段原样透传（不把整块归属地抹掉）。语言判定读 i18n 实例的 locale（非中文界面一律英文），渲染期读 ref 即建立响应式依赖，切语言重算                                         |
| 词典   | 国家名 244 条由 `Intl.DisplayNames` 按 ISO 3166-1 **双向生成**（zh 键 ↔ en 值，不手抄 244 条）；省州 / 城市 / 运营商人工校对。实测覆盖 CJK 出现次数 **98.06%**（国家 100%、省州 98.6%、城市 93.2%、运营商 96.7%）                                                                                                                 |
| 豁免   | 10 条高频段登记未收录（`内网IP` + 9 个译名不确定的段），理由逐条写在测试里，**上限 12 条**且每条键必须仍在数据里。口径：宁可以英文界面回退中文，也不把没把握的译名写进词典——**错的译名比中文更难发现**                                                                                                                            |
| 闸     | `web-admin/src/tests/utils/ipLocationDictionary.test.js` 直接对**真实 xdb** 取数（复用后端 `loadFromBuffer` 解析指针，只补段索引遍历）：国家/省州 100%、城市/运营商高频段（出现次数 ≥ 阈值）除登记豁免外全覆盖、整体覆盖率 ≥ 98%、词典无陈旧键、译文不含中文、豁免不越上限。数据刷新带入新地名 ⇒ 测试列出缺哪些，而不是靠用户发现 |
| 体积   | 词典经三个懒加载视图进入**异步分块**：首屏 `entryJsGzip` +1.1 KB，总 gzip +19.4 KB；五项预算均仍有余量（`check-bundle-budget` 通过），基线未动                                                                                                                                                                                    |
| 兼容性 | `location` 契约不变（仍是 string）；中文界面行为零变化（数据本就是中文，不过词典）                                                                                                                                                                                                                                                |

### 依赖审计：dev 树盲区补门禁（2026-10-09 · `security-audit` 只审 `--omit=dev`）

> 本批**不改依赖树**。改的是「谁在被审」：CI 两处 audit 都是 `npm audit --omit=dev`，
> 于是 devDependencies 的 advisory 永远不会让构建失败。实测含 dev **35 条（30 high / 5 moderate）**，
> `--omit=dev` 为 **0**，web-admin 两侧均为 0。

| 项                 | 内容                                                                                                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因               | 35 条包维度告警**只由 2 条公告**传染而来：`GHSA-vfj7-8cjw-p6xm`（braces，high，栈耗尽 DoS）与 `GHSA-hp3w-g68c-fv3c`（sprintf-js，moderate）                                                                                                                 |
| 为何不能 overrides | 两条公告的 `first_patched_version` 均为 **null**，受影响区间上界就是 registry 的 latest（braces 3.0.3 / sprintf-js 1.1.3）⇒ **无版本可指向**，与 uuid override 的前提不同                                                                                   |
| 为何不升 jest 30   | 实测（隔离探针）：jest 30 + nodemon = 3 high / 19 moderate；jest 30 去 nodemon = 0 high / 19 moderate。**moderate 反而由 5 升到 19**，且清不掉 `js-yaml@3 → argparse@1 → sprintf-js` 链                                                                     |
| 可达性             | 两条链实测**不可达**：braces 需攻击者可控 glob（本仓输入只有 jest CLI/config 与 nodemon ignore）；argparse 只被 `js-yaml/bin/js-yaml.js` 引用，`load-nyc-config` 走 `lib/js-yaml.js` 不加载它 ⇒ 性质是卫生问题，非可利用漏洞                                |
| 改法               | 新增 `scripts/check-audit-allowlist.js`（含 dev 审计**硬门禁 + 显式允许清单**）+ `deployment/audit-allowlist.json`（登记两条无补丁公告，含理由/可达性/复核期限 `2027-01-31`）；`ci.yml` 的 `security-audit` 作业新增一步；`ciGateWiring.test.js` 登记新门禁 |
| fail-closed 三判据 | ①未登记 ⇒ 红；②`reviewBy` 过期 ⇒ 红；③清单项在本次报告里**已无对应公告** ⇒ 红，必须删行（防清单只增不减）                                                                                                                                                   |
| 文档               | `docs/security-dependency-watch.md` 修正「含 dev 0 漏洞」的过期结论（该结论是 2026-09-16 时点，上游 09-18 / 09-24 才发公告 ⇒ 时间性回归，非本批引入），并登记两条已知例外                                                                                   |

判据来源是**根因公告**而非受影响包（35 条 = 2 条根因），故清单按 GHSA 编号登记，
不按包名——按包登记必然得到一份腐烂清单。

### CI 覆盖率门禁修复（2026-10-08 · `#13 Run tests with coverage` 三条阈值未达标）

> 这条红**不是**本批引入，而是被下一节的修复**逼出来的**：`#11 Run tests` / `#12` 修绿之前，
> `#13` 每轮都被前序 step 的失败 skip/cancel，从未真正执行。根因是 `ccddabc`
> （2026-10-03 并行会话批次）给两个文件新增了**从未被执行过**的函数/分支，
> 而阈值是 2026-09-04 / 2026-09-30 定的。

| 文件                             | 阈值（fn/br） | 修复前实测                 | 根因（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                                                                                                                    | 改法                                                                                                                                                                                                                                                                                    |
| -------------------------------- | ------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/middleware/auth.js`         | 90 / 87       | fn **87.5%**               | `ccddabc` 给 `invalidateUserCache` 补了 `publishInvalidate(...).catch((err) => …)`，函数数 15 → 16（14/15 变 14/16）。覆盖它的 `roleStatusInvalidatesUserCache.test.js` 把整个 `invalidateUserCache` `jest.mock` 掉了，只断言"被调用"，从不碰函数体                                                                                                                  | `observabilityWritesNeverReject.test.js` 新增 L7：三种拒绝形态（Error / undefined / 无 message 对象）下断言不抛 + warn 文案逐字。注：该键是 `auth:user:`；同一调用链上 `userPermissionService` 还会广播一条 `permcache:` 键（`userPermissionService.js:191`），故判据按前缀点名而非计数 |
| `src/services/deviceReminder.js` | 97 / 90       | fn **90%** / br **86.79%** | 调度器里两处 `markOverdueInspections().catch(...)`（`ccddabc` 新增）从未执行。**且普通 DB 故障驱动不了它们**——`markOverdueInspections` 整段体在 try/catch 内、**永不 reject**，这两条箭头是**第二道防线**，只在第一道被破坏（内层 catch 体自身抛错）时才生效。第一版用例正是用 DB 故障驱动的，实测 `logger.error` 只收到内层那条 `巡检逾期标记失败：…`，箭头一次没跑 | `deviceReminderScopeIsolationGuards.test.js` 新增 2 例：让**内层** `logger.error` 抛错以打断第一道防线，两种形态（Error / undefined）各一条，把 `${err?.message ?? err}` 的两条路径都走到                                                                                               |

**为什么是补测试而不是下调阈值**：`jest.config.js` 有明确纪律「每条阈值 = 实测下方 5pt(分支) / 3pt(函数)，
只紧不松」；2026-09-30 那次 auth.js `functions 97 → 90` 是**修正推导错误**（原值按"实测 100%"机械套用，
真值 93.33%，那条 setInterval 回调是刻意不覆盖的）。本批两处缺口**都可以被行为用例覆盖**，
所以按同一纪律应补测试。

修复后实测（全量 `jest --coverage`）：`auth.js` 函数 **100%** / 分支 **92.59%**；
`deviceReminder.js` 函数 **100%** / 分支 **94.33%**——两项阈值均达标。

复跑事实：两套件 `jest <两个文件>` **40/40 通过**；`jest src/tests/ci/ --runInBand` **15/16 通过**
（`testTreePurity` 因 `execFileSync('git')` 被本机沙箱拦而红，与下一节同一条环境性假红，
该套件只判"测试文件是否入库"，不涉及本次改动）。

### CI 真红修复（2026-10-08 · `test` 腿两条既有红：断言读错流 + 循环复用夹具撞秒级归档名）

> 两条在基线 run `37711343020`（`b7834f1`，本批之前）上**逐字相同** ⇒ 既有红，非本批引入。
> `security-audit` 腿已由 `5ab7e91` 修绿（上游 2026-10-05T22:50–23:31Z 一次批量公告刷新，
> `compression` / `proxy-addr` / `source-map-js` / `@vue/server-renderer` 四条与本仓依赖面无关），
> 此后只剩这两条挡住 `test (20.x)` / `test (22.x)`，并连带 `build` 被 skip。

| #   | 缺陷（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                        | 改法                                                                          | 证据                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `imageDigestGate.test.js` 的 SIGTERM 用例把 `d.stdout + d.stderr` 拼成一个串再断言 `/RC=143$/`。驱动脚本的 `printf "RC=%s\n"` 走 stdout，而 `wait` 被信号打断时 shell 把作业终止语写**自己的 stderr** ⇒ 拼完是 `"RC=143\nTerminated"`，`$` 锚点恒不成立                  | rc 只认 `d.stdout`；`printed` 保留，继续用于「不得出现 KILLFAILED」的否定断言 | 用 dash（CI 的 `/bin/sh`）跑同一个驱动脚本：stdout=`RC=143`、stderr=`Terminated`                                                    |
| ②   | `backupFailureArtifactHygiene.test.js` 的三轮 `for (const blank of [...])` 复用 `beforeEach` 的同一个夹具。归档名只到**秒**，而"只含空白"的判据落在异地副本那一步（加密归档已定稿落盘）⇒ 第 2 轮同秒撞名，先命中「目标加密归档已存在，拒绝覆盖」，断言变成在测另一条判据 | 每轮自建 `mkwork()`、`finally` 拆掉，三条之间只差 `blank` 一个变量            | 固定时间戳的 `date` 替身把"同秒"从偶发变确定性：共用夹具第 2 轮复现出与 CI 同形的「拒绝覆盖」；每轮新夹具三轮全部「只含空白」+ rc=1 |

为什么本地一直没暴露：两套件都是 shell-out 型，本机 `spawnSync` 对任何可执行文件返回 `EBUSY`
（逐 host 探针 `status=null` / `error=EBUSY`），本地根本跑不到断言。另有一条会误导归因的环境差异：
本机 `rm` 被安全包装器接管，单次约 10–13 s，把单轮备份脚本从 CI 的亚秒级拖到 **31 s**——
"本地复现不出同秒撞名"正是这个延迟造成的。

复跑事实：`prettier --check` 两文件通过、`eslint` 两文件 RC=0、`jest src/tests/ci/ --runInBand`
**15/16 通过**（`testTreePurity` 因 `execFileSync('git')` 被 EBUSY 拦而红，属环境性假红，
且该套件只判"测试文件是否入库"，不涉及本次改动）。

### 运维脚本 E（2026-10-04 · 备份/恢复/密钥生成的失败面：容器侧那段命令第一次被真跑一遍，收紧失败第一次非零退出）

> 这一族的形状全都一样：**成功回显与失败信号在出口处不对账**。备份脚本对"一条都没跑"的异地命令
> 回显"已完成异地副本"；容器侧对一份 0 字节归档返回 0 并打印 `Restore completed successfully`；
> 密钥生成对"11 个文件一个都没收紧"照样退 0——三处都把没做过的事记成了做过。
>
> 方法上是本仓第一次让 `docker` **桩真的执行**容器侧命令（把 `-c` 后面那段交回 bash，容器内的
> `mongodump`/`mongorestore` 由 PATH 上的桩充当）。此前所有 docker 门禁只记 argv 与 stdin，
> 于是容器侧那七八行的缺陷谁都不判——注释里"用完即删""不落盘"都是没有实物的一句话。
> 新增断言一律配**前世版自证**（把脚本副本还原成修前形态，证明断言真能红）。

已落地：

| #   | 缺陷（读源码确认，非推断）                                                                                                                                                            | 改法                                                                                                                                                                 | 门禁（行为级，不是 grep）                                                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `backup-mongo.sh` 在 `case` **之前**无条件 `mktemp + 写入含口令的 URI`，而 docker 传输（默认）从头到尾没人读它 ⇒ 每次备份都在宿主盘上留一份 0600 明文口令                             | 配置文件挪进 `local` 分支按需创建；docker 分支只经 stdin 送 `uri:` 行                                                                                                | `backupFailureArtifactHygiene` C.1：docker 跑完 `"$TMPDIR"/*` 里**一个** `^uri: ` 结构的文件都没有；反向对照 local 恰好探到 1 个                                                                                                                                                               |
| ②   | 备份侧容器内路径写死 `/tmp/.mongodump-backup`，且 `cat`/`printf` 不判返回码（与 peer 已修的恢复侧同源）                                                                               | `mktemp` + 每步 `                                                                                                                                                    |                                                                                                                                                                                                                                                                                                | { rm -f "$cfg"; exit 1; }` | C.1 的 `DOCKER .*exec -T mongo sh -c` 自证 + 断言 argv 上没有口令字面量 |
| ③   | `BACKUP_OFFSITE_CMD` 含换行/回车时按"一条命令"解析只执行**第一行**，却把整份配置回显成 `Offsite copy completed` ⇒ 多行 env、CRLF 写的 env、误粘两条命令三种现场都记账为"异地副本已做" | 执行前拒绝（一条都不跑），并把 `\\r` 的 CRLF 出路点名                                                                                                                | C.2 三腿：多行/内嵌 `\\r` ⇒ rc≠0 且桩一次都没被调用、归档不被动；尾随单个换行 ⇒ 仍放行且回显文本逐字节等于那条命令（正向对照，防过度收紧）                                                                                                                                                     |
| ④   | `generate-secrets.js` 逐个收紧密钥文件时**丢弃返回值**，且目录级复核不通过也只 `console.log` 后 `exit 0` ⇒ `generate-secrets … && 下一步` 在密钥仍可被本机其他用户读写时继续推进      | 收返回值聚合成 `fileFailures` 点名清单；`check.tightened && fileFailures.length === 0` 之外一律 **非零退出**；产物保留不删（内容有效，毁掉只会把运维推向手搓随机值） | `filePermissionEnforcementAndVerify` 新 describe 5 腿：`node -r <preload>` 把 `src/utils/filePermission` 顶成可编程桩（真实宿主造不出"icacls 被拒"），目录失败/复核失败/仅文件失败三档各钉 rc=1 + stderr 点名 + 成功文案缺席；**前世版腿**：删掉返回值检查的副本在同一份桩下 rc=0 还打印成功行 |

同批的"探针"改造：宿主机凭据落点的探测从**按文件名**（`mongorestore-config.*`）改成**按内容结构**
（首行匹配 `^uri: `），与本批次前 peer 在 `restoreTransport.test.js` 里立的同一把尺子对齐——按名字探的是
"祸害叫什么"，改名即失明。

**押后（本轮不入库，见下方协调项）**：`restore-mongo.sh` 的两条同族修复——⑤ `RESTORE_SKIP_CHECKSUM=true`
把"哈希对不上"一起豁免（该开关的原意是"恢复本来就没有校验和的老归档"，实现出来却允许把一份已知损坏/
被替换的归档写进生产库；前者缺的是证据，后者是**反证**）；⑥ 容器侧固定名 + 不判返回码 + 0 字节归档被记成
一次成功恢复。改动与门禁都写好了并且是绿的（`backupEncryptionContract` 新增 3 腿 + 新文件
`restoreRemoteHardening.test.js` 7 腿，后者让 docker 桩执行容器侧命令，配 canary 预创建、两次运行路径互不相同、
0 字节拒收、空 stdin 停在 `read` 四个面，外加前世版翻转腿），但 ⑥ 撞上一条**已在 HEAD 里**的 peer 门禁：
`src/tests/deploy/restoreTransport.test.js:185` 字面钉死 `rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive`。
该文件的意图（"容器侧凭据用完即删"）在 mktemp 形态下依然成立，字面却必然失效；而它在我的改动范围之外，
工作树里还叠着同一位 peer 未提交的探测器改造——按行拆开提交做不到，于是整条 ⑥（连带只依赖它的 ⑤ 与两份测试）
押后，等那条字面 pin 换成判 `rm -f "$cfg" "$arch"` 之后单独入库。

协调项（交给并行会话或下一批）：

1. `restoreTransport.test.js:185` 的字面断言改成结构判据（清理了 `cfg`/`arch` 两个变量，而不是清理了某两个名字），
   随后 `scripts/restore-mongo.sh` + `src/tests/deploy/{backupEncryptionContract,restoreRemoteHardening}.test.js` 一起落地。
2. `deployment/backup-encryption.md` 里 `RESTORE_SKIP_CHECKSUM` 的口径要与 ⑤ 同步（文档现在描述的是"整段跳过"的旧语义）。

复跑事实：`src/tests/deploy` + `src/tests/security` 全量 **755 passed / 8 failed / 763**，两条红点各有其主——
`bundleBudget.test.js` 7 条是真实 `web-admin/dist` 的 `entryCssGzip 21900 B > 预算 19000 B`（并行会话新增
`apple-refine.css` 后重建产物而未重置基线，本批未碰任何前端文件）；`restoreTransport.test.js` 1 条即上面 ⑥。
本批相关 5 个文件 **67 passed**。`npx eslint src scripts --quiet` 0 项、`lint-ratchet` 通过（21 个含 warn 文件
均未超基线）、`check-utf8` 全绿（1061 个文件）、`prettier --check` 对改动文件全部通过。

### 供应链 D（2026-10-04 · 上一批的 21/21 变异矩阵被独立审计复跑出 9 条存活变异：逐条封红，并把"只有真实数据全对才绿"那一族补成夹具可证伪）

> 上一批自己写的变异矩阵（9+12 条）判的是"解析器/流程被改坏会不会漏"，但**漏掉了另一族**：
> 判据的输入在仓库里恰好是"全对"的，于是任何**削弱比较本身**的改动都没有实物能打红。
> 独立审计员逐行复跑后点名 9 条存活变异（下表 M/D 编号），其中两条正是"防投毒"链条上最关键的位：
> `repo` 判据放行了官方镜像的裸短名（第三个来源静默退化成两源），以及打印面把**硬报错**算进"可用"。

九条存活变异与本轮的封堵（每条都配了 arm，见下面矩阵）：

| 编号 | 原缺陷（存活原因）                                                                                                                                                   | 本轮改法                                                                                                                                                                                        |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M9   | `expect([shortName, 'library/'+shortName]).toContain(e.repo)` 二选一 ⇒ 官方镜像登记成裸短名照样绿，而 ECR 的 `map()` 靠 `library/` 前缀判托管 ⇒ "三源一致"悄悄变两源 | 改成 `repo` 由 `ref` **唯一决定**的 `toBe`；再加"声称用过 ECR ⇒ `map()` 必须给得出路径"的 ③ 号腿                                                                                                |
| M6   | digest 对账写成"长度不同才不符"仍全绿（表与文件全等，判据无实物）                                                                                                    | 对账逻辑抽成纯函数 `reconcile(refs, table)`，用**同长度、末位不同**的夹具 digest 直接打红；孤儿/陈行/不符三类各钉独立断言                                                                       |
| M7   | `sources`/`sites` 两列只判"非空" ⇒ 改成任意假话都绿                                                                                                                  | 新增一条可证伪用例：散文里所有像主机名的 token 必须**恰好等于**来源表里被点名的集合；点名数 ≥2；ECR 声称⇔可映射；`sites` 与扫描面**逐文件双向**对齐（多说不说都红）；引用点总数 `[1,1,1,1,2,3]` |
| M2   | `--only ,` ⇒ `split/filter` 得空数组（JS 里为真值）⇒ 六行全被排除 ⇒ 打印"核验 0 个引用 … 全部通过"退 0                                                               | 抽纯函数 `planRuns(argv, table)`，命中 0 行 ⇒ **退出码 2** 并点名"拒绝把空跑报成通过"                                                                                                           |
| M3   | `tag = ref.slice(ref.indexOf(':')+1)` 与 `lastIndexOf` 在真实六行上无差别（都只有一个冒号）                                                                          | 抽 `tagOf(ref)` + 端口夹具（`reg.example.com:5000/team/app:1.2.3` ⇒ `1.2.3`），另钉"真实六行切出的 tag 不含斜杠也不含冒号"                                                                      |
| D6   | 非 JSON 响应体走 `JSON.parse` 的原生异常文本 ⇒ 响应体前若干字符进日志（违反"外部响应体一律不回显"）                                                                  | `try/catch` 包住，报错只说"响应体不是 JSON（N 字节，内容未回显）"；用例同时钉 `not.toMatch(/<html>/)`                                                                                           |
| D13  | 打印面 `可用 = 非跳过的来源数` ⇒ **HTTP 500 / 非 JSON 的硬报错被算进"可用"**，`2/3（可用 3）`是给读者的一句话谎言                                                    | 分母改成 `应答`（拿到摘要的来源数），另起两位 `跳过 N，报错 1`；报错行前缀写"报错："。用例直接断言整行文本                                                                                      |
| D10  | `isIndex` 的 `every` 改成 `some` 存活（夹具只喂过"两条都单层"）                                                                                                      | 新增混合腿（一条 index + 一条单层）**两种顺序各判一次**：`ok` 必须 false，而 `agreeCount` 仍为 2（判据①与③不许混成一团）                                                                        |
| D5   | `judge` 不透传 `bytes` 时输出念 `undefined 字节`/`0 字节`，而用例只判 `/(\d+) 字节/`                                                                                 | `bytes` 过一道；断言改成**真实字节数**（"对返回字节自算 sha256"这句话唯一的实物证据就是它）                                                                                                     |

同批补强的三处（审计员另外点名的"判据依赖仓库内容配合"）：

- `workflowFileNames(names)` 从 `targetFiles()` 抽成纯函数并喂夹具：`.yaml` 分支在本仓**没有实例**，
  真实扫描面证不了它没写错；同时钉住"排序与 `readdirSync` 顺序无关"与噪音后缀（`yml`/`ci.yml.bak`/`x.YML`）。
- 永真断言替换：原来那条 `all.some(r => /<64 位 hex>|<捕获值>|示例/.test(r.value)) === false` 不可能红
  （扫到的 value 全都过了解析器）。改成**否定语料自证**：注释里带 `@sha256:` 的行按文件精确计数
  （Dockerfile 3 / compose 2 / deploy.yml 1），并断言它们既不进 `all` 也不进 `unreachable`——
  compose 的 mongo 段那条**反引号包裹的 `image: …<捕获值>`** 正是"注释排除一删就红"的实物。
- 替身自己也进判据：`resp()` 的大小写归一化在**存/取两面**各钉一条直接断言（删任一半就有用例红），
  外加 `ok` 的算法（404 false / 201 true）。上一轮的"header 各种大小写都要读得到"只在此之上才有意义。

退出码外壳（`process.exit(code)` 那一层）第一次进了门禁：`main(argv, table = EXPECTED)` 与
`planRuns(argv, table = EXPECTED)` 都接受表注入，于是"表本身写坏"与"命中 0 行"这两档在**触网之前**
就能被夹具判（真实仓库里表现在是好的，少这个注入点这两条分支永远走不到）；再用 `spawnSync` 真跑三次
脚本判 2 号路径的退出码与 stderr 文案，把"返回值→退出码"的接线也钉住（挑的都是不联网的分支，
所以门禁仍然离线）。

变异矩阵 **22 条 arm = 21 CAUGHT + 1 条刻意负对照**（`/c/tmp/mut-d.js`，跑完四个文件 sha1 逐字节还原）：
判据侧 arm（空跑守卫、`return plan.code`、`process.exit(code)`、`indexOf`、非 JSON 回显、分母把报错算进来、
`every→some`、`bytes` 不透传、下限归零、替身存/取不归一化 ×2）+ 数据侧 arm（官方镜像裸短名、
第三方命名空间被加 `library/` 前缀、表内 digest 末位改一位、`sites` 指错文件、`sources` 编造来源名、
声称用了 ECR 但其实不托管、compose 退回裸 tag）+ 闸自身（注释排除、对账退化成比长度、`.yaml` 分支）。
唯一一条"预期存活"是**负对照**：把 `repo` 判据退回二选一并同时喂"第三方命名空间被加 `library/` 前缀"
这条数据缺陷 ⇒ 13 条全绿，用来证明严格版 `toBe` 是唯一能抓它的判据，而不是装饰。

复跑事实（不联网的闸与联网的工具各一次）：`node scripts/verify-image-digests.js` 6 引用全 PASS、
**退出码 0**；本轮 `docker.1ms.run` 起效后 redis/mongo 为三源一致；`public.ecr.aws` 对 redis/mongo
仍**不发** `Docker-Content-Digest`（三态输出的实证），对 node 这一次直接 `fetch failed`——输出如实念成
`一致来源 2/2（跳过 0，报错 1）`，旧写法这里会念"可用 3"。散文里的取证数字第一次可复核：
`index 7 个条目`（mongo）与 `index 3 个条目`（grafana）与实测一致，其余来源逐条打印条目数与字节数。

未收（诚实清单）：

- `captured` 仍是人手写日期，闸只判形状。本批把 `sources`/`sites` 变成可证伪，但**取证日期**没有
  仓库内可对齐的事实来源（对表情的最硬约束是：某行 `sources` 写了 `public.ecr.aws` 而该 repo 在
  ECR 上不存在 ⇒ 红，见 ③）。
- "来源表三条腿全活"不是判据：某条腿抖动报错时，只要 ≥2 源一致脚本仍退 0（这是设计——独立性要求
  的是**运营主体不同**，不是三条全响）。`reasons` 会把报错的腿点名，但不改结论。
- `sources` 散文里的 `index N 个条目`只有 mongo/grafana 两条写了数字，本批不强制其余四条补齐
  （工具已经逐条打印，补不补只影响人读表时的方便）。
- `verify-image-digests.js` 仍不进 CI（联网门禁红了之后人先怀疑网络）。

同批收到两份独立逐行审计报告（`scripts/*.sh` 5 条：备份默认 docker 传输把全库口令写进宿主 `/tmp`
且无人读取、`RESTORE_SKIP_CHECKSUM=true` 连"校验和不匹配"一起跳过、`generate-secrets.js` 权限收紧
失败仍退 0、多行 `BACKUP_OFFSITE_CMD` 只跑第一行却宣布跑完、容器侧固定 `/tmp` 路径 + `cat` 不检查；
`src/services`+`src/controllers` 5 条：部门成员缓存无失效钩子导致 ≤30 s 跨部门可见、告警 `meta.total`
取自分页而 `hasMore` 在过滤前算、`rolePermissionController` 把畸形权限 ID 静默丢弃后整体覆写、
MFA 恢复码集 last-write-wins、`User.findById` 结果未守卫）。**本批未动这些文件**（属于并发会话在飞
范围与另一条链路），逐条自行复核后排入下一批。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 13 + `imageDigestVerify` 19 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **90 绿**（上一批 77）；元门禁 13 套 123 例
仅 1 红，且是 `ci/testTreePurity` 列出 7 份他人未入库的 `*.test.js`（本批只改既有用例文件，未新增）；
`ci/commentAnchorFreshness` 与 `ci/bareAnchorAttribution` 本轮**转绿**（他人会话已把 `runtime.js:88` 的
锚点同步到 `statsCache.js:147/157`）。`eslint src scripts --quiet` 0 error；`lint-ratchet` 通过
（21 个 warn 文件均未超基线，`main` 拆出 `planRuns` 后复杂度未升）；`check-utf8` 1050 文件通过；
prettier 对本批三个文件 `--write` 后 `--check` 通过。

### 供应链 C（2026-10-04 · 「全仓镜像都已钉版」第一次变成机器可判的账：6 个引用 × 3 处事实来源，配上不联网的两把闸）

> 上一批的诚实清单欠了三件事：compose 的 mongo / prometheus / alertmanager / grafana 与 `ci.yml`
> 的 service 容器还是可变 tag；三处"全覆盖式表述"是失实的；而"脚本能跑"与"文件真的钉完了"之间
> 没有任何东西在对账。这批一次性收掉：**引用面账**（`src/tests/security/imageReferenceInventory.test.js`）
> 把真实文件 ↔ 期望表 ↔ 脚本常量 ↔ 老闸字面量四处钉成同一笔账，**判据行为账**
> （`src/tests/imageDigestVerify.test.js`）把新工具的三条放行判据逐个做成可打红的用例。

钉版落地（本轮补 5 条，仓库内第三方引用至此 6 个 / 全部 `name:tag@sha256:<64hex>`，保留可读 tag）：

- `docker-compose.yml`：mongo `eb581912…`、prometheus `075b1ba2…`、alertmanager `e13b6ed5…`、
  grafana `079600c9…`（redis `858f009f…` 上一批已钉）；`.github/workflows/ci.yml` 的 service
  容器 mongo 与 compose **同一个 digest**（不同则 CI 是在"另一个 mongod"上跑绿的，而日志看不出区别）。
  `${APP_IMAGE:-fire-safety-app:local}` 是本机构建产物，不属于第三方供应链输入，分类器把它归"动态"。
- **取值不需要 docker**：新增 `scripts/verify-image-digests.js`（零依赖，只用 node 内置 `fetch`/`crypto`）
  对 registry 的 manifest 端点取**原始字节**自算 sha256——这就是该 manifest 的 digest，`Docker-Content-Digest`
  只作旁证不作结论。放行要三条同时成立：①自算值等于期望表值；②≥`--min-sources`（默认 2）个
  **运营主体不同**的来源给同一个值（`public.ecr.aws` 是 AWS 自己发布的 official 面，另两个是不同
  运营商的 Hub pull-through 缓存）；③拿到的必须是 manifest 列表 / OCI index——钉单层摘要等于锁死一个
  architecture。`captured`/`sources` 两列记录取证现场，不是装饰。
- 本批落地时与今日复跑都是三源/两源一致：**6 引用全 PASS（退出码 0）**。prom/grafana 只有两源
  是实测事实：ECR Public 对这些命名空间就是 404（不托管 ⇒ `skipped`，与"来源报错"分成两类，
  混同会把坏掉的 registry 路径念成"这条腿今天没说话"）。

两把新闸的判据（都不联网；联网核验仍是人跑一次的工具，理由见"未收"⑤）：

- `security/imageReferenceInventory`（9 条）：扫描面自证（8 个文件 / 11 条指令行 / byFile 精确到
  Dockerfile 3 + compose 6 + ci.yml 2 / 2 条动态 / 9 条 registry 引用，解析塌缩不许静默绿）；
  行分类器与钉版解析器各带**夹具**自证（13 例分类表 + 6 例拒绝表；注释排除、YAML 键大小写敏感、
  `image:` 后必须有空白、`(^|[^A-Za-z0-9_.-])image:` 词边界，都不靠仓库内容配合）；双向对账
  （孤儿引用 / digest 不符 / 期望表过期条目 / `present.size === EXPECTED.length`）；同 tag 必须同
  digest；`capture-image-digests.sh` 的 `NODE_TAG`/`MONGO_TAG` 与 `baseImageDigestPinned` 的字面量
  交叉对账，脚本管不到的 4 条引用点名列出。变异 **9/9 全红**（grafana 解钉、表内 digest 分叉、
  CI↔compose 分叉、解析器收大写、删注释排除、表里放不存在的引用、redis 写成序列项、大写 digest、
  `image:` 去空格），四份被改文件 sha1 逐字节还原。
- `imageDigestVerify`（10 条，`global.fetch` 替身）：judge 三条判据各自能单独把结论打回 false
  （含"两源一致但是单层"这一臂）+ `min-sources` 调大必须变红 + `headerMatches` 三态；fetchOne 的
  替身故意让 header 与字节摘要**不相等**，钉住"取的是字节"；单层响应体 `entries` 必须归 0（判据③
  唯一的输入）；Bearer 流程把 URL 序列与 `Authorization` 序列逐位钉死（少一步重试、或取 token 那步
  带上凭据都要红）；`realm=`/`Realm=` 两种写法都认，解析不出 realm 时报错而不是静默匿名直连；
  `token` 与 `access_token` 两个字段名都认。变异 **12/12 全红**，同样逐字节还原。

脚本侧顺手修掉的真缺陷（都是写用例时暴露的，不在"计划改"之列）：

- `anonymousToken` 按小写 `realm=` 匹配：registry 生态里 `Realm=` 真实存在，只认一种会让那条来源
  常年报"响应里没有 Bearer 挑战"，运维第一反应是怀疑网络而不是脚本。改为 `i` 匹配；同时它的旧注释
  写着"没有 realm 就当作公开端点直连"，而代码从第一版起就是 throw——注释失实已改（静默直连的产物
  是一个要鉴权的端点用匿名身份返回 401，最后被归因成"这个来源没说话"）。
- 旧结构是"先探测再取"：公开端点（来源表里两个都是）会为每个引用**把 manifest 下载两遍**，第一遍
  响应体整批扔掉。改成一次请求、非 200 才按挑战取 token 重试一次，重试目标仍是同一 URL、token 只流向
  `realm` 指定的地址。
- 输出侧把"来源没发 `Docker-Content-Digest`"念成"header 相符"——ECR Public 实测就不发这个 header，
  等于每轮三行假话。改成三态（相符 / 与自算摘要不符 / 来源未发），且认不出的值一律落到**不作断言**
  那一档（默认值不能是"通过"）。
- 新增上面那句三态判断立刻触发 `lint-ratchet` 的 `[complexity] 0→1` 回退（`main` 贴着上限 15）。
  拆出 `printVerdict` / `headerNote` 把复杂度降回基线，**没有**收紧基线。

口径同步（三处失实表述随本批改掉）：`docs/architecture.md` 原写"digest 待部署机捕获"（部署机什么都没
跑、值已经在仓库里 ⇒ 已是假话）⇒ 改为全部已钉 + 指路取值口径与对账闸；`.github/dependabot.yml` 的 docker 段补上第三处站点
（期望表，漏改由新闸判红）；`security/baseImageDigestPinned` 文件头原来只承认一条升级路径（部署机跑
`capture-image-digests.sh`）⇒ 补成两条，并明说本闸覆盖面早就不止 node/redis（它保留的是"三阶段同
digest"这条工具链漂移不变量与最早的两条字面量）。compose 里那条 `#（它 pull 之后把输出追加为…）`
示例行**故意留着**：它是 shell 脚本自证文案的一部分，删了脚本的说法就不成立了。

未收（诚实清单）：

- 本批不新增依赖 ⇒ 三个来源里两个是第三方缓存，独立性建立在"缓存不重打包"这个前提上，不是密码学
  证明。要证伪投毒只能把 digest 与上游签名（Notary / content trust）对上，本批不做。
- 期望表的 `captured` 是人手写的日期，闸只判形状（`^\d{4}-\d{2}-\d{2}$`）不判真伪；`sources` 列同理。
- `--only` 里写了表里没有的引用 ⇒ 退出码 2 并点名，但"新镜像进表"这件事仍靠人记得；`imageReferenceInventory`
  能抓到的是**文件里出现**而表里没有的引用，反向（表里有、文件里全删了）也能抓，靠条数相等那条。
- `verify-image-digests.js` 不进 CI：联网门禁红了之后人先怀疑网络，那正是最容易被人为绕开的形态。
  机器只保证仓库内四处事实来源对得上；外部事实变了要靠人跑一次，或等 Dependabot 把 tag 改掉触发红。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 9 + `imageDigestVerify` 10 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **77 绿**；`node scripts/verify-image-digests.js`
全表 6 引用 **PASS，退出码 0**；元门禁 18 套 239 例中 4 红，全部指向并发会话——`ci/testTreePurity`
列出的 7 份未入库用例里有 5 份是他人在飞的 `*.test.js`（本批 2 份随本批入库），另 3 条锚点红是
`src/services/statsCache.js` 顶部插入 35 行把 `src/constants/runtime.js:88` 钉住的
`publishInvalidate`/`onInvalidate` 从 **114/124 移到 147/157**，锚点与台账应由该会话同步（本批不代改
他人文件）。`eslint src scripts --quiet` 0 error（`AbortSignal` 是本仓 globals 白名单缺的一项，已补）；
`lint-ratchet` 通过（21 个 warn 文件均未超基线）；`check-utf8` 1049 文件通过；prettier 对本批全部文件
通过，工作树里两份他人文件仍未格式化（不代改）；`git diff -- Dockerfile` 为空（上一批已钉完），
`docker-compose.yml` 只动了本轮那 4 处 `image:` 与其注释块，`.github/workflows/ci.yml` 只动了 service
容器的 1 处。

### 供应链（2026-10-04 · 把上一批的脚本逐个改坏：五条真缺陷全都属于"把没做完说成做完了"，而闸的共同毛病是只会说"非零"）

> 这批的输入不是新代码，而是**对同日上一批落地的 `scripts/capture-image-digests.sh` 做变异测试**：
> 派三个子 agent 逐行审计，再手工把脚本一条条改坏，看闸会不会红。结果两边各中一处系统病——
> 脚本侧五条缺陷全在同一类上（**报成功而事情没做完**），闸侧的根病是**失败臂只判 `rc !== 0`**：
> 把整份脚本换成一个语法错误的文件时，14 条"必须拒绝"的用例全部照绿，因为它们不看是谁在说话。
> 下面每条都附复现形状，不读脚本也能验。

脚本侧（`scripts/capture-image-digests.sh`）：

- **①「够不着」只在整文件都够不着时才报**（最坏的一条）。分类器先看指令词、再取第一个字段当值，
  字段不属于本镜像 ⇒ `next`；这条 `next` 顺手把"值压根不在能锚定的位置上"也吞了。于是同一文件里
  一条 `FROM --platform=$BUILDPLATFORM node:22.14.0-alpine AS b` + 一条正常 `FROM` 时，前者被当成
  不相干的镜像行放过 ⇒ 打印"钉好 1 条 / 已替换并校验"，文件里**留着一条可变 tag**。compose 的
  `image: ${MONGO_IMAGE:-mongo:6.0.20}` 同形。修：含 tag 字面串却没取到值、且不是注释行 ⇒ 新增
  `unreach` 类 ⇒ 停手并给行号（`--platform=` 与变量展开都归到"指令行但取不到值"这一支）。
- **② 外部输出按行判 ⇒ 多行可以伪造脚本的判据**。`grep -Eq '@sha256:[0-9a-f]{64}$'` 是**按行**判的，
  而 `${raw%@*}` 取的是**最后一个** `@` 之前的全部内容 ⇒ `docker inspect` 返回"一行合法引用 + 任意
  一行"时，形状判据与仓库名判据双双通过；`--apply` 只是碰巧撞在 `sed` 的 unterminated s command 上，
  不加 `--apply` 则 rc=0 并把那一行**原样打进给运维的粘贴块**（把外部输出当代码用）。修：先要求
  **恰好一行**，行数不对就拒收，且**不回显内容**——多行输出可以伪造本脚本自己的日志行。
- **③ CRLF 行尾：同一输入在两台上是两种结果**。MSYS 的 gawk 与 GNU sed 会吃掉行尾的 CR（⇒ 整份
  部署文件的行尾被静默改成 LF 还报成功），Linux 的 gawk 留着 CR（⇒ 判成"形态不认识"而拒改）。
  检测必须走**字节**通道：本机 `grep -q "$CR"` 与 `awk '/\r/'` 对同一份文件都报 0 处，`od -c` 明明
  看得见 `\r`——文本模式在读取时就把 CRLF 换成了 LF。改成 `tr -dc '\r' < file | wc -c`，非零即拒，
  并把"请先把行尾改成 LF"作为可执行建议打出来。
- **④ 信号只清了残留，没有停下手**。`trap 'cleanup_pin_tmp' EXIT HUP INT TERM` 里那三个信号句柄跑完
  清理就**继续执行**：运维按 Ctrl-C 之后脚本照样把两个目标文件写完、照样打印"已替换并校验"、照样
  rc=0（在 15MB 夹具上实测：SIGINT 之后两个文件都已落盘）。修：`on_signal` 清理之后
  `exit $((128 + sig))`；实测 SIGTERM ⇒ rc=143、两文件逐字节原样、无 `*.pin.tmp`。
- **⑤ 全文刷新缺名字边界 ⇒ 两种真实损坏**。`s%tag@sha256:[0-9a-f]{64}%…%g` 不带边界时：
  前无边界会把 `myorg/mongo:6.0.20@sha256:…`（别人的命名空间）里的同名子串当成自己的引用改掉，
  注释从"别人的仓库"变成一张假证；后无边界会把 `@sha256:` 后面 68 位十六进制的前 64 位换掉、
  留下 4 位尾巴，产出一行**看起来完全合法**的钉版引用。修：两侧各加边界字符类
  `(^|[^A-Za-z0-9._/:@-])` / `([^0-9a-f]|$)`，定界符仍是 `%`（`|` 是 ERE 的选择运算符）。

闸侧（`src/tests/imageDigestGate.test.js`，38 → **54 用例全部真跑**）：

- 失败矩阵 14 → **25 臂**，每臂判**精确退出码 + 原因文案（逐行匹配 `^错误：`）+ `第 N 行` 的行号契约**
  再加共同后置条件（两目标逐字节不变、不留临时文件）。新增臂：digest 只有 63 位 / 只有 8 位 /
  大写十六进制（三条各**只违反一件事**——旧夹具 `sha256:short` 同时违反字符集与长度，于是删掉 `{64}`
  或放开大写都不会红）、多行 inspect 输出、CRLF、命名空间前缀、`image:` 后无空白、混合写法两臂、
  缺目标文件两臂（"不存在"与"够不着"是两条不同的臂）。
- **差分语料三条**：输入 → 脚本自己声明的处置计划（`待钉 N 条、待刷新 M 条、已是本次 digest K 条`）
  → **逐字节期望产物**，三格同时判，并加两条越界自证（改动行必须都含 tag 字面串；行数不许变）。
  这是①和⑤那类"少报一笔 / 多改一笔"唯一的交集防线——按形态写的判据两边都看不见。
- docker 调用**序列**断言（`info → pull node → pull mongo → inspect node → inspect mongo`）取代
  `calls.length >= 4`：条数挡不住"从不 pull mongo 就直接 inspect"（本地恰好有旧镜像时照样拿到 digest，
  钉上去的是过期摘要）。
- **SIGTERM 用例**：docker 替身每次睡 1 秒（整轮约 5 秒），驱动脚本在第 1 秒发信号——那一刻离第一次
  落笔还差整个 capture + 分类阶段，所以"信号之后文件有没有被动"是稳定差值而不是竞速。
- `findShell()` 探不到带 awk/sed 的 sh 时整组 `describe.skip`，等于 54 条零断言的绿 ⇒ CI 上单独一条红
  （ubuntu runner 一定有 `/bin/sh`，探不到就是探测本身坏了）。
- `run()` 读目标文件改成缺文件返回 `null`：否则"脚本没碰它"和"那个文件根本不存在"会混成同一条异常。

未收（诚实清单）：SIGTERM 用例的时机靠"裕度 3 秒"而不是同步点——若 runner 上 `sleep` 被替换成
非阻塞实现，它会退化成竞速，这条得盯；`.sh` 依旧不在 eslint/prettier 覆盖内（无 parser、本批不新增
依赖），脚本的验证手段只有 `sh -n` + 本文件真跑；两条 `mv` 之间不原子。上一批那条"未收"仍然成立：
compose 的 mongo / prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器
都还是可变 tag（没有 `docker pull` 证据就不臆造 digest），三处全覆盖式表述要和下批的镜像引用面账
一起改。

验证：`sh -n` 通过；`npx jest --runInBand src/tests/imageDigestGate.test.js` = **54 绿**（含 SIGTERM
腿实测 rc=143）；`security/baseImageDigestPinned` 4 绿、`ci/commentAnchorFreshness` 13 绿、
`ci/codeViewPhantomLedger` 5 绿（共享 helper `jsCodeOnly` 的幻影已被并发会话修到 0，本文件在旧台账里
的 32 行登记项随之消失——那份修复此刻还在工作树里未提交，若被回退这把闸会自己红，不会静默放行）。
`deploy/deployScript` 56 绿；`eslint --quiet` 0 error、`lint-ratchet` 通过（21 个 warn 文件未超基线）、
prettier 与 `check-utf8` 通过（1042 文件）；`git status -- Dockerfile docker-compose.yml` 为空 ⇒
本轮全部 `--apply` 都跑在 `--root` 临时根里，真实部署文件逐字节未动。

### 供应链（2026-10-04 · 唯一能修"半钉仓库"的脚本自己拒绝再跑：已钉从报错改成按目标跳过，digest 刷新与"够不着就停手"补齐）

> 起点是 `src/tests/security/baseImageDigestPinned.test.js` 的文件头——它把升级路径写成
> "在部署机跑 `scripts/capture-image-digests.sh` 重新捕获，再同步闸里的字面量"。上一轮把产物
> 口径与双 digest 修好之后，这条路径**仍然一步都走不通**：check 阶段把"这一行已经是
> `tag@sha256:…`"当成错误直接退出。而本仓库今天的真实状态恰好是混合仓库——Dockerfile 三条
> `FROM` 全钉死、compose 的 mongo 没钉 ⇒ 脚本在第一个目标就停手，永远到不了需要它的那个目标。
> 也就是说闸的注释把自己否证了：它点名的唯一工具，对着真实仓库跑必然红。
> 实测入口很简单：`sh scripts/capture-image-digests.sh --apply` 在本仓库根跑一次即可复现。

> 第二类更隐蔽，是"报告成功而什么都没做"的**反向版本**。判"这条引用够不够得着"用的是无锚定
> 子串计数，而替换用的是锚定正则——两套口径不同，于是这些形态被判成"可改"、进了落笔分支，
> 替换却一条都不匹配（`sed` 无匹配仍然 rc=0）⇒ 打印"已替换并校验"，文件一字未改：
> `FROM --platform=… node:22.14.0-alpine`（值不在能锚定的位置）、compose 的引号包裹值
> `"mongo:6.0.20"`、序列项 `- image: mongo:6.0.20`、折叠标量、`${MONGO_IMAGE}` 变量展开、
> `node:22.14.0-alpine @sha256:…`（tag 与 `@` 之间夹空白）、以及无 tag 的纯 digest 钉版
> （旧上一版脚本自己写坏出来的形态）。每一类都留下同一个后果：仍指向可变 tag 的引用被当成
> 已固定提交上去。

修（`scripts/capture-image-digests.sh` 的 check→stage→commit 三相，判据从"数子串"换成"分类值 token"）：

- **单遍分类器**（awk，只限 POSIX 构造，CI 的 mawk 与本机的 gawk 同结果）：按"行首 = 可选缩进 +
  指令词（`FROM` / `image:`）+ 空白"锚定，取整个值做 token，再按镜像名（剥 `@…`、剥最后一个 `/`
  之前的仓库名与 tag）过滤掉不相干的镜像行——redis / prometheus / `${APP_IMAGE:-…}` 不会被误判。
  值分四类：`待钉 bare`、`已钉 same`、`待刷新 refresh`（钉在**别的** 64hex 上）、其余一律
  `够不着` ⇒ 立即停手、零写入、只打**行号与形态名**（不回显整行）。分类器只按脚本顶部的 tag
  常量精确匹配，不做模糊猜测；指向本镜像的引用一条都找不到同样报错（脚本常量与仓库漂移是
  另一类事故）。
- **按目标跳过，而不是整体报错**：`same` 让该目标原样不动并明打"本次跳过（不改动）"，
  混合仓库因此能收敛（已钉行一笔不碰、未钉行钉上）；`refresh` 让滚动同名 tag 换 digest 的升级
  路径真的存在。**整体 no-op 仍然是错误**（两个目标都 `same` ⇒ 红），保住"报告成功但一字未改"
  那条老缺陷的判据。
- stage 用两条 `sed -E` 表达式：① 锚定的裸 tag 追加本次 digest；② 全文 `tag@sha256:<64hex>` →
  本次 digest，**故意不带锚定**——Dockerfile 顶部的用法注释里也写了完整钉版引用，只改指令行会把
  "正确示例"变成"错误示例"，而那正是本脚本要躲开的第一类失效。产物先落 `*.pin.tmp`，再用**同一个
  分类器复查预演结果**：仍残留 `待钉`/`待刷新`、或指向本镜像的条数变了 ⇒ 删临时文件退出；
  分类说"要改"而 `cmp` 判逐字节一致 ⇒ 报"分类与替换不一致"退出（这是自我矛盾探测器，不是保险丝）。
  commit 阶段 `mv` 之后对盘上的真实文件再 classify 一次。两个 `mv` 之间不是原子的，这条边界
  明写在脚本注释里，没有假装成原子替换。
- 计划可见：check 阶段就打印每个目标"待钉 N 条、待刷新 M 条、已是本次 digest K 条 ⇒ 会改动/跳过"，
  跑之前就知道这次动哪几条。

本轮实测到、并写进注释当教训的三处自身缺陷：POSIX sh 没有 `local`，`classify_ref` 覆写全局
`file` ⇒ `cmp -s "$file" "$tmp"` 变成"临时文件与自己比"，每一次合法运行都被报成"逐字节一致"；
`plan_ref` 读的是全局计数，两个目标都 probe 完再统一打印 ⇒ compose 的计数被打在 Dockerfile 标签下；
`sed` 用 `|` 作定界符与 ERE 的选择运算符撞车（`unknown option to 's'`）⇒ 换成 `%`（registry 引用
文法不含 `%`）。

闸（`src/tests/imageDigestGate.test.js`，38 用例全部真跑，PATH 插 docker 替身，不用扫源码文本）：
失败矩阵从 7 臂扩到 14 臂，新增 6 条"够不着"臂（`--platform=`、夹空白、无 tag 纯 digest、
引号包裹、序列项、折叠标量、变量展开），共同后置条件是**目标文件逐字节不变 + 目录里没有
`*.pin.tmp`**；表宽自证同步改成 14（jest-each 少喂一格是超时假绿，不是失败）。新增成功腿：
混合仓库（已钉的 DF 一笔不碰、compose 钉上、打印"跳过"）、`refresh`（含注释示例自愈、断言旧
digest 不再出现在文件里、复跑判 no-op）、单行内混合收敛、`FROM  node:…` 双空格；命名空间腿把
脚本的 `repo_of_ref`/`norm_repo` 抽进 sh 夹具跑 7 个真实引用（`node`→`docker.io/library/node`、
`prom/prometheus`、带端口的 registry 必须保留原样，反向 2 例必须 REJECT）并断言 ACCEPT 集非空——
只比末段会把别人的仓库当成自己的。零串扰自检保持：真实 `Dockerfile` 与 `docker-compose.yml` 的
base64 前后相等，本轮实测 `git diff -- Dockerfile docker-compose.yml` 为空。

未收（诚实清单，留作下一批）：compose 的 mongo 本身仍未钉（本轮没有 `docker pull` 证据，不臆造
digest），prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器同理；
`baseImageDigestPinned` 的标题、compose 里"digest 由部署机 docker pull 后捕获追加"的注释、
`docs/architecture.md` 的"镜像钉版本：node、mongo"这三处**全覆盖式表述**与上述现状不符，
要和那份清单同批一起改成可核对的范围。`.sh` 不在 eslint/prettier 的覆盖里（无 parser），
本文件的验证手段只有 `sh -n` + 真跑。

验证：`sh -n` 通过；14 形态探测（临时夹具 + docker 替身，digest 用假值）全 PASS，且每次成功之后
复跑都被判 no-op 红；对真实仓库跑 dry 分类 ⇒ 三条 `FROM` 与三处注释引用识别为待刷新，
redis/prometheus/alertmanager/grafana/`${APP_IMAGE}` 与 Dockerfile 的散文行一笔不碰；
`npx jest --runInBand` 跑 `imageDigestGate` + `security/baseImageDigestPinned` +
`ci/commentAnchorFreshness` = 55 绿、`deploy/deployScript` = 56 绿、`ci/codeViewPhantomLedger` 绿；
`eslint src scripts --quiet` 0 error、`lint-ratchet` 通过、prettier 与 `check-utf8` 通过。

### 运维手册（2026-10-04 · 轮换手册 ① 发的 cookie 名服务端根本不读，"旧令牌必须立即失效"是一项不可能失败的检查）

> 起点是运维侧 P2-3（`deployment/secret-rotation.md` 的 L-01 ①）。复现只需一次函数调用：
> `extractAccessToken({headers:{cookie:'accessToken=X'}})` → `null`，而
> `extractAccessToken({headers:{cookie:'access_token=X'}})` → `X`。服务端只有
> `ACCESS_COOKIE_NAME='access_token'` 这一个名字（`src/utils/cookie.js` 的导出，
> `src/middleware/auth.js` 的 extractAccessToken 是 /api/auth/me 上 authenticate 的第一步），
> 手册却教运维发 `accessToken=`——名字对不上时走的是 `AUTH_TOKEN_MISSING`（"没带令牌"），
> 而轮换真正生效时走的是 `AUTH_TOKEN_INVALID`（验签失败），**两者同为 401**
> （`src/utils/errorCodes.js` 里两条的 status 都是 401，这条前提已被钉进用例）。
>
> 于是这项检查有两层失效，第二层更根本：判据只写"预期 401"、没有轮换前的正向对照，
> 匿名请求同样 401。**"检查通过"与"检查没跑"输出完全一样**，这样的判据不是弱，是零。
> 换句话说：即便当初把名字写对了，这一条也什么都没证明。
>
> 修（`deployment/secret-rotation.md` ①）：名字改回 `access_token`；补轮换前的同命令对照
> （必须 200，不是 200 就先修命令别开始轮换）；判据从状态码换成 `errors.errorCode`，
> 并把三种 401 的读法写进手册——`AUTH_TOKEN_INVALID`＝旧密钥确实没了、
> `AUTH_TOKEN_MISSING`＝令牌没被读到（不是轮换成功的证据）、`AUTH_TOKEN_EXPIRED`＝样本本来
> 就过期，证明不了任何事，重新登录换令牌再测。
>
> 闸（新增 `src/tests/deploy/runbookCheckCanFail.test.js`，7 用例）守两条同根判据：
> **A 是行为重放而不是字符串比对**——文档里每条 `Cookie: <name>=…` 与 `curl -b <name>=…`
> 的名字拼成真实请求头喂给服务端读取点（access 走 extractAccessToken，refresh 走四处共用的
> `getCookies(req)[REFRESH_COOKIE_NAME]`），断言取得回值；合法名集合由 `src/utils/cookie.js`
> 的 `*_COOKIE_NAME` 导出派生，且**每个导出名必须登记一条读取点**（加名不登记即红，闸不另立
> 第二份清单）。**B 是"负面判据必须自带对照"**——代码块里出现 401/403 时同块必须有 200 级
> 正向对照或同一状态码下可区分的 errorCode/AUTH_* 码。覆盖域沿用 runbookSecretSource 的
> "说明书"口径，刻意排除 CHANGELOG/deliverables/docs/adr——本条 CHANGELOG 里写着的
> `accessToken=` 是证据，不是指令。端点归属（把 refresh 发给 /me）是已声明的边界，不收。
>
> 变异（真文档上跑，每次只动一处，跑完逐字节还原）：把 ① 的名字改回 `accessToken` ⇒
> **恰好 1 红**（判据 A）；把 ① 整段还原成缺陷形状（只留"预期 401"）⇒ **恰好 1 红**（判据 B）。
> no-op 基线 7/7，扫描器不是空的（前提自证：真文档 ≥1 条 Cookie 名且必须来自被修的文件）。
>
> 验证：新闸 7/7；`ci/commentAnchorFreshness` + `testTreePurity` + `src/tests/deploy` 全套
> 400/407 绿，7 处红**全部**在 `deploy/bundleBudget`（并发会话正在改 web-admin，
> 前端产物超出现有预算基线；与本批无关，本批一个字节都没碰前端）；
> eslint 0 error；prettier 对新文件与手册均 unchanged。服务端代码零改动——
> 缺陷在文档，闸把文档接进了代码。

### 供应链（2026-10-03 · `capture-image-digests.sh` 的产物会被本仓自己的钉版门禁判红，还会把已钉过的行改成双 digest）

> 起点是运维侧 P2-4（"脚本在已钉版仓库上不可操作"）。复现成立，但**失效方向判反了**：
> 它不是拒绝工作，而是**开心地工作并打印成功**。2026-10-03 对着本仓库真实的
> `Dockerfile`（三条 FROM 都是 `node:22.14.0-alpine@sha256:9bef…`）抽出脚本的
> `check_ref` / `stage_ref` 单独跑：check 返回 0（放行），stage 产出
> **3 条 `@sha256:[0-9a-f]{64}@sha256:` 的双 digest**，脚本随后打印"已替换并校验"。
> 根因是一句无边界的前缀匹配：钉版形态**仍然包含**脚本常量 `FROM node:22.14.0-alpine`，
> 于是 `grep -qF "$old"` 把"已经钉过"读成"还能改"，`s|$old|$new|g` 再在它前面插一个新 digest。
>
> 顺着这条线查下去撞出第二类、也更严重：**`RepoDigests[0]` 天生不带 tag**
> （`docker.io/library/node@sha256:…`，本仓 2026-10-02 已实测），而旧实现把整串当引用写入，
> 产物就是无 tag 的 `FROM docker.io/library/node@sha256:…`。本仓的钉版口径是**保留可读 tag**
> ——`baseImageDigestPinned.test.js` 的 FROM 判据 `/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/`、
> `deploy/deployScript.test.js:118` 的 `<repo>:<tag>@sha256:…`、`docker-compose.yml:159` 的
> "纯 digest 看不出版本，排障时得先 inspect"三处同源，真实文件也全是这个形态。
> 也就是说 `baseImageDigestPinned` 的文件头把"跑这个脚本重新捕获"写成升级路径，
> 而**照这条路跑一次，红的一定是它自己**。这个矛盾在审计复核第 20 轮 §A3 已判过、
> 挂在"等拍板"上；本轮按证据收敛（口径由 3 处文档/闸 + 全部真实文件定死，不是二选一的风格题）。
> 顺带更正第 20 轮的一句推断：它写"改成追加式之后双 digest 自然失去土壤"——**恰好相反**，
> 追加式的产物 `tag@sha256:…` 正是 `tag` 的前缀扩展，边界判据从此是承重墙而不是保险丝。

- `capture_digest`：**只取 `@sha256:<hex>` 尾巴追加到 `$tag` 上**，不再回传 RepoDigests 原文；
  另加仓库名一致性校验（`docker.io/library/node` 对 `node` 放行，`…/alpine` 对 `node` 拒绝）——
  追加式写法若拿到的 digest 其实属于别的镜像，写出去的就是"这个 tag 指向那个 digest"这个
  不成立的断言，只能等构建期 pull 才炸。形状判据（`@sha256:[0-9a-f]{64}$`）拦不住它，实测过。
- `check_ref` / `stage_ref`：子串判据换成**边界口径**——"含 `old` 的指令行数 − 含 `old@` 的
  指令行数 > 0"才算可改，替换用 BRE 把 `old` 锚在空白或行尾（`\([[:space:]]\)` / `$` 两式）。
  于是"已钉 Dockerfile + 未钉 compose"这个**本仓库今天的形状**从"改坏还报成功"变成
  早退报错、逐字节不变、不留临时文件；混合仓库（有的阶段钉了、有的没钉）则一笔不碰已钉的、
  只钉未钉的，且改完再跑会正确报 no-op 而不是二次污染。
- 打印口径与脚本头部注释同步改为"直接可用于 `name:tag@sha256:<hex>` 的钉版引用"，
  收尾提示补上那条会把矛盾的闸（`npx jest src/tests/security/baseImageDigestPinned.test.js`）。
- `src/tests/imageDigestGate.test.js`（实跑 19 → **27 格**）：删掉那条把错误口径钉成**必要条件**的
  旧断言 `expect(r.dockerfile).not.toContain('node:22.14.0-alpine')`——它正是两道闸互不相容
  却各自全绿的成因；替身补 `qualified`（全限定 RepoDigests）与 `wrongname` 两个模式，
  新增 6 格：产物形态按**闸的原判据**逐条 FROM 实跑、短名与全限定两种 docker 名号收敛成同一串、
  "已钉 Dockerfile + 未钉 compose"现场必须报错、混合仓库只钉未钉的那条且二次运行不再污染、
  名号对不上必须拒（含"换回 node 就放行"的反向自证）；
  前缀陷阱另配一格前提自证（把 `@` 换成空格时三条判据必须同时翻转）。
  失败矩阵 5 → 7 臂，表宽用例改为 `widths: [4]` + `rows: 7`，行数本身也在台账里留痕。
- 变异证明（每个变异体跑整套，跑完即还原）：**M1** 判据+替换回到无边界 ⇒ 6 红
  （含两条新格与"幂等重跑""compose 漂移不留半钉"）；**M2** 直接回传 RepoDigests 原文 ⇒ 6 红
  （含"产物形态按闸判据"与"名号口径无关"）；**M3** 去掉仓库名校验 ⇒ 恰好 2 红（wrongname 两臂）。
- 验证：`imageDigestGate` 27/27；邻近两闸 `baseImageDigestPinned` + `deploy/deployScript` 60/60，
  注释锚点闸 `ci/commentAnchorFreshness` 13/13；`sh -n` 通过；eslint 0 error；prettier 对测试文件 unchanged。
  真实 `Dockerfile` / `docker-compose.yml` 一个字节未动（套件里有 sha 前后比对兜住）。

### 安全（2026-10-03 · 审计链核验脚本把"报告里已见的缺口"在出口处丢了，PASS 照打）

> 起点是运维侧一条待核判断（P1-1）。我自己复现了一遍，成立，而且比原判据更宽：
> 漏传的不止一个脚本。现场（`node scripts/verify-audit-chain.js` 对着真库）——
> 链尾一条 `hashFailure` 记录（写侧算 hash 抛错后照常落库，`AuditLog.hashFailure` 的既定形态）：
> 报告 `total=3 breaks=0 legacy=0 hashComputeFailed=1`，
> 而 CLI 打 `VERDICT: PASS（全量、无断裂、hmac 已校验）`、**退 0**。
> `deployment/rollback-drill.md:111` 与 `deployment/secret-rotation.md:397` 正是拿
> "退出码 0"当验收条件的那两步，于是链上不可追认的缺口穿过了验收。

- `scripts/verify-audit-chain.js`、`scripts/resign-audit-chain-v3.js` 各补一行
  `hashComputeFailed: <report>.hashComputeFailed`。判据（`computeChainVerdict`）这一格
  本来就有实现且正确，**坏的只是调用方**：`src/controllers/auditController.js`、
  `src/services/auditChainMonitor.js` 都回传了，两个运维脚本没有。
  修复后同一现场 ⇒ `INCOMPLETE` 退 2（复现脚本前后各跑一次，只差那一行）。
- 判据 `hasUnattestableGapOf` 的 JSDoc 里那句**失实前提**已就地更正：原文写"它由
  verifyAuditChain 恒回填，唯一漏传路径是旧调用方"——实测两个现役调用方就在漏传，
  而报告确实恒回填该字段。缺省方向（漏传按 0）**保持不变**：把它翻成 fail-closed 会让
  判据对任何不带该字段的调用报 INCOMPLETE，而真值表用例与在线侧构造的字段子集调用都属
  正常用法；本仓对"未来调用方漏传"的既有机制是逐调用点门禁，不是把判据调瞎。
- `src/tests/verifyChainExitCode.test.js` 把原来那份**硬编码三个文件名**的 scanned 回传断言
  换成**全仓枚举**（`src/` 去 tests + `scripts/`，按花括号配对取出每个调用点的对象字面量，
  逐个查 `scanned` / `hashComputeFailed`；纯 `computeChainVerdict(外部对象)` 形态按
  "静态看不见字段"点名）。实测 4 个调用点，全部合规。新增 CLI 端到端一格：
  真库真链尾真 `hashFailure` ⇒ 先自证"报告看得见缺口且不是篡改"，再验退 2、理由点名缺口、
  **绝不出现 PASS**，且 `--allow-empty --allow-no-hmac --allow-all-legacy` 三个豁免同时给也盖不住；
  `finally` 还原后必须回到退 0。
- 变异实测（不是推演）：删掉 CLI 那一行 ⇒ 枚举闸、CLI 端到端、scanned 那格**三条一起红**；
  删掉 resign 脚本那一行 ⇒ 枚举红并点名该文件。两处都已还原（`grep -c` 各 1）。
  反向自证 4 形：少 `scanned`、少 `hashComputeFailed`、同文件第二个调用点漏传、
  非字面量调用，各自都被点名。
- `scripts/verify-audit-chain.js` 头注释的退出码清单补上第五类不完整（缺口无任何豁免口子），
  此前它只列了截断 / 无 hmac / 空集合 / 整窗无哈希四类。
- 验证：`verifyChainExitCode` + `auditChainGuardedIntegrity` 45/45；
  `commentAnchorFreshness` 13/13（新增的 4 处引用都取到实文件实行号）；
  `npm run lint` 0 error、`lint:ratchet` 通过（21 个 warn 文件未超基线）；prettier 已格式化。

### 质量（2026-10-03 · 「任何新增验签入口都必须引用同一份判据」这句话，判据是注释而不是代码）

> 读 `src/utils/tokenPurpose.js` 时发现它的收敛承诺没有闸：
> `src/tests/utils/tokenPurposeAndConsumers.test.js` 的「三个入口都引用 utils/tokenPurpose」
> 用的是**手写死的三个文件名**。它证的是"这三份今天还引用着"，不是"没有第四份"——
> 新增一处 `jwt.verify(t, config.jwt.secret)` 而忘了用途闸，两个闸都照常绿。
> 而同一个文件里其实已经有全仓扫描的机器（另一条用例扫的是"不许内联写第二份 type 比较"），
> 只是没扫这一维。

- 新增 `src/tests/security/tokenPurposeEntryInventory.test.js`（7 格）：**枚举** `src/` 下所有
  用 access 密钥验签的调用（剥注释后按调用点判，`refreshSecret` 那一侧不算），未引用判据的
  必须出现在豁免表里。实测全仓 5 处：`middleware/auth.js`、`services/tokenService.js`、
  `services/websocketService.js` 引用判据；`middleware/logoutAuth.js`、`services/authService.js`
  是豁免。清单钉成**双向**不变量：多一处红、少一处也红。
- 两条豁免各绑一条**行为**用例，不是文件名白名单：
  · 登出入口那次未套判据的验签只决定"走哪条身份通路"，权威判定仍在 `authenticate()` 里 ——
  拿 `type:'refresh'` 的载荷用 access 密钥签（= 两把密钥被配成同值时攻击者手里的东西）打
  `/logout` ⇒ 401 且错误码必须是 `AUTH_TOKEN_INVALID`（换成"缺失/过期"那两条 401 本用例就
  指错了方向），并且 `req.user` 根本没被构造；
  · 吊销路径少一道用途闸的失效方向是**多吊销一条**而不是**多放行一个** —— 同形态串填进
  `revokeTokensOnLogout` 的 `accessToken` 槽 ⇒ 唯一的副作用是写黑名单。
  哪天有人改动让根据不再成立（比如在吊销路径上开始用 payload 构造身份），红的是这两条行为用例，
  不是清单。
- 反向自证 + 实跑 mutation：给分类器喂一段"没引用判据的 verify"与"引用了判据的 verify"，
  两者必须给出相反答案，且注释里提到的 `jwt.verify` 不算入口；再把一个合成入口临时写进
  `src/utils/superAdmin.js` 真跑一次 ⇒「清单逐条归队」与「规模钉住」两条立刻红并点名
  `src/utils/superAdmin.js ⇒ jwt.verify(t, config.jwt.secret, …)`，随后恢复原文件（`git diff` 空）。
- `src/utils/tokenPurpose.js` 的头注释补上这句承诺现在由谁执行，并把实测的 5 处入口写进去。

### 安全（2026-10-03 · 轮换手册把**两代**真凭据指向一个没被忽略的目录，而生成器"缺哪个补哪个"）

> 触发形态直接写在手册里：`deployment/secret-rotation.md` 第 1 步 `generate-secrets.js
--out ./secrets-new`（即将上线的那套），第 4 步 `mv ./secrets ./secrets-old`（刚刚下线的
> **全套生产密钥**）。而 `.gitignore` 当时只有 `secrets/` 一条——目录名不同，一条都挡不住；
> 本仓库是公开仓库，轮换做完那天一次 `git add -A` 就把新旧两代凭据一起推上去。
> `.dockerignore` 同族：docker 的忽略模式按**整段路径**匹配，`secrets` 匹配不到 `secrets-new`，
> 所以一次 `docker compose build` 会把两代真凭据送进构建上下文（镜像层里删不掉）。

- `.gitignore` 加 `secrets-*/`、`.dockerignore` 加 `secrets-*`，各带一句"为什么不是 `secrets`"。
- 新增 `src/tests/deploy/secretCarriersIgnored.test.js`（14 格）。要点是**哪些目录会装凭据不写死清单**，
  而是从手册/compose/README 自己的文本里抓 `--out <dir>` 与 `mv <src> <dst>` 两种入口：
  将来文档新起一个 `./secrets-staging` 而忘了忽略，本闸变红；写死清单则它永远绿着，
  而漏的恰好是那个新名字。git 侧的"是否被忽略"交给 `git check-ignore` 本身（与
  `scripts/mongoUri.sh` 同一条规矩：判据按参考解析器怎么读来定），并配一条**反向自证**
  （同一条命令对没被忽略的目录回 1）——否则探测器坏掉时全部用例会一起假绿。
- `generate-secrets.js` 前置检查 A（落盘之前问 git）：`--out` 目标在仓库内而 git 不认它被忽略
  ⇒ 退出码 1，**一个文件都不写**。退出码逐档实测：0=命中规则；1=在仓库内但不报忽略；
  128=判不了（仓库外 / 容器里没有 `.git` / 没装 git）。只有 1 拒，128 只把"没判成"说出来——
  拦下一条轮换/DR 路径换来的安全性是负的。判 git 时的 cwd 取**目标最近的已存在祖先目录**
  而不是调用方所在目录：`--out ~/keys` 而家目录本身是个 dotfiles 仓库时，用调用方 cwd 会一律
  判成 128 而放行，而那正是必须拦的形状。
- rc=1 其实合并了**两**种形态（都实测，话术两种都点名）：没有规则命中它；规则有了但文件
  **已经在 index 里**（先 `git add`、事后才补 `.gitignore`）。第二种更要紧——它就是"密钥已经
  进了公开仓库"的状态，所以这里**刻意不加** `--no-index`。这条加没加不是风格问题，实跑过：
  加上后前置检查 A 放行，`--force` 一路 rc=0 把已入库那颗 `jwt_secret` 覆盖成新生成的随机值
  （历史里一份、工作目录里另一份，且再没有任何一环报警）。用例把这一格钉住，含"旧字节必须
  原样还在"与"`--force` 也救不了"两条断言。
- `generate-secrets.js` 前置检查 B：目录里已有密钥时不再"缺哪个补哪个"。原实现逐个
  `已存在，跳过`，一次中断后的重跑会产出**混合代次**目录——多数密钥彼此独立看不出来，但
  `mongodb_uri` 是把 `mongo_root_password` 拼进去生成的：mongo 初始化用旧口令建用户、应用拿
  对不上号的连接串连库，轮换"成功"结束后第一次连库就认证失败，而现场证据是两份刚生成的
  0600 文件。现在要么 `--force` 重做整套、要么拒绝；用例在 `--force` 之后现场断言
  `mongodb_uri` 里拼的就是同目录那份 `mongo_root_password`，把这对耦合写成判据而不只是注释。
- 两处**自我纠正**（都因为"注释不执行"）：① 我先前在注释里写"用目录名探测会假绿"，实测三组
  形态（`s/`、`s/`+反向 `!s/jwt_secret`、文件先入 index 再补规则）里目录名与文件名探针的命中
  结果**完全一致**，那句是没取证就下的结论，已删；② 拒绝话术原本指向手册的「失陷处置」小节，
  而 `secret-rotation.md` 里根本没有这一节（grep 过），改成它真实存在的轮换流程 + `git rm --cached`。
- 顺带修掉自己上一次提交造成的两处陈旧行号引用：`28f7247` 插入 NUL 守卫后
  `process.env[name] = value` 从 `src/config/secrets.js:113` 挪到了 `:134`，
  `scripts/devSecretIsolation.js` 与 `disposableSecretIsolation.test.js` 的锚点跟着改对
  （`commentAnchorFreshness` 报的，不是豁免掉的）。

### 安全（2026-10-03 · 破坏性恢复的**默认**传输路径从来没有一个用例跑过，而它正在宿主机上多留一份凭据）

> 背景：给 `restore-mongo.sh` 补用例时发现，本仓所有真跑过它的地方（backupUriFile /
> backupEncryptionContract / infraParam…）都显式设了 `MONGO_RESTORE_TRANSPORT=local`，
> 而 README 与 deployment/backup-encryption.md 教的恰恰是**默认那条 docker**——compose 里
> mongo 只 `expose` 不 `publish`，宿主机连不上，mongorestore 必须在容器内跑。
> 于是"数据级回滚抓手"的默认路径在修前**从未被任何用例执行过**：主机段改写的拒绝、
> `--drop` 的拼接、凭据在容器内即删、归档经 stdin 流向容器，没有一条是被证过的事实。
> 备份侧的 docker 拒绝同样没人跑过（`backupTransport.test.js` 只演过它成功的那格）。

- 新增 `src/tests/deploy/restoreTransport.test.js`（8 格）：桩 `docker` 把 argv 与 stdin
  分别落盘，断言的是**真正送进容器的那条命令与那段字节流**——`uri:` 行主机段已换成
  容器内地址、库名与 `authSource` 原样保留、归档字节确实跟在配置行后面流进去、
  argv 上没有凭据、容器侧 `/tmp/.mongorestore.cfg` 与 `.archive` 都在同一条远端命令里 `rm -f`。
  `--drop` 在两条分支各写一遍（local 拼数组、docker 拼远端字符串），所以两侧都演
  "开了有、没开无"——这是防漂移，不是重复断言。
- 实测到的**修复**：`restore-mongo.sh` 原先在分支之前就无条件 `umask 077 + mktemp +
写入含口令的 URI`，而 docker 路径从头到尾没人读那个文件——它在宿主机磁盘上实打实
  留了一次凭据（DR 现场往往是笔记本/运维机），**而下方的注释一直声称"含凭据的 URI
  不落宿主机临时文件"，那句当时是失实的**。创建挪进 `local)` 分支（`--config` 只吃文件，
  那里是必需的），注释与代码这才一致。判据"宿主机上有没有 `mongorestore-config.*`"由
  两个桩**共用同一段探测代码**：local 必须探到、docker 必须探不到，探测器坏掉时不可能
  只让 docker 那一格假绿。把修前那段贴回去，两条用例立刻变红（docker 那格探到文件名、
  local 那格数出 2 个文件）——这次 mutation 实跑过，不是推演。
- 备份侧补上缺失的那格：URI 主机段无法改写 ⇒ 非零退出、`docker.argv`/`docker.stdin`
  根本没被创建、`backups/` 里不留半成品归档，且拒绝信息不回显口令字节。
- 一个**否证的结论**（原先记成高危，源码读下来不成立）：曾判断"备份只导出 URI 里那个库，
  恢复却不带 `--nsInclude` ⇒ 归档里有几个库就覆写几个库"。mongo-tools 100.9 的
  `common/options` 在没有显式 `--db` 时把**连接串里的库名**赋给 `opts.DB`，mongodump 只为
  那一个库建 intents，mongorestore 则把 `[库名.*]` 当作 includes 过滤归档条目——
  两侧范围因此**同一个库**，没有错配。这条不改任何破坏性参数（`--drop` 的口径维持原样），
  改为把口径写进 `backup-mongo.sh` 的注释并标明它是**读源码得来的、本机无二进制可实测**。
- 一条**待拍板的不对称**（没在门禁里偷偷改语义）：含未转义 `@` 的口令，docker 分支硬拒、
  local 分支放行（备份侧同形）。方向不同是有理由的——docker 必须知道"哪段是主机"才能替换，
  两个读者读法相反时替换就是猜；local 从不改写，歧义不是脚本引入的，且两种读法下的
  **库名相同**，确认门禁没有被绕过。残余风险是"横幅里的主机不一定是实际拨号的主机"，
  而 Go 驱动本机不可测。压平它要开始拒绝一批现在能跑的口令，因此留给人决定，
  新用例只把现状钉住并注明是钉现状、不是背书。

### 安全（2026-10-03 · UTF-16 密钥文件：bash 侧把连接串改坏、Node 侧把密钥截成一个字符，两边都 rc=0）

> 背景：`*_FILE` 约定有两个读者，它们吃掉"坏字节"的方式**相反**，而两个都不报警。
> 触发形态是运维用记事本/PowerShell 把密钥"另存为 Unicode"——UTF-16LE 里每个 ASCII
> 字符后面都跟一个 `00`，肉眼看文件内容完全正常。
>
> - **bash 侧**（`scripts/mongoUri.sh` 的 `mongo_hydrate_uri`）：`_body=$(cat -- "$_file")`
>   这一步命令替换就把 NUL **删掉**了（bash 只在 stderr 留一行 warning，退出码仍是 0），
>   于是后面四条判据（单行 / 纯可打印 ASCII / scheme / 非空）校验的是**改写后的串**，
>   不是文件里的字节。实测（bash 5.3.9）：UTF-16LE 的
>   `mongodb://fsms:pw@h/db` 剥掉 NUL 后字形与正确值一模一样 ⇒ 放行；把 NUL 埋在库名中间
>   （`…/fsms<NUL>x`）则放行一个"没人写过的库"，rc=0。
> - **Node 侧**（`src/config/secrets.js` 的 `hydrateSecretsFromFiles`）：`readFileSync(…,'utf8')`
>   把 NUL **留在** JS 字符串里，`trim()` 不认它是空白（所以既不裁也不告警），
>   随后 `process.env[name] = value` 在第一个 NUL 处**截断**。实测（Windows / Node 24.18）：
>   `process.env.X='A\0b'` 不抛错、回读得到 `'A'`；把 UTF-16 的 AES 密钥喂进去，
>   注入值是 1 个字符，`loaded` 照常包含该键、`warnings` 为空。
>
> 哪些会被下游拦住纯属巧合，所以不能拿它当"没问题"的证据：`JWT_SECRET` /
> `JWT_REFRESH_SECRET` / `AES_SECRET_KEY` / `HMAC_SECRET` 有 ≥32 长度闸、`DOCS_PASSWORD` 有
> ≥16 闸（这些会启动失败，吵得响）；`METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` /
> `LOG_SHIPPING_TOKEN` / `MONGO_ROOT_PASSWORD` / `SENTRY_DSN` / `REDIS_URL` 没有长度判据，
> 它们的形态是"进程活着但对不上"——其中 webhook 签名密钥被截断等于**安全告警静默丢弃**。
> 反向核验过一条更吓人的假设，结论是否定的：`ADMIN_INITIAL_PASSWORD` 被截断**不会**
> 造出 1 字符管理员口令，`models/User.js:67` 的 `minlength: 12` 会在 `User.create` 抛错。

- `scripts/mongoUri.sh`：在任何命令替换**之前**按原始文件字节判 NUL
  （`tr -dc '\000' < file | wc -c`），非零即拒绝并点名文件与"UTF-16/二进制另存为"这一成因。
  判据写成"剩下的字节个数 ≠ 0"而不是"grep 到就算"：`tr` 自身失败时残串是空串，
  `"" != "0"` 照样点亮 ⇒ fail-closed。
- `src/config/secrets.js`：在唯一的注入入口抛错，早于赋值也早于"空文件"判定
  （`'\0'` 单字符文件若走到赋值，得到的会是**空**环境变量）。只拒 NUL，不拒"所有控制字符"——
  `LOGIN_ECDH_PRIVATE_KEY` 是多行 PEM，中间的 `\n` 合法，一刀切会把正常部署拦死。
- 报错只点名变量名与文件路径，不回显任何密钥字节（新增一条用例钉住这点）。
- 新增 4 条 shell 侧 + 6 条 Node 侧用例，其中两条是**闸内的变异自证**：
  `backupUriFile.test.js` 按代码特征删掉 NUL 闸那段、用同一份 UTF-16 夹具重跑备份，
  必须变成 rc=0 且产出归档——这证明"红"确实来自那道闸，而不是被别的东西凑出来的绿；
  找不到判据行就直接抛错，避免上一轮踩过的"变异没落地、用例对着未改动的文件保持绿"。
  Node 侧配套一条反向自证：多行 PEM 照常注入，证明判据没退化成拒绝一切。
- 记一条踩过的测试环境坑：**平台事实不能在 jest 进程里量**。第一版把
  `process.env.X='A\0b'` 的回读断言写在用例里，jest-environment-node 用自己的对象代理
  `process.env`，NUL 能原样往返 ⇒ 把"真实进程会截断"这条前提判成了假。改为 spawn 子进程量，
  并把判据写成"长度不是 3"（截断得到 1、或某平台直接拒绝赋值都算通过），
  这样 Linux 上的表现尚未实测也不会成为跨平台红灯。

### 安全（2026-10-03 · 异地副本的"空命令假成功"：`BACKUP_OFFSITE_CMD=" "` 时一次都没复制，回显却写 completed）

> 背景：`scripts/backup-mongo.sh` 的异地副本那一步，头部注释早就写着原则
> 「被吞掉的异地失败比没有异地更危险——它让运维以为自己有异地副本」。判据却是
> `[ -n "$BACKUP_OFFSITE_CMD" ]`：**非空**不等于**有词**。实测（bash 5.3.9）
> `BACKUP_OFFSITE_CMD=" "`（env 文件里多打一个空格就够了）会走进分支，
> `read -r -a` 切出 0 个词，而 `"${空数组[@]}"` 落在命令位置是一条**空命令**——返回 0。
> 于是异地副本一次都没有执行，回显却是 `Offsite copy completed:`，连未配置那支的
> `Warning` 都不打。这是那条原则里最坏的形态：它连"失败"都不是，没有任何信号可看，
> cron 邮件里是一次"带异地副本的成功备份"，而备份实际只存在于本机（与数据库同机，
> 宿主机级故障时等于没有备份）。

- 判据从"字符串是否非空"改成"**是否切出至少一个词**"：`${#OFFSITE_ARGS[@]} -gt 0` 才执行；
  配置了却全是空白 ⇒ 单独一句 `Error`（说清是配错了，不是没配）并 `exit 1`，与异地命令
  失败同档——那档本来就是 `exit 1`，没有新的中断面。
- 未设置那一支不变（仍是 Warning + 退出码 0），且新增一条反向自证钉住它：
  新分支不得把"没配异地"吞成失败。
- 顺带让 `"${OFFSITE_ARGS[@]}"` 只在词数 > 0 时展开。旧写法在老 bash（4.2/4.3，RHEL7 一类
  宿主）的 `set -u` 下展开空数组会直接掐死调用方——那是"备份跑到最后一步才崩"，
  比这次的静默更响，但同一处判据一次修掉。
- 三条新用例（真跑脚本 + PATH 桩 mongodump/gpg/offsite-ok）：空白值 ⇒ 退出码 1 且
  **不得**出现 `Offsite copy completed`；真命令 ⇒ 桩确实被调用过、且拿得到定稿后的
  `BACKUP_FILE`/`BACKUP_SHA256`；未设置 ⇒ 只有 Warning、退出码 0。
  旧实现下第一条为红（已实测），后两条在旧实现下也是绿 ⇒ 信号只由第一条承担。

### 安全（2026-10-03 · 主机段改写的 13 条拒绝收拢成一句句能定位的原因，并改掉上一轮两处失实论证）

> 背景：`scripts/mongoUri.sh` 的 `mongo_swap_host` 上一轮已经按参考解析器的读法重做了取段，
> 但拒绝路径只剩一个退出码。本会话实测出两类问题，一类是现场可用性，一类是**注释里写的
> 事实站不住**——后者更贵，因为它会让下一个读者照着错的模型改这段代码。
>
> 1. **汇总句几乎总是指向错误的变量**：13 个互不相同的失效方向全部折叠成调用方那一句
>    「无法把 URI 主机段改写为容器内地址（`<目标>`），请检查 `MONGODB_URI` 形态」。
>    `MONGO_CONTAINER_HOST` 为空或拼错时同样 rc=1，而运维被告知去查 URI——在恢复窗口里
>    这是把人往错误的文件上引。
> 2. **少给一个参数会打断调用方**：本文件被 `set -u` 的脚本 source，`mongo_swap_host x`
>    原先以 `$2: unbound variable` 中断**调用方**，走不到任何一条能看懂的拒绝。

- 新增 `mongo_swap_refuse`：每条拒绝往 stderr 打一行**原因类别**（未转义 `@`、空凭据段、
  种子列表空项、越界端口、`+srv` 带端口/带逗号、目标地址非法……），只点变量名与形态，
  **绝不回显 URI 或口令的任何字节**——这是凭据，点名不取值。调用方那句汇总改为
  「拒绝执行；上一行点名是哪条判据拦下的」，不再独自承担定位责任。
- `mongo_swap_host` 的入参取 `${1:-}` / `${2:-}`：缺参数现在是一条拒绝，而不是一次崩溃。
- 顺带修掉一处**指错变量的标签**（是新测试在跑的时候自己撞出来的）：改写产物过值判据时，
  标签原先写成「`MONGO_CONTAINER_HOST` 改写后的连接串 含空白、换行…」，于是 URI 里带换行时
  运维被告知去查那个本来就没问题的变量。走到这一步时 `_scheme` 由 case 字面量决定、
  `_target` 刚过 `mongo_valid_hostport`（单行纯可打印 ASCII），可能带越界字节的只剩凭据段与尾部
  ⇒ 标签改为点名 `MONGODB_URI`，这是**可证明的**归因而不是措辞偏好。
- 纠正上一轮写下的两条**失实论证**（都已实测取证，判据本身不变）：
  - 「参考解析器把 `a,,b` 读成少一个主机」不成立——它**接受**并读成
    `hosts=["a:27017", ":27017", "b:27017"]`，即多出一个空主机名的种子。所以这一条是
    「刻意比解析器严」，不是「它也会拒」；`a@b@c` 同理，实测它**不报错**而是静默把主机
    换成没人写过的那一段。本机实测的两个读者对同一条串给出相反答案
    （`mongodb://u:p@ss@h:27017/db` ⇒ JS 包按**第一个** `@` 切凭据 ⇒ `hosts=["ss:27017"]`；
    Node 的 WHATWG `new URL` 按**最后一个** `@` 定界 userinfo ⇒ `hostname=h`）。
    原先这里写着"Go 驱动按 RFC 3986 取最后一个"——Go 驱动本机没有二进制，那一直是**推断**，
    不该写成实测。判据因此不赌读者：两个读者读法相反的形态一律硬拒。
  - 「刻意更严的两处」实际是四处，漏记了种子列表空项与值里的空白字节两条同族判据。
- 交代一条**能力边界**，防止 parity 全绿被读成"已验证过 mongodump"：本仓 parity 闸用的
  参考解析器是 JS 包（`mongoose` 内嵌的 `mongodb-connection-string-url`），而真正消费产物的是
  mongodump / mongorestore 的 **Go 驱动**；这台机器上没有 mongodump，所以 parity 只能证到
  "与 JS 包同口径"。已知两边读法不一致的形态就是上面的裸 `@` 分界——判据一律取更严的一侧。

### 供应链（2026-10-03 · `capture-image-digests.sh` 不再能留下"半钉"仓库，也不再吞别人的临时文件）

> 背景：这个脚本把 Dockerfile / compose 的基础镜像从可变 tag 换成 registry digest。上一轮已经补上
> "sed 无匹配仍返回 0"的静默 no-op 校验，但落笔顺序还是**边检查边写、两个目标顺序跑**。本轮真跑
> （PATH 插 docker 替身 + `--root` 指向临时仓库副本）实测出三种失效形态，都属"报成功/报错都看不出来"：
>
> 1. **半钉仓库**：compose 的 tag 与脚本常量漂移 ⇒ 第一轮把 Dockerfile 改成 digest，第二步才报错退出，
>    仓库留下"Dockerfile 已钉、compose 仍指向可变 tag"。
> 2. **死路**：照报错把 compose 修好再跑第二次，脚本在 Dockerfile 那一步就撞
>    "已经存在 @sha256 钉版引用"退出 ⇒ compose **永远钉不上**，唯一能修它的脚本自己拒绝再跑。
> 3. **吞别人的文件**：`sed > $file.pin.tmp; mv $tmp $file` 会把上一次中断留下（或人工放置）的
>    `Dockerfile.pin.tmp` 静默吃掉——探针读到的是 ENOENT，而退出码 0。

- 落笔改成**三相**：`check_ref`（只读，两个目标都确认可改，含"临时文件此前不存在"）→ `stage_ref`
  （只写临时文件并预演校验）→ `commit_ref`（`mv` 改名 + 落笔后复核）。任何一步失败，两个目标文件
  都逐字节不变、目录里没有残留临时文件。
- `trap … EXIT HUP INT TERM` 只清理**本脚本确认过"原本不存在"**的临时文件：`PIN_TMP_*` 两个全局量先置空，
  `check_ref` 通过之后才赋值。直觉写法 `trap 'rm -f "$ROOT"/*.pin.tmp' EXIT` 会在报错退出的那一刻删掉
  运维的文件——变异实验（把 `-e` 门禁摘掉）证明这条判据是承重的：残留内容变成 `<<DELETED>>`、退出码 0。
- 诚实交代残余边界：两条 `mv` 之间不是原子的（跨两个文件不存在单次 rename）。check 已确认两文件都在且
  都可改、stage 已验过改好的产物，失败面从"任何解析/匹配错"缩到"同目录 rename 本身出错"。
- 测试 `src/tests/imageDigestGate.test.js` 10 → 19 条：新增原子性（第二个目标漂移时第一个必须 `toBe`
  原始字节）、自愈（修好 compose 后重跑必须 rc=0 两边都钉上）、残留（拒绝 + 不覆盖 + 退出时不删 +
  删掉后能正常钉版），以及失败臂矩阵（tag 漂移×2 / digest 取不到 / 伪 digest / 未知参数）的公共后置条件。
  逐条做过变异反证：`M1_order`（把 compose 的检查挪到 Dockerfile 落笔之后）点亮前两条，
  `M2_noTempGate`（摘掉临时文件门禁）点亮第三条；control 三场景全绿。
- 夹具侧补两条门禁自身的自证：`tmps` 过滤器在残留用例里必须**看得见**那个文件（否则"失败不留临时文件"
  是空集造成的假绿）；`test.each` 的表宽必须等于处理函数形参个数——窄一格 jest-each 会注入 `done`，
  用例不失败而是卡满 30s 超时。

### 安全（2026-10-03 · 备份的主机段改写按参考解析器的读法重做：静默连到别处、合法 URI 被拒、坏端口被顺手换掉）

> 背景：`scripts/mongoUri.sh` 上一轮已经把那句 `sed -E "s#^((mongodb(\+srv)?://)…#"` 换成纯 shell
> 字符串重建，但**取哪一段**的判据还是那套 `case */* | \?* | *` 三分支 + `##*@` 切凭据。
> 本轮拿参考解析器（`mongoose.mongo.MongoClient`，即 `src/config/database.js:51` 讨论的那份内嵌
> `mongodb-connection-string-url`）逐条形对照，实测五条同根缺陷，全部与"备份到底连了谁"有关：
>
> 1. **静默改错主机**：`mongodb://u:p@db.internal:27017?appname=bob@corp`（无路径、查询串里有裸 `@`）
>    ⇒ rc=0，产物 `…@db.internal:27017?appname=bob@127.0.0.1:27017`。主机段一动没动、目标地址被拼进
>    查询串，而解析器把它读成 `hosts=["db.internal:27017"]`（**不报错**）——横幅承诺 127.0.0.1，
>    mongodump 连的是 db.internal，退出码却可以是 0。根因：第三分支把整串当 authority，再按**最后**一个 `@` 切凭据。
> 2. **副本集种子列表被拒**：`mongodb://a:27017,b:27017/db?replicaSet=rs0` ⇒ rc=1（逗号不在字符集里）——
>    合法 URI 备份不了，报的却是"形态异常"。
> 3. **无路径带查询被拒**：`mongodb://h:27017?directConnection=true` ⇒ rc=1（`\?*` 只匹配以 `?` **开头**的串）。
> 4. **IPv6 容器地址当目标被拒**：`MONGO_CONTAINER_HOST='[::1]:27017'` ⇒ rc=1，而 URI 里写同一段是放行的
>    ——同一件事两侧判据不一致。
> 5. **交回 mongodump 自己都不认的串**：`mongodb://a@b@c:27017/db` 与 `mongodb+srv://…` 带端口的产物
>    （`+srv` 禁止端口）都是 rc=0。

- 取段判据改成按**解析器怎么读主机段**来定：authority 终止于第一个 `/ ? #`，凭据与主机的分界取**第一个**
  `@`，主机段允许逗号分隔的种子列表且每项都得过 `host[:port]`/`[IPv6][:port]` 判据，主机段已等于目标地址
  ⇒ 合法空操作放行（上一版那条假阳性就是这一形态），其余认不出来的一律硬失败。
- 新增四个可复用判据：`mongo_valid_hostport` / `mongo_valid_hostlist` / `mongo_valid_userinfo` / `mongo_valid_port`。
  端口区间那条是新发现的第二类失效方向：`h:0`（'Invalid port (zero) with hostname'）与 `h:65536`
  （'Unable to parse h:65536 with URL'）解析器都报错，而我们放行等于**顺手把坏端口换成目标端口**——
  现场拿到的是一个从来不存在、也从来没被 mongodump 拒过的 URI。区间判据写成字符串比较而不是 `$(( ))`：
  shell 把 0 前缀当八进制（`08` 直接算错），而解析器把 `07017` 读成 7017。
- 一条**负结果**记录在案，防止下一个读者把 `#` 也当成缺陷：`mongodb://h#1/db` 曾被写成"解析器读成
  `["h#1"]`、我们比它严"，实测不成立——它在 `#` 处终止 authority 读成 `hosts=["h:27017"]`、db 仍是 `db`，
  与我们的取段口径完全一致 ⇒ 放行，由 parity 闸逐条比对产物。
- `src/tests/config/mongoTransportParity.test.js` 60 → **160 例**，承重的那条是新加的**参考解析器 parity 闸**：
  真值表里每一条 rc=0 的产物都重新真跑一遍并交给 `new MongoClient(…)` 读，要求
  `hosts === [目标地址]`、库名与凭据逐字不动；输入本来就解析不动的那一类只有"两边同一句错"才判为继承
  （唯一一条：`?drop:true` 撞驱动的 option 白名单）。清单从真值表**推导**而不是另抄一份，新加一条自动进闸。
  闸自身由六条合成违例（旧写法的真实产物）反向自证，含上面缺陷 1 那条"解析器不报错却连到别处"的形态。
- 一条夹具层的坑记进注释与判据：jest-each@29.7.0 的 `applyArguments`（`bind.js:78-80`）在
  **行数组比测试函数声明的形参短**时会把 `done` 注入成最后一个实参 ⇒ 那些行不是断言失败而是**超时**。
  实测一次跑出 5 条 30 秒超时 + 1 条真失败，看起来像整道闸坏了。现在 trailing 形参带默认值
  （`Function.length` 停在第一个默认值之前），并有一条表宽判据配合成违例钉住它。

### 安全（2026-10-03 · 一次性 harness 的第二根暴露轴：宿主上的明文密钥，不只 `*_FILE`）

> 背景：`scripts/devSecretIsolation.js` 上一版把宿主的 `*_FILE` 指针全量置空，但它只看指针。
> 密钥有**两根正交的轴**——形态（`<NAME>_FILE` 指针 / `<NAME>` 明文值）与通道（宿主 `export` / `.env`），
> 上一版按通道堵了两格，形态那一根整条没堵。而明文形态不是事故形态：`.env.example:2`
> 就明写「JWT_SECRET / AES_SECRET_KEY 等可以直接写在本文件（适合本地开发）」。
> 本机实测（`node -e` 枚举 `FILE_BACKED_SECRETS`）：仓库根 `.env` 今天正带着 6 个明文密钥，
> 其中 `MONGODB_URI` / `ADMIN_INITIAL_PASSWORD` 与一次性 harness 要用的值是同一类东西。

- **守卫按名字全量置空两类**：`<NAME>_FILE` 与 `<NAME>`。漏掉的这一类比原来那条更宽，
  因为 harness 只覆写它记得的那几个名字，其余名字一个都不碰，于是明文值直接穿过 dotenv 被读到：
  `REDIS_URL` ⇒ 冒烟的验证码/限流计数读写宿主那台 Redis；`SECURITY_ALERT_WEBHOOK_SECRET`
  ⇒ 冒烟造的假告警签名有效、真推到值班群；`SENTRY_DSN` / `LOG_SHIPPING_TOKEN` ⇒ 测试流量进真实观测面；
  `ADMIN_INITIAL_PASSWORD` / `MONGO_ROOT_PASSWORD` ⇒ 播种与清理动的是真凭据。
- **由此新增一条顺序不变量**：置空明文值意味着 harness 自己的一次性赋值必须**晚于**守卫
  （先赋值再调守卫会被擦掉）。接线闸原来只钉"早于 `require('../src/index.js')`"，
  现在同时钉"早于任何 `process.env.<密钥名>[/_FILE] =` 赋值"，并带三条负向对照
  （非密钥赋值不算、生成的子脚本里整行是字符串字面量的赋值不算、真赋值提到守卫前必须点名）。
- **"空串会不会变成第三种状态"有专门用例**：这几个名字在 `src/config` 里没有字段，消费方直读 env
  （`sharedCache.js:52` 的 `(process.env.REDIS_URL || '').trim() !== ''`、`initData.js:770` 的
  `if (process.env.ADMIN_INITIAL_PASSWORD)`），置空与"宿主本来没配"逐点等价；用例钉的是**真实源码行**，
  判据写法改成 `!== undefined` 立刻红。
- **告警点名不取值**：`*_FILE` 条目打路径（值本身是路径），明文条目只打名字并注明"值不打印"——
  报错里复读密钥等于把它从 env 搬进 stdout/stderr，CI 日志保留时间通常更长（同一口径见 `scripts/secretFileArg.js`）。
- **`src/tests/config/disposableSecretIsolation.test.js` 12 → 19 例**：来源臂从两条加到三条
  （`export` / `.env` 混装 / **`.env` 里只有明文、一个 `*_FILE` 都没有**）。第三条臂就是上一版的靶子：
  它的 `uri`/`jwt` 本来就是一次性值，"全绿"完全可以和"真 Redis、真初始口令已接上"同时成立。
  真值表随之扩到九格，`del × {dotenv, plain}` 两臂共同钉住"置空而非删除"对**两类**都承重；
  `rootPw` 的期望从 `undefined` 改成 `''`（`undefined` 只证"没 hydrate"，`''` 才证"宿主明文也没接上"），
  并在探针里给所有 env 观测加 `?? null`——`JSON.stringify` 会丢掉 `undefined` 键，
  那样"挡住了"与"夹具压根没跑"分不开，是一条空断言；另补一条**真文件减法自证**：
  擦掉置空明文的那两行、只留置空指针，明文轴必须立刻漏且被点名。
- 单位夹具改用"先全部置空"而不是 `delete` 构造"宿主干净"：本 describe 的 cwd 是仓库根，
  那里真有一个带 6 个明文密钥的 `.env`，`delete` 会被守卫内的 dotenv 填回来——
  这正是实现选择置空而非删除的同一条理由。
- **真 harness 复跑**：`REDIS_URL=… ADMIN_INITIAL_PASSWORD=… SENTRY_DSN=… node scripts/e2e-smoke.js`
  ⇒ 守卫打印 3 条明文点名（无值）、`[E2E] 结果：14 通过, 0 失败`、退出码 0；
  不带毒环境的裸跑同样 14/14 绿。

### 安全（2026-10-03 · 备份/恢复：主机段改写去掉 sed，失败现场不留明文归档）

> 背景：`scripts/mongoUri.sh` 是备份与恢复共用的唯一一份 URI 判据，它自己却是
> `sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1${MONGO_CONTAINER_HOST}#"`——
> 两条注入路径都落在这句替换上，而落点都是 mongodump/mongorestore 的 **0600 配置文件**：
> 配置里唯一由调用方决定的就是那一行 `uri:`。

- **`mongo_swap_host` 改为纯 shell 字符串重建**（scheme / authority / tail 三段用参数展开切开）。
  sed 形态的两个实测失效：① 替换串里的字面 `\n` 被 GNU sed 展开成**真换行** ⇒
  `MONGO_CONTAINER_HOST='127.0.0.1:27017\ncollection:auditLog'` 能给配置追加第二行，
  单集合导出被记成一次成功的全量备份；② 口令里未转义的 `/` 提前终结 `[^/]*` 那次匹配 ⇒
  替换错位（`mongodb://u:p/x@h:27017/db` → `mongodb://127.0.0.1:27017/x@h:27017/db`），
  **凭据被静默丢弃**而横幅承诺的仍是 `h:27017`/`db`。
- **`MONGO_CONTAINER_HOST` 新增字符集判据**（`[A-Za-z0-9.:_-]`，且端口必须是数字、
  IPv6 字面量 `[::1]:27017` 单独放行）。换行、空格、`\`、`;`、`|`、反引号、`$` 全部进不来。
- **切出来的主机段必须"确实是一个 authority"**：认不出来就拒（`u:p`、`mongo:abc`、`mongo:`、
  `[::1]:abc` 都在这一条）。第一版在这里补过一条"有凭据且路径里含 `@` ⇒ 拒"，实测把
  `mongodb://u:p@mongo/db@name` 一起误杀（库名带 `@` 合法，authority 终止于第一个 `/`），
  已由精确判据取代。
- **两条出口都过值判据**：改写那一支与"主机段本来就等于目标地址"的合法空操作那一支。
  少了后者，`$'mongodb://127.0.0.1:27017/fsms\ndrop:true'` 配 `MONGO_CONTAINER_HOST=127.0.0.1:27017`
  会绕过全部检查被原样交回调用方。
- **`mongo_validate_uri` 的越界字节判据补哨兵**：`$(… | tr -d '\041-\176')` 非空这个写法漏在
  **命令替换会剥掉尾部全部换行**——载荷 `…?authSource=admin\ndrop:true` 的注入部分本身全是
  可打印 ASCII，残串为空 ⇒ 放行，`drop:true` 成为配置文件的第二行，而门禁与横幅都声明相反。
  现在先补一个 `~` 再比，判据无歧义。
- **`backup-mongo.sh` 的加密门禁提到 `mongodump` 之前**（新增 `crypto_precheck_backup`，
  与 `crypto_encrypt` 同源）。原先 `gpg` 不在 PATH 或 `BACKUP_GPG_RECIPIENT` 没配时，
  脚本先花几分钟导出整个明文全量库（人员 PII + 不可篡改审计集合）再在加密步失败退出，
  而 `set -e` 直接带走 ⇒ "写完就删明文"那行永远执行不到，**每次失败都往 `backups/`
  多留一份明文**。现在三种不可用形态都在创建目录之前拒绝。
- **未定稿产物由 `cleanup` 一律删除（`FINALIZED` 标志）**。失败产物与成功产物同名
  （`fire-safety-backup-*.gz[.gpg][.sha256]`），留着就会被 retention 清单、回滚演练与
  "最近一次备份"的报表挑中。定稿点（密文 + 校验和都在手且非空）之后反向成立：
  一个都不能删——异地副本失败按设计整体失败，那时已到手的本地副本仍是回滚抓手。
  `deployment/backup-encryption.md` 的失败语义两条已同步。
- **闸**：`src/tests/config/mongoTransportParity.test.js` 15 → 41 例（真跑 bash 的行为真值表 +
  目标地址字符集九臂 + 值判据的 LF/CR 成对臂；结构层的"反向前提"换了方向——原先断言
  那句 sed 还在共享实现里，现在断言改写函数体内不许出现 sed，并用历史写法作合成违例
  证明判据非空集，注释过滤本身也自证）。夹具改经单引号安全转义传入（`$`/反引号不得被
  bash 先展开一次），CR 载荷由 shell `printf` 现场构造（Node 传 `bash -c` 时裸 CR 会在
  传输层被吃掉，测到的是"没有 CR 的串"——假绿）。
- **新闸 `src/tests/deploy/backupFailureArtifactHygiene.test.js`（9 例）**：真进程 + 桩
  mongodump/gpg（PATH 注入），断言的是"目录里到底有什么文件、桩有没有被调用"。
  含一处前世版对照：从脚本副本里按缩进反向引用删掉 `FINALIZED` 块（并 `bash -n` 证明它仍是
  合法脚本），同一夹具必须**留下明文归档**，否则这条断言抓不住回退。
  `backupUriFile.test.js` 的 SIGINT 用例同时补上"打断后目录里不得留半截归档"。

### 安全（2026-10-03 · 密钥轮换的密钥不再经过命令行）

> 背景：仓里所有密钥早已统一成 `<NAME>_FILE` 口径，唯独密钥轮换这一族还留着
> `--new-key <KEY>`：把值写在 argv 上，同一个密钥就同时出现在
> `/proc/<pid>/cmdline`（Linux 默认 0444 ⇒ 同机任意本地用户可读，而一次全量迁移要跑几分钟，
> 窗口足够长；`ps(1)` / 任务管理器同理）、shell 历史（`HISTCONTROL=ignorespace` 只是
> "记得在前面加空格"的人为约定，不是机制）、以及任何 `set -x` 的 CI 日志。
> 同一门安全要求上的两个标准，收口成一条。

- **新增 `scripts/secretFileArg.js`**：`readSecretFile` 把"密钥文件"的形状判据写死——
  恰好一行非空内容、去 UTF-8 BOM 与 CR/尾空白、字符集限 `0x21–0x7E`（与 shell 侧
  `mongoUri.sh` 的 `tr -d '\041-\176'` 同判据）；读不到、多行、含空白一律**硬失败**，
  绝不"取第一条非空行"蒙过去。`resolveSecretSource` 的优先级与 shell 侧一致：
  **显式 `--*-file` 赢过环境变量**（命令行点名的是"这一次轮换要用的值"，不能被 shell 里
  残留的同名变量悄悄改写），两者都给时只打一行提示且**只点名不取值**。
  所有错误信息只含标签与路径——一条"密钥泄漏"的报错如果把密钥再打一遍，
  就是把它从 argv 换成了 stdout/stderr，而 CI 日志的保留时间通常更长。
- **`migrate-mfa-secret.js` / `resign-audit-hmac.js` 改为 `--new-key-file` / `--old-key-file`**，
  旧形态不是"删掉了事"而是**具名拒绝**（exit 2 并指向替代写法）。具名而非落到
  `未知参数：${argv[i]}` 那条默认分支是刻意的：默认分支打印 `argv[i]`，而循环下一步就是
  那个密钥本身——报错本身就成了第二次泄漏。
- **一处有意的收窄**：`--*-file` 只接受 ASCII 密钥；密钥本身含非 ASCII 的用户仍走环境变量
  （env 不经 `/proc/<pid>/cmdline`，不在这条禁令范围），报错里直接写明这条路。
- **手册同步改口径，并顺手拆掉一个更常见的事故源**：`deployment/secret-rotation.md` 原先第 0 步
  `openssl rand -hex 32` 让人"记下输出"、第 3 步 `printf '%s' '<新KEY>' > 载体` 让人**再敲一遍**——
  重敲一次打错一个字符，数据已经用新钥加密完毕而应用拿的是另一把钥，比不改更糟。现在生成即落盘
  （`umask 077` + 单行文件），迁移用 `--new-key-file` 指它，换钥用 `mv` 把同一份字节扶正；
  全量轮换一节本就由 `generate-secrets.js` 产出文件，直接指过去即可。
- **新闸 `src/tests/deploy/cliSecretArgGate.test.js`（20 例）**，三层判据：
  静态完备性用**派生枚举**（"从 argv 取值"的判据是 `argv[i] === '--x'` 之后 60 字符窗口内的
  `argv[++i]`，因此具名拒绝分支不会被误判成还在收密钥），任何密钥类选项必须以 `-file` 结尾，
  文档里 `node scripts/…` 形态的命令行只允许使用该脚本确实接受的那些选项——新写第三个轮换脚本
  时这条闸自动对它提要求，不需要有人记得来登记；行为闸真起子进程传 canary，断言 exit 2、
  点名替代写法、**canary 一个字节都不出现在 stdout/stderr**、且看不到"已连接"（拒绝早于连库）；
  再加 `--new-key-file` 成功路径"值进内存但不进输出"与优先级提示。
  自证：合成违规（`--new-key` / `--db-password`）与真文件减法（把手册里的 `-file` 去掉）都能点亮。
- 受影响的既有套件同步迁移到新形态并复跑绿：`destructiveGuardOrder`（9 例，夹具改为真实密钥文件——
  必须是**能过强度校验**的密钥，否则 migrate 会以"拒绝迁移"而非断言的"拒绝执行"退出）、
  `hmacResignPrecheck`（8 例）、`runbookApplyCommandContract`、`migrateMfaWriteVerify`。

### 安全（2026-10-03 · 冒烟/压测/演练不得接回真实基础设施）

> 背景：`src/config/index.js:10-11` 在 **require 期**就调 `hydrateSecretsFromFiles()`，而冲突规则是
> **文件优先**（`src/config/secrets.js:113` 无条件 `process.env[name] = value`）。三个 harness
> （`e2e-smoke` / `load-test` / `production-drill`）的形状是「先设一次性 env，再 `require('../src/index.js')`」，
> 于是只要宿主上还留着 `*_FILE`，回填就会把一次性 `MONGODB_URI` 覆写成真实库连接串——**并且不报错**。
> 后果不是测试变红，是**写**：`npm run test:e2e` 往那个库播种管理员、建用户、发告警；
> `npm run test:load` 往它打五相压测流量并写审计。

- **新增 `scripts/devSecretIsolation.js`**：按 `FILE_BACKED_SECRETS` 全量把 `*_FILE` **置空**。
  两个来源都必须堵（第一版只堵了第一条，实测被打回）：宿主 shell 的 `export`
  （`deployment/secret-rotation.md` 要求每条命令自带 `*_FILE` 前缀，把它 export 起来是最省事的顺手做法），
  以及 `.env` 里写着 `*_FILE`（`.env.example:12` 的生产口径 b)）。第二条的关键在时序：dotenv 跑在
  hydrate 的前一行，守卫只看"当前 `process.env` 里有没有"就会漏掉整条路径，故守卫自己先 `require('dotenv').config()`。
- **置空而非 `delete` 是承重的**：dotenv 16.6.1 对"已定义"的键不覆盖（空串也算已定义），
  但会重新填充被 `delete` 掉的键；`secrets.js:71` 又把空路径当"未配置"跳过。
  六格真值表把这条钉死：`del × .env` 那一臂**仍然被覆写**，所以"觉得 delete 更干净"的改法立刻红。
- **刻意不做的两个替代**：用 `NODE_ENV` 跳过回填（`production-drill` 自己要 `NODE_ENV=production`，
  跳过等于演练失去生产同构性，而那正是它存在的意义）；把 hydrate 改成"环境变量优先"
  （推翻一个深思熟虑的安全决定——挂载 secret 必须压过残留的 `.env` 明文，否则轮换看起来生效实则没生效）。
- **新闸 `src/tests/config/disposableSecretIsolation.test.js`（12 例）**：真子进程 + 真 `src/config`，
  断言的是"配置对象里到底是哪个 URI"而不是脚本里有没有某个字符串。含 `MONGO_ROOT_PASSWORD`
  这一臂：harness 从不给它赋值，回填却照样把真实值填进去 ⇒ 危害不止"它记得覆写的那几个键"，
  同时反向钉住守卫自己绝不 hydrate。
- **顺手拆掉上一轮自带的一颗定时炸弹**：`backupUriFile.test.js` 的 SIGINT 用例让外面的
  `sleep 0.4` 与桩里 `sleep 1.2` 赛跑，本机并行跑 `src/tests/config src/tests/deploy` 时漂了
  （归档写完信号才到 ⇒ "Backup completed successfully" 照打 ⇒ 用例红）。改成由桩在
  **半截归档落盘的那一刻** `kill -INT "$PPID"`：红绿只取决于脚本自己的 trap 语义，
  不再取决于机器当时有多忙。
- **既有闸 `scriptSecretHydration.test.js`（14 → 16 例）被这次改动撞红一次，且它是对的**：
  守卫用 `process.env[name + '_FILE']` 动态键读密钥注入项，按闸的口径就是"读取者"，
  而它的合规写法（在库内调 `hydrateSecretsFromFiles()`）恰恰是它要防的那个动作。
  因此给的是**逐名取证**的"共享库"豁免：原来那句 `consumers.length >= 4` 是全局计数，
  新登记的库蹭得到同一句结论却可能压根没人调用；改成每条豁免各自要求"被至少一个入口 require"
  （引入点判据在这里**刻意收紧**：读点判据宽松只会多算一个读取，豁免前提判据宽松则让空白条看起来有主）
  - "库里没有 `require.main === module` 入口支"，并补一条**真文件减法**：把三个 harness 的 require 全擦掉，
    豁免必须当场失效。

### 安全（2026-10-03 · 备份/恢复 shell 的输入校验与退出路径）

> 背景：上一轮给 shell 侧接上 `*_FILE` 后，逐行审计发现"能跑起来"和"不会把凭据/目标库交给
> 一个没人校验的字符串"是两件事。九条 CONFIRMED 全部按缺陷本身定级，不看发现者的措辞。

- **显式 `MONGODB_URI` 此前完全不校验**（只有文件那条路校验）。最糟的一条：连接串里嵌一个换行，
  `printf 'uri: %s\n'` 写进 mongodump 的 `--config` 后，第二行就成了**配置文件里的一行选项**——
  `…@host/db\n drop: true` 直接越过恢复侧所有门禁把"删库再恢复"追加进去。
  新增共享判据 `mongo_validate_uri`（整串必须是单行纯可打印 ASCII + `mongodb(+srv)://` 前缀），
  两个来源同闸。
- **缺 `--` 操作数分隔符**：`MONGODB_URI_FILE=-c` 会被 `cat`/`grep` 当选项 ⇒ 读的是**调用方的 stdin**
  而不是那个文件。补 `--`，并用真子进程断言"打开的是那个文件"。
- **告警回显会泄出口令尾巴**：`${MONGODB_URI#*://}` 之后接 `${…*@}` 是最短匹配，
  口令里含未转义 `@` 时把口令后半段连同主机名一起打进日志。改最长匹配，并补含 `@` 口令的夹具。
- **恢复目标必须由字面决定**：URI 不含库名时，目标库由**归档内容**决定，
  而 `RESTORE_CONFIRM` 的核对退化成"输入就是整串 URI 本身"——一个可猜的哨兵。
  现在缺库名直接拒绝执行（门禁的前提是目标 identifiable），正向对照同夹具带库名放行。
- **`trap cleanup EXIT INT TERM` 不自己 exit**：SIGINT 打断备份时，清理跑完继续往下执行，
  实测打印「Backup completed successfully」而产物只有 5 字节。三条 trap 各自补 `exit 130/143`。
- **`local` 传输分支失败后留 0 字节归档**：`docker` 分支早就处理了（重定向在失败前就建了文件），
  `local` 分支没有——一个躺在 `backups/` 里的空 `.gz` 在回滚清单上"就是一次备份"。同一处理补齐。
- **`grep -c` 无命中时把 `-c` 当选项吃 stdin**，且失败路径留下的空串会让 `[ "$_n" -eq 0 ]`
  报 integer expression。改成先 `cat` 进变量再从 stdin 计数。
- 测试：`backupUriFile.test.js` 17 → 23 例、`backupTransport.test.js` 7 → 8 例，每例都带**正向对照**
  （证明不是靠"永远判红"混过去的）。`src/tests/config` + `src/tests/deploy` 合计 632/632 绿。

### 运维可用性（2026-10-03 · `*_FILE` 这条线的最后一公里：shell 侧解析 + 手册里每条命令行自带密钥）

> 背景：前两轮把 Node 侧的六个运维脚本 + `npm run validate` 都接上了 `<NAME>_FILE` 回填，
> 但**备份/恢复是 shell 脚本**，而手册里的命令行为它们提供的是明文 `MONGODB_URI=`。
> 两条都在生产口径（`.env.example:12` 的 b)「只配 `*_FILE`，`.env` 不写同名变量」）下失效。

- **finding：`scripts/backup-mongo.sh` / `restore-mongo.sh` 只认明文 `MONGODB_URI`**。
  生产宿主机上只有 `./secrets/mongodb_uri` 这个文件，于是每日 cron 每晚 `exit 1`、
  **零归档**，而 cron 的 stderr 没人读——备份线静默停摆可以拖到第一次真要恢复的那天。
  修法：共享实现 `scripts/mongoUri.sh` 里加 `mongo_hydrate_uri`，两个调用点各三行改过去，
  仍保持"凭据不进 argv"（连接串走 mongodump/mongorestore 的临时 `--config` 文件）。
- **一处刻意与 Node 侧相反**：shell 里**显式 `MONGODB_URI` 赢**（`secrets.js:106-113` 是文件赢）。
  理由：恢复的目标库必须由这一行的字面内容决定，不能被环境里残留的 `*_FILE` 静默改写到
  另一个库——把备份写进错库远比连不上严重。并存时打 Warning，README 与手册都写明这层反向。
  坏文件（空 / 多行 / 不是连接串 / 含空白或控制字符）**硬失败**，不像应用侧只告警。
- **夹具暴露的实测纠偏**：`printf 'mongodb+srv://u:p%40ss@h/db'` 里 `%40s` 被 printf 当宽度
  说明符，写出 40 个空格，而首版形状检查**照样放行**（只裁了尾部）。改成"整串必须落在
  0x21–0x7E"后该形态才被判红。同批 probe 还纠正了 `tr` 的两处写法：八进制只认三位
  （`\0176` 会解析成 `\017`+`6`），且空格属于可打印区（`tr -d '\040-\176'` 会把内嵌空格删掉
  而不是查出来）——`*[! -~]*)` 那版更是 `bash -n` 直接报语法错，而语法错让 source 中断，
  导致当轮所有"应当被拒"的 probe 空过（正向样本才暴露了它）。
- **新闸 `src/tests/deploy/backupUriFile.test.js`（17 例）**：真 `bash` + 桩 `mongodump`/
  `mongorestore`，断言的是"文件里的串真的进了 `--config` 内容"而不是脚本自报成功；
  含**前世版减法自证**（把 `mongo_hydrate_uri` 换成只认 `MONGODB_URI` 的旧实现 ⇒ 同一夹具
  必须红）、四种真实密钥文件形态（无尾换行 / 尾换行 / CRLF+空行 / PowerShell BOM）、
  以及 hydrate 之后凭据仍不出现在 argv。
- **新闸 `src/tests/deploy/runbookSecretSource.test.js`（10 例）**：把手册当成可执行契约扫——
  语料 **40 条命令行 / 31 条需要连库**，五通道：缺 `MONGODB_URI(_FILE)`、缺该脚本额外的
  `HMAC_SECRET`/`AES_SECRET_KEY`、命令行出现 `*_FILE=/run/secrets`（那是容器内路径）、
  经 `docker compose exec` 跑 ops 脚本、`--apply` 未配 `ALLOWED_SOURCE_DB`。
  自证三件：前提（条数下限 + 被调用脚本文件必须都存在）、每通道合成违例、
  **真实文件减法**（把 31 条真实命令逐一抹掉前缀喂回同一条通道，全部必须点亮）。
- **判据取舍（记下来以免下轮又被"放宽"回去）**：围栏内位置无关，所以注释形态的 crontab
  示例、`cd /opt/xf && …` 复合行都在检查范围；围栏外抓**每个**内联代码 span，所以
  「- **处置**：`node scripts/…`」这种带标签写法不是盲区（实测把语料从 36 条提到 40 条）。
  但同一条 `--apply` 命令当时**仍然**看不见：它写在跨两行的内联代码里（`\` 续行 + 未闭合的
  span），任何 span 判据都读不到——所以把它连同演练那条一起搬进 ```bash 围栏，
  这才是让它受检的动作。代价是文本判据分不出"这样写"与"不要这样写"，于是把手册里
  `docker compose exec -T app node scripts/x.js` 那条反例拆成两个 span——
  **不给判据开"这条不算"的豁免口**。
  表格行按"记录/状态"排除，覆盖域只含说明书（`deployment/*.md`、`docs/incident-response.md`、
  `README.md`、`SECURITY.md`、`migrations/README.md`），不含 CHANGELOG/`deliverables`/`docs/adr`。
- **我自己写错的两句论证（自查后改掉，没有留到现场）**：
  ① `deployment/secret-rotation.md` 曾写「缺 `MONGODB_URI` 时脚本自己会红」——
  `destructiveGuard.resolveMongoUri` 只打一行 stderr 告警就**回退本地库**，而
  `assertApplyAllowed` 在 `apply=false` 时直接放行，真实症状是"数出来的是开发库的 v1 行数"；
  ② 反证了一个听起来合理的建议：`docker compose exec -T app node scripts/…` **不是**
  宿主机缺密钥的补救路径，镜像里只有 `scripts/destructiveGuard.js`（`Dockerfile:122-124`，
  故意的：容器被攻破时拿不到带 `--apply` 的灭迹工具），那条路径只会 `Cannot find module`。
  能进容器的只有 `npm run validate`（= `node src/config/validate.js`，`src/` 在镜像里）。
- **文档同步**：`secret-rotation.md` 新增「执行位置与 `*_FILE` 前缀」一节（含逐脚本所需密钥表）、
  `backup-encryption.md` cron 行、`rollback-drill.md` 备份/校验行、`incident-response.md` 两条处置命令、
  `README.md` 备份/恢复块。`rollback-drill-record.md` **只改检查单模板那一行**，
  已完成演练的历史行原样不动——为了让闸变绿去改写演练记录等于伪造现场。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 37 套件 / 612 例全绿；
  `npx eslint` 两个新文件 0 问题；`npx prettier --check docs deployment README.md migrations src/tests/deploy`
  全绿；`node scripts/lint-ratchet.js` 仅剩并发线在改的 `src/services/securityAlert.js`
  （complexity/max-lines 各 0→1），本批新增文件未引入任何 warn。

### 运维可用性（2026-10-03 · `npm run validate` 是这条线的第三个入口，而它一直站在闸外）

> 背景：`*_FILE` 回填（P3-48）只在 require 到 `src/config` 的入口自动发生。上一轮补了六个
> 运维脚本并立了 `scriptSecretHydration.test.js` 这条闸；本轮由并发审计线（lane-hydration-audit）
> 逐条攻击那条闸的判据，查出**四个漏判形态**和**第三个同类入口**。

- **finding：`node src/config/validate.js`（= `npm run validate`）在 `*_FILE` 部署下报四条假弱密钥**。
  它不经过 `src/config/index.js:11`，没人回填，于是 `collectSecretErrors` 读到 `undefined`，
  报「JWT_SECRET / JWT_REFRESH_SECRET / AES_SECRET_KEY / HMAC_SECRET 必须设置为至少 32 字符」
  并以 1 退出。而 `deployment/secret-rotation.md:156` 正是拿这一步的退出码当
  "轮换后配置自洽"的证据——密钥轮换流程的收尾在容器里做不到。
  失效形态也和其余六个不同：它们症状是"读不到"，这条是**"密钥看起来弱"**，
  会把排查方向直接带到"是不是运维把密钥换短了"上去。
- **我自己的修法被打回了第一次（如实记录）**：第一版按位置判据把 hydrate 放在
  `validate.js` 文件顶部（这样"hydrate 早于首次读取"在源码位置上成立、可被闸钉住）。
  结果连带打红 5 个配置套件（validate / startupGuards / weakSecretPlaceholder /
  transportTlsAssertion / immutableConfigGuard）。根因不是测试写错，是**判据形状与文件形状不匹配**：
  `validate.js` 同时是库（app.js / index.js / staticFrontend.js / websocketService.js 都 require 它）
  和进程入口，而"库在 require 期覆写调用方的 `process.env`"本身就是不该有的副作用——
  `src/tests/setup.js` 给每个 worker 预置了四把 `*_FILE` 临时副本，凡"先设 env、后 require"
  的夹具都被回填悄悄改回测试密钥。`index.js` 能那么做是因为它自己就是应用入口。
  最终改法：hydrate 放进 `if (require.main === module)` 入口支，先回填再 `validateConfig()`。
  A/B 实测（只给 `*_FILE`、`NODE_ENV=production`）：A 臂（预加载删掉 `*_FILE`，复现"回填没发生"）
  四条假弱密钥 + 「MONGODB_URI 不能指向 localhost」全在；B 臂（当前代码，走真实 CLI）
  弱密钥计数 0，剩下的是我没给的 `CORS_ORIGIN` / `REDIS_URL` / `ALLOWED_HOSTS` /
  `TRUST_PROXY_HOPS`——与密钥无关。
- **finding：闸的读点判据只认一种书写形态**。审计线逐条攻击后确认四处漏判：
  ① 注释里提到 `hydrateSecretsFromFiles()` 就算证据（删掉真调用、留一句注释即绿）；
  ② 解构 `const { MONGODB_URI } = process.env`、别名 `const env = process.env; env.X`、
  动态键 `process.env[k]` 三种读法一律看不见——**看不见比判错更坏**，那等于静默豁免；
  ③ 护栏代读通道 `resolveMongoUri()` 的 require 正则不认带扩展名（`'./destructiveGuard.js'`）
  和 `require(path.join(__dirname, 'destructiveGuard'))` 两种写法，
  而 `fix-token-blacklist-index.js` 唯一的读取通道就是它——上一轮那个"静默回退本地库"的
  缺陷类别因此可以再次溜过；④ 扫描范围只有 `scripts/**`，既不含 package.json 里
  `node <file>` 形态的 npm 入口（`src/config/validate.js` 就是这么漏的），也不含根目录
  `migrate-mongo-config.js`。后者是本轮新发现：`npm run migrate:up` 是以**裸命令名**调 CLI，
  `node <file>` 匹配看不见它，而 CLI 会把同目录的 `migrate-mongo-config.js` 当模块加载——
  那个文件里既有 `resolveMongoUri()`，也有一行上一轮补的 hydrate，**但那行一直站在闸外**，
  删掉不会有任何测试变红。
- **闸改造**：判据抽成三个纯函数（`findHydrationOffender` / `findCliEntryOffender` / `topLevelReads`）
  以便被合成源码直接攻击。注释先剥（逐字符走并跟踪引号，`'mongodb://127.0.0.1/db'` 里的 `//`
  不能当注释起点）；动态键按"可能是读取"计（多算无害，少算是静默漏判）；护栏 require 放宽到
  「`require(` 之后、右括号之前出现 destructiveGuard」。扫描范围三处并集，每处各由一条前提自证钉住。
  新增三条豁免都带**可执行**证据而不是一句注释：豁免一（自带临时值的探针）逐个名字找到赋值处、
  豁免二（共享库 `destructiveGuard.js`）用"确实被 ≥4 个入口 require"自证、
  豁免三（库兼入口）的前提是该文件**没有任何模块顶层读取**（用括号深度算，`depthAt`）——
  前提一破用例即红，逼着改法回到正题。压测/演练三个入口今天不读文件型密钥，
  因此**不许预先占豁免位**（`expect(CLI_ENTRY_BLOCKS).not.toContain(f)` 那类反向钉）。
  减法自证两处：把六个脚本各自的 hydrate 擦掉 ⇒ 闸逐个点名（`verdict` 必须含 hydrate，
  并断言 `stripped !== a.code` 防止"减法没真的动"）；`migrate-mongo-config.js` 同做一遍。
- **工具层陷阱（影响结论可信度，单独记）**：本会话的 Bash 里 `env VAR=x node …` 这种前缀
  **静默不执行**（rc=0、无任何输出），于是第一版 A/B 探针两臂都数到 0 条错误，
  看起来像"缺陷不存在"。同一份 env 用 bash 原生 `VAR=x node …` 前缀跑，才拿到 4 vs 0。
  与上一轮 `'j'.repeat(48)` 夹具被 `isWeakSecret` 判弱那次同一性质：**探针自己坏掉时，
  它给出的"否证"和"证伪"长得一模一样**，所以每条 A/B 都要先证明两臂至少各产出过非零信号。
- 验证：`npx jest src/tests/config src/tests/deploy` ⇒ 35 套件 / 585 条全绿；
  `scriptSecretHydration.test.js` 单跑 15/15；`prettier --check`、`eslint` 对改动的两个文件 0 问题；
  `node scripts/lint-ratchet.js` 对我改的两个文件无回退（现存回退在 `src/services/securityAlert.js`，
  属并发会话在改的文件，未动）。本轮没改 `docker-compose.yml`、`scripts/*.js` 与任何文档。

### 部署（2026-10-03 · SSH 部署路径上 digest 钉死闸一直是静默关闭的 + compose 密钥闸的清单只有 5/15）

> 背景：本轮由「`*_FILE` 密钥回填」那条线连带查出。三条 finding 都属于同一类形状——
> **配了但没送达**、**清单抄短了**、**断言扫空了**——共同点是工作流和 jest 全都绿。

- **finding：`DEPLOY_REQUIRE_DIGEST_PIN` 在 SSH 路径上从未到达 `deploy.js`**。
  `deploy-ssh` 的 `env:` 块里写着 `DEPLOY_REQUIRE_DIGEST_PIN: 'true'`，注释还注明
  「与 self-hosted 同口径」——但两条路径的送达形态根本不同：`deploy-self-hosted` 在
  部署机 runner 上直接 `node scripts/deploy.js`，step env 就是进程 env；`deploy-ssh` 的
  `node` 跑在**目标机**上，而 ssh 既不转发本地环境变量，`SendEnv` 又只在目标机 sshd
  显式 `AcceptEnv` 该变量名时才生效（默认只放行 `LANG/LC_*`）。于是那道"拒绝非 digest
  引用"的兜底闸在 SSH 路径上始终不存在。
  讽刺的是判据早就写过这条口径：本文件 `compose 里每个 :? 变量都由两条部署路径下发`
  那条用例的注释就是「env 里有但没 SendEnv = 目标机收不到」——只是没把同一口径用到
  兜底闸上，而 ⑤ 的断言形状（`expect(ssh).toMatch(/DEPLOY_REQUIRE_DIGEST_PIN: 'true'/)`）
  恰好只查"配了"，替这个洞做了一套完整的掩护。
  如实定级：**这是纵深防御缺一段，不是可利用漏洞**——`IMAGE_TAG` 本身由 preflight 解析
  并过 `sha256:[0-9a-f]{64}` 校验，实际 pull 的就是 digest 引用；闸要防的是"误配/绕过
  preflight 直接把 tag 传进来"，而那条路径上它形同不存在。
- 修法：把它拼进远程命令，并用 `${var:?}` 而不是 `$var`——漏配时报错退出，
  而不是展开成空串让 `deploy.js` 把闸读成"关"（那正是本 finding 的原始形态）。
  不走 `SendEnv`：那要求目标机 sshd 配合，且会撞红上面那条"SendEnv 恰好等于 compose
  硬声明项"的用例。bash 实测两向：置 `true` 时远程命令串为
  `… DEPLOY_REQUIRE_DIGEST_PIN='true' node scripts/deploy.js --dry-run`；
  漏配时 `bash` 立刻退 1 并打印「deploy-ssh 未下发 digest 钉死闸」。
- **闸改造**：`run: |` 扫描器从 describe 内的闭包抽成模块作用域纯函数
  （`collectRunLines(text)` / `deployInvokeLines(text)` / `digestPinDelivered(text)`），
  `allRunLines` 改为委托——同一个 job 可能有多个 step，"取第一个 run"会取到
  Prepare SSH 而不是部署命令（本仓 helper 的注释里就写着这条，但 ⑤ 没用它）。
  抽成纯函数是为了**反向自证**：把修复前的命令串喂进 `digestPinDelivered` 必须判 false。
  变异实测：只删远程命令串里那段（env 块保持"配了"）⇒ ⑤ 当场红在第 248 行
  `expect(digestPinDelivered(ssh)).toBe(true)`（Expected true / Received false），
  其余 16 条不动——正是原洞的签名：所有旧断言都不看送达。
- **finding：compose 密钥闸的名字清单是抄的，5 个 vs `FILE_BACKED_SECRETS` 的 15 个**。
  `docker-compose 不再用 environment 传任何密钥` 把 JWT/REFRESH/AES/HMAC/MONGODB_URI
  五个名字写死在断言里；其余 10 个（`DOCS_PASSWORD` / `LOG_SHIPPING_TOKEN` /
  `METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` / `SENTRY_DSN` /
  `LOGIN_ECDH_PRIVATE_KEY` / `REDIS_URL` …）哪天被写成 `- X=${X}` 明文注入，闸一声不响。
  改为清单从 `src/config/secrets.js` 反向推导（新增文件型密钥不必回来改用例，
  与 compose `:?` 清单闸同套路）。
  实测现状：7/15 走 `_FILE`（含 `REDIS_PASSWORD`），`REDIS_URL=redis://redis:6379` 明文，
  其余 7 个今天压根不在 app 的 environment 里 ⇒ 新判据对它们是"不许以明文出现"，
  不需要动 compose。**唯一豁免 `REDIS_URL` 不写在注释里，条件就地可执行**：
  URL 里一旦出现 `//…@`（口令 userinfo）立刻判红——redis 只挂在
  `data-net: internal: true` 上、口令走 `REDIS_PASSWORD_FILE`，这条豁免成立当且仅当
  它不含凭据。反向自证用合成源（真实 compose 是并发会话共享的文件，不临时改它）：
  把 `HMAC_SECRET_FILE` 换回明文 ⇒ 抓到；换成第 6+ 个名字 `DOCS_PASSWORD` 再试一次
  （这条才真正证明"扩清单"这件事本身有效）；给 REDIS_URL 塞口令 ⇒ 豁免失效；
  喂一份认不出 app 服务的文本 ⇒ 全部名字按违规上报（判据失效不许静默放行）。
- **新增：`/run/secrets/<名>` 三处一致性闸**（environment 的 `_FILE` 引用、服务级
  `secrets:` 列表、顶层 `secrets:` 段）。漏声明的后果不是"没密钥"而是"启动即崩"——
  `hydrateSecretsFromFiles` 对不可读的 `_FILE` 直接抛错，运维看到的是一条与密钥无关的
  启动失败。顺带钉住顶层每个 `file:` 必须落在 `./secrets/`（`.gitignore` 与
  `.dockerignore` 只排除这一个目录，指到别处等于把密钥放回版本库与构建上下文）。
  合成夹具 `CLEAN` / `ORPHAN` 各证一侧：`b_secret` 顶层声明了却没挂到 app ⇒
  `missingFromService` 抓到、`missingFromTopLevel` 必须为空（判据认的是"两处一致性"，
  不是一刀切盯 environment）。
- **自查出一条假绿（自己写自己抓）**：本条第一版的顶层扫描用了
  `/^ {2}[a-z0-9_]+:\n {4}file: (\S+)$/gm`——本仓库文件是 CRLF，`:` 与 `\n` 之间夹着
  `\r`，这条正则**恒不匹配**，那个 `for` 循环体一次都没执行，而用例是绿的。
  这正是本仓踩过两次、写在 `deployWorkflow.test.js` 注释里的坑（"不用 $ 锚点：
  本仓库工作流是 CRLF，`\r` 会让行尾锚定的正则恒不匹配（实测过）"），我照样踩了。
  现在所有 compose 扫描统一先 `split(/\r?\n/)` 再逐行匹配，并把这类"取到多少条"
  写进前提自证（`referenced.length >= 7`、`targets.length >= referenced.length`、
  每个 `file:` 必须是字符串）。
- 核过撤销的怀疑：`ADMIN_INITIAL_PASSWORD_FILE` 曾被记为"compose 接了但应用不读"的
  疑似死接线——`src/services/initData.js:770,833` 确实在读它（初始管理员口令），
  嫌疑撤销。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 35 套件 / 578 条全绿；
  `prettier --check` 与 `eslint` 对改动的三个文件均 0 问题。
  本轮未改 `docker-compose.yml` 与 `scripts/deployPolicy.js`（判据变了，配置没变）。

### 运维可用性（2026-10-03 · `*_FILE` 密钥部署下六个独立脚本拿不到连接串）

> 背景：`src/config/secrets.js` 的 `<NAME>_FILE` 约定（P3-48：密钥走文件挂载，不进
> `docker inspect` / `compose config` / 子进程继承）只在**require 到 `src/config` 的入口**
> 自动回填 process.env。运维手边的独立脚本几乎都是 `require('dotenv').config()` +
> 直读 `process.env.MONGODB_URI`，这两者从来没接上。
>
> **本轮推翻了自己的第一版判据**：先用静态依赖图筛"哪些脚本需要补 hydrate"，
> `verify-audit-chain.js` 的图确实通向 `src/config`（auditChainVerify → utils/auditChain →
> 函数体内 `require('../config')`），按图它不需要改。改成动态探测（只给 `MONGODB_URI_FILE`、
> 显式把 `MONGODB_URI` 置空、目标端口 1）后结论相反——那是**懒 require**，脚本在 `main()`
> 里读 env 时它还没执行。静态图在这里会给出假绿。

- 实测（修前）：`verify-audit-chain` / `revoke-user-sessions` / `run-rollback-drill` /
  `sync-audit-indexes` / `perf/explain-spotcheck` 读到空串，开局报错退出；
  `fix-token-blacklist-index` 更隐蔽——`resolveMongoUri` **静默回退本地默认库**并打印
  「已连接：127.0.0.1:27017/fire_safety_db」，运维以为在清生产索引。
  同族 `resign-audit-hmac.js` / `resign-audit-chain-v3.js` 因为显式调了 hydrate 一直正常，
  它们同时充当探测方法学的正向对照（对照组判"已 hydrate"，说明判据不是在猜）。
- 后果直接落在文档化的运维步骤上：`deployment/secret-rotation.md` 的 HMAC 轮换第 0/4/5 步
  都要求 `node scripts/verify-audit-chain.js` 且注明"要求退出码 0"，
  在 `*_FILE` 部署里这一步**做不到**——第 5 步会退 1，轮换完成后无人给出链条干净的证据。
- 六个脚本各自补 `require('../src/config/secrets').hydrateSecretsFromFiles();`
  （紧跟 `dotenv`，早于任何 env 读取），与本仓既有同族写法一致。
  不用"把 hydrate 塞进 `destructiveGuard.js`"这种集中式改法：它是被 require 的库，
  无权决定进程何时回填，而且 `verify-audit-chain` / `explain-spotcheck` 根本不经它。
- 新闸 `src/tests/config/scriptSecretHydration.test.js`（8 条，逐条能被打红）：
  读取文件型密钥的入口必须**自己**显式 hydrate，且早于首次读取。
  读点有两条通道，只钉第一条会漏——`fix-token-blacklist-index` 唯一的读取通道是
  `require('./destructiveGuard')` 代读，所以把护栏引入点也按读点计（否则删掉它的
  hydrate 行，闸照样绿）。
  判据自证：合成源码攻击（缺 hydrate / hydrate 太晚 / 只赋值不读 / `===` 比较 /
  `JWT_SECRET_V2` 前缀同名）各一条；豁免两条各自带证据——
  `audit-probes/ws-session-bypass.cjs` 必须能为每个读到的名字指出赋值处，
  `destructiveGuard.js` 必须真的被 ≥4 个入口 require；
  压测/演练入口（e2e-smoke / load-test / production-drill）今天只写不读，
  因此**不许预先占豁免位**，哪天它们开始读 env 就会撞红再登记。
  变异实测（用真实文件，不是合成源码）：删掉 `fix-token-blacklist-index.js` 的 hydrate 行
  ⇒ 闸当场报出该文件（「读取文件型密钥 MONGODB_URI，但整个文件没有调用
  hydrateSecretsFromFiles()」），恢复后 8/8 绿——这条正是"只钉直读通道"时会静默漏掉的那个脚本。
- 核过不动的：`scripts/*.sh`（backup/restore）按文档就是 `MONGODB_URI='<连接串>' ./scripts/...`
  显式传值（secret-rotation.md:277），不经 Node 的 env 回填路径。
- 实测（修后）：同一探针下六个脚本全部改为"拿文件值去连"（端口 1 上超时被杀，
  即它们真的读到了 `*_FILE` 里的连接串）。
  另用真实内存 MongoDB 端到端跑 `verify-audit-chain.js`：只给 `MONGODB_URI_FILE`
  （文件内容**故意带尾部换行**）时它连上了库并打印
  「VERDICT: INCOMPLETE — 审计集合为空（0 条）：无记录可验」——这条判定只有连接成功才可能给出，
  空集合是夹具本身没种记录；两者都不给时退 1「未提供 MONGODB_URI」，
  作为反向对照证明前一条不是默认值蒙出来的。

### 修复（2026-10-03 · 上一轮 PII 收窄的两处回归：揭示迟到写入 + 审计副本仍存明文号码）

> 背景：四路并行逐行审计复核 2026-10-02 的两批改动，各命中一条**由那批改动自己引出**的缺陷。
> 两条都已回源核实并做变异实测，不是推测。

- **lane-B #1｜`web-admin/src/views/UserView.vue` 的 `doReveal` 迟到写入守卫**。
  原实现 `await` 之后无条件 `dialog.form.phone = full; dialog.phoneBaseline = full`，
  既不校验目标行也不校验弹层是否还开着。可达路径：点「查看完整号码」后请求飞行期间
  ESC 掉 step-up、关掉编辑框、再点另一行的「编辑」⇒ **A 的明文连同基线一起落进 B 的表单**，
  而界面上的提示恰好是「清空并提交即删除」⇒ 管理员照着删空再保存，
  抹掉的是 **B 的真实号码**。修法是发请求前把 `reveal.userId` 快照成 `targetUserId`
  （step-up 一关 `resetReveal` 就会把它清空，事后读不到），响应回来只在
  `dialog.form._id === targetUserId` 时写入。只比 `_id` 不叠加 `dialog.visible`/`isEdit`：
  关框必走 `resetForm`（`_id` 归 null）、新增框同样是 null，多余的两个条件恒真且**写不出
  能覆盖它们的用例**，留着就是无人验证的死分支。
  门禁：`web-admin/src/tests/views/userView.test.js` 新增两条（切到另一行 / 切到新增框），
  夹具用**手工 defer 的 Promise**——`mockResolvedValue` 在下一个微任务就落地，
  任何迟到守卫都来不及被触发，用例会退化成恒真。
  变异实测：把守卫改成 `if (false && …)` ⇒ 两条同时转红（`expected '13900000000' to be ''`），
  恢复后 61/61 绿。
- **lane-A #2｜`src/utils/helpers.js` 的 `SENSITIVE_KEY_SUBSTRINGS` 补 `phone`**。
  名单原本只管"凭据"，于是 `PUT /api/users/:id`、`POST /api/alarms/report` 这些**写路径**
  把手机号明文留在了 `AuditLog.body` 里，而 `services/securityAlert.getRecentAlerts`
  的投影含 `body` ⇒ `GET /api/security/alerts` 把它再下发一次；`auditBuffer` 的明文 WAL
  同样带着它。结果：持 `security:audit` 的账号无需口令、无需 `system:read`、
  不写一条 `view_sensitive_data`，就能读到任意用户与任意报警上报人的完整号码——
  上一轮"读接口停发明文"只堵了响应侧，**审计侧是同一条合规通道的另一半旁路**，
  而当时新增的 egress 门禁全绿（它只盯响应体），这正是那条门禁的盲区。
  改的是单一事实来源：`auditLogSanitizer` 与 `middleware/security.js` 的两条脱敏流水线、
  以及 morgan 的 URL 打码（`isCredentialQueryKey` 取并集）同时生效，
  扁平 `phone` / 嵌套 `reporter.phone` / camelCase `workPhone` / 敏感键装数组四种形态一起收，
  `?phone=` 在访问日志里同步打码。既有用例 `auditLogSanitizer.test.js`「真实中间件驱动」
  按名单逐键构造请求体，因此**免费**获得了对 `phone` 的端到端覆盖。
  不误伤边界保持原样：`postcode` / `zipcode` 不含 `phone` 子串，值仍可读。
  门禁：`src/tests/models/auditLogSanitizer.test.js` 新增一组 5 条（形态覆盖 + 键名噪声 +
  不误伤 + query/URL 同口径），`src/tests/security/userPhoneMaskedEgress.test.js` 新增一条
  **真实路由**用例（发一次带明文的 PUT → `auditBuffer.flush()` → 读回审计行，
  断 `body.phone === '***'`、序列化不含明文，并用 `body.realName` 证明不是"整块抹掉"）。
  变异实测：从名单里删掉 `phone` ⇒ 4 条同时转红（含真实路由那条），恢复后 12/12 + 11/11 绿。
- **如实声明的残留**：脱敏判定只看**键名**，不做值形态扫描。因此装在非敏感键下的号码
  （`{contacts:['139…']}`、备注文本里的号码）仍会进审计副本——这是刻意止步，
  不是漏网：按 11 位正则扫值会连带抹掉报警描述/备注里的号码，取证价值损失大于收益。
  该边界已写成一条可执行用例（「如实声明边界」），要跨过它需要单独拍板。
  `AuditLog` 里的**历史**明文行不会因本改动消失，清理属数据迁移议题，另行决策。
- 消费方核实：全仓非测试代码只有 `securityAlert.js:84` 按 `body.ipAttempts` 取数，
  没有任何逻辑依赖审计 body 里的手机号可读；现有测试无一断言审计副本含明文号码。
- 文档同批（lane-C #8 的实证条目）：`controllers/securityController.js` 里三处注释错位——
  「举报异常行为 POST /security/report」的标题悬在空处、举报核验的整段 JSDoc（含 `@returns`）
  挂在 `REPORT_TARGET_KINDS` 这张**对象表**头上、还有一段描述 `buildAuditLogQuery` 的 JSDoc
  紧跟在 `getRegistrationConfig` 的文档之前（该函数早已搬到 `utils/auditQuery.js` 的
  `buildAuditQuery`，全仓不存在同名符号）。按"注释只描述它紧邻的代码"重挂，
  并删掉那段失效的构建器文档。改动纯注释：逐行比对确认代码行零差异（只少一个空行）。

### 修复（2026-10-02 · 管理员用户读接口停发明文手机号，改走「脱敏下发 + step-up 揭示」）

> 背景：上一轮把 `reporter.phone` 从报警读出路径摘掉后，同一列在**用户管理**上更严重：
> `models/User.js` 的 `phone` 有 getter 透明解密，且 schema 的 `toJSON/toObject` 只设了
> `getters:true` 没有 `transform` ⇒ 任何**不带投影**的读取都会把明文号码整体发出去。
> 原 `User.RESPONSE_EXCLUDE` 排了 password/phoneKey 等 9 项却**没排 phone**，
> 于是列表 / 详情 / 建号回显 / 改号回显 / 角色回显**五条路径**全部明文下发。
> 后果不只是"看得到"：明文一旦进列表，`POST /api/security/view-sensitive`
> 那条专为手机号建的合规通道（step-up 二次验证 + `view_sensitive_data` 审计 +
> 审计写失败即不返回明文）就被彻底架空——想查号码的人不需要口令，翻页就行。
> 拍板口径：**表格默认脱敏 + 按需 step-up**（用户明确选择服务端一起收窄，不是前端打码）。

- `models/User.js`：`RESPONSE_EXCLUDE` 改为由字段数组拼出，新增 `-phone` 进默认排除；
  派生出 `RESPONSE_EXCLUDE_PHONE_VISIBLE`（同一份数组**滤掉** `-phone`）。
  用数组而不是对字符串做 `replace(' -phone','')`：字符串手术在字段顺序变动时会**静默失配**，
  失配后的表现恰好是"明文照发、门禁照绿"。变体名字本身就写着危险，注释规定它只能与
  `toMaskedAdminUser` 配对使用。
- `services/userService.js`：新增读模型 `toMaskedAdminUser(doc)` —— `phoneMasked =
DataMasking.maskPhone(obj.phone)` 后 **`delete obj.phone`**。四个管理员读函数
  （`listUsers` / `getUserDetail` / `getCreatedUser` / `getUpdatedUser`）改用
  `RESPONSE_EXCLUDE_PHONE_VISIBLE` 并统一过这个函数：投影留着 phone 是为了让**解密 getter
  在服务端跑一次**，脱敏只在服务端这一处做——`maskPhone` **不幂等**（对 `138****5678`
  再打一次得到 `****`），所以前端一律不再打码，只做展示。
- **响应字段改名成 `phoneMasked` 而不是 `phone: 脱敏值`**（有意偏离 `my-info` 的既有口径）：
  编辑对话框会把行对象灌进表单，而 `userController.js` 用 `if (phone !== undefined)` 落库、
  路由校验是 `/^1[3-9]\d{9}$/` ⇒ 叫 `phone` 的展示值只有两种结局，且**都是坏的**：
  原样回传被 400 拒掉，或被当成"用户想清空号码"抹掉真值。改名让"这是展示值、不是可写字段"
  在类型上就不可能被搞混。
- `web-admin/src/views/UserView.vue`：列表列读 `phoneMasked`；编辑对话框**不再回填**手机号，
  改为输入框旁一个「查看完整号码」→ 二级 step-up 弹层（只收当前登录口令）→
  `POST /api/security/view-sensitive` 返回的 `full` 才进输入框。提交按**脏字段**发键：
  未揭示 / 揭示后未改 ⇒ 不发 `phone`；揭示后删空 ⇒ 发 `''`（这才是真的清空）。
  提示语随 `phoneBaseline` 切换，两处状态各自说清"留空即不修改"和"已载入现值"。
  step-up 的口令由 el-dialog `@closed` 单一清理点负责（打开时再清一次是冗余，
  冗余那处会让清理逻辑被改坏时测试照样绿）。
- **有意的边界，不一起收窄**：自助通道 `GET /api/auth/me` 与 `PUT /api/auth/profile`
  仍返回本人明文号码——那是用户自己的数据、且编辑页需要现值；`utils/permissionHelper.js`
  处早已写明"回填脱敏值会污染数据或阻断保存"。这条边界用一条**反向**用例钉住
  （`/auth/me` 必须还能拿到明文），免得下一个人"顺手统一"。
- 消费方核实：web-admin 里 `users.getList` 的 phone 只有 UserView 一处读，ProfileView 读的是
  `/auth/me`，RegisterView 是自己的表单 ⇒ 停发零界面功能损失。搜索侧无残留 oracle：
  列表 `search` 的 `$or` 只覆盖 username/email/realName，`phoneKey` 全仓**无** `find({phoneKey})`
  （`models/User.js:270-277` 已记为"已供未接"）。
- 文档同批：`openapi.json` 建号请求体的 `phone` 补 description「仅接受写入；
  列表/详情/建号/改号/角色回显返回 phoneMasked，不含该字段」（`src/docs/generate.js` 重生成）。
- **门禁**：新套件 `src/tests/security/userPhoneMaskedEgress.test.js`（10 例）——
  夹具自证（不带投影的裸读确实能拿到明文，证明排除不是空转）/ 两条投影只相差 `-phone` /
  五条响应路径逐个断言 `'phone' in payload === false` **且** `JSON.stringify` 不含明文
  **且** `phoneMasked` 值正确（只断言"没有"会让整列被删也测成通过）/ 边界自证
  （省略键 ≠ 清空；把 `139****1122` 提交上去必须 400 **且库里原值未变**）/
  view-sensitive 揭示与 `/auth/me` 两条反向钉 / 源码文本闸：`RESPONSE_EXCLUDE_PHONE_VISIBLE`
  出现处必须紧邻 `toMaskedAdminUser`（防"换投影忘了脱敏"），并钉住 `delete obj.phone;`。
  变异实测三臂：摘投影 → 5 红；摘 `delete obj.phone` → 2 红；把变体名改回基名（模拟漏接）→ 1 红。
- 前端门禁：`userView.test.js` 新增 9 例（脱敏列渲染 / 新增框无揭示入口 / 空口令不发请求 /
  揭示请求形状 / 揭示后不改不发键 / 揭示后删空发 `''` / 揭示失败不污染也不误发 /
  口令不跨次残留 / 关外层时二级弹层一并收起）。step-up 是嵌套对话框，`append-to-body` 后
  节点挂在 body 上，"是否关闭"只能断言 overlay 的 `display` 终态——EP 关闭后 DOM 仍在，
  断言节点消失会得到一条恒真的假绿。变异实测三臂：提交无条件带 `phone` → 3 红；
  列改回 `row.phone` → 1 红；摘掉 `@closed` 清理 / 摘掉外层关闭 → 各自对应那条红。
- **如实声明残留**：库里仍是可解密的密文（本改动只收窄**下发面**）；操作者**本人**的明文手机号
  仍会写进 `localStorage.currentUser`（`/auth/me` 的形状），是否连浏览器持久化一起收窄
  需要单独拍板——它会改变刷新后 ProfileView 的短暂空值表现，且 email/realName 同批同性质。

### 修复（2026-10-02 · 报警读出路径停发 `reporter.phone`）

> 背景：四路逐行审计的 lane-B 报出一条新缺陷并回源核实。`FireAlarm.reporter.phone`
> 是**明文存的第三方手机号**，不属于 `models/User.js` 那套「getter 解密 +
> `POST /api/security/view-sensitive` step-up + `view_sensitive_data` 审计」通道；
> 而报警的读出路径原本一条根文档投影都没有 ⇒ 任何持 `alarm:read` 且落在该条范围内的
> 账号都能**整页批量**读到它，无二次验证、无 `system:read`、无留痕——把仓里专为
> 手机号建的合规通道架空。同一 model 上的 `handler.phone` 正因同样理由被收窄过
> （`alarmDetailHandlerPii.test.js`），这条是同一列的邻接漏点。
> 拍板口径：**读出全部停发**（对齐 handler.phone 先例），不做静态加密改造。

- `services/AlarmService.js`：新增模块级 `ALARM_READ_SELECT = '-reporter.phone'`，
  **八处**调用点全部引用同一个常量——游标列表 / offset 列表 / 详情用 `.select()`，
  五个处置接口（dispatch/arrive/resolve/false-alarm/cancel）用 `options.projection`。
  后者是这次真正容易被漏掉的部分：它们把 `findOneAndUpdate` 的 `updated` 文档原样回给
  客户端，只修列表与详情等于同一列从这五个口整块漏出去，而 CI 仍全绿（那五个响应体
  本来没有用例读过）。
- **有意的例外**：`POST /api/alarms/report` 回显 create 出来的文档，其中含提交者自己
  刚写进去的号码——不构成新的读取，故不改（已把这条写进常量的 JSDoc，免得被当成漏点
  重新发现或"顺手补上"）。
- **如实声明残留缺口**：值仍明文存在库里；备份转储与密钥轮换的保护缺口**不随本改动关闭**。
  将来若要开放"回拨上报人"，正确做法是给它一条与 User PII 同级的揭示通道，
  而不是把这一列加回读接口。
- 消费方核实：web-admin 全文 0 处读 `reporter.phone`/`reporterPhone`，报表导出只取
  `reporter.name`（`reportExportService.js:266`），e2e 0 处 ⇒ 停发零界面功能损失。
- 文档同批：`models/FireAlarm.js` 的 `reporter.phone` 注释写明"明文存储 + 读接口不回传"，
  `openapi.json` 的请求体字段补 description「仅接受写入，列表/详情/处置响应均不返回」。
- **门禁**：新套件 `src/tests/services/alarmReporterPhoneEgress.test.js`（7 例：
  夹具自证裸查询能拿到明文 / 详情 / offset 列表 / 游标列表 / 五个处置回显 / 状态机前提自证 /
  源码文本闸）。每条排除断言都带反向证据（`reporter.name` 必须还在），防止"整个子文档被
  删了"或"populate 没生效"伪装成通过。源码闸的窗口取「到下一个调用点为止」而不是固定字数
  ——`resolveAlarm` 的 `$push` 文案块就比 420 字符长，固定窗口会对正确的代码报红。
  变异实测两臂：摘掉详情的 `.select` → 行为与源码闸 2 红；只摘 `cancelAlarm` 一处的
  `projection` → 处置回显 + 状态机自证 + 源码闸 3 红（证明"只修一条"确实会被抓住）。

### 测试（2026-10-01 · 两处 HEAD 上就存在的红灯）

> 全量 `npx jest --ci` + `npm run format:check` 复跑时发现：不需要本轮任何改动，main 上已经有
> 三条用例与一条格式闸是红的。CI 跑这两条（`ci.yml` 的 jest 与 `:79` 的 format:check）⇒ 合并队列
> 上任何后续提交都会被这两处**别人的**失败误判成"本提交引入的回归"，所以先修它们。

- **`websocketRedisAdapter.test.js` 落后于 Redis 认证改造（2 例红）**：`2816d68` 给订阅端补了
  `password: sharedCache.redisConnectionPassword()`（`websocketService.js:260`），但该套件的
  `jest.mock('../../services/sharedCache')` 工厂只造了 `isRedisEnabled`/`getRedisClient` 两个键。
  失败形态很有教育意义：第一条是 `toHaveBeenCalledWith` 的对象不匹配，第二条**不是**它声称要测的
  "挂载失败降级"，而是桩自身缺键抛出的 `sharedCache.redisConnectionPassword is not a function`
  被 `catch` 吞掉后进了同一条 warn 分支——断言只匹配 `stringContaining`，于是"桩坏了"伪装成
  "降级路径测过了"。收口：桩补该函数并返回哨兵值，断言要求哨兵出现在 `new Redis` 的 options 里
  （`toHaveBeenCalledWith` 是全等对象匹配，多键/少键/漏传都红 ⇒ 这条现在是"口令必须外发到
  订阅端"的真闸，而不是只让套件变绿）。
- **`piiEncryption.test.js` 格式（1 条格式闸红）**：`4402562` 移除未使用导入时留下了未过 prettier 的
  解构折行。本轮只做格式化（1 增 6 删，零行为变化）。

### 修复（2026-10-01 · `POST /api/security/report` 的目标核验与账号配额）

> 背景：该端点刻意不挂权限码（人人可举报是产品设计），但路由注释自称「本人资源…无越权面」
> 是**假的**——上报内容由调用者撰写，`targetId` 指向的却是别人的记录。修复前任何登录用户
> 都能提交任意 `targetId`（不校验存在性、不校验范围、无独立配额），服务端原样写进一条
> `riskLevel:'high'` 的审计行，而安全概览的「高风险操作数」与告警取数都读这批行。

- **路由层**：`targetId` 的形态由 `targetType` 决定——记录型（user/device/alarm）必须是非空
  字符串且为 ObjectId；`system` 型**禁止携带**（否则把类型改成 system 就绕过整条核验）。
  `.exists({ values:'falsy' })` 承担的是文案而不是拒绝：删掉它后面的 `isString` 会给同一个
  400 和同一个 path，变异实测确认「只看状态码+path」的用例是绿的但不设防，故用例断言 msg。
- **控制器**：记录型目标必须**真实存在**（否则 404，`USER_NOT_FOUND` 在注册表里是 401 的
  登录语义，此处显式改 404）且**落在举报人的数据范围内**（否则 403）。范围判定复用
  `rbac.assertRecordInScope` + `DATA_SCOPE_FIELDS` 单一声明，与各自详情/写路径同判据；
  404/403 的先后与 `deviceController.js:122/124`、`alarmController.js:156/158` 的既有口径
  一致（存在性预言机在每条授权读路径上本来就存在，本处不新引入一类泄露）。
  自由文本 `reason`/`description` 不受影响：被约束的是"结构化字段必须是真记录"。
- **限流**：新增账号维度桶 `securityReportUserLimiter`（20 次/15 分钟，键 `report-user:<userId>`，
  不含 IP 成分）。与凭据型姊妹桶同一口径：**并列**而不是把 IP 从组合键里删掉；同样
  **不接** `noteRateLimitHit`（账号桶没有可封的 IP）。阈值刻意不导出：测试里钉死 20 并同时
  校验服务端声明的 `RateLimit-Limit`，改配额会让用例变红而不是自动适配。
- **分层**：数据访问经 services 的 `findScopeFieldsByIds`（`AlarmService` 补该 getter，
  投影 `reporter.userId handler location.building`），控制器不新增直连 model——
  初版直连 FireDevice/FireAlarm 被 `architecture/layeringRatchet` 判红（5→7）后改的。
  连带：`skipGlobalAuditWriteFailure.test.js` 的 `models/User` 桩只提供了 `findById`，
  而 `userService.findScopeFieldsByIds` 的形状是 `find().select().lean()` ⇒ 桩补该链路并返回
  与夹具 `targetId` 同 `_id` 的记录，否则该套件两条举报用例先撞 `TypeError`，
  走不到它要测的审计写入点（全量跑实测到）。
- **门禁**：新套件 `src/tests/security/reportTargetScopeAndLimiter.test.js`（23 例：存在性、
  三条范围臂的放行与拒绝、绕口封堵、配额与 XFF 轮换、trust proxy 前提自证、
  投影完备性静态闸）+ 改写 `reportTargetIdBoundary.test.js`（形状边界，7 例）。
  变异实测 5 臂：中和范围臂→B 组 4 红；摘掉限流→D 组 2 红；删 `.exists`→msg 断言红；
  删 system 反例→绕口封堵红；删存在性→A 组与边界 404 判据 3 红；删投影一列→B/E 同时红。
- 文档同批收窄：`models/AuditLog.js` 的 `targetId` 契约注释、`PERMISSION-EXEMPT` 理由改写为
  如实版本、`src/docs/openapi.json` 重生成（targetId 加 ObjectId pattern + 403/404 响应）。

### 修复（2026-10-01 · 13 项报告回源复核后的三处落地）

> 背景：对一份 13 条的审计报告**逐条回源复核**，其中 8 条已在 19:21~20:50 的提交里闭环、
> 1 条（封禁目标可伪造）在他方在途、4 条未动。本轮落地的是**报告里没有的三处**——
> 两条由复核过程新发现，一条属报告第 13 条所在的低优先段。

- **N1 HMAC_SECRET 消费点清单收敛为单一来源**。复核发现同一份仓库里存在**三份互不相同**的清单：
  `deployment/secret-rotation.md` 写「**两个**消费点」（审计链 + 口令历史），
  `deliverables/AGENT工作总账与待办` 的 F-26 写「三个」（审计链 + MFA 恢复码 pepper + 数据签名密钥，
  **漏了口令历史**），而真实源码是**四个**（`src/utils/auditChain.js` / `src/utils/passwordHistory.js` /
  `src/services/mfaService.js` / `src/utils/encryption.js`）。手册全文 `恢复码` **0 命中**——
  而恢复码是用户丢掉认证器时的唯一逃生门，换钥后静默失效，故障只在"某个人手机丢了"那天暴露。
  收口：① 手册改成四消费点表（含"只有第 1 个有迁移工具"的非对称事实）；
  ② 新增门禁 `src/tests/config/hmacSecretConsumersSingleSource.test.js`——扫描 `src/`（排除
  `src/tests` 与 `src/config` 装载面）里**取值访问** `HMAC_SECRET` 的文件，要求集合恰好等于登记清单，
  并要求手册逐个点名。判据取「取值访问」而非「提到 HMAC_SECRET」：注释/报错文案/校验器里都会出现
  大写 `HMAC_SECRET`，算进来会让清单被噪声撑大、反而失去意义（`services/auditChainVerify.js` 的
  `computeHmac` 是从 `utils/auditChain.js` 导入的，密钥取值不在它那里，故不重复计）
  - 门禁：新套件 9 例（含"扫描基线非空"防"零命中被当成通过"、"手册必须点名恢复码"作回归哨兵）
- **N2 PII v1 存量行的静默缺口补启动期告警**。10-01 把写侧切到 v2（AAD 行绑定）时读侧刻意保留 v1 兼容，
  代价是 **v1 密文与行身份无关**——`utils/piiCrypto.js` 的 v1 分支 `aad` 保持 `null`、`if (aad)` 永不
  `setAAD`，于是把 A 行的 `enc.v1.…` 复制到 B 行，B 行的 getter（`models/User.js:105-106` 虽已传
  `{subjectId, field:'phone'}`）会**正常解出 A 的明文**。写侧不再产 v1，但**存量行不会被自动升级**，
  而升级唯一入口是手工跑迁移脚本，**没有任何启动期信号**（`src/config` 下只有 `pii_rotation_old_key_lingering`
  那条旧钥告警，与"v1 未迁移"无关）。收口：`config/immutableConfigGuard.js` 增加第三项
  `pii_v1_rows_unmigrated`（生产 + PII 主密钥可用 ⇒ 告警 + `incSecurityAlert`，**不阻断启动**，
  口径同 immutable 档位），并写进轮换手册收尾清单
  - **如实声明边界**：该告警的判据是"代码仍支持读 v1"，**不是"库里还有 v1 行"**——启动路径
    （`config/validate.js`）在 mongoose 连接**之前**执行，不连库，故它**不会自行消失**。要判"迁完了没"
    只有一条路：`node scripts/migrate-pii-encryption.js`（演练模式、只读）看剩余行数。这条边界已写进
    手册与告警文案，否则运维会拿"告警还在"误判成"没迁完"
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **2 条反向断言**：非生产不得告警、
    主密钥缺失不得告警）。**变异实测被杀**：把判据改成 `NODE_ENV !== 'never-matches' && true` ⇒
    4 条红（2 条反向断言 + 2 条既有的 `toHaveLength(1)`），改回后 29/29 绿
  - **待拍板（未落地）**：更彻底的做法是把 v1 读路径也改成 fail-closed（镜像 `ALLOW_LEGACY_CBC_DECRYPT`：
    缺 `ALLOW_PII_V1_DECRYPT=true` 即抛），那样"库里有 v1 行"会当场变成响亮的读错误。
    未做是因为它是**生产行为变更**（升级即可能让存量行读失败），按本仓纪律属"需人拍板"那一档
- **#12 上传扩展名闸由 fail-open 改为构造期 fail-closed**。`middleware/security.js` 原实现是
  `allowedExts = allowedTypes.map(t => MIME_TO_EXT[t]).filter(Boolean)` 配 `if (allowedExts.length > 0 && …)`
  短路：白名单里**一个都映射不到**时 `filter(Boolean)` 把结果清空 ⇒ **扩展名校验整条消失**，
  只剩客户端自报的 MIME。今天无 multer 挂载故不可利用，但"配了却不生效"一旦随首个上传路由上线就会同时生效。
  收口：MIME→扩展名映射与校验提到**构造期**（= 路由装配期，即启动期），`allowedTypes` 里存在**任何一个**
  未映射项即抛错（只抛"全部未映射"会把部分静默放行留在原地），运行期不可能再出现"白名单非空但扩展名闸为空"
  的组合，短路判据随之简化为 `allowedTypes.length > 0`
  - 门禁：`securitySanitizeAndBlacklistDegrade.test.js` 追加 5 例（全部未映射抛 / 部分未映射抛 /
    报错点名支持集 / 空白名单不抛 / 受支持白名单不抛——最后两条防"一律抛"的恒真实现），该套件 30/30 绿
  - 已知边界：本次**只**修扩展名闸的 fail-open，未新增任何上传路由；中间件仍是"预留能力、无路由挂载"

### 修复（2026-09-30 · 安全缺口核查落地）

- **敏感 GET 读取审计判据反转（P1-④）+ PII at-rest 加密（P1-②）+ 备份加密（P1-①）等七项缺口收口**（对照 `deliverables/安全缺口核查-2026-09-30.md`，其中 P1-④ 与 P2-⑥ 已于本日早先提交落地）：
  - **P2-⑧ 传输加密启动断言**：生产环境 Mongo 非回环主机必须 `tls=true`、Redis 必须 `rediss:`，豁免走显式旗标 `MONGODB_TLS_EXEMPT`/`REDIS_TLS_EXEMPT`（同宿主 compose 即豁免使用者，拆分拓扑忘摘旗标会被启动期拦截）；判据收口 `config/transportSecurity.js`（回环判定吃 127.0.0.1/::1/IPv4-mapped/localhost 全形态；hostname 解析不出保持沉默——compose 契约测试的替身 URI 不被误杀）
  - **P2-⑨ 出站目标门禁**：`LOG_SHIPPING_URL` 在 scheme 白名单之外再拒内网/回环/链路本地目标（云元数据端点是经典 SSRF 目标）；歧义 IPv4 形态（127.1/2130706433/0x7f.0.0.1，严格解析判 null 但 OS 仍按回环连）一并拒绝；内网 SIEM 用 `LOG_SHIPPING_ALLOW_PRIVATE_HOSTS` 显式放行（主机名/IP/CIDR，与 IP 名单同一把尺）。判据 `isPrivateOrLoopback` 自 metricsAuth 迁入 `utils/ipUtils.js` 单一来源（middleware→utils 反向依赖会破分层）
  - **P1-① 备份加密 + 校验和 + 异地副本**：`backup-mongo.sh` 默认 gpg 非对称加密（备份宿主机只放公钥，私钥托管异地），明文出口 `BACKUP_ENCRYPTION=plaintext-acknowledged`（取值即确认词）；产物三件套 .gz.gpg + .sha256 + `BACKUP_OFFSITE_CMD` 异地钩子（argv 解析不经 shell 展开、失败即整体失败）；`restore-mongo.sh` 按后缀自动解密；加密/解密/校验和收口 `scripts/backupCrypto.sh`（与 mongoUri.sh 同一共享范式）；恢复演练与密钥托管见 `deployment/backup-encryption.md`
  - **P1-② PII at-rest 加密（范围修订）**：`phone` 走随机 IV AES-256-GCM（`utils/piiCrypto.js`，密文带 `enc.v1` 版本前缀供轮换），精确检索走 HMAC 检索键 `phoneKey`（select:false + 索引）——相等性不泄漏在密文列里；存量明文**读路径透传**（迁移前的旧行照常可读），写侧 `pre('validate')` 钩子加密（手机号格式校验随钩子前移到明文阶段，错误文案逐字不变）；迁移/轮换脚本 `scripts/migrate-pii-encryption.js`（演练/apply 双模，损坏行点名不覆盖，同族 allowlist 门禁）。**realName 暂不加密**（2026-09-30 决策）：姓名片段模糊检索是用户列表的日常能力，正则对密文不成立，加密它等于砍掉该能力——用户列表搜索继续覆盖 username/email/realName；`realName` 转入加密需先给姓名检索另立方案，脚本对加密窗口内已产生的密文行自动解回明文自愈
  - **P2-⑩ 供应链可追溯**：CI 构建产出 CycloneDX SBOM 并上传 artifact；镜像 `provenance: true` + cosign keyless 签名（build 作业补 `id-token: write`）
  - **P2-⑫ 依赖钉版**：`.npmrc` `save-exact=true` 从源头杜绝 caret 漂移；新增 CI 硬门禁「生产依赖树禁止任何 install 脚本」（`scripts/check-prod-install-scripts.js`，fail-closed + 显式白名单——比 --ignore-scripts 更强：ignore-scripts 只让本机跳过，树里有没有脚本没人看）
  - **P3-⑬⑭⑮ 治理文档三份**：`docs/threat-model.md`（STRIDE + 残余风险如实申报）、`docs/incident-response.md`（角色/时限/命令级遏制清单，全部绑定本系统实际存在的端点与脚本）、`docs/mlps2-controls.md`（等保 2.0 第三级重点项对照，每条挂文件/测试/端点证据）
  - 门禁：`transportTlsAssertion`（9 例）/ `backupEncryptionContract`（stub gpg 行为链）/ `piiEncryption`（纯判据 + 真实 Mongo 接线，9 例）/ logShipper 出站目标真值表（27 例）等新增约 60 例；既有 backupTransport/backupScriptGuards 夹具显式声明明文确认出口，保持其原断言对象不变

### 修复（2026-09-30 · 供应链完整性锚 + PII 旧钥残留守卫）

- **P2-⑩ 补：lockfile 完整性锚**（`scripts/check-lockfile-integrity.js` + `deployment/lockfile-anchor.json` + `npm run check:lockfile` + CI `security-audit` 一步）。已有的 SBOM/cosign/provenance 回答的是「我用了哪些组件」与「镜像来源可证」，但**不比对「依赖树与上次拍板时是否一致」**——一个夹带改 `integrity` 的 PR 会被 SBOM 忠实记录、却被当成正常构建。本锚把「上次人工拍板时锁文件长什么样」固化成哈希写进版本库，任何改动必在 diff 现形。判据口径是 **semantic 哈希**（`JSON.parse` → key 排序 → 紧凑序列化 → SHA-256）：**用原始字节哈希会在 CRLF/LF 间漂移**（开发机 Windows/CI ubuntu），后果不是「偶尔红」而是 **CI 恒假红**，而假红第一次出现就会被 `continue-on-error` 消化掉、等于没有门禁。覆盖面 2 份（后端 + `web-admin`；`zznpmtest/` 已 gitignore 故不纳入）。fail-closed：锁文件缺失/解析失败/锚缺失一律 exit 1
  - 门禁：`src/tests/deploy/lockfileAnchor.test.js` 11 例，真调脚本导出的纯函数（**不复刻判据**）；核心是「同一 JSON 的 CRLF 与 LF 版本必须同哈希」——把上述决定性实验固化成回归闸。篡改一处 `integrity` 实测 `exit=1` 且报错点名文件与期望/实际值
  - **如实声明边界**：本锚**不是 SBOM**，挡住的是「锁文件被改」，**挡不住「上游包本身被投毒且 lockfile/integrity 未变」**
- **P1-② 补：PII 轮换旧钥残留守卫**。`scripts/migrate-pii-encryption.js:48-53,106` 把 `PII_ROTATION_OLD_AES_KEY`（**旧主密钥明文**）作为 `--rotate` 的输入参数，但**没有任何地方要求轮换后清理它**——不在启动校验面、不在轮换手册收尾清单、不在脚本输出里。它是**过程残留物**而非运行时配置：一旦驻留生产环境，**轮换等于白做**（轮换的前提是「假定旧钥已泄露」，而旧钥 + 轮换前备份归档仍可解出当时全部 PII）。三处收口：① 启动期生产环境检测（并入 `config/immutableConfigGuard.js`，**告警 + `incSecurityAlert`，不阻断启动**——口径同 immutable 档位，它可恢复而阻断会让疏忽变成停机事故）；② 轮换手册收尾清单加一条；③ `--rotate --apply` 成功且无损坏行时脚本主动打印清理提示（运维跑完就在看这个输出，命中率最高）。空串/纯空白判为「无残留」（`.env` 写 `KEY=`、compose 传空值是常见 unset 等价物，判成残留会造成恒真误报）
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **4 条反向断言**：无旧钥不得告警、非生产不得告警、空串不得告警、无残留不得顶掉既有告警）。**4 组变异全部被杀**（去掉生产条件 1 红 / 去掉空串判断 2 红 / 守卫恒真 6 红 / 去掉 `incSecurityAlert` 1 红）——反向断言不是摆设
  - 同时记录一处会咬人的内部行为（非缺陷）：`--rotate` 执行期间脚本把 `AES_SECRET_KEY` 临时指向**旧钥**（`:106`），结束后恢复；当前是独立 CLI 故风险低，但**勿把迁移逻辑内联进服务进程**，否则轮换窗口内服务会用旧钥加密新数据
- **测试基建：`ciGateWiring` 的门禁清单补防瘦身断言**。`CI_ENFORCED_GATE_SCRIPTS` 此前只有**正向**检查（登记了 → 必须被 CI 调用）。变异实测：删掉清单任一行，套件只是「少跑一条」，**13/13 依然全绿** ⇒ 清单可被静默删行、被删掉的门禁从此无人守护且无任何测试变红。补反向断言：从 workflow 文本抽出实际调用的 `scripts/*.js`，要求全部已登记或已进**显式豁免清单**（豁免附理由，如 `scripts/deploy.js` 是部署脚本、非判定类门禁）。用显式豁免而非放宽匹配，是为了让「为什么它不算门禁」这个判断本身可审计。变异验证：删登记行 ⇒ 1 条红

### 新增（2026-09-30）

- **口令复用历史**：此前 `changeUserPassword` 里只有 `SAME_PASSWORD`（"不能与**当前**口令相同"），A→B→A 这种两步复用完全放行；`helpers.validatePasswordStrength` 只覆盖长度/复杂度/泄露库，全仓零处检查复用。现 `User.passwordHistory` 保存最近 N 条（默认 5，`PASSWORD_HISTORY_DEPTH` 可调，上限 24）**已退役**口令的 HMAC-SHA256 摘要，改密时逐条比对并拒绝，写入被替换掉的旧口令。摘要用 HMAC 而非 bcrypt：历史条目的用途是**等值比较**（比较时明文就在手里），bcrypt 的"慢"是为离线爆破服务的，此处不适用，而代价很实在——rounds=12 下每条 250~300ms、保留 5 条即 1.5 秒且全部挂在改密端点上，而 `passwordChangeLimiter` 只按 user+ip 限到 5 次/15 分钟、**没有全局护栏**，N 个账号就能把 CPU 打满。沿用本仓已有的同类先例 `services/mfaService.hashRecoveryCode`（HMAC + pepper，未配密钥时退化 sha256）。新增错误码 `PASSWORD_REUSED_IN_HISTORY`（400），两个改密端点（`/api/auth/password` 与 `/api/security/change-password`）映射一致，文案里的 N 由后端 `params.historyDepth` 下发，前端不写死数字
  - 已知取舍（如实记录而非假装解决）：轮换 `HMAC_SECRET` 后既有摘要全部对不上 ⇒ 历史长度归零，轮换窗口内复用防线短暂变弱。审计链 HMAC 那套重签工具在这里**不适用**——没有明文就无法重算
  - 门禁：`src/tests/utils/passwordHistory.test.js` 20 例。除判定语义与 A→B→A 行为级用例外，另有**接线不变量**（`.select('+passwordHistory')`、成功后写历史、schema `select:false`、两个控制器 outcome 映射、错误码 4xx、前端登记）——语义测对了而没接线是这类修复最常见的落地失败形态，那时下面所有语义测试仍会全绿

### 变更（2026-09-30）

- **敏感 GET 读取审计判据反转：6 条允许清单 → 默认全量 + 显式豁免清单**（`middleware/security.js` 的 `auditGetPaths` → `auditGetExcludePaths`，收口审计报告 §3.4）。原判据是 fail-open：新增一条敏感 GET 路由而忘记登记即零留痕——设备/报警/巡检的**列表与详情**正是一批这样的盲区（P0 时的 HEAD 归一修复只救了已登记的 6 条前缀；列表与详情共用派生 action `*_view`，故无需新增 action 登记）。反转后 GET/HEAD 默认审计，豁免清单只剩两类、逐条写明理由：a) 预认证/登录流程面（captcha/captcha-status/login-public-key/mfa-status，无业务数据且调用频率由认证流程决定）；b) 纯自读面（session/me/sessions/my-info/bindings/my-logs——数据主体即请求者本人且被前端每次导航轮询，操作留痕由写路径承担：改密/MFA 变更/踢会话均为写方法照常审计）。fail-closed 的直接后果：未匹配路径的 GET 探测与匿名 401 也会在审计里留痕（与既有 `/api/users` 行为一致），审计记录量随读取流量上升属预期成本；运维看板若高频轮询设备/报警列表，按 security.js auditLog 头注口径逐条评估后加豁免，**不回退允许清单**。守卫同步：`auditActionReachability` 台账 A 类 25→9（16 条随反转为真实落库并从台账移除），解析器改读 `auditGetExcludePaths` 并反转判定
- **CC 防护升级：限流信号按类别分桶，阀值差 10 倍**（`src/services/rateLimitEscalation.js`，拆出 `rateLimitEscalationBan.js`）。此前全仓只有**一个**阀值（30 次/5 分钟），而喂进这个计数器的 7 个限流器**合法拒绝率相差两个数量级**——把「30 次 captcha 拒绝」与「30 次任意请求拒绝」当成同一种证据。实际后果是两条具体的误封：① `strict` 是**已认证**端点（refresh / MFA / 报表导出 / 审计导出 / 重置他人密码），一个管理员给 20 名新员工批量开户 = 60 次操作，**共享出口 IP 的整间办公室被封 1 小时**——而越界的是账号不是 IP；② `general`/`ip` 是体量信号，其配额在 NAT 共享出口下本就被多人分摊。现分三类各用各的阀值：`ANON_ABUSE`（captcha/login-ip/register，默认 10，封 IP）、`VOLUME`（general/ip，默认 **100**——原取 30 时这一档被误伤，100 才是它的量纲，封 IP）、`AUTH`（strict/user-ip，默认 30，**只告警不封 IP**，处置走账号侧）。混检不提前：10 次 captcha + 90 次 general 不会让 ANON_ABUSE 到点
- **固定窗口 → 令牌桶**（同上）。原实现的固定窗口有两个固有缺陷：**边界突发**（窗口末秒打满 N 次、次秒重开再打 N 次可取到 2N 速率）与**升级即清零**（达阈值后 `count = 0; windowStart = now`，封禁若恰好失败则下一轮又白拿一整个窗口）。令牌桶按 `阀值/窗口` 匀速回填，两个缺陷一并消除；持续速率恰好等于阀值的攻击者不再触发（等于预算本就不该被封）。代价是纯突发打满 N 次要第 N+1 次才封——这是去掉时序后门的代价，不是弱化
- **处置与通知解耦**（`src/services/rateLimitEscalationBan.js`）。原实现 `if (!shouldSendAlert(...)) return;` 把**审计与封禁一起挡在门外**：封禁失败（写库故障 / 命中白名单）时 5 分钟内的重试也被吞掉，而审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 档」。现审计与封禁无条件执行，只有 `dispatchNotification` 受频控约束
- **计数表淘汰：`clear()` → 压力升序有界淘汰**（同上）。`hits.clear()` 是一条**可主动触发的旁路**：攻击者轮换满额 IP 就能把所有人的计数归零。改为先清已回填的，仍满则牺牲「最接近升级」程度最低的条目。刻意**不按最旧优先**——那同样是旁路：被牺牲的会是积累已久、正要升级的那条，而攻击者新轮换进来的垃圾（压力 1）反倒留在表里。淘汰顺序必须由**安全价值**决定，不由时间决定
- **审计记全量构成**（同上）。原实现只把**触发阀值的那一个限流器**写进 `body.limiter`，于是「10 次 captcha + 20 次 general」被记成「general 触发」，事后复盘归因错误。现写 `body.mix`（各限流器计数）+ `body.total` + `body.className`
- 新增 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH` / `CC_ESCALATION_EVICT_RATIO` 五个环境变量（此前 `CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 已于本轮移除），`.env.example` 补全分类判据与推导依据

### 修复（2026-09-30）

- **immutable 档位（改配置需配套数据迁移）在启动期完全静默，运维改了配置直接重启无任何提示**（新增 `src/config/immutableConfigGuard.js` + `src/tests/config/immutableConfigGuard.test.js` 10 例）。`HMAC_SECRET` 在本仓有两个消费点：审计链 `hmac`（有 `scripts/resign-audit-hmac.js` 重签工具可迁移）与**口令复用历史摘要的 pepper**（`utils/passwordHistory.js`，**没有也不可能有配套工具**——历史里存的是 `HMAC(旧钥, 旧口令)` 的 hex，无明文无从重算）。`deployment/secret-rotation.md` 的「各密钥轮换影响面」表只写了前者，收尾清单也没提后者 ⇒ 运维照 Runbook 做完全量轮换，口令复用防线已归零而手册不吭声。现启动期推一条 warning（文案点名 pepper / 历史归零 / 无重签工具 / 指向手册），并计 `incSecurityAlert('password_history_pepper_rotation','medium')`——口径与 `ALLOW_LEGACY_CBC_DECRYPT` 的既有加固完全一致（"可检测 ≠ 已告警"）。**刻意不阻断启动**：该配置的合法取值本身包含"已知代价"那一档，要拦的是**静默**不是取舍。手册同步补该影响面小节、收尾清单条目，以及 `PASSWORD_HISTORY_DEPTH` **调小**（唯一不动密钥却同样让存量对不上的项，`sanitizeHistory` 读取侧截断）的说明。**实测变异验证**：把 immutable 的 push 塞进 CBC 的 `if` 块 ⇒ 2 条红；去掉 `incSecurityAlert` ⇒ 1 条红
- **安装脚本门禁的可证伪性为零（"测试复刻了一份判据"）**（`scripts/check-prod-install-scripts.js` / `src/tests/deploy/installScriptGate.test.js`）。该门禁是 Dockerfile 里 `npm ci --omit=dev --ignore-scripts` 安全性成立的**唯一依据**，而它初版的测试把判定语义**复刻**了一遍（自写 `classify`），注释还自称"可证伪"。**实测证伪**：把筛选条件 `omitDev ? !e.dev : e.dev` 写反（生产树与 dev 树颠倒 ⇒ 门禁退化成"永远失败"），复刻版测试 **6/6 全绿**。这是一类通用的失效形态——复刻一份判据等于测试了一个平行实现，与被测对象是否还正确无关。现脚本导出纯函数 `evaluate(lock, omitDev)` 并加 `require.main === module` 守卫，测试**真调**它；同一变异下 6 条变红。另：白名单按依赖树分两档（生产树命中即红 / dev 树逐个登记理由），判据改用 `package-lock.json` 的 `hasInstallScript` + `dev` 标记（实测 `npm ls --json` 的节点**不含 scripts 字段**，1317 节点 0 命中，故不能作判据来源）、白名单登记 `@scarf/scarf`（锁文件 `dev:false`，经 swagger-ui-express 传递引入生产树）与 `mongodb-memory-server` / `fsevents`
- **`npm ci --ignore-scripts` 的落点（CI 4 处 + Dockerfile 3 处，逐处给判据而非一刀切）**：`Dockerfile` 三处**全加**（builder 阶段从不跑测试、web-builder 与 runtime 均与 mongod 无关，且 runtime 那处由 `--omit=dev` 档门禁保证"没有脚本需要忽略"），`migrate-mongo` 补装命令一并加。CI 侧**刻意只给 e2e-browser 加**（其 Mongo 来自 `mongo:6.0.20` service 容器，不依赖 `mongodb-memory-server`）；`test` 与 `e2e` 作业**不加**——它们真的需要内存 Mongo 的 mongod 二进制，跳过安装脚本会把「安装期一次性下载」挪进 jest worker / 脚本进程，而本仓已有 `mongodb-memory-server` 子进程句柄与 jest 退出竞态的实证记录（`ci.yml` 的 `--forceExit` 头注）。判据：跳脚本不会让 `npm ci` 失败（`postinstallHelper.js` 失败路径是 `process.exit(0)`），代价是时序面，不是安装成败- **`checkBruteForce` 的通知频控挡在审计与封禁之前（与 CC 那条线同源，是同一轮修法的漏网）**。`securityAlert.js` 里两行 `shouldSendAlert`（账户维度 + IP 维度）排在阶梯统计 / 审计落库 / `addToBlacklist` **之前**，任一命中即 `return`，把三件事一起关在门外。后果不是少一条通知：① 封禁**失败**（白名单命中 / 黑名单写库故障）时 5 分钟内的重试被这行吞掉——而"封禁没生效"恰恰最需要重试；② 审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 次」。修法与 `rateLimitEscalationBan.js` 同一条纪律：**统计 / 审计 / 封禁无条件执行，频控只约束 `dispatchNotification`**。两个去重键保持内联（键里同时含 username 与归一化 IP）且短路语义逐字保留（`||`——任一维度放行即投递，改 `|` 会多消费一个 key 使抑制变强）。**实测变异验证**：把闸移回原位后 2 条用例红
- **`checkPermissionAbuse` 只告警、不封任何东西（唯一一处"跨层探测已认证权限边界"的哨兵没有遏制手段）**（新增 `src/services/securityAlertPermissionAbuse.js`）。该检测器此前整条路径只有「审计 + 通知」，另两个检测器都有封禁动作。缺口是：攻击者只要拿到一份**有效凭据**，把权限探测压到每 5 分钟 < 20 次，就能永久试探权限边界——每次都不达阈值 ⇒ 无告警、无审计、无遏制（20 次/5 分钟这条阈值只挡"不会隐藏自己的人"）。现达阈值时对**来源 IP** 走与暴力破解同一条渐进式封禁阶梯（1h→4h→24h→7d），事件源是独立的 `action=permission_abuse`（与 `brute_force_login` 分账，各数各的，只共用时长档位与 30 天窗口，新增 `IPBanEvents.countPermissionAbusePrior`）；无 IP 上下文时只告警不封（不得把 `undefined` 当 IP 封）。同样的处置/通知解耦、同样的"先读阶梯后写审计"、同样的按返回值分派（F-160 口径：`addToBlacklist` 从不抛错，白名单/写库失败时"已封禁"日志就是纸面防线撒谎）。处置侧整块抽到新文件是体积债收口（`securityAlert.js` 净代码行已贴 300 上限）。**实测变异验证**：跳过封禁后 3 条用例红
- **出站告警契约闸的两处能力缺口**（`src/tests/services/outboundAlertContract.test.js` / `fireAndForgetAlertSingleEntry.test.js`）：① 判据只认**裸** `ALERT_TYPES.X`，不认带模块前缀的 `securityAlert.ALERT_TYPES.X`——而后者语义完全等价且跨模块调用时必须用；`auditChainMonitor.js` 的调用点原是三表达式，拆成 if/else 后双闸齐红。现解析器接受可选前缀（键的真实性仍逐条校验）。② `sendNotification` 白名单未登记 `auditChainMonitor.js`（它是第二个 `await` 侧调用点，要拿投递结果做自己的记账），按该闸的设计意图显式登记。**注**：这两处是上一轮审计链守护闭环引入的欠账，非本轮新增缺陷
- **`backgroundJobs.test.js` 的频控断言钉的是被修掉的旧行为**：原断言「5 分钟频控窗口内第二次检测不再写审计」，正是上面第一条缺陷的形状。已改为「通知不重复，但**审计必须照写**」（`after === before + 1`）；另把 `securityAlertWriteFailureTolerance.test.js` 的"写入成功不打 error"反向对照显式桩掉封禁链路——该用例的命题是"审计写入成功"，不该被"这个 IP 恰好能不能被封"污染
- 门禁：新增 `src/tests/services/securityAlertContainmentDecoupling.test.js`（7 例：频控命中时审计/封禁照做、封禁失败后重试不被吞且阶梯升档、权限滥用必须真的封 IP、权限滥用阶梯独立分账、无 IP 不封、两条 `shouldSendAlert` 位置文本闸）

- **`auditChainMonitor.runVerification` 的函数体积债（101/100，上一轮的欠账）**：该文件是未跟踪新文件，不在棘轮基线里，于是它的 `max-lines-per-function` 超标要到下一次全量跑才暴露。把「告警投递」整块（`noticeData` 组装 + 按 `hasBreaks` 的 if/else 静态分派）抽成 `dispatchChainAlert`——拆函数正是本仓对体积债的既定处置。顺带把「档位/类型不得写成三元表达式」这条约束的注释挪进新函数，让它有独立的注释位而不容易被后来的重构顺手"简化"掉。行为逐字不变（`outboundAlertContract` / `fireAndForgetAlertSingleEntry` / `auditChainGuardedIntegrity` 三套件 31 例全绿）
- **补上一轮遗漏的 prettier 格式**（`auditChainMonitor.js` / `securityAlert.js` / `auditBufferFlushAndWalGuards.test.js` / `securityAlertContainmentDecoupling.test.js` 四文件）。`npm run format:check` 自那轮起就是红的

- **`web-admin/src/tests/build/` 被 `.gitignore` 的 `build/` 规则吞掉，一份正牌回归测试从未进过 CI**。该目录下是 `manualChunks.test.js`（P2-52 回归，4 例，直接 `import` 真实 `vite.config.js` 调 `manualChunks`，注释里记着实测更正与反证记录）。`.gitignore:46` 的 `build/` 是为构建产物加的，而它**无前导斜杠 ⇒ 匹配任意层级的 `build` 目录**，于是测试目录被一起吃掉。后果是它在本地跑、在 CI 上根本不存在（本地前端 1431 例含它，CI 从未执行）。已把目录改名为 `web-admin/src/tests/bundling/`（不改 `.gitignore`：`build/` 规则本身有其必要，不该为一个测试目录放宽）
- **门禁：测试树纯净性**（新增 `src/tests/ci/testTreePurity.test.js` 5 例）。`testMatch` 是「任意层级下的 `src/tests/` 里的 `*.test.js`」，因此放在那里的**任何** `.test.js` 都会被执行——包括从未提交、只是调试时落下的草稿。这类失效形态是"不出错、只污染信号"：草稿的 pass/fail 混进总数，而**本该入库**的用例一旦漏 `git add` 则是本地全绿、CI 上压根不存在。两条方向相反的判据：未跟踪 ⇒ 报红（给出"入库或挪出"两条出路）；已跟踪的 `zzz-*.test.js` ⇒ 报红（`.gitignore` 只约束未入库，管不住 `git add .`，而当初那批 8 个探针 / 591 行 / 51 test / 0 expect 正是这么进去的）。判据用 `!tracked.has(f)` 而非 `ls-files --others --exclude-standard`：**被 gitignore 误伤的文件正是本条门禁上线当天抓到的第一个案例**，用 `--exclude-standard` 它会隐身
- **补上 `d72872c` 漏同步的两处断言**（`auditQuerySharedBuilder.test.js` / `auditQueryFindAggregateParity.test.js`）：该提交把 username 前缀查询的上界从「末字符码点 +1」改为追加 collation 哨兵 `U+FFFF`（ICU 排序下前者对 `z`/`Z`/`9` 等末字符构成**空区间**），并同步了 `auditUsernamePrefixIndex.test.js` 的契约，却漏掉了另两处同样断言该 helper 输出形状的用例 ⇒ HEAD 上稳定 2 红。断言已改为钉哨兵形状；哨兵在 collation 下确实恒大于任何 `prefix + <已分配字符>` 仍由 `auditUsernamePrefixIndex.test.js` 的 DB 回归用例负责，不在此处重复造一个纸面断言

- **`req.query` 物化：Express 5 下 query 注入防线此前靠注释撑着**（新增 `middleware/security.js` 的 `materializeQuery`）。`req.query` 是原型上的 getter（`express/lib/request.js: defineGetter(req, 'query', ...)`），每次访问重新解析 URL，于是 `sanitizeMongo` 与 `hpp` 对 query 的原地清洗是**彻底空操作**——实测（Express 5.2.1 + supertest）`delete req.query.search` 之后**同一 handler 同一 tick** 内回读 `Object.keys(req.query)` 仍带 `search`，比 P1-33 记录的"下次访问才丢"更彻底。现改为读一次 → 复用 `deepSanitizeKeys` 清洗 → `Object.defineProperty` 物化成自有数据属性 → **回读自证身份，不等即拒绝请求并 error 级留痕**（物化失效是零报错事件，"服务不可用"远好过带着未清洗的 query 继续服务）。附带收益：解析次数从"每个消费者一次"降到全请求一次。`sanitizeMongo` 已移除对 `req.query` 的遍历——留着只会让人误以为 query 有两道防线
- **静态面限流判据单一来源 + 补上零预算**（`middleware/staticFrontend.js` / `rateLimit.js`）。此前限流侧判据是"安全方法 + 非 `/api/` 前缀"，与 `staticFrontend` 的 `RESERVED_PREFIXES` 是两份独立清单，实测对 11 条非 `/api` 路径有 **8 条判定相反**。逐条核对后真正裸奔的两条：`/socket.io/`（Socket.IO HTTP long-polling 握手是未认证 GET，而 `MAX_CONNECTIONS=1000` 约束的是**已建立连接数**、`authenticateSocket` 在连接建立之后才跑 ⇒ 握手面应用层零限流）与 `/metrics`（`metricsAuth` 允许内网免令牌，而 `app.js` 自陈的威胁模型正是"容器网络内直连 app:3000"）。判据现由 `isStaticSurfaceRequest` 单一来源提供，豁免集合**收窄**（新登记的保留前缀自动重新纳入限流，限流侧无需改动）。另新增 `staticSurfaceLimiter`：静态面此前被整体豁免，而豁免的代价是**零预算**（单 IP 可无限拉 `/assets/*`）；现按"按成本分桶"给它自己的宽松桶（12000 次/15 分钟，按 34 静态请求/页 × 30 人 NAT × 10 次页面加载 = 10200 留 18% 余量推导），429 文案与通用限流刻意区分，且**不接入 CC 封禁升级阶梯**（静态面被限流多为出口聚合，接上去会把误封从单个 IP 放大到整个办公室）
- **门禁：把"注释级约定"变成可执行不变量**（新增 `src/tests/app/queryDefenseSingleSource.test.js` 11 例、`staticSurfaceRateLimitGate.test.js` 17 例）。前者刻意跑在**真实 express 实例 + supertest** 上并含一条**反向对照**（未物化时 `req.query` 确实不是自有属性、确实跨读取不稳定）——因为既有那组 `sanitizeMongo` 单测用的是手搓 `req` 桩，桩上的 `query` 是普通属性，**结构上不可能**发现 Express 5 的 getter 前提；本次同时把该单测里断言 `query: 10` 的那条改成如实反映"query 不再经过 sanitizeMongo"。后者钉住判据单一来源、8 条分歧路径逐条归属、大小写同尺、以及静态面不再是零预算
- ~~**CC 升级封禁阈值 100 → 30，并新增预警档**~~ —— **本条已被上方「变更」段的分类分桶方案取代，保留在此仅说明演进过程**：单一阀值（无论 100 还是 30）的问题不在数值，而在它把 7 个合法拒绝率相差两个数量级的限流器加进了同一个桶；`CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 两个变量均已移除，改为按类别的 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH`。原判断里成立的部分（`generalLimiter` 触顶后窗口内每条请求都是 429、真攻击 5 分钟可刷出数千次）已被吸收进 `ANON_ABUSE` 的推导

- **`package.json` 的 `engines.node` 与前端实际要求对齐**：`>=18` 与 `web-admin` 的 Vite 8.1.4（`engines.node: ^20.19.0 || >=22.12.0`）冲突——声明允许的 Node 18 上 `npm ci` 能装完依赖，但 `npm run build` 结构性失败。改为 `^20.19.0 || >=22.12.0`，与 CI 的 `[20.x, 22.x]` 矩阵、前端 job 的 `24.x`、Dockerfile 的 `node:22.14.0-alpine` 落在同一条区间上
- **`.dockerignore` 补齐被漏掉的构建上下文**：Docker 的忽略模式只从上下文根起算，bare `coverage` **不匹配** `web-admin/coverage`（与本文件必须写全 `web-admin/node_modules` / `web-admin/dist` 是同一条语义），而 `web-builder` 阶段是 `COPY web-admin/ ./` ⇒ 3.2 MB 前端覆盖率报告与 4 个 `coverage-zz*` 残留目录一直进构建上下文与镜像层。同时补 `web-admin/.mimosa`、`.mimosa`、`.jesttmp`（本机 82 MB）、`playwright-report`（9.5 MB）、`test-results`、`.lint-ratchet-selftest-*`、`zztmpctl`/`zznpmtest`（含自带 `node_modules` ~93 MB）与 `.admin-initial-password`（当前超管明文口令，59 字节）。后几项目前因 Dockerfile 走 `COPY` 白名单路径而未泄漏，但任何将来新增的宽泛 `COPY .` 都会一次性引爆

### 新增（2026-09-28）

- **IP 归属地展示（离线零依赖）**：会话管理、审计日志列表、IP 黑白名单等后台界面把裸 IP 翻译为「国家·省·市·运营商」。数据采用 ip2region 官方 xdb（Apache-2.0）入库 `src/data/`（约 11MB，Docker `COPY src/` 一并带入镜像），检索器 `src/utils/ip2regionSearcher.js` 以纯 Node 实现 xdb v2 格式（向量索引 + 二分，全内存约微秒级/次），不引入任何 npm 依赖；`src/services/ipLocationService.js` 负责业务口径（复用 `ipUtils.normalizeIP` 收敛 `::ffff:` 形态、内网/保留地址统一标「内网」含 IPv6 回环/链路本地/ULA、结果 FIFO 缓存 2048 条、任何异常 fail-soft 返回 null）。`GET /api/auth/sessions` 每条会话新增 `location`（最近活跃 IP）与 `loginLocation`（登录 IP）；审计日志两条分页路径与 IP 名单列表逐行补 `location`；前端在 IP 旁以 `·` 拼接展示（后端缺字段/CIDR 网段自动省略）。数据刷新：`node scripts/update-ip2region.js`（Gitee→GitHub→jsDelivr→npm 镜像四级数据源 + 结构校验 + 探针查询 + 原子替换），`--check` 只打印当前数据构建日期
- **CC 防护升级闭环**（`src/services/rateLimitEscalation.js`）：限流从「只挡不罚」变为「可观测 + 可升级」——每次 429 上报 `security_alerts_total{type=rate_limit_triggered}`；同一 IP 在 5 分钟窗口内触顶达阈值（`CC_ESCALATION_THRESHOLD` / `CC_ESCALATION_WINDOW_MS` 可调，**2026-09-30 起已重构为按类别分桶（见上方「变更」段：单一阀值与预警档均已移除）**）即按与暴力破解同一条封禁阶梯（1h→4h→24h→7d，30 天审计事件计数升档）自动封禁。防误封设计：白名单 IP 的资源型限流直接 skip 不会产生升级信号；凭据型账号维度桶不接入（无 IP 可封）；升级链路全程 fail-soft 不拖垮 429 响应。计数为进程内固定窗口（多实例下按实例数摊薄，少封不误封）
- 数据文件入库配套：`check-utf8` 门禁的常见二进制扩展名清单加入 `.xdb`，`.gitattributes` 钉 `*.xdb binary`

### 变更（2026-09-28）

- **限流键统一 IP 归一化**（总账 §4.4「限流键直接拼原文 req.ip」收口）：全部 IP 维度限流器（general/strict/login/ip/user 未认证分支/captcha/register/pwd-change/reauth 及 wellKnown 三个上报限流器）的键改走 `normalizeRateLimitIp`（与名单侧同一把 `ipUtils.normalizeIP`），消除 `::ffff:1.2.3.4` 与 `1.2.3.4` 双桶导致的「同一来源配额翻倍」；歧义写法回退原文自成桶，fail-closed 语义不变。`ipLimiter` 补显式 handler（响应体与原 message 逐字一致，差异仅多升级信号上报）
- **暴力破解自动封禁判据只看 IP 维度**（总账 R-H2）：`checkBruteForce` 此前以 `max(userFailures, ipFailures)` 达标即封禁**当前请求 IP**——分布式撞单账号时把可能只贡献了 1 次失败的 IP（NAT 出口后的无辜用户/受害者本人）封 1 小时。现改为告警与审计照发（双维度都是真实攻击信号，审计 body 含双维度计数），封禁仅在 `ipFailures` 达阈值时执行
- **wellKnownRoutes 三个限流器接入共享存储**（总账 P-9）：`/csp-report`、`/client-errors`、`/.well-known/security.txt` 的限流计数从每实例独立 MemoryStore 改为 `makeSharedStore`（无 Redis 时行为不变），多副本部署下攻击者不再能对每个副本各刷满一份配额

### 测试基线

- 后端：477 个套件 / 4583 个用例文件（2026-09-30 按文件数与 `test()/it()` 声明数实测；此前记的「130 套件 / 1736 例」与 `jest.config.js` 注释里的「280 套 / 3300+ 例」均已失真一个台阶）
- 覆盖率阈值：全局 br 79 / fn 87 / ln 91 / st 91，另 36 个安全关键文件单独设阈；**不复写实时覆盖率数值**——要当前数字看 `npm run test:coverage` 的输出，写死即立刻失真

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
  \t\n'`（循环后还原），并补一条「source 注入 `IFS=' '` + 共谋 tr」
的能红用例（`backupUriFile.test.js` 45→46）。`capture` 是子 shell 执行的脚本、IFS 传不进来，
只在注释写明不对称。
四处判据最终统一为**三条真实载荷腿**（每条腿的失败方向都与「拒绝」一致）：**互补绝对计数**
（允许字节数 + 禁止字节数 == 总字节数；`tr` 不过滤 ⇒ 两边都等于总数 ⇒ 判「检测不可用」）、
**直接数违禁字节**（换行 / NUL / CR 必须为 0 —— 内容相关退化在这条上藏不住）、**`od`逐字节
目视**（不经`tr`/`wc` 的独立字节通道：token 数必须等于总字节数、`0d` 等违禁 token 逐项判定）：

- `scripts/mongoUri.sh::mongo_validate_uri`：`${#_uri}`（shell 内建）交叉 + 互补计数闭合 +
  直接数违禁字节 + `od` token 区间目视（`for … in $var` 解析）。
- `scripts/mongoUri.sh::mongo_hydrate_uri`：`stat -c %s` 与 `wc` 独立交叉、`[ -s ]` 自相矛盾守卫、
  `_n`（行数）形状校验、互补计数闭合 + NUL 直数 + `od` 目视。
- `scripts/capture-image-digests.sh`：同上三腿 + 直接数 CR 字节；`od` 解析用 `for … in $var`
  （第五轮实测：手写 while 对行尾 token 漏计 ⇒ 16 字节边界的 CR 看不见 ⇒ 共谋 `tr` 下 CRLF 被
  静默改写 rc=0；修复后同一夹具「有 7 个 CR」拒绝落笔）。为什么不用 `grep`（第一版就是它）：
  MSYS/Git Bash 的 grep 走文本模式，CRLF 被当成行尾、CR 在匹配前就被吃掉——实测 `LC_ALL=C grep -q
-e "$(printf '\r')"` 对 CRLF 文件返回 1（＝「没有 CR」），那样的所谓独立腿在 Windows 上恒绿。
  `tr`/`wc`/`od` 是字节流、不认行尾，两个平台同一语义。
- `scripts/backup-mongo.sh`：归档字节数先过「非空 + 纯数字」形状校验，再比 `-le 0`。

用例（红→绿→红→绿，逐条变异取证，全部落在上表各条腿上）：`src/tests/deploy/backupUriFile.test.js`
45 条、`src/tests/imageDigestGate.test.js` 62 条（含第五轮新增 3 条：同源共谋 `tr` + CR 全部落在
16 字节边界 ⇒ 必须拒；`od` 桩只吐 3 个 token ⇒ 判「目视不可用」；`od` 对内容说谎 ⇒ 兜底腿仍拒）、
`src/tests/backupScriptGuards.test.js` 11 条。关键变异：摘互补和式 ⇒ 红；摘 NUL 拒绝臂需与 `od`
NUL 臂双摘才红（两臂冗余是设计，单摘时另一臂仍拦）；摘 `capture` 的 `od_cr` 腿 / 直接计数腿 /
token 数腿 ⇒ 各自用例以 rc=0 的 fail-open 复现变红；还原后所有文件 sha256 与改前一致。

> 顺带修正 `src/tests/deploy/backupUriFile.test.js` 的「前提自证：删掉 NUL 闸」用例：它按「第一个 `fi`」
> 定位删除区间，而本轮在它前面插了新腿，冷启动会**删掉半截**、留下悬空的 `_file_nonnull` 引用 ——
> 那正是这条用例自己要防的静默错删。现在按两条 NUL 臂（直接计数 + `od`）各自的 `if` 行成对定位，
> 找不到就抛（判据变了 ⇒ 同步用例），不许静默跳过。

### 修复：权限软删除的「只读墓碑」被写路径绕过（D5，2026-10-30）

> 来源：`work/audit-round3-config-mw.md` 的 D5。

`src/models/Permission.js` 的软删除过滤原本只挂 `/^find/` 与 `countDocuments`，
而模型自己的承诺是「文档永不离开集合、保留期后可复核」——`updateOne`/`updateMany` 一条就能
**就地改掉已删除的行**，`distinct`/`aggregate` 则会把已删除的 code 重新吐出来（审计实测：
`updateOne({_id}, {$set:{name}})` 对已删除文档返回 `modifiedCount: 1`）。

现在把覆盖面扩到 `updateOne`/`updateMany`/`replaceOne`、`distinct`、`estimatedDocumentCount`
与 `aggregate`（管道首部注入 `$match`），并保留两个**显式**放行口子：过滤条件自己写了 `deletedAt`，
或更新文档本身在动 `deletedAt`（软删除/恢复这类状态变更——`permissionService` 的恢复补偿
`updateOne({_id}, {$set:{deletedAt:null}})` 正是这种形态，不能把它吃掉）。
`deleteOne`/`deleteMany` **有意不加**：非测试代码里零调用方，而测试清理与运维删除需要硬删；
把它留给「谁真要在生产硬删已删除的权限」时显式决定（本轮不替未来做决定）。

用例（`src/tests/services/permissionSoftDelete.test.js` 三条）：写路径不命中（活跃行对照命中）、
两条放行口子仍有效、`distinct`/`aggregate` 不泄露。实测变异（撤掉写过滤 + 撤掉 distinct/aggregate 注入）
⇒ 正好两条新用例红（`Expected: 0 / Received: 1`）；还原 ⇒ 10/10 绿。

### 加固：三处「缺 shell 就整组静默跳过」的门禁补上 CI 守卫（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S2 —— 与 `imageDigestGate.test.js:80-89` 的既定先例不一致。

`backupScriptGuards`、`ciProvisionFailurePropagation`、`appEntrypointQueuePermFallback` 三份行为闸都写着
`const group = BASH ? describe : describe.skip`：本机（Windows/MSYS）探不到 POSIX shell 时**整组跳过**。
在本机这是合理的降级，但在 **CI（ubuntu）上探不到 shell 就是探测本身坏了** —— 此时整组零断言的绿
与「这些不变量根本没被验证」是同一件事，而且没人会去数 skipped 的条数。

现在三份文件都补上 `if (!BASH && process.env.CI)` 的守卫：CI 上解析不到 shell ⇒ 直接红（口径同 imageDigestGate 的先例）。
实测（临时让候选表返回空 + `CI=1`）：三份守卫同时红并给出「本文件全部覆盖都是假的」的原因；
恢复候选表后 `CI=1` 下 3 suites / 21 tests 全绿。

### 加固：仓库 shell 脚本的语法闸 + 两处 spawnSync 超时兜底（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的 S3/S4（疑似）。

- **新增 `src/tests/ci/shellScriptSyntax.test.js`（S4）**：每份**已入库**的 `*.sh` 都要用它
  **shebang 指定的解释器**过一遍 `-n`（`#!/bin/sh` 用 `sh -n`、`#!/usr/bin/env bash` 用 `bash -n`），
  并单独钉住 `docker/app-entrypoint.sh` 必须按 **sh（dash 语义）** 检查，不许被 bash 顶替。
  此前仓库只有 workflow 的 `run:` 块有 `bash -n` 闸，脚本本体一个语法判据都没有 ——
  而 `docker/app-entrypoint.sh` 一旦语法错误，后果是**容器起不来**，要等下一次部署才发现。
  反向自证用**同一个** `checkScript()`：造一份少 `fi` 的脚本必须报红、同目录合法的必须绿、
  没有 shebang 的必须判否（不许静默跳过）。实测把 entrypoint 的收尾 `fi` 去掉 ⇒ 闸红并给出 dash 的报错行号；还原 ⇒ 绿。
- **两处 `spawnSync` 补 `timeout: 30000`（S3）**：`appEntrypointQueuePermFallback` 与
  `ciProvisionFailurePropagation` 的夹具子 shell 卡住时，应当红在断言上（超时 ⇒ `status=null`），
  而不是把整条流水线拖到 CI 超时。

### 修复：「工具在不在」的自证 ≠ 「这一次判据能不能执行」（2026-10-30）

> 来源：`work/audit-round3-toolfailopen.md`（第三轮审计对上一轮修复的**再攻击**）。
> 上一轮给两处字节判据装了「工具缺失 ⇒ 拒绝」的探针，本轮被证明**探针与判据不是同一个调用形态**：
> 探针证明「本机有 tr」，判据需要的是「这一次 tr 真的跑起来了」。两者之间的失败面无人观测。

三个实测反例（第三轮审计给出端到端复现，本轮已逐条用用例钉住）：

1. `scripts/mongoUri.sh` 的「单行纯可打印 ASCII」：探针跑 `tr -d 'a'`（单字符集合），
   判据跑 `tr -d '\041-\176'`（八进制区间集合）。只让后者失败 ⇒ `$(…; printf '~')` 恰好等于 `~` ⇒
   **带换行的连接串 rc=0**，换行会成为 mongodump/mongorestore 配置的第二行。
2. `scripts/mongoUri.sh` 的 NUL 判据：正常值就是 0，与「tr 死了、wc 读空 stdin 打印 0」不可分 ⇒
   UTF-16LE 密钥文件 rc=0（目标库名被改坏）。只有「管道首尾同时死」才偶然拒绝。
3. `scripts/capture-image-digests.sh` 的 CR 判据：探针走**管道输入**，判据走**文件重定向输入** ⇒
   后者失败被读成「没有 CR」⇒ 把 CRLF 的 Dockerfile 重写成 LF 并钉版，**exit 0**。

**改法（两处同一条通则）**：不用探针兜，直接让判据**自己会失败**——改成两个**字节计数相比**，
并先做「非空 + 纯数字」形状校验：

- mongoUri：可打印字节数 == 总字节数（`wc -c` 拿总数；`tr -cd '\041-\176'` 拿可打印数）；
  NUL 判据同理，比的是「非 NUL 字节数 == 总字节数」——**用非 NUL 而不是 NUL 计数**，
  因为后者的正常值就是 0，与工具的失败输出不可分。
- capture-image-digests：非 CR 字节数 == 总字节数。

于是**工具的失败方向与判据的拒绝方向一致**：tr 任何形态失败 ⇒ 计数变成 0（或形状非法）⇒ 与总数不等 ⇒
拒绝。空值两边都是 0，由后序判据（scheme / 空文件）给出准确原因。

**证据**：`backupUriFile.test.js` 34/34、`imageDigestGate.test.js` 56/56、
`backupScriptGuards.test.js` + `backupFailureArtifactHygiene.test.js` 29/29；
新增 5 条用例在**回退脚本**后恰好全红（探针形态失败 / NUL 形态失败 / 文件重定向形态失败 / 两种「无 tr」形态），
改回后全绿。桩是否真的生效由用例自己观测（打印 `tr=` 的解析结果，并要求落在桩目录里）。

### 修复：跨平台夹具 `exec` 的两种失效形态（2026-10-30）

> 来源：`work/audit-round2-infra.md` 的「疑似（高）」。`src/tests/helpers/stubPath.js` 把「PATH 桩目录」
> 收口到孩子 shell 内部（MSYS 启动时会前置 `/mingw64/bin:/usr/bin`，从 Node 侧改 `env.PATH` 无效），
> 但它的 `exec` 形态选错了两次，两次都不会让套件「变红得有意义」。

- **`exec "$@"`（直接 exec 脚本文件）依赖可执行位**：本仓 `scripts/*.sh` 在 git 里全是 `100644`。
  MSYS 下照样能跑（shell 自己读文件），Linux 上 `execve` 直接 `EACCES`，非交互 shell 随即退出 ⇒
  两个备份套件会在 CI 上整片**假红**。
- **改成 `exec "$0"` 会静默毁掉夹具**：Windows 上 `$0` 是 `…/Git/bin/bash.exe`，重起一个 Windows 进程
  让 MSYS 再走一遍启动注入，`/mingw64/bin:/usr/bin` 被塞回 PATH 最前 ⇒ 桩目录失效。实测 PATH 首项变成
  `/mingw64/bin`、`date` 命中 `/usr/bin/date`，用例报出真日期（`fire-safety-backup-20261030-205053.gz`）。
  这比假红更坏：套件是红的，但红在夹具，而夹具失效本身不报警。
- **最终写法 `exec bash "$@"`**：按 PATH 解析到 MSYS 本体，不重走启动注入、走解释器与可执行位无关，
  两个平台语义一致。实测改后 `backupScriptGuards`（10 例）+ `backupFailureArtifactHygiene`（19 例）全绿，
  含那条「同名归档存在时拒绝覆盖」的确定性时间戳用例。

### 加固：第二轮逐行审计的「闸没有判别力」收口（2026-10-30）

> 来源：`work/audit-round2-infra.md`（132 行，逐条 file:line + 真跑复现）。这些缺陷的共同形状不是
> 「代码写错」，而是**闸自己不会红**：注释里声明的不变量，没有任何一条判据能单独钉住它。

- **逐条 `&&` 无人守**：`appEntrypointQueuePermFallback.test.js` 的夹具只有「整类命令全失败」一档，
  于是 `docker/app-entrypoint.sh:135` 的 `&&` 删掉后 4/4 仍绿（链上第一条就断，中间失败跑不到）。
  夹具改为「第 N 次调用失败，N=1..8」逐条注入，并加一条反向对照：把 `&&` 换成分号的**历史形态**
  喂进同一夹具，第 2 条失败必须被静默吞掉（证明本闸抓得住它）。
- **正则判别力为零**：`hotUpgradeQueueContract.test.js:135` 的 `/…(?: &&)?$/m` 对「有/没有 `&&`」都真。
  改成必需的 ` &&# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

，并补一条前提自证：整块 8 条命令之间必须恰好 7 个 `&&`。

- **`test -n "$MONGOD"` 无判据**：`.github/workflows/ci.yml:137/:508` 的这行删掉后整族仍绿，
  而「provision 退出 0 但什么都没打印」正是该步骤自述的头号危害（空值让 MongoBinary 回落到
  未经仓库 SHA-256 锚的下载）。补「exit 0 + 空输出 ⇒ 步骤必须红且不写空值」用例，
  并从**抽取到的真实步骤体**删掉那一行做前世版自证（不抄副本）。
- **「失败即放行」语义未钉**：`app-entrypoint.sh:148` 的 `return 0` 换成 `exit 1`（容器起不来）闸仍绿。
  逐条注入的用例现在同时断言 `rc=0`：失败必须告警放行，而不是把容器弄得起不来。
- **探针假阳性**：`helpers/posixShell.js` 的可用性判据用 `includes`，而 MSYS 的 `echo.exe` 会把参数
  原样回显（标记于是「包含」在 stdout 里）⇒ 一个根本不是 shell 的可执行文件被判为可用。
  改成**严格相等**（标记必须独占 stdout），并补一条用「只回显 argv」的可执行文件做的反向对照。
- 实测（Windows / Git Bash，非 Linux 权威）：入口脚本变异 `&&` → `; true &&`（`&&` 计数不变、语义已断）
  ⇒ 用例红在「第 1 条失败却被吞」；还原 ⇒ 绿。`hotUpgradeQueueContract` 删掉一个 `&&` ⇒ 红；还原 ⇒ 绿。
  `posixShell` 探针退回 `includes` ⇒ 新用例红；还原 ⇒ 7/7 绿。

### 修复：两处「工具缺失即静默放行」的字节级判据改为失败关（2026-10-30）

> 来源：第一轮逐行审计的 A6（运维脚本族的 fail-open）。两处的形状相同：判据由外部工具执行，
> 而工具失败时命令替换得到的是**空串**，与「值/文件本来就干净」不可分。

- `scripts/mongoUri.sh` 的 `mongo_validate_uri`：「单行纯可打印 ASCII」判据由 `tr` 执行。实测（PATH 里没有 `tr`）
  带真换行的连接串照样 rc=0 —— 那个换行会被写成 `mongodump`/`mongorestore` 配置文件（0600）的第二行，
  正是这条判据存在的理由（同文件顶部 2026-10-03 的取证）。现在先让字节通道**自证**：`'ab'` 删掉 `'a'` 必须恰好
  剩下 `'b'`；量不到就拒绝放行（fail-closed）。
- `scripts/capture-image-digests.sh` 的 CR 检测（`tr -dc '\r' | wc -c`）同理：`wc` 照旧输出 `0`，与「文件里没有 CR」
  不可分 ⇒ 检测被整体跳过，MSYS 的 `sed`/`gawk` 顺手吃掉 CR，脚本会把 CRLF 静默改写成 LF 并报成功。
  现在先用一个已知含 CR 的输入证明通道是活的，量不到即拒绝落笔（与同脚本 :47 的 `docker` 存在性检查同一口径）。
- 用例：`src/tests/deploy/backupUriFile.test.js` 新增 3 条（含「tr 在位」的前提自证与「无法校验即拒绝」），
  `src/tests/imageDigestGate.test.js` 新增 1 条（含「同一夹具在真 tr 下必须成功」的反向前提）。
  两处守卫都以「临时摘掉判据 ⇒ 用例必须红」证伪过（实测 2 红 / 1 红），再还原为绿。
- 同批：`src/tests/middleware/avatarUnmatchedSurfaceGuard.test.js` 的固定 30ms 睡眠换成条件等待
  （`helpers/waitFor` / `waitForStable`），修掉 `noFixedSleepRatchet` 的回退。

### 新增：临时权限授予与定期复核（C-08 / C-09）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 C-08 / C-09 控制项实现；决策与取舍见 `docs/adr/ADR-012-临时权限授予与定期复核.md`。

- **端点**：`GET /api/permissions/grants`（列表，按 status/userId 过滤）、`GET /api/permissions/grants/review`（复核汇总 + 超期清单）、`POST /api/permissions/grants`（申请）、`POST /api/permissions/grants/:id/{approve,reject,revoke}`。权限码 `privilege:read` / `privilege:grant` / `privilege:approve` 已进目录与菜单。
- **不变量**：到期在**读取路径**判定（`status==='active' && expiresAt > now`），后台 `expireDue` 只收敛状态；申请人不得自审；高敏模块（user/role/permission/security/system/privilege）的码需 2 名不同审批人；审批人必须自持被授予的每个码；每次状态变更都失效目标用户权限缓存（钩子缺失时抛错，fail-closed）。
- **数据**：新集合 `PrivilegeGrant`（`models/PrivilegeGrant.js`），审批链以 `{by,name,at}` 快照落库，终态记录不删除（审计可回看）；索引 `{userId,status,expiresAt}` 与 `{status,expiresAt,createdAt}`。
- **审计**：新增 action `permission_grants`、`permission_grants_review`、`permission_grants_approve`、`permission_grants_reject`、`permission_grants_revoke`（category 仍为 `permission`，见 ADR-012「为什么不新开 privilege 分类」）；派生动作由 `/api/permissions/grants` 前缀自然得出，无手工登记路径。
- **运维**：`scripts/access-review.js`（默认输出 JSON 汇总；`--expire` 收敛过期状态；`--fail-on-overdue` 退出码 1 可挂 CI）+ `deployment/systemd/fsms-access-review.{service,timer}` 每小时巡检。
- **用例**：`src/tests/services/privilegeGrantFlow.test.js`（21 例规则：到期失效、双人复核、自审/无码阻断、并发签批、驳回与撤销的状态机单向、复核登记、服务层入参兜底、被授权账户不可用、权限判定与缓存失效两处钩子缺失时 fail-closed）、`src/tests/routes/privilegeGrantEndpoints.test.js`（7 例：鉴权、校验链、全链路、双人复核、自审阻断、驳回端点、审计派生 action 入缓冲）。

- **覆盖率门槛**：`services/privilegeGrantService.js`、`services/accessReviewService.js`、`controllers/privilegeController.js`、`constants/privilegeGrant.js` 在 `jest.config.js` 单独设阈值（取「实测 −5pt(分支) / −3pt(函数)」，向下取整），不并入 global 均值——这几个模块退化时的表现是安全结论错误，不是报错。同批拆出的 `services/privilegeGrantHooks.js`（两个外部钩子，未注册即抛）与 `services/privilegeGrantValidation.js`（`grantError` 与有效期/权限码归一的单一出口）也各带阈值，拆分的动因是 `max-lines` 棘轮（服务本体已越过 300 行），语义与导出面逐字不变。
- **Web 端入口**：`web-admin/src/views/PrivilegeGrantView.vue`（菜单 `/system/privilege-grants`，路由 `meta.permission = privilege:read`）——状态筛选（默认「待审批」）、复核汇总五计数、申请表单（权限码逗号/空格混排解析、有效期 1-168 小时本地校验）、签批/驳回/撤销三条决定链路；按钮按 `privilege:grant|approve` 门控（与后端 `checkPermission` 同码），高敏提交提示显式给出「还需几人签批」。用例 `web-admin/src/tests/views/privilegeGrantView.test.js`（34 例，分支覆盖率 90/90）。
- **未落地（如实申报）**：堡垒机/跳板机与 JIT 会话录屏（C-09 的另一半）尚未实现——「谁能拿到高敏码」已可控可追会过期，但「拿到之后在什么通道上操作」仍由操作系统与运维流程保证。

### 新增：部署面配置漂移检测（M-05）（2026-10-30）

> 依据 `deliverables/FSMS安全设计方案-v2-2026-10-30.docx` 的 M-05 控制项实现。

- **脚本**：`scripts/config-drift-check.js`，把 compose 的容器安全标志（`read_only`/`cap_drop`/`security_opt`/`user`/`tmpfs`/`networks`/内存上限…）、Dockerfile 的 `USER` 与 `HEALTHCHECK`、nginx 模板的 TLS 与安全响应头、`.env.example` 的安全相关键**逐项摘要**（sha256 前 16 位），与 `deployment/config-drift-baseline.json` 对账。
- **输出纪律**：只打印条目名与 `ADDED/REMOVED/CHANGED`，**不打印取值**——配置模板里可能夹带密钥样例，回显会把基线本身变成泄露面。`--json` 供机器消费，`--update` 重写基线（须与变更同轮提交）。
- **退出码**：0 无漂移、1 有漂移、2 输入不可解析或基线缺失（宁可报 2 也不给空账面）。
- **边界（如实申报）**：检的是**仓库内**的配置面，即漂移被引入的地方；不读 `process.env`，因此不能替代「运行时配置与基线对账」（后者由启动期断言与 `config/validate.js` 负责）。
- **用例**：`src/tests/scripts/configDriftCheck.test.js`（5 例：抽面有效、无关项不入账且取值不落明文、改值/删项/加项各自被识别、仓库基线不撒谎、CLI 退出码与 `--json` 契约）。

### 新增：用户头像上传（2026-10-30）

> 依据 `deliverables/头像上传功能-计划报告-2026-10-30.md` 评审后的 v2 修订实现。

- **端点**：`PUT /api/auth/avatar`（本人上传/替换，JSON data URI）、`DELETE /api/auth/avatar`
  （本人移除，幂等）、`GET /api/avatars/:userId?v=<hash16>`（本人直通；他人需 `user:read`
  且通过用户数据范围校验，与 `GET /api/users/:id` 同一把尺）。
- **存储**：新集合 `UserAvatar`（`_id = userId`，1:1），图片二进制以 Base64 经 `encryptPii`
  v2（AAD 绑定 `{subjectId, field:'data'}`）加密落库；`data` 为 `select:false`，读取时解密后
  复核 magic bytes 与 SHA-256，防篡改/错配。不落磁盘卷（容器 `read_only: true`）。
- **校验**：仅 JPEG/PNG，原始上限 256 KB，16–1024 px 且 ≤1 MP；拒绝 APNG 与带 EXIF/文本
  元数据的图片（不做"服务端剥离"——剥离需解析全部段，直接拒绝边界更小）。
- **一致性**：上传/移除在事务内同时写 `UserAvatar` 与 `User.avatar`；`PUT /api/auth/profile`
  与 `PUT /api/users/:id` 的 `avatar: ''` 同事务删除记录，避免"指针清了、图还能拉"。
  删号/批量删/匿名化级联删除头像记录。
- **D3 收口**：资料更新只接受**服务端为目标用户生成**的 `/api/avatars/<id>?v=<hash16>`；
  外部 URL / 相对路径 / data URI 一律 400（data URI 会绕过上传校验、加密与尺寸限制）。
- **审计与限流**：新增 action `auth_avatar`（写）/ `avatar_view`（读路由派生，读默认豁免）；
  审计体对头像 data URI 打码为 `***`（窄键规则，不并进全局敏感键子串名单）。
  读路径独立限流桶：预认证 IP 600/15min、认证后用户 1200/15min；响应带
  `ETag` + `Cache-Control: private, no-cache` + `Vary: Cookie`，命中 `If-None-Match` 返回 304。
- **前端**：新增 `UserAvatar.vue`（失败回退首字母）与 `utils/avatarImage.js`
  （中心方形裁切 + 512×512 JPEG q0.85，超 400000 字符自动降质/降尺寸）；
  个人资料页提供更换/移除入口，顶栏、欢迎卡、用户列表统一改用该组件。
- **复核修复（同日）**：图片校验改为"结构解析到文件尾"——JPEG 必须扫描到 EOI 且
  EOI 为最后一个标记，PNG 必须存在 IEND 且 IEND 为最后一个 chunk（另要求至少一个
  `IDAT`）；EOI/IEND 之后夹带 HTML/ZIP/自定义数据一律拒绝，并补回归用例。
  `useravatars.data` 同时纳入 `scripts/migrate-pii-encryption.js` 的 `PII_TARGETS` 与
  `deployment/secret-rotation.md`、ADR-003 的 PII 清单——否则轮换 `AES_SECRET_KEY`
  后头像密文无法解密。头像读取响应另显式下发 `X-Content-Type-Options: nosniff` 与
  `Content-Security-Policy: default-src 'none'; sandbox`，即使直接导航到图片 URL
  也不会把 polyglot 响应渲染成可执行文档。
- **夹带面再收口（同日）**：段/chunk 判定由"黑名单"改为**白名单**——黑名单漏一个
  APPn/chunk 就是一条夹带通道。JPEG 只放行 APP0（标准 14 字节 JFIF，带缩略图即拒）、
  APP2（单段完整 ICC_PROFILE：序号/总数为 1、声明长度与实际一致、profile 含 `acsp`
  签名）、APP14（定长 12 字节 Adobe 头）、DQT/DHT/DAC/DRI/SOF/SOS；其余 APPn 一律
  `JPEG_UNSUPPORTED_SEGMENT`。
  PNG 只放行 IHDR/PLTE/IDAT/IEND 与 sRGB/gAMA/cHRM/pHYs/sBIT/bKGD/tRNS/acTL，且定长
  chunk 的长度必须精确，其余（iCCP/sPLT/hIST/私有 chunk）一律 `PNG_UNSUPPORTED_CHUNK`。
  Chromium canvas 与 System.Drawing 的真实编码产物（JPEG 带 ICC APP2、PNG 带
  sRGB/gAMA/pHYs）实测全部通过。同时收紧边界：空 `IDAT`、重复 `IHDR`、扫描数据为空
  的 JPEG 一律拒——否则会存下"结构自洽但解不开"的坏头像。
- **特殊情况收口（同日）**：白名单只挡"夹带"，挡不住"结构自洽但解不开"，补齐四处语义判据——
  ① PNG `IHDR` 的位深/色型必须落在规范表 11.1 的合法组合内，压缩法/滤波法必须为 0（否则
  `bitDepth=3`、`colorType=7`、`compression=99` 这类头能过白名单）；② `IDAT` 必须是真能解压的
  zlib 流，且解压字节数**恰好**等于声明尺寸的原始行字节数——只查结构会放过解压炸弹（实测
  203 KB 的 PNG 声明 16×16、`IDAT` 解出 200 MB）；`maxOutputLength` 让超限在解压过程中中断，
  另核对 `engine.bytesWritten` 与 `IDAT` 总长，堵住"流尾巴夹带未消费字节"；③ 隔行（Adam7）
  一律 `PNG_INTERLACE_UNSUPPORTED`——本仓合法流量全是 canvas 重编码产物（`interlace` 恒 0），
  而 Adam7 的行布局无法用一个定长字节数核对，放行等于给炸弹留后门；④ 调色板图必须有
  `PLTE` 且在 `IDAT` 之前、长度是 3 的倍数，JPEG `SOF` 的 `Nf` 必须 1–4 且与段长 `2+6+3Nf`
  自洽（`Nf=0` 的帧头解不出一个像素）。
  同轮把 PNG 结构解析拆到 `utils/pngStructure.js`、错误类型拆到 `utils/avatarImageError.js`，
  避免 `utils/avatarImage.js` 撞 `max-lines` 棘轮（注释净增 0 行）。
  实测最坏情况成本：1024×1024 PNG 7.2 ms/次、3.8 千段 JPEG 2.7 ms/次，256 KB 上限不变。
  - **结构自洽性再收口（同日）**：把“白名单里的每个结构件都必须真的自洽”补齐——
    PNG 逐 chunk 核对 CRC（否则整张图除了签名外每个字节都能被改写而无人发现），
    `IDAT` 之后除 `IEND` 不得再有任何 chunk，同一 chunk 不得重复（`PLTE`/`tRNS`/`bKGD`/
    `sBIT`/`sRGB`/`gAMA`/`cHRM`/`pHYs`/`acTL` 各限一次），变量长度 chunk 的长度按色型定值
    （`sBIT`/`bKGD`/`tRNS` 各有表，`tRNS` 对调色板图限 1–256），灰度图（`colorType` 0/4）
    不允许 `PLTE`；JPEG 的 `DQT`/`DHT`/`SOS` 长度必须被段内表结构整除（`Pq/Tq`+64|128、
    `Tc/Th`+16+符号和、`6+2Nf`）——不校验长度时这三种段就是“合法段名 + 任意字节”的通道。
    变异测试实测：PNG 逐字节翻位 3 种掩码 × 96 字节全数被拒，JPEG 197 字节全数被拒，
    2764 例变异（翻位/截断/插入）无一崩溃。
    真实编码器产物仍全通过：Chromium canvas 的 12 段 `IDAT` PNG、带 alpha 的 PNG、
    512×512 JPEG q0.85，以及 System.Drawing 的 RGB/ARGB/8 位调色板 PNG 与 JPEG。
    成本重测（含 CRC 与全部语义校验）：1024×1024 RGBA PNG 3.7 ms/次、21333 chunk 洪水
    1.1 ms/次、3711 段 DQT 洪水 1.8 ms/次、1039 段 `IDAT` 1.7 ms/次，256 KB 上限不变。

### 安全改造：账号救济 / 删除匿名化 / 异地备份 / 时钟基线（2026-10-30）

> 依据 `deliverables/安全改造待办-2026-10-30.md`。按用户明确要求，**不实施强制 MFA（P1-1）**：
> MFA 能力保持现状，管理员强制开关不启用，文档口径同步改为「能力具备、未强制」。

- **P1-2 账号救济（管理员轨）**：新增 `PUT /api/security/users/:userId/password/reset`，
  权限 `user:reset_password` + 二次验证 + 数据范围/层级/内置超管保护；生成一次性临时口令
  （≥12 位、四类字符），`tokenVersion++` + 吊销全部会话 + `mustChangePassword=true`，
  审计 `admin_reset_password`（临时口令不入审计/日志）。首次登录只放行改密/me/logout，
  改密完成清标记并审计 `password_force_changed`。内部系统无邮件通道，自助找回轨不做。
- **P1-3 删除改匿名化**：单删/批量删除改走 `userService.anonymizeById/anonymizeMany`，
  保留 `_id/username` 维持审计引用，抹除 realName/phone/email/avatar 并置 inactive，
  释放进行中指派，审计 `user_anonymized`；硬删除只保留建号回滚与测试夹具。
- **P1-4 异地备份**：`deployPolicy.checkBackupOffsite` 在 `DEPLOY_ENFORCE_OFFSITE=true`
  或 `NODE_ENV=production` 时要求 `BACKUP_OFFSITE_CMD/DIR`；`BACKUP_REQUIRE_OFFSITE=true`
  使备份脚本缺配置即失败。补 gpg 密钥轮换、逻辑恢复演练记录模板与生产部署清单。
- **P1-5 时钟基线**：新增 `scripts/check-clock-sync.js`（timedatectl/chrony，偏移阈值可配，
  判不了退出 2）、`deployment/systemd/chrony.conf.example` 与 `deployment/clock-sync.md`；
  self-hosted/SSH 部署在正式发布前调用，dry-run 跳过。
- **审计与前端**：新增 action `admin_reset_password`/`password_force_changed`/`user_anonymized`/
  `security_users_password_reset`，中英文标签同步；登录响应与 `/auth/me` 下发
  `mustChangePassword`，前端登录后直达个人资料页并由路由守卫收敛，用户删除提示改为
  「已注销并匿名化」。

### 新增：应用内一键蓝绿升级（2026-10-30）

> 目标：把「发版」从「SSH 上去敲命令」变成「应用里点一次按钮」，同时不让应用容器
> 拿到宿主的 docker / nginx 控制面——那条路等于把容器逃逸做成常驻攻击面。

- **契约：文件队列 + 双向重校验**。应用只往共享队列目录（`UPGRADE_QUEUE_DIR`，compose
  以 bind mount 与宿主共享）写一份 **HMAC 签名**的请求文件，宿主机上的
  `scripts/hotUpgradeAgent.js`（systemd timer）重新校验摘要与仓库白名单后才执行
  `scripts/hotUpgrade.js`。应用侧的校验只是输入错误的前置拒绝，不是安全边界本身。
- **镜像必须 digest 钉扎**：只接受 `registry/repo@sha256:<64hex>`，tag 一律拒绝
  （tag 可被覆盖，审计里记的版本会与线上跑的不是一回事）；仓库前缀须命中
  `HOT_UPGRADE_REGISTRY_ALLOWLIST`，**空白名单 = 全拒**（fail-closed，不是全放）。
- **新端点**：`GET /api/security/upgrade`（构建信息 + 就绪判据逐条原因 + 最近任务）、
  `GET /api/security/upgrade/jobs/{jobId}`、`POST /api/security/upgrade/requests`
  （路由层 `security:config` + 函数内唯一超管 `*:*` + 二次验证凭据 / `X-Reauth-Ticket`）。
  三条路径已进 `src/docs/generate.js` 与产物，`openapiSync` 双向对账。
- **审计先落盘再回 202**：`upgrade_triggered`（`riskLevel: high`，含 jobId / 镜像 / 来源 IP）
  走 `recordDurably`；失败路径不设 `skipGlobalAudit`，由全局审计记录这次尝试。
- **队列读写加固**：请求文件 `0600`（随机临时名 + `wx` 打开 + fsync + rename，
  避免可预测临时名被符号链接劫持）、只读侧单 fd 读取（`O_NOFOLLOW`）、心跳缺 `ready`
  或时钟回拨一律判未就绪。
- **前端**：`AboutView` 版本卡 + `UpgradeDialog`（镜像地址、二次验证、进度步骤），
  中英文案齐备；`utils/api.js` 增加对应调用。
- **运维面**：`deployment/systemd/{fsms-hot-upgrade-agent.service,.timer}` 与
  `hot-upgrade.env.example`；`deployment/hot-upgrade.md` 第 3 节补「应用内一键升级」流程；
  `deployment/secret-rotation.md` 把 `HMAC_SECRET` 的影响面从「五个消费点」更新为**六个**
  （第 6 个是升级请求签名：换钥后只让在途请求被拒，重发即可，既无迁移手段也不需要迁移）。
- **门禁同步登记**：`.env.example` 补 `UPGRADE_QUEUE_DIR`；`services/upgradeService.js`
  的 `TERMINAL_STATES/ACTIVE_STATES` 进单进程豁免表（静态字面量词表，无跨进程语义）；
  日期解析收口到 `utils/helpers.toEpochMs`（裸 `Date.parse` 只允许一处）；
  `controllers/securityController/upgrade.js#triggerUpgrade` 进可靠审计登记表；
  升级错误码改成逐码字面量发出（动态查表会让五个已注册的码退化成死码）。
- **默认关闭**：`UPGRADE_ENABLED=false` 时概览仍可读（按钮不可用并给出原因），
  POST 返回 `UPGRADE_DISABLED`。
- **对外命名**：应用内入口统一称「一键升级」（原「一键热升级」）——弹窗标题、不可用/白名单
  错误文案（中英）、接口兜底 message 与 OpenAPI 摘要同步去「热」字，与「蓝绿切换」的语义对齐。

### 加固：升级链路的第二轮逐行审计收口（2026-10-30）

> 依据多子代理逐行审计报告（部署/脚本/后端/前端/门禁五路）。这一轮**不新增能力**，
> 只把「升级看起来成功、实际没成」与「把权限收紧做成功能失效」两类形态从链路上消掉。

- **队列属主矩阵**（`docker/app-entrypoint.sh`）：应用只写 `requests/`、只读 `status/processing/`。
  原先一律 `chown nodejs` 让被攻陷的应用可以删 `processing/.agent.lock`（升级永久显示进行中）、
  伪造 `status/<id>` 为 `succeeded`（界面假成功、请求被丢弃）、清空 `rejected/`（验签失败留证消失）。
  现改为 `requests=nodejs:nodejs 0700`、`status/processing=root:nodejs 0750`、`rejected=root:root 0700`；
  顺序固定为「收回 root → chmod → 交出属主」（`cap_drop: ALL` 且不补 `FOWNER`，对已属 nodejs 的
  目录 chmod 必然 EPERM，而入口是 `set -eu`——第二次启动/app-green/一次性迁移容器都会因此起不来）。
  另拒绝对 `/`、`/etc` 等系统目录改属主，`find -xdev` 不跨文件系统、不跟随符号链接。
- **蓝绿互不踩**：`app-green` 显式 `AUDIT_WAL_PATH=/app/logs/audit-buffer.green.wal`——两色共用
  `app-logs` 卷时，按库名派生的 WAL 会被两个进程同时追加，而 WAL 的全部价值是崩溃重放，
  双写者让「谁写的、该不该重放」不可判定（重复插入 → 哈希链分叉）。
- **CI 的 hot 分支补 `--apply`**：此前直接调 `hotUpgrade.js` 而未加 `--apply`，脚本按设计走演练
  分支并**以 2 退出**——流水线会「成功打印了计划」，线上什么都没变。现两条模式（本地/SSH）
  都显式在 `--apply` 与 `--dry-run` 之间二选一。
- **布尔旗标严格解析**（`scripts/hotUpgradePolicy.js`）：`--apply=false` 此前被当成「出现过就是真」，
  模板里写 `--apply=${{ inputs.apply }}` 且值为 false 时会真的开始切流。现在只接受 true/false（含 1/0、yes/no），
  其他值报错而不是猜。
- **代理锁的 pid 复用**（`scripts/hotUpgradeQueue.js`）：锁新增 `/proc/<pid>/stat` 的启动时刻与 3h 锁龄上限，
  空锁文件/损坏锁/pid 被复用都能接管；此前只判 `kill(pid,0)`，一个恰好复用旧 pid 的无关进程会让按钮
  永远显示「另一个升级正在进行中」。
- **只读侧单 fd**：`readJsonFile` 改为 `openSync(O_NOFOLLOW)` + `fstat` + 从 fd 读——原先 `statSync` 后按路径
  `readFileSync` 是两次解析，应用对 `requests/` 可写时可换成符号链接，让 root 代理读到任意宿主文件。
- **写入与观测**：`status/processing` 文件 `0640`（属组＝队列目录属组，应用可读、other 不可读）；
  `hotUpgradeJob` 记录子进程 pid 失败时 `SIGTERM` 回收进程并如实报错（原先会留下无人跟踪的升级进程）；
  起备色补 `--no-build`（compose 里 app 段带 `build:`，否则会在部署机上重建当前源码，线上跑的就不是请求里的 digest）；
  观察期未通过**回滚成功后才**停新色（回滚失败分支不停，否则可能把仍在接流量的容器杀掉）。
- **监控**：`prometheus.yml` 同时抓 `app:3000` 与 `app-green:3000`；`BackendDown` 改为
  `sum(up{job="xf-app"}) == 0`——逐实例判会让平时根本没起的备色永久点亮告警，而永远在响的告警等于没有告警。
- **systemd 加固**：代理单元补 `NoNewPrivileges/Umask=0077/PrivateTmp/ProtectHome/ProtectSystem=full`
  与 `ReadWritePaths`；`hot-upgrade.env.example` 补 `MONGODB_URI_FILE`/`BACKUP_ENCRYPTION`/
  `BACKUP_GPG_RECIPIENT`——代理的环境**只来自该文件**，缺任一项时第一个升级请求都会停在备份步。
- **门禁同步**：`LAZY_SCC` 登记 `config/jwtRotation.js`（真实惰性环）、单进程豁免表登记
  `middleware/auth.js` 的 `PASSWORD_CHANGE_ALLOWED_PATHS`（静态只读 Set）；三处环境相关的用例判据收窄到
  「本子系统自己的那几条文案」（ACL 噪声另有专门用例钉住），而不是靠机器上有没有 `USERNAME`/`bash` 决定红绿。

### CI 修复：锁文件锚未重算 + 三处用例随实现漂移（2026-10-30）

> 现象：`CI` 从 `6415fd6` 起红，且**只红在第一个作业** `dependency-policy`——
> 后面 `test`/`e2e`/`e2e-browser`/`build` 全部 `needs: dependency-policy`，
> 一个闸失败就把整条流水线的可见性一起挡掉。本地逐闸复跑后发现：闸背后还压着
> 三处**与依赖无关**的红（`test` 作业一旦被放行就会立刻暴露），故一并修。

- **锁文件锚（`dependency-policy` 唯一的红）**：`6415fd6` 把 `vue-i18n` 从
  `9.14.5` 升到 `11.4.16`（v9/v10 已被上游标记 deprecated 并停止维护），
  `web-admin/package.json` 与 `package-lock.json` 都改了，但
  `deployment/lockfile-anchor.json` 没重算 ⇒ `LOCKFILE_ANCHOR_MISMATCH`。
  处理口径按锚文件自身的提示走：先人工复核锁文件 diff（仅 `vue-i18n` /
  `@intlify/*` 一族，`resolved` 全为 registry.npmjs.org、integrity 随版本同步变更，
  无夹带），再 `npm ci --dry-run` 确认锁文件与 package.json 自洽，最后
  `node scripts/check-lockfile-integrity.js --update`。**不是**回退依赖：
  v9 已停止维护，回退等于把 EOL 依赖留在发布基线上。
- **compose 告警配置链（`test`）**：`894f1de` 的 F-15 把 alertmanager 的配置挂载
  从「直接 bind mount 宿主文件」改成「一次性 `alertmanager-config-init` 复制进
  命名卷并 chown 65534，alertmanager 只读消费该卷」（宿主 0600 文件容器内 nobody
  读不到）。`alertingConfig.test.js` 与 `alertmanagerComposeGate.test.js` 仍断言
  旧的 bind mount 形状。改为钉新链条的三段——校验容器、初始化容器都取同一个
  `${ALERTMANAGER_CONFIG_PATH:-…}`，运行侧只消费 `alertmanager-config` 卷且
  `depends_on` 初始化容器 `service_completed_successfully`。「校验的是 A、跑的是 B」
  这条原始不变量原样保留，只是中间多了一跳。
- **单进程依赖清单（`test`）**：`6415fd6` 新增的 `controllers/ipListWriteGuards.js`
  带模块级 `Set`（`IP_LIST_WRITE_FIELDS`，写路径字段白名单），未进
  `SINGLE_PROCESS_DEPENDENCIES` 也未进豁免表。按既有口径补豁免条目（静态字面量
  词表、只读、无跨进程语义），与 `routes/wellKnownRoutes.js` 的 `CLIENT_ERROR_KINDS`
  同族——**不是**登记进清单：登记会让启动期对运维误报"多实例下这条会失效"。
- **NODE_ENV 未设置（`test`）**：`93519ae` 起 `validate.js` 对「`NODE_ENV` 键根本
  不存在」直接拒绝启动（缺失时无法区分"开发机裸跑"与"生产容器漏配"，按开发语义
  放行等于弱密钥/Host/Redis/TLS 四类校验一起静默跳过），README 部署清单与
  `.env.example` 已同口径。`nodeEnvGateFailsClosed.test.js` 仍把「未设置」放在
  「允许跳过生产校验」那张表里。改为单列一条：未设置 ⇒ 拒绝启动；同时保留
  `normalizeNodeEnv()` 对 `undefined` 仍返回 `development`（其他模块依赖这个归一值，
  改它会波及一圈无关判据）——两件事分开钉。
- **WS 握手用例夹具（`test`）**：`93519ae` 让握手期 IP 判定在「取不到客户端地址」
  时 fail-closed（`无法验证网络来源`），`#9` 又加了按来源 IP 的未认证连接准入表。
  两处夹具因此失真：`wsFlow.test.js` 的假 socket 有 `handshake` 但**没有**
  `address`，`tokenPurposeAndConsumers.test.js` 的假 socket 连 `handshake` 都没有
  ⇒ 认证分支一条都跑不到（表现为 8s 超时 / 断言拿到「无法验证网络来源」）。
  补 `address: '127.0.0.1'`；`wsFlow` 的假服务实例补
  `unauthConnectionsByIp = new Map()`（真实构造器在 `index.js:66` 初始化）；
  `tokenPurpose` 补桩 `models/IPBlacklist`（该套件没有真实 DB，不桩就会以
  「网络黑名单校验暂不可用」fail-closed）。被测判据一条没放松。

> **本机复跑的两处"红"不是 CI 红，未改代码**：`backupEncryptionContract` /
> `backupTransport` 在本机失败的原因是本会话工具链注入的 `rm` 垫片拒绝
> Windows 盘符路径（`[safe-delete][SAFE_DELETE_INVALID_PATH] embedded drive prefix`），
> 把 `safe-bin` 从 `PATH` 移出后同一脚本行为正确（半成品归档确实被删）。
> CI 是 ubuntu + 真 coreutils `rm`，不受影响。

---

### 修复（2026-10-28 · dev 代理覆盖上游 X-Forwarded-For，审计与限流只见内网地址）

> 现象：经外层反代/预览网关访问时，后端审计与限流记录的客户端 IP 恒为
> `127.0.0.1`/`::1`，真实地址丢失。

- 根因：`web-admin/vite.config.js` 的 dev 代理无条件用 `req.socket.remoteAddress`
  覆盖 `X-Forwarded-For`。外层代理已经把真实 IP 写进该头，而它连 Vite 的对端是回环
  地址，覆盖等于把真实地址抹掉。
- 修复：`/api`、`/client-errors`、`/socket.io/` 三个代理块统一改为「上游有 XFF 则
  原样透传（数组形态拼接），缺失才回落 socket 对端」。本地直连 dev server 的行为不变。
- 测试：新增 `web-admin/src/tests/bundling/devProxyForwardedFor.test.js`，对三个代理块
  分别钉住「透传 / 多值拼接 / 回落」三条契约。

---

### CI 修复：runner 内核误报导致 e2e-browser 起不来 Mongo（2026-10-28）

> 现象：`CI` 的 `e2e-browser` 在 **Start full stack** 步骤失败，后端日志是
> `connect ECONNREFUSED 127.0.0.1:27017`，看起来像服务没起来；`test`/`e2e` 全绿。
> 定位到真正原因不在本仓代码：

- **根因**：GitHub 自镜像 `20261018.339.1` 起把内核抬到 `7.0.0-1017-azure`，其
  `/proc/version_signature` 实为上游 **7.0.14**；而 MongoDB 8.0.x 只读 `uname -r`（得 `7.0.0`），
  误判进 SERVER-121912 的「6.19–7.0.13 不兼容区间」，启动即以 fatal `12257600` 退出。
  上游误报修在 SERVER-131779，**8.0.34 没有**（8.0.x 最新即 8.0.34，2026-10-13 发布）。
  旁证：同一次运行里 `e2e` 落在旧镜像 `20261012.334` 上，同一份 mongod 8.0.34 正常启动并通过。
  外部登记：`actions/runner-images#15005`（open，GitHub 工程师给出的临时变通即回 `ubuntu-22.04`）。
- **为什么换二进制绕不过**：把官方 tarball（sha256 与仓内锚一致）解开后，该 fatal 串在 `mongod`
  二进制内可直接检索到——闸是编进 mongod 的，不是 Docker 镜像特有的。故 `test`/`e2e` 的
  `MONGOMS_SYSTEM_BINARY` 路径同样会在新内核上失败，只是尚未落到新内核宿主机而已。
- **修法**：`test`/`e2e`/`e2e-browser` 三个用真实 mongod 的 job 钉 `runs-on: ubuntu-22.04`
  （其余 job 保持 `ubuntu-latest`）；`deployment/mongod-artifacts.json` 增补 `ubuntu2204` 条目
  （2404 包要求 glibc 2.39，22.04 的 2.35 跑不了），sha256 `8eef2a82…c7aced43` 取
  `downloads.mongodb.org/current.json` 官方值与自算字节哈希**逐字一致**的双锚。
  不动的部分：mongo 镜像仍钉 8.0.34 及其 digest（生产 compose 口径不变），三方对账闸不受影响。
- **回滚条件**：MongoDB 8.0.35 发布并完成 digest/sha256 对账，或 runner 内核进入 ≥7.0.14 区间。

---

### 审计第五轮复核：逐条回源码验证、修成立项、登记不成立与暂缓项（2026-10-26）

> 承接 `deliverables/audit-2026-10-26/audit-report.md`（复核基线 `4a1bdae` + 工作区）。
> 先把 P1/P2/P3 全部结论逐条回到当前源码与实跑结果复核，再只修验证成立的部分；
> 报告补第九节复核记录。**不修不存在的问题，也不沿用报告里的数字。**

| 项                          | 复核结论     | 处理                                                                                                                                                                                                                                                                                              |
| --------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1-1 工作区卫生             | 成立         | 删除 `.jest-*`/`.vitest-*` 日志、`.ci-repro.log`、`.tmp-probe.json` 与 4 个 `.lint-ratchet-selftest-*` 残骸；`.env` 的 `HMAC_SECRET` 19 → 43 字符（dev 文件、gitignored；本地既有审计 HMAC/二次验证票据随之不可验，重登即恢复）。`logs/`、`.mimosa/`、`CHANGELOG.md.bak` 是运行产物且已忽略，保留 |
| P2-1 假 performance 指标    | 成立         | 删除 `overview.performance` 三字段（无消费方且与 A-2「不可用≠零值」冲突），真实指标仍在 `/metrics`                                                                                                                                                                                                |
| P2-2 `data.data` 双层信封   | **部分成立** | 审计列表（游标/偏移两臂）与 `getRecentAlerts` 改用新增的 `ApiResponse.successWithMeta`（`data`/`meta` 平级），前端 `AuditLogView` 同步；`exportAuditLogs` 是流式 CSV，不经 `ApiResponse`，报告把它算进来不准确                                                                                    |
| P2-3 权限列表上限           | 成立         | `permissionRoutes` 的 `limit` 500 → 100                                                                                                                                                                                                                                                           |
| P2-4 authRoutes 错位注释    | 成立         | 删除两处错贴的 PERMISSION-EXEMPT 注释（`refresh` 在 `:325`）                                                                                                                                                                                                                                      |
| P2-6 设备统计无缓存         | 成立         | 新增 `services/deviceStatsService.js`：`scopeFilter` 序列化键 + 15s TTL + 单次 8 臂 `$facet`；7 条写路径统一 `invalidateDeviceStats`（代际防旧值写回 + `sharedCache` 跨实例广播）。`DeviceService` 只留委派，守住 max-lines 棘轮                                                                  |
| P3-3 wellKnown 未入 OpenAPI | **不成立**   | `openapiSync` 两条用例明文钉住「wellKnownRoutes 属于豁免面（不进 `openapi.json`，且豁免有据）」，是有测试保护的设计而非漏登记                                                                                                                                                                     |
| P2-5 / P3-1/2/4/5/6/8       | 暂缓         | warning 全在棘轮基线内、0 error；拆分与产品/运维决策按报告原路径排期                                                                                                                                                                                                                              |
| 锚点与密度同步              | 必做         | `DeviceService.js:445→deviceStatsService.js:82`、`auditQueryService.js:320→:314`、`statsCache.js:155/201→:159/:230`、`DeviceService` 计数 `:108/:502→:110/:444`；7 处引用注释与 2 个消费方断言同步；`statsCache`/`apiResponse` 注释压回密度基线（98→97、59→59）                                   |
| 验收                        | —            | 全量 `jest` **644/644 套件、7,956/7,956 例**；前端 `auditLogView` 44/44；`lint` 0 error/14 warn、`lint:ratchet`/`format:check`/`docs:check`（86 path / 105 operation）全绿；锚点两闸 28/28、`commentDensityRatchet` 5/5、路由契约 44/44                                                           |

---

### 审计第四轮：惰性环 4 → 1 个分量、台账单源化、注释治理落 ADR-011（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §15.2 如实登记的「A-1 剩余三个分量未做」，
> 并一并收口 **Q-3/T-6**（多份台账各自手抄实现清单）与 **Q-1**（生产注释混入变更史）。
> 报告补第 16 节。所有修复先复现红点再改，没有放宽任何断言。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A-1 惰性环清零   | 强连通分量 **4 → 1**、模块 **36 → 22**。新叶子：`middleware/userAuthCache.js`（用户缓存与失效广播，断 `auth ↔ tokenBlacklist`）、`middleware/dataScope.js`、`middleware/httpMethods.js`、`middleware/security/ipBlacklistStore.js`（封禁原语）、`middleware/security/earlyRejection.js`（早拒绝审计）、`services/alertTypes.js`、`services/alertDispatch.js`（告警链断环）。`models/User.js` 删除三个权限薄代理，调用方直接走 `userPermissionService`。`LAZY_SCC` 只剩 config/audit/metrics 22 模块，保留理由写在 `requireCycles` 头 |
| A-1 行为保持     | `addToBlacklist` 在两个封禁模块保留**调用时取属性**的薄包装（解构会在加载期固化绑定，测试就无法替换封禁结果）；F-160 的 `await addToBlacklist(` 文本门禁继续命中。6 个封禁/升级套件的注入点迁移到 `ipBlacklistStore`，是跟随唯一写入原语，不是放宽断言                                                                                                                                                                                                                                                                               |
| Q-3/T-6 台账单源 | 写方法名单收敛到 `middleware/httpMethods.js`（originCheck / security/auditLog / protocolCompliance / behaviorBaseline 四处不再各抄一份）；审计分类测试改为引用 `constants/audit.js` 的 `AUDIT_CATEGORIES`；Redis 降级失效清单改为从 `SINGLE_PROCESS_DEPENDENCIES` 过滤派生                                                                                                                                                                                                                                                           |
| Q-1 注释治理     | 新增 `docs/adr/ADR-011-注释治理-源码只保留当前约束.md`：源码只写当前约束与不明显的 Why，变更史归 CHANGELOG、权衡归 ADR、锚点优先符号。`securityHeaders.js` 整行注释 180 → **102**（生产注释 22,504 → **22,426** 行，−78）                                                                                                                                                                                                                                                                                                            |
| Q-1 密度棘轮     | 新增 `scripts/commentDensity.js` + `scripts/commentDensity.baseline.json`（258 文件 / 22,426 注释 / 34,798 代码）与 `src/tests/ci/commentDensityRatchet.test.js`（5 例：统计面自证、只降不升、新文件密度 ≤ 30%、反向对照、总量对账）。`--update-baseline` 遇回归直接拒绝                                                                                                                                                                                                                                                             |
| 棘轮实测         | A-1 给两个封禁模块各加 1 行说明后，棘轮立即报 2 处回归并拒绝收紧基线；按 Q-1 口径把 3 行历史压成 2 行后才写回基线——证明它不是「写完就绿」的摆设                                                                                                                                                                                                                                                                                                                                                                                      |
| 测试重定向       | `auditScopeFilterDeptCache` / `edgeCases` / `auditQueryOperationCatch` 的桩从 `middleware/rbac` 改到 `middleware/dataScope`（后者才是 `auditScopeFilter` 的叶子依赖；旧桩失效时真实查询打未连接 Mongo，表现为 10s 超时且日志为空）；`websocketRedisAdapter` 的 `sharedCache` 桩补 `onInvalidate`（`userPermissionService` 在加载期注册）；`sharedCacheDegradationLog` 改为派生清单（手抄版已漂移成 `middleware/auth.js`）；`reportPiiExportStepUp` 的审计断言改为轮询到真实落库（全量并发下响应先回、行尚未可见）                    |
| 验收             | 全量 `jest` **643/643 套件、7,950/7,950 例全绿**；`requireCycles` 6/6、`commentDensityRatchet` 5/5、封禁链 57 例、定向回归 179 例全绿；`npm run lint` / `lint:ratchet` 0 error（14 条既有 warning 未超基线）、`docs:check`（86 path / 105 operation）与 `format:check` 一致                                                                                                                                                                                                                                                          |

---

### 审计剩余项收口：事务拓扑 fail-closed、导出并发闸、日志 PII 掩码、运行指标补齐（2026-10-26）

> 承接 `deliverables/audit-2026-10-25/audit-report.md` §14.5 的"仍未处置"清单。
> 本轮把 `P-1`/`P-2`/`O-1`/`O-2`/`O-3`/`T-3`/`T-4` 做掉，`A-1` 解掉一个强连通分量
> （40 → 36 模块），剩余三个分量属需改所有权的重构，**只登记不改结构**（报告 §15.2）。

| 项                       | 内容                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-1 事务拓扑 fail-closed | 生产语义下探测到 `standalone`（多集合写非原子、失败留残骸）⇒ `/readyz` 判 503（`checks.topology=transactions_degraded`），**不阻断启动**。判据落在 `utils/transaction.js` 的 `transactionReadinessBlocker()`，与既有的多实例闸合并成单一 `topologyBlocker`，同时命中时**多实例优先**（它同时影响审计链与限流计数，且修法与事务拓扑无关）                                      |
| P-2 导出并发闸           | 新增 `services/exportConcurrency.js`：上限 2 / 有界队列 8 / 排队超时 30s，全部可经 `EXPORT_MAX_CONCURRENCY`、`EXPORT_MAX_QUEUE`、`EXPORT_QUEUE_TIMEOUT_MS` 调整并在越界时**钳制 + 一次性告警**。队列满或超时 → 429 `EXPORT_BUSY` + `Retry-After`。释放幂等、槽位**移交**给 waiter（不"先减再加"，避免空窗被第三个请求插队）                                                   |
| O-1 日志 PII 集中掩码    | 新增 `utils/logPiiMask.js`，接在 `logger.sanitizeLogInfo` 末尾（清洗 → 截断 → 掩码）。判定顺序 **email → 身份证 → 手机号**（身份证必须先于手机号，否则 18 位号码会被手机号正则切碎）；键名用闭合集 + 后缀判定，**刻意不含 `token`** 后缀以免误伤 `tokenVersion`；`requestId`/`userId`/`socketId` 作为结构性标识不掩。`LOG_PII_MASK=false` 可关，关闭时在生产语义下落一条 warn |
| O-2 运行指标补齐         | 新增 `export_inflight`、`export_queued`、`export_rejected_total{reason}`、`ws_connections`、`ws_inbound_throttled_total`、`ws_inbound_disconnects_total`。WS 连接数用**拉取式** `registerWsConnectionSource`（4 处增删点任一漏推都会让 gauge 长期偏高，拉取式免掉这个失效面）；文本与 JSON 快照两通道同源                                                                     |
| O-3 tracing 适用边界     | 新增 `docs/adr/ADR-010-不引入分布式追踪的适用边界.md`：把 `requestId` 能覆盖什么、跨进程边界为何断在这里、什么条件下该重新评估，写成可证伪的判据而不是"暂时不做"                                                                                                                                                                                                              |
| A-1 惰性环（部分）       | 抽出零 require 叶子 `src/config/envSemantics.js`（环境别名/生产语义判据），`config/validate.js` 改为 re-export。实测强连通分量 40 → **36** 模块，`requireCycles` 的 `LAZY_SCC[0]` 26 → **22**                                                                                                                                                                                 |
| T-3 路由分支补测         | 新增 `routes/routeGuardBranches.test.js` 9 例：strict 档两条守卫（明文注册被拒、enc+明文并存被拒）与改密接口、巡检时间窗倒置、`POST /reports/export/pii` 类型白名单、创建用户口令 64 字符上限，均带反向对照                                                                                                                                                                   |
| T-4 sharedCache 故障注入 | 41 → **47** 例，覆盖三类"总闸式注入看不见"的形态：单条命令失败（`GETDEL` 抛错走 get→del 降级，两步必须落在同一份内存回退上）、`DECR` 回收路径（真实现此前零覆盖）、连接级故障的**日志节流**（未就绪期的重试风暴不得刷 error 日志）。三处逐一做变异，确认变红后还原                                                                                                            |

---

### 七维审计复核：把「报告结论」逐条回源码验证，再修真正成立的那几条（2026-10-25）

> `deliverables/audit-2026-10-25/audit-report.md` 的基线是 `01e08f7`。复核时 HEAD 已是
> `170467c`，**报告里的大部分数字已经过期**（380/109 个文件、28 套件 56 用例红、19 条环）。
> 本轮先把每条结论回到当前源码与实跑结果上验证，再只修验证成立的部分；报告已就地打叉
> 并补第 13 节复核记录。**不修不存在的问题，也不沿用别人的数字。**

| 项                                          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-4 压测脚本（修）                          | `scripts/load-test.js` 仍在读 `r.body.data.token`，而登录早已只下发 httpOnly Cookie（I-01）⇒ 登录步必然抛错，E/D 两相**从未真正执行过**。改为从 `Set-Cookie` 取 `access_token` 显式回放（`loadTestEngine` 增加 `cookie` 通道，与 k6 脚本同口径）。**实跑证据**：`npm run test:load` 8 通过 0 失败，B/C/E/D/D+ 全绿，基线已落 `logs/load-baseline.json`——这是本仓第一份可信的压测结果                                                                                                                                                                                                                                                                                                    |
| 压测 D 相与新封禁策略冲突（修，报告未发现） | #21 之后 IP 封禁要求「同一 IP 失败过 ≥2 个不同账号」，而脚本只打一个用户名 ⇒ 即使取到凭据也永远等不到 403。改为两个一次性靶用户交替失败，并显式断言「401 覆盖 ≥2 个账号」。实跑日志确认 `distinctAccounts:2, ipBanApplied:true`                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| A-2 就绪闸（修，已在工作区）                | 多实例且无分布式审计锁时 `/readyz` 判 503（`checks.topology`），不再只打日志；`constants/runtime.js` 把重复的 Redis 就绪探测抽成 `sharedCacheReady()` 一处                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| A-1 惰性环（登记，不是消除）                | 报告写的「19 条」在任何枚举口径下都复现不出来。实测：**4 个强连通分量 / 40 个模块 / 122 条简单环**（长度 ≤9）。新增 `requireCycles` 用例按**分量**逐条登记，新增或消失都会红——分量是与遍历顺序无关的不变量，条数不是                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| T-1 MFA（补测）                             | `mfaController` 分支 64.58% → **87.5%**，函数覆盖 80% → **100%**（补 `getMfaStatus` 三例：余量如实、已关闭为 0、用户不存在不抛）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| T-2 二次验证（补测）                        | `securityController/reauth.js` 分支 50% → **100%**：补「令牌无 sid 时按未绑定会话签发，且不认任何具体会话」                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 锚点台账（同步）                            | A-2 改动使 `app.js` 行号整体后移，7 处 `LIVE` 登记与 4 个文件里的引用注释逐条改到新行号（`:205→:206`、`:249→:250`、`:487→:500`、`:546→:559`、`:550→:563`、`435-457→435-479`、`460→:473`），手册 `:297→:302` ；同日 `src/app.js` 的 `recordReadyz` 判据由 prettier 展开的九行嵌套三元收成 `?.` + `??` 单行形态（`format:check` 原本就在这个文件上红），行号再迁 3 行，登记同步到 `:462/:476/:503/:562/:566` 与 `435-482`；顺带发现 `queryLimit.test.js` 引用的 `app.js:536` 本就失实（真实落点是 `:592` 的 `query parser`），一并改对                                                                                                                                                    |
| 文档对账（修判据）                          | `documentationDrift` 的 bash 续行断言在 CRLF 检出下必然假红（同一份文档 Windows 红、CI 绿）。改在 `read()` 入口统一行尾——行尾是检出形态，不是内容事实                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 指标契约（同步）                            | `runtimeMetricsCoverage` 的 `/readyz` 判定正则绑定死了旧的三元表达式形状，A-2 加一档拓扑阻断即假红。改为钉三件语义（`ready ? 'ok'` / `mongo.ok ? redis.reason` / `topologyBlocker.reason`），并保留可失败反证                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 信号用例（修竞速）                          | `imageDigestGate` 的 SIGTERM 用例写死「睡 1 秒再发信号」，而 Windows/MSYS 起一个 sh+替身要 2–3 秒 ⇒ 替身日志为空、被判成"脚本没被叫醒"。改为**等替身留下第一行日志再发信号**（判据更严，不再依赖机器速度）                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 随机顺序 worker 崩溃（修，CI 实证）         | CI 的 `Test order independence (randomized)` 在 `170467c` 上是红的（`test (26.x)` 失败、22/24 被 fail-fast 取消），红点是 `appTrustProxyAndReadyzGuards` 的 `Jest worker encountered 4 child process exceptions`。根因不在断言：`auditLog` 用 `setImmediate` 异步落库，而回调体里才惰性 require `utils/fingerprint`；文件跑完、Jest 拆环境后回调才被调度，require 拿到 `undefined` ⇒ `TypeError: Cannot destructure property 'computeFingerprint'` 抛在测试框架之外，**直接崩 worker**（同文件按默认顺序却全绿，是典型的顺序耦合指纹）。修法：该套件 `afterAll` 放完一个 tick；修复后按三个 seed 各跑两次该文件 6/6 绿，再按 CI 口径跑全量三 seed，`appTrustProxy` 不再出现 worker 崩溃 |
| 测试树纯净性（入库）                        | 3 个新增用例（T-1/T-2/T-5 与 P-3 降级 TTL）与 `scripts/check-openapi-drift.js` 此前未跟踪，`testTreePurity` 因此红；已入库                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| D-1 OpenAPI 门禁（修，已在工作区）          | 新增 `npm run docs:check` 并在 CI 阻断；反证过：给生成器注入一条 path 后比较必然为 false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

### 告警抑制规则移除、nginx 显式拒绝 `/readyz`、Node 运行时进 CI 矩阵、5 条"假绿"测试逐条复核（2026-10-24）

> 审计第二批 6 项。其中 **2 项经复核不成立**（compose app 的 healthcheck、两个"假绿"测试），
> 记录在下方表格的对应行——不修一个不存在的问题，与修一个真问题同等重要。

| 项                            | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 告警抑制规则（移除）          | `alertmanager.yml` 原为「任何 critical 抑制同实例任何 warning，`equal:['instance']`」，理由写的是「BackendDown 时 HighP95Latency 必然伴随」。复核后整条移除，三条理由写进文件：①该理由**事实错误**——目标停止导出指标后 `rate()` 无样本，延迟告警根本不会触发；②即便成立，`equal:['instance']` 也匹配不到 `ReadinessProbeMissing` 的 `absent()` 分支（`absent()` 只回填选择器里的 `job`），而那正是"后端真挂了"时唯一会亮的伴随告警；③若真能生效，`AuditRecordsDropped`(critical) 会压掉同实例 `DiskSpaceLow`(warning)——把**根因**信号静默掉。同时留了新增抑制的三条门槛（alertname 精确 / target 是 source 的纯后果 / equal 标签两侧必然存在）                                                                          |
| 告警标签（修）                | `alert-rules.yml` 的 `HighErrorRate`、`SecurityAlertBurst` 由 bare `sum(...)` 改为 `sum by (instance)`。理由不是"为了让抑制能匹配"（那条规则已移除），而是多实例部署下 bare `sum` 会把全部标签丢掉：告警分不清哪台机器出错、面板无法按实例下钻、`{{ $labels.instance }}` 渲染成空串。单实例环境里这个缺陷"看起来完全正常"，所以只能靠契约测试钉住                                                                                                                                                                                                                                                                                                                                                                       |
| nginx `/readyz`（修）         | `deployment/nginx.conf.example` 此前只有注释「/readyz 刻意不对外」，配置上无任何对应指令 ⇒ 落进 `location /` 的 `try_files` 返回 **200 + index.html**。外部拨测配了这个地址会**恒判健康**（它探的是 nginx 能否返回 HTML，不是 Mongo 可不可达）。新增 `location = /readyz { return 404; }`：精确匹配、不反代、用 404 而非 403（403 等于确认"该路径存在且被保护"）                                                                                                                                                                                                                                                                                                                                                        |
| compose healthcheck（不成立） | `docker-compose.yml` 的 app 服务确实没有 `healthcheck`，但**不是缺陷**：健康检查来自镜像（`Dockerfile:201` 的 `HEALTHCHECK --interval=30s`），Compose 在服务未声明时原样继承；mongo/redis 要在 compose 里写，是因为它们的官方镜像不带。**反过来补一条是有害的**——compose 侧手写的通常只探 `/health`，会整体顶掉镜像侧"并行探 `/readyz` + `/health`、退出码只取 health"的口径。已补契约测试钉住该形态，compose 该块内写明不要补的理由                                                                                                                                                                                                                                                                                    |
| Node 运行时（修）             | 生产镜像 `node:26.12.0-alpine`，CI 矩阵只有 `22.x/24.x` ⇒ **实际发布到生产的运行时从未被任何 CI 用例执行过**。矩阵加 `26.x`（`[22.x, 24.x, 26.x]`，分别对应 `engines` 下界 / 当前 LTS / 发布基线），并新增 `nodeRuntimeMatrixParity.test.js` 把"镜像主版本 ∈ 矩阵、三处 FROM 一致、`engines` 下界 ∈ 矩阵"钉成闸门。选加矩阵而非降镜像版本：后者要回退一次四天前做过三源核验的升级，前者只增加验证、不改生产行为                                                                                                                                                                                                                                                                                                         |
| 前端 PII（修）                | `web-admin` 的 `currentUser` 落 localStorage 时改为白名单投影（`userId`/`id`/`_id`/`username`/`roles`），不再写入 `email`/`realName`/`phone` 等 PII。httpOnly cookie 的收益此前被明文 PII 抵消。新增 `authPersistenceNoPii.test.js` 6 例：白名单闭合性、登录与 `/auth/me` 两条路径不落 PII、内存态仍保留完整字段、刷新后身份骨架可用、历史脏数据被覆盖                                                                                                                                                                                                                                                                                                                                                                  |
| 5 条"假绿"测试                | 3 条成立并已修（见下），2 条不成立。①`authMiddlewareFailClosedGuards`：三条 `not.toThrow()` 换成可观察后果（库里改 inactive → 失效后必须 401），**变异复测**从"11 例全绿"变为"1 例红"；②`User.test.js`：从"字段存在"改为按**选项值**断言（10 个凭证字段 `select:false`、西里尔同形字 `аdmin` 必须被拒、72 **字节**边界、`status.enum` 与 `USER_STATUS` 同源、`username_ci` 的 collation）；③`mfaReplayGuardMax`：补"先认领再写库"的顺序断言（原断言对换序完全免疫）。**不成立**的 2 条：`mfaControllerOrchestration` 的认领失败分支已在 `mfaReplayGuardMax:118` 覆盖；`securityConfigHandlers` 的读回一致已由 `systemConfigBooleanContract.test.js`（真实 Mongo）覆盖——两处都在文件头写明了分工，避免同一结论被再次提出 |
| 契约测试                      | 新增 `composeAppHealthcheck.test.js`（5 例）、`nodeRuntimeMatrixParity.test.js`（5 例）、`authPersistenceNoPii.test.js`（6 例）；`nginxProxyContract` +1 例、`alertingConfig` +6 例。三处变异实测：`return 404`→`200` 变红、`sum by (instance)`→bare `sum(` 红 2 例、给 app 补 healthcheck 变红 1 例                                                                                                                                                                                                                                                                                                                                                                                                                    |

### WS 绕过探针改为两个单违规场景，并要求拒绝理由可归因（2026-10-24）

> 审计 P2：`scripts/audit-probes/ws-session-bypass.cjs` 只用一个令牌，**同时**带
> 「已吊销会话」与「非白名单 IP」两条违规，判据是"收到任何 `auth-error` 就算拒绝"。
> 于是它只证明了**至少一条**控制在生效：把 `sid` 校验删掉、只留 IP 校验，探针照样
> `exit 0` 报"P0-2 修复在位"。对一个有两条独立控制项的漏洞，"至少一条"不是证据。
> 另外 HTTP 侧只 `console.log` 状态码、从不校验，一个 500 或"因别的原因 401"也会被
> 当成有效对照。

| 项            | 内容                                                                                                                                                                                                                                         |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 场景拆分      | 拆成 `session_revoked`（会话已吊销 + IP 不限制）与 `ip_not_allowed`（会话正常 + IP 不在白名单），每个场景只带一条违规。两个用户、两个会话、两个令牌，`allowedIPs` 与 `sessionStatus` 互斥地只坏一个                                          |
| 理由归因      | `decideVerdict` 新增 `expected` 参数：必须收到 `auth-error` **且文案匹配本场景那条控制**才判 `rejected`。不匹配、或调用方未声明期望 → `inconclusive`（exit 2），不再算通过。帧里没有错误码，文案是唯一通道，故文案改动会让探针变红而不是变绿 |
| HTTP 前置对照 | 改为断言 `status + errorCode`（`401/DEVICE_SESSION_REVOKED`、`403/AUTH_IP_RANGE_DENIED`）。不符即判 `inconclusive`：同一令牌在 HTTP 侧不是因本场景那条规则被拒时，WS 侧的"被拒"无法归因                                                      |
| 服务端观察    | 不再取 `[...clients.values()][0]`（多场景同进程时会拿到上一场景的残留或未认证占位条目），改为按**本场景 userId** 精确匹配；第 5 步同时打印实际收到的下行帧，让证据可见                                                                       |
| 体积          | `makeClients` 的 get/post 合并为一个 `send(method, path, body)`，抵消新增逻辑，维持 `max-lines` 300 以内                                                                                                                                     |
| 测试          | `src/tests/wsProbeVerdict.test.js` 6 例 → 9 例：新增「理由不匹配 ⇒ 不可判定」「两场景理由互不通用（互为反例）」「未声明期望理由 ⇒ 不可判定」，并钉住场景表仍是两个单违规场景                                                                 |
| 可证伪性      | 实测三组：① 两条控制都摘 → `bypass,bypass exit=1`；② **只摘 IP 校验** → `rejected,bypass exit=1`（旧判据在这种情形下会给 exit 0）；③ 恢复后 → `rejected,rejected exit=0`，两场景各自拿到自己的 `auth-error` 帧                               |

### MFA 关闭与恢复码重生成改为条件写（CAS）（2026-10-24）

> 审计 P2：`mfaController.js` 四个状态变更写点里，`mfaEnroll`（:174）与 `mfaEnable`（:273）
> 已是条件写，注释还写着「下发即生效，不得被并发请求静默回收」；而
> `regenerateRecoveryCodes`（:104）与 `mfaDisable`（:368）仍是 `findByIdAndUpdate(_id)`
> **无条件覆盖**。同一份文件里同一条不变量，修了两处漏了两处。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 重生成 CAS | 过滤条件改为 `{_id, mfaEnabled:true, 旧码组全等}`。两次并发重生成携带**相邻窗口**的不同码时两次 `claimTotpWindow` 都会成功（窗口不同不算重放），后到者原会顶掉先到者刚下发的 10 张——调用方已抄走的那组全部作废，而两个响应都宣称"已生成"。空数组分支用 `$in: [[], null]` 覆盖"字段缺失"的历史文档（Mongoose 读时补 `default:[]`，库里没有该字段，直接写 `[]` 会永不命中 ⇒ 这类用户永久 409） |
| 关闭 CAS   | 过滤条件改为 `{_id, mfaEnabled:true, **本次验证过的 mfaSecret**}`。验证是对 `user.mfaSecret` 解密后做的；该字段被并发 enroll/enable 换掉后，无条件写仍会 `mfaEnabled:false + mfaSecret:''`，把本次从未证明过控制权的**新登记**一起清掉，审计还记成"用户关闭 MFA"                                                                                                                             |
| 落空归因   | 两处 CAS 落空后重读一次：已关 → `MFA_NOT_ENABLED`（不再记第二条"成功关闭"审计）、码组被换 → `USER_STATE_CONFLICT`、无 MFA → `MFA_NOT_ENABLED_NO_CODES`。**落空时绝不返回本次生成的码**——它们从未生效                                                                                                                                                                                         |
| 分层       | `mfaDisable` 的第二因子判定（TOTP 优先 / 恢复码兜底）移入 `mfaService.verifyDisableFactor`：这是"什么算验证通过"的领域判定，controller 只该决定"通过后写什么、失败回什么码"。顺带把控制器压回 `max-lines` 300 以内                                                                                                                                                                           |
| 测试       | 新增 `src/tests/controllers/mfaWriteCasConcurrency.test.js`（4 例，**真实 Mongo**，用闸门制造确定性交错而非 sleep）：① 并发重生成恰好一次 200，且成功响应下发的 10 张码**逐张**能对上库内摘要；② 关闭与新登记并发时旧密钥的验证不得清掉新登记；③ 缺 `mfaRecoveryCodes` 字段的历史文档仍可重生成；④ 无并发时两端点照常成功（CAS 不得把正当用户挡在门外）                                      |
| 可证伪性   | 已做变异验证：把两处过滤条件临时改回 `{_id}` 后，用例 ①② 立即变红（实测 `Expected length: 1 / Received length: 2`，两份响应各带一组不同的 10 张码），用例 ③④ 保持绿 —— 说明断言钉的是 CAS 本身，不是环境                                                                                                                                                                                     |

### 迁移脚本参数严格化，且不再在 require 时连库（2026-10-21）

> 审计 P2：`scripts/migrate-pii-encryption.js` 用五个独立 `if` 解析开关，未知参数一律当没看见。
> `--keys-onl`（少一个字母）不会报错，`keysOnly` 保持 false ⇒ 退化为**默认全量模式**
> （加密列 + 回填检索键 + 升级 v1），而操作者以为只补键。同一文件还在模块顶层无条件
> `main()`：任何 `require()` 都会立刻连库并扫描改写 PII。

| 项         | 内容                                                                                                                                                                                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 参数严格化 | 新增 `scripts/cliFlagPolicy.js`（本仓第四份「开关白名单」实现，抽出来共用）：`parseFlags(argv, allowed)` 把白名单外 token 全部收进 `errors`；建议用**编辑距离 ≤ 2**（全等抹平法对"少一个字母"永不命中，而那正是最危险的误输）。`migrate-pii-encryption.parseArgs(argv)` 返回 `{args, errors}`，`main()` 在**任何副作用之前**以退出码 2 拒绝 |
| 顶层执行   | `main()` 改为 `if (require.main === module)`；`--rotate` 的密钥快照本就在 `main()` 内有等价语句，删掉顶层重复。`parseArgs` / `MODE_FLAGS` / `PII_TARGETS` 导出供测试                                                                                                                                                                        |
| 文档闸     | `runbookSecretSource.test.js` 的 `EXTRA_SECRETS` 补 `run-rollback-drill.js: ['AES_SECRET_KEY']`——快照加密后缺密钥即 exit 2，手册 cron 必须自带来源，否则预发演练静默失败                                                                                                                                                                    |
| 测试       | `src/tests/deploy/cliArgStrictness.test.js` 增用例 19-23（合法全给不误伤 / 拼错必须报错且不猜真 / 位置参数拒绝 / 子进程实测退出码 2 且不连库 / `require` 不触发 `main`）；同时把 `generate-secrets` 的密钥清单钉数补上 `mongo_keyfile`（并行改动新增，钉数按设计要求显式确认）                                                              |

### 举报对话框改为可搜索对象选择器（2026-10-21）

> 缺陷（可用性）：举报对话框把「对象 ID」摆给用户填 24 位 ObjectId，而一线人员拿不到该值
> —— 它只出现在接口响应里，界面上从不显示。记录型举报（用户/设备/报警记录）实际不可用。

| 项       | 内容                                                                                                                                                                                                                                                                     |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 前端控件 | `ReportDialog.vue` 的记录型目标由 ID 输入框改为远程搜索下拉：界面只出现名称/编号，`targetId` 作为选中值随载荷上行、用户不可见。输入防抖 300ms（每次输入只落一条审计）、请求序号防「后发先至」覆盖、选中项在候选刷新后仍保留标签                                          |
| 新端点   | `GET /api/security/report-targets?type=&keyword=`：免权限码（举报对全员开放），候选集按**举报人数据范围**过滤，每类上限 20 条；投影不含 phone/email、报警描述、上报人姓名                                                                                                |
| 同判据   | 新增 `rbac.buildRecordScopeFilter`，与核验侧的 `isRecordInScope` **逐臂同值**（含「本人 `_id` 短路」、department 缺失仍放行本人、`none` 一律 deny）。`buildDataScopeFilter` 在这两处边界上并不等价——直接复用它会出现「下拉里选不到自己」或「选得到却提交 403」           |
| 限流     | 候选查询消耗 `authenticate` 内的账号级 userLimiter（200/15min），与举报提交的独立 20 次写配额分开：搜索不会吃掉提交配额（否则 429 文案会指向「提交过于频繁」，根因不可见）                                                                                               |
| 文档     | `src/docs/generate.js` 补 `/api/security/report-targets` 并重生成产物；端点经 `securityRoutes` 直接注册（不走 `router.use` 子挂载——openapiSync 的采集对子挂载是盲区，塞进去等于绕过文档门禁）                                                                            |
| 测试     | 新增 `src/tests/security/reportTargetCandidates.test.js`（16 例：免权限码可达 / 范围一致性 / **候选与提交核验同值** / 最小投影 / 参数边界 / 20 条上限与独立配额）；`web-admin/src/tests/components/reportDialog.test.js` 重写为 13 例，含「界面上不出现对象 ID」回归锚点 |

### 审计 WAL 裁剪按持久化承诺分级 + 回滚演练备份加密（2026-10-21）

> 按 `deliverables/七维审计终稿-核验版-2026-10-21.md` 的两项 P1 整改。
> 旧结论「outbox 先落 WAL 名不副实」已在工作树中修复（`auditOutbox.js` 已 `await appendLineDurable` 并 fsync），
> 但**裁剪侧**仍会把这些已 fsync 的行按位置丢出主 WAL，本节点修的是这一半。

| 项           | 内容                                                                                                                                                                                                                                                                                                                                                                    |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WAL 裁剪分级 | `auditOutbox.js` 写出的行带 `__walDurable`；`auditWalCap.enforceWalLimit` 改为**普通行优先丢、durable 行默认不丢**。普通行不足时记 `walDurableTrimRefusals` 并停手（WAL 继续超限，这是有意取舍），只有显式 `AUDIT_WAL_ALLOW_DURABLE_TRIM=true` 才裁 durable 并计 `walDurableDropped`。理由：`.discarded` 永不回灌，按位置裁剪等于把「已回成功」改成「落盘但永久不入库」 |
| 重放剥离     | `auditBufferWal.stampReplaySeqs` 在交给缓冲前删除 `__walDurable`（保留 `__walSeq`），避免 WAL 记账字段进入 Mongo 文档；回写补号行在删除**之前**序列化，否则会丢标记                                                                                                                                                                                                     |
| 面板投影     | `securityController/overview.js` 的 `auditLoss` 新增两项；`AuditLogView.vue` 的 `auditLossTotal` 计入 `walDurableDropped`（承诺缺失），`walDurableTrimRefusals` 只进明细（此刻尚未丢记录，处置方向是扩容而非取证）                                                                                                                                                      |
| 演练备份加密 | `run-rollback-drill.js` 由明文 gzip 改为 gzip 后 AES-256-GCM（魔数 `FSMSBK1`，密钥由 `AES_SECRET_KEY` 派生），缺密钥直接退出、不退回明文；`.discarded` 同族：`restoreCollection` 按魔数识别，改造前的明文快照仍可回灌但显式告警                                                                                                                                         |
| 可观测性     | `metricsAuditDrops` 新增 reason `wal_durable_lost`（由 `auditWalCap` 在显式开关裁掉 durable 行时上报，自动被既有 `AuditRecordsDropped` critical 规则覆盖）；新增计数器 `audit_wal_durable_trim_refusals_total` 与告警 `AuditWalTrimRefused`（warning）——「拒绝裁剪」意味着 WAL 无界增长，必须在写满磁盘前可见                                                           |
| 文档对齐     | `deployment/backup-encryption.md` 删除「单人拿不到完整链」这一与设计矛盾的断言，改为「默认无口令私钥下该控制不成立」并给出两条可兑现路径（口令分离 / 人员分离）；`deployment/rollback-drill.md` 的 cron 示例补 `AES_SECRET_KEY_FILE`，并新增第 5 条纪律（缺密钥退出码 2 是 fail-closed，不是配置错误）                                                                  |
| 测试         | 新增 `src/tests/services/auditWalDurableTrim.test.js`（5 例：durable 全留 / 拒绝裁剪 / 显式放开 / 全 durable 不动文件 / 重放剥字段，含两条 Prometheus 上报断言）；`rollbackDrillRestoreVerification.test.js` 增「归档必须带 FSMSBK1 魔数且不得同时留下明文 .ndjson.gz」与 `manifest.encrypted` 断言；`auditDropMetrics.test.js` 的 reason 闭合集合断言扩到五项          |

### 搜索面板新增可见关闭按钮、隐藏 ESC 提示（2026-10-21）

> 全屏态下 ESC 先被浏览器用于退出全屏（`keydown` 的 `preventDefault` 拦不住），把 ESC 当关闭卖点展示会误导；改为「按钮是可见入口，ESC 静默保留」。

| 项         | 内容                                                                                                                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 组件行为   | `web-admin/src/components/SearchPalette.vue` 输入行右侧新增 `.search-palette__close` 按钮（`aria-label`/`title` 取 `common.close`，纳入既有 Tab 焦点陷阱）。ESC、遮罩点击、⌘K/Ctrl+K 再次按下仍照旧可关闭，只是 ESC 不再出现在 UI 上 |
| 提示与词表 | 页脚去掉 `ESC 关闭` 提示、输入行去掉 ESC 键帽（页脚只剩 ↑↓ 与 ↵）；随之无引用的 `common.searchHintClose` 从中英词表删除（两语言同步，键位仍对齐）                                                                                    |
| 测试       | `web-admin/src/tests/components/searchPalette.test.js` 新增「关闭按钮可关」与「UI 无 ESC 字样（kbd 与页脚）」断言；ESC 关闭与焦点归还用例保持原契约                                                                                  |

### 七维审计 2026-10-20：审计链检查点 / 固定睡眠门禁 / 运维关键路径 E2E

> 按 `deliverables/七维深度审计报告-2026-10-20.md` 整改。本节只记录三项中危的**结构性**修复；
> 其余按报告编号分散落在各模块的修复不在此逐条复述。

| 项               | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S-8 审计链外部锚 | 新增 `scripts/audit-chain-checkpoint.js` 与 `src/services/auditChainCheckpoint.js`：把链头与记录数写成 HMAC 签名的 JSONL 检查点，校验时逐行验签并核对锚点。可检出分支插入 / 链头替换 / 锚点前截断 / 检查点文件被改；**残余边界**（锚点与库同机、锚点后先加后删）已在 `docs/architecture.md` §7 与 `docs/threat-model.md` 明示，不宣称完整防篡改                                                                                                                                             |
| T-2 固定睡眠     | 新增 `src/tests/helpers/waitFor.js`（条件轮询）与 `src/tests/ci/noFixedSleepRatchet.test.js`：固定 `setTimeout` 收进棘轮，新增一处即红；真实网络/进程等待改走健康检查与事件，定时器逻辑用 fake timers                                                                                                                                                                                                                                                                                       |
| T-1 运维 E2E     | 新增 `scripts/ops-e2e.js` 与 `scripts/ops-e2e/journeys/*` 四条旅程：告警投递探针、部署失败→自动回滚、备份→恢复→校验、跨部门越权。各自独立子进程 + 内存 Mongo + 随机端口 + 本地假 Alertmanager；CI 的 `e2e` job 新增 `npm run test:ops-e2e` 并登记进 `ciGateWiring`。浏览器 no-skip 门禁（`MIN_PASSED=32`、`skipped==0`）未改动                                                                                                                                                              |
| O-5 部署演练     | `scripts/deployCommands.js` 抽出全部外发命令的 argv 构造（部署脚本不再自带命令字面量），`--dry-run` 打印与实际执行同源的真实命令；新增 `src/tests/deploy/deployCommands.test.js`。首次 `dry_run=true` 真实演练的步骤与留证表登记在 `deployment/deploy-workflow-rehearsal.md`——**真实 run 尚未执行**（需预发环境），未留证前 deploy.yml 的「未验证声明」保留。T-4 的预发定期演练 cron 见 `deployment/rollback-drill.md` §5.5；S-9 的 CI 开发机隔离口径见 `docs/security-dependency-watch.md` |
| 冒烟测试修正     | I-01 改为令牌只经 httpOnly cookie 下发后，`scripts/e2e-smoke.js` 仍从响应体取 `data.token`，导致 9 步 401（CI 必红）。改为从 `Set-Cookie` 取 `access_token`，继续用 Bearer 路径覆盖 `authenticate`                                                                                                                                                                                                                                                                                          |

### lint 棘轮批 1–3c：大文件目录化拆分与阈值重设（2026-10-18/19）

> 本轮是**纯搬家 + 度量收敛**：`security.js`、`authService.js`、`websocketService.js`、
> `authController.js`、`userController.js`、`securityController.js`、`sharedCache.js`、`initData.js`
> 按职责拆入同名目录（入口文件保留原有导出形态），复杂度与函数体积告警逐批下降。
> 业务语义未变；覆盖率/体积棘轮的键随路径迁移同步重设，并有 `coverageGateWiring` 与
> 分层棘轮测试守住“拆分后门槛没有被悄悄放宽”。针对拆分中暴露的 `max-lines` 最后若干条，
> 批 3a/3c 只做内容保持式迁移，未借机改行为。

### 响应头加固：X-XSS-Protection 测试守护 + Trusted Types 灰度 + CORP/Referrer-Policy 口径统一到 same-origin（2026-10-15 · 按 `deliverables/安全加固待办清单-2026-10-15.md` 的 P1+P2 逐项落地）

> 清单 P1（Trusted Types report-only）与 P2（COEP 决策记录 / CORP / Referrer-Policy）四项全部落地；P3 的 CSRF 双保险按清单自陈「不做也不构成缺口；仅在明确有子域/多应用共站时做」未做（本仓 nginx 单 `server_name`、无子域前端，已复核）。
>
> 落地过程中发现**三处清单本身没写准的地方**，一并记录：
> ① 清单给的 Trusted Types 写法（`useDefaults:false` + 只写 `require-trusted-types-for`）在 helmet 7.2.0 下**构造期直接抛错**——`normalizeDirectives()` 要求「必须有 default-src，除非显式 `dangerouslyDisableDefaultSrc`」，且该检查对 `reportOnly` 一视同仁（回源 `node_modules/helmet/index.cjs:90-92`，已实测复现）。照抄会让整个 app 起不来。已改为显式摘掉 `default-src`，下发结果就是单条 `require-trusted-types-for 'script'`，不会把 helmet 的全套默认指令拖进灰度策略制造噪音。
> ② Referrer-Policy 实际有**五份**副本，清单只列了 4 处，漏了 `web-admin/vite.config.js` 的 `buildSecurityHeaders`（vite dev/preview 这条托管路径）。五份已一并改，并由新用例钉住取值一致。
> ③ 顺带发现 `src/tests/controllers/roleControllerHierarchyGuards.test.js` 中「角色/权限审计全部由全局中间件派生（`utils/auditMeta.js:85-103` → `middleware/security.js:648`；挂载 `src/app.js:325-326`）」这句的**三个锚点全部指错位置**（其中 `security.js:648` 在 HEAD 就已落在 `checkIPBlacklist` 的 `IP_BLOCKED` 行，内容保持式迁移只会把它一路带下来）。已按真实落点更正为派生定义 / 派生调用 / 中间件挂载。

| 项                         | 内容                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trusted Types 灰度（P1）   | `src/middleware/security.js` 新增独立中间件 `trustedTypesReportOnly`，挂到 `applyResponseHardening()` 的 `reportingEndpoints` 之后。只写 `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'`，与主 CSP 头名不同、互不覆盖；`CSP_REPORT_ENABLED=true` 时附带 `report-uri`/`report-to`（复用既有 `/csp-report` 与 `csp-endpoint`），关闭时一条多余指令都不下发。**只上报不阻断**，对现有行为零影响 |
| COEP 决策记录（P2）        | `crossOriginEmbedderPolicy: false` 处补注释：为何关闭（无跨源隔离需求；开启会拦掉 Swagger UI 自注入资源、Google Fonts、导出 `blob:` 下载）、什么条件下应重新评估（含「`credentialless` 不是免费开关」这条反面证据）。此前全仓无任何 COEP 决策留痕                                                                                                                                                                      |
| CORP 收紧（P2）            | `crossOriginResourcePolicy` 由 `same-site` → `same-origin`，与 nginx 三份副本、`web-admin/vite.config.js` 及 helmet 7 默认值（`index.cjs:168`）对齐。同源反代拓扑下前后端同源，对同源 fetch 无影响                                                                                                                                                                                                                     |
| Referrer-Policy 收紧（P2） | 5 处由 `strict-origin-when-cross-origin` → `same-origin`：`src/middleware/security.js:139`、`deployment/nginx.conf.example:108`/`:175`/`:217`、`web-admin/vite.config.js:134`。前置确认已实测：跨源子资源仅 Google Fonts（不依赖 Referer）、全仓无外部跳转/防盗链/外链来源分析、后端唯一 Referer 消费点是 `originCheck.js` 的 Origin 缺失回退（同源请求照常携带 Referer）                                              |
| X-XSS-Protection 守护      | 新增 `src/tests/middleware/xssProtectionHeader.test.js`（5 例）钉住「下发且精确等于 `'0'`」与「恰好一个头」——该头此前全仓无断言，误改为 `false`（= 完全不设该头）不会有任何红灯。变异实测：`xssFilter: false` ⇒ 前 4 条转红。同时更正 `security.js` 中语义写反的旧注释（`xssFilter: true` 的语义本就是下发 `0`，照字面读会以为这是"开启保护"）                                                                         |
| 锚点同步                   | `security.js` 净 +82 行 ⇒ 指向其 123 行之后的 **9 处**锚点逐条迁移（`:608`→`:685`、`:666`→`:743`、`:686-690`→`:763-767`），涉及 5 个源码/文档 + 4 个测试文件；`git grep` 核验旧值 0 残留、新值一一对应，`commentAnchorFreshness` + `bareAnchorAttribution` 全绿                                                                                                                                                        |
| 新用例                     | 新增 `src/tests/middleware/securityHeaderPolicyHardening.test.js`（11 例）：report-only 头取值 / 不污染强制 CSP / 上报开关两态 / CORP 与 Referrer-Policy 五份副本取值一致 + 两类可证伪反证。变异实测：摘掉 `app.use(trustedTypesReportOnly)` ⇒ 4 条转红；CORP 回退 `same-site` ⇒ 2 条转红（断言有牙，非空洞）                                                                                                          |
| 门禁联动                   | 两个新用例文件均已 `git add`：`testTreePurity` 要求 `src/tests/**` 下不得存在未跟踪的 `*.test.js`（放在那里 `testMatch` 一定会执行它）                                                                                                                                                                                                                                                                                 |

### 修 CI 真红：审计 action 对账闸补登 roleController updated 广播载荷（2026-10-11 · 678e211 漏登）

> 678e211 给 updateRole 补 role-updated 广播时加了 action: 'updated' 载荷字段，但未同步 auditActionReconciliation 的 NOT_AUDIT_ACTION_LITERALS 排除清单（该闸要求每个 action 字面量要么有写入形态认领、要么逐条登记家族与出处；同文件 created/deleted 两条广播载荷均在册）。f4afd88 的 CI 止步于 lint ratchet 未跑到该步、f6bf4e7 早于 678e211，故此前未暴露。按既有机制补登（ws 家族，tally 5→6），并改准两处被 678e211 移动而过时的行号出处。

### 登录加密轨道安全收口七项（2026-10-10 · 外部审计 8 项发现逐项处置：限流漏配 / 对客预言机 / 信封不绑用途 / 公钥无钉扎 / strict 无生产收口 / PFS 未文档化 / dev 链存量 CVE）

> 对登录口令 ECDH 密文轨（ADR-001）的一轮外部审计逐项修复。另有两项审计结论经核对已过期：nginx 边层 Permissions-Policy 与 transportSecurity 的 HTTPS 断言在受审版本前已落地，本次仅复核确认、无改动。

| 项                             | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/mfa/enable` 补限流           | enroll/disable/recovery-codes 都有 strictLimiter，唯独「确认开启」那步漏配；已补齐。危害有界（爆破只能加速攻击者给自己的账户开 MFA），属一致性收口                                                                                                                                                                                                                                                                                                                |
| 登录 ENC_INVALID 对客统一      | 解密失败原映射 400 `AUTH_ENCRYPTED_CREDENTIAL_INVALID`，与 `AUTH_INVALID_CREDENTIALS` 可区分 ⇒ nonce 消费/时间窗弱预言机，与 loginCipher「失败原因不回传客户端做区分」的设计意图相悖。登录端点改为统一 401 `AUTH_INVALID_CREDENTIALS`；register/changePassword/mfaDisable/userCreate **保留**独立错误码——那些端点输入由攻击者自控（注册新用户、改自己口令），无预言机价值，且前端公钥缓存自愈依赖该码触发（自愈判定改由 `web-admin/src/utils/api.js` 按端点承担） |
| 信封绑定端点用途（AAD）        | 载荷原本只有 `{p, ts, nonce}`：一条**从未到达服务端**的捕获信封（提交失败/被丢弃，密文已上线）可在 ±5 分钟窗口内提交到任何接收密文口令的端点。新增 `CREDENTIAL_AAD`（login / register / password:current / password:new / mfa:disable / user:create）纳入 GCM additionalData，跨端点信封解密失败；刻意**不**绑用户名——跨用户重放会在口令比对处自然 401，绑用户名零收益却让每个前端表单多一个必须逐字一致的条件                                                    |
| 公钥指纹钉扎（防主动 MITM）    | 公钥经同一信道下发、不固定不验签，主动中间人替换公钥即可解密再转发——「截获密文无法恢复口令」只对被动窃听成立。构建期把公钥 SHA-256 指纹钉进前端包（`VITE_LOGIN_PUBLIC_KEY_SHA256`，≥16 位 hex 前缀），`ensurePublicKey` 对**取到的 PEM** 自行计算并比对，不符抛 `PUBLIC_KEY_PIN_MISMATCH` 且不得降级明文；指纹取自服务端启动日志的 `publicKeySha256` 字段（公钥指纹是公开信息）                                                                                   |
| strict 未开的启动期告警        | 新增 `src/config/loginEncryptGuard.js`：`LOGIN_ENCRYPT_STRICT` 未开时 loud warning + `incSecurityAlert('login_encrypt_strict_disabled', medium)`（已登记进 `failOpenSites` 台账）。**刻意不阻断启动**：strict 关死明文轨的前提是浏览器有 WebCrypto，而纯 HTTP 内网形态拿不到——致命闸会拦死一种合法部署形态；收口方式是「可见」而非「拒绝」                                                                                                                        |
| PFS 与轮换文档化               | `SECURITY.md` 新增「登录口令加密的密钥管理」：静态私钥 = 无前向保密，泄露按**口令泄露**处置（轮换私钥 + 强制全体改密），不是单纯换钥；轮换须与前端钉扎包一起发布（只换服务端私钥 ⇒ 全部登录被 `PUBLIC_KEY_PIN_MISMATCH` 阻断）。ADR-001 补三条决策记录（PFS 局限 / 钉扎收口 / AAD 绑定与 ENC_INVALID 合并的理由）；`deployment/secret-rotation.md` 补钉扎联动段                                                                                                   |
| dev 链存量 CVE（仅记录，未动） | `npm audit`：生产依赖 0 漏洞，35 个（5 moderate / 30 high）全在 jest 开发链（js-yaml→argparse→sprintf-js 等，经 istanbul 传入）。`npm audit fix` 非破坏性无效；`--force` 仅升 jest@30.5.2（breaking 大版本，559 个套件重度依赖 jest 29 配置与全局 setup）。CI 安全门禁为 `--omit=dev` 口径（生产 0 漏洞即过）。**决策：本次不升级**，建议维护窗口单独做 jest 29→30 并全量验证                                                                                     |

### 补装 login_ecdh_private_key 并修正 loginCipher 的前向保密表述（2026-10-10 · compose 挂了 10 个 secret 唯独漏了登录 ECDH 私钥，轮换手册里这把钥匙的流程从未生效）

> `src/config/secrets.js` 的 `FILE_BACKED_SECRETS` 早已支持 `LOGIN_ECDH_PRIVATE_KEY_FILE`，`scripts/generate-secrets.js` 也一直产出 `login_ecdh_private_key`（P-256 PEM），但 `docker-compose.yml` 从未装配它：app 的 `environment:` 没有对应 `_FILE` 指针，app 服务与顶层 `secrets:` 也没有对应定义。后果是生产部署下服务每次启动惰性生成临时密钥对——`deployment/secret-rotation.md` 里这把钥匙的轮换流程从不生效，且重启前的历史登录密文永久无法解密（做流量取证须在重启前完成）。另修正 `src/utils/loginCipher.js` 头注释：「截获密文的攻击者无法恢复口令」仅在私钥不泄露时成立，静态私钥 + 历史密文 = 明文（无前向保密），注释已补上前提与两种模式的取舍。

| 项           | 内容                                                                                                                                                                                                                                                                                               |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| compose 装配 | app `environment:` 补 `LOGIN_ECDH_PRIVATE_KEY_FILE=/run/secrets/login_ecdh_private_key`；app 服务与顶层 `secrets:` 补 `login_ecdh_private_key`（`file: ./secrets/login_ecdh_private_key`）；头注释手抄清单补 `openssl genpkey` 一条（原「首选」注释里"本清单遗漏"的说法随之失效）                  |
| 注释修正     | `src/utils/loginCipher.js` 头注释把「无法恢复口令」改为带前提的表述：信封自带临时公钥坐标，持静态私钥即可解密任一历史密文（无前向保密）；临时密钥对模式反之——重启前的密文永久不可解密                                                                                                              |
| 契约测试     | `composeProductionContract.test.js`：新变量进 ENV_KEYS 与 fileMap，`/run/secrets/login_ecdh_private_key` 的替身改为真实 EC PEM；新增「文件注入密钥装配三方一致」用例（environment `*_FILE` ↔ app secrets 清单 ↔ 顶层 secrets，且轮换手册点名的文件注入密钥必须全部在装），两类漏法各有一条反向自证 |
| 手册         | `deployment/secret-rotation.md` 的 `LOGIN_ECDH_PRIVATE_KEY` 行后补机制段：经 secret 文件注入，换钥＝随批替换文件后重启；未配置时重启前的密文永久不可解密                                                                                                                                           |

### 下拉浮层边角打磨：表面只画一层（2026-10-09 · 双层表面叠出双边框与错角，边角不圆润）

> 顶栏用户菜单与语言/主题下拉的浮层边角发毛、不圆润。复现定位到根因是**两层表面**：Element Plus 把浮层表面（底色/描边/阴影）画在外壳 .el-dropdown__popper.el-popper 上，还带着 base 的 5px 11px 内边距与 global.css 的 10px 圆角；pple-refine.css 又把表面画在内层 .el-dropdown-menu（12px 圆角 + 1px 描边 + 6px 内边距）。两层半径、描边、内边距全不一致，圆角处叠出双边框与错角。暗色还多一层脱节：html.dark .el-popper 的 --xf-gray-50 实底框围着半透明菜单。

| 项       | 内容                                                                                                                                                                                                               |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 外壳透明 | .el-dropdown__popper.el-popper 的 padding/background/border/box-shadow 全部清空（带 !important），表面只由 .el-dropdown-menu 画一层；箭头是外壳子元素、::before 自带配色，位置不受影响                             |
| 暗色再盖 | html.dark .el-popper 的实底/描边两条声明带 !important 且特异性 (0,2,1) 压过上面的 (0,2,0)，用 html.dark .el-dropdown__popper.el-popper 对 ackground/border 再盖一次，否则暗色菜单四周围一圈 --xf-gray-50 实底框    |
| 箭头同源 | 亮色下拉箭头描边改为跟随菜单的 --xf-border-color（EP 默认取 --el-border-color-light #e4e7ed，箭头根部露一截异色），底色取 EP 给菜单的 --el-bg-color-overlay；依旧不写 !important——placement 的透明边规则必须继续赢 |
| 不变量   | web-admin/src/tests/styles/tooltipTheme.test.js 补两例：外壳透明四件套 + 暗色再盖两条；亮色箭头与菜单描边同源、底色同源 EP overlay，并进「不能带 !important」循环                                                  |

### fail-open 降级补信号 + 持续型告警 + 站点台账门禁（2026-10-09 · 同一个降级动作被复刻 3 份，且全都没有可告警信号）

> 本仓早有明文纪律（`middleware/security.js:763-767`、`middleware/rateLimitStore.js:53-56`、
> `services/websocketService.js:723-725` 三处自陈）：「fail-open 放行必须有显式可观测信号——
> 否则『DB 挂了 + 全站裸奔』只有一条 error 日志可循」「降级态只写日志等于没有可告警信号——
> `grep 日志` 不是运维动作」。**验证码开关这条链没做到**：`isLoginCaptchaEnabled` /
> `isRegisterCaptchaEnabled` 自身没有 try/catch，真正做降级的是调用点，而同一段 try/catch
> 被复刻了 **3 份**（`authService.registerUser`、`authService.resolveLoginPassword`、
> `authController.getCaptchaStatus`），三份都是空 catch、都不发信号。

| 项          | 内容                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 收口        | 新增 `SystemConfig.captchaSwitch(kind)`：静态默认兜底 + 降级信号只在这一处发生；3 个调用点改为调它，各自手写的 try/catch 删除                                                                                                                                                                                                                                                                                              |
| 新信号      | `captcha_switch_db_fallback`（level `medium`）——验证码只是登录链**前置层**，降级后凭据型限流与爆破检测仍在，故与 `ip_blacklist_failopen` 的 `high` 不同级                                                                                                                                                                                                                                                                  |
| 第二个信号  | `captcha_active_bound_lost`（level `high`）：`captchaService.generate` 在「Redis 已启用但活跃数读取失败」时不设上限放行。**真正的放行点在 `active === null` 而非 `catch`**——`sharedCache.incrWithTtl` 两条降级路径都返回 `null`、从不抛，原先那个 catch 不可达、也永远发不出信号                                                                                                                                           |
| 告警        | 新增 `SecurityFailOpenSustained`（`for: 10m`，critical）。**按 type 分开判、不跨类型求和**：求和会掺进启动期恒正项（`immutableConfigGuard`/`legacyCbcGuard` 进程启动即写 `security_alerts_total`），既稀释真实突发、又让 crash loop 冒充安全事件；**用持续型而非速率型**：`SecurityAlertBurst` 是「10 分钟 ≥10 条」，而 fail-open 的危险形态恰是低速而持续，速率型可以永远不达标                                           |
| 台账 + 门禁 | 新增 `constants/failOpenSites.js`（5 个 fail-open 站点 + 10 个其它信号 + 1 个转发点，逐条声明 `direction/trigger/effect/why/tightening`）与 `tests/ci/failOpenLedgerGate.test.js`（8 例）：代码里的静态站点 ⇄ 台账条目双向闭合；每条 type 必须被持续型规则覆盖（**登记信号 ≠ 接上告警**）；反向也拦（规则点名不存在的 type 要红）                                                                                          |
| 刻意不做    | **不自动收紧**。把 fail-open 自动翻成 fail-closed 会把「保密性降级」转成「可用性事故」，且恰好发生在系统已经不健康时（黑名单 fail-closed = 库挂时全站请求无法验证；验证码 fail-closed = 没人能登录）。是否收紧是产品决策，不是告警规则能代做的                                                                                                                                                                             |
| 用例        | 新增 `tests/services/failOpenSignals.test.js`（11 例，含反向对照：两个 type 必须真能渲染进 `formatPrometheus()`）；`authControllerOutcomes.test.js` 的两条 `getCaptchaStatus` 重写到新接缝并**补前提自证**（断言真的调了 `captchaSwitch`）——原写法在该文件的 `../../models` 部分 mock 下会因 `captchaSwitch` 是 `undefined` 抛错、被兜底网吞掉而"通过"，等于在断言静态默认值                                               |
| 文档        | `README.md` 新增「开发/预览服务器的暴露边界」：dev 与 preview **都**绑 `0.0.0.0`，dev 下发**未打包源码**而 `src/**` 不在敏感文件黑名单内 ⇒ 禁止把 3001 发布到公网；`docs/threat-model.md` §3 增第 5 条（明确标注「仅开发期、不构成生产面」）；`docs/incident-response.md` §2 增「护栏失效信号」一条（该规则触发时，「没看到拦截」不能当作「没被攻击」的证据）。顺带修正 `README.md` 已过期的「4 条内置告警」（实为 13 条） |
| 锚点迁移    | 本轮删行使 `authService.js` -7 行、`authController.js` +13 行，全仓 **32 处**注释锚点随行号迁移（逐条按「迁移后该行内容 == 迁移前该行在 HEAD 的内容」核验）；`bareAnchorAttribution.test.js` 的回指台账两处坐标同步随迁。另修正 `statsAnomalyScope.test.js` 一处**本就指错**的锚点（写 `securityController.js:284`，而 `getSecurityStats` 实为 `:317`）                                                                    |

### 顶栏入口提示统一走 Element Plus 浮层 + 浮层箭头主题适配（2026-10-09 · 语言/主题图标此前挂的是浏览器原生 title）

> 顶栏语言/主题入口把提示写在 `el-icon` 的 `:title` 上，走浏览器原生提示——样式、字号、圆角与出现时机全由浏览器决定，和搜索/刷新/全屏的 `el-tooltip` 浮层是两套观感。本批把两处统一成 `el-tooltip`；顺着这条线查浮层配色时，又发现 Element Plus 的箭头是**独立元素**、取的是另一套变量，仓库只改了浮层底色，亮/暗两个主题下尖角都露着异色（暗色下拉菜单甚至挂一块异色三角）。

| 项       | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 统一提示 | `web-admin/src/layout/index.vue`：语言/主题的 `el-icon` 去掉 `:title`，外面套 `el-tooltip`（`placement="bottom"`，与搜索/刷新同规格）。**不能**反过来把 tooltip 塞进 `el-dropdown` 里——`el-tooltip` 的根是 `ElPopper`（`inheritAttrs: false`），dropdown 经 `ElOnlyChild` 下发的 `role`/`tabindex`/`id`/`aria-*` 与 forward-ref 会在那一层被吃掉，下拉直接点不开（实测：菜单浮层不再出现）                                                                                                                                                                                                                                                                                                                                       |
| 防叠放   | 下拉展开期间用 `:disabled` 收起提示：菜单浮层与提示浮层同位叠放会互相盖住，而展开时指针停在图标上不产生 `mouseleave`，提示不会自行消失。状态由 `@visible-change` 回写，两个入口互斥共用一个 ref                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 箭头同色 | `apple-refine.css` 新增四条 `.el-popper__arrow::before` 规则（亮色 tooltip / 暗色 tooltip / 暗色下拉菜单 / 暗色 `.is-light`，末条见「续修」），底色与描边逐一对齐浮层。箭头规则**不能**加 `!important`：朝浮层的那两条边由 EP 的 placement 规则置 `transparent`，那条规则带 `!important` 必须继续赢，否则旋转 45° 的方块会露出实心方角                                                                                                                                                                                                                                                                                                                                                                                           |
| 暗色描边 | `html.dark .el-popper.is-dark` 补上自己的 `border`：原先不写，暗色边悄悄吃亮色那条 `.el-popper.is-dark` 的边（两条特异性相同、后者在源流里更晚），改亮色配色会把暗色一起带跑                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 用例     | `web-admin/src/tests/layout/layout.test.js`：定位辅助从「按 title 找图标」改成文件原有的图标 path oracle（title 已不存在）；新增 `布局 · 顶栏入口悬停提示` 四条——顶栏图标一律不留原生 title、语言/主题悬停出 EP 浮层且文案走 i18n、下拉展开期间只剩菜单浮层。`web-admin/src/tests/styles/tooltipTheme.test.js`：读 CSS 源码比对「箭头与浮层同色」+ 箭头规则不带 `!important`，两条变异（箭头改回白、箭头加 `!important`）均能测红；续修新增两例——「暗色 date-picker 箭头与 `html.dark .el-popper` 实底同色」（表面规则在 dark.css，测试改读两个样式文件）与「`.is-light` 规则必须 `:not(.el-dropdown__popper)`」（特异性 (0,5,2) 高于下拉箭头规则 (0,3,2)，不排除会把半透明下拉箭头打成实底），第三种变异（删掉 `:not`）同样测红 |
| 续修     | 暗色 `.is-light` 浮层（`el-date-picker`，经 `ElTooltip effect="light"` 带 `is-light`）的箭头补上 `--xf-gray-50`/`--xf-border-color`：EP 的 `.is-light` 箭头取 `--el-popper-bg-color-light`（=`--el-bg-color-overlay`，EP 暗色 `#1d1e1f` 中性灰）与 `--el-border-color-light`（`#414243`），与 `#0f172a` 表面对不上。选择器必须 `:not(.el-dropdown__popper)`：下拉菜单表面是半透明 `rgba(30,41,59,.95)`，而 `.is-light` 规则特异性更高，不排除会把下拉箭头一起打成实底。`el-select` 浮层不渲染箭头，无需处理                                                                                                                                                                                                                      |

### 弱口令黑名单：匹配器口径修复 + 词干表扩充（2026-10-09 · 原 40 条里 24 条永远命中不了）

> 本批**不改依赖、不引入外部服务**。改的是「清单里的条目到底能不能被命中」。
> 旧实现是 40 条**口令字面量**，而归一化只做「末尾 ≥4 位数字收敛为 3 位」且**只归一化
> 口令侧**——两侧口径不一致的后果：实测 **24 条永远命中不了**，有效字典只有 **16 个词干**，
> 而文件看起来有 40 条。`helpers.test.js` 断言 `isBreachedPassword('admin@123') === true`
> 也是误导性的：生产路径上黑名单排在长度/复杂度之后，9 位口令根本走不到黑名单。

| 项       | 内容                                                                                                                                                                                                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因     | **匹配器与数据口径不一致，不是数据错**。清单里 `passw0rd!` / `p@ssw0rd` / `1qaz@wsx` / `abcd1234!` 这种写法本身就说明作者意图是「按词干匹配」；而旧匹配器要求字面量全等。死条目分两族：①8~11 位条目先被长度规则拒掉；②以 ≥4 位数字结尾的条目永远不等于任何口令的归一化结果                                                       |
| 改法     | 表改为**词干**（`constants/breachedPasswords.js`，40 条字面量 → 123 条词干）；归一化只保留一份且在口令侧：小写 → 去所有非字母数字 → 去末尾连续数字。两侧口径因此不可能再漂移                                                                                                                                                     |
| 不变量   | 每个词干至少含 2 个字母。这是**必要条件**：归一化不重排字母，故口令的字母序列（小写）必须等于词干的字母序列，而策略要求同时含大写与小写 ⇒ 字母数 <2 的词干在策略下不可达                                                                                                                                                         |
| 覆盖变化 | 有效词干 16 → 123（**+107**）；`Passw0rd!1234`、`P@ssw0rd1234!`、`Abcd1234!5678`、`1Qaz@Wsx1234!` 等由漏变拦；精度用例同时钉住 12 条强口令不被误伤（`SunshineRain99!` 归一化后是 `sunshinerain`，不是词干）                                                                                                                      |
| 用例     | 新增 `src/tests/utils/breachedPasswordMatcher.test.js`（176 例）：逐条为 123 个词干构造「除黑名单外无懈可击」的反例并断言被拦；表内条目必须已是词干（混入字面量即红）；回归指纹；精度；边界；原 16 条不回退                                                                                                                      |
| 失败策略 | 本批**不接** HIBP。若将来要接，失败策略**已预先拍板**：**fail-open + 指标 + 启动日志告警**，且必须带超时与缓存——不让第三方可用性拖垮改密链路                                                                                                                                                                                     |
| 文档     | `docs/mlps2-controls.md` 的 G8 证据补上「清单规模 + 用例文件」，并新增一段**如实边界声明**（是高频词干表，不是泄露库；长尾覆盖不了）；`breachedPasswords.js` 文件头修正「以隐私为由拒绝 HIBP」的**不完整推论**（原话本身准确：range API 确实只收 SHA-1 前 5 位；但真正有分量的理由是多一个运行时外部依赖及其失败策略，原文没写） |

三处测试夹具注释同步更新（`authCookies.test.js` / `changePasswordTypeGuard.test.js` /
`sessionManagement.test.js`）：导出名 `BREACHED_PASSWORDS` → `BREACHED_PASSWORD_STEMS`，
且 `Test@12345 归一化后为 test@123` 的解释已不成立（现在一步归一化成 `test`）。
三处夹具口令均经 `deliverables/probe-matcher-behavior.js` 复核为新口径下的安全值。

### IP 归属地英文化（2026-10-09 · 私网/环回地址的 `location` 从中文文案改为稳定码）

> 缺陷形状与 `constants/securitySuggestions.js` 那次同族：**后端把文案拼死，前端就永远翻不动**。
> `ipLocationService` 把私网/环回地址收敛成中文两字「内网」直接下发，而三个消费面
> （会话管理、审计日志列表 + 详情弹窗、IP 黑白名单）都是 `· {{ row.location }}` 原样渲染——
> 管理员把界面切到 en-US，IP 旁边那一格仍是中文。公网 IP 的归属地是 ip2region 数据文本
> （「中国·广东省·深圳市·电信」），不在本次范围：数据侧本地化是另一个议题。

| 项     | 内容                                                                                                                                                                                                                                                                                                                                             |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 根因   | 展示文本由后端拼好并焊进 API 响应：私网这一支既非数据也非用户输入，而是**服务层自己写死的中文**，vue-i18n 对已定型的字符串无从下手                                                                                                                                                                                                               |
| 修法   | 沿用仓内既有口径（`utils/labelMaps.js` 的 DEVICE_TYPE、`utils/auditLabels.js` 的 `audit.action.*`、`constants/securitySuggestions.js`）：**后端只出稳定码，文案归前端词表**。新增 `src/constants/ipLocationCodes.js`（单一来源，当前一码 `private`），`ipLocationService` 的 IPv4 数据侧（xdb 的「内网IP」）与 IPv6 range 判定两支都改为产出该码 |
| 前端   | 新增 `web-admin/src/utils/ipLocationLabels.js`（三处消费方共用一份映射，与 securityLabels/auditLabels 同形状：调用方传 `t`、未知值原样透传），词表新增 `ipLocation.private`（zh「内网」/ en "Internal network"）                                                                                                                                 |
| 兼容性 | `location` 类型不变（string\|null）；老后端下发的中文「内网」按原样透传（与修复前一致，不回退成空白），滚动发布不会出现空归属地                                                                                                                                                                                                                  |
| 对账闸 | 新增 `web-admin/src/tests/utils/ipLocationCodeParity.test.js`：`createRequire` 后端码表逐一对账双语词表，并断言英文侧不得残留 CJK——「后端加一码、前端漏翻」变红，而不是在界面上静默显示裸码                                                                                                                                                      |
| 用例   | 后端 `ipLocationService.test.js`（私网取值不含中日韩字符）、`sessionService.test.js`（内网 IP 两字段均为稳定码）；前端三个视图各补一条「切 en-US → Internal network、公网数据文本原样」的语言跟随用例                                                                                                                                            |

### IP 归属地英文化·续（2026-10-09 · 公网归属地的中英对照词典：数据段也跟随界面语言）

> 上一节只解决了「内网」那一格（后端写死的中文）。公网 IP 的归属地是 ip2region xdb 的
> **数据原文**——库里只有中文一份，于是切到 en-US 后「中国·浙江省·杭州市·阿里云」照样是中文：
> 实测全部地区段里 **89.9% 的出现次数是中文**，只修私网标签等于修了个零头。

| 项     | 内容                                                                                                                                                                                                                                                                                                                              |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 修法   | 新增 `web-admin/src/data/ipLocationDictionary.json`（1024 条中英对照）；`utils/ipLocationLabels.js` 按当前 locale **逐段**译名后以 `·` 重拼，词典未收录的段原样透传（不把整块归属地抹掉）。语言判定读 i18n 实例的 locale（非中文界面一律英文），渲染期读 ref 即建立响应式依赖，切语言重算                                         |
| 词典   | 国家名 244 条由 `Intl.DisplayNames` 按 ISO 3166-1 **双向生成**（zh 键 ↔ en 值，不手抄 244 条）；省州 / 城市 / 运营商人工校对。实测覆盖 CJK 出现次数 **98.06%**（国家 100%、省州 98.6%、城市 93.2%、运营商 96.7%）                                                                                                                 |
| 豁免   | 10 条高频段登记未收录（`内网IP` + 9 个译名不确定的段），理由逐条写在测试里，**上限 12 条**且每条键必须仍在数据里。口径：宁可以英文界面回退中文，也不把没把握的译名写进词典——**错的译名比中文更难发现**                                                                                                                            |
| 闸     | `web-admin/src/tests/utils/ipLocationDictionary.test.js` 直接对**真实 xdb** 取数（复用后端 `loadFromBuffer` 解析指针，只补段索引遍历）：国家/省州 100%、城市/运营商高频段（出现次数 ≥ 阈值）除登记豁免外全覆盖、整体覆盖率 ≥ 98%、词典无陈旧键、译文不含中文、豁免不越上限。数据刷新带入新地名 ⇒ 测试列出缺哪些，而不是靠用户发现 |
| 体积   | 词典经三个懒加载视图进入**异步分块**：首屏 `entryJsGzip` +1.1 KB，总 gzip +19.4 KB；五项预算均仍有余量（`check-bundle-budget` 通过），基线未动                                                                                                                                                                                    |
| 兼容性 | `location` 契约不变（仍是 string）；中文界面行为零变化（数据本就是中文，不过词典）                                                                                                                                                                                                                                                |

### 依赖审计：dev 树盲区补门禁（2026-10-09 · `security-audit` 只审 `--omit=dev`）

> 本批**不改依赖树**。改的是「谁在被审」：CI 两处 audit 都是 `npm audit --omit=dev`，
> 于是 devDependencies 的 advisory 永远不会让构建失败。实测含 dev **35 条（30 high / 5 moderate）**，
> `--omit=dev` 为 **0**，web-admin 两侧均为 0。

| 项                 | 内容                                                                                                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 根因               | 35 条包维度告警**只由 2 条公告**传染而来：`GHSA-vfj7-8cjw-p6xm`（braces，high，栈耗尽 DoS）与 `GHSA-hp3w-g68c-fv3c`（sprintf-js，moderate）                                                                                                                 |
| 为何不能 overrides | 两条公告的 `first_patched_version` 均为 **null**，受影响区间上界就是 registry 的 latest（braces 3.0.3 / sprintf-js 1.1.3）⇒ **无版本可指向**，与 uuid override 的前提不同                                                                                   |
| 为何不升 jest 30   | 实测（隔离探针）：jest 30 + nodemon = 3 high / 19 moderate；jest 30 去 nodemon = 0 high / 19 moderate。**moderate 反而由 5 升到 19**，且清不掉 `js-yaml@3 → argparse@1 → sprintf-js` 链                                                                     |
| 可达性             | 两条链实测**不可达**：braces 需攻击者可控 glob（本仓输入只有 jest CLI/config 与 nodemon ignore）；argparse 只被 `js-yaml/bin/js-yaml.js` 引用，`load-nyc-config` 走 `lib/js-yaml.js` 不加载它 ⇒ 性质是卫生问题，非可利用漏洞                                |
| 改法               | 新增 `scripts/check-audit-allowlist.js`（含 dev 审计**硬门禁 + 显式允许清单**）+ `deployment/audit-allowlist.json`（登记两条无补丁公告，含理由/可达性/复核期限 `2027-01-31`）；`ci.yml` 的 `security-audit` 作业新增一步；`ciGateWiring.test.js` 登记新门禁 |
| fail-closed 三判据 | ①未登记 ⇒ 红；②`reviewBy` 过期 ⇒ 红；③清单项在本次报告里**已无对应公告** ⇒ 红，必须删行（防清单只增不减）                                                                                                                                                   |
| 文档               | `docs/security-dependency-watch.md` 修正「含 dev 0 漏洞」的过期结论（该结论是 2026-09-16 时点，上游 09-18 / 09-24 才发公告 ⇒ 时间性回归，非本批引入），并登记两条已知例外                                                                                   |

判据来源是**根因公告**而非受影响包（35 条 = 2 条根因），故清单按 GHSA 编号登记，
不按包名——按包登记必然得到一份腐烂清单。

### CI 覆盖率门禁修复（2026-10-08 · `#13 Run tests with coverage` 三条阈值未达标）

> 这条红**不是**本批引入，而是被下一节的修复**逼出来的**：`#11 Run tests` / `#12` 修绿之前，
> `#13` 每轮都被前序 step 的失败 skip/cancel，从未真正执行。根因是 `ccddabc`
> （2026-10-03 并行会话批次）给两个文件新增了**从未被执行过**的函数/分支，
> 而阈值是 2026-09-04 / 2026-09-30 定的。

| 文件                             | 阈值（fn/br） | 修复前实测                 | 根因（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                                                                                                                    | 改法                                                                                                                                                                                                                                                                                    |
| -------------------------------- | ------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/middleware/auth.js`         | 90 / 87       | fn **87.5%**               | `ccddabc` 给 `invalidateUserCache` 补了 `publishInvalidate(...).catch((err) => …)`，函数数 15 → 16（14/15 变 14/16）。覆盖它的 `roleStatusInvalidatesUserCache.test.js` 把整个 `invalidateUserCache` `jest.mock` 掉了，只断言"被调用"，从不碰函数体                                                                                                                  | `observabilityWritesNeverReject.test.js` 新增 L7：三种拒绝形态（Error / undefined / 无 message 对象）下断言不抛 + warn 文案逐字。注：该键是 `auth:user:`；同一调用链上 `userPermissionService` 还会广播一条 `permcache:` 键（`userPermissionService.js:191`），故判据按前缀点名而非计数 |
| `src/services/deviceReminder.js` | 97 / 90       | fn **90%** / br **86.79%** | 调度器里两处 `markOverdueInspections().catch(...)`（`ccddabc` 新增）从未执行。**且普通 DB 故障驱动不了它们**——`markOverdueInspections` 整段体在 try/catch 内、**永不 reject**，这两条箭头是**第二道防线**，只在第一道被破坏（内层 catch 体自身抛错）时才生效。第一版用例正是用 DB 故障驱动的，实测 `logger.error` 只收到内层那条 `巡检逾期标记失败：…`，箭头一次没跑 | `deviceReminderScopeIsolationGuards.test.js` 新增 2 例：让**内层** `logger.error` 抛错以打断第一道防线，两种形态（Error / undefined）各一条，把 `${err?.message ?? err}` 的两条路径都走到                                                                                               |

**为什么是补测试而不是下调阈值**：`jest.config.js` 有明确纪律「每条阈值 = 实测下方 5pt(分支) / 3pt(函数)，
只紧不松」；2026-09-30 那次 auth.js `functions 97 → 90` 是**修正推导错误**（原值按"实测 100%"机械套用，
真值 93.33%，那条 setInterval 回调是刻意不覆盖的）。本批两处缺口**都可以被行为用例覆盖**，
所以按同一纪律应补测试。

修复后实测（全量 `jest --coverage`）：`auth.js` 函数 **100%** / 分支 **92.59%**；
`deviceReminder.js` 函数 **100%** / 分支 **94.33%**——两项阈值均达标。

复跑事实：两套件 `jest <两个文件>` **40/40 通过**；`jest src/tests/ci/ --runInBand` **15/16 通过**
（`testTreePurity` 因 `execFileSync('git')` 被本机沙箱拦而红，与下一节同一条环境性假红，
该套件只判"测试文件是否入库"，不涉及本次改动）。

### CI 真红修复（2026-10-08 · `test` 腿两条既有红：断言读错流 + 循环复用夹具撞秒级归档名）

> 两条在基线 run `37711343020`（`b7834f1`，本批之前）上**逐字相同** ⇒ 既有红，非本批引入。
> `security-audit` 腿已由 `5ab7e91` 修绿（上游 2026-10-05T22:50–23:31Z 一次批量公告刷新，
> `compression` / `proxy-addr` / `source-map-js` / `@vue/server-renderer` 四条与本仓依赖面无关），
> 此后只剩这两条挡住 `test (20.x)` / `test (22.x)`，并连带 `build` 被 skip。

| #   | 缺陷（读源码 + 实测复现，非推断）                                                                                                                                                                                                                                        | 改法                                                                          | 证据                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `imageDigestGate.test.js` 的 SIGTERM 用例把 `d.stdout + d.stderr` 拼成一个串再断言 `/RC=143$/`。驱动脚本的 `printf "RC=%s\n"` 走 stdout，而 `wait` 被信号打断时 shell 把作业终止语写**自己的 stderr** ⇒ 拼完是 `"RC=143\nTerminated"`，`$` 锚点恒不成立                  | rc 只认 `d.stdout`；`printed` 保留，继续用于「不得出现 KILLFAILED」的否定断言 | 用 dash（CI 的 `/bin/sh`）跑同一个驱动脚本：stdout=`RC=143`、stderr=`Terminated`                                                    |
| ②   | `backupFailureArtifactHygiene.test.js` 的三轮 `for (const blank of [...])` 复用 `beforeEach` 的同一个夹具。归档名只到**秒**，而"只含空白"的判据落在异地副本那一步（加密归档已定稿落盘）⇒ 第 2 轮同秒撞名，先命中「目标加密归档已存在，拒绝覆盖」，断言变成在测另一条判据 | 每轮自建 `mkwork()`、`finally` 拆掉，三条之间只差 `blank` 一个变量            | 固定时间戳的 `date` 替身把"同秒"从偶发变确定性：共用夹具第 2 轮复现出与 CI 同形的「拒绝覆盖」；每轮新夹具三轮全部「只含空白」+ rc=1 |

为什么本地一直没暴露：两套件都是 shell-out 型，本机 `spawnSync` 对任何可执行文件返回 `EBUSY`
（逐 host 探针 `status=null` / `error=EBUSY`），本地根本跑不到断言。另有一条会误导归因的环境差异：
本机 `rm` 被安全包装器接管，单次约 10–13 s，把单轮备份脚本从 CI 的亚秒级拖到 **31 s**——
"本地复现不出同秒撞名"正是这个延迟造成的。

复跑事实：`prettier --check` 两文件通过、`eslint` 两文件 RC=0、`jest src/tests/ci/ --runInBand`
**15/16 通过**（`testTreePurity` 因 `execFileSync('git')` 被 EBUSY 拦而红，属环境性假红，
且该套件只判"测试文件是否入库"，不涉及本次改动）。

### 运维脚本 E（2026-10-04 · 备份/恢复/密钥生成的失败面：容器侧那段命令第一次被真跑一遍，收紧失败第一次非零退出）

> 这一族的形状全都一样：**成功回显与失败信号在出口处不对账**。备份脚本对"一条都没跑"的异地命令
> 回显"已完成异地副本"；容器侧对一份 0 字节归档返回 0 并打印 `Restore completed successfully`；
> 密钥生成对"11 个文件一个都没收紧"照样退 0——三处都把没做过的事记成了做过。
>
> 方法上是本仓第一次让 `docker` **桩真的执行**容器侧命令（把 `-c` 后面那段交回 bash，容器内的
> `mongodump`/`mongorestore` 由 PATH 上的桩充当）。此前所有 docker 门禁只记 argv 与 stdin，
> 于是容器侧那七八行的缺陷谁都不判——注释里"用完即删""不落盘"都是没有实物的一句话。
> 新增断言一律配**前世版自证**（把脚本副本还原成修前形态，证明断言真能红）。

已落地：

| #   | 缺陷（读源码确认，非推断）                                                                                                                                                            | 改法                                                                                                                                                                 | 门禁（行为级，不是 grep）                                                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `backup-mongo.sh` 在 `case` **之前**无条件 `mktemp + 写入含口令的 URI`，而 docker 传输（默认）从头到尾没人读它 ⇒ 每次备份都在宿主盘上留一份 0600 明文口令                             | 配置文件挪进 `local` 分支按需创建；docker 分支只经 stdin 送 `uri:` 行                                                                                                | `backupFailureArtifactHygiene` C.1：docker 跑完 `"$TMPDIR"/*` 里**一个** `^uri: ` 结构的文件都没有；反向对照 local 恰好探到 1 个                                                                                                                                                               |
| ②   | 备份侧容器内路径写死 `/tmp/.mongodump-backup`，且 `cat`/`printf` 不判返回码（与 peer 已修的恢复侧同源）                                                                               | `mktemp` + 每步 `                                                                                                                                                    |                                                                                                                                                                                                                                                                                                | { rm -f "$cfg"; exit 1; }` | C.1 的 `DOCKER .*exec -T mongo sh -c` 自证 + 断言 argv 上没有口令字面量 |
| ③   | `BACKUP_OFFSITE_CMD` 含换行/回车时按"一条命令"解析只执行**第一行**，却把整份配置回显成 `Offsite copy completed` ⇒ 多行 env、CRLF 写的 env、误粘两条命令三种现场都记账为"异地副本已做" | 执行前拒绝（一条都不跑），并把 `\\r` 的 CRLF 出路点名                                                                                                                | C.2 三腿：多行/内嵌 `\\r` ⇒ rc≠0 且桩一次都没被调用、归档不被动；尾随单个换行 ⇒ 仍放行且回显文本逐字节等于那条命令（正向对照，防过度收紧）                                                                                                                                                     |
| ④   | `generate-secrets.js` 逐个收紧密钥文件时**丢弃返回值**，且目录级复核不通过也只 `console.log` 后 `exit 0` ⇒ `generate-secrets … && 下一步` 在密钥仍可被本机其他用户读写时继续推进      | 收返回值聚合成 `fileFailures` 点名清单；`check.tightened && fileFailures.length === 0` 之外一律 **非零退出**；产物保留不删（内容有效，毁掉只会把运维推向手搓随机值） | `filePermissionEnforcementAndVerify` 新 describe 5 腿：`node -r <preload>` 把 `src/utils/filePermission` 顶成可编程桩（真实宿主造不出"icacls 被拒"），目录失败/复核失败/仅文件失败三档各钉 rc=1 + stderr 点名 + 成功文案缺席；**前世版腿**：删掉返回值检查的副本在同一份桩下 rc=0 还打印成功行 |

同批的"探针"改造：宿主机凭据落点的探测从**按文件名**（`mongorestore-config.*`）改成**按内容结构**
（首行匹配 `^uri: `），与本批次前 peer 在 `restoreTransport.test.js` 里立的同一把尺子对齐——按名字探的是
"祸害叫什么"，改名即失明。

**押后（本轮不入库，见下方协调项）**：`restore-mongo.sh` 的两条同族修复——⑤ `RESTORE_SKIP_CHECKSUM=true`
把"哈希对不上"一起豁免（该开关的原意是"恢复本来就没有校验和的老归档"，实现出来却允许把一份已知损坏/
被替换的归档写进生产库；前者缺的是证据，后者是**反证**）；⑥ 容器侧固定名 + 不判返回码 + 0 字节归档被记成
一次成功恢复。改动与门禁都写好了并且是绿的（`backupEncryptionContract` 新增 3 腿 + 新文件
`restoreRemoteHardening.test.js` 7 腿，后者让 docker 桩执行容器侧命令，配 canary 预创建、两次运行路径互不相同、
0 字节拒收、空 stdin 停在 `read` 四个面，外加前世版翻转腿），但 ⑥ 撞上一条**已在 HEAD 里**的 peer 门禁：
`src/tests/deploy/restoreTransport.test.js:185` 字面钉死 `rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive`。
该文件的意图（"容器侧凭据用完即删"）在 mktemp 形态下依然成立，字面却必然失效；而它在我的改动范围之外，
工作树里还叠着同一位 peer 未提交的探测器改造——按行拆开提交做不到，于是整条 ⑥（连带只依赖它的 ⑤ 与两份测试）
押后，等那条字面 pin 换成判 `rm -f "$cfg" "$arch"` 之后单独入库。

协调项（交给并行会话或下一批）：

1. `restoreTransport.test.js:185` 的字面断言改成结构判据（清理了 `cfg`/`arch` 两个变量，而不是清理了某两个名字），
   随后 `scripts/restore-mongo.sh` + `src/tests/deploy/{backupEncryptionContract,restoreRemoteHardening}.test.js` 一起落地。
2. `deployment/backup-encryption.md` 里 `RESTORE_SKIP_CHECKSUM` 的口径要与 ⑤ 同步（文档现在描述的是"整段跳过"的旧语义）。

复跑事实：`src/tests/deploy` + `src/tests/security` 全量 **755 passed / 8 failed / 763**，两条红点各有其主——
`bundleBudget.test.js` 7 条是真实 `web-admin/dist` 的 `entryCssGzip 21900 B > 预算 19000 B`（并行会话新增
`apple-refine.css` 后重建产物而未重置基线，本批未碰任何前端文件）；`restoreTransport.test.js` 1 条即上面 ⑥。
本批相关 5 个文件 **67 passed**。`npx eslint src scripts --quiet` 0 项、`lint-ratchet` 通过（21 个含 warn 文件
均未超基线）、`check-utf8` 全绿（1061 个文件）、`prettier --check` 对改动文件全部通过。

### 供应链 D（2026-10-04 · 上一批的 21/21 变异矩阵被独立审计复跑出 9 条存活变异：逐条封红，并把"只有真实数据全对才绿"那一族补成夹具可证伪）

> 上一批自己写的变异矩阵（9+12 条）判的是"解析器/流程被改坏会不会漏"，但**漏掉了另一族**：
> 判据的输入在仓库里恰好是"全对"的，于是任何**削弱比较本身**的改动都没有实物能打红。
> 独立审计员逐行复跑后点名 9 条存活变异（下表 M/D 编号），其中两条正是"防投毒"链条上最关键的位：
> `repo` 判据放行了官方镜像的裸短名（第三个来源静默退化成两源），以及打印面把**硬报错**算进"可用"。

九条存活变异与本轮的封堵（每条都配了 arm，见下面矩阵）：

| 编号 | 原缺陷（存活原因）                                                                                                                                                   | 本轮改法                                                                                                                                                                                        |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M9   | `expect([shortName, 'library/'+shortName]).toContain(e.repo)` 二选一 ⇒ 官方镜像登记成裸短名照样绿，而 ECR 的 `map()` 靠 `library/` 前缀判托管 ⇒ "三源一致"悄悄变两源 | 改成 `repo` 由 `ref` **唯一决定**的 `toBe`；再加"声称用过 ECR ⇒ `map()` 必须给得出路径"的 ③ 号腿                                                                                                |
| M6   | digest 对账写成"长度不同才不符"仍全绿（表与文件全等，判据无实物）                                                                                                    | 对账逻辑抽成纯函数 `reconcile(refs, table)`，用**同长度、末位不同**的夹具 digest 直接打红；孤儿/陈行/不符三类各钉独立断言                                                                       |
| M7   | `sources`/`sites` 两列只判"非空" ⇒ 改成任意假话都绿                                                                                                                  | 新增一条可证伪用例：散文里所有像主机名的 token 必须**恰好等于**来源表里被点名的集合；点名数 ≥2；ECR 声称⇔可映射；`sites` 与扫描面**逐文件双向**对齐（多说不说都红）；引用点总数 `[1,1,1,1,2,3]` |
| M2   | `--only ,` ⇒ `split/filter` 得空数组（JS 里为真值）⇒ 六行全被排除 ⇒ 打印"核验 0 个引用 … 全部通过"退 0                                                               | 抽纯函数 `planRuns(argv, table)`，命中 0 行 ⇒ **退出码 2** 并点名"拒绝把空跑报成通过"                                                                                                           |
| M3   | `tag = ref.slice(ref.indexOf(':')+1)` 与 `lastIndexOf` 在真实六行上无差别（都只有一个冒号）                                                                          | 抽 `tagOf(ref)` + 端口夹具（`reg.example.com:5000/team/app:1.2.3` ⇒ `1.2.3`），另钉"真实六行切出的 tag 不含斜杠也不含冒号"                                                                      |
| D6   | 非 JSON 响应体走 `JSON.parse` 的原生异常文本 ⇒ 响应体前若干字符进日志（违反"外部响应体一律不回显"）                                                                  | `try/catch` 包住，报错只说"响应体不是 JSON（N 字节，内容未回显）"；用例同时钉 `not.toMatch(/<html>/)`                                                                                           |
| D13  | 打印面 `可用 = 非跳过的来源数` ⇒ **HTTP 500 / 非 JSON 的硬报错被算进"可用"**，`2/3（可用 3）`是给读者的一句话谎言                                                    | 分母改成 `应答`（拿到摘要的来源数），另起两位 `跳过 N，报错 1`；报错行前缀写"报错："。用例直接断言整行文本                                                                                      |
| D10  | `isIndex` 的 `every` 改成 `some` 存活（夹具只喂过"两条都单层"）                                                                                                      | 新增混合腿（一条 index + 一条单层）**两种顺序各判一次**：`ok` 必须 false，而 `agreeCount` 仍为 2（判据①与③不许混成一团）                                                                        |
| D5   | `judge` 不透传 `bytes` 时输出念 `undefined 字节`/`0 字节`，而用例只判 `/(\d+) 字节/`                                                                                 | `bytes` 过一道；断言改成**真实字节数**（"对返回字节自算 sha256"这句话唯一的实物证据就是它）                                                                                                     |

同批补强的三处（审计员另外点名的"判据依赖仓库内容配合"）：

- `workflowFileNames(names)` 从 `targetFiles()` 抽成纯函数并喂夹具：`.yaml` 分支在本仓**没有实例**，
  真实扫描面证不了它没写错；同时钉住"排序与 `readdirSync` 顺序无关"与噪音后缀（`yml`/`ci.yml.bak`/`x.YML`）。
- 永真断言替换：原来那条 `all.some(r => /<64 位 hex>|<捕获值>|示例/.test(r.value)) === false` 不可能红
  （扫到的 value 全都过了解析器）。改成**否定语料自证**：注释里带 `@sha256:` 的行按文件精确计数
  （Dockerfile 3 / compose 2 / deploy.yml 1），并断言它们既不进 `all` 也不进 `unreachable`——
  compose 的 mongo 段那条**反引号包裹的 `image: …<捕获值>`** 正是"注释排除一删就红"的实物。
- 替身自己也进判据：`resp()` 的大小写归一化在**存/取两面**各钉一条直接断言（删任一半就有用例红），
  外加 `ok` 的算法（404 false / 201 true）。上一轮的"header 各种大小写都要读得到"只在此之上才有意义。

退出码外壳（`process.exit(code)` 那一层）第一次进了门禁：`main(argv, table = EXPECTED)` 与
`planRuns(argv, table = EXPECTED)` 都接受表注入，于是"表本身写坏"与"命中 0 行"这两档在**触网之前**
就能被夹具判（真实仓库里表现在是好的，少这个注入点这两条分支永远走不到）；再用 `spawnSync` 真跑三次
脚本判 2 号路径的退出码与 stderr 文案，把"返回值→退出码"的接线也钉住（挑的都是不联网的分支，
所以门禁仍然离线）。

变异矩阵 **22 条 arm = 21 CAUGHT + 1 条刻意负对照**（`/c/tmp/mut-d.js`，跑完四个文件 sha1 逐字节还原）：
判据侧 arm（空跑守卫、`return plan.code`、`process.exit(code)`、`indexOf`、非 JSON 回显、分母把报错算进来、
`every→some`、`bytes` 不透传、下限归零、替身存/取不归一化 ×2）+ 数据侧 arm（官方镜像裸短名、
第三方命名空间被加 `library/` 前缀、表内 digest 末位改一位、`sites` 指错文件、`sources` 编造来源名、
声称用了 ECR 但其实不托管、compose 退回裸 tag）+ 闸自身（注释排除、对账退化成比长度、`.yaml` 分支）。
唯一一条"预期存活"是**负对照**：把 `repo` 判据退回二选一并同时喂"第三方命名空间被加 `library/` 前缀"
这条数据缺陷 ⇒ 13 条全绿，用来证明严格版 `toBe` 是唯一能抓它的判据，而不是装饰。

复跑事实（不联网的闸与联网的工具各一次）：`node scripts/verify-image-digests.js` 6 引用全 PASS、
**退出码 0**；本轮 `docker.1ms.run` 起效后 redis/mongo 为三源一致；`public.ecr.aws` 对 redis/mongo
仍**不发** `Docker-Content-Digest`（三态输出的实证），对 node 这一次直接 `fetch failed`——输出如实念成
`一致来源 2/2（跳过 0，报错 1）`，旧写法这里会念"可用 3"。散文里的取证数字第一次可复核：
`index 7 个条目`（mongo）与 `index 3 个条目`（grafana）与实测一致，其余来源逐条打印条目数与字节数。

未收（诚实清单）：

- `captured` 仍是人手写日期，闸只判形状。本批把 `sources`/`sites` 变成可证伪，但**取证日期**没有
  仓库内可对齐的事实来源（对表情的最硬约束是：某行 `sources` 写了 `public.ecr.aws` 而该 repo 在
  ECR 上不存在 ⇒ 红，见 ③）。
- "来源表三条腿全活"不是判据：某条腿抖动报错时，只要 ≥2 源一致脚本仍退 0（这是设计——独立性要求
  的是**运营主体不同**，不是三条全响）。`reasons` 会把报错的腿点名，但不改结论。
- `sources` 散文里的 `index N 个条目`只有 mongo/grafana 两条写了数字，本批不强制其余四条补齐
  （工具已经逐条打印，补不补只影响人读表时的方便）。
- `verify-image-digests.js` 仍不进 CI（联网门禁红了之后人先怀疑网络）。

同批收到两份独立逐行审计报告（`scripts/*.sh` 5 条：备份默认 docker 传输把全库口令写进宿主 `/tmp`
且无人读取、`RESTORE_SKIP_CHECKSUM=true` 连"校验和不匹配"一起跳过、`generate-secrets.js` 权限收紧
失败仍退 0、多行 `BACKUP_OFFSITE_CMD` 只跑第一行却宣布跑完、容器侧固定 `/tmp` 路径 + `cat` 不检查；
`src/services`+`src/controllers` 5 条：部门成员缓存无失效钩子导致 ≤30 s 跨部门可见、告警 `meta.total`
取自分页而 `hasMore` 在过滤前算、`rolePermissionController` 把畸形权限 ID 静默丢弃后整体覆写、
MFA 恢复码集 last-write-wins、`User.findById` 结果未守卫）。**本批未动这些文件**（属于并发会话在飞
范围与另一条链路），逐条自行复核后排入下一批。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 13 + `imageDigestVerify` 19 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **90 绿**（上一批 77）；元门禁 13 套 123 例
仅 1 红，且是 `ci/testTreePurity` 列出 7 份他人未入库的 `*.test.js`（本批只改既有用例文件，未新增）；
`ci/commentAnchorFreshness` 与 `ci/bareAnchorAttribution` 本轮**转绿**（他人会话已把 `runtime.js:88` 的
锚点同步到 `statsCache.js:147/157`）。`eslint src scripts --quiet` 0 error；`lint-ratchet` 通过
（21 个 warn 文件均未超基线，`main` 拆出 `planRuns` 后复杂度未升）；`check-utf8` 1050 文件通过；
prettier 对本批三个文件 `--write` 后 `--check` 通过。

### 供应链 C（2026-10-04 · 「全仓镜像都已钉版」第一次变成机器可判的账：6 个引用 × 3 处事实来源，配上不联网的两把闸）

> 上一批的诚实清单欠了三件事：compose 的 mongo / prometheus / alertmanager / grafana 与 `ci.yml`
> 的 service 容器还是可变 tag；三处"全覆盖式表述"是失实的；而"脚本能跑"与"文件真的钉完了"之间
> 没有任何东西在对账。这批一次性收掉：**引用面账**（`src/tests/security/imageReferenceInventory.test.js`）
> 把真实文件 ↔ 期望表 ↔ 脚本常量 ↔ 老闸字面量四处钉成同一笔账，**判据行为账**
> （`src/tests/imageDigestVerify.test.js`）把新工具的三条放行判据逐个做成可打红的用例。

钉版落地（本轮补 5 条，仓库内第三方引用至此 6 个 / 全部 `name:tag@sha256:<64hex>`，保留可读 tag）：

- `docker-compose.yml`：mongo `eb581912…`、prometheus `075b1ba2…`、alertmanager `e13b6ed5…`、
  grafana `079600c9…`（redis `858f009f…` 上一批已钉）；`.github/workflows/ci.yml` 的 service
  容器 mongo 与 compose **同一个 digest**（不同则 CI 是在"另一个 mongod"上跑绿的，而日志看不出区别）。
  `${APP_IMAGE:-fire-safety-app:local}` 是本机构建产物，不属于第三方供应链输入，分类器把它归"动态"。
- **取值不需要 docker**：新增 `scripts/verify-image-digests.js`（零依赖，只用 node 内置 `fetch`/`crypto`）
  对 registry 的 manifest 端点取**原始字节**自算 sha256——这就是该 manifest 的 digest，`Docker-Content-Digest`
  只作旁证不作结论。放行要三条同时成立：①自算值等于期望表值；②≥`--min-sources`（默认 2）个
  **运营主体不同**的来源给同一个值（`public.ecr.aws` 是 AWS 自己发布的 official 面，另两个是不同
  运营商的 Hub pull-through 缓存）；③拿到的必须是 manifest 列表 / OCI index——钉单层摘要等于锁死一个
  architecture。`captured`/`sources` 两列记录取证现场，不是装饰。
- 本批落地时与今日复跑都是三源/两源一致：**6 引用全 PASS（退出码 0）**。prom/grafana 只有两源
  是实测事实：ECR Public 对这些命名空间就是 404（不托管 ⇒ `skipped`，与"来源报错"分成两类，
  混同会把坏掉的 registry 路径念成"这条腿今天没说话"）。

两把新闸的判据（都不联网；联网核验仍是人跑一次的工具，理由见"未收"⑤）：

- `security/imageReferenceInventory`（9 条）：扫描面自证（8 个文件 / 11 条指令行 / byFile 精确到
  Dockerfile 3 + compose 6 + ci.yml 2 / 2 条动态 / 9 条 registry 引用，解析塌缩不许静默绿）；
  行分类器与钉版解析器各带**夹具**自证（13 例分类表 + 6 例拒绝表；注释排除、YAML 键大小写敏感、
  `image:` 后必须有空白、`(^|[^A-Za-z0-9_.-])image:` 词边界，都不靠仓库内容配合）；双向对账
  （孤儿引用 / digest 不符 / 期望表过期条目 / `present.size === EXPECTED.length`）；同 tag 必须同
  digest；`capture-image-digests.sh` 的 `NODE_TAG`/`MONGO_TAG` 与 `baseImageDigestPinned` 的字面量
  交叉对账，脚本管不到的 4 条引用点名列出。变异 **9/9 全红**（grafana 解钉、表内 digest 分叉、
  CI↔compose 分叉、解析器收大写、删注释排除、表里放不存在的引用、redis 写成序列项、大写 digest、
  `image:` 去空格），四份被改文件 sha1 逐字节还原。
- `imageDigestVerify`（10 条，`global.fetch` 替身）：judge 三条判据各自能单独把结论打回 false
  （含"两源一致但是单层"这一臂）+ `min-sources` 调大必须变红 + `headerMatches` 三态；fetchOne 的
  替身故意让 header 与字节摘要**不相等**，钉住"取的是字节"；单层响应体 `entries` 必须归 0（判据③
  唯一的输入）；Bearer 流程把 URL 序列与 `Authorization` 序列逐位钉死（少一步重试、或取 token 那步
  带上凭据都要红）；`realm=`/`Realm=` 两种写法都认，解析不出 realm 时报错而不是静默匿名直连；
  `token` 与 `access_token` 两个字段名都认。变异 **12/12 全红**，同样逐字节还原。

脚本侧顺手修掉的真缺陷（都是写用例时暴露的，不在"计划改"之列）：

- `anonymousToken` 按小写 `realm=` 匹配：registry 生态里 `Realm=` 真实存在，只认一种会让那条来源
  常年报"响应里没有 Bearer 挑战"，运维第一反应是怀疑网络而不是脚本。改为 `i` 匹配；同时它的旧注释
  写着"没有 realm 就当作公开端点直连"，而代码从第一版起就是 throw——注释失实已改（静默直连的产物
  是一个要鉴权的端点用匿名身份返回 401，最后被归因成"这个来源没说话"）。
- 旧结构是"先探测再取"：公开端点（来源表里两个都是）会为每个引用**把 manifest 下载两遍**，第一遍
  响应体整批扔掉。改成一次请求、非 200 才按挑战取 token 重试一次，重试目标仍是同一 URL、token 只流向
  `realm` 指定的地址。
- 输出侧把"来源没发 `Docker-Content-Digest`"念成"header 相符"——ECR Public 实测就不发这个 header，
  等于每轮三行假话。改成三态（相符 / 与自算摘要不符 / 来源未发），且认不出的值一律落到**不作断言**
  那一档（默认值不能是"通过"）。
- 新增上面那句三态判断立刻触发 `lint-ratchet` 的 `[complexity] 0→1` 回退（`main` 贴着上限 15）。
  拆出 `printVerdict` / `headerNote` 把复杂度降回基线，**没有**收紧基线。

口径同步（三处失实表述随本批改掉）：`docs/architecture.md` 原写"digest 待部署机捕获"（部署机什么都没
跑、值已经在仓库里 ⇒ 已是假话）⇒ 改为全部已钉 + 指路取值口径与对账闸；`.github/dependabot.yml` 的 docker 段补上第三处站点
（期望表，漏改由新闸判红）；`security/baseImageDigestPinned` 文件头原来只承认一条升级路径（部署机跑
`capture-image-digests.sh`）⇒ 补成两条，并明说本闸覆盖面早就不止 node/redis（它保留的是"三阶段同
digest"这条工具链漂移不变量与最早的两条字面量）。compose 里那条 `#（它 pull 之后把输出追加为…）`
示例行**故意留着**：它是 shell 脚本自证文案的一部分，删了脚本的说法就不成立了。

未收（诚实清单）：

- 本批不新增依赖 ⇒ 三个来源里两个是第三方缓存，独立性建立在"缓存不重打包"这个前提上，不是密码学
  证明。要证伪投毒只能把 digest 与上游签名（Notary / content trust）对上，本批不做。
- 期望表的 `captured` 是人手写的日期，闸只判形状（`^\d{4}-\d{2}-\d{2}$`）不判真伪；`sources` 列同理。
- `--only` 里写了表里没有的引用 ⇒ 退出码 2 并点名，但"新镜像进表"这件事仍靠人记得；`imageReferenceInventory`
  能抓到的是**文件里出现**而表里没有的引用，反向（表里有、文件里全删了）也能抓，靠条数相等那条。
- `verify-image-digests.js` 不进 CI：联网门禁红了之后人先怀疑网络，那正是最容易被人为绕开的形态。
  机器只保证仓库内四处事实来源对得上；外部事实变了要靠人跑一次，或等 Dependabot 把 tag 改掉触发红。

验证：`npx jest --runInBand` 供应链四套（`security/imageReferenceInventory` 9 + `imageDigestVerify` 10 +
`security/baseImageDigestPinned` 4 + `imageDigestGate` 54）= **77 绿**；`node scripts/verify-image-digests.js`
全表 6 引用 **PASS，退出码 0**；元门禁 18 套 239 例中 4 红，全部指向并发会话——`ci/testTreePurity`
列出的 7 份未入库用例里有 5 份是他人在飞的 `*.test.js`（本批 2 份随本批入库），另 3 条锚点红是
`src/services/statsCache.js` 顶部插入 35 行把 `src/constants/runtime.js:88` 钉住的
`publishInvalidate`/`onInvalidate` 从 **114/124 移到 147/157**，锚点与台账应由该会话同步（本批不代改
他人文件）。`eslint src scripts --quiet` 0 error（`AbortSignal` 是本仓 globals 白名单缺的一项，已补）；
`lint-ratchet` 通过（21 个 warn 文件均未超基线）；`check-utf8` 1049 文件通过；prettier 对本批全部文件
通过，工作树里两份他人文件仍未格式化（不代改）；`git diff -- Dockerfile` 为空（上一批已钉完），
`docker-compose.yml` 只动了本轮那 4 处 `image:` 与其注释块，`.github/workflows/ci.yml` 只动了 service
容器的 1 处。

### 供应链（2026-10-04 · 把上一批的脚本逐个改坏：五条真缺陷全都属于"把没做完说成做完了"，而闸的共同毛病是只会说"非零"）

> 这批的输入不是新代码，而是**对同日上一批落地的 `scripts/capture-image-digests.sh` 做变异测试**：
> 派三个子 agent 逐行审计，再手工把脚本一条条改坏，看闸会不会红。结果两边各中一处系统病——
> 脚本侧五条缺陷全在同一类上（**报成功而事情没做完**），闸侧的根病是**失败臂只判 `rc !== 0`**：
> 把整份脚本换成一个语法错误的文件时，14 条"必须拒绝"的用例全部照绿，因为它们不看是谁在说话。
> 下面每条都附复现形状，不读脚本也能验。

脚本侧（`scripts/capture-image-digests.sh`）：

- **①「够不着」只在整文件都够不着时才报**（最坏的一条）。分类器先看指令词、再取第一个字段当值，
  字段不属于本镜像 ⇒ `next`；这条 `next` 顺手把"值压根不在能锚定的位置上"也吞了。于是同一文件里
  一条 `FROM --platform=$BUILDPLATFORM node:22.14.0-alpine AS b` + 一条正常 `FROM` 时，前者被当成
  不相干的镜像行放过 ⇒ 打印"钉好 1 条 / 已替换并校验"，文件里**留着一条可变 tag**。compose 的
  `image: ${MONGO_IMAGE:-mongo:6.0.20}` 同形。修：含 tag 字面串却没取到值、且不是注释行 ⇒ 新增
  `unreach` 类 ⇒ 停手并给行号（`--platform=` 与变量展开都归到"指令行但取不到值"这一支）。
- **② 外部输出按行判 ⇒ 多行可以伪造脚本的判据**。`grep -Eq '@sha256:[0-9a-f]{64}$'` 是**按行**判的，
  而 `${raw%@*}` 取的是**最后一个** `@` 之前的全部内容 ⇒ `docker inspect` 返回"一行合法引用 + 任意
  一行"时，形状判据与仓库名判据双双通过；`--apply` 只是碰巧撞在 `sed` 的 unterminated s command 上，
  不加 `--apply` 则 rc=0 并把那一行**原样打进给运维的粘贴块**（把外部输出当代码用）。修：先要求
  **恰好一行**，行数不对就拒收，且**不回显内容**——多行输出可以伪造本脚本自己的日志行。
- **③ CRLF 行尾：同一输入在两台上是两种结果**。MSYS 的 gawk 与 GNU sed 会吃掉行尾的 CR（⇒ 整份
  部署文件的行尾被静默改成 LF 还报成功），Linux 的 gawk 留着 CR（⇒ 判成"形态不认识"而拒改）。
  检测必须走**字节**通道：本机 `grep -q "$CR"` 与 `awk '/\r/'` 对同一份文件都报 0 处，`od -c` 明明
  看得见 `\r`——文本模式在读取时就把 CRLF 换成了 LF。改成 `tr -dc '\r' < file | wc -c`，非零即拒，
  并把"请先把行尾改成 LF"作为可执行建议打出来。
- **④ 信号只清了残留，没有停下手**。`trap 'cleanup_pin_tmp' EXIT HUP INT TERM` 里那三个信号句柄跑完
  清理就**继续执行**：运维按 Ctrl-C 之后脚本照样把两个目标文件写完、照样打印"已替换并校验"、照样
  rc=0（在 15MB 夹具上实测：SIGINT 之后两个文件都已落盘）。修：`on_signal` 清理之后
  `exit $((128 + sig))`；实测 SIGTERM ⇒ rc=143、两文件逐字节原样、无 `*.pin.tmp`。
- **⑤ 全文刷新缺名字边界 ⇒ 两种真实损坏**。`s%tag@sha256:[0-9a-f]{64}%…%g` 不带边界时：
  前无边界会把 `myorg/mongo:6.0.20@sha256:…`（别人的命名空间）里的同名子串当成自己的引用改掉，
  注释从"别人的仓库"变成一张假证；后无边界会把 `@sha256:` 后面 68 位十六进制的前 64 位换掉、
  留下 4 位尾巴，产出一行**看起来完全合法**的钉版引用。修：两侧各加边界字符类
  `(^|[^A-Za-z0-9._/:@-])` / `([^0-9a-f]|$)`，定界符仍是 `%`（`|` 是 ERE 的选择运算符）。

闸侧（`src/tests/imageDigestGate.test.js`，38 → **54 用例全部真跑**）：

- 失败矩阵 14 → **25 臂**，每臂判**精确退出码 + 原因文案（逐行匹配 `^错误：`）+ `第 N 行` 的行号契约**
  再加共同后置条件（两目标逐字节不变、不留临时文件）。新增臂：digest 只有 63 位 / 只有 8 位 /
  大写十六进制（三条各**只违反一件事**——旧夹具 `sha256:short` 同时违反字符集与长度，于是删掉 `{64}`
  或放开大写都不会红）、多行 inspect 输出、CRLF、命名空间前缀、`image:` 后无空白、混合写法两臂、
  缺目标文件两臂（"不存在"与"够不着"是两条不同的臂）。
- **差分语料三条**：输入 → 脚本自己声明的处置计划（`待钉 N 条、待刷新 M 条、已是本次 digest K 条`）
  → **逐字节期望产物**，三格同时判，并加两条越界自证（改动行必须都含 tag 字面串；行数不许变）。
  这是①和⑤那类"少报一笔 / 多改一笔"唯一的交集防线——按形态写的判据两边都看不见。
- docker 调用**序列**断言（`info → pull node → pull mongo → inspect node → inspect mongo`）取代
  `calls.length >= 4`：条数挡不住"从不 pull mongo 就直接 inspect"（本地恰好有旧镜像时照样拿到 digest，
  钉上去的是过期摘要）。
- **SIGTERM 用例**：docker 替身每次睡 1 秒（整轮约 5 秒），驱动脚本在第 1 秒发信号——那一刻离第一次
  落笔还差整个 capture + 分类阶段，所以"信号之后文件有没有被动"是稳定差值而不是竞速。
- `findShell()` 探不到带 awk/sed 的 sh 时整组 `describe.skip`，等于 54 条零断言的绿 ⇒ CI 上单独一条红
  （ubuntu runner 一定有 `/bin/sh`，探不到就是探测本身坏了）。
- `run()` 读目标文件改成缺文件返回 `null`：否则"脚本没碰它"和"那个文件根本不存在"会混成同一条异常。

未收（诚实清单）：SIGTERM 用例的时机靠"裕度 3 秒"而不是同步点——若 runner 上 `sleep` 被替换成
非阻塞实现，它会退化成竞速，这条得盯；`.sh` 依旧不在 eslint/prettier 覆盖内（无 parser、本批不新增
依赖），脚本的验证手段只有 `sh -n` + 本文件真跑；两条 `mv` 之间不原子。上一批那条"未收"仍然成立：
compose 的 mongo / prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器
都还是可变 tag（没有 `docker pull` 证据就不臆造 digest），三处全覆盖式表述要和下批的镜像引用面账
一起改。

验证：`sh -n` 通过；`npx jest --runInBand src/tests/imageDigestGate.test.js` = **54 绿**（含 SIGTERM
腿实测 rc=143）；`security/baseImageDigestPinned` 4 绿、`ci/commentAnchorFreshness` 13 绿、
`ci/codeViewPhantomLedger` 5 绿（共享 helper `jsCodeOnly` 的幻影已被并发会话修到 0，本文件在旧台账里
的 32 行登记项随之消失——那份修复此刻还在工作树里未提交，若被回退这把闸会自己红，不会静默放行）。
`deploy/deployScript` 56 绿；`eslint --quiet` 0 error、`lint-ratchet` 通过（21 个 warn 文件未超基线）、
prettier 与 `check-utf8` 通过（1042 文件）；`git status -- Dockerfile docker-compose.yml` 为空 ⇒
本轮全部 `--apply` 都跑在 `--root` 临时根里，真实部署文件逐字节未动。

### 供应链（2026-10-04 · 唯一能修"半钉仓库"的脚本自己拒绝再跑：已钉从报错改成按目标跳过，digest 刷新与"够不着就停手"补齐）

> 起点是 `src/tests/security/baseImageDigestPinned.test.js` 的文件头——它把升级路径写成
> "在部署机跑 `scripts/capture-image-digests.sh` 重新捕获，再同步闸里的字面量"。上一轮把产物
> 口径与双 digest 修好之后，这条路径**仍然一步都走不通**：check 阶段把"这一行已经是
> `tag@sha256:…`"当成错误直接退出。而本仓库今天的真实状态恰好是混合仓库——Dockerfile 三条
> `FROM` 全钉死、compose 的 mongo 没钉 ⇒ 脚本在第一个目标就停手，永远到不了需要它的那个目标。
> 也就是说闸的注释把自己否证了：它点名的唯一工具，对着真实仓库跑必然红。
> 实测入口很简单：`sh scripts/capture-image-digests.sh --apply` 在本仓库根跑一次即可复现。

> 第二类更隐蔽，是"报告成功而什么都没做"的**反向版本**。判"这条引用够不够得着"用的是无锚定
> 子串计数，而替换用的是锚定正则——两套口径不同，于是这些形态被判成"可改"、进了落笔分支，
> 替换却一条都不匹配（`sed` 无匹配仍然 rc=0）⇒ 打印"已替换并校验"，文件一字未改：
> `FROM --platform=… node:22.14.0-alpine`（值不在能锚定的位置）、compose 的引号包裹值
> `"mongo:6.0.20"`、序列项 `- image: mongo:6.0.20`、折叠标量、`${MONGO_IMAGE}` 变量展开、
> `node:22.14.0-alpine @sha256:…`（tag 与 `@` 之间夹空白）、以及无 tag 的纯 digest 钉版
> （旧上一版脚本自己写坏出来的形态）。每一类都留下同一个后果：仍指向可变 tag 的引用被当成
> 已固定提交上去。

修（`scripts/capture-image-digests.sh` 的 check→stage→commit 三相，判据从"数子串"换成"分类值 token"）：

- **单遍分类器**（awk，只限 POSIX 构造，CI 的 mawk 与本机的 gawk 同结果）：按"行首 = 可选缩进 +
  指令词（`FROM` / `image:`）+ 空白"锚定，取整个值做 token，再按镜像名（剥 `@…`、剥最后一个 `/`
  之前的仓库名与 tag）过滤掉不相干的镜像行——redis / prometheus / `${APP_IMAGE:-…}` 不会被误判。
  值分四类：`待钉 bare`、`已钉 same`、`待刷新 refresh`（钉在**别的** 64hex 上）、其余一律
  `够不着` ⇒ 立即停手、零写入、只打**行号与形态名**（不回显整行）。分类器只按脚本顶部的 tag
  常量精确匹配，不做模糊猜测；指向本镜像的引用一条都找不到同样报错（脚本常量与仓库漂移是
  另一类事故）。
- **按目标跳过，而不是整体报错**：`same` 让该目标原样不动并明打"本次跳过（不改动）"，
  混合仓库因此能收敛（已钉行一笔不碰、未钉行钉上）；`refresh` 让滚动同名 tag 换 digest 的升级
  路径真的存在。**整体 no-op 仍然是错误**（两个目标都 `same` ⇒ 红），保住"报告成功但一字未改"
  那条老缺陷的判据。
- stage 用两条 `sed -E` 表达式：① 锚定的裸 tag 追加本次 digest；② 全文 `tag@sha256:<64hex>` →
  本次 digest，**故意不带锚定**——Dockerfile 顶部的用法注释里也写了完整钉版引用，只改指令行会把
  "正确示例"变成"错误示例"，而那正是本脚本要躲开的第一类失效。产物先落 `*.pin.tmp`，再用**同一个
  分类器复查预演结果**：仍残留 `待钉`/`待刷新`、或指向本镜像的条数变了 ⇒ 删临时文件退出；
  分类说"要改"而 `cmp` 判逐字节一致 ⇒ 报"分类与替换不一致"退出（这是自我矛盾探测器，不是保险丝）。
  commit 阶段 `mv` 之后对盘上的真实文件再 classify 一次。两个 `mv` 之间不是原子的，这条边界
  明写在脚本注释里，没有假装成原子替换。
- 计划可见：check 阶段就打印每个目标"待钉 N 条、待刷新 M 条、已是本次 digest K 条 ⇒ 会改动/跳过"，
  跑之前就知道这次动哪几条。

本轮实测到、并写进注释当教训的三处自身缺陷：POSIX sh 没有 `local`，`classify_ref` 覆写全局
`file` ⇒ `cmp -s "$file" "$tmp"` 变成"临时文件与自己比"，每一次合法运行都被报成"逐字节一致"；
`plan_ref` 读的是全局计数，两个目标都 probe 完再统一打印 ⇒ compose 的计数被打在 Dockerfile 标签下；
`sed` 用 `|` 作定界符与 ERE 的选择运算符撞车（`unknown option to 's'`）⇒ 换成 `%`（registry 引用
文法不含 `%`）。

闸（`src/tests/imageDigestGate.test.js`，38 用例全部真跑，PATH 插 docker 替身，不用扫源码文本）：
失败矩阵从 7 臂扩到 14 臂，新增 6 条"够不着"臂（`--platform=`、夹空白、无 tag 纯 digest、
引号包裹、序列项、折叠标量、变量展开），共同后置条件是**目标文件逐字节不变 + 目录里没有
`*.pin.tmp`**；表宽自证同步改成 14（jest-each 少喂一格是超时假绿，不是失败）。新增成功腿：
混合仓库（已钉的 DF 一笔不碰、compose 钉上、打印"跳过"）、`refresh`（含注释示例自愈、断言旧
digest 不再出现在文件里、复跑判 no-op）、单行内混合收敛、`FROM  node:…` 双空格；命名空间腿把
脚本的 `repo_of_ref`/`norm_repo` 抽进 sh 夹具跑 7 个真实引用（`node`→`docker.io/library/node`、
`prom/prometheus`、带端口的 registry 必须保留原样，反向 2 例必须 REJECT）并断言 ACCEPT 集非空——
只比末段会把别人的仓库当成自己的。零串扰自检保持：真实 `Dockerfile` 与 `docker-compose.yml` 的
base64 前后相等，本轮实测 `git diff -- Dockerfile docker-compose.yml` 为空。

未收（诚实清单，留作下一批）：compose 的 mongo 本身仍未钉（本轮没有 `docker pull` 证据，不臆造
digest），prometheus / alertmanager / grafana 与 `.github/workflows/ci.yml` 的 service 容器同理；
`baseImageDigestPinned` 的标题、compose 里"digest 由部署机 docker pull 后捕获追加"的注释、
`docs/architecture.md` 的"镜像钉版本：node、mongo"这三处**全覆盖式表述**与上述现状不符，
要和那份清单同批一起改成可核对的范围。`.sh` 不在 eslint/prettier 的覆盖里（无 parser），
本文件的验证手段只有 `sh -n` + 真跑。

验证：`sh -n` 通过；14 形态探测（临时夹具 + docker 替身，digest 用假值）全 PASS，且每次成功之后
复跑都被判 no-op 红；对真实仓库跑 dry 分类 ⇒ 三条 `FROM` 与三处注释引用识别为待刷新，
redis/prometheus/alertmanager/grafana/`${APP_IMAGE}` 与 Dockerfile 的散文行一笔不碰；
`npx jest --runInBand` 跑 `imageDigestGate` + `security/baseImageDigestPinned` +
`ci/commentAnchorFreshness` = 55 绿、`deploy/deployScript` = 56 绿、`ci/codeViewPhantomLedger` 绿；
`eslint src scripts --quiet` 0 error、`lint-ratchet` 通过、prettier 与 `check-utf8` 通过。

### 运维手册（2026-10-04 · 轮换手册 ① 发的 cookie 名服务端根本不读，"旧令牌必须立即失效"是一项不可能失败的检查）

> 起点是运维侧 P2-3（`deployment/secret-rotation.md` 的 L-01 ①）。复现只需一次函数调用：
> `extractAccessToken({headers:{cookie:'accessToken=X'}})` → `null`，而
> `extractAccessToken({headers:{cookie:'access_token=X'}})` → `X`。服务端只有
> `ACCESS_COOKIE_NAME='access_token'` 这一个名字（`src/utils/cookie.js` 的导出，
> `src/middleware/auth.js` 的 extractAccessToken 是 /api/auth/me 上 authenticate 的第一步），
> 手册却教运维发 `accessToken=`——名字对不上时走的是 `AUTH_TOKEN_MISSING`（"没带令牌"），
> 而轮换真正生效时走的是 `AUTH_TOKEN_INVALID`（验签失败），**两者同为 401**
> （`src/utils/errorCodes.js` 里两条的 status 都是 401，这条前提已被钉进用例）。
>
> 于是这项检查有两层失效，第二层更根本：判据只写"预期 401"、没有轮换前的正向对照，
> 匿名请求同样 401。**"检查通过"与"检查没跑"输出完全一样**，这样的判据不是弱，是零。
> 换句话说：即便当初把名字写对了，这一条也什么都没证明。
>
> 修（`deployment/secret-rotation.md` ①）：名字改回 `access_token`；补轮换前的同命令对照
> （必须 200，不是 200 就先修命令别开始轮换）；判据从状态码换成 `errors.errorCode`，
> 并把三种 401 的读法写进手册——`AUTH_TOKEN_INVALID`＝旧密钥确实没了、
> `AUTH_TOKEN_MISSING`＝令牌没被读到（不是轮换成功的证据）、`AUTH_TOKEN_EXPIRED`＝样本本来
> 就过期，证明不了任何事，重新登录换令牌再测。
>
> 闸（新增 `src/tests/deploy/runbookCheckCanFail.test.js`，7 用例）守两条同根判据：
> **A 是行为重放而不是字符串比对**——文档里每条 `Cookie: <name>=…` 与 `curl -b <name>=…`
> 的名字拼成真实请求头喂给服务端读取点（access 走 extractAccessToken，refresh 走四处共用的
> `getCookies(req)[REFRESH_COOKIE_NAME]`），断言取得回值；合法名集合由 `src/utils/cookie.js`
> 的 `*_COOKIE_NAME` 导出派生，且**每个导出名必须登记一条读取点**（加名不登记即红，闸不另立
> 第二份清单）。**B 是"负面判据必须自带对照"**——代码块里出现 401/403 时同块必须有 200 级
> 正向对照或同一状态码下可区分的 errorCode/AUTH_* 码。覆盖域沿用 runbookSecretSource 的
> "说明书"口径，刻意排除 CHANGELOG/deliverables/docs/adr——本条 CHANGELOG 里写着的
> `accessToken=` 是证据，不是指令。端点归属（把 refresh 发给 /me）是已声明的边界，不收。
>
> 变异（真文档上跑，每次只动一处，跑完逐字节还原）：把 ① 的名字改回 `accessToken` ⇒
> **恰好 1 红**（判据 A）；把 ① 整段还原成缺陷形状（只留"预期 401"）⇒ **恰好 1 红**（判据 B）。
> no-op 基线 7/7，扫描器不是空的（前提自证：真文档 ≥1 条 Cookie 名且必须来自被修的文件）。
>
> 验证：新闸 7/7；`ci/commentAnchorFreshness` + `testTreePurity` + `src/tests/deploy` 全套
> 400/407 绿，7 处红**全部**在 `deploy/bundleBudget`（并发会话正在改 web-admin，
> 前端产物超出现有预算基线；与本批无关，本批一个字节都没碰前端）；
> eslint 0 error；prettier 对新文件与手册均 unchanged。服务端代码零改动——
> 缺陷在文档，闸把文档接进了代码。

### 供应链（2026-10-03 · `capture-image-digests.sh` 的产物会被本仓自己的钉版门禁判红，还会把已钉过的行改成双 digest）

> 起点是运维侧 P2-4（"脚本在已钉版仓库上不可操作"）。复现成立，但**失效方向判反了**：
> 它不是拒绝工作，而是**开心地工作并打印成功**。2026-10-03 对着本仓库真实的
> `Dockerfile`（三条 FROM 都是 `node:22.14.0-alpine@sha256:9bef…`）抽出脚本的
> `check_ref` / `stage_ref` 单独跑：check 返回 0（放行），stage 产出
> **3 条 `@sha256:[0-9a-f]{64}@sha256:` 的双 digest**，脚本随后打印"已替换并校验"。
> 根因是一句无边界的前缀匹配：钉版形态**仍然包含**脚本常量 `FROM node:22.14.0-alpine`，
> 于是 `grep -qF "$old"` 把"已经钉过"读成"还能改"，`s|$old|$new|g` 再在它前面插一个新 digest。
>
> 顺着这条线查下去撞出第二类、也更严重：**`RepoDigests[0]` 天生不带 tag**
> （`docker.io/library/node@sha256:…`，本仓 2026-10-02 已实测），而旧实现把整串当引用写入，
> 产物就是无 tag 的 `FROM docker.io/library/node@sha256:…`。本仓的钉版口径是**保留可读 tag**
> ——`baseImageDigestPinned.test.js` 的 FROM 判据 `/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/`、
> `deploy/deployScript.test.js:118` 的 `<repo>:<tag>@sha256:…`、`docker-compose.yml:159` 的
> "纯 digest 看不出版本，排障时得先 inspect"三处同源，真实文件也全是这个形态。
> 也就是说 `baseImageDigestPinned` 的文件头把"跑这个脚本重新捕获"写成升级路径，
> 而**照这条路跑一次，红的一定是它自己**。这个矛盾在审计复核第 20 轮 §A3 已判过、
> 挂在"等拍板"上；本轮按证据收敛（口径由 3 处文档/闸 + 全部真实文件定死，不是二选一的风格题）。
> 顺带更正第 20 轮的一句推断：它写"改成追加式之后双 digest 自然失去土壤"——**恰好相反**，
> 追加式的产物 `tag@sha256:…` 正是 `tag` 的前缀扩展，边界判据从此是承重墙而不是保险丝。

- `capture_digest`：**只取 `@sha256:<hex>` 尾巴追加到 `$tag` 上**，不再回传 RepoDigests 原文；
  另加仓库名一致性校验（`docker.io/library/node` 对 `node` 放行，`…/alpine` 对 `node` 拒绝）——
  追加式写法若拿到的 digest 其实属于别的镜像，写出去的就是"这个 tag 指向那个 digest"这个
  不成立的断言，只能等构建期 pull 才炸。形状判据（`@sha256:[0-9a-f]{64}$`）拦不住它，实测过。
- `check_ref` / `stage_ref`：子串判据换成**边界口径**——"含 `old` 的指令行数 − 含 `old@` 的
  指令行数 > 0"才算可改，替换用 BRE 把 `old` 锚在空白或行尾（`\([[:space:]]\)` / `$` 两式）。
  于是"已钉 Dockerfile + 未钉 compose"这个**本仓库今天的形状**从"改坏还报成功"变成
  早退报错、逐字节不变、不留临时文件；混合仓库（有的阶段钉了、有的没钉）则一笔不碰已钉的、
  只钉未钉的，且改完再跑会正确报 no-op 而不是二次污染。
- 打印口径与脚本头部注释同步改为"直接可用于 `name:tag@sha256:<hex>` 的钉版引用"，
  收尾提示补上那条会把矛盾的闸（`npx jest src/tests/security/baseImageDigestPinned.test.js`）。
- `src/tests/imageDigestGate.test.js`（实跑 19 → **27 格**）：删掉那条把错误口径钉成**必要条件**的
  旧断言 `expect(r.dockerfile).not.toContain('node:22.14.0-alpine')`——它正是两道闸互不相容
  却各自全绿的成因；替身补 `qualified`（全限定 RepoDigests）与 `wrongname` 两个模式，
  新增 6 格：产物形态按**闸的原判据**逐条 FROM 实跑、短名与全限定两种 docker 名号收敛成同一串、
  "已钉 Dockerfile + 未钉 compose"现场必须报错、混合仓库只钉未钉的那条且二次运行不再污染、
  名号对不上必须拒（含"换回 node 就放行"的反向自证）；
  前缀陷阱另配一格前提自证（把 `@` 换成空格时三条判据必须同时翻转）。
  失败矩阵 5 → 7 臂，表宽用例改为 `widths: [4]` + `rows: 7`，行数本身也在台账里留痕。
- 变异证明（每个变异体跑整套，跑完即还原）：**M1** 判据+替换回到无边界 ⇒ 6 红
  （含两条新格与"幂等重跑""compose 漂移不留半钉"）；**M2** 直接回传 RepoDigests 原文 ⇒ 6 红
  （含"产物形态按闸判据"与"名号口径无关"）；**M3** 去掉仓库名校验 ⇒ 恰好 2 红（wrongname 两臂）。
- 验证：`imageDigestGate` 27/27；邻近两闸 `baseImageDigestPinned` + `deploy/deployScript` 60/60，
  注释锚点闸 `ci/commentAnchorFreshness` 13/13；`sh -n` 通过；eslint 0 error；prettier 对测试文件 unchanged。
  真实 `Dockerfile` / `docker-compose.yml` 一个字节未动（套件里有 sha 前后比对兜住）。

### 安全（2026-10-03 · 审计链核验脚本把"报告里已见的缺口"在出口处丢了，PASS 照打）

> 起点是运维侧一条待核判断（P1-1）。我自己复现了一遍，成立，而且比原判据更宽：
> 漏传的不止一个脚本。现场（`node scripts/verify-audit-chain.js` 对着真库）——
> 链尾一条 `hashFailure` 记录（写侧算 hash 抛错后照常落库，`AuditLog.hashFailure` 的既定形态）：
> 报告 `total=3 breaks=0 legacy=0 hashComputeFailed=1`，
> 而 CLI 打 `VERDICT: PASS（全量、无断裂、hmac 已校验）`、**退 0**。
> `deployment/rollback-drill.md:111` 与 `deployment/secret-rotation.md:397` 正是拿
> "退出码 0"当验收条件的那两步，于是链上不可追认的缺口穿过了验收。

- `scripts/verify-audit-chain.js`、`scripts/resign-audit-chain-v3.js` 各补一行
  `hashComputeFailed: <report>.hashComputeFailed`。判据（`computeChainVerdict`）这一格
  本来就有实现且正确，**坏的只是调用方**：`src/controllers/auditController.js`、
  `src/services/auditChainMonitor.js` 都回传了，两个运维脚本没有。
  修复后同一现场 ⇒ `INCOMPLETE` 退 2（复现脚本前后各跑一次，只差那一行）。
- 判据 `hasUnattestableGapOf` 的 JSDoc 里那句**失实前提**已就地更正：原文写"它由
  verifyAuditChain 恒回填，唯一漏传路径是旧调用方"——实测两个现役调用方就在漏传，
  而报告确实恒回填该字段。缺省方向（漏传按 0）**保持不变**：把它翻成 fail-closed 会让
  判据对任何不带该字段的调用报 INCOMPLETE，而真值表用例与在线侧构造的字段子集调用都属
  正常用法；本仓对"未来调用方漏传"的既有机制是逐调用点门禁，不是把判据调瞎。
- `src/tests/verifyChainExitCode.test.js` 把原来那份**硬编码三个文件名**的 scanned 回传断言
  换成**全仓枚举**（`src/` 去 tests + `scripts/`，按花括号配对取出每个调用点的对象字面量，
  逐个查 `scanned` / `hashComputeFailed`；纯 `computeChainVerdict(外部对象)` 形态按
  "静态看不见字段"点名）。实测 4 个调用点，全部合规。新增 CLI 端到端一格：
  真库真链尾真 `hashFailure` ⇒ 先自证"报告看得见缺口且不是篡改"，再验退 2、理由点名缺口、
  **绝不出现 PASS**，且 `--allow-empty --allow-no-hmac --allow-all-legacy` 三个豁免同时给也盖不住；
  `finally` 还原后必须回到退 0。
- 变异实测（不是推演）：删掉 CLI 那一行 ⇒ 枚举闸、CLI 端到端、scanned 那格**三条一起红**；
  删掉 resign 脚本那一行 ⇒ 枚举红并点名该文件。两处都已还原（`grep -c` 各 1）。
  反向自证 4 形：少 `scanned`、少 `hashComputeFailed`、同文件第二个调用点漏传、
  非字面量调用，各自都被点名。
- `scripts/verify-audit-chain.js` 头注释的退出码清单补上第五类不完整（缺口无任何豁免口子），
  此前它只列了截断 / 无 hmac / 空集合 / 整窗无哈希四类。
- 验证：`verifyChainExitCode` + `auditChainGuardedIntegrity` 45/45；
  `commentAnchorFreshness` 13/13（新增的 4 处引用都取到实文件实行号）；
  `npm run lint` 0 error、`lint:ratchet` 通过（21 个 warn 文件未超基线）；prettier 已格式化。

### 质量（2026-10-03 · 「任何新增验签入口都必须引用同一份判据」这句话，判据是注释而不是代码）

> 读 `src/utils/tokenPurpose.js` 时发现它的收敛承诺没有闸：
> `src/tests/utils/tokenPurposeAndConsumers.test.js` 的「三个入口都引用 utils/tokenPurpose」
> 用的是**手写死的三个文件名**。它证的是"这三份今天还引用着"，不是"没有第四份"——
> 新增一处 `jwt.verify(t, config.jwt.secret)` 而忘了用途闸，两个闸都照常绿。
> 而同一个文件里其实已经有全仓扫描的机器（另一条用例扫的是"不许内联写第二份 type 比较"），
> 只是没扫这一维。

- 新增 `src/tests/security/tokenPurposeEntryInventory.test.js`（7 格）：**枚举** `src/` 下所有
  用 access 密钥验签的调用（剥注释后按调用点判，`refreshSecret` 那一侧不算），未引用判据的
  必须出现在豁免表里。实测全仓 5 处：`middleware/auth.js`、`services/tokenService.js`、
  `services/websocketService.js` 引用判据；`middleware/logoutAuth.js`、`services/authService.js`
  是豁免。清单钉成**双向**不变量：多一处红、少一处也红。
- 两条豁免各绑一条**行为**用例，不是文件名白名单：
  · 登出入口那次未套判据的验签只决定"走哪条身份通路"，权威判定仍在 `authenticate()` 里 ——
  拿 `type:'refresh'` 的载荷用 access 密钥签（= 两把密钥被配成同值时攻击者手里的东西）打
  `/logout` ⇒ 401 且错误码必须是 `AUTH_TOKEN_INVALID`（换成"缺失/过期"那两条 401 本用例就
  指错了方向），并且 `req.user` 根本没被构造；
  · 吊销路径少一道用途闸的失效方向是**多吊销一条**而不是**多放行一个** —— 同形态串填进
  `revokeTokensOnLogout` 的 `accessToken` 槽 ⇒ 唯一的副作用是写黑名单。
  哪天有人改动让根据不再成立（比如在吊销路径上开始用 payload 构造身份），红的是这两条行为用例，
  不是清单。
- 反向自证 + 实跑 mutation：给分类器喂一段"没引用判据的 verify"与"引用了判据的 verify"，
  两者必须给出相反答案，且注释里提到的 `jwt.verify` 不算入口；再把一个合成入口临时写进
  `src/utils/superAdmin.js` 真跑一次 ⇒「清单逐条归队」与「规模钉住」两条立刻红并点名
  `src/utils/superAdmin.js ⇒ jwt.verify(t, config.jwt.secret, …)`，随后恢复原文件（`git diff` 空）。
- `src/utils/tokenPurpose.js` 的头注释补上这句承诺现在由谁执行，并把实测的 5 处入口写进去。

### 安全（2026-10-03 · 轮换手册把**两代**真凭据指向一个没被忽略的目录，而生成器"缺哪个补哪个"）

> 触发形态直接写在手册里：`deployment/secret-rotation.md` 第 1 步 `generate-secrets.js
--out ./secrets-new`（即将上线的那套），第 4 步 `mv ./secrets ./secrets-old`（刚刚下线的
> **全套生产密钥**）。而 `.gitignore` 当时只有 `secrets/` 一条——目录名不同，一条都挡不住；
> 本仓库是公开仓库，轮换做完那天一次 `git add -A` 就把新旧两代凭据一起推上去。
> `.dockerignore` 同族：docker 的忽略模式按**整段路径**匹配，`secrets` 匹配不到 `secrets-new`，
> 所以一次 `docker compose build` 会把两代真凭据送进构建上下文（镜像层里删不掉）。

- `.gitignore` 加 `secrets-*/`、`.dockerignore` 加 `secrets-*`，各带一句"为什么不是 `secrets`"。
- 新增 `src/tests/deploy/secretCarriersIgnored.test.js`（14 格）。要点是**哪些目录会装凭据不写死清单**，
  而是从手册/compose/README 自己的文本里抓 `--out <dir>` 与 `mv <src> <dst>` 两种入口：
  将来文档新起一个 `./secrets-staging` 而忘了忽略，本闸变红；写死清单则它永远绿着，
  而漏的恰好是那个新名字。git 侧的"是否被忽略"交给 `git check-ignore` 本身（与
  `scripts/mongoUri.sh` 同一条规矩：判据按参考解析器怎么读来定），并配一条**反向自证**
  （同一条命令对没被忽略的目录回 1）——否则探测器坏掉时全部用例会一起假绿。
- `generate-secrets.js` 前置检查 A（落盘之前问 git）：`--out` 目标在仓库内而 git 不认它被忽略
  ⇒ 退出码 1，**一个文件都不写**。退出码逐档实测：0=命中规则；1=在仓库内但不报忽略；
  128=判不了（仓库外 / 容器里没有 `.git` / 没装 git）。只有 1 拒，128 只把"没判成"说出来——
  拦下一条轮换/DR 路径换来的安全性是负的。判 git 时的 cwd 取**目标最近的已存在祖先目录**
  而不是调用方所在目录：`--out ~/keys` 而家目录本身是个 dotfiles 仓库时，用调用方 cwd 会一律
  判成 128 而放行，而那正是必须拦的形状。
- rc=1 其实合并了**两**种形态（都实测，话术两种都点名）：没有规则命中它；规则有了但文件
  **已经在 index 里**（先 `git add`、事后才补 `.gitignore`）。第二种更要紧——它就是"密钥已经
  进了公开仓库"的状态，所以这里**刻意不加** `--no-index`。这条加没加不是风格问题，实跑过：
  加上后前置检查 A 放行，`--force` 一路 rc=0 把已入库那颗 `jwt_secret` 覆盖成新生成的随机值
  （历史里一份、工作目录里另一份，且再没有任何一环报警）。用例把这一格钉住，含"旧字节必须
  原样还在"与"`--force` 也救不了"两条断言。
- `generate-secrets.js` 前置检查 B：目录里已有密钥时不再"缺哪个补哪个"。原实现逐个
  `已存在，跳过`，一次中断后的重跑会产出**混合代次**目录——多数密钥彼此独立看不出来，但
  `mongodb_uri` 是把 `mongo_root_password` 拼进去生成的：mongo 初始化用旧口令建用户、应用拿
  对不上号的连接串连库，轮换"成功"结束后第一次连库就认证失败，而现场证据是两份刚生成的
  0600 文件。现在要么 `--force` 重做整套、要么拒绝；用例在 `--force` 之后现场断言
  `mongodb_uri` 里拼的就是同目录那份 `mongo_root_password`，把这对耦合写成判据而不只是注释。
- 两处**自我纠正**（都因为"注释不执行"）：① 我先前在注释里写"用目录名探测会假绿"，实测三组
  形态（`s/`、`s/`+反向 `!s/jwt_secret`、文件先入 index 再补规则）里目录名与文件名探针的命中
  结果**完全一致**，那句是没取证就下的结论，已删；② 拒绝话术原本指向手册的「失陷处置」小节，
  而 `secret-rotation.md` 里根本没有这一节（grep 过），改成它真实存在的轮换流程 + `git rm --cached`。
- 顺带修掉自己上一次提交造成的两处陈旧行号引用：`28f7247` 插入 NUL 守卫后
  `process.env[name] = value` 从 `src/config/secrets.js:113` 挪到了 `:134`，
  `scripts/devSecretIsolation.js` 与 `disposableSecretIsolation.test.js` 的锚点跟着改对
  （`commentAnchorFreshness` 报的，不是豁免掉的）。

### 安全（2026-10-03 · 破坏性恢复的**默认**传输路径从来没有一个用例跑过，而它正在宿主机上多留一份凭据）

> 背景：给 `restore-mongo.sh` 补用例时发现，本仓所有真跑过它的地方（backupUriFile /
> backupEncryptionContract / infraParam…）都显式设了 `MONGO_RESTORE_TRANSPORT=local`，
> 而 README 与 deployment/backup-encryption.md 教的恰恰是**默认那条 docker**——compose 里
> mongo 只 `expose` 不 `publish`，宿主机连不上，mongorestore 必须在容器内跑。
> 于是"数据级回滚抓手"的默认路径在修前**从未被任何用例执行过**：主机段改写的拒绝、
> `--drop` 的拼接、凭据在容器内即删、归档经 stdin 流向容器，没有一条是被证过的事实。
> 备份侧的 docker 拒绝同样没人跑过（`backupTransport.test.js` 只演过它成功的那格）。

- 新增 `src/tests/deploy/restoreTransport.test.js`（8 格）：桩 `docker` 把 argv 与 stdin
  分别落盘，断言的是**真正送进容器的那条命令与那段字节流**——`uri:` 行主机段已换成
  容器内地址、库名与 `authSource` 原样保留、归档字节确实跟在配置行后面流进去、
  argv 上没有凭据、容器侧 `/tmp/.mongorestore.cfg` 与 `.archive` 都在同一条远端命令里 `rm -f`。
  `--drop` 在两条分支各写一遍（local 拼数组、docker 拼远端字符串），所以两侧都演
  "开了有、没开无"——这是防漂移，不是重复断言。
- 实测到的**修复**：`restore-mongo.sh` 原先在分支之前就无条件 `umask 077 + mktemp +
写入含口令的 URI`，而 docker 路径从头到尾没人读那个文件——它在宿主机磁盘上实打实
  留了一次凭据（DR 现场往往是笔记本/运维机），**而下方的注释一直声称"含凭据的 URI
  不落宿主机临时文件"，那句当时是失实的**。创建挪进 `local)` 分支（`--config` 只吃文件，
  那里是必需的），注释与代码这才一致。判据"宿主机上有没有 `mongorestore-config.*`"由
  两个桩**共用同一段探测代码**：local 必须探到、docker 必须探不到，探测器坏掉时不可能
  只让 docker 那一格假绿。把修前那段贴回去，两条用例立刻变红（docker 那格探到文件名、
  local 那格数出 2 个文件）——这次 mutation 实跑过，不是推演。
- 备份侧补上缺失的那格：URI 主机段无法改写 ⇒ 非零退出、`docker.argv`/`docker.stdin`
  根本没被创建、`backups/` 里不留半成品归档，且拒绝信息不回显口令字节。
- 一个**否证的结论**（原先记成高危，源码读下来不成立）：曾判断"备份只导出 URI 里那个库，
  恢复却不带 `--nsInclude` ⇒ 归档里有几个库就覆写几个库"。mongo-tools 100.9 的
  `common/options` 在没有显式 `--db` 时把**连接串里的库名**赋给 `opts.DB`，mongodump 只为
  那一个库建 intents，mongorestore 则把 `[库名.*]` 当作 includes 过滤归档条目——
  两侧范围因此**同一个库**，没有错配。这条不改任何破坏性参数（`--drop` 的口径维持原样），
  改为把口径写进 `backup-mongo.sh` 的注释并标明它是**读源码得来的、本机无二进制可实测**。
- 一条**待拍板的不对称**（没在门禁里偷偷改语义）：含未转义 `@` 的口令，docker 分支硬拒、
  local 分支放行（备份侧同形）。方向不同是有理由的——docker 必须知道"哪段是主机"才能替换，
  两个读者读法相反时替换就是猜；local 从不改写，歧义不是脚本引入的，且两种读法下的
  **库名相同**，确认门禁没有被绕过。残余风险是"横幅里的主机不一定是实际拨号的主机"，
  而 Go 驱动本机不可测。压平它要开始拒绝一批现在能跑的口令，因此留给人决定，
  新用例只把现状钉住并注明是钉现状、不是背书。

### 安全（2026-10-03 · UTF-16 密钥文件：bash 侧把连接串改坏、Node 侧把密钥截成一个字符，两边都 rc=0）

> 背景：`*_FILE` 约定有两个读者，它们吃掉"坏字节"的方式**相反**，而两个都不报警。
> 触发形态是运维用记事本/PowerShell 把密钥"另存为 Unicode"——UTF-16LE 里每个 ASCII
> 字符后面都跟一个 `00`，肉眼看文件内容完全正常。
>
> - **bash 侧**（`scripts/mongoUri.sh` 的 `mongo_hydrate_uri`）：`_body=$(cat -- "$_file")`
>   这一步命令替换就把 NUL **删掉**了（bash 只在 stderr 留一行 warning，退出码仍是 0），
>   于是后面四条判据（单行 / 纯可打印 ASCII / scheme / 非空）校验的是**改写后的串**，
>   不是文件里的字节。实测（bash 5.3.9）：UTF-16LE 的
>   `mongodb://fsms:pw@h/db` 剥掉 NUL 后字形与正确值一模一样 ⇒ 放行；把 NUL 埋在库名中间
>   （`…/fsms<NUL>x`）则放行一个"没人写过的库"，rc=0。
> - **Node 侧**（`src/config/secrets.js` 的 `hydrateSecretsFromFiles`）：`readFileSync(…,'utf8')`
>   把 NUL **留在** JS 字符串里，`trim()` 不认它是空白（所以既不裁也不告警），
>   随后 `process.env[name] = value` 在第一个 NUL 处**截断**。实测（Windows / Node 24.18）：
>   `process.env.X='A\0b'` 不抛错、回读得到 `'A'`；把 UTF-16 的 AES 密钥喂进去，
>   注入值是 1 个字符，`loaded` 照常包含该键、`warnings` 为空。
>
> 哪些会被下游拦住纯属巧合，所以不能拿它当"没问题"的证据：`JWT_SECRET` /
> `JWT_REFRESH_SECRET` / `AES_SECRET_KEY` / `HMAC_SECRET` 有 ≥32 长度闸、`DOCS_PASSWORD` 有
> ≥16 闸（这些会启动失败，吵得响）；`METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` /
> `LOG_SHIPPING_TOKEN` / `MONGO_ROOT_PASSWORD` / `SENTRY_DSN` / `REDIS_URL` 没有长度判据，
> 它们的形态是"进程活着但对不上"——其中 webhook 签名密钥被截断等于**安全告警静默丢弃**。
> 反向核验过一条更吓人的假设，结论是否定的：`ADMIN_INITIAL_PASSWORD` 被截断**不会**
> 造出 1 字符管理员口令，`models/User.js:67` 的 `minlength: 12` 会在 `User.create` 抛错。

- `scripts/mongoUri.sh`：在任何命令替换**之前**按原始文件字节判 NUL
  （`tr -dc '\000' < file | wc -c`），非零即拒绝并点名文件与"UTF-16/二进制另存为"这一成因。
  判据写成"剩下的字节个数 ≠ 0"而不是"grep 到就算"：`tr` 自身失败时残串是空串，
  `"" != "0"` 照样点亮 ⇒ fail-closed。
- `src/config/secrets.js`：在唯一的注入入口抛错，早于赋值也早于"空文件"判定
  （`'\0'` 单字符文件若走到赋值，得到的会是**空**环境变量）。只拒 NUL，不拒"所有控制字符"——
  `LOGIN_ECDH_PRIVATE_KEY` 是多行 PEM，中间的 `\n` 合法，一刀切会把正常部署拦死。
- 报错只点名变量名与文件路径，不回显任何密钥字节（新增一条用例钉住这点）。
- 新增 4 条 shell 侧 + 6 条 Node 侧用例，其中两条是**闸内的变异自证**：
  `backupUriFile.test.js` 按代码特征删掉 NUL 闸那段、用同一份 UTF-16 夹具重跑备份，
  必须变成 rc=0 且产出归档——这证明"红"确实来自那道闸，而不是被别的东西凑出来的绿；
  找不到判据行就直接抛错，避免上一轮踩过的"变异没落地、用例对着未改动的文件保持绿"。
  Node 侧配套一条反向自证：多行 PEM 照常注入，证明判据没退化成拒绝一切。
- 记一条踩过的测试环境坑：**平台事实不能在 jest 进程里量**。第一版把
  `process.env.X='A\0b'` 的回读断言写在用例里，jest-environment-node 用自己的对象代理
  `process.env`，NUL 能原样往返 ⇒ 把"真实进程会截断"这条前提判成了假。改为 spawn 子进程量，
  并把判据写成"长度不是 3"（截断得到 1、或某平台直接拒绝赋值都算通过），
  这样 Linux 上的表现尚未实测也不会成为跨平台红灯。

### 安全（2026-10-03 · 异地副本的"空命令假成功"：`BACKUP_OFFSITE_CMD=" "` 时一次都没复制，回显却写 completed）

> 背景：`scripts/backup-mongo.sh` 的异地副本那一步，头部注释早就写着原则
> 「被吞掉的异地失败比没有异地更危险——它让运维以为自己有异地副本」。判据却是
> `[ -n "$BACKUP_OFFSITE_CMD" ]`：**非空**不等于**有词**。实测（bash 5.3.9）
> `BACKUP_OFFSITE_CMD=" "`（env 文件里多打一个空格就够了）会走进分支，
> `read -r -a` 切出 0 个词，而 `"${空数组[@]}"` 落在命令位置是一条**空命令**——返回 0。
> 于是异地副本一次都没有执行，回显却是 `Offsite copy completed:`，连未配置那支的
> `Warning` 都不打。这是那条原则里最坏的形态：它连"失败"都不是，没有任何信号可看，
> cron 邮件里是一次"带异地副本的成功备份"，而备份实际只存在于本机（与数据库同机，
> 宿主机级故障时等于没有备份）。

- 判据从"字符串是否非空"改成"**是否切出至少一个词**"：`${#OFFSITE_ARGS[@]} -gt 0` 才执行；
  配置了却全是空白 ⇒ 单独一句 `Error`（说清是配错了，不是没配）并 `exit 1`，与异地命令
  失败同档——那档本来就是 `exit 1`，没有新的中断面。
- 未设置那一支不变（仍是 Warning + 退出码 0），且新增一条反向自证钉住它：
  新分支不得把"没配异地"吞成失败。
- 顺带让 `"${OFFSITE_ARGS[@]}"` 只在词数 > 0 时展开。旧写法在老 bash（4.2/4.3，RHEL7 一类
  宿主）的 `set -u` 下展开空数组会直接掐死调用方——那是"备份跑到最后一步才崩"，
  比这次的静默更响，但同一处判据一次修掉。
- 三条新用例（真跑脚本 + PATH 桩 mongodump/gpg/offsite-ok）：空白值 ⇒ 退出码 1 且
  **不得**出现 `Offsite copy completed`；真命令 ⇒ 桩确实被调用过、且拿得到定稿后的
  `BACKUP_FILE`/`BACKUP_SHA256`；未设置 ⇒ 只有 Warning、退出码 0。
  旧实现下第一条为红（已实测），后两条在旧实现下也是绿 ⇒ 信号只由第一条承担。

### 安全（2026-10-03 · 主机段改写的 13 条拒绝收拢成一句句能定位的原因，并改掉上一轮两处失实论证）

> 背景：`scripts/mongoUri.sh` 的 `mongo_swap_host` 上一轮已经按参考解析器的读法重做了取段，
> 但拒绝路径只剩一个退出码。本会话实测出两类问题，一类是现场可用性，一类是**注释里写的
> 事实站不住**——后者更贵，因为它会让下一个读者照着错的模型改这段代码。
>
> 1. **汇总句几乎总是指向错误的变量**：13 个互不相同的失效方向全部折叠成调用方那一句
>    「无法把 URI 主机段改写为容器内地址（`<目标>`），请检查 `MONGODB_URI` 形态」。
>    `MONGO_CONTAINER_HOST` 为空或拼错时同样 rc=1，而运维被告知去查 URI——在恢复窗口里
>    这是把人往错误的文件上引。
> 2. **少给一个参数会打断调用方**：本文件被 `set -u` 的脚本 source，`mongo_swap_host x`
>    原先以 `$2: unbound variable` 中断**调用方**，走不到任何一条能看懂的拒绝。

- 新增 `mongo_swap_refuse`：每条拒绝往 stderr 打一行**原因类别**（未转义 `@`、空凭据段、
  种子列表空项、越界端口、`+srv` 带端口/带逗号、目标地址非法……），只点变量名与形态，
  **绝不回显 URI 或口令的任何字节**——这是凭据，点名不取值。调用方那句汇总改为
  「拒绝执行；上一行点名是哪条判据拦下的」，不再独自承担定位责任。
- `mongo_swap_host` 的入参取 `${1:-}` / `${2:-}`：缺参数现在是一条拒绝，而不是一次崩溃。
- 顺带修掉一处**指错变量的标签**（是新测试在跑的时候自己撞出来的）：改写产物过值判据时，
  标签原先写成「`MONGO_CONTAINER_HOST` 改写后的连接串 含空白、换行…」，于是 URI 里带换行时
  运维被告知去查那个本来就没问题的变量。走到这一步时 `_scheme` 由 case 字面量决定、
  `_target` 刚过 `mongo_valid_hostport`（单行纯可打印 ASCII），可能带越界字节的只剩凭据段与尾部
  ⇒ 标签改为点名 `MONGODB_URI`，这是**可证明的**归因而不是措辞偏好。
- 纠正上一轮写下的两条**失实论证**（都已实测取证，判据本身不变）：
  - 「参考解析器把 `a,,b` 读成少一个主机」不成立——它**接受**并读成
    `hosts=["a:27017", ":27017", "b:27017"]`，即多出一个空主机名的种子。所以这一条是
    「刻意比解析器严」，不是「它也会拒」；`a@b@c` 同理，实测它**不报错**而是静默把主机
    换成没人写过的那一段。本机实测的两个读者对同一条串给出相反答案
    （`mongodb://u:p@ss@h:27017/db` ⇒ JS 包按**第一个** `@` 切凭据 ⇒ `hosts=["ss:27017"]`；
    Node 的 WHATWG `new URL` 按**最后一个** `@` 定界 userinfo ⇒ `hostname=h`）。
    原先这里写着"Go 驱动按 RFC 3986 取最后一个"——Go 驱动本机没有二进制，那一直是**推断**，
    不该写成实测。判据因此不赌读者：两个读者读法相反的形态一律硬拒。
  - 「刻意更严的两处」实际是四处，漏记了种子列表空项与值里的空白字节两条同族判据。
- 交代一条**能力边界**，防止 parity 全绿被读成"已验证过 mongodump"：本仓 parity 闸用的
  参考解析器是 JS 包（`mongoose` 内嵌的 `mongodb-connection-string-url`），而真正消费产物的是
  mongodump / mongorestore 的 **Go 驱动**；这台机器上没有 mongodump，所以 parity 只能证到
  "与 JS 包同口径"。已知两边读法不一致的形态就是上面的裸 `@` 分界——判据一律取更严的一侧。

### 供应链（2026-10-03 · `capture-image-digests.sh` 不再能留下"半钉"仓库，也不再吞别人的临时文件）

> 背景：这个脚本把 Dockerfile / compose 的基础镜像从可变 tag 换成 registry digest。上一轮已经补上
> "sed 无匹配仍返回 0"的静默 no-op 校验，但落笔顺序还是**边检查边写、两个目标顺序跑**。本轮真跑
> （PATH 插 docker 替身 + `--root` 指向临时仓库副本）实测出三种失效形态，都属"报成功/报错都看不出来"：
>
> 1. **半钉仓库**：compose 的 tag 与脚本常量漂移 ⇒ 第一轮把 Dockerfile 改成 digest，第二步才报错退出，
>    仓库留下"Dockerfile 已钉、compose 仍指向可变 tag"。
> 2. **死路**：照报错把 compose 修好再跑第二次，脚本在 Dockerfile 那一步就撞
>    "已经存在 @sha256 钉版引用"退出 ⇒ compose **永远钉不上**，唯一能修它的脚本自己拒绝再跑。
> 3. **吞别人的文件**：`sed > $file.pin.tmp; mv $tmp $file` 会把上一次中断留下（或人工放置）的
>    `Dockerfile.pin.tmp` 静默吃掉——探针读到的是 ENOENT，而退出码 0。

- 落笔改成**三相**：`check_ref`（只读，两个目标都确认可改，含"临时文件此前不存在"）→ `stage_ref`
  （只写临时文件并预演校验）→ `commit_ref`（`mv` 改名 + 落笔后复核）。任何一步失败，两个目标文件
  都逐字节不变、目录里没有残留临时文件。
- `trap … EXIT HUP INT TERM` 只清理**本脚本确认过"原本不存在"**的临时文件：`PIN_TMP_*` 两个全局量先置空，
  `check_ref` 通过之后才赋值。直觉写法 `trap 'rm -f "$ROOT"/*.pin.tmp' EXIT` 会在报错退出的那一刻删掉
  运维的文件——变异实验（把 `-e` 门禁摘掉）证明这条判据是承重的：残留内容变成 `<<DELETED>>`、退出码 0。
- 诚实交代残余边界：两条 `mv` 之间不是原子的（跨两个文件不存在单次 rename）。check 已确认两文件都在且
  都可改、stage 已验过改好的产物，失败面从"任何解析/匹配错"缩到"同目录 rename 本身出错"。
- 测试 `src/tests/imageDigestGate.test.js` 10 → 19 条：新增原子性（第二个目标漂移时第一个必须 `toBe`
  原始字节）、自愈（修好 compose 后重跑必须 rc=0 两边都钉上）、残留（拒绝 + 不覆盖 + 退出时不删 +
  删掉后能正常钉版），以及失败臂矩阵（tag 漂移×2 / digest 取不到 / 伪 digest / 未知参数）的公共后置条件。
  逐条做过变异反证：`M1_order`（把 compose 的检查挪到 Dockerfile 落笔之后）点亮前两条，
  `M2_noTempGate`（摘掉临时文件门禁）点亮第三条；control 三场景全绿。
- 夹具侧补两条门禁自身的自证：`tmps` 过滤器在残留用例里必须**看得见**那个文件（否则"失败不留临时文件"
  是空集造成的假绿）；`test.each` 的表宽必须等于处理函数形参个数——窄一格 jest-each 会注入 `done`，
  用例不失败而是卡满 30s 超时。

### 安全（2026-10-03 · 备份的主机段改写按参考解析器的读法重做：静默连到别处、合法 URI 被拒、坏端口被顺手换掉）

> 背景：`scripts/mongoUri.sh` 上一轮已经把那句 `sed -E "s#^((mongodb(\+srv)?://)…#"` 换成纯 shell
> 字符串重建，但**取哪一段**的判据还是那套 `case */* | \?* | *` 三分支 + `##*@` 切凭据。
> 本轮拿参考解析器（`mongoose.mongo.MongoClient`，即 `src/config/database.js:51` 讨论的那份内嵌
> `mongodb-connection-string-url`）逐条形对照，实测五条同根缺陷，全部与"备份到底连了谁"有关：
>
> 1. **静默改错主机**：`mongodb://u:p@db.internal:27017?appname=bob@corp`（无路径、查询串里有裸 `@`）
>    ⇒ rc=0，产物 `…@db.internal:27017?appname=bob@127.0.0.1:27017`。主机段一动没动、目标地址被拼进
>    查询串，而解析器把它读成 `hosts=["db.internal:27017"]`（**不报错**）——横幅承诺 127.0.0.1，
>    mongodump 连的是 db.internal，退出码却可以是 0。根因：第三分支把整串当 authority，再按**最后**一个 `@` 切凭据。
> 2. **副本集种子列表被拒**：`mongodb://a:27017,b:27017/db?replicaSet=rs0` ⇒ rc=1（逗号不在字符集里）——
>    合法 URI 备份不了，报的却是"形态异常"。
> 3. **无路径带查询被拒**：`mongodb://h:27017?directConnection=true` ⇒ rc=1（`\?*` 只匹配以 `?` **开头**的串）。
> 4. **IPv6 容器地址当目标被拒**：`MONGO_CONTAINER_HOST='[::1]:27017'` ⇒ rc=1，而 URI 里写同一段是放行的
>    ——同一件事两侧判据不一致。
> 5. **交回 mongodump 自己都不认的串**：`mongodb://a@b@c:27017/db` 与 `mongodb+srv://…` 带端口的产物
>    （`+srv` 禁止端口）都是 rc=0。

- 取段判据改成按**解析器怎么读主机段**来定：authority 终止于第一个 `/ ? #`，凭据与主机的分界取**第一个**
  `@`，主机段允许逗号分隔的种子列表且每项都得过 `host[:port]`/`[IPv6][:port]` 判据，主机段已等于目标地址
  ⇒ 合法空操作放行（上一版那条假阳性就是这一形态），其余认不出来的一律硬失败。
- 新增四个可复用判据：`mongo_valid_hostport` / `mongo_valid_hostlist` / `mongo_valid_userinfo` / `mongo_valid_port`。
  端口区间那条是新发现的第二类失效方向：`h:0`（'Invalid port (zero) with hostname'）与 `h:65536`
  （'Unable to parse h:65536 with URL'）解析器都报错，而我们放行等于**顺手把坏端口换成目标端口**——
  现场拿到的是一个从来不存在、也从来没被 mongodump 拒过的 URI。区间判据写成字符串比较而不是 `$(( ))`：
  shell 把 0 前缀当八进制（`08` 直接算错），而解析器把 `07017` 读成 7017。
- 一条**负结果**记录在案，防止下一个读者把 `#` 也当成缺陷：`mongodb://h#1/db` 曾被写成"解析器读成
  `["h#1"]`、我们比它严"，实测不成立——它在 `#` 处终止 authority 读成 `hosts=["h:27017"]`、db 仍是 `db`，
  与我们的取段口径完全一致 ⇒ 放行，由 parity 闸逐条比对产物。
- `src/tests/config/mongoTransportParity.test.js` 60 → **160 例**，承重的那条是新加的**参考解析器 parity 闸**：
  真值表里每一条 rc=0 的产物都重新真跑一遍并交给 `new MongoClient(…)` 读，要求
  `hosts === [目标地址]`、库名与凭据逐字不动；输入本来就解析不动的那一类只有"两边同一句错"才判为继承
  （唯一一条：`?drop:true` 撞驱动的 option 白名单）。清单从真值表**推导**而不是另抄一份，新加一条自动进闸。
  闸自身由六条合成违例（旧写法的真实产物）反向自证，含上面缺陷 1 那条"解析器不报错却连到别处"的形态。
- 一条夹具层的坑记进注释与判据：jest-each@29.7.0 的 `applyArguments`（`bind.js:78-80`）在
  **行数组比测试函数声明的形参短**时会把 `done` 注入成最后一个实参 ⇒ 那些行不是断言失败而是**超时**。
  实测一次跑出 5 条 30 秒超时 + 1 条真失败，看起来像整道闸坏了。现在 trailing 形参带默认值
  （`Function.length` 停在第一个默认值之前），并有一条表宽判据配合成违例钉住它。

### 安全（2026-10-03 · 一次性 harness 的第二根暴露轴：宿主上的明文密钥，不只 `*_FILE`）

> 背景：`scripts/devSecretIsolation.js` 上一版把宿主的 `*_FILE` 指针全量置空，但它只看指针。
> 密钥有**两根正交的轴**——形态（`<NAME>_FILE` 指针 / `<NAME>` 明文值）与通道（宿主 `export` / `.env`），
> 上一版按通道堵了两格，形态那一根整条没堵。而明文形态不是事故形态：`.env.example:2`
> 就明写「JWT_SECRET / AES_SECRET_KEY 等可以直接写在本文件（适合本地开发）」。
> 本机实测（`node -e` 枚举 `FILE_BACKED_SECRETS`）：仓库根 `.env` 今天正带着 6 个明文密钥，
> 其中 `MONGODB_URI` / `ADMIN_INITIAL_PASSWORD` 与一次性 harness 要用的值是同一类东西。

- **守卫按名字全量置空两类**：`<NAME>_FILE` 与 `<NAME>`。漏掉的这一类比原来那条更宽，
  因为 harness 只覆写它记得的那几个名字，其余名字一个都不碰，于是明文值直接穿过 dotenv 被读到：
  `REDIS_URL` ⇒ 冒烟的验证码/限流计数读写宿主那台 Redis；`SECURITY_ALERT_WEBHOOK_SECRET`
  ⇒ 冒烟造的假告警签名有效、真推到值班群；`SENTRY_DSN` / `LOG_SHIPPING_TOKEN` ⇒ 测试流量进真实观测面；
  `ADMIN_INITIAL_PASSWORD` / `MONGO_ROOT_PASSWORD` ⇒ 播种与清理动的是真凭据。
- **由此新增一条顺序不变量**：置空明文值意味着 harness 自己的一次性赋值必须**晚于**守卫
  （先赋值再调守卫会被擦掉）。接线闸原来只钉"早于 `require('../src/index.js')`"，
  现在同时钉"早于任何 `process.env.<密钥名>[/_FILE] =` 赋值"，并带三条负向对照
  （非密钥赋值不算、生成的子脚本里整行是字符串字面量的赋值不算、真赋值提到守卫前必须点名）。
- **"空串会不会变成第三种状态"有专门用例**：这几个名字在 `src/config` 里没有字段，消费方直读 env
  （`sharedCache.js:52` 的 `(process.env.REDIS_URL || '').trim() !== ''`、`initData.js:770` 的
  `if (process.env.ADMIN_INITIAL_PASSWORD)`），置空与"宿主本来没配"逐点等价；用例钉的是**真实源码行**，
  判据写法改成 `!== undefined` 立刻红。
- **告警点名不取值**：`*_FILE` 条目打路径（值本身是路径），明文条目只打名字并注明"值不打印"——
  报错里复读密钥等于把它从 env 搬进 stdout/stderr，CI 日志保留时间通常更长（同一口径见 `scripts/secretFileArg.js`）。
- **`src/tests/config/disposableSecretIsolation.test.js` 12 → 19 例**：来源臂从两条加到三条
  （`export` / `.env` 混装 / **`.env` 里只有明文、一个 `*_FILE` 都没有**）。第三条臂就是上一版的靶子：
  它的 `uri`/`jwt` 本来就是一次性值，"全绿"完全可以和"真 Redis、真初始口令已接上"同时成立。
  真值表随之扩到九格，`del × {dotenv, plain}` 两臂共同钉住"置空而非删除"对**两类**都承重；
  `rootPw` 的期望从 `undefined` 改成 `''`（`undefined` 只证"没 hydrate"，`''` 才证"宿主明文也没接上"），
  并在探针里给所有 env 观测加 `?? null`——`JSON.stringify` 会丢掉 `undefined` 键，
  那样"挡住了"与"夹具压根没跑"分不开，是一条空断言；另补一条**真文件减法自证**：
  擦掉置空明文的那两行、只留置空指针，明文轴必须立刻漏且被点名。
- 单位夹具改用"先全部置空"而不是 `delete` 构造"宿主干净"：本 describe 的 cwd 是仓库根，
  那里真有一个带 6 个明文密钥的 `.env`，`delete` 会被守卫内的 dotenv 填回来——
  这正是实现选择置空而非删除的同一条理由。
- **真 harness 复跑**：`REDIS_URL=… ADMIN_INITIAL_PASSWORD=… SENTRY_DSN=… node scripts/e2e-smoke.js`
  ⇒ 守卫打印 3 条明文点名（无值）、`[E2E] 结果：14 通过, 0 失败`、退出码 0；
  不带毒环境的裸跑同样 14/14 绿。

### 安全（2026-10-03 · 备份/恢复：主机段改写去掉 sed，失败现场不留明文归档）

> 背景：`scripts/mongoUri.sh` 是备份与恢复共用的唯一一份 URI 判据，它自己却是
> `sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1${MONGO_CONTAINER_HOST}#"`——
> 两条注入路径都落在这句替换上，而落点都是 mongodump/mongorestore 的 **0600 配置文件**：
> 配置里唯一由调用方决定的就是那一行 `uri:`。

- **`mongo_swap_host` 改为纯 shell 字符串重建**（scheme / authority / tail 三段用参数展开切开）。
  sed 形态的两个实测失效：① 替换串里的字面 `\n` 被 GNU sed 展开成**真换行** ⇒
  `MONGO_CONTAINER_HOST='127.0.0.1:27017\ncollection:auditLog'` 能给配置追加第二行，
  单集合导出被记成一次成功的全量备份；② 口令里未转义的 `/` 提前终结 `[^/]*` 那次匹配 ⇒
  替换错位（`mongodb://u:p/x@h:27017/db` → `mongodb://127.0.0.1:27017/x@h:27017/db`），
  **凭据被静默丢弃**而横幅承诺的仍是 `h:27017`/`db`。
- **`MONGO_CONTAINER_HOST` 新增字符集判据**（`[A-Za-z0-9.:_-]`，且端口必须是数字、
  IPv6 字面量 `[::1]:27017` 单独放行）。换行、空格、`\`、`;`、`|`、反引号、`$` 全部进不来。
- **切出来的主机段必须"确实是一个 authority"**：认不出来就拒（`u:p`、`mongo:abc`、`mongo:`、
  `[::1]:abc` 都在这一条）。第一版在这里补过一条"有凭据且路径里含 `@` ⇒ 拒"，实测把
  `mongodb://u:p@mongo/db@name` 一起误杀（库名带 `@` 合法，authority 终止于第一个 `/`），
  已由精确判据取代。
- **两条出口都过值判据**：改写那一支与"主机段本来就等于目标地址"的合法空操作那一支。
  少了后者，`$'mongodb://127.0.0.1:27017/fsms\ndrop:true'` 配 `MONGO_CONTAINER_HOST=127.0.0.1:27017`
  会绕过全部检查被原样交回调用方。
- **`mongo_validate_uri` 的越界字节判据补哨兵**：`$(… | tr -d '\041-\176')` 非空这个写法漏在
  **命令替换会剥掉尾部全部换行**——载荷 `…?authSource=admin\ndrop:true` 的注入部分本身全是
  可打印 ASCII，残串为空 ⇒ 放行，`drop:true` 成为配置文件的第二行，而门禁与横幅都声明相反。
  现在先补一个 `~` 再比，判据无歧义。
- **`backup-mongo.sh` 的加密门禁提到 `mongodump` 之前**（新增 `crypto_precheck_backup`，
  与 `crypto_encrypt` 同源）。原先 `gpg` 不在 PATH 或 `BACKUP_GPG_RECIPIENT` 没配时，
  脚本先花几分钟导出整个明文全量库（人员 PII + 不可篡改审计集合）再在加密步失败退出，
  而 `set -e` 直接带走 ⇒ "写完就删明文"那行永远执行不到，**每次失败都往 `backups/`
  多留一份明文**。现在三种不可用形态都在创建目录之前拒绝。
- **未定稿产物由 `cleanup` 一律删除（`FINALIZED` 标志）**。失败产物与成功产物同名
  （`fire-safety-backup-*.gz[.gpg][.sha256]`），留着就会被 retention 清单、回滚演练与
  "最近一次备份"的报表挑中。定稿点（密文 + 校验和都在手且非空）之后反向成立：
  一个都不能删——异地副本失败按设计整体失败，那时已到手的本地副本仍是回滚抓手。
  `deployment/backup-encryption.md` 的失败语义两条已同步。
- **闸**：`src/tests/config/mongoTransportParity.test.js` 15 → 41 例（真跑 bash 的行为真值表 +
  目标地址字符集九臂 + 值判据的 LF/CR 成对臂；结构层的"反向前提"换了方向——原先断言
  那句 sed 还在共享实现里，现在断言改写函数体内不许出现 sed，并用历史写法作合成违例
  证明判据非空集，注释过滤本身也自证）。夹具改经单引号安全转义传入（`$`/反引号不得被
  bash 先展开一次），CR 载荷由 shell `printf` 现场构造（Node 传 `bash -c` 时裸 CR 会在
  传输层被吃掉，测到的是"没有 CR 的串"——假绿）。
- **新闸 `src/tests/deploy/backupFailureArtifactHygiene.test.js`（9 例）**：真进程 + 桩
  mongodump/gpg（PATH 注入），断言的是"目录里到底有什么文件、桩有没有被调用"。
  含一处前世版对照：从脚本副本里按缩进反向引用删掉 `FINALIZED` 块（并 `bash -n` 证明它仍是
  合法脚本），同一夹具必须**留下明文归档**，否则这条断言抓不住回退。
  `backupUriFile.test.js` 的 SIGINT 用例同时补上"打断后目录里不得留半截归档"。

### 安全（2026-10-03 · 密钥轮换的密钥不再经过命令行）

> 背景：仓里所有密钥早已统一成 `<NAME>_FILE` 口径，唯独密钥轮换这一族还留着
> `--new-key <KEY>`：把值写在 argv 上，同一个密钥就同时出现在
> `/proc/<pid>/cmdline`（Linux 默认 0444 ⇒ 同机任意本地用户可读，而一次全量迁移要跑几分钟，
> 窗口足够长；`ps(1)` / 任务管理器同理）、shell 历史（`HISTCONTROL=ignorespace` 只是
> "记得在前面加空格"的人为约定，不是机制）、以及任何 `set -x` 的 CI 日志。
> 同一门安全要求上的两个标准，收口成一条。

- **新增 `scripts/secretFileArg.js`**：`readSecretFile` 把"密钥文件"的形状判据写死——
  恰好一行非空内容、去 UTF-8 BOM 与 CR/尾空白、字符集限 `0x21–0x7E`（与 shell 侧
  `mongoUri.sh` 的 `tr -d '\041-\176'` 同判据）；读不到、多行、含空白一律**硬失败**，
  绝不"取第一条非空行"蒙过去。`resolveSecretSource` 的优先级与 shell 侧一致：
  **显式 `--*-file` 赢过环境变量**（命令行点名的是"这一次轮换要用的值"，不能被 shell 里
  残留的同名变量悄悄改写），两者都给时只打一行提示且**只点名不取值**。
  所有错误信息只含标签与路径——一条"密钥泄漏"的报错如果把密钥再打一遍，
  就是把它从 argv 换成了 stdout/stderr，而 CI 日志的保留时间通常更长。
- **`migrate-mfa-secret.js` / `resign-audit-hmac.js` 改为 `--new-key-file` / `--old-key-file`**，
  旧形态不是"删掉了事"而是**具名拒绝**（exit 2 并指向替代写法）。具名而非落到
  `未知参数：${argv[i]}` 那条默认分支是刻意的：默认分支打印 `argv[i]`，而循环下一步就是
  那个密钥本身——报错本身就成了第二次泄漏。
- **一处有意的收窄**：`--*-file` 只接受 ASCII 密钥；密钥本身含非 ASCII 的用户仍走环境变量
  （env 不经 `/proc/<pid>/cmdline`，不在这条禁令范围），报错里直接写明这条路。
- **手册同步改口径，并顺手拆掉一个更常见的事故源**：`deployment/secret-rotation.md` 原先第 0 步
  `openssl rand -hex 32` 让人"记下输出"、第 3 步 `printf '%s' '<新KEY>' > 载体` 让人**再敲一遍**——
  重敲一次打错一个字符，数据已经用新钥加密完毕而应用拿的是另一把钥，比不改更糟。现在生成即落盘
  （`umask 077` + 单行文件），迁移用 `--new-key-file` 指它，换钥用 `mv` 把同一份字节扶正；
  全量轮换一节本就由 `generate-secrets.js` 产出文件，直接指过去即可。
- **新闸 `src/tests/deploy/cliSecretArgGate.test.js`（20 例）**，三层判据：
  静态完备性用**派生枚举**（"从 argv 取值"的判据是 `argv[i] === '--x'` 之后 60 字符窗口内的
  `argv[++i]`，因此具名拒绝分支不会被误判成还在收密钥），任何密钥类选项必须以 `-file` 结尾，
  文档里 `node scripts/…` 形态的命令行只允许使用该脚本确实接受的那些选项——新写第三个轮换脚本
  时这条闸自动对它提要求，不需要有人记得来登记；行为闸真起子进程传 canary，断言 exit 2、
  点名替代写法、**canary 一个字节都不出现在 stdout/stderr**、且看不到"已连接"（拒绝早于连库）；
  再加 `--new-key-file` 成功路径"值进内存但不进输出"与优先级提示。
  自证：合成违规（`--new-key` / `--db-password`）与真文件减法（把手册里的 `-file` 去掉）都能点亮。
- 受影响的既有套件同步迁移到新形态并复跑绿：`destructiveGuardOrder`（9 例，夹具改为真实密钥文件——
  必须是**能过强度校验**的密钥，否则 migrate 会以"拒绝迁移"而非断言的"拒绝执行"退出）、
  `hmacResignPrecheck`（8 例）、`runbookApplyCommandContract`、`migrateMfaWriteVerify`。

### 安全（2026-10-03 · 冒烟/压测/演练不得接回真实基础设施）

> 背景：`src/config/index.js:10-11` 在 **require 期**就调 `hydrateSecretsFromFiles()`，而冲突规则是
> **文件优先**（`src/config/secrets.js:113` 无条件 `process.env[name] = value`）。三个 harness
> （`e2e-smoke` / `load-test` / `production-drill`）的形状是「先设一次性 env，再 `require('../src/index.js')`」，
> 于是只要宿主上还留着 `*_FILE`，回填就会把一次性 `MONGODB_URI` 覆写成真实库连接串——**并且不报错**。
> 后果不是测试变红，是**写**：`npm run test:e2e` 往那个库播种管理员、建用户、发告警；
> `npm run test:load` 往它打五相压测流量并写审计。

- **新增 `scripts/devSecretIsolation.js`**：按 `FILE_BACKED_SECRETS` 全量把 `*_FILE` **置空**。
  两个来源都必须堵（第一版只堵了第一条，实测被打回）：宿主 shell 的 `export`
  （`deployment/secret-rotation.md` 要求每条命令自带 `*_FILE` 前缀，把它 export 起来是最省事的顺手做法），
  以及 `.env` 里写着 `*_FILE`（`.env.example:12` 的生产口径 b)）。第二条的关键在时序：dotenv 跑在
  hydrate 的前一行，守卫只看"当前 `process.env` 里有没有"就会漏掉整条路径，故守卫自己先 `require('dotenv').config()`。
- **置空而非 `delete` 是承重的**：dotenv 16.6.1 对"已定义"的键不覆盖（空串也算已定义），
  但会重新填充被 `delete` 掉的键；`secrets.js:71` 又把空路径当"未配置"跳过。
  六格真值表把这条钉死：`del × .env` 那一臂**仍然被覆写**，所以"觉得 delete 更干净"的改法立刻红。
- **刻意不做的两个替代**：用 `NODE_ENV` 跳过回填（`production-drill` 自己要 `NODE_ENV=production`，
  跳过等于演练失去生产同构性，而那正是它存在的意义）；把 hydrate 改成"环境变量优先"
  （推翻一个深思熟虑的安全决定——挂载 secret 必须压过残留的 `.env` 明文，否则轮换看起来生效实则没生效）。
- **新闸 `src/tests/config/disposableSecretIsolation.test.js`（12 例）**：真子进程 + 真 `src/config`，
  断言的是"配置对象里到底是哪个 URI"而不是脚本里有没有某个字符串。含 `MONGO_ROOT_PASSWORD`
  这一臂：harness 从不给它赋值，回填却照样把真实值填进去 ⇒ 危害不止"它记得覆写的那几个键"，
  同时反向钉住守卫自己绝不 hydrate。
- **顺手拆掉上一轮自带的一颗定时炸弹**：`backupUriFile.test.js` 的 SIGINT 用例让外面的
  `sleep 0.4` 与桩里 `sleep 1.2` 赛跑，本机并行跑 `src/tests/config src/tests/deploy` 时漂了
  （归档写完信号才到 ⇒ "Backup completed successfully" 照打 ⇒ 用例红）。改成由桩在
  **半截归档落盘的那一刻** `kill -INT "$PPID"`：红绿只取决于脚本自己的 trap 语义，
  不再取决于机器当时有多忙。
- **既有闸 `scriptSecretHydration.test.js`（14 → 16 例）被这次改动撞红一次，且它是对的**：
  守卫用 `process.env[name + '_FILE']` 动态键读密钥注入项，按闸的口径就是"读取者"，
  而它的合规写法（在库内调 `hydrateSecretsFromFiles()`）恰恰是它要防的那个动作。
  因此给的是**逐名取证**的"共享库"豁免：原来那句 `consumers.length >= 4` 是全局计数，
  新登记的库蹭得到同一句结论却可能压根没人调用；改成每条豁免各自要求"被至少一个入口 require"
  （引入点判据在这里**刻意收紧**：读点判据宽松只会多算一个读取，豁免前提判据宽松则让空白条看起来有主）
  - "库里没有 `require.main === module` 入口支"，并补一条**真文件减法**：把三个 harness 的 require 全擦掉，
    豁免必须当场失效。

### 安全（2026-10-03 · 备份/恢复 shell 的输入校验与退出路径）

> 背景：上一轮给 shell 侧接上 `*_FILE` 后，逐行审计发现"能跑起来"和"不会把凭据/目标库交给
> 一个没人校验的字符串"是两件事。九条 CONFIRMED 全部按缺陷本身定级，不看发现者的措辞。

- **显式 `MONGODB_URI` 此前完全不校验**（只有文件那条路校验）。最糟的一条：连接串里嵌一个换行，
  `printf 'uri: %s\n'` 写进 mongodump 的 `--config` 后，第二行就成了**配置文件里的一行选项**——
  `…@host/db\n drop: true` 直接越过恢复侧所有门禁把"删库再恢复"追加进去。
  新增共享判据 `mongo_validate_uri`（整串必须是单行纯可打印 ASCII + `mongodb(+srv)://` 前缀），
  两个来源同闸。
- **缺 `--` 操作数分隔符**：`MONGODB_URI_FILE=-c` 会被 `cat`/`grep` 当选项 ⇒ 读的是**调用方的 stdin**
  而不是那个文件。补 `--`，并用真子进程断言"打开的是那个文件"。
- **告警回显会泄出口令尾巴**：`${MONGODB_URI#*://}` 之后接 `${…*@}` 是最短匹配，
  口令里含未转义 `@` 时把口令后半段连同主机名一起打进日志。改最长匹配，并补含 `@` 口令的夹具。
- **恢复目标必须由字面决定**：URI 不含库名时，目标库由**归档内容**决定，
  而 `RESTORE_CONFIRM` 的核对退化成"输入就是整串 URI 本身"——一个可猜的哨兵。
  现在缺库名直接拒绝执行（门禁的前提是目标 identifiable），正向对照同夹具带库名放行。
- **`trap cleanup EXIT INT TERM` 不自己 exit**：SIGINT 打断备份时，清理跑完继续往下执行，
  实测打印「Backup completed successfully」而产物只有 5 字节。三条 trap 各自补 `exit 130/143`。
- **`local` 传输分支失败后留 0 字节归档**：`docker` 分支早就处理了（重定向在失败前就建了文件），
  `local` 分支没有——一个躺在 `backups/` 里的空 `.gz` 在回滚清单上"就是一次备份"。同一处理补齐。
- **`grep -c` 无命中时把 `-c` 当选项吃 stdin**，且失败路径留下的空串会让 `[ "$_n" -eq 0 ]`
  报 integer expression。改成先 `cat` 进变量再从 stdin 计数。
- 测试：`backupUriFile.test.js` 17 → 23 例、`backupTransport.test.js` 7 → 8 例，每例都带**正向对照**
  （证明不是靠"永远判红"混过去的）。`src/tests/config` + `src/tests/deploy` 合计 632/632 绿。

### 运维可用性（2026-10-03 · `*_FILE` 这条线的最后一公里：shell 侧解析 + 手册里每条命令行自带密钥）

> 背景：前两轮把 Node 侧的六个运维脚本 + `npm run validate` 都接上了 `<NAME>_FILE` 回填，
> 但**备份/恢复是 shell 脚本**，而手册里的命令行为它们提供的是明文 `MONGODB_URI=`。
> 两条都在生产口径（`.env.example:12` 的 b)「只配 `*_FILE`，`.env` 不写同名变量」）下失效。

- **finding：`scripts/backup-mongo.sh` / `restore-mongo.sh` 只认明文 `MONGODB_URI`**。
  生产宿主机上只有 `./secrets/mongodb_uri` 这个文件，于是每日 cron 每晚 `exit 1`、
  **零归档**，而 cron 的 stderr 没人读——备份线静默停摆可以拖到第一次真要恢复的那天。
  修法：共享实现 `scripts/mongoUri.sh` 里加 `mongo_hydrate_uri`，两个调用点各三行改过去，
  仍保持"凭据不进 argv"（连接串走 mongodump/mongorestore 的临时 `--config` 文件）。
- **一处刻意与 Node 侧相反**：shell 里**显式 `MONGODB_URI` 赢**（`secrets.js:106-113` 是文件赢）。
  理由：恢复的目标库必须由这一行的字面内容决定，不能被环境里残留的 `*_FILE` 静默改写到
  另一个库——把备份写进错库远比连不上严重。并存时打 Warning，README 与手册都写明这层反向。
  坏文件（空 / 多行 / 不是连接串 / 含空白或控制字符）**硬失败**，不像应用侧只告警。
- **夹具暴露的实测纠偏**：`printf 'mongodb+srv://u:p%40ss@h/db'` 里 `%40s` 被 printf 当宽度
  说明符，写出 40 个空格，而首版形状检查**照样放行**（只裁了尾部）。改成"整串必须落在
  0x21–0x7E"后该形态才被判红。同批 probe 还纠正了 `tr` 的两处写法：八进制只认三位
  （`\0176` 会解析成 `\017`+`6`），且空格属于可打印区（`tr -d '\040-\176'` 会把内嵌空格删掉
  而不是查出来）——`*[! -~]*)` 那版更是 `bash -n` 直接报语法错，而语法错让 source 中断，
  导致当轮所有"应当被拒"的 probe 空过（正向样本才暴露了它）。
- **新闸 `src/tests/deploy/backupUriFile.test.js`（17 例）**：真 `bash` + 桩 `mongodump`/
  `mongorestore`，断言的是"文件里的串真的进了 `--config` 内容"而不是脚本自报成功；
  含**前世版减法自证**（把 `mongo_hydrate_uri` 换成只认 `MONGODB_URI` 的旧实现 ⇒ 同一夹具
  必须红）、四种真实密钥文件形态（无尾换行 / 尾换行 / CRLF+空行 / PowerShell BOM）、
  以及 hydrate 之后凭据仍不出现在 argv。
- **新闸 `src/tests/deploy/runbookSecretSource.test.js`（10 例）**：把手册当成可执行契约扫——
  语料 **40 条命令行 / 31 条需要连库**，五通道：缺 `MONGODB_URI(_FILE)`、缺该脚本额外的
  `HMAC_SECRET`/`AES_SECRET_KEY`、命令行出现 `*_FILE=/run/secrets`（那是容器内路径）、
  经 `docker compose exec` 跑 ops 脚本、`--apply` 未配 `ALLOWED_SOURCE_DB`。
  自证三件：前提（条数下限 + 被调用脚本文件必须都存在）、每通道合成违例、
  **真实文件减法**（把 31 条真实命令逐一抹掉前缀喂回同一条通道，全部必须点亮）。
- **判据取舍（记下来以免下轮又被"放宽"回去）**：围栏内位置无关，所以注释形态的 crontab
  示例、`cd /opt/xf && …` 复合行都在检查范围；围栏外抓**每个**内联代码 span，所以
  「- **处置**：`node scripts/…`」这种带标签写法不是盲区（实测把语料从 36 条提到 40 条）。
  但同一条 `--apply` 命令当时**仍然**看不见：它写在跨两行的内联代码里（`\` 续行 + 未闭合的
  span），任何 span 判据都读不到——所以把它连同演练那条一起搬进 ```bash 围栏，
  这才是让它受检的动作。代价是文本判据分不出"这样写"与"不要这样写"，于是把手册里
  `docker compose exec -T app node scripts/x.js` 那条反例拆成两个 span——
  **不给判据开"这条不算"的豁免口**。
  表格行按"记录/状态"排除，覆盖域只含说明书（`deployment/*.md`、`docs/incident-response.md`、
  `README.md`、`SECURITY.md`、`migrations/README.md`），不含 CHANGELOG/`deliverables`/`docs/adr`。
- **我自己写错的两句论证（自查后改掉，没有留到现场）**：
  ① `deployment/secret-rotation.md` 曾写「缺 `MONGODB_URI` 时脚本自己会红」——
  `destructiveGuard.resolveMongoUri` 只打一行 stderr 告警就**回退本地库**，而
  `assertApplyAllowed` 在 `apply=false` 时直接放行，真实症状是"数出来的是开发库的 v1 行数"；
  ② 反证了一个听起来合理的建议：`docker compose exec -T app node scripts/…` **不是**
  宿主机缺密钥的补救路径，镜像里只有 `scripts/destructiveGuard.js`（`Dockerfile:122-124`，
  故意的：容器被攻破时拿不到带 `--apply` 的灭迹工具），那条路径只会 `Cannot find module`。
  能进容器的只有 `npm run validate`（= `node src/config/validate.js`，`src/` 在镜像里）。
- **文档同步**：`secret-rotation.md` 新增「执行位置与 `*_FILE` 前缀」一节（含逐脚本所需密钥表）、
  `backup-encryption.md` cron 行、`rollback-drill.md` 备份/校验行、`incident-response.md` 两条处置命令、
  `README.md` 备份/恢复块。`rollback-drill-record.md` **只改检查单模板那一行**，
  已完成演练的历史行原样不动——为了让闸变绿去改写演练记录等于伪造现场。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 37 套件 / 612 例全绿；
  `npx eslint` 两个新文件 0 问题；`npx prettier --check docs deployment README.md migrations src/tests/deploy`
  全绿；`node scripts/lint-ratchet.js` 仅剩并发线在改的 `src/services/securityAlert.js`
  （complexity/max-lines 各 0→1），本批新增文件未引入任何 warn。

### 运维可用性（2026-10-03 · `npm run validate` 是这条线的第三个入口，而它一直站在闸外）

> 背景：`*_FILE` 回填（P3-48）只在 require 到 `src/config` 的入口自动发生。上一轮补了六个
> 运维脚本并立了 `scriptSecretHydration.test.js` 这条闸；本轮由并发审计线（lane-hydration-audit）
> 逐条攻击那条闸的判据，查出**四个漏判形态**和**第三个同类入口**。

- **finding：`node src/config/validate.js`（= `npm run validate`）在 `*_FILE` 部署下报四条假弱密钥**。
  它不经过 `src/config/index.js:11`，没人回填，于是 `collectSecretErrors` 读到 `undefined`，
  报「JWT_SECRET / JWT_REFRESH_SECRET / AES_SECRET_KEY / HMAC_SECRET 必须设置为至少 32 字符」
  并以 1 退出。而 `deployment/secret-rotation.md:156` 正是拿这一步的退出码当
  "轮换后配置自洽"的证据——密钥轮换流程的收尾在容器里做不到。
  失效形态也和其余六个不同：它们症状是"读不到"，这条是**"密钥看起来弱"**，
  会把排查方向直接带到"是不是运维把密钥换短了"上去。
- **我自己的修法被打回了第一次（如实记录）**：第一版按位置判据把 hydrate 放在
  `validate.js` 文件顶部（这样"hydrate 早于首次读取"在源码位置上成立、可被闸钉住）。
  结果连带打红 5 个配置套件（validate / startupGuards / weakSecretPlaceholder /
  transportTlsAssertion / immutableConfigGuard）。根因不是测试写错，是**判据形状与文件形状不匹配**：
  `validate.js` 同时是库（app.js / index.js / staticFrontend.js / websocketService.js 都 require 它）
  和进程入口，而"库在 require 期覆写调用方的 `process.env`"本身就是不该有的副作用——
  `src/tests/setup.js` 给每个 worker 预置了四把 `*_FILE` 临时副本，凡"先设 env、后 require"
  的夹具都被回填悄悄改回测试密钥。`index.js` 能那么做是因为它自己就是应用入口。
  最终改法：hydrate 放进 `if (require.main === module)` 入口支，先回填再 `validateConfig()`。
  A/B 实测（只给 `*_FILE`、`NODE_ENV=production`）：A 臂（预加载删掉 `*_FILE`，复现"回填没发生"）
  四条假弱密钥 + 「MONGODB_URI 不能指向 localhost」全在；B 臂（当前代码，走真实 CLI）
  弱密钥计数 0，剩下的是我没给的 `CORS_ORIGIN` / `REDIS_URL` / `ALLOWED_HOSTS` /
  `TRUST_PROXY_HOPS`——与密钥无关。
- **finding：闸的读点判据只认一种书写形态**。审计线逐条攻击后确认四处漏判：
  ① 注释里提到 `hydrateSecretsFromFiles()` 就算证据（删掉真调用、留一句注释即绿）；
  ② 解构 `const { MONGODB_URI } = process.env`、别名 `const env = process.env; env.X`、
  动态键 `process.env[k]` 三种读法一律看不见——**看不见比判错更坏**，那等于静默豁免；
  ③ 护栏代读通道 `resolveMongoUri()` 的 require 正则不认带扩展名（`'./destructiveGuard.js'`）
  和 `require(path.join(__dirname, 'destructiveGuard'))` 两种写法，
  而 `fix-token-blacklist-index.js` 唯一的读取通道就是它——上一轮那个"静默回退本地库"的
  缺陷类别因此可以再次溜过；④ 扫描范围只有 `scripts/**`，既不含 package.json 里
  `node <file>` 形态的 npm 入口（`src/config/validate.js` 就是这么漏的），也不含根目录
  `migrate-mongo-config.js`。后者是本轮新发现：`npm run migrate:up` 是以**裸命令名**调 CLI，
  `node <file>` 匹配看不见它，而 CLI 会把同目录的 `migrate-mongo-config.js` 当模块加载——
  那个文件里既有 `resolveMongoUri()`，也有一行上一轮补的 hydrate，**但那行一直站在闸外**，
  删掉不会有任何测试变红。
- **闸改造**：判据抽成三个纯函数（`findHydrationOffender` / `findCliEntryOffender` / `topLevelReads`）
  以便被合成源码直接攻击。注释先剥（逐字符走并跟踪引号，`'mongodb://127.0.0.1/db'` 里的 `//`
  不能当注释起点）；动态键按"可能是读取"计（多算无害，少算是静默漏判）；护栏 require 放宽到
  「`require(` 之后、右括号之前出现 destructiveGuard」。扫描范围三处并集，每处各由一条前提自证钉住。
  新增三条豁免都带**可执行**证据而不是一句注释：豁免一（自带临时值的探针）逐个名字找到赋值处、
  豁免二（共享库 `destructiveGuard.js`）用"确实被 ≥4 个入口 require"自证、
  豁免三（库兼入口）的前提是该文件**没有任何模块顶层读取**（用括号深度算，`depthAt`）——
  前提一破用例即红，逼着改法回到正题。压测/演练三个入口今天不读文件型密钥，
  因此**不许预先占豁免位**（`expect(CLI_ENTRY_BLOCKS).not.toContain(f)` 那类反向钉）。
  减法自证两处：把六个脚本各自的 hydrate 擦掉 ⇒ 闸逐个点名（`verdict` 必须含 hydrate，
  并断言 `stripped !== a.code` 防止"减法没真的动"）；`migrate-mongo-config.js` 同做一遍。
- **工具层陷阱（影响结论可信度，单独记）**：本会话的 Bash 里 `env VAR=x node …` 这种前缀
  **静默不执行**（rc=0、无任何输出），于是第一版 A/B 探针两臂都数到 0 条错误，
  看起来像"缺陷不存在"。同一份 env 用 bash 原生 `VAR=x node …` 前缀跑，才拿到 4 vs 0。
  与上一轮 `'j'.repeat(48)` 夹具被 `isWeakSecret` 判弱那次同一性质：**探针自己坏掉时，
  它给出的"否证"和"证伪"长得一模一样**，所以每条 A/B 都要先证明两臂至少各产出过非零信号。
- 验证：`npx jest src/tests/config src/tests/deploy` ⇒ 35 套件 / 585 条全绿；
  `scriptSecretHydration.test.js` 单跑 15/15；`prettier --check`、`eslint` 对改动的两个文件 0 问题；
  `node scripts/lint-ratchet.js` 对我改的两个文件无回退（现存回退在 `src/services/securityAlert.js`，
  属并发会话在改的文件，未动）。本轮没改 `docker-compose.yml`、`scripts/*.js` 与任何文档。

### 部署（2026-10-03 · SSH 部署路径上 digest 钉死闸一直是静默关闭的 + compose 密钥闸的清单只有 5/15）

> 背景：本轮由「`*_FILE` 密钥回填」那条线连带查出。三条 finding 都属于同一类形状——
> **配了但没送达**、**清单抄短了**、**断言扫空了**——共同点是工作流和 jest 全都绿。

- **finding：`DEPLOY_REQUIRE_DIGEST_PIN` 在 SSH 路径上从未到达 `deploy.js`**。
  `deploy-ssh` 的 `env:` 块里写着 `DEPLOY_REQUIRE_DIGEST_PIN: 'true'`，注释还注明
  「与 self-hosted 同口径」——但两条路径的送达形态根本不同：`deploy-self-hosted` 在
  部署机 runner 上直接 `node scripts/deploy.js`，step env 就是进程 env；`deploy-ssh` 的
  `node` 跑在**目标机**上，而 ssh 既不转发本地环境变量，`SendEnv` 又只在目标机 sshd
  显式 `AcceptEnv` 该变量名时才生效（默认只放行 `LANG/LC_*`）。于是那道"拒绝非 digest
  引用"的兜底闸在 SSH 路径上始终不存在。
  讽刺的是判据早就写过这条口径：本文件 `compose 里每个 :? 变量都由两条部署路径下发`
  那条用例的注释就是「env 里有但没 SendEnv = 目标机收不到」——只是没把同一口径用到
  兜底闸上，而 ⑤ 的断言形状（`expect(ssh).toMatch(/DEPLOY_REQUIRE_DIGEST_PIN: 'true'/)`）
  恰好只查"配了"，替这个洞做了一套完整的掩护。
  如实定级：**这是纵深防御缺一段，不是可利用漏洞**——`IMAGE_TAG` 本身由 preflight 解析
  并过 `sha256:[0-9a-f]{64}` 校验，实际 pull 的就是 digest 引用；闸要防的是"误配/绕过
  preflight 直接把 tag 传进来"，而那条路径上它形同不存在。
- 修法：把它拼进远程命令，并用 `${var:?}` 而不是 `$var`——漏配时报错退出，
  而不是展开成空串让 `deploy.js` 把闸读成"关"（那正是本 finding 的原始形态）。
  不走 `SendEnv`：那要求目标机 sshd 配合，且会撞红上面那条"SendEnv 恰好等于 compose
  硬声明项"的用例。bash 实测两向：置 `true` 时远程命令串为
  `… DEPLOY_REQUIRE_DIGEST_PIN='true' node scripts/deploy.js --dry-run`；
  漏配时 `bash` 立刻退 1 并打印「deploy-ssh 未下发 digest 钉死闸」。
- **闸改造**：`run: |` 扫描器从 describe 内的闭包抽成模块作用域纯函数
  （`collectRunLines(text)` / `deployInvokeLines(text)` / `digestPinDelivered(text)`），
  `allRunLines` 改为委托——同一个 job 可能有多个 step，"取第一个 run"会取到
  Prepare SSH 而不是部署命令（本仓 helper 的注释里就写着这条，但 ⑤ 没用它）。
  抽成纯函数是为了**反向自证**：把修复前的命令串喂进 `digestPinDelivered` 必须判 false。
  变异实测：只删远程命令串里那段（env 块保持"配了"）⇒ ⑤ 当场红在第 248 行
  `expect(digestPinDelivered(ssh)).toBe(true)`（Expected true / Received false），
  其余 16 条不动——正是原洞的签名：所有旧断言都不看送达。
- **finding：compose 密钥闸的名字清单是抄的，5 个 vs `FILE_BACKED_SECRETS` 的 15 个**。
  `docker-compose 不再用 environment 传任何密钥` 把 JWT/REFRESH/AES/HMAC/MONGODB_URI
  五个名字写死在断言里；其余 10 个（`DOCS_PASSWORD` / `LOG_SHIPPING_TOKEN` /
  `METRICS_TOKEN` / `SECURITY_ALERT_WEBHOOK_SECRET` / `SENTRY_DSN` /
  `LOGIN_ECDH_PRIVATE_KEY` / `REDIS_URL` …）哪天被写成 `- X=${X}` 明文注入，闸一声不响。
  改为清单从 `src/config/secrets.js` 反向推导（新增文件型密钥不必回来改用例，
  与 compose `:?` 清单闸同套路）。
  实测现状：7/15 走 `_FILE`（含 `REDIS_PASSWORD`），`REDIS_URL=redis://redis:6379` 明文，
  其余 7 个今天压根不在 app 的 environment 里 ⇒ 新判据对它们是"不许以明文出现"，
  不需要动 compose。**唯一豁免 `REDIS_URL` 不写在注释里，条件就地可执行**：
  URL 里一旦出现 `//…@`（口令 userinfo）立刻判红——redis 只挂在
  `data-net: internal: true` 上、口令走 `REDIS_PASSWORD_FILE`，这条豁免成立当且仅当
  它不含凭据。反向自证用合成源（真实 compose 是并发会话共享的文件，不临时改它）：
  把 `HMAC_SECRET_FILE` 换回明文 ⇒ 抓到；换成第 6+ 个名字 `DOCS_PASSWORD` 再试一次
  （这条才真正证明"扩清单"这件事本身有效）；给 REDIS_URL 塞口令 ⇒ 豁免失效；
  喂一份认不出 app 服务的文本 ⇒ 全部名字按违规上报（判据失效不许静默放行）。
- **新增：`/run/secrets/<名>` 三处一致性闸**（environment 的 `_FILE` 引用、服务级
  `secrets:` 列表、顶层 `secrets:` 段）。漏声明的后果不是"没密钥"而是"启动即崩"——
  `hydrateSecretsFromFiles` 对不可读的 `_FILE` 直接抛错，运维看到的是一条与密钥无关的
  启动失败。顺带钉住顶层每个 `file:` 必须落在 `./secrets/`（`.gitignore` 与
  `.dockerignore` 只排除这一个目录，指到别处等于把密钥放回版本库与构建上下文）。
  合成夹具 `CLEAN` / `ORPHAN` 各证一侧：`b_secret` 顶层声明了却没挂到 app ⇒
  `missingFromService` 抓到、`missingFromTopLevel` 必须为空（判据认的是"两处一致性"，
  不是一刀切盯 environment）。
- **自查出一条假绿（自己写自己抓）**：本条第一版的顶层扫描用了
  `/^ {2}[a-z0-9_]+:\n {4}file: (\S+)$/gm`——本仓库文件是 CRLF，`:` 与 `\n` 之间夹着
  `\r`，这条正则**恒不匹配**，那个 `for` 循环体一次都没执行，而用例是绿的。
  这正是本仓踩过两次、写在 `deployWorkflow.test.js` 注释里的坑（"不用 $ 锚点：
  本仓库工作流是 CRLF，`\r` 会让行尾锚定的正则恒不匹配（实测过）"），我照样踩了。
  现在所有 compose 扫描统一先 `split(/\r?\n/)` 再逐行匹配，并把这类"取到多少条"
  写进前提自证（`referenced.length >= 7`、`targets.length >= referenced.length`、
  每个 `file:` 必须是字符串）。
- 核过撤销的怀疑：`ADMIN_INITIAL_PASSWORD_FILE` 曾被记为"compose 接了但应用不读"的
  疑似死接线——`src/services/initData.js:770,833` 确实在读它（初始管理员口令），
  嫌疑撤销。
- 验证：`npx jest src/tests/deploy src/tests/config` ⇒ 35 套件 / 578 条全绿；
  `prettier --check` 与 `eslint` 对改动的三个文件均 0 问题。
  本轮未改 `docker-compose.yml` 与 `scripts/deployPolicy.js`（判据变了，配置没变）。

### 运维可用性（2026-10-03 · `*_FILE` 密钥部署下六个独立脚本拿不到连接串）

> 背景：`src/config/secrets.js` 的 `<NAME>_FILE` 约定（P3-48：密钥走文件挂载，不进
> `docker inspect` / `compose config` / 子进程继承）只在**require 到 `src/config` 的入口**
> 自动回填 process.env。运维手边的独立脚本几乎都是 `require('dotenv').config()` +
> 直读 `process.env.MONGODB_URI`，这两者从来没接上。
>
> **本轮推翻了自己的第一版判据**：先用静态依赖图筛"哪些脚本需要补 hydrate"，
> `verify-audit-chain.js` 的图确实通向 `src/config`（auditChainVerify → utils/auditChain →
> 函数体内 `require('../config')`），按图它不需要改。改成动态探测（只给 `MONGODB_URI_FILE`、
> 显式把 `MONGODB_URI` 置空、目标端口 1）后结论相反——那是**懒 require**，脚本在 `main()`
> 里读 env 时它还没执行。静态图在这里会给出假绿。

- 实测（修前）：`verify-audit-chain` / `revoke-user-sessions` / `run-rollback-drill` /
  `sync-audit-indexes` / `perf/explain-spotcheck` 读到空串，开局报错退出；
  `fix-token-blacklist-index` 更隐蔽——`resolveMongoUri` **静默回退本地默认库**并打印
  「已连接：127.0.0.1:27017/fire_safety_db」，运维以为在清生产索引。
  同族 `resign-audit-hmac.js` / `resign-audit-chain-v3.js` 因为显式调了 hydrate 一直正常，
  它们同时充当探测方法学的正向对照（对照组判"已 hydrate"，说明判据不是在猜）。
- 后果直接落在文档化的运维步骤上：`deployment/secret-rotation.md` 的 HMAC 轮换第 0/4/5 步
  都要求 `node scripts/verify-audit-chain.js` 且注明"要求退出码 0"，
  在 `*_FILE` 部署里这一步**做不到**——第 5 步会退 1，轮换完成后无人给出链条干净的证据。
- 六个脚本各自补 `require('../src/config/secrets').hydrateSecretsFromFiles();`
  （紧跟 `dotenv`，早于任何 env 读取），与本仓既有同族写法一致。
  不用"把 hydrate 塞进 `destructiveGuard.js`"这种集中式改法：它是被 require 的库，
  无权决定进程何时回填，而且 `verify-audit-chain` / `explain-spotcheck` 根本不经它。
- 新闸 `src/tests/config/scriptSecretHydration.test.js`（8 条，逐条能被打红）：
  读取文件型密钥的入口必须**自己**显式 hydrate，且早于首次读取。
  读点有两条通道，只钉第一条会漏——`fix-token-blacklist-index` 唯一的读取通道是
  `require('./destructiveGuard')` 代读，所以把护栏引入点也按读点计（否则删掉它的
  hydrate 行，闸照样绿）。
  判据自证：合成源码攻击（缺 hydrate / hydrate 太晚 / 只赋值不读 / `===` 比较 /
  `JWT_SECRET_V2` 前缀同名）各一条；豁免两条各自带证据——
  `audit-probes/ws-session-bypass.cjs` 必须能为每个读到的名字指出赋值处，
  `destructiveGuard.js` 必须真的被 ≥4 个入口 require；
  压测/演练入口（e2e-smoke / load-test / production-drill）今天只写不读，
  因此**不许预先占豁免位**，哪天它们开始读 env 就会撞红再登记。
  变异实测（用真实文件，不是合成源码）：删掉 `fix-token-blacklist-index.js` 的 hydrate 行
  ⇒ 闸当场报出该文件（「读取文件型密钥 MONGODB_URI，但整个文件没有调用
  hydrateSecretsFromFiles()」），恢复后 8/8 绿——这条正是"只钉直读通道"时会静默漏掉的那个脚本。
- 核过不动的：`scripts/*.sh`（backup/restore）按文档就是 `MONGODB_URI='<连接串>' ./scripts/...`
  显式传值（secret-rotation.md:277），不经 Node 的 env 回填路径。
- 实测（修后）：同一探针下六个脚本全部改为"拿文件值去连"（端口 1 上超时被杀，
  即它们真的读到了 `*_FILE` 里的连接串）。
  另用真实内存 MongoDB 端到端跑 `verify-audit-chain.js`：只给 `MONGODB_URI_FILE`
  （文件内容**故意带尾部换行**）时它连上了库并打印
  「VERDICT: INCOMPLETE — 审计集合为空（0 条）：无记录可验」——这条判定只有连接成功才可能给出，
  空集合是夹具本身没种记录；两者都不给时退 1「未提供 MONGODB_URI」，
  作为反向对照证明前一条不是默认值蒙出来的。

### 修复（2026-10-03 · 上一轮 PII 收窄的两处回归：揭示迟到写入 + 审计副本仍存明文号码）

> 背景：四路并行逐行审计复核 2026-10-02 的两批改动，各命中一条**由那批改动自己引出**的缺陷。
> 两条都已回源核实并做变异实测，不是推测。

- **lane-B #1｜`web-admin/src/views/UserView.vue` 的 `doReveal` 迟到写入守卫**。
  原实现 `await` 之后无条件 `dialog.form.phone = full; dialog.phoneBaseline = full`，
  既不校验目标行也不校验弹层是否还开着。可达路径：点「查看完整号码」后请求飞行期间
  ESC 掉 step-up、关掉编辑框、再点另一行的「编辑」⇒ **A 的明文连同基线一起落进 B 的表单**，
  而界面上的提示恰好是「清空并提交即删除」⇒ 管理员照着删空再保存，
  抹掉的是 **B 的真实号码**。修法是发请求前把 `reveal.userId` 快照成 `targetUserId`
  （step-up 一关 `resetReveal` 就会把它清空，事后读不到），响应回来只在
  `dialog.form._id === targetUserId` 时写入。只比 `_id` 不叠加 `dialog.visible`/`isEdit`：
  关框必走 `resetForm`（`_id` 归 null）、新增框同样是 null，多余的两个条件恒真且**写不出
  能覆盖它们的用例**，留着就是无人验证的死分支。
  门禁：`web-admin/src/tests/views/userView.test.js` 新增两条（切到另一行 / 切到新增框），
  夹具用**手工 defer 的 Promise**——`mockResolvedValue` 在下一个微任务就落地，
  任何迟到守卫都来不及被触发，用例会退化成恒真。
  变异实测：把守卫改成 `if (false && …)` ⇒ 两条同时转红（`expected '13900000000' to be ''`），
  恢复后 61/61 绿。
- **lane-A #2｜`src/utils/helpers.js` 的 `SENSITIVE_KEY_SUBSTRINGS` 补 `phone`**。
  名单原本只管"凭据"，于是 `PUT /api/users/:id`、`POST /api/alarms/report` 这些**写路径**
  把手机号明文留在了 `AuditLog.body` 里，而 `services/securityAlert.getRecentAlerts`
  的投影含 `body` ⇒ `GET /api/security/alerts` 把它再下发一次；`auditBuffer` 的明文 WAL
  同样带着它。结果：持 `security:audit` 的账号无需口令、无需 `system:read`、
  不写一条 `view_sensitive_data`，就能读到任意用户与任意报警上报人的完整号码——
  上一轮"读接口停发明文"只堵了响应侧，**审计侧是同一条合规通道的另一半旁路**，
  而当时新增的 egress 门禁全绿（它只盯响应体），这正是那条门禁的盲区。
  改的是单一事实来源：`auditLogSanitizer` 与 `middleware/security.js` 的两条脱敏流水线、
  以及 morgan 的 URL 打码（`isCredentialQueryKey` 取并集）同时生效，
  扁平 `phone` / 嵌套 `reporter.phone` / camelCase `workPhone` / 敏感键装数组四种形态一起收，
  `?phone=` 在访问日志里同步打码。既有用例 `auditLogSanitizer.test.js`「真实中间件驱动」
  按名单逐键构造请求体，因此**免费**获得了对 `phone` 的端到端覆盖。
  不误伤边界保持原样：`postcode` / `zipcode` 不含 `phone` 子串，值仍可读。
  门禁：`src/tests/models/auditLogSanitizer.test.js` 新增一组 5 条（形态覆盖 + 键名噪声 +
  不误伤 + query/URL 同口径），`src/tests/security/userPhoneMaskedEgress.test.js` 新增一条
  **真实路由**用例（发一次带明文的 PUT → `auditBuffer.flush()` → 读回审计行，
  断 `body.phone === '***'`、序列化不含明文，并用 `body.realName` 证明不是"整块抹掉"）。
  变异实测：从名单里删掉 `phone` ⇒ 4 条同时转红（含真实路由那条），恢复后 12/12 + 11/11 绿。
- **如实声明的残留**：脱敏判定只看**键名**，不做值形态扫描。因此装在非敏感键下的号码
  （`{contacts:['139…']}`、备注文本里的号码）仍会进审计副本——这是刻意止步，
  不是漏网：按 11 位正则扫值会连带抹掉报警描述/备注里的号码，取证价值损失大于收益。
  该边界已写成一条可执行用例（「如实声明边界」），要跨过它需要单独拍板。
  `AuditLog` 里的**历史**明文行不会因本改动消失，清理属数据迁移议题，另行决策。
- 消费方核实：全仓非测试代码只有 `securityAlert.js:84` 按 `body.ipAttempts` 取数，
  没有任何逻辑依赖审计 body 里的手机号可读；现有测试无一断言审计副本含明文号码。
- 文档同批（lane-C #8 的实证条目）：`controllers/securityController.js` 里三处注释错位——
  「举报异常行为 POST /security/report」的标题悬在空处、举报核验的整段 JSDoc（含 `@returns`）
  挂在 `REPORT_TARGET_KINDS` 这张**对象表**头上、还有一段描述 `buildAuditLogQuery` 的 JSDoc
  紧跟在 `getRegistrationConfig` 的文档之前（该函数早已搬到 `utils/auditQuery.js` 的
  `buildAuditQuery`，全仓不存在同名符号）。按"注释只描述它紧邻的代码"重挂，
  并删掉那段失效的构建器文档。改动纯注释：逐行比对确认代码行零差异（只少一个空行）。

### 修复（2026-10-02 · 管理员用户读接口停发明文手机号，改走「脱敏下发 + step-up 揭示」）

> 背景：上一轮把 `reporter.phone` 从报警读出路径摘掉后，同一列在**用户管理**上更严重：
> `models/User.js` 的 `phone` 有 getter 透明解密，且 schema 的 `toJSON/toObject` 只设了
> `getters:true` 没有 `transform` ⇒ 任何**不带投影**的读取都会把明文号码整体发出去。
> 原 `User.RESPONSE_EXCLUDE` 排了 password/phoneKey 等 9 项却**没排 phone**，
> 于是列表 / 详情 / 建号回显 / 改号回显 / 角色回显**五条路径**全部明文下发。
> 后果不只是"看得到"：明文一旦进列表，`POST /api/security/view-sensitive`
> 那条专为手机号建的合规通道（step-up 二次验证 + `view_sensitive_data` 审计 +
> 审计写失败即不返回明文）就被彻底架空——想查号码的人不需要口令，翻页就行。
> 拍板口径：**表格默认脱敏 + 按需 step-up**（用户明确选择服务端一起收窄，不是前端打码）。

- `models/User.js`：`RESPONSE_EXCLUDE` 改为由字段数组拼出，新增 `-phone` 进默认排除；
  派生出 `RESPONSE_EXCLUDE_PHONE_VISIBLE`（同一份数组**滤掉** `-phone`）。
  用数组而不是对字符串做 `replace(' -phone','')`：字符串手术在字段顺序变动时会**静默失配**，
  失配后的表现恰好是"明文照发、门禁照绿"。变体名字本身就写着危险，注释规定它只能与
  `toMaskedAdminUser` 配对使用。
- `services/userService.js`：新增读模型 `toMaskedAdminUser(doc)` —— `phoneMasked =
DataMasking.maskPhone(obj.phone)` 后 **`delete obj.phone`**。四个管理员读函数
  （`listUsers` / `getUserDetail` / `getCreatedUser` / `getUpdatedUser`）改用
  `RESPONSE_EXCLUDE_PHONE_VISIBLE` 并统一过这个函数：投影留着 phone 是为了让**解密 getter
  在服务端跑一次**，脱敏只在服务端这一处做——`maskPhone` **不幂等**（对 `138****5678`
  再打一次得到 `****`），所以前端一律不再打码，只做展示。
- **响应字段改名成 `phoneMasked` 而不是 `phone: 脱敏值`**（有意偏离 `my-info` 的既有口径）：
  编辑对话框会把行对象灌进表单，而 `userController.js` 用 `if (phone !== undefined)` 落库、
  路由校验是 `/^1[3-9]\d{9}$/` ⇒ 叫 `phone` 的展示值只有两种结局，且**都是坏的**：
  原样回传被 400 拒掉，或被当成"用户想清空号码"抹掉真值。改名让"这是展示值、不是可写字段"
  在类型上就不可能被搞混。
- `web-admin/src/views/UserView.vue`：列表列读 `phoneMasked`；编辑对话框**不再回填**手机号，
  改为输入框旁一个「查看完整号码」→ 二级 step-up 弹层（只收当前登录口令）→
  `POST /api/security/view-sensitive` 返回的 `full` 才进输入框。提交按**脏字段**发键：
  未揭示 / 揭示后未改 ⇒ 不发 `phone`；揭示后删空 ⇒ 发 `''`（这才是真的清空）。
  提示语随 `phoneBaseline` 切换，两处状态各自说清"留空即不修改"和"已载入现值"。
  step-up 的口令由 el-dialog `@closed` 单一清理点负责（打开时再清一次是冗余，
  冗余那处会让清理逻辑被改坏时测试照样绿）。
- **有意的边界，不一起收窄**：自助通道 `GET /api/auth/me` 与 `PUT /api/auth/profile`
  仍返回本人明文号码——那是用户自己的数据、且编辑页需要现值；`utils/permissionHelper.js`
  处早已写明"回填脱敏值会污染数据或阻断保存"。这条边界用一条**反向**用例钉住
  （`/auth/me` 必须还能拿到明文），免得下一个人"顺手统一"。
- 消费方核实：web-admin 里 `users.getList` 的 phone 只有 UserView 一处读，ProfileView 读的是
  `/auth/me`，RegisterView 是自己的表单 ⇒ 停发零界面功能损失。搜索侧无残留 oracle：
  列表 `search` 的 `$or` 只覆盖 username/email/realName，`phoneKey` 全仓**无** `find({phoneKey})`
  （`models/User.js:270-277` 已记为"已供未接"）。
- 文档同批：`openapi.json` 建号请求体的 `phone` 补 description「仅接受写入；
  列表/详情/建号/改号/角色回显返回 phoneMasked，不含该字段」（`src/docs/generate.js` 重生成）。
- **门禁**：新套件 `src/tests/security/userPhoneMaskedEgress.test.js`（10 例）——
  夹具自证（不带投影的裸读确实能拿到明文，证明排除不是空转）/ 两条投影只相差 `-phone` /
  五条响应路径逐个断言 `'phone' in payload === false` **且** `JSON.stringify` 不含明文
  **且** `phoneMasked` 值正确（只断言"没有"会让整列被删也测成通过）/ 边界自证
  （省略键 ≠ 清空；把 `139****1122` 提交上去必须 400 **且库里原值未变**）/
  view-sensitive 揭示与 `/auth/me` 两条反向钉 / 源码文本闸：`RESPONSE_EXCLUDE_PHONE_VISIBLE`
  出现处必须紧邻 `toMaskedAdminUser`（防"换投影忘了脱敏"），并钉住 `delete obj.phone;`。
  变异实测三臂：摘投影 → 5 红；摘 `delete obj.phone` → 2 红；把变体名改回基名（模拟漏接）→ 1 红。
- 前端门禁：`userView.test.js` 新增 9 例（脱敏列渲染 / 新增框无揭示入口 / 空口令不发请求 /
  揭示请求形状 / 揭示后不改不发键 / 揭示后删空发 `''` / 揭示失败不污染也不误发 /
  口令不跨次残留 / 关外层时二级弹层一并收起）。step-up 是嵌套对话框，`append-to-body` 后
  节点挂在 body 上，"是否关闭"只能断言 overlay 的 `display` 终态——EP 关闭后 DOM 仍在，
  断言节点消失会得到一条恒真的假绿。变异实测三臂：提交无条件带 `phone` → 3 红；
  列改回 `row.phone` → 1 红；摘掉 `@closed` 清理 / 摘掉外层关闭 → 各自对应那条红。
- **如实声明残留**：库里仍是可解密的密文（本改动只收窄**下发面**）；操作者**本人**的明文手机号
  仍会写进 `localStorage.currentUser`（`/auth/me` 的形状），是否连浏览器持久化一起收窄
  需要单独拍板——它会改变刷新后 ProfileView 的短暂空值表现，且 email/realName 同批同性质。

### 修复（2026-10-02 · 报警读出路径停发 `reporter.phone`）

> 背景：四路逐行审计的 lane-B 报出一条新缺陷并回源核实。`FireAlarm.reporter.phone`
> 是**明文存的第三方手机号**，不属于 `models/User.js` 那套「getter 解密 +
> `POST /api/security/view-sensitive` step-up + `view_sensitive_data` 审计」通道；
> 而报警的读出路径原本一条根文档投影都没有 ⇒ 任何持 `alarm:read` 且落在该条范围内的
> 账号都能**整页批量**读到它，无二次验证、无 `system:read`、无留痕——把仓里专为
> 手机号建的合规通道架空。同一 model 上的 `handler.phone` 正因同样理由被收窄过
> （`alarmDetailHandlerPii.test.js`），这条是同一列的邻接漏点。
> 拍板口径：**读出全部停发**（对齐 handler.phone 先例），不做静态加密改造。

- `services/AlarmService.js`：新增模块级 `ALARM_READ_SELECT = '-reporter.phone'`，
  **八处**调用点全部引用同一个常量——游标列表 / offset 列表 / 详情用 `.select()`，
  五个处置接口（dispatch/arrive/resolve/false-alarm/cancel）用 `options.projection`。
  后者是这次真正容易被漏掉的部分：它们把 `findOneAndUpdate` 的 `updated` 文档原样回给
  客户端，只修列表与详情等于同一列从这五个口整块漏出去，而 CI 仍全绿（那五个响应体
  本来没有用例读过）。
- **有意的例外**：`POST /api/alarms/report` 回显 create 出来的文档，其中含提交者自己
  刚写进去的号码——不构成新的读取，故不改（已把这条写进常量的 JSDoc，免得被当成漏点
  重新发现或"顺手补上"）。
- **如实声明残留缺口**：值仍明文存在库里；备份转储与密钥轮换的保护缺口**不随本改动关闭**。
  将来若要开放"回拨上报人"，正确做法是给它一条与 User PII 同级的揭示通道，
  而不是把这一列加回读接口。
- 消费方核实：web-admin 全文 0 处读 `reporter.phone`/`reporterPhone`，报表导出只取
  `reporter.name`（`reportExportService.js:266`），e2e 0 处 ⇒ 停发零界面功能损失。
- 文档同批：`models/FireAlarm.js` 的 `reporter.phone` 注释写明"明文存储 + 读接口不回传"，
  `openapi.json` 的请求体字段补 description「仅接受写入，列表/详情/处置响应均不返回」。
- **门禁**：新套件 `src/tests/services/alarmReporterPhoneEgress.test.js`（7 例：
  夹具自证裸查询能拿到明文 / 详情 / offset 列表 / 游标列表 / 五个处置回显 / 状态机前提自证 /
  源码文本闸）。每条排除断言都带反向证据（`reporter.name` 必须还在），防止"整个子文档被
  删了"或"populate 没生效"伪装成通过。源码闸的窗口取「到下一个调用点为止」而不是固定字数
  ——`resolveAlarm` 的 `$push` 文案块就比 420 字符长，固定窗口会对正确的代码报红。
  变异实测两臂：摘掉详情的 `.select` → 行为与源码闸 2 红；只摘 `cancelAlarm` 一处的
  `projection` → 处置回显 + 状态机自证 + 源码闸 3 红（证明"只修一条"确实会被抓住）。

### 测试（2026-10-01 · 两处 HEAD 上就存在的红灯）

> 全量 `npx jest --ci` + `npm run format:check` 复跑时发现：不需要本轮任何改动，main 上已经有
> 三条用例与一条格式闸是红的。CI 跑这两条（`ci.yml` 的 jest 与 `:79` 的 format:check）⇒ 合并队列
> 上任何后续提交都会被这两处**别人的**失败误判成"本提交引入的回归"，所以先修它们。

- **`websocketRedisAdapter.test.js` 落后于 Redis 认证改造（2 例红）**：`2816d68` 给订阅端补了
  `password: sharedCache.redisConnectionPassword()`（`websocketService.js:260`），但该套件的
  `jest.mock('../../services/sharedCache')` 工厂只造了 `isRedisEnabled`/`getRedisClient` 两个键。
  失败形态很有教育意义：第一条是 `toHaveBeenCalledWith` 的对象不匹配，第二条**不是**它声称要测的
  "挂载失败降级"，而是桩自身缺键抛出的 `sharedCache.redisConnectionPassword is not a function`
  被 `catch` 吞掉后进了同一条 warn 分支——断言只匹配 `stringContaining`，于是"桩坏了"伪装成
  "降级路径测过了"。收口：桩补该函数并返回哨兵值，断言要求哨兵出现在 `new Redis` 的 options 里
  （`toHaveBeenCalledWith` 是全等对象匹配，多键/少键/漏传都红 ⇒ 这条现在是"口令必须外发到
  订阅端"的真闸，而不是只让套件变绿）。
- **`piiEncryption.test.js` 格式（1 条格式闸红）**：`4402562` 移除未使用导入时留下了未过 prettier 的
  解构折行。本轮只做格式化（1 增 6 删，零行为变化）。

### 修复（2026-10-01 · `POST /api/security/report` 的目标核验与账号配额）

> 背景：该端点刻意不挂权限码（人人可举报是产品设计），但路由注释自称「本人资源…无越权面」
> 是**假的**——上报内容由调用者撰写，`targetId` 指向的却是别人的记录。修复前任何登录用户
> 都能提交任意 `targetId`（不校验存在性、不校验范围、无独立配额），服务端原样写进一条
> `riskLevel:'high'` 的审计行，而安全概览的「高风险操作数」与告警取数都读这批行。

- **路由层**：`targetId` 的形态由 `targetType` 决定——记录型（user/device/alarm）必须是非空
  字符串且为 ObjectId；`system` 型**禁止携带**（否则把类型改成 system 就绕过整条核验）。
  `.exists({ values:'falsy' })` 承担的是文案而不是拒绝：删掉它后面的 `isString` 会给同一个
  400 和同一个 path，变异实测确认「只看状态码+path」的用例是绿的但不设防，故用例断言 msg。
- **控制器**：记录型目标必须**真实存在**（否则 404，`USER_NOT_FOUND` 在注册表里是 401 的
  登录语义，此处显式改 404）且**落在举报人的数据范围内**（否则 403）。范围判定复用
  `rbac.assertRecordInScope` + `DATA_SCOPE_FIELDS` 单一声明，与各自详情/写路径同判据；
  404/403 的先后与 `deviceController.js:122/124`、`alarmController.js:156/158` 的既有口径
  一致（存在性预言机在每条授权读路径上本来就存在，本处不新引入一类泄露）。
  自由文本 `reason`/`description` 不受影响：被约束的是"结构化字段必须是真记录"。
- **限流**：新增账号维度桶 `securityReportUserLimiter`（20 次/15 分钟，键 `report-user:<userId>`，
  不含 IP 成分）。与凭据型姊妹桶同一口径：**并列**而不是把 IP 从组合键里删掉；同样
  **不接** `noteRateLimitHit`（账号桶没有可封的 IP）。阈值刻意不导出：测试里钉死 20 并同时
  校验服务端声明的 `RateLimit-Limit`，改配额会让用例变红而不是自动适配。
- **分层**：数据访问经 services 的 `findScopeFieldsByIds`（`AlarmService` 补该 getter，
  投影 `reporter.userId handler location.building`），控制器不新增直连 model——
  初版直连 FireDevice/FireAlarm 被 `architecture/layeringRatchet` 判红（5→7）后改的。
  连带：`skipGlobalAuditWriteFailure.test.js` 的 `models/User` 桩只提供了 `findById`，
  而 `userService.findScopeFieldsByIds` 的形状是 `find().select().lean()` ⇒ 桩补该链路并返回
  与夹具 `targetId` 同 `_id` 的记录，否则该套件两条举报用例先撞 `TypeError`，
  走不到它要测的审计写入点（全量跑实测到）。
- **门禁**：新套件 `src/tests/security/reportTargetScopeAndLimiter.test.js`（23 例：存在性、
  三条范围臂的放行与拒绝、绕口封堵、配额与 XFF 轮换、trust proxy 前提自证、
  投影完备性静态闸）+ 改写 `reportTargetIdBoundary.test.js`（形状边界，7 例）。
  变异实测 5 臂：中和范围臂→B 组 4 红；摘掉限流→D 组 2 红；删 `.exists`→msg 断言红；
  删 system 反例→绕口封堵红；删存在性→A 组与边界 404 判据 3 红；删投影一列→B/E 同时红。
- 文档同批收窄：`models/AuditLog.js` 的 `targetId` 契约注释、`PERMISSION-EXEMPT` 理由改写为
  如实版本、`src/docs/openapi.json` 重生成（targetId 加 ObjectId pattern + 403/404 响应）。

### 修复（2026-10-01 · 13 项报告回源复核后的三处落地）

> 背景：对一份 13 条的审计报告**逐条回源复核**，其中 8 条已在 19:21~20:50 的提交里闭环、
> 1 条（封禁目标可伪造）在他方在途、4 条未动。本轮落地的是**报告里没有的三处**——
> 两条由复核过程新发现，一条属报告第 13 条所在的低优先段。

- **N1 HMAC_SECRET 消费点清单收敛为单一来源**。复核发现同一份仓库里存在**三份互不相同**的清单：
  `deployment/secret-rotation.md` 写「**两个**消费点」（审计链 + 口令历史），
  `deliverables/AGENT工作总账与待办` 的 F-26 写「三个」（审计链 + MFA 恢复码 pepper + 数据签名密钥，
  **漏了口令历史**），而真实源码是**四个**（`src/utils/auditChain.js` / `src/utils/passwordHistory.js` /
  `src/services/mfaService.js` / `src/utils/encryption.js`）。手册全文 `恢复码` **0 命中**——
  而恢复码是用户丢掉认证器时的唯一逃生门，换钥后静默失效，故障只在"某个人手机丢了"那天暴露。
  收口：① 手册改成四消费点表（含"只有第 1 个有迁移工具"的非对称事实）；
  ② 新增门禁 `src/tests/config/hmacSecretConsumersSingleSource.test.js`——扫描 `src/`（排除
  `src/tests` 与 `src/config` 装载面）里**取值访问** `HMAC_SECRET` 的文件，要求集合恰好等于登记清单，
  并要求手册逐个点名。判据取「取值访问」而非「提到 HMAC_SECRET」：注释/报错文案/校验器里都会出现
  大写 `HMAC_SECRET`，算进来会让清单被噪声撑大、反而失去意义（`services/auditChainVerify.js` 的
  `computeHmac` 是从 `utils/auditChain.js` 导入的，密钥取值不在它那里，故不重复计）
  - 门禁：新套件 9 例（含"扫描基线非空"防"零命中被当成通过"、"手册必须点名恢复码"作回归哨兵）
- **N2 PII v1 存量行的静默缺口补启动期告警**。10-01 把写侧切到 v2（AAD 行绑定）时读侧刻意保留 v1 兼容，
  代价是 **v1 密文与行身份无关**——`utils/piiCrypto.js` 的 v1 分支 `aad` 保持 `null`、`if (aad)` 永不
  `setAAD`，于是把 A 行的 `enc.v1.…` 复制到 B 行，B 行的 getter（`models/User.js:105-106` 虽已传
  `{subjectId, field:'phone'}`）会**正常解出 A 的明文**。写侧不再产 v1，但**存量行不会被自动升级**，
  而升级唯一入口是手工跑迁移脚本，**没有任何启动期信号**（`src/config` 下只有 `pii_rotation_old_key_lingering`
  那条旧钥告警，与"v1 未迁移"无关）。收口：`config/immutableConfigGuard.js` 增加第三项
  `pii_v1_rows_unmigrated`（生产 + PII 主密钥可用 ⇒ 告警 + `incSecurityAlert`，**不阻断启动**，
  口径同 immutable 档位），并写进轮换手册收尾清单
  - **如实声明边界**：该告警的判据是"代码仍支持读 v1"，**不是"库里还有 v1 行"**——启动路径
    （`config/validate.js`）在 mongoose 连接**之前**执行，不连库，故它**不会自行消失**。要判"迁完了没"
    只有一条路：`node scripts/migrate-pii-encryption.js`（演练模式、只读）看剩余行数。这条边界已写进
    手册与告警文案，否则运维会拿"告警还在"误判成"没迁完"
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **2 条反向断言**：非生产不得告警、
    主密钥缺失不得告警）。**变异实测被杀**：把判据改成 `NODE_ENV !== 'never-matches' && true` ⇒
    4 条红（2 条反向断言 + 2 条既有的 `toHaveLength(1)`），改回后 29/29 绿
  - **待拍板（未落地）**：更彻底的做法是把 v1 读路径也改成 fail-closed（镜像 `ALLOW_LEGACY_CBC_DECRYPT`：
    缺 `ALLOW_PII_V1_DECRYPT=true` 即抛），那样"库里有 v1 行"会当场变成响亮的读错误。
    未做是因为它是**生产行为变更**（升级即可能让存量行读失败），按本仓纪律属"需人拍板"那一档
- **#12 上传扩展名闸由 fail-open 改为构造期 fail-closed**。`middleware/security.js` 原实现是
  `allowedExts = allowedTypes.map(t => MIME_TO_EXT[t]).filter(Boolean)` 配 `if (allowedExts.length > 0 && …)`
  短路：白名单里**一个都映射不到**时 `filter(Boolean)` 把结果清空 ⇒ **扩展名校验整条消失**，
  只剩客户端自报的 MIME。今天无 multer 挂载故不可利用，但"配了却不生效"一旦随首个上传路由上线就会同时生效。
  收口：MIME→扩展名映射与校验提到**构造期**（= 路由装配期，即启动期），`allowedTypes` 里存在**任何一个**
  未映射项即抛错（只抛"全部未映射"会把部分静默放行留在原地），运行期不可能再出现"白名单非空但扩展名闸为空"
  的组合，短路判据随之简化为 `allowedTypes.length > 0`
  - 门禁：`securitySanitizeAndBlacklistDegrade.test.js` 追加 5 例（全部未映射抛 / 部分未映射抛 /
    报错点名支持集 / 空白名单不抛 / 受支持白名单不抛——最后两条防"一律抛"的恒真实现），该套件 30/30 绿
  - 已知边界：本次**只**修扩展名闸的 fail-open，未新增任何上传路由；中间件仍是"预留能力、无路由挂载"

### 修复（2026-09-30 · 安全缺口核查落地）

- **敏感 GET 读取审计判据反转（P1-④）+ PII at-rest 加密（P1-②）+ 备份加密（P1-①）等七项缺口收口**（对照 `deliverables/安全缺口核查-2026-09-30.md`，其中 P1-④ 与 P2-⑥ 已于本日早先提交落地）：
  - **P2-⑧ 传输加密启动断言**：生产环境 Mongo 非回环主机必须 `tls=true`、Redis 必须 `rediss:`，豁免走显式旗标 `MONGODB_TLS_EXEMPT`/`REDIS_TLS_EXEMPT`（同宿主 compose 即豁免使用者，拆分拓扑忘摘旗标会被启动期拦截）；判据收口 `config/transportSecurity.js`（回环判定吃 127.0.0.1/::1/IPv4-mapped/localhost 全形态；hostname 解析不出保持沉默——compose 契约测试的替身 URI 不被误杀）
  - **P2-⑨ 出站目标门禁**：`LOG_SHIPPING_URL` 在 scheme 白名单之外再拒内网/回环/链路本地目标（云元数据端点是经典 SSRF 目标）；歧义 IPv4 形态（127.1/2130706433/0x7f.0.0.1，严格解析判 null 但 OS 仍按回环连）一并拒绝；内网 SIEM 用 `LOG_SHIPPING_ALLOW_PRIVATE_HOSTS` 显式放行（主机名/IP/CIDR，与 IP 名单同一把尺）。判据 `isPrivateOrLoopback` 自 metricsAuth 迁入 `utils/ipUtils.js` 单一来源（middleware→utils 反向依赖会破分层）
  - **P1-① 备份加密 + 校验和 + 异地副本**：`backup-mongo.sh` 默认 gpg 非对称加密（备份宿主机只放公钥，私钥托管异地），明文出口 `BACKUP_ENCRYPTION=plaintext-acknowledged`（取值即确认词）；产物三件套 .gz.gpg + .sha256 + `BACKUP_OFFSITE_CMD` 异地钩子（argv 解析不经 shell 展开、失败即整体失败）；`restore-mongo.sh` 按后缀自动解密；加密/解密/校验和收口 `scripts/backupCrypto.sh`（与 mongoUri.sh 同一共享范式）；恢复演练与密钥托管见 `deployment/backup-encryption.md`
  - **P1-② PII at-rest 加密（范围修订）**：`phone` 走随机 IV AES-256-GCM（`utils/piiCrypto.js`，密文带 `enc.v1` 版本前缀供轮换），精确检索走 HMAC 检索键 `phoneKey`（select:false + 索引）——相等性不泄漏在密文列里；存量明文**读路径透传**（迁移前的旧行照常可读），写侧 `pre('validate')` 钩子加密（手机号格式校验随钩子前移到明文阶段，错误文案逐字不变）；迁移/轮换脚本 `scripts/migrate-pii-encryption.js`（演练/apply 双模，损坏行点名不覆盖，同族 allowlist 门禁）。**realName 暂不加密**（2026-09-30 决策）：姓名片段模糊检索是用户列表的日常能力，正则对密文不成立，加密它等于砍掉该能力——用户列表搜索继续覆盖 username/email/realName；`realName` 转入加密需先给姓名检索另立方案，脚本对加密窗口内已产生的密文行自动解回明文自愈
  - **P2-⑩ 供应链可追溯**：CI 构建产出 CycloneDX SBOM 并上传 artifact；镜像 `provenance: true` + cosign keyless 签名（build 作业补 `id-token: write`）
  - **P2-⑫ 依赖钉版**：`.npmrc` `save-exact=true` 从源头杜绝 caret 漂移；新增 CI 硬门禁「生产依赖树禁止任何 install 脚本」（`scripts/check-prod-install-scripts.js`，fail-closed + 显式白名单——比 --ignore-scripts 更强：ignore-scripts 只让本机跳过，树里有没有脚本没人看）
  - **P3-⑬⑭⑮ 治理文档三份**：`docs/threat-model.md`（STRIDE + 残余风险如实申报）、`docs/incident-response.md`（角色/时限/命令级遏制清单，全部绑定本系统实际存在的端点与脚本）、`docs/mlps2-controls.md`（等保 2.0 第三级重点项对照，每条挂文件/测试/端点证据）
  - 门禁：`transportTlsAssertion`（9 例）/ `backupEncryptionContract`（stub gpg 行为链）/ `piiEncryption`（纯判据 + 真实 Mongo 接线，9 例）/ logShipper 出站目标真值表（27 例）等新增约 60 例；既有 backupTransport/backupScriptGuards 夹具显式声明明文确认出口，保持其原断言对象不变

### 修复（2026-09-30 · 供应链完整性锚 + PII 旧钥残留守卫）

- **P2-⑩ 补：lockfile 完整性锚**（`scripts/check-lockfile-integrity.js` + `deployment/lockfile-anchor.json` + `npm run check:lockfile` + CI `security-audit` 一步）。已有的 SBOM/cosign/provenance 回答的是「我用了哪些组件」与「镜像来源可证」，但**不比对「依赖树与上次拍板时是否一致」**——一个夹带改 `integrity` 的 PR 会被 SBOM 忠实记录、却被当成正常构建。本锚把「上次人工拍板时锁文件长什么样」固化成哈希写进版本库，任何改动必在 diff 现形。判据口径是 **semantic 哈希**（`JSON.parse` → key 排序 → 紧凑序列化 → SHA-256）：**用原始字节哈希会在 CRLF/LF 间漂移**（开发机 Windows/CI ubuntu），后果不是「偶尔红」而是 **CI 恒假红**，而假红第一次出现就会被 `continue-on-error` 消化掉、等于没有门禁。覆盖面 2 份（后端 + `web-admin`；`zznpmtest/` 已 gitignore 故不纳入）。fail-closed：锁文件缺失/解析失败/锚缺失一律 exit 1
  - 门禁：`src/tests/deploy/lockfileAnchor.test.js` 11 例，真调脚本导出的纯函数（**不复刻判据**）；核心是「同一 JSON 的 CRLF 与 LF 版本必须同哈希」——把上述决定性实验固化成回归闸。篡改一处 `integrity` 实测 `exit=1` 且报错点名文件与期望/实际值
  - **如实声明边界**：本锚**不是 SBOM**，挡住的是「锁文件被改」，**挡不住「上游包本身被投毒且 lockfile/integrity 未变」**
- **P1-② 补：PII 轮换旧钥残留守卫**。`scripts/migrate-pii-encryption.js:48-53,106` 把 `PII_ROTATION_OLD_AES_KEY`（**旧主密钥明文**）作为 `--rotate` 的输入参数，但**没有任何地方要求轮换后清理它**——不在启动校验面、不在轮换手册收尾清单、不在脚本输出里。它是**过程残留物**而非运行时配置：一旦驻留生产环境，**轮换等于白做**（轮换的前提是「假定旧钥已泄露」，而旧钥 + 轮换前备份归档仍可解出当时全部 PII）。三处收口：① 启动期生产环境检测（并入 `config/immutableConfigGuard.js`，**告警 + `incSecurityAlert`，不阻断启动**——口径同 immutable 档位，它可恢复而阻断会让疏忽变成停机事故）；② 轮换手册收尾清单加一条；③ `--rotate --apply` 成功且无损坏行时脚本主动打印清理提示（运维跑完就在看这个输出，命中率最高）。空串/纯空白判为「无残留」（`.env` 写 `KEY=`、compose 传空值是常见 unset 等价物，判成残留会造成恒真误报）
  - 门禁：`immutableConfigGuard.test.js` 追加 10 例（含 **4 条反向断言**：无旧钥不得告警、非生产不得告警、空串不得告警、无残留不得顶掉既有告警）。**4 组变异全部被杀**（去掉生产条件 1 红 / 去掉空串判断 2 红 / 守卫恒真 6 红 / 去掉 `incSecurityAlert` 1 红）——反向断言不是摆设
  - 同时记录一处会咬人的内部行为（非缺陷）：`--rotate` 执行期间脚本把 `AES_SECRET_KEY` 临时指向**旧钥**（`:106`），结束后恢复；当前是独立 CLI 故风险低，但**勿把迁移逻辑内联进服务进程**，否则轮换窗口内服务会用旧钥加密新数据
- **测试基建：`ciGateWiring` 的门禁清单补防瘦身断言**。`CI_ENFORCED_GATE_SCRIPTS` 此前只有**正向**检查（登记了 → 必须被 CI 调用）。变异实测：删掉清单任一行，套件只是「少跑一条」，**13/13 依然全绿** ⇒ 清单可被静默删行、被删掉的门禁从此无人守护且无任何测试变红。补反向断言：从 workflow 文本抽出实际调用的 `scripts/*.js`，要求全部已登记或已进**显式豁免清单**（豁免附理由，如 `scripts/deploy.js` 是部署脚本、非判定类门禁）。用显式豁免而非放宽匹配，是为了让「为什么它不算门禁」这个判断本身可审计。变异验证：删登记行 ⇒ 1 条红

### 新增（2026-09-30）

- **口令复用历史**：此前 `changeUserPassword` 里只有 `SAME_PASSWORD`（"不能与**当前**口令相同"），A→B→A 这种两步复用完全放行；`helpers.validatePasswordStrength` 只覆盖长度/复杂度/泄露库，全仓零处检查复用。现 `User.passwordHistory` 保存最近 N 条（默认 5，`PASSWORD_HISTORY_DEPTH` 可调，上限 24）**已退役**口令的 HMAC-SHA256 摘要，改密时逐条比对并拒绝，写入被替换掉的旧口令。摘要用 HMAC 而非 bcrypt：历史条目的用途是**等值比较**（比较时明文就在手里），bcrypt 的"慢"是为离线爆破服务的，此处不适用，而代价很实在——rounds=12 下每条 250~300ms、保留 5 条即 1.5 秒且全部挂在改密端点上，而 `passwordChangeLimiter` 只按 user+ip 限到 5 次/15 分钟、**没有全局护栏**，N 个账号就能把 CPU 打满。沿用本仓已有的同类先例 `services/mfaService.hashRecoveryCode`（HMAC + pepper，未配密钥时退化 sha256）。新增错误码 `PASSWORD_REUSED_IN_HISTORY`（400），两个改密端点（`/api/auth/password` 与 `/api/security/change-password`）映射一致，文案里的 N 由后端 `params.historyDepth` 下发，前端不写死数字
  - 已知取舍（如实记录而非假装解决）：轮换 `HMAC_SECRET` 后既有摘要全部对不上 ⇒ 历史长度归零，轮换窗口内复用防线短暂变弱。审计链 HMAC 那套重签工具在这里**不适用**——没有明文就无法重算
  - 门禁：`src/tests/utils/passwordHistory.test.js` 20 例。除判定语义与 A→B→A 行为级用例外，另有**接线不变量**（`.select('+passwordHistory')`、成功后写历史、schema `select:false`、两个控制器 outcome 映射、错误码 4xx、前端登记）——语义测对了而没接线是这类修复最常见的落地失败形态，那时下面所有语义测试仍会全绿

### 变更（2026-09-30）

- **敏感 GET 读取审计判据反转：6 条允许清单 → 默认全量 + 显式豁免清单**（`middleware/security.js` 的 `auditGetPaths` → `auditGetExcludePaths`，收口审计报告 §3.4）。原判据是 fail-open：新增一条敏感 GET 路由而忘记登记即零留痕——设备/报警/巡检的**列表与详情**正是一批这样的盲区（P0 时的 HEAD 归一修复只救了已登记的 6 条前缀；列表与详情共用派生 action `*_view`，故无需新增 action 登记）。反转后 GET/HEAD 默认审计，豁免清单只剩两类、逐条写明理由：a) 预认证/登录流程面（captcha/captcha-status/login-public-key/mfa-status，无业务数据且调用频率由认证流程决定）；b) 纯自读面（session/me/sessions/my-info/bindings/my-logs——数据主体即请求者本人且被前端每次导航轮询，操作留痕由写路径承担：改密/MFA 变更/踢会话均为写方法照常审计）。fail-closed 的直接后果：未匹配路径的 GET 探测与匿名 401 也会在审计里留痕（与既有 `/api/users` 行为一致），审计记录量随读取流量上升属预期成本；运维看板若高频轮询设备/报警列表，按 security.js auditLog 头注口径逐条评估后加豁免，**不回退允许清单**。守卫同步：`auditActionReachability` 台账 A 类 25→9（16 条随反转为真实落库并从台账移除），解析器改读 `auditGetExcludePaths` 并反转判定
- **CC 防护升级：限流信号按类别分桶，阀值差 10 倍**（`src/services/rateLimitEscalation.js`，拆出 `rateLimitEscalationBan.js`）。此前全仓只有**一个**阀值（30 次/5 分钟），而喂进这个计数器的 7 个限流器**合法拒绝率相差两个数量级**——把「30 次 captcha 拒绝」与「30 次任意请求拒绝」当成同一种证据。实际后果是两条具体的误封：① `strict` 是**已认证**端点（refresh / MFA / 报表导出 / 审计导出 / 重置他人密码），一个管理员给 20 名新员工批量开户 = 60 次操作，**共享出口 IP 的整间办公室被封 1 小时**——而越界的是账号不是 IP；② `general`/`ip` 是体量信号，其配额在 NAT 共享出口下本就被多人分摊。现分三类各用各的阀值：`ANON_ABUSE`（captcha/login-ip/register，默认 10，封 IP）、`VOLUME`（general/ip，默认 **100**——原取 30 时这一档被误伤，100 才是它的量纲，封 IP）、`AUTH`（strict/user-ip，默认 30，**只告警不封 IP**，处置走账号侧）。混检不提前：10 次 captcha + 90 次 general 不会让 ANON_ABUSE 到点
- **固定窗口 → 令牌桶**（同上）。原实现的固定窗口有两个固有缺陷：**边界突发**（窗口末秒打满 N 次、次秒重开再打 N 次可取到 2N 速率）与**升级即清零**（达阈值后 `count = 0; windowStart = now`，封禁若恰好失败则下一轮又白拿一整个窗口）。令牌桶按 `阀值/窗口` 匀速回填，两个缺陷一并消除；持续速率恰好等于阀值的攻击者不再触发（等于预算本就不该被封）。代价是纯突发打满 N 次要第 N+1 次才封——这是去掉时序后门的代价，不是弱化
- **处置与通知解耦**（`src/services/rateLimitEscalationBan.js`）。原实现 `if (!shouldSendAlert(...)) return;` 把**审计与封禁一起挡在门外**：封禁失败（写库故障 / 命中白名单）时 5 分钟内的重试也被吞掉，而审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 档」。现审计与封禁无条件执行，只有 `dispatchNotification` 受频控约束
- **计数表淘汰：`clear()` → 压力升序有界淘汰**（同上）。`hits.clear()` 是一条**可主动触发的旁路**：攻击者轮换满额 IP 就能把所有人的计数归零。改为先清已回填的，仍满则牺牲「最接近升级」程度最低的条目。刻意**不按最旧优先**——那同样是旁路：被牺牲的会是积累已久、正要升级的那条，而攻击者新轮换进来的垃圾（压力 1）反倒留在表里。淘汰顺序必须由**安全价值**决定，不由时间决定
- **审计记全量构成**（同上）。原实现只把**触发阀值的那一个限流器**写进 `body.limiter`，于是「10 次 captcha + 20 次 general」被记成「general 触发」，事后复盘归因错误。现写 `body.mix`（各限流器计数）+ `body.total` + `body.className`
- 新增 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH` / `CC_ESCALATION_EVICT_RATIO` 五个环境变量（此前 `CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 已于本轮移除），`.env.example` 补全分类判据与推导依据

### 修复（2026-09-30）

- **immutable 档位（改配置需配套数据迁移）在启动期完全静默，运维改了配置直接重启无任何提示**（新增 `src/config/immutableConfigGuard.js` + `src/tests/config/immutableConfigGuard.test.js` 10 例）。`HMAC_SECRET` 在本仓有两个消费点：审计链 `hmac`（有 `scripts/resign-audit-hmac.js` 重签工具可迁移）与**口令复用历史摘要的 pepper**（`utils/passwordHistory.js`，**没有也不可能有配套工具**——历史里存的是 `HMAC(旧钥, 旧口令)` 的 hex，无明文无从重算）。`deployment/secret-rotation.md` 的「各密钥轮换影响面」表只写了前者，收尾清单也没提后者 ⇒ 运维照 Runbook 做完全量轮换，口令复用防线已归零而手册不吭声。现启动期推一条 warning（文案点名 pepper / 历史归零 / 无重签工具 / 指向手册），并计 `incSecurityAlert('password_history_pepper_rotation','medium')`——口径与 `ALLOW_LEGACY_CBC_DECRYPT` 的既有加固完全一致（"可检测 ≠ 已告警"）。**刻意不阻断启动**：该配置的合法取值本身包含"已知代价"那一档，要拦的是**静默**不是取舍。手册同步补该影响面小节、收尾清单条目，以及 `PASSWORD_HISTORY_DEPTH` **调小**（唯一不动密钥却同样让存量对不上的项，`sanitizeHistory` 读取侧截断）的说明。**实测变异验证**：把 immutable 的 push 塞进 CBC 的 `if` 块 ⇒ 2 条红；去掉 `incSecurityAlert` ⇒ 1 条红
- **安装脚本门禁的可证伪性为零（"测试复刻了一份判据"）**（`scripts/check-prod-install-scripts.js` / `src/tests/deploy/installScriptGate.test.js`）。该门禁是 Dockerfile 里 `npm ci --omit=dev --ignore-scripts` 安全性成立的**唯一依据**，而它初版的测试把判定语义**复刻**了一遍（自写 `classify`），注释还自称"可证伪"。**实测证伪**：把筛选条件 `omitDev ? !e.dev : e.dev` 写反（生产树与 dev 树颠倒 ⇒ 门禁退化成"永远失败"），复刻版测试 **6/6 全绿**。这是一类通用的失效形态——复刻一份判据等于测试了一个平行实现，与被测对象是否还正确无关。现脚本导出纯函数 `evaluate(lock, omitDev)` 并加 `require.main === module` 守卫，测试**真调**它；同一变异下 6 条变红。另：白名单按依赖树分两档（生产树命中即红 / dev 树逐个登记理由），判据改用 `package-lock.json` 的 `hasInstallScript` + `dev` 标记（实测 `npm ls --json` 的节点**不含 scripts 字段**，1317 节点 0 命中，故不能作判据来源）、白名单登记 `@scarf/scarf`（锁文件 `dev:false`，经 swagger-ui-express 传递引入生产树）与 `mongodb-memory-server` / `fsevents`
- **`npm ci --ignore-scripts` 的落点（CI 4 处 + Dockerfile 3 处，逐处给判据而非一刀切）**：`Dockerfile` 三处**全加**（builder 阶段从不跑测试、web-builder 与 runtime 均与 mongod 无关，且 runtime 那处由 `--omit=dev` 档门禁保证"没有脚本需要忽略"），`migrate-mongo` 补装命令一并加。CI 侧**刻意只给 e2e-browser 加**（其 Mongo 来自 `mongo:6.0.20` service 容器，不依赖 `mongodb-memory-server`）；`test` 与 `e2e` 作业**不加**——它们真的需要内存 Mongo 的 mongod 二进制，跳过安装脚本会把「安装期一次性下载」挪进 jest worker / 脚本进程，而本仓已有 `mongodb-memory-server` 子进程句柄与 jest 退出竞态的实证记录（`ci.yml` 的 `--forceExit` 头注）。判据：跳脚本不会让 `npm ci` 失败（`postinstallHelper.js` 失败路径是 `process.exit(0)`），代价是时序面，不是安装成败- **`checkBruteForce` 的通知频控挡在审计与封禁之前（与 CC 那条线同源，是同一轮修法的漏网）**。`securityAlert.js` 里两行 `shouldSendAlert`（账户维度 + IP 维度）排在阶梯统计 / 审计落库 / `addToBlacklist` **之前**，任一命中即 `return`，把三件事一起关在门外。后果不是少一条通知：① 封禁**失败**（白名单命中 / 黑名单写库故障）时 5 分钟内的重试被这行吞掉——而"封禁没生效"恰恰最需要重试；② 审计行是**阶梯的事件源**（`IPBanEvents.countPrior` 数的就是它），跳过审计 ⇒ 阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 次」。修法与 `rateLimitEscalationBan.js` 同一条纪律：**统计 / 审计 / 封禁无条件执行，频控只约束 `dispatchNotification`**。两个去重键保持内联（键里同时含 username 与归一化 IP）且短路语义逐字保留（`||`——任一维度放行即投递，改 `|` 会多消费一个 key 使抑制变强）。**实测变异验证**：把闸移回原位后 2 条用例红
- **`checkPermissionAbuse` 只告警、不封任何东西（唯一一处"跨层探测已认证权限边界"的哨兵没有遏制手段）**（新增 `src/services/securityAlertPermissionAbuse.js`）。该检测器此前整条路径只有「审计 + 通知」，另两个检测器都有封禁动作。缺口是：攻击者只要拿到一份**有效凭据**，把权限探测压到每 5 分钟 < 20 次，就能永久试探权限边界——每次都不达阈值 ⇒ 无告警、无审计、无遏制（20 次/5 分钟这条阈值只挡"不会隐藏自己的人"）。现达阈值时对**来源 IP** 走与暴力破解同一条渐进式封禁阶梯（1h→4h→24h→7d），事件源是独立的 `action=permission_abuse`（与 `brute_force_login` 分账，各数各的，只共用时长档位与 30 天窗口，新增 `IPBanEvents.countPermissionAbusePrior`）；无 IP 上下文时只告警不封（不得把 `undefined` 当 IP 封）。同样的处置/通知解耦、同样的"先读阶梯后写审计"、同样的按返回值分派（F-160 口径：`addToBlacklist` 从不抛错，白名单/写库失败时"已封禁"日志就是纸面防线撒谎）。处置侧整块抽到新文件是体积债收口（`securityAlert.js` 净代码行已贴 300 上限）。**实测变异验证**：跳过封禁后 3 条用例红
- **出站告警契约闸的两处能力缺口**（`src/tests/services/outboundAlertContract.test.js` / `fireAndForgetAlertSingleEntry.test.js`）：① 判据只认**裸** `ALERT_TYPES.X`，不认带模块前缀的 `securityAlert.ALERT_TYPES.X`——而后者语义完全等价且跨模块调用时必须用；`auditChainMonitor.js` 的调用点原是三表达式，拆成 if/else 后双闸齐红。现解析器接受可选前缀（键的真实性仍逐条校验）。② `sendNotification` 白名单未登记 `auditChainMonitor.js`（它是第二个 `await` 侧调用点，要拿投递结果做自己的记账），按该闸的设计意图显式登记。**注**：这两处是上一轮审计链守护闭环引入的欠账，非本轮新增缺陷
- **`backgroundJobs.test.js` 的频控断言钉的是被修掉的旧行为**：原断言「5 分钟频控窗口内第二次检测不再写审计」，正是上面第一条缺陷的形状。已改为「通知不重复，但**审计必须照写**」（`after === before + 1`）；另把 `securityAlertWriteFailureTolerance.test.js` 的"写入成功不打 error"反向对照显式桩掉封禁链路——该用例的命题是"审计写入成功"，不该被"这个 IP 恰好能不能被封"污染
- 门禁：新增 `src/tests/services/securityAlertContainmentDecoupling.test.js`（7 例：频控命中时审计/封禁照做、封禁失败后重试不被吞且阶梯升档、权限滥用必须真的封 IP、权限滥用阶梯独立分账、无 IP 不封、两条 `shouldSendAlert` 位置文本闸）

- **`auditChainMonitor.runVerification` 的函数体积债（101/100，上一轮的欠账）**：该文件是未跟踪新文件，不在棘轮基线里，于是它的 `max-lines-per-function` 超标要到下一次全量跑才暴露。把「告警投递」整块（`noticeData` 组装 + 按 `hasBreaks` 的 if/else 静态分派）抽成 `dispatchChainAlert`——拆函数正是本仓对体积债的既定处置。顺带把「档位/类型不得写成三元表达式」这条约束的注释挪进新函数，让它有独立的注释位而不容易被后来的重构顺手"简化"掉。行为逐字不变（`outboundAlertContract` / `fireAndForgetAlertSingleEntry` / `auditChainGuardedIntegrity` 三套件 31 例全绿）
- **补上一轮遗漏的 prettier 格式**（`auditChainMonitor.js` / `securityAlert.js` / `auditBufferFlushAndWalGuards.test.js` / `securityAlertContainmentDecoupling.test.js` 四文件）。`npm run format:check` 自那轮起就是红的

- **`web-admin/src/tests/build/` 被 `.gitignore` 的 `build/` 规则吞掉，一份正牌回归测试从未进过 CI**。该目录下是 `manualChunks.test.js`（P2-52 回归，4 例，直接 `import` 真实 `vite.config.js` 调 `manualChunks`，注释里记着实测更正与反证记录）。`.gitignore:46` 的 `build/` 是为构建产物加的，而它**无前导斜杠 ⇒ 匹配任意层级的 `build` 目录**，于是测试目录被一起吃掉。后果是它在本地跑、在 CI 上根本不存在（本地前端 1431 例含它，CI 从未执行）。已把目录改名为 `web-admin/src/tests/bundling/`（不改 `.gitignore`：`build/` 规则本身有其必要，不该为一个测试目录放宽）
- **门禁：测试树纯净性**（新增 `src/tests/ci/testTreePurity.test.js` 5 例）。`testMatch` 是「任意层级下的 `src/tests/` 里的 `*.test.js`」，因此放在那里的**任何** `.test.js` 都会被执行——包括从未提交、只是调试时落下的草稿。这类失效形态是"不出错、只污染信号"：草稿的 pass/fail 混进总数，而**本该入库**的用例一旦漏 `git add` 则是本地全绿、CI 上压根不存在。两条方向相反的判据：未跟踪 ⇒ 报红（给出"入库或挪出"两条出路）；已跟踪的 `zzz-*.test.js` ⇒ 报红（`.gitignore` 只约束未入库，管不住 `git add .`，而当初那批 8 个探针 / 591 行 / 51 test / 0 expect 正是这么进去的）。判据用 `!tracked.has(f)` 而非 `ls-files --others --exclude-standard`：**被 gitignore 误伤的文件正是本条门禁上线当天抓到的第一个案例**，用 `--exclude-standard` 它会隐身
- **补上 `d72872c` 漏同步的两处断言**（`auditQuerySharedBuilder.test.js` / `auditQueryFindAggregateParity.test.js`）：该提交把 username 前缀查询的上界从「末字符码点 +1」改为追加 collation 哨兵 `U+FFFF`（ICU 排序下前者对 `z`/`Z`/`9` 等末字符构成**空区间**），并同步了 `auditUsernamePrefixIndex.test.js` 的契约，却漏掉了另两处同样断言该 helper 输出形状的用例 ⇒ HEAD 上稳定 2 红。断言已改为钉哨兵形状；哨兵在 collation 下确实恒大于任何 `prefix + <已分配字符>` 仍由 `auditUsernamePrefixIndex.test.js` 的 DB 回归用例负责，不在此处重复造一个纸面断言

- **`req.query` 物化：Express 5 下 query 注入防线此前靠注释撑着**（新增 `middleware/security.js` 的 `materializeQuery`）。`req.query` 是原型上的 getter（`express/lib/request.js: defineGetter(req, 'query', ...)`），每次访问重新解析 URL，于是 `sanitizeMongo` 与 `hpp` 对 query 的原地清洗是**彻底空操作**——实测（Express 5.2.1 + supertest）`delete req.query.search` 之后**同一 handler 同一 tick** 内回读 `Object.keys(req.query)` 仍带 `search`，比 P1-33 记录的"下次访问才丢"更彻底。现改为读一次 → 复用 `deepSanitizeKeys` 清洗 → `Object.defineProperty` 物化成自有数据属性 → **回读自证身份，不等即拒绝请求并 error 级留痕**（物化失效是零报错事件，"服务不可用"远好过带着未清洗的 query 继续服务）。附带收益：解析次数从"每个消费者一次"降到全请求一次。`sanitizeMongo` 已移除对 `req.query` 的遍历——留着只会让人误以为 query 有两道防线
- **静态面限流判据单一来源 + 补上零预算**（`middleware/staticFrontend.js` / `rateLimit.js`）。此前限流侧判据是"安全方法 + 非 `/api/` 前缀"，与 `staticFrontend` 的 `RESERVED_PREFIXES` 是两份独立清单，实测对 11 条非 `/api` 路径有 **8 条判定相反**。逐条核对后真正裸奔的两条：`/socket.io/`（Socket.IO HTTP long-polling 握手是未认证 GET，而 `MAX_CONNECTIONS=1000` 约束的是**已建立连接数**、`authenticateSocket` 在连接建立之后才跑 ⇒ 握手面应用层零限流）与 `/metrics`（`metricsAuth` 允许内网免令牌，而 `app.js` 自陈的威胁模型正是"容器网络内直连 app:3000"）。判据现由 `isStaticSurfaceRequest` 单一来源提供，豁免集合**收窄**（新登记的保留前缀自动重新纳入限流，限流侧无需改动）。另新增 `staticSurfaceLimiter`：静态面此前被整体豁免，而豁免的代价是**零预算**（单 IP 可无限拉 `/assets/*`）；现按"按成本分桶"给它自己的宽松桶（12000 次/15 分钟，按 34 静态请求/页 × 30 人 NAT × 10 次页面加载 = 10200 留 18% 余量推导），429 文案与通用限流刻意区分，且**不接入 CC 封禁升级阶梯**（静态面被限流多为出口聚合，接上去会把误封从单个 IP 放大到整个办公室）
- **门禁：把"注释级约定"变成可执行不变量**（新增 `src/tests/app/queryDefenseSingleSource.test.js` 11 例、`staticSurfaceRateLimitGate.test.js` 17 例）。前者刻意跑在**真实 express 实例 + supertest** 上并含一条**反向对照**（未物化时 `req.query` 确实不是自有属性、确实跨读取不稳定）——因为既有那组 `sanitizeMongo` 单测用的是手搓 `req` 桩，桩上的 `query` 是普通属性，**结构上不可能**发现 Express 5 的 getter 前提；本次同时把该单测里断言 `query: 10` 的那条改成如实反映"query 不再经过 sanitizeMongo"。后者钉住判据单一来源、8 条分歧路径逐条归属、大小写同尺、以及静态面不再是零预算
- ~~**CC 升级封禁阈值 100 → 30，并新增预警档**~~ —— **本条已被上方「变更」段的分类分桶方案取代，保留在此仅说明演进过程**：单一阀值（无论 100 还是 30）的问题不在数值，而在它把 7 个合法拒绝率相差两个数量级的限流器加进了同一个桶；`CC_ESCALATION_THRESHOLD` 与 `CC_ESCALATION_WARNING_THRESHOLD` 两个变量均已移除，改为按类别的 `CC_ESCALATION_THRESHOLD_ANON` / `_VOLUME` / `_AUTH`。原判断里成立的部分（`generalLimiter` 触顶后窗口内每条请求都是 429、真攻击 5 分钟可刷出数千次）已被吸收进 `ANON_ABUSE` 的推导

- **`package.json` 的 `engines.node` 与前端实际要求对齐**：`>=18` 与 `web-admin` 的 Vite 8.1.4（`engines.node: ^20.19.0 || >=22.12.0`）冲突——声明允许的 Node 18 上 `npm ci` 能装完依赖，但 `npm run build` 结构性失败。改为 `^20.19.0 || >=22.12.0`，与 CI 的 `[20.x, 22.x]` 矩阵、前端 job 的 `24.x`、Dockerfile 的 `node:22.14.0-alpine` 落在同一条区间上
- **`.dockerignore` 补齐被漏掉的构建上下文**：Docker 的忽略模式只从上下文根起算，bare `coverage` **不匹配** `web-admin/coverage`（与本文件必须写全 `web-admin/node_modules` / `web-admin/dist` 是同一条语义），而 `web-builder` 阶段是 `COPY web-admin/ ./` ⇒ 3.2 MB 前端覆盖率报告与 4 个 `coverage-zz*` 残留目录一直进构建上下文与镜像层。同时补 `web-admin/.mimosa`、`.mimosa`、`.jesttmp`（本机 82 MB）、`playwright-report`（9.5 MB）、`test-results`、`.lint-ratchet-selftest-*`、`zztmpctl`/`zznpmtest`（含自带 `node_modules` ~93 MB）与 `.admin-initial-password`（当前超管明文口令，59 字节）。后几项目前因 Dockerfile 走 `COPY` 白名单路径而未泄漏，但任何将来新增的宽泛 `COPY .` 都会一次性引爆

### 新增（2026-09-28）

- **IP 归属地展示（离线零依赖）**：会话管理、审计日志列表、IP 黑白名单等后台界面把裸 IP 翻译为「国家·省·市·运营商」。数据采用 ip2region 官方 xdb（Apache-2.0）入库 `src/data/`（约 11MB，Docker `COPY src/` 一并带入镜像），检索器 `src/utils/ip2regionSearcher.js` 以纯 Node 实现 xdb v2 格式（向量索引 + 二分，全内存约微秒级/次），不引入任何 npm 依赖；`src/services/ipLocationService.js` 负责业务口径（复用 `ipUtils.normalizeIP` 收敛 `::ffff:` 形态、内网/保留地址统一标「内网」含 IPv6 回环/链路本地/ULA、结果 FIFO 缓存 2048 条、任何异常 fail-soft 返回 null）。`GET /api/auth/sessions` 每条会话新增 `location`（最近活跃 IP）与 `loginLocation`（登录 IP）；审计日志两条分页路径与 IP 名单列表逐行补 `location`；前端在 IP 旁以 `·` 拼接展示（后端缺字段/CIDR 网段自动省略）。数据刷新：`node scripts/update-ip2region.js`（Gitee→GitHub→jsDelivr→npm 镜像四级数据源 + 结构校验 + 探针查询 + 原子替换），`--check` 只打印当前数据构建日期
- **CC 防护升级闭环**（`src/services/rateLimitEscalation.js`）：限流从「只挡不罚」变为「可观测 + 可升级」——每次 429 上报 `security_alerts_total{type=rate_limit_triggered}`；同一 IP 在 5 分钟窗口内触顶达阈值（`CC_ESCALATION_THRESHOLD` / `CC_ESCALATION_WINDOW_MS` 可调，**2026-09-30 起已重构为按类别分桶（见上方「变更」段：单一阀值与预警档均已移除）**）即按与暴力破解同一条封禁阶梯（1h→4h→24h→7d，30 天审计事件计数升档）自动封禁。防误封设计：白名单 IP 的资源型限流直接 skip 不会产生升级信号；凭据型账号维度桶不接入（无 IP 可封）；升级链路全程 fail-soft 不拖垮 429 响应。计数为进程内固定窗口（多实例下按实例数摊薄，少封不误封）
- 数据文件入库配套：`check-utf8` 门禁的常见二进制扩展名清单加入 `.xdb`，`.gitattributes` 钉 `*.xdb binary`

### 变更（2026-09-28）

- **限流键统一 IP 归一化**（总账 §4.4「限流键直接拼原文 req.ip」收口）：全部 IP 维度限流器（general/strict/login/ip/user 未认证分支/captcha/register/pwd-change/reauth 及 wellKnown 三个上报限流器）的键改走 `normalizeRateLimitIp`（与名单侧同一把 `ipUtils.normalizeIP`），消除 `::ffff:1.2.3.4` 与 `1.2.3.4` 双桶导致的「同一来源配额翻倍」；歧义写法回退原文自成桶，fail-closed 语义不变。`ipLimiter` 补显式 handler（响应体与原 message 逐字一致，差异仅多升级信号上报）
- **暴力破解自动封禁判据只看 IP 维度**（总账 R-H2）：`checkBruteForce` 此前以 `max(userFailures, ipFailures)` 达标即封禁**当前请求 IP**——分布式撞单账号时把可能只贡献了 1 次失败的 IP（NAT 出口后的无辜用户/受害者本人）封 1 小时。现改为告警与审计照发（双维度都是真实攻击信号，审计 body 含双维度计数），封禁仅在 `ipFailures` 达阈值时执行
- **wellKnownRoutes 三个限流器接入共享存储**（总账 P-9）：`/csp-report`、`/client-errors`、`/.well-known/security.txt` 的限流计数从每实例独立 MemoryStore 改为 `makeSharedStore`（无 Redis 时行为不变），多副本部署下攻击者不再能对每个副本各刷满一份配额

### 测试基线

- 后端：477 个套件 / 4583 个用例文件（2026-09-30 按文件数与 `test()/it()` 声明数实测；此前记的「130 套件 / 1736 例」与 `jest.config.js` 注释里的「280 套 / 3300+ 例」均已失真一个台阶）
- 覆盖率阈值：全局 br 79 / fn 87 / ln 91 / st 91，另 36 个安全关键文件单独设阈；**不复写实时覆盖率数值**——要当前数字看 `npm run test:coverage` 的输出，写死即立刻失真

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
