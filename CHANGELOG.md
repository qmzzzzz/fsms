# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

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
