# 更新日志（CHANGELOG）

本文件记录「消防安全管理系统（Fire Safety RBAC System）」各版本的变更。

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 维护约定：每次合并功能性变更时同步更新 `[未发布]` 段落；发版时将其重命名为对应版本号与日期。

## [未发布]

### 修复（2026-09-30 · 安全缺口核查落地）

- **敏感 GET 读取审计判据反转（P1-④）+ PII at-rest 加密（P1-②）+ 备份加密（P1-①）等七项缺口收口**（对照 `deliverables/安全缺口核查-2026-09-30.md`，其中 P1-④ 与 P2-⑥ 已于本日早先提交落地）：
  - **P2-⑧ 传输加密启动断言**：生产环境 Mongo 非回环主机必须 `tls=true`、Redis 必须 `rediss:`，豁免走显式旗标 `MONGODB_TLS_EXEMPT`/`REDIS_TLS_EXEMPT`（同宿主 compose 即豁免使用者，拆分拓扑忘摘旗标会被启动期拦截）；判据收口 `config/transportSecurity.js`（回环判定吃 127.0.0.1/::1/IPv4-mapped/localhost 全形态；hostname 解析不出保持沉默——compose 契约测试的替身 URI 不被误杀）
  - **P2-⑨ 出站目标门禁**：`LOG_SHIPPING_URL` 在 scheme 白名单之外再拒内网/回环/链路本地目标（云元数据端点是经典 SSRF 目标）；歧义 IPv4 形态（127.1/2130706433/0x7f.0.0.1，严格解析判 null 但 OS 仍按回环连）一并拒绝；内网 SIEM 用 `LOG_SHIPPING_ALLOW_PRIVATE_HOSTS` 显式放行（主机名/IP/CIDR，与 IP 名单同一把尺）。判据 `isPrivateOrLoopback` 自 metricsAuth 迁入 `utils/ipUtils.js` 单一来源（middleware→utils 反向依赖会破分层）
  - **P1-① 备份加密 + 校验和 + 异地副本**：`backup-mongo.sh` 默认 gpg 非对称加密（备份宿主机只放公钥，私钥托管异地），明文出口 `BACKUP_ENCRYPTION=plaintext-acknowledged`（取值即确认词）；产物三件套 .gz.gpg + .sha256 + `BACKUP_OFFSITE_CMD` 异地钩子（argv 解析不经 shell 展开、失败即整体失败）；`restore-mongo.sh` 按后缀自动解密；加密/解密/校验和收口 `scripts/backupCrypto.sh`（与 mongoUri.sh 同一共享范式）；恢复演练与密钥托管见 `deployment/backup-encryption.md`
  - **P1-② PII at-rest 加密**：realName/phone 走随机 IV AES-256-GCM（`utils/piiCrypto.js`，密文带 `enc.v1` 版本前缀供轮换），精确检索走 HMAC 检索键 `realNameKey`/`phoneKey`（select:false + 索引）——相等性不泄漏在密文列里；存量明文**读路径透传**（迁移前的旧行照常可读），写侧 `pre('validate')` 钩子加密（长度/手机号格式校验随钩子前移到明文阶段，错误文案逐字不变）；迁移/轮换脚本 `scripts/migrate-pii-encryption.js`（演练/apply 双模，损坏行点名不覆盖，同族 allowlist 门禁）。**能力回归如实申报**：用户列表按姓名片段模糊搜索不再命中（正则对密文不成立），改为全名精确匹配
  - **P2-⑩ 供应链可追溯**：CI 构建产出 CycloneDX SBOM 并上传 artifact；镜像 `provenance: true` + cosign keyless 签名（build 作业补 `id-token: write`）
  - **P2-⑫ 依赖钉版**：`.npmrc` `save-exact=true` 从源头杜绝 caret 漂移；新增 CI 硬门禁「生产依赖树禁止任何 install 脚本」（`scripts/check-prod-install-scripts.js`，fail-closed + 显式白名单——比 --ignore-scripts 更强：ignore-scripts 只让本机跳过，树里有没有脚本没人看）
  - **P3-⑬⑭⑮ 治理文档三份**：`docs/threat-model.md`（STRIDE + 残余风险如实申报）、`docs/incident-response.md`（角色/时限/命令级遏制清单，全部绑定本系统实际存在的端点与脚本）、`docs/mlps2-controls.md`（等保 2.0 第三级重点项对照，每条挂文件/测试/端点证据）
  - 门禁：`transportTlsAssertion`（9 例）/ `backupEncryptionContract`（stub gpg 行为链）/ `piiEncryption`（纯判据 + 真实 Mongo 接线，9 例）/ logShipper 出站目标真值表（27 例）等新增约 60 例；既有 backupTransport/backupScriptGuards 夹具显式声明明文确认出口，保持其原断言对象不变

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
