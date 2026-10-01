# 密钥轮换操作手册（R-1）

配套脚本：`scripts/generate-secrets.js`（全套密钥一次性生成）、
`scripts/migrate-mfa-secret.js`（AES）、`scripts/resign-audit-hmac.js`（HMAC）。
密钥载体：本地开发用 `.env`；生产容器用 `secrets/` 文件 + `*_FILE` 注入
（机制见 `src/config/secrets.js`，`docker-compose.yml` 已按此配置）。

生成器用法（默认只打印，不落盘；`--out` 写文件且默认不覆盖）：

```bash
node scripts/generate-secrets.js --out ./secrets-new        # 生产：写入 0600 文件
node scripts/generate-secrets.js --env-snippet              # 本地：打印 .env 片段
```

## 各密钥轮换影响面

| 密钥                   | 轮换影响                                    | 是否需要数据迁移           |
| ---------------------- | ------------------------------------------- | -------------------------- |
| JWT_SECRET             | 全部访问令牌立即失效，用户重新登录          | 否                         |
| JWT_REFRESH_SECRET     | 全部刷新令牌失效，会话需重建                | 否                         |
| AES_SECRET_KEY         | **存量 mfaSecret 无法解密，MFA 登录恒失败** | 是（先迁移后换钥）         |
| HMAC_SECRET            | 存量审计记录 hmac 校验失配                  | 是（用新钥重签，无需旧钥） |
| LOGIN_ECDH_PRIVATE_KEY | 无：前端每次登录重新获取公钥                | 否                         |
| MONGODB_URI / 口令     | 需同步改 Mongo 账户，属数据库运维动作       | 不适用                     |

### ⚠️ HMAC_SECRET 的四重影响：请按这张表读，不要按小节读

上表 HMAC_SECRET 一行只写了审计链。**`HMAC_SECRET` 在本仓有四个消费点**，
其中只有第 1 个有迁移工具——另外三个换钥后**静默失效**：

| #   | 消费点（路径按仓库根写全，行号会漂移、判据是文件） | 用途                      | 轮换后                 | 迁移手段                                  |
| --- | -------------------------------------------------- | ------------------------- | ---------------------- | ----------------------------------------- |
| 1   | `src/utils/auditChain.js:64`                       | 审计记录 `hmac` 字段      | 存量记录 hmac 全部失配 | ✅ `scripts/resign-audit-hmac.js`（重签） |
| 2   | `src/utils/passwordHistory.js:64`                  | 口令复用历史摘要的 pepper | 历史长度归零           | ❌ 无（没有明文就无法重算）               |
| 3   | `src/services/mfaService.js:29`                    | **备用恢复码**的 pepper   | **全部恢复码失效**     | ❌ 无                                     |
| 4   | `src/utils/encryption.js:189`                      | `HMACSigner` 数据签名密钥 | 存量签名全部失配       | ❌ 无                                     |

> **这张表是单一来源**：`src/tests/config/hmacSecretConsumersSingleSource.test.js`
> 会扫描 `src/`（排除测试与配置装载面）下所有 `HMAC_SECRET` / `hmacSecret` 的消费点，
> 与上表逐项比对——**新增消费点而不更新本表，该用例变红**。
> 之所以钉这一条：本表曾长期只写「两个消费点」，而第 3、4 点在**同一份仓库**里
> 分别被 `AGENT工作总账与待办` 的 F-26 记成「三个」——三份清单各写各的，
> 谁也没覆盖全。清单漂移的代价是运维按表轮换，以为自己收口了。

#### 第 2 点：口令复用历史（无迁移手段）

第 2 点在轮换后**没有配套工具，也不可能有**：历史里存的是
`HMAC-SHA256(HMAC_SECRET, 旧口令)` 的 hex，**没有明文**就无从重算——
`resign-audit-hmac.js` 那套（重签 `hmac = HMAC(新钥, hash)`）在这里不适用，
因为审计链的 hmac 只覆盖 `hash` 这一列、与新钥无关，而口令历史的摘要与旧钥强绑定。

**后果**：换钥后既有摘要一条都对不上，历史长度静默归零，用户在轮换后可复用
前 `PASSWORD_HISTORY_DEPTH` 条旧口令各一次，之后重新积累。

**这是已知取舍**（`utils/passwordHistory.js:30-34` 有完整记录），但取舍的**代价**
与**窗口**必须在轮换时被知悉，而不是靠读源码发现。启动期已配套告警：
`config/immutableConfigGuard.js` 在每次启动时输出一条 warning
（同时计 `incSecurityAlert('password_history_pepper_rotation', 'medium')`），
只要 `PASSWORD_HISTORY_DEPTH > 0` 就会推——运维看到这条就知道自己撞上了哪个窗口。

**轮换时的操作**：本轮换不阻断、无需额外步骤；只需知悉窗口并就近择时
（口令复用防线最弱的那段时间，建议避开与「口令泄露应急重置」重叠）。
若这条告警出现在**非轮换窗口**的启动日志里，说明存在未同步的密钥副本，需立即排查
（同下文「L-01 验证步骤」第 ②/④ 条的口径）。

#### 第 3 点：备用恢复码（故障只在最坏时刻暴露）

`services/mfaService.js:29` 用 `HMAC_SECRET` 作 pepper 对恢复码做摘要
（恢复码熵约 39.6 bit，pepper 是它唯一的离线穷举防线，见该文件注释）。

**换钥后所有恢复码静默失效**，而恢复码是用户丢掉认证器时的**唯一逃生门**——
故障不会在轮换当天暴露，而是在某个用户手机丢了、进不了门的那一天暴露，
且此时运维早已忘记当天换过钥。与第 2 点同因（无明文可重算）⇒ 同样无迁移手段。

**轮换时的操作**：本轮换不阻断。若轮换窗口内已有用户持有恢复码，
建议在轮换后主动提示「恢复码已重置，请重新生成」——**本仓目前没有这条提示，
也没有使存量恢复码失效的批处理**（`scripts/` 下与恢复码相关的脚本为零，
只有 `resign-audit-hmac.js` / `resign-audit-chain-v3.js` 两支，都只服务第 1 点）。

#### 第 4 点：HMACSigner 数据签名密钥

`utils/encryption.js:189` 的 `HMACSigner` 在未显式传 `secretKey` 时回落到
`process.env.HMAC_SECRET || config.hmacSecret`（生产缺钥直接抛，不会退化为可预测值）。

换钥后**存量签名全部失配**：验签侧若拿新旧混合的密钥集比对，会表现为
「原本有效的签名突然判为伪造」。排查方向容易走偏（先怀疑数据被篡改），
故在此点名：**先确认轮换时间点，再判篡改**。

## AES_SECRET_KEY 轮换（必须先迁数据）

```bash
# 0. 生成新密钥（不要直接覆盖旧文件）
openssl rand -hex 32   # 记下输出作为 <新KEY>

# 1. 停应用（避免迁移期间新数据用旧钥写入）
docker compose stop app        # 或 kill 本地进程

# 2. 演练 → 执行迁移
node scripts/migrate-mfa-secret.js --new-key <新KEY>
#    --apply 是破坏性写：必须显式给出目标库白名单，否则 destructiveGuard 以 exitCode=2 拒绝
#    （防止将演练/迁移误指向非预期库）。本文件所有 `--apply` 同理，不再逐处重复注释。
ALLOWED_SOURCE_DB=<库名> node scripts/migrate-mfa-secret.js --new-key <新KEY> --apply

# 3. 换钥
#    本地开发：更新 .env 的 AES_SECRET_KEY
#    容器：更新宿主机 ./secrets/aes_secret_key（chmod 600）
printf '%s' '<新KEY>' > ./secrets/aes_secret_key

# 4. 启动并验证：任一已开启 MFA 的账户走一遍 登录→输入动态码
docker compose up -d app
```

失败处理：脚本对每条记录做新钥回读校验，任何一条失败都会拒绝写入并以非零码退出；
此时**不要换钥**，按报告中的账户清单人工处理（通常是数据损坏，需重置该账户 MFA）。

## HMAC_SECRET 轮换（审计链重签）

```bash
# 0. 轮换前先留档当前链条状态（证明轮换时点前链条干净）
node scripts/verify-audit-chain.js > audit-chain-before-rotation.log

# 1. 停应用
docker compose stop app

# 2. 生成新密钥并重签（演练 → 执行）
NEW=$(openssl rand -hex 32)
node scripts/resign-audit-hmac.js --new-key "$NEW"
ALLOWED_SOURCE_DB=<库名> node scripts/resign-audit-hmac.js --new-key "$NEW" --apply --yes

# 3. 换钥并启动
printf '%s' "$NEW" > ./secrets/hmac_secret
docker compose up -d app

# 4. 复核（预期零 hmac 失配）
node scripts/verify-audit-chain.js
echo "退出码 $?"
```

> 退出码含义（F-41 起）：**0** = 全量校验、无断裂、且 hmac 层确实参与；
> **1** = 发现断裂/失配；**2** = 校验不完整，**不能当作"链是好的"**——
> 常见原因是命中 `--limit`/`maxRecords` 上限（只覆盖了窗口）或该环境未配置
> `HMAC_SECRET`（此时只有无密钥 SHA-256 在跑，拿到 DB 写权限者可整条链重算）。
> 确要在无 hmac 的环境跑，显式加 `--allow-no-hmac`（知情放行，而不是默认绿）；
> 该开关**不会**豁免"没验完"这一条。本步骤要求的是 0。

## JWT 双密钥轮换

直接替换 `secrets/jwt_secret` 与 `secrets/jwt_refresh_secret` 并重启即可：
所有存量令牌失效、用户重新登录，无数据迁移。建议选低峰期执行；
`tokenVersion`/黑名单机制不受影响（黑名单存的是 tokenHash，令牌失效后自然过期）。

## 收尾检查清单

- [ ] 旧密钥密封留档（离线保管，确认无回滚需要后再销毁）
- [ ] `docker compose config` 输出与 CI 日志中不再出现任何密钥明文
- [ ] `npm run validate`（config/validate.js）通过
- [ ] 抽查日志无「MFA 种子解密失败」「hmac 失配」告警
- [ ] 启动日志中出现过 `password_history_pepper_rotation` 告警（HMAC 轮换的**预期**
      副作用，见上文「HMAC_SECRET 的四重影响」）——**换完钥的首次启动若没有它，
      说明告警链路失效或 `PASSWORD_HISTORY_DEPTH=0`，需人工确认**
- [ ] **PII 轮换后必须 unset `PII_ROTATION_OLD_AES_KEY`**（见下节），
      且启动日志**不得**再出现 `pii_rotation_old_key_lingering` 告警
- [ ] 启动日志出现 `pii_v1_rows_unmigrated` 告警时（见下节），
      确认 `enc.v1.` 存量行已迁移完——**该告警目前不会自行消失**（它跟随 v1 读支持的
      存在而存在），所以"每次都看到它"是正常的；要判"迁完了没"**必须看脚本演练输出**，
      不能看告警有没有

### PII 轮换旧钥必须移除（不做等于轮换白做）

`scripts/migrate-pii-encryption.js --rotate` 需要 `PII_ROTATION_OLD_AES_KEY=<轮换前的
AES_SECRET_KEY>` 作为**输入参数**——它是轮换过程的中间态，不是运行时配置。

**它一旦驻留生产环境，轮换这件事等于没做**：轮换的全部意义是"假定旧钥已泄露"，
而旧钥 + 轮换前的备份归档仍能解出当时全部 PII。把已泄露的东西在生产环境变量里
再挂一个可读副本，等于把风险窗口从"轮换那一刻"延长到"永远"。

- **检测**：生产环境（`NODE_ENV=production`）启动时若该变量存在且非空，
  `src/config/immutableConfigGuard.js` 会推一条 `pii_rotation_old_key_lingering`
  告警并计入 `incSecurityAlert`（口径同 immutable 档位：**告警不阻断启动**——
  它可恢复，unset 后重启即可，阻断会让一次疏忽变成停机事故）。
- **脚本自提示**：`--apply --yes --rotate` 成功且无损坏行时，脚本会在报告末尾
  主动打印清理提醒。
- **处置**：`unset PII_ROTATION_OLD_AES_KEY`（容器：从 compose 环境块 / secrets 挂载
  中移除）→ 重启 → 确认启动日志无该告警。
- **注意**：开发机与 CI 保留该变量做演练是正常的，故守卫**只在生产环境生效**。

> 另需知悉（`migrate-pii-encryption.js` 的内部行为，不是缺陷但会咬人）：
> `--rotate` 执行期间，脚本会把 `AES_SECRET_KEY` **临时改写为旧钥**
> （`:106`，为了在旧钥下解密），结束后恢复。因此**该进程内 `AES_SECRET_KEY`
> 指向的是旧钥**。当前脚本是独立 CLI、不加载应用，实际风险低；
> 但**不要把迁移逻辑内联进服务进程**，否则轮换窗口内服务会用旧钥加密新数据。

### PII v1 存量行必须迁完（v1 密文无行绑定）

**这不是"轮换"引入的问题，而是"写侧切 v2"引入的存量缺口**，但它与轮换共用同一套迁移管道，
故一并记在这里。

2026-10-01 把 PII 写侧切到 **v2**（`enc.v2.`，AAD 绑定 `pii:v2:<_id>:phone`）：跨行复制
密文会在 GCM 认证标签处失败。但读侧**刻意保留了 v1 兼容**（存量行不必先跑迁移就能继续读），
代价是 **v1 密文与行身份无关**——同一把派生钥下，把 A 行的 `enc.v1.…` 复制到 B 行，
B 行的 getter（`models/User.js:105-106`）会正常解出 A 的明文。

**攻击者模型**：只要持有 DB 写权限（本仓威胁模型自认的"内部人"档位），
一次写操作即可把任意用户的手机号明文兑换出来。写侧不会再产 v1，
**但存量 v1 行不会被自动升级**——迁移脚本跑完之前，这条通道一直开着。

- **检测**：生产环境（`NODE_ENV=production`）且 PII 加密确实在用（主密钥可用）时，
  `src/config/immutableConfigGuard.js` 推一条 `pii_v1_rows_unmigrated` 告警并计入
  `incSecurityAlert`（口径同 immutable 档位：**告警不阻断启动**）。
- **已知边界（必须知道，否则会被这条告警误导）**：该告警的判据是"代码仍支持读 v1"，
  **不是"库里还有 v1 行"**——启动路径上不连库（`config/validate.js` 在 mongoose 连接之前
  执行），所以它**不会自行消失**。要判"迁完了没"只有一条路：
  `node scripts/migrate-pii-encryption.js`（演练模式，只读）看剩余行数。
- **处置**：`ALLOWED_SOURCE_DB=<库名> node scripts/migrate-pii-encryption.js --apply --yes`
  （先把演练输出留档，它同时给出待加密 / 已加密 / 损坏三档计数）。
- **注意**：开发机与 CI 的库里有 v1 行是正常的（夹具由 `encryptPii` 不带 AAD 上下文产生），
  故守卫**只在生产环境生效**。

> **待拍板**：更彻底的做法是把 v1 读路径也改成 fail-closed
> （镜像 `ALLOW_LEGACY_CBC_DECRYPT` 的形态：缺 `ALLOW_PII_V1_DECRYPT=true` 即抛），
> 那样"库里有 v1 行"会当场变成响亮的读错误，而不是只靠一条可被忽略的启动告警。
> 未落地是因为它是**生产行为变更**（升级即可能让存量行读失败），
> 按本仓纪律属"需人拍板"那一档。

### PASSWORD_HISTORY_DEPTH 调小（无需轮换密钥）

单独列出：这是**唯一**不需要动任何密钥、却同样让存量数据「对不上」的配置项。

`utils/passwordHistory.js:86-98` 的 `sanitizeHistory` 在**读取侧**按当前
`HISTORY_DEPTH` 截断——把 `PASSWORD_HISTORY_DEPTH` 从 10 调到 5，库里每人的
10 条历史立刻只剩前 5 条，**被截掉的那 5 条不会被删除，但也不再参与比较**：
用户可以用第 6~10 条里的任意一条改密成功。

- 取值区间：读入后夹到 `[1, 24]`（上限防误配成 1000 后单文档膨胀）；
  非正整数走 `readPositiveNumberEnv` 的 `onInvalid` 回调，**只打 error 日志**后按默认 5 处理。
- **调小时**：属产品决策，无技术阻断。请知悉窗口并按需记录。
- **调大时**：安全侧只会更严，无需操作（但库里的历史条数不会追溯补全，
  即"调到 10"只对**此后**的改密生效，存量用户仍是 5 条）。
- 该配置**不在**启动期告警范围内（它是纯运维口径，且
  `collectInvariantWarnings` 只在 pepper 相关组合下推文案）——
  判断依据：调小它有真实业务动机（减少单文档体积），
  而 pepper 轮换通常不是有意为之，两者的告警价值不同。

### L-01 验证步骤（单一事实来源）

轮换后**必须**逐条确认新旧值没有并存，否则会出现「只轮换一处、旧密钥仍有效」的静默失效：

```bash
# ① 旧令牌必须立即失效（JWT_SECRET 轮换的判据）
curl -s -o /dev/null -w '%{http_code}\n' -H "Cookie: accessToken=<轮换前签发的令牌>" \
  http://127.0.0.1:3000/api/auth/me      # 预期 401

# ② 启动日志不得出现「同时配置且取值不同」告警
#    （src/config/secrets.js:86-91 会在 NAME 与 NAME_FILE 并存且取值不同时告警；
#     该告警出现即说明存在多副本，必须清理后再轮换）

# ③ 生产 secrets/ 目录权限（Linux）
stat -c '%a' ./secrets/jwt_secret        # 预期 600
# ③' Windows 主机改用：
#   icacls "secrets"                       # 不应出现 BUILTIN\Users / Authenticated Users

# ④ 确认不存在第二份取值不同的副本：列出两处载体上的密钥变量名，逐个核对是否同名同值
#    本地开发：grep -c '^JWT_SECRET=' .env                     → 预期 0（已切文件注入时）
#    生产容器：grep -rl 'JWT_SECRET=' ./secrets ./docker-compose.yml  → 预期无明文赋值
#    判定口径：**同一个密钥不得同时以「环境变量明文」与「文件」两种形态存在**。
#    仅存在其中一种即为合规；两者并存即触发 ② 的告警，属必须清理的配置。
```

## 全量轮换（单维护窗口编排）

适用：上线前首次全量换钥（例如从开发期 `.env` 明文密钥切换到生产密钥），
或怀疑任一密钥泄露。**不可回滚性**：换钥 + 数据迁移之后，旧密钥下加密的
数据已重写为新钥密文，旧密钥不再能解密任何东西——因此必须先备份。

```bash
# 0. 备份（回滚资格的前提）
MONGODB_URI='<连接串>' ./scripts/backup-mongo.sh ./backups

# 1. 生成全套新密钥到隔离目录（勿直接写 ./secrets，避免半新半旧混跑）
node scripts/generate-secrets.js --out ./secrets-new

# 2. 停应用（迁移期间禁止新数据用旧钥写入）
docker compose stop app

# 3. 两个需要数据迁移的密钥：先迁移、后换钥（顺序不可颠倒）
NEW_AES=$(cat ./secrets-new/aes_secret_key)
node scripts/migrate-mfa-secret.js --new-key "$NEW_AES"            # 演练
ALLOWED_SOURCE_DB=<库名> node scripts/migrate-mfa-secret.js --new-key "$NEW_AES" --apply    # 执行
NEW_HMAC=$(cat ./secrets-new/hmac_secret)
node scripts/verify-audit-chain.js > audit-chain-before-rotation.log
node scripts/resign-audit-hmac.js --new-key "$NEW_HMAC"            # 演练
ALLOWED_SOURCE_DB=<库名> node scripts/resign-audit-hmac.js --new-key "$NEW_HMAC" --apply --yes    # 执行

# 4. 原子替换 secrets 目录（JWT/URI/口令等无迁移依赖的随批生效）
mv ./secrets ./secrets-old && mv ./secrets-new ./secrets
chmod 700 ./secrets && chmod 600 ./secrets/*
#    ⚠️ 上面两条 chmod 仅在 Linux 生效。Windows 开发机不支持 POSIX 权限位
#    （NTFS 用 ACL），chmod 是空操作，密钥会继承父目录的宽松 ACL（默认对
#    BUILTIN\Users 可读、Authenticated Users 可改）。Windows 上请改用：
#      icacls "secrets" /reset /T /C /Q
#      icacls "secrets" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
#    ⚠️ 两步都要跑，且顺序不能颠倒：只 /inheritance:r 只移除**继承来的** ACE，
#    不动**显式授予**的 ACE——目录若曾被管理员/安装器授予过 Everyone、Users，
#    那条 ACE 会在"收紧"后存活，密钥仍人人可读。先 /reset 把显式 ACE 清掉
#    （/T 连目录内既有文件一起重置），再切断继承并授权。与 src/utils/filePermission.js
#    里 hardenPath 实际执行的两步完全一致（提示与执行同源，见该文件注释）。
#    另外 %USERNAME% 只在 cmd.exe 展开；PowerShell 里写成 $env:USERNAME。
#    验证：icacls "secrets" 不应再出现 BUILTIN\Users / Authenticated Users
#    生产环境经 Docker Secrets 挂载，不受此影响。

# 5. 启动并验证
docker compose up -d
curl -fsS http://127.0.0.1:3000/health
node scripts/verify-audit-chain.js     # 要求退出码 0（含义见上文"HMAC 密钥轮换"一节）
#   1 = 有断裂/失配：若本轮换了 HMAC_SECRET 却没先跑 resign-audit-hmac.js 重签，
#       存量记录的 hmac 必然全红——那是流程漏步，不是被篡改，补跑重签后再验；
#   2 = 校验不完整（窗口截断或该环境没有 HMAC_SECRET），不得当作"验过了"。
# 人工验证：已开 MFA 的账户 登录→动态码；管理员登录→核心旅程抽查
```

失败处置：第 3 步任一脚本报错即**终止窗口**——此时密钥未切换，
`mv ./secrets-old ./secrets` 后重启即回到原状态；数据层面的异常按备份恢复
（见 rollback-drill.md 3.3 节）。

本地开发环境说明：本地 `.env` 的密钥用于开发库，轮换会强制重建本地会话与
MFA 数据，收益低；开发库直接删库重建更快。全量轮换面向生产执行。
