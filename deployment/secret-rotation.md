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
