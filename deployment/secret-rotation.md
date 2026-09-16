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
node scripts/migrate-mfa-secret.js --new-key <新KEY> --apply

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
node scripts/resign-audit-hmac.js --new-key "$NEW" --apply

# 3. 换钥并启动
printf '%s' "$NEW" > ./secrets/hmac_secret
docker compose up -d app

# 4. 复核（预期零 hmac 失配）
node scripts/verify-audit-chain.js
```

## JWT 双密钥轮换

直接替换 `secrets/jwt_secret` 与 `secrets/jwt_refresh_secret` 并重启即可：
所有存量令牌失效、用户重新登录，无数据迁移。建议选低峰期执行；
`tokenVersion`/黑名单机制不受影响（黑名单存的是 tokenHash，令牌失效后自然过期）。

## 收尾检查清单

- [ ] 旧密钥密封留档（离线保管，确认无回滚需要后再销毁）
- [ ] `docker compose config` 输出与 CI 日志中不再出现任何密钥明文
- [ ] `npm run validate`（config/validate.js）通过
- [ ] 抽查日志无「MFA 种子解密失败」「hmac 失配」告警

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
node scripts/migrate-mfa-secret.js --new-key "$NEW_AES" --apply    # 执行
NEW_HMAC=$(cat ./secrets-new/hmac_secret)
node scripts/verify-audit-chain.js > audit-chain-before-rotation.log
node scripts/resign-audit-hmac.js --new-key "$NEW_HMAC"            # 演练
node scripts/resign-audit-hmac.js --new-key "$NEW_HMAC" --apply    # 执行

# 4. 原子替换 secrets 目录（JWT/URI/口令等无迁移依赖的随批生效）
mv ./secrets ./secrets-old && mv ./secrets-new ./secrets
chmod 700 ./secrets && chmod 600 ./secrets/*
#    ⚠️ 上面两条 chmod 仅在 Linux 生效。Windows 开发机不支持 POSIX 权限位
#    （NTFS 用 ACL），chmod 是空操作，密钥会继承父目录的宽松 ACL（默认对
#    BUILTIN\Users 可读、Authenticated Users 可改）。Windows 上请改用：
#      icacls "secrets" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
#    验证：icacls "secrets" 不应再出现 BUILTIN\Users / Authenticated Users
#    生产环境经 Docker Secrets 挂载，不受此影响。

# 5. 启动并验证
docker compose up -d
curl -fsS http://127.0.0.1:3000/health
node scripts/verify-audit-chain.js     # 预期零失配
# 人工验证：已开 MFA 的账户 登录→动态码；管理员登录→核心旅程抽查
```

失败处置：第 3 步任一脚本报错即**终止窗口**——此时密钥未切换，
`mv ./secrets-old ./secrets` 后重启即回到原状态；数据层面的异常按备份恢复
（见 rollback-drill.md 3.3 节）。

本地开发环境说明：本地 `.env` 的密钥用于开发库，轮换会强制重建本地会话与
MFA 数据，收益低；开发库直接删库重建更快。全量轮换面向生产执行。
