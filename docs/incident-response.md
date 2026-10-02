# 应急响应预案（Incident Response Playbook）

> 对应审计缺口：`deliverables/安全缺口核查-2026-09-30.md` P3-⑭「发现入侵后谁在多久内做什么」。
> 本预案的每一项动作都绑定本系统**实际存在**的能力（端点 / 脚本 / 日志位置）——
> 写不出执行命令的预案在事故夜里等于废纸。

## 1. 角色与升级链

| 角色       | 承担者                                 | 职责                                            |
| ---------- | -------------------------------------- | ----------------------------------------------- |
| 值班响应人 | 当日运维值班（默认：管理员账号持有者） | 按第 3 节清单执行遏制；10 分钟内通报负责人      |
| 决策负责人 | 系统负责人                             | 决定是否停服、是否报监管（个保法/等保事件上报） |
| 恢复执行人 | 具备服务器 SSH 与私钥托管权限者        | 执行恢复、轮换、验证                            |

升级原则：**宁可误报升级，不许静默压单**。无法在 30 分钟内排除「数据被读取」的
事件，一律升级到决策负责人。

## 2. 检测信号从哪来（本系统的告警面）

- **审计页** `GET /api/security/audit-logs`（按 action/riskLevel 过滤）：`rate_limit_abuse`、
  `login_failed` 激增、`view_sensitive_data` 异常、`bulk_data_export`；
- **告警通道**：Alertmanager webhook（告警规则见 `observability/alert-rules.yml`，
  接收端未配置 = 触达链路断开，部署前置校验会拦——见 D-1 Top-2）；
- **指标**：`security_alerts_total`、`audit_records_dropped_total`、`readyz_verdict`；
- **审计中断判据**：审计落库失败会打 error 日志并计入 `audit_write_failed`——
  「审计页没有新记录」本身就是事件（先查服务是否在写 WAL：`logs/audit.wal`）。

## 3. 遏制清单（按事件类型，命令即用）

### 3.1 凭据泄露 / 账号被冒用

```bash
# 吊销某用户全部会话（tokenVersion 全局失效）
# 事件处置时手上通常只有密钥文件（生产口径 .env 不写明文），故给 *_FILE；
# 这些脚本在宿主机执行——运行镜像里只有 scripts/destructiveGuard.js。
MONGODB_URI_FILE=./secrets/mongodb_uri node scripts/revoke-user-sessions.js <username>
# 锁定账号：管理端 PUT /api/security/users/:id/lock（写审计 user_locked）
```

配合：轮换 `JWT_SECRET` 使全站 access 令牌失效（见 `deployment/secret-rotation.md`，
refresh 令牌与审计链 HMAC 的连带轮换一并按该文档执行）。

### 3.2 攻击源 IP（扫描 / 撞库 / 限流绕过）

```bash
# 管理端封禁（写审计，1h 起步阶梯）：POST /api/security/ip-list
# 查证：审计页按 ip 过滤，看该 IP 的全部轨迹（GET/HEAD 读取自 2026-09-30 起全留痕）
```

自动防线：限流升级封禁已开启（令牌桶 + 分桶阈值 + 阶梯升档）——
出现「封禁了还在来」说明换 IP 轮换，转 3.3。

### 3.3 应用层漏洞被利用（疑似）

1. `docker compose stop app`（先停写，蓝绿结构见 rollback-drill.md §2）；
2. 保全证据：`cp -r logs/ logs-incident-<时间>/`（含审计 WAL）+ `mongodump` 一份
   （备份脚本默认加密，见 `deployment/backup-encryption.md`）；
3. 排查入口：审计页按时间窗导出 CSV（`GET /api/security/audit-logs/export`）。

### 3.4 数据库被拖 / 备份介质丢失

- 数据库文件或备份**明文形态**不在本系统存在（PII 加密 + 备份默认 gpg），
  密钥未失守时按「未泄露」处理并记录判断依据；
- 私钥失守 → 立即按 `deployment/secret-rotation.md` 全量轮换
  （`JWT/AES/HMAC` 三把 + gpg 私钥吊销重造），并执行 PII 轮换脚本：
  `MONGODB_URI_FILE=./secrets/mongodb_uri AES_SECRET_KEY_FILE=./secrets/aes_secret_key ALLOWED_SOURCE_DB=<库名> PII_ROTATION_OLD_AES_KEY=<旧KEY> node scripts/migrate-pii-encryption.js --apply --yes --rotate`。
  （宿主机执行，`*_FILE` 前缀不能省：`MONGODB_URI` 缺失时 `destructiveGuard` 会回退到本地默认库，
  而 `--apply` 恰好拒绝作用于该回退库——报错看起来像"白名单配错了"，实际是没给连接串。）

## 4. 恢复与验证

- 数据恢复走 `scripts/restore-mongo.sh`（三道门禁 + 加密归档自动解密）；
- 恢复后必验三项：用户可登录、审计页可按 action 过滤（`validateEnum` 不 400）、
  审计链 verify 通过（`GET /api/security/audit-logs/verify`）；
- 服务恢复后 24 小时内保持 `LOG_LEVEL=info` 观察告警面。

## 5. 复盘与上报

- 72 小时内出复盘：时间线（以审计时间戳为准）、入口、扩散面、已补的洞；
- 涉个人数据泄露的，按个保法第 57 条与属地监管要求评估上报义务；
- 复盘产出回填本预案：每个「当时没有工具做 X」都要变成 Issue，而不是下一段文字。
