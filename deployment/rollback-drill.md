# 蓝绿 / 回滚演练手册（C-1）

> 目标：让「发版出问题 → 回到上一版」成为一条演练过的、分钟级的路径，
> 而不是事故现场临时拼凑的操作。回滚靠人工不是问题，**没练过**才是问题。

## 1. 版本单元

一个「版本」= 一份可复现的部署组合：

| 组成       | 载体                                                | 回滚抓手                       |
| ---------- | --------------------------------------------------- | ------------------------------ |
| 应用镜像   | `Dockerfile` 构建（R-7 接入 registry 后带版本 tag） | 切回上一镜像                   |
| 数据库结构 | `migrations/`（O-9，migrate-mongo）                 | `migrate:down` 或备份恢复      |
| 密钥       | `./secrets/`（P3-48 `_FILE` 注入）                  | 轮换是单向操作，回滚不还原密钥 |
| 配置       | `docker-compose.yml` + `.env`（非敏感项）           | 与 compose 同版本管理          |

**铁律：发布前必须先备份。** 没有备份的发布不具备回滚资格。

```bash
# 发布前（每次）
MONGODB_URI='<连接串>' ./scripts/backup-mongo.sh ./backups
```

## 2. 蓝绿部署流程（单机 compose 版）

单机没有真正的双环境流量切换，蓝绿退化为「双实例 + 反代摘流」：

1. **绿（现网）** 正常运行：`app` 服务绑定 `127.0.0.1:3000`，宿主 nginx 反代。
2. **起蓝**：用新镜像/新 compose 起第二实例（换端口，如 `127.0.0.1:3100:3000`），
   独立服务名（如 `app-blue`），共用同一 `mongo` 与 `secrets`。
3. **验证蓝**：
   ```bash
   curl -fsS http://127.0.0.1:3100/health          # 存活
   # 用低权限账号走一遍核心旅程：登录 → MFA → 列表查询 → 审计日志可见
   ```
4. **切流**：把宿主 nginx 的 `proxy_pass` 指向 3100，`nginx -s reload`（平滑，不断连）。
5. **观察期**（≥30 分钟）：盯 `logs/error-*.log`、审计 WAL 是否正常、/metrics 错误率。
6. **下线绿**：确认稳定后停旧实例。**镜像与旧 compose 保留至少一个版本周期。**

## 3. 回滚流程（按严重度分层）

### 3.1 应用层回滚（数据无涉，秒级）

现象：新版本逻辑错误、崩溃循环、性能退化。

```bash
# 切回 nginx 指向（蓝→绿端口互换），或直接回退 compose 里的镜像/构建
nginx -s reload
# 或：
docker compose down app && docker compose up -d app   # compose 已改回旧版本定义时
```

判定成功：/health 200、错误日志停止增长、核心旅程可用。

### 3.2 数据库结构回滚（迁移可逆时）

现象：新版本带的迁移（migrate:up）引发问题，且该迁移有 down。

```bash
# 先停应用，避免迁移中途被写入干扰
docker compose stop app
npm run migrate:status      # 确认当前迁移位点
npm run migrate:down        # 回退一个迁移（逐步，勿连跳）
docker compose start app
```

### 3.3 数据级回滚（最后手段，分钟级）

现象：脏数据已写入、迁移不可逆、误操作删改。

```bash
docker compose stop app                                # 先停写
MONGODB_URI='<连接串>' RESTORE_CONFIRM='<目标库名>' \
  ./scripts/restore-mongo.sh backups/fire-safety-backup-<时间点>.gz
# 需要彻底替换集合内容时才追加 RESTORE_DROP=true（默认不 drop）
docker compose start app
curl -fsS http://127.0.0.1:3000/health
```

门禁说明（脚本自带）：会回显目标主机/库名，交互或 `RESTORE_CONFIRM` 必须与库名一致，
`--drop` 必须显式 `RESTORE_DROP=true`。不要绕过任何一道。

## 4. 演练要求

- **频率**：每个发布周期至少一次完整演练（备份 → 起第二实例 → 切流 → 回退 → 恢复）。
- **记录**：每次演练记录起止时间、发现的问题、耗时。回滚耗时 >10 分钟即为不合格项。
  演练完成后在 `deployment/rollback-drill-record.md` 登记（该文件含记录模板与检查点清单）。
- **检查点**：
  - [ ] 备份文件可在异机解开（`mongorestore --dryRun` 抽查）
  - [ ] 双实例可同时连接同一 mongo（连接池/会话无冲突）
  - [ ] nginx reload 期间无请求失败（`curl` 循环抽样）
  - [ ] 回滚后审计链校验通过：`node scripts/verify-audit-chain.js`
  - [ ] WebSocket 重连正常（客户端应自动重连到新实例）

## 5. 已知边界

- 审计链是哈希链：数据级回滚会把链尾回退到备份时刻，此后新写入从旧尾续链。
  `verify-audit-chain.js` 校验的是连续性而非绝对时间，回滚后链依然自洽，
  但**回滚窗口内**产生的审计记录会随库一起消失（这正是审计合规需要评估的点，
  出现真实事故时优先 3.1/3.2，尽量不动数据）。
- 密钥轮换（R-1 runbook）不可回滚：新密钥下加密的 mfaSecret 在旧密钥下无法解密，
  因此密钥轮换永远单独成窗口，不与应用发布混批。
