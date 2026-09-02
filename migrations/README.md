# 数据库迁移规范（O-9）

本项目使用 [migrate-mongo](https://github.com/seppevs/migrate-mongo) 管理数据与索引演进，
迁移台账存放于数据库 `_migrations` 集合，可追溯每次应用记录。

## 常用命令

| 命令                                     | 作用                                             |
| ---------------------------------------- | ------------------------------------------------ |
| `npm run migrate:create -- <snake-名称>` | 生成带时间戳前缀的新迁移文件（按文件名顺序应用） |
| `npm run migrate:status`                 | 查看已应用/待应用的迁移位点                      |
| `npm run migrate:up`                     | 顺序应用所有待执行迁移                           |
| `npm run migrate:down`                   | **回退最近应用的一个迁移**（逐级回退，勿连跳）   |

连接串经 `MONGODB_URI` 注入（`migrate-mongo-config.js` 读取）。

## 迁移编写规范

- **每个迁移必须实现可回滚的 `down()`**（回退策略）。确实不可逆的数据变更，
  须在文件头注释中写明理由，并在执行前留档备份
  （`scripts/backup-mongo.sh` / `scripts/restore-mongo.sh`）。
- 迁移只做**数据/索引演进**；模型结构约束仍由 Mongoose schema 声明，
  两侧变更需同一批次提交，避免「迁移改了数据、schema 仍按旧口径校验」。
- 与既有维护脚本的分工：
  - `scripts/migrate-mfa-secret.js`（AES 密钥轮换配套）与
    `scripts/resign-audit-hmac.js`（HMAC 密钥轮换配套）依赖密钥参数与
    停机窗口编排，保留为脚本，不纳入自动迁移序列；
  - 其余一次性修数需求一律走本框架，留下 `_migrations` 台账可追溯。
- 幂等优先：迁移应可在重复执行时自行跳过（如 `$exists` 过滤、先读后写），
  降低半途失败重跑的副作用。

## schema 迁移回滚方案

迁移失败或升级后需要回退时，按以下顺序操作（与 `deployment/rollback-drill.md` 3.2 节一致）：

```bash
# 0. 先停应用，避免回滚期间新数据用旧口径写入
docker compose stop app

# 1. 确认当前迁移位点（决定要回退到哪一级）
npm run migrate:status

# 2. （推荐）执行前先备份，保证数据级兜底可用
MONGODB_URI='<连接串>' ./scripts/backup-mongo.sh ./backups

# 3. 逐级回退（每执行一次回退一个迁移；查看结果后再决定是否继续）
npm run migrate:down
npm run migrate:status

# 4. 恢复应用并验证核心旅程
docker compose start app
curl -fsS http://127.0.0.1:3000/health
```

回滚示例（现有迁移均已实现 `down()`）：

- `20260830000000-backfill-token-version.js`：`down` 移除本次补齐的
  `tokenVersion` 字段；注意 `down` 无法区分「本次补的 0」与「业务推进后仍为 0」，
  精确回退需依赖执行前备份。
- `20260831000000-reconcile-audit-index-options.js`：`down` 将
  `timestamp_-1` 回滚为无 TTL 索引（**留存策略会停止自动清理**）、
  `sessionId_1`/`hash_1` 回滚为普通索引——非必要不回滚本迁移。

注意事项：

- `migrate:down` 一次只回退**一个**迁移；连跳多级请重复执行并逐步核对。
- 对 TTL/部分索引执行 drop + 重建在大集合上是耗时操作，请在低峰窗口执行。
- 回滚不还原密钥类单向操作（AES/HMAC 轮换），此类操作见
  `deployment/secret-rotation.md`，永远单独成窗口。
