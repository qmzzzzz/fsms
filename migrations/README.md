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

- **每个迁移必须实现 `down()` 函数**（migrate-mongo 会无条件调用它，函数必须存在）。
  能真回滚的必须真回滚；**确实不可逆、或回滚射程会超出本迁移写入范围**的，
  写成空操作 / 只打日志，并在文件头注释写明理由，执行前用
  `scripts/backup-mongo.sh` 留档 —— 此时回退靠**备份**，不靠 `down()`。
  注意「实现了 `down()`」**不等于**「回滚能撤销变更」，逐迁移语义见下方「回滚语义一览」。
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

## 回滚语义一览（**`migrate:down` ≠ 数据一定回到迁移前**）

| 迁移                                                 | `down()` 语义  | 回滚后果                                                                                                                                                                                                                      |
| ---------------------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `20260830000000-backfill-token-version.js`           | **有意空操作** | **不撤销**补齐的 `tokenVersion`。原实现按 `{ tokenVersion: 0 }` 撤字段，而 User schema 有 `default: 0` ⇒ 射程远超本迁移的写入范围 `{ $exists: false }`，会把存量字段一并抹掉。精确回退须用执行前的备份，按 `_id` 白名单撤字段 |
| `20260831000000-reconcile-audit-index-options.js`    | 真实回滚       | `timestamp_-1` 重建为无 TTL 索引（**留存策略会停止自动清理**）、`sessionId_1` / `hash_1` 回普通索引 —— 非必要不回滚本迁移                                                                                                     |
| `20260919000000-reconcile-audit-ttl-to-retention.js` | **明确不回滚** | 脚本只打印理由：把留存期改回旧值可能更短，且**已被 TTL 删除的审计记录无法恢复**                                                                                                                                               |
| `20260926000000-cursor-tiebreak-compound-indexes.js` | 真实回滚       | 删除本次建立的复合 tiebreak 索引（并按 `replaceSingle` 还原被替换的单列索引）                                                                                                                                                 |
| `20260928000000-audit-username-ci-index.js`          | 真实回滚       | 删除 `username_ci_timestamp` 索引（不存在则跳过）                                                                                                                                                                             |

⇒ 5 个迁移里 **2 个不撤销变更**。规划回退前请先读对应迁移文件的 `down()` 与文件头注释，**不要只看本表**（本表是导读，迁移文件才是事实来源）。

注意事项：

- `migrate:down` 一次只回退**一个**迁移；连跳多级请重复执行并逐步核对。
- 对 TTL/部分索引执行 drop + 重建在大集合上是耗时操作，请在低峰窗口执行。
- 回滚不还原密钥类单向操作（AES/HMAC 轮换），此类操作见
  `deployment/secret-rotation.md`，永远单独成窗口。
