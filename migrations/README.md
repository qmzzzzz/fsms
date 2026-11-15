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
- `migrate:create` 的文件模板可通过 `migrations/sample-migration.js` 定制（该文件存在时
  migrate-mongo 会以它为模板）。本仓**刻意不放置**自定义模板：模板文件会被迁移计数门禁
  （`src/tests/migrations/migrationReadmeLedger.test.js` 的 `migrations/*.js` 全量盘点）计入迁移数。
  若未来确需模板，必须在该模板的注释里写明「已应用迁移不可修改」的提醒，并同步调整计数口径。

## 已应用迁移不可修改（正式规范）

**已应用（或可能已被任何共享环境应用）的迁移文件一律不得再修改**；需要修正逻辑时，
新建一个带更晚时间戳的迁移来补偿，而不是改旧文件。

根因：`migrate-mongo-config.js` 显式配置 `useFileHash: false`——台账（`_migrations` 集合）
只按**文件名**记录「已应用」，不记录文件内容哈希。因此：

- 修改一个已应用迁移的代码，任何已经跑过它的环境（生产 / 同事本地 / CI 库）都**不会重新执行**
  它——改动被静默跳过，各环境的实际 schema 从此分叉，而 `migrate:status` 依旧全绿；
- 反过来，还没跑过该迁移的环境执行的又是**改过之后**的版本——同一个文件在不同环境上语义不同；
- migrate-mongo 对这种改动不给任何信号，只能靠本规范与评审纪律兜住。

执行口径：

- 合并进 `main` 之后（更严格地说：在任何共享 / 线上环境执行过之后），迁移文件按
  **不可变发布物**对待；
- 发现已应用迁移有缺陷（幂等判据漏漂移、`down()` 语义错等）：新建
  `2026xxxx000000-fix-xxx.js` 补偿，旧文件保持原样；需要撤销旧迁移的效果时，用执行前备份
  恢复，或在新迁移里写**射程精确**的逆向操作；
- Code review 时，diff 里出现的**已存在**迁移文件（非新增）一律按事故处理。

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

| 迁移                                                 | `down()` 语义  | 回滚后果                                                                                                                                                                                                                                                                                   |
| ---------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `20260830000000-backfill-token-version.js`           | **有意空操作** | **不撤销**补齐的 `tokenVersion`。原实现按 `{ tokenVersion: 0 }` 撤字段，而 User schema 有 `default: 0` ⇒ 射程远超本迁移的写入范围 `{ $exists: false }`，会把存量字段一并抹掉。精确回退须用执行前的备份，按 `_id` 白名单撤字段                                                              |
| `20260831000000-reconcile-audit-index-options.js`    | 真实回滚       | `timestamp_-1` 重建为无 TTL 索引（**留存策略会停止自动清理**）、`sessionId_1` / `hash_1` 回普通索引 —— 非必要不回滚本迁移                                                                                                                                                                  |
| `20260919000000-reconcile-audit-ttl-to-retention.js` | **明确不回滚** | 脚本只打印理由：把留存期改回旧值可能更短，且**已被 TTL 删除的审计记录无法恢复**                                                                                                                                                                                                            |
| `20260926000000-cursor-tiebreak-compound-indexes.js` | 真实回滚       | 删除本次建立的复合 tiebreak 索引（并按 `replaceSingle` 还原被替换的单列索引）                                                                                                                                                                                                              |
| `20260928000000-audit-username-ci-index.js`          | 真实回滚       | 删除 `username_ci_timestamp` 索引（不存在则跳过）                                                                                                                                                                                                                                          |
| `20261021000000-query-performance-indexes.js`        | 真实回滚       | 删除本次新增的复合索引，并按旧形态建回 `nextCheckDate_1` / `assignedTo_1` / `level_1` / `usersessions.status_1`                                                                                                                                                                            |
| `20261030000000-backfill-password-set-at.js`         | 真实回滚       | 只撤「有 `passwordSetAt` 且无 `mustChangePassword`」的存量文档该字段（射程与本迁移写入范围一致）；新生用户不受影响                                                                                                                                                                         |
| `20261101000000-filter-tiebreak-compound-indexes.js` | 真实回滚       | 删除六条三键索引，并按旧形态建回 `status_1_occurredAt_-1` / `handler_1_occurredAt_-1` / `reporter.userId_1_occurredAt_-1` / `location.building_1_occurredAt_-1` / `alarmType_1_occurredAt_-1` / `status_1_planStartTime_-1`；**列表排序随之退化为阻塞排序**                                |
| `20261201000000-audit-list-tiebreak-indexes.js`      | 真实回滚       | 删除七条三键索引，并按旧形态建回 `userId_1_timestamp_-1` / `category_1_timestamp_-1` / `action_1_timestamp_-1` / `riskLevel_1_timestamp_-1` / `success_1_timestamp_-1` / `ip_1_timestamp_-1` / `category_1_action_1_timestamp_-1`；**审计列表的筛选查询随之退回「扫满时间窗 + 阻塞排序」** |
| `20261103000000-device-reminder-tiebreak-index.js`   | 真实回滚       | 删除 `expiryDate_1__id_1` 两键索引，并按旧形态建回 `expiryDate_1`；**提醒扫描的到期两档排序随之退化为日期块内阻塞排序（且同值页可能漂移成员）**                                                                                                                                            |

⇒ 目录里现有 **10 个迁移**（2026-11-03 实测：`ls migrations/*.js | wc -l` = `10`），其中 **2 个不撤销变更**（`20260830000000` 有意空操作、`20260919000000` 明确不回滚）。规划回退前请先读对应迁移文件的 `down()` 与文件头注释，**不要只看本表**（本表是**手工维护**的导读——`src/tests/migrations/migrationReadmeLedger.test.js` 只核「每行都指向真实文件 + 自报数量 == 实测文件数」，**不判 `down()` 到底撤不撤得动**；新增迁移必须自己补一行并把语义写对，迁移文件才是事实来源）。

注意事项：

- `migrate:down` 一次只回退**一个**迁移；连跳多级请重复执行并逐步核对。
- 对 TTL/部分索引执行 drop + 重建在大集合上是耗时操作，请在低峰窗口执行。
- 回滚不还原密钥类单向操作（AES/HMAC 轮换），此类操作见
  `deployment/secret-rotation.md`，永远单独成窗口。
