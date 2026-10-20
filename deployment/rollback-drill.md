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
MONGODB_URI_FILE=./secrets/mongodb_uri ./scripts/backup-mongo.sh ./backups
# 默认产出加密归档 .gz.gpg + .sha256（P1-①）；明文出口/异地副本/私钥托管见 backup-encryption.md
# 本手册所有命令都在**宿主机**执行：运行镜像里只有 scripts/destructiveGuard.js
# （Dockerfile:122-124 故意不把其余 scripts/ 打进镜像），而宿主机按生产口径
# 只持密钥文件、不持明文变量，所以前缀是 *_FILE 而不是明文串。
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

### 3.1a 自动回滚的边界（O-2）

`scripts/deploy.js` 的自动回滚**只在本次发布没有应用数据库迁移时**触发：
它切回的是镜像，数据库结构不会跟着回退。若本次 `migrate:up` 应用过迁移
（脚本会打印 `MIGRATED UP: <file>` 与「本次应用 N 个迁移」），健康门禁失败后
脚本会停在原地并转人工，而不是切回旧镜像——旧代码跑在新 schema 上，轻则启动
报错，重则按旧字段语义写坏数据，而「回滚后服务就绪」只会制造已恢复的假象。

人工处置顺序：

1. 确认这些迁移对上一版本是否向后兼容（推荐 expand/contract 两阶段迁移：
   先加字段/索引、双写，再在下一版收紧）。兼容 → 按 3.1 切回旧镜像。
2. 不兼容 → 按 3.2 评估 `migrate:down`，或按 3.3 用发布前的 `./backups` 做数据级恢复。

因此：**破坏性迁移不要与新版本放在同一次发布**，否则自动回滚将永远转人工。

### 3.2 数据库结构回滚（迁移可逆时）

现象：新版本带的迁移（migrate:up）引发问题，且该迁移有 down。

```bash
# 先停应用，避免迁移中途被写入干扰
docker compose stop app

# 迁移器在**应用镜像内**（node_modules/.bin/migrate-mongo）：生产主机
# 只需 Docker，不依赖本机装没装 Node/全局包。用 compose run 在一个
# 一次性容器里执行，与 scripts/deploy.js 的迁移步骤同路径：
docker compose run --rm --no-deps app node node_modules/.bin/migrate-mongo status
docker compose run --rm --no-deps app node node_modules/.bin/migrate-mongo down

docker compose start app
```

> 为什么不用 `npm run migrate:down`：那要求宿主机自己执行过 `npm ci`（migrate-mongo
> 在 package.json 的 `dependencies` 里，会随应用镜像安装，但宿主机的 npm script
> 仍需本地 `node_modules`），而生产主机上通常只有 Docker。上面的写法与
> 部署脚本保持同一条执行路径，避免「演练跑通、真事故时跑不通」。

### 3.3 数据级回滚（最后手段，分钟级）

现象：脏数据已写入、迁移不可逆、误操作删改。

```bash
docker compose stop app                                # 先停写
MONGODB_URI='<连接串>' RESTORE_CONFIRM='<目标库名>' \
  ./scripts/restore-mongo.sh backups/fire-safety-backup-<时间点>.gz.gpg
#    目标库由命令行点名（恢复是破坏性写入，必须赢过环境残留）；
#    手上只有密钥文件时改写 RESTORE_CONFIRM='<目标库名>' \
#      MONGODB_URI_FILE=./secrets/mongodb_uri ./scripts/restore-mongo.sh …
# 默认 MONGO_RESTORE_TRANSPORT=docker：mongo 只 expose 不 publish，宿主机既连不上也
# 常常没有 mongorestore CLI（备份侧一直是这个口径）。直连场景才显式设 local。
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
  - [ ] 回滚后审计链校验通过：
        `MONGODB_URI_FILE=./secrets/mongodb_uri HMAC_SECRET_FILE=./secrets/hmac_secret node scripts/verify-audit-chain.js`
        **退出码 0**
        （1=有断裂；2=校验不完整——窗口截断或该环境无 HMAC_SECRET，不算通过。见 secret-rotation.md 的退出码说明。
        宿主机上不给这两个 `*_FILE` 前缀就恒得 2，"跑了校验"不等于"校验过"）
  - [ ] WebSocket 重连正常（客户端应自动重连到新实例）

## 5. 恢复目标（RPO / RTO）—— 与备份频率的对齐

> A8（2026-10-16）。本节回答两个此前**在仓库里没有任何一处可查**的问题：
> 「允许丢多久数据」（RPO）与「多久必须恢复」（RTO）。
> 可执行底座：`src/constants/backupObjectives.js`（声明与对齐判据）、
> `scripts/backup-integrity-patrol.js`（巡检）。

### 5.1 技术事实：备份频率（已定，非目标值）

| 项       | 值                                                 | 来源                                                      |
| -------- | -------------------------------------------------- | --------------------------------------------------------- |
| 定时全量 | 每日 02:00（`0 2 * * *`），cron 跑在**宿主机**上   | `deployment/backup-encryption.md:39-43`                   |
| 发布前   | 每次发布前额外一次（`scripts/deploy.js` 自动触发） | `deployment/rollback-drill.md:17`（「发布前必须先备份」） |
| 异地副本 | 由 `BACKUP_OFFSITE_CMD` 决定，未配置时只警告不失败 | `deployment/backup-encryption.md:15`                      |

⇒ **最坏情况必丢 24 小时内的写入**（02:00 备份完成、02:01 故障）。
这是备份频率**决定**的上限，不是任何人拍的目标。

### 5.2 目标值（RPO / RTO）

> **已定值（2026-10-17 业务方拍板）**：RPO = **24h**，RTO = **4h**。
> 声明写入 `src/constants/backupObjectives.js` 的 `declaredHours`（随代码评审留痕），
> 部署侧再用 `BACKUP_RPO_HOURS` / `BACKUP_RTO_HOURS` 启用（两条通道分开，可分别回退）。

| 目标 | 含义                             | 目标值 | 依据（**别把内部决策说成标准条文**）                                                                                                                                           |
| ---- | -------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| RPO  | 故障时**允许丢失**多长时间的数据 | 24h    | **由备份频率技术下限决定**，不是等保规定的小时数。等保三级「备份和恢复」只要求"有本地备份与恢复""有异地数据备份"，未规定 RPO。每日 02:00 全量 ⇒ 24h 是现有底座可兑现的最优值。 |
| RTO  | 从故障到**恢复可用**允许的时长   | 4h     | **业务决策值**（半天内恢复的内部合格线），同样不是标准条文。可执行形态 = 演练实测耗时 ≤ 4h（见 5.3 的数据级恢复耗时字段）。                                                    |

**两条判据方向相反，都必须过**（`scripts/compliance-check.js` 与巡检都会跑）：

| 判据                                    | 拦的是什么                        | 失败码                                                  |
| --------------------------------------- | --------------------------------- | ------------------------------------------------------- |
| `evaluateRpoAlignment`（声明 vs 能力）  | 声明 1h 而备份每天一次 ⇒ 兑现不了 | `rpo_better_than_frequency`                             |
| `evaluateDeclaredBound`（能力 vs 声明） | 声明 24h 而部署配 48h ⇒ 没做到    | `rpo_looser_than_declared` / `rto_looser_than_declared` |

- 声明 RPO ≥ 备份间隔 ⇒ 可兑现；< 备份间隔 ⇒ **error**：
  「要么加密备份频率，要么改口径——不能只改文档」；
- 生效值 > 声明值 ⇒ **error**：「对外承诺的数字在部署配置上不成立」；
- 未配置生效值 ⇒ warn（巡检里如实告知"未设定"），但**发布路径会判 error**
  （`scripts/deployPolicy.js` 的 `checkBackupObjectives`）——发布正是把承诺推上线的动作，
  此时没配等于承诺未生效。启动路径不判，避免已在运行的服务重启失败。

### 5.3 演练结果自动留档

演练结束后用下面这一条把 manifest 落进留档文件（默认 **dry-run**，确认无误再加 `--write`）：

```bash
# manifest 由 run-rollback-drill.js --apply-source 产出在 backups/rollback-drill/ 下
node scripts/record-rollback-drill.js \
  --manifest backups/rollback-drill/manifest-<时间戳>.json \
  --operator '<姓名/角色>' --environment '<环境描述>' --write
```

> 开关叫 `--write` 而不是 `--apply`：本仓的 `--apply` 专指「对数据库做破坏性改写」
> （需 `ALLOWED_SOURCE_DB` + `--yes`），本脚本只追加一个 markdown 文件，不该混进那一族。

它会渲染成「## 三、实际演练记录」段末的一条 `### 演练 #N（…，自动登记）`，
含每个集合的「快照条数 / 回灌后条数 / 是否一致」。

> 脚本会**拒绝**登记 `applySource !== true` 的 manifest：只做快照、没清空并回灌的
> 一次运行不构成「回滚能力」证明，不该在留档里留下一条看起来正常、实际什么都没验的记录。
> （同一坑在 `run-rollback-drill.js` 里也堵过一次：空快照时 0 === 0 会"验证通过"。）

### 5.4 巡检（自动化，替代人工"想起来就查"）

```bash
# 备份宿主机 cron（每日，与备份脚本错开）：产物完整性 + 异地副本探针 + 演练时效
BACKUP_DIR=./backups BACKUP_OFFSITE_DIR=/mnt/offsite \
  node scripts/backup-integrity-patrol.js

# CI（每周一，只需仓库内文件）：只判演练时效是否超过一个季度
node scripts/backup-integrity-patrol.js --drill-only
```

退出码：`0` 无 error 级发现 / `1` 存在 error 级发现 / `2` 未做任何判定（目录不存在等）。
**`2` 不等于 `0`**：巡检无法执行时不能报成"就绪"。

### 5.5 预发环境定期自动演练（T-4）

> 现状（2026-10-20 审计 T-4）：记录里的两次演练都是开发环境专项（#1 迁移回滚、
> #2 内存 mongod 数据快照），完整「容器 + 真库 + 切流」从未在预发跑过。
> `dr-readiness.yml` 只判**留档时效**，它不会替你执行演练——本节的宿主 cron
> 才是执行者，两者共用同一份记录文件。

| 能力                  | 执行者                                         | 失败形态                    |
| --------------------- | ---------------------------------------------- | --------------------------- |
| 演练时效 ≤ 一个季度   | `.github/workflows/dr-readiness.yml`（每周一） | job 变红                    |
| 真实演练（快照+回灌） | 预发宿主机 cron（本节命令）                    | 无新记录 ⇒ 上一条在周期后红 |

预发宿主 cron（示例：每周日 02:30，与备份错开）：

```bash
# /etc/cron.d/fsms-drill（执行用户需能读 ./secrets 与写 ./backups）
30 2 * * 0 ops cd /srv/fsms && \
  ALLOWED_SOURCE_DB=fsms_staging MONGODB_URI_FILE=./secrets/mongodb_uri \
  node scripts/run-rollback-drill.js --apply-source --yes >> /var/log/fsms-drill.log 2>&1 && \
  node scripts/record-rollback-drill.js \
    --manifest "$(ls -t backups/rollback-drill/manifest-*.json | head -1)" \
    --operator 'staging-cron' --environment '预发（cron 自动）' --write >> /var/log/fsms-drill.log 2>&1
```

四条纪律（缺一条就不要把这条 cron 装上去）：

1. `ALLOWED_SOURCE_DB` 必须是**预发库名**：`--apply-source --yes` 会清空
   `users / roles / permissions / auditlogs` 四个集合并回灌。指向错误库就是把
   开发数据清空；指向生产库则直接违反「破坏性动作必须有人值守」的纪律。
2. 只允许预发/隔离库。生产环境的完整演练仍按第 4 节人工执行——
   无人值守的破坏性恢复演练不接受「反正有备份」作为理由。
3. `--write` 只改工作树里的 `deployment/rollback-drill-record.md`，**不会自动提交**。
   必须有人复核 cron 日志与 manifest 后把该记录随 PR 入库；否则 CI 读不到，
   `dr-readiness` 仍会在季度后变红——这是**预期**，不是误报。
4. 留证：`/var/log/fsms-drill.log` 与 `backups/rollback-drill/manifest-*.json`
   至少保留到下一次演练；失败项按第 4 节转待办。

首次在预发执行后：把「演练 #N」登记进 `deployment/rollback-drill-record.md`
（模板见该文件第一节），并在记录里注明执行者是 cron 还是人工。

## 6. 已知边界

- 审计链是哈希链：数据级回滚会把链尾回退到备份时刻，此后新写入从旧尾续链。
  `verify-audit-chain.js` 校验的是连续性而非绝对时间，回滚后链依然自洽，
  但**回滚窗口内**产生的审计记录会随库一起消失（这正是审计合规需要评估的点，
  出现真实事故时优先 3.1/3.2，尽量不动数据）。
- 密钥轮换（R-1 runbook）不可回滚：新密钥下加密的 mfaSecret 在旧密钥下无法解密，
  因此密钥轮换永远单独成窗口，不与应用发布混批。
