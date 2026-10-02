# 备份加密与异地副本（P1-①）

> 对应审计缺口：`deliverables/安全缺口核查-2026-09-30.md` P1-①「备份未加密、且无异地副本」。
> 备份归档是**全量业务库**：全部人员 PII（realName/phone/email）+ 不可篡改审计集合。
> 拿到归档 = 拿到整个系统的人员名录与操作史。

## 现在的默认行为（2026-09-30 起）

`scripts/backup-mongo.sh` 每次产出**三件套**：

| 产物     | 形态                                 | 说明                                                                       |
| -------- | ------------------------------------ | -------------------------------------------------------------------------- |
| 加密归档 | `fire-safety-backup-<时间戳>.gz.gpg` | gpg 非对称加密（`--trust-model always`），明文归档在加密成功后**立即删除** |
| 校验和   | `…​.gz.gpg.sha256`                   | sha256，异地副本与恢复演练都必须先验它                                     |
| 异地副本 | 由 `BACKUP_OFFSITE_CMD` 决定         | 未配置时脚本打警告但不失败；配置了却失败则**整体失败**                     |

明文出口只有一个：`BACKUP_ENCRYPTION=plaintext-acknowledged`——取值本身就是一句
确认词，脚本仍会打 error 级警告。任何"忘了配加密"的部署在备份这一步硬失败，
不会静默产出明文全量库。

## 一次性初始化（在安全的机器上做，不是在备份宿主机上）

```bash
# 1. 生成密钥对（私钥永不进备份宿主机）
gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "fsms-backup <ops@example.net>" rsa3072 encr 2y

# 2. 导出公钥，导入到备份宿主机 / 容器
gpg --armor --export "ops@example.net" > fsms-backup.pub
# 在备份宿主机上：gpg --import fsms-backup.pub

# 3. 私钥托管：打印一份进保险库 + 一份给异地恢复介质持有者，
#    并把口令的知情人与归档的密文分离（单人拿不到完整链）
```

## cron / deploy 配置示例

```bash
# deploy.js 每次发布前自动走备份脚本；cron 另外跑每日全量：
0 2 * * * cd /opt/xf && \
  BACKUP_GPG_RECIPIENT=ops@example.net \
  BACKUP_OFFSITE_CMD='rclone copy ./backups remote:fsms-backups' \
  MONGODB_URI_FILE=./secrets/mongodb_uri ./scripts/backup-mongo.sh ./backups
```

> **这一行为什么必须写成 `./secrets/…` 而不是 `/run/secrets/…`**：cron 跑在**宿主机**上
> （`cd /opt/xf`），而 `/run/secrets/<name>` 是容器内的挂载点，宿主机没有这个目录。
> 两者都错过一次：写 `/run/secrets/…` 时文件读不到，写明文串则要求把生产凭据抄进 crontab。
> 备份/恢复脚本经 `scripts/mongoUri.sh` 的 `mongo_hydrate_uri` 支持 `MONGODB_URI_FILE`，
> 行为闸见 `src/tests/deploy/backupUriFile.test.js`（真跑 bash + 桩 mongodump）。
> 这条 cron 在支持 `*_FILE` 之前是**每天退出 1**、一份归档都不产出，
> 而失败只出现在 cron 的 stderr 里——没人读邮件，于是"有备份"是错觉，
> 唯一暴露时刻是真正要恢复的那天。

- `BACKUP_GPG_RECIPIENT`：收件人公钥指纹/邮箱（必填，gpg 模式下）。
- `BACKUP_OFFSITE_CMD`：按 **argv** 解析后直接执行（不经 shell 展开，无注入面；
  不支持 `$VAR` 与引号聚合——复杂同步逻辑请包成自己的脚本再填路径）。
  脚本会把产物路径通过 `BACKUP_FILE` / `BACKUP_SHA256` 环境变量传给它。
- 失败语义：加密失败 / 校验和失败 / 异地命令失败，任一发生都按**备份失败**处理
  （deploy.js 据此中止发布）。被吞掉的异地失败比没有异地更危险——它制造
  「以为自己有异地副本」的假象。
- **门禁早于导出**：`BACKUP_ENCRYPTION` 认不出来、gpg 不在 PATH、`BACKUP_GPG_RECIPIENT`
  没配，三种情况都在 `mongodump` 之前拒绝（连 `backups/` 都不创建）。此前它们是
  "先导出整个明文全量库、再在加密步失败"——`set -e` 直接带走脚本，那句"加密成功后
  立即删除明文"永远执行不到，于是每次失败都往备份目录多留一份全量库明文。
- **失败现场零残留**：未到"定稿点"（密文 + 校验和都已在手且非空）的产物由 `cleanup`
  一律删除，包括被 SIGINT/SIGTERM 打断时那半截归档。它们在 `backups/` 里与成功产物
  **同名**（`fire-safety-backup-*.gz[.gpg][.sha256]`），留着就会被 retention 清单、
  回滚演练和"最近一次备份"的报表挑中。定稿之后反过来一个都不删——异地副本失败时，
  已到手的本地副本仍是回滚抓手。行为闸见
  `src/tests/deploy/backupFailureArtifactHygiene.test.js`（真跑 bash + 桩 mongodump/gpg）。

## 恢复演练（每季度至少一次，与 rollback-drill.md 联动）

```bash
# 1. 从异地取回密文 + 校验和（两个文件都要取回）
#    restore-mongo.sh 会在解密与写库**之前**自己比对 <归档>.sha256，
#    对不上直接终止；缺 sidecar 同样硬失败（除非显式 RESTORE_SKIP_CHECKSUM=true）。
#    人工复核可用，但注意 `sha256sum --check` 认的是备份宿主机上的路径字符串，
#    异地副本改名/换目录后会报 no such file——脚本比的是哈希值，不受影响。
sha256sum --check backups/fire-safety-backup-<时间点>.gz.gpg.sha256   # 可选

# 2. 在**持有私钥**的机器上恢复（restore-mongo.sh 按 .gz.gpg 后缀自动解密）
MONGODB_URI='<目标连接串>' ./scripts/restore-mongo.sh backups/fire-safety-backup-<时间点>.gz.gpg
#    目标库也可以经密钥文件给：MONGODB_URI_FILE=./secrets/mongodb_uri ./scripts/restore-mongo.sh …
#    但**命令行点名的 MONGODB_URI 一定赢**（两者并存时告警后取显式值）：
#    恢复是破坏性写入，目标库必须由这一行的字面内容决定，不能被环境残留改写。

# 3. 恢复后抽验：用户可登录、审计页可按 action 过滤（validateEnum 不 400）、
#    审计链 verify 通过（GET /api/security/audit-logs/verify）
```

演练要证明的正是这三条链各自独立成立：**异地副本取回得了、私钥解得开、
恢复进库后系统跑得动**。任何一环只存在于文档里没被演练过，就当它不存在。

## 已知边界（如实记录）

- gpg 解密侧的口令交互由 gpg-agent 处理：cron 场景的恢复用无口令子钥或 agent 预缓存，
  交互式演练走 pinentry。
- `plaintext-acknowledged` 的部署必须在本文档追加一节「明文备份的理由与补偿控制」，
  并在等保测评材料中如实申报（对照表见 `docs/mlps2-controls.md`）。
- 备份宿主机上删除明文归档用的是 `rm`，不是 shred：SSD 上的安全擦除本就不可靠，
  保密性由"明文存在的时间窗口 = 加密执行的那几秒"保证，而不是由擦除保证。
