#!/bin/bash

# MongoDB 备份脚本
# 用法: ./scripts/backup-mongo.sh [backup_dir]
#
# 环境变量：
#   MONGODB_URI             必填（或用 MONGODB_URI_FILE 指向密钥文件），含凭据的连接串
#   MONGODB_URI_FILE        生产默认形态：宿主机 ./secrets/mongodb_uri。
#                           两者都给时以 MONGODB_URI 为准并告警（详见 scripts/mongoUri.sh）
#   BACKUP_RETENTION_DAYS   可选，备份保留天数（默认 30）
#   MONGO_BACKUP_TRANSPORT  可选，local | docker（默认 docker）
#                           docker = 在 compose 服务容器内跑 mongodump，归档经 stdout 流回宿主。
#                           这是默认值：mongo 在 compose 里只 expose 不 publish，
#                           URI 的主机名又是容器网内服务名，宿主机直连必然失败。
#   MONGO_COMPOSE_SERVICE   可选，容器内执行 mongodump 的服务名（默认 mongo）
#   MONGO_CONTAINER_HOST    可选，容器内连接地址（默认 127.0.0.1:27017）
#   COMPOSE_FILE            可选，compose 文件路径（默认 docker-compose.yml）
#   BACKUP_ENCRYPTION       可选，gpg（默认）| plaintext-acknowledged
#                           P1-①：归档是全量业务库（含人员 PII 与审计集合），
#                           明文落盘 = 拿到文件即拿到整个系统。默认 gpg 非对称加密
#                           （宿主机只放公钥，私钥托管异地/密钥库）；
#                           明文出口取值本身就是一句确认词，且仍打 error 级警告。
#   BACKUP_GPG_RECIPIENT    BACKUP_ENCRYPTION=gpg 时必填，收件人公钥指纹/邮箱
#   BACKUP_OFFSITE_CMD      可选，备份+校验和完成后的异地副本命令（如 rclone copy）。
#                           以 BACKUP_FILE / BACKUP_SHA256 环境变量传产物路径，
#                           失败即整体失败（异地副本失败被吞掉等于没有异地副本）
#
# 【P2-27 凭据不上命令行】
# 原实现 `mongodump --uri="$MONGODB_URI"`：进程参数在 Linux 上对同机任意用户
# 可见（ps aux / /proc/<pid>/cmdline 全局可读），备份窗口内数据库口令持续暴露；
# shell history、CI 任务日志、进程监控采集器同样会留痕。
# 改用 mongodump 官方推荐的 --config 配置文件方式传递 uri：
# 文件以 umask 077 创建（仅属主可读），并在退出时无条件删除。

set -euo pipefail

# URI 主机段改写的唯一实现（与 restore-mongo.sh 共用）
. "$(dirname "$0")/mongoUri.sh"
# 加密/解密/校验和的唯一实现（与 restore-mongo.sh 共用，P1-①）
. "$(dirname "$0")/backupCrypto.sh"

BACKUP_DIR=${1:-"./backups"}
# 时间戳带秒。原先是 %Y%m%d-%H%M（只到分钟）：同一分钟内两次备份会算出**同名**文件，
# 而 mongodump --archive 是覆盖写——事故现场手工补的那一份会静默吃掉整点 cron 那一份
# （scripts/deploy.js 每次发布前也走这里，与 cron 撞在同一分钟完全可能）。
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="fire-safety-backup-$TIMESTAMP.gz"
ARCHIVE_PATH="$BACKUP_DIR/$BACKUP_FILE"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}

# 检查环境变量（在创建任何文件之前）
# `*_FILE` 回填必须早于空值检查：生产部署的默认形态是密钥文件
# （docker-compose.yml 的 secrets 指向宿主机 ./secrets/<name>，应用侧由
# src/config/secrets.js 的 hydrateSecretsFromFiles() 读取），而本脚本是 shell，
# 接不到那次回填 ⇒ 照手册配 cron 的人每次拿到的是"变量没设置"，
# 备份产出静默为零。判据与"显式值优先"的规则都收在 mongoUri.sh 一处，两个脚本共用。
if ! mongo_hydrate_uri; then
  echo "Error: 需要 MONGODB_URI，或 MONGODB_URI_FILE 指向的密钥文件" >&2
  exit 1
fi

# 保留天数必须是正整数，且**早于**工具探测与任何动作。
# 旧写法没有这条：BACKUP_RETENTION_DAYS 写成 30d / 空 / 负数时，下面的 find 会直接报错，
# 而那句末尾挂着 `|| true` —— 于是"过期备份根本没被清理"这件事以成功退出码收场，
# 备份目录一路涨到磁盘写满。本系统磁盘满的后果不是慢，是审计落库失败（WAL 也写不下）。
if ! printf '%s' "$RETENTION_DAYS" | grep -Eq '^[1-9][0-9]*$'; then
  echo "Error: BACKUP_RETENTION_DAYS 必须是正整数（当前：'${RETENTION_DAYS}'）" >&2
  echo "       留空即默认 30；不允许 0 与负数——那等价于「把所有备份立刻删光」。" >&2
  exit 1
fi

# 备份在哪台机器上执行：
#   local  —— 宿主机直接跑 mongodump（URI 主机在宿主可达时用）
#   docker —— 在 compose 服务容器内跑 mongodump，归档经 stdout 流回宿主文件
# 为什么默认要选 docker 之外还要留 local：compose 里的 mongo 只 expose 不 publish，
# 而 secrets/mongodb_uri 的主机名正是容器网内的服务名（generate-secrets.js 合成）——
# 宿主机上直连必然失败，部署会在备份步稳定中止（或被 --skip-backup 绕过而失去回滚资格）。
# 判据由调用方给出（deploy.js 掌握拓扑），本脚本不猜：猜错的代价是"备份看起来成功了"。
MONGO_BACKUP_TRANSPORT=${MONGO_BACKUP_TRANSPORT:-docker}
MONGO_COMPOSE_SERVICE=${MONGO_COMPOSE_SERVICE:-mongo}
MONGO_CONTAINER_HOST=${MONGO_CONTAINER_HOST:-127.0.0.1:27017}

case "$MONGO_BACKUP_TRANSPORT" in
  local)
    if ! command -v mongodump >/dev/null 2>&1; then
      echo "Error: mongodump not found in PATH（MONGO_BACKUP_TRANSPORT=local）" >&2
      exit 1
    fi
    ;;
  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo "Error: docker 不在 PATH 中（MONGO_BACKUP_TRANSPORT=docker）" >&2
      exit 1
    fi
    ;;
  *)
    echo "Error: MONGO_BACKUP_TRANSPORT 只能是 local 或 docker（当前：'${MONGO_BACKUP_TRANSPORT}'）" >&2
    exit 1
    ;;
esac

# ================= P1-① 加密门禁（必须早于 mongodump） =================
# 默认 gpg 非对称加密；明文出口取值本身就是一句确认词。
# 为什么在这里查而不是等到加密那一步：判据原先只写在归档**之后**的 case 里，
# 于是"宿主机没装 gpg"或"忘配 BACKUP_ENCRYPTION 收件人"的部署会先花几分钟导出
# 整个明文全量库（含人员 PII 与不可篡改审计集合），再在加密步失败退出——
# 每次失败都往 backups/ 留下一份 0600 的明文归档（set -e 直接带走脚本，
# 加密分支里"写完就删明文"那行永远执行不到）。问不清能不能加密就不开始导出。
BACKUP_ENCRYPTION=${BACKUP_ENCRYPTION:-gpg}
if ! crypto_precheck_backup "$BACKUP_ENCRYPTION"; then
  exit 1
fi

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 目标归档不得已存在（同名覆盖是上面那条时间戳缺陷的兜底闸；也是"永不销毁既有备份"的意图声明）
if [ -e "$ARCHIVE_PATH" ]; then
  echo "Error: 目标归档文件已存在，拒绝覆盖：$ARCHIVE_PATH" >&2
  echo "       同一秒内重复执行？请错开或改用不同 BACKUP_DIR。" >&2
  exit 1
fi

# 凭据配置文件：umask 077 保证 0600 权限，trap 保证任何退出路径都清理
# （含 set -e 触发的中途失败与 SIGINT/SIGTERM）
CONFIG_FILE=""
# 定稿标志：0 = 这次运行还不是一次可信备份，它的产物必须被清掉；
# 1 = 加密副本（或经确认的明文归档）与校验和都已在手，任何退出路径都不许再碰。
FINALIZED=0
cleanup() {
  if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
    rm -f "$CONFIG_FILE"
  fi
  # 未定稿的产物一律删除。它们在 backups/ 里和成功产物**同名**
  # （fire-safety-backup-*.gz[.gpg][.sha256]），于是会被 retention 清单、回滚演练
  # 与"最近一次备份"的报表挑中——真要恢复那天才发现是半截的。
  # 分支里原有的删除点只覆盖两条 mongodump 失败路径，覆盖不到的是：
  #   · 加密步失败/校验和写不出（明文归档已经在盘上，set -e 直接带走，
  #     "写完就删明文"那行永远执行不到 ⇒ 每次失败多留一份全量明文）；
  #   · 被 SIGINT/SIGTERM 打断的窗口：下面两条 trap 已经会自己收尾退出，
  #     但退出后那 5 字节的半截归档仍留在目录里（实测过它的形状）。
  # 反过来，定稿之后一个都不能删：异地副本失败按设计要让整体失败，
  # 那时到手的加密备份连同校验和必须留下。
  if [ "$FINALIZED" -ne 1 ]; then
    for _artifact in "$ARCHIVE_PATH" "$ARCHIVE_PATH.sha256" \
                     "${ENCRYPTED_PATH:-}" "${ENCRYPTED_PATH:-}.sha256"; do
      if [ -n "$_artifact" ]; then
        rm -f -- "$_artifact"
      fi
    done
  fi
  # umask 的还原也放在这里：还原点一旦写在"临时凭据文件建好之后"，收紧就只覆盖了
  # 那一格，而后面 mongodump 产出的归档同样是**全量业务库明文**（含 PII 与审计集合）。
  # 修复前的实测：`.sha256`/`.gpg`/（plaintext 模式下的）.gz 全部落在调用方 umask 022
  # 上 = 0644 世界可读，而 backupCrypto.sh 里那句「0600 权限由调用方的 umask 约束」
  # 在那一刻已经不再成立。加密模式下明文归档只短暂存在，但那道"写完才删"的窗口
  # 恰恰是提权到本机的进程最省事的读取时机。
  if [ -n "${OLD_UMASK:-}" ]; then
    umask "$OLD_UMASK"
  fi
}
# INT/TERM 两条 trap 必须**自己收尾退出**：`trap cleanup EXIT INT TERM` 只在同一条里做清理、
# 不做 exit，于是信号打断 mongodump 后脚本会**继续往下跑**——此刻 cleanup 已把 0600 配置删掉、
# umask 也还原了，而后面"归档存在且非空"的判据用的是 mongodump 中途被截断的产物。
# 实测（local 传输 + 桩工具响应 SIGINT 后退出）：产出 5 字节归档，仍然打印
# `Backup completed successfully: …（5 bytes）`并补写 .sha256，哈希还对得上。
# 那次"看起来成功的备份"正是 retention 清单与回滚演练会挑中的那一份。
# 130/143 = 128+SIGINT/SIGTERM，让 cron 邮件与 CI 看得见是被信号打断的。
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

OLD_UMASK=$(umask)
umask 077
CONFIG_FILE=$(mktemp "${TMPDIR:-/tmp}/mongodump-config.XXXXXX")
# umask 之外再显式 chmod：双保险，且让"仅属主可读"成为代码里可见的意图。
# 注意：在 Git Bash/MSYS（Windows）下 stat 恒报 644 —— NTFS 不承载 POSIX
# 权限位，chmod 与 umask 在该环境均为空操作。本脚本的目标运行环境是
# Linux 服务器 / 容器，那里两者都真实生效。
chmod 600 "$CONFIG_FILE"
printf 'uri: %s\n' "$MONGODB_URI" > "$CONFIG_FILE"

echo "Starting MongoDB backup at $(date)"

# 执行备份。两条路径的共同点：含凭据的 URI 只出现在 0600 的配置文件里或管道里，
# 绝不出现在任何 argv 上（P2-27 的原始动机）。
#
# 顺带交代一个范围问题（曾被记成缺陷，源码读下来否证了）：URI 末尾的库名**会**限制 mongodump
# 的范围——mongo-tools 100.9 的 common/options 在没有显式 --db 时把连接串里的库名赋给 opts.DB，
# mongodump 随后只为那一个库建 intents，归档里就只有 `<库名>.*`；mongorestore 对同一个字段做
# 同样的赋值，并把 `[库名.*]` 当作 includes 过滤归档条目。**两侧范围因此一致**，不存在
# "备份一个库、恢复时把整台实例覆写掉"的错配（恢复脚本核对的 RESTORE_CONFIRM 正是这个库名）。
# 口径来源是读 100.9 的源码，本机没有 mongodump/mongorestore 可实测——这是**源码推断**，
# 不是执行证据；工具大版本换了就要重读。
case "$MONGO_BACKUP_TRANSPORT" in
  local)
    # 失败也要删半成品：docker 分支早就这么做了（重定向会先建出 0 字节文件），
    # local 分支漏掉 ⇒ mongodump 非零退出时 set -e 直接把脚本带走，一个截断的 .gz
    # 留在 backups/ 里，而它同样匹配 retention/回滚清单的时间戳命名。
    # 失败现场不能留下看起来像成功的产物（与下方"不能只信退出码"同一条理由）。
    if ! mongodump --config="$CONFIG_FILE" --archive="$ARCHIVE_PATH" --gzip; then
      rm -f "$ARCHIVE_PATH"
      echo "Error: mongodump 失败，已删除半成品归档：$ARCHIVE_PATH" >&2
      exit 1
    fi
    ;;
  docker)
    # 主机段换成容器内地址：账号、口令、库名与查询串原样保留。判据与 restore 共用
    # scripts/mongoUri.sh（同一份 sed 原先在两个脚本里各写一遍，失败判据还会各自漂移）。
    # 静默按原 URI 在容器里跑就会连到宿主机名，得到"备份失败"这种最难查的表象。
    if ! CONTAINER_URI=$(mongo_swap_host "$MONGODB_URI" "$MONGO_CONTAINER_HOST"); then
      echo "Error: 无法把 URI 主机段改写为容器内地址（目标 ${MONGO_CONTAINER_HOST}），拒绝执行；上一行点名是哪条判据拦下的" >&2
      exit 1
    fi
    # 归档用 --archive（不带路径＝写 stdout）经 docker exec 流回宿主机文件：
    # 不需要往容器里挂备份卷，容器文件系统里的临时 cfg 用完即删。
    if ! printf 'uri: %s\n' "$CONTAINER_URI" |
      docker compose -f "${COMPOSE_FILE:-docker-compose.yml}" exec -T "$MONGO_COMPOSE_SERVICE" \
        sh -c 'umask 077; cfg=/tmp/.mongodump-backup.cfg; cat > "$cfg" || exit 1;
               mongodump --config="$cfg" --gzip --archive; rc=$?;
               rm -f "$cfg"; exit $rc' >"$ARCHIVE_PATH"; then
      # 重定向在命令失败前就已经创建了 0 字节文件。必须删掉：
      # 一个躺在 backups/ 里的 0 字节 .gz 在回滚清单上"就是一次备份"，
      # 等到真要恢复时才发现它是空的——失败现场不能留下看起来像成功的产物。
      rm -f "$ARCHIVE_PATH"
      echo "Error: 容器内 mongodump 失败，已删除半成品归档：$ARCHIVE_PATH" >&2
      exit 1
    fi
    ;;
esac

# **不能只信退出码**：README/rollback-drill 里"升级前确认备份文件非空"这一步原先是
# 人工动作。mongodump 返回 0 而归档缺失/0 字节并非不可能（目标目录被换掉、
# 写盘失败被上层吞掉、--archive 指向的路径后来被清理任务删了）。
# 一次"看起来成功"的备份比没有备份更糟：发布流程据此认为自己有回滚抓手。
if [ ! -f "$ARCHIVE_PATH" ]; then
  echo "Error: mongodump 退出码为 0 但归档不存在：$ARCHIVE_PATH" >&2
  exit 1
fi
ARCHIVE_BYTES=$(wc -c < "$ARCHIVE_PATH")
if [ "$ARCHIVE_BYTES" -le 0 ]; then
  echo "Error: 归档为 0 字节，不是一次有效备份：$ARCHIVE_PATH" >&2
  exit 1
fi

# ================= P1-① 加密与校验和 =================
# 模式与前置条件已在 mongodump 之前由 crypto_precheck_backup 问过（见上），这里只做分发。
# 归档 → 归档.gz.gpg + .sha256，明文归档在"加密副本 + 校验和都到手"的瞬间删除。
case "$BACKUP_ENCRYPTION" in
  gpg)
    ENCRYPTED_PATH="$ARCHIVE_PATH.gpg"
    if [ -e "$ENCRYPTED_PATH" ]; then
      echo "Error: 目标加密归档已存在，拒绝覆盖：$ENCRYPTED_PATH" >&2
      exit 1
    fi
    if ! crypto_encrypt "$ARCHIVE_PATH" "$ENCRYPTED_PATH"; then
      rm -f "$ENCRYPTED_PATH"
      echo "Error: gpg 加密失败，已删除半成品：$ENCRYPTED_PATH" >&2
      exit 1
    fi
    if [ ! -s "$ENCRYPTED_PATH" ]; then
      rm -f "$ENCRYPTED_PATH"
      echo "Error: 加密产物为空，不是一次有效备份：$ENCRYPTED_PATH" >&2
      exit 1
    fi
    crypto_checksum "$ENCRYPTED_PATH"
    # 定稿点：密文与校验和都已在手且非空。此刻起 cleanup 不得再删任何产物
    # （见下方 FINALIZED 的注释），而明文归档的历史使命已经结束。
    FINALIZED=1
    # 明文归档完成历史使命：加密副本 + 校验和在手的瞬间就地删除。
    # 留着它 = P1-① 的缺口原样存在，只是多花了一次加密的 CPU。
    rm -f "$ARCHIVE_PATH"
    BACKUP_FILE_FINAL="$ENCRYPTED_PATH"
    ;;
  plaintext-acknowledged)
    echo "ERROR-LEVEL WARNING: BACKUP_ENCRYPTION=plaintext-acknowledged——本次备份是明文全量库，" >&2
    echo "  含全部人员 PII 与不可篡改审计集合。此选择必须已在部署文档记录理由与补偿控制。" >&2
    crypto_checksum "$ARCHIVE_PATH"
    FINALIZED=1
    BACKUP_FILE_FINAL="$ARCHIVE_PATH"
    ;;
  *)
    # 前置门禁已经用同一句判据拒过这个值，走到这里只可能是有人在导出途中改了它。
    # 错误文案由共享实现产出（两处的口径不会各自漂移），兜底分支再点名分发口径。
    crypto_precheck_backup "$BACKUP_ENCRYPTION" || exit 1
    echo "Error: 加密模式 '${BACKUP_ENCRYPTION}' 未进入任何已知分发支" >&2
    exit 1
    ;;
esac

echo "Backup completed successfully: $BACKUP_FILE_FINAL ($(wc -c < "$BACKUP_FILE_FINAL") bytes)"
echo "Backup size: $(du -h "$BACKUP_FILE_FINAL" | cut -f1)"
echo "Checksum: $BACKUP_FILE_FINAL.sha256"

# 异地副本（P1-① 的另一半：单机副本在"机器没了"面前等于没有备份）。
# 值按 argv 解析后直接 exec（rclone copy / scp 目标 …），不经过 shell 展开——
# 命令注入面为零；代价是不支持 $VAR 展开与引号聚合（写不过来的复杂同步逻辑
# 请包成自己的脚本再填路径）。失败即整体失败：被吞掉的异地失败比没有异地更
# 危险——它让运维以为自己有异地副本。
# 判据是"有没有切出词"，不是"字符串是否非空"：`BACKUP_OFFSITE_CMD=" "`（env 文件里
# 多打一个空格就够了）非空 ⇒ 进分支，`read -a` 却切出 0 个词，而空数组在命令位置是
# **空命令**——实测 bash 5.3.9 返回 0。于是异地副本一次都没执行，回显却是
# "Offsite copy completed:"，连 unset 那支的 Warning 都不打。这是上面那句
# "被吞掉的异地失败比没有异地更危险"里最坏的一种：它连"失败"都不算，没有任何信号。
# 顺带让 `"${OFFSITE_ARGS[@]}"` 只在词数 > 0 时展开，老 bash（4.2/4.3，RHEL7 一类宿主）
# 在 `set -u` 下展开空数组会直接掐死调用方，旧写法对那批宿主是"备份到最后一步崩"。
read -r -a OFFSITE_ARGS <<< "${BACKUP_OFFSITE_CMD:-}"
if [ "${#OFFSITE_ARGS[@]}" -gt 0 ]; then
  export BACKUP_FILE="$BACKUP_FILE_FINAL"
  export BACKUP_SHA256="$BACKUP_FILE_FINAL.sha256"
  if ! "${OFFSITE_ARGS[@]}"; then
    echo "Error: 异地副本命令失败（BACKUP_OFFSITE_CMD），本次备份按失败处理" >&2
    exit 1
  fi
  echo "Offsite copy completed: $BACKUP_OFFSITE_CMD"
elif [ -n "${BACKUP_OFFSITE_CMD:-}" ]; then
  # 配了而一个词都没切出来：这是配置错误，不是"决定不做异地"。与异地命令失败同档处理
  # （那档本来就是 exit 1），免得一次拼错的副本看起来像一次成功的备份。
  echo "Error: BACKUP_OFFSITE_CMD 已设置但只含空白，异地副本一步都没有执行；本次备份按失败处理" >&2
  exit 1
else
  echo "Warning: 未配置 BACKUP_OFFSITE_CMD——备份只存在于本机。等保 2.0 与 P1-① 都要求异地副本。" >&2
fi

# 清理过期备份。
# 实测：find 在**没有任何文件匹配**时返回 0，所以旧写法末尾的 `|| true` 并不是
# 防"无匹配"（注释是错的），它只会在真实故障时（谓词非法、目录不可读、-delete 权限不足）
# 把退出码抹平——恰是最需要看见错误的那一类。
# 这里改为显式分叉：清理失败要喊出来，但不让一次已成功的备份整体判失败
# （scripts/deploy.js 见到非零退出会中止发布；备份已经在手了）。
# 匹配模式覆盖加密产物（.gz.gpg）与校验和（.sha256）：过期清理漏掉任何一种
# 都会让 backups/ 单向膨胀（校验和通常先被漏掉——它比归档晚出现）。
echo "Pruning backups older than $RETENTION_DAYS days"
if ! find "$BACKUP_DIR" \( -name "fire-safety-backup-*.gz" -o -name "fire-safety-backup-*.gz.gpg" -o -name "fire-safety-backup-*.sha256" \) -mtime "+$RETENTION_DAYS" -delete; then
  echo "Warning: 过期备份清理失败（备份本身已成功，不阻断发布）——请看上面的 find 报错。" >&2
fi

echo "Backup process finished at $(date)"
