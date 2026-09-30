#!/bin/bash

# MongoDB 备份脚本
# 用法: ./scripts/backup-mongo.sh [backup_dir]
#
# 环境变量：
#   MONGODB_URI             必填，含凭据的连接串
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
if [ -z "${MONGODB_URI:-}" ]; then
  echo "Error: MONGODB_URI environment variable is not set" >&2
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
cleanup() {
  if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
    rm -f "$CONFIG_FILE"
  fi
}
trap cleanup EXIT INT TERM

OLD_UMASK=$(umask)
umask 077
CONFIG_FILE=$(mktemp "${TMPDIR:-/tmp}/mongodump-config.XXXXXX")
# umask 之外再显式 chmod：双保险，且让"仅属主可读"成为代码里可见的意图。
# 注意：在 Git Bash/MSYS（Windows）下 stat 恒报 644 —— NTFS 不承载 POSIX
# 权限位，chmod 与 umask 在该环境均为空操作。本脚本的目标运行环境是
# Linux 服务器 / 容器，那里两者都真实生效。
chmod 600 "$CONFIG_FILE"
printf 'uri: %s\n' "$MONGODB_URI" > "$CONFIG_FILE"
umask "$OLD_UMASK"

echo "Starting MongoDB backup at $(date)"

# 执行备份。两条路径的共同点：含凭据的 URI 只出现在 0600 的配置文件里或管道里，
# 绝不出现在任何 argv 上（P2-27 的原始动机）。
case "$MONGO_BACKUP_TRANSPORT" in
  local)
    mongodump --config="$CONFIG_FILE" --archive="$ARCHIVE_PATH" --gzip
    ;;
  docker)
    # 只把主机段换成容器内地址：账号、口令、库名与查询参数原样保留
    # 主机段换成容器内地址：账号、口令、库名与查询串原样保留。判据与 restore 共用
    # scripts/mongoUri.sh（同一份 sed 原先在两个脚本里各写一遍，失败判据还会各自漂移）。
    # 静默按原 URI 在容器里跑就会连到宿主机名，得到"备份失败"这种最难查的表象。
    if ! CONTAINER_URI=$(mongo_swap_host "$MONGODB_URI" "$MONGO_CONTAINER_HOST"); then
      echo "Error: 无法把 URI 主机段改写为容器内地址（${MONGO_CONTAINER_HOST}），请检查 MONGODB_URI 形态" >&2
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
# 默认 gpg 非对称加密（归档 → 归档.gz.gpg + .sha256，明文归档随后删除）。
# 明文出口的取值本身就是一句确认词——它必须出现在环境配置里才生效，
# 任何"忘了配加密"的部署会在这一步硬失败，而不是静默产出明文全量库。
BACKUP_ENCRYPTION=${BACKUP_ENCRYPTION:-gpg}
case "$BACKUP_ENCRYPTION" in
  gpg)
    crypto_require_gpg || exit 1
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
    # 明文归档完成历史使命：加密副本 + 校验和在手的瞬间就地删除。
    # 留着它 = P1-① 的缺口原样存在，只是多花了一次加密的 CPU。
    rm -f "$ARCHIVE_PATH"
    BACKUP_FILE_FINAL="$ENCRYPTED_PATH"
    ;;
  plaintext-acknowledged)
    echo "ERROR-LEVEL WARNING: BACKUP_ENCRYPTION=plaintext-acknowledged——本次备份是明文全量库，" >&2
    echo "  含全部人员 PII 与不可篡改审计集合。此选择必须已在部署文档记录理由与补偿控制。" >&2
    crypto_checksum "$ARCHIVE_PATH"
    BACKUP_FILE_FINAL="$ARCHIVE_PATH"
    ;;
  *)
    echo "Error: BACKUP_ENCRYPTION 只能是 gpg 或 plaintext-acknowledged（当前：'${BACKUP_ENCRYPTION}'）" >&2
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
if [ -n "${BACKUP_OFFSITE_CMD:-}" ]; then
  read -r -a OFFSITE_ARGS <<< "$BACKUP_OFFSITE_CMD"
  export BACKUP_FILE="$BACKUP_FILE_FINAL"
  export BACKUP_SHA256="$BACKUP_FILE_FINAL.sha256"
  if ! "${OFFSITE_ARGS[@]}"; then
    echo "Error: 异地副本命令失败（BACKUP_OFFSITE_CMD），本次备份按失败处理" >&2
    exit 1
  fi
  echo "Offsite copy completed: $BACKUP_OFFSITE_CMD"
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
