#!/bin/bash

# MongoDB 恢复脚本
# 用法: ./scripts/restore-mongo.sh <backup_file>
#
# 环境变量：
#   MONGODB_URI      必填，目标库连接串
#   RESTORE_CONFIRM  非交互场景下的确认令牌，须等于目标库名
#   MONGO_RESTORE_TRANSPORT 可选，local | docker（默认 docker，与 backup-mongo.sh 同口径）
#   MONGO_COMPOSE_SERVICE   可选，容器内执行 mongorestore 的服务名（默认 mongo）
#   MONGO_CONTAINER_HOST    可选，容器内连接地址（默认 127.0.0.1:27017）
#   COMPOSE_FILE            可选，compose 文件路径（默认 docker-compose.yml）
#
# 【P1-① 加密归档】（2026-09-30）：backup-mongo.sh 默认产出 .gz.gpg（gpg 非对称
# 加密，见 scripts/backupCrypto.sh）。本脚本按**后缀**自动识别：*.gz.gpg 先解密到
# 0600 临时文件再走既有恢复链路；*.gz 旧归档原样支持。解密需要**私钥**——
# 它按设计不在备份宿主机上，恢复演练就是验证"私钥托管 + 异地副本"这条链的。
#
# 【P2-27 恢复必须有门禁】
# 恢复是**破坏性**操作：mongorestore 会把归档内容写入目标库，
# 原实现仅检查文件存在与 URI 非空便直接执行——把生产 URI 填错一次即覆盖生产数据，
# 且无任何二次确认。此处补三道门禁：
#   1. 解析并回显目标主机与库名（让操作者看到自己到底在恢复到哪）
#   2. 交互式终端要求键入库名确认；非交互（CI/cron）要求 RESTORE_CONFIRM 匹配库名
#   3. --drop 需显式 RESTORE_DROP=true，默认不删除既有集合
#
# 另：原实现在 `set -e` 下写了 `if [ $? -eq 0 ]; ... else ... fi`，
# mongorestore 一旦失败脚本已经退出，else 分支永远不会执行——是误导运维的死代码，已移除。

set -euo pipefail

# 与 backup-mongo.sh 共用同一个 URI 主机段改写判据（见该文件注释）
. "$(dirname "$0")/mongoUri.sh"
# 加密/解密/校验和的共享实现（P1-①）：.gz.gpg 归档的解密走这里
. "$(dirname "$0")/backupCrypto.sh"

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <backup_file>" >&2
  echo "Example: $0 backups/fire-safety-backup-20240101-1200.gz" >&2
  exit 1
fi

BACKUP_FILE=$1

if [ ! -f "$BACKUP_FILE" ]; then
  echo "Error: Backup file not found: $BACKUP_FILE" >&2
  exit 1
fi

if [ -z "${MONGODB_URI:-}" ]; then
  echo "Error: MONGODB_URI environment variable is not set" >&2
  exit 1
fi

# 传输方式与 backup-mongo.sh 同口径：本仓 compose 里 mongo 只 `expose` 不 `publish`
# （URI 主机段是容器名），宿主机既连不上它、也常常没装 mongorestore CLI。
# 备份侧早就为此提供 docker 传输，恢复侧没有 ⇒ "数据级回滚抓手"要在真正用的那天
# 才发现跑不通，这是最贵的发现时机。默认 docker，local 仍保留给本机/直连场景。
MONGO_RESTORE_TRANSPORT=${MONGO_RESTORE_TRANSPORT:-docker}
MONGO_COMPOSE_SERVICE=${MONGO_COMPOSE_SERVICE:-mongo}
MONGO_CONTAINER_HOST=${MONGO_CONTAINER_HOST:-127.0.0.1:27017}

case "$MONGO_RESTORE_TRANSPORT" in
  local)
    if ! command -v mongorestore >/dev/null 2>&1; then
      echo "Error: mongorestore not found in PATH（MONGO_RESTORE_TRANSPORT=local）" >&2
      exit 1
    fi
    ;;
  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo "Error: docker 不在 PATH 中（MONGO_RESTORE_TRANSPORT=docker）" >&2
      exit 1
    fi
    ;;
  *)
    echo "Error: MONGO_RESTORE_TRANSPORT 只能是 local 或 docker（当前：'${MONGO_RESTORE_TRANSPORT}'）" >&2
    exit 1
    ;;
esac

# ================= 目标识别 =================
# 从 URI 中剥离凭据后提取 host 与库名用于回显（绝不打印口令部分）
URI_NO_CRED=${MONGODB_URI#*://}
URI_NO_CRED=${URI_NO_CRED#*@}
TARGET_HOST=${URI_NO_CRED%%/*}
TARGET_DB=${URI_NO_CRED#*/}
TARGET_DB=${TARGET_DB%%\?*}
if [ "$TARGET_DB" = "$URI_NO_CRED" ] || [ -z "$TARGET_DB" ]; then
  TARGET_DB="(未在 URI 中指定，将按归档内的库名恢复)"
fi

echo "=============================================="
echo " MongoDB 恢复操作（破坏性）"
echo "   归档文件 : $BACKUP_FILE"
echo "   目标主机 : $TARGET_HOST"
echo "   目标库名 : $TARGET_DB"
echo "   删除既有 : ${RESTORE_DROP:-false}"
echo "=============================================="

# ================= 门禁 =================
if [ -t 0 ]; then
  # 交互式终端：要求键入目标库名
  printf '请键入目标库名以确认恢复（Ctrl-C 取消）: '
  read -r ANSWER
  if [ "$ANSWER" != "$TARGET_DB" ]; then
    echo "Error: 确认输入与目标库名不一致，已取消" >&2
    exit 1
  fi
else
  # 非交互（CI / cron）：要求预置 RESTORE_CONFIRM
  if [ "${RESTORE_CONFIRM:-}" != "$TARGET_DB" ]; then
    echo "Error: 非交互环境需设置 RESTORE_CONFIRM=<目标库名> 才能执行恢复" >&2
    echo "       当前 RESTORE_CONFIRM='${RESTORE_CONFIRM:-}'，期望 '$TARGET_DB'" >&2
    exit 1
  fi
fi

# ================= 凭据保护（同 backup 口径） =================
CONFIG_FILE=""
DECRYPTED_FILE=""
cleanup() {
  if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
    rm -f "$CONFIG_FILE"
  fi
  if [ -n "$DECRYPTED_FILE" ] && [ -f "$DECRYPTED_FILE" ]; then
    rm -f "$DECRYPTED_FILE"
  fi
}
trap cleanup EXIT INT TERM

OLD_UMASK=$(umask)
umask 077
CONFIG_FILE=$(mktemp "${TMPDIR:-/tmp}/mongorestore-config.XXXXXX")
# umask 之外再显式 chmod（Windows/MSYS 下两者均为空操作，Linux 生效）
chmod 600 "$CONFIG_FILE"
printf 'uri: %s\n' "$MONGODB_URI" > "$CONFIG_FILE"
umask "$OLD_UMASK"

DROP_ARG=""
if [ "${RESTORE_DROP:-false}" = "true" ]; then
  echo "警告：已启用 --drop，目标库中同名集合将先被删除"
  DROP_ARG="--drop"
fi

# P1-①：加密归档先解密到 0600 临时文件（trap 清理），其余链路不变。
# 解密产物与归档同为 mongodump --gzip 形态，--gzip 参数两种来源通用。
DECRYPTED_FILE=""
case "$BACKUP_FILE" in
  *.gz.gpg)
    crypto_require_gpg || exit 1
    OLD_UMASK_DECRYPT=$(umask)
    umask 077
    DECRYPTED_FILE=$(mktemp "${TMPDIR:-/tmp}/mongorestore-decrypted.XXXXXX.gz")
    chmod 600 "$DECRYPTED_FILE"
    umask "$OLD_UMASK_DECRYPT"
    echo "检测到加密归档（$BACKUP_FILE），先解密到临时文件"
    if ! crypto_decrypt "$BACKUP_FILE" "$DECRYPTED_FILE"; then
      echo "Error: 解密失败（私钥缺失/口令错误/归档损坏）" >&2
      exit 1
    fi
    if [ ! -s "$DECRYPTED_FILE" ]; then
      echo "Error: 解密产物为 0 字节，归档可能已损坏" >&2
      exit 1
    fi
    BACKUP_FILE="$DECRYPTED_FILE"
    ;;
  *.gz) ;; # 明文旧归档：直接走既有链路
  *)
    echo "Error: 无法识别的归档后缀：$BACKUP_FILE（期望 .gz 或 .gz.gpg）" >&2
    exit 1
    ;;
esac

RESTORE_ARGS=(--config="$CONFIG_FILE" --archive="$BACKUP_FILE" --gzip)
if [ -n "$DROP_ARG" ]; then
  RESTORE_ARGS+=("$DROP_ARG")
fi

echo "Starting MongoDB restore from $BACKUP_FILE（transport=${MONGO_RESTORE_TRANSPORT}）"

# set -e 已保证失败即退出（退出码由 mongorestore / docker exec 传递给调用方），无需再判 $?
case "$MONGO_RESTORE_TRANSPORT" in
  local)
    mongorestore "${RESTORE_ARGS[@]}"
    ;;
  docker)
    # 主机段换成容器内地址：账号、口令、库名与查询串原样保留（判据与 backup 同一份）
    if ! CONTAINER_URI=$(mongo_swap_host "$MONGODB_URI" "$MONGO_CONTAINER_HOST"); then
      echo "Error: 无法把 URI 主机段改写为容器内地址（${MONGO_CONTAINER_HOST}），请检查 MONGODB_URI 形态" >&2
      exit 1
    fi
    # 一条 stdin 流里先送一行配置、再送归档：容器内 `IFS= read -r` 只吃掉第一行（我们写的那行），
    # 余下字节原样进 --archive。含凭据的 URI 因此既不出现在 argv/ps，也不落宿主机临时文件。
    # 归档要经容器 /tmp 落地一份（mongorestore 的 --config 只吃文件，stdin 已被配置行占用），
    # 这是与 backup 同源的取舍：宁可多占一份容器磁盘，也不把口令写进命令行。
    REMOTE_CMD="umask 077; IFS= read -r _uri_line; printf '%s\n' \"\$_uri_line\" > /tmp/.mongorestore.cfg;
cat > /tmp/.mongorestore.archive;
mongorestore --config=/tmp/.mongorestore.cfg --archive=/tmp/.mongorestore.archive --gzip ${DROP_ARG};
rc=\$?; rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive; exit \$rc"
    {
      printf 'uri: %s\n' "$CONTAINER_URI"
      cat "$BACKUP_FILE"
    } | docker compose -f "${COMPOSE_FILE:-docker-compose.yml}" exec -T "$MONGO_COMPOSE_SERVICE" \
      sh -c "$REMOTE_CMD"
    ;;
esac

echo "Restore completed successfully"
