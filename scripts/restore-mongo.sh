#!/bin/bash

# MongoDB 恢复脚本
# 用法: ./scripts/restore-mongo.sh <backup_file>
#
# 环境变量：
#   MONGODB_URI      必填，目标库连接串
#   RESTORE_CONFIRM  非交互场景下的确认令牌，须等于目标库名
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

if ! command -v mongorestore >/dev/null 2>&1; then
  echo "Error: mongorestore not found in PATH" >&2
  exit 1
fi

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
cleanup() {
  if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
    rm -f "$CONFIG_FILE"
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

RESTORE_ARGS=(--config="$CONFIG_FILE" --archive="$BACKUP_FILE" --gzip)
if [ "${RESTORE_DROP:-false}" = "true" ]; then
  echo "警告：已启用 --drop，目标库中同名集合将先被删除"
  RESTORE_ARGS+=(--drop)
fi

echo "Starting MongoDB restore from $BACKUP_FILE"

# set -e 已保证失败即退出（退出码由 mongorestore 传递给调用方），无需再判 $?
mongorestore "${RESTORE_ARGS[@]}"

echo "Restore completed successfully"
