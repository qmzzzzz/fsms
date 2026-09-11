#!/bin/bash

# MongoDB 备份脚本
# 用法: ./scripts/backup-mongo.sh [backup_dir]
#
# 环境变量：
#   MONGODB_URI            必填，含凭据的连接串
#   BACKUP_RETENTION_DAYS  可选，备份保留天数（默认 30）
#
# 【P2-27 凭据不上命令行】
# 原实现 `mongodump --uri="$MONGODB_URI"`：进程参数在 Linux 上对同机任意用户
# 可见（ps aux / /proc/<pid>/cmdline 全局可读），备份窗口内数据库口令持续暴露；
# shell history、CI 任务日志、进程监控采集器同样会留痕。
# 改用 mongodump 官方推荐的 --config 配置文件方式传递 uri：
# 文件以 umask 077 创建（仅属主可读），并在退出时无条件删除。

set -euo pipefail

BACKUP_DIR=${1:-"./backups"}
TIMESTAMP=$(date +%Y%m%d-%H%M)
BACKUP_FILE="fire-safety-backup-$TIMESTAMP.gz"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}

# 检查环境变量（在创建任何文件之前）
if [ -z "${MONGODB_URI:-}" ]; then
  echo "Error: MONGODB_URI environment variable is not set" >&2
  exit 1
fi

if ! command -v mongodump >/dev/null 2>&1; then
  echo "Error: mongodump not found in PATH" >&2
  exit 1
fi

# 创建备份目录
mkdir -p "$BACKUP_DIR"

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

# 执行备份（set -e 会在 mongodump 失败时自动退出，trap 负责清理凭据文件）
mongodump --config="$CONFIG_FILE" --archive="$BACKUP_DIR/$BACKUP_FILE" --gzip

echo "Backup completed successfully: $BACKUP_DIR/$BACKUP_FILE"
echo "Backup size: $(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)"

# 清理过期备份（加 || true 防止无匹配文件时 find 返回非 0）
echo "Pruning backups older than $RETENTION_DAYS days"
find "$BACKUP_DIR" -name "fire-safety-backup-*.gz" -mtime "+$RETENTION_DAYS" -delete || true

echo "Backup process finished at $(date)"
