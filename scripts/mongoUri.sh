#!/bin/sh
# shellcheck shell=sh
#
# 「把 MongoDB URI 的主机段换成容器内地址」的唯一实现
#
# 为什么单独成文件：backup-mongo.sh 与 restore-mongo.sh 各自维护过一份一模一样的
# `sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1${MONGO_CONTAINER_HOST}#"`，
# 而两处的失败判据都是"替换后与原串相同 ⇒ 认定形态不认识"。这个判据有个真实的假阳性：
# 无凭据且主机本来就写成了目标地址（`mongodb://127.0.0.1:27017/fsms`，在容器内跑脚本时
# 就是这一形态）会被判成"URI 形态异常"而拒绝执行——备份/恢复在最需要它们的时候报错。
# 收敛成一处后，两个脚本共用同一判据：
#   · 先正认提取主机段，认不出来才算形态异常；
#   · 主机段已经等于目标地址 ⇒ 合法的空操作，放行；
#   · 其余情形必须真的发生变化，否则按不认识处理（宁可拒，也不要静默连到宿主机名上）。
# 凭据段与查询串一律原样保留：调用方随后把结果写进 0600 的配置或管道，绝不上 argv。

mongo_swap_host() {
  _uri=$1
  _target=$2

  case "$_uri" in
    mongodb://* | mongodb+srv://*) ;;
    *) return 1 ;;
  esac

  _host=$(printf '%s' "$_uri" | sed -E 's#^mongodb(\+srv)?://([^/]*@)?([^/]*)(/.*)?$#\3#')
  if [ -z "$_host" ] || [ "$_host" = "$_uri" ]; then
    # sed 没有命中 ⇒ 不是可识别的 `scheme://[creds@]host[/db][?opts]` 形态
    return 1
  fi

  if [ "$_host" = "$_target" ]; then
    printf '%s' "$_uri"
    return 0
  fi

  _swapped=$(printf '%s' "$_uri" |
    sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1${_target}#")
  if [ -z "$_swapped" ] || [ "$_swapped" = "$_uri" ]; then
    return 1
  fi
  printf '%s' "$_swapped"
}
