#!/bin/sh
# 文件型 secret 的权限适配入口（2026-10-24）
#
# 为什么需要它：docker compose 的 `secrets: file:` 在 Linux 上是 **bind mount**，
# 容器内看到的属主/权限就是宿主机文件本身（Compose issue #9648）。本仓
# scripts/generate-secrets.js 刻意把密钥落成 0600、目录 0700（属主＝部署用户），
# 而镜像里的应用进程是 UID 1001（nodejs）——1001 既不是属主、也不在属组，
# 直接读 /run/secrets/* 会 EACCES，服务在 config/secrets.js 的 readFileSync 处
# 启动失败。`secrets:` 的 uid/gid/mode 对 file 型 secret 不生效，把宿主机权限
# 降成 0644 又等于牺牲 at-rest 保护，所以只能在容器启动时做一次
# 「复制 → 收紧 → 改属主」。
#
# 设计取舍：
#   - 副本只落 tmpfs（compose 的 /run/app-secrets），不写镜像层；根文件系统只读；
#   - 副本 0400、目录 0500，属主 nodejs；root 只存在于入口阶段，随后 su-exec
#     降权，dumb-init 与 node 都以 nodejs 运行；
#   - 不改 compose 里的 `*_FILE=/run/secrets/...`（那是 Docker 的挂载点，也是
#     部署合同的锚点），而是在本脚本内把指针重写到副本路径。宿主机侧看到的
#     compose 文本仍是熟悉的挂载点，容器内读的则是 UID 1001 可读的副本。
#   - 任何一步失败都退出（set -eu），不带着半套密钥启动。

set -eu

SECRET_SRC=/run/secrets
SECRET_DST=/run/app-secrets

# 把 `*_FILE=/run/secrets/<name>` 重写到副本路径。只改指针，不改值。
# 用 for + case 而不是 `env | while read`：后者在管道子 shell 里执行，
# `exit` 退不出主脚本。这里的 *_FILE 值都是 compose 写死的路径（不含空格），
# 因此按 shell 默认 IFS 切分是安全的。
rewrite_file_pointers() {
  for entry in $(env); do
    case "$entry" in
      *_FILE=/run/secrets/*)
        var=${entry%%=*}
        path=${entry#*=}
        name=${path#/run/secrets/}
        export "$var=$SECRET_DST/$name"
        ;;
    esac
  done
}

# 逐个检查 *_FILE 指针。$1 为检查命令前缀（root 分支以 nodejs 身份检查，
# 非 root 分支直接检查当前用户）——权限问题必须在入口处说清楚，
# 不能留给 config/secrets.js 在启动中途报一个与密钥无关的错误。
verify_file_pointers() {
  for entry in $(env); do
    case "$entry" in
      *_FILE=*)
        path=${entry#*=}
        if ! "$@" "$path"; then
          echo "app-entrypoint: $entry 指向的密钥文件不存在或不可读：$path" >&2
          echo "app-entrypoint: file 型 secret 在 Linux 上保留宿主机属主/权限。" >&2
          echo "app-entrypoint: 请用 docker compose（app 服务的 user: 0:0 + cap_add）启动，" >&2
          echo "app-entrypoint: 或自行保证运行应用的用户能读取该文件。" >&2
          exit 1
        fi
        ;;
    esac
  done
}

# 以 nodejs 身份测试可读性。这里不能再依赖 `test` 是外部命令：
# Alpine 的 test 是 shell 内建，su-exec 需要真的 execve 一个程序。
nodejs_can_read() {
  su-exec nodejs:nodejs sh -c 'test -r "$1"' sh "$1"
}

# 容器以 root 启动时 Docker 会把 HOME 设为 /root；su-exec 只改 uid/gid，
# 不会重设 HOME。降权后若 HOME 仍指向 /root，任何尝试在 HOME 下写缓存的
# 工具都会 EACCES（根文件系统还是只读的）。按 passwd 里的 nodejs home 重设。
set_nodejs_home() {
  nodejs_home=$(grep '^nodejs:' /etc/passwd | cut -d: -f6)
  if [ -n "$nodejs_home" ]; then
    export HOME="$nodejs_home"
  fi
  export USER=nodejs
  export LOGNAME=nodejs
}
# 升级队列目录：宿主代理与应用通过 bind mount 共享（应用只**写 requests**、
# 只**读 status/processing**）。属主矩阵按「谁真的需要写」分配，不是一律 chown nodejs：
#   requests    nodejs:nodejs  0700   应用写、代理读
#   status      root:nodejs    0750   代理写、应用只读（含镜像 digest 与发起人）
#   processing  root:nodejs    0750   同上（已认领请求同样含镜像与发起人）
#   rejected    root:root      0700   只有代理看；给应用写权限等于让它删验签失败留证
# 一律 chown nodejs 的后果：应用被攻陷后可删 .agent.lock（升级永久 busy）、
# 写 status/<id>{"state":"succeeded"}（界面假成功、请求被丢弃）、清空 rejected（取证消失）。
# 目录不存在时（本地 docker run 未挂载）静默跳过：升级不可用，但服务照常启动。
QUEUE_DIR=${UPGRADE_QUEUE_DIR:-/var/lib/fsms/upgrade}
prepare_upgrade_queue() {
  [ -d "$QUEUE_DIR" ] || return 0
  # 下面会对目录树做 chown。误配成 /、/var/lib、/etc 之类时，容器 root 会把宿主
  # 大量文件的属主改成 UID 1001——宿主权限体系被破坏，且事后很难解释。
  # 只接受绝对路径，且不得是系统目录本身。
  case "$QUEUE_DIR" in
    /*) : ;;
    *)
      echo "app-entrypoint: 警告：UPGRADE_QUEUE_DIR 必须是绝对路径，已跳过权限适配：$QUEUE_DIR" >&2
      return 0
      ;;
  esac
  case "$QUEUE_DIR" in
    / | /var | /var/lib | /var/log | /etc | /etc/* | /usr | /usr/* | /home | /home/* | /root | /root/* | /tmp | /run)
      echo "app-entrypoint: 警告：UPGRADE_QUEUE_DIR 指向系统目录，已跳过权限适配：$QUEUE_DIR" >&2
      return 0
      ;;
  esac
  if ! mkdir -p \
    "$QUEUE_DIR/requests" \
    "$QUEUE_DIR/status" \
    "$QUEUE_DIR/processing" \
    "$QUEUE_DIR/rejected"; then
    echo "app-entrypoint: 警告：升级队列目录不可写，应用内升级将不可用：$QUEUE_DIR" >&2
    return 0
  fi

  # 顺序必须是「先收回 root，再 chmod，最后按矩阵交出属主」：本容器 cap_drop: ALL
  # 且刻意不补 FOWNER，对**已属 nodejs** 的目录再 chmod 必然 EPERM；脚本是 set -eu，
  # 一次 EPERM 就终止入口——第二次启动、app-green 启动、compose run 的一次性迁移
  # 容器都会踩到（升级窗口里恰好是最不能起不来的时刻）。
  chown root:root \
    "$QUEUE_DIR" \
    "$QUEUE_DIR/requests" \
    "$QUEUE_DIR/status" \
    "$QUEUE_DIR/processing" \
    "$QUEUE_DIR/rejected" 2>/dev/null || true
  # 只读 bind / root-squash 会让下面任意一条 chmod/chgrp 失败，而入口是 set -eu：
  # 单条失败就终止容器——升级窗口里最不能起不来的恰恰是这个容器。整块做失败容忍：
  # 改不动就告警放行，升级不可用但服务照常启动（compose run 的一次性迁移容器同理）。
  # 命令之间必须是 && 而不是逐行并列：`{ a; b; c; }` 的退出码只取**最后一条**，
  # 而 if 的条件列表又不受 set -e 约束——中间任何一条 EPERM 都会被静默吞掉，剩下的
  # 命令继续执行，于是"改不动就告警放行"对中间几条根本不成立。&& 一断即失败。
  if ! {
    chmod 0750 "$QUEUE_DIR" &&
      chmod 0700 "$QUEUE_DIR/requests" &&
      chmod 0700 "$QUEUE_DIR/rejected" &&
      chmod 0750 "$QUEUE_DIR/status" &&
      chmod 0750 "$QUEUE_DIR/processing" &&
      chown nodejs:nodejs "$QUEUE_DIR/requests" &&
      chgrp nodejs "$QUEUE_DIR" "$QUEUE_DIR/status" "$QUEUE_DIR/processing" &&
      chown root:root "$QUEUE_DIR/rejected"
  } 2>/dev/null; then
    # 2026-10-30 审计修正：此处原先写成「成功走 else、失败走 :」，与上面那句注释正好相反——
    # 于是成功时打出一条**假告警**并 return 0（下面的 find 归一化整段被跳过，队列文件归属
    # 永远不修正），失败时反而静默继续。现在按注释的本意：整块改不动就告警放行。
    echo "app-entrypoint: 警告：升级队列权限适配失败（只读挂载或 root-squash？），应用内升级将不可用：$QUEUE_DIR" >&2
    return 0
  fi

  # 只处理这四棵树，-xdev 不跨文件系统、不跟随符号链接：应用对 requests 可写，
  # 被攻陷后可放一个指向宿主文件的链接，`chown -R` 会改到宿主关键文件。
  find "$QUEUE_DIR/requests" -xdev -type d -exec chown nodejs:nodejs {} + 2>/dev/null || true
  find "$QUEUE_DIR/requests" -xdev -type f -exec chown nodejs:nodejs {} + 2>/dev/null || true
  # status/processing 由 root 代理写、应用只读：属主 root、属组 nodejs、0640。
  find "$QUEUE_DIR/status" "$QUEUE_DIR/processing" -xdev -type f \
    -exec chown root:nodejs {} + -exec chmod 0640 {} + 2>/dev/null || true
  find "$QUEUE_DIR/rejected" -xdev -type f \
    -exec chown root:root {} + -exec chmod 0600 {} + 2>/dev/null || true
}

if [ "$(id -u)" = "0" ]; then
  if [ -d "$SECRET_SRC" ]; then
    mkdir -p "$SECRET_DST"
    # tmpfs 在容器启动时是空的，但同一容器内重启进程可能留下上一轮副本；
    # 先清掉，避免已从 compose 删除的 secret 仍以旧值存在。
    rm -f "$SECRET_DST"/* 2>/dev/null || true
    for src in "$SECRET_SRC"/*; do
      [ -f "$src" ] || continue
      name=${src##*/}
      cp "$src" "$SECRET_DST/$name"
      # 顺序要紧：先 chmod（此时 root 仍是文件属主，可改 mode），再 chown。
      # 反过来会在 cap_drop: ALL + 最小 cap_add 下失败——chown 之后 root
      # 已不是属主，chmod 需要 FOWNER，而本容器刻意不补这项 capability。
      chmod 0400 "$SECRET_DST/$name"
      chown nodejs:nodejs "$SECRET_DST/$name"
    done
    chmod 0500 "$SECRET_DST"
    chown nodejs:nodejs "$SECRET_DST"
    rewrite_file_pointers
  fi
  prepare_upgrade_queue
  # 即使 /run/secrets 不存在（例如本地没挂 secret），只要 compose 仍给了
  # *_FILE 指针，就在这里以 nodejs 身份把「读不到」说清楚。
  verify_file_pointers nodejs_can_read
  set_nodejs_home
  # dumb-init 以 nodejs 身份成为 PID 1，再由它启动 CMD。这样 root 只存在于
  # 复制密钥的短暂窗口；应用与 PID 1 都是非 root。
  exec su-exec nodejs:nodejs dumb-init -- "$@"
fi

# 非 root 启动（镜像默认 USER nodejs，例如直接 docker run）：没有权限复制
# 或改属主，只能要求部署方自己保证指针可读。
verify_file_pointers test -r
exec dumb-init -- "$@"
