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
