#!/usr/bin/env sh
# 捕获基础镜像 digest 并钉入 Dockerfile / docker-compose.yml（R-5）
#
# 为什么必须本机捕获：digest 是 registry 内容的哈希，随上游补丁滚动；
# 凭记忆或从别处抄来的 digest 可能与本地 tag 不一致，部署时才炸。
# 在**部署机**（或有拉取权限的构建机）执行本脚本。
#
# 用法：
#   sh scripts/capture-image-digests.sh            # 只打印，人工核对后自行替换
#   sh scripts/capture-image-digests.sh --apply    # 自动替换 Dockerfile 与 compose
#
# 替换后请执行 `docker compose config` 与 `docker build .` 验证。

set -eu

NODE_TAG="node:22.14.0-alpine"
MONGO_TAG="mongo:6.0.20"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

command -v docker >/dev/null 2>&1 || { echo "错误：未找到 docker 命令"; exit 1; }
docker info >/dev/null 2>&1 || { echo "错误：Docker 守护进程未运行，请先启动"; exit 1; }

echo "==> 拉取 $NODE_TAG 与 $MONGO_TAG（可能耗时数分钟）"
docker pull "$NODE_TAG"
docker pull "$MONGO_TAG"

NODE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$NODE_TAG")
MONGO_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$MONGO_TAG")

echo
echo "捕获结果："
echo "  node : $NODE_DIGEST"
echo "  mongo: $MONGO_DIGEST"

if [ "$APPLY" -ne 1 ]; then
  echo
  echo "未加 --apply，不改动文件。确认后执行："
  echo "  sh scripts/capture-image-digests.sh --apply"
  exit 0
fi

# 仓库根目录（脚本在 scripts/ 下）
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "==> 替换 Dockerfile 中的 FROM $NODE_TAG（全部阶段同一 digest）"
# sed -i 兼容 GNU/BSD 写法；tag@digest 保留可读 tag
sed -i.bak "s|FROM $NODE_TAG|FROM $NODE_DIGEST|g" "$ROOT/Dockerfile" && rm -f "$ROOT/Dockerfile.bak"

echo "==> 替换 docker-compose.yml 中的 image: $MONGO_TAG"
sed -i.bak "s|image: $MONGO_TAG|image: $MONGO_DIGEST|g" "$ROOT/docker-compose.yml" && rm -f "$ROOT/docker-compose.yml.bak"

echo
echo "已替换。请验证："
echo "  docker compose config >/dev/null && echo compose-ok"
echo "  docker build . --target builder   # 或直接完整构建"
