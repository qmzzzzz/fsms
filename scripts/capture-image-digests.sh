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
#   sh scripts/capture-image-digests.sh --apply --root=<dir>   # 测试/排障：对指定仓库副本操作
#
# 替换后请执行 `docker compose config` 与 `docker build .` 验证。

set -eu

NODE_TAG="node:22.14.0-alpine"
MONGO_TAG="mongo:6.0.20"
APPLY=0
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# 参数解析用 while+case：原先的 `[ "$1" = --apply ] && APPLY=1` 只看第一个参数，
# 把 --root 放在前面就会静默不生效（实测过同类"顺序敏感"的脚本坑）。
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --root=*) ROOT=$(CDPATH= cd -- "${arg#--root=}" && pwd) ;;
    *) echo "错误：未知参数 '$arg'（支持 --apply / --root=<dir>）" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "错误：未找到 docker 命令"; exit 1; }
docker info >/dev/null 2>&1 || { echo "错误：Docker 守护进程未运行，请先启动"; exit 1; }

echo "==> 拉取 $NODE_TAG 与 $MONGO_TAG（可能耗时数分钟）"
docker pull "$NODE_TAG"
docker pull "$MONGO_TAG"

# `{{index .RepoDigests 0}}` 有两个实测过的失败形态：
#   ① 本地镜像是 build/load 出来的（无 registry 来源）⇒ 切片为空，docker 直接报错；
#   ② 某些 docker 版本对缺失字段打印 `<no value>` 而不是报错 ⇒ 后面替换会把
#      `FROM <no value>` 写进 Dockerfile，构建期才炸，而且炸在一个"看起来已钉版"的文件里。
# 因此取值后立刻校验形状：必须是 name@sha256:64 位十六进制。
# 注意：本函数在 `$( )` 里执行 ⇒ 报错要打 stderr，并用非零退出让**赋值语句**失败
# （set -e 下 `VAR=$(...)` 的命令替换返回非零会终止脚本；实测确认，别依赖函数里的 echo）。
capture_digest() {
  tag=$1
  digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$tag" 2>/dev/null || true)
  if ! printf '%s' "$digest" | grep -Eq '@sha256:[0-9a-f]{64}$'; then
    printf '错误：取不到 %s 的 registry digest（得到：%s）。\n' "$tag" "'${digest:-空}'" >&2
    printf '       多为本机镜像是 build/load 而来（无 digest）或 docker 输出异常；\n' >&2
    printf '       请在有拉取权限的机器上重新 pull，不要在拿不到 digest 时手工抄。\n' >&2
    return 1
  fi
  printf '%s' "$digest"
}

NODE_DIGEST=$(capture_digest "$NODE_TAG") || exit 1
MONGO_DIGEST=$(capture_digest "$MONGO_TAG") || exit 1

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

# 替换 + **验证替换确实发生了**。
# 为什么必须验证：sed 没匹配到任何内容时退出码仍是 0。原先脚本在两种情况下会
# "报告成功但一个字都没改"：① 已经钉过 digest 之后再跑一次（幂等重跑）；
# ② Dockerfile/compose 里的 tag 写法与本文件顶部的常量漂移（例如有人升级了 tag）。
# 而这个脚本的职责是**供应链钉版**——静默 no-op 会让一份仍指向可变 tag 的
# Dockerfile 被当成"已按 digest 固定"提交上去。
# addr 是**行定位正则**：只在指令行上替换。
# 实测教训：compose 里 `image: mongo:6.0.20` 这个字面串同时出现在一段注释里
# （"把输出追加为 `image: mongo:6.0.20@sha256:<捕获值>`"），不带 addr 的全文 sed 会把
# 注释一起改掉——注释是给人读的用法示例，改掉之后它就成了错误示例。
#
# 为什么拆成 check / stage / commit 三相（原先是一个 pin_ref 边检查边落笔，两个目标顺序跑）：
# 实测的半钉状态——Dockerfile 正常、compose 的 tag 漂移 ⇒
#   第一轮：Dockerfile 被改成 digest，compose 那步报错退出 rc=1，仓库留下"半钉"；
#   第二轮（运维把 compose 的 tag 修好再跑）：脚本在 Dockerfile 那一步就撞
#   "已经存在 @sha256 钉版引用"退出，compose **永远钉不上**。
# 也就是说旧顺序不仅会半途落笔，还会把半途状态变成死路：供应链钉版的产物是一个
# compose 仍指向可变 tag 的仓库，而唯一能修它的脚本自己拒绝再跑。
# 现在 check 阶段只读（两个目标都确认可改，包括"临时文件不存在"），stage 阶段只写临时文件，
# commit 阶段才 mv——任何一步失败，目标文件都是原样。
# 诚实交代残余边界：两条 `mv` 之间不是原子的（跨两个文件不存在 single-phase rename）。
# 之所以够用：check 已确认两文件都在且都可改，stage 已把两改好的内容验过一遍，
# 到 commit 只剩同目录 rename——失败面从"任何解析/匹配错"缩到"rename 本身出错"。
check_ref() {
  addr=$1
  file=$2
  old=$3
  label=$4
  tmp=$5
  if [ ! -f "$file" ]; then
    echo "错误：找不到 $label：$file" >&2
    exit 1
  fi
  # 残留的临时文件必须**先看见再说**：它可能是上一次运行中断留下的，也可能是别人放的。
  # 本脚本既不覆盖它也不在退出时删它（下面的 trap 只删自己创建过的那些）。
  if [ -e "$tmp" ]; then
    echo "错误：$label 的临时文件已存在：$tmp" >&2
    echo "       可能是上一次中断的运行留下的残留；确认无用后请人工删除再重跑。" >&2
    exit 1
  fi
  # 只在符合 addr 的行里找旧引用（注释里的同名字面串不算）
  if ! sed -n "/$addr/p" "$file" | grep -qF "$old"; then
    if sed -n "/$addr/p" "$file" | grep -qF 'sha256:'; then
      echo "错误：$label 的指令行里找不到 '$old'，但已经存在 @sha256 钉版引用。" >&2
      echo "       两种可能：(a) 已经钉过 —— 那是 no-op，不该被报成成功；" >&2
      echo "                 (b) 钉的是**别的** digest —— 请核对顶部常量与文件里的 tag 是否漂移。" >&2
      echo "       确认要更新请先把旧引用改回可识别的 tag，或人工替换。" >&2
      exit 1
    fi
    echo "错误：$label 的指令行里找不到 '$old'，也没有已钉版引用 ⇒ 脚本常量与仓库文件已漂移。" >&2
    echo "       静默跳过会让未钉版的镜像引用被误认为已固定，请同步脚本顶部的 tag 常量。" >&2
    exit 1
  fi
}

stage_ref() {
  addr=$1
  file=$2
  old=$3
  new=$4
  label=$5
  tmp=$6
  # 先落到临时文件再原子替换：中途失败不会留下半改的目标文件
  sed "/$addr/s|$old|$new|g" "$file" > "$tmp"
  # 预演校验：临时文件里新引用必须出现、旧引用必须消失（mv 之后再报就晚了）
  if ! sed -n "/$addr/p" "$tmp" | grep -qF "$new" ||
    sed -n "/$addr/p" "$tmp" | grep -qF "$old"; then
    rm -f "$tmp"
    echo "错误：$label 预演失败（新引用未出现或旧引用仍在），未改动任何目标文件。" >&2
    exit 1
  fi
}

commit_ref() {
  file=$1
  tmp=$2
  addr=$3
  new=$4
  label=$5
  mv "$tmp" "$file"
  if ! sed -n "/$addr/p" "$file" | grep -qF "$new"; then
    echo "错误：$label 替换后校验失败（mv 之后新引用不在指令行上）" >&2
    exit 1
  fi
  printf '%s → %s\n' "$label" "$new"
}

DOCKERFILE="$ROOT/Dockerfile"
COMPOSE="$ROOT/docker-compose.yml"
ADDR_FROM='^FROM '
ADDR_IMAGE='^[[:space:]]*image: '
TMP_DOCKERFILE="$DOCKERFILE.pin.tmp"
TMP_COMPOSE="$COMPOSE.pin.tmp"

# trap 只删**本脚本确认过"原本不存在"**的临时文件：这两个变量先置空，
# check_ref 通过后才赋值。少了这两步，退出时顺手 rm 掉的可能是别人放在这里的同名文件
# （check_ref 里那条"临时文件已存在"报错正是为了不覆盖它，不能转头又把它删了）。
PIN_TMP_DOCKERFILE=''
PIN_TMP_COMPOSE=''

cleanup_pin_tmp() {
  for _tmp in "$PIN_TMP_DOCKERFILE" "$PIN_TMP_COMPOSE"; do
    if [ -n "$_tmp" ] && [ -f "$_tmp" ]; then
      rm -f "$_tmp"
    fi
  done
  return 0
}
trap 'cleanup_pin_tmp' EXIT HUP INT TERM

echo "==> 目标仓库根：$ROOT"
echo "==> 只读检查两个目标（有一个不可改就一个字都不写）"
check_ref "$ADDR_FROM" "$DOCKERFILE" "FROM $NODE_TAG" "Dockerfile" "$TMP_DOCKERFILE"
PIN_TMP_DOCKERFILE="$TMP_DOCKERFILE"
check_ref "$ADDR_IMAGE" "$COMPOSE" "image: $MONGO_TAG" "docker-compose.yml" "$TMP_COMPOSE"
PIN_TMP_COMPOSE="$TMP_COMPOSE"

echo "==> 预演替换（只写临时文件）"
echo "    钉定 Dockerfile 中的基础镜像（全部阶段同一 digest）"
stage_ref "$ADDR_FROM" "$DOCKERFILE" "FROM $NODE_TAG" "FROM $NODE_DIGEST" "Dockerfile" "$TMP_DOCKERFILE"
echo "    钉定 docker-compose.yml 中的 mongo 镜像"
stage_ref "$ADDR_IMAGE" "$COMPOSE" "image: $MONGO_TAG" "image: $MONGO_DIGEST" "docker-compose.yml" "$TMP_COMPOSE"

echo "==> 落笔（临时文件原子改名，两侧都校验）"
commit_ref "$DOCKERFILE" "$TMP_DOCKERFILE" "$ADDR_FROM" "FROM $NODE_DIGEST" "Dockerfile"
commit_ref "$COMPOSE" "$TMP_COMPOSE" "$ADDR_IMAGE" "image: $MONGO_DIGEST" "docker-compose.yml"

echo
echo "已替换并校验。请验证："
echo "  docker compose -f $ROOT/docker-compose.yml config >/dev/null && echo compose-ok"
echo "  docker build $ROOT --target builder   # 或直接完整构建"
