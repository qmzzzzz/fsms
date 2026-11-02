#!/usr/bin/env bash
# 离线升级包构建（联机侧 / 有 registry 拉取权限的构建机执行）
#
# 为什么必须由脚本从 docker 取回 digest：在线升级的真相来自 registry（digest 是 registry
# 给的），离线升级的真相只能来自包本身。包一旦拷进 air-gap，目标机再没有任何外部来源能
# 证明"装进去的就是那一版"，所以 manifest 里的 ref / bytes / sha256 必须从 docker 的
# **实际结果**取回，而不是照操作者口述填写。判据的唯一来源是 scripts/offlineBundlePolicy.js，
# 导入器 scripts/importOfflineBundle.js 会逐条核对本脚本的产物；两者对不上时包会被（正确地）拒绝。
#
# 用法：
#   bash scripts/build-offline-bundle.sh --image <repo[:tag]|repo@sha256:<64hex>> \\
#        --version <版本号> --out <输出目录> [--build-id <CI 构建号>] [--sign-key <Ed25519 私钥.pem>]
#
# 产出（<outDir> 下，就是导入器要的形态）：
#   manifest.json          包清单（format=1、images[0].role=app）
#   manifest.sig           对 manifest.json 原始字节的 Ed25519 签名（给了 --sign-key 时才有）
#   SHA256SUMS             sha256 清单（sha256sum -c 兼容；覆盖 payload 与 manifest.sig，
#                          不含 manifest.json 自身——清单不能自我覆盖）
#   payload/fsms-app.tar   docker save 产物
#
# 当前只导出一个应用镜像：判据层 IMAGE_ROLES 目前只认 role=app（scripts/offlineBundlePolicy.js:34），
# 多角色必须与判据层同批扩展，否则包会被导入器拒绝。
#
# 关键取舍：
#   · 没有"演练"开关：本脚本只产出文件，真正的破坏性动作在导入侧（importOfflineBundle.js
#     默认演练）。这里的对应措施是"拒绝覆盖既有产物"＋"失败即清掉本次产物"——半截的包
#     在目标机上看起来和完整的包一模一样。
#   · 只依赖 bash + docker + sha256sum（+ 可选 openssl）：升级路径不该再拉进 node/jq 之类的新前提。
#     --sign-key 需要 OpenSSL ≥ 3.0（pkeyutl 的 Ed25519 -rawin 支持）；签名在构建机完成，
#     目标机只持公钥（scripts/offlineBundleSignature.js 验签），私钥永不进包。
#   · 未签名也能构建（向后兼容既有搬运流程），但目标机配了验签公钥时未签名包会被拒绝；
#     FSMS_BUNDLE_REQUIRE_SIGNATURE=1 可把"忘了带 --sign-key"从事故变成构建期报错。
#   · 用户给的引用与版本号一律当**数据**：只经 argv 传给 docker，绝不进 shell 求值；
#     写进 manifest 的值先收成"不需要转义"的字符集，因此这里没有第二套 JSON 转义实现。
#   · --out 不要指向仓库工作树内的路径：包动辄上 GB，一次 git add 会把整包带进版本库。

set -euo pipefail

USAGE='用法: bash scripts/build-offline-bundle.sh --image <repo[:tag]|repo@sha256:<64hex>> --version <版本号> --out <输出目录> [--build-id <CI 构建号>] [--sign-key <Ed25519 私钥.pem>] [--archive <输出归档.tar.gz>]'
FLAGS_TEXT='--image / --out / --version / --build-id / --sign-key / --archive / --help'
KNOWN_FLAGS=(--image --out --version --build-id --sign-key --archive --help)

ROLE='app'
PAYLOAD_REL='payload/fsms-app.tar'
MANIFEST_REL='manifest.json'
SIG_REL='manifest.sig'
SUMS_REL='SHA256SUMS'

# ================= 参数解析（未知参数报错、退出码 2、用法错误时 stdout 不留一个字节） =================

usage_error() {
  printf '错误：%s\n' "$1" >&2
  printf '%s\n' "$USAGE" >&2
  exit 2
}

# 只留字母的"形状"：连字符数量与大小写在手误里最常见，先抹掉再比距离
shape_of() {
  local s=${1,,}
  printf '%s' "${s//[!a-z]/}"
}

# Levenshtein 距离（两行滚动数组；token 都很短，不做优化）
flag_distance() {
  local a=$1 b=$2 i j cost tmp
  local la=${#a} lb=${#b}
  local -a prev cur
  for ((j = 0; j <= lb; j++)); do prev[j]=$j; done
  for ((i = 1; i <= la; i++)); do
    cur[0]=$i
    for ((j = 1; j <= lb; j++)); do
      cost=1
      if [ "${a:i-1:1}" = "${b:j-1:1}" ]; then cost=0; fi
      tmp=$((prev[j] + 1))
      if [ $((cur[j - 1] + 1)) -lt "$tmp" ]; then tmp=$((cur[j - 1] + 1)); fi
      if [ $((prev[j - 1] + cost)) -lt "$tmp" ]; then tmp=$((prev[j - 1] + cost)); fi
      cur[j]=$tmp
    done
    prev=("${cur[@]}")
  done
  printf '%s' "${prev[lb]}"
}

# 拼错开关时给"是否想写"建议：口径照 scripts/cliFlagPolicy.js 的 suggestFlag（距离 ≤ 2 取最近项）。
# 未知参数必须报错而不是忽略——`--imag`（少一个字母）被忽略时脚本会退成"缺 --image"，
# 而操作者以为参数已经生效（同族教训见 generate-secrets.js 的 --output 静默降级）。
suggest_flag() {
  local shape best='' best_d=3 f d
  shape=$(shape_of "$1")
  for f in "${KNOWN_FLAGS[@]}"; do
    d=$(flag_distance "$shape" "$(shape_of "$f")")
    if [ "$d" -lt "$best_d" ]; then
      best_d=$d
      best=$f
    fi
  done
  if [ "$best_d" -le 2 ]; then printf '%s' "$best"; fi
  return 0
}

IMAGE_REF=''
OUT_DIR=''
VERSION=''
BUILD_ID=''
SIGN_KEY=''
ARCHIVE_OUT=''
HELP=0
ERRORS=()

while [ "$#" -gt 0 ]; do
  arg=$1
  shift
  case "$arg" in
    --help) HELP=1 ;;
    --image=*) IMAGE_REF=${arg#--image=} ;;
    --out=*) OUT_DIR=${arg#--out=} ;;
    --version=*) VERSION=${arg#--version=} ;;
    --build-id=*) BUILD_ID=${arg#--build-id=} ;;
    --sign-key=*) SIGN_KEY=${arg#--sign-key=} ;;
    --archive=*) ARCHIVE_OUT=${arg#--archive=} ;;
    --image | --out | --version | --build-id | --sign-key | --archive)
      # 值槽被开关形态的 token 占掉后，后面的边界已不可信，不再继续解析（同 generate-secrets.js）
      if [ "$#" -lt 1 ] || [ "${1#--}" != "$1" ]; then
        ERRORS+=("「${arg}」需要一个值（后面跟着另一个开关，或已到末尾）")
        break
      fi
      value=$1
      shift
      case "$arg" in
        --image) IMAGE_REF=$value ;;
        --out) OUT_DIR=$value ;;
        --version) VERSION=$value ;;
        --build-id) BUILD_ID=$value ;;
        --sign-key) SIGN_KEY=$value ;;
        --archive) ARCHIVE_OUT=$value ;;
      esac
      ;;
    *)
      hint=$(suggest_flag "$arg")
      msg="未知参数：「${arg}」（本脚本只接受 ${FLAGS_TEXT}）"
      if [ -n "$hint" ]; then msg="${msg}；是否想写 ${hint}？"; fi
      ERRORS+=("$msg")
      ;;
  esac
done

if [ "$HELP" -eq 1 ]; then
  printf '%s\n' "$USAGE"
  exit 0
fi
if [ "${#ERRORS[@]}" -gt 0 ]; then
  for e in "${ERRORS[@]}"; do printf '错误：%s\n' "$e" >&2; done
  printf '%s\n' "$USAGE" >&2
  exit 2
fi

[ -n "$IMAGE_REF" ] || usage_error '缺少 --image：要导出的是哪个镜像（例：ghcr.io/org/fsms@sha256:<64hex>，或 ghcr.io/org/fsms:v1.2.3）'
[ -n "$OUT_DIR" ] || usage_error '缺少 --out：离线包输出目录（目录结构必须保持原样，导入器按相对路径读）'
[ -n "$VERSION" ] || usage_error '缺少 --version：这次发布的是哪一版（会写进 manifest，导入留痕要用）'

# 值的形态在**产生任何副作用之前**收紧：
#   · 引用只允许 docker 引用文法的字符集，且必须以字母数字开头 —— "以减号开头"会让 docker
#     把用户输入当成开关解析；
#   · 版本号/构建号会被原样写进 JSON，故排掉引号、反斜杠、控制字符等一切需要转义的字符。
if [[ ! $IMAGE_REF =~ ^[A-Za-z0-9][A-Za-z0-9._/:@+-]*$ ]]; then
  usage_error "「${IMAGE_REF}」不是合法的镜像引用（只接受字母数字开头的 字母数字/._:@+- 组合）"
fi
if [[ ! $VERSION =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]]; then
  usage_error "「${VERSION}」不是合法的版本号（只接受字母数字开头的 字母数字/._+- 组合）"
fi
if [[ ! $BUILD_ID =~ ^[A-Za-z0-9._:+-]*$ ]]; then
  usage_error "「${BUILD_ID}」不是合法的构建号（只接受 字母数字/._:+- 组合；也可以整个不给 --build-id）"
fi

# ================= 前置条件 =================
# 顺序：先判**参数组合与本地文件**（不需要任何外部命令就能判的），再判外部命令可用性。
# 反过来的话，本机没装 docker 会让「--archive 缺 --sign-key」这类用法错误被一句
# 「Docker 守护进程不可用」掩盖——使用者会去查 docker，而真正要改的是命令行。

if [ -n "$ARCHIVE_OUT" ] && [ -z "$SIGN_KEY" ]; then
  printf '错误：--archive 需要同时给 --sign-key（单文件归档必须带外层签名）。\n' >&2
  printf '       目录形态允许未签名（可由搬运前后人工比对清单兜底），单文件形态不允许——\n' >&2
  printf '       它正是为了让"传一个文件"这件事可被机器验证。\n' >&2
  exit 1
fi
if [ -n "$SIGN_KEY" ] && [ ! -r "$SIGN_KEY" ]; then
  printf '错误：--sign-key 指向的私钥不可读：%s\n' "$SIGN_KEY" >&2
  exit 1
fi
if [ -n "$ARCHIVE_OUT" ] && [ -e "$ARCHIVE_OUT" ]; then
  printf '错误：--archive 指向的路径已存在，拒绝覆盖（上一份归档再也找不回来）：%s\n' "$ARCHIVE_OUT" >&2
  exit 1
fi

command -v docker >/dev/null 2>&1 || {
  printf '错误：未找到 docker 命令（本脚本要在有 registry 拉取权限的构建机上执行）。\n' >&2
  exit 1
}
docker info >/dev/null 2>&1 || {
  printf '错误：Docker 守护进程不可用（docker info 失败）。\n' >&2
  exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
  printf '错误：未找到 sha256sum 命令（包内摘要与 SHA256SUMS 都依赖它）。\n' >&2
  exit 1
}

# 签名前置：带 --sign-key 却半路发现私钥读不了，不该以"已经 save 出一个 8GB tar"为代价才发现。
if [ -n "$SIGN_KEY" ]; then
  command -v openssl >/dev/null 2>&1 || {
    printf '错误：未找到 openssl 命令（--sign-key 的 Ed25519 签名依赖它，需 OpenSSL ≥ 3.0）。\n' >&2
    exit 1
  }
  if [ -n "$ARCHIVE_OUT" ]; then
    # 归档产出还要一次 tar（打包四个条目）；缺 tar 时同样该在起点报出来
    command -v tar >/dev/null 2>&1 || {
      printf '错误：未找到 tar 命令（--archive 的单文件归档依赖它）。\n' >&2
      exit 1
    }
  fi
elif [ "${FSMS_BUNDLE_REQUIRE_SIGNATURE:-0}" = "1" ]; then
  # 部署把"未签名包"定为事故口径时，让构建在起点就失败，而不是产出一个
  # 到目标机才被（正确地）拒收的包。
  printf '错误：FSMS_BUNDLE_REQUIRE_SIGNATURE=1 但未给 --sign-key：本次构建要求产出已签名包。\n' >&2
  exit 1
fi

# ================= 产物落点：形状、拒绝覆盖、清理钩子 =================

if [ -e "$OUT_DIR" ] && [ ! -d "$OUT_DIR" ]; then
  printf '错误：--out 指向的路径已存在且不是目录：%s\n' "$OUT_DIR" >&2
  exit 1
fi
# 拒绝覆盖既有产物：包被覆盖后上一份再也找不回来，而"上一次的 payload + 这一次的 manifest"
# 这种混合现场没有任何判据能识别出来。
for _rel in "$MANIFEST_REL" "$SUMS_REL" "$PAYLOAD_REL" "$SIG_REL"; do
  if [ -e "$OUT_DIR/$_rel" ]; then
    printf '错误：--out 目录里已经有本脚本的产物，拒绝覆盖：%s\n' "$OUT_DIR/$_rel" >&2
    printf '       请换一个空目录（或人工确认后删掉旧包）后重跑。\n' >&2
    exit 1
  fi
done
if ! mkdir -p -- "$OUT_DIR"; then
  printf '错误：无法创建 --out 目录：%s\n' "$OUT_DIR" >&2
  exit 1
fi
OUT_ARG=$OUT_DIR
if ! OUT_DIR=$(cd -- "$OUT_ARG" 2>/dev/null && pwd); then
  printf '错误：--out 目录无法进入：%s\n' "$OUT_ARG" >&2
  exit 1
fi

TAR_PATH="$OUT_DIR/$PAYLOAD_REL"
MANIFEST_PATH="$OUT_DIR/$MANIFEST_REL"
SIG_PATH="$OUT_DIR/$SIG_REL"
SUMS_PATH="$OUT_DIR/$SUMS_REL"
ARCHIVE_SIG_PATH=''
ARCHIVE_SHA_TMP=''

FINALIZED=0          # 1 = 产物齐备且自校验通过，清理钩子从此不碰任何文件
ARTIFACTS_STARTED=0  # 1 = 已经开始往 outDir 写东西
# 失败现场不能留下"看起来像成功"的产物：导入器只看 manifest.json 里有什么，
# 一个半截的 tar 会被当成完整包拷到目标机。清理必须幂等——INT/TERM 的 trap 先清一次
# 再退出，退出时 EXIT trap 还会走一遍（第二次因为 ARTIFACTS_STARTED 已归零而不再删）。
#
# 归档产物（--archive，落在 --out 之外）由同一把钩子清理：它是**搬运面的成品**，
# 半截的 .tar.gz 与本脚本在 --out 里要防的"半截 tar"是同一个失效——运维会把它当
# 完整包拷走。变量在产出段才赋值，空值 rm -f 是 no-op（清理必须幂等）。
cleanup() {
  if [ "$FINALIZED" -eq 1 ]; then return 0; fi
  if [ -n "$ARCHIVE_SIG_PATH" ] || [ -n "$ARCHIVE_SHA_TMP" ]; then
    rm -f -- "$ARCHIVE_SIG_PATH" "$ARCHIVE_SHA_TMP" 2>/dev/null || true
    printf '已清理本次未完成的归档签名产物。\n' >&2
  fi
  if [ "$ARTIFACTS_STARTED" -ne 1 ]; then return 0; fi
  ARTIFACTS_STARTED=0
  rm -f -- "$TAR_PATH" "$MANIFEST_PATH" "$SUMS_PATH" "$SIG_PATH" 2>/dev/null || true
  printf '已清理本次未完成的产物：%s\n' "$OUT_DIR" >&2
  return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# ================= 从 docker 的实际结果取回 digest =================

# RepoDigests 是 docker 记下的"这个镜像的内容摘要"，是整条链上唯一不能由我们自称的东西。
# 用 --format 逐行打印而不是解析 JSON：为了读一个数组不值得把 jq/node 拉成构建机前提。
repo_digests_of() {
  docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$1"
}

# 仓库名归一：docker 会补全隐式命名空间（node → docker.io/library/node），直接拿用户输入的
# 仓库段比对会得出"仓库对不上"的假红。口径与 scripts/capture-image-digests.sh 的 norm_repo 一致。
repo_of_ref() {
  case "${1##*/}" in
    *:*) printf '%s' "${1%:*}" ;;
    *) printf '%s' "$1" ;;
  esac
}
norm_repo() {
  local first
  first=${1%%/*}
  if [ "$first" = "$1" ]; then
    printf 'docker.io/library/%s' "$1"
    return 0
  fi
  case "$first" in
    *.* | *:*) printf '%s' "$1" ;;
    *) printf 'docker.io/%s' "$1" ;;
  esac
}

# 先拉用户给的引用。tag 输入时这一步是"取回当前 tag 指向"，digest 输入时 pull 本身就是
# 内容寻址校验（registry 必须供出与该 digest 逐字节相符的内容，否则 pull 自己就失败）。
printf '==> docker pull %s\n' "$IMAGE_REF"
if ! docker pull "$IMAGE_REF"; then
  printf '错误：docker pull 失败：%s\n' "$IMAGE_REF" >&2
  exit 1
fi

WANT_REPO=$(norm_repo "$(repo_of_ref "$IMAGE_REF")")
PINNED=''
MATCHES=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  case "$line" in
    *@sha256:*) ;;
    *) continue ;;
  esac
  if [ "$(norm_repo "${line%@*}")" = "$WANT_REPO" ]; then
    PINNED=$line
    MATCHES=$((MATCHES + 1))
  fi
done <<EOF
$(repo_digests_of "$IMAGE_REF")
EOF

if [ "$MATCHES" -eq 0 ]; then
  printf '错误：docker 里取不到 %s 的 registry digest（RepoDigests 为空，或仓库名对不上）。\n' "$IMAGE_REF" >&2
  printf '       本机镜像若是 docker build / docker load 来的，就没有 registry 来源，\n' >&2
  printf '       也就给不出"能过判据层的内容寻址引用"——请在构建机上先 docker pull。\n' >&2
  exit 1
fi
if [ "$MATCHES" -ne 1 ]; then
  printf '错误：%s 对应 %s 个 digest，本脚本不猜哪一个才是要发布的那一版。\n' "$IMAGE_REF" "$MATCHES" >&2
  printf '       请换一个明确指向单版的引用（repo@sha256:<64hex>）重跑。\n' >&2
  exit 1
fi

# 形态校验只为保证"写进 manifest 的引用一定能过判据层"（唯一来源是 offlineBundlePolicy.js
# 调用的 hotUpgradePolicy.parseImageRef），真正的判据不在本脚本里。
if [[ ! $PINNED =~ ^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$ ]]; then
  printf '错误：docker 给出的镜像引用形态非法（本脚本不猜）：%s\n' "$PINNED" >&2
  exit 1
fi
case "${PINNED%@*}" in
  *//*)
    printf '错误：docker 给出的仓库名含空段（//），拒绝写进 manifest：%s\n' "$PINNED" >&2
    exit 1
    ;;
esac

case "$IMAGE_REF" in
  *@sha256:*)
    if [ "${PINNED##*@}" != "${IMAGE_REF##*@}" ]; then
      printf '错误：取回的 digest 与请求的不一致（请求 %s，docker 记录 %s）。\n' "${IMAGE_REF##*@}" "${PINNED##*@}" >&2
      printf '       按 digest 拉取必须得到同一内容；拒绝把来源不明的版本写进 manifest。\n' >&2
      exit 1
    fi
    ;;
esac

# 再按 digest 引用拉一次：tag 输入时这是"让本机镜像能被 digest 直接引用"的动作，
# digest 输入时它是同一引用的幂等复查——registry 必须能按该 digest 供内容，否则现在就失败，
# 而不是等到目标机 load 完才发现拿不到对应的版本。
printf '==> docker pull %s（本次真正要导出的那一版）\n' "$PINNED"
if ! docker pull "$PINNED"; then
  printf '错误：docker pull 失败：%s\n' "$PINNED" >&2
  exit 1
fi

# ================= 产物：save → 算字节/摘要 → manifest → SHA256SUMS =================

ARTIFACTS_STARTED=1
if ! mkdir -p -- "$OUT_DIR/payload"; then
  printf '错误：无法创建 payload 目录：%s\n' "$OUT_DIR/payload" >&2
  exit 1
fi

# 用**钉死的引用** save 而不是 tag：pull 与 save 之间上游滚动同名 tag 时，导出的会是另一个
# 版本，而 manifest 里写的仍是刚才捕获的 digest——"save 一个 tag 就宣称是该 digest"正是要挡的形态。
printf '==> docker save → %s\n' "$PAYLOAD_REL"
if ! docker save -o "$TAR_PATH" "$PINNED"; then
  printf '错误：docker save 失败（docker 的输出上面已给出）。\n' >&2
  exit 1
fi
if [ ! -f "$TAR_PATH" ]; then
  printf '错误：docker save 退出码为 0 但产物不存在：%s\n' "$TAR_PATH" >&2
  exit 1
fi
if [ ! -s "$TAR_PATH" ]; then
  printf '错误：docker save 产物为 0 字节，不是可搬运的离线包：%s\n' "$TAR_PATH" >&2
  exit 1
fi

# bytes 要写进 manifest（判据层按它比对实际文件），所以计数本身得先有形状：
# wc 退出 0 却不打印时留下的是空串，会写出 "bytes": （空）——那是个"看起来成功"的包。
TAR_BYTES=$(wc -c < "$TAR_PATH")
TAR_BYTES=${TAR_BYTES//[[:space:]]/}
case "$TAR_BYTES" in
  '' | *[!0-9]*)
    printf '错误：payload 字节数读不出来（wc 未给出计数）：%s\n' "$TAR_PATH" >&2
    exit 1
    ;;
esac

# 哈希是 sha256sum 输出的第一个空格之前的字段；文件名含特殊字符时 coreutils 会在行首加
# \\ 转义标记，必须剥掉再判形状——否则一个合法路径会让摘要校验无谓地失败。
sha256_of() {
  local out
  out=$(sha256sum -- "$1")
  out=${out%% *}
  printf '%s' "${out#\\}"
}
TAR_SHA=$(sha256_of "$TAR_PATH")
if [[ ! $TAR_SHA =~ ^[0-9a-f]{64}$ ]]; then
  printf '错误：payload 的 sha256 不可用（sha256sum 输出无法解析）：%s\n' "$TAR_SHA" >&2
  exit 1
fi

# 落盘后再读一次 docker 认的 digest：save 的退出码只说明 tar 结构被接受，而 manifest 是把
# "这一版"带出联机机的唯一凭据（同仓"不能只信退出码"的口径，见 backup-mongo.sh 的归档判据）。
STILL_PRESENT=0
while IFS= read -r line; do
  if [ "$line" = "$PINNED" ]; then STILL_PRESENT=1; fi
done <<EOF
$(repo_digests_of "$PINNED")
EOF
if [ "$STILL_PRESENT" -ne 1 ]; then
  printf '错误：docker 不再把 %s 认作本机镜像的 digest，拒绝写下与现场不符的 manifest。\n' "$PINNED" >&2
  exit 1
fi

CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# 手写 JSON 而不是过一遍 json 工具：构建机只保证 bash+docker+sha256sum，而拼进模板的每个值
# 都已被上面的字符集校验收成"不需要转义"的形态——没有第二套转义实现会与判据层漂移。
printf '{
  "format": 1,
  "version": "%s",
  "buildId": "%s",
  "createdAt": "%s",
  "images": [
    {
      "role": "%s",
      "ref": "%s",
      "file": "%s",
      "bytes": %s,
      "sha256": "%s"
    }
  ]
}
' "$VERSION" "$BUILD_ID" "$CREATED_AT" "$ROLE" "$PINNED" "$PAYLOAD_REL" "$TAR_BYTES" "$TAR_SHA" > "$MANIFEST_PATH"

# ================= 签名（可选，但目标机配了公钥时就是必需） =================

# 签名覆盖 manifest.json 的**原始字节**：目标机的验签（scripts/offlineBundleSignature.js）按
# 字节比对，这里的任何后处理（重排键、改行尾）都会让包在自己构建机以外的地方验不过。
# -rawin 是 Ed25519 的要求（One-shot 签名，不做摘要预热）；签完立即用同一把钥匙回验一次，
# 把"openssl 版本不支持 -rawin 也退出码 0"这类假成功挡在构建机上。
if [ -n "$SIGN_KEY" ]; then
  printf '==> openssl pkeyutl -sign（Ed25519）→ %s\n' "$SIG_REL"
  if ! openssl pkeyutl -sign -rawin -inkey "$SIGN_KEY" -in "$MANIFEST_PATH" -out "$SIG_PATH"; then
    printf '错误：manifest 签名失败（需 OpenSSL ≥ 3.0 支持 Ed25519 的 pkeyutl -rawin）。\n' >&2
    exit 1
  fi
  if ! openssl pkeyutl -verify -rawin -inkey "$SIGN_KEY" -in "$MANIFEST_PATH" -sigfile "$SIG_PATH" >/dev/null; then
    printf '错误：签名回验失败——私钥与刚产出的 %s 对不上，拒绝发出一个连自己都验不了的包。\n' "$SIG_REL" >&2
    exit 1
  fi
  SIGNED=1
else
  SIGNED=0
  printf '==> 未签名（未给 --sign-key）：目标机配置验签公钥后，这个包会被拒绝导入。\n' >&2
fi

# SHA256SUMS 覆盖 payload 与 manifest.sig：manifest.json 是清单本身，让它包含"自己的摘要"
# 不可能自洽；manifest 的完整性由 manifest.sig（签名，机器校验）与搬运前后人工比对兜底。
# 写法与 sha256sum 的产出一致（相对路径），目标机 cd <包目录> && sha256sum -c SHA256SUMS 直接可用。
# （追加写而不是 { A; [ cond ] && B; } 组合：set -e 下未签名分支的 [ ] 会以非零退出，
#  把整条管线变成假失败。）
( cd -- "$OUT_DIR" && sha256sum -- "$PAYLOAD_REL" ) > "$SUMS_PATH"
if [ "$SIGNED" -eq 1 ]; then
  ( cd -- "$OUT_DIR" && sha256sum -- "$SIG_REL" ) >> "$SUMS_PATH"
fi
# 写完立刻按清单自校验一次：避免"清单写成功，但它与产物不是同一时刻的读数"。
if ! ( cd -- "$OUT_DIR" && sha256sum -c -- "$SUMS_REL" ) >/dev/null; then
  printf '错误：SHA256SUMS 自校验失败（清单与产物对不上），本次产物按失败处理。\n' >&2
  exit 1
fi

# ================= 单文件归档（--archive，可选的搬运形态） =================

# 为什么另产出 .tar.gz：目录形态（四个条目）在 scp/U 盘搬运时最容易漏一个——漏 manifest.sig
# 的包看起来完全正常，直到目标机 fail-closed 拒绝。单文件搬运消除这个失效面；
# 目标机由 scripts/offlineBundleIntake.js 落位（只解点名条目，见 ADR-020）。
#
# 归档自身的完整性由**外层签名**承接：`<archive>.sig` 签的是归档 sha256 的 hex 文本
# （64 字节），不是归档本身——Ed25519 是 one-shot 签名，GB 级归档整包签必 OOM。
# 三层信任链：外层 sig → 归档 sha256 → manifest.sig → manifest 字节 → payload sha256。
ARCHIVE_SHA=''
ARCHIVE_BYTES=''
ARCHIVE_SIG_REL=''
if [ -n "$ARCHIVE_OUT" ]; then
  # 前置段已判过「--archive 必带 --sign-key」与「目标不存在」；这里不重复判据，
  # 只判**只有走到这一步才知道的事**：签名是否真的成功了。
  if [ "$SIGNED" -ne 1 ]; then
    printf '错误：--archive 需要 --sign-key：归档一旦离开构建机就没有任何可信来源。\n' >&2
    printf '       （前置段已拦一次；走到这里说明签名步骤本身失败了，见上面的输出。）\n' >&2
    exit 1
  fi
  printf '==> tar -czf → %s\n' "$ARCHIVE_OUT"
  # 只打包四个已定条目（不用 . 避免把编辑器临时文件、.DS_Store 之类卷进去）；
  # 相对路径入档：归档内条目名必须是包内相对名，落位侧按 manifest 声明逐一解包。
  if ! tar -czf "$ARCHIVE_OUT" -C "$OUT_DIR" "$MANIFEST_REL" "$SIG_REL" "$SUMS_REL" payload; then
    printf '错误：归档打包失败（tar 的输出上面已给出）。\n' >&2
    exit 1
  fi
  if [ ! -s "$ARCHIVE_OUT" ]; then
    printf '错误：归档产物为空：%s\n' "$ARCHIVE_OUT" >&2
    exit 1
  fi
  ARCHIVE_BYTES=$(wc -c < "$ARCHIVE_OUT")
  ARCHIVE_BYTES=${ARCHIVE_BYTES//[[:space:]]/}
  ARCHIVE_SHA=$(sha256_of "$ARCHIVE_OUT")
  if [[ ! $ARCHIVE_SHA =~ ^[0-9a-f]{64}$ ]]; then
    printf '错误：归档的 sha256 不可用（sha256sum 输出无法解析）：%s\n' "$ARCHIVE_SHA" >&2
    exit 1
  fi
  # 外层签名：签摘要的 hex 文本（不是归档字节）。printf 不加换行——落位侧用
  # policy.digestPayloadOf 收成 Buffer 再验，两侧必须对"文本形态"逐字节一致。
  ARCHIVE_SIG_PATH="${ARCHIVE_OUT}.sig"
  if [ -e "$ARCHIVE_SIG_PATH" ]; then
    printf '错误：归档签名路径已存在，拒绝覆盖：%s\n' "$ARCHIVE_SIG_PATH" >&2
    exit 1
  fi
  ARCHIVE_SHA_TMP="${ARCHIVE_OUT}.sha.tmp"
  printf '%s' "$ARCHIVE_SHA" > "$ARCHIVE_SHA_TMP"
  if ! openssl pkeyutl -sign -rawin -inkey "$SIGN_KEY" -in "$ARCHIVE_SHA_TMP" -out "$ARCHIVE_SIG_PATH"; then
    printf '错误：归档外层签名失败。\n' >&2
    exit 1
  fi
  # 签完立即回验（同 manifest.sig 的纪律：不让「连自己都验不了」的归档出门）。
  # 摘要临时文件此刻还在，正好既当签名输入又当验签输入——用完再删。
  if ! openssl pkeyutl -verify -rawin -inkey "$SIGN_KEY" -in "$ARCHIVE_SHA_TMP" -sigfile "$ARCHIVE_SIG_PATH" >/dev/null; then
    printf '错误：归档外层签名回验失败，拒绝发出一个连自己都验不了的包。\n' >&2
    exit 1
  fi
  rm -f -- "$ARCHIVE_SHA_TMP"
  ARCHIVE_SHA_TMP=''
  ARCHIVE_SIG_REL=$(basename "$ARCHIVE_SIG_PATH")
  printf '==> 归档外层签名完成：%s（签的是归档 sha256 的文本）\n' "$ARCHIVE_SIG_REL"
fi

FINALIZED=1

# ================= 摘要 =================

REPO_PART=${PINNED%@*}
ALLOWLIST_HINT="${REPO_PART%/*}/"
MANIFEST_SHA=$(sha256_of "$MANIFEST_PATH")
BUILD_LABEL=''
if [ -n "$BUILD_ID" ]; then BUILD_LABEL="（构建号 ${BUILD_ID}）"; fi

printf '\n离线包构建完成：%s\n' "$OUT_DIR"
printf '  版本：%s%s\n' "$VERSION" "$BUILD_LABEL"
printf '  镜像：%s → %s\n' "$ROLE" "$PINNED"
printf '  %s：%s 字节，sha256 %s\n' "$PAYLOAD_REL" "$TAR_BYTES" "$TAR_SHA"
printf '  %s sha256：%s（不在 SHA256SUMS 内：清单不能自我覆盖，搬运前后请核对这一行）\n' "$MANIFEST_REL" "$MANIFEST_SHA"
if [ "$SIGNED" -eq 1 ]; then
  printf '  签名：已用 %s 对 manifest 签名（%s）；目标机以 OFFLINE_BUNDLE_VERIFY_PUBKEY 钉对应公钥\n' "$SIGN_KEY" "$SIG_REL"
else
  printf '  签名：无——目标机配置了验签公钥（OFFLINE_BUNDLE_VERIFY_PUBKEY）时此包将被拒绝\n'
fi
if [ -n "$ARCHIVE_OUT" ]; then
  printf '  归档：%s（%s 字节，sha256 %s）\n' "$ARCHIVE_OUT" "$ARCHIVE_BYTES" "$ARCHIVE_SHA"
  printf '        外层签名 %s（签的是上面这行 sha256 的文本；三层信任链见 ADR-020）\n' "$ARCHIVE_SIG_REL"
  printf '\n搬运用单文件形态时，只搬这两个文件（归档 + 外层签名）：\n'
  printf '  scp %s %s <目标机>:/var/lib/fsms/upgrade/inbox/\n' "$(basename "$ARCHIVE_OUT")" "$ARCHIVE_SIG_REL"
  printf '  目标机由宿主代理自动落位（每轮最多一个包，静默期后确认传输完成）；\n'
  printf '  也可人工 CLI 兜底：node scripts/offlineBundleIntake.js --inbox /var/lib/fsms/upgrade/inbox --apply\n'
fi
printf '\n目标机（air-gap）下一步：把整个目录原样搬到目标机，然后\n'
printf '  演练： node scripts/importOfflineBundle.js --bundle <包目录> --allowlist %s\n' "$ALLOWLIST_HINT"
printf '  执行： node scripts/importOfflineBundle.js --bundle <包目录> --allowlist %s --apply\n' "$ALLOWLIST_HINT"
printf '  （--allowlist 必须给：空白名单 = 全拒；建议前缀先收紧到组织一级，不要放宽到整个 registry。）\n'
