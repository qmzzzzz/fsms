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
#
# 产出/写入的引用形态是 `name:tag@sha256:<hex>`（保留可读 tag），
# 不是 `docker inspect` 的 RepoDigests 原文（`docker.io/library/node@sha256:<hex>`，天生无 tag）：
# 详见下方 capture_digest 的注释——两把门禁都按前者判，写成后者会当场变红。

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
# 因此取值后立刻校验形状：必须以 `@sha256:` + 64 位十六进制结尾。
# 注意：本函数在 `$( )` 里执行 ⇒ 报错要打 stderr，并用非零退出让**赋值语句**失败
# （set -e 下 `VAR=$(...)` 的命令替换返回非零会终止脚本；实测确认，别依赖函数里的 echo）。
#
# 返回值不是 RepoDigests 原文，而是 `$tag@sha256:<hex>`（把 digest 追加到调用方给的可读引用上）。
# 因为 RepoDigests 的条目天生**不带 tag**——本仓 2026-10-02 实测
# `docker inspect --format='{{index .RepoDigests 0}}' node:22.14.0-alpine`
# 得到 `docker.io/library/node@sha256:…`。旧实现把整串直接写进 Dockerfile，产物是
# `FROM docker.io/library/node@sha256:…`：tag 整段消失，而本仓的钉版口径明确是**保留 tag**——
#   docker-compose.yml 里 mongo 那段注释写着"保留可读 tag：纯 digest 看不出版本，
#     排障时得先 inspect 才知道跑的是哪个大版本"；
#   Dockerfile 的三处 FROM 与 docker-compose.yml 的 redis 都是 `name:tag@sha256:<hex>`；
#   门禁 src/tests/security/baseImageDigestPinned.test.js 的 FROM 判据是
#     `/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/`，deployScript.test.js 把约定写成 `<repo>:<tag>@sha256:…`。
# 也就是说照本脚本的升级路径跑一次 `--apply`，产物会被那道闸直接判红——
# 工具否定了它自己的产物。取尾巴追加到 tag 上，两种形态（短名 `node@…`、
# 全限定 `docker.io/library/node@…`）都会收敛成同一个 `node:22.14.0-alpine@sha256:…`。
#
# 追加之前必须先确认"这个 digest 确实属于这个镜像"，否则写进去的是"tag 指向别人仓库的 digest"
# 这种根本不成立的断言，构建期 pull 才炸。仓库名对账有两处坑（2026-10-03 复核实测，两侧都踩）：
#   ① 只比末段：`${tag%%:*}` 取到的 `mongo` 会被 `docker.io/myorg/mongo` 满足——
#      把**别人仓库**的 digest 挂到官方 tag 上，判据却是"名字一致"。
#   ② 带端口的私有 registry：`reg.example.com:8443/lib/node:1.2` 里 `${tag%%:*}` 从**第一个**
#      冒号截断 ⇒ 得到 `reg.example.com`，与 RepoDigests 的 `reg.example.com:8443/lib/node`
#      永远对不上 ⇒ 合法引用被硬拒，而报错文案还把人往"本地同名镜像来自第二个 registry"引。
# 两条一起修：tag 的切分按"最后一个 `/` 之后有没有冒号"判（Docker 自己的规则：
# 冒号只在最后一段才是 tag 分隔符，否则是 registry 端口），比对前两侧都做**隐式命名空间**归一
# （`node` → `docker.io/library/node`、`prom/prometheus` → `docker.io/prom/prometheus`、
# 首段含 `.` 或 `:` 的按显式 registry 原样保留），归一后必须逐字相等。
repo_of_ref() {
  ref=$1
  case "${ref##*/}" in
    *:*) printf '%s' "${ref%:*}" ;;
    *) printf '%s' "$ref" ;;
  esac
}

norm_repo() {
  r=$1
  first=${r%%/*}
  if [ "$first" = "$r" ]; then
    printf 'docker.io/library/%s' "$r"
    return
  fi
  case "$first" in
    *.*) printf '%s' "$r" ;;
    *:*) printf '%s' "$r" ;;
    *) printf 'docker.io/%s' "$r" ;;
  esac
}

capture_digest() {
  tag=$1
  raw=$(docker inspect --format='{{index .RepoDigests 0}}' "$tag" 2>/dev/null || true)
  if ! printf '%s' "$raw" | grep -Eq '@sha256:[0-9a-f]{64}$'; then
    printf '错误：取不到 %s 的 registry digest（得到：%s）。\n' "$tag" "'${raw:-空}'" >&2
    printf '       多为本机镜像是 build/load 而来（无 digest）或 docker 输出异常；\n' >&2
    printf '       请在有拉取权限的机器上重新 pull，不要在拿不到 digest 时手工抄。\n' >&2
    return 1
  fi
  want=$(norm_repo "$(repo_of_ref "$tag")")
  got=$(norm_repo "${raw%@*}")
  if [ "$want" != "$got" ]; then
    printf '错误：%s 的 RepoDigests 仓库名是 %s，与请求的引用对不上（归一后 %s ≠ %s）。\n' \
      "$tag" "${raw%@*}" "$got" "$want" >&2
    printf '       可能是本地同名镜像来自第二个 registry 或别人的命名空间；\n' >&2
    printf '       请确认取的是刚 pull 的那个，不要手工拼。\n' >&2
    return 1
  fi
  printf '%s' "${tag}@${raw##*@}"
}

NODE_PINNED=$(capture_digest "$NODE_TAG") || exit 1
MONGO_PINNED=$(capture_digest "$MONGO_TAG") || exit 1

echo
echo "捕获结果（直接可用于 name:tag@sha256:<hex> 形态的钉版引用）："
echo "  node : $NODE_PINNED"
echo "  mongo: $MONGO_PINNED"

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
# addr/kw 是**指令定位**：只认指令行上"值的位置"那一段。
# 实测教训有两条，根子都在把字面串当成"位置无关的子串"：
#   ① compose 里 `image: mongo:6.0.20` 这个字面串同时出现在一段注释里（"把输出追加为
#      `image: mongo:6.0.20@sha256:<捕获值>`"），不带行定位的全文 sed 会把注释一起改掉——
#      注释是给人读的用法示例，改掉之后它就成了错误示例；
#   ② 钉版形态 `node:22.14.0-alpine@sha256:9bef…` 仍然**包含**脚本常量
#      `FROM node:22.14.0-alpine` 这个前缀，于是旧的 `grep -qF "$old"` 把"已经钉过"读成
#      "还能改"，替换再在它前面插一个新 digest ⇒ 产出 `@sha256:新@sha256:旧` 的双 digest：
#      脚本打印"已替换并校验"，失败推迟到 `docker build`，而现场是一份"看起来已按 digest
#      固定"的文件（2026-10-03 对着本仓真实 Dockerfile 实测复现，三条 FROM 全部中招）。
# 所以现在的判据不看"这行里有没有 tag 的字面串"，而是把指令行的**值 token** 取出来分类
# （裸 tag / `tag@sha256:<64hex>` / 其它形态），"其它形态"一律停手而不是猜。
#
# 处置分四类（classify_ref 的产物）：
#   待钉 bare       裸 tag ⇒ 追加刚捕获的 digest
#   已钉 same       钉的就是刚捕获的 digest ⇒ **该目标跳过**：不报错，也不碰一个字节
#   待刷新 refresh  钉在**别的** digest 上 ⇒ 换成刚捕获的（上游滚动同名 tag 时唯一出路）
#   够不着 其余形态 立即停手、零写入，并打印行号
# 为什么"已钉"从报错改成跳过：本仓库今天的真实状态就是混合仓库——Dockerfile 三条 FROM
# 全钉死、compose 的 mongo 没钉。旧实现在第一步就撞"已经存在 @sha256 钉版引用"退出，
# compose 因此**永远钉不上**，而 `src/tests/security/baseImageDigestPinned.test.js` 的文件头
# 把"在部署机跑本脚本重新捕获"写成唯一的升级路径——那条路径是死的。现在混合仓库能收敛，
# 已钉行保持原样，未钉行被钉上。整体 no-op（两个目标都"已钉"）仍然是错误：
# 那才是上面说的"报告成功但一字未改"，也是运维真正需要知道的"这次什么都没发生"。
#
# 为什么拆成 check / stage / commit 三相（原先是一个 pin_ref 边检查边落笔，两个目标顺序跑）：
# 实测的半钉状态——Dockerfile 正常、compose 的 tag 漂移 ⇒
#   第一轮：Dockerfile 被改成 digest，compose 那步报错退出 rc=1，仓库留下"半钉"；
#   第二轮：半钉虽然不再致命，但"改了一个文件才发现另一个不能改"仍然是把仓库
#          停在中间状态。所以 check 阶段只读（两个目标都分类完、并确认临时文件不存在），
#          stage 阶段只写临时文件并对临时文件复查，commit 阶段才 mv——
#          任何一步失败，两个目标文件都是原样。
# 诚实交代残余边界：两条 `mv` 之间不是原子的（跨两个文件不存在 single-phase rename）。
# 之所以够用：check 已确认两文件都在且都可改，stage 已把两份改好的内容验过一遍，
# 到 commit 只剩同目录 rename——失败面从"任何解析/匹配错"缩到"rename 本身出错"。
#
# 字面串要拿当 sed 的模式就得转义元字符。这里可能出现的元字符只有 `.`：
# Docker 的引用文法是 [A-Za-z0-9._-]（tag）加上 `:` `/` `@`（repo/digest 分隔），
# 后者都不是正则元字符。不转义的话 `22.14.0` 里的 `.` 会当通配，匹配到 `22x14x0` 这类
# 根本不存在的写法——本仓不需要它出错，只需要它别在别处多改一笔。
to_re() {
  printf '%s' "$1" | sed 's/\./\\./g'
}

# 取出指令行"值的位置"上的 token，并对它分类。整段用 awk 而不是 shell 循环：
# 需要同时看"去掉行首空白后的前缀"和"前缀之后的第一个字段"，shell 里要两趟剪切。
# 只用 POSIX awk 的构造（index/substr/sub 与 [ \t] 显式空白类）——CI 的 mawk 对
# POSIX 字符类和区间表达式的支持历来不齐，`[[:space:]]` 与 `{64}` 在这里都不要写；
# 64 位十六进制的校验交给调用方的 grep -E，awk 只判"是不是 tag@sha256: 开头"。
# 输出的每一行是固定四字段（空格分隔，字段内不含空格）：
#   instr <类> <行号> <token>    指令行上指向**本镜像**的引用；类 ∈
#                                bare | pinned | stray | malformed | tagless | drift
#   unreach x <行号> x           含 tag 字面串、但既不是指令行也不是注释行的行
# 注释行（去掉行首空白后以 `#` 开头）里的提及**不算引用**：那是给人读的示例，
# 本脚本既不读它也不改它——Dockerfile 顶部就写着三行这样的示例。
probe_ref() {
  file=$1
  kw=$2
  tag=$3
  awk -v tag="$tag" -v kw="$kw" '
    function imgname(r,   s) {
      # 引用里的"仓库末段名"：@ 之后是 digest，最后一个 / 之后是 repo[:tag]，: 之后是 tag。
      s = r; sub(/@.*$/, "", s); sub(/.*\//, "", s); sub(/:.*$/, "", s); return s
    }
    {
      line = $0
      sub(/^[ \t]*/, "", line)
      if (index(line, kw) == 1 && substr(line, length(kw) + 1, 1) ~ /^[ \t]$/) {
        rest = substr(line, length(kw) + 1)
        sub(/^[ \t]+/, "", rest)
        tok = rest
        sub(/[ \t].*$/, "", tok)
        # 不是本镜像的指令行（redis / prometheus / ${APP_IMAGE:-…}）直接跳过：
        # 本脚本只管自己常量里那一个引用，别的一律不碰。
        if (tok == "" || imgname(tok) != imgname(tag)) next
        scan = rest
        sha = gsub(/@sha256:/, "@", scan)
        if (index(tok, tag) != 1) {
          # 同一个仓库名但**不以 tag 常量开头**：带 digest 的是"无 tag 的钉版"（旧实现写坏的
          # 产物形态），不带的就是 tag 漂移。两种都要人看，脚本不猜。
          print "instr", (tok ~ /@sha256:/ ? "tagless" : "drift"), NR, tok
          next
        }
        if (tok == tag) {
          # 行里还有别的 @sha256: ⇒ 这是 `TAG @sha256:X`（tag 与 digest 之间夹了空白）这类
          # 畸形写法。钉上去会得到"值指向裸 tag、后面跟着一个游离摘要"的行，改完仍是可变引用。
          print "instr", (sha == 0 ? "bare" : "stray"), NR, tok
          next
        }
        print "instr", (index(tok, tag "@sha256:") == 1 ? "pinned" : "malformed"), NR, tok
        next
      }
      if (index($0, tag) > 0 && line !~ /^#/) print "unreach", "x", NR, "x"
    }
  ' "$file"
}

# 够不着的形态：把行号与原因打印出来就停手。不回显整行——compose/Dockerfile 里
# 引用位上理论上能出现带凭据的变量展开，而运维按行号去看比脚本替他打印更安全。
refuse_shape() {
  printf '错误：%s 第 %s 行的引用形态本脚本处理不了：%s（%s）\n' "$1" "$2" "$4" "$3" >&2
  printf '       本次一个字都不写。请把该行改成裸 tag 或 name:tag@sha256:<64 位 hex> 后重跑，\n' >&2
  printf '       或人工替换（脚本的判据就在上面注释里，形态对了它才敢动手）。\n' >&2
  exit 1
}

refuse_drift() {
  printf '错误：%s 第 %s 行的 tag 与脚本常量漂移：文件里是 %s，常量是 %s。\n' \
    "$1" "$2" "$3" "$4" >&2
  printf '       静默跳过会让未钉版的镜像引用被误认为已固定，请同步本文件顶部的 tag 常量，\n' >&2
  printf '       或直接把该行钉上（digest 用上面刚打印的捕获值）。\n' >&2
  exit 1
}

# 分类并把计数写进全局（POSIX sh 没有 local，本脚本一贯用全局 + 调用方负责读取）。
# PROBE_BARE   待钉条数
# PROBE_SAME   已钉且就是刚捕获的 digest
# PROBE_REFRESH 已钉但是别的 digest（可刷新）
# PROBE_TOTAL  指向本镜像的指令行总数（staging 前后必须相等 ⇒ sed 不增删引用）
classify_ref() {
  file=$1
  kw=$2
  tag=$3
  want=$4
  label=$5
  PROBE_BARE=0
  PROBE_SAME=0
  PROBE_REFRESH=0
  PROBE_TOTAL=0
  stream=$(probe_ref "$file" "$kw" "$tag")
  kind=''
  cls=''
  ln=''
  tok=''
  while read -r kind cls ln tok; do
    if [ -z "$kind" ]; then continue; fi
    case "$kind" in
      unreach)
        printf '错误：%s 第 %s 行提到了 %s，但既不是能解析的指令行、也不是注释行。\n' \
          "$label" "$ln" "$tag" >&2
        printf '       这类写法（引号包裹的值、折叠标量、序列项 - image:、变量展开等）本脚本改不了；\n' >&2
        printf '       静默跳过会留下一条仍指向可变 tag 的引用，所以在这里停手，请人工处理。\n' >&2
        exit 1
        ;;
      instr)
        PROBE_TOTAL=$((PROBE_TOTAL + 1))
        case "$cls" in
          bare) PROBE_BARE=$((PROBE_BARE + 1)) ;;
          pinned)
            if [ "$tok" = "$want" ]; then
              PROBE_SAME=$((PROBE_SAME + 1))
            elif printf '%s' "$tok" | grep -Eq "$(to_re "$tag")@sha256:[0-9a-f]{64}$"; then
              PROBE_REFRESH=$((PROBE_REFRESH + 1))
            else
              refuse_shape "$label" "$ln" "$tok" "digest 不是 64 位十六进制"
            fi
            ;;
          stray)
            refuse_shape "$label" "$ln" "$tok" "tag 与 @sha256 之间夹了空白"
            ;;
          malformed)
            refuse_shape "$label" "$ln" "$tok" "tag@sha256 之后的形态不认识"
            ;;
          tagless)
            refuse_shape "$label" "$ln" "$tok" \
              "已按 digest 钉版但没有可读 tag（本仓口径是 name:tag@sha256:<hex>）"
            ;;
          drift)
            refuse_drift "$label" "$ln" "$tok" "$tag"
            ;;
          *)
            printf '错误：%s 的分类器给出了预定义之外的类「%s」（脚本自身缺陷，请报告）\n' \
              "$label" "$cls" >&2
            exit 1
            ;;
        esac
        ;;
      *)
        printf '错误：%s 的分类器给出了预定义之外的行「%s」（脚本自身缺陷，请报告）\n' \
          "$label" "$kind" >&2
        exit 1
        ;;
    esac
  done <<EOF
$stream
EOF
  if [ "$PROBE_TOTAL" -eq 0 ]; then
    printf '错误：%s 的指令行里找不到指向 %s 的引用 ⇒ 脚本常量与仓库文件已漂移。\n' \
      "$label" "$tag" >&2
    printf '       常见原因：该引用被写成引号包裹/折叠标量/--platform= 前缀/变量展开，\n' >&2
    printf '       或者 tag 已经换名（本脚本只按常量精确匹配，不做模糊猜测）。\n' >&2
    printf '       请核对该行与脚本顶部的 tag 常量；静默跳过等于把可变 tag 说成已钉版。\n' >&2
    exit 1
  fi
}

# 该目标的处置计划：check 阶段算好的三条计数 + 是否要动手。
# 计划由 probe_target 打印，供运维在跑之前就知道"这次会改哪几条"。
plan_ref() {
  label=$1
  if [ "$PROBE_BARE" -gt 0 ] || [ "$PROBE_REFRESH" -gt 0 ]; then
    printf '    %s：待钉 %s 条、待刷新 %s 条、已是本次 digest %s 条 ⇒ 本次会改动\n' \
      "$label" "$PROBE_BARE" "$PROBE_REFRESH" "$PROBE_SAME"
    return 0
  fi
  printf '    %s：%s 条指令行全都已经钉在刚捕获的 digest 上 ⇒ 本次跳过（不改动）\n' \
    "$label" "$PROBE_SAME"
  return 1
}

stage_ref() {
  src=$1
  tmp=$2
  kw=$3
  tag=$4
  want=$5
  label=$6
  want_total=$7
  # 先落到临时文件再原子替换：中途失败不会留下半改的目标文件。
  # 两条表达式的分工：
  #   ① 带锚定（行首 = 可选缩进 + 指令词 + 空白）的裸 tag → 追加刚捕获的 digest。
  #      锚定是"只改值的位置"的全部保证：注释里的示例（`# 把输出追加为 image: mongo:6.0.20…`）
  #      不在行首指令词之后，一笔不碰；旧实现用无锚定的 `s|FROM node:22.14.0-alpine|…|g`，
  #      而该字面串是钉版行的**前缀** ⇒ 已钉行也被改 ⇒ 双 digest（见上面的注释）。
  #   ② 全文 `tag@sha256:<64hex>` → 刚捕获的 digest：把"钉在别的 digest 上"的引用刷新，
  #      这是上游滚动同名 tag 之后的升级路径（旧实现把这种仓库直接判成不可操作）。
  #      它**故意不带锚定**：Dockerfile 顶部的用法注释里也写了完整的钉版引用，
  #      digest 换了若只改指令行，注释就从"正确示例"变成"错误示例"——那正是本脚本
  #      要躲开的第一类失效。digest 相同时 ② 是逐字节 no-op，所以锚定行也不会被改两遍。
  # ①在 ②之前：① 产出的 `tag@sha256:<新>` 随后被 ② 命中并替换成同一个值，不跑偏。
  # `&` 与 `\` 在替换侧是特殊字符，但 registry 引用文法（[A-Za-z0-9._-] : / @）不含二者，
  # 故原样插入。`$` 在双引号里后跟 `)` 不是变量展开，shell 会原样交给 sed 当行尾锚。
  # 分隔符用 `%` 而不是 `|`：**`|` 是 ERE 的选择运算符**，`([[:space:]]|$)` 里的 `|`
  # 会把 s 表达式提前截断（实测报 `unknown option to 's'`）。registry 引用文法不含 `%`。
  tag_re=$(to_re "$tag")
  sed -E \
    -e "s%^([[:space:]]*${kw}[[:space:]]+)${tag_re}([[:space:]]|$)%\1${want}\2%" \
    -e "s%${tag_re}@sha256:[0-9a-f]{64}%${want}%g" \
    "$src" > "$tmp"
  # 预演校验对**临时文件**再跑一遍分类器（mv 之后再报就晚了）：
  # 待钉与待刷新必须归零、指向本镜像的条数必须不变（sed 只能改形态，不能增删引用）。
  # 注意这里传给 classify_ref 的是 tmp：它把 `file` 也当全局赋值，所以原文件路径另存在
  # `src` 里——本脚本没有 local（POSIX sh 没有），同名全局会被下游改写，实测就踩过
  # "cmp 自己比自己"从而把每一次正常 staging 报成"分类与替换不一致"。
  classify_ref "$tmp" "$kw" "$tag" "$want" "$label"
  if [ "$PROBE_BARE" -ne 0 ] || [ "$PROBE_REFRESH" -ne 0 ] ||
    [ "$PROBE_TOTAL" -ne "$want_total" ]; then
    rm -f "$tmp"
    printf '错误：%s 预演失败（待钉 %s 条 / 待刷新 %s 条 / 共 %s 条，期望 %s 条全部钉好），未改动任何目标文件。\n' \
      "$label" "$PROBE_BARE" "$PROBE_REFRESH" "$PROBE_TOTAL" "$want_total" >&2
    exit 1
  fi
  # "说要改却一个字没改"是旧缺陷（sed 无匹配仍返回 0）的正面表达：这里逐字节比一次。
  if cmp -s "$src" "$tmp"; then
    rm -f "$tmp"
    printf '错误：%s 计划要改动（待钉/待刷新），但预演产物与原文件逐字节一致 ⇒ 分类与替换不一致，停止落笔。\n' "$label" >&2
    exit 1
  fi
}

commit_ref() {
  file=$1
  tmp=$2
  kw=$3
  tag=$4
  want=$5
  label=$6
  want_total=$7
  mv "$tmp" "$file"
  # mv 之后再验一次：读的是最终落盘的内容，不是内存里的预期。
  classify_ref "$file" "$kw" "$tag" "$want" "$label"
  if [ "$PROBE_BARE" -ne 0 ] || [ "$PROBE_REFRESH" -ne 0 ] ||
    [ "$PROBE_TOTAL" -ne "$want_total" ]; then
    printf '错误：%s 替换后校验失败（落盘后仍有未钉或待刷新的引用）\n' "$label" >&2
    exit 1
  fi
  printf '%s → %s（钉好 %s 条）\n' "$label" "$want" "$PROBE_SAME"
}

probe_target() {
  file=$1
  tmp=$2
  kw=$3
  tag=$4
  want=$5
  label=$6
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
  classify_ref "$file" "$kw" "$tag" "$want" "$label"
}

DOCKERFILE="$ROOT/Dockerfile"
COMPOSE="$ROOT/docker-compose.yml"
# KW_* 是**指令词**：awk 按"去掉行首空白后以该词开头、词后紧跟空白"定位指令行，
# sed 用同一条文法拼锚定。旧实现传的是行定位正则（'^FROM '、'^[[:space:]]*image: '），
# 两个阶段各写一遍、口径靠人维持——现在只有指令词这一处，分类与替换共用。
KW_FROM='FROM'
KW_IMAGE='image:'
TMP_DOCKERFILE="$DOCKERFILE.pin.tmp"
TMP_COMPOSE="$COMPOSE.pin.tmp"

# trap 只删**本脚本确认过"原本不存在"**的临时文件：这两个变量先置空，
# probe_target 通过后才赋值。少了这两步，退出时顺手 rm 掉的可能是别人放在这里的同名文件
# （probe_target 里那条"临时文件已存在"报错正是为了不覆盖它，不能转头又把它删了）。
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
echo "==> 只读分类两个目标（有任何一个够不着就一个字都不写）"
# 每个目标各自决定"动手"还是"跳过"：混合仓库（Dockerfile 已钉、compose 没钉）是本仓库
# 今天的真实状态，旧实现在这里直接退出，于是 compose 永远钉不上。
# plan_ref 读的就是 classify_ref 留下的那组全局，所以**必须紧跟在自己的 probe 之后**——
# 两个目标都分类完再统一打印会把后一个的计数安到前一个的标签上（实测打印过假 plan）。
probe_target "$DOCKERFILE" "$TMP_DOCKERFILE" "$KW_FROM" "$NODE_TAG" "$NODE_PINNED" "Dockerfile"
PIN_TMP_DOCKERFILE="$TMP_DOCKERFILE"
DF_NEEDS=0
if plan_ref "Dockerfile"; then DF_NEEDS=1; fi
DF_TOTAL=$PROBE_TOTAL
probe_target "$COMPOSE" "$TMP_COMPOSE" "$KW_IMAGE" "$MONGO_TAG" "$MONGO_PINNED" "docker-compose.yml"
PIN_TMP_COMPOSE="$TMP_COMPOSE"
CF_NEEDS=0
if plan_ref "docker-compose.yml"; then CF_NEEDS=1; fi
CF_TOTAL=$PROBE_TOTAL

if [ "$DF_NEEDS" -eq 0 ] && [ "$CF_NEEDS" -eq 0 ]; then
  printf '错误：两个目标的指令行上已经存在与刚捕获值逐字相同的 @sha256 引用 ⇒ 本次是 no-op，\n' >&2
  printf '       不该被报成成功（旧实现正是在这里"打印已替换却一字未改"）。确实只想确认状态\n' >&2
  printf '       就去掉 --apply 重跑（只读打印，不改文件）；要换 tag 请先改本文件顶部的常量。\n' >&2
  exit 1
fi

echo "==> 预演替换（只写临时文件，写完立刻对临时文件复查）"
if [ "$DF_NEEDS" -eq 1 ]; then
  stage_ref "$DOCKERFILE" "$TMP_DOCKERFILE" "$KW_FROM" "$NODE_TAG" "$NODE_PINNED" "Dockerfile" "$DF_TOTAL"
fi
if [ "$CF_NEEDS" -eq 1 ]; then
  stage_ref "$COMPOSE" "$TMP_COMPOSE" "$KW_IMAGE" "$MONGO_TAG" "$MONGO_PINNED" "docker-compose.yml" "$CF_TOTAL"
fi

echo "==> 落笔（临时文件原子改名，落盘的内容再验一次）"
if [ "$DF_NEEDS" -eq 1 ]; then
  commit_ref "$DOCKERFILE" "$TMP_DOCKERFILE" "$KW_FROM" "$NODE_TAG" "$NODE_PINNED" "Dockerfile" "$DF_TOTAL"
fi
if [ "$CF_NEEDS" -eq 1 ]; then
  commit_ref "$COMPOSE" "$TMP_COMPOSE" "$KW_IMAGE" "$MONGO_TAG" "$MONGO_PINNED" "docker-compose.yml" "$CF_TOTAL"
fi

echo
if [ "$DF_NEEDS" -eq 0 ]; then
  echo "  跳过：Dockerfile（原本就钉在本次捕获的 digest 上，一个字节都没动）"
fi
if [ "$CF_NEEDS" -eq 0 ]; then
  echo "  跳过：docker-compose.yml（原本就钉在本次捕获的 digest 上，一个字节都没动）"
fi
echo "已替换并校验。请验证："
echo "  docker compose -f $ROOT/docker-compose.yml config >/dev/null && echo compose-ok"
echo "  docker build $ROOT --target builder   # 或直接完整构建"
echo "  # 钉版形态由门禁把守（name:tag@sha256:<hex>），同一次改动要同步它的字面量："
echo "  npx jest src/tests/security/baseImageDigestPinned.test.js"
