#!/bin/sh
# shellcheck shell=sh
#
# 备份/恢复脚本共用的 MONGODB_URI 处理（两件事各一处实现）：
#   · mongo_hydrate_uri：按 `*_FILE` 约定从文件回填 MONGODB_URI
#   · mongo_swap_host：把 URI 的主机段换成容器内地址
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

# 校验一个连接串**值本身**（不论它来自显式 MONGODB_URI 还是密钥文件）。
#
# 为什么两条来源都要过，而不是只过文件那条：这个值最终会被写成
# `uri: <值>` 放进 mongodump/mongorestore 的 0600 配置文件，而它是配置里唯一
# 由调用方决定的部分。实测：
#   MONGODB_URI=$'mongodb://fsms:pw@127.0.0.1:27017/fsms?authSource=admin\ndrop: true'
#   ./scripts/restore-mongo.sh <归档>
# 因为恢复了 0 而非拒绝 ⇒ 换行把 `drop: true` 追加成配置文件的第二行，mongorestore
# 按 drop 执行；而横幅回显「删除既有 : false」、门禁也要求 `RESTORE_DROP=true` 才允许
# --drop。**门禁被一条值里的换行绕过，而现场证据声明相反**——这是恢复侧最坏的一类失效。
# 提取目标库名用的还是 `%%\?*`/`#*/` 这类截断，`?authSource=admin` 之后的内容不进库名，
# 所以确认令牌照样对得上，没有任何一环会亮。
#
# 判据与文件侧同源：单行、纯可打印 ASCII（越界字节按 tr 的八进制区间判，
# 空格也算越界——连接串里的空格必须写成 %20）、scheme 认识。
mongo_validate_uri() {
  _uri=$1
  _src=$2

  if [ -n "$(printf '%s' "$_uri" | tr -d '\041-\176')" ]; then
    printf 'Error: %s 含空白、换行或不可打印字符（应为单行纯 ASCII，特殊字符需 %%XX 转义）\n' \
      "$_src" >&2
    return 1
  fi
  case "$_uri" in
    mongodb://* | mongodb+srv://*) return 0 ;;
  esac
  printf 'Error: %s 不是 mongodb:// 或 mongodb+srv:// 连接串\n' "$_src" >&2
  return 1
}

# 按 `<NAME>_FILE` 约定从文件回填 MONGODB_URI（读不到/形状不认识 ⇒ 硬失败）。
#
# 为什么需要：`*_FILE` 回填的权威实现只有一处——src/config/secrets.js 的
# hydrateSecretsFromFiles()，而它只在「require 到 src/config 的 Node 入口」里生效。
# backup-mongo.sh / restore-mongo.sh 是纯 shell，从来没接上：运维照
# deployment/backup-encryption.md 的每日 cron（`MONGODB_URI_FILE=… backup-mongo.sh`）
# 跑，脚本只看 MONGODB_URI，于是每次都是
# `Error: MONGODB_URI environment variable is not set` + 退出码 1。报错是响的，
# 但响在 cron 的 stderr 里没人听——备份产出连续为零只在真要恢复的那天被发现。
#
# 与 Node 侧刻意的两处不同（其余语义一致：去 UTF-8 BOM、去尾部 CR/换行）：
#   1. 谁赢：Node 侧「文件赢」——应用只被 compose 在启动时配一次，文件是唯一真源。
#      这里「显式 MONGODB_URI 赢」——调用方是人在命令行上点名目标库
#      （`MONGODB_URI='<目标串>' ./scripts/restore-mongo.sh <归档>`，README/恢复手册
#      就是这么写的）。若被环境里残留的 MONGODB_URI_FILE 覆写，恢复会静默打进
#      另一个库：把备份写进错误的目标，比连不上严重一个量级。并存时打 warning，
#      让 cron 邮件里看得见。
#   2. 空文件/多条非空行一律拒绝。静默取第一条非空行等于连一个「文件里写了但
#      没人知道」的库；空文件则会让下面的 `-z` 检查把原因报成「变量没设置」。
mongo_hydrate_uri() {
  if [ -n "${MONGODB_URI:-}" ]; then
    if [ -n "${MONGODB_URI_FILE:-}" ]; then
      printf 'Warning: MONGODB_URI 与 MONGODB_URI_FILE 同时存在，按显式 MONGODB_URI 执行（忽略 %s）\n' \
        "$MONGODB_URI_FILE" >&2
    fi
    mongo_validate_uri "$MONGODB_URI" "MONGODB_URI" || return 1
    return 0
  fi
  if [ -z "${MONGODB_URI_FILE:-}" ]; then
    return 1
  fi

  _file=$MONGODB_URI_FILE
  if [ ! -f "$_file" ]; then
    printf 'Error: MONGODB_URI_FILE 不是可读的普通文件：%s\n' "$_file" >&2
    return 1
  fi

  # 一律经 stdin 读，不把 $_file 作为操作数交给 grep/sed：文件名以 `-` 开头时
  # （`MONGODB_URI_FILE=-c` 是实测过的形态）它会被当成选项，grep 转去读**调用方的
  # stdin**，于是密钥文件从头到尾没被打开，而报错却说"内容不是连接串"——
  # 说的是它根本没读过的字节。cat -- 之后所有环节只碰管道，没有可被误认成选项的参数。
  if ! _body=$(cat -- "$_file" 2>/dev/null); then
    printf 'Error: MONGODB_URI_FILE 读取失败：%s\n' "$_file" >&2
    return 1
  fi

  # grep -c 无命中时打印 0 并以 1 退出；`|| _n=0` 同时兜住"输出被上层吞掉变成空串"，
  # 否则 `[ "" -eq 0 ]` 会抛 shell 的 integer 表达式错误，退出码与原因都不对。
  _n=$(printf '%s\n' "$_body" | grep -c '[^[:space:]]') || _n=0
  if [ "$_n" -eq 0 ]; then
    printf 'Error: MONGODB_URI_FILE 是空文件（没有任何非空行）：%s\n' "$_file" >&2
    return 1
  fi
  if [ "$_n" -gt 1 ]; then
    printf 'Error: MONGODB_URI_FILE 里有 %s 条非空行，应为 1 条：%s\n' "$_n" "$_file" >&2
    return 1
  fi

  # 只有一条非空行时才会走到这里。取该行：
  #   · `s/^[^ -~]*//` 去掉行首的非可打印 ASCII 字节 —— 现实场景是 UTF-8 BOM
  #     （Windows 记事本 / `Set-Content -Encoding UTF8` 写出的密钥文件）。
  #     连接串本身全是 ASCII，绝不会以这类字节开头，所以这一步不会误伤。
  #   · `s/[[:space:]]*$//` 去掉行尾空白与 CR（CRLF 文件、编辑器残留）。
  MONGODB_URI=$(printf '%s\n' "$_body" | grep -m 1 '[^[:space:]]' |
    sed -e 's/^[^ -~]*//' -e 's/[[:space:]]*$//')

  # 连接串必须是**单行纯可打印 ASCII**（凭据里的特殊字符按 RFC 3986 写成 %XX）。
  # 空白/控制字符留在中间时，mongodump 只会报一个和"密钥文件写坏了"毫无关系的解析错，
  # 所以在这里点名文件拒绝掉。
  # 这条不是假想：探针实测过——用 `printf 'mongodb+srv://u:p%40ss@h/db'` 生成夹具时
  # `%40s` 被 printf 当成宽度说明符，落盘成"40 个空格"，而前缀形状检查照样放行。
  # 触发它的正是这份夹具自己，因此判据必须包含不可打印字符，而不只是"像不像 URI"。
  #
  # 用 tr 而不是 case 的字符类：`*[! -~]*` 在 bash 里是语法错误（实测），而
  # `[:print:]` 在 UTF-8 locale 下把非 ASCII 也算"可打印"，会漏掉 BOM 出现在中间的情形。
  # tr 按字节做八进制区间，任何 locale 下都精确。两个坑都实测过：
  #   · 区间必须写成 3 位八进制 —— `'\040-\0176'` 被解析成 `\017` 加字面量 '6'（漏检）。
  #   · 起点是 \041 不是 \040：空格属于"可打印 ASCII"，但合法连接串里绝不该有空格
  #     （要写成 %20），把它算进允许集就等于放行上面那条夹具事故。
  mongo_validate_uri "$MONGODB_URI" "MONGODB_URI_FILE 的内容（$_file）" || return 1
}
