#!/bin/sh
# shellcheck shell=sh
#
# 备份/恢复脚本共用的 MONGODB_URI 处理（两件事各一处实现）：
#   · mongo_hydrate_uri：按 `*_FILE` 约定从文件回填 MONGODB_URI
#   · mongo_swap_host：把 URI 的主机段换成容器内地址
#
# 为什么单独成文件：backup-mongo.sh 与 restore-mongo.sh 各自维护过一份一模一样的
# 主机段替换（`sed -E "s#^((mongodb(\+srv)?://)([^/]*@)?)[^/]*#\1${MONGO_CONTAINER_HOST}#"`），
# 而两处的失败判据都是"替换后与原串相同 ⇒ 认定形态不认识"。这个判据有个真实的假阳性：
# 无凭据且主机本来就写成了目标地址（`mongodb://127.0.0.1:27017/fsms`，在容器内跑脚本时
# 就是这一形态）会被判成"URI 形态异常"而拒绝执行——备份/恢复在最需要它们的时候报错。
# 现在这条替换是**纯 shell 字符串重建，不再有 sed**，因为 sed 形态带着两处实测到的失效：
#   · 替换串里的字面 `\n` 被 GNU sed 展开成真换行 ⇒
#     `MONGO_CONTAINER_HOST='127.0.0.1:27017\ncollection:auditLog'` 能给 mongodump 的
#     0600 配置追加第二行，单集合导出被记成一次**成功的全量备份**；
#   · 口令里未转义的 `/` 会终结 `[^/]*` 那次匹配 ⇒ 替换错位
#     （`mongodb://u:p/x@h:27017/db` → `mongodb://127.0.0.1:27017/x@h:27017/db`），
#     凭据被静默丢弃，而横幅承诺的是 `h:27017`/`db`。
# 但"去掉 sed"只改变了取字节的方式，**取哪一段**的判据本身还留着五条同根缺陷
# （2026-10-03 逐条实测；产物都写成 `mongodb://…` 原样交给 mongodump）：
#   1. 静默改错主机：`mongodb://u:p@db.internal:27017?appname=bob@corp`（无路径、查询串里有
#      裸 `@`）⇒ rc=0，输出 `mongodb://u:p@db.internal:27017?appname=bob@127.0.0.1:27017`。
#      主机段根本没动，目标地址被拼进了查询串——横幅承诺 127.0.0.1，mongodump 连的是
#      db.internal。根因：取段用 `case */* | \?* | *` 三分支，第三条分支把整串（含查询串）
#      当成 authority，再用 `##*@`（**最后**一个 `@`）切凭据。
#   2. 副本集种子列表被拒：`mongodb://a:27017,b:27017/db?replicaSet=rs0` ⇒ rc=1
#      （逗号不在字符集判据里）——合法 URI 备份不了，报的却是"形态异常"。
#   3. 无路径带查询被拒：`mongodb://h:27017?directConnection=true` ⇒ rc=1（同 1 的分支缺陷：
#      `\?*` 只匹配**以** `?` 开头的串，于是查询串并进主机段，`?`/`=` 再撞字符集判据）。
#   4. IPv6 容器地址当目标被拒：`MONGO_CONTAINER_HOST='[::1]:27017'` ⇒ rc=1（方括号不在目标
#      字符集里），而 URI 里写 `[::1]:27017` 却是放行的——同一件事两侧判据不一致。
#   5. 交回一个 mongodump 自己都不认的串：`mongodb://a@b@c:27017/db` ⇒ rc=0，输出
#      `mongodb://a@b@127.0.0.1:27017/db`；`mongodb+srv://u:p@cluster0.example.net/fsms`
#      ⇒ rc=0，输出带端口的 `mongodb+srv://…:27017`（`+srv` 禁止端口）。参考解析器两条都抛。
# 所以取段判据改成按**参考解析器怎么读主机段**来定（顶层 mongodb 内嵌的
# mongodb-connection-string-url；本仓按同一族包钉行为的另一处是 src/config/database.js:51，
# 那里判的是它的报错形态）。三条正面规则 + 一条兜底：
#   · authority 终止于**第一个** `/`、`?` 或 `#`（RFC 3986 与该包 hosts 段的字符类同一口径），
#     凭据与主机的分界取**第一个** `@`（该包的 username/password 字符类都不含 `@`）；
#   · 主机段允许逗号分隔的种子列表，每项都得是 `host[:port]` 或 `[IPv6][:port]`；
#   · 主机段已经等于目标地址 ⇒ 合法的空操作，放行（旧判据在这里假阳性，见开头那条）；
#   · 其余认不出来的形态一律硬失败，绝不"原样返回"——宁可拒，也不要静默连到宿主机名上。
# 刻意比参考解析器更严的两处（失效方向是"响亮拒绝"而不是"静默连到别处"，故可接受）：
#   · `mongodb://h:/db`（空端口）它读成 hosts=["h:27017"]——空端口被**静默补成默认端口**，我们拒；
#   · `mongodb+srv://…` 而目标带端口时也拒（`+srv` 禁端口，容器内地址按实际部署必然带端口）。
#   真撞上运维看到的是"无法把 URI 主机段改写为容器内地址"，而不是一个连向别处的串。
# 一条**负结果**，防止下一个读者把 `#` 也当成缺陷：第一版这里写着"`mongodb://h#1/db`
# 解析器读成 ["h#1"]，所以我们更严"，实测不成立——参考解析器把它读成
# hosts=["h:27017"]、db="db"，即 `#` 同样终止 authority（与本文件 `${_rest%%[/?#]*}`
# 的取段判据同一口径），而片段区里的 `/db` 仍然是库名。这一形态因此是**放行**的，
# 由 parity 闸逐条比对主机/库名/凭据。同族的 `mongodb://h/my#db` 库名被解析器截成 `my`
# 是它自身的规则（`#` 之后是片段）：改写把尾部原样保留，没有制造任何新差异。
# 判据的承重面由 src/tests/config/mongoTransportParity.test.js 用**真解析器**
#   跑一遍（改写产物必须解析成"主机就是横幅里那个目标地址、库名与凭据没变"），
#   而不是断言源码里含某个字符串——注释不执行，也不能当证据。
# 凭据段与查询串一律原样保留：调用方随后把结果写进 0600 的配置或管道，绝不上 argv。

# 端口：纯数字且落在 1..65535。参考解析器对这两条越界形态都**报错**（实测）：
#   `h:0` ⇒ 'Invalid port (zero) with hostname'，`h:65536` ⇒ 'Unable to parse h:65536 with URL'。
# 放行它们的失效方向不是"响亮拒绝"而是"顺手把坏端口换掉了"：改写后的产物解析得动，
# 于是运维拿到的是一个从来不存在、也从来没被 mongodump 拒过的 URI（横幅却写着原库名/原凭据）。
# 前导零按解析器的读法处理（`07017` 它读成 7017）：剥掉前导零再比长度与字典序。
# 刻意不用 `$(( ))`——shell 把 0 前缀当八进制，`08` 会算错甚至直接报错，
# 而这里是字符串判据，不存在进制陷阱。
mongo_valid_port() {
  _p=$1
  case "$_p" in
    '' | *[!0-9]*) return 1 ;;
  esac
  _t=${_p#"${_p%%[!0]*}"}
  # 全零 ⇒ 剥完是空串（0 端口）；6 位以上；以及 65536..99999 的每一段。
  # 这五个模式合起来正好是"5 位且 > 65535"，逐个区间写死而不用比较运算符：
  # `[ "$a" \< "$b" ]` 不是 POSIX（dash 不支持），而本文件必须是 `sh`。
  case "$_t" in
    '' | ??????*) return 1 ;;
    6553[6-9] | 655[4-9]? | 65[6-9]?? | 6[6-9]??? | [7-9]????) return 1 ;;
  esac
  return 0
}

# 单个主机项：`host[:port]` 或 `[IPv6][:port]`。逗号列表由 mongo_valid_hostlist 逐项交给它。
# 判据按**参考解析器怎么读主机段**来定，而不是按 RFC 的字面：这个函数的产物会原样写进
# mongodump 的 0600 配置，"横幅承诺的主机"必须等于"实际被拨号的主机"。逐条对应实测：
#   · `h:1:2` ⇒ 'Unable to parse h:1:2 with URL' ⇒ 第二个冒号拒；
#   · 未加方括号的 IPv6（`::1:27017`）⇒ 同族报错，而前导冒号也撞"空 userinfo"判据 ⇒ 拒；
#   · `[::1]` 不带端口合法（SRV/默认端口场景），`[::1]x`、`[::1]:`、`[::1]:1:2` 拒；
#   · 端口区间由 mongo_valid_port 统一判（`h:0`、`h:65536`、`[::1]:65536` 一起拒）。
# 括号内做的是**字符集**判据（只留十六进制与冒号），不是"整段跳过方括号"：越界字节
# （空格、换行、`]`）留在括号里时，靠下游 mongodump 报错等于把"配置被改写"伪装成解析错。
mongo_valid_hostport() {
  _h=$1

  case "$_h" in
    \[*\])
      _inner=${_h#\[}
      _inner=${_inner%\]}
      case "$_inner" in
        '' | *[!0-9A-Fa-f:]*) return 1 ;;
      esac
      return 0
      ;;
    \[*\]:*)
      _inner=${_h#\[}
      _inner=${_inner%%\]:*}
      case "$_inner" in
        '' | *[!0-9A-Fa-f:]*) return 1 ;;
      esac
      _suffix=${_h#*\]}
      case "$_suffix" in
        :*) ;;
        *) return 1 ;;
      esac
      mongo_valid_port "${_suffix#:}" || return 1
      return 0
      ;;
  esac

  case "$_h" in
    '' | :*) return 1 ;;
    *[!A-Za-z0-9.:_-]*) return 1 ;;
  esac
  case "$_h" in
    *:*)
      case "${_h%:*}" in
        *:*) return 1 ;;
      esac
      mongo_valid_port "${_h##*:}" || return 1
      ;;
  esac
  return 0
}

# 逗号分隔的种子列表（副本集）。空项一律拒：参考解析器把 `a,,b` 读成"少一个主机"，
# 而"少一个种子"在备份脚本里正是那种现场看不出来的差异。
mongo_valid_hostlist() {
  _list=$1

  # 判据是"首/尾/连续逗号 = 空项"。注意 `case` 的模式里**给 `*` 加引号会让它变成字面量**
  # （实测 `case "h:27017," in "*,")` 不命中，而 `*,)` 命中）：逗号本身不是元字符，
  # 这里必须让 `*` 保持通配。本文件其余带引号的模式都只引首字符（`'@'*`、`*'['*`），
  # 那才是"字面量 + 通配"的正确写法。
  case "$_list" in
    '' | ,* | *,) return 1 ;;
  esac
  while [ -n "$_list" ]; do
    case "$_list" in
      *,*) _item=${_list%%,*}; _list=${_list#*,} ;;
      *) _item=$_list
        _list='' ;;
    esac
    mongo_valid_hostport "$_item" || return 1
  done
  return 0
}

# userinfo（authority 里第一个 `@` 之前那段）。参考解析器对 username/password 用的非法
# 字符集是 `/[:/?#[\]@]/gi`，其中 `/`、`?`、`#`、`@` 在到达这里之前已被取段规则排除
# （authority 终止于第一个 `/ ? #`，userinfo 取第一个 `@` 之前），所以真正还要判的只有
# 方括号与多余冒号。`u:@h`（空口令）是放行的——实测参考解析器接受它。
mongo_valid_userinfo() {
  _ui=$1

  case "$_ui" in
    *'['* | *']'*) return 1 ;;
    *:*:*) return 1 ;;
  esac
  return 0
}

mongo_swap_host() {
  _uri=$1
  _target=$2

  case "$_uri" in
    mongodb://* | mongodb+srv://*) ;;
    *) return 1 ;;
  esac
  _scheme=${_uri%%://*}

  # 目标地址与 URI 里的主机段过**同一个**判据。旧写法两边各一套字符集，于是
  # `[::1]:27017` 在 URI 里放行、作为 MONGO_CONTAINER_HOST 却拒绝（实测缺陷 4）。
  mongo_valid_hostport "$_target" || return 1
  if [ "$_scheme" = 'mongodb+srv' ]; then
    # `+srv` 靠 DNS SRV 发现种子列表，形态上禁止端口（'mongodb+srv URI cannot have port
    # number'），而容器内地址按实际部署必然带端口（默认 127.0.0.1:27017）。旧写法照样改写
    # 并交出 `mongodb+srv://u:p@127.0.0.1:27017/fsms`——mongodump 直接拒。这里硬拒并把原因说明白。
    case "$_target" in
      *:*) return 1 ;;
    esac
  fi

  _rest=${_uri#*://}
  # 空的 userinfo 段（`mongodb://@h/db`、`mongodb://:p@h/db`）：参考解析器直接拒
  # （'URI contained empty userinfo section'）。旧写法把它当"没有凭据"静默改写通过。
  case "$_rest" in
    '@'* | ':'*) return 1 ;;
  esac

  # authority 终止于**第一个** `/`、`?` 或 `#`（RFC 3986 与参考解析器 hosts 段的字符类同一
  # 口径），尾部整段原样保留。旧写法用 `case */* | \?* | *` 三分支，第三条分支在"无路径但
  # 有查询串"时把整串（含查询串）当成 authority ⇒ 实测
  # `mongodb://u:p@db.internal:27017?appname=bob@corp` 的产物是
  # `…?appname=bob@127.0.0.1:27017`：主机段没动，目标地址被拼进了查询串。
  _auth=${_rest%%[/?#]*}
  _tail=${_rest#"$_auth"}
  if [ -z "$_auth" ]; then
    # `mongodb://` 之后什么都没有（或紧跟 `/`）：不是可识别的 `scheme://[creds@]host[/db][?opts]`
    return 1
  fi

  case "$_auth" in
    *@*)
      # 凭据与主机的分界取**第一个** `@`：参考解析器的 username/password 字符类都不含 `@`，
      # 它读的也是第一个。旧写法 `%%@*`/`##*@` 取最后一个，于是 `a@b@c:27017/db` 被切成
      # "凭据 = a@b、主机 = c:27017"，产物里的裸 `@` 让解析器报 'Invalid connection string'。
      _creds=${_auth%%@*}
      _host=${_auth#*@}
      case "$_host" in
        *@*) return 1 ;;
      esac
      mongo_valid_userinfo "$_creds" || return 1
      ;;
    *)
      _creds=''
      _host=$_auth
      # 没有凭据时，路径/查询串里的裸 `@` 会被解析器当成 userinfo 分隔符**吃掉主机段**：
      # 实测 `mongodb://h:27017/db@x` 读成 username=h、password=`27017/db` ⇒
      # 'Password contains unescaped characters'。这种输入本身无效，改写它只是把一个已经
      # 坏掉的串交回调用方，所以点名拒绝。有凭据时不受影响（分隔符已在第一个 `@` 处用掉）：
      # `mongodb://u:p@mongo/db@name` 合法，库名里的 `@` 不参与主机段提取。
      case "$_tail" in
        *@*) return 1 ;;
      esac
      ;;
  esac

  # 主机段必须"确实是一个主机列表"，否则整次重建都是在猜。副本集种子列表（逗号分隔）与
  # `[::1]:27017` 都是合法形态，旧写法按单主机 + 不含逗号的字符集判据把它们一起拒了
  # （实测缺陷 2、3、4：备份不了合法 URI，报的却是"形态异常"）。
  mongo_valid_hostlist "$_host" || return 1
  if [ "$_scheme" = 'mongodb+srv' ]; then
    case "$_host" in
      *,*) return 1 ;;
    esac
  fi

  if [ "$_host" = "$_target" ]; then
    # 合法空操作也要过一次值判据。少了这一步，"主机段本来就等于目标地址"的 URI
    # 会绕过全部换行/不可打印检查被原样交回调用方，而调用方紧接着就把返回值
    # 写进 mongodump 的 0600 配置（实测形态：`$'mongodb://127.0.0.1:27017/fsms\ndrop:true'`
    # 配 `MONGO_CONTAINER_HOST=127.0.0.1:27017`）。上游 hydrate 确实会拒它，
    # 但判据不能靠调用方的顺序——这正是本函数存在的理由（一处实现，两侧共用）。
    mongo_validate_uri "$_uri" "MONGODB_URI（主机段已等于目标地址，未改写）" || return 1
    printf '%s' "$_uri"
    return 0
  fi

  if [ -n "$_creds" ]; then
    _new="${_scheme}://${_creds}@${_target}${_tail}"
  else
    _new="${_scheme}://${_target}${_tail}"
  fi
  if [ "$_new" = "$_uri" ]; then
    return 1
  fi
  # 重建结果再过一次值判据：越界字节留在中间时 mongodump 只会报一个和"配置被改写"
  # 毫无关系的解析错，所以在这里点名拒绝。
  mongo_validate_uri "$_new" "MONGO_CONTAINER_HOST 改写后的连接串" || return 1
  printf '%s' "$_new"
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

  # 哨兵是必需的，不是装饰：命令替换会剥掉**尾部**全部换行，所以
  #   $(printf '%s' "$_uri" | tr -d '\041-\176')
  # 对"注入内容本身全是可打印 ASCII、只靠换行分隔"的载荷返回空串 ⇒ 放行。实测形态：
  #   MONGODB_URI=$'mongodb://fsms:pw@10.0.0.5:27017/fire_safety?authSource=admin\ndrop:true'
  # 旧写法照样退 0，`drop:true` 成为配置文件的第二行，而横幅回显「删除既有 : false」——
  # 门禁被值里的一条换行绕过，现场证据还声明相反。
  # 先补一个哨兵字符再比较：残串只可能是越界字节（可打印 ASCII 已被 tr 删掉），
  # 因此 "残串+哨兵" 等于哨兵 当且仅当 残串为空，判据无歧义。
  if [ "$(printf '%s' "$_uri" | tr -d '\041-\176'; printf '~')" != '~' ]; then
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
