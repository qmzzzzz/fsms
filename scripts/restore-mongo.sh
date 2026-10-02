#!/bin/bash

# MongoDB 恢复脚本
# 用法: ./scripts/restore-mongo.sh <backup_file>
#
# 环境变量：
#   MONGODB_URI      必填（或用 MONGODB_URI_FILE 指向密钥文件），目标库连接串
#                    **必须含库名**（`…/fire_safety?authSource=admin`）：没有库名时
#                    恢复范围由归档内容决定，确认门禁无从核对，脚本直接拒绝执行
#                    恢复目标是破坏性写入的落点，故命令行点名的 MONGODB_URI 一定赢过
#                    环境里残留的 MONGODB_URI_FILE（两者并存时告警，不静默改目标）
#   RESTORE_CONFIRM  非交互场景下的确认令牌，须等于目标库名
#   RESTORE_SKIP_CHECKSUM 可选，默认 false。true = 跳过 <归档>.sha256 完整性校验，
#                    仅用于恢复无校验和的历史/外部归档；缺失 sidecar 本身是硬失败
#   MONGO_RESTORE_TRANSPORT 可选，local | docker（默认 docker，与 backup-mongo.sh 同口径）
#   MONGO_COMPOSE_SERVICE   可选，容器内执行 mongorestore 的服务名（默认 mongo）
#   MONGO_CONTAINER_HOST    可选，容器内连接地址（默认 127.0.0.1:27017）
#   COMPOSE_FILE            可选，compose 文件路径（默认 docker-compose.yml）
#
# 【P1-① 加密归档】（2026-09-30）：backup-mongo.sh 默认产出 .gz.gpg（gpg 非对称
# 加密，见 scripts/backupCrypto.sh）。本脚本按**后缀**自动识别：*.gz.gpg 先解密到
# 0600 临时文件再走既有恢复链路；*.gz 旧归档原样支持。解密需要**私钥**——
# 它按设计不在备份宿主机上，恢复演练就是验证"私钥托管 + 异地副本"这条链的。
#
# 【P2-27 恢复必须有门禁】
# 恢复是**破坏性**操作：mongorestore 会把归档内容写入目标库，
# 原实现仅检查文件存在与 URI 非空便直接执行——把生产 URI 填错一次即覆盖生产数据，
# 且无任何二次确认。此处补三道门禁：
#   1. 解析并回显目标主机与库名（让操作者看到自己到底在恢复到哪）
#   2. 交互式终端要求键入库名确认；非交互（CI/cron）要求 RESTORE_CONFIRM 匹配库名
#   3. --drop 需显式 RESTORE_DROP=true，默认不删除既有集合
#
# 另：原实现在 `set -e` 下写了 `if [ $? -eq 0 ]; ... else ... fi`，
# mongorestore 一旦失败脚本已经退出，else 分支永远不会执行——是误导运维的死代码，已移除。

set -euo pipefail

# 与 backup-mongo.sh 共用同一个 URI 主机段改写判据（见该文件注释）
. "$(dirname "$0")/mongoUri.sh"
# 加密/解密/校验和的共享实现（P1-①）：.gz.gpg 归档的解密走这里
. "$(dirname "$0")/backupCrypto.sh"

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <backup_file>" >&2
  echo "Example: $0 backups/fire-safety-backup-20240101-1200.gz" >&2
  exit 1
fi

BACKUP_FILE=$1

if [ ! -f "$BACKUP_FILE" ]; then
  echo "Error: Backup file not found: $BACKUP_FILE" >&2
  exit 1
fi

# ================= 完整性校验（解密与写库之前）=================
# 备份侧对**每个**产物都写一份 .sha256（backup-mongo.sh 的加密与明文两条分支都调
# crypto_checksum），但恢复侧此前从不读它：从异地取回的归档哪怕传错文件、被截断、
# 被替换，也照样进 mongorestore。deployment/backup-encryption.md 把「先 sha256sum
# --check」写成恢复前的人工步骤——一道只存在于文档、代码从不执行的防线等于没有防线，
# 而恢复恰恰是在最糟的时刻（数据已经出事）才跑的那条路径。
#
# 校验对象是**取回的原文件**（密文或明文归档），放在解密之前 ⇒ 覆盖传输/存储环节的
# 全部损坏；私钥对不对由后续 gpg 自己判。
#
# 比对**哈希值**而不用 `sha256sum --check`：sidecar 里记的是备份宿主机上的路径字符串
# （含目录；Windows 侧还会带 \ 转义与 * 二进制模式标记），而异地副本常被改名或换目录，
# --check 会因为文件名对不上直接报 "no such file"——那等于逼操作者跳过校验。
#
# 缺 sidecar 按失败处理（与"忘配加密 = 硬失败"同一条口径）：静默放行会让
# "有没有校验和"退化成"备份文件有没有被完整复制"的运气。确需恢复无校验和的
# 历史/外部归档时，显式 RESTORE_SKIP_CHECKSUM=true，且警告走 stderr。
CHECKSUM_FILE="$BACKUP_FILE.sha256"
if [ "${RESTORE_SKIP_CHECKSUM:-false}" = "true" ]; then
  echo "警告：RESTORE_SKIP_CHECKSUM=true —— 本次恢复的归档未经任何完整性证明" >&2
elif [ ! -f "$CHECKSUM_FILE" ]; then
  echo "Error: 缺少校验和文件：$CHECKSUM_FILE" >&2
  echo "       备份脚本会为每个产物生成 .sha256，异地取回时须一并取回。" >&2
  echo "       确需恢复无校验和的归档：显式设置 RESTORE_SKIP_CHECKSUM=true（不建议）" >&2
  exit 1
else
  # grep -oE 只取 64 位十六进制串：与 sidecar 的分隔符形态（两空格 / 单个 * / 前置 \）解耦。
  # `|| true` 是必需的：set -e + pipefail 下 grep 无匹配会让赋值命令替换直接结束脚本，
  # 那样下面那个 -z 分支永远走不到（一道写在那里却不可能执行的分支，和死代码同罪）。
  EXPECTED_HASH=$(grep -oE '[0-9a-f]{64}' "$CHECKSUM_FILE" | head -1 || true)
  ACTUAL_HASH=$(sha256sum "$BACKUP_FILE" | grep -oE '[0-9a-f]{64}' | head -1 || true)
  if [ ${#EXPECTED_HASH} -ne 64 ]; then
    echo "Error: 校验和文件里解析不出 sha256（期望 64 位十六进制）：$CHECKSUM_FILE" >&2
    exit 1
  fi
  if [ -z "$ACTUAL_HASH" ]; then
    echo "Error: 无法为归档计算 sha256（sha256sum 不可用或文件不可读）：$BACKUP_FILE" >&2
    exit 1
  fi
  if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
    echo "Error: 归档完整性校验失败 —— 已终止恢复（未解密、未写库）" >&2
    echo "       期望 $EXPECTED_HASH" >&2
    echo "       实际 $ACTUAL_HASH" >&2
    echo "       文件 $BACKUP_FILE" >&2
    exit 1
  fi
  echo "完整性校验通过：sha256=${ACTUAL_HASH}"
fi

# 与 backup-mongo.sh 同口径：先按 `*_FILE` 约定回填，再判空（判据见 mongoUri.sh）。
# 恢复的目标库只在这里确定，因此"显式 MONGODB_URI 优先于 MONGODB_URI_FILE"
# 是刻意的——命令行点名目标时必须赢，否则环境里残留的 *_FILE 会把恢复静默打进另一个库。
if ! mongo_hydrate_uri; then
  echo "Error: 需要 MONGODB_URI，或 MONGODB_URI_FILE 指向的密钥文件" >&2
  exit 1
fi

# 传输方式与 backup-mongo.sh 同口径：本仓 compose 里 mongo 只 `expose` 不 `publish`
# （URI 主机段是容器名），宿主机既连不上它、也常常没装 mongorestore CLI。
# 备份侧早就为此提供 docker 传输，恢复侧没有 ⇒ "数据级回滚抓手"要在真正用的那天
# 才发现跑不通，这是最贵的发现时机。默认 docker，local 仍保留给本机/直连场景。
MONGO_RESTORE_TRANSPORT=${MONGO_RESTORE_TRANSPORT:-docker}
MONGO_COMPOSE_SERVICE=${MONGO_COMPOSE_SERVICE:-mongo}
MONGO_CONTAINER_HOST=${MONGO_CONTAINER_HOST:-127.0.0.1:27017}

case "$MONGO_RESTORE_TRANSPORT" in
  local)
    if ! command -v mongorestore >/dev/null 2>&1; then
      echo "Error: mongorestore not found in PATH（MONGO_RESTORE_TRANSPORT=local）" >&2
      exit 1
    fi
    ;;
  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo "Error: docker 不在 PATH 中（MONGO_RESTORE_TRANSPORT=docker）" >&2
      exit 1
    fi
    ;;
  *)
    echo "Error: MONGO_RESTORE_TRANSPORT 只能是 local 或 docker（当前：'${MONGO_RESTORE_TRANSPORT}'）" >&2
    exit 1
    ;;
esac

# ================= 目标识别 =================
# 从 URI 中剥离凭据后提取 host 与库名用于回显（绝不打印口令部分）。
# 用 `##*@`（最长匹配）而不是 `#*@`（最短匹配）：口令里出现未转义的 `@` 时，
# 最短匹配会把"口令的后半段@…"当成主机起点留在回显里——实测
# `mongodb://fsms:Sup3r!ca@99@10.0.0.5:27017/fsms` 原先打印成
# `目标主机 : 99@10.0.0.5:27017`，把口令尾巴送进了 stdout（cron 邮件、CI 日志都会收走）。
# 以主机段里**最后一个** `@` 界定 userinfo 的那一侧是 WHATWG/RFC 3986 口径——本机实测的
# 读者是 Node 的 `new URL`（同一条串它给出 hostname=10.0.0.5）；mongorestore/mongodump 的
# Go 解析器本机没有二进制，方向上应与之一致，那是**推断**。所以"剥到最后一个 @"取的是
# 两个读者中更保守的那一侧：无论哪个是对的，回显里都不会剩口令字节。
# 需要限定主语：本仓用作 parity 的那个 JS 连接串包对**同一条串**读出的是另一段主机——实测
# `mongodb://fsms:Sup3r!ca@99@10.0.0.5:27017/fsms` 在它眼里 hosts=["99:27017"]。两个读者对
# 未转义 `@` 的读法不一致，正是 mongoUri.sh 里"凭据段有裸 @ ⇒ 硬拒"的理由；只有 local 传输
# （URI 原样交给 mongorestore）才会走到这里的回显。
URI_NO_CRED=${MONGODB_URI#*://}
URI_NO_CRED=${URI_NO_CRED##*@}
TARGET_HOST=${URI_NO_CRED%%/*}
TARGET_DB=${URI_NO_CRED#*/}
TARGET_DB=${TARGET_DB%%\?*}
# 库名还要在**第一个** `#` 处截断：`#` 之后是片段，参考解析器不把它算进库名（实测
# `mongodb://u:p@h:27017/fsms#prod` 的 dbName 是 `fsms`）。少了这一步，回显与
# `RESTORE_CONFIRM`/键入要核对的名字是 `fsms#prod`，而真正恢复进去的库是 `fsms`——
# 门禁核对的是一个从来不存在目标库名，"两处点名一致"这条语义就断了。
# 残余：库名里写成 `%23` 的转义 `#` 不会被这一步截断，回显因此是编码形态
# （`fsms%23prod`，解析器解码成 `fsms#prod`）。它不会让门禁核对到**别的库**，
# 只是把同一个库名以编码形态出示，运维照抄即可。
TARGET_DB=${TARGET_DB%%#*}
if [ "$TARGET_DB" = "$URI_NO_CRED" ] || [ -z "$TARGET_DB" ]; then
  # 门禁的语义是"你在两处点名的目标必须一致"：一处是 URI，一处是 RESTORE_CONFIRM/键入。
  # URI 里没有库名时只剩一处，原来的兜底是把一句固定文案当作待确认的"库名"——
  # 而那句话恰好被拒绝信息原样回显（`期望 '(未在 URI 中指定，将按归档内的库名恢复)'`），
  # 于是第二次运行把这句抄进 RESTORE_CONFIRM 就能放行，门禁自己印出了自己的钥匙，
  # 实际恢复范围变成"归档里有哪些库就恢复哪些"。
  echo "Error: MONGODB_URI 未指定库名，恢复目标将由归档内容决定 ⇒ 确认门禁无从核对，拒绝执行" >&2
  echo "       请在连接串末尾写明目标库：mongodb://<用户>:<口令>@<主机>:27017/<库名>?authSource=admin" >&2
  exit 1
fi

echo "=============================================="
echo " MongoDB 恢复操作（破坏性）"
echo "   归档文件 : $BACKUP_FILE"
echo "   目标主机 : $TARGET_HOST"
echo "   目标库名 : $TARGET_DB"
echo "   删除既有 : ${RESTORE_DROP:-false}"
echo "=============================================="

# ================= 门禁 =================
if [ -t 0 ]; then
  # 交互式终端：要求键入目标库名
  printf '请键入目标库名以确认恢复（Ctrl-C 取消）: '
  read -r ANSWER
  if [ "$ANSWER" != "$TARGET_DB" ]; then
    echo "Error: 确认输入与目标库名不一致，已取消" >&2
    exit 1
  fi
else
  # 非交互（CI / cron）：要求预置 RESTORE_CONFIRM
  if [ "${RESTORE_CONFIRM:-}" != "$TARGET_DB" ]; then
    echo "Error: 非交互环境需设置 RESTORE_CONFIRM=<目标库名> 才能执行恢复" >&2
    echo "       当前 RESTORE_CONFIRM='${RESTORE_CONFIRM:-}'，期望 '$TARGET_DB'" >&2
    exit 1
  fi
fi

# ================= 凭据保护（同 backup 口径） =================
CONFIG_FILE=""
DECRYPTED_FILE=""
cleanup() {
  if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
    rm -f "$CONFIG_FILE"
  fi
  if [ -n "$DECRYPTED_FILE" ] && [ -f "$DECRYPTED_FILE" ]; then
    rm -f "$DECRYPTED_FILE"
  fi
}
# INT/TERM 必须**自己收尾退出**：`trap cleanup EXIT INT TERM` 在同一条 trap 里只做清理
# 不做 exit，信号打断 mongorestore 后脚本会**继续往下跑**（cleanup 已把 0600 配置删掉、
# umask 也还原了），后面的成功回显照打。备份侧实测过同一形态：产出一份 5 字节的
# 半成品归档并打印 "Backup completed successfully"，还补写了 .sha256 ——
# 于是它在回滚清单上就是一次"好备份"。恢复侧少一层产物、多一份"以为没恢复成"的误判。
# 130/143 是 128+SIGINT/SIGTERM 的惯例退出码，让 cron/CI 看得见是被信号打断的。
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# 凭据配置文件**不在这里创建**：只有 local 分支需要它（mongorestore 的 --config 只吃文件），
# 而 docker 分支——本脚本的默认传输——是经 stdin 把 `uri:` 行送进容器的。
# 修前这里无条件 umask 077 + mktemp + 写入含口令的 URI，docker 路径从头到尾没人读它，
# 却在宿主机磁盘上实打实留了一次凭据（DR 现场往往是笔记本/运维机）；
# 下方 docker 分支的注释还一直声称"含凭据的 URI 不落宿主机临时文件"，那句当时是失实的。
# 改成按需创建之后，那句注释才与代码一致。
# 这条不是自我表扬：src/tests/deploy/restoreTransport.test.js 的判据是"宿主机上有没有
# mongorestore-config.*"。把上面那段无条件写入原样贴回来，两条用例立刻变红（docker 那格
# 探到文件名、local 那格数出 2 个文件）——实测过，不是推演。

DROP_ARG=""
if [ "${RESTORE_DROP:-false}" = "true" ]; then
  echo "警告：已启用 --drop，目标库中同名集合将先被删除"
  DROP_ARG="--drop"
fi

# P1-①：加密归档先解密到 0600 临时文件（trap 清理），其余链路不变。
# 解密产物与归档同为 mongodump --gzip 形态，--gzip 参数两种来源通用。
DECRYPTED_FILE=""
case "$BACKUP_FILE" in
  *.gz.gpg)
    crypto_require_gpg || exit 1
    OLD_UMASK_DECRYPT=$(umask)
    umask 077
    DECRYPTED_FILE=$(mktemp "${TMPDIR:-/tmp}/mongorestore-decrypted.XXXXXX.gz")
    chmod 600 "$DECRYPTED_FILE"
    umask "$OLD_UMASK_DECRYPT"
    echo "检测到加密归档（$BACKUP_FILE），先解密到临时文件"
    if ! crypto_decrypt "$BACKUP_FILE" "$DECRYPTED_FILE"; then
      echo "Error: 解密失败（私钥缺失/口令错误/归档损坏）" >&2
      exit 1
    fi
    if [ ! -s "$DECRYPTED_FILE" ]; then
      echo "Error: 解密产物为 0 字节，归档可能已损坏" >&2
      exit 1
    fi
    BACKUP_FILE="$DECRYPTED_FILE"
    ;;
  *.gz) ;; # 明文旧归档：直接走既有链路
  *)
    echo "Error: 无法识别的归档后缀：$BACKUP_FILE（期望 .gz 或 .gz.gpg）" >&2
    exit 1
    ;;
esac

echo "Starting MongoDB restore from $BACKUP_FILE（transport=${MONGO_RESTORE_TRANSPORT}）"

# set -e 已保证失败即退出（退出码由 mongorestore / docker exec 传递给调用方），无需再判 $?
case "$MONGO_RESTORE_TRANSPORT" in
  local)
    # mongorestore 的 --config 只吃文件 ⇒ 凭据必须落一次盘。范围压到最小：
    # umask 077 + 显式 chmod 600（Windows/MSYS 下两者均为空操作，Linux 生效），
    # 收尾由顶部 trap 删除，含被信号打断的 130/143 两条路径。
    OLD_UMASK=$(umask)
    umask 077
    CONFIG_FILE=$(mktemp "${TMPDIR:-/tmp}/mongorestore-config.XXXXXX")
    printf 'uri: %s\n' "$MONGODB_URI" > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    umask "$OLD_UMASK"
    # 两条传输的 --drop 口径必须一致：docker 分支把参数拼在远端命令字符串里，
    # 与这里各写一遍，任一侧漏掉 ${DROP_ARG} 都会让"默认不删既有集合"的门禁
    # 只在一台机器上成立（用例见 src/tests/deploy/restoreTransport.test.js）。
    RESTORE_ARGS=(--config="$CONFIG_FILE" --archive="$BACKUP_FILE" --gzip)
    if [ -n "$DROP_ARG" ]; then
      RESTORE_ARGS+=("$DROP_ARG")
    fi
    mongorestore "${RESTORE_ARGS[@]}"
    ;;
  docker)
    # 主机段换成容器内地址：账号、口令、库名与查询串原样保留（判据与 backup 同一份）
    if ! CONTAINER_URI=$(mongo_swap_host "$MONGODB_URI" "$MONGO_CONTAINER_HOST"); then
      echo "Error: 无法把 URI 主机段改写为容器内地址（目标 ${MONGO_CONTAINER_HOST}），拒绝执行；上一行点名是哪条判据拦下的" >&2
      exit 1
    fi
    # 一条 stdin 流里先送一行配置、再送归档：容器内 `IFS= read -r` 只吃掉第一行（我们写的那行），
    # 余下字节原样进 --archive。含凭据的 URI 因此既不出现在 argv/ps，也不落宿主机临时文件。
    # 归档要经容器 /tmp 落地一份（mongorestore 的 --config 只吃文件，stdin 已被配置行占用），
    # 这是与 backup 同源的取舍：宁可多占一份容器磁盘，也不把口令写进命令行。
    REMOTE_CMD="umask 077; IFS= read -r _uri_line; printf '%s\n' \"\$_uri_line\" > /tmp/.mongorestore.cfg;
cat > /tmp/.mongorestore.archive;
mongorestore --config=/tmp/.mongorestore.cfg --archive=/tmp/.mongorestore.archive --gzip ${DROP_ARG};
rc=\$?; rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive; exit \$rc"
    {
      printf 'uri: %s\n' "$CONTAINER_URI"
      cat "$BACKUP_FILE"
    } | docker compose -f "${COMPOSE_FILE:-docker-compose.yml}" exec -T "$MONGO_COMPOSE_SERVICE" \
      sh -c "$REMOTE_CMD"
    ;;
esac

echo "Restore completed successfully"
