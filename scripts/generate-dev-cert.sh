#!/usr/bin/env bash
# 生成开发/内网自测用的自签名 TLS 证书（仅用于本地 HTTPS 验证，勿用于生产）
# 生产环境必须使用受信任 CA 签发的证书。
#
# 用法： bash scripts/generate-dev-cert.sh
# 生成的证书位于 ./certs/server.crt 与 ./certs/server.key
#
# 后端启用：在 .env 中设置 ENABLE_HTTPS=true 与证书路径
# 前端启用： HTTPS=true TLS_CERT_PATH=../certs/server.crt TLS_KEY_PATH=../certs/server.key npm run dev

set -euo pipefail

# P3-47：私钥权限不能只依赖调用者的 umask。
# openssl 以默认 0644 创建 -keyout 文件，若 umask 为常见的 022，
# 同机任意用户都能读取该私钥。开发证书虽不用于生产，但开发机上
# 往往同时存在其他账号/CI runner，且这份 key 常被复制去内网联调。
# 双重保障：① 先收紧 umask，让文件从创建那一刻就是 600；
#           ② 生成后再显式 chmod，覆盖 umask 被外部覆写的情况。
umask 077

OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

CERT="$OUT_DIR/server.crt"
KEY="$OUT_DIR/server.key"

if ! command -v openssl >/dev/null 2>&1; then
  echo "错误：未检测到 openssl，请先安装 OpenSSL。" >&2
  exit 1
fi

# 已存在时不静默覆盖：正在被服务加载的证书被换掉会导致 TLS 握手失败，
# 且旧私钥一旦覆盖无法找回（若它已被签发进某个信任库）
if [ -e "$KEY" ] || [ -e "$CERT" ]; then
  echo "错误：证书已存在，拒绝覆盖：" >&2
  [ -e "$CERT" ] && echo "  $CERT" >&2
  [ -e "$KEY" ] && echo "  $KEY" >&2
  echo "如需重新生成，请先手动删除上述文件。" >&2
  exit 1
fi

# 失败清理：openssl 先写 -keyout 再校验其余参数，中途失败会留下一个残缺私钥，
# 而上面的"已存在即拒绝"门禁会让下次运行直接报错 —— 必须自己清干净。
# 同时清理临时 openssl 配置。
CONF=""
cleanup_on_failure() {
  status=$?
  [ -n "$CONF" ] && rm -f "$CONF"
  if [ "$status" -ne 0 ]; then
    rm -f "$KEY" "$CERT"
    echo "生成失败（exit=$status），已清理不完整的证书文件。" >&2
  fi
}
trap cleanup_on_failure EXIT

# 用配置文件而非 -subj / -addext 表达主体与 SAN，原因有两个：
#  1) Git Bash / MSYS 会把以 / 开头的参数当路径转换，把 "/CN=localhost" 改写成
#     "C:/Program Files/Git/CN=localhost"，openssl 随即报
#     "subject name is expected to be in the format /type0=value0"。
#     用 MSYS_NO_PATHCONV=1 关掉转换会连 -keyout 的路径一起失效（openssl 是原生
#     Windows 程序，读不懂 /d/... 形式），所以只能从参数形式上规避。
#  2) -addext 需要 openssl ≥ 1.1.1，配置文件方式对更老的版本同样可用。
# 模板的 X 必须位于末尾：GNU mktemp 不接受 "xxx.XXXXXX.cnf" 形式的中缀模板。
CONF="$(mktemp "${TMPDIR:-/tmp}/xf-devcert-XXXXXX")"
cat > "$CONF" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = localhost

[v3_req]
subjectAltName = DNS:localhost, IP:127.0.0.1
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" \
  -out "$CERT" \
  -days 365 \
  -config "$CONF"

rm -f "$CONF"
CONF=""

# 私钥仅所有者可读写；证书是公开材料，可保持可读
chmod 600 "$KEY"
chmod 644 "$CERT"

echo "自签名证书已生成："
echo "  $CERT (644)"
echo "  $KEY (600)"
echo ""
echo "浏览器会因自签名证书报警，可临时信任或忽略；仅用于本地测试。"
echo "注意：Windows/NTFS 下 chmod 不承载 POSIX 权限位，上述权限仅在 Linux/macOS 生效。"
