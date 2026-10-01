#!/bin/bash
# 备份加密/解密/校验和的唯一实现（backup-mongo.sh 与 restore-mongo.sh 共用）
#
# 【P1-① 备份未加密】（deliverables/安全缺口核查-2026-09-30.md）
# 备份归档是全量业务库（含人员 PII 与审计集合），明文躺在 backups/ 里等于
# "拿到文件 = 拿到整个系统的人员名录与操作史"。本模块把加密做成**默认路径**：
#   - BACKUP_ENCRYPTION=gpg（默认）：非对称加密，备份宿主机只需要导入**公钥**
#     （BACKUP_GPG_RECIPIENT），私钥托管在另一台机器/密钥保险库——
#     "密钥不进同一台机"由部署形态保证，而不是靠自觉。
#   - BACKUP_ENCRYPTION=plaintext-acknowledged：唯一的明文出口，取值本身就是
#     一句确认词；脚本仍会打 error 级警告，明文备份在审计上是有意识的例外。
# 校验和（sha256）对两种模式都生成：异地副本与恢复演练都要先验完整性。
#
# 为什么抽成共享模块（同 mongoUri.sh 的先例）：加密形态、后缀约定（.gz.gpg）、
# 校验和位置这三件事一旦两侧各写一遍，备份侧改了恢复侧不知道——恢复演练
# 在真正要用的那天才发现跑不通，是最贵的发现时机。

# 确认 gpg 可用（调用方在产出任何文件之前调用，缺工具直接失败而非明文兜底）
crypto_require_gpg() {
  if ! command -v gpg >/dev/null 2>&1; then
    echo "Error: gpg 不在 PATH 中（BACKUP_ENCRYPTION=gpg 需要它）。" >&2
    echo "       安装 gpg 并导入备份公钥；或显式 BACKUP_ENCRYPTION=plaintext-acknowledged（不建议）。" >&2
    return 1
  fi
}

# 加密：<src> → <dest>.gpg 语义由调用方给全路径；本函数只负责调用形态一致
# 非交互（--batch --yes）：备份跑在 cron / deploy 流程里，任何 pinentry 弹窗
# 都会让备份挂死，而加密侧只需要公钥、本就不该有交互。
crypto_encrypt() {
  _crypto_src=$1
  _crypto_dest=$2
  if [ -z "${BACKUP_GPG_RECIPIENT:-}" ]; then
    echo "Error: BACKUP_GPG_RECIPIENT 未设置（gpg 加密需要收件人公钥指纹/邮箱）。" >&2
    return 1
  fi
  gpg --batch --yes --trust-model always \
    --output "$_crypto_dest" --encrypt --recipient "$BACKUP_GPG_RECIPIENT" "$_crypto_src"
}

# 解密：<src> → <dest>（恢复侧；私钥所在机器由 gpg-agent 处理口令交互）
crypto_decrypt() {
  _crypto_src=$1
  _crypto_dest=$2
  gpg --batch --yes --output "$_crypto_dest" --decrypt "$_crypto_src"
}

# 校验和：<file> → <file>.sha256
# 权限**继承调用方此刻仍生效的 umask**，本函数自己不动 umask：调用方（backup-mongo.sh）
# 的 `umask 077` 一直收到 cleanup trap 才还原，所以归档、密文、校验和三者都在 0600 下产出。
# 这句话此前是错的（调用方在写完凭据文件后就还原了 umask，产物落成 0644）——
# 现在由 src/tests/deploy/backupEncryptionContract.test.js 的位置闸把守。
crypto_checksum() {
  _crypto_file=$1
  sha256sum "$_crypto_file" > "$_crypto_file.sha256"
}
