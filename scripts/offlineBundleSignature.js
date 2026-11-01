/**
 * 离线包签名（Ed25519，node:crypto 内置，零新依赖）
 *
 * 解决的问题：离线包离开构建机后（U 盘/跳板机/内网拷贝），manifest.json 与 payload 可以被
 * **整体重写**——manifest 自带的 sha256 只能证明「payload 与 manifest 同源」，证明不了
 * 「manifest 出自构建机」。签名把信任锚从「搬运通道可信」挪到「构建机私钥」：目标机只钉一把
 * 公钥，manifest 原始字节与 manifest.sig 对不上（或根本没有 sig）即整包拒绝。
 *
 * 覆盖关系：签名覆盖 manifest.json 的**原始字节**（刻意不做 JSON canonical——键序、空白、
 * 行尾任何一个字节动了就该验签失败，而 canonical 化反而会把「字节被改过」洗白成「语义相同」）；
 * payload 的完整性由 manifest 内的 sha256 逐字节比对承接（scripts/importOfflineBundle.js 的
 * 既有判据），于是 信任根(公钥) → manifest 字节 → payload 摘要 传递覆盖整包。
 *
 * 分工：签在构建机（build-offline-bundle.sh 调 openssl pkeyutl -sign -rawin，构建机只保证
 * bash+docker+sha256sum，openssl 是既有系统组件）；验在目标机（本模块，node:crypto）。
 * 两侧都是标准 Ed25519：私钥由 `openssl genpkey -algorithm ed25519` 生成，公钥
 * `openssl pkey -pubout` 导出，互操作由测试（签用 node、验用 node）与 openssl 的规范实现保证。
 *
 * 边界（ADR-019）：
 *   · 只加「验签」，仍不做解包——导入器只接受已解压目录的原决策不变（自实现安全解包等于
 *     在升级链路上再开一条路径穿越面，签名不改变这笔取舍）；
 *   · 目标机公钥未配置时按「未启用验签」放行、留痕明示 signature: 'unchecked'——是否
 *     fail-closed 由部署显式选择（配了公钥 = 必须验签），运行时不替没分发过密钥的环境兜底；
 *   · 本模块零副作用：不读 process.env、不打印、不退出；文件 IO 留在调用方
 *     （scripts/importOfflineBundle.js），判据与 IO 分层才能在毫秒级被逐条断言。
 */

'use strict';

const crypto = require('crypto');

/** 签名文件名（包根目录下，与 manifest.json 并列） */
const SIG_FILE = 'manifest.sig';

/** Ed25519 签名恒为 64 字节；上限只为把「sig 路径被指到 GB 级文件」挡在读取之前 */
const MAX_SIG_BYTES = 4096;

/** 密钥类型收紧： RSA/EC 的钥匙塞进来必须报错，而不是按通用 verify 悄悄工作 */
function assertEd25519(key, what) {
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(
      `${what}不是 Ed25519 密钥（收到：${key.asymmetricKeyType}）。` +
        '本链路只认 Ed25519：私钥用 `openssl genpkey -algorithm ed25519` 生成。'
    );
  }
  return key;
}

/** 公钥解析 + 类型校验；PEM 坏、类型不符都抛可读错误（调用方决定是中止还是按未验签放行） */
function parsePublicKey(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || publicKeyPem.trim() === '') {
    throw new Error('验签公钥为空：OFFLINE_BUNDLE_VERIFY_PUBKEY / --pubkey-file 指向的文件读不出 PEM');
  }
  let key;
  try {
    key = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new Error(`验签公钥无法解析（${err.message}）`);
  }
  return assertEd25519(key, '验签公钥');
}

/** 对 manifest 原始字节签名（测试与文档用；生产打包走 build-offline-bundle.sh 的 openssl） */
function signManifestBytes(manifestBytes, privateKeyPem) {
  if (!Buffer.isBuffer(manifestBytes) || manifestBytes.length === 0) {
    throw new Error('manifest 字节为空，无从签名');
  }
  let key;
  try {
    key = crypto.createPrivateKey(privateKeyPem);
  } catch (err) {
    throw new Error(`签名私钥无法解析（${err.message}）`);
  }
  assertEd25519(key, '签名私钥');
  return crypto.sign(null, manifestBytes, key);
}

/**
 * 验签。返回 { ok } 而不是抛错：调用方要把「为什么拒」原样写进留痕与 stdout，
 * 且「验签未启用」与「验签失败」在这条链上是两种不同的处境。
 */
function verifyManifestBytes(manifestBytes, sigBytes, publicKeyPem) {
  if (!Buffer.isBuffer(manifestBytes) || manifestBytes.length === 0) {
    return { ok: false, reason: 'manifest.json 为空，无从验签' };
  }
  if (!Buffer.isBuffer(sigBytes) || sigBytes.length === 0) {
    return {
      ok: false,
      reason: 'manifest.sig 不存在或为空（包未签名，或签名文件在搬运中丢失）',
    };
  }
  if (sigBytes.length > MAX_SIG_BYTES) {
    return {
      ok: false,
      reason: `manifest.sig 有 ${sigBytes.length} 字节，超过 Ed25519 签名的形状上限（${MAX_SIG_BYTES}）`,
    };
  }
  let publicKey;
  try {
    publicKey = parsePublicKey(publicKeyPem);
  } catch (err) {
    return { ok: false, reason: err.message };
  }
  let ok;
  try {
    ok = crypto.verify(null, manifestBytes, publicKey, sigBytes);
  } catch (err) {
    return { ok: false, reason: `验签计算失败（${err.message}）` };
  }
  if (!ok) {
    return {
      ok: false,
      reason:
        '签名与 manifest.json 字节不符：包在搬运中被篡改，或目标机公钥与构建机签名私钥不是同一对',
    };
  }
  return { ok: true };
}

module.exports = {
  SIG_FILE,
  MAX_SIG_BYTES,
  parsePublicKey,
  signManifestBytes,
  verifyManifestBytes,
};
