/** 取证导出与签名校验（T5-2）：导出的意义是「离线也能证明这批记录当时确实存在且未被改」。签名把记录摘要与清单 chainHash 绑在一起，所以篡改要么改记录、要么改清单，两边都得动且都要连审计锚点一起改。用后即签的对称密钥（HMAC）只证明「导出方确实导出过这份」，不证明「库当时是诚实的」——后者只能靠审计链锚点。文档里不得把这两件事混为一谈。 */
const crypto = require('crypto');
const { canonicalJson } = require('./forensicCaptureCodec');

const EXPORT_VERSION = 1;
const ALG = 'HMAC-SHA256';
const MAX_RECORDS = 5000;

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/** 密钥来自环境变量：没配就拒绝导出，绝不产出「看起来签过」的未签名包 */
const secretOf = (env = process.env) => env.FORENSIC_EXPORT_SECRET || env.AUDIT_HMAC_SECRET || '';

const digestOf = (records) => sha256(canonicalJson(records));

/** 签名材料把清单锚点也算进去：只签记录的话，把清单删了再重签就自洽了 */
const materialOf = ({ version, exportedAt, count, digest, manifestRef }) =>
  [
    String(version),
    exportedAt,
    String(count),
    digest,
    manifestRef && manifestRef.chainHash ? String(manifestRef.chainHash) : '-',
  ].join('|');

function buildExport({
  records,
  manifestRef = null,
  secret = secretOf(),
  operator = 'system',
  now = new Date(),
} = {}) {
  if (!secret) return { ok: false, reason: 'no_secret' };
  if (!Array.isArray(records)) return { ok: false, reason: 'bad_records' };
  if (records.length > MAX_RECORDS)
    return { ok: false, reason: 'too_many_records', max: MAX_RECORDS };
  const exportedAt = now.toISOString();
  const count = records.length;
  const digest = digestOf(records);
  const material = materialOf({ version: EXPORT_VERSION, exportedAt, count, digest, manifestRef });
  const signature = crypto.createHmac('sha256', secret).update(material, 'utf8').digest('hex');
  const keyId = sha256(secret).slice(0, 16);
  return {
    ok: true,
    pkg: {
      v: EXPORT_VERSION,
      alg: ALG,
      keyId,
      exportedAt,
      operator,
      count,
      digest,
      manifestRef,
      signature,
      records,
    },
  };
}

/** 校验：先看密钥指纹对不对，再逐字重算签名。任何一步不确定都返回 ok:false 并点名原因 */
function verifyExport({ pkg, secret = secretOf() } = {}) {
  if (!secret) return { ok: false, reason: 'no_secret' };
  if (!pkg || typeof pkg !== 'object') return { ok: false, reason: 'bad_pkg' };
  if (pkg.alg !== ALG || pkg.v !== EXPORT_VERSION)
    return { ok: false, reason: 'unsupported_alg_or_version' };
  const keyId = sha256(secret).slice(0, 16);
  if (pkg.keyId !== keyId) return { ok: false, reason: 'key_mismatch' };
  const digest = digestOf(pkg.records);
  if (digest !== pkg.digest) return { ok: false, reason: 'records_modified' };
  const material = materialOf({
    version: pkg.v,
    exportedAt: pkg.exportedAt,
    count: pkg.count,
    digest,
    manifestRef: pkg.manifestRef,
  });
  const expect = crypto.createHmac('sha256', secret).update(material, 'utf8').digest('hex');
  const a = Buffer.from(expect, 'utf8');
  const b = Buffer.from(String(pkg.signature || ''), 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'signature_mismatch' };
  }
  return { ok: true, count: pkg.count, digest };
}

module.exports = {
  EXPORT_VERSION,
  ALG,
  MAX_RECORDS,
  secretOf,
  materialOf,
  buildExport,
  verifyExport,
};
