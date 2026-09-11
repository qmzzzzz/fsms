/**
 * 审计链 payload 版本化：固定字段白名单、确定性序列化与历史口径兼容。
 */

const crypto = require('crypto');

const PAYLOAD_FIELDS_V1 = [
  'timestamp',
  'action',
  'category',
  'userId',
  'username',
  'ip',
  'path',
  'statusCode',
  'body',
];

const PAYLOAD_FIELDS_V2 = [
  'timestamp',
  'action',
  'category',
  'userId',
  'username',
  'targetUserId',
  'targetUsername',
  'reason',
  'method',
  'path',
  'params',
  'query',
  'body',
  'statusCode',
  'success',
  'errorMessage',
  'ip',
  'userAgent',
  'clientInfo',
  'location',
  'riskLevel',
  'riskFactors',
  'sessionId',
  'fingerprint',
  'duration',
];

const PAYLOAD_FIELDS_V3 = PAYLOAD_FIELDS_V2;
const CURRENT_PAYLOAD_VERSION = 3;

const stableStringify = (value) => {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
};

const normalizeValue = (value) => {
  if (value === undefined || value === null) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'object') {
    if (typeof value.toHexString === 'function') return value.toHexString();
    return value;
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  return String(value);
};

const canonicalPayloadV1 = (doc) => {
  const timestamp = doc.timestamp;
  let timestampIso;
  if (timestamp instanceof Date) {
    timestampIso = timestamp.toISOString();
  } else if (timestamp !== null && timestamp !== undefined && timestamp !== '') {
    timestampIso = new Date(timestamp).toISOString();
  } else {
    timestampIso = null;
  }

  return JSON.stringify({
    timestamp: timestampIso,
    action: doc.action != null ? String(doc.action) : null,
    category: doc.category != null ? String(doc.category) : null,
    userId: doc.userId != null ? String(doc.userId) : null,
    username: doc.username != null ? String(doc.username) : null,
    ip: doc.ip != null ? String(doc.ip) : null,
    path: doc.path != null ? String(doc.path) : null,
    statusCode: doc.statusCode != null ? Number(doc.statusCode) : null,
    body: doc.body === undefined ? {} : doc.body,
  });
};

const canonicalPayloadV2 = (doc) => {
  const defaultEmptyObjectFields = new Set(['params', 'query', 'body']);
  const payload = {};
  for (const field of PAYLOAD_FIELDS_V2) {
    payload[field] =
      doc[field] === undefined && defaultEmptyObjectFields.has(field)
        ? {}
        : normalizeValue(doc[field]);
  }
  return stableStringify(payload);
};

const canonicalPayloadV2LegacyBatch = (doc) => {
  const probe = { ...doc };
  delete probe.riskLevel;
  delete probe.riskFactors;
  return canonicalPayloadV2(probe);
};

const canonicalPayload = (doc, version = CURRENT_PAYLOAD_VERSION) =>
  version >= 2 ? canonicalPayloadV2(doc) : canonicalPayloadV1(doc);

const computeHash = (prevHash, payload) => {
  const previous = prevHash === undefined ? null : prevHash;
  return crypto
    .createHash('sha256')
    .update(String(previous) + '|' + payload, 'utf8')
    .digest('hex');
};

module.exports = {
  PAYLOAD_FIELDS_V1,
  PAYLOAD_FIELDS_V2,
  PAYLOAD_FIELDS_V3,
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
  computeHash,
};
