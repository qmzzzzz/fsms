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

// v3 = v2 字段集（只补了「算哈希前统一填默认值」的口径）。必须独立快照：同一引用时给 v2 加字段会静默改写 v3 语义，历史哈希再也算不回来。
const PAYLOAD_FIELDS_V3 = [...PAYLOAD_FIELDS_V2];

// v4：补进四字段（谁举报了谁 / 哪类敏感数据 / 操作描述）——取证要看的值，不进 payload 就能落库后被静默改写而三层校验全绿。
const PAYLOAD_FIELDS_V4 = [
  ...PAYLOAD_FIELDS_V3,
  'targetType',
  'targetId',
  'dataType',
  'description',
];

// v5：补进 refusalReason（4xx 拒绝原因码）——归因证据，与 riskLevel 同族。**只能在 V5 加**：往 V4 追加会让存量 v4 记录按新口径复算 ⇒ 集体 hash_mismatch（假篡改告警）。
const PAYLOAD_FIELDS_V5 = [...PAYLOAD_FIELDS_V4, 'refusalReason'];

const CURRENT_PAYLOAD_VERSION = 5;

// 历史清单一律冻结：清单被改动 ⇒ 历史哈希算不回来 ⇒ 大面积假篡改告警（本文件 v3 那行记的事故）。冻结是可执行判据，注释与 review 防不住第三次。
Object.freeze(PAYLOAD_FIELDS_V1);
Object.freeze(PAYLOAD_FIELDS_V2);
Object.freeze(PAYLOAD_FIELDS_V3);
Object.freeze(PAYLOAD_FIELDS_V4);
Object.freeze(PAYLOAD_FIELDS_V5);

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

const canonicalPayloadV2 = (doc, fields = PAYLOAD_FIELDS_V2) => {
  const defaultEmptyObjectFields = new Set(['params', 'query', 'body']);
  const payload = {};
  for (const field of fields) {
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

// 按记录自带 hashVersion 选口径；每新增一版都必须保留旧分支——历史哈希只有按当年口径才复算得出来。
const canonicalPayload = (doc, version = CURRENT_PAYLOAD_VERSION) => {
  if (version >= 5) return canonicalPayloadV2(doc, PAYLOAD_FIELDS_V5);
  if (version >= 4) return canonicalPayloadV2(doc, PAYLOAD_FIELDS_V4);
  // v3 必须读 V3 那份快照。此前这一行读的是 PAYLOAD_FIELDS_V2，于是上面"必须是独立快照"
  // 的承诺实际未生效：给 V2 追加字段会连同 v3 的口径一起改掉，全部 v3 历史记录
  // 瞬时变 hash_mismatch（大面积假篡改告警）——正是那条注释声称要防的事故。
  // 今日 V3 与 V2 内容相等（由 auditFieldSetsImmutable 钉住），所以本行
  // 不改变任何既有哈希；改的是"将来加字段时谁受影响"。
  if (version >= 2)
    return canonicalPayloadV2(doc, version >= 3 ? PAYLOAD_FIELDS_V3 : PAYLOAD_FIELDS_V2);
  return canonicalPayloadV1(doc);
};

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
  PAYLOAD_FIELDS_V4,
  PAYLOAD_FIELDS_V5,
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  canonicalPayloadV2,
  canonicalPayloadV2LegacyBatch,
  computeHash,
};
