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

/**
 * v3 = v2 的字段集（当时只是补了「算哈希前统一填默认值」的口径，字段没变）。
 * 必须是**独立快照**而不是 `= PAYLOAD_FIELDS_V2`：同一引用的话，将来给 v2
 * 追加任何字段都会静默改写 v3 的语义，历史记录的哈希就再也算不回来了。
 */
const PAYLOAD_FIELDS_V3 = [...PAYLOAD_FIELDS_V2];

/**
 * v4：补进 P1-12 加到 schema 却从未进哈希的四个字段
 * （targetType / targetId / dataType / description）。
 * 这四字段承载「谁举报了谁 / 看了哪类敏感数据 / 操作描述」，正是取证要看的值；
 * 不在 payload 里就意味着落库后可被任意改写而三层校验一层都不会红。
 */
const PAYLOAD_FIELDS_V4 = [
  ...PAYLOAD_FIELDS_V3,
  'targetType',
  'targetId',
  'dataType',
  'description',
];

const CURRENT_PAYLOAD_VERSION = 4;

/**
 * 四份历史清单一律冻结。
 *
 * 理由不是洁癖：本文件第 48-51 行记着的事故（v3 曾写成 `= PAYLOAD_FIELDS_V2`
 * 同一个引用）就是"清单被别处改动 ⇒ 历史哈希再也算不回来"这一类，
 * 而它的后果是**大面积假篡改告警**——防篡改链最坏的失败形态
 * （把完好的链路报成被篡改，运维只能整库重签）。
 * 靠注释与 code review 防不住第三次，冻结能防住：数组内容从此不可能被 push/splice 改掉。
 */
Object.freeze(PAYLOAD_FIELDS_V1);
Object.freeze(PAYLOAD_FIELDS_V2);
Object.freeze(PAYLOAD_FIELDS_V3);
Object.freeze(PAYLOAD_FIELDS_V4);

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

/**
 * 按记录自带的 hashVersion 选择口径。v2/v3 共用 25 字段集（v3 只是补齐默认值
 * 的写入口径，字段集未变），v4 起加入 targetType/targetId/dataType/description。
 * 每新增一版都必须保留旧分支——历史记录的哈希只有按当年口径才复算得出来。
 */
const canonicalPayload = (doc, version = CURRENT_PAYLOAD_VERSION) => {
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
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  canonicalPayloadV2,
  canonicalPayloadV2LegacyBatch,
  computeHash,
};
