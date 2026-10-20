/**
 * 审计哈希链签名检查点（2026-10-20，审计 S-8 / P2-7）
 *
 * 哈希链能防「改/删」，但不能防「在已知锚点后插枝」：滑动窗口只要求 prevHash
 * 命中近期任一 hash，插入一条 prevHash 指向链中已有 hash 的伪造记录，链重算与
 * 链接检查都会放过（见 auditChainVerify.js「已知检出上限」）。另外，**尾部截断**
 * （删掉最新若干条）在纯链内校验里同样不可见——链仍自洽。
 *
 * 本模块把「某个时刻的链尾」固化成**带 HMAC 签名的检查点**，并同时记录该尾之前
 * 的记录总数。核验时逐条重算签名、比对头部 hash/hmac、比对计数：
 *   · 插入分支记录 ⇒ 计数变大 ⇒ count_mismatch；
 *   · 替换/改写头部 ⇒ hash 或 hmac 失配；
 *   · 把链截断到检查点之前（含把头部本身删掉）⇒ 当前链尾早于最后检查点 ⇒ tail_rolled_back；
 *   · 改检查点文件本身 ⇒ 没密钥签不出来 ⇒ signature_invalid。
 *
 * 能力边界（如实记录，不得读成「完整防篡改」）：
 *   · 检查点文件默认落在本机 logs/；**能同时改 Mongo 与该文件的人**可以重写两者。
 *     真正的外部锚定需要把文件（或每行 signature/tailDigest）周期性复制到
 *     WORM/对象存储/时间戳服务；本模块只负责产出可验证的锚点，不做传输。
 *   · 检查点之间的窗口内插入分支，只有落在下一次检查点计数差内的部分能被发现；
 *     检查点越频繁，可检出窗口越小。
 *   · 检查点**之后**新增又删掉的记录无法被这一条锚点发现（链尾仍等于锚点）。
 *     这是纯锚点方案的固有边界：需要更晚的检查点，或把每次检查点的计数差
 *     与外部日志留存比对，才能收窄。
 *   · 未配置 HMAC_SECRET 时**拒绝创建**（无密钥的检查点等于一张可随意重写的便条）。
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_CHECKPOINT_FILE = path.join(
  path.resolve(__dirname, '..', '..'),
  'logs',
  'audit-chain-checkpoints.jsonl'
);
const CHECKPOINT_VERSION = 1;

function hmacSecretOf(secret) {
  if (typeof secret === 'string' && secret.length > 0) return secret;
  try {
    return require('../config').hmacSecret || '';
  } catch {
    return process.env.HMAC_SECRET || '';
  }
}

/** 参与签名的字段与顺序只有这一份；改字段就是改锚点格式（version 必须一起升）。 */
const canonicalCheckpoint = (record) =>
  JSON.stringify([
    record.version,
    record.createdAt,
    record.headId,
    record.headHash,
    record.headHmac,
    record.recordCount,
  ]);

const signCheckpoint = (record, secret) =>
  crypto
    .createHmac('sha256', hmacSecretOf(secret))
    .update(canonicalCheckpoint(record), 'utf8')
    .digest('hex');

/**
 * 创建一个检查点并追加到 JSONL 文件。
 *
 * @param {object} [options]
 * @param {object} [options.model] AuditLog 模型（测试可注入假模型）
 * @param {string} [options.filePath] 检查点文件路径
 * @param {string} [options.secret] HMAC 密钥（默认 config.hmacSecret / env）
 * @param {Date} [options.now] 检查点时间（便于测试）
 * @returns {Promise<{record: object, filePath: string}>}
 */
async function createCheckpoint({ model, filePath, secret, now = new Date() } = {}) {
  const hmacSecret = hmacSecretOf(secret);
  if (!hmacSecret) {
    const err = new Error('未配置 HMAC_SECRET，拒绝创建无签名检查点');
    err.code = 'AUDIT_CHECKPOINT_HMAC_REQUIRED';
    throw err;
  }
  const AuditLog = model || require('../models/AuditLog');
  const out = filePath || DEFAULT_CHECKPOINT_FILE;

  const latest = await AuditLog.findOne({ hash: { $ne: null } }, { hash: 1, hmac: 1, _id: 1 })
    .sort({ _id: -1 })
    .lean();
  const headId = latest ? String(latest._id) : null;
  const recordCount = headId ? await AuditLog.countDocuments({ _id: { $lte: headId } }) : 0;

  const record = {
    version: CHECKPOINT_VERSION,
    createdAt: now.toISOString(),
    headId,
    headHash: latest ? latest.hash : null,
    headHmac: latest ? latest.hmac || null : null,
    recordCount,
  };
  record.signature = signCheckpoint(record, hmacSecret);

  fs.mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
  fs.appendFileSync(out, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return { record, filePath: out };
}

/** 读取并逐行解析检查点；坏行不跳过（跳过等于给篡改留静默位）。 */
function readCheckpoints(filePath = DEFAULT_CHECKPOINT_FILE) {
  if (!fs.existsSync(filePath)) return [];
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const out = [];
  lines.forEach((line, idx) => {
    if (!line.trim()) return;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (err) {
      const e = new Error(`检查点第 ${idx + 1} 行不是合法 JSON：${err.message}`);
      e.code = 'AUDIT_CHECKPOINT_MALFORMED';
      throw e;
    }
    out.push({ line: idx + 1, record: parsed });
  });
  return out;
}

const sameId = (a, b) => String(a) === String(b);

/** 签名与版本：任一不过则该条不再参与后续比对（`continue` 的语义）。 */
function checkSignature(record, hmacSecret, line, errors) {
  if (record.signature !== signCheckpoint(record, hmacSecret)) {
    errors.push({
      line,
      type: 'signature_invalid',
      message: '检查点签名不匹配（文件被改写或密钥已轮换）',
    });
    return false;
  }
  if (record.version !== CHECKPOINT_VERSION) {
    errors.push({
      line,
      type: 'version_unsupported',
      message: `不支持的检查点版本：${record.version}`,
    });
    return false;
  }
  return true;
}

/** 相邻检查点的时间/头部 _id 必须单调不回退。 */
function checkOrder(previous, record, line, errors) {
  if (!previous) return;
  if (new Date(record.createdAt).getTime() < new Date(previous.record.createdAt).getTime()) {
    errors.push({ line, type: 'order_violation', message: '检查点时间倒退' });
  }
  if (record.headId && previous.record.headId) {
    if (String(record.headId) < String(previous.record.headId)) {
      errors.push({
        line,
        type: 'order_violation',
        message: '检查点头部 _id 倒退（检查点被重排）',
      });
    }
  }
}

/** 头部记录的 hash/hmac 与「头部之前」的记录数都必须与锚点一致。 */
async function checkHead(AuditLog, record, line, errors) {
  if (!record.headId) return;
  const head = await AuditLog.findOne({ _id: record.headId }).lean();
  if (!head) {
    errors.push({ line, type: 'head_missing', message: `检查点头部记录不存在：${record.headId}` });
  } else {
    if (head.hash !== record.headHash) {
      errors.push({ line, type: 'head_hash_mismatch', message: '检查点头部 hash 与库中不一致' });
    }
    if ((head.hmac || null) !== record.headHmac) {
      errors.push({ line, type: 'head_hmac_mismatch', message: '检查点头部 hmac 与库中不一致' });
    }
  }
  const count = await AuditLog.countDocuments({ _id: { $lte: record.headId } });
  if (count !== record.recordCount) {
    errors.push({
      line,
      type: 'count_mismatch',
      message: `检查点计数 ${record.recordCount} 与库中 ${count} 不一致（检查点之前有插入或删除）`,
    });
  }
}

/** 尾部截断：删掉最后一次检查点之后的记录，链本身仍自洽，只有与锚点比较才看得见。 */
async function checkTail(AuditLog, last, errors) {
  if (!last || !last.headId) return;
  const tail = await AuditLog.findOne({ hash: { $ne: null } }, { _id: 1 })
    .sort({ _id: -1 })
    .lean();
  // 尾部一条不剩与「尾部倒退」是同一件事的两种现场：都不能因为 tail 为空就跳过。
  if (!tail) {
    errors.push({
      line: null,
      type: 'tail_rolled_back',
      message: `库中已无任何哈希记录，最后检查点 ${last.headId} 之后的内容被整体删除`,
    });
  } else if (sameId(tail._id, last.headId) === false && String(tail._id) < String(last.headId)) {
    errors.push({
      line: null,
      type: 'tail_rolled_back',
      message: `当前链尾 ${tail._id} 早于最后检查点 ${last.headId}（尾部记录可能被删除）`,
    });
  }
}

/**
 * 校验全部检查点。
 *
 * @returns {Promise<{ok: boolean, checked: number, errors: Array<{line:number|null,type:string,message:string}>}>}
 */
async function verifyCheckpoints({ model, filePath, secret } = {}) {
  const hmacSecret = hmacSecretOf(secret);
  const AuditLog = model || require('../models/AuditLog');
  const errors = [];
  const fail = (type, message) => ({
    ok: false,
    checked: 0,
    errors: [{ line: null, type, message }],
  });

  let entries;
  try {
    entries = readCheckpoints(filePath);
  } catch (err) {
    return fail('file_unreadable', err.message);
  }
  if (!hmacSecret) return fail('hmac_not_configured', '未配置 HMAC_SECRET，无法验证检查点签名');
  if (entries.length === 0) return fail('no_checkpoints', '没有检查点可验证');

  let previous = null;
  for (const { line, record } of entries) {
    if (!checkSignature(record, hmacSecret, line, errors)) continue;
    checkOrder(previous, record, line, errors);
    await checkHead(AuditLog, record, line, errors);
    previous = { line, record };
  }
  await checkTail(AuditLog, previous && previous.record, errors);

  return { ok: errors.length === 0, checked: entries.length, errors };
}

module.exports = {
  DEFAULT_CHECKPOINT_FILE,
  CHECKPOINT_VERSION,
  canonicalCheckpoint,
  signCheckpoint,
  createCheckpoint,
  readCheckpoints,
  verifyCheckpoints,
};
