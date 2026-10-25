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
 *     ⇒ 传输由 `auditAnchorSink` 负责，核验侧的「双向比对」由本模块的
 *     `compareAnchors` 负责（2026-10-24 补）。两者缺一，上面的攻击路径（改链 →
 *     删检查点文件 → 重新 create）就仍然成立且**不需要 HMAC_SECRET**。
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
 * 本地检查点集合与**外部锚点副本**的双向比对（2026-10-24，P1 外锚）。
 *
 * 为什么必须有这一项：上面所有检查都只看「本地文件 + 当前库」这一对，而这两者
 * 同属一个主权边界。攻击者改完链、删掉检查点文件、再跑一次 `create`，就能为被
 * 篡改后的链尾重新签出一个**完全自洽**的检查点集合——`signature_invalid` /
 * `count_mismatch` / `tail_rolled_back` 一个都不会触发，因为文件里已经没有旧锚点
 * 了。这条路径**不需要 HMAC_SECRET**（签名由服务自己算）。
 *
 * 只有把旧锚点留在受保护数据之外，才能看见「本地少了什么」：
 *   · 外部有、本地无 ⇒ anchor_missing_local：文件被删除 / 截断 / 整体重写。
 *   · 外部签名验不过 ⇒ anchor_signature_invalid：外部副本本身被动过，不能当锚点，
 *     也不能因为「验不过所以跳过」就静默放过（跳过等于给篡改留静默位）。
 *   · 本地有、外部无 ⇒ 只记 `pending`，**不判错**：正常情况就是「刚 create、还没
 *     ship」。判红会让每个尚未配置 ship 的部署常红，从而把这条告警训练成噪音。
 *   · 外部为空 ⇒ no_external_anchors：空存储证明不了任何事，不能读成「无失配」。
 *
 * 比对用 `signature` 作为锚点身份（它覆盖 version/createdAt/headId/headHash/
 * headHmac/recordCount 全部字段），因此不依赖外部存储的行序或索引——外部存储被
 * 重排、被并行 ship 追加出重复行，都不影响判定。
 *
 * @param {{localEntries: Array<{line:number, record:object}>, externalAnchors: object[], secret?: string}} input
 * @returns {{errors: Array<{line:number|null, type:string, message:string}>, pending: object[], externalValid: object[]}}
 */
function compareAnchors({ localEntries = [], externalAnchors = [], secret } = {}) {
  const hmacSecret = hmacSecretOf(secret);
  const errors = [];
  const pending = [];
  const externalValid = [];

  if (!Array.isArray(externalAnchors) || externalAnchors.length === 0) {
    return {
      errors: [
        {
          line: null,
          type: 'no_external_anchors',
          message: '锚点存储为空：外锚比对无从进行（空存储不能当作「无失配」）',
        },
      ],
      pending,
      externalValid,
    };
  }

  // 本地先自筛一遍：验不过的本地行已由 checkSignature 报 signature_invalid，
  // 这里不再重复计一次，否则同一处篡改会出现两条错误。
  const localSignatures = new Set();
  const localBadLines = new Set();
  for (const { line, record } of localEntries) {
    if (
      record &&
      record.signature === signCheckpoint(record, hmacSecret) &&
      record.version === CHECKPOINT_VERSION
    ) {
      localSignatures.add(record.signature);
    } else {
      localBadLines.add(line);
    }
  }

  const externalSignatures = new Set();
  externalAnchors.forEach((record, idx) => {
    const position = idx + 1;
    if (!record || typeof record !== 'object' || typeof record.signature !== 'string') {
      errors.push({
        line: null,
        type: 'anchor_signature_invalid',
        message: `外部锚点第 ${position} 条不是可识别的检查点记录`,
      });
      return;
    }
    if (record.signature !== signCheckpoint(record, hmacSecret)) {
      errors.push({
        line: null,
        type: 'anchor_signature_invalid',
        message: `外部锚点第 ${position} 条签名不匹配（外部副本被改写，或 HMAC_SECRET 已轮换）`,
      });
      return;
    }
    if (record.version !== CHECKPOINT_VERSION) {
      errors.push({
        line: null,
        type: 'anchor_version_unsupported',
        message: `外部锚点第 ${position} 条版本不支持：${record.version}`,
      });
      return;
    }
    externalValid.push(record);
    externalSignatures.add(record.signature);
    if (!localSignatures.has(record.signature)) {
      errors.push({
        line: null,
        type: 'anchor_missing_local',
        message:
          `外部锚点 ${record.headId || '(空链)'}（${record.createdAt}，计数 ${record.recordCount}）` +
          '在本地检查点文件中缺失 —— 本地检查点被删除、截断或重写（重新锚定）',
      });
    }
  });

  for (const { line, record } of localEntries) {
    if (localBadLines.has(line)) continue;
    if (!externalSignatures.has(record.signature)) {
      pending.push({ line, headId: record.headId, createdAt: record.createdAt });
    }
  }

  return { errors, pending, externalValid };
}

/**
 * 校验全部检查点。
 *
 * `externalAnchors` 为 `undefined` 时不比对（向后兼容，输出形状与旧版逐字一致）；
 * 传入数组（含空数组）才比对——空数组会被判 `no_external_anchors` 而非通过。
 *
 * @returns {Promise<{ok: boolean, checked: number, errors: Array<{line:number|null,type:string,message:string}>,
 *   anchors?: {compared:number, pending:number, externalValid:number}}>}
 */
async function verifyCheckpoints({ model, filePath, secret, externalAnchors } = {}) {
  const hmacSecret = hmacSecretOf(secret);
  const AuditLog = model || require('../models/AuditLog');
  const errors = [];
  const anchorsCompared = Array.isArray(externalAnchors);
  let anchorResult = null;

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

  if (anchorsCompared) {
    anchorResult = compareAnchors({ localEntries: entries, externalAnchors, secret: hmacSecret });
    errors.push(...anchorResult.errors);
  }

  // 本地一条都没有：可能是从没建过检查点，也可能是被删了。
  // 有外部锚点为证时 compareAnchors 已经逐条报了 anchor_missing_local（每条外部锚点
  // 都「本地缺失」），这里不再补一条重复的摘要；只有「一条有效外部锚点都没有」时才
  // 补 no_checkpoints，免得两种完全不同的现场被折叠成同一句。
  if (entries.length === 0) {
    if (!anchorResult || anchorResult.externalValid.length === 0) {
      errors.push({ line: null, type: 'no_checkpoints', message: '没有检查点可验证' });
    }
    return assemble(errors, 0);
  }

  let previous = null;
  for (const { line, record } of entries) {
    if (!checkSignature(record, hmacSecret, line, errors)) continue;
    checkOrder(previous, record, line, errors);
    await checkHead(AuditLog, record, line, errors);
    previous = { line, record };
  }
  await checkTail(AuditLog, previous && previous.record, errors);

  return assemble(errors, entries.length);

  function assemble(collected, checked) {
    const out = { ok: collected.length === 0, checked, errors: collected };
    // 只在真的比对过时才带 anchors 键：旧调用方与旧断言按「无此键」比较，
    // 无条件加一个 null 会破坏 `toEqual({ok, checked, errors})` 的既有契约。
    if (anchorResult) {
      out.anchors = {
        compared: externalAnchors.length,
        pending: anchorResult.pending.length,
        externalValid: anchorResult.externalValid.length,
      };
    }
    return out;
  }
}

module.exports = {
  DEFAULT_CHECKPOINT_FILE,
  CHECKPOINT_VERSION,
  canonicalCheckpoint,
  hmacSecretOf,
  signCheckpoint,
  createCheckpoint,
  readCheckpoints,
  compareAnchors,
  verifyCheckpoints,
};
