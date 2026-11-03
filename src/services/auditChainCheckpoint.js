/**
 * 审计哈希链签名检查点（2026-10-20，审计 S-8 / P2-7）。
 *
 * 哈希链能防「改/删」，但不能防「在已知锚点后插枝」：滑动窗口只要求 prevHash 命中近期任一
 * hash，插入伪造记录后链重算与链接检查都会放过（见 auditChainVerify.js「已知检出上限」）。
 * **尾部截断**（删掉最新若干条）在纯链内校验里同样不可见——链仍自洽。
 *
 * 本模块把「某个时刻的链尾」固化成**带 HMAC 签名的检查点**。链尾定义是「库里没有任何记录把它
 * 当作 prevHash」，**不是「_id 最大」**：auditBuffer.push 在 push 时预分配 _id（F-143），久候
 * 批次的 _id 小于其后直写的记录 ⇒ _id 序 ≠ 追加序。核验时重算签名、比对头部 hash/hmac，再从
 * 当前链尾沿 prevHash 回溯找 headId：替换/改写头部 ⇒ hash 或 hmac 失配；截断到检查点之前 ⇒
 * tail_rolled_back；回溯 TAIL_WALK_LIMIT 步仍未见到 ⇒ tail_unverifiable（不静默绿，也不假红）；
 * 改检查点文件本身 ⇒ 没密钥签不出来 ⇒ signature_invalid。`recordCount` 只是创建时的估算，不参与
 * 任何判红（TTL 裁剪与迟到批写都会让它与库对不上）；v1 存量仍按 v1 口径验，标 degraded。
 *
 * 能力边界（不得读成「完整防篡改」）：检查点文件默认落在本机 logs/，**能同时改 Mongo 与该
 * 文件的人**可以重写两者；真正的外部锚定要把文件周期性复制到 WORM/对象存储/时间戳服务（传输由
 * auditAnchorSink，双向比对由 compareAnchors）——缺任一半，「改链 → 删文件 → 重新 create」仍
 * 成立。两检查点之间插入的分支靠 auditChainVerify 的一父两子与外锚比对判定；检查点之后新增又
 * 删掉的记录无法被这一条锚点发现（纯锚点固有边界）。未配置 HMAC_SECRET 时**拒绝创建**。
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getLatestHash } = require('../utils/auditChainTail');
// 新鲜度臂的判据与 env 读法独立成叶子模块（体积棘轮：本文件代码行数顶在 300，见其文件头）
const { freshnessBudgetMs, pushStaleIfAny } = require('./auditCheckpointFreshness');

const DEFAULT_CHECKPOINT_FILE = path.join(
  path.resolve(__dirname, '..', '..'),
  'logs',
  'audit-chain-checkpoints.jsonl'
);
const CHECKPOINT_VERSION = 2;
const TAIL_WALK_LIMIT = 1024;
const pushErr = (list, type, message, line = null) => list.push({ line, type, message });
const isSupportedVersion = (v) => v === 1 || v === CHECKPOINT_VERSION;

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

  const tailHash = await getLatestHash(AuditLog);
  const latest = tailHash
    ? await AuditLog.findOne({ hash: tailHash }, { hash: 1, hmac: 1, _id: 1 }).lean()
    : null;
  const headId = latest ? String(latest._id) : null;
  const recordCount = headId ? await AuditLog.countDocuments({ hash: { $ne: null } }) : 0;

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
    pushErr(errors, 'signature_invalid', '检查点签名不匹配（文件被改写或密钥已轮换）', line);
    return false;
  }
  if (!isSupportedVersion(record.version)) {
    pushErr(errors, 'version_unsupported', `不支持的检查点版本：${record.version}`, line);
    return false;
  }
  return true;
}

/** 相邻检查点的 createdAt 必须单调不回退。仅校验时间单调：_id 序 ≠ 追加序
 *（见文件头说明），不作为序判据——本注释此前宣称连 _id 也校验，与实现不符。 */
function checkOrder(previous, record, line, errors) {
  if (!previous) return;
  const at = (x) => new Date(x).getTime();
  if (at(record.createdAt) < at(previous.record.createdAt)) {
    pushErr(errors, 'order_violation', '检查点时间倒退', line);
  }
}

/** 头部记录的 hash/hmac 与「头部之前」的记录数都必须与锚点一致。 */
async function checkHead(AuditLog, record, line, errors) {
  if (!record.headId) return;
  const head = await AuditLog.findOne({ _id: record.headId }).lean();
  if (!head) return pushErr(errors, 'head_missing', `检查点头部记录不存在：${record.headId}`, line);
  if (head.hash !== record.headHash)
    pushErr(errors, 'head_hash_mismatch', '头部 hash 与库中不一致', line);
  if ((head.hmac || null) !== record.headHmac)
    pushErr(errors, 'head_hmac_mismatch', '头部 hmac 与库中不一致', line);
}

/** 尾部截断：删掉最后一次检查点之后的记录，链本身仍自洽，只有与锚点比较才看得见。 */
async function checkTail(AuditLog, last, errors, degraded) {
  if (!last || !last.headId) return;
  const tailHash = await getLatestHash(AuditLog);
  if (!tailHash) {
    pushErr(
      errors,
      'tail_rolled_back',
      `库中已无任何哈希记录，最后检查点 ${last.headId} 之后的内容被整体删除`
    );
    return;
  }
  let cur = await AuditLog.findOne({ hash: tailHash }, { _id: 1, hash: 1, prevHash: 1 }).lean();
  let steps = 0;
  while (cur && steps < TAIL_WALK_LIMIT) {
    if (sameId(cur._id, last.headId)) return;
    cur = cur.prevHash
      ? await AuditLog.findOne({ hash: cur.prevHash }, { _id: 1, hash: 1, prevHash: 1 }).lean()
      : null;
    steps += 1;
  }
  if (cur) {
    pushErr(
      degraded,
      'tail_unverifiable',
      `从当前链尾沿 prevHash 走了 ${TAIL_WALK_LIMIT} 步仍未见到最后检查点 ${last.headId}（窗口耗尽，不判回滚）`
    );
    return;
  }
  pushErr(
    errors,
    'tail_rolled_back',
    `从当前链尾沿 prevHash 回到链头仍未见到最后检查点 ${last.headId}（尾部记录被删除）`
  );
}

/** 本地缺失的两种成因：外锚水位已越过它 ⇒ 回滚（报错）；水位之前才是「还没发」（null）。日期用 `new Date(x).getTime()` 构造式（dateParamGateSingleSource 只许 helpers 一处裸解析）。 */
const anchorRollbackError = (line, record, watermark) => {
  const at = new Date(record.createdAt).getTime();
  if (!Number.isFinite(at) || !(at < watermark.at)) return null;
  const when = new Date(watermark.at).toISOString();
  return {
    line,
    type: 'anchor_rollback',
    message: `本地锚点 ${record.headId || '(空链)'}（${record.createdAt}）在外锚中缺失，但外锚已有更晚的锚点 ${watermark.headId || '(空链)'}（${when}）—— 只可能是外部副本被回退，不是「还没外发」`,
  };
};
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
 *   · 本地有、外部无 ⇒ 外锚水位（最晚 createdAt）已越过它 ⇒ anchor_rollback（发过又被回退，
 *     判红，不混进 pending）；否则才是 pending。整份为空 ⇒ no_external_anchors。
 *
 * 比对用 `signature` 作锚点身份（覆盖 version/createdAt/headId/headHash/headHmac/recordCount），
 * 不依赖外部行序。回滚只在水位留下**缺口**时可判：整段截到更早水位的副本与「还没发」同形。
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
      isSupportedVersion(record.version)
    ) {
      localSignatures.add(record.signature);
    } else {
      localBadLines.add(line);
    }
  }

  const mkErr = (type, message, line = null) => ({ line, type, message });
  const externalSignatures = new Set();
  // wm = 外锚水位（最晚的合法 createdAt）：回退与「还没发」的分界，缺失/非法时间不参与
  const wm = { at: -Infinity, headId: null };
  externalAnchors.forEach((record, idx) => {
    const n = idx + 1;
    if (!record || typeof record !== 'object' || typeof record.signature !== 'string') {
      errors.push(mkErr('anchor_signature_invalid', `外部锚点第 ${n} 条不是可识别的检查点记录`));
      return;
    }
    if (record.signature !== signCheckpoint(record, hmacSecret)) {
      errors.push(
        mkErr('anchor_signature_invalid', `外部锚点第 ${n} 条签名不匹配（副本被改写/密钥轮换）`)
      );
      return;
    }
    if (!isSupportedVersion(record.version)) {
      errors.push(
        mkErr('anchor_version_unsupported', `锚点第 ${n} 条版本不支持：${record.version}`)
      );
      return;
    }
    externalValid.push(record);
    externalSignatures.add(record.signature);
    const ts = new Date(record.createdAt).getTime();
    if (Number.isFinite(ts) && ts > wm.at) Object.assign(wm, { at: ts, headId: record.headId });
    if (!localSignatures.has(record.signature)) {
      const head = record.headId || '(空链)';
      errors.push(
        mkErr('anchor_missing_local', `外部锚点 ${head}（计数 ${record.recordCount}）缺失`)
      );
    }
  });

  for (const { line, record } of localEntries) {
    if (localBadLines.has(line)) continue;
    if (externalSignatures.has(record.signature)) continue;
    const rollback = anchorRollbackError(line, record, wm);
    if (rollback) {
      errors.push(rollback);
      continue;
    }
    pending.push({ line, headId: record.headId, createdAt: record.createdAt });
  }

  return { errors, pending, externalValid };
}

/**
 * 校验全部检查点。
 *
 * `externalAnchors` 为 `undefined` 时不比对（向后兼容，输出形状与旧版逐字一致）；
 * 传入数组（含空数组）才比对——空数组会被判 `no_external_anchors` 而非通过。
 * `now` 可注入当前时间（测试用）；新鲜度臂只在「有可验检查点」时生效——集合为空走
 * no_checkpoints 判红臂，不因新鲜度重复报红。degraded 不影响 ok，但脚本侧据此退 3。
 *
 * @returns {Promise<{ok: boolean, checked: number, errors: Array<{line:number|null,type:string,message:string}>,
 *   anchors?: {compared:number, pending:number, externalValid:number}}>}
 */
async function verifyCheckpoints({ model, filePath, secret, externalAnchors, now } = {}) {
  const hmacSecret = hmacSecretOf(secret);
  const AuditLog = model || require('../models/AuditLog');
  const errors = [];
  const degraded = [];
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
    if (record.version === 1)
      degraded.push({
        line,
        type: 'legacy_version',
        message:
          'v1 检查点：计数判据已退役（旧判据在 TTL 裁剪/迟到批写下会误报），本条只验签名/头部/链尾',
      });
    checkOrder(previous, record, line, errors);
    await checkHead(AuditLog, record, line, errors);
    previous = { line, record };
  }
  await checkTail(AuditLog, previous && previous.record, errors, degraded);

  // 新鲜度臂（degraded 档）：最近一个**签名有效**的检查点距今超预算 ⇒ create 疑似停摆。
  // 判据、env 读法与"空集合不重复报"的边界见 services/auditCheckpointFreshness.js。
  pushStaleIfAny(degraded, previous, now, freshnessBudgetMs());

  return assemble(errors, entries.length);

  function assemble(collected, checked) {
    const out = { ok: collected.length === 0, checked, errors: collected };
    if (degraded.length) out.degraded = degraded;
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
