#!/usr/bin/env node
/**
 * 审计链存量重签工具（离线维护窗口执行）
 *
 * 目标版本 = CURRENT_PAYLOAD_VERSION（当前 v4），脚本本身不写死版本号：
 * payload 每升一版，重跑本脚本即可把存量拉到新口径。
 *
 * 背景：
 * - v1 记录没有哈希链，无法只改本条 hash 追认；
 * - v2 记录的部分批量写入 hash 未纳入 riskLevel/riskFactors 默认值；
 * - v2/v3 记录的 targetType/targetId/dataType/description **从未参与哈希**，
 *   升 v4 重签后这四个字段才受保护（但只能保护"从现在起的值"：
 *   重签是对当前值重新摘要，无法证明这些值在历史上未被改过）；
 * - 任何一条记录 hash 变更后，后续 prevHash/hash 都必须同步重算。
 *
 * 执行顺序：
 *   1. 停止应用写入；
 *   2. ALLOWED_SOURCE_DB=<库名> node scripts/resign-audit-chain-v3.js --apply --yes；
 *   3. 启动应用；
 *   4. node scripts/verify-audit-chain.js --from=earliest 复核。
 *
 * ⚠️ 本脚本是**灭迹能力**最强的那类工具，因此改写前必须先核验（与
 *    resign-audit-hmac.js 同一口径，见该文件头）：
 *    它按当前库里的 payload 重算 hash，并**重建整条 prevHash 链**。拥有
 *    数据库写权限的攻击者本就无法伪造 hmac（无钥），所以他改过的记录会以
 *    hmac_mismatch 暴露；而中间删掉一条会以 chain_break/哈希失联暴露。
 *    一旦先重签，这两种暴露同时消失，事后 verify 只会说"链完整"。
 *    即：重签不是修复，是**给一份可能已被改写的库补签**。
 *    所以 --apply 前跑一次与复核完全同源的 computeChainVerdict，
 *    判不了（有断裂/被截断/未配 hmac）就拒绝；确知原因要强行执行时
 *    显式传 --allow-suspect-chain，并在日志里留下越权记录。
 *    演练模式（不带 --apply）只报告不拒绝：预检本身就是运维要看的信息。
 *
 * 命名说明：文件名里的 v3 是它被引入时的目标版本，保留原名以免与既有
 * 轮换手册/运维记录脱钩；实际目标版本始终取常量。
 */

require('dotenv').config();
require('../src/config/secrets').hydrateSecretsFromFiles();

const mongoose = require('mongoose');
const AuditLog = require('../src/models/AuditLog');
const {
  PAYLOAD_SCHEMA_DEFAULTS,
  canonicalPayload,
  computeHash,
  computeHmac,
  CURRENT_PAYLOAD_VERSION,
} = require('../src/utils/auditChain');
const { verifyAuditChain, computeChainVerdict } = require('../src/services/auditChainVerify');

// M-08 / L-26：破坏性操作护栏（fail-closed 库名白名单 + 双标志），
// 与 resign-audit-hmac.js / run-rollback-drill.js 共用同一份声明。
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');

// L-26：确认标志的单一常量。同族脚本必须用同一份字符串，
// 否则「统一护栏」会在字面上统一、在行为上分叉。
const CONFIRM_FLAG = '--yes';

const BATCH_SIZE = 1000;

// 核验窗口上限。预检与复检必须用同一个数：窗口不同 ⇒ 结论不同，
// 用两个常量就会有一天"预检放行、复检喊停"各说各话。
const MAX_VERIFY_RECORDS = 200000;

const ALLOW_SUSPECT_FLAG = '--allow-suspect-chain';

function parseArgs(argv) {
  const out = { apply: false, confirmYes: false, allowSuspect: false };
  for (const a of argv.slice(2)) {
    if (a === '--apply') out.apply = true;
    else if (a === CONFIRM_FLAG) out.confirmYes = true;
    else if (a === ALLOW_SUSPECT_FLAG) out.allowSuspect = true;
    else {
      // 未知参数不得静默接受：`--aply` 会被当成"没传"，于是运维以为在改写、
      // 实际只跑了一次演练，还看到一个 exit 0。
      console.error(`未知参数：${a}\n可用参数：--apply ${CONFIRM_FLAG} ${ALLOW_SUSPECT_FLAG}`);
      process.exit(2);
    }
  }
  return out;
}

async function rechainAllDocuments(apply) {
  const collection = mongoose.connection.collection('auditlogs');
  const count = await collection.countDocuments({});
  const batches = Math.ceil(count / BATCH_SIZE);
  let prevHash = null;
  let chained = 0;
  let hmacMissing = 0;

  for (let page = 0; page < batches; page += 1) {
    const docs = await AuditLog.find({})
      .sort({ _id: 1 })
      .skip(page * BATCH_SIZE)
      .limit(BATCH_SIZE);
    const operations = [];

    for (const doc of docs) {
      const payload = doc.toObject();
      const defaulted = {};
      for (const [field, makeDefault] of Object.entries(PAYLOAD_SCHEMA_DEFAULTS)) {
        if (payload[field] === undefined || (field === 'timestamp' && payload[field] === null)) {
          payload[field] = makeDefault();
        }
        // 无论 toObject 是否已按 schema 默认填过，都把"参与哈希的值"显式写回文档：
        // 校验端以 .lean() 读，不会应用 schema 默认，若库里缺该字段则读到 undefined→null，
        // 而 hash 覆盖的是默认值 → hash_mismatch 且重跑不可逆。运行时 chainBatch 正是
        // "算 hash 前写回文档本身"来消除这个偏差，存量重签必须同源对齐（F-C1）。
        defaulted[field] = payload[field];
      }

      doc.prevHash = prevHash;
      doc.hash = computeHash(prevHash, canonicalPayload(payload, CURRENT_PAYLOAD_VERSION));
      doc.hmac = computeHmac(doc.hash);
      doc.hashVersion = CURRENT_PAYLOAD_VERSION;
      prevHash = doc.hash;
      if (!doc.hmac) hmacMissing += 1;

      operations.push({
        updateOne: {
          filter: { _id: doc._id },
          update: {
            $set: {
              ...defaulted,
              prevHash: doc.prevHash,
              hash: doc.hash,
              hmac: doc.hmac,
              hashVersion: doc.hashVersion,
            },
          },
        },
      });
      chained += 1;
    }

    if (apply && operations.length > 0) await collection.bulkWrite(operations, { ordered: false });
  }

  return { count, chained, hmacMissing, batches };
}

/** 与复核脚本同源的一次全量核验（预检/复检共用同一判据，不各写一份） */
async function runChainVerify() {
  const verify = await verifyAuditChain(AuditLog, {
    fromLatest: false,
    maxRecords: MAX_VERIFY_RECORDS,
  });
  const collectionTotal = await AuditLog.estimatedDocumentCount();
  const verdict = computeChainVerdict({
    breaks: verify.breaks,
    total: verify.total,
    maxRecords: MAX_VERIFY_RECORDS,
    collectionTotal,
    hmacChecked: verify.hmacChecked,
    // 整窗无哈希（全 legacy）不得背书：本脚本从最早扫起，窗口若全落在链启用前的
    // legacy 段，旧判据会给 code=0 —— 那正是"为灭迹签发合格证明"。
    legacy: verify.legacy,
    // 缺口计数同样必须回传：本脚本用「能否宣称完整」作为改写前/后的合格证明，
    // 而 verifyAuditChain 的报告恒带 hashComputeFailed。漏传不是少一条理由，
    // 是让"链上有 N 条算不出 hash"直接穿过判据拿到 canAttestIntact=true。
    hashComputeFailed: verify.hashComputeFailed,
    // 改写前/后核验的"能否宣称完整"是这条链的合格证明本体，扫描口径必须回显给判据
    scanned: verify.scanned,
  });
  return { verify, verdict };
}

function printVerifyReport(label, { verify, verdict }) {
  console.log(
    `\n[${label}] 扫描 ${verify.total} 条（窗口上限 ${verify.scanned.maxRecords}）：` +
      `断裂 ${verify.breaks} ${JSON.stringify(verify.byType)} ` +
      `v2 默认值漂移（已知容忍）${verify.legacyV2BatchTolerated}`
  );
  if (verify.samples && verify.samples.length > 0) {
    console.log(`[${label}] 断裂样本：${JSON.stringify(verify.samples.slice(0, 5))}`);
  }
  console.log(`[${label}] 能否宣称完整：${verdict.canAttestIntact ? '能' : '不能'}`);
  if (!verdict.canAttestIntact) console.log(`[${label}] 理由：${verdict.reasons.join('；')}`);
}

/**
 * 改写前的放行判定（纯函数：判据要能脱离数据库被单测取走）。
 *
 * 只在 --apply 时拒绝：演练模式的目的就是把这份报告打印出来，
 * 让它退 0 与 resign-audit-hmac.js 同口径（否则"演练"和"失败"分不开）。
 */
function decidePrecheck({ verdict, apply, allowSuspect }) {
  if (verdict.canAttestIntact) return true;
  if (allowSuspect) {
    console.log(`\n已按 ${ALLOW_SUSPECT_FLAG} 越权放行改写前核验：${verdict.reasons.join('；')}`);
    return true;
  }
  if (!apply) {
    console.log('\n演练模式未改写任何记录。加上 --apply 时会因上面的预检被拒绝。');
    return true;
  }
  console.error(`\n拒绝执行：改写前审计链不具备完整性背书（${verdict.reasons.join('；')}）。`);
  console.error(
    '本脚本按库内现值重算 hash 并重建 prevHash 链——现在重签，会把"字段被改过"' +
      '与"整条记录被删过"两类唯一留存的证据一并抹掉，事后 verify 只会说链完整。'
  );
  console.error(`确知原因仍需执行时，显式传 ${ALLOW_SUSPECT_FLAG}（该选择会打印在日志里）。`);
  return false;
}

async function main() {
  const { apply, confirmYes, allowSuspect } = parseArgs(process.argv);
  // L-26：改用共享解析器——原实现直读 process.env.MONGODB_URI，
  // 与本族其余脚本的「缺省回退本地库 + 显式告警」口径不一致，
  // 且缺少回退提示，无法判断本次到底连了哪个库。
  const { uri, dbName, host, isFallback } = resolveMongoUri({
    scriptName: 'resign-audit-chain-v3.js',
  });
  if (!process.env.HMAC_SECRET) {
    console.error('错误：必须提供 HMAC_SECRET；重签需要同时生成新 HMAC');
    process.exit(2);
  }

  // 四道门（前三道 L-26 后与同族脚本完全一致）：
  //   ① 白名单 fail-closed（共享 assertApplyAllowed，未设 ALLOWED_SOURCE_DB 即拒绝）；
  //   ② --apply 之外还需 --yes 二次确认（批量改写 hash/hmac/prevHash 不可逆）；
  //   ③ 连接后回显目标库，便于维护窗口内肉眼核对；
  //   ④ 改写前核验（本次新增）：见文件头「灭迹能力」说明。
  // 原先 ① 是本脚本内联的 fail-open 版本（`allowList.length > 0 &&`），
  // 未设白名单时等同于无白名单——已由共享实现修正。
  if (
    !assertApplyAllowed({
      scriptName: 'resign-audit-chain-v3.js',
      dbName,
      host,
      isFallback,
      apply,
    })
  ) {
    process.exit(2);
  }
  if (apply && !confirmYes) {
    console.error(
      `错误：--apply 将重签全部审计记录的 hash/hmac/prevHash，需再传 ${CONFIRM_FLAG} 确认。`
    );
    process.exit(2);
  }

  await mongoose.connect(uri);
  console.log(`>>> 目标数据库：${mongoose.connection.name}（--apply=${apply}）`);

  // ---- ④ 预检：必须早于任何改写 ----
  const pre = await runChainVerify();
  printVerifyReport('预检（改写前）', pre);
  if (!decidePrecheck({ verdict: pre.verdict, apply, allowSuspect })) {
    await mongoose.connection.close();
    process.exit(2);
  }

  const report = await rechainAllDocuments(apply);
  console.log(JSON.stringify({ ...report, apply }, null, 2));

  if (!apply) {
    await mongoose.connection.close();
    console.log('\n演练完成：未改写任何记录。确认无误后追加 --apply --yes 执行。');
    process.exit(0);
  }

  // 复核与运维脚本共用同一判据（services/auditChainVerify 的 computeChainVerdict）。
  // 原来这里只看 `breaks === 0`：那只说明"扫过的这批没断"。窗口上限 20 万条，
  // 生产审计集合一旦超过它，重签后**尾部（正是本次新写入区）从未被核验**却退 0，
  // 等于给未核验的段落签发合格证明——而 verify-audit-chain.js 对同一情形退 2。
  const post = await runChainVerify();
  printVerifyReport('复检（改写后）', post);
  await mongoose.connection.close();
  if (post.verify.legacyV2BatchTolerated > 0) {
    console.error(
      `复核未通过：${post.verify.legacyV2BatchTolerated} 条 v2 批量写入的默认值漂移记录（重签后应归零）`
    );
  }
  if (!post.verdict.canAttestIntact) {
    console.error(`复核未通过：${post.verdict.reasons.join('；') || '存在断裂'}`);
  }
  process.exit(post.verdict.code === 0 && post.verify.legacyV2BatchTolerated === 0 ? 0 : 1);
}

module.exports = { parseArgs, decidePrecheck, printVerifyReport, MAX_VERIFY_RECORDS };

// 可被 require 的脚本不在模块级跑副作用：判定要能被单测取走而不触发连库。
if (require.main === module) {
  main().catch(async (error) => {
    console.error(`审计链重签失败：${error.message}`);
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
    process.exit(1);
  });
}
