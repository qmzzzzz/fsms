#!/usr/bin/env node
/**
 * 审计链 v2/v1 存量重签工具（离线维护窗口执行）
 *
 * 背景：
 * - v1 记录没有哈希链，无法只改本条 hash 追认；
 * - v2 记录的部分批量写入 hash 未纳入 riskLevel/riskFactors 默认值；
 * - 任何一条记录 hash 变更后，后续 prevHash/hash 都必须同步重算。
 *
 * 执行顺序：
 *   1. 停止应用写入；
 *   2. node scripts/resign-audit-chain-v3.js --apply；
 *   3. 启动应用；
 *   4. node scripts/verify-audit-chain.js --from=earliest 复核。
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
const { verifyAuditChain } = require('../src/services/auditChainVerify');

// M-08 / L-26：破坏性操作护栏（fail-closed 库名白名单 + 双标志），
// 与 resign-audit-hmac.js / run-rollback-drill.js 共用同一份声明。
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');

// L-26：确认标志的单一常量。同族脚本必须用同一份字符串，
// 否则「统一护栏」会在字面上统一、在行为上分叉。
const CONFIRM_FLAG = '--yes';

const BATCH_SIZE = 1000;

function parseArgs(argv) {
  return { apply: argv.includes('--apply'), confirmYes: argv.includes(CONFIRM_FLAG) };
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
      for (const [field, makeDefault] of Object.entries(PAYLOAD_SCHEMA_DEFAULTS)) {
        if (payload[field] === undefined || (field === 'timestamp' && payload[field] === null)) {
          payload[field] = makeDefault();
        }
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

(async () => {
  const { apply, confirmYes } = parseArgs(process.argv);
  // L-26：改用共享解析器——原实现直读 process.env.MONGODB_URI，
  // 与本族其余脚本的「缺省回退本地库 + 显式告警」口径不一致，
  // 且缺少回退提示，无法判断本次到底连了哪个库。
  const { uri, dbName } = resolveMongoUri({ scriptName: 'resign-audit-chain-v3.js' });
  if (!process.env.HMAC_SECRET) {
    console.error('错误：必须提供 HMAC_SECRET；重签需要同时生成新 HMAC');
    process.exit(2);
  }

  // 三道门（L-26 后与同族脚本完全一致）：
  //   ① 白名单 fail-closed（共享 assertApplyAllowed，未设 ALLOWED_SOURCE_DB 即拒绝）；
  //   ② --apply 之外还需 --yes 二次确认（批量改写 hash/hmac/prevHash 不可逆）；
  //   ③ 连接后回显目标库，便于维护窗口内肉眼核对。
  // 原先 ① 是本脚本内联的 fail-open 版本（`allowList.length > 0 &&`），
  // 未设白名单时等同于无白名单——已由共享实现修正。
  if (!assertApplyAllowed({ scriptName: 'resign-audit-chain-v3.js', dbName, apply })) {
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
  const report = await rechainAllDocuments(apply);
  console.log(JSON.stringify({ ...report, apply }, null, 2));

  const verify = await verifyAuditChain(AuditLog, { fromLatest: false, maxRecords: 200000 });
  console.log(JSON.stringify(verify, null, 2));
  await mongoose.connection.close();

  process.exit(verify.breaks === 0 && verify.legacyV2BatchTolerated === 0 ? 0 : 1);
})().catch(async (error) => {
  console.error(`审计链重签失败：${error.message}`);
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  process.exit(1);
});
