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

const BATCH_SIZE = 1000;

function parseArgs(argv) {
  return { apply: argv.includes('--apply'), confirmYes: argv.includes('--yes') };
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
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('错误：必须通过环境变量或 .env 提供 MONGODB_URI');
    process.exit(2);
  }
  if (!process.env.HMAC_SECRET) {
    console.error('错误：必须提供 HMAC_SECRET；重签需要同时生成新 HMAC');
    process.exit(2);
  }

  await mongoose.connect(uri);
  // 评价报告 #21（破坏性脚本护栏）：--apply 会 bulkWrite 重签整条审计链，
  // 加三道门——目标库回显、--yes 二次确认、ALLOWED_SOURCE_DB 库名白名单
  // （生产库必须显式列入白名单才可作用；演练库不受影响时无需设置）。
  const dbName = mongoose.connection.name;
  console.log(`>>> 目标数据库：${dbName}（--apply=${apply}）`);
  if (apply && !confirmYes) {
    console.error('错误：--apply 将重签全部审计记录的 hash/hmac/prevHash，需再传 --yes 确认。');
    await mongoose.connection.close();
    process.exit(2);
  }
  if (apply) {
    const allowList = (process.env.ALLOWED_SOURCE_DB || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (allowList.length > 0 && !allowList.includes(dbName)) {
      console.error(
        `错误：目标库「${dbName}」不在 ALLOWED_SOURCE_DB 白名单中（当前白名单：${allowList.join(', ') || '空'}）。` +
          '如确需重签该库，请设置 ALLOWED_SOURCE_DB=<库名> 后重试。'
      );
      await mongoose.connection.close();
      process.exit(2);
    }
  }
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
