#!/usr/bin/env node
/**
 * 数据级回滚演练（本地/隔离环境）
 *
 * 说明：
 * - 使用 Node 原生 zlib 生成 .ndjson.gz 快照，避免依赖 mongodump/mongorestore；
 * - 快照仍包含 BSON 兼容的 EJSON，ObjectId/Date 可无损还原；
 * - 默认只演练 DRILL/SHADOW 库。源库带 --apply-source 才允许清空回滚，
 *   避免误连生产库造成破坏。
 *
 * 评价报告 #21（破坏性脚本护栏）/ M-08：
 * - 库名白名单（**fail-closed**）：--apply-source 只允许作用于显式列入
 *   ALLOWED_SOURCE_DB 白名单的库。**未设置白名单即拒绝执行**——原先未设置时
 *   等于不校验，与「默认安全、显式放开」相反，已修正；
 * - 目标库回显：执行前打印实际连接的数据库名，人工核对一眼可辨；
 * - 二次确认：--apply-source 需再传 --yes 才真正落斧（CI 里显式带 --yes）。
 */

require('dotenv').config();

const fs = require('fs/promises');
const path = require('path');
const zlib = require('zlib');
const mongoose = require('mongoose');

// M-08：破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明
const { assertApplyAllowed } = require('./destructiveGuard');

const COLLECTIONS = ['users', 'roles', 'permissions', 'auditlogs'];

function parseArgs(argv) {
  const args = {
    applySource: false,
    confirmYes: false,
    backupDir: path.join('backups', 'rollback-drill'),
  };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--apply-source') args.applySource = true;
    if (argv[index] === '--yes') args.confirmYes = true;
    if (argv[index] === '--backup-dir') args.backupDir = argv[index + 1];
  }
  return args;
}

/** #21 / M-08：源库白名单——生产库名必须显式列入才允许 --apply-source
 *
 * 【M-08 修复】原实现为 fail-open：
 *   `if (allowList.length > 0 && !allowList.includes(dbName))`
 * 未设置 ALLOWED_SOURCE_DB 时 allowList 为空 → 条件恒假 → **白名单形同不存在**，
 * 与函数注释承诺的「默认安全、显式放开」相反。现改用共享护栏（fail-closed）：
 * 未设置白名单即拒绝执行。
 */
function assertSourceDbAllowed(dbName) {
  return assertApplyAllowed({ scriptName: 'run-rollback-drill.js', dbName, apply: true });
}

async function backupCollection(collection, file) {
  const docs = await collection.find({}).toArray();
  await fs.writeFile(file, zlib.gzipSync(JSON.stringify(docs)));
  return docs.length;
}

async function restoreCollection(collection, file) {
  const raw = await fs.readFile(file);
  const docs = JSON.parse(zlib.gunzipSync(raw).toString('utf8')).map((doc) => {
    if (doc._id && doc._id.$oid) doc._id = new mongoose.Types.ObjectId(doc._id.$oid);
    for (const [key, value] of Object.entries(doc)) {
      if (value && value.$date) doc[key] = new Date(value.$date);
    }
    return doc;
  });
  if (docs.length === 0) return 0;
  const prepared = docs.map((doc) => {
    const { _id, ...rest } = doc;
    return { replaceOne: { filter: { _id }, replacement: rest, upsert: true } };
  });
  await collection.bulkWrite(prepared, { ordered: false });
  return docs.length;
}

(async () => {
  const { applySource, confirmYes, backupDir } = parseArgs(process.argv.slice(2));
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('错误：必须提供 MONGODB_URI');
    process.exit(2);
  }

  await fs.mkdir(backupDir, { recursive: true });
  await mongoose.connect(uri);
  const database = mongoose.connection.db;
  const dbName = mongoose.connection.name;
  console.log(`>>> 目标数据库：${dbName}（--apply-source=${applySource}）`);
  if (applySource && !confirmYes) {
    console.error(
      `错误：--apply-source 将对上述库执行 deleteMany + 回灌，需再传 --yes 确认。` +
        `当前库名：${dbName}；如非预期请立即中断。`
    );
    await mongoose.connection.close();
    process.exit(2);
  }
  if (applySource && !assertSourceDbAllowed(dbName)) {
    await mongoose.connection.close();
    process.exit(2);
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const manifest = { uri: dbName, timestamp, collections: {} };

  for (const name of COLLECTIONS) {
    const source = database.collection(name);
    const backupFile = path.join(backupDir, `${name}-${timestamp}.ndjson.gz`);
    manifest.collections[name] = { file: path.basename(backupFile), documents: 0 };
    manifest.collections[name].documents = await backupCollection(source, backupFile);
  }

  const manifestFile = path.join(backupDir, `manifest-${timestamp}.json`);
  await fs.writeFile(manifestFile, JSON.stringify(manifest, null, 2));

  if (applySource) {
    for (const name of COLLECTIONS) {
      const file = path.join(backupDir, manifest.collections[name].file);
      await database.collection(name).deleteMany({});
      await restoreCollection(database.collection(name), file);
    }
  }

  console.log(JSON.stringify({ ...manifest, applySource }, null, 2));
  await mongoose.connection.close();
})().catch(async (error) => {
  console.error(`回滚演练失败：${error.message}`);
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  process.exit(1);
});
