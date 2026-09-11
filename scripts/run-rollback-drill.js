#!/usr/bin/env node
/**
 * 数据级回滚演练（本地/隔离环境）
 *
 * 说明：
 * - 使用 Node 原生 zlib 生成 .ndjson.gz 快照，避免依赖 mongodump/mongorestore；
 * - 快照仍包含 BSON 兼容的 EJSON，ObjectId/Date 可无损还原；
 * - 默认只演练 DRILL/SHADOW 库。源库带 --apply-source 才允许清空回滚，
 *   避免误连生产库造成破坏。
 */

require('dotenv').config();

const fs = require('fs/promises');
const path = require('path');
const zlib = require('zlib');
const mongoose = require('mongoose');

const COLLECTIONS = ['users', 'roles', 'permissions', 'auditlogs'];

function parseArgs(argv) {
  const args = { applySource: false, backupDir: path.join('backups', 'rollback-drill') };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--apply-source') args.applySource = true;
    if (argv[index] === '--backup-dir') args.backupDir = argv[index + 1];
  }
  return args;
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
  const { applySource, backupDir } = parseArgs(process.argv.slice(2));
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('错误：必须提供 MONGODB_URI');
    process.exit(2);
  }

  await fs.mkdir(backupDir, { recursive: true });
  await mongoose.connect(uri);
  const database = mongoose.connection.db;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const manifest = { uri: mongoose.connection.name, timestamp, collections: {} };

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
