'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { assert, createJourney, listFiles, readJson, runNode } = require('../lib');
const { isolateDisposableSecrets } = require('../../devSecretIsolation');

const COLLECTIONS = ['users', 'roles', 'permissions', 'auditlogs'];
const REQUIRED_MARKERS = [
  '未声明白名单时拒绝落斧',
  '快照→清空→回灌后与快照逐条一致',
  'ObjectId/Date 往返无损',
  'manifest 可被留档脚本接受',
];

const OID = mongoose.Types.ObjectId;
const CREATED_AT = '2026-10-20T08:30:00.000Z';

function seedDocuments() {
  const roleId = new OID();
  const permissionId = new OID();
  return {
    users: [
      {
        _id: new OID(),
        username: 'ops-a',
        department: 'A',
        roleIds: [roleId],
        createdAt: new Date(CREATED_AT),
        profile: { level: 3, tags: ['night'] },
      },
      {
        _id: new OID(),
        username: 'ops-b',
        department: 'B',
        roleIds: [roleId],
        createdAt: new Date(CREATED_AT),
        profile: { level: 4, tags: [] },
      },
    ],
    roles: [
      {
        _id: roleId,
        code: 'SECURITY_ADMIN',
        level: 8,
        grants: [permissionId],
        updatedAt: new Date(CREATED_AT),
      },
    ],
    permissions: [{ _id: permissionId, code: 'device:read', createdAt: new Date(CREATED_AT) }],
    auditlogs: [
      {
        _id: new OID(),
        action: 'LOGIN',
        timestamp: new Date(CREATED_AT),
        details: { ip: '127.0.0.1' },
      },
      {
        _id: new OID(),
        action: 'DEVICE_UPDATE',
        timestamp: new Date('2026-10-20T09:00:00.000Z'),
        details: { ip: '127.0.0.1', device: 'D-1' },
      },
    ],
  };
}

async function openSeedDatabase(dbName) {
  const mongo = await MongoMemoryServer.create();
  const uri = mongo.getUri(dbName);
  const connection = await mongoose.createConnection(uri).asPromise();
  const documents = seedDocuments();
  for (const [name, docs] of Object.entries(documents)) {
    await connection.db.collection(name).insertMany(docs);
  }
  return { mongo, uri, connection, documents };
}

async function counts(db) {
  const out = {};
  for (const name of COLLECTIONS) out[name] = await db.collection(name).countDocuments({});
  return out;
}

function runDrill(root, drillDir, uri, allowedSourceDb) {
  return runNode(
    path.join(root, 'scripts', 'run-rollback-drill.js'),
    ['--apply-source', '--yes', '--backup-dir', drillDir],
    {
      timeoutMs: 120000,
      env: { ...process.env, MONGODB_URI: uri, ALLOWED_SOURCE_DB: allowedSourceDb },
    }
  );
}

function describe(result) {
  return `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`;
}

async function assertTypeFaithful(db, manifest, drillDir) {
  const users = await db.collection('users').find({}).toArray();
  assert.equal(users.length, 2);
  const a = users.find((u) => u.username === 'ops-a');
  assert.ok(a, '回灌后缺少 ops-a');
  assert.equal(a._id._bsontype, 'ObjectId', '_id 不得退化成字符串');
  assert.ok(a.createdAt instanceof Date, 'createdAt 不得退化成字符串');
  assert.equal(a.createdAt.toISOString(), CREATED_AT);
  assert.equal(a.roleIds[0]._bsontype, 'ObjectId', '嵌套数组里的 ObjectId 必须保留');
  assert.equal(a.profile.level, 3);
  assert.deepEqual(a.profile.tags, ['night']);

  const snapshot = path.join(drillDir, manifest.collections.users.file);
  const raw = zlib.gunzipSync(fs.readFileSync(snapshot)).toString('utf8');
  assert.match(raw, /"\$oid"/, '快照必须以 EJSON 编码 ObjectId');
  assert.match(raw, /"\$date"/, '快照必须以 EJSON 编码 Date');
}

async function main(config) {
  const { root, tmpDir } = config;
  const journey = createJourney('backup-restore', REQUIRED_MARKERS);
  const drillDir = path.join(tmpDir, 'drill');
  const recordFile = path.join(tmpDir, 'rollback-drill-record.md');
  const dbName = `fsms_ops_e2e_${process.pid}`;

  // 必须在设一次性 MONGODB_URI 之前调用：宿主残留的 *_FILE 会在子进程 require 期
  // 把 MONGODB_URI 覆写成真实库，演练的清空/回灌就会落到那个库上。
  isolateDisposableSecrets({ scriptName: 'ops-e2e-backup-restore' });

  let mongo = null;
  let connection = null;
  let uri = null;
  let db = null;
  let documents = null;
  let manifest = null;
  let manifestFile = null;

  try {
    await journey.step('准备内存 Mongo 并写入种子数据（含 ObjectId/Date 嵌套）', async () => {
      const opened = await openSeedDatabase(dbName);
      mongo = opened.mongo;
      connection = opened.connection;
      uri = opened.uri;
      db = opened.connection.db;
      documents = opened.documents;
    });

    await journey.step('未声明白名单时拒绝落斧（fail-closed，数据原样）', async () => {
      assert.ok(uri, '准备步骤未完成');
      const before = await counts(db);
      const result = runDrill(root, path.join(tmpDir, 'drill-refused'), uri, '');
      assert.equal(
        result.status,
        2,
        `被拒绝的演练应退出 2，实得 ${result.status}\n${describe(result)}`
      );
      assert.match(`${result.stdout}\n${result.stderr}`, /拒绝执行/);
      assert.deepEqual(await counts(db), before, '被拒绝的演练不得清空任何集合');
    });

    await journey.step('快照→清空→回灌后与快照逐条一致', async () => {
      assert.ok(uri, '准备步骤未完成');
      const result = runDrill(root, drillDir, uri, dbName);
      assert.equal(result.status, 0, `演练退出码 ${result.status}\n${describe(result)}`);

      const manifests = listFiles(drillDir, /^manifest-.*\.json$/);
      assert.equal(manifests.length, 1, '一次演练应恰好产出一份 manifest');
      manifestFile = manifests[0];
      manifest = readJson(manifestFile);

      assert.equal(manifest.uri, dbName);
      assert.equal(manifest.applySource, true);
      assert.equal(manifest.restoreVerified, true, 'restoreVerified 必须为 true');
      let total = 0;
      for (const name of COLLECTIONS) {
        const expected = documents[name].length;
        assert.equal(manifest.collections[name].documents, expected, `${name} 快照条数`);
        assert.equal(manifest.collections[name].restored, expected, `${name} 回灌条数`);
        total += expected;
      }
      assert.equal(manifest.totalSnapshotDocuments, total);
      const expectedCounts = Object.fromEntries(
        COLLECTIONS.map((name) => [name, documents[name].length])
      );
      assert.deepEqual(await counts(db), expectedCounts, '回灌后集合条数应与种子一致');
    });

    await journey.step('ObjectId/Date 往返无损（BSON 类型不退回字符串）', async () => {
      assert.ok(manifest, '前置步骤未完成');
      await assertTypeFaithful(db, manifest, drillDir);
    });

    await journey.step('manifest 可被留档脚本接受（dry-run 渲染）', async () => {
      assert.ok(manifestFile, '前置步骤未完成');
      fs.writeFileSync(recordFile, '# 回滚演练记录\n\n## 三、实际演练记录\n');
      const before = fs.readFileSync(recordFile, 'utf8');
      const result = runNode(
        path.join(root, 'scripts', 'record-rollback-drill.js'),
        ['--manifest', manifestFile, '--record-file', recordFile],
        { timeoutMs: 30000 }
      );
      assert.equal(result.status, 0, `留档脚本退出码 ${result.status}\n${describe(result)}`);
      assert.match(result.stdout, /演练 #1/);
      assert.match(result.stdout, /回灌与快照逐集合一致/);
      assert.match(result.stdout, /\| users \| 2 \| 2 \|/);
      assert.equal(
        fs.readFileSync(recordFile, 'utf8'),
        before,
        '未加 --write 的 dry-run 不得改写留档文件'
      );
    });
  } finally {
    if (connection) await connection.close().catch(() => {});
    if (mongo) await mongo.stop().catch(() => {});
  }

  return journey.finish();
}

module.exports = { main, seedDocuments, COLLECTIONS, REQUIRED_MARKERS };
